use futures::stream::StreamExt;
use libp2p::gossipsub::Topic;
use libp2p::{gossipsub, mdns, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux};
use libp2p::{PeerId, Swarm};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use std::vec;
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;

use frost_secp256k1 as frost;
use rand::thread_rng;

// Dkg Fsm states

// Define the events that can trigger state transitions
#[derive(Debug, Clone, PartialEq)]
pub enum DKGEvent {
    Start,
    Round1,
    Round2,
    Round3,
    DKGFailed,
}

// Define the states of the state machine
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DKGState {
    Initial,
    Round1,
    Round2,
    Round3,
    DkgFailed,
}

// Implement the state machine using rust-fsm
#[derive(Debug)]
struct DKGStateMachine {
    state: DKGState,
    min_signers: u16,
    max_signers: u16,
    personal_identifier: frost::Identifier,
    personal_secret_package: frost::keys::dkg::round1::SecretPackage,
    personal_round1_package: frost::keys::dkg::round1::Package,
    group_packages: Vec<frost::keys::dkg::round1::Package>,
}

impl DKGStateMachine {
    pub fn new(min_signers: u16, max_signers: u16, personal_id_bytes: &[u8]) -> Self {
        let mut rng = thread_rng();
        let personal_identifier =
            frost::Identifier::derive(personal_id_bytes).expect("can derive identifier");
        let (personal_secret_package, personal_round1_package) =
            frost::keys::dkg::part1(personal_identifier, min_signers, max_signers, &mut rng)
                .unwrap();
        Self {
            state: DKGState::Initial,
            min_signers,
            max_signers,
            personal_secret_package,
            personal_round1_package,
            personal_identifier,
            group_packages: vec![],
        }
    }
}

impl DKGStateMachine {
    fn next_state<H: libp2p::gossipsub::Hasher>(
        &mut self,
        event: DKGEvent,
        swarm: &mut Swarm<FrostBehaviour>,
        topic: Topic<H>,
    ) {
        match (self.state, event) {
            // Define state transitions based on events
            (DKGState::Initial, DKGEvent::Round1) => {
                info!("Starting DKG, sending round 1 package to all peers");
                let topic_hash = topic.hash();
                let request = Request {
                    request_type: EventRequestType::DkgRound1,
                    data: Some(
                        serde_json::to_string(&self.personal_round1_package)
                            .expect("can jsonify request"),
                    ),
                };
                let json = serde_json::to_string(&request).expect("can jsonify request");
                // Broadcast to all peers
                swarm.behaviour_mut().gossipsub.publish(topic_hash.clone(), json.as_bytes());

                self.state = DKGState::Round1;
            }
            // TODO for round 2, 3
            _ => panic!("Invalid transition"),
        }
    }
}

#[derive(NetworkBehaviour)]
struct FrostBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

// Response Structs
#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum EventResponseType {
    Pong,
    DkgRound1,
}

struct DKGRound1ResponsePackage {
    from_peer_id: String,
    package: frost::keys::dkg::round1::Package,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response<T> {
    response_type: EventResponseType,
    data: Option<T>,
    // peer id for who should recieve
    receiver: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum EventRequestType {
    Ping,
    // Event for everyone to start DKG by sharing their coefficients
    DkgRound1,
}

// Request structs
#[derive(Debug, Serialize, Deserialize)]
struct Request<T> {
    request_type: EventRequestType,
    data: Option<T>,
}

async fn handle_ping<H: libp2p::gossipsub::Hasher>(
    swarm: &mut Swarm<FrostBehaviour>,
    topic: Topic<H>,
) {
    info!("Sending Ping");
    let request: Request<Option<String>> = Request {
        request_type: EventRequestType::Ping,
        data: None,
    };
    let json = serde_json::to_string(&request).expect("can jsonify request");

    debug!("json: {}", json);
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, json.as_bytes());
}

async fn handle_pong<H: libp2p::gossipsub::Hasher>(
    swarm: &mut Swarm<FrostBehaviour>,
    topic: Topic<H>,
    peer_id: PeerId,
) {
    info!("Sending Pong");
    let request: Response<Option<String>> = Response {
        response_type: EventResponseType::Pong,
        receiver: peer_id.to_string(),
        data: None,
    };
    let json = serde_json::to_string(&request).expect("can jsonify request");

    debug!("json: {}", json);
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, json.as_bytes());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {
            // To content-address message, we can take the hash of message and use it as an ID.
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = DefaultHasher::new();
                message.data.hash(&mut s);
                gossipsub::MessageId::from(s.finish().to_string())
            };

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(10)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message signing)
                .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            Ok(FrostBehaviour { gossipsub, mdns })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("frost");
    let dkg_state_machine =
        &mut DKGStateMachine::new(2, 2, swarm.local_peer_id().to_bytes().as_ref());

    println!("dkg_state_machine: {:?}", dkg_state_machine);

    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    println!("Enter messages via STDIN and they will be sent to connected peers using Gossipsub");

    // Kick it off
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                match line.as_str() {
                    "ls p" => {
                        println!("Connected peers:");
                        for peer in swarm.behaviour_mut().gossipsub.all_peers() {
                            println!("{:?}", peer);
                        }
                    }
                    "ping" => {
                        handle_ping(&mut swarm, topic.clone()).await;
                    }
                    "dkg" => {
                        dkg_state_machine.next_state(DKGEvent::Round1, &mut swarm, topic.clone());
                    }
                    _ => println!("Sending message: {}", line),
                }
                if let Err(e) = swarm
                    .behaviour_mut().gossipsub
                    .publish(topic.clone(), line.as_bytes()) {
                    println!("Publish error: {e:?}");
                }
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(FrostBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(FrostBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                },
                SwarmEvent::Behaviour(FrostBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {

                    info!(
                        "Got message: '{}' with id: {id} from peer: {peer_id}",
                        String::from_utf8_lossy(&message.data),
                    );
                    if let Ok(req) = serde_json::from_slice::<Request<Option<String>>>(&message.data) {
                        match req.request_type {
                            EventRequestType::Ping => {
                                info!("Got ping from peer: {peer_id}");
                                handle_pong(&mut swarm, topic.clone(), peer_id).await;
                            }
                            EventRequestType::DkgRound1 => {
                                info!("Got DKG round 1 from peer: {peer_id}");
                                if peer_id == *swarm.local_peer_id() {
                                    debug!("Got our own round 1 package back");
                                    continue;
                                }
                                // A peer is requesting to start DKG
                                // Assuming we are in init state, otherwise we shouldnt ignore
                                dkg_state_machine.next_state(DKGEvent::Round1, &mut swarm, topic.clone());
                            }
                        }
                    } else if let Ok(resp) = serde_json::from_slice::<Response<Option<String>>>(&message.data) {
                        if resp.receiver == swarm.local_peer_id().to_string() {
                            info!("Got response from peer: {peer_id}");
                            match resp.response_type {
                                EventResponseType::Pong => {
                                    info!("Got pong from peer: {peer_id}");
                                }
                                EventResponseType::DkgRound1 => {
                                    info!("Got DKG round 1 from peer: {peer_id}");
                                    
                                    todo!();
                                }
                            }
                        }
                    }

                },

                _ => {}
            }
        }
    }
}
