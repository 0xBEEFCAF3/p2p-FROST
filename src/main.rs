use libp2p::{
    core::upgrade,
    floodsub::{Floodsub, FloodsubEvent, Topic},
    futures::StreamExt,
    identity,
    mdns::{Mdns, MdnsEvent},
    mplex,
    noise::{Keypair, NoiseConfig, X25519Spec},
    request_response::throttled::Event,
    swarm::{NetworkBehaviourEventProcess, Swarm, SwarmBuilder},
    tcp::TokioTcpConfig,
    NetworkBehaviour, PeerId, Transport,
};
use log::{error, info};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::{io::AsyncBufReadExt, sync::mpsc};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

static KEYS: Lazy<identity::Keypair> = Lazy::new(|| identity::Keypair::generate_ed25519());
static PEER_ID: Lazy<PeerId> = Lazy::new(|| PeerId::from(KEYS.public()));
static TOPIC: Lazy<Topic> = Lazy::new(|| Topic::new("frost"));

#[derive(Debug, Serialize, Deserialize)]
struct Ping {
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Pong {
    message: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum EventResponseType {
    Pong,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response {
    respose_type: EventResponseType,
    data: Option<String>,
    // peer id for who should recieve
    receiver: String,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum EventRequestType {
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    request_type: EventRequestType,
    data: Option<String>,
}

#[derive(Debug)]
enum EventType {
    Response(Response),
    Input(String),
}

#[derive(NetworkBehaviour)]
struct FrostBehaviour {
    floodsub: Floodsub,
    mdns: Mdns,
    #[behaviour(ignore)]
    response_sender: mpsc::UnboundedSender<Response>,
}

impl NetworkBehaviourEventProcess<FloodsubEvent> for FrostBehaviour {
    fn inject_event(&mut self, event: FloodsubEvent) {
        info!("Floodsub Event: {:?}", event);
        match event {
            FloodsubEvent::Message(msg) => {
                // The following event is a Response
                if let Ok(resp) = serde_json::from_slice::<Response>(&msg.data) {
                    if resp.receiver == PEER_ID.to_string() {
                        info!("Got a pong response from {}:", msg.source);
                    }
                } 
                // The following event is a Request
                else if let Ok(req) = serde_json::from_slice::<Request>(&msg.data) {
                    if req.request_type == EventRequestType::Ping {
                        info!("Got a ping request from {}:", msg.source);
                        respond_with_pong(self.response_sender.clone(), msg.source.to_string());
                    }
                }
            }
            _ => (),
        }
    }
}

fn respond_with_pong(sender: mpsc::UnboundedSender<Response>, receiver: String) {
    tokio::spawn(async move {
        let response: Response = Response {
            respose_type: EventResponseType::Pong,
            data: None,
            receiver,
        };
        sender.send(response).expect("can send response");
    });
}

impl NetworkBehaviourEventProcess<MdnsEvent> for FrostBehaviour {
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(discovered_list) => {
                for (peer, _addr) in discovered_list {
                    self.floodsub.add_node_to_partial_view(peer);
                }
            }
            MdnsEvent::Expired(expired_list) => {
                for (peer, _addr) in expired_list {
                    if !self.mdns.has_node(&peer) {
                        self.floodsub.remove_node_from_partial_view(&peer);
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();

    info!("Peer Id: {}", PEER_ID.clone());
    let (response_sender, mut response_rcv) = mpsc::unbounded_channel();

    let auth_keys = Keypair::<X25519Spec>::new()
        .into_authentic(&KEYS)
        .expect("can create auth keys");

    let transp = TokioTcpConfig::new()
        .upgrade(upgrade::Version::V1)
        // XX Handshake pattern, IX exists as well and IK - only XX currently provides interop with other libp2p impls
        .authenticate(NoiseConfig::xx(auth_keys).into_authenticated())
        .multiplex(mplex::MplexConfig::new())
        .boxed();

    let mut behaviour = FrostBehaviour {
        floodsub: Floodsub::new(PEER_ID.clone()),
        mdns: Mdns::new(Default::default())
            .await
            .expect("can create mdns"),
        response_sender,
    };

    behaviour.floodsub.subscribe(TOPIC.clone());

    let mut swarm = SwarmBuilder::new(transp, behaviour, PEER_ID.clone())
        .executor(Box::new(|fut| {
            tokio::spawn(fut);
        }))
        .build();

    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    Swarm::listen_on(
        &mut swarm,
        "/ip4/0.0.0.0/tcp/0"
            .parse()
            .expect("can get a local socket"),
    )
    .expect("swarm can be started");

    loop {
        let evt = {
            tokio::select! {
                line = stdin.next_line() => Some(EventType::Input(line.expect("can get line").expect("can read line from stdin"))),
                response = response_rcv.recv() => Some(EventType::Response(response.expect("response exists"))),
                event = swarm.select_next_some() => {
                    info!("Unhandled Swarm Event: {:?}", event);
                    None
                },
            }
        };

        if let Some(event) = evt {
            log::info!("Event: {:?}", event);
            match event {
                EventType::Response(resp) => {
                    let json = serde_json::to_string(&resp).expect("can jsonify response");
                    swarm
                        .behaviour_mut()
                        .floodsub
                        .publish(TOPIC.clone(), json.as_bytes());
                }
                EventType::Input(line) => match line.as_str() {
                    "ls p" => handle_list_peers(&mut swarm).await,
                    cmd if cmd.starts_with("ping") => handle_ping(&mut swarm).await,
                    _ => error!("unknown command"),
                },
            }
        }
    }
}

async fn handle_ping(swarm: &mut Swarm<FrostBehaviour>) {
    info!("Sending Ping");
    let request = Request {
        request_type: EventRequestType::Ping,
        data: None,
    };
    let json = serde_json::to_string(&request).expect("can jsonify request");

    println!("json: {}", json);
    swarm
        .behaviour_mut()
        .floodsub
        .publish(TOPIC.clone(), json.as_bytes());
}

async fn handle_list_peers(swarm: &mut Swarm<FrostBehaviour>) {
    info!("Discovered Peers:");
    let nodes = swarm.behaviour().mdns.discovered_nodes();
    let mut unique_peers = HashSet::new();
    for peer in nodes {
        unique_peers.insert(peer);
    }
    unique_peers.iter().for_each(|p| info!("{}", p));
}
