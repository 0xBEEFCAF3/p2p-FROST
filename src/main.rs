use frost::Identifier;
use futures::stream::StreamExt;
use libp2p::gossipsub::{Event, Topic, TopicHash};
use libp2p::{gossipsub, mdns, noise, swarm::NetworkBehaviour, swarm::SwarmEvent, tcp, yamux};
use libp2p::{PeerId, Swarm};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::error::Error;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
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
    Round1Start,
    Round1Waiting,
    Round2Start,
    Round2Waiting,
    Round3,
    DkgFailed,
}

#[derive(Debug, Clone)]
struct DKGStateMachine {
    state: DKGState,
    min_signers: u16,
    max_signers: u16,
    personal_identifier: frost::Identifier,
    personal_secret_package: frost::keys::dkg::round1::SecretPackage,
    personal_round1_package: frost::keys::dkg::round1::Package,
    round1_group_packages: HashMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    round2_group_packages: HashMap<frost::Identifier, frost::keys::dkg::round2::Package>,
    round2_group_secret_package: Option<frost::keys::dkg::round2::SecretPackage>,
    key_package: Option<frost::keys::KeyPackage>,
    public_key_package: Option<frost::keys::PublicKeyPackage>,
}

fn peer_id_to_identifier(peer_id: &PeerId) -> frost::Identifier {
    frost::Identifier::derive(peer_id.to_bytes().as_ref()).expect("can derive identifier")
}

impl DKGStateMachine {
    pub fn new(min_signers: u16, max_signers: u16, peer_id: &PeerId) -> Self {
        let mut rng = thread_rng();
        let personal_identifier = peer_id_to_identifier(peer_id);
        info!("personal_identifier: {:?}", personal_identifier);
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
            round1_group_packages: HashMap::new(),
            round2_group_packages: HashMap::new(),
            round2_group_secret_package: None,
            key_package: None,
            public_key_package: None,
        }
    }
}

impl DKGStateMachine {
    fn next_state(&mut self, event: DKGEvent, swarm: &mut Swarm<FrostBehaviour>, topic: TopicHash) {
        match (self.state, event) {
            // Define state transitions based on events
            (DKGState::Initial, DKGEvent::Round1) => {
                self.state = DKGState::Round1Start;
                info!("Starting DKG, sending round 1 package to all peers");
                // Broadcast dkg round 1 package to all peers
                let response = Response {
                    response_type: EventResponseType::DkgRound1,
                    data: Some(self.personal_round1_package.clone()),
                    receiver: None,
                };
                let json = serde_json::to_string(&response).expect("can jsonify request");
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), json.as_bytes())
                    .unwrap();
                println!("Package send! {:?}", json);
                std::thread::sleep(std::time::Duration::from_secs(1));

                // Once the round 1 package is sent we are waiting
                self.state = DKGState::Round1Waiting;
                self.next_state(DKGEvent::Round1, swarm, topic);
            }
            (DKGState::Round1Waiting, DKGEvent::Round1)
            | (DKGState::Round1Waiting, DKGEvent::Round2) => {
                info!("Waiting for round 1 packages from other peers");
                info!("round1_group_packages: {:?}", self.round1_group_packages);
                // thread sleep for 1 second
                std::thread::sleep(std::time::Duration::from_secs(1));
                // Check if we are ready to progress to round 2
                if self.round1_group_packages.len() >= (self.max_signers - 1) as usize {
                    info!("Progressing to round 2");
                    self.state = DKGState::Round1Start;
                    self.next_state(DKGEvent::Round2, swarm, topic);
                    return;
                }
            }
            (DKGState::Round1Start, DKGEvent::Round2) => {
                info!("Attempting to start round 2");
                let (round2_secret_package, round2_packages) = frost::keys::dkg::part2(
                    self.personal_secret_package.clone(),
                    &self.round1_group_packages,
                )
                .expect("can start round 2");
                println!("round2_packages: {:?}", round2_packages);

                self.round2_group_secret_package = Some(round2_secret_package.clone());
                let response = Response {
                    response_type: EventResponseType::DkgRound2,
                    data: Some(round2_packages),
                    receiver: None,
                };
                let json = serde_json::to_string(&response).expect("can jsonify request");
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), json.as_bytes())
                    .unwrap();

                self.state = DKGState::Round2Waiting;
                self.next_state(DKGEvent::Round2, swarm, topic);
            }

            (DKGState::Round2Waiting, DKGEvent::Round2) => {
                info!("Waiting for round 2 packages from other peers");
                info!("round2_group_packages: {:?}", self.round2_group_packages);
                if self.round2_group_packages.len() >= (self.max_signers - 1) as usize {
                    info!("Progressing to round 3");
                    self.state = DKGState::Round3;
                    self.next_state(DKGEvent::Round3, swarm, topic);
                    return;
                }
                return;
            }

            (DKGState::Round3, DKGEvent::Round3) => {
                info!("Starting round 3");
                info!("round1 pkgs {:?}", self.round1_group_packages);
                info!("round2 pkgs {:?}", self.round2_group_packages);

                let (key_package, public_key_package) = frost::keys::dkg::part3(
                    &self
                        .round2_group_secret_package
                        .clone()
                        .expect("valid secret package "),
                    &self.round1_group_packages,
                    &self.round2_group_packages,
                )
                .unwrap();

                info!("key_package: {:?}", key_package);
                info!("pubkey_package: {:?}", public_key_package);
                self.key_package = Some(key_package.clone());
                self.public_key_package = Some(public_key_package.clone());
            }

            _ => panic!("Invalid transition"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigningState {
    Initial,
    Round1Start,
    Round1Waiting,
    Round2Start,
    Round2Waiting,
    Success,
    SigningFailed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SigningEvent {
    Start,
    Round1,
    Round2,
    SigningFailed,
}

struct SigningStateMachine {
    state: SigningState,
    is_cordinator: bool,
    personal_identifier: frost::Identifier,
    public_key_package: Option<frost::keys::PublicKeyPackage>,
    key_package: Option<frost::keys::KeyPackage>,
    signing_pacakge: Option<frost::SigningPackage>,
    message: Vec<u8>,
    signer_nonces: Option<frost::round1::SigningNonces>,
    peer_signature_shares: HashMap<frost::Identifier, frost::round2::SignatureShare>,
    peer_nonce_commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
}

impl SigningStateMachine {
    pub fn new(personal_identifier: frost::Identifier) -> Self {
        Self {
            state: SigningState::Initial,
            personal_identifier,
            is_cordinator: false,
            public_key_package: None,
            key_package: None,
            signing_pacakge: None,
            message: vec![],
            signer_nonces: None,
            peer_signature_shares: HashMap::new(),
            peer_nonce_commitments: BTreeMap::new(),
        }
    }

    pub fn update_fields_from_dkg_state_machine(&mut self, dkg_state_machine: &DKGStateMachine) {
        self.public_key_package = dkg_state_machine.public_key_package.clone();
        self.key_package = dkg_state_machine.key_package.clone();
    }

    pub fn set_is_cordinator(&mut self) {
        self.is_cordinator = true;
    }

    pub fn set_key_package(&mut self, key_package: frost::keys::KeyPackage) {
        self.key_package = Some(key_package);
    }

    pub fn set_public_key_package(&mut self, public_key_package: frost::keys::PublicKeyPackage) {
        self.public_key_package = Some(public_key_package);
    }

    pub fn set_message(&mut self, message: Vec<u8>) {
        self.message = message;
    }

    fn send_signing_package(&mut self, swarm: &mut Swarm<FrostBehaviour>, topic: TopicHash) {
        let signing_package = frost::SigningPackage::new(
            self.peer_nonce_commitments.clone(),
            self.message.as_slice().as_ref(),
        );
        self.signing_pacakge = Some(signing_package.clone());

        let response = Response {
            response_type: EventResponseType::SigningPackage,
            data: Some(signing_package),
            receiver: None,
        };
        let json = serde_json::to_string(&response).expect("can jsonify request");
        swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), json.as_bytes())
            .unwrap();
        info!("Signing Package send! {:?}", json);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    fn next_state(
        &mut self,
        event: SigningEvent,
        swarm: &mut Swarm<FrostBehaviour>,
        topic: TopicHash,
    ) {
        match (self.state, event) {
            (SigningState::Initial, SigningEvent::Round1) => {
                info!("Attempting to start round 1 of signing");
                if self.key_package.is_none() {
                    warn!("key package must be set before starting signing");
                    return;
                }
                self.state = SigningState::Round1Start;

                let signing_share = self
                    .key_package
                    .as_ref()
                    .expect("valid key package")
                    .secret_share();
                info!("Starting signing, sending round 1 nonce commitments to all peers");
                // Create and broadcast nonce commitments pairs to all peers
                let mut rng = thread_rng();
                let package = frost::round1::commit(signing_share, &mut rng);
                info!("package: {:?}", package.1);
                self.signer_nonces = Some(package.0);
                // Add my own commitment
                self.peer_nonce_commitments
                    .insert(self.personal_identifier.clone(), package.1.clone());

                let commitments = package.1;
                // Broadcast dkg round 1 package to all peers
                let response = Response {
                    response_type: EventResponseType::SigningRound1,
                    data: Some(commitments),
                    receiver: None,
                };
                let json = serde_json::to_string(&response).expect("can jsonify request");
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), json.as_bytes())
                    .unwrap();
                info!("Round 1 Package send! {:?}", json);
                std::thread::sleep(std::time::Duration::from_secs(1));

                // Once the round 1 commitments are sent we are waiting
                self.state = SigningState::Round1Waiting;
                self.next_state(SigningEvent::Round1, swarm, topic);
            }

            (SigningState::Round1Waiting, SigningEvent::Round1)
            | (SigningState::Round1Waiting, SigningEvent::Round2) => {
                // If we are the cordinator we are waiting for all other peers to send their commitments
                // If we are peer that is just signing we are waiting for the cordinator to signing package
                info!("Waiting for round 1 packages from other peers");
                info!("peer_nonce_commitments: {:?}", self.peer_nonce_commitments);
                if self.is_cordinator {
                    if self.peer_nonce_commitments.len()
                        >= (self
                            .key_package
                            .as_ref()
                            .expect("valid key package")
                            .min_signers())
                        .to_owned() as usize
                    {
                        info!("Progressing to round 2");
                        self.state = SigningState::Round2Start;
                        // As the cordinator we have to send out the signing package
                        self.send_signing_package(swarm, topic.clone());
                        self.next_state(SigningEvent::Round2, swarm, topic);
                        return;
                    }
                } else {
                    if self.signing_pacakge.is_some() {
                        info!("Progressing to round 2");
                        self.state = SigningState::Round2Start;
                        self.next_state(SigningEvent::Round2, swarm, topic);
                        return;
                    }
                }
            }
            (SigningState::Round2Start, SigningEvent::Round2) => {
                info!("Signing: Attempting to start round 2");
                if self.key_package.is_none() {
                    warn!("Key package must be set before starting signing");
                    return;
                }
                if self.public_key_package.is_none() {
                    warn!("Public key package must be set before starting signing");
                    return;
                }
                if self.signer_nonces.is_none() {
                    warn!("Signer nonces must be set before starting signing");
                    return;
                }
                if self.signing_pacakge.is_none() {
                    warn!("Signing package must be set before starting signing");
                    return;
                }

                let mut rng = thread_rng();

                let signature = frost::round2::sign(
                    &self
                        .signing_pacakge
                        .as_mut()
                        .expect("valid signing package"),
                    &self.signer_nonces.as_mut().expect("signer nonces"),
                    &self.key_package.as_mut().expect("valid key package"),
                )
                .expect("valid signature");

                self.peer_signature_shares
                    .insert(self.personal_identifier.clone(), signature.clone());

                let response = Response {
                    response_type: EventResponseType::SigningRound2,
                    data: Some(signature),
                    receiver: None,
                };
                let json = serde_json::to_string(&response).expect("can jsonify request");

                swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(topic.clone(), json.as_bytes())
                    .unwrap();
                self.state = SigningState::Round2Waiting;

                info!("Signature share: {:?}", signature);
                // self.public_key_package.group_public().verify(self.signing_pacakge.as_slice(), signature).expect("valid signature");gg254
            }

            (SigningState::Round2Waiting, SigningEvent::Round2) => {
                info!("Waiting for round 2 partial signatures from other peers");
                info!("peer_signature_shares: {:?}", self.peer_signature_shares);
                if self.peer_signature_shares.len()
                    >= (self
                        .key_package
                        .as_ref()
                        .expect("valid key package")
                        .min_signers())
                    .to_owned() as usize
                {
                    info!("Progressing to success");
                    // Any peer can construct the signature share b/c they are all broadcasted
                    self.state = SigningState::Success;
                    let group_signature = frost::aggregate(
                        &self
                            .signing_pacakge
                            .as_ref()
                            .expect("valid signing package"),
                        &self.peer_signature_shares,
                        &self.public_key_package.as_ref().expect("pub key package"),
                    )
                    .unwrap();
                    info!("group_signature: {:?}", group_signature);
                    self.public_key_package
                        .as_ref()
                        .expect("valid pub key package")
                        .group_public()
                        .verify(&self.message.as_slice(), &group_signature)
                        .unwrap();

                    info!("Signature verified!");

                    return;
                }
            }

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
    DkgRound2,
    DkgRound3,
    SigningPackage,
    SigningRound1,
    SigningRound2,
}

impl FromStr for EventResponseType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Pong" => Ok(EventResponseType::Pong),
            "DkgRound1" => Ok(EventResponseType::DkgRound1),
            "DkgRound2" => Ok(EventResponseType::DkgRound2),
            "DkgRound3" => Ok(EventResponseType::DkgRound3),
            "SigningRound1" => Ok(EventResponseType::SigningRound1),
            "SigningRound2" => Ok(EventResponseType::SigningRound2),
            "SigningPackage" => Ok(EventResponseType::SigningPackage),
            _ => Err(()),
        }
    }
}

struct DKGRound1ResponsePackage {
    from_peer_id: String,
    package: frost::keys::dkg::round1::Package,
}

struct DKGRound2ResponsePackage {
    intended_peer_id: String,
    package: frost::keys::dkg::round2::Package,
}

#[derive(Debug, Serialize, Deserialize)]
struct Response<T> {
    response_type: EventResponseType,
    data: Option<T>,
    // peer id for who should recieve, optional if this is a broadcast to all peers
    receiver: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum EventRequestType {
    Ping,
    SigningRound1,
}

impl FromStr for EventRequestType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Ping" => Ok(EventRequestType::Ping),
            _ => Err(()),
        }
    }
}

// Request structs
#[derive(Debug, Serialize, Deserialize)]
struct Request<T> {
    request_type: EventRequestType,
    data: Option<T>,
}

async fn handle_signing_round1_request<H: libp2p::gossipsub::Hasher>(
    swarm: &mut Swarm<FrostBehaviour>,
    topic: Topic<H>,
) {
    info!("Sending signing round 1 request");
    let request: Request<Option<String>> = Request {
        request_type: EventRequestType::SigningRound1,
        data: None,
    };
    let json = serde_json::to_string(&request).expect("can jsonify request");
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, json.as_bytes())
        .unwrap();
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
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, json.as_bytes())
        .unwrap();
}

async fn handle_pong(swarm: &mut Swarm<FrostBehaviour>, topic: TopicHash, peer_id: PeerId) {
    info!("Sending Pong");
    let request: Response<Option<String>> = Response {
        response_type: EventResponseType::Pong,
        receiver: Some(peer_id.to_string()),
        data: None,
    };
    let json = serde_json::to_string(&request).expect("can jsonify request");
    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, json.as_bytes())
        .unwrap();
}

enum RequestResponseParsingError {
    UnableToParse,
    CouldNotParseRound1Package,
    CouldNotParseRound2Package,
    CouldNotParseSigningPackage,
}

async fn handle_request(
    payload: Vec<u8>,
    dkg_state_machine: &mut DKGStateMachine,
    swarm: &mut Swarm<FrostBehaviour>,
    topic: TopicHash,
    peer_id: PeerId,
) -> Result<(), RequestResponseParsingError> {
    if peer_id == *swarm.local_peer_id() {
        debug!("Got our own request back, skipping");
        return Ok(());
    }
    let parsed: Value =
        serde_json::from_slice(&payload).map_err(|e| RequestResponseParsingError::UnableToParse)?;
    if let Some(request_type) = parsed.get("request_type").and_then(|v| v.as_str()) {
        // parse back into enum variant
        let req_type = request_type
            .parse::<EventRequestType>()
            .map_err(|e| RequestResponseParsingError::UnableToParse)?;

        match req_type {
            EventRequestType::Ping => {
                info!("Got ping from peer: {peer_id}");
                handle_pong(swarm, topic, peer_id).await;
            }
            EventRequestType::SigningRound1 => {
                info!("Got signing round 1 request from peer: {peer_id}");
                if peer_id == *swarm.local_peer_id() {
                    debug!("Got our own round 1 request back");
                    return Ok(());
                }
            }
        }
        return Ok(());
    }

    Err(RequestResponseParsingError::UnableToParse)
}

async fn handle_response(
    payload: Vec<u8>,
    dkg_state_machine: &mut DKGStateMachine,
    signing_state_machine: &mut SigningStateMachine,
    swarm: &mut Swarm<FrostBehaviour>,
    topic: TopicHash,
    peer_id: PeerId,
) -> Result<(), RequestResponseParsingError> {
    let parsed: Value =
        serde_json::from_slice(&payload).map_err(|e| RequestResponseParsingError::UnableToParse)?;
    if let Some(request_type) = parsed.get("response_type").and_then(|v| v.as_str()) {
        // parse back into enum variant
        let resp_type = request_type
            .parse::<EventResponseType>()
            .map_err(|e| RequestResponseParsingError::UnableToParse)?;

        debug!("resp_type: {:?}", resp_type);
        let value = parsed.get("data").expect("can get data").to_string();
        let package_bytes = value.as_bytes();
        match resp_type {
            EventResponseType::Pong => {
                info!("Got pong from peer: {peer_id}");
                // Nothing else to do
            }
            EventResponseType::DkgRound1 => {
                info!("Got DKG round 1 from peer: {peer_id}");
                if peer_id == *swarm.local_peer_id() {
                    debug!("Got our own round 1 package back");
                    // This package should already be in our list
                    return Ok(());
                }

                let package: frost::keys::dkg::round1::Package =
                    serde_json::from_slice(package_bytes).map_err(|e| {
                        println!("Unable to parse round 1 package: {:?}", e);
                        RequestResponseParsingError::CouldNotParseRound1Package
                    })?;
                dkg_state_machine
                    .round1_group_packages
                    .insert(peer_id_to_identifier(&peer_id), package);
                dkg_state_machine.next_state(DKGEvent::Round1, swarm, topic);
            }
            EventResponseType::DkgRound2 => {
                info!("Got DKG round 2 from peer: {peer_id}");
                // Check if this is intended for us
                // let receipeint = parsed
                //     .get("intended_peer_id")
                //     .expect("can get receipeint")
                //     .as_str()
                //     .expect("can get receipeint")
                //     .to_string();
                // info!("receipeint: {:?}", receipeint);
                // if receipeint != swarm.local_peer_id().to_string() {
                //     return Ok(());
                // }
                let package: HashMap<Identifier, frost::keys::dkg::round2::Package> =
                    serde_json::from_slice(package_bytes).map_err(|e| {
                        println!("Unable to parse round 2 package: {:?}", e);
                        RequestResponseParsingError::CouldNotParseRound1Package
                    })?;

                info!("package: {:?}", package);
                for id in package.keys() {
                    info!("id: {:?}", id);
                    dkg_state_machine
                        .round2_group_packages
                        // TODO filter id when it matches your peer id / indentifier
                        .insert(peer_id_to_identifier(&peer_id), package[id].clone());
                }
                dkg_state_machine.next_state(DKGEvent::Round2, swarm, topic);
            }
            EventResponseType::DkgRound3 => {
                todo!()
            }
            EventResponseType::SigningPackage => {
                info!("Got signing package from: {peer_id}");
                let signing_package: frost::SigningPackage = serde_json::from_slice(package_bytes)
                    .map_err(|e| {
                        println!("Unable to signing package: {:?}", e);
                        RequestResponseParsingError::CouldNotParseRound1Package
                    })?;

                signing_state_machine.signing_pacakge = Some(signing_package.clone());
                signing_state_machine.next_state(SigningEvent::Round2, swarm, topic);
            }

            EventResponseType::SigningRound1 => {
                info!("Got signing round 1 from peer: {peer_id}");
                if peer_id == *swarm.local_peer_id() {
                    debug!("Got our own round 1 package back");
                    // This package should already be in our list
                    return Ok(());
                }
                let nonce_pair: frost::round1::SigningCommitments =
                    serde_json::from_slice(package_bytes).map_err(|e| {
                        println!("Unable to parse round 1 package: {:?}", e);
                        RequestResponseParsingError::CouldNotParseRound1Package
                    })?;
                info!("nonce_pair: {:?}", nonce_pair);
                // set the signing packages
                signing_state_machine.update_fields_from_dkg_state_machine(dkg_state_machine);
                signing_state_machine
                    .peer_nonce_commitments
                    .insert(peer_id_to_identifier(&peer_id), nonce_pair.clone());
                signing_state_machine.next_state(SigningEvent::Round1, swarm, topic);
            }
            EventResponseType::SigningRound2 => {
                info!("Got signing round 2 from peer: {peer_id}");
                let signature: frost::round2::SignatureShare =
                    serde_json::from_slice(package_bytes).map_err(|e| {
                        println!("Unable to parse round 2 package: {:?}", e);
                        RequestResponseParsingError::CouldNotParseRound2Package
                    })?;
                info!("signature: {:?}", signature);
                // set the signing packages
                signing_state_machine
                    .peer_signature_shares
                    .insert(peer_id_to_identifier(&peer_id), signature.clone());
                signing_state_machine.next_state(SigningEvent::Round2, swarm, topic);
            }
            _ => {
                panic!("Invalid response type")
            }
        }
        return Ok(());
    }

    Err(RequestResponseParsingError::UnableToParse)
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
    let dkg_state_machine = &mut DKGStateMachine::new(2, 2, &swarm.local_peer_id());
    let signing_state_machine =
        &mut SigningStateMachine::new(dkg_state_machine.personal_identifier.clone());

    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    info!("Enter messages via STDIN");
    info!("Type 'ls p' to list connected peers");
    info!("Type 'ping' to send a ping to all peers");
    info!("Type 'dkg' to start the DKG process");
    info!("Type 'sign <message>' to sign a message");

    // Kick it off
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                if line.starts_with("sign") {
                    if (dkg_state_machine.public_key_package.is_none()) {
                        warn!("Key generation step must be performed first");
                        continue;
                    }
                    if let Some(rest) = line.strip_prefix("sign") {
                        let message = rest.trim();
                        if message.is_empty() {
                            warn!("Message must not be empty");
                            continue;
                        }
                        info!("Signing message: {}", message);
                        // Set that we are cordinating the singing effor
                        signing_state_machine.set_is_cordinator();
                        signing_state_machine.update_fields_from_dkg_state_machine(dkg_state_machine);
                        signing_state_machine.set_message(message.as_bytes().to_vec());
                        signing_state_machine.next_state(SigningEvent::Round1, &mut swarm, topic.hash());

                    }
                    continue;
                }
                match line.as_str() {
                    "ls p" => {
                        info!("Connected peers:");
                        for peer in swarm.behaviour_mut().gossipsub.all_peers() {
                            info!("{:?}", peer);
                        }
                    }
                    "ping" => {
                        handle_ping(&mut swarm, topic.clone()).await;
                    }
                    "dkg" => {
                        dkg_state_machine.next_state(DKGEvent::Round1, &mut swarm, topic.hash());
                    }
                    _ => println!("Sending message: {}", line),
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
                    if let Ok(_) = handle_request(message.data.clone(), dkg_state_machine, &mut swarm, topic.hash(), peer_id).await {
                        info!("Successfully handled request");
                    } else if let Ok(_) = handle_response(message.data.clone(), dkg_state_machine, signing_state_machine, &mut swarm, topic.hash(), peer_id).await {
                        info!("Successfully handled response");
                    } else {
                        info!("Unable to handle request or response");
                    }
                },

                _ => {}
            }
        }
    }
}
