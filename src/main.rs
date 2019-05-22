mod printer;
mod reader;
mod peer;
mod timeout_stream;
mod datastore;

use std::{cmp, env};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{Ordering, AtomicBool};
use std::time::{Duration, Instant};
use std::net::{SocketAddr, ToSocketAddrs};

use bitcoin_hashes::sha256d;

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message_blockdata::{GetHeadersMessage, Inventory, InvType};
use bitcoin::util::hash::BitcoinHash;

use printer::{Printer, Stat};
use peer::Peer;
use datastore::{AddressState, Store, U64Setting, RegexSetting};
use timeout_stream::TimeoutStream;

use tokio::prelude::*;
use tokio::timer::Delay;

static mut HIGHEST_HEADER: Option<Box<Mutex<(sha256d::Hash, u64)>>> = None;
static mut HEADER_MAP: Option<Box<Mutex<HashMap<sha256d::Hash, u64>>>> = None;
static mut HEIGHT_MAP: Option<Box<Mutex<HashMap<u64, sha256d::Hash>>>> = None;
static mut DATA_STORE: Option<Box<Store>> = None;
static mut PRINTER: Option<Box<Printer>> = None;
pub static START_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static SCANNING: AtomicBool = AtomicBool::new(false);

struct PeerState {
	request: (u64, sha256d::Hash),
	node_services: u64,
	msg: (String, bool),
	fail_reason: AddressState,
	recvd_version: bool,
	recvd_verack: bool,
	recvd_addrs: bool,
	recvd_block: bool,
}

pub fn scan_node(scan_time: Instant, node: SocketAddr) {
	if START_SHUTDOWN.load(Ordering::Relaxed) { return; }
	let printer = unsafe { PRINTER.as_ref().unwrap() };
	let store = unsafe { DATA_STORE.as_ref().unwrap() };

	let peer_state = Arc::new(Mutex::new(PeerState {
		recvd_version: false,
		recvd_verack: false,
		recvd_addrs: false,
		recvd_block: false,
		node_services: 0,
		fail_reason: AddressState::Timeout,
		msg: (String::new(), false),
		request: (0, Default::default()),
	}));
	let final_peer_state = Arc::clone(&peer_state);

	let peer = Delay::new(scan_time).then(move |_| {
		printer.set_stat(Stat::NewConnection);
		let timeout = store.get_u64(U64Setting::RunTimeout);
		Peer::new(node.clone(), Duration::from_secs(timeout), printer)
	});
	tokio::spawn(peer.and_then(move |(mut write, read)| {
		let requested_height = unsafe { HIGHEST_HEADER.as_ref().unwrap() }.lock().unwrap().1 - 1008;
		let requested_block = unsafe { HEIGHT_MAP.as_ref().unwrap() }.lock().unwrap().get(&requested_height).unwrap().clone();
		peer_state.lock().unwrap().request = (requested_height, requested_block);

		TimeoutStream::new_timeout(read, scan_time + Duration::from_secs(store.get_u64(U64Setting::RunTimeout))).map_err(|_| { () }).for_each(move |msg| {
			let mut state_lock = peer_state.lock().unwrap();
			macro_rules! check_set_flag {
				($recvd_flag: ident, $msg: expr) => { {
					if state_lock.$recvd_flag {
						state_lock.fail_reason = AddressState::ProtocolViolation;
						state_lock.msg = (format!("ProtocolViolation due to dup {}", $msg), true);
						state_lock.$recvd_flag = false;
						return future::err(());
					}
					state_lock.$recvd_flag = true;
				} }
			}
			state_lock.fail_reason = AddressState::TimeoutDuringRequest;
			match msg {
				NetworkMessage::Version(ver) => {
					if ver.start_height < 0 || ver.start_height as u64 > state_lock.request.0 + 1008*2 {
						state_lock.fail_reason = AddressState::HighBlockCount;
						return future::err(());
					}
					let safe_ua = ver.user_agent.replace(|c: char| !c.is_ascii() || c < ' ' || c > '~', "");
					if (ver.start_height as u64) < state_lock.request.0 {
						state_lock.msg = (format!("LowBlockCount ({} < {})", ver.start_height, state_lock.request.0), true);
						state_lock.fail_reason = AddressState::LowBlockCount;
						return future::err(());
					}
					let min_version = store.get_u64(U64Setting::MinProtocolVersion);
					if (ver.version as u64) < min_version {
						state_lock.msg = (format!("LowVersion ({} < {})", ver.version, min_version), true);
						state_lock.fail_reason = AddressState::LowVersion;
						return future::err(());
					}
					if ver.services & (1 | (1 << 10)) == 0 {
						state_lock.msg = (format!("NotFullNode ({}: services {:x})", safe_ua, ver.services), true);
						state_lock.fail_reason = AddressState::NotFullNode;
						return future::err(());
					}
					if !store.get_regex(RegexSetting::SubverRegex).is_match(&ver.user_agent) {
						state_lock.msg = (format!("BadVersion subver {}", safe_ua), true);
						state_lock.fail_reason = AddressState::BadVersion;
						return future::err(());
					}
					check_set_flag!(recvd_version, "version");
					state_lock.node_services = ver.services;
					state_lock.msg = (format!("to Good: {}", safe_ua), false);
					if let Err(_) = write.try_send(NetworkMessage::Verack) {
						return future::err(());
					}
				},
				NetworkMessage::Verack => {
					check_set_flag!(recvd_verack, "verack");
					if let Err(_) = write.try_send(NetworkMessage::GetAddr) {
						return future::err(());
					}
				},
				NetworkMessage::Ping(v) => {
					if let Err(_) = write.try_send(NetworkMessage::Pong(v)) {
						return future::err(())
					}
				},
				NetworkMessage::Addr(addrs) => {
					if addrs.len() > 1000 {
						state_lock.fail_reason = AddressState::ProtocolViolation;
						state_lock.msg = (format!("ProtocolViolation due to oversized addr: {}", addrs.len()), true);
						state_lock.recvd_addrs = false;
						return future::err(());
					}
					if !state_lock.recvd_addrs {
						if let Err(_) = write.try_send(NetworkMessage::GetData(vec![Inventory {
							inv_type: InvType::WitnessBlock,
							hash: state_lock.request.1,
						}])) {
							return future::err(());
						}
					}
					state_lock.recvd_addrs = true;
					unsafe { DATA_STORE.as_ref().unwrap() }.add_fresh_nodes(&addrs);
				},
				NetworkMessage::Block(block) => {
					if block.header.bitcoin_hash() != state_lock.request.1 ||
							!block.check_merkle_root() || !block.check_witness_commitment() {
						state_lock.fail_reason = AddressState::ProtocolViolation;
						state_lock.msg = ("ProtocolViolation due to bad block".to_string(), true);
						return future::err(());
					}
					check_set_flag!(recvd_block, "block");
				},
				_ => {},
			}
			future::ok(())
		}).then(|_| {
			future::err(())
		})
	}).then(move |_: Result<(), ()>| {
		let printer = unsafe { PRINTER.as_ref().unwrap() };
		let store = unsafe { DATA_STORE.as_ref().unwrap() };
		printer.set_stat(Stat::ConnectionClosed);

		let state_lock = final_peer_state.lock().unwrap();
		if state_lock.recvd_version && state_lock.recvd_verack &&
				state_lock.recvd_addrs && state_lock.recvd_block {
			let old_state = store.set_node_state(node, AddressState::Good, state_lock.node_services);
			if old_state != AddressState::Good && state_lock.msg.0 != "" {
				printer.add_line(format!("Updating {} from {} to {}", node, old_state.to_str(), &state_lock.msg.0), state_lock.msg.1);
			}
		} else {
			assert!(state_lock.fail_reason != AddressState::Good);
			let old_state = store.set_node_state(node, state_lock.fail_reason, 0);
			if old_state != state_lock.fail_reason && state_lock.msg.0 != "" && state_lock.msg.1 {
				printer.add_line(format!("Updating {} from {} to {}", node, old_state.to_str(), &state_lock.msg.0), state_lock.msg.1);
			} else if old_state != state_lock.fail_reason && state_lock.fail_reason == AddressState::TimeoutDuringRequest {
				printer.add_line(format!("Updating {} from {} to Timeout During Request (ver: {}, vack: {}, addr: {}, block: {})",
					node, old_state.to_str(), state_lock.recvd_version, state_lock.recvd_verack, state_lock.recvd_addrs, state_lock.recvd_block), true);
			}
		}
		future::ok(())
	}));
}

fn poll_dnsseeds() {
	tokio::spawn(future::lazy(|| {
		let printer = unsafe { PRINTER.as_ref().unwrap() };
		let store = unsafe { DATA_STORE.as_ref().unwrap() };

		let mut new_addrs = 0;
		for seed in ["seed.bitcoin.sipa.be", "dnsseed.bitcoin.dashjr.org", "seed.bitcoinstats.com", "seed.bitcoin.jonasschnelli.ch", "seed.btc.petertodd.org", "seed.bitcoin.sprovoost.nl", "dnsseed.emzy.de"].iter() {
			new_addrs += store.add_fresh_addrs((*seed, 8333u16).to_socket_addrs().unwrap_or(Vec::new().into_iter()));
			new_addrs += store.add_fresh_addrs((("x9.".to_string() + seed).as_str(), 8333u16).to_socket_addrs().unwrap_or(Vec::new().into_iter()));
		}
		printer.add_line(format!("Added {} new addresses from other DNS seeds", new_addrs), false);
		Delay::new(Instant::now() + Duration::from_secs(60)).then(|_| {
			if !START_SHUTDOWN.load(Ordering::Relaxed) {
				poll_dnsseeds();
			}
			future::ok(())
		})
	}));
}

fn scan_net() {
	tokio::spawn(future::lazy(|| {
		let store = unsafe { DATA_STORE.as_ref().unwrap() };

		let mut scan_nodes = store.get_next_scan_nodes();
		let per_iter_time = Duration::from_millis(1000 / store.get_u64(U64Setting::ConnsPerSec));
		let start_time = Instant::now();
		let mut iter_time = start_time;

		for node in scan_nodes.drain(..) {
			scan_node(iter_time, node);
			iter_time += per_iter_time;
		}
		Delay::new(cmp::max(iter_time, start_time + Duration::from_secs(15))).then(|_| {
			let store = unsafe { DATA_STORE.as_ref().unwrap() };
			store.save_data().then(|_| {
				if !START_SHUTDOWN.load(Ordering::Relaxed) {
					scan_net();
				}
				future::ok(())
			})
		})
	}));
}

fn make_trusted_conn(trusted_sockaddr: SocketAddr) {
	let printer = unsafe { PRINTER.as_ref().unwrap() };
	let trusted_peer = Peer::new(trusted_sockaddr.clone(), Duration::from_secs(600), printer);
	tokio::spawn(trusted_peer.and_then(move |(mut trusted_write, trusted_read)| {
		printer.add_line("Connected to local peer".to_string(), false);
		let mut starting_height = 0;
		TimeoutStream::new_persistent(trusted_read, Duration::from_secs(600)).map_err(|_| { () }).for_each(move |msg| {
			if START_SHUTDOWN.load(Ordering::Relaxed) {
				return future::err(());
			}
			match msg {
				NetworkMessage::Version(ver) => {
					if let Err(_) = trusted_write.try_send(NetworkMessage::Verack) {
						return future::err(())
					}
					starting_height = ver.start_height;
				},
				NetworkMessage::Verack => {
					if let Err(_) = trusted_write.try_send(NetworkMessage::SendHeaders) {
						return future::err(());
					}
					if let Err(_) = trusted_write.try_send(NetworkMessage::GetHeaders(GetHeadersMessage {
						version: 70015,
						locator_hashes: vec![unsafe { HIGHEST_HEADER.as_ref().unwrap() }.lock().unwrap().0.clone()],
						stop_hash: Default::default(),
					})) {
						return future::err(());
					}
					if let Err(_) = trusted_write.try_send(NetworkMessage::GetAddr) {
						return future::err(());
					}
				},
				NetworkMessage::Addr(addrs) => {
					unsafe { DATA_STORE.as_ref().unwrap() }.add_fresh_nodes(&addrs);
				},
				NetworkMessage::Headers(headers) => {
					if headers.is_empty() {
						return future::ok(());
					}
					let mut header_map = unsafe { HEADER_MAP.as_ref().unwrap() }.lock().unwrap();
					let mut height_map = unsafe { HEIGHT_MAP.as_ref().unwrap() }.lock().unwrap();
					if let Some(height) = header_map.get(&headers[0].prev_blockhash).cloned() {
						for i in 0..headers.len() {
							let hash = headers[i].bitcoin_hash();
							if i < headers.len() - 1 && headers[i + 1].prev_blockhash != hash {
								return future::err(());
							}
							header_map.insert(headers[i].bitcoin_hash(), height + 1 + (i as u64));
							height_map.insert(height + 1 + (i as u64), headers[i].bitcoin_hash());
						}
						let top_height = height + headers.len() as u64;
						*unsafe { HIGHEST_HEADER.as_ref().unwrap() }.lock().unwrap()
							= (headers.last().unwrap().bitcoin_hash(), top_height);
						printer.set_stat(printer::Stat::HeaderCount(top_height));
						if top_height >= starting_height as u64 {
							if !SCANNING.swap(true, Ordering::SeqCst) {
								scan_net();
								poll_dnsseeds();
							}
						}
					} else {
						// Wat? Lets start again...
						printer.add_line("Got unconnected headers message from local trusted peer".to_string(), true);
					}
					if let Err(_) = trusted_write.try_send(NetworkMessage::GetHeaders(GetHeadersMessage {
						version: 70015,
						locator_hashes: vec![unsafe { HIGHEST_HEADER.as_ref().unwrap() }.lock().unwrap().0.clone()],
						stop_hash: Default::default(),
					})) {
						return future::err(())
					}
				},
				NetworkMessage::Ping(v) => {
					if let Err(_) = trusted_write.try_send(NetworkMessage::Pong(v)) {
						return future::err(())
					}
				},
				_ => {},
			}
			future::ok(())
		}).then(|_| {
			future::err(())
		})
	}).then(move |_: Result<(), ()>| {
		if !START_SHUTDOWN.load(Ordering::Relaxed) {
			printer.add_line("Lost connection from trusted peer".to_string(), true);
			make_trusted_conn(trusted_sockaddr);
		}
		future::ok(())
	}));
}

fn main() {
	if env::args().len() != 3 {
		println!("USAGE: dnsseed-rust datastore localPeerAddress");
		return;
	}

	unsafe { HEADER_MAP = Some(Box::new(Mutex::new(HashMap::with_capacity(600000)))) };
	unsafe { HEIGHT_MAP = Some(Box::new(Mutex::new(HashMap::with_capacity(600000)))) };
	unsafe { HEADER_MAP.as_ref().unwrap() }.lock().unwrap().insert(genesis_block(Network::Bitcoin).bitcoin_hash(), 0);
	unsafe { HEIGHT_MAP.as_ref().unwrap() }.lock().unwrap().insert(0, genesis_block(Network::Bitcoin).bitcoin_hash());
	unsafe { HIGHEST_HEADER = Some(Box::new(Mutex::new((genesis_block(Network::Bitcoin).bitcoin_hash(), 0)))) };

	tokio::run(future::lazy(|| {
		let mut args = env::args();
		args.next();
		let path = args.next().unwrap();
		let addr = args.next().unwrap();

		Store::new(path).and_then(move |store| {
			unsafe { DATA_STORE = Some(Box::new(store)) };
			let store = unsafe { DATA_STORE.as_ref().unwrap() };
			unsafe { PRINTER = Some(Box::new(Printer::new(store))) };

			let trusted_sockaddr: SocketAddr = addr.parse().unwrap();
			make_trusted_conn(trusted_sockaddr);

			reader::read(store, unsafe { PRINTER.as_ref().unwrap() });

			future::ok(())
		}).or_else(|_| {
			future::err(())
		})
	}));

	tokio::run(future::lazy(|| {
		unsafe { DATA_STORE.as_ref().unwrap() }.save_data()
	}));
}
