mod printer;
mod reader;
mod peer;
mod bgp_client;
mod timeout_stream;
mod datastore;

use std::{cmp, env};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{Ordering, AtomicBool};
use std::time::{Duration, Instant};
use std::net::{SocketAddr, ToSocketAddrs};

use bitcoin_hashes::sha256d;

use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::network::constants::Network;
use bitcoin::network::message::NetworkMessage;
use bitcoin::network::message_blockdata::{GetHeadersMessage, Inventory, InvType};
use bitcoin::util::hash::BitcoinHash;

use printer::{Printer, Stat};
use peer::Peer;
use datastore::{AddressState, Store, U64Setting, RegexSetting};
use timeout_stream::TimeoutStream;
use rand::Rng;
use bgp_client::BGPClient;

use tokio::prelude::*;
use tokio::timer::Delay;

static mut REQUEST_BLOCK: Option<Box<Mutex<Arc<(u64, sha256d::Hash, Block)>>>> = None;
static mut HIGHEST_HEADER: Option<Box<Mutex<(sha256d::Hash, u64)>>> = None;
static mut HEADER_MAP: Option<Box<Mutex<HashMap<sha256d::Hash, u64>>>> = None;
static mut HEIGHT_MAP: Option<Box<Mutex<HashMap<u64, sha256d::Hash>>>> = None;
static mut DATA_STORE: Option<Box<Store>> = None;
static mut PRINTER: Option<Box<Printer>> = None;
pub static START_SHUTDOWN: AtomicBool = AtomicBool::new(false);
static SCANNING: AtomicBool = AtomicBool::new(false);

struct PeerState {
	request: Arc<(u64, sha256d::Hash, Block)>,
	node_services: u64,
	msg: (String, bool),
	fail_reason: AddressState,
	recvd_version: bool,
	recvd_verack: bool,
	recvd_pong: bool,
	recvd_addrs: bool,
	recvd_block: bool,
	pong_nonce: u64,
}

pub fn scan_node(scan_time: Instant, node: SocketAddr, manual: bool) {
	if START_SHUTDOWN.load(Ordering::Relaxed) { return; }
	let printer = unsafe { PRINTER.as_ref().unwrap() };
	let store = unsafe { DATA_STORE.as_ref().unwrap() };

	let mut rng = rand::thread_rng();
	let peer_state = Arc::new(Mutex::new(PeerState {
		recvd_version: false,
		recvd_verack: false,
		recvd_pong: false,
		recvd_addrs: false,
		recvd_block: false,
		pong_nonce: rng.gen(),
		node_services: 0,
		fail_reason: AddressState::Timeout,
		msg: (String::new(), false),
		request: Arc::clone(&unsafe { REQUEST_BLOCK.as_ref().unwrap() }.lock().unwrap()),
	}));
	let err_peer_state = Arc::clone(&peer_state);
	let final_peer_state = Arc::clone(&peer_state);

	let peer = Delay::new(scan_time).then(move |_| {
		printer.set_stat(Stat::NewConnection);
		let timeout = store.get_u64(U64Setting::RunTimeout);
		Peer::new(node.clone(), Duration::from_secs(timeout), printer)
	});
	tokio::spawn(peer.and_then(move |(mut write, read)| {
		TimeoutStream::new_timeout(read, scan_time + Duration::from_secs(store.get_u64(U64Setting::RunTimeout))).map_err(move |err| {
			match err {
				bitcoin::consensus::encode::Error::UnrecognizedNetworkCommand(ref msg) => {
					// If we got here, we hit one of the explicitly disallowed messages indicating
					// a bogus "node".
					let mut state_lock = err_peer_state.lock().unwrap();
					state_lock.msg = (format!("(bad msg type {})", msg), true);
					state_lock.fail_reason = AddressState::EvilNode;
				},
				_ => {},
			}
			()
		}).for_each(move |msg| {
			let mut state_lock = peer_state.lock().unwrap();
			macro_rules! check_set_flag {
				($recvd_flag: ident, $msg: expr) => { {
					if state_lock.$recvd_flag {
						state_lock.fail_reason = AddressState::ProtocolViolation;
						state_lock.msg = (format!("due to dup {}", $msg), true);
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
						state_lock.msg = (format!("({} < {})", ver.start_height, state_lock.request.0), true);
						state_lock.fail_reason = AddressState::LowBlockCount;
						return future::err(());
					}
					let min_version = store.get_u64(U64Setting::MinProtocolVersion);
					if (ver.version as u64) < min_version {
						state_lock.msg = (format!("({} < {})", ver.version, min_version), true);
						state_lock.fail_reason = AddressState::LowVersion;
						return future::err(());
					}
					if ver.services & (1 | (1 << 10)) == 0 {
						state_lock.msg = (format!("({}: services {:x})", safe_ua, ver.services), true);
						state_lock.fail_reason = AddressState::NotFullNode;
						return future::err(());
					}
					if !store.get_regex(RegexSetting::SubverRegex).is_match(&ver.user_agent) {
						state_lock.msg = (format!("subver {}", safe_ua), true);
						state_lock.fail_reason = AddressState::BadVersion;
						return future::err(());
					}
					check_set_flag!(recvd_version, "version");
					state_lock.node_services = ver.services;
					state_lock.msg = (format!("(subver: {})", safe_ua), false);
					if let Err(_) = write.try_send(NetworkMessage::Verack) {
						return future::err(());
					}
				},
				NetworkMessage::Verack => {
					check_set_flag!(recvd_verack, "verack");
					if let Err(_) = write.try_send(NetworkMessage::Ping(state_lock.pong_nonce)) {
						return future::err(());
					}
				},
				NetworkMessage::Ping(v) => {
					if let Err(_) = write.try_send(NetworkMessage::Pong(v)) {
						return future::err(())
					}
				},
				NetworkMessage::Pong(v) => {
					if v != state_lock.pong_nonce {
						state_lock.fail_reason = AddressState::ProtocolViolation;
						state_lock.msg = ("due to invalid pong nonce".to_string(), true);
						return future::err(());
					}
					check_set_flag!(recvd_pong, "pong");
					if let Err(_) = write.try_send(NetworkMessage::GetAddr) {
						return future::err(());
					}
				},
				NetworkMessage::Addr(addrs) => {
					if addrs.len() > 1000 {
						state_lock.fail_reason = AddressState::ProtocolViolation;
						state_lock.msg = (format!("due to oversized addr: {}", addrs.len()), true);
						state_lock.recvd_addrs = false;
						return future::err(());
					}
					if addrs.len() > 10 {
						if !state_lock.recvd_addrs {
							if let Err(_) = write.try_send(NetworkMessage::GetData(vec![Inventory {
								inv_type: InvType::WitnessBlock,
								hash: state_lock.request.1,
							}])) {
								return future::err(());
							}
						}
						state_lock.recvd_addrs = true;
					}
					unsafe { DATA_STORE.as_ref().unwrap() }.add_fresh_nodes(&addrs);
				},
				NetworkMessage::Block(block) => {
					if block != state_lock.request.2 {
						state_lock.fail_reason = AddressState::ProtocolViolation;
						state_lock.msg = ("due to bad block".to_string(), true);
						return future::err(());
					}
					check_set_flag!(recvd_block, "block");
					return future::err(());
				},
				NetworkMessage::Inv(invs) => {
					for inv in invs {
						if inv.inv_type == InvType::Transaction {
							state_lock.fail_reason = AddressState::EvilNode;
							state_lock.msg = ("due to unrequested inv tx".to_string(), true);
							return future::err(());
						}
					}
				},
				NetworkMessage::Tx(_) => {
					state_lock.fail_reason = AddressState::EvilNode;
					state_lock.msg = ("due to unrequested transaction".to_string(), true);
					return future::err(());
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

		let mut state_lock = final_peer_state.lock().unwrap();
		if state_lock.recvd_version && state_lock.recvd_verack && state_lock.recvd_pong &&
				state_lock.recvd_addrs && state_lock.recvd_block {
			let old_state = store.set_node_state(node, AddressState::Good, state_lock.node_services);
			if manual || (old_state != AddressState::Good && state_lock.msg.0 != "") {
				printer.add_line(format!("Updating {} from {} to Good {}", node, old_state.to_str(), &state_lock.msg.0), state_lock.msg.1);
			}
		} else {
			assert!(state_lock.fail_reason != AddressState::Good);
			if state_lock.fail_reason == AddressState::TimeoutDuringRequest && state_lock.recvd_version && state_lock.recvd_verack {
				if !state_lock.recvd_pong {
					state_lock.fail_reason = AddressState::TimeoutAwaitingPong;
				} else if !state_lock.recvd_addrs {
					state_lock.fail_reason = AddressState::TimeoutAwaitingAddr;
				} else if !state_lock.recvd_block {
					state_lock.fail_reason = AddressState::TimeoutAwaitingBlock;
				}
			}
			let old_state = store.set_node_state(node, state_lock.fail_reason, 0);
			if (manual || old_state != state_lock.fail_reason) && state_lock.fail_reason == AddressState::TimeoutDuringRequest {
				printer.add_line(format!("Updating {} from {} to Timeout During Request (ver: {}, vack: {})",
					node, old_state.to_str(), state_lock.recvd_version, state_lock.recvd_verack), true);
			} else if manual || (old_state != state_lock.fail_reason && state_lock.msg.0 != "" && state_lock.msg.1) {
				printer.add_line(format!("Updating {} from {} to {} {}", node, old_state.to_str(), state_lock.fail_reason.to_str(), &state_lock.msg.0), state_lock.msg.1);
			}
		}
		future::ok(())
	}));
}

fn poll_dnsseeds(bgp_client: Arc<BGPClient>) {
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
			let store = unsafe { DATA_STORE.as_ref().unwrap() };
			let dns_future = store.write_dns(Arc::clone(&bgp_client));
			store.save_data().join(dns_future).then(|_| {
				if !START_SHUTDOWN.load(Ordering::Relaxed) {
					poll_dnsseeds(bgp_client);
				} else {
					bgp_client.disconnect();
				}
				future::ok(())
			})
		})
	}));
}

fn scan_net() {
	tokio::spawn(future::lazy(|| {
		let printer = unsafe { PRINTER.as_ref().unwrap() };
		let store = unsafe { DATA_STORE.as_ref().unwrap() };

		let mut scan_nodes = store.get_next_scan_nodes();
		printer.add_line(format!("Got {} addresses to scan", scan_nodes.len()), false);
		let per_iter_time = Duration::from_millis(1000 / store.get_u64(U64Setting::ConnsPerSec));
		let start_time = Instant::now();
		let mut iter_time = start_time;

		for node in scan_nodes.drain(..) {
			scan_node(iter_time, node, false);
			iter_time += per_iter_time;
		}
		Delay::new(cmp::max(iter_time, start_time + Duration::from_secs(1))).then(|_| {
			if !START_SHUTDOWN.load(Ordering::Relaxed) {
				scan_net();
			}
			future::ok(())
		})
	}));
}

fn make_trusted_conn(trusted_sockaddr: SocketAddr, bgp_client: Arc<BGPClient>) {
	let printer = unsafe { PRINTER.as_ref().unwrap() };
	let trusted_peer = Peer::new(trusted_sockaddr.clone(), Duration::from_secs(600), printer);
	let bgp_reload = Arc::clone(&bgp_client);
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
							if let Err(_) = trusted_write.try_send(NetworkMessage::GetData(vec![Inventory {
								inv_type: InvType::WitnessBlock,
								hash: height_map.get(&(top_height - 216)).unwrap().clone(),
							}])) {
								return future::err(());
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
				NetworkMessage::Block(block) => {
					let hash = block.header.bitcoin_hash();
					let header_map = unsafe { HEADER_MAP.as_ref().unwrap() }.lock().unwrap();
					let height = *header_map.get(&hash).expect("Got loose block from trusted peer we coulnd't have requested");
					if height == unsafe { HIGHEST_HEADER.as_ref().unwrap() }.lock().unwrap().1 - 216 {
						*unsafe { REQUEST_BLOCK.as_ref().unwrap() }.lock().unwrap() = Arc::new((height, hash, block));
						if !SCANNING.swap(true, Ordering::SeqCst) {
							scan_net();
							poll_dnsseeds(Arc::clone(&bgp_client));
						}
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
			make_trusted_conn(trusted_sockaddr, bgp_reload);
		}
		future::ok(())
	}));
}

fn main() {
	if env::args().len() != 4 {
		println!("USAGE: dnsseed-rust datastore localPeerAddress bgp_peer");
		return;
	}

	unsafe { HEADER_MAP = Some(Box::new(Mutex::new(HashMap::with_capacity(600000)))) };
	unsafe { HEIGHT_MAP = Some(Box::new(Mutex::new(HashMap::with_capacity(600000)))) };
	unsafe { HEADER_MAP.as_ref().unwrap() }.lock().unwrap().insert(genesis_block(Network::Bitcoin).bitcoin_hash(), 0);
	unsafe { HEIGHT_MAP.as_ref().unwrap() }.lock().unwrap().insert(0, genesis_block(Network::Bitcoin).bitcoin_hash());
	unsafe { HIGHEST_HEADER = Some(Box::new(Mutex::new((genesis_block(Network::Bitcoin).bitcoin_hash(), 0)))) };
	unsafe { REQUEST_BLOCK = Some(Box::new(Mutex::new(Arc::new((0, genesis_block(Network::Bitcoin).bitcoin_hash(), genesis_block(Network::Bitcoin)))))) };

	let trt = tokio::runtime::Builder::new()
		.blocking_threads(2).core_threads(num_cpus::get().max(1) * 3)
		.build().unwrap();

	let _ = trt.block_on_all(future::lazy(|| {
		let mut args = env::args();
		args.next();
		let path = args.next().unwrap();
		let trusted_sockaddr: SocketAddr = args.next().unwrap().parse().unwrap();
		let bgp_sockaddr: SocketAddr = args.next().unwrap().parse().unwrap();

		Store::new(path).and_then(move |store| {
			unsafe { DATA_STORE = Some(Box::new(store)) };
			let store = unsafe { DATA_STORE.as_ref().unwrap() };
			unsafe { PRINTER = Some(Box::new(Printer::new(store))) };

			let bgp_client = BGPClient::new(bgp_sockaddr, Duration::from_secs(600), unsafe { PRINTER.as_ref().unwrap() });
			make_trusted_conn(trusted_sockaddr, Arc::clone(&bgp_client));

			reader::read(store, unsafe { PRINTER.as_ref().unwrap() }, bgp_client);

			future::ok(())
		}).or_else(|_| {
			future::err(())
		})
	}));

	tokio::run(future::lazy(|| {
		unsafe { DATA_STORE.as_ref().unwrap() }.save_data()
	}));
}
