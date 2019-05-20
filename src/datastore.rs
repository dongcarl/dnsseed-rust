use std::{cmp, mem};
use std::collections::{HashSet, HashMap, hash_map};
use std::sync::{Arc, RwLock};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use std::io::{BufRead, BufReader};

use bitcoin::network::address::Address;

use rand::thread_rng;
use rand::seq::{SliceRandom, IteratorRandom};

use tokio::prelude::*;
use tokio::fs::File;
use tokio::io::write_all;

use regex::Regex;

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
pub enum AddressState {
	Untested,
	LowBlockCount,
	HighBlockCount,
	LowVersion,
	BadVersion,
	NotFullNode,
	ProtocolViolation,
	Timeout,
	TimeoutDuringRequest,
	Good,
	WasGood,
}

#[derive(Hash, PartialEq, Eq)]
pub enum U64Setting {
	ConnsPerSec,
	RunTimeout,
	WasGoodTimeout,
	RescanInterval(AddressState),
	MinProtocolVersion,
}

#[derive(Hash, PartialEq, Eq)]
pub enum RegexSetting {
	SubverRegex,
}

struct Node {
	state: AddressState,
	last_services: u64,
	last_update: Instant,
}

struct Nodes {
	good_node_services: HashMap<u8, HashSet<SocketAddr>>,
	nodes_to_state: HashMap<SocketAddr, Node>,
	state_next_scan: HashMap<AddressState, Vec<(Instant, SocketAddr)>>,
}
struct NodesMutRef<'a> {
	good_node_services: &'a mut HashMap<u8, HashSet<SocketAddr>>,
	nodes_to_state: &'a mut HashMap<SocketAddr, Node>,
	state_next_scan: &'a mut HashMap<AddressState, Vec<(Instant, SocketAddr)>>,

}
impl Nodes {
	fn borrow_mut<'a>(&'a mut self) -> NodesMutRef<'a> {
		NodesMutRef {
			good_node_services: &mut self.good_node_services,
			nodes_to_state: &mut self.nodes_to_state,
			state_next_scan: &mut self.state_next_scan,
		}
	}
}

pub struct Store {
	u64_settings: RwLock<HashMap<U64Setting, u64>>,
	subver_regex: RwLock<Arc<Regex>>,
	nodes: RwLock<Nodes>,
	store: String,
}

impl Store {
	pub fn new(store: String) -> impl Future<Item=Store, Error=()> {
		let settings_future = File::open(store.clone() + "/settings").and_then(|f| {
			let mut l = BufReader::new(f).lines();
			macro_rules! try_read {
				($lines: expr, $ty: ty) => { {
					match $lines.next() {
						Some(line) => match line {
							Ok(line) => match line.parse::<$ty>() {
								Ok(res) => res,
								Err(e) => return future::err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
							},
							Err(e) => return future::err(e),
						},
						None => return future::err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "")),
					}
				} }
			}
			let mut u64s = HashMap::with_capacity(15);
			u64s.insert(U64Setting::ConnsPerSec, try_read!(l, u64));
			u64s.insert(U64Setting::RunTimeout, try_read!(l, u64));
			u64s.insert(U64Setting::WasGoodTimeout, try_read!(l, u64));
			u64s.insert(U64Setting::MinProtocolVersion, try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::Untested), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::LowBlockCount), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::HighBlockCount), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::LowVersion), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::BadVersion), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::NotFullNode), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::ProtocolViolation), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::Timeout), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutDuringRequest), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::Good), try_read!(l, u64));
			u64s.insert(U64Setting::RescanInterval(AddressState::WasGood), try_read!(l, u64));
			future::ok((u64s, try_read!(l, Regex)))
		}).or_else(|_| -> future::FutureResult<(HashMap<U64Setting, u64>, Regex), ()> {
			let mut u64s = HashMap::with_capacity(15);
			u64s.insert(U64Setting::ConnsPerSec, 10);
			u64s.insert(U64Setting::RunTimeout, 120);
			u64s.insert(U64Setting::WasGoodTimeout, 21600);
			u64s.insert(U64Setting::RescanInterval(AddressState::Untested), 0);
			u64s.insert(U64Setting::RescanInterval(AddressState::LowBlockCount), 3600);
			u64s.insert(U64Setting::RescanInterval(AddressState::HighBlockCount), 7200);
			u64s.insert(U64Setting::RescanInterval(AddressState::LowVersion), 21600);
			u64s.insert(U64Setting::RescanInterval(AddressState::BadVersion), 21600);
			u64s.insert(U64Setting::RescanInterval(AddressState::NotFullNode), 86400);
			u64s.insert(U64Setting::RescanInterval(AddressState::ProtocolViolation), 86400);
			u64s.insert(U64Setting::RescanInterval(AddressState::Timeout), 86400);
			u64s.insert(U64Setting::RescanInterval(AddressState::TimeoutDuringRequest), 21600);
			u64s.insert(U64Setting::RescanInterval(AddressState::Good), 1800);
			u64s.insert(U64Setting::RescanInterval(AddressState::WasGood), 1800);
			u64s.insert(U64Setting::MinProtocolVersion, 10000); //XXX
			future::ok((u64s, Regex::new(".*").unwrap()))
		});

		macro_rules! nodes_uninitd {
			() => { {
				let mut state_vecs = HashMap::with_capacity(11);
				state_vecs.insert(AddressState::Untested, Vec::new());
				state_vecs.insert(AddressState::LowBlockCount, Vec::new());
				state_vecs.insert(AddressState::HighBlockCount, Vec::new());
				state_vecs.insert(AddressState::LowVersion, Vec::new());
				state_vecs.insert(AddressState::BadVersion, Vec::new());
				state_vecs.insert(AddressState::NotFullNode, Vec::new());
				state_vecs.insert(AddressState::ProtocolViolation, Vec::new());
				state_vecs.insert(AddressState::Timeout, Vec::new());
				state_vecs.insert(AddressState::TimeoutDuringRequest, Vec::new());
				state_vecs.insert(AddressState::Good, Vec::new());
				state_vecs.insert(AddressState::WasGood, Vec::new());
				let mut good_node_services = HashMap::with_capacity(64);
				for i in 0..64 {
					good_node_services.insert(i, HashSet::new());
				}
				Nodes {
					good_node_services,
					nodes_to_state: HashMap::new(),
					state_next_scan: state_vecs,
				}
			} }
		}

		let nodes_future = File::open(store.clone() + "/nodes").and_then(|f| {
			let mut res = nodes_uninitd!();
			let l = BufReader::new(f).lines();
			for line_res in l {
				let line = match line_res {
					Ok(l) => l,
					Err(_) => return future::ok(res),
				};
				let mut line_iter = line.split(',');
				macro_rules! try_read {
					($lines: expr, $ty: ty) => { {
						match $lines.next() {
							Some(line) => match line.parse::<$ty>() {
								Ok(res) => res,
								Err(_) => return future::ok(res),
							},
							None => return future::ok(res),
						}
					} }
				}
				let sockaddr = try_read!(line_iter, SocketAddr);
				let state = try_read!(line_iter, u8);
				let last_services = try_read!(line_iter, u64);
				let node = Node {
					state: match state {
						0x0 => AddressState::Untested,
						0x1 => AddressState::LowBlockCount,
						0x2 => AddressState::HighBlockCount,
						0x3 => AddressState::LowVersion,
						0x4 => AddressState::BadVersion,
						0x5 => AddressState::NotFullNode,
						0x6 => AddressState::ProtocolViolation,
						0x7 => AddressState::Timeout,
						0x8 => AddressState::TimeoutDuringRequest,
						0x9 => AddressState::Good,
						0xa => AddressState::WasGood,
						_   => return future::ok(res),
					},
					last_services,
					last_update: Instant::now(),
				};
				if node.state == AddressState::Good {
					for i in 0..64 {
						if node.last_services & (1 << i) != 0 {
							res.good_node_services.get_mut(&i).unwrap().insert(sockaddr);
						}
					}
				}
				res.state_next_scan.get_mut(&node.state).unwrap().push((Instant::now(), sockaddr));
				res.nodes_to_state.insert(sockaddr, node);
			}
			future::ok(res)
		}).or_else(|_| -> future::FutureResult<Nodes, ()> {
			future::ok(nodes_uninitd!())
		});
		settings_future.join(nodes_future).and_then(move |((u64_settings, regex), nodes)| {
			future::ok(Store {
				u64_settings: RwLock::new(u64_settings),
				subver_regex: RwLock::new(Arc::new(regex)),
				nodes: RwLock::new(nodes),
				store,
			})
		})
	}

	pub fn get_u64(&self, setting: U64Setting) -> u64 {
		*self.u64_settings.read().unwrap().get(&setting).unwrap()
	}

	pub fn set_u64(&self, setting: U64Setting, value: u64) {
		*self.u64_settings.write().unwrap().get_mut(&setting).unwrap() = value;
	}

	pub fn get_node_count(&self, state: AddressState) -> usize {
		self.nodes.read().unwrap().state_next_scan.get(&state).unwrap().len()
	}

	pub fn get_regex(&self, _setting: RegexSetting) -> Arc<Regex> {
		Arc::clone(&*self.subver_regex.read().unwrap())
	}

	pub fn set_regex(&self, _setting: RegexSetting, value: Regex) {
		*self.subver_regex.write().unwrap() = Arc::new(value);
	}

	pub fn add_fresh_nodes(&self, addresses: &Vec<(u32, Address)>) {
		let mut nodes = self.nodes.write().unwrap();
		let cur_time = Instant::now();
		for &(_, ref addr) in addresses {
			if let Ok(socketaddr) = addr.socket_addr() {
				match nodes.nodes_to_state.entry(socketaddr.clone()) {
					hash_map::Entry::Vacant(e) => {
						e.insert(Node {
							state: AddressState::Untested,
							last_services: 0,
							last_update: cur_time,
						});
						nodes.state_next_scan.get_mut(&AddressState::Untested).unwrap().push((cur_time, socketaddr));
					},
					hash_map::Entry::Occupied(_) => {},
				}
			} else {
				//TODO: Handle onions
			}
		}
	}

	pub fn set_node_state(&self, addr: SocketAddr, state: AddressState, services: u64) {
		let mut nodes_lock = self.nodes.write().unwrap();
		let nodes = nodes_lock.borrow_mut();
		let state_ref = nodes.nodes_to_state.get_mut(&addr).unwrap();
		state_ref.last_update = Instant::now();
		if state_ref.state == AddressState::Good && state != AddressState::Good {
			state_ref.state = AddressState::WasGood;
			for i in 0..64 {
				if state_ref.last_services & (1 << i) != 0 {
					nodes.good_node_services.get_mut(&i).unwrap().remove(&addr);
				}
			}
			state_ref.last_services = 0;
			nodes.state_next_scan.get_mut(&AddressState::WasGood).unwrap().push((state_ref.last_update, addr));
		} else {
			state_ref.state = state;
			if state == AddressState::Good {
				for i in 0..64 {
					if services & (1 << i) != 0 && state_ref.last_services & (1 << i) == 0 {
						nodes.good_node_services.get_mut(&i).unwrap().insert(addr);
					} else if services & (1 << i) == 0 && state_ref.last_services & (1 << i) != 0 {
						nodes.good_node_services.get_mut(&i).unwrap().remove(&addr);
					}
				}
				state_ref.last_services = services;
			}
			nodes.state_next_scan.get_mut(&state).unwrap().push((state_ref.last_update, addr));
		}
	}

	pub fn save_data(&'static self) -> impl Future<Item=(), Error=()> {
		let settings_file = self.store.clone() + "/settings";
		let settings_future = File::create(settings_file.clone() + ".tmp").and_then(move |f| {
			let settings_string = format!("{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
				self.get_u64(U64Setting::ConnsPerSec),
				self.get_u64(U64Setting::RunTimeout),
				self.get_u64(U64Setting::WasGoodTimeout),
				self.get_u64(U64Setting::MinProtocolVersion),
				self.get_u64(U64Setting::RescanInterval(AddressState::Untested)),
				self.get_u64(U64Setting::RescanInterval(AddressState::LowBlockCount)),
				self.get_u64(U64Setting::RescanInterval(AddressState::HighBlockCount)),
				self.get_u64(U64Setting::RescanInterval(AddressState::LowVersion)),
				self.get_u64(U64Setting::RescanInterval(AddressState::BadVersion)),
				self.get_u64(U64Setting::RescanInterval(AddressState::NotFullNode)),
				self.get_u64(U64Setting::RescanInterval(AddressState::ProtocolViolation)),
				self.get_u64(U64Setting::RescanInterval(AddressState::Timeout)),
				self.get_u64(U64Setting::RescanInterval(AddressState::TimeoutDuringRequest)),
				self.get_u64(U64Setting::RescanInterval(AddressState::Good)),
				self.get_u64(U64Setting::RescanInterval(AddressState::WasGood)),
				self.get_regex(RegexSetting::SubverRegex).as_str());
			write_all(f, settings_string).and_then(|(mut f, _)| {
				f.poll_sync_all()
			}).and_then(|_| {
				tokio::fs::rename(settings_file.clone() + ".tmp", settings_file)
			})
		});

		let nodes_file = self.store.clone() + "/nodes";
		let nodes_future = File::create(nodes_file.clone() + ".tmp").and_then(move |f| {
			let mut nodes_buff = String::new();
			{
				let nodes = self.nodes.read().unwrap();
				nodes_buff.reserve(nodes.nodes_to_state.len() * 20);
				for (ref sockaddr, ref node) in nodes.nodes_to_state.iter() {
					nodes_buff += &sockaddr.to_string();
					nodes_buff += ",";
					nodes_buff += &match node.state {
						AddressState::Untested => 0u8,
						AddressState::LowBlockCount => 1u8,
						AddressState::HighBlockCount => 2u8,
						AddressState::LowVersion => 3u8,
						AddressState::BadVersion => 4u8,
						AddressState::NotFullNode => 5u8,
						AddressState::ProtocolViolation => 6u8,
						AddressState::Timeout => 7u8,
						AddressState::TimeoutDuringRequest => 8u8,
						AddressState::Good => 9u8,
						AddressState::WasGood => 10u8,
					}.to_string();
					nodes_buff += ",";
					nodes_buff += &node.last_services.to_string();
					nodes_buff += "\n";
				}
			}
			write_all(f, nodes_buff)
		}).and_then(|(mut f, _)| {
			f.poll_sync_all()
		}).and_then(|_| {
			tokio::fs::rename(nodes_file.clone() + ".tmp", nodes_file)
		});

		let dns_file = self.store.clone() + "/nodes.dump";
		let dns_future = File::create(dns_file.clone() + ".tmp").and_then(move |f| {
			let mut dns_buff = String::new();
			{
				let nodes = self.nodes.read().unwrap();
				let mut rng = thread_rng();
				for i in &[1u64, 4, 5, 8, 9, 12, 13, 1024, 1025, 1028, 1029, 1032, 1033, 1036, 1037] {
					let mut v6_set = Vec::new();
					let mut v4_set = Vec::new();
					if i.count_ones() == 1 {
						for j in 0..64 {
							if i & (1 << j) != 0 {
								let set_ref = nodes.good_node_services.get(&j).unwrap();
								v4_set = set_ref.iter().filter(|e| e.is_ipv4() && e.port() == 8333)
									.choose_multiple(&mut rng, 21).iter().map(|e| e.ip()).collect();
								v6_set = set_ref.iter().filter(|e| e.is_ipv6() && e.port() == 8333)
									.choose_multiple(&mut rng, 12).iter().map(|e| e.ip()).collect();
								break;
							}
						}
					} else if i.count_ones() == 2 {
						let mut first_set = None;
						let mut second_set = None;
						for j in 0..64 {
							if i & (1 << j) != 0 {
								if first_set == None {
									first_set = Some(nodes.good_node_services.get(&j).unwrap());
								} else {
									second_set = Some(nodes.good_node_services.get(&j).unwrap());
									break;
								}
							}
						}
						v4_set = first_set.unwrap().intersection(second_set.unwrap())
							.filter(|e| e.is_ipv4() && e.port() == 8333)
							.choose_multiple(&mut rng, 21).iter().map(|e| e.ip()).collect();
						v6_set = first_set.unwrap().intersection(second_set.unwrap())
							.filter(|e| e.is_ipv6() && e.port() == 8333)
							.choose_multiple(&mut rng, 12).iter().map(|e| e.ip()).collect();
					} else {
						//TODO: Could optimize this one a bit
						let mut intersection;
						let mut intersection_set_ref = None;
						for j in 0..64 {
							if i & (1 << j) != 0 {
								if intersection_set_ref == None {
									intersection_set_ref = Some(nodes.good_node_services.get(&j).unwrap());
								} else {
									let new_intersection = intersection_set_ref.unwrap()
										.intersection(nodes.good_node_services.get(&j).unwrap()).map(|e| (*e).clone()).collect();
									intersection = Some(new_intersection);
									intersection_set_ref = Some(intersection.as_ref().unwrap());
								}
							}
						}
						v4_set = intersection_set_ref.unwrap().iter()
							.filter(|e| e.is_ipv4() && e.port() == 8333)
							.choose_multiple(&mut rng, 21).iter().map(|e| e.ip()).collect();
						v6_set = intersection_set_ref.unwrap().iter()
							.filter(|e| e.is_ipv6() && e.port() == 8333)
							.choose_multiple(&mut rng, 12).iter().map(|e| e.ip()).collect();
					}
					for a in v4_set {
						dns_buff += &format!("x{:x}.dnsseed.bluematt.me\tIN\tA\t{}\n", i, a);
					}
					for a in v6_set {
						dns_buff += &format!("x{:x}.dnsseed.bluematt.me\tIN\tAAAA\t{}\n", i, a);
					}
				}
			}
			write_all(f, dns_buff)
		}).and_then(|(mut f, _)| {
			f.poll_sync_all()
		}).and_then(|_| {
			tokio::fs::rename(dns_file.clone() + ".tmp", dns_file)
		});

		settings_future.join3(nodes_future, dns_future).then(|_| { future::ok(()) })
	}

	pub fn get_next_scan_nodes(&self) -> Vec<SocketAddr> {
		let mut res = Vec::with_capacity(600);
		let cur_time = Instant::now();
		let mut nodes = self.nodes.write().unwrap();
		for (state, state_nodes) in nodes.state_next_scan.iter_mut() {
			let cmp_time = cur_time - Duration::from_secs(self.get_u64(U64Setting::RescanInterval(*state)));
			let split_point = cmp::min(cmp::min(600 - res.len(), 60),
					state_nodes.binary_search_by(|a| a.0.cmp(&cmp_time)).unwrap_or_else(|idx| idx));
			let mut new_nodes = state_nodes.split_off(split_point);
			mem::swap(&mut new_nodes, state_nodes);
			for (_, node) in new_nodes.drain(..) {
				res.push(node);
			}
		}
		res.shuffle(&mut thread_rng());
		res
	}
}
