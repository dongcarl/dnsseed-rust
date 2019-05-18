use std::{cmp, mem};
use std::collections::{HashMap, hash_map};
use std::sync::RwLock;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use bitcoin::network::address::Address;

use rand::thread_rng;
use rand::seq::SliceRandom;

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
pub enum StringSetting {
	SubverRegex,
}

struct Nodes {
	good_node_services: HashMap<u8, Vec<SocketAddr>>,
	nodes_to_state: HashMap<SocketAddr, AddressState>,
	state_next_scan: HashMap<AddressState, Vec<(Instant, SocketAddr)>>,
}

pub struct Store {
	u64_settings: RwLock<HashMap<U64Setting, u64>>,
	subver_regex: RwLock<String>,
	nodes: RwLock<Nodes>,
}

impl Store {
	pub fn new() -> Store {
		let mut u64s = HashMap::with_capacity(15);
		u64s.insert(U64Setting::ConnsPerSec, 50);
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
			good_node_services.insert(i, Vec::new());
		}
		Store {
			u64_settings: RwLock::new(u64s),
			subver_regex: RwLock::new(".*".to_string()),
			nodes: RwLock::new(Nodes {
				good_node_services,
				nodes_to_state: HashMap::new(),
				state_next_scan: state_vecs,
			}),
		}
	}

	pub fn get_u64(&self, setting: U64Setting) -> u64 {
		*self.u64_settings.read().unwrap().get(&setting).unwrap()
	}

	pub fn get_node_count(&self, state: AddressState) -> usize {
		self.nodes.read().unwrap().state_next_scan.get(&state).unwrap().len()
	}

	pub fn get_string(&self, _setting: StringSetting) -> String {
		self.subver_regex.read().unwrap().clone()
	}

	pub fn add_fresh_nodes(&self, addresses: &Vec<(u32, Address)>) {
		let mut nodes = self.nodes.write().unwrap();
		let cur_time = Instant::now();
		for &(_, ref addr) in addresses {
			if let Ok(socketaddr) = addr.socket_addr() {
				match nodes.nodes_to_state.entry(socketaddr.clone()) {
					hash_map::Entry::Vacant(e) => {
						e.insert(AddressState::Untested);
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
		let mut nodes = self.nodes.write().unwrap();
		let state_ref = nodes.nodes_to_state.get_mut(&addr).unwrap();
		if *state_ref == AddressState::Good && state != AddressState::Good {
			*state_ref = AddressState::WasGood;
			nodes.state_next_scan.get_mut(&AddressState::WasGood).unwrap().push((Instant::now(), addr));
		} else {
			*state_ref = state;
			nodes.state_next_scan.get_mut(&state).unwrap().push((Instant::now(), addr));
		}
		if state == AddressState::Good {

		}
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
