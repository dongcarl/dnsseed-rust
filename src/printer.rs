use std::sync::atomic::Ordering;
use std::collections::LinkedList;
use std::sync::{Arc, Mutex};
use std::io::Write;

use crate::datastore::{Store, AddressState, U64Setting, RegexSetting};

use crate::START_SHUTDOWN;

pub enum Stat {
	HeaderCount(u64),
	NewConnection,
	ConnectionClosed,
}

struct Stats {
	lines: LinkedList<String>,
	header_count: u64,
	connection_count: u64,
}

pub struct Printer {
	stats: Arc<Mutex<Stats>>,
}

impl Printer {
	pub fn new(store: &'static Store) -> Printer {
		let stats: Arc<Mutex<Stats>> = Arc::new(Mutex::new(Stats {
			lines: LinkedList::new(),
			header_count: 0,
			connection_count: 0,
		}));
		let thread_arc = Arc::clone(&stats);
		std::thread::spawn(move || {
			loop {
				std::thread::sleep(std::time::Duration::from_secs(1));

				let stdout = std::io::stdout();
				let mut out = stdout.lock();

				let stats = thread_arc.lock().unwrap();
				if START_SHUTDOWN.load(Ordering::Relaxed) && stats.connection_count == 0 {
					break;
				}

				out.write_all(b"\x1b[2J\x1b[;H\n").expect("stdout broken?");
				for line in stats.lines.iter() {
					out.write_all(line.as_bytes()).expect("stdout broken?");
					out.write_all(b"\n").expect("stdout broken?");
				}

				out.write_all(b"\nNode counts by status:\n").expect("stdout broken?");
				out.write_all(format!("Untested:               {}\n", store.get_node_count(AddressState::Untested)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("Low Block Count:        {}\n", store.get_node_count(AddressState::LowBlockCount)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("High Block Count:       {}\n", store.get_node_count(AddressState::HighBlockCount)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("Low Version:            {}\n", store.get_node_count(AddressState::LowVersion)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("Bad Version:            {}\n", store.get_node_count(AddressState::BadVersion)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("Not Full Node:          {}\n", store.get_node_count(AddressState::NotFullNode)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("Protocol Violation:     {}\n", store.get_node_count(AddressState::ProtocolViolation)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("Timeout:                {}\n", store.get_node_count(AddressState::Timeout)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("Timeout During Request: {}\n", store.get_node_count(AddressState::TimeoutDuringRequest)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("Good:                   {}\n", store.get_node_count(AddressState::Good)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!("WasGood:                {}\n", store.get_node_count(AddressState::WasGood)
						).as_bytes()).expect("stdout broken?");

				out.write_all(format!(
						"\nCurrent connections open/in progress: {}\n", stats.connection_count).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Connections opened each second: {} (\"c x\" to change to x seconds)\n", store.get_u64(U64Setting::ConnsPerSec)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Current block count: {}\n", stats.header_count).as_bytes()).expect("stdout broken?");

				out.write_all(format!(
						"Timeout for full run (in seconds): {} (\"t x\" to change to x seconds)\n", store.get_u64(U64Setting::RunTimeout)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Minimum protocol version: {} (\"v x\" to change value to x)\n", store.get_u64(U64Setting::MinProtocolVersion)
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Subversion match regex: {} (\"s x\" to change value to x)\n", store.get_regex(RegexSetting::SubverRegex).as_str()
						).as_bytes()).expect("stdout broken?");

				out.write_all(b"\nRetry times (in seconds):\n").expect("stdout broken?");
				out.write_all(format!(
						"Untested:               {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::Untested))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Low Block Count:        {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::LowBlockCount))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"High Block Count        {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::HighBlockCount))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Low Version:            {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::LowVersion))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Bad Version:            {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::BadVersion))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Not Full Node:          {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::NotFullNode))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Protocol Violation:     {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::ProtocolViolation))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Timeout:                {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::Timeout))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Timeout During Request: {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::TimeoutDuringRequest))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Good:                   {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::Good))
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"Was Good:               {}\n", store.get_u64(U64Setting::RescanInterval(AddressState::WasGood))
						).as_bytes()).expect("stdout broken?");

				out.write_all(b"\nCommands:\n").expect("stdout broken?");
				out.write_all(b"q: quit\n").expect("stdout broken?");
				out.write_all(format!(
						"r x y: Change retry time for status x (int value, see retry times section for name mappings) to y (in seconds)\n"
						).as_bytes()).expect("stdout broken?");
				out.write_all(format!(
						"w x: Change the amount of time a node is considered WAS_GOOD after it fails to x from {} (in seconds)\n",
						store.get_u64(U64Setting::WasGoodTimeout)
						).as_bytes()).expect("stdout broken?");
				out.write_all(b"a x: Scan node x\n").expect("stdout broken?");
				out.write_all(b"\x1b[s").expect("stdout broken?"); // Save cursor position and provide a blank line before cursor
				out.write_all(b"\x1b[;H\x1b[2K").expect("stdout broken?");
				out.write_all(b"Most recent log:\n").expect("stdout broken?");
				out.write_all(b"\x1b[u").expect("stdout broken?"); // Restore cursor position and go up one line

				out.flush().expect("stdout broken?");
			}
		});
		Printer {
			stats,
		}
	}

	pub fn add_line(&self, line: String, err: bool) {
		let mut stats = self.stats.lock().unwrap();
		if err {
			stats.lines.push_back("\x1b[31m".to_string() + &line + "\x1b[0m");
		} else {
			stats.lines.push_back(line);
		}
		if stats.lines.len() > 50 {
			stats.lines.pop_front();
		}
	}

	pub fn set_stat(&self, s: Stat) {
		match s {
			Stat::HeaderCount(c) => self.stats.lock().unwrap().header_count = c,
			Stat::NewConnection => self.stats.lock().unwrap().connection_count += 1,
			Stat::ConnectionClosed => self.stats.lock().unwrap().connection_count -= 1,
		}
	}
}
