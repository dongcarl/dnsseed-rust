use std::sync::atomic::Ordering;
use std::io::BufReader;
use std::net::SocketAddr;
use std::time::Instant;

use tokio::prelude::*;
use tokio::io::{stdin, lines};

use crate::printer::Printer;
use crate::datastore::{Store, AddressState, U64Setting, RegexSetting};

use crate::{START_SHUTDOWN, scan_node};

use regex::Regex;

pub fn read(store: &'static Store, printer: &'static Printer) {
	tokio::spawn(lines(BufReader::new(stdin())).for_each(move |line| {
		macro_rules! err {
			() => { {
				printer.add_line(format!("Unparsable input: \"{}\"", line), true);
				return future::ok(());
			} }
		}
		let mut line_iter = line.split(' ');
		macro_rules! get_next_chunk {
			() => { {
				match line_iter.next() {
					Some(c) => c,
					None => err!(),
				}
			} }
		}
		macro_rules! try_parse_next_chunk {
			($type: ty) => { {
				match get_next_chunk!().parse::<$type>() {
					Ok(res) => res,
					Err(_) => err!(),
				}
			} }
		}
		match get_next_chunk!() {
			"c" => store.set_u64(U64Setting::ConnsPerSec, try_parse_next_chunk!(u64)),
			"t" => store.set_u64(U64Setting::RunTimeout, try_parse_next_chunk!(u64)),
			"v" => store.set_u64(U64Setting::MinProtocolVersion, try_parse_next_chunk!(u64)),
			"w" => store.set_u64(U64Setting::WasGoodTimeout, try_parse_next_chunk!(u64)),
			"s" => {
				if line.len() < 3 || !line.starts_with("s ") {
					err!();
				}
				store.set_regex(RegexSetting::SubverRegex, match line[2..].parse::<Regex>() {
					Ok(res) => res,
					Err(_) => err!(),
				});
			},
			"a" => scan_node(Instant::now(), try_parse_next_chunk!(SocketAddr)),
			"r" => {
				match AddressState::from_num(try_parse_next_chunk!(u8)) {
					Some(state) => store.set_u64(U64Setting::RescanInterval(state), try_parse_next_chunk!(u64)),
					None => err!(),
				}
			},
			"q" => {
				START_SHUTDOWN.store(true, Ordering::SeqCst);
				return future::err(std::io::Error::new(std::io::ErrorKind::Other, ""));
			},
			_ => err!(),
		}
		future::ok(())
	}).then(move |_| {
		printer.add_line("Shutting down...".to_string(), true);
		future::ok(())
	}));
}
