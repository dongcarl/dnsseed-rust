use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use std::cmp;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use bgp_rs::{AFI, SAFI, AddPathDirection, Open, OpenCapability, OpenParameter, NLRIEncoding, PathAttribute};
use bgp_rs::Capabilities;
use bgp_rs::Segment;
use bgp_rs::Message;
use bgp_rs::Reader;

use tokio::prelude::*;
use tokio::codec;
use tokio::codec::Framed;
use tokio::net::TcpStream;
use tokio::timer::Delay;

use futures::sync::mpsc;

use crate::printer::{Printer, Stat};
use crate::timeout_stream::TimeoutStream;

struct Route {
	path: Vec<u32>,
	pref: u32,
	med: u32,
}

struct RoutingTable {
	v4_table: HashMap<(Ipv4Addr, u8), HashMap<u32, Arc<Route>>>,
	v6_table: HashMap<(Ipv6Addr, u8), HashMap<u32, Arc<Route>>>,
}

impl RoutingTable {
	fn new() -> Self {
		Self {
			v4_table: HashMap::new(),
			v6_table: HashMap::new(),
		}
	}

	fn get_route_attrs(&self, ip: IpAddr) -> Vec<Arc<Route>> {
		macro_rules! lookup_res {
			($addr: expr, $table: expr, $addr_intty: ty) => { {
				//TODO: Optimize this!
				const ADDR_BITS: usize = std::mem::size_of::<$addr_intty>() * 8;
				for i in (0..ADDR_BITS).rev() {
					let mask: $addr_intty = !((1 << i) - 1);
					let lookup: $addr_intty = $addr.into();
					if let Some(routes) = $table.get(&((lookup & mask).into(), (ADDR_BITS - i) as u8))
					                            .map(|hm| hm.values()) {
						if routes.len() > 0 {
							return routes.map(|x| Arc::clone(&x)).collect();
						}
					}
				}
				vec![]
			} }
		}
		match ip {
			IpAddr::V4(v4a) => lookup_res!(v4a, self.v4_table, u32),
			IpAddr::V6(v6a) => lookup_res!(v6a, self.v6_table, u128),
		}
	}

	fn withdraw(&mut self, route: NLRIEncoding) {
		match route {
			NLRIEncoding::IP(p) => {
				let (ip, len) = <(IpAddr, u8)>::from(&p);
				match ip {
					IpAddr::V4(v4a) => self.v4_table.get_mut(&(v4a, len)).and_then(|hm| hm.remove(&0)),
					IpAddr::V6(v6a) => self.v6_table.get_mut(&(v6a, len)).and_then(|hm| hm.remove(&0)),
				}
			},
			NLRIEncoding::IP_WITH_PATH_ID((p, id)) => {
				let (ip, len) = <(IpAddr, u8)>::from(&p);
				match ip {
					IpAddr::V4(v4a) => self.v4_table.get_mut(&(v4a, len)).and_then(|hm| hm.remove(&id)),
					IpAddr::V6(v6a) => self.v6_table.get_mut(&(v6a, len)).and_then(|hm| hm.remove(&id)),
				}
			},
			NLRIEncoding::IP_MPLS(_) => None,
		};
	}

	fn announce(&mut self, prefix: NLRIEncoding, route: Arc<Route>) {
		match prefix {
			NLRIEncoding::IP(p) => {
				let (ip, len) = <(IpAddr, u8)>::from(&p);
				match ip {
					IpAddr::V4(v4a) => self.v4_table.entry((v4a, len)).or_insert(HashMap::new()).insert(0, route),
					IpAddr::V6(v6a) => self.v6_table.entry((v6a, len)).or_insert(HashMap::new()).insert(0, route),
				}
			},
			NLRIEncoding::IP_WITH_PATH_ID((p, id)) => {
				let (ip, len) = <(IpAddr, u8)>::from(&p);
				match ip {
					IpAddr::V4(v4a) => self.v4_table.entry((v4a, len)).or_insert(HashMap::new()).insert(id, route),
					IpAddr::V6(v6a) => self.v6_table.entry((v6a, len)).or_insert(HashMap::new()).insert(id, route),
				}
			},
			NLRIEncoding::IP_MPLS(_) => None,
		};
	}
}

struct BytesCoder<'a>(&'a mut bytes::BytesMut);
impl<'a> std::io::Write for BytesCoder<'a> {
	fn write(&mut self, b: &[u8]) -> Result<usize, std::io::Error> {
		self.0.extend_from_slice(&b);
		Ok(b.len())
	}
	fn flush(&mut self) -> Result<(), std::io::Error> {
		Ok(())
	}
}
struct BytesDecoder<'a> {
	buf: &'a mut bytes::BytesMut,
	pos: usize,
}
impl<'a> std::io::Read for BytesDecoder<'a> {
	fn read(&mut self, b: &mut [u8]) -> Result<usize, std::io::Error> {
		let copy_len = cmp::min(b.len(), self.buf.len() - self.pos);
		b[..copy_len].copy_from_slice(&self.buf[self.pos..self.pos + copy_len]);
		self.pos += copy_len;
		Ok(copy_len)
	}
}

struct MsgCoder<'a>(&'a Printer);
impl<'a> codec::Decoder for MsgCoder<'a> {
	type Item = Message;
	type Error = std::io::Error;

	fn decode(&mut self, bytes: &mut bytes::BytesMut) -> Result<Option<Message>, std::io::Error> {
		let mut decoder = BytesDecoder {
			buf: bytes,
			pos: 0
		};
		match (Reader {
			stream: &mut decoder,
			capabilities: Capabilities {
				FOUR_OCTET_ASN_SUPPORT: true,
				EXTENDED_PATH_NLRI_SUPPORT: true,
			}
		}).read() {
			Ok((_header, msg)) => {
				decoder.buf.advance(decoder.pos);
				Ok(Some(msg))
			},
			Err(e) => match e.kind() {
				std::io::ErrorKind::UnexpectedEof => Ok(None),
				_ => Err(e),
			},
		}
	}
}
impl<'a> codec::Encoder for MsgCoder<'a> {
	type Item = Message;
	type Error = std::io::Error;

	fn encode(&mut self, msg: Message, res: &mut bytes::BytesMut) -> Result<(), std::io::Error> {
		msg.write(&mut BytesCoder(res))?;
		Ok(())
	}
}

pub struct BGPClient {
	routes: Mutex<RoutingTable>,
	shutdown: AtomicBool,
}
impl BGPClient {
	pub fn get_asn(&self, addr: IpAddr) -> u32 {
		let mut path_vecs = self.routes.lock().unwrap().get_route_attrs(addr).clone();
		if path_vecs.is_empty() { return 0; }

		path_vecs.sort_unstable_by(|path_a, path_b| {
			path_a.pref.cmp(&path_b.pref)
				.then(path_b.path.len().cmp(&path_a.path.len()))
				.then(path_b.med.cmp(&path_a.med))
		});

		let primary_route = path_vecs.pop().unwrap();
		'asn_candidates: for asn in primary_route.path.iter().rev() {
			for secondary_route in path_vecs.iter() {
				if !secondary_route.path.contains(asn) {
					continue 'asn_candidates;
				}
			}
			return *asn;
		}
		*primary_route.path.last().unwrap_or(&0)
	}

	pub fn disconnect(&self) {
		self.shutdown.store(true, Ordering::Relaxed);
	}

	fn map_attrs(mut attrs: Vec<PathAttribute>) -> Option<Route> {
		let mut as4_path = None;
		let mut as_path = None;
		let mut pref = 100;
		let mut med = 0;
		for attr in attrs.drain(..) {
			match attr {
				PathAttribute::AS4_PATH(path) => as4_path = Some(path),
				PathAttribute::AS_PATH(path) => as_path = Some(path),
				PathAttribute::LOCAL_PREF(p) => pref = p,
				PathAttribute::MULTI_EXIT_DISC(m) => med = m,
				_ => {},
			}
		}
		if let Some(mut aspath) = as4_path.or(as_path) {
			let mut path = Vec::new();
			for seg in aspath.segments.drain(..) {
				match seg {
					Segment::AS_SEQUENCE(mut asn) => path.append(&mut asn),
					Segment::AS_SET(_) => {}, // Ignore sets for now, they're not that common anyway
				}
			}
			return Some(Route {
				path: path.clone(),
				pref,
				med,
			})
		} else { None }
	}

	fn connect_given_client(addr: SocketAddr, timeout: Duration, printer: &'static Printer, client: Arc<BGPClient>) {
		tokio::spawn(Delay::new(Instant::now() + timeout / 4).then(move |_| {
			let connect_timeout = Delay::new(Instant::now() + timeout.clone()).then(|_| {
				future::err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout reached"))
			});
			let client_reconn = Arc::clone(&client);
			TcpStream::connect(&addr).select(connect_timeout)
				.or_else(move |_| {
					Delay::new(Instant::now() + timeout / 2).then(|_| {
						future::err(())
					})
				}).and_then(move |stream| {
					let (write, read) = Framed::new(stream.0, MsgCoder(printer)).split();
					let (mut sender, receiver) = mpsc::channel(10); // We never really should send more than 10 messages unless they're dumb
					tokio::spawn(write.sink_map_err(|_| { () }).send_all(receiver)
						.then(|_| {
							future::err(())
						}));
					let _ = sender.try_send(Message::Open(Open {
						version: 4,
						peer_asn: 23456,
						hold_timer: timeout.as_secs() as u16,
						identifier: 0x453b1215, // 69.59.18.21
						parameters: vec![OpenParameter::Capabilities(vec![
							OpenCapability::MultiProtocol((AFI::IPV4, SAFI::Unicast)),
							OpenCapability::MultiProtocol((AFI::IPV6, SAFI::Unicast)),
							OpenCapability::FourByteASN(397444),
							OpenCapability::RouteRefresh,
							OpenCapability::AddPath(vec![
								(AFI::IPV4, SAFI::Unicast, AddPathDirection::ReceivePaths),
								(AFI::IPV6, SAFI::Unicast, AddPathDirection::ReceivePaths)]),
						])]
					}));
					TimeoutStream::new_persistent(read, timeout).for_each(move |bgp_msg| {
						if client.shutdown.load(Ordering::Relaxed) {
							return future::err(std::io::Error::new(std::io::ErrorKind::Other, "Shutting Down"));
						}
						match bgp_msg {
							Message::Open(_) => {
								client.routes.lock().unwrap().v4_table.clear();
								client.routes.lock().unwrap().v6_table.clear();
								printer.add_line("Connected to BGP route provider".to_string(), false);
							},
							Message::KeepAlive => {
								let _ = sender.try_send(Message::KeepAlive);
							},
							Message::Update(mut upd) => {
								upd.normalize();
								let mut route_table = client.routes.lock().unwrap();
								for r in upd.withdrawn_routes {
									route_table.withdraw(r);
								}
								if let Some(path) = Self::map_attrs(upd.attributes) {
									let path_arc = Arc::new(path);
									for r in upd.announced_routes {
										route_table.announce(r, Arc::clone(&path_arc));
									}
								}
								printer.set_stat(Stat::V4RoutingTableSize(route_table.v4_table.len()));
								printer.set_stat(Stat::V6RoutingTableSize(route_table.v6_table.len()));
							},
							_ => {}
						}
						future::ok(())
					}).or_else(move |e| {
						printer.add_line(format!("Got error from BGP stream: {:?}", e), true);
						future::ok(())
					})
				}).then(move |_| {
					if !client_reconn.shutdown.load(Ordering::Relaxed) {
						BGPClient::connect_given_client(addr, timeout, printer, client_reconn);
					}
					future::ok(())
				})
			})
		);
	}

	pub fn new(addr: SocketAddr, timeout: Duration, printer: &'static Printer) -> Arc<BGPClient> {
		let client = Arc::new(BGPClient {
			routes: Mutex::new(RoutingTable::new()),
			shutdown: AtomicBool::new(false),
		});
		BGPClient::connect_given_client(addr, timeout, printer, Arc::clone(&client));
		client
	}
}
