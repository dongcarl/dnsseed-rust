use std::cmp;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::consensus::encode;
use bitcoin::consensus::encode::{Decodable, Encodable};
use bitcoin::network::address::Address;
use bitcoin::network::constants::Network;
use bitcoin::network::message::{RawNetworkMessage, NetworkMessage};
use bitcoin::network::message_network::VersionMessage;

use tokio::prelude::*;
use tokio::codec;
use tokio::codec::Framed;
use tokio::net::TcpStream;
use tokio::timer::Delay;

use futures::sync::mpsc;

use crate::printer::Printer;
use crate::timeout_stream::TimeoutStream;

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
	type Item = NetworkMessage;
	type Error = std::io::Error;

	fn decode(&mut self, bytes: &mut bytes::BytesMut) -> Result<Option<NetworkMessage>, std::io::Error> {
		let mut decoder = BytesDecoder {
			buf: bytes,
			pos: 0
		};
		match RawNetworkMessage::consensus_decode(&mut decoder) {
			Ok(res) => {
				decoder.buf.advance(decoder.pos);
				if res.magic == Network::Bitcoin.magic() {
					Ok(Some(res.payload))
				} else {
					Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "bad net magic"))
				}
			},
			Err(e) => match e {
				encode::Error::Io(_) => Ok(None),
				encode::Error::UnrecognizedNetworkCommand(_msg) => {
					decoder.buf.advance(decoder.pos);
					//XXX(fixthese): self.0.add_line(format!("rust-bitcoin doesn't support {}!", msg), true);
					Ok(None)
				},
				_ => {
					self.0.add_line(format!("Error decoding message: {:?}", e), true);
					Err(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
				},
			}
		}
	}
}
impl<'a> codec::Encoder for MsgCoder<'a> {
	type Item = NetworkMessage;
	type Error = std::io::Error;

	fn encode(&mut self, msg: NetworkMessage, res: &mut bytes::BytesMut) -> Result<(), std::io::Error> {
		if let Err(_) = (RawNetworkMessage {
			magic: Network::Bitcoin.magic(),
			payload: msg,
		}.consensus_encode(&mut BytesCoder(res))) {
			//XXX
		}
		Ok(())
	}
}

pub struct Peer {}
impl Peer {
	pub fn new(addr: SocketAddr, timeout: Duration, printer: &'static Printer) -> impl Future<Error=(), Item=(mpsc::Sender<NetworkMessage>, impl Stream<Item=NetworkMessage, Error=std::io::Error>)> {
		let connect_timeout = Delay::new(Instant::now() + timeout.clone()).then(|_| {
			future::err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout reached"))
		});
		TcpStream::connect(&addr).select(connect_timeout)
			.or_else(move |_| {
				Delay::new(Instant::now() + timeout / 10).then(|_| {
					future::err(())
				})
			}).and_then(move |stream| {
				let (write, read) = Framed::new(stream.0, MsgCoder(printer)).split();
				let (mut sender, receiver) = mpsc::channel(10); // We never really should send more than 10 messages unless they're dumb
				tokio::spawn(write.sink_map_err(|_| { () }).send_all(receiver)
					.then(|_| {
						future::err(())
					}));
				let _ = sender.try_send(NetworkMessage::Version(VersionMessage {
					version: 70015,
					services: (1 << 3), // NODE_WITNESS
					timestamp: SystemTime::now().duration_since(UNIX_EPOCH).expect("time > 1970").as_secs() as i64,
					receiver: Address::new(&addr, 0),
					sender: Address::new(&"0.0.0.0:0".parse().unwrap(), 0),
					nonce: 0xdeadbeef,
					user_agent: "/rust-bitcoin:0.18/bluematt-tokio-client:0.1/".to_string(),
					start_height: 0,
					relay: true,
				}));
				future::ok((sender, TimeoutStream::new(read, timeout)))
			})
	}
}
