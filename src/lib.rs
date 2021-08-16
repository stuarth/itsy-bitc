use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};
use std::net::{TcpStream, SocketAddr};
use std::collections::HashSet;

#[derive(Clone)]
pub struct Network {
    magic: u32,
    port: u16,
    nonces: HashSet<u64>,
}

use messages::Message;

const VERSION: i32 = 31402;

#[allow(non_camel_case_types)]
#[repr(u64)]
pub enum Services {
    NODE_NETWORK = 1,
    NODE_GETUTXO = 2,
    NODE_BLOOM = 4,
    NODE_WITNESS = 8,
    NODE_XTHIN = 16,
    NODE_COMPACT_FILTERS = 64,
    NODE_NETWORK_LIMITED = 1024,
}

fn now() -> u64 {
    use std::time::SystemTime;

    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("clock mishap");

    since_epoch.as_secs()
}

impl Network {
    pub fn testnet() -> Self {
        Network {
            magic: 0xDAB5BFFA,
            port: 18333,
            nonces: HashSet::new(),
        }
    }

    pub fn connect(&mut self, addr: SocketAddr) -> Result<Peer, io::Error> {
        let s = TcpStream::connect(addr)?;

        let peer = Peer {
            s,
            network: self.clone(),
            addr,
            version: None,
        };

        Ok(peer)
    }

    pub fn version_message_for(&self, addr: &SocketAddr) -> Message {
        Message::Version {
            version: VERSION,
            services: Services::NODE_NETWORK as u64,
            addr_recv: addr.clone(),
            addr_from: addr.clone(), // TODO fix
            nonce: rand::random(),
            user_agent: VarStr::new(""),
            start_height: 0,
            relay: true,
            timestamp: now() as i64,
        }
    }

    pub fn verack(&self) -> Message {
        Message::Verack {}
    }

    pub fn serialize_to(&self, message: &Message) -> io::Result<Vec<u8>> {
        let mut bytes = vec![];

        let message_bytes = message.serialize_to()?;
        bytes.write_u32::<LittleEndian>(self.magic)?;
        bytes.write(&message.command())?;
        bytes.write_u32::<LittleEndian>(message_bytes.len() as u32)?;

        let sha2_bytes = Message::sha2(&message_bytes);
        bytes.write(&sha2_bytes)?;
        bytes.write(&message_bytes)?;

        Ok(bytes)
    }

    pub fn deserialize_from(&self, buf: &mut [u8]) -> anyhow::Result<Message> {
        let rdr = &mut &buf[..];

        let magic = rdr.read_u32::<LittleEndian>()?;

        let mut command = [0u8; 12];
        rdr.read_exact(&mut command)?;

        let c = std::str::from_utf8(&command[..])
            .unwrap()
            .trim_end_matches('\0');

        match c {
            "version" => println!("version found"),
            "verack" => println!("verack found"),
            _ => println!("unknown!"),
        };

        println!("length {:x?}", &rdr[..4]);
        let length = rdr.read_u32::<LittleEndian>()?;
        let sha2 = rdr.read_u32::<LittleEndian>();
        let payload = &rdr[..length as usize];

        println!("payload {:x?}", &payload);

        Ok(Message::Verack {})
    }
}

pub struct Peer {
    s: TcpStream,
    network: Network,
    addr: SocketAddr,
    version: Option<i32>,
}

impl Peer {
    pub fn handshake(&mut self) -> Result<(), io::Error> {
        // When the local peer (L) connects to a remote peer (R), the remote peer will not send any data until it receives a version message.

        // L -> R: Send version message with the local peer's version
        // R -> L: Send version message back
        // R -> L: Send verack message
        // R:      Sets version to the minimum of the 2 versions
        // L -> R: Send verack message after receiving version message from R
        // L:      Sets version to the minimum of the 2 versions

        let version_message = self.network.version_message_for(&self.addr);
        self.send(version_message)?;

        Ok(())
    }

    pub fn set_version(&mut self, version: Option<i32>) {
        self.version = version;
    }

    pub fn send(&mut self, message: messages::Message) -> io::Result<()> {
        let mut bytes = message.serialize_to()?;
        self.s.write_all(&mut bytes)?;

        Ok(())
    }

    pub fn receive(&mut self) -> io::Result<Message> {
        todo!()
    }
}

impl SerializeTo for SocketAddr {
    fn serialize_to(&self, buf: &mut Vec<u8>, options: u8) -> io::Result<u8> {
        use std::net::IpAddr;

        let include_time = !options & 0x1 == 0x1;

        // TODO: encode as enum
        if include_time {
            buf.write_all(&(now() as u32).to_le_bytes())?;
        }

        // services
        buf.write_all(&0u64.to_le_bytes())?; // TODO ???

        match self.ip() {
            IpAddr::V4(addr) => {
                let as_u32 = u32::from_le_bytes(addr.octets());
                buf.write_all(&(as_u32 as u128).to_le_bytes())?;
            },
            IpAddr::V6(addr) => {
                buf.write_all(&addr.octets())?;
            }
        }

        buf.write_all(&self.port().to_be_bytes())?;

        if include_time {
            Ok(30)
        } else {
            Ok(26)
        }
    }
}

// impl NetAddr {
//     pub fn serialize_to(&self) -> io::Result<Vec<u8>> {
//         let mut bytes = vec![];

//         if !self.version_message {
//             // Time is not present in version message.
//             bytes.write_all(&(now() as u32).to_le_bytes())?;
//         }

//         //ip_addr
//         self.ip_addr.serialize_to(&mut bytes)?;

//         // port is BE
//         bytes.write_all(&self.port.to_be_bytes())?;

//         Ok(bytes)
//     }
// }

pub trait SerializeTo {
    fn serialize_to(&self, buf: &mut Vec<u8>, options: u8) -> io::Result<u8>;
}

struct VarInt(u64);

impl VarInt {
    fn new(v: u64) -> Self {
        Self(v)
    }
}

impl SerializeTo for VarInt {
    fn serialize_to(&self, buf: &mut Vec<u8>, _options: u8) -> io::Result<u8> {
        // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

        // Value	Storage length	Format
        // < 0xFD	1	uint8_t
        // <= 0xFFFF	3	0xFD followed by the length as uint16_t
        // <= 0xFFFF FFFF	5	0xFE followed by the length as uint32_t
        // -	9	0xFF followed by the length as uint64_t

        let bytes_written = match self.0 {
            v if v < 0xFDu64 => {
                buf.write_all(&(v as u8).to_le_bytes())?;
                1
            }
            v if v < 0xFFFFu64 => {
                buf.write_all(&0xFDu8.to_le_bytes())?;
                buf.write_all(&(v as u16).to_le_bytes())?;
                3
            }
            v if v < 0xFFFF_FFFFu64 => {
                buf.write_all(&0xFEu8.to_le_bytes())?;
                buf.write_all(&(v as u32).to_le_bytes())?;
                5
            }
            v @ _ => {
                buf.write_all(&0xFFu8.to_le_bytes())?;
                buf.write_all(&v.to_le_bytes())?;
                9
            }
        };

        Ok(bytes_written)
    }
}

#[derive(Debug)]
pub struct VarStr(String);

impl SerializeTo for VarStr {
    fn serialize_to(&self, mut buf: &mut Vec<u8>, _options: u8) -> io::Result<u8> {
        let len = VarInt::new(self.0.len() as u64);
        let len_bytes = len.serialize_to(&mut buf, 0)?;
        let str_bytes = buf.write(self.0.as_bytes())?;

        Ok(len_bytes + str_bytes as u8)
    }
}

impl VarStr {
    fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }
}

// impl SerializeTo for Ipv4Addr {
//     fn serialize_to(&self, mut buf: &mut Vec<u8>, _options: u8) -> io::Result<u8> {
//         let mut bytes = [0u8; 16];
//         (&mut bytes[12..]).write_all(&self.octets())?;
//         buf.copy_from_slice(&bytes);

//         Ok(16)
//     }
// }
mod messages {

    use crate::SerializeTo;

    use super::{VarStr};
    use sha2::{Digest, Sha256};
    use std::{io::{self, Write}, net::SocketAddr};

    #[derive(Debug)]
    pub enum Message {
        Version {
            version: i32,
            services: u64,
            timestamp: i64,
            addr_recv: SocketAddr,
            addr_from: SocketAddr,
            nonce: u64,
            user_agent: VarStr,
            start_height: i32,
            relay: bool,
        },
        Verack {},
    }

    impl Message {
        pub(crate) fn serialize_to(&self) -> io::Result<Vec<u8>> {
            // Almost all integers are encoded in little endian. Only IP or port number are encoded big endian. All field sizes are numbers of bytes.

            let mut bytes = vec![];

            match self {
                Message::Version {
                    version,
                    services,
                    timestamp,
                    addr_recv,
                    addr_from,
                    nonce,
                    user_agent,
                    start_height,
                    relay,
                } => {
                    bytes.write_all(&version.to_le_bytes())?;
                    bytes.write_all(&services.to_le_bytes())?;
                    bytes.write_all(&timestamp.to_le_bytes())?;
                    addr_recv.serialize_to(&mut bytes, 0)?;
                    addr_from.serialize_to(&mut bytes, 0)?;
                    bytes.write_all(&nonce.to_le_bytes())?;
                    user_agent.serialize_to(&mut bytes, 0)?;
                    bytes.write_all(&start_height.to_le_bytes())?;

                    if *version > 70001 {
                        bytes.write_all(&[(*relay as u8)])?;
                    }
                }
                Message::Verack {} => {}
            }

            Ok(bytes)
        }

        pub(crate) fn command(&self) -> [u8; 12] {
            let s = match self {
                Message::Version { .. } => "version",
                Message::Verack { .. } => "verack",
            };

            as_command(s)
        }

        pub fn sha2(message_bytes: &[u8]) -> [u8; 4] {
            let sha2 = Sha256::digest(&Sha256::digest(&message_bytes));
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&sha2[0..4]);
            bytes
        }
    }

    pub fn as_command<S: AsRef<[u8]>>(s: S) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        (&mut bytes[..]).write(s.as_ref()).unwrap();
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verack_roundtrip() {
        let network = Network::testnet();
        let verack = network.verack();
        let mut msg_bytes = network.serialize_to(&verack).unwrap();
        let msg = network.deserialize_from(&mut msg_bytes).unwrap();

        match msg {
            Message::Verack { .. } => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn version_roundtrip() {
        let network = Network::testnet();
        let version = network.version_message_for(&SocketAddr::from(([8,4,2,1], 18333)));
        let mut msg_bytes = network.serialize_to(&version).unwrap();

        println!("{:x?}", &msg_bytes);

        let msg = network.deserialize_from(&mut msg_bytes).unwrap();

        dbg!(&msg);

        match msg {
            Message::Version { .. } => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn var_int_serialize_to() {
        let mut buf = vec![];

        VarInt::new(0).serialize_to(&mut buf, 0).unwrap();

        assert_eq!(&buf, &[0x0]);

        buf.clear();

        VarInt::new(1).serialize_to(&mut buf, 0).unwrap();

        assert_eq!(&buf, &[0x1]);

        buf.clear();

        VarInt::new(0xFFFF_FF).serialize_to(&mut buf, 0).unwrap();

        assert_eq!(&buf, &[0xFE, 0xff, 0xff, 0xff, 0]);
    }

    #[test]
    fn var_str_serialize_to() {
        let mut buf = vec![];

        VarStr::new("hello").serialize_to(&mut buf, 0).unwrap();

        assert_eq!(buf, [0x5, 104, 101, 108, 108, 111]);
    }
}
