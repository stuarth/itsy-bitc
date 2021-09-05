use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use std::collections::HashSet;
use std::io::{self, Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, ToSocketAddrs};

#[derive(Clone)]
pub struct Network {
    magic: u32,
    port: u16,
    nonces: HashSet<u64>,
}

pub use messages::Message;

const VERSION: i32 = 70016;

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

pub trait ReadBitc: io::Read {
    fn read_varint(&mut self) -> io::Result<VarInt> {
        let inner = match self.read_u8()? {
            v @ 0..=0xfc => v as u64,
            0xfd => self.read_u16::<LittleEndian>()? as u64,
            0xfe => self.read_u32::<LittleEndian>()? as u64,
            0xff => self.read_u64::<LittleEndian>()?,
        };

        Ok(VarInt(inner))
    }

    fn read_varstr(&mut self) -> io::Result<VarStr> {
        let byte_count = self.read_varint()?;

        let mut bytes = vec![0u8; byte_count.inner() as usize];
        self.read_exact(&mut bytes)?;

        Ok(VarStr::new(String::from_utf8(bytes).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, e)
        })?))
    }

    fn read_inv_vec_element(&mut self) -> io::Result<InvVecElement> {
        let r#type = self.read_u32::<LittleEndian>()?;
        let mut hash = [0u8; 32];
        self.read_exact(&mut hash)?;

        Ok(InvVecElement { r#type, hash })
    }

    fn read_network_address_no_time(&mut self) -> io::Result<NetworkAddress> {
        let services = self.read_u64::<LittleEndian>()?;
        let mut addr_bytes = [0u8; 16];
        self.read_exact(&mut addr_bytes)?;
        let addr = Ipv4Addr::new(
            addr_bytes[12],
            addr_bytes[13],
            addr_bytes[14],
            addr_bytes[15],
        );
        let port = self.read_u16::<BigEndian>()?;

        Ok(NetworkAddress {
            time: None,
            services,
            addr: SocketAddr::from((addr, port)),
        })
    }

    fn read_network_address(&mut self) -> io::Result<NetworkAddress> {
        let time = self.read_u32::<LittleEndian>()?;
        let services = self.read_u64::<LittleEndian>()?;
        let mut addr_bytes = [0u8; 16];
        self.read_exact(&mut addr_bytes)?;
        let addr = Ipv4Addr::new(
            addr_bytes[12],
            addr_bytes[13],
            addr_bytes[14],
            addr_bytes[15],
        );
        let port = self.read_u16::<BigEndian>()?;

        Ok(NetworkAddress {
            time: Some(time),
            services,
            addr: SocketAddr::from((addr, port)),
        })
    }

    fn read_message(&mut self) -> io::Result<Message> {
        let _magic = self.read_u32::<LittleEndian>()?;

        let mut command = [0u8; 12];
        self.read_exact(&mut command)?;

        let command = std::str::from_utf8(&command[..])
            .unwrap()
            .trim_end_matches('\0')
            .to_ascii_lowercase();

        eprintln!("processing {}", &command);

        let length = self.read_u32::<LittleEndian>()?;
        let sha2 = self.read_u32::<LittleEndian>()?;

        let mut payload = vec![0u8; length as usize];

        self.read_exact(&mut payload)?;

        if sha2.to_le_bytes() != Message::sha2(&payload) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sha2 does not match!",
            ));
        }

        let mut rdr = Cursor::new(payload);

        let message = match command.as_ref() {
            "addr" => {
                let count = rdr.read_varint()?;
                let mut addrs = Vec::with_capacity(count.inner() as usize);

                for _ in 0..count.inner() {
                    addrs.push(rdr.read_network_address()?);
                }

                Message::Addr { count, addrs }
            }
            "feefilter" => {
                let fee_rate = rdr.read_u64::<LittleEndian>()?;
                Message::FeeFilter { fee_rate }
            }
            "getheaders" => {
                let version = rdr.read_u32::<LittleEndian>()?;
                let hash_count = rdr.read_varint()?;

                let mut block_locator_hashes = [0u8; 32];
                rdr.read_exact(&mut block_locator_hashes)?;

                let mut hash_stop = [0u8; 32];
                rdr.read_exact(&mut hash_stop)?;

                Message::GetHeaders {
                    version,
                    hash_count,
                    block_locator_hashes,
                    hash_stop,
                }
            }
            "inv" => {
                let count = rdr.read_varint()?;
                let mut inventory = Vec::with_capacity(count.inner() as usize);

                for _ in 0..count.inner() {
                    inventory.push(rdr.read_inv_vec_element()?);
                }

                Message::Inv { count, inventory }
            }
            "ping" => {
                let nonce = rdr.read_u64::<LittleEndian>()?;
                Message::Ping { nonce }
            }
            "pong" => {
                let nonce = rdr.read_u64::<LittleEndian>()?;
                Message::Pong { nonce }
            }
            "sendcmpct" => {
                let enabled_byte = rdr.read_u8()?;
                let enabled = enabled_byte == 0x1;
                let version = rdr.read_u64::<LittleEndian>()?;

                Message::SendCmpct { enabled, version }
            }
            "sendheaders" => Message::SendHeaders {},
            "verack" => Message::Verack {},
            "version" => {
                // Field Size	Description	Data type	Comments
                // 4	version	int32_t	Identifies protocol version being used by the node
                // 8	services	uint64_t	bitfield of features to be enabled for this connection
                // 8	timestamp	int64_t	standard UNIX timestamp in seconds
                // 26	addr_recv	net_addr	The network address of the node receiving this message
                // Fields below require version ≥ 106
                // 26	addr_from	net_addr	Field can be ignored. This used to be the network address of the node emitting this message, but most P2P implementations send 26 dummy bytes. The "services" field of the address would also be redundant with the second field of the version message.
                // 8	nonce	uint64_t	Node random nonce, randomly generated every time a version packet is sent. This nonce is used to detect connections to self.
                // ?	user_agent	var_str	User Agent (0x00 if string is 0 bytes long)
                // 4	start_height	int32_t	The last block received by the emitting node
                // Fields below require version ≥ 70001
                // 1	relay	bool	Whether the remote peer should announce relayed transactions or not, see BIP 0037

                let version = rdr.read_i32::<LittleEndian>()?;
                let services = rdr.read_u64::<LittleEndian>()?;
                let timestamp = rdr.read_i64::<LittleEndian>()?;
                let addr_recv = rdr.read_network_address_no_time()?;
                let addr_from = rdr.read_network_address_no_time()?;
                let nonce = rdr.read_u64::<LittleEndian>()?;
                let user_agent = rdr.read_varstr()?;
                let start_height = rdr.read_i32::<LittleEndian>()?;
                let relay = if version >= 70001 {
                    Some(rdr.read_u8()? == 1)
                } else {
                    None
                };

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
                }
            }
            _ => Message::Unknown {
                bytes: rdr.into_inner(),
            },
        };

        Ok(message)
    }
}

impl<R: io::Read + ?Sized> ReadBitc for R {}

impl Network {
    pub fn testnet() -> Self {
        Network {
            magic: 0x0709110B,
            port: 18333,
            nonces: HashSet::new(),
        }
    }

    pub fn connect<A: ToSocketAddrs>(&mut self, addr: A) -> io::Result<Peer> {
        let s = TcpStream::connect(addr)?;
        let addr = s.peer_addr()?;

        let peer = Peer {
            s,
            network: self.clone(),
            addr,
            version: None,
        };

        Ok(peer)
    }

    pub fn version_message_for(&self, addr: &NetworkAddress) -> Message {
        Message::Version {
            version: VERSION,
            services: Services::NODE_NETWORK as u64,
            addr_recv: addr.clone(),
            addr_from: NetworkAddress::blank(),
            nonce: rand::random(),
            user_agent: VarStr::new("/Satoshi:0.21.1/"),
            start_height: 1,
            relay: Some(true),
            timestamp: now() as i64,
        }
    }

    pub fn verack(&self) -> Message {
        Message::Verack {}
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
        // https://en.bitcoin.it/wiki/Version_Handshake

        // When the local peer (L) connects to a remote peer (R), the remote peer will not send any data until it receives a version message.

        // L -> R: Send version message with the local peer's version
        // R -> L: Send version message back
        // R -> L: Send verack message
        // R:      Sets version to the minimum of the 2 versions
        // L -> R: Send verack message after receiving version message from R
        // L:      Sets version to the minimum of the 2 versions

        let addr = NetworkAddress {
            time: None,
            addr: self.addr,
            services: Services::NODE_NETWORK as u64,
        };

        let version_msg = self.network.version_message_for(&addr);

        self.send(version_msg)?;

        match self.s.read_message()? {
            _msg @ Message::Version { .. } => (),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected version message",
                ))
            }
        }

        match self.s.read_message()? {
            _msg @ Message::Verack { .. } => (),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected verack message",
                ))
            }
        }

        let verack_msg = self.network.verack();
        self.send(verack_msg)?;

        // set peer version

        Ok(())
    }

    pub fn set_version(&mut self, version: Option<i32>) {
        self.version = version;
    }

    pub fn send(&mut self, message: messages::Message) -> io::Result<()> {
        self.s.write_message(&message, &self.network)?;
        self.s.flush()?;

        Ok(())
    }

    pub fn read_message(&mut self) -> io::Result<Message> {
        self.s.read_message()
    }

    pub fn pong_message(&self, nonce: u64) -> Message {
        Message::Pong { nonce }
    }
}

// 4	time	uint32	the Time (version >= 31402). Not present in version message.
// 8	services	uint64_t	same service(s) listed in version
// 16	IPv6/4	char[16]	IPv6 address. Network byte order. The original client only supported IPv4 and only read the last 4 bytes to get the IPv4 address. However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address
// (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).

// 2	port	uint16_t	port number, network byte order

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NetworkAddress {
    time: Option<u32>,
    services: u64,
    addr: SocketAddr,
}

impl NetworkAddress {
    pub fn blank() -> Self {
        Self {
            time: None,
            services: Services::NODE_NETWORK as u64,
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0),
        }
    }
}

pub trait WriteBitc: io::Write {
    fn write_varint(&mut self, v: &VarInt) -> io::Result<()> {
        // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer

        // Value	Storage length	Format
        // < 0xFD	1	uint8_t
        // <= 0xFFFF	3	0xFD followed by the length as uint16_t
        // <= 0xFFFF FFFF	5	0xFE followed by the length as uint32_t
        // -	9	0xFF followed by the length as uint64_t

        match v.0 {
            v if v < 0xFDu64 => {
                self.write_all(&(v as u8).to_le_bytes())?;
            }
            v if v < 0xFFFFu64 => {
                self.write_all(&0xFDu8.to_le_bytes())?;
                self.write_all(&(v as u16).to_le_bytes())?;
            }
            v if v < 0xFFFF_FFFFu64 => {
                self.write_all(&0xFEu8.to_le_bytes())?;
                self.write_all(&(v as u32).to_le_bytes())?;
            }
            v @ _ => {
                self.write_all(&0xFFu8.to_le_bytes())?;
                self.write_all(&v.to_le_bytes())?;
            }
        };

        Ok(())
    }

    fn write_varstr(&mut self, v: &VarStr) -> io::Result<()> {
        let len = VarInt::new(v.0.len() as u64);
        self.write_varint(&len)?;
        self.write_all(v.0.as_bytes())?;

        Ok(())
    }

    fn write_message(&mut self, msg: &Message, network: &Network) -> io::Result<()> {
        // Almost all integers are encoded in little endian. Only IP or port number are encoded big endian. All field sizes are numbers of bytes.

        let mut message_bytes = Cursor::new(vec![]);
        message_bytes.write_message_body(&msg)?;
        let mut message_bytes = message_bytes.into_inner();

        self.write_all(&network.magic.to_le_bytes())?;
        self.write_all(&msg.command())?;
        self.write_all(&(message_bytes.len() as u32).to_le_bytes())?;

        self.write_all(&Message::sha2(&message_bytes))?;
        self.write_all(&mut message_bytes)?;

        Ok(())
    }

    fn write_message_body(&mut self, msg: &Message) -> io::Result<()> {
        match msg {
            Message::Ping { nonce } => {
                self.write_all(&nonce.to_le_bytes())?;
            }
            Message::Pong { nonce } => {
                self.write_all(&nonce.to_le_bytes())?;
            }
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
                self.write_all(&version.to_le_bytes())?;
                self.write_all(&services.to_le_bytes())?;
                self.write_all(&timestamp.to_le_bytes())?;
                self.write_network_address(&addr_recv)?;
                self.write_network_address(&addr_from)?;
                self.write_all(&nonce.to_le_bytes())?;
                self.write_varstr(&user_agent)?;
                self.write_all(&start_height.to_le_bytes())?;

                if *version > 70001 {
                    match relay {
                        Some(true) => self.write_all(&1u8.to_le_bytes())?,
                        Some(false) => self.write_all(&0u8.to_le_bytes())?,
                        _ => panic!("relay not set!"),
                    }
                }
            }
            Message::Verack {} => {}
            _ => panic!("don't know how to serialize!"),
        }

        Ok(())
    }

    fn write_network_address(&mut self, addr: &NetworkAddress) -> io::Result<()> {
        if let Some(time) = addr.time {
            self.write_all(&time.to_le_bytes())?;
        }
        self.write_all(&mut addr.services.to_le_bytes())?;
        match addr.addr.ip() {
            IpAddr::V4(ip) => {
                self.write_all(&mut 0u32.to_be_bytes())?;
                self.write_all(&mut 0u32.to_be_bytes())?;
                self.write_all(&mut 0xffffu32.to_be_bytes())?;
                self.write_all(&mut ip.octets())?;
            }
            IpAddr::V6(ip) => {
                self.write_all(&mut ip.octets())?;
            }
        }
        self.write_all(&mut addr.addr.port().to_be_bytes())?;

        Ok(())
    }
}

impl<W> WriteBitc for W where W: io::Write + ?Sized {}

#[derive(Debug, PartialEq, Eq)]
pub struct VarInt(u64);

impl VarInt {
    fn new(v: u64) -> Self {
        Self(v)
    }

    fn inner(&self) -> u64 {
        self.0
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct VarStr(String);

impl VarStr {
    fn new<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct InvVecElement {
    r#type: u32,
    hash: [u8; 32],
}

mod messages {

    use crate::{InvVecElement, NetworkAddress, VarInt};

    use super::VarStr;
    use sha2::{Digest, Sha256};
    use std::io::Write;

    #[derive(Debug, PartialEq, Eq)]
    pub enum Message {
        Addr {
            count: VarInt,
            addrs: Vec<NetworkAddress>,
        },
        FeeFilter {
            fee_rate: u64,
        },
        GetHeaders {
            version: u32,
            hash_count: VarInt,
            block_locator_hashes: [u8; 32],
            hash_stop: [u8; 32],
        },
        Inv {
            count: VarInt,
            inventory: Vec<InvVecElement>,
        },
        Ping {
            nonce: u64,
        },
        Pong {
            nonce: u64,
        },
        SendCmpct {
            enabled: bool,
            version: u64,
        },
        SendHeaders {},
        Version {
            version: i32,
            services: u64,
            timestamp: i64,
            addr_recv: NetworkAddress,
            addr_from: NetworkAddress,
            nonce: u64,
            user_agent: VarStr,
            start_height: i32,
            relay: Option<bool>,
        },
        Verack {},
        Unknown {
            bytes: Vec<u8>,
        },
    }

    impl Message {
        pub fn command(&self) -> [u8; 12] {
            let s = match self {
                Message::Addr { .. } => "addr",
                Message::FeeFilter { .. } => "feefilter",
                Message::GetHeaders { .. } => "getheaders",
                Message::Inv { .. } => "inv",
                Message::Ping { .. } => "ping",
                Message::Pong { .. } => "pong",
                Message::SendCmpct { .. } => "sendcmpct",
                Message::SendHeaders { .. } => "sendheaders",
                Message::Version { .. } => "version",
                Message::Verack { .. } => "verack",
                Message::Unknown { .. } => "unknown??",
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
    use std::io::Cursor;

    #[test]
    fn verack_roundtrip() {
        let network = Network::testnet();
        let verack = network.verack();
        let mut msg_bytes = Cursor::new(vec![]);
        msg_bytes.write_message(&verack, &network).unwrap();

        msg_bytes.set_position(0);

        let msg = msg_bytes.read_message().unwrap();

        match msg {
            Message::Verack { .. } => assert!(true),
            _ => assert!(false),
        }
    }

    #[test]
    fn version_roundtrip() {
        let network = Network::testnet();
        let addr = NetworkAddress {
            time: None,
            services: Services::NODE_NETWORK as u64,
            addr: SocketAddr::from(([8, 4, 2, 1], 18333)),
        };
        let version = network.version_message_for(&addr);
        let mut msg_bytes = Cursor::new(vec![]);
        msg_bytes.write_message(&version, &network).unwrap();

        msg_bytes.set_position(0);

        let msg = msg_bytes.read_message().unwrap();

        assert_eq!(version, msg);
    }

    #[test]
    fn var_int_serialize_to() {
        let mut buf = Cursor::new(vec![]);

        buf.write_varint(&VarInt::new(0)).unwrap();

        assert_eq!(buf.get_ref(), &[0x0]);

        let mut buf = Cursor::new(vec![]);

        buf.write_varint(&VarInt::new(1)).unwrap();

        assert_eq!(buf.get_ref(), &[0x1]);

        let mut buf = Cursor::new(vec![]);

        buf.write_varint(&VarInt::new(0xFFFF_FF)).unwrap();

        assert_eq!(buf.get_ref(), &[0xFE, 0xff, 0xff, 0xff, 0]);
    }

    #[test]
    fn var_str_serialize_to() {
        let mut buf = Cursor::new(vec![]);
        let hello = VarStr::new("hello");

        buf.write_varstr(&hello).unwrap();

        assert_eq!(buf.get_ref(), &[0x5, 104, 101, 108, 108, 111]);

        buf.set_position(0);

        assert_eq!(buf.read_varstr().unwrap(), hello);
    }
}
