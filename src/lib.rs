use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpStream, ToSocketAddrs};

#[derive(Clone, Copy)]
pub struct Network {
    magic: u32,
    port: u16,
}

use messages::Message;

impl Network {
    pub fn testnet() -> Self {
        Network {
            magic: 0xDAB5BFFA,
            port: 18333,
        }
    }

    pub fn connect<A: ToSocketAddrs>(&mut self, addr: A) -> Result<Peer, io::Error> {
        let s = TcpStream::connect(addr)?;

        let peer = Peer {
            s,
            network: self.clone(),
        };

        Ok(peer)
    }

    pub fn version_message(&self) -> Message {
        todo!()
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
}

impl Peer {
    pub fn handshake(&mut self) -> Result<(), io::Error> {
        let version_message = self.network.version_message();
        self.send(version_message)?;

        Ok(())
    }

    pub fn send(&mut self, message: messages::Message) -> io::Result<()> {
        let mut bytes = message.serialize_to()?;
        self.s.write_all(&mut bytes)?;

        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub struct NetAddr {
    version_message: bool,
    time: u32,
    ip_addr: Ipv4Addr,
    port: u16,
}

mod messages {

    use super::NetAddr;
    use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
    use sha2::{Digest, Sha256};
    use std::io::{self, Write};

    #[derive(Debug)]
    pub enum Message {
        Version {
            version: i32,
            services: u64,
            timestamp: i64,
            addr_recv: NetAddr,
            addr_from: NetAddr,
            nonce: u64,
            user_agent: String,
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
                    // addr_recv
                    // addr_from
                    bytes.write_all(&nonce.to_le_bytes())?;
                    // user_agent
                    bytes.write_all(&start_height.to_le_bytes())?;
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
            _ => assert!(false)
        }
    }

    #[test]
    fn version_roundtrip() {
        let network = Network::testnet();
        let version = network.version_message();
        let mut msg_bytes = network.serialize_to(&version).unwrap();
        let msg = network.deserialize_from(&mut msg_bytes).unwrap();

        match msg {
            Message::Version { .. } => assert!(true),
            _ => assert!(false)
        }
    }
}
