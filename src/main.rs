use itsy_bitc::{Message, Network};
use std::io::{self};

fn main() -> io::Result<()> {
    // dig A seed.tbtc.petertodd.org
    let mut network = Network::testnet();

    let mut peer = network.connect(("99.79.74.229", 18333)).unwrap();

    peer.handshake()?;

    loop {
        let msg = peer.read_message()?;

        match msg {
            Message::Ping { nonce } => {
                let pong = peer.pong_message(nonce);
                peer.send(pong)?;
            }
            _ => {
                dbg!(&msg);
            }
        }
    }
}
