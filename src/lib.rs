extern crate rustc_serialize;
extern crate rand;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;
use rustc_serialize::hex::FromHex;

//------------------------------------------------------------------------------

#[derive(Debug)]
pub struct UUID {
    mac: Vec<u8>,
}

impl UUID {

    pub fn new(iface: &str) -> UUID {
        let path = Path::new("/sys/class/net").join(Path::new(iface)).join("address");

        let f = File::open(path)
            .expect("Network interface not found.");

        let mut reader = BufReader::new(f);
        let mut line = String::new();

        reader.read_line(&mut line)
            .expect("Unable to read iface.");

        let mut mac_address = String::new();
        for _ in 0..6 {
            let s: String = line.drain(0..2).collect();
            line.drain(0..1);
            mac_address = mac_address + &s;
        }

        let mac = mac_address.from_hex()
            .expect("Unable to decode mac address.");

        UUID { mac: mac }
    }

    // Generates a 64-bit nonce. (should not be used as a UUID)
    pub fn generate_nonce(&self) -> [u8; 8] {
        let nanosec_bytes = nanosecs_since_unix_epoch();

        let mut rng = rand::thread_rng();
        let r = rng.gen::<[u8; 2]>();

        let mut bytes = [0; 8];
        bytes[0] = nanosec_bytes[0] ^ self.mac[0];
        bytes[1] = nanosec_bytes[1] ^ self.mac[1];
        bytes[2] = nanosec_bytes[2] ^ self.mac[2];
        bytes[3] = nanosec_bytes[3] ^ self.mac[3];
        bytes[4] = nanosec_bytes[4] ^ self.mac[4];
        bytes[5] = nanosec_bytes[5] ^ self.mac[5];
        bytes[6] = nanosec_bytes[6] ^ r[0];
        bytes[7] = nanosec_bytes[7] ^ r[1];
        bytes
    }

    // A variant of the v1 UUID (128-bit) where the main difference is performing
    // an xor on the mac address with a random set of bytes so that the mac address
    // does not get revealed.
    pub fn generate(&self) -> [u8; 16] {
        let nanosec_bytes = nanosecs_since_unix_epoch();

        let mut rng = rand::thread_rng();
        let r = rng.gen::<[u8; 8]>();

        let mut bytes = [0; 16];
        bytes[0] = nanosec_bytes[0];
        bytes[1] = nanosec_bytes[1];
        bytes[2] = nanosec_bytes[2];
        bytes[3] = nanosec_bytes[3];
        bytes[4] = nanosec_bytes[4];
        bytes[5] = nanosec_bytes[5];
        bytes[6] = nanosec_bytes[6];
        bytes[7] = nanosec_bytes[7];
        bytes[8] = self.mac[0] ^ r[0];
        bytes[9] = self.mac[1] ^ r[1];
        bytes[10] = self.mac[2] ^ r[2];
        bytes[11] = self.mac[3] ^ r[3];
        bytes[12] = self.mac[4] ^ r[4];
        bytes[13] = self.mac[5] ^ r[5];
        bytes[14] = r[6];
        bytes[15] = r[7];
        bytes
    }
}

//------------------------------------------------------------------------------
// Internal
//------------------------------------------------------------------------------

// Takes the inverse of the little_endian function on a 64-bit integer
// in order to obtain 8 bytes.
fn little_endian_inv64(x: u64) -> [u8; 8] {
    let mut bytes: [u8; 8] = [0; 8];
    bytes[0] = (x & 0xFF) as u8;
    for i in 1..8 {
        bytes[i] = ((x & (0xFF << i * 8)) >> i * 8) as u8;
    }
    bytes
}

// 100-nanosecond intervals since UNIX_EPOCH.
fn nanosecs_since_unix_epoch() -> [u8; 8] {
    let now = SystemTime::now();
    let duration = now.duration_since(UNIX_EPOCH)
        .expect("Failed to get duration since unix epoch.");

    // seconds to 100-nanosecond interval bytes
    let secs: u64 = duration.as_secs() as u64 * 1_000_000_0;
    let nanosecs: u64 = secs + (duration.subsec_nanos() as u64 / 1_00);

    little_endian_inv64(nanosecs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustc_serialize::hex::ToHex;
    use std::collections::HashMap;

    #[test]
    fn generate_uuid() {
        let uuid = UUID::new("enp0s31f6");

        let mut m = HashMap::new();

        for _ in 1..1_000_000 {
            let nonce = uuid.generate_nonce().to_hex();
            match m.get(&nonce) {
                Some(_) => {
                    println!("collision => {:?}", nonce);
                },
                None => {
                    m.insert(nonce.clone(), ());
                }
            }
        }
    }
}
