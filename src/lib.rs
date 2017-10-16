#![feature(libc)]

extern crate libc;
extern crate rustc_serialize;
extern crate rand;
extern crate eui48;

use libc::{c_char};
use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::ops::Add;
use std::time::{SystemTime, Duration, UNIX_EPOCH};
use std::ffi::CStr;
use rand::{OsRng, Rng};
use rustc_serialize::hex::FromHex;
use eui48::{MacAddress, Eui48};

//------------------------------------------------------------------------------

#[no_mangle]
pub extern fn uuid_gen_new(ptr: *const c_char) -> *mut UUIDGen {
    let eui_cstr = unsafe {
        assert!(!ptr.is_null());
        CStr::from_ptr(ptr)
    };
    let mut eui: [u8; 6] = Default::default();
    eui.copy_from_slice(&eui_cstr.to_bytes()[0..6]);
    Box::into_raw(Box::new(UUIDGen::new(eui)))
}

#[no_mangle]
pub extern fn uuid_gen_free(ptr: *mut UUIDGen) {
    if ptr.is_null() { return }
    unsafe {
        Box::from_raw(ptr);
    }
}

#[no_mangle]
pub extern fn uuid_gen_nonce64(gen_ptr: *mut UUIDGen, nonce_ptr: *mut u8) {
    let gen = unsafe {
        assert!(!gen_ptr.is_null());
        &mut *gen_ptr
    };
    let nonce64: [u8; 8] = gen.nonce64();
    let nonce64: &[u8] = &nonce64[0..8];
    unsafe { std::ptr::copy(&(nonce64)[0], nonce_ptr, 8) }
}

#[no_mangle]
pub extern fn uuid_gen_uuid128(gen_ptr: *mut UUIDGen, uuid_ptr: *mut u8) {
    let gen = unsafe {
        assert!(!gen_ptr.is_null());
        &mut *gen_ptr
    };
    let uuid128: [u8; 16] = gen.uuid128();
    let uuid128: &[u8] = &uuid128[0..16];
    unsafe { std::ptr::copy(&(uuid128)[0], uuid_ptr, 16) }
}

//------------------------------------------------------------------------------

#[derive(Debug)]
pub struct UUIDGen(MacAddress);

impl UUIDGen {

    pub fn new(eui: Eui48) -> UUIDGen {
        UUIDGen(MacAddress::new(eui))
    }

    // Generates a 64-bit nonce. This should not be used as a UUID.
    pub fn nonce64(&self) -> [u8; 8] {
        let nanosec_bytes = nanosecs_since_epoch56();

        let mut rng = OsRng::new()
            .expect("Failed to initialise RNG.");
        let r = rng.gen::<[u8; 1]>();

        let mut bytes = [0; 8];
        bytes[0] = nanosec_bytes[0];
        bytes[1] = nanosec_bytes[1];
        bytes[2] = nanosec_bytes[2];
        bytes[3] = nanosec_bytes[3];
        bytes[4] = nanosec_bytes[4];
        bytes[5] = nanosec_bytes[5];
        bytes[6] = nanosec_bytes[6];
        bytes[7] = r[0];
        bytes
    }

    // A variant of the v1 UUID (128-bit).
    pub fn uuid128(&self) -> [u8; 16] {
        let nanosec_bytes = nanosecs_since_epoch();

        let mut rng = OsRng::new()
            .expect("Failed to initialise RNG.");
        let r = rng.gen::<[u8; 2]>();

        let mac_bytes = self.0.as_bytes();
        let mut bytes = [0; 16];
        bytes[0] = nanosec_bytes[0];
        bytes[1] = nanosec_bytes[1];
        bytes[2] = nanosec_bytes[2];
        bytes[3] = nanosec_bytes[3];
        bytes[4] = nanosec_bytes[4];
        bytes[5] = nanosec_bytes[5];
        bytes[6] = nanosec_bytes[6];
        bytes[7] = nanosec_bytes[7];
        bytes[8] = mac_bytes[0];
        bytes[9] = mac_bytes[1];
        bytes[10] = mac_bytes[2];
        bytes[11] = mac_bytes[3];
        bytes[12] = mac_bytes[4];
        bytes[13] = mac_bytes[5];
        bytes[14] = r[0];
        bytes[15] = r[1];
        bytes
    }
}

//------------------------------------------------------------------------------
// Internal
//------------------------------------------------------------------------------

fn epoch_min() -> SystemTime {
    let secs_years_47: u64 = 60 * 60 * 24 * 365 * 47;
    UNIX_EPOCH.add(Duration::new(secs_years_47, 0))
}

// Takes the inverse of the little_endian function on a 64-bit integer
// in order to obtain 7 bytes.
fn little_endian_inv56(x: u64) -> [u8; 7] {
    let mut bytes: [u8; 7] = [0; 7];
    bytes[0] = (x & 0xFF) as u8;
    for i in 1..7 {
        bytes[i] = ((x & (0xFF << i * 8)) >> i * 8) as u8;
    }
    bytes
}

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

// 100-nanosecond intervals since 2017 as 56-bits.
fn nanosecs_since_epoch56() -> [u8; 7] {
    let now = SystemTime::now();
    let duration = now.duration_since(epoch_min())
        .expect("Failed to get duration since unix epoch.");

    // seconds to 100-nanosecond interval bytes
    let secs: u64 = duration.as_secs() as u64 * 1_000_000_0;
    let nanosecs: u64 = secs + (duration.subsec_nanos() / 1_00) as u64;

    little_endian_inv56(nanosecs)
}

// 100-nanosecond intervals since 2017 as 64-bits.
fn nanosecs_since_epoch() -> [u8; 8] {
    let now = SystemTime::now();
    let duration = now.duration_since(epoch_min())
        .expect("Failed to get duration since unix epoch.");

    // seconds to 100-nanosecond interval bytes
    let secs: u64 = duration.as_secs() as u64 * 1_000_000_0;
    let nanosecs: u64 = secs + (duration.subsec_nanos() / 1_00) as u64;

    little_endian_inv64(nanosecs)
}

// Linux only interface Eui48 read.
pub fn read_interface_eui(iface: &str) -> Eui48 {
    let path = Path::new("/sys/class/net").join(Path::new(iface)).join("address");

    let f = File::open(path)
        .expect("Network interface not found.");

    let mut reader = BufReader::new(f);
    let mut line = String::new();

    reader.read_line(&mut line)
        .expect("Unable to read iface.");

    let mut eui: Eui48 = [0; 6];
    for i in 0..6 {
        let byte: String = line.drain(0..2).collect();
        line.drain(0..1);
        let byte_v = byte.from_hex()
            .expect(format!("Failed to decode mac_address byte {}", i).as_str());
        eui[i] = byte_v[0];
    }

    eui
}

//------------------------------------------------------------------------------
// Tests
//------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use rustc_serialize::hex::ToHex;

    #[test]
    fn uuid_gen() {

        let eui = read_interface_eui("new0");
        let gen = UUIDGen::new(eui);

        // birthday paradox B ^ (1/2 * n) of 64 bits => 2 ^ 32
        let mut entries = HashMap::new();

        for i in 1..4_294_967_296 as u64 {
            let key = gen.nonce64().to_hex();
            if !entries.contains_key(&key) {
                entries.insert(key, ());
            } else {
                println!("Found collision at {} where key = {}", i, key);
            }
        }
    }
}
