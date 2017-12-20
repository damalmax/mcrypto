extern crate byteorder;
extern crate crypto;

use byteorder::{LittleEndian, ByteOrder};
use self::crypto::digest::Digest;
use self::crypto::sha2::Sha256;

const MAX_INT32: u64 = 0x7fffffff;
const CHARS: &'static [u8] = b"0123456789abcdef";

pub fn ms_sha256(ts: &str, id: &str, key: &str, magic_key: u64) -> String {
    let ts_ints = ts.as_bytes();
    let id_ints = id.as_bytes();
    let key_ints = key.as_bytes();

    let padding_len = (8 - ((ts_ints.len() + id_ints.len()) % 8)) % 8;
    let padding = vec![b'0'; padding_len];

    let mut message8 = ts_ints.to_vec();
    message8.extend_from_slice(id_ints);
    message8.extend_from_slice(padding.as_slice());

    let message32 = to_u32(message8);

    let mut sha_source = ts_ints.to_vec();
    sha_source.extend_from_slice(key_ints);

    let sha = sha256_sum(sha_source.as_slice());
    let trunc_sha = &sha.as_slice()[..16];

    let sha256_parts = to_u32(trunc_sha.to_vec());

    let hash0 = sha256_parts[0] as u64 & MAX_INT32;
    let hash1 = sha256_parts[1] as u64 & MAX_INT32;
    let hash2 = sha256_parts[2] as u64 & MAX_INT32;
    let hash3 = sha256_parts[3] as u64 & MAX_INT32;

    let mut low = 0u64;
    let mut high = 0u64;

    let loop_count = message32.len() - 2;
    let mut i = 0;
    loop {
        if i > loop_count {
            break;
        }
        let massage_value = message32[i + 1] as u64;
        let mut temp = (massage_value * magic_key) % MAX_INT32;
        low = ((low + temp) * hash0 + hash1) % MAX_INT32;
        high = high + low;

        temp = massage_value;
        low = ((low + temp) * hash2 + hash3) % MAX_INT32;
        high = high + low;
        i += 2;
    }

    let checksum64 = vec![
        (low + hash1) % MAX_INT32,
        (high + hash3) % MAX_INT32
    ];

    let output32 = vec![
        sha256_parts[0] ^ checksum64[0] as u32,
        sha256_parts[1] ^ checksum64[1] as u32,
        sha256_parts[2] ^ checksum64[0] as u32,
        sha256_parts[3] ^ checksum64[1] as u32
    ];

    let output8 = to_u8(output32);
    to_hex(output8.as_slice())
}

fn sha256_sum(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    let mut bytes = vec!(0u8; hasher.output_bytes());
    hasher.result(bytes.as_mut_slice());

    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(input);
    result.extend_from_slice(bytes.as_slice());
    result
}

fn to_hex(bytes: &[u8]) -> String {
    let mut v = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        v.push(CHARS[(byte >> 4) as usize]);
        v.push(CHARS[(byte & 0xf) as usize]);
    }
    String::from_utf8(v).expect("Unable to build result hash")
}

fn to_u8(input: Vec<u32>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();
    for value in input.to_vec().iter() {
        let bytes = vec!(
            *value as u8,
            (*value >> 8) as u8,
            (*value >> 16) as u8,
            (*value >> 24) as u8,
        );
        result.extend_from_slice(bytes.as_slice());
    }
    result
}

fn to_u32(input: Vec<u8>) -> Vec<u32> {
    let mut buf: Vec<u8> = Vec::new();
    let mut result: Vec<u32> = Vec::new();

    for value in input.iter() {
        if buf.len() < 4 {
            buf.push(*value)
        }
        if buf.len() == 4 {
            result.push(LittleEndian::read_u32(&buf));
            buf.clear();
        }
    }
    result
}
