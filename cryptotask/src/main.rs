#![feature(step_by)]
extern crate num;
extern crate crypto;
extern crate time;
extern crate ascii;
extern crate core;

use crypto::{aes, blockmodes};
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use num::bigint::BigInt;
use num::ToPrimitive;
use std::io::prelude::*;
use std::fs::File;
use std::str;
use ascii::AsAsciiStr;
use std::process;


const PASSWORD_LEN: usize = 32;
const ALFABET: &'static [u8; 36] = b"abcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Debug)]
struct BrokenCipher {
    multiplier: BigInt,
    shift: BigInt,
    alphabet_length: BigInt,
}

#[derive(Clone,Copy, PartialEq,Eq, Debug)]
struct BrokenCipherFailure(usize);

impl BrokenCipher {
    pub fn new() -> BrokenCipher {
        BrokenCipher {
            multiplier: BigInt::parse_bytes(b"B11924E1", 16).unwrap(),
            shift: BigInt::parse_bytes(b"27100001", 16).unwrap(),
            alphabet_length: BigInt::from(ALFABET.len()),
        }
    }

    pub fn decode(self: &BrokenCipher, key: &[u8; 32], data: &[u8], buffer: &mut [u8]) {
        let mut read_buffer = RefReadBuffer::new(data);
        let mut write_buffer = RefWriteBuffer::new(buffer);
        let mut decryptor =
            aes::ecb_decryptor(aes::KeySize::KeySize256, key, blockmodes::NoPadding);
        decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
    }

    pub fn generate_password(self: &BrokenCipher, timestamp: i32) -> [u8; PASSWORD_LEN] {
        let mut password: [u8; PASSWORD_LEN] = [0; PASSWORD_LEN];
        let mut ts = BigInt::from(timestamp);
        for round in 0..PASSWORD_LEN {
            let index: usize = (&ts % &self.alphabet_length).to_usize().unwrap();
            password[round] = ALFABET[index];
            ts = ((&ts * &self.multiplier) + &self.shift) >> 8;
        }
        return password;
    }

    pub fn try_decode_string<'a>(self: &BrokenCipher,
                                 key: &[u8; 32],
                                 data: &[u8],
                                 buffer: &'a mut [u8])
                                 -> core::result::Result<&'a str, BrokenCipherFailure> {
        self.decode(key, data, buffer);
        return str::from_utf8(buffer)
            .or(buffer.as_ascii_str().map(|i| i.as_str()))
            .map_err(|err| BrokenCipherFailure(err.valid_up_to()));
    }
}

fn read_task() -> Vec<u8> {
    let mut enc_buffer = Vec::new();
    let mut file = File::open("encrypted_file").unwrap();
    file.read_to_end(&mut enc_buffer).unwrap();
    return enc_buffer;
}

fn main() {
    let mut enc_buffer = read_task();
    let buffer_len = enc_buffer.len();
    let original_buffer = enc_buffer.clone();
    let last_bits = enc_buffer.split_off(buffer_len - 32);
    let first_bits = enc_buffer;
    println!("buffer size {} bits, last bit slice {}, fist bit slice {}",
             buffer_len * 8,
             last_bits.len() * 8,
             first_bits.len() * 8);
    let mut last_byte_decode_result = [0; 32];
    let mut text_decode_result = vec![0; original_buffer.len()];
    let cipher = BrokenCipher::new();
    for timestamp in (1467121149..0).step_by(-1) {
        if timestamp % 100000 == 0 {
            println!("{}: checking {} timestamp", time::get_time().sec, timestamp);
        }
        let password = cipher.generate_password(timestamp);
        cipher.decode(&password, &last_bits, &mut last_byte_decode_result);
        let last_char = last_byte_decode_result.last().unwrap();
        let same_elements_count =
            last_byte_decode_result.iter().rev().take_while(|it| last_char == *it).count();
        let last_char_should_be = 32 - ((buffer_len - same_elements_count) % 16);
        if *last_char as usize == last_char_should_be &&
           same_elements_count == last_char_should_be {
            print!("Candidate found for timestamp {}, same_elements_count {}. ",
                   timestamp,
                   same_elements_count);
            match cipher.try_decode_string(&password, &original_buffer, &mut text_decode_result) {
                Ok(text) => {
                    println!("timestamp {}, last_char {}, same_elements: {}",
                             timestamp,
                             last_char,
                             same_elements_count);
                    println!("{}", text);
                    process::exit(0);
                }
                Err(error) => println!("Can't decode {} char", error.0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    use self::rustc_serialize::base64::FromBase64;
    use ascii::AsAsciiStr;
    use super::BrokenCipher;

    #[test]
    fn should_generate_same_password_as_python() {
        let cipher = BrokenCipher::new();
        assert_eq!("etjvga7g3ph2eoickljmii4mi6fngono",
                   cipher.generate_password(1473444112).as_ascii_str().unwrap());
        assert_eq!("ovbu8d12dnvt6ftatp8pjtj617m1r2xs",
                   cipher.generate_password(1473445202).as_ascii_str().unwrap());
    }

    #[test]
    fn should_decode_test_string_encoded_with_python() {
        let cipher = BrokenCipher::new();
        let pwd = cipher.generate_password(1473447392);
        let mut text_decode_result = vec![0; 9];
        cipher.decode(&pwd,
                      &("35O496/FTsIGhAIA5IX9pV2vxw5rjc+te+SCGJOhvGU=".from_base64().unwrap()),
                      &mut text_decode_result);
        assert_eq!("lollollol", text_decode_result.as_ascii_str().unwrap());
    }
}
