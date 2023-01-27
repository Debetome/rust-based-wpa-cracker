use ring::pbkdf2;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use itertools::Itertools;
use std::{
    collections::HashMap,
    io::BufReader,
    io::Read,
    fs::File,
    iter::Iterator,
    str::FromStr,
    process,
    env
};

type HmacSha1 = Hmac<Sha1>;

enum CharSet {
    LowerCase(String),
    UpperCase(String),
    Digits(String)
}

impl FromStr for CharSet {
    type Err = String;

    fn from_str(arg: &str) -> Result<Self, Self::Err> {
        match arg {
            "--lowercase" => Ok(CharSet::LowerCase(String::from("abcdefghijklmnopqrstuvwxyz"))),
            "--uppercase" => Ok(CharSet::UpperCase(String::from("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))),
            "--digits" => Ok(CharSet::Digits(String::from("1234567890"))),
            _ => Err(String::from("Invalid charset argument"))
        }
    }
}

struct Config {
    ssid: String,
    charset: CharSet,
    length: usize,
    iterator: Box<dyn Iterator<Item=String>>,
    eapols: Vec<Option<&'static str>>
}

struct Message {
    content: Vec<u8>
}

impl Message {
    fn new(eapol1: &[u8], eapol2: &[u8]) -> Self {
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

struct WpaCracker {
    config: Config,
    message: Message,
    frame802: Vec<u8>,
    mic: Vec<u8>
}

impl WpaCracker {
    fn new(config: Config) -> Result<Self, String> {
        let mut eapols = HashMap::<String, Vec<u8>>::new();
        for i in 0..config.eapols.len() {
            match Self::read_bytes(config.eapols[i].unwrap()) {
                Ok(bytes) => eapols.insert(format!("eapol{i}"), bytes).unwrap(),
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

    fn read_bytes(filename: &'static str) -> Result<Vec<u8>, String> {
        let mut bytes_content = Vec::new();
        let file = File::open(filename);
        if let Err(_) = file {
            return Err(String::from("Could not open '{}'"));
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

        while let Some(passphrase) = self.config.iterator.next() {
            let mut pmk = [0u8, 32];
            pbkdf2::derive(
                pbkdf2::PBKDF2_HMAC_SHA1, 
                std::num::NonZeroU32::new(4096).unwrap(), 
                &self.config.ssid.as_bytes(), 
                passphrase.as_bytes(), 
                &mut pmk);

            let mut ptk_hmac = HmacSha1::new_from_slice(&pmk).unwrap();
            ptk_hmac.update(self.message.as_bytes());
            let kck = &ptk_hmac.finalize().into_bytes()[..16];

            let mut calculated_mic_hmac = HmacSha1::new_from_slice(&kck).unwrap();
            calculated_mic_hmac.update(&zeroed_frame);
            let calculated_mic = &calculated_mic_hmac.finalize().into_bytes()[..];

            if self.mic == calculated_mic {
                println!("[+] Passphrase found: {passphrase}");
                break;
            }
        }
    }
}

fn main() {
    let args = env::args().collect::<Vec<String>>();
    let args = &args[1..].into_iter()
        .map(|arg| {
            match CharSet::from_str(arg.as_str()) {
                Ok(charset) => charset,
                Err(err) => {
                    eprintln!("[-] Error: {}", err);
                    process::exit(0);
                }
            }
        })
        .map(|charset| {
            match charset {
                CharSet::LowerCase(chars) => chars,
                CharSet::UpperCase(chars) => chars,
                CharSet::Digits(chars) => chars
            }
        })
        .collect::<Vec<String>>()
        .join("");

    for perm in args.chars().permutations(10).unique() {
        let perm = perm.iter().join("");
        println!("{}", perm);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_iterator_trait() {
        todo!();
    }
}
