use std::process;
use std::env;

mod cracker;
mod config;
mod errors;

use cracker::*;
use config::*;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<String>>();

    let config = match Config::try_from(&args) {
        Ok(config) => config,
        Err(errors) => {
            errors.into_iter().for_each(|err| {
                println!("[-] Error: {}", err);
            });
            process::exit(0);
        },
    };

    let mut cracker = match WpaCracker::new(config) {
        Ok(cracker) => cracker,
        Err(error) => {
            println!("Error: {}", error);
            process::exit(0);
        }
    };

    cracker.run();

    Ok(())
}

#[cfg(test)]
mod tests {
    use ring::pbkdf2;
    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    use std::io::BufReader;
    #[allow(unused_imports)]
    use std::io::{Read, BufRead};
    use std::fs::File;

    use crate::cracker::*;
    use crate::config::*;

    #[test]
    fn test_instantiate_cracker() {
        let args = vec!["", "--ssid", "testap", "--eapol1", "eapol", "--eapol2", "eapol", "--max", "4", "--min", "4", "--digits"]
            .iter()
            .map(|arg| arg.to_string())
            .collect::<Vec<String>>();

        let config = match Config::try_from(&args) {
            Ok(config) => Some(config),
            Err(errors) => {
                errors.into_iter().for_each(|err| {
                    println!("[-] Error: {}", err);
                });
                None
            }
        };

        assert!(config.is_some());

        if config.is_some() {
            let cracker = match WpaCracker::new(config.unwrap()) {
                Ok(cracker) => Some(cracker),
                Err(error) => {
                    println!("[-] Error: {}", error);
                    None
                }
            };

            assert!(cracker.is_some());
        }
    }

    #[test]
    fn test_run_cracker() {
        let config = Config {
            ssid: String::from("pepe"),
            charset: vec![CharSet::Digits(String::from("123"))],
            max: 3,
            min: 3,
            eapols: vec![String::from("eapol"), String::from("eapol")]
        };

        let mut cracker = WpaCracker::new(config).unwrap();
        cracker.run();
    }

    #[test]
    fn test_crack_wpa_passphrase() {
        type HmacSha1 = Hmac<Sha1>;
    
        let ssid = "MOVISTAR_04E0";    
        let password = "e7pfRLCcDAcNnje5jAX7";
        
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
        
        let eapol1 = read_bytes("eapol1.bin").unwrap();
        let eapol2 = read_bytes("eapol2.bin").unwrap();
        let frame802 = (&eapol2[34..]).to_vec();
        let mic = (&frame802[81..97]).to_vec();
        
        let message = Message::new(&eapol1, &eapol2);
        
        let zeroed_frame = [
            &frame802[..81],
            b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
            &frame802[97..]
        ]
        .concat();
        
        let mut pmk = [0u8, 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA1,
            std::num::NonZeroU32::new(4096).unwrap(), 
            ssid.as_bytes(), 
            password.as_bytes(), 
            &mut pmk);

        let mut ptk_hmac = HmacSha1::new_from_slice(&pmk).unwrap();
        ptk_hmac.update(message.as_bytes());
        let kck = &ptk_hmac.finalize().into_bytes()[..16];

        let mut calculated_mic_hmac = HmacSha1::new_from_slice(&kck).unwrap();
        calculated_mic_hmac.update(&zeroed_frame);
        let calculated_mic = (&calculated_mic_hmac.finalize().into_bytes()[..]).to_vec();

        assert_eq!(mic, calculated_mic)
    }
}
