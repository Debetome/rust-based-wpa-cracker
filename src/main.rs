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
        let args = vec!["", "--ssid", "testap", "--eapol1", "eapol1.bin", "--eapol2", "eapol2.bin", "--max", "4", "--min", "4", "--digits"]
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
            eapols: vec![String::from("eapol1.bin"), String::from("eapol2.bin")]
        };

        let mut cracker = WpaCracker::new(config).unwrap();
        cracker.run();
    }

    #[test]
    fn test_crack_wpa_passphrase() {
        type HmacSha1 = Hmac<Sha1>;
    
        let ssid = "MOVISTAR_04E0";    
        let password = "e7pfRLCcDAcNnje5jAX7";

        let sample_message = [80, 97, 105, 114, 119, 105, 115, 101, 32, 107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110, 0, 48, 25, 102, 192, 32, 29, 252, 90, 29, 77, 4, 232, 9, 239, 76, 145, 67, 160, 252, 185, 201, 30, 44, 171, 78, 75, 63, 57, 199, 3, 253, 100, 232, 174, 82, 224, 66, 98, 188, 75, 125, 56, 6, 250, 151, 1, 84, 187, 235, 245, 114, 206, 190, 61, 170, 148, 206, 200, 252, 120, 95, 12, 104, 151, 70, 215, 221, 127, 107, 23, 125, 115, 97, 188, 167, 39, 0];

        let sample_pmk = vec![51, 53, 131, 150, 6, 215, 46, 64, 229, 153, 199, 254, 112, 243, 61, 69, 66, 241, 5, 238, 134, 233, 134, 147, 191, 43, 51, 141, 14, 134, 156, 128];
        
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
        
        let mut pmk = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA1,
            std::num::NonZeroU32::new(4096).unwrap(), 
            ssid.trim().as_bytes(), 
            password.trim().as_bytes(), 
            &mut pmk);

        let mut ptk_hmac = HmacSha1::new_from_slice(&pmk).unwrap();
        ptk_hmac.update(message.as_bytes());
        let kck = &ptk_hmac.finalize().into_bytes()[..16];

        let mut calculated_mic_hmac = HmacSha1::new_from_slice(&kck).unwrap();
        calculated_mic_hmac.update(&zeroed_frame);
        let calculated_mic = (&calculated_mic_hmac.finalize().into_bytes()[..16]).to_vec();

        assert_eq!(message.as_bytes(), &sample_message);
        assert_eq!(pmk.to_vec(), sample_pmk);
        assert_eq!(kck.len(), 16);
        assert_eq!(kck, [223, 211, 112, 202, 223, 189, 187, 81, 178, 111, 229, 142, 199, 171, 130, 217]);
        assert_eq!(mic, calculated_mic);
    }
}
