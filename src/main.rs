use tokio::sync::mpsc;

use std::process;
use std::env;

mod cracker;
mod config;
mod errors;

use cracker::*;
use config::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().collect::<Vec<String>>();
    let (tx, mut rx) = mpsc::channel::<Config>(200);

    let config_handle = tokio::spawn_blocking(move || {
        let config = match Config::try_from(&args) {
            Ok(config) => config,
            Err(errors) => {
                errors.into_iter().for_each(|err| {
                    println!("[-] Error: {}", err);
                });
                process::exit(0);
            },
        };
        tx.send(config);
    }

    let cracker_handle = tokio::spawn(async move {
        loop {
            if let Ok(config) = rx.try_recv() {
                let mut cracker = match WpaCracker::new(config) {
                    Ok(cracker) => cracker,
                    Err(error) => {
                        println!("Error: {}", error);
                        process::exit(0);
                    }
                };
                cracker.run();
            }
        }
    }

    config_handle.await.unwrap();
    cracker_handle.await.unwrap();

    cracker.run();
}

#[cfg(test)]
mod tests {
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
}
