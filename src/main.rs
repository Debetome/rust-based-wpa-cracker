use std::env;

mod cracker;
mod config;
mod errors;

use config::*;

fn main() {
    let args = env::args().collect::<Vec<String>>();
    
    match Config::try_from(args) {
        Ok(config) => {
            println!("{:#?}", config)
        },
        Err(errors) => {
            errors.into_iter().for_each(|err| {
                println!("[-] Error: {}", err);
            })
        },
    };
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_iterator_trait() {
        todo!();
    }
}
