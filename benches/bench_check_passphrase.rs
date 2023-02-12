use criterion::{
    criterion_main, 
    criterion_group, 
    black_box,
    Criterion
};

use std::time::Duration;

use ring::pbkdf2;
use hmac::{Hmac, Mac};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

criterion_group!(benches, bench_generate_check_mic);
criterion_main!(benches);

struct TestMessage {
    content: Vec<u8>
}

impl TestMessage {
    pub fn new() -> Self {
        let ap_mac: Vec<u8> = (&"00:45:ED:FE:32:14".as_bytes()).to_vec();
        let sta_mac: Vec<u8> = (&"44:55:FE:27:42:66".as_bytes()).to_vec();
        let anonce: Vec<u8> = (&"123456789".as_bytes()).to_vec();
        let snonce: Vec<u8> = (&"987654321".as_bytes()).to_vec();

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

fn generate_check_mic(message: &TestMessage, zeroed_frame: &[u8]) {
    let mut pmk = [0u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA1,
        std::num::NonZeroU32::new(4096).unwrap(),
        "test_ap".as_bytes(),
        "123456789".as_bytes(),
        &mut pmk);

    let mut ptk_hmac = HmacSha1::new_from_slice(&pmk).unwrap();
    ptk_hmac.update(message.as_bytes());
    let kck = &ptk_hmac.finalize().into_bytes()[..16];

    let mut calculated_mic_hmac = HmacSha1::new_from_slice(&kck).unwrap();
    calculated_mic_hmac.update(zeroed_frame);
    let _calculated_mic = &calculated_mic_hmac.finalize().into_bytes()[..16];
}

pub fn bench_generate_check_mic(c: &mut Criterion) {
    let message = TestMessage::new();
    let zeroed_frame = 
        b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

    let mut group = c.benchmark_group("MIC generation");

    group.warm_up_time(Duration::from_secs(10));
    group.measurement_time(Duration::from_secs(15));
    group.sample_size(1000);

    group.bench_function("Bench MIC", |b| b.iter(|| {
        generate_check_mic(black_box(&message), black_box(zeroed_frame));
    }));

    group.finish();
}
