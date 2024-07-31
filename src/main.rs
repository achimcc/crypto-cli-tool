use aes_siv::{
    aead::{Aead, KeyInit, OsRng},
    aead::rand_core::RngCore,
    Aes256SivAead,
    Nonce, // Or `Aes128SivAead`
    Key, 
};
use std::io::{self, BufRead};
use std::fs;

fn pad_password(password: String) -> Vec<u8> {
    let mut pass_vec = password.as_bytes().to_vec();
    pass_vec.resize(64, 0);
    pass_vec
}

fn generate_nonce() -> Nonce {
    let mut nonce: [u8; 16] = [0; 16];
    OsRng.fill_bytes(&mut nonce);
    Nonce::from_slice(&nonce).to_owned()
}

fn main() {
    let nonce = &generate_nonce(); // 128-bits; unique per message
    println!("enter password :");
    let stdin = io::stdin();
    let password = stdin.lock().lines().next().unwrap().unwrap();
    println!("input is:  {}", password);

    let pass_vec = pad_password(password);
    let key: &Key<Aes256SivAead> = pass_vec.as_slice().into();
    let cipher = Aes256SivAead::new(&key);

    let text = fs::read("plaintext.txt").unwrap();
    
    let ciphertext = cipher
        .encrypt(nonce, &text[..])
        .unwrap();
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
    println!("plaintext message: {}", String::from_utf8(plaintext).unwrap());
}
