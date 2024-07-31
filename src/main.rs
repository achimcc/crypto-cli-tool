use aes_siv::{
    aead::rand_core::RngCore,
    aead::{Aead, KeyInit, OsRng},
    Aes256SivAead, Key, Nonce,
};
use clap::{Parser, ValueEnum};
use std::{fs, path::PathBuf};

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

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    // Mode: encrypt or decrypt the input file ?
    #[arg(short, long)]
    mode: Mode,

    /// The input file
    #[arg(short, long)]
    input: PathBuf,

    // The output file
    #[arg(short, long)]
    output: PathBuf,

    /// The password
    #[arg(short, long)]
    password: String,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Mode {
    Encrypt,
    Decrypt,
}

fn main() {
    let cli = Cli::parse();
    let pass_vec = pad_password(cli.password);
    let key: &Key<Aes256SivAead> = pass_vec.as_slice().into();
    let cipher = Aes256SivAead::new(&key);
    let input = fs::read(cli.input).expect("Failed to read from input file");
    match cli.mode {
        Mode::Encrypt => {
            let nonce = &generate_nonce();
            let mut output: Vec<u8> = Vec::new();
            // We write the generated nonce into the first 16 bytes of the output file
            let _ = std::io::copy(&mut nonce.as_slice(), &mut output);
            let ciphertext = cipher
                .encrypt(nonce, &input[..])
                .expect("Encryption failed");
            let _ = std::io::copy(&mut &ciphertext[..], &mut output);
            fs::write(cli.output, output).expect("Failed to write output file");
        }
        Mode::Decrypt => {
            // First 16 bytes are the used nonce
            let (nonce, input) = input.split_at(16);
            let nonce = &Nonce::from_slice(&nonce).to_owned();
            let output = cipher
                .decrypt(nonce, &input[..])
                .expect("Decryption failed");
            fs::write(cli.output, output).expect("Failed to write output file");
        }
    }
}
