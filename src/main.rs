use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncryptMut, KeyInit,
};
use clap::Parser;
use sha1::{Digest, Sha1};

use std::collections::VecDeque;
use std::fs::{create_dir, File};
use std::io::prelude::*;
use std::path::PathBuf;

type Aes128EcbEnc = ecb::Encryptor<aes::Aes128>;

const CRYPT_KEY: &str = "Yohane the Parhelion - NUMAZU in the MIRAGE";
const DEMO_KEY: &str = "Yohane the Parhelion - NUMAZU in the MIRAGE - Demo";

#[derive(Parser)]
#[command(version, about, long_about = None, after_help = "`¶cﾘ˘ヮ˚)|")]
struct Cli {
    #[arg(short, long)]
    quiet: bool,
    #[arg(short, long, group = "group_key", help = "Use demo key")]
    demo: bool,
    #[arg(short, long, group = "group_key", help = "Use custom key")]
    key: Option<String>,
    path: PathBuf,
}

fn main() {
    let args = Cli::parse();
    let key = if let Some(k) = &args.key {
        k
    } else {
        if args.demo {
            DEMO_KEY
        } else {
            CRYPT_KEY
        }
    };

    if args.path.is_file() {
        let new_extension = match args.path.extension() {
            Some(os_str) => match os_str.to_str() {
                Some("bundle") => "processed.bundle",
                _ => panic!("invalid file extension!"),
            },
            None => panic!("invalid file extension!"),
        };
        let new_file_path = args.path.with_extension(new_extension);
        let file_name = &args.path.file_stem().unwrap().to_str().unwrap();
        let salt = &file_name[..32];
        if !args.quiet {
            println!("Processing {}", &file_name)
        }
        cipher_file(&key, &salt, &args.path, &new_file_path);
    } else if args.path.is_dir() {
        let file_path_template = &args.path.with_extension("processed");
        create_dir(&file_path_template).expect("failed to create directory!");
        for entry in args.path.read_dir().expect("failed to read directory!") {
            if let Ok(entry) = entry {
                let path = entry.path();
                if path.is_file() && path.extension().unwrap().eq("bundle") {
                    let file_name = &path.file_name().unwrap().to_str().unwrap();
                    let new_file_path = file_path_template.join(&file_name);
                    let salt = &file_name[..32];
                    if !args.quiet {
                        println!("Processing {}", &file_name)
                    }
                    cipher_file(&key, &salt, &path, &new_file_path);
                }
            }
        }
    }
}

fn cipher_file(key: &str, salt: &str, filepath: &PathBuf, newfilepath: &PathBuf) {
    let mut aes_arr: [GenericArray<u8, U16>; 16] = [Default::default(); 16];
    let mut keystream: VecDeque<u8> = VecDeque::new();

    let mut buffer = [0u8; 0x1000];
    let mut read_file = File::open(filepath).unwrap();
    let mut write_file = File::create(newfilepath).unwrap();

    // PBKDF1 processing
    let mut sha1 = Sha1::new();
    sha1.update(key.as_bytes());
    sha1.update(salt);
    let mut digested = sha1.finalize();
    for _ in 0..99 {
        let mut sha1 = Sha1::new();
        sha1.update(digested);
        digested = sha1.finalize();
    }

    let mut cnt = 1u64;
    let mut enc = Aes128EcbEnc::new((&digested[..16]).into());
    // Keystream processing
    loop {
        // read data
        let read_size = read_file.read(&mut buffer).unwrap();
        if read_size == 0 {
            break;
        }
        // check keystream buffer
        while keystream.len() < read_size {
            // refill keystream buffer
            aes_arr.fill(Default::default());
            for arr in aes_arr.iter_mut() {
                arr[0..8].copy_from_slice(&cnt.to_le_bytes());
                cnt += 1;
            }
            enc.encrypt_blocks_mut(&mut aes_arr);
            keystream.extend(aes_arr.iter().flatten().collect::<Vec<_>>());
        }
        write_file
            .write(
                &buffer
                    .iter()
                    .zip(keystream.drain(..read_size))
                    .map(|(&a, b)| a ^ b)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
    }
}
