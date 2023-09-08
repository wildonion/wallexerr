

use sha2::{Digest, Sha256};
use crypto;
use std::io::{BufWriter, Write, Read};
use ring::{signature as ring_signature, rand as ring_rand};
use ring::signature::Ed25519KeyPair;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use ring::{signature::KeyPair, pkcs8::Document};
use secp256k1::Secp256k1;
use secp256k1::ecdsa::Signature;
use secp256k1::{rand::SeedableRng, rand::rngs::StdRng, PublicKey, SecretKey, Message, hashes::sha256};
use tiny_keccak::keccak256;
use std::str::FromStr;
use std::{fs::OpenOptions, io::BufReader};
use web3::{ /* a crate to interact with evm based chains */
    transports,
    types::{Address, TransactionParameters, H256, U256},
    Web3,
};
use themis::keys as themis_keys;
use themis::secure_message::{SecureSign, SecureVerify};
use themis::keygen::gen_ec_key_pair;
use themis::keys::{EcdsaKeyPair, EcdsaPrivateKey, EcdsaPublicKey};
use themis::keys::KeyPair as ThemisKeyPair;
use secp256k1::hashes::Hash;
use rand::random;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use crypter::string_to_static_str;
mod misc;





fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>>{


    // command line parsing
    // ...

    Ok(())
}

