


use tiny_keccak::Hasher;
use web3::types::SignedData;
use std::io::{BufWriter, Write, Read};
use ring::{signature as ring_signature, rand as ring_rand};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use ring::signature::KeyPair;
use secp256k1::Secp256k1;
use secp256k1::ecdsa::Signature;
use sha2::{Sha256, Digest};
use secp256k1::{rand::SeedableRng, rand::rngs::StdRng, PublicKey, SecretKey, Message};
use std::str::FromStr;
use web3::{ /* a crate to interact with evm based chains */
    transports,
    types::Address,
    Web3,
    signing::keccak256
};
use themis::secure_message::{SecureSign, SecureVerify};
use themis::keygen::gen_ec_key_pair;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use themis::keys::KeyPair as ThemisKeyPair;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use base64::{engine::general_purpose, Engine as _};
use base58::{ToBase58, FromBase58};
use aes256ctr_poly1305aes::{Aes256CtrPoly1305Aes, Key, Nonce};
use aes256ctr_poly1305aes::aead::Aead;
use themis::keys::SymmetricKey;
use themis::secure_cell::SecureCell;

pub mod misc;
use crate::misc::*;


/** 
     ---------------------------------------------------------------------
    |   RSA (Asymmetric) Crypto Wallet Implementations using ECC Curves
    |---------------------------------------------------------------------
    |
    |       CURVES
    | ed25519   -> EdDSA                                                      ::::::: ring
    | secp256k1 -> ECDSA (can be imported in EVM based wallets like metamask) ::::::: secp256k1
    | secp256r1 -> ECDSA                                                      ::::::: themis
    |
    |  secp256k1 ENTROPY: BIP39 SEED PHRASES
    |
    |       256 BITS HASH METHDOS
    | sha2
    | sha3 keccak256 -> Default used in signing methods
    | aes256
    |

    https://github.com/skerkour/black-hat-rust/tree/main/ch_11
    https://cryptobook.nakov.com/digital-signatures
    https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/using/ecc_curve_cross-reference.htm

**/


/* >---------------------------------------------------------------------------
    EVM module containing all evm based web3 calls like signing and verifying 
    note that web3 is using secp256k1 curve algorithm in its core api thus the 
    generated public and private keys are the same one as for Secp256k1 crate
*/
pub mod evm{

    use super::*;

    pub async fn sign(wallet: Wallet, data: &str, infura_url: &str) -> (SignedData, String){

        let transport = transports::WebSocket::new(infura_url).await.unwrap();
        let web3_con = Web3::new(transport);
    
        /* generating private key instance from secp256k1 secret key */
        let web3_sec = web3::signing::SecretKey::from_str(wallet.secp256k1_secret_key.as_ref().unwrap().as_str()).unwrap();
        
        /* generating keccak256 sha3 hash of data */
        let keccak256_hash_of_message = web3_con.accounts().hash_message(data.to_string().as_bytes());
        println!("web3 keccak256 hash of message {:?}", keccak256_hash_of_message); 
    
        /* signing the keccak256 hash of data using created private key */
        let signed_data = web3_con.accounts().sign(
            keccak256_hash_of_message, 
            &web3_sec
        );
    
        /* getting signature of the signed data */
        //--- signature bytes schema: pub struct Bytes(pub Vec<u8>);
        let sig_bytes = signed_data.signature.0.as_slice();
        let sig_str = hex::encode(sig_bytes);
        println!("web3 hex signature :::: {}", sig_str);

        /* 
            signature is a 520 bits or 65 bytes string which has 
            130 hex chars inside of it and can be divided into 
            two 256 bits or 32 bytes packs of hex string namely as
            r and s.
        */
        let signature = web3::types::H520::from_str(sig_str.as_str()).unwrap(); /* 64 bytes signature */
        println!("web3 signature :::: {}", signature);
        
        let hex_keccak256_hash_of_message = hex::encode(keccak256_hash_of_message.0).to_string();
        (signed_data, hex_keccak256_hash_of_message)
    
    }

    pub async fn verify(
        sender: &str,
        sig: &str,
        data_hash: &str,
        infura_url: &str
    ) -> Result<bool, bool>{
    
        let transport = transports::WebSocket::new(infura_url).await.unwrap();
        let web3_con = Web3::new(transport);
    
        /* generating a recovery message from keccak256 sha3 hash of the message */
        let data_hash = match hex::decode(data_hash){
            Ok(hash) => hash,
            Err(e) => return Err(false),
        };
        let rec_msg = web3::types::RecoveryMessage::Data(data_hash.clone());

        /* signature is a 65 bytes or 520 bits hex string contains 64 bytes of r + s (32 byte each) and a byte in the last which is v */
        let rec = web3::types::Recovery::from_raw_signature(rec_msg, hex::decode(sig).unwrap()).unwrap();
        
        println!("web3 recovery object {:?}", rec);
        
        /* recovers the EVM based public address or screen_cid which was used to sign the given data */
        if web3_con.accounts().recover(rec.clone()).is_err(){
            return Err(false);
        }
        let recovered_screen_cidh160 = web3_con.accounts().recover(rec).unwrap().to_fixed_bytes();
        let recovered_screen_cid_hex = format!("0x{}", hex::encode(&recovered_screen_cidh160));
    
        /* means the message gets signed by the owner */
        if sender == recovered_screen_cid_hex{
            Ok(true)
        } else{
            Err(false)
        }
    
    }

}


impl Wallet{

    pub fn generate_keccak256_from(pubk: String) -> String{

        let pubk = PublicKey::from_str(&pubk).unwrap();
        let public_key = pubk.serialize_uncompressed();
        let pubhash = keccak256(&public_key[1..]);
        let addr: Address = Address::from_slice(&pubhash[12..]);
        let addr_bytes = addr.as_bytes();
        let addr_string = format!("0x{}", hex::encode(&addr_bytes));
        addr_string

    }

    pub fn new_ed25519() -> Self{

        /* generating an rng with high entropy */
        let rng = ring_rand::SystemRandom::new();

        /* generating ed25519 keypair */
        let pkcs8_bytes = ring_signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keys = ring_signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        /* ED25519 keypair */
        let pubkey = keys.public_key().as_ref();
        let prvkey = pkcs8_bytes.as_ref();

        /*              -------------- converting bytes to base64 string --------------
            URL-Safe: Base64 encoding usually makes use of + and / characters, which aren't safe for 
                      URLs since they have special meanings. The URL-safe variant replaces + with - and 
                      / with _ to avoid these issues.
            No Padding: Traditional Base64 encoding can end with one or two = characters as padding. 
                      With the NO_PAD option, this padding is omitted. It's a variant that's useful 
                      for situations where padding isn't necessary or where it's important to reduce 
                      the size of the Base64-encoded data.
        */
        let base64_pubkey_string = general_purpose::URL_SAFE_NO_PAD.encode(pubkey);
        let base64_prvkey_string = general_purpose::URL_SAFE_NO_PAD.encode(prvkey);


        /*             -------------- converting bytes to base58 string --------------
            by default ToBase58 and FromBase58 traits are implemented for 
            [u8] so by importing them in here we can call the to_base58()
            on &[u8] and from_base58() on String 
        */
        let base58_pubkey_string = pubkey.to_base58();
        let base58_prvkey_string = prvkey.to_base58();

        let wallet = Wallet{
            secp256k1_secret_key: None,
            secp256k1_public_key: None,
            secp256k1_public_address: None,
            secp256k1_mnemonic: None,
            secp256r1_public_key: None,
            secp256r1_secret_key: None,
            ed25519_public_key: Some(base58_pubkey_string),
            ed25519_secret_key: Some(base58_prvkey_string)
        };

        wallet

    }
    
    pub fn new_secp256k1(passphrase: &str, mnemonic: Option<&str>) -> Self{

        let seed_mnemonic_bytes_and_string = Self::generate_seed_phrases(passphrase);
        let seed_mnemonic_hash_bytes = if mnemonic.is_some(){
            Self::generate_keccak256_hash_from(mnemonic.unwrap())
        } else{
            seed_mnemonic_bytes_and_string.0
        };

        /* generate rng from hash of the seed phrase */
        let rng = &mut StdRng::from_seed(seed_mnemonic_hash_bytes); 
        
        /* since the secp is going to be built from an specific seed thus the generated keypair will be the same everytime we request a new one */
        let secp = secp256k1::Secp256k1::new();
        let (prvk, pubk) = secp.generate_keypair(rng);
        let prv_str = prvk.display_secret().to_string();
        
        let wallet = Wallet{
            secp256k1_secret_key: Some(prv_str), /* (compatible with all evm based chains) */
            secp256k1_public_key: Some(pubk.to_string()),
            secp256k1_public_address: Some(Self::generate_keccak256_from(pubk.to_string())),
            secp256k1_mnemonic: Some(seed_mnemonic_bytes_and_string.1),
            secp256r1_public_key: None,
            secp256r1_secret_key: None,
            ed25519_public_key: None,
            ed25519_secret_key: None
        };

        wallet

    }

    pub fn new_secp256r1() -> Self{

        /* ECDSA keypairs */
        let ec_key_pair = gen_ec_key_pair(); // generates a pair of Elliptic Curve (ECDSA) keys
        let (private, public) = ec_key_pair.clone().split();
        let hex_pub = Some(hex::encode(public.as_ref()));
        let hex_prv = Some(hex::encode(private.as_ref()));

        let wallet = Wallet { 
            secp256k1_secret_key: None, 
            secp256k1_public_key: None, 
            secp256k1_public_address: None, 
            secp256k1_mnemonic: None,
            secp256r1_secret_key: hex_prv, 
            secp256r1_public_key: hex_pub,
            ed25519_public_key: None,
            ed25519_secret_key: None,
        };

        wallet

    }

    pub fn self_ed25519_sign(&mut self, data: &str, prvkey: &str) -> Option<String>{

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_keccak256_hash_from(data);

        let ed25519 = Self::retrieve_ed25519_keypair(prvkey);
        
        /* signing the hashed data */
        let signature = ed25519.sign(&hash_data_bytes);
        let sig = signature.as_ref().to_vec();

        /* generating base58 string of the signature */
        let base58_sig_string = sig.to_base58();
        
        Some(base58_sig_string)

    }

    pub fn ed25519_sign(data: &str, prvkey: &str) -> Option<String>{

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_keccak256_hash_from(data);

        let ed25519 = Self::retrieve_ed25519_keypair(prvkey);
        
        /* signing the hashed data */
        let signature = ed25519.sign(&hash_data_bytes);
        let sig = signature.as_ref().to_vec();

        /* generating base58 string of the signature */
        let base58_sig_string = sig.to_base58();
        
        Some(base58_sig_string)

    }

    pub fn ed25519_aes256_sign(prvkey: &str, aes256config: &mut Aes256Config) -> Option<String>{

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_aes256_from(aes256config);
        aes256config.data = hash_data_bytes.clone();

        let ed25519 = Self::retrieve_ed25519_keypair(prvkey);
        
        /* signing the hashed data */
        let signature = ed25519.sign(&hash_data_bytes);
        let sig = signature.as_ref().to_vec();

        /* generating base58 string of the signature */
        let base58_sig_string = sig.to_base58();
        
        Some(base58_sig_string)

    }

    pub fn self_ed25519_aes256_sign(&mut self, prvkey: &str, aes256config: &mut Aes256Config) -> Option<String>{

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_aes256_from(aes256config);
        aes256config.data = hash_data_bytes.clone();

        let ed25519 = Self::retrieve_ed25519_keypair(prvkey);
        
        /* signing the hashed data */
        let signature = ed25519.sign(&hash_data_bytes);
        let sig = signature.as_ref().to_vec();

        /* generating base58 string of the signature */
        let base58_sig_string = sig.to_base58();
        
        Some(base58_sig_string)

    }

    pub fn ed25519_secure_cell_sign(prvkey: &str, secure_cell_config: &mut SecureCellConfig) -> Option<String>{

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::secure_cell_encrypt(secure_cell_config).unwrap();
        secure_cell_config.data = hash_data_bytes.clone();

        let ed25519 = Self::retrieve_ed25519_keypair(prvkey);
        
        /* signing the hashed data */
        let signature = ed25519.sign(&hash_data_bytes);
        let sig = signature.as_ref().to_vec();

        /* generating base58 string of the signature */
        let base58_sig_string = sig.to_base58();

        /*
            we must return the hash_data_bytes in here since generating
            a new one is different than the one in here which causes the 
            verifying will be failed.
        */
        Some(base58_sig_string)

    }

    pub fn self_ed25519_secure_cell_sign(&mut self, prvkey: &str, secure_cell_config: &mut SecureCellConfig) -> Option<String>{

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::secure_cell_encrypt(secure_cell_config).unwrap();
        secure_cell_config.data = hash_data_bytes.clone();

        let ed25519 = Self::retrieve_ed25519_keypair(prvkey);
        
        /* signing the hashed data */
        let signature = ed25519.sign(&hash_data_bytes);
        let sig = signature.as_ref().to_vec();

        /* generating base58 string of the signature */
        let base58_sig_string = sig.to_base58();
        
        Some(base58_sig_string)

    }

    /* 
        for security reasons we must verify the hash of data against the signature 
        the sha256 hash of data must be passed from client to this function, we 
        can't hash the raw data in this method, so data is alrady the sha256 
        hash of real data
    */
    pub fn verify_ed25519_signature(sig: &str, hash_data_bytes: &[u8], pubkey: &str) -> Result<(), ring::error::Unspecified>{

        /* decoding the base58 sig to get the actual bytes */
        let sig_bytes = sig.from_base58().unwrap();

        /* decoding the base58 public key to get the actual bytes */
        let pubkey_bytes = pubkey.from_base58().unwrap();

        /* creating the public key  */
        let ring_pubkey = ring_signature::UnparsedPublicKey::new(
            &ring_signature::ED25519, 
            &pubkey_bytes);

        /* 
            Vec<u8> can be coerced to &[u8] slice by taking a reference to it 
            since a pointer to the underlying Vec<u8> means taking a slice of 
            vector with a valid lifetime
        */
        let verify_res = ring_pubkey.verify(&hash_data_bytes, &sig_bytes);
        verify_res

    }

    pub fn self_verify_ed25519_signature(&mut self, sig: &str, hash_data_bytes: &[u8], pubkey: &str) -> Result<(), ring::error::Unspecified>{

        /* decoding the base58 sig to get the actual bytes */
        let sig_bytes = sig.from_base58().unwrap();

        /* decoding the base58 public key to get the actual bytes */
        let pubkey_bytes = pubkey.from_base58().unwrap();

        /* creating the public key  */
        let ring_pubkey = ring_signature::UnparsedPublicKey::new(
            &ring_signature::ED25519, 
            &pubkey_bytes);

        /* 
            Vec<u8> can be coerced to &[u8] slice by taking a reference to it 
            since a pointer to the underlying Vec<u8> means taking a slice of 
            vector with a valid lifetime
        */
        let verify_res = ring_pubkey.verify(&hash_data_bytes, &sig_bytes);
        verify_res

    }

    pub fn retrieve_ed25519_keypair(prv_key: &str) -> Ed25519KeyPair{

        /* decoding the base58 private key to get the actual bytes */
        let prvkey_bytes = prv_key.from_base58().unwrap();
        let generated_ed25519_keys = Ed25519KeyPair::from_pkcs8(&prvkey_bytes).unwrap();
        generated_ed25519_keys

    }

    pub fn self_retrieve_ed25519_keypair(&mut self, prv_key: &str) -> Ed25519KeyPair{

        /* decoding the base58 private key to get the actual bytes */
        let prvkey_bytes = prv_key.from_base58().unwrap();
        let generated_ed25519_keys = Ed25519KeyPair::from_pkcs8(&prvkey_bytes).unwrap();
        generated_ed25519_keys

    }

    pub fn generate_secp256k1_pubkey_from(pk: &str) -> Result<PublicKey, secp256k1::Error>{
        let secp256k1_pubkey = PublicKey::from_str(&pk);
        secp256k1_pubkey
    }

    /* 
        for security reasons we must verify the hash of data against the signature 
        the sha256 hash of data must be passed from client to this function, we 
        can't hash the raw data in this method, so data is alrady the sha256 
        hash of real data
    */
    pub fn verify_secp256k1_signature_from_pubkey_str(data: &[u8], sig: &str, pk: &str) -> Result<(), secp256k1::Error>{

        /* data is alrady the sha256 hash of real data */
        let hash_data_bytes = convert_into_u8_32(data).unwrap();
        let hashed_message = Message::from_digest(hash_data_bytes);

        let sig = Signature::from_str(sig).unwrap();
        let pubkey = PublicKey::from_str(pk).unwrap();
            
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&hashed_message, &sig, &pubkey)

    }

    pub fn self_verify_secp256k1_signature_from_pubkey_str(&mut self, data: &[u8], sig: &str, pk: &str) -> Result<(), secp256k1::Error>{

        /* data is alrady the sha256 hash of real data */
        let hash_data_bytes = convert_into_u8_32(data).unwrap();
        let hashed_message = Message::from_digest(hash_data_bytes);

        let sig = Signature::from_str(sig).unwrap();
        let pubkey = PublicKey::from_str(pk).unwrap();
            
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&hashed_message, &sig, &pubkey)

    }

    /* 
        for security reasons we must verify the hash of data against the signature 
        the sha256 hash of data must be passed from client to this function, we 
        can't hash the raw data in this method, so data is alrady the sha256 
        hash of real data
    */
    pub fn verify_secp256k1_signature_from_pubkey(data: &[u8], sig: &str, pk: PublicKey) -> Result<(), secp256k1::Error>{

        /* data is alrady the sha256 hash of real data */
        let hash_data_bytes = convert_into_u8_32(data).unwrap();
        let hashed_message = Message::from_digest(hash_data_bytes);
        let sig = Signature::from_str(sig).unwrap();
            
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&hashed_message, &sig, &pk)

    }

    pub fn self_verify_secp256k1_signature_from_pubkey(&mut self, data: &[u8], sig: &str, pk: PublicKey) -> Result<(), secp256k1::Error>{

        /* data is alrady the sha256 hash of real data */
        let hash_data_bytes = convert_into_u8_32(data).unwrap();
        let hashed_message = Message::from_digest(hash_data_bytes);
        let sig = Signature::from_str(sig).unwrap();
            
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&hashed_message, &sig, &pk)

    }

    pub fn retrieve_secp256k1_keypair(secret_key: &str) -> (PublicKey, SecretKey){

        /* 
            since secret_key is a hex string we have to get its bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let prv_bytes = hex::decode(secret_key).unwrap();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&prv_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        (public_key, secret_key)
    }

    pub fn self_retrieve_secp256k1_keypair(&mut self, secret_key: &str) -> (PublicKey, SecretKey){

        /* 
            since secret_key is a hex string we have to get its bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let prv_bytes = hex::decode(secret_key).unwrap();
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(&prv_bytes).unwrap();
        let public_key = PublicKey::from_secret_key(&secp, &secret_key);

        (public_key, secret_key)
    }

    pub fn secp256k1_sign(signer: &str, data: &str) -> Signature{

        let secret_key = SecretKey::from_str(signer).unwrap();
        let hashed_data = Self::generate_keccak256_hash_from(data);
        let hashed_message = Message::from_digest(hashed_data);
        
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::new();

        /* signing the hashed data */
        secp.sign_ecdsa(&hashed_message, &secret_key)

    }

    pub fn self_secp256k1_sign(&mut self, signer: &str, data: &str) -> Signature{

        let secret_key = SecretKey::from_str(signer).unwrap();
        let hashed_data = Self::generate_keccak256_hash_from(data);
        let hashed_message = Message::from_digest(hashed_data);
        
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::new();

        /* signing the hashed data */
        secp.sign_ecdsa(&hashed_message, &secret_key)

    }

    pub fn retrieve_secp256r1_keypair(pubkey: &str, prvkey: &str) -> themis::keys::KeyPair{

        /* 
            since pubkey and prvkey are hex string we have to get their bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let pubkey_bytes = hex::decode(pubkey).unwrap();
        let prvkey_bytes = hex::decode(prvkey).unwrap();

        /* building ECDSA keypair from pubkey and prvkey slices */
        let ec_pubkey = EcdsaPublicKey::try_from_slice(&pubkey_bytes).unwrap();
        let ec_prvkey = EcdsaPrivateKey::try_from_slice(&prvkey_bytes).unwrap();
        let generated_ec_keypair = ThemisKeyPair::try_join(ec_prvkey, ec_pubkey).unwrap();
        generated_ec_keypair

    }

    pub fn self_retrieve_secp256r1_keypair(&mut self, pubkey: &str, prvkey: &str) -> themis::keys::KeyPair{

        /* 
            since pubkey and prvkey are hex string we have to get their bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let pubkey_bytes = hex::decode(pubkey).unwrap();
        let prvkey_bytes = hex::decode(prvkey).unwrap();

        /* building ECDSA keypair from pubkey and prvkey slices */
        let ec_pubkey = EcdsaPublicKey::try_from_slice(&pubkey_bytes).unwrap();
        let ec_prvkey = EcdsaPrivateKey::try_from_slice(&prvkey_bytes).unwrap();
        let generated_ec_keypair = ThemisKeyPair::try_join(ec_prvkey, ec_pubkey).unwrap();
        generated_ec_keypair

    }

    pub fn secp256r1_sign(signer: &str, data: &str) -> Option<String>{

        /* 
            since signer is a hex string we have to get its bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let prvkey_bytes = hex::decode(signer).unwrap();
        let ec_prvkey = EcdsaPrivateKey::try_from_slice(&prvkey_bytes).unwrap();
        let ec_signer = SecureSign::new(ec_prvkey.clone());

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_keccak256_hash_from(data);
    
        /* generating signature from the hashed data */
        let ec_sig = ec_signer.sign(&hash_data_bytes).unwrap();
        
        /* converting the signature bytes into hex string */
        Some(hex::encode(&ec_sig))

    }

    pub fn self_secp256r1_sign(&mut self, signer: &str, data: &str) -> Option<String>{

        /* 
            since signer is a hex string we have to get its bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let prvkey_bytes = hex::decode(signer).unwrap();
        let ec_prvkey = EcdsaPrivateKey::try_from_slice(&prvkey_bytes).unwrap();
        let ec_signer = SecureSign::new(ec_prvkey.clone());

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_keccak256_hash_from(data);
    
        /* generating signature from the hashed data */
        let ec_sig = ec_signer.sign(&hash_data_bytes).unwrap();
        
        /* converting the signature bytes into hex string */
        Some(hex::encode(&ec_sig))

    }

    pub fn verify_secp256r1_signature(signature: &str, pubkey: &str) -> Result<Vec<u8>, themis::Error>{

        /* 
            since signature and pubkey are hex string we have to get their bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let signature_bytes = hex::decode(signature).unwrap();
        let pubkey_bytes = hex::decode(pubkey).unwrap();

        /* building the public key from public key bytes */
        let Ok(ec_pubkey) = EcdsaPublicKey::try_from_slice(&pubkey_bytes) else{
            let err = EcdsaPublicKey::try_from_slice(&pubkey_bytes).unwrap_err();
            return Err(err); /* can't build pubkey from the passed in slice */
        };

        /* building the verifier from the public key */
        let ec_verifier = SecureVerify::new(ec_pubkey.clone());

        /* verifying the signature byte which returns the hash of data in form of vector of utf8 bytes */
        let encoded_data = ec_verifier.verify(&signature_bytes);

        /* this is the encoded sha256 bits hash of data */
        encoded_data

    }

    pub fn self_verify_secp256r1_signature(&mut self, signature: &str, pubkey: &str) -> Result<Vec<u8>, themis::Error>{

        /* 
            since signature and pubkey are hex string we have to get their bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let signature_bytes = hex::decode(signature).unwrap();
        let pubkey_bytes = hex::decode(pubkey).unwrap();

        /* building the public key from public key bytes */
        let Ok(ec_pubkey) = EcdsaPublicKey::try_from_slice(&pubkey_bytes) else{
            let err = EcdsaPublicKey::try_from_slice(&pubkey_bytes).unwrap_err();
            return Err(err); /* can't build pubkey from the passed in slice */
        };

        /* building the verifier from the public key */
        let ec_verifier = SecureVerify::new(ec_pubkey.clone());

        /* verifying the signature byte which returns the hash of data in form of vector of utf8 bytes */
        let encoded_data = ec_verifier.verify(&signature_bytes);

        /* this is the encoded sha256 bits hash of data */
        encoded_data

    }

    pub fn generate_sha256_from(data: &str) -> [u8; 32]{

        /* generating sha25 bits hash of data */
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash_data = hasher.finalize();
        let hash_data_bytes = hash_data;
        hash_data_bytes.into()

    }

    pub fn self_generate_sha256_from(&mut self, data: &str) -> [u8; 32]{

        /* generating sha25 bits hash of data */
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash_data = hasher.finalize();
        let hash_data_bytes = hash_data;
        hash_data_bytes.into()

    }
    
    pub fn generate_aes256_from(aes256config: &mut Aes256Config) -> Vec<u8>{

        /* 
            in here data is the raw form of our data which is the plaintext
            that we want to encrypt it
        */
        let Aes256Config{ secret_key, nonce, data } = aes256config;
        
        /* encrypting data using aes256 bits secret key */
        let cipher = Aes256CtrPoly1305Aes::new(
            Key::from_slice(
                secret_key.as_bytes()
            )
        );
        let nonce = Nonce::from_slice(
            nonce.as_bytes()
        );

        let ciphertext = cipher.encrypt(nonce, data.as_slice()).unwrap();
        ciphertext
        
    }

    pub fn generate_data_from_aes256(aes256config: &mut Aes256Config) -> Vec<u8>{

        /* 
            in here data is the encrypted form of plaintext which is the cipher text 
            that we want to decrypt it
        */
        let Aes256Config{ secret_key, nonce, data } = aes256config;

        /* decrypting cipher text */
        let cipher = Aes256CtrPoly1305Aes::new(
            Key::from_slice(
                secret_key.as_bytes()
            )
        );
        let nonce = Nonce::from_slice(
            nonce.as_bytes()
        );

        let data = cipher.decrypt(nonce, data.as_slice()).unwrap();
        data
    }

    pub fn self_generate_aes256_from(&mut self, aes256config: &mut Aes256Config) -> Vec<u8>{

        /* 
            in here data is the raw form of our data which is the plaintext
            that we want to encrypt it
        */
        let Aes256Config{ secret_key, nonce, data } = aes256config;
        
        /* encrypting data using aes256 bits secret key */
        let cipher = Aes256CtrPoly1305Aes::new(
            Key::from_slice(
                secret_key.as_bytes()
            )
        );
        let nonce = Nonce::from_slice(
            nonce.as_bytes()
        );

        let ciphertext = cipher.encrypt(nonce, data.as_slice()).unwrap();
        ciphertext
        
    }

    pub fn self_generate_data_from_aes256(&mut self, aes256config: &mut Aes256Config) -> Vec<u8>{

        /* 
            in here data is the encrypted form of plaintext which is the cipher text 
            that we want to decrypt it
        */
        let Aes256Config{ secret_key, nonce, data } = aes256config;

        /* decrypting cipher text */
        let cipher = Aes256CtrPoly1305Aes::new(
            Key::from_slice(
                secret_key.as_bytes()
            )
        );
        let nonce = Nonce::from_slice(
            nonce.as_bytes()
        );

        let data = cipher.decrypt(nonce, data.as_slice()).unwrap();
        data
    }

    pub fn generate_keccak256_hash_from(data: &str) -> [u8; 32]{

        /* generating keccak256 sha3 hash of data */
        let mut sha3 = tiny_keccak::Sha3::v256();
        let mut output = [0u8; 32];
        sha3.update(data.as_bytes());
        sha3.finalize(&mut output); /* pass a mutable pointer to the output so the output can be mutated */
        output
    }

    pub fn self_generate_keccak256_hash_from(&mut self, data: &str) -> [u8; 32]{

        /* generating keccak256 sha3 hash of data */
        let mut sha3 = tiny_keccak::Sha3::v256();
        let mut output = [0u8; 32];
        sha3.update(data.as_bytes());
        sha3.finalize(&mut output); /* pass a mutable pointer to the output so the output can be mutated */
        output
    }

    fn generate_seed_phrases(passphrase: &str) -> ([u8; 32], String){

        /* 

            1 - create mnemonic words
            2 - create seed from mnemonic and password
            3 - sha256 bits hash of generated mnemonic based seed
            4 - generate rng based on output of step 3

            creating mnemonic words as the seed phrases for deriving secret keys, by doing this
            we're creating a 64 bytes or 512 bits entropy to construct the keypair, with a same 
            seed we'll get same keypair every time thus we can generate a secret words to generate 
            keypair for the wallet owner and by recovering the seed phrase wen can recover 
            the entire wallet.
        */
        let mnemoni_type = MnemonicType::for_word_count(12).unwrap();
        let mnemonic = Mnemonic::new(mnemoni_type, Language::English);
        
        /* generating seed from the password and generated menmonic */
        let bip_seed_phrases = Seed::new(&mnemonic, passphrase);
        
        /*          -------------- generating sha25 bits hash of data --------------
            generating a 32 bytes hash of the bip_seed_phrases using sha256 we're doing this
            because StdRng::from_seed() takes 32 bytes seed to generate the rng 
        */
        let mut hasher = Sha256::new();
        hasher.update(bip_seed_phrases.as_bytes());
        let hash_data = hasher.finalize();
        let hash_data_bytes: [u8; 32] = hash_data.into();

        /* we'll use the sha256 hash of the seed to generate the keypair */
        let seed_bytes = hash_data_bytes.to_owned();

        (seed_bytes, mnemonic.to_string())

    }

    pub fn save_to_json(wallet: &Wallet, _type: &str) -> Result<(), ()>{

        let walletdir = std::fs::create_dir_all("wallexerr-keys").unwrap();
        let errordir = std::fs::create_dir_all("logs").unwrap();
        let walletpath = format!("wallexerr-keys/{_type:}.json");  
        let errorpath = format!("logs/error.log");  
        let mut file = std::fs::File::create(walletpath).unwrap();
        let mut filelog = std::fs::File::create(errorpath).unwrap();
        
        let pretty_json = serde_json::to_string_pretty(wallet).unwrap();
        let write_res = file.write(pretty_json.as_bytes());
        if let Err(why) = write_res{
            filelog.write(why.to_string().as_bytes());
        } 

        Ok(())
    }

    pub fn self_save_to_json(&mut self, _type: &str) -> Result<(), ()>{

        let walletdir = std::fs::create_dir_all("wallexerr-keys").unwrap();
        let errordir = std::fs::create_dir_all("logs").unwrap();
        let walletpath = format!("wallexerr-keys/{_type:}.json");  
        let errorpath = format!("logs/error.log");  
        let mut file = std::fs::File::create(walletpath).unwrap();
        let mut filelog = std::fs::File::create(errorpath).unwrap();
        
        let pretty_json = serde_json::to_string_pretty(self).unwrap();
        let write_res = file.write(pretty_json.as_bytes());
        if let Err(why) = write_res{
            filelog.write(why.to_string().as_bytes());
        } 

        Ok(())
    }

    pub fn secure_cell_encrypt(secure_cell_config: &mut SecureCellConfig) -> Result<Vec<u8> , themis::Error>{

        let key = secure_cell_config.clone().secret_key;
        let data = secure_cell_config.clone().data;

        let key = SymmetricKey::try_from_slice(key.as_bytes()).unwrap();
        let cell = SecureCell::with_key(&key).unwrap().seal();

        let encrypted = cell.encrypt(&data);
        encrypted
    }

    pub fn secure_cell_decrypt(secure_cell_config: &mut SecureCellConfig) -> Result<Vec<u8> , themis::Error>{

        let key = secure_cell_config.clone().secret_key;
        let data = secure_cell_config.clone().data; /* this is the raw data */

        let key = SymmetricKey::try_from_slice(key.as_bytes()).unwrap();
        let cell = SecureCell::with_key(&key).unwrap().seal();

        let decrypted = cell.decrypt(&data);
        decrypted
    }

    pub fn self_secure_cell_encrypt(&mut self, secure_cell_config: &mut SecureCellConfig) -> Result<Vec<u8> , themis::Error>{

        let key = secure_cell_config.clone().secret_key;
        let data = secure_cell_config.clone().data; /* this is the encrypted data */

        let key = SymmetricKey::try_from_slice(key.as_bytes()).unwrap();
        let cell = SecureCell::with_key(&key).unwrap().seal();

        let encrypted = cell.encrypt(&data);
        encrypted
    }

    pub fn self_secure_cell_decrypt(&mut self, secure_cell_config: &mut SecureCellConfig) -> Result<Vec<u8> , themis::Error>{

        let key = secure_cell_config.clone().secret_key;
        let data = secure_cell_config.clone().data;

        let key = SymmetricKey::try_from_slice(key.as_bytes()).unwrap();
        let cell = SecureCell::with_key(&key).unwrap().seal();

        let decrypted = cell.decrypt(&data);
        decrypted
    }
    
}

impl Contract{

    pub fn new_with_ed25519(owner: &str) -> Self{
        
        let static_owner = string_to_static_str(owner.to_string());
        let wallet = Wallet::new_ed25519();

        Self { 
            wallet,
            iat: chrono::Local::now().timestamp_nanos(), 
            owner: static_owner,
            data: None
        }
        
    }

    pub fn new_with_secp256r1(owner: &str) -> Self{
        
        let static_owner = string_to_static_str(owner.to_string());
        let wallet = Wallet::new_secp256r1();

        Self { 
            wallet,
            iat: chrono::Local::now().timestamp_nanos(), 
            owner: static_owner,
            data: None
        }
        
    }

    pub fn new_with_secp256k1(owner: &str, passphrase: &str, mnemonic: Option<&str>) -> Self{
        
        let static_owner = string_to_static_str(owner.to_string());
        let wallet = Wallet::new_secp256k1(passphrase, mnemonic);

        Self { 
            wallet,
            iat: chrono::Local::now().timestamp_nanos(), 
            owner: static_owner,
            data: None
        }
        
    }

}



/* ----------------------------- */
//              TESTS   
/* ----------------------------- */

#[cfg(test)]
pub mod tests{

    use super::*;

    #[test]
    pub fn ed25519_test() -> Result<(), ring::error::Unspecified>{
        
        let mut data = DataBucket{
            value: "json stringify data".to_string(), /* json stringify */ 
            signature: "".to_string(),
            signed_at: 0,
        };
        let stringify_data = serde_json::to_string_pretty(&data).unwrap();

        /* wallet operations */

        let contract = Contract::new_with_ed25519("0xDE6D7045Df57346Ec6A70DfE1518Ae7Fe61113f4");
        Wallet::save_to_json(&contract.wallet, "ed25519").unwrap();
        
        let signature_base58 = Wallet::ed25519_sign(stringify_data.clone().as_str(), contract.wallet.ed25519_secret_key.as_ref().unwrap().as_str());

        let hash_of_data = Wallet::generate_keccak256_hash_from(&stringify_data);
        let verify_res = Wallet::verify_ed25519_signature(signature_base58.clone().unwrap().as_str(), hash_of_data.as_slice(), contract.wallet.ed25519_public_key.unwrap().as_str());

        let keypair = Wallet::retrieve_ed25519_keypair(
            /* 
                unwrap() takes the ownership of the type hence we must borrow 
                the type before calling it using as_ref() 
            */
            contract.wallet.ed25519_secret_key.unwrap().as_str()
        );

        match verify_res{
            Ok(is_verified) => {
                
                /* fill the signature and signed_at fields if the signature was valid */
                data.signature = signature_base58.unwrap();
                data.signed_at = chrono::Local::now().timestamp_nanos();
                Ok(())

            },
            Err(e) => Err(e)
        }

    }

    #[test]
    pub fn ed25519_aes256_test() -> Result<(), ring::error::Unspecified>{
        
        let mut data = DataBucket{
            value: "json stringify data".to_string(), /* json stringify */ 
            signature: "".to_string(),
            signed_at: 0,
        };
        let stringify_data = serde_json::to_string_pretty(&data).unwrap();

        let mut aes256config = &mut Aes256Config{
            secret_key: String::from("This is an example of a very secret key. Keep it always secret!!"),
            nonce: String::from("my unique nonce!"),
            data: stringify_data.as_bytes().to_vec(),
        };

        /* wallet operations */

        let contract = Contract::new_with_ed25519("0xDE6D7045Df57346Ec6A70DfE1518Ae7Fe61113f4");
        Wallet::save_to_json(&contract.wallet, "ed25519").unwrap();
        
        let signature_base58 = Wallet::ed25519_aes256_sign(contract.wallet.ed25519_secret_key.as_ref().unwrap().as_str(), aes256config);

        /* aes256config.data now contains the aes256 hash of the raw data */
        let hash_of_data = aes256config.clone().data;
        println!("aes256 encrypted data :::: {:?}", hex::encode(&hash_of_data));
        println!("signature :::: {:?}", signature_base58.clone());

        let verify_res = Wallet::verify_ed25519_signature(signature_base58.clone().unwrap().as_str(), hash_of_data.as_slice(), contract.wallet.ed25519_public_key.unwrap().as_str());

        let keypair = Wallet::retrieve_ed25519_keypair(
            /* 
                unwrap() takes the ownership of the type hence we must borrow 
                the type before calling it using as_ref() 
            */
            contract.wallet.ed25519_secret_key.unwrap().as_str()
        );

        match verify_res{
            Ok(is_verified) => {

                aes256config.data = hash_of_data.clone(); /* update data field with encrypted form of raw data */
                let dec = Wallet::generate_data_from_aes256(aes256config);
                println!("aes256 decrypted data :::: {:?}", std::str::from_utf8(&dec));

                let deserialized_data = serde_json::from_str::<DataBucket>(std::str::from_utf8(&dec).unwrap()).unwrap();
                
                if deserialized_data == data{

                    println!("✅ got same data");
                    /* fill the signature and signed_at fields if the signature was valid */
                    data.signature = signature_base58.unwrap();
                    data.signed_at = chrono::Local::now().timestamp_nanos();
                    return Ok(());

                } else{

                    eprintln!("🔴 invalid data");
                    Ok(())
                }

            },
            Err(e) => Err(e)
        }

    }

    #[test]
    pub fn ed25519_secure_cell_test() -> Result<(), ring::error::Unspecified>{
        
        let mut data = DataBucket{
            value: "json stringify data".to_string(), /* json stringify */ 
            signature: "".to_string(),
            signed_at: 0,
        };
        let stringify_data = serde_json::to_string_pretty(&data).unwrap();

        let mut secure_cell_config = &mut SecureCellConfig{
            secret_key: hex::encode(Wallet::generate_keccak256_hash_from(&String::from("very secret key"))),
            passphrase: String::from(""),
            data: stringify_data.as_bytes().to_vec(),
        };

        /* wallet operations */

        let contract = Contract::new_with_ed25519("0xDE6D7045Df57346Ec6A70DfE1518Ae7Fe61113f4");
        Wallet::save_to_json(&contract.wallet, "ed25519").unwrap();
        
        let signature_base58 = Wallet::ed25519_secure_cell_sign(contract.wallet.ed25519_secret_key.as_ref().unwrap().as_str(), secure_cell_config).unwrap();
        
        /* secure_cell_config.data now contains the aes256 hash of the raw data */
        let hash_of_data = secure_cell_config.clone().data;
        println!("secure cell aes256 encrypted data :::: {:?}", hex::encode(&hash_of_data));
        println!("signature :::: {:?}", signature_base58.clone());

        /* 
            note that don't generate a new hash data since it'll generate a new one which is 
            completely different from the one generated in signing process, use the one 
            inside the data field of the secure_cell_config instance
        */
        let verify_res = Wallet::verify_ed25519_signature(signature_base58.clone().as_str(), hash_of_data.as_slice(), contract.wallet.ed25519_public_key.unwrap().as_str());

        let keypair = Wallet::retrieve_ed25519_keypair(
            /* 
                unwrap() takes the ownership of the type hence we must borrow 
                the type before calling it using as_ref() 
            */
            contract.wallet.ed25519_secret_key.unwrap().as_str()
        );

        match verify_res{
            Ok(is_verified) => {

                secure_cell_config.data = hash_of_data.clone(); /* update data field with encrypted form of raw data */
                let dec = Wallet::secure_cell_decrypt(secure_cell_config).unwrap();
                println!("secure cell aes256 decrypted data :::: {:?}", std::str::from_utf8(&dec));

                let deserialized_data = serde_json::from_str::<DataBucket>(std::str::from_utf8(&dec).unwrap()).unwrap();
                
                if deserialized_data == data{

                    println!("✅ got same data");
                    /* fill the signature and signed_at fields if the signature was valid */
                    data.signature = signature_base58;
                    data.signed_at = chrono::Local::now().timestamp_nanos();
                    return Ok(());

                } else{

                    eprintln!("🔴 invalid data");
                    Ok(())
                }

            },
            Err(e) => Err(e)
        }

    }

    #[test]
    pub fn secp256r1_test() -> Result<(), themis::Error>{

        let mut data = DataBucket{
            value: "json stringify data".to_string(), 
            signature: "".to_string(),
            signed_at: 0,
        };
        let stringify_data = serde_json::to_string_pretty(&data).unwrap();

        /* wallet operations */
        
        let contract = Contract::new_with_secp256r1("0xDE6D7045Df57346Ec6A70DfE1518Ae7Fe61113f4");
        Wallet::save_to_json(&contract.wallet, "secp256r1").unwrap();

        let hashed_data = Wallet::generate_keccak256_hash_from(stringify_data.clone().as_str());

        let signature_hex = Wallet::secp256r1_sign(contract.wallet.secp256r1_secret_key.as_ref().unwrap().to_string().as_str(), stringify_data.clone().as_str());

        let verification_result = Wallet::verify_secp256r1_signature(&signature_hex.clone().unwrap(), contract.wallet.secp256r1_public_key.as_ref().unwrap().as_str());

        let keypair = Wallet::retrieve_secp256r1_keypair(
            /* 
                unwrap() takes the ownership of the type hence we must borrow 
                the type before calling it using as_ref() 
            */
            contract.wallet.secp256r1_public_key.as_ref().unwrap(),
            contract.wallet.secp256r1_secret_key.as_ref().unwrap() 
        );

        
        match verification_result{
            Ok(hashed_data_vector) => {
                
                if hashed_data_vector == hashed_data{
                    
                    /* fill the signature and signed_at fields if the signature was valid */
                    data.signature = signature_hex.unwrap();
                    data.signed_at = chrono::Local::now().timestamp_nanos();
                    println!("[+] valid hash data");

                } else{
                    println!("[?] invalid hash data");
                }

                Ok(())

            },
            Err(e) => Err(e)
        }

    }

    #[test]
    pub fn secp256k1_test() -> Result<(), secp256k1::Error>{

        let mut data = DataBucket{
            value: "json stringify data".to_string(), 
            signature: "".to_string(),
            signed_at: 0,
        };
        let stringify_data = serde_json::to_string_pretty(&data).unwrap();

        /* wallet operations */
        // let existing_mnemonic_sample = Some("obot glare amazing hip saddle habit soft barrel sell fine document february");
        // let contract = Contract::new_with_secp256k1("0xDE6D7045Df57346Ec6A70DfE1518Ae7Fe61113f4", "wildonion123", existing_mnemonic_sample, None);
        let contract = Contract::new_with_secp256k1("0xDE6D7045Df57346Ec6A70DfE1518Ae7Fe61113f4", "wildonion123", None);
        Wallet::save_to_json(&contract.wallet, "secp256k1").unwrap();

        let signature = Wallet::secp256k1_sign(contract.wallet.secp256k1_secret_key.as_ref().unwrap().to_string().as_str(), stringify_data.clone().as_str());

        let pubkey = Wallet::generate_secp256k1_pubkey_from(contract.wallet.secp256k1_public_key.as_ref().unwrap().to_string().as_str());

        let keypair = Wallet::retrieve_secp256k1_keypair(
            /* 
                unwrap() takes the ownership of the type hence we must borrow 
                the type before calling it using as_ref() 
            */
            contract.wallet.secp256k1_secret_key.as_ref().unwrap().as_str()
        );

        
        match pubkey{
            Ok(pk) => {
                
                let hash_of_data = Wallet::generate_keccak256_hash_from(&stringify_data);
                let verification_result = Wallet::verify_secp256k1_signature_from_pubkey(hash_of_data.as_slice(), signature.to_string().as_str(), pk);
                match verification_result{
                    Ok(_) => {
                        
                        /* fill the signature and signed_at fields if the signature was valid */
                        data.signature = signature.to_string();
                        data.signed_at = chrono::Local::now().timestamp_nanos();
                        
                        Ok(())
                    },
                    Err(e) => Err(e) 
                }

            },
            Err(e) => Err(e)
        }


    }

    #[tokio::test]
    pub async fn test_evm(){

        let wallet = Wallet::new_secp256k1("", None); // generate a new wallet with no passphrase and mnemonic

        let data_to_be_signed = serde_json::json!({
            "recipient": "deadkings",
            "from_cid": wallet.secp256k1_public_address.as_ref().unwrap(),
            "amount": 5
        });

        let sign_res = self::evm::sign(
            wallet.clone(), 
            data_to_be_signed.to_string().as_str(),
            "" /******* TODO - Fill Me! *******/
        ).await;

        let signed_data = sign_res.0;

        println!("sig :::: {}", hex::encode(&signed_data.signature.0));
        println!("v :::: {}", signed_data.v);
        println!("r :::: {}", hex::encode(&signed_data.r.0));
        println!("s :::: {}", hex::encode(&signed_data.s.0));
        println!("hash data :::: {}", sign_res.1);

        let verification_res = self::evm::verify(
            wallet.secp256k1_public_address.as_ref().unwrap(),
            hex::encode(&signed_data.signature.0).as_str(),
            sign_res.1.as_str(),
            "" /******* TODO - Fill Me! *******/
        ).await;
        
        if verification_res.is_ok(){
            println!("✅ valid signature");
        } else{
            eprintln!("🔴 invalid signature");
        }

    }
 

}

