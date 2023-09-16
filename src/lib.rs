


use sha2::{Digest, Sha256};
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
use bip39::{Language, Mnemonic, MnemonicType, Seed};



/* 
    converting the String into an static str by leaking the memory of the 
    String to create a longer lifetime allocation for an slice of the String 
*/
fn string_to_static_str(s: String) -> &'static str { 
    Box::leak(s.into_boxed_str()) 
}





/* 
     ---------------------------------------------------------------------
    |  RSA (Asymmetric) Crypto Wallet Implementations using ECC Algorithms
    |---------------------------------------------------------------------
    |
    |       CURVES
    | ed25519   -> EdDSA                                                    ::::::: ring
    | secp256k1 -> EC (can be imported in EVM based wallets like metamask)  ::::::: web3
    | secp256r1 -> ECDSA                                                    ::::::: themis
    |
    |       ENTROPY
    | BIP39 SEED PHRASES
    |

    https://github.com/skerkour/black-hat-rust/tree/main/ch_11
    https://cryptobook.nakov.com/digital-signatures
*/



#[derive(Serialize, Deserialize)]
pub struct DataBucket{
    pub value: String, /* json stringify */
    pub signed_at: i64,
    pub signature: String
}

// https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/using/ecc_curve_cross-reference.htm
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Wallet {
    pub secp256k1_secret_key: Option<String>,
    pub secp256k1_public_key: Option<String>,
    pub secp256k1_public_address: Option<String>,
    pub secp256k1_mnemonic: Option<String>,
    pub secp256r1_secret_key: Option<String>,
    pub secp256r1_public_key: Option<String>,
    pub ed25519_secret_key: Option<String>,
    pub ed25519_public_key: Option<String>
}

impl Wallet{

    pub fn generate_keccak256_from(pubk: String) -> String{

        let pubk = PublicKey::from_str(&pubk).unwrap();
        let public_key = pubk.serialize_uncompressed();
        let hash = keccak256(&public_key[1..]);
        let addr: Address = Address::from_slice(&hash[12..]);
        let addr_bytes = addr.as_bytes();
        let addr_string = format!("0x{}", hex::encode(&addr_bytes));
        addr_string

    }

    pub fn new_ed25519() -> Self{

        let rng = ring_rand::SystemRandom::new();
        let pkcs8_bytes = ring_signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keys = ring_signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap();

        /* ED25519 keypair */
        let pubkey = keys.public_key().as_ref();
        let prvkey = pkcs8_bytes.as_ref();

        /* converting bytes to hex string */
        let pubkey_string = hex::encode(&pubkey);
        let prvkey_string  = hex::encode(&prvkey);

        let wallet = Wallet{
            secp256k1_secret_key: None,
            secp256k1_public_key: None,
            secp256k1_public_address: None,
            secp256k1_mnemonic: None,
            secp256r1_public_key: None,
            secp256r1_secret_key: None,
            ed25519_public_key: Some(pubkey_string),
            ed25519_secret_key: Some(prvkey_string)
        };

        wallet

    }
    
    pub fn new_secp256k1(passphrase: &str) -> Self{

        let seed_mnemonic = Self::generate_seed_phrases(passphrase);
        let rng = &mut StdRng::from_seed(seed_mnemonic.0);
        
        /* since the secp is going to be built from an specific seed thus the generated keypair will be the same everytime we request a new one */
        let secp = secp256k1::Secp256k1::new();
        let (prvk, pubk) = secp.generate_keypair(rng);
        let prv_str = prvk.display_secret().to_string();
        
        let wallet = Wallet{
            secp256k1_secret_key: Some(prv_str), /* (compatible with all evm based chains) */
            secp256k1_public_key: Some(pubk.to_string()),
            secp256k1_public_address: Some(Self::generate_keccak256_from(pubk.to_string())),
            secp256k1_mnemonic: Some(seed_mnemonic.1),
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

    pub fn ed25519_sign(data: String, prvkey: &str) -> Option<String>{

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_sha256_from(data);

        let ed25519 = Self::retrieve_ed25519_keypair(prvkey);

        /* signing the hashed data */
        let signature = ed25519.sign(&hash_data_bytes);
        let sig = signature.as_ref().to_vec();
        Some(hex::encode(&sig))

    }

    pub fn verify_ed25519_signature(sig: String, data: String, pubkey: String) -> Result<(), ring::error::Unspecified>{

        /* 
            since sig and pubkey are hex string we have to get their bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let sig_bytes = hex::decode(&sig).unwrap();
        let pubkey_bytes = hex::decode(pubkey).unwrap();

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_sha256_from(data);

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

        /* 
            since prv_key is a hex string we have to get its bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let private_key = hex::decode(prv_key).unwrap();
        let generated_ed25519_keys = Ed25519KeyPair::from_pkcs8(private_key.as_ref()).unwrap();
        generated_ed25519_keys

    }

    pub fn generate_secp256k1_pubkey_from(pk: String) -> Result<PublicKey, secp256k1::Error>{
        let secp256k1_pubkey = PublicKey::from_str(&pk);
        secp256k1_pubkey
    }

    pub fn verify_secp256k1_signature(data: String, sig: Signature, pk: PublicKey) -> Result<(), secp256k1::Error>{

        /* 
            data is required to be passed to the method since we'll compare
            the hash of it with the one inside the signature 
        */
        let data_bytes = data.as_bytes();
        let hashed_data = Message::from_hashed_data::<sha256::Hash>(data_bytes);
            
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&hashed_data, &sig, &pk)

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

    pub fn secp256k1_sign(signer: String, data: String) -> Signature{

        let secret_key = SecretKey::from_str(&signer).unwrap();
        let data_bytes = data.as_bytes();
        let hashed_data = Message::from_hashed_data::<sha256::Hash>(data_bytes);
        
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::new();

        /* signing the hashed data */
        secp.sign_ecdsa(&hashed_data, &secret_key)

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

    pub fn secp256r1_sign(signer: String, data: String) -> Option<String>{

        /* 
            since signer is a hex string we have to get its bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let prvkey_bytes = hex::decode(signer).unwrap();
        let ec_prvkey = EcdsaPrivateKey::try_from_slice(&prvkey_bytes).unwrap();
        let ec_signer = SecureSign::new(ec_prvkey.clone());

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_sha256_from(data);
    
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

    pub fn generate_sha256_from(data: String) -> [u8; 32]{

        /* generating sha25 bits hash of data */
        let data_bytes = data.as_bytes();
        let hash_data = sha256::Hash::hash(data_bytes);
        let hash_data_bytes = hash_data.as_byte_array();
        hash_data_bytes.to_owned()

    }

    fn generate_seed_phrases(passphrase: &str) -> ([u8; 32], String){

        /* 
            creating mnemonic words as the seed phrases for deriving secret keys, by doing this
            we're creating a 64 bytes or 256 bits entropy from the seed phrases to construct the 
            keypair, with a same seed we'll get same keypair every time thus we can generate a 
            secret words to generate keypair for the wallet owner and by recovering the seed phrase 
            wen can recover the entire wallet.
        */
        let mnemoni_type = MnemonicType::for_word_count(12).unwrap();
        let mnemonic = Mnemonic::new(mnemoni_type, Language::English);
        let bip_seed_phrases = Seed::new(&mnemonic, passphrase);
        
        /* 
            generating a 32 bytes hash of the bip_seed_phrases using sha256 we're doing this
            because StdRng::from_seed() takes 32 bytes seed to generate the rng 
        */
        let hash_data = sha256::Hash::hash(bip_seed_phrases.as_bytes());
        let hash_data_bytes = hash_data.as_byte_array();
        let seed_bytes = hash_data_bytes.to_owned();

        (seed_bytes, mnemonic.to_string())

    }

    pub fn save_to_json(wallet: &Wallet, _type: &str) -> Result<(), ()>{

        let walletdir = std::fs::create_dir_all("wallet").unwrap();
        let walletpath = format!("wallet/{_type:}.json");  
        let mut file = std::fs::File::create(walletpath).unwrap();
        
        let pretty_json = serde_json::to_string_pretty(wallet).unwrap();
        file.write(pretty_json.as_bytes());

        Ok(())
    }
    
}

pub struct Contract{
    pub wallet: Wallet,
    pub iat: i64,
    pub owner: &'static str,
    pub data: Option<DataBucket>,
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

    pub fn new_with_secp256k1(owner: &str, passphrase: &str) -> Self{
        
        let static_owner = string_to_static_str(owner.to_string());
        let wallet = Wallet::new_secp256k1(passphrase);

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
        
        let signature_hex = Wallet::ed25519_sign(stringify_data.clone(), contract.wallet.ed25519_secret_key.as_ref().unwrap());
        
        let verify_res = Wallet::verify_ed25519_signature(signature_hex.clone().unwrap(), stringify_data, contract.wallet.ed25519_public_key.unwrap());

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
                data.signature = signature_hex.unwrap();
                data.signed_at = chrono::Local::now().timestamp_nanos();
                Ok(())

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

        let hashed_data = Wallet::generate_sha256_from(stringify_data.clone());

        let signature_hex = Wallet::secp256r1_sign(contract.wallet.secp256r1_secret_key.as_ref().unwrap().to_string(), stringify_data.clone());

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

        let contract = Contract::new_with_secp256k1("0xDE6D7045Df57346Ec6A70DfE1518Ae7Fe61113f4", "wildonion123");
        Wallet::save_to_json(&contract.wallet, "secp256k1").unwrap();

        let signature = Wallet::secp256k1_sign(contract.wallet.secp256k1_secret_key.as_ref().unwrap().to_string(), stringify_data.clone());

        let pubkey = Wallet::generate_secp256k1_pubkey_from(contract.wallet.secp256k1_public_key.as_ref().unwrap().to_string());

        let keypair = Wallet::retrieve_secp256k1_keypair(
            /* 
                unwrap() takes the ownership of the type hence we must borrow 
                the type before calling it using as_ref() 
            */
            contract.wallet.secp256k1_secret_key.as_ref().unwrap().as_str()
        );

        
        match pubkey{
            Ok(pk) => {
                
                let verification_result = Wallet::verify_secp256k1_signature(stringify_data, signature, pk);
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
 

}

