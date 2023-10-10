


use web3::types::SignedData;
use std::io::{BufWriter, Write, Read};
use ring::{signature as ring_signature, rand as ring_rand};
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use ring::signature::KeyPair;
use secp256k1::Secp256k1;
use secp256k1::ecdsa::Signature;
use secp256k1::{rand::SeedableRng, rand::rngs::StdRng, PublicKey, SecretKey, Message, hashes::sha256};
use tiny_keccak::keccak256;
use std::str::FromStr;
use web3::{ /* a crate to interact with evm based chains */
    transports,
    types::Address,
    Web3,
};
use themis::secure_message::{SecureSign, SecureVerify};
use themis::keygen::gen_ec_key_pair;
use themis::keys::{EcdsaPrivateKey, EcdsaPublicKey};
use themis::keys::KeyPair as ThemisKeyPair;
use secp256k1::hashes::Hash;
use bip39::{Language, Mnemonic, MnemonicType, Seed};
use base64::{engine::general_purpose, Engine as _};


/* 
    converting the String into an static str by leaking the memory of the 
    String to create a longer lifetime allocation for an slice of the String 
*/
fn string_to_static_str(s: String) -> &'static str { 
    Box::leak(s.into_boxed_str()) 
}



/* 
     ---------------------------------------------------------------------
    |   RSA (Asymmetric) Crypto Wallet Implementations using ECC Curves
    |---------------------------------------------------------------------
    |
    |       CURVES
    | ed25519   -> EdDSA                                                    ::::::: ring
    | secp256k1 -> EC (can be imported in EVM based wallets like metamask)  ::::::: secp256k1
    | secp256r1 -> ECDSA                                                    ::::::: themis
    |
    |       ENTROPY
    | BIP39 SEED PHRASES
    |

    https://github.com/skerkour/black-hat-rust/tree/main/ch_11
    https://cryptobook.nakov.com/digital-signatures
    https://thalesdocs.com/gphsm/luna/7/docs/network/Content/sdk/using/ecc_curve_cross-reference.htm

*/



pub mod evm{

    use super::*;

    pub async fn sign(wallet: Wallet, data: &str, infura_url: &str) -> (SignedData, String){

        let transport = transports::WebSocket::new(infura_url).await.unwrap();
        let web3_con = Web3::new(transport);
    
        /* generating secret key instance from secp256k1 secret key */
        let web3_sec = web3::signing::SecretKey::from_str(wallet.secp256k1_secret_key.as_ref().unwrap().as_str()).unwrap();
        let keccak256_hash_of_message = web3_con.accounts().hash_message(data.to_string().as_bytes());
        println!("web3 keccak256 hash of message {:?}", keccak256_hash_of_message); 
    
        /* comparing the secp256k1 keypair with the web3 keypair */
        let secp = Secp256k1::default();
        println!("web3 secret key from secp256k1 {:?}", web3_sec.display_secret()); 
        println!("secp256k1 secret key {:?}", wallet.secp256k1_secret_key.as_ref().unwrap().as_str()); 
        println!("web3 pub key from secp256k1 {:?}", web3_sec.public_key(&secp));
        println!("secp256k1 pub key {:?}", web3_sec.public_key(&secp));
    
        /* signing the keccak256 hash of data */
        let signed_data = web3_con.accounts().sign(
            keccak256_hash_of_message, 
            &web3_sec
        );
    
        /* getting signature of the signed data */
        // signature bytes schema: pub struct Bytes(pub Vec<u8>);
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
    
        /* recovering public address from signature and keccak256 bits hash of the message */
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
    
        if sender == recovered_screen_cid_hex{
            Ok(true)
        } else{
            Err(false)
        }
    
    }

}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct DataBucket{
    pub value: String, /* json stringify */
    pub signed_at: i64,
    pub signature: String
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
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

        let wallet = Wallet{
            secp256k1_secret_key: None,
            secp256k1_public_key: None,
            secp256k1_public_address: None,
            secp256k1_mnemonic: None,
            secp256r1_public_key: None,
            secp256r1_secret_key: None,
            ed25519_public_key: Some(base64_pubkey_string),
            ed25519_secret_key: Some(base64_prvkey_string)
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

    pub fn ed25519_sign(data: &str, prvkey: &str) -> Option<String>{

        /* generating sha25 bits hash of data */
        let hash_data_bytes = Self::generate_sha256_from(data);

        let ed25519 = Self::retrieve_ed25519_keypair(prvkey);

        /* signing the hashed data */
        let signature = ed25519.sign(&hash_data_bytes);
        let sig = signature.as_ref().to_vec();
        Some(hex::encode(&sig))

    }

    pub fn verify_ed25519_signature(sig: &str, data: &str, pubkey: &str) -> Result<(), ring::error::Unspecified>{

        /* 
            since sig and pubkey are hex string we have to get their bytes using 
            hex::decode() cause calling .as_bytes() on the hex string converts
            the hex string itself into bytes and it doesn't return the acutal bytes
        */
        let sig_bytes = hex::decode(&sig).unwrap();

        /* decoding the base64 public key to get the actual bytes */
        let pubkey_bytes = general_purpose::URL_SAFE_NO_PAD.decode(pubkey).unwrap();

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

        /* decoding the base64 private key to get the actual bytes */
        let prvkey_bytes = general_purpose::URL_SAFE_NO_PAD.decode(prv_key).unwrap();
        let generated_ed25519_keys = Ed25519KeyPair::from_pkcs8(&prvkey_bytes).unwrap();
        generated_ed25519_keys

    }

    pub fn generate_secp256k1_pubkey_from(pk: &str) -> Result<PublicKey, secp256k1::Error>{
        let secp256k1_pubkey = PublicKey::from_str(&pk);
        secp256k1_pubkey
    }

    pub fn verify_secp256k1_signature_from_pubkey_str(data: &str, sig: &str, pk: &str) -> Result<(), secp256k1::Error>{

        /* 
            data is required to be passed to the method since we'll compare
            the hash of it with the one inside the signature 
        */
        let data_bytes = data.as_bytes();
        let hashed_data = Message::from_hashed_data::<sha256::Hash>(data_bytes);
        let sig = Signature::from_str(sig).unwrap();
        let pubkey = PublicKey::from_str(pk).unwrap();
            
        /* message is an sha256 bits hashed data */
        let secp = Secp256k1::verification_only();
        secp.verify_ecdsa(&hashed_data, &sig, &pubkey)

    }

    pub fn verify_secp256k1_signature_from_pubkey(data: &str, sig: &str, pk: PublicKey) -> Result<(), secp256k1::Error>{

        /* 
            data is required to be passed to the method since we'll compare
            the hash of it with the one inside the signature 
        */
        let data_bytes = data.as_bytes();
        let hashed_data = Message::from_hashed_data::<sha256::Hash>(data_bytes);
        let sig = Signature::from_str(sig).unwrap();
            
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

    pub fn secp256k1_sign(signer: &str, data: &str) -> Signature{

        let secret_key = SecretKey::from_str(signer).unwrap();
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

    pub fn generate_sha256_from(data: &str) -> [u8; 32]{

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
        let errordir = std::fs::create_dir_all("logs").unwrap();
        let walletpath = format!("wallet/{_type:}.json");  
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
    
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
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
        
        let signature_hex = Wallet::ed25519_sign(stringify_data.clone().as_str(), contract.wallet.ed25519_secret_key.as_ref().unwrap().as_str());
        
        let verify_res = Wallet::verify_ed25519_signature(signature_hex.clone().unwrap().as_str(), stringify_data.as_str(), contract.wallet.ed25519_public_key.unwrap().as_str());

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

        let hashed_data = Wallet::generate_sha256_from(stringify_data.clone().as_str());

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

        let contract = Contract::new_with_secp256k1("0xDE6D7045Df57346Ec6A70DfE1518Ae7Fe61113f4", "wildonion123");
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
                
                let verification_result = Wallet::verify_secp256k1_signature_from_pubkey(stringify_data.as_str(), signature.to_string().as_str(), pk);
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

        /* 
            ECDSA with secp256k1 curve keypairs 
            (compatible with all evm based chains) 
        */
        let wallet = Wallet::new_secp256k1("");

        let data_to_be_signed = serde_json::json!({
            "recipient": "deadkings",
            "from_cid": wallet.secp256k1_public_address.as_ref().unwrap(),
            "amount": 5
        });

        let sign_res = self::evm::sign(
            wallet.clone(), 
            data_to_be_signed.to_string().as_str(),
            ""
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
            ""
        ).await;
        
        if verification_res.is_ok(){
            println!("✅ valid signature");
        } else{
            eprintln!("🔴 invalid signature");
        }

    }
 

}

