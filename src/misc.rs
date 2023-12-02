


use crate::*;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct DataBucket{
    pub value: String, /* any json stringify data */
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

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SecureCellConfig{
    pub secret_key: String, 
    pub passphrase: String, 
    pub data: Vec<u8> // either encrypted or decrypted
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Aes256Config{
    pub secret_key: String, // 64 bytes
    pub nonce: String, // 16 bytes - unique per each message
    pub data: Vec<u8> // either encrypted or decrypted
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Contract{
    pub wallet: Wallet,
    pub iat: i64,
    pub owner: &'static str,
    pub data: Option<DataBucket>,
}

/* 
    converting the String into an static str by leaking the memory of the 
    String to create a longer lifetime allocation for an slice of the String 
*/
pub(crate) fn string_to_static_str(s: String) -> &'static str { 
    Box::leak(s.into_boxed_str()) 
}

/* 
    converting the Vector into an static slice by leaking the memory of the 
    Vector to create a longer lifetime allocation for an slice of the ٰVector 
*/
pub(crate) fn vector_to_static_slice(v: Vec<u8>) -> &'static [u8] { 
    Box::leak(v.into_boxed_slice())
}

/* converting an slice array of u8 bytes into an array with 32 byte length */
pub(crate) fn convert_into_u8_32(data: &[u8]) -> Option<[u8; 32]>{
    data.try_into().ok()
}

pub(crate) fn convert_into_u8_64(data: &[u8]) -> Option<[u8; 64]>{
    data.try_into().ok()
}

pub(crate) fn convert_into_u8_16(data: &[u8]) -> Option<[u8; 16]>{
    data.try_into().ok()
}