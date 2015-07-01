use openssl::crypto::pkcs5::pbkdf2_hmac_sha1;
use openssl::crypto::symm;
use rand::{Rng, OsRng};
use std::str;

fn crypt_opt(mode: symm::Mode, key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
    let crypter = symm::Crypter::new(symm::Type::AES_256_CBC);
    crypter.pad(true);
    crypter.init(mode, key, iv);
    let mut final_result = Vec::new();
    final_result.push_all(&crypter.update(data));
    final_result.push_all(&crypter.finalize());

    final_result
}

pub type Iv = Vec<u8>;
pub fn encrypt(key: &[u8], string: &str) -> (Iv, Vec<u8>) {
    let iv = gen_bytes();
    let data: Vec<u8> = string.bytes().collect();

    (iv.clone(), crypt_opt(symm::Mode::Encrypt, key, &iv, &data))
}

pub fn decrypt(key: &[u8], iv: &[u8], data: &[u8]) -> String {
    let result = crypt_opt(symm::Mode::Decrypt, key, iv, data);
    str::from_utf8(&result).ok().unwrap_or("").to_owned()
}

pub fn derive_key(p: &str, salt: &[u8]) -> Vec<u8> {
    pbkdf2_hmac_sha1(p, salt, 1024, 32)
}

pub fn gen_bytes() -> Vec<u8> {
    let mut salt = [0; 16];
    let mut f = OsRng::new().ok().expect("Unable to use OS Rng. Can't save");
    f.fill_bytes(&mut salt);
    salt.to_vec()
}
