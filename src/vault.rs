use rustc_serialize::{json, Decodable, Encodable};
use rustc_serialize::base64::{self, ToBase64, FromBase64};
use std::fmt::{Debug, Display};
use std::str::FromStr;

use error::{VaultError, VResult};
use crypto::{encrypt, decrypt, gen_bytes, derive_key};

/// Stores the data in an encrypted format. The only information
/// needed to decrypt the data should be the password.
pub struct RawVault {
    /// This is printed as the first line of the Vault::to_string
    pub header: String,
    /// The raw encrypted data
    pub data: Vec<u8>,

    salt: Vec<u8>,
    iv: Vec<u8>,
}

impl ToString for RawVault {
    fn to_string(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}",
            self.header,
            self.salt.to_base64(base64::STANDARD),
            self.iv.to_base64(base64::STANDARD),
            self.data.to_base64(base64::Config { newline: base64::Newline::LF, .. base64::MIME })
        )
    }
}

impl FromStr for RawVault {
    type Err = VaultError;
    fn from_str(s: &str) -> VResult<RawVault> {
        let mut lines = s.lines_any();
        Ok(RawVault {
            header: lines.next().unwrap_or_default().to_owned(),
            salt: try!(lines.next().unwrap_or_default().from_base64()),
            iv: try!(lines.next().unwrap_or_default().from_base64()),
            data: try!(lines.fold("".to_owned(), |acc, item| format!("{}{}", acc, item)).from_base64())
        })
    }
}

impl RawVault {
    /// Decrypts the data into a Vault
    pub fn decrypt<T>(&self, password: &str) -> VResult<Vault<T>> where T: Decodable + Encodable + Debug {
        let master_key = derive_key(&password, &self.salt);
        let decrypted = decrypt(&master_key, &self.iv, &self.data);

        Ok(Vault {
            header: self.header.clone(),
            key_info: Some(KeyInfo {
                master_key: master_key,
                salt: self.salt.clone()
            }),
            objects: try!(json::decode(&decrypted))
        })
    }
}

#[derive(Debug)]
struct KeyInfo {
    master_key: Vec<u8>,
    salt: Vec<u8>
}

/// Stores the decrypted data. May have the master key and salt for encryption.
#[derive(Debug)]
pub struct Vault<T: Decodable + Encodable + Debug> {
    /// Same as for RawVault. This is printed at the top of the encrypted store file.
    pub header: String,
    /// The decrypted data
    pub objects: Vec<T>,

    key_info: Option<KeyInfo>,
}

impl<T: Decodable + Encodable + Debug> Vault<T> {
    /// Sets the password. Overrides previous password.
    pub fn set_password(&mut self, password: &str) {
        let salt = gen_bytes();
        self.key_info = Some(KeyInfo {
            master_key: derive_key(password, &salt),
            salt: salt
        });
    }

    /// Sets the password. Overrides previous password.
    ///
    /// Chainable version of set_password
    pub fn with_password(mut self, password: &str) -> Vault<T> {
        self.set_password(password);
        self
    }

    /// Encrypts the store into a RawVault.
    ///
    /// Returns a `VaultError::NoPasswordSpecifiedError` if there is no password set on the store.
    pub fn encrypt(&self) -> VResult<RawVault> {
        let (salt, master_key) = match self.key_info {
            Some(KeyInfo { ref salt, ref master_key }) => (salt, master_key),
            None => return Err(VaultError::NoPasswordSpecifiedError)
        };
        let (iv, data) = encrypt(&master_key, &json::as_json(&self.objects).to_string());
        Ok(RawVault {
            header: self.header.clone(),
            iv: iv,
            salt: salt.clone(),
            data: data
        })
    }

    /// Constructor function
    pub fn new() -> Vault<T> {
        Vault {
            header: "crypto_vault v1.0 https://github.com/zmbush/crypto_vault".to_owned(),
            key_info: None,
            objects: Vec::new()
        }
    }

    /// Constructor with a custom header
    pub fn with_header<D>(h: D) -> Vault<T> where D: Display {
        Vault {
            header: format!("{}", h),
            .. Vault::new()
        }
    }
}

impl<T: Decodable + Encodable + Debug> Default for Vault<T> {
    fn default() -> Vault<T> {
        Vault::new()
    }
}
