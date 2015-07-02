//! A simple vault for storing encrypted data.
//!
//! View the project on [Github](https://github.com/zmbush/crypto_vault).
//!
//! # Usage
//!
//! ```
//! extern crate rustc_serialize;
//! extern crate crypto_vault;
//!
//! use rustc_serialize::{Decoder, Encoder};
//! use crypto_vault::{Vault, RawVault, DecryptVault};
//! use std::str::FromStr;
//!
//! #[derive(RustcEncodable, RustcDecodable, Debug)]
//! struct Obj {
//!     key: String
//! }
//!
//! fn main() {
//!     let mut vault = Vault::new().with_password("foo");
//!     vault.objects.push(Obj { key: "bar".to_owned() });
//!     let vault_str = vault.encrypt().unwrap().to_string();
//!
//!     // The long way
//!     let new_vault1: Vault<Obj> = RawVault::from_str(&vault_str)
//!         .unwrap()
//!         .decrypt("foo")
//!         .unwrap();
//!     assert_eq!(new_vault1.objects[0].key, "bar".to_owned());
//!
//!     // The short way
//!     let new_vault2: Vault<Obj> = vault_str.decrypt_vault("foo").unwrap();
//!     assert_eq!(new_vault2.objects[0].key, "bar".to_owned());
//! }
//! ```
#![feature(vec_push_all, plugin)]
#![deny(missing_docs, bad_style, unused)]

extern crate openssl;
extern crate rand;
extern crate rustc_serialize;

#[macro_use] mod macros;
mod crypto;
mod vault;
mod error;

pub use vault::*;
pub use error::*;
