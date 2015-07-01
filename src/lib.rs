//! A simple vault for storing encrypted data
//!
//! # Usage
//!
//! ```
//! extern crate rustc_serialize;
//! extern crate crypto_vault;
//!
//! use rustc_serialize::{Decoder, Encoder};
//! use crypto_vault::{Vault, RawVault};
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
//!     let new_vault: Vault<Obj> = RawVault::from_str(&vault_str).unwrap().decrypt("foo").unwrap();
//!     assert_eq!(new_vault.objects[0].key, "bar".to_owned());
//! }
//! ```
#![feature(vec_push_all, plugin)]
#![plugin(regex_macros)]
#![deny(missing_docs, bad_style, unused)]

extern crate openssl;
extern crate rand;
extern crate regex;
extern crate rustc_serialize;

#[macro_use] mod macros;
mod crypto;
mod vault;
mod error;

pub use vault::*;
pub use error::*;
