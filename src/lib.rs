#![feature(vec_push_all, plugin)]
#![plugin(regex_macros, clippy)]
#![deny(bad_style, unused, clippy)]

extern crate openssl;
extern crate rand;
extern crate regex;
extern crate rustc_serialize;

#[macro_use] mod macros;
mod crypto;
mod vault;
mod error;

pub use vault::*;
