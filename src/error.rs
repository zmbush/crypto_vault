use rustc_serialize::json::DecoderError;
use rustc_serialize::base64::FromBase64Error;
use self::VaultError::*;

#[derive(Debug)]
pub enum VaultError {
    Base64Error(FromBase64Error),
    VaultEntrySchemaError(DecoderError),
    BadPasswordError,
    NoPasswordSpecifiedError
}

pub type VResult<T> = Result<T, VaultError>;

impl From<DecoderError> for VaultError {
    fn from(e: DecoderError) -> VaultError {
        match e {
            DecoderError::ParseError(_) => BadPasswordError,
            e => VaultEntrySchemaError(e)
        }
    }
}

impl From<FromBase64Error> for VaultError {
    fn from(e: FromBase64Error) -> VaultError {
        Base64Error(e)
    }
}
