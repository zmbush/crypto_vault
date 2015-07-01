use rustc_serialize::json::DecoderError;
use rustc_serialize::base64::FromBase64Error;
use self::VaultError::*;

/// Various errors for vault operations
#[derive(Debug)]
pub enum VaultError {
    /// If the vault is corrupted, we may not be able to read the base64 encoded data
    Base64Error(FromBase64Error),
    /// This happens when the data in the vault is valid, but does not match the vault type
    VaultEntrySchemaError(DecoderError),
    /// When the decrypted data is not valid JSON
    BadPasswordError,
    /// When you attempt to encrypt a Vault that has no password set
    NoPasswordSpecifiedError
}

/// Convenience type for VaultError functions
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
