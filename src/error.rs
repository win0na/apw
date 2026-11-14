use crate::model::Status;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    NoResults(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Toml(#[from] toml::de::Error),
    #[error(transparent)]
    TomlEncode(#[from] toml::ser::Error),
    #[error("cannot decrypt the snapshot: wrong key or damaged file")]
    Aead,
    #[error(transparent)]
    Http(#[from] reqwest::Error),
    #[error(transparent)]
    Plist(#[from] plist::Error),
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
}

impl Error {
    pub fn status(&self) -> i32 {
        match self {
            Error::Message(_) => Status::GenericError as i32,
            Error::Invalid(_) => Status::InvalidParam as i32,
            Error::NoResults(_) => Status::NoResults as i32,
            _ => Status::GenericError as i32,
        }
    }

    pub fn message(&self) -> String {
        self.to_string()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
