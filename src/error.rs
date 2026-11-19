use crate::model::Status;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    NoResults(String),
    #[error("{0}")]
    Auth(String),
    #[error("{0}")]
    Network(String),
    #[error("{0}")]
    Locked(String),
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
    #[error("{} (CloudKit code {code})", description.as_deref().unwrap_or("CloudKit operation failed"))]
    CloudKit {
        code: i32,
        description: Option<String>,
    },
    #[error(transparent)]
    Plist(#[from] plist::Error),
    #[cfg(feature = "keyring")]
    #[error(transparent)]
    Keyring(#[from] keyring::Error),
}

impl Error {
    pub fn status(&self) -> i32 {
        match self {
            Error::Message(_) => Status::GenericError as i32,
            Error::Invalid(_) => Status::InvalidParam as i32,
            Error::NoResults(_) => Status::NoResults as i32,
            Error::Auth(_) => Status::Auth as i32,
            Error::Network(_) | Error::Http(_) => Status::Network as i32,
            Error::Locked(_) | Error::Aead => Status::Locked as i32,
            Error::CloudKit { .. } => Status::GenericError as i32,
            _ => Status::GenericError as i32,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Error::Invalid(_) => "usage",
            Error::NoResults(_) => "not_found",
            Error::Auth(_) => "auth",
            Error::Network(_) | Error::Http(_) => "network",
            Error::Locked(_) | Error::Aead => "locked",
            Error::CloudKit { .. } => "cloudkit",
            _ => "error",
        }
    }

    pub fn message(&self) -> String {
        self.to_string()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
