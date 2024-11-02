use std::fmt::Display;

/// Universal Hash error.
#[derive(Debug, thiserror::Error)]
pub struct UniversalHashError {
    kind: ErrorKind,
    #[source]
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl UniversalHashError {
    pub(crate) fn state<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind: ErrorKind::InvalidState,
            source: Some(source.into()),
        }
    }

    pub(crate) fn key<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind: ErrorKind::KeyLength,
            source: Some(source.into()),
        }
    }

    pub(crate) fn input<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind: ErrorKind::InputLength,
            source: Some(source.into()),
        }
    }

    pub(crate) fn conversion<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind: ErrorKind::ShareConversion,
            source: Some(source.into()),
        }
    }

    pub(crate) fn flush<E>(source: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self {
            kind: ErrorKind::Flush,
            source: Some(source.into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ErrorKind {
    InvalidState,
    KeyLength,
    InputLength,
    ShareConversion,
    Flush,
}

impl Display for UniversalHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            ErrorKind::InvalidState => write!(f, "invalid state error")?,
            ErrorKind::KeyLength => write!(f, "key length error")?,
            ErrorKind::InputLength => write!(f, "input length error")?,
            ErrorKind::ShareConversion => write!(f, "share conversion error")?,
            ErrorKind::Flush => write!(f, "flush error")?,
        }

        if let Some(source) = &self.source {
            write!(f, " caused by: {}", source)?;
        }

        Ok(())
    }
}
