#[cfg(feature = "codec")]
pub mod codec_trait;
#[cfg(feature = "std-codecs")]
pub mod length_delimited;
#[cfg(feature = "std-codecs")]
pub mod spake2_encrypted;
