use std::io;
use crate::codec::codec_trait::TfCodec;
use crate::structures::temp_transport::TempTransport;
use crate::structures::transport::{AsyncReadWrite, Transport};
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures_util::{SinkExt, StreamExt};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use std::sync::Arc;
use tokio_util::codec::{Decoder, Encoder, Framed, LengthDelimitedCodec};
use crate::util::session_keys::{
    CONFIRM_LABEL_CLIENT, CONFIRM_LABEL_SERVER, SessionKeys, constant_time_eq,
    derive_confirmation_tag,
};

pub struct Spake2Encrypted {
    server_provider: Option<Arc<dyn ServerCredentialProvider>>,
    client_provider: Option<Arc<dyn ClientCredentialProvider>>,
    is_server: bool,
    server_id: Vec<u8>,
    length_codec: LengthDelimitedCodec,
    keys: Option<SessionKeys>,
}

impl Spake2Encrypted {
    pub fn create_server(
        server_provider: Arc<dyn ServerCredentialProvider>,
        server_id: String,
        codec: LengthDelimitedCodec,
    ) -> Self {
        Self {
            server_provider: Some(server_provider),
            client_provider: None,
            is_server: true,
            server_id: server_id.as_bytes().to_vec(),
            length_codec: codec,
            keys: None,
        }
    }

    pub fn create_client(
        client_provider: Arc<dyn ClientCredentialProvider>,
        server_id: String,
        codec: LengthDelimitedCodec,
    ) -> Self {
        Self {
            server_provider: None,
            client_provider: Some(client_provider),
            is_server: false,
            server_id: server_id.as_bytes().to_vec(),
            length_codec: codec,
            keys: None,
        }
    }
}
impl Decoder for Spake2Encrypted {
    type Item = BytesMut;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let mut frame = match self.length_codec.decode(src)? {
            Some(f) => f,
            None => return Ok(None),
        };
        if let Some(keys) = &self.keys {
            keys.open_in_place(&mut frame)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "decryption failed"))?;
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "decryption failed"));
        }
        Ok(Some(frame))
    }
}

impl Encoder<Bytes> for Spake2Encrypted {
    type Error = io::Error;

    fn encode(&mut self, item: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        if let Some(keys) = &self.keys {
            let mut buf = BytesMut::from(item);
            keys.seal_in_place(&mut buf)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "encryption failed"))?;
            self.length_codec.encode(buf.freeze(), dst)
        } else {
            return Err(io::Error::new(io::ErrorKind::Other, "encryption failed"));
        }
    }
}
impl Clone for Spake2Encrypted {
    fn clone(&self) -> Self {
        Self{
            server_provider: self.server_provider.clone(),
            client_provider: self.client_provider.clone(),
            is_server: self.is_server.clone(),
            server_id: self.server_id.clone(),
            length_codec: self.length_codec.clone(),
            keys: None
        }
    }
}

#[async_trait]
impl TfCodec for Spake2Encrypted {
    async fn initial_setup(&mut self, tr: &mut Transport) -> bool {
        //Safe limitation to prevent dos
        let length_codec = LengthDelimitedCodec::builder().max_frame_length(2048).new_codec();
        let mut framed = Framed::new(TempTransport::new(tr), length_codec);
        if self.is_server{
            let res = server_handshake(&mut framed, self.server_provider.as_ref().unwrap().clone(), self.server_id.as_slice()).await;
            if let Some(keys) = res {
                self.keys = Some(keys);
                return true;
            } else {
                return false;
            }
        } else {
            let res = client_handshake(&mut framed, self.client_provider.as_ref().unwrap().clone(), self.server_id.as_slice()).await;
            if let Some(keys) = res {
                self.keys = Some(keys);
                return true;
            }
            return false;
        }
    }
}


#[async_trait]
pub trait ServerCredentialProvider: Send+Sync+'static  {
    async fn get_client_password(&self, client_identity: &str) -> Option<Vec<u8>>;
}

#[async_trait]
pub trait ClientCredentialProvider: Send+Sync+'static {
    ///Return 0 - client identity, 1 - client password
    async fn get_client_credentials(&self) -> Option<(Vec<u8>, Vec<u8>)>;
}

pub async fn client_handshake<'a, IO: AsyncReadWrite>(
    io: &mut Framed<TempTransport<'a, IO>, LengthDelimitedCodec>,
    cred: Arc<dyn ClientCredentialProvider>,
    server_id: &[u8],
) -> Option<SessionKeys> {
    let (client_id, password) = cred.get_client_credentials().await?;
    let (spake, outbound_msg) = Spake2::<Ed25519Group>::start_a(
        &Password::new(password.as_slice()),
        &Identity::new(client_id.as_slice()),
        &Identity::new(server_id),
    );
    // Both are kept for the transcript; cloning `Bytes` only bumps a refcount.
    let client_id = Bytes::from(client_id);
    let outbound_msg = Bytes::from(outbound_msg);
    io.send(client_id.clone()).await.ok()?;
    io.send(outbound_msg.clone()).await.ok()?;

    let peer_msg = io.next().await?.ok()?;

    let transcript = build_transcript(&client_id, server_id, &outbound_msg, &peer_msg);
    let shared = spake.finish(&peer_msg).ok()?;

    // Client proves password knowledge first; the server only answers once
    // this checks out.
    let client_tag = derive_confirmation_tag(&shared, CONFIRM_LABEL_CLIENT, &transcript)?;
    io.send(Bytes::copy_from_slice(&client_tag)).await.ok()?;

    let server_tag = io.next().await?.ok()?;
    let expected = derive_confirmation_tag(&shared, CONFIRM_LABEL_SERVER, &transcript)?;
    if !constant_time_eq(&server_tag, &expected) {
        return None;
    }

    SessionKeys::derive_session_keys(&shared, &transcript, false)
}

pub async fn server_handshake<'a, IO: AsyncReadWrite>(
    io: &mut Framed<TempTransport<'a, IO>, LengthDelimitedCodec>,
    cred_provider: Arc<dyn ServerCredentialProvider>,
    server_id: &[u8],
) -> Option<SessionKeys>
where
    IO: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let client_identity = io.next().await?.ok()?;
    let client_identity = String::from_utf8_lossy(client_identity.as_ref());
    let password = cred_provider.get_client_password(&client_identity).await?;
    let client_identity = client_identity.as_bytes();
    let (spake, outbound_msg) = Spake2::<Ed25519Group>::start_b(
        &Password::new(password),
        &Identity::new(client_identity),
        &Identity::new(server_id),
    );
    let peer_msg = io.next().await?.ok()?;

    let transcript = build_transcript(client_identity, server_id, &peer_msg, &outbound_msg);
    io.send(Bytes::from(outbound_msg)).await.ok()?;

    let shared = spake.finish(&peer_msg).ok()?;

    let client_tag = io.next().await?.ok()?;
    let expected = derive_confirmation_tag(&shared, CONFIRM_LABEL_CLIENT, &transcript)?;
    if !constant_time_eq(&client_tag, &expected) {
        return None;
    }

    let server_tag = derive_confirmation_tag(&shared, CONFIRM_LABEL_SERVER, &transcript)?;
    io.send(Bytes::copy_from_slice(&server_tag)).await.ok()?;

    SessionKeys::derive_session_keys(&shared, &transcript, true)
}

/// Serialize the handshake as `client_id | server_id | msg_a | msg_b`, each
/// field prefixed with its u32 big-endian length so no two distinct handshakes
/// can produce the same transcript bytes.
fn build_transcript(client_id: &[u8], server_id: &[u8], msg_a: &[u8], msg_b: &[u8]) -> Vec<u8> {
    let fields = [client_id, server_id, msg_a, msg_b];
    let mut out = Vec::with_capacity(fields.iter().map(|f| 4 + f.len()).sum());
    for f in fields {
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}


#[cfg(test)]
mod seal_open_tests {
    use super::*;


    fn pair() -> (SessionKeys, SessionKeys) {
        (
            SessionKeys::derive_session_keys(b"shared-secret", b"transcript", true).unwrap(),
            SessionKeys::derive_session_keys(b"shared-secret", b"transcript", false).unwrap(),
        )
    }

    fn roundtrip(plaintext: &[u8]) {
        let (server, client) = pair();

        let mut buf = BytesMut::from(plaintext);
        server.seal_in_place(&mut buf).expect("seal");
        // wire layout = ciphertext | tag(16); the counter is implicit
        assert_eq!(buf.len(), SessionKeys::sealed_len(plaintext.len()));
        client.open_in_place(&mut buf).expect("open");
        assert_eq!(&buf[..], plaintext);
    }

    #[test]
    fn roundtrip_various_sizes() {
        roundtrip(b"");
        roundtrip(b"hello");
        roundtrip(&[0x41u8; 4096]);
    }

    #[test]
    fn replay_is_rejected() {
        let (server, client) = pair();
        let mut buf = BytesMut::from(&b"first"[..]);
        server.seal_in_place(&mut buf).unwrap();
        let mut replay = buf.clone();
        client.open_in_place(&mut buf).unwrap();
        assert!(client.open_in_place(&mut replay).is_none(), "replay must be rejected");
    }

    #[test]
    fn tamper_is_rejected() {
        let (server, client) = pair();
        let mut buf = BytesMut::from(&b"payload"[..]);
        server.seal_in_place(&mut buf).unwrap();
        let idx = buf.len() - 1;
        buf[idx] ^= 0xFF; // flip a tag byte
        assert!(client.open_in_place(&mut buf).is_none(), "tamper must fail tag check");
    }
}
