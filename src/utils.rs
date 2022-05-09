//use crate::encryption::PubKeyComp;

//use crate::netcore::{L3Addr, L4Addr};
use ipnetwork::IpNetworkError;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
//use rsa::RSAPrivateKey;
use std::array::TryFromSliceError;
use std::string::FromUtf8Error;
use std::sync::mpsc::RecvError as SyncRecvError;
use std::sync::mpsc::SendError as SyncSendError;
use std::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::mpsc::error::RecvError as AsyncRecvError;
use tokio::sync::mpsc::error::SendError as AsyncSendError;
use tokio::task::JoinError;

use err_derive::Error;
use std::iter;
use tokio::sync::mpsc::{
    channel as tokio_channel, Receiver as AsyncReceiver, Sender as AsyncSender,
};

/// used to generate things such as pair keys, and global peer hash, see ArtificePeer
pub fn random_string(len: usize) -> String {
    let mut rng = thread_rng();
    iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .take(len)
        .collect()
}

pub trait Query {
    type Left;
    type Right;
    /// manually create using an existing sender and receiver
    fn create(sender: Self::Left, receiver: Self::Right) -> Self;
    /// split a query into its components
    fn into_split(self) -> (Self::Left, Self::Right);
    fn split(&mut self) -> (&mut Self::Left, &mut Self::Right);
}

pub fn async_channel<S, R>(len: usize) -> (AsyncQuery<R, S>, AsyncQuery<S, R>) {
    let (l_sender, l_receiver): (AsyncSender<R>, AsyncReceiver<R>) = tokio_channel(len);
    let (r_sender, r_receiver): (AsyncSender<S>, AsyncReceiver<S>) = tokio_channel(len);
    (
        AsyncQuery {
            sender: l_sender,
            receiver: r_receiver,
        },
        AsyncQuery {
            sender: r_sender,
            receiver: l_receiver,
        },
    )
}
#[derive(Debug)]
pub struct AsyncQuery<S, R> {
    sender: AsyncSender<S>,
    receiver: AsyncReceiver<R>,
}
impl<S, R> AsyncQuery<S, R> {
    pub async fn send(&mut self, data: S) -> Result<(), NetworkError> {
        Ok(self.sender.send(data).await?)
    }
    pub async fn recv(&mut self) -> Option<R> {
        Some(self.receiver.recv().await?)
    }
}
impl<S, R> Query for AsyncQuery<S, R> {
    type Left = AsyncSender<S>;
    type Right = AsyncReceiver<R>;
    fn create(sender: Self::Left, receiver: Self::Right) -> Self {
        Self { sender, receiver }
    }
    fn into_split(self) -> (Self::Left, Self::Right) {
        (self.sender, self.receiver)
    }
    fn split(&mut self) -> (&mut Self::Left, &mut Self::Right) {
        (&mut self.sender, &mut self.receiver)
    }
}
pub fn sync_channel<R, S>() -> (SyncQuery<R, S>, SyncQuery<S, R>) {
    let (l_sender, l_receiver) = channel();
    let (r_sender, r_receiver) = channel();
    (
        SyncQuery {
            sender: l_sender,
            receiver: r_receiver,
        },
        SyncQuery {
            sender: r_sender,
            receiver: l_receiver,
        },
    )
}
#[derive(Debug)]
pub struct SyncQuery<S, R> {
    sender: Sender<S>,
    receiver: Receiver<R>,
}
impl<S, R> SyncQuery<S, R> {
    pub fn send(&mut self, data: S) -> Result<(), NetworkError> {
        Ok(self.sender.send(data)?)
    }
    pub fn recv(&mut self) -> Result<R, NetworkError> {
        Ok(self.receiver.recv()?)
    }
}
impl<S, R> Query for SyncQuery<S, R> {
    type Left = Sender<S>;
    type Right = Receiver<R>;
    fn create(sender: Self::Left, receiver: Self::Right) -> Self {
        Self { sender, receiver }
    }
    fn into_split(self) -> (Self::Left, Self::Right) {
        (self.sender, self.receiver)
    }
    fn split(&mut self) -> (&mut Self::Left, &mut Self::Right) {
        (&mut self.sender, &mut self.receiver)
    }
}
/*#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error(display = "Invalid Header: {:?}", _0)]
    InvalidHeader(StreamHeader),
    #[error(display = "Invalid Peer: {:?}", _0)]
    InvalidPeer,
    UnReachable,
}*/
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error(display = "IO Error: {}", _0)]
    IOError(#[source] std::io::Error),
    #[error(display = "RSA Error: {}", _0)]
    RSAError(#[source] rsa::errors::Error),
    #[error(display = "JSON Parse Error: {}", _0)]
    JsonError(#[source] serde_json::error::Error),
    #[error(display = "UTF-8 Parse Error: {}", _0)]
    UTF8(#[source] FromUtf8Error),
    #[error(display = "Connect Denied: {}", _0)]
    ConnectionDenied(#[error(no_from)] String),
    #[error(display = "From Slice Error: {}", _0)]
    FromSlice(#[source] TryFromSliceError),
    #[error(display = "Unknown Error Kind: {}", _0)]
    UnSet(String),
    #[error(display = "Execution Failed: {:?}", _0)]
    ExecFailed(#[error(no_from)] String),
    #[error(display = "Async Send Error: {}", _0)]
    AsyncSendError(#[error(no_from)] String),
    #[error(display = "Async Recv Error: {}", _0)]
    AsyncRecvError(#[error(no_from)] String),
    #[error(display = "Sync Send Error: {}", _0)]
    SyncSendError(#[error(no_from)] String),
    #[error(display = "Sync Recv Error: {}", _0)]
    SyncRecvError(#[error(no_from)] String),
    #[error(display = "Join Error: {}", _0)]
    JoinError(#[source] JoinError),
    #[error(display = "WalkDir Error: {}", _0)]
    DirError(#[source] walkdir::Error),
    #[error(display = "Not Asyncronous")]
    NotAsync,
    #[error(display = "Not Syncronous")]
    NotSync,
    #[error(display = "No Data Yet")]
    Empty,
    #[error(display = "ip network error: {}", _0)]
    NetErr(#[source] IpNetworkError),
}
impl<T> From<AsyncSendError<T>> for NetworkError {
    fn from(error: AsyncSendError<T>) -> NetworkError {
        NetworkError::AsyncSendError(format!("{}", error))
    }
}
impl From<AsyncRecvError> for NetworkError {
    fn from(error: AsyncRecvError) -> NetworkError {
        NetworkError::AsyncRecvError(format!("{}", error))
    }
}
impl<T> From<SyncSendError<T>> for NetworkError {
    fn from(error: SyncSendError<T>) -> NetworkError {
        NetworkError::SyncSendError(format!("{}", error))
    }
}
impl From<SyncRecvError> for NetworkError {
    fn from(error: SyncRecvError) -> NetworkError {
        NetworkError::SyncRecvError(format!("{}", error))
    }
}
/*impl From<std::option::NoneError> for NetworkError {
    fn from(_: std::option::NoneError) -> NetworkError {
        NetworkError::Empty
    }
}*/
