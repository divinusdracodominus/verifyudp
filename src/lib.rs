#[macro_use]
extern crate serde_derive;
mod encryption;
pub mod netcore;
mod protocol;
pub use netcore::*;
pub mod utils;
pub use utils::*;
use crate::encryption::{PrivKeyComp, PubKeyComp};
use std::error::Error;
use std::net::IpAddr;
use std::sync::mpsc::*;
use std::thread;
use std::time::Duration;
pub use utils::*;
// ===================================================================
//                                 Dependencies
// ===================================================================
//use crate::asyncronous::{AsyncNetworkHost};
use crate::encryption::{
    asym_aes_decrypt as aes_decrypt, asym_aes_encrypt as aes_encrypt, sym_aes_decrypt,
    sym_aes_encrypt,
};
use crate::{
    protocol::RemotePeer, protocol::StreamHeader, random_string, AsyncQuery, L4Addr, NetworkError,
    Query,
};
use async_trait::async_trait;
use futures::{
    future::Future,
    task::{Context, Poll},
};
use rsa::{RSAPrivateKey, RSAPublicKey};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    stream::Stream,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex, MutexGuard,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtificeConfig {
    broadcast: bool,
    addr: L4Addr,
    host: ArtificeHostData,
}
impl ArtificeConfig {
    pub fn new(addr: L4Addr, host: ArtificeHostData, broadcast: bool) -> Self {
        Self {
            broadcast,
            addr,
            host,
        }
    }
    /// used to create new host, primarily designed for use by the installer crate
    pub fn generate(addr: L4Addr) -> Self {
        let broadcast = false;
        let host = ArtificeHostData::default();
        Self {
            broadcast,
            addr,
            host,
        }
    }
    pub fn host_data(&self) -> &ArtificeHostData {
        &self.host
    }
    pub fn broadcast(&self) -> bool {
        self.broadcast
    }
    pub fn port(&self) -> u16 {
        self.addr.port()
    }
    pub fn addr(&self) -> L3Addr {
        self.addr.ip()
    }
    pub fn socket_addr(&self) -> L4Addr {
        self.addr
    }
    pub fn set_socket_addr(&mut self, addr: SocketAddr) {
        self.addr = addr.into();
    }
}

/// provides a means of saving private keys to files, because the process of generating the keys takes a really long time, but creating them from existing values does not
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ArtificeHostData {
    priv_key: PrivKeyComp,
}
impl Default for ArtificeHostData {
    fn default() -> Self {
        let priv_key = PrivKeyComp::generate().unwrap();
        Self { priv_key }
    }
}
impl ArtificeHostData {
    pub fn new(private_key: &RSAPrivateKey) -> Self {
        let priv_key = PrivKeyComp::from(private_key);
        Self { priv_key }
    }
    /// returns the n, e, d, and primes of an RSA key
    pub fn privkeycomp(&self) -> &PrivKeyComp {
        &self.priv_key
    }
}

/// used to set discoverability on the local network
pub trait ArtificeHost {
    /// sets up a udp socket to broadcast the existence of a peer on the local network
    /// kind of stupid, but at the time I thought it was a good idea as an optional feature
    fn begin_broadcast<S: std::net::ToSocketAddrs>(
        socket_addr: S,
    ) -> std::io::Result<std::sync::mpsc::Sender<bool>> {
        let (sender, recv) = std::sync::mpsc::channel();
        let socket = std::net::UdpSocket::bind(socket_addr)?;
        socket.set_broadcast(true)?;
        thread::spawn(move || loop {
            match recv.recv_timeout(Duration::from_millis(200)) {
                Ok(_) => break,
                Err(e) => match e {
                    RecvTimeoutError::Timeout => continue,
                    RecvTimeoutError::Disconnected => break,
                },
            }
        });
        Ok(sender)
    }
    /// stop the udp socket from sending packets, by using the sender provided from the begin_broadcast method
    fn stop_broadcasting(&self);
}

//=======================================
//            Async Traits
//========================================

#[async_trait]
pub trait AsyncNetworkHost: Stream {
    type Error: Error;
    /// construct a host instance based on the data in ArtificeConfig
    async fn from_host_config(config: &ArtificeConfig) -> Result<Self, Self::Error>
    where
        Self: std::marker::Sized;
}

/// trait for sending data over the network
#[async_trait]
pub trait AsyncSend {
    /// the error that is thrown when sending data fails
    type SendError: Error;
    /// send data returning the length of data sent, in theory
    async fn send(&mut self, outbuf: &[u8]) -> Result<usize, Self::SendError>;
    /// returns the socket addr that this tream is connected to
    fn remote_addr(&self) -> &SocketAddr;
}
/// trait for receiving network data
#[async_trait]
pub trait AsyncRecv {
    type RecvError: Error;
    /// receive data into inbuf, returning indexes into the vector at which position, seperate messages begin because of tcp concating packets
    async fn recv(&mut self, inbuf: &mut Vec<u8>) -> Result<Vec<usize>, Self::RecvError>;
    /// return current StreamHeader, not the packet len is not accurate, that field is only used in the encoded version of the struct
    fn header(&self) -> &StreamHeader;
}

#[async_trait]
pub trait AsyncDataStream: AsyncSend + AsyncRecv {
    type NetStream;
    type StreamError: Error;
    fn new(
        stream: Self::NetStream,
        header: StreamHeader,
        remote_addr: SocketAddr,
    ) -> Result<Self, Self::StreamError>
    where
        Self: std::marker::Sized;
    #[allow(missing_docs)]
    fn remote_port(&self) -> u16 {
        self.remote_addr().port()
    }
    #[allow(missing_docs)]
    fn remote_ip(&self) -> IpAddr {
        self.remote_addr().ip()
    }
}

pub struct AsyncRequest<T: AsyncDataStream> {
    pubkey: PubKeyComp,
    stream: T,
}

pub trait PeerList {
    fn verify_peer(&self, peer: &crate::encryption::PubKeyComp) -> bool;
}

pub trait ConnectionRequest {
    type Error: Error;
    /// the data stream object that this trait operates on
    type NetStream;
    #[allow(missing_docs)]
    fn new(stream: Self::NetStream, pubkey: PubKeyComp) -> Self;
    /// used to ensure only known peers are allow to connect
    fn verify<L: PeerList>(self, list: &L) -> Result<Self::NetStream, Self::Error>;
    /// # Safety
    /// this function allows unauthorized peers to connect to this device
    /// should only be used if a pair request is being run
    unsafe fn unverify(self) -> Self::NetStream;
}

// used to create handshake between both sides of sllp stream
async fn handshake(
    header: &StreamHeader,
    peer: &RemotePeer,
    priv_key: &RSAPrivateKey,
    sender_addr: SocketAddr,
) -> Result<(), NetworkError> {
    let addr: SocketAddr = peer.socket_addr();
    let mut tcpstream = TcpStream::connect(addr).await?;
    let sender_addr: L4Addr = sender_addr.into();
    tcpstream
        .write(&aes_encrypt(
            &RSAPublicKey::from(priv_key),
            header.clone(),
            &serde_json::to_string(&peer)?.into_bytes(),
        )?)
        .await?;
    let mut inbuf: [u8; 1000] = [0; 1000];
    let data_len = tcpstream.read(&mut inbuf).await?;
    let (dec_data, new_header) = aes_decrypt(&priv_key, &mut inbuf[0..data_len])?;
    if header.checksum() != new_header.checksum() {
        return Err(NetworkError::ConnectionDenied(
            "headers don't match".to_string(),
        ));
    }
    //let in_data = String::from_utf8(dec_data)?;
    
    tcpstream.write(&aes_encrypt(&RSAPublicKey::from(priv_key), header.clone(), &dec_data)?).await?;
    let dec_res_len = tcpstream.read(&mut inbuf).await?;
    let (dec_result, _, _) = sym_aes_decrypt(&header, &mut inbuf[0..dec_res_len])?;
    let in_data = String::from_utf8(dec_result)?;
    if in_data != "okay" {
        return Err(NetworkError::ConnectionDenied(String::from(
            "connection failed",
        )));
    }
    Ok(())
}
fn incoming_conn(
    receiver: &mut Receiver<NewConnection>,
    ctx: &mut Context<'_>,
) -> Poll<Option<Result<AsyncRequest<SllpStream>, NetworkError>>> {
    let (header, addr, query, pubkey) = match receiver.poll_recv(ctx) {
        Poll::Ready(data) => match data {
            Some(data) => data?,
            None => return Poll::Ready(None),
        },
        Poll::Pending => return Poll::Pending,
    };

    Poll::Ready(Some(Ok(AsyncRequest::new(
        match SllpStream::new(query, header, addr) {
            Ok(stream) => stream,
            Err(e) => return Poll::Ready(Some(Err(e))),
        },
        pubkey,
    ))))
}
async fn recv_incoming(
    listener: &mut TcpListener,
    in_priv_key: &RSAPrivateKey,
    in_sender: &Streams,
    outgoing_sender: &Sender<OutgoingMsg>,
) -> NewConnection {
    let mut buffer: [u8; 65535] = [0; 65535];
    let (mut stream, tcpaddr) = listener.accept().await?;
    let data_len = stream.read(&mut buffer).await?;
    let (dec_data, header) = aes_decrypt(&in_priv_key, &mut buffer[0..data_len])?;
    let remote_peer: RemotePeer = serde_json::from_str(&String::from_utf8(dec_data)?)?;
    let (layer3_addr, pubkeycomp) = remote_peer.decompose();
    // then randomly generate a string encypt using public key
    // then have client send the random string back, there by completing
    // the challenge and verifyig the publickey
    let addr = SocketAddr::new(tcpaddr.ip(), layer3_addr.port());
    let challenge_str = random_string(32);
    let challenge = challenge_str.as_bytes();
    stream.write(&aes_encrypt(&pubkeycomp.clone().into(), header, challenge)?).await?;
    //buffer.clear();
    let newlen = stream.read(&mut buffer).await?;
    let (newdec, header) = aes_decrypt(&in_priv_key, &mut buffer[0..newlen])?;
    if newdec != challenge {
        // should really return an error here
        panic!("public key verification failed");
    }
    stream.write(&sym_aes_encrypt(&header, b"okay")).await?;
    // SllpSocket -> SllpStream Vec<u8> = data recv, usize = data length
    let (incoming_sender, incoming_receiver): (Sender<IncomingMsg>, Receiver<(Vec<u8>, usize)>) =
        channel(1);
    // moved into the stream and pocesses a reciever to get incoming data, and a sender = outgoing_sender
    // to send to the sending thread
    let foward: AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)> =
        AsyncQuery::create(outgoing_sender.clone(), incoming_receiver);
    // store incoming sender
    println!("recv addr: {}", addr);
    in_sender.lock().await.insert(addr, incoming_sender);
    Ok((header, addr, foward, pubkeycomp))
}

impl<T: AsyncDataStream> ConnectionRequest for AsyncRequest<T> {
    type Error = NetworkError;
    type NetStream = T;
    fn new(stream: Self::NetStream, pubkey: PubKeyComp) -> Self {
        Self { stream, pubkey }
    }
    fn verify<L: PeerList>(self, list: &L) -> Result<Self::NetStream, Self::Error> {
        // public key should be sent in first packet

        if list.verify_peer(&self.pubkey) {
            Ok(self.stream)
        } else {
            Err(NetworkError::ConnectionDenied(
                "verification of peer failed".to_string(),
            ))
        }
    }
    unsafe fn unverify(self) -> Self::NetStream {
        self.stream
    }
}

// ==========================================================================
//                          Split type for Sllp Stream
// ==========================================================================

#[derive(Debug)]
pub struct OwnedSllpReceiver {
    header: StreamHeader,
    receiver: Receiver<IncomingMsg>,
}
impl OwnedSllpReceiver {
    pub fn new(header: StreamHeader, receiver: Receiver<IncomingMsg>) -> Self {
        Self { header, receiver }
    }
}
#[async_trait]
impl AsyncRecv for OwnedSllpReceiver {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<Vec<usize>, NetworkError> {
        let (mut data, data_len) = match self.receiver.recv().await {
            Some(result) => result,
            None => {
                return Err(NetworkError::IOError(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "channel closed",
                )))
            }
        };
        let (dec_data, header, indexes) = sym_aes_decrypt(&self.header, &mut data[0..data_len])?;
        if header.checksum() != self.header.checksum() {
            return Err(NetworkError::ConnectionDenied(
                "potential man in the middle attack".to_string(),
            ));
        }
        outbuf.extend_from_slice(&dec_data);
        Ok(indexes)
    }
    fn header(&self) -> &StreamHeader {
        &self.header
    }
}

/// send half of SllpStream
#[derive(Debug)]
pub struct SllpReceiver<'a> {
    header: &'a StreamHeader,
    receiver: &'a mut Receiver<IncomingMsg>,
}

impl<'a> SllpReceiver<'a> {
    pub fn new(header: &'a StreamHeader, receiver: &'a mut Receiver<IncomingMsg>) -> Self {
        Self { header, receiver }
    }
}
#[async_trait]
impl<'a> AsyncRecv for SllpReceiver<'a> {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<Vec<usize>, NetworkError> {
        let (mut data, data_len) = match self.receiver.recv().await {
            Some(result) => result,
            None => {
                return Err(NetworkError::IOError(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "channel closed",
                )))
            }
        };
        let (dec_data, header, indexes) = sym_aes_decrypt(&self.header, &mut data[0..data_len])?;
        if self.header.checksum() != header.checksum() {
            return Err(NetworkError::ConnectionDenied(String::from(
                "header's don't match",
            )));
        }
        outbuf.extend_from_slice(&dec_data);
        Ok(indexes)
    }
    fn header(&self) -> &StreamHeader {
        self.header
    }
}
/// owned half of SllpSender
#[derive(Debug, Clone)]
pub struct OwnedSllpSender {
    header: StreamHeader,
    remote_addr: SocketAddr,
    sender: Sender<OutgoingMsg>,
}
impl OwnedSllpSender {
    pub fn new(header: StreamHeader, remote_addr: SocketAddr, sender: Sender<OutgoingMsg>) -> Self {
        Self {
            header,
            remote_addr,
            sender,
        }
    }
}
#[async_trait]
impl AsyncSend for OwnedSllpSender {
    type SendError = NetworkError;
    async fn send(&mut self, inbuf: &[u8]) -> Result<usize, NetworkError> {
        self.sender
            .send((sym_aes_encrypt(&self.header, inbuf), self.remote_addr))
            .await?;
        Ok(inbuf.len())
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
}

/// send half of SllpStream
#[derive(Debug)]
pub struct SllpSender<'a> {
    header: &'a StreamHeader,
    remote_addr: SocketAddr,
    sender: &'a mut Sender<OutgoingMsg>,
}
impl<'a> SllpSender<'a> {
    pub fn new(
        header: &'a StreamHeader,
        remote_addr: SocketAddr,
        sender: &'a mut Sender<OutgoingMsg>,
    ) -> Self {
        Self {
            header,
            remote_addr,
            sender,
        }
    }
}
#[async_trait]
impl<'a> AsyncSend for SllpSender<'a> {
    type SendError = NetworkError;
    async fn send(&mut self, inbuf: &[u8]) -> Result<usize, NetworkError> {
        self.sender
            .send((sym_aes_encrypt(&self.header, inbuf), self.remote_addr))
            .await?;
        Ok(inbuf.len())
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
}

/// this represents a UDP connection to a peer.
/// while that may seem oxymoronic, in practice, implementing a structure this way allows for a finer grain of
/// what data transfer methods are nessisary, as this crate implements high security, an increase in efficiency wouldn't rely on
/// lack of connection, instead, the connection is maintained, and the efficiency gain comes from the lack of packet ordering,
/// and extraneous network transmissions

// ==========================================================================
//                                 Sllp Stream
// ===========================================================================
#[derive(Debug)]
pub struct SllpStream {
    header: StreamHeader,
    query: AsyncQuery<OutgoingMsg, IncomingMsg>,
    remote_addr: SocketAddr,
}
#[async_trait]
impl AsyncSend for SllpStream {
    type SendError = NetworkError;
    async fn send(&mut self, inbuf: &[u8]) -> Result<usize, NetworkError> {
        self.query
            .send((sym_aes_encrypt(&self.header, inbuf), self.remote_addr))
            .await?;
        Ok(inbuf.len())
    }
    fn remote_addr(&self) -> &SocketAddr {
        &self.remote_addr
    }
}
#[async_trait]
impl AsyncRecv for SllpStream {
    type RecvError = NetworkError;
    async fn recv(&mut self, outbuf: &mut Vec<u8>) -> Result<Vec<usize>, NetworkError> {
        let (mut data, data_len) = match self.query.recv().await {
            Some(result) => result,
            None => {
                return Err(NetworkError::IOError(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "channel closed",
                )))
            }
        };
        let (dec_data, header, indexes) = sym_aes_decrypt(&self.header, &mut data[0..data_len])?;
        if header.checksum() != self.header.checksum() {
            return Err(NetworkError::ConnectionDenied(
                "potential man in the middle attack".to_string(),
            ));
        }
        outbuf.extend_from_slice(&dec_data);
        Ok(indexes)
    }
    fn header(&self) -> &StreamHeader {
        &self.header
    }
}
impl SllpStream {
    /// reverse of into_split
    pub fn reform(send: OwnedSllpSender, recv: OwnedSllpReceiver) -> Self {
        let header = recv.header;
        let receiver = recv.receiver;
        let sender = send.sender;
        let remote_addr = send.remote_addr;
        let query = AsyncQuery::create(sender, receiver);
        Self {
            header,
            query,
            remote_addr,
        }
    }
    pub fn split(&mut self) -> (SllpSender<'_>, SllpReceiver<'_>) {
        let (sender, receiver) = self.query.split();
        (
            SllpSender::new(&self.header, self.remote_addr, sender),
            SllpReceiver::new(&self.header, receiver),
        )
    }
    pub fn into_split(self) -> (OwnedSllpSender, OwnedSllpReceiver) {
        let (sender, receiver) = self.query.into_split();
        (
            OwnedSllpSender::new(self.header.clone(), self.remote_addr, sender),
            OwnedSllpReceiver::new(self.header, receiver),
        )
    }
}
impl AsyncDataStream for SllpStream {
    type NetStream = AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)>;
    type StreamError = NetworkError;
    fn new(
        query: AsyncQuery<(Vec<u8>, SocketAddr), (Vec<u8>, usize)>,
        header: StreamHeader,
        remote_addr: SocketAddr,
    ) -> Result<Self, NetworkError> {
        Ok(Self {
            header,
            query,
            remote_addr,
        })
    }
}
// ===================================================================================
//                             Convenience types
// ===================================================================================
/// messages sent from the socket to the main program use this format
pub type IncomingMsg = (Vec<u8>, usize);
/// messages sent from main to the socket use this format
pub type OutgoingMsg = (Vec<u8>, SocketAddr);

pub type NewConnection = Result<
    (
        StreamHeader,
        SocketAddr,
        AsyncQuery<OutgoingMsg, IncomingMsg>,
        PubKeyComp
    ),
    NetworkError,
>;
/// a type alias, more or less for Arc<Mutex<HashMap<SocketAddr, Sender<IncomingMsg>>>>
#[derive(Debug, Clone)]
pub struct Streams {
    value: Arc<Mutex<HashMap<SocketAddr, Sender<IncomingMsg>>>>,
}
impl Streams {
    pub async fn lock(&self) -> MutexGuard<'_, HashMap<SocketAddr, Sender<IncomingMsg>>> {
        self.value.lock().await
    }
}
impl Default for Streams {
    fn default() -> Self {
        let value = Arc::new(Mutex::new(HashMap::new()));
        Self { value }
    }
}
// =================================================================
//               Split Types for SLLP Socket
// ==================================================================
#[derive(Debug)]
pub struct OwnedIncoming {
    streams: Streams,
    priv_key: RSAPrivateKey,
    receiver: Receiver<NewConnection>,
}
impl OwnedIncoming {
    pub fn new(
        streams: Streams,
        priv_key: RSAPrivateKey,
        receiver: Receiver<NewConnection>,
    ) -> Self {
        Self {
            streams,
            priv_key,
            receiver,
        }
    }
    pub fn incoming(&mut self) -> &mut Self {
        self
    }
}
impl Stream for OwnedIncoming {
    type Item = Result<AsyncRequest<SllpStream>, NetworkError>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        incoming_conn(&mut self.receiver, ctx)
    }
}
impl Future for OwnedIncoming {
    type Output = Option<Result<AsyncRequest<SllpStream>, NetworkError>>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.poll_next(ctx) {
            Poll::Ready(val) => Poll::Ready(val),
            Poll::Pending => Poll::Pending,
        }
    }
}
/// incoming half of SllpSocket allows for listening for new connections but not opening new connections
#[derive(Debug)]
pub struct SllpIncoming<'a> {
    priv_key: &'a RSAPrivateKey,
    receiver: &'a mut Receiver<NewConnection>,
}
impl<'a> SllpIncoming<'a> {
    pub fn new(priv_key: &'a RSAPrivateKey, receiver: &'a mut Receiver<NewConnection>) -> Self {
        Self { priv_key, receiver }
    }
}
impl<'a> Stream for SllpIncoming<'a> {
    type Item = Result<AsyncRequest<SllpStream>, NetworkError>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        incoming_conn(&mut self.receiver, ctx)
    }
}
impl<'a> Future for SllpIncoming<'a> {
    type Output = Option<Result<AsyncRequest<SllpStream>, NetworkError>>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.poll_next(ctx) {
            Poll::Ready(val) => Poll::Ready(val),
            Poll::Pending => Poll::Pending,
        }
    }
}
#[derive(Debug, Clone)]
pub struct OwnedOutgoing {
    streams: Streams,
    priv_key: RSAPrivateKey,
    outgoing_sender: Sender<OutgoingMsg>,
    addr: SocketAddr,
}
impl OwnedOutgoing {
    pub fn new(
        streams: Streams,
        priv_key: RSAPrivateKey,
        outgoing_sender: Sender<OutgoingMsg>,
        addr: SocketAddr,
    ) -> Self {
        Self {
            streams,
            priv_key,
            outgoing_sender,
            addr,
        }
    }
    pub async fn connect(&self, peer: &RemotePeer) -> Result<SllpStream, NetworkError> {
        let (incoming_sender, incoming_receiver) = channel(1);
        let query = AsyncQuery::create(self.outgoing_sender.clone(), incoming_receiver);
        let key = random_string(16).into_bytes();
        let header: StreamHeader = StreamHeader::with_key(key, 0);

        handshake(&header, &peer, &self.priv_key, self.addr).await?;

        let stream = SllpStream::new(query, header, peer.socket_addr());
        self.streams
            .lock()
            .await
            .insert(peer.socket_addr(), incoming_sender);
        Ok(stream?)
    }
}
/// outgoing half of SllpSocket allows for opening connections, but not listening for new ones
#[derive(Debug, Clone)]
pub struct SllpOutgoing<'a> {
    streams: &'a Streams,
    priv_key: &'a RSAPrivateKey,
    outgoing_sender: &'a Sender<OutgoingMsg>,
    addr: SocketAddr,
}
impl<'a> SllpOutgoing<'a> {
    /// could've been private, but functionality and transparency are important
    pub fn new(
        streams: &'a Streams,
        priv_key: &'a RSAPrivateKey,
        outgoing_sender: &'a Sender<OutgoingMsg>,
        addr: SocketAddr,
    ) -> Self {
        Self {
            streams,
            priv_key,
            outgoing_sender,
            addr,
        }
    }
    /// same as SllpSocket, couldn't find an easy way of putting it in a trait
    pub async fn connect(&self, peer: &RemotePeer) -> Result<SllpStream, NetworkError> {
        let (incoming_sender, incoming_receiver) = channel(1);
        let query = AsyncQuery::create(self.outgoing_sender.clone(), incoming_receiver);
        let key = random_string(16).into_bytes();
        let header: StreamHeader = StreamHeader::with_key(key, 0);

        handshake(&header, peer, &self.priv_key, self.addr).await?;

        let stream = SllpStream::new(query, header, peer.socket_addr());
        self.streams
            .lock()
            .await
            .insert(peer.socket_addr(), incoming_sender);
        Ok(stream?)
    }
}

// =====================================================================
//                          SLLP Socket
// =====================================================================
/// this structure provides an alternative to TCP Networking, but is not connectionless
/// while this structure uses an owned UdpSocket for networking, it also maintains a connection through the standard means that this crate provides
/// this is offered as a way to increase the efficiency of the network of TCP at the cost of a lack of garuntee of packet order
/// future implementations may implement a system of dropping out dated packets
#[derive(Debug)]
pub struct SllpSocket {
    priv_key: RSAPrivateKey,
    receiver: Receiver<NewConnection>,
    streams: Streams,
    outgoing_sender: Sender<OutgoingMsg>,
    addr: SocketAddr,
    client_only: bool,
}
#[async_trait]
impl AsyncNetworkHost for SllpSocket {
    type Error = NetworkError;
    async fn from_host_config(config: &ArtificeConfig) -> Result<Self, NetworkError> {
        Self::initialize(config, false).await
    }
}
impl SllpSocket {
    pub async fn client_only(config: &ArtificeConfig) -> Result<Self, NetworkError> {
        Self::initialize(config, true).await
    }
    async fn initialize(config: &ArtificeConfig, client_only: bool) -> Result<Self, NetworkError> {
        let data = config.host_data();
        let priv_key_comp = data.privkeycomp();
        let socket_addr: SocketAddr = config.socket_addr().into();
        println!("socket addr: {}", socket_addr);
        let priv_key: RSAPrivateKey = priv_key_comp.into();
        // centralized udp socket, that data is routed through
        let socket = UdpSocket::bind(socket_addr).await?;
        let (mut request_sender, request_receiver): (
            Sender<NewConnection>,
            Receiver<NewConnection>,
        ) = channel(200);
        let (outgoing_sender, mut outgoing_receiver): (
            Sender<OutgoingMsg>,
            Receiver<(Vec<u8>, SocketAddr)>,
        ) = channel(200);
        let senders: Streams = Streams::default();
        let (mut recv_half, mut send_half) = socket.split();
        // spawn incoming
        let streams = senders.clone();
        let out_sender = outgoing_sender.clone();
        tokio::spawn(async move {
            loop {
                let mut buffer: [u8; 65535] = [0; 65535];
                match recv_half.recv_from(&mut buffer).await {
                    Ok((data_len, addr)) => {
                        //println!("got message for: {}", addr);
                        let mut senders = streams.lock().await;
                        // check if they are authorized, but if someone tries to spoof
                        // IP it wo't matter because of encryption they will get garbage.
                        if let Some(sender) = senders.get_mut(&addr) {
                            sender
                                .send((buffer[0..data_len].to_vec(), data_len))
                                .await
                                .unwrap();
                        }
                    }
                    Err(e) => panic!("error: {}", e),
                }
            }
        });
        // spawn outgoing
        tokio::spawn(async move {
            loop {
                let (out_data, remote_addr) = outgoing_receiver.recv().await.unwrap();
                send_half.send_to(&out_data, &remote_addr).await.unwrap();
            }
        });
        if !client_only {
            // spawn tcp listener to wait for incoming connections
            let mut listener = TcpListener::bind("0.0.0.0:6432").await?;
            let in_priv_key = priv_key.clone();
            let in_senders = senders.clone();
            // checks for new incoming connections
            // note connections must be initiated by using a tcp stream
            tokio::spawn(async move {
                loop {
                    request_sender
                        .send(
                            recv_incoming(
                                &mut listener,
                                &in_priv_key,
                                &in_senders,
                                &outgoing_sender,
                            )
                            .await,
                        )
                        .await
                        .unwrap();
                }
            });
        }

        Ok(Self {
            priv_key,
            receiver: request_receiver,
            streams: senders,
            outgoing_sender: out_sender,
            addr: socket_addr,
            client_only,
        })
    }
    pub async fn connect(&self, peer: &RemotePeer) -> Result<SllpStream, NetworkError> {
        let (incoming_sender, incoming_receiver) = channel(1);
        let query = AsyncQuery::create(self.outgoing_sender.clone(), incoming_receiver);
        let key = random_string(16).into_bytes();
        let header: StreamHeader = StreamHeader::with_key(key, 0);
        handshake(&header, peer, &self.priv_key, self.addr).await?;

        let stream = SllpStream::new(query, header, peer.socket_addr());
        self.streams
            .lock()
            .await
            .insert(peer.socket_addr(), incoming_sender);
        Ok(stream?)
    }
    pub fn split(&mut self) -> Result<(SllpOutgoing<'_>, SllpIncoming<'_>), NetworkError> {
        if self.client_only {
            return Err(NetworkError::UnSet("client only".to_string()));
        }
        Ok((
            SllpOutgoing::new(
                &self.streams,
                &self.priv_key,
                &self.outgoing_sender,
                self.addr,
            ),
            SllpIncoming::new(&self.priv_key, &mut self.receiver),
        ))
    }
    pub fn into_split(self) -> Result<(OwnedOutgoing, OwnedIncoming), NetworkError> {
        if self.client_only {
            return Err(NetworkError::UnSet("client only".to_string()));
        }
        Ok((
            OwnedOutgoing::new(
                self.streams.clone(),
                self.priv_key.clone(),
                self.outgoing_sender,
                self.addr,
            ),
            OwnedIncoming::new(self.streams, self.priv_key, self.receiver),
        ))
    }
    pub fn incoming(&mut self) -> &mut Self {
        self
    }
}
impl Stream for SllpSocket {
    type Item = Result<AsyncRequest<SllpStream>, NetworkError>;
    fn poll_next(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        incoming_conn(&mut self.receiver, ctx)
    }
}
impl Future for SllpSocket {
    type Output = Option<Result<AsyncRequest<SllpStream>, NetworkError>>;
    fn poll(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.poll_next(ctx) {
            Poll::Ready(val) => Poll::Ready(val),
            Poll::Pending => Poll::Pending,
        }
    }
}
