use crate::random_string;
use crate::{NetworkError};
use crate::netcore::*;
use crate::encryption::*;

use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use std::net::SocketAddr;
//use std::convert::TryFrom;

#[derive(
    FromPrimitive,
    ToPrimitive,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Clone,
    Copy,
)]
pub enum PacketType {
    RawData = 0,
    RawDataAck = 1,
    Admin = 2,
    AdminAck = 3,
}
impl Default for PacketType {
    fn default() -> Self {
        Self::RawData
    }
}

pub struct RemotePeer {
    addr: SocketAddr,
    pubkey: rsa::RSAPublicKey,
}

impl RemotePeer {
    pub fn new(addr: L4Addr, pubkey: PubKeyComp) -> Self {
        Self {
            addr: addr.into(),
            pubkey: pubkey.into(),
        }
    }
    pub fn socket_addr(&self) -> SocketAddr {
        self.addr
    }
}

use std::convert::TryInto;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct StreamHeader {
    /// this exists for legacy reasons
    checksum: [u8;32],
    aes_key: Vec<u8>,
    packet_len: usize,
    packet_type: PacketType,
    remander: u8,
}
impl StreamHeader {
    pub fn new(packet_len: usize) -> Self {
        let aes_key: Vec<u8> = random_string(16).into_bytes();
        Self::with_key(aes_key, packet_len)
    }
    pub fn with_key(
        aes_key: Vec<u8>,
        packet_len: usize,
    ) -> Self {
        let checksum = [0;32];
        Self {
            checksum,
            aes_key,
            packet_len,
            packet_type: PacketType::RawData,
            remander: 0,
        }
    }
    pub fn set_packet_type(&mut self, packet_type: PacketType) {
        self.packet_type = packet_type;
    }
    pub fn packet_type(&self) -> PacketType {
        self.packet_type
    }
    pub fn key(&self) -> &[u8] {
        &self.aes_key
    }
    pub fn packet_len(&self) -> usize {
        self.packet_len
    }
    pub fn data_len(&self) -> usize {
        self.packet_len
    }
    pub fn set_packet_len(&mut self, packet_len: usize) {
        self.packet_len = packet_len;
    }
    /// remander is calculated by 128 - (packet_len % 128) to break into encryptable blocks for async
    /// for sync calculated based on 16 - (packet_len % 128)
    pub fn remander(&self) -> u8 {
        self.remander
    }
    pub fn set_remander(&mut self, remander: u8) {
        self.remander = remander;
    }
    /// used in place of serde_json::to_string(), because serde_json generates un-needed data
    pub fn to_raw(&self) -> Vec<u8> {
        let mut outvec: Vec<u8> = Vec::with_capacity(58);
        outvec.extend_from_slice(&self.checksum);
        outvec.extend_from_slice(&self.aes_key);
        outvec.extend_from_slice(&self.packet_len.to_be_bytes());
        outvec.push(self.remander);
        outvec.push(self.packet_type.to_u8().unwrap_or_default());
        outvec
    }
    pub fn to_raw_padded(&self) -> Vec<u8> {
        let mut vec = self.to_raw();
        let mut rem_vec = Vec::with_capacity(71);
        unsafe { rem_vec.set_len(71) };
        vec.extend_from_slice(&rem_vec);
        vec
    }
    pub fn from_raw_padded(data: &[u8]) -> Result<Self, NetworkError> {
        Self::from_raw(&data[0..58])
    }
    /// convert 125 bytes (length of data) to StreamHeader
    pub fn from_raw(data: &[u8]) -> Result<Self, NetworkError> {
        assert_eq!(data.len(), 58);
        let checksum = data[0..32].try_into().unwrap();
        let aes_key = data[32..48].to_vec();
        let packet_len = usize::from_be_bytes(data[48..56].try_into()?);
        let remander = data[56];
        let packet_type = FromPrimitive::from_u8(data[57]).unwrap_or_default();
        Ok(Self {
            checksum,
            aes_key,
            packet_len,
            remander,
            packet_type,
        })
    }
    pub fn checksum(&self) -> &[u8] {
        &self.checksum
    }
}