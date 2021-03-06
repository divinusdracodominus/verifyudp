use verifyudp::{AsyncNetworkHost, AsyncSend};
use verifyudp::utils::random_string;
use verifyudp::SllpSocket;
use verifyudp::L3Addr;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let (mut peer, mut config) = test_config();
    println!("peer addr: {}", peer.socket_addr());
    // update default addr because only one udp socket per addr
    config.set_socket_addr((L3Addr::newv4(0, 0, 0, 0), 3232).into());
    println!("about to create socket");
    let socket = SllpSocket::client_only(&config).await?;
    peer.set_socket_addr(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(192, 168, 2, 5)),
        6464,
    ));
    println!("created socket");
    let mut stream = socket.connect(&peer).await?;
    println!("entering loop");
    loop {
        stream.send(&random_string(65).into_bytes()).await.unwrap();
    }
}
