use verifyudp::{AsyncNetworkHost, AsyncRecv};
use verifyudp::SllpSocket;
use verifyudp::{ConnectionRequest};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    
    println!("config addr: {}", config.socket_addr());
    let mut socket = SllpSocket::from_host_config(&config).await?;
    while let Some(strm) = socket.incoming().await {
        let mut stream = strm?.verify(&peer)?;
        tokio::spawn(async move {
            println!("new connection");
            loop {
                let mut invec = Vec::new();
                stream.recv(&mut invec).await.unwrap();
                println!("got message {}", String::from_utf8(invec).unwrap());
            }
        });
    }
    Ok(())
}
