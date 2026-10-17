use super::*;
use carrier::datagram::DatagramRoute;
use nestlink_node::service_plane::{DatagramMapping, DatagramPacket, PreparedLocalTunnel};
use tokio::io::AsyncReadExt;

pub(super) async fn forward(
    prepared: PreparedLocalTunnel,
    mut control: BiStream,
    context: ForwardContext,
    mut packets: DatagramRoute,
) -> Result<(), SdkError> {
    let mapping = DatagramMapping::new(prepared).await?;
    let maximum_age = tokio::time::sleep(Duration::from_secs(60));
    tokio::pin!(maximum_age);
    loop {
        let mut unexpected = [0];
        tokio::select! {biased;
            _=mapping.wait_stopped()=>return Ok(()),
            _=&mut maximum_age=>return Ok(()),
            _=context.connection.closed()=>return Ok(()),
            _=AsyncReadExt::read(&mut control,&mut unexpected)=>return Ok(()),
            packet=packets.receive()=>{
                let Some(packet)=packet else{return Ok(())};
                let Ok(packet)=DatagramPacket::decode(&packet) else{continue;};
                let _=mapping.send_packet(&packet).await;
            },
            reply=mapping.receive_reply()=>{
                let Ok(reply)=reply else{continue;};
                let _=carrier::datagram::send(&context.connection,reply.encode()?);
            },
        }
    }
}
