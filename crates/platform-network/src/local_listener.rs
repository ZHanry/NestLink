//! Windows loopback sockets reserve their endpoint before being exposed to a
//! local client. Default Winsock bind semantics allow SO_REUSEADDR takeover.
//! Socket2 owns creation/I/O conversion; this is only the missing socket option.
#![allow(unsafe_code)]
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::{SocketAddr, TcpListener, UdpSocket},
    os::windows::io::AsRawSocket,
};
use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, WSAGetLastError, setsockopt,
};

fn exclusive(endpoint: SocketAddr, kind: Type, protocol: Protocol) -> io::Result<Socket> {
    if !endpoint.ip().is_loopback() {
        return Err(io::Error::other(
            "exclusive local entry requires a loopback endpoint",
        ));
    }
    let socket = Socket::new(Domain::for_address(endpoint), kind, Some(protocol))?;
    let enabled = 1i32;
    // SAFETY: Socket2 owns this live Winsock socket. The option reads exactly
    // one live i32; its borrowed address does not escape this synchronous call.
    if unsafe {
        setsockopt(
            socket.as_raw_socket(),
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&enabled as *const i32).cast(),
            std::mem::size_of::<i32>() as i32,
        )
    } == SOCKET_ERROR
    {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }));
    }
    socket.set_nonblocking(true)?;
    socket.bind(&endpoint.into())?;
    Ok(socket)
}
pub fn tcp(endpoint: SocketAddr) -> io::Result<TcpListener> {
    let socket = exclusive(endpoint, Type::STREAM, Protocol::TCP)?;
    socket.listen(128)?;
    Ok(socket.into())
}
pub fn udp(endpoint: SocketAddr) -> io::Result<UdpSocket> {
    Ok(exclusive(endpoint, Type::DGRAM, Protocol::UDP)?.into())
}
