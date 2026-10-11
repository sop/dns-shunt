use std::{
    io,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    os::windows::io::AsRawSocket,
};
use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, setsockopt,
};

pub fn bind_exclusive(port: u16) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    let exclusive: i32 = 1;
    let result = unsafe {
        setsockopt(
            socket.as_raw_socket() as usize,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&exclusive as *const i32).cast(),
            size_of::<i32>() as i32,
        )
    };
    if result == SOCKET_ERROR {
        return Err(io::Error::last_os_error());
    }
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into())?;
    Ok(socket.into())
}
