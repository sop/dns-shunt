use crate::{
    backend::{self, BackendError, CapturedPacket, FlowContext, InterceptionBackend},
    config::Config,
    packet,
};
use std::{
    ffi::CString,
    io,
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    os::windows::io::AsRawSocket,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use windivert::{address::WinDivertAddress, layer::NetworkLayer, packet::WinDivertPacket};
use windivert_sys::{
    ChecksumFlags, WinDivertClose, WinDivertFlags, WinDivertLayer, WinDivertOpen, WinDivertRecv,
    WinDivertSend, WinDivertShutdown, WinDivertShutdownMode,
};
use windows::Win32::Foundation::HANDLE;
use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET_ERROR, SOL_SOCKET, setsockopt,
};

// Largest IPv6 packet: 40-byte base header plus the 16-bit payload length.
const MAX_NETWORK_PACKET_SIZE: usize = 65_535 + 40;

struct CapturedAddress {
    address: WinDivertAddress<NetworkLayer>,
}

struct WinDivertBackend {
    driver: WinDivertDriver,
    shutdown_requested: AtomicBool,
    receive_buffer: Mutex<Vec<u8>>,
}

struct WinDivertDriver {
    handle: HANDLE,
}

// WinDivert supports multi-threaded send/receive and shutdown on the same handle.
unsafe impl Send for WinDivertDriver {}
unsafe impl Sync for WinDivertDriver {}

impl WinDivertDriver {
    fn open(filter: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let filter = CString::new(filter)?;
        let handle = unsafe {
            WinDivertOpen(
                filter.as_ptr(),
                WinDivertLayer::Network,
                0,
                WinDivertFlags::new(),
            )
        };
        if handle.is_invalid() {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self { handle })
    }

    fn recv(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, WinDivertAddress<NetworkLayer>), io::Error> {
        let mut address = unsafe { WinDivertAddress::<NetworkLayer>::new() };
        let mut received = 0;
        let result = unsafe {
            WinDivertRecv(
                self.handle,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut received,
                address.as_mut(),
            )
        };
        if !result.as_bool() {
            return Err(io::Error::last_os_error());
        }
        Ok((received as usize, address))
    }

    fn send(&self, packet: &WinDivertPacket<NetworkLayer>) -> Result<(), io::Error> {
        let mut sent = 0;
        let result = unsafe {
            WinDivertSend(
                self.handle,
                packet.data.as_ptr().cast(),
                packet.data.len() as u32,
                &mut sent,
                packet.address.as_ref(),
            )
        };
        if !result.as_bool() {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn shutdown_receive(&self) -> Result<(), io::Error> {
        let result = unsafe { WinDivertShutdown(self.handle, WinDivertShutdownMode::Recv) };
        if !result.as_bool() {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for WinDivertDriver {
    fn drop(&mut self) {
        unsafe {
            let _ = WinDivertClose(self.handle);
        }
    }
}

impl InterceptionBackend for WinDivertBackend {
    fn capture(&self) -> Result<CapturedPacket, BackendError> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(BackendError("capture stopped during shutdown".into()));
        }
        let mut receive_buffer = self
            .receive_buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let buffer_capacity = receive_buffer.len();
        let (packet_length, address) = self.driver.recv(&mut receive_buffer).map_err(|error| {
            BackendError(format!(
                "WinDivert receive failed with a {buffer_capacity}-byte buffer: {error}"
            ))
        })?;
        let bytes = receive_buffer[..packet_length].to_vec();
        let (tuple, dns_payload) = match packet::parse_ipv4_udp(&bytes) {
            Ok((tuple, payload)) if tuple.destination_port == 53 => {
                (Some(tuple), Some(payload.to_vec()))
            }
            _ => (None, None),
        };
        let metadata = CapturedAddress { address };
        Ok(CapturedPacket {
            context: FlowContext {
                tuple,
                original_packet: bytes,
                backend_data: Arc::new(metadata),
            },
            dns_payload,
        })
    }

    fn inject_response(
        &self,
        context: &FlowContext,
        dns_payload: &[u8],
    ) -> Result<(), BackendError> {
        let tuple = context
            .tuple
            .ok_or_else(|| BackendError("response context has no IPv4/UDP tuple".into()))?;
        let response = packet::build_ipv4_udp(packet::response_tuple(tuple), dns_payload)
            .map_err(|error| BackendError(error.to_string()))?;
        let captured = context
            .backend_data
            .downcast_ref::<CapturedAddress>()
            .ok_or_else(|| BackendError("invalid WinDivert packet context".into()))?;
        let mut injected = unsafe { WinDivertPacket::<NetworkLayer>::new(response) };
        injected.address = captured.address.clone();
        injected.address.set_outbound(false);
        injected.address.set_impostor(true);
        injected
            .recalculate_checksums(ChecksumFlags::new())
            .map_err(|error| BackendError(error.to_string()))?;
        self.driver
            .send(&injected)
            .map_err(|error| BackendError(error.to_string()))?;
        Ok(())
    }

    fn reinject_original(&self, context: &FlowContext) -> Result<(), BackendError> {
        let captured = context
            .backend_data
            .downcast_ref::<CapturedAddress>()
            .ok_or_else(|| BackendError("invalid WinDivert packet context".into()))?;
        let mut packet =
            unsafe { WinDivertPacket::<NetworkLayer>::new(context.original_packet.clone()) };
        packet.address = captured.address.clone();
        self.driver
            .send(&packet)
            .map_err(|error| BackendError(error.to_string()))?;
        Ok(())
    }

    fn request_shutdown(&self) {
        if self.shutdown_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Err(error) = self.driver.shutdown_receive() {
            eprintln!("could not shut down WinDivert receive: {error}");
        }
    }
}

pub fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_socket = bind_exclusive(config.source_port)?;
    let filter = format!(
        "outbound and !loopback and ip and udp and udp.DstPort == 53 and udp.SrcPort != {} and ip.MF == 0 and ip.FragOff == 0",
        config.source_port
    );
    let driver = WinDivertDriver::open(&filter)?;
    println!("WinDivert capture active; Ctrl+C stops the foreground prototype");
    backend::run_proxy(
        Arc::new(WinDivertBackend {
            driver,
            shutdown_requested: AtomicBool::new(false),
            receive_buffer: Mutex::new(vec![0; MAX_NETWORK_PACKET_SIZE]),
        }),
        config,
        upstream_socket,
    )
}

fn bind_exclusive(port: u16) -> io::Result<UdpSocket> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::FlowTuple;

    #[test]
    fn filter_is_outbound_only_and_excludes_proxy_source_port() {
        let filter = format!(
            "outbound and !loopback and ip and udp and udp.DstPort == 53 and udp.SrcPort != {} and ip.MF == 0 and ip.FragOff == 0",
            53053
        );
        assert!(filter.starts_with("outbound"));
        assert!(filter.contains("udp.SrcPort != 53053"));
        assert!(!filter.contains("inbound"));
    }

    #[test]
    fn response_source_matches_original_dns_server() {
        let query = FlowTuple {
            source: Ipv4Addr::new(192, 0, 2, 11),
            source_port: 12345,
            destination: Ipv4Addr::new(192, 0, 2, 53),
            destination_port: 53,
        };
        let reversed = packet::response_tuple(query);
        assert_eq!(reversed.source, query.destination);
        assert_eq!(reversed.destination, query.source);
        assert_eq!(
            (reversed.source_port, reversed.destination_port),
            (53, 12345)
        );
    }
}
