use crate::{
    backend::{self, BackendError, CapturedPacket, FlowContext, InterceptionBackend},
    config::Config,
    packet,
};
use std::{
    ffi::CString,
    io,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use windivert::{address::WinDivertAddress, layer::NetworkLayer, packet::WinDivertPacket};
use windivert_sys::{
    ChecksumFlags, WinDivertClose, WinDivertFlags, WinDivertLayer, WinDivertOpen, WinDivertRecv,
    WinDivertSend, WinDivertShutdown, WinDivertShutdownMode,
};
use windows::Win32::Foundation::HANDLE;

// Largest IPv6 packet: 40-byte base header plus the 16-bit payload length.
const MAX_NETWORK_PACKET_SIZE: usize = 65_535 + 40;

struct CapturedAddress {
    address: WinDivertAddress<NetworkLayer>,
    original_packet: Vec<u8>,
    tuple: Option<packet::FlowTuple>,
    terminal: Mutex<bool>,
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
        let metadata = CapturedAddress {
            address,
            original_packet: bytes,
            tuple,
            terminal: Mutex::new(false),
        };
        Ok(CapturedPacket {
            context: FlowContext {
                tuple,
                backend_context: Arc::new(metadata),
            },
            dns_payload,
        })
    }

    fn inject_response(
        &self,
        context: &FlowContext,
        dns_payload: &[u8],
    ) -> Result<(), BackendError> {
        let captured = validated_context(context)?;
        let tuple = context
            .tuple
            .ok_or_else(|| BackendError("response context has no IPv4/UDP tuple".into()))?;
        let response = packet::build_ipv4_udp(packet::response_tuple(tuple), dns_payload)
            .map_err(|error| BackendError(error.to_string()))?;
        let mut terminal = begin_terminal(&captured.terminal)?;
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
        *terminal = true;
        Ok(())
    }

    fn reinject_original(&self, context: &FlowContext) -> Result<(), BackendError> {
        let captured = validated_context(context)?;
        let mut terminal = begin_terminal(&captured.terminal)?;
        let mut packet =
            unsafe { WinDivertPacket::<NetworkLayer>::new(captured.original_packet.clone()) };
        packet.address = captured.address.clone();
        self.driver
            .send(&packet)
            .map_err(|error| BackendError(error.to_string()))?;
        *terminal = true;
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

fn validated_context(context: &FlowContext) -> Result<&CapturedAddress, BackendError> {
    let captured = context
        .backend_context
        .downcast_ref::<CapturedAddress>()
        .ok_or_else(|| BackendError("invalid WinDivert packet context".into()))?;
    if context.tuple != captured.tuple {
        return Err(BackendError(
            "WinDivert packet tuple does not match context".into(),
        ));
    }
    Ok(captured)
}

fn begin_terminal(terminal: &Mutex<bool>) -> Result<MutexGuard<'_, bool>, BackendError> {
    let state = terminal
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *state {
        return Err(BackendError(
            "WinDivert packet context already resolved".into(),
        ));
    }
    Ok(state)
}

pub fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let upstream_socket = crate::upstream_socket::bind_exclusive(config.source_port)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::FlowTuple;
    use std::net::Ipv4Addr;

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

    #[test]
    fn validates_private_packet_context_and_prevents_duplicate_resolution() {
        let tuple = FlowTuple {
            source: Ipv4Addr::new(192, 0, 2, 11),
            source_port: 12345,
            destination: Ipv4Addr::new(192, 0, 2, 53),
            destination_port: 53,
        };
        let captured = CapturedAddress {
            address: unsafe { WinDivertAddress::<NetworkLayer>::new() },
            original_packet: vec![1, 2, 3],
            tuple: Some(tuple),
            terminal: Mutex::new(false),
        };
        let context = FlowContext {
            tuple: Some(tuple),
            backend_context: Arc::new(captured),
        };
        let metadata = validated_context(&context).unwrap();
        *begin_terminal(&metadata.terminal).unwrap() = true;
        assert!(begin_terminal(&metadata.terminal).is_err());

        let invalid_context = FlowContext {
            tuple: None,
            backend_context: Arc::new(()),
        };
        assert!(validated_context(&invalid_context).is_err());
    }
}
