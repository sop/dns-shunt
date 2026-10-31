use crate::{
    backend::{self, BackendError, CapturedPacket, FlowContext, InterceptionBackend},
    config::Config,
    interfaces::SystemInterfaceProvider,
    mdns_scheduler::RandomJitter,
    packet,
};
use std::{
    ffi::CString,
    io,
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
use windows_048::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};

// Largest IPv6 packet: 40-byte base header plus the 16-bit payload length.
const MAX_NETWORK_PACKET_SIZE: usize = 65_535 + 40;
const WIN_DIVERT_FILTER: &str = concat!(
    "!impostor and !loopback and (",
    "(outbound and ip and udp and udp.DstPort == 53 and ip.MF == 0 and ip.FragOff == 0) or ",
    "(outbound and udp and udp.DstPort == 5353 and ",
    "((ip and ip.DstAddr == 224.0.0.251) or (ipv6 and ipv6.DstAddr == ff02::fb))) or ",
    "(inbound and udp and udp.SrcPort == 5353)",
    ")"
);

enum ContextState {
    SingleTerminal {
        resolved: bool,
    },
    MdnsQuery {
        forwarded: bool,
        qm_sent: bool,
        qu_sent: bool,
    },
}

struct CapturedAddress {
    address: WinDivertAddress<NetworkLayer>,
    tuple: Option<packet::FlowTuple>,
    state: Arc<Mutex<ContextState>>,
}

struct WinDivertBackend {
    driver: WinDivertDriver,
    shutdown_requested: AtomicBool,
    receive_buffer: Mutex<Vec<u8>>,
}

struct WinDivertDriver {
    handle: HANDLE,
}

// WinDivert supports multi-threaded send/receive and shutdown on the same
// handle.
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
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        tracing::info!("opened WinDivert handle");
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
        tracing::info!("shutting down WinDivert receive");
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
                concat!("WinDivert receive failed with a ", "{}-byte buffer: {}"),
                buffer_capacity, error
            ))
        })?;
        let bytes = receive_buffer[..packet_length].to_vec();
        let parsed = packet::parse_packet_range(&bytes);
        let if_index = address.interface_index();
        let outbound = address.outbound();

        let (tuple, dns_payload, ip_ttl, kind) = match parsed {
            Ok(parsed) => {
                let kind = if outbound {
                    if parsed.tuple.destination_port == 53 && parsed.tuple.is_ipv4() {
                        backend::PacketKind::UnicastDns
                    } else if parsed.tuple.destination_port == 5353 {
                        let is_mdns_dst = match parsed.tuple.destination {
                            std::net::IpAddr::V4(v4) => v4 == crate::mdns::MDNS_IPV4_ADDR,
                            std::net::IpAddr::V6(v6) => v6 == crate::mdns::MDNS_IPV6_ADDR,
                        };
                        if is_mdns_dst {
                            backend::PacketKind::OutboundMdnsQuery
                        } else {
                            backend::PacketKind::Other
                        }
                    } else {
                        backend::PacketKind::Other
                    }
                } else if parsed.tuple.source_port == 5353 {
                    backend::PacketKind::InboundMdnsObserver
                } else {
                    backend::PacketKind::Other
                };
                (
                    Some(parsed.tuple),
                    Some(parsed.payload_range),
                    parsed.ip_ttl,
                    kind,
                )
            }
            Err(_) => (None, None, 0, backend::PacketKind::Other),
        };

        let state = match kind {
            backend::PacketKind::UnicastDns
            | backend::PacketKind::InboundMdnsObserver
            | backend::PacketKind::Other => {
                Arc::new(Mutex::new(ContextState::SingleTerminal { resolved: false }))
            }
            backend::PacketKind::OutboundMdnsQuery => {
                Arc::new(Mutex::new(ContextState::MdnsQuery {
                    forwarded: false,
                    qm_sent: false,
                    qu_sent: false,
                }))
            }
        };

        let metadata = CapturedAddress {
            address,
            tuple,
            state,
        };

        tracing::trace!(
            packet_length,
            ?tuple,
            outbound,
            if_index,
            ?kind,
            "WinDivert packet captured"
        );

        Ok(CapturedPacket {
            context: FlowContext {
                tuple,
                original_packet: bytes,
                interface_index: if_index,
                outbound,
                backend_context: Box::new(metadata),
            },
            dns_payload,
            kind,
            ip_ttl,
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

        tracing::debug!(
            ?tuple,
            len = dns_payload.len(),
            "WinDivert injecting DNS response"
        );

        {
            let mut state = captured.state.lock().unwrap();
            match &mut *state {
                ContextState::SingleTerminal { resolved } => {
                    if *resolved {
                        return Err(BackendError(
                            "WinDivert packet context already resolved".into(),
                        ));
                    }
                    *resolved = true;
                }
                _ => {
                    return Err(BackendError(
                        "invalid context state for inject_response".into(),
                    ));
                }
            }
        }

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

    fn reinject_original(&self, context: FlowContext) -> Result<(), BackendError> {
        let FlowContext {
            tuple,
            original_packet,
            backend_context,
            ..
        } = context;
        let captured = backend_context
            .downcast::<CapturedAddress>()
            .map_err(|_| BackendError("invalid WinDivert packet context".into()))?;
        if tuple != captured.tuple {
            return Err(BackendError(
                "WinDivert packet tuple does not match context".into(),
            ));
        }

        {
            let mut state = captured.state.lock().unwrap();
            match &mut *state {
                ContextState::SingleTerminal { resolved } => {
                    if *resolved {
                        return Err(BackendError(
                            "WinDivert packet context already resolved".into(),
                        ));
                    }
                    *resolved = true;
                }
                _ => {
                    return Err(BackendError(
                        "invalid context state for reinject_original".into(),
                    ));
                }
            }
        }

        let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(original_packet) };
        packet.address = captured.address.clone();
        tracing::trace!(
            ?tuple,
            len = packet.data.len(),
            "WinDivert reinjecting original packet"
        );
        self.driver
            .send(&packet)
            .map_err(|error| BackendError(error.to_string()))?;
        Ok(())
    }

    fn forward_query(&self, context: &FlowContext) -> Result<(), BackendError> {
        let captured = validated_context(context)?;
        {
            let mut state = captured.state.lock().unwrap();
            match &mut *state {
                ContextState::MdnsQuery { forwarded, .. } => {
                    if *forwarded {
                        return Err(BackendError("mDNS query already forwarded".into()));
                    }
                    *forwarded = true;
                }
                _ => {
                    return Err(BackendError(
                        "invalid context state for forward_query".into(),
                    ));
                }
            }
        }
        let mut packet =
            unsafe { WinDivertPacket::<NetworkLayer>::new(context.original_packet.clone()) };
        packet.address = captured.address.clone();
        tracing::trace!(?context.tuple, "WinDivert forwarding original mDNS query");
        self.driver
            .send(&packet)
            .map_err(|error| BackendError(error.to_string()))?;
        Ok(())
    }

    fn inject_raw_packet(
        &self,
        context: &FlowContext,
        raw_packet: &[u8],
        outbound: bool,
    ) -> Result<(), BackendError> {
        let captured = validated_context(context)?;
        {
            let mut state = captured.state.lock().unwrap();
            match &mut *state {
                ContextState::MdnsQuery {
                    forwarded,
                    qm_sent,
                    qu_sent,
                } => {
                    if !*forwarded {
                        return Err(BackendError(
                            "cannot inject response before query is forwarded".into(),
                        ));
                    }
                    if outbound {
                        if *qm_sent {
                            return Err(BackendError("QM response already sent".into()));
                        }
                        *qm_sent = true;
                    } else {
                        if *qu_sent {
                            return Err(BackendError("QU response already sent".into()));
                        }
                        *qu_sent = true;
                    }
                }
                _ => {
                    return Err(BackendError(
                        "invalid context state for inject_raw_packet".into(),
                    ));
                }
            }
        }
        let mut packet = unsafe { WinDivertPacket::<NetworkLayer>::new(raw_packet.to_vec()) };
        packet.address = captured.address.clone();
        packet.address.set_outbound(outbound);
        tracing::debug!(
            ?context.tuple,
            outbound,
            len = raw_packet.len(),
            "WinDivert injecting raw packet"
        );
        packet.address.set_impostor(true);
        packet
            .recalculate_checksums(ChecksumFlags::new())
            .map_err(|error| BackendError(error.to_string()))?;
        self.driver
            .send(&packet)
            .map_err(|error| BackendError(error.to_string()))?;
        Ok(())
    }

    fn request_shutdown(&self) -> Result<(), BackendError> {
        if self.shutdown_requested.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.driver.shutdown_receive().map_err(|error| {
            BackendError(format!("could not shut down WinDivert receive: {error}"))
        })
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

pub fn run(
    config: Config,
    runtime: Arc<crate::admin::RuntimeState>,
    console_mode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let driver = WinDivertDriver::open(WIN_DIVERT_FILTER)?;
    if console_mode {
        println!("WinDivert capture active; Ctrl+C stops the foreground process");
    }
    backend::run_proxy(
        Arc::new(WinDivertBackend {
            driver,
            shutdown_requested: AtomicBool::new(false),
            receive_buffer: Mutex::new(vec![0; MAX_NETWORK_PACKET_SIZE]),
        }),
        config,
        runtime,
        Arc::new(SystemInterfaceProvider::new()),
        Arc::new(RandomJitter),
        console_mode,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::FlowTuple;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn filter_matches_required_criteria() {
        let filter = WIN_DIVERT_FILTER;
        assert!(filter.contains("!impostor"));
        assert!(filter.contains("!loopback"));
        assert!(filter.contains("udp.DstPort == 53"));
        assert!(filter.contains("udp.DstPort == 5353"));
        assert!(filter.contains("udp.SrcPort == 5353"));
        assert!(filter.contains("224.0.0.251"));
        assert!(filter.contains("ff02::fb"));
        assert!(filter.contains("ip.MF == 0 and ip.FragOff == 0"));
    }

    #[test]
    fn response_source_matches_original_dns_server() {
        let query = FlowTuple {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
            source_port: 12345,
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
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
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 11)),
            source_port: 12345,
            destination: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            destination_port: 53,
        };
        let captured = CapturedAddress {
            address: unsafe { WinDivertAddress::<NetworkLayer>::new() },
            tuple: Some(tuple),
            state: Arc::new(Mutex::new(ContextState::SingleTerminal { resolved: false })),
        };
        let context = FlowContext {
            tuple: Some(tuple),
            original_packet: vec![1, 2, 3],
            interface_index: 1,
            outbound: true,
            backend_context: Box::new(captured),
        };
        let metadata = validated_context(&context).unwrap();
        {
            let mut state = metadata.state.lock().unwrap();
            match &mut *state {
                ContextState::SingleTerminal { resolved } => *resolved = true,
                _ => panic!("wrong state"),
            }
        }
        {
            let state = metadata.state.lock().unwrap();
            match &*state {
                ContextState::SingleTerminal { resolved } => assert!(*resolved),
                _ => panic!("wrong state"),
            }
        }

        let invalid_context = FlowContext {
            tuple: None,
            original_packet: Vec::new(),
            interface_index: 0,
            outbound: true,
            backend_context: Box::new(()),
        };
        assert!(validated_context(&invalid_context).is_err());
    }
}
