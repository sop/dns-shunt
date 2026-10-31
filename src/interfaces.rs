use std::net::IpAddr;
#[cfg(target_os = "windows")]
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
};

pub trait InterfaceProvider: Send + Sync {
    fn has_unicast_source(&self, if_index: u32, addr: IpAddr) -> bool;
    fn is_on_link(&self, if_index: u32, addr: IpAddr) -> bool;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubnetPrefix {
    pub network: IpAddr,
    pub prefix_len: u8,
}

impl SubnetPrefix {
    pub fn new(network: impl Into<IpAddr>, prefix_len: u8) -> Self {
        Self {
            network: network.into(),
            prefix_len,
        }
    }

    pub fn matches(&self, addr: IpAddr) -> bool {
        match (self.network, addr) {
            (IpAddr::V4(net), IpAddr::V4(target)) => {
                let len = self.prefix_len.min(32);
                let mask = if len == 0 {
                    0u32
                } else {
                    (!0u32) << (32 - len)
                };
                (u32::from_be_bytes(net.octets()) & mask)
                    == (u32::from_be_bytes(target.octets()) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(target)) => {
                let len = self.prefix_len.min(128);
                let mask = if len == 0 {
                    0u128
                } else {
                    (!0u128) << (128 - len)
                };
                (u128::from_be_bytes(net.octets()) & mask)
                    == (u128::from_be_bytes(target.octets()) & mask)
            }
            _ => false,
        }
    }
}

pub fn is_usable_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_multicast() && !v4.is_loopback()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast() && !v6.is_loopback(),
    }
}

pub fn is_ipv6_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
        IpAddr::V4(_) => false,
    }
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceData {
    pub unicast_addresses: Vec<IpAddr>,
    pub prefixes: Vec<SubnetPrefix>,
}

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct MockInterfaceProvider {
    interfaces: std::sync::RwLock<std::collections::HashMap<u32, InterfaceData>>,
}

#[allow(dead_code)]
impl MockInterfaceProvider {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_interface(&self, if_index: u32, data: InterfaceData) {
        let mut map = self
            .interfaces
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        map.insert(if_index, data);
    }
}

impl InterfaceProvider for MockInterfaceProvider {
    fn has_unicast_source(&self, if_index: u32, addr: IpAddr) -> bool {
        if !is_usable_unicast(addr) {
            return false;
        }
        let map = self
            .interfaces
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(data) = map.get(&if_index) else {
            return false;
        };
        data.unicast_addresses.contains(&addr)
    }

    fn is_on_link(&self, if_index: u32, addr: IpAddr) -> bool {
        if !is_usable_unicast(addr) {
            return false;
        }
        if is_ipv6_link_local(addr) {
            return true;
        }
        let map = self
            .interfaces
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(data) = map.get(&if_index) else {
            return false;
        };
        data.prefixes.iter().any(|prefix| prefix.matches(addr))
    }
}

#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub struct SystemInterfaceProvider {
    cache: RwLock<HashMap<u32, InterfaceData>>,
    last_refresh: Mutex<Option<Instant>>,
}

#[cfg(target_os = "windows")]
impl Default for SystemInterfaceProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "windows")]
impl SystemInterfaceProvider {
    pub fn new() -> Self {
        let provider = Self {
            cache: RwLock::new(HashMap::new()),
            last_refresh: Mutex::new(None),
        };
        let _ = provider.refresh();
        provider
    }

    fn refresh(&self) -> Result<(), Box<dyn std::error::Error>> {
        use windows::Win32::NetworkManagement::IpHelper::{
            GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
        };

        let mut size = 15000u32;
        let mut buffer = vec![0u8; size as usize];
        let flags = GAA_FLAG_INCLUDE_PREFIX;

        // SAFETY: `GetAdaptersAddresses` is called with a pre-allocated buffer
        // sized by `size` bytes. If `size` is insufficient, the call fails with
        // `ERROR_BUFFER_OVERFLOW` (111) and writes the required size to `size`,
        // allowing us to reallocate and retry.
        let ret = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC.0 as u32,
                flags,
                None,
                Some(buffer.as_mut_ptr().cast()),
                &mut size,
            )
        };
        if ret == 111 {
            // ERROR_BUFFER_OVERFLOW
            buffer.resize(size as usize, 0);
            // SAFETY: Re-calling with resized buffer guaranteed to fit adapter list.
            let ret2 = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    flags,
                    None,
                    Some(buffer.as_mut_ptr().cast()),
                    &mut size,
                )
            };
            if ret2 != 0 {
                return Err(format!("GetAdaptersAddresses failed with code {ret2}").into());
            }
        } else if ret != 0 {
            return Err(format!("GetAdaptersAddresses failed with code {ret}").into());
        }

        let mut new_cache: HashMap<u32, InterfaceData> = HashMap::new();
        let mut current = buffer.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        // SAFETY: `GetAdaptersAddresses` guarantees a valid null-terminated linked list
        // of `IP_ADAPTER_ADDRESSES_LH` entries on success.
        while !current.is_null() {
            let adapter = unsafe { &*current };
            let ipv4_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            let ipv6_index = adapter.Ipv6IfIndex;

            let mut data = InterfaceData::default();

            // Unicast addresses
            let mut unicast = adapter.FirstUnicastAddress;
            while !unicast.is_null() {
                let entry = unsafe { &*unicast };
                let sockaddr = entry.Address.lpSockaddr;
                if !sockaddr.is_null() {
                    let family = unsafe { (*sockaddr).sa_family };
                    let on_link_len = entry.OnLinkPrefixLength;
                    if family == AF_INET {
                        let sin = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
                        let addr =
                            Ipv4Addr::from(u32::from_be(unsafe { sin.sin_addr.S_un.S_addr }));
                        data.unicast_addresses.push(IpAddr::V4(addr));
                        if on_link_len > 0 {
                            data.prefixes
                                .push(SubnetPrefix::new(IpAddr::V4(addr), on_link_len));
                        }
                    } else if family == AF_INET6 {
                        let sin6 = unsafe { &*(sockaddr as *const SOCKADDR_IN6) };
                        let addr = Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte });
                        data.unicast_addresses.push(IpAddr::V6(addr));
                        if on_link_len > 0 {
                            data.prefixes
                                .push(SubnetPrefix::new(IpAddr::V6(addr), on_link_len));
                        }
                    }
                }
                unicast = entry.Next;
            }

            // On-link prefixes
            let mut prefix_ptr = adapter.FirstPrefix;
            while !prefix_ptr.is_null() {
                let entry = unsafe { &*prefix_ptr };
                let sockaddr = entry.Address.lpSockaddr;
                if !sockaddr.is_null() {
                    let family = unsafe { (*sockaddr).sa_family };
                    let len = entry.PrefixLength as u8;
                    if family == AF_INET {
                        let sin = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
                        let addr =
                            Ipv4Addr::from(u32::from_be(unsafe { sin.sin_addr.S_un.S_addr }));
                        data.prefixes.push(SubnetPrefix::new(IpAddr::V4(addr), len));
                    } else if family == AF_INET6 {
                        let sin6 = unsafe { &*(sockaddr as *const SOCKADDR_IN6) };
                        let addr = Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte });
                        data.prefixes.push(SubnetPrefix::new(IpAddr::V6(addr), len));
                    }
                }
                prefix_ptr = entry.Next;
            }

            if ipv4_index != 0 {
                new_cache
                    .entry(ipv4_index)
                    .or_default()
                    .unicast_addresses
                    .extend(data.unicast_addresses.iter().copied());
                new_cache
                    .entry(ipv4_index)
                    .or_default()
                    .prefixes
                    .extend(data.prefixes.iter().cloned());
            }
            if ipv6_index != 0 {
                new_cache
                    .entry(ipv6_index)
                    .or_default()
                    .unicast_addresses
                    .extend(data.unicast_addresses.iter().copied());
                new_cache
                    .entry(ipv6_index)
                    .or_default()
                    .prefixes
                    .extend(data.prefixes.iter().cloned());
            }

            current = adapter.Next;
        }

        let mut cache = self
            .cache
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *cache = new_cache;
        let mut last = self
            .last_refresh
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *last = Some(Instant::now());
        Ok(())
    }

    fn ensure_fresh(&self, if_index: u32) {
        let should_refresh = {
            let cache = self
                .cache
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let not_found = !cache.contains_key(&if_index);
            let last = self
                .last_refresh
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let expired = last
                .map(|t| t.elapsed() > Duration::from_secs(2))
                .unwrap_or(true);
            not_found || expired
        };
        if should_refresh {
            let _ = self.refresh();
        }
    }
}

#[cfg(target_os = "windows")]
impl InterfaceProvider for SystemInterfaceProvider {
    fn has_unicast_source(&self, if_index: u32, addr: IpAddr) -> bool {
        if !is_usable_unicast(addr) {
            return false;
        }
        self.ensure_fresh(if_index);
        let cache = self
            .cache
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(data) = cache.get(&if_index) else {
            return false;
        };
        data.unicast_addresses.contains(&addr)
    }

    fn is_on_link(&self, if_index: u32, addr: IpAddr) -> bool {
        if !is_usable_unicast(addr) {
            return false;
        }
        if is_ipv6_link_local(addr) {
            return true;
        }
        self.ensure_fresh(if_index);
        let cache = self
            .cache
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(data) = cache.get(&if_index) else {
            return false;
        };
        data.prefixes.iter().any(|prefix| prefix.matches(addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn validates_ipv4_and_ipv6_prefix_matching() {
        let p4 = SubnetPrefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        assert!(p4.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 55))));
        assert!(!p4.matches(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 55))));

        let p6 = SubnetPrefix::new(Ipv6Addr::new(0x2001, 0xdb8, 0x1234, 0, 0, 0, 0, 0), 48);
        assert!(p6.matches(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x1234, 0x5678, 0, 0, 0, 1
        ))));
        assert!(!p6.matches(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0xdb8, 0x9999, 0, 0, 0, 0, 1
        ))));
    }

    #[test]
    fn mock_interface_provider_validates_unicast_source_and_on_link() {
        let provider = MockInterfaceProvider::new();
        let if_index = 12;
        let mut data = InterfaceData::default();
        let my_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let peer_on_link = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20));
        let peer_off_link = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 20));
        data.unicast_addresses.push(my_ip);
        data.prefixes
            .push(SubnetPrefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
        provider.add_interface(if_index, data);

        assert!(provider.has_unicast_source(if_index, my_ip));
        assert!(!provider.has_unicast_source(if_index, peer_on_link));
        assert!(!provider.has_unicast_source(if_index, IpAddr::V4(Ipv4Addr::UNSPECIFIED)));

        assert!(provider.is_on_link(if_index, peer_on_link));
        assert!(!provider.is_on_link(if_index, peer_off_link));
        // IPv6 link-local is always on-link
        assert!(provider.is_on_link(
            if_index,
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        ));
    }
}
