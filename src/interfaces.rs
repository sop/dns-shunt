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
}

pub fn is_usable_unicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_unspecified() && !v4.is_broadcast() && !v4.is_multicast() && !v4.is_loopback()
        }
        IpAddr::V6(v6) => !v6.is_unspecified() && !v6.is_multicast() && !v6.is_loopback(),
    }
}

#[derive(Debug, Clone, Default)]
pub struct InterfaceData {
    pub unicast_addresses: Vec<IpAddr>,
}

#[cfg(test)]
#[derive(Debug, Default)]
pub struct MockInterfaceProvider {
    interfaces: std::sync::RwLock<std::collections::HashMap<u32, InterfaceData>>,
}

#[cfg(test)]
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

#[cfg(test)]
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
}

#[cfg(target_os = "windows")]
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
            GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
        };
        use windows::Win32::Networking::WinSock::{
            AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
        };

        let mut size = 15000u32;
        let mut buffer = vec![0u8; size as usize];
        let flags = GET_ADAPTERS_ADDRESSES_FLAGS::default();

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
                    if family == AF_INET {
                        let sin = unsafe { &*(sockaddr as *const SOCKADDR_IN) };
                        let addr =
                            Ipv4Addr::from(u32::from_be(unsafe { sin.sin_addr.S_un.S_addr }));
                        data.unicast_addresses.push(IpAddr::V4(addr));
                    } else if family == AF_INET6 {
                        let sin6 = unsafe { &*(sockaddr as *const SOCKADDR_IN6) };
                        let addr = Ipv6Addr::from(unsafe { sin6.sin6_addr.u.Byte });
                        data.unicast_addresses.push(IpAddr::V6(addr));
                    }
                }
                unicast = entry.Next;
            }

            if ipv4_index != 0 {
                new_cache
                    .entry(ipv4_index)
                    .or_default()
                    .unicast_addresses
                    .extend(data.unicast_addresses.iter().copied());
            }
            if ipv6_index != 0 {
                new_cache
                    .entry(ipv6_index)
                    .or_default()
                    .unicast_addresses
                    .extend(data.unicast_addresses.iter().copied());
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn mock_interface_provider_validates_unicast_source() {
        let provider = MockInterfaceProvider::new();
        let if_index = 12;
        let mut data = InterfaceData::default();
        let my_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let peer_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 20));
        data.unicast_addresses.push(my_ip);
        provider.add_interface(if_index, data);

        assert!(provider.has_unicast_source(if_index, my_ip));
        assert!(!provider.has_unicast_source(if_index, peer_ip));
        assert!(!provider.has_unicast_source(if_index, IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!provider.has_unicast_source(if_index, IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }
}
