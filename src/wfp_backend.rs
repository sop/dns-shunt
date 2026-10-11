use crate::{
    backend::{self, BackendError, CapturedPacket, FlowContext, InterceptionBackend},
    config::Config,
    wfp_protocol::{self, Resolution},
};
use std::{
    io, ptr,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};
use windows_sys::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_IO_PENDING, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
            WAIT_OBJECT_0,
        },
        NetworkManagement::WindowsFilteringPlatform::*,
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, ReadFile,
        },
        System::{
            IO::{CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED},
            Services::{
                CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
                QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
                SERVICE_START, SERVICE_STATUS, SERVICE_STOP, StartServiceW,
            },
            Threading::{CreateEventW, INFINITE, WaitForSingleObject},
        },
    },
    core::GUID,
};

const DEVICE_PATH: &[u16] = &[
    b'\\' as u16,
    b'\\' as u16,
    b'.' as u16,
    b'\\' as u16,
    b'D' as u16,
    b'n' as u16,
    b's' as u16,
    b'S' as u16,
    b'h' as u16,
    b'u' as u16,
    b'n' as u16,
    b't' as u16,
    b'W' as u16,
    b'f' as u16,
    b'p' as u16,
    0,
];
const SERVICE_NAME: &[u16] = &[
    b'D' as u16,
    b'n' as u16,
    b's' as u16,
    b'S' as u16,
    b'h' as u16,
    b'u' as u16,
    b'n' as u16,
    b't' as u16,
    b'W' as u16,
    b'f' as u16,
    b'p' as u16,
    0,
];
const PROVIDER_KEY: GUID = GUID::from_u128(0x0a4e_628f_253c_4a12_a85a_670c_87de_4121);
const SUBLAYER_KEY: GUID = GUID::from_u128(0x5bdd_152c_6c8d_480c_b66e_d40a_8b51_b729);
const CALLOUT_KEY: GUID = GUID::from_u128(0xa232_e608_8a6f_4bb9_9037_25df_abf5_176a);
const FILTER_KEY: GUID = GUID::from_u128(0x7c6a_7814_1106_41df_8d70_868a_2c4d_859b);

struct WfpSession(HANDLE);

impl WfpSession {
    fn install() -> Result<Self, String> {
        let session = FWPM_SESSION0 {
            flags: FWPM_SESSION_FLAG_DYNAMIC,
            ..FWPM_SESSION0::default()
        };
        let mut engine = ptr::null_mut();
        check_status(
            unsafe { FwpmEngineOpen0(ptr::null(), 10, ptr::null(), &session, &mut engine) },
            "open dynamic WFP engine session",
        )?;

        let result = Self::install_objects(engine);
        if let Err(error) = result {
            unsafe {
                let _ = FwpmEngineClose0(engine);
            }
            return Err(error);
        }
        Ok(Self(engine))
    }

    fn install_objects(engine: HANDLE) -> Result<(), String> {
        check_status(
            unsafe { FwpmTransactionBegin0(engine, 0) },
            "begin WFP transaction",
        )?;

        let mut provider_name: Vec<u16> = "dns-shunt dynamic provider\0".encode_utf16().collect();
        let mut provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER_KEY,
            ..FWPM_PROVIDER0::default()
        };
        provider.displayData.name = provider_name.as_mut_ptr();
        let add_result = unsafe { FwpmProviderAdd0(engine, &provider, ptr::null_mut()) };
        if let Err(error) = check_status(add_result, "add WFP provider") {
            unsafe {
                let _ = FwpmTransactionAbort0(engine);
            }
            return Err(error);
        }

        let mut sublayer_name: Vec<u16> = "dns-shunt dynamic sublayer\0".encode_utf16().collect();
        let mut sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER_KEY,
            providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
            weight: 0x7fff,
            ..FWPM_SUBLAYER0::default()
        };
        sublayer.displayData.name = sublayer_name.as_mut_ptr();
        let add_sublayer = unsafe { FwpmSubLayerAdd0(engine, &sublayer, ptr::null_mut()) };
        if let Err(error) = check_status(add_sublayer, "add WFP sublayer") {
            unsafe {
                let _ = FwpmTransactionAbort0(engine);
            }
            return Err(error);
        }

        let layer = FWPM_LAYER_OUTBOUND_TRANSPORT_V4;
        let mut callout_name: Vec<u16> =
            "dns-shunt outbound DNS callout\0".encode_utf16().collect();
        let mut callout = FWPM_CALLOUT0 {
            calloutKey: CALLOUT_KEY,
            providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
            applicableLayer: layer,
            ..FWPM_CALLOUT0::default()
        };
        callout.displayData.name = callout_name.as_mut_ptr();
        if let Err(error) = check_status(
            unsafe { FwpmCalloutAdd0(engine, &callout, ptr::null_mut(), ptr::null_mut()) },
            "add WFP callout",
        ) {
            unsafe {
                let _ = FwpmTransactionAbort0(engine);
            }
            return Err(error);
        }

        let mut conditions = filter_conditions();
        let mut filter_name: Vec<u16> = "dns-shunt outbound IPv4 DNS filter\0"
            .encode_utf16()
            .collect();
        let mut action = FWPM_ACTION0 {
            r#type: FWP_ACTION_CALLOUT_TERMINATING,
            ..FWPM_ACTION0::default()
        };
        action.Anonymous.calloutKey = CALLOUT_KEY;
        let mut filter = FWPM_FILTER0 {
            filterKey: FILTER_KEY,
            providerKey: &PROVIDER_KEY as *const GUID as *mut GUID,
            layerKey: layer,
            subLayerKey: SUBLAYER_KEY,
            weight: FWP_VALUE0 {
                r#type: FWP_EMPTY,
                ..FWP_VALUE0::default()
            },
            numFilterConditions: conditions.len() as u32,
            filterCondition: conditions.as_mut_ptr(),
            action,
            ..FWPM_FILTER0::default()
        };
        filter.displayData.name = filter_name.as_mut_ptr();
        if let Err(error) = check_status(
            unsafe { FwpmFilterAdd0(engine, &filter, ptr::null_mut(), ptr::null_mut()) },
            "add outbound DNS filter",
        ) {
            unsafe {
                let _ = FwpmTransactionAbort0(engine);
            }
            return Err(error);
        }
        check_status(
            unsafe { FwpmTransactionCommit0(engine) },
            "commit WFP transaction",
        )
    }
}

impl Drop for WfpSession {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.0);
        }
    }
}

fn check_status(status: u32, operation: &str) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!(
            "{operation}: {}",
            io::Error::from_raw_os_error(status as i32)
        ))
    }
}

fn filter_conditions() -> Vec<FWPM_FILTER_CONDITION0> {
    vec![
        condition(FWPM_CONDITION_IP_PROTOCOL, FWP_MATCH_EQUAL, FWP_UINT8, 17),
        condition(
            FWPM_CONDITION_IP_REMOTE_PORT,
            FWP_MATCH_EQUAL,
            FWP_UINT16,
            53,
        ),
        condition(
            FWPM_CONDITION_FLAGS,
            FWP_MATCH_FLAGS_NONE_SET,
            FWP_UINT32,
            FWP_CONDITION_FLAG_IS_LOOPBACK,
        ),
    ]
}

fn condition(
    field: GUID,
    match_type: FWP_MATCH_TYPE,
    value_type: FWP_DATA_TYPE,
    value: u32,
) -> FWPM_FILTER_CONDITION0 {
    let value = match value_type {
        FWP_UINT8 => FWP_CONDITION_VALUE0_0 { uint8: value as u8 },
        FWP_UINT16 => FWP_CONDITION_VALUE0_0 {
            uint16: value as u16,
        },
        _ => FWP_CONDITION_VALUE0_0 { uint32: value },
    };
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: match_type,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: value_type,
            Anonymous: value,
        },
    }
}

struct Device(HANDLE);

// Win32 file handles can be used concurrently; ownership remains with this wrapper.
unsafe impl Send for Device {}
unsafe impl Sync for Device {}

impl Device {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let handle = unsafe {
            CreateFileW(
                DEVICE_PATH.as_ptr(),
                0x8000_0000 | 0x4000_0000,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        Ok(Self(handle))
    }

    fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let mut read = 0;
        let event = create_io_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..OVERLAPPED::default()
        };
        let result = unsafe {
            ReadFile(
                self.0,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                ptr::null_mut(),
                &mut overlapped,
            )
        };
        if result == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_IO_PENDING {
                unsafe {
                    let _ = CloseHandle(event);
                }
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        }
        let wait = unsafe { WaitForSingleObject(event, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            unsafe {
                let _ = CloseHandle(event);
            }
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { GetOverlappedResult(self.0, &overlapped, &mut read, 0) };
        unsafe {
            let _ = CloseHandle(event);
        }
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read as usize)
    }

    fn control(&self, code: u32, input: Option<&[u8]>) -> io::Result<()> {
        let (input_ptr, input_len) = match input {
            Some(bytes) => (bytes.as_ptr().cast(), bytes.len() as u32),
            None => (ptr::null(), 0),
        };
        let mut returned = 0;
        let event = create_io_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event,
            ..OVERLAPPED::default()
        };
        let result = unsafe {
            DeviceIoControl(
                self.0,
                code,
                input_ptr,
                input_len,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut overlapped,
            )
        };
        if result == 0 {
            let error = unsafe { GetLastError() };
            if error != ERROR_IO_PENDING {
                unsafe {
                    let _ = CloseHandle(event);
                }
                return Err(io::Error::from_raw_os_error(error as i32));
            }
        }
        let wait = unsafe { WaitForSingleObject(event, INFINITE) };
        if wait != WAIT_OBJECT_0 {
            unsafe {
                let _ = CloseHandle(event);
            }
            return Err(io::Error::last_os_error());
        }
        let result = unsafe { GetOverlappedResult(self.0, &overlapped, &mut returned, 0) };
        unsafe {
            let _ = CloseHandle(event);
        }
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn cancel_io(&self) {
        unsafe {
            let _ = CancelIoEx(self.0, ptr::null());
        }
    }
}

fn create_io_event() -> io::Result<HANDLE> {
    let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if event.is_null() {
        Err(io::Error::last_os_error())
    } else {
        Ok(event)
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

struct DriverService {
    manager: HANDLE,
    service: HANDLE,
    started_here: bool,
}

unsafe impl Send for DriverService {}
unsafe impl Sync for DriverService {}

impl DriverService {
    fn start_if_needed() -> io::Result<Self> {
        let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err(io::Error::last_os_error());
        }
        let service = unsafe {
            OpenServiceW(
                manager,
                SERVICE_NAME.as_ptr(),
                SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS,
            )
        };
        if service.is_null() {
            unsafe {
                let _ = CloseServiceHandle(manager);
            }
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "WFP callout driver is not installed; install it with driver\\install-wfp.ps1",
            ));
        }
        let mut status = SERVICE_STATUS::default();
        if unsafe { QueryServiceStatus(service, &mut status) } == 0 {
            let error = io::Error::last_os_error();
            unsafe {
                let _ = CloseServiceHandle(service);
                let _ = CloseServiceHandle(manager);
            }
            return Err(error);
        }
        let started_here = if status.dwCurrentState != SERVICE_RUNNING {
            if unsafe { StartServiceW(service, 0, ptr::null()) } == 0 {
                let error = io::Error::last_os_error();
                unsafe {
                    let _ = CloseServiceHandle(service);
                    let _ = CloseServiceHandle(manager);
                }
                return Err(error);
            }
            true
        } else {
            false
        };
        Ok(Self {
            manager,
            service,
            started_here,
        })
    }
}

impl Drop for DriverService {
    fn drop(&mut self) {
        if self.started_here {
            let mut status = SERVICE_STATUS::default();
            unsafe {
                let _ = ControlService(self.service, 1, &mut status);
            }
        }
        unsafe {
            let _ = CloseServiceHandle(self.service);
            let _ = CloseServiceHandle(self.manager);
        }
    }
}

struct WfpToken {
    token: u64,
    tuple: crate::packet::FlowTuple,
    resolved: Mutex<bool>,
}

struct WfpBackend {
    device: Option<Device>,
    filter: Option<WfpSession>,
    service: Option<DriverService>,
    shutdown_requested: AtomicBool,
    receive_buffer: Mutex<Vec<u8>>,
}

unsafe impl Send for WfpSession {}
unsafe impl Sync for WfpSession {}

impl InterceptionBackend for WfpBackend {
    fn capture(&self) -> Result<CapturedPacket, BackendError> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(BackendError("WFP capture stopped during shutdown".into()));
        }
        let mut buffer = self
            .receive_buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let device = self
            .device
            .as_ref()
            .ok_or_else(|| BackendError("WFP device is closed".into()))?;
        let length = device
            .read(&mut buffer)
            .map_err(|error| BackendError(format!("WFP capture read failed: {error}")))?;
        let capture = wfp_protocol::decode_capture(&buffer[..length])?;
        let context = FlowContext {
            tuple: Some(capture.tuple),
            backend_context: Arc::new(WfpToken {
                token: capture.token,
                tuple: capture.tuple,
                resolved: Mutex::new(false),
            }),
        };
        Ok(CapturedPacket {
            context,
            dns_payload: Some(capture.payload),
        })
    }

    fn inject_response(
        &self,
        context: &FlowContext,
        dns_payload: &[u8],
    ) -> Result<(), BackendError> {
        let token = valid_token(context)?;
        let mut resolved = begin_resolution(&token.resolved)?;
        let command = wfp_protocol::encode_resolution(Resolution::Response {
            token: token.token,
            payload: dns_payload,
        })?;
        self.device_ref()?
            .control(wfp_protocol::IOCTL_RESOLVE, Some(&command))
            .map_err(|error| BackendError(format!("WFP response injection failed: {error}")))?;
        *resolved = true;
        Ok(())
    }

    fn reinject_original(&self, context: &FlowContext) -> Result<(), BackendError> {
        let token = valid_token(context)?;
        let mut resolved = begin_resolution(&token.resolved)?;
        let command = wfp_protocol::encode_resolution(Resolution::Reinject { token: token.token })?;
        self.device_ref()?
            .control(wfp_protocol::IOCTL_RESOLVE, Some(&command))
            .map_err(|error| BackendError(format!("WFP reinjection failed: {error}")))?;
        *resolved = true;
        Ok(())
    }

    fn request_shutdown(&self) {
        if self.shutdown_requested.swap(true, Ordering::AcqRel) {
            return;
        }
        if let Some(device) = &self.device
            && let Err(error) = device.control(wfp_protocol::IOCTL_SHUTDOWN, None)
        {
            eprintln!("could not stop WFP capture read: {error}");
            device.cancel_io();
        }
    }
}

impl WfpBackend {
    fn device_ref(&self) -> Result<&Device, BackendError> {
        self.device
            .as_ref()
            .ok_or_else(|| BackendError("WFP device is closed".into()))
    }
}

fn valid_token(context: &FlowContext) -> Result<&WfpToken, BackendError> {
    let token = context
        .backend_context
        .downcast_ref::<WfpToken>()
        .ok_or_else(|| BackendError("invalid WFP packet context".into()))?;
    if context.tuple != Some(token.tuple) {
        return Err(BackendError(
            "WFP packet tuple does not match token context".into(),
        ));
    }
    Ok(token)
}

fn begin_resolution(resolved: &Mutex<bool>) -> Result<MutexGuard<'_, bool>, BackendError> {
    let state = resolved
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if *state {
        return Err(BackendError("WFP token already resolved".into()));
    }
    Ok(state)
}

impl Drop for WfpBackend {
    fn drop(&mut self) {
        self.request_shutdown();
        self.filter.take();
        self.device.take();
        self.service.take();
    }
}

pub fn run(
    config: Config,
    runtime: Arc<crate::admin::RuntimeState>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !cfg!(target_arch = "x86_64") {
        return Err("the WFP backend currently supports x64 Windows only".into());
    }
    let service = DriverService::start_if_needed().map_err(|error| {
        format!("could not start installed WFP driver service (run elevated): {error}")
    })?;
    let device = Device::open().map_err(|error| {
        format!(
            "could not open WFP callout device; verify driver installation and elevation: {error}"
        )
    })?;
    let filter = WfpSession::install().map_err(|error| {
        format!("could not install dynamic WFP filters (run elevated): {error}")
    })?;
    println!("WFP outbound DNS capture active; Ctrl+C stops the foreground prototype");
    backend::run_proxy(
        Arc::new(WfpBackend {
            device: Some(device),
            filter: Some(filter),
            service: Some(service),
            shutdown_requested: AtomicBool::new(false),
            receive_buffer: Mutex::new(vec![
                0;
                wfp_protocol::CAPTURE_HEADER_LEN
                    + wfp_protocol::MAX_PAYLOAD_LEN
            ]),
        }),
        config,
        runtime,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn guid_eq(left: GUID, right: GUID) -> bool {
        left.data1 == right.data1
            && left.data2 == right.data2
            && left.data3 == right.data3
            && left.data4 == right.data4
    }

    #[test]
    fn filter_conditions_capture_non_loopback_udp_dns_without_source_port_exclusion() {
        let conditions = filter_conditions();
        assert_eq!(conditions.len(), 3);
        assert!(conditions.iter().any(|condition| {
            guid_eq(condition.fieldKey, FWPM_CONDITION_IP_PROTOCOL)
                && condition.matchType == FWP_MATCH_EQUAL
                && condition.conditionValue.r#type == FWP_UINT8
                && unsafe { condition.conditionValue.Anonymous.uint8 == 17 }
        }));
        assert!(conditions.iter().any(|condition| {
            guid_eq(condition.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT)
                && unsafe { condition.conditionValue.Anonymous.uint16 == 53 }
        }));
        assert!(
            !conditions
                .iter()
                .any(|condition| guid_eq(condition.fieldKey, FWPM_CONDITION_IP_LOCAL_PORT))
        );
        assert!(conditions.iter().any(|condition| {
            guid_eq(condition.fieldKey, FWPM_CONDITION_FLAGS)
                && condition.matchType == FWP_MATCH_FLAGS_NONE_SET
                && unsafe {
                    condition.conditionValue.Anonymous.uint32 == FWP_CONDITION_FLAG_IS_LOOPBACK
                }
        }));
    }

    #[test]
    fn validates_token_tuple_and_allows_only_one_terminal_resolution() {
        let tuple = crate::packet::FlowTuple {
            source: Ipv4Addr::new(192, 0, 2, 9),
            source_port: 49152,
            destination: Ipv4Addr::new(1, 1, 1, 1),
            destination_port: 53,
        };
        let context = FlowContext {
            tuple: Some(tuple),
            backend_context: Arc::new(WfpToken {
                token: 7,
                tuple,
                resolved: Mutex::new(false),
            }),
        };
        let token = valid_token(&context).unwrap();
        *begin_resolution(&token.resolved).unwrap() = true;
        assert!(begin_resolution(&token.resolved).is_err());

        let mismatched = FlowContext {
            tuple: None,
            backend_context: Arc::clone(&context.backend_context),
        };
        assert!(valid_token(&mismatched).is_err());
    }
}
