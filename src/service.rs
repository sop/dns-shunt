use crate::admin::RuntimeState;
use std::{
    error::Error,
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering},
    },
};
use windows_sys::Win32::{
    Foundation::ERROR_SERVICE_SPECIFIC_ERROR,
    System::{
        EventLog::{
            DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
            RegisterEventSourceW, ReportEventW,
        },
        Services::{
            RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
            SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
            SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
            SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
            SetServiceStatus, StartServiceCtrlDispatcherW,
        },
    },
};

const SERVICE_NAME: &[u16] = &[
    b'D' as u16,
    b'n' as u16,
    b's' as u16,
    b'S' as u16,
    b'h' as u16,
    b'u' as u16,
    b'n' as u16,
    b't' as u16,
    0,
];
const EVENT_SOURCE: &[u16] = &[
    b'D' as u16,
    b'n' as u16,
    b's' as u16,
    b'-' as u16,
    b'S' as u16,
    b'h' as u16,
    b'u' as u16,
    b'n' as u16,
    b't' as u16,
    0,
];

static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
static CURRENT_STATE: AtomicU32 = AtomicU32::new(SERVICE_START_PENDING);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static RUNTIME: OnceLock<Mutex<Option<Arc<RuntimeState>>>> = OnceLock::new();

pub struct ServicePaths {
    pub config: PathBuf,
    pub rules: PathBuf,
}

pub fn paths_under(program_data: &Path) -> ServicePaths {
    let root = program_data.join("dns-shunt");
    ServicePaths {
        config: root.join("config.toml"),
        rules: root.join("rules.json"),
    }
}

pub fn service_paths() -> Result<ServicePaths, std::io::Error> {
    let root = std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "could not locate the ProgramData directory",
            )
        })?;
    Ok(paths_under(&root))
}

pub fn dispatch() -> Result<(), Box<dyn Error>> {
    STOP_REQUESTED.store(false, Ordering::Release);
    let mut entries = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: SERVICE_NAME.as_ptr() as *mut u16,
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    let result = unsafe { StartServiceCtrlDispatcherW(entries.as_mut_ptr()) };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        return Err(error.into());
    }
    Ok(())
}

pub fn attach_runtime(runtime: &Arc<RuntimeState>) {
    *RUNTIME
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::clone(runtime));
    if STOP_REQUESTED.load(Ordering::Acquire) {
        runtime.stop();
    }
    runtime.set_ready_callback(Arc::new(|| {
        log_information("DNS interception and admin interface are ready");
        report_status(SERVICE_RUNNING, 0, 0);
    }));
}

pub fn log_error(message: &str) {
    log_event(EVENTLOG_ERROR_TYPE, 0x1001, message);
}

fn log_information(message: &str) {
    log_event(EVENTLOG_INFORMATION_TYPE, 0x1000, message);
}

fn log_event(event_type: u16, event_id: u32, message: &str) {
    let source = unsafe { RegisterEventSourceW(ptr::null(), EVENT_SOURCE.as_ptr()) };
    if source.is_null() {
        return;
    }
    let message: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    let strings = [message.as_ptr()];
    unsafe {
        let _ = ReportEventW(
            source,
            event_type,
            0,
            event_id,
            ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            ptr::null(),
        );
        let _ = DeregisterEventSource(source);
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            SERVICE_NAME.as_ptr(),
            Some(control_handler),
            ptr::null_mut(),
        )
    };
    if status_handle.is_null() {
        log_error(&format!(
            "could not register service control handler: {}",
            std::io::Error::last_os_error()
        ));
        return;
    }
    STATUS_HANDLE.store(status_handle as isize, Ordering::Release);
    report_status(SERVICE_START_PENDING, 0, 0);
    log_information("service startup requested");

    match crate::run_service() {
        Ok(()) => {
            log_information("service stopped");
            report_status(SERVICE_STOPPED, 0, 0);
        }
        Err(error) => {
            log_error(&format!("service startup or runtime failed: {error}"));
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR, 1);
        }
    }
    STATUS_HANDLE.store(0, Ordering::Release);
    *RUNTIME
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP_REQUESTED.store(true, Ordering::Release);
            report_status(SERVICE_STOP_PENDING, 0, 0);
            let runtime = RUNTIME
                .get_or_init(|| Mutex::new(None))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            if let Some(runtime) = runtime {
                runtime.stop();
            }
            0
        }
        SERVICE_CONTROL_INTERROGATE => {
            report_status(CURRENT_STATE.load(Ordering::Acquire), 0, 0);
            0
        }
        _ => 1,
    }
}

fn report_status(state: u32, exit_code: u32, service_exit_code: u32) {
    CURRENT_STATE.store(state, Ordering::Release);
    let handle = STATUS_HANDLE.load(Ordering::Acquire);
    if handle == 0 {
        return;
    }
    let (controls, wait_hint) = match state {
        SERVICE_START_PENDING => (0, 30_000),
        SERVICE_STOP_PENDING => (0, 30_000),
        SERVICE_RUNNING => (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN, 0),
        _ => (0, 0),
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: exit_code,
        dwServiceSpecificExitCode: service_exit_code,
        dwCheckPoint: if state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING {
            1
        } else {
            0
        },
        dwWaitHint: wait_hint,
    };
    unsafe {
        let _ = SetServiceStatus(handle as SERVICE_STATUS_HANDLE, &status);
    }
}
