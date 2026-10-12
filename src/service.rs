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
use std::{fs, fs::OpenOptions, io::Write, os::windows::ffi::OsStrExt};
use windows_sys::Win32::{
    Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING,
        ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR,
        LocalFree,
    },
    Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW,
    Security::{DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetFileSecurityW},
    System::{
        EventLog::{
            DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
            RegisterEventSourceW, ReportEventW,
        },
        Registry::{
            HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD, REG_SZ, RegCloseKey, RegCreateKeyExW,
            RegDeleteTreeW, RegSetValueExW,
        },
        Services::{
            ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW,
            DeleteService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
            QueryServiceConfigW, QueryServiceStatus, RegisterServiceCtrlHandlerExW,
            SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ACCEPT_SHUTDOWN,
            SERVICE_ACCEPT_STOP, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
            SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
            SERVICE_ERROR_NORMAL, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
            SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
            SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW,
            SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
            StartServiceW,
        },
    },
    UI::Shell::IsUserAnAdmin,
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
const EVENT_SOURCE_KEY: &str =
    "SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\Dns-Shunt";
const PROGRAM_DATA_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BA)";
const DELETE_ACCESS: u32 = 0x0001_0000;

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

pub fn manage(command: crate::ServiceCommand) -> Result<(), Box<dyn Error>> {
    if unsafe { IsUserAnAdmin() } == 0 {
        return Err("service management requires an elevated administrator".into());
    }

    match command {
        crate::ServiceCommand::Stop => stop_installed_service(),
        crate::ServiceCommand::Install => install_or_update_service(),
        crate::ServiceCommand::Uninstall => uninstall_service(),
    }
}

fn install_or_update_service() -> Result<(), Box<dyn Error>> {
    let executable = std::env::current_exe()?;
    verify_runtime_files(&executable)?;
    prepare_service_data()?;
    register_event_source(&executable)?;

    let binary_path = format!("\"{}\" --service", executable.display());
    let binary_path = wide(&binary_path);
    let display_name = wide("dns-shunt DNS override service");
    let manager = open_manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let service = match open_service(
        &manager,
        SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
    ) {
        Ok(service) => {
            stop_handle(&service)?;
            let changed = unsafe {
                ChangeServiceConfigW(
                    service.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    binary_path.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                    display_name.as_ptr(),
                )
            };
            if changed == 0 {
                return Err(last_error("could not update the DnsShunt service"));
            }
            service
        }
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
            let service_name = wide("DnsShunt");
            let handle = unsafe {
                CreateServiceW(
                    manager.0,
                    service_name.as_ptr(),
                    display_name.as_ptr(),
                    SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    binary_path.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    ptr::null(),
                    ptr::null(),
                )
            };
            if handle.is_null() {
                return Err(last_error("could not create the DnsShunt service"));
            }
            ServiceHandle(handle)
        }
        Err(error) => return Err(error.into()),
    };

    let started = unsafe { StartServiceW(service.0, 0, ptr::null()) };
    if started == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
            return Err(format!("could not start the DnsShunt service: {error}").into());
        }
    }
    wait_for_service_state(&service, SERVICE_RUNNING, "DnsShunt")?;
    Ok(())
}

fn stop_installed_service() -> Result<(), Box<dyn Error>> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service = match open_service(&manager, SERVICE_QUERY_STATUS | SERVICE_STOP) {
        Ok(service) => service,
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };
    stop_handle(&service)
}

fn uninstall_service() -> Result<(), Box<dyn Error>> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    match open_named_service(
        &manager,
        "DnsShunt",
        SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE_ACCESS,
    ) {
        Ok(service) => {
            stop_handle(&service)?;
            if unsafe { DeleteService(service.0) } == 0 {
                return Err(last_error("could not delete the DnsShunt service"));
            }
        }
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {}
        Err(error) => return Err(error.into()),
    }
    stop_installed_windivert_driver(&manager)?;
    unregister_event_source()?;
    Ok(())
}

struct ServiceHandle(windows_sys::Win32::System::Services::SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn open_manager(access: u32) -> Result<ServiceHandle, std::io::Error> {
    let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) };
    if handle.is_null() {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ServiceHandle(handle))
    }
}

fn open_service(manager: &ServiceHandle, access: u32) -> Result<ServiceHandle, std::io::Error> {
    open_named_service(manager, "DnsShunt", access)
}

fn open_named_service(
    manager: &ServiceHandle,
    service_name: &str,
    access: u32,
) -> Result<ServiceHandle, std::io::Error> {
    let name = wide(service_name);
    let handle = unsafe { OpenServiceW(manager.0, name.as_ptr(), access) };
    if handle.is_null() {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(ServiceHandle(handle))
    }
}

fn stop_handle(service: &ServiceHandle) -> Result<(), Box<dyn Error>> {
    stop_named_handle(service, "DnsShunt")
}

fn stop_named_handle(service: &ServiceHandle, service_name: &str) -> Result<(), Box<dyn Error>> {
    let mut status = SERVICE_STATUS::default();
    if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
        return Err(last_error(&format!(
            "could not query the {service_name} service state"
        )));
    }
    if status.dwCurrentState == SERVICE_STOPPED {
        return Ok(());
    }
    if status.dwCurrentState != SERVICE_STOP_PENDING {
        let stopped = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) };
        if stopped == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
                return Err(format!("could not stop the {service_name} service: {error}").into());
            }
        }
    }
    wait_for_service_state(service, SERVICE_STOPPED, service_name)
}

fn wait_for_service_state(
    service: &ServiceHandle,
    expected_state: u32,
    service_name: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let mut status = SERVICE_STATUS::default();
        if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
            return Err(last_error(&format!(
                "could not query the {service_name} service state"
            )));
        }
        if status.dwCurrentState == expected_state {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            let state = status.dwCurrentState;
            return Err(format!(
                concat!(
                    "timed out waiting for the {} service state ",
                    "{} (current state {})"
                ),
                service_name, expected_state, state
            )
            .into());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn stop_installed_windivert_driver(manager: &ServiceHandle) -> Result<(), Box<dyn Error>> {
    let driver = match open_named_service(
        manager,
        "WinDivert",
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP,
    ) {
        Ok(driver) => driver,
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
            eprintln!("WinDivert driver service is not registered; nothing to stop.");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let image_path = service_binary_path(&driver)?;
    let expected_path = std::env::current_exe()?
        .parent()
        .ok_or("could not locate the application directory")?
        .join("WinDivert64.sys");
    let image_path = normalize_driver_image_path(&image_path)?;
    let expected_path = std::fs::canonicalize(expected_path)?;
    eprintln!("WinDivert service image path: {}", image_path.display());

    if !image_path
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected_path.to_string_lossy())
    {
        eprintln!("WinDivert is registered from a different path; leaving it running.");
        return Ok(());
    }

    let mut status = SERVICE_STATUS::default();
    if unsafe { QueryServiceStatus(driver.0, &mut status) } == 0 {
        return Err(last_error("could not query the WinDivert driver state"));
    }
    if status.dwCurrentState == SERVICE_STOPPED {
        eprintln!("The installed WinDivert driver is already stopped.");
        return Ok(());
    }

    eprintln!("Stopping the WinDivert driver loaded from the install directory.");
    stop_named_handle(&driver, "WinDivert")
}

fn service_binary_path(service: &ServiceHandle) -> Result<String, Box<dyn Error>> {
    let mut bytes_needed = 0;
    unsafe {
        let _ = QueryServiceConfigW(service.0, ptr::null_mut(), 0, &mut bytes_needed);
    }
    let error = std::io::Error::last_os_error();
    if bytes_needed == 0 && error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error.into());
    }

    let word_count = (bytes_needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; word_count];
    let buffer_size = std::mem::size_of_val(buffer.as_slice()) as u32;
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if unsafe { QueryServiceConfigW(service.0, config, buffer_size, &mut bytes_needed) } == 0 {
        return Err(last_error(
            "could not query the WinDivert driver image path",
        ));
    }

    let binary_path = unsafe { (*config).lpBinaryPathName };
    if binary_path.is_null() {
        return Err("WinDivert driver has no registered image path".into());
    }
    let mut length = 0;
    unsafe {
        while *binary_path.add(length) != 0 {
            length += 1;
        }
        let path = std::slice::from_raw_parts(binary_path, length);
        Ok(String::from_utf16_lossy(path))
    }
}

fn normalize_driver_image_path(path: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = path.trim().trim_matches('"');
    let path = path
        .strip_prefix(r"\??\")
        .or_else(|| path.strip_prefix(r"\\?\"))
        .unwrap_or(path);
    Ok(std::fs::canonicalize(path)?)
}

fn prepare_service_data() -> Result<(), Box<dyn Error>> {
    let paths = service_paths()?;
    let data_dir = paths.config.parent().ok_or("invalid ProgramData path")?;
    fs::create_dir_all(data_dir)?;

    let descriptor_text = wide(PROGRAM_DATA_SDDL);
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(last_error("could not prepare ProgramData permissions"));
    }
    let directory = wide(&data_dir.to_string_lossy());
    let secured = unsafe {
        SetFileSecurityW(
            directory.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        )
    };
    unsafe {
        let _ = LocalFree(descriptor);
    }
    if secured == 0 {
        return Err(last_error(
            "could not grant SYSTEM and Administrators access to ProgramData",
        ));
    }

    let bundled_config = std::env::current_exe()?
        .parent()
        .map(|directory| directory.join("dns-shunt.example.toml"))
        .filter(|path| path.is_file());
    let seed = match bundled_config {
        Some(path) => fs::read(path)?,
        None => include_bytes!("../dns-shunt.example.toml").to_vec(),
    };
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&paths.config)
    {
        Ok(mut config) => config.write_all(&seed)?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    crate::config::Config::load(&paths.config).map_err(|error| -> Box<dyn Error> {
        format!(
            "service configuration is invalid at {}: {error}",
            paths.config.display()
        )
        .into()
    })?;
    Ok(())
}

fn verify_runtime_files(executable: &Path) -> Result<(), Box<dyn Error>> {
    let directory = executable
        .parent()
        .ok_or("could not locate the application directory")?;
    for name in ["WinDivert.dll", "WinDivert64.sys"] {
        let path = directory.join(name);
        let metadata = fs::metadata(&path).map_err(|error| {
            format!(
                "required WinDivert runtime file is unavailable at {}: {error}",
                path.display()
            )
        })?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(format!(
                "required WinDivert runtime file is missing or empty: {}",
                path.display()
            )
            .into());
        }
    }
    Ok(())
}

fn register_event_source(executable: &Path) -> Result<(), Box<dyn Error>> {
    let key_path = wide(EVENT_SOURCE_KEY);
    let mut key = ptr::null_mut();
    let created = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            ptr::null(),
            0,
            KEY_SET_VALUE,
            ptr::null(),
            &mut key,
            ptr::null_mut(),
        )
    };
    if created != 0 {
        return Err(std::io::Error::from_raw_os_error(created as i32).into());
    }

    let result = (|| {
        let executable = wide(&executable.to_string_lossy());
        set_registry_value(key, "EventMessageFile", REG_SZ, &executable)?;
        set_registry_dword(key, "TypesSupported", 7)?;
        Ok::<(), Box<dyn Error>>(())
    })();
    unsafe {
        let _ = RegCloseKey(key);
    }
    result
}

fn unregister_event_source() -> Result<(), Box<dyn Error>> {
    let key_path = wide(EVENT_SOURCE_KEY);
    let result = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, key_path.as_ptr()) };
    if result != 0 && result != ERROR_FILE_NOT_FOUND {
        return Err(std::io::Error::from_raw_os_error(result as i32).into());
    }
    Ok(())
}

fn set_registry_value(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
    value_type: u32,
    value: &[u16],
) -> Result<(), Box<dyn Error>> {
    let name = wide(name);
    let result = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            value_type,
            value.as_ptr().cast::<u8>(),
            std::mem::size_of_val(value) as u32,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32).into());
    }
    Ok(())
}

fn set_registry_dword(
    key: windows_sys::Win32::System::Registry::HKEY,
    name: &str,
    value: u32,
) -> Result<(), Box<dyn Error>> {
    let name = wide(name);
    let result = unsafe {
        RegSetValueExW(
            key,
            name.as_ptr(),
            0,
            REG_DWORD,
            (&value as *const u32).cast::<u8>(),
            std::mem::size_of::<u32>() as u32,
        )
    };
    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32).into());
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn last_error(context: &str) -> Box<dyn Error> {
    format!("{context}: {}", std::io::Error::last_os_error()).into()
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
