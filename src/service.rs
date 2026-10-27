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
use windows::{
    Win32::{
        Foundation::{
            ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_SERVICE_ALREADY_RUNNING,
            ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_NOT_ACTIVE, ERROR_SERVICE_SPECIFIC_ERROR,
            HLOCAL, LocalFree,
        },
        Security::Authorization::{
            BuildTrusteeWithSidW, ConvertSecurityDescriptorToStringSecurityDescriptorW,
            ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
            EXPLICIT_ACCESS_W, GRANT_ACCESS, GetNamedSecurityInfoW, GetSecurityInfo,
            SE_FILE_OBJECT, SE_SERVICE, SetEntriesInAclW, SetSecurityInfo,
        },
        Security::{
            ACL, DACL_SECURITY_INFORMATION, EqualSid, GetSecurityDescriptorOwner,
            OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
            PSID, SetFileSecurityW,
        },
        System::{
            EventLog::{
                DeregisterEventSource, EVENTLOG_ERROR_TYPE, EVENTLOG_INFORMATION_TYPE,
                RegisterEventSourceW, ReportEventW,
            },
            Registry::{
                HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_DWORD, REG_OPTION_NON_VOLATILE,
                REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW,
                RegSetValueExW,
            },
            Services::{
                ChangeServiceConfigW, CloseServiceHandle, ControlService, CreateServiceW,
                DeleteService, OpenSCManagerW, OpenServiceW, QUERY_SERVICE_CONFIGW,
                QueryServiceConfigW, QueryServiceStatus, RegisterServiceCtrlHandlerExW, SC_HANDLE,
                SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SERVICE_ACCEPT_SHUTDOWN,
                SERVICE_ACCEPT_STOP, SERVICE_AUTO_START, SERVICE_CHANGE_CONFIG,
                SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP,
                SERVICE_ERROR_NORMAL, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING,
                SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE,
                SERVICE_STATUS_HANDLE, SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED,
                SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus,
                StartServiceCtrlDispatcherW, StartServiceW,
            },
        },
        UI::Shell::IsUserAnAdmin,
    },
    core::{PCWSTR, PWSTR},
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
const CONFIG_SDDL: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x120089;;;BU)";
const RULES_LOCKED_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BA)";
const RULES_EDITABLE_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;0x1301bf;;;BA)(A;OICI;0x1301bf;;;BU)";
const DELETE_ACCESS: u32 = 0x0001_0000;
const WRITE_DAC_ACCESS: u32 = 0x0004_0000;
const READ_CONTROL_ACCESS: u32 = 0x0002_0000;
const SERVICE_CONTROL_RIGHTS: u32 = SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP;

static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);
static CURRENT_STATE: AtomicU32 = AtomicU32::new(SERVICE_START_PENDING.0);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static RUNTIME: OnceLock<Mutex<Option<Arc<RuntimeState>>>> = OnceLock::new();

pub use crate::service_paths::ServicePaths;

pub fn service_paths() -> Result<ServicePaths, std::io::Error> {
    crate::service_paths::service_paths()
}

pub fn manage(command: crate::ServiceCommand) -> Result<(), Box<dyn Error>> {
    if matches!(
        &command,
        crate::ServiceCommand::Install
            | crate::ServiceCommand::Uninstall
            | crate::ServiceCommand::PrepareUpgrade { .. }
    ) && !unsafe { IsUserAnAdmin() }.as_bool()
    {
        return Err("service management requires an elevated administrator".into());
    }

    match command {
        crate::ServiceCommand::Start => start_installed_service(),
        crate::ServiceCommand::Stop => stop_installed_service(),
        crate::ServiceCommand::Install => install_or_update_service(),
        crate::ServiceCommand::Uninstall => uninstall_service(),
        crate::ServiceCommand::PrepareUpgrade {
            install_dir,
            error_file,
        } => {
            let result = prepare_upgrade(&install_dir);
            if let Err(error) = result {
                if let Err(write_error) = fs::write(&error_file, error.to_string()) {
                    return Err(format!(
                        "{error}; additionally could not write the upgrade failure details to {}: {write_error}",
                        error_file.display()
                    )
                    .into());
                }
                return Err(error);
            }
            Ok(())
        }
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
        SERVICE_CHANGE_CONFIG
            | SERVICE_QUERY_STATUS
            | SERVICE_START
            | SERVICE_STOP
            | READ_CONTROL_ACCESS
            | WRITE_DAC_ACCESS,
    ) {
        Ok(service) => {
            stop_handle(&service)?;
            let changed = unsafe {
                ChangeServiceConfigW(
                    service.0,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR::from_raw(binary_path.as_ptr()),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::from_raw(display_name.as_ptr()),
                )
            };
            changed.map_err(|error| {
                last_error_with_source("could not update the DnsShunt service", error)
            })?;
            service
        }
        Err(error) if win32_error_io(&error) == ERROR_SERVICE_DOES_NOT_EXIST.0 => {
            let service_name = wide("DnsShunt");
            let handle = unsafe {
                CreateServiceW(
                    manager.0,
                    PCWSTR::from_raw(service_name.as_ptr()),
                    PCWSTR::from_raw(display_name.as_ptr()),
                    SERVICE_CHANGE_CONFIG
                        | SERVICE_QUERY_STATUS
                        | SERVICE_START
                        | SERVICE_STOP
                        | READ_CONTROL_ACCESS
                        | WRITE_DAC_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    PCWSTR::from_raw(binary_path.as_ptr()),
                    PCWSTR::null(),
                    None,
                    PCWSTR::null(),
                    PCWSTR::null(),
                    PCWSTR::null(),
                )
            };
            ServiceHandle(handle.map_err(|error| {
                last_error_with_source("could not create the DnsShunt service", error)
            })?)
        }
        Err(error) => return Err(error.into()),
    };

    grant_service_control_to_users(&service)?;

    if let Err(error) = unsafe { StartServiceW(service.0, None) }
        && win32_error(&error) != ERROR_SERVICE_ALREADY_RUNNING.0
    {
        return Err(format!("could not start the DnsShunt service: {error}").into());
    }
    wait_for_service_state(&service, SERVICE_RUNNING, "DnsShunt")?;
    Ok(())
}

fn start_installed_service() -> Result<(), Box<dyn Error>> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service = open_service(&manager, SERVICE_QUERY_STATUS | SERVICE_START)?;
    if let Err(error) = unsafe { StartServiceW(service.0, None) }
        && win32_error(&error) != ERROR_SERVICE_ALREADY_RUNNING.0
    {
        return Err(format!("could not start the DnsShunt service: {error}").into());
    }
    wait_for_service_state(&service, SERVICE_RUNNING, "DnsShunt")
}

fn stop_installed_service() -> Result<(), Box<dyn Error>> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service = match open_service(&manager, SERVICE_QUERY_STATUS | SERVICE_STOP) {
        Ok(service) => service,
        Err(error) if win32_error_io(&error) == ERROR_SERVICE_DOES_NOT_EXIST.0 => {
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
            unsafe { DeleteService(service.0) }.map_err(|error| {
                last_error_with_source("could not delete the DnsShunt service", error)
            })?;
        }
        Err(error) if win32_error_io(&error) == ERROR_SERVICE_DOES_NOT_EXIST.0 => {}
        Err(error) => return Err(error.into()),
    }
    let install_dir = std::env::current_exe()?
        .parent()
        .ok_or("could not locate the application directory")?
        .to_path_buf();
    stop_windivert_driver(&manager, &install_dir)?;
    unregister_event_source()?;
    Ok(())
}

fn prepare_upgrade(install_dir: &Path) -> Result<(), Box<dyn Error>> {
    let manager = open_manager(SC_MANAGER_CONNECT)?;
    let service = match open_named_service(
        &manager,
        "DnsShunt",
        SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
    ) {
        Ok(service) => Some(service),
        Err(error) if win32_error_io(&error) == ERROR_SERVICE_DOES_NOT_EXIST.0 => None,
        Err(error) => return Err(error.into()),
    };
    let was_running = if let Some(service) = &service {
        query_service_state(service, "DnsShunt")? == SERVICE_RUNNING
    } else {
        false
    };

    let result = (|| {
        if let Some(service) = &service {
            stop_named_handle(service, "DnsShunt")?;
        }
        stop_windivert_driver(&manager, install_dir)
    })();
    if let Err(error) = result {
        if was_running
            && let Some(service) = &service
            && let Err(restore_error) = start_named_handle(service, "DnsShunt")
        {
            return Err(format!(
                "{error}; additionally failed to restore the previously running DnsShunt service: {restore_error}"
            )
            .into());
        }
        return Err(error);
    }
    Ok(())
}

struct ServiceHandle(SC_HANDLE);

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseServiceHandle(self.0);
        }
    }
}

fn open_manager(access: u32) -> Result<ServiceHandle, std::io::Error> {
    unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), access) }
        .map(ServiceHandle)
        .map_err(win_error_to_io)
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
    unsafe { OpenServiceW(manager.0, PCWSTR::from_raw(name.as_ptr()), access) }
        .map(ServiceHandle)
        .map_err(win_error_to_io)
}

fn stop_handle(service: &ServiceHandle) -> Result<(), Box<dyn Error>> {
    stop_named_handle(service, "DnsShunt")
}

fn stop_named_handle(service: &ServiceHandle, service_name: &str) -> Result<(), Box<dyn Error>> {
    let mut status = SERVICE_STATUS::default();
    unsafe { QueryServiceStatus(service.0, &mut status) }.map_err(|error| {
        last_error_with_source(
            &format!("could not query the {service_name} service state"),
            error,
        )
    })?;
    if status.dwCurrentState != SERVICE_STOP_PENDING
        && let Err(error) = unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) }
        && win32_error(&error) != ERROR_SERVICE_NOT_ACTIVE.0
    {
        return Err(format!("could not stop the {service_name} service: {error}").into());
    }
    wait_for_service_state(service, SERVICE_STOPPED, service_name)
}

fn query_service_state(
    service: &ServiceHandle,
    service_name: &str,
) -> Result<SERVICE_STATUS_CURRENT_STATE, Box<dyn Error>> {
    let mut status = SERVICE_STATUS::default();
    unsafe { QueryServiceStatus(service.0, &mut status) }.map_err(|error| {
        last_error_with_source(
            &format!("could not query the {service_name} service state"),
            error,
        )
    })?;
    Ok(status.dwCurrentState)
}

fn start_named_handle(service: &ServiceHandle, service_name: &str) -> Result<(), Box<dyn Error>> {
    if let Err(error) = unsafe { StartServiceW(service.0, None) }
        && win32_error(&error) != ERROR_SERVICE_ALREADY_RUNNING.0
    {
        return Err(format!("could not start the {service_name} service: {error}").into());
    }
    wait_for_service_state(service, SERVICE_RUNNING, service_name)
}

fn wait_for_service_state(
    service: &ServiceHandle,
    expected_state: SERVICE_STATUS_CURRENT_STATE,
    service_name: &str,
) -> Result<(), Box<dyn Error>> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let mut status = SERVICE_STATUS::default();
        unsafe { QueryServiceStatus(service.0, &mut status) }.map_err(|error| {
            last_error_with_source(
                &format!("could not query the {service_name} service state"),
                error,
            )
        })?;
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
                service_name, expected_state.0, state.0
            )
            .into());
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

fn stop_windivert_driver(
    manager: &ServiceHandle,
    install_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let driver = match open_named_service(
        manager,
        "WinDivert",
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_STOP,
    ) {
        Ok(driver) => driver,
        Err(error) if win32_error_io(&error) == ERROR_SERVICE_DOES_NOT_EXIST.0 => {
            eprintln!("WinDivert driver service is not registered; nothing to stop.");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let image_path = service_binary_path(&driver)?;
    eprintln!("WinDivert service image path: {image_path}");

    if !driver_image_matches_install_dir(&image_path, install_dir)? {
        eprintln!("WinDivert is registered from a different path; leaving it running.");
        return Ok(());
    }

    let mut status = SERVICE_STATUS::default();
    unsafe { QueryServiceStatus(driver.0, &mut status) }.map_err(|error| {
        last_error_with_source("could not query the WinDivert driver state", error)
    })?;
    if status.dwCurrentState == SERVICE_STOPPED {
        eprintln!("The installed WinDivert driver is already stopped.");
        return Ok(());
    }

    eprintln!("Stopping the WinDivert driver loaded from the install directory.");
    stop_named_handle(&driver, "WinDivert")
}

fn driver_image_matches_install_dir(
    image_path: &str,
    install_dir: &Path,
) -> Result<bool, Box<dyn Error>> {
    let image_path = normalize_driver_image_path(image_path)?;
    let expected_path = std::fs::canonicalize(install_dir.join("WinDivert64.sys"))?;
    Ok(image_path
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected_path.to_string_lossy()))
}

fn service_binary_path(service: &ServiceHandle) -> Result<String, Box<dyn Error>> {
    let mut bytes_needed = 0;
    let probe = unsafe { QueryServiceConfigW(service.0, None, 0, &mut bytes_needed) };
    if bytes_needed == 0
        && probe
            .as_ref()
            .is_err_and(|error| win32_error(error) != ERROR_INSUFFICIENT_BUFFER.0)
    {
        return Err(probe.unwrap_err().into());
    }

    let word_count = (bytes_needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; word_count];
    let buffer_size = std::mem::size_of_val(buffer.as_slice()) as u32;
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    // The API fills this aligned buffer and points lpBinaryPathName into it.
    unsafe { QueryServiceConfigW(service.0, Some(config), buffer_size, &mut bytes_needed) }
        .map_err(|error| {
            last_error_with_source("could not query the WinDivert driver image path", error)
        })?;

    let binary_path = unsafe { (*config).lpBinaryPathName.0 };
    if binary_path.is_null() {
        return Err("WinDivert driver has no registered image path".into());
    }
    let mut length = 0;
    // QueryServiceConfigW points into the live buffer above and returns UTF-16.
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

    set_path_security_owned(data_dir, PROGRAM_DATA_SDDL, "BA")?;

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
    set_path_security_owned(&paths.config, CONFIG_SDDL, "BA")?;
    crate::config::Config::load(&paths.config).map_err(|error| -> Box<dyn Error> {
        format!(
            "service configuration is invalid at {}: {error}",
            paths.config.display()
        )
        .into()
    })?;
    crate::service_paths::migrate_rules(&paths)?;
    // The DACL grants stopped-service rule editing directly. Preserve the
    // existing owner; it may be SYSTEM from a previous service run.
    set_rules_edit_access_with_owner(&paths, true, None)?;
    Ok(())
}

pub(crate) struct RulesAccessGuard {
    paths: ServicePaths,
    active: bool,
}

impl RulesAccessGuard {
    pub(crate) fn lock(paths: ServicePaths) -> Result<Self, Box<dyn Error>> {
        set_rules_edit_access(&paths, false)?;
        Ok(Self {
            paths,
            active: true,
        })
    }

    pub(crate) fn restore(&mut self) -> Result<(), Box<dyn Error>> {
        set_rules_edit_access(&self.paths, true)?;
        self.active = false;
        Ok(())
    }
}

impl Drop for RulesAccessGuard {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = set_rules_edit_access(&self.paths, true)
        {
            log_error(&format!("could not restore rules edit access: {error}"));
        }
    }
}

fn set_rules_edit_access(paths: &ServicePaths, editable: bool) -> Result<(), Box<dyn Error>> {
    set_rules_edit_access_with_owner(paths, editable, Some("SY"))
}

fn set_rules_edit_access_with_owner(
    paths: &ServicePaths,
    editable: bool,
    owner: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let directory_sddl = if editable {
        RULES_EDITABLE_SDDL
    } else {
        RULES_LOCKED_SDDL
    };
    let file_sddl = if editable {
        "D:P(A;;FA;;;SY)(A;;0x1301bf;;;BA)(A;;0x1301bf;;;BU)"
    } else {
        "D:P(A;;FA;;;SY)(A;;0x1301bf;;;BA)"
    };
    set_path_security_with_owner(&paths.rules_dir, directory_sddl, owner)?;
    if paths.rules.exists()
        && let Err(error) = set_path_security_with_owner(&paths.rules, file_sddl, owner)
    {
        if !editable {
            let _ = set_path_security_with_owner(&paths.rules_dir, RULES_EDITABLE_SDDL, owner);
        }
        return Err(error);
    }
    Ok(())
}

fn set_path_security_owned(path: &Path, sddl: &str, owner: &str) -> Result<(), Box<dyn Error>> {
    set_path_security_with_owner(path, sddl, Some(owner))
}

fn set_path_security_with_owner(
    path: &Path,
    sddl: &str,
    owner: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let descriptor_text = wide(&match owner {
        Some(owner) => format!("O:{owner}{sddl}"),
        None => sddl.to_owned(),
    });
    let mut descriptor = PSECURITY_DESCRIPTOR(ptr::null_mut());
    if let Err(error) = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(descriptor_text.as_ptr()),
            1,
            &mut descriptor,
            None,
        )
    } {
        return Err(last_error_with_source(
            "could not build the requested file permissions",
            error,
        ));
    }
    let path_wide = wide(&path.to_string_lossy());
    let mut security_information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let mut owner_matches = owner.is_none();
    if owner.is_some() {
        let mut current_owner = PSID(ptr::null_mut());
        let mut current_descriptor = PSECURITY_DESCRIPTOR(ptr::null_mut());
        let result = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR::from_raw(path_wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION,
                Some(&mut current_owner),
                None,
                None,
                None,
                &mut current_descriptor,
            )
        };
        if result.0 != 0 {
            free_local(descriptor.0);
            return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
        }

        let mut requested_owner = PSID(ptr::null_mut());
        let mut owner_defaulted = windows::core::BOOL(0);
        let owner_read = unsafe {
            GetSecurityDescriptorOwner(descriptor, &mut requested_owner, &mut owner_defaulted)
        };
        if owner_read.is_err() || requested_owner.is_invalid() || current_owner.is_invalid() {
            free_local(current_descriptor.0);
            free_local(descriptor.0);
            return Err("could not read the requested or current owner".into());
        }

        owner_matches = unsafe { EqualSid(current_owner, requested_owner) }.is_ok();
        free_local(current_descriptor.0);
        if !owner_matches {
            security_information |= OWNER_SECURITY_INFORMATION;
        }
    }
    if owner_matches {
        match path_dacl_sddl(path) {
            Ok(current_dacl) if current_dacl == sddl => {
                free_local(descriptor.0);
                return Ok(());
            }
            Ok(_) => {}
            Err(error) => {
                free_local(descriptor.0);
                return Err(error);
            }
        }
    }
    let secured = unsafe {
        SetFileSecurityW(
            PCWSTR::from_raw(path_wide.as_ptr()),
            security_information,
            descriptor,
        )
    };
    free_local(descriptor.0);
    if !secured.as_bool() {
        return Err(format!(
            "could not set permissions on {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )
        .into());
    }
    Ok(())
}

fn grant_service_control_to_users(service: &ServiceHandle) -> Result<(), Box<dyn Error>> {
    let mut old_acl: *mut ACL = ptr::null_mut();
    let mut security_descriptor = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let result = unsafe {
        GetSecurityInfo(
            windows::Win32::Foundation::HANDLE(service.0.0),
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut old_acl),
            None,
            Some(&mut security_descriptor),
        )
    };
    if result.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
    }

    let users_sid_text = wide("S-1-5-32-545");
    let mut users_sid = PSID(ptr::null_mut());
    if let Err(error) =
        unsafe { ConvertStringSidToSidW(PCWSTR::from_raw(users_sid_text.as_ptr()), &mut users_sid) }
    {
        free_local(security_descriptor.0);
        return Err(last_error_with_source(
            "could not resolve the built-in Users SID",
            error,
        ));
    }
    let mut entry = EXPLICIT_ACCESS_W::default();
    unsafe { BuildTrusteeWithSidW(&mut entry.Trustee, Some(users_sid)) };
    entry.grfAccessPermissions = SERVICE_CONTROL_RIGHTS;
    entry.grfAccessMode = GRANT_ACCESS;
    let mut new_acl: *mut ACL = ptr::null_mut();
    let result = unsafe {
        SetEntriesInAclW(
            Some(std::slice::from_ref(&entry)),
            Some(old_acl),
            &mut new_acl,
        )
    };
    if result.0 != 0 {
        free_local(users_sid.0);
        free_local(security_descriptor.0);
        return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
    }
    let result = unsafe {
        SetSecurityInfo(
            windows::Win32::Foundation::HANDLE(service.0.0),
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl),
            None,
        )
    };
    free_local(users_sid.0);
    free_local(new_acl.cast());
    free_local(security_descriptor.0);
    if result.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
    }
    Ok(())
}

fn path_dacl_sddl(path: &Path) -> Result<String, Box<dyn Error>> {
    let path = wide(&path.to_string_lossy());
    let mut descriptor = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let result = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(path.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    if result.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
    }
    let mut text = PWSTR::null();
    let converted = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            None,
        )
    };
    free_local(descriptor.0);
    converted.map_err(|error| {
        last_error_with_source("could not read the test security descriptor", error)
    })?;
    let mut length = 0;
    // The returned security string is NUL-terminated and owned by LocalAlloc.
    unsafe {
        while *text.0.add(length) != 0 {
            length += 1;
        }
        let value = String::from_utf16_lossy(std::slice::from_raw_parts(text.0, length));
        free_local(text.0.cast());
        Ok(value)
    }
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
    let mut key = HKEY(ptr::null_mut());
    let created = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR::from_raw(key_path.as_ptr()),
            None,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        )
    };
    if created.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(created.0 as i32).into());
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
    let result = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR::from_raw(key_path.as_ptr())) };
    if result.0 != 0 && result != ERROR_FILE_NOT_FOUND {
        return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
    }
    Ok(())
}

fn set_registry_value(
    key: HKEY,
    name: &str,
    value_type: REG_VALUE_TYPE,
    value: &[u16],
) -> Result<(), Box<dyn Error>> {
    let name = wide(name);
    let bytes = value
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let result = unsafe {
        RegSetValueExW(
            key,
            PCWSTR::from_raw(name.as_ptr()),
            None,
            value_type,
            Some(&bytes),
        )
    };
    if result.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
    }
    Ok(())
}

fn set_registry_dword(key: HKEY, name: &str, value: u32) -> Result<(), Box<dyn Error>> {
    let name = wide(name);
    let bytes = value.to_le_bytes();
    let result = unsafe {
        RegSetValueExW(
            key,
            PCWSTR::from_raw(name.as_ptr()),
            None,
            REG_DWORD,
            Some(&bytes),
        )
    };
    if result.0 != 0 {
        return Err(std::io::Error::from_raw_os_error(result.0 as i32).into());
    }
    Ok(())
}

fn wide(value: &str) -> Vec<u16> {
    std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn last_error_with_source(context: &str, error: windows::core::Error) -> Box<dyn Error> {
    format!("{context}: {}", win_error_to_io(error)).into()
}

fn win32_error(error: &windows::core::Error) -> u32 {
    error.code().0 as u32 & 0xffff
}

fn win32_error_io(error: &std::io::Error) -> u32 {
    error.raw_os_error().unwrap_or_default() as u32
}

fn win_error_to_io(error: windows::core::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(win32_error(&error) as i32)
}

fn free_local(pointer: *mut core::ffi::c_void) {
    // These pointers are allocated by Windows security APIs using LocalAlloc.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(pointer)));
    }
}

pub fn dispatch() -> Result<(), Box<dyn Error>> {
    STOP_REQUESTED.store(false, Ordering::Release);
    let entries = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(SERVICE_NAME.as_ptr() as *mut u16),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::null(),
            lpServiceProc: None,
        },
    ];
    unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) }.map_err(Into::into)
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

fn log_event(
    event_type: windows::Win32::System::EventLog::REPORT_EVENT_TYPE,
    event_id: u32,
    message: &str,
) {
    let Ok(source) =
        (unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR::from_raw(EVENT_SOURCE.as_ptr())) })
    else {
        return;
    };
    let message: Vec<u16> = message.encode_utf16().chain(Some(0)).collect();
    let strings = [PCWSTR::from_raw(message.as_ptr())];
    unsafe {
        let _ = ReportEventW(
            source,
            event_type,
            0,
            event_id,
            None,
            0,
            Some(&strings),
            None,
        );
        let _ = DeregisterEventSource(source);
    }
}

// The service control manager invokes this callback with the system ABI.
unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let status_handle = unsafe {
        RegisterServiceCtrlHandlerExW(
            PCWSTR::from_raw(SERVICE_NAME.as_ptr()),
            Some(control_handler),
            None,
        )
    };
    let status_handle = match status_handle {
        Ok(handle) => handle,
        Err(error) => {
            log_error(&format!(
                "could not register service control handler: {error}"
            ));
            return;
        }
    };
    STATUS_HANDLE.store(status_handle.0 as isize, Ordering::Release);
    report_status(SERVICE_START_PENDING, 0, 0);
    log_information("service startup requested");

    match crate::run_service() {
        Ok(()) => {
            log_information("service stopped");
            report_status(SERVICE_STOPPED, 0, 0);
        }
        Err(error) => {
            log_error(&format!("service startup or runtime failed: {error}"));
            report_status(SERVICE_STOPPED, ERROR_SERVICE_SPECIFIC_ERROR.0, 1);
        }
    }
    STATUS_HANDLE.store(0, Ordering::Release);
    *RUNTIME
        .get_or_init(|| Mutex::new(None))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

// The SCM invokes this callback while dispatching control requests.
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
            report_status(
                SERVICE_STATUS_CURRENT_STATE(CURRENT_STATE.load(Ordering::Acquire)),
                0,
                0,
            );
            0
        }
        _ => 1,
    }
}

fn report_status(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u32, service_exit_code: u32) {
    CURRENT_STATE.store(state.0, Ordering::Release);
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
        let _ = SetServiceStatus(SERVICE_STATUS_HANDLE(handle as *mut _), &status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn driver_image_matching_normalizes_paths_and_rejects_other_installations() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "dns-shunt-driver-path-{}-{nonce}",
            std::process::id()
        ));
        let install_dir = root.join("DNS Shunt");
        let other_install_dir = root.join("Other DNS Shunt");
        fs::create_dir_all(&install_dir).unwrap();
        fs::create_dir_all(&other_install_dir).unwrap();
        let driver = install_dir.join("WinDivert64.sys");
        fs::write(&driver, b"driver").unwrap();
        fs::write(other_install_dir.join("WinDivert64.sys"), b"driver").unwrap();

        let quoted_path = format!("\"{}\"", driver.display());
        assert!(driver_image_matches_install_dir(&quoted_path, &install_dir).unwrap());

        let nt_path = format!(r"\??\{}", driver.display());
        assert!(driver_image_matches_install_dir(&nt_path, &install_dir).unwrap());
        let extended_path = format!(r"\\?\{}", driver.display());
        assert!(driver_image_matches_install_dir(&extended_path, &install_dir).unwrap());
        let differently_cased_path = driver.to_string_lossy().to_lowercase();
        assert!(driver_image_matches_install_dir(&differently_cased_path, &install_dir).unwrap());
        assert!(
            !driver_image_matches_install_dir(&driver.to_string_lossy(), &other_install_dir)
                .unwrap()
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rules_acl_toggles_users_modify_without_changing_config_acl() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let program_data = std::env::temp_dir().join(format!(
            "dns-shunt-service-acl-{}-{nonce}",
            std::process::id()
        ));
        let paths = crate::service_paths::paths_under(&program_data);
        fs::create_dir_all(&paths.rules_dir).unwrap();
        fs::write(&paths.config, b"ttl = 60\n").unwrap();
        fs::write(&paths.rules, b"[]\n").unwrap();

        set_path_security_with_owner(&paths.config, CONFIG_SDDL, None).unwrap();
        let config_acl = path_dacl_sddl(&paths.config).unwrap();
        assert!(config_acl.contains(";;;BU)"));
        assert!(!config_acl.contains("0x1301bf;;;BU"));

        set_rules_edit_access_with_owner(&paths, true, None).unwrap();
        set_rules_edit_access_with_owner(&paths, true, None).unwrap();
        assert!(
            path_dacl_sddl(&paths.rules_dir)
                .unwrap()
                .contains("0x1301bf;;;BU")
        );
        assert!(
            path_dacl_sddl(&paths.rules)
                .unwrap()
                .contains("0x1301bf;;;BU")
        );

        set_rules_edit_access_with_owner(&paths, false, None).unwrap();
        assert!(!path_dacl_sddl(&paths.rules_dir).unwrap().contains(";;;BU)"));
        assert!(!path_dacl_sddl(&paths.rules).unwrap().contains(";;;BU)"));
        assert_eq!(path_dacl_sddl(&paths.config).unwrap(), config_acl);

        set_rules_edit_access_with_owner(&paths, true, None).unwrap();
        fs::remove_dir_all(program_data).unwrap();
    }
}
