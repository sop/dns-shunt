#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

#[cfg(target_os = "windows")]
#[path = "../config.rs"]
#[allow(dead_code)]
mod config;
#[cfg(target_os = "windows")]
#[path = "../service_paths.rs"]
#[allow(dead_code)]
mod service_paths;
#[cfg(target_os = "windows")]
#[path = "../tray_state.rs"]
mod tray_state;

#[cfg(target_os = "windows")]
mod tray {
    use std::{
        ffi::OsStr,
        os::windows::ffi::OsStrExt,
        path::PathBuf,
        ptr,
        sync::{Mutex, OnceLock},
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_SERVICE_DOES_NOT_EXIST, HWND, LPARAM, LRESULT, WPARAM},
        System::{
            LibraryLoader::GetModuleHandleW,
            Services::{
                CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW,
                QueryServiceStatus, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS,
                SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS,
                SERVICE_STOP, SERVICE_STOP_PENDING, SERVICE_STOPPED, StartServiceW,
            },
        },
        UI::{
            Shell::{
                NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
                Shell_NotifyIconW, ShellExecuteW,
            },
            WindowsAndMessaging::{
                AppendMenuW, CreatePopupMenu, CreateWindowExW, DefWindowProcW, DestroyMenu,
                DispatchMessageW, FindWindowW, GetCursorPos, GetMessageW, LoadIconW, MB_ICONERROR,
                MB_OK, MF_GRAYED, MF_STRING, MessageBoxW, PostMessageW, PostQuitMessage,
                RegisterClassW, SW_HIDE, SW_SHOWNORMAL, SetForegroundWindow, SetTimer, ShowWindow,
                TPM_RETURNCMD, TrackPopupMenu, TranslateMessage, WM_CLOSE, WM_COMMAND,
                WM_CONTEXTMENU, WM_DESTROY, WM_LBUTTONDBLCLK, WM_NULL, WM_RBUTTONUP, WM_TIMER,
                WNDCLASSW, WS_OVERLAPPED,
            },
        },
    };

    const ICON_ID: u32 = 1;
    const ICON_CALLBACK: u32 = 0x8001;
    const TIMER_ID: usize = 1;
    const MENU_START: u32 = 100;
    const MENU_STOP: u32 = 101;
    const MENU_GUI: u32 = 102;
    const MENU_RULES: u32 = 103;
    const MENU_EXIT: u32 = 104;
    const STATUS_TEXT: u32 = 0;

    use super::tray_state::ServiceState;

    struct AppState {
        hwnd: isize,
        config: PathBuf,
        rules: PathBuf,
        state: ServiceState,
    }

    static APP: OnceLock<Mutex<AppState>> = OnceLock::new();

    pub fn run() -> Result<(), String> {
        let paths = super::service_paths::service_paths().map_err(|error| error.to_string())?;
        APP.set(Mutex::new(AppState {
            hwnd: 0,
            config: paths.config,
            rules: paths.rules,
            state: ServiceState::Unknown,
        }))
        .map_err(|_| "tray application is already running".to_owned())?;

        let instance = unsafe { GetModuleHandleW(ptr::null()) };
        if instance.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let class_name = wide("DnsShuntTrayWindow");
        if !unsafe { FindWindowW(class_name.as_ptr(), ptr::null()) }.is_null() {
            return Ok(());
        }
        let title = wide("DNS Shunt");
        let window_class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: class_name.as_ptr(),
            ..Default::default()
        };
        if unsafe { RegisterClassW(&window_class) } == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        let hwnd = unsafe {
            CreateWindowExW(
                0,
                class_name.as_ptr(),
                title.as_ptr(),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                instance,
                ptr::null(),
            )
        };
        if hwnd.is_null() {
            return Err(std::io::Error::last_os_error().to_string());
        }
        with_app(|app| app.hwnd = hwnd as isize);

        add_tray_icon(hwnd)?;
        unsafe {
            let _ = ShowWindow(hwnd, SW_HIDE);
            SetTimer(hwnd, TIMER_ID, 2_000, None);
            let _ = PostMessageW(hwnd, WM_TIMER, TIMER_ID, 0);
        }

        let mut message = unsafe { std::mem::zeroed() };
        loop {
            let result = unsafe { GetMessageW(&mut message, ptr::null_mut(), 0, 0) };
            if result <= 0 {
                if result < 0 {
                    return Err(std::io::Error::last_os_error().to_string());
                }
                break;
            }
            unsafe {
                let _ = TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        }
        Ok(())
    }

    unsafe extern "system" fn window_proc(
        hwnd: HWND,
        message: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match message {
            ICON_CALLBACK => {
                let event = lparam as u32;
                if event == WM_RBUTTONUP || event == WM_CONTEXTMENU {
                    show_menu(hwnd);
                } else if event == WM_LBUTTONDBLCLK {
                    refresh_state(hwnd, false);
                    if current_state() == ServiceState::Running {
                        open_gui(hwnd);
                    }
                }
                0
            }
            WM_TIMER if wparam == TIMER_ID => {
                refresh_state(hwnd, true);
                0
            }
            WM_COMMAND => {
                dispatch_command(hwnd, (wparam & 0xffff) as u32);
                0
            }
            WM_DESTROY => {
                unsafe {
                    let _ = SetTimer(hwnd, TIMER_ID, 0, None);
                    remove_tray_icon(hwnd);
                    PostQuitMessage(0);
                }
                0
            }
            WM_CLOSE => {
                unsafe { windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd) };
                0
            }
            _ => unsafe { DefWindowProcW(hwnd, message, wparam, lparam) },
        }
    }

    fn add_tray_icon(hwnd: HWND) -> Result<(), String> {
        let instance = unsafe { GetModuleHandleW(ptr::null()) };
        let icon_resource = ptr::without_provenance::<u16>(1);
        let icon = unsafe { LoadIconW(instance, icon_resource) };
        if icon.is_null() {
            return Err("could not load the DNS Shunt application icon".to_owned());
        }
        let mut data = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ICON_ID,
            uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
            uCallbackMessage: ICON_CALLBACK,
            hIcon: icon,
            ..Default::default()
        };
        set_tip(&mut data, "DNS Shunt: Checking service");
        if unsafe { Shell_NotifyIconW(NIM_ADD, &data) } == 0 {
            return Err("could not add the DNS Shunt notification icon".to_owned());
        }
        Ok(())
    }

    fn remove_tray_icon(hwnd: HWND) {
        let data = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ICON_ID,
            ..Default::default()
        };
        unsafe {
            let _ = Shell_NotifyIconW(NIM_DELETE, &data);
        }
    }

    fn set_tip(data: &mut NOTIFYICONDATAW, tip: &str) {
        for (slot, value) in data.szTip.iter_mut().zip(wide(tip)) {
            *slot = value;
        }
    }

    fn refresh_state(hwnd: HWND, notify: bool) {
        let new_state = match query_state() {
            Ok(state) => state,
            Err(error) => {
                let old_state = current_state();
                if notify && old_state != ServiceState::Error {
                    show_error(
                        hwnd,
                        &format!("Could not query the DNS Shunt service. {error}"),
                    );
                }
                ServiceState::Error
            }
        };
        let old_state = current_state();
        with_app(|app| app.state = new_state);
        update_tip(hwnd, new_state);
        if notify && new_state == ServiceState::Missing && old_state != ServiceState::Missing {
            show_error(
                hwnd,
                "The DNS Shunt service is not installed. Run the DNS Shunt installer as an administrator.",
            );
        }
    }

    fn update_tip(hwnd: HWND, state: ServiceState) {
        let text = match state {
            ServiceState::Unknown => "DNS Shunt: Checking service",
            ServiceState::Stopped => "DNS Shunt: Stopped",
            ServiceState::Running => "DNS Shunt: Running",
            ServiceState::Transitional => "DNS Shunt: Changing state",
            ServiceState::Missing => "DNS Shunt: Not installed",
            ServiceState::Error => "DNS Shunt: Status unavailable",
        };
        let mut data = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: ICON_ID,
            uFlags: NIF_TIP,
            ..Default::default()
        };
        set_tip(&mut data, text);
        unsafe {
            let _ = Shell_NotifyIconW(windows_sys::Win32::UI::Shell::NIM_MODIFY, &data);
        }
    }

    fn show_menu(hwnd: HWND) {
        refresh_state(hwnd, false);
        let state = current_state();
        let menu = unsafe { CreatePopupMenu() };
        if menu.is_null() {
            return;
        }
        let status_text = format!("DNS Shunt service: {}", state_label(state));
        append_menu(menu, &status_text, STATUS_TEXT, true);
        let actions = state.menu_availability();
        append_menu(menu, "Start Service", MENU_START, !actions.start);
        append_menu(menu, "Stop Service", MENU_STOP, !actions.stop);
        append_menu(menu, "Open GUI", MENU_GUI, !actions.open_gui);
        append_menu(menu, "Open Rules File", MENU_RULES, !actions.open_rules);
        append_menu(menu, "Exit", MENU_EXIT, false);

        let mut point = unsafe { std::mem::zeroed() };
        unsafe {
            let _ = GetCursorPos(&mut point);
            let _ = SetForegroundWindow(hwnd);
            let command =
                TrackPopupMenu(menu, TPM_RETURNCMD, point.x, point.y, 0, hwnd, ptr::null());
            let _ = PostMessageW(hwnd, WM_NULL, 0, 0);
            let _ = DestroyMenu(menu);
            if command != 0 {
                dispatch_command(hwnd, command as u32);
            }
        }
    }

    fn append_menu(
        menu: windows_sys::Win32::UI::WindowsAndMessaging::HMENU,
        label: &str,
        id: u32,
        disabled: bool,
    ) {
        let flags = MF_STRING | if disabled { MF_GRAYED } else { 0 };
        unsafe {
            let _ = AppendMenuW(menu, flags, id as usize, wide(label).as_ptr());
        }
    }

    fn state_label(state: ServiceState) -> &'static str {
        match state {
            ServiceState::Unknown => "Checking",
            ServiceState::Stopped => "Stopped",
            ServiceState::Running => "Running",
            ServiceState::Transitional => "Changing state",
            ServiceState::Missing => "Not installed",
            ServiceState::Error => "Status unavailable",
        }
    }

    fn dispatch_command(hwnd: HWND, command: u32) {
        match command {
            MENU_START => {
                if current_state() == ServiceState::Stopped
                    && let Err(error) = start_service()
                {
                    show_error(
                        hwnd,
                        &format!(
                            "Could not start the DNS Shunt service. Check the Application event log and service configuration. {error}"
                        ),
                    );
                }
            }
            MENU_STOP => {
                if current_state() == ServiceState::Running
                    && let Err(error) = stop_service()
                {
                    show_error(
                        hwnd,
                        &format!("Could not stop the DNS Shunt service. {error}"),
                    );
                }
            }
            MENU_GUI => {
                if current_state() == ServiceState::Running {
                    open_gui(hwnd);
                }
            }
            MENU_RULES => {
                if current_state() == ServiceState::Stopped {
                    open_rules(hwnd);
                }
            }
            MENU_EXIT => unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::DestroyWindow(hwnd);
            },
            _ => {}
        }
    }

    fn query_state() -> Result<ServiceState, String> {
        let manager = open_manager()?;
        let name = wide("DnsShunt");
        let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                unsafe { CloseServiceHandle(manager) };
                return Ok(ServiceState::Missing);
            }
            unsafe { CloseServiceHandle(manager) };
            return Err(error.to_string());
        }
        let mut status = SERVICE_STATUS::default();
        let queried = unsafe { QueryServiceStatus(service, &mut status) };
        let error = if queried == 0 {
            Some(std::io::Error::last_os_error().to_string())
        } else {
            None
        };
        unsafe {
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(manager);
        }
        if let Some(error) = error {
            return Err(error);
        }
        Ok(match status.dwCurrentState {
            SERVICE_STOPPED => ServiceState::Stopped,
            SERVICE_RUNNING => ServiceState::Running,
            SERVICE_START_PENDING | SERVICE_STOP_PENDING => ServiceState::Transitional,
            _ => ServiceState::Transitional,
        })
    }

    fn open_manager() -> Result<windows_sys::Win32::System::Services::SC_HANDLE, String> {
        let handle = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
        if handle.is_null() {
            Err(std::io::Error::last_os_error().to_string())
        } else {
            Ok(handle)
        }
    }

    fn start_service() -> Result<(), String> {
        let manager = open_manager()?;
        let name = wide("DnsShunt");
        let service =
            unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_START) };
        if service.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { CloseServiceHandle(manager) };
            return Err(error.to_string());
        }
        let started = unsafe { StartServiceW(service, 0, ptr::null()) };
        let error = if started == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(1056) {
                Some(error.to_string())
            } else {
                None
            }
        } else {
            None
        };
        unsafe {
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(manager);
        }
        error.map_or(Ok(()), Err)
    }

    fn stop_service() -> Result<(), String> {
        let manager = open_manager()?;
        let name = wide("DnsShunt");
        let service =
            unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_STOP) };
        if service.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe { CloseServiceHandle(manager) };
            return Err(error.to_string());
        }
        let mut status = SERVICE_STATUS::default();
        let result = unsafe { QueryServiceStatus(service, &mut status) };
        if result == 0 {
            let error = std::io::Error::last_os_error().to_string();
            unsafe {
                let _ = CloseServiceHandle(service);
                let _ = CloseServiceHandle(manager);
            }
            return Err(error);
        }
        let error = if status.dwCurrentState == SERVICE_STOPPED {
            None
        } else {
            let stopped = unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) };
            if stopped == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(1062) {
                    None
                } else {
                    Some(error.to_string())
                }
            } else {
                None
            }
        };
        unsafe {
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(manager);
        }
        error.map_or(Ok(()), Err)
    }

    fn open_gui(hwnd: HWND) {
        let config_path = with_app(|app| app.config.clone());
        let config = match super::config::Config::load(&config_path) {
            Ok(config) => config,
            Err(error) => {
                show_error(
                    hwnd,
                    &format!(
                        "The service configuration is invalid at {}. Repair config.toml before opening the GUI. {error}",
                        config_path.display()
                    ),
                );
                return;
            }
        };
        let url = wide(&config.gui_url());
        let operation = wide("open");
        let result = unsafe {
            ShellExecuteW(
                hwnd,
                operation.as_ptr(),
                url.as_ptr(),
                ptr::null(),
                ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if result as isize <= 32 {
            show_error(hwnd, "Windows could not open the configured GUI URL.");
        }
    }

    fn open_rules(hwnd: HWND) {
        let path = with_app(|app| app.rules.clone());
        let operation = wide("open");
        let file = wide(&path.to_string_lossy());
        let result = unsafe {
            ShellExecuteW(
                hwnd,
                operation.as_ptr(),
                file.as_ptr(),
                ptr::null(),
                ptr::null(),
                SW_SHOWNORMAL,
            )
        };
        if result as isize <= 32 {
            show_error(
                hwnd,
                &format!(
                    "Windows could not open the shared rules file at {}.",
                    path.display()
                ),
            );
        }
    }

    fn show_error(hwnd: HWND, message: &str) {
        unsafe {
            let _ = MessageBoxW(
                hwnd,
                wide(message).as_ptr(),
                wide("DNS Shunt").as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }

    fn current_state() -> ServiceState {
        with_app(|app| app.state)
    }

    fn with_app<T>(action: impl FnOnce(&mut AppState) -> T) -> T {
        let mut app = APP
            .get()
            .expect("tray state initialized")
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        action(&mut app)
    }

    fn wide(value: &str) -> Vec<u16> {
        OsStr::new(value).encode_wide().chain(Some(0)).collect()
    }
}

#[cfg(target_os = "windows")]
fn main() {
    if std::env::args().any(|argument| argument == "--exit") {
        let class_name = "DnsShuntTrayWindow"
            .encode_utf16()
            .chain(Some(0))
            .collect::<Vec<_>>();
        unsafe {
            let hwnd = windows_sys::Win32::UI::WindowsAndMessaging::FindWindowW(
                class_name.as_ptr(),
                std::ptr::null(),
            );
            if !hwnd.is_null() {
                let _ = windows_sys::Win32::UI::WindowsAndMessaging::SendMessageW(
                    hwnd,
                    windows_sys::Win32::UI::WindowsAndMessaging::WM_CLOSE,
                    0,
                    0,
                );
            }
        }
        return;
    }
    if let Err(error) = tray::run() {
        let wide = error.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
        unsafe {
            let _ = windows_sys::Win32::UI::WindowsAndMessaging::MessageBoxW(
                std::ptr::null_mut(),
                wide.as_ptr(),
                windows_sys::core::w!("DNS Shunt Tray"),
                windows_sys::Win32::UI::WindowsAndMessaging::MB_OK
                    | windows_sys::Win32::UI::WindowsAndMessaging::MB_ICONERROR,
            );
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {}
