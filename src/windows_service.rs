//! Windows SCM entry point. The console and SCM entry points share the daemon,
//! while stop/shutdown controls drive its normal graceful-shutdown path.

#[cfg(windows)]
mod native {
    use anyhow::{Context, Result, bail};
    use std::{
        ffi::c_void,
        sync::{
            Mutex,
            atomic::{AtomicBool, AtomicPtr, Ordering},
        },
    };
    use tokio::sync::Notify;

    type Runner = fn() -> Result<()>;
    static RUNNER: Mutex<Option<Runner>> = Mutex::new(None);
    static FAILURE: Mutex<Option<String>> = Mutex::new(None);
    static HANDLE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
    static STOP: AtomicBool = AtomicBool::new(false);
    static NOTIFY: Notify = Notify::const_new();
    static STATUS_LOCK: Mutex<()> = Mutex::new(());

    const STOPPED: u32 = 1;
    const START_PENDING: u32 = 2;
    const STOP_PENDING: u32 = 3;
    const RUNNING: u32 = 4;

    #[repr(C)]
    struct ServiceStatus {
        service_type: u32,
        current_state: u32,
        controls_accepted: u32,
        win32_exit_code: u32,
        service_specific_exit_code: u32,
        checkpoint: u32,
        wait_hint: u32,
    }
    #[repr(C)]
    struct ServiceTableEntry {
        name: *mut u16,
        entry: Option<unsafe extern "system" fn(u32, *mut *mut u16)>,
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn StartServiceCtrlDispatcherW(table: *const ServiceTableEntry) -> i32;
        fn RegisterServiceCtrlHandlerExW(
            name: *const u16,
            handler: Option<unsafe extern "system" fn(u32, u32, *mut c_void, *mut c_void) -> u32>,
            context: *mut c_void,
        ) -> *mut c_void;
        fn SetServiceStatus(handle: *mut c_void, status: *const ServiceStatus) -> i32;
    }

    fn report(state: u32, failed: bool) -> std::io::Result<()> {
        let _guard = STATUS_LOCK
            .lock()
            .map_err(|_| std::io::Error::other("Service status lock poisoned"))?;
        let status = ServiceStatus {
            service_type: 0x10, // SERVICE_WIN32_OWN_PROCESS
            current_state: state,
            controls_accepted: if state == RUNNING { 0x1 | 0x4 } else { 0 },
            win32_exit_code: if failed { 1066 } else { 0 }, // ERROR_SERVICE_SPECIFIC_ERROR
            service_specific_exit_code: u32::from(failed),
            checkpoint: if matches!(state, START_PENDING | STOP_PENDING) {
                1
            } else {
                0
            },
            wait_hint: if matches!(state, START_PENDING | STOP_PENDING) {
                30_000
            } else {
                0
            },
        };
        if unsafe { SetServiceStatus(HANDLE.load(Ordering::Acquire), &status) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    unsafe extern "system" fn control(
        code: u32,
        _event: u32,
        _data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        match code {
            1 | 5 => {
                // SERVICE_CONTROL_STOP / SERVICE_CONTROL_SHUTDOWN
                if !STOP.swap(true, Ordering::AcqRel) {
                    let _ = report(STOP_PENDING, false);
                    NOTIFY.notify_one();
                }
                0
            }
            4 => 0,   // SERVICE_CONTROL_INTERROGATE: SCM already knows the current status.
            _ => 120, // ERROR_CALL_NOT_IMPLEMENTED
        }
    }

    fn remember_error(error: impl std::fmt::Display) {
        if let Ok(mut failure) = FAILURE.lock() {
            *failure = Some(error.to_string());
        }
    }

    unsafe extern "system" fn service_main(argc: u32, argv: *mut *mut u16) {
        let fallback: Vec<u16> = "Custos".encode_utf16().chain(Some(0)).collect();
        // SCM supplies the registered service name as argv[0], including in CI's
        // temporary service. No command-line arguments are interpreted here.
        let name = if argc > 0 && !argv.is_null() {
            unsafe { *argv }
        } else {
            fallback.as_ptr() as *mut u16
        };
        let handle =
            unsafe { RegisterServiceCtrlHandlerExW(name, Some(control), std::ptr::null_mut()) };
        if handle.is_null() {
            remember_error(std::io::Error::last_os_error());
            return;
        }
        HANDLE.store(handle, Ordering::Release);
        let run = RUNNER.lock().ok().and_then(|mut runner| runner.take());
        let result = (|| -> Result<()> {
            report(START_PENDING, false)?;
            let run = run.context("Missing Windows service daemon entry point")?;
            report(RUNNING, false)?;
            // Never unwind through the foreign callback boundary.
            match std::panic::catch_unwind(run) {
                Ok(result) => result,
                Err(_) => anyhow::bail!("Windows service daemon panicked"),
            }
        })();
        if let Err(error) = &result {
            remember_error(error);
        }
        let _ = report(STOPPED, result.is_err());
        HANDLE.store(std::ptr::null_mut(), Ordering::Release);
    }

    pub fn dispatch(run: Runner) -> Result<()> {
        {
            let mut runner = RUNNER
                .lock()
                .map_err(|_| anyhow::anyhow!("Service runner lock poisoned"))?;
            if runner.is_some() {
                bail!("Windows service dispatcher already initialized");
            }
            *runner = Some(run);
        }
        STOP.store(false, Ordering::Release);
        let mut name: Vec<u16> = "Custos".encode_utf16().chain(Some(0)).collect();
        let entries = [
            ServiceTableEntry {
                name: name.as_mut_ptr(),
                entry: Some(service_main),
            },
            ServiceTableEntry {
                name: std::ptr::null_mut(),
                entry: None,
            },
        ];
        if unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) } == 0 {
            if let Ok(mut runner) = RUNNER.lock() {
                *runner = None;
            }
            return Err(std::io::Error::last_os_error()).context("Could not connect to Windows SCM; use `run` without --windows-service for a console daemon");
        }
        if let Some(error) = FAILURE.lock().ok().and_then(|mut failure| failure.take()) {
            bail!("Windows service failed: {error}");
        }
        Ok(())
    }

    pub async fn shutdown_requested() {
        while !STOP.load(Ordering::Acquire) {
            NOTIFY.notified().await;
        }
    }
}

#[cfg(windows)]
pub use native::{dispatch, shutdown_requested};

#[cfg(not(windows))]
pub fn dispatch(_run: fn() -> anyhow::Result<()>) -> anyhow::Result<()> {
    anyhow::bail!("The Windows service entry point is only available on Windows")
}

#[cfg(not(windows))]
pub async fn shutdown_requested() {
    std::future::pending::<()>().await;
}
