use std::ffi::OsString;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Linux(#[from] linux::Error),
    #[cfg(target_os = "windows")]
    #[error(transparent)]
    Windows(#[from] windows::Error),
}

type Result<T> = std::result::Result<T, Error>;

/// A trait for creating and using a virtual device.
pub trait VitaVirtualDevice<ConfigSetter: ?Sized>: Sized {
    type Config;

    fn get_config(&self) -> &Self::Config;
    fn identifiers(&self) -> Option<&[OsString]>;
    fn set_config(&mut self, config: ConfigSetter) -> Result<()>;
    fn send_report(&mut self, report: vita_reports::MainReport) -> Result<()>;
}

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        mod linux;
        pub use linux::VitaDevice;
    } else if #[cfg(target_os = "windows")] {
        mod windows;
        pub use windows::VitaDevice;
    }
}
