//! OpenBSD specific functionality.

pub mod sys;

mod device;
pub use self::device::Device;

use crate::configuration::Configuration;
use crate::error::Result;

/// OpenBSD-only interface configuration.
#[derive(Copy, Clone, Default, Debug)]
pub struct PlatformConfig;

/// Create a TUN device with the given name.
pub fn create(configuration: &Configuration) -> Result<Device> {
    Device::new(configuration)
}
