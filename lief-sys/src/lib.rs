use std::ffi::c_void;
use std::os::raw::{c_char, c_uint};

pub type Binary = *mut c_void;
pub type ResourceManager = *mut c_void;

extern "C" {
    pub fn Binary_New(path: *const c_char) -> Binary;
    pub fn Binary_Free(this: Binary);
    pub fn Binary_Build(this: Binary) -> c_uint;
    pub fn Binary_GetResourceManager(this: Binary) -> ResourceManager;
    pub fn ResourceManager_Free(this: ResourceManager);
    pub fn SetRcData(this: ResourceManager, data: *mut u8, data_size: u32, resource_id: u32);
}
