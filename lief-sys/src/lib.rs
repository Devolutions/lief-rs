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
    pub fn SetRcData(
        this: ResourceManager,
        data: *mut u8,
        data_size: usize,
        resource_id: u32,
    ) -> c_uint;
    pub fn SetString(this: ResourceManager, string: *const u16, resource_id: u32) -> c_uint;
    pub fn ReplaceIcon(this: ResourceManager, data: *const u8, data_size: usize) -> c_uint;
}
