use std::ffi::c_void;
use std::os::raw::{c_char, c_uint};

pub type Binary = *mut c_void;
pub type ResourceManager = *mut c_void;

extern "C" {
    pub fn Binary_New(path: *const c_char) -> Binary;
    pub fn Binary_Free(this: Binary);
    pub fn Binary_Build(this: Binary, path: *const c_char) -> c_uint;
    pub fn Binary_GetResourceManager(this: Binary) -> ResourceManager;
    pub fn ResourceManager_Free(this: ResourceManager);
    pub fn SetRcData(
        this: ResourceManager,
        data: *const u8,
        data_len: usize,
        resource_id: u32,
    ) -> c_uint;
    pub fn GetRcData(this: ResourceManager, resource_id: u32, rcdata_len: *mut usize) -> *const u8;
    pub fn DeallocateRcData(rcdata: *const u8);
    pub fn SetString(this: ResourceManager, string: *const u16, resource_id: u32) -> c_uint;
    pub fn GetString(this: ResourceManager, resource_id: u32, string_len: *mut usize)
        -> *const u16;
    pub fn DeallocateString(string: *const u16);
    pub fn ReplaceIcon(this: ResourceManager, data: *const u8, data_len: usize) -> c_uint;
    pub fn GetIcon(
        this: ResourceManager,
        width: u32,
        height: u32,
        pixels_data_len: *mut usize,
    ) -> *const u8;
    pub fn DeallocateIcon(pixels: *const u8);
}
