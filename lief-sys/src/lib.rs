use std::ffi::c_void;
use std::os::raw::{c_char, c_uint};

pub type Binary = *mut c_void;
pub type ResourceManager = *mut c_void;

#[repr(C)]
pub struct CResult<T> {
    pub value: T,
    pub message: *mut c_char,
}

extern "C" {
    pub fn Binary_New(path: *const c_char) -> CResult<Binary>;
    pub fn Binary_Build(this: Binary, path: *const c_char, with_resource: bool) -> CResult<c_uint>;
    pub fn GetFileHash(this: Binary, hash_len: *mut usize) -> CResult<*const u8>;
    pub fn SetAuthenticode(
        this: Binary,
        cert_data: *const u8,
        cert_data_len: usize,
    ) -> CResult<c_uint>;
    pub fn CheckSignature(this: Binary, checks: i32) -> CResult<i32>;
    pub fn Binary_GetResourceManager(this: Binary) -> CResult<ResourceManager>;
    pub fn Binary_Free(this: Binary);
    pub fn ResourceManager_Free(this: ResourceManager);

    pub fn SetRcData(
        this: ResourceManager,
        data: *const u8,
        data_len: usize,
        resource_id: u32,
    ) -> CResult<c_uint>;
    pub fn SetString(
        this: ResourceManager,
        string: *const u16,
        resource_id: u32,
    ) -> CResult<c_uint>;
    pub fn ReplaceIcon(this: ResourceManager, data: *const u8, data_len: usize) -> CResult<c_uint>;

    pub fn GetRcData(
        this: ResourceManager,
        resource_id: u32,
        rcdata_len: *mut usize,
    ) -> CResult<*const u8>;
    pub fn GetString(
        this: ResourceManager,
        resource_id: u32,
        string_len: *mut usize,
    ) -> CResult<*const u16>;
    pub fn GetIcon(
        this: ResourceManager,
        width: u32,
        height: u32,
        pixels_data_len: *mut usize,
    ) -> CResult<*const u8>;

    pub fn DeallocateRcData(rcdata: *const u8);
    pub fn DeallocateString(string: *const u16);
    pub fn DeallocateIcon(pixels: *const u8);
    pub fn DeallocateMessage(message: *const c_char);
    pub fn DeallocateFileHash(file_hash: *const u8);
}
