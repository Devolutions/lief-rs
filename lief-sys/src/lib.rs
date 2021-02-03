use std::ffi::c_void;
use std::os::raw::c_char;

pub type Binary = *mut c_void;

extern "C" {
    pub fn Binary_New(path: *const c_char) -> Binary;
    pub fn Binary_Free(this: Binary);
    pub fn Binary_Print(this: Binary);
}
