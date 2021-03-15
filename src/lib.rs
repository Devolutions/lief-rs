use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, BufReader, ErrorKind},
    path::{Path, PathBuf},
    slice,
};

use image::{codecs::ico::IcoDecoder, imageops::FilterType, DynamicImage, ImageOutputFormat};
use thiserror::Error;
use widestring::U16CString;

use lief_sys as lief;
use lief_sys::CResult;

const LIEF_SYS_OK: u32 = 0;

const ICONS_SIZES: [u32; 10] = [256, 128, 96, 64, 48, 40, 32, 24, 20, 16];

#[derive(Debug, Error)]
pub enum LiefError {
    #[error("Failed to parse Binary file({0:?})")]
    ParseFileError(Option<String>),
    #[error("Failed to build Binary file({0:?})")]
    BuildFileError(Option<String>),
    #[error("Failed to create ResourceManager({0:?})")]
    CreateResourceManagerError(Option<String>),
    #[error("Failed to set RCDATA resource({0:?})")]
    SetRcDataError(Option<String>),
    #[error("Failed to get RCDATA resource({0:?})")]
    GetRcDataError(Option<String>),
    #[error("Failed to set string into STRINGTABLE({0:?})")]
    SetStringError(Option<String>),
    #[error("Failed to get string form STRINGTABLE({0:?})")]
    GetStringError(Option<String>),
    #[error("Failed to set the icon for Binary file({0:?})")]
    SetIconError(Option<String>),
    #[error("Failed to get icon {width}x{height} pixels({description:?})")]
    GetIconError {
        width: u32,
        height: u32,
        description: Option<String>,
    },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{description}")]
    Other { description: String },
    #[error("{0}")]
    CError(String),
}

pub type LiefResult<T> = Result<T, LiefError>;

pub struct Binary {
    handle: lief::Binary,
}

pub struct ResourceManager {
    handle: lief::ResourceManager,
}

impl Binary {
    pub fn new(path: PathBuf) -> LiefResult<Self> {
        let path: CString = path_to_cstring(path.as_path())?;

        let cresult = unsafe { lief::Binary_New(path.as_ptr()) };

        let handle = cresult_into_lief_result(cresult)
            .map_err(|err| LiefError::ParseFileError(Some(err.to_string())))?;

        if handle.is_null() {
            return Err(LiefError::ParseFileError(None));
        }

        Ok(Self { handle })
    }

    pub fn build(self, where_to_save: PathBuf) -> LiefResult<()> {
        let path = path_to_cstring(where_to_save.as_path())?;

        let cresult = unsafe { lief::Binary_Build(self.handle, path.as_ptr()) };
        let status_code = cresult_into_lief_result(cresult)
            .map_err(|err| LiefError::BuildFileError(Some(err.to_string())))?;

        match status_code {
            LIEF_SYS_OK => Ok(()),
            _ => unreachable!(),
        }
    }

    pub fn resource_manager(&self) -> LiefResult<ResourceManager> {
        let cresult = unsafe { lief::Binary_GetResourceManager(self.handle) };

        let handle = cresult_into_lief_result(cresult)
            .map_err(|err| LiefError::CreateResourceManagerError(Some(err.to_string())))?;

        if handle.is_null() {
            return Err(LiefError::CreateResourceManagerError(None));
        }

        Ok(ResourceManager { handle })
    }
}

impl ResourceManager {
    pub fn set_rcdata(&self, data: Vec<u8>, id: u32) -> LiefResult<()> {
        if data.is_empty() {
            return Err(LiefError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "Input buffer is empty",
            )));
        }

        let cresult = unsafe { lief::SetRcData(self.handle, data.as_ptr(), data.len(), id) };
        let status_code = cresult_into_lief_result(cresult)
            .map_err(|err| LiefError::SetRcDataError(Some(err.to_string())))?;

        match status_code {
            LIEF_SYS_OK => Ok(()),
            _ => unreachable!(),
        }
    }

    pub fn get_rcdata(&self, id: u32) -> LiefResult<Vec<u8>> {
        let mut rcdata_len = 0;
        unsafe {
            let cresult = lief::GetRcData(self.handle, id, &mut rcdata_len);

            let rcdata_pointer = cresult_into_lief_result(cresult)
                .map_err(|err| LiefError::GetRcDataError(Some(err.to_string())))?;

            if rcdata_pointer.is_null() || rcdata_len == 0 {
                lief::DeallocateRcData(rcdata_pointer);
                return Err(LiefError::GetRcDataError(None));
            }

            let rcdata = slice::from_raw_parts(rcdata_pointer, rcdata_len).to_vec();

            lief::DeallocateRcData(rcdata_pointer);

            Ok(rcdata)
        }
    }

    pub fn set_string(&self, string: String, id: u32) -> LiefResult<()> {
        if string.is_empty() {
            return Err(LiefError::Io(io::Error::new(
                ErrorKind::InvalidData,
                "Input string is empty",
            )));
        }

        let cresult = unsafe {
            let u16string = U16CString::from_str(string).map_err(|_| LiefError::Other {
                description: "Failed to convert UTF8 string to UTF16 string".to_owned(),
            })?;

            lief::SetString(self.handle, u16string.as_ptr(), id)
        };

        let status_code = cresult_into_lief_result(cresult)
            .map_err(|err| LiefError::SetStringError(Some(err.to_string())))?;

        match status_code {
            LIEF_SYS_OK => Ok(()),
            _ => unreachable!(),
        }
    }

    pub fn get_string(&self, id: u32) -> LiefResult<String> {
        let mut string_len = 0;
        let u16string = unsafe {
            let cresult = lief::GetString(self.handle, id, &mut string_len);

            let string_pointer = cresult_into_lief_result(cresult)
                .map_err(|err| LiefError::GetStringError(Some(err.to_string())))?;

            if string_pointer.is_null() || string_len == 0 {
                lief::DeallocateString(string_pointer);
                return Err(LiefError::GetStringError(Some(String::new())));
            }

            let u16string =
                U16CString::from_ptr(string_pointer, string_len).map_err(|err| LiefError::Other {
                    description: format!("Failed to create UTF16 string from raw pointer {}", err),
                });

            lief::DeallocateString(string_pointer);

            u16string?
        };

        let string = u16string.to_string().map_err(|_| LiefError::Other {
            description: "Failed to convert UTF16 string to UTF8 string".to_owned(),
        })?;

        Ok(string)
    }

    pub fn set_icon(&self, icon_path: PathBuf) -> LiefResult<()> {
        let file = File::open(icon_path)?;
        let reader = BufReader::new(file);

        let icon_decoder = IcoDecoder::new(reader).map_err(|err| LiefError::Other {
            description: format!("Failed to decode icon: {}", err),
        })?;

        let icon = DynamicImage::from_decoder(icon_decoder).unwrap();

        for icon_size in ICONS_SIZES.iter() {
            let resized_icon_data = icon.resize_exact(*icon_size, *icon_size, FilterType::Lanczos3);

            let mut resized_icon = Vec::new();

            resized_icon_data
                .write_to(&mut resized_icon, ImageOutputFormat::Ico)
                .map_err(|err| LiefError::Other {
                    description: format!("Failed to encode resized icon: {}", err),
                })?;

            let cresult = unsafe {
                lief::ReplaceIcon(self.handle, resized_icon.as_ptr(), resized_icon.len())
            };

            let status_code = cresult_into_lief_result(cresult)
                .map_err(|err| LiefError::SetIconError(Some(err.to_string())))?;

            match status_code {
                LIEF_SYS_OK => {}
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    pub fn get_icon(&self, width: u32, height: u32) -> LiefResult<Vec<u8>> {
        let icon = unsafe {
            let mut pixels_data_len = 0;

            let cresult = lief::GetIcon(self.handle, width, height, &mut pixels_data_len);

            let icon_pointer =
                cresult_into_lief_result(cresult).map_err(|err| LiefError::GetIconError {
                    description: Some(err.to_string()),
                    width,
                    height,
                })?;

            if icon_pointer.is_null() || pixels_data_len == 0 {
                lief::DeallocateIcon(icon_pointer);
                return Err(LiefError::GetIconError {
                    description: None,
                    width,
                    height,
                });
            }

            let icon_pixels = slice::from_raw_parts(icon_pointer, pixels_data_len).to_vec();

            lief::DeallocateIcon(icon_pointer);

            icon_pixels
        };

        let image_buffer =
            image::load_from_memory(icon.as_slice()).map_err(|err| LiefError::Other {
                description: format!("Failed to create an icon from memory: {}", err),
            })?;

        let mut buffer = Vec::new();
        image_buffer
            .write_to(&mut buffer, ImageOutputFormat::Ico)
            .map_err(|err| LiefError::Other {
                description: format!("Failed to encode an icon: {}", err),
            })?;

        Ok(buffer)
    }
}

impl Drop for Binary {
    fn drop(&mut self) {
        unsafe {
            lief::Binary_Free(self.handle);
        }
    }
}

impl Drop for ResourceManager {
    fn drop(&mut self) {
        unsafe {
            lief::ResourceManager_Free(self.handle);
        }
    }
}

#[cfg(unix)]
fn path_to_cstring(path: &Path) -> LiefResult<CString> {
    use std::os::unix::ffi::OsStrExt;

    CString::new(path.as_os_str().as_bytes()).map_err(|_| LiefError::Other {
        description: "Path contains invalid characters".to_owned(),
    })
}

#[cfg(not(unix))]
fn path_to_cstring(path: &Path) -> LiefResult<CString> {
    CString::new(path.to_string_lossy().to_string().into_bytes()).map_err(|_| LiefError::Other {
        description: "Path contains invalid characters".to_owned(),
    })
}

fn cresult_into_lief_result<T>(cresult: CResult<T>) -> LiefResult<T> {
    if cresult.message.is_null() {
        let CResult { value, .. } = cresult;
        Ok(value)
    } else {
        let message = unsafe {
            let message = CStr::from_ptr(cresult.message);
            lief::DeallocateMessage(cresult.message);
            message
        };

        let message = message
            .to_str()
            .map_err(|err| LiefError::Other {
                description: format!("Failed to convert CStr error message to &str: {}", err),
            })?
            .to_owned();

        Err(LiefError::CError(message))
    }
}
