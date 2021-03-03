use std::{
    ffi::CString,
    fs::File,
    io::{self, BufReader, ErrorKind},
    path::{Path, PathBuf},
    slice,
};

use image::{codecs::ico::IcoDecoder, imageops::FilterType, DynamicImage, ImageOutputFormat};
use thiserror::Error;
use widestring::U16CString;

use lief_sys as lief;

const LIEF_SYS_OK: u32 = 0;
const LIEF_SYS_BUILD_ERROR: u32 = 1;
const LIEF_SYS_SET_RCDATA_ERROR: u32 = 2;
const LIEF_SYS_SET_STRING_ERROR: u32 = 3;
const LIEF_SYS_SET_ICON_ERROR: u32 = 4;

const ICONS_SIZES: [u32; 10] = [256, 128, 96, 64, 48, 40, 32, 24, 20, 16];

#[derive(Debug, Error)]
pub enum LiefError {
    #[error("Failed to parse Binary file")]
    ParseFileError,
    #[error("Failed to build Binary file")]
    BuildFileError,
    #[error("Failed to create ResourceManager")]
    CreateResourceManagerError,
    #[error("Failed to set RCDATA resource")]
    SetRcDataError,
    #[error("Failed to get RCDATA resource")]
    GetRcDataError,
    #[error("Failed to set string into STRINGTABLE")]
    SetStringError,
    #[error("Failed to get string form STRINGTABLE")]
    GetStringError,
    #[error("Failed to set the icon for Binary file")]
    SetIconError,
    #[error("Failed to get icon {width:?}x{height:?} pixels")]
    GetIconError { width: u32, height: u32 },
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{description}")]
    Other { description: String },
}

type LiefResult<T> = Result<T, LiefError>;

pub struct Binary {
    handle: lief::Binary,
}

pub struct ResourceManager {
    handle: lief::ResourceManager,
}

impl Binary {
    pub fn new(path: PathBuf) -> LiefResult<Self> {
        let path: CString = path_to_cstring(path.as_path())?;

        let handle = unsafe { lief::Binary_New(path.as_ptr()) };

        if handle.is_null() {
            return Err(LiefError::ParseFileError);
        }

        Ok(Self { handle })
    }

    pub fn build(self, where_to_save: PathBuf) -> LiefResult<()> {
        let path = path_to_cstring(where_to_save.as_path())?;

        match unsafe { lief::Binary_Build(self.handle, path.as_ptr()) } {
            LIEF_SYS_OK => Ok(()),
            LIEF_SYS_BUILD_ERROR => Err(LiefError::BuildFileError),
            _ => unreachable!(),
        }
    }

    pub fn resource_manager(&self) -> LiefResult<ResourceManager> {
        let handle = unsafe { lief::Binary_GetResourceManager(self.handle) };

        if handle.is_null() {
            return Err(LiefError::CreateResourceManagerError);
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

        match unsafe { lief::SetRcData(self.handle, data.as_ptr(), data.len(), id) } {
            LIEF_SYS_OK => Ok(()),
            LIEF_SYS_SET_RCDATA_ERROR => Err(LiefError::SetRcDataError),
            _ => unreachable!(),
        }
    }

    pub fn get_rcdata(&self, id: u32) -> LiefResult<Vec<u8>> {
        let mut rcdata_len = 0;
        unsafe {
            let rcdata_pointer = lief::GetRcData(self.handle, id, &mut rcdata_len);

            if rcdata_pointer.is_null() || rcdata_len == 0 {
                lief::DeallocateRcData(rcdata_pointer);
                return Err(LiefError::GetRcDataError);
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

        let set_string_result = unsafe {
            let u16string = U16CString::from_str(string).map_err(|_| LiefError::Other {
                description: "Failed to convert UTF8 string to UTF16 string".to_owned(),
            })?;

            lief::SetString(self.handle, u16string.as_ptr(), id)
        };

        match set_string_result {
            LIEF_SYS_OK => Ok(()),
            LIEF_SYS_SET_STRING_ERROR => Err(LiefError::SetStringError),
            _ => unreachable!(),
        }
    }

    pub fn get_string(&self, id: u32) -> LiefResult<String> {
        let mut string_len = 0;
        let u16string = unsafe {
            let string_pointer = lief::GetString(self.handle, id, &mut string_len);

            if string_pointer.is_null() || string_len == 0 {
                lief::DeallocateString(string_pointer);
                return Err(LiefError::GetStringError);
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

            let replace_result = unsafe { lief::ReplaceIcon(self.handle, resized_icon.as_ptr(), resized_icon.len()) };

            match replace_result {
                LIEF_SYS_OK => {}
                LIEF_SYS_SET_ICON_ERROR => return Err(LiefError::SetIconError),
                _ => unreachable!(),
            }
        }

        Ok(())
    }

    pub fn get_icon(&self, width: u32, height: u32) -> LiefResult<Vec<u8>> {
        let icon = unsafe {
            let mut pixels_data_len = 0;

            let icon_pointer = lief::GetIcon(self.handle, width, height, &mut pixels_data_len);

            if icon_pointer.is_null() || pixels_data_len == 0 {
                 lief::DeallocateIcon(icon_pointer);
                return Err(LiefError::GetIconError { width, height });
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
