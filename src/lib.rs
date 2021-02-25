use std::{
    ffi::CString,
    fs::File,
    io::{self, BufReader},
    path::{Path, PathBuf},
};

use image::{
    codecs::ico::{IcoDecoder, IcoEncoder},
    ColorType, ImageDecoder,
};
use thiserror::Error;
use widestring::U16CString;

use lief_sys as lief;

const LIEF_SYS_OK: usize = 0;
const LIEF_SYS_BUILD_ERROR: usize = 1;
const LIEF_SYS_SET_RCDATA_ERROR: usize = 2;
const LIEF_SYS_SET_STRING_ERROR: usize = 3;
const LIEF_SYS_SET_ICON_ERROR: usize = 4;

const ICONS_SIZES: [u32; 9] = [16, 20, 24, 32, 40, 48, 64, 128, 256];

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
    #[error("Failed to set string into STRINGTABLE")]
    SetStringError,
    #[error("Failed to set icon for Binary file")]
    SetIconError,
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
        match unsafe { lief::SetRcData(self.handle, data.as_ptr(), data.len(), id) } {
            LIEF_SYS_OK => Ok(()),
            LIEF_SYS_SET_RCDATA_ERROR => Err(LiefError::SetRcDataError),
            _ => unreachable!(),
        }
    }

    pub fn set_string(&self, string: String, id: u32) -> LiefResult<()> {
        let set_string_result = unsafe {
            let u16string = U16CString::from_str(string).map_err(|_| LiefError::Other {
                description: "Failed to convert utf8 string to utf16 string".to_owned(),
            })?;

            lief::SetString(self.handle, u16string.as_ptr(), id)
        };

        match set_string_result {
            LIEF_SYS_OK => Ok(()),
            LIEF_SYS_SET_STRING_ERROR => Err(LiefError::SetStringError),
            _ => unreachable!(),
        }
    }

    pub fn set_icon(&self, icon_path: PathBuf) -> LiefResult<()> {
        let file = File::open(icon_path)?;
        let reader = BufReader::new(file);

        let icon_decoder = IcoDecoder::new(reader).map_err(|err| LiefError::Other {
            description: format!("Failed to decode icon: {}", err),
        })?;

        let total_icon_bytes = icon_decoder.total_bytes();
        let mut icon_buffer = vec![0u8; total_icon_bytes as usize];
        icon_decoder
            .read_image(&mut icon_buffer)
            .map_err(|err| LiefError::Other {
                description: format!("Failed to read icon data: {}", err),
            })?;

        for icon_size in ICONS_SIZES.iter() {
            let (reader, writer) = pipe::pipe();

            let icon_encoder = IcoEncoder::new(writer);
            icon_encoder
                .encode(
                    icon_buffer.as_ref(),
                    *icon_size,
                    *icon_size,
                    ColorType::Rgb8,
                )
                .map_err(|err| LiefError::Other {
                    description: format!(
                        "Failed to encode {}x{} icon: {}",
                        icon_size, icon_size, err
                    ),
                })?;

            let buffer = reader.buffer().to_vec();

            let replace_result =
                unsafe { lief::ReplaceIcon(self.handle, buffer.as_ptr(), buffer.len()) };

            match replace_result {
                LIEF_SYS_OK => {}
                LIEF_SYS_SET_ICON_ERROR => return Err(LiefError::SetIconError),
                _ => unreachable!(),
            }
        }

        Ok(())
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
fn path_to_cstring(path: &Path) -> io::Result<Cstring> {
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
