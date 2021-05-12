use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, BufReader, Cursor, ErrorKind},
    path::{Path, PathBuf},
    slice,
};

use bitflags::bitflags;
use image::{codecs::ico::IcoDecoder, imageops::FilterType, DynamicImage, ImageOutputFormat};
use picky::{
    hash::HashAlgorithm,
    key::{self, PrivateKey},
    pem::{self, Pem},
    x509::{
        pkcs7::{self, Pkcs7},
        wincert::WinCertificateError,
    },
};
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
    #[error("unknown, unexpected error occurred")]
    Unknown,
    #[error(transparent)]
    AuthenticodeError(#[from] AuthenticodeError),
}

#[derive(Debug, Error)]
pub enum AuthenticodeError {
    #[error("Failed to get authenticode file hash({0:?})")]
    FileHashError(Option<String>),
    #[error("Failed to set authenticode({0:?})")]
    SetAuthenticodeError(Option<String>),
    #[error("Failed to check signature({0:?})")]
    SignatureCheckError(Option<String>),
    #[error(transparent)]
    PemError(#[from] pem::PemError),
    #[error(transparent)]
    KeyError(#[from] key::KeyError),
    #[error(transparent)]
    CertError(#[from] pkcs7::Pkcs7Error),
    #[error(transparent)]
    WinCertificateEncodeError(#[from] WinCertificateError),
}

bitflags! {
     pub struct VerificationChecks: i32 {
        const DEFAULT           =   0b0000_0001;
        const HASH_ONLY         =   0b0000_0010;
        const LIFETIME_SIGNING  =   0b0000_0100;
        const SKIP_CERT_TIME    =   0b0000_1000;
    }
}

bitflags! {
    pub struct VerificationFlags: i32 {
        const OK                            = 0b0000_0000_0000_0000;
        const INVALID_SIGNER                = 0b0000_0000_0000_0001;
        const UNSUPPORTED_ALGORITHM         = 0b0000_0000_0000_0010;
        const INCONSISTENT_DIGEST_ALGORITHM = 0b0000_0000_0000_0100;
        const CERT_NOT_FOUND                = 0b0000_0000_0000_1000;
        const CORRUPTED_CONTENT_INFO        = 0b0000_0000_0001_0000;
        const CORRUPTED_AUTH_DATA           = 0b0000_0000_0010_0000;
        const MISSING_PKCS9_MESSAGE_DIGEST  = 0b0000_0000_0100_0000;
        const BAD_DIGEST                    = 0b0000_0000_1000_0000;
        const BAD_SIGNATURE                 = 0b0000_0001_0000_0000;
        const NO_SIGNATURE                  = 0b0000_0010_0000_0000;
        const CERT_EXPIRED                  = 0b0000_0100_0000_0000;
        const CERT_FUTURE                   = 0b0000_1000_0000_0000;
    }
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

    pub fn build(self, where_to_save: PathBuf, with_resources: bool) -> LiefResult<()> {
        let path = path_to_cstring(where_to_save.as_path())?;

        let cresult = unsafe { lief::Binary_Build(self.handle, path.as_ptr(), with_resources) };
        let status_code = cresult_into_lief_result(cresult)
            .map_err(|err| LiefError::BuildFileError(Some(err.to_string())))?;

        ffi_status_code_to_lief_result(status_code)
    }

    // WARNING!!! The  set_authenticode function shouldn't be used with the patching resource section at the same time.
    // The resource section hash is not included in the file hash set_authenticode as the resource section constructed while building.
    // Patch resource section first, build it, load the built binary, set Authenticode, and build again.

    pub fn set_authenticode(
        &self,
        certificate: Vec<u8>,
        private_key: Vec<u8>,
        program_name: Option<String>,
    ) -> LiefResult<()> {
        let pem = Pem::read_from(&mut BufReader::new(Cursor::new(private_key)))
            .map_err(AuthenticodeError::PemError)?;
        let private_key = PrivateKey::from_pem(&pem).map_err(AuthenticodeError::KeyError)?;

        let pem = Pem::read_from(&mut BufReader::new(Cursor::new(certificate)))
            .map_err(AuthenticodeError::PemError)?;
        let pkcs7_certfile = Pkcs7::from_pem(&pem).map_err(AuthenticodeError::CertError)?;

        let mut hash_len: usize = 0;
        let file_hash = unsafe {
            let cresult = lief::GetFileHash(self.handle, &mut hash_len);

            let file_hash_pointer = cresult_into_lief_result(cresult)
                .map_err(|err| AuthenticodeError::FileHashError(Some(err.to_string())))?;

            if file_hash_pointer.is_null() || hash_len == 0 {
                lief::DeallocateFileHash(file_hash_pointer);
                return Err(AuthenticodeError::FileHashError(None).into());
            }

            let file_hash = slice::from_raw_parts(file_hash_pointer, hash_len).to_vec();

            lief::DeallocateFileHash(file_hash_pointer);

            file_hash
        };

        let wincert = pkcs7_certfile
            .into_win_certificate(
                file_hash.as_ref(),
                HashAlgorithm::SHA2_256,
                &private_key,
                program_name,
            )
            .map_err(AuthenticodeError::CertError)?;

        let data = wincert
            .encode()
            .map_err(AuthenticodeError::WinCertificateEncodeError)?;

        let cresult = unsafe { lief::SetAuthenticode(self.handle, data.as_ptr(), data.len()) };

        let status_code = cresult_into_lief_result(cresult)
            .map_err(|err| AuthenticodeError::SetAuthenticodeError(Some(err.to_string())))?;

        ffi_status_code_to_lief_result(status_code)
    }

    pub fn check_signature(&self, checks: VerificationChecks) -> LiefResult<VerificationFlags> {
        let cresult = unsafe { lief::CheckSignature(self.handle, checks.bits) };

        let verification_flags = cresult_into_lief_result(cresult)
            .map_err(|err| AuthenticodeError::SignatureCheckError(Some(err.to_string())))?;

        VerificationFlags::from_bits(verification_flags)
            .ok_or_else(|| AuthenticodeError::SignatureCheckError(None).into())
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

        ffi_status_code_to_lief_result(status_code)
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

        ffi_status_code_to_lief_result(status_code)
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

            ffi_status_code_to_lief_result(status_code)?
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

#[inline]
fn ffi_status_code_to_lief_result(status_code: u32) -> LiefResult<()> {
    match status_code {
        LIEF_SYS_OK => Ok(()),
        _ => Err(LiefError::Unknown),
    }
}
