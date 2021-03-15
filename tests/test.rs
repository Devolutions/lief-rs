use image::ImageOutputFormat;
use lazy_static::lazy_static;
use lief::Binary;
use std::{path::PathBuf, str::FromStr};
use tempfile::{tempdir, TempDir};
use uuid::Uuid;

const BINARY_PATH: &str = "tests/assets/WaykCse.exe";
const ICON_16X16: &str = "tests/assets/icon_16x16.ico";
const ICON_24X24: &str = "tests/assets/icon_24x24.ico";
const ICON_32X32: &str = "tests/assets/icon_32x32.ico";
const ICON_48X48: &str = "tests/assets/icon_48x48.ico";
const ICON_64X64: &str = "tests/assets/icon_64x64.ico";
const ICON_96X96: &str = "tests/assets/icon_96x96.ico";
const ICON_128X128: &str = "tests/assets/icon_128x128.ico";
const ICON_256X256: &str = "tests/assets/icon_256x256.ico";

lazy_static! {
    static ref TEMP_DIR: TempDir = tempdir().unwrap();
}

fn read_icon_into_vector(icon_path: PathBuf) -> Vec<u8> {
    let icon = image::open(icon_path).unwrap();

    let mut buffer = Vec::new();
    icon.write_to(&mut buffer, ImageOutputFormat::Ico).unwrap();
    buffer
}

#[test]
fn binary_parse_test() {
    let path = PathBuf::from_str(BINARY_PATH).unwrap();
    let binary = Binary::new(path);

    assert!(binary.is_ok());
}

#[test]
fn binary_parse_fails_if_file_not_exists() {
    let path = PathBuf::from_str("tests/assets/SomeMissingBinary.exe").unwrap();
    let binary = Binary::new(path);

    assert!(binary.is_err());
}

#[test]
fn resource_manager_can_be_created() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager();
    assert!(resource_manager.is_ok());
}

#[test]
fn binary_build_test() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    assert!(binary.build(file_path).is_ok())
}

#[test]
fn set_rcdata_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let data = "Hello RcData".to_owned().into_bytes();
    let resource_id = 1;

    assert!(resource_manager
        .set_rcdata(data.clone(), resource_id)
        .is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let rcdata = resource_manager.get_rcdata(resource_id).unwrap();

    assert_eq!(rcdata, data);
}

#[test]
fn set_empty_rcdata_to_binary_fails() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let data = Vec::new();
    let resource_id = 1;

    assert!(resource_manager.set_rcdata(data, resource_id).is_err());
}

#[test]
fn set_string_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let string = "Hello StringTable".to_owned();
    let resource_id = 10;
    assert!(resource_manager
        .set_string(string.clone(), resource_id)
        .is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let initial_string = resource_manager.get_string(resource_id).unwrap();

    assert_eq!(initial_string, string);
}

#[test]
fn set_empty_string_to_binary_fails() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let string = String::new();
    let resource_id = 10;
    assert!(resource_manager.set_string(string, resource_id).is_err());
}

#[test]
fn set_16x16_icon_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let icon_path = PathBuf::from_str(ICON_16X16).unwrap();

    assert!(resource_manager.set_icon(icon_path.clone()).is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let buffer = read_icon_into_vector(icon_path);
    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let icon = resource_manager.get_icon(16, 16).unwrap();

    assert_eq!(icon, buffer);
}

#[test]
fn set_24x24_icon_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let icon_path = PathBuf::from_str(ICON_24X24).unwrap();

    assert!(resource_manager.set_icon(icon_path.clone()).is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let buffer = read_icon_into_vector(icon_path);
    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let icon = resource_manager.get_icon(24, 24).unwrap();

    assert_eq!(icon, buffer);
}

#[test]
fn set_32x32_icon_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let icon_path = PathBuf::from_str(ICON_32X32).unwrap();

    assert!(resource_manager.set_icon(icon_path.clone()).is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let buffer = read_icon_into_vector(icon_path);
    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let icon = resource_manager.get_icon(32, 32).unwrap();

    assert_eq!(icon, buffer);
}

#[test]
fn set_48x48_icon_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let icon_path = PathBuf::from_str(ICON_48X48).unwrap();

    assert!(resource_manager.set_icon(icon_path.clone()).is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let buffer = read_icon_into_vector(icon_path);
    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let icon = resource_manager.get_icon(48, 48).unwrap();

    assert_eq!(icon, buffer);
}

#[test]
fn set_64x64_icon_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let icon_path = PathBuf::from_str(ICON_64X64).unwrap();

    assert!(resource_manager.set_icon(icon_path.clone()).is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let buffer = read_icon_into_vector(icon_path);
    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let icon = resource_manager.get_icon(64, 64).unwrap();

    assert_eq!(icon, buffer);
}

#[test]
fn set_96x96_icon_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let icon_path = PathBuf::from_str(ICON_96X96).unwrap();

    assert!(resource_manager.set_icon(icon_path.clone()).is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let buffer = read_icon_into_vector(icon_path);
    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let icon = resource_manager.get_icon(96, 96).unwrap();

    assert_eq!(icon, buffer);
}

#[test]
fn set_128x128_icon_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let icon_path = PathBuf::from_str(ICON_128X128).unwrap();

    assert!(resource_manager.set_icon(icon_path.clone()).is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let buffer = read_icon_into_vector(icon_path);
    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let icon = resource_manager.get_icon(128, 128).unwrap();

    assert_eq!(icon, buffer);
}

#[test]
fn set_256x256_icon_to_binary() {
    let path = PathBuf::from(BINARY_PATH);
    let binary = Binary::new(path).unwrap();

    let resource_manager = binary.resource_manager().unwrap();

    let icon_path = PathBuf::from_str(ICON_256X256).unwrap();

    assert!(resource_manager.set_icon(icon_path.clone()).is_ok());

    let file_path = TEMP_DIR.path().join(format!("{}.exe", Uuid::new_v4()));

    binary.build(file_path.clone()).unwrap();

    let buffer = read_icon_into_vector(icon_path);
    let binary = Binary::new(file_path).unwrap();
    let resource_manager = binary.resource_manager().unwrap();

    let icon = resource_manager.get_icon(128, 128).unwrap();

    assert_eq!(icon.len(), buffer.len());
}
