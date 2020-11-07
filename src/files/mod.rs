pub mod flags;
pub mod locker;

use crate::errors;
use flags::*;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

pub const READ_BUFFER_SIZE: usize = 1024;

// fn get_file_metadata(file: &fs::File) -> Result<fs::Metadata, errors::Error> {
//     match file.metadata() {
//         Ok(m) => Ok(m),
//         Err(_) => Err(errors::Error::FileGetMetadata),
//     }
// }

// fn get_file_length(file: &fs::File) -> Result<u64, errors::Error> {
//     match file.metadata() {
//         Ok(m) => Ok(m.len()),
//         Err(_) => Err(errors::Error::FileGetMetadata),
//     }
// }

fn file_seek(file: &mut fs::File, pos: SeekFrom) -> Result<u64, errors::LockerError> {
    match file.seek(pos) {
        Ok(result) => Ok(result),
        Err(_) => Err(errors::LockerError::SeekFile),
    }
}

fn file_write_all(file: &mut fs::File, buf: &[u8]) -> Result<(), errors::LockerError> {
    match file.write_all(buf) {
        Ok(()) => Ok(()),
        Err(_) => Err(errors::LockerError::WriteFile),
    }
}

fn file_read(file: &mut fs::File, buf: &mut [u8]) -> Result<usize, errors::LockerError> {
    match file.read(buf) {
        Ok(result) => Ok(result),
        Err(_) => Err(errors::LockerError::ReadFile),
    }
}

pub trait OpenPasswordsFile {
    fn open_passwords_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<fs::File, errors::LockerError>;
}
impl OpenPasswordsFile for fs::OpenOptions {
    fn open_passwords_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<fs::File, errors::LockerError> {
        match self.open(path) {
            Ok(f) => Ok(f),
            Err(_) => Err(errors::LockerError::OpenFile),
        }
    }
}

pub trait XorPasswordsFile {
    fn xor_passwords_file<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), errors::LockerError>;
}
impl XorPasswordsFile for fs::File {
    fn xor_passwords_file<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), errors::LockerError> {
        let key_bytes = key.as_ref();
        let ket_bytes_length = key_bytes.len();
        let mut key_index = 0;
        let mut buffer = [0u8; READ_BUFFER_SIZE];
        let mut file_cursor_position = 0u64;
        loop {
            let amount = file_read(self, &mut buffer)?;
            if amount == 0 {
                break Ok(());
            }
            for byte in &mut buffer[..amount] {
                *byte ^= key_bytes[key_index];
                key_index = (key_index + 1) % ket_bytes_length;
            }
            file_seek(self, SeekFrom::Start(file_cursor_position))?;
            file_write_all(self, &buffer[..amount])?;
            file_cursor_position += amount as u64;
        }
    }
}

pub trait BackupFile {
    fn backup(&mut self, backup_file_path: &str) -> Result<fs::File, errors::LockerError>;
}
impl BackupFile for fs::File {
    fn backup(&mut self, backup_file_path: &str) -> Result<fs::File, errors::LockerError> {
        let mut backup_file = match fs::OpenOptions::new()
            .create(true)
            .write(true)
            .read(true)
            .open(backup_file_path)
        {
            Ok(file) => file,
            Err(_) => return Err(errors::LockerError::CreatBackupFile),
        };
        file_seek(self, SeekFrom::Start(0))?;
        let mut buffer = [0u8; READ_BUFFER_SIZE];
        let mut total_amount=0u64;
        loop {
            let amount=file_read(self, &mut buffer)?;
            if amount==0{
                break;
            }
            total_amount+=amount as u64;
            if backup_file.write_all(&mut buffer[..amount]).is_err(){
                return Err(errors::LockerError::WriteBackupFile)
            }
        }
        match backup_file.set_len(total_amount){
            Ok(())=>Ok(backup_file),
            Err(_)=>Err(errors::LockerError::SetLengthBackupFile),
        }
    }
}

pub trait RevertToBackupFile{
    fn revert_to_backup(&mut self,backup_file:&mut fs::File)->Result<(),errors::LockerError>;
}
impl RevertToBackupFile for fs::File{
    fn revert_to_backup(&mut self, backup_file:&mut fs::File)->Result<(),errors::LockerError>{
        if backup_file.seek(SeekFrom::Start(0)).is_err(){
            return Err(errors::LockerError::SeekBackupFile)
        }
        file_seek(self, SeekFrom::Start(0))?;
        let mut buffer = [0u8;READ_BUFFER_SIZE];
        let mut total_amount=0u64;
        loop{
            let amount= match backup_file.read(&mut buffer) {
                Ok(result) => {result},
                Err(_) => {return Err(errors::LockerError::ReadBackupFile);},
            };
            if amount==0{
                break;
            }
            total_amount+=amount as u64;
            file_write_all(self, &buffer[..amount])?;
        }
        match self.set_len(total_amount){
            Ok(())=>Ok(()),
            Err(_)=>Err(errors::LockerError::SetLengthFile)
        }
    }
}

#[macro_export]
macro_rules! file_read_primitive {
    ($file:expr,$primitive_type:ty) => {
        {
            use std::io::Read;
            let mut bytes=[0u8;std::mem::size_of::<$primitive_type>()];
            match $file.read_exact(&mut bytes){
                Ok(())=>Ok(<$primitive_type>::from_ne_bytes(bytes)),
                Err(e)=>Err(e)
            }
        }
    };
}