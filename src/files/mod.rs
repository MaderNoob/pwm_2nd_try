pub mod flags;

use crate::errors;
use flags::*;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

fn get_file_metadata(file: &fs::File) -> Result<fs::Metadata, errors::Error> {
    match file.metadata() {
        Ok(m) => Ok(m),
        Err(_) => Err(errors::Error::FileGetMetadata),
    }
}

fn get_file_length(file: &fs::File) -> Result<u64, errors::Error> {
    match file.metadata() {
        Ok(m) => Ok(m.len()),
        Err(_) => Err(errors::Error::FileGetMetadata),
    }
}

fn file_seek(file: &mut fs::File, pos: SeekFrom) -> Result<u64, errors::Error> {
    match file.seek(pos) {
        Ok(result) => Ok(result),
        Err(_) => Err(errors::Error::SeekFile),
    }
}

fn file_write_all(file: &mut fs::File, buf: &mut [u8]) -> Result<(), errors::Error> {
    match file.write_all(buf) {
        Ok(()) => Ok(()),
        Err(e) => Err(errors::Error::WriteFile),
    }
}

fn file_read(file: &mut fs::File, buf: &mut [u8]) -> Result<usize, errors::Error> {
    match file.read(buf) {
        Ok(result) => Ok(result),
        Err(e) => Err(errors::Error::ReadFile),
    }
}

pub trait OpenPasswordsFile {
    fn open_passwords_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<fs::File, errors::Error>;
}
impl OpenPasswordsFile for fs::OpenOptions {
    fn open_passwords_file<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> Result<fs::File, errors::Error> {
        match self.open(path) {
            Ok(f) => Ok(f),
            Err(_) => Err(errors::Error::OpenFile),
        }
    }
}

pub trait XorPasswordsFile {
    fn xor_passwords_file<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), errors::Error>;
}
impl XorPasswordsFile for fs::File {
    fn xor_passwords_file<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), errors::Error> {
        let key_bytes = key.as_ref();
        let ket_bytes_length = key_bytes.len();
        let mut key_index = 0;
        let mut buffer = [0u8; 1024];
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
            file_write_all(self, &mut buffer[..amount])?;
            file_cursor_position += amount as u64;
        }
    }
}

pub struct LockPasswordsFileResult {
    pub flags_before_lock: i32,
}
pub trait LockPasswordsFile {
    fn lock_passwords_file(&mut self) -> Result<LockPasswordsFileResult, errors::Error>;
}
#[cfg(target_family = "unix")]
impl LockPasswordsFile for fs::File {
    fn lock_passwords_file(&mut self) -> Result<LockPasswordsFileResult, errors::Error> {
        let flags = self.get_unix_flags()?;
        self.set_unix_flags(flags | (UnixFileFlags::Immutable as i32))?;
        Ok(LockPasswordsFileResult {
            flags_before_lock: flags,
        })
    }
}

pub trait EncryptPasswordsFile {
    fn encrypt_passwords_file<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), errors::Error>;
}
impl EncryptPasswordsFile for fs::File {
    fn encrypt_passwords_file<K: AsRef<[u8]>>(&mut self, key: K) -> Result<(), errors::Error> {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let seed_bytes = hasher.finalize();
        let mut seed = [0u8; 32];
        for (index, byte) in seed_bytes.as_slice().iter().enumerate() {
            seed[index] = *byte;
        }
        let mut chacha = ChaCha20Rng::from_seed(seed);
        let mut xor_key_buffer = [0u8; 1024];
        let mut file_buffer = [0u8; 1024];
        let mut file_cursor_position = 0;
        loop {
            let amount = file_read(self, &mut file_buffer)?;
            if amount == 0 {
                break Ok(());
            }
            // generate key
            chacha.fill_bytes(&mut xor_key_buffer[..amount]);
            for i in 0..amount {
                file_buffer[i] ^= xor_key_buffer[i];
            }
            file_seek(self, SeekFrom::Start(file_cursor_position))?;
            file_write_all(self, &mut file_buffer[..amount])?;
            file_cursor_position += amount as u64;
        }
    }
}
