pub mod flags;

use crate::errors;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use flags::*;

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
            match self.read(&mut buffer) {
                Ok(amount) => {
                    if amount == 0 {
                        break Ok(());
                    }
                    for byte in &mut buffer[..amount] {
                        *byte ^= key_bytes[key_index];
                        key_index = (key_index + 1) % ket_bytes_length;
                    }
                    if self.seek(SeekFrom::Start(file_cursor_position)).is_err() {
                        return Err(errors::Error::SeekFile);
                    }
                    if self.write_all(&buffer[..amount]).is_err() {
                        return Err(errors::Error::WriteFile);
                    }
                    file_cursor_position += amount as u64;
                }
                Err(_) => return Err(errors::Error::ReadFile),
            }
        }
    }
}

pub struct LockPasswordsFileResult{
    pub flags_before_lock:i32,
}
pub trait LockPasswordsFile {
    fn lock_passwords_file(&mut self) -> Result<LockPasswordsFileResult, errors::Error>;
}
#[cfg(target_family = "unix")]
impl LockPasswordsFile for fs::File {
    fn lock_passwords_file(&mut self) -> Result<LockPasswordsFileResult, errors::Error> {
        let flags=self.get_unix_flags()?;
        self.set_unix_flags(flags|(UnixFileFlags::Immutable as i32))?;
        Ok(LockPasswordsFileResult{
            flags_before_lock:flags,
        })
    }
}
