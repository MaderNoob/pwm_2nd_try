use crate::errors;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};

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

pub trait FileGetFlags {
    fn get_unix_flags(&self) -> Result<i32, errors::Error>;
}
#[cfg(target_family = "unix")]
impl FileGetFlags for fs::File {
    fn get_unix_flags(&self) -> Result<i32, errors::Error> {
        let mut flags = 0;
        let flags_ptr = &mut flags as *mut i32;
        unsafe {
            use std::os::unix::io::AsRawFd;
            if libc::ioctl(self.as_raw_fd(), 2148034049, flags_ptr) < 0 {
                Err(errors::Error::FileGetFlags)
            } else {
                Ok(flags)
            }
        }
    }
}

pub trait FileSetFlags {
    fn set_unix_flags(&self, new_flags: i32) -> Result<i32, errors::Error>;
}
#[cfg(target_family = "unix")]
impl FileSetFlags for fs::File {
    fn set_unix_flags(&self, new_flags: i32) -> Result<(), errors::Error> {
        let flags_ptr = &mut new_flags as *mut i32;
        unsafe {
            use std::os::unix::io::AsRawFd;
            if libc::ioctl(self.as_raw_fd(), 1074292226, flags_ptr)<0{
                Err(errors::Error::FileSetFlags)
            }else{
                Ok(())
            }
        }
    }
}

pub trait LockPasswordsFile {
    fn lock_passwords_file(&mut self) -> Result<(), errors::Error>;
}
impl LockPasswordsFile for fs::File {
    fn lock_passwords_file(&mut self) -> Result<(), errors::Error> {
        let metadata = match self.metadata() {
            Ok(m) => m,
            Err(_) => return Err(errors::Error::FileGetMetadata),
        };
        let mut permissions = metadata.permissions();
        permissions.set_readonly(true);
        if cfg!(unix) {
            use std::os::unix::fs::PermissionsExt;
            // set all access modifiers to read only read only
            permissions.set_mode(0o1444);
            if self.set_permissions(permissions).is_err() {
                return Err(errors::Error::FileSetPermissions);
            }
        }
        Ok(())
    }
}
