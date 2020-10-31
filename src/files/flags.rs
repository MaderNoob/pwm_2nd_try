use std::fs;
use crate::errors;

pub enum UnixFileFlags{
    Immutable=0x10,
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
    fn set_unix_flags(&self, new_flags: i32) -> Result<(), errors::Error>;
}
#[cfg(target_family = "unix")]
impl FileSetFlags for fs::File {
    fn set_unix_flags(&self, mut new_flags: i32) -> Result<(), errors::Error> {
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