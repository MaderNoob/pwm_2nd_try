use crate::encrypt::*;
use crate::errors;
use crate::files::*;
use rand::rngs::ThreadRng;
use rand::RngCore;
use sha2::Sha512;
use std::fs;

pub trait LockFile {
    fn lock(
        &mut self,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::Error>;
    fn lock_file<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::Error>;
}

fn lock_file(
    file: &mut fs::File,
    backup_file: &mut fs::File,
    key: &str,
    salt_length: usize,
    encryption_salt_buffer: &[u8],
    hash_salt_buffer: &[u8],
    salted_key_hash_buffer: &[u8],
    hmac_buffer: &mut [u8],
    flags: i32,
    headers_size: usize,
) -> Result<(), errors::Error> {
    let mut hmac_hasher = Sha512::new();

    // leave the headers empty for now,
    // as some of the values like the hmac havn't been calculated yet
    file_seek(file, SeekFrom::Start(headers_size as u64))?;

    // seek to the start of the backup file
    if backup_file.seek(SeekFrom::Start(0)).is_err() {
        return Err(errors::Error::SeekBackupFile);
    }
    // encrypt the file. used extra scope to dispose large buffers
    {
        let mut file_buffer = [0u8; READ_BUFFER_SIZE];
        let mut xor_key_buffer = [0u8; READ_BUFFER_SIZE];
        let mut chacha = create_chacha(&key, &encryption_salt_buffer[..salt_length]);
        loop {
            let amount = file_read(backup_file, &mut file_buffer)?;
            if amount == 0 {
                break;
            }
            chacha_encrypt(
                &mut file_buffer[..amount],
                &mut xor_key_buffer[..amount],
                &mut chacha,
            );
            file_write_all(file, &file_buffer[..amount])?;
            hmac_hasher.update(&file_buffer[..amount]);
        }
    }

    // finalize hmac after updating it with encrypted file content
    finalize_hash_into_buffer(hmac_hasher, hmac_buffer);

    // go back to the start of the file to write the headers
    file_seek(file, SeekFrom::Start(0))?;

    file_write_all(file, &salted_key_hash_buffer)?;
    file_write_all(file, &hmac_buffer)?;
    file_write_all(file, &salt_length.to_ne_bytes())?;
    file_write_all(file, &hash_salt_buffer)?;
    file_write_all(file, &encryption_salt_buffer)?;
    file_write_all(file, &flags.to_ne_bytes())?;
    if cfg!(debug_assertions) {
        Ok(())
    } else {
        file.set_unix_flags(flags | (flags::UnixFileFlags::Immutable as i32))
    }
}

impl LockFile for fs::File {
    fn lock(
        &mut self,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::Error> {
        let mut hash_salt_buffer = vec![0u8; salt_length];
        thread_random.fill_bytes(&mut hash_salt_buffer);

        let mut encryption_salt_buffer = vec![0u8; salt_length];
        thread_random.fill_bytes(&mut encryption_salt_buffer);

        // generate salted key hash
        let mut salted_key_hash_buffer = [0u8; 64];
        create_salted_hash::<Sha512, _, _>(&key, &hash_salt_buffer, &mut salted_key_hash_buffer);
        // 64 bytes for the hmac itself
        // and one more byte for the null byte at the end
        let mut hmac_buffer = [0u8; 64];

        // get file flags before locking
        let flags = self.get_unix_flags()?;

        // calculate headers size
        let headers_size = salted_key_hash_buffer.len()
            + hmac_buffer.len()
            + std::mem::size_of::<usize>()
            + hash_salt_buffer.len()
            + encryption_salt_buffer.len()
            + std::mem::size_of::<i32>();

        let mut backup_file = self.backup(backup_file_name)?;

        match lock_file(
            self,
            &mut backup_file,
            key,
            salt_length,
            &encryption_salt_buffer,
            &hash_salt_buffer,
            &salted_key_hash_buffer,
            &mut hmac_buffer,
            flags,
            headers_size,
        ) {
            Ok(()) => {
                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(errors::Error::RemoveBackupFile),
                }
            }
            Err(e) => {
                self.revert_to_backup(&mut backup_file)?;

                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Err(e),
                    Err(_) => Err(errors::Error::RemoveBackupFile),
                }
            }
        }
    }
    fn lock_file<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::Error> {
        match fs::OpenOptions::new().read(true).write(true).open(path) {
            Ok(mut file) => file.lock(key, salt_length, thread_random, backup_file_name),
            Err(_) => Err(errors::Error::OpenFile),
        }
    }
}

#[derive(Debug)]
pub struct LockedFileHeaders {
    salted_key_hash: [u8; 64],
    hmac: [u8; 64],
    salt_length: usize,
    hash_salt: Vec<u8>,
    encryption_salt: Vec<u8>,
    flags: i32,
    headers_size: usize,
}
impl LockedFileHeaders {
    fn from_file(file: &mut fs::File) -> Result<LockedFileHeaders, errors::Error> {
        let mut salted_key_hash = [0u8; 64];
        let mut hmac = [0u8; 64];
        let mut salt_length_bytes = [0u8; std::mem::size_of::<usize>()];
        if file.read_exact(&mut salted_key_hash).is_err()
            || file.read_exact(&mut hmac).is_err()
            || file.read_exact(&mut salt_length_bytes).is_err()
        {
            return Err(errors::Error::FileNotLocked);
        }
        let salt_length = usize::from_ne_bytes(salt_length_bytes);
        let mut hash_salt = vec![0u8; salt_length];
        let mut encryption_salt = vec![0u8; salt_length];
        let mut flags_buffer = [0u8; std::mem::size_of::<i32>()];
        if file.read_exact(&mut hash_salt).is_err()
            || file.read_exact(&mut encryption_salt).is_err()
            || file.read_exact(&mut flags_buffer).is_err()
        {
            Err(errors::Error::FileNotLocked)
        } else {
            Ok(LockedFileHeaders {
                headers_size: salted_key_hash.len()
                    + hmac.len()
                    + std::mem::size_of::<usize>()
                    + &hash_salt.len()
                    + &encryption_salt.len()
                    + std::mem::size_of::<i32>(),
                salted_key_hash,
                hmac,
                salt_length,
                hash_salt,
                encryption_salt,
                flags: i32::from_ne_bytes(flags_buffer),
            })
        }
    }
}

pub trait ReadLockedFileHeaders {
    fn read_locked_file_headers<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<LockedFileHeaders, errors::Error>;
}
impl ReadLockedFileHeaders for fs::File {
    fn read_locked_file_headers<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<LockedFileHeaders, errors::Error> {
        let mut immutable_file = fs::OpenOptions::new()
            .read(true)
            .open_passwords_file(&path)?;
        let headers = LockedFileHeaders::from_file(&mut immutable_file)?;
        if cfg!(debug_assertion) {
        } else {
            immutable_file.set_unix_flags(headers.flags)?;
        }
        Ok(headers)
    }
}

pub trait UnlockFile {
    fn unlock_file<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
        backup_file_name: &str,
        headers: &LockedFileHeaders,
    ) -> Result<(), errors::Error>;
}
#[cfg(target_family = "unix")]
fn unlock_file(
    file: &mut fs::File,
    backup_file: &mut fs::File,
    key: &str,
    headers: &LockedFileHeaders,
) -> Result<(), errors::Error> {
    if backup_file
        .seek(SeekFrom::Start(headers.headers_size as u64))
        .is_err()
    {
        return Err(errors::Error::SeekBackupFile);
    }
    file_seek(file, SeekFrom::Start(0))?;
    let mut hmac_hasher = Sha512::new();
    let mut total_amount = 0u64;
    {
        let mut chacha = create_chacha(key, &headers.encryption_salt);
        let mut file_buffer = [0u8; READ_BUFFER_SIZE];
        let mut xor_key_buffer = [0u8; READ_BUFFER_SIZE];
        loop {
            let amount = match backup_file.read(&mut file_buffer) {
                Ok(result) => result,
                Err(_) => return Err(errors::Error::ReadBackupFile),
            };
            if amount == 0 {
                break;
            }
            total_amount += amount as u64;
            chacha_encrypt(&mut file_buffer, &mut xor_key_buffer, &mut chacha);
            file_write_all(file, &mut file_buffer)?;
            hmac_hasher.update(&file_buffer);
        }
    }
    let mut hmac_buffer = [0u8; 64];
    finalize_hash_into_buffer(hmac_hasher, &mut hmac_buffer);
    if hmac_buffer == headers.hmac {
        return Err(errors::Error::InvalidHmac);
    }
    if file.set_len(total_amount).is_err() {
        return Err(errors::Error::SetLengthFile);
    }
    if cfg!(unix) {
        Ok(())
    } else {
        file.set_unix_flags(headers.flags)
    }
}
impl UnlockFile for fs::File {
    fn unlock_file<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
        backup_file_name: &str,
        headers:&LockedFileHeaders,
    ) -> Result<(), errors::Error> {
        // close file so we can open it with write permissions
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open_passwords_file(&path)?;
        let mut backup_file = file.backup(backup_file_name)?;
        file_seek(&mut file, SeekFrom::Start(0))?;
        let mut salted_key_hash_buffer = [0u8; 64];
        create_salted_hash::<Sha512, _, _>(key, &headers.hash_salt, &mut salted_key_hash_buffer);
        match {
            if salted_key_hash_buffer == headers.salted_key_hash {
                unlock_file(&mut file, &mut backup_file, key, &headers)
            } else {
                Err(errors::Error::WrongPassword)
            }
        } {
            Ok(()) => {
                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(errors::Error::RemoveBackupFile),
                }
            }
            Err(e) => {
                file.revert_to_backup(&mut backup_file)?;

                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Err(e),
                    Err(_) => Err(errors::Error::RemoveBackupFile),
                }
            }
        }
    }
}
