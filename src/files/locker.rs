use crate::encrypt::*;
use crate::errors;
use crate::files::*;
use rand::rngs::ThreadRng;
use rand::RngCore;
use sha2::Sha512;
use std::fs;

pub trait LockFile {
    fn lock<F: FnOnce() -> bool>(
        &mut self,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
        backup_failed_continue_anyway: F,
    ) -> Result<(), errors::Error>;
}

fn lock_file(
    file: &mut fs::File,
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

    // encrypt the file. used extra scope to dispose large buffers
    {
        let mut file_buffer = [0u8; 1024];
        let mut xor_key_buffer = [0u8; 1024];
        let mut chacha = create_chacha(&key, &encryption_salt_buffer[..salt_length]);
        loop {
            let amount = file_read(file, &mut file_buffer)?;
            if amount == 0 {
                break;
            }
            chacha_encrypt(
                &mut file_buffer[..amount],
                &mut xor_key_buffer[..amount],
                &mut chacha,
            );
            file_seek(file, SeekFrom::Current(-(amount as i64)))?;
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
    file.set_unix_flags(flags | (flags::UnixFileFlags::Immutable as i32))
}

#[cfg(target_family = "unix")]
impl LockFile for fs::File {
    fn lock<F: FnOnce() -> bool>(
        &mut self,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
        backup_failed_continue_anyway: F,
    ) -> Result<(), errors::Error> {
        let mut hash_salt_buffer = vec![0u8; salt_length];
        thread_random.fill_bytes(&mut hash_salt_buffer);

        let mut encryption_salt_buffer = vec![0u8; salt_length];
        thread_random.fill_bytes(&mut encryption_salt_buffer);

        // generate salted key hash
        let mut salted_key_hash_buffer = [0u8; 65];
        create_salted_hash::<Sha512, _, _>(&key, &hash_salt_buffer, &mut salted_key_hash_buffer);
        // 64 bytes for the hmac itself
        // and one more byte for the null byte at the end
        let mut hmac_buffer = [0u8; 65];

        // get file flags before locking
        let flags = self.get_unix_flags()?;

        // calculate headers size
        let headers_size = salted_key_hash_buffer.len()
            + hmac_buffer.len()
            + std::mem::size_of::<usize>()
            + hash_salt_buffer.len()
            + encryption_salt_buffer.len()
            + std::mem::size_of::<i32>();

        let backup_file = match self.backup(backup_file_name) {
            Ok(file) => Some(file),
            Err(e) => {
                if backup_failed_continue_anyway() {
                    None
                } else {
                    return Err(e);
                }
            }
        };

        match lock_file(
            self,
            key,
            salt_length,
            &encryption_salt_buffer,
            &hash_salt_buffer,
            &salted_key_hash_buffer,
            &mut hmac_buffer,
            flags,
            headers_size,
        ) {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(mut backup) = backup_file {
                    self.revert_to_backup(&mut backup)?;
                }
                Err(e)
            }
        }
    }
}
