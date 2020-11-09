use crate::encrypt::*;
use crate::errors;
use crate::files::*;
use rand::rngs::ThreadRng;
use rand::RngCore;
use sha2::Sha512;
use std::fs;

pub trait EncryptFile {
    fn encrypt(
        &mut self,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::LockerError>;
    fn encrypt_file<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::LockerError>;
}

fn encrypt_file(
    file: &mut fs::File,
    backup_file: &mut fs::File,
    key: &str,
    headers: &mut EncryptedFileHeaders,
) -> Result<(), errors::LockerError> {
    let mut hmac_hasher = Sha512::new();

    // leave the headers empty for now,
    // as some of the values like the hmac havn't been calculated yet
    file_seek(file, SeekFrom::Start(headers.len() as u64))?;

    // seek to the start of the backup file
    if backup_file.seek(SeekFrom::Start(0)).is_err() {
        return Err(errors::LockerError::SeekBackupFile);
    }
    // encrypt the file. used extra scope to dispose large buffers
    {
        let mut file_buffer = [0u8; READ_BUFFER_SIZE];
        let mut xor_key_buffer = [0u8; READ_BUFFER_SIZE];
        let mut chacha = create_chacha(&key, &headers.encryption_salt);
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
    finalize_hash_into_buffer(hmac_hasher, &mut headers.hmac);
    Ok(())
}

impl EncryptFile for fs::File {
    fn encrypt(
        &mut self,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::LockerError> {
        let mut headers = EncryptedFileHeaders::new(salt_length);
        let mut hash_salt_buffer = vec![0u8; salt_length];
        thread_random.fill_bytes(&mut hash_salt_buffer);

        let mut encryption_salt_buffer = vec![0u8; salt_length];
        thread_random.fill_bytes(&mut encryption_salt_buffer);

        // generate salted key hash
        create_salted_hash::<Sha512, _, _>(&key, &hash_salt_buffer, &mut headers.salted_key_hash);

        let mut backup_file = self.backup(backup_file_name)?;

        fn encrypt_content_and_write_headers(
            file: &mut fs::File,
            backup_file: &mut fs::File,
            key: &str,
            headers: &mut EncryptedFileHeaders,
        ) -> Result<(), errors::LockerError> {
            encrypt_file(file, backup_file, key, headers)?;
            // go back to the start of the file to write the headers
            file_seek(file, SeekFrom::Start(0))?;

            file_write_all(file, &headers.salted_key_hash)?;
            file_write_all(file, &headers.hmac)?;
            file_write_all(file, &headers.salt_length.to_ne_bytes())?;
            file_write_all(file, &headers.hash_salt)?;
            file_write_all(file, &headers.encryption_salt)
        }

        match encrypt_content_and_write_headers(self, &mut backup_file, key, &mut headers) {
            Ok(()) => {
                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(errors::LockerError::RemoveBackupFile),
                }
            }
            Err(e) => {
                self.revert_to_backup(&mut backup_file)?;

                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Err(e),
                    Err(_) => Err(errors::LockerError::RemoveBackupFile),
                }
            }
        }
    }
    fn encrypt_file<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
        salt_length: usize,
        thread_random: &mut ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::LockerError> {
        match fs::OpenOptions::new().read(true).write(true).open(path) {
            Ok(mut file) => file.encrypt(key, salt_length, thread_random, backup_file_name),
            Err(_) => Err(errors::LockerError::OpenFile),
        }
    }
}

#[derive(Debug)]
pub struct EncryptedFileHeaders {
    salted_key_hash: [u8; 64],
    hmac: [u8; 64],
    salt_length: usize,
    hash_salt: Vec<u8>,
    encryption_salt: Vec<u8>,
}
impl EncryptedFileHeaders {
    fn new(salt_length: usize) -> EncryptedFileHeaders {
        EncryptedFileHeaders {
            salted_key_hash: [0u8; 64],
            hmac: [0u8; 64],
            salt_length,
            hash_salt: vec![0u8; 64],
            encryption_salt: vec![0u8; 64],
        }
    }
    fn from_file(file: &mut fs::File) -> Result<EncryptedFileHeaders, errors::LockerError> {
        let mut salted_key_hash = [0u8; 64];
        let mut hmac = [0u8; 64];
        let mut salt_length_bytes = [0u8; std::mem::size_of::<usize>()];
        if file.read_exact(&mut salted_key_hash).is_err()
            || file.read_exact(&mut hmac).is_err()
            || file.read_exact(&mut salt_length_bytes).is_err()
        {
            return Err(errors::LockerError::FileNotLocked);
        }
        let salt_length = usize::from_ne_bytes(salt_length_bytes);
        let mut hash_salt = vec![0u8; salt_length];
        let mut encryption_salt = vec![0u8; salt_length];
        if file.read_exact(&mut hash_salt).is_err()
            || file.read_exact(&mut encryption_salt).is_err()
        {
            Err(errors::LockerError::FileNotLocked)
        } else {
            Ok(EncryptedFileHeaders {
                salted_key_hash,
                hmac,
                salt_length,
                hash_salt,
                encryption_salt,
            })
        }
    }
    fn write_to_file(&self, file: &mut fs::File) -> Result<(), errors::LockerError> {
        file_write_all(file, &self.salted_key_hash)?;
        file_write_all(file, &self.hmac)?;
        file_write_all(file, &self.salt_length.to_ne_bytes())?;
        file_write_all(file, &self.hash_salt)?;
        file_write_all(file, &self.encryption_salt)
    }
    fn len(&self) -> usize {
        self.salted_key_hash.len()
            + self.hmac.len()
            + self.salt_length * 2
            + std::mem::size_of::<usize>()
    }
    fn encryption_salt_start(&self) -> usize {
        self.salted_key_hash.len() + self.hmac.len() + self.salt_length
    }
}

pub trait ReadLockedFileHeaders {
    fn read_locked_file_headers<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<EncryptedFileHeaders, errors::LockerError>;
}
impl ReadLockedFileHeaders for fs::File {
    fn read_locked_file_headers<P: AsRef<std::path::Path>>(
        path: P,
    ) -> Result<EncryptedFileHeaders, errors::LockerError> {
        let mut immutable_file = fs::OpenOptions::new()
            .read(true)
            .open_passwords_file(&path)?;
        let headers = EncryptedFileHeaders::from_file(&mut immutable_file)?;
        Ok(headers)
    }
}

#[derive(Debug)]
pub struct EncryptedFile {
    headers: EncryptedFileHeaders,
    file: fs::File,
    chacha: rand_chacha::ChaCha20Rng,
    key: String,
}
impl EncryptedFile {
    pub fn open<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
    ) -> Result<EncryptedFile, errors::LockerError> {
        let mut file = match fs::OpenOptions::new().read(true).open(path) {
            Ok(f) => f,
            Err(_) => return Err(errors::LockerError::OpenFile),
        };
        let headers = EncryptedFileHeaders::from_file(&mut file)?;
        Ok(EncryptedFile {
            chacha: create_chacha(key, &headers.encryption_salt),
            headers,
            file,
            key: key.to_string(),
        })
    }
    pub fn from_file(mut file: fs::File, key: &str) -> Result<EncryptedFile, errors::LockerError> {
        let headers = EncryptedFileHeaders::from_file(&mut file)?;
        Ok(EncryptedFile {
            chacha: create_chacha(key, &headers.encryption_salt),
            headers,
            file,
            key: key.to_string(),
        })
    }
    pub fn with_headers(file: fs::File, headers: EncryptedFileHeaders, key: &str) -> EncryptedFile {
        EncryptedFile {
            chacha: create_chacha(key, &headers.encryption_salt),
            headers,
            file,
            key: key.to_string(),
        }
    }
    fn seek(&mut self, pos: SeekFrom) -> Result<(), errors::LockerError> {
        match self.file.seek(pos) {
            Ok(_) => Ok(()),
            Err(_) => Err(errors::LockerError::SeekFile),
        }
    }
    fn seek_to_encryption_salt_start(&mut self) -> Result<(), errors::LockerError> {
        self.seek(SeekFrom::Start(self.headers.encryption_salt_start() as u64))
    }
    pub fn read_exact(
        &mut self,
        buf: &mut [u8],
        key_buf: &mut [u8],
    ) -> Result<(), errors::LockerError> {
        if self.file.read_exact(buf).is_err() {
            return Err(errors::LockerError::ReadFile);
        }
        self.chacha.fill_bytes(key_buf);
        for i in 0..buf.len() {
            buf[i] ^= key_buf[i]
        }
        Ok(())
    }
    pub fn read(
        &mut self,
        buf: &mut [u8],
        key_buf: &mut [u8],
    ) -> Result<usize, errors::LockerError> {
        let amount = match self.file.read(buf) {
            Ok(amount) => amount,
            Err(_) => return Err(errors::LockerError::ReadFile),
        };
        chacha_encrypt(&mut buf[..amount], &mut key_buf[..amount], &mut self.chacha);
        Ok(amount)
    }
    pub fn reencrypt(
        &mut self,
        thread_random: &mut rand::rngs::ThreadRng,
        backup_file_name: &str,
    ) -> Result<(), errors::LockerError> {
        let mut encryption_salt_buffer = vec![0u8; self.headers.salt_length];
        thread_random.fill_bytes(&mut encryption_salt_buffer);

        let mut backup_file = self.file.backup(backup_file_name)?;

        fn reencrypt_content_and_rewrite_header(
            file: &mut EncryptedFile,
            backup_file: &mut fs::File,
            encryption_salt_buffer: &[u8],
        ) -> Result<(), errors::LockerError> {
            encrypt_file(&mut file.file, backup_file, &file.key, &mut file.headers)?;
            file.seek_to_encryption_salt_start()?;
            file_write_all(&mut file.file, &encryption_salt_buffer)
        }
        match reencrypt_content_and_rewrite_header(self, &mut backup_file, &encryption_salt_buffer)
        {
            Ok(()) => {
                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(errors::LockerError::RemoveBackupFile),
                }
            }
            Err(e) => {
                self.file.revert_to_backup(&mut backup_file)?;

                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Err(e),
                    Err(_) => Err(errors::LockerError::RemoveBackupFile),
                }
            }
        }
    }
}

pub trait ImmutableFile {
    fn is_immutable(&mut self) -> Result<bool, errors::LockerError>;
    fn make_immutable(&mut self, original_flags: i32) -> Result<(), errors::LockerError>;
    fn make_mutable(&mut self, original_flags: i32) -> Result<(), errors::LockerError>;
}
#[cfg(target_family = "unix")]
impl ImmutableFile for EncryptedFile {
    fn is_immutable(&mut self) -> Result<bool, errors::LockerError> {
        Ok((self.file.get_unix_flags()? & UnixFileFlags::Immutable as i32) != 0)
    }
    fn make_immutable(&mut self, original_flags: i32) -> Result<(), errors::LockerError> {
        self.file
            .set_unix_flags(original_flags | (UnixFileFlags::Immutable as i32))
    }
    fn make_mutable(&mut self, original_flags: i32) -> Result<(), errors::LockerError> {
        self.file
            .set_unix_flags(original_flags & (!(UnixFileFlags::Immutable as i32)))
    }
}
#[cfg(target_family = "unix")]
impl ImmutableFile for fs::File {
    fn is_immutable(&mut self) -> Result<bool, errors::LockerError> {
        Ok((self.get_unix_flags()? & UnixFileFlags::Immutable as i32) != 0)
    }
    fn make_immutable(&mut self, original_flags: i32) -> Result<(), errors::LockerError> {
        self.set_unix_flags(original_flags | (UnixFileFlags::Immutable as i32))
    }
    fn make_mutable(&mut self, original_flags: i32) -> Result<(), errors::LockerError> {
        self.set_unix_flags(original_flags & (!(UnixFileFlags::Immutable as i32)))
    }
}

pub trait UnlockFile {
    fn unlock_file<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
        backup_file_name: &str,
        headers: &EncryptedFileHeaders,
    ) -> Result<(), errors::LockerError>;
}
#[cfg(target_family = "unix")]
fn unlock_file(
    file: &mut fs::File,
    backup_file: &mut EncryptedFile,
    headers: &EncryptedFileHeaders,
) -> Result<(), errors::LockerError> {
    if backup_file
        .seek(SeekFrom::Start(headers.len() as u64))
        .is_err()
    {
        return Err(errors::LockerError::SeekBackupFile);
    }
    file_seek(file, SeekFrom::Start(0))?;
    let mut hmac_hasher = Sha512::new();
    let mut total_amount = 0u64;
    {
        let mut file_buffer = [0u8; READ_BUFFER_SIZE];
        let mut xor_key_buffer = [0u8; READ_BUFFER_SIZE];
        loop {
            let amount = match backup_file.read(&mut file_buffer, &mut xor_key_buffer) {
                Ok(result) => result,
                Err(_) => return Err(errors::LockerError::ReadBackupFile),
            };
            if amount == 0 {
                break;
            }
            total_amount += amount as u64;
            file_write_all(file, &mut file_buffer)?;
            hmac_hasher.update(&file_buffer);
        }
    }
    let mut hmac_buffer = [0u8; 64];
    finalize_hash_into_buffer(hmac_hasher, &mut hmac_buffer);
    if hmac_buffer == headers.hmac {
        return Err(errors::LockerError::InvalidHmac);
    }
    match file.set_len(total_amount) {
        Ok(_) => Ok(()),
        Err(_) => Err(errors::LockerError::SetLengthFile),
    }
}
impl UnlockFile for fs::File {
    fn unlock_file<P: AsRef<std::path::Path>>(
        path: P,
        key: &str,
        backup_file_name: &str,
        headers: &EncryptedFileHeaders,
    ) -> Result<(), errors::LockerError> {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open_passwords_file(&path)?;
        let mut backup_file = EncryptedFile::from_file(file.backup(backup_file_name)?, key)?;
        file_seek(&mut file, SeekFrom::Start(0))?;
        let mut salted_key_hash_buffer = [0u8; 64];
        create_salted_hash::<Sha512, _, _>(key, &headers.hash_salt, &mut salted_key_hash_buffer);
        match {
            if salted_key_hash_buffer == headers.salted_key_hash {
                unlock_file(&mut file, &mut backup_file, &headers)
            } else {
                Err(errors::LockerError::WrongPassword)
            }
        } {
            Ok(()) => {
                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(errors::LockerError::RemoveBackupFile),
                }
            }
            Err(e) => {
                file.revert_to_backup(&mut backup_file.file)?;

                // close the file before removing it
                drop(backup_file);
                match fs::remove_file(backup_file_name) {
                    Ok(()) => Err(e),
                    Err(_) => Err(errors::LockerError::RemoveBackupFile),
                }
            }
        }
    }
}
