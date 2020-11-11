use crate::errors;
use crate::errors::ToGlobalError;
use crate::locker::{EncryptedFile, EncryptedFileWriter};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections;
use std::str;

const SYMBOLS: &'static str = " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
macro_rules! character_difference {
    ($bigger_char:expr,$smaller_char:expr) => {
        ($bigger_char as u8 - $smaller_char as u8) as usize + 1
    };
}
pub struct PasswordGeneratorSettings {
    use_numbers: bool,
    use_lowercase_letters: bool,
    use_uppercase_letters: bool,
    use_symbols: bool,
}
pub struct PasswordGenerator {
    used_characters: Vec<char>,
    chacha: ChaCha20Rng,
    pub password_length: usize,
}
impl PasswordGeneratorSettings {
    pub fn new() -> PasswordGeneratorSettings {
        PasswordGeneratorSettings {
            use_numbers: false,
            use_lowercase_letters: false,
            use_uppercase_letters: false,
            use_symbols: false,
        }
    }
    pub fn use_numbers(&mut self) -> &mut Self {
        self.use_numbers = true;
        self
    }
    pub fn use_lowercase_letters(&mut self) -> &mut Self {
        self.use_lowercase_letters = true;
        self
    }
    pub fn use_uppercase_letters(&mut self) -> &mut Self {
        self.use_uppercase_letters = true;
        self
    }
    pub fn use_symbols(&mut self) -> &mut Self {
        self.use_symbols = true;
        self
    }
    fn count_used_characters(&self) -> usize {
        let mut used_characters_count = 0usize;
        if self.use_numbers {
            used_characters_count += character_difference!('9', '0')
        }
        if self.use_lowercase_letters {
            used_characters_count += character_difference!('z', 'a')
        }
        if self.use_uppercase_letters {
            used_characters_count += character_difference!('Z', 'A')
        }
        if self.use_symbols {
            used_characters_count += SYMBOLS.chars().count()
        }
        used_characters_count
    }
    pub fn create_generator(&self, password_length: usize) -> PasswordGenerator {
        let mut used_characters = Vec::with_capacity(self.count_used_characters());
        if self.use_numbers {
            used_characters.extend('0'..='9');
        }
        if self.use_lowercase_letters {
            used_characters.extend('a'..='z');
        }
        if self.use_uppercase_letters {
            used_characters.extend('A'..='Z');
        }
        if self.use_symbols {
            used_characters.extend(SYMBOLS.chars())
        }
        PasswordGenerator {
            used_characters,
            password_length,
            chacha: ChaCha20Rng::from_entropy(),
        }
    }
}
impl PasswordGenerator {
    pub fn get_used_characters<'a>(&'a self) -> String {
        self.used_characters.iter().collect()
    }
    fn generate_random_usize(&mut self, min_inclusive: usize, max_exclusive: usize) -> usize {
        let mut usize_bytes = [0u8; std::mem::size_of::<usize>()];
        self.chacha.fill_bytes(usize_bytes.as_mut());
        let random_usize = usize::from_ne_bytes(usize_bytes);
        (random_usize % (max_exclusive - min_inclusive)) + min_inclusive
    }
    fn generate_random_character(&mut self) -> char {
        let random_index = self.generate_random_usize(0, self.used_characters.len());
        self.used_characters[random_index]
    }
    pub fn generate(&mut self) -> String {
        let mut result = String::with_capacity(self.password_length);
        for _ in 0..self.password_length {
            result.push(self.generate_random_character())
        }
        result
    }
}
pub struct PasswordMeta {
    pub domain: String,
    pub username: String,
    pub additional_fields: collections::HashMap<String, String>,
}
pub struct Password {
    password: String,
    meta: PasswordMeta,
}
impl Password {
    pub fn new() -> Password {
        Password {
            password: String::new(),
            meta: PasswordMeta {
                domain: String::new(),
                username: String::new(),
                additional_fields: collections::HashMap::new(),
            },
        }
    }
}

pub trait ReadPassword {
    fn read_usize(&mut self) -> Result<usize, errors::GlobalError>;
    fn read_string(&mut self, string: &mut String) -> Result<(), errors::GlobalError>;
    fn read_password(&mut self,string:&mut Password) -> Result<(),errors::GlobalError>;
}
impl ReadPassword for EncryptedFile {
    fn read_usize(&mut self) -> Result<usize, errors::GlobalError> {
        let mut usize_bytes = [0u8; std::mem::size_of::<usize>()];
        self.read_exact(&mut usize_bytes).to_global_error()?;
        Ok(usize::from_ne_bytes(usize_bytes))
    }
    fn read_string(&mut self, string: &mut String) -> Result<(), errors::GlobalError> {
        let length = self.read_usize()?;
        let mut bytes = vec![0u8; length];
        self.read_exact(&mut bytes).to_global_error()?;
        string.reserve_exact(length);
        string.extend(
            match str::from_utf8(&bytes) {
                Ok(s) => s,
                Err(_) => return Err(errors::PasswordManagerError::EncodingError.into()),
            }
            .chars(),
        );
        Ok(())
    }
    fn read_password(&mut self, password:&mut Password) -> Result<(),errors::GlobalError> {
        self.read_string(&mut password.password)?;
        self.read_string(&mut password.meta.domain)?;
        self.read_string(&mut password.meta.username)?;
        let fields_amount = self.read_usize()?;
        for _ in 0..fields_amount {
            let mut field_name = String::new();
            let mut field_value = String::new();
            self.read_string(&mut field_name)?;
            self.read_string(&mut field_value)?;
            password
                .meta
                .additional_fields
                .insert(field_name, field_value);
        }
        Ok(())
    }
}

pub struct PasswordsIterator {
    amount: usize,
    current_index: usize,
    file: EncryptedFile,
}
impl PasswordsIterator {
    pub fn from_file(
        file: std::fs::File,
        key: &str,
    ) -> Result<PasswordsIterator, errors::GlobalError> {
        let mut file: EncryptedFile = EncryptedFile::from_file(file, key).to_global_error()?;
        Ok(PasswordsIterator {
            amount: file.read_usize()?,
            current_index: 0,
            file,
        })
    }
}
impl fallible_iterator::FallibleIterator for PasswordsIterator {
    type Item = Password;
    type Error = errors::GlobalError;
    fn next(&mut self) -> Result<Option<Self::Item>, Self::Error> {
        if self.current_index >= self.amount {
            return Ok(None);
        }
        let mut password = Password::new();
        self.file.read_password(&mut password)?;
        Ok(Some(password))
    }
}
pub trait WritePasswords {
    fn write_usize(&mut self, usize_value: usize) -> Result<&mut Self, errors::GlobalError>;
    fn write_string(&mut self, string: &str) -> Result<&mut Self, errors::GlobalError>;
    fn write_password(&mut self, password: Password) -> Result<&mut Self, errors::GlobalError>;
    fn write_passwords(
        &mut self,
        passwords: Vec<Password>,
    ) -> Result<&mut Self, errors::GlobalError>;
}
impl WritePasswords for EncryptedFileWriter {
    fn write_usize(&mut self, usize_value: usize) -> Result<&mut Self, errors::GlobalError> {
        self.write_all(&mut usize_value.to_ne_bytes())
            .to_global_error()
    }
    fn write_string(&mut self, string: &str) -> Result<&mut Self, errors::GlobalError> {
        self.write_usize(string.len())?;
        let mut string_bytes: Vec<u8> = string.bytes().collect();
        self.write_all(&mut string_bytes).to_global_error()
    }
    fn write_password(&mut self, password: Password) -> Result<&mut Self, errors::GlobalError> {
        self.write_string(&password.password)?
            .write_string(&password.meta.domain)?
            .write_string(&password.meta.username)?
            .write_usize(password.meta.additional_fields.len());
        for (field_name, field_value) in password.meta.additional_fields {
            self.write_string(&field_name)?.write_string(&field_value)?;
        }
        Ok(self)
    }
    fn write_passwords(
        &mut self,
        passwords: Vec<Password>,
    ) -> Result<&mut Self, errors::GlobalError> {
        self.write_usize(passwords.len())?;
        for password in passwords {
            self.write_password(password)?;
        }
        Ok(self)
    }
}
