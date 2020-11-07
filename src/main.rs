mod commands;
mod encrypt;
mod errors;
mod files;
mod password;

use files::flags::*;
use files::locker::*;
use files::*;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use password::*;

fn main() {
    let mut gen = password::PasswordGeneratorSettings::new()
        .use_numbers()
        .use_lowercase_letters()
        .use_uppercase_letters()
        .use_symbols()
        .create_generator(30);
    println!("{}",gen.generate());
}
