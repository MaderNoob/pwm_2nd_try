mod commands;
mod encrypt;
mod errors;
mod files;
mod password;

use files::flags::*;
use files::locker::*;
use files::*;
use password::*;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

fn main() {
    // commands::lock(
    //     "/home/clear/Documents/rust/password_manager/test.txt",
    //     "suka noob",
    //     Some(30),
    //     false,
    // );
    commands::unlock("/home/clear/Documents/rust/password_manager/test.txt");
}
