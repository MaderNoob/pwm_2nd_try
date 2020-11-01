mod encrypt;
mod errors;
mod files;

use files::flags::*;
use files::locker::*;
use files::*;
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};

fn xor_file_test() {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open("test.txt")
        .unwrap();
    let metadata = file.metadata().unwrap();
    if metadata.len() == 0 {
        file.write_all(b"hello world").unwrap();
    }
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut content = String::new();
    file.read_to_string(&mut content).unwrap();
    println!("'{}'", content);
    file.seek(SeekFrom::Start(0)).unwrap();
    file.xor_passwords_file("tuktuk").unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    content.clear();
    file.read_to_string(&mut content).unwrap();
    println!("'{}'", content);
}

fn file_flags_test() {
    let mut file = OpenOptions::new().read(true).open("test.txt").unwrap();
    let mut file_flags = file.get_unix_flags().unwrap();
    println!("inital flags: {}", file_flags);
    file_flags |= 0x10;
    println!("desired flags: {}", file_flags);
    file.set_unix_flags(file_flags).unwrap();
    file_flags = file.get_unix_flags().unwrap();
    println!("new flags: {}", file_flags);
}

fn make_immutable_test() {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .open("test.txt")
        .unwrap();
    file.make_immutable().unwrap();
}

fn lock_file_test() {
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open("test.txt")
        .unwrap();
    let mut thread_random = rand::thread_rng();
    file.lock("stfu", 12, &mut thread_random, "test.txt.backup")
        .unwrap();
}

fn unlock_file_test() {
    std::fs::File::unlock("test.txt", "stfu", "test.txt.backup").unwrap();
}

fn main() {
    // lock_file_test();
    unlock_file_test();
}
