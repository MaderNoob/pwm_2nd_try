mod errors;
mod files;

use files::*;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

fn xor_file_test(){
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

fn main() {
    
}
