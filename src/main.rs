mod errors;
mod files;

use files::*;
use files::flags::*;
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

fn file_flags_test(){
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open("test.txt")
        .unwrap();
    let mut flags=file.get_unix_flags().unwrap();
    println!("inital flags: {}",flags);
    flags |=0x10;
}

fn lock_file_test(){
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .open("test.txt")
        .unwrap();
    //file.lock_passwords_file().unwrap();
    use std::os::unix::io::AsRawFd;
    let mut x=0;
    unsafe {
        let addr= &mut x as *mut i32;
        let get_result=libc::ioctl(file.as_raw_fd(), 2148034049,addr);
        if get_result<0{
            panic!("failed to get flags");
        }
        println!("flags: {}",*addr);
        *addr|=0x10;
        let result=libc::ioctl(file.as_raw_fd(), 1074292226,addr);
        if result<0{
            panic!("failed to set flags");
        }else{
            println!("success");
        }
    }
}


fn main() {
    lock_file_test();
}
