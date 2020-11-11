use crate::errors::LockerError;
use crate::files::OpenWithCustomError;
use crate::flags::{FileGetFlags, FileSetFlags, UnixFileFlags};
use crate::locker::{
    EncryptFile, EncryptedFileHeaders, ImmutableFile, ReadLockedFileHeaders, UnlockFile,
};
use std::fs;

pub const DEFAULT_SALT_LENGTH: usize = 20;

fn get_backup_file_name(path: &str) -> String {
    format!("{}.pwm.backup", path)
}

enum StringErrorMessage {
    String(String),
    Str(&'static str),
}

// handles every error except the WrongPassword error,
// which should be handled before calling this function
fn handle_locker_error(
    error: LockerError,
    path: &str,
    backup_file_path: &str,
    error_style: &ansi_term::Style,
) {
    let error_message = match error {
        LockerError::OpenFile => {
            StringErrorMessage::String(format!("Failed to open the target file: \"{}\"", path))
        }
        LockerError::ReadFile => StringErrorMessage::Str("Failed to read from the target file"),
        LockerError::SeekFile => StringErrorMessage::Str("Failed to seek on the target file"),
        LockerError::WriteFile => StringErrorMessage::Str("Failed to write to the target file"),
        LockerError::SetLengthFile => {
            StringErrorMessage::Str("Failed to set the length of the target file")
        }
        LockerError::FileGetFlags => {
            StringErrorMessage::Str("Failed to get flags of the target file")
        }
        LockerError::FileSetFlags => {
            StringErrorMessage::Str("Failed to set flags for the target file")
        }
        LockerError::CreatBackupFile => StringErrorMessage::String(format!(
            "Failed to create a backup file: \"{}\"",
            backup_file_path
        )),
        LockerError::WriteBackupFile => StringErrorMessage::String(format!(
            "Failed to write to the backup file: \"{}\"",
            backup_file_path
        )),
        LockerError::ReadBackupFile => StringErrorMessage::String(format!(
            "Failed to read from the backup file: \"{}\"",
            backup_file_path
        )),
        LockerError::SeekBackupFile => StringErrorMessage::String(format!(
            "Failed to seek on the backup file: \"{}\"",
            backup_file_path
        )),
        LockerError::SetLengthBackupFile => StringErrorMessage::String(format!(
            "Failed to set the length of the the backup file: \"{}\"",
            backup_file_path
        )),
        LockerError::RemoveBackupFile => StringErrorMessage::String(format!(
            "Failed to remove the the backup file: \"{}\"",
            backup_file_path
        )),
        LockerError::FileNotLocked => StringErrorMessage::Str("The target file is not locked"),
        LockerError::WrongPassword => {
            panic!("Wrong password error should be handled oustside of this function")
        }
        LockerError::InvalidHmac => StringErrorMessage::Str("Invalid HMAC for file"),
    };
    match error_message {
        StringErrorMessage::Str(msg) => eprintln!("{}", error_style.paint(msg)),
        StringErrorMessage::String(msg) => eprintln!("{}", error_style.paint(&msg[..])),
    }
}

// handle locker errors caused by function that are no using passwords,
// will print that an unexpected error has occured if it gets a wrong password error
fn handle_locker_error_no_password(
    error: LockerError,
    path: &str,
    backup_file_path: &str,
    error_style: &ansi_term::Style,
) {
    if let LockerError::WrongPassword = error {
        eprintln!("{}", error_style.paint("An unexpected error has occured"));
    } else {
        handle_locker_error(error, path, backup_file_path, error_style);
    }
}

fn get_error_message_style() -> ansi_term::Style {
    ansi_term::Colour::Red.bold()
}

fn get_success_message_style() -> ansi_term::Style {
    ansi_term::Colour::Green.bold()
}

macro_rules! try_locker_error_no_password {
    ($result:expr,$path:expr,$backup_path:expr,$error_style:expr) => {
        match $result {
            Ok(v) => v,
            Err(e) => {
                handle_locker_error_no_password(e, $path, $backup_path, $error_style);
                return;
            }
        }
    };
}

pub fn lock(path: &str, key: &str, salt_length: Option<usize>, make_immutable: bool) {
    let backup_file_name = get_backup_file_name(path);
    let mut thread_random = rand::thread_rng();
    let error_style = get_error_message_style();
    let success_style = get_success_message_style();
    let mut file = try_locker_error_no_password!(
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open_with_custom_error(path),
        path,
        &backup_file_name[..],
        &error_style
    );
    match file.encrypt(
        key,
        salt_length.unwrap_or(DEFAULT_SALT_LENGTH),
        &mut thread_random,
        &backup_file_name[..],
    ) {
        Ok(()) => {
            if make_immutable {
                let flags = try_locker_error_no_password!(
                    file.get_unix_flags(),
                    path,
                    &backup_file_name[..],
                    &error_style
                );
                try_locker_error_no_password!(
                    file.make_immutable(flags),
                    path,
                    &backup_file_name[..],
                    &error_style
                );
            } else {
                println!(
                    "{}",
                    success_style.paint("The target file was successfully locked")
                )
            }
        }
        Err(error) => {
            handle_locker_error_no_password(error, path, &backup_file_name[..], &error_style);
        }
    }
}

fn flush_and_read_password() -> std::io::Result<String> {
    use std::io::Write;
    std::io::stdout().flush()?;
    rpassword::read_password()
}

pub fn unlock(path: &str) {
    let backup_file_name = get_backup_file_name(path);
    let error_style = get_error_message_style();
    let success_style = get_success_message_style();
    let mut file = try_locker_error_no_password!(
        fs::OpenOptions::new()
            .read(true)
            .open_with_custom_error(path),
        path,
        &backup_file_name[..],
        &error_style
    );
    let flags = try_locker_error_no_password!(
        file.get_unix_flags(),
        path,
        &backup_file_name[..],
        &error_style
    );
    if UnixFileFlags::is_flag_set(UnixFileFlags::Immutable, flags) {
        try_locker_error_no_password!(
            file.make_mutable(flags),
            path,
            &backup_file_name[..],
            &error_style
        );
    }
    let headers = try_locker_error_no_password!(
        EncryptedFileHeaders::from_file(&mut file),
        path,
        &backup_file_name[..],
        &error_style
    );
    // close the file before reopening it to unlock it
    drop(file);
    loop {
        print!("Enter the password for the target file: ");
        let key = match flush_and_read_password() {
            Ok(key) => key,
            Err(_) => {
                eprintln!(
                    "{}",
                    error_style.paint(
                        "An unexpected IO error has occured \
                    while trying to prompt the user to enter a password"
                    )
                );
                return;
            }
        };
        match fs::File::unlock_file(path, key.as_ref(), &backup_file_name[..], &headers) {
            Ok(()) => {
                println!(
                    "{}",
                    success_style.paint("The target file was successfully unlocked")
                );
                break;
            }
            Err(error) => {
                if let LockerError::WrongPassword = error {
                    eprintln!("{}", error_style.paint("Wrong password\n"))
                } else {
                    handle_locker_error(error, path, &backup_file_name[..], &error_style);
                    break;
                }
            }
        }
    }
}

// fn new(password:String,domain:String,username:String);
