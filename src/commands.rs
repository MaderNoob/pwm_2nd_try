use crate::errors::LockerError;
use crate::locker::{LockFile, ReadLockedFileHeaders, UnlockFile};
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
fn handle_error(error: LockerError, path: &str, backup_file_path: &str, error_style: &ansi_term::Style) {
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
        LockerError::FileGetFlags => StringErrorMessage::Str("Failed to get flags of the target file"),
        LockerError::FileSetFlags => StringErrorMessage::Str("Failed to set flags for the target file"),
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

fn get_error_message_style() -> ansi_term::Style {
    ansi_term::Colour::Red.bold()
}

fn get_success_message_style() -> ansi_term::Style {
    ansi_term::Colour::Green.bold()
}

fn lock(path: &str, key: &str, salt_length: Option<usize>) {
    let backup_file_name = get_backup_file_name(path);
    let mut thread_random = rand::thread_rng();
    let error_style = get_error_message_style();
    let success_style = get_success_message_style();
    match fs::File::lock_file(
        path,
        key,
        salt_length.unwrap_or(DEFAULT_SALT_LENGTH),
        &mut thread_random,
        &backup_file_name[..],
    ) {
        Ok(()) => println!(
            "{}",
            success_style.paint("The target file was successfully locked")
        ),
        Err(error) => {
            if let LockerError::WrongPassword = error {
                eprintln!("{}", error_style.paint("An unexpected error has occured"));
            } else {
                handle_error(error, path, &backup_file_name[..], &error_style);
            }
        }
    }
}

fn unlock(path: &str) {
    let backup_file_name = get_backup_file_name(path);
    let error_style = get_error_message_style();
    let success_style = get_success_message_style();
    let headers = match fs::File::read_locked_file_headers(path) {
        Ok(headers) => headers,
        Err(error) => {
            if let LockerError::WrongPassword = error {
                eprintln!("{}", error_style.paint("An unexpected error has occured"));
            } else {
                handle_error(error, path, &backup_file_name[..], &error_style);
            }
            return;
        }
    };
    loop {
        let key = match rpassword::read_password_from_tty(Some(
            "Enter the password for the target file:",
        )) {
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
            Ok(()) => println!(
                "{}",
                success_style.paint("The target file was successfully unlocked")
            ),
            Err(error) => {
                if let LockerError::WrongPassword = error {
                } else {
                    handle_error(error, path, &backup_file_name[..], &error_style);
                }
            }
        }
    }
}

// fn new(password:String,domain:String,username:String);
