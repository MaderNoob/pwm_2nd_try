use crate::errors::Error;
use crate::locker::{LockFile,UnlockFile};
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
fn handle_error(error: Error, path: &str, backup_file_path: &str, error_style: &ansi_term::Style) {
    let error_message = match error {
        Error::OpenFile => {
            StringErrorMessage::String(format!("Failed to open the target file: \"{}\"", path))
        }
        Error::ReadFile => StringErrorMessage::Str("Failed to read from the target file"),
        Error::SeekFile => StringErrorMessage::Str("Failed to seek on the target file"),
        Error::WriteFile => StringErrorMessage::Str("Failed to write to the target file"),
        Error::SetLengthFile => {
            StringErrorMessage::Str("Failed to set the length of the target file")
        }
        Error::FileGetFlags => StringErrorMessage::Str("Failed to get flags of the target file"),
        Error::FileSetFlags => StringErrorMessage::Str("Failed to set flags for the target file"),
        Error::CreatBackupFile => StringErrorMessage::String(format!(
            "Failed to create a backup file: \"{}\"",
            backup_file_path
        )),
        Error::WriteBackupFile => StringErrorMessage::String(format!(
            "Failed to write to the backup file: \"{}\"",
            backup_file_path
        )),
        Error::ReadBackupFile => StringErrorMessage::String(format!(
            "Failed to read from the backup file: \"{}\"",
            backup_file_path
        )),
        Error::SeekBackupFile => StringErrorMessage::String(format!(
            "Failed to seek on the backup file: \"{}\"",
            backup_file_path
        )),
        Error::SetLengthBackupFile => StringErrorMessage::String(format!(
            "Failed to set the length of the the backup file: \"{}\"",
            backup_file_path
        )),
        Error::RemoveBackupFile => StringErrorMessage::String(format!(
            "Failed to remove the the backup file: \"{}\"",
            backup_file_path
        )),
        Error::FileNotLocked => StringErrorMessage::Str("The target file is not locked"),
        Error::WrongPassword => {
            panic!("Wrong password error should be handled oustside of this function")
        }
        Error::InvalidHmac => StringErrorMessage::Str("Invalid HMAC for file"),
    };
    match error_message {
        StringErrorMessage::Str(msg) => eprintln!("{}",error_style.paint(msg)),
        StringErrorMessage::String(msg) => eprintln!("{}",error_style.paint(&msg[..])),
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
            if let Error::WrongPassword = error {
                eprintln!("{}", error_style.paint("An unexpected error has occured"));
            } else {
                handle_error(error, path, &backup_file_name[..],&error_style);
            }
        }
    }
}

fn unlock(path: &str, key: &str) {
    let backup_file_name = get_backup_file_name(path);
    let error_style = get_error_message_style();
    let success_style = get_success_message_style();
    match fs::File::unlock_file(
        path,
        key,
        &backup_file_name[..],
    ) {
        Ok(()) => println!(
            "{}",
            success_style.paint("The target file was successfully locked")
        ),
        Err(error) => {
            if let Error::WrongPassword = error {
                eprintln!("{}", error_style.paint("An unexpected error has occured"));
            } else {
                handle_error(error, path, &backup_file_name[..],&error_style);
            }
        }
    }
}
