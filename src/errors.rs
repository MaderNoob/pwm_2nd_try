#[derive(Debug)]
pub enum LockerError{
    OpenFile,
    ReadFile,
    SeekFile,
    WriteFile,
    SetLengthFile,
    FileGetFlags,
    FileSetFlags,
    CreatBackupFile,
    WriteBackupFile,
    ReadBackupFile,
    SeekBackupFile,
    SetLengthBackupFile,
    RemoveBackupFile,
    FileNotLocked,
    WrongPassword,
    InvalidHmac,
}

pub enum PasswordManagerError{
    ReadPasswordsFile,
}