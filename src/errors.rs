#[derive(Debug)]
pub enum Error{
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
    WrongPassword
}