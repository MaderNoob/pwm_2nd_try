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
impl Into<GlobalError> for LockerError{
    fn into(self) -> GlobalError {
        GlobalError::Locker(self)
    }
}
pub enum PasswordManagerError{
    ReadPasswordsFile,
    EncodingError,
}
impl Into<GlobalError> for PasswordManagerError{
    fn into(self) -> GlobalError {
        GlobalError::PasswordManager(self)
    }
}
pub trait ToGlobalError<T>{
    fn to_global_error(self)->Result<T,GlobalError>;
}
impl<T> ToGlobalError<T> for Result<T,LockerError>{
    fn to_global_error(self) ->Result<T,GlobalError> {
        match self{
            Ok(t)=>Ok(t),
            Err(e)=>Err(e.into())
        }
    }
}
impl<T> ToGlobalError<T> for Result<T,PasswordManagerError>{
    fn to_global_error(self) ->Result<T,GlobalError> {
        match self{
            Ok(t)=>Ok(t),
            Err(e)=>Err(e.into())
        }
    }
}
pub enum GlobalError{
    Locker(LockerError),
    PasswordManager(PasswordManagerError),
}