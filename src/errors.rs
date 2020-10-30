#[derive(Debug)]
pub enum Error{
    OpenFile,
    ReadFile,
    SeekFile,
    WriteFile,
    FileGetMetadata,
    FileSetPermissions,
    FileGetFlags,
    FileSetFlags,
}