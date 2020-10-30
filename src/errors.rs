#[derive(Debug)]
pub enum Error{
    OpenFile,
    ReadFile,
    SeekFile,
    WriteFile,
}