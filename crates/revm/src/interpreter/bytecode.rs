pub use bytes::Bytes;

use super::contract::BytecodeAnalysis;
pub struct Bytecode {
    bytes: Bytes,
    // for analysis some bytecode gets padded in that sense having standalone size field is needed.
    original_size: usize, 
    info: BytecodeInfo,
}

impl Bytecode {

    pub fn len(&self) -> usize {
        self.original_size
    }

    pub fn bytes(&self) -> &Bytes {
        &self.bytes
    }

    pub fn original_bytes(&self) -> &[u8] {
        &self.bytes[..self.original_size]
    }

}



pub enum BytecodeInfo {
    Default,
    AnalysedBig(BytecodeAnalysis),
    // we probably need to have analysis compact that is going be saved inside db
}


