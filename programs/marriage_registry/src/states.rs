use anchor_lang::prelude::*;

#[account]
pub struct CertificateRecord {
    pub cert_hash: [u8; 32], 
}

impl CertificateRecord {
    // PDA seeds have a max of 32 bytes per seed
    pub const MAX_CERT_ID_LEN: usize = 32;
    pub const MAX_SIZE: usize = 32;  // Only cert_hash
}
