use anchor_lang::prelude::*;
use crate::contexts::VerifyCertificate;

pub fn verify_certificate(
    ctx: Context<VerifyCertificate>,
    expected_hash: [u8; 32],
) -> Result<bool> {
    let record = &ctx.accounts.record;
    
    // SECURITY: Account<T> wrapper has already validated:
    // - Account is owned by this program
    // - Account discriminator is correct
    // - Account deserializes to CertificateRecord
    // No spoofed accounts can pass this check
    
    // Compare hashes
    let is_valid = record.cert_hash == expected_hash;

    Ok(is_valid)
}
