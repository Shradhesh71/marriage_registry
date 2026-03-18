use anchor_lang::prelude::*;
use crate::states::CertificateRecord;
use crate::error::RegistryError;
use crate::contexts::RegisterCertificate;

pub fn register_certificate(
    ctx: Context<RegisterCertificate>,
    cert_id: String,
    cert_hash: [u8; 32],
) -> Result<()> {
    // SECURITY: Validate cert_id is valid UTF-8 and not empty
    require!(
        !cert_id.is_empty(),
        RegistryError::InvalidCertId
    );

    // SECURITY: Prevent excessively long cert_ids (PDA seed limit)
    require!(
        cert_id.len() <= CertificateRecord::MAX_CERT_ID_LEN,
        RegistryError::CertIdTooLong
    );
    
    // SECURITY: Validate UTF-8 encoding
    require!(
        cert_id.is_ascii() || std::str::from_utf8(cert_id.as_bytes()).is_ok(),
        RegistryError::InvalidCertId
    );

    // SECURITY: Prevent zero hash (likely error or attack)
    require!(
        cert_hash != [0u8; 32],
        RegistryError::InvalidHash
    );
    
    // SECURITY: Prevent all 0xFF hash (another common invalid value)
    require!(
        cert_hash != [0xFF; 32],
        RegistryError::InvalidHash
    );

    let record = &mut ctx.accounts.record;
    record.cert_hash = cert_hash;

    Ok(())
}