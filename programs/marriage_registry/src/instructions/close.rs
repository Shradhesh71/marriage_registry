use anchor_lang::prelude::*;
use crate::contexts::CloseCertificate;
use crate::error::RegistryError;

// Close certificate and reclaim rent
pub fn close_certificate(ctx: Context<CloseCertificate>) -> Result<()> {
    // SECURITY: Only the original issuer can close their certificate
    // This is enforced by the PDA seeds constraint in CloseCertificate context:
    // seeds = [b"cert", issuer.key().as_ref(), cert_id.as_bytes()]
    // 
    // The issuer MUST be the signer AND match the issuer used in PDA derivation
    // Otherwise, the PDA derivation will fail and the account won't be found
    
    // Additional runtime verification
    require!(
        ctx.accounts.record.to_account_info().owner == &crate::ID,
        RegistryError::Unauthorized
    );

    Ok(())
}