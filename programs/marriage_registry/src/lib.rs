use anchor_lang::prelude::*;

declare_id!("CmkicBWwA7dVBKPXbZ5AGHXQGGqNhyS7rY8skEv6NxMy");

mod error;
mod states;
mod contexts;
mod instructions;

pub use error::*;
pub use states::*;
pub use contexts::*;

#[program]
pub mod marriage_registry {
    use super::*;

    pub fn register_certificate(
        ctx: Context<RegisterCertificate>,
        cert_id: String,
        cert_hash: [u8; 32],
    ) -> Result<()> {
        instructions::register::register_certificate(ctx, cert_id, cert_hash)
    }

    pub fn verify_certificate(
        ctx: Context<VerifyCertificate>,
        expected_hash: [u8; 32],
    ) -> Result<bool> {
        instructions::verify::verify_certificate(ctx, expected_hash)
    }

    pub fn close_certificate(ctx: Context<CloseCertificate>, _cert_id: String) -> Result<()> {
       instructions::close::close_certificate(ctx)
    }
}

