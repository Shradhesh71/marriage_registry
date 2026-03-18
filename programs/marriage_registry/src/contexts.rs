use anchor_lang::prelude::*;
use crate::states::CertificateRecord;

/// Account context for registering a new certificate
#[derive(Accounts)]
#[instruction(cert_id: String)]
pub struct RegisterCertificate<'info> {
    #[account(
        init,
        payer = issuer,
        space = 8 + CertificateRecord::MAX_SIZE,
        seeds = [b"cert", issuer.key().as_ref(), cert_id.as_bytes()],
        bump
    )]
    pub record: Account<'info, CertificateRecord>,

    #[account(mut)]
    pub issuer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Account context for verifying a certificate
#[derive(Accounts)]
pub struct VerifyCertificate<'info> {
    // SECURITY: Account<T> wrapper automatically validates:
    // 1. Account is owned by this program
    // 2. Account discriminator matches CertificateRecord
    // 3. Account data can deserialize to CertificateRecord
    // This prevents spoofed accounts from passing verification
    pub record: Account<'info, CertificateRecord>,
}

/// Account context for closing a certificate and reclaiming rent
#[derive(Accounts)]
#[instruction(cert_id: String)]
pub struct CloseCertificate<'info> {
    #[account(
        mut,
        close = issuer,
        seeds = [b"cert", issuer.key().as_ref(), cert_id.as_bytes()],
        bump
    )]
    pub record: Account<'info, CertificateRecord>,

    #[account(mut)] 
    pub issuer: Signer<'info>,
}
