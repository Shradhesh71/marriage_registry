use anchor_lang::error_code;

#[error_code]
pub enum RegistryError {
    #[msg("Unauthorized: Account not owned by this program or wrong issuer")]
    Unauthorized,

    #[msg("Certificate ID exceeds maximum length of 32 bytes")]
    CertIdTooLong,

    #[msg("Certificate is already revoked")]
    AlreadyRevoked,

    #[msg("Certificate ID cannot be empty or contains invalid characters")]
    InvalidCertId,

    #[msg("Certificate hash cannot be zero or invalid value")]
    InvalidHash,

    #[msg("Certificate must be revoked before closing")]
    NotRevoked,
}