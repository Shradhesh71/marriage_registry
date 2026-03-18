import * as anchor from "@coral-xyz/anchor";
import { Program, web3 } from "@coral-xyz/anchor";
import { MarriageRegistry } from "../target/types/marriage_registry";
import { expect } from "chai";
import { createHash } from "crypto";

describe("Marriage Registry - Security Tests", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const program = anchor.workspace.MarriageRegistry as Program<MarriageRegistry>;

  let issuer: web3.Keypair;
  let unauthorizedUser: web3.Keypair;

  // helper function to generate certificate hash
  const generateCertHash = (data: string): number[] => {
    const hash = createHash("sha256").update(data).digest();
    return Array.from(hash);
  };

  // helper function to get PDA
  const getCertificatePDA = async (certId: string, issuerPubkey: web3.PublicKey) => {
    const [pda] = web3.PublicKey.findProgramAddressSync(
      [Buffer.from("cert"), issuerPubkey.toBuffer(), Buffer.from(certId)],
      program.programId
    );
    return pda;
  };

  // for airdrop SOL
  const airdrop = async (publicKey: web3.PublicKey, amount: number = 2) => {
    const signature = await provider.connection.requestAirdrop(
      publicKey,
      amount * web3.LAMPORTS_PER_SOL
    );
    await provider.connection.confirmTransaction(signature);
  };

  beforeEach(async () => {
    issuer = web3.Keypair.generate();
    unauthorizedUser = web3.Keypair.generate();

    // airdrop
    await airdrop(issuer.publicKey);
    await airdrop(unauthorizedUser.publicKey);
  });

  describe("Valid Certificate Registration", () => {
    it("Should successfully register a valid certificate", async () => {
      const certId = "CERT-2026-001";
      const certHash = generateCertHash("Marriage Certificate Data");
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      const tx = await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      // verify the certificate record
      const record = await program.account.certificateRecord.fetch(recordPDA);
      
      expect(Array.from(record.certHash)).to.deep.equal(certHash);
    });
  });

  describe("Vulnerability Test: Certificate ID Length", () => {
    it("Should reject certificate ID exceeding max length (32 bytes)", async () => {
      const longCertId = "A".repeat(35);
      const certHash = generateCertHash("Test");

      try {
        const recordPDA = await getCertificatePDA(longCertId, issuer.publicKey);
        
        await program.methods
          .registerCertificate(longCertId, certHash)
          .accounts({
            record: recordPDA,
            issuer: issuer.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .signers([issuer])
          .rpc();
        
        expect.fail("Should have thrown error for cert ID too long");
      } catch (error) {
        // will fail either at PDA generation or contract validation
        expect(error).to.exist;
      }
    });

    it("Should accept certificate ID at reasonable length (32 bytes)", async () => {
      const maxLengthCertId = "A".repeat(32); // solana PDA seed max
      const certHash = generateCertHash("Test");
      const recordPDA = await getCertificatePDA(maxLengthCertId, issuer.publicKey);

      await program.methods
        .registerCertificate(maxLengthCertId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      const record = await program.account.certificateRecord.fetch(recordPDA);
      expect(Array.from(record.certHash)).to.deep.equal(certHash);
    });
  });

  describe("Vulnerability Test: Duplicate Registration", () => {
    it("Should prevent registering the same certificate twice", async () => {
      const certId = "CERT-2026-DUP";
      const certHash = generateCertHash("Duplicate Test");
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      // 1st registration
      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      // attempt second registration
      try {
        await program.methods
          .registerCertificate(certId, certHash)
          .accounts({
            record: recordPDA,
            issuer: issuer.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .signers([issuer])
          .rpc();
        
        expect.fail("Should have thrown error for duplicate registration");
      } catch (error) {
        // should fail at account initialization level
        expect(error).to.exist;
      }
    });
  });

  describe("Security Fix: PDA Front-running Prevention", () => {
    it("Should prevent front-running by including issuer in PDA (different issuers have separate namespaces)", async () => {
      const certId = "CERT-FRONTRUN";
      const certHash1 = generateCertHash("Legitimate Certificate");
      const certHash2 = generateCertHash("Malicious Certificate");
      
      // Each issuer gets their own PDA for the same cert_id
      const legitimatePDA = await getCertificatePDA(certId, issuer.publicKey);
      const maliciousPDA = await getCertificatePDA(certId, unauthorizedUser.publicKey);

      // PDAs should be different even with same cert_id
      expect(legitimatePDA.toString()).to.not.equal(maliciousPDA.toString());

      // Malicious user registers their version
      await program.methods
        .registerCertificate(certId, certHash2)
        .accounts({
          record: maliciousPDA,
          issuer: unauthorizedUser.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([unauthorizedUser])
        .rpc();

      // Legitimate issuer can still register - no front-running!
      await program.methods
        .registerCertificate(certId, certHash1)
        .accounts({
          record: legitimatePDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      // Verify both certificates exist with correct hashes
      const legitRecord = await program.account.certificateRecord.fetch(legitimatePDA);
      const maliciousRecord = await program.account.certificateRecord.fetch(maliciousPDA);
      
      expect(Array.from(legitRecord.certHash)).to.deep.equal(certHash1);
      expect(Array.from(maliciousRecord.certHash)).to.deep.equal(certHash2);
    });
  });

  describe("Edge Cases", () => {
    it("Should reject empty string cert_id", async () => {
      const certId = "";
      const certHash = generateCertHash("Empty ID Test");
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      try {
        await program.methods
          .registerCertificate(certId, certHash)
          .accounts({
            record: recordPDA,
            issuer: issuer.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .signers([issuer])
          .rpc();

        expect.fail("Should have thrown InvalidCertId error");
      } catch (error) {
        expect(error.message).to.include("InvalidCertId");
      }
    });

    it("Should handle special characters in cert_id", async () => {
      const certId = "CERT-2024!@#$%";
      const certHash = generateCertHash("Special Chars Test");
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      const record = await program.account.certificateRecord.fetch(recordPDA);
      expect(Array.from(record.certHash)).to.deep.equal(certHash);
    });

    it("Should reject zero hash", async () => {
      const certId = "CERT-ZERO-HASH";
      const certHash = new Array(32).fill(0);
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      try {
        await program.methods
          .registerCertificate(certId, certHash)
          .accounts({
            record: recordPDA,
            issuer: issuer.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .signers([issuer])
          .rpc();

        expect.fail("Should have thrown InvalidHash error");
      } catch (error) {
        expect(error.message).to.include("InvalidHash");
      }
    });
  });

  describe("Certificate Verification Scenarios", () => {
    it("Should maintain certificate integrity after registration", async () => {
      const certId = "CERT-INTEGRITY";
      const certData = "John & Jane - 2024-02-21";
      const certHash = generateCertHash(certData);
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      // verify by re-computing hash
      const record = await program.account.certificateRecord.fetch(recordPDA);
      const recomputedHash = generateCertHash(certData);
      
      expect(Array.from(record.certHash)).to.deep.equal(recomputedHash);
    });

    it("Should detect tampering when hash doesn't match", async () => {
      const certId = "CERT-TAMPER";
      const originalData = "Original Data";
      const tamperedData = "Tampered Data";
      const certHash = generateCertHash(originalData);
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      const record = await program.account.certificateRecord.fetch(recordPDA);
      const tamperedHash = generateCertHash(tamperedData);
      
      // should NOT match
      expect(Array.from(record.certHash)).to.not.deep.equal(tamperedHash);
    });

    it("Should successfully verify a valid certificate on-chain", async () => {
      const certId = "CERT-VERIFY-001";
      const certData = "Valid Certificate Data";
      const certHash = generateCertHash(certData);
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      // verify with correct hash
      const result = await program.methods
        .verifyCertificate(certHash)
        .accounts({
          record: recordPDA,
        })
        .view();

      expect(result).to.be.true;
    });

    it("Should fail verification with incorrect hash", async () => {
      const certId = "CERT-VERIFY-002";
      const certData = "Valid Certificate Data";
      const wrongData = "Wrong Data";
      const certHash = generateCertHash(certData);
      const wrongHash = generateCertHash(wrongData);
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      // verify with wrong hash
      const result = await program.methods
        .verifyCertificate(wrongHash)
        .accounts({
          record: recordPDA,
        })
        .view();

      expect(result).to.be.false;
    });
  });

  describe("Account Closure and Rent Reclamation", () => {
    it("Should allow issuer to close certificate and reclaim rent", async () => {
      const certId = "CERT-CLOSE-001";
      const certHash = generateCertHash("Close Test");
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      // register
      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      const balanceBefore = await provider.connection.getBalance(issuer.publicKey);

      // close and reclaim rent
      await program.methods
        .closeCertificate(certId)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
        })
        .signers([issuer])
        .rpc();

      const balanceAfter = await provider.connection.getBalance(issuer.publicKey);
      
      // balance should increase (rent reclaimed)
      expect(balanceAfter).to.be.greaterThan(balanceBefore);

      // account should no longer exist
      try {
        await program.account.certificateRecord.fetch(recordPDA);
        expect.fail("Account should be closed");
      } catch (error) {
        expect(error.message).to.include("Account does not exist");
      }
    });

    it("Should prevent unauthorized user from closing certificate", async () => {
      const certId = "CERT-CLOSE-UNAUTH";
      const certHash = generateCertHash("Close Test");
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      // unauthorized user tries to close
      try {
        await program.methods
          .closeCertificate(certId)
          .accounts({
            record: recordPDA,
            issuer: unauthorizedUser.publicKey,
          })
          .signers([unauthorizedUser])
          .rpc();
        
        expect.fail("Should have thrown unauthorized error");
      } catch (error) {
        expect(error).to.exist;
      }
    });
  });

  describe("PDA Security Tests", () => {
    it("Should reject transaction with wrong PDA", async () => {
      const certId = "CERT-WRONG-PDA";
      const certHash = generateCertHash("PDA Test");
      // const correctPDA = await getCertificatePDA(certId, issuer.publicKey);
      const wrongPDA = await getCertificatePDA("DIFFERENT-ID", issuer.publicKey);

      try {
        await program.methods
          .registerCertificate(certId, certHash)
          .accounts({
            record: wrongPDA, // using wrong PDA
            issuer: issuer.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .signers([issuer])
          .rpc();
        
        expect.fail("Should have failed with wrong PDA");
      } catch (error) {
        expect(error).to.exist;
      }
    });

    it("Should allow same issuer to register multiple certificates", async () => {
      const certIds = ["CERT-MULTI-001", "CERT-MULTI-002", "CERT-MULTI-003"];
      
      for (const certId of certIds) {
        const certHash = generateCertHash(`Certificate ${certId}`);
        const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

        await program.methods
          .registerCertificate(certId, certHash)
          .accounts({
            record: recordPDA,
            issuer: issuer.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .signers([issuer])
          .rpc();

        const record = await program.account.certificateRecord.fetch(recordPDA);
        expect(Array.from(record.certHash)).to.deep.equal(certHash);
      }
    });
  });

  describe("Boundary and Stress Tests", () => {
    it("Should accept certificate ID with exactly 32 bytes", async () => {
      const certId = "A".repeat(32);
      const certHash = generateCertHash("Boundary Test");
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      await program.methods
        .registerCertificate(certId, certHash)
        .accounts({
          record: recordPDA,
          issuer: issuer.publicKey,
          systemProgram: web3.SystemProgram.programId,
        })
        .signers([issuer])
        .rpc();

      const record = await program.account.certificateRecord.fetch(recordPDA);
      expect(Array.from(record.certHash)).to.deep.equal(certHash);
    });

    it("Should handle maximum hash value", async () => {
      const certId = "CERT-MAX-HASH";
      const certHash = new Array(32).fill(255); // all 0xFF
      const recordPDA = await getCertificatePDA(certId, issuer.publicKey);

      try {
        await program.methods
          .registerCertificate(certId, certHash)
          .accounts({
            record: recordPDA,
            issuer: issuer.publicKey,
            systemProgram: web3.SystemProgram.programId,
          })
          .signers([issuer])
          .rpc();

        expect.fail("Should have thrown InvalidHash error");
      } catch (error) {
        expect(error.message).to.include("InvalidHash");
      }
    });
  });
});

