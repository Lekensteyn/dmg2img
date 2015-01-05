#ifndef _FVDECRYPT_H

#define _FVDECRYPT_H		1

/* length of message digest output in bytes (160 bits) */
#define MD_LENGTH		20
/* length of cipher key in bytes (128 bits) */
#define CIPHER_KEY_LENGTH	16
/* block size of cipher in bytes (128 bits) */
#define CIPHER_BLOCKSIZE	16
/* chunk size (FileVault specific) */
#define CHUNK_SIZE		4096
/* number of iterations for PBKDF2 key derivation */
#define PBKDF2_ITERATION_COUNT	1000

typedef struct {
  /* 0x000: */ uint8_t  filler1[48];
  /* 0x034: */ uint32_t kdf_iteration_count;
  /* 0x034: */ uint32_t kdf_salt_len;
  /* 0x038: */ uint8_t  kdf_salt[48]; /* salt value for key derivation */
  /* 0x068: */ uint8_t  unwrap_iv[32]; /* IV for encryption-key unwrapping */
  /* 0x088: */ uint32_t len_wrapped_aes_key;
  /* 0x08c: */ uint8_t  wrapped_aes_key[296];
  /* 0x1b4: */ uint32_t len_hmac_sha1_key;
  /* 0x1b8: */ uint8_t  wrapped_hmac_sha1_key[300];
  /* 0x1b4: */ uint32_t len_integrity_key;
  /* 0x2e8: */ uint8_t  wrapped_integrity_key[48];
  /* 0x318: */ uint8_t  filler6[484];
} cencrypted_v1_header;

/* this structure is valid only if there's a recovery key defined */
typedef struct {
  unsigned char sig[8];
  uint32_t version;
  uint32_t enc_iv_size;
  uint32_t unk1;
  uint32_t unk2;
  uint32_t unk3;
  uint32_t unk4;
  uint32_t unk5;
  unsigned char uuid[16];
  uint32_t blocksize;
  uint64_t datasize;
  uint64_t dataoffset;
  uint8_t filler1[0x260];
  uint32_t kdf_algorithm;
  uint32_t kdf_prng_algorithm;
  uint32_t kdf_iteration_count;
  uint32_t kdf_salt_len; /* in bytes */
  uint8_t  kdf_salt[32];
  uint32_t blob_enc_iv_size;
  uint8_t  blob_enc_iv[32];
  uint32_t blob_enc_key_bits;
  uint32_t blob_enc_algorithm;
  uint32_t blob_enc_padding;
  uint32_t blob_enc_mode;
  uint32_t encrypted_keyblob_size;
  uint8_t  encrypted_keyblob[0x30];
} cencrypted_v2_pwheader;

/* PasswordHeader:
0x2a8:
   aHeader.keyDerivationAlgorithm      %ld
   aHeader.keyDerivationPRNGAlgorithm  %ld
0x70:
   aHeader.keyDerivationIterationCount %ld
0x74:
   aHeader.keyDerivationSaltSize       %ld
0x78:
   aHeader.keyDerivationSalt

   aHeader.blobEncryptionIVSize        %ld
   aHeader.blobEncryptionIV            %ld
   aHeader.blobEncryptionKeySizeInBits %ld
   aHeader.blobEncryptionAlgorithm     %ld
   aHeader.blobEncryptionPadding       %ld
   aHeader.blobEncryptionMode          %ld
   aHeader.encryptedBlobSize           %ld
   aHeader.encryptedBlob
*/


/*
aHeader.uuid
aHeader.dataBlockSize               %u
aHeader.keyWrappingAlgorithm        %ld
aHeader.keyWrappingPadding    
aHeader.keyWrappingMode             %ld
aHeader.keyWrappingKeySizeInBits    %ld
aHeader.keyWrappingIVSize           %ld
aHeader.keyDerivationAlgorithm      %ld
aHeader.keyDerivationPRNGAlgorithm  %ld
aHeader.keyDerivationIterationCount %ld
aHeader.keyDerivationSaltSize       %ld
aHeader.keyDerivationSalt
aHeader.encryptionIVSize            %ld
aHeader.encryptionMode              %ld
aHeader.encryptionAlgorithm         %ld
aHeader.encryptionKeySizeInBits     %ld
aHeader.encryptionKeyWrappingIV
aHeader.wrappedEncryptionKeySize    %ld
aHeader.wrappedEncryptionKey
aHeader.prngAlgorithm               %ld
aHeader.prngKeySizeInBits           %ld
aHeader.prngKeyWrappingIV
aHeader.wrappedPrngKeySize          %ld
aHeader.wrappedPrngKey
aHeader.signingAlgorithm            %ld
aHeader.signingKeySizeInBits        %ld
aHeader.signingKeyWrappingIV
aHeader.wrappedSigningKeySize       %ld
aHeader.wrappedSigningKey
aHeader.signatureSize               %ld
aHeader.signature
aHeader.dataForkSize                %qd
aHeader.version                     %ld
aHeader.signature2                  %4.4s
aHeader.signature1                  %4.4s
aHeader.version                     %u
aHeader.dataForkStartOffset
    %qd
aHeader.blobEncryptionIVSize        %ld
aHeader.blobEncryptionIV
aHeader.blobEncryptionKeySizeInBits %ld
aHeader.blobEncryptionAlgorithm     %ld
aHeader.blobEncryptionPadding       %ld
aHeader.blobEncryptionMode          %ld
aHeader.encryptedBlobSize           %ld
aHeader.encryptedBlob
aHeader.publicKeyHashSize           %ld
aHeader.publicKeyHash
*/
#endif
