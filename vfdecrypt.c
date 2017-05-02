/*
 ** Copyright (c) 2006 
 ** Ralf-Philipp Weinmann <ralf@coderpunks.org>
 ** Jacob Appelbaum <jacob@appelbaum.net>
 ** Christian Fromme <kaner@strace.org>
 **
 ** Decrypt a AES-128 encrypted disk image given the encryption key
 ** and the hmacsha1key of the image. These two keys can be found
 ** out by running hdiutil attach with -debug on the disk image.
 **
 ** Permission is hereby granted, free of charge, to any person
 ** obtaining a copy of this software and associated documentation
 ** files (the "Software"), to deal in the Software without
 ** restriction, including without limitation the rights to use,
 ** copy, modify, merge, publish, distribute, sublicense, and/or sell
 ** copies of the Software, and to permit persons to whom the
 ** Software is furnished to do so, subject to the following
 ** conditions:
 **
 ** The above copyright notice and this permission notice shall be
 ** included in all copies or substantial portions of the Software.
 ** 
 ** THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 ** EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 ** OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 ** NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 ** HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 ** WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 ** FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 ** OTHER DEALINGS IN THE SOFTWARE.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

#define OSSwapHostToBigInt32(x) ntohl(x)

/* length of message digest output in bytes (160 bits) */
#define MD_LENGTH		20
/* length of cipher key in bytes (128 bits) */
#define CIPHER_KEY_LENGTH	16
/* block size of cipher in bytes (128 bits) */
#define CIPHER_BLOCKSIZE	16
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

void print_hex(uint8_t * /* data */, uint32_t /* len */);
void convert_hex(char * /* str */, uint8_t * /* bytes */,
		 int /* maxlen */);
void dump_v2_header(void * /* hdr */);
void adjust_v1_header_byteorder(cencrypted_v1_header * /* hdr */);
void adjust_v2_header_byteorder(cencrypted_v2_pwheader * /* pwhdr */);

void print_hex(uint8_t *data, uint32_t len) {
  uint32_t ctr;
  char *sep;

  if (len > 64) len = 64;

  for(ctr = 0; ctr < len; ctr++) {
    sep = (((ctr&7)==0)&&ctr) ? "\n" : "";
    fprintf(stderr, "%s%02x ", sep, data[ctr]);
  }
  fprintf(stderr, "\n\n");
}

void convert_hex(char *str, uint8_t *bytes, int maxlen) {
  int bytelen = maxlen;
  int rpos, wpos = 0;

  for(rpos = 0; rpos < bytelen; rpos++) {
    sscanf(&str[rpos*2], "%02hhx", &bytes[wpos++]);
  }
}

void dump_v2_header(void *hdr) {
  cencrypted_v2_pwheader *pwhdr = (cencrypted_v2_pwheader *) hdr;

  fprintf(stderr, "sig\t%8s\n", pwhdr->sig);
  fprintf(stderr, "blocksize\t%"PRIX32"\n", pwhdr->blocksize);
  fprintf(stderr, "datasize\t%"PRIu64"\n", pwhdr->datasize);
  fprintf(stderr, "dataoffset\t%"PRIu64"\n", pwhdr->dataoffset);

  /* 103: CSSM_ALGID_PKCS5_PBKDF2 */
  fprintf(stderr, "keyDerivationAlgorithm      %lu\n", (unsigned long) pwhdr->kdf_algorithm);
  fprintf(stderr, "keyDerivationPRNGAlgorithm  %lu\n", (unsigned long) pwhdr->kdf_prng_algorithm);
  /* by default the iteration count should be 1000 iterations */
  fprintf(stderr, "keyDerivationIterationCount %lu\n", (unsigned long) pwhdr->kdf_iteration_count);
  fprintf(stderr, "keyDerivationSaltSize       %lu\n", (unsigned long) pwhdr->kdf_salt_len);
  fprintf(stderr, "keyDerivationSalt           \n");
  print_hex(pwhdr->kdf_salt, pwhdr->kdf_salt_len);
  fprintf(stderr, "blobEncryptionIVSize        %lu\n", (unsigned long) pwhdr->blob_enc_iv_size);
  fprintf(stderr, "blobEncryptionIV            \n");
  print_hex(pwhdr->blob_enc_iv, pwhdr->blob_enc_iv_size);
  fprintf(stderr, "blobEncryptionKeySizeInBits %lu\n",  (unsigned long) pwhdr->blob_enc_key_bits);
  /*  17: CSSM_ALGID_3DES_3KEY_EDE */
  fprintf(stderr, "blobEncryptionAlgorithm     %lu\n",  (unsigned long) pwhdr->blob_enc_algorithm);
  /*   7: CSSM_PADDING_PKCS7 */
  fprintf(stderr, "blobEncryptionPadding       %lu\n",  (unsigned long) pwhdr->blob_enc_padding);
  /*   6: CSSM_ALGMODE_CBCPadIV8 */
  fprintf(stderr, "blobEncryptionMode          %lu\n",  (unsigned long)  pwhdr->blob_enc_mode);
  fprintf(stderr, "encryptedBlobSize           %lu\n",  (unsigned long)  pwhdr->encrypted_keyblob_size);
  fprintf(stderr, "encryptedBlob               \n");
  print_hex(pwhdr->encrypted_keyblob, pwhdr->encrypted_keyblob_size);
}

void adjust_v1_header_byteorder(cencrypted_v1_header *hdr) {
  hdr->kdf_iteration_count = htonl(hdr->kdf_iteration_count);
  hdr->kdf_salt_len = htonl(hdr->kdf_salt_len);
  hdr->len_wrapped_aes_key = htonl(hdr->len_wrapped_aes_key);
  hdr->len_hmac_sha1_key = htonl(hdr->len_hmac_sha1_key);
  hdr->len_integrity_key = htonl(hdr->len_integrity_key);
}

#define swap32(x) x = OSSwapHostToBigInt32(x)
#define swap64(x) x = ((uint64_t) ntohl(x >> 32)) | (((uint64_t) ntohl((uint32_t) (x & 0xFFFFFFFF))) << 32)

void adjust_v2_header_byteorder(cencrypted_v2_pwheader *pwhdr) {
  swap32(pwhdr->blocksize);
  swap64(pwhdr->datasize);
  swap64(pwhdr->dataoffset);
  pwhdr->kdf_algorithm = htonl(pwhdr->kdf_algorithm);
  pwhdr->kdf_prng_algorithm = htonl(pwhdr->kdf_prng_algorithm);
  pwhdr->kdf_iteration_count = htonl(pwhdr->kdf_iteration_count);
  pwhdr->kdf_salt_len = htonl(pwhdr->kdf_salt_len);
  pwhdr->blob_enc_iv_size = htonl(pwhdr->blob_enc_iv_size);
  pwhdr->blob_enc_key_bits = htonl(pwhdr->blob_enc_key_bits);
  pwhdr->blob_enc_algorithm = htonl(pwhdr->blob_enc_algorithm);
  pwhdr->blob_enc_padding = htonl(pwhdr->blob_enc_padding);
  pwhdr->blob_enc_mode = htonl(pwhdr->blob_enc_mode);
  pwhdr->encrypted_keyblob_size = htonl(pwhdr->encrypted_keyblob_size);
}

HMAC_CTX *hmacsha1_ctx;
AES_KEY aes_decrypt_key;
int CHUNK_SIZE=4096;  // default

/**
 *  * Compute IV of current block as
 *   * truncate128(HMAC-SHA1(hmacsha1key||blockno))
 *    */
void compute_iv(uint32_t chunk_no, uint8_t *iv) {
  unsigned char mdResult[MD_LENGTH];
  unsigned int mdLen;
  
  chunk_no = OSSwapHostToBigInt32(chunk_no);
  HMAC_Init_ex(hmacsha1_ctx, NULL, 0, NULL, NULL);
  HMAC_Update(hmacsha1_ctx, (void *) &chunk_no, sizeof(uint32_t));
  HMAC_Final(hmacsha1_ctx, mdResult, &mdLen);
  memcpy(iv, mdResult, CIPHER_BLOCKSIZE);
}

void decrypt_chunk(uint8_t *ctext, uint8_t *ptext, uint32_t chunk_no) {
  uint8_t iv[CIPHER_BLOCKSIZE];

  compute_iv(chunk_no, iv);
  AES_cbc_encrypt(ctext, ptext, CHUNK_SIZE, &aes_decrypt_key, iv, AES_DECRYPT);
}

/* DES3-EDE unwrap operation loosely based on to RFC 2630, section 12.6 
 *    wrapped_key has to be 40 bytes in length.  */
int apple_des3_ede_unwrap_key(uint8_t *wrapped_key, int wrapped_key_len, uint8_t *decryptKey, uint8_t *unwrapped_key) {
  EVP_CIPHER_CTX *ctx;
  uint8_t *TEMP1, *TEMP2, *CEKICV;
  uint8_t IV[8] = { 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05 };
  int outlen, tmplen, i;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = EVP_CIPHER_CTX_new();
#else
  ctx = malloc(sizeof(*ctx));
#endif
  if (!ctx) {
    fprintf(stderr, "Out of memory: EVP_CIPHER_CTX!\n");
    return(-1);
  }

  EVP_CIPHER_CTX_init(ctx);
  /* result of the decryption operation shouldn't be bigger than ciphertext */
  TEMP1 = malloc(wrapped_key_len);
  TEMP2 = malloc(wrapped_key_len);
  CEKICV = malloc(wrapped_key_len);
  /* uses PKCS#7 padding for symmetric key operations by default */
  EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, decryptKey, IV);

  if(!EVP_DecryptUpdate(ctx, TEMP1, &outlen, wrapped_key, wrapped_key_len)) {
    fprintf(stderr, "internal error (1) during key unwrap operation!\n");
    return(-1);
  }
  if(!EVP_DecryptFinal_ex(ctx, TEMP1 + outlen, &tmplen)) {
    fprintf(stderr, "internal error (2) during key unwrap operation!\n");
    return(-1);
  }
  outlen += tmplen;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX_reset(ctx);
#else
  EVP_CIPHER_CTX_cleanup(ctx);
#endif

  /* reverse order of TEMP3 */
  for(i = 0; i < outlen; i++) TEMP2[i] = TEMP1[outlen - i - 1];

  EVP_CIPHER_CTX_init(ctx);
  /* uses PKCS#7 padding for symmetric key operations by default */
  EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, decryptKey, TEMP2);
  if(!EVP_DecryptUpdate(ctx, CEKICV, &outlen, TEMP2+8, outlen-8)) {
    fprintf(stderr, "internal error (3) during key unwrap operation!\n");
    return(-1);
  }
  if(!EVP_DecryptFinal_ex(ctx, CEKICV + outlen, &tmplen)) {
    fprintf(stderr, "internal error (4) during key unwrap operation!\n");
    return(-1);
  }

  outlen += tmplen;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX_reset(ctx);
#else
  EVP_CIPHER_CTX_cleanup(ctx);
#endif

  memcpy(unwrapped_key, CEKICV+4, outlen-4);
  free(TEMP1);
  free(TEMP2);
  free(CEKICV);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX_free(ctx);
#else
  free(ctx);
#endif
  return(0);
}

int unwrap_v1_header(char *passphrase, cencrypted_v1_header *header, uint8_t *aes_key, uint8_t *hmacsha1_key) {
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];

  PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), (unsigned char*)header->kdf_salt, 20, 
			 PBKDF2_ITERATION_COUNT, sizeof(derived_key), derived_key);

  if (apple_des3_ede_unwrap_key(header->wrapped_aes_key, 40, derived_key, aes_key) != 0)
    return(-1);
  if (apple_des3_ede_unwrap_key(header->wrapped_hmac_sha1_key, 48, derived_key, hmacsha1_key) != 0)
    return(-1);

  return(0);
}

int unwrap_v2_header(char *passphrase, cencrypted_v2_pwheader *header, uint8_t *aes_key, uint8_t *hmacsha1_key) {
  /* derived key is a 3DES-EDE key */
  uint8_t derived_key[192/8];
  EVP_CIPHER_CTX *ctx;
  uint8_t *TEMP1;
  int outlen, tmplen;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  ctx = EVP_CIPHER_CTX_new();
#else
  ctx = malloc(sizeof(*ctx));
#endif
  if (!ctx) {
    fprintf(stderr, "Out of memory: EVP_CIPHER_CTX!\n");
    return(-1);
  }

  PKCS5_PBKDF2_HMAC_SHA1(passphrase, strlen(passphrase), (unsigned char*)header->kdf_salt, 20,
			 PBKDF2_ITERATION_COUNT, sizeof(derived_key), derived_key);

  print_hex(derived_key, 192/8);

  EVP_CIPHER_CTX_init(ctx);
  /* result of the decryption operation shouldn't be bigger than ciphertext */
  TEMP1 = malloc(header->encrypted_keyblob_size);
  /* uses PKCS#7 padding for symmetric key operations by default */
  EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, derived_key, header->blob_enc_iv);

  if(!EVP_DecryptUpdate(ctx, TEMP1, &outlen, header->encrypted_keyblob, header->encrypted_keyblob_size)) {
    fprintf(stderr, "internal error (1) during key unwrap operation!\n");
    return(-1);
  }
  if(!EVP_DecryptFinal_ex(ctx, TEMP1 + outlen, &tmplen)) {
    fprintf(stderr, "internal error (2) during key unwrap operation!\n");
    return(-1);
  }
  outlen += tmplen;
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  EVP_CIPHER_CTX_free(ctx);
#else
  EVP_CIPHER_CTX_cleanup(ctx);
  free(ctx);
#endif
  memcpy(aes_key, TEMP1, 16);
  memcpy(hmacsha1_key, TEMP1, 20);

  return(0);
}

int determine_header_version(FILE *dmg) {
  return(2);
}

int usage(char *message) {
  fprintf(stderr, "%s\n", message);
  fprintf(stderr, "Usage: vfdecrypt [-e] [-p password] [-k key] -i in-file -o out-file\n");
  fprintf(stderr, "Option -e attempts to extract key from <in-file>\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  FILE *in, *out;
  cencrypted_v1_header v1header;
  cencrypted_v2_pwheader v2header;
  
  uint8_t hmacsha1_key[20], aes_key[16], inbuf[CHUNK_SIZE], outbuf[CHUNK_SIZE];
  uint32_t chunk_no;
  int hdr_version, c, optError = 0;
  char inFile[512], outFile[512], passphrase[512], cmd[640];
  int iflag = 0, oflag = 0, pflag = 0, kflag = 0, verbose = 0;
  extern char *optarg;
  extern int optind, optopt;
  
  memset(inFile, 0, 512);
  memset(outFile, 0, 512);
  memset(passphrase, 0, 512);
  memset(cmd, 0, 640);

  /* This was the key used in iPhone1,1_1.0_1A543a_Restore.ipsw ... */
  /*
  convert_hex("28c909fc6d322fa18940f03279d70880", aes_key, 16);
  convert_hex("e59a4507998347c70d5b8ca7ef090ecccc15e82d", hmacsha1_key, 20);
  kflag = 1;
  */

  while((c = getopt(argc, argv, "hvei:o:p:k:")) != -1) {
    switch(c) {
    case 'h':
      usage("Help is on the way. Stay calm.");
      break;
    case 'v':
      verbose++;
      break;
    case 'e':
      *cmd = 1;
      break;
    case 'i':
      if(optarg) strncpy(inFile, optarg, sizeof(inFile)-1);
      iflag = 1;
      break;
    case 'o':
      if (optarg) strncpy(outFile, optarg, sizeof(outFile)-1);
      oflag = 1;
      break;
    case 'p':
      if (optarg) strncpy(passphrase, optarg, sizeof(passphrase)-1);
      pflag = 1;
      break;
    case 'k':
      convert_hex(optarg, aes_key, 16);
      convert_hex(optarg+32, hmacsha1_key, 20);
      kflag=1;
      break;
    case '?':
      fprintf(stderr, "Unknown option: -%c\n", optopt);
      optError++;
      break;
    }
  }

  /* check to see if our user gave incorrect options */
  if (optError) usage("Incorrect arguments.");

  if (strlen(inFile) == 0) {
    in = stdin;
  } else {
    if ((in = fopen(inFile, "rb")) == NULL) {
      fprintf(stderr, "Error: unable to open %s\n", inFile);
      exit(1);
    }
  }

  if (*cmd && *inFile) {
      sprintf(cmd, 
"strings %s | grep '^[0-9a-fA-F]*$' | awk '{ if (length($1) == 72) print; }'",
              inFile);
      system(cmd);
      exit(0);
  }

  if (strlen(outFile) == 0) {
    out = stdout;
  } else {
    if ((out = fopen(outFile, "wb")) == NULL) {
      fprintf(stderr, "Error: unable to open %s\n", outFile);
      exit(1);
    }
  }

  if (!pflag && !kflag) {
    usage("No Passphrase given.");
    exit(1);
  }

  hdr_version = determine_header_version(in);
  
  if (verbose >= 1) {
    if (hdr_version > 0) {
      fprintf(stderr, "v%d header detected.\n", hdr_version);
    } else {
      fprintf(stderr, "unknown format.\n");
      exit(1);
    }
  }
  
  if (hdr_version == 1) {
    fseek(in, (long) -sizeof(cencrypted_v1_header), SEEK_END);
    if (fread(&v1header, sizeof(cencrypted_v1_header), 1, in) < 1) {
      fprintf(stderr, "header corrupted?\n"), exit(1);
    }
    adjust_v1_header_byteorder(&v1header);
    if(!kflag) unwrap_v1_header(passphrase, &v1header, aes_key, hmacsha1_key);
  }
  
  if (hdr_version == 2) {
    fseek(in, 0L, SEEK_SET);
    if (fread(&v2header, sizeof(cencrypted_v2_pwheader), 1, in) < 1) {
      fprintf(stderr, "header corrupted?\n"), exit(1);
    }
    adjust_v2_header_byteorder(&v2header);
    dump_v2_header(&v2header);
    if(!kflag) unwrap_v2_header(passphrase, &v2header, aes_key, hmacsha1_key);
    CHUNK_SIZE = v2header.blocksize;
  }
  
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  hmacsha1_ctx = HMAC_CTX_new();
#else
  hmacsha1_ctx = malloc(sizeof(*hmacsha1_ctx));
#endif
  if (!hmacsha1_ctx) {
    fprintf(stderr, "Out of memory: HMAC CTX!\n");
    exit(1);
  }
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX_reset(hmacsha1_ctx);
#else
  HMAC_CTX_init(hmacsha1_ctx);
#endif
  HMAC_Init_ex(hmacsha1_ctx, hmacsha1_key, sizeof(hmacsha1_key), EVP_sha1(), NULL);
  AES_set_decrypt_key(aes_key, CIPHER_KEY_LENGTH * 8, &aes_decrypt_key);
  
  if (verbose >= 1) {
    printf("AES Key: \n");
    print_hex(aes_key, 16);
    printf("SHA1 seed: \n");
    print_hex(hmacsha1_key, 20);
  }
  
  if (hdr_version == 2) fseek(in, v2header.dataoffset, SEEK_SET);
  else fseek(in, 0L, SEEK_SET);
  
  chunk_no = 0;
  while(fread(inbuf, CHUNK_SIZE, 1, in) > 0) {
    decrypt_chunk(inbuf, outbuf, chunk_no);
    chunk_no++;
    if(hdr_version == 2 && (v2header.datasize-ftell(out)) < CHUNK_SIZE) {
      fwrite(outbuf, v2header.datasize - ftell(out), 1, out);
      break;
    }
    fwrite(outbuf, CHUNK_SIZE, 1, out);
  }
  
  if (verbose)  fprintf(stderr, "%"PRIX32" chunks written\n", chunk_no);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  HMAC_CTX_free(hmacsha1_ctx);
#else
  HMAC_CTX_cleanup(hmacsha1_ctx);
  free(hmacsha1_ctx);
#endif
  return(0);
}
