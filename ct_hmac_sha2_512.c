/*
    Chris M. Thomasson 6/4/2018
    Experimental HMAC Cipher
    C version with hardcoded secret key

    FIXED VERSION: Now uses proper TRNG (/dev/urandom on Unix, CryptGenRandom on Windows)

    Using the following HMAC lib:
    https://github.com/ogay/hmac

    Here is some info on my cipher:
    http://funwithfractals.atspace.cc/ct_cipher
________________________________________________________*/


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

#include "hmac_sha2.h"


#define CT_HMAC_SZ 64

// Uncomment PYTHON_TEST_VECTOR to sync with the Python 3 test vector
// Python code: https://pastebin.com/raw/NAnsBJAZ
// plaintext 9 bytes at: "Plaintext"
// ciphertext bytes:
// 9a419a03ac79bfa74edbbdda778316f6840b1aac07910de758e03e35a0d8ff1d407d
// 757ed6b734de9f9ed339bedf73786c5130d2f1891813c179ca20b82e81375e7a64e2
// dddead403b8284b9b76d1e83eddb


//#define PYTHON_TEST_VECTOR


struct ct_secret_key
{
    unsigned char* hmac_key;
    size_t hmac_key_sz;
    char* hmac_algo;
    size_t rand_n;
};

struct ct_buf
{
    unsigned char* p;
    size_t sz;
};


/*
    CRITICAL: Cryptographically Secure Random Number Generation

    This function uses:
    - /dev/urandom on Unix/Linux/macOS (non-blocking, cryptographically secure)
    - CryptGenRandom on Windows (CSPRNG)

    NEVER use rand() for cryptographic purposes!
*/
int ct_get_random_bytes(
    unsigned char* buf,
    size_t buf_sz
) {
    if (!buf || buf_sz == 0) {
        fprintf(stderr, "ERROR: Invalid buffer for random bytes\n");
        return 0;
    }

#ifdef _WIN32
    // Windows: Use CryptGenRandom
    HCRYPTPROV hCryptProv;

    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        fprintf(stderr, "ERROR: CryptAcquireContext failed\n");
        return 0;
    }

    if (!CryptGenRandom(hCryptProv, (DWORD)buf_sz, buf)) {
        fprintf(stderr, "ERROR: CryptGenRandom failed\n");
        CryptReleaseContext(hCryptProv, 0);
        return 0;
    }

    CryptReleaseContext(hCryptProv, 0);
    return 1;

#else
    // Unix/Linux/macOS: Use /dev/urandom
    int fd = open("/dev/urandom", O_RDONLY);

    if (fd < 0) {
        fprintf(stderr, "ERROR: Cannot open /dev/urandom\n");
        perror("open");
        return 0;
    }

    size_t bytes_read = 0;
    while (bytes_read < buf_sz) {
        ssize_t result = read(fd, buf + bytes_read, buf_sz - bytes_read);

        if (result < 0) {
            fprintf(stderr, "ERROR: Failed to read from /dev/urandom\n");
            perror("read");
            close(fd);
            return 0;
        }

        bytes_read += result;
    }

    close(fd);
    return 1;
#endif
}


void ct_hex_printf(
    FILE* fout,
    unsigned char* buf,
    size_t buf_sz
) {
    for (size_t i = 0; i < buf_sz; i++)
    {
        fprintf(fout, "%02x", buf[i]);
    }
}


unsigned char*
ct_reverse(
    unsigned char* P,
    size_t P_sz
) {
    for (size_t i = 0; i < P_sz / 2; ++i)
    {
        size_t r = P_sz - i - 1;
        unsigned char t = P[i];
        P[i] = P[r];
        P[r] = t;
    }

    return P;
}


size_t
ct_file_get_size(
    FILE* file
) {
    size_t file_sz = 0;
    for (file_sz = 0; fgetc(file) != EOF; ++file_sz);
    rewind(file);
    return file_sz;
}



// return value ct_buf.p needs to be freed!
struct ct_buf
ct_file_copy(
    FILE* file
) {
    size_t file_sz = ct_file_get_size(file);
    struct ct_buf buf = { calloc(1, file_sz), file_sz };
    assert(buf.p);

    if (buf.p)
    {
        for (size_t i = 0; i < file_sz; ++i)
        {
            int byte = fgetc(file);
            assert(byte != EOF);
            buf.p[i] = byte;
        }
    }

    return buf;
}



// return value ct_buf.p needs to be freed!
struct ct_buf
ct_prepend_from_file(
    struct ct_secret_key const* const SK,
    const char* fname
) {
    FILE* file = fopen(fname, "rb");
    assert(file);

    size_t file_sz = ct_file_get_size(file) + SK->rand_n;

    struct ct_buf buf = { calloc(1, file_sz), file_sz };

    if (buf.p)
    {
        // Prepend the random bytes.
        // CRITICAL: These are drawn from a TRNG (cryptographically secure)

#if defined (PYTHON_TEST_VECTOR)
    // Test vector mode: deterministic for testing only
        printf("WARNING: Using test vector mode - NOT SECURE!\n");
        for (size_t i = 0; i < SK->rand_n; ++i)
        {
            buf.p[i] = (unsigned char)i;
        }
#else
    // Production mode: Use proper TRNG
        printf("Generating %zu bytes of cryptographically secure random data...\n", SK->rand_n);

        if (!ct_get_random_bytes(buf.p, SK->rand_n)) {
            fprintf(stderr, "FATAL: Failed to generate secure random bytes!\n");
            free(buf.p);
            fclose(file);
            exit(EXIT_FAILURE);
        }

        printf("Random prefix generated successfully\n");
#endif

        // Append the original plaintext
        for (size_t i = SK->rand_n; i < file_sz; ++i)
        {
            int byte = fgetc(file);
            assert(byte != EOF);
            buf.p[i] = byte;
        }
    }

    fclose(file);

    return buf;
}


struct ct_buf
ct_load_from_file(
    const char* fname
) {
    FILE* file = fopen(fname, "rb");
    assert(file);

    size_t file_sz = ct_file_get_size(file);

    struct ct_buf buf = { calloc(1, file_sz), file_sz };

    if (buf.p)
    {
        // Append the original plaintext
        for (size_t i = 0; i < file_sz; ++i)
        {
            int byte = fgetc(file);
            assert(byte != EOF);
            buf.p[i] = byte;
        }
    }

    fclose(file);

    return buf;
}


void ct_hmac_sha512_digest(
    hmac_sha512_ctx* ctx,
    unsigned char* digest
) {
    hmac_sha512_ctx ctx_copy = *ctx;
    hmac_sha512_final(&ctx_copy, digest, CT_HMAC_SZ);
}


unsigned char*
ct_crypt_round(
    struct ct_secret_key* SK,
    unsigned char* P,
    size_t P_sz,
    int M
) {
    hmac_sha512_ctx H;
    hmac_sha512_init(&H, SK->hmac_key, SK->hmac_key_sz);
    ct_reverse(SK->hmac_key, SK->hmac_key_sz);
    hmac_sha512_update(&H, SK->hmac_key, SK->hmac_key_sz);
    ct_reverse(SK->hmac_key, SK->hmac_key_sz);

    unsigned char D[256] = { 0 };
    size_t P_I = 0;
    unsigned long di = 0;

    while (P_I < P_sz)
    {
        ct_hmac_sha512_digest(&H, D);

        // Progress indicator
        if (!(di % 128))
        {
            printf("P_I = %zu of %zu\r", P_I, P_sz);
        }

        size_t D_I = 0;
        ++di;

        unsigned char update[CT_HMAC_SZ * 2];
        size_t bytes_written = 0;

        while (P_I < P_sz && D_I < CT_HMAC_SZ)
        {
            unsigned char P_byte = P[P_I];
            unsigned char C_byte = P_byte ^ D[D_I];
            P[P_I] = C_byte;

            if (M == 0)
            {
                update[D_I * 2] = P_byte;
                update[D_I * 2 + 1] = C_byte;
            }
            else
            {
                update[D_I * 2] = C_byte;
                update[D_I * 2 + 1] = P_byte;
            }

            ++P_I;
            ++D_I;
            bytes_written += 2;
        }

        // Update with ACTUAL bytes, not full buffer!
        hmac_sha512_update(&H, update, bytes_written);
    }

    printf("P_I = %zu of %zu\n", P_I, P_sz);

    return P;
}


unsigned char*
ct_crypt(
    struct ct_secret_key* SK,
    unsigned char* P,
    size_t P_sz,
    int M
) {
    printf("Crypt Round 0:\n________________________\n");
    unsigned char* C = ct_crypt_round(SK, P, P_sz, M);
    unsigned char* C_1 = ct_reverse(C, P_sz);
    printf("\n\nCrypt Round 1:\n________________________\n");
    C = ct_crypt_round(SK, C_1, P_sz, M);
    return C;
}



int
ct_ciphertext_to_file(
    FILE* fout,
    struct ct_buf const* buf
) {
    for (size_t i = 0; i < buf->sz; ++i)
    {
        int status = fputc((int)buf->p[i], fout);

        if (status == EOF)
        {
            assert(status != EOF);
            return 0;
        }
    }

    return 1;
}


int
ct_plaintext_to_file(
    FILE* fout,
    struct ct_secret_key* SK,
    struct ct_buf const* buf
) {
    assert(SK->rand_n <= buf->sz);

    for (size_t i = SK->rand_n; i < buf->sz; ++i)
    {
        int status = fputc((int)buf->p[i], fout);

        if (status == EOF)
        {
            assert(status != EOF);
            return 0;
        }
    }

    return 1;
}


int
ct_encrypt(
    struct ct_secret_key* SK,
    char const* fname_in,
    char const* fname_out
) {
    int status = 0;

    // Prepend the random bytes to the file...
    struct ct_buf buf = ct_prepend_from_file(SK, fname_in);

    if (buf.p)
    {
        unsigned char* C = ct_crypt(SK, buf.p, buf.sz, 0);

        //printf("\n\n\nCiphertext:");
        //ct_hex_printf(stdout, C, buf.sz);
        //printf("\n\n\n");

        // Write encrypted buffer to out file
        {
            FILE* fout = fopen(fname_out, "wb");
            assert(fout);

            status = ct_ciphertext_to_file(fout, &buf);

            fclose(fout);
        }

        free(buf.p);
    }

    return status;
}


int
ct_decrypt(
    struct ct_secret_key* SK,
    char const* fname_in,
    char const* fname_out
) {
    int status = 0;

    // Load the file...
    struct ct_buf buf = ct_load_from_file(fname_in);

    if (buf.p)
    {
        unsigned char* C = ct_crypt(SK, buf.p, buf.sz, 1);

        //printf("\n\n\nPlaintext:");
        //ct_hex_printf(stdout, C, buf.sz);
        //printf("\n\n\n");

        // Write decrypted buffer to out file
        {
            FILE* fout = fopen(fname_out, "wb");
            assert(fout);

            status = ct_plaintext_to_file(fout, SK, &buf);

            fclose(fout);
        }

        free(buf.p);
    }

    return status;
}


void ct_help(void)
{
    printf(
        "\n\n\n"
        "DrMoron Cipher - HMAC-based Stream Cipher\n"
        "==========================================\n\n"
        "Usage: program in_file out_file mode_flag\n\n"
        "mode_flag -e is encrypt where the in_file gets encrypted as out_file\n\n"
        "mode_flag -d is decrypt where the in_file gets decrypted as out_file\n\n"
        "Example:\n\n"
        "program plaintext.txt ciphertext.bin -e\n"
        "program ciphertext.bin plaintext_decrypt.txt -d\n\n"
        "SECURITY NOTES:\n"
        "- Uses cryptographically secure RNG (/dev/urandom on Unix, CryptGenRandom on Windows)\n"
        "- Hardcoded key in this version - REPLACE with proper key management for real use!\n"
        "- This is an EXPERIMENTAL cipher - not recommended for production use\n\n"
    );
}


int main(int argc, char* argv[])
{
    printf("\n=== DrMoron Cipher (Fixed TRNG Version) ===\n\n");

    if (argc != 4)
    {
        printf("ERROR: Incorrect argument count!\n");
        ct_help();
        return EXIT_FAILURE;
    }

    {
        int mode = 0;

        if (strcmp(argv[3], "-e") == 0)
        {
            mode = 0;
            printf("Mode: ENCRYPT\n");
        }

        else if (strcmp(argv[3], "-d") == 0)
        {
            mode = 1;
            printf("Mode: DECRYPT\n");
        }

        else
        {
            printf("ERROR: Invalid encrypt/decrypt flag!\n");
            ct_help();
            return EXIT_FAILURE;
        }

        // WARNING: This is a hardcoded key for demonstration only!
        // In real use, generate a proper 64-byte key from a TRNG
        unsigned char hmac_key[] = "Password";

        printf("WARNING: Using hardcoded demo key - NOT SECURE for production!\n");
        printf("Input file: %s\n", argv[1]);
        printf("Output file: %s\n\n", argv[2]);

        struct ct_secret_key SK = {
            hmac_key,
            sizeof(hmac_key) - 1,
            "sha512",
            73  // >64 bytes for SHA-512 digest size requirement
        };

        if (mode == 0)
        {
            ct_encrypt(&SK, argv[1], argv[2]);
            printf("\n\nEncryption complete!\n");
        }

        else
        {
            ct_decrypt(&SK, argv[1], argv[2]);
            printf("\n\nDecryption complete!\n");
        }
    }

    return EXIT_SUCCESS;
}
