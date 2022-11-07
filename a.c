#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <byteswap.h>
#include <string.h>

#define D(...) fprintf(stderr, __VA_ARGS__)

//// 3.2 Operations on Words
typedef unsigned int word_t;  // SHA-256 operates 32-bit word
const size_t w = 8 * sizeof(word_t);  // w-bit word_t
word_t shr(size_t n, word_t x) { return x >> n; }  // right shift
word_t rotr(size_t n, word_t x) { return x >> n | x << w - n; } // rotate right
word_t rotl(size_t n, word_t x) { return x << n | x >> w - n; } // rotate left

//// 4. FUNCTIONS AND CONSTANTS
//// 4.1.2 SHA-256 Functions
word_t ch(word_t x, word_t y, word_t z) { return x & y ^ ~x & z; }      //4.2
word_t maj(word_t x, word_t y, word_t z) { return x & y ^ x & z ^ y & z; }//4.3
word_t m0(word_t x) { return rotr( 2, x) ^ rotr(13, x) ^ rotr(22, x); } //Σ 4.4
word_t m1(word_t x) { return rotr( 6, x) ^ rotr(11, x) ^ rotr(25, x); } //Σ 4.5
word_t q0(word_t x) { return rotr( 7, x) ^ rotr(18, x) ^  shr( 3, x); } //σ 4.6
word_t q1(word_t x) { return rotr(17, x) ^ rotr(19, x) ^  shr(10, x); } //σ 4.7

//// 4.2.2 SHA-256 Constants
const word_t ks[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

//// Write hex
char fprint_helper(char c) {
    return c < '\x20' || c > '\x7E' ? '?' : c;
}

void fprint_mc(FILE *file_descriptor, const char *message) {
    size_t i, j;

    // assume message size is 64 bytes
    for (i = 0; i < 4; ++i) {
        for (j = 0; j < 16; ++j) {
            fprintf(file_descriptor, " %02X", (unsigned char)*message++);

            if (j % 4 == 3 && j % 16 != 15) {
                fprintf(file_descriptor, " |");
            }
        }

        message -= 16;
        fprintf(file_descriptor, "  \"");

        for (j = 0; j < 16; ++j) {
            fprintf(file_descriptor, "%c", fprint_helper(*message++));
        }

        fprintf(file_descriptor, "\"\n");
    }
}

//// Read message
enum PadState { PAD_NULL = 0, PAD_ONE = 1, PAD_SIZE = 2 };

struct Reader {
    int file_descriptor;
    ssize_t message_size_bits;
    enum PadState pad_state;
    char buffer[64];
    char null_terminator;
};

struct Reader* create_reader(int file_descriptor) {
    struct Reader *this = (struct Reader*)malloc(sizeof(struct Reader));
    this->file_descriptor = file_descriptor;
    return this;
}

void pad(struct Reader *, ssize_t);

void read_block(struct Reader *this, word_t *ms) {
    ssize_t read_bytes, i;

    read_bytes = read(this->file_descriptor, this->buffer, 64);

    if (read_bytes == -1) {  // Error on read
        if (EINTR == errno) {
            D("eintr\n");
            exit(EXIT_FAILURE);
        } else {
            perror("read. ");
            exit(EXIT_FAILURE);
        }
    }

    this->message_size_bits += read_bytes << 3;

    if (read_bytes < 64) {
        pad(this, read_bytes);
    }

    memcpy(ms, this->buffer, 64);
    for (i = 0; i < 16; ++i) {
        ms[i] = bswap_32(ms[i]);
    }
}

//// 5. PREPROCESSING
//// 5.1 Padding the Message
void pad(struct Reader *this, ssize_t buffer_size_bytes) {
    ssize_t zero_bytes_count; char *buffer_cursor, *size_begin, *buffer_end;

    buffer_cursor = this->buffer;
    buffer_end = buffer_cursor + 64;

    // return in case of insufficient space for 1-byte '\x80'
    if (buffer_end == buffer_cursor) { return; }

    buffer_cursor += buffer_size_bytes;

    if (this->pad_state == PAD_NULL) {
        *buffer_cursor++ = '\x80';
        this->pad_state = PAD_ONE;
    }

    size_begin = buffer_end - 8;

    if (size_begin < buffer_cursor) {
        // insufficient space for 8-bytes size
        while (buffer_cursor < buffer_end) { *buffer_cursor++ = '\0'; }
        return;
    }

    while (buffer_cursor < size_begin) { *buffer_cursor++ = '\0'; }

    for (ssize_t i = 7; i >= 0; --i) {
        *buffer_cursor++ = ((unsigned char*)&this->message_size_bits)[i];
    }

    this->pad_state = PAD_SIZE;
}

//// 5.3 Setting the Initial Hash Value
const word_t hs_init[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

//// 6. SECURE HASH ALGORITHMS
void hash() {
    word_t a, b, c, d, e, f, g, h, t1, t2; int i, t; struct Reader *reader;
    word_t ws[64]; word_t hs[8]; word_t ms[16];

    // Init Reader
    reader = create_reader(STDIN_FILENO);

    // Init hs
    for (i = 0; i < 8; ++i) { hs[i] = hs_init[i]; }

    // 6.2.2 SHA-256 Hash Computation
    for (i = 0; /* For each message block */; ++i) {
        // Read, pad and parse message block
        read_block(reader, ms);

        D("buffer (%d) :\n", i);
        fprint_mc(stderr, reader->buffer);
        D("\n");

        // 1. Prepare the message shedule, ws[t]
        for (t = 0; t < 16; ++t) { ws[t] = ms[t]; }
        for (t = 16; t < 64; ++t) {
            ws[t] = q1(ws[t - 2]) + ws[t - 7] + q0(ws[t - 15]) + ws[t - 16];
        }
        // 2. Initialize a..g
        a = hs[0]; b = hs[1]; c = hs[2]; d = hs[3];
        e = hs[4]; f = hs[5]; g = hs[6]; h = hs[7];
        // 3.
        for (t = 0; t < 64; ++t) {
            t1 = h + m1(e) + ch(e, f, g) + ks[t] + ws[t];
            t2 = m0(a) + maj(a, b, c);
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        // 4. Compute intermidiate hash value hs
        hs[0] += a; hs[1] += b; hs[2] += c; hs[3] += d;
        hs[4] += e; hs[5] += f; hs[6] += g; hs[7] += h;

        // exit messages loop
        if (reader->pad_state == PAD_SIZE) {
            break;
        }
    }

    for (i = 0; i < 8; ++i) {
        printf("%08x", hs[i]);
    }
    printf("\n");
}

void main() {
    hash();
}
