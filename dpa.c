#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#define ECB 1

#include "aes.h"

typedef enum {
    dpa_test_16,
    dpa_test_4,
    dpa_test_1,
} dpa_test_type;

/*
 * hamming distance table.
 * 00-00, 00-01, 00-02, ...
 * 01-00, 01-01, 01-02, ...
 * ..
 * FF-00, FF-01, FF-02, ...
 */
static uint8_t distance_table[256][256];
static int score_table[16][256];

static void __attribute__((unused)) dump_block(const uint8_t data[], int size, const char *title)
{
    puts(title);
    for (int i = 0; i < size; i ++) {
        printf("%02x:", data[i]);
        if (((i + 1) % 16) == 0) {
            printf("\n");
        }
    }
}

static int count8(uint8_t x)
{
    int c = 0;
    for (int i = 0; i < 8; i ++) {
        if (x & (1 << i))  c ++;
    }
    return c;
}

static void init_distance_table(void)
{
    for (int i = 0; i < 256; i ++) {
        for (int j = 0; j < 256; j ++) {
            distance_table[i][j] = count8(i ^ j);
        }
    }
}

static void init_score_table()
{
    memset(score_table, 0, sizeof(score_table));
}

static void score_by_distance_table(
        const uint8_t *text, const uint8_t *distances, dpa_test_type type)
{
    int dist[16] = {0};
    int mul[3] = {1, 4, 16};
    switch (type) {
    default:
    case dpa_test_16:
        /* for each 1-byte */
        for (int i = 0; i < 16; i ++) {
            dist[i] = distances[i];
        }
        break;
    case dpa_test_4:
        /* each 4-bytes as a group */
        for (int i = 0; i < 16; i += 4) {
            int d = (distances[i]
                     + distances[i + 1]
                     + distances[i + 2]
                     + distances[i + 3]);
            /* set same value */
            dist[i + 0] = d;
            dist[i + 1] = d;
            dist[i + 2] = d;
            dist[i + 3] = d;
        }
        break;
    case dpa_test_1:
        /* a single group */
        {
            int d = 0;
            for (int i = 0; i < 16; i ++) {
                d += distances[i];
            }
            /* set same value */
            for (int i = 0; i < 16; i ++) {
                dist[i] = d;
            }
        }
        break;
    }

    for (int n = 0; n < 16; n ++) {
        for (int i = 0; i < 256; i ++) {
            if (distance_table[text[n]][i] * mul[type] == dist[n]) {
                score_table[n][i] ++;
            }
        }
    }
}

static int argmax(int *array, int size)
{
	int max = INT_MIN;
    int idx = 0;
	for (int i = 0; i < size; i ++) {
        if (array[i] > max) {
            max = array[i];
            idx = i;
        }
	}
    return idx;
}

static void calc_prob_key(uint8_t *prob_key)
{
    for (int n = 0; n < 16; n ++) {
        prob_key[n] = argmax(score_table[n], 256);
    }
}

/*
 * incrment block
 * 00000000_00000000 -> 00000000_00000001
 * 00000000_0000000f -> 00000000_00000010
 * 00000000_000000ff -> 00000000_00000100
 */
static void increment_block(uint8_t *p)
{
	for (int i = 0; i < 16; i ++) {
		p[i] ++;
		if (p[i] != 0) {
			break;
		}
	}
}

static int simple_test() {
    struct AES_ctx ctx;
    const uint8_t key[16] = {
        0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c
    };
    const uint8_t plain[16] = {
        0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a
    };
    const uint8_t cipher[16] = {
        0x3a,0xd7,0x7b,0xb4,0x0d,0x7a,0x36,0x60,0xa8,0x9e,0xca,0xf3,0x24,0x66,0xef,0x97
    };
    uint8_t text[16];
    AES_init_ctx(&ctx, key);
    memcpy(text, plain, sizeof(plain));
    AES_ECB_encrypt(&ctx, text);
    return memcmp(text, cipher, sizeof(text));
}

static int cmp_count(const uint8_t *d1, const uint8_t *d2, size_t size)
{
    int count = 0;
    for (size_t i = 0; i < size; i ++) {
        if (d1[i] == d2[i]) {
            count ++;
        }
    }
    return count;
}

/* copied from aes.c */
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

/* copied from aes.c */
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static void aes_key_from_last_round_key(uint8_t *aes_key, const uint8_t *last_round_key)
{
    int i, j, k;
    uint8_t tempa[4]; // Used for the column/row operations

    uint8_t RoundKey[176];
    memcpy(&RoundKey[sizeof(RoundKey) - 16], last_round_key, 16);
    for (i = 11; i > 0; i --) {
        for (j = 0; j < 4; j ++) {
            k = (i * 4 - j) * 4 - 1;
            tempa[(4 - 1) - 0] = RoundKey[k - 4 - 0];
            tempa[(4 - 1) - 1] = RoundKey[k - 4 - 1];
            tempa[(4 - 1) - 2] = RoundKey[k - 4 - 2];
            tempa[(4 - 1) - 3] = RoundKey[k - 4 - 3];

            if (j == 3) {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
                tempa[0] = sbox[tempa[0]];
                tempa[1] = sbox[tempa[1]];
                tempa[2] = sbox[tempa[2]];
                tempa[3] = sbox[tempa[3]];
                tempa[0] = tempa[0] ^ Rcon[(i - 1)];
            }
            RoundKey[k - 16] = RoundKey[k - 0] ^ tempa[(4 - 1) - 0];
            RoundKey[k - 17] = RoundKey[k - 1] ^ tempa[(4 - 1) - 1];
            RoundKey[k - 18] = RoundKey[k - 2] ^ tempa[(4 - 1) - 2];
            RoundKey[k - 19] = RoundKey[k - 3] ^ tempa[(4 - 1) - 3];
        }
    }
    memcpy(aes_key, RoundKey, 16);
}

static int dpa_test(dpa_test_type type) {
    printf("----- dpa test %d ----\n", type);
    struct AES_ctx ctx;
    const uint8_t key[16] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    };
    const uint8_t plain[16] = {0};
    uint8_t text[16];

    init_distance_table();
    init_score_table();

    AES_init_ctx(&ctx, key);
    printf("roundkey\n");
    memcpy(text, plain, sizeof(plain));
    uint8_t *act_key = &ctx.RoundKey[sizeof(ctx.RoundKey) - 16];
    dump_block(act_key, 16, "--last_round_key(target)--");

    int almost15 = 0;
    int almost14 = 0;
    int almost13 = 0;

    for (int try = 0;; try ++) {
        uint8_t distances[16] = {0};
        AES_ECB_encrypt_with_distance(&ctx, text, distances);
        score_by_distance_table(text, distances, type);
		increment_block(text);
        uint8_t prob_key[16];
        calc_prob_key(prob_key);
        int cmpcnt = cmp_count(act_key, prob_key, 16);
        if (cmpcnt == 16) {
            printf("whole key found! by %d-try.\n", try);
            uint8_t aes_key[16];
            aes_key_from_last_round_key(aes_key, prob_key);
            dump_block(aes_key, sizeof(aes_key), "--calculaed aes_key--");
            break;
        } else if (cmpcnt == 15 && almost15 == 0) {
            printf("key of 15-bytes found! by %d-try.\n", try);
            almost15 = 1;
        } else if (cmpcnt == 14 && almost14 == 0) {
            printf("key of 14-bytes found! by %d-try.\n", try);
            almost14 = 1;
        } else if (cmpcnt == 13 && almost13 == 0) {
            printf("key of 13-bytes found! by %d-try.\n", try);
            almost13 = 1;
        }
        if ((try % 0x10000) == 0 && try != 0) {
            if (try == 0x10000) {
                printf("inspecting key..\n");
            }
            dump_block(prob_key, sizeof(prob_key), "--last_round_key(intermediate)--");
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    if (simple_test()) {
        printf("simple_test failed.\n");
        return EXIT_FAILURE;
    }
    if (dpa_test(dpa_test_16)) {
        printf("dpa_test_16 failed.\n");
        return EXIT_FAILURE;
    }
    if (dpa_test(dpa_test_4)) {
        printf("dpa_test_4 failed.\n");
        return EXIT_FAILURE;
    }
    if (dpa_test(dpa_test_1)) {
        printf("dpa_test_1 failed.\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
