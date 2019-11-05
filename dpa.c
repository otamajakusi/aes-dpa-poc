#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#define ECB 1

#include "aes.h"

static uint8_t distance_table[256][256];
static int score_table[16][256];

static void __attribute__((unused)) dump_block(const uint8_t data[], int size)
{
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

static void score_by_index(const uint8_t *text, const uint8_t *distance)
{
    for (int n = 0; n < 16; n ++) {
        for (int i = 0; i < 256; i ++) {
            if (distance_table[text[n]][i] == distance[n]) {
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

static int dpa_test() {
    struct AES_ctx ctx;
    const uint8_t key[16] = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    };
    const uint8_t plain[16] = {0};
    uint8_t text[16];

    init_distance_table();
    init_score_table();

    AES_init_ctx(&ctx, key);
    memcpy(text, plain, sizeof(plain));

    for (int try = 0;; try ++) {
        uint8_t distance[16] = {0};
        AES_ECB_encrypt_with_distance(&ctx, text, distance);
        score_by_index(text, distance);
		increment_block(text);
        uint8_t prob_key[16];
        calc_prob_key(prob_key);
        uint8_t *act_key = &ctx.RoundKey[sizeof(ctx.RoundKey) - 16];
        if (memcmp(act_key, prob_key, 16) == 0) {
            printf("key found! by %d try.\n", try);
            break;
        }
    }
    return 0;
}

int main(void)
{
    if (simple_test()) {
        printf("simple_test failed.\n");
        return EXIT_FAILURE;
    }
    if (dpa_test()) {
        printf("dpa_test failed.\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
