/**********************************************************************
 * Copyright (c) 2020 Elichai Turkel	                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include "random.h"
#include "secp256k1.h"


void print_hex(unsigned char* data, size_t size) {
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main(void) {
    unsigned char seckey[32];
    unsigned char compressed_pubkey[33];
    unsigned char uncompressed_pubkey[65];
    size_t len;
    secp256k1_pubkey pubkey;
    /* The docs in secp256k1.h above the `secp256k1_ec_pubkey_create` function say:
     * "pointer to a context object, initialized for signing"
     * Which is why we create a context for signing(SECP256K1_CONTEXT_SIGN). */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    while (1) {
        if (!fill_random(seckey, sizeof(seckey))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (secp256k1_ec_seckey_verify(ctx, seckey)) {
            break;
        }
    }

    /* Pubkey creation on a valid Context with a verified seckey should never fail */
    assert(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey));

    /* Serialize the pubkey in a compressed form */
    len = sizeof(compressed_pubkey);
    secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    /* Should be the same size as the size of the output */
    assert(len == sizeof(compressed_pubkey));

    /* Serialize the pubkey in an uncompressed form */
    len = sizeof(uncompressed_pubkey);
    secp256k1_ec_pubkey_serialize(ctx, uncompressed_pubkey, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    assert(len == sizeof(uncompressed_pubkey));

    printf("Secret Key: ");
    print_hex(seckey, sizeof(seckey));
    printf("Compressed Pubkey: ");
    print_hex(compressed_pubkey, sizeof(compressed_pubkey));
    printf("Uncompressed Pubkey: ");
    print_hex(uncompressed_pubkey, sizeof(uncompressed_pubkey));

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);

   /* It's best practice to try and zero out secrets after using them.
    * This is done because some bugs can allow an attacker leak memory, for example out of bounds array access(see Heartbleed for example).
    * We want to prevent the secrets from living in memory after they are used so they won't be leaked,
    * for that we zero out the buffer.
    *
    * TODO: Prevent these writes from being optimized out, as any good compiler will remove any writes that aren't used. */
    memset(seckey, 0, sizeof(seckey));

    return 0;
}
