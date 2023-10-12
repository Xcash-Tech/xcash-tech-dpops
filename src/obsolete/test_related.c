#include "test_related.h"

#include "variables.h"

void test_generate_secret_key(void) {
    size_t count, count2;
    char data[SMALL_BUFFER_SIZE];
    memset(data,0,sizeof(data));


    memset(secret_key,0,sizeof(secret_key));
    memset(secret_key_data,0,sizeof(secret_key_data));
    if (strncmp(xcash_wallet_public_address,TEST_WALLET_1,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_1,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_2,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_2,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_3,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_3,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_4,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_4,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_5,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_5,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_6,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_6,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_7,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_7,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_8,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_8,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_9,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_9,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_10,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_10,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_11,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_11,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_12,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_12,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_13,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_13,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_14,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_14,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_15,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_15,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_16,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_16,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_17,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_17,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_18,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_18,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_19,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_19,VRF_SECRET_KEY_LENGTH);
    }
    else if (strncmp(xcash_wallet_public_address,TEST_WALLET_20,XCASH_WALLET_LENGTH) == 0)
    {
    memcpy(secret_key,TEST_WALLET_SECRET_KEY_20,VRF_SECRET_KEY_LENGTH);
    }
    // convert the hexadecimal string to a string
    for (count = 0, count2 = 0; count < VRF_SECRET_KEY_LENGTH; count2++, count += 2)
    {
    memset(data,0,sizeof(data));
    memcpy(data,&secret_key[count],2);
    secret_key_data[count2] = (unsigned char)strtol(data, NULL, 16);
    }
}

