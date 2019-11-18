// crypto.cpp : example console application to test libhydrogen library and to create first prototype of encryted comm of mavlink devices
// Made by Roman Ligocki
// Used library: libhydrogen

#include <stdio.h>
#include "hydrogen.h"

#include "impl/common.h"
#include "impl/hydrogen_p.h"

#include "impl/core.h"
#include "impl/gimli-core.h"
#include "impl/random.h"

#include "impl/hash.h"
#include "impl/kdf.h"
#include "impl/secretbox.h"

#include "impl/x25519.h"

#include "impl/kx.h"
#include "impl/pwhash.h"
#include "impl/sign.h"

#include "monocypher.h"

#include <time.h>

/* Read about context: https://github.com/jedisct1/libhydrogen/wiki/Contexts */
#define CONTEXTHASH "hashhash"
#define CONTEXTSIGN "signsign"
#define CONTEXTENCR "encrencr"

/* My random message. Lenght of 279 bytes is prepared for max lenght of mavlink message. Is it right idea????*/
#define MESSAGE "Some telemetry data, that needs to be encrypted. Lets see if they are able to do it !!!"
#define MAVLINK_LENGHT_MAX 279
#define ENCRYPTED_MAVLINK_LENGHT_MAX (MAVLINK_LENGHT_MAX + hydro_secretbox_HEADERBYTES)

#define DEBUG 0
#define TIMER 1




typedef struct certificateLibHydrogen {
    char name[10]; //  name of device
    char maintainer[10]; //Name of pilot or company
    uint8_t privilages; //privilages in mavlink comm
    uint8_t pubK[hydro_kx_PUBLICKEYBYTES]; //Pointer to publicKey of drone
    uint8_t sign[hydro_sign_PUBLICKEYBYTES]; // Signed hash(name + maintainer + privilages), When verified you know if the divice is realy this device
} certificateLibHydrogen;


typedef struct certificateMonoCypher {
    char name[10]; //  name of device
    char maintainer[10]; //Name of pilot or company
    uint8_t privilages; //privilages in mavlink comm
    uint8_t pubK[32]; //Pointer to publicKey of drone
    uint8_t sign[64]; // Signed hash(name + maintainer + privilages), When verified you know if the divice is realy this device
} certificateMonoCypher;

typedef struct keyStorageLibHydrogen {
    hydro_kx_keypair deviceEncKeyPair; // Both keys generated in divice
    hydro_sign_keypair authoritySignKeyPair; // Only publicKey of GCS (authority) that device need for veryfication
    hydro_kx_session_keypair symetricKeyPair; // Two symetric keys. TODO: Reasearch why we should use two keys.
    hydro_sign_keypair deviceSignKeyPair; // This struct uses only GCS ()

    certificateLibHydrogen cert; // Information about device, that needs to be signed by authority.
} keyStorageLibHydrogen;

typedef struct keyStorageMonoCypher {
    uint8_t deviceEncPublicKey[32];
    uint8_t deviceEncPrivateKey[32];
    uint8_t deviceSignPublicKey[32];
    uint8_t deviceSignPrivateKey[32];
    uint8_t authorityPublicKey[32];
    uint8_t symK[32];

    certificateMonoCypher cert; // Information about device, that needs to be signed by authority.
} keyStorageMonoCyper;

void signCertificateLibHydrogen(certificateLibHydrogen *cert, uint8_t *pk);
bool verifyCertificateLibHydrogen(certificateLibHydrogen *cert, uint8_t *pk);

void generateKeysMonoCypher(keyStorageMonoCyper *keyStorageMono);
void signCertificateMonoCypher(certificateMonoCypher *cert, uint8_t *sk, uint8_t *pk);
bool verifyCertificateMonoCypher(certificateMonoCypher *cert, uint8_t *pk);


int main()
{
    double time_spent = 0.0;
    clock_t begin,end;
    
    
    //Initialization of library libhydrogen.
    if (hydro_init() != 0) {
        abort();
    }

    //Storage of keys for every device.
    keyStorageLibHydrogen drone1KeysHydro;
    keyStorageLibHydrogen drone2KeysHydro;
    keyStorageLibHydrogen drone3KeysHydro;
    keyStorageLibHydrogen gcsKeysHydro;
    
    //Key generation for every device
    
    begin = clock();
    hydro_kx_keygen(&drone1KeysHydro.deviceEncKeyPair);
    hydro_sign_keygen(&drone1KeysHydro.deviceSignKeyPair);
    end = clock();
    if(TIMER){printf("LibHydrogen - keygeneration took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    

    hydro_kx_keygen(&drone2KeysHydro.deviceEncKeyPair);
    hydro_sign_keygen(&drone2KeysHydro.deviceSignKeyPair);

    hydro_kx_keygen(&drone3KeysHydro.deviceEncKeyPair);
    hydro_sign_keygen(&drone3KeysHydro.deviceSignKeyPair);

    hydro_kx_keygen(&gcsKeysHydro.deviceEncKeyPair);
    hydro_sign_keygen(&gcsKeysHydro.deviceSignKeyPair);
    
    memcpy(&drone1KeysHydro.authoritySignKeyPair.pk, &gcsKeysHydro.deviceSignKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);
    memcpy(&drone2KeysHydro.authoritySignKeyPair.pk, &gcsKeysHydro.deviceSignKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);
    memcpy(&drone3KeysHydro.authoritySignKeyPair.pk, &gcsKeysHydro.deviceSignKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);
    
    strcmp("Tarot 650", drone1KeysHydro.cert.name);
    strcmp("Roman Ligocki", drone1KeysHydro.cert.maintainer);
    drone1KeysHydro.cert.privilages = 5;
    memcpy(drone1KeysHydro.cert.pubK, drone1KeysHydro.deviceEncKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

    strcmp("Tarot 680", drone1KeysHydro.cert.name);
    strcmp("Adam Ligocki", drone1KeysHydro.cert.maintainer);
    drone2KeysHydro.cert.privilages = 2;
    memcpy(drone2KeysHydro.cert.pubK, drone2KeysHydro.deviceEncKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

    strcmp("Random VTOL plane", drone1KeysHydro.cert.name);
    strcmp("Matej Malinowski", drone1KeysHydro.cert.maintainer);
    drone3KeysHydro.cert.privilages = 1;
    memcpy(drone3KeysHydro.cert.pubK, drone3KeysHydro.deviceEncKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

    //Signing of certificateLibHydrogen
    
    begin = clock();
    signCertificateLibHydrogen(&drone1KeysHydro.cert, gcsKeysHydro.deviceSignKeyPair.sk);
    end = clock();
    if(TIMER){printf("LibHydrogen - certificate signing took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    signCertificateLibHydrogen(&drone2KeysHydro.cert, gcsKeysHydro.deviceSignKeyPair.sk);
    signCertificateLibHydrogen(&drone3KeysHydro.cert, gcsKeysHydro.deviceSignKeyPair.sk);
    
    //Verification of certificateLibHydrogen
    begin = clock();
    if (verifyCertificateLibHydrogen(&drone1KeysHydro.cert, drone2KeysHydro.authoritySignKeyPair.pk)) {
        if(DEBUG){ printf("%s", "LibHydrogen - Drone1: Its OK Drone2, I will trust your certificate\n");}
    }else {
        if(DEBUG){ printf("%s", "LibHydrogen - Drone1: Hey Drone2 !! You are scam !!!!\n");}
    }
    end = clock();
    if(TIMER){printf("LibHydrogen - certificate varification took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}

    signCertificateLibHydrogen(&drone1KeysHydro.cert, drone3KeysHydro.deviceSignKeyPair.sk);

    if (verifyCertificateLibHydrogen(&drone1KeysHydro.cert, drone2KeysHydro.authoritySignKeyPair.pk)) {
        if(DEBUG){ printf("%s", "LibHydrogen - Drone1: Don't worry Drone2, I will trust your certificate\n");}
    }
    else {
        if(DEBUG){ printf("%s", "LibHydrogen - Drone1: Hey !! You are scam !!!!\n");}
    }

    uint8_t packet1[hydro_kx_N_PACKET1BYTES];
    
    //Doesnt work
    
    if(DEBUG){printf("Libhydrogen - key exchange step 1 is ");}
    begin = clock();
    if (hydro_kx_n_1(&drone1KeysHydro.symetricKeyPair, packet1, NULL, drone2KeysHydro.deviceEncKeyPair.pk) != 0) {
        if(DEBUG){ printf("not OK\n");}
    }else{
        if(DEBUG){ printf("OK\n");}
    }
    end = clock();
    if(TIMER){printf("LibHydrogen - session key encryption took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    
    if(DEBUG){printf("Libhydrogen - key exchange step 2 is ");}
    begin = clock();
    if (hydro_kx_n_2(&drone2KeysHydro.symetricKeyPair, packet1, NULL, &drone2KeysHydro.deviceEncKeyPair) != 0) {
        if(DEBUG){printf("not OK\n");}
    }else{
        if(DEBUG){printf("OK\n");}
    }
    end = clock();
    if(TIMER){printf("LibHydrogen - session key decryption took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}

    uint8_t ciphertext[ENCRYPTED_MAVLINK_LENGHT_MAX];
    
    begin = clock();
    hydro_secretbox_encrypt(ciphertext, MESSAGE, MAVLINK_LENGHT_MAX, 0, CONTEXTENCR, drone1KeysHydro.symetricKeyPair.tx);
    end = clock();
    if(TIMER){printf("LibHydrogen - message encryption took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    // Received ciphertext decryption
    char decrypted[MAVLINK_LENGHT_MAX];
    
    begin = clock();
    if(hydro_secretbox_decrypt(decrypted, ciphertext, ENCRYPTED_MAVLINK_LENGHT_MAX, 0, CONTEXTENCR, drone1KeysHydro.symetricKeyPair.tx)){
        if(DEBUG){printf("LibHydrogen - decryption is not OK\n");}
    }else{
        if(DEBUG){printf("LibHydrogen - decryption is OK\n");}
    }
    end = clock();
    if(TIMER){printf("LibHydrogen - message decryption took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    printf("\n\n");
    
    keyStorageMonoCyper drone1KeysMono;
    keyStorageMonoCyper drone2KeysMono;
    keyStorageMonoCyper drone3KeysMono;
    keyStorageMonoCyper gcsKeysMono;
    
    begin = clock();
    generateKeysMonoCypher(&drone1KeysMono);
    end = clock();
    if(TIMER){printf("MonoCypher - key generation took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    generateKeysMonoCypher(&drone2KeysMono);
    generateKeysMonoCypher(&drone3KeysMono);
    generateKeysMonoCypher(&gcsKeysMono);
    
    memcpy(&drone1KeysMono.authorityPublicKey, &gcsKeysHydro.deviceSignKeyPair, sizeof(uint8_t) * 32);
    memcpy(&drone2KeysMono.authorityPublicKey, &gcsKeysHydro.deviceSignKeyPair, sizeof(uint8_t) * 32);
    memcpy(&drone3KeysMono.authorityPublicKey, &gcsKeysHydro.deviceSignKeyPair, sizeof(uint8_t) * 32);
    
    strcmp("Tarot 650", drone1KeysMono.cert.name);
    strcmp("Roman Ligocki", drone1KeysMono.cert.maintainer);
    drone1KeysMono.cert.privilages = 5;
    memcpy(drone1KeysMono.cert.pubK, drone1KeysMono.deviceEncPublicKey, sizeof(uint8_t) * 32);

    strcmp("Tarot 680", drone2KeysMono.cert.name);
    strcmp("Adam Ligocki", drone2KeysMono.cert.maintainer);
    drone2KeysMono.cert.privilages = 2;
    memcpy(drone2KeysMono.cert.pubK, drone2KeysMono.deviceEncPublicKey, sizeof(uint8_t) * 32);

    strcmp("Random VTOL plane", drone3KeysHydro.cert.name);
    strcmp("Matej Malinowski", drone3KeysHydro.cert.maintainer);
    drone3KeysHydro.cert.privilages = 1;
    memcpy(drone3KeysMono.cert.pubK, drone3KeysMono.deviceEncPublicKey, sizeof(uint8_t) * 32);
    
    begin = clock();
    signCertificateMonoCypher(&drone1KeysMono.cert, gcsKeysMono.deviceSignPrivateKey, gcsKeysMono.deviceSignPublicKey);
    end = clock();
    if(TIMER){printf("MonoCypher - certificate signing took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    begin = clock();
    if(verifyCertificateMonoCypher(&drone1KeysMono.cert, drone2KeysMono.authorityPublicKey)){
        if(DEBUG){printf("Something goes wrong\n");}
    }else{
        if(DEBUG){ printf("Certificate is OK");}
    }
    end = clock();
    if(TIMER){printf("MonoCypher - certificate veryfication took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    
    
    uint8_t sharedKeyDrone1[32];
    uint8_t sharedKeyDrone2[32];
    
    const uint8_t nonce      [24] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    const uint8_t plain_text[] = MESSAGE;
    uint8_t       mac        [16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
    uint8_t       cipher_text[sizeof plain_text];
    uint8_t plain_text_decrypt[sizeof plain_text];
    
    begin = clock();
    crypto_key_exchange(sharedKeyDrone1, drone1KeysMono.deviceEncPrivateKey, drone2KeysMono.deviceEncPublicKey);
    end = clock();
    if(TIMER){printf("MonoCypher - session key computation took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    crypto_key_exchange(sharedKeyDrone2, drone2KeysMono.deviceEncPrivateKey, drone1KeysMono.deviceEncPublicKey);
    
    begin = clock();
    crypto_lock(mac, cipher_text, sharedKeyDrone1, nonce, plain_text, sizeof plain_text);
    end = clock();
    if(TIMER){printf("MonoCypher - message encryption took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    begin = clock();
    if (crypto_unlock(plain_text_decrypt, sharedKeyDrone2, nonce, mac, cipher_text, sizeof cipher_text)) {
        if(DEBUG){printf("Something goes wrong");}
    }else{
        if(DEBUG){printf("%s", plain_text_decrypt);}
    }
    end = clock();
    if(TIMER){printf("MonoCypher - message decryption took %f seconds\n", (double)(end - begin) / CLOCKS_PER_SEC);}
    
    getchar();
    return 0;

    

}

void signCertificateLibHydrogen(certificateLibHydrogen *cert, uint8_t *sk) {
    
    hydro_hash_state state;

    hydro_hash_init(&state, CONTEXTHASH, NULL);

    hydro_hash_update(&state, cert->name, sizeof(cert->name));
    hydro_hash_update(&state, cert->maintainer, sizeof(cert->maintainer));
    hydro_hash_update(&state, &cert->privilages, sizeof(cert->privilages));
    hydro_hash_update(&state, &cert->pubK, sizeof(cert->pubK));

    uint8_t hash[hydro_hash_BYTES];
    
    hydro_hash_final(&state, hash, sizeof hash);
    
    hydro_sign_create(cert->sign, hash, sizeof(uint8_t) * hydro_hash_BYTES, CONTEXTSIGN, sk);
}

bool verifyCertificateLibHydrogen(certificateLibHydrogen *cert, uint8_t *pk) {
    
    hydro_hash_state state;

    uint8_t privilages[1];
    privilages[0] = cert->privilages;
    
    hydro_hash_init(&state, CONTEXTHASH, NULL);

    hydro_hash_update(&state, (const uint8_t *)cert->name, sizeof(cert->name));
    hydro_hash_update(&state, (const uint8_t *)cert->maintainer, sizeof(cert->maintainer));
    hydro_hash_update(&state, (const uint8_t *)privilages, sizeof(cert->privilages));
    hydro_hash_update(&state, (const uint8_t *)cert->pubK, sizeof(cert->pubK));

    uint8_t hash[hydro_hash_BYTES];
    
    hydro_hash_final(&state, hash, sizeof hash);
    
    if (hydro_sign_verify(cert->sign, hash, sizeof(uint8_t) * hydro_hash_BYTES, CONTEXTSIGN, pk) != 0) {
        return 0;
    }else {
        return 1;
    }
}

void generateKeysMonoCypher(keyStorageMonoCyper *keyStorageMono){
    
    hydro_random_buf(keyStorageMono->deviceEncPrivateKey, sizeof keyStorageMono->deviceEncPrivateKey);
    hydro_random_buf(keyStorageMono->deviceSignPrivateKey, sizeof keyStorageMono->deviceSignPrivateKey);
    
    crypto_key_exchange_public_key(keyStorageMono->deviceEncPublicKey, keyStorageMono->deviceEncPrivateKey);
    crypto_sign_public_key(keyStorageMono->deviceSignPublicKey, keyStorageMono->deviceSignPrivateKey);
    
    hydro_random_buf(keyStorageMono->symK, sizeof keyStorageMono->symK);
}

void signCertificateMonoCypher(certificateMonoCypher *cert, uint8_t *sk, uint8_t *pk) {

    uint8_t hash[64];
    crypto_blake2b_ctx ctx;
    
    uint8_t privilages[1];
    privilages[0] = cert->privilages;
    
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->name, sizeof cert->name);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->maintainer, sizeof cert->maintainer);
    crypto_blake2b_update(&ctx, (const uint8_t *)privilages, sizeof(cert->privilages));
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->pubK, sizeof cert->pubK);
    
    crypto_blake2b_final(&ctx, hash);
    
    crypto_sign(cert->sign, sk, pk, hash, 64);
}

bool verifyCertificateMonoCypher(certificateMonoCypher *cert, uint8_t *pk) {

    uint8_t hash[64];
    crypto_blake2b_ctx ctx;
    
    uint8_t privilages[1];
    privilages[0] = cert->privilages;
    
    crypto_blake2b_init(&ctx);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->name, sizeof cert->name);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->maintainer, sizeof cert->maintainer);
    crypto_blake2b_update(&ctx, (const uint8_t *)privilages, sizeof cert->privilages);
    crypto_blake2b_update(&ctx, (const uint8_t *)cert->pubK, sizeof cert->pubK);
    
    crypto_blake2b_final(&ctx, hash);
    
    if(crypto_check(cert->sign, pk, hash, 64) != 0){
        return 0;
    }else{
        return 1;
    }
    
}



