#include "mbed.h"
#include "hydrogen.h" 

Serial pc(USBTX,USBRX);
 
Timer t;

/* Read about context: https://github.com/jedisct1/libhydrogen/wiki/Contexts */
#define CONTEXTHASH "hashhash"
#define CONTEXTSIGN "signsign"
#define CONTEXTENCR "encrencr"

/* My random message. Lenght of 279 bytes is prepared for max lenght of mavlink message. Is it right idea????*/
#define MESSAGE "Jmenuji se Roman Ligocki a mam se opravdu dobre. Co rikas na tento kod Juliane ??? :D"
#define MAVLINK_LENGHT_MAX 279
#define ENCRYPTED_MAVLINK_LENGHT_MAX (MAVLINK_LENGHT_MAX + hydro_secretbox_HEADERBYTES)


typedef struct certificate {
	/*
	This certificate struct contains all data for self introducing to other devides (GCS, drones, operators) from fleet
	TODO: add next useful information to certificate
	TODO: verify if pubKey must be inside this struct ... if it is nessesery
	*/
	char name[10]; //  name of device
	char maintainer[10]; //Name of pilot or company
	uint8_t privilages; //privilages in mavlink comm
	uint8_t pubK[hydro_kx_PUBLICKEYBYTES]; //Pointer to publicKey of drone 
	uint8_t hash[hydro_hash_BYTES]; //Hash of certificate data
	uint8_t sign[hydro_sign_PUBLICKEYBYTES]; // Signed hash(name + maintainer + privilages), When verified you know if the divice is realy this device
} certificate;

typedef struct keyStorage {
	/*
	Struct, that contains all keys, that device needs for encryption. All devices uses same structure. 
	*/
	hydro_kx_keypair deviceEncKeyPair; // Both keys generated in divice
	hydro_sign_keypair authoritySignKeyPair; // Only publicKey of GCS (authority) that device need for veryfication
	hydro_kx_session_keypair symetricKeyPair; // Two symetric keys. TODO: Reasearch why we should use two keys.
	hydro_sign_keypair deviceSignKeyPair; // This struct uses only GCS ()

	certificate cert; // Information about device, that needs to be signed by authority. 
} keyStorage;

void hashCertificate(certificate *cert);
void generateKey(uint8_t *key);
void signCertificate(certificate *cert, uint8_t *pk);
bool verifyCertificate(certificate *cert, uint8_t *pk);

int main()
{
	//Initialization of library libhydrogen.
	if (hydro_init() != 0) {
		abort();
	}

    keyStorage drone1Keys;
    keyStorage gcsKeys;

    strcmp("Tarot 650", drone1Keys.cert.name);
	strcmp("Roman Ligocki", drone1Keys.cert.maintainer);
	drone1Keys.cert.privilages = 5;
	memcpy(drone1Keys.cert.pubK, drone1Keys.deviceEncKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

    memcpy(&drone1Keys.authoritySignKeyPair.pk, &gcsKeys.deviceSignKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

    hydro_kx_keygen(&gcsKeys.deviceEncKeyPair);
	hydro_sign_keygen(&gcsKeys.deviceSignKeyPair);

    while(true){
        t.start();
        hydro_kx_keygen(&drone1Keys.deviceEncKeyPair);
        t.stop();
        pc.printf("Assymetric encryption keys generation took %f seconds\n", t.read());
        t.reset();
        wait(1.0);

        t.start();
	    hydro_sign_keygen(&drone1Keys.deviceSignKeyPair);
        t.stop();
        pc.printf("Assymetric signing keys generation took  %f seconds\n", t.read());
        t.reset();
        wait(1.0);

        t.start();
	    hashCertificate(&drone1Keys.cert);
        t.stop();
        pc.printf("Hashing certificate took %f seconds\n", t.read());
        t.reset();
        wait(1.0);

        t.start();
        signCertificate(&drone1Keys.cert, gcsKeys.deviceSignKeyPair.sk);
        t.stop();
        pc.printf("Signing hashed certificate took %f seconds\n", t.read());
        t.reset();
        wait(1.0);

        t.start();
        verifyCertificate(&drone1Keys.cert, gcsKeys.deviceSignKeyPair.pk);
        t.stop();
        pc.printf("Verifying certificate took %f seconds\n", t.read());
        t.reset();
        wait(1.0);

        uint8_t packet1[hydro_kx_N_PACKET1BYTES];

        t.start();
        hydro_kx_n_1(&drone1Keys.symetricKeyPair, packet1, NULL, gcsKeys.deviceEncKeyPair.pk);
        t.stop();
        pc.printf("Encryption of symmetric key took %f seconds\n", t.read());
        t.reset();
        wait(1.0);

        t.start();
        hydro_kx_n_2(&gcsKeys.symetricKeyPair, packet1, NULL, &gcsKeys.deviceEncKeyPair);
        t.stop();
        pc.printf("Decryption of symmetric key took %f seconds\n", t.read());
        t.reset();
        wait(1.0);

        uint8_t ciphertext[ENCRYPTED_MAVLINK_LENGHT_MAX];
        char decrypted[MAVLINK_LENGHT_MAX];

        t.start();
        hydro_secretbox_encrypt(ciphertext, MESSAGE, MAVLINK_LENGHT_MAX, 0, CONTEXTENCR, drone1Keys.symetricKeyPair.tx);
        t.stop();
        pc.printf("Message encryption took %f seconds\n", t.read());
        t.reset();
        wait(1.0);

        t.start();
        hydro_secretbox_decrypt(decrypted, ciphertext, ENCRYPTED_MAVLINK_LENGHT_MAX, 0, CONTEXTENCR, gcsKeys.symetricKeyPair.rx);
        t.stop();
        pc.printf("Massage decryption took %f seconds\n", t.read());
        t.reset();
        wait(1.0);
    }
	getchar();
    return 0;

	

}


bool verifyCertificate(certificate *cert, uint8_t *pk) {
	if (hydro_sign_verify(cert->sign, cert->hash, sizeof(uint8_t) * hydro_hash_BYTES, CONTEXTSIGN, pk) != 0) {
		return 0;
	}else {
		return 1;
	}
}

void signCertificate(certificate *cert, uint8_t *sk) {
	hydro_sign_create(cert->sign, cert->hash, sizeof(uint8_t) * hydro_hash_BYTES, CONTEXTSIGN, sk);
}

void hashCertificate(certificate *cert) {

	
	hydro_hash_state state;

	hydro_hash_init(&state, CONTEXTHASH, NULL);

	hydro_hash_update(&state, cert->name, sizeof(cert->name));
	hydro_hash_update(&state, cert->maintainer, sizeof(cert->maintainer));
	hydro_hash_update(&state, &cert->privilages, sizeof(cert->privilages));
	hydro_hash_update(&state, &cert->pubK, sizeof(cert->pubK));

	hydro_hash_final(&state, cert->hash, sizeof cert->hash);
}


void generateKey(uint8_t *key) {
	hydro_random_buf(key, sizeof key);
}
