// crypto.cpp : example console application to test libhydrogen library and to create first prototype of encryted comm of mavlink devices
// Made by Roman Ligocki
// Used library: libhydrogen

#include "stdafx.h"
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

	//Storage of keys for every device.
	keyStorage drone1Keys;
	keyStorage drone2Keys;
	keyStorage drone3Keys;
	keyStorage gcsKeys;

	//Key generation for every device 
	hydro_kx_keygen(&drone1Keys.deviceEncKeyPair);
	hydro_sign_keygen(&drone1Keys.deviceSignKeyPair);

	hydro_kx_keygen(&drone2Keys.deviceEncKeyPair);
	hydro_sign_keygen(&drone2Keys.deviceSignKeyPair);

	hydro_kx_keygen(&drone3Keys.deviceEncKeyPair);
	hydro_sign_keygen(&drone3Keys.deviceSignKeyPair);

	hydro_kx_keygen(&gcsKeys.deviceEncKeyPair);
	hydro_sign_keygen(&gcsKeys.deviceSignKeyPair);

	//Copy singing public key from GCS (authority) to device (verifier). In production it will be possible only over USB from QGC (Critical for security !!!!). 
	memcpy(&drone1Keys.authoritySignKeyPair.pk, &gcsKeys.deviceSignKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);
	memcpy(&drone2Keys.authoritySignKeyPair.pk, &gcsKeys.deviceSignKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

	//Creation of certificates. In production it will be possible only over USB from QGC (Critical for security !!!!)
	strcmp("Tarot 650", drone1Keys.cert.name);
	strcmp("Roman Ligocki", drone1Keys.cert.maintainer);
	drone1Keys.cert.privilages = 5;
	memcpy(drone1Keys.cert.pubK, drone1Keys.deviceEncKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

	strcmp("Tarot 680", drone1Keys.cert.name);
	strcmp("Adam Ligocki", drone1Keys.cert.maintainer);
	drone2Keys.cert.privilages = 2;
	memcpy(drone2Keys.cert.pubK, drone2Keys.deviceEncKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

	strcmp("Random VTOL plane", drone1Keys.cert.name);
	strcmp("Matej Malinowski", drone1Keys.cert.maintainer);
	drone2Keys.cert.privilages = 1;
	memcpy(drone2Keys.cert.pubK, drone2Keys.deviceEncKeyPair.pk, sizeof(uint8_t) * hydro_kx_PUBLICKEYBYTES);

	//From all data we need to create hash, that will be signed in next step by GCSs secret signing key. 
	hashCertificate(&drone1Keys.cert);
	hashCertificate(&drone2Keys.cert);

	//Signing of certificate
	signCertificate(&drone1Keys.cert, gcsKeys.deviceSignKeyPair.sk);


	//////////////
	//Verification
	/////////////
	/*
	Verification Example 1: 
		Drone1 gives certificate with his public key to drone2 over unsecured channel. Sign is valid.
		When sign is valid, you can encrypt randomly generate symetric key and send it over unsecured channel
	*/
	if (verifyCertificate(&drone1Keys.cert, drone2Keys.authoritySignKeyPair.pk)) {
		printf("%s", "Drone1: Its OK, I will trust your public key\n");
	}else {
		printf("%s", "Drone1: Hey !! You are scam !!!!\n");
	}	

	/*
	Verification Example 2:
	Drone1 gives certificate signed with other key than GCSs to drone2 over unsecured channel. Sign is not valid 
	because it is "signed" drone3s secret key.
	*/
	signCertificate(&drone1Keys.cert, drone3Keys.deviceSignKeyPair.sk);

	if (verifyCertificate(&drone1Keys.cert, drone2Keys.authoritySignKeyPair.pk)) {
		printf("%s", "Drone1: Its OK, I will trust your public key\n");
	}
	else {
		printf("%s", "Drone1: Hey !! You are scam !!!!\n");
	}



	//////////////
	//Symetric key exchange
	/////////////
	/*
	Client side:
		client (drone1) wants to communicate with server (drone2), so using servers public key which is already verified 
		send packet1 which contains symetric key. This function saves also symetric keys to keyStorage of drone1. 
	*/
	uint8_t packet1[hydro_kx_N_PACKET1BYTES];

	if (hydro_kx_n_1(&drone1Keys.symetricKeyPair, packet1, NULL, drone2Keys.deviceEncKeyPair.pk) != 0) {
		// If something is wrong ... do something
	}

	/*
	Server side:
	server (drone2) receives packet1 with information about keys. This data must be decrypted using drone2s secret key
	Now both sides had exchange symetric keys. Now they can start symetric encryption.
	*/
	if (hydro_kx_n_2(&drone2Keys.symetricKeyPair, packet1, NULL, &drone2Keys.deviceEncKeyPair) != 0) {
		// If something is wrong ... do something
	}

	// Symetric encryption that does drone1
	uint8_t ciphertext[ENCRYPTED_MAVLINK_LENGHT_MAX];
	hydro_secretbox_encrypt(ciphertext, MESSAGE, MAVLINK_LENGHT_MAX, 0, CONTEXTENCR, drone1Keys.symetricKeyPair.tx);
	
	// Received ciphertext decryption
	char decrypted[MAVLINK_LENGHT_MAX];
	hydro_secretbox_decrypt(decrypted, ciphertext, ENCRYPTED_MAVLINK_LENGHT_MAX, 0, CONTEXTENCR, drone2Keys.symetricKeyPair.rx);
	printf("%s", decrypted);


	/*
	If you get here ... congratulation :D, but I have few questions ... 
		
	1.	What is an idea of privilages in mavlink ecosystem ????
		For now I implemented uint_8 value that could be used for role in mavlink ecosystem
		It is not possible to modify this value wihout GCS secret key which is used for signing certificate

	2.  Do you think that someone will need other authority except GCS? For example it could be second drone operator in one company
		Easies way is to copy asymmetric secret key from GCS1 to GCS2. For now I have no idea how to do it without copying secret key

	3.  How much flash and RAM storage is possible to get for encryption? Is libhydrogen suitable? 

	4.	I will be very grateful for any ideas or recommendation. Do you have something on mind? 
	*/

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
