//
//  PQCgenKAT_sign.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <oqs/rand.h>

#include "../sign.h"
#include "../sign_params.h"

#define MAX_MARKER_LEN      50

#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int FindMarker(FILE *infile, const char *marker);
int ReadHex(FILE *infile, unsigned char *a, int Length, char *str);
void    fprintBstr(FILE *fp, char *s, unsigned char *a, unsigned long long l);

int
main() {
	char                fn_req[128], fn_rsp[128];
	FILE                *fp_req, *fp_rsp;
	uint8_t             seed[48];
	uint8_t             msg[3300];
	uint8_t             entropy_input[48];
	uint8_t             *m, *sm, *m1;
	unsigned long long  mlen, smlen, max, remain, mlen1;
	int                 count;
	int                 done;
	uint8_t             pk[CRYPTO_PUBLICKEYBYTES] = {0}, sk[CRYPTO_SECRETKEYBYTES] = {0};
	int                 ret_val;

	// Create the REQUEST file
	sprintf(fn_req, "%.48s.req", CRYPTO_ALGNAME);
	sprintf(fn_rsp, "%.48s.rsp", CRYPTO_ALGNAME);
	
	// Remove the "/" in filename
	for (unsigned i = 0; i < strlen(CRYPTO_ALGNAME); i++)
	{
		if (fn_req[i] == 47)
		{
			fn_req[i] = 45;
			fn_rsp[i] = 45;
		}
	}

	if ( (fp_req = fopen(fn_req, "w")) == NULL ) {
		printf("Couldn't open <%s> for write\n", fn_req);
		return KAT_FILE_OPEN_ERROR;
	}
	if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
		printf("Couldn't open <%s> for write\n", fn_rsp);
		return KAT_FILE_OPEN_ERROR;
	}

	for (int i = 0; i < 48; i++) {
		entropy_input[i] = i;
	}

	/* Using AES as random generator */
    if (OQS_randombytes_switch_algorithm("NIST-KAT") != OQS_SUCCESS)
    {
        return KAT_CRYPTO_FAILURE;
    }

    /* Initialize NIST KAT seed by value in `buf` */
    OQS_randombytes_nist_kat_init_256bit(entropy_input, NULL);

	// Generate the public/private keypair
	if ( (ret_val = crypto_sign_keypair(pk, sk)) != 0) {
		printf("crypto_sign_keypair returned <%d>\n", ret_val);
		return KAT_CRYPTO_FAILURE;
	}
	fprintf(fp_req, "# %s\n\n", CRYPTO_ALGNAME);
	fprintBstr(fp_req, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
	fprintBstr(fp_req, "sk = ", sk, CRYPTO_SECRETKEYBYTES);
	fprintf(fp_req, "\n\n");

	for (int i = 0; i < 48; i++) {
		entropy_input[i] = i + 10;
	}

	// Init again to make sure the seed is consistent
	OQS_randombytes_nist_kat_init_256bit(entropy_input, NULL);
	for (int i = 0; i < 10; i++) {
		fprintf(fp_req, "count = %d\n", i);
		OQS_randombytes(seed, 48);
		// Make sure to msg is the first thing we read from randombytes
		OQS_randombytes_nist_kat_init_256bit(seed, NULL);
		fprintBstr(fp_req, "seed = ", seed, 48);
		mlen = 33 * (i + 1);
		fprintf(fp_req, "mlen = %llu\n", mlen);
		OQS_randombytes(msg, mlen);
		fprintBstr(fp_req, "msg = ", msg, mlen);
		fprintf(fp_req, "smlen =\n");
		fprintf(fp_req, "sm =\n");
		fprintf(fp_req, "remain =\n");
		fprintf(fp_req, "max =\n");
		fprintf(fp_req, "sklen =\n");
		fprintf(fp_req, "sk =\n\n\n");
	}
	fclose(fp_req);

	//Create the RESPONSE file based on what's in the REQUEST file
	if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
		printf("Couldn't open <%s> for read\n", fn_req);
		return KAT_FILE_OPEN_ERROR;
	}

	fprintf(fp_rsp, "# %s\n\n", CRYPTO_ALGNAME);

	// Grab the pk and sk input
	if (!ReadHex(fp_req, pk, CRYPTO_PUBLICKEYBYTES, "pk = ")) {
		printf("ERROR: unable to read 'pk' from <%s>\n", fn_req);
		return KAT_DATA_ERROR;
	}
	if (!ReadHex(fp_req, sk, CRYPTO_SECRETKEYBYTES, "sk = ")) {
		printf("ERROR: unable to read 'sk' from <%s>\n", fn_req);
		return KAT_DATA_ERROR;
	}

	// Write pk and sk down to output
	fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
	fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);
	fprintf(fp_rsp, "\n\n");

	done = 0;
	do {
		if ( FindMarker(fp_req, "count = ") ) {
			ret_val = fscanf(fp_req, "%d", &count);
		} else {
			done = 1;
			break;
		}
		fprintf(fp_rsp, "count = %d\n", count);

		if ( !ReadHex(fp_req, seed, 48, "seed = ") ) {
			printf("ERROR: unable to read 'seed' from <%s>\n", fn_req);
			return KAT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "seed = ", seed, 48);

		OQS_randombytes_nist_kat_init_256bit(seed, NULL);

		if ( FindMarker(fp_req, "mlen = ") ) {
			ret_val = fscanf(fp_req, "%llu", &mlen);
		} else {
			printf("ERROR: unable to read 'mlen' from <%s>\n", fn_req);
			return KAT_DATA_ERROR;
		}
		fprintf(fp_rsp, "mlen = %llu\n", mlen);

		m = (uint8_t *)calloc(mlen, sizeof(uint8_t));
		m1 = (uint8_t *)calloc(CRYPTO_BYTES + mlen, sizeof(uint8_t));
		sm = (uint8_t *)calloc(CRYPTO_BYTES + mlen, sizeof(uint8_t));

		if ( !ReadHex(fp_req, m, (int)mlen, "msg = ") ) {
			printf("ERROR: unable to read 'msg' from <%s>\n", fn_req);
			return KAT_DATA_ERROR;
		}
		fprintBstr(fp_rsp, "msg = ", m, mlen);

		if ( (ret_val = crypto_sign(sm, &smlen, m, mlen, sk)) != 0) {
			printf("crypto_sign returned <%d>\n", ret_val);
			return KAT_CRYPTO_FAILURE;
		}
		fprintf(fp_rsp, "smlen = %llu\n", smlen);
		fprintBstr(fp_rsp, "sm = ", sm, smlen);

		if ( (ret_val = crypto_sign_open(m1, &mlen1, sm, smlen, pk)) != 0) {
			printf("crypto_sign_open returned <%d>\n", ret_val);
			return KAT_CRYPTO_FAILURE;
		}

		if (mlen1 != mlen)
		{
			printf("Incorrect message length\n");
			return KAT_CRYPTO_FAILURE;
		}
		if (memcmp(m, m1, mlen))
		{
			fprintf(fp_rsp, "mlen1 = %llu\n", mlen1);
			fprintBstr(fp_rsp, "m1 = ", m1, mlen1);
			printf("Incorrect message content\n");
			return KAT_CRYPTO_FAILURE;
		}

		if ( (ret_val = crypto_remaining_signatures(&remain, sk)) != 0) {
			printf("crypto_remaining_signatures returned <%d>\n", ret_val);
			return KAT_CRYPTO_FAILURE;
		}

		fprintf(fp_rsp, "remain = %llu\n", remain);

		if ( (ret_val = crypto_total_signatures(&max, sk)) != 0) {
			printf("crypto_total_signatures returned <%d>\n", ret_val);
			return KAT_CRYPTO_FAILURE;
		}

		fprintf(fp_rsp, "max = %llu\n", max);

		if (max - remain != (unsigned long long) count + 1) {
			printf("secret key update failed\n");
			return KAT_CRYPTO_FAILURE;
		}

		// fprintf(fp_rsp, "sklen = %u\n", CRYPTO_SECRETKEYBYTES);
		// fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);
		fprintf(fp_rsp, "\n\n");

		free(m);
		free(sm);

	} while ( !done );

	fclose(fp_req);
	fclose(fp_rsp);

	return KAT_SUCCESS;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
FindMarker(FILE *infile, const char *marker) {
	char    line[MAX_MARKER_LEN];
	int i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN - 1 ) {
		len = MAX_MARKER_LEN - 1;
	}

	for ( i = 0; i < len; i++ ) {
		curr_line = fgetc(infile);
		line[i] = curr_line;
		if (curr_line == EOF ) {
			return 0;
		}
	}
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) ) {
			return 1;
		}

		for ( i = 0; i < len - 1; i++ ) {
			line[i] = line[i + 1];
		}
		curr_line = fgetc(infile);
		line[len - 1] = curr_line;
		if (curr_line == EOF ) {
			return 0;
		}
		line[len] = '\0';
	}

	// shouldn't get here
	return 0;
}

//
// ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
//
int
ReadHex(FILE *infile, unsigned char *a, int Length, char *str) {
	int     i, ch, started;
	unsigned char   ich;

	if ( Length == 0 ) {
		a[0] = 0x00;
		return 1;
	}
	memset(a, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' ) {
						break;
					} else {
						continue;
					}
				} else {
					break;
				}
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') ) {
				ich = ch - '0';
			} else if ( (ch >= 'A') && (ch <= 'F') ) {
				ich = ch - 'A' + 10;
			} else if ( (ch >= 'a') && (ch <= 'f') ) {
				ich = ch - 'a' + 10;
			} else { // shouldn't ever get here
				ich = 0;
			}

			for ( i = 0; i < Length - 1; i++ ) {
				a[i] = (a[i] << 4) | (a[i + 1] >> 4);
			}
			a[Length - 1] = (a[Length - 1] << 4) | ich;
		} else {
		return 0;
	}

	return 1;
}

void
fprintBstr(FILE *fp, char *s, unsigned char *a, unsigned long long l) {
	unsigned long long  i;

	fprintf(fp, "%s", s);

	for ( i = 0; i < l; i++ ) {
		fprintf(fp, "%02X", a[i]);
	}

	if ( l == 0 ) {
		fprintf(fp, "00");
	}

	fprintf(fp, "\n");
}


