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

#include "sign.h"
#include "sign_params.h"

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
	char                fn_rsp[128];
	FILE                *fp_rsp;
	uint8_t             seed[48];
	uint8_t             *m, *sm;
	uint8_t             *sm_kat;
	unsigned long long  mlen, smlen, max, remain;
	unsigned long long  smlen_kat, sklen_kat, max_kat, remain_kat;
	int                 count;
	int                 done;
	uint8_t             pk[CRYPTO_PUBLICKEYBYTES] = {0}, sk[CRYPTO_SECRETKEYBYTES] = {0}, sk_kat[CRYPTO_SECRETKEYBYTES] = {0};
	int                 ret_val;

	sprintf(fn_rsp, "%.32s.rsp", CRYPTO_ALGNAME);
	if ( (fp_rsp = fopen(fn_rsp, "r")) == NULL ) {
		printf("Couldn't open <%s> for read\n", fn_rsp);
		return KAT_FILE_OPEN_ERROR;
	}

	// Grab the pk and sk from rsp file
	if (!ReadHex(fp_rsp, pk, CRYPTO_PUBLICKEYBYTES, "pk = ")) {
		printf("ERROR: unable to read 'pk' from <%s>\n", fn_rsp);
		return KAT_DATA_ERROR;
	}
	if (!ReadHex(fp_rsp, sk, CRYPTO_SECRETKEYBYTES, "sk = ")) {
		printf("ERROR: unable to read 'sk' from <%s>\n", fn_rsp);
		return KAT_DATA_ERROR;
	}

	if (OQS_randombytes_switch_algorithm("NIST-KAT") != OQS_SUCCESS)
    {
        return OQS_ERROR;
    }

	done = 0;
	do {
		if ( FindMarker(fp_rsp, "count = ") ) {
			fscanf(fp_rsp, "%d", &count);
		} else {
			done = 1;
			break;
		}

		if ( !ReadHex(fp_rsp, seed, 48, "seed = ") ) {
			printf("ERROR: unable to read 'seed' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

		OQS_randombytes_nist_kat_init_256bit(seed, NULL);

		if ( FindMarker(fp_rsp, "mlen = ") ) {
			fscanf(fp_rsp, "%llu", &mlen);
		} else {
			printf("ERROR: unable to read 'mlen' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

		m = (uint8_t *)calloc(mlen, sizeof(uint8_t));
		sm = (uint8_t *)calloc(CRYPTO_BYTES, sizeof(uint8_t));
		sm_kat = (uint8_t *)calloc(CRYPTO_BYTES, sizeof(uint8_t));

		if ( !ReadHex(fp_rsp, m, (int)mlen, "msg = ") ) {
			printf("ERROR: unable to read 'msg' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

		if ( FindMarker(fp_rsp, "smlen = ") ) {
			fscanf(fp_rsp, "%llu", &smlen_kat);
		} else {
			printf("ERROR: unable to read 'smlen' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

        if (smlen_kat != CRYPTO_BYTES)
        {
            printf("Error: incorrect 'smlen' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

		if ( !ReadHex(fp_rsp, sm_kat, CRYPTO_BYTES, "sm = ") ) {
			printf("ERROR: unable to read 'sm' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

        // Test Sign: Sign and compare with `sm` in KAT
		if ( (ret_val = crypto_sign(sm, &smlen, m, mlen, sk)) != 0) {
			printf("crypto_sign returned <%d>\n", ret_val);
			return KAT_CRYPTO_FAILURE;
		}

		if (smlen != smlen_kat) {
            printf("ERROR: incorrect smlen or smlen_kat from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}
		if (memcmp(sm, sm_kat, smlen)) {
            printf("ERROR: incorrect signed message sm count<%d>\n from <%s>\n", count, fn_rsp);
			return KAT_CRYPTO_FAILURE;
		}

        // Test updated Secret Key: Compare with `sk` in KAT
        if ( FindMarker(fp_rsp, "sklen = ") ) {
			fscanf(fp_rsp, "%llu", &sklen_kat);
		} else {
			printf("ERROR: unable to read 'sklen' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

        if (sklen_kat != CRYPTO_SECRETKEYBYTES) {
            printf("Error: incorrect 'sklen' from <%s>\n", fn_rsp);
            return KAT_DATA_ERROR;
        }

		if ( !ReadHex(fp_rsp, sk_kat, CRYPTO_SECRETKEYBYTES, "sk = ") ) {
			printf("ERROR: unable to read 'sk' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

		if (memcmp(sk, sk_kat, CRYPTO_SECRETKEYBYTES)) {
            printf("ERROR: incorrect secret key sk count<%d>\n from <%s>\n", count, fn_rsp);
			return KAT_CRYPTO_FAILURE;
		}

		if ( (ret_val = crypto_sign_open(m, mlen, sm, smlen, pk)) != 0) {
			printf("crypto_sign_open returned <%d>\n", ret_val);
			return KAT_CRYPTO_FAILURE;
		}

        // Test remain and max signature to see if they match KAT
		if ( (ret_val = crypto_remaining_signatures(&remain, sk)) != 0) {
			printf("crypto_remaining_signatures returned <%d>\n", ret_val);
			return KAT_CRYPTO_FAILURE;
		}

		if ( (ret_val = crypto_total_signatures(&max, sk)) != 0) {
			printf("crypto_total_signatures returned <%d>\n", ret_val);
			return KAT_CRYPTO_FAILURE;
		}

		if ( FindMarker(fp_rsp, "remain = ") ) {
			fscanf(fp_rsp, "%llu", &remain_kat);
		} else {
			printf("ERROR: unable to read 'remain' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

		if ( FindMarker(fp_rsp, "max = ") ) {
			fscanf(fp_rsp, "%llu", &max_kat);
		} else {
			printf("ERROR: unable to read 'max' from <%s>\n", fn_rsp);
			return KAT_DATA_ERROR;
		}

		if (remain != remain_kat) {
            printf("Error: incorrect 'remain' from <%s>\n", fn_rsp);
			return KAT_CRYPTO_FAILURE;
		}

		if (max != max_kat) {
            printf("Error: incorrect 'max' from <%s>\n", fn_rsp);
			return KAT_CRYPTO_FAILURE;
		}

		if (max - remain != (unsigned long long) count + 1) {
			printf("secret key update failed\n");
			return KAT_CRYPTO_FAILURE;
		}

		free(m);
		free(sm);
        free(sm_kat);

	} while ( !done );

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


