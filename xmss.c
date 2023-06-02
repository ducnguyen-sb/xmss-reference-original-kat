#include <stdint.h>

#include "params.h"
#include "xmss_core.h"
#include "utils.h"

/* This file provides wrapper functions that take keys that include OIDs to
identify the parameter set to be used. After setting the parameters accordingly
it falls back to the regular XMSS core functions. */

int xmss_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid)
{
    xmss_params params;
    unsigned int i;

    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        /* For an implementation that uses runtime parameters, it is crucial
        that the OID is part of the secret key as well;
        i.e. not just for interoperability, but also for internal use. */
        sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }
    return xmss_core_keypair(&params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN);
}

int xmss_sign(unsigned char *sk,
              unsigned char *sm, unsigned long long *smlen,
              const unsigned char *m, unsigned long long mlen)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    return xmss_core_sign(&params, sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmss_sign_open(unsigned char *m, unsigned long long *mlen,
                   const unsigned char *sm, unsigned long long smlen,
                   const unsigned char *pk)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmss_parse_oid(&params, oid)) {
        return -1;
    }
    return xmss_core_sign_open(&params, m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}

/**
 * The function calculates the remaining number of signatures that can be generated using a given XMSS
 * private key.
 * 
 * @param remain a pointer to a uint64_t variable that will store the number of remaining signatures
 * that can be generated with the given secret key.
 * @param sk The `sk` parameter is a pointer to an array of unsigned characters representing the secret
 * key used in the XMSS signature scheme.
 * 
 * @return This function returns an integer value. If the function executes successfully, it returns 0.
 * If there is an error, it returns -1.
 */
int xmss_remaining_signatures(unsigned long long *remain, const unsigned  char *sk)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;
    unsigned long long idx, max; 

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }

    if (xmss_parse_oid(&params, oid)) {
        *remain = 0;
        return -1;
    }

    idx = bytes_to_ull(sk + XMSS_OID_LEN, params.index_bytes);
    max = ((1ULL << params.full_height) - 1);

    *remain = max - idx;

    return 0;
}

/**
 * The function calculates the maximum number of signatures that can be generated for a given XMSS private key.
 * 
 * @param max a pointer to an unsigned long long variable that will store the maximum number of
 * signatures that can be generated with the given XMSS private key.
 * @param sk The secret key used for XMSS signature scheme. It is a pointer to an array of unsigned
 * characters.
 * 
 * @return an integer value. If the XMSS OID cannot be parsed, it returns -1. Otherwise, it sets the
 * value of the variable pointed to by the "max" parameter to the maximum number of signatures that can
 * be generated with the given XMSS private key and returns 0.
 */
int xmss_total_signatures(unsigned long long *max, const unsigned  char *sk)
{
    xmss_params params;
    uint32_t oid = 0;

    for (unsigned i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }

    if (xmss_parse_oid(&params, oid)) {
        *max = 0;
        return -1;
    }

    *max = ((1ULL << params.full_height) - 1);

    return 0;
}

int xmssmt_keypair(unsigned char *pk, unsigned char *sk, const uint32_t oid)
{
    xmss_params params;
    unsigned int i;

    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    for (i = 0; i < XMSS_OID_LEN; i++) {
        pk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
        sk[XMSS_OID_LEN - i - 1] = (oid >> (8 * i)) & 0xFF;
    }
    return xmssmt_core_keypair(&params, pk + XMSS_OID_LEN, sk + XMSS_OID_LEN);
}

int xmssmt_sign(unsigned char *sk,
                unsigned char *sm, unsigned long long *smlen,
                const unsigned char *m, unsigned long long mlen)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    return xmssmt_core_sign(&params, sk + XMSS_OID_LEN, sm, smlen, m, mlen);
}

int xmssmt_sign_open(unsigned char *m, unsigned long long *mlen,
                     const unsigned char *sm, unsigned long long smlen,
                     const unsigned char *pk)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= pk[XMSS_OID_LEN - i - 1] << (i * 8);
    }
    if (xmssmt_parse_oid(&params, oid)) {
        return -1;
    }
    return xmssmt_core_sign_open(&params, m, mlen, sm, smlen, pk + XMSS_OID_LEN);
}

/**
 * The function calculates the remaining number of signatures that can be generated using a given
 * XMSSMT private key.
 * 
 * @param remain a pointer to an unsigned long long variable that will store the number of remaining
 * signatures that can be generated using the given secret key.
 * @param sk The `sk` parameter is a pointer to an array of unsigned characters representing the secret
 * key used in the XMSSMT signature scheme.
 * 
 * @return This function returns an integer value. If the function executes successfully, it returns 0.
 * If there is an error, it returns -1.
 */
int xmssmt_remaining_signatures(unsigned long long *remain, const unsigned  char *sk)
{
    xmss_params params;
    uint32_t oid = 0;
    unsigned int i;
    unsigned long long idx, max; 

    for (i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }

    if (xmssmt_parse_oid(&params, oid)) {
        *remain = 0;
        return -1;
    }

    idx = bytes_to_ull(sk + XMSS_OID_LEN, params.index_bytes);
    max = ((1ULL << params.full_height) - 1);

    *remain = max - idx;

    return 0;
}

/**
 * The function calculates the maximum number of signatures that can be generated for a given XMSSMT private key.
 * 
 * @param max a pointer to an unsigned long long variable that will store the maximum number of
 * signatures that can be generated with the given secret key.
 * @param sk The `sk` parameter is a pointer to an array of unsigned characters representing the secret
 * key used in the XMSS signature scheme.
 * 
 * @return an integer value. If the XMSS OID cannot be parsed, it returns -1. Otherwise, it returns 0.
 */
int xmssmt_total_signatures(unsigned long long *max, const unsigned  char *sk)
{
    xmss_params params;
    uint32_t oid = 0;

    for (unsigned i = 0; i < XMSS_OID_LEN; i++) {
        oid |= sk[XMSS_OID_LEN - i - 1] << (i * 8);
    }

    if (xmss_parse_oid(&params, oid)) {
        *max = 0;
        return -1;
    }

    *max = ((1ULL << params.full_height) - 1);

    return 0;
}