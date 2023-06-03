/*
This code was taken from the SPHINCS reference implementation and is public domain.
*/

#include <fcntl.h>
#include <unistd.h>
#include <oqs/rand.h>

void randombytes(unsigned char *x, unsigned long long xlen)
{
    OQS_randombytes(x, xlen);
}
