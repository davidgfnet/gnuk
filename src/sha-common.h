
#include <stdint.h>

extern const uint32_t sha_cpool[160];

#define k512(idx) ((uint64_t*)(sha_cpool))[idx]
// This assumes a little endian system, so that most significant word is located
// at the word offset 1.
#define k256(idx) sha_cpool[2*(idx)+1]


