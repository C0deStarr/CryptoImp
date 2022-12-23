#include <common/common.h>

#if WORD_SIZE==4

#define BLOCK_SIZE 64   // 16 * WORD_SIZE

#endif

typedef struct _HashState {
    uint32_t hash[5];
    // BLOCK_SIZE == 16 * WORD_SIZE bytes
    // 64 bytes == 512 bits for SHA-256
    // 128 bytes == 1024 bits for SHA-512
    uint8_t block[BLOCK_SIZE];    
    uint8_t nBytesLen;        // byte offset of current block
    uint64_t nBitsLen;          // for msg padding
} HashState;

