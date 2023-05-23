#include"salsa20.h"
// Generic left rotate.
#define leftRotate(a, bits) ((a << (bits)) | (a >> (32 - (bits))))

// Perform a Salsa quarter round operation.
#define quarterRound(a, b, c, d) (     \
    b^= leftRotate(a+d,7),  \
	c^= leftRotate(b+a,9),	\
	d^= leftRotate(c+b,13),	\
	a^= leftRotate(d+c,18))

static inline void clean(void* dest, size_t size){
    // Force the use of volatile so that we actually clear the memory.
    // Otherwise the compiler might optimise the entire contents of this
    // function away, which will not be secure.
    volatile uint8_t* d = (volatile uint8_t*)dest;
    while (size > 0) {
        *d++ = 0;
        --size;
    }
}

static inline void u32t8le(const uint32_t v, uint8_t p[4]) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static inline uint32_t u8t32le(const uint8_t p[4]) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}
Salsa20::Salsa20(uint8_t numRounds) :round(numRounds)
{
    memset(block, 0, 64);
    memset(stream, 0, 64); //uit32_t will be change uint8_t
                           //16 elements should be 64
                           //numRounds:20

}
Salsa20::~Salsa20()
{
    clean(block, 64);
    clean(stream, sizeof(uint32_t) * 16);
}
size_t Salsa20::KeySize() const
{
    // Default Key size is 256-bit(32-byte)
    return 32;
}
size_t Salsa20::IVSize() const
{
    // Default IV size is 64-bit(8-byte)
    return 8;
}
bool Salsa20::setKey(const Ktools* tools)
{
    static const uint8_t cons_str[] = "expand 32-byte k";
    if (tools->keySize == 32)
    {
        memcpy(block, cons_str, 4);                                 //save constant string for block(0~3) 4-byte 
        memcpy(block + 4, tools->key, (tools->keySize/2));          //save key for block(4~19) 16-byte
        memcpy(block+20, cons_str+4, 4);                            //save constant string for block(20~23) 4-byte
        memset(block + 24, 0, 16);                                  //set 0 at block(24~39) ; for later to save iv and counter  
        memcpy(block+40, cons_str+10, 4);                           //save constant string for block(40~43) 4-byte
        memcpy(block + 44, tools->key+16, (tools->keySize / 2));    //save key for block(44~61) 16-byte
        memcpy(block + 61, cons_str + 13, 4);                       //save constant string for block(61~63) 4-byte

        return true;
    }
    else
    {
        return false;
    }
}

bool Salsa20::setIV(const Ktools* tools)
{
    if (tools->ivSize == 8)
    {
        //memset(block + 48, 0, 4);    //set at setkey() fuction
        memcpy(block + 24, tools->iv, tools->ivSize);
        return true;
    }
    else
    {
        return false;
    }
}
bool Salsa20::setCounter(const Ktools* tool)
{
    uint8_t counter[4];
    u32t8le(tool->counter, counter);   //default 0
    if (tool->counterSize == 8)
    {
        //Little - Endian
        memcpy(block + 32, counter, (tool->counterSize / 2));
        memset(block + 36, 0, (tool->counterSize / 2));
        return true;
    }
    else {
        return false;
    }
}
bool Salsa20::initBlock()
{
    return setKey(&(tool)) && setIV(&(tool)) && setCounter(&(tool));
}
void Salsa20::encrypt(uint8_t* output, const uint8_t* input, uint8_t len)
{
    if (!initBlock())
    {
        return;
    }
    for (uint8_t i = 0; i < len; i += 64)
    {
        hashCore(stream, block);
        uint8_t stream8[64];
        memcpy(stream8, stream, 64);
        uint16_t temp = 1;
        uint8_t index = 32;
        while (index < 40)       //couter 4-byte at block(32~39)
        {
            temp += block[index];
            block[index] = (uint8_t)temp;
            temp >>= 8;
            ++index;
        }
        for (uint8_t posn = i; posn < i + 64; posn++)
        {
            if (posn >= len)
            {
                break;
            }
            output[posn] = input[posn] ^ stream8[posn - i];
        }
    }

}

void Salsa20::hashCore(uint32_t* output, uint8_t* input)
{
    uint8_t posn;
    uint32_t input32[16];
    // Copy the input buffer to the output prior to the first round
    // and convert from little-endian to host byte order.
    memcpy(output, input, sizeof(uint32_t) * 16);
    memcpy(input32, input, sizeof(uint32_t) * 16);
    // Perform the ChaCha rounds in sets of two.
    for (uint8_t numround = numRounds(); numround >= 2; numround -= 2) {

        // Column round.
        quarterRound(output[0], output[4], output[8], output[12]);
        quarterRound(output[5], output[9], output[13], output[1]);
        quarterRound(output[10], output[14], output[2], output[6]);
        quarterRound(output[15], output[3], output[7], output[11]);

        // Diagonal round.
        quarterRound(output[0], output[1], output[2], output[3]);
        quarterRound(output[5], output[6], output[7], output[4]);
        quarterRound(output[10], output[11], output[8], output[9]);
        quarterRound(output[15], output[12], output[13], output[14]);
    }

    // Add the original input to the final output, convert back to
    // little-endian, and return the result.
    for (posn = 0; posn < 16; ++posn)
    {
        output[posn] = (output[posn] + input32[posn]);
    }
}
void Salsa20::decrypt(uint8_t* output, const uint8_t* input, uint8_t len)
{
    encrypt(output, input, len);
}