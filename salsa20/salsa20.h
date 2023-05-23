#pragma once
#ifndef CRYPTO_SALSA_H
#define CRYPTO_SALSA_H
#endif

#include <stdint.h>
#include <string.h>

static inline void clean(void* dest, size_t size);
static inline void u32t8le(uint32_t v, uint8_t p[4]);
static inline uint32_t u8t32le(uint8_t p[4]);

class Salsa20
{
private:
	uint8_t block[64]; //516-bit
	uint32_t stream[16]; //516-bit ; //Keys stream:(Key(256-bit)+IV(96-bit)+Counter(32-bit))& Algorithm 
	uint8_t round;

	/**
	* \Key:32-byte(256-bit)
	* \IV:12-byte(96-bit)
	* \counter:4-byte(32-bit)
	* \size(block size 64-byte(512-bit))
	* \Those value can be changed
	*/
	typedef struct __Key_tools
	{
		const uint8_t key[32] = { 0x29, 0x46, 0x42, 0x79, 0x24, 0x39, 0x76, 0x36,
							0x37, 0x73, 0x30, 0x59, 0x6B, 0x75, 0x67, 0x53,
							0x60, 0x64, 0x15, 0x6B, 0x2D, 0x47, 0x28, 0x44,
							0x3F, 0x41, 0x2F, 0x78, 0x38, 0x75, 0x35, 0x35 }; //must change
		const size_t keySize = 32;
		const uint8_t iv[8] = { 0x01, 0x40, 0x00, 0x00, 0x80, 0x00, 0x70, 0x4a }; //must change
		const size_t ivSize = 8;
		const uint32_t counter = 0;	  //defualt value 0 or 1
		const size_t counterSize = 8; //64-bit 
		const size_t Size = 64;

	}Ktools;
	const Ktools tool;

public:

	explicit Salsa20(uint8_t numRounds = 20);
	~Salsa20();
	size_t KeySize() const;
	size_t IVSize() const;

	uint8_t numRounds() const { return round; }

	bool setKey(const Ktools* tool);
	bool setIV(const Ktools* tool);
	bool setCounter(const Ktools* tool);
	bool initBlock();
	void encrypt(uint8_t* output, const uint8_t* input, uint8_t len);
	void hashCore(uint32_t* output, uint8_t* input);
	void decrypt(uint8_t* output, const uint8_t* input, uint8_t len);
};