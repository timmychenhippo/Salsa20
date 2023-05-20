#include <iostream>
#include <cstdlib>
#include <bitset>
#include "salsa20.h"
#include <chrono>

#define MAVLINK_MSG_ID_TEST1 28
#define MAVLINK_MSG_ID_TEST2 137

typedef struct __mavlink_test1_t {
	uint64_t time;
	float test_1;
	float test_2;
	float test_3;
	float test_4;
	float test_5;

} mavlink_test1_t;

typedef struct __mavlink_test2_t {
	uint64_t time;
	double distance[16];
	uint8_t count;
} mavlink_test2_t;

mavlink_test1_t generate()
{
	mavlink_test1_t test;
	test.time = 500;
	test.test_1 = -10.5;
	test.test_2 = 11.5;
	test.test_3 = 12.5;
	test.test_4 = -13.5;
	test.test_5 = 14.5;
	return test;
}
mavlink_test2_t generate2()
{
	mavlink_test2_t test;
	test.time = 600;
	double y = -10.5;
	for (uint16_t i = 0; i < 16; i++)
	{
		test.distance[i] = (y + i);
	}
	test.count = 'T';
	return test;

}
void hex_print(uint8_t* pv, uint16_t len)
{
	uint8_t* p = pv;
	if (NULL == pv)
		printf("NULL");
	else
	{
		unsigned int i;
		for (i = 0; i < len; ++i)
			printf("%02x ", p[i]);


	}
	printf("\n\n");
}

int main()
{
	Salsa20 chacha;
	Salsa20 chacha2;
	mavlink_test1_t test1 = generate();
	mavlink_test2_t test2 = generate2();
	mavlink_test2_t test4;
	mavlink_test2_t* test3 = &test4;
	const char* packet = (const char*)&test2;
	for (int i = 0; i < 128; i++)
	{
		std::bitset<8> bits(packet[i]);
		std::cout << bits << std::endl;

	}
	std::cout << "...................................................." << std::endl;
	uint8_t encrypt[MAVLINK_MSG_ID_TEST2];
	uint8_t decrypt[MAVLINK_MSG_ID_TEST2];
	//chacha.initBlock();

	auto start = std::chrono::high_resolution_clock::now();

	chacha.encrypt(encrypt, (uint8_t*)packet, MAVLINK_MSG_ID_TEST2);
	chacha2.decrypt(decrypt, encrypt, MAVLINK_MSG_ID_TEST2);

	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> duration = end - start;
	double seconds = duration.count();

	for (int i = 0; i < MAVLINK_MSG_ID_TEST2; i++)
	{
		std::bitset<8> bits(encrypt[i]);
		std::cout << bits << std::endl;

	}
	std::cout << ".................................................." << std::endl;
	for (int i = 0; i < MAVLINK_MSG_ID_TEST2; i++)
	{
		std::bitset<8> bits(decrypt[i]);
		std::cout << bits << std::endl;

	}
	uint64_t payload64[255];
	char* payload = (char*)&payload64[0];
	hex_print((uint8_t*)packet, MAVLINK_MSG_ID_TEST2);
	hex_print(encrypt, MAVLINK_MSG_ID_TEST2);
	hex_print(decrypt, MAVLINK_MSG_ID_TEST2);

	for (int i = 0; i < MAVLINK_MSG_ID_TEST2; i++)
	{
		payload[i] = (char)decrypt[i];

	}

	memset(test3, 0, MAVLINK_MSG_ID_TEST2);
	memcpy(test3, (const char*)&payload64[0], MAVLINK_MSG_ID_TEST2);
	std::cout << "time:" << test4.time << std::endl;
	std::cout << "test1:" << test4.distance[0] << std::endl;
	std::cout << "test2:" << test4.distance[1] << std::endl;
	std::cout << "test3:" << test4.distance[3] << std::endl;
	std::cout << "test4:" << test4.distance[4] << std::endl;
	std::cout << "test5:" << test4.distance[15] << std::endl;
	std::cout << "cout:" << test4.count << std::endl;

	std::cout << "程式執行時間: " << seconds << " 秒" << std::endl;
	std::cout << "程式執行時間: " << std::fixed<< seconds << " 秒" << std::endl;
}