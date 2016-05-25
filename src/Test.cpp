#pragma hdrstop
#include<istream>
#include <string.h>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <stdio.h>
#include <openssl/des.h>

#pragma argsused
#define BUFSIZE 256
#define CFBMODE 64
using namespace std;
class Des {
public:
	typedef vector<unsigned char> Bytes;
	static Bytes encrypt(Bytes in) {
		const unsigned char IV[] = { 48, 48, 48, 48, 48, 48, 48, 48 };
		const unsigned char key[] = { 51, 57, 101, 49, 50, 48, 51, 48, 45, 49,
				55, 49, 53, 45, 52, 97, 57, 101, 45, 57, 52, 49, 98, 45 };
		DES_key_schedule schedule;
		DES_key_schedule schedule2;
		DES_key_schedule schedule3;
		DES_cblock desKey = { 0 };
		DES_cblock iv = { 0 };

		memcpy(desKey, key, 8);
		DES_set_key_unchecked(&desKey, &schedule);
		memcpy(desKey, key + 8, 8);
		DES_set_key_unchecked(&desKey, &schedule2);
		memcpy(desKey, key + 16, 8);
		DES_set_key_unchecked(&desKey, &schedule3);
		copy(IV, IV + 8, iv);
		int i = 0;
		const size_t paddingLength = (8 - in.size() % 8);
		const Bytes padding(paddingLength, 8 - in.size() % 8);
		copy(padding.begin(), padding.end(), back_inserter(in));
		Bytes result(in.size());
		DES_ede3_cfb_encrypt(&in[0], &result[0], CFBMODE, in.size(), &schedule,
				&schedule2, &schedule3, &iv,
				DES_ENCRYPT);
		return result;
	}
	static Bytes decrypt(Bytes in) {
		//偏移向量
		const unsigned char IV[] = { 48, 48, 48, 48, 48, 48, 48, 48 };
		//24位加密key，3des下秘钥必须为24位
		const unsigned char key[] = { 51, 57, 101, 49, 50, 48, 51, 48, 45, 49,
				55, 49, 53, 45, 52, 97, 57, 101, 45, 57, 52, 49, 98, 45 };
		DES_key_schedule schedule;
		DES_key_schedule schedule2;
		DES_key_schedule schedule3;
		DES_cblock desKey = { 0 };
		DES_cblock iv = { 0 };
		memcpy(desKey, key, 8);
		DES_set_key_unchecked(&desKey, &schedule);
		memcpy(desKey, key + 8, 8);
		DES_set_key_unchecked(&desKey, &schedule2);
		memcpy(desKey, key + 16, 8);
		DES_set_key_unchecked(&desKey, &schedule3);
		copy(IV, IV + 8, iv);
		int i = 0;
		Bytes result(in.size());
		DES_ede3_cfb_encrypt(&in[0], &result[0], CFBMODE, in.size(), &schedule,
				&schedule2, &schedule3, &iv,
				DES_DECRYPT);
		int paddingLength = result.size() - result[result.size() - 1];
		Bytes padding(0);
		if (paddingLength > 0
				&& result[result.size() - 1] == result[paddingLength])
			copy(result.begin(), result.begin() + paddingLength,
					back_inserter(padding));
		else
			padding = result;
		return padding;
	}
};

int main() {
	string message = "111111111111";
	Des::Bytes in(message.begin(), message.end());
	Des::Bytes encr = Des::encrypt(in);
	Des::Bytes decr = Des::decrypt(encr);
//	size_t size = encr.size();
	for (Des::Bytes::const_iterator byte = decr.begin(); byte != decr.end();
			++byte) {
		printf("%02X ", *byte);
	}
	printf("\n");
	return 0;
}
