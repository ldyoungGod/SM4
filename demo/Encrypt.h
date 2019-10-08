#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <string>
#include <string.h>
#include "XSM4.h"

class Encrypt
{
public:
    Encrypt();

    static int SM4_Encrypt(char (&srcStr) [32]/*字符串*/, char (&dstStr) [64]/*加密后的16进制字符串*/);
    static int SM4_Decrypt(char (&srcStr) [64]/*加密后的16进制字符串*/, char (&dstStr) [32]/*字符串*/);

    static int SM4_EncryptEx(char* srcStr, int srcLen, char* dstStr, int dstLen);
    static int SM4_DecryptEx(char* srcStr, int srcLen, char* dstStr, int dstLen);

    static int SM4_EncryptionString(std::string& srcStr, std::string& dstStr);
    static int SM4_DecryptString(std::string& srcStr, std::string& dstStr);

private:
    static unsigned char StrHex2Byte_2(std::string str);// 0A -> 10
};


#endif // ENCRYPT_H
