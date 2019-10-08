#include "Encrypt.h"

unsigned char g_key[16] = {0x86,0xC6,0x31,0x80,0xC2,0x80,0x6E,0xD1,0xF4,0x7B,0x85,0x9D,0xE5,0x01,0x21,0x5B};

Encrypt::Encrypt()
{
}


int Encrypt::SM4_Encrypt(char (&srcStr) [32], char (&dstStr) [64])
{
    unsigned char szInput[32] = {'\0'};
    unsigned char szOutput[64] = {'\0'};
    memcpy(szInput,srcStr,32);
    memset(dstStr, 0, 64);

    sm4_context ctx;
    sm4_setkey_enc(&ctx,g_key);
    sm4_crypt_ecb(&ctx,1,strlen(srcStr),szInput,szOutput);

    std::string strTemp = "";
    for (size_t len = 0; len < strlen((char*)szOutput) && len < 64; len++)
    {
        char strnum[10] = { '\0' };
        sprintf(strnum, "%02X", szOutput[len]);
        strTemp += strnum;
    }
    memcpy(dstStr, strTemp.c_str(), strTemp.length());

    return strlen(dstStr);
}

int Encrypt::SM4_Decrypt(char (&srcStr) [64], char (&dstStr) [32])
{
    unsigned char szInput[64] = {'\0'};
    unsigned char szOutput[32] = {'\0'};
    memset(dstStr, 0, 32);

    for (size_t i = 0; i < strlen(srcStr); i += 2)
    {
        std::string temp = "";
        temp += srcStr[i];
        temp += srcStr[i + 1];
        unsigned char m = StrHex2Byte_2(temp);
        szInput[i / 2] = m;
    }

    sm4_context ctx;
    sm4_setkey_dec(&ctx,g_key);
    sm4_crypt_ecb(&ctx,0,strlen(srcStr)/2,szInput,szOutput);

    memcpy(dstStr,szOutput,strlen(srcStr)/2);
    return strlen(dstStr);
}

int Encrypt::SM4_EncryptEx(char *srcStr, int srcLen, char *dstStr, int dstLen)
{
    char* str = new char[srcLen + 1];
    memset(str, 0, srcLen + 1);
    memcpy(str, srcStr, srcLen);

    memset(dstStr, 0, dstLen);

    std::string _str = str;
    std::string _dst = "";
    SM4_EncryptionString(_str, _dst);
    memcpy(dstStr, _dst.c_str(), _dst.length());
    delete[] str;
    return _dst.length();
}

int Encrypt::SM4_DecryptEx(char *srcStr, int srcLen, char *dstStr, int dstLen)
{
    char* str = new char[srcLen + 1];
    memset(str, 0, srcLen + 1);

    memcpy(str, srcStr, srcLen);

    memset(dstStr, 0, dstLen);

    std::string _str = str;
    std::string _dst = "";
    SM4_DecryptString(_str, _dst);
    memcpy(dstStr, _dst.c_str(), _dst.length());
    delete[] str;
    return _dst.length();
}

int Encrypt::SM4_EncryptionString(std::string& srcStr, std::string& dstStr)
{
    dstStr.clear();
    size_t len = srcStr.length();
    size_t outlen = (len + 15) / 16 * 16;
    unsigned char* szInput = new unsigned char[len + 1];
    unsigned char* szOutput = new unsigned char[outlen + 1];
    memset(szInput,'\0',len+1);
    memcpy(szInput,srcStr.data(),len);
    memset(szOutput,'\0',outlen+1);

    sm4_context ctx;
    sm4_setkey_enc(&ctx,g_key);
    sm4_crypt_ecb(&ctx,1,len,szInput,szOutput);
    for(int i = 0;i<outlen;i++)
    {
        char strnum[10] = {'\0'};
        sprintf(strnum,"%02X",szOutput[i]);
        dstStr += strnum;
    }
    delete[] szInput;
    delete[] szOutput;
    return dstStr.length();
}

int Encrypt::SM4_DecryptString(std::string& srcStrHex, std::string& dstStr)
{
    if(srcStrHex.length() % 2 != 0)
        return -1;
    dstStr.clear();
    size_t len = srcStrHex.length() / 2;

    unsigned char* szInput = new unsigned char[len + 1];
    unsigned char* szOutput = new unsigned char[len + 1];
    memset(szInput,'\0',len+1);
    memset(szOutput,'\0',len+1);
    for(int i = 0; i< srcStrHex.length(); i+=2)
    {
        std::string temp = srcStrHex.substr(i,2);
        unsigned char m = StrHex2Byte_2(temp);
        szInput[i/2] = m;
    }

    sm4_context ctx;
    sm4_setkey_dec(&ctx,g_key);
    sm4_crypt_ecb(&ctx,0,len,szInput,szOutput);
    dstStr = (char*)szOutput;
    delete[] szInput;
    delete[] szOutput;
    return dstStr.length();
}

unsigned char Encrypt::StrHex2Byte_2(std::string str)
{
    if(str.length() != 2)
        return 0;
    unsigned char temp = 0;
    for(auto iter = str.begin();iter != str.end();iter++)
    {
        if(*iter >= 'a' && *iter <= 'f')
        {
            *iter -= 87;
        }
        else if(*iter >= 'A' && *iter <= 'F')
        {
            *iter -= 55;
        }
        else if(*iter >= '0' && *iter <= '9')
        {
            *iter -= 48;
        }
        else
            return 0;
    }
    temp = str.at(0) * 16 + str.at(1);
    return temp;
}

