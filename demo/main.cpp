#include <iostream>
#include "Encrypt.h"
using namespace std;

int main(int argc, char *argv[])
{
    char src[32] = "abcdefghijklmnopqrstuvwxyz!";
    char dst[64];
    int len = 0;
    len = Encrypt::SM4_Encrypt(src,dst);
    len = Encrypt::SM4_Decrypt(dst,src);
    return 0;
}
