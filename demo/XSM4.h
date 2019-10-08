
/**
 * \file sm4.h
 */
#ifndef XYSSL_SM4_H
#define XYSSL_SM4_H

#define SM4_ENCRYPT     1
#define SM4_DECRYPT     0

/**
 * \brief          SM4 context structure
 */
typedef struct
{
    int mode;                   /*!<  encrypt/decrypt mode参数控制加密还是解密，其中mode=1为加密，mode=0为解密  */
    unsigned long sk[32];       /*!<  SM4 subkeys   数组sk为轮密钥。SM4为32轮加密变换。 */
}
sm4_context;


#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          SM4 key schedule (128-bit, encryption) 用来设置密钥的，这个函数内部会对当前传入的主密钥进行32轮的迭代，每次迭代的轮密钥都被存放到ctx结构中的sk数组中
 *
 * \param ctx      SM4 context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_enc( sm4_context *ctx, unsigned char key[16] );

/**
 * \brief          SM4 key schedule (128-bit, decryption)
 *
 * \param ctx      SM4 context to be initialized
 * \param key      16-byte secret key
 */
void sm4_setkey_dec( sm4_context *ctx, unsigned char key[16] );

/**
 * \brief  SM4-ECB block encryption/decryption 函数的作用是使用ECB模式（ECB（Electronic Codebook，电码本），ECB模式是分组密码的一种最基本的工作模式。根据length的长度来进行循环，每次循环都调用sm4_one_round进行加密或者解密，到底是加密还是解密，主要是根据第二个参数Mode来进行决定。
 * \param ctx      SM4 context
 * \param mode     SM4_ENCRYPT or SM4_DECRYPT
 * \param length   length of the input data
 * \param input    input block
 * \param output   output block
 */
void sm4_crypt_ecb( sm4_context *ctx,
                                     int mode,
                                         int length,
                     unsigned char *input,
                     unsigned char *output);

/**
 * \brief          SM4-CBC buffer encryption/decryption
 * \param ctx      SM4 context
 * \param mode     SM4_ENCRYPT or SM4_DECRYPT
 * \param length   length of the input data
 * \param iv       initialization vector (updated after use)
 * \param input    buffer holding the input data
 * \param output   buffer holding the output data
 */
void sm4_crypt_cbc( sm4_context *ctx,
                     int mode,
                     int length,
                     unsigned char iv[16],
                     unsigned char *input,
                     unsigned char *output );

#ifdef __cplusplus
}
#endif

#endif /* sm4.h */
