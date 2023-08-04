#include <cstdio>
#include <cstdlib>
#include <memory.h>
#include <chrono>
#include <thread>

#define SM3_HASH_SIZE 32

struct SM3Context
{
    unsigned int intermediateHash[SM3_HASH_SIZE / 4];
    unsigned char messageBlock[64];
};

static const int endianTest = 1;
#define IsLittleEndian() (*(char *)&endianTest == 1)

#define LeftRotate(word, bits) ((word) << (bits) | (word) >> (32 - (bits)))

unsigned int *ReverseWord(unsigned int *word)
{
    unsigned char *byte, temp;

    byte = (unsigned char *)word;
    temp = byte[0];
    byte[0] = byte[3];
    byte[3] = temp;

    temp = byte[1];
    byte[1] = byte[2];
    byte[2] = temp;
    return word;
}

unsigned int T(int i)
{
    if (i >= 0 && i <= 15)
        return 0x79CC4519;
    else if (i >= 16 && i <= 63)
        return 0x7A879D8A;
    else
        return 0;
}

unsigned int FF(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
    if (i >= 0 && i <= 15)
        return X ^ Y ^ Z;
    else if (i >= 16 && i <= 63)
        return (X & Y) | (X & Z) | (Y & Z);
    else
        return 0;
}

unsigned int GG(unsigned int X, unsigned int Y, unsigned int Z, int i)
{
    if (i >= 0 && i <= 15)
        return X ^ Y ^ Z;
    else if (i >= 16 && i <= 63)
        return (X & Y) | (~X & Z);
    else
        return 0;
}

unsigned int P0(unsigned int X)
{
    return X ^ LeftRotate(X, 9) ^ LeftRotate(X, 17);
}

unsigned int P1(unsigned int X)
{
    return X ^ LeftRotate(X, 15) ^ LeftRotate(X, 23);
}

void SM3Init(SM3Context *context)
{
    context->intermediateHash[0] = 0x7380166F;
    context->intermediateHash[1] = 0x4914B2B9;
    context->intermediateHash[2] = 0x172442D7;
    context->intermediateHash[3] = 0xDA8A0600;
    context->intermediateHash[4] = 0xA96F30BC;
    context->intermediateHash[5] = 0x163138AA;
    context->intermediateHash[6] = 0xE38DEE4D;
    context->intermediateHash[7] = 0xB0FB0E4E;
}

void SM3ProcessMessageBlock(SM3Context *context)
{
    int i;
    unsigned int W[68];
    unsigned int W_[64];
    unsigned int A, B, C, D, E, F, G, H, SS1, SS2, TT1, TT2;

    for (i = 0; i < 16; i++)
    {
        W[i] = *(unsigned int *)(context->messageBlock + i * 4);
        if (IsLittleEndian())
            ReverseWord(W + i);
    }
    for (i = 16; i < 68; i++)
    {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ LeftRotate(W[i - 3], 15)) ^ LeftRotate(W[i - 13], 7) ^ W[i - 6];
    }
    for (i = 0; i < 64; i++)
    {
        W_[i] = W[i] ^ W[i + 4];
    }

    A = context->intermediateHash[0];
    B = context->intermediateHash[1];
    C = context->intermediateHash[2];
    D = context->intermediateHash[3];
    E = context->intermediateHash[4];
    F = context->intermediateHash[5];
    G = context->intermediateHash[6];
    H = context->intermediateHash[7];
    for (i = 0; i < 64; i++)
    {
        SS1 = LeftRotate((LeftRotate(A, 12) + E + LeftRotate(T(i), i)), 7);
        SS2 = SS1 ^ LeftRotate(A, 12);
        TT1 = FF(A, B, C, i) + D + SS2 + W_[i];
        TT2 = GG(E, F, G, i) + H + SS1 + W[i];
        D = C;
        C = LeftRotate(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = LeftRotate(F, 19);
        F = E;
        E = P0(TT2);
    }
    context->intermediateHash[0] ^= A;
    context->intermediateHash[1] ^= B;
    context->intermediateHash[2] ^= C;
    context->intermediateHash[3] ^= D;
    context->intermediateHash[4] ^= E;
    context->intermediateHash[5] ^= F;
    context->intermediateHash[6] ^= G;
    context->intermediateHash[7] ^= H;
}

unsigned char *SM3_hash(const unsigned char *message,
                        unsigned int messageLen, unsigned char digest[SM3_HASH_SIZE])
{
    SM3Context context;
    unsigned int i, remainder, bitLen;

    SM3Init(&context);

    for (i = 0; i < messageLen / 64; i++)
    {
        memcpy(context.messageBlock, message + i * 64, 64);
        SM3ProcessMessageBlock(&context);
    }

    bitLen = messageLen * 8;
    if (IsLittleEndian())
        ReverseWord(&bitLen);
    remainder = messageLen % 64;
    memcpy(context.messageBlock, message + i * 64, remainder);
    context.messageBlock[remainder] = 0x80;
    if (remainder <= 55)
    {
        memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1 - 8 + 4);
        memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
        SM3ProcessMessageBlock(&context);
    }
    else
    {
        memset(context.messageBlock + remainder + 1, 0, 64 - remainder - 1);
        SM3ProcessMessageBlock(&context);
        memset(context.messageBlock, 0, 64 - 4);
        memcpy(context.messageBlock + 64 - 4, &bitLen, 4);
        SM3ProcessMessageBlock(&context);
    }

    if (IsLittleEndian())
        for (i = 0; i < 8; i++)
            ReverseWord(context.intermediateHash + i);
    memcpy(digest, context.intermediateHash, SM3_HASH_SIZE);

    return digest;
}

int main(int argc, char *argv[])
{
    unsigned char input[256] = "0000000000000000000000000000000000000000000000000000000000000001";

    int length = 64;
    unsigned char output[32];

    auto start = std::chrono::high_resolution_clock::now();
    std::thread threads[16];
    for (int i = 0; i < 16; i++)
    {
        threads[i] = std::thread([input, length, &output]()
                                 {
            for (int j = 0; j < 10000 / 16; j++) {
                SM3_hash(input, length, output);
            } });
    }
    for (auto &thread : threads)
        thread.join();
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    printf("Elapsed time: %f s\n", elapsed.count());
    return 0;
}
