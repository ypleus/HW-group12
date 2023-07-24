#include <openssl/evp.h>
#include <string>
#include <array>
#include <vector>
#include <memory>
#include <cstdio>
#include <cstdint>

// 定义一个长度扩展攻击的函数
std::array<std::byte, 32> attack(std::array<std::byte, 32> H, int L, std::string X)
{
    // 计算填充的内容P，使得M||P||X的长度是512的倍数
    int pad_len = (448 - (L * 8 + 1)) % 512;
    std::vector<std::byte> P(64);
    P[0] = std::byte{0x80};
    std::fill(P.begin() + 1, P.begin() + pad_len / 8 + 1, std::byte{0});
    *reinterpret_cast<std::uint64_t *>(P.data() + pad_len / 8 + 1) = L * 8;

    // 创建一个EVP_MD_CTX对象，并用EVP_DigestInit_ex()函数初始化它，传入EVP_sm3()函数作为参数
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_DigestInit_ex(ctx.get(), EVP_sm3(), NULL);

    // 更新哈希值，把M||P作为输入消息
    EVP_DigestUpdate(ctx.get(), P.data(), pad_len / 8 + 9);

    // 复制一个EVP_MD_CTX对象，保留当前的状态
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx2(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    EVP_MD_CTX_copy_ex(ctx2.get(), ctx.get());

    // 输出最终的哈希值，这就是H(M||P)的值
    std::array<std::byte, 32> HMP;
    EVP_DigestFinal_ex(ctx2.get(), reinterpret_cast<unsigned char *>(HMP.data()), NULL);

    // 初始化另一个EVP_MD_CTX对象，并用H(M||P)作为初始向量
    EVP_DigestInit_ex(ctx.get(), EVP_sm3(), NULL);
    EVP_MD_CTX_ctrl(ctx.get(), EVP_CTRL_SET_SM3_INITIAL_VECTOR, 32, HMP.data());

    // 更新哈希值，把X作为输入消息
    EVP_DigestUpdate(ctx.get(), X.data(), X.size());

    // 输出最终的哈希值，这就是H(M||X)的值
    std::array<std::byte, 32> HMX;
    EVP_DigestFinal_ex(ctx.get(), reinterpret_cast<unsigned char *>(HMX.data()), NULL);

    // 返回结果
    return HMX;
}

int main()
{
    // 定义一个字符串作为起始的消息
    std::string M = "The quick brown fox jumps over the lazy dog";

    // 把这个字符串转换成array<byte>
    std::array<std::byte, 32> H;
    for (int i = 0; i < M.size(); i++)
    {
        H[i] = static_cast<std::byte>(M[i]);
    }

    // 获取他的长度
    int L = M.size();

    // 定义一个字符串作为要附加的消息
    std::string X = "&waffle=liege";

    // 调用攻击函数并得到最后的结果
    std::array<std::byte, 32> HMX = attack(H, L, X);

    // 打印结果
    printf("H(M||X) = ");
    for (auto b : HMX)
    {
        printf("%02x", static_cast<unsigned char>(b));
    }
    printf("\n");
}
