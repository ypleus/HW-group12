#include <stdio.h>
#include <openssl/evp.h>
#include <iostream>
#include <string>

// 封装一个SM3类，使用RAII管理EVP_MD_CTX对象
class SM3
{
public:
    // 构造函数，创建EVP_MD_CTX对象，并初始化
    SM3()
    {
        ctx = EVP_MD_CTX_new();
        if (ctx == nullptr)
        {
            throw std::runtime_error("Failed to create EVP_MD_CTX");
        }
        if (EVP_DigestInit_ex(ctx, EVP_sm3(), nullptr) != 1)
        {
            throw std::runtime_error("Failed to initialize EVP_MD_CTX");
        }
    }

    // 析构函数，释放EVP_MD_CTX对象
    ~SM3()
    {
        EVP_MD_CTX_free(ctx);
    }

    // 更新函数，将数据输入到哈希上下文中
    void update(const std::string &data)
    {
        if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1)
        {
            throw std::runtime_error("Failed to update EVP_MD_CTX");
        }
    }

    // 结束函数，输出哈希值，并重置上下文
    std::string final()
    {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int md_len;
        if (EVP_DigestFinal_ex(ctx, md, &md_len) != 1)
        {
            throw std::runtime_error("Failed to final EVP_MD_CTX");
        }
        if (EVP_DigestInit_ex(ctx, EVP_sm3(), nullptr) != 1)
        {
            throw std::runtime_error("Failed to reset EVP_MD_CTX");
        }
        return std::string(reinterpret_cast<char *>(md), md_len);
    }

private:
    EVP_MD_CTX *ctx; // 哈希上下文对象
};

// 测试函数，计算一个字符串的SM3哈希值，并打印为十六进制
void test(const std::string &msg)
{
    SM3 sm3;
    sm3.update(msg);
    std::string digest = sm3.final();
    std::cout << "SM3(\"" << msg << "\") = ";
    printf("%s", digest.c_str());
    std::cout << "\n";
}

int main()
{
    test("abc");
    test("The quick brown fox jumps over the lazy dog");
    system("pause");
}
