#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <openssl/sha.h>

// 定义Merkle树节点
struct MerkleNode
{
    std::string hash;
    MerkleNode *left;
    MerkleNode *right;

    MerkleNode(const std::string &hashValue) : hash(hashValue), left(nullptr), right(nullptr) {}
};

// 计算SHA-256哈希值
std::string calculateHash(const std::string &data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)data.c_str(), data.length(), hash);
    char hashHex[2 * SHA256_DIGEST_LENGTH + 1];
    hashHex[2 * SHA256_DIGEST_LENGTH] = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        sprintf(hashHex + (i * 2), "%02x", hash[i]);
    }
    return std::string(hashHex);
}

// 构建Merkle树
MerkleNode *buildMerkleTree(const std::vector<std::string> &dataBlocks)
{
    std::vector<MerkleNode *> nodes;

    // 构建叶节点
    for (const auto &block : dataBlocks)
    {
        MerkleNode *node = new MerkleNode(calculateHash(block));
        nodes.push_back(node);
    }

    // 构建Merkle树
    while (nodes.size() > 1)
    {
        std::vector<MerkleNode *> parents;
        for (size_t i = 0; i < nodes.size(); i += 2)
        {
            MerkleNode *left = nodes[i];
            MerkleNode *right = (i + 1 < nodes.size()) ? nodes[i + 1] : nullptr;
            std::string combinedHash = left->hash + ((right != nullptr) ? right->hash : "");
            MerkleNode *parent = new MerkleNode(calculateHash(combinedHash));
            parent->left = left;
            parent->right = right;
            parents.push_back(parent);
        }
        nodes = parents;
    }

    return nodes[0]; // 返回根节点
}

// 验证数据块是否在Merkle树中
bool verifyDataInMerkleTree(const std::string &dataBlock, const std::string &rootHash)
{
    MerkleNode *root = buildMerkleTree({dataBlock});
    return (root->hash == rootHash);
}

int main()
{
    std::vector<std::string> dataBlocks = {
        "Data Block 1",
        "Data Block 2",
        "Data Block 3",
        "Data Block 4"};

    // 构建Merkle树
    MerkleNode *root = buildMerkleTree(dataBlocks);

    // 输出根节点哈希值
    printf("Root Hash: %s\n", root->hash.c_str());

    // 验证数据块是否在Merkle树中
    std::string dataBlockToVerify = "Data Block 3";
    bool isDataValid = verifyDataInMerkleTree(dataBlockToVerify, root->hash);
    printf("Data Block 3 is %s\n", (isDataValid ? "valid." : "not valid."));

    system("pause");
    delete root->left;
    delete root->right;
    delete root;

    return 0;
}
