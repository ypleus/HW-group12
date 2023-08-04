#include <cstdio>
#include <vector>
#include <string>
#include <openssl/sha.h>
#include <chrono>

struct MerkleNode
{
    std::string hash;
    MerkleNode *left;
    MerkleNode *right;
    MerkleNode(std::string h, MerkleNode *l, MerkleNode *r) : hash(h), left(l), right(r) {}
};

class MerkleTree
{
private:
    MerkleNode *root;
    std::vector<std::string> leaves;

    std::string sha256(std::string input)
    {
        unsigned char output[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)input.c_str(), input.length(), output);
        std::string hex_output;
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        {
            char hex[3];
            sprintf(hex, "%02x", output[i]);
            hex_output += hex;
        }
        return hex_output;
    }

    MerkleNode *buildTree(std::vector<std::string> data)
    {
        if (data.empty())
            return nullptr;
        std::vector<MerkleNode *> nodes;
        for (auto &d : data)
        {
            std::string hash = sha256(d);
            MerkleNode *node = new MerkleNode(hash, nullptr, nullptr);
            nodes.push_back(node);
        }
        while (nodes.size() > 1)
        {
            std::vector<MerkleNode *> new_nodes;
            for (int i = 0; i < nodes.size(); i += 2)
            {
                MerkleNode *left = nodes[i];
                MerkleNode *right = (i + 1 < nodes.size()) ? nodes[i + 1] : left;
                std::string hash = sha256(left->hash + right->hash);
                MerkleNode *parent = new MerkleNode(hash, left, right);
                new_nodes.push_back(parent);
            }
            nodes = new_nodes;
        }
        return nodes[0];
    }

public:
    MerkleTree(std::vector<std::string> data)
    {
        leaves = data;
        root = buildTree(data);
    }

    std::string getRootHash()
    {
        if (root == nullptr)
            return "";
        return root->hash;
    }

    bool verify(std::string data)
    {
        std::string hash = sha256(data);
        for (auto &node : leaves)
        {
            if (node == data)
                return true;
        }
        return false;
    }

    void printTree()
    {
        if (root == nullptr)
        {
            printf("Empty tree.\n");
            return;
        }
        std::vector<MerkleNode *> nodes;
        nodes.push_back(root);
        int level = 0;
        while (!nodes.empty())
        {
            printf("Level %d:\n", level);
            std::vector<MerkleNode *> new_nodes;
            for (auto &node : nodes)
            {
                printf("%s\n", node->hash.c_str());
                if (node->left != nullptr)
                    new_nodes.push_back(node->left);
                if (node->right != nullptr && node->right != node->left)
                    new_nodes.push_back(node->right);
            }
            printf("\n");
            nodes = new_nodes;
            level++;
        }
    }
};

int main()
{
    std::vector<std::string> data_100k;

    for (int i = 1; i <= 100000; i++)
        data_100k.push_back(std::to_string(i));
    auto start_time = std::chrono::high_resolution_clock::now();
    MerkleTree tree(data_100k);
    auto end_time = std::chrono::high_resolution_clock::now();

    std::chrono::duration<double> duration = end_time - start_time;
    printf("It takes %f seconds to build the Merkle tree.\n", duration.count());

    // tree.printTree();

    printf("The root hash: %s\n", tree.getRootHash().c_str());
    printf("if 1 in tree: %d\n", tree.verify("1"));
    printf("if 100001 in tree: %d\n", tree.verify("100001"));

    system("pause");
    return 0;
}
