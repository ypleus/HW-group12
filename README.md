# HW-group12
​		这是group12的作业实现, 本组在完成时只有我一个人, 故以下内容均由个人完成.

​		受个人能力与时间的限制, 在共计21个项目里完成了个, 分别是:
​		Project 1, 2, 3, 4, 5, 9.

​		以下内容将较为详细地介绍每个项目的实现情况, 而在具体文件夹中将不再重复实验报告.

​		以下内容如无特殊说明均为在笔记本的R7-5800H CPU上原生运行. 

                由于在Markdown文件中插入图片比较麻烦所以以下很少使用图片展示结果. 



## Project1: implement the naïve birthday attack of reduced SM3

​		该项目要求对简化版本的SM3实现简单生日攻击, 通过查阅相关论文得知有人实现了对于缩减轮数的SM3算法进行生日攻击, 然而此过程涉及到较为复杂的算法分析, 很难说与简单生日攻击的要求相符, 故这里认为是对Hash结果的部分碰撞, 即对于原始SM3算法只要能够找到两个不同的原像使得它们具有部分相同(如前n位)的Hash值就判定攻击成功, 基于此可以实现生日攻击.

​		首先是实现SM3算法, 这一部分较为简单, 只是对着给定的算法逻辑实现, 为了更加简单而不必进行复杂的内存处理, 这里使用了python语言. 

​		而在攻击部分, 首先实现了一个装饰器用以计时, 接着实现了一个随机数生成器和一个截断器用以截断要求的位数, 然后在给定的次数限制内尽可能对每个生成的随机数进行Hash, 并将结果存入字典中, 一旦发现碰撞则立即返回, 否则认为没有找到. 这是出于算力限制, 因为为了确保结果的相对准确性, 这里采用了计算5次取平均时间的操作, 尽管这样筛选可能会导致平均结果偏低, 但也是受于算力限制的不得已之举. 主体代码如下:

```python
@timer
def birthday_attack(bits):
    # 勘误: 这里的bits实为char, 指前n个字符相同, 即前4n个bit相同
    # 例如birthday_attack(4)指前16个bit相同
    global num_attempts
    hash_dict = {}
    for i in range(num_attempts):
        input_data = generate_random_input()
        hashed = sm3_hash(input_data)
        truncated_hash = truncate_hash(hashed, bits)
        if truncated_hash in hash_dict:
            collision_input = hash_dict[truncated_hash]
            print(f"输入1: {collision_input}\n输入2: {input_data}")
            print("hash1:", sm3_hash(collision_input))
            print("hash2:", sm3_hash(input_data))
            print("\n")
            return collision_input, input_data
        else:
            hash_dict[truncated_hash] = input_data
    print("未找到碰撞。")
    return None
```

最终得到的时间如下:

| 位数    | 8          | 16         | 24         | 32          |
| ------- | ---------- | ---------- | ---------- | ----------- |
| 时间(s) | 0.01829566 | 0.23345784 | 5.06369562 | 74.19311604 |

​		而更高位数的碰撞由于算力限制这里无法实现. 

## Project2: implement the Rho method of reduced SM3

​		Rho算法是指形如大步小步形式进行计算寻找碰撞的方式, 其最终形成一个循环. 对于SM3算法来说, 由于其映像空间是有限的, 故在有限步数内必然能够找到一个循环(尽管在只要求指定位数的碰撞下, 这个循环的阶数都会过大难以计算), 则可以再循环内找到碰撞(然而找到碰撞也未必一定需要循环). 总之这是一种期望效率比简单的随机生日攻击更高的碰撞算法. 其实现过程也与项目一较为类似, 其中使用了相同的计时器与生成器, 只是在碰撞阶段由生日攻击中的存储在字典中寻找碰撞变为了跳步寻找, 过程如下:

```python
for _ in range(times):
        x = generate_random_input()
        h1 = sm3(x) 
        h2 = sm3(h1)
        for _ in range(10000):
            h3 = sm3(h1)
            h4 = sm3(sm3(h2))
            if truncate_hash(h3, n) == truncate_hash(h4, n):
                break
            h1 = h3
            h2 = h4
```

​		这里通过times参数限制了最大寻找次数, times每增大1便多寻找10 000次, 尽管从数学上来说Hash函数的寻找过程是无记忆性的, 即无论生成新的随机数还是沿原有路径计算都不会影响找到碰撞的期望, 但这里为了得到确定的结果还是在一定次数后便放弃计算, 机关这样可能会对最后得到的平均时间产生一些影响. 

​		由于本项目在WSL虚拟机中完成故性能会有一定损耗, 导致最终耗时较多. 

| 位数    | 8          | 16         | 24         | 32          |
| ------- | ---------- | ---------- | ---------- | ----------- |
| 时间(s) | 0.0324 |0.4852 | 9.7824 | 120.3360 |



## Project3: implement length extension attack for SM3, SHA256, etc.

​		本实验要求实现对SM3和SHA256等的长度拓展攻击, Hash函数的长度拓展攻击是一种利用Hash函数的补位机制和迭代结构, 从已知消息M的哈希值和M的长度, 但不知道M本身的情况下, 构造出新的消息(M+append)的哈希值的攻击方法, 这里为了简洁仍然使用python来实现了对SM3的长度拓展攻击. 

​		部分Hash函数在计算时会保留部分状态, 如SM3在进行计算时首先会对每个块进行计算得到中间值, 最后再对所有中间值进行迭代压缩得到最后的Hash结果, 因此可以使用已知的原消息的Hash值作为内部状态, 再生成一块满足Hash函数规则同时包含了要附加信息的填充, 并计算出该padding的中间状态与先前的Hash值继续迭代来模拟在原消息后附加新消息时计算Hash值的过程. 主要函数如下:
```python
def attack(msghash, length, msgappend):
    # 根据原消息的Hash值作为中间状态继续迭代
    vectors = []
    message = ""
    for r in range(0, len(msghash), 8):
        vectors.append(int(msghash[r:r + 8], 16))

    if length > 64:
        for _ in range(0, int(length / 64) * 64):
            message += 'a'
    for _ in range(0, length % 64):
        message += 'a'
    message = func.bytes_to_list(bytes(message))
    message = padding(message)
    message.extend(func.bytes_to_list(bytes(msgappend)))
    return SM3.sm3_hash(message, vectors)
```

​		最后效果如下:
    ![image](https://github.com/ypleus/Images/blob/main/SM3.png)


​		

##  Project4: do your best to optimize SM3 implementation (software)

​		项目要求实现SM3算法的软件优化.

​		为了实现更高的效率这里选择了C++实现SM3算法, 此外, 还应用了内联优化与多线程处理等常见优化手段, 要求为软件层面的优化所以没有采用例如指令集等手段. 实际上在算法实现方面的区别不大, 主要还是在多线程等方面进行了优化, 以下是主要代码:
```c++
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
```

​		该部分实现了使用16线程对一个相同的消息进行SM3运算10 000次的操作, 最终耗时: 0.003999 s.





## Project5: Impl Merkle Tree following RFC6962

​		Merkle Tree是一种数据结构, 用于验证大量数据的完整性, 通过将数据分块并构建树状结构的哈希值来高效检测任何数据更改. RFC 6962是一份IETF标准文档, 定义了"Certificate Transparency"协议, 旨在提高网络安全, 特别是在SSL/TLS数字证书颁发和管理过程中, 通过使用Merkle Tree保证数字证书的透明性和防止伪造. 该项目指按照RFC6962标准的要求, 包括Hash算法, API等来实现一棵Merkle Tree, 此外还应满足以下要求:

- Construct a Merkle tree with 10w leaf nodes

- Build inclusion proof for specified element

- Build exclusion proof for specified element

  ​	首先构造Merkle Tree的节点结构:

  ```C++
  struct MerkleNode
  {
      std::string hash;
      MerkleNode *left;
      MerkleNode *right;
      MerkleNode(std::string h, MerkleNode *l, MerkleNode *r) : hash(h), left(l), right(r) {}
  };
  ```

  ​		然后调用openSSL的接口封装成SHA256计算函数, 并以此为基础实现树的构建函数. 树的构建则是让每个叶结点都保存给定数据的Hash值, 而非叶结点保存其子节点的Hash结果, 最终计算至根节点. 这里由于过长不再展示. 

  ​		而验证过程则是首先计算出给定要验证数据的Hash值并直接遍历所有的叶子结点进行比对, 若能够找到相同Hash值则可以认为该数据位于树内. 这里使用了1至100 000这10w个数字作为数据传入构建一棵Merkle Tree, 并验证了部分数据的存在性:

  ![image](https://github.com/ypleus/Images/blob/main/Merkle.png)


## Project9: AES / SM4 software implementation

​		本项目要求软件实现AES以及SM4算法.

​		由于课堂上已经多次学习并实现过了相关算法, 这里不会再详细介绍算法的具体流程, 只会简要概括其步骤以及主函数测试.

​		由于没有要求, 所以在实现时没有考虑填充以及加密模式等问题, 假定明文都是满足大小规范的, 当然再实现一层封装也并不会很难.

---

​		AES:

​		AES通常使用128位明文块和128位(也有更高)密钥，并通过多轮的置换和混淆操作，将明文块转换为密文块。其中列混淆, 字节代换和矩阵相乘等过程已在代码中实现这里也不再赘述. 

在这里先使用

```python
    hex_strings = [random.randint(0x0, 0xFFFFFFFFFFFFFFFF) for _ in range(num_strings)]
```

生成了包含1k个明文块的列表并采用16线程对该明文列表进行加密, 如下所示:

```python
    threads = []
    for i in range(0, num_strings, num_strings // num_threads):
        thread_strings = hex_strings[i:i + num_strings // num_threads]
        thread = threading.Thread(
            target=lambda strings: [encrypt(s, RK) for s in strings],
            args=(thread_strings, ))
        threads.append(thread)
        thread.start()
    for thread in threads:
        thread.join()
```

​		最终耗时8.6398s完成对10k个明文的加密.

​		而使用python的Crypto库加密同样的明文仅耗时0.296269s, 可以看出与官方的库仍存在很大差距, 不过除了许多优化手段外, Crypto库本质上仍是使用C进行计算, 故与Python关系不大. 

---

​		SM4:

​		SM4算法使用128位的明文和128位的密钥, 与AES的非线性的S盒和线性的行移位、列混淆、轮密钥加和SubBytes、ShiftRows、MixColumns和AddRoundKey的代换和置换相比, 它的核心加密步骤看似更少, 仅有非线性的S盒和线性的P盒进行的代换和置换, 然而和AES通常的10轮相比, SM4需要进行32轮加密, 故在轮数上弥补了结构上的复杂度. 同样的, 这里也不会过多展开SM4算法的流程, 仅展示其最后加密结果. 

​		由于除了算法本体之外, 其余部分的封装与处理的实现都与AES相似, 这里不再展示, 仅展示结果, 加密10k个128位字符串共耗时4.3697s. 使用gmSSL耗时1.62916s, 可以看出差距并没有上面AES那么大. 

​		当然, 以上内容也有很多值得优化的地方, 例如在使用相同密钥加密不同的字符串时, 轮密钥的生成过程完全不必重复, 仅一次即可, 不过在这里由于其不是耗时的主要部分故暂时略去. 



