#include <iostream>
#include <vector>
#include <string>
#include <algorithm>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstddef>
#include <openssl/sha.h>
#include <cassert>
#include <fstream>

// 将二进制哈希转换为十六进制字符串
std::string toHex(const std::vector<std::byte>& hash) {
    std::stringstream ss;
    for (std::byte b : hash) {
        ss << std::hex << std::setw(2) << std::setfill('0') 
           << static_cast<int>(b);
    }
    return ss.str();
}

std::vector<char> read_file_segment(std::fstream& file, size_t start, size_t num) {
    // std::shared_lock<std::shared_mutex> lock(FILE_RW_MUTEX);
    
    // 检查文件是否打开
    if (!file.is_open()) {
        throw std::runtime_error("File is not open");
    }

    // 定位到起始位置
    file.seekg(static_cast<std::streamoff>(start));
    if (file.fail()) {  // 检查是否定位失败（如 start 超过文件大小）
        throw std::runtime_error("Seek position exceeds file size");
    }

    // 获取剩余可读字节数
    const auto current_pos = file.tellg();
    file.seekg(0, std::ios::end);
    const auto remaining_bytes = static_cast<size_t>(file.tellg() - current_pos);
    file.seekg(current_pos);  // 恢复位置

    // 调整实际要读取的字节数
    const size_t bytes_to_read = std::min(num, remaining_bytes);
    std::vector<char> buffer(bytes_to_read);

    // 读取数据
    file.read(buffer.data(), static_cast<std::streamsize>(bytes_to_read));

    // 检查是否发生严重错误（非EOF的读取错误）
    if (file.bad()) {
        throw std::runtime_error("Read operation failed");
    }

    // 确保缓冲区大小与实际读取一致（防御性编程）
    buffer.resize(static_cast<size_t>(file.gcount()));
    return buffer;
}

std::pair<size_t, size_t> get_file_size_and_shard_count(std::fstream& file, size_t shard_size) {
    if (!file.is_open()) {
        throw std::runtime_error("File is not open");
    }
    if (shard_size == 0) {
        throw std::runtime_error("Shard size must be greater than 0");
    }

    // 使用共享锁保护文件读取操作
    // std::shared_lock<std::shared_mutex> lock(FILE_RW_MUTEX);

    // 保存当前文件位置
    auto original_pos = file.tellg();
    auto buf = file.rdbuf();
    size_t file_size =  buf->pubseekoff(0, std::ios::end);

    // 计算分片数量
    size_t num_shards = (file_size + shard_size - 1) / shard_size;

    return {file_size, num_shards};

}

// 从十六进制字符串转换回字节向量
std::vector<std::byte> fromHex(const std::string& hexStr) {
    std::vector<std::byte> result;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteStr = hexStr.substr(i, 2);
        auto byte = static_cast<std::byte>(std::stoi(byteStr, nullptr, 16));
        result.push_back(byte);
    }
    return result;
}

// 重载1: 接受字符串输入
std::vector<std::byte> sha256(const std::string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);
    
    std::vector<std::byte> result;
    result.reserve(SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        result.push_back(static_cast<std::byte>(hash[i]));
    }
    return result;
}

// 重载2: 接受字节向量输入
std::vector<std::byte> sha256(const std::vector<std::byte>& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.data(), data.size());
    SHA256_Final(hash, &sha256);
    
    std::vector<std::byte> result;
    result.reserve(SHA256_DIGEST_LENGTH);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        result.push_back(static_cast<std::byte>(hash[i]));
    }
    return result;
}

class MerkleNode : public std::enable_shared_from_this<MerkleNode> {
public:
    std::vector<std::byte> hash;
    std::shared_ptr<MerkleNode> left;
    std::shared_ptr<MerkleNode> right;
    std::weak_ptr<MerkleNode> parent;
    bool is_leaf;

    MerkleNode(const std::vector<std::byte>& data, bool leaf = true)
        : hash(data), left(nullptr), right(nullptr), is_leaf(leaf) {}

    static std::shared_ptr<MerkleNode> createNode(
        std::shared_ptr<MerkleNode> left, 
        std::shared_ptr<MerkleNode> right) 
    {
        auto node = std::shared_ptr<MerkleNode>(new MerkleNode(left, right));
        if (left) left->parent = node;
        if (right) right->parent = node;
        return node;
    }

private:
    MerkleNode(std::shared_ptr<MerkleNode> left, std::shared_ptr<MerkleNode> right)
        : left(left), right(right), is_leaf(false) {
        computeHash();
    }

public:
    void computeHash() {
        if (is_leaf) return;
        
        std::vector<std::byte> combined;
        if (left) combined.insert(combined.end(), left->hash.begin(), left->hash.end());
        if (right) combined.insert(combined.end(), right->hash.begin(), right->hash.end());
        else combined.insert(combined.end(), left->hash.begin(), left->hash.end());
        
        hash = sha256(combined);
        
        if (auto parent_ptr = parent.lock()) {
            parent_ptr->computeHash();
        }
    }
};

class MerkleTree {
private:
    std::shared_ptr<MerkleNode> root;
    std::vector<std::shared_ptr<MerkleNode>> leaves;

    std::shared_ptr<MerkleNode> buildTree(const std::vector<std::shared_ptr<MerkleNode>>& nodes) {
        if (nodes.empty()) return nullptr;
        if (nodes.size() == 1) return nodes[0];

        std::vector<std::shared_ptr<MerkleNode>> parents;
        for (size_t i = 0; i < nodes.size(); i += 2) {
            if (i + 1 < nodes.size()) {
                parents.push_back(MerkleNode::createNode(nodes[i], nodes[i+1]));
            } else {
                parents.push_back(MerkleNode::createNode(nodes[i], nullptr));
            }
        }
        return buildTree(parents);
    }

    // 序列化辅助函数 - 前序遍历
    void serializeNode(std::ostringstream& oss, const std::shared_ptr<MerkleNode>& node) const {
        if (!node) {
            oss << "null ";
            return;
        }
        
        oss << toHex(node->hash) << " ";
        oss << (node->is_leaf ? "1 " : "0 ");
        serializeNode(oss, node->left);
        serializeNode(oss, node->right);
    }

    // 反序列化辅助函数 - 前序遍历
    std::shared_ptr<MerkleNode> deserializeNode(std::istringstream& iss) const {
        std::string hashHex;
        if (!(iss >> hashHex) || hashHex == "null") {
            return nullptr;
        }
        
        std::string leafFlag;
        iss >> leafFlag;
        bool isLeaf = (leafFlag == "1");
        
        auto node = std::make_shared<MerkleNode>(fromHex(hashHex), isLeaf);
        node->left = deserializeNode(iss);
        node->right = deserializeNode(iss);
        
        if (node->left) node->left->parent = node;
        if (node->right) node->right->parent = node;
        
        return node;
    }

    // 收集所有叶子节点
    void collectLeaves(const std::shared_ptr<MerkleNode>& node) {
        if (!node) return;
        
        if (node->is_leaf) {
            leaves.push_back(node);
        } else {
            collectLeaves(node->left);
            collectLeaves(node->right);
        }
    }

public:
    MerkleTree() : root(nullptr) {}
    ~MerkleTree() { clear(); }

    void clear() {
        root.reset();
        leaves.clear();
    }

    void build(const std::vector<std::string>& data) {
        clear();
        if (data.empty()) return;

        for (const auto& item : data) {
            leaves.push_back(std::make_shared<MerkleNode>(sha256(item)));
        }

        root = buildTree(leaves);
    }

    std::string getRootHash() const {
        return root ? toHex(root->hash) : "";
    }

    void addLeaf(const std::string& data) {
        leaves.push_back(std::make_shared<MerkleNode>(sha256(data)));
        root = buildTree(leaves);
    }

    void updateLeaf(size_t index, const std::string& new_data) {
        if (index >= leaves.size()) {
            throw std::out_of_range("Leaf index out of range");
        }
        leaves[index]->hash = sha256(new_data);
        leaves[index]->computeHash();
    }

    void removeLeaf(size_t index) {
        if (index >= leaves.size()) {
            throw std::out_of_range("Leaf index out of range");
        }
        leaves.erase(leaves.begin() + index);
        root = buildTree(leaves);
    }

    std::vector<std::pair<std::string, bool>> getProof(size_t index) const {
        if (index >= leaves.size()) {
            throw std::out_of_range("Leaf index out of range");
        }
    
        std::vector<std::pair<std::string, bool>> proof; // pair of (hash, isLeft)
        auto node = leaves[index];
        auto parent = node->parent.lock();
        if (parent->left && parent->left == node){
            proof.emplace_back(toHex(node->hash), true);
        } else{
            proof.emplace_back(toHex(node->hash), false);
        }
    
        while (parent) {
            if (parent->left && parent->left != node) {
                // 当前节点是右孩子，所以兄弟是左孩子
                proof.emplace_back(toHex(parent->left->hash), true);
            } else if (parent->right && parent->right != node) {
                // 当前节点是左孩子，所以兄弟是右孩子
                proof.emplace_back(toHex(parent->right->hash), false);
            }
            node = parent;
            parent = node->parent.lock();
        }
    
        return proof;
    }
    
    bool verifyProof(const std::vector<std::pair<std::string, bool>>& proof, 
                    const std::string& rootHash) const {
        std::vector<std::byte> currentHash = fromHex(proof[0].first);
        
        for (int i = 1; i < proof.size(); i++) {
            
            std::vector<std::byte> proofHash = fromHex(proof[i].first);
            std::vector<std::byte> combined;
            
            // 根据证明中的位置信息决定组合顺序
            if (proof[i].second) {
                // 证明节点是左兄弟，所以应该放在前面
                combined.insert(combined.end(), proofHash.begin(), proofHash.end());
                combined.insert(combined.end(), currentHash.begin(), currentHash.end());
            } else {
                // 证明节点是右兄弟，所以应该放在后面
                combined.insert(combined.end(), currentHash.begin(), currentHash.end());
                combined.insert(combined.end(), proofHash.begin(), proofHash.end());
            }
            
            currentHash = sha256(combined);
        }
        
        return toHex(currentHash) == rootHash;
    }

    std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> 
    batchGetProofs(const std::vector<size_t>& indices) const {
        std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> proofs;
        
        for (size_t index : indices) {
            if (index >= leaves.size()) {
                throw std::out_of_range("Leaf index " + std::to_string(index) + 
                                      " out of range [0-" + 
                                      std::to_string(leaves.size()-1) + "]");
            }
            proofs[index] = getProof(index);
        }
        
        return proofs;
    }

    /**
     * Verifies multiple proofs against the current root hash
     * @param proofs Map of index to proof
     * @return Map of index to verification result (true/false)
     */
    bool batchVerifyProofs(const std::unordered_map<size_t, 
                        std::vector<std::pair<std::string, bool>>>& proofs) const 
    {
        std::unordered_map<size_t, bool> results;
        const std::string current_root = getRootHash();
        
        for (const auto& [index, proof] : proofs) {
            // Skip invalid indices rather than throwing
            if (index >= leaves.size()) {
                throw std::out_of_range("Leaf index " + std::to_string(index) + 
                                      " out of range [0-" + 
                                      std::to_string(leaves.size()-1) + "]");
            }
            if (! verifyProof(proof, current_root)){
                return false;
            }
        }
        
        return true;
    }

        // Serialize a proof into a string
    static std::string serializeProof(const std::vector<std::pair<std::string, bool>>& proof) {
        std::ostringstream oss;
        for (const auto& p : proof) {
            oss << p.first << ":" << (p.second ? "1" : "0") << " ";
        }
        return oss.str();
    }

    // Deserialize a proof from a string
    std::vector<std::pair<std::string, bool>> deserializeProof(const std::string& serialized) const {
        std::vector<std::pair<std::string, bool>> proof;
        std::istringstream iss(serialized);
        std::string item;
        
        while (iss >> item) {
            size_t colon_pos = item.find(':');
            if (colon_pos == std::string::npos) {
                throw std::runtime_error("Invalid proof format");
            }
            
            std::string hash = item.substr(0, colon_pos);
            bool isLeft = (item.substr(colon_pos + 1) == "1");
            proof.emplace_back(hash, isLeft);
        }
        
        return proof;
    }

    // 序列化整个Merkle树
    std::string serialize() const {
        std::ostringstream oss;
        serializeNode(oss, root);
        return oss.str();
    }

    // 反序列化整个Merkle树
    void deserialize(const std::string& serialized) {
        clear();
        std::istringstream iss(serialized);
        root = deserializeNode(iss);
        if (root) {
            collectLeaves(root);
        }
    }

    void printTree() const {
        if (!root) {
            std::cout << "Empty tree" << std::endl;
            return;
        }

        std::vector<std::shared_ptr<MerkleNode>> current_level;
        current_level.push_back(root);

        while (!current_level.empty()) {
            std::vector<std::shared_ptr<MerkleNode>> next_level;
            for (const auto& node : current_level) {
                std::cout << toHex(node->hash).substr(0,16) << " ";
                if (node->left) next_level.push_back(node->left);
                if (node->right) next_level.push_back(node->right);
            }
            std::cout << std::endl;
            current_level = next_level;
        }
    }

    void buildFromFile(std::fstream& f, size_t shard_size) {
        if (!f.is_open()) {
            throw std::runtime_error("File is not open");
        }
    
        // Get file size and calculate number of shards needed
        auto [file_size, shard_count] = get_file_size_and_shard_count(f, shard_size);
        
        if (file_size == 0) {
            clear();  // Handle empty file case
            return;
        }
    
        std::vector<std::string> shards;
        shards.reserve(shard_count);  // Pre-allocate for efficiency
    
        // Read each shard and add to the tree
        for (size_t i = 0; i < shard_count; ++i) {
            size_t start_pos = i * shard_size;
            size_t read_size = (i == shard_count - 1) ? (file_size - start_pos) : shard_size;
            
            auto segment = read_file_segment(f, start_pos, read_size);
            shards.emplace_back(segment.data(), segment.size());
        }
        build(shards);
    }
};

int main() {
    MerkleTree tree;
    
    // 构建初始树
    // std::vector<std::string> data = {"data1", "data2", "data3", "data4"};
    // tree.build(data);
    std::fstream f("../data/hello.txt", std::ios::binary|std::ios::in);
    tree.buildFromFile(f, 512);
    std::cout << "Initial root hash: " << tree.getRootHash() << std::endl;
    tree.printTree();

    // 测试序列化和反序列化
    std::string serialized = tree.serialize();
    std::cout << "\nSerialized tree: " << serialized << std::endl;
    
    MerkleTree newTree;
    newTree.deserialize(serialized);
    std::cout << "\nDeserialized tree root hash: " << newTree.getRootHash() << std::endl;
    newTree.printTree();

    // 测试验证证明
    // size_t index = 2;
    // auto proof = tree.getProof(index);
    // std::cout << "\nProof for data3: ";
    // for (const auto& p : proof) {
    //     std::cout << p.first << " ";
    // }
    // std::cout << std::endl;

    // std::string serialized_proof = tree.serializeProof(proof);
    // std::cout << "\nSerialized proof: " << serialized_proof << std::endl;

    // auto deserialized_proof = tree.deserializeProof(serialized_proof);
    // bool proof_valid = tree.verifyProof(deserialized_proof, tree.getRootHash());
    // std::cout << "Deserialized proof is " << (proof_valid ? "valid" : "invalid") << std::endl;
    
    // // 测试无效证明
    // proof[0].first = toHex(sha256("fake data"));
    // bool isInvalid = tree.verifyProof( proof, tree.getRootHash());
    // std::cout << "Fake proof is " << (isInvalid ? "valid" : "invalid") << std::endl;

    // 测试批量验证证明
    std::vector<size_t> indices;
    indices.push_back(1);
    auto batch_proof = tree.batchGetProofs(indices);

    auto result = tree.batchVerifyProofs(batch_proof);
    std::cout << "验证结果：" << result << std::endl; 

    return 0;
}