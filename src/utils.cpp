#include "bls_utils.h"
#include "file_utils.h"
#include <openssl/evp.h>
#include <stdexcept>
#include <cmath>
#include <algorithm>
#include <cstring>
#include <vector>
#include <fstream>
#include <iostream>
#include <openssl/sha.h>
#include <utility>



// Initialize pairing parameters

std::shared_mutex FILE_RW_MUTEX;

// BLS utility functions implementation

std::pair<size_t, size_t> get_file_size_and_shard_count(std::fstream& file, size_t shard_size = DEFAULT_SHARD_SIZE) {
    if (!file.is_open()) {
        throw std::runtime_error("File is not open");
    }
    if (shard_size == 0) {
        throw std::runtime_error("Shard size must be greater than 0");
    }

    // 使用共享锁保护文件读取操作
    std::shared_lock<std::shared_mutex> lock(FILE_RW_MUTEX);

    // 保存当前文件位置
    auto original_pos = file.tellg();
    auto buf = file.rdbuf();
    size_t file_size =  buf->pubseekoff(0, std::ios::end);

    // 计算分片数量
    size_t num_shards = (file_size + shard_size - 1) / shard_size;


    return {file_size, num_shards};

}



// std::pair<std::vector<std::vector<char>>, std::vector<std::vector<std::vector<char>>>> 
// calculate_merkle_proof(std::fstream& file, const std::vector<size_t>& indices, size_t shard_size) {
//     if (!file.is_open()) {
//         throw std::runtime_error("File is not open");
//     }
//     if (shard_size <= 0) {
//         throw std::runtime_error("Shard size must be greater than 0");
//     }
//     if (indices.empty()) {
//         throw std::runtime_error("Proof indices cannot be empty");
//     }

//     // 保存当前文件位置
//     auto original_pos = file.tellg();

//     // 1. 获取文件大小并计算分片数量
//     auto[file_size, num_shards] = get_file_size_and_shard_count(file, shard_size);

//     // 验证nums中的索引是否有效
//     for (auto num : indices) {
//         if (num >= num_shards) {
//             file.seekg(original_pos);
//             throw std::runtime_error("Shard index out of range");
//         }
//     }

//     // 2. 计算所有叶节点的哈希
//     std::vector<std::vector<char>> leaf_hashes;
//     for (size_t i = 0; i < num_shards; ++i) {
//         size_t start = i * shard_size;
//         size_t read_size = std::min(shard_size, file_size - start);
        
//         auto shard_data = read_file_segment(file, start, read_size);
        
//         unsigned char hash[SHA256_DIGEST_LENGTH];
//         SHA256(reinterpret_cast<const unsigned char*>(shard_data.data()), 
//               shard_data.size(), hash);
        
//         leaf_hashes.emplace_back(hash, hash + SHA256_DIGEST_LENGTH);
//     }

//     if (leaf_hashes.empty()) {
//         // 处理空文件情况
//         unsigned char hash[SHA256_DIGEST_LENGTH];
//         SHA256(reinterpret_cast<const unsigned char*>(""), 0, hash);
//         leaf_hashes.emplace_back(hash, hash + SHA256_DIGEST_LENGTH);
//     }

//     // 3. 提取请求的分片哈希
//     std::vector<std::vector<char>> requested_hashes;
//     for (auto num : indices) {
//         requested_hashes.push_back(leaf_hashes[num]);
//     }

//     // 4. 为每个请求的分片构建Merkle证明路径
//     std::vector<std::vector<std::vector<char>>> all_proofs;
    
//     for (auto num : indices) {
//         std::vector<std::vector<char>> proof_path;
//         size_t current_index = num;
//         std::vector<std::vector<char>> current_level = leaf_hashes;
        
//         while (current_level.size() > 1) {
//             // 确定兄弟节点的位置
//             size_t sibling_index;
//             if (current_index % 2 == 0) {
//                 // 当前节点是左节点，取右兄弟
//                 sibling_index = current_index + 1;
//             } else {
//                 // 当前节点是右节点，取左兄弟
//                 sibling_index = current_index - 1;
//             }
            
//             // 确保兄弟索引不越界
//             if (sibling_index < current_level.size()) {
//                 proof_path.push_back(current_level[sibling_index]);
//             } else {
//                 // 如果没有兄弟节点（奇数个节点的情况），复制自己
//                 proof_path.push_back(current_level[current_index]);
//             }
            
//             // 构建下一层
//             std::vector<std::vector<char>> next_level;
//             for (size_t i = 0; i < current_level.size(); i += 2) {
//                 std::vector<char> combined_hash;
                
//                 if (i + 1 < current_level.size()) {
//                     combined_hash.insert(combined_hash.end(), 
//                                         current_level[i].begin(), 
//                                         current_level[i].end());
//                     combined_hash.insert(combined_hash.end(), 
//                                         current_level[i+1].begin(), 
//                                         current_level[i+1].end());
//                 } else {
//                     // 奇数个节点，复制最后一个
//                     combined_hash.insert(combined_hash.end(), 
//                                         current_level[i].begin(), 
//                                         current_level[i].end());
//                     combined_hash.insert(combined_hash.end(), 
//                                         current_level[i].begin(), 
//                                         current_level[i].end());
//                 }
                
//                 unsigned char hash[SHA256_DIGEST_LENGTH];
//                 SHA256(reinterpret_cast<const unsigned char*>(combined_hash.data()),
//                       combined_hash.size(), hash);
//                 next_level.emplace_back(hash, hash + SHA256_DIGEST_LENGTH);
//             }
            
//             // 更新当前索引为父节点在下一层的位置
//             current_index = current_index / 2;
//             current_level = next_level;
//         }
        
//         all_proofs.push_back(proof_path);
//     }

//     // 恢复文件指针
//     file.seekg(original_pos);

//     return {requested_hashes, all_proofs};
// }

// std::pair<bool, std::vector<char>> 
// verify_merkle_proof(const std::vector<std::vector<char>>& shard_hashes,
//                    const std::vector<std::vector<std::vector<char>>>& proofs,
//                    const std::vector<size_t>& indices) {
//     // 验证输入参数的有效性
//     if (shard_hashes.empty() || proofs.empty() || indices.empty()) {
//         return {false, {}};
//     }
//     if (shard_hashes.size() != proofs.size() || shard_hashes.size() != indices.size()) {
//         return {false, {}};
//     }

//     // 用于存储计算得到的根哈希
//     std::vector<char> computed_root;

//     // 为每个分片验证其证明路径
//     for (size_t i = 0; i < shard_hashes.size(); ++i) {
//         const auto& shard_hash = shard_hashes[i];
//         const auto& proof_path = proofs[i];
//         size_t index = indices[i];

//         std::vector<char> current_hash = shard_hash;
//         size_t current_index = index;

//         // 沿着证明路径向上计算
//         for (const auto& sibling_hash : proof_path) {
//             std::vector<char> combined_hash;
//             unsigned char hash[SHA256_DIGEST_LENGTH];

//             if (current_index % 2 == 0) {
//                 // 当前节点是左节点，兄弟是右节点
//                 combined_hash.insert(combined_hash.end(), 
//                                     current_hash.begin(), 
//                                     current_hash.end());
//                 combined_hash.insert(combined_hash.end(), 
//                                     sibling_hash.begin(), 
//                                     sibling_hash.end());
//             } else {
//                 // 当前节点是右节点，兄弟是左节点
//                 combined_hash.insert(combined_hash.end(), 
//                                     sibling_hash.begin(), 
//                                     sibling_hash.end());
//                 combined_hash.insert(combined_hash.end(), 
//                                     current_hash.begin(), 
//                                     current_hash.end());
//             }

//             // 计算父节点哈希
//             SHA256(reinterpret_cast<const unsigned char*>(combined_hash.data()),
//                   combined_hash.size(), hash);

//             current_hash.assign(hash, hash + SHA256_DIGEST_LENGTH);
//             current_index = current_index / 2;
//         }

//         // 如果是第一个分片，保存计算得到的根哈希
//         if (i == 0) {
//             computed_root = current_hash;
//         }
//         // 检查后续分片计算得到的根哈希是否一致
//         else if (current_hash != computed_root) {
//             return {false, {}};
//         }
//     }

//     return {true, computed_root};
// }



std::pair<std::vector<element_t*>, std::vector<std::vector<std::vector<char>>>> 
calculate_merkle_proof(std::fstream& file, const std::vector<size_t>& indices, size_t shard_size) {


    std::cout << std::endl;

    if (!file.is_open()) {
        throw std::runtime_error("File is not open");
    }
    if (shard_size <= 0) {
        throw std::runtime_error("Shard size must be greater than 0");
    }
    if (indices.empty()) {
        throw std::runtime_error("Proof indices cannot be empty");
    }

    file.seekg(std::ios::beg);


    // 1. 获取文件大小并计算分片数量
    auto[file_size, num_shards] = get_file_size_and_shard_count(file, shard_size);

    // 验证nums中的索引是否有效
    for (auto num : indices) {
        if (num >= num_shards) {
            // file.seekg(original_pos);
            throw std::runtime_error("Shard index out of range");
        }
    }

    // 2. 计算所有叶节点的哈希并存储分片数据
    std::vector<std::vector<char>> leaf_hashes;
    std::vector<std::vector<char>> shard_data_list;
    for (size_t i = 0; i < num_shards; ++i) {

        auto shard_data = read_file_segment(file, i * shard_size, shard_size);

        shard_data_list.push_back(shard_data);
        
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(shard_data.data()), 
              shard_data.size(), hash);
        
        leaf_hashes.emplace_back(hash, hash + SHA256_DIGEST_LENGTH);
    }

    if (leaf_hashes.empty()) {
        // 处理空文件情况
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(""), 0, hash);
        leaf_hashes.emplace_back(hash, hash + SHA256_DIGEST_LENGTH);
        shard_data_list.emplace_back(); // 空数据
    }

    // 3. 创建element_t*列表（请求的分片数据）
    std::vector<element_t*> requested_elements;
    for (auto num : indices) {
        element_t* elem = (element_t*)malloc(sizeof(element_t));
        element_init_G1(*elem, PAIRING);
        element_from_hash(*elem, shard_data_list[num].data(), shard_data_list[num].size());

        element_printf("calculate_merkle_proof H_mi in mid: %B\n", *elem);

        requested_elements.push_back(elem);
    }

    // 4. 为每个请求的分片构建Merkle证明路径
    std::vector<std::vector<std::vector<char>>> all_proofs;
    
    for (auto num : indices) {
        std::vector<std::vector<char>> proof_path;
        
        // 将请求的块的哈希值作为证明路径的第一个元素
        proof_path.push_back(leaf_hashes[num]);
        
        size_t current_index = num;
        std::vector<std::vector<char>> current_level = leaf_hashes;
        
        while (current_level.size() > 1) {
            // 确定兄弟节点的位置
            size_t sibling_index;
            if (current_index % 2 == 0) {
                // 当前节点是左节点，取右兄弟
                sibling_index = current_index + 1;
            } else {
                // 当前节点是右节点，取左兄弟
                sibling_index = current_index - 1;
            }
            
            // 确保兄弟索引不越界
            if (sibling_index < current_level.size()) {
                proof_path.push_back(current_level[sibling_index]);
            } else {
                // 如果没有兄弟节点（奇数个节点的情况），复制自己
                proof_path.push_back(current_level[current_index]);
            }
            
            // 构建下一层
            std::vector<std::vector<char>> next_level;
            for (size_t i = 0; i < current_level.size(); i += 2) {
                std::vector<char> combined_hash;
                
                if (i + 1 < current_level.size()) {
                    combined_hash.insert(combined_hash.end(), 
                                        current_level[i].begin(), 
                                        current_level[i].end());
                    combined_hash.insert(combined_hash.end(), 
                                        current_level[i+1].begin(), 
                                        current_level[i+1].end());
                } else {
                    // 奇数个节点，复制最后一个
                    combined_hash.insert(combined_hash.end(), 
                                        current_level[i].begin(), 
                                        current_level[i].end());
                    combined_hash.insert(combined_hash.end(), 
                                        current_level[i].begin(), 
                                        current_level[i].end());
                }
                
                unsigned char hash[SHA256_DIGEST_LENGTH];
                SHA256(reinterpret_cast<const unsigned char*>(combined_hash.data()),
                      combined_hash.size(), hash);
                next_level.emplace_back(hash, hash + SHA256_DIGEST_LENGTH);
            }
            
            // 更新当前索引为父节点在下一层的位置
            current_index = current_index / 2;
            current_level = next_level;
        }
        
        all_proofs.push_back(proof_path);
    }

    // 恢复文件指针
    file.seekg(std::ios::beg);

    return {requested_elements, all_proofs};
}

std::pair<bool, std::vector<char>> 
verify_merkle_proof(const std::vector<std::vector<std::vector<char>>>& proofs,
                   const std::vector<size_t>& indices) {
    // 验证输入参数的有效性
    if (proofs.empty() || indices.empty()) {
        return {false, {}};
    }
    if (proofs.size() != indices.size()) {
        return {false, {}};
    }

    // 用于存储计算得到的根哈希
    std::vector<char> computed_root;

    // 为每个分片验证其证明路径
    for (size_t i = 0; i < proofs.size(); ++i) {
        const auto& proof_path = proofs[i];
        if (proof_path.empty()) {
            return {false, {}};
        }

        // 第一个元素是分片的哈希值
        const auto& shard_hash = proof_path[0];
        size_t index = indices[i];

        std::vector<char> current_hash = shard_hash;
        size_t current_index = index;

        // 沿着证明路径向上计算（跳过第一个元素，因为它是分片哈希本身）
        for (size_t j = 1; j < proof_path.size(); ++j) {
            const auto& sibling_hash = proof_path[j];
            std::vector<char> combined_hash;
            unsigned char hash[SHA256_DIGEST_LENGTH];

            if (current_index % 2 == 0) {
                // 当前节点是左节点，兄弟是右节点
                combined_hash.insert(combined_hash.end(), 
                                    current_hash.begin(), 
                                    current_hash.end());
                combined_hash.insert(combined_hash.end(), 
                                    sibling_hash.begin(), 
                                    sibling_hash.end());
            } else {
                // 当前节点是右节点，兄弟是左节点
                combined_hash.insert(combined_hash.end(), 
                                    sibling_hash.begin(), 
                                    sibling_hash.end());
                combined_hash.insert(combined_hash.end(), 
                                    current_hash.begin(), 
                                    current_hash.end());
            }

            // 计算父节点哈希
            SHA256(reinterpret_cast<const unsigned char*>(combined_hash.data()),
                  combined_hash.size(), hash);

            current_hash.assign(hash, hash + SHA256_DIGEST_LENGTH);
            current_index = current_index / 2;
        }

        // 如果是第一个分片，保存计算得到的根哈希
        if (i == 0) {
            computed_root = current_hash;
        }
        // 检查后续分片计算得到的根哈希是否一致
        else if (current_hash != computed_root) {
            return {false, {}};
        }
    }

    return {true, computed_root};
}

element_t* sig_init() {
    element_t* sig = (element_t*)malloc(sizeof(element_t));
    element_init_G1(*sig, PAIRING);
    return sig;
}

void sig_clear(element_t *sig) {
    element_clear(*sig);
    free(sig);
}

void sign_message(element_t sk, std::string message, element_t sig) {
    element_t h;
    element_init_G1(h, PAIRING);
    element_from_hash(h, (char*)message.c_str(), message.length());
    element_pow_zn(sig, h, sk);
    element_clear(h);
}
unsigned long vector_to_ulong(
    const std::vector<char>& data,
    char fill_byte,
    bool is_little_endian
) {
    if (data.empty()) {
        throw std::runtime_error("Input data is empty");
    }

    // 复制数据到临时缓冲区，自动填充不足部分
    std::vector<char> bytes(sizeof(unsigned long), fill_byte);
    std::copy_n(
        data.begin(),
        std::min(data.size(), bytes.size()),
        bytes.begin()
    );

    // 处理字节序
    if (!is_little_endian) {
        std::reverse(bytes.begin(), bytes.end());
    }

    // 转换为 unsigned long
    unsigned long result = 0;
    std::memcpy(&result, bytes.data(), sizeof(unsigned long));
    return result;
}

int verify_signature(element_t sig, element_t g, element_t public_key, std::string message) {
    element_t h;
    element_init_G1(h, PAIRING);
    element_from_hash(h, (char*)message.c_str(), message.length());

    element_t temp1, temp2;
    element_init_GT(temp1, PAIRING);
    element_init_GT(temp2, PAIRING);

    element_pairing(temp1, sig, g);
    element_pairing(temp2, h, public_key);

    int result = !element_cmp(temp1, temp2);

    element_clear(h);
    element_clear(temp1);
    element_clear(temp2);

    return result;
}

std::string get_fileName_from_path(const std::string& filePath) {
    // 查找最后一个路径分隔符（支持Windows和Unix风格）
    size_t pos = filePath.find_last_of("/\\");
    
    // 如果找到分隔符，返回分隔符后面的部分
    if (pos != std::string::npos) {
        return filePath.substr(pos + 1);
    }
    
    // 如果没有分隔符，直接返回原字符串
    return filePath;
}


void compress_element(unsigned char **data, int *n, element_t sig, pairing_t PAIRING) {
    *n = pairing_length_in_bytes_compressed_G1(PAIRING);
    element_to_bytes_compressed(*data, sig);
}

void decompress_element(element_t sig, unsigned char *data, int n) {
    element_from_bytes_compressed(sig, data);
}


std::vector<char> calculate_merkle_root(std::fstream& file, size_t shard_size = DEFAULT_SHARD_SIZE) {
    if (!file.is_open()) {
        throw std::runtime_error("File is not open");
    }
    if (shard_size <= 0) {
        throw std::runtime_error("Shard size must be greater than 0");
    }

    // // 1. 获取文件大小和分片数量
    auto original_pos = file.tellg();
    auto[file_size, num_shards] = get_file_size_and_shard_count(file, shard_size);

    // 2. 计算每个分片的哈希
    std::vector<std::vector<char>> leaf_hashes;


    for (size_t i = 0; i < num_shards; ++i) {
        
        // 使用现有的 readFileSegment 函数读取分片
        auto shard_data = read_file_segment(file, i * shard_size, shard_size);
        
        // 计算 SHA256 哈希
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(shard_data.data()), 
              shard_data.size(), hash);
        
        // 存储二进制哈希结果
        leaf_hashes.emplace_back(hash, hash + SHA256_DIGEST_LENGTH);
    }

    if (leaf_hashes.empty()) {
        // 处理空文件情况
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const unsigned char*>(""), 0, hash);
        return std::vector<char>(hash, hash + SHA256_DIGEST_LENGTH);
    }

    // 3. 构建 Merkle 树
    std::vector<std::vector<char>> current_level = leaf_hashes;
    while (current_level.size() > 1) {
        std::vector<std::vector<char>> next_level;

        for (size_t i = 0; i < current_level.size(); i += 2) {
            // 组合两个哈希
            std::vector<char> combined_hash;
            
            if (i + 1 < current_level.size()) {
                combined_hash.insert(combined_hash.end(), 
                                    current_level[i].begin(), 
                                    current_level[i].end());
                combined_hash.insert(combined_hash.end(), 
                                    current_level[i + 1].begin(), 
                                    current_level[i + 1].end());
            } else {
                // 奇数个哈希时，复制最后一个
                combined_hash.insert(combined_hash.end(), 
                                    current_level[i].begin(), 
                                    current_level[i].end());
                combined_hash.insert(combined_hash.end(), 
                                    current_level[i].begin(), 
                                    current_level[i].end());
            }

            // 计算组合哈希的 SHA256
            unsigned char hash[SHA256_DIGEST_LENGTH];
            SHA256(reinterpret_cast<const unsigned char*>(combined_hash.data()),
                  combined_hash.size(), hash);
            
            next_level.emplace_back(hash, hash + SHA256_DIGEST_LENGTH);
        }

        current_level = next_level;
    }

    // 恢复文件指针
    file.seekg(original_pos);

    return current_level[0];
}

// std::vector<char> read_file_segment(std::fstream& file, size_t start, size_t num) {
//     std::shared_lock<std::shared_mutex> lock(FILE_RW_MUTEX);
//     file.seekg(start);
//     if (!file.is_open()) {
//         throw std::runtime_error("Seek failed in file: ");
//     }

//     std::vector<char> buffer(num);
//     file.read(buffer.data(), num);

//     if (!file.is_open() && !file.eof()) {
//         throw std::runtime_error("Read failed in file: ");
//     }

//     size_t bytes_read = file.gcount();
//     if (bytes_read < num) {
//         buffer.resize(bytes_read);
//     }

//     return buffer;
// }

std::vector<char> read_file_segment(std::fstream& file, size_t start, size_t num) {
    std::shared_lock<std::shared_mutex> lock(FILE_RW_MUTEX);
    
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