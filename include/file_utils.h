#pragma once

#include <fstream>
#include <vector>
#include <string>
#include <shared_mutex>
#include "bls_utils.h"

extern std::shared_mutex FILE_RW_MUTEX;
const long DEFAULT_SHARD_SIZE = 1024 * 1024 * 4;

// File utility functions

/**
 * @brief 将字符向量转换为无符号长整型
 * @param data 需要转换的字符向量
 * @param fill_byte 填充字节，默认为'\0'
 * @param is_little_endian 是否为小端序，默认为true
 * @return 转换后的无符号长整型值
 */
unsigned long vector_to_ulong(const std::vector<char>& data, char fill_byte = '\0', bool is_little_endian = true);

/**
 * @brief 从文件中读取指定段的数据
 * 
 * 该函数从指定的文件流中读取从start位置开始的num个字节的数据，并将其存储在字符向量中返回。
 * 
 * @param file 输入文件流引用，必须已经打开
 * @param start 开始读取的位置（字节偏移量）
 * @param num 要读取的字节数
 * @return std::vector<char> 包含读取数据的字符向量
 */
std::vector<char> read_file_segment(std::fstream& file, size_t start, size_t num);

/**
 * 计算文件的 Merkle 根节点值
 * 
 * 该函数从输入文件流读取数据，按照指定的分片大小划分数据块，然后计算这些数据块的 Merkle 树根哈希值。
 * Merkle 树是一种哈希树，可用于验证大型数据结构的内容完整性。
 * 
 * @param file 输入文件流，用于读取需要计算哈希的数据
 * @param shard_size 每个数据分片的大小（字节数）
 * @return 包含 Merkle 根哈希值的字符向量
 */
std::vector<char> calculate_merkle_root(std::fstream& file, size_t shard_size);

/**
 * @brief 从文件路径中提取文件名
 * 
 * 该函数从完整的文件路径中提取出文件名部分。
 * 例如，从路径 "/path/to/file.txt" 中提取出 "file.txt"。
 * 
 * @param filePath 完整的文件路径
 * @return std::string 提取出的文件名
 */
std::string get_fileName_from_path(const std::string& filePath);


std::pair<bool, std::vector<char>> 
verify_merkle_proof(const std::vector<std::vector<std::vector<char>>>& proofs,
                   const std::vector<size_t>& indices);

/**
 * @brief 计算Merkle证明
 * 
 * 该函数计算指定文件中特定分片的Merkle证明，用于后续验证分片数据的完整性
 * 
 * @param file 输入文件流，包含需要计算Merkle证明的数据
 * @param indices 需要计算Merkle证明的分片索引列表
 * @param shard_size 每个分片的大小（字节数）
 * @return 返回一个pair，第一部分是分片哈希值列表，第二部分是对应的Merkle证明列表
 */
// std::pair<std::vector<std::vector<char>>, std::vector<std::vector<std::vector<char>>>> 
// calculate_merkle_proof(std::fstream& file, const std::vector<size_t>& indices, size_t shard_size);
std::pair<std::vector<element_t*>, std::vector<std::vector<std::vector<char>>>> 
calculate_merkle_proof(std::fstream& file, const std::vector<size_t>& indices, size_t shard_size);

/**
 * @brief 获取文件的大小和分片数量
 * 
 * 该函数计算一个已打开文件的总大小，并根据指定的分片大小确定需要的分片数量。
 * 
 * @param file 已打开的输入文件流引用
 * @param shard_size 单个分片的大小（以字节为单位）
 * @return std::pair<size_t, size_t> 包含文件总大小和所需分片数量的键值对
 *         - first: 文件的总大小（以字节为单位）
 *         - second: 根据指定分片大小计算得出的分片数量
 */
std::pair<size_t, size_t> get_file_size_and_shard_count(std::fstream& file, size_t shard_size);
