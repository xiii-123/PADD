#include "padd.h"
#include <filesystem>
#include <iostream>
#include <sstream>
#include <random>
#include <chrono>
#include <string>
#include <algorithm>  // for std::transform, std::shuffle, std::sort
#include <vector>
#include <utility>
#include <cstring>  // for memcpy
#include <fstream>
#include <memory>
#include <stdexcept>

#define TYPEA_PARAMS                                           \
    "type a\n"                                                 \
    "q 87807107996633125224377819847540498158068831994142082"  \
    "1102865339926647563088022295707862517942266222142315585"  \
    "8769582317459277713367317481324925129998224791\n"         \
    "h 12016012264891146079388821366740534204802954401251311"  \
    "822919615131047207289359704531102844802183906537786776\n" \
    "r 730750818665451621361119245571504901405976559617\n"     \
    "exp2 159\n"                                               \
    "exp1 107\n"                                               \
    "sign1 1\n"                                                \
    "sign0 1\n"

pairing_t PAIRING;

namespace fs = std::filesystem;

Proof::Proof(element_t* mu, element_t* sigma, 
    std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> &merkle_proofs, 
    std::vector<element_t*>& required_elements,
    std::string root_hash,
    element_t* sig_mht, std::vector<size_t>& indices)
    {

    element_init_same_as(this->mu, *mu);
    element_set(this->mu, *mu);
    element_init_same_as(this->sigma, *sigma);
    element_set(this->sigma, *sigma);
    this->root_hash = root_hash;

    // 深拷贝merkle_proofs
    for (const auto& [key, value] : merkle_proofs) {
        this->merkle_proofs[key] = value;  // std::string and vector will be properly copied
    }

    for (element_t* elem : required_elements) {
        element_t* new_elem = (element_t*)malloc(sizeof(element_t));
        if (!new_elem) throw std::bad_alloc();
        
        element_init_same_as(*new_elem, *elem);
        element_set(*new_elem, *elem);
        this->required_elements.push_back(new_elem);
    }

    element_init_same_as(this->sig_mht, *sig_mht);
    element_set(this->sig_mht, *sig_mht);
    this->indices = indices;
}

Proof::Proof(){}

Proof::~Proof() {
    // Clean up mu
    if (mu != NULL) {
        element_clear(mu);
    }

    // Clean up sigma
    if (sigma != NULL) {
        element_clear(sigma);
    }

    // Clean up sig_mht
    if (sig_mht != NULL) {
        element_clear(sig_mht);
    }

    for (element_t* elem : required_elements) {
        if (elem != NULL) {
            element_clear(*elem);
            free(elem);
        }
    }
}

void padd_init(element_t pk, element_t sk, element_t g) {
    pairing_init_set_buf(PAIRING, TYPEA_PARAMS, sizeof(TYPEA_PARAMS));
    element_init_G2(g, PAIRING);
    element_init_G2(pk, PAIRING);
    element_init_Zr(sk, PAIRING);
    element_random(g);
    element_random(sk);
    element_pow_zn(pk, g, sk);
}

bls_pkc* key_gen() {
    bls_pkc* pkc = (bls_pkc*)malloc(sizeof(bls_pkc));
    pkc->pk = (bls_pk*)malloc(sizeof(bls_pk));
    pkc->sk = (bls_sk*)malloc(sizeof(bls_sk));
    
    padd_init(pkc->pk->spk, pkc->sk->ssk, pkc->g);

    element_init_Zr(pkc->sk->alpha, PAIRING);
    element_init_G2(pkc->pk->v, PAIRING);

    element_random(pkc->sk->alpha);
    element_pow_zn(pkc->pk->v, pkc->g, pkc->sk->alpha);

    return pkc;
}

void padd_clear(bls_pkc* pkc) {
    element_clear(pkc->pk->spk);
    element_clear(pkc->pk->v);
    element_clear(pkc->sk->ssk);
    element_clear(pkc->sk->alpha);
    element_clear(pkc->g);
    // pairing_clear(PAIRING);
    free(pkc->pk);
    free(pkc->sk);
    free(pkc);
}

element_t* sig_init(){
    element_t* sig = (element_t*)malloc(sizeof(element_t));
    element_init_G1(*sig, PAIRING);
    return sig;
}

std::string construct_t(bls_pkc& pkc, const std::string& file_name, size_t n,  element_t u) {
    // 第一步：拼接文件名、n和u
    std::ostringstream oss;
    
    // 安全地转换element_t为字符串
    const size_t buf_size = 1024;
    std::vector<char> u_buf(buf_size);
    if (element_snprint(u_buf.data(), buf_size, u) < 0) {
        throw std::runtime_error("Failed to convert element_t to string");
    }
    
    oss << file_name << n << u_buf.data();
    std::string t = oss.str();

    // 第二步：生成签名
    element_t *sig = sig_init();

    try {
        sign_message(pkc.sk->ssk, t.c_str(), *sig);

        // 安全地转换签名到字符串
        std::vector<char> sig_buf(buf_size);
        element_snprint(sig_buf.data(), buf_size, *sig);

        // 追加签名到结果
        t.append(sig_buf.data());
    } catch (...) {
        free_element_ptr(sig); // 确保在异常情况下清理资源
        throw;
    }

    // 清理资源
    free_element_ptr(sig);
    return t;
}

void calculate_single_sigma(std::fstream& f, size_t start, size_t num, bls_pkc& pkc, element_t u, element_t sigma){
    // 读取文件分片
    std::vector<char> buffer = read_file_segment(f, start, num);

    // 计算sigma
    element_t temp;
    element_t m;
    element_t u_m;
    element_init_G1(temp,PAIRING);
    element_init_G1(u_m,PAIRING);
    element_init_Zr(m,PAIRING);

    element_from_hash(temp, buffer.data(), buffer.size());
    // element_printf("H_mi first: %B\n", temp);

    element_set_si(m, vector_to_ulong(buffer));
    element_pow_zn(u_m, u, m);
    element_mul(temp, temp, u_m);
    element_pow_zn(sigma, temp, pkc.sk->alpha);

    element_clear(u_m);
    element_clear(m);
    element_clear(temp);
}

std::vector<element_t *> calculate_phi(std::fstream& f, bls_pkc& pkc, element_t u, size_t shard_size = DEFAULT_SHARD_SIZE) {
    if (!f.is_open()) {
        throw std::runtime_error("File is not open");
    }
    if (shard_size <= 0) {
        throw std::runtime_error("Shard size must be greater than 0");
    }

    auto original_pos = f.tellg();
    auto[file_size, num_shard] = get_file_size_and_shard_count(f, shard_size);

    size_t num_shards = (file_size + shard_size - 1) / shard_size;

    std::vector<element_t*> phi;

    try {
        for (size_t i = 0; i < num_shards; ++i) {
            size_t start = i * shard_size;
            size_t read_size = std::min(shard_size, file_size - start);

            element_t *sigma = (element_t*)malloc(sizeof(element_t));
            element_init_G1(*sigma, PAIRING);
            calculate_single_sigma(f, start, read_size, pkc, u, *sigma);

            phi.push_back(sigma);
        }
    } catch (...) {
        for (auto elem : phi) {
            element_clear(*elem);
        }
        f.seekg(original_pos);
        throw;
    }

    f.seekg(original_pos);
    return phi;
}

std::vector<char> serialize_phi(std::vector<element_t *> phi) {
    if (phi.empty()) {
        throw std::runtime_error("Null phi pointer");
    }

    std::vector<char> serialized_data;
    
    // 首先写入签名数量
    uint32_t num_sigs = phi.size();
    char num_buf[sizeof(uint32_t)];
    memcpy(num_buf, &num_sigs, sizeof(uint32_t));
    serialized_data.insert(serialized_data.end(), num_buf, num_buf + sizeof(uint32_t));

    // 序列化每个 G2 元素
    for (const auto& sig : phi) {
        if (!sig) {
            throw std::runtime_error("Null element in phi");
        }

        // 获取 G2 元素的压缩形式大小
        int buf_len = element_length_in_bytes_compressed(*sig);
        std::vector<char> sig_buf(buf_len);
        
        // 压缩 G2 元素
        int written = element_to_bytes_compressed(
            reinterpret_cast<unsigned char*>(sig_buf.data()), 
            *sig
        );
        
        if (written != buf_len) {
            throw std::runtime_error("Failed to serialize G2 element");
        }
        
        // 添加到序列化数据
        serialized_data.insert(
            serialized_data.end(), 
            sig_buf.begin(), 
            sig_buf.end()
        );
    }

    return serialized_data;
}

std::vector<element_t *> deserialize_phi(const std::vector<char>& serialized_data, pairing_t pairing) {
    if (serialized_data.size() < sizeof(uint32_t)) {
        throw std::runtime_error("Invalid serialized data");
    }

    // 读取签名数量
    uint32_t num_sigs;
    memcpy(&num_sigs, serialized_data.data(), sizeof(uint32_t));

    std::vector<element_t*> phi;

    size_t offset = sizeof(uint32_t);

    try {
        for (uint32_t i = 0; i < num_sigs; ++i) {
            // 分配并初始化新元素
            element_t* sig = (element_t*)malloc(sizeof(element_t));
            element_init_G2(*sig, pairing);

            // 计算 G2 元素压缩形式的大小
            int buf_len = element_length_in_bytes_compressed(*sig);
            
            if (offset + buf_len > serialized_data.size()) {
                throw std::runtime_error("Invalid serialized data length");
            }

            // 从字节流反序列化 G2 元素
            if (element_from_bytes_compressed(
                *sig, 
                const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(serialized_data.data() + offset))
            )) {
                throw std::runtime_error("Failed to deserialize G2 element");
            }

            phi.push_back(sig);
            offset += buf_len;
        }
    } catch (...) {
        // 发生错误时清理已分配的元素
        for (auto elem : phi) {
            element_clear(*elem);
            free(elem);
        }
        throw;
    }

    return phi;
}

void free_phi(std::vector<element_t *>& phi) {
    if (phi.empty()) return;  // Early return if null
    
    for (element_t* elem : phi) {
        if (elem != nullptr) {
            element_clear(*elem);  // Clear the PBC element
            free(elem);            // Free the allocated memory
        }
    }
    phi.clear();  // Clear the vector
}

std::pair<std::pair<std::string, element_t*>, std::vector<element_t *>> 
sig_gen(bls_pkc& pkc, std::string file_name, std::fstream& f, MerkleTree& tree, size_t shard_size = DEFAULT_SHARD_SIZE) {
    auto[file_size, shard_num] = get_file_size_and_shard_count(f, shard_size);
    element_t u;
    element_init_G1(u, PAIRING);
    element_random(u);

    std::string t = construct_t(pkc, get_fileName_from_path(file_name), shard_num, u);
    auto phi = calculate_phi(f, pkc, u, shard_size);

    // std::vector<char> root = calculate_merkle_root(f, shard_size);
    auto root = tree.get_root_hash();
    element_t *sig = (element_t*)malloc(sizeof(element_t));
    element_init_G1(*sig, PAIRING);
    element_from_hash(*sig, root.data(), root.size());
    element_pow_zn(*sig, *sig, pkc.sk->alpha);

    element_clear(u);
    return std::make_pair(std::make_pair(t, sig), phi);
}

std::vector<std::string> extract_parts(const std::string& input) {
    std::vector<std::string> parts;
    
    // 提取第一部分（文件名）
    size_t firstBracket = input.find('[');
    if (firstBracket == std::string::npos) {
        return parts; // 无效输入
    }
    parts.push_back(input.substr(0, firstBracket));
    
    // 提取第二部分（第一个中括号内容）
    size_t secondBracket = input.find('[', firstBracket + 1);
    if (secondBracket == std::string::npos) {
        return parts; // 无效输入
    }
    
    // 第一个中括号内容从firstBracket到secondBracket之前
    parts.push_back(input.substr(firstBracket, secondBracket - firstBracket));
    
    // 提取第三部分（第二个中括号内容）
    parts.push_back(input.substr(secondBracket));
    
    return parts;
}

std::pair<bool, element_t*> deserialize_t(std::string t, element_t g, element_t pk){
    // 1, 拆分t
    auto t_sub = extract_parts(t);
    if (t_sub.size() != 3) return std::make_pair(false, nullptr);
    
    element_t sig;
    element_init_G1(sig, PAIRING);
    element_set_str(sig, t_sub[2].c_str(), 10);

    // element_printf("sig: %B\n", sig);

    // 2， 验证签名
    int result = verify_signature(sig, g, pk, t_sub[0]+t_sub[1]);
    // std::cout << "result: " << result << std::endl;
    if (result != 1) return std::make_pair(false, nullptr);
    

    // 3，返回u
    element_t *u = (element_t*)malloc(sizeof(element_t));
    element_init_G1(*u, PAIRING);
    element_set_str(*u, t_sub[1].c_str(), 10);

    return std::make_pair(true, u);
}

void free_element_ptr(element_t* t){
    if (t == nullptr){
        return;
    }
    element_clear(*t);
    free(t);
    return;
}


std::vector<size_t> select_random_numbers(size_t n, size_t k = 0) {
    // 处理特殊情况：n=1时总是返回{0}
    if (n == 1) {
        return {0};
    }

    // 设置默认k值为n/2（向下取整）
    if (k == 0) {
        k = n / 2;
    }
    
    // 参数检查
    if (n == 0 || k == 0 || k > n) {
        return {};
    }
    
    // 创建包含0到n-1的向量
    std::vector<size_t> numbers(n);
    for (size_t i = 0; i < n; ++i) {
        numbers[i] = i;  // 现在从0开始
    }
    
    // 使用更好的随机数生成方式
    std::random_device rd;
    std::mt19937 g(rd());
    
    // 随机打乱向量
    std::shuffle(numbers.begin(), numbers.end(), g);
    
    // 取前k个元素
    numbers.resize(k);
    
    // 排序结果（保持升序）
    std::sort(numbers.begin(), numbers.end());
    
    return numbers;
}

// 生成挑战，直接返回pair向量
std::vector<std::pair<size_t, element_t*>> gen_chal(size_t n) {

    if (n == 0) {
        throw std::runtime_error("Number of challenges cannot be zero");
    }

    // 1. 获取随机分片索引
    auto nums = select_random_numbers(n); 
    
    std::vector<std::pair<size_t, element_t*>> challenges;
    
    try {
        for (auto num : nums) {
            // 2. 为每个索引创建随机元素
            element_t* random_elem = (element_t*)malloc(sizeof(element_t));
            if (!random_elem) {
                throw std::runtime_error("Memory allocation failed");
            }
            
            element_init_Zr(*random_elem, PAIRING);
            element_random(*random_elem);
            
            challenges.emplace_back(num, random_elem);
        }
    } catch (...) {
        // 清理已分配的元素
        for (auto& [num, elem] : challenges) {
            element_clear(*elem);
            free(elem);
        }
        throw;
    }
    
    return challenges;
}

void free_chal(std::vector<std::pair<size_t, element_t*>>& challenges) {
    for (auto& [num, elem] : challenges) {
        if (elem != nullptr) {
            element_clear(*elem);  // Clear the PBC element
            free(elem);           // Free the allocated memory
            elem = nullptr;       // Set pointer to null
        }
    }
    challenges.clear();  // Clear the vector
}

// 将挑战序列化为字节流
std::vector<char> serialize_chal(const std::vector<std::pair<size_t, element_t*>>& chal) {
    std::vector<char> serialized;
    
    for (const auto& [num, elem] : chal) {
        // 1. 序列化数字部分
        std::string num_str = std::to_string(num);
        serialized.insert(serialized.end(), num_str.begin(), num_str.end());
        serialized.push_back(',');
        
        // 2. 序列化元素部分
        unsigned char elem_bytes[20]; // 假设Zr元素序列化为20字节
        element_to_bytes(elem_bytes, *elem);
        
        serialized.insert(serialized.end(), elem_bytes, elem_bytes + sizeof(elem_bytes));
        serialized.push_back(';');
    }
    
    return serialized;
}

element_t* calculate_proof_mu(
    const std::vector<std::pair<size_t, 
    element_t*>>& chal, std::fstream& f, 
    size_t shard_size = DEFAULT_SHARD_SIZE) {
    // 初始化结果 μ
    element_t *mu = (element_t*)malloc(sizeof(element_t));
    element_init_Zr(*mu, PAIRING);
    element_set0(*mu);

    auto[file_size, shard_num] = get_file_size_and_shard_count(f, shard_size);

    // 临时变量
    element_t temp_prod, m_i;
    element_init_Zr(temp_prod, PAIRING);
    element_init_Zr(m_i, PAIRING);

    try {
        for (const auto& [s_i, v_i] : chal) {
            // 1. 读取文件块 (自动处理锁和边界检查)

            auto buffer = read_file_segment(f, s_i *shard_size, shard_size);

            // 2. 将mi转化为zr元素
            element_set_si(m_i, vector_to_ulong(buffer));

            // 3. 计算 v_i * m_i 并累加
            element_mul(temp_prod, *v_i, m_i);
            element_add(*mu, *mu, temp_prod);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in calculate_proof_mu: " << e.what() << std::endl;
        element_clear(*mu);
        element_clear(temp_prod);
        element_clear(m_i);
        return nullptr;
    }

    // 清理临时变量
    element_clear(temp_prod);
    element_clear(m_i);

    f.seekg(std::ios::beg);

    return mu;
}

element_t* calculate_proof_sigma_from_file(std::vector<std::pair<size_t, element_t*>> chal, 
    std::fstream& f,
    bls_pkc& pkc,
    element_t u,
    size_t shard_size = DEFAULT_SHARD_SIZE) {
    // 初始化结果 σ (G1群元素)
    element_t* sigma = (element_t*)malloc(sizeof(element_t));
    element_init_G1(*sigma, PAIRING);
    element_set1(*sigma); // σ = 1 (群单位元)

    // 临时变量
    element_t sigma_i, temp;
    element_init_G1(sigma_i, PAIRING);
    element_init_G1(temp, PAIRING);

    try {
    for (const auto& [s_i, v_i] : chal) {
        // 1. 计算单个σ_i (使用已有calculate_single_sigma函数)
        calculate_single_sigma(f, s_i * shard_size, shard_size, pkc, u, sigma_i);

        // 2. 计算σ_i^{v_i}
        element_pow_zn(temp, sigma_i, *v_i); // temp = σ_i^{v_i}

        // 3. 累乘到结果σ
        element_mul(*sigma, *sigma, temp); // σ = σ * (σ_i^{v_i})
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in calculate_proof_sigma: " << e.what() << std::endl;
        element_clear(*sigma);
        free(sigma);
        element_clear(sigma_i);
        element_clear(temp);
        return nullptr;
    }

    element_clear(sigma_i);
    element_clear(temp);

    return sigma;
}

element_t* calculate_proof_sigma(const std::vector<std::pair<size_t, element_t*>>& chal,const std::vector<element_t *>& phi) {
    
    // 验证输入
    if (phi.empty()) {
        throw std::runtime_error("phi is null");
    }
    if (chal.empty()) {
        throw std::runtime_error("challenge is empty");
    }

    // 初始化结果 σ (G1群元素)
    element_t* sigma = (element_t*)malloc(sizeof(element_t));
    if (!sigma) {
        throw std::runtime_error("Memory allocation failed");
    }
    element_init_G1(*sigma, PAIRING);
    element_set1(*sigma); // σ = 1 (群单位元)

    // 临时变量
    element_t temp;
    element_init_G1(temp, PAIRING);

    try {
        for (const auto& [s_i, v_i] : chal) {
 
            // 检查索引是否有效
            if (s_i >= phi.size()) {
                throw std::runtime_error("Invalid shard index in challenge");
            }

            // 获取预先计算的sigma_i
    
            element_t* sigma_i = phi.at(s_i);

            // 计算σ_i^{v_i}
            element_pow_zn(temp, *sigma_i, *v_i); // temp = σ_i^{v_i}

            // 累乘到结果σ
            element_mul(*sigma, *sigma, temp); // σ = σ * (σ_i^{v_i})
        }
    } catch (...) {
        element_clear(*sigma);
        free(sigma);
        element_clear(temp);
        throw;
    }

    element_clear(temp);
    return sigma;
}

std::vector<size_t> extract_first(const std::vector<std::pair<size_t, element_t*>>& chal) {
    std::vector<size_t> result;
    result.reserve(chal.size()); // 预分配空间以提高效率
    std::transform(chal.begin(), chal.end(), std::back_inserter(result),
                   [](const auto& pair) { return pair.first; });
    return result;
}

std::vector<element_t*> get_requeired_elements(std::fstream& file, std::vector<size_t> indices, size_t shard_size){
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

        requested_elements.push_back(elem);
    }
    return requested_elements;
}

Proof gen_proof(std::fstream& f,
    std::vector<element_t *>& phi, 
    std::vector<std::pair<size_t, element_t*>>& chal, 
    element_t* sig_mht,
    MerkleTree& tree,
    size_t shard_size = DEFAULT_SHARD_SIZE
){

    element_t* mu = calculate_proof_mu(chal, f, shard_size);
    element_t* sigma = calculate_proof_sigma(chal, phi);
    // auto merkle_proof = calculate_merkle_proof(f, extract_first(chal), shard_size);
    auto merkle_proofs = tree.batch_get_proofs(extract_first(chal));

    auto required_elements = get_requeired_elements(f, extract_first(chal), shard_size);


    // return Proof(mu, sigma, merkle_proof, sig_mht, extract_first(chal));
    auto indices = extract_first(chal);
    return Proof(mu, sigma, merkle_proofs, required_elements, tree.get_root_hash(), sig_mht, indices);
}

bool authentication(Proof &proof, bls_pkc& pkc){
    element_t temp1, temp2;
    element_t g_alpha;
    element_t hash_mht;
    element_init_G1(hash_mht, PAIRING);
    element_init_G2(g_alpha, PAIRING);
    element_set(g_alpha, pkc.g);
    element_pow_zn(g_alpha, g_alpha, pkc.sk->alpha);
    element_init_GT(temp1, PAIRING);
    element_init_GT(temp2, PAIRING);

    // auto[flag, hash_mht_vector] = verify_merkle_proof(proof.merkle_proofs.second, proof.indices);
    bool flag = MerkleTree::batch_verify_proofs(proof.merkle_proofs, proof.root_hash);


    if (!flag) return false;
    element_from_hash(hash_mht, proof.root_hash.data(), proof.root_hash.size());

    element_pairing(temp1, proof.sig_mht, pkc.g);
    element_pairing(temp2, hash_mht, g_alpha);
    bool result = !element_cmp(temp1, temp2);

    element_clear(temp1);
    element_clear(temp2);
    element_clear(g_alpha);
    element_clear(hash_mht);

    return result;
}

element_t* calculate_product_proof(const std::vector<element_t*>& m_hashes, const std::vector<std::pair<size_t, element_t*>>& chal) { 

    // 参数检查
    if (m_hashes.empty() || chal.empty()) {
        throw std::invalid_argument("Input vectors cannot be empty");
    }
    if (m_hashes.size() != chal.size()) {
        throw std::invalid_argument("m_hashes and chal sizes must match");
    }

    // 初始化结果
    element_t* result = (element_t*)malloc(sizeof(element_t));
    element_init_G1(*result, PAIRING);
    element_set1(*result);  // 初始化为乘法单位元

    // 临时变量
    element_t temp;
    element_init_G1(temp, PAIRING);

    try {
        for (size_t i = 0; i < chal.size(); ++i) {
            // 获取当前项的 ν_i
            element_t* v_i = chal[i].second;

            // 计算 H(m_i)^{ν_i}
            element_pow_zn(temp, *m_hashes[i], *v_i);
            // element_printf("H_mi last: %B\n", *m_hashes[i]);
            
            // 累乘到结果
            element_mul(*result, *result, temp);
        }
    } catch (...) {
        // 异常处理
        element_clear(*result);
        element_clear(temp);
        free(result);
        throw;
    }

    // 清理临时变量
    element_clear(temp);


    return result;
}

bool verify(bls_pkc& pkc, std::vector<std::pair<size_t, element_t*>>& chal, Proof &proof,element_t u){  
    // std::cout << "authentication: " << authentication(proof, pkc) << std::endl;
    // 1. merkle hash root 验证以及身份验证
    if (!authentication(proof, pkc)) return false;
    // element_printf("u: %B\n", u);

    // 2. 证明验证
    element_t temp1, temp2;
    element_t temp3;
    element_t test_temp;
    
    element_init_GT(temp1, PAIRING);
    element_init_GT(temp2, PAIRING);
    element_init_G1(temp3, PAIRING);
    element_init_G1(test_temp, PAIRING);

    element_pairing(temp1, proof.sigma, pkc.g);
    // auto temp4 = calculate_product_proof(proof.merkle_proofs.first, chal);
    auto temp4 = calculate_product_proof(proof.required_elements, chal);
    element_pow_zn(temp3, u, proof.mu);
    element_mul(temp3, *temp4, temp3);
    element_pow_zn(test_temp, temp3, pkc.sk->alpha);

    element_pairing(temp2, temp3, pkc.pk->v);

    bool result = !element_cmp(temp1, temp2);
    return result;
}