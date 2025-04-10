#include <vrf.h>
#include <padd.h>
#include <pbc/pbc.h>
#include <vector>
#include <algorithm>
#include <string>
#include <functional>
#include <numeric>
#include <random>
#include <sstream>
#include <iomanip>


std::pair<element_t*, std::pair<element_t*, element_t*>> gen(){
    pairing_init_set_buf(PAIRING, TYPEA_PARAMS, sizeof(TYPEA_PARAMS));
    element_t* sk = (element_t*)malloc(sizeof(element_t));
    element_t* g = (element_t*)malloc(sizeof(element_t));
    element_t* pk = (element_t*)malloc(sizeof(element_t));
 
    element_init_Zr(*sk, PAIRING);
    element_init_G1(*g, PAIRING);
    element_init_G1(*pk, PAIRING);

    element_random(*g);
    element_pow_zn(*pk, *g, *sk);

    return std::make_pair(sk, std::make_pair(g, pk));
}

std::pair<element_t*, element_t*> prove_sk(std::string random_seed, element_t* sk, element_t* g){
    element_t x;
    element_t power;
    element_t* y = (element_t*)malloc(sizeof(element_t));
    element_t* pi = (element_t*)malloc(sizeof(element_t));

    element_init_Zr(x, PAIRING);
    element_init_Zr(power, PAIRING);
    element_init_GT(*y, PAIRING);
    element_init_G1(*pi, PAIRING);

    element_from_hash(x, random_seed.data(), random_seed.size());
    element_set1(power);

    element_add(x, x, *sk);
    element_div(power, power, x);

    element_pairing(*y, *g, *g);
    element_pow_zn(*y, *y, power);

    element_pow_zn(*pi, *g, power);

    return std::pair(y, pi);
}

bool ver_pk(std::string random_seed, element_t* y, element_t* pi, element_t* pk, element_t* g){
    element_t x;
    element_t temp1;
    element_t temp2;
    element_t temp3;
    element_t temp4;

    element_init_Zr(x, PAIRING);
    element_init_G1(temp1, PAIRING);
    element_init_GT(temp2, PAIRING);
    element_init_GT(temp3, PAIRING);
    element_init_GT(temp4, PAIRING);

    element_from_hash(x, random_seed.data(), random_seed.size());

    element_pow_zn(temp1, *g, x);
    element_mul(temp1, temp1, *pk);

    element_pairing(temp2, temp1, *pi);

    element_pairing(temp3, *g, *g);

    if (element_cmp(temp2, temp3)) return false;

    element_pairing(temp4, *g, *pi);
    if (element_cmp(*y, temp4)) return false;

    element_clear(x);
    element_clear(temp1);
    element_clear(temp2);
    element_clear(temp3);
    element_clear(temp4);
    return true;
}

std::string serialize_vrf_pair(const std::pair<element_t*, element_t*>& pair) {
    // 计算每个元素序列化后的大小
    size_t y_size = element_length_in_bytes(*pair.first);
    size_t pi_size = element_length_in_bytes(*pair.second);
    
    // 分配足够大的缓冲区
    std::vector<unsigned char> buffer(y_size + pi_size);
    size_t offset = 0;
    
    // 序列化 y (GT元素)
    offset += element_to_bytes(buffer.data() + offset, *pair.first);
    
    // 序列化 pi (G1元素)
    offset += element_to_bytes(buffer.data() + offset, *pair.second);
    
    // 将二进制数据转换为十六进制字符串
    std::ostringstream oss;
    oss << std::hex;
    for (unsigned char byte : buffer) {
        oss << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    
    return oss.str();
}

std::pair<element_t*, element_t*> deserialize_vrf_pair(const std::string& str) {
    // 检查字符串长度是否为偶数 (每个字节用2个十六进制字符表示)
    if (str.size() % 2 != 0) {
        throw std::invalid_argument("Invalid serialized string length");
    }
    
    // 将十六进制字符串转换回二进制数据
    std::vector<unsigned char> buffer(str.size() / 2);
    for (size_t i = 0; i < buffer.size(); ++i) {
        std::string byte_str = str.substr(2*i, 2);
        buffer[i] = static_cast<unsigned char>(std::stoi(byte_str, nullptr, 16));
    }
    
    // 分配并初始化元素
    element_t* y = (element_t*)malloc(sizeof(element_t));
    element_t* pi = (element_t*)malloc(sizeof(element_t));
    element_init_GT(*y, PAIRING);
    element_init_G1(*pi, PAIRING);
    
    // 反序列化 y (GT元素)
    size_t offset = 0;
    offset += element_from_bytes(*y, buffer.data() + offset);
    
    // 反序列化 pi (G1元素)
    offset += element_from_bytes(*pi, buffer.data() + offset);
    
    // 检查是否成功读取了所有数据
    if (offset != buffer.size()) {
        element_clear(*y);
        element_clear(*pi);
        delete y;
        delete pi;
        throw std::runtime_error("Deserialization incomplete");
    }
    
    return {y, pi};
}

std::vector<size_t> random_from_vrf(std::string vrf_str, size_t n, size_t k) {
    // 参数检查
    if (n == 0 || k == 0 || k > n) {
        return {};
    }

    // 使用VRF字符串作为种子生成哈希值
    std::hash<std::string> hasher;
    size_t seed = hasher(vrf_str);

    // 使用种子初始化伪随机数生成器
    std::mt19937_64 engine(seed);
    
    // 生成Fisher-Yates洗牌算法的变体，只选取前k个元素
    std::vector<size_t> result(n);
    std::iota(result.begin(), result.end(), 0); // 填充0到n-1
    
    for (size_t i = 0; i < k; ++i) {
        // 在[i, n-1]范围内生成随机索引
        std::uniform_int_distribution<size_t> dist(i, n - 1);
        size_t j = dist(engine);
        
        // 交换当前位置和随机位置的元素
        std::swap(result[i], result[j]);
    }
    
    // 只保留前k个元素并排序
    result.resize(k);
    std::sort(result.begin(), result.end());
    
    return result;
}