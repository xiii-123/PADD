#include "padd.h"
#include <iostream>
#include <filesystem>

namespace fs = std::filesystem;

void print_vector_as_hex(const std::vector<char>& vec) {
    for (size_t i = 0; i < vec.size(); ++i) {
        // 使用std::hex设置输出格式为16进制
        // 使用std::setw(2)确保每个16进制数占用至少2个字符的宽度，不足的前面补0
        // 使用std::setfill('0')设置填充字符为'0'
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(static_cast<unsigned char>(vec[i]));
        // 在每个16进制数后面添加一个空格，以便于阅读
    }
    // 输出换行符，完成输出
    std::cout << std::endl;
}

int main() {
    bls_pkc *pkc = key_gen();
    element_printf("sk: %B\npk: %B\ng: %B\n", pkc->sk->ssk, pkc->pk->spk, pkc->g);

    element_t* sig = sig_init();
    std::string s1 = "hello,world!";
    sign_message(pkc->sk->ssk, s1, *sig);

    // printf("产生签名\n"); 
    // element_printf("sig: %B\n", sig);

    int result = verify_signature(*sig, pkc->g, pkc->pk->spk, s1);
    // printf("验证签名:%d\n", result);

    std::string filePath = "../data/hello.txt";
    std::fstream f(filePath, std::ios::binary|std::ios::in);
    if (!f.is_open()) {
        std::cerr << "无法打开文件" << std::endl;
        return 1;
    }

    auto [pair_result, phi] = sig_gen(*pkc, fs::absolute(filePath).string(), f, 4096);
    auto [t, mht_sig] = pair_result;
    std::cout << "t:" << t << std::endl;

    element_printf("mht_sig: %B\n", mht_sig);

    // int i = 0;
    // for (auto element : *(phi)) {
    //     element_printf("sigma%d: %B\n", ++i, *element);
    // }

    auto[flag, u] = deserialize_t(t, pkc->g, pkc->pk->spk);
    if (!false){
        element_printf("u in main: %B\n", u);
    }

    auto chal = gen_chal(1);

    for (auto i : chal){
        element_printf("v_i in chal: %B\n", i.second);
    }
   

    for (int i = 0; i < chal.size(); i++){
        std::cout << chal[i].first << std::endl;
    }
    auto nums = extract_first(chal);

    
    
     // 使用解析结果
    // for (const auto& pair : parsed) {
    //     std::cout << "in main---" << "num:" << pair.first;
    //     element_printf(", random: %B\n", pair.second);
    // }

    auto merkle_root = calculate_merkle_root(f, 4096);
    // std::cout << "merkle root: ";
    // print_vector_as_hex(merkle_root);

    // std::vector<size_t> nums = {0, 1};
    

    auto shard_pairs = calculate_merkle_proof(f, nums, 4096);



    // std::cout << "merkle proof: \n";
    // for (int i = 0; i < shard_pairs.first.size(); i++){
    //     std::cout << "shard_hash: ";
    //     print_vector_as_hex(shard_pairs.first[i]);
    //     std::cout << "merkle proof :";
    //     for (auto proof : shard_pairs.second[i]){
    //         print_vector_as_hex(proof);
    //     }
    // }

    auto[merkle_result_1, merkle_root_1] = verify_merkle_proof(shard_pairs.second, nums);
    std::cout << "result: " << merkle_result_1 << std::endl;


    auto proof = gen_proof(f, std::move(phi), chal, mht_sig, nums, 4096);


    element_printf("mu: %B\n", proof.mu);
    element_printf("sigma: %B\n", proof.sigma);
    auto[merkle_result_2, merkle_root_2] = verify_merkle_proof(proof.shard_proofs.second, nums);
    std::cout << "result: " << merkle_result_2 << std::endl;
    element_printf("sig: %B\n", proof.sig_mht);

    auto result3 = verify(*pkc, chal, proof, *u);

    

    std::cout << "verify success: "<< result3 << std::endl;

    sig_clear(sig);
    padd_clear(pkc);

    return 0;
}