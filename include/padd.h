#pragma once

#include "bls_utils.h"
#include "file_utils.hpp"
#include <utility>
#include <memory>

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


class Proof{
    public: 
        element_t mu;
        element_t sigma;
        // std::pair<std::vector<element_t*>, std::vector<std::vector<std::vector<char>>>> merkle_proofs;
        std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> merkle_proofs;
        std::vector<element_t*> required_elements;
        std::vector<size_t> indices;
        element_t sig_mht;
        std::string root_hash;
        Proof();
        // Proof(element_t* mu, element_t* sigma, 
        //     std::pair<std::vector<element_t*>, std::vector<std::vector<std::vector<char>>>> &merkle_proofs, 
        //     element_t* sig_mht, std::vector<size_t> indices);
        Proof(element_t* mu, element_t* sigma, 
            std::unordered_map<size_t, std::vector<std::pair<std::string, bool>>> &merkle_proofs, 
            std::vector<element_t*>& required_elements,
            std::string root_hash,
            element_t* sig_mht, std::vector<size_t>& indices);
        ~Proof();
        std::vector<std::byte> Proof_serialize();
};

Proof Proof_deserialize(const std::vector<std::byte>& buf);

element_t* sig_init();

std::string construct_t(bls_pkc& pkc, const std::string& file_name, size_t n,  element_t u);

void calculate_single_sigma(std::fstream& f, size_t start, size_t num, bls_pkc& pkc, element_t u, element_t sigma);

// std::shared_ptr<std::vector<element_t *>> calculate_phi(std::fstream& f, bls_pkc& pkc, element_t u, size_t shard_size);
std::vector<element_t *> calculate_phi(std::fstream& f, bls_pkc& pkc, element_t u, size_t shard_size);

void free_phi(std::vector<element_t *>& phi);

std::pair<std::pair<std::string, element_t*>, std::vector <element_t*>> 
sig_gen(bls_pkc& pkc, std::string file_name, std::fstream& f, MerkleTree&, size_t shard_size);

std::pair<bool, element_t*> deserialize_t(std::string t, element_t g, element_t pk);

std::vector<std::pair<size_t, element_t*>> gen_chal(size_t n);

void free_chal(std::vector<std::pair<size_t, element_t*>>& challenges);

std::vector<char> serialize_chal(const std::vector<std::pair<size_t, element_t*>>& chal);

void free_pkc(bls_pkc* pkc);

void free_element_ptr(element_t* t);

bls_pkc* key_gen();

std::vector<std::byte> chal_serialize(const std::vector<std::pair<size_t, element_t*>>& challenges);

std::vector<std::pair<size_t, element_t*>> chal_deserialize(const std::vector<std::byte>& buf);

void padd_init(element_t pk, element_t sk, element_t g);

std::vector<size_t> extract_first(const std::vector<std::pair<size_t, element_t*>>& chal);

Proof gen_proof(std::fstream& f,
    std::vector<element_t *>& phi, 
    std::vector<std::pair<size_t, element_t*>>& chal, 
    element_t* sig_mht,
    MerkleTree& tree,
    size_t shard_size
);

bool verify(bls_pkc& pkc, 
    std::vector<std::pair<size_t, element_t*>>& chal, 
    Proof &proof,
    element_t u
);

std::vector<std::byte> bls_pkc_serialize(bls_pkc* pkc);

bls_pkc* bls_pkc_deserialize(const std::vector<std::byte>& buf);