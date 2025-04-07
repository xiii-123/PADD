#pragma once

#include "bls_utils.h"
#include "file_utils.h"
#include <utility>
#include <memory>


class Proof{
    public: 
        element_t mu;
        element_t sigma;
        std::pair<std::vector<element_t*>, std::vector<std::vector<std::vector<char>>>> merkle_proofs;
        std::vector<size_t> indices;
        element_t sig_mht;
        Proof();
        Proof(element_t* mu, element_t* sigma, 
            std::pair<std::vector<element_t*>, std::vector<std::vector<std::vector<char>>>> &merkle_proofs, 
            element_t* sig_mht, std::vector<size_t> indices);
        ~Proof();
};

element_t* sig_init();

std::string construct_t(bls_pkc& pkc, const std::string& file_name, size_t n,  element_t u);

void calculate_sigma(std::fstream& f, size_t start, size_t num, bls_pkc& pkc, element_t u, element_t sigma);

std::shared_ptr<std::vector<element_t *>> calculate_phi(std::fstream& f, bls_pkc& pkc, element_t u, size_t shard_size);

void free_phi(std::shared_ptr<std::vector<element_t*>>& phi);

std::pair<std::pair<std::string, element_t*>, std::shared_ptr<std::vector <element_t*>>> 
sig_gen(bls_pkc& pkc, std::string file_name, std::fstream& f, size_t shard_size);

std::pair<bool, element_t*> deserialize_t(std::string t, element_t g, element_t pk);

std::vector<std::pair<size_t, element_t*>> gen_chal(size_t n);

void free_chal(std::vector<std::pair<size_t, element_t*>>& challenges);

std::vector<char> serialize_chal(const std::vector<std::pair<size_t, element_t*>>& chal);

void padd_clear(bls_pkc* pkc);

void free_element_ptr(element_t* t);

bls_pkc* key_gen();

void padd_init(element_t pk, element_t sk, element_t g);

std::vector<size_t> extract_first(const std::vector<std::pair<size_t, element_t*>>& chal);

Proof gen_proof(std::fstream& f,
    std::shared_ptr<std::vector<element_t *>> &&phi, 
    std::vector<std::pair<size_t, element_t*>>& chal, 
    element_t* sig_mht,
    std::vector<size_t> indices,
    size_t shard_size
);

bool verify(bls_pkc& pkc, 
    std::vector<std::pair<size_t, element_t*>>& chal, 
    Proof &proof,
    element_t u
);