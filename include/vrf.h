#pragma once

#include <utility>
#include <memory>
#include <pbc/pbc.h>
#include <vector>

std::pair<element_t*, std::pair<element_t*, element_t*>>gen();

std::pair<element_t*, element_t*> prove_sk(std::string x, element_t* sk, element_t* g);

bool ver_pk(std::string x, element_t* y, element_t* pi, element_t* pk, element_t* g);

std::string serialize_vrf_pair(const std::pair<element_t*, element_t*>& pair);

std::pair<element_t*, element_t*> deserialize_vrf_pair(const std::string& str);

std::vector<size_t> random_from_vrf(std::string vrf_str, size_t n, size_t k);