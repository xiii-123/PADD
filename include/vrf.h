#pragma once

#include <utility>
#include <memory>
#include <pbc/pbc.h>

std::pair<element_t*, std::pair<element_t*, element_t*>>gen();

std::pair<element_t*, element_t*> prove_sk(std::string x, element_t* sk, element_t* g);

bool ver_pk(std::string x, element_t* y, element_t* pi, element_t* pk, element_t* g);