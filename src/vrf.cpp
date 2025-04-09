#include <vrf.h>
#include <padd.h>
#include <pbc/pbc.h>


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