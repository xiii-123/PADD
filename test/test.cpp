#include <gtest/gtest.h>
#include "padd.h"



TEST(BlsTest, generate) {
    bls_pkc *pkc = key_gen();
    // EXPECT_EQ
}


int main(int argc, char **argv) {
    printf("Running main() from %s\n", __FILE__);
    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();   
}