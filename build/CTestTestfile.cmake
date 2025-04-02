# CMake generated Testfile for 
# Source directory: /home/wyh/POS/PADD/PADD01
# Build directory: /home/wyh/POS/PADD/PADD01/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(padd_01_test "/home/wyh/POS/PADD/PADD01/build/bin/padd_01_test")
set_tests_properties(padd_01_test PROPERTIES  _BACKTRACE_TRIPLES "/home/wyh/POS/PADD/PADD01/CMakeLists.txt;116;add_test;/home/wyh/POS/PADD/PADD01/CMakeLists.txt;0;")
subdirs("lib/googletest")
