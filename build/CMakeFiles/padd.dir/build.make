# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/wyh/POS/PADD/PADD01

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/wyh/POS/PADD/PADD01/build

# Include any dependencies generated for this target.
include CMakeFiles/padd.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/padd.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/padd.dir/flags.make

CMakeFiles/padd.dir/test/test.cpp.o: CMakeFiles/padd.dir/flags.make
CMakeFiles/padd.dir/test/test.cpp.o: ../test/test.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wyh/POS/PADD/PADD01/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/padd.dir/test/test.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/padd.dir/test/test.cpp.o -c /home/wyh/POS/PADD/PADD01/test/test.cpp

CMakeFiles/padd.dir/test/test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/padd.dir/test/test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/wyh/POS/PADD/PADD01/test/test.cpp > CMakeFiles/padd.dir/test/test.cpp.i

CMakeFiles/padd.dir/test/test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/padd.dir/test/test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/wyh/POS/PADD/PADD01/test/test.cpp -o CMakeFiles/padd.dir/test/test.cpp.s

CMakeFiles/padd.dir/src/padd_01.cpp.o: CMakeFiles/padd.dir/flags.make
CMakeFiles/padd.dir/src/padd_01.cpp.o: ../src/padd_01.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wyh/POS/PADD/PADD01/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/padd.dir/src/padd_01.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/padd.dir/src/padd_01.cpp.o -c /home/wyh/POS/PADD/PADD01/src/padd_01.cpp

CMakeFiles/padd.dir/src/padd_01.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/padd.dir/src/padd_01.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/wyh/POS/PADD/PADD01/src/padd_01.cpp > CMakeFiles/padd.dir/src/padd_01.cpp.i

CMakeFiles/padd.dir/src/padd_01.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/padd.dir/src/padd_01.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/wyh/POS/PADD/PADD01/src/padd_01.cpp -o CMakeFiles/padd.dir/src/padd_01.cpp.s

CMakeFiles/padd.dir/src/utils.cpp.o: CMakeFiles/padd.dir/flags.make
CMakeFiles/padd.dir/src/utils.cpp.o: ../src/utils.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/wyh/POS/PADD/PADD01/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/padd.dir/src/utils.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/padd.dir/src/utils.cpp.o -c /home/wyh/POS/PADD/PADD01/src/utils.cpp

CMakeFiles/padd.dir/src/utils.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/padd.dir/src/utils.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/wyh/POS/PADD/PADD01/src/utils.cpp > CMakeFiles/padd.dir/src/utils.cpp.i

CMakeFiles/padd.dir/src/utils.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/padd.dir/src/utils.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/wyh/POS/PADD/PADD01/src/utils.cpp -o CMakeFiles/padd.dir/src/utils.cpp.s

# Object files for target padd
padd_OBJECTS = \
"CMakeFiles/padd.dir/test/test.cpp.o" \
"CMakeFiles/padd.dir/src/padd_01.cpp.o" \
"CMakeFiles/padd.dir/src/utils.cpp.o"

# External object files for target padd
padd_EXTERNAL_OBJECTS =

padd: CMakeFiles/padd.dir/test/test.cpp.o
padd: CMakeFiles/padd.dir/src/padd_01.cpp.o
padd: CMakeFiles/padd.dir/src/utils.cpp.o
padd: CMakeFiles/padd.dir/build.make
padd: CMakeFiles/padd.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/wyh/POS/PADD/PADD01/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Linking CXX executable padd"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/padd.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/padd.dir/build: padd

.PHONY : CMakeFiles/padd.dir/build

CMakeFiles/padd.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/padd.dir/cmake_clean.cmake
.PHONY : CMakeFiles/padd.dir/clean

CMakeFiles/padd.dir/depend:
	cd /home/wyh/POS/PADD/PADD01/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/wyh/POS/PADD/PADD01 /home/wyh/POS/PADD/PADD01 /home/wyh/POS/PADD/PADD01/build /home/wyh/POS/PADD/PADD01/build /home/wyh/POS/PADD/PADD01/build/CMakeFiles/padd.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/padd.dir/depend

