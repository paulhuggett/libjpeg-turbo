set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR RISC-V)
set(CMAKE_TRY_COMPILE_TARGET_TYPE   STATIC_LIBRARY)

set(CMAKE_C_COMPILER    clang)
set(CMAKE_C_CPP         clang-cpp)
set(CMAKE_AR            llvm-ar)
set(CMAKE_ASM_COMPILER  clang)
set(CMAKE_OBJCOPY       llvm-objcopy)
set(CMAKE_OBJDUMP       llvm-objdump)
set(CMAKE_RANLIB        llvm-ranlib)
set(CMAKE_SIZE          llvm-size)
set(CMAKE_STRIP         llvm-strip)

option(COMPILATION_OPTION_ARCH_EXT_M "Risc-V extension M (Multiplication and Division)" On)
option(COMPILATION_OPTION_ARCH_EXT_A "Risc-V extension A (Atomic)"                      On)
option(COMPILATION_OPTION_ARCH_EXT_F "Risc-V extension F (Float simple precision)"      Off)
option(COMPILATION_OPTION_ARCH_EXT_D "Risc-V extension D (Float double precision)"      Off)
option(COMPILATION_OPTION_ARCH_EXT_C "Risc-V extension C (Compress)"                    Off)

set(KEYSOM_ABI_DEFAULT  "ilp32")
set(KEYSOM_ABI_LIST     ilp32 ilp32f ilp32d)

set(COMPILATION_OPTION_ABI "${KEYSOM_ABI_DEFAULT}" CACHE STRING "ABI")
set_property(CACHE COMPILATION_OPTION_ABI PROPERTY STRINGS ${KEYSOM_ABI_LIST})

set(COMPILATION_OPTION_ARCH_ISA_SPEC "2.2" CACHE STRING "")
set_property(CACHE COMPILATION_OPTION_ARCH_ISA_SPEC PROPERTY STRINGS "2.2")

set(CMAKE_C_STANDARD "23" CACHE STRING "")
set_property(CACHE CMAKE_C_STANDARD PROPERTY STRINGS "90" "99" "11" "17" "20" "23")
option(CMAKE_C_EXTENSIONS  "compiler specific extensions are requested"  "OFF")
set(CMAKE_C_STANDARD_REQUIRED ON)

# adjust the default behavior of the FIND_XXX() commands:
# search programs in the host environment
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)

set(CMAKE_BUILD_TYPE "DEBUG" CACHE STRING "RELEASE or DEBUG or RELWITHDEBINFO or MINSIZEREL")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "RELEASE;DEBUG;RELWITHDEBINFO;MINSIZEREL")

if(NOT DEFINED PICOLIBC_PRINTF_SCANF)
  set(PICOLIBC_PRINTF_SCANF "DOUBLE")
endif()
set(PICOLIBC_PRINTF_SCANF "${PICOLIBC_PRINTF_SCANF}" CACHE STRING "Support for double, float, long long, integer or
minimal")
set_property(CACHE PICOLIBC_PRINTF_SCANF PROPERTY STRINGS "DOUBLE;FLOAT;LONG_LONG;INTEGER;MINIMAL")

# This function generates the correct string to be passed to the compiler's -march switch.
# The result depends on the user's COMPILATION_OPTION_ARCH_EXT_? option flags above.
# Result is returned in the first argument.
function(arch_flag RESULT)
  set(ARCH "rv32i")
  if(COMPILATION_OPTION_ARCH_EXT_M)
    string(APPEND ARCH m)
  endif()
  if(COMPILATION_OPTION_ARCH_EXT_A)
    string(APPEND ARCH a)
  endif()
  if(COMPILATION_OPTION_ARCH_EXT_F)
    string(APPEND ARCH f)
  endif()
  if(COMPILATION_OPTION_ARCH_EXT_D)
    string(APPEND ARCH d)
  endif()
  if(COMPILATION_OPTION_ARCH_EXT_C)
    string(APPEND ARCH c)
  endif()
  set(${RESULT} "${ARCH}" PARENT_SCOPE)
endfunction(arch_flag)

# Use a function here so that local variables don't pollute the global namespace.
function (generate_compilation_flags)
  # Where is clang? We'll locate includes and libraries relative to the binary.
  find_program(clang_path NAMES "${CMAKE_C_COMPILER}" "${CMAKE_CXX_COMPILER}" REQUIRED)

  # Get the directory in which the clang binary lives.
  cmake_path(GET clang_path PARENT_PATH clang_path)

  arch_flag(arch) # The value for -march is returned in ${arch}
  # The basic collection of compiler switches
  string(JOIN " " flags
    -march=${arch}
    -mabi=${COMPILATION_OPTION_ABI}
    -idirafter "${clang_path}/../picolibc/rv32-keysom/include"
    -D_GNU_SOURCE
    -DNO_GETENV
    -DNO_PUTENV
  )

  set(CMAKE_C_FLAGS   ${flags} PARENT_SCOPE)
  set(CMAKE_ASM_FLAGS ${flags} PARENT_SCOPE)

  set(CMAKE_C_FLAGS_DEBUG          "-O0 -g"          PARENT_SCOPE)
  set(CMAKE_C_FLAGS_RELEASE        "-O3 -DNDEBUG"    PARENT_SCOPE)
  set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O2 -g -DNDEBUG" PARENT_SCOPE)
  set(CMAKE_C_FLAGS_MINSIZEREL     "-Os -DNDEBUG -g" PARENT_SCOPE)

  set(CMAKE_C_COMPILER_TARGET riscv32-unknown-elf PARENT_SCOPE)

  string(JOIN " " exe_linker_flags
    -Wl,-Map,${CMAKE_PROJECT_NAME}.map
    -Wl,--gc-sections
    -T "${PROJECT_SOURCE_DIR}/spike.ld"
    -nostdlib
    -L "${clang_path}/../picolibc/rv32-keysom/lib"
    -lc
    /Users/paul/compiler-build/install/lib/keysom/libclang_rt.builtins-riscv32.a
    /Users/paul/compiler-build/install/picolibc/rv32-keysom/lib/crt0-semihost.o
  )
  set(CMAKE_EXE_LINKER_FLAGS ${exe_linker_flags} PARENT_SCOPE)
endfunction(generate_compilation_flags)

generate_compilation_flags()
