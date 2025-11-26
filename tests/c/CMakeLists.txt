cmake_minimum_required(VERSION 3.11.4)

# Add the tokenizer test
add_executable(test_tok test_tok.c ../../src/tok.c)
target_include_directories(test_tok PRIVATE ../../src ../../src/include)

enable_testing()
add_test(NAME tokenizer_tests COMMAND test_tok)
