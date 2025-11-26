/* Test suite for pmtr tokenizer */
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

/* Include the token definitions */
#define TOK_REPORT                          1
#define TOK_TO                              2
#define TOK_STR                             3
#define TOK_LISTEN                          4
#define TOK_ON                              5
#define TOK_JOB                             6
#define TOK_LCURLY                          7
#define TOK_RCURLY                          8
#define TOK_NAME                            9
#define TOK_CMD                            10
#define TOK_DIR                            11
#define TOK_OUT                            12
#define TOK_IN                             13
#define TOK_ERR                            14
#define TOK_USER                           15
#define TOK_ORDER                          16
#define TOK_ENV                            17
#define TOK_ULIMIT                         18
#define TOK_DISABLED                       19
#define TOK_WAIT                           20
#define TOK_ONCE                           21
#define TOK_NICE                           22
#define TOK_BOUNCE                         23
#define TOK_EVERY                          24
#define TOK_DEPENDS                        25
#define TOK_CPUSET                         26
#define TOK_QUOTEDSTR                      27

/* Forward declaration from tok.c */
int get_tok(char *c_orig, char **c, size_t *bsz, size_t *toksz, int *line);

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) void test_##name(void)
#define RUN_TEST(name) do { \
    printf("Running %s... ", #name); \
    test_##name(); \
    tests_run++; \
    tests_passed++; \
    printf("OK\n"); \
} while(0)

/* Helper to tokenize an entire string and return tokens */
typedef struct {
    int id;
    char tok[256];
} Token;

static int tokenize_all(const char *input, Token *tokens, int max_tokens) {
    char *buf = strdup(input);
    char *c = buf;
    size_t bsz = strlen(buf);
    size_t toksz;
    int line = 1;
    int count = 0;
    int id;

    while ((id = get_tok(buf, &c, &bsz, &toksz, &line)) > 0 && count < max_tokens) {
        tokens[count].id = id;
        if (toksz < 256) {
            strncpy(tokens[count].tok, c, toksz);
            tokens[count].tok[toksz] = '\0';
        }
        c += toksz;
        bsz -= toksz;
        count++;
    }

    free(buf);
    return count;
}

TEST(empty_input) {
    Token tokens[10];
    int count = tokenize_all("", tokens, 10);
    assert(count == 0);
}

TEST(whitespace_only) {
    Token tokens[10];
    int count = tokenize_all("   \t\n  ", tokens, 10);
    assert(count == 0);
}

TEST(comment_only) {
    Token tokens[10];
    int count = tokenize_all("# this is a comment\n", tokens, 10);
    assert(count == 0);
}

TEST(job_keyword) {
    Token tokens[10];
    int count = tokenize_all("job {\n}", tokens, 10);
    assert(count == 3);
    assert(tokens[0].id == TOK_JOB);
    assert(tokens[1].id == TOK_LCURLY);
    assert(tokens[2].id == TOK_RCURLY);
}

TEST(name_keyword) {
    Token tokens[10];
    int count = tokenize_all("name test-job", tokens, 10);
    assert(count == 2);
    assert(tokens[0].id == TOK_NAME);
    assert(tokens[1].id == TOK_STR);
    assert(strcmp(tokens[1].tok, "test-job") == 0);
}

TEST(cmd_keyword) {
    Token tokens[10];
    int count = tokenize_all("cmd /bin/sleep 10", tokens, 10);
    assert(count == 3);
    assert(tokens[0].id == TOK_CMD);
    assert(tokens[1].id == TOK_STR);
    assert(tokens[2].id == TOK_STR);
}

TEST(quoted_string) {
    Token tokens[10];
    int count = tokenize_all("cmd /bin/echo \"hello world\"", tokens, 10);
    assert(count == 3);
    assert(tokens[0].id == TOK_CMD);
    assert(tokens[1].id == TOK_STR);
    assert(tokens[2].id == TOK_QUOTEDSTR);
}

TEST(listen_on) {
    Token tokens[10];
    int count = tokenize_all("listen on udp://127.0.0.1:5555", tokens, 10);
    assert(count == 3);
    assert(tokens[0].id == TOK_LISTEN);
    assert(tokens[1].id == TOK_ON);
    assert(tokens[2].id == TOK_STR);
}

TEST(report_to) {
    Token tokens[10];
    int count = tokenize_all("report to udp://192.168.1.1:6666", tokens, 10);
    assert(count == 3);
    assert(tokens[0].id == TOK_REPORT);
    assert(tokens[1].id == TOK_TO);
    assert(tokens[2].id == TOK_STR);
}

TEST(disabled) {
    Token tokens[10];
    int count = tokenize_all("disable", tokens, 10);
    assert(count == 1);
    assert(tokens[0].id == TOK_DISABLED);
}

TEST(wait_once) {
    Token tokens[10];
    int count = tokenize_all("wait\nonce", tokens, 10);
    assert(count == 2);
    assert(tokens[0].id == TOK_WAIT);
    assert(tokens[1].id == TOK_ONCE);
}

TEST(env_var) {
    Token tokens[10];
    int count = tokenize_all("env FOO=bar", tokens, 10);
    assert(count == 2);
    assert(tokens[0].id == TOK_ENV);
    assert(tokens[1].id == TOK_STR);
    assert(strcmp(tokens[1].tok, "FOO=bar") == 0);
}

TEST(ulimit) {
    Token tokens[10];
    int count = tokenize_all("ulimit -n 1024", tokens, 10);
    assert(count == 3);
    assert(tokens[0].id == TOK_ULIMIT);
    assert(tokens[1].id == TOK_STR);
    assert(tokens[2].id == TOK_STR);
}

TEST(nice) {
    Token tokens[10];
    int count = tokenize_all("nice -5", tokens, 10);
    assert(count == 2);
    assert(tokens[0].id == TOK_NICE);
    assert(tokens[1].id == TOK_STR);
}

TEST(cpu) {
    Token tokens[10];
    int count = tokenize_all("cpu 0x0f", tokens, 10);
    assert(count == 2);
    assert(tokens[0].id == TOK_CPUSET);
    assert(tokens[1].id == TOK_STR);
}

TEST(bounce_every) {
    Token tokens[10];
    int count = tokenize_all("bounce every 1h", tokens, 10);
    assert(count == 3);
    assert(tokens[0].id == TOK_BOUNCE);
    assert(tokens[1].id == TOK_EVERY);
    assert(tokens[2].id == TOK_STR);
}

TEST(depends) {
    Token tokens[10];
    /* Note: } must be on its own line (preceded by newline) to be recognized as RCURLY */
    int count = tokenize_all("depends { file1.txt file2.txt\n}", tokens, 10);
    assert(count == 5);
    assert(tokens[0].id == TOK_DEPENDS);
    assert(tokens[1].id == TOK_LCURLY);
    assert(tokens[2].id == TOK_STR);
    assert(tokens[3].id == TOK_STR);
    assert(tokens[4].id == TOK_RCURLY);
}

TEST(full_job) {
    const char *config =
        "job {\n"
        "  name test-service\n"
        "  cmd /usr/bin/sleep 3600\n"
        "  dir /tmp\n"
        "  user nobody\n"
        "  env PATH=/usr/bin\n"
        "  nice 5\n"
        "}\n";
    Token tokens[50];
    int count = tokenize_all(config, tokens, 50);

    /* Verify we got all expected tokens */
    assert(count >= 15);
    assert(tokens[0].id == TOK_JOB);
    assert(tokens[1].id == TOK_LCURLY);
    assert(tokens[2].id == TOK_NAME);
}

TEST(multiple_jobs) {
    const char *config =
        "job {\n"
        "  name job1\n"
        "  cmd /bin/true\n"
        "}\n"
        "job {\n"
        "  name job2\n"
        "  cmd /bin/false\n"
        "}\n";
    Token tokens[50];
    int count = tokenize_all(config, tokens, 50);

    /* Count job keywords */
    int job_count = 0;
    for (int i = 0; i < count; i++) {
        if (tokens[i].id == TOK_JOB) job_count++;
    }
    assert(job_count == 2);
}

TEST(line_counting) {
    char *buf = strdup("job\n\n\nname");
    char *c = buf;
    size_t bsz = strlen(buf);
    size_t toksz;
    int line = 1;

    int id = get_tok(buf, &c, &bsz, &toksz, &line);
    assert(id == TOK_JOB);
    c += toksz; bsz -= toksz;

    id = get_tok(buf, &c, &bsz, &toksz, &line);
    assert(id == TOK_NAME);
    assert(line == 4);  /* Should be on line 4 after skipping newlines */

    free(buf);
}

int main(void) {
    printf("=== pmtr tokenizer tests ===\n\n");

    RUN_TEST(empty_input);
    RUN_TEST(whitespace_only);
    RUN_TEST(comment_only);
    RUN_TEST(job_keyword);
    RUN_TEST(name_keyword);
    RUN_TEST(cmd_keyword);
    RUN_TEST(quoted_string);
    RUN_TEST(listen_on);
    RUN_TEST(report_to);
    RUN_TEST(disabled);
    RUN_TEST(wait_once);
    RUN_TEST(env_var);
    RUN_TEST(ulimit);
    RUN_TEST(nice);
    RUN_TEST(cpu);
    RUN_TEST(bounce_every);
    RUN_TEST(depends);
    RUN_TEST(full_job);
    RUN_TEST(multiple_jobs);
    RUN_TEST(line_counting);

    printf("\n=== Results: %d/%d tests passed ===\n", tests_passed, tests_run);
    return tests_passed == tests_run ? 0 : 1;
}
