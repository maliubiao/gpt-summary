Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of `stdio_test.cpp` from Android's Bionic library. This section of the test suite focuses on various standard input/output (stdio) functions.

Here's a breakdown of the functions being tested in this snippet:

1. **`popen()` and `pclose()`:**  Testing the execution of shell commands and retrieval of their exit status and signal information.
2. **`getc()`:** Testing reading a single character from a file.
3. **`putc()`:** Testing writing a single character to a file (and verifying errors for read-only files).
4. **`sscanf()` and `swscanf()`:** Testing formatted input from strings, including:
    *   Basic parsing of strings, integers, characters, and floating-point numbers.
    *   Character class matching (`%[...]`).
    *   Dynamic memory allocation for scanned strings and characters (`%m`).
    *   Wide character input.
    *   Suppression of input (`%*`).
    *   Reading up to a certain number of characters.
    *   Handling of EOF and invalid UTF-8 input.
    *   Behavior when no match is found.
    *   Interaction with wide character classes.
5. **`putc()`, `fprintf()`, `fwprintf()`, `fwrite()`, `fputs()`, `fputwc()`:** Testing error handling when attempting to write to a file opened in read-only mode.
6. **`fgetpos()` and `fsetpos()`:** Testing the ability to get and set file positions, particularly with multi-byte characters in UTF-8 encoding.
7. **`fseek()`:** Testing seeking within a file, and its interaction with `fgetpos`/`fsetpos`, particularly around multi-byte characters.
8. **`fmemopen()`:** Testing operations on in-memory streams, including:
    *   Basic read/write.
    *   Handling of null buffers.
    *   Trailing null bytes.
    *   Determining the size of the buffer and how `SEEK_END` behaves.
    *   Handling invalid seek operations.
    *   Behavior when reading past the end of the buffer.
    *   Handling null bytes in the buffer during reads.
    *   Write operations and buffer resizing.
    *   Behavior when writing past the buffer's capacity.
    *   Initial position of the file pointer in different modes.
    *   Handling of zero-length buffers.
    *   Write-only allocated memory streams.
    *   Verification that `fileno()` returns an error for in-memory streams.
    *   Behavior of append mode after seeking.
9. **`open_memstream()`:** Testing the creation of a stream that writes to dynamically allocated memory.

The overall goal of this section of the test is to ensure the correct behavior and robustness of the standard C library's input/output functions within the Android Bionic environment.
这段代码是 Android Bionic 库中 `stdio_test.cpp` 文件的一部分，专门用于测试标准输入/输出（stdio）库函数的各种功能。

**功能归纳：**

这段代码主要集中在测试以下几类 stdio 函数的功能和边界情况：

1. **进程管理相关:**
    *   `popen()` 和 `pclose()`：测试执行外部命令并获取其退出状态的能力，包括正常退出和被信号终止的情况。

2. **字符输入/输出:**
    *   `getc()`：测试从文件中读取单个字符的功能。
    *   `putc()`：测试向文件中写入单个字符的功能，并验证对只读文件的写入操作会返回错误。

3. **格式化输入:**
    *   `sscanf()` 和 `swscanf()`：测试从字符串中解析格式化输入的功能，涵盖了各种格式说明符，包括：
        *   字符串 (`%s`)
        *   整数 (`%i`)
        *   字符 (`%c`)
        *   字符集 (`%[...]`)
        *   动态分配内存的字符串 (`%ms`) 和字符 (`%mc`)
        *   宽字符 (`%ls`, `%lc`, `%mls`, `%mlc`)
        *   忽略输入 (`%*`)

4. **文件操作错误处理:**
    *   测试尝试写入以只读模式打开的文件时，各种写入函数（`putc`, `fprintf`, `fwprintf`, `fwrite`, `fputs`, `fputwc`）是否能正确返回错误（通常是 `EBADF`）。

5. **文件定位:**
    *   `fgetpos()` 和 `fsetpos()`：测试获取和设置文件当前位置的功能，并验证在处理多字节字符（UTF-8）时的正确性。
    *   `fseek()`：测试在文件中进行定位的功能，并验证与 `fgetpos`/`fsetpos` 的交互，特别是在多字节字符的边界情况下。

6. **内存流操作:**
    *   `fmemopen()`：测试在内存中创建和操作流的功能，包括：
        *   基本的读写操作。
        *   处理空指针缓冲区。
        *   写入时在缓冲区末尾添加空字符。
        *   使用 `SEEK_END` 定位到缓冲区末尾。
        *   处理无效的 seek 操作。
        *   读取超过缓冲区末尾的情况。
        *   读取包含空字符的缓冲区。
        *   写入操作以及缓冲区大小的调整。
        *   写入超过缓冲区大小的情况。
        *   不同模式下文件指针的初始位置。
        *   处理零长度的缓冲区。
        *   创建只写模式的内存流。
        *   验证 `fileno()` 对内存流返回错误。
        *   在 `append` 模式下进行 seek 操作后的写入行为。
    *   `open_memstream()`：测试创建可以写入动态分配内存的流的功能。

总而言之，这段代码系统地测试了 C 标准库中与输入输出相关的核心功能，并覆盖了多种使用场景和潜在的错误情况，确保了 Android Bionic 库中这些函数的稳定性和正确性。

Prompt: 
```
这是目录为bionic/tests/stdio_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第2部分，共4部分，请归纳一下它的功能

"""
e_1) {
  FILE* fp = popen("false", "r");
  ASSERT_TRUE(fp != nullptr);
  int status = pclose(fp);
  EXPECT_TRUE(WIFEXITED(status));
  EXPECT_EQ(1, WEXITSTATUS(status));
}

TEST(STDIO_TEST, popen_return_value_signal) {
  // Use a realtime signal to avoid creating a tombstone when running.
  std::string cmd = android::base::StringPrintf("kill -%d $$", SIGRTMIN);
  FILE* fp = popen(cmd.c_str(), "r");
  ASSERT_TRUE(fp != nullptr);
  int status = pclose(fp);
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(SIGRTMIN, WTERMSIG(status));
}

TEST(STDIO_TEST, getc) {
  FILE* fp = fopen("/proc/version", "r");
  ASSERT_TRUE(fp != nullptr);
  ASSERT_EQ('L', getc(fp));
  ASSERT_EQ('i', getc(fp));
  ASSERT_EQ('n', getc(fp));
  ASSERT_EQ('u', getc(fp));
  ASSERT_EQ('x', getc(fp));
  fclose(fp);
}

TEST(STDIO_TEST, putc) {
  FILE* fp = fopen("/proc/version", "r");
  ASSERT_TRUE(fp != nullptr);
  ASSERT_EQ(EOF, putc('x', fp));
  fclose(fp);
}

TEST(STDIO_TEST, sscanf_swscanf) {
  struct stuff {
    char s1[123];
    int i1, i2;
    char cs1[3];
    char s2[3];
    char c1;
    double d1;
    float f1;
    char s3[123];

    void Check() {
      EXPECT_STREQ("hello", s1);
      EXPECT_EQ(123, i1);
      EXPECT_EQ(456, i2);
      EXPECT_EQ('a', cs1[0]);
      EXPECT_EQ('b', cs1[1]);
      EXPECT_EQ('x', cs1[2]); // No terminating NUL.
      EXPECT_STREQ("AB", s2); // Terminating NUL.
      EXPECT_EQ('!', c1);
      EXPECT_DOUBLE_EQ(1.23, d1);
      EXPECT_FLOAT_EQ(9.0f, f1);
      EXPECT_STREQ("world", s3);
    }
  } s;

  memset(&s, 'x', sizeof(s));
  ASSERT_EQ(9, sscanf("  hello 123 456abAB! 1.23 0x1.2p3 world",
                      "%s %i%i%2c%[A-Z]%c %lf %f %s",
                      s.s1, &s.i1, &s.i2, s.cs1, s.s2, &s.c1, &s.d1, &s.f1, s.s3));
  s.Check();

  memset(&s, 'x', sizeof(s));
  ASSERT_EQ(9, swscanf(L"  hello 123 456abAB! 1.23 0x1.2p3 world",
                       L"%s %i%i%2c%[A-Z]%c %lf %f %s",
                       s.s1, &s.i1, &s.i2, s.cs1, s.s2, &s.c1, &s.d1, &s.f1, s.s3));
  s.Check();
}

template <typename T>
static void CheckScanf(int sscanf_fn(const T*, const T*, ...),
                       const T* input, const T* fmt,
                       int expected_count, const char* expected_string) {
  char buf[256] = {};
  ASSERT_EQ(expected_count, sscanf_fn(input, fmt, &buf)) << fmt;
  ASSERT_STREQ(expected_string, buf) << fmt;
}

TEST(STDIO_TEST, sscanf_ccl) {
  // `abc` is just those characters.
  CheckScanf(sscanf, "abcd", "%[abc]", 1, "abc");
  // `a-c` is the range 'a' .. 'c'.
  CheckScanf(sscanf, "abcd", "%[a-c]", 1, "abc");
  CheckScanf(sscanf, "-d", "%[a-c]", 0, "");
  CheckScanf(sscanf, "ac-bAd", "%[a--c]", 1, "ac-bA");
  // `a-c-e` is equivalent to `a-e`.
  CheckScanf(sscanf, "abcdefg", "%[a-c-e]", 1, "abcde");
  // `e-a` is equivalent to `ae-` (because 'e' > 'a').
  CheckScanf(sscanf, "-a-e-b", "%[e-a]", 1, "-a-e-");
  // An initial '^' negates the set.
  CheckScanf(sscanf, "abcde", "%[^d]", 1, "abc");
  CheckScanf(sscanf, "abcdefgh", "%[^c-d]", 1, "ab");
  CheckScanf(sscanf, "hgfedcba", "%[^c-d]", 1, "hgfe");
  // The first character may be ']' or '-' without being special.
  CheckScanf(sscanf, "[[]]x", "%[][]", 1, "[[]]");
  CheckScanf(sscanf, "-a-x", "%[-a]", 1, "-a-");
  // The last character may be '-' without being special.
  CheckScanf(sscanf, "-a-x", "%[a-]", 1, "-a-");
  // X--Y is [X--] + Y, not [X--] + [--Y] (a bug in my initial implementation).
  CheckScanf(sscanf, "+,-/.", "%[+--/]", 1, "+,-/");
}

TEST(STDIO_TEST, swscanf_ccl) {
  // `abc` is just those characters.
  CheckScanf(swscanf, L"abcd", L"%[abc]", 1, "abc");
  // `a-c` is the range 'a' .. 'c'.
  CheckScanf(swscanf, L"abcd", L"%[a-c]", 1, "abc");
  CheckScanf(swscanf, L"-d", L"%[a-c]", 0, "");
  CheckScanf(swscanf, L"ac-bAd", L"%[a--c]", 1, "ac-bA");
  // `a-c-e` is equivalent to `a-e`.
  CheckScanf(swscanf, L"abcdefg", L"%[a-c-e]", 1, "abcde");
  // `e-a` is equivalent to `ae-` (because 'e' > 'a').
  CheckScanf(swscanf, L"-a-e-b", L"%[e-a]", 1, "-a-e-");
  // An initial '^' negates the set.
  CheckScanf(swscanf, L"abcde", L"%[^d]", 1, "abc");
  CheckScanf(swscanf, L"abcdefgh", L"%[^c-d]", 1, "ab");
  CheckScanf(swscanf, L"hgfedcba", L"%[^c-d]", 1, "hgfe");
  // The first character may be ']' or '-' without being special.
  CheckScanf(swscanf, L"[[]]x", L"%[][]", 1, "[[]]");
  CheckScanf(swscanf, L"-a-x", L"%[-a]", 1, "-a-");
  // The last character may be '-' without being special.
  CheckScanf(swscanf, L"-a-x", L"%[a-]", 1, "-a-");
  // X--Y is [X--] + Y, not [X--] + [--Y] (a bug in my initial implementation).
  CheckScanf(swscanf, L"+,-/.", L"%[+--/]", 1, "+,-/");
}

template <typename T1, typename T2>
static void CheckScanfM(int sscanf_fn(const T1*, const T1*, ...),
                        const T1* input, const T1* fmt,
                        int expected_count, const T2* expected_string) {
  T2* result = nullptr;
  ASSERT_EQ(expected_count, sscanf_fn(input, fmt, &result)) << fmt;
  if (expected_string == nullptr) {
    ASSERT_EQ(nullptr, result);
  } else {
    ASSERT_STREQ(expected_string, result) << fmt;
  }
  free(result);
}

TEST(STDIO_TEST, sscanf_mc) {
  char* p1 = nullptr;
  char* p2 = nullptr;
  ASSERT_EQ(2, sscanf("hello", "%mc%mc", &p1, &p2));
  ASSERT_EQ('h', *p1);
  ASSERT_EQ('e', *p2);
  free(p1);
  free(p2);

  p1 = nullptr;
  ASSERT_EQ(1, sscanf("hello", "%4mc", &p1));
  ASSERT_EQ('h', p1[0]);
  ASSERT_EQ('e', p1[1]);
  ASSERT_EQ('l', p1[2]);
  ASSERT_EQ('l', p1[3]);
  free(p1);

  p1 = nullptr;
  ASSERT_EQ(1, sscanf("hello world", "%30mc", &p1));
  ASSERT_EQ('h', p1[0]);
  ASSERT_EQ('e', p1[1]);
  ASSERT_EQ('l', p1[2]);
  ASSERT_EQ('l', p1[3]);
  ASSERT_EQ('o', p1[4]);
  free(p1);
}

TEST(STDIO_TEST, sscanf_mlc) {
  // This is so useless that clang doesn't even believe it exists...
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
#pragma clang diagnostic ignored "-Wformat-extra-args"

  wchar_t* p1 = nullptr;
  wchar_t* p2 = nullptr;
  ASSERT_EQ(2, sscanf("hello", "%mlc%mlc", &p1, &p2));
  ASSERT_EQ(L'h', *p1);
  ASSERT_EQ(L'e', *p2);
  free(p1);
  free(p2);

  p1 = nullptr;
  ASSERT_EQ(1, sscanf("hello", "%4mlc", &p1));
  ASSERT_EQ(L'h', p1[0]);
  ASSERT_EQ(L'e', p1[1]);
  ASSERT_EQ(L'l', p1[2]);
  ASSERT_EQ(L'l', p1[3]);
  free(p1);

  p1 = nullptr;
  ASSERT_EQ(1, sscanf("hello world", "%30mlc", &p1));
  ASSERT_EQ(L'h', p1[0]);
  ASSERT_EQ(L'e', p1[1]);
  ASSERT_EQ(L'l', p1[2]);
  ASSERT_EQ(L'l', p1[3]);
  ASSERT_EQ(L'o', p1[4]);
  free(p1);
#pragma clang diagnostic pop
}

TEST(STDIO_TEST, sscanf_ms) {
  CheckScanfM(sscanf, "hello", "%ms", 1, "hello");
  CheckScanfM(sscanf, "hello", "%4ms", 1, "hell");
  CheckScanfM(sscanf, "hello world", "%30ms", 1, "hello");
}

TEST(STDIO_TEST, sscanf_mls) {
  CheckScanfM(sscanf, "hello", "%mls", 1, L"hello");
  CheckScanfM(sscanf, "hello", "%4mls", 1, L"hell");
  CheckScanfM(sscanf, "hello world", "%30mls", 1, L"hello");
}

TEST(STDIO_TEST, sscanf_m_ccl) {
  CheckScanfM(sscanf, "hello", "%m[a-z]", 1, "hello");
  CheckScanfM(sscanf, "hello", "%4m[a-z]", 1, "hell");
  CheckScanfM(sscanf, "hello world", "%30m[a-z]", 1, "hello");
}

TEST(STDIO_TEST, sscanf_ml_ccl) {
  CheckScanfM(sscanf, "hello", "%ml[a-z]", 1, L"hello");
  CheckScanfM(sscanf, "hello", "%4ml[a-z]", 1, L"hell");
  CheckScanfM(sscanf, "hello world", "%30ml[a-z]", 1, L"hello");
}

TEST(STDIO_TEST, sscanf_ls) {
  wchar_t w[32] = {};
  ASSERT_EQ(1, sscanf("hello world", "%ls", w));
  ASSERT_EQ(L"hello", std::wstring(w));
}

TEST(STDIO_TEST, sscanf_ls_suppress) {
  ASSERT_EQ(0, sscanf("hello world", "%*ls %*ls"));
}

TEST(STDIO_TEST, sscanf_ls_n) {
  setlocale(LC_ALL, "C.UTF-8");
  wchar_t w[32] = {};
  int pos = 0;
  ASSERT_EQ(1, sscanf("\xc4\x80", "%ls%n", w, &pos));
  ASSERT_EQ(static_cast<wchar_t>(256), w[0]);
  ASSERT_EQ(2, pos);
}

TEST(STDIO_TEST, sscanf_ls_realloc) {
  // This is so useless that clang doesn't even believe it exists...
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
#pragma clang diagnostic ignored "-Wformat-extra-args"
  wchar_t* p1 = nullptr;
  wchar_t* p2 = nullptr;
  ASSERT_EQ(2, sscanf("1234567890123456789012345678901234567890 world", "%mls %mls", &p1, &p2));
  ASSERT_EQ(L"1234567890123456789012345678901234567890", std::wstring(p1));
  ASSERT_EQ(L"world", std::wstring(p2));
#pragma clang diagnostic pop
}

// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=202240
TEST(STDIO_TEST, scanf_wscanf_EOF) {
  EXPECT_EQ(0, sscanf("b", "ab"));
  EXPECT_EQ(EOF, sscanf("", "a"));
  EXPECT_EQ(0, swscanf(L"b", L"ab"));
  EXPECT_EQ(EOF, swscanf(L"", L"a"));
}

TEST(STDIO_TEST, scanf_invalid_UTF8) {
#if 0 // TODO: more tests invented during code review; no regressions, so fix later.
  char buf[BUFSIZ];
  wchar_t wbuf[BUFSIZ];

  memset(buf, 0, sizeof(buf));
  memset(wbuf, 0, sizeof(wbuf));
  EXPECT_EQ(0, sscanf("\xc0" " foo", "%ls %s", wbuf, buf));
#endif
}

TEST(STDIO_TEST, scanf_no_match_no_termination) {
  char buf[4] = "x";
  EXPECT_EQ(0, sscanf("d", "%[abc]", buf));
  EXPECT_EQ('x', buf[0]);
  EXPECT_EQ(0, swscanf(L"d", L"%[abc]", buf));
  EXPECT_EQ('x', buf[0]);

  wchar_t wbuf[4] = L"x";
  EXPECT_EQ(0, swscanf(L"d", L"%l[abc]", wbuf));
  EXPECT_EQ(L'x', wbuf[0]);

  EXPECT_EQ(EOF, sscanf("", "%s", buf));
  EXPECT_EQ('x', buf[0]);

  EXPECT_EQ(EOF, swscanf(L"", L"%ls", wbuf));
  EXPECT_EQ(L'x', wbuf[0]);
}

TEST(STDIO_TEST, scanf_wscanf_wide_character_class) {
#if 0 // TODO: more tests invented during code review; no regressions, so fix later.
  wchar_t buf[BUFSIZ];

  // A wide character shouldn't match an ASCII-only class for scanf or wscanf.
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(1, sscanf("xĀyz", "%l[xy]", buf));
  EXPECT_EQ(L"x"s, std::wstring(buf));
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(1, swscanf(L"xĀyz", L"%l[xy]", buf));
  EXPECT_EQ(L"x"s, std::wstring(buf));

  // Even if scanf has wide characters in a class, they won't match...
  // TODO: is that a bug?
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(1, sscanf("xĀyz", "%l[xĀy]", buf));
  EXPECT_EQ(L"x"s, std::wstring(buf));
  // ...unless you use wscanf.
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(1, swscanf(L"xĀyz", L"%l[xĀy]", buf));
  EXPECT_EQ(L"xĀy"s, std::wstring(buf));

  // Negation only covers ASCII for scanf...
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(1, sscanf("xĀyz", "%l[^ab]", buf));
  EXPECT_EQ(L"x"s, std::wstring(buf));
  // ...but covers wide characters for wscanf.
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(1, swscanf(L"xĀyz", L"%l[^ab]", buf));
  EXPECT_EQ(L"xĀyz"s, std::wstring(buf));

  // We already determined that non-ASCII characters are ignored in scanf classes.
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(1, sscanf("x"
                      "\xc4\x80" // Matches a byte from each wide char in the class.
                      "\xc6\x82" // Neither byte is in the class.
                      "yz",
                      "%l[xy" "\xc5\x80" "\xc4\x81" "]", buf));
  EXPECT_EQ(L"x", std::wstring(buf));
  // bionic and glibc both behave badly for wscanf, so let's call it right for now...
  memset(buf, 0, sizeof(buf));
  EXPECT_EQ(1, swscanf(L"x"
                       L"\xc4\x80"
                       L"\xc6\x82"
                       L"yz",
                       L"%l[xy" L"\xc5\x80" L"\xc4\x81" L"]", buf));
  // Note that this isn't L"xĀ" --- although the *bytes* matched, they're
  // not put back together as a wide character.
  EXPECT_EQ(L"x" L"\xc4" L"\x80", std::wstring(buf));
#endif
}

TEST(STDIO_TEST, cantwrite_EBADF) {
  // If we open a file read-only...
  FILE* fp = fopen("/proc/version", "r");

  // ...all attempts to write to that file should return failure.

  // They should also set errno to EBADF. This isn't POSIX, but it's traditional.
  // glibc gets the wide-character functions wrong.

  errno = 0;
  EXPECT_EQ(EOF, putc('x', fp));
  EXPECT_ERRNO(EBADF);

  errno = 0;
  EXPECT_EQ(EOF, fprintf(fp, "hello"));
  EXPECT_ERRNO(EBADF);

  errno = 0;
  EXPECT_EQ(EOF, fwprintf(fp, L"hello"));
#if defined(__BIONIC__)
  EXPECT_ERRNO(EBADF);
#endif

  errno = 0;
  EXPECT_EQ(0U, fwrite("hello", 1, 2, fp));
  EXPECT_ERRNO(EBADF);

  errno = 0;
  EXPECT_EQ(EOF, fputs("hello", fp));
  EXPECT_ERRNO(EBADF);

  errno = 0;
  EXPECT_EQ(WEOF, fputwc(L'x', fp));
#if defined(__BIONIC__)
  EXPECT_ERRNO(EBADF);
#endif
}

// Tests that we can only have a consistent and correct fpos_t when using
// f*pos functions (i.e. fpos doesn't get inside a multi byte character).
TEST(STDIO_TEST, consistent_fpos_t) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  FILE* fp = tmpfile();
  ASSERT_TRUE(fp != nullptr);

  wchar_t mb_one_bytes = L'h';
  wchar_t mb_two_bytes = 0x00a2;
  wchar_t mb_three_bytes = 0x20ac;
  wchar_t mb_four_bytes = 0x24b62;

  // Write to file.
  ASSERT_EQ(mb_one_bytes, static_cast<wchar_t>(fputwc(mb_one_bytes, fp)));
  ASSERT_EQ(mb_two_bytes, static_cast<wchar_t>(fputwc(mb_two_bytes, fp)));
  ASSERT_EQ(mb_three_bytes, static_cast<wchar_t>(fputwc(mb_three_bytes, fp)));
  ASSERT_EQ(mb_four_bytes, static_cast<wchar_t>(fputwc(mb_four_bytes, fp)));

  rewind(fp);

  // Record each character position.
  fpos_t pos1;
  fpos_t pos2;
  fpos_t pos3;
  fpos_t pos4;
  fpos_t pos5;
  EXPECT_EQ(0, fgetpos(fp, &pos1));
  ASSERT_EQ(mb_one_bytes, static_cast<wchar_t>(fgetwc(fp)));
  EXPECT_EQ(0, fgetpos(fp, &pos2));
  ASSERT_EQ(mb_two_bytes, static_cast<wchar_t>(fgetwc(fp)));
  EXPECT_EQ(0, fgetpos(fp, &pos3));
  ASSERT_EQ(mb_three_bytes, static_cast<wchar_t>(fgetwc(fp)));
  EXPECT_EQ(0, fgetpos(fp, &pos4));
  ASSERT_EQ(mb_four_bytes, static_cast<wchar_t>(fgetwc(fp)));
  EXPECT_EQ(0, fgetpos(fp, &pos5));

#if defined(__BIONIC__)
  // Bionic's fpos_t is just an alias for off_t. This is inherited from OpenBSD
  // upstream. Glibc differs by storing the mbstate_t inside its fpos_t. In
  // Bionic (and upstream OpenBSD) the mbstate_t is stored inside the FILE
  // structure.
  ASSERT_EQ(0, static_cast<off_t>(pos1));
  ASSERT_EQ(1, static_cast<off_t>(pos2));
  ASSERT_EQ(3, static_cast<off_t>(pos3));
  ASSERT_EQ(6, static_cast<off_t>(pos4));
  ASSERT_EQ(10, static_cast<off_t>(pos5));
#endif

  // Exercise back and forth movements of the position.
  ASSERT_EQ(0, fsetpos(fp, &pos2));
  ASSERT_EQ(mb_two_bytes, static_cast<wchar_t>(fgetwc(fp)));
  ASSERT_EQ(0, fsetpos(fp, &pos1));
  ASSERT_EQ(mb_one_bytes, static_cast<wchar_t>(fgetwc(fp)));
  ASSERT_EQ(0, fsetpos(fp, &pos4));
  ASSERT_EQ(mb_four_bytes, static_cast<wchar_t>(fgetwc(fp)));
  ASSERT_EQ(0, fsetpos(fp, &pos3));
  ASSERT_EQ(mb_three_bytes, static_cast<wchar_t>(fgetwc(fp)));
  ASSERT_EQ(0, fsetpos(fp, &pos5));
  ASSERT_EQ(WEOF, fgetwc(fp));

  fclose(fp);
}

// Exercise the interaction between fpos and seek.
TEST(STDIO_TEST, fpos_t_and_seek) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  // In glibc-2.16 fseek doesn't work properly in wide mode
  // (https://sourceware.org/bugzilla/show_bug.cgi?id=14543). One workaround is
  // to close and re-open the file. We do it in order to make the test pass
  // with all glibcs.

  TemporaryFile tf;
  FILE* fp = fdopen(tf.fd, "w+");
  ASSERT_TRUE(fp != nullptr);

  wchar_t mb_two_bytes = 0x00a2;
  wchar_t mb_three_bytes = 0x20ac;
  wchar_t mb_four_bytes = 0x24b62;

  // Write to file.
  ASSERT_EQ(mb_two_bytes, static_cast<wchar_t>(fputwc(mb_two_bytes, fp)));
  ASSERT_EQ(mb_three_bytes, static_cast<wchar_t>(fputwc(mb_three_bytes, fp)));
  ASSERT_EQ(mb_four_bytes, static_cast<wchar_t>(fputwc(mb_four_bytes, fp)));

  fflush(fp);
  fclose(fp);

  fp = fopen(tf.path, "r");
  ASSERT_TRUE(fp != nullptr);

  // Store a valid position.
  fpos_t mb_two_bytes_pos;
  ASSERT_EQ(0, fgetpos(fp, &mb_two_bytes_pos));

  // Move inside mb_four_bytes with fseek.
  long offset_inside_mb = 6;
  ASSERT_EQ(0, fseek(fp, offset_inside_mb, SEEK_SET));

  // Store the "inside multi byte" position.
  fpos_t pos_inside_mb;
  ASSERT_EQ(0, fgetpos(fp, &pos_inside_mb));
#if defined(__BIONIC__)
  ASSERT_EQ(offset_inside_mb, static_cast<off_t>(pos_inside_mb));
#endif

  // Reading from within a byte should produce an error.
  ASSERT_EQ(WEOF, fgetwc(fp));
  ASSERT_ERRNO(EILSEQ);

  // Reverting to a valid position should work.
  ASSERT_EQ(0, fsetpos(fp, &mb_two_bytes_pos));
  ASSERT_EQ(mb_two_bytes, static_cast<wchar_t>(fgetwc(fp)));

  // Moving withing a multi byte with fsetpos should work but reading should
  // produce an error.
  ASSERT_EQ(0, fsetpos(fp, &pos_inside_mb));
  ASSERT_EQ(WEOF, fgetwc(fp));
  ASSERT_ERRNO(EILSEQ);

  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen) {
  char buf[16];
  memset(buf, 0, sizeof(buf));
  FILE* fp = fmemopen(buf, sizeof(buf), "r+");
  ASSERT_EQ('<', fputc('<', fp));
  ASSERT_NE(EOF, fputs("abc>\n", fp));
  fflush(fp);

  // We wrote to the buffer...
  ASSERT_STREQ("<abc>\n", buf);

  // And can read back from the file.
  AssertFileIs(fp, "<abc>\n", true);
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_nullptr) {
  FILE* fp = fmemopen(nullptr, 128, "r+");
  ASSERT_NE(EOF, fputs("xyz\n", fp));

  AssertFileIs(fp, "xyz\n", true);
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_trailing_NUL_byte) {
  FILE* fp;
  char buf[8];

  // POSIX: "When a stream open for writing is flushed or closed, a null byte
  // shall be written at the current position or at the end of the buffer,
  // depending on the size of the contents."
  memset(buf, 'x', sizeof(buf));
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "w"));
  // Even with nothing written (and not in truncate mode), we'll flush a NUL...
  ASSERT_EQ(0, fflush(fp));
  EXPECT_EQ("\0xxxxxxx"s, std::string(buf, buf + sizeof(buf)));
  // Now write and check that the NUL moves along with our writes...
  ASSERT_NE(EOF, fputs("hello", fp));
  ASSERT_EQ(0, fflush(fp));
  EXPECT_EQ("hello\0xx"s, std::string(buf, buf + sizeof(buf)));
  ASSERT_NE(EOF, fputs("wo", fp));
  ASSERT_EQ(0, fflush(fp));
  EXPECT_EQ("hellowo\0"s, std::string(buf, buf + sizeof(buf)));
  ASSERT_EQ(0, fclose(fp));

  // "If a stream open for update is flushed or closed and the last write has
  // advanced the current buffer size, a null byte shall be written at the end
  // of the buffer if it fits."
  memset(buf, 'x', sizeof(buf));
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "r+"));
  // Nothing written yet, so no advance...
  ASSERT_EQ(0, fflush(fp));
  EXPECT_EQ("xxxxxxxx"s, std::string(buf, buf + sizeof(buf)));
  ASSERT_NE(EOF, fputs("hello", fp));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_size) {
  FILE* fp;
  char buf[16];
  memset(buf, 'x', sizeof(buf));

  // POSIX: "The stream shall also maintain the size of the current buffer
  // contents; use of fseek() or fseeko() on the stream with SEEK_END shall
  // seek relative to this size."

  // "For modes r and r+ the size shall be set to the value given by the size
  // argument."
  ASSERT_NE(nullptr, fp = fmemopen(buf, 16, "r"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(16, ftell(fp));
  EXPECT_EQ(16, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(16, ftell(fp));
  EXPECT_EQ(16, ftello(fp));
  ASSERT_EQ(0, fclose(fp));
  ASSERT_NE(nullptr, fp = fmemopen(buf, 16, "r+"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(16, ftell(fp));
  EXPECT_EQ(16, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(16, ftell(fp));
  EXPECT_EQ(16, ftello(fp));
  ASSERT_EQ(0, fclose(fp));

  // "For modes w and w+ the initial size shall be zero..."
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 16, "w"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  EXPECT_EQ(0, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  EXPECT_EQ(0, ftello(fp));
  ASSERT_EQ(0, fclose(fp));
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 16, "w+"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  EXPECT_EQ(0, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  EXPECT_EQ(0, ftello(fp));
  ASSERT_EQ(0, fclose(fp));

  // "...and for modes a and a+ the initial size shall be:
  // 1. Zero, if buf is a null pointer
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 16, "a"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  EXPECT_EQ(0, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  EXPECT_EQ(0, ftello(fp));
  ASSERT_EQ(0, fclose(fp));
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 16, "a+"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  EXPECT_EQ(0, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  EXPECT_EQ(0, ftello(fp));
  ASSERT_EQ(0, fclose(fp));

  // 2. The position of the first null byte in the buffer, if one is found
  memset(buf, 'x', sizeof(buf));
  buf[3] = '\0';
  ASSERT_NE(nullptr, fp = fmemopen(buf, 16, "a"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(3, ftell(fp));
  EXPECT_EQ(3, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(3, ftell(fp));
  EXPECT_EQ(3, ftello(fp));
  ASSERT_EQ(0, fclose(fp));
  memset(buf, 'x', sizeof(buf));
  buf[3] = '\0';
  ASSERT_NE(nullptr, fp = fmemopen(buf, 16, "a+"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(3, ftell(fp));
  EXPECT_EQ(3, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(3, ftell(fp));
  EXPECT_EQ(3, ftello(fp));
  ASSERT_EQ(0, fclose(fp));

  // 3. The value of the size argument, if buf is not a null pointer and no
  // null byte is found.
  memset(buf, 'x', sizeof(buf));
  ASSERT_NE(nullptr, fp = fmemopen(buf, 16, "a"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(16, ftell(fp));
  EXPECT_EQ(16, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(16, ftell(fp));
  EXPECT_EQ(16, ftello(fp));
  ASSERT_EQ(0, fclose(fp));
  memset(buf, 'x', sizeof(buf));
  ASSERT_NE(nullptr, fp = fmemopen(buf, 16, "a+"));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(16, ftell(fp));
  EXPECT_EQ(16, ftello(fp));
  ASSERT_EQ(0, fseeko(fp, 0, SEEK_END));
  EXPECT_EQ(16, ftell(fp));
  EXPECT_EQ(16, ftello(fp));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_SEEK_END) {
  // fseek SEEK_END is relative to the current string length, not the buffer size.
  FILE* fp;
  char buf[8];
  memset(buf, 'x', sizeof(buf));
  strcpy(buf, "str");
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "w+"));
  ASSERT_NE(EOF, fputs("string", fp));
  EXPECT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(static_cast<long>(strlen("string")), ftell(fp));
  EXPECT_EQ(static_cast<off_t>(strlen("string")), ftello(fp));
  EXPECT_EQ(0, fclose(fp));

  // glibc < 2.22 interpreted SEEK_END the wrong way round (subtracting rather
  // than adding).
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "w+"));
  ASSERT_NE(EOF, fputs("54321", fp));
  EXPECT_EQ(0, fseek(fp, -2, SEEK_END));
  EXPECT_EQ('2', fgetc(fp));
  EXPECT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_seek_invalid) {
  char buf[8];
  memset(buf, 'x', sizeof(buf));
  FILE* fp = fmemopen(buf, sizeof(buf), "w");
  ASSERT_TRUE(fp != nullptr);

  // POSIX: "An attempt to seek ... to a negative position or to a position
  // larger than the buffer size given in the size argument shall fail."
  // (There's no mention of what errno should be set to, and glibc doesn't
  // set errno in any of these cases.)
  EXPECT_EQ(-1, fseek(fp, -2, SEEK_SET));
  EXPECT_EQ(-1, fseeko(fp, -2, SEEK_SET));
  EXPECT_EQ(-1, fseek(fp, sizeof(buf) + 1, SEEK_SET));
  EXPECT_EQ(-1, fseeko(fp, sizeof(buf) + 1, SEEK_SET));
}

TEST(STDIO_TEST, fmemopen_read_EOF) {
  // POSIX: "A read operation on the stream shall not advance the current
  // buffer position beyond the current buffer size."
  char buf[8];
  memset(buf, 'x', sizeof(buf));
  FILE* fp = fmemopen(buf, sizeof(buf), "r");
  ASSERT_TRUE(fp != nullptr);
  char buf2[BUFSIZ];
  ASSERT_EQ(8U, fread(buf2, 1, sizeof(buf2), fp));
  // POSIX: "Reaching the buffer size in a read operation shall count as
  // end-of-file.
  ASSERT_TRUE(feof(fp));
  ASSERT_EQ(EOF, fgetc(fp));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_read_null_bytes) {
  // POSIX: "Null bytes in the buffer shall have no special meaning for reads."
  char buf[] = "h\0e\0l\0l\0o";
  FILE* fp = fmemopen(buf, sizeof(buf), "r");
  ASSERT_TRUE(fp != nullptr);
  ASSERT_EQ('h', fgetc(fp));
  ASSERT_EQ(0, fgetc(fp));
  ASSERT_EQ('e', fgetc(fp));
  ASSERT_EQ(0, fgetc(fp));
  ASSERT_EQ('l', fgetc(fp));
  ASSERT_EQ(0, fgetc(fp));
  // POSIX: "The read operation shall start at the current buffer position of
  // the stream."
  char buf2[8];
  memset(buf2, 'x', sizeof(buf2));
  ASSERT_EQ(4U, fread(buf2, 1, sizeof(buf2), fp));
  ASSERT_EQ('l', buf2[0]);
  ASSERT_EQ(0, buf2[1]);
  ASSERT_EQ('o', buf2[2]);
  ASSERT_EQ(0, buf2[3]);
  for (size_t i = 4; i < sizeof(buf2); ++i) ASSERT_EQ('x', buf2[i]) << i;
  ASSERT_TRUE(feof(fp));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_write) {
  FILE* fp;
  char buf[8];

  // POSIX: "A write operation shall start either at the current position of
  // the stream (if mode has not specified 'a' as the first character)..."
  memset(buf, 'x', sizeof(buf));
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "r+"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ(0, fseek(fp, 2, SEEK_SET));
  ASSERT_EQ(' ', fputc(' ', fp));
  EXPECT_EQ("xx xxxxx", std::string(buf, buf + sizeof(buf)));
  ASSERT_EQ(0, fclose(fp));

  // "...or at the current size of the stream (if mode had 'a' as the first
  // character)." (See the fmemopen_size test for what "size" means, but for
  // mode "a", it's the first NUL byte.)
  memset(buf, 'x', sizeof(buf));
  buf[3] = '\0';
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "a+"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ(' ', fputc(' ', fp));
  EXPECT_EQ("xxx \0xxx"s, std::string(buf, buf + sizeof(buf)));
  ASSERT_EQ(0, fclose(fp));

  // "If the current position at the end of the write is larger than the
  // current buffer size, the current buffer size shall be set to the current
  // position." (See the fmemopen_size test for what "size" means, but to
  // query it we SEEK_END with offset 0, and then ftell.)
  memset(buf, 'x', sizeof(buf));
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "w+"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(0, ftell(fp));
  ASSERT_EQ(' ', fputc(' ', fp));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(1, ftell(fp));
  ASSERT_NE(EOF, fputs("123", fp));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(4, ftell(fp));
  EXPECT_EQ(" 123\0xxx"s, std::string(buf, buf + sizeof(buf)));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_write_EOF) {
  // POSIX: "A write operation on the stream shall not advance the current
  // buffer size beyond the size given in the size argument."
  FILE* fp;

  // Scalar writes...
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 4, "w"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ('x', fputc('x', fp));
  ASSERT_EQ('x', fputc('x', fp));
  ASSERT_EQ('x', fputc('x', fp));
  ASSERT_EQ(EOF, fputc('x', fp)); // Only 3 fit because of the implicit NUL.
  ASSERT_EQ(0, fclose(fp));

  // Vector writes...
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 4, "w"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ(3U, fwrite("xxxx", 1, 4, fp));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_initial_position) {
  // POSIX: "The ... current position in the buffer ... shall be initially
  // set to either the beginning of the buffer (for r and w modes) ..."
  char buf[] = "hello\0world";
  FILE* fp;
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "r"));
  EXPECT_EQ(0L, ftell(fp));
  EXPECT_EQ(0, fclose(fp));
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "w"));
  EXPECT_EQ(0L, ftell(fp));
  EXPECT_EQ(0, fclose(fp));
  buf[0] = 'h'; // (Undo the effects of the above.)

  // POSIX: "...or to the first null byte in the buffer (for a modes)."
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "a"));
  EXPECT_EQ(5L, ftell(fp));
  EXPECT_EQ(0, fclose(fp));

  // POSIX: "If no null byte is found in append mode, the initial position
  // shall be set to one byte after the end of the buffer."
  memset(buf, 'x', sizeof(buf));
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "a"));
  EXPECT_EQ(static_cast<long>(sizeof(buf)), ftell(fp));
  EXPECT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_initial_position_allocated) {
  // POSIX: "If buf is a null pointer, the initial position shall always be
  // set to the beginning of the buffer."
  FILE* fp = fmemopen(nullptr, 128, "a+");
  ASSERT_TRUE(fp != nullptr);
  EXPECT_EQ(0L, ftell(fp));
  EXPECT_EQ(0L, fseek(fp, 0, SEEK_SET));
  EXPECT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_zero_length) {
  // POSIX says it's up to the implementation whether or not you can have a
  // zero-length buffer (but "A future version of this standard may require
  // support of zero-length buffer streams explicitly"). BSD and glibc < 2.22
  // agreed that you couldn't, but glibc >= 2.22 allows it for consistency.
  FILE* fp;
  char buf[16];
  ASSERT_NE(nullptr, fp = fmemopen(buf, 0, "r+"));
  ASSERT_EQ(EOF, fgetc(fp));
  ASSERT_TRUE(feof(fp));
  ASSERT_EQ(0, fclose(fp));
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 0, "r+"));
  ASSERT_EQ(EOF, fgetc(fp));
  ASSERT_TRUE(feof(fp));
  ASSERT_EQ(0, fclose(fp));

  ASSERT_NE(nullptr, fp = fmemopen(buf, 0, "w+"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ(EOF, fputc('x', fp));
  ASSERT_EQ(0, fclose(fp));
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 0, "w+"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ(EOF, fputc('x', fp));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_zero_length_buffer_overrun) {
  char buf[2] = "x";
  ASSERT_EQ('x', buf[0]);
  FILE* fp = fmemopen(buf, 0, "w");
  ASSERT_EQ('x', buf[0]);
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_write_only_allocated) {
  // POSIX says fmemopen "may fail if the mode argument does not include a '+'".
  // BSD fails, glibc doesn't. We side with the more lenient.
  FILE* fp;
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 16, "r"));
  ASSERT_EQ(0, fclose(fp));
  ASSERT_NE(nullptr, fp = fmemopen(nullptr, 16, "w"));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_fileno) {
  // There's no fd backing an fmemopen FILE*.
  FILE* fp = fmemopen(nullptr, 16, "r");
  ASSERT_TRUE(fp != nullptr);
  errno = 0;
  ASSERT_EQ(-1, fileno(fp));
  ASSERT_ERRNO(EBADF);
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fmemopen_append_after_seek) {
  // In BSD and glibc < 2.22, append mode didn't force writes to append if
  // there had been an intervening seek.

  FILE* fp;
  char buf[] = "hello\0world";
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "a"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ(0, fseek(fp, 0, SEEK_SET));
  ASSERT_NE(EOF, fputc('!', fp));
  EXPECT_EQ("hello!\0orld\0"s, std::string(buf, buf + sizeof(buf)));
  ASSERT_EQ(0, fclose(fp));

  memcpy(buf, "hello\0world", sizeof(buf));
  ASSERT_NE(nullptr, fp = fmemopen(buf, sizeof(buf), "a+"));
  setbuf(fp, nullptr); // Turn off buffering so we can see what's happening as it happens.
  ASSERT_EQ(0, fseek(fp, 0, SEEK_SET));
  ASSERT_NE(EOF, fputc('!', fp));
  EXPECT_EQ("hello!\0orld\0"s, std::string(buf, buf + sizeof(buf)));
  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, open_memstream) {
  char* p = nullptr;
  size_t size = 0;
  FILE* fp = open_memstream(&p, &size);
  ASSERT_NE(EOF, fputs("hello, world!", fp));
  fclose(fp);

  ASSERT_STREQ("hello, world!", p);
  ASSERT_EQ(strlen("hello, world!"), size);
  free(p);
}

TEST(STDIO_TEST, open_memstream_EINVAL) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  char* p;
  size_t size;

  // Invalid buffer.
  errno = 0;
  ASSERT_EQ(nullptr, open_memstream(nullptr, &size));
  ASSERT_ERRNO(EINVAL);

  // Invalid size.
  errno = 0;
  ASSERT_EQ(nullptr, open_memstream(&p, nullptr));
  ASSERT_ERRNO(EINVAL);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "glibc is broken";
#endif
}

TEST(STDIO_TEST, fdopen_add_CLOEXEC) {
  // This fd doesn't have O_CLOEXEC...
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_FALSE(CloseOnExec(fd));
  // ...but the new one does.
  FI
"""


```