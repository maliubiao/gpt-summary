Response:
The user wants a summary of the functionality of the C++ code snippet provided, which is the third part of a larger test file `stdio_test.cpp` from Android's Bionic library.

The code primarily tests various functionalities related to standard input/output (stdio) library functions in C. It covers file opening, closing, reading, writing, seeking, and other operations, specifically focusing on edge cases, error handling, and interactions with the operating system.

To summarize effectively, I will iterate through the `TEST` blocks and identify the core functionality being tested in each.
这是 `bionic/tests/stdio_test.cpp` 文件第三部分的功能归纳：

**核心功能：针对标准 C 库的输入/输出 (stdio) 功能进行单元测试，特别是文件操作相关的函数。**

**具体功能点：**

* **`fdopen` 和 `fclose` 的交互：**
    * 测试 `fdopen` 创建的 `FILE*` 指针是否正确继承了文件描述符的 `close-on-exec` (CLOEXEC) 标志。
    * 测试 `fdopen` 创建的 `FILE*` 指针是否可以移除底层文件描述符的 `close-on-exec` 标志。

* **`freopen` 的功能：**
    * 测试 `freopen` 是否可以为一个已打开的 `FILE*` 指针添加或移除 `close-on-exec` 标志。
    * 测试 `freopen` 在 `filename` 参数为 `nullptr` 时，是否可以为一个已打开的 `FILE*` 指针添加或移除 `close-on-exec` 标志。

* **`fopen64` 和 `freopen64` 的基本功能：**
    * 简单测试 `fopen64` 和 `freopen64` 可以成功打开和重新打开文件。

* **`fread` 的性能和行为：**
    * 测试 `fread` 在未缓冲模式下的性能，验证其在读取大量数据时的效率。
    * 测试 `fread` 在到达文件末尾 (EOF) 时的行为，包括读取量小于剩余内容和大于剩余内容的情况。
    * 测试尝试从只写模式的文件流中读取数据时 `fread` 的错误处理 (返回 0，设置 `errno` 为 `EBADF`)。

* **`fwrite`、`fputc`、`fprintf` 对只读文件流的操作：**
    * 测试尝试向只读模式的文件流中写入数据时，这些函数是否会正确返回错误并设置文件流的错误标志。

* **`fwrite` 在 `fread` 之后的操作：**
    * 测试在对文件进行读取操作并到达 EOF 后，是否仍然可以向文件中写入数据。
    * 测试 `rewind` 函数在 `fread` 之后的作用，确保文件指针可以正确回到开头。

* **`fread` 在 `fseek` 之后的操作：**
    * 测试在文件指针移动后，`fread` 是否能从正确的位置开始读取数据，并验证 `fseek` 不会重用内部缓冲区导致错误。

* **`fread` 和 EOF 的交互 (问题 #184847)：**
    * 测试在读写操作交替进行时，`fread` 如何处理 EOF 状态，验证是否能正确读取新写入的数据。

* **`fclose` 的作用：**
    * 测试 `fclose` 是否会使关联的文件描述符失效，避免程序继续使用已关闭的文件描述符。

* **`fseek` 和 `ftell` 对不可搜索文件流的操作：**
    * 测试 `ftell` 和 `fseek` 在处理 `funopen` 创建的不可搜索文件流时的错误处理 (返回 -1，设置 `errno` 为 `ESPIPE`)。

* **`funopen` 的错误处理：**
    * 测试当 `funopen` 的读写函数都为 `nullptr` 时，是否会返回错误 (`EINVAL`)。

* **`funopen` 和 seek 操作：**
    * 测试 `funopen` 创建的文件流，当指定了 seek 函数时，`fgetpos` 是否能返回预期的位置信息。

* **大量并发文件操作：**
    * 测试同时打开和操作大量文件是否会导致问题。

* **`fseek`、`ftell` 及其相关函数的综合测试：**
    * 覆盖 `fseek`、`ftell`、`ftello`、`ftello64`、`fgetpos`、`fgetpos64`、`fsetpos`、`fsetpos64`、`fseeko`、`fseeko64` 等一系列函数的基本功能，包括设置偏移量、获取偏移量和设置位置等。

* **`fseek` 和 `fseeko` 的错误处理：**
    * 测试 `fseek`、`fseeko`、`fseeko64` 在 `whence` 参数错误或偏移量错误时的错误处理 (`EINVAL`)。

* **`ctermid` 的功能：**
    * 测试 `ctermid` 函数是否能正确返回控制终端的路径 `/dev/tty`。

* **`remove` 的功能：**
    * 测试 `remove` 函数是否能正确删除文件和空目录，并处理文件或目录不存在的情况 (`ENOENT`)。

* **`snprintf` 的安全检查 (问题 #30445072)：**
    * 使用 DeathTest 测试 `snprintf` 在传入负数或非常大的 `size` 参数时是否会触发 `SIGABRT` 信号，表明有安全检查机制。

* **`sprintf` 的基本功能：**
    * 简单测试 `sprintf` 的字符串格式化功能。

* **`printf` 和 `wprintf` 的 `%m` 格式符：**
    * 测试 `%m` 格式符是否能根据当前的 `errno` 值输出相应的错误信息，包括成功的情况 (errno=0) 和未知错误的情况 (errno=-1)。
    * 测试 `%#m` 格式符的输出格式。
    * 测试使用 `%m` 格式符不会影响 `strerror` 函数返回的错误信息。

* **`fopen` 和 `fdopen` 在追加模式下的 `ftell` 行为：**
    * 测试以追加模式打开文件时，初始文件指针的位置是否在文件末尾。
    * 测试在追加模式下进行 `fseek` 操作后的 `ftell` 行为。

* **常量定义：**
    * 简单验证 `FILENAME_MAX` 和 `PATH_MAX` 的关系，以及 `L_tmpnam` 的值。

* **`perror` 的功能：**
    * 测试 `perror` 函数是否能根据当前的 `errno` 值输出错误信息到标准错误流。

* **`puts` 和 `putchar` 的功能：**
    * 简单测试 `puts` 和 `putchar` 函数的基本输出功能。

* **带 `_unlocked` 后缀的 stdio 函数：**
    * 测试一系列带 `_unlocked` 后缀的 stdio 函数 (如 `clearerr_unlocked`、`feof_unlocked`、`ferror_unlocked`、`fileno_unlocked`、`putc_unlocked`、`fputc_unlocked`、`fwrite_unlocked`、`fread_unlocked`、`fgets_unlocked`) 的基本功能，这些函数通常用于无锁环境。

* **`fseek` 的 64 位偏移量支持：**
    * 测试 `fseeko64` 和 `ftello64` 是否能处理大于 32 位的文件偏移量。

* **`fseek` 在 32 位系统上的溢出处理：**
    * 测试在 32 位系统上，`fseek` 是否会正确处理偏移量溢出的情况 (`EOVERFLOW`)，特别是 `SEEK_CUR` 的情况。

* **`/dev/std*` 文件的存在性：**
    * 验证 `/dev/stdin`、`/dev/stdout` 和 `/dev/stderr` 这三个特殊文件链接到 `/proc/self/fd/0`、`/proc/self/fd/1` 和 `/proc/self/fd/2`。

* **`fread` 和文件锁的交互：**
    * 测试在一个线程中读取未缓冲或行缓冲的文件时，不会因为其他线程持有文件锁而被阻塞。

* **`SEEK_*` 宏的定义：**
    * 验证 `SEEK_SET`、`SEEK_CUR`、`SEEK_END`、`SEEK_DATA` 和 `SEEK_HOLE` 等宏的值。

* **`rename` 和 `renameat` 的功能：**
    * 测试 `rename` 和 `renameat` 函数是否能正确重命名文件。

* **`renameat2` 的功能和标志：**
    * 测试 `renameat2` 函数的基本重命名功能，并测试 `RENAME_NOREPLACE` 标志的行为。
    * 验证 `RENAME_EXCHANGE`、`RENAME_NOREPLACE` 和 `RENAME_WHITEOUT` 等标志已定义且非零。

* **`fdopen` 的错误处理：**
    * 测试 `fdopen` 在传入无效模式、与文件描述符模式不兼容的模式、尝试设置追加模式以及传入无效文件描述符时的错误处理 (`EINVAL` 或 `EBADF`)。

* **`fmemopen`、`fopen`、`freopen` 的无效模式处理：**
    * 测试这些函数在传入无效的文件打开模式时的错误处理 (`EINVAL`)。

* **`asprintf` 的基本功能：**
    * 简单测试 `asprintf` 函数的动态内存分配和格式化功能。

* **`fopen` 的 `ENOENT` 错误：**
    * 测试 `fopen` 在尝试打开不存在的文件时的错误处理 (`ENOENT`)。

* **`tempnam` 的功能和目录选择逻辑：**
    * 测试 `tempnam` 函数在不同情况下生成临时文件的路径，包括有无 `TMPDIR` 环境变量，以及传入的 `dir` 和 `prefix` 参数的影响。

* **`tmpnam` 的功能：**
    * 测试 `tmpnam` 函数生成临时文件名的功能。

* **`freopen` 在 `filename` 为 `nullptr` 时的模式切换：**
    * 测试 `freopen(nullptr, mode, fp)` 可以改变已打开文件流的读写模式。

* **`fread` 和 `fwrite` 的整数溢出处理：**
    * 测试在 64 位系统上，`fread` 和 `fwrite` 是否能处理大于 `INT_MAX` 的读取/写入大小。

* **`snprintf` 和 `swprintf` 的二进制格式化输出 (%b, %B)：**
    * 测试 `snprintf` 和 `swprintf` 是否支持 `%b` 和 `%B` 格式符进行二进制格式化输出，包括带前缀和不带前缀的情况。

* **`scanf` 的 `%i` 格式符：**
    * 测试 `scanf` 的 `%i` 格式符可以解析十进制、十六进制和八进制的整数。

总而言之，这部分代码着重测试了 C 标准库中与文件 I/O 操作相关的各种函数的正确性、错误处理、边界情况和性能表现，确保在 Android Bionic 库中的实现符合预期。

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
这是第3部分，共4部分，请归纳一下它的功能

"""
LE* fp = fdopen(fd, "re");
  ASSERT_TRUE(CloseOnExec(fileno(fp)));
  fclose(fp);
}

TEST(STDIO_TEST, fdopen_remove_CLOEXEC) {
  // This fd has O_CLOEXEC...
  int fd = open("/proc/version", O_RDONLY | O_CLOEXEC);
  ASSERT_TRUE(CloseOnExec(fd));
  // ...but the new one doesn't.
  FILE* fp = fdopen(fd, "r");
  ASSERT_TRUE(CloseOnExec(fileno(fp)));
  fclose(fp);
}

TEST(STDIO_TEST, freopen_add_CLOEXEC) {
  // This FILE* doesn't have O_CLOEXEC...
  FILE* fp = fopen("/proc/version", "r");
  ASSERT_FALSE(CloseOnExec(fileno(fp)));
  // ...but the new one does.
  fp = freopen("/proc/version", "re", fp);
  ASSERT_TRUE(CloseOnExec(fileno(fp)));

  fclose(fp);
}

TEST(STDIO_TEST, freopen_remove_CLOEXEC) {
  // This FILE* has O_CLOEXEC...
  FILE* fp = fopen("/proc/version", "re");
  ASSERT_TRUE(CloseOnExec(fileno(fp)));
  // ...but the new one doesn't.
  fp = freopen("/proc/version", "r", fp);
  ASSERT_FALSE(CloseOnExec(fileno(fp)));
  fclose(fp);
}

TEST(STDIO_TEST, freopen_null_filename_add_CLOEXEC) {
  // This FILE* doesn't have O_CLOEXEC...
  FILE* fp = fopen("/proc/version", "r");
  ASSERT_FALSE(CloseOnExec(fileno(fp)));
  // ...but the new one does.
  fp = freopen(nullptr, "re", fp);
  ASSERT_TRUE(CloseOnExec(fileno(fp)));
  fclose(fp);
}

TEST(STDIO_TEST, freopen_null_filename_remove_CLOEXEC) {
  // This FILE* has O_CLOEXEC...
  FILE* fp = fopen("/proc/version", "re");
  ASSERT_TRUE(CloseOnExec(fileno(fp)));
  // ...but the new one doesn't.
  fp = freopen(nullptr, "r", fp);
  ASSERT_FALSE(CloseOnExec(fileno(fp)));
  fclose(fp);
}

TEST(STDIO_TEST, fopen64_freopen64) {
  FILE* fp = fopen64("/proc/version", "r");
  ASSERT_TRUE(fp != nullptr);
  fp = freopen64("/proc/version", "re", fp);
  ASSERT_TRUE(fp != nullptr);
  fclose(fp);
}

// https://code.google.com/p/android/issues/detail?id=81155
// http://b/18556607
TEST(STDIO_TEST, fread_unbuffered_pathological_performance) {
  FILE* fp = fopen("/dev/zero", "r");
  ASSERT_TRUE(fp != nullptr);

  // Make this stream unbuffered.
  setvbuf(fp, nullptr, _IONBF, 0);

  char buf[65*1024];
  memset(buf, 0xff, sizeof(buf));

  time_t t0 = time(nullptr);
  for (size_t i = 0; i < 1024; ++i) {
    ASSERT_EQ(1U, fread(buf, 64*1024, 1, fp));
  }
  time_t t1 = time(nullptr);

  fclose(fp);

  // 1024 64KiB reads should have been very quick.
  ASSERT_LE(t1 - t0, 1);

  for (size_t i = 0; i < 64*1024; ++i) {
    ASSERT_EQ('\0', buf[i]);
  }
  for (size_t i = 64*1024; i < 65*1024; ++i) {
    ASSERT_EQ('\xff', buf[i]);
  }
}

TEST(STDIO_TEST, fread_EOF) {
  std::string digits("0123456789");
  FILE* fp = fmemopen(&digits[0], digits.size(), "r");

  // Try to read too much, but little enough that it still fits in the FILE's internal buffer.
  char buf1[4 * 4];
  memset(buf1, 0, sizeof(buf1));
  ASSERT_EQ(2U, fread(buf1, 4, 4, fp));
  ASSERT_STREQ("0123456789", buf1);
  ASSERT_TRUE(feof(fp));

  rewind(fp);

  // Try to read way too much so stdio tries to read more direct from the stream.
  char buf2[4 * 4096];
  memset(buf2, 0, sizeof(buf2));
  ASSERT_EQ(2U, fread(buf2, 4, 4096, fp));
  ASSERT_STREQ("0123456789", buf2);
  ASSERT_TRUE(feof(fp));

  fclose(fp);
}

static void test_fread_from_write_only_stream(size_t n) {
  FILE* fp = fopen("/dev/null", "w");
  std::vector<char> buf(n, 0);
  errno = 0;
  ASSERT_EQ(0U, fread(&buf[0], n, 1, fp));
  ASSERT_ERRNO(EBADF);
  ASSERT_TRUE(ferror(fp));
  ASSERT_FALSE(feof(fp));
  fclose(fp);
}

TEST(STDIO_TEST, fread_from_write_only_stream_slow_path) {
  test_fread_from_write_only_stream(1);
}

TEST(STDIO_TEST, fread_from_write_only_stream_fast_path) {
  test_fread_from_write_only_stream(64*1024);
}

TEST(STDIO_TEST, fwrite_to_read_only_stream) {
  FILE* fp = fopen("/proc/version", "re");
  ASSERT_FALSE(ferror(fp));
  ASSERT_EQ(0U, fwrite("hello", 1, 5, fp));
  ASSERT_TRUE(ferror(fp));
}

TEST(STDIO_TEST, fputc_to_read_only_stream) {
  FILE* fp = fopen("/proc/version", "re");
  ASSERT_FALSE(ferror(fp));
  ASSERT_EQ(EOF, fputc('x', fp));
  ASSERT_TRUE(ferror(fp));
}

TEST(STDIO_TEST, fprintf_to_read_only_stream) {
  FILE* fp = fopen("/proc/version", "re");
  ASSERT_FALSE(ferror(fp));
  ASSERT_EQ(-1, fprintf(fp, "%s%d", "hello", 123));
  ASSERT_TRUE(ferror(fp));
}

static void test_fwrite_after_fread(size_t n) {
  TemporaryFile tf;

  FILE* fp = fdopen(tf.fd, "w+");
  ASSERT_EQ(1U, fwrite("1", 1, 1, fp));
  fflush(fp);

  // We've flushed but not rewound, so there's nothing to read.
  std::vector<char> buf(n, 0);
  ASSERT_EQ(0U, fread(&buf[0], 1, buf.size(), fp));
  ASSERT_TRUE(feof(fp));

  // But hitting EOF doesn't prevent us from writing...
  errno = 0;
  ASSERT_EQ(1U, fwrite("2", 1, 1, fp)) << strerror(errno);

  // And if we rewind, everything's there.
  rewind(fp);
  ASSERT_EQ(2U, fread(&buf[0], 1, buf.size(), fp));
  ASSERT_EQ('1', buf[0]);
  ASSERT_EQ('2', buf[1]);

  fclose(fp);
}

TEST(STDIO_TEST, fwrite_after_fread_slow_path) {
  test_fwrite_after_fread(16);
}

TEST(STDIO_TEST, fwrite_after_fread_fast_path) {
  test_fwrite_after_fread(64*1024);
}

// http://b/19172514
TEST(STDIO_TEST, fread_after_fseek) {
  TemporaryFile tf;

  FILE* fp = fopen(tf.path, "w+");
  ASSERT_TRUE(fp != nullptr);

  char file_data[12288];
  for (size_t i = 0; i < 12288; i++) {
    file_data[i] = i;
  }
  ASSERT_EQ(12288U, fwrite(file_data, 1, 12288, fp));
  fclose(fp);

  fp = fopen(tf.path, "r");
  ASSERT_TRUE(fp != nullptr);

  char buffer[8192];
  size_t cur_location = 0;
  // Small read to populate internal buffer.
  ASSERT_EQ(100U, fread(buffer, 1, 100, fp));
  ASSERT_EQ(memcmp(file_data, buffer, 100), 0);

  cur_location = static_cast<size_t>(ftell(fp));
  // Large read to force reading into the user supplied buffer and bypassing
  // the internal buffer.
  ASSERT_EQ(8192U, fread(buffer, 1, 8192, fp));
  ASSERT_EQ(memcmp(file_data+cur_location, buffer, 8192), 0);

  // Small backwards seek to verify fseek does not reuse the internal buffer.
  ASSERT_EQ(0, fseek(fp, -22, SEEK_CUR)) << strerror(errno);
  cur_location = static_cast<size_t>(ftell(fp));
  ASSERT_EQ(22U, fread(buffer, 1, 22, fp));
  ASSERT_EQ(memcmp(file_data+cur_location, buffer, 22), 0);

  fclose(fp);
}

// https://code.google.com/p/android/issues/detail?id=184847
TEST(STDIO_TEST, fread_EOF_184847) {
  TemporaryFile tf;
  char buf[6] = {0};

  FILE* fw = fopen(tf.path, "w");
  ASSERT_TRUE(fw != nullptr);

  FILE* fr = fopen(tf.path, "r");
  ASSERT_TRUE(fr != nullptr);

  fwrite("a", 1, 1, fw);
  fflush(fw);
  ASSERT_EQ(1U, fread(buf, 1, 1, fr));
  ASSERT_STREQ("a", buf);

  // 'fr' is now at EOF.
  ASSERT_EQ(0U, fread(buf, 1, 1, fr));
  ASSERT_TRUE(feof(fr));

  // Write some more...
  fwrite("z", 1, 1, fw);
  fflush(fw);

  // ...and check that we can read it back.
  // (BSD thinks that once a stream has hit EOF, it must always return EOF. SysV disagrees.)
  ASSERT_EQ(1U, fread(buf, 1, 1, fr));
  ASSERT_STREQ("z", buf);

  // But now we're done.
  ASSERT_EQ(0U, fread(buf, 1, 1, fr));

  fclose(fr);
  fclose(fw);
}

TEST(STDIO_TEST, fclose_invalidates_fd) {
  // The typical error we're trying to help people catch involves accessing
  // memory after it's been freed. But we know that stdin/stdout/stderr are
  // special and don't get deallocated, so this test uses stdin.
  ASSERT_EQ(0, fclose(stdin));

  // Even though using a FILE* after close is undefined behavior, I've closed
  // this bug as "WAI" too many times. We shouldn't hand out stale fds,
  // especially because they might actually correspond to a real stream.
  errno = 0;
  ASSERT_EQ(-1, fileno(stdin));
  ASSERT_ERRNO(EBADF);
}

TEST(STDIO_TEST, fseek_ftell_unseekable) {
#if defined(__BIONIC__) // glibc has fopencookie instead.
  auto read_fn = [](void*, char*, int) { return -1; };
  FILE* fp = funopen(nullptr, read_fn, nullptr, nullptr, nullptr);
  ASSERT_TRUE(fp != nullptr);

  // Check that ftell balks on an unseekable FILE*.
  errno = 0;
  ASSERT_EQ(-1, ftell(fp));
  ASSERT_ERRNO(ESPIPE);

  // SEEK_CUR is rewritten as SEEK_SET internally...
  errno = 0;
  ASSERT_EQ(-1, fseek(fp, 0, SEEK_CUR));
  ASSERT_ERRNO(ESPIPE);

  // ...so it's worth testing the direct seek path too.
  errno = 0;
  ASSERT_EQ(-1, fseek(fp, 0, SEEK_SET));
  ASSERT_ERRNO(ESPIPE);

  fclose(fp);
#else
  GTEST_SKIP() << "glibc uses fopencookie instead";
#endif
}

TEST(STDIO_TEST, funopen_EINVAL) {
#if defined(__BIONIC__)
  errno = 0;
  ASSERT_EQ(nullptr, funopen(nullptr, nullptr, nullptr, nullptr, nullptr));
  ASSERT_ERRNO(EINVAL);
#else
  GTEST_SKIP() << "glibc uses fopencookie instead";
#endif
}

TEST(STDIO_TEST, funopen_seek) {
#if defined(__BIONIC__)
  auto read_fn = [](void*, char*, int) { return -1; };

  auto seek_fn = [](void*, fpos_t, int) -> fpos_t { return 0xfedcba12; };
  auto seek64_fn = [](void*, fpos64_t, int) -> fpos64_t { return 0xfedcba12345678; };

  FILE* fp = funopen(nullptr, read_fn, nullptr, seek_fn, nullptr);
  ASSERT_TRUE(fp != nullptr);
  fpos_t pos;
#if defined(__LP64__)
  EXPECT_EQ(0, fgetpos(fp, &pos)) << strerror(errno);
  EXPECT_EQ(0xfedcba12LL, pos);
#else
  EXPECT_EQ(-1, fgetpos(fp, &pos)) << strerror(errno);
  EXPECT_ERRNO(EOVERFLOW);
#endif

  FILE* fp64 = funopen64(nullptr, read_fn, nullptr, seek64_fn, nullptr);
  ASSERT_TRUE(fp64 != nullptr);
  fpos64_t pos64;
  EXPECT_EQ(0, fgetpos64(fp64, &pos64)) << strerror(errno);
  EXPECT_EQ(0xfedcba12345678, pos64);
#else
  GTEST_SKIP() << "glibc uses fopencookie instead";
#endif
}

TEST(STDIO_TEST, lots_of_concurrent_files) {
  std::vector<TemporaryFile*> tfs;
  std::vector<FILE*> fps;

  for (size_t i = 0; i < 256; ++i) {
    TemporaryFile* tf = new TemporaryFile;
    tfs.push_back(tf);
    FILE* fp = fopen(tf->path, "w+");
    fps.push_back(fp);
    fprintf(fp, "hello %zu!\n", i);
    fflush(fp);
  }

  for (size_t i = 0; i < 256; ++i) {
    char expected[BUFSIZ];
    snprintf(expected, sizeof(expected), "hello %zu!\n", i);

    AssertFileIs(fps[i], expected);
    fclose(fps[i]);
    delete tfs[i];
  }
}

static void AssertFileOffsetAt(FILE* fp, off64_t offset) {
  EXPECT_EQ(offset, ftell(fp));
  EXPECT_EQ(offset, ftello(fp));
  EXPECT_EQ(offset, ftello64(fp));
  fpos_t pos;
  fpos64_t pos64;
  EXPECT_EQ(0, fgetpos(fp, &pos));
  EXPECT_EQ(0, fgetpos64(fp, &pos64));
#if defined(__BIONIC__)
  EXPECT_EQ(offset, static_cast<off64_t>(pos));
  EXPECT_EQ(offset, static_cast<off64_t>(pos64));
#else
  GTEST_SKIP() << "glibc's fpos_t is opaque";
#endif
}

TEST(STDIO_TEST, seek_tell_family_smoke) {
  TemporaryFile tf;
  FILE* fp = fdopen(tf.fd, "w+");

  // Initially we should be at 0.
  AssertFileOffsetAt(fp, 0);

  // Seek to offset 8192.
  ASSERT_EQ(0, fseek(fp, 8192, SEEK_SET));
  AssertFileOffsetAt(fp, 8192);
  fpos_t eight_k_pos;
  ASSERT_EQ(0, fgetpos(fp, &eight_k_pos));

  // Seek forward another 8192...
  ASSERT_EQ(0, fseek(fp, 8192, SEEK_CUR));
  AssertFileOffsetAt(fp, 8192 + 8192);
  fpos64_t sixteen_k_pos64;
  ASSERT_EQ(0, fgetpos64(fp, &sixteen_k_pos64));

  // Seek back 8192...
  ASSERT_EQ(0, fseek(fp, -8192, SEEK_CUR));
  AssertFileOffsetAt(fp, 8192);

  // Since we haven't written anything, the end is also at 0.
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  AssertFileOffsetAt(fp, 0);

  // Check that our fpos64_t from 16KiB works...
  ASSERT_EQ(0, fsetpos64(fp, &sixteen_k_pos64));
  AssertFileOffsetAt(fp, 8192 + 8192);
  // ...as does our fpos_t from 8192.
  ASSERT_EQ(0, fsetpos(fp, &eight_k_pos));
  AssertFileOffsetAt(fp, 8192);

  // Do fseeko and fseeko64 work too?
  ASSERT_EQ(0, fseeko(fp, 1234, SEEK_SET));
  AssertFileOffsetAt(fp, 1234);
  ASSERT_EQ(0, fseeko64(fp, 5678, SEEK_SET));
  AssertFileOffsetAt(fp, 5678);

  fclose(fp);
}

TEST(STDIO_TEST, fseek_fseeko_EINVAL) {
  TemporaryFile tf;
  FILE* fp = fdopen(tf.fd, "w+");

  // Bad whence.
  errno = 0;
  ASSERT_EQ(-1, fseek(fp, 0, 123));
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  ASSERT_EQ(-1, fseeko(fp, 0, 123));
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  ASSERT_EQ(-1, fseeko64(fp, 0, 123));
  ASSERT_ERRNO(EINVAL);

  // Bad offset.
  errno = 0;
  ASSERT_EQ(-1, fseek(fp, -1, SEEK_SET));
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  ASSERT_EQ(-1, fseeko(fp, -1, SEEK_SET));
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  ASSERT_EQ(-1, fseeko64(fp, -1, SEEK_SET));
  ASSERT_ERRNO(EINVAL);

  fclose(fp);
}

TEST(STDIO_TEST, ctermid) {
  ASSERT_STREQ("/dev/tty", ctermid(nullptr));

  char buf[L_ctermid] = {};
  ASSERT_EQ(buf, ctermid(buf));
  ASSERT_STREQ("/dev/tty", buf);
}

TEST(STDIO_TEST, remove) {
  struct stat sb;

  TemporaryFile tf;
  ASSERT_EQ(0, remove(tf.path));
  ASSERT_EQ(-1, lstat(tf.path, &sb));
  ASSERT_ERRNO(ENOENT);

  TemporaryDir td;
  ASSERT_EQ(0, remove(td.path));
  ASSERT_EQ(-1, lstat(td.path, &sb));
  ASSERT_ERRNO(ENOENT);

  errno = 0;
  ASSERT_EQ(-1, remove(tf.path));
  ASSERT_ERRNO(ENOENT);

  errno = 0;
  ASSERT_EQ(-1, remove(td.path));
  ASSERT_ERRNO(ENOENT);
}

TEST_F(STDIO_DEATHTEST, snprintf_30445072_known_buffer_size) {
  char buf[16];
  ASSERT_EXIT(snprintf(buf, atol("-1"), "hello"),
              testing::KilledBySignal(SIGABRT),
#if defined(NOFORTIFY)
              "FORTIFY: vsnprintf: size .* > SSIZE_MAX"
#else
              "FORTIFY: vsnprintf: prevented .*-byte write into 16-byte buffer"
#endif
              );
}

TEST_F(STDIO_DEATHTEST, snprintf_30445072_unknown_buffer_size) {
  std::string buf = "hello";  // So the compiler doesn't know the buffer size.
  ASSERT_EXIT(snprintf(&buf[0], atol("-1"), "hello"),
              testing::KilledBySignal(SIGABRT),
              "FORTIFY: vsnprintf: size .* > SSIZE_MAX");
}

TEST(STDIO_TEST, sprintf_30445072) {
  std::string buf = "world";
  sprintf(&buf[0], "hello");
  ASSERT_EQ(buf, "hello");
}

TEST(STDIO_TEST, printf_m) {
  errno = 0;
  EXPECT_SNPRINTF("<Success>", "<%m>");
  errno = -1;
  EXPECT_SNPRINTF("<Unknown error -1>", "<%m>");
  errno = EINVAL;
  EXPECT_SNPRINTF("<Invalid argument>", "<%m>");
}

TEST(STDIO_TEST, wprintf_m) {
  errno = 0;
  EXPECT_SWPRINTF(L"<Success>", L"<%m>");
  errno = -1;
  EXPECT_SWPRINTF(L"<Unknown error -1>", L"<%m>");
  errno = EINVAL;
  EXPECT_SWPRINTF(L"<Invalid argument>", L"<%m>");
}

TEST(STDIO_TEST, printf_hash_m) {
  errno = 0;
  EXPECT_SNPRINTF("<0>", "<%#m>");
  errno = -1;
  EXPECT_SNPRINTF("<-1>", "<%#m>");
  errno = EINVAL;
  EXPECT_SNPRINTF("<EINVAL>", "<%#m>");
}

TEST(STDIO_TEST, wprintf_hash_m) {
  errno = 0;
  EXPECT_SWPRINTF(L"<0>", L"<%#m>");
  errno = -1;
  EXPECT_SWPRINTF(L"<-1>", L"<%#m>");
  errno = EINVAL;
  EXPECT_SWPRINTF(L"<EINVAL>", L"<%#m>");
}

TEST(STDIO_TEST, printf_m_does_not_clobber_strerror) {
  const char* m = strerror(-1);
  ASSERT_STREQ("Unknown error -1", m);
  errno = -2;
  EXPECT_SNPRINTF("<Unknown error -2>", "<%m>");
  ASSERT_STREQ("Unknown error -1", m);
}

TEST(STDIO_TEST, wprintf_m_does_not_clobber_strerror) {
  const char* m = strerror(-1);
  ASSERT_STREQ("Unknown error -1", m);
  errno = -2;
  EXPECT_SWPRINTF(L"<Unknown error -2>", L"<%m>");
  ASSERT_STREQ("Unknown error -1", m);
}

TEST(STDIO_TEST, fopen_append_mode_and_ftell) {
  TemporaryFile tf;
  SetFileTo(tf.path, "0123456789");
  FILE* fp = fopen(tf.path, "a");
  EXPECT_EQ(10, ftell(fp));
  ASSERT_EQ(0, fseek(fp, 2, SEEK_SET));
  EXPECT_EQ(2, ftell(fp));
  ASSERT_NE(EOF, fputs("xxx", fp));
  ASSERT_EQ(0, fflush(fp));
  EXPECT_EQ(13, ftell(fp));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(13, ftell(fp));
  ASSERT_EQ(0, fclose(fp));
  AssertFileIs(tf.path, "0123456789xxx");
}

TEST(STDIO_TEST, fdopen_append_mode_and_ftell) {
  TemporaryFile tf;
  SetFileTo(tf.path, "0123456789");
  int fd = open(tf.path, O_RDWR);
  ASSERT_NE(-1, fd);
  // POSIX: "The file position indicator associated with the new stream is set to the position
  // indicated by the file offset associated with the file descriptor."
  ASSERT_EQ(4, lseek(fd, 4, SEEK_SET));
  FILE* fp = fdopen(fd, "a");
  EXPECT_EQ(4, ftell(fp));
  ASSERT_EQ(0, fseek(fp, 2, SEEK_SET));
  EXPECT_EQ(2, ftell(fp));
  ASSERT_NE(EOF, fputs("xxx", fp));
  ASSERT_EQ(0, fflush(fp));
  EXPECT_EQ(13, ftell(fp));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(13, ftell(fp));
  ASSERT_EQ(0, fclose(fp));
  AssertFileIs(tf.path, "0123456789xxx");
}

TEST(STDIO_TEST, freopen_append_mode_and_ftell) {
  TemporaryFile tf;
  SetFileTo(tf.path, "0123456789");
  FILE* other_fp = fopen("/proc/version", "r");
  FILE* fp = freopen(tf.path, "a", other_fp);
  EXPECT_EQ(10, ftell(fp));
  ASSERT_EQ(0, fseek(fp, 2, SEEK_SET));
  EXPECT_EQ(2, ftell(fp));
  ASSERT_NE(EOF, fputs("xxx", fp));
  ASSERT_EQ(0, fflush(fp));
  EXPECT_EQ(13, ftell(fp));
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  EXPECT_EQ(13, ftell(fp));
  ASSERT_EQ(0, fclose(fp));
  AssertFileIs(tf.path, "0123456789xxx");
}

TEST(STDIO_TEST, constants) {
  ASSERT_LE(FILENAME_MAX, PATH_MAX);
  ASSERT_EQ(L_tmpnam, PATH_MAX);
}

TEST(STDIO_TEST, perror) {
  ExecTestHelper eth;
  eth.Run([&]() { errno = EINVAL; perror("a b c"); exit(0); }, 0, "a b c: Invalid argument\n");
  eth.Run([&]() { errno = EINVAL; perror(nullptr); exit(0); }, 0, "Invalid argument\n");
  eth.Run([&]() { errno = EINVAL; perror(""); exit(0); }, 0, "Invalid argument\n");
}

TEST(STDIO_TEST, puts) {
  ExecTestHelper eth;
  eth.Run([&]() { exit(puts("a b c")); }, 0, "a b c\n");
}

TEST(STDIO_TEST, putchar) {
  ExecTestHelper eth;
  eth.Run([&]() { exit(putchar('A')); }, 65, "A");
}

TEST(STDIO_TEST, putchar_unlocked) {
  ExecTestHelper eth;
  eth.Run([&]() { exit(putchar('B')); }, 66, "B");
}

TEST(STDIO_TEST, unlocked) {
  TemporaryFile tf;

  FILE* fp = fopen(tf.path, "w+");
  ASSERT_TRUE(fp != nullptr);

  clearerr_unlocked(fp);
  ASSERT_FALSE(feof_unlocked(fp));
  ASSERT_FALSE(ferror_unlocked(fp));

  ASSERT_EQ(fileno(fp), fileno_unlocked(fp));

  ASSERT_NE(EOF, putc_unlocked('a', fp));
  ASSERT_NE(EOF, putc('b', fp));
  ASSERT_NE(EOF, fputc_unlocked('c', fp));
  ASSERT_NE(EOF, fputc('d', fp));

  rewind(fp);
  ASSERT_EQ('a', getc_unlocked(fp));
  ASSERT_EQ('b', getc(fp));
  ASSERT_EQ('c', fgetc_unlocked(fp));
  ASSERT_EQ('d', fgetc(fp));

  rewind(fp);
  ASSERT_EQ(2U, fwrite_unlocked("AB", 1, 2, fp));
  ASSERT_EQ(2U, fwrite("CD", 1, 2, fp));
  ASSERT_EQ(0, fflush_unlocked(fp));

  rewind(fp);
  char buf[BUFSIZ] = {};
  ASSERT_EQ(2U, fread_unlocked(&buf[0], 1, 2, fp));
  ASSERT_EQ(2U, fread(&buf[2], 1, 2, fp));
  ASSERT_STREQ("ABCD", buf);

  rewind(fp);
  ASSERT_NE(EOF, fputs("hello ", fp));
  ASSERT_NE(EOF, fputs_unlocked("world", fp));
  ASSERT_NE(EOF, fputc('\n', fp));

  rewind(fp);
  ASSERT_TRUE(fgets_unlocked(buf, sizeof(buf), fp) != nullptr);
  ASSERT_STREQ("hello world\n", buf);

  ASSERT_EQ(0, fclose(fp));
}

TEST(STDIO_TEST, fseek_64bit) {
  TemporaryFile tf;
  FILE* fp = fopen64(tf.path, "w+");
  ASSERT_TRUE(fp != nullptr);
  ASSERT_EQ(0, fseeko64(fp, 0x2'0000'0000, SEEK_SET));
  ASSERT_EQ(0x2'0000'0000, ftello64(fp));
  ASSERT_EQ(0, fseeko64(fp, 0x1'0000'0000, SEEK_CUR));
  ASSERT_EQ(0x3'0000'0000, ftello64(fp));
  ASSERT_EQ(0, fclose(fp));
}

// POSIX requires that fseek/fseeko fail with EOVERFLOW if the new file offset
// isn't representable in long/off_t.
TEST(STDIO_TEST, fseek_overflow_32bit) {
  TemporaryFile tf;
  FILE* fp = fopen64(tf.path, "w+");
  ASSERT_EQ(0, ftruncate64(fileno(fp), 0x2'0000'0000));

  // Bionic implements overflow checking for SEEK_CUR, but glibc doesn't.
#if defined(__BIONIC__) && !defined(__LP64__)
  ASSERT_EQ(0, fseek(fp, 0x7fff'ffff, SEEK_SET));
  ASSERT_EQ(-1, fseek(fp, 1, SEEK_CUR));
  ASSERT_ERRNO(EOVERFLOW);
#endif

  // Neither Bionic nor glibc implement the overflow checking for SEEK_END.
  // (Aside: FreeBSD's libc is an example of a libc that checks both SEEK_CUR
  // and SEEK_END -- many C libraries check neither.)
  ASSERT_EQ(0, fseek(fp, 0, SEEK_END));
  ASSERT_EQ(0x2'0000'0000, ftello64(fp));

  fclose(fp);
}

TEST(STDIO_TEST, dev_std_files) {
  // POSIX only mentions /dev/stdout, but we should have all three (http://b/31824379).
  char path[PATH_MAX];
  ssize_t length = readlink("/dev/stdin", path, sizeof(path));
  ASSERT_LT(0, length);
  ASSERT_EQ("/proc/self/fd/0", std::string(path, length));

  length = readlink("/dev/stdout", path, sizeof(path));
  ASSERT_LT(0, length);
  ASSERT_EQ("/proc/self/fd/1", std::string(path, length));

  length = readlink("/dev/stderr", path, sizeof(path));
  ASSERT_LT(0, length);
  ASSERT_EQ("/proc/self/fd/2", std::string(path, length));
}

TEST(STDIO_TEST, fread_with_locked_file) {
  // Reading an unbuffered/line-buffered file from one thread shouldn't block on
  // files locked on other threads, even if it flushes some line-buffered files.
  FILE* fp1 = fopen("/dev/zero", "r");
  ASSERT_TRUE(fp1 != nullptr);
  flockfile(fp1);

  std::thread([] {
    for (int mode : { _IONBF, _IOLBF }) {
      FILE* fp2 = fopen("/dev/zero", "r");
      ASSERT_TRUE(fp2 != nullptr);
      setvbuf(fp2, nullptr, mode, 0);
      ASSERT_EQ('\0', fgetc(fp2));
      fclose(fp2);
    }
  }).join();

  funlockfile(fp1);
  fclose(fp1);
}

TEST(STDIO_TEST, SEEK_macros) {
  ASSERT_EQ(0, SEEK_SET);
  ASSERT_EQ(1, SEEK_CUR);
  ASSERT_EQ(2, SEEK_END);
  ASSERT_EQ(3, SEEK_DATA);
  ASSERT_EQ(4, SEEK_HOLE);
  // So we'll notice if Linux grows another constant in <linux/fs.h>...
  ASSERT_EQ(SEEK_MAX, SEEK_HOLE);
}

TEST(STDIO_TEST, rename) {
  TemporaryDir td;
  std::string old_path = td.path + "/old"s;
  std::string new_path = td.path + "/new"s;

  // Create the file, check it exists.
  ASSERT_EQ(0, close(creat(old_path.c_str(), 0666)));
  struct stat sb;
  ASSERT_EQ(0, stat(old_path.c_str(), &sb));
  ASSERT_EQ(-1, stat(new_path.c_str(), &sb));

  // Rename and check it moved.
  ASSERT_EQ(0, rename(old_path.c_str(), new_path.c_str()));
  ASSERT_EQ(-1, stat(old_path.c_str(), &sb));
  ASSERT_EQ(0, stat(new_path.c_str(), &sb));
}

TEST(STDIO_TEST, renameat) {
  TemporaryDir td;
  android::base::unique_fd dirfd{open(td.path, O_PATH)};
  std::string old_path = td.path + "/old"s;
  std::string new_path = td.path + "/new"s;

  // Create the file, check it exists.
  ASSERT_EQ(0, close(creat(old_path.c_str(), 0666)));
  struct stat sb;
  ASSERT_EQ(0, stat(old_path.c_str(), &sb));
  ASSERT_EQ(-1, stat(new_path.c_str(), &sb));

  // Rename and check it moved.
  ASSERT_EQ(0, renameat(dirfd, "old", dirfd, "new"));
  ASSERT_EQ(-1, stat(old_path.c_str(), &sb));
  ASSERT_EQ(0, stat(new_path.c_str(), &sb));
}

TEST(STDIO_TEST, renameat2) {
#if defined(__GLIBC__) || defined(ANDROID_HOST_MUSL)
  GTEST_SKIP() << "glibc doesn't have renameat2 until 2.28 and musl doesn't have renameat2";
#else
  TemporaryDir td;
  android::base::unique_fd dirfd{open(td.path, O_PATH)};
  std::string old_path = td.path + "/old"s;
  std::string new_path = td.path + "/new"s;

  // Create the file, check it exists.
  ASSERT_EQ(0, close(creat(old_path.c_str(), 0666)));
  struct stat sb;
  ASSERT_EQ(0, stat(old_path.c_str(), &sb));
  ASSERT_EQ(-1, stat(new_path.c_str(), &sb));

  // Rename and check it moved.
  ASSERT_EQ(0, renameat2(dirfd, "old", dirfd, "new", 0));
  ASSERT_EQ(-1, stat(old_path.c_str(), &sb));
  ASSERT_EQ(0, stat(new_path.c_str(), &sb));

  // After this, both "old" and "new" exist.
  ASSERT_EQ(0, close(creat(old_path.c_str(), 0666)));

  // Rename and check it moved.
  ASSERT_EQ(-1, renameat2(dirfd, "old", dirfd, "new", RENAME_NOREPLACE));
  ASSERT_ERRNO(EEXIST);
#endif
}

TEST(STDIO_TEST, renameat2_flags) {
#if defined(__GLIBC__)
  GTEST_SKIP() << "glibc doesn't have renameat2 until 2.28";
#else
 ASSERT_NE(0, RENAME_EXCHANGE);
 ASSERT_NE(0, RENAME_NOREPLACE);
 ASSERT_NE(0, RENAME_WHITEOUT);
#endif
}

TEST(STDIO_TEST, fdopen_failures) {
  FILE* fp;
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);

  // Nonsense mode.
  errno = 0;
  fp = fdopen(fd, "nonsense");
  ASSERT_TRUE(fp == nullptr);
  ASSERT_ERRNO(EINVAL);

  // Mode that isn't a subset of the fd's actual mode.
  errno = 0;
  fp = fdopen(fd, "w");
  ASSERT_TRUE(fp == nullptr);
  ASSERT_ERRNO(EINVAL);

  // Can't set append on the underlying fd.
  errno = 0;
  fp = fdopen(fd, "a");
  ASSERT_TRUE(fp == nullptr);
  ASSERT_ERRNO(EINVAL);

  // Bad fd.
  errno = 0;
  fp = fdopen(-1, "re");
  ASSERT_TRUE(fp == nullptr);
  ASSERT_ERRNO(EBADF);

  close(fd);
}

TEST(STDIO_TEST, fmemopen_invalid_mode) {
  errno = 0;
  FILE* fp = fmemopen(nullptr, 16, "nonsense");
  ASSERT_TRUE(fp == nullptr);
  ASSERT_ERRNO(EINVAL);
}

TEST(STDIO_TEST, fopen_invalid_mode) {
  errno = 0;
  FILE* fp = fopen("/proc/version", "nonsense");
  ASSERT_TRUE(fp == nullptr);
  ASSERT_ERRNO(EINVAL);
}

TEST(STDIO_TEST, freopen_invalid_mode) {
  FILE* fp = fopen("/proc/version", "re");
  ASSERT_TRUE(fp != nullptr);

  errno = 0;
  fp = freopen("/proc/version", "nonsense", fp);
  ASSERT_TRUE(fp == nullptr);
  ASSERT_ERRNO(EINVAL);
}

TEST(STDIO_TEST, asprintf_smoke) {
  char* p = nullptr;
  ASSERT_EQ(11, asprintf(&p, "hello %s", "world"));
  ASSERT_STREQ("hello world", p);
  free(p);
}

TEST(STDIO_TEST, fopen_ENOENT) {
  errno = 0;
  FILE* fp = fopen("/proc/does-not-exist", "re");
  ASSERT_TRUE(fp == nullptr);
  ASSERT_ERRNO(ENOENT);
}

static void tempnam_test(bool has_TMPDIR, const char* dir, const char* prefix, const char* re) {
  if (has_TMPDIR) {
    setenv("TMPDIR", "/my/tmp/dir", 1);
  } else {
    unsetenv("TMPDIR");
  }
  char* s1 = tempnam(dir, prefix);
  char* s2 = tempnam(dir, prefix);
  ASSERT_MATCH(s1, re);
  ASSERT_MATCH(s2, re);
  ASSERT_STRNE(s1, s2);
  free(s1);
  free(s2);
}

TEST(STDIO_TEST, tempnam__system_directory_system_prefix_with_TMPDIR) {
  tempnam_test(true, nullptr, nullptr, "^/my/tmp/dir/.*");
}

TEST(STDIO_TEST, tempnam__system_directory_system_prefix_without_TMPDIR) {
  tempnam_test(false, nullptr, nullptr, "^/data/local/tmp/.*");
}

TEST(STDIO_TEST, tempnam__system_directory_user_prefix_with_TMPDIR) {
  tempnam_test(true, nullptr, "prefix", "^/my/tmp/dir/prefix.*");
}

TEST(STDIO_TEST, tempnam__system_directory_user_prefix_without_TMPDIR) {
  tempnam_test(false, nullptr, "prefix", "^/data/local/tmp/prefix.*");
}

TEST(STDIO_TEST, tempnam__user_directory_system_prefix_with_TMPDIR) {
  tempnam_test(true, "/a/b/c", nullptr, "^/my/tmp/dir/.*");
}

TEST(STDIO_TEST, tempnam__user_directory_system_prefix_without_TMPDIR) {
  tempnam_test(false, "/a/b/c", nullptr, "^/a/b/c/.*");
}

TEST(STDIO_TEST, tempnam__user_directory_user_prefix_with_TMPDIR) {
  tempnam_test(true, "/a/b/c", "prefix", "^/my/tmp/dir/prefix.*");
}

TEST(STDIO_TEST, tempnam__user_directory_user_prefix_without_TMPDIR) {
  tempnam_test(false, "/a/b/c", "prefix", "^/a/b/c/prefix.*");
}

static void tmpnam_test(char* s) {
  char s1[L_tmpnam], s2[L_tmpnam];

  strcpy(s1, tmpnam(s));
  strcpy(s2, tmpnam(s));
  ASSERT_MATCH(s1, "/tmp/.*");
  ASSERT_MATCH(s2, "/tmp/.*");
  ASSERT_STRNE(s1, s2);
}

TEST(STDIO_TEST, tmpnam) {
  tmpnam_test(nullptr);
}

TEST(STDIO_TEST, tmpnam_buf) {
  char buf[L_tmpnam];
  tmpnam_test(buf);
}

TEST(STDIO_TEST, freopen_null_filename_mode) {
  TemporaryFile tf;
  FILE* fp = fopen(tf.path, "r");
  ASSERT_TRUE(fp != nullptr);

  // "r" = O_RDONLY
  char buf[1];
  ASSERT_EQ(0, read(fileno(fp), buf, 1));
  ASSERT_EQ(-1, write(fileno(fp), "hello", 1));
  // "r+" = O_RDWR
  fp = freopen(nullptr, "r+", fp);
  ASSERT_EQ(0, read(fileno(fp), buf, 1));
  ASSERT_EQ(1, write(fileno(fp), "hello", 1));
  // "w" = O_WRONLY
  fp = freopen(nullptr, "w", fp);
  ASSERT_EQ(-1, read(fileno(fp), buf, 1));
  ASSERT_EQ(1, write(fileno(fp), "hello", 1));

  fclose(fp);
}

#if defined(__LP64__)
static int64_t GetTotalRamGiB() {
  struct sysinfo si;
  sysinfo(&si);
  return (static_cast<int64_t>(si.totalram) * si.mem_unit) / 1024 / 1024 / 1024;
}
#endif

TEST(STDIO_TEST, fread_int_overflow) {
#if defined(__LP64__)
  if (GetTotalRamGiB() <= 4) GTEST_SKIP() << "not enough memory";

  const size_t too_big_for_an_int = 0x80000000ULL;
  std::vector<char> buf(too_big_for_an_int);
  std::unique_ptr<FILE, decltype(&fclose)> fp{fopen("/dev/zero", "re"), fclose};
  ASSERT_EQ(too_big_for_an_int, fread(&buf[0], 1, too_big_for_an_int, fp.get()));
#else
  GTEST_SKIP() << "32-bit can't allocate 2GiB";
#endif
}

TEST(STDIO_TEST, fwrite_int_overflow) {
#if defined(__LP64__)
  if (GetTotalRamGiB() <= 4) GTEST_SKIP() << "not enough memory";

  const size_t too_big_for_an_int = 0x80000000ULL;
  std::vector<char> buf(too_big_for_an_int);
  std::unique_ptr<FILE, decltype(&fclose)> fp{fopen("/dev/null", "we"), fclose};
  ASSERT_EQ(too_big_for_an_int, fwrite(&buf[0], 1, too_big_for_an_int, fp.get()));
#else
  GTEST_SKIP() << "32-bit can't allocate 2GiB";
#endif
}

TEST(STDIO_TEST, snprintf_b_B) {
#if defined(__BIONIC__)
  uint8_t b = 5;
  EXPECT_SNPRINTF("<101>", "<%" PRIb8 ">", b);
  EXPECT_SNPRINTF("<101>", "<%" PRIB8 ">", b);
  EXPECT_SNPRINTF("<00000101>", "<%08" PRIb8 ">", b);
  EXPECT_SNPRINTF("<00000101>", "<%08" PRIB8 ">", b);

  uint16_t s = 0xaaaa;
  EXPECT_SNPRINTF("<1010101010101010>", "<%" PRIb16 ">", s);
  EXPECT_SNPRINTF("<1010101010101010>", "<%" PRIB16 ">", s);
  EXPECT_SNPRINTF("<0b1010101010101010>", "<%#" PRIb16 ">", s);
  EXPECT_SNPRINTF("<0B1010101010101010>", "<%#" PRIB16 ">", s);

  EXPECT_SNPRINTF("<10101010101010101010101010101010>", "<%" PRIb32 ">", 0xaaaaaaaa);
  EXPECT_SNPRINTF("<10101010101010101010101010101010>", "<%" PRIB32 ">", 0xaaaaaaaa);
  EXPECT_SNPRINTF("<0b10101010101010101010101010101010>", "<%#" PRIb32 ">", 0xaaaaaaaa);
  EXPECT_SNPRINTF("<0B10101010101010101010101010101010>", "<%#" PRIB32 ">", 0xaaaaaaaa);

  // clang doesn't like "%lb" (https://github.com/llvm/llvm-project/issues/62247)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
  EXPECT_SNPRINTF("<1010101010101010101010101010101010101010101010101010101010101010>",
                  "<%" PRIb64 ">", 0xaaaaaaaa'aaaaaaaa);
  EXPECT_SNPRINTF("<1010101010101010101010101010101010101010101010101010101010101010>",
                  "<%" PRIB64 ">", 0xaaaaaaaa'aaaaaaaa);
  EXPECT_SNPRINTF("<0b1010101010101010101010101010101010101010101010101010101010101010>",
                  "<%#" PRIb64 ">", 0xaaaaaaaa'aaaaaaaa);
  EXPECT_SNPRINTF("<0B1010101010101010101010101010101010101010101010101010101010101010>",
                  "<%#" PRIB64 ">", 0xaaaaaaaa'aaaaaaaa);
#pragma clang diagnostic pop

  EXPECT_SNPRINTF("<0>", "<%#b>", 0);
  EXPECT_SNPRINTF("<0>", "<%#B>", 0);
#else
  GTEST_SKIP() << "no %b in glibc";
#endif
}

TEST(STDIO_TEST, swprintf_b_B) {
#if defined(__BIONIC__)
  uint8_t b = 5;
  EXPECT_SWPRINTF(L"<101>", L"<%" PRIb8 ">", b);
  EXPECT_SWPRINTF(L"<101>", L"<%" PRIB8 ">", b);
  EXPECT_SWPRINTF(L"<0b101>", L"<%#" PRIb8 ">", b);
  EXPECT_SWPRINTF(L"<0B101>", L"<%#" PRIB8 ">", b);
  EXPECT_SWPRINTF(L"<00000101>", L"<%08" PRIb8 ">", b);
  EXPECT_SWPRINTF(L"<00000101>", L"<%08" PRIB8 ">", b);

  uint16_t s = 0xaaaa;
  EXPECT_SWPRINTF(L"<1010101010101010>", L"<%" PRIb16 ">", s);
  EXPECT_SWPRINTF(L"<1010101010101010>", L"<%" PRIB16 ">", s);
  EXPECT_SWPRINTF(L"<0b1010101010101010>", L"<%#" PRIb16 ">", s);
  EXPECT_SWPRINTF(L"<0B1010101010101010>", L"<%#" PRIB16 ">", s);

  EXPECT_SWPRINTF(L"<10101010101010101010101010101010>", L"<%" PRIb32 ">", 0xaaaaaaaa);
  EXPECT_SWPRINTF(L"<10101010101010101010101010101010>", L"<%" PRIB32 ">", 0xaaaaaaaa);
  EXPECT_SWPRINTF(L"<0b10101010101010101010101010101010>", L"<%#" PRIb32 ">", 0xaaaaaaaa);
  EXPECT_SWPRINTF(L"<0B10101010101010101010101010101010>", L"<%#" PRIB32 ">", 0xaaaaaaaa);

  // clang doesn't like "%lb" (https://github.com/llvm/llvm-project/issues/62247)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
  EXPECT_SWPRINTF(L"<1010101010101010101010101010101010101010101010101010101010101010>",
                  L"<%" PRIb64 ">", 0xaaaaaaaa'aaaaaaaa);
  EXPECT_SWPRINTF(L"<1010101010101010101010101010101010101010101010101010101010101010>",
                  L"<%" PRIB64 ">", 0xaaaaaaaa'aaaaaaaa);
  EXPECT_SWPRINTF(L"<0b1010101010101010101010101010101010101010101010101010101010101010>",
                  L"<%#" PRIb64 ">", 0xaaaaaaaa'aaaaaaaa);
  EXPECT_SWPRINTF(L"<0B1010101010101010101010101010101010101010101010101010101010101010>",
                  L"<%#" PRIB64 ">", 0xaaaaaaaa'aaaaaaaa);
#pragma clang diagnostic pop

  EXPECT_SWPRINTF(L"<0>", L"<%#b>", 0);
  EXPECT_SWPRINTF(L"<0>", L"<%#B>", 0);
#else
  GTEST_SKIP() << "no %b in glibc";
#endif
}

TEST(STDIO_TEST, scanf_i_decimal) {
  int i;
  EXPECT_EQ(1, sscanf("<123789>", "<%i>", &i));
  EXPECT_EQ(123789, i);

  long long int lli;
  char ch;
  EXPECT_EQ(2, sscanf("1234567890abcdefg", "%lli%c", &lli, &ch));
  EXPECT_EQ(1234567890, lli);
  EXPECT_EQ('a', ch);
}

TEST(STDIO_TEST, scanf_i_hex) {
  int i;
  EXPECT_EQ(1, sscanf("<0x123abf>", "<%i>", &i));
  EXPECT_EQ(0x123abf, i);

  long long int lli;
  char ch;
  EXPECT_EQ(2, sscanf("0x1234567890abcdefg", "%lli%c", &lli, &ch));
  EXPECT_EQ(0x1234567890abcdefLL, lli);
  EXPECT_EQ('g', ch);
}

TEST(STDIO_TEST, scanf_i_octal) {
  int i;
  EXPECT_EQ(1, sscanf("<01234567>", "<%i>", &i));
  EXP
"""


```