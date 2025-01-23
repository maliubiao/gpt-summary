Response:
My goal is to analyze the provided C++ code snippet from `bionic/tests/string_test.cpp` and summarize its functionality as the first part of a two-part response.

Here's my thought process to achieve that:

1. **Identify the Core Purpose:** The filename `string_test.cpp` immediately suggests that this file contains tests for string manipulation functions. The inclusion of `<string.h>` further confirms this. The presence of `gtest/gtest.h` indicates that Google Test is used as the testing framework.

2. **Break Down the Code into Functional Blocks:** I'll scan through the code, looking for distinct `TEST` macros. Each `TEST` block represents a test case for a specific function or a group of related functionalities.

3. **List the Tested Functions:**  As I identify the `TEST` blocks, I'll note down the function being tested within each block. This will give me a comprehensive list of the string functions covered by these tests. The functions I see are:
    * `strerror`
    * `strerror_l`
    * `strerror_concurrent`
    * `gnu_strerror_r`
    * `strsignal`
    * `strsignal_concurrent`
    * `strcat`
    * `strcpy`
    * `stpcpy`
    * `strncat`
    * `strchr`
    * `strchrnul`
    * `strcmp`
    * `strlcat`
    * `strlcpy`
    * `strncmp`
    * `stpncpy`
    * `strncpy`
    * `strrchr`
    * `memchr`
    * `memrchr`
    * `memcmp`
    * `wmemcmp`
    * `memcpy`
    * `memset`
    * `memmove`
    * `bcopy`
    * `bzero`

4. **Recognize Test Patterns:**  I notice a common pattern within many of the `TEST` blocks:
    * Setting up test data (often using `StringTestState` for parameterized testing with various lengths and alignments).
    * Calling the function under test.
    * Using `ASSERT_*` or `EXPECT_*` macros from Google Test to verify the correctness of the function's behavior (e.g., comparing return values, checking memory contents).

5. **Identify Conditional Compilation:**  The `#if defined(__BIONIC__)` blocks are important. They indicate that certain tests or behaviors are specific to the Bionic library. I need to note these distinctions. Specifically, `STRLCPY_SUPPORTED` and `STRLCAT_SUPPORTED` are defined under `__BIONIC__`, and some concurrency tests are also conditional.

6. **Look for Special Test Structures:** The `StringTestState` template class appears to be a custom helper for generating test cases with varying string lengths and memory alignments. This is a significant part of the testing strategy and should be mentioned.

7. **Consider the Scope:**  The initial prompt states that this is a test file for Android's Bionic library. Therefore, the functions being tested are likely standard C library string functions, as Bionic provides these.

8. **Formulate the Summary:**  Based on the above observations, I can now formulate a concise summary of the file's functionality:

    * **Core Function:** The primary purpose of the file is to test the implementation of various string manipulation functions within Android's Bionic library.
    * **Testing Framework:** It uses Google Test for structuring and running the tests.
    * **Functions Tested:**  A comprehensive list of the tested functions (as identified in step 3).
    * **Test Coverage:** The tests aim to cover different scenarios, including valid and invalid inputs, edge cases (like empty strings or buffer overflows - implicitly through checks on buffer boundaries and return values), and different memory alignments.
    * **Bionic Specifics:** Some tests are specifically designed for Bionic, particularly those related to thread safety of `strerror` and the presence of `strlcpy` and `strlcat`.
    * **Parameterized Testing:** The `StringTestState` class facilitates parameterized testing by varying string lengths and memory alignments.
    * **Focus:** The tests primarily focus on the correctness of the standard C string functions provided by Bionic.

By following this thought process, I can effectively analyze the code and generate the required summary for part 1 of the response. This systematic approach ensures that I capture the key aspects of the file's functionality.
这是bionic/tests/string_test.cpp文件的第一部分，其主要功能是**测试 Android Bionic 库中字符串处理相关函数的实现是否正确**。

以下是对其功能的归纳：

1. **测试标准 C 字符串函数：** 该文件包含了大量针对 `<string.h>` 中定义的标准 C 字符串函数的测试用例，例如：
    * `strerror` 和 `strerror_l`:  测试获取错误码对应的错误信息字符串的功能。
    * `strsignal`: 测试获取信号编号对应的信号名称字符串的功能。
    * `strerror_r`: 测试线程安全的 `strerror` 版本（仅针对 GNU 实现）。
    * `strcat`, `strcpy`, `stpcpy`, `strncat`, `strncpy`, `stpncpy`: 测试字符串复制和连接功能。
    * `strchr`, `strrchr`, `strchrnul`: 测试在字符串中查找字符的功能。
    * `strcmp`, `strncmp`: 测试字符串比较功能。
    * `strlcat`, `strlcpy`: 测试具有大小限制的安全字符串复制和连接功能（仅在 Bionic 中支持）。
    * `memchr`, `memrchr`: 测试在内存块中查找字符的功能。
    * `memcmp`: 测试内存块比较功能。
    * `memcpy`, `memmove`, `bcopy`: 测试内存块复制功能（`memmove` 考虑了内存重叠的情况，`bcopy` 是一个历史遗留函数）。
    * `memset`, `bzero`: 测试填充内存块的功能。
    * `wmemcmp`: 测试宽字符内存块比较功能。

2. **覆盖各种测试场景：**  测试用例设计考虑了多种情况，包括：
    * **边界情况：** 例如空字符串、缓冲区大小限制等。
    * **不同的输入值：** 例如有效的和无效的错误码、信号编号。
    * **内存对齐：** 使用 `StringTestState` 模板类来测试不同内存对齐方式下的函数行为。
    * **重叠内存区域：**  `memmove` 的测试用例专门验证了处理源和目标内存区域重叠的能力。
    * **并发情况：**  针对 `strerror` 和 `strsignal` 进行了并发测试，以验证其线程安全性（部分测试仅在 Bionic 环境下运行）。

3. **使用 Google Test 框架：**  该文件使用了 Google Test 框架来编写和组织测试用例，使得测试代码结构清晰，易于维护。

4. **Bionic 特有功能测试：**  通过条件编译 (`#if defined(__BIONIC__)`)，该文件也包含了一些针对 Bionic 库特有功能的测试，例如 `strlcpy` 和 `strlcat`。

5. **内存安全测试：**  虽然没有明确的安全测试框架，但测试用例通过各种边界条件和缓冲区大小的测试，可以间接验证一些潜在的内存安全问题。

**总结来说，`bionic/tests/string_test.cpp` 的第一部分是一个针对 Android Bionic 库中核心字符串处理函数的综合性测试套件，旨在确保这些函数的功能正确、稳定，并能在各种场景下可靠运行。**

在后续的第二部分中，可能会包含更多针对性能、特定平台或者更复杂的字符串操作的测试。

### 提示词
```
这是目录为bionic/tests/string_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE 1

#include <string.h>

#include <errno.h>
#include <gtest/gtest.h>
#include <malloc.h>
#include <math.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include <algorithm>
#include <vector>

#include "buffer_tests.h"
#include "utils.h"

#if defined(NOFORTIFY)
#define STRING_TEST string_nofortify
#else
#define STRING_TEST string
#endif

#if defined(__BIONIC__)
#define STRLCPY_SUPPORTED
#define STRLCAT_SUPPORTED
#endif

constexpr auto KB = 1024;
constexpr auto SMALL = 1 * KB;
constexpr auto MEDIUM = 4 * KB;
constexpr auto LARGE = 64 * KB;

static int signum(int i) {
  if (i < 0) {
    return -1;
  } else if (i > 0) {
    return 1;
  }
  return 0;
}

TEST(STRING_TEST, strerror) {
  // Valid.
  ASSERT_STREQ("Success", strerror(0));
  ASSERT_STREQ("Operation not permitted", strerror(1));

  // Invalid.
  ASSERT_STREQ("Unknown error -1", strerror(-1));
  ASSERT_STREQ("Unknown error 134", strerror(EHWPOISON + 1));
}

TEST(STRING_TEST, strerror_l) {
  // bionic just forwards to strerror(3).
  ASSERT_STREQ("Success", strerror_l(0, LC_GLOBAL_LOCALE));
}

#if defined(__BIONIC__)
static void* ConcurrentStrErrorFn(void*) {
  bool equal = (strcmp("Unknown error 2002", strerror(2002)) == 0);
  return reinterpret_cast<void*>(equal);
}
#endif // __BIONIC__

// glibc's strerror isn't thread safe, only its strsignal.
TEST(STRING_TEST, strerror_concurrent) {
#if defined(__BIONIC__)
  const char* strerror1001 = strerror(1001);
  ASSERT_STREQ("Unknown error 1001", strerror1001);

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, ConcurrentStrErrorFn, nullptr));
  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_TRUE(static_cast<bool>(result));

  ASSERT_STREQ("Unknown error 1001", strerror1001);
#else // __BIONIC__
  GTEST_SKIP() << "thread-safe strerror not available";
#endif // __BIONIC__
}

TEST(STRING_TEST, gnu_strerror_r) {
#if !defined(ANDROID_HOST_MUSL)
  char buf[256];

  // Note that glibc doesn't necessarily write into the buffer.

  // Valid.
  ASSERT_STREQ("Success", strerror_r(0, buf, sizeof(buf)));
#if defined(__BIONIC__)
  ASSERT_STREQ("Success", buf);
#endif
  ASSERT_STREQ("Operation not permitted", strerror_r(1, buf, sizeof(buf)));
#if defined(__BIONIC__)
  ASSERT_STREQ("Operation not permitted", buf);
#endif

  // Invalid.
  ASSERT_STREQ("Unknown error -1", strerror_r(-1, buf, sizeof(buf)));
  ASSERT_STREQ("Unknown error -1", buf);
  ASSERT_STREQ("Unknown error 1234", strerror_r(1234, buf, sizeof(buf)));
  ASSERT_STREQ("Unknown error 1234", buf);

  // Buffer too small.
  errno = 0;
  memset(buf, 0, sizeof(buf));
  ASSERT_EQ(buf, strerror_r(4567, buf, 2));
  ASSERT_STREQ("U", buf);
  // The GNU strerror_r doesn't set errno (the POSIX one sets it to ERANGE).
  ASSERT_ERRNO(0);
#else
  GTEST_SKIP() << "musl doesn't have GNU strerror_r";
#endif
}

TEST(STRING_TEST, strsignal) {
  // A regular signal.
  ASSERT_STREQ("Hangup", strsignal(1));

  // A real-time signal.
  ASSERT_STREQ("Real-time signal 14", strsignal(SIGRTMIN + 14));
  // One of the signals the C library keeps to itself.
  ASSERT_STREQ("Unknown signal 32", strsignal(32));  // __SIGRTMIN

  // Errors.
  ASSERT_STREQ("Unknown signal -1", strsignal(-1)); // Too small.
  ASSERT_STREQ("Unknown signal 0", strsignal(0)); // Still too small.
  ASSERT_STREQ("Unknown signal 1234", strsignal(1234)); // Too large.
}

static void* ConcurrentStrSignalFn(void*) {
  bool equal = (strcmp("Unknown signal 2002", strsignal(2002)) == 0);
  return reinterpret_cast<void*>(equal);
}

TEST(STRING_TEST, strsignal_concurrent) {
  const char* strsignal1001 = strsignal(1001);
  ASSERT_STREQ("Unknown signal 1001", strsignal1001);

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, ConcurrentStrSignalFn, nullptr));
  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_TRUE(static_cast<bool>(result));

  ASSERT_STREQ("Unknown signal 1001", strsignal1001);
}

// TODO: where did this number come from?
#define ITER        500

// For every length we want to test, vary and change alignment
// of allocated memory, fill it with some values, calculate
// expected result and then run function and compare what we got.
// These tests contributed by Intel Corporation.
// TODO: make these tests more intention-revealing and less random.
template<class Character>
class StringTestState {
 public:
  explicit StringTestState(size_t MAX_LEN) : MAX_LEN(MAX_LEN), align1_index_(0), align2_index_(0) {
    int max_alignment = 64;

    // TODO: fix the tests to not sometimes use twice their specified "MAX_LEN".
    glob_ptr = reinterpret_cast<Character*>(memalign(sysconf(_SC_PAGESIZE), 2 * sizeof(Character) * MAX_LEN + max_alignment));
    glob_ptr1 = reinterpret_cast<Character*>(memalign(sysconf(_SC_PAGESIZE), 2 * sizeof(Character) * MAX_LEN + max_alignment));
    glob_ptr2 = reinterpret_cast<Character*>(memalign(sysconf(_SC_PAGESIZE), 2 * sizeof(Character) * MAX_LEN + max_alignment));

    InitLenArray();

    srandom(1234);
  }

  ~StringTestState() {
    free(glob_ptr);
    free(glob_ptr1);
    free(glob_ptr2);
  }

  void BeginIterations() {
    align1_index_ = 0;
    align2_index_ = 0;

    ResetPointers();
  }

  bool HasNextIteration() {
    return (align1_index_ != (alignments_size - 1) || align2_index_ != (alignments_size - 1));
  }

  void NextIteration() {
    if (align1_index_ == (alignments_size - 1) && align2_index_ == (alignments_size - 1)) {
      return;
    }

    if (align1_index_ == (alignments_size - 1)) {
      align1_index_ = 0;
      align2_index_++;
    } else {
      align1_index_++;
    }

    ResetPointers();
  }

  const size_t MAX_LEN;
  Character *ptr, *ptr1, *ptr2;
  size_t n;
  size_t len[ITER + 1];

 private:
  static size_t alignments[];
  static size_t alignments_size;
  Character *glob_ptr, *glob_ptr1, *glob_ptr2;
  size_t align1_index_, align2_index_;

  // Calculate input lengths and fill state.len with them.
  // Test small lengths with more density than big ones. Manually push
  // smallest (0) and biggest (MAX_LEN) lengths. Avoid repeats.
  // Return number of lengths to test.
  void InitLenArray() {
    n = 0;
    len[n++] = 0;
    for (size_t i = 1; i < ITER; ++i) {
      size_t l = static_cast<size_t>(exp(log(static_cast<double>(MAX_LEN)) * i / ITER));
      if (l != len[n - 1]) {
        len[n++] = l;
      }
    }
    len[n++] = MAX_LEN;
  }

  void ResetPointers() {
    if (align1_index_ == alignments_size || align2_index_ == alignments_size) {
      ptr = ptr1 = ptr2 = nullptr;
    } else {
      ptr = glob_ptr + alignments[align1_index_];
      ptr1 = glob_ptr1 + alignments[align1_index_];
      ptr2 = glob_ptr2 + alignments[align2_index_];
    }
  }
};

template<class Character>
size_t StringTestState<Character>::alignments[] = { 24, 32, 16, 48, 0, 1, 2, 3, 4, 5, 6, 7, 11 };

template<class Character>
size_t StringTestState<Character>::alignments_size = sizeof(alignments)/sizeof(size_t);

TEST(STRING_TEST, strcat) {
  StringTestState<char> state(SMALL);
  for (size_t i = 1; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr2, '\2', state.MAX_LEN);
      state.ptr2[state.MAX_LEN - 1] = '\0';
      memcpy(state.ptr, state.ptr2, 2 * state.MAX_LEN);

      memset(state.ptr1, 'L', state.len[i]);
      state.ptr1[random() % state.len[i]] = '\0';
      state.ptr1[state.len[i] - 1] = '\0';

      strcpy(state.ptr + state.MAX_LEN - 1, state.ptr1);

      EXPECT_TRUE(strcat(state.ptr2, state.ptr1) == state.ptr2);
      EXPECT_TRUE(memcmp(state.ptr, state.ptr2, 2 * state.MAX_LEN) == 0);
    }
  }
}

// one byte target with "\0" source
TEST(STRING_TEST, strcpy2) {
  char buf[1];
  char* orig = strdup("");
  ASSERT_EQ(buf, strcpy(buf, orig));
  ASSERT_EQ('\0', buf[0]);
  free(orig);
}

// multibyte target where we under fill target
TEST(STRING_TEST, strcpy3) {
  char buf[10];
  char* orig = strdup("12345");
  memset(buf, 'A', sizeof(buf));
  ASSERT_EQ(buf, strcpy(buf, orig));
  ASSERT_STREQ("12345", buf);
  ASSERT_EQ('A',  buf[6]);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('A',  buf[9]);
  free(orig);
}

// multibyte target where we fill target exactly
TEST(STRING_TEST, strcpy4) {
  char buf[10];
  char* orig = strdup("123456789");
  memset(buf, 'A', sizeof(buf));
  ASSERT_EQ(buf, strcpy(buf, orig));
  ASSERT_STREQ("123456789", buf);
  free(orig);
}

// one byte target with "\0" source
TEST(STRING_TEST, stpcpy2) {
  char buf[1];
  memset(buf, 'A', sizeof(buf));
  char* orig = strdup("");
  EXPECT_EQ(buf, stpcpy(buf, orig));
  EXPECT_EQ('\0', buf[0]);
  free(orig);
}

// multibyte target where we under fill target
TEST(STRING_TEST, stpcpy3) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  char* orig = strdup("12345");
  EXPECT_EQ(buf+strlen(orig), stpcpy(buf, orig));
  EXPECT_STREQ("12345", buf);
  EXPECT_EQ('A',  buf[6]);
  EXPECT_EQ('A',  buf[7]);
  EXPECT_EQ('A',  buf[8]);
  EXPECT_EQ('A',  buf[9]);
  free(orig);
}

// multibyte target where we fill target exactly
TEST(STRING_TEST, stpcpy4) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  char* orig = strdup("123456789");
  EXPECT_EQ(buf+strlen(orig), stpcpy(buf, orig));
  EXPECT_STREQ("123456789", buf);
  free(orig);
}

TEST(STRING_TEST, strcat2) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = strcat(buf, "01234");
  ASSERT_EQ(buf, res);
  ASSERT_STREQ("a01234", buf);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('A',  buf[9]);
}

TEST(STRING_TEST, strcat3) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = strcat(buf, "01234567");
  ASSERT_EQ(buf, res);
  ASSERT_STREQ("a01234567", buf);
}

TEST(STRING_TEST, strncat2) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = strncat(buf, "01234", sizeof(buf) - strlen(buf) - 1);
  ASSERT_EQ(buf, res);
  ASSERT_STREQ("a01234", buf);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('A',  buf[9]);
}

TEST(STRING_TEST, strncat3) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = strncat(buf, "0123456789", 5);
  ASSERT_EQ(buf, res);
  ASSERT_STREQ("a01234", buf);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('A',  buf[9]);
}

TEST(STRING_TEST, strncat4) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = strncat(buf, "01234567", 8);
  ASSERT_EQ(buf, res);
  ASSERT_STREQ("a01234567", buf);
}

TEST(STRING_TEST, strncat5) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = strncat(buf, "01234567", 9);
  ASSERT_EQ(buf, res);
  ASSERT_STREQ("a01234567", buf);
}

TEST(STRING_TEST, strchr_with_0) {
  char buf[10];
  const char* s = "01234";
  memcpy(buf, s, strlen(s) + 1);
  EXPECT_TRUE(strchr(buf, '\0') == (buf + strlen(s)));
}

TEST(STRING_TEST, strchr_multiple) {
  char str[128];
  memset(str, 'a', sizeof(str) - 1);
  str[sizeof(str)-1] = '\0';

  // Verify that strchr finds the first occurrence of 'a' in a string
  // filled with 'a' characters. Iterate over the string putting
  // non 'a' characters at the front of the string during each iteration
  // and continue to verify that strchr can find the first occurrence
  // properly. The idea is to cover all possible alignments of the location
  // of the first occurrence of the 'a' character and which includes
  // other 'a' characters close by.
  for (size_t i = 0; i < sizeof(str) - 1; i++) {
    EXPECT_EQ(&str[i], strchr(str, 'a'));
    str[i] = 'b';
  }
}

TEST(STRING_TEST, strchr) {
  int seek_char = 'R';

  StringTestState<char> state(SMALL);
  for (size_t i = 1; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      if (~seek_char > 0) {
        memset(state.ptr1, ~seek_char, state.len[i]);
      } else {
        memset(state.ptr1, '\1', state.len[i]);
      }
      state.ptr1[state.len[i] - 1] = '\0';

      size_t pos = random() % state.MAX_LEN;
      char* expected;
      if (pos >= state.len[i] - 1) {
        if (seek_char == 0) {
          expected = state.ptr1 + state.len[i] - 1;
        } else {
          expected = nullptr;
        }
      } else {
        state.ptr1[pos] = seek_char;
        expected = state.ptr1 + pos;
      }

      ASSERT_TRUE(strchr(state.ptr1, seek_char) == expected);
    }
  }
}

TEST(STRING_TEST, strchrnul) {
  const char* s = "01234222";
  EXPECT_TRUE(strchrnul(s, '2') == &s[2]);
  EXPECT_TRUE(strchrnul(s, '8') == (s + strlen(s)));
  EXPECT_TRUE(strchrnul(s, '\0') == (s + strlen(s)));
}

TEST(STRING_TEST, strcmp) {
  StringTestState<char> state(SMALL);
  for (size_t i = 1; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr1, 'v', state.MAX_LEN);
      memset(state.ptr2, 'n', state.MAX_LEN);
      state.ptr1[state.len[i] - 1] = '\0';
      state.ptr2[state.len[i] - 1] = '\0';

      size_t pos = 1 + (random() % (state.MAX_LEN - 1));
      int actual;
      int expected;
      if (pos >= state.len[i] - 1) {
        memcpy(state.ptr1, state.ptr2, state.len[i]);
        expected = 0;
        actual = strcmp(state.ptr1, state.ptr2);
      } else {
        memcpy(state.ptr1, state.ptr2, pos);
        if (state.ptr1[pos] > state.ptr2[pos]) {
          expected = 1;
        } else if (state.ptr1[pos] == state.ptr2[pos]) {
          state.ptr1[pos + 1] = '\0';
          state.ptr2[pos + 1] = '\0';
          expected = 0;
        } else {
          expected = -1;
        }
        actual = strcmp(state.ptr1, state.ptr2);
      }

      ASSERT_EQ(expected, signum(actual));
    }
  }
}

TEST(STRING_TEST, stpcpy) {
  StringTestState<char> state(SMALL);
  for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
    size_t pos = random() % state.MAX_LEN;

    memset(state.ptr1, '\2', pos);
    state.ptr1[pos] = '\0';
    state.ptr1[state.MAX_LEN - 1] = '\0';

    memcpy(state.ptr, state.ptr1, state.MAX_LEN);

    memset(state.ptr2, '\1', state.MAX_LEN);
    state.ptr2[state.MAX_LEN - 1] = '\0';

    memset(state.ptr + state.MAX_LEN, '\1', state.MAX_LEN);
    memcpy(state.ptr + state.MAX_LEN, state.ptr1, pos + 1);
    state.ptr[2 * state.MAX_LEN - 1] = '\0';

    ASSERT_TRUE(stpcpy(state.ptr2, state.ptr1) == state.ptr2 + strlen(state.ptr1));
    ASSERT_FALSE((memcmp(state.ptr1, state.ptr, state.MAX_LEN)) != 0 ||
                 (memcmp(state.ptr2, state.ptr + state.MAX_LEN, state.MAX_LEN) != 0));
  }
}

TEST(STRING_TEST, strcpy) {
  StringTestState<char> state(SMALL);
  for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
    size_t pos = random() % state.MAX_LEN;

    memset(state.ptr1, '\2', pos);
    state.ptr1[pos] = '\0';
    state.ptr1[state.MAX_LEN - 1] = '\0';

    memcpy(state.ptr, state.ptr1, state.MAX_LEN);

    memset(state.ptr2, '\1', state.MAX_LEN);
    state.ptr2[state.MAX_LEN - 1] = '\0';

    memset(state.ptr + state.MAX_LEN, '\1', state.MAX_LEN);
    memcpy(state.ptr + state.MAX_LEN, state.ptr1, pos + 1);
    state.ptr[2 * state.MAX_LEN - 1] = '\0';

    ASSERT_TRUE(strcpy(state.ptr2, state.ptr1) == state.ptr2);
    ASSERT_FALSE((memcmp(state.ptr1, state.ptr, state.MAX_LEN)) != 0 ||
                 (memcmp(state.ptr2, state.ptr + state.MAX_LEN, state.MAX_LEN) != 0));
  }
}

TEST(STRING_TEST, strlcat) {
#if defined(STRLCAT_SUPPORTED)
  StringTestState<char> state(SMALL);
  for (size_t i = 0; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr2, '\2', state.MAX_LEN + state.len[i]);
      state.ptr2[state.MAX_LEN - 1] = '\0';
      memcpy(state.ptr, state.ptr2, state.MAX_LEN + state.len[i]);

      size_t pos = random() % state.MAX_LEN;
      memset(state.ptr1, '\3', pos);
      state.ptr1[pos] = '\0';
      if (pos < state.len[i]) {
        memcpy(state.ptr + state.MAX_LEN - 1, state.ptr1, pos + 1);
      } else {
        memcpy(state.ptr + state.MAX_LEN - 1, state.ptr1, state.len[i]);
        state.ptr[state.MAX_LEN + state.len[i] - 1] = '\0';
      }

      strlcat(state.ptr2, state.ptr1, state.MAX_LEN + state.len[i]);

      ASSERT_TRUE(memcmp(state.ptr, state.ptr2, state.MAX_LEN + state.len[i]) == 0);
    }
  }
#else
  GTEST_SKIP() << "strlcat not available";
#endif
}

TEST(STRING_TEST, strlcpy) {
#if defined(STRLCPY_SUPPORTED)
  StringTestState<char> state(SMALL);
  for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
    int rand = 'O';
    memset(state.ptr1, rand, state.MAX_LEN);

    size_t pos = random() % state.MAX_LEN;
    if (pos < state.MAX_LEN) {
      state.ptr1[pos] = '\0';
    }
    memcpy(state.ptr, state.ptr1, state.MAX_LEN);

    memset(state.ptr2, 'I', state.MAX_LEN);
    memcpy(state.ptr + state.MAX_LEN, state.ptr2, state.MAX_LEN);

    if (pos > state.MAX_LEN - 1) {
      memcpy(state.ptr + state.MAX_LEN, state.ptr1, state.MAX_LEN);
      state.ptr[2 * state.MAX_LEN - 1] = '\0';
    } else {
      memcpy(state.ptr + state.MAX_LEN, state.ptr1, pos + 1);
    }

    ASSERT_EQ(strlcpy(state.ptr2, state.ptr1, state.MAX_LEN), strlen(state.ptr1));
    ASSERT_FALSE((memcmp(state.ptr1, state.ptr, state.MAX_LEN) != 0) ||
                 (memcmp(state.ptr2, state.ptr + state.MAX_LEN, state.MAX_LEN) != 0));
  }
#else
  GTEST_SKIP() << "strlcpy not available";
#endif
}

TEST(STRING_TEST, strncat) {
  StringTestState<char> state(SMALL);
  for (size_t i = 1; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr2, '\2', state.MAX_LEN);
      state.ptr2[state.MAX_LEN - 1] = '\0';
      memcpy(state.ptr, state.ptr2, 2 * state.MAX_LEN);

      memset(state.ptr1, 'I', state.len[i]);
      state.ptr1[random() % state.len[i]] = '\0';
      state.ptr1[state.len[i] - 1] = '\0';

      size_t pos = strlen(state.ptr1);

      size_t actual = random() % state.len[i];
      strncpy(state.ptr + state.MAX_LEN - 1, state.ptr1, std::min(actual, pos));
      state.ptr[state.MAX_LEN + std::min(actual, pos) - 1] = '\0';

      ASSERT_TRUE(strncat(state.ptr2, state.ptr1, actual) == state.ptr2);
      ASSERT_EQ(memcmp(state.ptr, state.ptr2, 2 * state.MAX_LEN), 0);
    }
  }
}

TEST(STRING_TEST, strncmp) {
  StringTestState<char> state(SMALL);
  for (size_t i = 1; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr1, 'v', state.MAX_LEN);
      memset(state.ptr2, 'n', state.MAX_LEN);
      state.ptr1[state.len[i] - 1] = '\0';
      state.ptr2[state.len[i] - 1] = '\0';

      size_t pos = 1 + (random() % (state.MAX_LEN - 1));
      int actual;
      int expected;
      if (pos >= state.len[i] - 1) {
        memcpy(state.ptr1, state.ptr2, state.len[i]);
        expected = 0;
        actual = strncmp(state.ptr1, state.ptr2, state.len[i]);
      } else {
        memcpy(state.ptr1, state.ptr2, pos);
        if (state.ptr1[pos] > state.ptr2[pos]) {
          expected = 1;
        } else if (state.ptr1[pos] == state.ptr2[pos]) {
          state.ptr1[pos + 1] = '\0';
          state.ptr2[pos + 1] = '\0';
          expected = 0;
        } else {
          expected = -1;
        }
        actual = strncmp(state.ptr1, state.ptr2, state.len[i]);
      }

      ASSERT_EQ(expected, signum(actual));
    }
  }
}

TEST(STRING_TEST, stpncpy) {
  StringTestState<char> state(SMALL);
  for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
    memset(state.ptr1, 'J', state.MAX_LEN);
    // Choose a random size for our src buffer.
    size_t ptr1_len = random() % state.MAX_LEN;
    state.ptr1[ptr1_len] = '\0';
    // Copy ptr1 into ptr, used to verify that ptr1 does not get modified.
    memcpy(state.ptr, state.ptr1, state.MAX_LEN);
    // Init ptr2 to a set value.
    memset(state.ptr2, '\1', state.MAX_LEN);

    // Choose a random amount of data to copy.
    size_t copy_len = random() % state.MAX_LEN;

    // Set the second half of ptr to the expected pattern in ptr2.
    memset(state.ptr + state.MAX_LEN, '\1', state.MAX_LEN);
    memcpy(state.ptr + state.MAX_LEN, state.ptr1, copy_len);
    size_t expected_end;
    if (copy_len > ptr1_len) {
      memset(state.ptr + state.MAX_LEN + ptr1_len, '\0', copy_len - ptr1_len);
      expected_end = ptr1_len;
    } else {
      expected_end = copy_len;
    }

    ASSERT_EQ(state.ptr2 + expected_end, stpncpy(state.ptr2, state.ptr1, copy_len));

    // Verify ptr1 was not modified.
    ASSERT_EQ(0, memcmp(state.ptr1, state.ptr, state.MAX_LEN));
    // Verify ptr2 contains the expected data.
    ASSERT_EQ(0, memcmp(state.ptr2, state.ptr + state.MAX_LEN, state.MAX_LEN));
  }
}

TEST(STRING_TEST, strncpy) {
  StringTestState<char> state(SMALL);
  for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
    // Choose a random value to fill the string, except \0 (string terminator),
    // or \1 (guarantees it's different from anything in ptr2).
    memset(state.ptr1, 'K', state.MAX_LEN);
    // Choose a random size for our src buffer.
    size_t ptr1_len = random() % state.MAX_LEN;
    state.ptr1[ptr1_len] = '\0';
    // Copy ptr1 into ptr, used to verify that ptr1 does not get modified.
    memcpy(state.ptr, state.ptr1, state.MAX_LEN);
    // Init ptr2 to a set value.
    memset(state.ptr2, '\1', state.MAX_LEN);

    // Choose a random amount of data to copy.
    size_t copy_len = random() % state.MAX_LEN;

    // Set the second half of ptr to the expected pattern in ptr2.
    memset(state.ptr + state.MAX_LEN, '\1', state.MAX_LEN);
    memcpy(state.ptr + state.MAX_LEN, state.ptr1, copy_len);
    if (copy_len > ptr1_len) {
      memset(state.ptr + state.MAX_LEN + ptr1_len, '\0', copy_len - ptr1_len);
    }

    ASSERT_EQ(state.ptr2, strncpy(state.ptr2, state.ptr1, copy_len));

    // Verify ptr1 was not modified.
    ASSERT_EQ(0, memcmp(state.ptr1, state.ptr, state.MAX_LEN));
    // Verify ptr2 contains the expected data.
    ASSERT_EQ(0, memcmp(state.ptr2, state.ptr + state.MAX_LEN, state.MAX_LEN));
  }
}

TEST(STRING_TEST, strrchr) {
  int seek_char = 'M';
  StringTestState<char> state(SMALL);
  for (size_t i = 1; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      if (~seek_char > 0) {
        memset(state.ptr1, ~seek_char, state.len[i]);
      } else {
        memset(state.ptr1, '\1', state.len[i]);
      }
      state.ptr1[state.len[i] - 1] = '\0';

      size_t pos = random() % state.MAX_LEN;
      char* expected;
      if (pos >= state.len[i] - 1) {
        if (seek_char == 0) {
          expected = state.ptr1 + state.len[i] - 1;
        } else {
          expected = nullptr;
        }
      } else {
        state.ptr1[pos] = seek_char;
        expected = state.ptr1 + pos;
      }

      ASSERT_TRUE(strrchr(state.ptr1, seek_char) == expected);
    }
  }
}

TEST(STRING_TEST, memchr) {
  int seek_char = 'N';
  StringTestState<char> state(SMALL);
  for (size_t i = 0; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr1, ~seek_char, state.len[i]);

      size_t pos = random() % state.MAX_LEN;
      char* expected;
      if (pos >= state.len[i]) {
        expected = nullptr;
      } else {
        state.ptr1[pos] = seek_char;
        expected = state.ptr1 + pos;
      }

      ASSERT_TRUE(memchr(state.ptr1, seek_char, state.len[i]) == expected);
    }
  }
}

TEST(STRING_TEST, memchr_zero) {
  uint8_t* buffer;
  ASSERT_EQ(0, posix_memalign(reinterpret_cast<void**>(&buffer), 64, 64));
  memset(buffer, 10, 64);
  ASSERT_TRUE(nullptr == memchr(buffer, 5, 0));
  ASSERT_TRUE(nullptr == memchr(buffer, 10, 0));
}

TEST(STRING_TEST, memrchr) {
  int seek_char = 'P';
  StringTestState<char> state(SMALL);
  for (size_t i = 0; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr1, ~seek_char, state.len[i]);

      size_t pos = random() % state.MAX_LEN;
      char* expected;
      if (pos >= state.len[i]) {
        expected = nullptr;
      } else {
        state.ptr1[pos] = seek_char;
        expected = state.ptr1 + pos;
      }

      ASSERT_TRUE(memrchr(state.ptr1, seek_char, state.len[i]) == expected);
    }
  }
}

TEST(STRING_TEST, memcmp) {
  StringTestState<char> state(SMALL);
  for (size_t i = 0; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      int c1 = 'A';
      int c2 = 'N';
      memset(state.ptr1, c1, state.MAX_LEN);
      memset(state.ptr2, c1, state.MAX_LEN);

      int pos = (state.len[i] == 0) ? 0 : (random() % state.len[i]);
      state.ptr2[pos] = c2;

      int expected = (static_cast<int>(c1) - static_cast<int>(c2));
      int actual = memcmp(state.ptr1, state.ptr2, state.MAX_LEN);

      ASSERT_EQ(signum(expected), signum(actual));
    }
  }
}

TEST(STRING_TEST, wmemcmp) {
  StringTestState<wchar_t> state(SMALL);

  for (size_t i = 0; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      long long mask = ((long long) 1 << 8 * sizeof(wchar_t)) - 1;
      int c1 = rand() & mask;
      int c2 = rand() & mask;
      wmemset(state.ptr1, c1, state.MAX_LEN);
      wmemset(state.ptr2, c1, state.MAX_LEN);

      int pos = (state.len[i] == 0) ? 0 : (random() % state.len[i]);
      state.ptr2[pos] = c2;

      int expected = (static_cast<int>(c1) - static_cast<int>(c2));
      int actual = wmemcmp(state.ptr1, state.ptr2, (size_t) state.MAX_LEN);

      ASSERT_EQ(signum(expected), signum(actual));
    }
  }
}

TEST(STRING_TEST, memcpy) {
  StringTestState<char> state(LARGE);
  int rand = 4;
  for (size_t i = 0; i < state.n - 1; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      size_t pos = random() % (state.MAX_LEN - state.len[i]);

      memset(state.ptr1, rand, state.len[i]);
      memset(state.ptr1 + state.len[i], ~rand, state.MAX_LEN - state.len[i]);

      memset(state.ptr2, rand, state.len[i]);
      memset(state.ptr2 + state.len[i], ~rand, state.MAX_LEN - state.len[i]);
      memset(state.ptr2 + pos, '\0', state.len[i]);

      ASSERT_FALSE(memcpy(state.ptr2 + pos, state.ptr1 + pos, state.len[i]) != state.ptr2 + pos);
      ASSERT_EQ(0, memcmp(state.ptr1, state.ptr2, state.MAX_LEN));
    }
  }
}

TEST(STRING_TEST, memset) {
  StringTestState<char> state(LARGE);
  char ch = 'P';
  for (size_t i = 0; i < state.n - 1; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr1, ~ch, state.MAX_LEN);
      memcpy(state.ptr2, state.ptr1, state.MAX_LEN);

      size_t pos = random () % (state.MAX_LEN - state.len[i]);
      for (size_t k = pos; k < pos + state.len[i]; k++) {
        state.ptr1[k] = ch;
      }

      ASSERT_TRUE(memset(state.ptr2 + pos, ch, state.len[i]) == state.ptr2 + pos);

      ASSERT_EQ(0, memcmp(state.ptr1, state.ptr2, state.MAX_LEN));
    }
  }
}

TEST(STRING_TEST, memmove) {
  StringTestState<char> state(LARGE);
  for (size_t i = 0; i < state.n - 1; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr1, 'Q', 2 * state.MAX_LEN);

      size_t pos = random() % (state.MAX_LEN - state.len[i]);

      memset(state.ptr1, 'R', state.len[i]);
      memcpy(state.ptr2, state.ptr1, 2 * state.MAX_LEN);
      memcpy(state.ptr, state.ptr1, state.len[i]);
      memcpy(state.ptr1 + pos, state.ptr, state.len[i]);

      ASSERT_TRUE(memmove(state.ptr2 + pos, state.ptr2, state.len[i]) == state.ptr2 + pos);
      ASSERT_EQ(0, memcmp(state.ptr2, state.ptr1, 2 * state.MAX_LEN));
    }
  }
}

TEST(STRING_TEST, memmove_cache_size) {
  size_t len = 600000;
  int max_alignment = 31;
  int alignments[] = {0, 5, 11, 29, 30};
  char* ptr = reinterpret_cast<char*>(malloc(sizeof(char) * len));
  char* ptr1 = reinterpret_cast<char*>(malloc(2 * sizeof(char) * len));
  char* glob_ptr2 = reinterpret_cast<char*>(malloc(2 * sizeof(char) * len + max_alignment));
  size_t pos = 64;

  ASSERT_TRUE(ptr != nullptr);
  ASSERT_TRUE(ptr1 != nullptr);
  ASSERT_TRUE(glob_ptr2 != nullptr);

  for (int i = 0; i < 5; i++) {
    char* ptr2 = glob_ptr2 + alignments[i];
    memset(ptr1, 'S', 2 * len);
    memset(ptr1, 'T', len);
    memcpy(ptr2, ptr1, 2 * len);
    memcpy(ptr, ptr1, len);
    memcpy(ptr1 + pos, ptr, len);

    ASSERT_TRUE(memmove(ptr2 + pos, ptr, len) == ptr2 + pos);
    ASSERT_EQ(0, memcmp(ptr2, ptr1, 2 * len));
  }
  free(ptr);
  free(ptr1);
  free(glob_ptr2);
}

static void verify_memmove(char* src_copy, char* dst, char* src, size_t size) {
  memset(dst, 0, size);
  memcpy(src, src_copy, size);
  ASSERT_EQ(dst, memmove(dst, src, size));
  ASSERT_EQ(0, memcmp(dst, src_copy, size));
}

#define MEMMOVE_DATA_SIZE (1024*1024*3)

TEST(STRING_TEST, memmove_check) {
  char* buffer = reinterpret_cast<char*>(malloc(MEMMOVE_DATA_SIZE));
  ASSERT_TRUE(buffer != nullptr);

  char* src_data = reinterpret_cast<char*>(malloc(MEMMOVE_DATA_SIZE));
  ASSERT_TRUE(src_data != nullptr);
  // Initialize to a known pattern to copy into src for each test and
  // to compare dst against.
  for (size_t i = 0; i < MEMMOVE_DATA_SIZE; i++) {
    src_data[i] = (i + 1) % 255;
  }

  // Check all different dst offsets between 0 and 127 inclusive.
  char* src = buffer;
  for (size_t i = 0; i < 127; i++) {
    char* dst = buffer + 256 + i;
    // Small copy.
    verify_memmove(src_data, dst, src, 1024);

    // Medium copy.
    verify_memmove(src_data, dst, src, 64 * 1024);

    // Medium copy.
    verify_memmove(src_data, dst, src, 1024 * 1024 + 128 * 1024);
  }

  // Check all leftover size offsets between 1 and 127 inclusive.
  char* dst = buffer + 256;
  src = buffer;
  for (size_t size = 1; size < 127; size++) {
    // Small copy.
    verify_memmove(src_data, dst, src, 1024);

    // Medium copy.
    verify_memmove(src_data, dst, src, 64 * 1024);

    // Large copy.
    verify_memmove(src_data, dst, src, 1024 * 1024 + 128 * 1024);
  }
}

TEST(STRING_TEST, bcopy) {
  StringTestState<char> state(LARGE);
  for (size_t i = 0; i < state.n; i++) {
    for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
      memset(state.ptr1, '4', state.MAX_LEN);
      memset(state.ptr1 + state.MAX_LEN, 'a', state.MAX_LEN);
      memcpy(state.ptr2, state.ptr1, 2 * state.MAX_LEN);

      size_t start = random() % (2 * state.MAX_LEN - state.len[i]);
      memcpy(state.ptr2 + start, state.ptr1, state.len[i]);

      bcopy(state.ptr1, state.ptr1 + start, state.len[i]);
      ASSERT_EQ(0, memcmp(state.ptr1, state.ptr2, 2 * state.MAX_LEN));
    }
  }
}

TEST(STRING_TEST, bzero) {
  StringTestState<char> state(LARGE);
  for (state.BeginIterations(); state.HasNextIteration(); state.NextIteration()) {
    memset(state.ptr1, 'R', state.MAX_LEN);

    size_t start = random() % state.MAX_LEN;
    size_t end = start + random() % (state.MAX_LEN - start);

    memcpy(state.ptr2, state.ptr1, start);
    memset(state.ptr2 + start, '\0', end - start);
    memcpy(state.ptr2 + end, state.ptr1 + end, state.MAX_LEN - end);

    bzero(state.ptr1 + start, end - start);

    ASSERT_EQ(0, memcmp(state.ptr1, state.ptr2, state.MAX_LEN));
  }
}

static void DoMemcpyTest(uint8_t* src, uint8_t* dst, size_t len) {
  memset(src, (len % 255) + 1, len);
  memset(dst, 0, len);

  ASSERT_EQ(dst, memcpy(dst, src, len));
  ASSERT_TRUE(memcmp(src, dst, len) == 0);
}

TEST(STRING_TEST, memcpy_align) {
  RunSrcDstBufferAlignTest(LARGE, DoMemcpyTest);
}

TEST(STRING_TEST, memcpy_overread) {
  RunSrcDstBufferOverreadTest(DoMemcpyTest);
}

static void DoMemmoveTest(uint8_t* src, uint8_t* dst, size_t len) {
  memset(src, (len % 255) + 1, len);
  memset(dst, 0, len);

  ASSERT_EQ(dst, memmove(dst, src, len));
  ASSERT_TRUE(memcmp(src, dst, len) == 0);
}

TEST(STRING_TEST, memmove_align) {
  RunSrcDstBufferAlignTest(L
```