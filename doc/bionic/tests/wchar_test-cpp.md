Response:
My goal is to provide a comprehensive summary of the given C++ code snippet, focusing on its functionalities, relationships with Android, explanations of libc functions, dynamic linker aspects, potential errors, and debugging information. Since this is part 1 of a 2-part request, I need to specifically focus on summarizing the functionalities present in this part.

Here's my thinking process:

1. **Identify the core purpose of the file:** The file name `wchar_test.cpp` and the inclusion of `<wchar.h>` strongly suggest that this file contains test cases for wide character functions in the bionic C library. The initial comments confirm this.

2. **Break down the code by test case:** The code is structured as a series of `TEST` macros, each testing a specific aspect of wide character handling. I'll go through each test case and identify the functions being tested and the core functionality being verified.

3. **List the tested functions and their immediate purpose:**  As I go through the test cases, I'll make a list of the wide character functions being tested. For each function, I'll note its basic purpose as demonstrated by the test. For instance, `mbrlen` tests the length of a multibyte sequence.

4. **Look for Android-specific considerations:**  The code includes conditional compilation based on `__ANDROID__` and mentions "Bionic's unicode implementation." This points to Android-specific behavior regarding UTF-8 handling (specifically, rejecting overlong UTF-8 sequences). I need to highlight this. The use of `uselocale(LC_GLOBAL_LOCALE)` also suggests testing in a specific locale context relevant to Android.

5. **Identify potential interactions with the dynamic linker:** While this part of the code doesn't directly *call* dynamic linker functions, the inclusion of standard C library headers implies that these functions will be resolved and linked at runtime. The `have_dl()` check in the last test case hints at dynamic loading functionality, although it's not the primary focus here. I'll keep this in mind for the broader context but not delve deeply into dynamic linking for *this* part.

6. **Note potential usage errors:** The test cases themselves often demonstrate correct usage. However, some tests, like those for `wcstombs` and `wcsrtombs`, explicitly check error conditions (e.g., invalid characters, insufficient buffer size). I should mention these as potential sources of programming errors.

7. **Ignore detailed implementation explanations (for now):** The prompt asks for detailed explanations of libc function implementations, but this is a *test* file. The focus is on *verifying* the behavior, not explaining the underlying implementation. I'll defer detailed implementation discussions to the hypothetical second part of the request if it provides the source code for the libc functions themselves.

8. **Ignore Android framework/NDK and Frida hooking for this part:** The prompt requests information on how the code is reached from the Android framework/NDK and how to debug with Frida. However, this is a unit test. While these tests *are* part of the Android build process, this specific file isn't directly called by framework components or typical NDK usage. I'll mention that these tests contribute to the overall quality of the Android C library but won't elaborate on the framework/NDK path or Frida in *this* summary.

9. **Focus on summarizing the *functions* tested:** The core task for part 1 is summarizing the functionality. Therefore, I'll create a bulleted list or similar structure outlining the wide character functions covered in the test file and the specific aspects of their behavior being verified (e.g., handling of null pointers, different UTF-8 encodings, error conditions, boundary cases).

10. **Review and refine:** After drafting the summary, I'll review it to ensure accuracy, clarity, and completeness within the constraints of part 1. I'll make sure to use clear and concise language.

By following these steps, I can generate a focused and accurate summary of the `wchar_test.cpp` file's functionalities, as requested for the first part of the prompt.
## bionic/tests/wchar_test.cpp 功能归纳 (第 1 部分)

该文件 `wchar_test.cpp` 是 Android Bionic 库的一部分，专门用于测试 Bionic 库中关于 **宽字符 (wchar_t)** 处理相关函数的正确性和健壮性。  简单来说，它的主要功能是：

**测试 Bionic 库中 `<wchar.h>` 头文件中声明的各种宽字符处理函数。**

更具体地，通过一系列的单元测试，该文件验证了以下方面：

* **基本类型大小:** 验证 `wchar_t` 和 `wint_t` 的大小是否符合预期 (4 字节)。
* **多字节字符与宽字符之间的转换:**
    * 测试 `mbrlen` 函数，用于获取多字节字符的长度。
    * 测试 `wctomb` 和 `wcrtomb` 函数，用于将宽字符转换为多字节字符。重点测试了 UTF-8 编码下不同字节数的宽字符转换，包括 1-byte, 2-byte, 3-byte 和 4-byte 的 UTF-8 序列。同时也测试了无效的宽字符转换。
    * 测试 `wcstombs` 和 `wcsrtombs` 函数，用于将宽字符串转换为多字节字符串。测试了在不同缓冲区大小下的转换行为，以及处理不可表示字符的情况。
    * 测试 `mbtowc` 和 `mbrtowc` 函数，用于将多字节字符转换为宽字符。重点测试了 UTF-8 编码下不同字节数的转换，包括完整和不完整的序列，以及处理非法序列的情况。
    * 测试 `mbsrtowcs` 函数，用于将多字节字符串转换为宽字符串。测试了转换过程中的错误处理，以及在目标缓冲区为空时的行为。
    * 测试 `mbsnrtowcs` 函数，类似于 `mbsrtowcs`，但可以限制转换的最大字节数。
* **字符串操作:**
    * 测试 `wcsstr` 函数，用于在一个宽字符串中查找另一个宽字符串的子串。
    * 测试 `wcscpy`, `wcsncpy`, `wcpcpy`, `wcpncpy`, `wmemmove`, `wmemcpy` 等宽字符串复制和移动函数。
* **数值转换:**
    * 测试 `wcstol`, `wcstoul`, `wcstoll`, `wcstoull`, `wcstoimax`, `wcstoumax` 等函数，用于将宽字符串转换为不同类型的整数。
    * 测试 `wcstof`, `wcstod`, `wcstold` 等函数，用于将宽字符串转换为浮点数。同时测试了对 "inf" 和 "nan" 等特殊值的解析。
    * 测试带有 locale 参数的数值转换函数，如 `wcstol_l`, `wcstoll_l`, `wcstoul_l`, `wcstoull_l`, `wcstof_l`, `wcstod_l`, `wcstold_l`。
* **时间和日期格式化:**
    * 测试 `wcsftime` 和 `wcsftime_l` 函数，用于将时间结构格式化为宽字符串。
* **其他功能:**
    * 测试 `wcwidth` 函数，用于获取宽字符的显示宽度。
    * 测试 `open_wmemstream` 函数，用于创建一个可以写入宽字符的内存流。

**与 Android 功能的关系举例说明：**

Android 系统内部广泛使用 UTF-8 编码来处理文本。Bionic 库提供的宽字符处理函数，允许 Android 系统在内部使用宽字符进行处理，并在需要时与外部的 UTF-8 数据进行转换。

* **例如，在 Java 层，字符串通常以 UTF-16 编码存储。当需要与 Native 层进行交互时，Java 字符串可能需要转换为 UTF-8 格式的 `char*`。Bionic 的 `wcstombs` 或 `wcsrtombs` 函数就可能被用于实现这种转换。**
* **反之，当 Native 代码接收到 UTF-8 编码的字符串，并需要进行更复杂的字符处理（例如，确定字符宽度以进行排版）时，可以使用 Bionic 的 `mbrtowc` 或 `mbsrtowcs` 函数将其转换为宽字符表示。**
* **Android 的 NDK 允许开发者使用 C/C++ 开发 Native 代码。这些 Native 代码可以直接调用 Bionic 提供的宽字符处理函数，从而方便地处理各种语言的文本数据。**

**需要注意的是，这只是第 1 部分的分析。  在第 2 部分中，可能会包含更多关于特定 libc 函数实现细节、动态链接、错误使用场景、以及 Android 框架/NDK 如何调用到这些函数的说明。**

Prompt: 
```
这是目录为bionic/tests/wchar_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <wchar.h>

#include "utils.h"

#define NUM_WCHARS(num_bytes) ((num_bytes)/sizeof(wchar_t))

#ifdef __GLIBC__
// glibc immediately dereferences the locale passed to all wcsto*_l functions,
// even if it won't be used, and even if it's LC_GLOBAL_LOCALE, which isn't a
// pointer to valid memory.
static locale_t SAFE_LC_GLOBAL_LOCALE = duplocale(LC_GLOBAL_LOCALE);
#else
static locale_t SAFE_LC_GLOBAL_LOCALE = LC_GLOBAL_LOCALE;
#endif

// Modern versions of UTF-8 (https://datatracker.ietf.org/doc/html/rfc3629 and
// newer) explicitly disallow code points beyond U+10FFFF, which exclude all 5-
// and 6-byte sequences. Earlier versions of UTF-8 allowed the wider range:
// https://datatracker.ietf.org/doc/html/rfc2279.
//
// Bionic's unicode implementation was written after the high values were
// excluded, so it has never supported them. Other implementations (at least
// as of glibc 2.36), do support those sequences.
#if defined(__ANDROID__) || defined(ANDROID_HOST_MUSL)
constexpr bool kLibcRejectsOverLongUtf8Sequences = true;
#elif defined(__GLIBC__)
constexpr bool kLibcRejectsOverLongUtf8Sequences = false;
#else
#error kLibcRejectsOverLongUtf8Sequences must be configured for this platform
#endif

#if defined(__GLIBC__)
constexpr bool kLibcSupportsParsingBinaryLiterals = __GLIBC_PREREQ(2, 38);
#else
constexpr bool kLibcSupportsParsingBinaryLiterals = true;
#endif

TEST(wchar, sizeof_wchar_t) {
  EXPECT_EQ(4U, sizeof(wchar_t));
  EXPECT_EQ(4U, sizeof(wint_t));
}

TEST(wchar, mbrlen) {
  char bytes[] = { 'h', 'e', 'l', 'l', 'o', '\0' };
  EXPECT_EQ(static_cast<size_t>(-2), mbrlen(&bytes[0], 0, nullptr));
  EXPECT_EQ(1U, mbrlen(&bytes[0], 1, nullptr));

  EXPECT_EQ(1U, mbrlen(&bytes[4], 1, nullptr));
  EXPECT_EQ(0U, mbrlen(&bytes[5], 1, nullptr));
}

TEST(wchar, wctomb_wcrtomb) {
  // wctomb and wcrtomb behave differently when s == NULL.
  EXPECT_EQ(0, wctomb(nullptr, L'h'));
  EXPECT_EQ(0, wctomb(nullptr, L'\0'));
  EXPECT_EQ(1U, wcrtomb(nullptr, L'\0', nullptr));
  EXPECT_EQ(1U, wcrtomb(nullptr, L'h', nullptr));

  char bytes[MB_LEN_MAX];

  // wctomb and wcrtomb behave similarly for the null wide character.
  EXPECT_EQ(1, wctomb(bytes, L'\0'));
  EXPECT_EQ(1U, wcrtomb(bytes, L'\0', nullptr));

  // ...and for regular characters.
  memset(bytes, 0, sizeof(bytes));
  EXPECT_EQ(1, wctomb(bytes, L'h'));
  EXPECT_EQ('h', bytes[0]);
  memset(bytes, 0, sizeof(bytes));
  EXPECT_EQ(1U, wcrtomb(bytes, L'h', nullptr));
  EXPECT_EQ('h', bytes[0]);

  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  // 1-byte UTF-8.
  memset(bytes, 0, sizeof(bytes));
  EXPECT_EQ(1U, wcrtomb(bytes, L'h', nullptr));
  EXPECT_EQ('h', bytes[0]);
  // 2-byte UTF-8.
  memset(bytes, 0, sizeof(bytes));
  EXPECT_EQ(2U, wcrtomb(bytes, 0x00a2, nullptr));
  EXPECT_EQ('\xc2', bytes[0]);
  EXPECT_EQ('\xa2', bytes[1]);
  // 3-byte UTF-8.
  memset(bytes, 0, sizeof(bytes));
  EXPECT_EQ(3U, wcrtomb(bytes, 0x20ac, nullptr));
  EXPECT_EQ('\xe2', bytes[0]);
  EXPECT_EQ('\x82', bytes[1]);
  EXPECT_EQ('\xac', bytes[2]);
  // 4-byte UTF-8.
  memset(bytes, 0, sizeof(bytes));
  EXPECT_EQ(4U, wcrtomb(bytes, 0x24b62, nullptr));
  EXPECT_EQ('\xf0', bytes[0]);
  EXPECT_EQ('\xa4', bytes[1]);
  EXPECT_EQ('\xad', bytes[2]);
  EXPECT_EQ('\xa2', bytes[3]);
  // Invalid code point.
  EXPECT_EQ(static_cast<size_t>(-1), wcrtomb(bytes, 0xffffffff, nullptr));
  EXPECT_ERRNO(EILSEQ);
}

TEST(wchar, wcrtomb_start_state) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  char out[MB_LEN_MAX];
  mbstate_t ps = {};

  // Any non-initial state is invalid when calling wcrtomb.
  EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "\xc2", 1, &ps));
  EXPECT_EQ(static_cast<size_t>(-1), wcrtomb(out, 0x00a2, &ps));
  EXPECT_ERRNO(EILSEQ);

  // If the first argument to wcrtomb is NULL or the second is L'\0' the shift
  // state should be reset.
  ps = {};
  EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "\xc2", 1, &ps));
  EXPECT_EQ(1U, wcrtomb(nullptr, 0x00a2, &ps));
  EXPECT_TRUE(mbsinit(&ps));

  ps = {};
  EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "\xf0\xa4", 1, &ps));
  EXPECT_EQ(1U, wcrtomb(out, L'\0', &ps));
  EXPECT_TRUE(mbsinit(&ps));
}

TEST(wchar, wcstombs_wcrtombs) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  const wchar_t chars[] = { L'h', L'e', L'l', L'l', L'o', 0 };
  const wchar_t bad_chars[] = { L'h', L'i', static_cast<wchar_t>(0xffffffff), 0 };
  const wchar_t* src;
  char bytes[BUFSIZ];

  // Given a NULL destination, these functions count valid characters.
  EXPECT_EQ(5U, wcstombs(nullptr, chars, 0));
  EXPECT_EQ(5U, wcstombs(nullptr, chars, 4));
  EXPECT_EQ(5U, wcstombs(nullptr, chars, 256));
  src = chars;
  EXPECT_EQ(5U, wcsrtombs(nullptr, &src, 0, nullptr));
  EXPECT_EQ(&chars[0], src);
  src = chars;
  EXPECT_EQ(5U, wcsrtombs(nullptr, &src, 4, nullptr));
  EXPECT_EQ(&chars[0], src);
  src = chars;
  EXPECT_EQ(5U, wcsrtombs(nullptr, &src, 256, nullptr));
  EXPECT_EQ(&chars[0], src);

  // An unrepresentable char just returns an error from wcstombs...
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), wcstombs(nullptr, bad_chars, 0));
  EXPECT_ERRNO(EILSEQ);
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), wcstombs(nullptr, bad_chars, 256));
  EXPECT_ERRNO(EILSEQ);

  // And wcsrtombs doesn't tell us where it got stuck because we didn't ask it
  // to actually convert anything...
  errno = 0;
  src = bad_chars;
  EXPECT_EQ(static_cast<size_t>(-1), wcsrtombs(nullptr, &src, 0, nullptr));
  EXPECT_EQ(&bad_chars[0], src);
  EXPECT_ERRNO(EILSEQ);
  errno = 0;
  src = bad_chars;
  EXPECT_EQ(static_cast<size_t>(-1), wcsrtombs(nullptr, &src, 256, nullptr));
  EXPECT_EQ(&bad_chars[0], src);
  EXPECT_ERRNO(EILSEQ);

  // Okay, now let's test actually converting something...
  memset(bytes, 'x', sizeof(bytes));
  EXPECT_EQ(0U, wcstombs(bytes, chars, 0));
  memset(bytes, 'x', sizeof(bytes));
  EXPECT_EQ(4U, wcstombs(bytes, chars, 4));
  bytes[5] = 0;
  EXPECT_STREQ("hellx", bytes);
  memset(bytes, 'x', sizeof(bytes));
  EXPECT_EQ(5U, wcstombs(bytes, chars, 256));
  EXPECT_STREQ("hello", bytes);
  memset(bytes, 'x', sizeof(bytes));
  EXPECT_EQ(5U, wcstombs(bytes, chars, 6));
  EXPECT_STREQ("hello", bytes);
  errno = 0;
  memset(bytes, 'x', sizeof(bytes));
  EXPECT_EQ(static_cast<size_t>(-1), wcstombs(bytes, bad_chars, 256));
  EXPECT_ERRNO(EILSEQ);
  bytes[3] = 0;
  EXPECT_STREQ("hix", bytes);

  // wcsrtombs is a bit more informative...
  memset(bytes, 'x', sizeof(bytes));
  src = chars;
  EXPECT_EQ(0U, wcsrtombs(bytes, &src, 0, nullptr));
  EXPECT_EQ(&chars[0], src); // No input consumed.
  EXPECT_ERRNO(EILSEQ);

  memset(bytes, 'x', sizeof(bytes));
  src = chars;
  EXPECT_EQ(4U, wcsrtombs(bytes, &src, 4, nullptr));
  EXPECT_EQ(&chars[4], src); // Some input consumed.
  EXPECT_ERRNO(EILSEQ);
  bytes[5] = 0;
  EXPECT_STREQ("hellx", bytes);

  memset(bytes, 'x', sizeof(bytes));
  src = chars;
  EXPECT_EQ(5U, wcsrtombs(bytes, &src, 256, nullptr));
  EXPECT_EQ(nullptr, src); // All input consumed!
  EXPECT_ERRNO(EILSEQ);
  EXPECT_STREQ("hello", bytes);

  memset(bytes, 'x', sizeof(bytes));
  src = chars;
  EXPECT_EQ(5U, wcsrtombs(bytes, &src, 6, nullptr));
  EXPECT_EQ(nullptr, src); // All input consumed.
  EXPECT_ERRNO(EILSEQ);
  EXPECT_STREQ("hello", bytes);

  memset(bytes, 'x', sizeof(bytes));
  src = bad_chars;
  EXPECT_EQ(static_cast<size_t>(-1), wcsrtombs(bytes, &src, 256, nullptr));
  EXPECT_EQ(&bad_chars[2], src);
  EXPECT_ERRNO(EILSEQ);
  bytes[3] = 0;
  EXPECT_STREQ("hix", bytes);

  // Any non-initial state is invalid when calling wcsrtombs.
  mbstate_t ps = {};
  src = chars;
  ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "\xc2", 1, &ps));
  EXPECT_EQ(static_cast<size_t>(-1), wcsrtombs(nullptr, &src, 0, &ps));
  EXPECT_ERRNO(EILSEQ);
}

TEST(wchar, limits) {
  ASSERT_LT(WCHAR_MIN, WCHAR_MAX);
}

TEST(wchar, wcsstr) {
  const wchar_t* haystack = L"big daddy/giant haystacks!";
  const wchar_t* empty_haystack = L"";

  // The empty needle is a special case.
  ASSERT_EQ(haystack, wcsstr(haystack, L""));
  ASSERT_EQ(empty_haystack, wcsstr(empty_haystack, L""));

  ASSERT_EQ(haystack, wcsstr(haystack, L"b"));
  ASSERT_EQ(haystack, wcsstr(haystack, L"big"));
  ASSERT_EQ(haystack + 9, wcsstr(haystack, L"/"));
  ASSERT_EQ(haystack + 9, wcsstr(haystack, L"/giant"));
  ASSERT_EQ(haystack + 25, wcsstr(haystack, L"!"));
  ASSERT_EQ(haystack + 19, wcsstr(haystack, L"stacks!"));

  ASSERT_EQ(nullptr, wcsstr(haystack, L"monkey"));
  ASSERT_EQ(nullptr, wcsstr(empty_haystack, L"monkey"));
}

TEST(wchar, wcsstr_80199) {
  // https://code.google.com/p/android/issues/detail?id=80199
  ASSERT_TRUE(wcsstr(L"romrom", L"rom") != nullptr);
}

TEST(wchar, mbtowc) {
  wchar_t out[8];

  // mbtowc and all the mbrto* APIs behave slightly differently when n is 0:
  //
  // mbrtowc returns 0 "if the next n or fewer bytes complete the multibyte
  // character that corresponds to the null wide character"
  //
  // mbrtoc (C23 7.24.7.2.4) says:
  //
  //     If s is not a null pointer, the mbtowc function either returns 0 (if s
  //     points to the null character), or returns the number of bytes that are
  //     contained in the converted multibyte character (if the next n or fewer
  //     bytes form a valid multibyte character), or returns -1 (if they do not
  //     form a valid multibyte character).
  //
  // glibc's interpretation differs from all the BSDs (including macOS) and
  // bionic (by way of openbsd). glibc returns 0 since s does point to the null
  // character, whereas the BSDs return -1 because the next 0 bytes do not form
  // a valid multibyte chatacter. glibc's interpretation is probably more
  // correct from a strict interpretation of the spec, but considering the other
  // APIs behave more like the BSD interpretation that may be a bug in the spec.
#ifdef __GLIBC__
  int expected_result_for_zero_length_empty_string = 0;
#else
  int expected_result_for_zero_length_empty_string = -1;
#endif

  out[0] = 'x';
  EXPECT_EQ(-1, mbtowc(out, "hello", 0));
  EXPECT_EQ('x', out[0]);

  EXPECT_EQ(-1, mbtowc(out, "hello", 0));
  EXPECT_EQ(expected_result_for_zero_length_empty_string, mbtowc(out, "", 0));
  EXPECT_EQ(1, mbtowc(out, "hello", 1));
  EXPECT_EQ(L'h', out[0]);

  EXPECT_EQ(-1, mbtowc(nullptr, "hello", 0));
  EXPECT_EQ(expected_result_for_zero_length_empty_string, mbtowc(nullptr, "", 0));
  EXPECT_EQ(1, mbtowc(nullptr, "hello", 1));

  EXPECT_EQ(0, mbtowc(nullptr, nullptr, 0));
}

TEST(wchar, mbrtowc) {
  wchar_t out[8];

  out[0] = 'x';
  EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(out, "hello", 0, nullptr));
  EXPECT_EQ('x', out[0]);

  EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(out, "hello", 0, nullptr));
  EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(out, "", 0, nullptr));
  EXPECT_EQ(1U, mbrtowc(out, "hello", 1, nullptr));
  EXPECT_EQ(L'h', out[0]);

  EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "hello", 0, nullptr));
  EXPECT_EQ(static_cast<size_t>(-2), mbrtowc(nullptr, "", 0, nullptr));
  EXPECT_EQ(1U, mbrtowc(nullptr, "hello", 1, nullptr));

  EXPECT_EQ(0U, mbrtowc(nullptr, nullptr, 0, nullptr));

  EXPECT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  // 1-byte UTF-8.
  EXPECT_EQ(1U, mbrtowc(out, "abcdef", 6, nullptr));
  EXPECT_EQ(L'a', out[0]);
  // 2-byte UTF-8.
  EXPECT_EQ(2U, mbrtowc(out,
                        "\xc2\xa2"
                        "cdef",
                        6, nullptr));
  EXPECT_EQ(static_cast<wchar_t>(0x00a2), out[0]);
  // 3-byte UTF-8.
  EXPECT_EQ(3U, mbrtowc(out,
                        "\xe2\x82\xac"
                        "def",
                        6, nullptr));
  EXPECT_EQ(static_cast<wchar_t>(0x20ac), out[0]);
  // 4-byte UTF-8.
  EXPECT_EQ(4U, mbrtowc(out,
                        "\xf0\xa4\xad\xa2"
                        "ef",
                        6, nullptr));
  EXPECT_EQ(static_cast<wchar_t>(0x24b62), out[0]);
#if defined(__BIONIC__) // glibc allows this.
  // Illegal 5-byte UTF-8.
  EXPECT_EQ(static_cast<size_t>(-1), mbrtowc(out,
                                             "\xf8\xa1\xa2\xa3\xa4"
                                             "f",
                                             6, nullptr));
  EXPECT_ERRNO(EILSEQ);
#endif
  // Illegal over-long sequence.
  EXPECT_EQ(static_cast<size_t>(-1), mbrtowc(out,
                                             "\xf0\x82\x82\xac"
                                             "ef",
                                             6, nullptr));
  EXPECT_ERRNO(EILSEQ);
}

TEST(wchar, mbrtowc_valid_non_characters) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  wchar_t out[8] = {};

  ASSERT_EQ(3U, mbrtowc(out, "\xef\xbf\xbe", 3, nullptr));
  ASSERT_EQ(static_cast<wchar_t>(0xfffe), out[0]);
  ASSERT_EQ(3U, mbrtowc(out, "\xef\xbf\xbf", 3, nullptr));
  ASSERT_EQ(static_cast<wchar_t>(0xffff), out[0]);
}

TEST(wchar, mbrtowc_out_of_range) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  wchar_t out[8] = {};
  errno = 0;
  auto result = mbrtowc(out, "\xf5\x80\x80\x80", 4, nullptr);
  if (kLibcRejectsOverLongUtf8Sequences) {
    ASSERT_EQ(static_cast<size_t>(-1), result);
    ASSERT_ERRNO(EILSEQ);
  } else {
    ASSERT_EQ(4U, result);
    ASSERT_ERRNO(0);
  }
}

static void test_mbrtowc_incomplete(mbstate_t* ps) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  wchar_t out;
  // 2-byte UTF-8.
  ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(&out, "\xc2", 1, ps));
  ASSERT_EQ(1U, mbrtowc(&out, "\xa2" "cdef", 5, ps));
  ASSERT_EQ(static_cast<wchar_t>(0x00a2), out);
  ASSERT_TRUE(mbsinit(ps));
  // 3-byte UTF-8.
  ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(&out, "\xe2", 1, ps));
  ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(&out, "\x82", 1, ps));
  ASSERT_EQ(1U, mbrtowc(&out, "\xac" "def", 4, ps));
  ASSERT_EQ(static_cast<wchar_t>(0x20ac), out);
  ASSERT_TRUE(mbsinit(ps));
  // 4-byte UTF-8.
  ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(&out, "\xf0", 1, ps));
  ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(&out, "\xa4\xad", 2, ps));
  ASSERT_EQ(1U, mbrtowc(&out, "\xa2" "ef", 3, ps));
  ASSERT_EQ(static_cast<wchar_t>(0x24b62), out);
  ASSERT_TRUE(mbsinit(ps));

  // Invalid 2-byte
  ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(&out, "\xc2", 1, ps));
  ASSERT_EQ(static_cast<size_t>(-1), mbrtowc(&out, "\x20" "cdef", 5, ps));
  ASSERT_ERRNO(EILSEQ);
}

TEST(wchar, mbrtowc_incomplete) {
  mbstate_t ps = {};

  test_mbrtowc_incomplete(&ps);
  test_mbrtowc_incomplete(nullptr);
}

static void test_mbsrtowcs(mbstate_t* ps) {
  constexpr const char* VALID = "A" "\xc2\xa2" "\xe2\x82\xac" "\xf0\xa4\xad\xa2" "ef";
  constexpr const char* INVALID = "A" "\xc2\x20" "ef";
  constexpr const char* INCOMPLETE = "A" "\xc2";
  wchar_t out[4];

  const char* valid = VALID;
  ASSERT_EQ(4U, mbsrtowcs(out, &valid, 4, ps));
  ASSERT_EQ(L'A', out[0]);
  ASSERT_EQ(static_cast<wchar_t>(0x00a2), out[1]);
  ASSERT_EQ(static_cast<wchar_t>(0x20ac), out[2]);
  ASSERT_EQ(static_cast<wchar_t>(0x24b62), out[3]);
  // Check that valid has advanced to the next unread character.
  ASSERT_EQ('e', *valid);

  wmemset(out, L'x', NUM_WCHARS(sizeof(out)));
  ASSERT_EQ(2U, mbsrtowcs(out, &valid, 4, ps));
  ASSERT_EQ(L'e', out[0]);
  ASSERT_EQ(L'f', out[1]);
  ASSERT_EQ(L'\0', out[2]);
  // Check that we didn't clobber the rest of out.
  ASSERT_EQ(L'x', out[3]);
  // Check that valid has advanced to the end of the string.
  ASSERT_EQ(nullptr, valid);

  const char* invalid = INVALID;
  ASSERT_EQ(static_cast<size_t>(-1), mbsrtowcs(out, &invalid, 4, ps));
  EXPECT_ERRNO(EILSEQ);
  ASSERT_EQ('\xc2', *invalid);

  const char* incomplete = INCOMPLETE;
  ASSERT_EQ(static_cast<size_t>(-1), mbsrtowcs(out, &incomplete, 2, ps));
  EXPECT_ERRNO(EILSEQ);
  ASSERT_EQ('\xc2', *incomplete);

  // If dst is null, *src shouldn't be updated.
  // https://code.google.com/p/android/issues/detail?id=166381
  const char* mbs = VALID;
  EXPECT_EQ(6U, mbsrtowcs(nullptr, &mbs, 0, ps));
  EXPECT_EQ(VALID, mbs);
  mbs = INVALID;
  EXPECT_EQ(static_cast<size_t>(-1), mbsrtowcs(nullptr, &mbs, 0, ps));
  EXPECT_EQ(INVALID, mbs);
  mbs = INCOMPLETE;
  EXPECT_EQ(static_cast<size_t>(-1), mbsrtowcs(nullptr, &mbs, 0, ps));
  EXPECT_EQ(INCOMPLETE, mbs);
}

TEST(wchar, mbsrtowcs) {
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  mbstate_t ps = {};
  test_mbsrtowcs(&ps);
  test_mbsrtowcs(nullptr);

  // Invalid multi byte continuation.
  const char* invalid = "\x20";
  wchar_t out;
  ASSERT_EQ(static_cast<size_t>(-2), mbrtowc(&out, "\xc2", 1, &ps));
  ASSERT_EQ(static_cast<size_t>(-1), mbsrtowcs(&out, &invalid, 1, &ps));
  EXPECT_ERRNO(EILSEQ);
  ASSERT_EQ('\x20', *invalid);
}

template <typename T>
using WcsToIntFn = T (*)(const wchar_t*, wchar_t**, int);

template <typename T>
void TestSingleWcsToInt(WcsToIntFn<T> fn, const wchar_t* str, int base,
                        T expected_value, ptrdiff_t expected_len) {
  wchar_t* p;
  EXPECT_EQ(expected_value, fn(str, &p, base)) << str << " " << base;
  EXPECT_EQ(expected_len, p - str) << str << " " << base;
}

template <typename T>
void TestWcsToInt(WcsToIntFn<T> fn) {
  TestSingleWcsToInt(fn, L"123", 10, static_cast<T>(123), 3);
  TestSingleWcsToInt(fn, L"123", 0, static_cast<T>(123), 3);
  TestSingleWcsToInt(fn, L"123#", 10, static_cast<T>(123), 3);
  TestSingleWcsToInt(fn, L"01000", 8, static_cast<T>(512), 5);
  TestSingleWcsToInt(fn, L"01000", 0, static_cast<T>(512), 5);
  TestSingleWcsToInt(fn, L"   123 45", 0, static_cast<T>(123), 6);
  TestSingleWcsToInt(fn, L"  -123", 0, static_cast<T>(-123), 6);
  TestSingleWcsToInt(fn, L"0x10000", 0, static_cast<T>(65536), 7);
  if (kLibcSupportsParsingBinaryLiterals) {
    TestSingleWcsToInt(fn, L"0b1011", 0, static_cast<T>(0b1011), 6);
  }
}

template <typename T>
void TestWcsToIntLimits(WcsToIntFn<T> fn, const wchar_t* min_str,
                        const wchar_t* max_str) {
  if (std::is_signed<T>::value) {
    ASSERT_EQ(std::numeric_limits<T>::min(), fn(min_str, nullptr, 0)) << min_str;
  } else {
    // If the subject sequence begins with a <hyphen-minus>, the value resulting
    // from the conversion shall be negated.
    // https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/strtoul.html
    ASSERT_EQ(std::numeric_limits<T>::max(), fn(min_str, nullptr, 0)) << min_str;
  }
  ASSERT_EQ(std::numeric_limits<T>::max(), fn(max_str, nullptr, 0)) << max_str;
}

TEST(wchar, wcstol) {
  TestWcsToInt(wcstol);
}

TEST(wchar, wcstol_limits) {
  if (sizeof(long) == 8) {
    TestWcsToIntLimits(wcstol, L"-9223372036854775809", L"9223372036854775808");
  } else {
    TestWcsToIntLimits(wcstol, L"-2147483649", L"2147483648");
  }
}

TEST(wchar, wcstoul) {
  TestWcsToInt(wcstoul);
}

TEST(wchar, wcstoul_limits) {
  if (sizeof(long) == 8) {
    TestWcsToIntLimits(wcstoul, L"-1", L"18446744073709551616");
  } else {
    TestWcsToIntLimits(wcstoul, L"-1", L"4294967296");
  }
}

TEST(wchar, wcstoll) {
  TestWcsToInt(wcstoll);
}

TEST(wchar, wcstoll_limits) {
  TestWcsToIntLimits(wcstoll, L"-9223372036854775809", L"9223372036854775808");
}

TEST(wchar, wcstoull) {
  TestWcsToInt(wcstoull);
}

TEST(wchar, wcstoull_limits) {
  TestWcsToIntLimits(wcstoull, L"-1", L"18446744073709551616");
}

TEST(wchar, wcstoimax) {
  TestWcsToInt(wcstoimax);
}

TEST(wchar, wcstoimax_limits) {
  TestWcsToIntLimits(wcstoimax, L"-9223372036854775809",
                     L"9223372036854775808");
}

TEST(wchar, wcstoumax) {
  TestWcsToInt(wcstoumax);
}

TEST(wchar, wcstoumax_limits) {
  TestWcsToIntLimits(wcstoumax, L"-1", L"18446744073709551616");
}

TEST(wchar, mbsnrtowcs) {
  wchar_t dst[128];
  const char* s = "hello, world!";
  const char* src;

  memset(dst, 0, sizeof(dst));
  src = s;
  ASSERT_EQ(0U, mbsnrtowcs(dst, &src, 0, 0, nullptr));

  memset(dst, 0, sizeof(dst));
  src = s;
  ASSERT_EQ(2U, mbsnrtowcs(dst, &src, 2, 123, nullptr)); // glibc chokes on SIZE_MAX here.
  ASSERT_EQ(L'h', dst[0]);
  ASSERT_EQ(L'e', dst[1]);
  ASSERT_EQ(&s[2], src);

  memset(dst, 0, sizeof(dst));
  src = s;
  ASSERT_EQ(3U, mbsnrtowcs(dst, &src, SIZE_MAX, 3, nullptr));
  ASSERT_EQ(L'h', dst[0]);
  ASSERT_EQ(L'e', dst[1]);
  ASSERT_EQ(L'l', dst[2]);
  ASSERT_EQ(&s[3], src);

  memset(dst, 0, sizeof(dst));
  const char* incomplete = "\xc2"; // Incomplete UTF-8 sequence.
  src = incomplete;
  errno = 0;
  ASSERT_EQ(static_cast<size_t>(-1), mbsnrtowcs(dst, &src, SIZE_MAX, 3, nullptr));
  ASSERT_ERRNO(EILSEQ);

  src = incomplete;
  errno = 0;
  ASSERT_EQ(static_cast<size_t>(-1), mbsnrtowcs(nullptr, &src, SIZE_MAX, 3, nullptr));
  ASSERT_ERRNO(EILSEQ);
}

TEST(wchar, wcsftime__wcsftime_l) {
  setenv("TZ", "UTC", 1);

  struct tm t = {.tm_year = 200, .tm_mon = 2, .tm_mday = 10};
  wchar_t buf[64];

  EXPECT_EQ(24U, wcsftime(buf, sizeof(buf), L"%c", &t));
  EXPECT_STREQ(L"Sun Mar 10 00:00:00 2100", buf);
  EXPECT_EQ(24U, wcsftime_l(buf, sizeof(buf), L"%c", &t, SAFE_LC_GLOBAL_LOCALE));
  EXPECT_STREQ(L"Sun Mar 10 00:00:00 2100", buf);
}

TEST(wchar, wmemmove_smoke) {
  const wchar_t const_wstr[] = L"This is a test of something or other.....";
  wchar_t wstr[NUM_WCHARS(sizeof(const_wstr))];

  EXPECT_EQ(wstr, wmemmove(wstr, const_wstr, NUM_WCHARS(sizeof(const_wstr))));
  EXPECT_STREQ(const_wstr, wstr);

  EXPECT_EQ(wstr+5, wmemmove(wstr+5, wstr, NUM_WCHARS(sizeof(const_wstr)) - 6));
  EXPECT_STREQ(L"This This is a test of something or other", wstr);
}

TEST(wchar, wmemcpy_smoke) {
  const wchar_t src[] = L"Source string";
  wchar_t dst[NUM_WCHARS(sizeof(src))];

  EXPECT_EQ(dst, wmemcpy(dst, src, NUM_WCHARS(sizeof(src))));
  EXPECT_STREQ(dst, src);
}

TEST(wchar, wcpcpy_smoke) {
  const wchar_t src[] = L"Source string";
  wchar_t dst[NUM_WCHARS(sizeof(src))];

  EXPECT_EQ(dst + NUM_WCHARS(sizeof(src)) - 1, wcpcpy(dst, src));
  EXPECT_STREQ(dst, src);
}

TEST(wchar, wcpncpy_smoke) {
  const wchar_t src[] = L"Source string";
  wchar_t dst[NUM_WCHARS(sizeof(src)) + 5];

  size_t src_len = NUM_WCHARS(sizeof(src)) - 1;
  EXPECT_EQ(dst + src_len, wcpncpy(dst, src, src_len + 1));
  EXPECT_STREQ(dst, src);

  EXPECT_EQ(dst + 6, wcpncpy(dst, src, 6));
  dst[6] = L'\0';
  EXPECT_STREQ(dst, L"Source");

  wmemset(dst, L'x', NUM_WCHARS(sizeof(dst)));
  EXPECT_EQ(dst + src_len, wcpncpy(dst, src, src_len + 4));
  EXPECT_STREQ(dst, src);
  EXPECT_EQ(dst[src_len], L'\0');
  EXPECT_EQ(dst[src_len+1], L'\0');
  EXPECT_EQ(dst[src_len+2], L'\0');
  EXPECT_EQ(dst[src_len+3], L'\0');
  EXPECT_EQ(dst[src_len+4], L'x');
}

TEST(wchar, wcscpy_smoke) {
  const wchar_t src[] = L"Source string";
  wchar_t dst[NUM_WCHARS(sizeof(src))];

  EXPECT_EQ(dst, wcscpy(dst, src));
  EXPECT_STREQ(src, dst);
}

TEST(wchar, wcsncpy_smoke) {
  const wchar_t src[] = L"Source string";
  wchar_t dst[NUM_WCHARS(sizeof(src)) + 5];

  size_t src_len = NUM_WCHARS(sizeof(src)) - 1;
  EXPECT_EQ(dst, wcsncpy(dst, src, src_len + 1));
  EXPECT_STREQ(dst, src);

  EXPECT_EQ(dst, wcsncpy(dst, src, 6));
  dst[6] = L'\0';
  EXPECT_STREQ(dst, L"Source");
  EXPECT_EQ(dst, wcsncpy(dst, L"clobber", 0));
  EXPECT_STREQ(dst, L"Source");

  wmemset(dst, L'x', NUM_WCHARS(sizeof(dst)));
  EXPECT_EQ(dst, wcsncpy(dst, src, src_len + 4));
  EXPECT_STREQ(dst, src);
  EXPECT_EQ(dst[src_len], L'\0');
  EXPECT_EQ(dst[src_len+1], L'\0');
  EXPECT_EQ(dst[src_len+2], L'\0');
  EXPECT_EQ(dst[src_len+3], L'\0');
  EXPECT_EQ(dst[src_len+4], L'x');
}

TEST(wchar, mbrtowc_15439554) {
  // http://b/15439554
  ASSERT_STREQ("C.UTF-8", setlocale(LC_CTYPE, "C.UTF-8"));
  uselocale(LC_GLOBAL_LOCALE);

  ASSERT_GE(static_cast<size_t>(MB_LEN_MAX), MB_CUR_MAX);
  ASSERT_GE(MB_CUR_MAX, 4U);

  wchar_t wc;
  size_t n;

  // 1-byte character.
  n = mbrtowc(&wc, "x", MB_CUR_MAX, nullptr);
  EXPECT_EQ(1U, n);
  EXPECT_EQ(L'x', wc);
  // 2-byte character.
  n = mbrtowc(&wc, "\xc2\xa2", MB_CUR_MAX, nullptr);
  EXPECT_EQ(2U, n);
  EXPECT_EQ(L'¢', wc);
  // 3-byte character.
  n = mbrtowc(&wc, "\xe2\x82\xac", MB_CUR_MAX, nullptr);
  EXPECT_EQ(3U, n);
  EXPECT_EQ(L'€', wc);
  // 4-byte character.
  n = mbrtowc(&wc, "\xf0\xa4\xad\xa2", MB_CUR_MAX, nullptr);
  EXPECT_EQ(4U, n);
  EXPECT_EQ(L'𤭢', wc);
}

TEST(wchar, open_wmemstream) {
  wchar_t* p = nullptr;
  size_t size = 0;
  FILE* fp = open_wmemstream(&p, &size);
  ASSERT_NE(EOF, fputws(L"hello, world!", fp));
  fclose(fp);

  ASSERT_STREQ(L"hello, world!", p);
  ASSERT_EQ(wcslen(L"hello, world!"), size);
  free(p);
}

TEST(stdio, open_wmemstream_EINVAL) {
#if defined(__BIONIC__)
  wchar_t* p;
  size_t size;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnonnull"
  // Invalid buffer.
  errno = 0;
  ASSERT_EQ(nullptr, open_wmemstream(nullptr, &size));
  ASSERT_ERRNO(EINVAL);

  // Invalid size.
  errno = 0;
  ASSERT_EQ(nullptr, open_wmemstream(&p, nullptr));
  ASSERT_ERRNO(EINVAL);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "This test is bionic-specific";
#endif
}

TEST(wchar, wcstol_EINVAL) {
  errno = 0;
  wcstol(L"123", nullptr, -1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstol(L"123", nullptr, 1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstol(L"123", nullptr, 37);
  ASSERT_ERRNO(EINVAL);
}

TEST(wchar, wcstoll_EINVAL) {
  errno = 0;
  wcstoll(L"123", nullptr, -1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoll(L"123", nullptr, 1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoll(L"123", nullptr, 37);
  ASSERT_ERRNO(EINVAL);
}

TEST(wchar, wcstoul_EINVAL) {
  errno = 0;
  wcstoul(L"123", nullptr, -1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoul(L"123", nullptr, 1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoul(L"123", nullptr, 37);
  ASSERT_ERRNO(EINVAL);
}

TEST(wchar, wcstoull_EINVAL) {
  errno = 0;
  wcstoull(L"123", nullptr, -1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoull(L"123", nullptr, 1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoull(L"123", nullptr, 37);
  ASSERT_ERRNO(EINVAL);
}

TEST(wchar, wcstoll_l_EINVAL) {
  errno = 0;
  wcstoll_l(L"123", nullptr, -1, SAFE_LC_GLOBAL_LOCALE);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoll_l(L"123", nullptr, 1, SAFE_LC_GLOBAL_LOCALE);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoll_l(L"123", nullptr, 37, SAFE_LC_GLOBAL_LOCALE);
  ASSERT_ERRNO(EINVAL);
}

TEST(wchar, wcstoull_l_EINVAL) {
  errno = 0;
  wcstoull_l(L"123", nullptr, -1, SAFE_LC_GLOBAL_LOCALE);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoull_l(L"123", nullptr, 1, SAFE_LC_GLOBAL_LOCALE);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoull_l(L"123", nullptr, 37, SAFE_LC_GLOBAL_LOCALE);
  ASSERT_ERRNO(EINVAL);
}

TEST(wchar, wmempcpy) {
#if !defined(ANDROID_HOST_MUSL)
  wchar_t dst[6];
  ASSERT_EQ(&dst[4], wmempcpy(dst, L"hello", 4));
#else
  GTEST_SKIP() << "musl doesn't have wmempcpy";
#endif
}

template <typename T>
using WcsToFloatFn = T (*)(const wchar_t*, wchar_t**);

template <typename T>
void TestSingleWcsToFloat(WcsToFloatFn<T> fn, const wchar_t* str,
                          T expected_value, ptrdiff_t expected_len) {
  wchar_t* p;
  ASSERT_EQ(expected_value, fn(str, &p));
  ASSERT_EQ(expected_len, p - str);
}

template <typename T>
void TestWcsToFloat(WcsToFloatFn<T> fn) {
  TestSingleWcsToFloat(fn, L"123", static_cast<T>(123.0L), 3);
  TestSingleWcsToFloat(fn, L"123#", static_cast<T>(123.0L), 3);
  TestSingleWcsToFloat(fn, L"   123 45", static_cast<T>(123.0L), 6);
  TestSingleWcsToFloat(fn, L"9.0", static_cast<T>(9.0L), 3);
  TestSingleWcsToFloat(fn, L"-9.0", static_cast<T>(-9.0L), 4);
  TestSingleWcsToFloat(fn, L" \t\v\f\r\n9.0", static_cast<T>(9.0L), 9);
}

template <typename T>
void TestWcsToFloatHexFloats(WcsToFloatFn<T> fn) {
  TestSingleWcsToFloat(fn, L"0.9e1", static_cast<T>(9.0L), 5);
  TestSingleWcsToFloat(fn, L"0x1.2p3", static_cast<T>(9.0L), 7);
  TestSingleWcsToFloat(fn, L"+1e+100", static_cast<T>(1e100L), 7);
  TestSingleWcsToFloat(fn, L"0x10000.80", static_cast<T>(65536.50L), 10);
}

template <typename T>
void TestWcsToFloatInfNan(WcsToFloatFn<T> fn) {
  ASSERT_TRUE(isnan(fn(L"+nan", nullptr)));
  ASSERT_TRUE(isnan(fn(L"nan", nullptr)));
  ASSERT_TRUE(isnan(fn(L"-nan", nullptr)));

  ASSERT_TRUE(isnan(fn(L"+nan(0xff)", nullptr)));
  ASSERT_TRUE(isnan(fn(L"nan(0xff)", nullptr)));
  ASSERT_TRUE(isnan(fn(L"-nan(0xff)", nullptr)));

  wchar_t* p;
  ASSERT_TRUE(isnan(fn(L"+nanny", &p)));
  ASSERT_STREQ(L"ny", p);
  ASSERT_TRUE(isnan(fn(L"nanny", &p)));
  ASSERT_STREQ(L"ny", p);
  ASSERT_TRUE(isnan(fn(L"-nanny", &p)));
  ASSERT_STREQ(L"ny", p);

  ASSERT_EQ(0, fn(L"muppet", &p));
  ASSERT_STREQ(L"muppet", p);
  ASSERT_EQ(0, fn(L"  muppet", &p));
  ASSERT_STREQ(L"  muppet", p);

  ASSERT_EQ(std::numeric_limits<T>::infinity(), fn(L"+inf", nullptr));
  ASSERT_EQ(std::numeric_limits<T>::infinity(), fn(L"inf", nullptr));
  ASSERT_EQ(-std::numeric_limits<T>::infinity(), fn(L"-inf", nullptr));

  ASSERT_EQ(std::numeric_limits<T>::infinity(), fn(L"+infinity", nullptr));
  ASSERT_EQ(std::numeric_limits<T>::infinity(), fn(L"infinity", nullptr));
  ASSERT_EQ(-std::numeric_limits<T>::infinity(), fn(L"-infinity", nullptr));

  ASSERT_EQ(std::numeric_limits<T>::infinity(), fn(L"+infinitude", &p));
  ASSERT_STREQ(L"initude", p);
  ASSERT_EQ(std::numeric_limits<T>::infinity(), fn(L"infinitude", &p));
  ASSERT_STREQ(L"initude", p);
  ASSERT_EQ(-std::numeric_limits<T>::infinity(), fn(L"-infinitude", &p));
  ASSERT_STREQ(L"initude", p);

  // Check case-insensitivity.
  ASSERT_EQ(std::numeric_limits<T>::infinity(), fn(L"InFiNiTy", nullptr));
  ASSERT_TRUE(isnan(fn(L"NaN", nullptr)));
}

TEST(wchar, wcstof) {
  TestWcsToFloat(wcstof);
}

TEST(wchar, wcstof_hex_floats) {
  TestWcsToFloatHexFloats(wcstof);
}

TEST(wchar, wcstof_hex_inf_nan) {
  TestWcsToFloatInfNan(wcstof);
}

TEST(wchar, wcstod) {
  TestWcsToFloat(wcstod);
}

TEST(wchar, wcstod_hex_floats) {
  TestWcsToFloatHexFloats(wcstod);
}

TEST(wchar, wcstod_hex_inf_nan) {
  TestWcsToFloatInfNan(wcstod);
}

TEST(wchar, wcstold) {
  TestWcsToFloat(wcstold);
}

TEST(wchar, wcstold_hex_floats) {
  TestWcsToFloatHexFloats(wcstold);
}

TEST(wchar, wcstold_hex_inf_nan) {
  TestWcsToFloatInfNan(wcstold);
}

TEST(wchar, wcstod_l) {
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(1.23, wcstod_l(L"1.23", nullptr, SAFE_LC_GLOBAL_LOCALE));
#else
  GTEST_SKIP() << "musl doesn't have wcstod_l";
#endif
}

TEST(wchar, wcstof_l) {
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(1.23f, wcstof_l(L"1.23", nullptr, SAFE_LC_GLOBAL_LOCALE));
#else
  GTEST_SKIP() << "musl doesn't have wcstof_l";
#endif
}

TEST(wchar, wcstol_l) {
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(123L, wcstol_l(L"123", nullptr, 10, SAFE_LC_GLOBAL_LOCALE));
#else
  GTEST_SKIP() << "musl doesn't have wcstol_l";
#endif
}

TEST(wchar, wcstold_l) {
  EXPECT_EQ(1.23L, wcstold_l(L"1.23", nullptr, SAFE_LC_GLOBAL_LOCALE));
}

TEST(wchar, wcstoll_l) {
  EXPECT_EQ(123LL, wcstoll_l(L"123", nullptr, 10, SAFE_LC_GLOBAL_LOCALE));
}

TEST(wchar, wcstoul_l) {
#if !defined(ANDROID_HOST_MUSL)
  EXPECT_EQ(123UL, wcstoul_l(L"123", nullptr, 10, SAFE_LC_GLOBAL_LOCALE));
#else
  GTEST_SKIP() << "musl doesn't have wcstoul_l";
#endif
}

TEST(wchar, wcstoull_l) {
  EXPECT_EQ(123ULL, wcstoull_l(L"123", nullptr, 10, SAFE_LC_GLOBAL_LOCALE));
}

static void AssertWcwidthRange(wchar_t begin, wchar_t end, int expected) {
  for (wchar_t i = begin; i < end; ++i) {
    EXPECT_EQ(expected, wcwidth(i)) << static_cast<int>(i);
  }
}

TEST(wchar, wcwidth_NUL) {
  // NUL is defined to return 0 rather than -1, despite being a C0 control.
  EXPECT_EQ(0, wcwidth(0));
}

TEST(wchar, wcwidth_ascii) {
  AssertWcwidthRange(0x20, 0x7f, 1); // Non-C0 non-DEL ASCII.
}

TEST(wchar, wcwidth_controls) {
  AssertWcwidthRange(0x01, 0x20, -1); // C0 controls.
  EXPECT_EQ(-1, wcwidth(0x7f)); // DEL.
  AssertWcwidthRange(0x80, 0xa0, -1); // C1 controls.
}

TEST(wchar, wcwidth_non_spacing_and_enclosing_marks_and_format) {
  if (!have_dl()) return;

  EXPECT_EQ(0, wcwidth
"""


```