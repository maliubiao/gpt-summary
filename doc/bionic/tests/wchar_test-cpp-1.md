Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a test file for wchar-related functions in Android's Bionic library. I need to identify the main purpose of the code and the specific functionalities it tests.

**Plan:**

1. Identify the core functionality being tested. Based on the function names (`wcwidth`, `wcswidth`, `wcslcpy`, etc.), it's clear this file tests wide character string manipulation functions.
2. Group the tested functions into logical categories (e.g., width calculation, string copying, string concatenation, string comparison, string searching, memory manipulation).
3. Summarize the purpose of each category.
4. Highlight any Android-specific aspects or context gleaned from the code (like `__BIONIC__` checks).
这是对 `bionic/tests/wchar_test.cpp` 文件中剩余部分功能的总结。 这部分代码主要测试了 `wchar.h` 头文件中定义的一些宽字符处理函数的功能，包括计算宽字符宽度、宽字符串操作（复制、连接、比较、查找等）以及宽字符内存操作。

**功能归纳:**

这部分代码主要测试了以下几类宽字符处理功能：

1. **宽字符宽度计算 (`wcwidth`, `wcswidth`)**:
    *   `wcwidth`:  测试了获取单个宽字符的显示宽度。涵盖了各种类型的字符，包括组合字符、特殊字符（如软连字符、填充符）、CJK字符（中文、日文、韩文）、韩文组合字符、谚文字母、假名、带圈数字、易经六十四卦符号以及一些默认可忽略的字符。
    *   `wcswidth`: 测试了获取宽字符串指定长度的显示宽度。

2. **宽字符串复制 (`wcslcpy`, `wcscpy`)**:
    *   `wcslcpy`:  安全地将一个宽字符串复制到另一个宽字符串，并限制复制的最大长度，防止缓冲区溢出。 这个函数在 glibc 中不存在，是 bionic 特有的。
    *   `wcscpy`: 将一个宽字符串复制到另一个宽字符串。

3. **宽字符串连接 (`wcscat`, `wcslcat`, `wcsncat`)**:
    *   `wcscat`: 将一个宽字符串追加到另一个宽字符串的末尾。
    *   `wcslcat`: 安全地将一个宽字符串追加到另一个宽字符串的末尾，并限制追加的最大长度，防止缓冲区溢出。 这个函数在 glibc 中不存在，是 bionic 特有的。
    *   `wcsncat`: 将一个宽字符串的前 N 个字符追加到另一个宽字符串的末尾。

4. **宽字符串比较 (`wcscasecmp`, `wcsncasecmp`, `wcsncmp`, `wmemcmp`)**:
    *   `wcscasecmp`: 忽略大小写比较两个宽字符串。
    *   `wcsncasecmp`: 忽略大小写比较两个宽字符串的前 N 个字符。
    *   `wcsncmp`: 比较两个宽字符串的前 N 个字符。
    *   `wmemcmp`: 比较两块内存区域的前 N 个宽字符。

5. **宽字符串查找 (`wcscspn`, `wcsspn`, `wcspbrk`, `wcstok`, `wmemchr`)**:
    *   `wcscspn`: 计算宽字符串中从起始位置开始，连续不包含指定字符集合中字符的字符个数。
    *   `wcsspn`: 计算宽字符串中从起始位置开始，连续包含指定字符集合中字符的字符个数。
    *   `wcspbrk`: 在宽字符串中查找第一次出现指定字符集合中任意字符的位置。
    *   `wcstok`: 将宽字符串分割成一组标记符。这是一个可重入性有问题的函数，需要小心使用。
    *   `wmemchr`: 在内存区域中查找第一次出现指定宽字符的位置。

6. **宽字符串长度 (`wcsnlen`)**:
    *   `wcsnlen`: 获取宽字符串的长度，但最多检查 N 个宽字符。

7. **宽字符串复制（内存操作） (`wmemcpy`, `wmemmove`)**:
    *   `wmemcpy`: 将一块内存区域的内容复制到另一块内存区域。源和目标内存区域不能重叠。
    *   `wmemmove`: 将一块内存区域的内容复制到另一块内存区域。源和目标内存区域可以重叠。

8. **宽字符串填充 (`wmemset`)**:
    *   `wmemset`: 将一块内存区域的前 N 个宽字符设置为指定的宽字符值。

9. **宽字符串复制（动态分配） (`wcsdup`)**:
    *   `wcsdup`: 复制一个宽字符串到新分配的内存中。调用者需要负责释放返回的内存。

**与 Android 功能的关系和举例:**

这些宽字符处理函数是 Android 系统中处理文本的基础。Android 系统需要支持多语言，包括各种包含宽字符的语言，例如中文、日文、韩文等。

*   **输入法 (IME):**  `wchar_test.cpp` 中测试了韩文兼容字母 (Hangeul Compatibility Jamo)，这与 Android 的输入法直接相关。当用户通过 IME 输入韩文时，可能会产生这些兼容字母的编码。测试确保了这些字符的宽度计算是正确的，从而保证文本布局的准确性。 例如，测试用例 `TEST(wchar, wcwidth_hangeul_compatibility_jamo)` 验证了类似 'ㅠ' 和 'ㄱ' 这样的韩文字符被正确地识别为占据 2 个显示单元的宽度。
*   **文本显示:** `wcwidth` 和 `wcswidth` 的正确性对于在屏幕上正确渲染文本至关重要。 例如，中日韩字符通常占用两个拉丁字符的宽度。测试用例 `TEST(wchar, wcwidth_cjk)` 验证了 CJK 统一汉字区块的字符宽度被正确计算为 2。
*   **字符串操作:**  例如，在处理用户输入的文本、文件名或者在应用程序内部进行字符串处理时，可能会用到 `wcscpy`, `wcscat` 等函数。  Android Framework 或 NDK 中处理国际化文本时，会大量使用这些宽字符函数。

**libc 函数的功能实现:**

这些 `wc` 开头的函数通常是 C 标准库提供的函数，其具体实现细节位于 Bionic 的 libc 库中。

*   **`wcwidth`**:  `wcwidth` 的实现通常会参考 Unicode 标准中定义的字符宽度属性。它会根据字符的 Unicode 编码点来判断其显示宽度是 0（不可见或组合字符）、1（窄字符）还是 2（宽字符）。对于某些特殊字符，例如软连字符，其行为可能依赖于具体的实现和上下文。
*   **`wcscpy`, `wcscat`, 等字符串操作函数**:  这些函数的实现通常会逐个宽字符地进行操作。例如，`wcscpy` 会遍历源宽字符串，将每个宽字符复制到目标宽字符串，直到遇到空宽字符 (`\0`) 为止。`wcscat` 会先找到目标宽字符串的末尾，然后从那里开始复制源宽字符串。
*   **`wmem...` 函数**: 这些内存操作函数直接操作内存中的宽字符数据。例如，`wmemcpy` 会直接复制指定数量的字节（`n * sizeof(wchar_t)`) 从源地址到目标地址。

**dynamic linker 的功能和处理过程 (本代码未直接涉及):**

这个 `wchar_test.cpp` 文件主要关注 `wchar` 函数的测试，**并没有直接涉及到 dynamic linker 的功能**。Dynamic linker 的主要职责是在程序启动时加载所需的共享库 (`.so` 文件) 并解析和链接符号。

**如果代码中涉及 dynamic linker，可能会出现以下情况：**

*   **依赖共享库:** 如果 `wchar_test.cpp` 中测试的某些功能依赖于其他共享库，那么 dynamic linker 需要在运行时加载这些库。
*   **符号解析:**  测试代码可能会调用其他共享库中提供的函数，这时 dynamic linker 需要解析这些符号的地址。

**假设的 SO 布局样本:**

```
libwchar_test.so:
    LOAD ...
    TEXT ...
        ... // wchar_test 的代码
    DATA ...
        ... // 全局变量
    DYNSYM ... // 动态符号表
        wcwidth
        wcscpy
        ...
    REL.PLT ... // PLT 重定位表
    REL.DYN ... // 动态重定位表

libc.so:
    LOAD ...
    TEXT ...
        ... // libc 的代码，包括 wcwidth, wcscpy 等函数的实现
    DATA ...
        ...
    DYNSYM ...
        wcwidth
        wcscpy
        ...
```

**链接的处理过程:**

1. 当 `libwchar_test.so` 被加载时，dynamic linker 会解析其 `DYNSYM` 表，找到它需要链接的外部符号，例如 `wcwidth`。
2. Dynamic linker 会搜索已经加载的共享库（例如 `libc.so`），查找这些外部符号的定义。
3. 一旦找到符号的定义，dynamic linker 会更新 `libwchar_test.so` 的 `REL.PLT` 和 `REL.DYN` 表，将对外部符号的引用指向其在 `libc.so` 中的实际地址。
4. 这样，当 `libwchar_test.so` 中的代码调用 `wcwidth` 时，实际上会跳转到 `libc.so` 中 `wcwidth` 的实现代码。

**假设输入与输出 (针对部分测试用例):**

*   **`TEST(wchar, wcwidth_cjk)`:**
    *   **假设输入:** Unicode 编码点 `0x4e00` (CJK 统一汉字的起始)
    *   **预期输出:** `wcwidth(0x4e00)` 返回 `2`

*   **`TEST(wchar, wcslcpy)`:**
    *   **假设输入:** `dst` 是一个大小为 3 的宽字符数组，源字符串是 `"hello world"`
    *   **预期输出:** `wcslcpy(dst, L"hello world", 3)` 返回 `11` (源字符串的长度)，`dst` 的内容为 `"he\0"`

*   **`TEST(wchar, wcscat)`:**
    *   **假设输入:** `dst` 是一个包含 `"hello\0"` 的宽字符数组，要连接的字符串是 `" world"`
    *   **预期输出:** `wcscat(dst, L" world")` 返回指向 `dst` 的指针，`dst` 的内容变为 `"hello world\0"`

**用户或编程常见的使用错误:**

*   **缓冲区溢出:**  在使用 `wcscpy` 和 `wcscat` 等无长度限制的函数时，如果目标缓冲区不够大，很容易发生缓冲区溢出。应该优先使用 `wcslcpy` 和 `wcslcat` 等带有长度限制的安全版本。
    ```c++
    wchar_t dst[5];
    // 潜在的缓冲区溢出
    wcscpy(dst, L"too long");
    ```

*   **`wcstok` 的重入性问题:** `wcstok` 使用静态内部变量来跟踪解析状态，因此不是线程安全的，并且在嵌套调用时可能会产生意外结果。应该考虑使用线程安全的替代方案，例如 `wcstok_r` (如果可用)。
    ```c++
    wchar_t str[] = L"a b c d";
    wchar_t *p, *q;
    wchar_t *context_p, *context_q;

    p = wcstok(str, L" ", &context_p);
    q = wcstok(NULL, L" ", &context_q); // 如果在多线程环境或递归调用中，context_p 可能被意外修改
    ```

*   **`wcwidth` 的误用:** 错误地假设所有非 ASCII 字符的宽度都为 2。实际上，一些组合字符和特殊字符的宽度为 0 或 1。

*   **忘记处理 `wcslcpy` 和 `wcslcat` 的返回值:**  这些函数返回源字符串的长度，可以用来判断是否发生了截断。忽略返回值可能导致逻辑错误。

**Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例:**

1. **NDK 开发:**  如果开发者使用 NDK 进行 C/C++ 开发，他们可以直接调用 Bionic 提供的 `wchar` 相关函数。例如，一个 NDK 应用可能会使用 `wcstombs` 将宽字符串转换为多字节字符串。
2. **Android Framework:**  Android Framework 的某些底层组件（例如，处理文本布局、国际化支持的部分）可能会间接地使用这些函数。例如，当 Framework 需要测量一段包含宽字符的文本的宽度时，可能会调用到 Bionic 的 `wcwidth` 或 `wcswidth`。
3. **系统服务:**  一些系统服务，例如 `SurfaceFlinger`（负责屏幕合成）在处理图形和文本时，也可能间接使用这些函数。

**Frida Hook 示例:**

可以使用 Frida Hook 来拦截和观察这些函数的调用，例如 `wcwidth`:

```javascript
// hook_wcwidth.js
if (Process.arch === 'arm64' || Process.arch === 'arm') {
    const wcwidthPtr = Module.findExportByName("libc.so", "wcwidth");

    if (wcwidthPtr) {
        Interceptor.attach(wcwidthPtr, {
            onEnter: function (args) {
                const wchar = args[0].toInt();
                console.log("[wcwidth] Called with wchar:", wchar.toString(16));
            },
            onLeave: function (retval) {
                console.log("[wcwidth] Returned:", retval.toInt());
            }
        });
        console.log("Hooked wcwidth");
    } else {
        console.log("wcwidth not found in libc.so");
    }
} else {
    console.log("Frida hook for wcwidth is only supported on ARM/ARM64");
}
```

**使用 Frida 运行 Hook:**

假设你的 Android 设备上运行着一个使用了 `wcwidth` 的应用，你可以使用以下 Frida 命令来运行上面的脚本：

```bash
frida -U -f <your_app_package_name> -l hook_wcwidth.js --no-pause
```

或者，如果你的应用已经在运行：

```bash
frida -U <your_app_package_name> -l hook_wcwidth.js
```

这个 Frida 脚本会在 `wcwidth` 函数被调用时打印出传入的宽字符的值（以十六进制显示）以及函数的返回值。 这可以帮助你理解在实际运行过程中，哪些字符被传递给 `wcwidth` 以及它们的宽度是多少。  你可以类似地 Hook 其他 `wchar` 函数来观察它们的行为。

### 提示词
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
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
(0x0300)); // Combining grave.
  EXPECT_EQ(0, wcwidth(0x20dd)); // Combining enclosing circle.
  EXPECT_EQ(0, wcwidth(0x200b)); // Zero width space.
}

TEST(wchar, wcwidth_non_spacing_special_cases) {
  if (!have_dl()) return;

  // U+00AD is a soft hyphen, which normally shouldn't be rendered at all.
  // I think the assumption here is that you elide the soft hyphen character
  // completely in that case, and never call wcwidth() if you don't want to
  // render it as an actual hyphen. Whereas if you do want to render it,
  // you call wcwidth(), and 1 is the right answer. This is what Markus Kuhn's
  // original https://www.cl.cam.ac.uk/~mgk25/ucs/wcwidth.c did,
  // and glibc and iOS do the same.
  // See also: https://en.wikipedia.org/wiki/Soft_hyphen#Text_to_be_formatted_by_the_recipient
  EXPECT_EQ(1, wcwidth(0x00ad)); // Soft hyphen (SHY).

  // U+115F is the Hangeul choseong filler (for a degenerate composed
  // character missing an initial consonant (as opposed to one with a
  // leading ieung). Since the code points for combining jungseong (medial
  // vowels) and jongseong (trailing consonants) have width 0, the choseong
  // (initial consonant) has width 2 to cover the entire syllable. So unless
  // U+115f has width 2, a degenerate composed "syllable" without an initial
  // consonant or ieung would have a total width of 0, which is silly.
  // The following sequence is effectively "약" without the leading ieung...
  EXPECT_EQ(2, wcwidth(0x115f)); // Hangeul choseong filler.
  EXPECT_EQ(0, wcwidth(0x1163)); // Hangeul jungseong "ya".
  EXPECT_EQ(0, wcwidth(0x11a8)); // Hangeul jongseong "kiyeok".

  // U+1160, the jungseong filler, has width 0 because it must have been
  // preceded by either a choseong or choseong filler.
  EXPECT_EQ(0, wcwidth(0x1160));
}

TEST(wchar, wcwidth_cjk) {
  if (!have_dl()) return;

  EXPECT_EQ(2, wcwidth(0x4e00)); // Start of CJK unified block.
  EXPECT_EQ(2, wcwidth(0x9fff)); // End of CJK unified block.
  EXPECT_EQ(2, wcwidth(0x3400)); // Start of CJK extension A block.
  EXPECT_EQ(2, wcwidth(0x4dbf)); // End of CJK extension A block.
  EXPECT_EQ(2, wcwidth(0x20000)); // Start of CJK extension B block.
  EXPECT_EQ(2, wcwidth(0x2a6df)); // End of CJK extension B block.
}

TEST(wchar, wcwidth_korean_combining_jamo) {
  if (!have_dl()) return;

  AssertWcwidthRange(0x1160, 0x1200, 0); // Original range.
  EXPECT_EQ(0, wcwidth(0xd7b0)); // Newer.
  EXPECT_EQ(0, wcwidth(0xd7cb));
}

TEST(wchar, wcwidth_korean_jeongeul_syllables) {
  if (!have_dl()) return;

  EXPECT_EQ(2, wcwidth(0xac00)); // Start of block.
  EXPECT_EQ(2, wcwidth(0xd7a3)); // End of defined code points as of Unicode 15.

  // Undefined characters at the end of the block currently have width 1,
  // but since they're undefined, we don't test that.
}

TEST(wchar, wcwidth_kana) {
  if (!have_dl()) return;

  // Hiragana (most, not undefined).
  AssertWcwidthRange(0x3041, 0x3097, 2);
  // Katakana.
  AssertWcwidthRange(0x30a0, 0x3100, 2);
}

TEST(wchar, wcwidth_circled_two_digit_cjk) {
  if (!have_dl()) return;

  // Circled two-digit CJK "speed sign" numbers are wide,
  // though EastAsianWidth is ambiguous.
  AssertWcwidthRange(0x3248, 0x3250, 2);
}

TEST(wchar, wcwidth_hexagrams) {
  if (!have_dl()) return;

  // Hexagrams are wide, though EastAsianWidth is neutral.
  AssertWcwidthRange(0x4dc0, 0x4e00, 2);
}

TEST(wchar, wcwidth_default_ignorables) {
  if (!have_dl()) return;

  AssertWcwidthRange(0xfff0, 0xfff8, 0); // Unassigned by default ignorable.
  EXPECT_EQ(0, wcwidth(0xe0000)); // ...through 0xe0fff.
}

TEST(wchar, wcwidth_hangeul_compatibility_jamo) {
  if (!have_dl()) return;

  // These are actually the *compatibility* jamo code points, *not* the regular
  // jamo code points (U+1100-U+11FF) using a jungseong filler. If you use the
  // Android IME to type any of these, you get these code points.

  // (Half of) the Korean "crying" emoticon "ㅠㅠ".
  // Actually U+3160 "Hangeul Letter Yu" from Hangeul Compatibility Jamo.
  EXPECT_EQ(2, wcwidth(L'ㅠ'));
  // The two halves of the Korean internet shorthand "ㄱㅅ" (short for 감사).
  // Actually U+3131 "Hangeul Letter Kiyeok" and U+3145 "Hangeul Letter Sios"
  // from Hangeul Compatibility Jamo.
  EXPECT_EQ(2, wcwidth(L'ㄱ'));
  EXPECT_EQ(2, wcwidth(L'ㅅ'));
}

TEST(wchar, wcswidth) {
  EXPECT_EQ(2, wcswidth(L"abc", 2));
  EXPECT_EQ(2, wcswidth(L"ab\t", 2));
  EXPECT_EQ(-1, wcswidth(L"a\tb", 2));
}

TEST(wchar, wcslcpy) {
#if defined(__BIONIC__)
  wchar_t dst[32];
  ASSERT_EQ(11U, wcslcpy(dst, L"hello world", 3));
  ASSERT_STREQ(L"he", dst);
  ASSERT_EQ(11U, wcslcpy(dst, L"hello world", 32));
  ASSERT_STREQ(L"hello world", dst);
#else
  GTEST_SKIP() << "no wcslcpy in glibc";
#endif
}

TEST(wchar, wcscat) {
  wchar_t dst[32];
  ASSERT_EQ(dst, wcscat(dst, L"hello"));
  ASSERT_STREQ(dst, L"hello");
  ASSERT_EQ(dst, wcscat(dst, L" world"));
  ASSERT_STREQ(dst, L"hello world");
}

TEST(wchar, wcscpy) {
  wchar_t dst[32];
  ASSERT_EQ(dst, wcscpy(dst, L"hello"));
  ASSERT_STREQ(dst, L"hello");
  ASSERT_EQ(dst, wcscpy(dst, L"world"));
  ASSERT_STREQ(dst, L"world");
}

TEST(wchar, wcscasecmp) {
  ASSERT_EQ(0, wcscasecmp(L"hello", L"HELLO"));
  ASSERT_TRUE(wcscasecmp(L"hello1", L"HELLO2") < 0);
  ASSERT_TRUE(wcscasecmp(L"hello2", L"HELLO1") > 0);
  ASSERT_TRUE(wcscasecmp(L"hello", L"HELL") > 0);
  ASSERT_TRUE(wcscasecmp(L"hell", L"HELLO") < 0);
}

TEST(wchar, wcscspn) {
  ASSERT_EQ(0U, wcscspn(L"hello world", L"abcdefghijklmnopqrstuvwxyz"));
  ASSERT_EQ(5U, wcscspn(L"hello world", L" "));
  ASSERT_EQ(11U, wcscspn(L"hello world", L"!"));
}

TEST(wchar, wcsspn) {
  ASSERT_EQ(0U, wcsspn(L"hello world", L"!"));
  ASSERT_EQ(5U, wcsspn(L"hello world", L"abcdefghijklmnopqrstuvwxyz"));
  ASSERT_EQ(11U, wcsspn(L"hello world", L"abcdefghijklmnopqrstuvwxyz "));
}

TEST(wchar, wcsdup) {
  wchar_t* s = wcsdup(L"hello");
  ASSERT_STREQ(s, L"hello");
  free(s);
}

TEST(wchar, wcslcat) {
#if defined(__BIONIC__)
  wchar_t dst[4] = {};
  ASSERT_EQ(1U, wcslcat(dst, L"a", 4));
  ASSERT_EQ(7U, wcslcat(dst, L"bcdefg", 4));
  ASSERT_STREQ(dst, L"abc");
#else
  GTEST_SKIP() << "no wcslcpy in glibc";
#endif
}

TEST(wchar, wcsncasecmp) {
  ASSERT_EQ(0, wcsncasecmp(L"foo", L"bar", 0));

  ASSERT_EQ(0, wcsncasecmp(L"hello1", L"HELLO2", 5));
  ASSERT_TRUE(wcsncasecmp(L"hello1", L"HELLO2", 6) < 0);
  ASSERT_TRUE(wcsncasecmp(L"hello2", L"HELLO1", 6) > 0);
  ASSERT_TRUE(wcsncasecmp(L"hello", L"HELL", 5) > 0);
  ASSERT_TRUE(wcsncasecmp(L"hell", L"HELLO", 5) < 0);
}

TEST(wchar, wcsncat) {
  wchar_t dst[32];
  ASSERT_EQ(dst, wcsncat(dst, L"hello, world!", 5));
  ASSERT_STREQ(dst, L"hello");
  ASSERT_EQ(dst, wcsncat(dst, L"hello, world!", 0));
  ASSERT_STREQ(dst, L"hello");
  ASSERT_EQ(dst, wcsncat(dst, L", world!", 8));
  ASSERT_STREQ(dst, L"hello, world!");
}

TEST(wchar, wcsncmp) {
  ASSERT_EQ(0, wcsncmp(L"foo", L"bar", 0));
  ASSERT_EQ(0, wcsncmp(L"aaaa", L"aaab", 3));
  ASSERT_TRUE(wcsncmp(L"aaaa", L"aaab", 4) < 0);
  ASSERT_TRUE(wcsncmp(L"aaab", L"aaaa", 4) > 0);
}

TEST(wchar, wcsnlen) {
  ASSERT_EQ(2U, wcsnlen(L"hello", 2));
  ASSERT_EQ(5U, wcsnlen(L"hello", 5));
  ASSERT_EQ(5U, wcsnlen(L"hello", 666));
}

TEST(wchar, wcspbrk) {
  const wchar_t* s = L"hello, world!";
  ASSERT_EQ(nullptr, wcspbrk(s, L"-"));
  ASSERT_EQ(s, wcspbrk(s, L"abch"));
  ASSERT_EQ(s + 2, wcspbrk(s, L"l"));
  ASSERT_EQ(s + 5, wcspbrk(s, L",. !"));
}

TEST(wchar, wcstok) {
  wchar_t s[] = L"this is\ta\nstring";
  wchar_t* p;
  ASSERT_EQ(s, wcstok(s, L"\t\n ", &p));
  ASSERT_STREQ(s, L"this");
  ASSERT_STREQ(p, L"is\ta\nstring");
  ASSERT_EQ(s + 5, wcstok(nullptr, L"\t\n ", &p));
  ASSERT_STREQ(s + 5, L"is");
  ASSERT_STREQ(p, L"a\nstring");
  ASSERT_EQ(s + 8, wcstok(nullptr, L"\t\n ", &p));
  ASSERT_STREQ(s + 8, L"a");
  ASSERT_STREQ(p, L"string");
  ASSERT_EQ(s + 10, wcstok(nullptr, L"\t\n ", &p));
  ASSERT_STREQ(s + 10, L"string");
  ASSERT_EQ(nullptr, p);
}

TEST(wchar, wmemchr) {
  const wchar_t* s = L"hello, world!";
  ASSERT_EQ(s, wmemchr(s, L'h', 13));
  ASSERT_EQ(s + 5, wmemchr(s, L',', 13));
  ASSERT_EQ(s + 12, wmemchr(s, L'!', 13));
  ASSERT_EQ(nullptr, wmemchr(s, L'a', 13));
}

TEST(wchar, wmemcmp) {
  ASSERT_EQ(0, wmemcmp(L"aaaa", L"aaab", 3));
  ASSERT_TRUE(wmemcmp(L"aaaa", L"aaab", 4) < 0);
  ASSERT_TRUE(wmemcmp(L"aaab", L"aaaa", 4) > 0);
}

TEST(wchar, wmemcpy) {
  wchar_t dst[32] = {};
  ASSERT_EQ(dst, wmemcpy(dst, L"hello", 5));
  ASSERT_STREQ(dst, L"hello");
}

TEST(wchar, wmemmove) {
  wchar_t dst[32] = {};
  ASSERT_EQ(dst, wmemmove(dst, L"hello", 5));
  ASSERT_STREQ(dst, L"hello");
}

TEST(wchar, wmemset) {
  wchar_t dst[4] = {};
  ASSERT_EQ(dst, wmemset(dst, 0x12345678, 3));
  ASSERT_EQ(dst[0], wchar_t(0x12345678));
  ASSERT_EQ(dst[1], wchar_t(0x12345678));
  ASSERT_EQ(dst[2], wchar_t(0x12345678));
  ASSERT_EQ(dst[3], wchar_t(0));
  ASSERT_EQ(dst, wmemset(dst, L'y', 0));
  ASSERT_EQ(dst[0], wchar_t(0x12345678));
}
```