Response:
The user wants a summary of the functionality of the provided C++ code snippet. This code is a test file for the `stdio` library in Android's Bionic. The tests cover various aspects of `scanf`, `sscanf`, `swscanf`, `printf`, `snprintf`, and `swprintf`, specifically focusing on:

1. **Parsing integers in different bases:**  Decimal, hexadecimal, octal, and binary.
2. **Width specifiers for integers:**  The `%w` and `%wf` format specifiers, which seem to be Bionic-specific extensions.
3. **Argument reordering in formatted output.**
4. **Handling of wide characters.**
5. **Error handling (death tests) for invalid format specifiers.**
6. **Specific edge cases (like printing a null wide character).**

The summary should be concise and highlight the main functionalities being tested.
这是`bionic/tests/stdio_test.cpp` 文件代码片段的第 4 部分，它延续了对 Android Bionic 中 `stdio` 库函数的测试。基于这段代码，我们可以归纳出以下功能测试点：

**主要功能归纳：**

* **扩展的格式化输入/输出功能测试 (`%w` 和 `%wf`):**
    * **固定宽度整数的格式化输出 (`snprintf`, `swprintf`):**  测试使用 `%w` 格式说明符，允许指定输出整数的固定宽度（以位为单位），并以二进制、十进制、八进制、十六进制等不同进制进行格式化。
    * **固定宽度快速整数类型的格式化输出 (`snprintf`, `swprintf`):** 测试使用 `%wf` 格式说明符，针对 `int_fastN_t` 和 `uint_fastN_t` 等快速整数类型进行固定宽度格式化输出。
    * **固定宽度整数的格式化输入 (`sscanf`, `swscanf`):** 测试使用 `%w` 和 `%wf` 格式说明符，从字符串中解析固定宽度的整数，并支持不同的进制。
    * **参数重排序的固定宽度格式化输出:** 测试 `%w` 和 `%wf` 格式说明符与参数重排序功能结合使用，确保能够正确地按照指定的顺序格式化输出。
* **二进制格式输入 (`scanf`, `swscanf`):**
    * 测试使用 `%i` 格式说明符，允许解析以 `0b` 或 `<0b` 开头的二进制数。
    * 测试使用 `%b` 格式说明符，专门用于解析二进制数，并能处理指定宽度的二进制数。
* **宽字符处理 (`swscanf`, `swprintf`):**
    * 测试 `swscanf` 解析宽字符串中的不同进制的整数。
    * 测试 `swprintf` 格式化输出宽字符串。
* **错误处理测试 (Death Tests):**
    * 针对 `%w` 和 `%wf` 格式说明符，测试当指定不支持的宽度时，程序是否会按照预期终止（使用 `EXPECT_DEATH`）。
* **特定字符处理:**
    * 测试 `printf` 和 `snprintf` 如何处理空宽字符 (`L'\0'`)。

**与 Android 功能的关系举例：**

这些测试覆盖的 `stdio` 函数是 Android 系统和应用程序开发的基础。

* **`scanf`/`sscanf`/`swscanf`**: 用于解析用户输入、配置文件等字符串数据，例如：
    * **应用设置解析:** 一个应用可能从配置文件中读取用户设置，例如 IP 地址、端口号等，这些信息可能是以字符串形式存储的，需要使用 `sscanf` 进行解析。
    * **命令行工具:** Android 的一些命令行工具可能需要解析用户输入的参数，例如 `adb shell` 命令中的参数。
* **`printf`/`snprintf`/`swprintf`**: 用于格式化输出信息，例如：
    * **日志记录:** Android 系统和应用程序经常使用 `printf` 或其变体来记录日志信息，包括调试信息、错误信息等。 `%w` 和 `%wf` 可能用于以更紧凑的二进制形式记录数据。
    * **用户界面显示:** 虽然 Android 更常用 Java/Kotlin 进行 UI 开发，但在 Native 层仍然可能需要格式化字符串来显示信息。
    * **网络通信:** 在进行网络通信时，可能需要将数据格式化成特定的字符串形式进行发送。

**libc 函数功能实现解释 (基于测试推断):**

* **`scanf`, `sscanf`, `swscanf` (格式化输入):**
    * 这些函数的核心功能是将输入的字符串按照指定的格式进行解析，并将解析结果存储到提供的变量中。
    * **进制处理:** 它们需要能够识别不同进制的前缀（例如 `0x` 表示十六进制，`0` 开头表示八进制，`0b` 或 `<0b` 表示二进制）。
    * **宽度限制:**  对于 `%w` 和 `%wf`，它们需要读取指定位数的二进制表示。
    * **错误处理:** 当输入字符串与格式不匹配时，它们需要能够返回错误指示。
* **`printf`, `snprintf`, `swprintf` (格式化输出):**
    * 这些函数的核心功能是将给定的数据按照指定的格式转换为字符串并输出。
    * **进制转换:** 它们需要能够将整数转换为不同进制的字符串表示。
    * **宽度控制:** 对于 `%w` 和 `%wf`，它们需要输出固定宽度的二进制字符串。
    * **参数重排序:** 它们需要根据格式字符串中的指示，按照指定的顺序读取和格式化参数。
    * **宽字符处理:** `swprintf` 需要能够处理宽字符。

**Dynamic Linker 功能涉及 (基于测试推断):**

从提供的代码片段来看，没有直接涉及 dynamic linker 的测试。这些测试主要关注 `stdio` 库自身的功能。通常，涉及 dynamic linker 的测试会关注库的加载、符号的解析、重定位等。

**so 布局样本与链接处理过程 (假设场景):**

假设有一个 Native 库 `libmylib.so` 使用了 `snprintf` 进行日志记录：

```c++
// libmylib.cpp
#include <cstdio>
#include <android/log.h>

void log_data(int value) {
  char buffer[32];
  snprintf(buffer, sizeof(buffer), "Value: %d", value);
  __android_log_print(ANDROID_LOG_INFO, "MyLib", "%s", buffer);
}
```

**so 布局样本 (`libmylib.so`):**

```
.text:  // 包含 log_data 函数的机器码
.data:  // 可能包含全局变量
.rodata: // 可能包含字符串常量 "Value: %d"
.dynamic: // 动态链接信息，例如依赖的库（libc.so）
.symtab:  // 符号表，包含 log_data 和 snprintf 等符号
.strtab:  // 字符串表，包含符号名
.rel.dyn: // 动态重定位表，指示需要在运行时链接的符号
.rel.plt: // PLT 重定位表，用于延迟绑定
```

**链接处理过程:**

1. **编译时链接:** 编译器在编译 `libmylib.cpp` 时，会记录下对 `snprintf` 和 `__android_log_print` 等外部函数的引用。这些引用会作为未定义的符号记录在 `libmylib.so` 的符号表中。
2. **加载时链接 (Dynamic Linker):** 当 Android 系统加载 `libmylib.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * **加载依赖库:**  根据 `libmylib.so` 的 `.dynamic` 段的信息，加载其依赖的库，例如 `libc.so` 和 `liblog.so`。
    * **符号解析:** 在 `libc.so` 和 `liblog.so` 的符号表中查找 `snprintf` 和 `__android_log_print` 的定义。
    * **重定位:**  将 `libmylib.so` 中对 `snprintf` 和 `__android_log_print` 的未定义引用，更新为它们在 `libc.so` 和 `liblog.so` 中的实际地址。这通过 `.rel.dyn` 和 `.rel.plt` 段中的信息来完成。
    * **PLT (Procedure Linkage Table):**  通常 `snprintf` 这样的标准 C 库函数会通过 PLT 进行延迟绑定。第一次调用 `snprintf` 时，会触发 dynamic linker 解析符号并更新 PLT 表项。后续调用将直接跳转到已解析的地址。

**假设输入与输出 (逻辑推理):**

* **`sscanf("<0b101>", "<%i>", &i)`:**
    * **假设输入:** 字符串 "<0b101>"，格式 "<%i>"
    * **预期输出:**  `i` 的值为 5 (二进制 101)，函数返回值为 1 (成功解析一个参数)。
* **`snprintf(buf, sizeof(buf), "<%w8b>", 5)`:**
    * **假设输入:**  格式 "<%w8b>"，整数 5
    * **预期输出:** `buf` 的内容为 "<00000101>"，函数返回值为 10 (输出字符串的长度)。

**用户或编程常见的使用错误举例:**

* **`scanf` 系列函数:**
    * **忘记取地址符 `&`:** `scanf(" %d", value);`  应该写成 `scanf(" %d", &value);`。会导致程序崩溃或写入到错误的内存位置。
    * **格式字符串与参数类型不匹配:** `scanf("%d", name);` (假设 `name` 是 `char[]`)。会导致未定义的行为。
    * **缓冲区溢出:** 使用 `%s` 读取字符串时，如果输入字符串过长，可能会导致缓冲区溢出。应该使用带宽度限制的格式，例如 `scanf("%19s", buffer);` (假设 `buffer` 大小为 20)。
* **`printf` 系列函数:**
    * **格式字符串与参数类型不匹配:** `printf("%d", "hello");`。会导致未定义的输出。
    * **格式字符串漏洞:** 如果格式字符串是由用户提供的，攻击者可以通过构造恶意的格式字符串来读取或写入任意内存位置。
    * **`snprintf` 缓冲区大小不足:**  `snprintf(buf, 5, "%s", "too long");`  会导致输出被截断。

**Android Framework 或 NDK 如何到达这里 & Frida Hook 示例:**

1. **Android Framework/NDK 调用:**
   * **Java Framework -> JNI -> Native Code:**  Android Framework 中的 Java 代码 (例如，`android.util.Log`) 可能会通过 JNI 调用到 Native 代码中，Native 代码可能会使用 `printf` 或相关函数进行日志输出。
   * **NDK 应用:** 使用 NDK 开发的 Android 应用可以直接调用 Bionic 提供的 `stdio` 函数。例如，一个游戏引擎的 Native 代码可能会使用 `snprintf` 来格式化游戏状态信息。

2. **一步步到达 `stdio_test.cpp` 中的测试:**
   * 开发者在 Bionic 源代码树中编写并运行单元测试。
   * 这些测试通常使用 Google Test 框架 (如代码中的 `TEST`, `EXPECT_EQ` 等)。
   * 编译系统 (如 Android 的 Soong) 会编译这些测试文件，生成可执行文件。
   * 运行这些可执行文件会逐个执行 `stdio_test.cpp` 中定义的测试用例，例如 `TEST(STDIO_TEST, scanf_i_decimal)`。

3. **Frida Hook 示例调试:**

   假设你想 hook `sscanf` 函数来观察它的行为：

   ```javascript
   // Frida 脚本
   Interceptor.attach(Module.findExportByName("libc.so", "sscanf"), {
     onEnter: function(args) {
       console.log("sscanf called");
       console.log("format:", Memory.readUtf8String(args[1]));
       console.log("arguments:");
       // 打印传入的参数，需要根据格式字符串来解析
       // 这里只是一个简单的示例，实际需要更复杂的逻辑
       if (Memory.readUtf8String(args[1]) === "<%i>") {
         console.log("  Address of int:", args[2]);
       }
     },
     onLeave: function(retval) {
       console.log("sscanf returned:", retval);
     }
   });
   ```

   **调试步骤:**

   1. 将 Frida 脚本保存为 `hook_sscanf.js`。
   2. 找到你想要调试的目标进程的进程 ID (PID)。
   3. 使用 Frida 连接到目标进程：`frida -U -f <package_name> -l hook_sscanf.js` (如果目标是应用) 或 `frida -p <pid> -l hook_sscanf.js` (如果目标是正在运行的进程)。
   4. 当目标进程执行到 `sscanf` 函数时，Frida 脚本会拦截调用，并打印出你指定的信息 (例如，格式字符串和参数)。

这个 Frida 示例可以帮助你动态地观察 `sscanf` 的调用情况，包括传入的格式字符串和参数，以及返回值，从而理解其行为。你可以根据需要修改脚本来 hook 其他 `stdio` 函数或提取更详细的信息。

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
这是第4部分，共4部分，请归纳一下它的功能

"""
ECT_EQ(01234567, i);

  long long int lli;
  char ch;
  EXPECT_EQ(2, sscanf("010234567890abcdefg", "%lli%c", &lli, &ch));
  EXPECT_EQ(010234567, lli);
  EXPECT_EQ('8', ch);
}

TEST(STDIO_TEST, scanf_i_binary) {
  int i;
  EXPECT_EQ(1, sscanf("<0b101>", "<%i>", &i));
  EXPECT_EQ(0b101, i);

  long long int lli;
  char ch;
  EXPECT_EQ(2, sscanf("0b10234567890abcdefg", "%lli%c", &lli, &ch));
  EXPECT_EQ(0b10, lli);
  EXPECT_EQ('2', ch);
}

TEST(STDIO_TEST, wscanf_i_decimal) {
  int i;
  EXPECT_EQ(1, swscanf(L"<123789>", L"<%i>", &i));
  EXPECT_EQ(123789, i);

  long long int lli;
  char ch;
  EXPECT_EQ(2, swscanf(L"1234567890abcdefg", L"%lli%c", &lli, &ch));
  EXPECT_EQ(1234567890, lli);
  EXPECT_EQ('a', ch);
}

TEST(STDIO_TEST, wscanf_i_hex) {
  int i;
  EXPECT_EQ(1, swscanf(L"<0x123abf>", L"<%i>", &i));
  EXPECT_EQ(0x123abf, i);

  long long int lli;
  char ch;
  EXPECT_EQ(2, swscanf(L"0x1234567890abcdefg", L"%lli%c", &lli, &ch));
  EXPECT_EQ(0x1234567890abcdefLL, lli);
  EXPECT_EQ('g', ch);
}

TEST(STDIO_TEST, wscanf_i_octal) {
  int i;
  EXPECT_EQ(1, swscanf(L"<01234567>", L"<%i>", &i));
  EXPECT_EQ(01234567, i);

  long long int lli;
  char ch;
  EXPECT_EQ(2, swscanf(L"010234567890abcdefg", L"%lli%c", &lli, &ch));
  EXPECT_EQ(010234567, lli);
  EXPECT_EQ('8', ch);
}

TEST(STDIO_TEST, wscanf_i_binary) {
  int i;
  EXPECT_EQ(1, swscanf(L"<0b101>", L"<%i>", &i));
  EXPECT_EQ(0b101, i);

  long long int lli;
  char ch;
  EXPECT_EQ(2, swscanf(L"0b10234567890abcdefg", L"%lli%c", &lli, &ch));
  EXPECT_EQ(0b10, lli);
  EXPECT_EQ('2', ch);
}

TEST(STDIO_TEST, scanf_b) {
  int i;
  char ch;
  EXPECT_EQ(2, sscanf("<1012>", "<%b%c>", &i, &ch));
  EXPECT_EQ(0b101, i);
  EXPECT_EQ('2', ch);
  EXPECT_EQ(1, sscanf("<00000101>", "<%08b>", &i));
  EXPECT_EQ(0b00000101, i);
  EXPECT_EQ(1, sscanf("<0b1010>", "<%b>", &i));
  EXPECT_EQ(0b1010, i);
  EXPECT_EQ(2, sscanf("-0b", "%i%c", &i, &ch));
  EXPECT_EQ(0, i);
  EXPECT_EQ('b', ch);
}

TEST(STDIO_TEST, swscanf_b) {
  int i;
  char ch;
  EXPECT_EQ(2, swscanf(L"<1012>", L"<%b%c>", &i, &ch));
  EXPECT_EQ(0b101, i);
  EXPECT_EQ('2', ch);
  EXPECT_EQ(1, swscanf(L"<00000101>", L"<%08b>", &i));
  EXPECT_EQ(0b00000101, i);
  EXPECT_EQ(1, swscanf(L"<0b1010>", L"<%b>", &i));
  EXPECT_EQ(0b1010, i);
  EXPECT_EQ(2, swscanf(L"-0b", L"%i%c", &i, &ch));
  EXPECT_EQ(0, i);
  EXPECT_EQ('b', ch);
}

TEST(STDIO_TEST, snprintf_w_base) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
#pragma clang diagnostic ignored "-Wconstant-conversion"
  int8_t a = 0b101;
  EXPECT_SNPRINTF("<101>", "<%w8b>", a);
  int8_t b1 = 0xFF;
  EXPECT_SNPRINTF("<-1>", "<%w8d>", b1);
  int8_t b2 = 0x1FF;
  EXPECT_SNPRINTF("<-1>", "<%w8d>", b2);
  int16_t c = 0xFFFF;
  EXPECT_SNPRINTF("<-1>", "<%w16i>", c);
  int32_t d = 021;
  EXPECT_SNPRINTF("<21>", "<%w32o>", d);
  uint32_t e = -1;
  EXPECT_SNPRINTF("<4294967295>", "<%w32u>", e);
  int64_t f = 0x3b;
  EXPECT_SNPRINTF("<3b>", "<%w64x>", f);
  EXPECT_SNPRINTF("<3B>", "<%w64X>", f);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, swprintf_w_base) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
#pragma clang diagnostic ignored "-Wconstant-conversion"
  int8_t a = 0b101;
  EXPECT_SWPRINTF(L"<101>", L"<%w8b>", a);
  int8_t b1 = 0xFF;
  EXPECT_SWPRINTF(L"<-1>", L"<%w8d>", b1);
  int8_t b2 = 0x1FF;
  EXPECT_SWPRINTF(L"<-1>", L"<%w8d>", b2);
  int16_t c = 0xFFFF;
  EXPECT_SWPRINTF(L"<-1>", L"<%w16i>", c);
  int32_t d = 021;
  EXPECT_SWPRINTF(L"<21>", L"<%w32o>", d);
  uint32_t e = -1;
  EXPECT_SWPRINTF(L"<4294967295>", L"<%w32u>", e);
  int64_t f = 0x3b;
  EXPECT_SWPRINTF(L"<3b>", L"<%w64x>", f);
  EXPECT_SWPRINTF(L"<3B>", L"<%w64X>", f);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, snprintf_w_arguments_reordering) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
#pragma clang diagnostic ignored "-Wformat-extra-args"
  int32_t a = 0xaaaaaaaa;
  int64_t b = 0x11111111'22222222;
  int64_t c = 0x33333333'44444444;
  int64_t d = 0xaaaaaaaa'aaaaaaaa;
  EXPECT_SNPRINTF("<10101010101010101010101010101010 --- 3333333344444444>",
                  "<%2$w32b --- %1$w64x>", c, a);
  EXPECT_SNPRINTF(
      "<1010101010101010101010101010101010101010101010101010101010101010 --- 1111111122222222 --- "
      "3333333344444444>",
      "<%3$w64b --- %1$w64x --- %2$w64x>", b, c, d);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, swprintf_w_arguments_reordering) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
#pragma clang diagnostic ignored "-Wformat-extra-args"
  int32_t a = 0xaaaaaaaa;
  int64_t b = 0x11111111'22222222;
  int64_t c = 0x33333333'44444444;
  int64_t d = 0xaaaaaaaa'aaaaaaaa;
  EXPECT_SWPRINTF(L"<10101010101010101010101010101010 --- 3333333344444444>",
                  L"<%2$w32b --- %1$w64x>", c, a);
  EXPECT_SWPRINTF(
      L"<1010101010101010101010101010101010101010101010101010101010101010 --- 1111111122222222 --- "
      L"3333333344444444>",
      L"<%3$w64b --- %1$w64x --- %2$w64x>", b, c, d);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST_F(STDIO_DEATHTEST, snprintf_invalid_w_width) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  char buf[BUFSIZ];
  int32_t a = 100;
  EXPECT_DEATH(snprintf(buf, sizeof(buf), "%w20d", &a), "%w20 is unsupported");
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST_F(STDIO_DEATHTEST, swprintf_invalid_w_width) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  wchar_t buf[BUFSIZ];
  int32_t a = 100;
  EXPECT_DEATH(swprintf(buf, sizeof(buf), L"%w20d", &a), "%w20 is unsupported");
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, snprintf_wf_base) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconstant-conversion"
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  int_fast8_t a = 0b101;
  EXPECT_SNPRINTF("<101>", "<%wf8b>", a);
  int_fast8_t b = 0x12341234'12341234;
  EXPECT_SNPRINTF("<34>", "<%wf8x>", b);
  uint_fast16_t c = 0x11111111'22222222;
#if defined(__LP64__)
  EXPECT_SNPRINTF("<1111111122222222>", "<%wf16x>", c);
#else
  EXPECT_SNPRINTF("<22222222>", "<%wf16x>", c);
#endif
  int_fast32_t d = 0x33333333'44444444;
#if defined(__LP64__)
  EXPECT_SNPRINTF("<3333333344444444>", "<%wf32x>", d);
#else
  EXPECT_SNPRINTF("<44444444>", "<%wf32x>", d);
#endif
  int_fast64_t e = 0xaaaaaaaa'aaaaaaaa;
  EXPECT_SNPRINTF("<aaaaaaaaaaaaaaaa>", "<%wf64x>", e);
  EXPECT_SNPRINTF("<AAAAAAAAAAAAAAAA>", "<%wf64X>", e);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %wf in glibc";
#endif
}
TEST(STDIO_TEST, swprintf_wf_base) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconstant-conversion"
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  int_fast8_t a = 0b101;
  EXPECT_SWPRINTF(L"<101>", L"<%wf8b>", a);
  int_fast8_t b = 0x12341234'12341234;
  EXPECT_SWPRINTF(L"<34>", L"<%wf8x>", b);
  uint_fast16_t c = 0x11111111'22222222;
#if defined(__LP64__)
  EXPECT_SWPRINTF(L"<1111111122222222>", L"<%wf16x>", c);
#else
  EXPECT_SWPRINTF(L"<22222222>", L"<%wf16x>", c);
#endif
  int_fast32_t d = 0x33333333'44444444;
#if defined(__LP64__)
  EXPECT_SWPRINTF(L"<3333333344444444>", L"<%wf32x>", d);
#else
  EXPECT_SWPRINTF(L"<44444444>", L"<%wf32x>", d);
#endif
  int_fast64_t e = 0xaaaaaaaa'aaaaaaaa;
  EXPECT_SWPRINTF(L"<aaaaaaaaaaaaaaaa>", L"<%wf64x>", e);
  EXPECT_SWPRINTF(L"<AAAAAAAAAAAAAAAA>", L"<%wf64X>", e);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %wf in glibc";
#endif
}

TEST(STDIO_TEST, snprintf_wf_arguments_reordering) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconstant-conversion"
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-extra-args"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  int_fast16_t a = 0x11111111'22222222;
  int_fast32_t b = 0x33333333'44444444;
  int_fast32_t c = 0xaaaaaaaa'aaaaaaaa;
#if defined(__LP64__)
  EXPECT_SNPRINTF(
      "<3333333344444444 --- 1010101010101010101010101010101010101010101010101010101010101010>",
      "<%2$wf32x --- %1$wf32b>", c, b);

  EXPECT_SNPRINTF(
      "<1010101010101010101010101010101010101010101010101010101010101010 --- 1111111122222222 --- "
      "3333333344444444>",
      "<%3$wf32b --- %1$wf16x --- %2$wf32x>", a, b, c);
#else
  EXPECT_SNPRINTF("<44444444 --- 10101010101010101010101010101010>", "<%2$wf32x --- %1$wf32b>", c,
                  b);
  EXPECT_SNPRINTF("<10101010101010101010101010101010 --- 22222222 --- 44444444>",
                  "<%3$wf32b --- %1$wf16x --- %2$wf32x>", a, b, c);
#endif
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, swprintf_wf_arguments_reordering) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconstant-conversion"
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-extra-args"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  int_fast16_t a = 0x11111111'22222222;
  int_fast32_t b = 0x33333333'44444444;
  int_fast32_t c = 0xaaaaaaaa'aaaaaaaa;
#if defined(__LP64__)
  EXPECT_SWPRINTF(
      L"<3333333344444444 --- 1010101010101010101010101010101010101010101010101010101010101010>",
      L"<%2$wf32x --- %1$wf32b>", c, b);

  EXPECT_SWPRINTF(
      L"<1010101010101010101010101010101010101010101010101010101010101010 --- 1111111122222222 --- "
      L"3333333344444444>",
      L"<%3$wf32b --- %1$wf16x --- %2$wf32x>", a, b, c);
#else
  EXPECT_SWPRINTF(L"<44444444 --- 10101010101010101010101010101010>", L"<%2$wf32x --- %1$wf32b>", c,
                  b);
  EXPECT_SWPRINTF(L"<10101010101010101010101010101010 --- 22222222 --- 44444444>",
                  L"<%3$wf32b --- %1$wf16x --- %2$wf32x>", a, b, c);
#endif
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST_F(STDIO_DEATHTEST, snprintf_invalid_wf_width) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  char buf[BUFSIZ];
  int_fast32_t a = 100;
  EXPECT_DEATH(snprintf(buf, sizeof(buf), "%wf20d", &a), "%wf20 is unsupported");
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST_F(STDIO_DEATHTEST, swprintf_invalid_wf_width) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  wchar_t buf[BUFSIZ];
  int_fast32_t a = 100;
  EXPECT_DEATH(swprintf(buf, sizeof(buf), L"%wf20d", &a), "%wf20 is unsupported");
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, sscanf_w_or_wf_base) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  int8_t a;
  EXPECT_EQ(1, sscanf("<0b101>", "<%w8b>", &a));
  EXPECT_EQ(0b101, a);
  int_fast8_t fast_a;
  EXPECT_EQ(1, sscanf("<0b101>", "<%wf8b>", &fast_a));
  EXPECT_EQ(0b101, fast_a);
  int8_t b1;
  EXPECT_EQ(1, sscanf("<0xFF>", "<%w8i>", &b1));
  EXPECT_EQ(-1, b1);
  int8_t b2;
  EXPECT_EQ(1, sscanf("<0x1FF>", "<%w8i>", &b2));
  EXPECT_EQ(-1, b2);
  int_fast8_t fast_b;
  EXPECT_EQ(1, sscanf("<0x1234123412341234>", "<%wf8x>", &fast_b));
  EXPECT_EQ(0x34, fast_b);
  int16_t c1;
  EXPECT_EQ(1, sscanf("<0xFFFF>", "<%w16i>", &c1));
  EXPECT_EQ(-1, c1);
  uint16_t c2;
  EXPECT_EQ(1, sscanf("<64>", "<%w16d>", &c2));
  EXPECT_EQ(64, c2);
  int_fast16_t fast_c;
#if defined(__LP64__)
  EXPECT_EQ(1, sscanf("<0x1111111122222222>", "<%wf16x>", &fast_c));
  EXPECT_EQ(0x1111111122222222, fast_c);
#else
  EXPECT_EQ(1, sscanf("<0x1111111122222222>", "<%wf16x>", &fast_c));
  EXPECT_EQ(0x22222222, fast_c);
#endif
  int32_t d;
  EXPECT_EQ(1, sscanf("<021>", "<%w32o>", &d));
  EXPECT_EQ(021, d);
  int_fast32_t fast_d;
#if defined(__LP64__)
  EXPECT_EQ(1, sscanf("<0x3333333344444444>", "<%wf32x>", &fast_d));
  EXPECT_EQ(0x3333333344444444, fast_d);
#else
  EXPECT_EQ(1, sscanf("<0x3333333344444444>", "<%wf32x>", &fast_d));
  EXPECT_EQ(0x44444444, fast_d);
#endif
  uint32_t e;
  EXPECT_EQ(1, sscanf("<-1>", "<%w32u>", &e));
  EXPECT_EQ(4294967295, e);
  int64_t f;
  EXPECT_EQ(1, sscanf("<0x3b>", "<%w64x>", &f));
  EXPECT_EQ(0x3b, f);
  EXPECT_EQ(1, sscanf("<0x3b>", "<%w64X>", &f));
  EXPECT_EQ(0x3B, f);
  uint_fast64_t fast_f;
  EXPECT_EQ(1, sscanf("<0xaaaaaaaa>", "<%wf64x>", &fast_f));
  EXPECT_EQ(0xaaaaaaaa, fast_f);
  EXPECT_EQ(1, sscanf("<0xaaaaaaaa>", "<%wf64X>", &fast_f));
  EXPECT_EQ(0xAAAAAAAA, fast_f);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, sscanf_w_combination) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
#pragma clang diagnostic ignored "-Wformat-extra-args"
  uint32_t a;
  int64_t b;
  char c;

  EXPECT_EQ(3, sscanf("<0b10101010101010101010101010101010 0x3333333344444444 1>",
                      "<%w32b %w64x %c>", &a, &b, &c));
  EXPECT_EQ(0xaaaaaaaa, a);
  EXPECT_EQ(0x3333333344444444, b);
  EXPECT_EQ('1', c);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST_F(STDIO_DEATHTEST, sscanf_invalid_w_or_wf_width) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  int32_t a;
  EXPECT_DEATH(sscanf("<100>", "<%w20d>", &a), "%w20 is unsupported");
  int_fast32_t fast_a;
  EXPECT_DEATH(sscanf("<100>", "<%wf20d>", &fast_a), "%wf20 is unsupported");
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, swscanf_w_or_wf_base) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  int8_t a;
  EXPECT_EQ(1, swscanf(L"<0b101>", L"<%w8b>", &a));
  EXPECT_EQ(0b101, a);
  int_fast8_t fast_a;
  EXPECT_EQ(1, swscanf(L"<0b101>", L"<%wf8b>", &fast_a));
  EXPECT_EQ(0b101, fast_a);
  int8_t b1;
  EXPECT_EQ(1, swscanf(L"<0xFF>", L"<%w8i>", &b1));
  EXPECT_EQ(-1, b1);
  int8_t b2;
  EXPECT_EQ(1, swscanf(L"<0x1FF>", L"<%w8i>", &b2));
  EXPECT_EQ(-1, b2);
  int_fast8_t fast_b;
  EXPECT_EQ(1, swscanf(L"<0x1234123412341234>", L"<%wf8i>", &fast_b));
  EXPECT_EQ(0x34, fast_b);
  int16_t c1;
  EXPECT_EQ(1, swscanf(L"<0xFFFF>", L"<%w16i>", &c1));
  EXPECT_EQ(-1, c1);
  uint16_t c2;
  EXPECT_EQ(1, swscanf(L"<64>", L"<%w16d>", &c2));
  EXPECT_EQ(64, c2);
  int_fast16_t fast_c;
#if defined(__LP64__)
  EXPECT_EQ(1, swscanf(L"<0x1111111122222222>", L"<%wf16x>", &fast_c));
  EXPECT_EQ(0x1111111122222222, fast_c);
#else
  EXPECT_EQ(1, swscanf(L"<0x1111111122222222>", L"<%wf16x>", &fast_c));
  EXPECT_EQ(0x22222222, fast_c);
#endif
  int32_t d;
  EXPECT_EQ(1, swscanf(L"<021>", L"<%w32o>", &d));
  EXPECT_EQ(021, d);
  int_fast32_t fast_d;
#if defined(__LP64__)
  EXPECT_EQ(1, swscanf(L"<0x3333333344444444>", L"<%wf32x>", &fast_d));
  EXPECT_EQ(0x3333333344444444, fast_d);
#else
  EXPECT_EQ(1, swscanf(L"<0x3333333344444444>", L"<%wf32x>", &fast_d));
  EXPECT_EQ(0x44444444, fast_d);
#endif
  uint32_t e;
  EXPECT_EQ(1, swscanf(L"<-1>", L"<%w32u>", &e));
  EXPECT_EQ(4294967295, e);
  int64_t f;
  EXPECT_EQ(1, swscanf(L"<0x3b>", L"<%w64x>", &f));
  EXPECT_EQ(0x3b, f);
  EXPECT_EQ(1, swscanf(L"<0x3b>", L"<%w64X>", &f));
  EXPECT_EQ(0x3B, f);
  uint_fast64_t fast_f;
  EXPECT_EQ(1, swscanf(L"<0xaaaaaaaa>", L"<%wf64x>", &fast_f));
  EXPECT_EQ(0xaaaaaaaa, fast_f);
  EXPECT_EQ(1, swscanf(L"<0xaaaaaaaa>", L"<%wf64X>", &fast_f));
  EXPECT_EQ(0xAAAAAAAA, fast_f);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, swscanf_w_combination) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
#pragma clang diagnostic ignored "-Wformat-extra-args"
  uint32_t a;
  int64_t b;
  char c;

  EXPECT_EQ(3, swscanf(L"<0b10101010101010101010101010101010 0x3333333344444444 1>",
                       L"<%w32b %w64x %c>", &a, &b, &c));
  EXPECT_EQ(0xaaaaaaaa, a);
  EXPECT_EQ(0x3333333344444444, b);
  EXPECT_EQ('1', c);
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST_F(STDIO_DEATHTEST, swscanf_invalid_w_or_wf_width) {
#if defined(__BIONIC__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat"
#pragma clang diagnostic ignored "-Wformat-invalid-specifier"
  int32_t a;
  EXPECT_DEATH(swscanf(L"<100>", L"<%w20d>", &a), "%w20 is unsupported");
  int_fast32_t fast_a;
  EXPECT_DEATH(swscanf(L"<100>", L"<%wf20d>", &fast_a), "%wf20 is unsupported");
#pragma clang diagnostic pop
#else
  GTEST_SKIP() << "no %w in glibc";
#endif
}

TEST(STDIO_TEST, printf_lc_0) {
  // https://austingroupbugs.net/view.php?id=1647
  char buf[BUFSIZ];
  EXPECT_EQ(3, snprintf(buf, sizeof(buf), "<%lc>", L'\0'));
  EXPECT_TRUE(!memcmp(buf, "<\0>", 3));
}

"""


```