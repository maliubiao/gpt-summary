Response:
Let's break down the thought process to answer the request about `bionic/tests/inttypes_test.cpp`.

**1. Understanding the Request:**

The core request is to analyze the given C++ test file and explain its purpose, how it relates to Android, how the involved libc functions work, its connection to the dynamic linker, potential errors, and how Android frameworks reach this code. A Frida hook example is also requested. This is a multi-faceted question requiring understanding of testing, C standard library, and the Android ecosystem.

**2. Initial Scan of the Code:**

The first thing to do is skim the code. Key observations:

* **Includes:** `<inttypes.h>`, `<errno.h>`, `<gtest/gtest.h>`, `<stdio.h>`, `"utils.h"`. This immediately tells us it's a C++ test file using Google Test framework, testing functionalities related to integer types, error handling, and standard input/output. The presence of `inttypes.h` is the most significant clue about the file's main purpose.
* **Macros:** `PRINTF_TYPED`, `PRINTF_SIZED`, `SCANF_TYPED`, `SCANF_SIZED`. These macros are clearly designed to test the `printf` and `scanf` family of functions with different integer types and format specifiers.
* **`TEST` macros:** This confirms it's a Google Test file with distinct test cases.
* **Function names:** `wcstoimax`, `wcstoumax`, `strtoimax`, `strtoumax`, `div`, `ldiv`, `lldiv`, `imaxdiv`, `imaxabs`. These are all standard C library functions related to integer conversions, division, and absolute value.
* **Assertions:** `EXPECT_STREQ`, `EXPECT_EQ`, `ASSERT_ERRNO`. These are Google Test assertions used to verify the correctness of the tested functions.

**3. Deconstructing the Request - Planning the Answer:**

Now, address each part of the request systematically:

* **Functionality:**  The primary function is testing the `inttypes.h` header and related C standard library functions. Specifically, it checks the correctness of `printf` and `scanf` format specifiers for different integer types and the behavior of integer conversion and arithmetic functions.

* **Relationship to Android:**  `inttypes.h` is part of Bionic, Android's C library. This test ensures the correct implementation of these standard functions within the Android environment. Examples would revolve around how Android apps and the framework rely on these functions for basic operations.

* **libc Function Implementation:** This requires explaining how each tested function (`printf`, `scanf`, `wcstoimax`, `wcstoumax`, `strtoimax`, `strtoumax`, `div`, `ldiv`, `lldiv`, `imaxdiv`, `imaxabs`) generally works. The level of detail shouldn't be the exact assembly code, but a conceptual overview of their input, processing, and output. For example, `printf` and `scanf`'s role in formatted I/O, and the string-to-integer conversion functions' handling of bases and error conditions.

* **Dynamic Linker:**  Since it's a *test* file within Bionic, it likely doesn't directly *use* dynamic linking in its execution. However, the *functions it tests* are part of libc, which *is* a shared library. The explanation needs to cover how libc is linked, how symbols are resolved, and provide a simple example of a `.so` layout. The linking process involves finding the definitions of the tested functions within `libc.so`.

* **Logical Reasoning (Input/Output):** The test file *itself* provides the input and expected output. The macros like `PRINTF_TYPED` and `SCANF_TYPED` set up scenarios and verify results. For example, `snprintf(buf, sizeof(buf), "%" PRId32, int32_t(123))` expects the output to be the string "123". The tests for conversion functions also provide clear input strings and expected numeric outputs.

* **Common Usage Errors:**  Focus on common mistakes developers make when using these functions. For example, incorrect format specifiers in `printf`/`scanf`, buffer overflows, neglecting to check return values, and errors in base specification for string conversions.

* **Android Framework/NDK Path:**  This involves describing how a high-level Android framework call (like displaying text) eventually leads down to the usage of C library functions tested here. The NDK path is more direct – native code directly calls these functions. The explanation should illustrate the layering.

* **Frida Hook Example:**  Select a relevant function (like `strtoimax`) and demonstrate how to hook it with Frida to inspect arguments and return values. This requires basic Frida syntax.

**4. Drafting and Refining:**

Start writing, focusing on clarity and accuracy. Use the decomposed plan as a guide.

* **Be precise:**  Use correct terminology (e.g., "format specifier," "shared library").
* **Provide examples:**  Illustrate concepts with concrete examples.
* **Structure the answer logically:** Follow the order of the request.
* **Review and revise:** Ensure the answer is comprehensive and easy to understand. For instance, initially I might have forgotten to explicitly mention that the *test* itself doesn't directly use the dynamic linker but the *code it tests* does. Revision catches this.

**Self-Correction/Refinement Example During the Process:**

Initially, I might focus too much on the specific test cases. I need to remember the broader context: this file tests *features* of `inttypes.h` and the C library. So, while explaining the macros is useful, the emphasis should be on the functionality being tested (formatted I/O, integer conversions, etc.). Also, when discussing the dynamic linker, it's important to clarify that while this *test* doesn't dynamically link other libraries during its *own execution*, the *libc functions* it tests are part of a dynamically linked library (`libc.so`). This distinction is crucial for a correct understanding. Similarly, when describing the Android framework path, initially, I might just say "the framework uses libc."  A better explanation would involve a specific example like displaying text and how it might involve `snprintf` internally.

By following this structured thought process, including a detailed analysis of the request and iterative refinement, the resulting comprehensive and accurate answer can be constructed.
好的，让我们来详细分析一下 `bionic/tests/inttypes_test.cpp` 这个文件。

**文件功能概览**

`bionic/tests/inttypes_test.cpp` 是 Android Bionic 库中的一个测试文件。它的主要功能是测试 `<inttypes.h>` 头文件中定义的各种整数类型以及相关的宏和函数是否正确实现。具体来说，它涵盖了以下几个方面：

1. **格式化输入/输出宏的测试 (`printf` 和 `scanf` 族函数)：**
   - 测试了用于 `printf` 和 `scanf` 族函数的格式化宏，例如 `PRId8`, `PRIu64`, `SCNd16` 等。这些宏用于指定不同大小和类型的整数在格式化字符串中的表示方式。
   - 验证了这些宏是否能正确地格式化和解析不同类型的整数。

2. **宽字符和多字节字符串到整数的转换函数测试：**
   - 测试了 `wcstoimax` 和 `wcstoumax` 函数，它们用于将宽字符字符串转换为最大大小的有符号和无符号整数类型 (`intmax_t` 和 `uintmax_t`)。
   - 测试了 `strtoimax` 和 `strtoumax` 函数，它们用于将多字节字符串转换为最大大小的有符号和无符号整数类型。

3. **整数除法函数测试：**
   - 测试了 `div`, `ldiv`, `lldiv`, `imaxdiv` 函数，它们用于执行整数除法并返回商和余数。

4. **整数绝对值函数测试：**
   - 测试了 `imaxabs` 函数，它用于计算最大大小的整数的绝对值。

5. **错误处理测试：**
   - 测试了在 `strtoimax`, `strtoumax`, `wcstoimax`, `wcstoumax` 函数中，当基数无效时是否能正确设置 `errno` 为 `EINVAL`。

**与 Android 功能的关系及举例说明**

`inttypes.h` 中定义的类型和函数是 C 标准库的一部分，而 Bionic 是 Android 的 C 库。因此，这个测试文件直接关系到 Android 系统的基础功能。许多 Android 组件和应用程序都依赖于这些基本的整数类型和操作。

**举例说明：**

* **底层系统服务:** Android 的一些底层系统服务（例如 SurfaceFlinger，AudioFlinger）在处理内存大小、缓冲区大小、时间戳等信息时，会使用 `<inttypes.h>` 中定义的固定大小的整数类型（如 `uint32_t`, `int64_t`）来确保跨平台的一致性。
* **NDK 开发:** 使用 Android NDK 进行原生开发的应用程序，可以直接使用 `<inttypes.h>` 中定义的类型和函数进行整数操作和格式化。例如，一个图像处理库可能使用 `uint8_t` 来表示像素值。
* **文件系统操作:**  Android 的文件系统操作在处理文件大小、偏移量等信息时，也会使用这些整数类型。
* **网络编程:**  网络协议中经常需要处理固定大小的整数，例如 IP 地址、端口号等。

**libc 函数的实现解释**

让我们详细解释一下测试文件中涉及的一些 libc 函数的功能和可能的实现方式：

1. **`snprintf(char *str, size_t size, const char *format, ...)`:**
   - **功能:** 将格式化的数据写入字符串 `str`，但最多写入 `size - 1` 个字符，并以 null 字符结尾。
   - **实现:**  `snprintf` 的实现通常会解析 `format` 字符串中的格式说明符（例如 `%d`, `%x`, `%s`），然后从可变参数列表中提取对应的值，并将它们格式化后写入 `str`。为了避免缓冲区溢出，它会检查已写入的字符数是否超过 `size - 1`。

2. **`sscanf(const char *str, const char *format, ...)`:**
   - **功能:** 从字符串 `str` 中读取格式化的数据，并将结果存储到可变参数列表中的变量中。
   - **实现:** `sscanf` 的实现会解析 `format` 字符串中的格式说明符，然后尝试从 `str` 中匹配相应的模式，并将提取的值转换为指定的类型并存储到相应的指针指向的内存位置。

3. **`wcstoimax(const wchar_t *nptr, wchar_t **endptr, int base)` / `wcstoumax(...)`:**
   - **功能:** 将宽字符字符串 `nptr` 转换为 `intmax_t` 或 `uintmax_t` 类型的整数。`base` 指定转换的基数（例如 10 表示十进制，16 表示十六进制）。`endptr` 用于返回解析停止的位置。
   - **实现:** 这些函数通常会跳过前导的空白字符，然后根据 `base` 解析数字部分。它们会处理正负号（对于 `wcstoimax`），并检查是否发生溢出或下溢。如果 `endptr` 不为 null，则会将其设置为指向解析停止的字符。如果 `base` 无效（不在 2 到 36 的范围内），则设置 `errno` 为 `EINVAL`。

4. **`strtoimax(const char *nptr, char **endptr, int base)` / `strtoumax(...)`:**
   - **功能:** 与 `wcstoimax` 和 `wcstoumax` 类似，但处理的是多字节字符串。
   - **实现:** 实现方式与宽字符版本类似，只是处理的是 `char` 类型的字符串。

5. **`div(int numer, int denom)` / `ldiv(...)` / `lldiv(...)` / `imaxdiv(...)`:**
   - **功能:** 执行整数除法，返回一个结构体，包含商 (`quot`) 和余数 (`rem`)。
   - **实现:** 这些函数执行基本的整数除法运算。余数的符号与被除数的符号相同。具体的实现可能依赖于硬件指令，但逻辑上是 `quot = numer / denom` 和 `rem = numer % denom`。

6. **`imaxabs(intmax_t j)`:**
   - **功能:** 返回 `intmax_t` 类型整数 `j` 的绝对值。
   - **实现:**  如果 `j` 是非负数，则返回 `j` 本身。如果 `j` 是负数，则返回 `-j`。需要注意处理 `INTMAX_MIN` 的情况，因为它的绝对值可能超出 `INTMAX_MAX` 的范围（虽然在 `inttypes_test.cpp` 中没有直接测试这种情况）。

**涉及 dynamic linker 的功能**

这个测试文件本身并没有直接使用 dynamic linker 的功能。然而，它测试的函数（如 `printf`, `scanf`, `strtoimax` 等）都位于 `libc.so` 这个共享库中，而 `libc.so` 的加载和链接是由 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 完成的。

**so 布局样本 (libc.so 的简化示例):**

```
libc.so:
  .text:  // 代码段
    _start:            // 程序入口点（对于可执行文件，libc.so 作为共享库没有这个）
    printf:            // printf 函数的代码
    scanf:             // scanf 函数的代码
    strtoimax:         // strtoimax 函数的代码
    ...

  .data:  // 已初始化数据段
    __stdout_buf:      // stdout 的缓冲区
    ...

  .bss:   // 未初始化数据段
    ...

  .dynsym: // 动态符号表
    printf (GLOBAL, FUNC)
    scanf (GLOBAL, FUNC)
    strtoimax (GLOBAL, FUNC)
    ...

  .dynstr: // 动态字符串表
    "printf"
    "scanf"
    "strtoimax"
    ...

  .rel.dyn: // 动态重定位表 (可能存在，取决于架构和编译选项)
    // 指示在加载时需要修改哪些地址
```

**链接的处理过程：**

1. **加载 `libc.so`:** 当一个应用程序启动时，Android 的 zygote 进程会 fork 出新的进程。新进程在启动过程中，dynamic linker 会被调用来加载程序依赖的共享库，包括 `libc.so`。
2. **符号解析:** dynamic linker 会遍历 `libc.so` 的 `.dynsym` (动态符号表)，查找应用程序中引用的外部符号（例如 `printf`）。
3. **重定位:**  由于共享库在内存中的加载地址可能是不固定的（ASLR），dynamic linker 会根据 `.rel.dyn` (动态重定位表) 中的信息，修改 `libc.so` 中需要修正的地址，使其指向正确的内存位置。
4. **绑定:**  一旦符号被解析和重定位，应用程序就可以通过 GOT (全局偏移量表) 或 PLT (过程链接表) 调用 `libc.so` 中的函数。

**假设输入与输出 (逻辑推理示例):**

以 `TEST(inttypes, strtoimax_dec)` 为例：

* **假设输入:** 字符串 `"-18737357foobar12"`，基数 `10`。
* **预期输出:**  `strtoimax` 函数应该返回 `-18737357`，并且指针 `p` 应该指向字符串 `"foobar12"` 的起始位置。
* **逻辑推理:**  `strtoimax` 会跳过前导空白（没有），然后解析以十进制表示的数字部分 `-18737357`。遇到非数字字符 `f` 时停止解析。返回值是解析到的整数，`endptr` 指向停止解析的位置。

**用户或编程常见的使用错误举例说明:**

1. **`printf` 和 `scanf` 格式说明符错误:**
   ```c
   int num = 123;
   printf("%s", num); // 错误：期望字符串，但提供了整数
   ```
   这将导致未定义的行为，可能崩溃或输出错误的信息。

2. **`scanf` 缓冲区溢出:**
   ```c
   char buffer[10];
   scanf("%s", buffer); // 如果输入超过 9 个字符，会发生缓冲区溢出
   ```
   应该使用限制长度的格式说明符，如 `scanf("%9s", buffer);`。

3. **`strtoimax` 等函数基数错误:**
   ```c
   char *endptr;
   strtoimax("10", &endptr, 1); // 错误：基数必须在 2 到 36 之间
   ```
   这将导致 `errno` 被设置为 `EINVAL`，返回值可能未定义。

4. **未检查 `strtoimax` 等函数的返回值和 `errno`:**
   ```c
   char *endptr;
   intmax_t num = strtoimax("invalid", &endptr, 10);
   // 应该检查 num 的值和 errno，以确定转换是否成功
   ```
   如果转换失败，返回值可能是 0 或其他值，`errno` 会被设置。

**Android framework 或 NDK 如何一步步到达这里**

**Android Framework 到 libc 的路径 (以 `printf` 为例):**

1. **Java 代码调用:** Android Framework 中的 Java 代码，例如 `android.util.Log.d()`，最终会调用到 native 代码。
2. **JNI 调用:**  `Log.d()` 的 native 实现会通过 JNI (Java Native Interface) 调用到 C/C++ 代码。
3. **libc 函数调用:**  在 native 代码中，可能会使用 `printf` 或相关的格式化输出函数将日志信息输出到 logcat。
   ```c++
   // 示例 (简化)
   #include <android/log.h>
   #include <stdio.h>

   void nativeLog(const char* tag, const char* message) {
       printf("[%s] %s\n", tag, message);
       __android_log_print(ANDROID_LOG_DEBUG, tag, "%s", message); // __android_log_print 内部也可能使用格式化输出
   }
   ```
4. **`printf` 实现:**  最终，对 `printf` 的调用会进入 `libc.so` 中 `printf` 函数的实现。

**NDK 到 libc 的路径:**

1. **NDK 代码直接调用:** 使用 NDK 开发的应用程序可以直接调用 `<stdio.h>` 或其他 Bionic 库中的头文件提供的函数。
   ```c++
   #include <stdio.h>
   #include <inttypes.h>

   void processNumber(int32_t value) {
       printf("The value is: %" PRId32 "\n", value);
   }
   ```
2. **编译和链接:** NDK 编译器会将代码编译成包含对 `libc.so` 中函数的调用的机器码。链接器会将应用程序与所需的 Bionic 库链接起来。
3. **运行时加载和调用:** 当应用程序运行时，dynamic linker 会加载 `libc.so`，并将应用程序中对 `printf` 的调用链接到 `libc.so` 中 `printf` 的实现。

**Frida Hook 示例调试步骤**

假设我们想 hook `strtoimax` 函数来观察它的输入和输出。

**Frida Hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Module.findExportByName(null, "libc.so");
  if (libc) {
    const strtoimax = Module.findExportByName(libc.name, "strtoimax");

    if (strtoimax) {
      Interceptor.attach(strtoimax, {
        onEnter: function (args) {
          const nptr = args[0];
          const base = args[2].toInt32();
          const str = Memory.readUtf8String(nptr);
          console.log(`[strtoimax] Input string: "${str}", base: ${base}`);
        },
        onLeave: function (retval) {
          console.log(`[strtoimax] Return value: ${retval}`);
        }
      });
      console.log("Hooked strtoimax");
    } else {
      console.log("strtoimax not found in libc");
    }
  } else {
    console.log("libc.so not found");
  }
} else {
  console.log("This script is for Android");
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 和 frida-server。
2. **启动目标应用:** 运行你想要调试的 Android 应用程序。
3. **运行 Frida 脚本:**
   ```bash
   frida -U -f <your_package_name> -l your_frida_script.js --no-pause
   ```
   或者，如果应用已经在运行：
   ```bash
   frida -U <your_package_name> -l your_frida_script.js
   ```
   将 `<your_package_name>` 替换为目标应用程序的包名，`your_frida_script.js` 替换为你的 Frida 脚本文件名。
4. **观察输出:** 当目标应用程序中调用 `strtoimax` 函数时，Frida 会拦截调用，执行 `onEnter` 和 `onLeave` 中的代码，并将输入参数和返回值打印到控制台。

通过这种方式，你可以动态地观察 `strtoimax` 函数的行为，例如它接收到的字符串和基数，以及返回的整数值。这对于理解代码执行流程和调试问题非常有帮助。

希望以上详细的解释能够帮助你理解 `bionic/tests/inttypes_test.cpp` 文件的功能及其在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/inttypes_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```cpp
/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <inttypes.h>

#include <errno.h>
#include <gtest/gtest.h>
#include <stdio.h>

#include "utils.h"

#define PRINTF_TYPED(FMT_SUFFIX, TYPE_SUFFIX) \
  do { \
    char buf[512]; \
    memset(buf, 0, sizeof(buf)); \
    snprintf(buf, sizeof(buf), "%" PRId##FMT_SUFFIX, int##TYPE_SUFFIX(123)); \
    EXPECT_STREQ("123", buf); \
    memset(buf, 0, sizeof(buf)); \
    snprintf(buf, sizeof(buf), "%" PRIi##FMT_SUFFIX, int##TYPE_SUFFIX(123)); \
    EXPECT_STREQ("123", buf); \
    memset(buf, 0, sizeof(buf)); \
    snprintf(buf, sizeof(buf), "%" PRIo##FMT_SUFFIX, int##TYPE_SUFFIX(123)); \
    EXPECT_STREQ("173", buf); \
    memset(buf, 0, sizeof(buf)); \
    snprintf(buf, sizeof(buf), "%" PRIu##FMT_SUFFIX, uint##TYPE_SUFFIX(123)); \
    EXPECT_STREQ("123", buf); \
    memset(buf, 0, sizeof(buf)); \
    snprintf(buf, sizeof(buf), "%" PRIx##FMT_SUFFIX, uint##TYPE_SUFFIX(123)); \
    EXPECT_STREQ("7b", buf); \
    memset(buf, 0, sizeof(buf)); \
    snprintf(buf, sizeof(buf), "%" PRIX##FMT_SUFFIX, uint##TYPE_SUFFIX(123)); \
    EXPECT_STREQ("7B", buf); \
  } while (false) \

#define PRINTF_SIZED(WIDTH) \
  PRINTF_TYPED(WIDTH, WIDTH##_t); \
  PRINTF_TYPED(FAST##WIDTH, _fast##WIDTH##_t); \
  PRINTF_TYPED(LEAST##WIDTH, _least##WIDTH##_t) \


#define SCANF_TYPED(FMT_SUFFIX, TYPE_SUFFIX) \
  do { \
    int##TYPE_SUFFIX dst_int##TYPE_SUFFIX = 0; \
    uint##TYPE_SUFFIX dst_uint##TYPE_SUFFIX = 0u; \
    \
    sscanf("123", "%" SCNd##FMT_SUFFIX, &dst_int##TYPE_SUFFIX); \
    EXPECT_EQ(123, dst_int##TYPE_SUFFIX); \
    dst_int##TYPE_SUFFIX = 0; \
    sscanf("123", "%" SCNi##FMT_SUFFIX, &dst_int##TYPE_SUFFIX); \
    EXPECT_EQ(123, dst_int##TYPE_SUFFIX); \
    dst_int##TYPE_SUFFIX = 0; \
    sscanf("173", "%" SCNo##FMT_SUFFIX, &dst_int##TYPE_SUFFIX); \
    EXPECT_EQ(123, dst_int##TYPE_SUFFIX); \
    dst_int##TYPE_SUFFIX = 0; \
    sscanf("123", "%" SCNu##FMT_SUFFIX, &dst_uint##TYPE_SUFFIX); \
    EXPECT_EQ(123u, dst_uint##TYPE_SUFFIX); \
    dst_uint##TYPE_SUFFIX = 0; \
    sscanf("7B", "%" SCNx##FMT_SUFFIX, &dst_uint##TYPE_SUFFIX); \
    EXPECT_EQ(123u, dst_uint##TYPE_SUFFIX); \
    dst_uint##TYPE_SUFFIX = 0; \
  } while (false) \

#define SCANF_SIZED(SIZE) \
  SCANF_TYPED(SIZE, SIZE##_t); \
  SCANF_TYPED(FAST##SIZE, _fast##SIZE##_t); \
  SCANF_TYPED(LEAST##SIZE, _least##SIZE##_t) \


TEST(inttypes, printf_macros) {
  PRINTF_SIZED(8);
  PRINTF_SIZED(16);
  PRINTF_SIZED(32);
  PRINTF_SIZED(64);

  PRINTF_TYPED(MAX, max_t);
  PRINTF_TYPED(PTR, ptr_t);
}

TEST(inttypes, scanf_macros) {
  SCANF_SIZED(8);
  SCANF_SIZED(16);
  SCANF_SIZED(32);
  SCANF_SIZED(64);

  SCANF_TYPED(MAX, max_t);
  SCANF_TYPED(PTR, ptr_t);
}

TEST(inttypes, wcstoimax) {
  wchar_t* end = nullptr;
  EXPECT_EQ(123, wcstoimax(L"  +123x", &end, 10));
  EXPECT_EQ(L'x', *end);
}

TEST(inttypes, wcstoumax) {
  wchar_t* end = nullptr;
  EXPECT_EQ(123U, wcstoumax(L"  +123x", &end, 10));
  EXPECT_EQ(L'x', *end);
}

TEST(inttypes, strtoimax_dec) {
  char* p;
  EXPECT_EQ(-18737357, strtoimax("-18737357foobar12", &p, 10));
  EXPECT_STREQ("foobar12", p);
}

TEST(inttypes, strtoimax_hex) {
  char* p;
  EXPECT_EQ(-0x18737357f, strtoimax("-18737357foobar12", &p, 16));
  EXPECT_STREQ("oobar12", p);
}

TEST(inttypes, strtoimax_EINVAL) {
  errno = 0;
  strtoimax("123", nullptr, -1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  strtoimax("123", nullptr, 1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  strtoimax("123", nullptr, 37);
  ASSERT_ERRNO(EINVAL);
}

TEST(inttypes, strtoumax_dec) {
  char* p;
  EXPECT_EQ(18737357U, strtoumax("18737357foobar12", &p, 10));
  EXPECT_STREQ("foobar12", p);
}

TEST(inttypes, strtoumax_hex) {
  char* p;
  EXPECT_EQ(0x18737357fU, strtoumax("18737357foobar12", &p, 16));
  EXPECT_STREQ("oobar12", p);
}

TEST(inttypes, strtoumax_negative) {
  char* p;
  EXPECT_EQ(UINTMAX_MAX - 18737357 + 1, strtoumax("-18737357foobar12", &p, 10));
  EXPECT_STREQ("foobar12", p);
}

TEST(inttypes, strtoumax_EINVAL) {
  errno = 0;
  strtoumax("123", nullptr, -1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  strtoumax("123", nullptr, 1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  strtoumax("123", nullptr, 37);
  ASSERT_ERRNO(EINVAL);
}

TEST(inttypes, wcstoimax_EINVAL) {
  errno = 0;
  wcstoimax(L"123", nullptr, -1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoimax(L"123", nullptr, 1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoimax(L"123", nullptr, 37);
  ASSERT_ERRNO(EINVAL);
}

TEST(inttypes, wcstoumax_EINVAL) {
  errno = 0;
  wcstoumax(L"123", nullptr, -1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoumax(L"123", nullptr, 1);
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  wcstoumax(L"123", nullptr, 37);
  ASSERT_ERRNO(EINVAL);
}

TEST(inttypes, div) {
  div_t r;

  r = div(5, 3);
  EXPECT_EQ(1, r.quot);
  EXPECT_EQ(2, r.rem);

  r = div(5, -3);
  EXPECT_EQ(-1, r.quot);
  EXPECT_EQ(2, r.rem);

  r = div(-5, 3);
  EXPECT_EQ(-1, r.quot);
  EXPECT_EQ(-2, r.rem);

  r = div(-5, -3);
  EXPECT_EQ(1, r.quot);
  EXPECT_EQ(-2, r.rem);
}

TEST(inttypes, ldiv) {
  ldiv_t r;

  r = ldiv(5, 3);
  EXPECT_EQ(1, r.quot);
  EXPECT_EQ(2, r.rem);

  r = ldiv(5, -3);
  EXPECT_EQ(-1, r.quot);
  EXPECT_EQ(2, r.rem);

  r = ldiv(-5, 3);
  EXPECT_EQ(-1, r.quot);
  EXPECT_EQ(-2, r.rem);

  r = ldiv(-5, -3);
  EXPECT_EQ(1, r.quot);
  EXPECT_EQ(-2, r.rem);
}

TEST(inttypes, lldiv) {
  lldiv_t r;

  r = lldiv(5, 3);
  EXPECT_EQ(1, r.quot);
  EXPECT_EQ(2, r.rem);

  r = lldiv(5, -3);
  EXPECT_EQ(-1, r.quot);
  EXPECT_EQ(2, r.rem);

  r = lldiv(-5, 3);
  EXPECT_EQ(-1, r.quot);
  EXPECT_EQ(-2, r.rem);

  r = lldiv(-5, -3);
  EXPECT_EQ(1, r.quot);
  EXPECT_EQ(-2, r.rem);
}

TEST(inttypes, imaxdiv) {
  imaxdiv_t r;

  r = imaxdiv(5, 3);
  EXPECT_EQ(1, r.quot);
  EXPECT_EQ(2, r.rem);

  r = imaxdiv(5, -3);
  EXPECT_EQ(-1, r.quot);
  EXPECT_EQ(2, r.rem);

  r = imaxdiv(-5, 3);
  EXPECT_EQ(-1, r.quot);
  EXPECT_EQ(-2, r.rem);

  r = imaxdiv(-5, -3);
  EXPECT_EQ(1, r.quot);
  EXPECT_EQ(-2, r.rem);
}

TEST(inttypes, imaxabs) {
  EXPECT_EQ(672423489, imaxabs(672423489));
  EXPECT_EQ(672423489, imaxabs(-672423489));
  EXPECT_EQ(INTMAX_MAX, imaxabs(-INTMAX_MAX));
  EXPECT_EQ(INTMAX_MAX, imaxabs(INTMAX_MAX));
}
```