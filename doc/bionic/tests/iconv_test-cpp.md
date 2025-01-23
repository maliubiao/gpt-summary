Response:
Let's break down the thought process for generating the comprehensive answer to the user's request.

**1. Understanding the Core Request:**

The user provided a C++ source file (`iconv_test.cpp`) from Android's Bionic library and asked for a detailed explanation of its functionality, its relation to Android, how the underlying `libc` functions work, details about dynamic linking if applicable, common usage errors, and how to trace its execution.

**2. Initial Analysis of the Source Code:**

The first step was to skim the code and identify the key components:

* **Includes:** `<gtest/gtest.h>`, `<iconv.h>`, `"utils.h"`. This immediately tells us it's a unit test file for the `iconv` functionality. `iconv.h` is the crucial header defining the `iconv_*` functions. `gtest` indicates it uses Google Test framework.
* **Test Fixtures:**  The code is organized into `TEST` macros, which are the core of Google Test. Each test function focuses on a specific aspect of `iconv`.
* **Key Functions Under Test:**  `iconv_open`, `iconv`, `iconv_close`. These are the central functions of the `iconv` API.
* **Error Handling:** The tests heavily rely on `ASSERT_EQ`, `ASSERT_NE`, `ASSERT_ERRNO`, `EXPECT_EQ`, etc., to verify expected behavior and error codes (like `EINVAL`, `EILSEQ`, `E2BIG`, `EBADF`).
* **Specific Test Cases:**  The names of the test cases provide clues about what aspects are being tested: invalid arguments to `iconv_open`, character set alias matching, basic conversion, handling lossy conversions (`//TRANSLIT`, `//IGNORE`), malformed and incomplete sequences, buffer overflow (`E2BIG`), and round-trip conversions.
* **Helper Functions:** `RoundTrip` and `Check` are used to simplify repetitive test scenarios.

**3. Deconstructing the Request - Mapping to Code:**

Next, I mapped each part of the user's request to the code:

* **Functionality:** This requires analyzing what each test case is doing. The tests cover opening converters, performing conversions between different encodings, handling errors, and testing different conversion flags (`//TRANSLIT`, `//IGNORE`).
* **Relationship to Android:**  Since this is in Bionic, it's a core part of Android's C library. The `iconv` functionality is used for internationalization (i18n) and handling different character encodings, crucial for supporting global languages. Examples would involve text input, display, and network communication.
* **`libc` Function Implementation:**  This required explaining how `iconv_open`, `iconv`, and `iconv_close` likely work internally, including the role of the dynamic linker for loading encoding data. I focused on conceptual explanations, as the actual implementation details are complex and platform-specific.
* **Dynamic Linker:** The `iconv` implementation likely relies on dynamically loaded data files for different encodings. This needs explanation, including a hypothetical `.so` structure and the linking process.
* **Logical Reasoning (Assumptions/Input/Output):**  Many test cases provide implicit examples. I needed to extract these and make them explicit, for instance, showing how converting "a٦ᄀ" from UTF-8 to UTF-32LE results in specific byte sequences.
* **Common Usage Errors:** I looked for patterns in the test cases that expose potential errors, such as providing invalid encoding names, insufficient output buffer sizes, and mishandling malformed input.
* **Android Framework/NDK and Frida Hooking:**  This required tracing the path from a higher-level Android component (like a TextView) down to the Bionic `iconv` functions and providing a practical example of how to intercept these calls using Frida.

**4. Structuring the Answer:**

I decided to structure the answer logically, addressing each part of the user's request in turn:

* **Overall Functionality:** Start with a high-level summary of the file's purpose.
* **Detailed Functionality (Test by Test):** Go through each `TEST` case and explain what it's verifying.
* **Relationship to Android:** Explain the role of `iconv` in the Android ecosystem.
* **`libc` Function Explanations:** Detail the implementation of `iconv_open`, `iconv`, and `iconv_close`.
* **Dynamic Linker Details:** Explain the dynamic loading of encoding data and provide a sample `.so` layout.
* **Logical Reasoning Examples:** Extract and present clear input/output examples from the test cases.
* **Common Usage Errors:** Provide practical scenarios where developers might misuse the `iconv` functions.
* **Android Framework/NDK Path:** Explain how `iconv` is called from higher levels.
* **Frida Hook Example:** Provide a concrete Frida script for intercepting `iconv_open`.

**5. Adding Detail and Specificity:**

For each section, I tried to provide as much detail as possible, drawing directly from the code and general knowledge of character encoding and system libraries. For example:

* When explaining `iconv_open`, I mentioned the role of the system in finding the appropriate conversion routines.
* When discussing `iconv`, I described how it handles input and output pointers, buffer sizes, and error conditions.
* For the dynamic linker, I provided a plausible directory structure and explained the steps involved in loading the `.so` file.
* For Frida, I included the necessary JavaScript code and explained how to use it.

**6. Refinement and Language:**

Finally, I reviewed the entire answer for clarity, accuracy, and completeness. I used precise language and avoided jargon where possible. I ensured the answer was in Chinese, as requested.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe focus heavily on the `gtest` framework. **Correction:** Realized the core request was about `iconv`, so shifted focus there while still acknowledging the testing framework.
* **Initial thought:**  Dive deep into the exact Bionic implementation details. **Correction:**  Recognized that the user likely needs a higher-level understanding, as the exact implementation can be complex and change. Focused on general principles and conceptual explanations.
* **Initial thought:** Provide a very technical explanation of dynamic linking. **Correction:** Simplified the explanation to be understandable to a broader audience while still conveying the key concepts.
* **Initial thought:** Just list the errors. **Correction:** Provided illustrative examples of how these errors might occur in practice.

By following these steps, combining code analysis, domain knowledge, and a structured approach, I was able to generate a comprehensive and helpful answer to the user's detailed request.
这个文件 `bionic/tests/iconv_test.cpp` 是 Android Bionic 库中 `iconv` 接口的单元测试文件。它的主要功能是**验证 `iconv` 相关的 API (如 `iconv_open`, `iconv`, `iconv_close`) 在各种场景下的正确性**。

让我们详细列举一下它的功能，并结合 Android 的功能进行说明：

**1. 功能列举:**

* **测试 `iconv_open` 函数:**
    * **无效参数测试 (EINVAL):**  测试当传递无效的 `tocode` 或 `fromcode` 时，`iconv_open` 是否返回 `INVALID_ICONV_T` 并设置 `errno` 为 `EINVAL`。这保证了 `iconv_open` 能正确处理错误的输入。
    * **字符集别名比较器测试:**  测试 `iconv_open` 是否能正确识别和匹配字符集别名，例如 "UTF-8", "utf8", "u.t.f-008" 应该被认为是相同的编码，而 "utf-80" 或 "ut80" 不应该被匹配。这符合 Unicode 联盟的建议，提高了字符集名称的灵活性。
* **测试 `iconv` 函数:**
    * **基本转换测试 (Smoke Test):** 测试 `iconv` 能否将 UTF-8 编码的字符串正确转换为 UTF-32LE 编码。这是一个最基本的功能验证。
    * **有损转换测试:**
        * **`//TRANSLIT` 标志:** 测试当目标编码无法表示源编码中的字符时，使用 `//TRANSLIT` 标志进行转写（通常替换为 `?`）的功能是否正常。
        * **`//IGNORE` 标志:** 测试当目标编码无法表示源编码中的字符时，使用 `//IGNORE` 标志忽略这些字符的功能是否正常。
        * **无标志的情况:** 测试当目标编码无法表示源编码中的字符时，`iconv` 返回错误 (`EILSEQ`) 并停止转换的功能。
    * **处理错误序列测试:**
        * **畸形序列 (Malformed Sequence - EILSEQ):** 测试当输入字符串包含无效的字符编码序列时，`iconv` 是否返回错误 (`EILSEQ`) 并将输入指针指向错误序列的开始。
        * **不完整序列 (Incomplete Sequence - EINVAL):** 测试当输入字符串的结尾包含一个不完整的字符编码序列时，`iconv` 是否返回错误 (`EINVAL`)。
    * **输出缓冲区不足测试 (E2BIG):** 测试当提供的输出缓冲区太小时，`iconv` 是否返回错误 (`E2BIG`) 并更新输入和输出指针和大小。
    * **无效转换描述符测试 (EBADF):** 测试当传递无效的 `iconv_t` 到 `iconv` 函数时，是否返回错误 (`EBADF`)。
* **测试 `iconv_close` 函数:**
    * **无效转换描述符测试 (EBADF):** 测试当传递无效的 `iconv_t` 到 `iconv_close` 函数时，是否返回错误 (`EBADF`)。
* **往返转换测试 (Round Trip):**  测试将 UTF-8 编码的字符串转换为其他编码，然后再转回 UTF-8 编码，结果是否与原始字符串一致。这验证了编码转换的可逆性。测试了 ASCII, UTF-8, UTF-16BE, UTF-16LE, UTF-32BE, UTF-32LE 和 `wchar_t` 等编码。
* **错误场景检查:** 使用 `Check` 函数检查各种编码中出现的特定错误情况，例如：
    * ASCII 编码中出现非 ASCII 字符 (`EILSEQ`).
    * UTF-8 编码中出现无效的起始字节或后续字节 (`EILSEQ`).
    * UTF-16 编码中出现低位代理项先于高位代理项 (`EILSEQ`).
    * UTF 编码中出现不完整的字节序列 (`EINVAL`).
* **初始移位状态测试:** 测试对于有状态编码，当 `inbuf` 为空指针时，`iconv` 是否会将转换描述符置于初始移位状态。

**2. 与 Android 功能的关系及举例说明:**

`iconv` 是一个标准的 POSIX 函数，用于字符编码转换。在 Android 中，它被广泛用于处理不同编码的文本数据。以下是一些例子：

* **文本显示:** Android 系统和应用程序需要处理各种语言的文本，这些文本可能使用不同的字符编码（例如，UTF-8, GBK, ISO-8859-1 等）。当从网络、文件或其他来源获取文本数据时，可能需要使用 `iconv` 将其转换为 Android 内部使用的 UTF-8 编码，以便正确显示在屏幕上。例如，一个从使用 GBK 编码的服务器下载网页的浏览器应用，就需要使用 `iconv` 将网页内容转换为 UTF-8 后再渲染。
* **文本输入:**  当用户在键盘上输入字符时，输入法可能会使用特定的编码。应用程序可能需要使用 `iconv` 将输入法提供的编码转换为 UTF-8 或其他需要的编码进行处理和存储。
* **文件读写:**  应用程序在读取或写入文本文件时，可能需要指定文件的编码格式。`iconv` 可以用于在应用程序内部编码和文件编码之间进行转换。例如，一个文本编辑器应用可以允许用户以不同的编码保存文件。
* **网络通信:**  网络协议和数据交换格式可能使用不同的字符编码。应用程序在发送或接收文本数据时，可能需要使用 `iconv` 进行编码转换，以确保数据的正确传输和解析。例如，HTTP 协议的 `Content-Type` 头部可以指定字符编码，浏览器需要根据这个编码来解析服务器返回的文本内容。
* **NDK 开发:**  Native 开发人员可以使用 NDK 调用 Bionic 提供的 `iconv` 函数，以便在 C/C++ 代码中处理字符编码转换。例如，一个使用 C++ 编写的网络库可能需要使用 `iconv` 来处理不同编码的 HTTP 响应。

**3. libc 函数功能实现解释:**

`iconv` 系列函数的具体实现细节在不同的操作系统和 C 库中可能有所不同，但其基本原理如下：

* **`iconv_open(const char *tocode, const char *fromcode)`:**
    * **功能:** 初始化一个字符编码转换描述符。
    * **实现:**
        1. 接收目标编码 (`tocode`) 和源编码 (`fromcode`) 的字符串参数。
        2. 在系统中查找支持这两种编码之间转换的转换例程。这通常涉及到查找预编译的编码转换表或算法。
        3. 如果找到合适的转换例程，则分配一个 `iconv_t` 类型的结构体，用于存储转换状态信息（例如，转换过程中可能需要的状态）。
        4. 初始化该结构体，例如设置初始转换状态。
        5. 返回指向该结构体的指针（类型转换为 `iconv_t`）。
        6. 如果找不到支持的转换，则返回 `INVALID_ICONV_T` (通常是 `(iconv_t)-1`) 并设置全局变量 `errno` 为 `EINVAL`。
* **`iconv(iconv_t cd, char **inbuf, size_t *inbytesleft, char **outbuf, size_t *outbytesleft)`:**
    * **功能:** 执行字符编码转换。
    * **实现:**
        1. 接收由 `iconv_open` 返回的转换描述符 `cd`。
        2. `inbuf`: 指向输入缓冲区的指针的指针。函数会修改这个指针，使其指向尚未转换的输入数据的起始位置。
        3. `inbytesleft`: 指向输入缓冲区剩余字节数的指针。函数会更新这个值，表示已处理的输入字节数。
        4. `outbuf`: 指向输出缓冲区的指针的指针。函数会修改这个指针，使其指向已写入的输出数据的末尾位置之后。
        5. `outbytesleft`: 指向输出缓冲区剩余字节数的指针。函数会更新这个值，表示输出缓冲区剩余的空间。
        6. 根据转换描述符 `cd` 中存储的编码转换信息，从 `*inbuf` 读取数据，并将其转换为目标编码，写入到 `*outbuf`。
        7. **错误处理:**
            * **`EILSEQ` (非法字节序列):** 当输入缓冲区中遇到无法识别或不合法的字节序列时，停止转换，返回 `(size_t)-1`，设置 `errno` 为 `EILSEQ`，并将 `*inbuf` 指向错误序列的开始。
            * **`EINVAL` (不完整的多字节序列):** 当输入缓冲区以一个不完整的多字节序列结尾时，停止转换，返回 `(size_t)-1`，设置 `errno` 为 `EINVAL`。
            * **`E2BIG` (输出缓冲区空间不足):** 当输出缓冲区没有足够的空间来存放转换后的字符时，停止转换，返回 `(size_t)-1`，设置 `errno` 为 `E2BIG`。函数会尽可能多地转换数据。
        8. 如果成功完成转换（或遇到上述错误），则更新 `*inbuf`, `*inbytesleft`, `*outbuf`, `*outbytesleft`。
        9. 返回已执行的非可逆转换的次数。如果未发生错误，则返回 0。
* **`iconv_close(iconv_t cd)`:**
    * **功能:** 释放由 `iconv_open` 分配的转换描述符。
    * **实现:**
        1. 接收转换描述符 `cd`。
        2. 释放与该描述符关联的内存和资源。
        3. 返回 0 表示成功，返回 -1 并设置 `errno` 为 `EBADF` 表示 `cd` 是无效的转换描述符。

**4. 涉及 dynamic linker 的功能及 so 布局样本和链接处理过程:**

虽然 `iconv_open`, `iconv`, `iconv_close` 本身是 `libc` 提供的函数，但它们的实现可能依赖于动态链接的其他库或数据文件来支持不同的字符编码。

**假设 `iconv` 的实现使用了动态链接加载编码转换表/例程:**

**so 布局样本:**

```
/system/lib64/libc.so        # Bionic C 库，包含 iconv_open, iconv, iconv_close 等基本实现
/system/lib64/libiconv_modules.so  # 假设包含各种编码转换模块的共享库

# 假设 libiconv_modules.so 的内部结构可能如下：
# libiconv_modules.so
#   |-- encoding_utf8.o         # UTF-8 相关的转换例程
#   |-- encoding_gbk.o          # GBK 相关的转换例程
#   |-- encoding_iso88591.o    # ISO-8859-1 相关的转换例程
#   |-- ... 其他编码的转换例程 ...
```

**链接处理过程:**

1. **`iconv_open("UTF-8", "GBK")` 调用:**
2. `libc.so` 中的 `iconv_open` 实现被调用。
3. `iconv_open` 内部可能需要找到 "UTF-8" 到 "GBK" 的转换例程。
4. 它可能会检查内部缓存或配置文件，如果没有找到，则可能触发动态链接器 (e.g., `linker64` on Android) 加载包含编码转换模块的共享库，例如 `libiconv_modules.so`。
5. 动态链接器会搜索预定义的路径（例如 `/system/lib64`, `/vendor/lib64` 等）来查找 `libiconv_modules.so`。
6. 加载 `libiconv_modules.so` 后，`iconv_open` 可能会查找其中注册的编码转换例程。一种方式是使用预定义的命名规则或一个查找表。例如，可能存在一个函数或数据结构，用于将编码名称映射到实际的转换函数。
7. 找到 "UTF-8" 到 "GBK" 的转换例程后，`iconv_open` 会分配并初始化 `iconv_t` 结构体，并将指向该转换例程的指针存储在其中。
8. 返回 `iconv_t` 描述符。

**注意:** 实际的 Bionic `iconv` 实现可能并不像上述例子那样完全依赖独立的 `.so` 文件来加载所有编码。它可能会将一些常见的编码转换直接编译到 `libc.so` 中，或者使用其他机制来管理编码转换。上述只是一个为了解释动态链接概念的假设性例子。

**5. 逻辑推理的假设输入与输出:**

* **假设输入:**  `iconv_open("UTF-16BE", "UTF-8")` 和 UTF-8 字符串 "你好" (字节序列: `0xE4 0xBD 0xA0 0xE5 0xA5 0xBD`)。
* **逻辑推理:** `iconv` 函数会将 UTF-8 编码的 "你好" 转换为 UTF-16BE 编码。UTF-8 的 "你" (`0xE4 0xBD 0xA0`) 对应的 UTF-16BE 是 `0x4F 0x60`，UTF-8 的 "好" (`0xE5 0xA5 0xBD`) 对应的 UTF-16BE 是 `0x59 0x7D`。
* **预期输出:**  输出缓冲区将包含字节序列 `0x4F 0x60 0x59 0x7D`。

* **假设输入:** `iconv_open("ASCII", "UTF-8")` 和 UTF-8 字符串 "你好"。
* **逻辑推理:**  由于 "你" 和 "好" 无法用 ASCII 编码表示，`iconv` 在没有 `//IGNORE` 或 `//TRANSLIT` 标志的情况下会遇到错误。
* **预期输出:** `iconv` 返回 `(size_t)-1`，`errno` 被设置为 `EILSEQ`。

**6. 用户或编程常见的使用错误:**

* **忘记检查 `iconv_open` 的返回值:**  如果 `iconv_open` 失败，它会返回 `INVALID_ICONV_T`。如果不检查返回值就直接传递给 `iconv` 或 `iconv_close`，会导致程序崩溃或未定义的行为 (`EBADF` 错误)。
    ```c++
    iconv_t cd = iconv_open("INVALID-ENCODING", "UTF-8");
    // 忘记检查 cd 是否为 INVALID_ICONV_T
    char in[] = "test";
    size_t in_bytes = strlen(in);
    char out[100];
    size_t out_bytes = sizeof(out);
    iconv(cd, &in, &in_bytes, &out, &out_bytes); // 可能会崩溃
    ```
* **输出缓冲区太小:**  提供的输出缓冲区不足以存放转换后的字符串，导致 `iconv` 返回 `E2BIG`。
    ```c++
    iconv_t cd = iconv_open("UTF-16", "UTF-8");
    char utf8_str[] = "你好";
    char utf16_buf[3]; // 缓冲区太小，无法容纳 "你好" 的 UTF-16 编码
    size_t in_bytes = strlen(utf8_str);
    size_t out_bytes = sizeof(utf16_buf);
    char *in = utf8_str;
    char *out = utf16_buf;
    errno = 0;
    iconv(cd, &in, &in_bytes, &out, &out_bytes);
    if (errno == E2BIG) {
        // 需要处理缓冲区不足的情况
    }
    iconv_close(cd);
    ```
* **没有正确处理 `iconv` 的返回值和 `errno`:**  `iconv` 返回值 `-1` 表示发生错误，需要检查 `errno` 来确定具体的错误类型 (`EILSEQ`, `EINVAL`, `E2BIG`) 并进行相应的处理。
* **在循环调用 `iconv` 时没有正确更新 `inbuf`, `inbytesleft`, `outbuf`, `outbytesleft`:** 这些指针和大小需要根据每次调用的结果进行更新，以便下一次调用能正确处理剩余的数据。
* **混淆字符编码名称:**  使用了错误的或不支持的字符编码名称，导致 `iconv_open` 失败。

**7. Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤。**

**Android Framework 到 `iconv` 的路径：**

1. **应用层 (Java/Kotlin):**  应用程序可能需要处理不同编码的文本数据。例如，一个浏览器应用接收到服务器返回的非 UTF-8 编码的网页内容。
2. **Android Framework (Java):**  Android Framework 提供了 `java.nio.charset` 包来进行字符编码转换。例如，可以使用 `Charset.forName("GBK").decode(ByteBuffer)` 将 GBK 编码的字节流解码为 Java `String`。
3. **Native Bridge:**  `java.nio.charset` 的底层实现通常会调用 Native 代码。例如，`CharsetEncoder` 和 `CharsetDecoder` 的某些实现会调用 JNI 方法。
4. **NDK Libraries:**  这些 JNI 方法可能会调用 Android 系统库，例如 `libicuuc.so` (International Components for Unicode)。 ICU 是一个广泛使用的国际化库。
5. **Bionic `iconv`:**  `libicuuc.so` 内部可能会使用 Bionic 提供的 `iconv` 函数来实现某些字符编码转换。这是一种优化的方式，可以直接利用系统底层的 `iconv` 实现。

**NDK 开发到 `iconv` 的路径：**

1. **NDK 代码 (C/C++):**  Native 开发人员可以直接在 C/C++ 代码中包含 `<iconv.h>` 头文件并调用 `iconv_open`, `iconv`, `iconv_close` 函数。
2. **Bionic `libc.so`:**  这些函数直接链接到 Bionic 的 `libc.so` 库中。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `iconv_open` 调用的示例，可以用来调试从 Android Framework 或 NDK 到 `iconv` 的调用过程。

```javascript
if (Process.platform === 'android') {
  const iconv_open = Module.findExportByName("libc.so", "iconv_open");
  if (iconv_open) {
    Interceptor.attach(iconv_open, {
      onEnter: function (args) {
        const tocode = Memory.readCString(args[0]);
        const fromcode = Memory.readCString(args[1]);
        console.log(`iconv_open called with tocode: ${tocode}, fromcode: ${fromcode}`);
        // 可以打印调用栈，查看调用来源
        // console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\\n'));
      },
      onLeave: function (retval) {
        console.log(`iconv_open returned: ${retval}`);
      }
    });
  } else {
    console.log("Could not find iconv_open in libc.so");
  }
} else {
  console.log("This script is for Android only.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_iconv.js`).
2. 使用 Frida 连接到 Android 设备或模拟器上的目标进程。
3. 运行 Frida 命令加载脚本：
   ```bash
   frida -U -f <package_name> -l hook_iconv.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <process_name_or_pid> -l hook_iconv.js
   ```

**调试步骤:**

1. 运行包含字符编码转换操作的 Android 应用或执行 NDK 代码。
2. Frida 会拦截对 `iconv_open` 的调用，并在控制台输出 `tocode` 和 `fromcode` 参数，以及返回值。
3. 如果需要更详细的调用堆栈信息，可以取消注释 `onEnter` 中的 `console.log(Thread.backtrace(...))` 行。
4. 通过分析 Frida 的输出，可以追踪到哪些模块或代码路径调用了 `iconv_open`，从而了解 Android Framework 或 NDK 是如何一步步到达 Bionic 的 `iconv` 函数的。

这个 `iconv_test.cpp` 文件是确保 Android 系统能够正确处理各种字符编码的关键组成部分，它通过详尽的测试用例保证了 `iconv` API 的稳定性和可靠性。

### 提示词
```
这是目录为bionic/tests/iconv_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#include <iconv.h>

#include "utils.h"

#define INVALID_ICONV_T reinterpret_cast<iconv_t>(-1)

TEST(iconv, iconv_open_EINVAL) {
  errno = 0;
  ASSERT_EQ(INVALID_ICONV_T, iconv_open("silly", "silly"));
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  ASSERT_EQ(INVALID_ICONV_T, iconv_open("silly", "UTF-8"));
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  ASSERT_EQ(INVALID_ICONV_T, iconv_open("UTF-8", "silly"));
  ASSERT_ERRNO(EINVAL);
}

TEST(iconv, iconv_open_comparator) {
  // Examples from http://www.unicode.org/reports/tr22/#Charset_Alias_Matching:
  // "For example, the following names should match: "UTF-8", "utf8", "u.t.f-008", ..."
  iconv_t c;
  ASSERT_NE(INVALID_ICONV_T, c = iconv_open("UTF-8", "utf8"));
  ASSERT_EQ(0, iconv_close(c));
  ASSERT_NE(INVALID_ICONV_T, c = iconv_open("UTF-8", "u.t.f-008"));
  ASSERT_EQ(0, iconv_close(c));

  // "...but not "utf-80" or "ut8"."
  errno = 0;
  ASSERT_EQ(INVALID_ICONV_T, iconv_open("UTF-8", "utf-80"));
  ASSERT_ERRNO(EINVAL);
  errno = 0;
  ASSERT_EQ(INVALID_ICONV_T, iconv_open("UTF-8", "ut80"));
  ASSERT_ERRNO(EINVAL);
}

TEST(iconv, iconv_smoke) {
  const char* utf8 = "a٦ᄀ"; // U+0666 ٦ 0xd9 0xa6 // U+1100 ᄀ 0xe1 0x84 0x80
  char buf[BUFSIZ] = {};

  iconv_t c = iconv_open("UTF-32LE", "UTF-8");
  ASSERT_NE(INVALID_ICONV_T, c);

  char* in = const_cast<char*>(utf8);
  size_t in_bytes = strlen(in);

  char* out = buf;
  size_t out_bytes = sizeof(buf);

  EXPECT_EQ(0U, iconv(c, &in, &in_bytes, &out, &out_bytes));

  wchar_t* utf16 = reinterpret_cast<wchar_t*>(buf);
  EXPECT_EQ(L'a', utf16[0]);
  EXPECT_EQ(L'٦', utf16[1]);
  EXPECT_EQ(L'ᄀ', utf16[2]);
  EXPECT_EQ(L'\0', utf16[3]);
  EXPECT_EQ(0U, in_bytes);
  EXPECT_EQ(sizeof(buf) - (3 /* chars */ * 4 /* bytes each */), out_bytes);

  ASSERT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_lossy_TRANSLIT) {
  const char* utf8 = "a٦ᄀz"; // U+0666 ٦ 0xd9 0xa6 // U+1100 ᄀ 0xe1 0x84 0x80
  char buf[BUFSIZ] = {};

  iconv_t c = iconv_open("ASCII//TRANSLIT", "UTF-8");
  ASSERT_NE(INVALID_ICONV_T, c);

  char* in = const_cast<char*>(utf8);
  size_t in_bytes = strlen(in);

  char* out = buf;
  size_t out_bytes = sizeof(buf);

  // Two of the input characters (5 input bytes) aren't representable as ASCII.
  // With "//TRANSLIT", we use a replacement character, and report the number
  // of replacements.
  EXPECT_EQ(2U, iconv(c, &in, &in_bytes, &out, &out_bytes));

  EXPECT_EQ('a', buf[0]);
  EXPECT_EQ('?', buf[1]);
  EXPECT_EQ('?', buf[2]);
  EXPECT_EQ('z', buf[3]);
  EXPECT_EQ(0, buf[4]);
  EXPECT_EQ(0U, in_bytes);
  EXPECT_EQ(sizeof(buf) - 4, out_bytes);

  ASSERT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_lossy_IGNORE) {
  const char* utf8 = "a٦ᄀz"; // U+0666 ٦ 0xd9 0xa6 // U+1100 ᄀ 0xe1 0x84 0x80
  char buf[BUFSIZ] = {};

  iconv_t c = iconv_open("ASCII//IGNORE", "UTF-8");
  ASSERT_NE(INVALID_ICONV_T, c);

  char* in = const_cast<char*>(utf8);
  size_t in_bytes = strlen(in);

  char* out = buf;
  size_t out_bytes = sizeof(buf);

  // Two of the input characters (5 input bytes) aren't representable as ASCII.
  // With "//IGNORE", we just skip them (but return failure).
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(EILSEQ);

  EXPECT_EQ('a', buf[0]);
  EXPECT_EQ('z', buf[1]);
  EXPECT_EQ(0, buf[2]);
  EXPECT_EQ(0U, in_bytes);
  EXPECT_EQ(sizeof(buf) - 2, out_bytes);

  ASSERT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_lossy) {
  const char* utf8 = "a٦ᄀz"; // U+0666 ٦ 0xd9 0xa6 // U+1100 ᄀ 0xe1 0x84 0x80
  char buf[BUFSIZ] = {};

  iconv_t c = iconv_open("ASCII", "UTF-8");
  ASSERT_NE(INVALID_ICONV_T, c);

  char* in = const_cast<char*>(utf8);
  size_t in_bytes = strlen(in);

  char* out = buf;
  size_t out_bytes = sizeof(buf);

  // The second input character isn't representable as ASCII, so we stop there.
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(EILSEQ);

  EXPECT_EQ('a', buf[0]);
  EXPECT_EQ(0, buf[1]);
  EXPECT_EQ(6U, in_bytes); // Two bytes for ٦, three bytes for ᄀ, and one byte for z.
  EXPECT_EQ(sizeof(buf) - 1, out_bytes);

  ASSERT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_malformed_sequence_EILSEQ) {
  const char* utf8 = "a\xd9z"; // 0xd9 is the first byte of the two-byte U+0666 ٦.
  char buf[BUFSIZ] = {};

  iconv_t c = iconv_open("UTF-8", "UTF-8");
  ASSERT_NE(INVALID_ICONV_T, c);

  char* in = const_cast<char*>(utf8);
  size_t in_bytes = strlen(in);

  char* out = buf;
  size_t out_bytes = sizeof(buf);

  // The second input byte is a malformed character, so we stop there.
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(EILSEQ);
  EXPECT_EQ('\xd9', *in); // *in is left pointing to the start of the invalid sequence.
  ++in;
  --in_bytes;
  errno = 0;
  EXPECT_EQ(0U, iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(0);

  EXPECT_EQ('a', buf[0]);
  EXPECT_EQ('z', buf[1]);
  EXPECT_EQ(0, buf[2]);
  EXPECT_EQ(0U, in_bytes);
  EXPECT_EQ(sizeof(buf) - 2, out_bytes);

  ASSERT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_incomplete_sequence_EINVAL) {
  const char* utf8 = "a\xd9"; // 0xd9 is the first byte of the two-byte U+0666 ٦.
  char buf[BUFSIZ] = {};

  iconv_t c = iconv_open("UTF-8", "UTF-8");
  ASSERT_NE(INVALID_ICONV_T, c);

  char* in = const_cast<char*>(utf8);
  size_t in_bytes = strlen(in);

  char* out = buf;
  size_t out_bytes = sizeof(buf);

  // The second input byte is just the start of a character, and we don't have any more bytes.
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(EINVAL);
  EXPECT_EQ('\xd9', *in); // *in is left pointing to the start of the incomplete sequence.

  EXPECT_EQ('a', buf[0]);
  EXPECT_EQ(0, buf[1]);
  EXPECT_EQ(1U, in_bytes);
  EXPECT_EQ(sizeof(buf) - 1, out_bytes);

  ASSERT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_E2BIG) {
  const char* utf8 = "abc";
  char buf[BUFSIZ] = {};

  iconv_t c = iconv_open("UTF-8", "UTF-8");
  ASSERT_NE(INVALID_ICONV_T, c);

  char* in = const_cast<char*>(utf8);
  size_t in_bytes = strlen(in);

  char* out = buf;
  size_t out_bytes = 1;

  // We need three bytes, so one isn't enough (but we will make progress).
  out_bytes = 1;
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(E2BIG);
  EXPECT_EQ(2U, in_bytes);
  EXPECT_EQ(0U, out_bytes);

  // Two bytes left, so zero isn't enough (and we can't even make progress).
  out_bytes = 0;
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(E2BIG);
  EXPECT_EQ(2U, in_bytes);
  EXPECT_EQ(0U, out_bytes);

  // Two bytes left, so one isn't enough (but we will make progress).
  out_bytes = 1;
  errno = 0;
  EXPECT_EQ(static_cast<size_t>(-1), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(E2BIG);
  EXPECT_EQ(1U, in_bytes);
  EXPECT_EQ(0U, out_bytes);

  // One byte left, so one byte is now enough.
  out_bytes = 1;
  errno = 0;
  EXPECT_EQ(0U, iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(0);
  EXPECT_EQ(0U, in_bytes);
  EXPECT_EQ(0U, out_bytes);

  EXPECT_EQ('a', buf[0]);
  EXPECT_EQ('b', buf[1]);
  EXPECT_EQ('c', buf[2]);
  EXPECT_EQ(0, buf[3]);

  ASSERT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_invalid_converter_EBADF) {
  char* in = nullptr;
  char* out = nullptr;
  size_t in_bytes = 0;
  size_t out_bytes = 0;
  errno = 0;
  ASSERT_EQ(static_cast<size_t>(-1), iconv(INVALID_ICONV_T, &in, &in_bytes, &out, &out_bytes));
  ASSERT_ERRNO(EBADF);
}

TEST(iconv, iconv_close_invalid_converter_EBADF) {
  errno = 0;
  ASSERT_EQ(-1, iconv_close(INVALID_ICONV_T));
  ASSERT_ERRNO(EBADF);
}

static void RoundTrip(const char* dst_enc, const char* expected_bytes, size_t n) {
  // Examples from https://en.wikipedia.org/wiki/UTF-16.
  const char* utf8 = "$€𐐷"; // U+0024, U+20AC, U+10437.

  iconv_t c = iconv_open(dst_enc, "UTF-8");
  ASSERT_NE(INVALID_ICONV_T, c) << dst_enc;

  char* in = const_cast<char*>(utf8);
  size_t in_bytes = strlen(utf8);
  char buf[BUFSIZ] = {};
  char* out = buf;
  size_t out_bytes = sizeof(buf);
  size_t replacement_count = iconv(c, &in, &in_bytes, &out, &out_bytes);

  // Check we got the bytes we were expecting.
  for (size_t i = 0; i < n; ++i) {
    EXPECT_EQ(expected_bytes[i], buf[i]) << i << ' '<< dst_enc;
  }

  ASSERT_EQ(0, iconv_close(c));

  // We can't round-trip if there were replacements.
  if (strstr(dst_enc, "ascii")) {
    GTEST_LOG_(INFO) << "can't round-trip " << dst_enc << "\n";
    return;
  }
  ASSERT_EQ(0U, replacement_count);

  c = iconv_open("UTF-8", dst_enc);
  ASSERT_NE(INVALID_ICONV_T, c) << dst_enc;

  in = buf;
  in_bytes = n;
  char buf2[BUFSIZ] = {};
  out = buf2;
  out_bytes = sizeof(buf2);
  iconv(c, &in, &in_bytes, &out, &out_bytes);

  ASSERT_STREQ(utf8, buf2) << dst_enc;

  ASSERT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_round_trip_ascii) {
  RoundTrip("ascii//TRANSLIT", "$??", 3);
}

TEST(iconv, iconv_round_trip_utf8) {
  RoundTrip("utf8", "\x24\xe2\x82\xac\xf0\x90\x90\xb7", 8);
}

TEST(iconv, iconv_round_trip_utf16be) {
  RoundTrip("utf16be", "\x00\x24" "\x20\xac" "\xd8\x01\xdc\x37", 8);
}

TEST(iconv, iconv_round_trip_utf16le) {
  RoundTrip("utf16le", "\x24\x00" "\xac\x20" "\x01\xd8\x37\xdc", 8);
}

TEST(iconv, iconv_round_trip_utf32be) {
  RoundTrip("utf32be", "\x00\x00\x00\x24" "\x00\x00\x20\xac" "\x00\x01\x04\x37", 12);
}

TEST(iconv, iconv_round_trip_utf32le) {
  RoundTrip("utf32le", "\x24\x00\x00\x00" "\xac\x20\x00\x00" "\x37\x04\x01\x00", 12);
}

TEST(iconv, iconv_round_trip_wchar_t) {
  RoundTrip("wchar_t", "\x24\x00\x00\x00" "\xac\x20\x00\x00" "\x37\x04\x01\x00", 12);
}

static void Check(int expected_errno, const char* src_enc, const char* src, size_t n) {
  iconv_t c = iconv_open("wchar_t", src_enc);
  char* in = const_cast<char*>(src);
  size_t in_bytes = n;
  wchar_t out_buf[16];
  size_t out_bytes = sizeof(out_buf);
  char* out = reinterpret_cast<char*>(out_buf);
  errno = 0;
  ASSERT_EQ(static_cast<size_t>(-1), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(expected_errno);
  EXPECT_EQ(0, iconv_close(c));
}

TEST(iconv, iconv_EILSEQ_ascii) {
  Check(EILSEQ, "ASCII", "\xac", 1); // > 0x7f, so not ASCII.
}

TEST(iconv, iconv_EILSEQ_utf8_initial) {
  Check(EILSEQ, "utf8", "\x82", 1); // Invalid initial byte.
}

TEST(iconv, iconv_EILSEQ_utf8_non_initial) {
  Check(EILSEQ, "utf8", "\xe2\xe2\x82", 3); // Invalid second byte.
}

TEST(iconv, iconv_EILSEQ_utf16be_low_surrogate_first) {
  Check(EILSEQ, "utf16be", "\xdc\x37" "\xd8\x01", 4);
}

TEST(iconv, iconv_EILSEQ_utf16le_low_surrogate_first) {
  Check(EILSEQ, "utf16le", "\x37\xdc" "\x01\xd8", 4);
}

TEST(iconv, iconv_EINVAL_utf8_short) {
  Check(EINVAL, "utf8", "\xe2\x82", 2); // Missing final byte of 3-byte sequence.
}

TEST(iconv, iconv_EINVAL_utf16be_short) {
  Check(EINVAL, "utf16be", "\x00", 1); // Missing second byte.
}

TEST(iconv, iconv_EINVAL_utf16be_missing_low_surrogate) {
  Check(EINVAL, "utf16be", "\xd8\x01", 2);
}

TEST(iconv, iconv_EINVAL_utf16be_half_low_surrogate) {
  Check(EINVAL, "utf16be", "\xd8\x01\xdc", 3);
}

TEST(iconv, iconv_EINVAL_utf16le_short) {
  Check(EINVAL, "utf16le", "\x24", 1); // Missing second byte.
}

TEST(iconv, iconv_EINVAL_utf16le_missing_low_surrogate) {
  Check(EINVAL, "utf16le", "\x01\xd8", 2);
}

TEST(iconv, iconv_EINVAL_utf16le_half_low_surrogate) {
  Check(EINVAL, "utf16le", "\x01\xd8\x37", 3);
}

TEST(iconv, iconv_EINVAL_utf32be_short) {
  Check(EINVAL, "utf32be", "\x00\x00\x00", 3); // Missing final byte.
}

TEST(iconv, iconv_EINVAL_utf32le_short) {
  Check(EINVAL, "utf32le", "\x24\x00\x00", 3); // Missing final byte.
}

TEST(iconv, iconv_initial_shift_state) {
  // POSIX: "For state-dependent encodings, the conversion descriptor
  // cd is placed into its initial shift state by a call for which inbuf
  // is a null pointer, or for which inbuf points to a null pointer."
  iconv_t c = iconv_open("utf8", "utf8");
  char* in = nullptr;
  size_t in_bytes = 0;
  wchar_t out_buf[16];
  size_t out_bytes = sizeof(out_buf);
  char* out = reinterpret_cast<char*>(out_buf);

  // Points to a null pointer...
  errno = 0;
  ASSERT_EQ(static_cast<size_t>(0), iconv(c, &in, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(0);
  EXPECT_EQ(sizeof(out_buf), out_bytes);

  // Is a null pointer...
  errno = 0;
  ASSERT_EQ(static_cast<size_t>(0), iconv(c, nullptr, &in_bytes, &out, &out_bytes));
  EXPECT_ERRNO(0);
  EXPECT_EQ(sizeof(out_buf), out_bytes);

  // Is a null pointer and so is in_bytes. This isn't specified by POSIX, but
  // glibc and macOS both allow that, where Android historically didn't.
  // https://issuetracker.google.com/180598400
  errno = 0;
  ASSERT_EQ(static_cast<size_t>(0), iconv(c, nullptr, nullptr, &out, &out_bytes));
  EXPECT_ERRNO(0);
  EXPECT_EQ(sizeof(out_buf), out_bytes);

  EXPECT_EQ(0, iconv_close(c));
}
```