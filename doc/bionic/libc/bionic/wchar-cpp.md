Response:
Let's break down the thought process for analyzing the provided C++ code and generating the comprehensive response.

**1. Understanding the Request:**

The core request is to analyze a specific C++ file (`wchar.cpp`) within the Android Bionic library. The request asks for several things:

* **Functionality listing:** What does this code *do*?
* **Android relevance:** How does this relate to Android's overall operation?
* **Detailed implementation explanation:** How are the individual functions implemented?
* **Dynamic linker connection:**  Does this code interact with the dynamic linker? If so, how?
* **Logic inference:** Any assumptions or deductions based on the code?
* **Common user errors:** What mistakes might developers make when using these functions?
* **Android framework/NDK path:** How does execution reach this code from higher levels?
* **Frida hooking:**  How can these functions be monitored using Frida?

**2. Initial Code Scan and High-Level Understanding:**

First, I'd quickly read through the code, paying attention to:

* **Includes:**  `<errno.h>`, `<string.h>`, `<sys/param.h>`, `<uchar.h>`, `<wchar.h>`, and `"private/bionic_mbstate.h"`. These immediately suggest the code deals with character encoding, wide characters, error handling, and internal Bionic structures.
* **Function names:** `mbsinit`, `mbrtowc`, `mbsnrtowcs`, `mbsrtowcs`, `wcrtomb`, `wcsnrtombs`, `wcsrtombs`. The `mbs` and `wcs` prefixes clearly indicate functions related to multi-byte strings and wide character strings, respectively. The `rtowc` and `rtombs` suffixes indicate conversion between these representations.
* **Comments:** The initial comment block referencing OpenBSD and the subsequent Bionic-specific comments are crucial for understanding the context and rationale behind the implementation. The comment about the `mbstate_t` size is particularly important for Android's ABI considerations.
* **Static private state:** The `static mbstate_t __private_state;` declaration and its usage indicate thread-safety considerations and default behavior when no explicit state is provided.
* **Helper functions:** The code uses functions like `mbstate_is_initial`, `mbstate_bytes_so_far`, and `mbstate_reset_and_return_illegal`. These suggest the existence of related code within Bionic for managing the conversion state.
* **Fast paths for ASCII:**  The code explicitly checks for ASCII characters and handles them efficiently.
* **Error handling:** The use of `EILSEQ` suggests handling of invalid multi-byte sequences.

**3. Deeper Dive into Each Function:**

Next, I'd examine each function individually:

* **`mbsinit`:**  Simple check for initial conversion state.
* **`mbrtowc`:** Converts a multi-byte character to a wide character. The comment about `wchar_t` being UTF-32 is key. It delegates to `mbrtoc32`, suggesting a lower-level implementation for UTF-32 conversion.
* **`mbsnrtowcs`:**  The most complex function. It handles converting a limited number of multi-byte characters to a wide character string, with an optional destination buffer. The "measure only" logic (when `dst` is `nullptr`) is important to note. The handling of incomplete and illegal sequences is also crucial.
* **`mbsrtowcs`:** A convenience wrapper around `mbsnrtowcs` with an unlimited size.
* **`wcrtomb`:** Converts a wide character to a multi-byte sequence. It delegates to `c32rtomb`, again indicating a lower-level UTF-32 to UTF-8 conversion.
* **`wcsnrtombs`:**  Converts a limited number of wide characters to a multi-byte string. The code handles potential buffer overflows and uses a temporary buffer (`buf`) for safety.
* **`wcsrtombs`:** Another convenience wrapper around `wcsnrtombs`.

**4. Connecting to Android:**

Now, I'd consider how these functions are used within the Android ecosystem:

* **Internationalization (i18n):** The core function is handling different character encodings, essential for supporting various languages.
* **Text processing:**  Android's UI and applications heavily rely on text manipulation. These functions are fundamental for that.
* **File I/O:**  Dealing with filenames and file content in different encodings.
* **NDK usage:**  Native code developers can directly use these functions for string conversions.

**5. Dynamic Linker Analysis:**

This part requires understanding how shared libraries work in Android.

* **`__strong_alias`:** This macro indicates that `mbsrtowcs_l` and `wcsrtombs_l` are aliases for the non-`_l` versions. The `_l` suffix usually denotes locale-aware versions, but in this case, they are likely aliased for compatibility or simplicity. This doesn't directly involve the dynamic linker in terms of complex resolution, but it's a linker feature.
* **SO Layout:** I would describe a typical SO layout with sections like `.text`, `.data`, `.bss`, and `.dynsym` (dynamic symbol table).
* **Linking Process:** Briefly explain how the dynamic linker resolves symbols at runtime.

**6. Logic Inference and Assumptions:**

* **UTF-8:** The code clearly works with UTF-8 as the multi-byte encoding.
* **UTF-32:** The code explicitly states that `wchar_t` is UTF-32.
* **State Management:** The `mbstate_t` structure is used to maintain the conversion state between function calls.

**7. Common User Errors:**

Think about typical mistakes developers might make:

* **Incorrect buffer sizes:** Leading to buffer overflows.
* **Ignoring return values:** Not checking for errors.
* **Mixing up character encodings:**  Assuming a particular encoding when the data is in a different one.
* **Incorrect `mbstate_t` handling:** Not initializing or updating the state correctly.

**8. Android Framework/NDK Path:**

Trace the call flow from high-level components down to these functions:

* **Java Framework:**  Android's Java framework uses `String` objects, which are internally UTF-16. Conversions might happen when interacting with native code or external systems.
* **NDK:** Native code can directly call these functions.
* **System Services:**  Various system services might need to handle text in different encodings.

**9. Frida Hooking:**

Think about how to intercept calls to these functions using Frida:

* **Function name:**  Use the function names directly.
* **Arguments and return values:**  Log the input parameters and the return value to understand the behavior.
* **State:**  Potentially hook related state variables if needed for deeper analysis.

**10. Structuring the Response:**

Finally, organize the information logically, using headings and bullet points for clarity. Use clear and concise language. Provide code examples where appropriate. Ensure all aspects of the original request are addressed.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "Is the dynamic linker heavily involved here?"  Correction:  While not directly managing symbol resolution for these specific functions within the same SO, the functions are *part* of a shared library loaded by the dynamic linker. The `__strong_alias` directive *is* a linker feature.
* **Initial thought:** "Just describe the function implementations." Refinement: Also explain *why* they are implemented this way, especially the `mbstate_t` handling and the fast paths for ASCII.
* **Ensuring all parts of the prompt are answered:**  Double-check that each specific requirement (functionality, Android relevance, implementation details, dynamic linker, etc.) is addressed.

By following this structured approach, combining code analysis with knowledge of Android internals and common development practices, it's possible to generate a comprehensive and accurate response to the user's request.
```chinese
## 对 bionic/libc/bionic/wchar.cpp 文件的分析

这个 `wchar.cpp` 文件是 Android Bionic 库中关于宽字符处理的一部分，主要负责在多字节字符（通常是 UTF-8）和宽字符（在 Android 中是 UTF-32）之间进行转换。它直接实现了 POSIX 标准中定义的一些宽字符相关的函数。

**主要功能列举：**

1. **多字节字符到宽字符的转换：**
   - `mbrtowc`: 将一个多字节字符转换为一个宽字符。
   - `mbsnrtowcs`: 将一个多字节字符串的一部分转换为一个宽字符串。
   - `mbsrtowcs`: 将一个多字节字符串转换为一个宽字符串。

2. **宽字符到多字节字符的转换：**
   - `wcrtomb`: 将一个宽字符转换为一个多字节字符。
   - `wcsnrtombs`: 将一个宽字符串的一部分转换为一个多字节字符串。
   - `wcsrtombs`: 将一个宽字符串转换为一个多字节字符串。

3. **多字节转换状态管理：**
   - `mbsinit`: 检查多字节转换状态是否处于初始状态。

**与 Android 功能的关系及举例说明：**

这些函数在 Android 系统中扮演着至关重要的角色，因为 Android 需要处理各种语言的文本，而不同的语言可能使用不同的字符编码。

* **国际化 (i18n) 支持：** Android 需要能够正确显示和处理各种语言的字符。这些函数提供了在内部 UTF-32 表示和外部 UTF-8 表示之间转换的桥梁。例如，当一个应用从网络接收到 UTF-8 编码的文本数据时，可以使用 `mbsrtowcs` 将其转换为宽字符以便在内存中处理和显示。
* **NDK 开发：** 使用 Android NDK 进行本地开发的开发者，可以直接调用这些 C 标准库函数进行字符串编码转换。例如，一个使用 C++ 编写的游戏引擎需要加载包含各种语言文本的资源文件，就可以使用这些函数来正确解析。
* **文件系统操作：** Android 文件系统通常使用 UTF-8 编码文件名。当 Java 或 Native 代码需要操作文件时，可能需要进行编码转换。例如，Java 的 `File` 类在内部使用 Unicode，当与底层文件系统交互时，会涉及到 UTF-8 和 UTF-16 之间的转换，而这些转换最终可能依赖于 Bionic 提供的底层函数。
* **输入法 (IME)：** 输入法需要处理用户输入的字符，并将其转换为应用可以理解的格式。这其中就涉及到不同字符编码之间的转换。

**详细解释每个 libc 函数的功能是如何实现的：**

* **`mbsinit(const mbstate_t* ps)`:**
    - **功能:** 检查给定的多字节转换状态 `ps` 是否处于初始状态。初始状态意味着没有未完成的多字节字符序列。
    - **实现:** 如果 `ps` 是 `nullptr`，则认为处于初始状态。否则，通过调用 `mbstate_is_initial(ps)` 来检查状态。`mbstate_is_initial` 的具体实现没有在此文件中，但通常会检查 `mbstate_t` 结构体内部的状态标志。

* **`mbrtowc(wchar_t* pwc, const char* s, size_t n, mbstate_t* ps)`:**
    - **功能:** 将最多 `n` 个字节的以 `s` 开头的多字节字符转换为一个宽字符，并将结果存储在 `pwc` 指向的位置。
    - **实现:**
        - 如果 `ps` 为空，则使用一个静态的私有 `mbstate_t` 变量 `__private_state`。
        - 调用 `mbrtoc32` 函数来执行实际的转换。`mbrtoc32` 是一个 Bionic 内部函数（可能在 `uchar.h` 或相关的内部头文件中定义），它将多字节字符转换为 `char32_t` 类型，这与 Android 的 `wchar_t` (UTF-32) 相对应。
        - 该函数依赖于底层的 UTF-8 解析逻辑，判断 `s` 开头的字节序列是否构成一个有效的 UTF-8 字符，并将其转换为相应的 UTF-32 编码。

* **`mbsnrtowcs(wchar_t* dst, const char** src, size_t nmc, size_t len, mbstate_t* ps)`:**
    - **功能:** 将以 `src` 指向的指针开始的，最多 `nmc` 个字节的多字节字符串转换为宽字符串，并将结果存储在 `dst` 中，最多写入 `len` 个宽字符。
    - **实现:**
        - 同样处理 `ps` 为空的情况。
        - **快速路径优化:** 如果遇到 ASCII 字符（小于 0x80），则直接进行转换，因为 ASCII 字符在 UTF-8 中是单字节表示，并且其编码值与 Unicode 编码值相同。
        - **测量模式:** 如果 `dst` 为 `nullptr`，则函数只计算转换后的宽字符数量，不进行实际写入。
        - **实际转换:** 循环遍历多字节字符串，每次调用 `mbrtowc` 将一个多字节字符转换为宽字符并写入 `dst`。
        - **错误处理:** 如果遇到非法的多字节序列或不完整的序列，则重置转换状态并返回错误代码 `EILSEQ`。
        - **空字符处理:** 当遇到多字节字符串的空字符时，转换停止。

* **`mbsrtowcs(wchar_t* dst, const char** src, size_t len, mbstate_t* ps)`:**
    - **功能:** 类似于 `mbsnrtowcs`，但是会转换整个多字节字符串，直到遇到空字符或达到 `len` 的限制。
    - **实现:** 简单地调用 `mbsnrtowcs`，并将 `nmc` 设置为 `SIZE_MAX`，表示转换尽可能多的字符。

* **`wcrtomb(char* s, wchar_t wc, mbstate_t* ps)`:**
    - **功能:** 将宽字符 `wc` 转换为一个多字节字符序列，并将结果存储在 `s` 指向的位置。
    - **实现:**
        - 同样处理 `ps` 为空的情况。
        - 调用 `c32rtomb` 函数执行实际的转换。`c32rtomb` 是一个 Bionic 内部函数，它将 UTF-32 编码的宽字符转换为 UTF-8 编码的多字节字符序列。

* **`wcsnrtombs(char* dst, const wchar_t** src, size_t nwc, size_t len, mbstate_t* ps)`:**
    - **功能:** 将以 `src` 指向的指针开始的，最多 `nwc` 个宽字符的宽字符串转换为多字节字符串，并将结果存储在 `dst` 中，最多写入 `len` 个字节。
    - **实现:**
        - 检查转换状态是否处于初始状态，如果不是则返回错误。
        - **快速路径优化:** 如果遇到 ASCII 范围内的宽字符（小于 0x80），则直接进行转换。
        - **测量模式:** 如果 `dst` 为 `nullptr`，则函数只计算转换后的字节数。
        - **实际转换:** 循环遍历宽字符串，每次调用 `wcrtomb` 将一个宽字符转换为多字节字符序列并写入 `dst`。
        - **缓冲区溢出保护:** 如果剩余空间不足以存储转换后的多字节字符，则停止转换。
        - **临时缓冲区:** 为了避免部分写入导致的错误，可能使用一个临时缓冲区 `buf` 来存储转换结果，然后再复制到目标缓冲区。

* **`wcsrtombs(char* dst, const wchar_t** src, size_t len, mbstate_t* ps)`:**
    - **功能:** 类似于 `wcsnrtombs`，但是会转换整个宽字符串，直到遇到空字符或达到 `len` 的限制。
    - **实现:** 简单地调用 `wcsnrtombs`，并将 `nwc` 设置为 `SIZE_MAX`。

**关于 dynamic linker 的功能：**

这个 `wchar.cpp` 文件本身的代码并没有直接涉及复杂的 dynamic linker 功能。然而：

1. **共享库 (Shared Object, SO) 的一部分:**  `wchar.cpp` 编译后会成为 `libc.so` 的一部分。dynamic linker (`linker64` 或 `linker`) 负责在程序启动时加载 `libc.so` 以及其他依赖的共享库，并将程序中的符号引用链接到这些库中定义的实际函数地址。
2. **符号导出:**  `wchar.cpp` 中定义的这些函数（如 `mbrtowc`, `mbsrtowcs` 等）会被导出为符号，使得其他共享库或可执行文件可以调用它们。

**so 布局样本:**

一个简化的 `libc.so` 的布局可能如下所示：

```
libc.so:
    .text          # 包含可执行代码，包括 wchar.cpp 中函数的指令
    .data          # 包含已初始化的全局变量
    .bss           # 包含未初始化的全局变量
    .rodata        # 包含只读数据，如字符串常量
    .dynsym        # 动态符号表，列出导出的和导入的符号
    .dynstr        # 动态字符串表，存储符号名称
    .rel.dyn       # 动态重定位表，用于在加载时修正地址
    .plt           # 程序链接表，用于延迟绑定
    ... 其他 section ...
```

**链接的处理过程:**

1. 当一个程序（例如一个应用进程）调用 `mbrtowc` 函数时，编译器会生成一个指向 `mbrtowc` 符号的引用。
2. 在程序启动时，dynamic linker 会加载程序依赖的共享库，包括 `libc.so`。
3. dynamic linker 会解析程序中的未定义符号，并在加载的共享库中查找匹配的符号。
4. 对于 `mbrtowc`，dynamic linker 会在 `libc.so` 的 `.dynsym` 表中找到 `mbrtowc` 符号的定义，并获取其在 `libc.so` 中的地址。
5. dynamic linker 会更新程序的链接表（例如 `.got.plt`），将 `mbrtowc` 的符号引用指向其在 `libc.so` 中的实际地址。
6. 之后，当程序执行到调用 `mbrtowc` 的指令时，会跳转到 `libc.so` 中 `mbrtowc` 函数的实际代码执行。

**对于涉及 dynamic linker 的功能，没有特别需要展示的 SO 布局样本或链接处理过程，因为 `wchar.cpp` 中的代码主要是标准 C 库函数的实现，其链接过程与其他标准库函数相同。**

**假设输入与输出 (逻辑推理):**

以 `mbrtowc` 为例：

**假设输入:**

* `pwc`: 指向一个可以存储 `wchar_t` 的内存位置。
* `s`: 指向一个包含 UTF-8 编码字符串的内存位置，例如 `"你好"` 的 UTF-8 编码 `\xE4\xBD\xA0\xE5\xA5\xBD`。
* `n`: 至少为 3 (因为 "你" 字的 UTF-8 编码占 3 个字节)。
* `ps`: 可以为 `nullptr` 或指向一个有效的 `mbstate_t` 结构。

**预期输出:**

* `mbrtowc` 的返回值将是转换的字节数，例如 3。
* `pwc` 指向的内存位置将存储宽字符 "你" 的 UTF-32 编码值。

**假设输入 (错误情况):**

* `s`: 指向一个包含无效 UTF-8 序列的内存位置，例如 `\xFF\xFF`。
* `n`: 至少为 2。

**预期输出:**

* `mbrtowc` 的返回值将是 `BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE` (-1)，并且 `errno` 会被设置为 `EILSEQ`。转换状态会被重置。

**涉及用户或编程常见的使用错误，请举例说明:**

1. **缓冲区溢出:**
   ```c
   char utf8_str[] = "你好世界";
   wchar_t wstr[5]; // 目标缓冲区太小，只能存储 4 个宽字符 + null
   mbstate_t state;
   mbsinit(&state);
   size_t result = mbsrtowcs(wstr, (const char**)&utf8_str, sizeof(wstr) / sizeof(wstr[0]), &state);
   // 可能导致缓冲区溢出，因为 "你好世界" 包含 4 个汉字，需要 4 个 wchar_t 加上 null 终止符。
   ```

2. **未正确初始化或管理 `mbstate_t`:**
   ```c
   char utf8_part1[] = "\xE4\xBD"; // "你" 的前两个字节
   char utf8_part2[] = "\xA0";    // "你" 的最后一个字节
   wchar_t wc;
   mbstate_t state;
   mbsinit(&state);

   mbrtowc(&wc, utf8_part1, sizeof(utf8_part1), &state); // 转换不完整序列

   // 错误地假设 state 可以用于转换下一个字符，但实际上 state 可能指示需要更多字节
   mbrtowc(&wc, utf8_part2, sizeof(utf8_part2), &state);
   ```

3. **忽略返回值和 `errno`:**
   ```c
   char invalid_utf8[] = "\xFF\xFF";
   wchar_t wc;
   mbstate_t state;
   mbsinit(&state);
   size_t result = mbrtowc(&wc, invalid_utf8, sizeof(invalid_utf8), &state);
   if (result == (size_t)-1) {
       // 应该检查 errno 以确定错误类型 (EILSEQ)
       // printf("转换失败\n"); // 没有提供足够的信息
   }
   ```

4. **假定字符大小:** 开发者可能错误地假设宽字符或多字节字符的固定大小，导致处理变长编码时出现问题。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `wchar.cpp` 的路径：**

1. **Java Framework 层:**  Android 应用通常使用 Java 代码进行开发。Java 中的 `String` 类内部使用 UTF-16 编码。
2. **JNI 调用:** 当 Java 代码需要与 Native 代码交互时，会通过 Java Native Interface (JNI) 进行调用。例如，当需要进行文件操作、网络通信或者使用 NDK 编写的库时。
3. **Native 代码:** 在 Native 代码中，如果需要处理来自 Java 层的字符串或需要进行字符编码转换，可能会使用 Bionic 提供的标准 C 库函数。
4. **`libcore` 和 `libc`:**  Java 层的字符串操作最终可能调用到 `libcore` 库中的相关方法，这些方法在底层可能会调用到 `libc.so` 中实现的函数，包括 `wchar.cpp` 中定义的函数。例如，`String.getBytes(String charsetName)` 方法在处理非 ISO-8859-1 编码时，可能会涉及到编码转换，最终会调用到 Native 层。
5. **NDK 直接调用:** 使用 NDK 开发的 C/C++ 代码可以直接调用 `wchar.cpp` 中定义的函数。

**Frida Hook 示例：**

假设我们想 hook `mbrtowc` 函数，以观察其输入和输出。

```python
import frida
import sys

package_name = "your.target.package" # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "mbrtowc"), {
    onEnter: function(args) {
        var pwc = args[0];
        var s = Memory.readUtf8String(args[1]);
        var n = args[2].toInt();
        var ps = args[3];

        console.log("mbrtowc called:");
        console.log("  pwc:", pwc);
        console.log("  s:", s);
        console.log("  n:", n);
        console.log("  ps:", ps);
    },
    onLeave: function(retval) {
        console.log("mbrtowc returned:", retval.toInt());
        if (retval.toInt() > 0 && this.context.r0 != 0) { // 假设返回值大于 0 且 pwc 不为空
            console.log("  Converted wchar_t:", Memory.readU32(this.context.r0)); // 读取 wchar_t 的值 (假设 ARM)
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**Frida Hook 调试步骤:**

1. **安装 Frida 和 USB 驱动:** 确保你的开发机器上安装了 Frida 和 Android 设备的 USB 驱动。
2. **启动目标应用:** 运行你想要调试的 Android 应用。
3. **运行 Frida 脚本:** 执行上面的 Python Frida 脚本，将 `your.target.package` 替换为实际的应用包名。
4. **观察输出:** 当目标应用执行到 `mbrtowc` 函数时，Frida 脚本会拦截调用，并在控制台打印出函数的参数值（指向宽字符缓冲区的指针、指向多字节字符串的指针、最大转换字节数、状态指针）以及返回值。
5. **分析数据:** 通过观察输入的多字节字符串和转换后的宽字符值，可以验证字符编码转换是否正确。

这个 Frida 示例提供了一个基本的 hook 框架。你可以根据需要修改 `onEnter` 和 `onLeave` 函数中的代码，以记录更多的信息，例如 `errno` 的值，或者在特定的条件下修改函数的行为。对于其他函数，只需要修改 `Module.findExportByName` 的第二个参数即可。

请注意，Frida 需要 root 权限或在可调试的应用上运行。
```
### 提示词
```
这是目录为bionic/libc/bionic/wchar.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
/*	$OpenBSD: citrus_utf8.c,v 1.6 2012/12/05 23:19:59 deraadt Exp $ */

/*-
 * Copyright (c) 2002-2004 Tim J. Robbins
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <errno.h>
#include <string.h>
#include <sys/param.h>
#include <uchar.h>
#include <wchar.h>

#include "private/bionic_mbstate.h"

//
// This file is basically OpenBSD's citrus_utf8.c but rewritten to not require a
// 12-byte mbstate_t so we're backwards-compatible with our LP32 ABI where
// mbstate_t was only 4 bytes.
//
// The state is the UTF-8 sequence. We only support <= 4-bytes sequences so LP32
// mbstate_t already has enough space (out of the 4 available bytes we only
// need 3 since we should never need to store the entire sequence in the
// intermediary state).
//
// The C standard leaves the conversion state undefined after a bad conversion.
// To avoid unexpected failures due to the possible use of the internal private
// state we always reset the conversion state when encountering illegal
// sequences.
//
// We also implement the POSIX interface directly rather than being accessed via
// function pointers.
//

int mbsinit(const mbstate_t* ps) {
  return ps == nullptr || mbstate_is_initial(ps);
}

size_t mbrtowc(wchar_t* pwc, const char* s, size_t n, mbstate_t* ps) {
  static mbstate_t __private_state;
  mbstate_t* state = (ps == nullptr) ? &__private_state : ps;

  // Our wchar_t is UTF-32.
  return mbrtoc32(reinterpret_cast<char32_t*>(pwc), s, n, state);
}

size_t mbsnrtowcs(wchar_t* dst, const char** src, size_t nmc, size_t len, mbstate_t* ps) {
  static mbstate_t __private_state;
  mbstate_t* state = (ps == nullptr) ? &__private_state : ps;
  size_t i, o, r;

  // The fast paths in the loops below are not safe if an ASCII
  // character appears as anything but the first byte of a
  // multibyte sequence. Check now to avoid doing it in the loops.
  if (nmc > 0 && mbstate_bytes_so_far(state) > 0 && static_cast<uint8_t>((*src)[0]) < 0x80) {
    return mbstate_reset_and_return_illegal(EILSEQ, state);
  }

  // Measure only?
  if (dst == nullptr) {
    for (i = o = 0; i < nmc; i += r, o++) {
      if (static_cast<uint8_t>((*src)[i]) < 0x80) {
        // Fast path for plain ASCII characters.
        if ((*src)[i] == '\0') {
          return mbstate_reset_and_return(o, state);
        }
        r = 1;
      } else {
        r = mbrtowc(nullptr, *src + i, nmc - i, state);
        if (r == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
          return mbstate_reset_and_return_illegal(EILSEQ, state);
        }
        if (r == BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE) {
          return mbstate_reset_and_return_illegal(EILSEQ, state);
        }
        if (r == 0) {
          return mbstate_reset_and_return(o, state);
        }
      }
    }
    return mbstate_reset_and_return(o, state);
  }

  // Actually convert, updating `dst` and `src`.
  for (i = o = 0; i < nmc && o < len; i += r, o++) {
    if (static_cast<uint8_t>((*src)[i]) < 0x80) {
      // Fast path for plain ASCII characters.
      dst[o] = (*src)[i];
      r = 1;
      if ((*src)[i] == '\0') {
        *src = nullptr;
        return mbstate_reset_and_return(o, state);
      }
    } else {
      r = mbrtowc(dst + o, *src + i, nmc - i, state);
      if (r == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
        *src += i;
        return mbstate_reset_and_return_illegal(EILSEQ, state);
      }
      if (r == BIONIC_MULTIBYTE_RESULT_INCOMPLETE_SEQUENCE) {
        *src += nmc;
        return mbstate_reset_and_return_illegal(EILSEQ, state);
      }
      if (r == 0) {
        *src = nullptr;
        return mbstate_reset_and_return(o, state);
      }
    }
  }
  *src += i;
  return mbstate_reset_and_return(o, state);
}

size_t mbsrtowcs(wchar_t* dst, const char** src, size_t len, mbstate_t* ps) {
  return mbsnrtowcs(dst, src, SIZE_MAX, len, ps);
}
__strong_alias(mbsrtowcs_l, mbsrtowcs);

size_t wcrtomb(char* s, wchar_t wc, mbstate_t* ps) {
  static mbstate_t __private_state;
  mbstate_t* state = (ps == nullptr) ? &__private_state : ps;

  // Our wchar_t is UTF-32.
  return c32rtomb(s, static_cast<char32_t>(wc), state);
}

size_t wcsnrtombs(char* dst, const wchar_t** src, size_t nwc, size_t len, mbstate_t* ps) {
  static mbstate_t __private_state;
  mbstate_t* state = (ps == nullptr) ? &__private_state : ps;

  if (!mbstate_is_initial(state)) {
    return mbstate_reset_and_return_illegal(EILSEQ, state);
  }

  char buf[MB_LEN_MAX];
  size_t i, o, r;
  if (dst == nullptr) {
    for (i = o = 0; i < nwc; i++, o += r) {
      wchar_t wc = (*src)[i];
      if (static_cast<uint32_t>(wc) < 0x80) {
        // Fast path for plain ASCII characters.
        if (wc == 0) {
          return o;
        }
        r = 1;
      } else {
        r = wcrtomb(buf, wc, state);
        if (r == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
          return r;
        }
      }
    }
    return o;
  }

  for (i = o = 0; i < nwc && o < len; i++, o += r) {
    wchar_t wc = (*src)[i];
    if (static_cast<uint32_t>(wc) < 0x80) {
      // Fast path for plain ASCII characters.
      dst[o] = wc;
      if (wc == 0) {
        *src = nullptr;
        return o;
      }
      r = 1;
    } else if (len - o >= sizeof(buf)) {
      // Enough space to translate in-place.
      r = wcrtomb(dst + o, wc, state);
      if (r == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
        *src += i;
        return r;
      }
    } else {
      // May not be enough space; use temp buffer.
      r = wcrtomb(buf, wc, state);
      if (r == BIONIC_MULTIBYTE_RESULT_ILLEGAL_SEQUENCE) {
        *src += i;
        return r;
      }
      if (r > len - o) {
        break;
      }
      memcpy(dst + o, buf, r);
    }
  }
  *src += i;
  return o;
}

size_t wcsrtombs(char* dst, const wchar_t** src, size_t len, mbstate_t* ps) {
  return wcsnrtombs(dst, src, SIZE_MAX, len, ps);
}
__strong_alias(wcsrtombs_l, wcsrtombs);
```