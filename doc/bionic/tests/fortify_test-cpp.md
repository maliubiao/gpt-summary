Response:
Let's break down the thought process for answering the user's request about `bionic/tests/fortify_test.cpp`.

**1. Understanding the Core Request:**

The user wants to understand the *functionality* of this specific test file. The name "fortify_test" and the inclusion of headers like `<string.h>` and `<stdio.h>` immediately suggest this file is about testing the "fortification" features of the C library. Fortification is a security mechanism aimed at preventing buffer overflows and other memory corruption vulnerabilities.

**2. Identifying Key Areas of Focus:**

The request explicitly asks for several specific aspects:

* **Functionality:** What does the code do?
* **Relationship to Android:** How does it relate to the broader Android system?
* **`libc` function details:** How are the `libc` functions tested implemented (even though this is a test file, the *intent* is to test the `libc` implementations).
* **Dynamic Linker:**  How does this relate to the dynamic linker?
* **Logical Reasoning (Assumptions/Inputs/Outputs):**  What are the test cases trying to achieve?
* **Common Errors:** What kind of programming mistakes does this test prevent?
* **Android Framework/NDK Integration:** How does code execution reach this test?
* **Frida Hooking:** How can these tests be debugged?

**3. Initial Code Analysis and Keyword Spotting:**

A quick scan of the code reveals several important things:

* **`#include <gtest/gtest.h>`:**  This indicates the use of Google Test, a C++ testing framework. This confirms it's a test file.
* **`ASSERT_FORTIFY(expr)`:** This macro is central. It expects the expression `expr` to cause a `SIGABRT` signal (a crash) when built with fortification enabled. This is the core mechanism of the tests: triggering expected failures.
* **`_FORTIFY_SOURCE`:** This preprocessor definition is used to conditionally compile some tests, confirming the focus on fortification.
* **Numerous `TEST_F(DEATHTEST, ...)` blocks:** Each block represents an individual test case.
* **Use of `strcpy`, `strncpy`, `sprintf`, `memcpy`, etc.:**  These are standard C library functions. The tests often intentionally misuse these functions (e.g., writing beyond buffer boundaries).

**4. Deconstructing the Test Cases:**

For each `TEST_F` block, I need to determine:

* **Which `libc` function is being tested.**
* **What kind of misuse is being simulated.**  Is it a buffer overflow?  Is it using an uninitialized string?
* **What the expected outcome is (a crash due to fortification).**

For example, the test `TEST_F(DEATHTEST, strcpy_fortified)` clearly tests `strcpy` with a destination buffer that is too small for the source string. The `ASSERT_FORTIFY` macro confirms that the test expects a crash.

**5. Addressing Specific Request Points:**

* **Functionality:**  The file tests the fortification mechanisms in `bionic` by intentionally triggering buffer overflows and other memory safety violations using standard `libc` functions. It verifies that the fortification logic correctly detects these errors and aborts the program.

* **Relationship to Android:** Bionic is Android's C library. Fortification is a crucial security feature within Bionic. This test file ensures this security feature works correctly, protecting Android from vulnerabilities.

* **`libc` function details:** While the test *uses* `libc` functions, it doesn't *implement* them. The explanation should focus on the *purpose* of these functions and how fortification *should* behave. For example, `strcpy` copies a string until a null terminator is found. Fortification adds checks to ensure the destination buffer is large enough.

* **Dynamic Linker:**  The connection here is less direct. Fortification is a compile-time/runtime check. However, the dynamic linker loads the `libc.so` containing the fortified functions. The `so` layout would be the standard structure of a shared library on Android. The linking process involves resolving symbols (like `strcpy`) to their implementations in `libc.so`.

* **Logical Reasoning:**  Each test case sets up specific conditions (buffer sizes, string content) and then calls a `libc` function in a way that *should* trigger a fortification failure. The input is the data provided to the function, and the expected output is a program termination (SIGABRT).

* **Common Errors:** The tests demonstrate classic buffer overflow scenarios – using `strcpy` with insufficient destination space, writing beyond the bounds of arrays in `sprintf`, etc.

* **Android Framework/NDK Integration:** This requires tracing the execution path. An app using the NDK calls `libc` functions. These calls go through the system call interface to the kernel, but the actual implementations reside in `libc.so`, which is loaded by the dynamic linker.

* **Frida Hooking:** Provide examples of how Frida can be used to intercept the fortified functions and observe their behavior or even prevent the crashes for debugging.

**6. Structuring the Answer:**

Organize the answer logically, addressing each part of the user's request. Use clear headings and bullet points to improve readability. Provide concrete examples from the code.

**7. Refinement and Language:**

Ensure the language is clear, concise, and technically accurate. Explain concepts like "fortification" and "buffer overflow" if necessary. Use Chinese as requested.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the *implementation* of `libc` functions.
* **Correction:** Realize the test file doesn't *implement* them, but rather *tests* their fortified behavior. Shift focus to the *intended* behavior and how fortification intercepts errors.
* **Initial thought:** Overcomplicate the dynamic linker explanation.
* **Correction:** Simplify to the basic role of loading `libc.so` and resolving symbols. The test file doesn't directly test the linker's internals.
* **Ensure consistent terminology:** Stick to "fortification" and related terms.

By following this thought process, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request.
这是一个关于 Android Bionic 库中 `fortify_test.cpp` 文件的分析。这个文件是 Bionic 库的测试套件的一部分，专门用于测试 Bionic 提供的 libc 函数的 "fortification" 功能。

**功能列举:**

`fortify_test.cpp` 的主要功能是：

1. **测试 libc 函数的安全性增强 (Fortification):**  它通过各种测试用例，验证 Bionic 的 libc 库是否正确实现了安全增强机制。这些机制旨在在运行时检测并阻止潜在的缓冲区溢出和其他内存安全漏洞。
2. **验证安全检查是否生效:**  测试用例会故意触发一些潜在的内存安全问题，例如向缓冲区写入超出其大小的数据，然后验证程序是否因为 Bionic 的 fortification 机制而中止（通常是通过 `SIGABRT` 信号）。
3. **提供回归测试:** 这些测试确保对 libc 函数的修改不会意外地移除或破坏其安全增强功能。
4. **作为开发和调试的工具:** 开发人员可以使用这些测试来验证他们对 libc 函数的修改是否引入了新的安全问题，或者他们新添加的函数是否需要进行类似的 fortification。

**与 Android 功能的关系及举例说明:**

Bionic 是 Android 系统的核心 C 库，几乎所有的 Android 应用和系统服务都直接或间接地依赖它。`fortify_test.cpp` 中测试的 fortification 功能对于 Android 的整体安全至关重要。

**举例说明:**

* **`strcpy` 和缓冲区溢出:**  `strcpy` 函数如果使用不当，很容易导致缓冲区溢出。例如，如果将一个很长的字符串复制到一个很小的缓冲区中，`strcpy` 会继续写入超出缓冲区边界的内存，可能覆盖其他重要数据或代码，导致程序崩溃或安全漏洞。
    ```c
    char buf[10];
    char *long_string = "This is a very long string";
    // 如果没有 fortification，这会导致缓冲区溢出
    // 在启用了 fortification 的 Bionic 上，这应该会触发一个中止信号
    // TEST_F(DEATHTEST, strcpy_fortified) 中就包含了类似的测试
    strcpy(buf, long_string);
    ```
    `fortify_test.cpp` 中的 `TEST_F(DEATHTEST, strcpy_fortified)`  这样的测试用例就是为了验证当发生这种溢出时，Bionic 的 fortification 机制是否能够检测到并阻止它。

* **`sprintf` 格式化字符串漏洞:** `sprintf` 函数如果使用了不受信任的格式化字符串，可能导致格式化字符串漏洞。例如：
    ```c
    char buf[100];
    char *user_input = "%s%s%s%s%s%s%s%s"; // 恶意输入
    // 如果没有 fortification，这可能导致程序崩溃或执行任意代码
    // 在启用了 fortification 的 Bionic 上，这应该会触发一个中止信号
    // TEST_F(DEATHTEST, sprintf_fortified) 中包含了类似的测试
    sprintf(buf, user_input);
    ```
    `fortify_test.cpp` 中的 `TEST_F(DEATHTEST, sprintf_fortified)` 等测试用例会尝试使用格式化字符串漏洞，以验证 fortification 机制是否能阻止这种攻击。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个 `fortify_test.cpp` 文件本身 **并不实现**  libc 函数的功能。它的目的是 **测试**  libc 函数的安全性。  libc 函数的具体实现位于 Bionic 库的其他源文件中（例如 `bionic/libc/bionic/` 和 `bionic/libc/upstream-openbsd/`）。

这个测试文件通过调用这些 libc 函数，并故意传递可能导致安全问题的参数，来触发 fortification 机制。

以下是一些测试用例中涉及的 libc 函数的简要功能说明：

* **`strcpy(char *dest, const char *src)`:** 将 `src` 指向的字符串（包括空字符 `\0`）复制到 `dest` 指向的缓冲区。 **安全隐患:** 如果 `dest` 缓冲区太小，会导致缓冲区溢出。
* **`strncpy(char *dest, const char *src, size_t n)`:** 将 `src` 指向的字符串的前 `n` 个字符复制到 `dest` 指向的缓冲区。如果 `src` 的长度小于 `n`，则用空字符填充 `dest` 的剩余部分。 **安全隐患:** 如果 `n` 大于 `dest` 缓冲区的大小，会导致缓冲区溢出。
* **`stpncpy(char *dest, const char *src, size_t n)`:** 类似于 `strncpy`，但返回指向复制的字符串结尾的指针（即结尾的空字符之后的位置）。
* **`sprintf(char *str, const char *format, ...)`:** 根据 `format` 字符串中的格式说明符，将格式化后的数据写入到 `str` 指向的缓冲区。 **安全隐患:** 如果 `format` 字符串不受信任，可能导致格式化字符串漏洞。如果写入的数据量超出 `str` 缓冲区的大小，会导致缓冲区溢出。
* **`vsprintf(char *str, const char *format, va_list ap)`:** 与 `sprintf` 类似，但使用 `va_list` 类型的参数列表。
* **`snprintf(char *str, size_t size, const char *format, ...)`:**  与 `sprintf` 类似，但最多写入 `size-1` 个字符到 `str`，并始终以空字符结尾，从而提供了一定的缓冲区溢出保护。  **Fortification 的目标之一就是增强类似 `snprintf` 这样的安全函数的保护，以及对不安全函数如 `sprintf` 进行运行时检查。**
* **`vsnprintf(char *str, size_t size, const char *format, va_list ap)`:** 与 `snprintf` 类似，但使用 `va_list` 类型的参数列表。
* **`strcat(char *dest, const char *src)`:** 将 `src` 指向的字符串追加到 `dest` 指向的字符串的末尾。 **安全隐患:** 如果 `dest` 缓冲区没有足够的空间容纳追加后的字符串，会导致缓冲区溢出。
* **`strncat(char *dest, const char *src, size_t n)`:** 将 `src` 指向的字符串的前 `n` 个字符追加到 `dest` 指向的字符串的末尾。 **安全隐患:** 如果 `dest` 缓冲区没有足够的空间容纳追加后的字符串，会导致缓冲区溢出。
* **`stpcpy(char *dest, const char *src)`:**  将 `src` 指向的字符串复制到 `dest`，并返回指向 `dest` 中结尾空字符的指针。 **安全隐患:** 与 `strcpy` 类似，如果 `dest` 缓冲区太小，会导致缓冲区溢出。
* **`strlen(const char *s)`:** 返回字符串 `s` 的长度（不包括结尾的空字符）。
* **`strchr(const char *s, int c)`:** 在字符串 `s` 中查找字符 `c` 第一次出现的位置。
* **`strrchr(const char *s, int c)`:** 在字符串 `s` 中查找字符 `c` 最后一次出现的位置。
* **`memchr(const void *s, int c, size_t n)`:** 在内存块 `s` 的前 `n` 个字节中查找字符 `c` 第一次出现的位置。
* **`memrchr(const void *s, int c, size_t n)`:** 在内存块 `s` 的前 `n` 个字节中查找字符 `c` 最后一次出现的位置。
* **`strlcpy(char *dst, const char *src, size_t size)`:**  将 `src` 复制到 `dst`，保证 `dst` 以空字符结尾，并返回复制的字符数（不包括结尾的空字符）。 如果 `size` 为 0，则不复制任何内容，但如果 `src` 非空，则返回 `strlen(src)`。
* **`strlcat(char *dst, const char *src, size_t size)`:** 将 `src` 追加到 `dst`，保证 `dst` 以空字符结尾，并返回追加后的字符串长度（不包括结尾的空字符）。
* **`bzero(void *s, size_t n)`:** 将内存块 `s` 的前 `n` 个字节设置为零。
* **`memmove(void *dest, const void *src, size_t n)`:** 将内存块 `src` 的前 `n` 个字节复制到 `dest`，即使 `src` 和 `dest` 指向的内存区域重叠也能正确处理。
* **`memcpy(void *dest, const void *src, size_t n)`:** 将内存块 `src` 的前 `n` 个字节复制到 `dest`。 **安全隐患:** 如果 `dest` 缓冲区太小，会导致缓冲区溢出。如果 `src` 和 `dest` 指向的内存区域重叠，行为是未定义的。
* **`memset(void *s, int c, size_t n)`:** 将内存块 `s` 的前 `n` 个字节设置为值 `c`。
* **`umask(mode_t mask)`:** 设置进程的文件模式创建屏蔽字。
* **`recv(int sockfd, void *buf, size_t len, int flags)`:** 从套接字接收数据。 **安全隐患:** 如果 `buf` 缓冲区太小，可能会导致缓冲区溢出。
* **`send(int sockfd, const void *buf, size_t len, int flags)`:** 通过套接字发送数据。
* **`FD_ISSET(int fd, fd_set *set)`:** 检查文件描述符 `fd` 是否在文件描述符集 `set` 中。 **安全隐患:** 如果 `set` 指针无效，会导致程序崩溃。
* **`getcwd(char *buf, size_t size)`:** 获取当前工作目录的绝对路径名。 **安全隐患:** 如果 `buf` 缓冲区太小，会导致缓冲区溢出。
* **`pread(int fd, void *buf, size_t count, off_t offset)`:** 从文件描述符 `fd` 的指定偏移量 `offset` 处读取 `count` 个字节到缓冲区 `buf`。 **安全隐患:** 如果 `buf` 缓冲区太小，可能会导致缓冲区溢出。
* **`pread64(int fd, void *buf, size_t count, off64_t offset)`:** `pread` 的 64 位偏移版本。
* **`pwrite(int fd, const void *buf, size_t count, off_t offset)`:** 将缓冲区 `buf` 中的 `count` 个字节写入到文件描述符 `fd` 的指定偏移量 `offset` 处。
* **`pwrite64(int fd, const void *buf, size_t count, off64_t offset)`:** `pwrite` 的 64 位偏移版本。
* **`read(int fd, void *buf, size_t count)`:** 从文件描述符 `fd` 读取最多 `count` 个字节到缓冲区 `buf`。 **安全隐患:** 如果 `buf` 缓冲区太小，可能会导致缓冲区溢出。
* **`write(int fd, const void *buf, size_t count)`:** 将缓冲区 `buf` 中的 `count` 个字节写入到文件描述符 `fd`。
* **`fread(void *ptr, size_t size, size_t count, FILE *stream)`:** 从文件流 `stream` 中读取最多 `count` 个大小为 `size` 的元素到缓冲区 `ptr`。 **安全隐患:** 如果 `ptr` 缓冲区太小，可能会导致缓冲区溢出。
* **`fwrite(const void *ptr, size_t size, size_t count, FILE *stream)`:** 将缓冲区 `ptr` 中的 `count` 个大小为 `size` 的元素写入到文件流 `stream`。
* **`readlink(const char *pathname, char *buf, size_t bufsiz)`:** 读取符号链接 `pathname` 的目标路径名。 **安全隐患:** 如果 `buf` 缓冲区太小，会导致缓冲区溢出。
* **`readlinkat(int dirfd, const char *pathname, char *buf, size_t bufsiz)`:** 相对于目录文件描述符 `dirfd` 读取符号链接。
* **`poll(struct pollfd *fds, nfds_t nfds, int timeout)`:**  等待一组文件描述符上的事件。
* **`ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *tmo_p, const sigset_t *sigmask)`:** 类似于 `poll`，但允许使用更精细的超时控制和信号屏蔽。
* **`ppoll64(...)`:** `ppoll` 的 64 位版本（在某些系统上）。
* **`open(const char *pathname, int flags, ... /* mode_t mode */)`:** 打开或创建文件。 **安全隐患:**  如果使用 `O_CREAT` 或 `O_TMPFILE` 标志但不提供 `mode` 参数，可能导致创建的文件权限不安全。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `fortify_test.cpp` 主要测试 libc 函数，但这些函数最终会被编译到 `libc.so` 共享库中，并由动态链接器加载和链接。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text          # 包含代码段
        strcpy:     # strcpy 函数的机器码
            ...
        sprintf:    # sprintf 函数的机器码
            ...
        __strcpy_chk: # strcpy 的 fortified 版本 (可能名称会有所不同)
            ...
        __sprintf_chk: # sprintf 的 fortified 版本
            ...
        ... 其他 libc 函数 ...

    .rodata        # 包含只读数据，例如字符串常量

    .data          # 包含已初始化的全局变量

    .bss           # 包含未初始化的全局变量

    .dynamic       # 包含动态链接信息，例如依赖的库、符号表等

    .symtab        # 符号表，包含导出的和导入的符号信息
        strcpy (address in .text)
        sprintf (address in .text)
        __strcpy_chk (address in .text)
        __sprintf_chk (address in .text)
        ...

    .strtab        # 字符串表，存储符号名称等
        strcpy
        sprintf
        __strcpy_chk
        __sprintf_chk
        ...

    .rel.dyn       # 动态重定位表
    .rel.plt       # PLT (Procedure Linkage Table) 重定位表
```

**链接的处理过程:**

1. **编译:**  当编译一个使用 libc 函数的 Android 应用或库时，编译器会生成对这些函数的未解析引用。例如，如果代码中调用了 `strcpy`，编译器会生成一个指向 `strcpy` 符号的引用。

2. **链接:** 链接器（在 Android 上是 `lld`）在构建可执行文件或共享库时，需要解析这些未解析的符号。对于 libc 函数，链接器知道这些符号位于 `libc.so` 中。

3. **动态链接:** 当 Android 启动一个应用程序或加载一个共享库时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载所有必要的共享库，包括 `libc.so`。

4. **符号解析和重定位:** 动态链接器会遍历可执行文件和共享库的 `.dynamic` 段，找到依赖的库。然后加载这些库到内存中。接下来，动态链接器会解析符号引用。例如，当遇到对 `strcpy` 的引用时，动态链接器会在 `libc.so` 的符号表 (`.symtab`) 中查找 `strcpy` 符号，并获取其在 `libc.so` 中的地址。

5. **重定位:**  由于共享库被加载到内存中的地址可能每次都不同（ASLR - 地址空间布局随机化），动态链接器需要修改可执行文件和共享库中的代码和数据，以反映实际的加载地址。这包括更新函数调用地址等。对于 PLT 条目，当第一次调用一个外部函数时，会触发动态链接器去解析该符号的实际地址。

6. **Fortification 的影响:**  当启用了 fortification (例如，通过编译器标志 `-D_FORTIFY_SOURCE=2`) 时，编译器会将对某些不安全函数的调用替换为对其 fortified 版本的调用。例如，对 `strcpy` 的调用可能会被替换为对 `__strcpy_chk` 的调用。这些 fortified 版本会在运行时执行额外的安全检查，例如检查目标缓冲区的大小。

**假设输入与输出 (针对单个测试用例):**

以 `TEST_F(DEATHTEST, strcpy_fortified)` 为例：

* **假设输入:**
    * `buf`: 一个大小为 10 的字符数组。
    * `orig`: 指向字符串 "0123456789" 的指针 (长度为 10，不包括空字符，加上空字符为 11)。
* **预期行为:**  `strcpy(buf, orig)` 会尝试将 11 个字节（包括空字符）写入到只能容纳 10 个字节的 `buf` 中。
* **预期输出:**  由于启用了 fortification，Bionic 的安全检查应该会检测到缓冲区溢出，并调用 `__fortify_fail` 函数，最终导致程序因为收到 `SIGABRT` 信号而终止。  `ASSERT_FORTIFY` 宏会捕捉到这个信号，并使测试通过。

**涉及用户或者编程常见的使用错误，请举例说明:**

`fortify_test.cpp` 中的测试用例直接反映了常见的 C/C++ 编程错误，这些错误可能导致安全漏洞：

1. **缓冲区溢出:**  使用 `strcpy`, `strcat`, `sprintf` 等函数时，没有仔细检查目标缓冲区的大小，导致写入的数据超出缓冲区边界。
    ```c
    char buf[10];
    strcpy(buf, "This string is too long"); // 缓冲区溢出
    ```

2. **使用未指定大小限制的字符串函数:**  过度依赖像 `strcpy` 这样的函数，而不是使用更安全的替代品，如 `strncpy` 或 `strlcpy`，并提供明确的大小限制。

3. **格式化字符串漏洞:**  将用户提供的输入直接用作 `printf` 或 `sprintf` 的格式化字符串。
    ```c
    char format_string[100];
    scanf("%99s", format_string); // 用户输入 "%x %x %x %x"
    printf(format_string); // 格式化字符串漏洞
    ```

4. **内存操作错误:**  在使用 `memcpy` 或 `memset` 时，指定了错误的缓冲区大小或复制长度。

5. **假设字符串以空字符结尾:**  在某些操作中，假设字符数组总是以空字符结尾，但实际上并非如此，导致字符串处理函数读取超出预期范围的内存。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 或 NDK 调用:**
   - **Android Framework:**  Android Framework 的 Java 代码最终会调用 Native 方法（通过 JNI）。这些 Native 方法通常会调用 Bionic 提供的 libc 函数。例如，文件操作、网络操作、字符串处理等。
   - **NDK:**  使用 NDK 开发的应用程序直接使用 C/C++ 代码，并可以直接调用 Bionic 的 libc 函数。

2. **系统调用:**  当 Native 代码调用 libc 函数时，某些 libc 函数会执行系统调用，与 Linux 内核进行交互。例如，`open`, `read`, `write`, `send`, `recv` 等。

3. **Bionic libc 实现:**  libc 函数的实际实现位于 Bionic 库中。例如，`strcpy` 的实现在 `bionic/libc/bionic/strcpy.cpp` 中（或者其汇编版本）。

4. **Fortification 检查:** 如果启用了 fortification，并且调用的是需要进行安全检查的函数，Bionic 的 fortification 机制会在函数执行过程中插入额外的检查。例如，在 `strcpy` 的 fortified 版本中，会检查目标缓冲区的大小是否足够容纳源字符串。

5. **触发 `__fortify_fail`:** 如果 fortification 检查发现潜在的安全问题（例如缓冲区溢出），会调用 `__fortify_fail` 函数。

6. **程序终止:** `__fortify_fail` 函数通常会打印错误信息并调用 `abort()` 函数，导致程序接收到 `SIGABRT` 信号并终止。

**Frida Hook 示例调试:**

可以使用 Frida 来 hook 这些 libc 函数，观察其参数、返回值，以及 fortification 机制是否被触发。

**示例 Hook `strcpy` 和 `__strcpy_chk`:**

```python
import frida
import sys

package_name = "your.target.package"  # 替换为你的目标应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "strcpy"), {
    onEnter: function(args) {
        console.log("[strcpy] Called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\\n"));
        console.log("[strcpy] Destination: " + args[0]);
        console.log("[strcpy] Source: " + args[1].readUtf8String());
    },
    onLeave: function(retval) {
        console.log("[strcpy] Return value: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "__strcpy_chk"), {
    onEnter: function(args) {
        console.log("[__strcpy_chk] Called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\\n"));
        console.log("[__strcpy_chk] Destination: " + args[0]);
        console.log("[__strcpy_chk] Source: " + args[1].readUtf8String());
        console.log("[__strcpy_chk] Dest size: " + args[2]);
    },
    onLeave: function(retval) {
        console.log("[__strcpy_chk] Return value: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "__fortify_fail"), {
    onEnter: function(args) {
        console.log("[__fortify_fail] Fortification check failed!");
        console.log("[__fortify_fail] Called from: " + Thread.backtrace(this.context).map(DebugSymbol.fromAddress).join("\\n"));
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用说明:**

1. 将 `your.target.package` 替换为你要调试的 Android 应用的包名。
2. 确保你的 Android 设备已连接并通过 USB 授权。
3. 运行这个 Frida 脚本。
4. 在 Android 应用中执行可能触发 `strcpy` 或 `__strcpy_chk` 的操作。
5. Frida 会打印出 `strcpy` 和 `__strcpy_chk` 函数的调用信息，包括参数和调用堆栈。
6. 如果 fortification 机制被触发，你会看到 `__fortify_fail` 的调用信息。

通过这种方式，你可以观察 Android Framework 或 NDK 代码如何调用 libc 函数，以及 Bionic 的 fortification 机制在何时被激活。你可以根据需要 hook 其他 libc 函数，例如 `sprintf`, `memcpy` 等，以进行更深入的调试和分析。

Prompt: 
```
这是目录为bionic/tests/fortify_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
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

#include <gtest/gtest.h>

#include <fcntl.h>
#include <malloc.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <android-base/silent_death_test.h>

#if defined(__BIONIC__)
#define ASSERT_FORTIFY(expr) ASSERT_EXIT(expr, testing::KilledBySignal(SIGABRT), "FORTIFY")
#else
#define ASSERT_FORTIFY(expr) ASSERT_EXIT(expr, testing::KilledBySignal(SIGABRT), "")
#endif

// Fortify test code needs to run multiple times, so TEST_NAME macro is used to
// distinguish different tests. TEST_NAME is defined in compilation command.
#define DEATHTEST_PASTER(name) name##_DeathTest
#define DEATHTEST_EVALUATOR(name) DEATHTEST_PASTER(name)
#define DEATHTEST DEATHTEST_EVALUATOR(TEST_NAME)

using DEATHTEST = SilentDeathTest;

#if defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE == 2
struct foo {
  char empty[0];
  char one[1];
  char a[10];
  char b[10];
};

TEST_F(DEATHTEST, stpncpy_fortified2) {
  foo myfoo;
  int copy_amt = atoi("11");
  ASSERT_FORTIFY(stpncpy(myfoo.a, "01234567890", copy_amt));
}

TEST_F(DEATHTEST, stpncpy2_fortified2) {
  foo myfoo = {};
  myfoo.one[0] = 'A'; // not null terminated string
  ASSERT_FORTIFY(stpncpy(myfoo.b, myfoo.one, sizeof(myfoo.b)));
}

TEST_F(DEATHTEST, strncpy_fortified2) {
  foo myfoo;
  int copy_amt = atoi("11");
  ASSERT_FORTIFY(strncpy(myfoo.a, "01234567890", copy_amt));
}

TEST_F(DEATHTEST, strncpy2_fortified2) {
  foo myfoo = {};
  myfoo.one[0] = 'A'; // not null terminated string
  ASSERT_FORTIFY(strncpy(myfoo.b, myfoo.one, sizeof(myfoo.b)));
}

TEST_F(DEATHTEST, sprintf_fortified2) {
  foo myfoo;
  char source_buf[15];
  memcpy(source_buf, "12345678901234", 15);
  ASSERT_FORTIFY(sprintf(myfoo.a, "%s", source_buf));
}

TEST_F(DEATHTEST, sprintf2_fortified2) {
  foo myfoo;
  ASSERT_FORTIFY(sprintf(myfoo.a, "0123456789"));
}

static int vsprintf_helper2(const char *fmt, ...) {
  foo myfoo;
  va_list va;
  int result;

  va_start(va, fmt);
  result = vsprintf(myfoo.a, fmt, va); // should crash here
  va_end(va);
  return result;
}

TEST_F(DEATHTEST, vsprintf_fortified2) {
  ASSERT_FORTIFY(vsprintf_helper2("%s", "0123456789"));
}

TEST_F(DEATHTEST, vsprintf2_fortified2) {
  ASSERT_FORTIFY(vsprintf_helper2("0123456789"));
}

static int vsnprintf_helper2(const char *fmt, ...) {
  foo myfoo;
  va_list va;
  int result;
  size_t size = atoi("11");

  va_start(va, fmt);
  result = vsnprintf(myfoo.a, size, fmt, va); // should crash here
  va_end(va);
  return result;
}

TEST_F(DEATHTEST, vsnprintf_fortified2) {
  ASSERT_FORTIFY(vsnprintf_helper2("%s", "0123456789"));
}

TEST_F(DEATHTEST, vsnprintf2_fortified2) {
  ASSERT_FORTIFY(vsnprintf_helper2("0123456789"));
}

// zero sized target with "\0" source (should fail)
TEST_F(DEATHTEST, stpcpy_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  char* src = strdup("");
  ASSERT_FORTIFY(stpcpy(myfoo.empty, src));
  free(src);
#else // __BIONIC__
  GTEST_SKIP() << "stpcpy not available";
#endif // __BIONIC__
}

// zero sized target with "\0" source (should fail)
TEST_F(DEATHTEST, strcpy_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  char* src = strdup("");
  ASSERT_FORTIFY(strcpy(myfoo.empty, src));
  free(src);
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

// zero sized target with longer source (should fail)
TEST_F(DEATHTEST, strcpy2_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  char* src = strdup("1");
  ASSERT_FORTIFY(strcpy(myfoo.empty, src));
  free(src);
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

// one byte target with longer source (should fail)
TEST_F(DEATHTEST, strcpy3_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  char* src = strdup("12");
  ASSERT_FORTIFY(strcpy(myfoo.one, src));
  free(src);
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strchr_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  memcpy(myfoo.a, "0123456789", sizeof(myfoo.a));
  myfoo.b[0] = '\0';
  ASSERT_FORTIFY(printf("%s", strchr(myfoo.a, 'a')));
  ASSERT_FORTIFY(printf("%s", strchr(static_cast<const char*>(myfoo.a), 'a')));
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strrchr_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  memcpy(myfoo.a, "0123456789", 10);
  memcpy(myfoo.b, "01234", 6);
  ASSERT_FORTIFY(printf("%s", strrchr(myfoo.a, 'a')));
  ASSERT_FORTIFY(printf("%s", strrchr(static_cast<const char*>(myfoo.a), 'a')));
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, memchr_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  volatile int asize = sizeof(myfoo.a) + 1;
  memcpy(myfoo.a, "0123456789", sizeof(myfoo.a));
  ASSERT_FORTIFY(printf("%s", static_cast<const char*>(memchr(myfoo.a, 'a', asize))));
  ASSERT_FORTIFY(printf(
      "%s", static_cast<const char*>(memchr(static_cast<const void*>(myfoo.a), 'a', asize))));
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, memrchr_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  volatile int asize = sizeof(myfoo.a) + 1;
  memcpy(myfoo.a, "0123456789", sizeof(myfoo.a));
  ASSERT_FORTIFY(printf("%s", static_cast<const char*>(memrchr(myfoo.a, 'a', asize))));
  ASSERT_FORTIFY(printf(
      "%s", static_cast<const char*>(memrchr(static_cast<const void*>(myfoo.a), 'a', asize))));
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strlcpy_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  strcpy(myfoo.a, "01");
  size_t n = strlen(myfoo.a);
  ASSERT_FORTIFY(strlcpy(myfoo.one, myfoo.a, n));
#else // __BIONIC__
  GTEST_SKIP() << "strlcpy not available";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strlcat_fortified2) {
#if defined(__BIONIC__)
  foo myfoo;
  strcpy(myfoo.a, "01");
  myfoo.one[0] = '\0';
  size_t n = strlen(myfoo.a);
  ASSERT_FORTIFY(strlcat(myfoo.one, myfoo.a, n));
#else // __BIONIC__
  GTEST_SKIP() << "strlcat not available";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strncat_fortified2) {
  foo myfoo;
  size_t n = atoi("10"); // avoid compiler optimizations
  strncpy(myfoo.a, "012345678", n);
  ASSERT_FORTIFY(strncat(myfoo.a, "9", n));
}

TEST_F(DEATHTEST, strncat2_fortified2) {
  foo myfoo;
  myfoo.a[0] = '\0';
  size_t n = atoi("10"); // avoid compiler optimizations
  ASSERT_FORTIFY(strncat(myfoo.a, "0123456789", n));
}

TEST_F(DEATHTEST, strncat3_fortified2) {
  foo myfoo;
  memcpy(myfoo.a, "0123456789", sizeof(myfoo.a)); // unterminated string
  myfoo.b[0] = '\0';
  size_t n = atoi("10"); // avoid compiler optimizations
  ASSERT_FORTIFY(strncat(myfoo.b, myfoo.a, n));
}

TEST_F(DEATHTEST, strcat_fortified2) {
  char src[11];
  strcpy(src, "0123456789");
  foo myfoo;
  myfoo.a[0] = '\0';
  ASSERT_FORTIFY(strcat(myfoo.a, src));
}

TEST_F(DEATHTEST, strcat2_fortified2) {
  foo myfoo;
  memcpy(myfoo.a, "0123456789", sizeof(myfoo.a)); // unterminated string
  myfoo.b[0] = '\0';
  ASSERT_FORTIFY(strcat(myfoo.b, myfoo.a));
}

TEST_F(DEATHTEST, snprintf_fortified2) {
  foo myfoo;
  strcpy(myfoo.a, "012345678");
  size_t n = strlen(myfoo.a) + 2;
  ASSERT_FORTIFY(snprintf(myfoo.b, n, "a%s", myfoo.a));
}

TEST_F(DEATHTEST, bzero_fortified2) {
  foo myfoo;
  memcpy(myfoo.b, "0123456789", sizeof(myfoo.b));
  size_t n = atoi("11");
  ASSERT_FORTIFY(bzero(myfoo.b, n));
}

#endif /* defined(_FORTIFY_SOURCE) && _FORTIFY_SOURCE=2 */

// multibyte target where we over fill (should fail)
TEST_F(DEATHTEST, strcpy_fortified) {
#if defined(__BIONIC__)
  char buf[10];
  char *orig = strdup("0123456789");
  ASSERT_FORTIFY(strcpy(buf, orig));
  free(orig);
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

// zero sized target with "\0" source (should fail)
TEST_F(DEATHTEST, strcpy2_fortified) {
#if defined(__BIONIC__)
  char buf[0];
  char *orig = strdup("");
  ASSERT_FORTIFY(strcpy(buf, orig));
  free(orig);
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

// zero sized target with longer source (should fail)
TEST_F(DEATHTEST, strcpy3_fortified) {
#if defined(__BIONIC__)
  char buf[0];
  char *orig = strdup("1");
  ASSERT_FORTIFY(strcpy(buf, orig));
  free(orig);
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

// one byte target with longer source (should fail)
TEST_F(DEATHTEST, strcpy4_fortified) {
#if defined(__BIONIC__)
  char buf[1];
  char *orig = strdup("12");
  ASSERT_FORTIFY(strcpy(buf, orig));
  free(orig);
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strlen_fortified) {
#if defined(__BIONIC__)
  char buf[10];
  memcpy(buf, "0123456789", sizeof(buf));
  ASSERT_FORTIFY(printf("%zd", strlen(buf)));
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strchr_fortified) {
#if defined(__BIONIC__)
  char buf[10];
  memcpy(buf, "0123456789", sizeof(buf));
  ASSERT_FORTIFY(printf("%s", strchr(buf, 'a')));
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strrchr_fortified) {
#if defined(__BIONIC__)
  char buf[10];
  memcpy(buf, "0123456789", sizeof(buf));
  ASSERT_FORTIFY(printf("%s", strrchr(buf, 'a')));
#else // __BIONIC__
  GTEST_SKIP() << "glibc is broken";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strlcpy_fortified) {
#if defined(__BIONIC__)
  char bufa[15];
  char bufb[10];
  strcpy(bufa, "01234567890123");
  size_t n = strlen(bufa);
  ASSERT_FORTIFY(strlcpy(bufb, bufa, n));
#else // __BIONIC__
  GTEST_SKIP() << "strlcpy not available";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, strlcat_fortified) {
#if defined(__BIONIC__)
  char bufa[15];
  char bufb[10];
  bufb[0] = '\0';
  strcpy(bufa, "01234567890123");
  size_t n = strlen(bufa);
  ASSERT_FORTIFY(strlcat(bufb, bufa, n));
#else // __BIONIC__
  GTEST_SKIP() << "strlcat not available";
#endif // __BIONIC__
}

TEST_F(DEATHTEST, sprintf_fortified) {
  char buf[10];
  char source_buf[15];
  memcpy(source_buf, "12345678901234", 15);
  ASSERT_FORTIFY(sprintf(buf, "%s", source_buf));
}

TEST_F(DEATHTEST, sprintf_malloc_fortified) {
  char* buf = (char *) malloc(10);
  char source_buf[11];
  memcpy(source_buf, "1234567890", 11);
  ASSERT_FORTIFY(sprintf(buf, "%s", source_buf));
  free(buf);
}

TEST_F(DEATHTEST, sprintf2_fortified) {
  char buf[5];
  ASSERT_FORTIFY(sprintf(buf, "aaaaa"));
}

static int vsprintf_helper(const char *fmt, ...) {
  char buf[10];
  va_list va;
  int result;

  va_start(va, fmt);
  result = vsprintf(buf, fmt, va); // should crash here
  va_end(va);
  return result;
}

TEST_F(DEATHTEST, vsprintf_fortified) {
  ASSERT_FORTIFY(vsprintf_helper("%s", "0123456789"));
}

TEST_F(DEATHTEST, vsprintf2_fortified) {
  ASSERT_FORTIFY(vsprintf_helper("0123456789"));
}

static int vsnprintf_helper(const char *fmt, ...) {
  char buf[10];
  va_list va;
  int result;
  size_t size = atoi("11");

  va_start(va, fmt);
  result = vsnprintf(buf, size, fmt, va); // should crash here
  va_end(va);
  return result;
}

TEST_F(DEATHTEST, vsnprintf_fortified) {
  ASSERT_FORTIFY(vsnprintf_helper("%s", "0123456789"));
}

TEST_F(DEATHTEST, vsnprintf2_fortified) {
  ASSERT_FORTIFY(vsnprintf_helper("0123456789"));
}

TEST_F(DEATHTEST, strncat_fortified) {
  char buf[10];
  size_t n = atoi("10"); // avoid compiler optimizations
  strncpy(buf, "012345678", n);
  ASSERT_FORTIFY(strncat(buf, "9", n));
}

TEST_F(DEATHTEST, strncat2_fortified) {
  char buf[10];
  buf[0] = '\0';
  size_t n = atoi("10"); // avoid compiler optimizations
  ASSERT_FORTIFY(strncat(buf, "0123456789", n));
}

TEST_F(DEATHTEST, strcat_fortified) {
  char src[11];
  strcpy(src, "0123456789");
  char buf[10];
  buf[0] = '\0';
  ASSERT_FORTIFY(strcat(buf, src));
}

TEST_F(DEATHTEST, memmove_fortified) {
  char buf[20];
  strcpy(buf, "0123456789");
  size_t n = atoi("10");
  ASSERT_FORTIFY(memmove(buf + 11, buf, n));
}

TEST_F(DEATHTEST, memcpy_fortified) {
  char bufa[10];
  char bufb[10];
  strcpy(bufa, "012345678");
  size_t n = atoi("11");
  ASSERT_FORTIFY(memcpy(bufb, bufa, n));
}

TEST_F(DEATHTEST, memset_fortified) {
  char buf[10];
  size_t n = atoi("11");
  ASSERT_FORTIFY(memset(buf, 0, n));
}

TEST_F(DEATHTEST, stpncpy_fortified) {
  char bufa[15];
  char bufb[10];
  strcpy(bufa, "01234567890123");
  size_t n = strlen(bufa);
  ASSERT_FORTIFY(stpncpy(bufb, bufa, n));
}

TEST_F(DEATHTEST, stpncpy2_fortified) {
  char dest[11];
  char src[10];
  memcpy(src, "0123456789", sizeof(src)); // src is not null terminated
  ASSERT_FORTIFY(stpncpy(dest, src, sizeof(dest)));
}

TEST_F(DEATHTEST, strncpy_fortified) {
  char bufa[15];
  char bufb[10];
  strcpy(bufa, "01234567890123");
  size_t n = strlen(bufa);
  ASSERT_FORTIFY(strncpy(bufb, bufa, n));
}


TEST_F(DEATHTEST, strncpy2_fortified) {
  char dest[11];
  char src[10];
  memcpy(src, "0123456789", sizeof(src)); // src is not null terminated
  ASSERT_FORTIFY(strncpy(dest, src, sizeof(dest)));
}

TEST_F(DEATHTEST, snprintf_fortified) {
  char bufa[15];
  char bufb[10];
  strcpy(bufa, "0123456789");
  size_t n = strlen(bufa) + 1;
  ASSERT_FORTIFY(snprintf(bufb, n, "%s", bufa));
}

TEST_F(DEATHTEST, bzero_fortified) {
  char buf[10];
  memcpy(buf, "0123456789", sizeof(buf));
  size_t n = atoi("11");
  ASSERT_FORTIFY(bzero(buf, n));
}

TEST_F(DEATHTEST, umask_fortified) {
  mode_t mask = atoi("1023");  // 01777 in octal
  ASSERT_FORTIFY(umask(mask));
}

TEST_F(DEATHTEST, recv_fortified) {
  size_t data_len = atoi("11"); // suppress compiler optimizations
  char buf[10];
  ASSERT_FORTIFY(recv(0, buf, data_len, 0));
}

TEST_F(DEATHTEST, send_fortified) {
  size_t data_len = atoi("11"); // suppress compiler optimizations
  char buf[10] = {0};
  ASSERT_FORTIFY(send(0, buf, data_len, 0));
}

TEST_F(DEATHTEST, FD_ISSET_fortified) {
#if defined(__BIONIC__) // glibc catches this at compile-time.
  fd_set set = {};
  ASSERT_FORTIFY(FD_ISSET(-1, &set));
#endif
}

TEST_F(DEATHTEST, FD_ISSET_2_fortified) {
  char buf[1];
  fd_set* set = (fd_set*) buf;
  ASSERT_FORTIFY(FD_ISSET(0, set));
}

TEST_F(DEATHTEST, getcwd_fortified) {
  char buf[1];
  size_t ct = atoi("2"); // prevent optimizations
  ASSERT_FORTIFY(getcwd(buf, ct));
}

TEST_F(DEATHTEST, pread_fortified) {
  char buf[1];
  size_t ct = atoi("2"); // prevent optimizations
  int fd = open("/dev/null", O_RDONLY);
  ASSERT_FORTIFY(pread(fd, buf, ct, 0));
  close(fd);
}

TEST_F(DEATHTEST, pread64_fortified) {
  char buf[1];
  size_t ct = atoi("2"); // prevent optimizations
  int fd = open("/dev/null", O_RDONLY);
  ASSERT_FORTIFY(pread64(fd, buf, ct, 0));
  close(fd);
}

TEST_F(DEATHTEST, pwrite_fortified) {
  char buf[1] = {0};
  size_t ct = atoi("2"); // prevent optimizations
  int fd = open("/dev/null", O_WRONLY);
  ASSERT_FORTIFY(pwrite(fd, buf, ct, 0));
  close(fd);
}

TEST_F(DEATHTEST, pwrite64_fortified) {
  char buf[1] = {0};
  size_t ct = atoi("2"); // prevent optimizations
  int fd = open("/dev/null", O_WRONLY);
  ASSERT_FORTIFY(pwrite64(fd, buf, ct, 0));
  close(fd);
}

TEST_F(DEATHTEST, read_fortified) {
  char buf[1];
  size_t ct = atoi("2"); // prevent optimizations
  int fd = open("/dev/null", O_RDONLY);
  ASSERT_FORTIFY(read(fd, buf, ct));
  close(fd);
}

TEST_F(DEATHTEST, write_fortified) {
  char buf[1] = {0};
  size_t ct = atoi("2"); // prevent optimizations
  int fd = open("/dev/null", O_WRONLY);
  ASSERT_EXIT(write(fd, buf, ct), testing::KilledBySignal(SIGABRT), "");
  close(fd);
}

TEST_F(DEATHTEST, fread_fortified) {
  char buf[1];
  size_t ct = atoi("2"); // prevent optimizations
  FILE* fp = fopen("/dev/null", "r");
  ASSERT_FORTIFY(fread(buf, 1, ct, fp));
  fclose(fp);
}

TEST_F(DEATHTEST, fwrite_fortified) {
  char buf[1] = {0};
  size_t ct = atoi("2"); // prevent optimizations
  FILE* fp = fopen("/dev/null", "w");
  ASSERT_FORTIFY(fwrite(buf, 1, ct, fp));
  fclose(fp);
}

TEST_F(DEATHTEST, readlink_fortified) {
  char buf[1];
  size_t ct = atoi("2"); // prevent optimizations
  ASSERT_FORTIFY(readlink("/dev/null", buf, ct));
}

TEST_F(DEATHTEST, readlinkat_fortified) {
  char buf[1];
  size_t ct = atoi("2"); // prevent optimizations
  ASSERT_FORTIFY(readlinkat(AT_FDCWD, "/dev/null", buf, ct));
}

TEST(TEST_NAME, snprintf_nullptr_valid) {
  ASSERT_EQ(10, snprintf(nullptr, 0, "0123456789"));
}

extern "C" char* __strncat_chk(char*, const char*, size_t, size_t);
extern "C" char* __strcat_chk(char*, const char*, size_t);

TEST(TEST_NAME, strncat) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = __strncat_chk(buf, "01234", sizeof(buf) - strlen(buf) - 1, sizeof(buf));
  ASSERT_EQ(buf, res);
  ASSERT_EQ('a',  buf[0]);
  ASSERT_EQ('0',  buf[1]);
  ASSERT_EQ('1',  buf[2]);
  ASSERT_EQ('2',  buf[3]);
  ASSERT_EQ('3',  buf[4]);
  ASSERT_EQ('4',  buf[5]);
  ASSERT_EQ('\0', buf[6]);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('A',  buf[9]);
}

TEST(TEST_NAME, strncat2) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = __strncat_chk(buf, "0123456789", 5, sizeof(buf));
  ASSERT_EQ(buf, res);
  ASSERT_EQ('a',  buf[0]);
  ASSERT_EQ('0',  buf[1]);
  ASSERT_EQ('1',  buf[2]);
  ASSERT_EQ('2',  buf[3]);
  ASSERT_EQ('3',  buf[4]);
  ASSERT_EQ('4',  buf[5]);
  ASSERT_EQ('\0', buf[6]);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('A',  buf[9]);
}

TEST(TEST_NAME, strncat3) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = '\0';
  char* res = __strncat_chk(buf, "0123456789", 5, sizeof(buf));
  ASSERT_EQ(buf, res);
  ASSERT_EQ('0',  buf[0]);
  ASSERT_EQ('1',  buf[1]);
  ASSERT_EQ('2',  buf[2]);
  ASSERT_EQ('3',  buf[3]);
  ASSERT_EQ('4',  buf[4]);
  ASSERT_EQ('\0', buf[5]);
  ASSERT_EQ('A',  buf[6]);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('A',  buf[9]);
}

TEST(TEST_NAME, strncat4) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[9] = '\0';
  char* res = __strncat_chk(buf, "", 5, sizeof(buf));
  ASSERT_EQ(buf, res);
  ASSERT_EQ('A',  buf[0]);
  ASSERT_EQ('A',  buf[1]);
  ASSERT_EQ('A',  buf[2]);
  ASSERT_EQ('A',  buf[3]);
  ASSERT_EQ('A',  buf[4]);
  ASSERT_EQ('A',  buf[5]);
  ASSERT_EQ('A',  buf[6]);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('\0', buf[9]);
}

TEST(TEST_NAME, strncat5) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = __strncat_chk(buf, "01234567", 8, sizeof(buf));
  ASSERT_EQ(buf, res);
  ASSERT_EQ('a',  buf[0]);
  ASSERT_EQ('0',  buf[1]);
  ASSERT_EQ('1',  buf[2]);
  ASSERT_EQ('2',  buf[3]);
  ASSERT_EQ('3',  buf[4]);
  ASSERT_EQ('4',  buf[5]);
  ASSERT_EQ('5', buf[6]);
  ASSERT_EQ('6',  buf[7]);
  ASSERT_EQ('7',  buf[8]);
  ASSERT_EQ('\0',  buf[9]);
}

TEST(TEST_NAME, strncat6) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = __strncat_chk(buf, "01234567", 9, sizeof(buf));
  ASSERT_EQ(buf, res);
  ASSERT_EQ('a',  buf[0]);
  ASSERT_EQ('0',  buf[1]);
  ASSERT_EQ('1',  buf[2]);
  ASSERT_EQ('2',  buf[3]);
  ASSERT_EQ('3',  buf[4]);
  ASSERT_EQ('4',  buf[5]);
  ASSERT_EQ('5', buf[6]);
  ASSERT_EQ('6',  buf[7]);
  ASSERT_EQ('7',  buf[8]);
  ASSERT_EQ('\0',  buf[9]);
}


TEST(TEST_NAME, strcat) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = __strcat_chk(buf, "01234", sizeof(buf));
  ASSERT_EQ(buf, res);
  ASSERT_EQ('a',  buf[0]);
  ASSERT_EQ('0',  buf[1]);
  ASSERT_EQ('1',  buf[2]);
  ASSERT_EQ('2',  buf[3]);
  ASSERT_EQ('3',  buf[4]);
  ASSERT_EQ('4',  buf[5]);
  ASSERT_EQ('\0', buf[6]);
  ASSERT_EQ('A',  buf[7]);
  ASSERT_EQ('A',  buf[8]);
  ASSERT_EQ('A',  buf[9]);
}

TEST(TEST_NAME, strcat2) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = __strcat_chk(buf, "01234567", sizeof(buf));
  ASSERT_EQ(buf, res);
  ASSERT_EQ('a',  buf[0]);
  ASSERT_EQ('0',  buf[1]);
  ASSERT_EQ('1',  buf[2]);
  ASSERT_EQ('2',  buf[3]);
  ASSERT_EQ('3',  buf[4]);
  ASSERT_EQ('4',  buf[5]);
  ASSERT_EQ('5', buf[6]);
  ASSERT_EQ('6',  buf[7]);
  ASSERT_EQ('7',  buf[8]);
  ASSERT_EQ('\0',  buf[9]);
}

TEST(TEST_NAME, stpncpy) {
  char src[10];
  char dst[10];
  memcpy(src, "0123456789", sizeof(src)); // non null terminated string
  stpncpy(dst, src, sizeof(dst));
  ASSERT_EQ('0', dst[0]);
  ASSERT_EQ('1', dst[1]);
  ASSERT_EQ('2', dst[2]);
  ASSERT_EQ('3', dst[3]);
  ASSERT_EQ('4', dst[4]);
  ASSERT_EQ('5', dst[5]);
  ASSERT_EQ('6', dst[6]);
  ASSERT_EQ('7', dst[7]);
  ASSERT_EQ('8', dst[8]);
  ASSERT_EQ('9', dst[9]);
}

TEST(TEST_NAME, stpncpy2) {
  char src[10];
  char dst[15];
  memcpy(src, "012345678\0", sizeof(src));
  stpncpy(dst, src, sizeof(dst));
  ASSERT_EQ('0',  dst[0]);
  ASSERT_EQ('1',  dst[1]);
  ASSERT_EQ('2',  dst[2]);
  ASSERT_EQ('3',  dst[3]);
  ASSERT_EQ('4',  dst[4]);
  ASSERT_EQ('5',  dst[5]);
  ASSERT_EQ('6',  dst[6]);
  ASSERT_EQ('7',  dst[7]);
  ASSERT_EQ('8',  dst[8]);
  ASSERT_EQ('\0', dst[9]);
  ASSERT_EQ('\0', dst[10]);
  ASSERT_EQ('\0', dst[11]);
  ASSERT_EQ('\0', dst[12]);
  ASSERT_EQ('\0', dst[13]);
  ASSERT_EQ('\0', dst[14]);
}

TEST(TEST_NAME, strncpy) {
  char src[10];
  char dst[10];
  memcpy(src, "0123456789", sizeof(src)); // non null terminated string
  strncpy(dst, src, sizeof(dst));
  ASSERT_EQ('0', dst[0]);
  ASSERT_EQ('1', dst[1]);
  ASSERT_EQ('2', dst[2]);
  ASSERT_EQ('3', dst[3]);
  ASSERT_EQ('4', dst[4]);
  ASSERT_EQ('5', dst[5]);
  ASSERT_EQ('6', dst[6]);
  ASSERT_EQ('7', dst[7]);
  ASSERT_EQ('8', dst[8]);
  ASSERT_EQ('9', dst[9]);
}

TEST(TEST_NAME, strncpy2) {
  char src[10];
  char dst[15];
  memcpy(src, "012345678\0", sizeof(src));
  strncpy(dst, src, sizeof(dst));
  ASSERT_EQ('0',  dst[0]);
  ASSERT_EQ('1',  dst[1]);
  ASSERT_EQ('2',  dst[2]);
  ASSERT_EQ('3',  dst[3]);
  ASSERT_EQ('4',  dst[4]);
  ASSERT_EQ('5',  dst[5]);
  ASSERT_EQ('6',  dst[6]);
  ASSERT_EQ('7',  dst[7]);
  ASSERT_EQ('8',  dst[8]);
  ASSERT_EQ('\0', dst[9]);
  ASSERT_EQ('\0', dst[10]);
  ASSERT_EQ('\0', dst[11]);
  ASSERT_EQ('\0', dst[12]);
  ASSERT_EQ('\0', dst[13]);
  ASSERT_EQ('\0', dst[14]);
}

TEST(TEST_NAME, strcat_chk_max_int_size) {
  char buf[10];
  memset(buf, 'A', sizeof(buf));
  buf[0] = 'a';
  buf[1] = '\0';
  char* res = __strcat_chk(buf, "01234567", (size_t)-1);
  ASSERT_EQ(buf, res);
  ASSERT_EQ('a',  buf[0]);
  ASSERT_EQ('0',  buf[1]);
  ASSERT_EQ('1',  buf[2]);
  ASSERT_EQ('2',  buf[3]);
  ASSERT_EQ('3',  buf[4]);
  ASSERT_EQ('4',  buf[5]);
  ASSERT_EQ('5',  buf[6]);
  ASSERT_EQ('6',  buf[7]);
  ASSERT_EQ('7',  buf[8]);
  ASSERT_EQ('\0', buf[9]);
}

TEST(TEST_NAME, mempcpy_chk) {
  const char input_str[] = "abcdefg";
  size_t input_str_size = strlen(input_str) + 1;

  char buf1[10] = {};
  char buf2[10] = {};

  __builtin_mempcpy(buf1, input_str, input_str_size);
  __builtin___mempcpy_chk(buf2, input_str, input_str_size, __bos0(buf2));

  ASSERT_EQ(memcmp(buf1, buf2, sizeof(buf2)), 0);

  void *builtin_ptr = __builtin_mempcpy(buf1, input_str, input_str_size);
  void *fortify_ptr = __builtin___mempcpy_chk(buf1, input_str, input_str_size, __bos0(buf2));

  ASSERT_EQ(builtin_ptr, fortify_ptr);
}

extern "C" char* __stpcpy_chk(char*, const char*, size_t);

TEST(TEST_NAME, stpcpy_chk_max_int_size) {
  char buf[10];
  char* res = __stpcpy_chk(buf, "012345678", (size_t)-1);
  ASSERT_EQ(buf + strlen("012345678"), res);
  ASSERT_STREQ("012345678", buf);
}

extern "C" char* __strcpy_chk(char*, const char*, size_t);

TEST(TEST_NAME, strcpy_chk_max_int_size) {
  char buf[10];
  char* res = __strcpy_chk(buf, "012345678", (size_t)-1);
  ASSERT_EQ(buf, res);
  ASSERT_STREQ("012345678", buf);
}

extern "C" void* __memcpy_chk(void*, const void*, size_t, size_t);

TEST(TEST_NAME, memcpy_chk_max_int_size) {
  char buf[10];
  void* res = __memcpy_chk(buf, "012345678", sizeof(buf), (size_t)-1);
  ASSERT_EQ((void*)buf, res);
  ASSERT_EQ('0',  buf[0]);
  ASSERT_EQ('1',  buf[1]);
  ASSERT_EQ('2',  buf[2]);
  ASSERT_EQ('3',  buf[3]);
  ASSERT_EQ('4',  buf[4]);
  ASSERT_EQ('5',  buf[5]);
  ASSERT_EQ('6',  buf[6]);
  ASSERT_EQ('7',  buf[7]);
  ASSERT_EQ('8',  buf[8]);
  ASSERT_EQ('\0', buf[9]);
}

// Verify that macro expansion is done properly for sprintf/snprintf (which
// are defined as macros in stdio.h under clang).
#define CONTENTS "macro expansion"
#define BUF_AND_SIZE(A) A, sizeof(A)
#define BUF_AND_CONTENTS(A) A, CONTENTS
#define BUF_AND_SIZE_AND_CONTENTS(A) A, sizeof(A), CONTENTS
TEST(TEST_NAME, s_n_printf_macro_expansion) {
  char buf[BUFSIZ];
  snprintf(BUF_AND_SIZE(buf), CONTENTS);
  EXPECT_STREQ(CONTENTS, buf);

  snprintf(BUF_AND_SIZE_AND_CONTENTS(buf));
  EXPECT_STREQ(CONTENTS, buf);

  sprintf(BUF_AND_CONTENTS(buf));
  EXPECT_STREQ(CONTENTS, buf);
}

TEST_F(DEATHTEST, poll_fortified) {
  nfds_t fd_count = atoi("2"); // suppress compiler optimizations
  pollfd buf[1] = {{0, POLLIN, 0}};
  // Set timeout to zero to prevent waiting in poll when fortify test fails.
  ASSERT_FORTIFY(poll(buf, fd_count, 0));
}

TEST_F(DEATHTEST, ppoll_fortified) {
  nfds_t fd_count = atoi("2"); // suppress compiler optimizations
  pollfd buf[1] = {{0, POLLIN, 0}};
  // Set timeout to zero to prevent waiting in ppoll when fortify test fails.
  timespec timeout;
  timeout.tv_sec = timeout.tv_nsec = 0;
  ASSERT_FORTIFY(ppoll(buf, fd_count, &timeout, nullptr));
}

TEST_F(DEATHTEST, ppoll64_fortified) {
#if defined(__BIONIC__)        // glibc doesn't have ppoll64.
  nfds_t fd_count = atoi("2"); // suppress compiler optimizations
  pollfd buf[1] = {{0, POLLIN, 0}};
  // Set timeout to zero to prevent waiting in ppoll when fortify test fails.
  timespec timeout;
  timeout.tv_sec = timeout.tv_nsec = 0;
  ASSERT_FORTIFY(ppoll64(buf, fd_count, &timeout, nullptr));
#endif
}

TEST_F(DEATHTEST, open_O_CREAT_without_mode_fortified) {
  int flags = O_CREAT; // Fool the compiler.
  ASSERT_FORTIFY(open("", flags));
}

TEST_F(DEATHTEST, open_O_TMPFILE_without_mode_fortified) {
  int flags = O_TMPFILE; // Fool the compiler.
  ASSERT_FORTIFY(open("", flags));
}

"""

```