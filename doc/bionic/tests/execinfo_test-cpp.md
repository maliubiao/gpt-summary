Response:
Let's break down the thought process for analyzing the `execinfo_test.cpp` file.

**1. Understanding the Goal:**

The primary request is to analyze the provided C++ test file (`execinfo_test.cpp`) for the Android bionic library. This means understanding its purpose, functionality, relationship to Android, how it uses libc functions, its interaction with the dynamic linker, potential errors, and how to debug it.

**2. Initial Code Scan - High-Level Overview:**

My first step is to quickly read through the code to get a general sense of what it's doing. I look for:

* **Includes:**  `dlfcn.h`, `execinfo.h`, `string.h`, standard C++ headers, and Android-specific headers. This immediately tells me it's testing functions related to dynamic linking and stack unwinding.
* **Test Structure:** The `TEST` macros suggest it's using Google Test (`gtest`). This tells me it's a unit test file.
* **Key Functions:**  `backtrace`, `backtrace_symbols`, `backtrace_symbols_fd`, `dladdr`. These are the core functions being tested.
* **Helper Functions:** `CallOne`, `CallTwo`, `DumpFrames`, `FindFunction`, `VerifyCalls`, `VerifyLineFormat`. These are used to set up test scenarios and verify results.
* **Assertions:** `ASSERT_*` and `EXPECT_*` macros are used for verifying expected behavior.

**3. Deciphering the Test Cases:**

Now, I go through each `TEST` case individually:

* **`backtrace_errors`:** Tests error handling of `backtrace` with invalid arguments (0 and -1). This is about robustness.
* **`backtrace`:** The core test for `backtrace`. It calls `CallOne`, which in turn calls `CallTwo`, and then uses `backtrace` to capture the stack frames. It then verifies the presence and order of these calls in the backtrace.
* **`backtrace_cutoff_frames`:**  Tests the behavior of `backtrace` when the provided buffer is too small.
* **`backtrace_symbols_errors`:** Tests error handling of `backtrace_symbols` with invalid arguments. It also notes a platform difference (glibc vs. bionic).
* **`backtrace_symbols`:** Tests the functionality of `backtrace_symbols` to convert addresses to human-readable strings. It checks the format of the output and verifies that the function names are present.
* **`backtrace_symbols_fd_errors`:** Tests error handling of `backtrace_symbols_fd`.
* **`backtrace_symbols_fd`:** Tests the functionality of `backtrace_symbols_fd` to write the symbolized backtrace to a file descriptor. It verifies the file content and format.

**4. Connecting to Android Functionality:**

At this point, I start connecting the tested functions to their role in Android.

* **`backtrace`:** Crucial for debugging crashes, generating error reports (like ANRs), and profiling. The example of catching crashes in production builds is a key illustration.
* **`backtrace_symbols` and `backtrace_symbols_fd`:**  Make the raw addresses from `backtrace` understandable. This is essential for developers analyzing crash logs. The connection to `logcat` is important.
* **`dladdr`:** Used internally by `backtrace_symbols` to get information about addresses. More generally, `dladdr` is a fundamental part of dynamic linking, allowing programs to introspect loaded libraries.

**5. Explaining libc Function Implementation:**

For each libc function, I consider:

* **Purpose:** What does it do?
* **Implementation (Simplified):**  I don't need to go into assembly-level details, but a conceptual understanding is necessary. For example, `backtrace` involves accessing stack frame pointers, and `dladdr` requires looking up information in the dynamic linker's data structures.
* **Underlying System Calls (if applicable):**  While not explicitly tested, I consider if the function relies on specific system calls.

**6. Dynamic Linker Aspects:**

* **`dladdr` is the key here.** I explain its role in resolving addresses to symbols and library information.
* **SO Layout Sample:**  I create a simple example to show how shared libraries are laid out in memory and how symbols are organized within them (GOT, PLT).
* **Linking Process:** I describe the basic steps of dynamic linking: loading, symbol resolution, and relocation.

**7. Assumptions, Inputs, and Outputs:**

For logical inferences, I consider the assumptions made by the tests (e.g., that `CallOne` and `CallTwo` will be on the stack). I look at the inputs to the tested functions (e.g., the frame buffer size) and the expected outputs (e.g., the number of frames returned, the format of the symbol strings).

**8. Common Errors:**

I think about how developers might misuse these functions:

* **Incorrect buffer size:**  Leading to truncation in `backtrace`.
* **Forgetting to free memory:**  A common issue with `backtrace_symbols`.
* **Interpreting symbolized output:**  Understanding the different parts of the output string is important.

**9. Android Framework and NDK:**

I trace how these functions are used from higher levels:

* **Framework:**  Highlighting crash reporting mechanisms like `Thread.UncaughtExceptionHandler`.
* **NDK:** Demonstrating direct use by native developers.

**10. Frida Hook Example:**

I create a simple Frida script to intercept `backtrace` and log its arguments and results. This provides a practical way to debug and observe the function's behavior.

**11. Language and Formatting:**

Finally, I ensure the response is in Chinese and well-formatted, addressing all aspects of the original request.

**Self-Correction/Refinement During the Process:**

* **Initially, I might focus too much on the `gtest` framework.** I need to remember that the core request is about the `execinfo` functions themselves.
* **I need to be careful about the level of detail.**  Going too deep into implementation details of the dynamic linker might be overwhelming. A high-level overview is usually sufficient.
* **The Android context is crucial.**  I need to make sure to tie the functionality back to how it's used within the Android ecosystem.
* **Clarity and examples are key.**  Using concrete examples, like the SO layout and the Frida script, makes the explanation easier to understand.

By following this structured approach, I can effectively analyze the code and provide a comprehensive and informative answer to the user's request.
这个文件 `bionic/tests/execinfo_test.cpp` 是 Android Bionic 库中用于测试 `execinfo.h` 头文件中声明的函数的单元测试。`execinfo.h` 提供了一些用于获取当前程序调用栈信息的功能。

**该文件的主要功能：**

1. **测试 `backtrace()` 函数:**
   - 测试在不同情况下 `backtrace()` 函数的正确性，例如传入无效的 `size` 参数（0 和负数）。
   - 测试 `backtrace()` 函数能够正确地捕获当前调用栈的地址信息。
   - 测试当提供的 `frames` 缓冲区大小不足以容纳所有栈帧时，`backtrace()` 函数的行为。

2. **测试 `backtrace_symbols()` 函数:**
   - 测试 `backtrace_symbols()` 函数能否将 `backtrace()` 返回的地址列表转换为可读的符号信息字符串。
   - 验证返回的符号信息字符串的格式是否正确，包括 ELF 文件名、函数名、偏移量和地址等。
   - 测试当传入无效的 `size` 参数时，`backtrace_symbols()` 函数是否返回 `nullptr`。
   - 针对 Bionic 和 glibc 在处理 `size` 为 0 时的差异进行了特定的测试。

3. **测试 `backtrace_symbols_fd()` 函数:**
   - 测试 `backtrace_symbols_fd()` 函数能否将符号信息写入到指定的文件描述符中。
   - 验证写入文件的符号信息格式是否正确。
   - 测试当传入无效的 `size` 参数或文件描述符时，`backtrace_symbols_fd()` 函数的行为（不写入任何数据）。

**与 Android 功能的关系及举例说明：**

`execinfo` 提供的功能对于 Android 系统至关重要，因为它被用于：

* **崩溃报告 (Crash Reporting):** 当应用或系统进程发生崩溃时，`backtrace()` 函数被用来收集调用栈信息，这些信息可以帮助开发者定位崩溃发生的位置和原因。例如，当一个 Java 应用发生 `NullPointerException` 时，底层的 Native 代码会调用 `backtrace()` 来记录当时的 C/C++ 调用栈。
* **性能分析 (Profiling):**  虽然 `execinfo` 提供的精度较低，但在某些情况下，可以使用 `backtrace()` 来采样程序的执行路径，辅助进行性能分析。例如，一个性能分析工具可能会周期性地调用 `backtrace()` 来了解程序最常执行的代码段。
* **调试 (Debugging):** 开发者可以使用 `backtrace()` 在程序运行时打印调用栈信息，帮助理解程序的执行流程。例如，在 Native 代码中使用 `__android_log_print` 结合 `backtrace()` 和 `backtrace_symbols_fd()` 可以方便地将调用栈信息输出到 logcat 中。
* **ANR (Application Not Responding) 检测:** 当应用主线程阻塞时，系统可能会收集应用的调用栈信息，以辅助开发者诊断 ANR 问题。

**示例说明:**

假设一个 Android Native 应用中发生了崩溃，底层的崩溃处理机制可能会调用 `backtrace()` 获取调用栈，然后调用 `backtrace_symbols()` 将地址转换为符号信息，最终将这些信息记录到系统的 tombstone 文件中。开发者可以通过分析 tombstone 文件中的调用栈信息来定位崩溃原因。

**详细解释每一个 libc 函数的功能是如何实现的:**

1. **`backtrace(void** buffer**, int size)`:**
   - **功能:**  尝试获取当前线程的调用栈信息，并将栈帧的返回地址存储到 `buffer` 指向的数组中。最多存储 `size` 个地址。
   - **实现原理:**
     - 该函数通常依赖于平台特定的机制来遍历栈帧。在基于 x86/x86_64 架构的系统中，它可能利用帧指针 (frame pointer, FP) 或 DWARF debugging information 来回溯调用栈。
     - 它从当前栈帧开始，通过帧指针或 DWARF 信息找到调用者的栈帧，然后获取调用者的返回地址。这个过程会一直重复，直到达到栈底或存储了 `size` 个地址。
     - Bionic 的实现会考虑到安全性和性能，可能有一些优化措施。
   - **假设输入与输出:**
     - **假设输入:** 当前函数被 `CallOne` 调用，`CallOne` 被 `main` 调用。`buffer` 指向一个大小为 10 的 `void*` 数组，`size` 为 10。
     - **假设输出:** `buffer` 中存储了 `main` 的返回地址，`CallOne` 的返回地址，当前函数的返回地址，以及可能更深层次的调用栈地址（如果栈更深）。返回值是实际存储的栈帧数量，可能小于等于 10。

2. **`backtrace_symbols(void* const* buffer, int size)`:**
   - **功能:** 将 `backtrace()` 返回的地址列表转换为可读的符号信息字符串数组。
   - **实现原理:**
     - 对于 `buffer` 中的每个地址，`backtrace_symbols()` 会尝试找到该地址所属的共享库 (SO 文件) 和在该 SO 文件中的符号信息。
     - 它会利用动态链接器提供的信息 (例如，通过 `dladdr()` 函数) 来查找地址所在的 SO 文件和符号。
     - 如果找到了符号，它会构建一个包含 SO 文件名、函数名（如果有）、相对于函数起始地址的偏移量以及地址本身的字符串。
     - 返回一个指向字符指针数组的指针，每个指针指向一个描述栈帧的字符串。调用者需要使用 `free()` 释放返回的内存。
   - **假设输入与输出:**
     - **假设输入:** `buffer` 是 `backtrace()` 返回的地址数组，包含地址 `A1`, `A2`, `A3`。`size` 是地址的数量。假设 `A1` 位于 `libtest.so` 的 `func1` 函数内，偏移量为 `0x10`；`A2` 位于 `libc.so` 的 `malloc` 函数内；`A3` 无法解析到具体符号。
     - **假设输出:** 返回一个指向包含三个字符串的字符指针数组，例如：
       - `"libtest.so (func1+0x10) [0xA1]"`
       - `"libc.so (malloc+0x??) [0xA2]"` (偏移量可能无法精确确定)
       - `"[0xA3]"` (如果无法解析符号)

3. **`backtrace_symbols_fd(const void* const* buffer, int size, int fd)`:**
   - **功能:** 与 `backtrace_symbols()` 类似，但不返回字符串数组，而是将符号信息直接写入到文件描述符 `fd` 中，每个栈帧的信息占一行。
   - **实现原理:**
     - 内部实现与 `backtrace_symbols()` 类似，只是不分配内存存储字符串，而是直接将格式化后的字符串写入到文件描述符 `fd` 中。
     - 它会遍历 `buffer` 中的地址，使用 `dladdr()` 获取符号信息，然后使用 `write()` 系统调用将格式化后的字符串写入 `fd`。
   - **假设输入与输出:**
     - **假设输入:** 同 `backtrace_symbols()` 的假设输入。`fd` 是一个已打开的文件的文件描述符。
     - **假设输出:**  向 `fd` 指向的文件写入以下内容：
       ```
       libtest.so (func1+0x10) [0xA1]
       libc.so (malloc+0x??) [0xA2]
       [0xA3]
       ```

4. **`dladdr(const void* addr, Dl_info* info)`:**
   - **功能:**  尝试查找给定地址 `addr` 所属的共享库和符号信息，并将结果存储在 `info` 指向的 `Dl_info` 结构体中。
   - **实现原理:**
     - 该函数是动态链接器提供的接口。当程序加载共享库时，动态链接器会维护一个关于已加载库的地址空间和符号信息的内部数据结构。
     - `dladdr()` 会在这些数据结构中查找包含 `addr` 的内存区域，并提取相关的共享库文件名、基地址、符号名和符号地址等信息。
     - `Dl_info` 结构体包含以下字段：
       - `dli_fname`: 指向包含 `addr` 的 SO 文件的路径名。
       - `dli_fbase`: SO 文件在内存中的加载基地址。
       - `dli_sname`: 指向与 `addr` 最近的符号的名称。
       - `dli_saddr`: 指向 `dli_sname` 所指符号的起始地址。
   - **假设输入与输出:**
     - **假设输入:** `addr` 的值为 `0xA1`，该地址位于已加载的 `libtest.so` 库中，且在 `func1` 函数的内部。
     - **假设输出:** `dladdr()` 返回非 0 值（表示成功），`info` 结构体的内容可能为：
       - `info->dli_fname` 指向字符串 `"libtest.so"`
       - `info->dli_fbase` 是 `libtest.so` 的加载基地址，例如 `0x10000`
       - `info->dli_sname` 指向字符串 `"func1"`
       - `info->dli_saddr` 是 `func1` 函数的起始地址，例如 `0x10010`

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

`dladdr` 是直接与动态链接器交互的函数。

**SO 布局样本:**

假设有一个简单的共享库 `libexample.so`：

```
libexample.so:
    .text (代码段):
        func_a:  // 地址 0x1000
            ...
        func_b:  // 地址 0x1050
            ...
    .rodata (只读数据段):
        string_const: "Hello"  // 地址 0x2000
    .data (可读写数据段):
        global_var: 0          // 地址 0x3000
    .dynamic (动态链接信息):
        ...
    .symtab (符号表):
        func_a (type: function, address: 0x1000)
        func_b (type: function, address: 0x1050)
        global_var (type: object, address: 0x3000)
        ...
```

**链接的处理过程:**

1. **加载 (Loading):** 当一个程序需要使用 `libexample.so` 中的函数时，操作系统会找到该 SO 文件并将其加载到内存中的某个地址空间。例如，加载基地址可能是 `0xB7000000`。
2. **重定位 (Relocation):**  由于 SO 文件在编译时不知道其最终的加载地址，因此需要进行重定位。动态链接器会修改 SO 文件中的某些指令和数据，使其指向正确的内存地址。例如，如果 `func_b` 中调用了 `global_var`，则对 `global_var` 的访问需要被修正为 `0xB7000000 + 0x3000`。
3. **符号解析 (Symbol Resolution):**  如果程序中引用了 `libexample.so` 中的符号（例如 `func_a`），动态链接器会查找 `libexample.so` 的符号表，找到 `func_a` 的地址 (`0x1000`，相对于 SO 文件的基地址)，然后结合 SO 文件的加载地址，得到 `func_a` 在内存中的实际地址 (`0xB7000000 + 0x1000`)。
4. **`dladdr` 的使用:** 当调用 `dladdr((void*)(0xB7001020), &info)` 时，动态链接器会执行以下操作：
   - 遍历已加载的 SO 列表，找到加载地址范围包含 `0xB7001020` 的 SO 文件，即 `libexample.so`。
   - 在 `libexample.so` 的符号表中查找，找到地址小于等于 `0x1020` 且最接近 `0x1020` 的符号，即 `func_a`，其地址为 `0x1000`。
   - 设置 `info->dli_fname` 为 `"libexample.so"`。
   - 设置 `info->dli_fbase` 为 `0xB7000000`。
   - 设置 `info->dli_sname` 为 `"func_a"`。
   - 设置 `info->dli_saddr` 为 `0xB7000000 + 0x1000`。

**逻辑推理的假设输入与输出:**

在 `execinfo_test.cpp` 中，`VerifyCalls` 函数进行了逻辑推理。

**假设输入:** `frames` 向量中存储了调用栈的返回地址，假设 `CallOne` 和 `CallTwo` 函数在栈中。

**输出:** `VerifyCalls` 函数会断言找到 `CallOne` 和 `CallTwo` 函数在调用栈中的索引，并且 `CallTwo` 的索引小于 `CallOne` 的索引，因为 `CallTwo` 是被 `CallOne` 调用的。

**用户或编程常见的使用错误:**

1. **`backtrace` 缓冲区过小:** 如果传递给 `backtrace` 的 `size` 参数太小，或者 `buffer` 数组不够大，`backtrace` 可能会截断调用栈，导致丢失部分栈帧信息。
   ```c++
   void my_function() {
       void* frames[2];
       int n = backtrace(frames, 2); // 如果调用栈深度超过 2，信息会被截断
       // ...
   }
   ```

2. **忘记 `free` `backtrace_symbols` 返回的内存:** `backtrace_symbols` 会动态分配内存来存储符号信息字符串数组，如果调用者忘记使用 `free()` 释放这些内存，会导致内存泄漏。
   ```c++
   void print_backtrace() {
       void* frames[10];
       int n = backtrace(frames, 10);
       char** symbols = backtrace_symbols(frames, n);
       if (symbols != nullptr) {
           for (int i = 0; i < n; ++i) {
               printf("%s\n", symbols[i]);
           }
           // 忘记 free(symbols); 导致内存泄漏
       }
   }
   ```

3. **错误地解释 `backtrace_symbols` 的输出:**  开发者需要理解输出字符串的格式，包括 SO 文件名、函数名和偏移量。不正确的解析可能导致对调用栈的误判。例如，误认为偏移量是绝对地址。

**Android framework 或 NDK 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `execinfo` 的路径 (以崩溃报告为例):**

1. **Java 层发生异常:** 当 Java 代码抛出未捕获的异常时，JVM 会捕获该异常。
2. **`Thread.UncaughtExceptionHandler`:**  通常会设置一个全局的 `UncaughtExceptionHandler` 来处理这些未捕获的异常。
3. **Native 崩溃处理:**  `UncaughtExceptionHandler` 可能会调用 Native 代码来处理崩溃，例如，通过 JNI 调用到 C/C++ 代码。
4. **`__android_log_print` 或类似的日志记录机制:**  在 Native 崩溃处理代码中，可能会使用 Android 的日志系统 (`__android_log_print`) 来记录崩溃信息。
5. **`libcorkscrew` 或 `libunwind`:** Android 系统可能会使用 `libcorkscrew` (较旧版本) 或 `libunwind` (较新版本) 库来获取 Native 层的调用栈信息。这些库内部会使用类似 `backtrace` 的机制来收集栈帧地址。
6. **`backtrace` 调用:**  `libcorkscrew` 或 `libunwind` 最终可能会调用 Bionic 提供的 `backtrace` 函数来获取原始的栈帧地址。
7. **符号化:**  获取到栈帧地址后，系统可能会使用 `dladdr` 和符号表信息将地址转换为可读的符号信息，或者使用 `backtrace_symbols` 或 `backtrace_symbols_fd` 完成符号化并输出到日志或 tombstone 文件。

**NDK 直接使用 `execinfo`:**

NDK 开发者可以直接在 Native 代码中包含 `<execinfo.h>` 头文件并调用其中的函数。例如，一个 Native 库想要在发生错误时记录调用栈信息：

```c++
#include <execinfo.h>
#include <cstdio>
#include <cstdlib>

void my_native_function() {
    // ... 发生错误 ...
    void* buffer[128];
    int n = backtrace(buffer, 128);
    char** symbols = backtrace_symbols(buffer, n);
    if (symbols != nullptr) {
        fprintf(stderr, "Backtrace:\n");
        for (int i = 0; i < n; ++i) {
            fprintf(stderr, "%s\n", symbols[i]);
        }
        free(symbols);
    }
}
```

**Frida Hook 示例调试步骤:**

假设我们要 hook `backtrace` 函数，查看其参数和返回值。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

def main(target_process):
    session = frida.attach(target_process)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "backtrace"), {
        onEnter: function(args) {
            console.log("[+] backtrace called");
            this.buffer = args[0];
            this.size = args[1];
            console.log("    buffer:", this.buffer);
            console.log("    size:", this.size.toInt());
        },
        onLeave: function(retval) {
            console.log("[-] backtrace returned:", retval.toInt());
            if (retval.toInt() > 0) {
                console.log("    Captured frames:");
                for (let i = 0; i < retval.toInt(); i++) {
                    let address = this.buffer.readPointer();
                    console.log("        [" + i + "]: " + address);
                    this.buffer = this.buffer.add(Process.pointerSize);
                }
            }
        }
    });
    """
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()
    session.detach()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python frida_backtrace_hook.py <process_name_or_pid>")
        sys.exit(1)

    target = sys.argv[1]
    try:
        main(target)
    except frida.ProcessNotFoundError:
        print(f"Process '{target}' not found.")
    except frida.InvalidArgumentError:
        print(f"Invalid argument: '{target}'. Please provide process name or PID.")
```

**使用步骤:**

1. **保存代码:** 将上面的 Python 代码保存为 `frida_backtrace_hook.py`。
2. **运行 Frida Server:** 在 Android 设备或模拟器上运行 Frida Server。
3. **运行目标应用:** 运行你想要监控的应用。
4. **执行 Frida 脚本:** 在 PC 上执行 `python frida_backtrace_hook.py <目标应用的进程名或 PID>`。将 `<目标应用的进程名或 PID>` 替换为实际的进程名或 PID。
5. **触发 `backtrace`:** 在目标应用中操作，触发可能调用 `backtrace` 的场景，例如导致崩溃或执行某些特定功能。
6. **查看输出:** Frida 脚本会在终端输出 `backtrace` 函数被调用时的参数（buffer 地址和 size）以及返回值（捕获的帧数）和捕获的栈帧地址。

这个 Frida 示例可以帮助你观察 `backtrace` 函数的实际行为，验证其是否被调用，以及调用时传入的参数和返回的结果，从而深入理解其在 Android 系统中的工作方式。你可以类似地 hook 其他 `execinfo` 函数来观察它们的行为。

Prompt: 
```
这是目录为bionic/tests/execinfo_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2021 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <gtest/gtest.h>

#include <dlfcn.h>
#include <execinfo.h>
#include <string.h>

#include <fstream>
#include <regex>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>

TEST(execinfo, backtrace_errors) {
  void* frames[20];
  ASSERT_EQ(0, backtrace(frames, 0));
  ASSERT_EQ(0, backtrace(frames, -1));
}

static constexpr int kMaxFrames = 50;

// Disable optimizations so that these functions show up properly in
// the backtrace.
#pragma clang optimize off
extern "C" __attribute__((__noinline__)) void CallTwo(std::vector<void*>& frames) {
  int num_frames = backtrace(frames.data(), static_cast<int>(frames.size()));
  ASSERT_LT(0, num_frames);
  frames.resize(static_cast<size_t>(num_frames));
}

extern "C" __attribute__((__noinline__)) void CallOne(std::vector<void*>& frames) {
  CallTwo(frames);
}
#pragma clang optimize on

static std::string DumpFrames(std::vector<void*>& frames) {
  std::string frame_data;
  for (auto frame : frames) {
    frame_data += android::base::StringPrintf("[%p]", frame);
    Dl_info info;
    if (dladdr(frame, &info) != 0 && info.dli_sname != nullptr) {
      frame_data += ' ';
      frame_data += info.dli_sname;
    }
    frame_data += '\n';
  }
  return frame_data;
}

static size_t FindFunction(std::vector<void*>& frames, uintptr_t func_addr) {
  Dl_info func_info;
  if (!dladdr(reinterpret_cast<void*>(func_addr), &func_info)) {
    return 0;
  }
  for (size_t i = 0; i < frames.size(); i++) {
    Dl_info frame_info;
    if (dladdr(frames[i], &frame_info) && func_info.dli_saddr == frame_info.dli_saddr) {
      return i + 1;
    }
  }
  return 0;
}

static void VerifyCalls(std::vector<void*>& frames, size_t* one_idx = nullptr,
                        size_t* two_idx = nullptr) {
  // Try and find the CallOne and CallTwo function addresses.
  size_t call_one_idx = FindFunction(frames, reinterpret_cast<uintptr_t>(&CallOne));
  ASSERT_TRUE(call_one_idx != 0) << DumpFrames(frames);
  size_t call_two_idx = FindFunction(frames, reinterpret_cast<uintptr_t>(&CallTwo));
  ASSERT_TRUE(call_two_idx != 0) << DumpFrames(frames);

  ASSERT_LT(call_two_idx, call_one_idx) << "CallTwo function found after CallOne\n"
                                        << DumpFrames(frames);

  if (one_idx != nullptr) *one_idx = call_one_idx;
  if (two_idx != nullptr) *two_idx = call_two_idx;
}

TEST(execinfo, backtrace) {
  std::vector<void*> frames(kMaxFrames);
  ASSERT_NO_FATAL_FAILURE(CallOne(frames));

  // Verfiy that there are at least two frames.
  ASSERT_LT(3U, frames.size()) << DumpFrames(frames);

  VerifyCalls(frames);
}

TEST(execinfo, backtrace_cutoff_frames) {
  // Verify the max frames is handled properly
  std::vector<void*> frames(1);
  ASSERT_NO_FATAL_FAILURE(CallOne(frames));
  ASSERT_EQ(1U, frames.size()) << DumpFrames(frames);
}

TEST(execinfo, backtrace_symbols_errors) {
  void* frames[kMaxFrames];
  // glibc incorrectly returns memory when a zero is passed in.
  // Since we know this works properly on bionic, only verify
  // this there.
#if defined(__BIONIC__)
  ASSERT_EQ(nullptr, backtrace_symbols(frames, 0));
#endif
  ASSERT_EQ(nullptr, backtrace_symbols(frames, -1));
}

static void VerifyLineFormat(std::string& line) {
  // Verify that the format of the line is one of these:
  //   elf_file(FuncName+0xFuncAddr) [0xAddress]
  //   elf_file(+0xRelAddress) [0xAddress]
  //   elf_file [0xAddress]
  //   [0xAddress]
#if defined(__GLIBC__)
  // For some reason, glibc will print a space before [0xAddress] for
  // backtrace symbols, and no space for backtrace_symbols_fd. Allow this
  // only for glibc.
  std::regex format1("[^\\(\\s]+\\([^\\+]+\\+0x[0-9a-fA-F]+\\) ?\\[0x[0-9a-fA-F]+\\]");
  std::regex format2("[^\\(\\s]+\\(+\\+0x[0-9a-fA-F]+\\) ?\\[0x[0-9a-fA-F]+\\]");
  std::regex format3("[^\\(\\s]+ ?\\[0x[0-9a-fA-F]+\\]");
#else
  std::regex format1("[^\\(\\s]+\\([^\\+]+\\+0x[0-9a-fA-F]+\\) \\[0x[0-9a-fA-F]+\\]");
  std::regex format2("[^\\(\\s]+\\(+\\+0x[0-9a-fA-F]+\\) \\[0x[0-9a-fA-F]+\\]");
  std::regex format3("[^\\(\\s]+ \\[0x[0-9a-fA-F]+\\]");
#endif
  std::regex format4("\\[0x[0-9a-fA-F]+\\]");

  EXPECT_TRUE(std::regex_match(line, format1) || std::regex_match(line, format2) ||
              std::regex_match(line, format3) || std::regex_match(line, format4))
      << "Unknown format of line:\n"
      << line;
}

static void VerifyLineFormat(char* raw_line, size_t length) {
  std::string line(raw_line, length);
  VerifyLineFormat(line);
}

TEST(execinfo, backtrace_symbols) {
  std::vector<void*> frames(kMaxFrames);
  ASSERT_NO_FATAL_FAILURE(CallOne(frames));
  ASSERT_LT(3U, frames.size()) << DumpFrames(frames);

  char** symbols = backtrace_symbols(frames.data(), static_cast<int>(frames.size()));
  ASSERT_TRUE(symbols != nullptr);
  for (size_t i = 0; i < frames.size(); i++) {
    ASSERT_TRUE(frames[i] != nullptr);
    VerifyLineFormat(symbols[i], strlen(symbols[i]));
  }

  size_t call_one_idx;
  size_t call_two_idx;
  ASSERT_NO_FATAL_FAILURE(VerifyCalls(frames, &call_one_idx, &call_two_idx));
  // Now verify that those frames contain the function names we expect.
  SCOPED_TRACE(DumpFrames(frames));
  ASSERT_MATCH(symbols[call_one_idx - 1], "\\(CallOne+");
  ASSERT_MATCH(symbols[call_two_idx - 1], "\\(CallTwo+");
  free(symbols);
}

TEST(execinfo, backtrace_symbols_fd_errors) {
  void* frames[kMaxFrames];
  frames[0] = reinterpret_cast<void*>(&backtrace_symbols);

  {
    TemporaryFile tf;
    backtrace_symbols_fd(frames, 0, tf.fd);
    close(tf.fd);
    std::string content;
    ASSERT_TRUE(android::base::ReadFileToString(tf.path, &content));
    // Verify that no data is written to the file.
    ASSERT_TRUE(content.empty());
  }

  {
    TemporaryFile tf;
    backtrace_symbols_fd(frames, -1, tf.fd);
    close(tf.fd);
    std::string content;
    ASSERT_TRUE(android::base::ReadFileToString(tf.path, &content));
    // Verify that no data is written to the file.
    ASSERT_TRUE(content.empty());
  }

  // Verify that there isn't a crash.
  backtrace_symbols_fd(frames, 0, -1);
}

TEST(execinfo, backtrace_symbols_fd) {
  std::vector<void*> frames(kMaxFrames);
  ASSERT_NO_FATAL_FAILURE(CallOne(frames));
  ASSERT_LT(3U, frames.size()) << DumpFrames(frames);

  TemporaryFile tf;
  backtrace_symbols_fd(frames.data(), static_cast<int>(frames.size()), tf.fd);
  close(tf.fd);

  size_t call_one_idx;
  size_t call_two_idx;
  ASSERT_NO_FATAL_FAILURE(VerifyCalls(frames, &call_one_idx, &call_two_idx));

  std::ifstream frame_stream(tf.path);
  ASSERT_TRUE(frame_stream.is_open());
  size_t num_lines = 0;
  std::string line;
  while (std::getline(frame_stream, line)) {
    ASSERT_FALSE(line.empty());
    VerifyLineFormat(line);
    num_lines++;

    if (num_lines == call_one_idx) {
      EXPECT_MATCH(line, "\\(CallOne+");
    } else if (num_lines == call_two_idx) {
      EXPECT_MATCH(line, "\\(CallTwo+");
    }
  }
  ASSERT_EQ(num_lines, frames.size()) << "Number of lines in file does not match number of frames.";
}

"""

```