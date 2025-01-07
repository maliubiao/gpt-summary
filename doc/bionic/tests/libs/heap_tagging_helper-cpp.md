Response:
Let's break down the thought process for analyzing the provided C++ code snippet. The goal is to address all the specific questions in the prompt.

**1. Understanding the Core Functionality:**

* **Initial Read:**  The first scan reveals standard C/C++ constructs: `#include` directives, a `main` function, signal handlers, memory allocation (`std::make_unique`, `mmap`), assembly instructions, and file operations (`system`). The presence of `#ifdef __ANDROID__` and architecture-specific code (`__aarch64__`) immediately signals its purpose is likely related to a specific platform, in this case, Android.
* **Signal Handlers:** The code defines two signal handlers, `action` and `action2`. `action` specifically looks for `SIGSEGV` with codes `SEGV_MTEAERR` and `SEGV_MTESERR`, which hints at Memory Tagging Extension (MTE). `action2` is a more general signal handler for unexpected signals.
* **Memory Allocation & Access:**  The `main` function allocates an integer array using `std::make_unique` and then deliberately performs an out-of-bounds write (`p[-1]`). This strongly suggests a test case for memory access violation detection.
* **Conditional MTE Code:**  The `#if defined(__BIONIC__) && defined(__aarch64__)` block clearly targets 64-bit ARM architectures within the Bionic library. It uses `getauxval(AT_HWCAP2) & HWCAP2_MTE` to check if MTE is enabled. If it is, it allocates memory with `mmap` using `PROT_MTE`, then executes inline assembly related to MTE (`irg`, `stg`, `addg`). This confirms the file's relation to MTE testing.
* **SMaps Check:**  The `system(cmd.c_str())` call to `cat /proc/%d/smaps | grep -E 'VmFlags:.* mt'` suggests a check for the presence of memory mappings with the "mt" flag, which is associated with MTE.

**2. Addressing the Specific Questions (Iterative Refinement):**

* **功能 (Functionality):**  Based on the above, the primary function is to test the behavior of the Android Bionic library when dealing with memory access violations, specifically related to the Memory Tagging Extension (MTE) on ARM64. It aims to verify that MTE-related faults are correctly handled and that tagged memory behaves as expected. It also checks for the absence of unexpected MTE mappings.

* **与 Android 功能的关系 (Relationship with Android Functionality):**  The file is *part* of the Android Bionic library's test suite. MTE is a security feature in Android that helps detect memory safety bugs. This test verifies the correctness of Bionic's handling of MTE. Examples of Android functionality related to this include memory allocation in apps, kernel memory management, and crash reporting.

* **libc 函数功能 (libc Function Details):**  Here, it's crucial to explain each used libc function:
    * `signal.h`, `sigaction`: Setting up signal handlers to intercept specific signals. Need to detail the `sigaction` structure and its members.
    * `stdio.h`, `fprintf`:  Printing error messages to standard error.
    * `stdlib.h`, `_exit`, `system`:  Exiting the program immediately and executing shell commands.
    * `sys/auxv.h`, `getauxval`: Retrieving auxiliary vector information, specifically checking for MTE capability.
    * `sys/cdefs.h`, `__unused`:  Marking unused variables to avoid compiler warnings.
    * `sys/mman.h`, `mmap`, `munmap`:  Mapping and unmapping memory regions, crucially using `PROT_MTE` in the MTE test.
    * `unistd.h`, `sysconf`: Getting system configuration information, like the page size.
    * `memory`, `std::make_unique`:  Smart pointer for automatic memory management.

* **dynamic linker 功能 (Dynamic Linker Functionality):** This is where careful consideration is needed. The code itself doesn't *directly* call dynamic linker functions (like `dlopen`, `dlsym`). However, it's part of Bionic, which *is* the dynamic linker. The relevant aspect here is how the dynamic linker itself might be involved in setting up the environment where this test runs, and how it handles libraries with MTE-enabled memory. A conceptual SO layout with and without MTE could be presented. The linking process would involve resolving symbols and setting up the process's memory space.

* **逻辑推理 (Logical Reasoning):** For the MTE section, the logic is:
    * *Hypothesis:*  If MTE is enabled, accessing tagged memory incorrectly will trigger a `SIGSEGV` with a specific code (`SEGV_MTEAERR` or `SEGV_MTESERR`).
    * *Input:* Allocate memory with `PROT_MTE`, then use inline assembly to intentionally cause a tag mismatch.
    * *Output:* The `action2` signal handler should be triggered (or the program should terminate due to a signal if `action2` isn't properly set up beforehand, demonstrating the fault).

* **用户/编程常见错误 (Common User/Programming Errors):** Focus on errors related to memory management and MTE if it's enabled:
    * Out-of-bounds access (demonstrated in the code).
    * Use-after-free.
    * Incorrect tag usage when manually managing tagged memory (if the API allowed for more direct tag manipulation).

* **Android Framework/NDK 到达这里 (How Android Framework/NDK Reaches Here):** This requires explaining the build process and how tests are executed. The framework or NDK doesn't *directly* call this code in typical usage. This is a *test* within the Bionic library. It's run during development and testing of the Android system itself. Mentioning the build system (like Soong) and test execution frameworks (like atest) is important.

* **Frida Hook 示例 (Frida Hook Example):**  Provide practical examples of how Frida could be used to intercept function calls (like `sigaction`, `mmap`) or examine variables within the test program. This needs concrete code snippets.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus heavily on the direct function of the code.
* **Correction:** Realize the prompt asks for broader context, including the relationship to Android, dynamic linking, and how it fits into the bigger picture.
* **Initial thought:**  Only explain the *purpose* of libc functions.
* **Correction:**  Explain *how* they work internally (briefly).
* **Initial thought:**  Assume the user is a developer familiar with Bionic internals.
* **Correction:**  Explain concepts like MTE and the dynamic linker at a slightly higher level to be more accessible.
* **Initial thought:**  Provide very complex Frida examples.
* **Correction:**  Keep the Frida examples simple and focused on the key function calls.

By following this iterative process of understanding the code, addressing each question systematically, and refining the answers, a comprehensive and accurate response can be generated.
这个 C++ 文件 `bionic/tests/libs/heap_tagging_helper.cpp` 是 Android Bionic 库的一部分，专门用于测试与堆内存标记（Heap Tagging）相关的特性。堆内存标记是一种用于检测内存安全漏洞（如缓冲区溢出、use-after-free）的技术，它在内存分配时附加标签，并在访问时进行校验。

**功能列举：**

1. **测试 MTE (Memory Tagging Extension) 的基本功能:**  该文件主要用于测试 ARMv8.5-A 及更高版本架构中引入的内存标记扩展（MTE）。它验证了当启用 MTE 时，对带有错误标签的内存进行访问是否会触发预期的信号（`SIGSEGV`，具体来说是 `SEGV_MTEAERR` 或 `SEGV_MTESERR`）。
2. **验证系统堆的 MTE 行为:**  代码首先尝试在系统堆上进行越界访问 (`p[-1]`)，观察是否会触发 MTE 错误。
3. **验证显式标记内存的 MTE 行为:**  如果系统堆上的访问没有触发错误（可能因为 MTE 未启用），代码会尝试使用 `mmap` 分配带有 `PROT_MTE` 保护属性的内存。然后，它使用内联汇编指令人为地制造一个标签不匹配的访问，以验证 MTE 是否按预期工作。
4. **检查是否存在意外的 MTE 映射:**  最后，代码使用 `system` 函数执行 shell 命令，检查当前进程的内存映射中是否存在任何带有 `mt` 标记（指示 `PROT_MTE`）的段。这用于确保在预期之外没有启用 MTE。
5. **设置信号处理程序:**  代码设置了两个信号处理程序 (`action` 和 `action2`) 来捕获 `SIGSEGV` 信号。`action` 特别关注 `SEGV_MTEAERR` 和 `SEGV_MTESERR`，而 `action2` 用于处理其他意外的信号。这允许测试程序在检测到 MTE 错误时优雅地退出，并输出相应的消息。
6. **抑制 HWASan 的崩溃报告:** 代码通过设置 `SIGABRT` 的默认处理程序为 `SIG_DFL` 来抑制 HWASan（硬件加速的 AddressSanitizer）可能产生的崩溃报告。这是因为该测试自身就在故意触发内存错误来验证 MTE 的行为。

**与 Android 功能的关系及举例说明：**

此文件是 Android Bionic 库的一部分，直接关系到 Android 系统的安全性和稳定性。

* **内存安全:** MTE 是 Android 为了提高内存安全而引入的一项重要技术。它可以帮助开发者和系统更容易地发现和修复内存相关的 bug，如缓冲区溢出和 use-after-free 漏洞，这些漏洞可能被恶意利用来执行任意代码或造成拒绝服务。
    * **举例:**  当一个 Android 应用（通过 NDK 使用 C/C++ 编写）由于编程错误尝试写入超出分配缓冲区边界的内存时，如果设备支持并启用了 MTE，内核会检测到内存标签不匹配，并发送 `SIGSEGV` 信号给应用，通常会携带 `si_code` 为 `SEGV_MTEAERR` 或 `SEGV_MTESERR`。这个测试文件就是用来验证这种机制是否正常工作。
* **Bionic 库的正确性:** 作为 Bionic 库的测试用例，它确保了 Bionic 提供的内存管理功能（如 `mmap`）在涉及到 MTE 时的行为是正确的。
    * **举例:**  该测试验证了使用 `mmap` 和 `PROT_MTE` 创建的内存区域是否 действительно 受到了 MTE 的保护，并且违规访问会触发预期的信号。

**每一个 libc 函数的功能实现：**

* **`signal.h` 中的 `sigaction`:**
    * **功能:** 用于设置进程如何处理特定的信号。
    * **实现:** `sigaction` 系统调用会修改内核中进程的信号处理表。它接收三个参数：要处理的信号编号、指向新 `sigaction` 结构体的指针以及一个可选的指向旧 `sigaction` 结构体的指针（用于保存之前的处理方式）。内核会根据 `sa_sigaction` 或 `sa_handler` 字段中设置的函数指针来处理接收到的信号。`sa_flags` 可以指定额外的行为，如 `SA_SIGINFO` 表示使用扩展的信号信息结构体 `siginfo_t`。
* **`stdio.h` 中的 `fprintf`:**
    * **功能:** 将格式化的输出写入到指定的文件流，通常用于输出错误信息到标准错误流 (`stderr`)。
    * **实现:** `fprintf` 函数会解析格式化字符串，并将参数转换为相应的文本表示，然后通过底层的 I/O 系统调用（如 `write`）将这些文本写入到文件描述符对应的文件或设备。
* **`stdlib.h` 中的 `exit` 和 `_exit`:**
    * **功能:** 终止当前进程的执行。`exit` 会执行一些清理工作，例如调用通过 `atexit` 注册的函数，刷新所有打开的输出流。`_exit` 则立即终止进程，不执行这些清理工作。
    * **实现:** `exit` 是一个 C 标准库函数，它会调用 `_exit` 系统调用。`_exit` 是一个直接的系统调用，通知内核立即结束当前进程。内核会回收进程占用的资源。
* **`stdlib.h` 中的 `system`:**
    * **功能:** 执行一个由字符串指定的 shell 命令。
    * **实现:** `system` 函数通常会 fork 一个新的子进程，然后在子进程中使用 shell（如 `/bin/sh`）来执行给定的命令。父进程会等待子进程执行完成。
* **`sys/auxv.h` 中的 `getauxval`:**
    * **功能:** 获取进程的 auxiliary vector 中的条目。auxiliary vector 是内核在启动程序时传递给程序的关于系统配置的信息。
    * **实现:** `getauxval` 是一个系统调用，内核会读取并返回 auxiliary vector 中指定类型的条目的值。在这个文件中，它被用来检查 `AT_HWCAP2`，其中包含了硬件能力信息，包括 `HWCAP2_MTE` 标志，指示 CPU 是否支持 MTE。
* **`sys/cdefs.h` 中的 `__unused`:**
    * **功能:**  这是一个编译器指令，用于标记某个变量为未使用，以避免编译器发出警告。
    * **实现:** 不同的编译器可能有不同的实现方式，但通常是在编译阶段被识别并处理，不会影响运行时的行为。
* **`sys/mman.h` 中的 `mmap` 和 `munmap`:**
    * **功能:** `mmap` 用于将文件或设备映射到内存中，或者创建一个匿名内存映射。`munmap` 用于解除 `mmap` 创建的映射。
    * **实现:** `mmap` 是一个复杂的系统调用，它会在进程的虚拟地址空间中创建一个新的映射。参数指定了映射的起始地址（通常为 NULL，由内核决定）、长度、保护属性（如 `PROT_READ`, `PROT_WRITE`, `PROT_MTE`）、映射类型（如 `MAP_PRIVATE`, `MAP_ANONYMOUS`）、文件描述符和偏移量。内核会管理这些映射，并负责将虚拟地址转换为物理地址。`munmap` 系统调用则会释放指定的内存映射。当使用 `PROT_MTE` 时，内核会在分配的内存区域上启用内存标记。
* **`unistd.h` 中的 `sysconf`:**
    * **功能:** 获取系统配置信息。
    * **实现:** `sysconf` 是一个系统调用，它接收一个配置名称（如 `_SC_PAGESIZE`），并返回相应的系统配置值。内核会维护这些配置信息。
* **`memory` 中的 `std::make_unique`:**
    * **功能:** 创建一个拥有动态分配对象的 `std::unique_ptr`。`std::unique_ptr` 是一种智能指针，用于自动管理动态分配的内存，防止内存泄漏。
    * **实现:** `std::make_unique<T>(args...)` 内部会调用 `new T(args...)` 来分配内存并构造对象，然后将返回的指针包装到一个 `std::unique_ptr<T>` 对象中。当 `std::unique_ptr` 对象超出作用域时，其析构函数会自动调用 `delete` 来释放所管理的内存。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程：**

虽然此代码本身没有直接调用 dynamic linker 的函数（如 `dlopen`, `dlsym`），但它作为 Bionic 库的一部分，其运行环境和某些行为与 dynamic linker 密切相关。

**SO 布局样本（简化）：**

考虑一个简单的场景，该测试程序作为一个独立的可执行文件运行，它链接了 Bionic 库。

```
内存地址空间：

[加载器（linker）]   <--- dynamic linker 代码和数据
[程序代码段]       <--- main 函数的代码和其他静态代码
[程序数据段]       <--- 全局变量、静态变量
[Bionic 库代码段]  <--- Bionic 库中与该测试相关的代码（如信号处理、内存管理）
[Bionic 库数据段]  <--- Bionic 库的全局数据
[堆内存]           <--- 通过 malloc/new 分配的内存 (可能包含 MTE 标签)
[栈内存]           <--- 局部变量、函数调用栈
[mmap 区域]        <--- 通过 mmap 分配的内存 (可能包含 PROT_MTE)
```

**链接的处理过程：**

1. **静态链接：** 在编译时，链接器（ld）会将该测试程序的代码与 Bionic 库中使用的函数进行链接。这包括将对 Bionic 函数的调用地址替换为实际的函数地址。
2. **动态链接：** 当程序运行时，内核会加载程序到内存，并启动 dynamic linker（在 Android 中通常是 `/system/bin/linker64` 或 `/system/bin/linker`）。
3. **重定位：** Dynamic linker 会解析程序依赖的动态库（如 Bionic）。它会加载这些库到内存中，并进行重定位，即将程序和库中对外部符号的引用绑定到实际的内存地址。
4. **符号解析：** 当程序调用 Bionic 库中的函数（如 `sigaction`, `mmap`）时，这些调用会通过动态链接过程解析到 Bionic 库中相应的函数地址。
5. **MTE 相关：** 如果设备支持 MTE，dynamic linker 在加载 Bionic 库时，可能会设置一些内部状态，以指示 MTE 功能可用。内核在进行内存分配（如 `mmap` with `PROT_MTE`) 时会根据这些信息来管理内存标签。

**逻辑推理，假设输入与输出：**

**场景 1：MTE 已启用**

* **假设输入：** 运行在支持 MTE 的 Android 设备上。
* **代码执行：**
    1. `std::make_unique` 分配的堆内存没有显式 MTE 保护，越界访问 `p[-1]` 可能会触发传统的内存错误，但如果 MTE 的实现也对未标记的堆进行保护，则可能触发 `SEGV_MTEAERR` 或 `SEGV_MTESERR`。
    2. `mmap` 分配带有 `PROT_MTE` 的内存。
    3. 内联汇编尝试使用错误的标签访问 `mmap` 分配的内存。
* **预期输出：** 程序会捕获 `SIGSEGV` 信号，`action2` 信号处理程序会被执行，输出 "SEGV_MTEAERR" 或 "SEGV_MTESERR"，然后程序退出。`system` 命令检查 `/proc/.../smaps` 应该不会找到带有 `mt` 标记的映射（因为测试后已 `munmap`）。最终输出 "normal exit" 不会打印，因为程序在信号处理程序中退出。

**场景 2：MTE 未启用**

* **假设输入：** 运行在不支持 MTE 或 MTE 未启用的 Android 设备上。
* **代码执行：**
    1. 越界访问 `p[-1]` 会触发传统的 `SIGSEGV`，但 `info->si_code` 不会是 `SEGV_MTEAERR` 或 `SEGV_MTESERR`。`action` 信号处理程序会输出 "signo 11"。
    2. `getauxval` 检查 `HWCAP2_MTE` 返回 0，跳过 `mmap` 和内联汇编部分。
    3. `system` 命令检查 `/proc/.../smaps` 不会找到带有 `mt` 标记的映射。
* **预期输出：** 标准错误输出 "signo 11"，然后 "normal exit"。

**用户或编程常见的使用错误：**

1. **在不支持 MTE 的设备上假设 MTE 已启用：**  开发者可能会编写依赖 MTE 提供的内存安全保障的代码，但在不支持 MTE 的设备上运行时，这些保障将不存在，可能导致难以追踪的 bug。
2. **错误地使用 MTE 相关 API（如果存在）：**  虽然此测试代码中直接使用了 `PROT_MTE`，但在更复杂的场景中，如果提供了用户空间的 MTE 控制 API，错误地使用这些 API（例如，分配了带标签的内存但忘记设置标签，或者使用了错误的标签值）会导致 MTE 无法有效工作。
3. **对齐问题：** MTE 通常对内存块进行标记，如果访问未对齐的内存区域，可能会导致 MTE 无法正确检测标签。
4. **与 AddressSanitizer (ASan) 或 HWAddressSanitizer (HWASan) 的冲突：**  MTE 和 ASan/HWASan 都是内存错误检测工具，但它们的工作原理不同。在某些情况下，同时启用它们可能会导致冲突或意外行为。此测试代码通过禁用 `SIGABRT` 的默认处理程序来避免与 HWASan 的冲突。

**Android Framework 或 NDK 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

这个测试文件通常不会被 Android Framework 或 NDK 直接调用。它属于 Bionic 库的测试套件，主要用于 Bionic 库的开发和验证阶段。

**执行路径（测试场景）：**

1. **Bionic 开发者编写/修改了与 MTE 相关的代码。**
2. **开发者运行 Bionic 的测试套件。**  这通常通过 Android 的构建系统 (如 Soong) 或命令行工具 (如 `atest`) 完成。
3. **测试框架执行 `bionic/tests/libs/heap_tagging_helper_test` 这个测试程序。**  该程序链接了 `heap_tagging_helper.cpp` 编译生成的代码。
4. **测试程序内部执行 `main` 函数中的逻辑，包括设置信号处理程序、分配内存、触发可能的 MTE 错误等。**
5. **根据设备是否支持 MTE 以及代码的执行情况，可能会触发 `SIGSEGV` 信号，并由设置的信号处理程序捕获。**
6. **测试程序根据预期的行为判断测试是否通过。**

**Frida Hook 示例：**

可以使用 Frida 来 hook 这个测试程序中的关键函数调用，以观察其行为。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['content']))
    else:
        print(message)

def main():
    package_name = "system_process" # 或者如果你的测试是独立运行的，可以使用进程名
    try:
        session = frida.attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"进程 '{package_name}' 未找到，请确保测试程序正在运行。")
        return

    script_code = """
    // Hook sigaction
    Interceptor.attach(Module.findExportByName(null, "sigaction"), {
        onEnter: function(args) {
            const signum = args[0].toInt32();
            const new_action = ptr(args[1]);
            const old_action = ptr(args[2]);
            send({ tag: "sigaction", content: `sigaction(${signum}, ${new_action}, ${old_action})` });
        },
        onLeave: function(retval) {
            send({ tag: "sigaction", content: `sigaction returned ${retval}` });
        }
    });

    // Hook mmap
    Interceptor.attach(Module.findExportByName(null, "mmap"), {
        onEnter: function(args) {
            const addr = args[0];
            const length = args[1].toInt32();
            const prot = args[2].toInt32();
            const flags = args[3].toInt32();
            const fd = args[4].toInt32();
            const offset = args[5].toInt32();
            send({ tag: "mmap", content: `mmap(addr=${addr}, length=${length}, prot=${prot}, flags=${flags}, fd=${fd}, offset=${offset})` });
        },
        onLeave: function(retval) {
            send({ tag: "mmap", content: `mmap returned ${retval}` });
        }
    });

    // Hook 内存访问 (可以使用 Instruction Listener 或 MemoryAccessMonitor 更精细地监控)
    // 这里仅作为一个示例，监控对 p 变量的写入
    const p_address = Module.findExportByName(null, "_ZN20heap_tagging_helper4mainEv").add( /* 计算 p 变量的偏移 */ );
    Memory.on('write', p_address, 4, function(details) {
        send({ tag: "memory_write", content: `写入地址: ${details.address}, 大小: ${details.size}, 值: ${details.data}` });
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    input("Press Enter to detach from process...")
    session.detach()

if __name__ == '__main__':
    main()
```

**使用步骤：**

1. **确保你的 Android 设备已 root，并且安装了 Frida 服务端。**
2. **编译并运行 `heap_tagging_helper_test` 程序在 Android 设备上。**  你需要找到该测试程序编译后的路径并执行它。
3. **在你的 PC 上运行上述 Python Frida 脚本。**  将 `package_name` 替换为实际的进程名称，如果测试程序是独立运行的，可以尝试使用进程名。
4. **Frida 会 attach 到目标进程，并 hook `sigaction` 和 `mmap` 函数。**  你可以在终端看到这些函数的调用信息。
5. **你可以根据需要修改 Frida 脚本来 hook 其他函数或监控特定的内存地址。**

请注意，直接 hook Bionic 库的测试程序可能需要一些关于 Bionic 内部实现和测试执行方式的知识。你需要找到测试程序在设备上的路径，并确保 Frida 能够 attach 到该进程。 上面的 Frida 示例提供了一些基本的 hook 方法，你可以根据具体的需求进行扩展。

Prompt: 
```
这是目录为bionic/tests/libs/heap_tagging_helper.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2020 The Android Open Source Project
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

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <unistd.h>
#include <memory>

#include <android-base/stringprintf.h>

void action(int signo, siginfo_t* info __unused, void*) {
#ifdef __ANDROID__
  if (signo == 11 && info->si_code == SEGV_MTEAERR) {
    fprintf(stderr, "SEGV_MTEAERR\n");
    _exit(0);
  }

  if (signo == 11 && info->si_code == SEGV_MTESERR) {
    fprintf(stderr, "SEGV_MTESERR\n");
    _exit(0);
  }
#endif

  fprintf(stderr, "signo %d\n", signo);
  _exit(0);
}

void action2(int signo, siginfo_t* info __unused, void*) {
  fprintf(stderr, "unexpected signal %d\n", signo);
  _exit(0);
}

__attribute__((optnone)) int main() {
  struct sigaction sa = {};
  sa.sa_sigaction = action;
  sa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &sa, nullptr);
  // suppress HWASan crash in logcat / tombstone.
  struct sigaction dfl_sa = {};
  dfl_sa.sa_handler = SIG_DFL;
  sigaction(SIGABRT, &dfl_sa, nullptr);

  std::unique_ptr<int[]> p = std::make_unique<int[]>(4);
  volatile int oob = p[-1];
  (void)oob;

#if defined(__BIONIC__) && defined(__aarch64__)
  // If we get here, bad access on system heap memory did not trigger a fault.
  // This suggests that MTE is disabled. Make sure that explicitly tagged PROT_MTE memory does not
  // trigger a fault either.
  if (getauxval(AT_HWCAP2) & HWCAP2_MTE) {
    sa.sa_sigaction = action2;
    sigaction(SIGSEGV, &sa, nullptr);

    size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    void* p = mmap(nullptr, page_size, PROT_READ | PROT_WRITE | PROT_MTE,
                   MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (!p) {
      fprintf(stderr, "mmap failed\n");
      return 1;
    }

    void* q = p;
    __asm__ __volatile__(
        ".arch_extension memtag\n"
        "irg %[Ptr], %[Ptr], xzr\n"
        "stg %[Ptr], [%[Ptr]]\n"
        "addg %[Ptr], %[Ptr], 0, 1\n"
        "str xzr, [%[Ptr]]\n"
        : [Ptr] "+&r"(q)
        :
        : "memory");

    munmap(p, page_size);
  }
#endif  // __aarch64__

  // In fact, make sure that there are no tagged mappings at all.
  auto cmd = android::base::StringPrintf("cat /proc/%d/smaps | grep -E 'VmFlags:.* mt'", getpid());
  if (system(cmd.c_str()) == 0) {
    fprintf(stderr, "unexpected PROT_MTE mappings found\n");
    return 1;
  }

  fprintf(stderr, "normal exit\n");
  return 0;
}

"""

```