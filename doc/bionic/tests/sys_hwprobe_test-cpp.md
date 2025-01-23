Response:
Let's break down the thought process for analyzing the C++ code and generating the detailed response.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the provided C++ test file (`bionic/tests/sys_hwprobe_test.cpp`). This means going beyond simply summarizing the code. The key requirements are:

* **Functionality:** What does this code *do*?
* **Android Relationship:** How does it relate to Android's functionality?
* **libc Function Explanation:** Detailed explanation of used libc functions.
* **Dynamic Linker:**  If applicable, explain the dynamic linking aspects.
* **Logic & I/O:**  Infer logic, consider inputs and outputs.
* **Common Errors:** Identify potential programmer errors.
* **Android Framework/NDK Path:** How does one reach this code from a higher level?
* **Frida Hooking:** Provide examples for dynamic analysis.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code for important keywords and patterns. This helps to establish the high-level purpose. Notable elements are:

* `#include <gtest/gtest.h>`:  This immediately signals that it's a unit test file using the Google Test framework.
* `#include <sys/hwprobe.h>`: This strongly suggests that the code is testing hardware probing capabilities.
* `#include <sys/syscall.h>`: This indicates the use of direct system calls.
* `#if defined(__riscv)`: The code is specifically targeting the RISC-V architecture.
* `__riscv_hwprobe()`:  This is the core function being tested.
* `TEST(...)`:  These are the individual test cases.
* `ASSERT_*`, `EXPECT_*`:  Google Test assertion macros.
* `scalar_cast`, `scalar_memcpy`, `vector_memcpy`, `vector_ldst`, `vector_ldst64`: These are helper functions, hinting at testing different memory access methods.
* `RISCV_HWPROBE_KEY_*`, `RISCV_HWPROBE_*`: Constants related to hardware probing.

**3. Deconstructing the Test Cases:**

The next step is to examine each `TEST` case individually to understand its specific purpose:

* **`__riscv_hwprobe_misaligned_scalar`:** Tests how `scalar_cast` and `scalar_memcpy` handle misaligned memory access on RISC-V. The `ASSERT_NE(0U, ...)` suggests that these accesses are expected to succeed (or at least not return 0 indicating failure in this context).
* **`__riscv_hwprobe_misaligned_vector`:** Tests misaligned vector memory access using `vector_ldst`, `vector_memcpy`, and `vector_ldst64`. Similar to the scalar test, `ASSERT_NE(0U, ...)` implies successful (or at least not zero-returning) misaligned vector operations.
* **`__riscv_hwprobe`:** This is a core test for `__riscv_hwprobe`. It sets up an array of `riscv_hwprobe` structures with specific keys and then calls `__riscv_hwprobe`. The `EXPECT_TRUE` checks verify that the returned values have the expected bits set. This reveals what kind of information `__riscv_hwprobe` retrieves (CPU features, extensions).
* **`__riscv_hwprobe_syscall_vdso`:** This tests two ways of calling `__riscv_hwprobe`: directly and via a system call. It verifies that both methods return the same results. This highlights the use of the VDSO (Virtual Dynamic Shared Object) for performance optimization.
* **`__riscv_hwprobe_fail`:** This test checks how `__riscv_hwprobe` handles invalid input (an empty array and a specific flag). It expects an `EINVAL` error, confirming error handling.

**4. Identifying Key Functions and Concepts:**

Based on the test cases, the following become important:

* `__riscv_hwprobe()`: The central function under test. Its purpose is to query hardware capabilities.
* `syscall()`: Used for directly invoking system calls, important for understanding the underlying mechanism of `__riscv_hwprobe`.
* VDSO:  The concept of the VDSO is crucial to the `__riscv_hwprobe_syscall_vdso` test.

**5. Answering Specific Questions from the Prompt:**

Now, with a good understanding of the code, we can address the specific points raised in the prompt:

* **Functionality:** Summarize the tests – checking hardware probing, especially misaligned access and VDSO usage on RISC-V.
* **Android Relationship:** Explain that `__riscv_hwprobe` allows Android to adapt to different RISC-V hardware configurations at runtime. Give examples of how this information could be used.
* **libc Functions:**  Focus on the standard C library functions used: `memcpy` (via `__builtin_memcpy`), and `syscall`. Explain their basic functionality. Since the prompt asks for *detailed* explanation, acknowledge that the actual implementation within bionic is more complex but focus on the core concept.
* **Dynamic Linker:**  This is where the VDSO comes in. Explain that the VDSO is a shared library mapped into process memory, providing optimized implementations of certain system calls. Describe its layout conceptually. The linking process involves the dynamic linker resolving the `__riscv_hwprobe` symbol in the VDSO.
* **Logic/I/O:**  For the misaligned access tests, the input is the address, and the output is the value read. For the main `__riscv_hwprobe` tests, the input is the array of probe requests, and the output is the filled-in values.
* **Common Errors:**  Point out common mistakes like incorrect key values, insufficient buffer sizes (although not directly tested here, it's a relevant concern), and ignoring return values.
* **Android Framework/NDK Path:**  Start from a high level (app using NDK), then describe how the NDK maps to system calls, and how bionic provides the libc implementation.
* **Frida Hooking:** Provide concrete Frida code examples targeting both the `__riscv_hwprobe` function and the underlying `syscall`. This demonstrates dynamic analysis techniques.

**6. Structuring the Response:**

Organize the answer logically, addressing each point of the prompt clearly and concisely. Use headings and bullet points for better readability.

**7. Refining and Adding Detail:**

Review the generated response for clarity, accuracy, and completeness. Add more specific examples and explanations where needed. For instance, elaborate on the benefits of using the VDSO. Ensure the language is clear and easy to understand.

**Self-Correction/Refinement Example During the Process:**

Initially, I might have focused too much on the low-level details of the RISC-V assembly instructions generated by the helper functions. However, the prompt asks for a broader understanding. I would then refine my explanation to focus on the *intent* of those functions (testing misaligned access) rather than getting bogged down in architecture-specific details. Similarly, I might initially forget to explicitly mention the VDSO's role and would add that during a review.

By following this systematic approach, breaking down the problem into smaller, manageable parts, and iteratively refining the response, I can generate a comprehensive and accurate answer to the user's request.
好的，让我们详细分析一下 `bionic/tests/sys_hwprobe_test.cpp` 这个文件。

**文件功能概述:**

这个文件是 Android Bionic 库中的一个测试文件，专门用于测试 RISC-V 架构下的硬件探测 (`hwprobe`) 功能。其主要目的是验证 `__riscv_hwprobe` 函数在不同场景下的行为，包括：

1. **基本功能测试:** 检查 `__riscv_hwprobe` 能否正确获取 RISC-V 处理器的硬件特性信息。
2. **非对齐访问测试:** 测试在 RISC-V 架构下，`__riscv_hwprobe` 是否能处理非对齐的内存访问 (标量和向量操作)。
3. **系统调用和 VDSO 测试:**  验证通过系统调用 (`syscall`) 和 VDSO (Virtual Dynamic Shared Object) 两种方式调用 `__riscv_hwprobe` 是否能得到一致的结果。
4. **错误处理测试:** 检查 `__riscv_hwprobe` 在接收到无效参数时是否能正确返回错误码。

**与 Android 功能的关系及举例说明:**

`__riscv_hwprobe` 函数是 Android 系统底层基础设施的一部分，它允许系统在运行时探测到 RISC-V 架构处理器的具体硬件特性。这对于以下 Android 功能至关重要：

* **运行时优化:** Android 可以根据探测到的硬件特性（例如，支持的扩展指令集，缓存大小，性能指标等）来选择最优的代码执行路径和算法。例如，如果 `__riscv_hwprobe` 检测到处理器支持特定的向量指令集 (如 Zba, Zbb, Zbs)，Android 运行时 (ART) 或 NDK 编译的库就可以利用这些指令集来加速计算密集型任务，如图形处理、机器学习等。
* **兼容性处理:** 不同的 RISC-V 处理器可能支持不同的扩展和特性。通过 `__riscv_hwprobe`，Android 可以了解当前硬件的能力，从而避免使用不支持的特性，确保应用在各种 RISC-V 设备上的兼容性。
* **性能监控和分析:** `__riscv_hwprobe` 还可以提供一些性能相关的指标，例如通过 `RISCV_HWPROBE_KEY_CPUPERF_0` 获取的非对齐访问性能信息。Android 系统或性能分析工具可以利用这些信息来诊断性能瓶颈。

**libc 函数功能详解:**

该测试文件中主要涉及以下 libc 函数：

1. **`memcpy` (通过 `__builtin_memcpy`):**
   - **功能:**  `memcpy` 用于将一段内存区域的内容复制到另一段内存区域。
   - **实现:**  `memcpy` 的基本实现通常涉及逐字节或逐字地复制数据。为了提高性能，尤其是在复制大量数据时，`memcpy` 的实现会针对不同的架构和数据大小进行优化，例如使用向量指令、缓存行对齐等技术。在 Bionic 中，`__builtin_memcpy` 通常会被编译器优化为调用 Bionic 提供的 `memcpy` 实现。Bionic 的 `memcpy` 实现会考虑内存对齐、数据大小等因素，选择最有效的复制方式。
   - **示例:** 在 `scalar_memcpy` 和 `vector_memcpy` 函数中，`__builtin_memcpy` 用于在内存之间复制数据。

2. **`syscall`:**
   - **功能:** `syscall` 是一个底层的系统调用接口，允许用户程序直接向操作系统内核发起请求。
   - **实现:**  `syscall` 的实现涉及到一系列的步骤：
     1. 将系统调用号和参数放入特定的寄存器中（不同架构的约定不同）。
     2. 执行一个特殊的 CPU 指令（例如，在 RISC-V 上是 `ecall`），触发一个软中断或异常。
     3. CPU 将控制权转移到操作系统内核中的系统调用处理程序。
     4. 内核根据系统调用号查找对应的处理函数。
     5. 内核执行处理函数，完成请求的操作。
     6. 内核将结果（返回值和错误码）放回寄存器中。
     7. 执行返回指令，CPU 将控制权返回给用户程序。
   - **示例:** 在 `TEST(sys_hwprobe, __riscv_hwprobe_syscall_vdso)` 中，`syscall(SYS_riscv_hwprobe, ...)` 直接调用了 `SYS_riscv_hwprobe` 这个系统调用。

**dynamic linker 的功能和处理过程:**

在这个测试文件中，dynamic linker 主要参与了 VDSO 的加载和链接过程。

**VDSO (Virtual Dynamic Shared Object):**

VDSO 是一个由内核提供的共享对象，它被映射到每个用户进程的地址空间中。VDSO 包含了一些常用且执行时间敏感的系统调用的实现。与传统的系统调用方式相比，通过 VDSO 调用可以减少上下文切换的开销，从而提高性能。

**SO 布局样本 (VDSO):**

假设一个简化的 VDSO 的内存布局：

```
地址范围          | 内容
-------------------|---------------------------------------------------
0xXXXXXXXX0000   | ELF header
0xXXXXXXXX0100   | Program headers (描述了代码段、数据段等)
0xXXXXXXXX0200   | .text 段 (VDSO 的代码，包含 __riscv_hwprobe 的实现)
0xXXXXXXXX0300   | .rodata 段 (只读数据)
0xXXXXXXXX0400   | .data 段 (可读写数据)
...              | ...
```

**链接的处理过程:**

1. **程序启动:** 当一个进程启动时，内核会将 VDSO 映射到该进程的地址空间中。
2. **符号解析:**  当程序调用 `__riscv_hwprobe` 函数时（即使是通过 `syscall` 间接调用），dynamic linker 会首先查找该符号。如果该符号在 VDSO 中存在，则会解析到 VDSO 中的地址。
3. **VDSO 调用优化:**  对于某些系统调用，例如 `__riscv_hwprobe`，libc 可能会优先尝试调用 VDSO 中提供的版本。这样做的好处是避免了陷入内核态，提高了性能。
4. **系统调用兜底:**  如果 VDSO 中没有提供某个系统调用的实现，或者 VDSO 的调用失败，libc 仍然可以使用传统的 `syscall` 方式来调用内核。

在 `TEST(sys_hwprobe, __riscv_hwprobe_syscall_vdso)` 中，测试了两种调用 `__riscv_hwprobe` 的方式：

* **直接调用 `__riscv_hwprobe(probes_vdso, ...)`:**  这种方式很可能会链接到 VDSO 中提供的 `__riscv_hwprobe` 实现。
* **通过 `syscall(SYS_riscv_hwprobe, probes_syscall, ...)`:** 这种方式是直接发起系统调用，绕过了 VDSO 的优化路径。

测试的目的是验证这两种方式得到的结果是否一致，从而确保 VDSO 提供的 `__riscv_hwprobe` 实现与内核提供的系统调用功能相同。

**逻辑推理、假设输入与输出:**

**`__riscv_hwprobe_misaligned_scalar` 和 `__riscv_hwprobe_misaligned_vector`:**

* **假设输入:**
    - `tmp` 数组初始化为 `{1, 1, 1}`。
    - `p` 指针指向 `tmp` 数组的第二个字节（非对齐地址）。
    - `dst` 数组初始化为 `{1, 1, 1}`。
    - `d` 指针指向 `dst` 数组的第二个字节（非对齐地址）。
* **逻辑推理:**  这些测试旨在检查在 RISC-V 架构上，即使内存访问是非对齐的，标量和向量的加载/存储操作是否能够成功执行（或者至少不返回表示失败的 0 值）。这依赖于 RISC-V 处理器对非对齐访问的支持。
* **预期输出:** `scalar_cast(p)`, `scalar_memcpy(p)`, `vector_ldst(d, p)`, `vector_memcpy(d, p)`, `vector_ldst64(d, p)` 的返回值应该不为 0。具体的返回值会依赖于从非对齐地址读取到的数据。

**`__riscv_hwprobe` 和 `__riscv_hwprobe_syscall_vdso`:**

* **假设输入:**
    - `probes` 数组包含两个 `riscv_hwprobe` 结构体，分别请求 `RISCV_HWPROBE_KEY_IMA_EXT_0` 和 `RISCV_HWPROBE_KEY_CPUPERF_0` 的信息。
    - 其他参数为 0 或 `nullptr`。
* **逻辑推理:**  `__riscv_hwprobe` 函数会查询 RISC-V 处理器关于 IMA 扩展 (Integer Multiply/Add) 和 CPU 性能特性的信息，并将结果填充到 `probes` 数组的 `value` 字段中。
* **预期输出:**
    - `probes[0].value` 的某些位应该被设置，指示处理器支持 IMA 扩展中的特定功能（例如 `RISCV_HWPROBE_IMA_FD`, `RISCV_HWPROBE_IMA_C`, `RISCV_HWPROBE_IMA_V`）以及 Zba, Zbb, Zbs 这些指令集扩展。
    - `probes[1].value` 的 `RISCV_HWPROBE_MISALIGNED_MASK` 位域应该被设置为 `RISCV_HWPROBE_MISALIGNED_FAST`，表示非对齐访问的性能特性。
    - `__riscv_hwprobe_syscall_vdso` 测试中，通过 VDSO 和系统调用两种方式获取的结果应该完全一致。

**`__riscv_hwprobe_fail`:**

* **假设输入:**
    - `probes` 数组为空。
    - `flags` 参数设置为 `~0` (全 1)。
* **逻辑推理:**  当 `probes` 数组为空时，`__riscv_hwprobe` 应该返回一个表示参数无效的错误码。
* **预期输出:** `__riscv_hwprobe` 函数应该返回 `EINVAL`。

**用户或编程常见的使用错误:**

1. **传递错误的 `key` 值:**  如果 `riscv_hwprobe` 结构体中的 `key` 值不是预定义的宏，`__riscv_hwprobe` 可能无法识别，导致返回错误或未定义的行为。
   ```c++
   riscv_hwprobe probes[] = {{.key = 0x99999999}}; // 错误的 key 值
   __riscv_hwprobe(probes, 1, 0, nullptr, 0);
   ```

2. **提供的 `probes` 数组大小不足:** 如果 `count` 参数大于 `probes` 数组的实际大小，`__riscv_hwprobe` 可能会访问越界内存，导致程序崩溃或未定义行为。
   ```c++
   riscv_hwprobe probes[1];
   __riscv_hwprobe(probes, 2, 0, nullptr, 0); // count 超出数组大小
   ```

3. **忽略返回值:**  `__riscv_hwprobe` 通过返回值指示操作是否成功。忽略返回值可能导致程序在发生错误时继续执行，产生难以调试的问题。
   ```c++
   riscv_hwprobe probes[1];
   __riscv_hwprobe(probes, 1, 0, nullptr, 0);
   // 没有检查返回值
   ```

4. **错误地解析 `value` 字段:**  `value` 字段是一个位掩码，需要使用位运算来正确解析其中的信息。直接将其作为整数处理可能会得到错误的结果。
   ```c++
   riscv_hwprobe probes[1] = {{.key = RISCV_HWPROBE_KEY_IMA_EXT_0}};
   __riscv_hwprobe(probes, 1, 0, nullptr, 0);
   if (probes[0].value == 1) { // 错误的判断方式
       // ...
   }
   if (probes[0].value & RISCV_HWPROBE_IMA_FD) { // 正确的判断方式
       // ...
   }
   ```

**Android Framework 或 NDK 如何到达这里:**

1. **应用层 (Java/Kotlin):**  Android 应用开发者通常不会直接调用 `__riscv_hwprobe` 或相关的系统调用。

2. **Android NDK (C/C++):**  NDK 开发者可以使用 Bionic 提供的 C 库函数，这些函数在底层可能会间接调用到 `__riscv_hwprobe` 或类似的硬件探测机制。例如，一些优化的数学库、图形库或性能分析工具可能需要在运行时检测 CPU 的特性。

3. **Android Framework (Java/Kotlin & Native):**
   - **System Services:** Android Framework 中的某些系统服务 (例如，`HardwarePropertiesManager`) 可能会使用底层的硬件抽象层 (HAL) 或直接调用 Bionic 库来获取硬件信息。
   - **ART (Android Runtime):** ART 在应用启动和代码执行过程中，可能会使用 `__riscv_hwprobe` 或类似机制来确定最佳的执行策略和代码优化方案。这通常发生在 Native 代码中。
   - **Native Libraries:**  Framework 依赖的 native 库也可能直接使用 Bionic 库的函数。

4. **Bionic 库:**  `__riscv_hwprobe` 本身就位于 Bionic 库中。

5. **Linux Kernel:**  `__riscv_hwprobe` 最终会通过系统调用（例如 `SYS_riscv_hwprobe`) 与 Linux 内核交互，内核负责实际的硬件信息探测。

**Frida Hook 示例调试步骤:**

我们可以使用 Frida 来 hook `__riscv_hwprobe` 函数，查看其输入参数和返回值。

**示例 1: Hook 用户空间的 `__riscv_hwprobe` 函数 (可能来自 VDSO):**

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Payload: {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found. Please launch the app.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "__riscv_hwprobe"), {
    onEnter: function(args) {
        console.log("[*] __riscv_hwprobe called");
        console.log("    probes:", args[0]);
        console.log("    count:", args[1]);
        console.log("    reserved1:", args[2]);
        console.log("    reserved2:", args[3]);
        console.log("    flags:", args[4]);

        // 可以读取 probes 数组的内容
        let count = parseInt(args[1]);
        if (count > 0) {
            console.log("    Probes data:");
            for (let i = 0; i < count; i++) {
                let probePtr = ptr(args[0]).add(i * Process.pointerSize * 2); // 假设 riscv_hwprobe 结构体包含两个指针大小的字段
                let key = probePtr.readU32();
                let value = probePtr.add(Process.pointerSize).readU64();
                console.log(`        Probe ${i}: key=${key}, value=${value}`);
            }
        }
    },
    onLeave: function(retval) {
        console.log("[*] __riscv_hwprobe returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**示例 2: Hook `syscall` 函数，并过滤 `SYS_riscv_hwprobe` 系统调用:**

```python
import frida
import sys

package_name = "your.app.package.name" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[+] Payload: {message['payload']}")
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found. Please launch the app.")
    sys.exit(1)

script_code = """
const SYS_riscv_hwprobe = 300; // 假设 SYS_riscv_hwprobe 的系统调用号是 300，需要根据实际情况调整

Interceptor.attach(Module.findExportByName(null, "syscall"), {
    onEnter: function(args) {
        let syscall_number = args[0].toInt32();
        if (syscall_number === SYS_riscv_hwprobe) {
            console.log("[*] syscall(SYS_riscv_hwprobe) called");
            console.log("    probes:", args[1]);
            console.log("    count:", args[2]);
            console.log("    reserved1:", args[3]);
            console.log("    reserved2:", args[4]);
            console.log("    flags:", args[5]);

            // 读取 probes 数组内容的代码与示例 1 类似
            let count = parseInt(args[2]);
            if (count > 0) {
                console.log("    Probes data:");
                for (let i = 0; i < count; i++) {
                    let probePtr = ptr(args[1]).add(i * Process.pointerSize * 2);
                    let key = probePtr.readU32();
                    let value = probePtr.add(Process.pointerSize).readU64();
                    console.log(`        Probe ${i}: key=${key}, value=${value}`);
                }
            }
        }
    },
    onLeave: function(retval) {
        let syscall_number = this.context.rdi.toInt32(); // 假设 syscall number 在 rdi 寄存器中
        if (syscall_number === SYS_riscv_hwprobe) {
            console.log("[*] syscall(SYS_riscv_hwprobe) returned:", retval);
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida:** 确保你的系统上安装了 Frida 和 Python 的 Frida 模块。
2. **找到目标进程:** 运行你想要分析的 Android 应用或进程。
3. **获取应用包名:**  找到目标应用的包名。
4. **运行 Frida 脚本:** 将上面的 Python 脚本保存为 `.py` 文件，并将 `package_name` 替换为你的应用包名。然后在终端中运行该脚本。
5. **观察输出:** 当目标应用调用 `__riscv_hwprobe` 或 `syscall` (并且系统调用号匹配 `SYS_riscv_hwprobe`) 时，Frida 脚本会在终端输出相关的参数和返回值。

这些 Frida hook 示例可以帮助你动态地观察 `__riscv_hwprobe` 函数的行为，了解它在实际运行中是如何被调用以及返回什么值的。你需要根据实际的 Android 版本和架构调整系统调用号以及寄存器名称。

希望以上分析能够帮助你理解 `bionic/tests/sys_hwprobe_test.cpp` 文件的功能和相关概念。

### 提示词
```
这是目录为bionic/tests/sys_hwprobe_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2023 The Android Open Source Project
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

#if __has_include(<sys/hwprobe.h>)
#include <sys/hwprobe.h>
#include <sys/syscall.h>
#endif


#if defined(__riscv)
#include <riscv_vector.h>

__attribute__((noinline))
uint64_t scalar_cast(uint8_t const* p) {
  return *(uint64_t const*)p;
}

__attribute__((noinline))
uint64_t scalar_memcpy(uint8_t const* p) {
  uint64_t r;
  __builtin_memcpy(&r, p, sizeof(r));
  return r;
}

__attribute__((noinline))
uint64_t vector_memcpy(uint8_t* d, uint8_t const* p) {
  __builtin_memcpy(d, p, 16);
  return *(uint64_t const*)d;
}

__attribute__((noinline))
uint64_t vector_ldst(uint8_t* d, uint8_t const* p) {
  __riscv_vse8(d, __riscv_vle8_v_u8m1(p, 16), 16);
  return *(uint64_t const*)d;
}

__attribute__((noinline))
uint64_t vector_ldst64(uint8_t* d, uint8_t const* p) {
  __riscv_vse64((unsigned long *)d, __riscv_vle64_v_u64m1((const unsigned long *)p, 16), 16);
  return *(uint64_t const*)d;
}

// For testing scalar and vector unaligned accesses.
uint64_t tmp[3] = {1,1,1};
uint64_t dst[3] = {1,1,1};
#endif

TEST(sys_hwprobe, __riscv_hwprobe_misaligned_scalar) {
#if defined(__riscv)
  uint8_t* p = (uint8_t*)tmp + 1;
  ASSERT_NE(0U, scalar_cast(p));
  ASSERT_NE(0U, scalar_memcpy(p));
#else
  GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
#endif
}

TEST(sys_hwprobe, __riscv_hwprobe_misaligned_vector) {
#if defined(__riscv)
  uint8_t* p = (uint8_t*)tmp + 1;
  uint8_t* d = (uint8_t*)dst + 1;

  ASSERT_NE(0U, vector_ldst(d, p));
  ASSERT_NE(0U, vector_memcpy(d, p));
  ASSERT_NE(0U, vector_ldst64(d, p));
#else
  GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
#endif
}

TEST(sys_hwprobe, __riscv_hwprobe) {
#if defined(__riscv) && __has_include(<sys/hwprobe.h>)
  riscv_hwprobe probes[] = {{.key = RISCV_HWPROBE_KEY_IMA_EXT_0},
                            {.key = RISCV_HWPROBE_KEY_CPUPERF_0}};
  ASSERT_EQ(0, __riscv_hwprobe(probes, 2, 0, nullptr, 0));
  EXPECT_EQ(RISCV_HWPROBE_KEY_IMA_EXT_0, probes[0].key);
  EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_IMA_FD) != 0);
  EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_IMA_C) != 0);
  EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_IMA_V) != 0);
  EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_EXT_ZBA) != 0);
  EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_EXT_ZBB) != 0);
  EXPECT_TRUE((probes[0].value & RISCV_HWPROBE_EXT_ZBS) != 0);

  EXPECT_EQ(RISCV_HWPROBE_KEY_CPUPERF_0, probes[1].key);
  EXPECT_TRUE((probes[1].value & RISCV_HWPROBE_MISALIGNED_MASK) == RISCV_HWPROBE_MISALIGNED_FAST);
#else
  GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
#endif
}

TEST(sys_hwprobe, __riscv_hwprobe_syscall_vdso) {
#if defined(__riscv) && __has_include(<sys/hwprobe.h>)
  riscv_hwprobe probes_vdso[] = {{.key = RISCV_HWPROBE_KEY_IMA_EXT_0},
                                 {.key = RISCV_HWPROBE_KEY_CPUPERF_0}};
  ASSERT_EQ(0, __riscv_hwprobe(probes_vdso, 2, 0, nullptr, 0));

  riscv_hwprobe probes_syscall[] = {{.key = RISCV_HWPROBE_KEY_IMA_EXT_0},
                                    {.key = RISCV_HWPROBE_KEY_CPUPERF_0}};
  ASSERT_EQ(0, syscall(SYS_riscv_hwprobe, probes_syscall, 2, 0, nullptr, 0));

  // Check we got the same answers from the vdso and the syscall.
  EXPECT_EQ(RISCV_HWPROBE_KEY_IMA_EXT_0, probes_syscall[0].key);
  EXPECT_EQ(probes_vdso[0].key, probes_syscall[0].key);
  EXPECT_EQ(probes_vdso[0].value, probes_syscall[0].value);
  EXPECT_EQ(RISCV_HWPROBE_KEY_CPUPERF_0, probes_syscall[1].key);
  EXPECT_EQ(probes_vdso[1].key, probes_syscall[1].key);
  EXPECT_EQ(probes_vdso[1].value, probes_syscall[1].value);
#else
  GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
#endif
}

TEST(sys_hwprobe, __riscv_hwprobe_fail) {
#if defined(__riscv) && __has_include(<sys/hwprobe.h>)
  riscv_hwprobe probes[] = {};
  ASSERT_EQ(EINVAL, __riscv_hwprobe(probes, 0, 0, nullptr, ~0));
#else
  GTEST_SKIP() << "__riscv_hwprobe requires riscv64";
#endif
}
```