Response:
Let's break down the thought process for answering the user's request about `memtag_globals_binary.cpp`.

**1. Understanding the Core Task:**

The fundamental goal is to analyze the provided C++ code and explain its purpose, functionality, and relevance within the Android ecosystem, specifically concerning memory tagging (MemTag/MTE). The user wants a comprehensive explanation covering libc functions, dynamic linking, potential errors, and how the code fits into the broader Android framework.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd quickly scan the code to grasp its overall structure and identify key elements. I'd look for:

* **Includes:**  Standard C/C++ headers (`stdio.h`, `stdlib.h`, `string.h`, `unistd.h`, `<string>`, `<vector>`) and the custom header `memtag_globals.h`. This indicates basic system-level operations and interaction with other parts of the codebase.
* **Global Variables:**  A large number of global variables are declared with different attributes (`no_sanitize("memtag")`, `const`, `static`, `visibility("hidden")`, `__thread`). This immediately suggests the file is designed to test how these different global variable types interact with memory tagging.
* **Function Declarations and Definitions:**  `exe_print_variables`, `dso_print`, `dso_print_others`, `exe_check_assertions`, `crash`, and `main`. This hints at a structure involving a main executable and potentially a shared library (`dso`).
* **Pointer Initialization:**  Lots of pointers are initialized to point to different parts of the global variables. This strongly suggests the code is testing address calculations and potentially memory tagging behavior on these pointers.
* **Helper Functions:** `get_expected_tagged_vars` and `get_expected_untagged_vars` likely define the expected tagging state of the global variables for verification purposes.
* **Assertions:** The `check_tagged`, `check_untagged`, `check_matching_tags`, and `check_eq` functions (likely defined in `memtag_globals.h`) point towards a testing or verification purpose.
* **The `crash` function:**  Intentionally causes a buffer overflow, clearly indicating a test for memory safety mechanisms.
* **The `main` function:**  Handles command-line arguments and orchestrates the tests.

**3. Deconstructing the Requirements:**

Next, I'd go through the user's explicit requests and map them to the code:

* **功能 (Functionality):** This requires explaining what the code *does*. The initial scan already gives a strong clue: testing memory tagging of global variables.
* **与 Android 功能的关系 (Relationship to Android functionality):**  The filename and the mention of "bionic" immediately link it to Android's C library. The focus on memory tagging strongly connects to Android's memory safety features, particularly MTE.
* **libc 函数的功能实现 (Implementation of libc functions):**  The code uses standard libc functions like `malloc`, `free`, `printf`, `fflush`, `strcmp`. I need to explain their general purpose and how they are used *in this specific context*. Since the question asks for implementation details, I should provide a general overview of those implementations within bionic.
* **dynamic linker 的功能 (Dynamic linker functionality):** The presence of `extern` declarations and the likely interaction with a `dso` (dynamic shared object) signifies dynamic linking. I need to explain how the linker resolves symbols, especially concerning global variables with different visibility and tagging attributes. The request for an SO layout and linking process is key here.
* **逻辑推理 (Logical inference):** The code makes assertions based on expected behavior. I need to explain the logic behind these expectations and potentially give examples of inputs and outputs.
* **用户或编程常见的使用错误 (Common user/programming errors):** The intentional buffer overflow in `crash()` is a prime example. I can also discuss other common memory-related errors that MemTag aims to prevent.
* **Android framework/NDK 如何到达这里 (How Android framework/NDK reaches this code):** This requires explaining the build process for bionic and how test binaries like this one are executed. I need to connect it to the NDK (for native development) and the broader Android framework's reliance on bionic.
* **Frida hook 示例调试 (Frida hook example):** This involves demonstrating how to use Frida to inspect the execution of this code, specifically focusing on the tagging of variables.

**4. Detailed Code Analysis and Explanation (Iterative Process):**

Now, I'd go through the code line by line, focusing on the user's requests. This would involve:

* **Global Variable Analysis:** For each global variable, explain its attributes (e.g., `static`, `const`, `hidden`, `no_sanitize("memtag")`) and how these attributes influence its visibility and tagging behavior.
* **Pointer Analysis:** Explain why each pointer is initialized in a specific way and what it's intended to demonstrate (e.g., pointers inside, at the end, and past the end of an array).
* **Function Analysis:**  Explain the purpose of each function and how it contributes to the overall testing strategy. For `exe_check_assertions`, I need to explain *why* certain checks are performed and what they are validating.
* **Dynamic Linking Aspects:**  Pay close attention to the `extern` declarations. Explain how the dynamic linker resolves these symbols, considering visibility attributes and tagging. Conceptualize the layout of the main executable and the shared library in memory.
* **Memory Tagging Explanation:** Explain the concept of memory tagging and how it's being tested in this code. Specifically address the `no_sanitize("memtag")` attribute and its effect.

**5. Structuring the Answer:**

To make the answer clear and organized, I'd structure it according to the user's requests:

* Start with a summary of the file's functionality.
* Address the relationship to Android, focusing on bionic and MemTag.
* Explain the libc functions used.
* Detail the dynamic linking aspects, including the SO layout and linking process.
* Provide logical reasoning with examples.
* Discuss common errors.
* Explain how the Android framework/NDK leads to this code.
* Provide Frida hook examples.

**6. Refining and Expanding:**

After the initial draft, I'd review and refine the answer:

* **Clarity and Accuracy:** Ensure the explanations are technically accurate and easy to understand.
* **Completeness:**  Double-check that all aspects of the user's request have been addressed.
* **Examples:** Provide concrete examples to illustrate abstract concepts (e.g., SO layout, linking process).
* **Assumptions and Simplifications:**  If making any assumptions or simplifications, explicitly state them.
* **Code Snippets:** Include relevant code snippets to support the explanations.

**Example of Self-Correction/Refinement during the process:**

Initially, I might just say "the code tests memory tagging." But then, realizing the user wants details, I'd refine this to: "The code primarily functions as a test case within the Android bionic library to verify the correct application of Memory Tagging Extension (MTE) to various types of global variables (static, const, hidden, thread-local, external) under different visibility and attribute settings. It specifically checks that pointers to tagged memory have their top byte set, while pointers to untagged memory do not."

Similarly, when explaining the dynamic linker, simply stating "the linker resolves symbols" isn't enough. I'd need to elaborate on *how* it resolves `extern` variables, the role of the symbol table, and the impact of visibility attributes on the linking process. The request for an SO layout forces me to visualize and describe the memory organization.

By following this structured and iterative process, I can generate a comprehensive and accurate answer that addresses all aspects of the user's detailed request.好的，让我们来详细分析一下 `bionic/tests/libs/memtag_globals_binary.cpp` 这个文件。

**文件功能概述**

这个 C++ 源文件 `memtag_globals_binary.cpp` 是 Android Bionic 库中的一个测试程序。它的主要功能是：

1. **定义各种类型的全局变量：**  文件中定义了多种具有不同存储类别、访问权限和内存标签属性的全局变量。这包括：
    * 普通全局变量
    * 声明为 `no_sanitize("memtag")` 的未标记全局变量
    * 常量全局变量
    * 静态常量全局变量
    * 静态全局变量
    * 具有 `hidden` 可见性属性的全局变量和常量
    * 线程局部存储 (TLS) 全局变量（标记和未标记）
    * 外部声明的全局变量（标记和未标记）
2. **初始化指向全局变量的指针：**  创建了指向各种全局变量及其内部不同位置的指针。这些指针用于测试内存地址的计算和内存标签的处理。
3. **断言检查：**  `exe_check_assertions` 函数执行一系列断言，以验证全局变量的预期状态，特别是关于内存标签的状态（是否被标记）和指针指向的地址是否正确。
4. **模拟内存访问：** 代码尝试写入一些非 `const` 的全局变量，以确保它们是可写的。
5. **模拟全局缓冲区溢出：**  `crash` 函数故意执行一个越界写入操作，用于测试内存安全机制（如 MTE - Memory Tagging Extension）是否能够捕获这种错误。
6. **打印变量地址：** `exe_print_variables` 和相关的 `dso_print_variables` 函数用于打印全局变量的地址，用于调试和验证。
7. **与共享库交互：**  代码中调用了 `dso_print` 和 `dso_print_others` 以及 `dso_check_assertions`，这表明该测试程序还与一个动态共享对象 (DSO) 进行交互，共同测试全局变量在不同模块之间的行为。

**与 Android 功能的关系及举例说明**

这个测试文件与 Android 的核心功能紧密相关，因为它直接测试了 **Bionic 库的内存管理和动态链接功能**，特别是与 **内存标签扩展 (MTE)** 相关的行为。

* **Bionic 库的内存管理：**  Bionic 负责 Android 上的内存分配、释放以及底层的内存管理。这个测试通过定义和操作各种全局变量，以及使用 `malloc` 和 `free`，来验证 Bionic 的内存管理机制是否正确地处理了不同类型的全局变量。
    * **举例：**  测试中声明了 `char global[30]`，Bionic 需要确保这块 30 字节的内存被正确分配并在程序的生命周期内有效。
* **动态链接器：**  Android 使用动态链接器 (linker) 来加载和链接共享库。测试中使用了 `extern` 关键字来声明在其他编译单元中定义的全局变量，这涉及到动态链接器如何解析这些符号，并确保不同模块之间对同一全局变量的访问是一致的。
    * **举例：**  `extern int global_extern;`  的声明意味着 `global_extern` 变量是在另一个编译单元（通常是另一个 `.o` 文件或共享库）中定义的。动态链接器需要在运行时找到这个符号的地址，并将其链接到当前的测试程序。
* **内存标签扩展 (MTE)：**  Android 引入了 MTE 作为一种硬件辅助的内存安全特性。该测试的核心目标是验证 MTE 在处理全局变量时的行为是否符合预期，包括：
    * **默认标记：**  默认情况下，大部分全局变量应该被标记。
    * **取消标记：**  使用 `__attribute__((no_sanitize("memtag")))` 可以显式地声明某些全局变量不被标记。
    * **跨模块标记：**  测试跨越可执行文件和共享库的全局变量的标记状态。
    * **指针标记：**  验证指向已标记内存的指针是否也被标记。
    * **错误检测：**  通过 `crash()` 函数模拟缓冲区溢出，验证 MTE 是否能够检测到这种违规行为。

**libc 函数的功能实现**

测试代码中使用的 libc 函数主要包括：

* **`stdint.h` 中的类型定义：**  如 `uintptr_t`，用于表示指针大小的无符号整数类型。
* **`stdio.h` 中的输入/输出函数：**
    * **`printf()`:**  格式化输出到标准输出。在测试中用于打印变量地址和状态信息。
    * **`fflush()`:**  刷新输出流，确保输出立即显示。
* **`stdlib.h` 中的通用工具函数：**
    * **`malloc()`:**  在堆上动态分配内存。测试中用于分配一块小的堆内存来检查其标记状态。
    * **`free()`:**  释放 `malloc` 分配的内存。
    * **`atoi()` (虽然代码中未使用，但 `main` 函数的参数处理逻辑可以看作是类似的功能):**  将字符串转换为整数。在 `main` 函数中，将命令行参数转换为布尔值。
* **`string.h` 中的字符串操作函数：**
    * **`strcmp()` (虽然代码中未使用，但 `main` 函数的参数比较逻辑可以看作是类似的功能):**  比较两个字符串。在 `main` 函数中比较命令行参数。
* **`unistd.h` 中的 POSIX 操作系统 API：**
    * **`sleep()` (虽然代码中未使用，但在实际的测试框架中可能被使用):**  使当前进程暂停执行一段时间。

**libc 函数的实现（简要说明）：**

这些 libc 函数的实现位于 Bionic 库中，它们通常是对操作系统提供的系统调用的封装，并可能包含一些优化和平台特定的处理。

* **`printf()`:**  Bionic 的 `printf` 函数会解析格式字符串，并将参数转换为相应的文本表示，最终通过系统调用（如 `write`）输出到标准输出文件描述符。
* **`malloc()`:**  Bionic 的 `malloc` 使用一种堆分配器（例如 jemalloc 或 scudo），负责管理进程的堆内存。当调用 `malloc` 时，分配器会在堆中找到一块足够大的空闲内存块，并返回指向该块的指针。Bionic 的 `malloc` 实现会考虑内存对齐和元数据管理。
* **`free()`:**  `free` 函数将之前通过 `malloc` 分配的内存块标记为空闲，使其可以被后续的 `malloc` 调用重新分配。Bionic 的 `free` 实现也会进行一些安全检查，例如检查释放的内存块是否是之前由 `malloc` 分配的。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程**

这个测试文件通过 `extern` 关键字引用了在其他编译单元中定义的全局变量，这触发了动态链接器的参与。

**SO 布局样本 (假设存在一个名为 `libmemtag_globals_dso.so` 的共享库):**

```
# 可执行文件 (memtag_globals_binary) 内存布局 (简化)
[代码段]          (可执行指令)
[只读数据段]      (常量数据，如 const_global)
[数据段]          (已初始化的全局变量，如 global, global_untagged)
[BSS段]           (未初始化的全局变量，如 hidden_global)
[堆]
[栈]
[共享库映射区]

# 共享库 (libmemtag_globals_dso.so) 内存布局 (简化)
[代码段]          (可执行指令)
[只读数据段]      (常量数据)
[数据段]          (已初始化的全局变量，如 global_extern 的定义)
[BSS段]           (未初始化的全局变量)
```

**链接的处理过程：**

1. **编译时链接 (静态链接)：** 编译器在编译 `memtag_globals_binary.cpp` 时，会遇到 `extern int global_extern;` 这样的声明。编译器知道 `global_extern` 是一个外部符号，但它的定义不在当前编译单元中。编译器会在生成的目标文件 (`.o`) 中记录这个未解析的符号。
2. **链接时链接 (动态链接)：**  当链接器将 `memtag_globals_binary.o` 和 `libmemtag_globals_dso.so` 链接成最终的可执行文件时，链接器会执行以下操作：
    * **符号解析：** 链接器会查找所有目标文件和共享库中的符号表，试图找到 `global_extern` 的定义。假设 `global_extern` 在 `libmemtag_globals_dso.so` 中定义并导出，链接器会找到它的地址。
    * **重定位：**  在 `memtag_globals_binary` 的代码或数据段中，凡是引用到 `global_extern` 的地方（例如 `&global_extern`），都需要用 `global_extern` 在 `libmemtag_globals_dso.so` 中的实际地址来替换。这个过程称为重定位。
    * **生成重定位表：**  链接器会在可执行文件中生成重定位表，记录哪些地方需要进行地址修改以及如何修改。
3. **运行时链接：**  当操作系统加载并执行 `memtag_globals_binary` 时，动态链接器 (在 Android 上是 `linker64` 或 `linker`) 会被激活。
    * **加载共享库：** 动态链接器会加载 `libmemtag_globals_dso.so` 到进程的地址空间。
    * **解析符号：**  动态链接器会再次检查未解析的符号。由于共享库已经被加载，`global_extern` 的地址现在是已知的。
    * **执行重定位：**  动态链接器会根据可执行文件中的重定位表，修改 `memtag_globals_binary` 中引用 `global_extern` 的地址，使其指向 `libmemtag_globals_dso.so` 中 `global_extern` 的实际地址。

**内存标签的处理与动态链接：**

在进行重定位时，动态链接器还需要考虑内存标签。对于启用了 MTE 的系统：

* **导入符号的标记：** 如果 `global_extern` 在 `libmemtag_globals_dso.so` 中被标记，那么在 `memtag_globals_binary` 中指向 `global_extern` 的指针也应该被标记。动态链接器需要确保重定位后的指针地址包含正确的标签。
* **导出符号的标记属性：**  共享库需要声明哪些符号是需要被标记的，以便链接器在进行跨模块链接时能够正确处理。

**逻辑推理，假设输入与输出**

假设我们运行 `memtag_globals_binary` 且命令行参数为空（不启用指针标记断言）。

* **假设输入:**  运行 `./memtag_globals_binary`
* **预期输出:**

```
heap address: 0x... (堆地址)
  Variables accessible from the binary:
    global: 0x... (global 的地址)
    pointer_inside_global: 0x... (pointer_inside_global 的值，应该比 global 地址偏移 17)
    pointer_to_global_end: 0x... (pointer_to_global_end 的值，应该比 global 地址偏移 30)
    pointer_past_global_end: 0x... (pointer_past_global_end 的值，应该比 global 地址偏移 48)
    hidden_global: 0x... (hidden_global 的地址)
    hidden_attr_global: 0x... (hidden_attr_global 的地址)
    global_extern: 0x... (global_extern 的地址)
  Variables accessible from the DSO:
    global_in_dso: 0x... (global_in_dso 的地址)
    tagged_global_in_dso: 0x... (tagged_global_in_dso 的地址)
    pointer_to_tagged_global_in_dso: 0x... (pointer_to_tagged_global_in_dso 的值)
  Untagged variables accessible from the binary:
    global_extern_untagged: 0x...
    global_extern_untagged_definition_but_tagged_import: 0x...
    global_untagged: 0x...
    const_global: 0x...
    hidden_const_global: 0x...
    hidden_attr_const_global: 0x...
    tls_global: 0x...
    hidden_tls_global: 0x...
  Untagged variables accessible from the DSO:
    untagged_global_in_dso: 0x...
Assertions were passed. Now doing a global-buffer-overflow.
Segmentation fault (core dumped)
```

**解释:**

* 会打印堆地址和各种全局变量的地址。
* 会执行断言检查，由于没有启用指针标记检查，与指针标记相关的断言会被跳过。
* 最终会调用 `crash()` 函数，导致全局缓冲区溢出，程序会因为内存访问错误而崩溃，产生 "Segmentation fault"。

如果运行 `./memtag_globals_binary 1`，则会启用指针标记断言，预期输出会类似，但在断言检查阶段会额外验证指针是否被正确标记。

**用户或者编程常见的使用错误**

* **忘记初始化全局变量：** 虽然 C++ 保证了基本类型的全局变量会被默认初始化为 0，但对于复杂类型，忘记初始化可能会导致未定义的行为。
* **在多线程环境下不正确地使用全局变量：**  全局变量在多线程环境中是共享的，如果不采取适当的同步措施（如互斥锁），可能会导致数据竞争和不一致性。
* **错误地假设全局变量的生命周期：** 全局变量的生命周期从程序启动到程序结束。在某些情况下，程序员可能会错误地认为全局变量在某个时刻会被销毁或重新初始化。
* **过度使用全局变量：**  过多的全局变量会增加程序的复杂性，降低模块化程度，并可能导致命名冲突。
* **与内存标签相关的错误：**
    * **混淆标记和未标记的指针：**  在启用了 MTE 的系统上，如果代码中没有正确区分标记和未标记的指针，可能会导致意外的内存访问错误。
    * **错误地假设外部符号的标记状态：**  当使用 `extern` 声明外部符号时，需要了解该符号在定义处的标记状态，并确保当前模块以兼容的方式使用它。
    * **不理解 `no_sanitize("memtag")` 的作用：** 开发者需要清楚何时以及为何使用 `no_sanitize("memtag")`，避免在应该标记的变量上禁用标记。

**android framework or ndk 是如何一步步的到达这里**

1. **Bionic 库的构建：**  `memtag_globals_binary.cpp` 是 Bionic 库源代码的一部分。在 Android 系统构建过程中，Bionic 库会被编译成共享库 (`libc.so`, `libm.so`, `libdl.so` 等) 和一些测试可执行文件。这个 `.cpp` 文件会被编译成一个可执行文件 `memtag_globals_binary`，通常位于 Android 系统镜像的某个测试目录下（例如 `/data/local/tmp` 或更底层的测试目录）。
2. **测试执行：**  Android 的测试框架（例如 Android Compatibility Test Suite (CTS) 或底层单元测试）会负责执行这些测试可执行文件。
3. **NDK 的关系：**  虽然这个特定的测试文件不是直接通过 NDK 构建的，但 NDK 提供的头文件和库（特别是 `libc` 相关的功能）与 Bionic 库是对应的。使用 NDK 开发的 native 代码最终会链接到 Bionic 库。理解 Bionic 的行为对于 NDK 开发者来说至关重要。例如，如果 NDK 开发者使用了全局变量并希望利用 MTE 的安全性，就需要了解 Bionic 如何处理全局变量的标记。
4. **Framework 的关系：**  Android Framework 的许多核心组件都是用 C++ 编写的，它们直接或间接地依赖于 Bionic 库提供的功能。例如，Framework 中进行内存管理的部分会使用 `malloc` 和 `free`，动态加载 native 库会使用动态链接器提供的接口。

**Frida hook 示例调试这些步骤**

我们可以使用 Frida 来 hook `memtag_globals_binary` 的执行，以观察全局变量的地址和内存标签状态。以下是一个简单的 Frida 脚本示例：

```javascript
if (Process.arch === 'arm64') {
  const getMteTag = ptr => {
    const address = ptr.and(0xfffffffffffffff0n); // 清除标签
    const tag = ptr.shr(56).toNumber();
    return `Address: ${address}, Tag: ${tag.toString(16)}`;
  };

  const checkTagged = Module.findExportByName(null, "check_tagged");
  if (checkTagged) {
    Interceptor.attach(checkTagged, {
      onEnter: function(args) {
        const ptr = ptr(args[0]);
        console.log(`check_tagged called with: ${getMteTag(ptr)}`);
      }
    });
  }

  const checkUntagged = Module.findExportByName(null, "check_untagged");
  if (checkUntagged) {
    Interceptor.attach(checkUntagged, {
      onEnter: function(args) {
        const ptr = ptr(args[0]);
        console.log(`check_untagged called with: ${getMteTag(ptr)}`);
      }
    });
  }

  const print_variable_address = Module.findExportByName(null, "print_variable_address");
  if (print_variable_address) {
    Interceptor.attach(print_variable_address, {
      onEnter: function(args) {
        const name = Memory.readUtf8String(args[0]);
        const ptr = ptr(args[1]);
        console.log(`print_variable_address: ${name} at ${getMteTag(ptr)}`);
      }
    });
  }
} else {
  console.log("MTE is only applicable on arm64 architecture.");
}
```

**使用方法：**

1. 将上述 JavaScript 代码保存为 `hook.js`。
2. 将编译好的 `memtag_globals_binary` 推送到 Android 设备上（例如 `/data/local/tmp/`）。
3. 使用 Frida 附加到该进程：

   ```bash
   frida -U -f /data/local/tmp/memtag_globals_binary -l hook.js --no-pause
   ```

   或者，如果进程已经运行：

   ```bash
   frida -U [进程ID或进程名] -l hook.js
   ```

**解释：**

* **架构检查：** 代码首先检查架构是否为 `arm64`，因为 MTE 是 ARMv8.5-A 引入的特性。
* **`getMteTag` 函数：**  这个函数用于从指针地址中提取 MTE 标签。在 ARM64 架构上，指针的最高字节（bits 56-63）用于存储标签。
* **Hook `check_tagged` 和 `check_untagged`：**  拦截这两个函数，打印出被检查的指针的地址和 MTE 标签。这可以验证测试代码是否正确地判断了变量的标记状态。
* **Hook `print_variable_address`：** 拦截这个函数，打印出变量名和对应的地址以及 MTE 标签。
* **Frida 命令：**  使用 Frida 的命令行工具来执行 hook 脚本。`-U` 表示连接 USB 设备，`-f` 指定要启动并 hook 的应用程序，`-l` 指定要加载的 hook 脚本，`--no-pause` 表示不暂停程序启动。

通过运行这个 Frida 脚本，你可以实时观察 `memtag_globals_binary` 中 `check_tagged` 和 `check_untagged` 函数的调用，以及 `print_variable_address` 打印的变量地址，并验证这些地址是否具有预期的 MTE 标签。这对于理解内存标签的工作原理和调试相关问题非常有帮助。

希望以上详细的分析能够帮助你理解 `bionic/tests/libs/memtag_globals_binary.cpp` 文件的功能、与 Android 的关系以及如何进行调试。

Prompt: 
```
这是目录为bionic/tests/libs/memtag_globals_binary.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2024 The Android Open Source Project
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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string>
#include <vector>

#include "memtag_globals.h"

// Adapted from the LLD test suite: lld/test/ELF/Inputs/aarch64-memtag-globals.s

/// Global variables defined here, of various semantics.
char global[30] = {};
__attribute__((no_sanitize("memtag"))) int global_untagged = 0;
const int const_global = 0;
static const int hidden_const_global = 0;
static char hidden_global[12] = {};
__attribute__((visibility("hidden"))) int hidden_attr_global = 0;
__attribute__((visibility("hidden"))) const int hidden_attr_const_global = 0;

/// Should be untagged.
__thread int tls_global;
__thread static int hidden_tls_global;

/// Tagged, from the other file.
extern int global_extern;
/// Untagged, from the other file.
extern __attribute__((no_sanitize("memtag"))) int global_extern_untagged;
/// Tagged here, but untagged in the definition found in the sister objfile
/// (explicitly).
extern int global_extern_untagged_definition_but_tagged_import;

/// ABS64 relocations. Also, forces symtab entries for local and external
/// globals.
char* pointer_to_global = &global[0];
char* pointer_inside_global = &global[17];
char* pointer_to_global_end = &global[30];
char* pointer_past_global_end = &global[48];
int* pointer_to_global_untagged = &global_untagged;
const int* pointer_to_const_global = &const_global;
/// RELATIVE relocations.
const int* pointer_to_hidden_const_global = &hidden_const_global;
char* pointer_to_hidden_global = &hidden_global[0];
int* pointer_to_hidden_attr_global = &hidden_attr_global;
const int* pointer_to_hidden_attr_const_global = &hidden_attr_const_global;
/// RELATIVE relocations with special AArch64 MemtagABI semantics, with the
/// offset ('12' or '16') encoded in the place.
char* pointer_to_hidden_global_end = &hidden_global[12];
char* pointer_past_hidden_global_end = &hidden_global[16];
/// ABS64 relocations.
int* pointer_to_global_extern = &global_extern;
int* pointer_to_global_extern_untagged = &global_extern_untagged;
int* pointer_to_global_extern_untagged_definition_but_tagged_import =
    &global_extern_untagged_definition_but_tagged_import;

// Force materialization of these globals into the symtab.
int* get_address_to_tls_global() {
  return &tls_global;
}
int* get_address_to_hidden_tls_global() {
  return &hidden_tls_global;
}

static const std::vector<std::pair<const char*, const void*>>& get_expected_tagged_vars() {
  static std::vector<std::pair<const char*, const void*>> expected_tagged_vars = {
      {"global", &global},
      {"pointer_inside_global", pointer_inside_global},
      {"pointer_to_global_end", pointer_to_global_end},
      {"pointer_past_global_end", pointer_past_global_end},
      {"hidden_global", &hidden_global},
      {"hidden_attr_global", &hidden_attr_global},
      {"global_extern", &global_extern},
  };
  return expected_tagged_vars;
}

static const std::vector<std::pair<const char*, const void*>>& get_expected_untagged_vars() {
  static std::vector<std::pair<const char*, const void*>> expected_untagged_vars = {
      {"global_extern_untagged", &global_extern_untagged},
      {"global_extern_untagged_definition_but_tagged_import",
       &global_extern_untagged_definition_but_tagged_import},
      {"global_untagged", &global_untagged},
      {"const_global", &const_global},
      {"hidden_const_global", &hidden_const_global},
      {"hidden_attr_const_global", &hidden_attr_const_global},
      {"tls_global", &tls_global},
      {"hidden_tls_global", &hidden_tls_global},
  };
  return expected_untagged_vars;
}

void exe_print_variables() {
  print_variables("  Variables accessible from the binary:\n", get_expected_tagged_vars(),
                  get_expected_untagged_vars());
}

// Dump the addresses of the global variables to stderr
void dso_print();
void dso_print_others();

void exe_check_assertions(bool check_pointers_are_tagged) {
  // Check that non-const variables are writeable.
  *pointer_to_global = 0;
  *pointer_inside_global = 0;
  *(pointer_to_global_end - 1) = 0;
  *pointer_to_global_untagged = 0;
  *pointer_to_hidden_global = 0;
  *pointer_to_hidden_attr_global = 0;
  *(pointer_to_hidden_global_end - 1) = 0;
  *pointer_to_global_extern = 0;
  *pointer_to_global_extern_untagged = 0;
  *pointer_to_global_extern_untagged_definition_but_tagged_import = 0;

  if (check_pointers_are_tagged) {
    for (const auto& [_, pointer] : get_expected_tagged_vars()) {
      check_tagged(pointer);
    }
  }

  for (const auto& [_, pointer] : get_expected_untagged_vars()) {
    check_untagged(pointer);
  }

  check_matching_tags(pointer_to_global, pointer_inside_global);
  check_matching_tags(pointer_to_global, pointer_to_global_end);
  check_matching_tags(pointer_to_global, pointer_past_global_end);
  check_eq(pointer_inside_global, pointer_to_global + 17);
  check_eq(pointer_to_global_end, pointer_to_global + 30);
  check_eq(pointer_past_global_end, pointer_to_global + 48);

  check_matching_tags(pointer_to_hidden_global, pointer_to_hidden_global_end);
  check_matching_tags(pointer_to_hidden_global, pointer_past_hidden_global_end);
  check_eq(pointer_to_hidden_global_end, pointer_to_hidden_global + 12);
  check_eq(pointer_past_hidden_global_end, pointer_to_hidden_global + 16);
}

void crash() {
  *pointer_past_global_end = 0;
}

int main(int argc, char** argv) {
  bool check_pointers_are_tagged = false;
  // For an MTE-capable device, provide argv[1] == '1' to enable the assertions
  // that pointers should be tagged.
  if (argc >= 2 && argv[1][0] == '1') {
    check_pointers_are_tagged = true;
  }

  char* heap_ptr = static_cast<char*>(malloc(1));
  print_variable_address("heap address", heap_ptr);
  *heap_ptr = 0;
  if (check_pointers_are_tagged) check_tagged(heap_ptr);
  free(heap_ptr);

  exe_print_variables();
  dso_print_variables();

  exe_check_assertions(check_pointers_are_tagged);
  dso_check_assertions(check_pointers_are_tagged);

  printf("Assertions were passed. Now doing a global-buffer-overflow.\n");
  fflush(stdout);
  crash();
  printf("global-buffer-overflow went uncaught.\n");
  return 0;
}

"""

```