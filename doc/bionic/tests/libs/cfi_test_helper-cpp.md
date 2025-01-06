Response:
Let's break down the thought process for answering the request about `cfi_test_helper.cpp`.

**1. Understanding the Goal:**

The core request is to analyze a C++ file in Android's Bionic library (`cfi_test_helper.cpp`) and explain its functionality, its relation to Android, the implementation of relevant libc functions (even if mocked here), its interaction with the dynamic linker, potential errors, and how to reach it from Android framework/NDK using Frida.

**2. Initial Code Analysis (Skimming and Identifying Key Parts):**

* **Headers:** `<stdint.h>`, `<stdlib.h>`, `"CHECK.h"`. These tell us it's standard C/C++ with potentially some Bionic-specific assertions (`CHECK`).
* **`__cfi_slowpath`:** Declared as `weak`. This immediately suggests a mechanism related to Control Flow Integrity (CFI), specifically the "slow path" handler when a CFI violation *might* occur. The `weak` attribute means it might not be present in all build configurations.
* **`g_count`:** A global integer initialized to zero. This looks like a counter used for tracking the execution flow.
* **`__cfi_check`:** This is the core of the test helper. It's marked with `no_sanitize("hwaddress")` and `aligned(4096)`, indicating it's deliberately bypassing Hardware Address Sanitizer (HWA) checks and has specific alignment requirements. Its function is to increment `g_count`. This is a **mock** implementation, not the real CFI check.
* **`preinit_ctor` and `preinit_ctor_p`:** This is the pre-initialization mechanism. `preinit_ctor` is a function executed very early in the program's startup, before `main`. The `section(".preinit_array")` and `used` attributes are crucial for ensuring this function is linked and called.
* **`ctor`:**  A regular constructor function, executed after the pre-init phase but before `main`.
* **`main`:** The entry point of the program. It also calls `__cfi_slowpath`.
* **`CHECK` macros:** These are assertions. If the condition is false, the program will likely abort.

**3. Deconstructing the Request - Addressing Each Point Systematically:**

* **功能 (Functionality):** The primary function is to *test* the CFI mechanism. It's not a real CFI implementation, but rather a controlled environment to verify how the CFI slow path is invoked during different stages of program initialization. The key actions are incrementing `g_count` and calling the (potentially absent) `__cfi_slowpath`.

* **与 Android 的关系 (Relationship with Android):** Explain that CFI is a security feature in Android to prevent certain types of attacks. This test helper validates parts of that infrastructure in Bionic. Give the example of preventing ROP attacks.

* **libc 函数 (libc Functions):** The file uses `stdlib.h` for `NULL` and potentially other standard library elements (though not explicitly called). Focus on the *mocked* `__cfi_check` and explain that a *real* implementation would likely involve looking up function type information and comparing it with the target address. Since it's mocked, describe the simplified behavior.

* **Dynamic Linker 功能 (Dynamic Linker Functionality):**  This is where the `preinit_array` and constructors become relevant. Explain how the dynamic linker (`linker64` or `linker`) is responsible for:
    * Loading shared libraries.
    * Resolving symbols.
    * Executing `.preinit_array` functions *before* `main`.
    * Executing constructors (`.init_array`) *before* `main`.
    * Provide a simplified SO layout illustrating these sections.
    * Explain the linking process – symbol resolution, relocation.

* **逻辑推理 (Logical Deduction):** The `g_count` variable provides a clear way to trace execution. State the assumptions (the code runs sequentially) and predict the values of `g_count` at each `CHECK` point. Input here is implicit (running the program). Output is the success of the `CHECK` assertions.

* **用户/编程常见错误 (Common User/Programming Errors):**  Focus on errors related to CFI and linking:
    * Mismatched function pointers.
    * Incorrect library linking.
    * Problems with the CFI configuration itself.

* **Android Framework/NDK 到达这里 (Path from Framework/NDK):** This requires outlining the process from a high-level Android component down to Bionic:
    * App starts -> Zygote -> `app_process` -> Dynamic linker.
    * NDK: Similar flow, but the NDK app links against Bionic libraries.
    * Emphasize that this test is *within* Bionic, used for Bionic's own testing. It's not directly called by typical Android apps.

* **Frida Hook 示例 (Frida Hook Example):** Provide practical Frida snippets to:
    * Hook `__cfi_check` to observe its arguments and count.
    * Hook `preinit_ctor` and `ctor` to understand the execution order.
    * Hook `main` to see when the main function starts.

**4. Structuring the Answer:**

Organize the information logically, following the order of the request. Use clear headings and bullet points for readability. Explain technical terms clearly.

**5. Refining and Reviewing:**

Read through the answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas where more detail might be needed. For instance, initially, I might just say "tests CFI." But refining that to "tests the CFI *mechanism* and the invocation of the slow path during initialization" is more accurate. Also, initially, I might forget to mention the importance of `used` attribute for the linker to keep those sections.

By following this structured approach, breaking down the problem, and thinking step-by-step, we can create a comprehensive and accurate answer to the complex request. The key is to understand the code's purpose, its place within the Android ecosystem, and the technologies it interacts with (CFI, dynamic linking).
这个文件 `bionic/tests/libs/cfi_test_helper.cpp` 是 Android Bionic 库中的一个测试辅助文件，主要用于测试 **控制流完整性 (Control Flow Integrity, CFI)** 机制。  Bionic 是 Android 的基础 C 库、数学库和动态链接器，因此这个测试文件直接关系到 Android 底层的安全和稳定性。

**它的功能：**

1. **模拟 CFI 检查:**  文件中定义了一个名为 `__cfi_check` 的函数，它被标记为 `no_sanitize("hwaddress")` 和 `aligned(4096)`。  这个函数的功能是模拟 CFI 机制中的类型检查。在实际的 CFI 实现中，当发生函数调用时，编译器会插入对目标函数类型的检查，确保调用目标的类型与预期类型一致，从而防止恶意代码修改函数指针或虚函数表进行攻击。  在这个测试文件中，`__cfi_check` 的简化版本只是简单地递增一个全局计数器 `g_count`。

2. **测试 CFI 的慢速路径:**  文件中声明了一个弱符号 `__cfi_slowpath`。  CFI 机制通常有两种路径：快速路径和慢速路径。快速路径是检查通过的情况，开销较低。慢速路径是在检查失败时调用的处理函数，通常用于记录日志或终止程序。  由于 `__cfi_slowpath` 被声明为 `weak`，这意味着它可能在某些构建配置中不存在。  测试文件通过显式调用 `__cfi_slowpath` 来测试在不同程序生命周期阶段（preinit, constructor, main）调用慢速路径的行为。

3. **验证程序初始化阶段的 CFI 行为:** 文件中使用了 `.preinit_array` 和构造函数 (`constructor`) 来在程序的不同初始化阶段调用 `__cfi_slowpath` 并检查 `g_count` 的值。这有助于验证 CFI 机制在程序启动的不同阶段是否按预期工作。

**与 Android 功能的关系及举例说明：**

CFI 是 Android 系统的一项重要的安全特性，旨在防止基于控制流劫持的攻击，例如：

* **ROP (Return-Oriented Programming) 攻击:**  攻击者通过篡改调用栈，将一系列已存在的代码片段（gadgets）串联起来执行恶意操作。CFI 可以通过验证函数调用的目标地址来阻止这种攻击。
* **虚函数表 (vtable) 劫持:**  C++ 中使用虚函数实现多态。攻击者可能修改对象的虚函数表，将虚函数指针指向恶意代码。CFI 可以通过验证虚函数调用的目标地址来防止这种攻击。

**举例说明:** 假设一个 Android 应用中使用了存在漏洞的 C++ 库。攻击者通过某种方式获得了控制权，并尝试将一个函数指针修改为指向恶意代码。如果启用了 CFI，并且编译器在调用该函数指针前插入了 CFI 检查（即调用 `__cfi_check` 或类似的机制），那么：

1. **正常情况（假设攻击者的恶意地址类型不匹配）:** `__cfi_check` 会检测到类型不匹配，并跳转到 `__cfi_slowpath`（如果存在）。系统可能会记录错误信息并终止程序，从而阻止攻击。

2. **测试文件模拟:** 在 `cfi_test_helper.cpp` 中，`__cfi_check` 只是递增 `g_count`。而对 `__cfi_slowpath` 的调用，即使它实际不存在（因为是 `weak`），也不会导致程序崩溃，因为这是测试环境。

**详细解释每一个 libc 函数的功能是如何实现的：**

这个测试文件本身并没有直接调用或实现复杂的 libc 函数。它主要使用了：

* **`<stdint.h>`:**  定义了标准整数类型，如 `uint64_t`。
* **`<stdlib.h>`:**  可能间接使用，例如 `reinterpret_cast` 涉及到类型转换。
* **`CHECK.h`:** 这是一个 Bionic 内部的宏，用于断言。如果条件为假，程序会终止并输出错误信息。

**关于 `__cfi_check` 的实现（模拟）：**

```c++
extern "C" __attribute__((no_sanitize("hwaddress")))  __attribute__((aligned(4096)))
void __cfi_check(uint64_t /*CallSiteTypeId*/, void* /*TargetAddr*/, void* /*Diag*/) {
  ++g_count;
}
```

* `extern "C"`:  指定使用 C 链接，因为 CFI 机制需要在汇编层面进行交互。
* `__attribute__((no_sanitize("hwaddress")))`:  告知编译器或静态分析工具，这个函数不需要进行硬件地址消毒 (Hardware Address Sanitizer, HWASan) 的检查。这通常用于一些底层的、需要直接操作内存的函数。
* `__attribute__((aligned(4096)))`:  指定函数的地址需要按照 4096 字节对齐。这可能是出于性能或特定的底层硬件要求。
* 函数参数：
    * `CallSiteTypeId`:  调用点的类型 ID，用于区分不同的调用位置。
    * `TargetAddr`:  目标函数的地址。
    * `Diag`:  可能用于传递诊断信息。
* 函数体： 简单地递增全局计数器 `g_count`。

**关于 `__cfi_slowpath` 的功能（通常的实现）：**

由于 `__cfi_slowpath` 在这个测试文件中是弱符号，我们无法看到其具体实现。在实际的 CFI 实现中，当 `__cfi_check` 检测到类型不匹配时，会跳转到 `__cfi_slowpath`。它的功能通常包括：

1. **记录错误日志:**  记录 CFI 违规的详细信息，例如发生违规的地址、目标地址、调用栈等。
2. **终止程序:**  为了安全性，通常会选择立即终止程序，防止恶意代码继续执行。
3. **生成 crash dump (可能):** 在某些情况下，可能会生成崩溃转储文件，用于后续分析。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个测试文件本身会被编译成一个可执行文件，而不是一个共享库 (`.so`)。但是，它使用了与动态链接器相关的特性，即 `.preinit_array` 和构造函数。

**SO 布局样本 (假设将类似的逻辑放在一个共享库中):**

```
ELF Header
...
Program Headers:
  LOAD           偏移量: 0x000000, 虚拟地址: 0xXXXXXXXX, 大小: ... (包含 .text, .rodata, .data, .bss)
  LOAD           偏移量: 0xYYYYYY, 虚拟地址: 0xYYYYYYYY, 大小: ... (包含 .dynamic, .got, .plt)
  ...
Section Headers:
  .text          类型: PROGBITS, 虚拟地址: 0xAAAAAAAA, 大小: ... (代码段)
  .rodata        类型: PROGBITS, 虚拟地址: 0xBBBBBBBB, 大小: ... (只读数据段)
  .data          类型: PROGBITS, 虚拟地址: 0xCCCCCCCC, 大小: ... (可读写数据段)
  .bss           类型: NOBITS,   虚拟地址: 0xDDDDDDDD, 大小: ... (未初始化数据段)
  .dynamic       类型: DYNAMIC,  虚拟地址: 0xEEEEEEEE, 大小: ... (动态链接信息)
  .got           类型: PROGBITS, 虚拟地址: 0xFFFFFFFF, 大小: ... (全局偏移量表)
  .plt           类型: PROGBITS, 虚拟地址: 0x11111111, 大小: ... (程序链接表)
  .preinit_array 类型: INIT_ARRAY, 虚拟地址: 0x22222222, 大小: ... (预初始化函数指针数组)
  .init_array    类型: INIT_ARRAY, 虚拟地址: 0x33333333, 大小: ... (初始化函数指针数组，对应构造函数)
  ...
```

**链接的处理过程：**

1. **加载:** 当 Android 系统启动或应用程序加载一个共享库时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会将共享库加载到内存中。

2. **解析 ELF 头和段头:** 链接器会解析 ELF 头和段头，了解共享库的结构，包括各个段的地址和大小。

3. **处理 `.preinit_array`:** 链接器会找到 `.preinit_array` 段，这个段包含了一组函数指针。在执行任何其他初始化代码之前，链接器会按照顺序调用这些函数。在 `cfi_test_helper.cpp` 中，`preinit_ctor_p` 指向 `preinit_ctor` 函数，这个函数会在非常早期的阶段被调用。

4. **处理 `.init_array`:** 链接器会找到 `.init_array` 段，这个段包含了构造函数（标记为 `__attribute__((constructor))` 的函数）的指针。链接器会在加载完所有必要的共享库，但在执行 `main` 函数之前，按照顺序调用这些构造函数。在 `cfi_test_helper.cpp` 中，`ctor` 函数会被作为构造函数调用。

5. **符号解析和重定位:** 链接器会解析共享库中引用的外部符号，并在全局偏移量表 (GOT) 和程序链接表 (PLT) 中填充正确的地址。这使得共享库能够调用其他库中的函数。

6. **执行 `main` 函数 (对于可执行文件):** 对于可执行文件，链接器在完成上述步骤后，最终会调用 `main` 函数。

**逻辑推理，假设输入与输出：**

**假设输入:**  运行编译后的 `cfi_test_helper` 可执行文件。

**输出预测:**

1. **`preinit_ctor` 执行:**  在程序启动的极早期，`preinit_ctor` 会被动态链接器调用。
   * `CHECK(g_count == 0)`:  初始时 `g_count` 为 0，断言通过。
   * `__cfi_slowpath(42, reinterpret_cast<void*>(&preinit_ctor))`: 调用 `__cfi_slowpath`，传递一些参数（在这里参数的具体值并不重要，只是为了触发调用）。
   * `CHECK(g_count == 1)`:  由于 `__cfi_slowpath` 前 `__cfi_check` 被调用（虽然看不到直接调用，但假设编译时启用了 CFI，或者为了测试目的，`__cfi_slowpath` 内部会触发 `__cfi_check`），`g_count` 会递增为 1，断言通过。

2. **`ctor` 执行:**  在 `preinit_ctor` 之后，但在 `main` 函数之前，构造函数 `ctor` 会被调用。
   * `CHECK(g_count == 1)`:  此时 `g_count` 应该为 1，断言通过。
   * `__cfi_slowpath(42, reinterpret_cast<void*>(&ctor))`: 调用 `__cfi_slowpath`。
   * `CHECK(g_count == 2)`: `g_count` 递增为 2，断言通过。

3. **`main` 函数执行:**
   * `CHECK(g_count == 2)`: 此时 `g_count` 应该为 2，断言通过。
   * `__cfi_slowpath(42, reinterpret_cast<void*>(&main))`: 调用 `__cfi_slowpath`。
   * `CHECK(g_count == 3)`: `g_count` 递增为 3，断言通过。
   * `return 0;`: 程序正常退出。

因此，如果没有编译错误或运行时问题，该程序的预期输出是成功执行并且不产生任何错误信息（因为所有的 `CHECK` 断言都应该通过）。

**涉及用户或者编程常见的使用错误，请举例说明：**

1. **CFI 配置错误:** 如果开发者错误地配置了 CFI 编译选项，可能导致 CFI 检查无法正常工作，从而降低安全性。例如，没有为关键的库或模块启用 CFI。

2. **链接错误:**  如果在链接时，`cfi_test_helper` 依赖的符号（例如，真实的 `__cfi_slowpath` 实现，如果存在）没有正确链接，会导致程序无法运行或行为异常。

3. **误解 CFI 的工作原理:**  开发者可能认为 CFI 可以阻止所有类型的攻击，但实际上 CFI 主要针对控制流劫持，对于内存破坏等其他类型的漏洞可能无能为力。

4. **在不兼容的环境中使用:**  CFI 的具体实现可能依赖于特定的硬件或操作系统特性。如果在不兼容的环境中使用，可能会导致崩溃或行为异常。

5. **性能影响:**  CFI 检查会带来一定的性能开销。如果开发者不了解其影响，可能会在性能敏感的应用中过度使用 CFI，导致性能下降。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

`cfi_test_helper.cpp` 是 Bionic 库的内部测试代码，通常 **不会** 被 Android Framework 或 NDK 直接调用。它的目的是为了测试 Bionic 库自身的 CFI 实现。

**Android Framework 到达相关 CFI 代码的路径 (概念性):**

1. **应用程序启动:** 当一个 Android 应用程序启动时，Zygote 进程会 fork 出一个新的进程来运行该应用。
2. **`app_process`:** 新进程会执行 `app_process`，这是一个 Android 运行时环境的关键组件。
3. **动态链接器加载库:** `app_process` 会加载必要的共享库，包括 Bionic 库 (`libc.so`, `libm.so`, `libdl.so` 等)。
4. **CFI 检查:** 当应用程序执行代码并发生函数调用时，如果启用了 CFI，编译器会插入对 `__cfi_check` 或类似机制的调用。  这发生在 **编译后的机器码层面**。
5. **`__cfi_slowpath` (如果违规):** 如果 CFI 检查失败，程序会跳转到 `__cfi_slowpath` 进行处理。

**NDK 到达相关 CFI 代码的路径 (概念性):**

1. **NDK 应用启动:** 使用 NDK 开发的应用程序本质上也是一个 Android 应用，遵循类似的启动流程。
2. **加载 NDK 库:** NDK 应用会链接到 Bionic 库以及其他 NDK 提供的库。
3. **CFI 检查:** 当 NDK 应用执行代码并调用函数时，如果启用了 CFI，同样会进行 CFI 检查。

**frida hook 示例调试这些步骤 (针对 `cfi_test_helper`):**

由于 `cfi_test_helper` 是一个独立的测试程序，我们可以直接针对它进行 Frida Hook。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    if len(sys.argv) != 2:
        print("Usage: python {} <target_process>".format(sys.argv[0]))
        sys.exit(1)

    target_process = sys.argv[1]

    try:
        session = frida.attach(target_process)
    except frida.ProcessNotFoundError:
        print(f"进程 '{target_process}' 未找到，请确保程序正在运行。")
        sys.exit(1)

    script_code = """
    console.log("Script loaded");

    // Hook __cfi_check
    var cfi_check_ptr = Module.findExportByName(null, "__cfi_check");
    if (cfi_check_ptr) {
        Interceptor.attach(cfi_check_ptr, {
            onEnter: function(args) {
                console.log("[CFI Check] CallSiteTypeId:", args[0], "TargetAddr:", args[1], "Diag:", args[2]);
            },
            onLeave: function(retval) {
                // console.log("[CFI Check] Returned:", retval);
            }
        });
        console.log("Hooked __cfi_check at", cfi_check_ptr);
    } else {
        console.log("__cfi_check not found.");
    }

    // Hook __cfi_slowpath
    var cfi_slowpath_ptr = Module.findExportByName(null, "__cfi_slowpath");
    if (cfi_slowpath_ptr) {
        Interceptor.attach(cfi_slowpath_ptr, {
            onEnter: function(args) {
                console.log("[CFI Slowpath] Arg1:", args[0], "Arg2:", args[1]);
            }
        });
        console.log("Hooked __cfi_slowpath at", cfi_slowpath_ptr);
    } else {
        console.log("__cfi_slowpath not found (likely weak symbol).");
    }

    // Hook preinit_ctor
    var preinit_ctor_ptr = Module.findExportByName(null, "preinit_ctor");
    if (preinit_ctor_ptr) {
        Interceptor.attach(preinit_ctor_ptr, {
            onEnter: function(args) {
                console.log("[preinit_ctor] Called");
            }
        });
        console.log("Hooked preinit_ctor at", preinit_ctor_ptr);
    }

    // Hook ctor
    var ctor_ptr = Module.findExportByName(null, "ctor");
    if (ctor_ptr) {
        Interceptor.attach(ctor_ptr, {
            onEnter: function(args) {
                console.log("[ctor] Called");
            }
        });
        console.log("Hooked ctor at", ctor_ptr);
    }

    // Hook main
    var main_ptr = Module.findExportByName(null, "main");
    if (main_ptr) {
        Interceptor.attach(main_ptr, {
            onEnter: function(args) {
                console.log("[main] Called");
            }
        });
        console.log("Hooked main at", main_ptr);
    }
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    try:
        input("Press Enter to detach from process...")
    except KeyboardInterrupt:
        pass
    finally:
        session.detach()

if __name__ == "__main__":
    main()
```

**使用方法:**

1. 将 `cfi_test_helper.cpp` 编译成可执行文件 (例如 `cfi_test_helper`)。
2. 运行该可执行文件： `./cfi_test_helper`
3. 运行 Frida 脚本，并将进程名称作为参数： `python your_frida_script.py cfi_test_helper`

**预期 Frida 输出:**

你会看到类似以下的输出，表明 Frida 成功 hook 到了相应的函数：

```
[*] Script loaded
[*] Hooked __cfi_check at [address]
[*] Hooked preinit_ctor at [address]
[*] Hooked ctor at [address]
[*] Hooked main at [address]
[*] [preinit_ctor] Called
[*] [CFI Slowpath] Arg1: 42 Arg2: [address of preinit_ctor]
[*] [ctor] Called
[*] [CFI Slowpath] Arg1: 42 Arg2: [address of ctor]
[*] [main] Called
[*] [CFI Slowpath] Arg1: 42 Arg2: [address of main]
```

**注意:**  由于 `__cfi_slowpath` 是弱符号，如果在编译时没有实际的实现，Frida 可能找不到该符号。

通过这个 Frida 示例，你可以观察 `cfi_test_helper` 程序中关键函数的执行顺序和 `__cfi_slowpath` 的调用情况，从而更好地理解 CFI 测试的流程。记住，这主要是针对 Bionic 内部测试的调试，对于理解 Android Framework 或 NDK 中实际的 CFI 工作机制，需要 hook 运行在 Android 系统上的应用程序或服务。

Prompt: 
```
这是目录为bionic/tests/libs/cfi_test_helper.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <stdint.h>
#include <stdlib.h>

#include "CHECK.h"

// This library is built for all targets, including host tests, so __cfi_slowpath may not be
// present. But it is only used in the bionic loader tests.
extern "C" __attribute__((weak)) void __cfi_slowpath(uint64_t, void*);

static int g_count;

// Mock a CFI-enabled library without relying on the compiler.
extern "C" __attribute__((no_sanitize("hwaddress")))  __attribute__((aligned(4096)))
void __cfi_check(uint64_t /*CallSiteTypeId*/, void* /*TargetAddr*/, void* /*Diag*/) {
  ++g_count;
}

// This code runs before hwasan is initialized.
__attribute__((no_sanitize("hwaddress")))
void preinit_ctor() {
  CHECK(g_count == 0);
  __cfi_slowpath(42, reinterpret_cast<void*>(&preinit_ctor));
  CHECK(g_count == 1);
}

__attribute__((section(".preinit_array"), used)) void (*preinit_ctor_p)(void) = preinit_ctor;

__attribute__((constructor, used)) void ctor() {
  CHECK(g_count == 1);
  __cfi_slowpath(42, reinterpret_cast<void*>(&ctor));
  CHECK(g_count == 2);
}

int main(void) {
  CHECK(g_count == 2);
  __cfi_slowpath(42, reinterpret_cast<void*>(&main));
  CHECK(g_count == 3);
  return 0;
}

"""

```