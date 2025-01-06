Response:
Let's break down the thought process for analyzing the provided C++ code. The goal is to understand its functionality, its connection to Android, and how it's used. Here's a step-by-step approach:

1. **Initial Skim and Identification of Key Concepts:**

   - The file name `dynamic_function_dispatch.cpp` immediately suggests this code is about choosing the right implementation of a function at runtime.
   - The `bionic` directory indicates this is part of Android's core C library.
   - The copyright notice confirms it's from the Android Open Source Project.
   - The `#include <private/bionic_ifuncs.h>` is a crucial hint. `ifuncs` likely stands for "indirect functions" or "ifunc," a technique for dynamic function resolution.
   - The macros `DEFINE_IFUNC_FOR` and `RETURN_FUNC` appear repeatedly, indicating a pattern.
   - Function names like `memchr`, `memcpy`, `strlen`, etc., are standard C library functions.

2. **Understanding `DEFINE_IFUNC_FOR` and the IFunc Mechanism:**

   - The repetitive structure suggests a macro-based approach to defining indirect functions.
   - The `arg` parameter within `DEFINE_IFUNC_FOR` hints at some kind of argument passing. Looking at the usage, `arg->_hwcap` and `arg->_hwcap2` strongly suggest hardware capability detection.
   - The `RETURN_FUNC` macro likely resolves to a function pointer assignment and then returns the chosen implementation.
   - The `MEMCHR_SHIM()`, `MEMCPY_SHIM()` etc., likely define the actual ifunc resolver function that the dynamic linker interacts with. They might be empty or contain minimal setup.

3. **Analyzing the Logic within Each `DEFINE_IFUNC_FOR` Block:**

   - **Conditional Logic:**  The `if` statements check for specific hardware capabilities (`HWCAP_ASIMD`, `HWCAP2_MTE`, `HWCAP2_MOPS`) and the CPU type (`__bionic_is_oryon`).
   - **Hardware Feature Detection:** The code explicitly checks for features like ASIMD (Advanced SIMD), MTE (Memory Tagging Extension), and MOPS (Memory Ordering Primitive Set). These are ARM architecture extensions.
   - **CPU-Specific Optimization:** The `__bionic_is_oryon` function checks for a specific Qualcomm CPU, indicating platform-specific optimizations. The assembly instruction `mrs %0, MIDR_EL1` confirms it's reading a CPU identification register.
   - **Choosing Implementations:** Based on the detected features, different underlying implementations are selected (e.g., `__memchr_aarch64_mte`, `__memcpy_aarch64_simd`).

4. **Connecting to Android Functionality:**

   - Bionic *is* the Android C library. This code directly *implements* parts of it.
   - **Performance Optimization:** The primary goal seems to be to select the most efficient implementation of standard C library functions based on the device's hardware capabilities. This is crucial for Android's performance across a wide range of devices.
   - **Security Features:** The checks for `HWCAP2_MTE` suggest the integration of memory tagging for improved security.

5. **Dynamic Linker Interaction (IFuncs):**

   - **SO Layout:**  The shared object (SO) containing this code (`libc.so`) will have entries in its dynamic symbol table for the ifunc resolvers (the `MEMCHR_SHIM`, `MEMCPY_SHIM`, etc.).
   - **Linking Process:**
      1. When a program calls `memchr`, it initially goes to the ifunc resolver.
      2. The dynamic linker identifies the ifunc resolver function associated with `memchr` in `libc.so`.
      3. The dynamic linker calls the ifunc resolver (the code within `DEFINE_IFUNC_FOR(memchr)`).
      4. The resolver examines the hardware capabilities.
      5. The resolver returns the *actual* address of the optimized `memchr` implementation.
      6. The dynamic linker overwrites the initial entry in the Procedure Linkage Table (PLT) with the resolved address.
      7. Subsequent calls to `memchr` go directly to the optimized implementation.

6. **Common Usage Errors:**

   - While this code itself isn't directly called by users, misunderstanding the implications of hardware capabilities can lead to issues. For example, if NDK code assumes a specific CPU feature is always present and it's not, the application might crash or behave incorrectly on some devices.

7. **Tracing the Call Path (Android Framework/NDK to this Code):**

   - An app or the Android framework calls a standard C library function (e.g., `memchr`).
   - This call goes through the PLT.
   - Initially, the PLT entry points to the ifunc resolver in `libc.so`.
   - The dynamic linker resolves the ifunc as described above.
   - Subsequent calls go directly to the chosen implementation.

8. **Frida Hooking:**

   - Frida can be used to intercept calls to the ifunc resolvers or the underlying implementations. Hooking the resolver allows you to see which implementation is chosen. Hooking the implementations lets you observe their behavior.

9. **Refinement and Structuring:**

   - Organize the information logically with clear headings and subheadings.
   - Provide concrete examples (even if hypothetical for input/output).
   - Use precise terminology (e.g., PLT, dynamic linker).
   - Review and refine the explanation for clarity and accuracy.

This detailed thought process, moving from high-level concepts to specific details and considering the broader context of Android and the dynamic linker, allows for a comprehensive understanding of the provided code. The key is to break down the problem into smaller, manageable parts and connect them logically.
这个文件 `bionic/libc/arch-arm64/dynamic_function_dispatch.cpp` 是 Android Bionic 库中用于 **动态函数分发 (Dynamic Function Dispatch)** 的源代码文件，专门针对 ARM64 架构。其核心功能是根据运行时的硬件能力 (hardware capabilities) 选择最优化的 C 库函数实现。

**功能列举:**

1. **运行时函数选择:**  根据当前设备的 CPU 特性和支持的指令集扩展 (如 ASIMD, MTE, MOPS)，动态地选择和绑定标准 C 库函数 (例如 `memchr`, `memcpy`, `strlen` 等) 的最佳实现。
2. **硬件优化:** 利用 CPU 的特定指令集来优化常用函数的性能。例如，如果 CPU 支持 ASIMD (Advanced SIMD)，则选择使用 ASIMD 指令优化的 `memcpy` 实现。
3. **平台特定优化:**  针对特定的 CPU 架构和型号进行优化。例如，代码中检测了 Qualcomm 的 Oryon CPU，并为其选择特定的非临时 (non-temporal) 内存操作实现。
4. **支持新硬件特性:**  为新的硬件特性 (如内存标记扩展 MTE) 提供支持。如果设备支持 MTE，则选择使用 MTE 优化的版本，以提高内存安全性和调试能力。
5. **透明的优化:**  应用程序开发者无需关心底层的优化细节，Bionic 库会自动选择最佳的函数实现。

**与 Android 功能的关系及举例:**

该文件是 Android 系统库 Bionic 的一部分，直接影响着 Android 应用程序的性能和效率。

* **性能提升:**  例如，在支持 ASIMD 的设备上，调用 `memcpy` 时，会选择 `__memcpy_aarch64_simd` 这个使用 SIMD 指令优化的版本，这比通用的 `__memcpy_aarch64` 版本速度更快，尤其是在处理大量数据时。这直接提升了应用程序的运行速度和流畅度。
* **功耗降低:** 更快的执行速度通常也意味着更低的功耗。通过选择最优化的实现，可以减少 CPU 的工作量，从而降低设备的能耗。
* **支持新的硬件特性:**  Android 系统可以通过这种机制无缝地利用新的硬件特性。例如，当设备支持 MTE 时，libc 中的 `memchr`、`strchr` 等函数可以自动使用带有 MTE 支持的版本，帮助开发者更容易地发现内存安全问题。
* **平台适配:**  Android 需要在各种不同的 ARM64 设备上运行，这些设备可能拥有不同的 CPU 和指令集支持。这个文件使得 Bionic 库能够根据具体的硬件环境进行适配，提供最佳的性能。

**libc 函数的实现解释:**

该文件本身并不直接实现 `memchr`、`memcpy` 等函数的功能，而是负责在运行时选择合适的已实现的版本。

* **`DEFINE_IFUNC_FOR(function_name)` 宏:**  这个宏定义了一个用于动态函数分发的“ifunc” (indirect function)。当程序首次调用 `function_name` 时，动态链接器会调用这里定义的逻辑来确定实际要使用的函数地址。
* **`arg` 参数:**  这个参数是一个指向 `bionic_ifunc_arg` 结构体的指针，该结构体包含了硬件能力信息，例如 `_hwcap` (hardware capabilities) 和 `_hwcap2` (extended hardware capabilities)。这些信息是从内核获取的，反映了当前 CPU 支持的特性。
* **硬件能力检查 (`arg->_hwcap & HWCAP_ASIMD`, `arg->_hwcap2 & HWCAP2_MTE` 等):** 代码通过位运算检查 `_hwcap` 和 `_hwcap2` 中的特定位，来判断 CPU 是否支持相应的指令集扩展或特性。
* **CPU 类型检查 (`__bionic_is_oryon(arg->_hwcap)`):**  `__bionic_is_oryon` 函数读取 CPU 的 MIDR_EL1 寄存器，从中提取制造商和变体信息，以判断是否为 Qualcomm 的 Oryon CPU。这是针对特定 CPU 架构的优化。
* **`RETURN_FUNC(function_type, function_implementation)` 宏:**  这个宏用于返回选定的函数实现的地址。`function_type` 是函数指针类型，`function_implementation` 是具体实现的函数名。

**以 `memcpy` 为例：**

当应用程序调用 `memcpy` 时，动态链接器会执行 `DEFINE_IFUNC_FOR(memcpy)` 中定义的逻辑：

1. **检查 `HWCAP2_MOPS`:** 如果 `arg->_hwcap2` 中设置了 `HWCAP2_MOPS` 位，表示 CPU 支持 Memory Ordering Primitive Set，则选择 `__memmove_aarch64_mops` 作为 `memcpy` 的实现。注意这里用的是 `__memmove`，可能是因为 MOPS 优化对可能重叠的内存区域更有效。
2. **检查 Oryon CPU:** 如果不是 MOPS，则检查是否为 Qualcomm Oryon CPU。如果是，则选择 `__memcpy_aarch64_nt` (non-temporal)，这种实现可能在某些情况下对性能更好，因为它提示缓存系统数据不会很快被再次访问。
3. **检查 `HWCAP_ASIMD`:** 如果不是 Oryon，则检查 `arg->_hwcap` 中是否设置了 `HWCAP_ASIMD` 位，表示 CPU 支持 ASIMD 指令集。如果是，则选择 `__memcpy_aarch64_simd`，这是一个使用 SIMD 指令优化的版本。
4. **默认实现:** 如果以上条件都不满足，则选择通用的 `__memcpy_aarch64` 实现。

**动态链接器功能及 SO 布局样本和链接过程:**

该文件依赖于动态链接器的 **IFunc 机制**。

**SO 布局样本 (`libc.so` 的简化示意):**

```
.dynsym (动态符号表):
    memcpy@IFUNC         ; 指向 memcpy 的 IFunc 解析器
    __memcpy_aarch64
    __memcpy_aarch64_simd
    __memcpy_aarch64_nt
    __memmove_aarch64_mops
    ...

.rela.dyn (动态重定位表):
    重定位 memcpy@IFUNC 以指向实际的函数实现 (在运行时由链接器填充)

.plt (过程链接表):
    memcpy:
        b   memcpy@IFUNC      ; 首次调用时跳转到 IFunc 解析器
        ...                  ; 后续调用直接跳转到解析后的地址
```

**链接的处理过程:**

1. **编译链接:** 当应用程序链接到 `libc.so` 时，对于声明为 IFunc 的符号 (例如 `memcpy`)，链接器会创建一个特殊的 PLT 条目，初始时指向对应的 IFunc 解析器 (`memcpy@IFUNC` 在动态符号表中的地址)。
2. **首次调用:** 当应用程序首次调用 `memcpy` 时，程序会跳转到 `libc.so` 的 PLT 中的 `memcpy` 条目。
3. **IFunc 解析:** PLT 条目会跳转到 `memcpy@IFUNC` 指向的地址，即 `bionic/libc/arch-arm64/dynamic_function_dispatch.cpp` 中 `DEFINE_IFUNC_FOR(memcpy)` 定义的代码。
4. **硬件能力检测:**  这段代码会读取硬件能力信息，并根据条件选择合适的 `memcpy` 实现 (例如 `__memcpy_aarch64_simd`)。
5. **地址解析和更新:**  `RETURN_FUNC` 宏会将选定的函数地址返回给动态链接器。动态链接器会更新 PLT 中的 `memcpy` 条目，使其直接指向 `__memcpy_aarch64_simd` 的地址。
6. **后续调用:**  后续对 `memcpy` 的调用将直接跳转到 `__memcpy_aarch64_simd` 的实现，不再需要执行 IFunc 解析过程。

**逻辑推理、假设输入与输出 (以 `memcpy` 为例):**

**假设输入:**

* 应用程序在 ARM64 设备上调用 `memcpy`。
* `arg->_hwcap` 的值为 `... | HWCAP_ASIMD | ...` (表示设备支持 ASIMD)。
* 该设备不是 Qualcomm Oryon CPU。
* `arg->_hwcap2` 的值没有设置 `HWCAP2_MOPS`。

**逻辑推理:**

`DEFINE_IFUNC_FOR(memcpy)` 中的逻辑会按顺序检查条件：

1. `arg->_hwcap2 & HWCAP2_MOPS` 为假。
2. `__bionic_is_oryon(arg->_hwcap)` 为假。
3. `arg->_hwcap & HWCAP_ASIMD` 为真。

**输出:**

`RETURN_FUNC(memcpy_func_t, __memcpy_aarch64_simd)` 将返回 `__memcpy_aarch64_simd` 函数的地址。动态链接器会将 PLT 中的 `memcpy` 条目更新为指向 `__memcpy_aarch64_simd`。

**用户或编程常见的使用错误:**

由于这是底层的库实现，普通用户或应用程序开发者通常不会直接与此文件交互。常见的错误更多发生在理解和利用硬件加速的层面：

1. **错误地假设硬件能力:**  NDK 开发者可能会错误地假设所有 ARM64 设备都支持特定的硬件特性 (例如 ASIMD 或 MTE)。如果在不支持这些特性的设备上运行，程序可能会崩溃或出现未定义行为，如果他们直接调用了特定优化的函数而不是通过标准 C 库函数。
2. **手动选择错误的实现:**  虽然不常见，但如果开发者试图绕过标准 C 库，并根据硬件能力手动选择不同的函数实现，可能会因为判断错误而选择了次优或不兼容的实现。
3. **忽略性能差异:**  开发者可能没有意识到在不同硬件上标准 C 库函数的性能差异很大，从而没有针对特定平台进行优化。

**Android Framework 或 NDK 如何到达这里:**

1. **应用程序调用标准 C 库函数:**  无论是通过 Java (Android Framework) 的 JNI 调用，还是通过 C/C++ (NDK) 代码直接调用，最终都会调用到 Bionic 库提供的标准 C 库函数。
   * **Java/Kotlin (Android Framework):**  当 Android Framework 需要执行一些底层操作，例如内存操作、字符串处理等，它会通过 JNI 调用到 Native 代码 (通常是 C/C++)。这些 Native 代码最终可能会调用到 `memcpy`, `strlen` 等标准 C 库函数。
   * **NDK 应用:** NDK 开发的应用程序可以直接调用标准 C 库函数。

2. **动态链接器介入:** 当程序首次调用一个外部共享库中的函数时，动态链接器 (linker) 会介入。对于 IFunc 函数，链接器会识别出这是一个需要动态解析的符号。

3. **执行 IFunc 解析器:**  动态链接器会调用 `libc.so` 中为该函数注册的 IFunc 解析器 (例如 `DEFINE_IFUNC_FOR(memcpy)` 中定义的代码)。

4. **硬件能力检测和函数选择:** IFunc 解析器会读取硬件能力信息并选择最佳的函数实现。

5. **更新 PLT:** 动态链接器更新 PLT 表，将后续的函数调用重定向到选定的优化实现。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook 来观察动态函数分发的执行过程和选择的函数实现。

```python
import frida
import sys

package_name = "your.app.package"  # 替换为你的应用包名
function_to_hook = "memcpy"       # 要 hook 的 C 库函数

session = frida.attach(package_name)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "%s@IFUNC"), {
    onEnter: function (args) {
        console.log("[+] Calling %s IFunc resolver");
        // 可以检查 args[0] 获取 bionic_ifunc_arg 结构体的信息
        // 例如，读取 hwcap 和 hwcap2
        const arg = ptr(args[0]);
        const hwcap = arg.readU64();
        const hwcap2 = arg.add(8).readU64();
        console.log("    hwcap: 0x" + hwcap.toString(16));
        console.log("    hwcap2: 0x" + hwcap2.toString(16));
    },
    onLeave: function (retval) {
        console.log("[+] %s IFunc resolver returned: " + retval);
        // 可以解析返回值，查看选择的函数地址
        const resolvedFunctionAddress = retval;
        const resolvedFunctionName = DebugSymbol.fromAddress(resolvedFunctionAddress);
        console.log("    Resolved function: " + resolvedFunctionName);
    }
});
""" % (function_to_hook, function_to_hook, function_to_hook)

script = session.create_script(script_code)
script.load()
sys.stdin.read()
```

**Frida Hook 调试步骤：**

1. **安装 Frida 和 frida-tools:** 确保你的电脑上安装了 Frida 和 Frida 的 Python 工具。
2. **启动目标应用:** 在 Android 设备或模拟器上启动你要调试的应用程序。
3. **运行 Frida 脚本:** 运行上述 Python Frida 脚本，将 `your.app.package` 替换为你的应用包名。
4. **触发函数调用:** 在应用程序中执行会调用目标 C 库函数 (例如 `memcpy`) 的操作。
5. **查看 Frida 输出:** Frida 会打印出当调用 `memcpy` 的 IFunc 解析器时以及返回时的信息，包括硬件能力值和最终选择的函数地址及其符号名。

通过 Frida Hook，你可以清晰地看到在特定设备上，对于某个 C 库函数，Bionic 库是如何根据硬件能力选择最优化的实现的。这对于理解 Android 系统的底层优化机制非常有帮助。

Prompt: 
```
这是目录为bionic/libc/arch-arm64/dynamic_function_dispatch.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#include <private/bionic_ifuncs.h>
#include <stddef.h>

static inline bool __bionic_is_oryon(unsigned long hwcap) {
  if (!(hwcap & HWCAP_CPUID)) return false;

  // Extract the implementor and variant bits from MIDR_EL1.
  // https://www.kernel.org/doc/html/latest/arch/arm64/cpu-feature-registers.html#list-of-registers-with-visible-features
  unsigned long midr;
  __asm__ __volatile__("mrs %0, MIDR_EL1" : "=r"(midr));
  uint16_t cpu = (midr >> 20) & 0xfff;

  auto make_cpu = [](unsigned implementor, unsigned variant) {
    return (implementor << 4) | variant;
  };

  // Check for implementor Qualcomm's variants 0x1..0x5 (Oryon).
  return cpu >= make_cpu('Q', 0x1) && cpu <= make_cpu('Q', 0x5);
}

extern "C" {

DEFINE_IFUNC_FOR(memchr) {
  if (arg->_hwcap2 & HWCAP2_MTE) {
    RETURN_FUNC(memchr_func_t, __memchr_aarch64_mte);
  } else {
    RETURN_FUNC(memchr_func_t, __memchr_aarch64);
  }
}
MEMCHR_SHIM()

DEFINE_IFUNC_FOR(memcmp) {
  // TODO: enable the SVE version.
  RETURN_FUNC(memcmp_func_t, __memcmp_aarch64);
}
MEMCMP_SHIM()

DEFINE_IFUNC_FOR(memcpy) {
  if (arg->_hwcap2 & HWCAP2_MOPS) {
    RETURN_FUNC(memcpy_func_t, __memmove_aarch64_mops);
  } else if (__bionic_is_oryon(arg->_hwcap)) {
    RETURN_FUNC(memcpy_func_t, __memcpy_aarch64_nt);
  } else if (arg->_hwcap & HWCAP_ASIMD) {
    RETURN_FUNC(memcpy_func_t, __memcpy_aarch64_simd);
  } else {
    RETURN_FUNC(memcpy_func_t, __memcpy_aarch64);
  }
}
MEMCPY_SHIM()

DEFINE_IFUNC_FOR(memmove) {
  if (arg->_hwcap2 & HWCAP2_MOPS) {
    RETURN_FUNC(memmove_func_t, __memmove_aarch64_mops);
  } else if (__bionic_is_oryon(arg->_hwcap)) {
    RETURN_FUNC(memmove_func_t, __memmove_aarch64_nt);
  } else if (arg->_hwcap & HWCAP_ASIMD) {
    RETURN_FUNC(memmove_func_t, __memmove_aarch64_simd);
  } else {
    RETURN_FUNC(memmove_func_t, __memmove_aarch64);
  }
}
MEMMOVE_SHIM()

DEFINE_IFUNC_FOR(memrchr) {
  RETURN_FUNC(memrchr_func_t, __memrchr_aarch64);
}
MEMRCHR_SHIM()

DEFINE_IFUNC_FOR(memset) {
  if (arg->_hwcap2 & HWCAP2_MOPS) {
    RETURN_FUNC(memset_func_t, __memset_aarch64_mops);
  } else if (__bionic_is_oryon(arg->_hwcap)) {
    RETURN_FUNC(memset_func_t, __memset_aarch64_nt);
  } else {
    RETURN_FUNC(memset_func_t, __memset_aarch64);
  }
}
MEMSET_SHIM()

DEFINE_IFUNC_FOR(stpcpy) {
  // TODO: enable the SVE version.
  RETURN_FUNC(stpcpy_func_t, __stpcpy_aarch64);
}
STPCPY_SHIM()

DEFINE_IFUNC_FOR(strchr) {
  if (arg->_hwcap2 & HWCAP2_MTE) {
    RETURN_FUNC(strchr_func_t, __strchr_aarch64_mte);
  } else {
    RETURN_FUNC(strchr_func_t, __strchr_aarch64);
  }
}
STRCHR_SHIM()

DEFINE_IFUNC_FOR(strchrnul) {
  if (arg->_hwcap2 & HWCAP2_MTE) {
    RETURN_FUNC(strchrnul_func_t, __strchrnul_aarch64_mte);
  } else {
    RETURN_FUNC(strchrnul_func_t, __strchrnul_aarch64);
  }
}
STRCHRNUL_SHIM()

DEFINE_IFUNC_FOR(strcmp) {
  // TODO: enable the SVE version.
  RETURN_FUNC(strcmp_func_t, __strcmp_aarch64);
}
STRCMP_SHIM()

DEFINE_IFUNC_FOR(strcpy) {
  // TODO: enable the SVE version.
  RETURN_FUNC(strcpy_func_t, __strcpy_aarch64);
}
STRCPY_SHIM()

DEFINE_IFUNC_FOR(strlen) {
  if (arg->_hwcap2 & HWCAP2_MTE) {
    RETURN_FUNC(strlen_func_t, __strlen_aarch64_mte);
  } else {
    RETURN_FUNC(strlen_func_t, __strlen_aarch64);
  }
}
STRLEN_SHIM()

DEFINE_IFUNC_FOR(strncmp) {
  // TODO: enable the SVE version.
  RETURN_FUNC(strncmp_func_t, __strncmp_aarch64);
}
STRNCMP_SHIM()

DEFINE_IFUNC_FOR(strnlen) {
  // TODO: enable the SVE version.
  RETURN_FUNC(strnlen_func_t, __strnlen_aarch64);
}
STRNLEN_SHIM()

DEFINE_IFUNC_FOR(strrchr) {
  if (arg->_hwcap2 & HWCAP2_MTE) {
    RETURN_FUNC(strrchr_func_t, __strrchr_aarch64_mte);
  } else {
    RETURN_FUNC(strrchr_func_t, __strrchr_aarch64);
  }
}
STRRCHR_SHIM()

}  // extern "C"

"""

```