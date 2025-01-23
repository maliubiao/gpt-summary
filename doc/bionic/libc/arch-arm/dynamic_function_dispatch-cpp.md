Response:
Let's break down the thought process for analyzing the `dynamic_function_dispatch.cpp` file.

**1. Understanding the Core Purpose:**

The file name and the initial description immediately suggest its primary function: dynamic dispatch of functions based on the underlying CPU architecture. The `bionic` context confirms it's about optimizing core library functions for specific hardware.

**2. Identifying Key Mechanisms:**

* **`CpuVariant` enum:** This is the central data structure. It defines the recognized CPU architectures. The associated `cpu_variant_names` array maps human-readable names to these variants.
* **`init_cpu_variant()`:** This function is clearly responsible for detecting the current CPU. It involves reading a file (`/dev/cpu_variant:arm`).
* **`get_cpu_variant()`:** This function implements a singleton pattern (static initialization) to ensure the CPU detection only happens once.
* **`DEFINE_IFUNC_FOR` macro:** This is the core mechanism for dynamic dispatch. It takes a function name as input.
* **`RETURN_FUNC` macro:** Used within `DEFINE_IFUNC_FOR` to select the appropriate implementation based on the CPU variant.
* **`_SHIM()` macros:** These likely create wrapper functions that trigger the dynamic dispatch.

**3. Analyzing the Code in Detail:**

* **CPU Detection (`init_cpu_variant()`):**
    * **File Reading:** The code attempts to open and read `/dev/cpu_variant:arm`. This immediately tells us Android provides a way to query the CPU variant at runtime.
    * **Error Handling:**  It checks for file open errors (`fd < 0`). If the file doesn't exist or can't be opened, it defaults to `kGeneric`.
    * **String Comparison:** It reads the CPU name from the file and compares it against the entries in `cpu_variant_names`. The `is_same_name` function does a byte-by-byte comparison.
    * **Handling Incomplete Reads:** The `while` loop and the `bytes_read != 0` check suggest it handles cases where the file might be larger than expected.
* **Dynamic Dispatch (`DEFINE_IFUNC_FOR` and `RETURN_FUNC`):**
    * The `switch` statement within the `DEFINE_IFUNC_FOR` blocks is crucial. It uses the result of `get_cpu_variant()` to select a specific function implementation (e.g., `memmove_a7`, `memmove_a9`).
    * The `RETURN_FUNC` macro likely handles the type casting and return of the appropriate function pointer.
* **System Calls (Assembly):**
    * The `ifunc_open`, `ifunc_read`, and `ifunc_close` functions use inline assembly to perform system calls directly. The register assignments (`r0`, `r1`, `r7`) are typical for ARM ABI. This shows a low-level interaction with the kernel.

**4. Connecting to Android Functionality:**

* **Performance Optimization:** The primary goal is clear: to provide optimized implementations of standard C library functions for different ARM processor architectures. This is vital for Android's performance and battery life.
* **Hardware Abstraction:** This mechanism allows the higher layers of Android (framework, NDK) to use standard C functions without needing to know the specific CPU architecture. Bionic handles the low-level details.

**5. Addressing Specific Requirements of the Prompt:**

* **Functionality Listing:**  Summarize the purpose of CPU detection and dynamic dispatch.
* **Android Relation and Examples:** Explain how this benefits Android (performance) and give examples of dispatched functions (e.g., `memmove`, `memcpy`).
* **Libc Function Implementation:**  Explain the CPU detection process. Mention the assembly code for system calls.
* **Dynamic Linker:** Explain that the dynamic linker is responsible for resolving these function pointers at runtime. Provide a simplified SO layout example and explain the relocation process.
* **Logical Inference (Hypothetical Input/Output):**  Create an example of how `get_cpu_variant()` would work based on the contents of `/dev/cpu_variant:arm`.
* **Common Usage Errors:**  Discuss potential issues if developers try to bypass or directly use the architecture-specific functions (generally discouraged).
* **Android Framework/NDK Path:** Explain the high-level flow: NDK uses standard C functions, which are resolved by the dynamic linker, which calls into the ifunc resolvers in bionic.
* **Frida Hook Example:** Provide a basic Frida script to intercept one of the dynamically dispatched functions.

**6. Structuring the Response:**

Organize the information logically, using headings and bullet points to make it easier to read. Start with a high-level overview and then delve into specifics.

**7. Iterative Refinement:**

After drafting the initial response, review it for clarity, accuracy, and completeness. Ensure all parts of the prompt have been addressed. For example, initially, the dynamic linker explanation might be too brief and need more detail about relocation. The Frida hook might need a clearer explanation of *what* it's hooking and *why*.

This step-by-step thought process, combining code analysis with an understanding of the underlying concepts and the prompt's requirements, leads to a comprehensive and accurate answer.
好的，让我们来详细分析 `bionic/libc/arch-arm/dynamic_function_dispatch.cpp` 这个文件。

**功能列举：**

这个文件的核心功能是实现**基于 CPU 架构的动态函数分发 (Dynamic Function Dispatch)**，也称为 **Indirect Function Calls (IFUNCs)**。 具体来说，它做了以下几件事：

1. **CPU 变体检测:**  它定义了一个 `CpuVariant` 枚举，列出了它所识别的 ARM CPU 架构变体（例如 Cortex-A7, Cortex-A9, Cortex-A53 等）。
2. **CPU 变体名称映射:**  它维护一个 `cpu_variant_names` 数组，将 CPU 名称字符串（从 `/dev/cpu_variant:arm` 读取）映射到对应的 `CpuVariant` 枚举值。
3. **读取 CPU 变体信息:** `init_cpu_variant()` 函数负责读取 `/dev/cpu_variant:arm` 文件来获取当前设备的 CPU 型号名称。
4. **缓存 CPU 变体:** `get_cpu_variant()` 函数使用静态变量来缓存 CPU 变体信息，确保只检测一次。
5. **定义 IFUNC 解析器:**  使用 `DEFINE_IFUNC_FOR` 宏为特定的 libc 函数（例如 `memmove`, `memcpy`, `memset`, `strcpy` 等）定义了 IFUNC 解析器。这些解析器会根据 `get_cpu_variant()` 返回的 CPU 类型，选择并返回针对该 CPU 优化过的函数实现。
6. **定义 IFUNC Shim:** 使用 `_SHIM()` 宏定义了与 IFUNC 解析器关联的 shim 函数。这些 shim 函数是实际被外部代码调用的入口点，它们会调用对应的 IFUNC 解析器来获取最终的函数地址。

**与 Android 功能的关系及举例：**

这个文件与 Android 的性能优化密切相关。不同的 ARM CPU 架构具有不同的特性和指令集，针对特定架构进行优化的函数实现可以显著提高性能和效率。

**举例说明：**

* **性能优化:**  例如，`memmove` 函数在不同的 CPU 上可能有不同的最佳实现方式。在某些 Cortex-A 处理器上，特定的指令序列可能更快。通过 IFUNC 机制，Android 可以在运行时选择针对当前 CPU 优化的 `memmove` 实现，例如 `memmove_a15` (针对较新的架构) 或者其他针对特定架构的版本。
* **功耗优化:**  某些优化的实现可能在执行相同任务时消耗更少的能量。
* **兼容性:**  虽然主要目的是优化，但 IFUNC 也可以用于处理一些架构特定的兼容性问题，虽然在这个文件中不太明显。

**详细解释 libc 函数的实现：**

这个文件本身**不实现** libc 函数的具体逻辑，而是负责**选择**合适的实现。实际的 `memmove_a15`、`memcpy_a7` 等函数的实现通常在 bionic 库的其他架构相关的源文件中（例如 `bionic/libc/arch-arm/bionic/memmove.S`）。

**以 `memmove` 为例：**

1. 当应用程序调用 `memmove` 函数时，实际上调用的是 `MEMMOVE_SHIM()` 宏定义的 shim 函数。
2. 这个 shim 函数会调用 `memmove_resolver(hwcap)`。注意，在这个特定的 ARM 实现中，`hwcap` 参数并没有被直接使用，而是通过 `get_cpu_variant()` 来确定 CPU 类型。在其他架构上，`hwcap` (hardware capabilities) 可能用于更细粒度的特性检测。
3. `memmove_resolver` 函数（由 `DEFINE_IFUNC_FOR(memmove)` 生成）内部会调用 `get_cpu_variant()` 获取当前的 CPU 变体。
4. 根据 CPU 变体的值，`RETURN_FUNC(memmove_func_t, memmove_a15)` 宏会返回指向 `memmove_a15` 函数的指针。
5. shim 函数最终会跳转到 `memmove_a15` 的实际代码执行。

**涉及 dynamic linker 的功能、SO 布局样本和链接处理过程：**

IFUNC 功能的实现依赖于动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`)。动态链接器负责在程序加载时解析符号并进行重定位。

**SO 布局样本：**

假设有一个共享库 `libmylib.so` 使用了 `memmove` 函数。

```
libmylib.so:
  ...
  .got.plt:  // Global Offset Table for Procedure Linkage Table
    ...
    [memmove的GOT条目] -> 指向 memmove 的 IFUNC resolver
    ...
  .plt:      // Procedure Linkage Table
    ...
    [memmove的PLT条目]:
      push lr
      ldr  pc, [pc, #offset_to_GOT_entry]
    ...
  ...
```

**链接处理过程：**

1. **编译时:** 编译器遇到 `memmove` 调用时，会生成一个对 `memmove@plt` 的调用。
2. **链接时:** 静态链接器会将 `memmove` 标记为一个需要动态链接的符号。在 `libmylib.so` 的 `.got.plt` 中会为 `memmove` 创建一个条目，初始值指向 `memmove` 的 IFUNC resolver 函数（即 `memmove_resolver`）。
3. **加载时:** 当动态链接器加载 `libmylib.so` 时：
   * 动态链接器会处理 `.got.plt` 的重定位。对于 IFUNC 符号，它会将 `.got.plt` 条目初始化为指向 IFUNC resolver。
   * **首次调用 `memmove`:**
     * 程序执行到 `memmove@plt` 时，会跳转到 `.plt` 表中对应的条目。
     * `.plt` 表中的指令会将控制权转移到 `.got.plt` 中存储的地址，此时指向的是 `memmove_resolver`。
     * `memmove_resolver` 函数会被执行：
       * 它会调用 `get_cpu_variant()` 获取 CPU 类型。
       * 它会根据 CPU 类型选择合适的 `memmove` 实现（例如 `memmove_a15`）。
       * **关键步骤：** `memmove_resolver` 会将 `.got.plt` 中 `memmove` 的条目更新为指向最终选择的 `memmove_a15` 函数的地址。
     * `memmove_resolver` 会跳转到选择的 `memmove` 实现。
   * **后续调用 `memmove`:**
     * 程序再次执行到 `memmove@plt` 时，会跳转到 `.got.plt` 中存储的地址，此时已经更新为 `memmove_a15` 的地址。
     * 因此，后续的调用会直接跳转到优化后的 `memmove_a15` 实现，而不会再次执行 resolver。

**逻辑推理、假设输入与输出：**

**假设输入：**

* `/dev/cpu_variant:arm` 文件内容为字符串 `"cortex-a53"`。

**逻辑推理过程：**

1. `init_cpu_variant()` 函数会打开 `/dev/cpu_variant:arm`。
2. `init_cpu_variant()` 函数会读取文件内容 `"cortex-a53"`。
3. `init_cpu_variant()` 函数会遍历 `cpu_variant_names` 数组，找到匹配的条目 `{"cortex-a53", kCortexA53}`。
4. `init_cpu_variant()` 函数会返回 `kCortexA53`。
5. `get_cpu_variant()` 函数会将静态变量 `cpu_variant` 设置为 `kCortexA53`。
6. 当调用 `memmove` 时，`memmove_resolver` 中的 `switch` 语句会匹配到 `case kCortexA53:`。
7. `RETURN_FUNC(memmove_func_t, memmove_a53)` 会返回 `memmove_a53` 函数的地址。

**输出：**

* 后续对 `memmove` 的调用将会执行针对 Cortex-A53 优化的 `memmove_a53` 函数。

**用户或编程常见的使用错误：**

1. **假设所有设备都使用相同的指令集优化:**  开发者不应该假设所有 Android 设备都支持特定的指令集扩展（例如 NEON）。IFUNC 机制正是为了解决这个问题，让系统自动选择最佳实现。
2. **尝试手动调用架构特定的函数:**  直接调用 `memmove_a15` 或类似的函数是不推荐的，因为这会导致代码在其他架构上无法运行，并且可能破坏 bionic 的内部优化机制。应该始终使用标准的 libc 函数名（例如 `memmove`）。
3. **错误地修改或删除 `/dev/cpu_variant:arm`:**  虽然不太可能，但如果用户修改或删除了这个文件，会导致 `init_cpu_variant()` 无法正确检测 CPU 类型，可能会回退到通用的实现，影响性能。

**Android framework 或 ndk 如何一步步的到达这里：**

1. **NDK 开发:** 开发者使用 NDK 编写 C/C++ 代码，调用标准的 C 库函数，例如 `memcpy`, `memset` 等。
2. **编译:** NDK 工具链中的编译器将这些 C/C++ 代码编译成机器码，生成包含对标准 libc 函数调用的共享库或可执行文件。
3. **链接:** 链接器将编译后的代码与所需的库（包括 bionic libc）链接在一起。对于 IFUNC 函数，链接器会设置好 `.got.plt` 条目，指向 IFUNC resolver。
4. **安装和加载:**  当 Android 应用被安装到设备上时，包含 NDK 代码的共享库会被安装到设备的文件系统中。当应用运行时，Android 的 `dalvik` 或 `art` 虚拟机（对于 Java/Kotlin 代码）或者直接由操作系统加载器（对于 Native 代码）加载这些共享库。
5. **动态链接:**  动态链接器（`linker` 或 `linker64`) 负责加载共享库，解析符号，并执行重定位，包括 IFUNC 解析。
6. **首次调用 libc 函数:**  当程序首次调用一个使用了 IFUNC 的 libc 函数时（例如 `memcpy`），控制权会转移到该函数的 IFUNC resolver。
7. **CPU 变体检测和函数选择:**  resolver 函数会调用 `get_cpu_variant()` 来确定当前设备的 CPU 架构，并选择相应的优化实现。
8. **GOT 表更新:** resolver 函数会将 GOT 表中该函数的条目更新为指向选定的优化实现。
9. **执行优化后的函数:**  后续对该函数的调用将直接跳转到优化后的代码执行。

**Frida hook 示例调试这些步骤：**

可以使用 Frida hook 来观察 IFUNC 的解析过程。以下是一个 hook `memmove` 的例子：

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] 找不到进程：{package_name}")
    sys.exit(1)

script_code = """
// 获取 memmove 的地址（初始时指向 resolver）
var memmove_resolver_addr = Module.findExportByName("libc.so", "memmove");
console.log("[*] memmove resolver 地址: " + memmove_resolver_addr);

// Hook memmove 的 resolver 函数
Interceptor.attach(memmove_resolver_addr, {
    onEnter: function(args) {
        console.log("[*] memmove resolver 被调用");
    },
    onLeave: function(retval) {
        console.log("[*] memmove resolver 返回，最终 memmove 地址: " + retval);
    }
});

// Hook 实际的 memmove 函数 (假设是 memmove_a53，需要根据实际情况调整或者hook所有可能的实现)
var memmove_a53_addr = Module.findExportByName("libc.so", "memmove_a53");
if (memmove_a53_addr) {
    Interceptor.attach(memmove_a53_addr, {
        onEnter: function(args) {
            console.log("[*] memmove_a53 被调用，参数: dst=" + args[0] + ", src=" + args[1] + ", size=" + args[2]);
        }
    });
} else {
    console.log("[-] 未找到 memmove_a53");
}
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤：**

1. 将上面的 Python 代码保存为 `hook_memmove.py`。
2. 确保你的 Android 设备已连接并通过 adb 可访问。
3. 将 `你的应用包名` 替换为你要调试的应用的包名。
4. 运行 Frida：`frida -U -f 你的应用包名 hook_memmove.py`  或者先启动应用，然后用 `frida -U 应用进程名 hook_memmove.py` 连接。

**预期输出（示例）：**

```
[*] memmove resolver 地址: 0xb6fxxxxx
[*] memmove resolver 被调用
[*] memmove resolver 返回，最终 memmove 地址: 0xb6yyyyy
[*] memmove_a53 被调用，参数: dst=0x..., src=0x..., size=...
```

**解释：**

* Frida 脚本首先获取 `memmove` 符号的地址，这个地址在初始时指向的是 IFUNC resolver 函数。
* 然后，它 hook 了 `memmove` 的 resolver 函数，在 `onEnter` 和 `onLeave` 中打印日志，显示 resolver 何时被调用以及返回的最终 `memmove` 函数的地址。
* 为了观察实际执行的优化函数，脚本尝试 hook `memmove_a53`（你需要根据设备的 CPU 架构和 bionic 的实现来调整 hook 的函数名）。当实际的 `memmove_a53` 被调用时，会打印出其参数。

通过这种方式，你可以观察到动态链接器如何调用 IFUNC resolver，以及 resolver 如何选择并返回最终的函数实现。

希望这个详细的解释能够帮助你理解 `dynamic_function_dispatch.cpp` 文件的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/arch-arm/dynamic_function_dispatch.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2018 The Android Open Source Project
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

#include <fcntl.h>
#include <private/bionic_ifuncs.h>
#include <sys/syscall.h>

extern "C" {

enum CpuVariant {
  kUnknown = 0,
  kGeneric,
  kCortexA7,
  kCortexA9,
  kCortexA53,
  kCortexA55,
  kKrait,
  kKryo,
};

static constexpr int MAX_CPU_NAME_LEN = 12;
struct CpuVariantNames {
  alignas(alignof(int)) char name[MAX_CPU_NAME_LEN];
  CpuVariant variant;
};

static constexpr CpuVariantNames cpu_variant_names[] = {
    {"cortex-a76", kCortexA55},
    {"kryo385", kCortexA55},
    {"cortex-a75", kCortexA55},
    {"kryo", kKryo},
    {"cortex-a73", kCortexA55},
    {"cortex-a55", kCortexA55},
    {"cortex-a53", kCortexA53},
    {"krait", kKrait},
    {"cortex-a9", kCortexA9},
    {"cortex-a7", kCortexA7},
    // kUnknown indicates the end of this array.
    {"", kUnknown},
};

static long ifunc_open(const char* pathname) {
  register long r0 __asm__("r0") = AT_FDCWD;
  register long r1 __asm__("r1") = reinterpret_cast<long>(pathname);
  register long r2 __asm__("r2") = O_RDONLY;
  register long r3 __asm__("r3") = 0;
  register long r7 __asm__("r7") = __NR_openat;
  __asm__ volatile("swi #0"
                   : "=r"(r0)
                   : "r"(r0), "r"(r1), "r"(r2), "r"(r3), "r"(r7));
  return r0;
}

static ssize_t ifunc_read(int fd, void* buf, size_t count) {
  register long r0 __asm__("r0") = fd;
  register long r1 __asm__("r1") = reinterpret_cast<long>(buf);
  register long r2 __asm__("r2") = count;
  register long r7 __asm__("r7") = __NR_read;
  __asm__ volatile("swi #0"
                   : "=r"(r0)
                   : "r"(r0), "r"(r1), "r"(r2), "r"(r7)
                   : "memory");
  return r0;
}

static int ifunc_close(int fd) {
  register long r0 __asm__("r0") = fd;
  register long r7 __asm__("r7") = __NR_close;
  __asm__ volatile("swi #0" : "=r"(r0) : "r"(r0), "r"(r7));
  return r0;
}

static bool is_same_name(const char* a, const char* b) {
  static_assert(MAX_CPU_NAME_LEN % sizeof(int) == 0, "");
  const int* ia = reinterpret_cast<const int*>(a);
  const int* ib = reinterpret_cast<const int*>(b);
  for (size_t i = 0; i < MAX_CPU_NAME_LEN / sizeof(int); ++i) {
    if (ia[i] != ib[i]) {
      return false;
    }
  }
  return true;
}

static CpuVariant init_cpu_variant() {
  int fd = ifunc_open("/dev/cpu_variant:arm");
  if (fd < 0) return kGeneric;

  alignas(alignof(int)) char name[MAX_CPU_NAME_LEN] = {};

  int bytes_read, total_read = 0;
  while (total_read < MAX_CPU_NAME_LEN - 1 &&
         (bytes_read = ifunc_read(fd, name + total_read,
                                  MAX_CPU_NAME_LEN - 1 - total_read)) > 0) {
    total_read += bytes_read;
  }
  ifunc_close(fd);

  if (bytes_read != 0) {
    // The file is too big. We haven't reach the end. Or maybe there is an
    // error when reading.
    return kGeneric;
  }
  name[total_read] = 0;

  const CpuVariantNames* cpu_variant = cpu_variant_names;
  while (cpu_variant->variant != kUnknown) {
    if (is_same_name(cpu_variant->name, name)) {
      return cpu_variant->variant;
    }
    cpu_variant++;
  }
  return kGeneric;
}

static CpuVariant get_cpu_variant() {
  static CpuVariant cpu_variant = kUnknown;
  if (cpu_variant == kUnknown) {
    cpu_variant = init_cpu_variant();
  }
  return cpu_variant;
}

DEFINE_IFUNC_FOR(memmove) {
  RETURN_FUNC(memmove_func_t, memmove_a15);
}
MEMMOVE_SHIM()

DEFINE_IFUNC_FOR(memcpy) {
  return memmove_resolver(hwcap);
}
MEMCPY_SHIM()

// On arm32, __memcpy() is not publicly exposed, but gets called by memmove()
// in cases where the copy is known to be overlap-safe.
typedef void* __memcpy_func_t(void*, const void*, size_t);
DEFINE_IFUNC_FOR(__memcpy) {
  switch (get_cpu_variant()) {
    case kCortexA7:
      RETURN_FUNC(__memcpy_func_t, __memcpy_a7);
    case kCortexA9:
      RETURN_FUNC(__memcpy_func_t, __memcpy_a9);
    case kKrait:
      RETURN_FUNC(__memcpy_func_t, __memcpy_krait);
    case kCortexA53:
      RETURN_FUNC(__memcpy_func_t, __memcpy_a53);
    case kCortexA55:
      RETURN_FUNC(__memcpy_func_t, __memcpy_a55);
    case kKryo:
      RETURN_FUNC(__memcpy_func_t, __memcpy_kryo);
    default:
      RETURN_FUNC(__memcpy_func_t, __memcpy_a15);
  }
}
DEFINE_STATIC_SHIM(void* __memcpy(void* dst, const void* src, size_t n) {
  FORWARD(__memcpy)(dst, src, n);
})

DEFINE_IFUNC_FOR(__memset_chk) {
  switch (get_cpu_variant()) {
    case kCortexA7:
    case kCortexA53:
    case kCortexA55:
    case kKryo:
      RETURN_FUNC(__memset_chk_func_t, __memset_chk_a7);
    case kCortexA9:
      RETURN_FUNC(__memset_chk_func_t, __memset_chk_a9);
    case kKrait:
      RETURN_FUNC(__memset_chk_func_t, __memset_chk_krait);
    default:
      RETURN_FUNC(__memset_chk_func_t, __memset_chk_a15);
  }
}
__MEMSET_CHK_SHIM()

DEFINE_IFUNC_FOR(memset) {
  switch (get_cpu_variant()) {
    case kCortexA7:
    case kCortexA53:
    case kCortexA55:
    case kKryo:
      RETURN_FUNC(memset_func_t, memset_a7);
    case kCortexA9:
      RETURN_FUNC(memset_func_t, memset_a9);
    case kKrait:
      RETURN_FUNC(memset_func_t, memset_krait);
    default:
      RETURN_FUNC(memset_func_t, memset_a15);
  }
}
MEMSET_SHIM()

DEFINE_IFUNC_FOR(strcpy) {
  switch (get_cpu_variant()) {
    case kCortexA9:
      RETURN_FUNC(strcpy_func_t, strcpy_a9);
    default:
      RETURN_FUNC(strcpy_func_t, strcpy_a15);
  }
}
STRCPY_SHIM()

DEFINE_IFUNC_FOR(__strcpy_chk) {
  switch (get_cpu_variant()) {
    case kCortexA7:
      RETURN_FUNC(__strcpy_chk_func_t, __strcpy_chk_a7);
    case kCortexA9:
      RETURN_FUNC(__strcpy_chk_func_t, __strcpy_chk_a9);
    case kKrait:
    case kKryo:
      RETURN_FUNC(__strcpy_chk_func_t, __strcpy_chk_krait);
    case kCortexA53:
      RETURN_FUNC(__strcpy_chk_func_t, __strcpy_chk_a53);
    case kCortexA55:
      RETURN_FUNC(__strcpy_chk_func_t, __strcpy_chk_a55);
    default:
      RETURN_FUNC(__strcpy_chk_func_t, __strcpy_chk_a15);
  }
}
__STRCPY_CHK_SHIM()

DEFINE_IFUNC_FOR(stpcpy) {
  switch (get_cpu_variant()) {
    case kCortexA9:
      RETURN_FUNC(stpcpy_func_t, stpcpy_a9);
    default:
      RETURN_FUNC(stpcpy_func_t, stpcpy_a15);
  }
}
STPCPY_SHIM()

DEFINE_IFUNC_FOR(strcat) {
  switch (get_cpu_variant()) {
    case kCortexA9:
      RETURN_FUNC(strcat_func_t, strcat_a9);
    default:
      RETURN_FUNC(strcat_func_t, strcat_a15);
  }
}
STRCAT_SHIM()

DEFINE_IFUNC_FOR(__strcat_chk) {
  switch (get_cpu_variant()) {
    case kCortexA7:
      RETURN_FUNC(__strcat_chk_func_t, __strcat_chk_a7);
    case kCortexA9:
      RETURN_FUNC(__strcat_chk_func_t, __strcat_chk_a9);
    case kKrait:
    case kKryo:
      RETURN_FUNC(__strcat_chk_func_t, __strcat_chk_krait);
    case kCortexA53:
      RETURN_FUNC(__strcat_chk_func_t, __strcat_chk_a53);
    case kCortexA55:
      RETURN_FUNC(__strcat_chk_func_t, __strcat_chk_a55);
    default:
      RETURN_FUNC(__strcat_chk_func_t, __strcat_chk_a15);
  }
}
__STRCAT_CHK_SHIM()

DEFINE_IFUNC_FOR(strcmp) {
  RETURN_FUNC(strcmp_func_t, strcmp_a15);
}
STRCMP_SHIM()

DEFINE_IFUNC_FOR(strlen) {
  switch (get_cpu_variant()) {
    case kCortexA9:
      RETURN_FUNC(strlen_func_t, strlen_a9);
    default:
      RETURN_FUNC(strlen_func_t, strlen_a15);
  }
}
STRLEN_SHIM()

}  // extern "C"
```