Response:
Let's break down the thought process for analyzing the given C++ benchmark code.

1. **Understand the Goal:** The first step is to recognize that this is a *benchmark* file. The filename `linker_gnu_hash_benchmark.cpp` immediately suggests it's measuring the performance of GNU hash calculations used by the Android linker. The `#include <benchmark/benchmark.h>` confirms this.

2. **Identify Key Components:** Look for the core elements of the benchmark:
    * **Data:** The `kSampleSymbolList` is a crucial piece. It contains a list of strings that are likely representative of actual symbol names used in shared libraries. The ROT13 encoding hints that the actual content isn't the main focus, but rather the *structure* and *length* of typical symbol names.
    * **Functions Being Benchmarked:** The functions `calculate_gnu_hash_simple` and `calculate_gnu_hash_neon` are the subjects of the performance tests. The `#if USE_GNU_HASH_NEON` indicates conditional compilation, likely using NEON intrinsics for optimized hashing.
    * **Benchmark Setup:** The `BENCHMARK()` macros register the test functions with the benchmarking framework. `BENCHMARK_MAIN()` initiates the benchmark execution.
    * **Loop Structure:** The `for (auto _ : state)` loops are standard boilerplate for Google Benchmark, iterating over the benchmarked operation multiple times to get statistically relevant results. `benchmark::DoNotOptimize()` is used to prevent the compiler from optimizing away the hash calculation.

3. **Infer Functionality:** Based on the filename and the functions being benchmarked, the primary function of the code is to *measure the performance of different implementations of the GNU hash function used by the Android dynamic linker.*

4. **Relate to Android:**  Connect the code to its role in Android:
    * **Dynamic Linker:**  The linker is responsible for loading shared libraries (`.so` files) and resolving symbols (function and variable names) between them.
    * **GNU Hash:**  Android's linker uses GNU hash tables to efficiently look up symbols in shared libraries. This benchmark directly tests the speed of calculating these hashes. Faster hash calculation leads to faster library loading and overall application startup times.

5. **Address Specific Questions:** Go through each of the user's requests systematically:

    * **的功能 (Functions):** Summarize the core purpose – benchmarking GNU hash implementations for the linker.

    * **与 Android 的关系 (Relationship to Android):** Explain the role of the linker and GNU hash in the Android system and how this benchmark contributes to improving performance. Use the `libhwbinder.so` example mentioned in the comments to provide context.

    * **libc 函数 (libc Functions):** Realize that this specific benchmark file doesn't *call* any standard `libc` functions directly related to string manipulation or hashing. The hashing functions are *internal* to the linker. State this clearly.

    * **dynamic linker 的功能 (Dynamic Linker Functions):** Explain the process of dynamic linking, focusing on symbol resolution. Provide a simplified `.so` layout example showing the `.dynsym` and `.hash` sections. Describe the linking process using the calculated hash to quickly find the symbol. Create a hypothetical input and output scenario for symbol lookup.

    * **用户或编程常见的使用错误 (Common User/Programming Errors):**  Think about how developers interact with dynamic linking. The most common issues are usually related to incorrect library paths, missing dependencies, or ABI incompatibilities. Provide examples.

    * **到达这里的步骤 (How to Reach Here):** Describe the journey from app launch to the linker being involved. Start with the app request, the zygote process, `dlopen`, and the linker's role in loading shared libraries.

    * **Frida Hook 示例 (Frida Hook Example):**  Develop a basic Frida script to intercept the `calculate_gnu_hash_simple` function. Explain how to set breakpoints, inspect arguments, and return values. The key is to demonstrate *how* to hook the function, even if the exact purpose within a larger context might be more complex.

6. **Structure and Language:**  Organize the answer clearly using headings and bullet points. Use precise and understandable Chinese. Translate technical terms accurately.

7. **Refinement and Review:**  Read through the entire response to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. For instance, initially, I might have focused too much on the details of the GNU hash algorithm itself. However, the prompt is about the *benchmark*, so the focus should be on its *purpose* and how it relates to the Android linker. Also, ensure that the Frida example is functional and easy to understand.

By following this structured thought process, one can systematically analyze the code and generate a comprehensive and accurate response to the user's request. The key is to connect the specific code snippet to the broader context of the Android operating system and its dynamic linking mechanisms.
好的，让我们来详细分析 `bionic/linker/linker_gnu_hash_benchmark.cpp` 这个文件。

**功能列举:**

这个文件的主要功能是 **benchmark（性能测试）** Android bionic 动态链接器中使用的 **GNU 哈希算法** 的不同实现。具体来说，它测试了以下两种实现：

1. **`calculate_gnu_hash_simple`**: 一个简单的 GNU 哈希算法实现。
2. **`calculate_gnu_hash_neon` (如果定义了 `USE_GNU_HASH_NEON`):** 一个使用 ARM NEON 指令集优化的 GNU 哈希算法实现。

**与 Android 功能的关系及举例说明:**

这个文件直接关系到 Android 的动态链接过程，这是 Android 系统中加载和运行应用程序的关键部分。

* **动态链接器 (linker)**: Android 使用 bionic 库中的动态链接器来加载应用程序依赖的共享库 (`.so` 文件)，并将这些库中的符号（函数、变量等）连接到应用程序的代码中。
* **GNU 哈希表**: 为了高效地查找共享库中的符号，动态链接器使用了哈希表。GNU 哈希是一种特定的哈希表实现，被广泛应用于 ELF 文件格式的共享库中。
* **性能影响**: GNU 哈希算法的效率直接影响到应用程序的启动速度和动态链接的性能。更快的哈希算法意味着更快的符号查找，从而加快库的加载和链接过程。

**举例说明:**

当 Android 系统启动一个应用程序时，动态链接器会执行以下步骤：

1. **加载必要的共享库**: 应用程序通常依赖于一些共享库，例如 `libc.so`, `libm.so`, `libbinder.so` 等。动态链接器会根据应用程序的依赖关系加载这些库。
2. **解析符号**: 加载共享库后，动态链接器需要解析应用程序和各个共享库之间引用的符号。例如，应用程序可能调用了 `libc.so` 中的 `printf` 函数。
3. **符号查找**: 为了找到 `printf` 函数在 `libc.so` 中的地址，动态链接器会使用 GNU 哈希算法在 `libc.so` 的 `.gnu.hash` 段中查找 `printf` 对应的哈希值，然后通过哈希值找到符号表中的条目，最终获得函数的地址。

`linker_gnu_hash_benchmark.cpp` 就是用来衡量步骤 3 中哈希算法的效率的。它使用了一组从 `libhwbinder.so` 中提取的真实符号名称（经过 ROT13 编码）来模拟实际的符号查找场景。

**详细解释每一个 libc 函数的功能是如何实现的:**

**重要提示:**  `linker_gnu_hash_benchmark.cpp` **本身并没有直接调用任何标准的 `libc` 函数** 来实现其 benchmark 功能。它主要关注的是动态链接器内部的 GNU 哈希算法的实现。

`calculate_gnu_hash_simple` 和 `calculate_gnu_hash_neon` 是动态链接器内部的函数，而不是 `libc` 的一部分。它们的实现细节通常涉及位运算和循环。

如果您想了解标准 `libc` 函数的实现，那将是另一个庞大的主题，涉及到例如 `stdio.h` 中的输入输出函数、`stdlib.h` 中的内存管理函数、`string.h` 中的字符串操作函数等等。它们的实现方式各不相同，通常会利用操作系统提供的系统调用。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**SO 布局样本 (简化版):**

```
ELF Header:
  ...
Program Headers:
  ...
Section Headers:
  .dynsym: Dynamic Symbol Table (包含库中定义的和需要引用的符号信息)
  .dynstr: Dynamic String Table (存储符号名称字符串)
  .hash:  Old style hash table (已废弃，但可能存在)
  .gnu.hash: GNU Hash Table (用于快速符号查找)
  .rel.dyn: Relocations for .dynamic section
  .rel.plt: Relocations for Procedure Linkage Table (PLT)
  .text:  可执行代码段
  .rodata: 只读数据段
  .data:  可读写数据段
  ...
```

**链接的处理过程 (简化版):**

1. **加载 SO 文件**: 动态链接器将 SO 文件加载到内存中。
2. **解析 ELF Header 和 Section Headers**:  动态链接器读取 ELF 头和节头，获取各个段的地址、大小等信息。
3. **处理依赖关系**: 动态链接器会递归地加载当前 SO 文件依赖的其他 SO 文件。
4. **处理重定位 (Relocation)**:
   * **识别需要重定位的条目**: 动态链接器会扫描 `.rel.dyn` 和 `.rel.plt` 段，这些段包含了需要进行地址修正的条目信息。
   * **符号查找**: 对于每个需要重定位的符号引用，动态链接器会使用 GNU 哈希表 (在 `.gnu.hash` 段中) 来查找符号在其他已加载的 SO 文件中的地址。
     * **计算哈希值**:  动态链接器使用 GNU 哈希算法计算目标符号名称的哈希值。
     * **在哈希表中查找**:  根据计算出的哈希值，在 `.gnu.hash` 表中查找对应的 bucket。
     * **遍历链表**: 如果 bucket 中存在多个符号，则遍历链表，逐个比较符号名称，直到找到匹配的符号。
   * **地址修正**: 找到符号的地址后，动态链接器会将该地址写入到需要重定位的内存位置。对于函数调用，通常会修改 PLT (Procedure Linkage Table) 中的条目。
5. **完成链接**: 所有符号都被解析和重定位后，SO 文件就可以被正常执行了。

**假设输入与输出 (针对 GNU 哈希函数):**

**假设输入:**  一个符号名称字符串，例如 `"printf"`.

**输出:**  一个 32 位或 64 位的哈希值，这个哈希值会用于在 `.gnu.hash` 表中查找对应的 bucket。

**GNU 哈希算法的简化逻辑:**

```c++
uint32_t calculate_gnu_hash_simple(const char* name) {
  uint32_t h = 5381;
  for (unsigned char c = *name; c != '\0'; c = *++name) {
    h = h * 33 + c; // 或 h = (h << 5) + h + c;
  }
  return h;
}
```

**用户或者编程常见的使用错误:**

1. **库文件路径配置错误 (LD_LIBRARY_PATH)**:  如果应用程序依赖的共享库不在系统默认路径或 `LD_LIBRARY_PATH` 指定的路径下，动态链接器将无法找到库文件，导致加载失败。
   * **错误示例**: 应用程序尝试加载 `mylib.so`，但该文件不在 `/system/lib`, `/vendor/lib` 等标准路径下，且用户没有正确设置 `LD_LIBRARY_PATH`。

2. **ABI 不兼容**:  如果应用程序编译时使用的库版本与运行时系统中提供的库版本不兼容（例如，使用了不同的编译器版本或编译选项），可能会导致符号不匹配或接口不兼容，从而引发链接错误或运行时崩溃。
   * **错误示例**: 应用程序使用 NDK 编译，链接了某个版本的 `libfoo.so`，但在目标设备上，`libfoo.so` 是另一个不兼容的版本。

3. **依赖关系缺失**:  如果应用程序依赖的某个共享库，而该共享库又依赖于其他共享库，但这些更深层次的依赖没有被正确安装或配置，会导致链接器找不到所需的符号。
   * **错误示例**:  `app` 依赖 `libA.so`，而 `libA.so` 又依赖 `libB.so`。如果系统中没有 `libB.so`，那么加载 `libA.so` 时会失败。

4. **符号冲突**:  在极端情况下，如果不同的共享库中定义了相同的符号名称，可能会导致链接器选择错误的符号，从而引发未定义的行为。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**从 Android Framework/NDK 到 GNU 哈希计算的步骤:**

1. **应用程序启动**:  用户点击应用图标，或者系统需要启动某个服务。
2. **Zygote 进程 fork**: Android 系统通常会从 Zygote 进程 fork 出一个新的进程来运行应用程序。
3. **加载应用程序主执行文件**:  系统加载应用程序的 APK 文件，并执行其主执行文件 (通常是一个 ELF 文件)。
4. **动态链接器介入**:  当应用程序的代码尝试访问外部共享库中的函数或变量时，动态链接器会被调用。这可能发生在程序启动初期，或者在程序运行过程中通过 `dlopen`/`dlsym` 等函数动态加载库。
5. **`dlopen` 或隐式链接**:
   * **隐式链接**: 如果应用程序在编译时就声明了对某个共享库的依赖，那么在程序启动时，动态链接器会自动加载这些库。
   * **`dlopen`**: 应用程序也可以在运行时通过 `dlopen` 函数显式地加载共享库。NDK 开发中经常使用 `dlopen` 来加载第三方库。
6. **查找符号**:  当需要解析一个来自共享库的符号时，动态链接器会使用 GNU 哈希算法在目标库的 `.gnu.hash` 段中查找符号的地址。
7. **执行哈希计算函数**:  在查找过程中，动态链接器内部会调用类似 `calculate_gnu_hash_simple` 或 `calculate_gnu_hash_neon` 的函数来计算符号名称的哈希值。

**Frida Hook 示例:**

假设我们要 hook `calculate_gnu_hash_simple` 函数，以便在每次计算哈希值时打印出符号名称和计算结果。

```python
import frida
import sys

# 连接到目标进程
process_name = "com.example.myapp"  # 替换为你的应用进程名
try:
    session = frida.attach(process_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{process_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
// 假设 calculate_gnu_hash_simple 在 linker 库中
const linker_module = Process.getModuleByName("linker64"); // 或 "linker" 根据架构
const calculate_gnu_hash_simple_addr = linker_module.findExportByName("calculate_gnu_hash_simple");

if (calculate_gnu_hash_simple_addr) {
    Interceptor.attach(calculate_gnu_hash_simple_addr, {
        onEnter: function(args) {
            const symbol_name = args[0].readUtf8String();
            console.log(`[GNU Hash Hook] 计算符号 "${symbol_name}" 的哈希值`);
        },
        onLeave: function(retval) {
            console.log(`[GNU Hash Hook] 哈希值为: ${retval}`);
        }
    });
    console.log("Hooked calculate_gnu_hash_simple successfully!");
} else {
    console.log("Error: calculate_gnu_hash_simple not found in linker.");
}
"""

script = session.create_script(script_code)

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Frida]: {message['payload']}")
    elif message['type'] == 'error':
        print(f"[Error]: {message['stack']}")

script.on('message', on_message)
script.load()

print("Press Enter to detach...")
input()
session.detach()
```

**使用说明:**

1. **安装 Frida**: 确保你的电脑上安装了 Frida 和 Python 的 Frida 模块。
2. **找到进程名**: 将 `process_name` 替换为你要调试的 Android 应用的进程名。
3. **运行 Frida 脚本**: 在终端中运行该 Python 脚本。
4. **操作应用程序**:  运行你的 Android 应用程序，当动态链接器进行符号查找时，Frida 会拦截 `calculate_gnu_hash_simple` 函数的调用，并打印出相关的日志信息。

**注意:**

* 上述 Frida 脚本假设 `calculate_gnu_hash_simple` 是一个导出的符号，这在实际的动态链接器实现中可能并不总是这样。如果它是静态函数，你需要使用更高级的 Frida 技术来定位和 hook 它，例如基于偏移地址或 pattern scanning。
* 你可能需要根据目标 Android 设备的架构 (32 位或 64 位) 调整 `Process.getModuleByName("linker64")` 中的模块名称。
* 为了 hook 系统进程，你的设备需要 root 权限。

希望这个详细的分析能够帮助你理解 `bionic/linker/linker_gnu_hash_benchmark.cpp` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/linker/linker_gnu_hash_benchmark.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <benchmark/benchmark.h>

#include "linker_gnu_hash.h"

// 250 symbols from the relocations of system/lib/libhwbinder.so in aosp/master, aosp_walleye.
// ROT13-encoded so as not to pollute code search.
static const char* const kSampleSymbolList[] = {
    "_MA7naqebvq8uneqjner9OUjOvaqre8genafnpgRwEXAF0_6CnepryRCF2_wAFg3__18shapgvbaVSiEF2_RRR",
    "_MA7naqebvq8uneqjner9OUjOvaqre11yvaxGbQrnguREXAF_2fcVAF0_7VOvaqre14QrnguErpvcvragRRRCiw",
    "_MA7naqebvq8uneqjner9OUjOvaqre13hayvaxGbQrnguREXAF_2jcVAF0_7VOvaqre14QrnguErpvcvragRRRCiwCF5_",
    "_MAX7naqebvq8uneqjner7VOvaqre13purpxFhopynffRCXi",
    "_MA7naqebvq8uneqjner9OUjOvaqre12nggnpuBowrpgRCXiCiF4_CSiF3_F4_F4_R",
    "_MAX7naqebvq8uneqjner9OUjOvaqre10svaqBowrpgRCXi",
    "_MA7naqebvq8uneqjner9OUjOvaqre12qrgnpuBowrpgRCXi",
    "_MA7naqebvq8uneqjner9OUjOvaqre11ybpnyOvaqreRi",
    "_MA7naqebvq8uneqjner7VOvaqre12erzbgrOvaqreRi",
    "_MA7naqebvq8uneqjner9OUjOvaqreQ1Ri",
    "_MA7naqebvq8uneqjner9OUjOvaqreQ0Ri",
    "_MA7naqebvq8uneqjner9OUjOvaqre10baGenafnpgRwEXAF0_6CnepryRCF2_wAFg3__18shapgvbaVSiEF2_RRR",
    "_MGi0_a12_A7naqebvq8uneqjner9OUjOvaqreQ1Ri",
    "_MGi0_a12_A7naqebvq8uneqjner9OUjOvaqreQ0Ri",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "_MA7naqebvq8uneqjner11OcUjErsOnfrQ1Ri",
    "_MA7naqebvq8uneqjner11OcUjErsOnfrQ0Ri",
    "_MA7naqebvq8uneqjner11OcUjErsOnfr10baSvefgErsRi",
    "_MA7naqebvq8uneqjner11OcUjErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq8uneqjner11OcUjErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MGi0_a12_A7naqebvq8uneqjner11OcUjErsOnfrQ1Ri",
    "_MGi0_a12_A7naqebvq8uneqjner11OcUjErsOnfrQ0Ri",
    "_MGi0_a16_A7naqebvq8uneqjner11OcUjErsOnfr10baSvefgErsRi",
    "_MGi0_a20_A7naqebvq8uneqjner11OcUjErsOnfr15baYnfgFgebatErsRCXi",
    "_MGi0_a24_A7naqebvq8uneqjner11OcUjErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "_MAX7naqebvq8uneqjner7VOvaqre13purpxFhopynffRCXi",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "_MA7naqebvq8uneqjner7VOvaqre11ybpnyOvaqreRi",
    "_MA7naqebvq8uneqjner7VOvaqre12erzbgrOvaqreRi",
    "_MA7naqebvq8uneqjner7VOvaqreQ1Ri",
    "_MA7naqebvq8uneqjner7VOvaqreQ0Ri",
    "_MGi0_a12_A7naqebvq8uneqjner7VOvaqreQ1Ri",
    "_MGi0_a12_A7naqebvq8uneqjner7VOvaqreQ0Ri",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "_MAX7naqebvq8uneqjner7VOvaqre13purpxFhopynffRCXi",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "_MA7naqebvq8uneqjner7VOvaqre11ybpnyOvaqreRi",
    "_MA7naqebvq8uneqjner7VOvaqre12erzbgrOvaqreRi",
    "_MA7naqebvq8uneqjner7VOvaqreQ1Ri",
    "_MA7naqebvq8uneqjner7VOvaqreQ0Ri",
    "_MGi0_a12_A7naqebvq8uneqjner7VOvaqreQ1Ri",
    "_MGi0_a12_A7naqebvq8uneqjner7VOvaqreQ0Ri",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "_MA7naqebvq8uneqjner10OcUjOvaqre8genafnpgRwEXAF0_6CnepryRCF2_wAFg3__18shapgvbaVSiEF2_RRR",
    "_MA7naqebvq8uneqjner10OcUjOvaqre11yvaxGbQrnguREXAF_2fcVAF0_7VOvaqre14QrnguErpvcvragRRRCiw",
    "_MA7naqebvq8uneqjner10OcUjOvaqre13hayvaxGbQrnguREXAF_2jcVAF0_7VOvaqre14QrnguErpvcvragRRRCiwCF5_",
    "_MAX7naqebvq8uneqjner7VOvaqre13purpxFhopynffRCXi",
    "_MA7naqebvq8uneqjner10OcUjOvaqre12nggnpuBowrpgRCXiCiF4_CSiF3_F4_F4_R",
    "_MAX7naqebvq8uneqjner10OcUjOvaqre10svaqBowrpgRCXi",
    "_MA7naqebvq8uneqjner10OcUjOvaqre12qrgnpuBowrpgRCXi",
    "_MA7naqebvq8uneqjner7VOvaqre11ybpnyOvaqreRi",
    "_MA7naqebvq8uneqjner10OcUjOvaqre12erzbgrOvaqreRi",
    "_MA7naqebvq8uneqjner10OcUjOvaqreQ1Ri",
    "_MA7naqebvq8uneqjner10OcUjOvaqreQ0Ri",
    "_MA7naqebvq8uneqjner10OcUjOvaqre10baSvefgErsRi",
    "_MA7naqebvq8uneqjner10OcUjOvaqre15baYnfgFgebatErsRCXi",
    "_MA7naqebvq8uneqjner10OcUjOvaqre20baVapFgebatNggrzcgrqRwCXi",
    "_MGi0_a12_A7naqebvq8uneqjner10OcUjOvaqreQ1Ri",
    "_MGi0_a12_A7naqebvq8uneqjner10OcUjOvaqreQ0Ri",
    "_MGi0_a16_A7naqebvq8uneqjner10OcUjOvaqre10baSvefgErsRi",
    "_MGi0_a20_A7naqebvq8uneqjner10OcUjOvaqre15baYnfgFgebatErsRCXi",
    "_MGi0_a24_A7naqebvq8uneqjner10OcUjOvaqre20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "_MAX7naqebvq8uneqjner7VOvaqre13purpxFhopynffRCXi",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "_MA7naqebvq8uneqjner7VOvaqre11ybpnyOvaqreRi",
    "_MA7naqebvq8uneqjner7VOvaqre12erzbgrOvaqreRi",
    "_MA7naqebvq8uneqjner7VOvaqreQ1Ri",
    "_MA7naqebvq8uneqjner7VOvaqreQ0Ri",
    "_MGi0_a12_A7naqebvq8uneqjner7VOvaqreQ1Ri",
    "_MGi0_a12_A7naqebvq8uneqjner7VOvaqreQ0Ri",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchgQ2Ri",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchgQ0Ri",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg5cevagRCXpw",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg10zbirVaqragRv",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg10chfuOhaqyrRi",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg9cbcOhaqyrRi",
    "__pkn_cher_iveghny",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "_MA7naqebvq8uneqjner10VVagresnprQ1Ri",
    "_MA7naqebvq8uneqjner10VVagresnprQ0Ri",
    "__pkn_cher_iveghny",
    "_MGi0_a12_A7naqebvq8uneqjner10VVagresnprQ1Ri",
    "_MGi0_a12_A7naqebvq8uneqjner10VVagresnprQ0Ri",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "_MAFg3__114onfvp_vbfgernzVpAF_11pune_genvgfVpRRRQ1Ri",
    "_MAFg3__114onfvp_vbfgernzVpAF_11pune_genvgfVpRRRQ0Ri",
    "_MGua8_AFg3__114onfvp_vbfgernzVpAF_11pune_genvgfVpRRRQ1Ri",
    "_MGua8_AFg3__114onfvp_vbfgernzVpAF_11pune_genvgfVpRRRQ0Ri",
    "_MGi0_a12_AFg3__114onfvp_vbfgernzVpAF_11pune_genvgfVpRRRQ1Ri",
    "_MGi0_a12_AFg3__114onfvp_vbfgernzVpAF_11pune_genvgfVpRRRQ0Ri",
    "_MAFg3__113onfvp_vfgernzVpAF_11pune_genvgfVpRRRQ1Ri",
    "_MAFg3__113onfvp_vfgernzVpAF_11pune_genvgfVpRRRQ0Ri",
    "_MGi0_a12_AFg3__113onfvp_vfgernzVpAF_11pune_genvgfVpRRRQ1Ri",
    "_MGi0_a12_AFg3__113onfvp_vfgernzVpAF_11pune_genvgfVpRRRQ0Ri",
    "_MAFg3__113onfvp_bfgernzVpAF_11pune_genvgfVpRRRQ1Ri",
    "_MAFg3__113onfvp_bfgernzVpAF_11pune_genvgfVpRRRQ0Ri",
    "_MGi0_a12_AFg3__113onfvp_bfgernzVpAF_11pune_genvgfVpRRRQ1Ri",
    "_MGi0_a12_AFg3__113onfvp_bfgernzVpAF_11pune_genvgfVpRRRQ0Ri",
    "_MAFg3__115onfvp_fgernzohsVpAF_11pune_genvgfVpRRR5vzohrREXAF_6ybpnyrR",
    "_MAFg3__115onfvp_fgernzohsVpAF_11pune_genvgfVpRRR6frgohsRCpv",
    "_MAFg3__115onfvp_fgernzohsVpAF_11pune_genvgfVpRRR4flapRi",
    "_MAFg3__115onfvp_fgernzohsVpAF_11pune_genvgfVpRRR9fubjznalpRi",
    "_MAFg3__115onfvp_fgernzohsVpAF_11pune_genvgfVpRRR6kftrgaRCpv",
    "_MAFg3__115onfvp_fgernzohsVpAF_11pune_genvgfVpRRR5hsybjRi",
    "_MAFg3__115onfvp_fgernzohsVpAF_11pune_genvgfVpRRR6kfchgaRCXpv",
    "_MA7naqebvq8uneqjner12CebprffFgngrQ1Ri",
    "_MA7naqebvq8uneqjner12CebprffFgngrQ0Ri",
    "_MGi0_a12_A7naqebvq8uneqjner12CebprffFgngrQ1Ri",
    "_MGi0_a12_A7naqebvq8uneqjner12CebprffFgngrQ0Ri",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "_MA7naqebvq6Guernq3ehaRCXpvw",
    "_MA7naqebvq6Guernq11erdhrfgRkvgRi",
    "_MA7naqebvq6Guernq10ernqlGbEhaRi",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "_MA7naqebvq6GuernqQ1Ri",
    "_MA7naqebvq6GuernqQ0Ri",
    "_MA7naqebvq6Guernq3ehaRCXpvw",
    "_MA7naqebvq6Guernq11erdhrfgRkvgRi",
    "_MA7naqebvq6Guernq10ernqlGbEhaRi",
    "__pkn_cher_iveghny",
    "_MGi0_a12_A7naqebvq6GuernqQ1Ri",
    "_MGi0_a12_A7naqebvq6GuernqQ0Ri",
    "_MA7naqebvq7ErsOnfr10baSvefgErsRi",
    "_MA7naqebvq7ErsOnfr15baYnfgFgebatErsRCXi",
    "_MA7naqebvq7ErsOnfr20baVapFgebatNggrzcgrqRwCXi",
    "_MA7naqebvq7ErsOnfr13baYnfgJrnxErsRCXi",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchgQ2Ri",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg5cevagRCXpw",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg10zbirVaqragRv",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg10chfuOhaqyrRi",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg9cbcOhaqyrRi",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchgQ2Ri",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg5cevagRCXpw",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg10zbirVaqragRv",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg10chfuOhaqyrRi",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg9cbcOhaqyrRi",
    "_MA7naqebvq8uneqjner10GrkgBhgchgQ2Ri",
    "_MA7naqebvq8uneqjner10GrkgBhgchgQ0Ri",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "__pkn_cher_iveghny",
    "_MGIA7naqebvq8uneqjner9OUjOvaqreR",
    "_MGPA7naqebvq8uneqjner9OUjOvaqreR0_AF0_7VOvaqreR",
    "_MGPA7naqebvq8uneqjner9OUjOvaqreR0_AF0_7VOvaqreR",
    "_MGIA7naqebvq8uneqjner9OUjOvaqreR",
    "_MGIA7naqebvq8uneqjner11OcUjErsOnfrR",
    "_MGIA7naqebvq8uneqjner11OcUjErsOnfrR",
    "_MGIA7naqebvq8uneqjner7VOvaqreR",
    "_MGIA7naqebvq8uneqjner7VOvaqreR",
    "_MGIA7naqebvq8uneqjner10OcUjOvaqreR",
    "_MGPA7naqebvq8uneqjner10OcUjOvaqreR0_AF0_7VOvaqreR",
    "_MGPA7naqebvq8uneqjner10OcUjOvaqreR0_AF0_7VOvaqreR",
    "_MGIA7naqebvq8uneqjner10OcUjOvaqreR",
    "_MGIA7naqebvq8uneqjner10VVagresnprR",
    "_MGIA7naqebvq8uneqjner10VVagresnprR",
    "_MGIAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR",
    "_MGPAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR0_AF_14onfvp_vbfgernzVpF2_RR",
    "_MGPAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR0_AF_13onfvp_vfgernzVpF2_RR",
    "_MGPAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR0_AF_13onfvp_vfgernzVpF2_RR",
    "_MGPAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR8_AF_13onfvp_bfgernzVpF2_RR",
    "_MGPAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR8_AF_13onfvp_bfgernzVpF2_RR",
    "_MGPAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR0_AF_14onfvp_vbfgernzVpF2_RR",
    "_MGPAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR0_AF_14onfvp_vbfgernzVpF2_RR",
    "_MGIAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR",
    "_MGIAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR",
    "_MGIA7naqebvq8uneqjner12CebprffFgngrR",
    "_MGIA7naqebvq8uneqjner12CebprffFgngrR",
    "_MGIA7naqebvq8uneqjner10CbbyGuernqR",
    "_MGPA7naqebvq8uneqjner10CbbyGuernqR0_AF_6GuernqR",
    "_MGPA7naqebvq8uneqjner10CbbyGuernqR0_AF_6GuernqR",
    "_MGIA7naqebvq8uneqjner10CbbyGuernqR",
    "_MGIA7naqebvq8uneqjner9OUjOvaqreR",
    "__fgnpx_pux_thneq",
    "_MGIA7naqebvq8uneqjner11OcUjErsOnfrR",
    "_MGIA7naqebvq12FbegrqIrpgbeVAF_16xrl_inyhr_cnve_gVCXiAF_8uneqjner10OcUjOvaqre13BowrpgZnantre7ragel_gRRRRR",
    "_MGPA7naqebvq8uneqjner10OcUjOvaqreR0_AF0_7VOvaqreR",
    "_MGIA7naqebvq8uneqjner10OcUjOvaqreR",
    "_MGIA7naqebvq6IrpgbeVAF_8uneqjner10OcUjOvaqre8BovghnelRRR",
    "_MGGA7naqebvq8uneqjner10OcUjOvaqreR",
    "_MGIA7naqebvq6IrpgbeVAF_2fcVAF_8uneqjner18OhssrerqGrkgBhgchg11OhssreFgngrRRRRR",
    "_MA7naqebvq8uneqjner18OhssrerqGrkgBhgchg16guernqQrfgehpgbeRCi",
    "_MGIA7naqebvq8uneqjner18OhssrerqGrkgBhgchgR",
    "_MA7naqebvq8uneqjner12tGrkgOhssrefR",
    "_MGIA7naqebvq8uneqjner18OhssrerqGrkgBhgchg11OhssreFgngrR",
    "_MA7naqebvq8uneqjner14VCPGuernqFgngr16guernqQrfgehpgbeRCi",
    "_MA7naqebvq8uneqjner14VCPGuernqFgngr10serrOhssreRCAF0_6CnepryRCXuwCXlwCi",
    "_MA7naqebvq8uneqjner18gur_pbagrkg_bowrpgR",
    "_MA7naqebvq9PnyyFgnpx18trgPheeragVagreanyRv",
    "_MA7naqebvq9PnyyFgnpx16ybtFgnpxVagreanyRCXpCXF0_19naqebvq_YbtCevbevgl",
    "_MGIA7naqebvq6IrpgbeVCAF_8uneqjner9OUjOvaqreRRR",
    "_MGIA7naqebvq6IrpgbeVCAF_7ErsOnfr12jrnxers_glcrRRR",
    "_MGIA7naqebvq6IrpgbeVCAF_7ErsOnfrRRR",
    "_MFg7abguebj",
    "_MGPAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR0_AF_13onfvp_vfgernzVpF2_RR",
    "_MGIAFg3__118onfvp_fgevatfgernzVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR",
    "_MGIAFg3__115onfvp_fgevatohsVpAF_11pune_genvgfVpRRAF_9nyybpngbeVpRRRR",
    "_MAFg3__15pglcrVpR2vqR",
    "_MA7naqebvq8uneqjner13tCebprffZhgrkR",
    "_MA7naqebvq8uneqjner8tCebprffR",
    "_MGIA7naqebvq8uneqjner12CebprffFgngrR",
    "_MGIA7naqebvq6IrpgbeVAF_8uneqjner12CebprffFgngr12unaqyr_ragelRRR",
    "_MGIA7naqebvq12FbegrqIrpgbeVAF_16xrl_inyhr_cnve_gVAF_8Fgevat16RAF_2fcVAF_8uneqjner7VOvaqreRRRRRRR",
    "_MGIA7naqebvq8uneqjner10CbbyGuernqR",
    "_MGGA7naqebvq8uneqjner12CebprffFgngrR",
    "_MGIA7naqebvq6IrpgbeVvRR",
    "_MGIA7naqebvq8uneqjner13YbtGrkgBhgchgR",
};

static void BM_gnu_hash_simple(benchmark::State& state) {
  for (auto _ : state) {
    for (const char* sym_name : kSampleSymbolList) {
      benchmark::DoNotOptimize(calculate_gnu_hash_simple(sym_name));
    }
  }
}

BENCHMARK(BM_gnu_hash_simple);

#if USE_GNU_HASH_NEON

static void BM_gnu_hash_neon(benchmark::State& state) {
  for (auto _ : state) {
    for (const char* sym_name : kSampleSymbolList) {
      benchmark::DoNotOptimize(calculate_gnu_hash_neon(sym_name));
    }
  }
}

BENCHMARK(BM_gnu_hash_neon);

#endif  // USE_GNU_HASH_NEON

BENCHMARK_MAIN();
```