Response:
Let's break down the thought process for answering the request about `bionic/libc/bionic/vdso.cpp`.

**1. Understanding the Core Request:**

The request is about understanding the functionality of the `vdso.cpp` file within Android's bionic library. The prompt specifically asks for:

* **Functions:** What does this file *do*?
* **Android Relationship:** How does it connect to Android's workings?
* **Libc Function Details:**  How are the libc functions within this file implemented?
* **Dynamic Linker (ld.so) Interaction:** How does it relate to the dynamic linker, and what does that look like in memory?
* **Logic/Examples:**  Illustrative scenarios.
* **Common Mistakes:** User errors.
* **Android Framework/NDK Path:**  How does a call from a higher layer reach this code?
* **Frida Hooking:** How to inspect this code dynamically.

**2. Initial Analysis of the Code:**

The first step is to read through the provided C++ code. Key observations immediately jump out:

* **VDSO in the Name:** "vdso" strongly suggests Virtual Dynamically Shared Object. This is a kernel mechanism for providing certain system calls in user space to avoid costly kernel transitions.
* **Function Pointers:** The code uses function pointers extensively (e.g., `vdso_clock_gettime`). This indicates the file is dynamically resolving functions.
* **`__libc_globals`:**  This global structure likely holds pointers to the VDSO functions.
* **`clock_gettime`, `clock_getres`, `gettimeofday`, `time`, `__riscv_hwprobe`:** These are all system-related calls, particularly time-related ones.
* **`__libc_init_vdso`:**  This function is clearly responsible for initializing the VDSO function pointers.
* **ELF Structures:** The code manipulates ELF header (`ElfW(Ehdr)`), section header (`ElfW(Shdr)`), program header (`ElfW(Phdr)`), dynamic table (`ElfW(Dyn)`), and symbol table (`ElfW(Sym)`) entries. This confirms the VDSO is treated as a shared object.
* **`getauxval(AT_SYSINFO_EHDR)`:**  This retrieves the address of the VDSO header from the auxiliary vector, confirming the standard VDSO mechanism is being used.

**3. Deconstructing the Functionality:**

Based on the code analysis, the core functionality is:

* **Providing Fast Paths for System Calls:** The primary goal is to intercept calls to certain system functions (like time-related ones) and, if a VDSO version is available, execute that faster user-space version.
* **Dynamic Resolution:**  `__libc_init_vdso` parses the VDSO ELF to find the addresses of the desired symbols.
* **Fallback Mechanism:** If a VDSO version isn't found, the code falls back to the standard `__` prefixed system call implementations.

**4. Addressing Specific Questions:**

Now, systematically answer each part of the prompt:

* **Functions:** List the publicly exposed functions: `clock_gettime`, `clock_getres`, `gettimeofday`, `time`, and `__riscv_hwprobe`. Explain their purpose (getting time, resolution, current time, RISC-V hardware probing).
* **Android Relationship:**  Explain *why* this is important for Android performance. Reducing kernel transitions is crucial for responsiveness, battery life, etc. Give concrete examples of where time functions are used (e.g., scheduling, networking, UI updates).
* **Libc Function Implementation:** Detail how each function works: check for VDSO function pointer, call it if available using `vdso_return` for error handling, otherwise call the underlying syscall. Explain `vdso_return`. Highlight the architecture-specific handling of `time()`.
* **Dynamic Linker:**
    * **SO Layout:**  Describe the typical VDSO layout in memory (mapped at a specific address, containing code and data sections). Provide a *simplified* memory map showing the ELF header, program headers, dynamic table, symbol table, and the actual function code.
    * **Linking Process:** Explain how `ld.so` (the dynamic linker) finds and loads the VDSO during process startup. Mention `AT_SYSINFO_EHDR`. Describe how `__libc_init_vdso` then resolves the specific symbols *within* the already loaded VDSO.
* **Logic/Examples:**
    * **Assumption:**  Assume the VDSO contains optimized `clock_gettime`.
    * **Input:** A call to `clock_gettime(CLOCK_REALTIME, &ts)`.
    * **Output:** Either the VDSO implementation successfully populates `ts`, or the syscall implementation does. Illustrate the path taken.
* **User Errors:**  Focus on *indirect* errors, as users don't directly call VDSO functions. Explain errors related to time inconsistencies or issues with system configuration affecting VDSO loading (although this is rare).
* **Android Framework/NDK Path:** Trace a call from a high-level Android API (e.g., `System.currentTimeMillis()`) down through the layers: Java Framework -> Native code (JNI) -> Bionic libc (`clock_gettime` or `gettimeofday`). Explain how the NDK exposes these libc functions.
* **Frida Hooking:** Provide concrete Frida code examples to:
    * Hook the `clock_gettime` function in the VDSO.
    * Hook the `__clock_gettime` syscall implementation as a comparison.
    * Demonstrate accessing arguments and return values.
    * Hook the `__libc_init_vdso` function to observe the VDSO initialization process.

**5. Structuring the Answer:**

Organize the information logically using headings and subheadings. Use clear and concise language. Provide code snippets and examples where appropriate. Emphasize key concepts like performance, kernel transitions, and dynamic linking.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on the ELF parsing details.
* **Correction:** Realize the prompt asks for the *functionality* and *context*, so the ELF parsing details should be explained concisely to support the main point about dynamic resolution.
* **Initial thought:**  Focus only on direct user calls to these functions.
* **Correction:** Recognize that most user interaction is indirect, so emphasize the role of the VDSO in optimizing system calls made by higher-level libraries and the framework.
* **Initial thought:**  Overcomplicate the Frida examples.
* **Correction:** Keep the Frida examples simple and focused on demonstrating the core concepts of hooking VDSO functions and syscalls.

By following this structured thought process, analyzing the code, and addressing each part of the prompt methodically, we arrive at a comprehensive and informative answer.
好的，让我们详细分析一下 `bionic/libc/bionic/vdso.cpp` 这个文件。

**文件功能概述**

`vdso.cpp` 文件实现了对某些常用系统调用的优化，通过使用虚拟动态共享对象（Virtual Dynamically Shared Object，VDSO）。VDSO 是一种内核机制，允许内核将一小部分核心系统调用以普通共享库的形式映射到用户进程的地址空间中。这使得用户空间可以直接调用这些函数，而无需陷入内核，从而显著提高性能。

简单来说，`vdso.cpp` 的主要功能是：

1. **提供更快版本的某些 libc 函数：** 它包含了 `clock_gettime`, `clock_getres`, `gettimeofday`, `time` (在某些架构上), 和 `__riscv_hwprobe`（RISC-V 架构） 这些函数的实现。这些实现会尝试优先调用 VDSO 中由内核提供的版本。
2. **初始化 VDSO 函数指针：**  `__libc_init_vdso` 函数负责在程序启动时检测系统中是否存在 VDSO，并从中找到所需函数的地址，并将这些地址存储在全局变量 `__libc_globals->vdso` 中。
3. **作为调用 VDSO 和 syscall 的桥梁：**  如果 VDSO 中存在对应的函数，则调用 VDSO 版本；否则，回退到传统的通过 `syscall` 指令陷入内核的方式调用。

**与 Android 功能的关系及举例**

VDSO 的存在直接提升了 Android 系统的性能和效率。许多核心系统操作都依赖于这里实现的函数，例如：

* **获取当前时间：** `clock_gettime`, `gettimeofday`, `time` 被广泛用于各种场景，例如：
    * **系统服务：** Android 的各种系统服务需要跟踪时间，进行事件调度等。例如，`ActivityManagerService` 需要记录应用的启动和运行时间。
    * **应用层：**  应用需要获取当前时间戳用于各种目的，例如网络请求的超时设置、日志记录、性能监控等。
    * **动画和渲染：**  流畅的动画和渲染需要精确的时间控制。
* **获取时钟分辨率：** `clock_getres` 用于查询特定时钟源的精度，这对于需要高精度计时的应用非常重要。
* **硬件探测 (RISC-V)：** `__riscv_hwprobe` 用于在 RISC-V 架构上探测硬件特性。这允许系统根据硬件能力进行优化。

**举例说明：`clock_gettime` 的使用**

假设一个 Android 应用需要获取当前的系统时间。它会调用 `clock_gettime` 函数：

```c++
#include <time.h>
#include <stdio.h>

int main() {
  struct timespec ts;
  if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
    printf("Current time: %ld seconds, %ld nanoseconds\n", ts.tv_sec, ts.tv_nsec);
  } else {
    perror("clock_gettime failed");
  }
  return 0;
}
```

在这个例子中，`clock_gettime` 的调用流程如下：

1. 应用调用 `clock_gettime` 函数。
2. `bionic/libc/bionic/vdso.cpp` 中的 `clock_gettime` 实现被调用。
3. 该实现首先检查全局变量 `__libc_globals->vdso[VDSO_CLOCK_GETTIME].fn` 是否为空。
4. 如果 VDSO 可用且内核提供了 `clock_gettime` 的 VDSO 版本，则该指针不为空，直接调用 VDSO 中的 `clock_gettime` 函数。这个调用是在用户空间完成的，避免了陷入内核。
5. 如果 VDSO 不可用或内核没有提供，则调用 `__clock_gettime`，这会通过系统调用陷入内核。

**libc 函数的实现细节**

让我们详细解释一下 `vdso.cpp` 中实现的 libc 函数：

* **`clock_gettime(int clock_id, timespec* tp)`:**
    * 首先尝试从 `__libc_globals->vdso` 中获取指向 VDSO 版本 `clock_gettime` 的函数指针。
    * 如果指针存在（VDSO 可用），则调用 VDSO 版本的函数。`vdso_return` 函数用于处理 VDSO 函数的返回值，如果返回值为 0 表示成功，否则将其取反并设置为 `errno`，然后返回 -1 表示失败。
    * 如果指针不存在，则调用 `__clock_gettime`，这是一个标准的 libc 函数，通常会通过 `syscall` 指令陷入内核。
* **`clock_getres(int clock_id, timespec* tp)`:**
    * 实现逻辑与 `clock_gettime` 类似，尝试优先调用 VDSO 版本的 `clock_getres`，否则回退到 `__clock_getres`。
* **`gettimeofday(timeval* tv, struct timezone* tz)`:**
    * 实现逻辑与 `clock_gettime` 类似，尝试优先调用 VDSO 版本的 `gettimeofday`，否则回退到 `__gettimeofday`。
* **`time(time_t* t)`:**
    * 这个函数的 VDSO 版本并不是在所有架构上都存在（代码中用 `#ifdef VDSO_TIME_SYMBOL` 进行条件编译）。
    * 如果 VDSO 版本存在，则直接调用。
    * 如果 VDSO 版本不存在，则会调用 `gettimeofday` 来获取时间，因为大多数架构上没有直接的 `time(2)` 系统调用。这说明了 VDSO 不可用时的一种替代方案。
* **`__riscv_hwprobe(struct riscv_hwprobe* _Nonnull pairs, size_t pair_count, size_t cpu_count, unsigned long* _Nullable cpus, unsigned flags)`:**
    * 优先尝试调用 VDSO 版本的 `__riscv_hwprobe`。
    * 如果 VDSO 版本不存在，则直接内联了 `riscv_hwprobe` 的系统调用指令。这样做是为了避免在 `ifunc` 解析器中调用此函数时可能出现的 `errno` 设置问题。

**涉及 dynamic linker 的功能**

`__libc_init_vdso` 函数是与 dynamic linker (通常是 `ld.so`) 交互的关键部分。其主要流程如下：

1. **获取 VDSO 的基地址：**  通过调用 `getauxval(AT_SYSINFO_EHDR)` 获取内核提供的 VDSO ELF 头的地址。`AT_SYSINFO_EHDR` 是一个辅助向量条目，由内核在进程启动时设置。
2. **检查 VDSO 是否存在：** 如果 `getauxval` 返回空指针，则表示系统中没有 VDSO，初始化过程结束。
3. **解析 ELF 结构：**  解析 VDSO 的 ELF 头（`ElfW(Ehdr)`）、节头表（`ElfW(Shdr)`）来找到动态符号表（`.dynsym`）。
4. **找到动态符号表的信息：** 从节头表中找到类型为 `SHT_DYNSYM` 的节，计算符号的数量。
5. **找到动态链接表：** 解析程序头表（`ElfW(Phdr)`）找到类型为 `PT_DYNAMIC` 的段，获取动态链接表（`.dynamic`）。
6. **计算 VDSO 的加载地址：**  从程序头表中找到 `PT_LOAD` 段，计算 VDSO 在内存中的加载地址。
7. **查找字符串表和符号表：** 遍历动态链接表，找到字符串表（`.strtab`）和符号表（`.symtab`）的地址。
8. **解析符号并填充函数指针：** 遍历预定义的 VDSO 函数名称列表（例如 `VDSO_CLOCK_GETTIME_SYMBOL`），在 VDSO 的符号表中查找对应的符号。如果找到，则计算出该符号在 VDSO 内存中的地址，并将其存储到 `__libc_globals->vdso` 数组中。

**SO 布局样本和链接处理过程**

假设一个简化的 VDSO 的内存布局如下：

```
[VDSO 基地址] --------------------
|  Elf Header                  |
|  Program Headers             |
|   - PT_LOAD (可执行代码)     |
|   - PT_DYNAMIC (动态链接表)  |
|  Section Headers             |
|   - .text (代码段)           |
|   - .dynsym (动态符号表)      |
|   - .dynstr (动态字符串表)    |
|   ...                         |
|  .text 段 (包含 clock_gettime 等函数的代码) |
|  .dynsym 段 (包含符号表条目)  |
|    - clock_gettime          |  <-- 指向 .text 段中 clock_gettime 代码的地址
|    - clock_getres           |
|    ...                         |
|  .dynstr 段 (包含符号名称字符串) |
|    - "clock_gettime"         |
|    - "clock_getres"          |
|    ...                         |
------------------------------------
```

**链接处理过程：**

1. **内核创建 VDSO：** 在系统启动时，内核会将 VDSO 代码和数据准备好。
2. **动态链接器加载：** 当一个新进程启动时，内核会将 VDSO 映射到进程的地址空间中。内核通过 `auxv` 传递 VDSO ELF 头的地址给进程。
3. **`__libc_init_vdso` 初始化：** `libc` 的初始化代码会调用 `__libc_init_vdso`。
4. **解析 VDSO：** `__libc_init_vdso` 根据 `auxv` 中获取的地址，解析 VDSO 的 ELF 结构，找到符号表和字符串表。
5. **符号查找和地址绑定：** `__libc_init_vdso` 遍历需要优化的函数名称，在 VDSO 的符号表中查找对应的符号。一旦找到，就将符号的地址（即 VDSO 中函数代码的地址）存储在 `__libc_globals->vdso` 数组中。

**假设输入与输出 (逻辑推理)**

假设：

* **输入：**  一个进程调用 `clock_gettime(CLOCK_MONOTONIC, &ts)`。
* **前提：**  系统支持 VDSO，且内核提供了 `clock_gettime` 的 VDSO 版本。

**输出：**

1. `bionic/libc/bionic/vdso.cpp` 中的 `clock_gettime` 函数被调用。
2. 函数内部检查 `__libc_globals->vdso[VDSO_CLOCK_GETTIME].fn`，发现其指向 VDSO 中的 `clock_gettime` 实现。
3. 直接调用 VDSO 中的 `clock_gettime` 函数，该函数在用户空间完成操作，将单调时钟的当前值写入 `ts` 结构。
4. VDSO 中的 `clock_gettime` 返回 0 表示成功。
5. `bionic/libc/bionic/vdso.cpp` 中的 `clock_gettime` 函数也返回 0。
6. 调用进程成功获取到单调时钟的时间。

**涉及的用户或编程常见使用错误**

虽然用户通常不会直接与 VDSO 交互，但一些间接的错误可能与 VDSO 相关：

1. **时间不一致：**  如果系统配置错误或存在虚拟化问题，可能导致 VDSO 提供的时间与实际系统时间不一致。这通常不是编程错误，而是系统环境问题。
2. **错误的 `clock_id`：**  传递给 `clock_gettime` 等函数错误的 `clock_id` 会导致函数返回错误。例如，使用了一个内核不支持的 clock ID。这与 VDSO 本身关系不大，但会影响时间获取的正确性。
3. **假设 VDSO 总是存在：**  虽然现代 Android 系统几乎都支持 VDSO，但在非常老的系统或某些特殊环境下，VDSO 可能不存在。程序不应该假设 VDSO 总是可用，`bionic/libc/bionic/vdso.cpp` 的设计已经考虑了这种情况并提供了回退机制。

**Android Framework 或 NDK 如何到达这里**

让我们以一个简单的例子说明，一个 Java 应用如何最终调用到 `bionic/libc/bionic/vdso.cpp` 中的 `clock_gettime`：

1. **Java 代码：** Android Framework 中的 Java 代码调用 `System.currentTimeMillis()` 或 `System.nanoTime()`。

2. **Framework 层：** `System.currentTimeMillis()` 最终会调用到 `java.lang.System` 类的 native 方法 `currentTimeMillis()`。`System.nanoTime()` 最终会调用到 `java.lang.System` 类的 native 方法 `nanoTime()`。

3. **JNI 调用：** 这些 native 方法通过 JNI (Java Native Interface) 调用到 Android 运行时 (ART) 或 Dalvik 虚拟机中的 native 代码。

4. **ART/Dalvik 虚拟机：** ART/Dalvik 虚拟机内部会调用到 Bionic libc 提供的相应的 C 函数。例如，`System.currentTimeMillis()` 可能会间接调用到 `gettimeofday` 或 `clock_gettime(CLOCK_REALTIME, ...)`，而 `System.nanoTime()` 可能会间接调用到 `clock_gettime(CLOCK_MONOTONIC, ...)` 或 `clock_gettime(CLOCK_BOOTTIME, ...)`。

5. **Bionic libc (vdso.cpp)：**  最终，对 `clock_gettime` 或 `gettimeofday` 的调用会进入 `bionic/libc/bionic/vdso.cpp` 中实现的对应函数。如果 VDSO 可用，则会调用 VDSO 中的优化版本，否则会调用到内核的系统调用。

**Frida Hook 示例调试步骤**

你可以使用 Frida 来 hook `vdso.cpp` 中的函数，观察其行为：

**示例 1：Hook `clock_gettime` 并打印参数和返回值**

```javascript
// hook_clock_gettime.js
if (Process.platform === 'android') {
  const clock_gettime = Module.findExportByName(null, "clock_gettime");
  if (clock_gettime) {
    Interceptor.attach(clock_gettime, {
      onEnter: function (args) {
        const clock_id = args[0].toInt32();
        const timespecPtr = ptr(args[1]);
        console.log(`[clock_gettime] clock_id: ${clock_id}, timespec*: ${timespecPtr}`);
      },
      onLeave: function (retval) {
        const result = retval.toInt32();
        console.log(`[clock_gettime] returned: ${result}`);
        if (result === 0) {
          const timespecPtr = this.context.sp.add(Process.pointerSize * 1); // Adjust based on architecture
          const tv_sec = timespecPtr.readU64();
          const tv_nsec = timespecPtr.add(8).readU64();
          console.log(`[clock_gettime] timespec: { tv_sec: ${tv_sec}, tv_nsec: ${tv_nsec} }`);
        }
      }
    });
    console.log("Hooked clock_gettime");
  } else {
    console.log("clock_gettime not found");
  }
} else {
  console.log("Not an Android environment");
}
```

**使用 Frida 运行：**

```bash
frida -U -f <your_app_package_name> -l hook_clock_gettime.js --no-pause
```

**示例 2：Hook `__libc_init_vdso` 查看 VDSO 初始化过程**

```javascript
// hook_libc_init_vdso.js
if (Process.platform === 'android') {
  const libc_init_vdso = Module.findExportByName("libc.so", "__libc_init_vdso");
  if (libc_init_vdso) {
    Interceptor.attach(libc_init_vdso, {
      onEnter: function (args) {
        const globalsPtr = ptr(args[0]);
        console.log(`[__libc_init_vdso] libc_globals*: ${globalsPtr}`);
      },
      onLeave: function (retval) {
        console.log("[__libc_init_vdso] finished");
      }
    });
    console.log("Hooked __libc_init_vdso");
  } else {
    console.log("__libc_init_vdso not found");
  }
} else {
  console.log("Not an Android environment");
}
```

**使用 Frida 运行：**

```bash
frida -U -f <your_app_package_name> -l hook_libc_init_vdso.js --no-pause
```

通过这些 Frida hook 示例，你可以观察到 `clock_gettime` 的调用参数和返回值，以及 `__libc_init_vdso` 的执行，从而更深入地理解 VDSO 的工作原理。

希望这个详细的解释能够帮助你理解 `bionic/libc/bionic/vdso.cpp` 文件的功能和作用。

### 提示词
```
这是目录为bionic/libc/bionic/vdso.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include "private/bionic_globals.h"
#include "private/bionic_vdso.h"

#include <limits.h>
#include <link.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/cdefs.h>
#include <sys/hwprobe.h>
#include <sys/time.h>
#include <syscall.h>
#include <time.h>
#include <unistd.h>

extern "C" int __clock_gettime(int, struct timespec*);
extern "C" int __clock_getres(int, struct timespec*);
extern "C" int __gettimeofday(struct timeval*, struct timezone*);

static inline int vdso_return(int result) {
  if (__predict_true(result == 0)) return 0;

  errno = -result;
  return -1;
}

int clock_gettime(int clock_id, timespec* tp) {
  auto vdso_clock_gettime = reinterpret_cast<decltype(&clock_gettime)>(
    __libc_globals->vdso[VDSO_CLOCK_GETTIME].fn);
  if (__predict_true(vdso_clock_gettime)) {
    return vdso_return(vdso_clock_gettime(clock_id, tp));
  }
  return __clock_gettime(clock_id, tp);
}

int clock_getres(int clock_id, timespec* tp) {
  auto vdso_clock_getres = reinterpret_cast<decltype(&clock_getres)>(
    __libc_globals->vdso[VDSO_CLOCK_GETRES].fn);
  if (__predict_true(vdso_clock_getres)) {
    return vdso_return(vdso_clock_getres(clock_id, tp));
  }
  return __clock_getres(clock_id, tp);
}

int gettimeofday(timeval* tv, struct timezone* tz) {
  auto vdso_gettimeofday = reinterpret_cast<decltype(&gettimeofday)>(
    __libc_globals->vdso[VDSO_GETTIMEOFDAY].fn);
  if (__predict_true(vdso_gettimeofday)) {
    return vdso_return(vdso_gettimeofday(tv, tz));
  }
  return __gettimeofday(tv, tz);
}

time_t time(time_t* t) {
  // Only x86/x86-64 actually have time() in the vdso.
#if defined(VDSO_TIME_SYMBOL)
  auto vdso_time = reinterpret_cast<decltype(&time)>(__libc_globals->vdso[VDSO_TIME].fn);
  if (__predict_true(vdso_time)) {
    return vdso_time(t);
  }
#endif

  // We can't fallback to the time(2) system call because it doesn't exist for most architectures.
  timeval tv;
  if (gettimeofday(&tv, nullptr) == -1) return -1;
  if (t) *t = tv.tv_sec;
  return tv.tv_sec;
}

#if defined(__riscv)
int __riscv_hwprobe(struct riscv_hwprobe* _Nonnull pairs, size_t pair_count, size_t cpu_count,
                    unsigned long* _Nullable cpus, unsigned flags) {
  auto vdso_riscv_hwprobe =
      reinterpret_cast<decltype(&__riscv_hwprobe)>(__libc_globals->vdso[VDSO_RISCV_HWPROBE].fn);
  if (__predict_true(vdso_riscv_hwprobe)) {
    return -vdso_riscv_hwprobe(pairs, pair_count, cpu_count, cpus, flags);
  }
  // Inline the syscall directly in case someone's calling it from an
  // ifunc resolver where we won't be able to set errno on failure.
  // (Rather than our usual trick of letting the python-generated
  // wrapper set errno but saving/restoring errno in cases where the API
  // is to return an error value rather than setting errno.)
  register long a0 __asm__("a0") = reinterpret_cast<long>(pairs);
  register long a1 __asm__("a1") = pair_count;
  register long a2 __asm__("a2") = cpu_count;
  register long a3 __asm__("a3") = reinterpret_cast<long>(cpus);
  register long a4 __asm__("a4") = flags;
  register long a7 __asm__("a7") = __NR_riscv_hwprobe;
  __asm__ volatile("ecall" : "=r"(a0) : "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a7));
  return -a0;
}
#endif

void __libc_init_vdso(libc_globals* globals) {
  auto&& vdso = globals->vdso;
  vdso[VDSO_CLOCK_GETTIME] = {VDSO_CLOCK_GETTIME_SYMBOL, nullptr};
  vdso[VDSO_CLOCK_GETRES] = {VDSO_CLOCK_GETRES_SYMBOL, nullptr};
  vdso[VDSO_GETTIMEOFDAY] = {VDSO_GETTIMEOFDAY_SYMBOL, nullptr};
#if defined(VDSO_TIME_SYMBOL)
  vdso[VDSO_TIME] = {VDSO_TIME_SYMBOL, nullptr};
#endif
#if defined(VDSO_RISCV_HWPROBE_SYMBOL)
  vdso[VDSO_RISCV_HWPROBE] = {VDSO_RISCV_HWPROBE_SYMBOL, nullptr};
#endif

  // Do we have a vdso?
  uintptr_t vdso_ehdr_addr = getauxval(AT_SYSINFO_EHDR);
  ElfW(Ehdr)* vdso_ehdr = reinterpret_cast<ElfW(Ehdr)*>(vdso_ehdr_addr);
  if (vdso_ehdr == nullptr) {
    return;
  }

  // How many symbols does it have?
  size_t symbol_count = 0;
  ElfW(Shdr)* vdso_shdr = reinterpret_cast<ElfW(Shdr)*>(vdso_ehdr_addr + vdso_ehdr->e_shoff);
  for (size_t i = 0; i < vdso_ehdr->e_shnum; ++i) {
    if (vdso_shdr[i].sh_type == SHT_DYNSYM) {
      symbol_count = vdso_shdr[i].sh_size / sizeof(ElfW(Sym));
      break;
    }
  }
  if (symbol_count == 0) {
    return;
  }

  // Where's the dynamic table?
  ElfW(Addr) vdso_addr = 0;
  ElfW(Dyn)* vdso_dyn = nullptr;
  ElfW(Phdr)* vdso_phdr = reinterpret_cast<ElfW(Phdr)*>(vdso_ehdr_addr + vdso_ehdr->e_phoff);
  for (size_t i = 0; i < vdso_ehdr->e_phnum; ++i) {
    if (vdso_phdr[i].p_type == PT_DYNAMIC) {
      vdso_dyn = reinterpret_cast<ElfW(Dyn)*>(vdso_ehdr_addr + vdso_phdr[i].p_offset);
    } else if (vdso_phdr[i].p_type == PT_LOAD) {
      vdso_addr = vdso_ehdr_addr + vdso_phdr[i].p_offset - vdso_phdr[i].p_vaddr;
    }
    if (vdso_addr && vdso_dyn) break;
  }
  if (vdso_addr == 0 || vdso_dyn == nullptr) {
    return;
  }

  // Where are the string and symbol tables?
  const char* strtab = nullptr;
  ElfW(Sym)* symtab = nullptr;
  for (ElfW(Dyn)* d = vdso_dyn; d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_STRTAB) {
      strtab = reinterpret_cast<const char*>(vdso_addr + d->d_un.d_ptr);
    } else if (d->d_tag == DT_SYMTAB) {
      symtab = reinterpret_cast<ElfW(Sym)*>(vdso_addr + d->d_un.d_ptr);
    }
    if (strtab && symtab) break;
  }
  if (strtab == nullptr || symtab == nullptr) {
    return;
  }

  // Are there any symbols we want?
  for (size_t i = 0; i < VDSO_END; ++i) {
    for (size_t j = 0; j < symbol_count; ++j) {
      if (strcmp(vdso[i].name, strtab + symtab[j].st_name) == 0) {
        vdso[i].fn = reinterpret_cast<void*>(vdso_addr + symtab[j].st_value);
        break;
      }
    }
  }
}
```