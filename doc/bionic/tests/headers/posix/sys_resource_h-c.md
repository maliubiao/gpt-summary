Response:
Let's break down the thought process for answering the request about `sys_resource_h.c`.

**1. Understanding the Core Task:**

The fundamental goal is to analyze the provided C code snippet and explain its purpose and functionality within the context of Android's Bionic library. The prompt specifically requests information about:

* Functionality of the file.
* Relationship to Android.
* Detailed explanation of libc functions.
* Dynamic linker aspects.
* Logic inference (if any).
* Common user errors.
* How Android Framework/NDK reach this code.
* Frida hooking examples.

**2. Initial Analysis of the Code:**

The first step is to read the code carefully. The key observations are:

* **Header File Test:** The filename and the `header_checks.h` inclusion strongly suggest this is a test file designed to verify the presence and correctness of definitions within the `sys/resource.h` header file.
* **Macros:** The `MACRO()` calls are checking for the existence of preprocessor macros like `PRIO_PROCESS`, `RLIM_INFINITY`, `RUSAGE_SELF`, etc.
* **Types:** The `TYPE()` calls are verifying the existence of data types like `rlim_t`, `struct rlimit`, `struct rusage`, and `struct timeval`.
* **Structure Members:** `STRUCT_MEMBER()` confirms the presence of specific members within the defined structs.
* **Functions:** `FUNCTION()` verifies the existence of function prototypes (specifically their return types and argument types).

**3. Determining the Functionality:**

Based on the observations above, the primary function of this file is **to test the `sys/resource.h` header file**. It doesn't *implement* the functions defined in the header; it merely checks that the header defines them correctly.

**4. Connecting to Android:**

Since this is a test within Bionic (Android's C library), it's directly related to ensuring the correct behavior of system-level functionality within Android. The `sys/resource.h` header provides interfaces for managing system resources for processes, which is a fundamental part of operating system functionality and therefore crucial for Android.

**5. Explaining Libc Functions (and Recognizing the Trap):**

The prompt asks for detailed explanations of *each libc function's implementation*. However, the crucial realization is that *this file doesn't implement any libc functions*. It only *checks for their declaration*. The correct approach is to explain what these functions *do* conceptually, without diving into their actual Bionic implementation (which isn't in this file). This involves describing the purpose of `getpriority`, `setpriority`, `getrlimit`, `setrlimit`, and `getrusage`.

**6. Dynamic Linker Aspects:**

The prompt specifically asks about dynamic linking. While `sys/resource.h` doesn't *directly* involve dynamic linking in the same way as functions defined in `.so` files, the functions *declared* here are part of the C library, which *is* dynamically linked. Therefore, the explanation should focus on:

* The role of `libc.so` and its layout (showing how the declared functions would be part of it).
* The dynamic linker's job of resolving these function calls at runtime.
* A simple example of how a program would link against `libc.so`.

**7. Logic Inference, Assumptions, and Examples:**

Since the code is primarily for testing, there isn't much complex logic inference to be done. However, we can infer:

* **Assumption:** The test assumes the underlying system provides the resource management features defined in `sys/resource.h`.
* **Input/Output:** We can illustrate the *usage* of the functions with hypothetical inputs and outputs, even though the test file itself doesn't execute these functions. For example, showing how `getrlimit` might return the current and maximum file descriptor limits.

**8. Common User Errors:**

This section requires thinking about how developers might misuse the functions defined in `sys/resource.h`. Examples include:

* Setting limits too low, leading to program crashes.
* Not checking return values of these functions, potentially missing errors.
* Misunderstanding the scope of resource limits (e.g., per-process vs. system-wide).

**9. Android Framework/NDK Reachability and Frida Hooking:**

This requires understanding the Android software stack:

* **Framework:** High-level Java code interacts with native code through JNI. Framework components might need to manage resources.
* **NDK:**  Native developers can directly use the functions declared in `sys/resource.h`.
* **Reaching the Code:**  Explain the path from Java (e.g., `ProcessBuilder`) or native code to the Bionic implementation of these functions.

For Frida hooking, the key is to demonstrate how to intercept calls to the functions declared in `sys/resource.h` within a running Android process. Provide a concrete example using function addresses or function names.

**10. Structuring the Answer:**

Finally, organize the information logically, following the structure requested in the prompt. Use clear headings and bullet points to enhance readability. Ensure all parts of the prompt are addressed comprehensively.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Perhaps I should try to explain the internal implementation details of `getrlimit`.
* **Correction:**  Realize that the provided file is just a header test, so focusing on implementation details is incorrect. Shift the focus to the *purpose* and *usage* of these functions.
* **Initial Thought:** Should I generate complex C code examples?
* **Correction:** Keep the examples concise and focused on illustrating the concepts. No need for a full application demonstrating resource management.
* **Initial Thought:** Is dynamic linking directly exercised by this test file?
* **Correction:**  Recognize that while the *test file* doesn't dynamically link, the *functions being tested* are part of the dynamically linked `libc.so`. Adjust the explanation accordingly.

By following this structured thought process, carefully analyzing the code, and addressing each part of the prompt, a comprehensive and accurate answer can be generated.
好的，让我们来详细分析一下 `bionic/tests/headers/posix/sys_resource_h.c` 这个文件的功能以及它在 Android Bionic 中的作用。

**文件功能概述**

这个 C 源文件的主要功能是**测试** `sys/resource.h` 这个头文件是否正确定义了相关的宏、类型、结构体及其成员、以及函数原型。它本身并不实现任何 `sys/resource.h` 中声明的功能，而是通过一系列的宏 (`MACRO`, `TYPE`, `STRUCT_MEMBER`, `FUNCTION`) 来检查这些定义是否存在且类型正确。

**与 Android 功能的关系**

`sys/resource.h` 定义了用于查询和设置进程资源限制的接口。这些资源包括 CPU 时间、内存使用、打开的文件描述符数量等等。Android 系统，作为一种基于 Linux 内核的操作系统，同样需要管理进程的资源使用，以保证系统的稳定性和公平性。

以下是一些 `sys/resource.h` 中定义的功能与 Android 相关的例子：

* **限制 CPU 时间 (RLIMIT_CPU):** Android 系统可以使用此功能来限制某个进程可以使用的 CPU 时间，防止恶意程序无限占用 CPU 资源，导致系统无响应。例如，当一个应用在后台进行计算密集型任务时，系统可能会限制其 CPU 使用时间。
* **限制文件大小 (RLIMIT_FSIZE):**  应用程序尝试写入超过限制大小的文件时，内核会发送一个信号 (SIGXFSZ) 给该进程。这可以防止应用程序意外地占用大量的存储空间。
* **限制打开的文件描述符数量 (RLIMIT_NOFILE):** 每个进程可以打开的文件描述符数量是有限的。限制这个数量可以防止某些程序耗尽系统资源，影响其他程序的运行。Android 系统会为每个应用设置一个合理的文件描述符限制。
* **限制虚拟内存大小 (RLIMIT_AS):**  限制进程可以使用的虚拟内存大小，防止内存泄漏或者恶意程序过度分配内存导致系统崩溃。Android 的 Dalvik/ART 虚拟机在运行时也受到内存限制的影响。
* **获取资源使用情况 (getrusage):** 可以获取进程及其子进程的资源使用统计信息，例如用户态 CPU 时间 (ru_utime)、内核态 CPU 时间 (ru_stime) 等。Android 系统可以使用这些信息来监控应用的资源使用情况，进行性能分析和优化。

**libc 函数的功能实现**

`bionic/tests/headers/posix/sys_resource_h.c` 文件本身**不实现** `libc` 函数。它只是检查 `sys/resource.h` 中声明的函数原型是否正确。这些函数的实际实现在 Bionic 的其他源文件中。

下面简单解释一下 `sys/resource.h` 中声明的几个 libc 函数的功能：

* **`getpriority(int which, id_t who)`:**
    * **功能:** 获取指定进程、进程组或用户的调度优先级。
    * **参数:**
        * `which`: 指定要获取优先级的目标类型，可以是 `PRIO_PROCESS` (进程), `PRIO_PGRP` (进程组), 或 `PRIO_USER` (用户)。
        * `who`: 指定目标的 ID。如果 `which` 是 `PRIO_PROCESS`，则 `who` 是进程 ID (PID)；如果 `which` 是 `PRIO_PGRP`，则 `who` 是进程组 ID (PGID)；如果 `which` 是 `PRIO_USER`，则 `who` 是用户 ID (UID)。
    * **返回值:** 成功时返回进程、进程组或用户的当前优先级（值越小优先级越高，通常在 -20 到 19 之间），失败时返回 -1 并设置 `errno`。
    * **实现 (Bionic 中):**  Bionic 的 `getpriority` 通常会通过系统调用与内核交互，获取内核中维护的进程调度信息。

* **`getrlimit(int resource, struct rlimit *rlp)`:**
    * **功能:** 获取指定资源的当前软限制和硬限制。
    * **参数:**
        * `resource`: 指定要获取限制的资源类型，例如 `RLIMIT_CPU`, `RLIMIT_NOFILE` 等。
        * `rlp`: 指向 `struct rlimit` 结构体的指针，用于存储获取到的限制值。
    * **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。
    * **实现 (Bionic 中):**  Bionic 的 `getrlimit` 通常会发起一个系统调用（例如 `prlimit64`）到内核，内核会返回相应的资源限制信息。

* **`getrusage(int who, struct rusage *usage)`:**
    * **功能:** 获取指定目标（当前进程或其子进程）的资源使用情况统计信息。
    * **参数:**
        * `who`: 指定要获取统计信息的目标，可以是 `RUSAGE_SELF` (当前进程) 或 `RUSAGE_CHILDREN` (已终止的子进程)。
        * `usage`: 指向 `struct rusage` 结构体的指针，用于存储获取到的资源使用情况。
    * **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。
    * **实现 (Bionic 中):** Bionic 的 `getrusage` 也会通过系统调用（例如 `getrusage` 或 `getrusage_ext`）与内核交互，获取内核维护的进程资源使用统计数据。

* **`setpriority(int which, id_t who, int prio)`:**
    * **功能:** 设置指定进程、进程组或用户的调度优先级。
    * **参数:**
        * `which`: 指定要设置优先级的目标类型，同 `getpriority`。
        * `who`: 指定目标的 ID，同 `getpriority`。
        * `prio`: 要设置的优先级，值越小优先级越高。
    * **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。
    * **实现 (Bionic 中):** Bionic 的 `setpriority` 通常会发起一个系统调用（例如 `setpriority`）到内核，内核会更新相应进程或进程组的调度优先级。需要注意的是，普通用户通常只能降低自己的优先级。

* **`setrlimit(int resource, const struct rlimit *rlim)`:**
    * **功能:** 设置指定资源的软限制和硬限制。
    * **参数:**
        * `resource`: 指定要设置限制的资源类型，例如 `RLIMIT_CPU`, `RLIMIT_NOFILE` 等。
        * `rlim`: 指向包含要设置的软限制和硬限制值的 `struct rlimit` 结构体的指针。
    * **返回值:** 成功时返回 0，失败时返回 -1 并设置 `errno`。
    * **实现 (Bionic 中):** Bionic 的 `setrlimit` 通常会发起一个系统调用（例如 `prlimit64`）到内核，内核会根据提供的 `rlimit` 结构体设置相应的资源限制。需要注意的是，软限制可以被进程在硬限制范围内调整，而硬限制只能由特权进程（通常是 root）设置。

**动态链接器功能**

虽然 `sys_resource_h.c` 文件本身不涉及动态链接的实现，但其中声明的函数 (`getpriority`, `getrlimit`, `getrusage`, `setpriority`, `setrlimit`) 都是标准 C 库 (`libc.so`) 的一部分，并通过动态链接的方式被应用程序使用。

**so 布局样本:**

一个典型的 Android 应用程序会链接到 `libc.so`。`libc.so` 的布局会包含这些函数的代码段：

```
libc.so
├── .text        // 代码段
│   ├── getpriority
│   ├── getrlimit
│   ├── getrusage
│   ├── setpriority
│   ├── setrlimit
│   └── ...      // 其他 libc 函数
├── .data        // 已初始化数据段
├── .bss         // 未初始化数据段
├── .rodata      // 只读数据段
├── .dynsym      // 动态符号表
├── .dynstr      // 动态字符串表
├── .rel.dyn     // 重定位表（动态链接）
└── ...
```

**链接的处理过程:**

1. **编译时:** 编译器在编译应用程序时，如果遇到对 `getpriority` 等函数的调用，会在生成的目标文件中记录对这些外部符号的引用。
2. **链接时:**  链接器（在 Android 上通常是 `lld`）会将应用程序的目标文件与所需的共享库 (`libc.so`) 链接在一起。链接器会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `getpriority` 等符号的地址。
3. **运行时:** 当应用程序启动时，Android 的动态链接器 (`linker64` 或 `linker`) 会负责将应用程序加载到内存，并解析其依赖的共享库。
4. **符号解析:** 动态链接器会遍历应用程序的重定位表 (`.rel.dyn`)，找到对 `getpriority` 等外部符号的引用。然后，它会查找 `libc.so` 在内存中的基地址，并加上之前找到的符号偏移量，从而得到 `getpriority` 函数在内存中的实际地址。
5. **代码执行:** 当应用程序执行到调用 `getpriority` 的代码时，程序会跳转到动态链接器解析出的 `getpriority` 函数的内存地址执行。

**逻辑推理 (假设输入与输出)**

由于 `sys_resource_h.c` 是一个测试文件，它本身不进行逻辑推理。但我们可以假设一些输入和输出，来说明这些函数的使用：

**假设 `getrlimit`:**

* **假设输入:** `resource = RLIMIT_NOFILE`, `rlp` 指向一个未初始化的 `struct rlimit` 结构体。
* **预期输出:** 函数返回 0 (成功)，`rlp->rlim_cur` 包含当前进程打开文件描述符的软限制，`rlp->rlim_max` 包含硬限制。例如，`rlp->rlim_cur` 可能为 1024，`rlp->rlim_max` 可能为 4096。

**假设 `setrlimit`:**

* **假设输入:** `resource = RLIMIT_NOFILE`, `rlim->rlim_cur = 2048`, `rlim->rlim_max = 4096` (假设当前进程有权限设置此限制)。
* **预期输出:** 函数返回 0 (成功)，当前进程打开文件描述符的软限制被设置为 2048。

**假设 `getrusage`:**

* **假设输入:** `who = RUSAGE_SELF`, `usage` 指向一个未初始化的 `struct rusage` 结构体。
* **预期输出:** 函数返回 0 (成功)，`usage` 结构体中包含了当前进程的资源使用统计信息，例如 `usage->ru_utime` 表示用户态 CPU 时间，`usage->ru_stime` 表示内核态 CPU 时间，等等。

**用户或编程常见的使用错误**

* **不检查返回值:**  调用 `getrlimit`, `setrlimit`, `getpriority`, `setpriority`, `getrusage` 等函数后，没有检查返回值是否为 0，从而忽略了可能发生的错误。例如，`setrlimit` 可能会因为权限不足或参数错误而失败。
* **设置超出硬限制的软限制:**  尝试使用 `setrlimit` 设置的软限制值大于硬限制值，会导致函数调用失败。
* **权限不足:**  尝试设置某些资源限制（特别是硬限制）时，如果当前进程没有足够的权限（例如不是 root 用户），则会失败。
* **误解资源限制的作用域:**  例如，以为修改了某个进程组的资源限制会影响到所有用户创建的进程。
* **在多线程程序中不正确地使用 `getrusage`:**  当 `who` 参数为 `RUSAGE_CHILDREN` 时，只会统计已终止的子进程的资源使用情况，对于仍在运行的子进程，需要进行额外的处理。
* **内存错误:** 传递给 `getrlimit` 或 `getrusage` 的 `struct rlimit` 或 `struct rusage` 指针是无效的（例如空指针或未分配内存）。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 代码):**
   * Android Framework 中的某些组件，例如 `ProcessBuilder` 或 `Runtime.exec()`, 最终会通过 JNI 调用到 Native 层。
   * 在 Native 层，可能会调用 Bionic 提供的与进程管理相关的函数，这些函数可能会间接地使用到 `getrlimit`, `setrlimit` 等。例如，`ProcessBuilder` 在创建新进程时，可能会设置一些资源限制。
   * **示例:**  Java 代码使用 `ProcessBuilder` 启动一个新进程，并设置其工作目录：
     ```java
     ProcessBuilder pb = new ProcessBuilder("/system/bin/ls", "-l");
     pb.directory(new File("/sdcard"));
     Process process = pb.start();
     ```
     在 `ProcessBuilder.start()` 的底层实现中，可能会调用到 Native 层创建进程的相关函数，这些函数可能会使用到 `setrlimit` 来设置新进程的资源限制。

2. **Android NDK (C/C++ 代码):**
   * 使用 NDK 开发的 Native 代码可以直接调用 Bionic 提供的标准 C 库函数，包括 `sys/resource.h` 中声明的函数。
   * **示例:** 一个使用 NDK 开发的应用可能需要获取当前进程的打开文件描述符限制：
     ```c++
     #include <sys/resource.h>
     #include <stdio.h>

     int main() {
       struct rlimit rl;
       if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
         printf("Current soft limit for open files: %lld\n", (long long)rl.rlim_cur);
         printf("Current hard limit for open files: %lld\n", (long long)rl.rlim_max);
       } else {
         perror("getrlimit failed");
       }
       return 0;
     }
     ```

**Frida Hook 示例调试这些步骤**

可以使用 Frida 来 hook 这些函数，观察它们的调用情况和参数。以下是一些 Frida hook 示例：

**Hook `getrlimit`:**

```javascript
if (Process.platform === 'android') {
  const getrlimitPtr = Module.findExportByName("libc.so", "getrlimit");
  if (getrlimitPtr) {
    Interceptor.attach(getrlimitPtr, {
      onEnter: function (args) {
        const resource = args[0].toInt32();
        const resourceName = {
          0: "RLIMIT_CPU",
          1: "RLIMIT_FSIZE",
          2: "RLIMIT_DATA",
          3: "RLIMIT_STACK",
          4: "RLIMIT_CORE",
          6: "RLIMIT_NOFILE",
          7: "RLIMIT_AS"
          // ... 其他 RLIMIT 常量
        }[resource] || resource;
        console.log(`[+] Calling getrlimit(${resourceName}, ${args[1]})`);
      },
      onLeave: function (retval) {
        if (retval.toInt32() === 0) {
          const rlimitPtr = this.context.r1; // 假设第二个参数通过 r1 寄存器传递
          const rlim_cur = Memory.readU64(rlimitPtr);
          const rlim_max = Memory.readU64(rlimitPtr.add(8));
          console.log(`[+] getrlimit returned 0, rlim_cur=${rlim_cur}, rlim_max=${rlim_max}`);
        } else {
          console.log(`[!] getrlimit failed with code ${retval}`);
        }
      }
    });
  } else {
    console.log("[-] getrlimit not found in libc.so");
  }
}
```

**Hook `setrlimit`:**

```javascript
if (Process.platform === 'android') {
  const setrlimitPtr = Module.findExportByName("libc.so", "setrlimit");
  if (setrlimitPtr) {
    Interceptor.attach(setrlimitPtr, {
      onEnter: function (args) {
        const resource = args[0].toInt32();
        const resourceName = {
          0: "RLIMIT_CPU",
          1: "RLIMIT_FSIZE",
          2: "RLIMIT_DATA",
          3: "RLIMIT_STACK",
          4: "RLIMIT_CORE",
          6: "RLIMIT_NOFILE",
          7: "RLIMIT_AS"
          // ... 其他 RLIMIT 常量
        }[resource] || resource;
        const rlimitPtr = args[1];
        const rlim_cur = Memory.readU64(rlimitPtr);
        const rlim_max = Memory.readU64(rlimitPtr.add(8));
        console.log(`[+] Calling setrlimit(${resourceName}, { rlim_cur: ${rlim_cur}, rlim_max: ${rlim_max} })`);
      },
      onLeave: function (retval) {
        console.log(`[+] setrlimit returned ${retval}`);
      }
    });
  } else {
    console.log("[-] setrlimit not found in libc.so");
  }
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_rlimit.js`）。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_rlimit.js --no-pause
   ```
   或者，如果进程已经在运行：
   ```bash
   frida -U <package_name> -l hook_rlimit.js
   ```
3. 当目标进程调用 `getrlimit` 或 `setrlimit` 时，Frida 会打印出相应的日志信息，包括参数和返回值。

希望以上详细的解释能够帮助你理解 `bionic/tests/headers/posix/sys_resource_h.c` 文件的作用以及 `sys/resource.h` 中相关功能在 Android 系统中的应用。

Prompt: 
```
这是目录为bionic/tests/headers/posix/sys_resource_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <sys/resource.h>

#include "header_checks.h"

static void sys_resource_h() {
  MACRO(PRIO_PROCESS);
  MACRO(PRIO_PGRP);
  MACRO(PRIO_USER);

  TYPE(rlim_t);

  MACRO(RLIM_INFINITY);
  MACRO(RLIM_SAVED_MAX);
  MACRO(RLIM_SAVED_CUR);

  MACRO(RUSAGE_SELF);
  MACRO(RUSAGE_CHILDREN);

  TYPE(struct rlimit);
  STRUCT_MEMBER(struct rlimit, rlim_t, rlim_cur);
  STRUCT_MEMBER(struct rlimit, rlim_t, rlim_max);

  TYPE(struct rusage);
  STRUCT_MEMBER(struct rusage, struct timeval, ru_utime);
  STRUCT_MEMBER(struct rusage, struct timeval, ru_stime);

  TYPE(struct timeval);

  MACRO(RLIMIT_CORE);
  MACRO(RLIMIT_CPU);
  MACRO(RLIMIT_DATA);
  MACRO(RLIMIT_FSIZE);
  MACRO(RLIMIT_NOFILE);
  MACRO(RLIMIT_STACK);
  MACRO(RLIMIT_AS);

  FUNCTION(getpriority, int (*f)(int, id_t));
  FUNCTION(getrlimit, int (*f)(int, struct rlimit*));
  FUNCTION(getrusage, int (*f)(int, struct rusage*));
  FUNCTION(setpriority, int (*f)(int, id_t, int));
  FUNCTION(setrlimit, int (*f)(int, const struct rlimit*));
}

"""

```