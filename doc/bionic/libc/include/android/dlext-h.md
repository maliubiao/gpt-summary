Response:
Let's break down the thought process to generate the detailed answer about `android/dlext.handroid`.

**1. Understanding the Core Request:**

The central request is to explain the functionality of the `android/dlext.handroid` header file within the Android Bionic library. This immediately signals that the focus should be on advanced dynamic linking capabilities beyond the standard `dlopen`. The prompt specifically asks for:

* **Functionality Listing:** What does this file *do*?
* **Android Relationship:** How does it tie into broader Android functionality?
* **`libc` Function Details:** Explanation of each function's implementation (though there's only one declared, `android_dlopen_ext`).
* **Dynamic Linker Aspects:**  Details on SO layouts and linking processes related to this file's features.
* **Logic & Examples:** Hypothetical inputs/outputs.
* **Common Errors:** How might users misuse these features?
* **Android Framework/NDK Path:** How does the system reach this code?
* **Frida Hooking:** Examples of using Frida for debugging.

**2. Initial Analysis of the Header File:**

The first step is to carefully read the header file itself. Key observations include:

* **Copyright & License:** Standard boilerplate.
* **`#pragma once`:**  Ensures the header is included only once.
* **Includes:** `sys/cdefs.h`, `stdbool.h`, `stddef.h`, `stdint.h`, `sys/types.h`. These indicate basic C types and definitions are used.
* **`@addtogroup libdl`:** This strongly indicates the file relates to the dynamic linker.
* **File Description:** Explicitly mentions "Advanced dynamic library opening support" and advises users to typically use standard `dlopen`. This is a crucial clue about the file's purpose.
* **`enum` for Flags:** A set of `ANDROID_DLEXT_` flags defines various advanced loading options. This is the core of the file's functionality. Each flag needs to be understood.
* **`struct android_namespace_t`:** Forward declaration suggesting the concept of namespaces is involved.
* **`struct android_dlextinfo`:**  A structure holding the flag bitmask and associated data. This is the main way to interact with the advanced features.
* **`android_dlopen_ext` Function:** The primary (and only declared) function, accepting the standard `dlopen` parameters plus the `android_dlextinfo` structure.

**3. Deconstructing the Flags (Key Functionality):**

The core functionality revolves around the `ANDROID_DLEXT_` flags. I mentally (or literally) create a list and try to understand the purpose of each:

* **`RESERVED_ADDRESS` and `RESERVED_ADDRESS_HINT`:**  Controlling load address. One is mandatory, the other is a suggestion. This is about memory management and potentially avoiding conflicts.
* **`WRITE_RELRO` and `USE_RELRO`:**  Relocation Read-Only. Related to security and sharing of relocated libraries, particularly for WebView. I need to remember what RELRO is and its benefits.
* **`USE_LIBRARY_FD` and `USE_LIBRARY_FD_OFFSET`:** Loading from a file descriptor and a specific offset. This allows loading from memory or embedded files (like within ZIPs).
* **`FORCE_LOAD`:**  Circumventing the "already loaded" check. Useful for replacing libraries with the same name.
* **`USE_NAMESPACE`:**  Loading into a specific namespace. This is for isolation and internal use.
* **`RESERVED_ADDRESS_RECURSIVE`:**  Applying the address reservation to dependencies. Complex and powerful, likely also related to WebView or specific performance needs.

**4. Connecting to Android Functionality:**

As I understand the flags, I start thinking about how these advanced features are used in Android:

* **WebView:** The comments explicitly mention WebView for RELRO and recursive address reservation. This becomes a key example.
* **Namespaces:**  Android uses namespaces for isolating applications and system components. This flag directly relates to that.
* **App Loading:** While standard apps use `dlopen`, the system likely uses `android_dlopen_ext` internally for more control.
* **System Updates/Overrides:**  `FORCE_LOAD` could be relevant here.

**5. Explaining `android_dlopen_ext`:**

Since this is the only declared function, the explanation focuses on how it extends the standard `dlopen` by incorporating the `android_dlextinfo` structure. I emphasize that it provides more fine-grained control over library loading.

**6. Dynamic Linker Details (SO Layout and Linking):**

This requires some background knowledge of ELF files and dynamic linking:

* **SO Layout:** I describe the common sections (`.text`, `.data`, `.bss`, `.plt`, `.got`, `.rel.dyn`, `.rel.plt`, `.dynamic`).
* **Linking Process:** I outline the steps: symbol resolution, relocation, and initialization.
* **How `android_dlextinfo` Impacts Linking:**  I explain how the flags (especially address reservation and RELRO) influence these stages.

**7. Hypothetical Inputs and Outputs:**

For each flag (or a combination), I consider a plausible scenario and the expected outcome. This helps illustrate the practical effect of the flags.

**8. Common User Errors:**

I think about how developers might misuse these advanced features:

* **Incorrect Flag Combinations:** Setting conflicting flags.
* **Memory Management Errors:** Incorrectly specifying reserved addresses or sizes.
* **File Descriptor Issues:**  Using invalid or closed file descriptors.
* **Namespace Confusion:**  Misunderstanding namespace implications.

**9. Android Framework/NDK Path:**

This involves tracing the call stack:

* **NDK:**  While there's no direct NDK API,  internal Android components use it.
* **Framework:**  System services (like `zygote`, `app_process`) and components like WebView are key users. `System.loadLibrary` in Java is a starting point. I describe the layers involved: Java, native code, and finally the dynamic linker.

**10. Frida Hooking:**

I provide examples of how to hook `android_dlopen_ext` using Frida, showing how to intercept calls, examine arguments, and modify behavior.

**11. Structuring the Answer:**

Finally, I organize the information logically with clear headings and explanations, ensuring all aspects of the prompt are addressed. I use bolding and formatting to improve readability.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus too much on the standard `dlopen`. **Correction:** Shift focus to the *advanced* capabilities of `android_dlopen_ext`.
* **Overlooking specific flags:**  Might initially miss the nuances of a less common flag. **Correction:** Go back and re-read the flag descriptions carefully.
* **Not enough concrete examples:**  Generic explanations are less helpful. **Correction:**  Develop specific scenarios for each flag or feature.
* **Forgetting the "why":** Explain *why* these features exist (e.g., security with RELRO, performance with address reservation).

By following this structured thought process, combining careful reading with background knowledge and anticipating the user's needs, I can generate a comprehensive and accurate answer.
这是一个位于 `bionic/libc/include/android/dlext.handroid` 的头文件，属于 Android 的 Bionic C 库，专门用于扩展动态链接器的功能。它定义了一些用于高级动态库加载的接口，允许开发者在加载动态库时进行更细粒度的控制。

**功能列举:**

该文件主要定义了一个结构体 `android_dlextinfo` 和一个函数 `android_dlopen_ext`，用于扩展标准的 `dlopen` 函数的功能。其主要功能可以归纳为以下几点：

1. **指定加载地址:**  允许指定动态库加载的内存地址（强制或提示）。
2. **RELRO 控制:**  支持读写 GNU RELRO（Relocation Read-Only）段，用于提高安全性和在不同进程间共享。
3. **使用文件描述符加载:**  允许通过已打开的文件描述符加载动态库，而不是文件名。
4. **指定文件描述符偏移:**  在使用文件描述符加载时，可以指定起始读取的偏移量。
5. **强制加载:**  允许强制加载库，即使同名库已经加载。
6. **指定命名空间:**  允许将动态库加载到特定的命名空间（主要为内部使用）。
7. **递归应用加载选项:**  可以将某些加载选项递归地应用于当前加载库的依赖库。

**与 Android 功能的关系及举例说明:**

这些扩展功能与 Android 的多个方面息息相关：

1. **性能优化:** 通过指定加载地址 (`ANDROID_DLEXT_RESERVED_ADDRESS`, `ANDROID_DLEXT_RESERVED_ADDRESS_HINT`)，可以尝试将多个库加载到连续的内存区域，减少内存碎片，提高缓存命中率。例如，Android 系统可能会在启动时使用此功能加载关键系统库。

2. **安全性提升:** RELRO 机制通过将重定位后的内存区域设置为只读，可以防止某些类型的内存篡改攻击。`ANDROID_DLEXT_WRITE_RELRO` 和 `ANDROID_DLEXT_USE_RELRO` 用于支持更细致的 RELRO 管理，例如，WebView 可能会使用这些功能来共享和验证已加载库的 RELRO 段。

3. **模块化和隔离:** 命名空间 (`ANDROID_DLEXT_USE_NAMESPACE`) 用于隔离不同的库，避免符号冲突，增强系统的模块化。Android 系统在管理不同应用程序的库加载时会使用命名空间。

4. **灵活的库加载方式:**  使用文件描述符加载 (`ANDROID_DLEXT_USE_LIBRARY_FD`) 和指定偏移 (`ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET`) 允许从内存映射的文件或其他特殊来源加载库，这对于 APK 内的未压缩库或其他特殊场景非常有用。

5. **系统更新和替换:** `ANDROID_DLEXT_FORCE_LOAD` 可以在某些情况下强制加载新的库版本，即使旧版本已加载，这可能用于系统更新或修复。

**libc 函数功能实现详解:**

这里主要涉及一个非标准的 libc 函数 `android_dlopen_ext`。它的实现并非简单的 libc 调用，而是 Bionic 动态链接器 (`linker`) 的一部分。

`android_dlopen_ext(const char* __filename, int __flags, const android_dlextinfo* __info)`:

* **功能:**  该函数类似于标准的 `dlopen`，但增加了通过 `__info` 参数传递 Android 特定的扩展选项。
* **实现逻辑:**
    1. **参数校验:** 检查传入的 `__flags` 和 `__info->flags` 是否合法，例如，检查互斥的标志位是否同时设置。
    2. **处理扩展选项:**  根据 `__info->flags` 中的设置，执行相应的操作：
        * **地址预留:** 如果设置了 `ANDROID_DLEXT_RESERVED_ADDRESS` 或 `ANDROID_DLEXT_RESERVED_ADDRESS_HINT`，linker 会尝试在指定的地址加载库。这涉及到内存管理和地址空间的分配。
        * **RELRO 处理:** 如果设置了 `ANDROID_DLEXT_WRITE_RELRO` 或 `ANDROID_DLEXT_USE_RELRO`，linker 会在完成库的重定位后，将 RELRO 段写入到指定的文件描述符或与指定文件描述符的内容进行比较。这需要访问库的内存布局和文件内容。
        * **文件描述符加载:** 如果设置了 `ANDROID_DLEXT_USE_LIBRARY_FD`，linker 不会通过文件名打开文件，而是使用提供的文件描述符。如果同时设置了 `ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET`，则从指定的偏移开始读取。这需要使用文件 I/O 系统调用（如 `lseek`, `read`）来读取 ELF 文件头和段信息。
        * **强制加载:** 如果设置了 `ANDROID_DLEXT_FORCE_LOAD`，linker 会跳过已加载库的检查，强制执行加载流程。这需要修改 linker 内部的库管理数据结构。
        * **命名空间处理:** 如果设置了 `ANDROID_DLEXT_USE_NAMESPACE`，linker 会将库加载到指定的命名空间中，这涉及到 linker 的命名空间管理机制。
        * **递归加载选项:** 如果设置了 `ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE`，linker 在加载当前库的依赖库时，会递归地应用地址预留和 RELRO 相关的选项。这需要在加载依赖库时传递相应的标志和信息。
    3. **标准 `dlopen` 流程:**  在处理完扩展选项后，`android_dlopen_ext` 会执行标准的动态链接和加载流程，包括：
        * **查找库:** 根据文件名或文件描述符查找 ELF 文件。
        * **解析 ELF 文件头:** 读取 ELF 头信息，确定库的类型、架构等。
        * **加载段:** 将 ELF 文件的各个段加载到内存中。
        * **符号解析和重定位:**  解析库的依赖关系，解析符号，并进行地址重定位。
        * **执行初始化代码:** 执行库的 `.init` 和 `.ctors` 段中的代码。
    4. **返回句柄:**  如果加载成功，返回指向加载的库的句柄；如果失败，返回 NULL 并设置错误信息（可以通过 `dlerror()` 获取）。

**涉及 dynamic linker 的功能、so 布局样本及链接处理过程:**

以下功能直接与 dynamic linker 相关：

* `ANDROID_DLEXT_RESERVED_ADDRESS` 和 `ANDROID_DLEXT_RESERVED_ADDRESS_HINT`: 影响库加载到内存的起始地址。
* `ANDROID_DLEXT_WRITE_RELRO` 和 `ANDROID_DLEXT_USE_RELRO`: 涉及到库加载后内存布局的修改和读取。
* `ANDROID_DLEXT_USE_NAMESPACE`: 涉及到 linker 的命名空间管理。
* `ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE`: 涉及到 linker 对依赖库的处理。

**SO 布局样本:**

一个典型的 SO (Shared Object) 文件的内存布局如下（简化）：

```
+-----------------+
|     .text       |  // 代码段
+-----------------+
|     .rodata     |  // 只读数据段
+-----------------+
|     .data       |  // 已初始化数据段
+-----------------+
|     .bss        |  // 未初始化数据段
+-----------------+
|     .plt        |  // Procedure Linkage Table，用于延迟绑定
+-----------------+
|     .got        |  // Global Offset Table，用于存储全局变量地址
+-----------------+
|   .rel.dyn      |  // 动态重定位表，用于数据段的重定位
+-----------------+
|   .rel.plt      |  // 动态重定位表，用于函数调用的重定位
+-----------------+
|    .dynamic     |  // 动态链接信息段
+-----------------+
```

**链接处理过程:**

1. **加载:** Dynamic linker 根据 `dlopen` 或 `android_dlopen_ext` 的请求，将 SO 文件加载到内存中。如果指定了加载地址，linker 会尝试在指定地址分配内存。
2. **解析:** Linker 解析 SO 文件的 `.dynamic` 段，获取动态链接所需的各种信息，例如依赖库列表 (`DT_NEEDED`)、符号表 (`DT_SYMTAB`)、字符串表 (`DT_STRTAB`)、重定位表 (`DT_REL`, `DT_RELA`, `DT_JMPREL`) 等。
3. **依赖解析:** Linker 递归地加载当前 SO 文件依赖的其他 SO 文件。
4. **符号解析:** Linker 根据 SO 文件中的符号表和依赖库的符号表，解析未定义的符号。这包括查找函数和全局变量的地址。
5. **重定位:** Linker 根据重定位表中的信息，修改 SO 文件中需要修正的地址。重定位分为两种主要类型：
    * **数据重定位:**  修正全局变量的地址。
    * **过程链接表 (PLT) 重定位:**  用于延迟绑定函数调用。当第一次调用一个外部函数时，会触发 PLT 中的代码，调用 linker 来解析函数地址并更新 GOT 表。
6. **RELRO 处理:**
    * **`ANDROID_DLEXT_WRITE_RELRO`:** 在重定位完成后，linker 将 RELRO 段（通常包含 GOT 表等）的内容写入到指定的文件描述符。
    * **`ANDROID_DLEXT_USE_RELRO`:** 在重定位完成后，linker 将当前加载库的 RELRO 段与指定文件描述符中的内容进行比较。如果相同，可以将这部分内存映射为只读，并可能与其他进程共享。
7. **初始化:** Linker 执行 SO 文件中的初始化代码，包括 `.init` 段中的代码和标记为 `__attribute__((constructor))` 的函数。

**假设输入与输出 (逻辑推理):**

假设我们有一个 SO 文件 `libtest.so`，我们想将其加载到特定的内存地址，并将其 RELRO 段保存到文件 `relro_data`。

**假设输入:**

```c
const char* filename = "libtest.so";
int flags = RTLD_NOW; // 立即解析所有符号
android_dlextinfo info = {
    .flags = ANDROID_DLEXT_RESERVED_ADDRESS | ANDROID_DLEXT_WRITE_RELRO,
    .reserved_addr = (void*)0x700000000000, // 假设的地址
    .reserved_size = 0x100000, // 假设的大小
    .relro_fd = open("relro_data", O_WRONLY | O_CREAT | O_TRUNC, 0644)
};

void* handle = android_dlopen_ext(filename, flags, &info);
```

**预期输出:**

* 如果加载成功，`handle` 将指向 `libtest.so` 的句柄。
* `libtest.so` 将被加载到以 `0x700000000000` 开始的内存区域（如果该区域可用且足够大）。
* `libtest.so` 的 RELRO 段的内容将被写入到 `relro_data` 文件中。
* 如果加载失败（例如，指定地址不可用或大小不足），`handle` 将为 `NULL`，并且可以通过 `dlerror()` 获取错误信息。

**用户或编程常见的使用错误:**

1. **地址冲突:** 使用 `ANDROID_DLEXT_RESERVED_ADDRESS` 指定的地址已被其他库占用，导致加载失败。
   ```c
   android_dlextinfo info = {
       .flags = ANDROID_DLEXT_RESERVED_ADDRESS,
       .reserved_addr = (void*)0x700000000000, // 该地址可能已被占用
       .reserved_size = 0x100000
   };
   void* handle = android_dlopen_ext("libtest.so", RTLD_NOW, &info);
   if (!handle) {
       fprintf(stderr, "加载失败: %s\n", dlerror()); // 可能提示地址冲突
   }
   ```

2. **RELRO 文件描述符无效:**  传递给 `relro_fd` 的文件描述符未打开或无法写入。
   ```c
   android_dlextinfo info = {
       .flags = ANDROID_DLEXT_WRITE_RELRO,
       .relro_fd = -1 // 无效的文件描述符
   };
   void* handle = android_dlopen_ext("libtest.so", RTLD_NOW, &info);
   if (!handle) {
       fprintf(stderr, "加载失败: %s\n", dlerror()); // 可能提示文件操作错误
   }
   ```

3. **标志位冲突:**  同时设置了互斥的标志位。
   ```c
   android_dlextinfo info = {
       .flags = ANDROID_DLEXT_RESERVED_ADDRESS | ANDROID_DLEXT_RESERVED_ADDRESS_HINT, // 冲突的标志位
       .reserved_addr = (void*)0x700000000000,
       .reserved_size = 0x100000
   };
   // 可能会导致未定义的行为或加载失败
   void* handle = android_dlopen_ext("libtest.so", RTLD_NOW, &info);
   ```

4. **`reserved_size` 不足:** 使用 `ANDROID_DLEXT_RESERVED_ADDRESS` 指定的内存区域大小不足以容纳整个库。
   ```c
   android_dlextinfo info = {
       .flags = ANDROID_DLEXT_RESERVED_ADDRESS,
       .reserved_addr = (void*)0x700000000000,
       .reserved_size = 0x1000 // 大小不足
   };
   void* handle = android_dlopen_ext("libtest.so", RTLD_NOW, &info);
   if (!handle) {
       fprintf(stderr, "加载失败: %s\n", dlerror()); // 可能提示内存不足
   }
   ```

**Android Framework 或 NDK 如何到达这里:**

虽然 NDK 公开的 API 通常是标准的 `dlopen`，但 Android Framework 内部的某些组件会使用 `android_dlopen_ext` 来进行更精细的库加载控制。

1. **Java Framework:**  在 Java 代码中，使用 `System.loadLibrary()` 或 `Runtime.loadLibrary()` 加载 native 库。
2. **Native Bridge:** 这些 Java 方法最终会调用 native 代码中的 `android_dlopen` 函数（注意不是 `android_dlopen_ext`，这是标准 `dlopen` 的 Android 版本）。
3. **Framework Native Libraries:** Android Framework 的某些 native 库，例如 WebView 的实现，可能会在内部使用 `android_dlopen_ext` 来加载其他模块，以便利用其高级功能。
4. **Zygote 进程:** Zygote 进程是 Android 应用进程的孵化器。它在启动时会预加载一些常用的系统库。在预加载这些库时，可能会使用 `android_dlopen_ext` 来指定加载地址或进行 RELRO 处理。
5. **系统服务:**  某些系统服务可能需要加载特定的 native 库，并且可能使用 `android_dlopen_ext` 来满足特定的加载需求。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `android_dlopen_ext` 函数来观察其调用和参数。

**Frida Hook 示例:**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'x64') {
  const android_dlopen_ext = Module.findExportByName(null, 'android_dlopen_ext');
  if (android_dlopen_ext) {
    Interceptor.attach(android_dlopen_ext, {
      onEnter: function (args) {
        const filename = args[0];
        const flags = args[1].toInt();
        const infoPtr = args[2];

        console.log('android_dlopen_ext called');
        if (filename) {
          console.log('  filename:', Memory.readUtf8String(filename));
        } else {
          console.log('  filename: null');
        }
        console.log('  flags:', flags);

        if (!infoPtr.isNull()) {
          const info = {
            flags: infoPtr.readU64(),
            reserved_addr: infoPtr.add(8).readPointer(),
            reserved_size: infoPtr.add(16).readU64(),
            relro_fd: infoPtr.add(24).readS32(),
            library_fd: infoPtr.add(28).readS32(),
            library_fd_offset: infoPtr.add(32).readU64(),
            library_namespace: infoPtr.add(40).readPointer()
          };
          console.log('  info:', info);
          if (info.flags & 0x1) {
            console.log('    ANDROID_DLEXT_RESERVED_ADDRESS is set');
          }
          if (info.flags & 0x2) {
            console.log('    ANDROID_DLEXT_RESERVED_ADDRESS_HINT is set');
          }
          // ... 可以根据需要打印其他标志位
        } else {
          console.log('  info: null');
        }
      },
      onLeave: function (retval) {
        console.log('android_dlopen_ext returned:', retval);
      }
    });
  } else {
    console.log('Failed to find android_dlopen_ext');
  }
} else {
  console.log('Unsupported architecture for this hook example.');
}
```

**调试步骤:**

1. **准备环境:** 确保已安装 Frida 和 Python 环境，并能够连接到目标 Android 设备或模拟器。
2. **编写 Frida 脚本:** 将上面的 JavaScript 代码保存到一个文件中，例如 `hook_dlopen_ext.js`。
3. **运行 Frida:** 使用 Frida 命令将脚本注入到目标进程中。例如，如果要 hook 一个名为 `com.example.myapp` 的应用，可以运行：
   ```bash
   frida -U -f com.example.myapp -l hook_dlopen_ext.js --no-pause
   ```
   或者，如果应用已经在运行，可以使用进程 ID：
   ```bash
   frida -U <进程ID> -l hook_dlopen_ext.js
   ```
4. **触发库加载:**  在目标应用中执行会导致调用 `android_dlopen_ext` 的操作，例如加载一个 native 库。
5. **查看 Frida 输出:** Frida 会在控制台上打印出 `android_dlopen_ext` 的调用信息，包括文件名、标志位和 `android_dlextinfo` 结构体的内容。

通过 Frida hook，可以详细观察 `android_dlopen_ext` 的调用时机、传递的参数，从而了解 Android Framework 或特定应用是如何使用这些高级动态链接功能的。

### 提示词
```
这是目录为bionic/libc/include/android/dlext.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```c
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

#pragma once

#include <sys/cdefs.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>  /* for off64_t */

/**
 * @addtogroup libdl Dynamic Linker
 * @{
 */

/**
 * \file
 * Advanced dynamic library opening support. Most users will want to use
 * the standard [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html)
 * functionality in `<dlfcn.h>` instead.
 */

__BEGIN_DECLS

/** Bitfield definitions for `android_dlextinfo::flags`. */
enum {
  /**
   * When set, the `reserved_addr` and `reserved_size` fields must point to an
   * already-reserved region of address space which will be used to load the
   * library if it fits.
   *
   * If the reserved region is not large enough, loading will fail.
   */
  ANDROID_DLEXT_RESERVED_ADDRESS      = 0x1,

  /**
   * Like `ANDROID_DLEXT_RESERVED_ADDRESS`, but if the reserved region is not large enough,
   * the linker will choose an available address instead.
   */
  ANDROID_DLEXT_RESERVED_ADDRESS_HINT = 0x2,

  /**
   * When set, write the GNU RELRO section of the mapped library to `relro_fd`
   * after relocation has been performed, to allow it to be reused by another
   * process loading the same library at the same address. This implies
   * `ANDROID_DLEXT_USE_RELRO`.
   *
   * This is mainly useful for the system WebView implementation.
   */
  ANDROID_DLEXT_WRITE_RELRO           = 0x4,

  /**
   * When set, compare the GNU RELRO section of the mapped library to `relro_fd`
   * after relocation has been performed, and replace any relocated pages that
   * are identical with a version mapped from the file.
   *
   * This is mainly useful for the system WebView implementation.
   */
  ANDROID_DLEXT_USE_RELRO             = 0x8,

  /**
   * Use `library_fd` instead of opening the file by name.
   * The filename parameter is still used to identify the library.
   */
  ANDROID_DLEXT_USE_LIBRARY_FD        = 0x10,

  /**
   * If opening a library using `library_fd` read it starting at `library_fd_offset`.
   * This is mainly useful for loading a library stored within another file (such as uncompressed
   * inside a ZIP archive).
   * This flag is only valid when `ANDROID_DLEXT_USE_LIBRARY_FD` is set.
   */
  ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET    = 0x20,

  /**
   * When set, do not use `stat(2)` to check if the library has already been loaded.
   *
   * This flag allows forced loading of the library in the case when for some
   * reason multiple ELF files share the same filename (because the already-loaded
   * library has been removed and overwritten, for example).
   *
   * Note that if the library has the same `DT_SONAME` as an old one and some other
   * library has the soname in its `DT_NEEDED` list, the first one will be used to resolve any
   * dependencies.
   */
  ANDROID_DLEXT_FORCE_LOAD = 0x40,

  // Historically we had two other options for ART.
  // They were last available in API level 28.
  // Reuse these bits last!
  // ANDROID_DLEXT_FORCE_FIXED_VADDR = 0x80
  // ANDROID_DLEXT_LOAD_AT_FIXED_ADDRESS = 0x100

  /**
   * This flag used to load library in a different namespace. The namespace is
   * specified in `library_namespace`.
   *
   * This flag is for internal use only (since there is no NDK API for namespaces).
   */
  ANDROID_DLEXT_USE_NAMESPACE = 0x200,

  /**
   * Instructs dlopen() to apply `ANDROID_DLEXT_RESERVED_ADDRESS`,
   * `ANDROID_DLEXT_RESERVED_ADDRESS_HINT`, `ANDROID_DLEXT_WRITE_RELRO` and
   * `ANDROID_DLEXT_USE_RELRO` to any libraries loaded as dependencies of the
   * main library as well.
   *
   * This means that if the main library depends on one or more not-already-loaded libraries, they
   * will be loaded consecutively into the region starting at `reserved_addr`, and `reserved_size`
   * must be large enough to contain all of the libraries. The libraries will be loaded in the
   * deterministic order constructed from the DT_NEEDED entries, rather than the more secure random
   * order used by default.
   *
   * Each library's GNU RELRO sections will be written out to `relro_fd` in the same order they were
   * loaded. This will mean that the resulting file is dependent on which of the libraries were
   * already loaded, as only the newly loaded libraries will be included, not any already-loaded
   * dependencies. The caller should ensure that the set of libraries newly loaded is consistent
   * for this to be effective.
   *
   * This is mainly useful for the system WebView implementation.
   */
  ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE = 0x400,


  /** Mask of valid bits. */
  ANDROID_DLEXT_VALID_FLAG_BITS       = ANDROID_DLEXT_RESERVED_ADDRESS |
                                        ANDROID_DLEXT_RESERVED_ADDRESS_HINT |
                                        ANDROID_DLEXT_WRITE_RELRO |
                                        ANDROID_DLEXT_USE_RELRO |
                                        ANDROID_DLEXT_USE_LIBRARY_FD |
                                        ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET |
                                        ANDROID_DLEXT_FORCE_LOAD |
                                        ANDROID_DLEXT_USE_NAMESPACE |
                                        ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE,
};

struct android_namespace_t;

/** Used to pass Android-specific arguments to android_dlopen_ext(). */
typedef struct {
  /** A bitmask of `ANDROID_DLEXT_` enum values. */
  uint64_t flags;

  /** Used by `ANDROID_DLEXT_RESERVED_ADDRESS` and `ANDROID_DLEXT_RESERVED_ADDRESS_HINT`. */
  void*   _Nullable reserved_addr;
  /** Used by `ANDROID_DLEXT_RESERVED_ADDRESS` and `ANDROID_DLEXT_RESERVED_ADDRESS_HINT`. */
  size_t  reserved_size;

  /** Used by `ANDROID_DLEXT_WRITE_RELRO` and `ANDROID_DLEXT_USE_RELRO`. */
  int     relro_fd;

  /** Used by `ANDROID_DLEXT_USE_LIBRARY_FD`. */
  int     library_fd;
  /** Used by `ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET` */
  off64_t library_fd_offset;

  /** Used by `ANDROID_DLEXT_USE_NAMESPACE`. */
  struct android_namespace_t* _Nullable library_namespace;
} android_dlextinfo;

/**
 * Opens the given library. The `__filename` and `__flags` arguments are
 * the same as for [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html),
 * with the Android-specific flags supplied via the `flags` member of `__info`.
 */
void* _Nullable android_dlopen_ext(const char* _Nullable __filename, int __flags, const android_dlextinfo* _Nullable __info);

__END_DECLS

/** @} */
```