Response:
Let's break down the thought process for answering the request about `linker_phdr.h`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the `linker_phdr.h` header file within the Android Bionic library, specifically the dynamic linker part. It requests an explanation of its functionality, its relation to Android, details on libc functions, dynamic linker aspects (including SO layout and linking), error examples, and how the Android framework/NDK reaches this point, culminating in Frida hooking.

**2. Initial Analysis of the Header File:**

The first step is to scan the provided code. Key observations include:

* **Copyright and Purpose:** The header declares structures and functions related to the ELF program header table and segments, emphasizing its role in the dynamic linking process. It aims for closeness to the ELF specification and independence from linker-specific structures.
* **Key Classes:** The central class is `ElfReader`. It contains methods for reading, loading, and managing ELF file information.
* **Helper Functions:**  Several standalone functions prefixed with `phdr_table_` exist. These likely operate on the program header table.
* **Includes:**  The header includes other linker-related files (`linker.h`, `linker_mapped_file_fragment.h`, `linker_note_gnu_property.h`) and standard C headers (`<list>`).
* **Macros:** `MAYBE_MAP_FLAG` and `PFLAGS_TO_PROT` hint at memory protection and mapping operations.
* **Constants:** `kCompatPageSize` suggests handling different page sizes for compatibility.

**3. Deconstructing the Request -  A Checklist Approach:**

To ensure all aspects are addressed, I'd mentally create a checklist:

* [x] Functionality of `linker_phdr.h`
* [x] Relation to Android functionality (with examples)
* [ ] Detailed explanation of libc functions (within the file)
* [x] Dynamic linker functions (with SO layout and linking)
* [x] Logical reasoning (with input/output examples)
* [x] Common user/programming errors (with examples)
* [x] Android framework/NDK path to this point
* [x] Frida hook examples

**4. Addressing Each Point Systematically:**

* **Functionality:** Based on the code, the primary function is parsing and processing the ELF program header table. This involves reading, verifying, and interpreting the program headers to manage memory mapping, loading segments, and extracting essential information for the dynamic linker.

* **Relation to Android:**  The dynamic linker is crucial for Android's application execution. This header is directly involved in loading shared libraries (.so files) into a process's address space. Examples include loading native libraries used by apps or the core system libraries.

* **libc Functions:**  A careful scan reveals *no* actual implementations of standard `libc` functions within *this* header file. It uses types and constants defined in `libc` (like `PROT_EXEC`, `PROT_READ`, `PROT_WRITE`), but doesn't define `malloc`, `open`, etc. The request misinterprets the presence of libc *types* as implementations. This is a crucial correction.

* **Dynamic Linker Functions:**  The `phdr_table_*` functions are key here. Analyze their names: `get_load_size`, `protect_segments`, `unprotect_segments`, `protect_gnu_relro`, `serialize_gnu_relro`, `map_gnu_relro`, `get_arm_exidx`, `get_dynamic_section`, `get_interpreter_name`. These strongly suggest operations related to loading, protecting, and accessing information within shared libraries. The `ElfReader` class orchestrates the process. Provide a sample SO layout illustrating sections like `.text`, `.data`, `.rodata`, and `.dynamic`. Describe the linking process: symbol resolution, relocation, and how the dynamic linker uses the program header to achieve this.

* **Logical Reasoning:** Choose a specific function, like `PFLAGS_TO_PROT`. Demonstrate its input (ELF flags) and output (memory protection flags). This provides a concrete example of the header's logic.

* **Common Errors:** Think about what could go wrong during dynamic linking. Examples include incorrect ELF headers, missing shared libraries, and incompatible architectures.

* **Android Framework/NDK Path:**  Trace the execution flow. Start with an app or the zygote process. Explain how `dlopen` (or the system's internal mechanisms for loading libraries) triggers the dynamic linker. Highlight the role of Bionic and how it utilizes these headers.

* **Frida Hooking:**  Identify key functions to hook, such as `ElfReader::Read`, `ElfReader::Load`, or `phdr_table_protect_segments`. Provide concrete Frida JavaScript code examples demonstrating how to intercept these functions, log arguments, and potentially modify behavior (though caution against modification in a production system is important).

**5. Structuring the Answer:**

Organize the information logically, mirroring the request's structure. Use clear headings and bullet points for readability. Start with a general overview and then delve into specifics. Emphasize the role of `linker_phdr.h` in the broader dynamic linking process.

**6. Refining and Reviewing:**

After drafting the initial response, reread the request and the answer. Ensure all points are addressed thoroughly and accurately. Correct any misunderstandings or errors (like the initial misinterpretation of libc functions). Ensure the language is clear and concise.

**Self-Correction Example During the Process:**

Initially, I might have thought `linker_phdr.h` *implements* libc functions because it's part of Bionic. However, upon closer inspection, it only uses *types* and *constants* defined in `libc`. The actual implementations reside in other parts of Bionic. Correcting this misconception is crucial for providing an accurate explanation. Similarly, ensure the explanation of dynamic linking is technically sound and accurately reflects the steps involved.
这是一个位于 Android Bionic 库中动态链接器目录 `bionic/linker/linker_phdr.h` 的头文件。它主要定义了与解析和处理 ELF (Executable and Linkable Format) 程序头表 (Program Header Table) 和段 (Segments) 相关的数据结构和函数。

**功能列举:**

这个头文件的主要功能是为动态链接器提供一个接口，用于读取、解析和操作 ELF 文件的程序头信息。程序头描述了如何将 ELF 文件加载到内存中。具体来说，它定义了以下关键功能：

1. **ELF 文件读取和解析:**
   - 定义了 `ElfReader` 类，用于读取和解析 ELF 文件的头部信息（`ElfW(Ehdr)`）和程序头表。
   - 提供了读取程序头表 (`ReadProgramHeaders`)、节头表 (`ReadSectionHeaders`) 和动态节 (`ReadDynamicSection`) 的方法。
   - 能够根据程序头信息计算加载地址、加载大小、入口点等关键信息。

2. **内存映射管理:**
   - 提供了将 ELF 文件中的段映射到内存中的功能 (`MapSegment`, `CompatMapSegment`)。
   - 能够根据程序头中的标志位 (`PF_R`, `PF_W`, `PF_X`) 设置内存保护属性（读、写、执行）。
   - 支持处理不同页面大小的兼容性问题 (`should_use_16kib_app_compat_`)。
   - 能够为加载的段分配地址空间 (`ReserveAddressSpace`)，并考虑地址空间的布局 (`gap_start_`, `gap_size_`)。

3. **安全性和完整性检查:**
   - 提供了验证 ELF 头部信息的函数 (`VerifyElfHeader`)。
   - 能够检查程序头的对齐要求 (`CheckProgramHeaderAlignment`)。
   - 提供了检查文件范围的函数 (`CheckFileRange`)。

4. **动态链接信息提取:**
   - 能够定位和读取动态节 (`dynamic_`)，其中包含了动态链接器执行链接所需的各种信息，如依赖库、符号表、重定位表等。
   - 提供了获取字符串表 (`strtab_`) 中字符串的函数 (`get_string`)。
   - 能够获取解释器名称 (`phdr_table_get_interpreter_name`)，用于加载动态链接器本身。

5. **GNU Relro (Read-only Relocations) 支持:**
   - 提供了保护 GNU Relro 区域的函数 (`phdr_table_protect_gnu_relro`)，增强安全性。
   - 能够序列化和映射 GNU Relro 数据 (`phdr_table_serialize_gnu_relro`, `phdr_table_map_gnu_relro`)。

6. **异常处理表 (Exception Handling Table) 支持 (ARM):**
   - 提供了获取 ARM 异常索引表的函数 (`phdr_table_get_arm_exidx`)。

7. **内存标签 (Memtag) 支持 (Android 平台安全特性):**
   - 提供了管理内存标签全局段的函数，如重映射、保护为只读和命名段 (`remap_memtag_globals_segments`, `protect_memtag_globals_ro_segments`, `name_memtag_globals_segments`)。

**与 Android 功能的关系及举例说明:**

`linker_phdr.h` 是 Android 动态链接器 (linker) 的核心组成部分，直接关系到 Android 平台加载和运行应用程序以及共享库的功能。

**举例说明:**

* **加载应用程序:** 当 Android 系统启动一个应用程序时，zygote 进程会 fork 出一个新的进程。动态链接器负责将应用程序的主可执行文件 (通常是 APK 包中的 native 库) 加载到进程的内存空间。`ElfReader` 类会读取主可执行文件的程序头，确定代码、数据等段的加载地址和大小，并使用 `MapSegment` 将它们映射到内存。
* **加载共享库 (.so 文件):**  应用程序或系统库通常会依赖其他共享库。当程序需要使用共享库中的函数或数据时，动态链接器会负责加载这些共享库。`linker_phdr.h` 中的函数会被用来解析这些共享库的程序头，并将其加载到合适的内存地址。例如，应用程序调用 `System.loadLibrary("native-lib")` 时，动态链接器会找到 `native-lib.so` 文件，并使用 `ElfReader` 读取其程序头信息。
* **地址空间布局随机化 (ASLR):** 动态链接器在加载共享库时，会根据程序头信息在内存中随机分配加载地址，这增强了安全性，防止攻击者利用固定的内存地址进行攻击。`linker_phdr.h` 中的功能负责解析程序头，为后续的地址分配提供依据。
* **权限管理:** 程序头中的段标志位 (`PF_R`, `PF_W`, `PF_X`) 告诉动态链接器哪些内存区域应该具有读、写或执行权限。例如，代码段通常具有读和执行权限，而数据段具有读写权限。`PFLAGS_TO_PROT` 宏可以将这些标志位转换为 `mmap` 系统调用所需的保护标志。
* **Relro 保护:** Android 使用 Relro 技术来增强安全性。`linker_phdr.h` 中与 Relro 相关的函数确保了重定位表的部分或全部在加载后被标记为只读，防止恶意修改。

**详细解释 libc 函数的功能是如何实现的:**

**需要注意的是，`linker_phdr.h` 本身** **并没有实现任何标准的 C 库 (libc) 函数**。它定义的是动态链接器内部使用的数据结构和函数，用于处理 ELF 文件格式。

虽然头文件中使用了诸如 `size_t`、`off64_t` 等类型，这些类型定义在 libc 的头文件中（例如 `<sys/types.h>`），但这并不意味着 `linker_phdr.h` 实现了 libc 函数。

`linker_phdr.h` 的作用是**辅助**动态链接器完成其工作，而动态链接器本身是作为 libc 的一部分实现的 (在 Android 中是 Bionic libc)。动态链接器会使用 libc 提供的系统调用 (如 `mmap`, `munmap`, `open`, `close`, `mprotect`) 来完成内存映射、文件操作和权限设置等任务。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

**SO 布局样本:**

一个典型的共享库 (.so) 文件在内存中的布局大致如下：

```
+----------------------+  <-- 加载基址 (Load Base Address)
| ELF Header           |
+----------------------+
| Program Header Table |  <-- linker_phdr.h 主要处理的对象
+----------------------+
| .text (代码段)       |  <-- 可执行，只读
+----------------------+
| .rodata (只读数据段) |  <-- 只读
+----------------------+
| .data (已初始化数据段) |  <-- 可读写
+----------------------+
| .bss (未初始化数据段) |  <-- 可读写，加载时清零
+----------------------+
| .dynamic (动态链接信息) |  <-- 包含链接器所需的信息
+----------------------+
| .symtab (符号表)     |  <-- 用于符号解析
+----------------------+
| .strtab (字符串表)   |  <-- 存储符号名称等字符串
+----------------------+
| .rel.plt (PLT 重定位表) |
+----------------------+
| .rel.dyn (数据重定位表) |
+----------------------+
| ... 其他节 ...        |
+----------------------+
```

**链接的处理过程:**

1. **加载 (Loading):**
   - 当程序需要使用共享库时，动态链接器会根据程序头表中的信息，使用 `mmap` 系统调用将共享库的各个段映射到进程的地址空间。
   - `linker_phdr.h` 中 `ElfReader` 的功能在这里至关重要，它负责读取和解析程序头，确定各个段的加载地址、大小和权限。

2. **重定位 (Relocation):**
   - 共享库在编译时并不知道最终的加载地址。重定位的过程就是修改代码和数据段中对全局变量、函数等的引用，使其指向正确的运行时地址。
   - 动态链接器会读取 `.rel.plt` 和 `.rel.dyn` 等重定位表，根据其中的指令修改相应的内存位置。
   - `linker_phdr.h` 中的函数虽然不直接处理重定位，但它负责加载包含重定位表信息的段 (`.dynamic`)。

3. **符号解析 (Symbol Resolution):**
   - 当程序调用共享库中的函数或访问其全局变量时，动态链接器需要找到这些符号的实际地址。
   - 动态链接器会搜索共享库的符号表 (`.symtab`)，找到匹配的符号，并将其地址用于重定位。
   - `linker_phdr.h` 中 `ElfReader` 可以访问字符串表 (`.strtab`)，用于获取符号名称。

4. **PLT 和 GOT (Procedure Linkage Table 和 Global Offset Table):**
   - 为了实现延迟绑定（即在第一次调用时才解析符号），动态链接器会使用 PLT 和 GOT。
   - PLT 中的条目会跳转到 GOT 中的地址，初始时 GOT 中的地址指向 PLT 中的一个解析器例程。
   - 当函数第一次被调用时，解析器会找到函数的实际地址并更新 GOT 表项。后续的调用将直接跳转到函数的实际地址，提高了性能。

**假设输入与输出 (针对 `PFLAGS_TO_PROT` 宏):**

**假设输入:**

一个程序头段的 `p_flags` 字段的值为 `PF_R | PF_X` (即可读且可执行)。

**输出:**

`PFLAGS_TO_PROT(PF_R | PF_X)` 将返回 `PROT_READ | PROT_EXEC`。

**逻辑推理:**

`PFLAGS_TO_PROT` 宏使用位运算来将 ELF 程序头中的段标志位转换为 `mmap` 系统调用所需的保护标志位。

- `MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC)`: 如果 `x` 中设置了 `PF_X` 位，则返回 `PROT_EXEC`，否则返回 0。
- `MAYBE_MAP_FLAG((x), PF_R, PROT_READ)`: 如果 `x` 中设置了 `PF_R` 位，则返回 `PROT_READ`，否则返回 0。
- `MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE)`: 如果 `x` 中设置了 `PF_W` 位，则返回 `PROT_WRITE`，否则返回 0。

最终将这三个结果进行或运算，得到最终的保护标志。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然用户或程序员通常不直接操作 `linker_phdr.h` 中的函数，但与动态链接相关的错误很常见，这些错误最终可能与动态链接器处理程序头的方式有关。

* **找不到共享库:** 当应用程序尝试加载一个不存在或路径不正确的共享库时，动态链接器会报错。这可能是由于 `System.loadLibrary()` 调用中传递了错误的库名称，或者库文件没有放在系统能够找到的路径下。
* **ABI 不兼容:** 如果应用程序尝试加载一个与当前设备架构 (如 arm64-v8a, armeabi-v7a) 不兼容的共享库，动态链接器会拒绝加载。程序头中的信息会指示库的目标架构。
* **符号未定义错误:** 当应用程序调用一个在已加载的共享库中找不到的符号（函数或变量）时，会发生符号未定义错误。这可能是由于链接时缺少了某些库，或者库的版本不匹配。
* **内存访问违规 (Segmentation Fault):** 如果程序尝试访问没有权限的内存区域，可能会导致段错误。这可能与动态链接器错误地设置了内存保护属性有关 (虽然这种情况比较少见，因为动态链接器的这部分代码经过了严格测试)。
* **依赖循环:** 如果共享库之间存在循环依赖关系，动态链接器可能会陷入无限循环或抛出错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到 `linker_phdr.h` 的路径:**

1. **应用程序启动:** 当 Android Framework 启动一个应用程序时，首先会 fork 出一个新的进程。
2. **Zygote 进程:** 新进程最初是 Zygote 进程的一个克隆。Zygote 进程在启动时已经加载了常用的系统库。
3. **`app_process` 可执行文件:** Zygote 会执行应用程序的 `app_process` 可执行文件。
4. **动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`):**  `app_process` 的加载过程依赖于动态链接器。内核会首先加载动态链接器到进程空间。
5. **动态链接器的初始化:** 动态链接器开始初始化自身，这包括解析 `app_process` 的 ELF 头和程序头表。这时，`linker_phdr.h` 中的 `ElfReader` 等类和函数会被使用。
6. **加载应用程序代码:** 动态链接器会根据 `app_process` 的程序头信息，将应用程序的代码段、数据段等映射到内存。
7. **加载依赖的共享库:** 当应用程序代码执行时，如果需要使用 native 代码，会调用 `System.loadLibrary()` 或 `dlopen()`。
8. **动态链接器寻找共享库:** 动态链接器会根据配置的库搜索路径查找指定的共享库文件。
9. **解析共享库的 ELF 头:** 找到共享库后，动态链接器会再次使用 `linker_phdr.h` 中的工具 (如 `ElfReader`) 来读取和解析共享库的 ELF 头和程序头表。
10. **映射共享库段:** 动态链接器根据共享库的程序头信息，使用 `mmap` 将其各个段映射到进程的地址空间。
11. **重定位和符号解析:** 动态链接器执行重定位和符号解析，使得应用程序能够正确调用共享库中的函数。
12. **NDK 的使用:** 当使用 NDK 开发 native 库时，编译出的 `.so` 文件就需要遵循 ELF 格式，其程序头信息会被动态链接器按照上述步骤处理。

**Frida Hook 示例:**

可以使用 Frida hook `linker_phdr.h` 中关键的函数来观察动态链接的过程。以下是一些示例：

**Hook `ElfReader::Read` 函数:**

```javascript
if (Process.arch === 'arm64') {
  const ElfReader_Read = Module.findExportByName("linker64", "_ZN9ElfReader4ReadEPKciz"); // arm64
  if (ElfReader_Read) {
    Interceptor.attach(ElfReader_Read, {
      onEnter: function (args) {
        const name = Memory.readUtf8String(args[1]);
        const fd = args[2].toInt32();
        const offset = args[3].toInt64String();
        const size = args[4].toInt64String();
        console.log(`[ElfReader::Read] name: ${name}, fd: ${fd}, offset: ${offset}, size: ${size}`);
      },
      onLeave: function (retval) {
        console.log(`[ElfReader::Read] returned: ${retval}`);
      }
    });
  }
} else if (Process.arch === 'arm') {
  const ElfReader_Read = Module.findExportByName("linker", "_ZN9ElfReader4ReadEPKciz"); // arm
  if (ElfReader_Read) {
    Interceptor.attach(ElfReader_Read, {
      onEnter: function (args) {
        const name = Memory.readUtf8String(args[1]);
        const fd = args[2].toInt32();
        const offset = ptr(args[3]).toInt32(); // 32-bit offset
        const size = ptr(args[4]).toInt32();   // 32-bit size
        console.log(`[ElfReader::Read] name: ${name}, fd: ${fd}, offset: ${offset}, size: ${size}`);
      },
      onLeave: function (retval) {
        console.log(`[ElfReader::Read] returned: ${retval}`);
      }
    });
  }
}
```

这个脚本会 hook `ElfReader::Read` 函数，当动态链接器尝试读取 ELF 文件头部时，会打印出文件名、文件描述符、偏移量和大小。

**Hook `phdr_table_protect_segments` 函数:**

```javascript
if (Process.arch === 'arm64') {
  const phdr_table_protect_segments = Module.findExportByName("linker64", "phdr_table_protect_segments");
  if (phdr_table_protect_segments) {
    Interceptor.attach(phdr_table_protect_segments, {
      onEnter: function (args) {
        const phdr_table = args[0];
        const phdr_count = args[1].toInt32();
        const load_bias = args[2];
        const should_pad_segments = args[3].toInt32();
        const should_use_16kib_app_compat = args[4].toInt32();
        console.log(`[phdr_table_protect_segments] phdr_table: ${phdr_table}, count: ${phdr_count}, bias: ${load_bias}, pad: ${should_pad_segments}, compat: ${should_use_16kib_app_compat}`);
      }
    });
  }
} else if (Process.arch === 'arm') {
  const phdr_table_protect_segments = Module.findExportByName("linker", "phdr_table_protect_segments");
  if (phdr_table_protect_segments) {
    Interceptor.attach(phdr_table_protect_segments, {
      onEnter: function (args) {
        const phdr_table = args[0];
        const phdr_count = args[1].toInt32();
        const load_bias = args[2];
        const should_pad_segments = args[3].toInt32();
        const should_use_16kib_app_compat = args[4].toInt32();
        console.log(`[phdr_table_protect_segments] phdr_table: ${phdr_table}, count: ${phdr_count}, bias: ${load_bias}, pad: ${should_pad_segments}, compat: ${should_use_16kib_app_compat}`);
      }
    });
  }
}
```

这个脚本会 hook `phdr_table_protect_segments` 函数，该函数负责设置内存段的保护属性。通过观察其参数，可以了解哪些段正在被保护以及使用了哪些保护标志。

通过 hook 这些关键函数，开发者可以深入了解 Android 动态链接器的运作方式，调试与库加载相关的问题。需要根据目标进程的架构 (32位或64位) 调整 Frida 脚本中查找导出函数名称的方式。

Prompt: 
```
这是目录为bionic/linker/linker_phdr.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2012 The Android Open Source Project
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

#pragma once

/* Declarations related to the ELF program header table and segments.
 *
 * The design goal is to provide an API that is as close as possible
 * to the ELF spec, and does not depend on linker-specific data
 * structures (e.g. the exact layout of struct soinfo).
 */

#include "linker.h"
#include "linker_mapped_file_fragment.h"
#include "linker_note_gnu_property.h"

#include <list>

#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

static constexpr size_t kCompatPageSize = 0x1000;

class ElfReader {
 public:
  ElfReader();

  [[nodiscard]] bool Read(const char* name, int fd, off64_t file_offset, off64_t file_size);
  [[nodiscard]] bool Load(address_space_params* address_space);

  const char* name() const { return name_.c_str(); }
  size_t phdr_count() const { return phdr_num_; }
  ElfW(Addr) load_start() const { return reinterpret_cast<ElfW(Addr)>(load_start_); }
  size_t load_size() const { return load_size_; }
  ElfW(Addr) gap_start() const { return reinterpret_cast<ElfW(Addr)>(gap_start_); }
  size_t gap_size() const { return gap_size_; }
  ElfW(Addr) load_bias() const { return load_bias_; }
  const ElfW(Phdr)* loaded_phdr() const { return loaded_phdr_; }
  const ElfW(Dyn)* dynamic() const { return dynamic_; }
  const char* get_string(ElfW(Word) index) const;
  bool is_mapped_by_caller() const { return mapped_by_caller_; }
  ElfW(Addr) entry_point() const { return header_.e_entry + load_bias_; }
  bool should_pad_segments() const { return should_pad_segments_; }
  bool should_use_16kib_app_compat() const { return should_use_16kib_app_compat_; }
  ElfW(Addr) compat_relro_start() const { return compat_relro_start_; }
  ElfW(Addr) compat_relro_size() const { return compat_relro_size_; }

 private:
  [[nodiscard]] bool ReadElfHeader();
  [[nodiscard]] bool VerifyElfHeader();
  [[nodiscard]] bool ReadProgramHeaders();
  [[nodiscard]] bool CheckProgramHeaderAlignment();
  [[nodiscard]] bool ReadSectionHeaders();
  [[nodiscard]] bool ReadDynamicSection();
  [[nodiscard]] bool ReadPadSegmentNote();
  [[nodiscard]] bool ReserveAddressSpace(address_space_params* address_space);
  [[nodiscard]] bool MapSegment(size_t seg_idx, size_t len);
  [[nodiscard]] bool CompatMapSegment(size_t seg_idx, size_t len);
  void ZeroFillSegment(const ElfW(Phdr)* phdr);
  void DropPaddingPages(const ElfW(Phdr)* phdr, uint64_t seg_file_end);
  [[nodiscard]] bool MapBssSection(const ElfW(Phdr)* phdr, ElfW(Addr) seg_page_end,
                                   ElfW(Addr) seg_file_end);
  [[nodiscard]] bool IsEligibleFor16KiBAppCompat(ElfW(Addr)* vaddr);
  [[nodiscard]] bool HasAtMostOneRelroSegment(const ElfW(Phdr)** relro_phdr);
  [[nodiscard]] bool Setup16KiBAppCompat();
  [[nodiscard]] bool LoadSegments();
  [[nodiscard]] bool FindPhdr();
  [[nodiscard]] bool FindGnuPropertySection();
  [[nodiscard]] bool CheckPhdr(ElfW(Addr));
  [[nodiscard]] bool CheckFileRange(ElfW(Addr) offset, size_t size, size_t alignment);

  bool did_read_;
  bool did_load_;
  std::string name_;
  int fd_;
  off64_t file_offset_;
  off64_t file_size_;

  ElfW(Ehdr) header_;
  size_t phdr_num_;

  MappedFileFragment phdr_fragment_;
  const ElfW(Phdr)* phdr_table_;

  MappedFileFragment shdr_fragment_;
  const ElfW(Shdr)* shdr_table_;
  size_t shdr_num_;

  MappedFileFragment dynamic_fragment_;
  const ElfW(Dyn)* dynamic_;

  MappedFileFragment strtab_fragment_;
  const char* strtab_;
  size_t strtab_size_;

  // First page of reserved address space.
  void* load_start_;
  // Size in bytes of reserved address space.
  size_t load_size_;
  // First page of inaccessible gap mapping reserved for this DSO.
  void* gap_start_;
  // Size in bytes of the gap mapping.
  size_t gap_size_;
  // Load bias.
  ElfW(Addr) load_bias_;

  // Maximum and minimum alignment requirements across all phdrs.
  size_t max_align_;
  size_t min_align_;

  // Loaded phdr.
  const ElfW(Phdr)* loaded_phdr_;

  // Is map owned by the caller
  bool mapped_by_caller_;

  // Pad gaps between segments when memory mapping?
  bool should_pad_segments_ = false;

  // Use app compat mode when loading 4KiB max-page-size ELFs on 16KiB page-size devices?
  bool should_use_16kib_app_compat_ = false;

  // RELRO region for 16KiB compat loading
  ElfW(Addr) compat_relro_start_ = 0;
  ElfW(Addr) compat_relro_size_ = 0;

  // Only used by AArch64 at the moment.
  GnuPropertySection note_gnu_property_ __unused;
};

size_t phdr_table_get_load_size(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr)* min_vaddr = nullptr, ElfW(Addr)* max_vaddr = nullptr);

int phdr_table_protect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                ElfW(Addr) load_bias, bool should_pad_segments,
                                bool should_use_16kib_app_compat,
                                const GnuPropertySection* prop = nullptr);

int phdr_table_unprotect_segments(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                  ElfW(Addr) load_bias, bool should_pad_segments,
                                  bool should_use_16kib_app_compat);

int phdr_table_protect_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                 ElfW(Addr) load_bias, bool should_pad_segments,
                                 bool should_use_16kib_app_compat);

int phdr_table_protect_gnu_relro_16kib_compat(ElfW(Addr) start, ElfW(Addr) size);

int phdr_table_serialize_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                   ElfW(Addr) load_bias, int fd, size_t* file_offset);

int phdr_table_map_gnu_relro(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                             ElfW(Addr) load_bias, int fd, size_t* file_offset);

#if defined(__arm__)
int phdr_table_get_arm_exidx(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias,
                             ElfW(Addr)** arm_exidx, size_t* arm_exidix_count);
#endif

void phdr_table_get_dynamic_section(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                    ElfW(Addr) load_bias, ElfW(Dyn)** dynamic,
                                    ElfW(Word)* dynamic_flags);

const char* phdr_table_get_interpreter_name(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                            ElfW(Addr) load_bias);

bool page_size_migration_supported();

int remap_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
                                  ElfW(Addr) load_bias);

void protect_memtag_globals_ro_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
                                        ElfW(Addr) load_bias);

void name_memtag_globals_segments(const ElfW(Phdr) * phdr_table, size_t phdr_count,
                                  ElfW(Addr) load_bias, const char* soname,
                                  std::list<std::string>* vma_names);

"""

```