Response:
Let's break down the thought process to answer the user's request based on the provided C header file.

**1. Understanding the Request:**

The user wants a comprehensive analysis of the `elf.handroid` header file within the context of Android's Bionic libc and dynamic linker. The key requirements are:

* **Functionality:** What does this file define?
* **Android Relevance:** How does it relate to Android's workings, providing concrete examples?
* **Libc Function Explanation:** A detailed breakdown of *each* libc function (though the file itself doesn't *define* libc functions, it defines *data structures* used by the dynamic linker, which is part of Bionic). This requires a slight reinterpretation to focus on the *elements* defined and their role.
* **Dynamic Linker Aspects:** Explanation of how these definitions are used by the dynamic linker, including SO layout and linking process.
* **Logic & Assumptions:**  Where reasoning is involved, clarify the assumptions and expected outcomes.
* **Common Errors:** Typical mistakes developers might make related to these concepts.
* **Android Framework/NDK Path:**  How does execution flow from the app/framework to these ELF structures?
* **Frida Hooking:** Practical examples of using Frida for debugging.

**2. Initial Analysis of the Header File:**

The first scan reveals that this isn't a file containing executable code or function definitions. Instead, it's a header file (`.h`) defining C data structures and constants. The copyright notice confirms it's part of Android's Open Source Project. The included headers (`linux/elf.h`, `linux/elf-em.h`, `bits/auxvec.h`, `bits/elf_common.h`) immediately point to ELF (Executable and Linkable Format) specifics.

**3. Identifying Key Concepts and Structures:**

The core elements defined in the file are:

* **Typedefs:**  `Elf32_Xword`, `Elf32_Sxword`, `Elf64_auxv_t`, etc. These are architecture-specific type definitions related to ELF structures. The `32` and `64` prefixes indicate different architectures.
* **Structures:** `Elf32_auxv_t`, `Elf64_Chdr`, `Elf32_Lib`, `Elf64_Move`, `Elf32_Syminfo`, `Elf32_Verdef`, `Elf32_Verneed`, `Elf32_Vernaux`. These structures represent different parts of the ELF format, like auxiliary vectors, section headers, library dependencies, relocation information, symbol versioning, etc.
* **Macros/Constants:** `DF_1_NOW`, `ELF32_R_INFO`, `SHT_RELR`, `DT_ANDROID_RELR`, etc. These are flags, bit manipulation macros, and constants used to identify and interpret ELF data.

**4. Connecting to Android Functionality:**

The file's purpose is clearly related to how Android loads and manages executable files (executables and shared libraries). The structures define the format of these files. Key connections include:

* **Dynamic Linking:** The structures directly relate to the dynamic linker's job of resolving dependencies between shared libraries at runtime. `DT_*` tags and relocation structures are critical here.
* **Auxiliary Vector:**  `Elf32_auxv_t` and `Elf64_auxv_t` are used to pass information from the kernel to the dynamic linker (and subsequently the application).
* **Relocations:** The `Elf*_Relr`, `Elf*_Move` structures are essential for adjusting addresses in shared libraries when they are loaded at a non-preferred base address.
* **Symbol Versioning:**  `Elf*_Verdef`, `Elf*_Verneed`, `Elf*_Vernaux` handle different versions of symbols in shared libraries, allowing for compatibility.

**5. Addressing Specific Request Points:**

* **Libc Functions:** The header *doesn't* define libc functions. It defines *data structures* used by the dynamic linker, which is *part of* Bionic. The explanation should focus on the *purpose* of these structures within the dynamic linking process.
* **Dynamic Linker Details:** Explain the role of each structure in the dynamic linking process. A sample SO layout can be simplified to show the sections relevant to these structures (e.g., `.dynamic`, `.rel.dyn`, `.symtab`, `.strtab`). The linking process explanation should cover symbol resolution and relocation.
* **Logic and Assumptions:**  Examples here could be based on how symbol lookup or relocation would work given specific values within these structures.
* **Common Errors:**  Focus on errors related to shared library dependencies, versioning conflicts, or incorrect relocation handling (though these are usually internal to the linker, programmer errors can lead to related issues).
* **Android Framework/NDK Path:** Describe the sequence of events from app launch to the dynamic linker processing these ELF structures.
* **Frida Hooking:** Demonstrate how to use Frida to inspect these ELF structures in memory during runtime.

**6. Structuring the Answer:**

Organize the response logically, addressing each part of the user's request. Use headings and bullet points for clarity. Start with a general overview of the file's purpose and then delve into specifics.

**7. Iterative Refinement (Self-Correction):**

During the process, review the initial interpretation. For example, realizing that the file doesn't define *libc functions* but rather *data structures* used by the dynamic linker within Bionic is crucial for accurate explanation. Adjust the focus accordingly. Similarly, when explaining the dynamic linking process, providing a simplified SO layout is more helpful than overwhelming detail.

**8. Language and Tone:**

Maintain a clear and technical tone, explaining concepts in a way that is understandable but also accurate. Use examples to illustrate points. Since the request is in Chinese, the final output should be in Chinese.

By following these steps, we can systematically analyze the header file and construct a comprehensive and accurate response to the user's request. The key is to understand the context of the file within the Android ecosystem and focus on its role in the dynamic linking process.
这个位于 `bionic/libc/include/elf.handroid` 的头文件定义了 Android Bionic C 库中与 ELF (Executable and Linkable Format) 文件格式相关的特定数据结构和常量。它是对标准 ELF 规范的补充和扩展，包含了 Android 特有的定义。

**功能列举:**

这个头文件主要定义了以下功能相关的结构体和宏：

1. **辅助向量 (Auxiliary Vector):**
   - `Elf32_auxv_t`, `Elf64_auxv_t`:  定义了辅助向量的条目结构。辅助向量是操作系统内核在程序启动时传递给用户空间程序的一些信息，例如堆栈地址、程序头表的地址、入口点地址等。

2. **节头部扩展 (Section Header Extension):**
   - `Elf32_Chdr`, `Elf64_Chdr`: 定义了节头部扩展的结构。节头部扩展允许在节头部表中添加额外的与节相关的信息。

3. **共享库列表 (Shared Library List):**
   - `Elf32_Lib`, `Elf64_Lib`: 定义了共享库信息的结构。可能用于记录共享库的名称、时间戳、校验和等，但更常见的共享库信息是通过 `.dynamic` 节中的 `DT_NEEDED` 项来表示。 这个结构在实际的 ELF 文件中并不常见，可能是历史遗留或特定工具使用的结构。

4. **移动表 (Move Table):**
   - `Elf32_Move`, `Elf64_Move`: 定义了移动表的条目结构。移动表用于描述需要在加载时进行地址调整的代码或数据块。在早期的动态链接实现中可能使用，但现代 ELF 通常使用重定位表。

5. **节索引 (Section Index):**
   - `Elf32_Section`, `Elf64_Section`:  定义了节索引的类型，通常是无符号短整型。

6. **符号信息 (Symbol Information):**
   - `Elf32_Syminfo`, `Elf64_Syminfo`: 定义了符号信息的结构，用于存储与符号相关的额外信息，例如绑定类型和标志。

7. **版本符号 (Version Symbol):**
   - `Elf32_Versym`, `Elf64_Versym`: 定义了版本符号的类型，通常是无符号短整型，用于标识符号的版本信息。

8. **版本定义 (Version Definition):**
   - `Elf32_Verdef`, `Elf64_Verdef`: 定义了版本定义的结构，用于描述共享库导出的符号的版本。
   - `Elf32_Verdaux`, `Elf64_Verdaux`: 定义了版本定义的辅助信息结构，用于存储版本名称等。

9. **版本需求 (Version Needed):**
   - `Elf32_Verneed`, `Elf64_Verneed`: 定义了版本需求的结构，用于描述一个共享库所依赖的其他共享库的符号版本。
   - `Elf32_Vernaux`, `Elf64_Vernaux`: 定义了版本需求的辅助信息结构，用于存储依赖的共享库名称和所需的符号版本。

10. **相对重定位表项 (Relative Relocation Entry for SHT_RELR):**
    - `Elf32_Relr`, `Elf64_Relr`: 定义了相对重定位表项的结构，用于 `SHT_RELR` 类型的节。这种重定位类型允许更紧凑地表示只进行加法运算的重定位信息。

11. **动态标志 (Dynamic Flags):**
    - 定义了以 `DF_1_` 开头的宏，表示动态链接器的标志，例如 `DF_1_NOW` (立即处理所有重定位)、`DF_1_INITFIRST` (优先执行初始化函数) 等。

12. **重定位信息宏 (Relocation Information Macros):**
    - `ELF32_R_INFO`, `ELF64_R_INFO`:  用于构建重定位表项中的信息字段，包含符号表索引和重定位类型。

13. **符号表信息宏 (Symbol Table Information Macros):**
    - `ELF_ST_INFO`, `ELF32_ST_INFO`, `ELF64_ST_INFO`: 用于构建符号表条目中的信息字段，包含符号的绑定属性和类型。

14. **节头部标志 (Section Header Flags):**
    - `GRP_MASKOS`, `GRP_MASKPROC`:  用于屏蔽节头部标志中的操作系统特定和处理器特定的位。

15. **Android 特有的节类型和动态标签 (Android Specific Section Types and Dynamic Tags):**
    - `SHT_RELR`: 标准的相对重定位节类型。
    - `SHT_ANDROID_RELR`, `DT_ANDROID_RELR`, `DT_ANDROID_RELRSZ`, `DT_ANDROID_RELRENT`, `DT_ANDROID_RELRCOUNT`: Android 实验性的相对重定位节类型和相关的动态标签。
    - `SHT_ANDROID_REL`, `SHT_ANDROID_RELA`, `DT_ANDROID_REL`, `DT_ANDROID_RELSZ`, `DT_ANDROID_RELA`, `DT_ANDROID_RELASZ`:  Android 用于压缩的 REL/RELA 节的类型和相关的动态标签。

16. **特定架构的动态标签 (Architecture Specific Dynamic Tags):**
    - `DT_AARCH64_MEMTAG_MODE`, `DT_AARCH64_MEMTAG_HEAP`, `DT_AARCH64_MEMTAG_STACK`, `DT_AARCH64_MEMTAG_GLOBALS`, `DT_AARCH64_MEMTAG_GLOBALSSZ`: ARM64 架构的内存标签相关的动态标签。
    - 定义了 ARM 和 RISC-V 架构中特有的重定位类型。

**与 Android 功能的关系及举例说明:**

这个头文件中的定义是 Android 动态链接器 (`linker`) 的核心组成部分。动态链接器负责在程序启动时加载共享库，并解析符号引用，使得程序能够正确调用共享库中的函数和访问其中的数据。

* **动态链接过程:** Android 应用和大部分系统服务都依赖于动态链接。当一个应用启动时，`zygote` 进程 `fork` 出新的进程，内核在加载可执行文件后，会启动动态链接器。动态链接器会解析可执行文件的头部信息，包括 `.dynamic` 节，其中包含了共享库的依赖信息 (`DT_NEEDED`)、重定位表的位置和大小 (`DT_REL`, `DT_RELA`, `DT_RELR` 等)、符号表的位置 (`DT_SYMTAB`) 等。

* **辅助向量的使用:** 内核通过辅助向量将重要的信息传递给动态链接器。例如，`AT_BASE` 指示了可执行文件的加载基地址，`AT_PHDR` 和 `AT_PHENT` 指示了程序头表的位置和大小，动态链接器需要这些信息来解析 ELF 文件结构。

* **重定位的处理:** 当加载共享库时，共享库的代码和数据段可能无法加载到其编译时指定的地址。重定位表 (`.rel.dyn`, `.rela.dyn`, `.relr.dyn`) 包含了需要动态链接器修改的地址信息。例如，如果一个共享库中的函数调用了另一个共享库中的函数，那么在编译时，这个调用地址是一个占位符，动态链接器会根据实际加载地址修改这个地址。`Elf32_Relr` 和 `Elf64_Relr` 定义了相对重定位的结构，用于优化只进行加法运算的重定位。

* **符号解析:** 当程序调用一个共享库中的函数时，动态链接器需要找到该函数的实际地址。符号表 (`.symtab`) 包含了共享库导出的符号信息，动态链接器通过查找符号表来解析符号引用。版本定义和版本需求相关的结构 (`Elf*_Verdef`, `Elf*_Verneed`) 允许不同版本的共享库提供相同名称的符号，并确保程序链接到正确的版本。

* **Android 特有的优化:** `SHT_ANDROID_RELR` 和相关的动态标签是 Android 为了减小可执行文件和共享库的大小以及加速加载速度而引入的优化。压缩的 REL/RELA 节 (`SHT_ANDROID_REL`, `SHT_ANDROID_RELA`) 也具有类似的目的。

**SO 布局样本和链接的处理过程:**

一个典型的 Android 共享库 (`.so`) 文件布局可能包含以下关键部分：

```
ELF Header
Program Headers
Section Headers

.text        (代码段)
.rodata      (只读数据段，例如字符串常量)
.data        (已初始化的可读写数据段)
.bss         (未初始化的数据段)
.symtab      (符号表)
.strtab      (字符串表，用于存储符号名等)
.dynsym      (动态符号表)
.dynstr      (动态字符串表)
.rel.dyn     (动态重定位表)
.rela.dyn    (动态重定位表，带显式加数的版本)
.relr.dyn    (相对重定位表)
.plt         (过程链接表)
.got         (全局偏移量表)
.dynamic     (动态链接信息节)
... 其他节 ...
```

**链接处理过程：**

1. **加载共享库:** 当程序需要使用某个共享库时，动态链接器会根据 `.dynamic` 节中的 `DT_NEEDED` 项找到并加载该共享库。
2. **解析符号:** 当遇到未解析的符号引用时，动态链接器会在已加载的共享库的符号表中查找该符号。
3. **重定位:** 动态链接器会遍历重定位表 (`.rel.dyn`, `.rela.dyn`, `.relr.dyn`)，根据重定位条目的指示，修改代码和数据段中的地址。
    - **绝对重定位:**  例如 `R_ARM_ABS32`，需要将符号的绝对地址写入到指定的位置。
    - **相对重定位:** 例如 `R_ARM_RELATIVE` 或 `R_ARM_REL32`，需要将加载地址和符号的偏移量计算后写入到指定的位置。`Elf32_Relr` 定义的相对重定位进一步优化了这种情况，只需要记录偏移量。
    - **过程链接表 (PLT) 和全局偏移量表 (GOT):** 对于函数调用，通常会使用 PLT 和 GOT。GOT 存储了全局变量和外部函数的地址。PLT 中的每一项对应一个外部函数，第一次调用时会跳转到动态链接器的解析例程，解析完成后会将函数的实际地址写入 GOT 表，后续调用会直接跳转到 GOT 表中的地址。

**假设输入与输出 (逻辑推理):**

假设有一个共享库 `libfoo.so`，其中定义了一个全局变量 `global_var` 和一个函数 `foo_function`。另一个程序 `app` 依赖于 `libfoo.so`。

**libfoo.so 的 `.symtab` 中可能包含：**

```
符号名         类型     绑定     节索引     地址      大小
global_var    OBJECT   GLOBAL   .data     0x...    4
foo_function  FUNC     GLOBAL   .text     0x...    ...
```

**app 的重定位表 (例如 `.rel.dyn`) 中可能包含：**

```
偏移量       类型            符号
0x...       R_ARM_GLOB_DAT   global_var
0x...       R_ARM_CALL       foo_function
```

**处理过程：**

1. 当 `app` 启动时，动态链接器加载 `libfoo.so`。
2. 动态链接器处理 `app` 中针对 `global_var` 的 `R_ARM_GLOB_DAT` 重定位条目。它会在 `libfoo.so` 的符号表中找到 `global_var` 的地址，并将该地址写入到 `app` 的指定内存位置。
3. 当 `app` 第一次调用 `foo_function` 时，会跳转到 PLT 中对应的条目。PLT 条目会跳转到动态链接器的解析例程。
4. 动态链接器解析 `foo_function` 符号，找到其在 `libfoo.so` 中的实际地址。
5. 动态链接器将 `foo_function` 的实际地址写入到 GOT 表中对应的条目。
6. 后续对 `foo_function` 的调用会直接跳转到 GOT 表中的地址，而无需再次解析。

**用户或编程常见的使用错误:**

1. **找不到共享库:**  如果在编译或运行时，动态链接器找不到程序依赖的共享库，会导致程序无法启动或运行。这通常是因为 `LD_LIBRARY_PATH` 环境变量没有设置正确，或者共享库没有放在系统默认的库路径下。

   ```bash
   # 错误示例：找不到 libbar.so
   dlopen("libbar.so", RTLD_LAZY); // 返回 NULL
   ```

2. **符号未定义:**  如果程序引用的符号在任何已加载的共享库中都找不到，会导致链接错误。这可能是因为共享库没有导出该符号，或者程序错误地引用了不存在的符号。

   ```c
   // 假设 libfoo.so 中没有定义 bar_function
   void bar_function(); // 声明了但实际链接时找不到
   ```

3. **版本冲突:**  当多个共享库提供相同名称的符号，但版本不兼容时，可能导致运行时错误。例如，程序可能链接到旧版本的共享库，但运行时加载了新版本的共享库，导致符号的接口不匹配。

4. **循环依赖:** 如果两个或多个共享库相互依赖，可能导致加载顺序问题和链接错误。动态链接器需要按照一定的顺序加载共享库，才能正确解析符号。

5. **使用错误的重定位类型:** 在手动编写汇编代码或使用底层工具时，如果选择了错误的重定位类型，会导致链接器无法正确处理地址。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **应用程序启动:**  当一个 Android 应用程序启动时，`zygote` 进程 `fork` 出一个新的进程。
2. **加载可执行文件:**  内核加载应用程序的可执行文件 (`.apk` 中的 `classes.dex` 通过 `dalvikvm` 或 `art` 解释或编译执行，但其依赖的原生库是 ELF 文件)。对于原生代码，内核会加载 ELF 格式的可执行文件。
3. **启动动态链接器:** 内核根据 ELF 头部的信息，找到动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 并启动它。
4. **解析 ELF 头部和程序头:** 动态链接器读取可执行文件的 ELF 头部和程序头，获取加载地址、程序入口点等信息。
5. **处理 `.dynamic` 节:** 动态链接器解析 `.dynamic` 节，获取依赖的共享库列表 (`DT_NEEDED`)、重定位表信息、符号表信息等。
6. **加载共享库:**  动态链接器根据 `DT_NEEDED` 项加载所需的共享库。这个过程中会读取被加载的共享库的 ELF 头部信息，包括 `elf.handroid` 中定义的结构。
7. **符号解析和重定位:**  动态链接器根据重定位表中的信息，修改代码和数据段中的地址，并将符号引用解析到共享库中的实际地址。这里会用到 `Elf32_Relr`, `Elf64_R_INFO` 等定义。
8. **执行初始化函数:** 加载完所有依赖的共享库并完成重定位后，动态链接器会执行每个共享库的初始化函数 (`.init` 和 `.ctors` 节中的代码)。
9. **跳转到程序入口点:** 最后，动态链接器将控制权转移到应用程序的入口点 (`_start` 函数或 `main` 函数)。

**NDK 的情况类似:** 当一个使用 NDK 开发的应用程序启动时，其包含的原生代码部分会经历上述动态链接过程。NDK 编译生成的共享库或可执行文件遵循 ELF 格式，因此也会用到 `elf.handroid` 中定义的结构。

**Frida Hook 示例调试步骤:**

可以使用 Frida hook 动态链接器的相关函数，来观察 ELF 结构的处理过程。例如，可以 hook `dlopen`, `dlsym`, 以及动态链接器内部处理重定位的函数。

以下是一个 Frida hook 示例，用于监控 `dlopen` 函数的调用，并尝试读取加载的共享库的 ELF 头部信息：

```javascript
// attach to the target process
function hook_dlopen() {
    const dlopenPtr = Module.getExportByName(null, "dlopen");
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onEnter: function (args) {
                const filename = args[0].readCString();
                console.log(`[+] dlopen called with: ${filename}`);
                this.filename = filename;
            },
            onLeave: function (retval) {
                if (retval.isNull()) {
                    console.log(`[-] dlopen failed for: ${this.filename}`);
                    return;
                }
                const handle = retval;
                console.log(`[+] dlopen returned handle: ${handle}`);

                // 尝试读取 ELF 头部 (假设目标架构是 64 位)
                const elfHeaderPtr = handle; // 假设句柄就是加载基址
                try {
                    const magic = elfHeaderPtr.readU32();
                    if (magic === 0x464c457f) { // 0x7F 'E' 'L' 'F'
                        console.log("[+] Found ELF magic!");
                        const e_type = elfHeaderPtr.add(0x10).readU16();
                        const e_machine = elfHeaderPtr.add(0x12).readU16();
                        console.log(`    e_type: ${e_type}`);
                        console.log(`    e_machine: ${e_machine}`);
                        // 可以继续读取其他 ELF 头部字段
                    } else {
                        console.log("[-] ELF magic not found.");
                    }
                } catch (e) {
                    console.log(`[-] Error reading ELF header: ${e}`);
                }
            }
        });
    } else {
        console.log("[-] dlopen not found!");
    }
}

function main() {
    console.log("Starting Frida script");
    hook_dlopen();
}

setImmediate(main);
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_dlopen.js`).
2. 使用 Frida 连接到目标 Android 进程:
   ```bash
   frida -U -f <package_name> -l hook_dlopen.js --no-pause
   # 或者对于正在运行的进程
   frida -U <process_name_or_pid> -l hook_dlopen.js
   ```

这个示例会 hook `dlopen` 函数，并在每次调用时打印加载的共享库名称和返回的句柄。然后，它会尝试读取该句柄指向的内存，并解析 ELF 头部，验证是否为有效的 ELF 文件。通过这种方式，可以观察动态链接器加载共享库的过程，并进一步 hook 其他相关函数来分析重定位和符号解析的步骤。

请注意，直接读取内存地址需要谨慎，并要确保目标地址是有效的。上面的示例只是一个简单的演示，实际调试中可能需要更精细的地址计算和错误处理。

### 提示词
```
这是目录为bionic/libc/include/elf.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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

#include <sys/cdefs.h>

#include <linux/elf.h>
#include <linux/elf-em.h>
#undef EI_PAD

#include <bits/auxvec.h>
#include <bits/elf_common.h>

/* http://www.sco.com/developers/gabi/latest/ch4.intro.html */
typedef __u64 Elf32_Xword;
typedef __s64 Elf32_Sxword;

typedef struct {
  __u32 a_type;
  union {
    __u32 a_val;
  } a_un;
} Elf32_auxv_t;

typedef struct {
  __u64 a_type;
  union {
    __u64 a_val;
  } a_un;
} Elf64_auxv_t;

/* http://www.sco.com/developers/gabi/latest/ch4.sheader.html */
typedef struct {
  Elf32_Word ch_type;
  Elf32_Word ch_size;
  Elf32_Word ch_addralign;
} Elf32_Chdr;
typedef struct {
  Elf64_Word ch_type;
  Elf64_Word ch_reserved;
  Elf64_Xword ch_size;
  Elf64_Xword ch_addralign;
} Elf64_Chdr;

typedef struct {
  Elf32_Word l_name;
  Elf32_Word l_time_stamp;
  Elf32_Word l_checksum;
  Elf32_Word l_version;
  Elf32_Word l_flags;
} Elf32_Lib;
typedef struct {
  Elf64_Word l_name;
  Elf64_Word l_time_stamp;
  Elf64_Word l_checksum;
  Elf64_Word l_version;
  Elf64_Word l_flags;
} Elf64_Lib;

typedef struct {
  Elf32_Xword m_value;
  Elf32_Word m_info;
  Elf32_Word m_poffset;
  Elf32_Half m_repeat;
  Elf32_Half m_stride;
} Elf32_Move;
typedef struct {
  Elf64_Xword m_value;
  Elf64_Xword m_info;
  Elf64_Xword m_poffset;
  Elf64_Half m_repeat;
  Elf64_Half m_stride;
} Elf64_Move;

typedef __u16 Elf32_Section;
typedef __u16 Elf64_Section;

typedef struct {
  Elf32_Half si_boundto;
  Elf32_Half si_flags;
} Elf32_Syminfo;
typedef struct {
  Elf64_Half si_boundto;
  Elf64_Half si_flags;
} Elf64_Syminfo;

typedef Elf32_Half Elf32_Versym;
typedef Elf64_Half Elf64_Versym;

typedef struct {
  Elf32_Half vd_version;
  Elf32_Half vd_flags;
  Elf32_Half vd_ndx;
  Elf32_Half vd_cnt;
  Elf32_Word vd_hash;
  Elf32_Word vd_aux;
  Elf32_Word vd_next;
} Elf32_Verdef;

typedef struct {
  Elf32_Word vda_name;
  Elf32_Word vda_next;
} Elf32_Verdaux;

typedef struct {
  Elf64_Half vd_version;
  Elf64_Half vd_flags;
  Elf64_Half vd_ndx;
  Elf64_Half vd_cnt;
  Elf64_Word vd_hash;
  Elf64_Word vd_aux;
  Elf64_Word vd_next;
} Elf64_Verdef;

typedef struct {
  Elf64_Word vda_name;
  Elf64_Word vda_next;
} Elf64_Verdaux;

typedef struct {
  Elf32_Half vn_version;
  Elf32_Half vn_cnt;
  Elf32_Word vn_file;
  Elf32_Word vn_aux;
  Elf32_Word vn_next;
} Elf32_Verneed;

typedef struct {
  Elf32_Word vna_hash;
  Elf32_Half vna_flags;
  Elf32_Half vna_other;
  Elf32_Word vna_name;
  Elf32_Word vna_next;
} Elf32_Vernaux;

typedef struct {
  Elf64_Half vn_version;
  Elf64_Half vn_cnt;
  Elf64_Word vn_file;
  Elf64_Word vn_aux;
  Elf64_Word vn_next;
} Elf64_Verneed;

typedef struct {
  Elf64_Word vna_hash;
  Elf64_Half vna_flags;
  Elf64_Half vna_other;
  Elf64_Word vna_name;
  Elf64_Word vna_next;
} Elf64_Vernaux;

/* Relocation table entry for relative (in section of type SHT_RELR). */
typedef Elf32_Word Elf32_Relr;
typedef Elf64_Xword Elf64_Relr;

/* http://www.sco.com/developers/gabi/latest/ch5.dynamic.html */

#define DF_1_NOW        0x00000001 /* Perform complete relocation processing. */
#define DF_1_GROUP      0x00000004
#define DF_1_INITFIRST  0x00000020
#define DF_1_DIRECT     0x00000100
#define DF_1_TRANS      0x00000200
#define DF_1_NODUMP     0x00001000 /* Object cannot be dumped with dldump(3) */
#define DF_1_CONFALT    0x00002000
#define DF_1_ENDFILTEE  0x00004000
#define DF_1_DISPRELDNE 0x00008000
#define DF_1_DISPRELPND 0x00010000
#define DF_1_NODIRECT   0x00020000
#define DF_1_IGNMULDEF  0x00040000 /* Internal use */
#define DF_1_NOKSYMS    0x00080000 /* Internal use */
#define DF_1_NOHDR      0x00100000 /* Internal use */
#define DF_1_EDITED     0x00200000
#define DF_1_NORELOC    0x00400000 /* Internal use */
#define DF_1_SYMINTPOSE 0x00800000
#define DF_1_GLOBAUDIT  0x01000000
#define DF_1_SINGLETON  0x02000000
#define DF_1_STUB       0x04000000

/* http://www.sco.com/developers/gabi/latest/ch4.reloc.html */
#define ELF32_R_INFO(sym, type) ((((Elf32_Word)sym) << 8) | ((type) & 0xff))
#define ELF64_R_INFO(sym, type) ((((Elf64_Xword)sym) << 32) | ((type) & 0xffffffff))

/* http://www.sco.com/developers/gabi/latest/ch4.symtab.html */
#define ELF_ST_INFO(b,t) (((b) << 4) + ((t) & 0xf))
#define ELF32_ST_INFO(b,t) ELF_ST_INFO(b,t)
#define ELF64_ST_INFO(b,t) ELF_ST_INFO(b,t)

/* http://www.sco.com/developers/gabi/latest/ch4.sheader.html */
#define GRP_MASKOS   0x0ff00000
#define GRP_MASKPROC 0xf0000000

/* http://www.sco.com/developers/gabi/latest/ch4.sheader.html */
/*
 * Standard replacement for SHT_ANDROID_RELR.
 */
#define SHT_RELR 19
#undef SHT_NUM
#define SHT_NUM 20

/*
 * Experimental support for SHT_RELR sections. For details, see proposal
 * at https://groups.google.com/forum/#!topic/generic-abi/bX460iggiKg.
 *
 * This was eventually replaced by SHT_RELR and DT_RELR (which are identical
 * other than their different constants), but those constants are only
 * supported by the OS in API levels >= 30.
 */
#define SHT_ANDROID_RELR 0x6fffff00
#define DT_ANDROID_RELR 0x6fffe000
#define DT_ANDROID_RELRSZ 0x6fffe001
#define DT_ANDROID_RELRENT 0x6fffe003
#define DT_ANDROID_RELRCOUNT 0x6fffe005

/*
 * Android compressed REL/RELA sections. These were generated by the relocation
 * packer in old versions of Android, and can be generated directly by lld
 * with https://reviews.llvm.org/D39152.
 *
 * This was replaced by SHT_ANDROID_RELR in API level 28 (but is supported
 * in all API levels >= 23).
 */
#define SHT_ANDROID_REL 0x60000001
#define SHT_ANDROID_RELA 0x60000002
#define DT_ANDROID_REL 0x6000000f // DT_LOOS + 2
#define DT_ANDROID_RELSZ 0x60000010 // DT_LOOS + 3
#define DT_ANDROID_RELA 0x60000011 // DT_LOOS + 4
#define DT_ANDROID_RELASZ 0x60000012 // DT_LOOS + 5

/* arm64 psabi. */

/* TODO: upstreamed to FreeBSD as https://github.com/freebsd/freebsd-src/pull/1141/. */
#define DT_AARCH64_MEMTAG_MODE 0x70000009
#define DT_AARCH64_MEMTAG_HEAP 0x7000000b
#define DT_AARCH64_MEMTAG_STACK 0x7000000c
#define DT_AARCH64_MEMTAG_GLOBALS 0x7000000d
#define DT_AARCH64_MEMTAG_GLOBALSSZ 0x7000000f

/* Linux traditionally doesn't have the trailing 64 that BSD has on these. */
#define R_AARCH64_TLS_DTPREL R_AARCH64_TLS_DTPREL64
#define R_AARCH64_TLS_DTPMOD R_AARCH64_TLS_DTPMOD64
#define R_AARCH64_TLS_TPREL R_AARCH64_TLS_TPREL64

/* TODO: upstream these to FreeBSD? */
#define R_ARM_TLS_DESC 13
#define R_ARM_IRELATIVE 160

/* riscv64 psabi. */

/*
 * https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#relocations
 * Missing from FreeBSD and the Linux uapi headers.
 * TODO: upstreamed to FreeBSD as https://github.com/freebsd/freebsd-src/pull/1141.
 */
#define R_RISCV_TLSDESC 12
#define R_RISCV_TLSDESC_HI20 62
#define R_RISCV_TLSDESC_LOAD_LO12 63
#define R_RISCV_TLSDESC_ADD_LO12 64
#define R_RISCV_TLSDESC_CALL 65

/* https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#program-header-table */
#define PT_RISCV_ATTRIBUTES 0x70000003

/* https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#section-types */
#define SHT_RISCV_ATTRIBUTES 0x70000003

/* FreeBSD spells this slightly differently to Linux. Linux is correct according to
 * https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/master/riscv-elf.adoc#file-header
 * so I've sent https://github.com/freebsd/freebsd-src/pull/1148 upstream.
 */
#define EF_RISCV_FLOAT_ABI EF_RISCV_FLOAT_ABI_MASK

/* FreeBSD spells this slightly differently to Linux. */
#define R_X86_64_JUMP_SLOT R_X86_64_JMP_SLOT
```