Response:
The user wants a summary of the functionality of the provided C++ code snippet from `bionic/linker/linker.cpp`. The snippet focuses on processing the dynamic section of an ELF file, specifically within the context of the Android dynamic linker.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Task:** The code iterates through the dynamic section (`DT_*` entries) of a shared object (`soinfo`). This immediately suggests the primary function is to extract and process information necessary for loading and linking the library.

2. **Group Functionality by Dynamic Tag:**  The `switch` statement on `d->d_tag` provides a natural way to categorize the functionalities. For each significant `DT_*` tag, identify its purpose and how it contributes to the linking process.

3. **Relate to Android's Dynamic Linking:** Consider how each extracted piece of information is used within the Android environment. This involves understanding concepts like shared libraries, symbol resolution, relocations, TLS, and security features like RELRO and MTE.

4. **Identify Key Data Structures:** Note the important data members of the `soinfo` class that are populated by this code (e.g., `strtab_`, `symtab_`, `needed_`, relocation information, etc.).

5. **Highlight Android-Specific Features:** Pay attention to `DT_ANDROID_*` tags and Android-specific implementations like the handling of text relocations for older apps and memory tagging extensions (MTE).

6. **Describe the Linking Process:** Explain how the extracted information is used in subsequent steps, such as resolving dependencies, performing relocations, and applying security protections.

7. **Address the User's Specific Requests:**
    * **Function Listing:**  Directly list the functionalities based on the dynamic tags.
    * **Android Relevance and Examples:** Connect each functionality to Android's dynamic linking mechanisms and provide examples where possible (e.g., `DT_NEEDED` for dependencies).
    * **`libc` Function Implementation:** While the code *uses* information that might be related to `libc` functions (like symbol resolution), it doesn't *implement* `libc` functions. Clarify this distinction.
    * **Dynamic Linker Functionality, SO Layout, Linking Process:** Focus on the dynamic linker's role in processing the dynamic section, the structure of a shared object (implicitly described by the `DT_*` tags), and the steps involved in linking.
    * **Logical Inference/Assumptions:** The code makes assumptions about the ELF format and the state of the system. Point out examples like assuming valid pointers after applying `load_bias`.
    * **Common Usage Errors:** While the code handles errors in the ELF file, it doesn't directly relate to *user* errors. Shift the focus to potential problems with the shared object itself.
    * **Framework/NDK to This Point:** Briefly describe the typical path from an Android app to the dynamic linker loading a library.
    * **Frida Hook Examples:**  Provide illustrative Frida examples targeting key functions within this code.
    * **Summary of Functionality (Part 4):**  Condense the detailed points into a concise summary.

8. **Structure the Response:** Organize the information logically with clear headings and bullet points for readability.

9. **Refine and Clarify:** Review the generated response to ensure accuracy, clarity, and completeness. For instance, initially, I might have focused too much on low-level ELF details. It's important to keep the answer accessible and relevant to the user's likely understanding of Android development. Emphasize the *purpose* of processing the dynamic section rather than just listing the tags. Also, be precise about what the code *does* vs. what it *facilitates*. For example, it extracts relocation information but doesn't *perform* the relocations in this specific snippet.

By following this thought process, we can generate a comprehensive and helpful answer that addresses all aspects of the user's request.
这是 `bionic/linker/linker.cpp` 文件的一部分，负责解析和处理共享库（Shared Object，SO）的动态链接信息。这段代码的主要功能是**从共享库的动态段（Dynamic Section）中提取关键信息，为后续的链接和加载过程做准备**。

**具体功能归纳:**

1. **处理 ARM 异常索引表 (仅限 ARM 架构):**
   - `able_get_arm_exidx()`:  这个函数用于获取 ARM 架构共享库的异常索引表 (`.ARM.exidx` 和 `.ARM.extab`) 的地址和大小。这些表用于在发生异常时进行栈回溯和异常处理。
   - **与 Android 功能的关系:**  Android 系统需要能够处理应用程序和库中发生的异常，这对于提供稳定的运行环境至关重要。异常索引表是实现这一目标的关键组成部分。

2. **处理线程本地存储 (TLS) 段:**
   - `__bionic_get_tls_segment()`:  检查共享库是否包含 TLS 段，并提取 TLS 段的信息，例如大小和对齐方式。
   - `__bionic_check_tls_align()`:  验证 TLS 段的对齐方式是否是 2 的幂次方。
   - **与 Android 功能的关系:**  TLS 允许每个线程拥有自己独立的全局变量副本。这在多线程应用程序中非常有用。Android 应用通常是多线程的，因此 TLS 的支持是必要的。
   - **举例说明:**  Java 的 `ThreadLocal` 类在底层就使用了 TLS 机制。当一个 Android 应用使用 `ThreadLocal` 创建线程局部变量时，动态链接器需要正确加载和初始化这些变量的存储空间。

3. **解析动态段条目 (DT_*)：**
   - 遍历动态段中的每个条目，根据 `d_tag` 的值执行不同的操作。
   - **DT_SONAME:**  提取共享库的规范名称 (Soname)。
   - **DT_HASH, DT_GNU_HASH:**  提取符号哈希表的元数据和地址，用于快速查找符号。Android 逐渐迁移到 GNU Hash。
   - **DT_STRTAB, DT_STRSZ:**  提取字符串表的地址和大小，字符串表包含了符号名称和其他字符串。
   - **DT_SYMTAB:**  提取符号表的地址，符号表包含了共享库导出的和引用的符号信息。
   - **DT_SYMENT:**  验证符号表条目的大小是否正确。
   - **DT_PLTREL, DT_JMPREL, DT_PLTRELSZ:**  提取 PLT (Procedure Linkage Table) 重定位条目的地址和数量。PLT 用于延迟绑定函数调用。
   - **DT_PLTGOT:**  虽然代码中注释为 "Ignored (because RTLD_LAZY is not supported).", 但在某些架构上可能用于 PLT/GOT (Global Offset Table) 的地址。
   - **DT_DEBUG:**  设置 `_r_debug` 的地址，用于 GDB 调试器。
   - **DT_RELA, DT_RELASZ, DT_ANDROID_RELA, DT_ANDROID_RELASZ, DT_RELAENT:** 提取 RELA 类型的重定位条目的地址、大小和条目大小。RELA 重定位包含加数。
   - **DT_REL, DT_RELSZ, DT_RELENT, DT_ANDROID_REL, DT_ANDROID_RELSZ:** 提取 REL 类型的重定位条目的地址、大小和条目大小。REL 重定位不包含加数。
   - **DT_RELR, DT_ANDROID_RELR, DT_RELRSZ, DT_ANDROID_RELRSZ, DT_RELRENT, DT_ANDROID_RELRENT:** 提取 RELR 类型的重定位条目的地址、大小和条目大小。RELR 用于只读重定位。
   - **DT_INIT:**  提取初始化函数的地址。
   - **DT_FINI:**  提取析构函数的地址。
   - **DT_INIT_ARRAY, DT_INIT_ARRAYSZ:**  提取初始化函数数组的地址和大小。
   - **DT_FINI_ARRAY, DT_FINI_ARRAYSZ:**  提取析构函数数组的地址和大小。
   - **DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ:** 提取预初始化函数数组的地址和大小（通常用于 C++ 静态对象的初始化）。
   - **DT_TEXTREL:**  指示共享库是否包含代码段重定位。在现代 Android 版本中是被禁止的，以提高安全性。
   - **DT_SYMBOLIC:**  指示链接器在查找符号时优先查找本共享库。
   - **DT_NEEDED:**  指示依赖的其他共享库的名称。
   - **DT_FLAGS:**  包含各种标志，例如 `DF_TEXTREL` 和 `DF_SYMBOLIC`。
   - **DT_FLAGS_1:**  包含更多的标志，代码中会检查并忽略不支持的标志。
   - **DT_BIND_NOW:**  已过时，被 `DF_BIND_NOW` 取代。
   - **DT_VERSYM, DT_VERDEF, DT_VERDEFNUM, DT_VERNEED, DT_VERNEEDNUM:**  提取版本控制相关的表的地址和大小，用于符号的版本管理。
   - **DT_RUNPATH:**  提取运行时库搜索路径。
   - **DT_TLSDESC_GOT, DT_TLSDESC_PLT:**  用于延迟 TLS 描述符重定位，但 Bionic 采用急切解析，因此被忽略。
   - **特定于架构的 DT_ 标记 (例如 DT_AARCH64_*)：**  处理特定于 ARM64 架构的动态标记，例如与 BTI (Branch Target Identification)、PAC (Pointer Authentication Code) 和 MTE (Memory Tagging Extension) 相关的标记。
   - **未知的 DT_ 标记:**  对于未知的动态标记，会发出警告信息。

4. **初始化 `soinfo` 结构体:**
   - 将从动态段提取的信息存储到 `soinfo` 结构体的成员变量中，例如 `strtab_`, `symtab_`, `needed_count`, 重定位相关的地址和计数等。`soinfo` 是表示一个已加载共享库的核心数据结构。

5. **执行校验:**
   - 检查关键的动态段条目是否存在，例如 `DT_HASH`/`DT_GNU_HASH`，`DT_STRTAB` 和 `DT_SYMTAB`。如果缺少这些条目，则认为共享库格式不正确。
   - 检查 `DT_SYMENT` 的值是否与 `ElfW(Sym)` 的大小一致。
   - 检查 `DT_PLTREL` 的值是否是期望的类型 (`DT_RELA` 或 `DT_REL`)。
   - 针对某些标记，例如 `DT_GNU_HASH` 的 `gnu_maskwords_`，进行有效性检查。
   - 对于重定位相关的标记，检查其条目大小是否正确。

6. **二次解析 (依赖于 strtab)：**
   - 在第一次遍历之后，当 `strtab_` 初始化后，进行第二次遍历以解析依赖于字符串表的条目，例如 `DT_SONAME` 和 `DT_RUNPATH`。

7. **处理缺少 DT_SONAME 的情况:**
   - 对于目标 SDK 版本低于 M 的应用，如果共享库缺少 `DT_SONAME`，则会使用库的文件名作为权宜之计，并发出警告。

8. **验证版本定义段:**
   - 调用 `validate_verdef_section()` 验证共享库的版本定义段是否有效。

9. **处理 MTE 全局变量 (仅限 ARM64):**
   - 如果共享库包含 MTE 全局变量并且系统支持 MTE，则会重新映射数据段，并对全局变量进行标记，以提供内存安全保护。

10. **设置 `FLAG_PRELINKED` 标志:**
    - 标记共享库已完成预链接处理。

**与 Android 功能的关系举例说明:**

* **DT_NEEDED:** 当一个应用或共享库依赖于另一个共享库时，`DT_NEEDED` 记录了被依赖库的名称。动态链接器会根据这些信息加载所需的库。例如，一个使用了 `libutils.so` 的应用，其可执行文件的动态段中会包含 `DT_NEEDED` 条目，值为 "libutils.so"。
* **DT_HASH/DT_GNU_HASH, DT_STRTAB, DT_SYMTAB:** 当动态链接器需要解析一个符号（例如函数或全局变量）的地址时，它会使用哈希表、字符串表和符号表来快速查找符号的定义。例如，当应用调用 `pthread_create` 函数时，动态链接器会在已加载的共享库中查找该符号的地址。
* **DT_RELA/DT_REL:** 这些条目描述了需要在加载时进行地址修正的位置。例如，如果一个共享库的代码中引用了另一个共享库的全局变量，那么在加载时，动态链接器需要根据实际加载地址更新这个引用的地址。
* **DT_INIT, DT_INIT_ARRAY:** 这些条目指定了在共享库加载完成后需要执行的初始化代码。例如，C++ 静态对象的构造函数通常会在这些地方被调用。

**libc 函数的实现:**

这段代码本身并不实现 `libc` 函数。它作为动态链接器的一部分，负责加载和链接共享库，这些共享库可能包含 `libc` 函数的实现。动态链接器确保在程序运行时能够找到并调用正确的 `libc` 函数。

**Dynamic Linker 功能、SO 布局样本和链接处理过程:**

**SO 布局样本 (简化):**

```
ELF Header
Program Headers (描述内存段，包括 LOAD 段)
Section Headers
.dynsym (符号表)
.dynstr (字符串表)
.hash 或 .gnu.hash (符号哈希表)
.rela.dyn 或 .rel.dyn (数据段重定位表)
.rela.plt 或 .rel.plt (PLT 重定位表)
.dynamic (动态段，包含 DT_* 条目)
... 其他段 (例如 .text, .data, .bss)
```

**链接的处理过程 (涉及此代码段):**

1. **加载 SO:**  Android 系统通过 `dlopen` 或在程序启动时加载共享库。加载器将 SO 文件映射到内存中。
2. **解析 ELF Header 和 Program Headers:**  动态链接器读取 ELF Header 和 Program Headers，确定 SO 的内存布局和加载地址。
3. **定位 Dynamic Section:**  从 Program Headers 中找到类型为 `PT_DYNAMIC` 的段，这就是动态段。
4. **解析 Dynamic Section (此代码段的功能):**  遍历动态段的条目，提取关键信息，例如依赖的库 (`DT_NEEDED`)，符号表的位置 (`DT_SYMTAB`, `DT_STRTAB`)，重定位信息 (`DT_RELA`, `DT_REL`) 等。
5. **加载依赖库:**  根据 `DT_NEEDED` 条目递归地加载所有依赖的共享库。
6. **符号解析:**  当程序需要调用一个外部函数或访问一个外部全局变量时，动态链接器会使用符号哈希表、字符串表和符号表来查找该符号的定义。
7. **重定位:**  根据重定位表中的信息，动态链接器会修改代码和数据段中的地址，以确保它们指向正确的内存位置。这包括处理代码段重定位 (在旧版本 Android 上) 和数据段/PLT 重定位。
8. **执行初始化函数:**  加载和链接完成后，动态链接器会执行 `DT_INIT` 和 `DT_INIT_ARRAY` 中指定的初始化函数。

**假设输入与输出:**

**假设输入:** 一个共享库文件的内存映射，其中包含有效的 ELF Header、Program Headers 和一个动态段。动态段中包含以下条目：

```
DT_SONAME      "libexample.so"
DT_HASH        指向哈希表的指针
DT_STRTAB      指向字符串表的指针
DT_SYMTAB      指向符号表的指针
DT_NEEDED      "libc.so"
DT_RELA        指向 RELA 重定位表的指针
DT_RELASZ      RELA 重定位表的大小
```

**逻辑推理和输出:**

- 代码会提取 `DT_SONAME` 的值 "libexample.so"，并设置 `soinfo` 的 `soname_` 成员。
- 代码会提取 `DT_HASH`，`DT_STRTAB` 和 `DT_SYMTAB` 的指针，并分别设置 `soinfo` 的 `bucket_`, `chain_`, `strtab_` 和 `symtab_` 成员。
- 代码会提取 `DT_NEEDED` 的值 "libc.so"，并增加 `soinfo` 的依赖计数。
- 代码会提取 `DT_RELA` 的指针和 `DT_RELASZ` 的大小，并设置 `soinfo` 的 `rela_` 和 `rela_count_` 成员。

**用户或编程常见的使用错误:**

* **缺少必要的动态段条目:**  如果共享库的动态段缺少关键条目 (例如 `DT_STRTAB`, `DT_SYMTAB`)，动态链接器将无法正确加载和链接该库，导致程序崩溃。
* **动态段条目值不正确:**  如果动态段中某些条目的值 (例如指针地址、大小) 不正确或指向无效的内存区域，会导致链接过程出错。
* **代码段重定位 (对于高版本 Android):**  尝试加载包含代码段重定位的共享库在 Android M 及更高版本上会被阻止，因为这被认为是不安全的。
* **依赖循环:**  如果共享库之间存在循环依赖 (例如 A 依赖 B，B 依赖 C，C 又依赖 A)，动态链接器可能无法正确加载这些库。

**Android Framework 或 NDK 如何到达这里:**

1. **应用程序启动或加载共享库:**  当 Android Framework 启动一个应用程序，或者应用程序通过 `System.loadLibrary()` 加载一个 NDK 编写的共享库时，会触发动态链接器的活动。
2. **`dlopen` 或类似调用:**  Framework 或应用程序会调用 `dlopen` (或其变体，例如 `android_dlopen_ext`) 来请求加载共享库。
3. **动态链接器介入:**  系统调用进入动态链接器 (linker)。
4. **查找 SO 文件:**  动态链接器根据库名称在预定义的路径中查找 SO 文件。
5. **加载 SO 文件:**  动态链接器将 SO 文件映射到内存中。
6. **创建 `soinfo` 结构体:**  动态链接器为该 SO 文件创建一个 `soinfo` 结构体来管理其信息。
7. **解析 ELF Header 和 Program Headers:** 动态链接器解析 SO 文件的头部信息。
8. **解析 Dynamic Section (本代码段):**  执行本代码段中的逻辑，提取动态链接信息。
9. **加载依赖库:**  根据 `DT_NEEDED` 条目加载依赖的库。
10. **符号解析和重定位:**  解析符号并执行必要的重定位操作。
11. **执行初始化函数:**  调用 SO 的初始化函数。
12. **返回 SO 句柄:**  `dlopen` 调用返回 SO 的句柄，应用程序可以使用该句柄来访问 SO 中的符号。

**Frida Hook 示例调试步骤:**

假设你想在解析 `DT_NEEDED` 条目时进行调试。

```python
import frida
import sys

package_name = "your.package.name"
lib_name = "your_ndk_library.so" # 你的 NDK 库的名字

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except Exception as e:
    print(f"Error attaching to process: {e}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "__android_dlopen_ext"), {
    onEnter: function(args) {
        var filename = Memory.readUtf8String(args[0]);
        if (filename.includes("%s")) {
            console.log("[*] __android_dlopen_ext called with:", filename);
            this.lib_base = Module.getBaseAddress(filename);
            console.log("[*] Library base address:", this.lib_base);
        }
    },
    onLeave: function(retval) {
        if (this.lib_base) {
            // 找到 soinfo::parse_dynamic_section 函数的地址
            var parse_dynamic_section_addr = null;
            Process.enumerateSymbols(this.lib_base.toString(), {
                onMatch: function(symbol) {
                    if (symbol.name.includes("soinfo::parse_dynamic_section")) {
                        parse_dynamic_section_addr = symbol.address;
                        console.log("[*] Found soinfo::parse_dynamic_section at:", parse_dynamic_section_addr);
                    }
                },
                onComplete: function() {
                    if (parse_dynamic_section_addr) {
                        Interceptor.attach(parse_dynamic_section_addr, {
                            onEnter: function(args) {
                                console.log("[*] soinfo::parse_dynamic_section called");
                                var dynamic_ptr = ptr(args[1]); // dynamic 段的地址
                                console.log("[*] Dynamic section address:", dynamic_ptr);

                                // 遍历 dynamic 段，找到 DT_NEEDED
                                var d_tag_offset = 0;
                                while (true) {
                                    var d_tag = dynamic_ptr.add(d_tag_offset).readU64();
                                    var d_val = dynamic_ptr.add(d_tag_offset + 8).readU64();

                                    if (d_tag === 1) { // DT_NEEDED 的值为 1
                                        var strtab_addr = this.context->r9; // 假设 strtab_ 在 r9 寄存器中，可能需要根据架构调整
                                        var needed_str_ptr = ptr(strtab_addr).add(d_val);
                                        var needed_lib = needed_str_ptr.readUtf8String();
                                        console.log("[*] Found DT_NEEDED:", needed_lib);
                                    } else if (d_tag === 0) { // DT_NULL，结束遍历
                                        break;
                                    }
                                    d_tag_offset += 16; // 假设 64 位 ELF
                                }
                            }
                        });
                    }
                }
            });
            this.lib_base = null; // 清理
        }
    }
});
""".replace("%s", lib_name)

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**说明:**

1. **附加到进程:**  使用 Frida 附加到目标 Android 应用程序的进程。
2. **Hook `__android_dlopen_ext`:**  Hook `__android_dlopen_ext` 函数，当加载指定的 NDK 库时记录其基地址。
3. **查找 `soinfo::parse_dynamic_section`:**  在加载库后，枚举库的符号表，找到 `soinfo::parse_dynamic_section` 函数的地址。
4. **Hook `soinfo::parse_dynamic_section`:**  Hook 这个函数，当进入该函数时，读取其参数，包括动态段的地址。
5. **遍历动态段:**  在 `soinfo::parse_dynamic_section` 的 `onEnter` 中，手动遍历动态段的条目，查找 `DT_NEEDED` 标记，并读取依赖库的名称。
6. **读取字符串表:**  需要根据架构和编译器优化等因素确定字符串表的地址。示例中假设 `strtab_` 的地址在 `r9` 寄存器中。
7. **打印信息:**  打印找到的 `DT_NEEDED` 条目的值。

**注意:**  Frida Hook 的具体实现可能需要根据目标设备的架构、Android 版本和编译器优化进行调整。寄存器使用和地址计算可能需要根据实际情况修改。

**归纳一下它的功能 (第 4 部分总结):**

这段代码是 Android Bionic 动态链接器的核心组成部分，负责解析共享库的动态段。其主要功能是：

- **提取共享库的关键元数据:**  例如 Soname、哈希表位置、字符串表位置、符号表位置等。
- **识别共享库的依赖关系:**  通过 `DT_NEEDED` 条目获取依赖的其他共享库。
- **获取重定位信息:**  提取不同类型的重定位表的地址和大小，为后续的地址修正做准备。
- **提取初始化和析构函数信息:**  获取初始化函数和析构函数的地址，以便在加载和卸载时执行。
- **处理 TLS 段信息:**  提取和验证线程本地存储段的信息。
- **处理 ARM 异常索引表 (仅限 ARM):**  获取异常处理所需的信息。
- **处理特定于架构的动态标记:**  例如 ARM64 上的 BTI、PAC 和 MTE 相关信息。
- **进行基本的有效性检查:**  确保动态段的结构和数据基本有效。

总而言之，这段代码就像一个信息提取器和验证器，它从共享库的动态段中提取构建和链接共享库所需的关键信息，为后续的动态链接过程奠定基础。

Prompt: 
```
这是目录为bionic/linker/linker.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第4部分，共4部分，请归纳一下它的功能

"""
able_get_arm_exidx(phdr, phnum, load_bias,
                                  &ARM_exidx, &ARM_exidx_count);
#endif

  TlsSegment tls_segment;
  if (__bionic_get_tls_segment(phdr, phnum, load_bias, &tls_segment)) {
    // The loader does not (currently) support ELF TLS, so it shouldn't have
    // a TLS segment.
    CHECK(!relocating_linker && "TLS not supported in loader");
    if (!__bionic_check_tls_align(tls_segment.aligned_size.align.value)) {
      DL_ERR("TLS segment alignment in \"%s\" is not a power of 2: %zu", get_realpath(),
             tls_segment.aligned_size.align.value);
      return false;
    }
    tls_ = std::make_unique<soinfo_tls>();
    tls_->segment = tls_segment;
  }

  // Extract useful information from dynamic section.
  // Note that: "Except for the DT_NULL element at the end of the array,
  // and the relative order of DT_NEEDED elements, entries may appear in any order."
  //
  // source: http://www.sco.com/developers/gabi/1998-04-29/ch5.dynamic.html
  uint32_t needed_count = 0;
  for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
    LD_DEBUG(dynamic, "dynamic entry @%p: d_tag=%p, d_val=%p",
             d, reinterpret_cast<void*>(d->d_tag), reinterpret_cast<void*>(d->d_un.d_val));
    switch (d->d_tag) {
      case DT_SONAME:
        // this is parsed after we have strtab initialized (see below).
        break;

      case DT_HASH:
        nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
        nchain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];
        bucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8);
        chain_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr + 8 + nbucket_ * 4);
        break;

      case DT_GNU_HASH:
        gnu_nbucket_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[0];
        // skip symndx
        gnu_maskwords_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[2];
        gnu_shift2_ = reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[3];

        gnu_bloom_filter_ = reinterpret_cast<ElfW(Addr)*>(load_bias + d->d_un.d_ptr + 16);
        gnu_bucket_ = reinterpret_cast<uint32_t*>(gnu_bloom_filter_ + gnu_maskwords_);
        // amend chain for symndx = header[1]
        gnu_chain_ = gnu_bucket_ + gnu_nbucket_ -
            reinterpret_cast<uint32_t*>(load_bias + d->d_un.d_ptr)[1];

        if (!powerof2(gnu_maskwords_)) {
          DL_ERR("invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
              gnu_maskwords_, get_realpath());
          return false;
        }
        --gnu_maskwords_;

        flags_ |= FLAG_GNU_HASH;
        break;

      case DT_STRTAB:
        strtab_ = reinterpret_cast<const char*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_STRSZ:
        strtab_size_ = d->d_un.d_val;
        break;

      case DT_SYMTAB:
        symtab_ = reinterpret_cast<ElfW(Sym)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_SYMENT:
        if (d->d_un.d_val != sizeof(ElfW(Sym))) {
          DL_ERR("invalid DT_SYMENT: %zd in \"%s\"",
              static_cast<size_t>(d->d_un.d_val), get_realpath());
          return false;
        }
        break;

      case DT_PLTREL:
#if defined(USE_RELA)
        if (d->d_un.d_val != DT_RELA) {
          DL_ERR("unsupported DT_PLTREL in \"%s\"; expected DT_RELA", get_realpath());
          return false;
        }
#else
        if (d->d_un.d_val != DT_REL) {
          DL_ERR("unsupported DT_PLTREL in \"%s\"; expected DT_REL", get_realpath());
          return false;
        }
#endif
        break;

      case DT_JMPREL:
#if defined(USE_RELA)
        plt_rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
#else
        plt_rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
#endif
        break;

      case DT_PLTRELSZ:
#if defined(USE_RELA)
        plt_rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
#else
        plt_rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
#endif
        break;

      case DT_PLTGOT:
        // Ignored (because RTLD_LAZY is not supported).
        break;

      case DT_DEBUG:
        // Set the DT_DEBUG entry to the address of _r_debug for GDB
        // if the dynamic table is writable
        if ((dynamic_flags & PF_W) != 0) {
          d->d_un.d_val = reinterpret_cast<uintptr_t>(&_r_debug);
        }
        break;
#if defined(USE_RELA)
      case DT_RELA:
        rela_ = reinterpret_cast<ElfW(Rela)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELASZ:
        rela_count_ = d->d_un.d_val / sizeof(ElfW(Rela));
        break;

      case DT_ANDROID_RELA:
        android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_ANDROID_RELASZ:
        android_relocs_size_ = d->d_un.d_val;
        break;

      case DT_ANDROID_REL:
        DL_ERR("unsupported DT_ANDROID_REL in \"%s\"", get_realpath());
        return false;

      case DT_ANDROID_RELSZ:
        DL_ERR("unsupported DT_ANDROID_RELSZ in \"%s\"", get_realpath());
        return false;

      case DT_RELAENT:
        if (d->d_un.d_val != sizeof(ElfW(Rela))) {
          DL_ERR("invalid DT_RELAENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      // Ignored (see DT_RELCOUNT comments for details).
      case DT_RELACOUNT:
        break;

      case DT_REL:
        DL_ERR("unsupported DT_REL in \"%s\"", get_realpath());
        return false;

      case DT_RELSZ:
        DL_ERR("unsupported DT_RELSZ in \"%s\"", get_realpath());
        return false;

#else
      case DT_REL:
        rel_ = reinterpret_cast<ElfW(Rel)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELSZ:
        rel_count_ = d->d_un.d_val / sizeof(ElfW(Rel));
        break;

      case DT_RELENT:
        if (d->d_un.d_val != sizeof(ElfW(Rel))) {
          DL_ERR("invalid DT_RELENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      case DT_ANDROID_REL:
        android_relocs_ = reinterpret_cast<uint8_t*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_ANDROID_RELSZ:
        android_relocs_size_ = d->d_un.d_val;
        break;

      case DT_ANDROID_RELA:
        DL_ERR("unsupported DT_ANDROID_RELA in \"%s\"", get_realpath());
        return false;

      case DT_ANDROID_RELASZ:
        DL_ERR("unsupported DT_ANDROID_RELASZ in \"%s\"", get_realpath());
        return false;

      // "Indicates that all RELATIVE relocations have been concatenated together,
      // and specifies the RELATIVE relocation count."
      //
      // TODO: Spec also mentions that this can be used to optimize relocation process;
      // Not currently used by bionic linker - ignored.
      case DT_RELCOUNT:
        break;

      case DT_RELA:
        DL_ERR("unsupported DT_RELA in \"%s\"", get_realpath());
        return false;

      case DT_RELASZ:
        DL_ERR("unsupported DT_RELASZ in \"%s\"", get_realpath());
        return false;

#endif
      case DT_RELR:
      case DT_ANDROID_RELR:
        relr_ = reinterpret_cast<ElfW(Relr)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_RELRSZ:
      case DT_ANDROID_RELRSZ:
        relr_count_ = d->d_un.d_val / sizeof(ElfW(Relr));
        break;

      case DT_RELRENT:
      case DT_ANDROID_RELRENT:
        if (d->d_un.d_val != sizeof(ElfW(Relr))) {
          DL_ERR("invalid DT_RELRENT: %zd", static_cast<size_t>(d->d_un.d_val));
          return false;
        }
        break;

      // Ignored (see DT_RELCOUNT comments for details).
      // There is no DT_RELRCOUNT specifically because it would only be ignored.
      case DT_ANDROID_RELRCOUNT:
        break;

      case DT_INIT:
        init_func_ = reinterpret_cast<linker_ctor_function_t>(load_bias + d->d_un.d_ptr);
        LD_DEBUG(dynamic, "%s constructors (DT_INIT) found at %p", get_realpath(), init_func_);
        break;

      case DT_FINI:
        fini_func_ = reinterpret_cast<linker_dtor_function_t>(load_bias + d->d_un.d_ptr);
        LD_DEBUG(dynamic, "%s destructors (DT_FINI) found at %p", get_realpath(), fini_func_);
        break;

      case DT_INIT_ARRAY:
        init_array_ = reinterpret_cast<linker_ctor_function_t*>(load_bias + d->d_un.d_ptr);
        LD_DEBUG(dynamic, "%s constructors (DT_INIT_ARRAY) found at %p", get_realpath(), init_array_);
        break;

      case DT_INIT_ARRAYSZ:
        init_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
        break;

      case DT_FINI_ARRAY:
        fini_array_ = reinterpret_cast<linker_dtor_function_t*>(load_bias + d->d_un.d_ptr);
        LD_DEBUG(dynamic, "%s destructors (DT_FINI_ARRAY) found at %p", get_realpath(), fini_array_);
        break;

      case DT_FINI_ARRAYSZ:
        fini_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
        break;

      case DT_PREINIT_ARRAY:
        preinit_array_ = reinterpret_cast<linker_ctor_function_t*>(load_bias + d->d_un.d_ptr);
        LD_DEBUG(dynamic, "%s constructors (DT_PREINIT_ARRAY) found at %p", get_realpath(), preinit_array_);
        break;

      case DT_PREINIT_ARRAYSZ:
        preinit_array_count_ = static_cast<uint32_t>(d->d_un.d_val) / sizeof(ElfW(Addr));
        break;

      case DT_TEXTREL:
#if defined(__LP64__)
        DL_ERR("\"%s\" has text relocations", get_realpath());
        return false;
#else
        has_text_relocations = true;
        break;
#endif

      case DT_SYMBOLIC:
        has_DT_SYMBOLIC = true;
        break;

      case DT_NEEDED:
        ++needed_count;
        break;

      case DT_FLAGS:
        if (d->d_un.d_val & DF_TEXTREL) {
#if defined(__LP64__)
          DL_ERR("\"%s\" has text relocations", get_realpath());
          return false;
#else
          has_text_relocations = true;
#endif
        }
        if (d->d_un.d_val & DF_SYMBOLIC) {
          has_DT_SYMBOLIC = true;
        }
        break;

      case DT_FLAGS_1:
        set_dt_flags_1(d->d_un.d_val);

        if ((d->d_un.d_val & ~SUPPORTED_DT_FLAGS_1) != 0) {
          DL_WARN("Warning: \"%s\" has unsupported flags DT_FLAGS_1=%p "
                  "(ignoring unsupported flags)",
                  get_realpath(), reinterpret_cast<void*>(d->d_un.d_val));
        }
        break;

      // Ignored: "Its use has been superseded by the DF_BIND_NOW flag"
      case DT_BIND_NOW:
        break;

      case DT_VERSYM:
        versym_ = reinterpret_cast<ElfW(Versym)*>(load_bias + d->d_un.d_ptr);
        break;

      case DT_VERDEF:
        verdef_ptr_ = load_bias + d->d_un.d_ptr;
        break;
      case DT_VERDEFNUM:
        verdef_cnt_ = d->d_un.d_val;
        break;

      case DT_VERNEED:
        verneed_ptr_ = load_bias + d->d_un.d_ptr;
        break;

      case DT_VERNEEDNUM:
        verneed_cnt_ = d->d_un.d_val;
        break;

      case DT_RUNPATH:
        // this is parsed after we have strtab initialized (see below).
        break;

      case DT_TLSDESC_GOT:
      case DT_TLSDESC_PLT:
        // These DT entries are used for lazy TLSDESC relocations. Bionic
        // resolves everything eagerly, so these can be ignored.
        break;

#if defined(__aarch64__)
      case DT_AARCH64_BTI_PLT:
      case DT_AARCH64_PAC_PLT:
      case DT_AARCH64_VARIANT_PCS:
        // Ignored: AArch64 processor-specific dynamic array tags.
        break;
      case DT_AARCH64_MEMTAG_MODE:
        memtag_dynamic_entries_.has_memtag_mode = true;
        memtag_dynamic_entries_.memtag_mode = d->d_un.d_val;
        break;
      case DT_AARCH64_MEMTAG_HEAP:
        memtag_dynamic_entries_.memtag_heap = d->d_un.d_val;
        break;
      // The AArch64 MemtagABI originally erroneously defined
      // DT_AARCH64_MEMTAG_STACK as `d_ptr`, which is why the dynamic tag value
      // is odd (`0x7000000c`). `d_val` is clearly the correct semantics, and so
      // this was fixed in the ABI, but the value (0x7000000c) didn't change
      // because we already had Android binaries floating around with dynamic
      // entries, and didn't want to create a whole new dynamic entry and
      // reserve a value just to fix that tiny mistake. P.S. lld was always
      // outputting DT_AARCH64_MEMTAG_STACK as `d_val` anyway.
      case DT_AARCH64_MEMTAG_STACK:
        memtag_dynamic_entries_.memtag_stack = d->d_un.d_val;
        break;
      // Same as above, except DT_AARCH64_MEMTAG_GLOBALS was incorrectly defined
      // as `d_val` (hence an even value of `0x7000000d`), when it should have
      // been `d_ptr` all along. lld has always outputted this as `d_ptr`.
      case DT_AARCH64_MEMTAG_GLOBALS:
        memtag_dynamic_entries_.memtag_globals = reinterpret_cast<void*>(load_bias + d->d_un.d_ptr);
        break;
      case DT_AARCH64_MEMTAG_GLOBALSSZ:
        memtag_dynamic_entries_.memtag_globalssz = d->d_un.d_val;
        break;
#endif

      default:
        if (!relocating_linker) {
          const char* tag_name;
          if (d->d_tag == DT_RPATH) {
            tag_name = "DT_RPATH";
          } else if (d->d_tag == DT_ENCODING) {
            tag_name = "DT_ENCODING";
          } else if (d->d_tag >= DT_LOOS && d->d_tag <= DT_HIOS) {
            tag_name = "unknown OS-specific";
          } else if (d->d_tag >= DT_LOPROC && d->d_tag <= DT_HIPROC) {
            tag_name = "unknown processor-specific";
          } else {
            tag_name = "unknown";
          }
          DL_WARN("Warning: \"%s\" unused DT entry: %s (type %p arg %p) (ignoring)",
                  get_realpath(),
                  tag_name,
                  reinterpret_cast<void*>(d->d_tag),
                  reinterpret_cast<void*>(d->d_un.d_val));
        }
        break;
    }
  }

  LD_DEBUG(dynamic, "si->base = %p, si->strtab = %p, si->symtab = %p",
           reinterpret_cast<void*>(base), strtab_, symtab_);

  // Validity checks.
  if (relocating_linker && needed_count != 0) {
    DL_ERR("linker cannot have DT_NEEDED dependencies on other libraries");
    return false;
  }
  if (nbucket_ == 0 && gnu_nbucket_ == 0) {
    DL_ERR("empty/missing DT_HASH/DT_GNU_HASH in \"%s\" "
        "(new hash type from the future?)", get_realpath());
    return false;
  }
  if (strtab_ == nullptr) {
    DL_ERR("empty/missing DT_STRTAB in \"%s\"", get_realpath());
    return false;
  }
  if (symtab_ == nullptr) {
    DL_ERR("empty/missing DT_SYMTAB in \"%s\"", get_realpath());
    return false;
  }

  // Second pass - parse entries relying on strtab. Skip this while relocating the linker so as to
  // avoid doing heap allocations until later in the linker's initialization.
  if (!relocating_linker) {
    for (ElfW(Dyn)* d = dynamic; d->d_tag != DT_NULL; ++d) {
      switch (d->d_tag) {
        case DT_SONAME:
          set_soname(get_string(d->d_un.d_val));
          break;
        case DT_RUNPATH:
          set_dt_runpath(get_string(d->d_un.d_val));
          break;
      }
    }
  }

  // Before M release, linker was using basename in place of soname. In the case when DT_SONAME is
  // absent some apps stop working because they can't find DT_NEEDED library by soname. This
  // workaround should keep them working. (Applies only for apps targeting sdk version < M.) Make
  // an exception for the main executable, which does not need to have DT_SONAME. The linker has an
  // DT_SONAME but the soname_ field is initialized later on.
  if (soname_.empty() && this != solist_get_somain() && !relocating_linker &&
      get_application_target_sdk_version() < 23) {
    soname_ = basename(realpath_.c_str());
    DL_WARN_documented_change(23, "missing-soname-enforced-for-api-level-23",
                              "\"%s\" has no DT_SONAME (will use %s instead)", get_realpath(),
                              soname_.c_str());

    // Don't call add_dlwarning because a missing DT_SONAME isn't important enough to show in the UI
  }

  // Validate each library's verdef section once, so we don't have to validate
  // it each time we look up a symbol with a version.
  if (!validate_verdef_section(this)) return false;

  // MTE globals requires remapping data segments with PROT_MTE as anonymous mappings, because file
  // based mappings may not be backed by tag-capable memory (see "MAP_ANONYMOUS" on
  // https://www.kernel.org/doc/html/latest/arch/arm64/memory-tagging-extension.html). This is only
  // done if the binary has MTE globals (evidenced by the dynamic table entries), as it destroys
  // page sharing. It's also only done on devices that support MTE, because the act of remapping
  // pages is unnecessary on non-MTE devices (where we might still run MTE-globals enabled code).
  if (should_tag_memtag_globals() &&
      remap_memtag_globals_segments(phdr, phnum, base) == 0) {
    tag_globals(dlext_use_relro);
    protect_memtag_globals_ro_segments(phdr, phnum, base);
  }

  flags_ |= FLAG_PRELINKED;
  return true;
}

bool soinfo::link_image(const SymbolLookupList& lookup_list, soinfo* local_group_root,
                        const android_dlextinfo* extinfo, size_t* relro_fd_offset) {
  if (is_image_linked()) {
    // already linked.
    return true;
  }

  if (g_is_ldd && !is_main_executable()) {
    async_safe_format_fd(STDOUT_FILENO, "\t%s => %s (%p)\n", get_soname(),
                         get_realpath(), reinterpret_cast<void*>(base));
  }

  local_group_root_ = local_group_root;
  if (local_group_root_ == nullptr) {
    local_group_root_ = this;
  }

  if ((flags_ & FLAG_LINKER) == 0 && local_group_root_ == this) {
    target_sdk_version_ = get_application_target_sdk_version();
  }

#if !defined(__LP64__)
  if (has_text_relocations) {
    // Fail if app is targeting M or above.
    int app_target_api_level = get_application_target_sdk_version();
    if (app_target_api_level >= 23) {
      DL_ERR_AND_LOG("\"%s\" has text relocations (%s#Text-Relocations-Enforced-for-API-level-23)",
                     get_realpath(), kBionicChangesUrl);
      return false;
    }
    // Make segments writable to allow text relocations to work properly. We will later call
    // phdr_table_protect_segments() after all of them are applied.
    DL_WARN_documented_change(23,
                              "Text-Relocations-Enforced-for-API-level-23",
                              "\"%s\" has text relocations",
                              get_realpath());
    add_dlwarning(get_realpath(), "text relocations");
    if (phdr_table_unprotect_segments(phdr, phnum, load_bias, should_pad_segments_,
                                      should_use_16kib_app_compat_) < 0) {
      DL_ERR("can't unprotect loadable segments for \"%s\": %m", get_realpath());
      return false;
    }
  }
#endif

  if (this != solist_get_vdso() && !relocate(lookup_list)) {
    return false;
  }

  LD_DEBUG(any, "[ finished linking %s ]", get_realpath());

#if !defined(__LP64__)
  if (has_text_relocations) {
    // All relocations are done, we can protect our segments back to read-only.
    if (phdr_table_protect_segments(phdr, phnum, load_bias, should_pad_segments_,
                                    should_use_16kib_app_compat_) < 0) {
      DL_ERR("can't protect segments for \"%s\": %m", get_realpath());
      return false;
    }
  }
#endif

  // We can also turn on GNU RELRO protection if we're not linking the dynamic linker
  // itself --- it can't make system calls yet, and will have to call protect_relro later.
  if (!is_linker() && !protect_relro()) {
    return false;
  }

  if (should_tag_memtag_globals()) {
    std::list<std::string>* vma_names_ptr = vma_names();
    // should_tag_memtag_globals -> __aarch64__ -> vma_names() != nullptr
    CHECK(vma_names_ptr);
    name_memtag_globals_segments(phdr, phnum, base, get_realpath(), vma_names_ptr);
  }

  /* Handle serializing/sharing the RELRO segment */
  if (extinfo && (extinfo->flags & ANDROID_DLEXT_WRITE_RELRO)) {
    if (phdr_table_serialize_gnu_relro(phdr, phnum, load_bias,
                                       extinfo->relro_fd, relro_fd_offset) < 0) {
      DL_ERR("failed serializing GNU RELRO section for \"%s\": %m", get_realpath());
      return false;
    }
  } else if (extinfo && (extinfo->flags & ANDROID_DLEXT_USE_RELRO)) {
    if (phdr_table_map_gnu_relro(phdr, phnum, load_bias,
                                 extinfo->relro_fd, relro_fd_offset) < 0) {
      DL_ERR("failed mapping GNU RELRO section for \"%s\": %m", get_realpath());
      return false;
    }
  }

  ++g_module_load_counter;
  notify_gdb_of_load(this);
  set_image_linked();
  return true;
}

bool soinfo::protect_relro() {
  if (should_use_16kib_app_compat_) {
    if (phdr_table_protect_gnu_relro_16kib_compat(compat_relro_start_, compat_relro_size_) < 0) {
      DL_ERR("can't enable COMPAT GNU RELRO protection for \"%s\": %s", get_realpath(),
             strerror(errno));
      return false;
    }
  } else {
    if (phdr_table_protect_gnu_relro(phdr, phnum, load_bias, should_pad_segments_,
                                     should_use_16kib_app_compat_) < 0) {
      DL_ERR("can't enable GNU RELRO protection for \"%s\": %m", get_realpath());
      return false;
    }
  }
  return true;
}

// https://github.com/ARM-software/abi-aa/blob/main/memtagabielf64/memtagabielf64.rst#global-variable-tagging
void soinfo::tag_globals(bool dlext_use_relro) {
  if (is_linked()) return;
  if (flags_ & FLAG_GLOBALS_TAGGED) return;
  flags_ |= FLAG_GLOBALS_TAGGED;

  constexpr size_t kTagGranuleSize = 16;
  const uint8_t* descriptor_stream = reinterpret_cast<const uint8_t*>(memtag_globals());

  if (memtag_globalssz() == 0) {
    DL_ERR("Invalid memtag descriptor pool size: %zu", memtag_globalssz());
  }

  uint64_t addr = load_bias;
  uleb128_decoder decoder(descriptor_stream, memtag_globalssz());
  // Don't ever generate tag zero, to easily distinguish between tagged and
  // untagged globals in register/tag dumps.
  uint64_t last_tag_mask = 1;
  uint64_t last_tag = 1;
  constexpr uint64_t kDistanceReservedBits = 3;

  while (decoder.has_bytes()) {
    uint64_t value = decoder.pop_front();
    uint64_t distance = (value >> kDistanceReservedBits) * kTagGranuleSize;
    uint64_t ngranules = value & ((1 << kDistanceReservedBits) - 1);
    if (ngranules == 0) {
      ngranules = decoder.pop_front() + 1;
    }

    addr += distance;
    void* tagged_addr;
    if (dlext_use_relro) {
      tagged_addr = reinterpret_cast<void*>(addr | (last_tag++ << 56));
      if (last_tag > (1 << kTagGranuleSize)) last_tag = 1;
    } else {
      tagged_addr = insert_random_tag(reinterpret_cast<void*>(addr), last_tag_mask);
      uint64_t tag = (reinterpret_cast<uint64_t>(tagged_addr) >> 56) & 0x0f;
      last_tag_mask = 1 | (1 << tag);
    }

    for (size_t k = 0; k < ngranules; k++) {
      auto* granule = static_cast<uint8_t*>(tagged_addr) + k * kTagGranuleSize;
      set_memory_tag(static_cast<void*>(granule));
    }
    addr += ngranules * kTagGranuleSize;
  }
}

static std::vector<android_namespace_t*> init_default_namespace_no_config(bool is_asan, bool is_hwasan) {
  g_default_namespace.set_isolated(false);
  auto default_ld_paths = is_asan ? kAsanDefaultLdPaths : (
    is_hwasan ? kHwsanDefaultLdPaths : kDefaultLdPaths);

  char real_path[PATH_MAX];
  std::vector<std::string> ld_default_paths;
  for (size_t i = 0; default_ld_paths[i] != nullptr; ++i) {
    if (realpath(default_ld_paths[i], real_path) != nullptr) {
      ld_default_paths.push_back(real_path);
    } else {
      ld_default_paths.push_back(default_ld_paths[i]);
    }
  }

  g_default_namespace.set_default_library_paths(std::move(ld_default_paths));

  std::vector<android_namespace_t*> namespaces;
  namespaces.push_back(&g_default_namespace);
  return namespaces;
}

// Given an `executable_path` starting with "/apex/<name>/bin/, return
// "/linkerconfig/<name>/ld.config.txt", which is the auto-generated config file for the APEX by the
// linkerconfig tool.
static std::string get_ld_config_file_apex_path(const char* executable_path) {
  std::vector<std::string> paths = android::base::Split(executable_path, "/");
  if (paths.size() >= 5 && paths[1] == "apex" && paths[3] == "bin") {
    std::string generated_apex_config = "/linkerconfig/" + paths[2] + "/ld.config.txt";
    if (file_exists(generated_apex_config.c_str())) {
      return generated_apex_config;
    }
  }
  return "";
}

static std::string get_ld_config_file_vndk_path() {
  if (android::base::GetBoolProperty("ro.vndk.lite", false)) {
    return kLdConfigVndkLiteFilePath;
  }

  std::string ld_config_file_vndk = kLdConfigFilePath;
  size_t insert_pos = ld_config_file_vndk.find_last_of('.');
  if (insert_pos == std::string::npos) {
    insert_pos = ld_config_file_vndk.length();
  }
  ld_config_file_vndk.insert(insert_pos, Config::get_vndk_version_string('.'));
  return ld_config_file_vndk;
}

bool is_linker_config_expected(const char* executable_path) {
  // Do not raise message from a host environment which is expected to miss generated linker
  // configuration.
#if !defined(__ANDROID__)
  return false;
#endif

  if (strcmp(executable_path, "/system/bin/init") == 0) {
    // Generated linker configuration can be missed from processes executed
    // with init binary
    return false;
  }

  return true;
}

static std::string get_ld_config_file_path(const char* executable_path) {
#ifdef USE_LD_CONFIG_FILE
  // This is a debugging/testing only feature. Must not be available on
  // production builds.
  const char* ld_config_file_env = getenv("LD_CONFIG_FILE");
  if (ld_config_file_env != nullptr && file_exists(ld_config_file_env)) {
    return ld_config_file_env;
  }
#endif

  std::string path = get_ld_config_file_apex_path(executable_path);
  if (!path.empty()) {
    if (file_exists(path.c_str())) {
      return path;
    }
    DL_WARN("Warning: couldn't read config file \"%s\" for \"%s\"",
            path.c_str(), executable_path);
  }

  path = kLdConfigArchFilePath;
  if (file_exists(path.c_str())) {
    return path;
  }

  if (file_exists(kLdGeneratedConfigFilePath)) {
    return kLdGeneratedConfigFilePath;
  }

  if (is_linker_config_expected(executable_path)) {
    DL_WARN("Warning: failed to find generated linker configuration from \"%s\"",
            kLdGeneratedConfigFilePath);
  }

  path = get_ld_config_file_vndk_path();
  if (file_exists(path.c_str())) {
    return path;
  }

  return kLdConfigFilePath;
}


std::vector<android_namespace_t*> init_default_namespaces(const char* executable_path) {
  g_default_namespace.set_name("(default)");

  soinfo* somain = solist_get_somain();

  const char *interp = phdr_table_get_interpreter_name(somain->phdr, somain->phnum,
                                                       somain->load_bias);
  const char* bname = (interp != nullptr) ? basename(interp) : nullptr;

  g_is_asan = bname != nullptr &&
              (strcmp(bname, "linker_asan") == 0 ||
               strcmp(bname, "linker_asan64") == 0);

#if defined(__aarch64__)
  // HWASan is only supported on AArch64.
  // The AT_SECURE restriction is because this is a debug feature that does
  // not need to work on secure binaries, it doesn't hurt to disallow the
  // environment variable for them, as it impacts the program execution.
  char* hwasan_env = getenv("LD_HWASAN");
  g_is_hwasan = (bname != nullptr &&
              strcmp(bname, "linker_hwasan64") == 0) ||
              (hwasan_env != nullptr && !getauxval(AT_SECURE) && strcmp(hwasan_env, "1") == 0);
#endif
  const Config* config = nullptr;

  {
    std::string ld_config_file_path = get_ld_config_file_path(executable_path);
    LD_DEBUG(any, "[ Reading linker config \"%s\" ]", ld_config_file_path.c_str());
    ScopedTrace trace(("linker config " + ld_config_file_path).c_str());
    std::string error_msg;
    if (!Config::read_binary_config(ld_config_file_path.c_str(), executable_path, g_is_asan, g_is_hwasan,
                                    &config, &error_msg)) {
      if (!error_msg.empty()) {
        DL_WARN("Warning: couldn't read '%s' for '%s' (using default configuration instead): %s",
                ld_config_file_path.c_str(), executable_path, error_msg.c_str());
      }
      config = nullptr;
    }
  }

  if (config == nullptr) {
    return init_default_namespace_no_config(g_is_asan, g_is_hwasan);
  }

  const auto& namespace_configs = config->namespace_configs();
  std::unordered_map<std::string, android_namespace_t*> namespaces;

  // 1. Initialize default namespace
  const NamespaceConfig* default_ns_config = config->default_namespace_config();

  g_default_namespace.set_isolated(default_ns_config->isolated());
  g_default_namespace.set_default_library_paths(default_ns_config->search_paths());
  g_default_namespace.set_permitted_paths(default_ns_config->permitted_paths());

  namespaces[default_ns_config->name()] = &g_default_namespace;
  if (default_ns_config->visible()) {
    g_exported_namespaces[default_ns_config->name()] = &g_default_namespace;
  }

  // 2. Initialize other namespaces

  for (auto& ns_config : namespace_configs) {
    if (namespaces.contains(ns_config->name())) {
      continue;
    }

    android_namespace_t* ns = new (g_namespace_allocator.alloc()) android_namespace_t();
    ns->set_name(ns_config->name());
    ns->set_isolated(ns_config->isolated());
    ns->set_default_library_paths(ns_config->search_paths());
    ns->set_permitted_paths(ns_config->permitted_paths());
    ns->set_allowed_libs(ns_config->allowed_libs());

    namespaces[ns_config->name()] = ns;
    if (ns_config->visible()) {
      g_exported_namespaces[ns_config->name()] = ns;
    }
  }

  // 3. Establish links between namespaces
  for (auto& ns_config : namespace_configs) {
    auto it_from = namespaces.find(ns_config->name());
    CHECK(it_from != namespaces.end());
    android_namespace_t* namespace_from = it_from->second;
    for (const NamespaceLinkConfig& ns_link : ns_config->links()) {
      auto it_to = namespaces.find(ns_link.ns_name());
      CHECK(it_to != namespaces.end());
      android_namespace_t* namespace_to = it_to->second;
      if (ns_link.allow_all_shared_libs()) {
        link_namespaces_all_libs(namespace_from, namespace_to);
      } else {
        link_namespaces(namespace_from, namespace_to, ns_link.shared_libs().c_str());
      }
    }
  }
  // we can no longer rely on the fact that libdl.so is part of default namespace
  // this is why we want to add ld-android.so to all namespaces from ld.config.txt
  soinfo* ld_android_so = solist_get_head();

  // we also need vdso to be available for all namespaces (if present)
  soinfo* vdso = solist_get_vdso();
  for (auto it : namespaces) {
    if (it.second != &g_default_namespace) {
      it.second->add_soinfo(ld_android_so);
      if (vdso != nullptr) {
        it.second->add_soinfo(vdso);
      }
      // somain and ld_preloads are added to these namespaces after LD_PRELOAD libs are linked
    }
  }

  set_application_target_sdk_version(config->target_sdk_version());

  std::vector<android_namespace_t*> created_namespaces;
  created_namespaces.reserve(namespaces.size());
  for (const auto& kv : namespaces) {
    created_namespaces.push_back(kv.second);
  }
  return created_namespaces;
}

// This function finds a namespace exported in ld.config.txt by its name.
// A namespace can be exported by setting .visible property to true.
android_namespace_t* get_exported_namespace(const char* name) {
  if (name == nullptr) {
    return nullptr;
  }
  auto it = g_exported_namespaces.find(std::string(name));
  if (it == g_exported_namespaces.end()) {
    return nullptr;
  }
  return it->second;
}

void purge_unused_memory() {
  // For now, we only purge the memory used by LoadTask because we know those
  // are temporary objects.
  //
  // Purging other LinkerBlockAllocator hardly yields much because they hold
  // information about namespaces and opened libraries, which are not freed
  // when the control leaves the linker.
  //
  // Purging BionicAllocator may give us a few dirty pages back, but those pages
  // would be already zeroed out, so they compress easily in ZRAM.  Therefore,
  // it is not worth munmap()'ing those pages.
  TypeBasedAllocator<LoadTask>::purge();
}

"""


```