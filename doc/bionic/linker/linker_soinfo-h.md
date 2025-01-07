Response:
我的目标是全面分析 `bionic/linker/linker_soinfo.h` 文件的功能，并结合 Android 的上下文进行解释。以下是我的思考过程：

1. **理解文件定位和作用:** 首先，我注意到文件路径 `bionic/linker/linker_soinfo.handroid bionic` 以及提供的上下文 "bionic is Android's C library, math library, and dynamic linker"。 这立刻让我意识到，这是一个关于动态链接器核心数据结构定义的文件。 `soinfo` 很可能代表 "shared object info"，存储了关于加载的共享库的关键信息。

2. **宏定义分析:**  我开始查看文件中的宏定义（`#define`），例如 `FLAG_LINKED`, `FLAG_EXE`, `FLAG_LINKER` 等。 这些标志位暗示了 `soinfo` 结构体内部会用一个字段来记录共享库的不同状态，比如是否已链接、是否是主执行文件、是否是链接器自身等等。  这些标志可以帮助理解动态链接器在加载和管理共享库时的各种状态。

3. **类型定义和结构体初步分析:**  接下来，我关注了 `typedef` 定义，比如 `linker_dtor_function_t` 和 `linker_ctor_function_t`。 这表明 `soinfo` 结构体很可能包含指向构造函数和析构函数的指针，这对于理解共享库的初始化和清理过程至关重要。

4. **`SymbolLookupLib` 和 `SymbolLookupList`:**  这两个结构体的出现让我意识到符号查找是动态链接器的核心功能之一。 `SymbolLookupLib` 包含用于符号查找的各种数据结构，比如哈希表、字符串表和符号表。 `SymbolLookupList` 则封装了需要搜索的库的列表。这暗示了链接器在解析符号引用时需要在一个或多个共享库中查找。

5. **`SymbolName` 结构体:**  这个结构体明显用于表示符号的名字，并且包含 ELF 和 GNU 两种哈希值。这表明链接器可能支持不同的哈希算法来加速符号查找。

6. **`version_info` 结构体:**  这个结构体与符号的版本控制相关。它包含了符号的哈希值和目标 `soinfo` 指针，这表明链接器需要处理不同版本的符号。

7. **核心结构体 `soinfo` 的深入分析:** 这是整个文件的核心。我逐个查看 `soinfo` 的成员变量，并思考它们的作用：
    * **ELF header 信息:** `phdr`, `phnum`, `base`, `size`, `dynamic` 等成员显然存储了从 ELF 文件头读取的关键信息。
    * **链接信息:** `next` 指针用于维护已加载共享库的链表。
    * **符号表信息:** `strtab_`, `symtab_`, `bucket_`, `chain_` 等成员存储了符号表的各种数据结构。
    * **重定位信息:** `plt_rela_`, `rela_`, `plt_rel_`, `rel_` 等成员用于存储重定位表的信息。
    * **构造/析构函数:** `preinit_array_`, `init_array_`, `fini_array_`, `init_func_`, `fini_func_` 存储了构造和析构函数的指针。
    * **引用计数:** `ref_count_` 用于跟踪共享库的引用次数，这对于确定何时可以卸载库非常重要。
    * **链接映射:** `link_map_head` 用于提供与 `ld.so` 兼容的链接映射信息。
    * **加载基址:** `load_bias` 是加载共享库时的地址偏移。
    * **版本控制信息:** `versym_`, `verdef_ptr_`, `verneed_ptr_` 等成员用于处理符号版本控制。
    * **命名空间信息:** `primary_namespace_`, `secondary_namespaces_` 用于支持 Android 的命名空间隔离。
    * **TLS 信息:** `tls_` 存储了线程局部存储的信息。
    * **内存标记信息:** `memtag_dynamic_entries_` 用于支持内存标记功能（MTE）。
    * **其他标志和状态:**  如 `constructors_called`, `has_DT_SYMBOLIC` 等。

8. **`soinfo` 的成员函数分析:**  我查看了 `soinfo` 的公共成员函数，并尝试理解它们的功能：
    * **构造和析构:**  `soinfo()` 和 `~soinfo()` 用于创建和销毁 `soinfo` 对象。
    * **构造/析构函数调用:** `call_constructors()`, `call_destructors()`, `call_pre_init_constructors()` 用于执行共享库的初始化和清理代码。
    * **链接过程:** `prelink_image()`, `link_image()`  是动态链接的核心步骤。
    * **符号查找:** `find_symbol_by_name()`, `find_symbol_by_address()`, `resolve_symbol_address()` 用于查找符号。
    * **其他访问器和修改器:** 许多 `get_` 和 `set_` 函数用于访问和修改 `soinfo` 的内部状态。
    * **命名空间管理:** `get_primary_namespace()`, `add_secondary_namespace()`.
    * **引用计数管理:** `increment_ref_count()`, `decrement_ref_count()`.
    * **内存标记管理:** `tag_globals()`, `apply_memtag_if_mte_globals()`.

9. **关联 Android 功能:**  我思考了 `soinfo` 中的哪些信息和功能与 Android 的特性相关：
    * **命名空间隔离:** `primary_namespace_` 和 `secondary_namespaces_` 直接支持 Android 的应用隔离机制。
    * **NDK:** NDK 开发的共享库会被加载和管理，因此 `soinfo` 是 NDK 应用运行的基础。
    * **内存标记 (MTE):** `memtag_dynamic_entries_`  支持 Android 的内存安全特性。
    * **动态加载 (dlopen/dlsym/dlclose):**  `soinfo` 结构体存储的信息是 `dlopen` 加载库后进行符号查找的基础。

10. **考虑链接过程:** 我根据 `soinfo` 的成员变量和函数，推测动态链接的过程：
    * 加载 ELF 文件，解析头部信息，创建 `soinfo` 对象。
    * 处理 `DT_NEEDED` 条目，加载依赖的共享库。
    * 解析符号表和重定位表。
    * 进行符号查找和重定位，解决符号引用。
    * 调用构造函数进行初始化。

11. **思考使用错误:** 我考虑了开发者在使用动态链接时可能遇到的错误，例如找不到符号、版本冲突、循环依赖等。

12. **Frida Hook 示例 (初步想法):**  我意识到可以使用 Frida Hook 来拦截 `soinfo` 的创建、链接过程、符号查找等关键步骤，以便进行调试和分析。

13. **组织答案:** 最后，我开始组织答案，将以上分析结果按照问题要求的顺序进行排列，力求清晰、完整、并提供具体的例子。  我特别注意详细解释 libc 函数（虽然文件中没有直接的 libc 函数实现，但可以解释其交互），并提供 so 布局样本和链接处理过程的抽象描述。

通过以上思考过程，我能够逐步理解 `linker_soinfo.h` 文件的作用和内部机制，并将其与 Android 的相关功能联系起来。  在撰写答案的过程中，我不断回顾代码，确保我的解释是准确的，并且能够回答问题的所有方面。
这是一个定义了 `soinfo` 结构体的头文件，该结构体是 Android 动态链接器的核心数据结构之一。`soinfo` 包含了动态链接器加载、链接和管理共享库（shared objects，.so 文件）所需的所有关键信息。

**`linker_soinfo.h` 的主要功能：**

1. **定义 `soinfo` 结构体:** 这是该文件的核心功能。`soinfo` 结构体用于表示一个已加载或即将加载的共享库。它包含了库的各种元数据，例如：
    * **ELF 文件头信息:** 程序头表 (`phdr`)，程序头数量 (`phnum`)，加载基址 (`base`)，大小 (`size`)，动态链接段 (`dynamic`)。
    * **链接信息:** 指向下一个 `soinfo` 的指针 (`next`)，引用计数 (`ref_count_`)，子库和父库列表 (`children_`, `parents_`)。
    * **符号表信息:** 字符串表 (`strtab_`)，符号表 (`symtab_`)，哈希表 (`bucket_`, `chain_`)，GNU 哈希表信息 (`gnu_bucket_`, `gnu_chain_`, `gnu_maskwords_`, `gnu_shift2_`, `gnu_bloom_filter_`)。
    * **重定位信息:** PLT 和普通重定位表的信息 (`plt_rela_`, `plt_rela_count_`, `rela_`, `rela_count_` 或 `plt_rel_`, `plt_rel_count_`, `rel_`, `rel_count_`)。
    * **构造和析构函数:**  `preinit_array_`, `init_array_`, `fini_array_`, `init_func_`, `fini_func_`。
    * **链接状态标志:**  例如 `FLAG_LINKED`，`FLAG_EXE`，`FLAG_LINKER` 等，用于标记库的不同状态。
    * **版本信息:** 版本符号表 (`versym_`)，版本定义和需求信息 (`verdef_ptr_`, `verdef_cnt_`, `verneed_ptr_`, `verneed_cnt_`)。
    * **命名空间信息:** 所属的命名空间 (`primary_namespace_`, `secondary_namespaces_`)。
    * **线程局部存储 (TLS) 信息:**  `tls_`。
    * **内存标记 (MTE) 信息:**  `memtag_dynamic_entries_`。
    * **其他信息:** soname，realpath，加载偏移，目标 SDK 版本等。

2. **定义辅助结构体和类型:**
    * **`SymbolLookupLib`:** 用于表示在符号查找过程中需要搜索的单个库的信息。
    * **`SymbolLookupList`:** 用于表示在符号查找过程中需要搜索的库的列表。
    * **`SymbolName`:**  用于表示符号名称及其哈希值。
    * **`version_info`:** 用于表示符号的版本信息。
    * **函数指针类型:** `linker_dtor_function_t`, `linker_ctor_function_t`。

3. **定义常量标志:** 例如 `FLAG_LINKED`，`FLAG_EXE` 等，用于表示 `soinfo` 的状态。

4. **声明内联函数和工具函数:** 例如 `call_ifunc_resolver`，`calculate_elf_hash`，`fix_dt_needed`，`for_each_dt_needed`，`soinfo_do_lookup`。

**与 Android 功能的关系及举例说明：**

`soinfo` 结构体是 Android 动态链接器实现其核心功能的基石。以下是一些关键的联系：

* **加载共享库 (.so 文件):** 当 Android 系统需要加载一个共享库时（例如，通过 `System.loadLibrary()` 或 `dlopen()`），链接器会读取该库的 ELF 文件头信息，并创建一个 `soinfo` 结构体来存储这些信息。这个 `soinfo` 对象就代表了这个加载的库。
    * **例子:** 当一个 Java 应用调用 `System.loadLibrary("mylib")` 时，Android Framework 会通过 JNI 调用到 native 代码，最终由动态链接器负责加载 `libmylib.so`。链接器会为 `libmylib.so` 创建一个 `soinfo` 结构体。

* **解析依赖关系:** ELF 文件的动态链接段 (`DT_NEEDED` 条目) 列出了当前库依赖的其他库。链接器会遍历这些依赖项，并为每个依赖项创建一个 `soinfo` 结构体并加载。
    * **例子:** 如果 `libmylib.so` 依赖于 `libcutils.so`，那么在加载 `libmylib.so` 的过程中，链接器会读取其 `DT_NEEDED` 条目，发现 `libcutils.so`，然后加载 `libcutils.so` 并为其创建 `soinfo`。

* **符号查找和重定位:** 当程序需要调用共享库中的函数或访问全局变量时，链接器需要找到这些符号的地址。`soinfo` 结构体中存储的符号表、哈希表等信息用于快速查找符号。重定位过程则会修改代码和数据段中的地址引用，使其指向正确的符号地址。
    * **例子:**  在 `libmylib.so` 中调用 `libcutils.so` 中的 `property_get()` 函数时，链接器会使用 `libmylib.so` 和 `libcutils.so` 的 `soinfo` 结构体中的符号表信息来找到 `property_get()` 的地址，并更新 `libmylib.so` 中的调用指令。

* **调用构造函数和析构函数:** 共享库通常包含初始化和清理代码，分别在加载和卸载时执行。`soinfo` 结构体存储了这些构造函数和析构函数的地址，链接器负责在合适的时机调用它们。
    * **例子:**  `libmylib.so` 可能包含一个使用 `__attribute__((constructor))` 修饰的函数，用于初始化一些全局状态。链接器会在成功加载 `libmylib.so` 后，读取其 `soinfo` 中的 `init_array_` 并调用该构造函数。

* **支持命名空间隔离:** Android 使用链接器命名空间来隔离不同应用或进程加载的共享库，防止符号冲突。`soinfo` 结构体中的 `primary_namespace_` 和 `secondary_namespaces_` 成员用于管理库所属的命名空间。
    * **例子:** 两个不同的应用可能都依赖于同一个名字的共享库，但是链接器会将它们加载到不同的命名空间中，并创建不同的 `soinfo` 对象，从而避免符号冲突。

* **内存标记 (MTE):**  对于支持内存标记扩展 (MTE) 的设备，`soinfo` 结构体可以存储与 MTE 相关的元数据 (`memtag_dynamic_entries_`)，用于在加载时对全局变量进行标记，以检测内存安全漏洞。

**详细解释 libc 函数的功能是如何实现的：**

该头文件本身**不包含** libc 函数的实现。它定义了动态链接器使用的数据结构，而 libc 函数的实现位于 bionic 的其他源文件中 (通常在 `bionic/libc/` 目录下)。

`soinfo` 结构体在动态链接器加载和链接共享库的过程中会与 libc 函数进行交互。例如：

* **内存管理函数 (`malloc`, `free`, `mmap`, `munmap`):** 动态链接器使用这些 libc 函数来分配和管理加载共享库所需的内存空间。
* **文件操作函数 (`open`, `close`, `read`, `lseek`, `fstat`):** 动态链接器使用这些函数来读取共享库的 ELF 文件内容。
* **字符串操作函数 (`strcmp`, `strcpy`, `strlen` 等):**  在解析 ELF 文件头、处理符号名等过程中会使用这些函数。
* **线程同步函数 (例如，mutexes, condition variables):** 动态链接器在多线程环境下需要使用这些函数来保证数据结构的一致性。
* **TLS 相关函数 (`pthread_key_create`, `pthread_getspecific`, `pthread_setspecific`):**  用于处理共享库的线程局部存储。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

**SO 布局样本:**

一个典型的共享库的 ELF 文件布局如下（简化）：

```
ELF Header
Program Headers (描述内存段，例如 .text, .data, .dynamic)
Section Headers (描述各个 section，例如 .symtab, .strtab, .rel.dyn, .rela.plt)

.text section (代码段)
.rodata section (只读数据段)
.data section (可读写数据段)
.bss section (未初始化数据段)
.dynamic section (动态链接信息，例如 DT_NEEDED, DT_SYMTAB, DT_STRTAB)
.symtab section (符号表)
.strtab section (字符串表)
.rel.dyn section (动态重定位表，使用相对偏移)
.rela.plt section (PLT 重定位表，通常使用绝对地址)
... 其他 section
```

**链接的处理过程 (简化):**

1. **加载:**
   - 当需要加载一个共享库时，动态链接器首先使用 `open()` 打开 SO 文件。
   - 使用 `fstat()` 获取文件信息。
   - 使用 `mmap()` 将 SO 文件的部分或全部内容映射到内存中。
   - 创建一个 `soinfo` 结构体，并将从 ELF header 中解析出的信息（如 `phdr`, `phnum`, `base`, `size`, `dynamic`）存储到 `soinfo` 中。

2. **依赖解析:**
   - 遍历 `soinfo` 的 `dynamic` 段，查找 `DT_NEEDED` 条目。
   - 对于每个 `DT_NEEDED` 条目，递归地加载依赖的共享库，并为其创建新的 `soinfo` 结构体。
   - 维护一个已加载库的列表，避免重复加载。

3. **符号查找:**
   - 当需要解析一个符号引用时（例如，调用其他 SO 中的函数），动态链接器会按照一定的顺序搜索已加载的库。
   - 使用 `soinfo` 结构体中的符号表 (`symtab_`) 和字符串表 (`strtab_`)，以及哈希表 (`bucket_`, `chain_` 或 `gnu_bucket_`, `gnu_chain_`, `gnu_bloom_filter_`) 来快速查找符号。
   - 如果使用了版本控制，还会查找 `versym_` 表来匹配符号的版本。

4. **重定位:**
   - 遍历 `soinfo` 的重定位表 (`.rel.dyn` 和 `.rela.plt` section)。
   - 对于每个重定位条目，根据重定位类型和符号信息，计算出需要修改的地址。
   - 将计算出的地址写入到相应的内存位置，从而将代码或数据中的符号引用绑定到实际的内存地址。
   - 对于 PLT (Procedure Linkage Table) 重定位，通常会延迟绑定，即在第一次调用时才进行重定位。

5. **构造函数调用:**
   - 加载和链接完成后，动态链接器会遍历 `soinfo` 结构体中的 `init_array_` 和 `init_func_`，并调用其中记录的构造函数。

6. **卸载:**
   - 当一个共享库不再被使用时（引用计数降为 0），动态链接器会调用其析构函数（存储在 `fini_array_` 和 `fini_func_` 中）。
   - 使用 `munmap()` 解除内存映射。
   - 销毁对应的 `soinfo` 结构体。

**假设输入与输出 (逻辑推理):**

**假设输入:**
* 加载器请求加载 `libA.so`。
* `libA.so` 的 `DT_NEEDED` 条目包含 `libB.so` 和 `libc.so`。
* `libA.so` 中调用了 `libB.so` 中的函数 `foo()`。

**输出:**
1. 创建 `libA.so` 的 `soinfo` 结构体 (`soinfo_A`)。
2. 创建 `libB.so` 的 `soinfo` 结构体 (`soinfo_B`)。
3. 创建 `libc.so` 的 `soinfo` 结构体 (`soinfo_C`)。
4. 链接器在 `soinfo_B` 的符号表中找到 `foo()` 的地址。
5. 链接器修改 `libA.so` 中调用 `foo()` 的指令，使其跳转到 `soinfo_B` 中 `foo()` 的实际地址。

**用户或编程常见的使用错误：**

1. **找不到共享库:** 在使用 `System.loadLibrary()` 或 `dlopen()` 时，指定的库名或路径不正确，导致链接器无法找到对应的 SO 文件。
    * **例子:**  `System.loadLibrary("my_lib")`，但实际的文件名是 `libmy_lib.so`，或者 SO 文件不在链接器搜索路径中。

2. **符号未定义:** 程序尝试调用或访问一个在所有已加载的共享库中都找不到的符号。
    * **例子:** `libA.so` 尝试调用 `libB.so` 中不存在的函数 `bar()`。

3. **版本冲突:** 不同的共享库依赖于同一个库的不同版本，导致符号冲突或行为不一致。
    * **例子:** `libA.so` 依赖于 `libc.so` 的版本 1，而 `libC.so` 依赖于 `libc.so` 的版本 2，可能导致符号解析错误。

4. **循环依赖:** 两个或多个共享库相互依赖，导致加载时出现死锁或无限循环。
    * **例子:** `libA.so` 依赖于 `libB.so`，而 `libB.so` 又依赖于 `libA.so`。

5. **内存错误:** 在构造函数或析构函数中发生内存泄漏或访问越界等错误。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework/NDK 到达 `soinfo` 的步骤 (以 `System.loadLibrary()` 为例):**

1. **Java 代码调用 `System.loadLibrary("mylib")`:**  应用层通过 Java 代码请求加载共享库。

2. **`Runtime.loadLibrary0()` (Java Framework):**  `System.loadLibrary()` 会委托给 `Runtime` 类的 `loadLibrary0()` 方法。

3. **`System.loadLibraryInternal()` (Native Framework):** `loadLibrary0()` 会通过 JNI 调用到 native 代码的 `System.loadLibraryInternal()` 函数（在 ART 虚拟机中）。

4. **`LoadNativeLibrary()` (ART):**  `System.loadLibraryInternal()` 调用 ART 虚拟机的 `LoadNativeLibrary()` 函数。

5. **`dlopen()` (bionic linker):** `LoadNativeLibrary()` 最终会调用 bionic 动态链接器的 `dlopen()` 函数。

6. **链接器执行加载和链接过程:** `dlopen()` 内部会执行上面描述的加载、依赖解析、符号查找、重定位等步骤。在这个过程中，会创建并操作 `soinfo` 结构体来管理加载的共享库。

**Frida Hook 示例调试步骤:**

可以使用 Frida Hook 来拦截 `dlopen()` 函数，查看其参数，并在 `dlopen()` 执行前后查看 `soinfo` 的状态。

```javascript
// Frida Hook 脚本
if (Process.platform === 'android') {
  const dlopenPtr = Module.findExportByName(null, "dlopen");
  if (dlopenPtr) {
    Interceptor.attach(dlopenPtr, {
      onEnter: function (args) {
        const path = args[0].readCString();
        const flags = args[1].toInt();
        console.log(`[dlopen] Loading library: ${path}, flags: ${flags}`);
      },
      onLeave: function (retval) {
        if (retval.isNull()) {
          console.error("[dlopen] Failed to load library.");
        } else {
          console.log(`[dlopen] Library loaded at: ${retval}`);
          // 可以尝试访问 retval 对应的 soinfo 结构体，但这需要了解 soinfo 的内存布局
          // 或者 hook 其他与 soinfo 相关的函数来获取更多信息
        }
      }
    });
  } else {
    console.error("Failed to find dlopen symbol.");
  }
}
```

**使用 Frida 运行脚本:**

1. 确保你的 Android 设备已 root，并且安装了 Frida Server。
2. 运行你的目标 Android 应用。
3. 使用 Frida 客户端连接到目标应用：`frida -U -f <your_package_name> -l your_hook_script.js --no-pause`

当你运行应用并加载共享库时，Frida 会拦截 `dlopen()` 调用，并在控制台中输出加载的库路径和标志。

**更深入的 Hook (需要更多逆向工程知识):**

要更深入地调试 `soinfo` 的操作，你可以尝试 Hook 与 `soinfo` 创建、修改和使用相关的函数，例如：

* **`create_soinfo()`:**  创建 `soinfo` 结构体的函数。
* **`link_image()`:**  执行链接过程的关键函数。
* **`find_library_internal()`:**  查找已加载库的函数。
* **`find_symbol()` 或 `soinfo::find_symbol_by_name()`:**  查找符号的函数。

Hook 这些函数需要更深入地了解动态链接器的实现细节，例如函数的名称和参数。你可以使用反汇编工具（如 IDA Pro 或 Ghidra）来分析 `linker` 模块，找到这些函数的地址和签名，然后在 Frida 中进行 Hook。

请注意，直接访问和解析 `soinfo` 结构体的内存布局是平台相关的，并且可能在不同的 Android 版本之间发生变化。因此，这种方法需要谨慎，并需要根据具体的 Android 版本进行调整。

Prompt: 
```
这是目录为bionic/linker/linker_soinfo.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2016 The Android Open Source Project
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

#include <link.h>

#include <list>
#include <memory>
#include <string>
#include <vector>

#include "async_safe/CHECK.h"
#include "linker_namespaces.h"
#include "linker_tls.h"
#include "private/bionic_elf_tls.h"
#include "private/bionic_globals.h"

#define FLAG_LINKED           0x00000001
#define FLAG_EXE              0x00000004 // The main executable
#define FLAG_LINKER           0x00000010 // The linker itself
#define FLAG_GNU_HASH         0x00000040 // uses gnu hash
#define FLAG_MAPPED_BY_CALLER 0x00000080 // the map is reserved by the caller
                                         // and should not be unmapped
#define FLAG_IMAGE_LINKED     0x00000100 // Is image linked - this is a guard on link_image.
                                         // The difference between this flag and
                                         // FLAG_LINKED is that FLAG_LINKED
                                         // means is set when load_group is
                                         // successfully loaded whereas this
                                         // flag is set to avoid linking image
                                         // when link_image called for the
                                         // second time. This situation happens
                                         // when load group is crossing
                                         // namespace boundary twice and second
                                         // local group depends on the same libraries.
#define FLAG_RESERVED         0x00000200 // This flag was set when there is at least one
                                         // outstanding thread_local dtor
                                         // registered with this soinfo. In such
                                         // a case the actual unload is
                                         // postponed until the last thread_local
                                         // destructor associated with this
                                         // soinfo is executed and this flag is
                                         // unset.
#define FLAG_PRELINKED        0x00000400 // prelink_image has successfully processed this soinfo
#define FLAG_GLOBALS_TAGGED   0x00000800 // globals have been tagged by MTE.
#define FLAG_NEW_SOINFO       0x40000000 // new soinfo format

#define SOINFO_VERSION 6

ElfW(Addr) call_ifunc_resolver(ElfW(Addr) resolver_addr);

typedef void (*linker_dtor_function_t)();
typedef void (*linker_ctor_function_t)(int, char**, char**);

// An entry within a SymbolLookupList.
struct SymbolLookupLib {
  uint32_t gnu_maskwords_ = 0;
  uint32_t gnu_shift2_ = 0;
  ElfW(Addr)* gnu_bloom_filter_ = nullptr;

  const char* strtab_;
  size_t strtab_size_;
  const ElfW(Sym)* symtab_;
  const ElfW(Versym)* versym_;

  const uint32_t* gnu_chain_;
  size_t gnu_nbucket_;
  uint32_t* gnu_bucket_;

  soinfo* si_ = nullptr;

  bool needs_sysv_lookup() const { return si_ != nullptr && gnu_bloom_filter_ == nullptr; }
};

// A list of libraries to search for a symbol.
class SymbolLookupList {
  std::vector<SymbolLookupLib> libs_;
  SymbolLookupLib sole_lib_;
  const SymbolLookupLib* begin_;
  const SymbolLookupLib* end_;
  size_t slow_path_count_ = 0;

 public:
  explicit SymbolLookupList(soinfo* si);
  SymbolLookupList(const soinfo_list_t& global_group, const soinfo_list_t& local_group);
  void set_dt_symbolic_lib(soinfo* symbolic_lib);

  const SymbolLookupLib* begin() const { return begin_; }
  const SymbolLookupLib* end() const { return end_; }
  bool needs_slow_path() const { return slow_path_count_ > 0; }
};

class SymbolName {
 public:
  explicit SymbolName(const char* name)
      : name_(name), has_elf_hash_(false), has_gnu_hash_(false),
        elf_hash_(0), gnu_hash_(0) { }

  const char* get_name() {
    return name_;
  }

  uint32_t elf_hash();
  uint32_t gnu_hash();

 private:
  const char* name_;
  bool has_elf_hash_;
  bool has_gnu_hash_;
  uint32_t elf_hash_;
  uint32_t gnu_hash_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(SymbolName);
};

struct version_info {
  constexpr version_info() : elf_hash(0), name(nullptr), target_si(nullptr) {}

  uint32_t elf_hash;
  const char* name;
  const soinfo* target_si;
};

// TODO(dimitry): remove reference from soinfo member functions to this class.
class VersionTracker;

struct soinfo_tls {
  TlsSegment segment;
  size_t module_id = kTlsUninitializedModuleId;
};

#if defined(__work_around_b_24465209__)
#define SOINFO_NAME_LEN 128
#endif

struct soinfo {
#if defined(__work_around_b_24465209__)
 private:
  char old_name_[SOINFO_NAME_LEN];
#endif
 public:
  const ElfW(Phdr)* phdr;
  size_t phnum;
#if defined(__work_around_b_24465209__)
  ElfW(Addr) unused0; // DO NOT USE, maintained for compatibility.
#endif
  ElfW(Addr) base;
  size_t size;

#if defined(__work_around_b_24465209__)
  uint32_t unused1;  // DO NOT USE, maintained for compatibility.
#endif

  ElfW(Dyn)* dynamic;

#if defined(__work_around_b_24465209__)
  uint32_t unused2; // DO NOT USE, maintained for compatibility
  uint32_t unused3; // DO NOT USE, maintained for compatibility
#endif

  soinfo* next;
 private:
  uint32_t flags_;

  const char* strtab_;
  ElfW(Sym)* symtab_;

  size_t nbucket_;
  size_t nchain_;
  uint32_t* bucket_;
  uint32_t* chain_;

#if !defined(__LP64__)
  ElfW(Addr)** unused4; // DO NOT USE, maintained for compatibility
#endif

#if defined(USE_RELA)
  ElfW(Rela)* plt_rela_;
  size_t plt_rela_count_;

  ElfW(Rela)* rela_;
  size_t rela_count_;
#else
  ElfW(Rel)* plt_rel_;
  size_t plt_rel_count_;

  ElfW(Rel)* rel_;
  size_t rel_count_;
#endif

  linker_ctor_function_t* preinit_array_;
  size_t preinit_array_count_;

  linker_ctor_function_t* init_array_;
  size_t init_array_count_;
  linker_dtor_function_t* fini_array_;
  size_t fini_array_count_;

  linker_ctor_function_t init_func_;
  linker_dtor_function_t fini_func_;

#if defined(__arm__)
 public:
  // ARM EABI section used for stack unwinding.
  uint32_t* ARM_exidx;
  size_t ARM_exidx_count;
 private:
#endif
  size_t ref_count_;
 public:
  link_map link_map_head;

  bool constructors_called;

  // When you read a virtual address from the ELF file, add this
  // value to get the corresponding address in the process' address space.
  ElfW(Addr) load_bias;

#if !defined(__LP64__)
  bool has_text_relocations;
#endif
  bool has_DT_SYMBOLIC;

 public:
  soinfo(android_namespace_t* ns, const char* name, const struct stat* file_stat,
         off64_t file_offset, int rtld_flags);
  ~soinfo();

  void call_constructors();
  void call_destructors();
  void call_pre_init_constructors();
  bool prelink_image(bool deterministic_memtag_globals = false);
  bool link_image(const SymbolLookupList& lookup_list, soinfo* local_group_root,
                  const android_dlextinfo* extinfo, size_t* relro_fd_offset);
  bool protect_relro();

  void tag_globals(bool deterministic_memtag_globals);
  ElfW(Addr) apply_memtag_if_mte_globals(ElfW(Addr) sym_addr) const;

  void add_child(soinfo* child);
  void remove_all_links();

  ino_t get_st_ino() const;
  dev_t get_st_dev() const;
  off64_t get_file_offset() const;

  uint32_t get_rtld_flags() const;
  uint32_t get_dt_flags_1() const;
  void set_dt_flags_1(uint32_t dt_flags_1);

  soinfo_list_t& get_children();
  const soinfo_list_t& get_children() const;

  soinfo_list_t& get_parents();

  const ElfW(Sym)* find_symbol_by_name(SymbolName& symbol_name, const version_info* vi) const;

  ElfW(Sym)* find_symbol_by_address(const void* addr);

  ElfW(Addr) resolve_symbol_address(const ElfW(Sym)* s) const {
    if (ELF_ST_TYPE(s->st_info) == STT_GNU_IFUNC) {
      return call_ifunc_resolver(s->st_value + load_bias);
    }

    return static_cast<ElfW(Addr)>(s->st_value + load_bias);
  }

  const char* get_string(ElfW(Word) index) const;
  bool can_unload() const;
  bool is_gnu_hash() const;

  bool inline has_min_version(uint32_t min_version __unused) const {
#if defined(__work_around_b_24465209__)
    return (flags_ & FLAG_NEW_SOINFO) != 0 && version_ >= min_version;
#else
    // If you make this return non-true in the case where
    // __work_around_b_24465209__ is not defined, you will have to change
    // memtag_dynamic_entries() and vma_names().
    return true;
#endif
  }

  const ElfW(Versym)* get_versym_table() const {
    return has_min_version(2) ? versym_ : nullptr;
  }

  bool is_linked() const;
  bool is_linker() const;
  bool is_main_executable() const;

  void set_linked();
  void set_linker_flag();
  void set_main_executable();
  void set_nodelete();

  size_t increment_ref_count();
  size_t decrement_ref_count();
  size_t get_ref_count() const;

  soinfo* get_local_group_root() const;

  void set_soname(const char* soname);
  const char* get_soname() const;
  void set_realpath(const char* path);
  const char* get_realpath() const;
  const ElfW(Versym)* get_versym(size_t n) const;
  ElfW(Addr) get_verneed_ptr() const;
  size_t get_verneed_cnt() const;
  ElfW(Addr) get_verdef_ptr() const;
  size_t get_verdef_cnt() const;

  int get_target_sdk_version() const;

  void set_dt_runpath(const char *);
  const std::vector<std::string>& get_dt_runpath() const;
  android_namespace_t* get_primary_namespace();
  void add_secondary_namespace(android_namespace_t* secondary_ns);
  android_namespace_list_t& get_secondary_namespaces();

  soinfo_tls* get_tls() const {
    return has_min_version(5) ? tls_.get() : nullptr;
  }

  void set_mapped_by_caller(bool reserved_map);
  bool is_mapped_by_caller() const;

  uintptr_t get_handle() const;
  void generate_handle();
  void* to_handle();

  SymbolLookupLib get_lookup_lib();

  void set_gap_start(ElfW(Addr) gap_start);
  ElfW(Addr) get_gap_start() const;

  void set_gap_size(size_t gap_size);
  size_t get_gap_size() const;

  const memtag_dynamic_entries_t* memtag_dynamic_entries() const {
#ifdef __aarch64__
#ifdef __work_around_b_24465209__
#error "Assuming aarch64 does not use versioned soinfo."
#endif
    return &memtag_dynamic_entries_;
#endif
    return nullptr;
  }
  void* memtag_globals() const {
    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    return entries ? entries->memtag_globals : nullptr;
  }
  size_t memtag_globalssz() const {
    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    return entries ? entries->memtag_globalssz : 0U;
  }
  bool has_memtag_mode() const {
    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    return entries ? entries->has_memtag_mode : false;
  }
  unsigned memtag_mode() const {
    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    return entries ? entries->memtag_mode : 0U;
  }
  bool memtag_heap() const {
    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    return entries ? entries->memtag_heap : false;
  }
  bool memtag_stack() const {
    const memtag_dynamic_entries_t* entries = memtag_dynamic_entries();
    return entries ? entries->memtag_stack : false;
  }

  void set_should_pad_segments(bool should_pad_segments) {
   should_pad_segments_ = should_pad_segments;
  }
  bool should_pad_segments() const { return should_pad_segments_; }
  bool should_tag_memtag_globals() const {
    return !is_linker() && memtag_globals() && memtag_globalssz() > 0 && __libc_mte_enabled();
  }
  std::list<std::string>* vma_names() {
#ifdef __aarch64__
#ifdef __work_around_b_24465209__
#error "Assuming aarch64 does not use versioned soinfo."
#endif
    return &vma_names_;
#endif
    return nullptr;
};

  void set_should_use_16kib_app_compat(bool should_use_16kib_app_compat) {
    should_use_16kib_app_compat_ = should_use_16kib_app_compat;
  }
  bool should_use_16kib_app_compat() const { return should_use_16kib_app_compat_; }

  void set_compat_relro_start(ElfW(Addr) start) { compat_relro_start_ = start; }
  ElfW(Addr) compat_relro_start() const { return compat_relro_start_; }

  void set_compat_relro_size(ElfW(Addr) size) { compat_relro_size_ = size; }
  ElfW(Addr) compat_relro_size() const { return compat_relro_start_; }

 private:
  bool is_image_linked() const;
  void set_image_linked();

  const ElfW(Sym)* gnu_lookup(SymbolName& symbol_name, const version_info* vi) const;
  const ElfW(Sym)* elf_lookup(SymbolName& symbol_name, const version_info* vi) const;
  ElfW(Sym)* gnu_addr_lookup(const void* addr);
  ElfW(Sym)* elf_addr_lookup(const void* addr);

 public:
  bool lookup_version_info(const VersionTracker& version_tracker, ElfW(Word) sym,
                           const char* sym_name, const version_info** vi);

 private:
  bool relocate(const SymbolLookupList& lookup_list);

  // This part of the structure is only available
  // when FLAG_NEW_SOINFO is set in this->flags.
  uint32_t version_;

  // version >= 0
  dev_t st_dev_;
  ino_t st_ino_;

  // dependency graph
  soinfo_list_t children_;
  soinfo_list_t parents_;

  // version >= 1
  off64_t file_offset_;
  uint32_t rtld_flags_;
  uint32_t dt_flags_1_;
  size_t strtab_size_;

  // version >= 2

  size_t gnu_nbucket_;
  uint32_t* gnu_bucket_;
  uint32_t* gnu_chain_;
  uint32_t gnu_maskwords_;
  uint32_t gnu_shift2_;
  ElfW(Addr)* gnu_bloom_filter_;

  soinfo* local_group_root_;

  uint8_t* android_relocs_;
  size_t android_relocs_size_;

  std::string soname_;
  std::string realpath_;

  const ElfW(Versym)* versym_;

  ElfW(Addr) verdef_ptr_;
  size_t verdef_cnt_;

  ElfW(Addr) verneed_ptr_;
  size_t verneed_cnt_;

  int target_sdk_version_;

  // version >= 3
  std::vector<std::string> dt_runpath_;
  android_namespace_t* primary_namespace_;
  android_namespace_list_t secondary_namespaces_;
  uintptr_t handle_;

  friend soinfo* get_libdl_info(const soinfo& linker_si);

  // version >= 4
  ElfW(Relr)* relr_;
  size_t relr_count_;

  // version >= 5
  std::unique_ptr<soinfo_tls> tls_;
  std::vector<TlsDynamicResolverArg> tlsdesc_args_;

  // version >= 6
  ElfW(Addr) gap_start_;
  size_t gap_size_;

  // __aarch64__ only, which does not use versioning.
  memtag_dynamic_entries_t memtag_dynamic_entries_;
  std::list<std::string> vma_names_;

  // Pad gaps between segments when memory mapping?
  bool should_pad_segments_ = false;

  // Use app compat mode when loading 4KiB max-page-size ELFs on 16KiB page-size devices?
  bool should_use_16kib_app_compat_ = false;

  // RELRO region for 16KiB compat loading
  ElfW(Addr) compat_relro_start_ = 0;
  ElfW(Addr) compat_relro_size_ = 0;
};

// This function is used by dlvsym() to calculate hash of sym_ver
uint32_t calculate_elf_hash(const char* name);

const char* fix_dt_needed(const char* dt_needed, const char* sopath);

template<typename F>
void for_each_dt_needed(const soinfo* si, F action) {
  for (const ElfW(Dyn)* d = si->dynamic; d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_NEEDED) {
      action(fix_dt_needed(si->get_string(d->d_un.d_val), si->get_realpath()));
    }
  }
}

const ElfW(Sym)* soinfo_do_lookup(const char* name, const version_info* vi,
                                  soinfo** si_found_in, const SymbolLookupList& lookup_list);

"""

```