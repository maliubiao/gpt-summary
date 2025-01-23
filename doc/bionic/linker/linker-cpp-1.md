Response:
My goal is to summarize the functionality of the provided C++ code snippet, which is a part of Android's dynamic linker (`linker.cpp`). Here's a breakdown of the thinking process to achieve that summary:

1. **Identify the Core Purpose:** The initial comment explicitly states the file's location and its role within Android: the dynamic linker. This immediately tells me the code is about loading and managing shared libraries (.so files).

2. **Scan for Key Function Names and Concepts:** I'll quickly read through the code, paying attention to function names and common dynamic linking terms. This helps me identify the main actions the code performs. I see functions like `open_library_at_path`, `load_library`, `find_loaded_library_by_soname`, `find_libraries`, `soinfo_unload`, etc. I also see mentions of `DT_NEEDED`, `DT_SONAME`, namespaces, and load tasks.

3. **Group Related Functionalities:**  Based on the function names and their parameters, I can start grouping related actions. For example, the functions starting with `find_loaded_library_by...` seem to be about locating already loaded libraries. `load_library` and its variations are clearly about loading libraries. `soinfo_unload` handles unloading.

4. **Infer Functionality from Code Snippets:** For each function or group of functions, I'll look at the code to understand *what* they are doing.

    * `open_library_at_path`:  The name suggests opening a library file.
    * `fix_dt_needed`: This function seems to handle potential inconsistencies in `DT_NEEDED` entries, particularly for older apps.
    * `for_each_dt_needed`: This iterates through `DT_NEEDED` entries in a library's dynamic section.
    * `find_loaded_library_by_inode`/`by_realpath`: These look for already loaded libraries using their file system identifiers or full path.
    * `load_library`: This is the core loading function. It checks for existing libraries, opens the library file, reads ELF headers, and manages dependencies. It also interacts with namespaces and load tasks.
    * `find_loaded_library_by_soname`:  Locates loaded libraries based on their "soname" (shared object name).
    * `find_library_in_linked_namespace`:  Specifically checks for libraries within linked namespaces.
    * `find_library_internal`:  A higher-level function that orchestrates the process of finding and potentially loading a library, including checking loaded libraries and linked namespaces.
    * `find_libraries`:  Handles loading multiple libraries and their dependencies, managing namespaces, and performing linking. This appears to be a crucial function for both `dlopen` and initial linking.
    * `soinfo_unload`/`soinfo_unload_impl`:  Handles unloading libraries, including calling destructors and managing dependencies.

5. **Identify Key Data Structures and Concepts:**  The code mentions `soinfo` (shared object info), `android_namespace_t`, `LoadTask`, `LoadTaskList`, `ZipArchiveCache`, and `ElfReader`. These are essential for understanding the linker's internal workings. I need to briefly mention these and their roles.

6. **Focus on the Request: Summarization:** The request specifically asks for a *summary*. This means I should focus on the high-level functionalities and avoid getting bogged down in low-level implementation details. I need to express the core functions concisely.

7. **Connect to Android Functionality (as requested):** While summarizing, I should explicitly mention how these functionalities relate to Android's dynamic linking process. For example, `dlopen`, library loading, and namespace management are all integral parts of how Android applications use shared libraries.

8. **Structure the Summary Logically:** I'll organize the summary into logical sections. A good approach is to group functionalities by their purpose (e.g., finding libraries, loading libraries, unloading libraries).

9. **Refine and Condense:** After the initial draft, I'll review the summary to ensure it is clear, concise, and accurately reflects the code's functionality. I'll remove redundant phrases and ensure the language is easy to understand. I'll double-check that I've addressed the core request of summarizing the functionality.

10. **Address the "Part 2 of 4" instruction:**  The prompt indicates this is part of a larger piece. While summarizing, I'll keep in mind that this is likely focusing on the *loading* aspect of the linker, as indicated by the prevalence of `load_library` related functions. This context helps frame the summary.

By following these steps, I can generate a comprehensive yet concise summary of the provided code, focusing on its core functionalities within the context of Android's dynamic linker.
这是 `bionic/linker/linker.cpp` 文件第二部分的功能归纳。这部分代码主要负责**查找和加载共享库**，以及处理相关的依赖关系和命名空间。

以下是详细的功能归纳：

**1. 查找已加载的共享库：**

* **`find_loaded_library_by_inode(android_namespace_t* ns, const struct stat& file_stat, off64_t file_offset, bool search_linked_namespaces, soinfo** candidate)`:**  在指定的命名空间 `ns` 中，根据文件的 inode (`file_stat.st_ino`)、设备 ID (`file_stat.st_dev`) 和文件偏移量 (`file_offset`) 查找已经加载的共享库。如果 `search_linked_namespaces` 为真，则也会在链接的命名空间中查找。
    * **与 Android 功能的关系:** 当系统尝试加载一个共享库时，会先检查是否已经加载过，避免重复加载。这有助于节省内存和提高效率。
    * **举例说明:**  当一个应用多次 `dlopen` 同一个 .so 文件时，linker 会先调用此函数检查是否已经加载，如果已加载则直接返回已加载的 `soinfo` 结构体。

* **`find_loaded_library_by_realpath(android_namespace_t* ns, const char* realpath, bool search_linked_namespaces, soinfo** candidate)`:** 在指定的命名空间 `ns` 中，根据共享库的真实路径 (`realpath`) 查找已经加载的共享库。同样，`search_linked_namespaces` 控制是否在链接的命名空间中查找。
    * **与 Android 功能的关系:** 类似于 `find_loaded_library_by_inode`，但使用文件路径进行查找。
    * **举例说明:**  如果一个库通过符号链接加载，或者有多个指向同一物理文件的路径，此函数可以根据规范化的路径找到已经加载的实例。

* **`find_loaded_library_by_soname(android_namespace_t* ns, const char* name, soinfo** candidate)`:** 在指定的命名空间 `ns` 中，根据共享库的 `soname` (Simple Name) 查找已经加载的共享库。
    * **与 Android 功能的关系:**  这是最常用的查找已加载库的方式，因为 `DT_NEEDED` 条目通常存储的是 `soname`。
    * **举例说明:**  当加载器遇到一个 `DT_NEEDED` 条目为 "libfoo.so" 时，会调用此函数在当前命名空间中查找 `soname` 为 "libfoo.so" 的库。

* **`find_loaded_library_by_soname(android_namespace_t* ns, const char* name, bool search_linked_namespaces, soinfo** candidate)`:**  扩展版本的 `find_loaded_library_by_soname`，增加了在链接的命名空间中查找的功能。
    * **与 Android 功能的关系:** 允许在不同的命名空间中共享库。
    * **举例说明:**  应用 A 的命名空间链接到系统命名空间，当应用 A 尝试加载一个系统库时，即使该库没有在应用 A 的命名空间中显式加载，也可以通过链接的命名空间找到。

**2. 加载共享库：**

* **`load_library(android_namespace_t* ns, LoadTask* task, LoadTaskList* load_tasks, int rtld_flags, const std::string& realpath, bool search_linked_namespaces)`:**  负责实际加载共享库到指定的命名空间 `ns` 中。它执行一系列检查，例如文件偏移量是否对齐、文件是否存在、是否已经加载等。还会读取 ELF 头信息，并创建新的 `soinfo` 结构体来表示加载的库。
    * **与 Android 功能的关系:** 这是 `dlopen` 等函数的核心实现部分。
    * **详细解释:**
        * **参数:**
            * `ns`: 要加载到的命名空间。
            * `task`: 一个 `LoadTask` 对象，包含了加载所需的信息，例如文件描述符、文件名等。
            * `load_tasks`: 一个 `LoadTaskList`，用于管理待加载的库及其依赖关系。
            * `rtld_flags`:  `dlopen` 函数的标志位，例如 `RTLD_NOW` 或 `RTLD_LAZY`。
            * `realpath`: 共享库的真实路径。
            * `search_linked_namespaces`:  是否搜索链接的命名空间。
        * **功能实现:**
            1. **参数校验:** 检查文件偏移量是否有效。
            2. **获取文件状态:** 使用 `fstat` 获取文件信息，例如 inode、大小等。
            3. **检查是否已加载:** 调用 `find_loaded_library_by_inode` 检查是否已经通过其他路径或名称加载过。
            4. **RTLD_NOLOAD 处理:** 如果设置了 `RTLD_NOLOAD` 且库未加载，则返回错误。
            5. **检查命名空间访问权限:**  确认当前命名空间是否有权限访问要加载的库。
            6. **分配 `soinfo`:**  为新加载的库分配 `soinfo` 结构体。
            7. **读取 ELF 头:** 从文件中读取 ELF 头和部分段的信息。
            8. **提取 DT_RUNPATH, DT_SONAME, DT_FLAGS_1:** 从动态段中提取这些信息并存储到 `soinfo` 中。
            9. **处理 DT_NEEDED:** 遍历 `DT_NEEDED` 条目，为每个依赖库创建一个新的 `LoadTask` 并添加到 `load_tasks` 列表中。

* **`load_library(android_namespace_t* ns, LoadTask* task, ZipArchiveCache* zip_archive_cache, LoadTaskList* load_tasks, int rtld_flags, bool search_linked_namespaces)`:**  `load_library` 的重载版本，处理从 APK 中的 zip 文件加载共享库的情况。它首先调用 `open_library` 获取文件描述符和偏移量，然后调用上面的 `load_library` 版本进行实际加载。
    * **与 Android 功能的关系:**  支持从 APK 中加载 native 库。
    * **详细解释:**
        * **参数:** 除了上面版本的参数外，还多了 `ZipArchiveCache* zip_archive_cache`，用于缓存 zip 文件信息。
        * **功能实现:**
            1. **处理 ANDROID_DLEXT_USE_LIBRARY_FD:** 如果 `extinfo` 中指定了文件描述符，则直接使用。
            2. **调用 `open_library`:** 否则，调用 `open_library` 函数根据库名查找并打开文件。
            3. **调用另一个 `load_library`:** 将获取到的文件描述符和偏移量传递给另一个 `load_library` 函数进行加载。

* **`open_library_at_path(ZipArchiveCache* zip_archive_cache, const char* path, off64_t* file_offset, std::string* realpath)`:**  根据给定的路径打开共享库文件，并获取文件偏移量和真实路径。如果库位于 APK 中，则使用 `ZipArchiveCache`。
    * **与 Android 功能的关系:**  处理加载指定路径的库，包括 APK 中的库。

* **`open_library(android_namespace_t* ns, ZipArchiveCache* zip_archive_cache, const char* name, soinfo* needed_by, off64_t* file_offset, std::string* realpath)`:**  在给定的命名空间 `ns` 中查找并打开指定名称的共享库。它会考虑库的搜索路径 (`ld_library_paths`) 和依赖关系 (`needed_by`)。
    * **与 Android 功能的关系:**  这是动态链接器查找库文件的核心函数。

**3. 处理依赖关系 (`DT_NEEDED`)：**

* **`for_each_dt_needed(const ElfReader& elf_reader, F action)`:** 遍历给定 ELF 文件的动态段中的 `DT_NEEDED` 条目，并对每个依赖库的名字执行 `action` 函数。
    * **与 Android 功能的关系:**  用于发现一个库依赖的其他库。
    * **详细解释:**
        * **参数:**
            * `elf_reader`:  一个 `ElfReader` 对象，用于读取 ELF 文件信息。
            * `action`: 一个函数对象，接收一个 `const char*` 参数，即依赖库的名字。
        * **功能实现:** 遍历动态段，如果遇到 `DT_NEEDED` 类型的条目，则获取其字符串值 (依赖库的名字)，并调用 `action` 函数处理。在调用 `action` 之前，会先调用 `fix_dt_needed` 对依赖库的名字进行修正。

* **`fix_dt_needed(const char* dt_needed, const char* sopath __unused)`:**  修正 `DT_NEEDED` 条目中的库名。在旧版本的 Android 中，`DT_NEEDED` 条目可能不包含完整的库文件名，此函数用于进行兼容性处理。
    * **与 Android 功能的关系:** 解决旧版本应用的兼容性问题。
    * **举例说明:**  对于 API level 小于 23 的应用，如果 `DT_NEEDED` 条目中只包含了 "foo" 而不是 "libfoo.so"，此函数会提取 "foo"。

**4. 在链接的命名空间中查找库：**

* **`find_library_in_linked_namespace(const android_namespace_link_t& namespace_link, LoadTask* task)`:** 在指定的链接命名空间中查找给定的库 (`task`)。它会检查库是否已经加载，以及该链接是否允许访问该库。
    * **与 Android 功能的关系:**  支持跨命名空间共享库。
    * **详细解释:**
        * **参数:**
            * `namespace_link`:  一个 `android_namespace_link_t` 对象，描述了命名空间之间的链接关系。
            * `task`:  一个 `LoadTask` 对象，包含了要查找的库的信息。
        * **功能实现:**
            1. **查找已加载库:** 首先尝试在链接的命名空间中查找是否已经加载了该库。
            2. **检查访问权限:**  如果未加载，则检查该链接是否允许访问该库 (根据库的 `soname`)。
            3. **设置 `soinfo`:**  如果找到已加载的库，则将 `soinfo` 设置到 `task` 中。如果未加载但允许访问，则将 `soinfo` 设置为 `nullptr`，表示可以在该命名空间加载。

**5. 核心查找库函数：**

* **`find_library_internal(android_namespace_t* ns, LoadTask* task, ZipArchiveCache* zip_archive_cache, LoadTaskList* load_tasks, int rtld_flags)`:**  这是查找库的核心逻辑函数。它首先尝试查找已加载的库，如果找不到则尝试加载该库及其依赖项。
    * **与 Android 功能的关系:**  `dlopen` 等函数内部会调用此函数来查找和加载库。
    * **详细解释:**
        * **功能实现:**
            1. **按 `soname` 查找:**  首先调用 `find_loaded_library_by_soname` 在当前命名空间及其链接的命名空间中查找。
            2. **尝试加载:** 如果找不到，则调用 `load_library` 尝试加载。
            3. **处理豁免列表 (Exempt List):**  如果库在豁免列表中，则尝试在默认命名空间中加载 (用于一些系统库)。
            4. **在链接的命名空间中查找和加载:** 如果在当前命名空间加载失败，则遍历链接的命名空间，尝试在其中查找或加载。

**6. 加载多个库及其依赖项：**

* **`find_libraries(android_namespace_t* ns, soinfo* start_with, const char* const library_names[], size_t library_names_count, soinfo* soinfos[], std::vector<soinfo*>* ld_preloads, size_t ld_preloads_count, int rtld_flags, const android_dlextinfo* extinfo, bool add_as_children, std::vector<android_namespace_t*>* namespaces)`:**  负责加载一个或多个指定的库及其所有的 `DT_NEEDED` 依赖项。它管理 `LoadTask` 列表，并按照一定的顺序加载和链接库。
    * **与 Android 功能的关系:**  这是 `dlopen` 和程序启动时加载依赖库的关键函数。
    * **详细解释:**
        * **参数:**
            * `ns`:  启动加载的命名空间。
            * `start_with`:  如果从某个已加载的库开始加载依赖项，则指向该库的 `soinfo`。
            * `library_names`:  要加载的库的名称数组。
            * `library_names_count`:  要加载的库的数量。
            * `soinfos`:  一个用于存储加载的库的 `soinfo` 指针数组。
            * `ld_preloads`:  `LD_PRELOAD` 列表。
            * `ld_preloads_count`:  `LD_PRELOAD` 的数量。
            * `rtld_flags`:  加载标志。
            * `extinfo`:  `dlopen_ext` 提供的额外信息。
            * `add_as_children`:  是否将新加载的库添加为 `start_with` 的子节点。
            * `namespaces`:  所有命名空间的列表。
        * **功能实现:**
            1. **创建 `LoadTask`:** 为每个要加载的库创建一个 `LoadTask`。
            2. **展开依赖项:**  递归地添加 `DT_NEEDED` 依赖项到 `load_tasks` 列表中。
            3. **加载库:**  遍历 `load_tasks` 列表，调用 `load_library` 加载每个库。
            4. **预链接:**  调用 `soinfo::prelink_image` 为每个加载的库进行预链接。
            5. **构建全局组:**  处理具有 `DF_1_GLOBAL` 标志的库。
            6. **链接局部组:**  处理跨命名空间边界的依赖关系，形成局部链接组。
            7. **标记为已链接并增加引用计数:**  更新 `soinfo` 的状态和引用计数。

**7. 查找单个库：**

* **`find_library(android_namespace_t* ns, const char* name, int rtld_flags, const android_dlextinfo* extinfo, soinfo* needed_by)`:**  用于查找单个库，它是 `find_libraries` 的一个简化版本。
    * **与 Android 功能的关系:**  `dlopen` 的一种实现方式。

**8. 卸载共享库：**

* **`soinfo_unload_impl(soinfo* root)`:** 负责卸载指定的共享库及其依赖项。它会调用析构函数并清理相关的资源。

**总结这部分代码的功能：**

这部分 `linker.cpp` 代码的核心功能是**动态查找和加载共享库**。它负责：

* **查找已经加载的库:** 通过 inode、路径或 `soname` 在指定的命名空间中查找。
* **加载新的共享库:** 从文件系统或 APK 中加载共享库到内存中。
* **处理库的依赖关系:** 识别和加载 `DT_NEEDED` 指明的依赖库。
* **管理命名空间:** 考虑库的加载位置和访问权限，支持跨命名空间共享库。
* **支持 `dlopen` 系列函数:**  为 `dlopen`, `dlopen_ext` 等函数提供底层实现。
* **支持程序启动时的库加载:**  负责加载程序启动时需要的共享库。

这部分代码是 Android 动态链接器的关键组成部分，确保了应用能够正确加载和使用所需的共享库。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

**so 布局样本 (简化版):**

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  ...
Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSize             MemSize              Flags  Align
  LOAD           0x0000000000000000 0x00000078b0000000 0x00000078b0000000 0x0000000000000528 0x0000000000000528  R E    1000
  LOAD           0x0000000000001000 0x00000078b0001000 0x00000078b0001000 0x00000000000001f0 0x00000000000002a8  RW     1000
  DYNAMIC        0x00000000000004a8 0x00000078b00004a8 0x00000078b00004a8 0x00000000000000c0 0x00000000000000c0  R      8
Section Headers:
  ...
Dynamic Section:
  TAG        TYPE              VALUE
  00000003 (DT_PLTGOT)      0x78b00004b0
  00000002 (DT_STRTAB)      0x58
  00000005 (DT_SYMTAB)      0x108
  0000000a (DT_STRSZ)      0x48
  0000000b (DT_SYMENT)      0x18
  0000000f (DT_SONAME)      索引 1 (指向 "libbar.so")
  0000000e (DT_NEEDED)      索引 10 (指向 "libcutils.so")
  00000001 (DT_NEEDED)      索引 20 (指向 "liblog.so")
  0000001a (DT_RPATH)       索引 30 (指向 "./lib")
  00000000 (DT_NULL)        0x0
String Table:
  偏移 0x58:  .symtab
  偏移 0x60:  libbar.so
  偏移 0x6a:  libcutils.so
  偏移 0x76:  liblog.so
  偏移 0x7e:  ./lib
Symbol Table:
  Num:    Size      Type   Bind   Vis      Ndx Name
    0: 00000000     NOTYPE LOCAL  DEFAULT  UND
    1: 00000010   FUNC   GLOBAL DEFAULT    7 some_function
    ...
```

**链接的处理过程 (简化):**

1. **加载 ELF 文件:** linker 读取 so 文件的 ELF 头和程序头，确定各个段的加载地址和大小。
2. **处理 DYNAMIC 段:** linker 解析 DYNAMIC 段，获取链接所需的各种信息，例如字符串表地址 (`DT_STRTAB`)、符号表地址 (`DT_SYMTAB`)、`soname` (`DT_SONAME`)、依赖库 (`DT_NEEDED`)、运行路径 (`DT_RPATH`) 等。
3. **加载依赖库:** 对于每个 `DT_NEEDED` 条目，linker 会查找并加载相应的依赖库 (例如上面的 `libcutils.so` 和 `liblog.so`)。这个过程会递归进行，直到所有依赖都被加载。
4. **符号解析 (Symbol Resolution):**
   - 当代码中引用了外部符号时 (例如调用了 `libcutils.so` 中的一个函数)，linker 需要找到该符号的实际地址。
   - linker 会遍历已加载的共享库的符号表，查找与引用符号名称匹配的符号。
   - 查找顺序通常是：
     - **全局符号表:** 包含所有具有 `DF_1_GLOBAL` 标志的库的符号。
     - **当前库的符号表。**
     - **依赖库的符号表 (按照加载顺序)。**
   - 一旦找到匹配的符号，linker 就将引用处的地址修改为该符号的实际地址 (这个过程称为重定位)。
5. **重定位 (Relocation):**
   - 共享库被加载到内存中的地址可能不是编译时的地址，因此需要进行地址调整。
   - ELF 文件中包含重定位表，描述了哪些地址需要被修改以及如何修改。
   - linker 根据重定位表中的信息，修改代码和数据段中的地址引用，使其指向正确的内存位置。
6. **完成链接:**  当所有依赖库都被加载、所有符号都被解析和重定位后，链接过程就完成了。

**假设输入与输出 (逻辑推理):**

**假设输入:**

* 应用 A 启动，需要加载 `libmylib.so`。
* `libmylib.so` 的 `DT_NEEDED` 条目包含 `libbar.so` 和 `libcutils.so`。
* 系统中已经加载了 `libcutils.so`。
* `libbar.so` 位于 `/system/lib64`。

**输出:**

1. linker 首先尝试加载 `libmylib.so`。
2. linker 解析 `libmylib.so` 的 DYNAMIC 段，发现依赖于 `libbar.so` 和 `libcutils.so`。
3. linker 检查 `libcutils.so` 是否已经加载，发现已加载，则跳过加载。
4. linker 查找 `libbar.so`，根据库搜索路径 (可能包含 `/system/lib64`) 找到 `libbar.so`。
5. linker 加载 `libbar.so` 到内存。
6. linker 对 `libmylib.so` 和 `libbar.so` 进行符号解析和重定位，将它们的代码和数据段中的符号引用指向正确的地址。
7. 加载完成，应用 A 可以开始执行。

**用户或编程常见的使用错误：**

1. **找不到共享库:**
   - **错误原因:**  依赖的 so 文件不存在于默认的库搜索路径中，或者路径配置不正确。
   - **举例说明:**  `dlopen("libnonexistent.so", RTLD_LAZY)` 会导致 `dlopen` 返回 NULL，并设置错误信息，可以通过 `dlerror()` 获取。

2. **ABI 不兼容:**
   - **错误原因:**  尝试加载与当前架构不兼容的 so 文件 (例如在 32 位系统上加载 64 位的 so 文件，或者使用了不兼容的 NDK 版本编译的 so 文件)。
   - **举例说明:**  尝试在 armv7 设备上加载为 arm64 编译的 .so 文件会导致加载失败。

3. **循环依赖:**
   - **错误原因:**  库 A 依赖库 B，库 B 又依赖库 A，形成循环依赖。
   - **举例说明:**  `liba.so` 的 `DT_NEEDED` 中包含 `libb.so`，而 `libb.so` 的 `DT_NEEDED` 中包含 `liba.so`，可能导致加载死锁或错误。

4. **命名空间隔离问题:**
   - **错误原因:**  在不同的命名空间中加载了相同 `soname` 但实际内容不同的库，导致符号冲突或行为异常。
   - **举例说明:**  应用 A 和应用 B 各自包含一个 `libutils.so`，但内容不同，如果它们运行在不同的命名空间中，可能导致彼此的 `libutils.so` 无法互相访问。

**Android Framework 或 NDK 是如何一步步的到达这里：**

1. **NDK 编译:** 开发者使用 NDK (Native Development Kit) 编译 C/C++ 代码生成 `.so` 文件。编译过程中，编译器和链接器会生成 ELF 文件，其中包括 DYNAMIC 段和 `DT_NEEDED` 信息。
2. **Android Framework `System.loadLibrary()` 或 `dlopen()`:**
   - Java 代码中可以使用 `System.loadLibrary("mylib")` 加载 native 库。
   - Native 代码可以使用 `dlopen("libmylib.so", RTLD_LAZY)` 手动加载库。
3. **Framework 调用 Linker:**  `System.loadLibrary()` 最终会调用 Android 系统的动态链接器 `/system/bin/linker64` (或 `/system/bin/linker` for 32-bit)。
4. **Linker 的入口:** Linker 的入口点处理 `dlopen` 请求，并根据库名和标志位调用相应的内部函数，例如我们分析的 `find_library` 或 `find_libraries`。
5. **查找和加载过程:**  Linker 按照我们上面描述的步骤，查找、加载和链接共享库。
6. **返回句柄:**  `dlopen` 成功后，linker 返回一个指向加载的 so 文件的句柄，可以用于后续的 `dlsym` (查找符号) 和 `dlclose` (卸载库) 操作。

**Frida Hook 示例调试这些步骤：**

假设我们要 hook `dlopen` 函数，并查看其加载过程：

```python
import frida
import sys

package_name = "your.package.name" # 替换为你的应用包名
lib_name = "libmylib.so" # 你想要观察加载的库名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except Exception as e:
    print(f"无法连接到设备或应用: {e}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
    onEnter: function(args) {
        var library_path = Memory.readCString(args[0]);
        this.library_path = library_path;
        console.log("[+] dlopen called with path: " + library_path);
    },
    onLeave: function(retval) {
        if (this.library_path.endsWith("%s")) {
            console.log("[+] dlopen for %s returned: " + retval);
            if (retval != 0) {
                var base_address = Module.findBaseAddress("%s");
                console.log("[+] Base address of %s: " + base_address);
                // 可以进一步 hook linker 的内部函数，例如 find_library_internal 或 load_library
                // 示例：hook load_library 函数
                Interceptor.attach(Module.findExportByName(null, "_ZN7android12linker_dlopenEPKcmiiPKNS_14android_dlextinfoEPNS_6soinfoE"), {
                    onEnter: function(args) {
                        var path = Memory.readCString(args[0]);
                        console.log("[+] load_library called for: " + path);
                    },
                    onLeave: function(retval) {
                        console.log("[+] load_library returned: " + retval);
                    }
                });
            }
        }
    }
});
""" % (lib_name, lib_name, lib_name, lib_name)

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**代码解释:**

1. **连接到目标应用:** 使用 Frida 连接到指定的 Android 应用。
2. **Hook `dlopen`:**  Hook 了 `dlopen` 函数的入口和出口。
3. **打印 `dlopen` 参数:** 在 `onEnter` 中打印 `dlopen` 的库路径参数。
4. **针对特定库进行操作:** 在 `onLeave` 中判断是否是我们感兴趣的库 (`libmylib.so`)，如果是，则打印 `dlopen` 的返回值 (库的句柄)。
5. **Hook `load_library` (示例):**  如果 `dlopen` 成功加载了我们的目标库，则进一步 hook linker 内部的 `load_library` 函数 (需要根据 Android 版本和架构调整符号名称)，以便更深入地观察加载过程。
6. **打印 `load_library` 参数:** 在 `load_library` 的 `onEnter` 中打印正在加载的库的路径。

通过运行这个 Frida 脚本，你可以在应用加载 `libmylib.so` 时，看到 `dlopen` 被调用以及 linker 内部 `load_library` 函数的执行情况，从而调试共享库的加载过程。你可以根据需要 hook 其他 linker 内部函数，例如 `find_library_internal` 等，以更详细地了解库的查找和加载过程。记得根据你的目标 Android 版本和架构调整 hook 的函数符号名称。

### 提示词
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
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
able(const char* path, off64_t* file_offset, std::string* realpath) {
  ZipArchiveCache zip_archive_cache;
  return open_library_at_path(&zip_archive_cache, path, file_offset, realpath);
}

const char* fix_dt_needed(const char* dt_needed, const char* sopath __unused) {
#if !defined(__LP64__)
  // Work around incorrect DT_NEEDED entries for old apps: http://b/21364029
  int app_target_api_level = get_application_target_sdk_version();
  if (app_target_api_level < 23) {
    const char* bname = basename(dt_needed);
    if (bname != dt_needed) {
      DL_WARN_documented_change(23,
                                "invalid-dt_needed-entries-enforced-for-api-level-23",
                                "library \"%s\" has invalid DT_NEEDED entry \"%s\"",
                                sopath, dt_needed, app_target_api_level);
      add_dlwarning(sopath, "invalid DT_NEEDED entry",  dt_needed);
    }

    return bname;
  }
#endif
  return dt_needed;
}

template<typename F>
static void for_each_dt_needed(const ElfReader& elf_reader, F action) {
  for (const ElfW(Dyn)* d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_NEEDED) {
      action(fix_dt_needed(elf_reader.get_string(d->d_un.d_val), elf_reader.name()));
    }
  }
}

static bool find_loaded_library_by_inode(android_namespace_t* ns,
                                         const struct stat& file_stat,
                                         off64_t file_offset,
                                         bool search_linked_namespaces,
                                         soinfo** candidate) {
  if (file_stat.st_dev == 0 || file_stat.st_ino == 0) {
    *candidate = nullptr;
    return false;
  }

  auto predicate = [&](soinfo* si) {
    return si->get_st_ino() == file_stat.st_ino &&
           si->get_st_dev() == file_stat.st_dev &&
           si->get_file_offset() == file_offset;
  };

  *candidate = ns->soinfo_list().find_if(predicate);

  if (*candidate == nullptr && search_linked_namespaces) {
    for (auto& link : ns->linked_namespaces()) {
      android_namespace_t* linked_ns = link.linked_namespace();
      soinfo* si = linked_ns->soinfo_list().find_if(predicate);

      if (si != nullptr && link.is_accessible(si->get_soname())) {
        *candidate = si;
        return true;
      }
    }
  }

  return *candidate != nullptr;
}

static bool find_loaded_library_by_realpath(android_namespace_t* ns, const char* realpath,
                                            bool search_linked_namespaces, soinfo** candidate) {
  auto predicate = [&](soinfo* si) { return strcmp(realpath, si->get_realpath()) == 0; };

  *candidate = ns->soinfo_list().find_if(predicate);

  if (*candidate == nullptr && search_linked_namespaces) {
    for (auto& link : ns->linked_namespaces()) {
      android_namespace_t* linked_ns = link.linked_namespace();
      soinfo* si = linked_ns->soinfo_list().find_if(predicate);

      if (si != nullptr && link.is_accessible(si->get_soname())) {
        *candidate = si;
        return true;
      }
    }
  }

  return *candidate != nullptr;
}

static bool load_library(android_namespace_t* ns,
                         LoadTask* task,
                         LoadTaskList* load_tasks,
                         int rtld_flags,
                         const std::string& realpath,
                         bool search_linked_namespaces) {
  off64_t file_offset = task->get_file_offset();
  const char* name = task->get_name();
  const android_dlextinfo* extinfo = task->get_extinfo();

  LD_LOG(kLogDlopen,
         "load_library(ns=%s, task=%s, flags=0x%x, realpath=%s, search_linked_namespaces=%d)",
         ns->get_name(), name, rtld_flags, realpath.c_str(), search_linked_namespaces);

  if ((file_offset % page_size()) != 0) {
    DL_OPEN_ERR("file offset for the library \"%s\" is not page-aligned: %" PRId64, name, file_offset);
    return false;
  }
  if (file_offset < 0) {
    DL_OPEN_ERR("file offset for the library \"%s\" is negative: %" PRId64, name, file_offset);
    return false;
  }

  struct stat file_stat;
  if (TEMP_FAILURE_RETRY(fstat(task->get_fd(), &file_stat)) != 0) {
    DL_OPEN_ERR("unable to stat file for the library \"%s\": %m", name);
    return false;
  }
  if (file_offset >= file_stat.st_size) {
    DL_OPEN_ERR("file offset for the library \"%s\" >= file size: %" PRId64 " >= %" PRId64,
        name, file_offset, file_stat.st_size);
    return false;
  }

  // Check for symlink and other situations where
  // file can have different names, unless ANDROID_DLEXT_FORCE_LOAD is set
  if (extinfo == nullptr || (extinfo->flags & ANDROID_DLEXT_FORCE_LOAD) == 0) {
    soinfo* si = nullptr;
    if (find_loaded_library_by_inode(ns, file_stat, file_offset, search_linked_namespaces, &si)) {
      LD_LOG(kLogDlopen,
             "load_library(ns=%s, task=%s): Already loaded under different name/path \"%s\" - "
             "will return existing soinfo",
             ns->get_name(), name, si->get_realpath());
      task->set_soinfo(si);
      return true;
    }
  }

  if ((rtld_flags & RTLD_NOLOAD) != 0) {
    DL_OPEN_ERR("library \"%s\" wasn't loaded and RTLD_NOLOAD prevented it", name);
    return false;
  }

  struct statfs fs_stat;
  if (TEMP_FAILURE_RETRY(fstatfs(task->get_fd(), &fs_stat)) != 0) {
    DL_OPEN_ERR("unable to fstatfs file for the library \"%s\": %m", name);
    return false;
  }

  // do not check accessibility using realpath if fd is located on tmpfs
  // this enables use of memfd_create() for apps
  if ((fs_stat.f_type != TMPFS_MAGIC) && (!ns->is_accessible(realpath))) {
    // TODO(dimitry): workaround for http://b/26394120 - the exempt-list

    const soinfo* needed_by = task->is_dt_needed() ? task->get_needed_by() : nullptr;
    if (is_exempt_lib(ns, name, needed_by)) {
      // print warning only if needed by non-system library
      if (needed_by == nullptr || !is_system_library(needed_by->get_realpath())) {
        const soinfo* needed_or_dlopened_by = task->get_needed_by();
        const char* sopath = needed_or_dlopened_by == nullptr ? "(unknown)" :
                                                      needed_or_dlopened_by->get_realpath();
        DL_WARN_documented_change(24,
                                  "private-api-enforced-for-api-level-24",
                                  "library \"%s\" (\"%s\") needed or dlopened by \"%s\" "
                                  "is not accessible by namespace \"%s\"",
                                  name, realpath.c_str(), sopath, ns->get_name());
        add_dlwarning(sopath, "unauthorized access to",  name);
      }
    } else {
      // do not load libraries if they are not accessible for the specified namespace.
      const char* needed_or_dlopened_by = task->get_needed_by() == nullptr ?
                                          "(unknown)" :
                                          task->get_needed_by()->get_realpath();

      DL_OPEN_ERR("library \"%s\" needed or dlopened by \"%s\" is not accessible for the namespace \"%s\"",
             name, needed_or_dlopened_by, ns->get_name());

      // do not print this if a library is in the list of shared libraries for linked namespaces
      if (!maybe_accessible_via_namespace_links(ns, name)) {
        DL_WARN("library \"%s\" (\"%s\") needed or dlopened by \"%s\" is not accessible for the"
                " namespace: [name=\"%s\", ld_library_paths=\"%s\", default_library_paths=\"%s\","
                " permitted_paths=\"%s\"]",
                name, realpath.c_str(),
                needed_or_dlopened_by,
                ns->get_name(),
                android::base::Join(ns->get_ld_library_paths(), ':').c_str(),
                android::base::Join(ns->get_default_library_paths(), ':').c_str(),
                android::base::Join(ns->get_permitted_paths(), ':').c_str());
      }
      return false;
    }
  }

  soinfo* si = soinfo_alloc(ns, realpath.c_str(), &file_stat, file_offset, rtld_flags);

  task->set_soinfo(si);

  // Read the ELF header and some of the segments.
  if (!task->read(realpath.c_str(), file_stat.st_size)) {
    task->remove_cached_elf_reader();
    task->set_soinfo(nullptr);
    soinfo_free(si);
    return false;
  }

  // Find and set DT_RUNPATH, DT_SONAME, and DT_FLAGS_1.
  // Note that these field values are temporary and are
  // going to be overwritten on soinfo::prelink_image
  // with values from PT_LOAD segments.
  const ElfReader& elf_reader = task->get_elf_reader();
  for (const ElfW(Dyn)* d = elf_reader.dynamic(); d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_RUNPATH) {
      si->set_dt_runpath(elf_reader.get_string(d->d_un.d_val));
    }
    if (d->d_tag == DT_SONAME) {
      si->set_soname(elf_reader.get_string(d->d_un.d_val));
    }
    // We need to identify a DF_1_GLOBAL library early so we can link it to namespaces.
    if (d->d_tag == DT_FLAGS_1) {
      si->set_dt_flags_1(d->d_un.d_val);
    }
  }

#if !defined(__ANDROID__)
  // Bionic on the host currently uses some Android prebuilts, which don't set
  // DT_RUNPATH with any relative paths, so they can't find their dependencies.
  // b/118058804
  if (si->get_dt_runpath().empty()) {
    si->set_dt_runpath("$ORIGIN/../lib64:$ORIGIN/lib64");
  }
#endif

  for_each_dt_needed(task->get_elf_reader(), [&](const char* name) {
    LD_LOG(kLogDlopen, "load_library(ns=%s, task=%s): Adding DT_NEEDED task: %s",
           ns->get_name(), task->get_name(), name);
    load_tasks->push_back(LoadTask::create(name, si, ns, task->get_readers_map()));
  });

  return true;
}

static bool load_library(android_namespace_t* ns,
                         LoadTask* task,
                         ZipArchiveCache* zip_archive_cache,
                         LoadTaskList* load_tasks,
                         int rtld_flags,
                         bool search_linked_namespaces) {
  const char* name = task->get_name();
  soinfo* needed_by = task->get_needed_by();
  const android_dlextinfo* extinfo = task->get_extinfo();

  if (extinfo != nullptr && (extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD) != 0) {
    off64_t file_offset = 0;
    if ((extinfo->flags & ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET) != 0) {
      file_offset = extinfo->library_fd_offset;
    }

    std::string realpath;
    if (!realpath_fd(extinfo->library_fd, &realpath)) {
      if (!is_first_stage_init()) {
        DL_WARN("unable to get realpath for the library \"%s\" by extinfo->library_fd. "
                "Will use given name.",
                name);
      }
      realpath = name;
    }

    task->set_fd(extinfo->library_fd, false);
    task->set_file_offset(file_offset);
    return load_library(ns, task, load_tasks, rtld_flags, realpath, search_linked_namespaces);
  }

  LD_LOG(kLogDlopen,
         "load_library(ns=%s, task=%s, flags=0x%x, search_linked_namespaces=%d): calling "
         "open_library",
         ns->get_name(), name, rtld_flags, search_linked_namespaces);

  // Open the file.
  off64_t file_offset;
  std::string realpath;
  int fd = open_library(ns, zip_archive_cache, name, needed_by, &file_offset, &realpath);
  if (fd == -1) {
    if (task->is_dt_needed()) {
      if (needed_by->is_main_executable()) {
        DL_OPEN_ERR("library \"%s\" not found: needed by main executable", name);
      } else {
        DL_OPEN_ERR("library \"%s\" not found: needed by %s in namespace %s", name,
                    needed_by->get_realpath(), task->get_start_from()->get_name());
      }
    } else {
      DL_OPEN_ERR("library \"%s\" not found", name);
    }
    return false;
  }

  task->set_fd(fd, true);
  task->set_file_offset(file_offset);

  return load_library(ns, task, load_tasks, rtld_flags, realpath, search_linked_namespaces);
}

static bool find_loaded_library_by_soname(android_namespace_t* ns,
                                          const char* name,
                                          soinfo** candidate) {
  return !ns->soinfo_list().visit([&](soinfo* si) {
    if (strcmp(name, si->get_soname()) == 0) {
      *candidate = si;
      return false;
    }

    return true;
  });
}

// Returns true if library was found and false otherwise
static bool find_loaded_library_by_soname(android_namespace_t* ns,
                                         const char* name,
                                         bool search_linked_namespaces,
                                         soinfo** candidate) {
  *candidate = nullptr;

  // Ignore filename with path.
  if (strchr(name, '/') != nullptr) {
    return false;
  }

  bool found = find_loaded_library_by_soname(ns, name, candidate);

  if (!found && search_linked_namespaces) {
    // if a library was not found - look into linked namespaces
    for (auto& link : ns->linked_namespaces()) {
      if (!link.is_accessible(name)) {
        continue;
      }

      android_namespace_t* linked_ns = link.linked_namespace();

      if (find_loaded_library_by_soname(linked_ns, name, candidate)) {
        return true;
      }
    }
  }

  return found;
}

static bool find_library_in_linked_namespace(const android_namespace_link_t& namespace_link,
                                             LoadTask* task) {
  android_namespace_t* ns = namespace_link.linked_namespace();

  soinfo* candidate;
  bool loaded = false;

  std::string soname;
  if (find_loaded_library_by_soname(ns, task->get_name(), false, &candidate)) {
    loaded = true;
    soname = candidate->get_soname();
  } else {
    soname = resolve_soname(task->get_name());
  }

  if (!namespace_link.is_accessible(soname.c_str())) {
    // the library is not accessible via namespace_link
    LD_LOG(kLogDlopen,
           "find_library_in_linked_namespace(ns=%s, task=%s): Not accessible (soname=%s)",
           ns->get_name(), task->get_name(), soname.c_str());
    return false;
  }

  // if library is already loaded - return it
  if (loaded) {
    LD_LOG(kLogDlopen, "find_library_in_linked_namespace(ns=%s, task=%s): Already loaded",
           ns->get_name(), task->get_name());
    task->set_soinfo(candidate);
    return true;
  }

  // returning true with empty soinfo means that the library is okay to be
  // loaded in the namespace but has not yet been loaded there before.
  LD_LOG(kLogDlopen, "find_library_in_linked_namespace(ns=%s, task=%s): Ok to load", ns->get_name(),
         task->get_name());
  task->set_soinfo(nullptr);
  return true;
}

static bool find_library_internal(android_namespace_t* ns,
                                  LoadTask* task,
                                  ZipArchiveCache* zip_archive_cache,
                                  LoadTaskList* load_tasks,
                                  int rtld_flags) {
  soinfo* candidate;

  if (find_loaded_library_by_soname(ns, task->get_name(), true /* search_linked_namespaces */,
                                    &candidate)) {
    LD_LOG(kLogDlopen,
           "find_library_internal(ns=%s, task=%s): Already loaded (by soname): %s",
           ns->get_name(), task->get_name(), candidate->get_realpath());
    task->set_soinfo(candidate);
    return true;
  }

  // Library might still be loaded, the accurate detection
  // of this fact is done by load_library.
  LD_DEBUG(any, "[ \"%s\" find_loaded_library_by_soname failed (*candidate=%s@%p). Trying harder... ]",
           task->get_name(), candidate == nullptr ? "n/a" : candidate->get_realpath(), candidate);

  if (load_library(ns, task, zip_archive_cache, load_tasks, rtld_flags,
                   true /* search_linked_namespaces */)) {
    return true;
  }

  // TODO(dimitry): workaround for http://b/26394120 (the exempt-list)
  if (ns->is_exempt_list_enabled() && is_exempt_lib(ns, task->get_name(), task->get_needed_by())) {
    // For the libs in the exempt-list, switch to the default namespace and then
    // try the load again from there. The library could be loaded from the
    // default namespace or from another namespace (e.g. runtime) that is linked
    // from the default namespace.
    LD_LOG(kLogDlopen,
           "find_library_internal(ns=%s, task=%s): Exempt system library - trying namespace %s",
           ns->get_name(), task->get_name(), g_default_namespace.get_name());
    ns = &g_default_namespace;
    if (load_library(ns, task, zip_archive_cache, load_tasks, rtld_flags,
                     true /* search_linked_namespaces */)) {
      return true;
    }
  }
  // END OF WORKAROUND

  // if a library was not found - look into linked namespaces
  // preserve current dlerror in the case it fails.
  DlErrorRestorer dlerror_restorer;
  LD_LOG(kLogDlopen, "find_library_internal(ns=%s, task=%s): Trying %zu linked namespaces",
         ns->get_name(), task->get_name(), ns->linked_namespaces().size());
  for (auto& linked_namespace : ns->linked_namespaces()) {
    if (find_library_in_linked_namespace(linked_namespace, task)) {
      // Library is already loaded.
      if (task->get_soinfo() != nullptr) {
        // n.b. This code path runs when find_library_in_linked_namespace found an already-loaded
        // library by soname. That should only be possible with a exempt-list lookup, where we
        // switch the namespace, because otherwise, find_library_in_linked_namespace is duplicating
        // the soname scan done in this function's first call to find_loaded_library_by_soname.
        return true;
      }

      if (load_library(linked_namespace.linked_namespace(), task, zip_archive_cache, load_tasks,
                       rtld_flags, false /* search_linked_namespaces */)) {
        LD_LOG(kLogDlopen, "find_library_internal(ns=%s, task=%s): Found in linked namespace %s",
               ns->get_name(), task->get_name(), linked_namespace.linked_namespace()->get_name());
        return true;
      }
    }
  }

  return false;
}

static void soinfo_unload(soinfo* si);

static void shuffle(std::vector<LoadTask*>* v) {
  if (is_first_stage_init()) {
    // arc4random* is not available in first stage init because /dev/random
    // hasn't yet been created.
    return;
  }
  for (size_t i = 0, size = v->size(); i < size; ++i) {
    size_t n = size - i;
    size_t r = arc4random_uniform(n);
    std::swap((*v)[n-1], (*v)[r]);
  }
}

// add_as_children - add first-level loaded libraries (i.e. library_names[], but
// not their transitive dependencies) as children of the start_with library.
// This is false when find_libraries is called for dlopen(), when newly loaded
// libraries must form a disjoint tree.
bool find_libraries(android_namespace_t* ns,
                    soinfo* start_with,
                    const char* const library_names[],
                    size_t library_names_count,
                    soinfo* soinfos[],
                    std::vector<soinfo*>* ld_preloads,
                    size_t ld_preloads_count,
                    int rtld_flags,
                    const android_dlextinfo* extinfo,
                    bool add_as_children,
                    std::vector<android_namespace_t*>* namespaces) {
  // Step 0: prepare.
  std::unordered_map<const soinfo*, ElfReader> readers_map;
  LoadTaskList load_tasks;

  for (size_t i = 0; i < library_names_count; ++i) {
    const char* name = library_names[i];
    load_tasks.push_back(LoadTask::create(name, start_with, ns, &readers_map));
  }

  // If soinfos array is null allocate one on stack.
  // The array is needed in case of failure; for example
  // when library_names[] = {libone.so, libtwo.so} and libone.so
  // is loaded correctly but libtwo.so failed for some reason.
  // In this case libone.so should be unloaded on return.
  // See also implementation of failure_guard below.

  if (soinfos == nullptr) {
    size_t soinfos_size = sizeof(soinfo*)*library_names_count;
    soinfos = reinterpret_cast<soinfo**>(alloca(soinfos_size));
    memset(soinfos, 0, soinfos_size);
  }

  // list of libraries to link - see step 2.
  size_t soinfos_count = 0;

  auto scope_guard = android::base::make_scope_guard([&]() {
    for (LoadTask* t : load_tasks) {
      LoadTask::deleter(t);
    }
  });

  ZipArchiveCache zip_archive_cache;
  soinfo_list_t new_global_group_members;

  // Step 1: expand the list of load_tasks to include
  // all DT_NEEDED libraries (do not load them just yet)
  for (size_t i = 0; i<load_tasks.size(); ++i) {
    LoadTask* task = load_tasks[i];
    soinfo* needed_by = task->get_needed_by();

    bool is_dt_needed = needed_by != nullptr && (needed_by != start_with || add_as_children);
    task->set_extinfo(is_dt_needed ? nullptr : extinfo);
    task->set_dt_needed(is_dt_needed);

    // Note: start from the namespace that is stored in the LoadTask. This namespace
    // is different from the current namespace when the LoadTask is for a transitive
    // dependency and the lib that created the LoadTask is not found in the
    // current namespace but in one of the linked namespaces.
    android_namespace_t* start_ns = const_cast<android_namespace_t*>(task->get_start_from());

    LD_LOG(kLogDlopen, "find_library_internal(ns=%s@%p): task=%s, is_dt_needed=%d",
           start_ns->get_name(), start_ns, task->get_name(), is_dt_needed);

    if (!find_library_internal(start_ns, task, &zip_archive_cache, &load_tasks, rtld_flags)) {
      return false;
    }

    soinfo* si = task->get_soinfo();

    if (is_dt_needed) {
      needed_by->add_child(si);
    }

    // When ld_preloads is not null, the first
    // ld_preloads_count libs are in fact ld_preloads.
    bool is_ld_preload = false;
    if (ld_preloads != nullptr && soinfos_count < ld_preloads_count) {
      ld_preloads->push_back(si);
      is_ld_preload = true;
    }

    if (soinfos_count < library_names_count) {
      soinfos[soinfos_count++] = si;
    }

    // Add the new global group members to all initial namespaces. Do this secondary namespace setup
    // at the same time that libraries are added to their primary namespace so that the order of
    // global group members is the same in the every namespace. Only add a library to a namespace
    // once, even if it appears multiple times in the dependency graph.
    if (is_ld_preload || (si->get_dt_flags_1() & DF_1_GLOBAL) != 0) {
      if (!si->is_linked() && namespaces != nullptr && !new_global_group_members.contains(si)) {
        new_global_group_members.push_back(si);
        for (auto linked_ns : *namespaces) {
          if (si->get_primary_namespace() != linked_ns) {
            linked_ns->add_soinfo(si);
            si->add_secondary_namespace(linked_ns);
          }
        }
      }
    }
  }

  // Step 2: Load libraries in random order (see b/24047022)
  LoadTaskList load_list;
  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    auto pred = [&](const LoadTask* t) {
      return t->get_soinfo() == si;
    };

    if (!si->is_linked() &&
        std::find_if(load_list.begin(), load_list.end(), pred) == load_list.end() ) {
      load_list.push_back(task);
    }
  }
  bool reserved_address_recursive = false;
  if (extinfo) {
    reserved_address_recursive = extinfo->flags & ANDROID_DLEXT_RESERVED_ADDRESS_RECURSIVE;
  }
  if (!reserved_address_recursive) {
    // Shuffle the load order in the normal case, but not if we are loading all
    // the libraries to a reserved address range.
    shuffle(&load_list);
  }

  // Set up address space parameters.
  address_space_params extinfo_params, default_params;
  size_t relro_fd_offset = 0;
  if (extinfo) {
    if (extinfo->flags & ANDROID_DLEXT_RESERVED_ADDRESS) {
      extinfo_params.start_addr = extinfo->reserved_addr;
      extinfo_params.reserved_size = extinfo->reserved_size;
      extinfo_params.must_use_address = true;
    } else if (extinfo->flags & ANDROID_DLEXT_RESERVED_ADDRESS_HINT) {
      extinfo_params.start_addr = extinfo->reserved_addr;
      extinfo_params.reserved_size = extinfo->reserved_size;
    }
  }

  for (auto&& task : load_list) {
    address_space_params* address_space =
        (reserved_address_recursive || !task->is_dt_needed()) ? &extinfo_params : &default_params;
    if (!task->load(address_space)) {
      return false;
    }
  }

  // The WebView loader uses RELRO sharing in order to promote page sharing of the large RELRO
  // segment, as it's full of C++ vtables. Because MTE globals, by default, applies random tags to
  // each global variable, the RELRO segment is polluted and unique for each process. In order to
  // allow sharing, but still provide some protection, we use deterministic global tagging schemes
  // for DSOs that are loaded through android_dlopen_ext, such as those loaded by WebView.
  bool dlext_use_relro =
      extinfo && extinfo->flags & (ANDROID_DLEXT_WRITE_RELRO | ANDROID_DLEXT_USE_RELRO);

  // Step 3: pre-link all DT_NEEDED libraries in breadth first order.
  bool any_memtag_stack = false;
  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    if (!si->is_linked() && !si->prelink_image(dlext_use_relro)) {
      return false;
    }
    // si->memtag_stack() needs to be called after si->prelink_image() which populates
    // the dynamic section.
    if (si->memtag_stack()) {
      any_memtag_stack = true;
      LD_LOG(kLogDlopen,
             "... load_library requesting stack MTE for: realpath=\"%s\", soname=\"%s\"",
             si->get_realpath(), si->get_soname());
    }
    register_soinfo_tls(si);
  }
  if (any_memtag_stack) {
    if (auto* cb = __libc_shared_globals()->memtag_stack_dlopen_callback) {
      cb();
    } else {
      // find_library is used by the initial linking step, so we communicate that we
      // want memtag_stack enabled to __libc_init_mte.
      __libc_shared_globals()->initial_memtag_stack_abi = true;
    }
  }

  // Step 4: Construct the global group. DF_1_GLOBAL bit is force set for LD_PRELOADed libs because
  // they must be added to the global group. Note: The DF_1_GLOBAL bit for a library is normally set
  // in step 3.
  if (ld_preloads != nullptr) {
    for (auto&& si : *ld_preloads) {
      si->set_dt_flags_1(si->get_dt_flags_1() | DF_1_GLOBAL);
    }
  }

  // Step 5: Collect roots of local_groups.
  // Whenever needed_by->si link crosses a namespace boundary it forms its own local_group.
  // Here we collect new roots to link them separately later on. Note that we need to avoid
  // collecting duplicates. Also the order is important. They need to be linked in the same
  // BFS order we link individual libraries.
  std::vector<soinfo*> local_group_roots;
  if (start_with != nullptr && add_as_children) {
    local_group_roots.push_back(start_with);
  } else {
    CHECK(soinfos_count == 1);
    local_group_roots.push_back(soinfos[0]);
  }

  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    soinfo* needed_by = task->get_needed_by();
    bool is_dt_needed = needed_by != nullptr && (needed_by != start_with || add_as_children);
    android_namespace_t* needed_by_ns =
        is_dt_needed ? needed_by->get_primary_namespace() : ns;

    if (!si->is_linked() && si->get_primary_namespace() != needed_by_ns) {
      auto it = std::find(local_group_roots.begin(), local_group_roots.end(), si);
      LD_LOG(kLogDlopen,
             "Crossing namespace boundary (si=%s@%p, si_ns=%s@%p, needed_by=%s@%p, ns=%s@%p, needed_by_ns=%s@%p) adding to local_group_roots: %s",
             si->get_realpath(),
             si,
             si->get_primary_namespace()->get_name(),
             si->get_primary_namespace(),
             needed_by == nullptr ? "(nullptr)" : needed_by->get_realpath(),
             needed_by,
             ns->get_name(),
             ns,
             needed_by_ns->get_name(),
             needed_by_ns,
             it == local_group_roots.end() ? "yes" : "no");

      if (it == local_group_roots.end()) {
        local_group_roots.push_back(si);
      }
    }
  }

  // Step 6: Link all local groups
  for (auto root : local_group_roots) {
    soinfo_list_t local_group;
    android_namespace_t* local_group_ns = root->get_primary_namespace();

    walk_dependencies_tree(root,
      [&] (soinfo* si) {
        if (local_group_ns->is_accessible(si)) {
          local_group.push_back(si);
          return kWalkContinue;
        } else {
          return kWalkSkip;
        }
      });

    soinfo_list_t global_group = local_group_ns->get_global_group();
    SymbolLookupList lookup_list(global_group, local_group);
    soinfo* local_group_root = local_group.front();

    bool linked = local_group.visit([&](soinfo* si) {
      // Even though local group may contain accessible soinfos from other namespaces
      // we should avoid linking them (because if they are not linked -> they
      // are in the local_group_roots and will be linked later).
      if (!si->is_linked() && si->get_primary_namespace() == local_group_ns) {
        const android_dlextinfo* link_extinfo = nullptr;
        if (si == soinfos[0] || reserved_address_recursive) {
          // Only forward extinfo for the first library unless the recursive
          // flag is set.
          link_extinfo = extinfo;
        }
        if (__libc_shared_globals()->load_hook) {
          __libc_shared_globals()->load_hook(si->load_bias, si->phdr, si->phnum);
        }
        lookup_list.set_dt_symbolic_lib(si->has_DT_SYMBOLIC ? si : nullptr);
        if (!si->link_image(lookup_list, local_group_root, link_extinfo, &relro_fd_offset) ||
            !get_cfi_shadow()->AfterLoad(si, solist_get_head())) {
          return false;
        }
      }

      return true;
    });

    if (!linked) {
      return false;
    }
  }

  // Step 7: Mark all load_tasks as linked and increment refcounts
  // for references between load_groups (at this point it does not matter if
  // referenced load_groups were loaded by previous dlopen or as part of this
  // one on step 6)
  if (start_with != nullptr && add_as_children) {
    start_with->set_linked();
  }

  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    si->set_linked();
  }

  for (auto&& task : load_tasks) {
    soinfo* si = task->get_soinfo();
    soinfo* needed_by = task->get_needed_by();
    if (needed_by != nullptr &&
        needed_by != start_with &&
        needed_by->get_local_group_root() != si->get_local_group_root()) {
      si->increment_ref_count();
    }
  }


  return true;
}

static soinfo* find_library(android_namespace_t* ns,
                            const char* name, int rtld_flags,
                            const android_dlextinfo* extinfo,
                            soinfo* needed_by) {
  soinfo* si = nullptr;

  if (name == nullptr) {
    si = solist_get_somain();
  } else if (!find_libraries(ns,
                             needed_by,
                             &name,
                             1,
                             &si,
                             nullptr,
                             0,
                             rtld_flags,
                             extinfo,
                             false /* add_as_children */)) {
    if (si != nullptr) {
      soinfo_unload(si);
    }
    return nullptr;
  }

  si->increment_ref_count();

  return si;
}

static void soinfo_unload_impl(soinfo* root) {
  ScopedTrace trace((std::string("unload ") + root->get_realpath()).c_str());
  bool is_linked = root->is_linked();

  if (!root->can_unload()) {
    LD_LOG(kLogDlopen,
           "... dlclose(root=\"%s\"@%p) ... not unloading - the load group is flagged with NODELETE",
           root->get_realpath(),
           root);
    return;
  }


  soinfo_list_t unload_list;
  unload_list.push_back(root);

  soinfo_list_t local_unload_list;
  soinfo_list_t external_unload_list;
  soinfo* si = nullptr;

  while ((si = unload_list.pop_front()) != nullptr) {
    if (local_unload_list.contains(si)) {
      continue;
    }

    local_unload_list.push_back(si);

    if (si->has_min_version(0)) {
      soinfo* child = nullptr;
      while ((child = si->get_children().pop_front()) != nullptr) {
        LD_DEBUG(any, "%s@%p needs to unload %s@%p", si->get_realpath(), si,
                 child->get_realpath(), child);

        child->get_parents().remove(si);

        if (local_unload_list.contains(child)) {
          continue;
        } else if (child->is_linked() && child->get_local_group_root() != root) {
          external_unload_list.push_back(child);
        } else if (child->get_parents().empty()) {
          unload_list.push_back(child);
        }
      }
    } else {
      async_safe_fatal("soinfo for \"%s\"@%p has no version", si->get_realpath(), si);
    }
  }

  local_unload_list.for_each([](soinfo* si) {
    LD_LOG(kLogDlopen,
           "... dlclose: calling destructors for \"%s\"@%p ... ",
           si->get_realpath(),
           si);
    si->call_destructors();
    LD_LOG(kLogDlopen,
           "... dlclos
```