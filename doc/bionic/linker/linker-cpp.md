Response:
Let's break down the thought process to analyze the provided C++ code snippet. The goal is to understand its functionality, especially in the context of Android's dynamic linker (bionic), and to structure the information clearly.

**1. Initial Understanding and Context:**

* **Keywords:** `bionic`, `linker`, `linker.cpp`, `Android`, `C library`, `dynamic linker`. This immediately tells us the core purpose of the code.
* **Copyright and Licensing:** The initial comments indicate an open-source project under a BSD-style license. This is standard for Android's core components.
* **Includes:**  A quick scan of the `#include` directives provides hints about the functionality:
    * Standard C/C++ libraries (`stdio.h`, `stdlib.h`, `string.h`, `<vector>`, `<unordered_map>`, etc.):  Basic utilities.
    * System calls (`fcntl.h`, `sys/mman.h`, `unistd.h`): Low-level operations related to file access, memory management, and process control.
    * Android-specific headers (`android/api-level.h`, `android-base/...`, `bionic/...`): Functionality related to Android's environment. Crucially, headers like `linker.h`, `linker_phdr.h`, `linker_relocate.h` strongly suggest dynamic linking mechanisms.
    * `ziparchive/zip_archive.h`:  Indicates support for loading libraries from zip files (like APKs).

**2. Identifying Key Data Structures and Global Variables:**

* **Allocators:**  The code defines custom allocators (`LinkerTypeAllocator`, `LinkerBlockAllocator`, `SizeBasedAllocator`, `TypeBasedAllocator`). This points to a desire for fine-grained memory management within the linker.
* **Namespaces:**  `android_namespace_t`, `g_anonymous_namespace`, `g_exported_namespaces`. This is a critical part of Android's linker, providing isolation between applications and the system.
* **`soinfo`:**  A very important structure. The name suggests "shared object info," likely holding metadata about loaded libraries (base address, size, dependencies, etc.). The allocator `g_soinfo_allocator` confirms its significance.
* **Path Variables:** `kSystemLibDir`, `kVendorLibDir`, `kDefaultLdPaths`, etc. These define the standard locations where the linker searches for libraries.
* **Preloading:** `g_ld_preload_names` indicates support for preloading shared libraries.
* **GDB Support:**  `notify_gdb_of_load`, `notify_gdb_of_unload`. The linker interacts with debuggers.
* **Protection:** `ProtectedDataGuard`. This suggests a mechanism to protect critical linker data from modification during library loading/unloading.
* **Zip Archive Cache:** `ZipArchiveCache`. Optimizes loading from zip files.

**3. Recognizing Core Functionality Blocks:**

* **`soinfo` Management:** Allocation (`soinfo_alloc`), deallocation (`soinfo_free`), and list management (`solist_add_soinfo`, `solist_remove_soinfo`).
* **Path Handling:**  `parse_path`, `parse_LD_LIBRARY_PATH`, `realpath_fd`, `open_library_on_paths`, `open_library_at_path`. The linker needs to find and open shared libraries.
* **TLS (Thread Local Storage):** `get_tls_block_for_this_thread`. The linker is involved in setting up thread-local data for libraries.
* **Exception Handling (ARM-specific):** `do_dl_unwind_find_exidx`. The linker provides information for stack unwinding during exceptions.
* **Symbol Lookup:** `dlsym_linear_lookup`, `dlsym_handle_lookup`. The core functionality of `dlsym`.
* **Dependency Tree Traversal:** `walk_dependencies_tree`. Used for symbol lookup and other operations on the graph of loaded libraries.
* **Loading Libraries:**  The `LoadTask` class encapsulates the process of finding, reading, and mapping a library into memory.

**4. Connecting to Android Features:**

* **Namespaces:** Directly relate to Android's app isolation and the separation of system and vendor libraries. Different apps can have different views of the available libraries.
* **`LD_LIBRARY_PATH`:**  An environment variable used to specify additional library search paths, particularly useful during development or for specific use cases.
* **Zip Files:**  Crucial for how Android apps are packaged (APKs). The linker can load native libraries directly from within APKs.
* **Preloading:**  Used by Android for performance optimization by loading frequently used libraries at startup.
* **GDB Support:** Enables debugging of native code in Android applications.

**5. Answering Specific Questions (Trial and Error/Refinement):**

* **"详细解释每一个libc函数的功能是如何实现的"**: Realized that this is too broad for *this* specific file. `linker.cpp` *uses* libc functions, but it doesn't implement them. Adjusted the focus to how `linker.cpp` *interacts* with libc (e.g., `mmap`, `munmap`, `open`, `close`, `stat`).
* **"对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程"**:  Recognized that the provided snippet doesn't *show* the actual linking process (relocation, symbol resolution). Made a note to address this in later parts if possible. Focused on identifying the *structures* involved (like `soinfo`) and how they're used.
* **"说明android framework or ndk是如何一步步的到达这里"**:  This requires understanding the Android startup process. Made a mental note to cover this in the "how to reach here" part.

**6. Structuring the Output:**

* **Categorization:** Grouping functionalities (memory management, path handling, symbol lookup, etc.) makes the information more digestible.
* **Clarity:**  Using clear and concise language, explaining terms like "soinfo" and "namespace."
* **Examples:**  Providing concrete examples (like the purpose of `LD_LIBRARY_PATH` or loading from APKs) enhances understanding.
* **Limitations:**  Acknowledging what the code snippet *doesn't* show (like the detailed linking process) sets realistic expectations.

**Self-Correction/Refinement during the process:**

* Initially considered going deep into the details of each allocator, but realized that it's not the primary focus of this file. Decided to keep it at a higher level.
*  Almost started explaining libc functions in detail, but quickly corrected course to focus on the linker's role.
*  Realized that generating a full `so` layout and linking process example within the constraints of analyzing *this specific file* is difficult. Decided to mention the relevant data structures and postpone detailed examples.

By following this structured thought process, combining code analysis with domain knowledge about Android's linker, and making adjustments along the way, it's possible to generate a comprehensive and accurate summary of the provided code snippet.
这是 `bionic/linker/linker.cpp` 文件的第一部分，主要负责 Android Bionic 动态链接器的初始化和核心数据结构的定义。 让我们归纳一下它的主要功能：

**核心功能归纳：**

1. **动态链接器基础架构的建立：**
   - **全局数据结构的初始化：** 定义和初始化了动态链接器运行所需的关键全局变量和数据结构，例如：
     - `g_soinfo_allocator` 和 `g_soinfo_links_allocator`: 用于分配 `soinfo` 结构体及其链表节点的内存池。`soinfo` 存储了有关已加载共享库的信息。
     - `g_namespace_allocator` 和 `g_namespace_list_allocator`: 用于分配命名空间结构体及其链表节点的内存池。Android 使用命名空间来隔离不同的应用和系统库。
     - `g_anonymous_namespace` 和 `g_exported_namespaces`:  管理匿名命名空间和导出的命名空间。
     - `g_module_load_counter` 和 `g_module_unload_counter`:  用于记录模块加载和卸载的计数器，供 `dl_iterate_phdr` 使用。
     - 定义了默认的库搜索路径，例如 `kSystemLibDir`, `kVendorLibDir` 等。
   - **配置文件的路径定义：** 定义了动态链接器配置文件的路径，例如 `kLdConfigFilePath`, `kLdGeneratedConfigFilePath`。
   - **辅助函数的定义：** 定义了许多辅助函数，用于执行诸如路径解析、文件操作、内存管理等操作，为后续的动态链接过程提供基础支持。

2. **共享库信息的管理 (`soinfo`)：**
   - **`soinfo` 结构体的定义和分配/释放：** 定义了 `soinfo` 结构体，用于存储每个加载的共享库的元数据，例如库的路径、加载地址、大小、依赖关系等。提供了 `soinfo_alloc` 用于分配 `soinfo` 结构体，并将其添加到全局链表中。`soinfo_free` 用于释放 `soinfo` 结构体并将其从全局链表中移除。
   - **共享库链表的维护：** 使用链表 `solist` 来管理所有已加载的共享库。

3. **命名空间管理：**
   - **命名空间结构体的定义和分配：** 定义了 `android_namespace_t` 结构体，用于表示一个独立的库加载命名空间，包含其自己的库搜索路径和可访问的库列表。提供了 `g_namespace_allocator` 来分配命名空间结构体。
   - **默认命名空间的设置：** 初始化了默认的命名空间 `g_default_namespace`。
   - **命名空间链接：** 提供了判断库是否可以通过命名空间链接访问的机制 (`maybe_accessible_via_namespace_links`)。

4. **路径处理和文件操作：**
   - **路径解析：** 提供了 `parse_path` 函数用于解析路径字符串，并将其分解为单独的路径，并进行路径的规范化。
   - **`LD_LIBRARY_PATH` 的处理：** 提供了 `parse_LD_LIBRARY_PATH` 函数用于解析环境变量 `LD_LIBRARY_PATH`，并将其添加到默认命名空间的库搜索路径中。
   - **文件打开和真实路径获取：** 提供了 `realpath_fd` 函数用于获取文件描述符对应的真实路径。

5. **线程本地存储 (TLS) 支持：**
   - **`get_tls_block_for_this_thread` 函数：**  提供了一种获取当前线程 TLS 模块副本地址的方法。

6. **异常处理支持 (ARM 架构特定)：**
   - **`do_dl_unwind_find_exidx` 函数：**  在 ARM 架构上，为异常处理机制 (`__gnu_Unwind_Find_exidx`) 提供回调，以查找给定 PC 值所属的共享库的 `.ARM.exidx` 段信息。

7. **`dl_iterate_phdr` 的实现：**
   - **`do_dl_iterate_phdr` 函数：**  实现了 `dl_iterate_phdr` 函数，允许用户遍历所有已加载的共享库的信息。

8. **数据保护机制：**
   - **`ProtectedDataGuard` 类：**  提供了一种机制来保护动态链接器的关键数据结构，防止在加载或卸载库的过程中被意外修改。

9. **基于大小和类型的内存分配器：**
   - 定义了模板类 `SizeBasedAllocator` 和 `TypeBasedAllocator`，用于根据内存块的大小和类型进行分配，提高内存管理的效率和安全性。

10. **加载任务管理 (`LoadTask`)：**
    - 定义了 `LoadTask` 类，用于封装加载共享库所需的各种信息和操作，例如库名、所属命名空间、文件描述符、偏移量等。

11. **依赖树遍历：**
    - 提供了 `walk_dependencies_tree` 模板函数，用于以广度优先的方式遍历共享库的依赖树，并对每个节点执行指定的操作。

12. **符号查找：**
    - 提供了 `dlsym_linear_lookup` 和 `dlsym_handle_lookup` 函数，用于实现 `dlsym` 函数的符号查找功能，支持全局查找和指定句柄查找。
    - `find_containing_library` 函数用于查找包含给定内存地址的共享库。

13. **从 Zip 文件加载库的支持：**
    - 定义了 `ZipArchiveCache` 类用于缓存打开的 Zip 文件，优化从 APK 等 Zip 文件中加载共享库的性能。
    - 提供了 `open_library_in_zipfile` 函数用于打开 Zip 文件中的库。

14. **库文件打开：**
    - 提供了 `open_library_at_path` 和 `open_library_on_paths` 函数，用于根据给定的路径或路径列表打开库文件。

**与 Android 功能的关系及举例：**

* **命名空间隔离：**  Android 使用命名空间来隔离不同的应用程序和系统库。例如，一个应用程序可能加载一个特定版本的 `libssl.so`，而系统库可能加载另一个版本。命名空间确保了它们之间的隔离，避免冲突。`g_default_namespace` 代表了默认的系统库命名空间，而每个应用通常都有自己的私有命名空间。
* **`LD_LIBRARY_PATH`：**  开发者可以通过设置 `LD_LIBRARY_PATH` 环境变量来指定额外的库搜索路径。这在开发和调试过程中非常有用。例如，开发者可以指定一个包含自定义编译的共享库的路径，以便在应用中使用它。
* **从 APK 加载库：**  Android 应用通常将 native 库打包在 APK 文件中。动态链接器能够解析 APK 文件，并从中加载共享库。`open_library_in_zipfile` 函数就是实现这一功能的关键部分。
* **`dlopen` 和 `dlsym`：**  这些是动态链接的核心 API。Android 应用程序和框架可以使用 `dlopen` 加载共享库，并使用 `dlsym` 查找共享库中的符号 (函数或变量)。例如，一个 Java Framework 服务可能会使用 `dlopen` 加载一个 native 库来执行某些底层操作，然后使用 `dlsym` 获取该库中函数的指针。
* **`dl_iterate_phdr`：**  这个函数允许开发者或工具（例如分析器、调试器）遍历所有已加载的共享库的信息，包括它们的加载地址、段信息等。Android 的 `am trace` 工具可能会使用这个函数来收集已加载库的信息。
* **异常处理支持：** 当 native 代码发生异常时，需要进行堆栈回溯。`do_dl_unwind_find_exidx` 提供的信息可以帮助异常处理机制找到正确的堆栈帧信息。

**libc 函数的实现：**

这个 `linker.cpp` 文件主要关注动态链接器的实现，它**使用** libc 函数来完成其工作，但**不负责实现** libc 函数本身。  例如，它会使用：

* **文件 I/O 函数：** `open`, `close`, `read`, `lseek`, `stat` 等，用于打开、读取和获取共享库文件的信息。
* **内存管理函数：** `mmap`, `munmap` 等，用于将共享库加载到内存中和释放内存。
* **字符串处理函数：** `strcmp`, `strlen`, `strcpy`, `basename`, `dirname` 等，用于处理库的名称和路径。
* **错误处理函数：** 设置 `errno` 并可能调用 `perror` 或类似的函数来报告错误。
* **线程同步函数：** `pthread_mutex_lock`, `pthread_mutex_unlock` 等（尽管在这个片段中没有直接看到，但在完整的链接器代码中会存在），用于保护共享的数据结构。

**Dynamic Linker 功能的 SO 布局样本和链接处理过程：**

由于这是第一部分，关于链接处理的细节还没有出现。不过，我们可以初步了解一些概念。

**SO 布局样本：**

一个典型的共享库 (`.so`) 文件（ELF 格式）的布局可能如下：

```
ELF Header
Program Headers (描述了如何将文件加载到内存中)
Section Headers (描述了文件中的不同节，如代码、数据、符号表等)

.text   (代码段)
.rodata (只读数据段)
.data   (已初始化数据段)
.bss    (未初始化数据段)
.dynamic (动态链接信息，包含依赖关系、符号表位置等)
.symtab (符号表)
.strtab (字符串表)
.rel.dyn (动态重定位表)
.rel.plt (PLT 重定位表)
... 其他节 ...
```

**链接处理过程（简述）：**

1. **加载：** 动态链接器读取 SO 文件的 ELF Header 和 Program Headers，根据 Program Headers 的指示，将 SO 文件的各个段加载到内存中的指定地址。
2. **重定位：**  由于共享库被加载到内存中的地址可能不是编译时的地址，动态链接器需要修改代码和数据段中对外部符号的引用，使其指向正确的内存地址。这通过读取 `.rel.dyn` 和 `.rel.plt` 重定位表来完成。
3. **符号解析：**  动态链接器解析 SO 文件中的 `.dynamic` 段，找到其依赖的其他共享库 (DT_NEEDED)。然后，它会加载这些依赖库，并解析 SO 文件中对外部符号的引用，使其指向已加载的依赖库中的符号地址。这通过查找 `.symtab` 符号表来完成。
4. **PLT/GOT 设置：**  对于函数调用，动态链接器会设置 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT)，以实现延迟绑定（lazy binding），即只有在第一次调用函数时才进行符号解析和重定位。

**假设输入与输出（逻辑推理）：**

假设调用 `soinfo_alloc("libtest.so", ...)`：

* **假设输入：**
    * `name`: "libtest.so"
    * `ns`: 指向一个有效的 `android_namespace_t` 结构体的指针。
    * 其他参数（文件状态、偏移量、标志等）。
* **输出：**
    * 如果分配成功，返回指向新分配的 `soinfo` 结构体的指针。
    * 新分配的 `soinfo` 结构体将被添加到 `ns` 的库列表中和全局 `solist` 链表中。
    * 如果内存分配失败，可能导致程序崩溃或返回空指针（取决于错误处理方式）。

假设调用 `parse_LD_LIBRARY_PATH("/system/lib:/vendor/lib")`：

* **假设输入：** 环境变量字符串 "/system/lib:/vendor/lib"。
* **输出：** 默认命名空间 `g_default_namespace` 的库搜索路径列表将被更新，包含 "/system/lib" 和 "/vendor/lib" 两个路径。

**用户或编程常见的使用错误：**

* **`LD_LIBRARY_PATH` 使用不当：**  过度依赖或错误配置 `LD_LIBRARY_PATH` 可能导致加载错误的库版本，引发兼容性问题。例如，在不应该使用的情况下设置 `LD_LIBRARY_PATH` 可能会覆盖系统库，导致系统不稳定。
* **`dlopen` 参数错误：**  传递无效的库路径或 `flags` 给 `dlopen` 可能导致加载失败。例如，尝试加载一个不存在的库或者使用不支持的 `flags`。
* **`dlsym` 找不到符号：**  尝试使用 `dlsym` 查找一个不存在的符号名称或在错误的库句柄中查找，会导致查找失败并返回空指针。
* **内存泄漏：**  使用 `dlopen` 加载库后，忘记使用 `dlclose` 关闭句柄，可能导致内存泄漏。
* **多线程安全问题：**  在多线程环境下不正确地使用动态链接 API (例如，在没有适当同步的情况下修改全局状态) 可能导致竞争条件和程序崩溃。

**Android Framework 或 NDK 如何到达这里：**

1. **Android 系统启动：**  当 Android 系统启动时，`init` 进程首先启动，并执行一系列初始化任务。
2. **`zygote` 进程启动：**  `zygote` 进程是一个特殊的进程，它是所有 Android 应用进程的父进程。`zygote` 进程在启动时会预加载一些常用的共享库，以便后续创建的应用进程可以共享这些库，减少内存占用。`zygote` 进程的启动过程中会涉及到动态链接器的加载和初始化。
3. **应用进程创建：**  当用户启动一个应用时，`zygote` 进程会 `fork` 出一个新的进程。新的应用进程会继承 `zygote` 进程预加载的共享库。
4. **Framework 服务启动：**  Android Framework 中的各种服务（例如 `ActivityManagerService`, `WindowManagerService` 等）通常也会使用 native 库来实现某些功能。这些服务在启动时可能会使用 `dlopen` 加载所需的 native 库。
5. **NDK 开发：**  使用 Android NDK 开发的应用程序可以直接调用动态链接 API (例如 `dlopen`, `dlsym`) 来加载和使用 native 库。

**Frida Hook 示例调试步骤：**

假设你想 hook `soinfo_alloc` 函数：

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("linker64" if Process.arch === 'arm64' else "linker", "soinfo_alloc"), {
    onEnter: function(args) {
        var name = Memory.readUtf8String(args[1]);
        console.log("[+] soinfo_alloc called with name: " + name);
    },
    onLeave: function(retval) {
        console.log("[+] soinfo_alloc returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤说明：**

1. **导入 Frida 库。**
2. **指定要 hook 的应用程序的包名。**
3. **定义消息处理函数 `on_message`，用于打印 Frida 脚本发送的消息。**
4. **尝试连接到目标应用程序进程。**
5. **编写 Frida 脚本代码：**
   - 使用 `Interceptor.attach` 拦截 `soinfo_alloc` 函数的调用。
   - `Module.findExportByName` 用于查找 linker 模块中导出的 `soinfo_alloc` 函数的地址。根据进程架构（32 位或 64 位）选择 "linker" 或 "linker64"。
   - `onEnter` 函数在 `soinfo_alloc` 函数调用前执行，读取并打印传入的库名。
   - `onLeave` 函数在 `soinfo_alloc` 函数返回后执行，打印返回值（`soinfo` 结构体的地址）。
6. **创建 Frida 脚本对象并加载脚本。**
7. **保持脚本运行，直到用户输入。**

运行这个 Frida 脚本，当目标应用程序加载新的共享库时，你将在控制台中看到 `soinfo_alloc` 函数被调用的信息，包括加载的库名和分配的 `soinfo` 结构体的地址。你可以根据需要 hook 其他函数，例如 `open_library` 或 `dlsym`，以调试动态链接过程中的其他步骤。

总而言之，`bionic/linker/linker.cpp` 的第一部分奠定了 Android 动态链接器的基础，定义了关键的数据结构和辅助函数，为后续的库加载、链接和符号解析等核心功能提供了必要的支持。

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
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```cpp
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

#include <android/api-level.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <iterator>
#include <new>
#include <string>
#include <unordered_map>
#include <vector>

#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <async_safe/log.h>
#include <bionic/pthread_internal.h>
#include <platform/bionic/mte.h>

// Private C library headers.

#include "linker.h"
#include "linker_block_allocator.h"
#include "linker_cfi.h"
#include "linker_config.h"
#include "linker_gdb_support.h"
#include "linker_globals.h"
#include "linker_debug.h"
#include "linker_dlwarning.h"
#include "linker_main.h"
#include "linker_namespaces.h"
#include "linker_sleb128.h"
#include "linker_phdr.h"
#include "linker_relocate.h"
#include "linker_tls.h"
#include "linker_translate_path.h"
#include "linker_utils.h"

#include "android-base/macros.h"
#include "android-base/stringprintf.h"
#include "android-base/strings.h"
#include "private/bionic_asm_note.h"
#include "private/bionic_call_ifunc_resolver.h"
#include "private/bionic_globals.h"
#include "ziparchive/zip_archive.h"

static std::unordered_map<void*, size_t> g_dso_handle_counters;

static bool g_anonymous_namespace_set = false;
static android_namespace_t* g_anonymous_namespace = &g_default_namespace;
static std::unordered_map<std::string, android_namespace_t*> g_exported_namespaces;

static LinkerTypeAllocator<soinfo> g_soinfo_allocator;
static LinkerTypeAllocator<LinkedListEntry<soinfo>> g_soinfo_links_allocator;

static LinkerTypeAllocator<android_namespace_t> g_namespace_allocator;
static LinkerTypeAllocator<LinkedListEntry<android_namespace_t>> g_namespace_list_allocator;

static uint64_t g_module_load_counter = 0;
static uint64_t g_module_unload_counter = 0;

static const char* const kLdConfigArchFilePath = "/system/etc/ld.config." ABI_STRING ".txt";

static const char* const kLdConfigFilePath = "/system/etc/ld.config.txt";
static const char* const kLdConfigVndkLiteFilePath = "/system/etc/ld.config.vndk_lite.txt";

static const char* const kLdGeneratedConfigFilePath = "/linkerconfig/ld.config.txt";

#if defined(__LP64__)
static const char* const kSystemLibDir        = "/system/lib64";
static const char* const kOdmLibDir           = "/odm/lib64";
static const char* const kVendorLibDir        = "/vendor/lib64";
static const char* const kAsanSystemLibDir    = "/data/asan/system/lib64";
static const char* const kAsanOdmLibDir       = "/data/asan/odm/lib64";
static const char* const kAsanVendorLibDir    = "/data/asan/vendor/lib64";
#else
static const char* const kSystemLibDir        = "/system/lib";
static const char* const kOdmLibDir           = "/odm/lib";
static const char* const kVendorLibDir        = "/vendor/lib";
static const char* const kAsanSystemLibDir    = "/data/asan/system/lib";
static const char* const kAsanOdmLibDir       = "/data/asan/odm/lib";
static const char* const kAsanVendorLibDir    = "/data/asan/vendor/lib";
#endif

static const char* const kAsanLibDirPrefix = "/data/asan";

static const char* const kDefaultLdPaths[] = {
  kSystemLibDir,
  kOdmLibDir,
  kVendorLibDir,
  nullptr
};

static const char* const kAsanDefaultLdPaths[] = {
  kAsanSystemLibDir,
  kSystemLibDir,
  kAsanOdmLibDir,
  kOdmLibDir,
  kAsanVendorLibDir,
  kVendorLibDir,
  nullptr
};

#if defined(__aarch64__)
static const char* const kHwasanSystemLibDir  = "/system/lib64/hwasan";
static const char* const kHwasanOdmLibDir     = "/odm/lib64/hwasan";
static const char* const kHwasanVendorLibDir  = "/vendor/lib64/hwasan";

// HWASan is only supported on aarch64.
static const char* const kHwsanDefaultLdPaths[] = {
  kHwasanSystemLibDir,
  kSystemLibDir,
  kHwasanOdmLibDir,
  kOdmLibDir,
  kHwasanVendorLibDir,
  kVendorLibDir,
  nullptr
};

// Is HWASAN enabled?
static bool g_is_hwasan = false;
#else
static const char* const kHwsanDefaultLdPaths[] = {
  kSystemLibDir,
  kOdmLibDir,
  kVendorLibDir,
  nullptr
};

// Never any HWASan. Help the compiler remove the code we don't need.
constexpr bool g_is_hwasan = false;
#endif

// Is ASAN enabled?
static bool g_is_asan = false;

static CFIShadowWriter g_cfi_shadow;

CFIShadowWriter* get_cfi_shadow() {
  return &g_cfi_shadow;
}

static bool is_system_library(const std::string& realpath) {
  for (const auto& dir : g_default_namespace.get_default_library_paths()) {
    if (file_is_in_dir(realpath, dir)) {
      return true;
    }
  }
  return false;
}

// Checks if the file exists and not a directory.
static bool file_exists(const char* path) {
  struct stat s;

  if (stat(path, &s) != 0) {
    return false;
  }

  return S_ISREG(s.st_mode);
}

static std::string resolve_soname(const std::string& name) {
  // We assume that soname equals to basename here

  // TODO(dimitry): consider having honest absolute-path -> soname resolution
  // note that since we might end up refusing to load this library because
  // it is not in shared libs list we need to get the soname without actually loading
  // the library.
  //
  // On the other hand there are several places where we already assume that
  // soname == basename in particular for any not-loaded library mentioned
  // in DT_NEEDED list.
  return basename(name.c_str());
}

static bool maybe_accessible_via_namespace_links(android_namespace_t* ns, const char* name) {
  std::string soname = resolve_soname(name);
  for (auto& ns_link : ns->linked_namespaces()) {
    if (ns_link.is_accessible(soname.c_str())) {
      return true;
    }
  }

  return false;
}

// TODO(dimitry): The exempt-list is a workaround for http://b/26394120 ---
// gradually remove libraries from this list until it is gone.
static bool is_exempt_lib(android_namespace_t* ns, const char* name, const soinfo* needed_by) {
  static const char* const kLibraryExemptList[] = {
    "libandroid_runtime.so",
    "libbinder.so",
    "libcrypto.so",
    "libcutils.so",
    "libexpat.so",
    "libgui.so",
    "libmedia.so",
    "libnativehelper.so",
    "libssl.so",
    "libstagefright.so",
    "libsqlite.so",
    "libui.so",
    "libutils.so",
    nullptr
  };

  // If you're targeting N, you don't get the exempt-list.
  if (get_application_target_sdk_version() >= 24) {
    return false;
  }

  // if the library needed by a system library - implicitly assume it
  // is exempt unless it is in the list of shared libraries for one or
  // more linked namespaces
  if (needed_by != nullptr && is_system_library(needed_by->get_realpath())) {
    return !maybe_accessible_via_namespace_links(ns, name);
  }

  // if this is an absolute path - make sure it points to /system/lib(64)
  if (name[0] == '/' && dirname(name) == kSystemLibDir) {
    // and reduce the path to basename
    name = basename(name);
  }

  for (size_t i = 0; kLibraryExemptList[i] != nullptr; ++i) {
    if (strcmp(name, kLibraryExemptList[i]) == 0) {
      return true;
    }
  }

  return false;
}
// END OF WORKAROUND

static std::vector<std::string> g_ld_preload_names;

static void notify_gdb_of_load(soinfo* info) {
  if (info->is_linker() || info->is_main_executable()) {
    // gdb already knows about the linker and the main executable.
    return;
  }

  link_map* map = &(info->link_map_head);

  map->l_addr = info->load_bias;
  // link_map l_name field is not const.
  map->l_name = const_cast<char*>(info->get_realpath());
  map->l_ld = info->dynamic;

  CHECK(map->l_name != nullptr);
  CHECK(map->l_name[0] != '\0');

  notify_gdb_of_load(map);
}

static void notify_gdb_of_unload(soinfo* info) {
  notify_gdb_of_unload(&(info->link_map_head));
}

LinkedListEntry<soinfo>* SoinfoListAllocator::alloc() {
  return g_soinfo_links_allocator.alloc();
}

void SoinfoListAllocator::free(LinkedListEntry<soinfo>* entry) {
  g_soinfo_links_allocator.free(entry);
}

LinkedListEntry<android_namespace_t>* NamespaceListAllocator::alloc() {
  return g_namespace_list_allocator.alloc();
}

void NamespaceListAllocator::free(LinkedListEntry<android_namespace_t>* entry) {
  g_namespace_list_allocator.free(entry);
}

soinfo* soinfo_alloc(android_namespace_t* ns, const char* name,
                     const struct stat* file_stat, off64_t file_offset,
                     uint32_t rtld_flags) {
  if (strlen(name) >= PATH_MAX) {
    async_safe_fatal("library name \"%s\" too long", name);
  }

  LD_DEBUG(any, "name %s: allocating soinfo for ns=%p", name, ns);

  soinfo* si = new (g_soinfo_allocator.alloc()) soinfo(ns, name, file_stat,
                                                       file_offset, rtld_flags);

  solist_add_soinfo(si);

  si->generate_handle();
  ns->add_soinfo(si);

  LD_DEBUG(any, "name %s: allocated soinfo @ %p", name, si);
  return si;
}

static void soinfo_free(soinfo* si) {
  if (si == nullptr) {
    return;
  }

  if (si->base != 0 && si->size != 0) {
    if (!si->is_mapped_by_caller()) {
      munmap(reinterpret_cast<void*>(si->base), si->size);
    } else {
      // remap the region as PROT_NONE, MAP_ANONYMOUS | MAP_NORESERVE
      mmap(reinterpret_cast<void*>(si->base), si->size, PROT_NONE,
           MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    }
  }

  if (si->has_min_version(6) && si->get_gap_size()) {
    munmap(reinterpret_cast<void*>(si->get_gap_start()), si->get_gap_size());
  }

  LD_DEBUG(any, "name %s: freeing soinfo @ %p", si->get_realpath(), si);

  if (!solist_remove_soinfo(si)) {
    async_safe_fatal("soinfo=%p is not in soinfo_list (double unload?)", si);
  }

  // clear links to/from si
  si->remove_all_links();

  si->~soinfo();
  g_soinfo_allocator.free(si);
}

static void parse_path(const char* path, const char* delimiters,
                       std::vector<std::string>* resolved_paths) {
  std::vector<std::string> paths;
  split_path(path, delimiters, &paths);
  resolve_paths(paths, resolved_paths);
}

static void parse_LD_LIBRARY_PATH(const char* path) {
  std::vector<std::string> ld_libary_paths;
  parse_path(path, ":", &ld_libary_paths);
  g_default_namespace.set_ld_library_paths(std::move(ld_libary_paths));
}

static bool realpath_fd(int fd, std::string* realpath) {
  // proc_self_fd needs to be large enough to hold "/proc/self/fd/" plus an
  // integer, plus the NULL terminator.
  char proc_self_fd[32];
  // We want to statically allocate this large buffer so that we don't grow
  // the stack by too much.
  static char buf[PATH_MAX];

  async_safe_format_buffer(proc_self_fd, sizeof(proc_self_fd), "/proc/self/fd/%d", fd);
  auto length = readlink(proc_self_fd, buf, sizeof(buf));
  if (length == -1) {
    if (!is_first_stage_init()) {
      DL_WARN("readlink(\"%s\" [fd=%d]) failed: %m", proc_self_fd, fd);
    }
    return false;
  }

  realpath->assign(buf, length);
  return true;
}

// Returns the address of the current thread's copy of a TLS module. If the current thread doesn't
// have a copy yet, allocate one on-demand if should_alloc is true, and return nullptr otherwise.
static inline void* get_tls_block_for_this_thread(const soinfo_tls* si_tls, bool should_alloc) {
  const TlsModule& tls_mod = get_tls_module(si_tls->module_id);
  if (tls_mod.static_offset != SIZE_MAX) {
    const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
    char* static_tls = reinterpret_cast<char*>(__get_bionic_tcb()) - layout.offset_bionic_tcb();
    return static_tls + tls_mod.static_offset;
  } else if (should_alloc) {
    const TlsIndex ti { si_tls->module_id, static_cast<size_t>(0 - TLS_DTV_OFFSET) };
    return TLS_GET_ADDR(&ti);
  } else {
    TlsDtv* dtv = __get_tcb_dtv(__get_bionic_tcb());
    if (dtv->generation < tls_mod.first_generation) return nullptr;
    return dtv->modules[__tls_module_id_to_idx(si_tls->module_id)];
  }
}

#if defined(__arm__)

// For a given PC, find the .so that it belongs to.
// Returns the base address of the .ARM.exidx section
// for that .so, and the number of 8-byte entries
// in that section (via *pcount).
//
// Intended to be called by libc's __gnu_Unwind_Find_exidx().
_Unwind_Ptr do_dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) {
  if (soinfo* si = find_containing_library(reinterpret_cast<void*>(pc))) {
    *pcount = si->ARM_exidx_count;
    return reinterpret_cast<_Unwind_Ptr>(si->ARM_exidx);
  }
  *pcount = 0;
  return 0;
}

#endif

// Here, we only have to provide a callback to iterate across all the
// loaded libraries. gcc_eh does the rest.
int do_dl_iterate_phdr(int (*cb)(dl_phdr_info* info, size_t size, void* data), void* data) {
  int rv = 0;
  for (soinfo* si = solist_get_head(); si != nullptr; si = si->next) {
    dl_phdr_info dl_info;
    dl_info.dlpi_addr = si->link_map_head.l_addr;
    dl_info.dlpi_name = si->link_map_head.l_name;
    dl_info.dlpi_phdr = si->phdr;
    dl_info.dlpi_phnum = si->phnum;
    dl_info.dlpi_adds = g_module_load_counter;
    dl_info.dlpi_subs = g_module_unload_counter;
    if (soinfo_tls* tls_module = si->get_tls()) {
      dl_info.dlpi_tls_modid = tls_module->module_id;
      dl_info.dlpi_tls_data = get_tls_block_for_this_thread(tls_module, /*should_alloc=*/false);
    } else {
      dl_info.dlpi_tls_modid = 0;
      dl_info.dlpi_tls_data = nullptr;
    }

    rv = cb(&dl_info, sizeof(dl_phdr_info), data);
    if (rv != 0) {
      break;
    }
  }
  return rv;
}

ProtectedDataGuard::ProtectedDataGuard() {
  if (ref_count_++ == 0) {
    protect_data(PROT_READ | PROT_WRITE);
  }

  if (ref_count_ == 0) { // overflow
    async_safe_fatal("Too many nested calls to dlopen()");
  }
}

ProtectedDataGuard::~ProtectedDataGuard() {
  if (--ref_count_ == 0) {
    protect_data(PROT_READ);
  }
}

void ProtectedDataGuard::protect_data(int protection) {
  g_soinfo_allocator.protect_all(protection);
  g_soinfo_links_allocator.protect_all(protection);
  g_namespace_allocator.protect_all(protection);
  g_namespace_list_allocator.protect_all(protection);
}

size_t ProtectedDataGuard::ref_count_ = 0;

// Each size has it's own allocator.
template<size_t size>
class SizeBasedAllocator {
 public:
  static void* alloc() {
    return allocator_.alloc();
  }

  static void free(void* ptr) {
    allocator_.free(ptr);
  }

  static void purge() {
    allocator_.purge();
  }

 private:
  static LinkerBlockAllocator allocator_;
};

template<size_t size>
LinkerBlockAllocator SizeBasedAllocator<size>::allocator_(size);

template<typename T>
class TypeBasedAllocator {
 public:
  static T* alloc() {
    return reinterpret_cast<T*>(SizeBasedAllocator<sizeof(T)>::alloc());
  }

  static void free(T* ptr) {
    SizeBasedAllocator<sizeof(T)>::free(ptr);
  }

  static void purge() {
    SizeBasedAllocator<sizeof(T)>::purge();
  }
};

class LoadTask {
 public:
  struct deleter_t {
    void operator()(LoadTask* t) {
      t->~LoadTask();
      TypeBasedAllocator<LoadTask>::free(t);
    }
  };

  static deleter_t deleter;

  // needed_by is NULL iff dlopen is called from memory that isn't part of any known soinfo.
  static LoadTask* create(const char* _Nonnull name, soinfo* _Nullable needed_by,
                          android_namespace_t* _Nonnull start_from,
                          std::unordered_map<const soinfo*, ElfReader>* _Nonnull readers_map) {
    LoadTask* ptr = TypeBasedAllocator<LoadTask>::alloc();
    return new (ptr) LoadTask(name, needed_by, start_from, readers_map);
  }

  const char* get_name() const {
    return name_;
  }

  soinfo* get_needed_by() const {
    return needed_by_;
  }

  soinfo* get_soinfo() const {
    return si_;
  }

  void set_soinfo(soinfo* si) {
    si_ = si;
  }

  off64_t get_file_offset() const {
    return file_offset_;
  }

  void set_file_offset(off64_t offset) {
    file_offset_ = offset;
  }

  int get_fd() const {
    return fd_;
  }

  void set_fd(int fd, bool assume_ownership) {
    if (fd_ != -1 && close_fd_) {
      close(fd_);
    }
    fd_ = fd;
    close_fd_ = assume_ownership;
  }

  const android_dlextinfo* get_extinfo() const {
    return extinfo_;
  }

  void set_extinfo(const android_dlextinfo* extinfo) {
    extinfo_ = extinfo;
  }

  bool is_dt_needed() const {
    return is_dt_needed_;
  }

  void set_dt_needed(bool is_dt_needed) {
    is_dt_needed_ = is_dt_needed;
  }

  // returns the namespace from where we need to start loading this.
  const android_namespace_t* get_start_from() const {
    return start_from_;
  }

  void remove_cached_elf_reader() {
    CHECK(si_ != nullptr);
    (*elf_readers_map_).erase(si_);
  }

  const ElfReader& get_elf_reader() const {
    CHECK(si_ != nullptr);
    return (*elf_readers_map_)[si_];
  }

  ElfReader& get_elf_reader() {
    CHECK(si_ != nullptr);
    return (*elf_readers_map_)[si_];
  }

  std::unordered_map<const soinfo*, ElfReader>* get_readers_map() {
    return elf_readers_map_;
  }

  bool read(const char* realpath, off64_t file_size) {
    ElfReader& elf_reader = get_elf_reader();
    return elf_reader.Read(realpath, fd_, file_offset_, file_size);
  }

  bool load(address_space_params* address_space) {
    ElfReader& elf_reader = get_elf_reader();
    if (!elf_reader.Load(address_space)) {
      return false;
    }

    si_->base = elf_reader.load_start();
    si_->size = elf_reader.load_size();
    si_->set_mapped_by_caller(elf_reader.is_mapped_by_caller());
    si_->load_bias = elf_reader.load_bias();
    si_->phnum = elf_reader.phdr_count();
    si_->phdr = elf_reader.loaded_phdr();
    si_->set_gap_start(elf_reader.gap_start());
    si_->set_gap_size(elf_reader.gap_size());
    si_->set_should_pad_segments(elf_reader.should_pad_segments());
    si_->set_should_use_16kib_app_compat(elf_reader.should_use_16kib_app_compat());
    if (si_->should_use_16kib_app_compat()) {
      si_->set_compat_relro_start(elf_reader.compat_relro_start());
      si_->set_compat_relro_size(elf_reader.compat_relro_size());
    }

    return true;
  }

 private:
  LoadTask(const char* name,
           soinfo* needed_by,
           android_namespace_t* start_from,
           std::unordered_map<const soinfo*, ElfReader>* readers_map)
    : name_(name), needed_by_(needed_by), si_(nullptr),
      fd_(-1), close_fd_(false), file_offset_(0), elf_readers_map_(readers_map),
      is_dt_needed_(false), start_from_(start_from) {}

  ~LoadTask() {
    if (fd_ != -1 && close_fd_) {
      close(fd_);
    }
  }

  const char* name_;
  soinfo* needed_by_;
  soinfo* si_;
  const android_dlextinfo* extinfo_;
  int fd_;
  bool close_fd_;
  off64_t file_offset_;
  std::unordered_map<const soinfo*, ElfReader>* elf_readers_map_;
  // TODO(dimitry): needed by workaround for http://b/26394120 (the exempt-list)
  bool is_dt_needed_;
  // END OF WORKAROUND
  const android_namespace_t* const start_from_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(LoadTask);
};

LoadTask::deleter_t LoadTask::deleter;

template <typename T>
using linked_list_t = LinkedList<T, TypeBasedAllocator<LinkedListEntry<T>>>;

typedef linked_list_t<soinfo> SoinfoLinkedList;
typedef linked_list_t<const char> StringLinkedList;
typedef std::vector<LoadTask*> LoadTaskList;

enum walk_action_result_t : uint32_t {
  kWalkStop = 0,
  kWalkContinue = 1,
  kWalkSkip = 2
};

// This function walks down the tree of soinfo dependencies
// in breadth-first order and
//   * calls action(soinfo* si) for each node, and
//   * terminates walk if action returns kWalkStop
//   * skips children of the node if action
//     return kWalkSkip
//
// walk_dependencies_tree returns false if walk was terminated
// by the action and true otherwise.
template<typename F>
static bool walk_dependencies_tree(soinfo* root_soinfo, F action) {
  SoinfoLinkedList visit_list;
  SoinfoLinkedList visited;

  visit_list.push_back(root_soinfo);

  soinfo* si;
  while ((si = visit_list.pop_front()) != nullptr) {
    if (visited.contains(si)) {
      continue;
    }

    walk_action_result_t result = action(si);

    if (result == kWalkStop) {
      return false;
    }

    visited.push_back(si);

    if (result != kWalkSkip) {
      si->get_children().for_each([&](soinfo* child) {
        visit_list.push_back(child);
      });
    }
  }

  return true;
}


static const ElfW(Sym)* dlsym_handle_lookup_impl(android_namespace_t* ns,
                                                 soinfo* root,
                                                 soinfo* skip_until,
                                                 soinfo** found,
                                                 SymbolName& symbol_name,
                                                 const version_info* vi) {
  const ElfW(Sym)* result = nullptr;
  bool skip_lookup = skip_until != nullptr;

  walk_dependencies_tree(root, [&](soinfo* current_soinfo) {
    if (skip_lookup) {
      skip_lookup = current_soinfo != skip_until;
      return kWalkContinue;
    }

    if (!ns->is_accessible(current_soinfo)) {
      return kWalkSkip;
    }

    result = current_soinfo->find_symbol_by_name(symbol_name, vi);
    if (result != nullptr) {
      *found = current_soinfo;
      return kWalkStop;
    }

    return kWalkContinue;
  });

  return result;
}

/* This is used by dlsym(3) to performs a global symbol lookup. If the
   start value is null (for RTLD_DEFAULT), the search starts at the
   beginning of the global solist. Otherwise the search starts at the
   specified soinfo (for RTLD_NEXT).
 */
static const ElfW(Sym)* dlsym_linear_lookup(android_namespace_t* ns,
                                            const char* name,
                                            const version_info* vi,
                                            soinfo** found,
                                            soinfo* caller,
                                            void* handle) {
  SymbolName symbol_name(name);

  auto& soinfo_list = ns->soinfo_list();
  auto start = soinfo_list.begin();

  if (handle == RTLD_NEXT) {
    if (caller == nullptr) {
      return nullptr;
    } else {
      auto it = soinfo_list.find(caller);
      CHECK (it != soinfo_list.end());
      start = ++it;
    }
  }

  const ElfW(Sym)* s = nullptr;
  for (auto it = start, end = soinfo_list.end(); it != end; ++it) {
    soinfo* si = *it;
    // Do not skip RTLD_LOCAL libraries in dlsym(RTLD_DEFAULT, ...)
    // if the library is opened by application with target api level < M.
    // See http://b/21565766
    if ((si->get_rtld_flags() & RTLD_GLOBAL) == 0 && si->get_target_sdk_version() >= 23) {
      continue;
    }

    s = si->find_symbol_by_name(symbol_name, vi);
    if (s != nullptr) {
      *found = si;
      break;
    }
  }

  // If not found - use dlsym_handle_lookup_impl for caller's local_group
  if (s == nullptr && caller != nullptr) {
    soinfo* local_group_root = caller->get_local_group_root();

    return dlsym_handle_lookup_impl(local_group_root->get_primary_namespace(),
                                    local_group_root,
                                    (handle == RTLD_NEXT) ? caller : nullptr,
                                    found,
                                    symbol_name,
                                    vi);
  }

  if (s != nullptr) {
    LD_DEBUG(lookup, "%s s->st_value = %p, found->base = %p",
             name, reinterpret_cast<void*>(s->st_value), reinterpret_cast<void*>((*found)->base));
  }

  return s;
}

// This is used by dlsym(3).  It performs symbol lookup only within the
// specified soinfo object and its dependencies in breadth first order.
static const ElfW(Sym)* dlsym_handle_lookup(soinfo* si,
                                            soinfo** found,
                                            const char* name,
                                            const version_info* vi) {
  // According to man dlopen(3) and posix docs in the case when si is handle
  // of the main executable we need to search not only in the executable and its
  // dependencies but also in all libraries loaded with RTLD_GLOBAL.
  //
  // Since RTLD_GLOBAL is always set for the main executable and all dt_needed shared
  // libraries and they are loaded in breath-first (correct) order we can just execute
  // dlsym(RTLD_DEFAULT, ...); instead of doing two stage lookup.
  if (si == solist_get_somain()) {
    return dlsym_linear_lookup(&g_default_namespace, name, vi, found, nullptr, RTLD_DEFAULT);
  }

  SymbolName symbol_name(name);
  // note that the namespace is not the namespace associated with caller_addr
  // we use ns associated with root si intentionally here. Using caller_ns
  // causes problems when user uses dlopen_ext to open a library in the separate
  // namespace and then calls dlsym() on the handle.
  return dlsym_handle_lookup_impl(si->get_primary_namespace(), si, nullptr, found, symbol_name, vi);
}

soinfo* find_containing_library(const void* p) {
  // Addresses within a library may be tagged if they point to globals. Untag
  // them so that the bounds check succeeds.
  ElfW(Addr) address = reinterpret_cast<ElfW(Addr)>(untag_address(p));
  for (soinfo* si = solist_get_head(); si != nullptr; si = si->next) {
    if (address < si->base || address - si->base >= si->size) {
      continue;
    }
    ElfW(Addr) vaddr = address - si->load_bias;
    for (size_t i = 0; i != si->phnum; ++i) {
      const ElfW(Phdr)* phdr = &si->phdr[i];
      if (phdr->p_type != PT_LOAD) {
        continue;
      }
      if (vaddr >= phdr->p_vaddr && vaddr < phdr->p_vaddr + phdr->p_memsz) {
        return si;
      }
    }
  }
  return nullptr;
}

class ZipArchiveCache {
 public:
  ZipArchiveCache() {}
  ~ZipArchiveCache();

  bool get_or_open(const char* zip_path, ZipArchiveHandle* handle);
 private:
  DISALLOW_COPY_AND_ASSIGN(ZipArchiveCache);

  std::unordered_map<std::string, ZipArchiveHandle> cache_;
};

bool ZipArchiveCache::get_or_open(const char* zip_path, ZipArchiveHandle* handle) {
  std::string key(zip_path);

  auto it = cache_.find(key);
  if (it != cache_.end()) {
    *handle = it->second;
    return true;
  }

  int fd = TEMP_FAILURE_RETRY(open(zip_path, O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    return false;
  }

  if (OpenArchiveFd(fd, "", handle) != 0) {
    // invalid zip-file (?)
    CloseArchive(*handle);
    return false;
  }

  cache_[key] = *handle;
  return true;
}

ZipArchiveCache::~ZipArchiveCache() {
  for (const auto& it : cache_) {
    CloseArchive(it.second);
  }
}

static int open_library_in_zipfile(ZipArchiveCache* zip_archive_cache,
                                   const char* const input_path,
                                   off64_t* file_offset, std::string* realpath) {
  std::string normalized_path;
  if (!normalize_path(input_path, &normalized_path)) {
    return -1;
  }

  const char* const path = normalized_path.c_str();
  LD_DEBUG(any, "Trying zip file open from path \"%s\" -> normalized \"%s\"", input_path, path);

  // Treat an '!/' separator inside a path as the separator between the name
  // of the zip file on disk and the subdirectory to search within it.
  // For example, if path is "foo.zip!/bar/bas/x.so", then we search for
  // "bar/bas/x.so" within "foo.zip".
  const char* const separator = strstr(path, kZipFileSeparator);
  if (separator == nullptr) {
    return -1;
  }

  char buf[512];
  if (strlcpy(buf, path, sizeof(buf)) >= sizeof(buf)) {
    DL_WARN("ignoring very long library path: %s", path);
    return -1;
  }

  buf[separator - path] = '\0';

  const char* zip_path = buf;
  const char* file_path = &buf[separator - path + 2];
  int fd = TEMP_FAILURE_RETRY(open(zip_path, O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    return -1;
  }

  ZipArchiveHandle handle;
  if (!zip_archive_cache->get_or_open(zip_path, &handle)) {
    // invalid zip-file (?)
    close(fd);
    return -1;
  }

  ZipEntry entry;

  if (FindEntry(handle, file_path, &entry) != 0) {
    // Entry was not found.
    close(fd);
    return -1;
  }

  // Check if it is properly stored
  if (entry.method != kCompressStored || (entry.offset % page_size()) != 0) {
    close(fd);
    return -1;
  }

  *file_offset = entry.offset;

  if (realpath_fd(fd, realpath)) {
    *realpath += separator;
  } else {
    if (!is_first_stage_init()) {
      DL_WARN("unable to get realpath for the library \"%s\". Will use given path.",
              normalized_path.c_str());
    }
    *realpath = normalized_path;
  }

  return fd;
}

static bool format_path(char* buf, size_t buf_size, const char* path, const char* name) {
  int n = async_safe_format_buffer(buf, buf_size, "%s/%s", path, name);
  if (n < 0 || n >= static_cast<int>(buf_size)) {
    DL_WARN("ignoring very long library path: %s/%s", path, name);
    return false;
  }

  return true;
}

static int open_library_at_path(ZipArchiveCache* zip_archive_cache,
                                const char* path, off64_t* file_offset,
                                std::string* realpath) {
  int fd = -1;
  if (strstr(path, kZipFileSeparator) != nullptr) {
    fd = open_library_in_zipfile(zip_archive_cache, path, file_offset, realpath);
  }

  if (fd == -1) {
    fd = TEMP_FAILURE_RETRY(open(path, O_RDONLY | O_CLOEXEC));
    if (fd != -1) {
      *file_offset = 0;
      if (!realpath_fd(fd, realpath)) {
        if (!is_first_stage_init()) {
          DL_WARN("unable to get realpath for the library \"%s\". Will use given path.", path);
        }
        *realpath = path;
      }
    }
  }

  return fd;
}

static int open_library_on_paths(ZipArchiveCache* zip_archive_cache,
                                 const char* name, off64_t* file_offset,
                                 const std::vector<std::string>& paths,
                                 std::string* realpath) {
  for (const auto& path : paths) {
    char buf[512];
    if (!format_path(buf, sizeof(buf), path.c_str(), name)) {
      continue;
    }

    int fd = open_library_at_path(zip_archive_cache, buf, file_offset, realpath);
    if (fd != -1) {
      return fd;
    }
  }

  return -1;
}

static int open_library(android_namespace_t* ns,
                        ZipArchiveCache* zip_archive_cache,
                        const char* name, soinfo *needed_by,
                        off64_t* file_offset, std::string* realpath) {
  LD_DEBUG(any, "[ opening %s from namespace %s ]", name, ns->get_name());

  // If the name contains a slash, we should attempt to open it directly and not search the paths.
  if (strchr(name, '/') != nullptr) {
    return open_library_at_path(zip_archive_cache, name, file_offset, realpath);
  }

  // LD_LIBRARY_PATH has the highest priority. We don't have to check accessibility when searching
  // the namespace's path lists, because anything found on a namespace path list should always be
  // accessible.
  int fd = open_library_on_paths(zip_archive_cache, name, file_offset, ns->get_ld_library_paths(), realpath);

  // Try the DT_RUNPATH, and verify that the library is accessible.
  if (fd == -1 && needed_by != nullptr) {
    fd = open_library_on_paths(zip_archive_cache, name, file_offset, needed_by->get_dt_runpath(), realpath);
    if (fd != -1 && !ns->is_accessible(*realpath)) {
      close(fd);
      fd = -1;
    }
  }

  // Finally search the namespace's main search path list.
  if (fd == -1) {
    fd = open_library_on_paths(zip_archive_cache, name, file_offset, ns->get_default_library_paths(), realpath);
  }

  return fd;
}

int open_execut
```