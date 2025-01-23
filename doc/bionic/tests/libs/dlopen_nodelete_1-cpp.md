Response:
Let's break down the thought process for analyzing the provided C++ code snippet and generating the comprehensive answer.

**1. Understanding the Context:**

The first step is to recognize the context provided:  `bionic/tests/libs/dlopen_nodelete_1.cpp` within the Android Bionic library. This immediately tells us the file is part of Bionic's test suite and likely related to the dynamic linker (`dlopen`). The filename `dlopen_nodelete_1` hints at testing the `RTLD_NODELETE` flag for `dlopen`.

**2. Deconstructing the Code:**

Next, we need to dissect the code line by line:

* **Includes:** `<stdint.h>` and `<stdlib.h>` are standard C headers. `<stdint.h>` provides fixed-width integer types, and `<stdlib.h>` provides general utility functions (though none are directly used in *this* specific file). This signals that the code is relatively simple.
* **Global Variable:** `uint32_t dlopen_nodelete_1_taxicab_number = 1729;`  A global, publicly visible integer variable initialized to 1729 (a well-known taxicab number). This variable likely serves as a simple symbol that can be checked for existence when the shared library is loaded. Its purpose is primarily for testing if the library is loaded.
* **Global Pointer:** `static bool* unload_flag_ptr = nullptr;` A static (internal linkage) pointer to a boolean. It's initialized to `nullptr`, suggesting it will be set later. The name `unload_flag_ptr` strongly suggests its role in tracking library unloading.
* **Extern "C" Function:** `extern "C" void dlopen_nodelete_1_set_unload_flag_ptr(bool* ptr)`  This defines a C-style function (due to `extern "C"`) that takes a boolean pointer as input and assigns it to the `unload_flag_ptr`. This function provides a way for external code (likely the test driver) to control the behavior of the destructor.
* **Destructor Function:** `static void __attribute__((destructor)) unload_guard()`  This is the most crucial part. The `__attribute__((destructor))` attribute designates this function to be executed when the shared library is unloaded (or when the program exits). Inside the function, it checks if `unload_flag_ptr` is not null and, if so, dereferences it to set the boolean value it points to as `true`. This is the core mechanism for testing if the destructor runs during an unload.

**3. Identifying the Core Functionality:**

Based on the code analysis, the primary function of this shared library is to:

* Export a global variable (`dlopen_nodelete_1_taxicab_number`).
* Provide a way to set a flag (`unload_flag_ptr`).
* Execute a destructor (`unload_guard`) upon unloading (or program exit) that sets the pointed-to flag to `true`.

**4. Connecting to Android Functionality:**

The filename and the presence of the destructor attribute strongly link this to the dynamic linker (`dlopen`) and the `RTLD_NODELETE` flag. The purpose is likely to test that when a library is loaded with `dlopen` and the `RTLD_NODELETE` flag, the destructor *does not* run when `dlclose` is called. Instead, it only runs when the process exits.

**5. Explaining libc Functions:**

The code uses a few standard C elements, but no actual libc functions are called within *this specific file*. The focus is on language features like destructors rather than explicit libc function calls. Therefore, the explanation should focus on these language features rather than `malloc`, `free`, etc.

**6. Detailing Dynamic Linker Aspects:**

This requires understanding how shared libraries are loaded and unloaded in Android. Key elements include:

* **SO Layout:**  Describing the structure of a typical `.so` file (ELF header, sections like `.text`, `.data`, `.bss`, symbol tables, etc.).
* **Linking Process:** Explaining how `dlopen` finds and loads the library, the role of symbol resolution, and how `RTLD_NODELETE` modifies the unloading behavior.

**7. Hypothesizing Inputs and Outputs:**

To illustrate the behavior, consider a test program that:

1. Loads this shared library using `dlopen` with and without `RTLD_NODELETE`.
2. Calls `dlopen_nodelete_1_set_unload_flag_ptr` to provide a boolean variable.
3. Calls `dlclose`.
4. Checks the value of the boolean variable.

The expected output depends on whether `RTLD_NODELETE` was used.

**8. Identifying Common Errors:**

Think about common pitfalls when working with shared libraries:

* Forgetting `extern "C"` for C-compatible interfaces.
* Incorrectly handling pointers passed between libraries.
* Misunderstanding the behavior of `RTLD_NODELETE`.

**9. Illustrating Android Framework/NDK Usage:**

Describe how the Android framework or NDK might interact with `dlopen`. For example, how the system loads native libraries for apps or how developers use `dlopen` in their NDK code.

**10. Providing Frida Hook Examples:**

Frida is a powerful tool for dynamic analysis. Think about how to hook:

* The `dlopen` function to observe when the library is loaded and with what flags.
* The `dlclose` function to see when it's called.
* The `dlopen_nodelete_1_set_unload_flag_ptr` function to see how the flag is being set.
* The `unload_guard` destructor to see when it executes.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus heavily on libc function explanations.
* **Correction:** Realize that the core of *this* file is about dynamic linking behavior, specifically destructors. Shift the focus accordingly and address libc only where directly relevant (like `stdlib.h`).
* **Initial thought:** Provide a highly technical, low-level explanation of the dynamic linker.
* **Refinement:** Balance technical detail with clarity and examples, making it accessible to a wider audience. Focus on the practical implications of `RTLD_NODELETE`.
* **Initial thought:**  Assume the user has deep knowledge of Android internals.
* **Refinement:** Provide context and definitions for key terms like "Bionic," "NDK," and "Frida."

By following these steps, iterating through the code, connecting it to the larger Android ecosystem, and considering potential user misunderstandings, a comprehensive and informative answer can be constructed. The process involves both a detailed technical analysis and a broader understanding of the context and intended use of the code.
好的，让我们详细分析一下 `bionic/tests/libs/dlopen_nodelete_1.cpp` 这个文件。

**文件功能概述**

这个 C++ 源文件定义了一个简单的共享库（shared library，通常编译成 `.so` 文件）。它的主要目的是为了测试 Android Bionic 动态链接器 (`dlopen`) 中 `RTLD_NODELETE` 标志的行为。具体来说，它验证了当使用 `RTLD_NODELETE` 加载共享库时，即使调用 `dlclose` 卸载该库，其析构函数也不会立即执行，而会在进程退出时执行。

**与 Android 功能的关系及举例**

这个文件直接关系到 Android 的动态链接机制。动态链接是 Android 操作系统的重要组成部分，它允许应用程序在运行时加载和链接共享库，从而实现代码的模块化、重用和减少应用程序的体积。

* **`dlopen` 函数:**  这是 Android Bionic 提供的用于动态加载共享库的函数。这个测试文件正是为了验证 `dlopen` 的特定行为。
* **`RTLD_NODELETE` 标志:**  这是 `dlopen` 函数的一个标志。当使用这个标志加载共享库时，即使使用 `dlclose` 卸载该库，系统也不会立即卸载该库占用的内存和调用其析构函数。这在某些特殊场景下很有用，例如，当多个库之间存在循环依赖，并且需要确保某些库的全局对象在其他库卸载后仍然有效。

**举例说明:**

假设有两个共享库 `libA.so` 和 `libB.so`。`libA.so` 中定义了一个全局对象，并且 `libB.so` 依赖于这个对象。如果 `libA.so` 使用 `RTLD_NODELETE` 加载，即使 `libA.so` 被 `dlclose`，其全局对象仍然存在，`libB.so` 仍然可以访问它，直到整个进程退出。

**详细解释每一个 libc 函数的功能是如何实现的**

在这个特定的文件中，涉及到的 "libc 函数" 主要指的是 C++ 的语言特性，而不是 `libc.so` 提供的标准 C 函数。

* **`uint32_t` (来自 `<stdint.h>`):** 这定义了一个 32 位无符号整数类型。在这个文件中，`dlopen_nodelete_1_taxicab_number` 就是这个类型。它的实现是编译器和目标架构相关的，确保变量能够存储 0 到 4,294,967,295 之间的整数。

* **`bool` (来自 `<stdbool.h>` 或 C++ 内置类型):**  这是一个布尔类型，可以取 `true` 或 `false` 两个值。`unload_flag_ptr` 指向一个 `bool` 变量。

* **`nullptr` (C++11):**  这是一个空指针常量，用于表示指针不指向任何有效的内存地址。`unload_flag_ptr` 初始化为 `nullptr`。

* **`extern "C"`:**  这是一个链接指示符，告诉 C++ 编译器使用 C 语言的链接约定来处理被声明的函数或变量。这通常用于与 C 代码进行互操作。在这个文件中，`dlopen_nodelete_1_set_unload_flag_ptr` 函数使用了 `extern "C"`，这意味着它可以被 C 代码直接调用。C 链接约定通常意味着函数名不会被 "name mangling"（名字修饰），这样链接器才能正确地找到函数。

* **`static` (用于全局变量和函数):**
    * **`static bool* unload_flag_ptr`:**  当用于全局变量时，`static` 关键字表示该变量具有内部链接。这意味着 `unload_flag_ptr` 只能在当前编译单元（即 `dlopen_nodelete_1.cpp` 文件）中访问，不会与其他编译单元中同名的全局变量冲突。
    * **`static void unload_guard()`:** 当用于函数时，`static` 关键字也表示该函数具有内部链接，只能在当前编译单元中调用。

* **`void dlopen_nodelete_1_set_unload_flag_ptr(bool* ptr)`:** 这是一个函数定义，它接受一个指向 `bool` 类型的指针 `ptr` 作为参数，并将该指针赋值给全局静态变量 `unload_flag_ptr`。

* **`__attribute__((destructor))`:** 这是一个 GCC 和 Clang 提供的编译器扩展属性。当用于函数声明时，它表示该函数是一个析构函数，会在共享库被卸载（或者程序退出）时自动执行。`unload_guard` 函数被标记为析构函数。

    * **实现原理:** 当动态链接器加载共享库时，它会记录所有带有 `__attribute__((destructor))` 属性的函数。当 `dlclose` 被调用，或者进程退出时，动态链接器会遍历这些记录，并调用相应的函数。对于使用 `RTLD_NODELETE` 加载的库，析构函数的调用会被延迟到进程退出时。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

**SO 布局样本:**

一个典型的 Android 共享库 (`.so` 文件) 的布局（简化版）如下：

```
ELF Header:
  Magic:   7f 45 4c 46 ... (标识这是一个 ELF 文件)
  Class:                             ELF32 或 ELF64 (32位或64位)
  Data:                              Little-endian 或 Big-endian
  Version:                           ...
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (共享目标文件)
  Machine:                           ARM, ARM64, x86, x86-64 等 (目标架构)
  Entry point address:               ...
  Program headers offset:            ...
  Section headers offset:            ...
  Flags:                             ...
  Size of this header:               ...
  Size of program headers:           ...
  Number of program headers:         ...
  Size of section headers:           ...
  Number of section headers:       ...
  String table index:                ...

Program Headers: (描述内存段的加载信息)
  Type           Offset             VirtAddr           PhysAddr           FileSiz            MemSiz              Flags  Align
  LOAD           0x00000000         0xXXXXXXXX         0xXXXXXXXX         0xYYYYYYYY         0xZZZZZZZZ          R E    0x1000  (.text, .rodata)
  LOAD           0xAAAAAAAA         0xWWWWWWWW         0xWWWWWWWW         0xVVVVVVVV         0xUUUUUUUU          RW     0x1000  (.data, .bss)
  DYNAMIC        ...                ...                ...                ...                ...                 ...    ...    (动态链接信息)

Section Headers: (描述文件中的各个节)
  [Nr] Name              Type             Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL             00000000         000000 000000  0      0   0
  [ 1] .text             PROGBITS         XXXXXXXX         YYYYYY ZZZZZZ  0  AX  0   0  4  (代码段)
  [ 2] .rodata           PROGBITS         XXXXXXXX         YYYYYY ZZZZZZ  0   A  0   0  4  (只读数据段)
  [ 3] .data             PROGBITS         XXXXXXXX         YYYYYY ZZZZZZ  0  WA  0   0  4  (已初始化数据段)
  [ 4] .bss              NOBITS           XXXXXXXX         YYYYYY ZZZZZZ  0  WA  0   0  4  (未初始化数据段)
  [ 5] .dynamic          DYNAMIC          XXXXXXXX         YYYYYY ZZZZZZ  0  WA  6   0  4  (动态链接信息)
  [ 6] .dynsym           DYNSYM           XXXXXXXX         YYYYYY ZZZZZZ 16   A  7   1  4  (动态符号表)
  [ 7] .dynstr           STRTAB           XXXXXXXX         YYYYYY ZZZZZZ  0   A  0   0  1  (动态字符串表)
  [ 8] .symtab           SYMTAB           XXXXXXXX         YYYYYY ZZZZZZ 16   A  9  34  4  (符号表)
  [ 9] .strtab           STRTAB           XXXXXXXX         YYYYYY ZZZZZZ  0   A  0   0  1  (字符串表)
  [10] .shstrtab         STRTAB           XXXXXXXX         YYYYYY ZZZZZZ  0   A  0   0  1  (节头字符串表)
  ...

Dynamic Section: (提供动态链接器所需的信息)
  TAG        VALUE
  SONAME     libdlopen_nodelete_1.so (共享库的名字)
  INIT       0xXXXXXXXX (初始化函数地址)
  FINI       0xYYYYYYYY (终止函数地址，可能指向 unload_guard)
  ...
  SYMTAB     指向 .dynsym
  STRTAB     指向 .dynstr
  ...

Symbol Table (.dynsym, .symtab): (包含导出的符号信息)
  Num:    Value          Size Type    Bind   Vis      Ndx Name
    0: 00000000     0 NOTYPE  LOCAL  DEFAULT  UND
    1: 000004b0     4 OBJECT  GLOBAL DEFAULT   17 dlopen_nodelete_1_taxicab_number
    2: 000004b4    36 FUNC    GLOBAL DEFAULT   17 dlopen_nodelete_1_set_unload_flag_ptr
    3: 000004ec     8 FUNC    LOCAL  DEFAULT   17 _ZL12unload_guardv
    ...
```

**链接的处理过程:**

1. **`dlopen` 调用:** 当应用程序调用 `dlopen("libdlopen_nodelete_1.so", RTLD_NOW | RTLD_NODELETE)` 时，系统内核会将这个请求传递给动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`)。

2. **查找共享库:** 动态链接器会在预定义的路径（例如 `/system/lib`, `/vendor/lib`, 以及应用程序的 `libs` 目录等）中查找名为 `libdlopen_nodelete_1.so` 的文件。

3. **加载共享库:**  如果找到该文件，动态链接器会执行以下操作：
   * **解析 ELF 头:** 读取 ELF 头来确定文件的类型、目标架构等信息。
   * **映射内存段:** 根据 Program Headers 中的信息，将共享库的各个段（如 `.text`, `.data`, `.bss`）映射到进程的地址空间中。
   * **处理动态链接信息:** 读取 `.dynamic` 段，获取动态链接所需的各种信息，例如依赖的共享库、符号表的位置、初始化和终止函数的地址等。

4. **符号解析:**
   * **查找所需符号:** 如果共享库依赖于其他共享库的符号，动态链接器会查找这些符号的定义。
   * **重定位:** 动态链接器会修改代码和数据段中的地址，以指向正确的内存位置。这包括对全局变量和函数地址的调整。

5. **执行初始化函数:** 如果共享库有初始化函数（通常通过 `.init` 或 `.init_array` 段指定），动态链接器会在此时执行这些函数。

6. **`RTLD_NODELETE` 的影响:** 当 `RTLD_NODELETE` 标志被使用时，动态链接器会标记该共享库，指示在调用 `dlclose` 时不要卸载该库的内存，也不要执行其析构函数。

7. **`dlclose` 调用:** 当应用程序调用 `dlclose(handle)` 时，如果加载时使用了 `RTLD_NODELETE`，动态链接器会减少该共享库的引用计数，但 **不会** 立即执行以下操作：
   * **解除内存映射:**  共享库的代码和数据段仍然映射在进程的地址空间中。
   * **执行析构函数:**  `unload_guard` 函数不会被立即调用。

8. **进程退出:** 当应用程序进程退出时，操作系统会清理进程占用的所有资源，包括使用 `RTLD_NODELETE` 加载的共享库。此时，动态链接器会执行这些共享库的析构函数（例如 `unload_guard`）。

**假设输入与输出**

假设我们有一个测试程序 `test_dlopen`，它执行以下操作：

1. `dlopen("libdlopen_nodelete_1.so", RTLD_NOW | RTLD_NODELETE)` 加载共享库。
2. 获取 `dlopen_nodelete_1_set_unload_flag_ptr` 函数的地址。
3. 分配一个 `bool` 变量 `unload_flag` 并初始化为 `false`。
4. 调用 `dlopen_nodelete_1_set_unload_flag_ptr(&unload_flag)`。
5. `dlclose` 卸载共享库。
6. 打印 `unload_flag` 的值。
7. 进程退出。

**预期输出:**

在步骤 6 打印 `unload_flag` 时，其值应该是 `false`，因为使用了 `RTLD_NODELETE`，析构函数 `unload_guard` 尚未执行。

当进程退出时，`unload_guard` 会被执行，将 `unload_flag` 指向的内存设置为 `true`。但是，由于步骤 6 发生在 `dlclose` 之后，进程退出之前，所以观察到的输出是 `false`。

**用户或编程常见的使用错误**

1. **忘记 `extern "C"`:** 如果 `dlopen_nodelete_1_set_unload_flag_ptr` 函数没有使用 `extern "C"`，C++ 编译器会对函数名进行修饰（name mangling），导致在 C 代码中使用 `dlsym` 查找该函数时失败。

   ```cpp
   // 错误示例，C 代码无法找到此函数
   void dlopen_nodelete_1_set_unload_flag_ptr(bool* ptr) {
     unload_flag_ptr = ptr;
   }
   ```

2. **误解 `RTLD_NODELETE` 的作用:** 开发者可能会错误地认为使用 `RTLD_NODELETE` 可以永久阻止共享库被卸载。实际上，这只是延迟了卸载和析构函数的执行到进程退出时。如果程序中有资源管理依赖于析构函数的及时执行，使用 `RTLD_NODELETE` 可能会导致问题。

3. **野指针:** 如果在 `dlclose` 之后仍然尝试访问共享库中的数据或函数（除了使用了 `RTLD_NODELETE` 的情况，但在进程退出前访问仍然是不安全的），可能会导致程序崩溃或未定义行为。

4. **忘记检查 `dlopen` 和 `dlsym` 的返回值:**  `dlopen` 在加载失败时会返回 `NULL`，`dlsym` 在找不到符号时也会返回 `NULL`。没有检查这些返回值会导致程序在遇到错误时崩溃。

**Android Framework 或 NDK 如何一步步的到达这里，给出 frida hook 示例调试这些步骤**

**Android Framework 到达这里的路径 (示例，可能因具体场景而异):**

1. **Java 代码调用 System.loadLibrary:**  Android 应用的 Java 代码可能会调用 `System.loadLibrary("dlopen_nodelete_1")` 来加载共享库。

2. **Framework 调用 Runtime Native 方法:** `System.loadLibrary` 最终会调用到 Android Framework 的 Runtime Native 方法，例如 `java.lang.Runtime.nativeLoad`。

3. **Runtime 调用 Linker 功能:** `nativeLoad` 方法会调用底层的 Bionic 链接器相关的功能。这可能涉及到调用 `dlopen` 函数。

4. **Bionic `dlopen` 执行:** Bionic 的 `dlopen` 函数会执行上述的动态链接过程，包括加载共享库、解析符号等。

**NDK 到达这里的路径:**

1. **NDK 代码调用 `dlopen`:**  使用 NDK 开发的本地代码可以直接调用 `dlopen` 函数来加载共享库。

   ```c++
   #include <dlfcn.h>

   void load_my_library() {
     void* handle = dlopen("libdlopen_nodelete_1.so", RTLD_NOW | RTLD_NODELETE);
     if (handle == nullptr) {
       // 处理错误
     }
     // ... 使用库中的符号
     // dlclose(handle); // 可能在稍后调用
   }
   ```

**Frida Hook 示例:**

我们可以使用 Frida 来 hook 关键的函数，观察参数和返回值，从而理解调用流程。

```python
import frida
import sys

package_name = "your.app.package"  # 替换成你的应用包名
library_name = "libdlopen_nodelete_1.so"

session = frida.attach(package_name)

script = session.create_script("""
    // Hook dlopen
    var dlopenPtr = Module.findExportByName(null, "dlopen");
    if (dlopenPtr) {
        Interceptor.attach(dlopenPtr, {
            onEnter: function(args) {
                var filename = Memory.readUtf8String(args[0]);
                var flags = args[1].toInt();
                console.log("[dlopen] filename: " + filename + ", flags: " + flags.toString(16));
                this.filename = filename;
            },
            onLeave: function(retval) {
                if (this.filename.indexOf("""" + library_name + """") !== -1) {
                    console.log("[dlopen] Loaded " + this.filename + " at " + retval);
                }
            }
        });
    } else {
        console.log("[-] dlopen not found");
    }

    // Hook dlclose
    var dlclosePtr = Module.findExportByName(null, "dlclose");
    if (dlclosePtr) {
        Interceptor.attach(dlclosePtr, {
            onEnter: function(args) {
                console.log("[dlclose] handle: " + args[0]);
            }
        });
    } else {
        console.log("[-] dlclose not found");
    }

    // Hook 析构函数 (需要找到实际地址，可以通过 readelf 或其他工具获取)
    var unloadGuardAddr = Module.findExportByName("libdlopen_nodelete_1.so", "_ZL12unload_guardv"); // 名字可能被修饰
    if (unloadGuardAddr) {
        Interceptor.attach(unloadGuardAddr, {
            onEnter: function(args) {
                console.log("[unload_guard] called");
            }
        });
    } else {
        console.log("[-] unload_guard not found (check name mangling)");
    }

    // Hook dlopen_nodelete_1_set_unload_flag_ptr
    var setFlagPtr = Module.findExportByName("libdlopen_nodelete_1.so", "dlopen_nodelete_1_set_unload_flag_ptr");
    if (setFlagPtr) {
        Interceptor.attach(setFlagPtr, {
            onEnter: function(args) {
                console.log("[dlopen_nodelete_1_set_unload_flag_ptr] ptr: " + args[0]);
            }
        });
    } else {
        console.log("[-] dlopen_nodelete_1_set_unload_flag_ptr not found");
    }

""")

script.on('message', lambda message, data: print(message))
script.load()
sys.stdin.read()
```

**Frida Hook 解释:**

* **Hook `dlopen`:**  捕获 `dlopen` 函数的调用，记录加载的文件名和标志位，特别是关注是否加载了 `libdlopen_nodelete_1.so` 以及是否使用了 `RTLD_NODELETE` (其值为 `0x2`).
* **Hook `dlclose`:** 捕获 `dlclose` 函数的调用，记录传入的句柄。
* **Hook `unload_guard`:**  捕获析构函数的执行。你需要找到 `unload_guard` 函数在 `libdlopen_nodelete_1.so` 中的实际地址或修饰后的名称。可以使用 `readelf -s libdlopen_nodelete_1.so` 命令来查看符号表。
* **Hook `dlopen_nodelete_1_set_unload_flag_ptr`:** 捕获设置 `unload_flag_ptr` 的函数调用，查看传入的指针地址。

通过运行这个 Frida 脚本，并让目标应用执行加载和卸载 `libdlopen_nodelete_1.so` 的操作，你可以在 Frida 的控制台中看到相关的日志输出，从而调试这些步骤。

希望这个详细的解释能够帮助你理解 `bionic/tests/libs/dlopen_nodelete_1.cpp` 文件的功能以及它在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/tests/libs/dlopen_nodelete_1.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <stdint.h>
#include <stdlib.h>

uint32_t dlopen_nodelete_1_taxicab_number = 1729;
static bool* unload_flag_ptr = nullptr;

extern "C" void dlopen_nodelete_1_set_unload_flag_ptr(bool* ptr) {
  unload_flag_ptr = ptr;
}

static void __attribute__((destructor)) unload_guard() {
  if (unload_flag_ptr != nullptr) {
    *unload_flag_ptr = true;
  }
}
```