Response:
Let's break down the thought process for answering the request about `libc_init_dynamic.cpp`.

**1. Understanding the Core Request:**

The central goal is to analyze the functionality of `libc_init_dynamic.cpp` within the Android bionic library. This involves identifying its roles, explaining its interactions with the Android ecosystem, detailing its internal mechanisms, and providing debugging insights.

**2. Initial Reading and Identifying Key Functions:**

The first step is to carefully read the provided source code and identify the major functions:

* `__libc_preinit`: Called early by the dynamic linker. It seems responsible for early libc initialization.
* `__libc_init`: Called after dynamic linking is complete, responsible for launching the program.
* `memtag_stack_dlopen_callback`:  A callback related to memory tagging.
* `__libc_preinit_impl`: A helper for `__libc_preinit`.
* `__libc_shared_globals`:  A helper to access global state.

Also, pay attention to comments, `#include` directives, and external function declarations. These provide clues about the purpose of the file.

**3. Deconstructing Functionality (Step-by-Step for each major function):**

* **`__libc_preinit`:**
    * **Trigger:**  The `__attribute__((constructor(1)))` strongly suggests it's an initializer called by the dynamic linker.
    * **Early Stage:**  The comment "before any other initializer" is crucial.
    * **Key Actions:** Initialize `__stack_chk_guard`, call `__libc_preinit_impl`.
    * **Android Relevance:** Essential for setting up the libc environment before other parts of the system initialize.

* **`__libc_preinit_impl`:**
    * **Reason for Existence:**  The comment about LTO and stack protector is the key here. It separates early initialization from potentially unsafe operations.
    * **Key Actions:**
        * Initialize system info (x86 specific).
        * Register TLS generation variable.
        * Initialize global variables, common libc stuff, and scudo (memory allocator).
        * Set up HWASan hooks.
        * Call malloc initialization (important!).
        * Install profiling and fork handlers.
        * Set the target SDK version hook.
        * Call `netdClientInit`.
    * **Android Relevance:** Initializes core services and hooks that many Android components rely on.

* **`__libc_init`:**
    * **Trigger:** Called from `_start` in `crtbegin.c` after dynamic linking.
    * **Late Stage:**  Happens after all constructors have run.
    * **Key Actions:**
        * Stop unwinding (safety measure).
        * Create `KernelArgumentBlock` to access program arguments.
        * Register the executable's destructors using `__cxa_atexit`.
        * Initialize MTE late.
        * Set the `memtag_stack_dlopen_callback`.
        * Finally, call the `slingshot` function (typically `main`).
    * **Android Relevance:** The entry point for user-space processes after the dynamic linker has done its work.

* **`memtag_stack_dlopen_callback`:**
    * **Purpose:** Related to Memory Tagging Extension (MTE).
    * **Action:** Remaps stacks with MTE protection if possible.
    * **Android Relevance:** Security feature in modern Android versions.

* **`__libc_shared_globals`:**
    * **Purpose:** Access a global data structure shared between libc and the dynamic linker.
    * **Android Relevance:**  Facilitates communication and shared state management between core system components.

**4. Connecting to Android Features:**

Throughout the analysis, actively think about how each function or action relates to broader Android concepts:

* **Dynamic Linking:** `__libc_preinit` and `__libc_init` are directly involved in the dynamic linking process.
* **Memory Management:** Scudo, HWASan, and MTE are crucial Android memory management and security features.
* **Process Startup:**  This file is central to the startup of every Android process.
* **NDK:**  NDK applications rely on the libc provided by bionic.
* **Framework:** The Android Framework ultimately starts processes that use this code.

**5. Explaining Libc Functions:**

For functions like `__cxa_atexit`, explain its standard C++ purpose (registering functions to be called at exit) and how it's used in this context (handling executable destructors).

**6. Dynamic Linker Details:**

* **SO Layout Sample:** Create a simple example with `libc.so` and a dependent library. Show the basic sections (.text, .data, .dynamic, etc.).
* **Linking Process:** Outline the key steps: finding libraries, resolving symbols, relocation, TLS setup. Mention the roles of the `.dynamic` section and GOT/PLT.

**7. Logic, Assumptions, and Input/Output:**

Consider scenarios:

* **Assumption:**  The `slingshot` function is typically the `main` function.
* **Input:**  Command-line arguments passed to the process.
* **Output:**  The execution of the program's `main` function.

**8. Common Usage Errors:**

Think about common programming mistakes that might relate to early initialization or dynamic linking:

* Incorrect library paths.
* Missing dependencies.
* Static initialization order problems.

**9. Tracing Execution with Frida:**

* **Identify Hook Points:** Focus on `__libc_preinit` and `__libc_init` as key entry points.
* **Frida Script:** Provide a basic example of how to attach to a process and hook these functions, logging their execution.

**10. Structuring the Answer:**

Organize the information logically using headings and bullet points. Start with a high-level summary, then delve into the details of each function and concept. Provide examples and code snippets where appropriate. Use clear and concise language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Should I explain ELF in great detail?"  **Correction:** Focus on the relevant aspects for this file (e.g., the `.init_array`, `.fini_array`, `.dynamic` section).
* **Initial thought:** "Just list the functions." **Correction:** Explain the *purpose* and *mechanism* of each function.
* **Initial thought:** "Assume the user knows about dynamic linking." **Correction:** Provide a basic overview of the dynamic linking process.

By following these steps and continuously refining the approach, you can construct a comprehensive and informative answer to the user's request.
好的，让我们深入分析 `bionic/libc/bionic/libc_init_dynamic.cpp` 文件。

**文件功能概览**

`libc_init_dynamic.cpp` 在 Android Bionic C 库中扮演着至关重要的角色，它为动态链接的可执行文件提供了两个核心功能：

1. **C 运行时预初始化 (`__libc_preinit`)**:  这是一个由动态链接器在加载 `libc.so` 时调用的函数。它发生在任何其他初始化器（例如，程序依赖的其他共享库中的静态 C++ 构造函数）之前。它的主要任务是设置 `libc` 自身运行所需的初始环境。

2. **程序启动 (`__libc_init`)**:  这是一个在所有动态链接完成之后被调用的函数。它负责完成 `libc` 的初始化，并最终启动应用程序的 `main` 函数。

**与 Android 功能的关系和举例**

这两个函数是 Android 应用程序启动流程的基石。没有它们，应用程序就无法正常运行。

* **动态链接器 (`linker`/`ld-android.so`)**:  `__libc_preinit` 是动态链接器与 `libc` 交互的关键点。动态链接器负责加载共享库，而 `libc` 是所有 Android 应用程序最基本、最重要的共享库。
    * **例子**: 当你启动一个 Android 应用时，动态链接器首先会加载 `libc.so`，并在加载过程中调用 `__libc_preinit` 来初始化 `libc` 的基本环境。
* **C 运行时环境**:  `__libc_init` 负责建立应用程序运行所需的 C 运行时环境，例如初始化全局变量、设置内存分配器等。
    * **例子**:  `__libc_init` 中会调用 `__libc_init_malloc` 初始化内存分配器 (例如 Scudo 或 jemalloc)，使得应用程序可以使用 `malloc`、`free` 等函数进行内存管理。
* **线程本地存储 (TLS)**: `__libc_preinit` 中注册了 `libc.so` 的 TLS 生成变量，这允许动态链接器在加载或卸载共享对象时更新 TLS。
    * **例子**: 当加载一个新的共享库时，动态链接器需要更新所有线程的 TLS 数据结构，`__libc_preinit` 中设置的机制确保了 `libc` 的 TLS 状态与动态链接器的状态同步。
* **安全特性**:  `__libc_preinit` 中会进行一些安全相关的初始化，例如设置栈保护 (`__stack_chk_guard`)，以及在支持硬件地址消毒器 (HWASan) 的设备上注册相应的 hook 函数。
    * **例子**: HWASan 是一种内存错误检测工具。`__libc_preinit` 中注册的 `__hwasan_library_loaded` 和 `__hwasan_library_unloaded` 函数允许 HWASan 在库加载和卸载时更新其影子内存，从而进行有效的内存错误检测。
* **性能分析**: `__libc_preinit` 中会安装用于平台性能分析器的保留信号处理程序。
    * **例子**: Android 的性能分析工具可以使用这些信号处理程序来收集应用程序的性能数据。
* **fork 处理**: `__libc_preinit` 中会初始化 `fork` 处理程序，用于在 `fork` 系统调用之后执行一些必要的清理和初始化操作。
* **目标 SDK 版本**: `__libc_preinit` 设置了用于获取目标 SDK 版本的钩子函数。
    * **例子**:  一些 `libc` 的行为会根据应用程序的目标 SDK 版本进行调整，这个钩子函数允许 `libc` 获取到这个信息。
* **网络**: `__libc_preinit` 调用了 `netdClientInit`，这可能涉及到与网络守护进程 (`netd`) 的初始化连接。

**libc 函数功能实现详解**

让我们逐个解释 `libc_init_dynamic.cpp` 中涉及的关键 `libc` 函数的功能和实现方式：

1. **`__libc_preinit()`**:
   * **功能**: 由动态链接器在加载 `libc.so` 时调用，进行 `libc` 的早期初始化。
   * **实现**:
     * 初始化栈保护 Cookie (`__stack_chk_guard`)：从 TLS 中获取动态链接器初始化的值。
     * 调用 `__libc_preinit_impl()` 执行具体的初始化逻辑。

2. **`__libc_preinit_impl()`**:
   * **功能**:  执行 `libc` 的核心预初始化工作。
   * **实现**:
     * (x86 架构) 初始化系统信息 (`__libc_init_sysinfo`)。
     * 注册 `libc.so` 的 TLS 生成变量，以便动态链接器更新。
     * 初始化全局变量 (`__libc_init_globals`)。
     * 初始化通用的 `libc` 组件 (`__libc_init_common`)。
     * 初始化内存分配器 Scudo (`__libc_init_scudo`)。
     * (如果启用了 HWASan) 注册库加载和卸载的 hook 函数。
     * 调用 `__libc_init_malloc` 初始化内存分配器。
     * 安装性能分析处理程序 (`__libc_init_profiling_handlers`)。
     * 初始化 `fork` 处理程序 (`__libc_init_fork_handler`)。
     * 设置目标 SDK 版本钩子 (`__libc_shared_globals()->set_target_sdk_version_hook = __libc_set_target_sdk_version`)。
     * 调用 `netdClientInit()` 进行网络相关的初始化。

3. **`__libc_init()`**:
   * **功能**: 在动态链接完成后，由可执行文件的入口点 `_start` 调用，完成 `libc` 的最终初始化并启动应用程序。
   * **实现**:
     * 禁用 unwind 操作 (`BIONIC_STOP_UNWIND`)。
     * 创建 `KernelArgumentBlock` 对象来访问程序参数 (argc, argv, envp)。
     * 使用 `__cxa_atexit` 注册可执行文件的析构函数，确保程序正常退出时被调用。
     * 执行后期的内存标签扩展 (MTE) 初始化 (`__libc_init_mte_late`)。
     * 设置用于内存标签堆栈 dlopen 回调的函数指针。
     * 调用 `exit()` 函数，参数是 `slingshot` 函数的返回值。`slingshot` 通常指向应用程序的 `main` 函数。

4. **`__cxa_atexit()`**:
   * **功能**:  一个 C++ 标准库函数，用于注册在程序正常退出时需要调用的函数。
   * **实现**: `libc` 内部维护一个函数指针链表，`__cxa_atexit` 将需要调用的函数添加到这个链表中。当程序调用 `exit()` 或 `return` 自 `main` 函数时，这个链表中的函数会被依次调用。

5. **`__libc_fini()`**:
   * **功能**:  `libc` 提供的析构函数，在程序退出时被 `__cxa_atexit` 调用。
   * **实现**:  这个函数的具体实现没有在这个文件中，它通常负责清理 `libc` 内部的资源。

6. **`__libc_shared_globals()`**:
   * **功能**:  返回一个指向全局共享状态结构的指针，这个结构在 `libc` 和动态链接器之间共享。
   * **实现**:  它简单地调用了 `__loader_shared_globals()`，这个函数由动态链接器提供。

7. **`memtag_stack_dlopen_callback()`**:
   * **功能**:  一个回调函数，用于在 `dlopen` 加载新的共享库时，重新映射线程堆栈以启用内存标签扩展 (MTE)。
   * **实现**:
     * 调用 `__pthread_internal_remap_stack_with_mte()` 尝试重新映射堆栈并启用 MTE。
     * 如果成功，则会记录一条日志。

**涉及 Dynamic Linker 的功能、SO 布局样本和链接处理过程**

`__libc_preinit` 和 `__libc_init` 是与动态链接器紧密相关的函数。

**SO 布局样本 (`libc.so`)**

```
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              DYN (Shared object file)
  Machine:                           AArch64
  Version:                           0x1
  Entry point address:               0
  Start of program headers:          64 (bytes into file)
  Start of section headers:          ... (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           56 (bytes)
  Number of program headers:         ...
  Size of section headers:           64 (bytes)
  Number of section headers:         ...
  Section header string table index: ...

Program Headers:
  Type           Offset             VirtAddr           PhysAddr           FileSize             MemSize              Flags  Align
  PHDR           0x0000000000000040 0x0000000000000040 0x0000000000000040 0x0000000000000248 0x0000000000000248  R      8
  INTERP         0x0000000000000288 0x0000000000000288 0x0000000000000288 0x000000000000001c 0x000000000000001c  R      1
      [Requesting program interpreter: /system/bin/linker64]
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000 0x00000000001xxxxx 0x00000000001xxxxx  R E    0x1000
  LOAD           0x0000000000yYYYYYY 0x0000000000yYYYYYY 0x0000000000yYYYYYY 0x00000000000zzzzz 0x00000000000uuuuu  RW     0x1000
  DYNAMIC        0x0000000000aaaaaa 0x0000000000aaaaaa 0x0000000000aaaaaa 0x00000000000bbbbb 0x00000000000bbbbb  RW     8
  GNU_RELRO      0x0000000000yYYYYYY 0x0000000000yYYYYYY 0x0000000000yYYYYYY 0x00000000000ccccc 0x00000000000ccccc  R      1
  GNU_EH_FRAME   0x0000000000dddddd 0x0000000000dddddd 0x0000000000dddddd 0x00000000000eeeee 0x00000000000eeeee  R      8
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000 0x0000000000000000 0x0000000000000000  RW     0x10

Section Headers:
  [Nr] Name              Type             Address   Off    Size   ES Align Link Info Align
   ...
  [ 1] .init_array       INIT_ARRAY       ...       ...    ...   0  8     0    0     8
  [ 2] .fini_array       FINI_ARRAY       ...       ...    ...   0  8     0    0     8
  [ 3] .dynamic         DYNAMIC          ...       ...    ... 16  8     6    0     8
   ...
```

* **`.init_array`**:  这个 section 包含了需要在库加载时执行的函数指针列表。`__libc_preinit` 被标记为 `constructor(1)`，确保了它的地址会被放置在这个数组中，从而被动态链接器调用。
* **`.fini_array`**:  包含了需要在库卸载时执行的函数指针列表。
* **`.dynamic`**:  包含了动态链接器需要的各种信息，例如依赖的库、符号表、重定位表等。

**链接的处理过程**

1. **加载**: 当动态链接器加载 `libc.so` 时，它会解析 ELF header 和 program headers。
2. **`.init_array` 执行**: 动态链接器会查找 `.init_array` section，并依次调用其中包含的函数指针。这就是 `__libc_preinit` 被调用的时机。
3. **符号解析**: 动态链接器会根据 `.dynamic` section 中的信息，解析 `libc.so` 中定义的符号，并将其地址填充到其他依赖库的 GOT (Global Offset Table) 或 PLT (Procedure Linkage Table) 中。
4. **TLS 设置**:  动态链接器会根据 `libc.so` 提供的 TLS 模板，为每个线程分配 TLS 存储空间，并初始化 TLS 变量。`__libc_preinit` 中注册的 TLS 生成变量用于同步 `libc` 和动态链接器的 TLS 状态。
5. **重定位**: 动态链接器会根据重定位表调整 `libc.so` 中的代码和数据，使其在内存中的实际地址生效。

**逻辑推理、假设输入与输出**

假设我们有一个非常简单的可执行文件 `my_app`，它链接到 `libc.so`。

**假设输入**:  执行命令 `./my_app`。

**逻辑推理**:

1. 操作系统内核加载 `my_app` 到内存。
2. 内核注意到 `my_app` 依赖于 `libc.so`，并将控制权交给动态链接器 (`/system/bin/linker64`)。
3. 动态链接器加载 `libc.so` 到内存。
4. 动态链接器解析 `libc.so` 的 ELF 文件头，找到 `.init_array`。
5. 动态链接器调用 `.init_array` 中指向 `__libc_preinit` 的函数指针。
6. `__libc_preinit` 执行，初始化 `libc` 的早期状态。
7. 动态链接器继续加载 `my_app` 依赖的其他共享库。
8. 动态链接器解析所有库的符号，并进行重定位。
9. 动态链接器调用 `my_app` 的 `_start` 函数。
10. `_start` 函数调用 `__libc_init`，并将程序参数传递给它。
11. `__libc_init` 执行，完成 `libc` 的初始化，并调用 `my_app` 的 `main` 函数（通过 `slingshot`）。

**假设输出**: 应用程序 `my_app` 的 `main` 函数开始执行。

**用户或编程常见的使用错误**

1. **静态初始化顺序问题**: 如果一个全局对象的构造函数依赖于 `libc` 中尚未完全初始化的部分（在 `__libc_preinit` 或 `__libc_init` 完成之前），可能会导致崩溃或未定义的行为。
   * **例子**:  一个静态全局变量的构造函数调用了 `malloc`，但在 `__libc_init_malloc` 之前执行，可能会失败。
2. **错误的动态链接库路径**: 如果 `LD_LIBRARY_PATH` 设置不正确，动态链接器可能找不到 `libc.so` 或其他依赖库，导致程序无法启动。虽然 `libc.so` 通常是系统默认路径，但在某些特殊情况下仍然可能出现问题。
3. **链接器错误**:  在编译和链接时，如果链接选项不正确，可能导致符号未定义或重复定义，从而影响程序的正常启动。

**Android Framework 或 NDK 如何一步步到达这里**

1. **Android Framework 启动应用**:
   * 当用户点击应用图标或系统需要启动某个应用时，`zygote` 进程 (Android 的孵化器进程) 会 `fork` 出一个新的进程。
   * 新进程调用 `execve` 系统调用来执行应用程序的可执行文件。
   * 内核加载应用程序的可执行文件，并将控制权交给动态链接器。
   * 动态链接器开始加载应用程序依赖的共享库，首先是 `libc.so`。
   * **到达 `__libc_preinit`**:  在加载 `libc.so` 的过程中，动态链接器会调用 `__libc_preinit`。
   * 完成所有库的加载和链接后，动态链接器调用应用程序的入口点 `_start`。
   * **到达 `__libc_init`**: `_start` 函数会调用 `__libc_init`。
   * `__libc_init` 最终调用应用程序的 `main` 函数，应用程序开始执行。

2. **NDK 开发**:
   * 使用 NDK 开发的 native 代码会被编译成共享库 (`.so` 文件)。
   * 当 Android Framework 加载包含 native 代码的应用程序时，动态链接器也会加载这些 `.so` 文件。
   * 这些 NDK 库通常会链接到 Bionic 的 `libc.so`。
   * 当 NDK 库被加载时，其内部的构造函数也会被动态链接器执行，这些构造函数可能依赖于 `libc` 已经完成初始化。

**Frida Hook 示例调试步骤**

你可以使用 Frida hook `__libc_preinit` 和 `__libc_init` 函数来观察它们的执行。

```python
import frida
import sys

package_name = "你的应用包名"

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"应用 {package_name} 未运行，请先启动应用")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "__libc_preinit"), {
    onEnter: function(args) {
        console.log("[*] __libc_preinit called");
    },
    onLeave: function(retval) {
        console.log("[*] __libc_preinit finished");
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "__libc_init"), {
    onEnter: function(args) {
        console.log("[*] __libc_init called");
        console.log("[*] Arguments:");
        console.log("  raw_args:", args[0]);
        console.log("  onexit:", args[1]);
        console.log("  slingshot:", args[2]);
        console.log("  structors:", args[3]);
    },
    onLeave: function(retval) {
        console.log("[*] __libc_init finished");
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida**: 确保你的电脑上安装了 Frida 和 Frida 命令行工具。
2. **连接设备**: 确保你的 Android 设备通过 USB 连接到电脑，并且 Frida 服务正在设备上运行。
3. **替换包名**: 将 `package_name` 替换为你想要调试的 Android 应用的包名。
4. **运行脚本**: 运行这个 Python 脚本。
5. **启动应用**: 在你的 Android 设备上启动目标应用。
6. **查看输出**: Frida 会打印出 `__libc_preinit` 和 `__libc_init` 函数被调用时的日志信息，以及 `__libc_init` 的参数。

这个 Frida 脚本可以帮助你观察 `libc` 初始化过程，并了解这些关键函数何时被调用以及接收到的参数。

希望以上详细的解释能够帮助你理解 `bionic/libc/bionic/libc_init_dynamic.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/libc_init_dynamic.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

/*
 * This source files provides two important functions for dynamic
 * executables:
 *
 * - a C runtime initializer (__libc_preinit), which is called by
 *   the dynamic linker when libc.so is loaded. This happens before
 *   any other initializer (e.g. static C++ constructors in other
 *   shared libraries the program depends on).
 *
 * - a program launch function (__libc_init), which is called after
 *   all dynamic linking has been performed.
 */

#include <elf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "bionic/pthread_internal.h"
#include "libc_init_common.h"

#include "private/bionic_defs.h"
#include "private/bionic_elf_tls.h"
#include "private/bionic_globals.h"
#include "platform/bionic/macros.h"
#include "private/bionic_ssp.h"
#include "private/bionic_tls.h"
#include "private/KernelArgumentBlock.h"

extern "C" {
  extern void netdClientInit(void);
  extern int __cxa_atexit(void (*)(void *), void *, void *);
};

void memtag_stack_dlopen_callback() {
  if (__pthread_internal_remap_stack_with_mte()) {
    async_safe_format_log(ANDROID_LOG_DEBUG, "libc", "remapped stacks as PROT_MTE");
  }
}

// Use an initializer so __libc_sysinfo will have a fallback implementation
// while .preinit_array constructors run.
#if defined(__i386__)
__LIBC_HIDDEN__ void* __libc_sysinfo = reinterpret_cast<void*>(__libc_int0x80);
#endif

extern "C" __attribute__((weak)) void __hwasan_library_loaded(ElfW(Addr) base,
                                                              const ElfW(Phdr)* phdr,
                                                              ElfW(Half) phnum);
extern "C" __attribute__((weak)) void __hwasan_library_unloaded(ElfW(Addr) base,
                                                                const ElfW(Phdr)* phdr,
                                                                ElfW(Half) phnum);

// We need a helper function for __libc_preinit because compiling with LTO may
// inline functions requiring a stack protector check, but __stack_chk_guard is
// not initialized at the start of __libc_preinit. __libc_preinit_impl will run
// after __stack_chk_guard is initialized and therefore can safely have a stack
// protector.
__attribute__((noinline))
static void __libc_preinit_impl() {
#if defined(__i386__)
  __libc_init_sysinfo();
#endif

  // Register libc.so's copy of the TLS generation variable so the linker can
  // update it when it loads or unloads a shared object.
  TlsModules& tls_modules = __libc_shared_globals()->tls_modules;
  tls_modules.generation_libc_so = &__libc_tls_generation_copy;
  __libc_tls_generation_copy = tls_modules.generation;

  __libc_init_globals();
  __libc_init_common();
  __libc_init_scudo();

#if __has_feature(hwaddress_sanitizer)
  // Notify the HWASan runtime library whenever a library is loaded or unloaded
  // so that it can update its shadow memory.
  // This has to happen before _libc_init_malloc which might dlopen to load
  // profiler libraries.
  __libc_shared_globals()->load_hook = __hwasan_library_loaded;
  __libc_shared_globals()->unload_hook = __hwasan_library_unloaded;
#endif

  // Hooks for various libraries to let them know that we're starting up.
  __libc_globals.mutate(__libc_init_malloc);

  // Install reserved signal handlers for assisting the platform's profilers.
  __libc_init_profiling_handlers();

  __libc_init_fork_handler();

  __libc_shared_globals()->set_target_sdk_version_hook = __libc_set_target_sdk_version;

  netdClientInit();
}

// We flag the __libc_preinit function as a constructor to ensure that
// its address is listed in libc.so's .init_array section.
// This ensures that the function is called by the dynamic linker as
// soon as the shared library is loaded.
// We give this constructor priority 1 because we want libc's constructor
// to run before any others (such as the jemalloc constructor), and lower
// is better (http://b/68046352).
__attribute__((constructor(1))) static void __libc_preinit() {
  // The linker has initialized its copy of the global stack_chk_guard, and filled in the main
  // thread's TLS slot with that value. Initialize the local global stack guard with its value.
  __stack_chk_guard = reinterpret_cast<uintptr_t>(__get_tls()[TLS_SLOT_STACK_GUARD]);

  __libc_preinit_impl();
}

// This function is called from the executable's _start entry point
// (see arch-$ARCH/bionic/crtbegin.c), which is itself called by the dynamic
// linker after it has loaded all shared libraries the executable depends on.
//
// Note that the dynamic linker has also run all constructors in the
// executable at this point.
__noreturn void __libc_init(void* raw_args,
                            void (*onexit)(void) __unused,
                            int (*slingshot)(int, char**, char**),
                            structors_array_t const * const structors) {
  BIONIC_STOP_UNWIND;

  KernelArgumentBlock args(raw_args);

  // Several Linux ABIs don't pass the onexit pointer, and the ones that
  // do never use it.  Therefore, we ignore it.

  // The executable may have its own destructors listed in its .fini_array
  // so we need to ensure that these are called when the program exits
  // normally.
  if (structors->fini_array) {
    __cxa_atexit(__libc_fini,structors->fini_array,nullptr);
  }

  __libc_init_mte_late();

  // This roundabout way is needed so we don't use the static libc linked into the linker, which
  // will not affect the process.
  __libc_shared_globals()->memtag_stack_dlopen_callback = memtag_stack_dlopen_callback;

  exit(slingshot(args.argc - __libc_shared_globals()->initial_linker_arg_count,
                 args.argv + __libc_shared_globals()->initial_linker_arg_count,
                 args.envp));
}

extern "C" libc_shared_globals* __loader_shared_globals();

__LIBC_HIDDEN__ libc_shared_globals* __libc_shared_globals() {
  return __loader_shared_globals();
}

"""

```