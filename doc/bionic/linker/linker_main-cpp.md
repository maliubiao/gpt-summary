Response:
Let's break down the thought process for answering this complex request about `linker_main.cpp`.

**1. Understanding the Core Request:**

The central goal is to analyze the `linker_main.cpp` file from Android's Bionic library. This means explaining its function, its relationship to Android, delving into the implementation of included libc functions, dissecting dynamic linking aspects, considering potential errors, and illustrating its involvement in the Android boot process and debugging.

**2. Initial High-Level Analysis (Skimming the Code):**

The first step is to skim the code to get a general understanding. Keywords like `linker_main`, `#include`, function names like `soinfo_alloc`, `link_image`, `relocate_linker`, and the various `LD_...` environment variable checks immediately highlight this file's role in dynamic linking. The presence of `linker.h`, `linker_phdr.h`, `linker_relocate.h`, etc., reinforces this.

**3. Identifying Key Functionalities:**

Based on the skimming and the include files, I can start listing the primary functions:

* **Dynamic Linking:** This is the most obvious. The file handles loading, linking, and relocating shared libraries (`.so` files).
* **Executable Loading:** It loads the main executable.
* **Initialization:** It performs various initializations, including for system properties, platform properties, and TLS.
* **Security:**  It handles security aspects like sanitizing the environment and checking for PIE executables.
* **Debugging Support:** It integrates with debuggers like GDB and supports `ldd`.
* **Error Handling:** It has error reporting mechanisms.

**4. Connecting to Android Functionality:**

Now, consider how these functionalities relate to Android:

* **App Startup:**  The linker is crucial for starting any Android application. It loads the necessary libraries.
* **Framework Operation:**  Android's framework relies heavily on shared libraries.
* **NDK Usage:**  NDK developers create shared libraries that are loaded by the linker.
* **System Libraries:**  Core Android components (like `libc`, `libm`, `libandroid_runtime`) are dynamically linked.

**5. Deep Dive into Specific Aspects:**

This is where the detailed analysis begins:

* **`libc` Functions:** Identify `libc` functions used (`stdlib.h`, `sys/auxv.h`, `sys/prctl.h`, etc.). Explain their standard functionality and how they are used *within the context of the linker*. For instance, `getauxval` retrieves information from the kernel, which is critical for the linker to understand the process's environment. *Initially, I might be tempted to explain the generic purpose of these functions. The key here is to tie their usage back to the linker's specific needs.*

* **Dynamic Linker Functionality:**  This requires explaining the core concepts:
    * **`soinfo`:**  The data structure representing a loaded library.
    * **`solist`:** The linked list of loaded libraries.
    * **Relocation:**  The process of adjusting addresses in shared libraries.
    * **Symbol Resolution:** Finding the addresses of functions and variables.
    * **`DT_NEEDED`:**  Dependencies specified in the ELF header.
    * **`LD_LIBRARY_PATH`, `LD_PRELOAD`:** Environment variables that influence linking.
    * **Namespaces:**  Isolating libraries for different applications.

* **SO Layout Sample:**  Create a simple example illustrating the structure of a `.so` file, highlighting sections relevant to dynamic linking (e.g., `.text`, `.data`, `.dynamic`, `.plt`, `.got`).

* **Linking Process:** Detail the steps involved when the linker loads a shared library. This involves `find_libraries`, `prelink_image`, `link_image`, and relocation.

* **Logic Inference (Hypothetical Input/Output):**  Consider a scenario where a simple app depends on `libm.so`. Show how the linker would identify and load this dependency.

* **Common Usage Errors:** Think about typical mistakes developers make that involve the dynamic linker: missing dependencies, incorrect paths, ABI mismatches, conflicts due to `LD_PRELOAD`.

* **Android Framework/NDK Path:** Trace how a call from the Android framework or an NDK application reaches the linker. Start with `System.loadLibrary` or a native function call, then explain the JNI bridge, and finally how the OS loader invokes the linker.

* **Frida Hook Example:**  Provide a practical example of using Frida to intercept calls within `linker_main.cpp`. Focus on a function like `soinfo_alloc` or `link_image` to demonstrate how to inspect the linker's behavior. *It's important to provide concrete code here, even a basic example.*

**6. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use bullet points and code blocks to enhance readability. Start with a concise summary of the file's purpose.

**7. Language and Tone:**

Use clear and precise language. Avoid overly technical jargon where possible, or explain it when necessary. The request specified Chinese, so ensure the entire response is in that language.

**8. Iterative Refinement:**

After drafting the initial answer, review it for accuracy, completeness, and clarity. Are the explanations easy to understand? Are there any missing pieces of information?  Does the Frida example work?  This iterative process helps to polish the answer and ensure it addresses all aspects of the original request.

**Self-Correction/Refinement Example During the Process:**

* **Initial Thought:** "I should explain all the `libc` functions in detail."
* **Correction:** "No, the focus is on how these functions are used *by the linker*. I should highlight the specific context."

* **Initial Thought:** "Just mentioning relocation is enough."
* **Refinement:** "I need to break down the relocation process into simpler steps, like GOT/PLT interaction, and potentially provide a simplified explanation of how relocation entries are processed."

By following this structured approach, breaking down the problem into smaller, manageable parts, and constantly refining the explanation, a comprehensive and accurate answer can be constructed.
这个文件 `bionic/linker/linker_main.cpp` 是 Android Bionic 动态链接器的主要入口点。它负责在程序启动时加载、链接和初始化动态链接库，使得程序能够正确运行。

下面是对其功能的详细列举和说明：

**1. 功能概述:**

* **作为动态链接器:** 这是其最核心的功能。当一个动态链接的可执行文件被执行时，内核会加载这个可执行文件，并根据其 ELF 头中的 `PT_INTERP` 段指定的路径（通常指向 linker）来启动动态链接器。`linker_main.cpp` 中的 `__linker_init` 函数就是动态链接器的入口点。
* **加载共享库:**  根据可执行文件的依赖关系（`DT_NEEDED` 条目）以及 `LD_PRELOAD` 环境变量的设置，加载所需的共享库 (`.so` 文件)。
* **符号解析和重定位:**  解析共享库之间的符号引用，并将代码和数据中的符号地址重定位到正确的内存地址。这是动态链接的关键步骤。
* **执行初始化代码:**  调用共享库中的初始化函数（`.init` 段和 C++ 构造函数）。
* **支持 `ldd` 命令:**  当以 `--list` 参数运行时，模拟 `ldd` 命令，列出可执行文件依赖的共享库。
* **处理 `LD_LIBRARY_PATH` 和 `LD_PRELOAD`:**  解析这两个环境变量，影响共享库的搜索路径和预加载行为。
* **处理地址空间布局随机化 (ASLR):**  确定加载地址，确保安全性。
* **集成调试支持:**  与 GDB 等调试器配合工作，方便调试动态链接库。
* **支持内存标签扩展 (MTE):**  在支持 MTE 的硬件上，进行相关的初始化和配置。
* **管理 TLS (线程本地存储):**  设置线程本地存储区域。
* **处理 VDSO (虚拟动态共享对象):** 加载和链接 VDSO，提供高效的系统调用接口。

**2. 与 Android 功能的关系及举例说明:**

`linker_main.cpp` 是 Android 平台运行所有动态链接程序的基础。

* **应用程序启动:** 当你点击一个 Android 应用图标时，Zygote 进程 fork 出一个新的进程来运行该应用。这个新进程执行应用的 APK 包中的可执行文件（通常是 `app_process` 或 `dalvikvm`/`art`）。这些可执行文件都依赖于各种共享库 (例如 `libc.so`, `libm.so`, `libandroid_runtime.so` 等)。`linker_main.cpp` 负责加载这些库，解析它们之间的依赖关系，并进行链接，最终使得应用的代码能够正确执行。
* **Android Framework:** Android Framework 的许多组件都是以共享库的形式存在的，例如 `libbinder.so` (Binder IPC 机制), `libsurfaceflinger.so` (SurfaceFlinger 服务)。`linker_main.cpp` 负责加载这些框架库，使得应用能够与系统服务进行交互。
* **NDK 开发:** 使用 NDK 开发的 native 代码会被编译成共享库 (`.so` 文件)。当 Java 代码通过 JNI 调用 native 代码时，`linker_main.cpp` 会负责加载这些 NDK 库。例如，如果你的 NDK 代码依赖于 `libcurl.so`，链接器会找到并加载它。
* **系统服务:** 许多 Android 系统服务也是动态链接的，例如 `servicemanager`, `surfaceflinger` 等。`linker_main.cpp` 在这些服务启动时也扮演着关键角色。

**3. `libc` 函数的实现解释:**

虽然 `linker_main.cpp` 中包含了对一些 `libc` 头文件的引用（如 `<stdlib.h>`, `<sys/auxv.h>`, `<sys/prctl.h>`），但它本身并不 *实现* 这些 `libc` 函数。它 *使用* 这些函数来完成其链接和加载的任务。这些 `libc` 函数的实现位于 Bionic 的其他源文件中，例如 `bionic/libc/`.

* **`stdlib.h` 中的函数 (例如 `getenv`, `atoi`, `exit`)**:
    * **`getenv(const char* name)`:**  用于获取环境变量的值。链接器使用它来读取 `LD_LIBRARY_PATH` 和 `LD_PRELOAD` 等环境变量，以确定共享库的搜索路径和预加载的库。它的实现通常会访问进程的环境变量表。
    * **`exit(int status)`:**  用于终止进程。链接器在遇到无法解决的链接错误时会调用 `exit`。它的实现通常会执行一些清理操作，然后调用内核的 `exit` 系统调用。
* **`sys/auxv.h` 中的函数 (例如 `getauxval(unsigned long type)`)**:
    * **`getauxval(unsigned long type)`:**  用于获取内核传递给进程的辅助向量 (auxiliary vector) 中的信息。链接器使用它来获取 ELF 头、程序头表、入口点等关键信息，例如 `AT_PHDR` (程序头表地址), `AT_PHNUM` (程序头表项数), `AT_ENTRY` (入口点地址)。它的实现通常通过系统调用来获取内核提供的数据。
* **`sys/prctl.h` 中的函数 (例如 `prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)`)**:
    * **`prctl` (process control):**  用于对进程进行各种控制。在 `linker_main.cpp` 中，`prctl(PR_SET_VMA, ...)` 被用来设置进程内存区域 (VMA) 的名称，例如给 `.bss` 段命名，方便调试和分析。它的实现会通过系统调用与内核交互。

**4. 涉及 dynamic linker 的功能、so 布局样本和链接处理过程:**

**SO 布局样本:**

一个典型的共享库 (`.so`) 文件布局如下（简化）：

```
ELF Header:
  Magic:   7f 45 4c 46 ... (识别为 ELF 文件)
  Class:                             ELF64 或 ELF32
  Data:                              Little-endian 或 Big-endian
  ...
Program Headers:  (描述内存段如何加载)
  Type           Offset             VirtAddr           PhysAddr           FileSize             MemSize              Flags              Align
  LOAD           0x0000000000000000 0x0000000000000000 0x0000000000000000 0x0000000000001000 0x0000000000001000 R E
  LOAD           0x0000000000001000 0x0000000000001000 0x0000000000001000 0x0000000000000500 0x0000000000000800 RW
  DYNAMIC        0x0000000000001500 0x0000000000001500 0x0000000000001500 0x0000000000000100 0x0000000000000100 R
  ...
Section Headers:  (描述文件中的各个节)
  Name              Type             Address             Offset             Size               EntSize              Flags              Link              Info              Align
  .text             PROGBITS         0x0000000000000000 0x0000000000000000 0x0000000000000800 0x0000000000000000  AX               0                 0                 16
  .rodata           PROGBITS         0x0000000000000800 0x0000000000000800 0x0000000000000200 0x0000000000000000   A               0                 0                 8
  .data             PROGBITS         0x0000000000001000 0x0000000000001000 0x0000000000000300 0x0000000000000000  WA               0                 0                 8
  .bss              NOBITS           0x0000000000001300 0x0000000000001300 0x0000000000000100 0x0000000000000000  WA               0                 0                 4
  .dynamic          DYNAMIC          0x0000000000001500 0x0000000000001500 0x0000000000000100 0x0000000000000010  WA               2                 0                 8
  .symtab           SYMTAB           ...
  .strtab           STRTAB           ...
  .rel.dyn          REL              ...
  .rela.plt         RELA             ...
  .plt              PROGBITS         ...
  .got              PROGBITS         ...
  ...
```

关键部分：

* **ELF Header:** 包含识别信息、入口点等。
* **Program Headers:**  描述如何将文件的各个段加载到内存中。`LOAD` 段指定了要加载的内存区域，以及它们的权限 (`R`, `W`, `E`)。`DYNAMIC` 段指向动态链接信息。
* **Section Headers:**  描述文件中的各个节，如 `.text` (代码), `.rodata` (只读数据), `.data` (已初始化数据), `.bss` (未初始化数据), `.dynamic` (动态链接信息), `.symtab` (符号表), `.strtab` (字符串表), `.rel.dyn` (动态重定位信息), `.rela.plt` (PLT 重定位信息)。
* **`.dynamic` 段:**  包含一系列的 tag-value 对，提供了动态链接器所需的信息，例如：
    * `DT_NEEDED`:  依赖的其他共享库的名字。
    * `DT_SONAME`:  共享库的规范名称。
    * `DT_HASH`:  符号哈希表的地址。
    * `DT_SYMTAB`:  符号表的地址。
    * `DT_STRTAB`:  字符串表的地址。
    * `DT_REL`, `DT_RELA`, `DT_RELPLT`, `DT_RELAPLT`:  重定位表的地址和大小。
    * `DT_PLTGOT`:  PLT 和 GOT 的地址。
    * `DT_INIT`:  初始化函数的地址。
    * `DT_FINI`:  终止函数的地址。
    * `DT_FLAGS`, `DT_FLAGS_1`:  各种标志。

**链接处理过程:**

当加载一个依赖于共享库的可执行文件时，链接器会执行以下步骤：

1. **加载可执行文件:** 内核加载可执行文件到内存。
2. **启动链接器:**  内核根据可执行文件的 `PT_INTERP` 段启动链接器 (`linker_main.cpp`)。
3. **解析可执行文件:** 链接器解析可执行文件的 ELF 头和程序头，获取基本信息。
4. **处理 `LD_PRELOAD`:**  链接器检查 `LD_PRELOAD` 环境变量，并加载指定的共享库。
5. **加载依赖库:**  链接器读取可执行文件的 `.dynamic` 段中的 `DT_NEEDED` 条目，确定需要加载的共享库。它会根据配置的搜索路径（包括 `LD_LIBRARY_PATH` 和系统默认路径）查找这些库。
6. **递归加载依赖:**  对于每个加载的共享库，链接器会递归地检查其 `DT_NEEDED` 条目，加载其依赖的库。
7. **符号解析:**  链接器遍历所有加载的共享库的符号表 (`.symtab`)，并解决符号引用。这涉及到查找被引用的符号的定义。
8. **重定位:**  这是链接的关键步骤。链接器会处理各种重定位条目 (`.rel.dyn`, `.rela.plt`)，将代码和数据段中对外部符号的引用更新为正确的内存地址。主要有以下类型的重定位：
    * **绝对重定位:** 直接将符号的绝对地址写入引用位置。
    * **相对重定位:** 将符号的地址相对于当前位置的偏移量写入引用位置。
    * **PLT/GOT 重定位:**  用于延迟绑定 (lazy binding)，最初在 GOT 中写入一个指向 PLT 条目的地址，当函数第一次被调用时，PLT 代码会调用链接器来解析符号并更新 GOT 表项。
9. **执行初始化函数:**  链接器调用每个加载的共享库的初始化函数 (`DT_INIT`) 和 C++ 构造函数。
10. **移交控制:**  链接完成后，链接器将控制权移交给可执行文件的入口点。

**5. 逻辑推理和假设输入/输出:**

**假设输入:**

* 一个简单的可执行文件 `my_app`，其 `.dynamic` 段中包含 `DT_NEEDED libmylib.so`。
* `libmylib.so` 存在于默认的库搜索路径中。

**链接处理过程的逻辑推理:**

1. 链接器首先加载 `my_app`。
2. 链接器解析 `my_app` 的 `.dynamic` 段，找到 `DT_NEEDED libmylib.so`。
3. 链接器在默认库路径中找到 `libmylib.so` 并加载。
4. 链接器解析 `libmylib.so` 的符号表。
5. 链接器处理 `my_app` 和 `libmylib.so` 中的重定位条目，将它们之间互相引用的符号地址修正。
6. 链接器执行 `libmylib.so` 的初始化函数。
7. 链接器执行 `my_app` 的初始化函数。
8. 链接器将控制权交给 `my_app` 的入口点。

**假设输出 (简化):**

* `libmylib.so` 被成功加载到内存中的某个地址（例如 `0x7efd400000`）。
* `my_app` 中调用 `libmylib.so` 中函数的指令被重定位为指向 `libmylib.so` 中函数的实际地址。
* 如果设置了 `LD_DEBUG=libs` 环境变量，可能会看到类似以下的日志输出：
  ```
  [...linker...] Loading library libmylib.so [0x7efd400000]
  ```

**6. 用户或编程常见的使用错误:**

* **缺少依赖库:**  可执行文件或共享库依赖的库不存在于链接器的搜索路径中。这会导致链接错误，程序无法启动，并可能报类似 "cannot find library" 的错误。
    * **例子:** 你的应用依赖 `libspecial.so`，但该库没有安装或不在 `LD_LIBRARY_PATH` 中。
* **ABI 不兼容:**  可执行文件和依赖库的架构 (例如 32 位 vs 64 位) 或 ABI (Application Binary Interface) 不匹配。这会导致加载或链接错误。
    * **例子:**  一个 32 位的应用尝试加载一个 64 位的共享库。
* **`LD_LIBRARY_PATH` 设置不当:**  错误地设置或使用 `LD_LIBRARY_PATH` 可能导致链接器找到错误的库版本，或者找不到需要的库。
    * **例子:**  `LD_LIBRARY_PATH` 指向一个包含旧版本 `libc.so` 的目录，可能导致系统崩溃。
* **`LD_PRELOAD` 的滥用:**  不恰当的使用 `LD_PRELOAD` 可能会覆盖系统库的函数，导致意想不到的行为或安全问题。
    * **例子:**  使用 `LD_PRELOAD` 替换 `malloc` 函数，但新的 `malloc` 实现存在缺陷。
* **循环依赖:**  共享库之间存在循环依赖关系，可能导致链接器陷入死循环或无法正常加载。
    * **例子:**  `libA.so` 依赖 `libB.so`，而 `libB.so` 又依赖 `libA.so`。
* **符号冲突:**  多个共享库中定义了相同的符号，可能导致链接器选择错误的符号定义。
    * **例子:**  两个不同的库都定义了一个名为 `getVersion` 的函数。

**7. Android Framework 或 NDK 如何到达这里，以及 Frida Hook 示例:**

**Android Framework 到 `linker_main.cpp` 的路径:**

1. **应用程序启动请求:** 用户启动一个应用，或者系统启动一个服务。
2. **Zygote 进程 fork:**  对于应用启动，Zygote 进程会 fork 出一个新的进程。
3. **`app_process`/`dalvikvm`/`art` 执行:** 新进程执行应用的入口点，通常是 `app_process` (较高 Android 版本) 或 `dalvikvm`/`art` (较低 Android 版本)。
4. **加载共享库:** 这些可执行文件本身就是动态链接的，它们的 ELF 头中指定了 linker 的路径。内核会加载 linker。
5. **`__linker_init` 调用:** linker 的入口点 `__linker_init` 被调用。
6. **链接和初始化:** `linker_main.cpp` 中的代码负责加载和链接应用依赖的各种 framework 库（例如 `libandroid_runtime.so`, `libbinder.so` 等）。

**NDK 到 `linker_main.cpp` 的路径:**

1. **Java 代码加载 native 库:** Java 代码使用 `System.loadLibrary("mylib")` 或 `System.load("path/to/mylib.so")` 加载 NDK 开发的共享库。
2. **JNI 调用:** 当 Java 代码调用一个声明为 `native` 的方法时，会触发 JNI (Java Native Interface) 机制。
3. **查找 native 函数:**  虚拟机 (Dalvik/ART) 需要找到 native 方法在共享库中的实现。
4. **加载 NDK 库 (如果尚未加载):** 如果 NDK 库尚未加载，虚拟机内部会调用加载器机制，最终会调用 `dlopen` 或类似的函数。
5. **`dlopen` -> linker:** `dlopen` 函数会调用动态链接器 (`linker_main.cpp`) 来加载指定的共享库。
6. **链接和重定位:**  链接器会加载 NDK 库，并将其链接到当前进程的地址空间。

**Frida Hook 示例:**

以下是一个使用 Frida hook `soinfo_alloc` 函数的示例，该函数在加载共享库时被调用：

```javascript
// Frida 脚本
console.log("Script loaded");

if (Process.arch === 'arm64') {
    var soinfo_alloc = Module.findExportByName(null, "_ZN6soinfoC1EP17android_namespace_tPKcPK8stat64_tji"); // Android 64-bit
} else {
    var soinfo_alloc = Module.findExportByName(null, "_ZN6soinfoC1EP17android_namespace_tPKcP6statji"); // Android 32-bit
}

if (soinfo_alloc) {
    Interceptor.attach(soinfo_alloc, {
        onEnter: function (args) {
            console.log("soinfo_alloc called");
            console.log("  namespace:", args[0]);
            console.log("  name:", Memory.readUtf8String(args[1]));
            // 可以进一步检查其他参数
        },
        onLeave: function (retval) {
            console.log("soinfo_alloc returned:", retval);
            // 可以检查返回的 soinfo 对象
        }
    });
} else {
    console.error("soinfo_alloc function not found!");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `hook.js`。
2. 找到你要 hook 的 Android 进程的进程 ID (PID)。
3. 使用 Frida 连接到目标进程：
   ```bash
   frida -U -f <package_name> -l hook.js  # 如果要启动应用并 hook
   frida -U <PID> -l hook.js             # 如果要 hook 正在运行的进程
   ```
   将 `<package_name>` 替换为应用的包名，`<PID>` 替换为进程 ID。

**预期输出:**

当目标进程加载新的共享库时，你会在 Frida 控制台中看到类似以下的输出：

```
Script loaded
soinfo_alloc called
  namespace: [object Object]
  name: /system/lib64/libc.so
soinfo_alloc returned: [object Object]
soinfo_alloc called
  namespace: [object Object]
  name: /system/lib64/libm.so
soinfo_alloc returned: [object Object]
...
```

这个例子展示了如何使用 Frida 拦截 `linker_main.cpp` 中的关键函数调用，帮助你理解动态链接器的行为和调试相关问题。 你可以根据需要 hook 其他函数，例如 `link_image`, `find_library`, `relocate_linker` 等，以更深入地了解链接过程的细节。

### 提示词
```
这是目录为bionic/linker/linker_main.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "linker_main.h"

#include <link.h>
#include <stdlib.h>
#include <sys/auxv.h>
#include <sys/prctl.h>

#include "linker.h"
#include "linker_auxv.h"
#include "linker_cfi.h"
#include "linker_debug.h"
#include "linker_debuggerd.h"
#include "linker_gdb_support.h"
#include "linker_globals.h"
#include "linker_phdr.h"
#include "linker_relocate.h"
#include "linker_relocs.h"
#include "linker_tls.h"
#include "linker_utils.h"

#include "platform/bionic/macros.h"
#include "private/KernelArgumentBlock.h"
#include "private/bionic_call_ifunc_resolver.h"
#include "private/bionic_globals.h"
#include "private/bionic_tls.h"

#include "android-base/unique_fd.h"
#include "android-base/strings.h"
#include "android-base/stringprintf.h"

#include <async_safe/log.h>
#include <bionic/libc_init_common.h>
#include <bionic/pthread_internal.h>

#include <vector>

__LIBC_HIDDEN__ extern "C" void _start();

static ElfW(Addr) get_elf_exec_load_bias(const ElfW(Ehdr)* elf);

static void get_elf_base_from_phdr(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                   ElfW(Addr)* base, ElfW(Addr)* load_bias);

static void set_bss_vma_name(soinfo* si);

void __libc_init_mte(const memtag_dynamic_entries_t* memtag_dynamic_entries, const void* phdr_start,
                     size_t phdr_count, uintptr_t load_bias);

void __libc_init_mte_stack(void* stack_top);

static void __linker_cannot_link(const char* argv0) {
  __linker_error("CANNOT LINK EXECUTABLE \"%s\": %s", argv0, linker_get_error_buffer());
}

// These should be preserved static to avoid emitting
// RELATIVE relocations for the part of the code running
// before linker links itself.

// TODO (dimtiry): remove somain, rename solist to solist_head
static soinfo* solist;
static soinfo* sonext;
static soinfo* somain; // main process, always the one after libdl_info
static soinfo* solinker;
static soinfo* vdso; // vdso if present

void solist_add_soinfo(soinfo* si) {
  sonext->next = si;
  sonext = si;
}

bool solist_remove_soinfo(soinfo* si) {
  soinfo *prev = nullptr, *trav;
  for (trav = solist; trav != nullptr; trav = trav->next) {
    if (trav == si) {
      break;
    }
    prev = trav;
  }

  if (trav == nullptr) {
    // si was not in solist
    DL_WARN("name \"%s\"@%p is not in solist!", si->get_realpath(), si);
    return false;
  }

  // prev will never be null, because the first entry in solist is
  // always the static libdl_info.
  CHECK(prev != nullptr);
  prev->next = si->next;
  if (si == sonext) {
    sonext = prev;
  }

  return true;
}

soinfo* solist_get_head() {
  return solist;
}

soinfo* solist_get_somain() {
  return somain;
}

soinfo* solist_get_vdso() {
  return vdso;
}

bool g_is_ldd;

static std::vector<std::string> g_ld_preload_names;

static std::vector<soinfo*> g_ld_preloads;

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

static void parse_LD_PRELOAD(const char* path) {
  g_ld_preload_names.clear();
  if (path != nullptr) {
    // We have historically supported ':' as well as ' ' in LD_PRELOAD.
    g_ld_preload_names = android::base::Split(path, " :");
    g_ld_preload_names.erase(std::remove_if(g_ld_preload_names.begin(), g_ld_preload_names.end(),
                                            [](const std::string& s) { return s.empty(); }),
                             g_ld_preload_names.end());
  }
}

// An empty list of soinfos
static soinfo_list_t g_empty_list;

static void add_vdso() {
  ElfW(Ehdr)* ehdr_vdso = reinterpret_cast<ElfW(Ehdr)*>(getauxval(AT_SYSINFO_EHDR));
  if (ehdr_vdso == nullptr) {
    return;
  }

  vdso = soinfo_alloc(&g_default_namespace, "[vdso]", nullptr, 0, 0);

  vdso->phdr = reinterpret_cast<ElfW(Phdr)*>(reinterpret_cast<char*>(ehdr_vdso) + ehdr_vdso->e_phoff);
  vdso->phnum = ehdr_vdso->e_phnum;
  vdso->base = reinterpret_cast<ElfW(Addr)>(ehdr_vdso);
  vdso->size = phdr_table_get_load_size(vdso->phdr, vdso->phnum);
  vdso->load_bias = get_elf_exec_load_bias(ehdr_vdso);

  if (!vdso->prelink_image() || !vdso->link_image(SymbolLookupList(vdso), vdso, nullptr, nullptr)) {
    __linker_cannot_link(g_argv[0]);
  }

  // Prevent accidental unloads...
  vdso->set_dt_flags_1(vdso->get_dt_flags_1() | DF_1_NODELETE);
  vdso->set_linked();
}

// Initializes an soinfo's link_map_head field using other fields from the
// soinfo (phdr, phnum, load_bias). The soinfo's realpath must not change after
// this function is called.
static void init_link_map_head(soinfo& info) {
  auto& map = info.link_map_head;
  map.l_addr = info.load_bias;
  map.l_name = const_cast<char*>(info.get_realpath());
  phdr_table_get_dynamic_section(info.phdr, info.phnum, info.load_bias, &map.l_ld, nullptr);
}

extern "C" int __system_properties_init(void);

struct ExecutableInfo {
  std::string path;
  struct stat file_stat;
  const ElfW(Phdr)* phdr;
  size_t phdr_count;
  ElfW(Addr) entry_point;
  bool should_pad_segments;
};

static ExecutableInfo get_executable_info(const char* arg_path) {
  ExecutableInfo result = {};
  char const* exe_path = "/proc/self/exe";

  // Stat "/proc/self/exe" instead of executable_path because
  // the executable could be unlinked by this point and it should
  // not cause a crash (see http://b/31084669)
  if (TEMP_FAILURE_RETRY(stat(exe_path, &result.file_stat) == -1)) {
    // Fallback to argv[0] for the case where /proc isn't available
    if (TEMP_FAILURE_RETRY(stat(arg_path, &result.file_stat) == -1)) {
      async_safe_fatal("unable to stat either \"/proc/self/exe\" or \"%s\": %m", arg_path);
    }
    exe_path = arg_path;
  }

  // Path might be a symlink; we need the target so that we get the right
  // linker configuration later.
  char sym_path[PATH_MAX];
  result.path = std::string(realpath(exe_path, sym_path) != nullptr ? sym_path : exe_path);

  result.phdr = reinterpret_cast<const ElfW(Phdr)*>(getauxval(AT_PHDR));
  result.phdr_count = getauxval(AT_PHNUM);
  result.entry_point = getauxval(AT_ENTRY);
  return result;
}

// Load an executable. Normally the kernel has already loaded the executable when the linker
// starts. The linker can be invoked directly on an executable, though, and then the linker must
// load it. This function doesn't load dependencies or resolve relocations.
static ExecutableInfo load_executable(const char* orig_path) {
  ExecutableInfo result = {};

  if (orig_path[0] != '/') {
    __linker_error("error: expected absolute path: \"%s\"", orig_path);
  }

  off64_t file_offset;
  android::base::unique_fd fd(open_executable(orig_path, &file_offset, &result.path));
  if (fd.get() == -1) {
    __linker_error("error: unable to open file \"%s\"", orig_path);
  }

  if (TEMP_FAILURE_RETRY(fstat(fd.get(), &result.file_stat)) == -1) {
    __linker_error("error: unable to stat \"%s\": %m", result.path.c_str());
  }

  ElfReader elf_reader;
  if (!elf_reader.Read(result.path.c_str(), fd.get(), file_offset, result.file_stat.st_size)) {
    __linker_error("error: %s", linker_get_error_buffer());
  }
  address_space_params address_space;
  if (!elf_reader.Load(&address_space)) {
    __linker_error("error: %s", linker_get_error_buffer());
  }

  result.phdr = elf_reader.loaded_phdr();
  result.phdr_count = elf_reader.phdr_count();
  result.entry_point = elf_reader.entry_point();
  result.should_pad_segments = elf_reader.should_pad_segments();
  return result;
}

static void platform_properties_init() {
#if defined(__aarch64__)
  const unsigned long hwcap2 = getauxval(AT_HWCAP2);
  g_platform_properties.bti_supported = (hwcap2 & HWCAP2_BTI) != 0;
#endif
}

static ElfW(Addr) linker_main(KernelArgumentBlock& args, const char* exe_to_load) {
  ProtectedDataGuard guard;

  timeval t0, t1;
  gettimeofday(&t0, nullptr);

  // Sanitize the environment.
  __libc_init_AT_SECURE(args.envp);

  // Initialize system properties
  __system_properties_init(); // may use 'environ'

  // Initialize platform properties.
  platform_properties_init();

  // Register the debuggerd signal handler.
  linker_debuggerd_init();

  g_linker_logger.ResetState();

  // Enable debugging logs?
  const char* LD_DEBUG = getenv("LD_DEBUG");
  if (LD_DEBUG != nullptr) init_LD_DEBUG(LD_DEBUG);

  if (getenv("LD_SHOW_AUXV") != nullptr) ld_show_auxv(args.auxv);

  LD_DEBUG(any, "[ Android dynamic linker (" ABI_STRING ") ]");

  // These should have been sanitized by __libc_init_AT_SECURE, but the test
  // doesn't cost us anything.
  const char* ldpath_env = nullptr;
  const char* ldpreload_env = nullptr;
  if (!getauxval(AT_SECURE)) {
    ldpath_env = getenv("LD_LIBRARY_PATH");
    if (ldpath_env != nullptr) {
      LD_DEBUG(any, "[ LD_LIBRARY_PATH set to \"%s\" ]", ldpath_env);
    }
    ldpreload_env = getenv("LD_PRELOAD");
    if (ldpreload_env != nullptr) {
      LD_DEBUG(any, "[ LD_PRELOAD set to \"%s\" ]", ldpreload_env);
    }
  }

  const ExecutableInfo exe_info = exe_to_load ? load_executable(exe_to_load) :
                                                get_executable_info(args.argv[0]);

  LD_DEBUG(any, "[ Linking executable \"%s\" ]", exe_info.path.c_str());

  // Initialize the main exe's soinfo.
  soinfo* si = soinfo_alloc(&g_default_namespace,
                            exe_info.path.c_str(), &exe_info.file_stat,
                            0, RTLD_GLOBAL);
  somain = si;
  si->phdr = exe_info.phdr;
  si->phnum = exe_info.phdr_count;
  si->set_should_pad_segments(exe_info.should_pad_segments);
  get_elf_base_from_phdr(si->phdr, si->phnum, &si->base, &si->load_bias);
  si->size = phdr_table_get_load_size(si->phdr, si->phnum);
  si->dynamic = nullptr;
  si->set_main_executable();
  init_link_map_head(*si);

  set_bss_vma_name(si);

  // Use the executable's PT_INTERP string as the solinker filename in the
  // dynamic linker's module list. gdb reads both PT_INTERP and the module list,
  // and if the paths for the linker are different, gdb will report that the
  // PT_INTERP linker path was unloaded once the module list is initialized.
  // There are three situations to handle:
  //  - the APEX linker (/system/bin/linker[64] -> /apex/.../linker[64])
  //  - the ASAN linker (/system/bin/linker_asan[64] -> /apex/.../linker[64])
  //  - the bootstrap linker (/system/bin/bootstrap/linker[64])
  const char *interp = phdr_table_get_interpreter_name(somain->phdr, somain->phnum,
                                                       somain->load_bias);
  if (interp == nullptr) {
    // This case can happen if the linker attempts to execute itself
    // (e.g. "linker64 /system/bin/linker64").
#if defined(__LP64__)
#define DEFAULT_INTERP "/system/bin/linker64"
#else
#define DEFAULT_INTERP "/system/bin/linker"
#endif
    interp = DEFAULT_INTERP;
  }
  solinker->set_realpath(interp);
  init_link_map_head(*solinker);

#if defined(__aarch64__)
  __libc_init_mte(somain->memtag_dynamic_entries(), somain->phdr, somain->phnum, somain->load_bias);

  if (exe_to_load == nullptr) {
    // Kernel does not add PROT_BTI to executable pages of the loaded ELF.
    // Apply appropriate protections here if it is needed.
    auto note_gnu_property = GnuPropertySection(somain);
    if (note_gnu_property.IsBTICompatible() &&
        (phdr_table_protect_segments(
             somain->phdr, somain->phnum, somain->load_bias, somain->should_pad_segments(),
             somain->should_use_16kib_app_compat(), &note_gnu_property) < 0)) {
      __linker_error("error: can't protect segments for \"%s\": %m", exe_info.path.c_str());
    }
  }
#endif

  // Register the main executable and the linker upfront to have
  // gdb aware of them before loading the rest of the dependency
  // tree.
  //
  // gdb expects the linker to be in the debug shared object list.
  // Without this, gdb has trouble locating the linker's ".text"
  // and ".plt" sections. Gdb could also potentially use this to
  // relocate the offset of our exported 'rtld_db_dlactivity' symbol.
  //
  insert_link_map_into_debug_map(&si->link_map_head);
  insert_link_map_into_debug_map(&solinker->link_map_head);

  add_vdso();

  ElfW(Ehdr)* elf_hdr = reinterpret_cast<ElfW(Ehdr)*>(si->base);

  // For security reasons we dropped non-PIE support in API level 21,
  // and the NDK no longer supports earlier API levels.
  if (elf_hdr->e_type != ET_DYN) {
    __linker_error("error: %s: Android only supports position-independent "
                   "executables (-fPIE)", exe_info.path.c_str());
  }

  // Use LD_LIBRARY_PATH and LD_PRELOAD (but only if we aren't setuid/setgid).
  parse_LD_LIBRARY_PATH(ldpath_env);
  parse_LD_PRELOAD(ldpreload_env);

  std::vector<android_namespace_t*> namespaces = init_default_namespaces(exe_info.path.c_str());

  if (!si->prelink_image()) __linker_cannot_link(g_argv[0]);

  // add somain to global group
  si->set_dt_flags_1(si->get_dt_flags_1() | DF_1_GLOBAL);
  // ... and add it to all other linked namespaces
  for (auto linked_ns : namespaces) {
    if (linked_ns != &g_default_namespace) {
      linked_ns->add_soinfo(somain);
      somain->add_secondary_namespace(linked_ns);
    }
  }

  linker_setup_exe_static_tls(g_argv[0]);

  // Load ld_preloads and dependencies.
  std::vector<const char*> needed_library_name_list;
  size_t ld_preloads_count = 0;

  for (const auto& ld_preload_name : g_ld_preload_names) {
    needed_library_name_list.push_back(ld_preload_name.c_str());
    ++ld_preloads_count;
  }

  for_each_dt_needed(si, [&](const char* name) {
    needed_library_name_list.push_back(name);
  });

  const char** needed_library_names = &needed_library_name_list[0];
  size_t needed_libraries_count = needed_library_name_list.size();

  if (needed_libraries_count > 0 &&
      !find_libraries(&g_default_namespace,
                      si,
                      needed_library_names,
                      needed_libraries_count,
                      nullptr,
                      &g_ld_preloads,
                      ld_preloads_count,
                      RTLD_GLOBAL,
                      nullptr,
                      true /* add_as_children */,
                      &namespaces)) {
    __linker_cannot_link(g_argv[0]);
  } else if (needed_libraries_count == 0) {
    if (!si->link_image(SymbolLookupList(si), si, nullptr, nullptr)) {
      __linker_cannot_link(g_argv[0]);
    }
    si->increment_ref_count();
  }

  // Exit early for ldd. We don't want to run the code that was loaded, so skip
  // the constructor calls. Skip CFI setup because it would call __cfi_init in
  // libdl.so.
  if (g_is_ldd) _exit(EXIT_SUCCESS);

#if defined(__aarch64__)
  // This has to happen after the find_libraries, which will have collected any possible
  // libraries that request memtag_stack in the dynamic section.
  __libc_init_mte_stack(args.argv);
#endif

  linker_finalize_static_tls();
  __libc_init_main_thread_final();

  if (!get_cfi_shadow()->InitialLinkDone(solist)) __linker_cannot_link(g_argv[0]);

  si->call_pre_init_constructors();
  si->call_constructors();

  if (g_linker_debug_config.timing) {
    gettimeofday(&t1, nullptr);
    long long t0_us = (t0.tv_sec * 1000000LL) + t0.tv_usec;
    long long t1_us = (t1.tv_sec * 1000000LL) + t1.tv_usec;
    LD_DEBUG(timing, "LINKER TIME: %s: %lld microseconds", g_argv[0], t1_us - t0_us);
  }
  if (g_linker_debug_config.statistics) {
    print_linker_stats();
  }

  // We are about to hand control over to the executable loaded.  We don't want
  // to leave dirty pages behind unnecessarily.
  purge_unused_memory();

  ElfW(Addr) entry = exe_info.entry_point;
  LD_DEBUG(any, "[ Ready to execute \"%s\" @ %p ]", si->get_realpath(), reinterpret_cast<void*>(entry));
  return entry;
}

/* Compute the load-bias of an existing executable. This shall only
 * be used to compute the load bias of an executable or shared library
 * that was loaded by the kernel itself.
 *
 * Input:
 *    elf    -> address of ELF header, assumed to be at the start of the file.
 * Return:
 *    load bias, i.e. add the value of any p_vaddr in the file to get
 *    the corresponding address in memory.
 */
static ElfW(Addr) get_elf_exec_load_bias(const ElfW(Ehdr)* elf) {
  ElfW(Addr) offset = elf->e_phoff;
  const ElfW(Phdr)* phdr_table =
      reinterpret_cast<const ElfW(Phdr)*>(reinterpret_cast<uintptr_t>(elf) + offset);
  const ElfW(Phdr)* phdr_end = phdr_table + elf->e_phnum;

  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++) {
    if (phdr->p_type == PT_LOAD) {
      return reinterpret_cast<ElfW(Addr)>(elf) + phdr->p_offset - phdr->p_vaddr;
    }
  }
  return 0;
}

/* Find the load bias and base address of an executable or shared object loaded
 * by the kernel. The ELF file's PHDR table must have a PT_PHDR entry.
 *
 * A VDSO doesn't have a PT_PHDR entry in its PHDR table.
 */
static void get_elf_base_from_phdr(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                   ElfW(Addr)* base, ElfW(Addr)* load_bias) {
  for (size_t i = 0; i < phdr_count; ++i) {
    if (phdr_table[i].p_type == PT_PHDR) {
      *load_bias = reinterpret_cast<ElfW(Addr)>(phdr_table) - phdr_table[i].p_vaddr;
      *base = reinterpret_cast<ElfW(Addr)>(phdr_table) - phdr_table[i].p_offset;
      return;
    }
  }
  async_safe_fatal("Could not find a PHDR: broken executable?");
}

/*
 * Set anonymous VMA name for .bss section.  For DSOs loaded by the linker, this
 * is done by ElfReader.  This function is here for DSOs loaded by the kernel,
 * namely the linker itself and the main executable.
 */
static void set_bss_vma_name(soinfo* si) {
  for (size_t i = 0; i < si->phnum; ++i) {
    auto phdr = &si->phdr[i];

    if (phdr->p_type != PT_LOAD) {
      continue;
    }

    ElfW(Addr) seg_start = phdr->p_vaddr + si->load_bias;
    ElfW(Addr) seg_page_end = page_end(seg_start + phdr->p_memsz);
    ElfW(Addr) seg_file_end = page_end(seg_start + phdr->p_filesz);

    if (seg_page_end > seg_file_end) {
      prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME,
            reinterpret_cast<void*>(seg_file_end), seg_page_end - seg_file_end,
            ".bss");
    }
  }
}

#if defined(USE_RELA)
using RelType = ElfW(Rela);
const unsigned kRelTag = DT_RELA;
const unsigned kRelSzTag = DT_RELASZ;
#else
using RelType = ElfW(Rel);
const unsigned kRelTag = DT_REL;
const unsigned kRelSzTag = DT_RELSZ;
#endif

extern __LIBC_HIDDEN__ ElfW(Ehdr) __ehdr_start;

static void call_ifunc_resolvers_for_section(RelType* begin, RelType* end) {
  auto ehdr = reinterpret_cast<ElfW(Addr)>(&__ehdr_start);
  for (RelType *r = begin; r != end; ++r) {
    if (ELFW(R_TYPE)(r->r_info) != R_GENERIC_IRELATIVE) {
      continue;
    }
    ElfW(Addr)* offset = reinterpret_cast<ElfW(Addr)*>(ehdr + r->r_offset);
#if defined(USE_RELA)
    ElfW(Addr) resolver = ehdr + r->r_addend;
#else
    ElfW(Addr) resolver = ehdr + *offset;
#endif
    *offset = __bionic_call_ifunc_resolver(resolver);
  }
}

static void relocate_linker() {
  // The linker should only have relative relocations (in RELR) and IRELATIVE
  // relocations. Find the IRELATIVE relocations using the DT_JMPREL and
  // DT_PLTRELSZ, or DT_RELA/DT_RELASZ (DT_REL/DT_RELSZ on ILP32).
  auto ehdr = reinterpret_cast<ElfW(Addr)>(&__ehdr_start);
  auto* phdr = reinterpret_cast<ElfW(Phdr)*>(ehdr + __ehdr_start.e_phoff);
  for (size_t i = 0; i != __ehdr_start.e_phnum; ++i) {
    if (phdr[i].p_type != PT_DYNAMIC) {
      continue;
    }
    auto *dyn = reinterpret_cast<ElfW(Dyn)*>(ehdr + phdr[i].p_vaddr);
    ElfW(Addr) relr = 0, relrsz = 0, pltrel = 0, pltrelsz = 0, rel = 0, relsz = 0;
    for (size_t j = 0, size = phdr[i].p_filesz / sizeof(ElfW(Dyn)); j != size; ++j) {
      const auto tag = dyn[j].d_tag;
      const auto val = dyn[j].d_un.d_ptr;
      // We don't currently handle IRELATIVE relocations in DT_ANDROID_REL[A].
      // We disabled DT_ANDROID_REL[A] at build time; verify that it was actually disabled.
      CHECK(tag != DT_ANDROID_REL && tag != DT_ANDROID_RELA);
      if (tag == DT_RELR || tag == DT_ANDROID_RELR) {
        relr = val;
      } else if (tag == DT_RELRSZ || tag == DT_ANDROID_RELRSZ) {
        relrsz = val;
      } else if (tag == DT_JMPREL) {
        pltrel = val;
      } else if (tag == DT_PLTRELSZ) {
        pltrelsz = val;
      } else if (tag == kRelTag) {
        rel = val;
      } else if (tag == kRelSzTag) {
        relsz = val;
      }
    }
    // Apply RELR relocations first so that the GOT is initialized for ifunc
    // resolvers.
    if (relr && relrsz) {
      // Nothing has tagged the memtag globals here, so it is pointless either
      // way to handle them, the tags will be zero anyway.
      // That is moot though, because the linker does not use memtag_globals
      // in the first place.
      relocate_relr(reinterpret_cast<ElfW(Relr*)>(ehdr + relr),
                    reinterpret_cast<ElfW(Relr*)>(ehdr + relr + relrsz), ehdr,
                    /*has_memtag_globals=*/ false);
    }
    if (pltrel && pltrelsz) {
      call_ifunc_resolvers_for_section(reinterpret_cast<RelType*>(ehdr + pltrel),
                                       reinterpret_cast<RelType*>(ehdr + pltrel + pltrelsz));
    }
    if (rel && relsz) {
      call_ifunc_resolvers_for_section(reinterpret_cast<RelType*>(ehdr + rel),
                                       reinterpret_cast<RelType*>(ehdr + rel + relsz));
    }
  }
}

// Usable before ifunc resolvers have been called. This function is compiled with -ffreestanding.
static void linker_memclr(void* dst, size_t cnt) {
  for (size_t i = 0; i < cnt; ++i) {
    reinterpret_cast<char*>(dst)[i] = '\0';
  }
}

// Remapping MTE globals segments happens before the linker relocates itself, and so can't use
// memcpy() from string.h. This function is compiled with -ffreestanding.
void linker_memcpy(void* dst, const void* src, size_t n) {
  char* dst_bytes = reinterpret_cast<char*>(dst);
  const char* src_bytes = reinterpret_cast<const char*>(src);
  for (size_t i = 0; i < n; ++i) {
    dst_bytes[i] = src_bytes[i];
  }
}

// Detect an attempt to run the linker on itself. e.g.:
//   /system/bin/linker64 /system/bin/linker64
// Use priority-1 to run this constructor before other constructors.
__attribute__((constructor(1))) static void detect_self_exec() {
  // Normally, the linker initializes the auxv global before calling its
  // constructors. If the linker loads itself, though, the first loader calls
  // the second loader's constructors before calling __linker_init.
  if (__libc_shared_globals()->auxv != nullptr) {
    return;
  }
#if defined(__i386__)
  // We don't have access to the auxv struct from here, so use the int 0x80
  // fallback.
  __libc_sysinfo = reinterpret_cast<void*>(__libc_int0x80);
#endif
  __linker_error("error: linker cannot load itself");
}

static ElfW(Addr) __attribute__((noinline))
__linker_init_post_relocation(KernelArgumentBlock& args, soinfo& linker_so);

/*
 * This is the entry point for the linker, called from begin.S. This
 * method is responsible for fixing the linker's own relocations, and
 * then calling __linker_init_post_relocation().
 *
 * Because this method is called before the linker has fixed it's own
 * relocations, any attempt to reference an extern variable, extern
 * function, or other GOT reference will generate a segfault.
 */
extern "C" ElfW(Addr) __linker_init(void* raw_args) {
  // Unlock the loader mutex immediately before transferring to the executable's
  // entry point. This must happen after destructors are called in this function
  // (e.g. ~soinfo), so declare this variable very early.
  struct DlMutexUnlocker {
    ~DlMutexUnlocker() { pthread_mutex_unlock(&g_dl_mutex); }
  } unlocker;

  // Initialize TLS early so system calls and errno work.
  KernelArgumentBlock args(raw_args);
  bionic_tcb temp_tcb __attribute__((uninitialized));
  linker_memclr(&temp_tcb, sizeof(temp_tcb));
  __libc_init_main_thread_early(args, &temp_tcb);

  // When the linker is run by itself (rather than as an interpreter for
  // another program), AT_BASE is 0.
  ElfW(Addr) linker_addr = getauxval(AT_BASE);
  if (linker_addr == 0) {
    // The AT_PHDR and AT_PHNUM aux values describe this linker instance, so use
    // the phdr to find the linker's base address.
    ElfW(Addr) load_bias;
    get_elf_base_from_phdr(
      reinterpret_cast<ElfW(Phdr)*>(getauxval(AT_PHDR)), getauxval(AT_PHNUM),
      &linker_addr, &load_bias);
  }

  ElfW(Ehdr)* elf_hdr = reinterpret_cast<ElfW(Ehdr)*>(linker_addr);
  ElfW(Phdr)* phdr = reinterpret_cast<ElfW(Phdr)*>(linker_addr + elf_hdr->e_phoff);

  // Relocate the linker. This step will initialize the GOT, which is needed for
  // accessing non-hidden global variables. (On some targets, the stack
  // protector uses GOT accesses rather than TLS.) Relocating the linker will
  // also call the linker's ifunc resolvers so that string.h functions can be
  // used.
  relocate_linker();

  soinfo tmp_linker_so(nullptr, nullptr, nullptr, 0, 0);

  tmp_linker_so.base = linker_addr;
  tmp_linker_so.size = phdr_table_get_load_size(phdr, elf_hdr->e_phnum);
  tmp_linker_so.load_bias = get_elf_exec_load_bias(elf_hdr);
  tmp_linker_so.dynamic = nullptr;
  tmp_linker_so.phdr = phdr;
  tmp_linker_so.phnum = elf_hdr->e_phnum;
  tmp_linker_so.set_linker_flag();

  if (!tmp_linker_so.prelink_image()) __linker_cannot_link(args.argv[0]);
  // There is special logic in soinfo::relocate to avoid duplicating the
  // relocations we did in relocate_linker().
  if (!tmp_linker_so.link_image(SymbolLookupList(&tmp_linker_so), &tmp_linker_so, nullptr, nullptr)) __linker_cannot_link(args.argv[0]);

  return __linker_init_post_relocation(args, tmp_linker_so);
}

/*
 * This code is called after the linker has linked itself and fixed its own
 * GOT. It is safe to make references to externs and other non-local data at
 * this point. The compiler sometimes moves GOT references earlier in a
 * function, so avoid inlining this function (http://b/80503879).
 */
static ElfW(Addr) __attribute__((noinline))
__linker_init_post_relocation(KernelArgumentBlock& args, soinfo& tmp_linker_so) {
  // Finish initializing the main thread.
  __libc_init_main_thread_late();

  // We didn't protect the linker's RELRO pages in link_image because we
  // couldn't make system calls on x86 at that point, but we can now...
  if (!tmp_linker_so.protect_relro()) __linker_cannot_link(args.argv[0]);

  // And we can set VMA name for the bss section now
  set_bss_vma_name(&tmp_linker_so);

  // Initialize the linker's static libc's globals
  __libc_init_globals();

  // A constructor could spawn a thread that calls into the loader, so as soon
  // as we've called a constructor, we need to hold the lock until transferring
  // to the entry point.
  pthread_mutex_lock(&g_dl_mutex);

  // Initialize the linker's own global variables
  tmp_linker_so.call_constructors();

  // Setting the linker soinfo's soname can allocate heap memory, so delay it until here.
  for (const ElfW(Dyn)* d = tmp_linker_so.dynamic; d->d_tag != DT_NULL; ++d) {
    if (d->d_tag == DT_SONAME) {
      tmp_linker_so.set_soname(tmp_linker_so.get_string(d->d_un.d_val));
    }
  }

  // When the linker is run directly rather than acting as PT_INTERP, parse
  // arguments and determine the executable to load. When it's instead acting
  // as PT_INTERP, AT_ENTRY will refer to the loaded executable rather than the
  // linker's _start.
  const char* exe_to_load = nullptr;
  if (getauxval(AT_ENTRY) == reinterpret_cast<uintptr_t>(&_start)) {
    if (args.argc == 3 && !strcmp(args.argv[1], "--list")) {
      // We're being asked to behave like ldd(1).
      g_is_ldd = true;
      exe_to_load = args.argv[2];
    } else if (args.argc <= 1 || !strcmp(args.argv[1], "--help")) {
      async_safe_format_fd(STDOUT_FILENO,
         "Usage: %s [--list] PROGRAM [ARGS-FOR-PROGRAM...]\n"
         "       %s [--list] path.zip!/PROGRAM [ARGS-FOR-PROGRAM...]\n"
         "\n"
         "A helper program for linking dynamic executables. Typically, the kernel loads\n"
         "this program because it's the PT_INTERP of a dynamic executable.\n"
         "\n"
         "This program can also be run directly to load and run a dynamic executable. The\n"
         "executable can be inside a zip file if it's stored uncompressed and at a\n"
         "page-aligned offset.\n"
         "\n"
         "The --list option gives behavior equivalent to ldd(1) on other systems.\n",
         args.argv[0], args.argv[0]);
      _exit(EXIT_SUCCESS);
    } else {
      exe_to_load = args.argv[1];
      __libc_shared_globals()->initial_linker_arg_count = 1;
    }
  }

  // store argc/argv/envp to use them for calling constructors
  g_argc = args.argc - __libc_shared_globals()->initial_linker_arg_count;
  g_argv = args.argv + __libc_shared_globals()->initial_linker_arg_count;
  g_envp = args.envp;
  __libc_shared_globals()->init_progname = g_argv[0];

  // Initialize static variables. Note that in order to
  // get correct libdl_info we need to call constructors
  // before get_libdl_info().
  sonext = solist = solinker = get_libdl_info(tmp_linker_so);
  g_default_namespace.add_soinfo(solinker);

  ElfW(Addr) start_address = linker_main(args, exe_to_load);

  LD_DEBUG(any, "[ Jumping to _start (%p)... ]", reinterpret_cast<void*>(start_address));

  // Return the address that the calling assembly stub should jump to.
  return start_address;
}
```