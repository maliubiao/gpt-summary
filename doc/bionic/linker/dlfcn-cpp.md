Response:
Let's break down the thought process for answering the request about `bionic/linker/dlfcn.cpp`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of the provided C++ code file. Key areas of focus are:

* **Functionality:** What does this code *do*?
* **Android Relevance:** How does it interact with the Android OS?
* **Libc Function Implementation:** Detailed explanation of functions.
* **Dynamic Linker Aspects:**  SO layout, linking process.
* **Logic & Reasoning:**  Hypothetical inputs and outputs.
* **Common Errors:**  Pitfalls for developers.
* **Android Framework/NDK Interaction:** How does execution reach this code?
* **Frida Hooking:**  Practical debugging example.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the code to get a general idea of its purpose. Keywords like `dlopen`, `dlsym`, `dlclose`, `namespace`, and `linker` immediately stand out. The `#include` directives also provide clues (e.g., `linker.h`, `link.h`, `pthread.h`).

From this initial scan, it's clear that this file is about the dynamic linking facilities in Android's Bionic library. It provides the API for loading and managing shared libraries at runtime.

**3. Function-by-Function Analysis:**

Next, iterate through each of the `__loader_` prefixed functions. For each function, identify:

* **Purpose:** What is the function intended to do? (The function name is usually a good starting point).
* **Parameters:** What input does it take?
* **Return Value:** What output does it produce?
* **Mutex Usage:** Is it protected by `g_dl_mutex`? This indicates thread-safety concerns.
* **Core Logic:** What's the essential operation being performed?  Often, these functions call internal `do_` prefixed functions (e.g., `do_dlopen`, `do_dlsym`). Recognize that this file acts as a wrapper around the core linker logic.
* **Error Handling:** How are errors reported (e.g., `__bionic_format_dlerror`)?

**4. Identifying Android-Specific Aspects:**

Look for elements that are unique to Android:

* **Namespaces:**  Functions like `__loader_android_create_namespace`, `__loader_android_link_namespaces` clearly relate to Android's library namespace isolation.
* **SDK Version:**  `__loader_android_get_application_target_sdk_version` and `__loader_android_set_application_target_sdk_version` are Android-specific.
* **LD_LIBRARY_PATH:** Functions for getting and setting `LD_LIBRARY_PATH` are relevant to Android's dynamic linking.
* **CFI:** `__loader_cfi_fail` relates to Control Flow Integrity, a security feature in Android.
* **`android_dlextinfo`:**  This structure is used for extended `dlopen` functionality in Android.

**5. Explaining Libc Function Implementations:**

Focus on the `__loader_` prefixed functions that directly correspond to standard `dlfcn.h` functions (e.g., `dlopen`, `dlsym`, `dlclose`, `dlerror`, `dladdr`, `dl_iterate_phdr`). Explain that these `__loader_` functions are wrappers that acquire the `g_dl_mutex` for thread safety and then call the internal `do_` prefixed functions which contain the core implementation. Emphasize that the real logic resides elsewhere.

**6. Delving into Dynamic Linker Features:**

This requires inferring information *not* directly present in `dlfcn.cpp`. Key concepts to address:

* **SO Layout:** Describe the typical structure of a shared object file (.so), including sections like `.text`, `.data`, `.bss`, `.dynamic`, `.symtab`, `.strtab`, `.plt`, `.got`.
* **Linking Process:** Explain the steps involved in dynamic linking: loading, relocation, symbol resolution (using the `.dynamic` section, hash tables, etc.). Connect this to the functions in the code (e.g., `dlopen` triggers loading and linking, `dlsym` performs symbol resolution).
* **Namespaces:**  Explain how namespaces provide isolation and how functions like `__loader_android_create_namespace` and `__loader_android_link_namespaces` manage them.

**7. Constructing Examples and Scenarios:**

* **Hypothetical Input/Output:** For `dlopen`, show how a filename and flags lead to a handle or an error. For `dlsym`, demonstrate resolving a symbol.
* **Common Errors:** Think about typical mistakes developers make with dynamic linking (e.g., incorrect paths, dependency issues, forgetting to close libraries).

**8. Tracing the Path from Framework/NDK:**

This requires understanding the Android application lifecycle and how native code is invoked. Explain the sequence:

* Java code uses `System.loadLibrary()` or `Runtime.load()`.
* This calls into native code in the Android runtime (like `libart.so`).
* The runtime then calls Bionic's `dlopen` (or a related function) to load the requested shared library.
* The `caller_addr` argument in the `dlopen` calls helps the linker make decisions based on the caller's context (e.g., namespace).

**9. Creating a Frida Hook Example:**

Choose a relatively simple and illustrative function like `dlopen`. Show the basic structure of a Frida script to intercept this function, log arguments, and potentially modify behavior.

**10. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use formatting (like code blocks and bullet points) to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on the individual lines of code.
* **Correction:** Shift focus to the high-level functionality and purpose of each function within the context of dynamic linking.
* **Initial thought:**  Assume the user has deep technical knowledge.
* **Correction:** Explain concepts clearly and provide background information where necessary.
* **Initial thought:**  Just list the functions.
* **Correction:**  Group functions by their role (e.g., loading, symbol resolution, namespace management).
* **Initial thought:**  Forget to include practical examples.
* **Correction:** Add examples for common errors, hypothetical input/output, and Frida hooking.

By following this structured approach, combining code analysis with conceptual understanding of dynamic linking in Android, and continually refining the explanation, it's possible to generate a comprehensive and informative answer like the example provided in the prompt.
好的，让我们深入分析 `bionic/linker/dlfcn.cpp` 这个文件。

**功能列举:**

`dlfcn.cpp` 文件实现了动态链接器 (dynamic linker) 对外提供的 API，允许程序在运行时加载和管理共享库 (shared libraries)。它提供了一组标准的 C 函数，通常被称为 "dlfcn" API，因为这些函数在 `dlfcn.h` 头文件中声明。 主要功能包括：

1. **加载共享库 (`dlopen`)**:  允许程序在运行时显式加载指定的共享库。
2. **查找符号 (`dlsym`, `dlvsym`)**:  在已加载的共享库中查找特定的符号（函数或变量）。`dlvsym` 允许指定符号的版本。
3. **关闭共享库 (`dlclose`)**: 卸载之前加载的共享库，释放相关的资源。
4. **获取错误信息 (`dlerror`)**: 获取最近一次 `dlopen`, `dlsym`, 或 `dlclose` 操作失败的错误信息。
5. **获取地址信息 (`dladdr`)**: 给定一个程序地址，返回包含该地址的共享库信息，包括库的基地址和符号信息。
6. **迭代共享库 (`dl_iterate_phdr`)**: 允许遍历当前进程加载的所有共享库。
7. **管理命名空间 (`__loader_android_create_namespace`, `__loader_android_link_namespaces` 等)**: Android 引入了命名空间的概念来隔离不同应用程序或组件加载的共享库，防止冲突。这些函数用于创建、连接和管理这些命名空间。
8. **CFI (Control Flow Integrity) 支持 (`__loader_cfi_fail`)**:  提供对控制流完整性的支持，用于检测运行时的安全漏洞。
9. **线程局部存储 (TLS) 管理 (`__loader_add_thread_local_dtor`, `__loader_remove_thread_local_dtor`)**:  用于管理线程局部存储的析构函数。
10. **获取和设置目标 SDK 版本 (`__loader_android_get_application_target_sdk_version`, `__loader_android_set_application_target_sdk_version`)**:  允许获取和设置应用程序的目标 SDK 版本，这会影响链接器的行为。
11. **处理信号 (`__loader_android_handle_signal`)**:  linker 可以处理某些信号，例如用于调试。
12. **设置兼容模式 (`__loader_android_set_16kb_appcompat_mode`)**:  为了兼容旧的应用，可以设置 16KB 对齐的兼容模式。
13. **获取全局共享状态 (`__loader_shared_globals`)**:  返回指向 `libc_shared_globals` 的指针，包含一些全局共享的状态。

**与 Android 功能的关系及举例说明:**

这个文件是 Android 动态链接机制的核心组成部分，直接支撑着 Android 应用程序框架和 NDK 的运行。

* **应用程序启动:** 当 Android 系统启动一个应用程序时，`dlfcn.cpp` 中实现的 `dlopen` 等函数会被调用，以加载应用程序依赖的共享库 (例如 `libc.so`, `libm.so`, 以及各种 NDK 库)。
* **NDK 开发:** 使用 NDK 开发的应用程序会使用这些函数来加载和使用 C/C++ 编写的共享库。例如，一个游戏引擎可能使用 `dlopen` 加载渲染库或物理引擎库。
    ```c++
    // NDK 代码示例
    #include <dlfcn.h>
    #include <stdio.h>

    void load_library() {
        void* handle = dlopen("libmylibrary.so", RTLD_LAZY);
        if (!handle) {
            fprintf(stderr, "dlopen error: %s\n", dlerror());
            return;
        }

        // 使用 dlsym 获取函数指针
        typedef int (*MyFunction)(int);
        MyFunction my_func = (MyFunction) dlsym(handle, "my_function");
        if (my_func) {
            int result = my_func(10);
            printf("Result from my_function: %d\n", result);
        } else {
            fprintf(stderr, "dlsym error: %s\n", dlerror());
        }

        dlclose(handle);
    }
    ```
* **框架服务:** Android 框架的许多服务也依赖动态链接。例如，`zygote` 进程在启动应用程序进程时会使用这些函数加载必要的库。
* **插件化/模块化:** Android 应用或系统服务可以使用动态加载来实现插件化或模块化的架构，允许在运行时添加或替换功能。
* **命名空间隔离:** Android 的命名空间机制用于隔离不同应用或模块的依赖，避免库版本冲突。`__loader_android_create_namespace` 等函数就是实现这一机制的关键。例如，不同的应用可能会依赖不同版本的 `libssl.so`，命名空间可以确保它们各自加载正确的版本。

**Libc 函数功能实现详解:**

这里所说的 "libc 函数" 实际上是指 `dlfcn` API 中的函数，它们在 Bionic (Android 的 C 库) 中实现。  `dlfcn.cpp` 文件本身**并不是**这些函数的**核心实现**，而是提供了一个**外层封装**，负责处理线程安全 (通过 `g_dl_mutex`) 和错误处理，然后调用内部的 `do_` 前缀的函数来完成实际的工作。这些内部函数的实现在其他的 linker 源文件中 (例如 `linker.cpp`)。

以下解释 `dlfcn.cpp` 中封装的每个函数的粗略实现逻辑：

* **`__loader_dlopen(const char* filename, int flags, const void* caller_addr)`:**
    1. 获取全局锁 `g_dl_mutex` 以保证线程安全。
    2. 调用内部函数 `do_dlopen(filename, flags, nullptr, caller_addr)` 来执行实际的库加载逻辑。 `caller_addr` 用于确定调用者的上下文，例如所在的命名空间。
    3. 如果 `do_dlopen` 返回 `nullptr` (加载失败)，则使用 `linker_get_error_buffer()` 获取错误信息，并使用 `__bionic_format_dlerror` 格式化错误信息存储到线程局部变量中。
    4. 返回 `do_dlopen` 的结果（加载的库的句柄或 `nullptr`）。

* **`__loader_dlsym(void* handle, const char* symbol, const void* caller_addr)` 和 `__loader_dlvsym(...)`:**
    1. 获取全局锁 `g_dl_mutex`。
    2. 调用内部函数 `do_dlsym(handle, symbol, version, caller_addr, &result)` 来执行符号查找。`dlvsym` 会传入 `version` 参数。
    3. 如果 `do_dlsym` 返回 `false` (查找失败)，则使用 `linker_get_error_buffer()` 获取错误信息并格式化。
    4. 返回查找到的符号地址或 `nullptr`。

* **`__loader_dlclose(void* handle)`:**
    1. 获取全局锁 `g_dl_mutex`。
    2. 调用内部函数 `do_dlclose(handle)` 执行库卸载。
    3. 如果 `do_dlclose` 返回非零值 (卸载失败)，则获取错误信息并格式化。
    4. 返回 `do_dlclose` 的结果。

* **`__loader_dlerror()`:**
    1. 调用 `__bionic_set_dlerror(nullptr)`，这会返回并清除当前线程存储的错误信息。
    2. 返回之前存储的错误信息。

* **`__loader_dladdr(const void* addr, Dl_info* info)`:**
    1. 获取全局锁 `g_dl_mutex`。
    2. 调用内部函数 `do_dladdr(addr, info)` 来填充 `Dl_info` 结构体，包含地址所在的库和符号信息。
    3. 返回 `do_dladdr` 的结果。

* **`__loader_dl_iterate_phdr(...)`:**
    1. 获取全局锁 `g_dl_mutex`。
    2. 调用内部函数 `do_dl_iterate_phdr(cb, data)`，该函数会遍历已加载的共享库并调用回调函数 `cb`。
    3. 返回 `do_dl_iterate_phdr` 的结果。

**涉及 dynamic linker 的功能，SO 布局样本，以及链接的处理过程:**

`dlfcn.cpp` 直接与 dynamic linker 的功能相关。让我们看看一个典型的 `.so` (共享对象) 文件的布局，以及链接的处理过程：

**SO 布局样本:**

一个 `.so` 文件是一个 ELF (Executable and Linkable Format) 文件。其主要部分包括：

```
ELF Header
Program Headers      (描述如何加载 .so 到内存)
Section Headers      (描述各个 section 的信息，用于链接和调试)

.text               (可执行代码段)
.rodata             (只读数据段，例如字符串常量)
.data               (已初始化的全局变量和静态变量)
.bss                (未初始化的全局变量和静态变量)

.dynamic            (动态链接信息，包含依赖的库、符号表位置等)
.symtab             (符号表，包含导出的和导入的符号信息)
.strtab             (字符串表，存储符号名称等字符串)
.hash 或 .gnu.hash  (符号哈希表，用于快速查找符号)
.plt                (Procedure Linkage Table，过程链接表，用于延迟绑定)
.got 或 .got.plt     (Global Offset Table，全局偏移表，存储全局符号的地址)

... 其他 section (例如 .rel.dyn, .rel.plt 用于重定位)
```

**链接的处理过程:**

1. **`dlopen` 调用:** 当应用程序调用 `dlopen("libexample.so", ...)` 时：
    * linker 首先查找 `libexample.so` 文件，通常会在 `LD_LIBRARY_PATH` 指定的路径中搜索。
    * linker 将 `.so` 文件加载到内存中，根据 Program Headers 的指示映射各个段。
    * **符号解析 (Symbol Resolution):**
        * linker 会解析 `.dynamic` 段中的 `DT_NEEDED` 条目，加载 `libexample.so` 依赖的其他共享库。
        * linker 会处理重定位信息 (`.rel.dyn`, `.rel.plt`)，这些信息指示了需要在运行时修正的地址。
        * **延迟绑定 (Lazy Binding, 默认行为):**  对于外部函数调用，linker 通常会使用 PLT 和 GOT。PLT 中的每个条目对应一个外部函数。第一次调用该函数时，会跳转到 PLT 中的一段代码，这段代码会调用 linker 来解析该符号的实际地址，并将地址填入 GOT 表中。后续的调用将直接通过 GOT 表跳转，避免了重复的解析。
        * **非延迟绑定 (RTLD_NOW 标志):**  如果 `dlopen` 使用 `RTLD_NOW` 标志，linker 会在加载时立即解析所有符号。
    * linker 会执行 `.init` 段中的初始化代码 (如果有)。
    * `dlopen` 返回一个指向加载的 `.so` 的句柄。

2. **`dlsym` 调用:** 当应用程序调用 `dlsym(handle, "my_function")` 时：
    * linker 会在与 `handle` 对应的共享库的符号表 (`.symtab`) 中查找名为 "my_function" 的符号。
    * linker 使用符号哈希表 (`.hash` 或 `.gnu.hash`) 来加速查找过程。
    * 如果找到符号，`dlsym` 返回该符号的地址。

3. **`dlclose` 调用:** 当应用程序调用 `dlclose(handle)` 时：
    * linker 会递减该共享库的引用计数。
    * 当引用计数变为零时，linker 会执行 `.fini` 段中的析构代码 (如果有)。
    * linker 会从内存中卸载该共享库。

**假设输入与输出 (逻辑推理):**

* **假设输入 `dlopen("libtest.so", RTLD_LAZY)`:**
    * **假设输出 (成功):** 返回一个非空的 `void*` 句柄，指向加载的 `libtest.so`。
    * **假设输出 (失败):** 返回 `nullptr`，并且后续调用 `dlerror()` 返回描述失败原因的字符串 (例如 "cannot find libtest.so")。

* **假设输入 `dlsym(handle, "calculate_sum")`，其中 `handle` 是 `libtest.so` 的句柄，且 `libtest.so` 导出了 `int calculate_sum(int a, int b)` 函数:**
    * **假设输出 (成功):** 返回 `calculate_sum` 函数的内存地址。
    * **假设输出 (失败):** 返回 `nullptr`，并且后续调用 `dlerror()` 返回描述失败原因的字符串 (例如 "undefined symbol calculate_sum")。

**用户或编程常见的使用错误举例:**

1. **路径错误:**  `dlopen` 时提供的共享库文件名或路径不正确，导致 linker 找不到该文件。
    ```c++
    // 错误示例
    void* handle = dlopen("mylibrary.so", RTLD_LAZY); // 假设 mylibrary.so 不在默认路径或 LD_LIBRARY_PATH 中
    if (!handle) {
        fprintf(stderr, "dlopen error: %s\n", dlerror()); // 可能输出 "cannot find mylibrary.so"
    }
    ```

2. **依赖缺失:**  要加载的共享库依赖于其他库，但这些依赖库没有被加载或找不到。
    ```c++
    // 假设 libA.so 依赖 libB.so，但 libB.so 没有被加载
    void* handle_a = dlopen("libA.so", RTLD_LAZY);
    if (!handle_a) {
        fprintf(stderr, "dlopen error: %s\n", dlerror()); // 可能输出 "cannot load libB.so"
    }
    ```

3. **符号名称错误:** `dlsym` 时提供的符号名称与共享库中实际的符号名称不符 (包括大小写错误)。
    ```c++
    // 假设 libmylib.so 中有函数 void myFunc();
    void* handle = dlopen("libmylib.so", RTLD_LAZY);
    void (*func)() = (void (*)()) dlsym(handle, "myfunc"); // 注意大小写错误
    if (!func) {
        fprintf(stderr, "dlsym error: %s\n", dlerror()); // 可能输出 "undefined symbol myfunc"
    }
    ```

4. **忘记 `dlclose`:**  加载了共享库后，如果没有及时调用 `dlclose` 释放资源，可能导致内存泄漏。

5. **在错误的命名空间加载:**  在 Android 中，如果尝试在错误的命名空间加载库，会导致加载失败。

6. **并发问题:**  在多线程环境下，如果不加锁地使用 `dlopen`, `dlsym`, `dlclose` 等函数，可能会导致竞争条件。 `dlfcn.cpp` 中使用 `g_dl_mutex` 来解决这个问题，但用户自定义的加载逻辑仍然需要注意线程安全。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Java 代码调用 `System.loadLibrary("mylibrary")` 或 `Runtime.load("/path/to/mylibrary.so")`:**  这是从 Java 层加载 native 库的常见方式。

2. **JNI 调用:** `System.loadLibrary` 会通过 JNI (Java Native Interface) 调用到 Android 运行时的 native 代码中 (例如 `libart.so`)。

3. **`android_dlopen_ext` 或 `dlopen` 调用:**  Android 运行时的 native 代码最终会调用 Bionic linker 提供的 `__loader_android_dlopen_ext` 或 `__loader_dlopen` 函数，这些函数在 `dlfcn.cpp` 中实现。
    * `System.loadLibrary` 通常会使用库名，linker 会在默认路径和 `LD_LIBRARY_PATH` 中搜索。
    * `Runtime.load` 提供完整的路径。

4. **linker 执行加载和链接:**  `dlfcn.cpp` 中的函数会调用内部的 linker 代码来执行实际的加载、符号解析和重定位等操作。

5. **返回句柄:** `dlopen` 成功后，会将加载的库的句柄返回给 Java 层的 `ClassLoader`，Java 代码可以通过 JNI 调用 `dlsym` 来获取 native 函数的地址。

**Frida Hook 示例调试步骤:**

假设我们想 hook `dlopen` 函数，查看哪个库被加载以及加载标志是什么：

```python
# Frida 脚本示例 (save as hook_dlopen.py)
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['msg']))
    else:
        print(message)

def main():
    package_name = "com.example.myapp"  # 替换为你的应用包名
    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"[-] Process '{package_name}' not found. Make sure the app is running.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName(null, "__loader_dlopen"), {
        onEnter: function(args) {
            var filename = Memory.readUtf8String(args[0]);
            var flags = args[1].toInt();
            var caller_addr = args[2];
            send({tag: "dlopen", msg: "Loading library: " + filename + ", flags: " + flags + ", caller: " + caller_addr});
        },
        onLeave: function(retval) {
            send({tag: "dlopen", msg: "dlopen returned: " + retval});
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Waiting for dlopen calls...")
    sys.stdin.read()
    session.detach()

if __name__ == "__main__":
    main()
```

**调试步骤:**

1. **准备环境:**
    * 确保你的 Android 设备已 root 并安装了 Frida 服务。
    * 安装 Python 和 Frida (`pip install frida-tools`).
    * 找到你要调试的 Android 应用的包名。

2. **运行应用:**  在 Android 设备上启动目标应用程序。

3. **运行 Frida 脚本:** 在你的电脑上打开终端，运行 `python hook_dlopen.py`。

4. **查看输出:** 当应用程序加载共享库时，Frida 脚本会拦截 `__loader_dlopen` 函数的调用，并打印出加载的库文件名、标志以及调用者地址。 你会在终端看到类似以下的输出：

   ```
   [*] Script loaded. Waiting for dlopen calls...
   [*] dlopen: Loading library: /system/lib64/liblog.so, flags: 2, caller: 0x...
   [*] dlopen: dlopen returned: 0x...
   [*] dlopen: Loading library: /data/app/com.example.myapp/lib/arm64/libnative-lib.so, flags: 2, caller: 0x...
   [*] dlopen: dlopen returned: 0x...
   ...
   ```

通过这种方式，你可以观察到应用程序加载了哪些共享库，以及加载时使用的标志，这有助于理解动态链接的行为和排查相关问题。 你可以根据需要 hook 其他函数，例如 `dlsym` 或 `dlclose`，以监控符号查找和库卸载过程。

希望这个详细的解释能够帮助你理解 `bionic/linker/dlfcn.cpp` 的功能及其在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/linker/dlfcn.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2007 The Android Open Source Project
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

#include "linker.h"
#include "linker_cfi.h"
#include "linker_debuggerd.h"
#include "linker_dlwarning.h"
#include "linker_globals.h"

#include <link.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <android/api-level.h>

#include <bionic/pthread_internal.h>
#include "private/bionic_globals.h"
#include "private/bionic_tls.h"
#include "private/ScopedPthreadMutexLocker.h"

#define __LINKER_PUBLIC__ __attribute__((visibility("default")))

extern "C" {

android_namespace_t* __loader_android_create_namespace(const char* name,
                                                       const char* ld_library_path,
                                                       const char* default_library_path,
                                                       uint64_t type,
                                                       const char* permitted_when_isolated_path,
                                                       android_namespace_t* parent_namespace,
                                                       const void* caller_addr) __LINKER_PUBLIC__;
void* __loader_android_dlopen_ext(const char* filename,
                           int flags,
                           const android_dlextinfo* extinfo,
                           const void* caller_addr) __LINKER_PUBLIC__;
void __loader_android_dlwarning(void* obj, void (*f)(void*, const char*)) __LINKER_PUBLIC__;
int __loader_android_get_application_target_sdk_version() __LINKER_PUBLIC__;
void __loader_android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size) __LINKER_PUBLIC__;
android_namespace_t* __loader_android_get_exported_namespace(const char* name) __LINKER_PUBLIC__;
bool __loader_android_init_anonymous_namespace(const char* shared_libs_sonames,
                                               const char* library_search_path) __LINKER_PUBLIC__;
bool __loader_android_link_namespaces(android_namespace_t* namespace_from,
                                      android_namespace_t* namespace_to,
                                      const char* shared_libs_sonames) __LINKER_PUBLIC__;
bool __loader_android_link_namespaces_all_libs(android_namespace_t* namespace_from,
                                               android_namespace_t* namespace_to) __LINKER_PUBLIC__;
void __loader_android_set_application_target_sdk_version(int target) __LINKER_PUBLIC__;
void __loader_android_update_LD_LIBRARY_PATH(const char* ld_library_path) __LINKER_PUBLIC__;
void __loader_cfi_fail(uint64_t CallSiteTypeId,
                       void* Ptr,
                       void *DiagData,
                       void *CallerPc) __LINKER_PUBLIC__;
int __loader_dl_iterate_phdr(int (*cb)(dl_phdr_info* info, size_t size, void* data),
                             void* data) __LINKER_PUBLIC__;
int __loader_dladdr(const void* addr, Dl_info* info) __LINKER_PUBLIC__;
int __loader_dlclose(void* handle) __LINKER_PUBLIC__;
char* __loader_dlerror() __LINKER_PUBLIC__;
void* __loader_dlopen(const char* filename, int flags, const void* caller_addr) __LINKER_PUBLIC__;
void* __loader_dlsym(void* handle, const char* symbol, const void* caller_addr) __LINKER_PUBLIC__;
void* __loader_dlvsym(void* handle,
                      const char* symbol,
                      const char* version,
                      const void* caller_addr) __LINKER_PUBLIC__;
void __loader_add_thread_local_dtor(void* dso_handle) __LINKER_PUBLIC__;
void __loader_remove_thread_local_dtor(void* dso_handle) __LINKER_PUBLIC__;
void __loader_android_set_16kb_appcompat_mode(bool enable_app_compat) __LINKER_PUBLIC__;
libc_shared_globals* __loader_shared_globals() __LINKER_PUBLIC__;
#if defined(__arm__)
_Unwind_Ptr __loader_dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) __LINKER_PUBLIC__;
#endif
bool __loader_android_handle_signal(int signal_number, siginfo_t* info,
                                    void* context) __LINKER_PUBLIC__;
}

pthread_mutex_t g_dl_mutex = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;

static char* __bionic_set_dlerror(char* new_value) {
  char* old_value = __get_thread()->current_dlerror;
  __get_thread()->current_dlerror = new_value;

  if (new_value != nullptr) LD_LOG(kLogErrors, "dlerror set to \"%s\"", new_value);
  return old_value;
}

static void __bionic_format_dlerror(const char* msg, const char* detail) {
  char* buffer = __get_thread()->dlerror_buffer;
  strlcpy(buffer, msg, __BIONIC_DLERROR_BUFFER_SIZE);
  if (detail != nullptr) {
    strlcat(buffer, ": ", __BIONIC_DLERROR_BUFFER_SIZE);
    strlcat(buffer, detail, __BIONIC_DLERROR_BUFFER_SIZE);
  }

  __bionic_set_dlerror(buffer);
}

char* __loader_dlerror() {
  char* old_value = __bionic_set_dlerror(nullptr);
  return old_value;
}

void __loader_android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  do_android_get_LD_LIBRARY_PATH(buffer, buffer_size);
}

void __loader_android_update_LD_LIBRARY_PATH(const char* ld_library_path) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  do_android_update_LD_LIBRARY_PATH(ld_library_path);
}

static void* dlopen_ext(const char* filename,
                        int flags,
                        const android_dlextinfo* extinfo,
                        const void* caller_addr) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  g_linker_logger.ResetState();
  void* result = do_dlopen(filename, flags, extinfo, caller_addr);
  if (result == nullptr) {
    __bionic_format_dlerror("dlopen failed", linker_get_error_buffer());
    return nullptr;
  }
  return result;
}

void* __loader_android_dlopen_ext(const char* filename,
                           int flags,
                           const android_dlextinfo* extinfo,
                           const void* caller_addr) {
  return dlopen_ext(filename, flags, extinfo, caller_addr);
}

void* __loader_dlopen(const char* filename, int flags, const void* caller_addr) {
  return dlopen_ext(filename, flags, nullptr, caller_addr);
}

void* dlsym_impl(void* handle, const char* symbol, const char* version, const void* caller_addr) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  g_linker_logger.ResetState();
  void* result;
  if (!do_dlsym(handle, symbol, version, caller_addr, &result)) {
    __bionic_format_dlerror(linker_get_error_buffer(), nullptr);
    return nullptr;
  }

  return result;
}

void* __loader_dlsym(void* handle, const char* symbol, const void* caller_addr) {
  return dlsym_impl(handle, symbol, nullptr, caller_addr);
}

void* __loader_dlvsym(void* handle, const char* symbol, const char* version, const void* caller_addr) {
  return dlsym_impl(handle, symbol, version, caller_addr);
}

int __loader_dladdr(const void* addr, Dl_info* info) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  return do_dladdr(addr, info);
}

int __loader_dlclose(void* handle) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  int result = do_dlclose(handle);
  if (result != 0) {
    __bionic_format_dlerror("dlclose failed", linker_get_error_buffer());
  }
  return result;
}

int __loader_dl_iterate_phdr(int (*cb)(dl_phdr_info* info, size_t size, void* data), void* data) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  return do_dl_iterate_phdr(cb, data);
}

#if defined(__arm__)
_Unwind_Ptr __loader_dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  return do_dl_unwind_find_exidx(pc, pcount);
}
#endif

void __loader_android_set_application_target_sdk_version(int target) {
  // lock to avoid modification in the middle of dlopen.
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  set_application_target_sdk_version(target);
}

int __loader_android_get_application_target_sdk_version() {
  return get_application_target_sdk_version();
}

void __loader_android_dlwarning(void* obj, void (*f)(void*, const char*)) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  get_dlwarning(obj, f);
}

bool __loader_android_init_anonymous_namespace(const char* shared_libs_sonames,
                                               const char* library_search_path) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  bool success = init_anonymous_namespace(shared_libs_sonames, library_search_path);
  if (!success) {
    __bionic_format_dlerror("android_init_anonymous_namespace failed", linker_get_error_buffer());
  }

  return success;
}

android_namespace_t* __loader_android_create_namespace(const char* name,
                                                const char* ld_library_path,
                                                const char* default_library_path,
                                                uint64_t type,
                                                const char* permitted_when_isolated_path,
                                                android_namespace_t* parent_namespace,
                                                const void* caller_addr) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);

  android_namespace_t* result = create_namespace(caller_addr,
                                                 name,
                                                 ld_library_path,
                                                 default_library_path,
                                                 type,
                                                 permitted_when_isolated_path,
                                                 parent_namespace);

  if (result == nullptr) {
    __bionic_format_dlerror("android_create_namespace failed", linker_get_error_buffer());
  }

  return result;
}

bool __loader_android_link_namespaces(android_namespace_t* namespace_from,
                                      android_namespace_t* namespace_to,
                                      const char* shared_libs_sonames) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);

  bool success = link_namespaces(namespace_from, namespace_to, shared_libs_sonames);

  if (!success) {
    __bionic_format_dlerror("android_link_namespaces failed", linker_get_error_buffer());
  }

  return success;
}

bool __loader_android_link_namespaces_all_libs(android_namespace_t* namespace_from,
                                               android_namespace_t* namespace_to) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);

  bool success = link_namespaces_all_libs(namespace_from, namespace_to);

  if (!success) {
    __bionic_format_dlerror("android_link_namespaces_all_libs failed", linker_get_error_buffer());
  }

  return success;
}

android_namespace_t* __loader_android_get_exported_namespace(const char* name) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  return get_exported_namespace(name);
}

void __loader_cfi_fail(uint64_t CallSiteTypeId, void* Ptr, void *DiagData, void *CallerPc) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  CFIShadowWriter::CfiFail(CallSiteTypeId, Ptr, DiagData, CallerPc);
}

void __loader_add_thread_local_dtor(void* dso_handle) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  increment_dso_handle_reference_counter(dso_handle);
}

void __loader_remove_thread_local_dtor(void* dso_handle) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  decrement_dso_handle_reference_counter(dso_handle);
}

void __loader_android_set_16kb_appcompat_mode(bool enable_app_compat) {
  ScopedPthreadMutexLocker locker(&g_dl_mutex);
  set_16kb_appcompat_mode(enable_app_compat);
}

libc_shared_globals* __loader_shared_globals() {
  return __libc_shared_globals();
}

bool __loader_android_handle_signal(int signal_number, siginfo_t* info, void* context) {
  return debuggerd_handle_signal(signal_number, info, context);
}

static uint8_t __libdl_info_buf[sizeof(soinfo)] __attribute__((aligned(8)));
static soinfo* __libdl_info = nullptr;

// This is used by the dynamic linker. Every process gets these symbols for free.
soinfo* get_libdl_info(const soinfo& linker_si) {
  CHECK((linker_si.flags_ & FLAG_GNU_HASH) != 0);

  if (__libdl_info == nullptr) {
    __libdl_info = new (__libdl_info_buf) soinfo(&g_default_namespace, nullptr, nullptr, 0, 0);
    __libdl_info->flags_ |= (FLAG_LINKED | FLAG_GNU_HASH);
    __libdl_info->strtab_ = linker_si.strtab_;
    __libdl_info->symtab_ = linker_si.symtab_;
    __libdl_info->load_bias = linker_si.load_bias;
    __libdl_info->phdr = linker_si.phdr;
    __libdl_info->phnum = linker_si.phnum;

    __libdl_info->gnu_nbucket_ = linker_si.gnu_nbucket_;
    __libdl_info->gnu_maskwords_ = linker_si.gnu_maskwords_;
    __libdl_info->gnu_shift2_ = linker_si.gnu_shift2_;
    __libdl_info->gnu_bloom_filter_ = linker_si.gnu_bloom_filter_;
    __libdl_info->gnu_bucket_ = linker_si.gnu_bucket_;
    __libdl_info->gnu_chain_ = linker_si.gnu_chain_;
    __libdl_info->memtag_dynamic_entries_ = linker_si.memtag_dynamic_entries_;

    __libdl_info->ref_count_ = 1;
    __libdl_info->strtab_size_ = linker_si.strtab_size_;
    __libdl_info->local_group_root_ = __libdl_info;
    __libdl_info->soname_ = linker_si.soname_;
    __libdl_info->target_sdk_version_ = __ANDROID_API__;
    __libdl_info->generate_handle();
#if defined(__work_around_b_24465209__)
    strlcpy(__libdl_info->old_name_, __libdl_info->soname_.c_str(),
            sizeof(__libdl_info->old_name_));
#endif
  }

  return __libdl_info;
}

"""

```