Response:
Let's break down the thought process for analyzing this C++ test file. The goal is to understand its functionality, its relation to Android, explain involved C library functions, dissect dynamic linking aspects, address potential errors, and trace its execution.

**1. Initial Understanding - What is the File About?**

* **File Name:** `elftls_dl_test.cpp`. The "elftls" part immediately suggests thread-local storage (TLS) within the ELF (Executable and Linkable Format) context. "dl" likely refers to dynamic linking (`dlopen`, `dlsym`, `dlclose`). "test" clearly indicates this is a unit test file.
* **Header Comments:**  The copyright notice points to the Android Open Source Project and redistribution terms. This confirms it's part of the Android Bionic library.
* **Includes:**  Key headers like `<dlfcn.h>` and `<link.h>` solidify the focus on dynamic linking. `<gtest/gtest.h>` signals this uses the Google Test framework. Other includes like `<string>`, `<thread>` are standard C++ and suggest the tests involve string manipulation and multithreading. The Bionic-specific headers (`platform/bionic/tls.h`, `bionic/pthread_internal.h`) are critical clues.

**2. Deconstructing the Tests - One by One:**

The core of the analysis involves examining each `TEST` function. For each test, the following questions need to be answered:

* **What is the test's name?** The name usually hints at the functionality being tested (e.g., `dlopen_shared_var_ie`, `dlclose_resets_values`).
* **What dynamic linking functions are used?** (`dlopen`, `dlsym`, `dlclose`).
* **What shared libraries are involved?** Look for strings passed to `dlopen`.
* **What are the expected outcomes (assertions)?** `ASSERT_NE(nullptr, ...)` checks for successful loading or symbol resolution. `ASSERT_EQ(...)` compares values.
* **What specific TLS concepts are being tested?** Look for terms like "IE access," "GD access," "static TLS," "dynamic TLS," "TPREL relocation," "TLSDESC."
* **Are there conditional checks (`#if defined(__BIONIC__)`)?** This highlights Android-specific behavior versus more general behavior (or other libc implementations like glibc).
* **Does the test involve multithreading?** Look for `std::thread`. This often relates to testing TLS isolation.
* **Does the test use an `ExecTestHelper`?**  This suggests the test launches a separate executable to verify behavior.

**3. Identifying Key Concepts and Their Android Relevance:**

As each test is analyzed, connections to broader concepts need to be made:

* **Thread-Local Storage (TLS):** The central theme. How do shared libraries access per-thread data? What are the different access models (IE, GD)? How does the dynamic linker manage TLS allocation?
* **Dynamic Linking:**  How are shared libraries loaded and unloaded at runtime? How are symbols resolved? What is the role of the dynamic linker?
* **Bionic Specifics:** What are the Android-specific implementations or behaviors related to TLS and dynamic linking? The conditional compilation blocks are crucial here. For example, the handling of IE errors is different in Bionic.
* **Error Handling:**  How are errors during dynamic linking reported? The `dlerror` function and the `dlopen_ie_error` test are relevant.
* **Memory Management:**  How is TLS memory allocated and deallocated?  The `dlclose_resets_values` and `dlclose_removes_entry` tests touch on this.
* **Symbol Lookup:** How does `dlsym` work with TLS variables?  The `dlsym_static_tls` and `dlsym_dynamic_tls` tests explore this.
* **Debugging and Inspection:** The `dladdr` and `dl_iterate_phdr` tests illustrate ways to introspect loaded libraries and their TLS segments.

**4. Explaining Libc Functions:**

For each libc function encountered (`dlopen`, `dlsym`, `dlclose`, `dlerror`, `dladdr`, `dl_iterate_phdr`), a concise explanation of its purpose and core functionality is required. For deeper understanding, consider:

* **Core Purpose:** What problem does the function solve?
* **Key Parameters:** What information does the function need to operate?
* **Return Value:** What does the function return (success, failure, a pointer, etc.)?
* **Error Handling:** How are errors indicated?

**5. Dynamic Linker Deep Dive:**

For aspects related to the dynamic linker, the following steps are necessary:

* **Identify the Scenario:** What specific dynamic linking behavior is being tested (e.g., loading a library with IE accesses, handling unresolved weak symbols)?
* **Hypothesize the SO Layout:**  Imagine the structure of the involved shared libraries (`.so` files). Where are the TLS variables? How are the symbols defined and referenced?  A simple textual representation is sufficient.
* **Describe the Linking Process:** Explain the steps the dynamic linker takes when loading the library, resolving symbols (especially TLS symbols), and performing relocations. This might involve concepts like the Global Offset Table (GOT), Procedure Linkage Table (PLT), and the Dynamic Thread Vector (DTV).

**6. Addressing User Errors and Providing Examples:**

Think about common mistakes developers might make when working with dynamic linking and TLS:

* **Incorrect `dlopen` flags:** Leading to unexpected symbol resolution or loading behavior.
* **Forgetting to `dlclose` libraries:** Causing resource leaks.
* **Incorrectly accessing TLS variables:**  Leading to crashes or undefined behavior.
* **Misunderstanding TLS access models:**  Trying to use IE access when GD is required, or vice-versa.

Provide simple code examples to illustrate these errors.

**7. Tracing Execution from Framework to Test:**

This requires understanding the Android system architecture and the role of Bionic.

* **High-Level Entry Points:**  Consider how an Android app or the framework itself loads shared libraries. `System.loadLibrary()` in Java (for framework/app interaction via JNI) or direct `dlopen()` calls in native code are key entry points.
* **NDK Connection:** How does the NDK enable developers to use native code and interact with Bionic?
* **Bionic's Role:** Emphasize that Bionic provides the core C library and the dynamic linker (`linker64`/`linker`).
* **Step-by-Step Breakdown:**  Trace the path from a framework call (e.g., `System.loadLibrary()`) down to the Bionic dynamic linker loading the `.so` and ultimately executing code within it.

**8. Frida Hooking:**

Demonstrate how Frida can be used to intercept and observe the relevant dynamic linking and TLS-related function calls. Provide concrete Frida script examples for functions like `dlopen`, `dlsym`, and potentially even internal Bionic functions related to TLS.

**Self-Correction/Refinement During the Process:**

* **Clarity and Precision:** Ensure the language used is clear and avoids ambiguity. Technical terms should be explained or used correctly.
* **Completeness:** Try to cover all the major aspects raised by the prompt. If a question is difficult to answer fully, acknowledge the limitations.
* **Accuracy:** Double-check technical details, especially function parameters and return values.
* **Organization:**  Structure the answer logically using headings and bullet points to improve readability.

By following this structured approach,  you can effectively analyze the given C++ test file and provide a comprehensive explanation that addresses all aspects of the prompt.
好的，我们来详细分析 `bionic/tests/elftls_dl_test.cpp` 这个文件。

**文件功能概览**

`elftls_dl_test.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是测试与动态链接器 (`dl`) 和线程本地存储 (`elftls`) 相关的各种场景。具体来说，它测试了：

* **使用 `dlopen` 加载共享库时，对 TLS 变量的访问和管理。**  这包括使用不同的 TLS 访问模型（如 Initial Exec，IE 和 Global Dynamic，GD）的情况。
* **`dlclose` 函数是否正确地重置和清理 TLS 变量。**
* **`dlsym` 函数是否能正确获取 TLS 变量的地址。**
* **`dladdr` 函数在 TLS 变量地址上的行为。**
* **`dl_iterate_phdr` 函数是否能正确枚举包含 TLS 段的共享库。**
* **处理对未定义的弱 TLS 符号的引用。**
* **在动态加载和卸载库的过程中，DTV（Dynamic Thread Vector）的大小管理。**

**与 Android 功能的关系及举例说明**

这个测试文件直接关系到 Android 操作系统中动态链接器和线程本地存储的关键功能，这些功能是应用程序和系统库正常运行的基础。

* **动态链接 (Dynamic Linking):** Android 系统广泛使用动态链接，使得应用程序可以按需加载和卸载共享库，节省内存并提高代码复用率。`dlopen`, `dlsym`, `dlclose` 等函数是动态链接的核心。例如，当一个应用需要使用某个系统服务时，可能会动态加载相应的服务库。
* **线程本地存储 (Thread-Local Storage, TLS):** TLS 允许每个线程拥有自己的全局变量副本，避免了多线程环境下的数据竞争问题。例如，某些库可能使用 TLS 来存储每个线程的错误码或者状态信息。

**具体举例：**

* **`TEST(elftls_dl, dlopen_shared_var_ie)`:**  这个测试模拟了 Android 中一种常见的模式，即某些库（例如，AddressSanitizer）在共享对象中使用 TLS IE 访问模型来访问主程序或其他预加载库中导出的特殊变量。这确保了即使在动态加载的情况下，这些工具也能正常工作。
* **`TEST(elftls_dl, dlclose_resets_values)`:**  这个测试确保了当一个动态库被卸载时，其 TLS 变量会被正确地重置。这对于避免不同库之间 TLS 变量的干扰至关重要。在 Android 系统中，插件化框架或者应用内的模块化功能都依赖于动态加载和卸载，需要确保资源和状态的隔离。

**每一个 libc 函数的功能及实现**

这里我们解释一下 `elftls_dl_test.cpp` 中涉及的 libc 函数：

* **`dlopen(const char *filename, int flag)`:**
    * **功能:**  加载指定的动态链接库 (`filename`) 到进程的地址空间。`flag` 参数指定了加载的方式（例如，`RTLD_LOCAL` 表示库的符号仅对当前进程可见，`RTLD_NOW` 表示立即解析所有未定义的符号）。
    * **实现:**  `dlopen` 的实现非常复杂，涉及到：
        1. **查找库文件:**  根据 `filename` 在系统路径中查找库文件。
        2. **读取 ELF 文件头:**  解析库文件的头部信息，包括程序头表和段头表。
        3. **内存映射:**  将库文件的各个段（如 `.text`, `.data`, `.bss`）映射到进程的地址空间。
        4. **符号解析和重定位:**  解析库文件中引用的外部符号，并根据重定位信息修改代码和数据中的地址。对于 TLS 相关的符号，动态链接器会进行特殊的处理，为该库分配 TLS 块，并更新 TLS 相关的结构。
        5. **执行初始化函数:**  执行库文件中的初始化函数 (`.init_array` 或 `DT_INIT`)。
        6. **维护内部数据结构:**  更新动态链接器的内部数据结构，记录已加载的库。

* **`dlsym(void *handle, const char *symbol)`:**
    * **功能:**  在由 `handle` 指定的动态链接库中查找名为 `symbol` 的符号的地址。`handle` 可以是 `dlopen` 的返回值，也可以是特殊值 `RTLD_DEFAULT` 或 `RTLD_NEXT`。
    * **实现:**
        1. **查找符号表:**  在指定库的符号表中查找与 `symbol` 匹配的条目。
        2. **处理重定位:**  如果找到符号，返回其在内存中的地址。对于需要重定位的符号（例如，全局变量或函数），返回的是重定位后的地址。对于 TLS 变量，返回的是该线程中该 TLS 变量的地址。

* **`dlclose(void *handle)`:**
    * **功能:**  卸载由 `handle` 指定的动态链接库。
    * **实现:**
        1. **执行析构函数:**  执行库文件中的析构函数 (`.fini_array` 或 `DT_FINI`)。
        2. **解除内存映射:**  将库文件映射的内存从进程的地址空间解除。
        3. **清理 TLS 数据:**  释放该库分配的 TLS 存储空间。这是测试文件中 `dlclose_resets_values` 和 `dlclose_removes_entry` 重点关注的部分。
        4. **更新内部数据结构:**  从动态链接器的内部数据结构中移除该库的记录。
        5. **处理依赖关系:**  如果其他库依赖于被卸载的库，`dlclose` 可能会失败，或者需要先卸载依赖库。

* **`dlerror()`:**
    * **功能:**  返回最近一次 `dlopen`, `dlsym`, 或 `dlclose` 调用失败的错误消息。
    * **实现:**  动态链接器内部维护一个线程局部的错误消息缓冲区。当上述函数失败时，会将错误信息写入该缓冲区。`dlerror` 只是简单地返回该缓冲区的指针。

* **`dladdr(const void *addr, Dl_info *info)`:**
    * **功能:**  尝试查找包含地址 `addr` 的动态链接库的信息，并将结果存储在 `Dl_info` 结构体中。
    * **实现:**
        1. **遍历已加载的库:**  动态链接器遍历当前进程中已加载的动态库列表。
        2. **地址匹配:**  对于每个库，检查 `addr` 是否落在该库的内存映射范围内。
        3. **填充 `Dl_info`:**  如果找到包含 `addr` 的库，则将库的路径、符号名（如果 `addr` 指向一个符号）、符号地址等信息填充到 `Dl_info` 结构体中。值得注意的是，对于 TLS 变量的地址，`dladdr` 通常无法找到对应的符号信息，因为 TLS 变量不是全局符号。

* **`dl_iterate_phdr(int (*callback)(struct dl_phdr_info *info, size_t size, void *data), void *data)`:**
    * **功能:**  遍历进程中所有已加载的动态库的程序头（Program Headers）。对于每个库，调用用户提供的回调函数 `callback`。
    * **实现:**
        1. **获取库列表:**  动态链接器维护着一个已加载库的列表。
        2. **遍历程序头:**  对于列表中的每个库，读取其 ELF 文件头，然后遍历其程序头表。
        3. **调用回调函数:**  对于每个库，将 `dl_phdr_info` 结构体（包含库的信息和程序头表）以及用户提供的 `data` 传递给回调函数。这个函数允许用户检查每个库的段信息，包括 TLS 段。

**涉及 dynamic linker 的功能，so 布局样本，以及链接的处理过程**

让我们以 `TEST(elftls_dl, dlopen_shared_var_ie)` 为例进行分析：

**涉及的库:**

* `libtest_elftls_shared_var.so`:  包含一个名为 `elftls_shared_var` 的全局 TLS 变量。
* `libtest_elftls_shared_var_ie.so`:  依赖于 `libtest_elftls_shared_var.so`，并使用 IE (Initial Exec) 模型访问 `elftls_shared_var`。主程序（测试程序本身）通过 `DT_NEEDED` 依赖 `libtest_elftls_shared_var.so`。

**SO 布局样本 (简化):**

**libtest_elftls_shared_var.so:**

```
ELF Header
...
Program Headers:
  PT_TLS: ... (描述 TLS 段)
...
.tdata (TLS 数据段):
  elftls_shared_var: ... (存储 elftls_shared_var 的空间)
...
Symbol Table:
  elftls_shared_var (TLS 符号, 可见性：默认)
```

**libtest_elftls_shared_var_ie.so:**

```
ELF Header
...
Dynamic Section:
  DT_NEEDED: libtest_elftls_shared_var.so
...
Relocation Section (.rela.dyn 或 .rela.plt):
  Type: R_AARCH64_TLS_TPOFF (或其他架构对应的 TLS 重定位类型)
  Offset: ... (引用 elftls_shared_var 的地址)
  Symbol: elftls_shared_var
```

**链接的处理过程:**

1. **加载 `libtest_elftls_shared_var.so`:**  由于测试程序通过 `DT_NEEDED` 依赖它，或者在 `dlopen("libtest_elftls_shared_var_ie.so", ...)` 之前已经被加载，动态链接器会先加载并初始化 `libtest_elftls_shared_var.so`。这包括分配 TLS 块，并初始化 `elftls_shared_var` 的值。

2. **加载 `libtest_elftls_shared_var_ie.so`:** 当 `dlopen("libtest_elftls_shared_var_ie.so", ...)` 被调用时，动态链接器会执行以下步骤：
   * **检查依赖:**  发现它依赖于 `libtest_elftls_shared_var.so`，并且该库已经被加载。
   * **处理 TLS 重定位:**  遇到对 `elftls_shared_var` 的 IE 访问时，动态链接器会查找 `libtest_elftls_shared_var.so` 的 TLS 模块 ID 和 `elftls_shared_var` 在其 TLS 块内的偏移量。
   * **生成 TLS 访问代码:**  对于 IE 访问，编译器通常会生成直接访问当前线程 TLS 区域的代码，偏移量在链接时确定。由于 `elftls_shared_var` 位于主程序或其依赖的库中，这种直接访问是允许的。

**假设输入与输出 (以 `TEST(elftls_dl, dlopen_shared_var_ie)` 为例):**

* **假设输入:**
    * 测试程序启动。
    * 调用 `dlopen("libtest_elftls_shared_var_ie.so", RTLD_LOCAL | RTLD_NOW)`。
* **预期输出:**
    * `dlopen` 调用成功，返回非空的库句柄。
    * `dlsym(lib, "bump_shared_var")` 调用成功，返回 `bump_shared_var` 函数的地址。
    * 对 `elftls_shared_var` 的操作（自增）会影响到该变量在当前线程中的副本。
    * 调用 `bump_shared_var()` 会修改 `libtest_elftls_shared_var.so` 中定义的共享 TLS 变量。
    * 在新线程中执行相同的操作也能正确访问和修改 TLS 变量。

**用户或编程常见的使用错误举例说明**

* **忘记 `dlclose` 加载的库:** 这会导致内存泄漏和资源浪费。

```c++
void* lib = dlopen("mylib.so", RTLD_NOW);
// ... 使用 lib 中的函数 ...
// 忘记 dlclose(lib);
```

* **在多线程环境下不正确地使用全局变量，应该使用 TLS 但没有使用:** 这会导致数据竞争和未定义的行为。

```c++
// 错误示例：使用全局变量而不是 TLS
int global_counter = 0;

void increment_counter() {
  global_counter++; // 多线程环境下可能出现竞争
}
```

应该使用 TLS：

```c++
// 正确示例：使用 TLS
__thread int thread_local_counter = 0;

void increment_counter() {
  thread_local_counter++; // 每个线程有自己的副本
}
```

* **尝试在未加载库的情况下使用 `dlsym`:** 这会导致 `dlsym` 返回 `nullptr`，如果不对返回值进行检查就使用，会导致程序崩溃。

```c++
void* lib = nullptr; // 假设库加载失败
auto func = (void(*)())dlsym(lib, "my_function");
if (func) {
  func(); // 如果 lib 为 nullptr，这里会崩溃
} else {
  // 处理符号查找失败的情况
}
```

* **在不兼容的 TLS 模型之间进行访问:** 例如，尝试使用 GD 访问由 IE 模型声明的变量，或者反之。这通常会在链接时或运行时导致错误。`TEST(elftls_dl, dlopen_ie_error)` 就是测试这种情况。

**Android framework 或 ndk 是如何一步步的到达这里**

1. **Android Framework (Java 层):**
   * 当 Android 应用需要加载 native 库时，通常会调用 `System.loadLibrary("mylib")`。
   * `System.loadLibrary` 最终会调用 `Runtime.getRuntime().loadLibrary0(String libName, ClassLoader classLoader)`。
   * `loadLibrary0` 涉及到查找库文件（根据库名和 ABI），并最终通过 JNI 调用到 native 代码。

2. **NDK (Native 开发):**
   * 使用 NDK 开发的 native 代码可以直接调用 `dlopen`, `dlsym`, `dlclose` 等动态链接相关的函数。
   * 例如，一个 native 模块可能需要动态加载另一个 native 库来实现插件化功能。

3. **Bionic (C 库和动态链接器):**
   * 无论是 Framework 还是 NDK，最终的动态库加载和符号解析都由 Bionic 的动态链接器 (`/system/bin/linker` 或 `/system/bin/linker64`) 完成。
   * 当 `dlopen` 被调用时，它会触发动态链接器的核心逻辑，如之前所述，包括查找、加载、重定位和初始化库。
   * TLS 变量的管理也是动态链接器的一部分。当加载包含 TLS 变量的库时，动态链接器会为当前线程分配相应的 TLS 存储空间，并进行初始化。

**Frida hook 示例调试这些步骤**

可以使用 Frida Hook 来观察 `dlopen`, `dlsym`, 和 TLS 相关的内部函数调用。

**示例 1: Hook `dlopen`**

```python
import frida
import sys

package_name = "your.app.package"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['message']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found. Please launch the app.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName(null, "dlopen"), {
  onEnter: function(args) {
    var filename = Memory.readUtf8String(args[0]);
    var flags = args[1].toInt();
    send({ tag: "dlopen", message: "Loading library: " + filename + ", flags: " + flags });
  },
  onLeave: function(retval) {
    send({ tag: "dlopen", message: "dlopen returned: " + retval });
  }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**示例 2: Hook `dlsym`**

```python
# ... (导入 frida 和定义 on_message，与上面相同)

script_code = """
Interceptor.attach(Module.findExportByName(null, "dlsym"), {
  onEnter: function(args) {
    var handle = args[0];
    var symbol = Memory.readUtf8String(args[1]);
    send({ tag: "dlsym", message: "Looking for symbol: " + symbol + " in handle: " + handle });
  },
  onLeave: function(retval) {
    send({ tag: "dlsym", message: "dlsym returned: " + retval });
  }
});
"""

# ... (创建 session 和加载 script，与上面相同)
```

**示例 3: 可能 Hook TLS 相关的 Bionic 内部函数 (更复杂，可能需要 root 权限和更深入的了解):**

可以尝试 Hook Bionic 中负责 TLS 管理的内部函数，例如 `__pthread_key_create`, `__get_tls`, 或者动态链接器中分配 TLS 块的函数。这些函数的符号可能不容易找到，需要查看 Bionic 的源码或使用更底层的调试技术。

```python
# 示例：尝试 Hook __get_tls (可能需要找到正确的模块和偏移)
# 这只是一个概念示例，实际操作可能更复杂
script_code = """
var bionicModule = Process.getModuleByName("libc.so"); // 或 "libc.so.64"
var getTlsAddress = bionicModule.getExportByName("__get_tls"); // 符号可能不同

if (getTlsAddress) {
  Interceptor.attach(getTlsAddress, {
    onEnter: function(args) {
      send({ tag: "__get_tls", message: "__get_tls called" });
    },
    onLeave: function(retval) {
      send({ tag: "__get_tls", message: "__get_tls returned: " + retval });
    }
  });
} else {
  send({ tag: "error", message: "__get_tls symbol not found" });
}
"""
# ... (创建 session 和加载 script)
```

**总结**

`bionic/tests/elftls_dl_test.cpp` 是一个关键的测试文件，用于验证 Android Bionic 库中动态链接器对 TLS 变量的管理和访问是否正确。通过分析这个文件，我们可以深入了解 Android 系统中动态链接和线程本地存储的工作原理，以及常见的编程错误和调试方法。

### 提示词
```
这是目录为bionic/tests/elftls_dl_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#include <dlfcn.h>
#include <link.h>

#include <gtest/gtest.h>

#include <string>
#include <thread>

#include "gtest_globals.h"
#include "platform/bionic/tls.h"
#include "utils.h"

#if defined(__BIONIC__)
#include "bionic/pthread_internal.h"
#endif

// Access libtest_elftls_shared_var.so's TLS variable using an IE access.
__attribute__((tls_model("initial-exec"))) extern "C" __thread int elftls_shared_var;

TEST(elftls_dl, dlopen_shared_var_ie) {
  // libtest_elftls_shared_var_ie.so can be dlopen'ed, even though it contains a
  // TLS IE access, because its IE access references a TLS variable from
  // libtest_elftls_shared_var.so, which is DT_NEEDED by the executable. This
  // pattern appears in sanitizers, which use TLS IE instrumentation in shared
  // objects to access special variables exported from the executable or from a
  // preloaded solib.
  void* lib = dlopen("libtest_elftls_shared_var_ie.so", RTLD_LOCAL | RTLD_NOW);
  ASSERT_NE(nullptr, lib);

  auto bump_shared_var = reinterpret_cast<int(*)()>(dlsym(lib, "bump_shared_var"));
  ASSERT_NE(nullptr, bump_shared_var);

  ASSERT_EQ(21, ++elftls_shared_var);
  ASSERT_EQ(22, bump_shared_var());

  std::thread([bump_shared_var] {
    ASSERT_EQ(21, ++elftls_shared_var);
    ASSERT_EQ(22, bump_shared_var());
  }).join();
}

TEST(elftls_dl, dlopen_ie_error) {
  std::string helper = GetTestLibRoot() + "/elftls_dlopen_ie_error_helper";
  std::string src_path = GetTestLibRoot() + "/libtest_elftls_shared_var_ie.so";
  std::string dst_path = GetTestLibRoot() + "/libtest_elftls_shared_var.so";
#if defined(__BIONIC__)
  std::string error =
      "dlerror: dlopen failed: TLS symbol \"elftls_shared_var\" in dlopened \"" + dst_path + "\" " +
      "referenced from \"" + src_path + "\" using IE access model\n";
#else
  // glibc will reserve some surplus static TLS memory, allowing this test to pass.
  std::string error = "success\n";
#endif

  ExecTestHelper eth;
  eth.SetArgs({ helper.c_str(), nullptr });
  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, error.c_str());
}

// Use a GD access (__tls_get_addr or TLSDESC) to modify a variable in static
// TLS memory.
TEST(elftls_dl, access_static_tls) {
  void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);
  ASSERT_NE(nullptr, lib);

  auto bump_shared_var = reinterpret_cast<int(*)()>(dlsym(lib, "bump_shared_var"));
  ASSERT_NE(nullptr, bump_shared_var);

  ASSERT_EQ(21, ++elftls_shared_var);
  ASSERT_EQ(22, bump_shared_var());

  std::thread([bump_shared_var] {
    ASSERT_EQ(21, ++elftls_shared_var);
    ASSERT_EQ(22, bump_shared_var());
  }).join();
}

TEST(elftls_dl, bump_local_vars) {
  void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);
  ASSERT_NE(nullptr, lib);

  auto get_local_var2 = reinterpret_cast<int(*)()>(dlsym(lib, "get_local_var2"));
  ASSERT_NE(nullptr, get_local_var2);

  auto get_local_var1 = reinterpret_cast<int(*)()>(dlsym(lib, "get_local_var1"));
  ASSERT_NE(nullptr, get_local_var1);

  auto get_local_var1_addr = reinterpret_cast<int*(*)()>(dlsym(lib, "get_local_var1_addr"));
  ASSERT_NE(nullptr, get_local_var1_addr);

  // Make sure subsequent accesses return the same pointer.
  ASSERT_EQ(get_local_var1_addr(), get_local_var1_addr());

  // Check the initial values are correct.
  ASSERT_EQ(25, get_local_var2());
  ASSERT_EQ(15, get_local_var1());

  auto bump_local_vars = reinterpret_cast<int(*)()>(dlsym(lib, "bump_local_vars"));
  ASSERT_NE(nullptr, bump_local_vars);

  ASSERT_EQ(42, bump_local_vars());
  std::thread([bump_local_vars] {
    ASSERT_EQ(42, bump_local_vars());
  }).join();
}

extern "C" int* missing_weak_tls_addr();

// The Bionic linker resolves a TPREL relocation to an unresolved weak TLS
// symbol to 0, which is added to the thread pointer. N.B.: A TPREL relocation
// in a static executable is resolved by the static linker instead, and static
// linker behavior varies (especially with bfd and gold). See
// https://bugs.llvm.org/show_bug.cgi?id=40570.
TEST(elftls_dl, tprel_missing_weak) {
  ASSERT_EQ(static_cast<void*>(__get_tls()), missing_weak_tls_addr());
  std::thread([] {
    ASSERT_EQ(static_cast<void*>(__get_tls()), missing_weak_tls_addr());
  }).join();
}

// The behavior of accessing an unresolved weak TLS symbol using a dynamic TLS
// relocation depends on which kind of implementation the target uses. With
// TLSDESC, the result is NULL. With __tls_get_addr, the result is the
// generation count (or maybe undefined behavior)? This test only tests TLSDESC.
TEST(elftls_dl, tlsdesc_missing_weak) {
#if defined(__aarch64__) || defined(__riscv)
  void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);
  ASSERT_NE(nullptr, lib);

  auto missing_weak_dyn_tls_addr = reinterpret_cast<int*(*)()>(dlsym(lib, "missing_weak_dyn_tls_addr"));
  ASSERT_NE(nullptr, missing_weak_dyn_tls_addr);

  ASSERT_EQ(nullptr, missing_weak_dyn_tls_addr());
  std::thread([missing_weak_dyn_tls_addr] {
    ASSERT_EQ(nullptr, missing_weak_dyn_tls_addr());
  }).join();
#else
  GTEST_SKIP() << "This test is only run on TLSDESC-based targets";
#endif
}

TEST(elftls_dl, dtv_resize) {
#if defined(__BIONIC__)
  std::string helper = GetTestLibRoot() + "/elftls_dtv_resize_helper";
  ExecTestHelper eth;
  eth.SetArgs({helper.c_str(), nullptr});
  eth.Run([&]() { execve(helper.c_str(), eth.GetArgs(), eth.GetEnv()); }, 0, nullptr);
#else
  GTEST_SKIP() << "test doesn't apply to glibc";
#endif
}

// Verify that variables are reset to their initial values after the library
// containing them is closed.
TEST(elftls_dl, dlclose_resets_values) {
  for (int round = 0; round < 2; ++round) {
    void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);
    ASSERT_NE(nullptr, lib);

    auto bump_local_vars = reinterpret_cast<int(*)()>(dlsym(lib, "bump_local_vars"));
    ASSERT_NE(nullptr, bump_local_vars);

    ASSERT_EQ(42, bump_local_vars());
    ASSERT_EQ(44, bump_local_vars());

    ASSERT_EQ(0, dlclose(lib));
  }
}

// Calling dlclose should remove the entry for the solib from the global list of
// ELF TLS modules. Test that repeatedly loading and unloading a library doesn't
// increase the DTV size.
TEST(elftls_dl, dlclose_removes_entry) {
#if defined(__BIONIC__)
  auto dtv = []() -> TlsDtv* { return __get_tcb_dtv(__get_bionic_tcb()); };

  bool first = true;
  size_t count = 0;

  // Use a large number of rounds in case the DTV is initially larger than
  // expected.
  for (int round = 0; round < 32; ++round) {
    void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);
    ASSERT_NE(nullptr, lib);

    auto bump_local_vars = reinterpret_cast<int(*)()>(dlsym(lib, "bump_local_vars"));
    ASSERT_NE(nullptr, bump_local_vars);

    ASSERT_EQ(42, bump_local_vars());
    if (first) {
      first = false;
      count = dtv()->count;
    } else {
      ASSERT_EQ(count, dtv()->count);
    }

    dlclose(lib);
  }
#else
  GTEST_SKIP() << "test doesn't apply to glibc";
#endif
}

// Use dlsym to get the address of a TLS variable in static TLS and compare it
// against the ordinary address of the variable.
TEST(elftls_dl, dlsym_static_tls) {
  void* lib = dlopen("libtest_elftls_shared_var.so", RTLD_LOCAL | RTLD_NOW);
  ASSERT_NE(nullptr, lib);

  int* var_addr = static_cast<int*>(dlsym(lib, "elftls_shared_var"));
  ASSERT_EQ(&elftls_shared_var, var_addr);

  std::thread([lib] {
    int* var_addr = static_cast<int*>(dlsym(lib, "elftls_shared_var"));
    ASSERT_EQ(&elftls_shared_var, var_addr);
  }).join();
}

// Use dlsym to get the address of a TLS variable in dynamic TLS and compare it
// against the ordinary address of the variable.
TEST(elftls_dl, dlsym_dynamic_tls) {
  void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);
  ASSERT_NE(nullptr, lib);
  auto get_var_addr = reinterpret_cast<int*(*)()>(dlsym(lib, "get_large_tls_var_addr"));
  ASSERT_NE(nullptr, get_var_addr);

  int* var_addr = static_cast<int*>(dlsym(lib, "large_tls_var"));
  ASSERT_EQ(get_var_addr(), var_addr);

  std::thread([lib, get_var_addr] {
    int* var_addr = static_cast<int*>(dlsym(lib, "large_tls_var"));
    ASSERT_EQ(get_var_addr(), var_addr);
  }).join();
}

// Calling dladdr on a TLS variable's address doesn't find anything.
TEST(elftls_dl, dladdr_on_tls_var) {
  Dl_info info;

  // Static TLS variable
  ASSERT_EQ(0, dladdr(&elftls_shared_var, &info));

  // Dynamic TLS variable
  void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);
  ASSERT_NE(nullptr, lib);
  int* var_addr = static_cast<int*>(dlsym(lib, "large_tls_var"));
  ASSERT_EQ(0, dladdr(var_addr, &info));
}

// Verify that dladdr does not misinterpret a TLS symbol's value as a virtual
// address.
TEST(elftls_dl, dladdr_skip_tls_symbol) {
  void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);

  auto get_local_addr = reinterpret_cast<void*(*)()>(dlsym(lib, "get_local_addr"));
  ASSERT_NE(nullptr, get_local_addr);
  void* local_addr = get_local_addr();

  Dl_info info;
  ASSERT_NE(0, dladdr(local_addr, &info));

  std::string libpath = GetTestLibRoot() + "/libtest_elftls_dynamic.so";
  char dli_realpath[PATH_MAX];
  ASSERT_TRUE(realpath(info.dli_fname, dli_realpath));
  ASSERT_STREQ(libpath.c_str(), dli_realpath);
  ASSERT_STREQ(nullptr, info.dli_sname);
  ASSERT_EQ(nullptr, info.dli_saddr);
}

TEST(elftls_dl, dl_iterate_phdr) {
  void* lib = dlopen("libtest_elftls_dynamic.so", RTLD_LOCAL | RTLD_NOW);

  auto get_var_addr = reinterpret_cast<void*(*)()>(dlsym(lib, "get_large_tls_var_addr"));
  ASSERT_NE(nullptr, get_var_addr);

  struct TlsInfo {
    bool found;
    size_t modid;
    void* data;
    size_t memsz;
  };

  auto get_tls_info = []() {
    auto callback = [](dl_phdr_info* info, size_t, void* data) {
      TlsInfo& tls_info = *static_cast<TlsInfo*>(data);

      // This test is also run with glibc, where dlpi_name may have relative path components, so
      // examine just the basename when searching for the library.
      if (strcmp(android::base::Basename(info->dlpi_name).c_str(), "libtest_elftls_dynamic.so") != 0) return 0;

      tls_info.found = true;
      tls_info.modid = info->dlpi_tls_modid;
      tls_info.data = info->dlpi_tls_data;
      for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        if (info->dlpi_phdr[i].p_type == PT_TLS) {
          tls_info.memsz = info->dlpi_phdr[i].p_memsz;
        }
      }
      EXPECT_NE(static_cast<size_t>(0), tls_info.memsz);
      return 1;
    };

    TlsInfo result {};
    dl_iterate_phdr(callback, &result);
    return result;
  };

  // The executable has a TLS segment, so it will use module ID #1, and the DSO's ID will be larger
  // than 1. Initially, the data field is nullptr, because this thread's instance hasn't been
  // allocated yet.
  TlsInfo tls_info = get_tls_info();
  ASSERT_TRUE(tls_info.found);
  ASSERT_GT(tls_info.modid, static_cast<size_t>(1));
  ASSERT_EQ(nullptr, tls_info.data);

  void* var_addr = get_var_addr();

  // Verify that dl_iterate_phdr returns a range of memory covering the allocated TLS variable.
  tls_info = get_tls_info();
  ASSERT_TRUE(tls_info.found);
  ASSERT_GE(var_addr, tls_info.data);
  ASSERT_LT(var_addr, static_cast<char*>(tls_info.data) + tls_info.memsz);
}
```