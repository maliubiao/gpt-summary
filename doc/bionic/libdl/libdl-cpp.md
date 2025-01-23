Response:
Let's break down the thought process for generating the detailed response to the user's request.

**1. Understanding the Core Request:**

The fundamental request is to analyze the `bionic/libdl/libdl.cpp` source code. The user wants to understand its functions, its relationship to Android, implementation details, dynamic linking aspects, error scenarios, and how to debug it. The request emphasizes clarity and examples.

**2. Initial Scoping and Keyword Extraction:**

Immediately, I identify the key areas to address:

* **Functions:** What functions are defined in this file?
* **Purpose:** What is the overall goal of `libdl.cpp`?
* **Android Integration:** How do these functions relate to the broader Android system?
* **Implementation Details:**  How are these functions actually implemented?  (Crucially, the code uses `__loader_*` functions, which points to the dynamic linker's role).
* **Dynamic Linking:**  This is a major theme, so focusing on `dlopen`, `dlsym`, `dlclose`, and the interaction with the dynamic linker is essential.
* **Error Handling:** What common mistakes do developers make when using these functions?
* **Debugging:** How can Frida be used to inspect the execution of this code?
* **Structure:** Organize the response logically, covering each aspect thoroughly.

**3. Analyzing the Code (Function by Function):**

I go through the code block by block, identifying each defined function. The `__attribute__((__weak__))` is a crucial indicator. It signifies that these are *weak* symbols, likely providing default implementations or proxies to the *actual* implementations in the dynamic linker.

* **`__loader_*` functions:**  These are clearly placeholders or interfaces to the dynamic linker. I note their purpose based on their names (e.g., `__loader_dlopen`, `__loader_dlsym`). The "TODO" comment is also important – it highlights that these are temporary and should eventually be replaced by direct libc calls.
* **`android_get_LD_LIBRARY_PATH`, `dlopen`, `dlerror`, etc.:** These are the standard POSIX `dlfcn.h` functions and Android-specific extensions. I recognize their standard meanings. The `caller_addr` parameter being passed to the `__loader_*` functions is significant – it's used for security and context.
* **`dl_iterate_phdr`:**  I understand its purpose in iterating through loaded shared libraries' headers.
* **`android_dlopen_ext`:**  This is an Android-specific extension providing more control over the loading process.
* **`android_get_application_target_sdk_version`:**  This function is related to compatibility and API levels.
* **`android_handle_signal`:**  This function deals with signal handling, potentially related to crash reporting or debugging.

**4. Connecting to Android:**

The file is explicitly part of Android's Bionic library. The functions provided are fundamental to how Android applications and the system load and use shared libraries. I connect the functions to key Android concepts:

* **Shared Libraries (.so files):** `dlopen`, `dlsym`, `dlclose` are the core mechanisms for interacting with these.
* **`LD_LIBRARY_PATH`:**  This environment variable is crucial for locating shared libraries.
* **SDK Version:** The `android_get_application_target_sdk_version` function highlights the importance of compatibility in Android.
* **Signal Handling:**  The `android_handle_signal` function relates to Android's robust error handling and debugging mechanisms.

**5. Explaining Implementations (The Proxy Pattern):**

The key insight here is that `libdl.cpp` acts as a *proxy*. The functions in this file don't *do* the actual work of dynamic linking. They forward the requests to the *dynamic linker* itself. This is why the `__loader_*` functions are crucial. I emphasize this proxy pattern in the explanation.

**6. Dynamic Linking Details (SO Layout and Linking Process):**

This is a complex area. I break it down:

* **SO Layout:** I describe the typical structure of a shared object file, focusing on the sections relevant to dynamic linking (ELF header, program headers, `.dynsym`, `.dynstr`, `.rel.plt`, `.rel.dyn`).
* **Linking Process:** I outline the steps involved in resolving symbols at runtime: locating libraries, symbol lookup, relocation.

**7. Error Scenarios:**

I think about common mistakes developers make:

* **Incorrect Path:**  Problems with `LD_LIBRARY_PATH` or missing libraries.
* **Symbol Not Found:**  Trying to access a non-existent symbol.
* **Version Issues:** Conflicts between different versions of libraries.
* **Memory Leaks:** Forgetting to `dlclose` handles.
* **Incorrect Flags:**  Using the wrong flags with `dlopen`.

**8. Debugging with Frida:**

I provide concrete Frida examples for hooking `dlopen`, `dlsym`, and `dlclose`. This demonstrates how to intercept these function calls and inspect their arguments and return values. I explain the purpose of each Frida snippet.

**9. Structure and Language:**

I organize the response into clear sections with headings. I use precise technical language but also provide explanations and examples to make it accessible. I adhere to the request for a Chinese response.

**Pre-computation and Pre-analysis (Implicit):**

Even before writing, I have a general understanding of how dynamic linking works, the roles of `dlopen`, `dlsym`, `dlclose`, and the structure of ELF files. This pre-existing knowledge allows me to interpret the code and generate the explanation effectively.

**Self-Correction/Refinement:**

During the writing process, I might reread sections of the code or my explanation to ensure accuracy and clarity. For example, I would double-check the parameters passed to the `__loader_*` functions and their corresponding `dlfcn.h` counterparts. I would also ensure the Frida examples are correct and easy to understand.

By following these steps, I can generate a comprehensive and accurate response that addresses all aspects of the user's request.
好的，我们来详细分析一下 `bionic/libdl/libdl.cpp` 这个文件。

**功能概述**

`bionic/libdl/libdl.cpp` 文件是 Android Bionic 库中 `libdl` 库的源代码。`libdl` 库提供了动态链接器 (dynamic linker) 的接口，允许程序在运行时加载和管理共享库 (`.so` 文件)。 它的主要功能包括：

1. **加载共享库 (`dlopen`)**:  允许程序在运行时动态加载指定的共享库。
2. **查找符号 (`dlsym`, `dlvsym`)**:  允许程序在已加载的共享库中查找指定的符号（函数或变量）。
3. **错误报告 (`dlerror`)**:  提供获取最近一次动态链接操作失败原因的机制。
4. **卸载共享库 (`dlclose`)**:  允许程序卸载之前动态加载的共享库。
5. **获取共享库信息 (`dladdr`)**:  允许程序获取给定地址所属的共享库和符号的信息。
6. **遍历已加载的共享库 (`dl_iterate_phdr`)**:  允许程序遍历当前进程中已加载的所有共享库的程序头信息。
7. **获取和更新库搜索路径 (`android_get_LD_LIBRARY_PATH`, `android_update_LD_LIBRARY_PATH`)**:  提供访问和修改共享库搜索路径的 Android 特定接口。
8. **高级加载选项 (`android_dlopen_ext`)**:  提供带额外参数的 Android 特定动态库加载接口。
9. **获取目标 SDK 版本 (`android_get_application_target_sdk_version`)**: 提供获取当前应用程序目标 SDK 版本的接口。
10. **处理信号 (`android_handle_signal`)**:  提供一个用于处理特定信号的 Android 特定接口，通常用于处理来自 GWP-ASan 等内存安全工具的信号。

**与 Android 功能的关系和举例说明**

`libdl` 库在 Android 系统中扮演着至关重要的角色，几乎所有的 Android 应用和系统服务都会用到它。

* **应用启动和运行:** 当一个 Android 应用启动时，其主可执行文件以及依赖的各种 `.so` 文件都需要被加载到内存中。`libdl` 提供的 `dlopen` 和相关函数是完成这个过程的核心。例如，当一个 Java 应用需要调用 Native 代码时，Android Framework 会使用 `dlopen` 加载包含 Native 代码的 `.so` 文件。

   **例子:**  假设一个应用使用了 OpenCV 库来进行图像处理。OpenCV 库会被编译成 `.so` 文件。在应用运行时，可能在第一次需要使用 OpenCV 功能时，或者在应用启动时，系统会调用 `dlopen("libopencv_java4.so", RTLD_NOW)` 来加载 OpenCV 库。

* **Framework 和 NDK 开发:** Android Framework 的许多组件以及 NDK (Native Development Kit) 开发的 Native 库都依赖 `libdl`。 Framework 使用它来加载各种系统服务和模块，NDK 开发人员可以使用 `dlfcn.h` 头文件中声明的函数来动态加载和使用其他 Native 库。

   **例子:**  Android Framework 中的 `SystemServer` 进程会使用 `dlopen` 加载各种系统服务，例如 `WindowManagerService` 或 `ActivityManagerService`。这些服务通常被编译成 `.so` 文件。

* **插件化和模块化:**  动态加载机制使得 Android 系统和应用可以实现插件化和模块化架构。应用或系统组件可以在运行时根据需要加载不同的模块，从而提高灵活性和可扩展性。

   **例子:**  一个音乐播放器应用可能在需要播放特定格式的音频文件时，动态加载相应的解码器 `.so` 文件。

* **热修复和动态更新:** 动态加载技术也常用于实现应用的热修复和动态更新。通过动态加载新的代码模块来替换旧的模块，可以在不重启应用的情况下修复 Bug 或更新功能。

**libc 函数的实现细节**

在 `libdl.cpp` 中，你会发现标准 POSIX `dlfcn.h` 中定义的函数 (如 `dlopen`, `dlsym`, `dlclose` 等) 的实现，但这些实现实际上是对以 `__loader_` 为前缀的函数的简单封装调用。

例如，`dlopen` 函数的实现如下：

```c++
__attribute__((__weak__))
void* dlopen(const char* filename, int flag) {
  const void* caller_addr = __builtin_return_address(0);
  return __loader_dlopen(filename, flag, caller_addr);
}
```

这表明 `libdl.cpp` 并没有实际实现 `dlopen` 的核心逻辑，而是将调用委托给了名为 `__loader_dlopen` 的函数。这些 `__loader_` 函数是由 **动态链接器 (linker)** 本身实现的。

**动态链接器的工作流程:**

1. 当程序调用 `dlopen` 时，`libdl.so` 中的 `dlopen` 函数会被调用。
2. `dlopen` 函数内部会将请求转发给动态链接器的 `__loader_dlopen` 函数。
3. 动态链接器接收到请求后，会执行以下步骤：
   * **查找共享库:** 根据传入的文件名和 `LD_LIBRARY_PATH` 环境变量查找对应的 `.so` 文件。
   * **加载共享库:** 将 `.so` 文件加载到进程的内存空间。这包括映射各个段 (如 `.text`, `.data`, `.bss`) 到内存。
   * **符号解析 (Symbol Resolution):** 遍历新加载的共享库的动态符号表 (`.dynsym`)，并根据其依赖关系解析未定义的符号。这可能涉及到加载其他的共享库。
   * **重定位 (Relocation):**  修改代码和数据中的地址引用，使其指向正确的内存位置。这是因为共享库被加载到哪个内存地址是运行时决定的。
   * **执行初始化代码:**  如果共享库有初始化函数 (通常在 `.init` 或 `.ctors` 段中)，动态链接器会执行这些函数。
4. `__loader_dlopen` 返回共享库的句柄 (一个指向内部数据结构的指针)，`dlopen` 函数再将这个句柄返回给调用者。

**涉及 Dynamic Linker 的功能**

`libdl.cpp` 中大部分函数都直接或间接地与动态链接器相关。以下是一些关键函数及其与动态链接器的交互：

* **`dlopen(filename, flag)`:**  指示动态链接器加载指定的共享库。`flag` 参数控制加载的方式（例如，`RTLD_LAZY` 表示延迟符号解析，`RTLD_NOW` 表示立即解析所有符号）。
* **`dlsym(handle, symbol)`:**  指示动态链接器在由 `handle` 指定的共享库中查找名为 `symbol` 的符号。
* **`dlclose(handle)`:**  指示动态链接器卸载由 `handle` 指定的共享库，并清理相关的资源。
* **`dladdr(addr, info)`:**  指示动态链接器查找包含给定地址 `addr` 的共享库和符号信息。
* **`dl_iterate_phdr(callback, data)`:**  指示动态链接器遍历当前进程中所有已加载的共享库的程序头信息，并将信息传递给回调函数 `callback`。

**SO 布局样本**

一个典型的 Android `.so` (Shared Object) 文件的布局大致如下（这是一个简化的视图）：

```
ELF Header:
  Magic number, class, endianness, version, OS/ABI, ...
Program Headers:
  Describes segments (loadable regions) like text, data, etc.
Section Headers:
  Detailed information about sections (e.g., .text, .data, .symtab, .strtab, .rel.dyn, .rel.plt)

.text:          可执行代码段
.rodata:        只读数据段 (例如，字符串常量)
.data:          已初始化的可写数据段
.bss:           未初始化的可写数据段
.symtab:        符号表 (包含程序中定义的和引用的符号)
.strtab:        字符串表 (存储符号名称等字符串)
.dynsym:        动态符号表 (用于动态链接的符号)
.dynstr:        动态字符串表 (用于动态链接的字符串)
.plt:           过程链接表 (用于延迟绑定)
.got.plt:       全局偏移量表 (用于存放外部符号的地址)
.rel.dyn:       动态重定位表 (用于重定位数据段)
.rel.plt:       过程链接表重定位表 (用于重定位函数调用)
... 其他段 ...
```

**链接的处理过程**

当动态链接器处理链接时，主要涉及以下步骤：

1. **加载共享库:** 如前所述，将 `.so` 文件映射到内存。
2. **符号查找:**
   * 当调用 `dlsym` 时，动态链接器会在指定的共享库的 `.dynsym` (动态符号表) 中查找匹配的符号名称。
   * 如果符号未找到，`dlsym` 返回 `NULL`。
3. **符号解析和重定位:**
   * 当加载共享库时，或者在首次调用一个外部函数时（对于延迟绑定），动态链接器需要解析符号的地址。
   * 动态链接器会查看 `.rel.dyn` 和 `.rel.plt` 重定位表，这些表描述了需要修改的代码和数据的位置以及需要引用的符号。
   * 对于每个需要重定位的项，动态链接器会找到对应符号的地址，并将该地址写入到代码或数据段的相应位置。
   * **GOT (Global Offset Table):**  对于函数调用，通常会使用 GOT 和 PLT (Procedure Linkage Table)。第一次调用外部函数时，PLT 中的代码会调用动态链接器来解析符号并将其地址填入 GOT。后续的调用会直接通过 GOT 获取地址，避免重复解析。

**假设输入与输出 (逻辑推理)**

假设我们有以下情况：

* 一个应用程序 `my_app` 依赖于一个共享库 `libmylib.so`，其中定义了一个函数 `my_function`.
* `libmylib.so` 位于 `/data/local/tmp`.

**假设输入:**

```c++
// 在 my_app 的代码中
void* handle = dlopen("/data/local/tmp/libmylib.so", RTLD_NOW);
if (handle == nullptr) {
  // 处理 dlopen 失败的情况
  const char* error = dlerror();
  // ...
}

typedef void (*MyFunctionType)();
MyFunctionType myFunctionPtr = (MyFunctionType)dlsym(handle, "my_function");
if (myFunctionPtr != nullptr) {
  myFunctionPtr(); // 调用 libmylib.so 中的 my_function
} else {
  // 处理 dlsym 失败的情况
  const char* error = dlerror();
  // ...
}

dlclose(handle);
```

**预期输出:**

* 如果 `/data/local/tmp/libmylib.so` 存在且格式正确，`dlopen` 将返回一个非空的句柄 `handle`。
* `dlsym` 将在 `libmylib.so` 中找到 `my_function` 符号，并返回其地址。`myFunctionPtr` 将指向 `my_function` 的入口点。
* 调用 `myFunctionPtr()` 将执行 `libmylib.so` 中 `my_function` 的代码。
* `dlclose(handle)` 将卸载 `libmylib.so`。

**假设输入与输出 (错误情况):**

* **假设输入:**  `dlopen("non_existent_library.so", RTLD_NOW)`
* **预期输出:** `dlopen` 返回 `nullptr`，`dlerror()` 返回一个描述错误的字符串，例如 "cannot open shared object file: No such file or directory"。

* **假设输入:**  `dlsym(handle, "non_existent_function")` (假设 `handle` 是一个有效的库句柄)
* **预期输出:** `dlsym` 返回 `nullptr`，`dlerror()` 返回一个描述错误的字符串，例如 "undefined symbol"。

**用户或编程常见的使用错误**

1. **忘记检查 `dlopen` 和 `dlsym` 的返回值:**  如果 `dlopen` 或 `dlsym` 失败，它们会返回 `nullptr`。不检查返回值会导致程序崩溃或行为异常。

   ```c++
   void* handle = dlopen("mylib.so", RTLD_NOW); // 缺少错误检查
   void (*func)() = (void(*)())dlsym(handle, "my_function"); // 如果 handle 为空，这里会崩溃
   func();
   ```

2. **`dlopen` 时使用了错误的路径或文件名:**  动态链接器找不到指定的共享库。

   ```c++
   void* handle = dlopen("wrong_name.so", RTLD_NOW); // 文件名错误
   if (!handle) {
       printf("Error: %s\n", dlerror());
   }
   ```

3. **尝试在未加载的库上使用 `dlsym`:**  必须先使用 `dlopen` 加载库，才能使用 `dlsym` 查找符号。

   ```c++
   void* handle = nullptr; // 忘记 dlopen
   void (*func)() = (void(*)())dlsym(handle, "my_function"); // handle 为空，会导致错误
   ```

4. **内存泄漏:**  使用 `dlopen` 加载了库，但在不再需要时忘记使用 `dlclose` 卸载，可能导致内存泄漏。

   ```c++
   void* handle = dlopen("mylib.so", RTLD_NOW);
   // ... 使用库 ...
   // 忘记 dlclose(handle);
   ```

5. **符号版本冲突:**  当加载的多个库定义了相同名称但不同版本的符号时，可能会发生冲突。可以使用 `dlvsym` 来指定要查找的符号的版本，或者使用链接器版本脚本来管理符号的版本。

6. **在错误的线程中使用 `dlopen`/`dlclose`:**  虽然 `dlopen` 和 `dlclose` 通常是线程安全的，但在某些情况下，例如在信号处理程序中调用它们可能存在风险。

**Android Framework 或 NDK 如何到达这里**

让我们以一个简单的 NDK 应用为例，说明调用 `dlopen` 的过程：

1. **Java 代码调用 Native 方法:**  在 Android 应用的 Java 代码中，通过 `System.loadLibrary("mylib")` 加载 Native 库。

   ```java
   // MainActivity.java
   static {
       System.loadLibrary("mylib");
   }

   private native void helloFromNative();

   public void onCreate(Bundle savedInstanceState) {
       super.onCreate(savedInstanceState);
       helloFromNative();
   }
   ```

2. **`System.loadLibrary` 的实现:**  `System.loadLibrary` 最终会调用到 Android Runtime (ART) 或 Dalvik 中的相关函数，这些函数会处理库的加载。

3. **ART/Dalvik 调用 `android_dlopen_ext`:**  ART 或 Dalvik 内部会调用 Bionic 库提供的 `android_dlopen_ext` 函数来加载 Native 库。`android_dlopen_ext` 是 `libdl.so` 中提供的 Android 扩展。

4. **`android_dlopen_ext` 调用 `__loader_android_dlopen_ext`:**  `libdl.cpp` 中的 `android_dlopen_ext` 函数会将调用转发给动态链接器的 `__loader_android_dlopen_ext` 函数。

5. **动态链接器执行加载过程:**  动态链接器根据传入的库名，查找、加载和链接 `libmylib.so`。

6. **Native 方法的执行:**  一旦库加载成功，Java 代码就可以调用 `helloFromNative` 方法，该方法的实现位于 `libmylib.so` 中。

**Frida Hook 示例**

可以使用 Frida 来 hook `dlopen` 函数，观察其参数和返回值。

```python
# frida 脚本
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libdl.so", "dlopen"), {
    onEnter: function(args) {
        var filename = Memory.readUtf8String(args[0]);
        var flag = args[1].toInt();
        console.log("[dlopen] filename: " + filename);
        console.log("[dlopen] flag: " + flag.toString(16));
        this.filename = filename;
    },
    onLeave: function(retval) {
        console.log("[dlopen] returned: " + retval);
        if (retval.isNull()) {
            console.log("[dlopen] Error: " + Memory.readUtf8String(Module.findExportByName("libdl.so", "dlerror")()));
        }
    }
});

Interceptor.attach(Module.findExportByName("libdl.so", "dlsym"), {
    onEnter: function(args) {
        var handle = args[0];
        var symbol = Memory.readUtf8String(args[1]);
        console.log("[dlsym] handle: " + handle);
        console.log("[dlsym] symbol: " + symbol);
        this.symbol = symbol;
    },
    onLeave: function(retval) {
        console.log("[dlsym] returned: " + retval);
        if (retval.isNull()) {
            console.log("[dlsym] Error: " + Memory.readUtf8String(Module.findExportByName("libdl.so", "dlerror")()));
        }
    }
});

Interceptor.attach(Module.findExportByName("libdl.so", "dlclose"), {
    onEnter: function(args) {
        var handle = args[0];
        console.log("[dlclose] handle: " + handle);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
session.detach()
```

**使用方法:**

1. 将上述 Python 代码保存为 `dl_hook.py`。
2. 替换 `package_name` 为你要调试的 Android 应用的包名。
3. 确保你的 Android 设备已连接并通过 USB 调试。
4. 运行 Frida 服务 (`frida-server`) 在 Android 设备上。
5. 在你的 PC 上运行 `python dl_hook.py`。
6. 运行目标 Android 应用。

**输出示例:**

当你运行应用时，Frida 脚本会拦截对 `dlopen`, `dlsym`, 和 `dlclose` 的调用，并在控制台上打印相关信息，例如：

```
[*] [dlopen] filename: /system/lib64/libbinder.so
[*] [dlopen] flag: 1
[*] [dlopen] returned: [object Object]
[*] [dlsym] handle: [object Object]
[*] [dlsym] symbol: android_os_BinderProxy_transact
[*] [dlsym] returned: [object Object]
[*] [dlclose] handle: [object Object]
...
```

这个 Frida 示例可以帮助你跟踪 Android 应用加载了哪些共享库，以及在这些库中查找了哪些符号，从而深入了解动态链接的过程。

希望以上详细的解释能够帮助你理解 `bionic/libdl/libdl.cpp` 的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libdl/libdl.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2007 The Android Open Source Project
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

#include <android/dlext.h>
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <stdlib.h>

// These functions are exported by the loader
// TODO(dimitry): replace these with reference to libc.so

extern "C" {

__attribute__((__weak__, visibility("default")))
void __loader_android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size);

__attribute__((__weak__, visibility("default")))
void* __loader_dlopen(const char* filename, int flags, const void* caller_addr);

__attribute__((__weak__, visibility("default")))
char* __loader_dlerror();

__attribute__((__weak__, visibility("default")))
void* __loader_dlsym(void* handle, const char* symbol, const void* caller_addr);

__attribute__((__weak__, visibility("default")))
void* __loader_dlvsym(void* handle,
                      const char* symbol,
                      const char* version,
                      const void* caller_addr);

__attribute__((__weak__, visibility("default")))
int __loader_dladdr(const void* addr, Dl_info* info);

__attribute__((__weak__, visibility("default")))
int __loader_dlclose(void* handle);

#if defined(__arm__)
__attribute__((__weak__, visibility("default")))
_Unwind_Ptr __loader_dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount);
#endif

__attribute__((__weak__, visibility("default")))
int __loader_dl_iterate_phdr(int (*cb)(struct dl_phdr_info* info, size_t size, void* data),
                             void* data);

__attribute__((__weak__, visibility("default")))
void __loader_android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size);

__attribute__((__weak__, visibility("default")))
void __loader_android_update_LD_LIBRARY_PATH(const char* ld_library_path);

__attribute__((__weak__, visibility("default")))
void* __loader_android_dlopen_ext(const char* filename,
                                  int flag,
                                  const android_dlextinfo* extinfo,
                                  const void* caller_addr);

__attribute__((__weak__, visibility("default")))
int __loader_android_get_application_target_sdk_version();

__attribute__((__weak__, visibility("default"))) bool __loader_android_handle_signal(
    int signal_number, siginfo_t* info, void* context);

// Proxy calls to bionic loader
__attribute__((__weak__))
void android_get_LD_LIBRARY_PATH(char* buffer, size_t buffer_size) {
  __loader_android_get_LD_LIBRARY_PATH(buffer, buffer_size);
}

__attribute__((__weak__))
void* dlopen(const char* filename, int flag) {
  const void* caller_addr = __builtin_return_address(0);
  return __loader_dlopen(filename, flag, caller_addr);
}

__attribute__((__weak__))
char* dlerror() {
  return __loader_dlerror();
}

__attribute__((__weak__))
void* dlsym(void* handle, const char* symbol) {
  const void* caller_addr = __builtin_return_address(0);
  return __loader_dlsym(handle, symbol, caller_addr);
}

__attribute__((__weak__))
void* dlvsym(void* handle, const char* symbol, const char* version) {
  const void* caller_addr = __builtin_return_address(0);
  return __loader_dlvsym(handle, symbol, version, caller_addr);
}

__attribute__((__weak__))
int dladdr(const void* addr, Dl_info* info) {
  return __loader_dladdr(addr, info);
}

__attribute__((__weak__))
int dlclose(void* handle) {
  return __loader_dlclose(handle);
}

#if defined(__arm__)
__attribute__((__weak__))
_Unwind_Ptr dl_unwind_find_exidx(_Unwind_Ptr pc, int* pcount) {
  return __loader_dl_unwind_find_exidx(pc, pcount);
}
#endif

/*
 * This needs to be defined as weak because it is also defined in libc.a.
 * Without this, static executables will have a multiple definition error.
 */
__attribute__((__weak__))
int dl_iterate_phdr(int (*cb)(struct dl_phdr_info* info, size_t size, void* data), void* data) {
  return __loader_dl_iterate_phdr(cb, data);
}

__attribute__((__weak__))
void* android_dlopen_ext(const char* filename, int flag, const android_dlextinfo* extinfo) {
  const void* caller_addr = __builtin_return_address(0);
  return __loader_android_dlopen_ext(filename, flag, extinfo, caller_addr);
}

__attribute__((__weak__))
int android_get_application_target_sdk_version() {
  return __loader_android_get_application_target_sdk_version();
}

// Returns true if this function handled the signal, false if the caller should handle the signal
// itself. This function returns true if the sigchain handler should immediately return, which
// happens when the signal came from GWP-ASan, and we've dumped a debuggerd report and patched up
// the GWP-ASan allocator to recover from the fault, and regular execution of the program can
// continue.
__attribute__((__weak__)) bool android_handle_signal(int signal_number, siginfo_t* info,
                                                     void* context) {
  return __loader_android_handle_signal(signal_number, info, context);
}

} // extern "C"
```