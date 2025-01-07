Response:
Let's break down the thought process for generating the detailed explanation of `linker_logger.cpp`.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of the given C++ code. Key requirements include:

* **Functionality:** What does this code do?
* **Relationship to Android:** How does it tie into Android's workings?
* **libc Function Explanations:** Detailed explanations of used libc functions.
* **Dynamic Linker Functionality:**  Explanation of relevant dynamic linking concepts, including SO layout and the linking process.
* **Logic Reasoning:**  If there's logic, illustrate with examples.
* **Common Errors:** Point out potential user/programming errors.
* **Android Framework/NDK Path:** Trace how execution reaches this code.
* **Frida Hooking:** Provide examples of how to debug with Frida.

**2. Initial Code Scan and Keyword Identification:**

The first step is to read through the code and identify key elements:

* **Includes:** `<string.h>`, `<sys/prctl.h>`, `<unistd.h>`, `<string>`, `<vector>`, `<async_safe/log.h>`, `"android-base/strings.h"`, `"private/CachedProperty.h"`, `"linker_logger.h"`. These headers suggest interaction with system calls, string manipulation, logging, and properties.
* **Global Variable:** `LinkerLogger g_linker_logger;`. This indicates a singleton-like pattern for managing logging.
* **Static Functions:** `ParseProperty`, `GetAppSpecificProperty`. These are helper functions, likely for parsing configuration.
* **Member Functions:** `ResetState`, `Log`. These are the core functionalities of the `LinkerLogger` class.
* **Constants:** `kLogErrors`, `kLogDlopen`, `kLogDlsym`. These suggest different logging levels or categories.
* **Property Names:** `"debug.ld.all"`, `"debug.ld.app."`. This immediately highlights the reliance on Android system properties for configuration.

**3. Deconstructing Function by Function:**

Now, go through each function and analyze its purpose and implementation:

* **`ParseProperty(const std::string& value)`:**
    * **Input:** A string representing comma-separated logging options.
    * **Logic:** Splits the string, checks for known options ("dlerror", "dlopen", "dlsym"), and sets corresponding flags. Includes a warning for unknown options.
    * **Output:** A `uint32_t` representing the combined flags.

* **`GetAppSpecificProperty(char* buffer)`:**
    * **Purpose:**  Get the application-specific debug property.
    * **Logic:**
        * Extracts the process name from `g_argv[0]` using `basename`.
        * Handles the case of service names (with a colon).
        * Constructs the property name `"debug.ld.app." + process_name`.
        * Uses `__system_property_get` to retrieve the property value.
    * **Key Observation:** This function depends on `g_argv` being initialized, which usually happens during process startup.

* **`LinkerLogger::ResetState()`:**
    * **Purpose:**  Initialize or refresh the logging state.
    * **Logic:**
        * Checks if the process is dumpable using `prctl(PR_GET_DUMPABLE)`. If not, logging might be disabled by default.
        * Reads the global property `"debug.ld.all"` using `CachedProperty`.
        * Reads the application-specific property using `GetAppSpecificProperty`.
        * Combines the flags from both properties.
    * **Important Detail:** The use of `CachedProperty` suggests optimization by caching the property value. The check for `g_argv` being valid is crucial for preventing crashes.

* **`LinkerLogger::Log(const char* format, ...)`:**
    * **Purpose:** The actual logging function.
    * **Logic:** Uses `async_safe_format_log_va_list` to perform thread-safe logging with variable arguments.

**4. Connecting to Android Concepts:**

At this point, it's important to link the code's functionality to Android-specific concepts:

* **Dynamic Linker:** The file path (`bionic/linker/`) and the logging options ("dlopen", "dlsym") clearly indicate this code is part of the dynamic linker.
* **System Properties:** The use of `__system_property_get` and property names like `"debug.ld.all"` highlights the reliance on Android's system properties for configuration.
* **Logging:** The use of `async_safe_log` shows integration with Android's logging system.
* **Process Naming:** The handling of service names (`:`) is a common Android convention.
* **Dumpable Processes:** The `PR_GET_DUMPABLE` check relates to security and debugging policies on Android.

**5. Addressing Specific Request Points:**

Now, systematically address each point in the original request:

* **Functionality:** Summarize the role of `linker_logger.cpp` in providing debug logging for the dynamic linker.
* **Android Relationship:** Explain how the logging helps debug dynamic linking issues. Provide examples of scenarios where these logs are useful (dlopen failures, symbol resolution issues).
* **libc Functions:**  Explain each libc function (`basename`, `strchr`, `prctl`, `__system_property_get`) in detail, including their purpose, parameters, return values, and potential errors.
* **Dynamic Linker:**
    * **SO Layout:** Describe a typical SO layout in memory.
    * **Linking Process:** Explain the steps involved in dynamic linking, mentioning where logging might occur (e.g., during library loading, symbol lookup). Create a sample log output based on the flags.
* **Logic Reasoning:** Provide concrete examples of how the property parsing works with different input strings. Show the mapping between property values and the internal flags.
* **Common Errors:**  Think about how developers might misuse or misunderstand the logging mechanism. Examples include typos in property names, incorrect property values, or forgetting to enable the properties.
* **Android Framework/NDK Path:** Trace how a `dlopen` call initiated from Java/Kotlin (via the NDK) would eventually reach the dynamic linker code and potentially trigger logging.
* **Frida Hooking:**  Provide specific Frida code examples to intercept the `LinkerLogger::Log` function and potentially other relevant functions like `ParseProperty`.

**6. Structuring the Output:**

Organize the information logically using headings and bullet points for clarity. Use code blocks for code examples and log outputs. Ensure the language is clear and concise.

**7. Review and Refinement:**

After drafting the explanation, review it for accuracy, completeness, and clarity. Check if all the points in the original request have been addressed adequately. Ensure that technical terms are explained clearly. For instance,  double-check the explanations of libc functions and the dynamic linking process for correctness.

This systematic approach ensures that all aspects of the request are covered in a detailed and organized manner, leading to the comprehensive explanation provided in the initial prompt's example answer.
好的，我们来详细分析一下 `bionic/linker/linker_logger.cpp` 文件的功能和实现。

**功能概述**

`linker_logger.cpp` 文件的主要功能是为 Android 的动态链接器 (linker) 提供调试日志记录功能。它允许在动态链接过程中记录各种事件，例如 `dlopen`，`dlsym` 的调用以及遇到的错误。这些日志可以帮助开发者和系统工程师理解和调试动态链接相关的问题。

**与 Android 功能的关系和举例说明**

动态链接器是 Android 系统启动、加载库文件、解析符号的关键组件。`linker_logger.cpp` 的功能直接服务于动态链接器，因此与 Android 的核心功能密切相关。

**举例说明：**

* **调试 `dlopen` 失败：** 当应用程序尝试使用 `dlopen` 加载一个共享库时失败，开发者可以通过设置相应的 `debug.ld` 属性来启用 `dlopen` 的日志记录。日志会显示 `dlopen` 的参数（库名），以及失败的原因，例如找不到库文件、权限不足等。这对于诊断库加载问题非常有用。

* **调试 `dlsym` 找不到符号：** 如果应用程序在通过 `dlsym` 获取共享库中的函数或变量地址时失败，启用 `dlsym` 的日志记录可以帮助开发者追踪符号查找的过程，例如搜索了哪些库、哪些库中没有找到该符号等。

* **排查动态链接器错误：**  动态链接器自身在运行过程中也可能遇到错误，例如循环依赖、版本冲突等。通过启用错误日志，可以记录这些内部错误，帮助系统工程师诊断和修复动态链接器自身的问题。

**libc 函数的功能实现**

`linker_logger.cpp` 中使用了一些 libc 函数，我们来详细解释它们的功能：

* **`basename(char *path)`:**
    * **功能:**  返回路径名字符串中最后一个斜杠 (/) 之后的部分。如果路径名中没有斜杠，则返回整个路径名。此函数会修改传入的 `path` 指针指向的字符串。
    * **实现:** `basename` 函数通常会从字符串的末尾开始向前搜索，直到找到一个斜杠或者到达字符串的开头。它会修改字符串，在最后一个斜杠之后的位置插入空字符 `\0`，然后返回指向该位置的指针。需要注意的是，某些实现可能会修改传入的字符串，也有些实现会返回一个静态分配的字符串，因此使用时需要注意。
    * **示例:**
        * `basename("/path/to/file.txt")` 返回 "file.txt" 并可能修改传入的字符串为 "/path/to\0".
        * `basename("file.txt")` 返回 "file.txt".
    * **常见错误:**  用户可能会误以为 `basename` 不会修改传入的字符串，从而在后续操作中遇到意外情况。 建议在调用 `basename` 前复制字符串。

* **`strchr(const char *s, int c)`:**
    * **功能:**  在字符串 `s` 中查找第一次出现字符 `c` 的位置。
    * **实现:** `strchr` 函数从字符串 `s` 的开头开始逐个字符地与 `c` 进行比较。如果找到匹配的字符，则返回指向该字符的指针。如果遍历完整个字符串都没有找到，则返回 `NULL`。
    * **示例:**
        * `strchr("hello world", 'o')` 返回指向字符串中第一个 'o' 的指针。
        * `strchr("hello world", 'z')` 返回 `NULL`.
    * **常见错误:**  将 `c` 误写成字符串而不是字符，例如 `strchr("hello", "o")` 是错误的。

* **`prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)`:**
    * **功能:**  对调用进程本身执行各种操作控制。它的具体行为由第一个参数 `option` 决定。
    * **实现:** `prctl` 是一个系统调用，它会陷入内核，由内核执行相应的操作。不同的 `option` 值对应不同的内核实现。
    * **在本代码中使用的 `PR_GET_DUMPABLE`：**  用于查询进程是否可以被转储内存 (dumpable)。如果进程是 dumpable 的，`prctl` 返回非零值；否则返回 0。这通常与安全策略有关，例如某些特权进程可能不允许被转储。
    * **示例:**
        * `prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)`  查询当前进程的 dumpable 状态。
    * **常见错误:**  传递错误的 `option` 值或参数，可能导致未定义的行为或错误。

* **`__system_property_get(const char *name, char *value)`:**
    * **功能:**  获取 Android 系统属性的值。
    * **实现:** `__system_property_get` 是一个 Bionic 库提供的函数，它最终会通过 Binder IPC 与 `system_server` 进程通信，获取指定属性的值。`system_server` 维护着系统属性的数据库。获取到的属性值会被复制到 `value` 指向的缓冲区中。
    * **示例:**
        * `char buffer[PROP_VALUE_MAX];`
        * `__system_property_get("ro.build.version.sdk", buffer);`  将 Android SDK 版本号写入 `buffer`。
    * **常见错误:**
        * 提供的 `name` 不存在。
        * `value` 指向的缓冲区太小，无法容纳属性值。
        * 在没有权限的情况下尝试获取某些受保护的属性。

**Dynamic Linker 的功能、SO 布局样本和链接处理过程**

`linker_logger.cpp` 的存在就是为了辅助动态链接器的调试，因此我们来详细了解动态链接器。

**Dynamic Linker 的功能：**

* **加载共享库 (`.so` 文件):**  当程序启动或运行时需要使用共享库时，动态链接器负责将这些库加载到进程的内存空间。
* **符号解析 (Symbol Resolution):**  程序和共享库中会引用一些外部符号（函数或变量），这些符号的实际地址需要在运行时确定。动态链接器负责在已加载的共享库中查找这些符号的定义，并将引用地址更新为实际地址。
* **重定位 (Relocation):**  共享库在编译时并不知道最终的加载地址，因此库中会包含一些需要根据实际加载地址进行调整的代码和数据。动态链接器负责在加载库后执行重定位操作，修正这些地址。
* **依赖关系处理:**  共享库之间可能存在依赖关系。动态链接器需要按照正确的顺序加载这些依赖库。

**SO 布局样本：**

```
内存地址:       内容:
--------------------------------------
0xb7000000 - 0xb7000fff:  ELF header (标识这是一个共享库)
0xb7001000 - 0xb7001fff:  Program headers (描述内存段的布局)
0xb7002000 - 0xb7002fff:  .text section (代码段)
0xb7003000 - 0xb7003fff:  .rodata section (只读数据段，例如字符串常量)
0xb7004000 - 0xb7004fff:  .data section (已初始化的全局变量和静态变量)
0xb7005000 - 0xb7005fff:  .bss section (未初始化的全局变量和静态变量)
0xb7006000 - 0xb7006fff:  .dynamic section (包含动态链接信息，例如符号表、重定位表)
0xb7007000 - 0xb7007fff:  .symtab section (符号表，包含库中定义的符号)
0xb7008000 - 0xb7008fff:  .strtab section (字符串表，存储符号名等字符串)
0xb7009000 - 0xb7009fff:  .rel.plt section (Procedure Linkage Table 的重定位信息)
0xb700a000 - 0xb700afff:  .rel.dyn section (数据段的重定位信息)
... 其他 section ...
```

**链接的处理过程（简化版）：**

1. **`dlopen("libexample.so")` 调用：**  应用程序调用 `dlopen` 请求加载共享库。
2. **查找库文件：** 动态链接器会在预定义的路径（例如 `/system/lib`, `/vendor/lib`, 应用的 nativeLibraryDir 等）中搜索 `libexample.so` 文件。
3. **加载库到内存：** 如果找到库文件，动态链接器会将其加载到进程的内存空间。这涉及到读取 ELF 文件头和 program headers，分配内存段，并将代码和数据拷贝到相应的内存区域。
4. **处理依赖关系：**  动态链接器会检查 `libexample.so` 的依赖库，并递归地加载这些依赖库。
5. **符号解析和重定位：**
   * **解析 `libexample.so` 的符号：** 动态链接器会遍历 `libexample.so` 的重定位表，找到需要重定位的符号引用。然后，它会在已加载的共享库（包括 `libexample.so` 自身以及其依赖库）的符号表中查找这些符号的定义，并将引用地址更新为实际地址。
   * **处理 PLT (Procedure Linkage Table)：** 对于函数调用，通常会使用 PLT 作为间接跳转表。动态链接器会初始化 PLT 表项，使其在第一次调用时跳转到动态链接器的解析代码，解析函数地址后再跳转到实际函数。后续调用可以直接通过 PLT 跳转，提高效率。
6. **执行初始化代码：**  共享库可能包含初始化函数（例如使用 `__attribute__((constructor))` 标记的函数）。动态链接器会在所有重定位完成后执行这些初始化函数。
7. **返回库句柄：** `dlopen` 成功后，动态链接器会返回一个指向加载的库的句柄，应用程序可以使用该句柄通过 `dlsym` 获取库中的符号地址。

**假设输入与输出 (针对 `ParseProperty`)**

**假设输入：**

* `value = ""`
* `value = "dlerror"`
* `value = "dlopen,dlsym"`
* `value = "unknown"`
* `value = "dlerror,unknown,dlopen"`

**输出：**

* `ParseProperty("")` 返回 `0`
* `ParseProperty("dlerror")` 返回 `kLogErrors` 的值 (假设为 1)
* `ParseProperty("dlopen,dlsym")` 返回 `kLogDlopen | kLogDlsym` 的值 (假设为 2 | 4 = 6)
* `ParseProperty("unknown")` 会输出警告日志，并返回 `0`
* `ParseProperty("dlerror,unknown,dlopen")` 会输出警告日志，并返回 `kLogErrors | kLogDlopen` 的值 (假设为 1 | 2 = 3)

**用户或编程常见的使用错误**

* **拼写错误的属性名：**  用户可能在设置系统属性时拼写错误，例如 `debug.ld.alll` 而不是 `debug.ld.all`，导致日志记录功能无法启用。
* **不正确的属性值：**  用户可能设置了无效的属性值，例如 `debug.ld.all=true`，而代码只识别特定的关键字（`dlerror`, `dlopen`, `dlsym`）。
* **权限问题：**  普通应用程序可能无法读取或设置某些系统属性，需要 root 权限或特定的系统权限。
* **忘记重启进程：**  在修改了 `debug.ld` 相关的系统属性后，需要重启目标进程才能使修改生效。
* **假设日志总是存在：** 开发者不应该依赖于日志的存在，因为用户可能没有启用相关的属性。日志主要用于调试目的。
* **在生产环境启用过多的日志：**  过多的日志会影响性能，因此在生产环境中应谨慎使用。

**Android Framework 或 NDK 如何到达这里**

1. **Java/Kotlin 代码调用 `System.loadLibrary("example")` 或 `dlopen("libexample.so")`:**  这是触发动态链接的常见方式。`System.loadLibrary` 最终会调用到 native 方法，进而调用 Bionic 的 `dlopen` 函数。

2. **NDK 代码直接调用 `dlopen`:**  使用 NDK 开发的 C/C++ 代码可以直接调用 `dlopen` 函数加载共享库。

3. **Bionic 的 `dlopen` 实现:**  Bionic 库中的 `dlopen` 函数是动态链接器的入口点之一。它会执行前面描述的查找库文件、加载库、解析符号等操作。

4. **`LinkerLogger` 的使用:**  在 `dlopen` 和其他动态链接相关的关键路径上，动态链接器会检查 `g_linker_logger` 的状态（是否启用了相应的日志记录），如果启用了，则会调用 `g_linker_logger.Log()` 函数记录相关信息。

5. **日志输出:**  `g_linker_logger.Log()` 函数最终会调用 `async_safe_format_log_va_list`，将日志信息输出到 Android 的日志系统 (logcat)。

**Frida Hook 示例调试步骤**

假设我们想 hook `LinkerLogger::Log` 函数，查看动态链接器输出了哪些日志。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[Linker Log] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"未找到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("linker64" if Process.arch === 'arm64' else "linker", "_ZN12LinkerLogger3LogEPKc"), {
    onEnter: function(args) {
        const format = Memory.readUtf8String(args[1]);
        const formattedString = Java.vm.getEnv().getStringUtfChars(Java.vm.getEnv().newStringUtf8(format), null);
        const formattedArgs = [];
        let match;
        const regex = /%([0-9]+\$)?([0-9]*\.?[0-9]*)(hh|h|l|ll|L|z|j|t)?([diouxXfFeEgGaAcspn])/g;
        let argIndex = 0;
        while ((match = regex.exec(formattedString)) !== null) {
            argIndex++;
            let argValue;
            const modifier = match[3];
            const typeSpecifier = match[4];

            try {
                if (modifier === 'l' && typeSpecifier === 's') { // wchar_t*
                    argValue = Memory.readUtf16String(ptr(args[argIndex + 1]));
                } else if (typeSpecifier === 's' || typeSpecifier === 'p') {
                    argValue = Memory.readUtf8String(ptr(args[argIndex + 1]));
                } else if (typeSpecifier === 'd' || typeSpecifier === 'i' || typeSpecifier === 'o' || typeSpecifier === 'u' || typeSpecifier === 'x' || typeSpecifier === 'X') {
                    argValue = ptr(args[argIndex + 1]).toInt();
                } else if (typeSpecifier === 'f' || typeSpecifier === 'F' || typeSpecifier === 'e' || typeSpecifier === 'E' || typeSpecifier === 'g' || typeSpecifier === 'G' || typeSpecifier === 'a' || typeSpecifier === 'A') {
                    argValue = ptr(args[argIndex + 1]).readFloat(); // 假设是 float，可能需要根据实际情况调整
                } else if (typeSpecifier === 'c') {
                    argValue = String.fromCharCode(ptr(args[argIndex + 1]).toInt() & 0xFF);
                } else {
                    argValue = ptr(args[argIndex + 1]);
                }
            } catch (e) {
                argValue = "[Error reading argument]";
            }
            formattedArgs.push(argValue);
        }
        send({ formattedString: formattedString, args: formattedArgs });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 示例解释：**

1. **连接目标进程：**  代码首先尝试连接到指定包名的应用程序进程。
2. **查找 `LinkerLogger::Log` 函数地址：**  `Module.findExportByName` 用于在 `linker` (或 `linker64`，取决于设备架构) 模块中查找 `LinkerLogger::Log` 函数的地址。需要注意的是，函数名需要使用 mangled name (C++ 命名修饰)。
3. **`Interceptor.attach` 进行 hook：**  `Interceptor.attach` 用于在函数入口处插入我们的代码。
4. **`onEnter` 回调：**  当 `LinkerLogger::Log` 函数被调用时，`onEnter` 回调函数会被执行。
5. **读取格式化字符串和参数：**
   * `args[1]` 通常指向格式化字符串。
   * 代码尝试解析格式化字符串，并根据格式说明符读取后续的参数。这部分代码可能需要根据实际的格式化字符串进行调整，以正确解析各种类型的参数。
6. **使用 `send` 发送数据到 Frida 客户端：**  将读取到的格式化字符串和参数通过 `send` 函数发送回 Frida 客户端。
7. **Frida 客户端接收并打印日志：**  Frida 客户端的 `on_message` 函数接收到数据，并打印到控制台。

**使用步骤：**

1. 确保你的 Android 设备已 root，并且安装了 Frida server。
2. 安装 Frida Python 客户端 (`pip install frida`).
3. 将上面的 Python 代码保存为 `.py` 文件，例如 `hook_linker_log.py`。
4. 替换 `package_name` 为你要调试的应用的包名。
5. 运行脚本：`python hook_linker_log.py`
6. 启动或操作你的目标应用程序，你将在 Frida 客户端看到动态链接器输出的日志信息。

这个 Frida Hook 示例提供了一种动态地观察动态链接器行为的方式，无需重新编译或修改系统代码。你可以根据需要修改 hook 的函数和要提取的信息。

Prompt: 
```
这是目录为bionic/linker/linker_logger.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include "linker_logger.h"

#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <async_safe/log.h>

#include "android-base/strings.h"
#include "private/CachedProperty.h"

LinkerLogger g_linker_logger;

static uint32_t ParseProperty(const std::string& value) {
  if (value.empty()) {
    return 0;
  }

  std::vector<std::string> options = android::base::Split(value, ",");

  uint32_t flags = 0;

  for (const auto& o : options) {
    if (o == "dlerror") {
      flags |= kLogErrors;
    } else if (o == "dlopen") {
      flags |= kLogDlopen;
    } else if (o == "dlsym") {
      flags |= kLogDlsym;
    } else {
      async_safe_format_log(ANDROID_LOG_WARN, "linker", "Ignoring unknown debug.ld option \"%s\"",
                            o.c_str());
    }
  }

  return flags;
}

static void GetAppSpecificProperty(char* buffer) {
  // Get process basename.
  const char* process_name_start = basename(g_argv[0]);

  // Remove ':' and everything after it. This is the naming convention for
  // services: https://developer.android.com/guide/components/services.html
  const char* process_name_end = strchr(process_name_start, ':');

  std::string process_name = (process_name_end != nullptr) ?
                             std::string(process_name_start, (process_name_end - process_name_start)) :
                             std::string(process_name_start);

  std::string property_name = std::string("debug.ld.app.") + process_name;
  __system_property_get(property_name.c_str(), buffer);
}

void LinkerLogger::ResetState() {
  // The most likely scenario app is not debuggable and
  // is running on a user build, in which case logging is disabled.
  if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0) {
    return;
  }

  flags_ = 0;

  // For logging, check the flag applied to all processes first.
  static CachedProperty debug_ld_all("debug.ld.all");
  flags_ |= ParseProperty(debug_ld_all.Get());

  // Safeguard against a NULL g_argv. Ignore processes started without argv (http://b/33276926).
  if (g_argv == nullptr || g_argv[0] == nullptr) {
    return;
  }

  // Otherwise check the app-specific property too.
  // We can't easily cache the property here because argv[0] changes.
  char debug_ld_app[PROP_VALUE_MAX] = {};
  GetAppSpecificProperty(debug_ld_app);
  flags_ |= ParseProperty(debug_ld_app);
}

void LinkerLogger::Log(const char* format, ...) {
  va_list ap;
  va_start(ap, format);
  async_safe_format_log_va_list(ANDROID_LOG_DEBUG, "linker", format, ap);
  va_end(ap);
}

"""

```