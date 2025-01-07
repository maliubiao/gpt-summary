Response:
Let's break down the thought process for analyzing the `linker_config.cpp` file and generating the comprehensive response.

1. **Understand the Goal:** The primary objective is to explain the functionality of this specific C++ file within the Android Bionic library, focusing on its role in configuring the dynamic linker. The request also includes details on related Android features, libc functions, dynamic linking processes, potential errors, and debugging techniques.

2. **Initial Scan and Keyword Identification:**  Read through the code quickly, noting key classes, functions, and included headers. Keywords like `ConfigParser`, `PropertyValue`, `NamespaceConfig`, `properties`, `search_paths`, `allowed_libs`, `links`, and the inclusion of `<android-base/...>` strongly suggest this file is responsible for parsing and interpreting configuration information. The file name `linker_config.cpp` reinforces this.

3. **Core Functionality - Configuration Parsing:**  The presence of `ConfigParser` immediately stands out. Analyze its `next_token` method. It clearly parses lines, identifies sections (`[]`), assignments (`=`), and appends (`+=`). This confirms the file's role in reading a configuration file.

4. **Data Structures - Storing Configuration:** Identify the `PropertyValue` class. It holds the value and line number of a property. The use of `std::unordered_map<std::string, PropertyValue>` in `parse_config_file` indicates that configurations are stored as key-value pairs.

5. **Linking Configuration to Android:** Notice the use of `android::base::ReadFileToString`, `android::base::Trim`, `android::base::Split`, and `android::base::GetProperty`. These strongly indicate interaction with the Android system, specifically for reading files and system properties. The presence of `DL_WARN` and `LD_DEBUG` points to logging mechanisms used by the dynamic linker.

6. **Namespace Configuration:** The `NamespaceConfig` class and the logic within `read_binary_config` that creates and populates these objects are crucial. Focus on how namespaces are linked (`add_namespace_link`), the handling of `shared_libs`, `allowed_libs`, `search_paths`, and `permitted_paths`. This reveals the core mechanism for isolating and controlling library loading.

7. **Dynamic Linking Concepts:**  The terms "search paths," "allowed libs," and namespace linking are directly related to dynamic linking. Consider how these configurations influence the linker's behavior when resolving shared library dependencies. This naturally leads to the explanation of SO layout and linking processes.

8. **Libc Function Analysis:**  Look for standard C library functions. `access`, `realpath`, `strtol`, `dirname`, and `strerror` are used. Explain the purpose of each and how they contribute to the overall configuration process (e.g., `access` to check file existence, `realpath` to resolve paths).

9. **Error Handling:** Note the use of `error_msg` parameters and the `DL_WARN` macros. Think about scenarios that would trigger these warnings (e.g., invalid format, undefined properties, contradictory settings). This forms the basis for the "common errors" section.

10. **Android Framework/NDK Integration:**  Consider *when* and *how* this configuration is used. The dynamic linker is invoked when an application starts. The configuration determines how libraries are loaded for that process. Trace the path from app launch to the linker's initialization.

11. **Frida Hooking:** Think about which functions would be useful to hook for debugging. `parse_config_file` and functions within `NamespaceConfig` are good candidates for observing the configuration process.

12. **Structure and Organization:**  Organize the information logically. Start with a high-level overview of the file's purpose. Then, delve into specific functionalities, linking them to Android features where appropriate. Provide clear explanations for libc functions and dynamic linking. Use examples and address potential errors. Conclude with the integration with the Android framework and debugging using Frida.

13. **Refinement and Detail:** Review the generated response for clarity, accuracy, and completeness. Ensure that technical terms are explained. Provide concrete examples where necessary (e.g., SO layout, Frida hooks). Double-check that all aspects of the prompt have been addressed.

**Self-Correction/Refinement Example during the process:**

* **Initial Thought:**  "The `ConfigParser` just reads lines."
* **Correction:** "No, it also identifies different token types (section, assign, append) and extracts the relevant names and values."  This leads to a more detailed explanation of the `next_token` method.

* **Initial Thought:** "Just list the libc functions."
* **Correction:** "Explain *how* each function is used within the context of the linker configuration process. What specific information does it provide or what action does it perform?"

* **Initial Thought:**  "The SO layout is straightforward."
* **Correction:** "Provide a concrete example of a directory structure and how the linker might search for libraries based on the configuration."

By following these steps of understanding, identifying key components, connecting them to broader concepts, and iteratively refining the analysis, a comprehensive and accurate response can be constructed.
这个文件 `bionic/linker/linker_config.cpp` 是 Android Bionic 库中动态链接器 (`linker`) 的一个关键组成部分，它的主要功能是**读取和解析动态链接器的配置文件，并根据配置信息来设置动态链接器的行为，例如库的搜索路径、命名空间隔离、允许加载的库等。**

下面详细列举其功能，并结合 Android 功能进行说明：

**1. 解析动态链接器配置文件:**

* **功能:**  `parse_config_file` 函数负责读取指定的配置文件 (`ld_config_file_path`)，并解析其中的内容。配置文件通常包含关于库搜索路径、命名空间以及它们之间的链接关系等信息。
* **Android 关系及举例:** Android 系统允许通过配置文件来更精细地控制动态链接器的行为，尤其是在引入命名空间隔离后，配置文件变得更加重要。
    * **举例:**  在 Android 中，不同的进程或不同的组件可能需要加载不同版本的共享库，或者需要将某些库隔离在特定的命名空间中。通过配置文件，可以定义不同的命名空间，并指定每个命名空间可以访问哪些库。例如，可以配置一个 `default` 命名空间和一个 `vndk` (Vendor Native Development Kit) 命名空间，`vndk` 命名空间只能访问供应商提供的库，而 `default` 命名空间可以访问系统库。

**2. 管理配置属性:**

* **功能:**  `ConfigParser` 类负责解析配置文件的每一行，识别属性的赋值 (`=`) 和追加 (`+=`) 操作，以及节的定义 (`[]`)。`PropertyValue` 类用于存储属性的值和行号。
* **Android 关系及举例:** 配置文件中的每一项设置都是一个属性。例如，`dir.default` 可以指定默认命名空间的搜索路径，`namespace.default.links` 可以指定默认命名空间链接的其他命名空间。
    * **举例:**  在配置文件中，可能会有如下配置：
        ```
        [default]
        dir.default = /system/lib64:/vendor/lib64
        namespace.default.links = vndk
        namespace.vndk.search.paths = /vendor/lib64/vndk
        ```
        这表示默认命名空间的搜索路径包括 `/system/lib64` 和 `/vendor/lib64`，并且链接到 `vndk` 命名空间。`vndk` 命名空间的搜索路径是 `/vendor/lib64/vndk`。

**3. 创建和管理命名空间配置:**

* **功能:** `Config` 类和 `NamespaceConfig` 类用于存储和管理命名空间的配置信息。`read_binary_config` 函数根据配置文件中的信息创建和配置不同的命名空间。
* **Android 关系及举例:** Android 的命名空间隔离机制是其安全性和模块化的重要组成部分。通过配置，可以定义不同的命名空间，限制每个命名空间可以访问的共享库，防止不同模块之间的库冲突，提高系统的稳定性。
    * **举例:**  如上面的例子，`NamespaceConfig` 实例会存储 `default` 和 `vndk` 命名空间的搜索路径、链接关系等信息。当进程需要加载共享库时，动态链接器会根据当前进程所属的命名空间和配置信息来查找和加载库。

**4. 设置库的搜索路径:**

* **功能:**  配置文件中可以指定不同命名空间的库搜索路径 (`namespace.<name>.search.paths`)。`Properties::get_paths` 函数用于解析这些路径，并进行一些处理，例如替换环境变量（如 `$LIB`）。
* **Android 关系及举例:**  指定搜索路径是动态链接器查找共享库的关键。不同的命名空间可以有不同的搜索路径，确保加载正确的库版本。
    * **举例:**  在上面的配置中，默认命名空间会先搜索 `/system/lib64` 和 `/vendor/lib64`，而 `vndk` 命名空间只会搜索 `/vendor/lib64/vndk`。

**5. 定义命名空间之间的链接关系:**

* **功能:**  配置文件中可以指定命名空间之间的链接关系 (`namespace.<name>.links` 和 `namespace.<name>.link.<linked_name>.shared_libs`)，以及是否允许链接所有共享库 (`allow_all_shared_libs`).
* **Android 关系及举例:** 命名空间之间的链接允许一个命名空间访问另一个命名空间中的特定共享库。这在实现模块化和代码复用时非常有用。
    * **举例:**  在上面的配置中，`default` 命名空间链接到 `vndk` 命名空间。可以配置 `namespace.default.link.vndk.shared_libs` 来指定 `default` 命名空间可以访问 `vndk` 命名空间中的哪些库。如果设置了 `allow_all_shared_libs = true`，则 `default` 命名空间可以访问 `vndk` 命名空间中的所有库。

**6. 控制允许加载的库:**

* **功能:**  配置文件中可以指定每个命名空间允许加载的库列表 (`namespace.<name>.allowed_libs` 或 `namespace.<name>.whitelisted`)。
* **Android 关系及举例:**  这是一种安全机制，可以限制特定进程或命名空间只能加载特定的库，防止恶意代码注入或意外的库冲突。
    * **举例:** 可以配置某个应用只能加载系统提供的特定库，而不能加载第三方库。

**7. 处理目标 SDK 版本:**

* **功能:**  `read_binary_config` 函数会读取二进制文件所在目录下的 `.version` 文件，获取目标 SDK 版本，并将其应用于后续的路径解析。
* **Android 关系及举例:**  目标 SDK 版本会影响某些库的查找路径，例如 `/system/lib[64]/android<sdk_version>`. 这允许为不同的应用加载针对其目标 SDK 版本优化的库。

**8. 支持 ASan/HWAsan:**

* **功能:**  配置文件支持针对 AddressSanitizer (ASan) 和 Hardware-assisted AddressSanitizer (HWAsan) 的特定配置，通过在属性名前添加 `.asan` 或 `.hwasan` 后缀来实现。
* **Android 关系及举例:**  ASan 和 HWAsan 是内存错误检测工具，需要在运行时加载特定的库版本。通过配置文件，可以为使用 ASan/HWAsan 编译的应用指定不同的库搜索路径或链接配置。

**详细解释 libc 函数的功能实现:**

在这个文件中，主要使用的 libc 函数及其功能如下：

* **`access(const char *pathname, int mode)`:**
    * **功能:** 检查调用进程是否可以访问 `pathname` 指定的文件。`mode` 指定要检查的访问权限 (例如，`R_OK` 表示读权限)。
    * **实现:**  `access` 系统调用由操作系统内核实现。内核会检查调用进程的 UID/GID 以及文件的权限位，来判断是否允许访问。
    * **本文件中的使用:** 用于检查配置文件中指定的路径是否存在并且可读 (`R_OK`)。

* **`realpath(const char *pathname, char *resolved_path)`:**
    * **功能:**  将 `pathname` 指向的相对路径名转换为绝对路径名。它会解析路径中的符号链接和 `.`、`..` 等特殊目录。
    * **实现:**  `realpath` 系统调用由操作系统内核实现。内核会沿着路径查找文件，并解析遇到的符号链接，直到找到最终的路径。
    * **本文件中的使用:**  用于解析配置文件中指定的库搜索路径，确保使用的是绝对路径，避免符号链接带来的歧义。

* **`strtol(const char *nptr, char **endptr, int base)`:**
    * **功能:**  将字符串 `nptr` 转换为长整型数。`base` 指定转换的基数（例如，10 表示十进制）。`endptr` 用于存储解析停止的位置。
    * **实现:**  `strtol` 函数通常由 C 标准库提供。它会跳过字符串前面的空白字符，然后尝试将后续字符按照指定的基数转换为数字。
    * **本文件中的使用:** 用于将 `.version` 文件中的字符串内容转换为整数，以获取目标 SDK 版本。

* **`dirname(char *path)`:**
    * **功能:**  返回路径名 `path` 的目录部分。例如，`dirname("/a/b/c")` 会返回 `"/a/b"`。注意，这个函数可能会修改传入的 `path` 参数。
    * **实现:**  `dirname` 函数通常由 C 标准库提供。它会在路径字符串中查找最后一个 `/` 字符，并将该字符后面的部分替换为 `\0`，从而返回目录部分。
    * **本文件中的使用:**  用于获取二进制文件所在的目录，以便查找 `.version` 文件。

* **`strerror(int errnum)`:**
    * **功能:**  根据错误码 `errnum` 返回对应的错误描述字符串。
    * **实现:**  `strerror` 函数通常由 C 标准库提供。它会维护一个错误码和错误描述的映射表，并根据传入的错误码查找对应的描述。
    * **本文件中的使用:**  用于在读取配置文件或 `.version` 文件出错时，获取错误信息并输出到日志。

**涉及 dynamic linker 的功能、so 布局样本和链接的处理过程:**

这个文件直接参与了 dynamic linker 的配置过程，因此其所有功能都与 dynamic linker 相关。

**SO 布局样本:**

假设有以下目录结构：

```
/
├── system
│   └── lib64
│       ├── libc.so
│       ├── libutils.so
│       └── ...
├── vendor
│   └── lib64
│       ├── libvulkan.so
│       └── vndk
│           └── libprotobuf.so
└── data
    └── app
        └── com.example.myapp
            ├── lib
            │   └── arm64
            │       └── libnative.so
            └── .version  (内容可能是 30)
```

**配置文件 (`/system/etc/ld.config.txt`) 样本:**

```
[default]
dir.default = /system/lib64:/vendor/lib64

[vndk]
dir.vndk = /vendor/lib64/vndk

[namespace.default]
link.vndk.shared_libs = libprotobuf.so
link.vndk.allow_all_shared_libs = false
links = vndk

[namespace.vndk]
isolated = true
```

**链接的处理过程 (以加载 `libnative.so` 中依赖的 `libprotobuf.so` 为例):**

1. **启动应用:** 当应用 `com.example.myapp` 启动时，操作系统会加载其主执行文件 `/data/app/com.example.myapp/lib/arm64/libnative.so`。

2. **读取配置:** 动态链接器会读取 `/system/etc/ld.config.txt` 文件，并调用 `parse_config_file` 进行解析。根据当前进程的路径 (`/data/app/com.example.myapp/lib/arm64/libnative.so`)，确定使用 `default` 配置节。

3. **创建命名空间:** 动态链接器会根据配置文件创建 `default` 和 `vndk` 两个命名空间，并根据配置信息设置它们的搜索路径、链接关系等。

4. **解析依赖:**  当加载 `libnative.so` 时，动态链接器会解析其依赖项，发现它依赖于 `libprotobuf.so`。

5. **查找依赖 (default 命名空间):**
   * 首先，动态链接器在 `default` 命名空间的搜索路径 `/system/lib64` 和 `/vendor/lib64` 中查找 `libprotobuf.so`。

6. **处理命名空间链接:**
   * 由于 `default` 命名空间链接到了 `vndk` 命名空间，并且配置了 `link.vndk.shared_libs = libprotobuf.so`，动态链接器会在 `vndk` 命名空间中查找 `libprotobuf.so`。

7. **查找依赖 (vndk 命名空间):**
   * 动态链接器在 `vndk` 命名空间的搜索路径 `/vendor/lib64/vndk` 中查找 `libprotobuf.so`。

8. **加载依赖:** 如果在 `/vendor/lib64/vndk` 中找到了 `libprotobuf.so`，动态链接器会将其加载到内存中。

**假设输入与输出 (针对 `parse_config_file` 函数):**

**假设输入:**

* `ld_config_file_path`: `/system/etc/ld.config.txt` (内容如上所示)
* `binary_realpath`: `/data/app/com.example.myapp/lib/arm64/libnative.so`

**预期输出 (简化):**

* `properties` (一个 `std::unordered_map`): 包含从配置文件中解析出的属性，例如：
    * `"dir.default"`: `PropertyValue("/system/lib64:/vendor/lib64", ...)`
    * `"namespace.default.links"`: `PropertyValue("vndk", ...)`
    * `"namespace.vndk.search.paths"`: `PropertyValue("/vendor/lib64/vndk", ...)`
    * ...
* 函数返回 `true`，表示解析成功。

**用户或编程常见的使用错误:**

1. **配置文件格式错误:**
   * **错误示例:**  `name = value` 中间缺少空格，或者使用了未定义的语法。
   * **后果:**  动态链接器会发出警告并忽略错误的行，可能导致配置不生效。

2. **命名空间链接配置错误:**
   * **错误示例:**  在 `namespace.default.links` 中指定了不存在的命名空间，或者在 `shared_libs` 中拼写错误了库的名称。
   * **后果:**  动态链接器会报错，可能导致应用启动失败。

3. **路径配置错误:**
   * **错误示例:**  指定的搜索路径不存在或者没有读取权限。
   * **后果:**  动态链接器可能找不到需要的共享库，导致加载失败。

4. **权限问题:**
   * **错误示例:**  动态链接器进程没有权限读取配置文件。
   * **后果:**  动态链接器无法加载配置，可能会使用默认配置，或者启动失败。

5. **版本文件错误:**
   * **错误示例:** `.version` 文件内容不是有效的整数。
   * **后果:**  动态链接器无法获取目标 SDK 版本，可能会导致加载错误版本的库。

**Android framework or ndk 是如何一步步的到达这里:**

1. **应用启动:** 用户启动一个 Android 应用。

2. **Zygote 进程:** Android 系统通过 Zygote 进程 fork 出新的应用进程。

3. **加载器调用:** 在新的应用进程中，内核会加载应用的入口点，通常是 `linker64` 或 `linker` (取决于架构)。

4. **动态链接器初始化:**  动态链接器开始初始化，其中一个重要的步骤就是读取和解析配置文件。

5. **`android_dlopen_ext` 或 `dlopen`:**  当应用代码 (无论是 Framework 层还是 NDK 代码) 调用 `android_dlopen_ext` 或 `dlopen` 函数来加载共享库时，动态链接器会根据之前加载的配置信息来查找和加载库。

6. **配置文件读取:**  在动态链接器的初始化阶段，会调用 `Config::read_binary_config` 函数，该函数会读取指定的配置文件，并调用 `parse_config_file` 进行解析。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `parse_config_file` 函数来观察配置文件的解析过程，或者 hook `NamespaceConfig` 的相关方法来查看命名空间的配置信息。

**Frida hook `parse_config_file` 示例:**

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("linker64", "_ZN6Config18read_binary_configEPKcS2_bbbPPKS_PS1_"), {
    onEnter: function(args) {
        console.log("[*] read_binary_config called");
        console.log("[*] ld_config_file_path:", Memory.readUtf8String(args[0]));
        console.log("[*] binary_realpath:", Memory.readUtf8String(args[1]));
    },
    onLeave: function(retval) {
        console.log("[*] read_binary_config returned:", retval);
    }
});

Interceptor.attach(Module.findExportByName("linker64", "_ZL17parse_config_filePKcS0_RSt11unordered_mapISs12PropertyValueSt4hashISsESt8equal_toISsESaISt4pairIKSsS3_EEEERSt6string"), {
    onEnter: function(args) {
        console.log("[*] parse_config_file called");
        console.log("[*] ld_config_file_path:", Memory.readUtf8String(args[0]));
        console.log("[*] binary_realpath:", Memory.readUtf8String(args[1]));
    },
    onLeave: function(retval) {
        console.log("[*] parse_config_file returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个 Frida 脚本会 hook `Config::read_binary_config` 和 `parse_config_file` 函数，并在函数调用时打印出相关的参数，例如配置文件路径和二进制文件路径。通过观察这些信息，可以了解动态链接器是如何加载配置文件的。

**Frida hook `NamespaceConfig::set_search_paths` 示例:**

```python
import frida
import sys

package_name = "com.example.myapp"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("linker64", "_ZN15NamespaceConfig16set_search_pathsESt6vectorISsSaISsEEE"), {
    onEnter: function(args) {
        var paths = [];
        var vector = new CModule.std.vector['std::string'](ptr(args[1]));
        for (var i = 0; i < vector.size(); i++) {
            paths.push(vector.get(i));
        }
        console.log("[*] NamespaceConfig::set_search_paths called");
        console.log("[*] Namespace Name:", this.name_); // Assuming 'name_' is a member variable
        console.log("[*] Search Paths:", paths);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

这个 Frida 脚本会 hook `NamespaceConfig::set_search_paths` 函数，并在设置搜索路径时打印出命名空间的名称和设置的搜索路径列表。这可以帮助理解每个命名空间的库搜索路径是如何配置的。

通过使用 Frida 这样的动态调试工具，可以深入了解 Android 动态链接器的内部工作原理，并对配置文件解析和命名空间配置等关键步骤进行调试和分析。

Prompt: 
```
这是目录为bionic/linker/linker_config.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#include "linker_config.h"

#include "linker_globals.h"
#include "linker_debug.h"
#include "linker_utils.h"

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>

#include <async_safe/log.h>

#include <limits.h>
#include <stdlib.h>
#include <unistd.h>

#include <string>
#include <unordered_map>

class ConfigParser {
 public:
  enum {
    kPropertyAssign,
    kPropertyAppend,
    kSection,
    kEndOfFile,
    kError,
  };

  explicit ConfigParser(std::string&& content)
      : content_(std::move(content)), p_(0), lineno_(0), was_end_of_file_(false) {}

  /*
   * Possible return values
   * kPropertyAssign: name is set to property name and value is set to property value
   * kPropertyAppend: same as kPropertyAssign, but the value should be appended
   * kSection: name is set to section name.
   * kEndOfFile: reached end of file.
   * kError: error_msg is set.
   */
  int next_token(std::string* name, std::string* value, std::string* error_msg) {
    std::string line;
    while(NextLine(&line)) {
      size_t found = line.find('#');
      line = android::base::Trim(line.substr(0, found));

      if (line.empty()) {
        continue;
      }

      if (line[0] == '[' && line.back() == ']') {
        *name = line.substr(1, line.size() - 2);
        return kSection;
      }

      size_t found_assign = line.find('=');
      size_t found_append = line.find("+=");
      if (found_assign != std::string::npos && found_append == std::string::npos) {
        *name = android::base::Trim(line.substr(0, found_assign));
        *value = android::base::Trim(line.substr(found_assign + 1));
        return kPropertyAssign;
      }

      if (found_append != std::string::npos) {
        *name = android::base::Trim(line.substr(0, found_append));
        *value = android::base::Trim(line.substr(found_append + 2));
        return kPropertyAppend;
      }

      *error_msg = std::string("invalid format: ") +
                   line +
                   ", expected \"name = property\", \"name += property\", or \"[section]\"";
      return kError;
    }

    // to avoid infinite cycles when programmer makes a mistake
    CHECK(!was_end_of_file_);
    was_end_of_file_ = true;
    return kEndOfFile;
  }

  size_t lineno() const {
    return lineno_;
  }

 private:
  bool NextLine(std::string* line) {
    if (p_ == std::string::npos) {
      return false;
    }

    size_t found = content_.find('\n', p_);
    if (found != std::string::npos) {
      *line = content_.substr(p_, found - p_);
      p_ = found + 1;
    } else {
      *line = content_.substr(p_);
      p_ = std::string::npos;
    }

    lineno_++;
    return true;
  }

  std::string content_;
  size_t p_;
  size_t lineno_;
  bool was_end_of_file_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(ConfigParser);
};

class PropertyValue {
 public:
  PropertyValue() = default;

  PropertyValue(std::string&& value, size_t lineno)
    : value_(std::move(value)), lineno_(lineno) {}

  const std::string& value() const {
    return value_;
  }

  void append_value(std::string&& value) {
    value_ = value_ + value;
    // lineno isn't updated as we might have cases like this:
    // property.x = blah
    // property.y = blah
    // property.x += blah
  }

  size_t lineno() const {
    return lineno_;
  }

 private:
  std::string value_;
  size_t lineno_;
};

static std::string create_error_msg(const char* file,
                                    size_t lineno,
                                    const std::string& msg) {
  char buf[1024];
  async_safe_format_buffer(buf, sizeof(buf), "%s:%zu: error: %s", file, lineno, msg.c_str());

  return std::string(buf);
}

static bool parse_config_file(const char* ld_config_file_path,
                              const char* binary_realpath,
                              std::unordered_map<std::string, PropertyValue>* properties,
                              std::string* error_msg) {
  std::string content;
  if (!android::base::ReadFileToString(ld_config_file_path, &content)) {
    if (errno != ENOENT) {
      *error_msg = std::string("error reading file \"") +
                   ld_config_file_path + "\": " + strerror(errno);
    }
    return false;
  }

  ConfigParser cp(std::move(content));

  std::string section_name;

  while (true) {
    std::string name;
    std::string value;
    std::string error;

    int result = cp.next_token(&name, &value, &error);
    if (result == ConfigParser::kError) {
      DL_WARN("%s:%zd: warning: couldn't parse %s (ignoring this line)",
              ld_config_file_path,
              cp.lineno(),
              error.c_str());
      continue;
    }

    if (result == ConfigParser::kSection || result == ConfigParser::kEndOfFile) {
      return false;
    }

    if (result == ConfigParser::kPropertyAssign) {
      if (!android::base::StartsWith(name, "dir.")) {
        DL_WARN("%s:%zd: warning: unexpected property name \"%s\", "
                "expected format dir.<section_name> (ignoring this line)",
                ld_config_file_path,
                cp.lineno(),
                name.c_str());
        continue;
      }

      // remove trailing '/'
      while (!value.empty() && value.back() == '/') {
        value.pop_back();
      }

      if (value.empty()) {
        DL_WARN("%s:%zd: warning: property value is empty (ignoring this line)",
                ld_config_file_path,
                cp.lineno());
        continue;
      }

      // If the path can be resolved, resolve it
      char buf[PATH_MAX];
      std::string resolved_path;
      if (access(value.c_str(), R_OK) != 0) {
        if (errno == ENOENT) {
          // no need to test for non-existing path. skip.
          continue;
        }
        // If not accessible, don't call realpath as it will just cause
        // SELinux denial spam. Use the path unresolved.
        resolved_path = value;
      } else if (realpath(value.c_str(), buf)) {
        resolved_path = buf;
      } else {
        // realpath is expected to fail with EPERM in some situations, so log
        // the failure with INFO rather than DL_WARN. e.g. A binary in
        // /data/local/tmp may attempt to stat /postinstall. See
        // http://b/120996057.
        LD_DEBUG(any, "%s:%zd: warning: path \"%s\" couldn't be resolved: %m",
                 ld_config_file_path, cp.lineno(), value.c_str());
        resolved_path = value;
      }

      if (file_is_under_dir(binary_realpath, resolved_path)) {
        section_name = name.substr(4);
        break;
      }
    }
  }

  LD_DEBUG(any, "[ Using config section \"%s\" ]", section_name.c_str());

  // skip everything until we meet a correct section
  while (true) {
    std::string name;
    std::string value;
    std::string error;

    int result = cp.next_token(&name, &value, &error);

    if (result == ConfigParser::kSection && name == section_name) {
      break;
    }

    if (result == ConfigParser::kEndOfFile) {
      *error_msg = create_error_msg(ld_config_file_path,
                                    cp.lineno(),
                                    std::string("section \"") + section_name + "\" not found");
      return false;
    }
  }

  // found the section - parse it
  while (true) {
    std::string name;
    std::string value;
    std::string error;

    int result = cp.next_token(&name, &value, &error);

    if (result == ConfigParser::kEndOfFile || result == ConfigParser::kSection) {
      break;
    }

    if (result == ConfigParser::kPropertyAssign) {
      if (properties->contains(name)) {
        DL_WARN("%s:%zd: warning: redefining property \"%s\" (overriding previous value)",
                ld_config_file_path,
                cp.lineno(),
                name.c_str());
      }

      (*properties)[name] = PropertyValue(std::move(value), cp.lineno());
    } else if (result == ConfigParser::kPropertyAppend) {
      if (!properties->contains(name)) {
        DL_WARN("%s:%zd: warning: appending to undefined property \"%s\" (treating as assignment)",
                ld_config_file_path,
                cp.lineno(),
                name.c_str());
        (*properties)[name] = PropertyValue(std::move(value), cp.lineno());
      } else {
        if (android::base::EndsWith(name, ".links") ||
            android::base::EndsWith(name, ".namespaces")) {
          value = "," + value;
          (*properties)[name].append_value(std::move(value));
        } else if (android::base::EndsWith(name, ".paths") ||
                   android::base::EndsWith(name, ".shared_libs") ||
                   android::base::EndsWith(name, ".whitelisted") ||
                   android::base::EndsWith(name, ".allowed_libs")) {
          value = ":" + value;
          (*properties)[name].append_value(std::move(value));
        } else {
          DL_WARN("%s:%zd: warning: += isn't allowed for property \"%s\" (ignoring)",
                  ld_config_file_path,
                  cp.lineno(),
                  name.c_str());
        }
      }
    }

    if (result == ConfigParser::kError) {
      DL_WARN("%s:%zd: warning: couldn't parse %s (ignoring this line)",
              ld_config_file_path,
              cp.lineno(),
              error.c_str());
      continue;
    }
  }

  return true;
}

static Config g_config;

static constexpr const char* kDefaultConfigName = "default";
static constexpr const char* kPropertyAdditionalNamespaces = "additional.namespaces";

class Properties {
 public:
  explicit Properties(std::unordered_map<std::string, PropertyValue>&& properties)
      : properties_(std::move(properties)), target_sdk_version_(__ANDROID_API__) {}

  std::vector<std::string> get_strings(const std::string& name, size_t* lineno = nullptr) const {
    auto it = find_property(name, lineno);
    if (it == properties_.end()) {
      // return empty vector
      return std::vector<std::string>();
    }

    std::vector<std::string> strings = android::base::Split(it->second.value(), ",");

    for (size_t i = 0; i < strings.size(); ++i) {
      strings[i] = android::base::Trim(strings[i]);
    }

    return strings;
  }

  bool get_bool(const std::string& name, size_t* lineno = nullptr) const {
    auto it = find_property(name, lineno);
    if (it == properties_.end()) {
      return false;
    }

    return it->second.value() == "true";
  }

  std::string get_string(const std::string& name, size_t* lineno = nullptr) const {
    auto it = find_property(name, lineno);
    return (it == properties_.end()) ? "" : it->second.value();
  }

  std::vector<std::string> get_paths(const std::string& name, bool resolve, size_t* lineno = nullptr) {
    std::string paths_str = get_string(name, lineno);

    std::vector<std::string> paths;
    split_path(paths_str.c_str(), ":", &paths);

    std::vector<std::pair<std::string, std::string>> params;
    params.push_back({ "LIB", kLibPath });
    if (target_sdk_version_ != 0) {
      char buf[16];
      async_safe_format_buffer(buf, sizeof(buf), "%d", target_sdk_version_);
      params.push_back({ "SDK_VER", buf });
    }

    static std::string vndk_ver = Config::get_vndk_version_string('-');
    params.push_back({ "VNDK_VER", vndk_ver });
    static std::string vndk_apex_ver = Config::get_vndk_version_string('v');
    params.push_back({ "VNDK_APEX_VER", vndk_apex_ver });

    for (auto& path : paths) {
      format_string(&path, params);
    }

    if (resolve) {
      std::vector<std::string> resolved_paths;
      for (const auto& path : paths) {
        if (path.empty()) {
          continue;
        }
        // this is single threaded. no need to lock
        auto cached = resolved_paths_.find(path);
        if (cached == resolved_paths_.end()) {
          resolved_paths_[path] = resolve_path(path);
          cached = resolved_paths_.find(path);
        }
        CHECK(cached != resolved_paths_.end());
        if (cached->second.empty()) {
          continue;
        }
        resolved_paths.push_back(cached->second);
      }

      return resolved_paths;
    } else {
      return paths;
    }
  }

  void set_target_sdk_version(int target_sdk_version) {
    target_sdk_version_ = target_sdk_version;
  }

 private:
  std::unordered_map<std::string, PropertyValue>::const_iterator
  find_property(const std::string& name, size_t* lineno) const {
    auto it = properties_.find(name);
    if (it != properties_.end() && lineno != nullptr) {
      *lineno = it->second.lineno();
    }

    return it;
  }
  std::unordered_map<std::string, PropertyValue> properties_;
  std::unordered_map<std::string, std::string> resolved_paths_;
  int target_sdk_version_;

  DISALLOW_IMPLICIT_CONSTRUCTORS(Properties);
};

bool Config::read_binary_config(const char* ld_config_file_path,
                                      const char* binary_realpath,
                                      bool is_asan,
                                      bool is_hwasan,
                                      const Config** config,
                                      std::string* error_msg) {
  g_config.clear();

  std::unordered_map<std::string, PropertyValue> property_map;
  if (!parse_config_file(ld_config_file_path, binary_realpath, &property_map, error_msg)) {
    return false;
  }

  Properties properties(std::move(property_map));

  auto failure_guard = android::base::make_scope_guard([] { g_config.clear(); });

  std::unordered_map<std::string, NamespaceConfig*> namespace_configs;

  namespace_configs[kDefaultConfigName] = g_config.create_namespace_config(kDefaultConfigName);

  std::vector<std::string> additional_namespaces = properties.get_strings(kPropertyAdditionalNamespaces);
  for (const auto& name : additional_namespaces) {
    namespace_configs[name] = g_config.create_namespace_config(name);
  }

  bool versioning_enabled = properties.get_bool("enable.target.sdk.version");
  int target_sdk_version = __ANDROID_API__;
  if (versioning_enabled) {
    std::string version_file = dirname(binary_realpath) + "/.version";
    std::string content;
    if (!android::base::ReadFileToString(version_file, &content)) {
      if (errno != ENOENT) {
        *error_msg = std::string("error reading version file \"") +
                     version_file + "\": " + strerror(errno);
        return false;
      }
    } else {
      content = android::base::Trim(content);
      errno = 0;
      char* end = nullptr;
      const char* content_str = content.c_str();
      int result = strtol(content_str, &end, 10);
      if (errno == 0 && *end == '\0' && result > 0) {
        target_sdk_version = result;
        properties.set_target_sdk_version(target_sdk_version);
      } else {
        *error_msg = std::string("invalid version \"") + version_file + "\": \"" + content +"\"";
        return false;
      }
    }
  }

  g_config.set_target_sdk_version(target_sdk_version);

  for (const auto& ns_config_it : namespace_configs) {
    auto& name = ns_config_it.first;
    NamespaceConfig* ns_config = ns_config_it.second;

    std::string property_name_prefix = std::string("namespace.") + name;

    size_t lineno = 0;
    std::vector<std::string> linked_namespaces =
        properties.get_strings(property_name_prefix + ".links", &lineno);

    for (const auto& linked_ns_name : linked_namespaces) {
      if (!namespace_configs.contains(linked_ns_name)) {
        *error_msg = create_error_msg(ld_config_file_path,
                                      lineno,
                                      std::string("undefined namespace: ") + linked_ns_name);
        return false;
      }

      bool allow_all_shared_libs = properties.get_bool(property_name_prefix + ".link." +
                                                       linked_ns_name + ".allow_all_shared_libs");

      std::string shared_libs = properties.get_string(property_name_prefix +
                                                      ".link." +
                                                      linked_ns_name +
                                                      ".shared_libs", &lineno);

      if (!allow_all_shared_libs && shared_libs.empty()) {
        *error_msg = create_error_msg(ld_config_file_path,
                                      lineno,
                                      std::string("list of shared_libs for ") +
                                      name +
                                      "->" +
                                      linked_ns_name +
                                      " link is not specified or is empty.");
        return false;
      }

      if (allow_all_shared_libs && !shared_libs.empty()) {
        *error_msg = create_error_msg(ld_config_file_path, lineno,
                                      std::string("both shared_libs and allow_all_shared_libs "
                                                  "are set for ") +
                                      name + "->" + linked_ns_name + " link.");
        return false;
      }

      ns_config->add_namespace_link(linked_ns_name, shared_libs, allow_all_shared_libs);
    }

    ns_config->set_isolated(properties.get_bool(property_name_prefix + ".isolated"));
    ns_config->set_visible(properties.get_bool(property_name_prefix + ".visible"));

    std::string allowed_libs =
        properties.get_string(property_name_prefix + ".whitelisted", &lineno);
    const std::string libs = properties.get_string(property_name_prefix + ".allowed_libs", &lineno);
    if (!allowed_libs.empty() && !libs.empty()) {
      allowed_libs += ":";
    }
    allowed_libs += libs;
    if (!allowed_libs.empty()) {
      ns_config->set_allowed_libs(android::base::Split(allowed_libs, ":"));
    }

    // these are affected by is_asan flag
    if (is_asan) {
      property_name_prefix += ".asan";
    } else if (is_hwasan) {
      property_name_prefix += ".hwasan";
    }

    // search paths are resolved (canonicalized). This is required mainly for
    // the case when /vendor is a symlink to /system/vendor, which is true for
    // non Treble-ized legacy devices.
    ns_config->set_search_paths(properties.get_paths(property_name_prefix + ".search.paths", true));

    // However, for permitted paths, we are not required to resolve the paths
    // since they are only set for isolated namespaces, which implies the device
    // is Treble-ized (= /vendor is not a symlink to /system/vendor).
    // In fact, the resolving is causing an unexpected side effect of selinux
    // denials on some executables which are not allowed to access some of the
    // permitted paths.
    ns_config->set_permitted_paths(properties.get_paths(property_name_prefix + ".permitted.paths", false));
  }

  failure_guard.Disable();
  *config = &g_config;
  return true;
}

std::string Config::get_vndk_version_string(const char delimiter) {
  std::string version = android::base::GetProperty("ro.vndk.version", "");
  if (version != "" && version != "current") {
    //add the delimiter char in front of the string and return it.
    return version.insert(0, 1, delimiter);
  }
  return "";
}

NamespaceConfig* Config::create_namespace_config(const std::string& name) {
  namespace_configs_.push_back(std::unique_ptr<NamespaceConfig>(new NamespaceConfig(name)));
  NamespaceConfig* ns_config_ptr = namespace_configs_.back().get();
  namespace_configs_map_[name] = ns_config_ptr;
  return ns_config_ptr;
}

void Config::clear() {
  namespace_configs_.clear();
  namespace_configs_map_.clear();
}

"""

```