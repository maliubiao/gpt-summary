Response:
Let's break down the thought process for analyzing the `check-symbols-glibc.py` script and generating the detailed answer.

**1. Understanding the Goal:**

The first step is to understand the script's fundamental purpose. The filename and the initial comments clearly indicate it's related to checking symbols in bionic (Android's C library) against those in glibc (a common Linux C library). The presence of "unwanted symbols" and NDK-related functions hints at ensuring compatibility and controlling the exposed API surface.

**2. Deconstructing the Script - High Level:**

Next, I'd mentally walk through the script's main sections:

* **Imports:**  Identify the necessary Python modules (`glob`, `os`, `re`, `sys`, `symbols`). This gives clues about file system operations, regular expressions, and external symbol data.
* **Configuration:**  Look for variables like `only_unwanted`, `toolchain`, `arch`. These configure the script's behavior and target architecture.
* **Helper Functions:**  Analyze functions like `MangleGlibcNameToBionic` and `GetNdkIgnored`. These perform specific tasks related to symbol naming and ignoring certain symbols.
* **Data Acquisition:**  Focus on how the script gathers symbol lists using functions like `symbols.GetFromSystemSo`, `symbols.GetFromAndroidSo`, and `symbols.GetFromTxt`. This is crucial for understanding the data the script operates on.
* **Symbol Sets:** Notice the creation of various sets like `glibc`, `bionic`, `posix`, `ndk_ignored`, `bsd_stuff`, `FORTIFY_stuff`, etc. These sets represent different categories of symbols, indicating the script's intention to compare and categorize them.
* **Set Operations:** Pay attention to set operations like `-` (difference), `intersection`, and `union` (`|`). These operations are the core logic for comparing and filtering symbol sets.
* **Output:**  See how the script prints the results based on the set operations. This reveals what discrepancies the script is designed to find.

**3. Deeper Dive - Function by Function:**

Now, go through each function in detail:

* **`MangleGlibcNameToBionic(name)`:** This is a simple renaming function, likely to account for minor naming differences between glibc and bionic. The `glibc_to_bionic_names` dictionary is key here.
* **`GetNdkIgnored(arch)`:** This function reads a list of ignored symbols for a specific architecture from files under the `ndk/build/tools/unwanted-symbols` directory. This signifies the NDK's influence on the exposed symbols.

**4. Analyzing Symbol Acquisition:**

* **`symbols.GetFromSystemSo(...)`:** This suggests fetching symbols from shared libraries on the system (likely the host system where the script is run). The provided glob patterns indicate the specific glibc libraries.
* **`symbols.GetFromAndroidSo(...)`:** This suggests fetching symbols from Android's shared libraries. The specific libraries are `libc.so` and `libm.so`.
* **`symbols.GetFromTxt(...)`:** This implies reading symbols from a text file (`posix-2013.txt`). This is likely a list of POSIX standard symbols.

**5. Understanding the Symbol Sets and Comparisons:**

* **`glibc`:** Symbols from standard glibc libraries.
* **`bionic`:** Symbols from Android's `libc.so` and `libm.so`.
* **`posix`:** Symbols defined by the POSIX standard.
* **`ndk_ignored`:** Symbols that are intentionally ignored for NDK compatibility.
* **`allowed_stuff`:** A union of various sets representing acceptable deviations from glibc or POSIX (BSD extensions, FORTIFY, Linux-specific, etc.).

The core comparisons involve finding:

* Symbols in glibc but not in POSIX and not in bionic.
* Symbols in POSIX (and glibc) but not in bionic.
* Symbols in bionic but not in glibc (after excluding the "allowed" deviations).

**6. Connecting to Android Functionality (and Anticipating Questions):**

Now, connect the dots to Android:

* **Bionic as the C library:** This is the fundamental link. The script directly examines bionic's symbols.
* **NDK impact:** The `GetNdkIgnored` function explicitly mentions the NDK. This signifies that the NDK has requirements for which symbols are exposed.
* **Dynamic linker:** The script operates on shared libraries (`.so`), which are loaded and linked by the dynamic linker. This calls for an explanation of dynamic linking.

**7. Anticipating User/Developer Errors:**

Think about common problems when dealing with C libraries:

* **Missing symbols:**  Trying to use a function that isn't provided by bionic.
* **Incorrect symbol names:** Mismatched names due to bionic's naming conventions.

**8. Explaining the "How to Reach Here" - Frida Hooking:**

Consider how Android code execution flows and how you could intercept it:

* **System calls:**  Many libc functions ultimately make system calls.
* **Function calls within libraries:**  Tracing calls within `libc.so` or `libm.so`.
* **Frida as a dynamic instrumentation tool:**  This is the standard tool for such debugging on Android.

**9. Structuring the Answer:**

Organize the findings into clear sections:

* **功能 (Functions):**  Summarize the script's core purpose.
* **与 Android 的关系 (Relationship with Android):** Explain the direct link to bionic and the NDK.
* **libc 函数详解 (Detailed Explanation of libc Functions):**  Acknowledge the impossibility of detailing *every* libc function. Focus on the *type* of functions the script deals with and the general implementation approach.
* **动态链接器功能 (Dynamic Linker Functionality):**  Provide a simplified explanation of dynamic linking, SO layout, and the linking process.
* **逻辑推理 (Logical Deduction):** Create a simple example to illustrate the script's symbol comparison logic.
* **用户或编程常见错误 (Common User/Programming Errors):** Provide examples of typical symbol-related errors.
* **Android Framework/NDK 如何到达这里 (How Android Framework/NDK Reaches Here):** Explain the execution path from app to libc and provide a Frida example.

**10. Refinement and Detail:**

* **Be precise with terminology:** Use terms like "symbol," "shared library," "dynamic linker" correctly.
* **Provide concrete examples:** The Frida hook example and the hypothetical symbol lists make the explanation clearer.
* **Address all parts of the prompt:** Ensure each question in the original request is addressed.
* **Maintain clarity and conciseness:**  While being detailed, avoid unnecessary jargon or overly technical explanations.

By following this thought process, breaking down the script into manageable parts, and connecting it to the broader Android ecosystem, a comprehensive and accurate answer can be generated. The iterative refinement and anticipation of questions are key to creating a helpful explanation.
好的，让我们来详细分析一下 `bionic/libc/tools/check-symbols-glibc.py` 这个 Python 脚本的功能和它与 Android 系统的关系。

**脚本功能概览**

这个脚本的主要功能是检查 Android Bionic C 库中的符号（函数、变量等）与 glibc（GNU C 库，Linux 系统常用的 C 库）中的符号之间的差异。它旨在识别以下几种情况：

1. **在 glibc 中存在，但在 Bionic 中缺失的符号：**  这可能意味着 Bionic 尚未实现某些 glibc 的功能，或者 Android 认为某些 glibc 的功能不必要或不适合在 Android 环境中使用。
2. **在 POSIX 标准中定义，且在 glibc 中实现，但在 Bionic 中缺失的符号：**  这可能表明 Bionic 未完全遵循 POSIX 标准，或者有其他考虑因素。
3. **在 Bionic 中存在，但在 glibc 中不存在的符号：** 这通常是 Android 特有的扩展或者为了特定目的而添加的符号。

**脚本的具体步骤：**

1. **导入必要的模块：** `glob`, `os`, `re`, `sys`, `symbols`。其中 `symbols` 模块很可能是 Bionic 项目内部定义的一个模块，用于处理符号信息的获取和解析。
2. **处理命令行参数：**  脚本可以接受一个可选的参数 `-u` 或 `--unwanted`，如果提供，则只打印 Bionic 中存在但不在 glibc 中的符号。
3. **获取工具链信息：** 从环境变量 `ANDROID_TOOLCHAIN` 中获取当前使用的 Android 工具链路径，并从中提取目标架构 (`arch`)。
4. **定义辅助函数：**
   - `MangleGlibcNameToBionic(name)`:  用于将 glibc 的符号名称转换为 Bionic 中可能使用的名称。例如，某些以双下划线开头的 glibc 函数在 Bionic 中可能只有一个下划线。
   - `GetNdkIgnored(arch)`:  获取 NDK (Native Development Kit) 中明确声明为“不需要的”符号列表。这些符号即使在 Bionic 中存在，也不会被视为问题。
5. **定义 glibc 到 Bionic 的名称映射：**  `glibc_to_bionic_names` 字典定义了一些 glibc 符号在 Bionic 中的对应名称。
6. **获取 glibc 的符号列表：**  使用 `symbols.GetFromSystemSo()` 函数从系统中的 glibc 共享库（如 `libc.so`, `librt.so` 等）中提取符号。
7. **获取 Bionic 的符号列表：** 使用 `symbols.GetFromAndroidSo()` 函数从 Android 系统中的 Bionic 共享库 (`libc.so`, `libm.so`) 中提取符号。
8. **获取 POSIX 标准的符号列表：** 使用 `symbols.GetFromTxt()` 函数从名为 `posix-2013.txt` 的文件中读取 POSIX 标准定义的符号。
9. **获取 NDK 忽略的符号列表：** 调用 `GetNdkIgnored(arch)` 获取当前架构下 NDK 声明要忽略的符号。
10. **预处理 glibc 符号：** 将 glibc 的符号名称映射到可能的 Bionic 名称。
11. **定义各种类型的符号集合：**  脚本定义了多个集合，用于表示不同来源或性质的符号：
    - `bsd_stuff`:  Bionic 中包含的 BSD 相关的符号。
    - `FORTIFY_stuff`:  Bionic 中实现的 FORTIFY 保护机制相关的符号。
    - `macro_stuff`:  Bionic 中用于实现公共函数/宏的符号。
    - `linux_stuff`:  Bionic 中暴露的 Linux 特有功能符号。
    - `std_stuff`:  在当前 glibc 版本中不存在但在后续标准中定义的符号。
    - `weird_stuff`:  在 glibc 中有不同命名的符号。
    - `libresolv_stuff`:  `libresolv` 库中一些命名不同的符号。
    - `known`:  已知 Bionic 导出的实现细节符号。
    - `in_posix_and_glibc_but_dead_or_useless`:  在 POSIX 和 glibc 中定义，但在现代系统中不常用或无法使用的符号。
12. **从 glibc 和 POSIX 符号集中排除无用符号：** 移除 `in_posix_and_glibc_but_dead_or_useless` 中的符号。
13. **执行符号比较和打印结果：**
    - 如果 `only_unwanted` 为 False（默认情况）：
        - 打印在 glibc 中存在（但不在 POSIX 标准中）且不在 Bionic 中的符号。
        - 打印在 POSIX 标准中定义（且在 glibc 中实现）但不在 Bionic 中的符号。
        - 打印在 Bionic 中存在但不在 glibc 中的符号（减去一些被认为是允许的差异，例如 BSD 扩展等）。
    - 如果 `only_unwanted` 为 True：
        - 只打印在 Bionic 中存在但不在 glibc 中的符号（减去允许的差异），并在 NDK 忽略的符号后面加上 `*`。

**它与 Android 功能的关系及举例说明**

这个脚本直接关系到 Android 系统最核心的组成部分——Bionic C 库。Bionic 提供了 Android 系统运行所需的各种基本 C 库函数，包括：

* **标准 C 库函数:** 例如 `printf`, `malloc`, `memcpy`, `fopen` 等，用于进行输入输出、内存管理、字符串操作、文件操作等。
* **POSIX 标准相关的函数:** 例如线程管理 (`pthread_create`, `pthread_mutex_lock`)、信号处理 (`signal`, `sigaction`)、进程控制 (`fork`, `exec`) 等，保证一定的系统兼容性。
* **网络相关的函数:** 例如 socket 编程接口 (`socket`, `bind`, `connect`)、DNS 解析 (`getaddrinfo`) 等。
* **数学函数:** 例如 `sin`, `cos`, `sqrt`, `pow` 等（通常在 `libm.so` 中）。
* **动态链接器相关的函数:**  虽然脚本本身不直接展示这些函数，但其检查的对象是共享库，这与动态链接器密切相关。

**举例说明：**

* **`res_init` 函数:**  在 `glibc_to_bionic_names` 中可以看到 `__res_init` 映射到 `res_init`。 `res_init` 函数用于初始化 DNS 解析器。Android 应用或系统服务进行网络请求时，如果需要将域名解析为 IP 地址，通常会间接调用到这个函数。Bionic 提供的 `res_init` 实现了 DNS 解析的功能，使得 Android 设备能够连接到互联网。
* **`pthread_gettid_np` 函数:**  在 `linux_stuff` 中可以看到这个函数。这是一个 Linux 特有的函数，用于获取线程的 ID。Android 系统大量使用了多线程，例如在处理用户界面、执行后台任务等。Bionic 提供 `pthread_gettid_np` 使得 Android 开发者可以使用这个 Linux 特有的线程 ID 获取方法。
* **`arc4random` 函数:**  在 `bsd_stuff` 中可以看到。这是一个生成高质量伪随机数的函数，源自 BSD 系统。Android 使用它来提供更安全的随机数生成能力，例如在加密操作中。

**libc 函数的功能及其实现**

由于 libc 函数数量庞大，逐一解释每个函数的功能和实现是不现实的。但可以概述一下 libc 函数的实现方式：

* **系统调用封装:**  许多 libc 函数是对操作系统提供的系统调用的封装。例如，`open` 函数最终会调用内核的 `open` 系统调用来打开文件。Bionic 的实现需要确保正确地调用 Android 内核提供的相应系统调用。
* **标准库算法实现:**  一些 libc 函数是标准库中定义的算法实现，例如字符串操作函数 (`strcpy`, `strlen`)、内存操作函数 (`memcpy`, `memmove`) 等。Bionic 需要实现这些算法，并可能根据 Android 平台的特性进行优化。
* **平台相关的实现:**  某些 libc 函数的实现会因操作系统和硬件架构的不同而有所差异。Bionic 需要针对 Android 平台的特定内核和硬件架构进行实现。
* **汇编代码优化:**  为了提高性能，一些关键的 libc 函数可能会使用汇编语言进行优化。

**涉及 dynamic linker 的功能、SO 布局样本和链接处理过程**

`check-symbols-glibc.py` 检查的对象是共享库 (`.so`) 的符号，这直接涉及到动态链接器 (`linker` 或 `ld-linux.so` 在 Linux 上，`linker64` 或 `linker` 在 Android 上)。

**SO 布局样本 (以 `libc.so` 为例):**

一个典型的共享库文件（例如 `libc.so`）包含以下主要部分：

```
ELF Header:
  ... # 包含文件类型、目标架构、入口点等信息
Program Headers:
  ... # 描述了如何将文件加载到内存，例如代码段、数据段、动态链接段等
Section Headers:
  ... # 描述了文件中的各个节（section），例如 .text（代码）、.data（已初始化数据）、.bss（未初始化数据）、.symtab（符号表）、.dynsym（动态符号表）、.rel.dyn（动态重定位表）、.rel.plt（PLT 重定位表）等
.text:  # 代码段，包含函数的可执行指令
.rodata: # 只读数据段，包含常量字符串等
.data:   # 已初始化数据段，包含全局变量的初始值
.bss:    # 未初始化数据段，全局变量在运行时分配空间
.symtab: # 符号表，包含所有符号的定义（函数名、变量名、地址等）
.dynsym: # 动态符号表，包含共享库导出的和需要导入的符号
.rel.dyn: # 动态重定位表，描述了需要在运行时修改的数据的位置
.rel.plt: # PLT 重定位表，用于延迟绑定（lazy binding）
...
```

**链接的处理过程：**

1. **编译时链接 (Static Linking):**  在编译时，链接器将所有需要的库的代码合并到最终的可执行文件中。Android 系统主要使用动态链接，静态链接较少使用。
2. **动态链接 (Dynamic Linking):**
   - **加载时链接 (Load-time Linking):** 当 Android 系统加载一个可执行文件或共享库时，动态链接器会执行以下操作：
     - **加载依赖库:**  根据可执行文件或共享库的依赖关系（记录在 ELF 头的 `DT_NEEDED` 条目中），加载所需的其他共享库。
     - **符号查找:**  当程序调用一个在外部共享库中定义的函数时，动态链接器需要在这些库中找到该符号的地址。
     - **重定位 (Relocation):**  由于共享库加载到内存的地址可能是不固定的，动态链接器需要修改代码和数据段中引用外部符号的地址，使其指向正确的内存位置。
   - **运行时链接 (Run-time Linking):**  延迟绑定是一种优化技术，即只有在函数第一次被调用时才解析其地址。这通过过程链接表 (PLT) 和全局偏移表 (GOT) 来实现。当第一次调用外部函数时，会跳转到 PLT 中的一段代码，该代码会调用动态链接器来解析符号地址并更新 GOT 表项，后续的调用将直接从 GOT 表中获取地址。

**`check-symbols-glibc.py` 在此过程中的作用：**

这个脚本确保了 Bionic 提供的符号与 glibc（作为参考）和 POSIX 标准保持一定的兼容性，并且控制了 Bionic 导出的符号集合，避免导出不必要的内部实现细节。这对于保证 Android 系统的稳定性和安全性至关重要。

**逻辑推理的假设输入与输出**

假设 `bionic/libc/tools/symbols.py` 模块提供了从 SO 文件中提取符号的功能，并且 `posix-2013.txt` 文件包含了 POSIX 标准的符号列表。

**假设输入：**

* `glibc` 符号集合：`{'printf', 'malloc', 'open', 'pthread_create', 'gettid'}`
* `bionic` 符号集合：`{'printf', 'malloc', 'open', 'pthread_create', 'pthread_gettid_np'}`
* `posix` 符号集合：`{'printf', 'malloc', 'open', 'pthread_create'}`

**预期输出 (在默认情况下，即 `only_unwanted` 为 False):**

```
in glibc (but not posix) but not bionic:
gettid

in posix (and implemented in glibc) but not bionic:

in bionic but not glibc:
pthread_gettid_np
```

**解释：**

* `gettid` 在 glibc 中存在，但不在 POSIX 标准中，且不在 Bionic 中。
* 所有在 POSIX 中定义的，且在 glibc 中实现的符号，也都存在于 Bionic 中。
* `pthread_gettid_np` 在 Bionic 中存在，但不在 glibc 中。

**用户或编程常见的使用错误**

* **使用了 Bionic 中不存在的 glibc 函数：**  开发者可能会习惯性地使用某些在 Linux 系统上常用的 glibc 函数，但这些函数可能没有在 Bionic 中实现。例如，某些高级的文件操作函数或者特定的网络协议函数。这会导致链接错误或者运行时找不到符号的错误。
   ```c
   #include <stdio.h>
   #include < Shadowed by graphdump >

   int main() {
       // error: undefined reference to 'canonicalize_file_name'
       char *abs_path = canonicalize_file_name("./myfile.txt");
       if (abs_path) {
           printf("Absolute path: %s\n", abs_path);
           free(abs_path);
       }
       return 0;
   }
   ```
   `canonicalize_file_name` 是 glibc 中的函数，但可能不在所有版本的 Bionic 中提供。

* **假设了符号的存在而没有进行检查：**  开发者可能会直接使用某个函数，而没有考虑到该函数可能在某些 Android 版本或架构上不可用。

* **使用了 NDK 中被标记为 "unwanted" 的符号：**  虽然这些符号可能存在于 Bionic 中，但在使用 NDK 进行开发时，应该避免使用这些符号，因为它们可能不稳定或有其他问题。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤**

1. **Android Framework 或应用层代码调用 C 库函数：**  例如，Java 代码通过 JNI (Java Native Interface) 调用 native 方法，这些 native 方法通常会调用 Bionic 提供的 C 库函数。例如，`java.io.File` 类的一些操作最终会调用 Bionic 的文件操作函数。

2. **NDK 开发：** 使用 NDK 进行 native 开发时，开发者直接编写 C/C++ 代码，这些代码链接到 Bionic 提供的共享库。

3. **动态链接器加载共享库并解析符号：**  当应用启动或加载 so 库时，动态链接器负责查找和链接所需的符号。

**Frida hook 示例调试步骤：**

假设我们想调试 `open` 函数的调用。

```python
import frida
import sys

package_name = "com.example.myapp" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        console.log("[*] open called");
        console.log("    pathname: " + Memory.readUtf8String(args[0]));
        console.log("    flags: " + args[1]);
    },
    onLeave: function(retval) {
        console.log("[*] open returned");
        console.log("    retval: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida 代码：**

1. **导入 Frida 模块。**
2. **指定要 hook 的应用的包名。**
3. **定义消息处理函数 `on_message`，用于打印 Frida 发送的消息。**
4. **尝试连接到目标应用进程。**
5. **编写 Frida 脚本 `script_code`：**
   - 使用 `Interceptor.attach` 拦截 `libc.so` 中的 `open` 函数。
   - `onEnter` 函数在 `open` 函数调用之前执行，打印调用的参数（文件路径和标志）。
   - `onLeave` 函数在 `open` 函数返回之后执行，打印返回值（文件描述符）。
6. **创建 Frida 脚本对象并加载到会话中。**
7. **保持脚本运行，直到用户手动停止。**

**调试步骤：**

1. 确保你的 Android 设备已连接并通过 USB 调试。
2. 确保你的 PC 上已安装 Frida 和 frida-tools。
3. 将上面的 Python 代码保存为 `hook_open.py`。
4. 启动目标 Android 应用 (`com.example.myapp`)。
5. 在 PC 上运行 `python hook_open.py`。
6. 在 Android 应用中执行会调用 `open` 函数的操作（例如打开文件）。
7. 你将在 PC 的终端上看到 Frida 打印出的 `open` 函数的调用信息，包括文件名和标志。

通过这种方式，你可以使用 Frida 动态地观察和调试 Android Framework 或应用层代码如何一步步调用到 Bionic 的 C 库函数。这对于理解系统行为、排查问题非常有帮助。

希望以上详细的解释能够帮助你理解 `check-symbols-glibc.py` 脚本的功能及其在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/tools/check-symbols-glibc.pyandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```python
#!/usr/bin/env python3
#
# Copyright (C) 2015 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# pylint: disable=bad-indentation,bad-continuation
import glob
import os
import re
import sys

import symbols

only_unwanted = False
if len(sys.argv) > 1:
  if sys.argv[1] in ('-u', '--unwanted'):
    only_unwanted = True

toolchain = os.environ['ANDROID_TOOLCHAIN']
arch = re.sub(r'.*/linux-x86/([^/]+)/.*', r'\1', toolchain)
if arch == 'aarch64':
  arch = 'arm64'

def MangleGlibcNameToBionic(name):
  if name in glibc_to_bionic_names:
    return glibc_to_bionic_names[name]
  return name

def GetNdkIgnored(arch):  # pylint: disable=redefined-outer-name
  ignored_symbols = set()
  files = glob.glob('%s/ndk/build/tools/unwanted-symbols/%s/*' %
                    (os.getenv('ANDROID_BUILD_TOP'), arch))
  for f in files:
    ignored_symbols |= set(open(f, 'r').read().splitlines())
  return ignored_symbols

glibc_to_bionic_names = {
  '__res_init': 'res_init',
  '__res_mkquery': 'res_mkquery',
  '__res_query': 'res_query',
  '__res_search': 'res_search',
  '__xpg_basename': '__gnu_basename',
}

glibc = symbols.GetFromSystemSo([
    'libc.so.*',
    'librt.so.*',
    'libpthread.so.*',
    'libresolv.so.*',
    'libm.so.*',
    'libutil.so.*',
])

bionic = symbols.GetFromAndroidSo(['libc.so', 'libm.so'])
this_dir = os.path.dirname(os.path.realpath(__file__))
posix = symbols.GetFromTxt(os.path.join(this_dir, 'posix-2013.txt'))
ndk_ignored = GetNdkIgnored(arch)

glibc = set(map(MangleGlibcNameToBionic, glibc))

# bionic includes various BSD symbols to ease porting other BSD-licensed code.
bsd_stuff = set([
  'arc4random',
  'arc4random_buf',
  'arc4random_uniform',
  'basename_r',
  'dirname_r',
  'fgetln',
  'fpurge',
  'funopen',
  'funopen64',
  'gamma_r',
  'gammaf_r',
  'getprogname',
  'setprogname',
  'strlcat',
  'strlcpy',
  'sys_signame',
  'wcslcat',
  'wcslcpy',
])
# Some symbols are part of the FORTIFY implementation.
FORTIFY_stuff = set([
  '__FD_CLR_chk',
  '__FD_ISSET_chk',
  '__FD_SET_chk',
  '__fwrite_chk',
  '__memchr_chk',
  '__memrchr_chk',
  '__pwrite64_chk',
  '__pwrite_chk',
  '__sendto_chk',
  '__stack_chk_guard',
  '__stpncpy_chk2',
  '__strchr_chk',
  '__strlcat_chk',
  '__strlcpy_chk',
  '__strlen_chk',
  '__strncpy_chk2',
  '__strrchr_chk',
  '__umask_chk',
  '__write_chk',
])
# Some symbols are used to implement public functions/macros.
macro_stuff = set([
  '__assert2',
  '__errno',
  '__fe_dfl_env',
  '__get_h_errno',
  '__gnu_strerror_r',
  '__fpclassifyd',
  '__isfinite',
  '__isfinitef',
  '__isfinitel',
  '__isnormal',
  '__isnormalf',
  '__isnormall',
  '__sF',
  '__pthread_cleanup_pop',
  '__pthread_cleanup_push',
])
# bionic exposes various Linux features that glibc doesn't.
linux_stuff = set([
  'getauxval',
  'gettid',
  'pthread_gettid_np',
  'tgkill',
])
# Some standard stuff isn't yet in the versions of glibc we're using.
std_stuff = set([
  'at_quick_exit',
  'c16rtomb',
  'c32rtomb',
  'mbrtoc16',
  'mbrtoc32',
])
# These have mangled names in glibc, with a macro taking the "obvious" name.
weird_stuff = set([
  'fstat',
  'fstat64',
  'fstatat',
  'fstatat64',
  'isfinite',
  'isfinitef',
  'isfinitel',
  'isnormal',
  'isnormalf',
  'isnormall',
  'lstat',
  'lstat64',
  'mknod',
  'mknodat',
  'stat',
  'stat64',
  'optreset',
  'sigsetjmp',
])
# These exist in glibc, but under slightly different names (generally one extra
# or one fewer _). TODO: check against glibc names.
libresolv_stuff = set([
  '__res_send_setqhook',
  '__res_send_setrhook',
  '_resolv_delete_cache_for_net',
  '_resolv_flush_cache_for_net',
  '_resolv_set_nameservers_for_net',
  'dn_expand',
  'nsdispatch',
])
# Implementation details we know we export (and can't get away from).
known = set([
  '_ctype_',
  '__libc_init',
])
# POSIX has some stuff that's unusable in the modern world (a64l) or not
# actually implemented in glibc unless you count always failing with ENOSYS
# as being implemented (fattach). Other stuff (fmtmsg) isn't used in any
# codebase I have access to, internal or external.
in_posix_and_glibc_but_dead_or_useless = set([
  'a64l', # obsolete
  'confstr', # obsolete
  'endutxent', # no utmp on Android
  'fattach', # <stropts.h> marked obsolescent
  'fdetach', # <stropts.h> marked obsolescent
  'fmtmsg', # unused
  'getdate', # unused
  'getdate_err', # unused
  'gethostid', # obsolete
  'getmsg', # <stropts.h> marked obsolescent
  'getpmsg', # <stropts.h> marked obsolescent
  'getutxent', # no utmp on Android
  'getutxid', # no utmp on Android
  'getutxline', # no utmp on Android
  'isastream', # <stropts.h> marked obsolescent
  'l64a', # obsolete
  'mq_close', # disallowed by SELinux
  'mq_getattr', # disallowed by SELinux
  'mq_notify', # disallowed by SELinux
  'mq_open', # disallowed by SELinux
  'mq_receive', # disallowed by SELinux
  'mq_send', # disallowed by SELinux
  'mq_setattr', # disallowed by SELinux
  'mq_timedreceive', # disallowed by SELinux
  'mq_timedsend', # disallowed by SELinux
  'mq_unlink', # disallowed by SELinux
  'pthread_getconcurrency', # marked obsolescent
  'pthread_setconcurrency', # marked obsolescent
  'putmsg', # <stropts.h> marked obsolescent
  'putpmsg', # <stropts.h> marked obsolescent
  'pututxline', # no utmp on Android
  'shm_open', # disallowed by SELinux
  'shm_unlink', # disallowed by SELinux
  'setutxent', # no utmp on Android
  'sockatmark', # obsolete (https://tools.ietf.org/html/rfc6093)
  'strfmon', # icu4c
  'strfmon_l', # icu4c
  'ulimit', # <ulimit.h> marked obsolescent
])

posix = posix - in_posix_and_glibc_but_dead_or_useless
glibc = glibc - in_posix_and_glibc_but_dead_or_useless

if not only_unwanted:
  #print('glibc:')
  #for symbol in sorted(glibc):
  #  print(symbol)
  #print()

  #print('bionic:')
  #for symbol in sorted(bionic):
  #  print(symbol)
  #print()

  print('in glibc (but not posix) but not bionic:')
  for symbol in sorted((glibc - posix).difference(bionic)):
    print(symbol)
  print()

  print('in posix (and implemented in glibc) but not bionic:')
  for symbol in sorted((posix.intersection(glibc)).difference(bionic)):
    print(symbol)
  print()

  print('in bionic but not glibc:')

allowed_stuff = (bsd_stuff | FORTIFY_stuff | linux_stuff | macro_stuff |
                 std_stuff | weird_stuff | libresolv_stuff | known)
for symbol in sorted((bionic - allowed_stuff).difference(glibc)):
  if symbol in ndk_ignored:
    symbol += '*'
  print(symbol)

sys.exit(0)
```