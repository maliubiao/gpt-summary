Response:
Let's break down the thought process for analyzing this Python script.

1. **Understanding the Core Purpose:** The very first thing to recognize is the filename: `genseccomp.py`. "gen" strongly suggests "generate," and "seccomp" points to the Linux Secure Computing mode. Therefore, the script likely generates seccomp policies. The comment about bionic reinforces that it's for Android's C library.

2. **Identifying Key Inputs:**  The `main()` function and the command-line arguments are crucial. The script takes several file paths as input:
    * `base_file`:  Likely the fundamental list of syscalls.
    * `files`:  A collection of files, differentiated by naming conventions (blocklist, allowlist, priority) or their content (syscall name-number mappings).
    * `--name-modifier` and `--out-dir`:  Control the output file naming and location.

3. **Tracing the Data Flow:**  Now, follow how the input files are processed:
    * **`load_syscall_names_from_file`**:  Extracts syscall names from allowlists and blocklists. The `SysCallsTxtParser` suggests a specific format for these files.
    * **`load_syscall_priorities_from_file`**: Extracts priority syscall names.
    * **`parse_syscall_NRs`**:  This is key. It parses preprocessed C header files to find the numerical values (NRs) associated with syscall names. The regular expressions here are vital for understanding the expected format. The handling of `__NR3264_*` is an important detail.
    * **`merge_names`**: Combines base syscalls with allowlists and removes blocklisted syscalls. This establishes the set of permitted syscalls.
    * **`extract_priority_syscalls`**: Separates the priority syscalls from the rest.
    * **`convert_NRs_to_ranges`**: Optimizes the list of syscalls by grouping consecutive numbers into ranges. This is done for efficiency in the BPF filter.
    * **`convert_to_intermediate_bpf` and `convert_priority_to_intermediate_bpf`**: These functions generate the core BPF instructions. The recursive nature of `convert_to_intermediate_bpf` for binary tree generation is a significant implementation detail. The use of placeholders `{fail}` and `{allow}` indicates a two-pass process.
    * **`convert_ranges_to_bpf`**:  Combines the priority and range-based BPF, and replaces the placeholders with actual jump offsets.
    * **`convert_bpf_to_output`**: Formats the BPF instructions into a C source file.
    * **`construct_bpf`**: Orchestrates the BPF construction process.
    * **`gen_policy`**:  Manages the entire policy generation for different architectures.

4. **Identifying Key Concepts:**
    * **Seccomp-BPF:**  The script is all about generating BPF (Berkeley Packet Filter) code for use with Linux's seccomp feature. Understanding the basic concepts of BPF (instructions, jumps, return codes) is helpful.
    * **Syscall Numbers:**  The script heavily relies on mapping syscall names to their numerical identifiers.
    * **Allowlisting and Blocklisting:** The script supports specifying allowed and disallowed syscalls.
    * **Prioritization:**  Some syscalls can be prioritized for faster checking in the BPF filter.
    * **Binary Search Tree:** The `convert_to_intermediate_bpf` function effectively builds a binary search tree in BPF instructions for efficient syscall lookup.

5. **Connecting to Android/Bionic:** The script resides within the bionic source tree. This immediately tells us that the generated seccomp policies are intended for processes running within the Android environment, likely using the bionic libc. Examples of processes using seccomp include isolated app processes and system services.

6. **Considering Error Handling and Potential Issues:** The script includes some error handling (e.g., checking for blocklisted items not in the base list). Thinking about common mistakes users might make (incorrect file formats, missing syscall definitions) is important.

7. **Thinking about Dynamic Linking:** While the script itself doesn't directly implement dynamic linking, the *output* (the generated seccomp policies) affects how dynamically linked binaries can behave. Seccomp policies restrict syscalls, which can indirectly impact dynamic linking if required syscalls are blocked. The request for SO layout and linking process requires a bit of inference and understanding of how dynamic linking works in Android.

8. **Frida Hooking (Advanced):**  This requires understanding how seccomp is applied in Android. Key points are identifying the syscalls related to seccomp (like `prctl` with `PR_SET_SECCOMP`) and where these policies are loaded.

9. **Structuring the Answer:**  Organize the information logically:
    * Start with the main function and overall purpose.
    * Explain the functionality of each key function.
    * Relate it to Android with concrete examples.
    * Explain libc function implementations (referring to standard libc functionality).
    * Address the dynamic linker aspect.
    * Provide example inputs and outputs.
    * Discuss common errors.
    * Outline the Android framework/NDK path.
    * Provide a Frida hooking example.

10. **Refinement and Clarity:**  Use clear and concise language. Define any technical terms. Provide code snippets where necessary. Double-check for accuracy and completeness. The iterative process of reading the code, identifying patterns, and then explaining those patterns is key. The prompt specifically asks for *detailed* explanations, so don't just skim the surface.

By following these steps, we can systematically analyze the Python script and generate a comprehensive and accurate explanation. The process involves both code comprehension and a broader understanding of the system the code operates within.
这个Python脚本 `genseccomp.py` 的主要功能是**生成 seccomp (Secure Computing Mode) BPF (Berkeley Packet Filter) 策略**。这些策略用于限制进程可以调用的系统调用，从而提高系统的安全性。由于它位于 `bionic` 目录下，所以是为 Android 系统中的进程生成 seccomp 策略的。

下面详细列举其功能，并结合 Android 功能进行说明：

**1. 加载和解析系统调用信息:**

* **`load_syscall_names_from_file(file_path, architecture)`:**
    * **功能:**  从指定的文件中加载特定架构（如 arm, arm64, x86, x86_64）的系统调用名称。
    * **实现:** 使用 `gensyscalls.SysCallsTxtParser` 解析类似 `SYSCALLS.TXT` 格式的文件，该文件列出了系统调用名称以及它们支持的架构。
    * **Android 举例:**  Android 的 bionic 库中会维护一个 `SYSCALLS.TXT` 文件，列出所有可用的系统调用。这个函数就是读取这个文件，根据目标架构筛选出可用的系统调用名称。例如，如果 `architecture` 是 "arm64"，则只返回在 `SYSCALLS.TXT` 中标记为 "arm64" 的系统调用。

* **`load_syscall_priorities_from_file(file_path)`:**
    * **功能:** 从文件中加载需要优先处理的系统调用名称列表。
    * **实现:**  逐行读取文件，每行一个系统调用名称。
    * **Android 举例:**  在 Android 中，一些常用的系统调用，例如 `gettid` 或 `clock_gettime`，可能会被放在优先级列表中。这样做的好处是，在 seccomp 策略中，会优先检查这些系统调用，如果匹配到，则直接允许执行，从而提高效率。

* **`parse_syscall_NRs(names_path)`:**
    * **功能:** 解析 C 预处理后的头文件，提取系统调用名称和对应的系统调用号 (NR - Number)。
    * **实现:**  读取预处理后的 C 头文件（通常是包含 `__NR_xxx` 或 `__ARM_NR_xxx` 宏定义的文件），使用正则表达式匹配并提取宏定义中的系统调用名称和对应的数值。它还会处理类似 `__NR3264_fcntl` 这样的中间定义。
    * **Android 举例:**  在编译 bionic 库时，会生成包含系统调用号定义的头文件，例如 `asm/unistd_32.h` 和 `asm/unistd_64.h`。这个函数就是解析这些文件，将系统调用名称（如 `openat`）与其对应的系统调用号（如 56）关联起来。

**2. 处理系统调用列表:**

* **`merge_names(base_names, allowlist_names, blocklist_names)`:**
    * **功能:** 合并基础系统调用列表、允许列表和阻止列表，生成最终允许的系统调用列表。
    * **实现:**  它首先检查阻止列表中的系统调用是否都在基础列表中，如果不是则报错。然后，它从基础列表中移除阻止列表中的系统调用，并添加允许列表中的系统调用。
    * **Android 举例:**  Android 可以定义一个基础的系统调用列表，然后针对特定的进程或组件，使用允许列表添加额外的权限，或者使用阻止列表禁止某些危险的系统调用。

* **`extract_priority_syscalls(syscalls, priorities)`:**
    * **功能:**  将系统调用列表分为两部分：优先级高的系统调用和其余的系统调用。
    * **实现:**  遍历所有的系统调用，如果系统调用的名称在优先级列表中，则将其放入优先级高的列表中，并保持在优先级列表中出现的顺序。其余的系统调用放入另一个列表。
    * **Android 举例:**  根据安全需求和性能考虑，可以将一些常用的且风险较低的系统调用设置为高优先级，以便在 seccomp 策略中快速放行。

**3. 将系统调用转换为 BPF 策略:**

* **`convert_NRs_to_ranges(syscalls)`:**
    * **功能:** 将排序后的系统调用号列表转换为连续的范围。
    * **实现:**  将系统调用按照系统调用号排序，然后将连续的系统调用号合并到一个 `SyscallRange` 对象中，以优化 BPF 策略的大小。
    * **Android 举例:**  如果允许 `read`, `write`, `openat` 这三个连续的系统调用，这个函数会将其合并为一个范围，在 BPF 策略中用一个范围判断代替三个独立的判断，提高效率。

* **`convert_to_intermediate_bpf(ranges)`:**
    * **功能:** 将系统调用范围列表转换为中间形式的 BPF 指令。
    * **实现:**  使用递归的方式，将范围列表构建成一个二叉树形式的 BPF 代码。对于单个范围，生成一个 `>=` 的跳转指令。对于多个范围，则将其拆分为两半，递归处理，并添加一个 `>=` 的跳转指令来选择处理哪一半。
    * **逻辑推理:** 假设 `ranges` 包含两个范围 `[(10, 12, ['read']), (15, 17, ['write'])]`。
        * 第一次调用，`half` 为 1，`first` 调用 `convert_to_intermediate_bpf([(10, 12, ['read'])])`，返回 `[BPF_JGE.format(12, "{fail}", "{allow}") + ", //read"]`。
        * `second` 调用 `convert_to_intermediate_bpf([(15, 17, ['write'])])`，返回 `[BPF_JGE.format(17, "{fail}", "{allow}") + ", //write"]`。
        * 当前调用返回 `[BPF_JGE.format(15, 1, 0) + ","] + [BPF_JGE.format(12, "{fail}", "{allow}") + ", //read"] + [BPF_JGE.format(17, "{fail}", "{allow}") + ", //write"]`。
    * **假设输入与输出:** 输入：一个包含系统调用范围的列表。输出：一系列 BPF 指令字符串，其中 `{fail}` 和 `{allow}` 是占位符。

* **`convert_priority_to_intermediate_bpf(priority_syscalls)`:**
    * **功能:** 将优先级高的系统调用转换为中间形式的 BPF 指令。
    * **实现:**  为每个优先级高的系统调用生成一个 `==` 的跳转指令，如果匹配到该系统调用，则直接跳转到允许执行的指令。
    * **Android 举例:**  对于优先级高的 `gettid` 系统调用，会生成类似 `BPF_JEQ.format(系统调用号, "{allow}", 0) + ", //gettid"` 的指令。

* **`convert_ranges_to_bpf(ranges, priority_syscalls)`:**
    * **功能:** 将所有中间形式的 BPF 指令组合起来，并替换占位符。
    * **实现:**  先将优先级高的系统调用的 BPF 指令添加到结果中，然后添加范围查询的 BPF 指令。最后，将 `{fail}` 和 `{allow}` 占位符替换为实际的跳转偏移量。还在开头添加了一个边界检查，确保系统调用号不小于第一个允许的系统调用号。
    * **逻辑推理:** 假设中间 BPF 指令列表为 `[..., BPF_JGE.format(12, "{fail}", "{allow}"), ...]`，最终会计算出从当前指令到 `allow` 和 `fail` 代码块的距离，并替换占位符。

* **`convert_bpf_to_output(bpf, architecture, name_modifier)`:**
    * **功能:** 将 BPF 指令列表转换为 C 代码格式的数组。
    * **实现:**  生成包含 `#include` 和 `const sock_filter` 数组定义的 C 代码，将 BPF 指令格式化为 `BPF_STMT` 和 `BPF_JUMP` 宏。
    * **Android 举例:**  最终会生成一个 `.cpp` 文件，其中定义了一个名为 `架构_策略名_filter` 的 `sock_filter` 数组，包含了生成的 BPF 指令。

* **`construct_bpf(syscalls, architecture, name_modifier, priorities)`:**
    * **功能:**  协调整个 BPF 策略生成过程。
    * **实现:**  调用上述的各个函数，依次完成系统调用列表的加载、处理和转换为 BPF 代码。

**4. 生成策略文件:**

* **`gen_policy(name_modifier, out_dir, base_syscall_file, syscall_files, syscall_NRs, priority_file)`:**
    * **功能:**  根据不同的架构生成对应的 seccomp 策略文件。
    * **实现:**  遍历所有支持的架构，加载对应的系统调用信息、允许列表、阻止列表和优先级列表，合并生成最终的允许系统调用列表，然后调用 `construct_bpf` 生成 BPF 代码，并将结果写入到指定的输出目录中。
    * **Android 举例:**  会为 `arm`, `arm64`, `x86`, `x86_64` 等不同的架构分别生成对应的策略文件，例如 `arm_app_policy.cpp`, `arm64_app_policy.cpp` 等。

**5. 主函数 `main()`:**

* **功能:**  解析命令行参数，调用 `gen_policy` 函数生成 seccomp 策略。
* **实现:**  使用 `argparse` 模块解析命令行参数，包括输出目录、基础系统调用列表文件、允许/阻止列表文件、优先级文件等。然后调用 `gen_policy` 函数执行策略生成。

**与 Android 功能的关系举例:**

* **应用沙箱:** Android 的应用进程通常会应用 seccomp 策略，限制应用可以调用的系统调用，防止恶意应用执行危险操作，例如直接访问硬件或修改系统设置。`genseccomp.py` 生成的策略可以用于限制应用进程的系统调用。
* **系统服务隔离:** Android 的系统服务也可能使用 seccomp 来增强安全性，防止服务被利用执行不希望的操作。例如，mediaserver 可能会有严格的 seccomp 策略。
* **NDK API 限制:**  NDK (Native Development Kit) 提供的 API 实际上是对底层系统调用的封装。Seccomp 策略可以限制 NDK 代码直接调用的系统调用，从而间接限制了 NDK 的功能。

**详细解释 libc 函数的功能是如何实现的:**

`genseccomp.py` 本身是一个 Python 脚本，它**不直接**实现 libc 函数的功能。它的作用是生成用于限制 libc 函数调用的底层系统调用的策略。libc 函数的实现是在 Android 的 bionic 库中，通常是 C 或汇编代码。

例如，如果 seccomp 策略阻止了 `openat` 系统调用，那么 libc 中的 `fopen` 函数（它在内部会调用 `openat`）将无法成功打开文件。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`genseccomp.py` **不直接涉及** dynamic linker 的功能。它的目标是限制进程可以执行的系统调用，这发生在 dynamic linker 完成其链接工作之后，当程序真正开始执行系统调用时。

然而，seccomp 策略可以**间接影响** dynamic linker 的行为。例如，如果策略阻止了 dynamic linker 加载共享库所需的系统调用（例如 `openat`, `mmap`, `execve` 等），那么动态链接过程可能会失败。

**SO 布局样本:**

```
// 假设这是一个简单的共享库 libtest.so

.text          // 代码段
   // ... 函数代码 ...

.data          // 已初始化数据段
   // ... 全局变量 ...

.bss           // 未初始化数据段
   // ... 全局变量 ...

.dynamic       // 动态链接信息
   // ... 指向符号表、重定位表等信息的指针 ...

.symtab        // 符号表
   // ... 包含共享库导出的符号信息 ...

.strtab        // 字符串表
   // ... 包含符号名称等字符串 ...

.rel.dyn       // 数据段重定位表
   // ... 描述如何重定位数据段中的地址 ...

.rel.plt       // PLT 重定位表
   // ... 描述如何重定位过程链接表中的地址 ...
```

**链接的处理过程:**

1. **加载器 (Loader):** 当一个可执行文件依赖共享库时，操作系统会调用加载器（在 Android 上是 `linker64` 或 `linker`）。
2. **加载共享库:** 加载器会找到并加载所需的共享库到内存中。
3. **符号解析:** 加载器会解析可执行文件和共享库的符号表，找到未定义的符号（通常是函数调用）在哪个共享库中定义。
4. **重定位:**  由于共享库被加载到内存的地址可能不是编译时的地址，加载器会根据重定位表中的信息，修改可执行文件和共享库中需要修改的地址（例如函数指针、全局变量地址）。
5. **PLT/GOT:**  过程链接表 (PLT) 和全局偏移表 (GOT) 用于延迟绑定。最初，GOT 条目指向 PLT 中的一段代码，该代码会调用加载器来解析符号。解析后，GOT 条目会被更新为目标函数的实际地址，后续调用将直接跳转到目标函数。

如果 seccomp 策略阻止了加载器执行某些操作（例如打开共享库文件、映射内存），那么动态链接过程就会失败，程序可能无法启动或在运行时崩溃。

**如果做了逻辑推理，请给出假设输入与输出:**

请参考上面 `convert_to_intermediate_bpf` 函数的逻辑推理示例。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **阻止了关键系统调用:** 如果 seccomp 策略过于严格，阻止了程序运行所必需的系统调用（例如 `read`, `write`, `openat`, `mmap`, `exit_group` 等），会导致程序无法正常运行甚至崩溃。
    * **例子:** 阻止了 `openat` 系统调用，会导致程序无法打开任何文件，libc 中的 `fopen`, `open` 等函数都会失败。
* **架构不匹配:**  使用了为错误架构生成的 seccomp 策略。例如，将为 ARM64 生成的策略应用到 32 位的进程上，会导致系统调用号不匹配，策略无法正常工作。
* **优先级设置不当:**  将大量不常用的系统调用设置为高优先级，会降低 seccomp 策略的效率，因为需要优先检查这些不常用的调用。
* **允许列表和阻止列表冲突:**  在允许列表和阻止列表中同时包含了同一个系统调用，可能会导致意想不到的结果，具体取决于策略处理的顺序。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `genseccomp.py` 的路径:**

1. **定义 Seccomp 策略:**  在 Android Framework 或系统服务中，会定义需要应用的 seccomp 策略。这些策略通常以文本文件（如 allowlist, blocklist）的形式存在。
2. **构建系统:**  在 Android 的构建系统中 (如 Soong 或 Make)，会使用 `genseccomp.py` 脚本将这些文本形式的策略转换为 BPF 代码。
3. **编译到二进制:**  `genseccomp.py` 的输出是 C++ 代码，会被编译成库文件或直接链接到需要应用 seccomp 的进程中。
4. **应用 Seccomp 策略:**  在进程启动时或运行时，Framework 或系统服务会调用相关的系统调用（通常是 `prctl`，使用 `PR_SET_SECCOMP` 操作码）来加载和应用生成的 BPF 策略。

**NDK 到 `genseccomp.py` 的路径:**

NDK 本身不直接使用 `genseccomp.py`。`genseccomp.py` 主要用于构建 Android 系统组件的 seccomp 策略。但是，NDK 开发的应用可能会受到系统默认或进程特定 seccomp 策略的限制。

**Frida Hook 示例调试步骤:**

要调试 seccomp 策略的应用过程，可以使用 Frida Hook `prctl` 系统调用，特别是当 `option` 参数为 `PR_SET_SECCOMP` 时。

```javascript
// Frida script

function hook_prctl() {
  const Prctl = Module.findExportByName(null, "prctl");
  if (Prctl) {
    Interceptor.attach(Prctl, {
      onEnter: function (args) {
        const option = args[0].toInt32();
        const arg2 = args[1].toInt32();
        const arg3 = args[2];

        const PR_SET_SECCOMP = 38;
        const SECCOMP_MODE_FILTER = 2;

        if (option === PR_SET_SECCOMP) {
          console.log("prctl called with PR_SET_SECCOMP");
          console.log("  mode:", arg2);
          if (arg2 === SECCOMP_MODE_FILTER) {
            console.log("  filter address:", arg3);

            // 可以进一步读取 filter 数据结构
            const sock_filter_ptr = ptr(arg3).readPointer();
            // 假设你知道 sock_filter 结构的大小
            // 可以遍历读取 BPF 指令
          }
        }
      },
    });
  } else {
    console.log("Could not find prctl export");
  }
}

setTimeout(hook_prctl, 0);
```

**调试步骤:**

1. **找到目标进程:**  确定你想要调试的进程，该进程应该会应用 seccomp 策略。
2. **运行 Frida:** 使用 Frida 连接到目标进程：`frida -U -f <package_name> -l your_script.js --no-pause` 或 `frida -p <pid> -l your_script.js`.
3. **观察输出:**  Frida 脚本会 hook `prctl` 系统调用，并打印出相关的参数。当看到 `prctl called with PR_SET_SECCOMP` 时，说明 seccomp 策略正在被应用。
4. **分析 Filter 数据:**  如果 `mode` 是 `SECCOMP_MODE_FILTER`，则可以尝试读取 `filter address` 指向的内存，解析 `sock_filter` 结构，从而查看具体的 BPF 指令。这需要对 BPF 结构有一定的了解。

通过 Frida Hook，你可以观察到哪些进程在应用 seccomp 策略，以及策略的具体内容，从而更好地理解 `genseccomp.py` 生成的策略是如何被使用的。

### 提示词
```
这是目录为bionic/libc/tools/genseccomp.pyandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

import argparse
import logging
import operator
import os
import re
import sys
import textwrap

from gensyscalls import SysCallsTxtParser


BPF_JGE = "BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, {0}, {1}, {2})"
BPF_JEQ = "BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, {0}, {1}, {2})"
BPF_ALLOW = "BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)"


class SyscallRange:
  def __init__(self, name, value):
    self.names = [name]
    self.begin = value
    self.end = self.begin + 1

  def __str__(self):
    return "(%s, %s, %s)" % (self.begin, self.end, self.names)

  def add(self, name, value):
    if value != self.end:
      raise ValueError
    self.end += 1
    self.names.append(name)


def load_syscall_names_from_file(file_path, architecture):
  parser = SysCallsTxtParser()
  parser.parse_open_file(open(file_path))
  return {x["name"] for x in parser.syscalls if x.get(architecture)}


def load_syscall_priorities_from_file(file_path):
  format_re = re.compile(r'^\s*([A-Za-z_][A-Za-z0-9_]+)\s*$')
  priorities = []
  with open(file_path) as priority_file:
    for line in priority_file:
      match = format_re.match(line)
      if match is None:
        continue
      try:
        name = match.group(1)
        priorities.append(name)
      except IndexError:
        # TODO: This should be impossible becauase it wouldn't have matched?
        logging.exception('Failed to parse %s from %s', line, file_path)

  return priorities


def merge_names(base_names, allowlist_names, blocklist_names):
  if bool(blocklist_names - base_names):
    raise RuntimeError("blocklist item not in bionic - aborting " + str(
        blocklist_names - base_names))

  return (base_names - blocklist_names) | allowlist_names


def extract_priority_syscalls(syscalls, priorities):
  # Extract syscalls that are not in the priority list
  other_syscalls = \
    [syscall for syscall in syscalls if syscall[0] not in priorities]
  # For prioritized syscalls, keep the order in which they appear in th
  # priority list
  syscall_dict = {syscall[0]: syscall[1] for syscall in syscalls}
  priority_syscalls = []
  for name in priorities:
    if name in syscall_dict.keys():
      priority_syscalls.append((name, syscall_dict[name]))
  return priority_syscalls, other_syscalls


def parse_syscall_NRs(names_path):
  # The input is now the preprocessed source file. This will contain a lot
  # of junk from the preprocessor, but our lines will be in the format:
  #
  #    #define __(ARM_)?NR_${NAME} ${VALUE}
  #
  # Where ${VALUE} is a preprocessor expression.
  #
  # Newer architectures have things like this though:
  #
  #    #define __NR3264_fcntl 25
  #    #define __NR_fcntl __NR3264_fcntl
  #
  # So we need to keep track of the __NR3264_* constants and substitute them.

  line_re = re.compile(r'^# \d+ ".*".*')
  undef_re = re.compile(r'^#undef\s.*')
  define_re = re.compile(r'^\s*#define\s+([A-Za-z0-9_(,)]+)(?:\s+(.+))?\s*$')
  token_re = re.compile(r'\b[A-Za-z_][A-Za-z0-9_]+\b')
  constants = {}
  nr3264s = {}
  with open(names_path) as f:
    for line in f:
      line = line.strip()
      m = define_re.match(line)
      if m:
        name = m.group(1)
        value = m.group(2)
        if name.startswith('__NR3264'):
          nr3264s[name] = value
        elif name.startswith('__NR_') or name.startswith('__ARM_NR_'):
          if value in nr3264s:
            value = nr3264s[value]
          # eval() takes care of any arithmetic that may be done
          value = eval(token_re.sub(lambda x: str(constants[x.group(0)]), value))

          constants[name] = value
      else:
        if not line_re.match(line) and not undef_re.match(line) and line:
          print('%s: failed to parse line `%s`' % (names_path, line))
          sys.exit(1)

  syscalls = {}
  for name, value in constants.items():
    # Remove the __NR_ prefix.
    # TODO: why not __ARM_NR too?
    if name.startswith("__NR_"):
      name = name[len("__NR_"):]
    syscalls[name] = value

  return syscalls


def convert_NRs_to_ranges(syscalls):
  # Sort the values so we convert to ranges and binary chop
  syscalls = sorted(syscalls, key=operator.itemgetter(1))

  # Turn into a list of ranges. Keep the names for the comments
  ranges = []
  for name, value in syscalls:
    if not ranges:
      ranges.append(SyscallRange(name, value))
      continue

    last_range = ranges[-1]
    if last_range.end == value:
      last_range.add(name, value)
    else:
      ranges.append(SyscallRange(name, value))
  return ranges


# Converts the sorted ranges of allowed syscalls to a binary tree bpf
# For a single range, output a simple jump to {fail} or {allow}. We can't set
# the jump ranges yet, since we don't know the size of the filter, so use a
# placeholder
# For multiple ranges, split into two, convert the two halves and output a jump
# to the correct half
def convert_to_intermediate_bpf(ranges):
  if len(ranges) == 1:
    # We will replace {fail} and {allow} with appropriate range jumps later
    return [BPF_JGE.format(ranges[0].end, "{fail}", "{allow}") +
            ", //" + "|".join(ranges[0].names)]

  half = (len(ranges) + 1) // 2
  first = convert_to_intermediate_bpf(ranges[:half])
  second = convert_to_intermediate_bpf(ranges[half:])
  jump = [BPF_JGE.format(ranges[half].begin, len(first), 0) + ","]
  return jump + first + second


# Converts the prioritized syscalls to a bpf list that  is prepended to the
# tree generated by convert_to_intermediate_bpf(). If we hit one of these
# syscalls, shortcut to the allow statement at the bottom of the tree
# immediately
def convert_priority_to_intermediate_bpf(priority_syscalls):
  result = []
  for syscall in priority_syscalls:
    result.append(BPF_JEQ.format(syscall[1], "{allow}", 0) +
                  ", //" + syscall[0])
  return result


def convert_ranges_to_bpf(ranges, priority_syscalls):
  bpf = convert_priority_to_intermediate_bpf(priority_syscalls) + \
    convert_to_intermediate_bpf(ranges)

  # Now we know the size of the tree, we can substitute the {fail} and {allow}
  # placeholders
  for i, statement in enumerate(bpf):
    # Replace placeholder with
    # "distance to jump to fail, distance to jump to allow"
    # We will add a kill statement and an allow statement after the tree
    # With bpfs jmp 0 means the next statement, so the distance to the end is
    # len(bpf) - i - 1, which is where we will put the kill statement, and
    # then the statement after that is the allow statement
    bpf[i] = statement.format(fail=str(len(bpf) - i),
                              allow=str(len(bpf) - i - 1))

  # Add the allow calls at the end. If the syscall is not matched, we will
  # continue. This allows the user to choose to match further syscalls, and
  # also to choose the action when we want to block
  bpf.append(BPF_ALLOW + ",")

  # Add check that we aren't off the bottom of the syscalls
  bpf.insert(0, BPF_JGE.format(ranges[0].begin, 0, str(len(bpf))) + ',')
  return bpf


def convert_bpf_to_output(bpf, architecture, name_modifier):
  if name_modifier:
    name_modifier = name_modifier + "_"
  else:
    name_modifier = ""
  header = textwrap.dedent("""\
    // File autogenerated by {self_path} - edit at your peril!!

    #include <linux/filter.h>
    #include <errno.h>

    #include "seccomp/seccomp_bpfs.h"
    const sock_filter {architecture}_{suffix}filter[] = {{
    """).format(self_path=os.path.basename(__file__), architecture=architecture,
                suffix=name_modifier)

  footer = textwrap.dedent("""\

    }};

    const size_t {architecture}_{suffix}filter_size = sizeof({architecture}_{suffix}filter) / sizeof(struct sock_filter);
    """).format(architecture=architecture,suffix=name_modifier)
  return header + "\n".join(bpf) + footer


def construct_bpf(syscalls, architecture, name_modifier, priorities):
  priority_syscalls, other_syscalls = \
    extract_priority_syscalls(syscalls, priorities)
  ranges = convert_NRs_to_ranges(other_syscalls)
  bpf = convert_ranges_to_bpf(ranges, priority_syscalls)
  return convert_bpf_to_output(bpf, architecture, name_modifier)


def gen_policy(name_modifier, out_dir, base_syscall_file, syscall_files,
               syscall_NRs, priority_file):
  for arch in syscall_NRs.keys():
    base_names = load_syscall_names_from_file(base_syscall_file, arch)
    allowlist_names = set()
    blocklist_names = set()
    for f in syscall_files:
      if "blocklist" in f.lower():
        blocklist_names |= load_syscall_names_from_file(f, arch)
      else:
        allowlist_names |= load_syscall_names_from_file(f, arch)
    priorities = []
    if priority_file:
      priorities = load_syscall_priorities_from_file(priority_file)

    allowed_syscalls = []
    for name in sorted(merge_names(base_names, allowlist_names, blocklist_names)):
      try:
        allowed_syscalls.append((name, syscall_NRs[arch][name]))
      except:
        logging.exception("Failed to find %s in %s (%s)", name, arch, syscall_NRs[arch])
        raise
    output = construct_bpf(allowed_syscalls, arch, name_modifier, priorities)

    # And output policy
    filename_modifier = "_" + name_modifier if name_modifier else ""
    output_path = os.path.join(out_dir,
                               "{}{}_policy.cpp".format(arch, filename_modifier))
    with open(output_path, "w") as output_file:
      output_file.write(output)


def main():
  parser = argparse.ArgumentParser(
      description="Generates a seccomp-bpf policy")
  parser.add_argument("--verbose", "-v", help="Enables verbose logging.")
  parser.add_argument("--name-modifier",
                      help=("Specifies the name modifier for the policy. "
                            "One of {app,system}."))
  parser.add_argument("--out-dir",
                      help="The output directory for the policy files")
  parser.add_argument("base_file", metavar="base-file", type=str,
                      help="The path of the base syscall list (SYSCALLS.TXT).")
  parser.add_argument("files", metavar="FILE", type=str, nargs="+",
                      help=("The path of the input files. In order to "
                            "simplify the build rules, it can take any of the "
                            "following files: \n"
                            "* /blocklist.*\\.txt$/ syscall blocklist.\n"
                            "* /allowlist.*\\.txt$/ syscall allowlist.\n"
                            "* /priority.txt$/ priorities for bpf rules.\n"
                            "* otherwise, syscall name-number mapping.\n"))
  args = parser.parse_args()

  if args.verbose:
    logging.basicConfig(level=logging.DEBUG)
  else:
    logging.basicConfig(level=logging.INFO)

  syscall_files = []
  priority_file = None
  syscall_NRs = {}
  for filename in args.files:
    if filename.lower().endswith('.txt'):
      if filename.lower().endswith('priority.txt'):
        priority_file = filename
      else:
        syscall_files.append(filename)
    else:
      m = re.search(r"libseccomp_gen_syscall_nrs_([^/]+)", filename)
      syscall_NRs[m.group(1)] = parse_syscall_NRs(filename)

  gen_policy(name_modifier=args.name_modifier, out_dir=args.out_dir,
             syscall_NRs=syscall_NRs, base_syscall_file=args.base_file,
             syscall_files=syscall_files, priority_file=priority_file)


if __name__ == "__main__":
  main()
```