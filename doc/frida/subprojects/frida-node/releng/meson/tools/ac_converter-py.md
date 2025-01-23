Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The immediate goal is to understand the function of the `ac_converter.py` script. The docstring at the beginning provides a crucial clue: it converts `config.h.meson` files (which are derived from `config.h.in`) into a usable `config.h` file for the Meson build system. It specifically focuses on handling "header checks" and generating corresponding Meson declarations.

**2. Deconstructing the Code:**

Now, we need to go through the script section by section:

* **Imports:** `sys` is used for command-line arguments, which is immediately useful for understanding how the script is invoked.

* **`help_message`:** This tells us the expected usage: `python ac_converter.py <config.h.meson>`. It also explains *why* this separate script is necessary (to handle arbitrary `#undef` statements).

* **`function_data`:** This is a large dictionary. The keys look like preprocessor macros (e.g., `HAVE_MMAP`), and the values are tuples containing a function name and a header file. This strongly suggests the script is checking for the availability of specific functions and the necessary headers.

* **`headers`, `functions`, `sizes`:** These are empty lists. It's reasonable to assume they will be populated as the script processes the input file.

* **Argument Check:** `if len(sys.argv) != 2:` confirms the script expects one command-line argument (the input file).

* **File Reading:** The `with open(...)` block reads the input `config.h.meson` file line by line.

* **Line Processing Loop:** The `for line in f:` loop is where the core logic resides. The script performs three main checks on each line:

    * **Header Checks:** `if line.startswith('#mesondefine') and line.endswith('_H'):` identifies lines that define header availability. It extracts the header name.

    * **Function Checks:** The `try...except` block attempts to identify function checks. It looks for lines where the second word is a key in `function_data` or starts with `HAVE_` (but doesn't end in `_H`). This suggests the script handles both predefined and potentially custom function checks.

    * **Sizeof Checks:** `if len(arr) == 2 and elem.startswith('SIZEOF_'):` identifies lines defining size checks for data types. It extracts the type name.

* **Meson Output Generation:** After processing the input file, the script prints out Meson code:

    * **Initialization:**  `cc = meson.get_compiler('c')` and `cdata = configuration_data()` are standard Meson constructs.

    * **Header Checks:** It iterates through the `headers` list and generates Meson code to check for each header using `cc.has_header()`.

    * **Function Checks:** It iterates through the `functions` list and generates Meson code to check for each function using `cc.has_function()`. It handles cases where header includes are needed.

    * **Sizeof Checks:** It iterates through the `sizes` list and generates Meson code to determine the size of data types using `cc.sizeof()`.

    * **`configure_file()`:** This is the final Meson command to create the output `config.h` file based on the `cdata`.

**3. Connecting to the Prompts:**

Now, address each part of the prompt specifically:

* **Functionality:** Summarize the purpose of the script based on the analysis above.

* **Reverse Engineering:** Think about how this script helps in reverse engineering. Knowing which functions and headers are available on a target system is valuable information when analyzing a binary. Consider the examples provided in `function_data`.

* **Low-Level/Kernel/Framework:** Look for functions in `function_data` that are clearly related to operating system interfaces, memory management, signals, etc. These are good candidates for examples.

* **Logical Inference:**  Consider how the script transforms the input. If it sees `#mesondefine HAVE_SYS_TYPES_H`, what Meson code does it generate?  This is a direct input-output mapping.

* **User Errors:**  Think about what could go wrong. Forgetting to run the script, modifying the input file incorrectly, or having unexpected content in the input file are potential issues.

* **User Path to the Script:** Consider the typical build process. A configuration step often precedes the actual compilation. This script likely plays a role in that configuration phase.

**4. Refinement and Examples:**

Finally, refine the explanations and provide concrete examples for each point. Don't just say "it checks for functions"; give specific function names like `mmap` and explain why it's relevant. Similarly, provide example input and output for the logical inference part.

This systematic approach, starting with the overall goal and then drilling down into the code, helps in understanding the script's functionality and its implications in the context of Frida and software builds.
这个Python脚本 `ac_converter.py` 的主要功能是将一个类似 `config.h.in` 的模板文件 (`config.h.meson`) 转换成 Meson 构建系统能够理解的格式，用于在编译时配置 C/C++ 代码。它主要关注提取和转换头文件检查和函数检查的信息。

具体来说，它的功能可以分解为以下几点：

1. **读取 `config.h.meson` 文件:** 脚本接收一个命令行参数，即 `config.h.meson` 文件的路径，并读取该文件的内容。

2. **识别头文件检查:** 脚本会查找以 `#mesondefine` 开头并且以 `_H` 结尾的行。这些行通常表示在 `config.h.in` 中进行的头文件存在性检查。脚本会提取出头文件名（例如，`SYS_TYPES` 会被转换为 `sys/types.h`）。

3. **识别函数检查:** 脚本维护一个预定义的字典 `function_data`，其中包含了常见的函数名称和它们所需的头文件。脚本会查找 `config.h.meson` 中以 `#mesondefine HAVE_` 开头，但不以 `_H` 结尾的行，并尝试在 `function_data` 中找到对应的条目。如果找到，它会记录函数名和所需的头文件。对于 `function_data` 中没有的函数检查，它也会记录下来。

4. **识别 `sizeof` 检查:** 脚本会查找以 `#mesondefine SIZEOF_` 开头的行，这些行表示对数据类型大小的检查。脚本会提取出数据类型的名称（例如，`SIZEOF_INT_P` 会被转换为 `int*`）。

5. **生成 Meson 代码:** 脚本会将提取到的头文件检查、函数检查和 `sizeof` 检查信息转换成相应的 Meson 构建系统的语法。

    * **头文件检查:** 对于每个识别出的头文件，脚本会生成 `cc.has_header(h)` 的 Meson 代码，用于检查头文件是否存在。如果存在，则会在配置数据中设置一个对应的宏定义（例如，`HAVE_SYS_TYPES_H`）。

    * **函数检查:** 对于每个识别出的函数，脚本会生成 `cc.has_function(f.get(1), prefix : f.get(2))` 的 Meson 代码，用于检查函数是否存在。如果存在，则会在配置数据中设置一个对应的宏定义（例如，`HAVE_MMAP`）。

    * **`sizeof` 检查:** 对于每个识别出的 `sizeof` 检查，脚本会生成 `cdata.set('{elem}', cc.sizeof('{typename}'))` 的 Meson 代码，用于获取数据类型的大小并将其存储在配置数据中。

6. **生成 `config.h` 文件:** 最后，脚本会使用 Meson 的 `configure_file` 函数，根据 `config.h.meson` 模板和生成的配置数据，生成最终的 `config.h` 文件。

**与逆向方法的关系及举例说明:**

这个脚本本身不是一个直接用于逆向工程的工具，但它生成的 `config.h` 文件对于理解和构建目标软件至关重要，而理解目标软件是逆向工程的基础。

* **了解目标软件的能力:** `config.h` 文件中定义的宏可以揭示目标软件在编译时启用了哪些特性，支持哪些系统调用和库函数。例如，如果 `config.h` 中定义了 `HAVE_MMAP`，则说明目标软件可能使用了 `mmap` 这个内存映射的系统调用。这对于逆向工程师理解程序的内存管理方式很有帮助。

* **模拟目标环境:** 在某些逆向场景中，可能需要在自己的环境中重新编译目标软件的某个组件或者相关的工具。使用正确的 `config.h` 文件可以确保编译出的二进制文件与目标环境的二进制文件在某些关键特性上保持一致，从而更容易进行调试和分析。

**举例说明:**

假设 `config.h.meson` 中有以下一行：

```
#mesondefine HAVE_GETTIMEOFDAY
```

`ac_converter.py` 会在 `function_data` 中找到 `HAVE_GETTIMEOFDAY` 对应的函数名 `gettimeofday` 和头文件 `sys/time.h`。然后，它会生成如下的 Meson 代码：

```meson
if cc.has_function('gettimeofday', prefix : '#include<sys/time.h>')
  cdata.set('HAVE_GETTIMEOFDAY', 1)
endif
```

最终，如果编译环境支持 `gettimeofday` 函数，生成的 `config.h` 文件中将包含：

```c
#define HAVE_GETTIMEOFDAY 1
```

逆向工程师看到这个宏定义，就能知道目标软件依赖于获取系统时间的函数。

**涉及二进制底层，Linux, Android内核及框架的知识及举例说明:**

脚本中 `function_data` 字典里的大部分函数都与底层的操作系统接口有关，特别是 Linux 和 Android 等类 Unix 系统。

* **系统调用:** 许多函数如 `mmap`, `fork`, `sigaction`, `socket` 等都是直接或间接的系统调用。了解这些函数的存在与否，可以推断目标软件与操作系统内核的交互方式。例如，`HAVE_MMAP` 表明软件可能使用了内存映射，这是一种直接操作进程地址空间的底层技术。在Android中，Binder机制的底层实现也可能涉及到类似的内存映射。

* **内核功能:** 一些宏定义，虽然不是直接的函数，但也反映了内核提供的功能。例如，`HAVE_EVENTFD` 表明系统支持 `eventfd` 机制，这是一种用于进程间或线程间事件通知的轻量级机制，常用于高性能服务器或框架中。Android 的 AOSP 框架中就可能使用 `eventfd` 来进行异步事件处理。

* **C标准库:** 许多函数如 `malloc`, `free`, `memcpy`, `strlen` 等都是 C 标准库提供的。这些函数是所有 C/C++ 程序的基础，了解它们的存在与否通常不是问题，但某些平台的特殊实现或扩展可能需要通过这种方式来检查。

* **POSIX 标准:**  很多函数如 `pthread_create`, `sem_open` 等都属于 POSIX 标准。这些标准定义了操作系统接口，确保了跨平台的兼容性。了解目标软件是否支持这些 POSIX 功能，可以推断其跨平台能力。

**举例说明:**

* `HAVE_EPOLL_CREATE1`:  表明目标软件可能使用了 Linux 特有的 `epoll` 机制进行高效的 I/O 多路复用。这在网络编程或者需要处理大量并发连接的场景中很常见，例如 Frida 的 Agent 和服务端之间的通信就可能用到。

* `HAVE_GETPAGESIZE`:  表明软件可能需要获取系统的页大小，这通常用于内存管理相关的操作，例如分配缓冲区时需要考虑页对齐。这在底层库或运行时环境中比较常见。

* `HAVE_INOTIFY_INIT1`:  表明软件可能使用了 Linux 的 `inotify` 机制来监控文件系统的事件。这在需要监控文件变化的场景中很有用，例如某些热重载的实现。

**逻辑推理及假设输入与输出:**

脚本的核心逻辑是模式匹配和转换。

**假设输入 `config.h.meson` 内容:**

```
#mesondefine HAVE_SYS_TYPES_H
#mesondefine HAVE_MMAP
#mesondefine SIZEOF_INT
```

**脚本执行后的逻辑推理:**

1. **`#mesondefine HAVE_SYS_TYPES_H`:**
   - 脚本识别出这是头文件检查。
   - 提取出 `SYS_TYPES`，转换为 `sys/types.h`。
   - 生成 Meson 代码：
     ```meson
     if cc.has_header('sys/types.h')
       cdata.set('HAVE_SYS_TYPES_H', 1)
     endif
     ```

2. **`#mesondefine HAVE_MMAP`:**
   - 脚本识别出这是函数检查。
   - 在 `function_data` 中找到 `HAVE_MMAP` 对应 `('mmap', 'sys/mman.h')`。
   - 生成 Meson 代码：
     ```meson
     if cc.has_function('mmap', prefix : '#include<sys/mman.h>')
       cdata.set('HAVE_MMAP', 1)
     endif
     ```

3. **`#mesondefine SIZEOF_INT`:**
   - 脚本识别出这是 `sizeof` 检查。
   - 提取出类型名 `INT`，转换为 `int`。
   - 生成 Meson 代码：
     ```meson
     cdata.set('SIZEOF_INT', cc.sizeof('int'))
     ```

**假设输出 `config.h` 内容 (如果所有检查都通过):**

```c
#define HAVE_SYS_TYPES_H 1
#define HAVE_MMAP 1
#define SIZEOF_INT <int 的大小，例如 4>
```

**涉及用户或者编程常见的使用错误及举例说明:**

1. **忘记运行脚本:** 用户在修改了 `config.h.in` (并相应地修改为 `config.h.meson`) 后，如果没有运行 `ac_converter.py`，那么 Meson 构建系统将无法正确识别新的配置项。

   **错误现象:** 构建过程中可能会缺少某些宏定义，导致编译错误或者运行时行为不符合预期。

2. **`config.h.meson` 格式错误:** 用户在手动编辑 `config.h.meson` 时，可能会引入语法错误，例如拼写错误、缺少空格等。

   **错误现象:** `ac_converter.py` 运行时可能会报错，或者生成的 Meson 代码不正确，导致构建失败。

   **例如:** 将 `#mesondefine HAVE_MMAP` 错误地写成 `#mesondefne HAVE_MMAP`。

3. **在 `config.h.meson` 中使用不规范的宏名称:** 如果 `#mesondefine` 后的宏名称不符合脚本的预期（例如，头文件检查宏没有以 `_H` 结尾），脚本可能无法正确识别。

   **错误现象:** 脚本可能忽略这些行，导致相应的配置项没有被添加到 Meson 的配置中。

4. **`function_data` 不完整:** 如果 `config.h.meson` 中存在 `function_data` 字典中没有的函数检查，脚本虽然会记录下来，但默认不会生成包含头文件的 `cc.has_function` 调用，可能导致检查失败。

   **用户操作导致:** 用户可能添加了检查新的、不常见的函数。

   **脚本输出示例:**  对于未知的函数检查，脚本会输出 `# check token ['HAVE_NEW_FUNCTION']`，提示用户可能需要手动处理。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者想要为一个 Frida 组件（frida-node）添加或修改配置选项。**

2. **他们通常会修改 `config.h.in` 文件。** 这个文件是配置的模板，包含了各种 `#undef` 或条件编译的宏。

3. **为了让 Meson 构建系统理解这些配置，开发者需要将 `config.h.in` 转换为 `config.h.meson`。**  这个转换过程通常包括将 `#undef` 替换为 `#mesondefine`，并根据需要添加其他 Meson 相关的指令。

4. **开发者运行 `ac_converter.py` 脚本，并将转换后的 `config.h.meson` 文件作为参数传递给它。**

   ```bash
   python ac_converter.py config.h.meson
   ```

5. **`ac_converter.py` 读取 `config.h.meson`，解析其中的头文件检查、函数检查和 `sizeof` 检查。**

6. **脚本生成相应的 Meson 代码，这些代码会被写入标准输出。**  通常，这个输出会被重定向到一个临时的 Meson 构建文件或者直接由构建系统处理。

7. **Meson 构建系统执行生成的代码，进行各种编译环境的检查，并将结果存储在配置数据中。**

8. **最后，Meson 使用配置数据和 `config.h.meson` 模板生成最终的 `config.h` 文件。**

**调试线索:**

* **如果构建过程中缺少某些宏定义:** 检查 `config.h.meson` 中对应的 `#mesondefine` 是否存在，并且格式是否正确。确认 `ac_converter.py` 是否被成功执行。

* **如果构建系统报告找不到某个头文件或函数:** 检查 `config.h.meson` 中相关的 `#mesondefine` 是否存在，并且 `ac_converter.py` 是否正确地将其转换为 `cc.has_header` 或 `cc.has_function` 的调用。对于 `function_data` 中不存在的函数，可能需要手动添加相应的 Meson 代码。

* **如果 `sizeof` 的值不正确:** 检查 `config.h.meson` 中 `SIZEOF_` 相关的定义是否正确，以及目标平台的类型大小是否与预期一致。

总而言之，`ac_converter.py` 是 Frida 构建流程中的一个关键辅助工具，它简化了将传统 autoconf 风格的配置检查转换为 Meson 构建系统可用的格式的过程。理解其工作原理有助于诊断与编译配置相关的各种问题。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/tools/ac_converter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2015 The Meson development team

help_message = """Usage: {} <config.h.meson>

This script reads config.h.meson, looks for header
checks and writes the corresponding meson declaration.

Copy config.h.in to config.h.meson, replace #undef
with #mesondefine and run this. We can't do this automatically
because some configure scripts have #undef statements
that are unrelated to configure checks.
"""

import sys


# Add stuff here as it is encountered.
function_data = \
    {'HAVE_FEENABLEEXCEPT': ('feenableexcept', 'fenv.h'),
     'HAVE_FECLEAREXCEPT': ('feclearexcept', 'fenv.h'),
     'HAVE_FEDISABLEEXCEPT': ('fedisableexcept', 'fenv.h'),
     'HAVE_MMAP': ('mmap', 'sys/mman.h'),
     'HAVE_GETPAGESIZE': ('getpagesize', 'unistd.h'),
     'HAVE_GETISAX': ('getisax', 'sys/auxv.h'),
     'HAVE_GETTIMEOFDAY': ('gettimeofday', 'sys/time.h'),
     'HAVE_MPROTECT': ('mprotect', 'sys/mman.h'),
     'HAVE_POSIX_MEMALIGN': ('posix_memalign', 'stdlib.h'),
     'HAVE_SIGACTION': ('sigaction', 'signal.h'),
     'HAVE_ALARM': ('alarm', 'unistd.h'),
     'HAVE_CTIME_R': ('ctime_r', 'time.h'),
     'HAVE_DRAND48': ('drand48', 'stdlib.h'),
     'HAVE_FLOCKFILE': ('flockfile', 'stdio.h'),
     'HAVE_FORK': ('fork', 'unistd.h'),
     'HAVE_FUNLOCKFILE': ('funlockfile', 'stdio.h'),
     'HAVE_GETLINE': ('getline', 'stdio.h'),
     'HAVE_LINK': ('link', 'unistd.h'),
     'HAVE_RAISE': ('raise', 'signal.h'),
     'HAVE_STRNDUP': ('strndup', 'string.h'),
     'HAVE_SCHED_GETAFFINITY': ('sched_getaffinity', 'sched.h'),
     'HAVE_WAITPID': ('waitpid', 'sys/wait.h'),
     'HAVE_XRENDERCREATECONICALGRADIENT': ('XRenderCreateConicalGradient', 'xcb/render.h'),
     'HAVE_XRENDERCREATELINEARGRADIENT': ('XRenderCreateLinearGradient', 'xcb/render.h'),
     'HAVE_XRENDERCREATERADIALGRADIENT': ('XRenderCreateRadialGradient', 'xcb/render.h'),
     'HAVE_XRENDERCREATESOLIDFILL': ('XRenderCreateSolidFill', 'xcb/render.h'),
     'HAVE_DCGETTEXT': ('dcgettext', 'libintl.h'),
     'HAVE_ENDMNTENT': ('endmntent', 'mntent.h'),
     'HAVE_ENDSERVENT': ('endservent', 'netdb.h'),
     'HAVE_EVENTFD': ('eventfd', 'sys/eventfd.h'),
     'HAVE_FALLOCATE': ('fallocate', 'fcntl.h'),
     'HAVE_FCHMOD': ('fchmod', 'sys/stat.h'),
     'HAVE_FCHOWN': ('fchown', 'unistd.h'),
     'HAVE_FDWALK': ('fdwalk', 'stdlib.h'),
     'HAVE_FSYNC': ('fsync', 'unistd.h'),
     'HAVE_GETC_UNLOCKED': ('getc_unlocked', 'stdio.h'),
     'HAVE_GETFSSTAT': ('getfsstat', 'sys/mount.h'),
     'HAVE_GETMNTENT_R': ('getmntent_r', 'mntent.h'),
     'HAVE_GETPROTOBYNAME_R': ('getprotobyname_r', 'netdb.h'),
     'HAVE_GETRESUID': ('getresuid', 'unistd.h'),
     'HAVE_GETVFSSTAT': ('getvfsstat', 'sys/statvfs.h'),
     'HAVE_GMTIME_R': ('gmtime_r', 'time.h'),
     'HAVE_HASMNTOPT': ('hasmntopt', 'mntent.h'),
     'HAVE_IF_INDEXTONAME': ('if_indextoname', 'net/if.h'),
     'HAVE_IF_NAMETOINDEX': ('if_nametoindex', 'net/if.h'),
     'HAVE_INOTIFY_INIT1': ('inotify_init1', 'sys/inotify.h'),
     'HAVE_ISSETUGID': ('issetugid', 'unistd.h'),
     'HAVE_KEVENT': ('kevent', 'sys/event.h'),
     'HAVE_KQUEUE': ('kqueue', 'sys/event.h'),
     'HAVE_LCHMOD': ('lchmod', 'sys/stat.h'),
     'HAVE_LCHOWN': ('lchown', 'unistd.h'),
     'HAVE_LSTAT': ('lstat', 'sys/stat.h'),
     'HAVE_MEMCPY': ('memcpy', 'string.h'),
     'HAVE_MEMALIGN': ('memalign', 'stdlib.h'),
     'HAVE_MEMMEM': ('memmem', 'string.h'),
     'HAVE_NEWLOCALE': ('newlocale', 'locale.h'),
     'HAVE_PIPE2': ('pipe2', 'fcntl.h'),
     'HAVE_POLL': ('poll', 'poll.h'),
     'HAVE_PRLIMIT': ('prlimit', 'sys/resource.h'),
     'HAVE_PTHREAD_ATTR_SETSTACKSIZE': ('pthread_attr_setstacksize', 'pthread.h'),
     'HAVE_PTHREAD_CONDATTR_SETCLOCK': ('pthread_condattr_setclock', 'pthread.h'),
     'HAVE_PTHREAD_COND_TIMEDWAIT_RELATIVE_NP': ('pthread_cond_timedwait_relative_np', 'pthread.h'),
     'HAVE_READLINK': ('readlink', 'unistd.h'),
     'HAVE_RES_INIT': ('res_init', 'resolv.h'),
     'HAVE_SENDMMSG': ('sendmmsg', 'sys/socket.h'),
     'HAVE_SOCKET': ('socket', 'sys/socket.h'),
     'HAVE_GETENV': ('getenv', 'stdlib.h'),
     'HAVE_SETENV': ('setenv', 'stdlib.h'),
     'HAVE_PUTENV': ('putenv', 'stdlib.h'),
     'HAVE_UNSETENV': ('unsetenv', 'stdlib.h'),
     'HAVE_SETMNTENT': ('setmntent', 'mntent.h'),
     'HAVE_SNPRINTF': ('snprintf', 'stdio.h'),
     'HAVE_SPLICE': ('splice', 'fcntl.h'),
     'HAVE_STATFS': ('statfs', 'mount.h'),
     'HAVE_STATVFS': ('statvfs', 'sys/statvfs.h'),
     'HAVE_STPCOPY': ('stpcopy', 'string.h'),
     'HAVE_STRCASECMP': ('strcasecmp', 'strings.h'),
     'HAVE_STRLCPY': ('strlcpy', 'string.h'),
     'HAVE_STRNCASECMP': ('strncasecmp', 'strings.h'),
     'HAVE_STRSIGNAL': ('strsignal', 'signal.h'),
     'HAVE_STRTOD_L': ('strtod_l', 'stdlib.h'),
     'HAVE_STRTOLL_L': ('strtoll_l', 'stdlib.h'),
     'HAVE_STRTOULL_L': ('strtoull_l', 'stdlib.h'),
     'HAVE_SYMLINK': ('symlink', 'unistd.h'),
     'HAVE_SYSCTLBYNAME': ('sysctlbyname', 'sys/sysctl.h'),
     'HAVE_TIMEGM': ('timegm', 'time.h'),
     'HAVE_USELOCALE': ('uselocale', 'xlocale.h'),
     'HAVE_UTIMES': ('utimes', 'sys/time.h'),
     'HAVE_VALLOC': ('valloc', 'stdlib.h'),
     'HAVE_VASPRINTF': ('vasprintf', 'stdio.h'),
     'HAVE_VSNPRINTF': ('vsnprintf', 'stdio.h'),
     'HAVE_BCOPY': ('bcopy', 'strings.h'),
     'HAVE_STRERROR': ('strerror', 'string.h'),
     'HAVE_MEMMOVE': ('memmove', 'string.h'),
     'HAVE_STRTOIMAX': ('strtoimax', 'inttypes.h'),
     'HAVE_STRTOLL': ('strtoll', 'stdlib.h'),
     'HAVE_STRTOQ': ('strtoq', 'stdlib.h'),
     'HAVE_ACCEPT4': ('accept4', 'sys/socket.h'),
     'HAVE_CHMOD': ('chmod', 'sys/stat.h'),
     'HAVE_CHOWN': ('chown', 'unistd.h'),
     'HAVE_FSTAT': ('fstat', 'sys/stat.h'),
     'HAVE_GETADDRINFO': ('getaddrinfo', 'netdb.h'),
     'HAVE_GETGRGID_R': ('getgrgid_r', 'grp.h'),
     'HAVE_GETGRNAM_R': ('getgrnam_r', 'grp.h'),
     'HAVE_GETGROUPS': ('getgroups', 'grp.h'),
     'HAVE_GETOPT_LONG': ('getopt_long', 'getopt.h'),
     'HAVE_GETPWNAM_R': ('getpwnam', 'pwd.h'),
     'HAVE_GETPWUID_R': ('getpwuid_r', 'pwd.h'),
     'HAVE_GETUID': ('getuid', 'unistd.h'),
     'HAVE_LRINTF': ('lrintf', 'math.h'),
     'HAVE_DECL_ISNAN': ('isnan', 'math.h'),
     'HAVE_DECL_ISINF': ('isinf', 'math.h'),
     'HAVE_ROUND': ('round', 'math.h'),
     'HAVE_NEARBYINT': ('nearbyint', 'math.h'),
     'HAVE_RINT': ('rint', 'math.h'),
     'HAVE_MKFIFO': ('mkfifo', 'sys/stat.h'),
     'HAVE_MLOCK': ('mlock', 'sys/mman.h'),
     'HAVE_NANOSLEEP': ('nanosleep', 'time.h'),
     'HAVE_PIPE': ('pipe', 'unistd.h'),
     'HAVE_PPOLL': ('ppoll', 'poll.h'),
     'HAVE_REGEXEC': ('regexec', 'regex.h'),
     'HAVE_SETEGID': ('setegid', 'unistd.h'),
     'HAVE_SETEUID': ('seteuid', 'unistd.h'),
     'HAVE_SETPGID': ('setpgid', 'unistd.h'),
     'HAVE_SETREGID': ('setregid', 'unistd.h'),
     'HAVE_SETRESGID': ('setresgid', 'unistd.h'),
     'HAVE_SETRESUID': ('setresuid', 'unistd.h'),
     'HAVE_SHM_OPEN': ('shm_open', 'fcntl.h'),
     'HAVE_SLEEP': ('sleep', 'unistd.h'),
     'HAVE_STRERROR_R': ('strerror_r', 'string.h'),
     'HAVE_STRTOF': ('strtof', 'stdlib.h'),
     'HAVE_SYSCONF': ('sysconf', 'unistd.h'),
     'HAVE_USLEEP': ('usleep', 'unistd.h'),
     'HAVE_VFORK': ('vfork', 'unistd.h'),
     'HAVE_MALLOC': ('malloc', 'stdlib.h'),
     'HAVE_CALLOC': ('calloc', 'stdlib.h'),
     'HAVE_REALLOC': ('realloc', 'stdlib.h'),
     'HAVE_FREE': ('free', 'stdlib.h'),
     'HAVE_ALLOCA': ('alloca', 'alloca.h'),
     'HAVE_QSORT': ('qsort', 'stdlib.h'),
     'HAVE_ABS': ('abs', 'stdlib.h'),
     'HAVE_MEMSET': ('memset', 'string.h'),
     'HAVE_MEMCMP': ('memcmp', 'string.h'),
     'HAVE_STRLEN': ('strlen', 'string.h'),
     'HAVE_STRLCAT': ('strlcat', 'string.h'),
     'HAVE_STRDUP': ('strdup', 'string.h'),
     'HAVE__STRREV': ('_strrev', 'string.h'),
     'HAVE__STRUPR': ('_strupr', 'string.h'),
     'HAVE__STRLWR': ('_strlwr', 'string.h'),
     'HAVE_INDEX': ('index', 'strings.h'),
     'HAVE_RINDEX': ('rindex', 'strings.h'),
     'HAVE_STRCHR': ('strchr', 'string.h'),
     'HAVE_STRRCHR': ('strrchr', 'string.h'),
     'HAVE_STRSTR': ('strstr', 'string.h'),
     'HAVE_STRTOL': ('strtol', 'stdlib.h'),
     'HAVE_STRTOUL': ('strtoul', 'stdlib.h'),
     'HAVE_STRTOULL': ('strtoull', 'stdlib.h'),
     'HAVE_STRTOD': ('strtod', 'stdlib.h'),
     'HAVE_ATOI': ('atoi', 'stdlib.h'),
     'HAVE_ATOF': ('atof', 'stdlib.h'),
     'HAVE_STRCMP': ('strcmp', 'string.h'),
     'HAVE_STRNCMP': ('strncmp', 'string.h'),
     'HAVE_VSSCANF': ('vsscanf', 'stdio.h'),
     'HAVE_CHROOT': ('chroot', 'unistd.h'),
     'HAVE_CLOCK': ('clock', 'time.h'),
     'HAVE_CLOCK_GETRES': ('clock_getres', 'time.h'),
     'HAVE_CLOCK_GETTIME': ('clock_gettime', 'time.h'),
     'HAVE_CLOCK_SETTIME': ('clock_settime', 'time.h'),
     'HAVE_CONFSTR': ('confstr', 'time.h'),
     'HAVE_CTERMID': ('ctermid', 'stdio.h'),
     'HAVE_DIRFD': ('dirfd', 'dirent.h'),
     'HAVE_DLOPEN': ('dlopen', 'dlfcn.h'),
     'HAVE_DUP2': ('dup2', 'unistd.h'),
     'HAVE_DUP3': ('dup3', 'unistd.h'),
     'HAVE_EPOLL_CREATE1': ('epoll_create1', 'sys/epoll.h'),
     'HAVE_ERF': ('erf', 'math.h'),
     'HAVE_ERFC': ('erfc', 'math.h'),
     'HAVE_EXECV': ('execv', 'unistd.h'),
     'HAVE_FACCESSAT': ('faccessat', 'unistd.h'),
     'HAVE_FCHDIR': ('fchdir', 'unistd.h'),
     'HAVE_FCHMODAT': ('fchmodat', 'sys/stat.h'),
     'HAVE_FDATASYNC': ('fdatasync', 'unistd.h'),
     'HAVE_FDOPENDIR': ('fdopendir', 'dirent.h'),
     'HAVE_FEXECVE': ('fexecve', 'unistd.h'),
     'HAVE_FLOCK': ('flock', 'sys/file.h'),
     'HAVE_FORKPTY': ('forkpty', 'pty.h'),
     'HAVE_FPATHCONF': ('fpathconf', 'unistd.h'),
     'HAVE_FSTATAT': ('fstatat', 'unistd.h'),
     'HAVE_FSTATVFS': ('fstatvfs', 'sys/statvfs.h'),
     'HAVE_FTELLO': ('ftello', 'stdio.h'),
     'HAVE_FTIME': ('ftime', 'sys/timeb.h'),
     'HAVE_FTRUNCATE': ('ftruncate', 'unistd.h'),
     'HAVE_FUTIMENS': ('futimens', 'sys/stat.h'),
     'HAVE_FUTIMES': ('futimes', 'sys/time.h'),
     'HAVE_GAI_STRERROR': ('gai_strerror', 'netdb.h'),
     'HAVE_GETGROUPLIST': ('getgrouplist', 'grp.h'),
     'HAVE_GETHOSTBYNAME': ('gethostbyname', 'netdb.h'),
     'HAVE_GETHOSTBYNAME_R': ('gethostbyname_r', 'netdb.h'),
     'HAVE_GETITIMER': ('getitimer', 'sys/time.h'),
     'HAVE_GETLOADAVG': ('getloadavg', 'stdlib.h'),
     'HAVE_GETLOGIN': ('getlogin', 'unistd.h'),
     'HAVE_GETNAMEINFO': ('getnameinfo', 'netdb.h'),
     'HAVE_GETPEERNAME': ('getpeername', 'sys/socket.h'),
     'HAVE_GETPGID': ('getpgid', 'unistd.h'),
     'HAVE_GETPGRP': ('getpgrp', 'unistd.h'),
     'HAVE_GETPID': ('getpid', 'unistd.h'),
     'HAVE_GETPRIORITY': ('getpriority', 'sys/resource.h'),
     'HAVE_GETPWENT': ('getpwent', 'pwd.h'),
     'HAVE_GETRANDOM': ('getrandom', 'linux/random.h'),
     'HAVE_GETRESGID': ('getresgid', 'unistd.h'),
     'HAVE_GETSID': ('getsid', 'unistd.h'),
     'HAVE_GETSPENT': ('getspent', 'shadow.h'),
     'HAVE_GETSPNAM': ('getspnam', 'shadow.h'),
     'HAVE_GETWD': ('getwd', 'unistd.h'),
     'HAVE_HSTRERROR': ('hstrerror', 'netdb.h'),
     'HAVE_HTOLE64': ('htole64', 'endian.h'),
     'HAVE_IF_NAMEINDEX': ('if_nameindex', 'net/if.h'),
     'HAVE_INET_ATON': ('inet_aton', 'arpa/inet.h'),
     'HAVE_INET_PTON': ('inet_pton', 'arpa/inet.h'),
     'HAVE_INITGROUPS': ('initgroups', 'grp.h'),
     'HAVE_KILL': ('kill', 'signal.h'),
     'HAVE_KILLPG': ('killpg', 'signal.h'),
     'HAVE_LINKAT': ('linkat', 'unistd.h'),
     'HAVE_LOCKF': ('lockf', 'unistd.h'),
     'HAVE_LUTIMES': ('lutimes', 'sys/time.h'),
     'HAVE_MAKEDEV': ('makedev', 'sys/sysmacros.h'),
     'HAVE_MBRTOWC': ('mbrtowc', 'wchar.h'),
     'HAVE_MEMRCHR': ('memrchr', 'string.h'),
     'HAVE_MKDIRAT': ('mkdirat', 'sys/stat.h'),
     'HAVE_MKFIFOAT': ('mkfifoat', 'sys/stat.h'),
     'HAVE_MKNOD': ('mknod', 'unistd.h'),
     'HAVE_MKNODAT': ('mknodat', 'unistd.h'),
     'HAVE_MKTIME': ('mktime', 'unistd.h'),
     'HAVE_MKREMAP': ('mkremap', 'sys/mman.h'),
     'HAVE_NICE': ('nice', 'unistd.h'),
     'HAVE_OPENAT': ('openat', 'fcntl.h'),
     'HAVE_OPENPTY': ('openpty', 'pty.h'),
     'HAVE_PATHCONF': ('pathconf', 'unistd.h'),
     'HAVE_PAUSE': ('pause', 'unistd.h'),
     'HAVE_PREAD': ('pread', 'unistd.h'),
     'HAVE_PTHREAD_KILL': ('pthread_kill', 'signal.h'),
     'HAVE_PTHREAD_SIGMASK': ('pthread_sigmask', 'signal.h'),
     'HAVE_PWRITE': ('pwrite', 'unistd.h'),
     'HAVE_READLINKAT': ('readlinkat', 'unistd.h'),
     'HAVE_READV': ('readv', 'sys/uio.h'),
     'HAVE_RENAMEAT': ('renamat', 'stdio.h'),
     'HAVE_SCHED_GET_PRIORITY_MAX': ('sched_get_priority_max', 'sched.h'),
     'HAVE_SCHED_RR_GET_INTERVAL': ('sched_rr_get_interval', 'sched.h'),
     'HAVE_SCHED_SETAFFINITY': ('sched_setaffinity', 'sched.h'),
     'HAVE_SCHED_SETPARAM': ('sched_setparam', 'sched.h'),
     'HAVE_SCHED_SETSCHEDULER': ('sched_setscheduler', 'sched.h'),
     'HAVE_SELECT': ('select', 'sys/select.h'),
     'HAVE_SEM_GETVALUE': ('sem_getvalue', 'semaphore.h'),
     'HAVE_SEM_OPEN': ('sem_open', 'semaphore.h'),
     'HAVE_SEM_TIMEDWAIT': ('sem_timedwait', 'semaphore.h'),
     'HAVE_SEM_UNLINK': ('sem_unlink', 'semaphore.h'),
     'HAVE_SENDFILE': ('sendfile', 'sys/sendfile.h'),
     'HAVE_SETGID': ('setgid', 'unistd.h'),
     'HAVE_SETGROUPS': ('setgroups', 'grp.h'),
     'HAVE_SETHOSTNAME': ('sethostname', 'unistd.h'),
     'HAVE_SETITIMER': ('setitimer', 'sys/time.h'),
     'HAVE_SETLOCALE': ('setlocale', 'locale.h'),
     'HAVE_SETPGRP': ('setpgrp', 'unistd.h'),
     'HAVE_SETPRIORITY': ('setpriority', 'sys/resource.h'),
     'HAVE_SETREUID': ('setreuid', 'unistd.h'),
     'HAVE_SETSID': ('setsid', 'unistd.h'),
     'HAVE_SETUID': ('setuid', 'unistd.h'),
     'HAVE_SETVBUF': ('setvbuf', 'unistd.h'),
     'HAVE_SIGALTSTACK': ('sigaltstack', 'signal.h'),
     'HAVE_SIGINTERRUPT': ('siginterrupt', 'signal.h'),
     'HAVE_SIGPENDING': ('sigpending', 'signal.h'),
     'HAVE_SIGRELSE': ('sigrelse', 'signal.h'),
     'HAVE_SIGTIMEDWAIT': ('sigtimedwait', 'signal.h'),
     'HAVE_SIGWAIT': ('sigwait', 'signal.h'),
     'HAVE_SIGWAITINFO': ('sigwaitinfo', 'signal.h'),
     'HAVE_SOCKETPAIR': ('socketpair', 'sys/socket.h'),
     'HAVE_STRFTIME': ('strftime', 'time.h'),
     'HAVE_SYMLINKAT': ('symlinkat', 'unistd.h'),
     'HAVE_SYNC': ('sync', 'unistd.h'),
     'HAVE_TCGETPGRP': ('tcgetpgrp', 'unistd.h'),
     'HAVE_TCSETPGRP': ('tcsetpgrp', 'unistd.h'),
     'HAVE_TEMPNAM': ('tempnam', 'stdio.h'),
     'HAVE_TIMES': ('times', 'sys/times.h'),
     'HAVE_TEMPFILE': ('tempfile', 'stdio.h'),
     'HAVE_TMPNAM': ('tmpnam', 'stdio.h'),
     'HAVE_TMPNAM_R': ('tmpnam_r', 'stdio.h'),
     'HAVE_TRUNCATE': ('truncate', 'unistd.h'),
     'HAVE_TZNAME': ('tzname', 'time.h'),
     'HAVE_UNAME': ('uname', 'sys/utsname.h'),
     'HAVE_UNLINKAT': ('unlinkat', 'unistd.h'),
     'HAVE_UTIMENSAT': ('utimensat', 'sys/stat.h'),
     'HAVE_WAIT3': ('wait3', 'sys/wait.h'),
     'HAVE_WAIT4': ('wait4', 'sys/wait.h'),
     'HAVE_WAITID': ('waitid', 'sys/wait.h'),
     'HAVE_WRITEV': ('writev', 'sys/uio.h'),
     'HAVE_WMEMCMP': ('wmemcmp', 'wchar.h'),
     'HAVE_ATAN': ('atan', 'math.h'),
     'HAVE_ATAN2': ('atan2', 'math.h'),
     'HAVE_ACOS': ('acos', 'math.h'),
     'HAVE_ACOSH': ('acosh', 'math.h'),
     'HAVE_ASIN': ('asin', 'math.h'),
     'HAVE_ASINH': ('asinh', 'math.h'),
     'HAVE_ATANH': ('atanh', 'math.h'),
     'HAVE_CEIL': ('ceil', 'math.h'),
     'HAVE_COPYSIGN': ('copysign', 'math.h'),
     'HAVE_COS': ('cos', 'math.h'),
     'HAVE_COSH': ('cosh', 'math.h'),
     'HAVE_COSF': ('cosf', 'math.h'),
     'HAVE_EXPM1': ('expm1', 'math.h'),
     'HAVE_FABS': ('fabs', 'math.h'),
     'HAVE_FINITE': ('finite', 'math.h'),
     'HAVE_FLOOR': ('floor', 'math.h'),
     'HAVE_GAMMA': ('gamma', 'math.h'),
     'HAVE_HYPOT': ('hypot', 'math.h'),
     'HAVE_ISINF': ('isinf', 'math.h'),
     'HAVE_LOG': ('log', 'math.h'),
     'HAVE_LOG1P': ('log1p', 'math.h'),
     'HAVE_LOG2': ('log2', 'math.h'),
     'HAVE_LGAMMA': ('lgamma', 'math.h'),
     'HAVE_POW': ('pow', 'math.h'),
     'HAVE_SCALBN': ('scalbn', 'math.h'),
     'HAVE_SIN': ('sin', 'math.h'),
     'HAVE_SINF': ('sinf', 'math.h'),
     'HAVE_SINH': ('sinh', 'math.h'),
     'HAVE_SQRT': ('sqrt', 'math.h'),
     'HAVE_TGAMMA': ('tgamma', 'math.h'),
     'HAVE_FSEEKO': ('fseeko', 'stdio.h'),
     'HAVE_FSEEKO64': ('fseeko64', 'stdio.h'),
     'HAVE_SETJMP': ('setjmp', 'setjmp.h'),
     'HAVE_PTHREAD_SETNAME_NP': ('pthread_setname_np', 'pthread.h'),
     'HAVE_PTHREAD_SET_NAME_NP': ('pthread_set_name_np', 'pthread.h'),
     }

headers = []
functions = []
sizes = []

if len(sys.argv) != 2:
    print(help_message.format(sys.argv[0]))
    sys.exit(0)

with open(sys.argv[1], encoding='utf-8') as f:
    for line in f:
        line = line.strip()
        arr = line.split()

        # Check for headers.
        if line.startswith('#mesondefine') and line.endswith('_H'):
            token = line.split()[1]
            tarr = token.split('_')[1:-1]
            tarr = [x.lower() for x in tarr]
            hname = '/'.join(tarr) + '.h'
            headers.append(hname)

        # Check for functions.
        try:
            token = arr[1]
            if token in function_data:
                fdata = function_data[token]
                functions.append([token, fdata[0], fdata[1]])
            elif token.startswith('HAVE_') and not token.endswith('_H'):
                functions.append([token])
        except Exception:
            pass

        # Check for sizeof tests.
        if len(arr) != 2:
            continue
        elem = arr[1]
        if elem.startswith('SIZEOF_'):
            typename = elem.split('_', 1)[1] \
                .replace('_P', '*') \
                .replace('_', ' ') \
                .lower() \
                .replace('size t', 'size_t')
            sizes.append((elem, typename))

print('''cc = meson.get_compiler('c')
cdata = configuration_data()''')

# Convert header checks.

print('check_headers = [')
for hname in headers:
    print(f"  '{hname}',")
print(']\n')

print('''foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach
''')

# Convert function checks.

print('check_functions = [')
for tok in functions:
    if len(tok) == 3:
        tokstr, fdata0, fdata1 = tok
        print(f"  ['{tokstr}', '{fdata0}', '#include<{fdata1}>'],")
    else:
        print('# check token', tok)
print(']\n')

print('''foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2))
    cdata.set(f.get(0), 1)
  endif
endforeach
''')

# Convert sizeof checks.

for elem, typename in sizes:
    print(f"cdata.set('{elem}', cc.sizeof('{typename}'))")

print('''
configure_file(input : 'config.h.meson',
  output : 'config.h',
  configuration : cdata)''')
```