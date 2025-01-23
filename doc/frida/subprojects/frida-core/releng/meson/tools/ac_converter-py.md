Response:
Let's break down the thought process to analyze the `ac_converter.py` script.

1. **Understand the Goal:** The script's name, `ac_converter.py`, and the initial comments strongly suggest its purpose: converting Autoconf-style configuration checks (often found in `config.h.in`) into Meson's configuration declarations. The key phrase is "reads config.h.meson, looks for header checks and writes the corresponding meson declaration."

2. **Identify Key Inputs and Outputs:**
    * **Input:** A `config.h.meson` file. This file is derived from a traditional `config.h.in` but with `#undef` replaced by `#mesondefine`.
    * **Output:** Meson build system code that can be incorporated into a `meson.build` file. This output configures the build based on the availability of headers, functions, and data types.

3. **Analyze the Code Structure:**  The script follows a straightforward procedural approach:
    * **Initialization:** Defines `help_message`, imports `sys`, and initializes data structures (`function_data`, `headers`, `functions`, `sizes`).
    * **Input Processing:** Checks command-line arguments, opens and reads the input file line by line.
    * **Parsing Logic:**  Inside the loop, it checks each line for specific patterns:
        * `#mesondefine` ending in `_H`: Identifies header checks.
        * Lines with at least two words: Potentially function checks. It looks up the second word in `function_data`.
        * Lines with exactly two words starting with `SIZEOF_`:  Identifies `sizeof` checks.
    * **Output Generation:** Prints Meson code snippets to the standard output. These snippets use `cc.has_header`, `cc.has_function`, and `cc.sizeof` to perform the checks within the Meson build system. It then uses `configure_file` to generate the final `config.h`.

4. **Deconstruct the Parsing Logic in Detail:**  This is the core of the script.
    * **Header Checks:** The assumption is that `#mesondefine` followed by a token ending in `_H` signifies a header check. The code extracts the header name by splitting the token and converting it to lowercase with `/` separators.
    * **Function Checks:** The `function_data` dictionary is crucial. It maps Autoconf-style `HAVE_` macros to the actual function name and the header it requires. The script looks for the `HAVE_` macro in the input and uses the dictionary to generate the corresponding `cc.has_function` call. It also handles cases where a `HAVE_` macro is present but not in the dictionary (it just adds a comment).
    * **`sizeof` Checks:** It looks for lines starting with `SIZEOF_`, extracts the type name, and converts it to a format suitable for `cc.sizeof`.

5. **Relate to the Prompt's Questions:** Now, systematically address each point in the prompt:

    * **Functionality:** List the steps the script performs (read, parse, generate Meson code for headers, functions, and sizes).
    * **Reversing:**  This script isn't directly *performing* reverse engineering. However, it *supports* the build process of tools like Frida, which *are* used for dynamic analysis (a form of reverse engineering). The example provided (`HAVE_MMAP`) illustrates this. `mmap` is a fundamental system call often encountered when analyzing memory management in reverse engineering.
    * **Binary/Kernel/Framework:**  The checks themselves (for `mmap`, `getpagesize`, `sigaction`, etc.) directly relate to operating system primitives and concepts found in the Linux kernel and Android framework. These functions are often used in low-level code.
    * **Logical Inference:** The script makes assumptions based on patterns in the input file. The assumptions are:
        * `#mesondefine ... _H` means a header check.
        * `HAVE_...` in `function_data` means a function check with a specific header.
        * `SIZEOF_...` means a `sizeof` check.
        The input/output examples demonstrate these inferences.
    * **User Errors:** Common errors involve:
        * Not replacing `#undef` with `#mesondefine`.
        * Incorrect `config.h.meson` format.
        * Missing entries in `function_data`.
    * **User Path:**  Explain the typical workflow:  configure script -> `config.h.in` -> manual edit to `config.h.meson` -> running this script.

6. **Refine and Organize:** Structure the answer clearly with headings for each point in the prompt. Use code examples where appropriate. Ensure the language is precise and avoids jargon where possible, or explains it when necessary. For instance, explain what "dynamic instrumentation" is briefly.

7. **Review and Verify:**  Read through the entire answer to ensure accuracy and completeness. Check that all aspects of the prompt have been addressed. Ensure the examples are clear and relevant. For instance, make sure the example of reverse engineering ties directly back to what the *script* does.

This methodical approach, starting with understanding the core purpose and then drilling down into the details of the code, allows for a comprehensive and accurate analysis of the script's functionality and its connections to related concepts.
这个 Python 脚本 `ac_converter.py` 的主要功能是将类似 Autoconf 的配置检查（通常在 `config.h.in` 文件中定义）转换为 Meson 构建系统可以理解的格式。它读取一个名为 `config.h.meson` 的文件，查找特定的模式，并生成相应的 Meson 代码片段，用于在构建过程中进行相同的检查。

**功能列表:**

1. **读取 `config.h.meson` 文件:** 脚本首先打开并读取作为命令行参数提供的 `config.h.meson` 文件。
2. **解析头文件检查:**  它查找以 `#mesondefine` 开头并以 `_H` 结尾的行。这些行被认为是头文件检查的指示。脚本会提取头文件名，并将其添加到待检查的头文件列表中。
3. **解析函数存在性检查:**  它查找包含至少两个词的行，并将第二个词视为可能的宏定义。如果这个宏定义存在于预定义的 `function_data` 字典中（例如 `HAVE_MMAP`），则认为这是一个函数存在性检查。脚本会提取宏定义、对应的函数名和所需的头文件名。对于不在 `function_data` 中的 `HAVE_` 开头的宏，也会将其视为函数检查，但缺少详细信息。
4. **解析 `sizeof` 检查:** 它查找包含两个词且第二个词以 `SIZEOF_` 开头的行。这表示需要检查特定数据类型的大小。脚本会提取宏定义和数据类型名。
5. **生成 Meson 代码:**  脚本根据解析到的信息，生成相应的 Meson 构建系统代码，用于执行以下操作：
    * **检查头文件是否存在:**  生成 `cc.has_header()` 调用，检查提取到的头文件是否存在。
    * **检查函数是否存在:** 生成 `cc.has_function()` 调用，检查提取到的函数是否存在，并提供必要的头文件包含。
    * **获取数据类型大小:** 生成 `cc.sizeof()` 调用，获取指定数据类型的大小。
6. **输出 Meson 配置数据:**  生成的 Meson 代码会将检查结果存储在 `configuration_data` 对象 `cdata` 中，以便后续在 `config.h` 文件中定义相应的宏。
7. **生成 `config.h` 文件:** 最后，脚本使用 `configure_file` 函数，根据 `config.h.meson` 模板和 `cdata` 中的配置数据，生成最终的 `config.h` 文件。

**与逆向方法的关系及举例:**

这个脚本本身并不直接执行逆向工程，但它为 Frida 这样的动态分析工具的构建过程提供了支持。动态分析是逆向工程中的一种重要方法。

* **举例:** 假设 `config.h.meson` 中包含一行 `#mesondefine HAVE_MMAP_H`，并且 `function_data` 中有 `'HAVE_MMAP': ('mmap', 'sys/mman.h')`。
    * `ac_converter.py` 会识别 `HAVE_MMAP_H` 并将其转换为 Meson 的 `cc.has_header('sys/mman.h')`。
    * 它还会识别 `HAVE_MMAP` 并将其转换为 Meson 的 `cc.has_function('mmap', prefix: '#include<sys/mman.h>')`。
    * 如果 `cc.has_function('mmap', prefix: '#include<sys/mman.h>')` 返回 true，则 Meson 会在 `config.h` 中定义 `HAVE_MMAP` 宏。
    * 在 Frida 的代码中，可能会使用条件编译 `#ifdef HAVE_MMAP` 来决定是否使用 `mmap` 系统调用。
    * `mmap` 是一个用于内存映射的重要系统调用，在逆向分析中，理解目标程序如何使用内存映射对于分析其行为至关重要。Frida 可以利用 `mmap` 来注入代码或监控内存访问。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

脚本中定义的许多宏和函数都直接关联到操作系统的底层功能。

* **二进制底层:** `SIZEOF_` 相关的检查直接关系到不同平台下数据类型（如指针、整型等）的二进制表示大小。这对于跨平台兼容性至关重要。
* **Linux 内核:**  许多 `HAVE_` 开头的宏对应的是 Linux 系统调用或 C 标准库函数，这些函数最终会与内核交互。例如：
    * `HAVE_FORK`: `fork()` 系统调用用于创建新的进程。
    * `HAVE_MMAP`: `mmap()` 系统调用用于内存映射。
    * `HAVE_SIGACTION`: `sigaction()` 系统调用用于处理信号。
    * `HAVE_PTHREAD_`: 前缀的宏涉及到 POSIX 线程库，这是 Linux 环境下进行多线程编程的基础。
* **Android 框架:**  虽然脚本本身不直接针对 Android，但 Frida 作为一个跨平台的工具，其核心库的构建也需要考虑 Android 平台。一些宏，如涉及文件系统操作（`openat`, `statfs`），进程管理（`getpid`, `kill`），或者网络操作（`socket`, `getaddrinfo`），在 Android 框架的底层也有广泛应用。

**逻辑推理及假设输入与输出:**

脚本的核心逻辑是基于预定义的模式识别和映射。

**假设输入 (`config.h.meson`):**

```meson
#mesondefine HAVE_UNISTD_H
#mesondefine HAVE_PTHREAD_H
#mesondefine SIZEOF_INT

#mesondefine HAVE_MMAP
#mesondefine HAVE_SOCKET
```

**假设输出 (部分生成的 Meson 代码):**

```meson
cc = meson.get_compiler('c')
cdata = configuration_data()
check_headers = [
  'unistd.h',
  'pthread.h',
]

foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

check_functions = [
  ['HAVE_MMAP', 'mmap', '#include<sys/mman.h>'],
  ['HAVE_SOCKET', 'socket', '#include<sys/socket.h>'],
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2))
    cdata.set(f.get(0), 1)
  endif
endforeach

cdata.set('SIZEOF_INT', cc.sizeof('int'))

configure_file(input : 'config.h.meson',
  output : 'config.h',
  configuration : cdata)
```

**用户或编程常见的使用错误及举例:**

1. **未将 `#undef` 替换为 `#mesondefine`:** 如果 `config.h.in` 中有 `#undef HAVE_MMAP`，而用户忘记将其改为 `#mesondefine HAVE_MMAP`，则 `ac_converter.py` 将不会识别到这个配置项，导致 Meson 构建系统中缺少相应的检查。
2. **`config.h.meson` 格式错误:** 如果 `config.h.meson` 文件格式不正确，例如 `#mesondefine` 后面的宏定义缺少空格，或者行末有多余的空格，可能会导致脚本解析错误。
3. **`function_data` 字典中缺少条目:** 如果 `config.h.meson` 中定义了一个 `HAVE_` 开头的宏，但该宏在 `function_data` 字典中没有对应的条目，脚本会将其识别为函数检查，但无法生成完整的 Meson 代码（缺少函数名和头文件信息）。这可能导致构建失败或运行时错误。
4. **命令行参数错误:** 用户可能忘记提供 `config.h.meson` 文件的路径作为命令行参数，或者提供了错误的路径，导致脚本无法找到输入文件并报错。

**用户操作如何一步步到达这里作为调试线索:**

1. **配置阶段 (通常由 `configure` 脚本完成):**  Frida 或其依赖的库在构建之前通常会运行一个配置脚本（可能是 Autoconf 生成的）。这个配置脚本会探测系统环境，检查所需的头文件、库和函数是否存在，并将结果写入 `config.h.in` 文件。
2. **手动修改 `config.h.in` 生成 `config.h.meson`:**  由于 `ac_converter.py` 需要特定的 `#mesondefine` 语法，因此开发者需要手动将 `config.h.in` 文件中的 `#undef` 行替换为 `#mesondefine`。这个步骤是必要的，因为配置脚本中的 `#undef` 语句可能与配置检查无关。
3. **运行 `ac_converter.py`:**  开发者在 `frida/subprojects/frida-core/releng/meson/tools/` 目录下，通过命令行执行 `python3 ac_converter.py config.h.meson`，将转换后的 Meson 配置代码输出到标准输出。通常，这个输出会被重定向或直接集成到 `meson.build` 文件中。
4. **Meson 构建系统使用生成的配置:**  当 Meson 构建系统运行时，它会读取生成的配置代码，并根据其中的指示执行头文件和函数检查。检查结果会被存储在 `cdata` 中。
5. **生成 `config.h`:** Meson 使用 `configure_file` 函数，根据 `config.h.meson` 模板和 `cdata` 中的信息，生成最终的 `config.h` 文件。这个文件会被包含在 Frida 的源代码中。

**调试线索:**

如果 Frida 的构建过程中出现与配置相关的错误，例如缺少某些宏定义或链接错误，可以按照以下步骤进行调试：

1. **检查 `config.h.meson`:**  确认 `#undef` 是否都已正确替换为 `#mesondefine`。
2. **检查 `ac_converter.py` 的输出:**  运行脚本并查看其生成的 Meson 代码，确认头文件、函数和 `sizeof` 检查是否正确生成。
3. **检查 `meson.build` 文件:**  查看 `meson.build` 文件中如何使用 `ac_converter.py` 的输出，以及如何配置编译选项。
4. **检查生成的 `config.h` 文件:**  查看最终生成的 `config.h` 文件，确认预期的宏定义是否已定义，并且值是否正确。
5. **检查 `function_data`:**  如果涉及到特定的函数检查失败，检查 `ac_converter.py` 中的 `function_data` 字典是否包含了该函数的正确信息。

通过以上分析，可以理解 `ac_converter.py` 在 Frida 的构建过程中扮演着重要的角色，它桥接了传统的 Autoconf 配置方式和现代的 Meson 构建系统，确保了 Frida 能够根据目标系统的特性进行正确编译。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/tools/ac_converter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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