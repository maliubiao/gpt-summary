Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to read the script and the accompanying comment block to understand its primary purpose. The comment `This script reads config.h.meson, looks for header checks and writes the corresponding meson declaration.` is key. It tells us this is a utility to convert information from a specific format (`config.h.meson`) into a format that the Meson build system understands.

**2. Identifying Key Operations:**

Next, I'd scan the code for the main actions:

* **Reading the input file:** The `with open(sys.argv[1], encoding='utf-8') as f:` clearly indicates file reading.
* **Parsing lines:** The `for line in f:` loop and the `line.strip().split()` tell us the script processes the input file line by line.
* **Identifying header checks:** The `if line.startswith('#mesondefine') and line.endswith('_H'):` block is responsible for finding lines that indicate successful header checks.
* **Identifying function checks:** The `if token in function_data:` block, along with the logic to handle `HAVE_` prefixes, points to identifying function availability.
* **Identifying `sizeof` checks:** The `if elem.startswith('SIZEOF_'):` block focuses on detecting size checks.
* **Generating Meson code:**  The `print(...)` statements are responsible for outputting the Meson-compatible declarations.

**3. Analyzing the Data Structures:**

The `function_data` dictionary is crucial. It maps preprocessor macros (like `HAVE_MMAP`) to the actual function name (`mmap`) and the header file it belongs to (`sys/mman.h`). This structure helps the script correlate the flags in the input file with the necessary information for Meson's function checking.

**4. Connecting to Reverse Engineering:**

At this point, I would ask myself:  "How does this relate to reverse engineering?"  The connection lies in the *purpose* of these checks. Software often needs to adapt its behavior based on the capabilities of the target system. Knowing whether a specific function or header exists is vital for this adaptation. Reverse engineers often encounter this conditional compilation logic when analyzing binaries. They might need to understand which code paths are enabled or disabled based on these feature checks.

**5. Considering Binary/Kernel Aspects:**

The checks for functions like `mmap`, `getpagesize`, `sigaction`, and `pthread_create` (though not explicitly listed in the `function_data`, the general concept applies) are direct interactions with the operating system kernel or low-level libraries. These functions are fundamental building blocks for process management, memory management, signal handling, and threading. A reverse engineer would encounter these when analyzing how a program interacts with the underlying system.

**6. Thinking About Logic and Assumptions:**

The script makes several assumptions:

* **Input file format:** It expects a specific format for `config.h.meson`.
* **Naming conventions:** It relies on conventions like `HAVE_FUNCTION_NAME` and `HEADER_FILE_H`.
* **Correct `function_data`:** The `function_data` dictionary needs to be accurate.

To illustrate the logical flow, I'd consider a simple input example and trace how the script would process it.

**7. Identifying User Errors:**

Common user errors would stem from not following the expected input format. For instance, directly using `config.h.in` without the `#mesondefine` replacements would lead to the script not recognizing the checks correctly.

**8. Reconstructing the User Journey:**

To understand how a user arrives at running this script, I'd consider the context of the Frida build process. The script is located within the Frida QML subdirectory and is named `ac_converter.py`. This suggests it's a step in the build process for the Frida QML component. The comment about copying `config.h.in` and replacing `#undef` hints at the preceding steps.

**Self-Correction/Refinement:**

Initially, I might focus too narrowly on the *mechanics* of the Python code. However, the prompt asks for the *functionality* and its relation to reverse engineering, etc. This requires stepping back and considering the *purpose* of the script within the larger context of building software and how those build-time decisions affect the final binary. I would review the prompt keywords ("reverse engineering," "binary底层," "linux, android内核及框架") to ensure I've addressed them adequately. For example, I initially missed the subtle connection between feature detection and reverse engineering – the script helps *create* the conditional logic that reverse engineers later analyze.

By following this thought process, moving from understanding the basic functionality to considering its implications in different domains (reverse engineering, OS interaction, etc.), I can generate a comprehensive and insightful explanation.
这个Python脚本 `ac_converter.py` 的主要功能是将 Autoconf 风格的配置检查结果转换为 Meson 构建系统能够理解的格式。更具体地说，它读取一个名为 `config.h.meson` 的文件，这个文件是手动从 `config.h.in` 转换而来的，其中包含了预处理器宏定义，用于指示特定头文件或函数在目标系统上是否可用。脚本解析这些宏定义，并生成相应的 Meson 构建系统的配置数据声明。

以下是该脚本的功能的详细列表：

1. **解析 `config.h.meson` 文件:**  脚本读取指定的文件，逐行处理。
2. **识别头文件检查:**  脚本查找以 `#mesondefine` 开头并且以 `_H` 结尾的行。这些行代表了 Autoconf 风格的头文件检查结果。例如，如果某行是 `#mesondefine SYS_SOCKET_H`，则表示找到了 `sys/socket.h` 头文件。
3. **提取头文件名:** 从识别出的头文件检查行中提取出实际的头文件名，例如将 `SYS_SOCKET_H` 转换为 `sys/socket.h`。
4. **生成 Meson 头文件检查声明:**  对于每个找到的头文件，脚本生成 Meson 构建系统中用于检查头文件是否存在的代码。如果头文件存在，则在 Meson 的配置数据中设置一个相应的宏。
5. **识别函数检查:** 脚本维护一个预定义的字典 `function_data`，其中包含了常见的函数名、所需的头文件以及用于 Meson 函数检查的额外信息。脚本在 `config.h.meson` 中查找以 `#mesondefine HAVE_` 开头的行，并尝试匹配 `function_data` 中的键。
6. **生成 Meson 函数检查声明:**  对于在 `function_data` 中找到的函数检查，脚本生成相应的 Meson 代码来检查该函数是否存在，并包含必要的头文件。如果函数存在，则在 Meson 的配置数据中设置相应的宏。
7. **处理未在预定义字典中的函数检查:** 对于以 `HAVE_` 开头但不在 `function_data` 中的宏，脚本也会生成一个简单的 Meson 配置数据设置语句，假设该宏代表一个可用的特性。
8. **识别 `sizeof` 检查:** 脚本查找以 `#mesondefine SIZEOF_` 开头的行，这些行表示了对特定数据类型大小的检查结果。
9. **生成 Meson `sizeof` 检查声明:**  对于每个找到的 `sizeof` 检查，脚本生成 Meson 代码来获取对应数据类型的大小，并将其存储在 Meson 的配置数据中。
10. **生成最终的 Meson 配置文件:**  脚本将所有生成的 Meson 代码片段组合在一起，形成一个完整的 Meson 配置文件，用于执行头文件、函数和数据类型大小的检查，并将结果存储在配置数据中。这个配置数据最终会被写入 `config.h` 文件。

**与逆向方法的关系:**

该脚本与逆向方法有一定的关系，因为它涉及到目标系统上特定库和函数的可用性。在逆向工程中，了解目标程序所依赖的库和函数是至关重要的。

**举例说明:**

假设逆向工程师正在分析一个在 Linux 上运行的二进制文件，并且他们注意到该程序使用了 `mmap` 函数进行内存映射。通过查看程序的构建系统（如果可用），他们可能会发现类似如下的配置检查：

在 `config.h.meson` 中可能有：

```
#mesondefine HAVE_MMAP
```

`ac_converter.py` 会将其转换为 Meson 代码：

```python
if cc.has_function('mmap', prefix : '#include<sys/mman.h>')
  cdata.set('HAVE_MMAP', 1)
endif
```

逆向工程师可以通过理解这些构建时的检查，推断出目标程序在运行时会依赖 `mmap` 函数以及相关的系统调用。这有助于他们理解程序的内存管理机制。

**涉及二进制底层，Linux，Android内核及框架的知识:**

该脚本处理的许多函数和头文件都直接关联到操作系统底层和内核功能。

**举例说明:**

* **二进制底层:** `SIZEOF_INT`, `SIZEOF_VOID_P` 等检查与目标体系结构的字长和指针大小有关，这直接影响二进制代码的结构和内存布局。
* **Linux 内核:**
    * `mmap`, `mprotect`:  内存管理系统调用。
    * `fork`, `waitpid`:  进程管理相关的系统调用。
    * `sigaction`:  信号处理机制。
    * `epoll_create1`:  I/O 多路复用机制。
    * `eventfd`:  事件通知机制。
* **Android 框架 (间接):** 虽然脚本本身不直接涉及 Android 框架，但 Frida 作为一个动态插桩工具，广泛应用于 Android 平台的逆向和安全分析。Frida 使用的某些底层功能，例如进程注入、内存操作等，会间接涉及到 Android 内核提供的系统调用和框架层的一些机制。例如，`gettid()` (尽管不在当前列表中) 是一个在 Android 上常用的获取线程 ID 的方法。

**逻辑推理 (假设输入与输出):**

**假设输入 `config.h.meson`:**

```
#mesondefine HAVE_POSIX_MEMALIGN
#mesondefine SYS_SOCKET_H
#mesondefine SIZEOF_INT
```

**脚本逻辑推理:**

1. 遇到 `#mesondefine HAVE_POSIX_MEMALIGN`，查找 `function_data`，找到 `POSIX_MEMALIGN`，头文件为 `stdlib.h`。
2. 遇到 `#mesondefine SYS_SOCKET_H`，识别为头文件检查，提取头文件名 `sys/socket.h`。
3. 遇到 `#mesondefine SIZEOF_INT`，识别为 `sizeof` 检查，提取类型名 `int`。

**假设输出的 Meson 代码片段:**

```
if cc.has_function('posix_memalign', prefix : '#include<stdlib.h>')
  cdata.set('HAVE_POSIX_MEMALIGN', 1)
endif

if cc.has_header('sys/socket.h')
  cdata.set('HAVE_SYS_SOCKET_H', 1)
endif

cdata.set('SIZEOF_INT', cc.sizeof('int'))
```

**用户或编程常见的使用错误:**

1. **忘记手动编辑 `config.h.meson`:**  用户可能直接运行脚本在 `config.h.in` 上，导致脚本无法正确识别 `#mesondefine` 指令，因为原始的 `config.h.in` 文件使用的是 `#undef`。
   * **举例:** 如果用户直接对包含 `#undef HAVE_MMAP` 的 `config.h.in` 运行脚本，则不会生成任何关于 `HAVE_MMAP` 的 Meson 代码。
2. **`function_data` 不完整或错误:**  如果 `function_data` 字典中缺少某个函数或其关联的头文件信息不正确，脚本就无法为该函数生成正确的 Meson 检查代码。
   * **举例:** 如果某个库引入了一个新的函数 `my_new_function`，但 `function_data` 中没有该函数的条目，即使 `config.h.meson` 中有 `#mesondefine HAVE_MY_NEW_FUNCTION`，脚本也只会生成一个简单的 `cdata.set('HAVE_MY_NEW_FUNCTION', 1)`，而不会执行实际的函数存在性检查。
3. **`config.h.meson` 中存在与配置检查无关的 `#mesondefine`:**  虽然脚本尽力只处理配置检查相关的宏，但如果 `config.h.meson` 中存在其他用途的 `#mesondefine`，可能会被错误地处理。
   * **举例:**  如果 `config.h.meson` 中有 `#mesondefine MY_CUSTOM_SETTING 123`，脚本可能会尝试将其解释为头文件或函数检查。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 构建过程:** 用户通常是为了构建 Frida 或其某个组件（如 `frida-qml`）而执行构建命令，例如使用 Meson 或 Ninja。
2. **配置阶段:** 在 Meson 构建系统的配置阶段，会执行一系列的检查来确定目标系统的特性。这通常涉及到运行一些小的测试程序或检查头文件是否存在。
3. **生成 `config.h.in`:**  在某些构建流程中，可能会先使用 Autoconf 或类似的工具生成一个 `config.h.in` 文件，其中包含了大量的 `#undef` 宏。
4. **手动转换到 `config.h.meson`:** 按照脚本的说明，用户需要手动将 `config.h.in` 复制到 `config.h.meson`，并将 `#undef` 替换为 `#mesondefine`。这是因为某些 `#undef` 可能与配置检查无关，需要人工区分。
5. **运行 `ac_converter.py`:**  Meson 构建系统会在适当的时候调用 `ac_converter.py` 脚本，并将 `config.h.meson` 的路径作为命令行参数传递给它。
6. **生成 `config.h`:**  `ac_converter.py` 解析 `config.h.meson` 并生成 Meson 的配置数据声明，最终 Meson 会使用这些数据生成 `config.h` 文件，其中包含了 `#define` 宏，指示了系统特性。

**作为调试线索:**

如果 Frida 的构建过程中出现与系统特性检测相关的问题，例如某个功能因为缺少某个头文件或函数而无法启用，开发者可能会检查以下内容：

* **`config.h.in` 的内容:** 确保 Autoconf 或其他工具正确地检测到了系统的特性。
* **`config.h.meson` 的内容:** 确保手动转换过程正确无误，所有的 `#undef` 都被替换成了 `#mesondefine`。
* **`ac_converter.py` 的输出:** 查看脚本生成的 Meson 代码，确认它是否正确地反映了 `config.h.meson` 中的信息。
* **`config.h` 的内容:** 查看最终生成的 `config.h` 文件，确认其中是否包含了期望的 `#define` 宏。

通过这些步骤，可以追踪配置检查的流程，定位问题可能出现的环节。例如，如果 `config.h` 中缺少了某个预期的宏定义，可以回溯到 `ac_converter.py` 的输入 (`config.h.meson`)，查看相应的 `#mesondefine` 是否存在，以及 `ac_converter.py` 是否正确地处理了它。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/tools/ac_converter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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