Response:
Let's break down the thought process for analyzing this Python script.

1. **Understanding the Purpose (High-Level):** The script's name, `ac_converter.py`, and the accompanying help message strongly suggest it converts something from `config.h.meson` to something else. The help mentions "header checks" and "meson declaration," indicating it's likely transforming build configuration information. The comment about replacing `#undef` with `#mesondefine` further reinforces this connection to a configuration process.

2. **Identifying Key Data Structures:**  The script initializes a few important data structures:
    * `function_data`:  A dictionary mapping macro names (like `HAVE_MMAP`) to function names (`mmap`) and their required header files (`sys/mman.h`). This looks like a predefined list of functions the build system might check for.
    * `headers`: An empty list to store header file names.
    * `functions`: An empty list to store information about functions to be checked.
    * `sizes`: An empty list to store information about data type sizes.

3. **Analyzing the Input Processing:** The script opens a file specified as a command-line argument (`sys.argv[1]`). It iterates through the lines of this file. Inside the loop, it performs several checks:
    * **Header Check:** It looks for lines starting with `#mesondefine` and ending with `_H`. This pattern suggests it's identifying lines defining the presence of specific header files. It extracts the header name and adds it to the `headers` list.
    * **Function Check:** It splits the line into words and tries to find the second word in the `function_data` dictionary. If found, it extracts the function name and header and adds relevant info to the `functions` list. It also handles cases where a `HAVE_` macro exists but isn't in the `function_data`.
    * **Sizeof Check:** It checks for lines with two words where the second word starts with `SIZEOF_`. It extracts the type name and adds the macro and type to the `sizes` list.

4. **Analyzing the Output Generation:** The script prints Python code that uses the Meson build system's API:
    * It gets a C compiler object (`meson.get_compiler('c')`).
    * It creates a configuration data object (`configuration_data()`).
    * **Header Conversion:** It iterates through the `headers` list and generates Meson code to check for the presence of each header using `cc.has_header()`. If a header is found, it sets a corresponding `HAVE_` macro in the `cdata`.
    * **Function Conversion:** It iterates through the `functions` list and generates Meson code to check for the presence of each function using `cc.has_function()`, optionally specifying a prefix (include directive). If a function is found, it sets a corresponding macro in `cdata`.
    * **Sizeof Conversion:** It iterates through the `sizes` list and generates Meson code to determine the size of each data type using `cc.sizeof()` and sets the corresponding `SIZEOF_` macro in `cdata`.
    * Finally, it uses `configure_file()` to generate a `config.h` file based on the `config.h.meson` input and the collected configuration data in `cdata`.

5. **Connecting to Concepts (as requested in the prompt):**

    * **Reverse Engineering:** This script isn't directly involved in *disassembling* or *analyzing* compiled code. However, it *supports* the process by ensuring that the software being built is aware of the capabilities of the target system. Knowing which functions and headers are available is crucial for writing platform-independent code, which is relevant when reverse engineering on different platforms.

    * **Binary/Low-Level:** The script directly deals with the availability of low-level system calls and data types (like `mmap`, `getpagesize`, `size_t`). The `sizeof` checks are inherently about the binary representation of data.

    * **Linux/Android Kernel/Framework:** Many of the functions listed in `function_data` are standard POSIX/Linux system calls (`fork`, `mprotect`, `socket`) or related to the C standard library. Some, like `eventfd` and `inotify_init1`, are Linux-specific. While not directly Android kernel-specific in this code,  Frida often targets Android, and the availability of these functions is relevant to its functionality *on* Android. The framework aspect comes into play because the presence or absence of these functions influences *how* Frida operates.

    * **Logical Reasoning:** The script follows a simple but clear logic:
        * **Input:**  A `config.h.meson` file containing preprocessor directives.
        * **Processing:**  Parsing the file to identify header, function, and size checks.
        * **Output:**  Generating Meson build system code that performs these checks and creates a `config.h` file.
        * *Assumption (Implicit):* The `config.h.meson` file follows a specific format with `#mesondefine` for headers and `HAVE_` prefixes for function checks.

    * **User Errors:** The primary user error is providing an incorrectly formatted `config.h.meson` file. This would cause the parsing logic to fail and potentially generate incorrect or incomplete `config.h`. For example, if `#mesondefine` is misspelled, the header check won't be recognized. If `HAVE_` prefixes are missing or inconsistent, function checks will be missed.

    * **User Journey (Debugging):** A developer might encounter this script during the build process of Frida. If the build fails due to missing function declarations or incorrect header includes, they might examine the generated `config.h`. To understand *how* that file was created, they would trace back to the `ac_converter.py` script, seeing how it parses the `config.h.meson` file. They might then need to examine the `config.h.meson` file itself to see if the necessary `#mesondefine` or `HAVE_` macros are present and correctly formatted.

This detailed breakdown covers all the points raised in the original prompt by systematically analyzing the script's functionality and its relation to the broader context of software building and reverse engineering.
好的，让我们详细分析一下 `ac_converter.py` 脚本的功能及其与逆向工程的相关性。

**功能列表：**

`ac_converter.py` 的主要功能是将一个类似于 `config.h` 的文件（`config.h.meson`）转换为 Meson 构建系统可以理解的配置声明。具体来说，它做了以下几件事：

1. **解析 `config.h.meson` 文件:**  脚本读取 `config.h.meson` 文件的内容。
2. **识别头文件检查:**  它查找以 `#mesondefine` 开头且以 `_H` 结尾的行，这些行通常表示对头文件是否存在的检查。例如，`#mesondefine HAVE_SYS_MMAN_H`。
3. **提取头文件名:** 从识别到的行中提取出头文件的名称，例如 `sys/mman.h`。
4. **生成 Meson 头文件检查代码:**  根据提取的头文件名，生成相应的 Meson 代码，用于检查这些头文件是否存在。Meson 的 `cc.has_header()` 函数会被用到。
5. **识别函数检查:**  它查找包含 `HAVE_` 前缀的宏定义，这些宏定义通常表示对特定函数是否存在的检查。例如，`#mesondefine HAVE_MMAP`。
6. **查找预定义的函数信息:**  脚本内部维护了一个 `function_data` 字典，其中包含了常见的函数名、对应的头文件以及实际的函数名。
7. **生成 Meson 函数检查代码:**  根据识别到的宏定义和 `function_data` 中的信息，生成相应的 Meson 代码，用于检查这些函数是否存在。Meson 的 `cc.has_function()` 函数会被用到。
8. **识别 `sizeof` 检查:** 它查找以 `SIZEOF_` 开头的宏定义，这些宏定义表示对特定数据类型大小的检查。
9. **生成 Meson `sizeof` 检查代码:**  根据识别到的宏定义，生成相应的 Meson 代码，用于获取数据类型的大小。Meson 的 `cc.sizeof()` 函数会被用到。
10. **生成最终的 Meson 配置文件:**  脚本将生成的 Meson 代码片段组合起来，创建一个 Meson 可以执行的配置文件，这个文件最终会被用来生成 `config.h` 文件。

**与逆向方法的关系及举例：**

虽然此脚本本身不直接执行逆向操作（例如反汇编、动态调试），但它为 Frida 这样的动态插桩工具的构建过程提供支持，而 Frida 正是用于逆向工程的重要工具。

**举例说明：**

假设目标程序依赖于 `mmap` 函数。在构建 Frida 时，`ac_converter.py` 会读取 `config.h.meson`，其中可能包含类似 `#mesondefine HAVE_MMAP` 的行。

1. `ac_converter.py` 会识别 `HAVE_MMAP`。
2. 它会在 `function_data` 中查找 `HAVE_MMAP`，找到对应的信息：函数名是 `mmap`，头文件是 `sys/mman.h`。
3. 脚本会生成如下的 Meson 代码：
   ```python
   if cc.has_function('mmap', prefix : '#include<sys/mman.h>')
     cdata.set('HAVE_MMAP', 1)
   endif
   ```
4. 当 Meson 执行这段代码时，它会检查系统中是否存在 `mmap` 函数以及是否能包含 `sys/mman.h`。
5. 如果存在，Meson 会在生成的 `config.h` 文件中定义 `HAVE_MMAP` 宏，例如 `#define HAVE_MMAP 1`。

在 Frida 的代码中，可能会有这样的条件编译：

```c
#ifdef HAVE_MMAP
  // 使用 mmap 的代码
#else
  // 使用其他方式的代码
#endif
```

这样，Frida 在不同的系统上构建时，会根据 `config.h` 中的宏定义来选择不同的实现方式，以确保其能在目标系统上正确运行。这对于逆向工程师来说至关重要，因为他们需要在各种不同的环境下使用 Frida 对目标程序进行分析。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例：**

`ac_converter.py` 脚本背后的逻辑和它处理的宏定义直接反映了对操作系统底层知识的依赖。

**举例说明：**

* **二进制底层：**  `SIZEOF_` 相关的检查，例如 `SIZEOF_INT`，直接关系到 `int` 类型在目标系统上的字节大小。这对于理解内存布局、数据结构以及在不同架构之间进行移植至关重要。
* **Linux 内核：** 许多函数（如 `mmap`, `fork`, `sigaction`, `epoll_create1`, `inotify_init1`) 都是 Linux 系统调用或与 Linux 内核提供的功能密切相关。`ac_converter.py` 能检查这些函数的存在，意味着 Frida 可能使用了这些 Linux 特有的功能。
* **Android 框架：** 虽然脚本本身没有直接的 Android 特有代码，但 Frida 作为一个跨平台的工具，其在 Android 上的运行也依赖于底层的 Linux 内核以及 Android 框架提供的接口。例如，Frida 可能使用 `gettid()` 来获取线程 ID，这在 Linux 和 Android 上都是常见的。
* **头文件：** 脚本中大量使用的头文件（如 `unistd.h`, `sys/mman.h`, `signal.h`, `pthread.h`）都是 C 标准库或 POSIX 标准的一部分，它们提供了访问操作系统底层功能的接口。

**逻辑推理及假设输入与输出：**

脚本的核心逻辑是模式匹配和转换。

**假设输入 (`config.h.meson` 的部分内容):**

```
#mesondefine HAVE_SYS_TIME_H
#mesondefine HAVE_PTHREAD_H
#mesondefine HAVE_MMAP
#mesondefine SIZEOF_INT
```

**脚本的推理过程：**

1. 发现 `#mesondefine HAVE_SYS_TIME_H`，识别出需要检查 `sys/time.h` 头文件。
2. 发现 `#mesondefine HAVE_PTHREAD_H`，识别出需要检查 `pthread.h` 头文件。
3. 发现 `#mesondefine HAVE_MMAP`，在 `function_data` 中找到 `mmap` 函数的信息。
4. 发现 `#mesondefine SIZEOF_INT`，识别出需要检查 `int` 类型的大小。

**假设输出 (生成的 Meson 代码部分):**

```python
cc = meson.get_compiler('c')
cdata = configuration_data()
check_headers = [
  'sys/time.h',
  'pthread.h',
]

foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

check_functions = [
  ['HAVE_MMAP', 'mmap', '#include<sys/mman.h>'],
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

**用户或编程常见的使用错误及举例：**

1. **`config.h.meson` 格式错误：**
   * **错误示例：**  `#meson define HAVE_MMAP` (拼写错误)
   * **后果：** 脚本可能无法正确识别该行，导致 Meson 构建时没有检查 `mmap` 函数，最终生成的 `config.h` 中可能缺少 `HAVE_MMAP` 的定义。

2. **`config.h.meson` 中使用了未知的 `HAVE_` 宏：**
   * **错误示例：** `#mesondefine HAVE_MY_CUSTOM_FUNCTION`，但 `function_data` 中没有这个宏的定义。
   * **后果：** 脚本会识别出 `HAVE_MY_CUSTOM_FUNCTION`，但由于没有对应的函数信息，可能无法生成正确的 Meson 代码来检查该函数。

3. **忘记在 `config.h.meson` 中添加必要的宏：**
   * **错误示例：**  Frida 的代码使用了某个函数，但 `config.h.meson` 中没有对应的 `HAVE_` 宏。
   * **后果：**  Meson 构建时不会检查该函数，生成的 `config.h` 中缺少相应的定义，可能导致 Frida 在某些系统上运行时出现链接错误或运行时错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

通常，用户不会直接运行 `ac_converter.py`。它是 Frida 构建过程的一部分，由 Meson 构建系统自动调用。以下是用户操作可能导致涉及 `ac_converter.py` 的调试场景：

1. **用户尝试构建 Frida：** 用户按照 Frida 的文档或仓库中的说明，使用 Meson 构建 Frida。例如，他们可能会执行以下命令：
   ```bash
   mkdir build
   cd build
   meson ..
   ninja
   ```
2. **构建失败，提示缺少某些函数或头文件：** 在构建过程中，如果 Meson 报告找不到某些函数或头文件，用户可能会查看构建日志。
3. **查看 `config.h` 文件：**  用户可能会被引导查看生成的 `config.h` 文件，以了解哪些功能被检测到，哪些没有。
4. **发现 `config.h` 中缺少预期的宏定义：**  如果 `config.h` 中缺少了某个用户认为应该存在的 `HAVE_XXX` 宏，用户可能会怀疑是配置过程出了问题。
5. **检查 `config.h.meson` 文件：**  用户可能会查看 `frida/subprojects/frida-tools/releng/meson/tools/ac_converter.py` 脚本的说明，了解到 `config.h` 是由 `config.h.meson` 生成的。他们会检查 `config.h.meson` 文件，看是否包含了必要的 `#mesondefine` 行。
6. **分析 `ac_converter.py` 脚本：**  如果 `config.h.meson` 中看起来没问题，用户可能会进一步查看 `ac_converter.py` 脚本的逻辑，了解它是如何解析 `config.h.meson` 并生成 Meson 代码的。他们可能会检查 `function_data` 中是否包含了相关的函数信息。
7. **修改 `config.h.meson` 或 `ac_converter.py` (如果必要且理解风险)：**  如果用户确定是 `config.h.meson` 缺少了某些定义，他们可能会修改它。在更复杂的情况下，如果 `function_data` 中缺少某些信息，有经验的用户可能会尝试修改 `ac_converter.py`（但这通常是不推荐的，除非非常清楚自己在做什么）。
8. **重新构建 Frida：**  修改配置文件后，用户会重新运行 Meson 和 Ninja 来重新构建 Frida，观察问题是否解决。

总而言之，`ac_converter.py` 是 Frida 构建过程中的一个重要工具，它负责将通用的配置描述转换为 Meson 可以理解的构建指令，确保 Frida 能够在不同的系统上正确配置和编译。理解它的功能对于调试 Frida 的构建问题至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/tools/ac_converter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```