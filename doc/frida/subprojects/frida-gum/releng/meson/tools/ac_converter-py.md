Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The script's initial comment and help message are the first clue. It converts a `config.h.meson` file (derived from a `config.h.in`) into a regular `config.h` file. This conversion involves identifying header checks and function availability checks. The presence of `#mesondefine` hints at the usage of the Meson build system.

2. **Identify Key Operations:**  The script reads a file line by line and performs three main checks on each line:
    * **Header Checks:** Looks for lines starting with `#mesondefine` and ending with `_H`. This suggests checking for the existence of header files.
    * **Function Checks:**  Looks for lines where the second word is a key in the `function_data` dictionary or starts with `HAVE_` (but not ending in `_H`). This indicates checking for the availability of specific functions.
    * **Sizeof Checks:** Looks for lines with two words where the second word starts with `SIZEOF_`. This clearly points to determining the size of data types.

3. **Analyze Data Structures:**
    * **`function_data` Dictionary:** This is crucial. It maps preprocessor macros (like `HAVE_MMAP`) to the actual function name (`mmap`) and the header file where it's declared (`sys/mman.h`). This strongly suggests the script is designed to detect the presence of these functions during the build process.
    * **`headers`, `functions`, `sizes` Lists:** These accumulate the information extracted from the input file based on the checks in step 2.

4. **Understand the Output:** The script generates Meson build system code. It uses `meson.get_compiler('c')` to get the C compiler object and `configuration_data()` to create a data structure to store configuration settings. The output code iterates through the collected headers and functions, using Meson's `has_header()` and `has_function()` to perform the checks. The results are then stored in the `cdata` object using `cdata.set()`. Finally, `configure_file()` is used to generate the `config.h` file.

5. **Connect to Reverse Engineering:**  The presence of function checks and header checks directly relates to reverse engineering. When analyzing a binary, you often need to know which system calls or library functions are used. This script automates the process of determining function availability at compile time. If a function like `mmap` is present, the corresponding `HAVE_MMAP` macro will be defined in `config.h`, and the compiled binary will likely use that function.

6. **Connect to Binary/Kernel/Framework:**  Many of the functions listed in `function_data` are low-level system calls or standard C library functions that directly interact with the operating system kernel (Linux, Android). Examples include `mmap`, `fork`, `socket`, `pthread_*`. The header files mentioned (like `sys/mman.h`, `unistd.h`, `pthread.h`) are standard Unix/Linux headers.

7. **Identify Logic and Assumptions:** The script assumes a specific format for the input `config.h.meson` file. It relies on the convention of using `HAVE_` prefixes for feature macros. The logic is straightforward: extract potential header/function/size information and then generate the corresponding Meson code to perform the actual checks during the build.

8. **Consider User Errors:**  The help message directly addresses a common user error: not correctly preparing the `config.h.meson` file by replacing `#undef` with `#mesondefine`. Other errors could involve providing the wrong input file or having an incorrectly formatted `config.h.meson`.

9. **Trace User Interaction:**  The prompt mentions the file path `frida/subprojects/frida-gum/releng/meson/tools/ac_converter.py`. This gives a strong indication of the context: building the Frida dynamic instrumentation tool using the Meson build system. The user would likely be running Meson commands to configure and build Frida, and this script would be executed as part of that build process.

10. **Refine and Structure the Explanation:**  Organize the findings into clear sections covering functionality, relevance to reverse engineering, binary/kernel/framework connections, logic/assumptions, user errors, and the user journey. Use examples to illustrate the points.

Essentially, the process involves reading the code, understanding its purpose, identifying its key actions, connecting it to the broader context of software development and reverse engineering, and then structuring the analysis in a clear and informative way.
这个Python脚本 `ac_converter.py` 的主要功能是将一个名为 `config.h.meson` 的文件转换成用于 Meson 构建系统的配置代码。它通过解析 `config.h.meson` 文件，识别其中定义的头文件检查、函数检查和类型大小检查，然后生成相应的 Meson 代码来执行这些检查，并将结果存储到 Meson 的配置数据中。

**功能列表：**

1. **解析 `config.h.meson` 文件:**  脚本读取指定的 `config.h.meson` 文件内容。
2. **识别头文件检查:**  查找以 `#mesondefine` 开头并以 `_H` 结尾的行，这些行通常表示头文件的存在性检查。例如 `#mesondefine HAVE_SYS_TYPES_H`。脚本会提取头文件名 (例如 `sys/types.h`)。
3. **识别函数检查:** 查找在 `function_data` 字典中存在的宏定义，或者以 `HAVE_` 开头但不以 `_H` 结尾的宏定义。`function_data` 字典预定义了一些常见的函数，并包含了函数名和所需头文件的信息。例如 `HAVE_MMAP` 对应 `mmap` 函数和 `sys/mman.h` 头文件。
4. **识别类型大小检查:** 查找以 `SIZEOF_` 开头的宏定义，表示需要检查某种数据类型的大小。例如 `SIZEOF_INT` 表示检查 `int` 类型的大小。
5. **生成 Meson 代码:** 根据识别出的头文件、函数和类型大小检查，生成相应的 Meson 代码片段。
    * **头文件检查:** 生成 `cc.has_header()` 调用，判断头文件是否存在。
    * **函数检查:** 生成 `cc.has_function()` 调用，判断函数是否存在，并可以指定所需的头文件。
    * **类型大小检查:** 生成 `cc.sizeof()` 调用，获取类型的大小。
6. **存储配置数据:**  将检查结果（头文件是否存在、函数是否存在、类型大小）存储到 Meson 的配置数据对象 `cdata` 中。
7. **生成 `config.h` 文件:** 使用 Meson 的 `configure_file()` 函数，根据 `config.h.meson` 模板和生成的配置数据 `cdata`，最终生成 `config.h` 文件。

**与逆向方法的关系及举例说明：**

这个脚本本身并不直接进行逆向操作，但它为 Frida 这样的动态 instrumentation 工具的构建过程服务，而动态 instrumentation 是逆向工程中常用的技术。

* **检测目标系统能力:**  在 Frida 构建过程中，需要了解目标系统（例如运行 Frida 的 Android 设备或 Linux 系统）是否支持某些特定的函数或特性。`ac_converter.py` 自动化了这个检测过程。
* **根据目标系统调整代码:** 通过检查函数和头文件的存在性，Frida 的代码可以根据目标系统的能力选择不同的实现方式或启用/禁用某些功能。这在逆向分析时非常重要，因为不同的系统可能有不同的 API 和特性。

**举例说明：**

假设在 `config.h.meson` 中有如下内容：

```meson
#mesondefine HAVE_SYS_MMAN_H
#mesondefine HAVE_POSIX_MEMALIGN
```

`ac_converter.py` 会解析这两行：

* `#mesondefine HAVE_SYS_MMAN_H`:  识别出需要检查头文件 `sys/mman.h` 的存在性。
* `#mesondefine HAVE_POSIX_MEMALIGN`:  在 `function_data` 中找到 `HAVE_POSIX_MEMALIGN` 对应的函数是 `posix_memalign`，需要包含头文件 `stdlib.h`。

脚本会生成如下 Meson 代码：

```meson
cc = meson.get_compiler('c')
cdata = configuration_data()
check_headers = [
  'sys/mman.h',
]

foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

check_functions = [
  ['HAVE_POSIX_MEMALIGN', 'posix_memalign', '#include<stdlib.h>'],
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2))
    cdata.set(f.get(0), 1)
  endif
endforeach
```

如果构建系统检测到 `sys/mman.h` 存在，并且 `posix_memalign` 函数可用，那么生成的 `config.h` 文件中会包含：

```c
#define HAVE_SYS_MMAN_H 1
#define HAVE_POSIX_MEMALIGN 1
```

Frida 的源代码就可以根据这些宏定义来决定是否使用 `posix_memalign` 或相关的内存管理函数。在逆向分析 Frida 时，了解这些条件编译的宏定义可以帮助理解 Frida 在目标系统上的具体行为。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

`function_data` 字典中包含了大量与操作系统底层交互的函数，这些函数通常是逆向分析人员需要关注的重点：

* **内存管理:** `mmap`, `mprotect`, `posix_memalign`, `malloc`, `free` 等函数直接与进程的内存空间操作相关。在逆向分析恶意软件或进行漏洞挖掘时，理解这些内存操作至关重要。例如，`mmap` 用于创建内存映射，常用于加载动态链接库。
* **进程控制:** `fork`, `execv`, `waitpid` 等函数用于创建、执行和管理进程。逆向分析程序如何启动子进程、如何进行进程间通信等需要了解这些函数。
* **信号处理:** `sigaction`, `raise` 等函数用于处理操作系统信号。理解程序如何响应信号可以揭示其错误处理机制或特定的行为模式。
* **文件和 I/O:** `open`, `read`, `write`, `close`, `stat` 等函数用于进行文件和输入/输出操作。逆向分析程序如何读写文件、访问哪些资源是常见的任务。
* **线程:** `pthread_attr_setstacksize`, `pthread_condattr_setclock` 等函数是 POSIX 线程库的一部分，用于创建和管理线程。多线程程序的逆向分析需要理解线程的创建、同步和通信机制。
* **Android 框架 (间接体现):** 虽然脚本本身不直接涉及 Android framework，但一些检查的函数（例如与时间相关的函数）在 Android 系统中也有其特定的实现和行为。Frida 作为在 Android 上运行的工具，需要考虑 Android 系统的特性。

**逻辑推理、假设输入与输出：**

**假设输入 `config.h.meson`:**

```meson
#mesondefine HAVE_UNISTD_H
#mesondefine HAVE_GETTIMEOFDAY
SIZEOF_INT
```

**`ac_converter.py` 的逻辑推理：**

1. 识别到 `#mesondefine HAVE_UNISTD_H`，提取头文件名 `unistd.h`。
2. 识别到 `#mesondefine HAVE_GETTIMEOFDAY`，在 `function_data` 中找到对应函数 `gettimeofday` 和头文件 `sys/time.h`。
3. 识别到 `SIZEOF_INT`，提取类型名 `int`。

**假设输出 Meson 代码：**

```meson
cc = meson.get_compiler('c')
cdata = configuration_data()
check_headers = [
  'unistd.h',
]

foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

check_functions = [
  ['HAVE_GETTIMEOFDAY', 'gettimeofday', '#include<sys/time.h>'],
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

**假设最终生成的 `config.h` (取决于构建系统的实际检查结果):**

```c
#define HAVE_UNISTD_H 1
#define HAVE_GETTIMEOFDAY 1
#define SIZEOF_INT 4 // 假设 int 大小为 4 字节
```

**涉及用户或编程常见的使用错误及举例说明：**

1. **未正确转换 `#undef` 到 `#mesondefine`:**  脚本的帮助信息已经明确指出，需要手动将 `config.h.in` 中的 `#undef` 替换为 `#mesondefine`。如果用户忘记这样做，脚本可能无法正确识别需要检查的特性。

   **错误示例 `config.h.meson`:**

   ```meson
   #undef HAVE_MMAP
   ```

   `ac_converter.py` 将不会识别到需要检查 `mmap` 函数。

2. **`config.h.meson` 文件路径错误:** 用户可能提供了错误的 `config.h.meson` 文件路径作为命令行参数。

   **错误示例命令行:**

   ```bash
   python ac_converter.py wrong_config.h.meson
   ```

   脚本会抛出文件未找到的异常。

3. **`config.h.meson` 文件格式错误:**  如果 `config.h.meson` 中的 `#mesondefine` 行格式不符合预期（例如缺少空格），脚本的解析逻辑可能会出错。

   **错误示例 `config.h.meson`:**

   ```meson
   #mesondefine HAVE_UNISTD_H
   #mesondefineHAVE_GETTIMEOFDAY // 缺少空格
   ```

   脚本可能无法正确提取 `HAVE_GETTIMEOFDAY`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发或维护 Frida:** 开发者在添加新功能或修复 Bug 时，可能需要修改 Frida 的构建配置。
2. **修改 `config.h.in`:**  为了在构建过程中检测新的依赖或特性，开发者可能会修改 `frida/subprojects/frida-gum/releng/meson/config.h.in` 文件，添加新的 `#undef` 宏定义。
3. **手动替换 `#undef` 为 `#mesondefine`:**  根据脚本的说明，开发者需要将 `config.h.in` 中的 `#undef` 替换为 `#mesondefine`，并将结果保存为 `frida/subprojects/frida-gum/releng/meson/config.h.meson`。
4. **运行 Meson 配置:**  开发者执行 Meson 的配置命令，例如：

   ```bash
   meson setup build
   ```

5. **Meson 执行 `ac_converter.py`:**  Meson 构建系统在处理 `meson.build` 文件时，会调用 `ac_converter.py` 脚本，并将 `config.h.meson` 的路径作为参数传递给它。这通常在 `meson.build` 文件中有类似如下的定义：

   ```python
   config_h_meson = configure_file(
     input: 'config.h.meson',
     output: 'config.h',
     configuration: cdata,
     command: [python_module, releng_scripts_dir / 'ac_converter.py', '@INPUT@'],
   )
   ```

6. **脚本执行并生成 `config.h`:** `ac_converter.py` 读取 `config.h.meson`，执行解析和转换，并将结果写入 `config.h` 文件。

**作为调试线索:**

如果 Frida 的构建过程中出现与配置相关的错误，例如缺少某个宏定义或使用了不存在的函数，可以按照以下步骤进行调试：

1. **检查 `config.h.meson`:**  确认该文件是否已正确创建，并且 `#undef` 已被替换为 `#mesondefine`。
2. **检查 Meson 的构建日志:**  查看 Meson 的构建日志，确认 `ac_converter.py` 是否被正确执行，以及是否有任何错误信息输出。
3. **手动运行 `ac_converter.py`:**  尝试手动运行 `ac_converter.py`，并传入 `config.h.meson` 的路径，检查其输出是否符合预期。
4. **检查 `config.h`:**  查看生成的 `config.h` 文件，确认是否包含了预期的宏定义。如果缺少某些宏定义，可能是在 `config.h.meson` 中没有正确定义，或者 `ac_converter.py` 的解析逻辑存在问题。
5. **检查 `function_data`:**  如果涉及到函数检查，确认 `function_data` 字典中是否包含了需要检查的函数，并且函数名和头文件名是否正确。

总而言之，`ac_converter.py` 是 Frida 构建过程中的一个重要工具，它自动化了检测目标系统能力并生成相应配置代码的过程，这对于 Frida 能够跨平台运行并利用目标系统的特性至关重要。了解其功能和工作原理有助于理解 Frida 的构建过程，并在遇到配置问题时进行调试。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/tools/ac_converter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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