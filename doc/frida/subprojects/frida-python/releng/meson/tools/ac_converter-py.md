Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to read the docstring and comments at the beginning of the script. These provide the primary purpose: converting `config.h.meson` (a Meson-specific configuration file) into something Meson can understand to perform feature checks. The core idea is taking pre-existing C header-style checks (like `#mesondefine HAVE_MMAP`) and translating them into Meson's internal representation for those checks.

**2. Identifying Key Data Structures:**

The script uses a dictionary `function_data`. This immediately stands out as important. Analyzing its structure reveals it maps macro names (like `HAVE_MMAP`) to tuples containing the function name (`mmap`) and the header file (`sys/mman.h`). This suggests the script is primarily concerned with checking for the *existence* of specific functions and the headers they reside in.

**3. Tracing the Input and Output:**

The script takes one command-line argument: the path to the `config.h.meson` file. It outputs text to standard output, which the comments indicate will be consumed by Meson. This output is Meson build system code.

**4. Analyzing the Core Logic:**

The script reads the input file line by line. It then performs three main checks on each line:

* **Header Check:** Looks for lines starting with `#mesondefine` and ending with `_H`. It extracts the header name and stores it.
* **Function Check:**  Looks for lines containing a token present in the `function_data` dictionary. If found, it extracts the function name and associated header. It also handles cases where a `HAVE_` macro isn't in `function_data` (likely a simpler existence check).
* **Sizeof Check:** Looks for lines with two words where the second word starts with `SIZEOF_`. It extracts the type name and prepares it for Meson's `sizeof` function.

**5. Understanding the Output Generation:**

The script generates Meson code. It initializes a `configuration_data` object.

* **Header Checks Output:** It iterates through the collected headers and generates Meson code using `cc.has_header(h)` to check for the existence of each header. It then sets a corresponding `HAVE_...` variable in the `cdata`.
* **Function Checks Output:** It iterates through the collected functions and generates Meson code using `cc.has_function(f.get(1), prefix: f.get(2))` to check for the existence of each function, optionally with a required header. It sets the corresponding `HAVE_...` variable in `cdata`.
* **Sizeof Checks Output:**  It iterates through the collected size checks and generates Meson code using `cc.sizeof('{typename}')` to determine the size of various data types.

**6. Connecting to Reverse Engineering (and other concepts):**

At this point, the connection to reverse engineering, binary internals, etc., becomes clearer. The script isn't *performing* these actions itself. Instead, it's a *tool* within a larger build process that *enables* decisions based on these lower-level details.

* **Reverse Engineering:** The *need* for these checks often arises from reverse engineering. When porting software to different platforms, you might encounter code that relies on specific system calls or libraries. Reverse engineering can help identify these dependencies, leading to the creation of `config.h.in` (the precursor to `config.h.meson`) which this script processes.
* **Binary/OS Internals:** The very existence of functions like `mmap`, `getpagesize`, `sigaction`, etc., are deeply tied to operating system kernels and their APIs. The script's purpose is to detect whether these OS features are available on the target system.
* **Linux/Android Kernels/Frameworks:**  Many of the listed functions are standard POSIX functions common on Linux and Android. The script's ability to check for them makes the build process adaptable to these environments.

**7. Formulating Examples (Hypotheses and Errors):**

With a good understanding of the script's functionality, generating examples becomes straightforward:

* **Logical Inference:**  Pick a function from `function_data` (e.g., `HAVE_MMAP`). Imagine the input `config.h.meson` has `#mesondefine HAVE_MMAP`. The script should output Meson code that checks for `mmap` and sets `cdata.set('HAVE_MMAP', 1)`.
* **User Errors:**  Consider how a user might misuse the script or the input file. Forgetting to run the script, incorrect `config.h.meson` syntax, or missing dependencies (like Meson itself) are all possibilities.

**8. Tracing User Steps:**

To understand how a user reaches this script, think about the typical build process for a project using Meson and autoconf-like checks:

1. The project uses a `configure` script (or similar) that generates `config.h.in`.
2. The user *manually* edits `config.h.in`, replacing `#undef` with `#mesondefine` for relevant checks, saving it as `config.h.meson`.
3. The user executes this Python script (`ac_converter.py`) providing the path to `config.h.meson`.
4. The output of this script is then used by Meson during the actual build process.

By following these steps, we can construct a comprehensive explanation of the script's purpose, its relationship to various technical concepts, and potential usage scenarios.
这个Python脚本 `ac_converter.py` 的主要功能是将类似于 `config.h.in` 文件的内容（经过少量修改后命名为 `config.h.meson`）转换为 Meson 构建系统能够理解的配置数据。它主要关注识别头文件检查和函数检查，并将它们转换为 Meson 的声明。

以下是其功能的详细列表：

**1. 解析 `config.h.meson` 文件:**
   - 读取输入的 `config.h.meson` 文件，逐行分析其内容。

**2. 识别头文件检查:**
   - 查找以 `#mesondefine` 开头并且以 `_H` 结尾的行。
   - 从这些行中提取头文件名（例如，`HAVE_SYS_MMAN_H` 对应 `sys/mman.h`）。
   - 将提取出的头文件名存储在一个列表中。

**3. 识别函数检查:**
   - 查找包含 `HAVE_` 前缀的宏定义的行。
   - 它维护一个预定义的字典 `function_data`，其中包含了常见的函数宏（例如 `HAVE_MMAP`）以及对应的函数名（例如 `mmap`）和头文件（例如 `sys/mman.h`）。
   - 如果在 `function_data` 中找到匹配的宏，则提取宏名、函数名和头文件名。
   - 如果宏以 `HAVE_` 开头但不在 `function_data` 中，则只记录宏名。

**4. 识别 `sizeof` 类型检查:**
   - 查找包含两个词的行，并且第二个词以 `SIZEOF_` 开头。
   - 从这些行中提取类型名（例如 `SIZEOF_SIZE_T` 对应 `size_t`）。
   - 它能处理一些简单的类型名转换，例如将 `_P` 替换为 `*` 表示指针。

**5. 生成 Meson 代码:**
   - 输出用于 Meson 构建系统的 Python 代码。
   - **头文件检查:**  生成 Meson 代码，使用 `cc.has_header(h)` 检查每个提取出的头文件是否存在，如果存在，则在 `cdata` 中设置相应的宏定义（例如，`HAVE_SYS_MMAN_H`）。
   - **函数检查:** 生成 Meson 代码，使用 `cc.has_function(f.get(1), prefix : f.get(2))` 检查每个提取出的函数是否存在，`prefix` 参数指定了包含该函数的头文件。如果存在，则在 `cdata` 中设置相应的宏定义（例如，`HAVE_MMAP`）。对于不在 `function_data` 中的 `HAVE_` 宏，它会输出注释，表示需要手动检查。
   - **`sizeof` 检查:** 生成 Meson 代码，使用 `cc.sizeof('{typename}')` 获取指定类型的大小，并将结果存储在 `cdata` 中。

**6. 创建 `config.h` 文件:**
   - 最后，它会生成 Meson 的 `configure_file` 命令，指示 Meson 使用生成的 `cdata` 来填充模板文件 `config.h.meson`，并生成最终的 `config.h` 文件。

**与逆向方法的关系及举例说明:**

这个脚本本身并不直接执行逆向工程，但它是构建 Frida 或其他需要与底层系统交互的软件的重要组成部分。在进行逆向工程时，你可能需要了解目标程序运行环境的特性和能力，例如是否支持某些特定的系统调用或库函数。

**举例说明:**

假设你正在逆向一个使用了 `mmap` 系统调用的程序。为了让你的 Frida 脚本或工具在不同的系统上正确编译和运行，你需要检查目标系统是否支持 `mmap`。

1. **`config.h.in` (或手动创建):**  你可能会在 `config.h.in` 文件中看到类似 `#undef HAVE_MMAP` 的条目。
2. **修改为 `config.h.meson`:** 你会手动将其修改为 `#mesondefine HAVE_MMAP`。
3. **运行 `ac_converter.py`:**  当你运行 `python ac_converter.py config.h.meson` 时，脚本会识别出 `HAVE_MMAP`。
4. **生成 Meson 代码:** 脚本会生成如下 Meson 代码：
   ```python
   if cc.has_function('mmap', prefix : '#include<sys/mman.h>')
     cdata.set('HAVE_MMAP', 1)
   endif
   ```
5. **Meson 构建:**  当 Meson 执行构建时，它会使用 C 编译器检查是否可以找到 `mmap` 函数（通过包含 `sys/mman.h`）。如果找到，`cdata` 中的 `HAVE_MMAP` 变量将被设置为 1。
6. **`config.h`:**  最终生成的 `config.h` 文件中会包含 `#define HAVE_MMAP 1` (如果系统支持 `mmap`) 或不包含此定义 (如果不支持)。

这样，Frida 的代码就可以根据 `config.h` 中的 `HAVE_MMAP` 宏来决定是否使用 `mmap` 或采用其他替代方案，从而实现跨平台的兼容性。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

`function_data` 字典中列出的许多函数都与操作系统底层操作密切相关，特别是 Linux 和 Android 系统：

**举例说明:**

* **`HAVE_MMAP`: (`mmap`, `sys/mman.h`)** - `mmap` 是一个 Linux/Unix 系统调用，用于将文件或设备映射到进程的地址空间。这在动态链接、共享内存等底层操作中非常常见。Frida 需要使用内存映射来注入代码和操作目标进程的内存。
* **`HAVE_GETPAGESIZE`: (`getpagesize`, `unistd.h`)** -  获取系统的内存页大小。Frida 需要知道页大小来进行内存管理和地址计算。
* **`HAVE_SIGACTION`: (`sigaction`, `signal.h`)** - 用于处理信号的系统调用。Frida 可以利用信号来中断目标进程或进行其他操作。
* **`HAVE_FORK`: (`fork`, `unistd.h`)** - 创建一个新的进程。Frida 在某些情况下可能需要 fork 来执行操作。
* **`HAVE_SCHED_GETAFFINITY`: (`sched_getaffinity`, `sched.h`)** - 获取或设置进程的 CPU 亲和性。Frida 可能需要控制其线程运行在哪些 CPU 核心上。
* **`HAVE_EVENTFD`: (`eventfd`, `sys/eventfd.h`)** -  创建一个事件文件描述符，用于进程间的事件通知。Frida 内部可能使用这种机制进行同步。
* **`HAVE_INOTIFY_INIT1`: (`inotify_init1`, `sys/inotify.h`)** - 初始化 inotify 子系统，用于监控文件系统事件。Frida 可能会利用它来监视目标进程加载的库或修改的文件。

这些函数都是构建在 Linux/Android 内核之上的 C 接口，Frida 作为动态分析工具，需要与这些底层机制进行交互。 `ac_converter.py` 的作用就是确保 Frida 的构建过程能够正确检测这些底层特性的存在，并在编译时做出相应的调整。

**逻辑推理及假设输入与输出:**

脚本的核心逻辑是模式匹配和数据转换。

**假设输入 (`config.h.meson`):**

```
#mesondefine HAVE_SYS_TYPES_H
#mesondefine HAVE_UNISTD_H
#mesondefine HAVE_STDLIB_H
#mesondefine HAVE_STRING_H
#mesondefine HAVE_FCNTL_H
#mesondefine HAVE_DLFCN_H
#mesondefine HAVE_SYS_MMAN_H
#mesondefine HAVE_SYS_TIME_H
#mesondefine HAVE_SYS_WAIT_H
#mesondefine HAVE_SCHED_H

#mesondefine HAVE_MMAP
#mesondefine HAVE_GETPAGESIZE
#mesondefine HAVE_DLOPEN

SIZEOF_VOID_P 8
SIZEOF_INT 4
```

**预期输出 (部分 Meson 代码):**

```python
cc = meson.get_compiler('c')
cdata = configuration_data()
check_headers = [
  'sys/types.h',
  'unistd.h',
  'stdlib.h',
  'string.h',
  'fcntl.h',
  'dlfcn.h',
  'sys/mman.h',
  'sys/time.h',
  'sys/wait.h',
  'sched.h',
]

foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

check_functions = [
  ['HAVE_MMAP', 'mmap', '#include<sys/mman.h>'],
  ['HAVE_GETPAGESIZE', 'getpagesize', '#include<unistd.h>'],
  ['HAVE_DLOPEN', 'dlopen', '#include<dlfcn.h>'],
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2))
    cdata.set(f.get(0), 1)
  endif
endforeach

cdata.set('SIZEOF_VOID_P', cc.sizeof('void*'))
cdata.set('SIZEOF_INT', cc.sizeof('int'))

configure_file(input : 'config.h.meson',
  output : 'config.h',
  configuration : cdata)
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **忘记运行 `ac_converter.py`:** 用户可能修改了 `config.h.meson` 文件，但忘记运行此脚本来生成 Meson 可以理解的配置数据。这会导致 Meson 构建时无法正确识别系统特性。
   * **错误现象:**  构建过程中可能会出现找不到某些函数或头文件的错误，或者程序的行为与预期不符，因为它没有正确检测到系统的能力。

2. **`config.h.meson` 格式错误:** 用户可能在编辑 `config.h.meson` 时引入了语法错误，例如拼写错误、缺少空格等。
   * **错误现象:**  `ac_converter.py` 脚本可能会抛出异常或生成不正确的 Meson 代码，导致构建失败或产生意外的行为。例如，如果 `#mesondefine HAVE_MMAP` 被错误地写成 `#mesondefine HAVE _MMAP`，脚本可能无法正确识别。

3. **`function_data` 中缺少条目:**  如果 `config.h.meson` 中包含了一个新的函数检查，但 `ac_converter.py` 的 `function_data` 字典中没有对应的条目，那么脚本只会识别出 `HAVE_XXX` 宏，但不会生成包含头文件的函数检查。
   * **错误现象:**  Meson 构建可能仍然会成功，但可能无法正确判断该函数是否存在，因为它缺少必要的头文件包含信息。这可能会导致在某些平台上构建失败，或者在运行时出现问题。用户需要手动更新 `function_data` 字典来解决这个问题。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **项目使用 Autoconf 或类似的配置系统 (或手动创建):**  Frida 的构建系统在早期或为了兼容性，可能仍然依赖于生成类似 `config.h.in` 的文件。或者，开发者可能手动创建了这样一个文件，或者从其他项目中复制而来。

2. **将 `config.h.in` 复制并重命名为 `config.h.meson`:**  为了与 Meson 集成，需要将传统的 `config.h.in` 文件复制一份，并重命名为 `config.h.meson`。

3. **修改 `config.h.meson`:**  用户需要手动编辑 `config.h.meson` 文件，将 Autoconf 的 `#undef` 替换为 Meson 的 `#mesondefine`。 这是因为 Meson 的配置系统需要特定的语法来识别配置项。脚本的帮助信息也明确指出了这一步。

4. **运行 `ac_converter.py`:**  在 `frida/subprojects/frida-python/releng/meson/tools/` 目录下，用户会执行命令 `python ac_converter.py config.h.meson`。

**作为调试线索:**

如果 Frida 的构建过程中出现与系统特性检测相关的问题，例如：

* **编译错误提示缺少某个本应存在的函数或头文件。**
* **程序在某些平台上运行时出现与系统调用或库函数相关的错误。**

那么，可以按照以下步骤进行调试：

1. **检查 `config.h` 文件:**  查看生成的 `config.h` 文件，确认相关的 `HAVE_XXX` 宏是否被正确定义。如果宏没有被定义，说明 Meson 在构建时没有检测到相应的特性。

2. **检查 `config.h.meson` 文件:**  确认 `config.h.meson` 文件中的 `#mesondefine` 语句是否正确，拼写是否正确。

3. **运行 `ac_converter.py` 并检查输出:**  手动运行 `ac_converter.py config.h.meson`，查看其输出的 Meson 代码，确认是否正确地转换了头文件和函数检查。特别注意 `check_functions` 部分，确认是否包含了正确的函数名和头文件路径。

4. **检查 `ac_converter.py` 代码:**  如果发现某些系统特性没有被正确检测，可能需要在 `ac_converter.py` 的 `function_data` 字典中添加相应的条目。

5. **检查 Meson 构建日志:**  查看 Meson 的构建日志，确认 `cc.has_header()` 和 `cc.has_function()` 的执行结果，以及 `cdata.set()` 的调用情况。

通过这些步骤，可以定位问题是出在 `config.h.meson` 的内容、`ac_converter.py` 的转换逻辑，还是 Meson 构建系统的执行过程中。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/tools/ac_converter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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