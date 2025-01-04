Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The first step is to read the introductory comments. The script's purpose is clearly stated: it converts information from a `config.h.meson` file (derived from a `config.h.in`) into Meson declarations. It specifically focuses on header and function availability checks. This immediately tells us the script's role in a build system (Meson) and its connection to configuration.

**2. Identifying Key Data Structures:**

Scanning the code reveals the `function_data` dictionary. This is crucial. It maps symbolic names (like `HAVE_MMAP`) to actual function names (`mmap`) and the header file required for that function (`sys/mman.h`). This suggests the script aims to determine if these functions are available on the target system.

**3. Tracing the Input and Output:**

The script takes one command-line argument: the path to the `config.h.meson` file. It then processes this file line by line. The output is printed to standard output, and the comments and the end of the script indicate that this output is designed to be used in a `meson.build` file. Specifically, it generates `cdata.set()` calls that Meson can interpret.

**4. Analyzing the Logic - Header Checks:**

The code iterates through the lines of the input file, looking for lines starting with `#mesondefine` and ending with `_H`. This pattern suggests it's identifying header availability. The script extracts the header name, converts it to a standard format (lowercase, `.h` extension), and stores it in the `headers` list. The output part then iterates through this list, using `cc.has_header()` to check for the header's existence and sets a corresponding `cdata` variable.

**5. Analyzing the Logic - Function Checks:**

The script looks for lines that can be split into at least two parts. It checks if the second part (`arr[1]`) is a key in the `function_data` dictionary. If it is, it extracts the function name and its header. If it starts with `HAVE_` but isn't in `function_data`, it's treated as a generic function check. The output part uses `cc.has_function()` to perform the check and set a `cdata` variable.

**6. Analyzing the Logic - Sizeof Checks:**

The code looks for lines with exactly two parts, where the second part starts with `SIZEOF_`. It then extracts the type name, performs some string manipulations to normalize it, and uses `cc.sizeof()` to get the size, setting a `cdata` variable.

**7. Identifying Connections to Reverse Engineering:**

Now, consider how this relates to reverse engineering:

* **Function Availability:** Knowing which functions are available on a target system is crucial for understanding the capabilities of a binary. Reverse engineers often need to identify system calls or library functions used by a program. This script automates a part of that discovery process during the build.
* **Header Files:**  Header files provide definitions and declarations for functions, data structures, and constants. Knowing which headers are present helps understand the programming environment and available APIs.
* **Data Type Sizes:**  Understanding the size of data types is essential for analyzing memory layouts and interpreting binary data. This script helps determine the sizes of fundamental types on the target architecture.

**8. Identifying Connections to Low-Level Concepts:**

* **System Calls:** Many of the functions listed in `function_data` are system calls or functions that directly interact with the operating system kernel (e.g., `mmap`, `fork`, `socket`).
* **Kernel Frameworks (indirectly):** While the script doesn't directly interact with kernel code, knowing the availability of functions like `inotify_init1` (for file system events) or `eventfd` (for inter-process communication) hints at the presence and potential usage of kernel features and frameworks.
* **Linux/Android Focus:**  The inclusion of functions like `getrandom` (specific to Linux) and the overall nature of the checks point to a focus on Linux-like environments, which includes Android.

**9. Considering Edge Cases and Errors:**

* **Manual Editing of `config.h.meson`:** The script relies on the user correctly converting `#undef` to `#mesondefine`. Forgetting to do this would lead to incorrect results.
* **Unrelated `#undef`s:** The script acknowledges that some `#undef` statements are unrelated to feature checks, hence the manual conversion step.
* **Typos in `function_data`:**  If there are errors in the `function_data` dictionary, the script might not correctly identify function availability.

**10. Constructing Examples:**

Based on the understanding of the script's logic,  it's possible to construct meaningful examples for input and output, and to illustrate how user actions lead to the script's execution.

**Self-Correction/Refinement:**

Initially, one might focus too much on the specific details of each function. However, the core purpose is about *configuration* and *feature detection*. The details of each individual function are less important than understanding *why* these checks are being performed. Also, recognizing the limitations of the script (the manual `#undef` replacement) is important for a complete analysis. Realizing the connection to Meson's build process is key to understanding the script's context.
This Python script, `ac_converter.py`, is a utility designed to bridge the gap between traditional autoconf-style configuration and the Meson build system. Its primary function is to parse a specially prepared header file (`config.h.meson`) and generate corresponding Meson build definitions based on the presence or absence of certain headers, functions, and data type sizes.

Here's a breakdown of its functionality:

**1. Parsing `config.h.meson`:**

   - The script reads a `config.h.meson` file, which is expected to be a modified version of a `config.h.in` file. The modification involves replacing `#undef` directives (typically used to indicate the absence of a feature) with `#mesondefine`.
   - It iterates through each line of the file.

**2. Identifying Header Availability:**

   - It looks for lines starting with `#mesondefine` and ending with `_H`. This pattern signifies a header check.
   - For example, a line like `#mesondefine HAVE_SYS_SOCKET_H` indicates a check for the `sys/socket.h` header.
   - It extracts the header name (e.g., `sys/socket.h`) and stores it in the `headers` list.

**3. Identifying Function Availability:**

   - It looks for lines that can be split into at least two words.
   - It checks if the second word (e.g., `HAVE_MMAP`) exists as a key in the `function_data` dictionary. This dictionary maps symbolic names (like `HAVE_MMAP`) to the actual function name (`mmap`) and the header file where it's typically declared (`sys/mman.h`).
   - If the token starts with `HAVE_` and doesn't end with `_H` and isn't in `function_data`, it's also considered a potential function check.
   - It stores information about the function checks in the `functions` list.

**4. Identifying Data Type Sizes:**

   - It looks for lines with exactly two words where the second word starts with `SIZEOF_`.
   - For example, `SIZEOF_INT` indicates a check for the size of an `int`.
   - It extracts the type name and performs some basic transformations (e.g., replacing `_P` with `*` for pointers) to get the C type name.
   - It stores the symbolic name and the C type name in the `sizes` list.

**5. Generating Meson Declarations:**

   - It prints out Meson code that uses the `cc` (C compiler) object and `configuration_data()` object.
   - **Header Checks:** For each header identified, it generates Meson code to check if the header exists using `cc.has_header(h)`. If it exists, it sets a corresponding variable in the `cdata` object (e.g., `cdata.set('HAVE_SYS_SOCKET_H', 1)`).
   - **Function Checks:** For each function check, it generates Meson code to check if the function exists using `cc.has_function(f.get(1), prefix : f.get(2))`. The `prefix` argument allows specifying a header to include before the check. If the function exists, it sets a corresponding variable in `cdata`.
   - **Sizeof Checks:** For each size check, it generates Meson code to determine the size of the data type using `cc.sizeof('{typename}')` and sets the corresponding variable in `cdata`.

**6. Creating `config.h`:**

   - Finally, it uses the `configure_file` Meson function to create the actual `config.h` file. It takes `config.h.meson` as input, uses the collected configuration data (`cdata`), and outputs `config.h`.

**Relationship with Reverse Engineering:**

This script has indirect but important connections to reverse engineering:

* **Identifying Available Functions and Libraries:**  Reverse engineers often need to understand which system calls, library functions, and data structures are available in the target environment. This script automates the process of determining the availability of common functions and headers, which is valuable information for understanding a compiled binary. If a reverse engineer sees that a certain `HAVE_` macro is defined in the generated `config.h`, they know the corresponding function is likely available and used by the software.
    * **Example:** If `HAVE_MMAP` is defined (meaning `mmap` is available), a reverse engineer might suspect that the program uses memory mapping techniques.

* **Understanding Build-Time Configuration:**  Reverse engineering often involves analyzing how software was built. Knowing the configuration options and available features at compile time can provide valuable context for understanding the binary's behavior and limitations. This script reveals the outcomes of feature detection tests performed during the build process.
    * **Example:** If `HAVE_PTHREAD_CREATE` is *not* defined, the reverse engineer knows that the binary is likely not using POSIX threads, which simplifies the analysis of its concurrency model.

* **Determining Data Type Sizes:** The sizes of data types can vary across architectures and compilers. Knowing the sizes used during compilation is crucial for correctly interpreting memory layouts and data structures when reverse engineering.
    * **Example:** If `SIZEOF_INT` is 4, a reverse engineer knows that integer values are represented using 32 bits.

**Connections to Binary 底层 (Low-Level), Linux, Android Kernel and Frameworks:**

The script heavily interacts with concepts related to low-level programming, operating systems, and system libraries:

* **Binary 底层 (Low-Level):** The script deals with the availability of functions that directly interact with the operating system kernel (system calls) and low-level memory management (e.g., `mmap`, `malloc`). The `SIZEOF_` checks directly relate to how data is represented in binary form.
* **Linux Kernel:** Many of the functions checked (e.g., `epoll_create1`, `getrandom`, functions in `<sys/eventfd.h>`) are specific to the Linux kernel or are common system calls on Linux-based systems.
* **Android Kernel:**  Android's kernel is based on Linux, so many of the same system calls and headers are relevant. While the script doesn't explicitly target Android kernel details, the presence of these checks suggests the software might be intended for or compatible with Android.
* **Frameworks (indirectly):** The presence of checks for functions related to threading (`pthread.h`), networking (`sys/socket.h`, `netdb.h`), and file system operations (`fcntl.h`, `sys/stat.h`) indicates the potential use of these system-level frameworks.

**Logic 推理 (Logical Inference) with Assumptions:**

Let's consider a hypothetical input and output:

**假设输入 (`config.h.meson`):**

```
#mesondefine HAVE_UNISTD_H
#mesondefine HAVE_STDLIB_H
#mesondefine HAVE_PTHREAD_H
#mesondefine HAVE_SYS_TYPES_H

#mesondefine SIZEOF_INT 4
#mesondefine SIZEOF_VOID_P 8

#mesondefine HAVE_FORK
#mesondefine HAVE_MALLOC
#undef HAVE_NONEXISTENT_FUNCTION
```

**逻辑推理:**

The script will identify:

- Headers: `unistd.h`, `stdlib.h`, `pthread.h`, `sys/types.h`
- Sizes: `SIZEOF_INT`, `SIZEOF_VOID_P`
- Functions: `HAVE_FORK`, `HAVE_MALLOC`

**预计输出 (partial Meson code):**

```
cc = meson.get_compiler('c')
cdata = configuration_data()
check_headers = [
  'unistd.h',
  'stdlib.h',
  'pthread.h',
  'sys/types.h',
]

foreach h : check_headers
  if cc.has_header(h)
    cdata.set('HAVE_' + h.underscorify().to_upper(), 1)
  endif
endforeach

check_functions = [
  ['HAVE_FORK', 'fork', '#include<unistd.h>'],
  ['HAVE_MALLOC', 'malloc', '#include<stdlib.h>'],
# check token ['HAVE_NONEXISTENT_FUNCTION']
]

foreach f : check_functions
  if cc.has_function(f.get(1), prefix : f.get(2))
    cdata.set(f.get(0), 1)
  endif
endforeach

cdata.set('SIZEOF_INT', cc.sizeof('int'))
cdata.set('SIZEOF_VOID_P', cc.sizeof('void *'))

configure_file(input : 'config.h.meson',
  output : 'config.h',
  configuration : cdata)
```

**用户或编程常见的使用错误:**

1. **Forgetting to replace `#undef` with `#mesondefine`:** If the user forgets to modify `config.h.in` correctly, the script won't identify the features that should be present.
   * **Example:** If `config.h.meson` still has `#undef HAVE_MMAP`, the script won't generate a check for `mmap`.

2. **Incorrectly modifying `config.h.meson`:**  Users might accidentally introduce syntax errors or modify lines that shouldn't be changed.
   * **Example:**  Changing `#mesondefine HAVE_SYS_SOCKET_H` to `#mesondefine HAVE_SOCKET` would lead to an incorrect variable name in the generated Meson code.

3. **Not providing the correct input file:** Running the script without specifying the `config.h.meson` file or providing the wrong file path will result in an error or unexpected behavior.

4. **Relying solely on this script:** This script only handles a specific set of checks. More complex configuration logic might require additional custom Meson code.

**用户操作到达这里的调试线索:**

Imagine a developer working on the Frida project and encountering an issue where a certain feature isn't being detected correctly by the Meson build system. Here's how they might end up looking at `ac_converter.py`:

1. **Initial Problem:** A build fails, or a feature that should be available isn't enabled in the built Frida components.
2. **Investigation of Build System:** The developer starts examining the `meson.build` files and the generated `config.h`. They notice that certain `HAVE_` macros are not defined as expected.
3. **Tracing Configuration:** They realize that the `config.h` is generated from `config.h.meson`.
4. **Examining `config.h.meson`:** The developer checks the `config.h.meson` file to see if the corresponding `#mesondefine` is present.
5. **Suspecting Conversion Issues:** If the `#mesondefine` is present in `config.h.meson`, but the `HAVE_` macro isn't set in the final `config.h`, the developer might suspect an issue with the conversion process.
6. **Looking at `ac_converter.py`:** The developer identifies `ac_converter.py` as the tool responsible for parsing `config.h.meson` and generating the Meson configuration.
7. **Analyzing the Script:** They would then examine the logic of `ac_converter.py` to understand how it identifies headers, functions, and sizes, and how it generates the Meson code. They might look for potential bugs in the parsing logic or discrepancies between the `function_data` and the actual checks being performed.
8. **Debugging:** They might then try running `ac_converter.py` manually on the `config.h.meson` file to see the generated Meson code and identify if the issue lies there. They might also add debugging print statements to `ac_converter.py` to track its execution and the values of variables.

This step-by-step process illustrates how understanding the role and functionality of `ac_converter.py` is crucial for debugging configuration-related issues in the Frida build process.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/tools/ac_converter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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