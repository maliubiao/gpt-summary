Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Core Purpose:**

The initial comments are crucial: "This script extracts the symbols of a given shared library into a file."  The follow-up sentence clarifies *why*: to skip relinking if the ABI hasn't changed. This immediately tells us the script is about dependency management and build optimization.

**2. Identifying Key Operations:**

Skimming the code, we see functions like `gnu_syms`, `osx_syms`, `windows_syms`, etc. These strongly suggest platform-specific logic for extracting symbols. The central function `gen_symbols` seems to orchestrate this based on the operating system.

**3. Analyzing Platform-Specific Logic:**

For each `*_syms` function, I'd look for:

* **Tools Used:**  What external utilities are being called (e.g., `readelf`, `nm`, `otool`, `dlltool`, `dumpbin`)?  This gives clues about the platform's symbol table format and the standard tools for interacting with it.
* **Command-Line Arguments:**  How are these tools being invoked? The arguments reveal what specific information is being extracted (e.g., dynamic symbols, external symbols, defined symbols, SONAME).
* **Output Processing:** How is the output of these tools parsed?  The script uses string manipulation (splitting lines, checking for specific keywords) to extract the relevant symbol information.
* **Handling Errors:** What happens if the tools aren't found or fail? The `call_tool` and `call_tool_nowarn` functions and the `print_tool_warning` function handle these cases.

**4. Recognizing Connections to Reverse Engineering:**

The use of tools like `readelf`, `nm`, and `otool` are strong indicators of a connection to reverse engineering. These tools are frequently used to inspect the internals of compiled binaries, including their symbol tables. The fact that the script *extracts* this information solidifies the connection.

**5. Identifying Low-Level Concepts:**

The mention of "shared library," "symbols," "dynamic linking," "ABI," "import library," and the use of platform-specific tools directly point to low-level operating system and compiler concepts. The differentiation between Linux, macOS, and Windows further emphasizes the OS-specific nature of binary formats and tooling.

**6. Spotting Logic and Assumptions:**

The `write_if_changed` function shows a clear logical step: only update the output file if the symbol information has changed. This is the core optimization logic. The cross-compilation handling is another logical branch: force relinking because cross-platform symbol extraction is complex.

**7. Considering User Errors:**

The script's reliance on external tools immediately brings up the possibility of those tools not being installed or in the system's PATH. The `print_tool_warning` function directly addresses this. Incorrect command-line arguments to the script itself are also a potential error.

**8. Tracing User Interaction (Debugging Clues):**

To understand how a user reaches this script, consider the build process:

* **Build System:** The script is part of Meson, a build system. The user would likely be using Meson to build a project.
* **Shared Library Target:** The project being built must involve creating a shared library.
* **Dependency Management:** Meson, in its optimization, uses this script to track changes in the shared library's symbols. This would happen automatically as part of the build process.
* **Debugging Scenario:** If relinking is happening unexpectedly, a developer might investigate *why*. This could lead them to this script to understand how Meson determines if relinking is necessary. They might examine the input and output files of this script.

**9. Structuring the Answer:**

Finally, I'd organize the information into the requested categories:

* **Functionality:** Start with the core purpose and then detail the platform-specific implementations.
* **Reverse Engineering:** Explain the connection and provide concrete examples of how the tools are used in reverse engineering.
* **Low-Level Concepts:** List the relevant concepts and provide brief explanations.
* **Logic and Assumptions:** Explain the decision-making within the code, particularly around optimization and cross-compilation.
* **User Errors:** Give practical examples of common mistakes.
* **User Journey:** Describe the steps a user might take that would lead to this script being executed, especially in a debugging context.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe the script directly parses binary files.
* **Correction:**  The script primarily calls external tools like `nm` and `readelf`, indicating reliance on existing utilities.
* **Initial thought:** Focus only on the positive aspects of the script.
* **Refinement:**  Consider error handling and potential user issues.
* **Initial thought:** Describe the functions in isolation.
* **Refinement:** Explain how the functions work together within the overall build process orchestrated by Meson.

By following this thought process, I could systematically analyze the script and generate a comprehensive explanation that addresses all the prompt's requirements.
这个Python脚本 `symbolextractor.py` 是 Frida 动态 instrumentation 工具构建系统 Meson 的一部分，它的主要功能是**提取共享库的符号信息，并将这些信息保存到一个文件中**。这个过程是为了优化构建过程，避免在共享库的应用程序二进制接口 (ABI) 没有变化时进行不必要的重新链接。

以下是更详细的功能列表以及与逆向、底层知识、逻辑推理、用户错误和调试线索相关的说明：

**1. 主要功能：提取共享库符号**

* **目的:**  为了跟踪共享库的 ABI 变化。如果共享库的导出符号没有改变，依赖于它的其他库或程序就不需要重新链接，从而加速构建过程。
* **实现方式:**  根据不同的操作系统，调用不同的命令行工具来获取符号信息。例如：
    * **Linux (gnu_syms):** 使用 `readelf` 获取库名 (SONAME)，使用 `nm` 获取导出的动态符号。
    * **macOS (osx_syms):** 使用 `otool` 获取库标识 (LC_ID_DYLIB)，使用 `nm` 获取导出的符号。
    * **Windows (windows_syms):** 使用 `lib.exe`, `llvm-lib.exe`, 或 `dlltool.exe` 获取 DLL 名称，使用 `dumpbin.exe`, `llvm-nm.exe`, 或 `nm.exe` 获取导出符号。
    * **其他平台:** 针对 OpenBSD、FreeBSD、NetBSD、Cygwin 和 Solaris 也有相应的处理函数。
* **输出:** 将提取到的符号信息（包括库名和导出的符号列表）写入一个指定的输出文件。

**2. 与逆向方法的联系及举例说明:**

这个脚本的核心功能与逆向工程密切相关。逆向工程师经常需要分析共享库的导出符号，以了解库的功能和接口，或者寻找可以利用的漏洞。

* **符号信息是逆向分析的基础:** 导出符号是共享库提供的公共接口，逆向工程师可以通过分析这些符号来理解库的用途，以及如何与库进行交互。例如，通过查看导出的函数名，可以猜测函数的功能；通过查看导出的全局变量，可以了解库的状态信息。
* **`nm` 工具的典型应用:**  脚本在多个平台都使用了 `nm` 命令。在逆向工程中，`nm` 是一个非常常用的工具，用于查看目标文件、库文件或可执行文件的符号表。逆向工程师可以使用 `nm` 来：
    * **识别库的导出函数:** 找到可以被其他模块调用的函数。
    * **查看全局变量:**  了解库提供的全局状态信息。
    * **分析符号类型:**  区分函数、数据对象等。
* **`readelf` 和 `otool` 的作用:** 脚本还使用了 `readelf` (Linux) 和 `otool` (macOS) 来获取库的元数据，例如 SONAME 或 LC_ID_DYLIB。这些信息对于理解库的身份和依赖关系非常重要，在逆向分析中也有应用。例如，通过 SONAME 可以了解库的规范名称，用于运行时链接。
* **`dumpbin` (Windows) 的使用:** 在 Windows 平台，脚本使用 `dumpbin -exports` 来获取导出符号，这也是逆向工程师常用的方法来查看 DLL 的导出函数。

**举例说明:**

假设有一个名为 `libtarget.so` 的共享库，逆向工程师想了解它的功能。他们可以使用如下命令：

```bash
nm --dynamic --extern-only --defined-only libtarget.so
```

这个命令类似于脚本中在 `gnu_syms` 函数中调用的 `nm` 命令。输出可能会包含如下内容：

```
0000000000001040 T initialize_library
0000000000001180 T process_data
00000000000030a0 D global_config
```

逆向工程师可以从这些符号信息中了解到，`libtarget.so` 库可能包含一个初始化函数 `initialize_library`，一个处理数据的函数 `process_data`，以及一个名为 `global_config` 的全局数据对象。

**3. 涉及二进制底层、Linux, Android 内核及框架的知识及举例说明:**

脚本的实现依赖于对底层二进制格式和操作系统特性的理解：

* **共享库和动态链接:** 脚本的目标是提取共享库的符号，这直接涉及到动态链接的概念。动态链接是操作系统加载和链接共享库的方式，允许程序在运行时加载所需的代码。理解动态链接的工作原理，例如链接器、加载器、符号解析等，有助于理解脚本的目的和实现。
* **符号表 (Symbol Table):**  脚本操作的核心是符号表。符号表是二进制文件中存储关于代码和数据地址、名称和类型等信息的表格。了解不同平台下符号表的格式 (例如 ELF, Mach-O, PE) 对于理解脚本如何提取信息至关重要。
* **ABI (Application Binary Interface):** 脚本的目标是检测 ABI 的变化。ABI 定义了不同编译单元或库之间进行交互的底层约定，包括函数调用约定、数据布局等。如果共享库的导出符号发生变化，可能意味着 ABI 发生了变化，依赖它的程序需要重新编译或链接。
* **操作系统特定的工具:** 脚本针对不同的操作系统调用不同的工具 (`nm`, `readelf`, `otool`, `dumpbin`, `dlltool`)，这些工具是操作系统提供的用于分析二进制文件的标准工具。了解这些工具的功能和使用方法是必要的。
* **Linux/Android 的 `readelf` 和 `nm`:** 在 Linux 和 Android 系统上，`readelf` 用于查看 ELF 格式文件的详细信息，包括动态段 (dynamic section)，其中包含了 SONAME 等信息。`nm` 用于查看符号表。Android 系统也基于 Linux 内核，因此这些工具和概念是共通的。
* **macOS 的 `otool` 和 `nm`:** 在 macOS 系统上，`otool` 用于显示 Mach-O 格式文件的各种信息，包括动态库 ID (LC_ID_DYLIB)。`nm` 的作用类似 Linux。
* **Windows 的 PE 格式和相关工具:** Windows 使用 PE (Portable Executable) 格式。`dumpbin` 是 Windows SDK 提供的用于查看 PE 文件信息的工具，包括导出表。`dlltool` 和 `lib.exe` 用于处理 DLL 的导入库。

**举例说明:**

在 Linux 上，`readelf -d libtarget.so` 命令可能会输出包含 `SONAME` 的行：

```
 0x000000000000000e (SONAME)             Library soname: [libtarget.so.1]
```

脚本的 `gnu_syms` 函数会解析这个输出，提取 `libtarget.so.1` 作为库名。这个 SONAME 是动态链接器在运行时查找库的依据。

**4. 逻辑推理及假设输入与输出:**

脚本中存在一些逻辑推理，用于确定需要提取哪些信息以及如何处理不同情况。

**假设输入:**

* `libfilename`:  `/path/to/libmylibrary.so` (Linux 共享库文件)
* `impfilename`:  `/path/to/libmylibrary.so` (在 Linux 上，`impfilename` 通常与 `libfilename` 相同，用于保持接口一致性)
* `outfilename`: `/path/to/libmylibrary.so.symbols`
* 假设系统安装了 `readelf` 和 `nm` 工具，并且在 PATH 环境变量中。

**逻辑推理过程 (针对 `gnu_syms`):**

1. **获取库名:** 调用 `readelf -d /path/to/libmylibrary.so`。
2. **解析 `readelf` 输出:** 查找包含 "SONAME" 的行，提取库名。假设找到 `Library soname: [libmylibrary.so.1]`，则库名为 `libmylibrary.so.1`。
3. **获取导出符号:** 调用 `nm --dynamic --extern-only --defined-only --format=posix /path/to/libmylibrary.so`。
4. **解析 `nm` 输出:**  遍历输出的每一行，提取符号名和类型。例如，如果输出包含：
   ```
   0000000000001040 T my_function
   00000000000030a0 D my_global_variable 4
   ```
   则提取 `my_function T` 和 `my_global_variable D 4`。注意，对于指向数据对象的符号，会存储其大小。
5. **组合结果:** 将库名和提取到的符号列表组合成一个字符串，每项占一行。
6. **检查是否需要更新输出文件:** 读取 `outfilename` 的内容，如果与新生成的符号信息相同，则不修改文件；否则，将新的符号信息写入 `outfilename`。

**预期输出 (`outfilename` 的内容):**

```
libmylibrary.so.1
my_function T
my_global_variable D 4
... (其他导出符号)
```

**5. 涉及用户或编程常见的使用错误及举例说明:**

* **缺少必要的工具:** 如果脚本依赖的工具（例如 `nm`, `readelf`）没有安装或者不在系统的 PATH 环境变量中，脚本会报错或产生不正确的结果。脚本中通过 `call_tool` 函数调用外部工具，并有相应的错误处理，但用户可能需要手动安装这些工具。
    * **错误示例:**  在没有安装 `readelf` 的 Linux 系统上构建项目，当执行到 `symbolextractor.py` 时，可能会出现 "readelf not found" 的错误，导致构建失败。
* **权限问题:**  如果用户对共享库文件没有读取权限，或者对输出文件目录没有写入权限，脚本会失败。
    * **错误示例:**  尝试提取一个只有 root 用户有读取权限的共享库的符号信息，脚本会因为权限不足而无法读取文件。
* **构建环境配置错误:**  交叉编译时，如果没有正确配置交叉编译工具链，脚本可能无法找到正确的 `nm` 等工具，导致符号提取失败。脚本中通过 `--cross-host` 参数来处理交叉编译的情况，但如果配置不当，仍然可能出错。
* **修改了共享库但未触发重新链接:**  虽然脚本的目标是避免不必要的重新链接，但如果由于某种原因（例如构建系统缓存机制问题）导致共享库的 ABI 发生了变化，但脚本认为没有变化，那么依赖它的程序可能会使用旧的接口，导致运行时错误。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

用户通常不会直接运行 `symbolextractor.py`。这个脚本是由 Meson 构建系统在构建过程中自动调用的。以下是用户操作如何一步步导致该脚本执行的典型场景：

1. **用户配置构建系统:** 用户使用 Meson 配置一个项目，该项目包含一个或多个共享库目标。例如，用户创建一个 `meson.build` 文件，其中定义了一个 `shared_library()` 目标。
2. **用户执行构建命令:** 用户在终端中运行 `meson compile` 或 `ninja` (如果使用 Ninja 后端) 等构建命令。
3. **Meson 构建系统处理共享库目标:** 当构建系统处理到一个共享库目标时，它会执行一系列操作，包括编译源代码、链接生成共享库。
4. **执行符号提取脚本:** 在链接生成共享库之后，Meson 会调用 `frida/releng/meson/mesonbuild/scripts/symbolextractor.py` 脚本，并将共享库文件路径、预期的符号输出文件路径等作为参数传递给它。
5. **脚本提取符号信息:** `symbolextractor.py` 根据操作系统调用相应的工具提取共享库的符号信息，并将结果写入输出文件。
6. **后续构建步骤依赖符号信息:**  Meson 会比较当前提取的符号信息与之前保存的符号信息。如果两者相同，则可以跳过某些后续的链接步骤，加快构建速度。

**作为调试线索:**

如果用户在构建过程中遇到与共享库链接相关的问题，例如链接错误或运行时符号找不到的错误，`symbolextractor.py` 及其输出文件可以作为调试线索：

* **检查符号输出文件:** 用户可以查看 `symbolextractor.py` 生成的符号输出文件，确认其中是否包含了预期的导出符号。如果缺少某些符号，可能意味着共享库的构建过程有问题，或者 `symbolextractor.py` 没有正确提取到符号。
* **比较符号输出文件的变化:**  如果构建过程中发生了意外的重新链接，用户可以比较不同构建过程生成的符号输出文件，找出 ABI 发生变化的根本原因。
* **检查 `symbolextractor.py` 的执行日志:**  虽然 `symbolextractor.py` 本身没有详细的日志输出，但构建系统的输出可能会包含关于该脚本执行的信息，例如调用的命令行和返回码，可以帮助诊断问题。
* **手动运行 `nm` 等工具:**  用户可以手动运行 `nm` 等工具来检查共享库的符号表，与 `symbolextractor.py` 的输出进行对比，验证脚本的正确性。

总而言之，`symbolextractor.py` 是 Frida 构建系统中的一个关键组件，用于优化共享库的构建过程。它通过提取和比较符号信息来判断 ABI 是否发生变化，从而避免不必要的重新链接。理解这个脚本的功能和实现方式，需要一定的逆向工程、底层二进制知识和操作系统特性方面的背景。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/scripts/symbolextractor.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2016 The Meson development team

# This script extracts the symbols of a given shared library
# into a file. If the symbols have not changed, the file is not
# touched. This information is used to skip link steps if the
# ABI has not changed.

# This file is basically a reimplementation of
# http://cgit.freedesktop.org/libreoffice/core/commit/?id=3213cd54b76bc80a6f0516aac75a48ff3b2ad67c
from __future__ import annotations

import typing as T
import os, sys
from .. import mesonlib
from .. import mlog
from ..mesonlib import Popen_safe
import argparse

parser = argparse.ArgumentParser()

parser.add_argument('--cross-host', default=None, dest='cross_host',
                    help='cross compilation host platform')
parser.add_argument('args', nargs='+')

TOOL_WARNING_FILE = None
RELINKING_WARNING = 'Relinking will always happen on source changes.'

def dummy_syms(outfilename: str) -> None:
    """Just touch it so relinking happens always."""
    with open(outfilename, 'w', encoding='utf-8'):
        pass

def write_if_changed(text: str, outfilename: str) -> None:
    try:
        with open(outfilename, encoding='utf-8') as f:
            oldtext = f.read()
        if text == oldtext:
            return
    except FileNotFoundError:
        pass
    with open(outfilename, 'w', encoding='utf-8') as f:
        f.write(text)

def print_tool_warning(tools: T.List[str], msg: str, stderr: T.Optional[str] = None) -> None:
    if os.path.exists(TOOL_WARNING_FILE):
        return
    m = f'{tools!r} {msg}. {RELINKING_WARNING}'
    if stderr:
        m += '\n' + stderr
    mlog.warning(m)
    # Write it out so we don't warn again
    with open(TOOL_WARNING_FILE, 'w', encoding='utf-8'):
        pass

def get_tool(name: str) -> T.List[str]:
    evar = name.upper()
    if evar in os.environ:
        import shlex
        return shlex.split(os.environ[evar])
    return [name]

def call_tool(name: str, args: T.List[str], **kwargs: T.Any) -> str:
    tool = get_tool(name)
    try:
        p, output, e = Popen_safe(tool + args, **kwargs)
    except FileNotFoundError:
        print_tool_warning(tool, 'not found')
        return None
    except PermissionError:
        print_tool_warning(tool, 'not usable')
        return None
    if p.returncode != 0:
        print_tool_warning(tool, 'does not work', e)
        return None
    return output

def call_tool_nowarn(tool: T.List[str], **kwargs: T.Any) -> T.Tuple[str, str]:
    try:
        p, output, e = Popen_safe(tool, **kwargs)
    except FileNotFoundError:
        return None, '{!r} not found\n'.format(tool[0])
    except PermissionError:
        return None, '{!r} not usable\n'.format(tool[0])
    if p.returncode != 0:
        return None, e
    return output, None

def gnu_syms(libfilename: str, outfilename: str) -> None:
    # Get the name of the library
    output = call_tool('readelf', ['-d', libfilename])
    if not output:
        dummy_syms(outfilename)
        return
    result = [x for x in output.split('\n') if 'SONAME' in x]
    assert len(result) <= 1
    # Get a list of all symbols exported
    output = call_tool('nm', ['--dynamic', '--extern-only', '--defined-only',
                              '--format=posix', libfilename])
    if not output:
        dummy_syms(outfilename)
        return
    for line in output.split('\n'):
        if not line:
            continue
        line_split = line.split()
        entry = line_split[0:2]
        # Store the size of symbols pointing to data objects so we relink
        # when those change, which is needed because of copy relocations
        # https://github.com/mesonbuild/meson/pull/7132#issuecomment-628353702
        if line_split[1].upper() in {'B', 'G', 'D'} and len(line_split) >= 4:
            entry += [line_split[3]]
        result += [' '.join(entry)]
    write_if_changed('\n'.join(result) + '\n', outfilename)

def solaris_syms(libfilename: str, outfilename: str) -> None:
    # gnu_syms() works with GNU nm & readelf, not Solaris nm & elfdump
    origpath = os.environ['PATH']
    try:
        os.environ['PATH'] = '/usr/gnu/bin:' + origpath
        gnu_syms(libfilename, outfilename)
    finally:
        os.environ['PATH'] = origpath

def osx_syms(libfilename: str, outfilename: str) -> None:
    # Get the name of the library
    output = call_tool('otool', ['-l', libfilename])
    if not output:
        dummy_syms(outfilename)
        return
    arr = output.split('\n')
    for (i, val) in enumerate(arr):
        if 'LC_ID_DYLIB' in val:
            match = i
            break
    result = [arr[match + 2], arr[match + 5]] # Libreoffice stores all 5 lines but the others seem irrelevant.
    # Get a list of all symbols exported
    output = call_tool('nm', ['--extern-only', '--defined-only',
                              '--format=posix', libfilename])
    if not output:
        dummy_syms(outfilename)
        return
    result += [' '.join(x.split()[0:2]) for x in output.split('\n')]
    write_if_changed('\n'.join(result) + '\n', outfilename)

def openbsd_syms(libfilename: str, outfilename: str) -> None:
    # Get the name of the library
    output = call_tool('readelf', ['-d', libfilename])
    if not output:
        dummy_syms(outfilename)
        return
    result = [x for x in output.split('\n') if 'SONAME' in x]
    assert len(result) <= 1
    # Get a list of all symbols exported
    output = call_tool('nm', ['-D', '-P', '-g', libfilename])
    if not output:
        dummy_syms(outfilename)
        return
    # U = undefined (cope with the lack of --defined-only option)
    result += [' '.join(x.split()[0:2]) for x in output.split('\n') if x and not x.endswith('U ')]
    write_if_changed('\n'.join(result) + '\n', outfilename)

def freebsd_syms(libfilename: str, outfilename: str) -> None:
    # Get the name of the library
    output = call_tool('readelf', ['-d', libfilename])
    if not output:
        dummy_syms(outfilename)
        return
    result = [x for x in output.split('\n') if 'SONAME' in x]
    assert len(result) <= 1
    # Get a list of all symbols exported
    output = call_tool('nm', ['--dynamic', '--extern-only', '--defined-only',
                              '--format=posix', libfilename])
    if not output:
        dummy_syms(outfilename)
        return

    result += [' '.join(x.split()[0:2]) for x in output.split('\n')]
    write_if_changed('\n'.join(result) + '\n', outfilename)

def cygwin_syms(impfilename: str, outfilename: str) -> None:
    # Get the name of the library
    output = call_tool('dlltool', ['-I', impfilename])
    if not output:
        dummy_syms(outfilename)
        return
    result = [output]
    # Get the list of all symbols exported
    output = call_tool('nm', ['--extern-only', '--defined-only',
                              '--format=posix', impfilename])
    if not output:
        dummy_syms(outfilename)
        return
    for line in output.split('\n'):
        if ' T ' not in line:
            continue
        result.append(line.split(maxsplit=1)[0])
    write_if_changed('\n'.join(result) + '\n', outfilename)

def _get_implib_dllname(impfilename: str) -> T.Tuple[T.List[str], str]:
    all_stderr = ''
    # First try lib.exe, which is provided by MSVC. Then llvm-lib.exe, by LLVM
    # for clang-cl.
    #
    # We cannot call get_tool on `lib` because it will look at the `LIB` env
    # var which is the list of library paths MSVC will search for import
    # libraries while linking.
    for lib in (['lib'], get_tool('llvm-lib')):
        output, e = call_tool_nowarn(lib + ['-list', impfilename])
        if output:
            # The output is a list of DLLs that each symbol exported by the import
            # library is available in. We only build import libraries that point to
            # a single DLL, so we can pick any of these. Pick the last one for
            # simplicity. Also skip the last line, which is empty.
            return output.split('\n')[-2:-1], None
        all_stderr += e
    # Next, try dlltool.exe which is provided by MinGW
    output, e = call_tool_nowarn(get_tool('dlltool') + ['-I', impfilename])
    if output:
        return [output], None
    all_stderr += e
    return ([], all_stderr)

def _get_implib_exports(impfilename: str) -> T.Tuple[T.List[str], str]:
    all_stderr = ''
    # Force dumpbin.exe to use en-US so we can parse its output
    env = os.environ.copy()
    env['VSLANG'] = '1033'
    output, e = call_tool_nowarn(get_tool('dumpbin') + ['-exports', impfilename], env=env)
    if output:
        lines = output.split('\n')
        start = lines.index('File Type: LIBRARY')
        end = lines.index('  Summary')
        return lines[start:end], None
    all_stderr += e
    # Next, try llvm-nm.exe provided by LLVM, then nm.exe provided by MinGW
    for nm in ('llvm-nm', 'nm'):
        output, e = call_tool_nowarn(get_tool(nm) + ['--extern-only', '--defined-only',
                                                     '--format=posix', impfilename])
        if output:
            result = []
            for line in output.split('\n'):
                if ' T ' not in line or line.startswith('.text'):
                    continue
                result.append(line.split(maxsplit=1)[0])
            return result, None
        all_stderr += e
    return ([], all_stderr)

def windows_syms(impfilename: str, outfilename: str) -> None:
    # Get the name of the library
    result, e = _get_implib_dllname(impfilename)
    if not result:
        print_tool_warning(['lib', 'llvm-lib', 'dlltool'], 'do not work or were not found', e)
        dummy_syms(outfilename)
        return
    # Get a list of all symbols exported
    symbols, e = _get_implib_exports(impfilename)
    if not symbols:
        print_tool_warning(['dumpbin', 'llvm-nm', 'nm'], 'do not work or were not found', e)
        dummy_syms(outfilename)
        return
    result += symbols
    write_if_changed('\n'.join(result) + '\n', outfilename)

def gen_symbols(libfilename: str, impfilename: str, outfilename: str, cross_host: str) -> None:
    if cross_host is not None:
        # In case of cross builds just always relink. In theory we could
        # determine the correct toolset, but we would need to use the correct
        # `nm`, `readelf`, etc, from the cross info which requires refactoring.
        dummy_syms(outfilename)
    elif mesonlib.is_linux() or mesonlib.is_hurd():
        gnu_syms(libfilename, outfilename)
    elif mesonlib.is_osx():
        osx_syms(libfilename, outfilename)
    elif mesonlib.is_openbsd():
        openbsd_syms(libfilename, outfilename)
    elif mesonlib.is_freebsd():
        freebsd_syms(libfilename, outfilename)
    elif mesonlib.is_netbsd():
        freebsd_syms(libfilename, outfilename)
    elif mesonlib.is_windows():
        if os.path.isfile(impfilename):
            windows_syms(impfilename, outfilename)
        else:
            # No import library. Not sure how the DLL is being used, so just
            # rebuild everything that links to it every time.
            dummy_syms(outfilename)
    elif mesonlib.is_cygwin():
        if os.path.isfile(impfilename):
            cygwin_syms(impfilename, outfilename)
        else:
            # No import library. Not sure how the DLL is being used, so just
            # rebuild everything that links to it every time.
            dummy_syms(outfilename)
    elif mesonlib.is_sunos():
        solaris_syms(libfilename, outfilename)
    else:
        if not os.path.exists(TOOL_WARNING_FILE):
            mlog.warning('Symbol extracting has not been implemented for this '
                         'platform. ' + RELINKING_WARNING)
            # Write it out so we don't warn again
            with open(TOOL_WARNING_FILE, 'w', encoding='utf-8'):
                pass
        dummy_syms(outfilename)

def run(args: T.List[str]) -> int:
    global TOOL_WARNING_FILE  # pylint: disable=global-statement
    options = parser.parse_args(args)
    if len(options.args) != 4:
        print('symbolextractor.py <shared library file> <import library> <output file>')
        sys.exit(1)
    privdir = os.path.join(options.args[0], 'meson-private')
    TOOL_WARNING_FILE = os.path.join(privdir, 'symbolextractor_tool_warning_printed')
    libfile = options.args[1]
    impfile = options.args[2] # Only used on Windows
    outfile = options.args[3]
    gen_symbols(libfile, impfile, outfile, options.cross_host)
    return 0

if __name__ == '__main__':
    sys.exit(run(sys.argv[1:]))

"""

```