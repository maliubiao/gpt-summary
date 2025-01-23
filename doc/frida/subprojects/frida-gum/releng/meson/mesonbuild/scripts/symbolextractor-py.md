Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Core Goal:** The initial comment is key: "This script extracts the symbols of a given shared library into a file."  The follow-up sentence clarifies *why*: to optimize builds by skipping relinking if the ABI hasn't changed. This immediately tells us it's a build system optimization tool.

2. **Identify Key Functionality Blocks:** Scan the script for function definitions. Each function likely represents a distinct part of the process. We see functions like `dummy_syms`, `write_if_changed`, `print_tool_warning`, `get_tool`, `call_tool`, and platform-specific functions like `gnu_syms`, `osx_syms`, `windows_syms`, etc. Finally, there's a `gen_symbols` function that orchestrates the platform-specific logic.

3. **Analyze Individual Functions:**

   * **`dummy_syms`:** Very simple - creates an empty file. The comment explains its purpose: to force relinking. This suggests a fallback mechanism.
   * **`write_if_changed`:**  Crucial for optimization. It reads the existing symbol file and only writes the new symbols if they've changed. This avoids unnecessary file modifications and triggers for the build system.
   * **`print_tool_warning`:** Handles warnings about missing or unusable tools. The `TOOL_WARNING_FILE` check prevents repeated warnings, an important detail for a build system.
   * **`get_tool`:** Handles finding tools, considering environment variables. This is important for flexibility (e.g., allowing users to specify custom tool paths).
   * **`call_tool`:**  Executes external tools and handles potential errors (file not found, permissions, non-zero exit code). The error handling is critical.
   * **Platform-specific `*_syms` functions:** These are the workhorses. They use platform-specific tools (`readelf`, `nm`, `otool`, `dlltool`, `dumpbin`) to extract symbol information. Notice the differences in the arguments and output parsing for each platform.
   * **`gen_symbols`:**  The dispatcher. It uses `mesonlib.is_*()` functions to determine the platform and call the appropriate `*_syms` function. The cross-compilation handling is a special case.

4. **Connect the Dots:**  See how the functions work together. `gen_symbols` calls the appropriate platform-specific function, which uses `call_tool` to execute external binaries. The output of these tools is processed to extract symbol information. `write_if_changed` then saves this information.

5. **Identify Connections to Reverse Engineering and Low-Level Concepts:**

   * **Reverse Engineering:** The entire script revolves around extracting information from compiled binaries (shared libraries). This is a core aspect of reverse engineering. The tools used (`readelf`, `nm`, `otool`, `dumpbin`) are standard reverse engineering utilities.
   * **Binary Structure:** The script works with the internal structure of shared libraries (ELF, Mach-O, PE). Concepts like symbol tables, dynamic linking (SONAME), and import libraries are central.
   * **Operating Systems:** The platform-specific handling highlights the differences in binary formats and tooling across Linux, macOS, and Windows.
   * **Kernel/Framework:**  While not directly interacting with the kernel, the script's purpose (optimizing shared library linking) is fundamental to how operating systems load and manage libraries. The concept of ABI (Application Binary Interface) is directly related to the kernel's interface.

6. **Look for Logic and Assumptions:**

   * The script assumes the presence of specific tools on each platform.
   * It assumes a certain format for the output of these tools.
   * The cross-compilation logic assumes that extracting symbols from the *host* system isn't useful for the *target* system.

7. **Consider Potential Errors:**

   * **Missing tools:** The script explicitly handles this with `print_tool_warning`.
   * **Incorrect tool output:** If the output format of `nm`, `readelf`, etc., changes, the parsing logic will break.
   * **File permissions:**  `Popen_safe` can raise `PermissionError`.
   * **Cross-compilation issues:** The forced relinking could be suboptimal.
   * **User error:** While the script itself is automated, incorrect configuration leading to it being called with the wrong arguments is possible (though the `argparse` helps prevent this).

8. **Trace User Interaction (Debugging Perspective):** Imagine a build process. The user initiates a build. The build system (Meson in this case) needs to link against a shared library. Before linking, it wants to know if the library's ABI has changed. This script is called by Meson, providing the paths to the library, import library (if applicable), and the output file for the symbols.

9. **Structure the Explanation:** Organize the findings into logical categories as requested (functionality, reverse engineering, low-level concepts, logic, errors, user interaction). Provide concrete examples for each point.

10. **Refine and Clarify:** Review the explanation for clarity and accuracy. Ensure that the examples are relevant and easy to understand. For instance, initially, I might have just said "it uses `nm`", but refining it to explain *why* `nm` is used (to get exported symbols) is more helpful.

This detailed breakdown demonstrates how to approach analyzing a piece of code, especially when its purpose is tied to a larger system (like a build system). It involves understanding the code's intent, dissecting its components, and connecting them to relevant concepts.
这个 `symbolextractor.py` 脚本是 Frida 工具链中用于提取共享库（shared library）符号信息的工具。它的主要目的是在构建过程中优化链接步骤，只有当共享库的 ABI（Application Binary Interface）发生变化时才进行重新链接。

以下是它的功能列表以及与逆向、二进制底层、Linux/Android 内核及框架知识的关联：

**功能列表:**

1. **提取共享库符号:**  脚本的主要功能是从指定的共享库文件中提取导出的符号（函数名、变量名等）。
2. **ABI 变更检测:** 通过比较当前提取的符号信息与之前保存的符号信息，来判断共享库的 ABI 是否发生了变化。
3. **优化链接:** 如果 ABI 没有变化，构建系统可以跳过重新链接的步骤，从而加快构建速度。
4. **平台特定处理:**  脚本针对不同的操作系统（Linux, macOS, Windows, BSD 等）使用不同的工具来提取符号，因为不同平台使用的二进制格式和符号表结构有所不同。
5. **处理导入库 (Windows/Cygwin):**  对于 Windows 和 Cygwin 平台，它还会处理导入库 (`.lib` 文件) 以提取导出的符号。
6. **错误处理与警告:**  当所需的工具（如 `readelf`, `nm`, `otool`, `dlltool`, `dumpbin`）找不到或执行失败时，会打印警告信息。
7. **跨平台构建支持:**  在交叉编译的情况下，默认会强制重新链接，因为确定目标平台的工具链和符号提取方式较为复杂。
8. **避免重复警告:**  使用 `TOOL_WARNING_FILE` 来记录是否已经打印过工具缺失的警告，避免重复输出。

**与逆向方法的关联及举例说明:**

* **符号信息是逆向分析的基础:** 符号信息（函数名、全局变量名等）能够帮助逆向工程师理解二进制代码的功能和结构。这个脚本提取的正是这些信息。
* **动态链接库分析:** 逆向工程师经常需要分析动态链接库，了解其导出了哪些函数，以及这些函数的功能。`symbolextractor.py` 的功能与逆向分析中分析动态链接库的步骤有重叠之处。
* **ABI 分析:**  逆向工程师有时需要了解不同版本的库之间的 ABI 兼容性。这个脚本通过比较符号变化来检测 ABI 变化，其背后的原理与 ABI 分析相关。

**举例说明:**

假设一个共享库 `libexample.so` 导出了一个函数 `calculate_sum(int a, int b)`。`symbolextractor.py` 可能会提取出包含 `calculate_sum` 的符号信息。逆向工程师可以通过查看这个符号信息得知库中存在这样一个函数，并可能进一步分析这个函数的具体实现。

**涉及到二进制底层、Linux, Android 内核及框架的知识及举例说明:**

* **二进制格式 (ELF, Mach-O, PE):** 脚本需要根据不同的操作系统处理不同的二进制格式。例如，在 Linux 上使用 `readelf` 和 `nm` 处理 ELF 格式的共享库，而在 macOS 上使用 `otool` 和 `nm` 处理 Mach-O 格式的共享库，在 Windows 上处理 PE 格式的 DLL。
* **符号表:**  脚本提取的核心信息来自二进制文件的符号表。了解符号表的结构和类型（如动态符号、外部符号、已定义符号）对于理解脚本的功能至关重要。
* **动态链接:**  脚本的目的是优化动态链接过程。它提取 `SONAME` (Shared Object Name) 等信息，这与动态链接器在运行时加载共享库的过程密切相关。
* **Linux 工具 (`readelf`, `nm`):** 脚本在 Linux 上使用了 `readelf` 来读取 ELF 文件的信息，包括 `SONAME`；使用 `nm` 来列出符号表中的符号。
* **macOS 工具 (`otool`, `nm`):** 在 macOS 上，使用 `otool -l` 来获取动态库 ID 信息，使用 `nm` 来列出符号。
* **Windows 工具 (`dlltool`, `dumpbin`):** 在 Windows 上，使用 `dlltool` 和 `dumpbin` 来处理导入库和提取符号。
* **Android (基于 Linux 内核):** 虽然脚本没有明确提到 Android，但由于 Android 底层基于 Linux 内核，其共享库也是 ELF 格式，因此 `gnu_syms` 函数中的逻辑也适用于 Android 平台上的共享库。Frida 本身就是一个常用于 Android 逆向和动态分析的工具。

**举例说明:**

在 Linux 上，`call_tool('readelf', ['-d', libfilename])` 命令会读取 `libfilename` 的动态段信息，其中就包含了 `SONAME`。`call_tool('nm', ['--dynamic', '--extern-only', '--defined-only', '--format=posix', libfilename])` 命令会列出 `libfilename` 中导出的动态符号。

**如果做了逻辑推理，请给出假设输入与输出:**

**假设输入:**

* `libfilename`: `/path/to/libmylib.so` (一个 Linux 共享库)
* `outfilename`: `/path/to/libmylib.so.symbols` (输出符号信息的文件)
* 假设 `libmylib.so` 导出了两个函数: `func_a` 和 `func_b`。

**预期输出 (写入到 `outfilename`):**

```
libmylib.so
         U   func_a
         U   func_b
```

**(解释:  `U` 表示这是一个已定义的全局符号。具体的 `nm` 输出格式可能略有不同，但核心是包含导出的符号名。实际的输出还会包含 `SONAME` 行。)**

**假设输入 (Windows):**

* `impfilename`: `C:\path\to\mylib.lib` (一个 Windows 导入库)
* `outfilename`: `C:\path\to\mylib.lib.symbols`

**预期输出 (写入到 `outfilename`):**

这取决于 `mylib.lib` 实际链接的 DLL 名称以及导出的符号。假设它链接到 `mylib.dll` 并导出了函数 `MyFunction`:

```
mylib.dll
MyFunction
```

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **缺少依赖工具:** 用户环境中没有安装 `readelf`, `nm`, `otool`, `dlltool`, `dumpbin` 等必要的工具。脚本会打印警告，并强制重新链接。
   ```
   mlog.warning(['readelf', 'nm'] 'not found. ' Relinking will always happen on source changes.')
   ```
2. **权限问题:** 用户对共享库文件或符号输出文件没有读取或写入权限，导致脚本执行失败。
3. **传递错误的文件路径:**  用户传递了不存在的共享库文件路径，脚本会尝试执行工具，但工具会报错，脚本可能会记录一个空的符号文件或发出警告。
4. **交叉编译环境配置错误:** 在交叉编译时，没有正确配置交叉编译工具链，导致脚本使用的工具是宿主系统的工具，而不是目标系统的工具，这会导致提取的符号信息不正确。 虽然脚本默认强制重新链接，但如果用户尝试修改脚本行为，可能会遇到此类问题。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户执行构建命令:** 用户使用构建系统（例如，使用 Meson 构建 Frida）来编译 Frida 项目。
   ```bash
   meson build
   ninja -C build
   ```
2. **构建系统处理共享库链接:** 在构建过程中，构建系统需要链接 Frida 的某个组件生成的共享库。
3. **构建系统调用 `symbolextractor.py`:** Meson 构建系统在决定是否需要重新链接这个共享库时，会调用 `symbolextractor.py` 脚本。它会传递共享库的路径、可能的导入库路径以及用于存储符号信息的文件路径作为参数。
   ```
   python3 frida/subprojects/frida-gum/releng/meson/mesonbuild/scripts/symbolextractor.py <shared library file> <import library> <output file>
   ```
4. **`symbolextractor.py` 执行符号提取:** 脚本根据操作系统调用相应的工具提取符号信息，并将结果写入输出文件。
5. **构建系统比较符号信息:** 构建系统会比较当前提取的符号信息与之前保存的符号信息。如果一致，则跳过链接步骤；否则，执行链接操作。

**作为调试线索:**

* **构建失败并提示符号提取错误:** 如果构建过程中出现与符号提取相关的错误，例如找不到工具的警告，可以查看构建日志中 `symbolextractor.py` 的输出。
* **不必要的重新链接:** 如果发现每次构建都会重新链接某个共享库，即使代码没有变化，可以检查 `symbolextractor.py` 的输出文件是否为空或每次都不同，这可能表明符号提取失败或 ABI 检测逻辑有问题。
* **交叉编译问题:**  在交叉编译场景下，如果出现链接错误或运行时问题，可能需要检查 `symbolextractor.py` 的行为，确认它是否正确处理了交叉编译的情况（默认是强制重新链接）。可以尝试修改脚本以使用目标系统的符号提取工具（但这通常需要更复杂的配置）。

总而言之，`symbolextractor.py` 是 Frida 构建流程中的一个关键优化环节，它通过提取和比较共享库的符号信息来减少不必要的链接操作，加快构建速度。理解其功能和背后的原理有助于理解 Frida 的构建过程，并在遇到相关构建问题时提供调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/scripts/symbolextractor.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```