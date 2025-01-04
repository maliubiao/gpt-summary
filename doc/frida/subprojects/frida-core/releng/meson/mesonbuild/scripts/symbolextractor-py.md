Response:
Let's break down the thought process to analyze this Python script.

1. **Understand the Purpose:** The initial comments are crucial. The script aims to extract symbols from shared libraries. The key motivation is to avoid unnecessary relinking if the library's ABI (Application Binary Interface) hasn't changed. This immediately tells us it's related to build systems and optimization.

2. **Identify Core Functionality:** Scan the code for key functions. `gnu_syms`, `osx_syms`, `windows_syms`, etc., clearly indicate platform-specific symbol extraction logic. `gen_symbols` acts as a dispatcher based on the OS. `write_if_changed` and `dummy_syms` are utility functions for handling output.

3. **Analyze Platform-Specific Logic (Pick one as an example):** Let's focus on `gnu_syms`. It uses `readelf` to get the SONAME (Shared Object Name), which is important for library versioning. Then, it uses `nm` to get the exported symbols. The options passed to `nm` (`--dynamic`, `--extern-only`, `--defined-only`, `--format=posix`) are important clues about what kind of symbols it's interested in. The handling of data symbols (`B`, `G`, `D`) signals awareness of relocation issues.

4. **Connect to Reverse Engineering:**  The use of `readelf`, `nm`, `otool`, `dumpbin`, `dlltool` are immediately recognizable reverse engineering tools. These tools are fundamental for inspecting binary files. Extracting exported symbols is a standard technique in reverse engineering to understand a library's public API.

5. **Identify Low-Level/Kernel Aspects:** The concept of shared libraries, linking, and ABIs directly relates to operating system fundamentals. The platform-specific nature of the code (handling Linux ELF, macOS Mach-O, Windows PE) reinforces the low-level aspect. The mention of "copy relocations" within `gnu_syms` points to a specific low-level linking mechanism.

6. **Trace User Interaction (Hypothetical):** Imagine a developer building a project using Frida. The build system (likely Meson in this case, as indicated by the directory structure) encounters a shared library dependency. The build system needs to know if it needs to relink against this library. This script is called by the build system to check if the library's symbols have changed since the last build.

7. **Look for Logic/Assumptions:** The `write_if_changed` function has a clear logical purpose: prevent unnecessary file writes. The `dummy_syms` function provides a fallback, forcing relinking, which is a safe but less efficient approach. The cross-compilation handling in `gen_symbols` is a pragmatic assumption (always relink for simplicity).

8. **Consider Potential Errors:**  The script checks for the existence and usability of the external tools. The `print_tool_warning` function handles cases where these tools are missing or fail. The Windows-specific code has multiple fallback mechanisms for getting symbol information, suggesting awareness of different toolchains. The logic around import libraries on Windows and Cygwin indicates potential issues with their presence or usage.

9. **Structure the Output:** Organize the findings into logical categories: functionality, reverse engineering relevance, low-level knowledge, logical reasoning, usage errors, and user journey. Provide concrete examples and explanations within each category.

10. **Refine and Review:** Read through the analysis to ensure clarity, accuracy, and completeness. Double-check the interpretations of the code and the connections to the prompt's requirements. For instance, ensure the "logical reasoning" section includes specific input/output examples (even if they are conceptual).

Essentially, the process involves: understanding the core problem, dissecting the code into its components, connecting those components to relevant technical domains (reverse engineering, OS internals), inferring the operational context, and anticipating potential issues and user interactions. The comments in the code itself are invaluable for understanding the developers' intentions and the nuances of the different platform implementations.
这个Python脚本 `symbolextractor.py` 是 Frida 动态 instrumentation 工具链中用于提取共享库符号信息的一个工具。其主要目的是在构建过程中检测共享库的 ABI (Application Binary Interface) 是否发生变化，从而优化构建过程，避免不必要的重新链接。

下面详细列举其功能以及与逆向、底层知识、逻辑推理和常见错误的关系：

**主要功能:**

1. **提取共享库符号:**  针对不同的操作系统（Linux, macOS, Windows, BSD 等），调用相应的系统工具（如 `readelf`, `nm`, `otool`, `dumpbin`, `dlltool`）来提取共享库导出的符号信息。
2. **记录符号信息到文件:** 将提取到的符号信息写入到一个指定的文件中。
3. **检测符号变化:** 在下次构建时，重新提取符号信息并与之前保存的文件进行比较。如果符号信息没有变化，则认为共享库的 ABI 没有变化，可以跳过重新链接步骤，加快构建速度。
4. **处理交叉编译:**  对于交叉编译的情况，为了简化处理，通常会强制进行重新链接。
5. **平台特定处理:**  针对不同的操作系统，使用了不同的工具和命令来提取符号信息，因为不同平台的共享库格式和符号表结构存在差异。
6. **处理导入库 (Windows/Cygwin):**  在 Windows 和 Cygwin 平台上，还需要处理导入库 (`.lib` 或 `.dll.a`)，提取其中包含的符号信息。
7. **处理符号大小变化 (GNU):**  在 GNU 系统上，还会记录指向数据对象的符号的大小，以便在这些数据对象大小发生变化时触发重新链接。

**与逆向方法的关系及举例说明:**

这个脚本的核心功能是提取共享库的符号信息，这与逆向工程密切相关。逆向工程师经常需要分析共享库的导出函数和全局变量，以了解其功能和接口。

* **动态分析基础:** Frida 本身就是一个动态分析工具，而这个脚本是为了优化 Frida 的构建过程而存在的。逆向工程师在进行动态分析时，需要了解目标进程加载的共享库及其提供的接口，`symbolextractor.py` 提取的信息正是这些接口的描述。
* **符号信息的价值:** 提取到的符号信息可以帮助逆向工程师：
    * **理解库的功能:** 通过函数名和变量名推断库的功能。
    * **定位关键函数:** 快速找到感兴趣的函数入口地址。
    * **进行 Hook 操作:** Frida 等动态 instrumentation 工具需要知道目标函数的符号才能进行 Hook 操作。
* **举例说明:**
    假设你想要逆向一个使用了 `libc.so` 的 Android 应用。你可以使用 `symbolextractor.py` (虽然通常 Frida 内部会自动处理) 或者手动使用 `nm` 命令来提取 `libc.so` 的符号信息。提取到的信息可能包含 `printf`, `malloc`, `free` 等函数的名称和地址。逆向工程师可以利用这些信息，使用 Frida Hook `printf` 函数来监控应用的输出，或者 Hook `malloc` 和 `free` 来分析内存管理行为。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

这个脚本的实现和目的都深深地扎根于底层的操作系统和二进制知识。

* **共享库和动态链接:**  脚本处理的是共享库，这涉及到操作系统如何加载和链接共享库的机制。Linux 的 `.so` 文件，macOS 的 `.dylib` 文件，Windows 的 `.dll` 文件都是共享库的不同形式。
* **符号表:** 脚本提取的核心是符号表，符号表是二进制文件中记录函数、变量等名称和地址的数据结构。理解符号表的结构和格式对于编写和理解这个脚本至关重要。
* **系统调用:**  虽然脚本本身没有直接进行系统调用，但它调用的 `readelf`, `nm` 等工具会进行系统调用来读取和解析二进制文件。
* **ABI (Application Binary Interface):** 脚本的核心目标是检测 ABI 的变化。ABI 定义了不同编译单元之间（例如共享库和可执行文件）如何进行交互的底层细节，包括函数调用约定、数据结构布局等。
* **平台差异:** 脚本需要针对不同的操作系统进行不同的处理，这反映了不同操作系统在共享库格式、符号表结构以及相关工具上的差异。例如：
    * **Linux:** 使用 `readelf` 和 `nm` 处理 ELF 格式的共享库。
    * **macOS:** 使用 `otool` 和 `nm` 处理 Mach-O 格式的共享库。
    * **Windows:** 使用 `dumpbin` 和 `dlltool` 处理 PE 格式的 DLL 和导入库。
* **Android:** 虽然脚本没有显式提到 Android，但由于 Frida 广泛用于 Android 逆向和动态分析，可以推断其在 Android 环境下的共享库处理逻辑与 Linux 类似，会使用相应的工具来提取符号。Android 的 Bionic libc 也是基于 ELF 格式的。
* **内核和框架:** 脚本本身不直接与内核交互，但其目的是为了构建 Frida，而 Frida 可以用来 instrument Android 的 framework，例如 Hook Java 层的方法或者 Native 层的函数。

**逻辑推理及假设输入与输出:**

脚本中存在一些逻辑推理，主要体现在对不同操作系统和工具的判断和使用上。

* **假设输入:**
    * `libfilename`:  一个共享库文件的路径，例如 `/usr/lib/libc.so.6` 或 `/System/Library/Frameworks/Foundation.framework/Foundation`。
    * `impfilename`:  在 Windows 或 Cygwin 上，可能是对应的导入库文件路径，例如 `mylib.lib`。在其他平台上可能为空或无意义。
    * `outfilename`:  用于保存符号信息的目标文件路径，例如 `mylib.syms`.
    * `cross_host`:  指示是否为交叉编译的目标平台，例如 `android-arm64`.

* **逻辑推理示例 (针对 `gnu_syms` 函数):**
    1. **输入一个 Linux 共享库文件路径 `libtest.so`。**
    2. **调用 `readelf -d libtest.so` 获取动态段信息。**  假设输出包含一行 ` 0x000000000000000e (SONAME)             Library soname: [libtest.so.1]`。
    3. **调用 `nm --dynamic --extern-only --defined-only --format=posix libtest.so` 获取导出的符号。** 假设输出包含：
       ```
       0000000000001149 T my_function
       0000000000004030 B my_global_var 1024
       ```
    4. **构建符号信息字符串:** 将 SONAME 和导出的符号信息组合起来，得到：
       ```
       SONAME               Library soname: [libtest.so.1]
       my_function 0000000000001149
       my_global_var 0000000000004030 1024
       ```
    5. **将该字符串写入到 `outfilename` 中。**

* **交叉编译的逻辑:** 如果 `cross_host` 不为 `None`，则直接调用 `dummy_syms(outfilename)`，这意味着在交叉编译的情况下，为了简化，总是会触发重新链接。这是基于假设跨平台提取精确的符号信息并进行比较可能比较复杂。

**涉及用户或者编程常见的使用错误及举例说明:**

虽然这个脚本是构建系统的一部分，用户通常不会直接运行它，但如果使用不当或者环境配置有问题，可能会导致构建失败或不必要的重新链接。

* **缺少依赖工具:** 如果系统上缺少 `readelf`, `nm`, `otool`, `dumpbin`, `dlltool` 等必要的工具，脚本会报错或产生不正确的符号信息。脚本中包含了 `print_tool_warning` 函数来处理这种情况。
    * **错误示例:** 在一个最小化的 Linux 环境中构建 Frida，但没有安装 `binutils` 包，导致 `nm` 命令找不到，脚本会输出警告信息并创建一个空的符号文件，导致每次都会重新链接。
* **权限问题:** 如果运行脚本的用户没有执行 `readelf`, `nm` 等工具的权限，脚本也会失败。
    * **错误示例:** 在一个受限的环境中，用户尝试构建 Frida，但由于安全策略限制，无法执行 `nm` 命令，构建过程会出错。
* **环境变量配置错误:** 某些工具的行为可能受到环境变量的影响。如果环境变量配置不当，可能会导致提取到错误的符号信息。
    * **错误示例:**  在 Windows 上，`dumpbin` 的输出语言可以通过环境变量 `VSLANG` 控制。如果用户的环境变量配置与脚本的预期不符，可能会导致解析错误。
* **文件路径错误:**  如果传递给脚本的共享库文件路径或输出文件路径不正确，脚本会无法找到文件或无法写入输出。
    * **错误示例:**  在构建脚本中错误地指定了共享库的路径，导致 `symbolextractor.py` 无法找到目标文件，构建失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接调用 `symbolextractor.py`。这个脚本是 Frida 构建系统（通常是 Meson）的一部分。用户与这个脚本交互的路径如下：

1. **用户下载 Frida 的源代码或使用 Git 克隆仓库。**
2. **用户配置构建环境，例如安装必要的依赖项（Python, Meson, 编译器等）。**
3. **用户执行 Meson 配置命令，指定构建目录和选项，例如：**
   ```bash
   meson setup build
   ```
4. **Meson 在配置过程中会解析 `meson.build` 文件，该文件定义了构建规则，包括如何处理共享库依赖。**
5. **当构建系统遇到需要提取符号信息的共享库时，Meson 会调用 `symbolextractor.py` 脚本。**  这通常发生在构建共享库目标或者链接到共享库的目标时。
6. **Meson 会将共享库文件路径、预期的符号信息输出文件路径等参数传递给 `symbolextractor.py`。**
7. **`symbolextractor.py` 根据操作系统调用相应的工具提取符号信息，并写入到输出文件中。**
8. **在后续的构建过程中，Meson 会再次调用 `symbolextractor.py` 检查符号信息是否发生变化。**

**作为调试线索:**

* **构建失败:** 如果构建过程因为符号提取相关的问题而失败，可以查看构建日志，查找 `symbolextractor.py` 的调用信息和输出的错误或警告信息。
* **不必要的重新链接:** 如果发现 Frida 在没有代码变更的情况下仍然频繁地重新链接共享库，可能是符号提取逻辑有问题，或者依赖的工具版本不兼容，导致符号信息被错误地判断为已更改。可以手动运行 `symbolextractor.py` 并检查其输出，或者比较新旧符号信息文件的差异。
* **工具缺失或权限问题:** 如果构建日志中出现 `print_tool_warning` 的信息，说明缺少必要的工具或者当前用户没有执行这些工具的权限，需要检查系统环境配置。

总而言之，`symbolextractor.py` 是 Frida 构建过程中的一个幕后英雄，它通过提取和比较共享库的符号信息，有效地优化了构建过程，避免了不必要的重新链接，而其功能和实现都与逆向工程的底层知识息息相关。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/scripts/symbolextractor.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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