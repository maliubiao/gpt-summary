Response:
Let's break down the thought process to analyze this Python script.

1. **Understand the Goal:** The initial comments clearly state the purpose: to extract symbols from a shared library and store them in a file. This file is used to determine if the library's ABI has changed, allowing Meson to skip unnecessary relinking. This is a performance optimization.

2. **Identify Key Actions:** Scan the code for the main actions the script performs. Keywords like `open`, `read`, `write`, `Popen_safe`, and calls to external tools like `readelf`, `nm`, `otool`, etc., are indicators.

3. **Categorize Functionality:** Group related actions into functional blocks. For example:
    * **File Handling:** `dummy_syms`, `write_if_changed`.
    * **Tool Invocation:** `get_tool`, `call_tool`, `call_tool_nowarn`.
    * **Symbol Extraction (Platform-Specific):** `gnu_syms`, `solaris_syms`, `osx_syms`, etc. This is a major part.
    * **Main Logic:** `gen_symbols`, `run`.
    * **Warning/Error Handling:** `print_tool_warning`.

4. **Analyze Platform Specifics:** Notice the distinct functions for different operating systems (GNU/Linux, macOS, Windows, etc.). This immediately suggests the script adapts to different environments and their respective tooling for symbol extraction. Note the tools used in each (e.g., `readelf`, `nm` on Linux, `otool` on macOS, `dumpbin` on Windows).

5. **Trace the Execution Flow:** Start with the `run` function. It parses arguments and then calls `gen_symbols`. `gen_symbols` then dispatches to the platform-specific symbol extraction functions based on `mesonlib.is_linux()`, `mesonlib.is_osx()`, etc. This is the core logic.

6. **Examine Individual Functions:** Dive deeper into each function:
    * **`dummy_syms`:**  Simple - creates an empty file to force relinking.
    * **`write_if_changed`:**  Important for the optimization - avoids writing if the symbols haven't changed.
    * **`get_tool`:**  Looks for environment variables to allow users to specify custom tool paths.
    * **`call_tool` and `call_tool_nowarn`:**  Wrappers around `Popen_safe` to execute external commands, handle errors (tool not found, permission denied, non-zero exit code), and print warnings.
    * **Platform-specific `*_syms` functions:** These are where the actual symbol extraction happens. Analyze the commands they execute and what information they extract (e.g., SONAME, exported symbols, data object sizes). Pay attention to how they parse the output of these commands.

7. **Connect to Reverse Engineering:** The core function is about identifying exported symbols. This is a fundamental aspect of reverse engineering because exported symbols are the entry points into a shared library's functionality. Think about how tools like `nm`, `objdump`, and IDA Pro are used in reverse engineering – this script automates a similar initial step.

8. **Consider Binary and Kernel/Framework Aspects:** The script directly interacts with binary files (shared libraries) using tools like `readelf`, `nm`, and `otool`. These tools provide low-level information about the structure and contents of these binaries. The concept of "symbols" is a low-level detail of how code is organized and linked. The script touches upon operating system differences in how shared libraries are structured (ELF, Mach-O, PE).

9. **Think about Logic and Assumptions:**  The script assumes the presence of certain tools (`readelf`, `nm`, etc.) on specific platforms. It also assumes that changes in exported symbols (or data object sizes) indicate a potential ABI break, requiring relinking.

10. **Brainstorm Potential Errors:** Consider what could go wrong. Missing tools, incorrect environment variables, changes in the output format of the external tools, and file permission issues are all possibilities.

11. **Work Backwards from the Script's Purpose:** How does a user's action lead to this script being executed?  Meson, the build system, uses this script as part of its dependency tracking and optimization. When a shared library is built, Meson will invoke this script to record its symbols.

12. **Structure the Explanation:** Organize the findings logically, covering the function, relevance to reverse engineering, low-level aspects, logical reasoning, potential errors, and user interaction. Use clear headings and examples. Start with a general overview and then delve into specifics.

By following these steps, systematically analyzing the code, and connecting its functionalities to broader concepts in software development and reverse engineering, a comprehensive explanation of the script's purpose and implications can be constructed.
这个Python脚本 `symbolextractor.py` 是 Frida 动态 instrumentation 工具链中用于提取共享库符号信息的一个工具。它的主要目的是为了优化构建过程，通过检查共享库的符号表是否发生变化来决定是否需要重新链接依赖该库的其他组件。

以下是其功能的详细列表和相关说明：

**主要功能:**

1. **提取共享库符号:**  脚本的核心功能是从指定的共享库文件中提取其导出的符号信息。这包括函数名、变量名以及它们在库中的地址（通常是相对地址）。
2. **记录符号信息到文件:** 将提取到的符号信息写入一个指定的输出文件中。
3. **比较符号信息:**  在写入新的符号信息之前，会先检查输出文件是否已存在。如果存在，则读取旧的符号信息并与新提取的符号信息进行比较。
4. **避免不必要的重写:** 只有当新提取的符号信息与旧的符号信息不同时，才会更新输出文件。这能确保只有在库的 ABI（Application Binary Interface）发生变化时，才会触发下游组件的重新链接。
5. **平台特定处理:** 脚本会根据不同的操作系统（Linux, macOS, Windows, 等）调用不同的工具来提取符号信息，因为不同平台的符号表格式和提取工具不同。
6. **处理交叉编译:**  对于交叉编译的情况，脚本默认总是触发重新链接，因为确定跨平台的符号信息需要更复杂的处理。
7. **错误处理和警告:** 当执行符号提取工具失败时，脚本会打印警告信息，并创建一个空文件来强制重新链接。这确保了构建过程的正确性，即使在符号提取失败的情况下。

**与逆向方法的关联及举例说明:**

* **符号信息是逆向分析的基础:** 符号信息（特别是导出的符号）是理解一个二进制文件功能的重要入口。逆向工程师经常使用工具（如 `nm`, `objdump`, IDA Pro, Ghidra 等）来查看共享库的导出符号，以此来了解库提供的功能接口和潜在的入口点。
* **动态分析的辅助:**  Frida 本身是一个动态分析工具。`symbolextractor.py` 的输出可以帮助理解目标库的结构和接口，这对于编写 Frida 脚本进行 hook 和拦截调用非常有帮助。知道导出的函数名，可以更容易地定位到需要 hook 的函数。

**举例说明:**

假设有一个名为 `libexample.so` 的共享库，它导出了一个名为 `calculate_sum` 的函数。`symbolextractor.py` 的输出文件（例如 `libexample.so.symbols`）可能会包含类似以下的信息：

```
SONAME libexample.so.1
00000000 T calculate_sum
```

这个信息告诉我们库的 SONAME 是 `libexample.so.1`，并且导出了一个类型为 `T`（通常表示代码段的符号）的函数 `calculate_sum`，其地址是 `00000000`（这是一个相对地址）。

在逆向分析中，如果想要 hook `calculate_sum` 函数，可以通过 Frida 脚本配合这个符号信息来定位目标函数：

```python
import frida

session = frida.attach("target_process")
script = session.create_script("""
Interceptor.attach(Module.findExportByName("libexample.so", "calculate_sum"), {
  onEnter: function(args) {
    console.log("Entering calculate_sum");
  },
  onLeave: function(retval) {
    console.log("Leaving calculate_sum, return value:", retval);
  }
});
""")
script.load()
input()
```

**涉及二进制底层、Linux、Android内核及框架的知识及举例说明:**

* **二进制文件格式:** 脚本需要理解不同平台下共享库的二进制文件格式，例如 Linux 的 ELF (Executable and Linkable Format)，macOS 的 Mach-O，Windows 的 PE (Portable Executable)。不同的格式有不同的符号表结构。
* **符号表:** 脚本的核心操作是提取符号表。符号表是二进制文件中的一个数据结构，记录了函数、变量等符号的名称、地址、类型等信息。理解符号表的结构对于编写正确的提取逻辑至关重要。
* **链接器和加载器:** 脚本的目的是优化链接过程。它利用了链接器和加载器的工作原理，即只有当依赖库的 ABI 发生变化时，才需要重新链接。ABI 的变化通常体现在导出的符号的变化上。
* **Linux 工具 (`readelf`, `nm`):**  在 Linux 平台，脚本使用了 `readelf` 来获取库的 SONAME (Shared Object Name)，使用 `nm` 来获取导出的符号列表。这些都是 Linux 下分析二进制文件的常用工具。
* **macOS 工具 (`otool`, `nm`):** 在 macOS 平台，脚本使用了 `otool` 和 `nm` 来提取类似的信息。
* **Windows 工具 (`dlltool`, `dumpbin`):** 在 Windows 平台，使用了 `dlltool` 和 `dumpbin` 来处理动态链接库（DLL）。
* **SONAME:**  脚本中提取的 SONAME 是 Linux 系统中共享库的一个重要属性，用于在运行时定位正确的库版本。
* **导入库 (Import Library):** 在 Windows 中，脚本还处理导入库（.lib 文件），这些文件包含了 DLL 导出的符号信息，用于链接时解析符号。

**举例说明:**

在 Linux 系统上，执行 `gnu_syms` 函数时，会调用 `readelf -d libfilename` 来获取包含 `SONAME` 的动态段信息。`readelf` 读取 ELF 文件的头部和各个段的信息，`-d` 参数表示显示动态段的内容。

```
输出示例 (readelf -d libexample.so):

Dynamic section at offset 0xde8 contains 27 entries:
  标记        类型                         名称/值
 0x0000000000000001 (NEEDED)             共享库：libc.so.6
 0x000000000000000f (RPATH)              Library rpath: [/path/to/libs]
 0x000000000000000e (SONAME)             libexample.so.1
 ...
```

脚本会解析这个输出，提取出 `SONAME` 的值 `libexample.so.1`。

然后，脚本会调用 `nm --dynamic --extern-only --defined-only --format=posix libfilename` 来获取导出的符号列表。`nm` 工具读取符号表，`--dynamic` 表示只显示动态符号，`--extern-only` 表示只显示外部符号，`--defined-only` 表示只显示已定义的符号，`--format=posix` 指定输出格式。

```
输出示例 (nm --dynamic --extern-only --defined-only --format=posix libexample.so):

00000000 T calculate_sum
...
```

脚本会解析这个输出，提取出符号的地址和名称。

**逻辑推理及假设输入与输出:**

**假设输入:**

* `libfilename`: `/path/to/libexample.so` (共享库文件路径)
* `impfilename`:  在 Linux 下通常为空或不使用，Windows 下可能是 `/path/to/libexample.lib` (导入库文件路径)
* `outfilename`: `/path/to/libexample.so.symbols` (输出文件路径)
* `cross_host`: `None` (非交叉编译)

**逻辑推理过程:**

1. `run` 函数解析参数。
2. `gen_symbols` 函数根据操作系统类型调用相应的符号提取函数。假设是 Linux，则调用 `gnu_syms`。
3. `gnu_syms` 函数首先调用 `readelf` 获取 SONAME。
4. `gnu_syms` 函数然后调用 `nm` 获取导出的符号列表。
5. `gnu_syms` 函数将 SONAME 和符号列表组合成文本。
6. `gnu_syms` 函数调用 `write_if_changed`，如果输出文件不存在或内容已更改，则写入新的符号信息。

**预期输出 (如果符号信息发生变化):**

`/path/to/libexample.so.symbols` 文件内容会被更新，包含类似以下内容：

```
SONAME libexample.so.1
00000000 T calculate_sum
```

**预期输出 (如果符号信息没有变化):**

`/path/to/libexample.so.symbols` 文件不会被修改。

**涉及用户或编程常见的使用错误及举例说明:**

1. **缺少必要的工具:** 如果系统上没有安装 `readelf`, `nm`, `otool`, `dlltool`, `dumpbin` 等工具，脚本会报错并打印警告。这通常是由于环境配置不正确导致的。
   * **错误示例:**  在没有安装 `binutils` 的精简 Linux 环境中运行构建过程。

2. **工具路径不在 PATH 环境变量中:** 如果这些工具安装了，但其路径没有添加到系统的 PATH 环境变量中，脚本也无法找到这些工具。
   * **错误示例:**  安装了 LLVM，但没有将 `llvm/bin` 目录添加到 PATH 中，导致 `llvm-nm` 找不到。

3. **文件权限问题:** 如果脚本没有读取共享库文件或写入输出文件的权限，会导致脚本执行失败。
   * **错误示例:**  尝试提取只读的系统库的符号信息，或者尝试将符号信息写入没有写入权限的目录。

4. **输出文件路径错误:** 如果提供的输出文件路径不正确（例如，目录不存在），会导致脚本无法创建或写入文件。
   * **错误示例:**  将输出文件路径设置为 `/nonexistent/directory/symbols.txt`。

5. **交叉编译配置错误:** 虽然脚本会避免在交叉编译时进行详细的符号提取，但错误的交叉编译环境配置可能会导致其他构建问题，间接影响到这个脚本的行为。
   * **错误示例:**  在进行 Android 交叉编译时，没有正确配置 NDK 路径或工具链。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动构建过程:** 用户通常会执行一个构建命令，例如 `meson build` 或 `ninja`。
2. **Meson 构建系统分析依赖:** Meson 会分析项目的 `meson.build` 文件，了解各个构建目标及其依赖关系。当一个共享库被构建时，并且有其他目标依赖于这个共享库，Meson 会记录这种依赖关系。
3. **触发符号提取:**  为了优化后续的构建过程，Meson 会调用 `symbolextractor.py` 脚本来提取刚构建完成的共享库的符号信息。
4. **脚本执行:**  `symbolextractor.py` 接收共享库文件路径、可能的导入库文件路径和输出文件路径作为参数。
5. **符号信息写入:** 脚本执行符号提取操作，并将结果写入输出文件。
6. **后续构建:**  在后续的构建过程中，如果共享库被重新构建，Meson 会再次调用 `symbolextractor.py`，并比较新的符号信息和之前保存的符号信息。如果信息没有变化，Meson 可以跳过重新链接依赖该库的目标，从而加速构建过程。

**作为调试线索:**

* **查看构建日志:**  构建系统的日志会显示 `symbolextractor.py` 的调用命令和输出，可以检查是否正确执行，以及是否有错误或警告信息。
* **检查输出文件:**  查看生成的符号信息文件，确认其内容是否符合预期，是否有缺失或错误的符号。
* **手动运行脚本:**  可以尝试手动运行 `symbolextractor.py` 脚本，传入相应的参数，来验证脚本的功能和排查问题。
* **检查工具链:**  确认系统中是否安装了必要的符号提取工具，并且这些工具的版本是否与预期一致。
* **环境变量:**  检查相关的环境变量（例如 PATH）是否配置正确，确保脚本可以找到所需的工具。

总而言之，`symbolextractor.py` 是 Frida 构建系统中一个关键的辅助工具，它通过提取和比较共享库的符号信息来优化构建过程，避免不必要的重新链接，从而提高构建效率。它深入涉及到二进制文件格式、操作系统特定的工具和链接器的原理。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/scripts/symbolextractor.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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