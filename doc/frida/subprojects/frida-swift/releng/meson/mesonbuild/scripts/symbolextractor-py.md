Response:
Let's break down the thought process to analyze this Python script.

1. **Understand the Core Purpose:** The initial comment is crucial: "This script extracts the symbols of a given shared library into a file. If the symbols have not changed, the file is not touched."  This immediately tells us the primary goal is ABI stability tracking to optimize builds.

2. **Identify Key Operations:** Scan the script for verbs and nouns that indicate actions. Look for function definitions, especially those with descriptive names. We see:
    * `dummy_syms`: Creates an empty file – likely to force a relink.
    * `write_if_changed`:  Checks for changes before writing – the core logic for optimization.
    * `print_tool_warning`: Handles missing or broken tools.
    * `get_tool`:  Finds the path to necessary tools.
    * `call_tool`, `call_tool_nowarn`: Executes external commands.
    * `gnu_syms`, `solaris_syms`, `osx_syms`, etc.: Platform-specific symbol extraction logic.
    * `_get_implib_dllname`, `_get_implib_exports`: Windows-specific logic for import libraries.
    * `windows_syms`, `cygwin_syms`: More platform-specific logic.
    * `gen_symbols`:  The main dispatcher based on the operating system.
    * `run`:  Parses arguments and calls `gen_symbols`.

3. **Relate to Reverse Engineering (Instruction 2):** The script extracts symbols (function names, variable names) from a shared library. This is fundamental to reverse engineering. Examples:
    * Knowing function names allows an attacker or researcher to understand the library's API.
    * Identifying exported symbols is the first step in using or modifying a library.
    * Tools like `nm`, `readelf`, `otool`, and `dumpbin` are standard reverse engineering utilities.

4. **Identify Low-Level/Kernel/Framework Aspects (Instruction 3):**
    * **Shared Libraries:** The script operates on shared libraries (`.so`, `.dylib`, `.dll`), which are core OS concepts for code sharing and dynamic linking.
    * **Symbols:** The concept of symbols is a low-level detail of compiled code.
    * **`readelf`, `nm`, `otool`, `dumpbin`, `dlltool`:** These are command-line tools that directly interact with the binary format of executable and library files.
    * **Linux/Android Kernel (Indirect):** While the script doesn't directly interact with the kernel, the *purpose* of managing shared library symbols is crucial for the dynamic linking process, which *is* a kernel responsibility. On Android, the framework relies heavily on shared libraries and the ability to resolve symbols.
    * **Cross-Compilation:** The `--cross-host` argument indicates awareness of different target architectures and the need to potentially use different toolchains.

5. **Infer Logical Reasoning and Provide Examples (Instruction 4):**
    * **Core Logic:** The script compares the *current* symbols with *previously extracted* symbols. The assumption is: If the symbols haven't changed, the ABI is likely stable, and relinking can be skipped, saving build time.
    * **Input:** `libfrida.so`, `libfrida.dll.a`, `libfrida.sym`. (Shared library, import library (Windows), output symbol file).
    * **Scenario 1 (No Change):**  If `libfrida.so` hasn't had any changes that affect its exported symbols, the `libfrida.sym` file will remain untouched.
    * **Scenario 2 (Symbol Added):** If a new function is added to `libfrida.so`, the `nm` output will include the new symbol. `write_if_changed` will detect the difference and update `libfrida.sym`.
    * **Scenario 3 (Tool Missing):** If `nm` is not found, `call_tool` will return `None`, and `gnu_syms` will call `dummy_syms`, ensuring a relink.

6. **Identify Potential User/Programming Errors (Instruction 5):**
    * **Missing Tools:**  The script explicitly handles cases where tools like `nm` or `readelf` are missing or not executable. This is a common issue, especially in cross-compilation or minimal environments. The warning messages guide the user.
    * **Incorrect Tool Versions:** While not directly handled, using an incompatible version of `nm` could lead to unexpected output, and the symbol comparison might fail to detect changes. This is a more subtle error.
    * **Incorrect Environment:**  On Windows, the script manipulates the `PATH` and `VSLANG` environment variables. If these are not set up correctly, the tool calls might fail.
    * **Permissions:** The script handles `PermissionError`, indicating that the tools might not be executable.

7. **Trace User Steps (Instruction 6):**  Think about how this script fits into a larger build process.
    * **Meson Build System:** The script's location (`frida/subprojects/frida-swift/releng/meson/mesonbuild/scripts/`) strongly suggests it's part of a Meson build system.
    * **Build Definition:**  A `meson.build` file somewhere in the Frida project will define how the shared library is built.
    * **Dependency Tracking:** Meson will track dependencies. When a source file for the shared library is modified, Meson will know it needs to rebuild the library.
    * **Symbol Extraction as a Post-Build Step:**  After the shared library is built, this `symbolextractor.py` script is likely executed as a post-build step. Meson will pass the necessary arguments (library path, output path).
    * **Subsequent Builds:**  On subsequent builds, Meson will check if the symbol file has changed. If not, and if other dependencies haven't changed, Meson can skip the linking step for targets that depend on this library.

8. **Review and Refine:**  Read through the analysis to ensure clarity, accuracy, and completeness. Check if all parts of the prompt have been addressed. For example, ensure the examples are concrete and easy to understand.

This systematic approach allows for a thorough understanding of the script's functionality and its context within the larger Frida project and the build process.This Python script, `symbolextractor.py`, is a utility used within the Frida build system (specifically within the Meson build environment for the Swift bindings). Its primary function is to **extract the exported symbols from a shared library and store them in a file.**  This information is then used to optimize the build process by skipping relinking steps if the library's Application Binary Interface (ABI), as defined by its exported symbols, hasn't changed.

Let's break down its functionalities and connections to various aspects you mentioned:

**1. Core Functionality: Extracting Symbols**

The script's main goal is to create a snapshot of the exported symbols of a shared library. It achieves this by using platform-specific command-line tools:

* **Linux/Hurd:** `readelf` (to get SONAME) and `nm` (to list dynamic, external, defined symbols).
* **macOS:** `otool` (to get the library's ID) and `nm` (to list external, defined symbols).
* **OpenBSD/FreeBSD/NetBSD:** `readelf` (SONAME) and `nm` (for symbols, with variations in flags).
* **Windows:** `dlltool` or `dumpbin` or `llvm-nm` or `nm` (to get the DLL name and exported symbols from the import library).
* **Cygwin:** `dlltool` and `nm`.
* **Solaris:** It attempts to use the GNU versions of `nm` and `readelf`.

**How it Works:**

1. **Input:** It takes the path to the shared library file, the import library file (primarily for Windows), and the desired output file for the symbols.
2. **Platform Detection:** It uses `mesonlib.is_linux()`, `mesonlib.is_osx()`, etc., to determine the operating system.
3. **Tool Invocation:** Based on the OS, it calls the appropriate command-line tools to extract symbol information.
4. **Symbol Parsing:** It parses the output of these tools to extract relevant information like symbol names and sometimes their types.
5. **Output:** It writes the extracted symbols, one per line, into the specified output file.
6. **Change Detection:** Before writing, it checks if the extracted symbols are different from the existing content of the output file. If they are the same, it doesn't touch the file, preserving its modification timestamp.

**2. Relationship to Reverse Engineering**

This script is directly related to reverse engineering techniques:

* **Symbol Identification:**  Reverse engineers often start by examining the exported symbols of a library or executable to understand its functionality and available APIs. Tools like `nm`, `dumpbin`, and `otool` (which this script uses) are fundamental tools in a reverse engineer's toolkit.
* **API Discovery:** The list of exported symbols reveals the functions and data that a library exposes for use by other parts of the system. This is crucial for understanding how different components interact.
* **Vulnerability Analysis:** By examining symbols, reverse engineers can identify potentially vulnerable functions or areas of interest for further analysis.
* **Dynamic Analysis Preparation:** Knowing the exported symbols helps in setting breakpoints or hooks during dynamic analysis (like with Frida itself) to observe the behavior of specific functions.

**Example:**

Imagine you are reverse engineering a closed-source library on Linux. You might use `nm -D <library_file.so>` to see its dynamic symbols. This script automates this process and stores the output. If a new version of the library is released, and this script detects new symbols, it indicates a change in the library's ABI, which is important for understanding the updates and potential impact on applications using the library.

**3. Involvement of Binary Underpinnings, Linux/Android Kernel & Framework**

* **Binary File Formats:** The script directly interacts with the binary file formats of shared libraries (`ELF` on Linux/Android, `Mach-O` on macOS, `PE` on Windows). Tools like `readelf` are specifically designed to parse the structure of ELF files.
* **Dynamic Linking:** The concept of exported symbols is central to dynamic linking. The operating system's loader uses these symbols to resolve dependencies between different libraries and executables at runtime. This script helps manage the ABI stability which is crucial for maintaining compatibility in dynamically linked environments.
* **Linux/Android Kernel (Indirect):** While the script doesn't directly interact with kernel code, the symbols it extracts are managed by the kernel's dynamic linker. The kernel uses this information to resolve function calls across shared library boundaries. On Android, the Android Runtime (ART) relies heavily on dynamic linking and shared libraries.
* **Android Framework (Indirect):**  Many parts of the Android framework are implemented as shared libraries. This script could be used (although not directly part of the Android build process) to track ABI changes in framework libraries. Frida itself is heavily used for interacting with and reverse engineering Android applications and the framework.

**4. Logical Reasoning and Examples**

The core logic revolves around the assumption that **changes in exported symbols likely indicate a change in the ABI**, requiring relinking of dependent components.

**Hypothetical Input:**

* `lib_to_analyze.so`: A shared library.
* `lib_to_analyze.sym`: The output file to store symbols.

**Scenario 1: No Change in Symbols**

* **Input `lib_to_analyze.so`:**
   * Exports functions: `funcA`, `funcB`
* **Content of `lib_to_analyze.sym` (previous run):**
   ```
   funcA
   funcB
   ```
* **Output:** The script will detect that the symbols in the current `lib_to_analyze.so` are the same as in `lib_to_analyze.sym`. The `lib_to_analyze.sym` file will not be modified (its timestamp remains the same). The build system can potentially skip relinking targets that depend on this library.

**Scenario 2: New Symbol Added**

* **Input `lib_to_analyze.so`:**
   * Exports functions: `funcA`, `funcB`, `funcC`
* **Content of `lib_to_analyze.sym` (previous run):**
   ```
   funcA
   funcB
   ```
* **Output:** The script will detect the new symbol `funcC`. The `lib_to_analyze.sym` file will be updated to:
   ```
   funcA
   funcB
   funcC
   ```
   The modification of `lib_to_analyze.sym` signals to the build system that the ABI has changed, and dependent targets should be relinked.

**5. User/Programming Common Errors**

* **Missing Dependencies (Command-line Tools):** A common error is not having the required command-line tools (`nm`, `readelf`, `otool`, `dumpbin`, `dlltool`) installed or accessible in the system's PATH. The script attempts to handle this by printing warnings.
    * **Example:** If `nm` is not found on a Linux system, the script will print a warning like: `['nm'] not found. Relinking will always happen on source changes.`
* **Incorrect Permissions:** The tools might not have execute permissions. The script handles `PermissionError` and prints a warning.
    * **Example:** If `nm` is not executable, a warning like `['nm'] not usable. Relinking will always happen on source changes.` might appear.
* **Corrupted Library File:** If the input shared library file is corrupted or not a valid shared library, the tools might fail, and the script will likely fall back to the `dummy_syms` function, forcing a relink.
* **Environment Issues (Windows):** On Windows, the script might rely on specific environment variables for finding the development tools. If these are not set up correctly, the script might fail to find `dumpbin` or other necessary tools.

**6. User Operation Leading to This Script (Debugging Clues)**

Typically, a developer using Frida wouldn't directly interact with this script. It's part of the internal build process. However, here's how a series of actions could lead to encountering this script or its output:

1. **Modifying Frida's Swift Bindings:** A developer might be working on the Swift bindings for Frida, making changes to the Swift code that interacts with the core Frida library.
2. **Running the Build System:** They would then run the Frida build system (using Meson commands like `meson build` and `ninja -C build`).
3. **Meson's Dependency Tracking:** Meson, the build system, detects that the Swift code or its dependencies (including the core Frida library) have changed.
4. **Building the Shared Library:** Meson compiles and links the necessary components, including the shared library for the Swift bindings.
5. **Executing `symbolextractor.py`:** As a post-build step for the shared library, Meson will execute `symbolextractor.py`, passing the path to the newly built shared library and the output file.
6. **Observing the Output:** If there are issues, a developer might look at the output of the build process, where they might see errors or warnings related to `symbolextractor.py`. They might also examine the generated symbol files to understand ABI changes.
7. **Debugging Relinking Issues:** If the build system is unexpectedly relinking components even without apparent source code changes, a developer might investigate the symbol files generated by this script to see if the ABI is indeed changing.

**In summary, `symbolextractor.py` is a crucial utility for optimizing the Frida build process by tracking ABI changes in shared libraries. It leverages standard reverse engineering tools to extract symbol information and plays a vital role in ensuring efficient incremental builds.**

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/scripts/symbolextractor.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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