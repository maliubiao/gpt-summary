Response:
Let's break down the thought process for analyzing this Python code and generating the comprehensive explanation.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of the provided Python code, specifically within the context of Frida's dynamic instrumentation tool. The prompt also asks for connections to reverse engineering, low-level concepts, examples of logical reasoning, common user errors, and how a user might reach this code.

**2. Initial Skim and Keyword Identification:**

The first step is to quickly read through the code, looking for keywords and familiar patterns. I see imports like `subprocess`, `os`, `shutil`, `unittest`, `zipfile`, and paths like `frida/subprojects/frida-gum/releng/meson/unittests/helpers.py`. This immediately suggests:

* **Testing:** The `unittest` import strongly indicates this is part of a test suite.
* **System Interaction:** `subprocess`, `os`, and `shutil` suggest interaction with the operating system, executing commands, and manipulating files/directories.
* **Build System:** The path containing "meson" points to the Meson build system.
* **Archiving:** `zipfile` suggests handling ZIP archives.

**3. Analyzing Individual Functions:**

Next, I'll go through each function and try to understand its purpose:

* **`is_ci()`:**  Checks for a specific environment variable (`MESON_CI_JOBNAME`) to determine if the code is running in a Continuous Integration (CI) environment. This is a common pattern in testing frameworks to handle CI-specific behavior.
* **`skip_if_not_base_option()`:** This is a decorator. It checks if the compiler supports a specific feature (a "base option"). If not, it skips the test. This relates to compiler capabilities.
* **`skipIfNoPkgconfig()`:** Another decorator. It checks for the `pkg-config` executable and skips the test if it's not found (unless in CI). `pkg-config` is used to find information about installed libraries.
* **`skipIfNoPkgconfigDep()`:**  Similar to the above, but checks for a specific *dependency* using `pkg-config`.
* **`skip_if_no_cmake()`:** Checks for the `cmake` executable. CMake is another build system.
* **`skip_if_not_language()`:**  Checks if a compiler for a specific programming language is available.
* **`skip_if_env_set()`:** Skips a test if a particular environment variable is set (unless in CI). This is useful for isolating tests.
* **`skipIfNoExecutable()`:** Skips a test if a specific executable is not found.
* **`is_tarball()`:** Checks if the current directory structure suggests it's within a tarball (by looking for a 'docs' directory).
* **`chdir()`:** A context manager for temporarily changing the current working directory. This is a standard pattern for localized file system operations in tests.
* **`get_dynamic_section_entry()`:** This function uses `readelf` to inspect the dynamic section of an ELF binary and extract a specific entry. This is a crucial function for reverse engineering and understanding how shared libraries are linked.
* **`get_soname()`:** A convenience function to get the "soname" (shared object name) from the dynamic section.
* **`get_rpath()`:**  Extracts the RPATH or RUNPATH from the dynamic section. RPATH and RUNPATH specify where the dynamic linker should look for shared libraries.
* **`get_classpath()`:**  Reads the `MANIFEST.MF` file inside a JAR (ZIP) archive and extracts the "Class-Path" entry. This is relevant for Java.
* **`get_path_without_cmd()`:**  Manipulates the `PATH` environment variable to remove directories containing a specific command. This is useful for controlling which version of a tool is used during testing.
* **`xfail_if_jobname()`:** Marks a test as an expected failure if running under a specific CI job name.

**4. Identifying Connections to Reverse Engineering and Low-Level Concepts:**

As I analyzed the functions, certain connections became clear:

* **ELF Binaries:** Functions like `get_dynamic_section_entry`, `get_soname`, and `get_rpath` directly deal with the structure of ELF (Executable and Linkable Format) binaries, which are fundamental in Linux and Android. This is a core aspect of reverse engineering.
* **Shared Libraries:** The focus on soname and RPATH/RUNPATH highlights the importance of understanding how shared libraries are loaded and linked, a critical concept in reverse engineering and system-level programming.
* **Dynamic Linking:**  The functions implicitly deal with the dynamic linker and its behavior.
* **Process Execution:** The use of `subprocess` is relevant to understanding how processes are launched and interact.

**5. Connecting to Linux, Android Kernel, and Frameworks:**

* **Linux:** ELF binaries are the standard executable format on Linux. The `readelf` command is a standard Linux utility.
* **Android:** Android uses a Linux kernel and also employs ELF binaries for native code. While Android uses its own dynamic linker (linker64/linker), the concepts of soname and RPATH are still relevant, though the implementation might differ slightly.
* **Frameworks (Implicit):** While not directly manipulating kernel code, the tests are designed to verify functionality related to how Frida (the instrumentation tool) interacts with and modifies running processes. This often involves understanding framework-level concepts like process injection and memory manipulation.

**6. Logical Reasoning and Examples:**

For functions like the decorators, the logical flow is based on conditional checks. I need to think about what happens when the condition is true and when it's false. For `get_path_without_cmd`, I can imagine a scenario where I want to test a specific version of a tool by excluding the directory where the system's default version is installed.

**7. Identifying Potential User Errors:**

Thinking about how users might interact with this code (even indirectly through the testing framework) helps identify potential errors. For example, forgetting to install dependencies like `pkg-config` or `cmake` could lead to tests being skipped. Incorrectly setting environment variables could also cause issues.

**8. Tracing User Actions:**

To understand how a user reaches this code, I need to consider the context:

* **Frida Development:**  Someone developing Frida or contributing to the project would be directly working with this code.
* **Running Tests:** Users might run the Frida test suite to verify their setup or after making changes.
* **Debugging Test Failures:** If a test fails, developers would examine the relevant helper functions to understand the test setup and assertions.

**9. Structuring the Explanation:**

Finally, I need to organize the information into a clear and understandable structure, addressing each part of the prompt. Using headings, bullet points, and code examples makes the explanation easier to follow. I also need to ensure that the language is precise and avoids jargon where possible, or explains it when necessary.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe some functions directly interact with the Android kernel. **Correction:** While the *purpose* of Frida relates to interacting with processes (which involves kernel calls), this specific helper file focuses on setting up and running tests, primarily dealing with system utilities and file manipulation.
* **Initial thought:**  Focus heavily on the specifics of Frida's internal workings. **Correction:** The prompt asks about the *helper file's* functionality. While the context is Frida, the explanation should focus on what *this code* does, not necessarily deep dives into Frida's core mechanisms. The connection to Frida is primarily through its test suite.

By following this structured analysis and refinement process, I can generate a comprehensive and accurate explanation of the provided Python code.
这是Frida动态仪器工具的一个源代码文件，位于`frida/subprojects/frida-gum/releng/meson/unittests/helpers.py`。这个文件主要提供了一系列辅助函数，用于在 Frida 的单元测试环境中简化测试用例的编写和管理。其核心功能是提供各种条件跳过测试的机制，以及一些用于检查二进制文件属性的工具。

**文件功能列表:**

1. **`is_ci()`**:  判断当前环境是否为持续集成 (CI) 环境。
2. **`skip_if_not_base_option(feature)`**:  一个装饰器，如果当前编译器不支持指定的编译器基础选项 (`feature`)，则跳过该测试。
3. **`skipIfNoPkgconfig(f)`**: 一个装饰器，如果系统中没有找到 `pkg-config` 工具（除非在 CI 环境下），则跳过该测试。
4. **`skipIfNoPkgconfigDep(depname)`**: 一个装饰器，如果系统中没有找到 `pkg-config` 工具，或者指定的 `pkg-config` 依赖 (`depname`) 不存在（除非在 CI 环境下），则跳过该测试。
5. **`skip_if_no_cmake(f)`**: 一个装饰器，如果系统中没有找到 `cmake` 工具（除非在 CI 环境下），则跳过该测试。
6. **`skip_if_not_language(lang)`**: 一个装饰器，如果系统中没有找到指定编程语言 (`lang`) 的编译器，则跳过该测试。
7. **`skip_if_env_set(key)`**: 一个装饰器，如果设置了特定的环境变量 (`key`)（除非在 CI 环境下），则跳过该测试。
8. **`skipIfNoExecutable(exename)`**: 一个装饰器，如果系统中没有找到指定的执行文件 (`exename`)，则跳过该测试。
9. **`is_tarball()`**: 判断当前目录是否看起来像一个 tarball 解压后的结构（通过检查是否存在 `docs` 目录）。
10. **`chdir(path)`**: 一个上下文管理器，用于临时切换当前工作目录到指定的 `path`。
11. **`get_dynamic_section_entry(fname, entry)`**:  读取指定文件 (`fname`) 的动态链接区，并返回指定条目 (`entry`) 的值。这个功能主要针对 ELF 格式的二进制文件。
12. **`get_soname(fname)`**:  读取指定 ELF 文件 (`fname`) 的动态链接区，并返回其 SONAME (Shared Object Name)。
13. **`get_rpath(fname)`**: 读取指定 ELF 文件 (`fname`) 的动态链接区，并返回其 RPATH 或 RUNPATH。
14. **`get_classpath(fname)`**: 读取指定的 ZIP 文件 (`fname`) (通常是 JAR 文件) 中的 `META-INF/MANIFEST.MF` 文件，并返回 `Class-Path` 的值。
15. **`get_path_without_cmd(cmd, path)`**: 从给定的 `path` 环境变量中移除包含指定命令 (`cmd`) 的目录。
16. **`xfail_if_jobname(name)`**: 如果当前 CI 任务的名称与给定的 `name` 匹配，则将该测试标记为预期失败。

**与逆向方法的关联及举例说明:**

这个文件中的几个函数与逆向工程方法直接相关，特别是针对 ELF 二进制文件的分析：

* **`get_dynamic_section_entry(fname, entry)`**:  在逆向工程中，理解动态链接库的依赖关系至关重要。动态链接区包含了关于程序运行时如何加载和链接共享库的信息。例如，可以使用这个函数来获取一个可执行文件依赖的所有共享库：

   ```python
   # 假设 test_executable 是一个 ELF 可执行文件
   soname_entries = []
   try:
       with open("test_executable", "rb") as f:
           # 简单判断是否是 ELF 文件
           if f.read(4) == b'\x7fELF':
               raw_out = subprocess.check_output(['readelf', '-d', "test_executable"], universal_newlines=True)
               for line in raw_out.split('\n'):
                   if "NEEDED" in line:
                       match = re.search(r'NEEDED\s+Shared library: \[(.*?)\]', line)
                       if match:
                           soname_entries.append(match.group(1))
               print(f"可执行文件 'test_executable' 依赖的共享库: {soname_entries}")
   except FileNotFoundError:
       print("找不到文件")
   except subprocess.CalledProcessError as e:
       print(f"执行 readelf 失败: {e}")
   ```

* **`get_soname(fname)`**:  SONAME 是共享库的一个重要属性，用于标识库的版本。在逆向分析中，了解共享库的 SONAME 可以帮助确定正在使用的库版本，从而查找已知的漏洞或分析特定版本的行为。

   ```python
   # 假设 libtest.so 是一个共享库文件
   soname = get_soname("libtest.so")
   if soname:
       print(f"共享库 'libtest.so' 的 SONAME 是: {soname}")
   else:
       print("无法获取 SONAME")
   ```

* **`get_rpath(fname)`**: RPATH 和 RUNPATH 指定了动态链接器在运行时搜索共享库的路径。逆向工程师可以通过分析 RPATH/RUNPATH 来了解程序在哪些目录下查找依赖库，这有助于理解程序的加载机制，或者在某些情况下，发现潜在的库劫持风险。

   ```python
   # 假设 an_application 是一个 ELF 可执行文件
   rpath = get_rpath("an_application")
   if rpath:
       print(f"可执行文件 'an_application' 的 RPATH/RUNPATH 是: {rpath}")
   else:
       print("未找到 RPATH/RUNPATH")
   ```

**涉及二进制底层、Linux、Android内核及框架的知识及举例说明:**

这些辅助函数涉及到以下底层知识：

* **二进制文件格式 (ELF):** `get_dynamic_section_entry`, `get_soname`, 和 `get_rpath` 函数都直接操作 ELF 文件格式，这是一种用于可执行文件、共享库和目标代码的标准格式，广泛应用于 Linux 和 Android 系统。理解 ELF 文件的结构（如 Section Header Table, Program Header Table, Dynamic Section 等）是使用这些函数的前提。

* **动态链接:**  这些函数涉及到动态链接的概念，即程序在运行时才解析符号引用，加载所需的共享库。这与静态链接形成对比，后者在编译时将所有依赖库的代码都链接到可执行文件中。

* **Linux 系统调用和工具:**  `get_dynamic_section_entry` 函数内部使用了 `readelf` 命令，这是一个 Linux 系统自带的用于显示 ELF 文件信息的工具。这体现了测试代码对底层系统工具的依赖。

* **Android 系统:** 虽然代码本身运行在主机环境上进行测试，但 Frida 的目标是动态分析 Android (以及其他系统) 的进程。理解 Android 的动态链接器 (如 `linker`, `linker64`) 如何处理共享库加载和 RPATH/RUNPATH，以及 Android 应用的 APK 文件结构（其中的 `lib` 目录包含 native 库），有助于理解这些测试辅助函数的意义。例如，在 Android 中，库的搜索路径可能与标准的 Linux 系统有所不同。

**逻辑推理、假设输入与输出:**

以 `skipIfNoPkgconfigDep(depname)` 为例：

* **假设输入:**
    * `depname`: 字符串，例如 `"glib-2.0"`
    * 当前运行环境没有安装 `pkg-config` 工具。

* **逻辑推理:**
    1. `skipIfNoPkgconfigDep` 装饰器被调用。
    2. 首先检查 `is_ci()` 的结果。假设当前不在 CI 环境。
    3. `shutil.which('pkg-config')` 返回 `None`，因为系统中没有 `pkg-config`。
    4. 装饰器内部会抛出一个 `unittest.SkipTest('pkg-config not found')` 异常。

* **预期输出:**  使用该装饰器的测试用例将被跳过，并在测试结果中显示跳过信息 "pkg-config not found"。

再以 `get_path_without_cmd(cmd, path)` 为例：

* **假设输入:**
    * `cmd`: 字符串，例如 `"python"`
    * `path`: 字符串，例如 `"/usr/bin:/opt/my_python/bin:/usr/local/bin"`
    * 系统中 `/usr/bin/python` 和 `/opt/my_python/bin/python` 都存在。

* **逻辑推理:**
    1. `get_path_without_cmd("python", "/usr/bin:/opt/my_python/bin:/usr/local/bin")` 被调用。
    2. 第一次调用 `shutil.which("python", path="/usr/bin:/opt/my_python/bin:/usr/local/bin")` 可能返回 `/usr/bin/python`。
    3. `/usr/bin` 从 `paths` 集合中被移除。
    4. 第二次调用 `shutil.which("python", path="/opt/my_python/bin:/usr/local/bin")` 可能返回 `/opt/my_python/bin/python`。
    5. `/opt/my_python/bin` 从 `paths` 集合中被移除。
    6. 第三次调用 `shutil.which` 找不到 `python`，循环结束。

* **预期输出:**  返回的字符串是 `"/usr/local/bin"`。

**涉及用户或者编程常见的使用错误及举例说明:**

* **忘记安装依赖工具:** 用户在本地运行测试时，如果忘记安装 `pkg-config` 或 `cmake`，会导致大量使用了 `skipIfNoPkgconfig` 和 `skip_if_no_cmake` 装饰器的测试被跳过，可能误以为所有测试都通过了。

   ```python
   # 假设用户本地没有安装 pkg-config
   @skipIfNoPkgconfig
   def test_something_that_requires_pkgconfig(self):
       # ... 一些需要 pkg-config 的测试代码 ...
       pass

   # 如果没有 pkg-config，这个测试会被静默跳过，用户可能意识不到。
   ```

* **环境变量设置不当:**  `skip_if_env_set` 旨在避免在特定环境变量存在时运行某些测试。如果用户错误地设置了这些环境变量，可能会导致本应运行的测试被跳过。

   ```python
   # 假设某个测试在设置了 DEBUG_MODE 环境变量时应该跳过
   @skip_if_env_set("DEBUG_MODE")
   def test_something_in_release_mode(self):
       # ... 仅在非 DEBUG 模式下运行的测试代码 ...
       pass

   # 如果用户设置了 export DEBUG_MODE=1，这个测试会被跳过。
   ```

* **文件路径错误:** 在使用 `get_dynamic_section_entry` 等函数时，如果提供的文件路径 `fname` 不存在或不是有效的 ELF 文件，会导致 `FileNotFoundError` 或 `subprocess.CalledProcessError`。

   ```python
   try:
       soname = get_soname("non_existent_file.so")
   except FileNotFoundError:
       print("错误：指定的文件不存在")
   except subprocess.CalledProcessError as e:
       print(f"错误：readelf 执行失败: {e}")
   ```

**说明用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接调用 `helpers.py` 中的函数。这个文件是 Frida 项目测试套件的一部分。以下是一些用户操作可能间接导致这里代码被执行的场景：

1. **运行 Frida 的单元测试:**  Frida 的开发者或贡献者会在开发过程中运行单元测试来验证代码的正确性。他们可能会使用类似 `python run_tests.py` 或 `meson test` 的命令来执行测试套件。 Meson 构建系统会负责发现并执行 `frida/subprojects/frida-gum/releng/meson/unittests/` 目录下的测试用例，这些测试用例可能会import并使用 `helpers.py` 中的函数。

2. **调试测试失败:** 当某个 Frida 功能出现问题或者修改了代码后，运行测试套件时可能会有测试用例失败。为了调试失败的测试，开发者会查看测试代码，而测试代码很可能使用了 `helpers.py` 中的辅助函数来设置测试环境、跳过不适用的测试或检查二进制文件的属性。

   例如，一个测试用例可能需要检查 Frida Gum 注入代码后，目标进程的某个共享库的 RPATH 是否被正确设置。这个测试用例可能会调用 `helpers.get_rpath()` 来获取目标库的 RPATH，并与期望值进行比较。如果测试失败，开发者会查看 `get_rpath()` 的实现，确认 `readelf` 命令是否正确执行，以及结果解析是否正确。

3. **贡献代码或进行代码审查:**  当开发者向 Frida 项目贡献代码时，通常需要确保新代码不会破坏现有的功能。这需要运行完整的测试套件，包括使用了 `helpers.py` 的单元测试。代码审查者也会关注测试用例的编写方式，确保使用了合适的辅助函数来保证测试的可靠性和覆盖率。

4. **CI 环境的自动化测试:**  Frida 项目的 CI 系统会在每次代码提交或合并时自动运行测试套件。CI 系统的执行流程会涉及到 Meson 构建和测试执行，从而间接地触发 `helpers.py` 中代码的执行。CI 日志中可能会包含由于 `skipIfNoPkgconfig` 等函数而跳过的测试信息，这可以作为调试环境配置问题的线索。

总之，用户通常不会直接与 `helpers.py` 交互，但它作为 Frida 测试框架的核心组成部分，在开发、测试和持续集成流程中扮演着重要的角色。开发者通过编写和运行测试用例，间接地触发了这个文件中代码的执行，并通过分析测试结果和相关辅助函数的行为来调试问题。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/helpers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
import subprocess
import os
import shutil
import unittest
import functools
import re
import typing as T
import zipfile
from pathlib import Path
from contextlib import contextmanager

from mesonbuild.compilers import detect_c_compiler, compiler_from_language
from mesonbuild.mesonlib import (
    MachineChoice, is_osx, is_cygwin, EnvironmentException, OptionKey, MachineChoice,
    OrderedSet
)
from run_tests import get_fake_env


def is_ci():
    if os.environ.get('MESON_CI_JOBNAME') not in {None, 'thirdparty'}:
        return True
    return False

def skip_if_not_base_option(feature):
    """Skip tests if The compiler does not support a given base option.

    for example, ICC doesn't currently support b_sanitize.
    """
    def actual(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            env = get_fake_env()
            cc = detect_c_compiler(env, MachineChoice.HOST)
            key = OptionKey(feature)
            if key not in cc.base_options:
                raise unittest.SkipTest(
                    f'{feature} not available with {cc.id}')
            return f(*args, **kwargs)
        return wrapped
    return actual

def skipIfNoPkgconfig(f):
    '''
    Skip this test if no pkg-config is found, unless we're on CI.
    This allows users to run our test suite without having
    pkg-config installed on, f.ex., macOS, while ensuring that our CI does not
    silently skip the test because of misconfiguration.

    Note: Yes, we provide pkg-config even while running Windows CI
    '''
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not is_ci() and shutil.which('pkg-config') is None:
            raise unittest.SkipTest('pkg-config not found')
        return f(*args, **kwargs)
    return wrapped

def skipIfNoPkgconfigDep(depname):
    '''
    Skip this test if the given pkg-config dep is not found, unless we're on CI.
    '''
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            if not is_ci() and shutil.which('pkg-config') is None:
                raise unittest.SkipTest('pkg-config not found')
            if not is_ci() and subprocess.call(['pkg-config', '--exists', depname]) != 0:
                raise unittest.SkipTest(f'pkg-config dependency {depname} not found.')
            return func(*args, **kwargs)
        return wrapped
    return wrapper

def skip_if_no_cmake(f):
    '''
    Skip this test if no cmake is found, unless we're on CI.
    This allows users to run our test suite without having
    cmake installed on, f.ex., macOS, while ensuring that our CI does not
    silently skip the test because of misconfiguration.
    '''
    @functools.wraps(f)
    def wrapped(*args, **kwargs):
        if not is_ci() and shutil.which('cmake') is None:
            raise unittest.SkipTest('cmake not found')
        return f(*args, **kwargs)
    return wrapped

def skip_if_not_language(lang: str):
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            try:
                compiler_from_language(get_fake_env(), lang, MachineChoice.HOST)
            except EnvironmentException:
                raise unittest.SkipTest(f'No {lang} compiler found.')
            return func(*args, **kwargs)
        return wrapped
    return wrapper

def skip_if_env_set(key):
    '''
    Skip a test if a particular env is set, except when running under CI
    '''
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            old = None
            if key in os.environ:
                if not is_ci():
                    raise unittest.SkipTest(f'Env var {key!r} set, skipping')
                old = os.environ.pop(key)
            try:
                return func(*args, **kwargs)
            finally:
                if old is not None:
                    os.environ[key] = old
        return wrapped
    return wrapper

def skipIfNoExecutable(exename):
    '''
    Skip this test if the given executable is not found.
    '''
    def wrapper(func):
        @functools.wraps(func)
        def wrapped(*args, **kwargs):
            if shutil.which(exename) is None:
                raise unittest.SkipTest(exename + ' not found')
            return func(*args, **kwargs)
        return wrapped
    return wrapper

def is_tarball():
    if not os.path.isdir('docs'):
        return True
    return False

@contextmanager
def chdir(path: str):
    curdir = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(curdir)

def get_dynamic_section_entry(fname: str, entry: str) -> T.Optional[str]:
    if is_cygwin() or is_osx():
        raise unittest.SkipTest('Test only applicable to ELF platforms')

    try:
        raw_out = subprocess.check_output(['readelf', '-d', fname],
                                          universal_newlines=True)
    except FileNotFoundError:
        # FIXME: Try using depfixer.py:Elf() as a fallback
        raise unittest.SkipTest('readelf not found')
    pattern = re.compile(entry + r': \[(.*?)\]')
    for line in raw_out.split('\n'):
        m = pattern.search(line)
        if m is not None:
            return str(m.group(1))
    return None # The file did not contain the specified entry.

def get_soname(fname: str) -> T.Optional[str]:
    return get_dynamic_section_entry(fname, 'soname')

def get_rpath(fname: str) -> T.Optional[str]:
    raw = get_dynamic_section_entry(fname, r'(?:rpath|runpath)')
    # Get both '' and None here
    if not raw:
        return None
    # nix/nixos adds a bunch of stuff to the rpath out of necessity that we
    # don't check for, so clear those
    final = ':'.join([e for e in raw.split(':') if not e.startswith('/nix')])
    # If we didn't end up anything but nix paths, return None here
    if not final:
        return None
    return final

def get_classpath(fname: str) -> T.Optional[str]:
    with zipfile.ZipFile(fname) as zip:
        with zip.open('META-INF/MANIFEST.MF') as member:
            contents = member.read().decode().strip()
    lines = []
    for line in contents.splitlines():
        if line.startswith(' '):
            # continuation line
            lines[-1] += line[1:]
        else:
            lines.append(line)
    manifest = {
        k.lower(): v.strip() for k, v in [l.split(':', 1) for l in lines]
    }
    return manifest.get('class-path')

def get_path_without_cmd(cmd: str, path: str) -> str:
    pathsep = os.pathsep
    paths = OrderedSet([Path(p).resolve() for p in path.split(pathsep)])
    while True:
        full_path = shutil.which(cmd, path=path)
        if full_path is None:
            break
        dirname = Path(full_path).resolve().parent
        paths.discard(dirname)
        path = pathsep.join([str(p) for p in paths])
    return path

def xfail_if_jobname(name: str):
    if os.environ.get('MESON_CI_JOBNAME') == name:
        return unittest.expectedFailure

    def wrapper(func):
        return func
    return wrapper
```