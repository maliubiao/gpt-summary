Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding: The Big Picture**

The first step is to understand the *purpose* of the code. The file path `frida/subprojects/frida-python/releng/meson/unittests/helpers.py` immediately suggests it's part of the testing infrastructure for Frida's Python bindings. The "helpers" part further suggests it provides utility functions to assist in writing and running tests.

**2. Identifying Key Functions and Their Roles**

Next, I'd go through the code and identify the individual functions and try to understand what each one does. I'd look for keywords and patterns that provide clues:

* **`is_ci()`:** The name and the check for `os.environ.get('MESON_CI_JOBNAME')` strongly suggest this checks if the code is running in a Continuous Integration environment.
* **`skip_if_not_base_option()`:** The name and the interaction with `mesonbuild.compilers` points to skipping tests based on compiler capabilities. The comment reinforces this.
* **`skipIfNoPkgconfig()` and `skipIfNoPkgconfigDep()`:**  The names and the use of `shutil.which('pkg-config')` clearly indicate these functions skip tests if `pkg-config` (and specific dependencies) aren't available. The CI exception is a detail to note.
* **`skip_if_no_cmake()`:** Similar logic to the `pkg-config` functions, but for `cmake`.
* **`skip_if_not_language()`:** The use of `compiler_from_language` suggests skipping tests if a specific programming language compiler is not found.
* **`skip_if_env_set()`:** The name and the environment variable check indicate skipping tests if a particular environment variable is set. The CI exception is again important.
* **`skipIfNoExecutable()`:** Similar to `pkg-config` and `cmake`, but for general executables.
* **`is_tarball()`:** Checking for the existence of a `docs` directory suggests this determines if the code is running from a tarball distribution (where the `docs` might be absent).
* **`chdir()`:** This is a standard context manager for temporarily changing the current working directory.
* **`get_dynamic_section_entry()`:** The use of `subprocess.check_output(['readelf', '-d', ...])` immediately points to inspecting ELF binary headers (used on Linux). The regex further suggests parsing the output. The skip for Cygwin/macOS reinforces the ELF-specific nature.
* **`get_soname()` and `get_rpath()`:** These build upon `get_dynamic_section_entry` and are specific ELF header entries related to shared libraries.
* **`get_classpath()`:** The use of `zipfile` and opening `META-INF/MANIFEST.MF` clearly indicates this function is for extracting the classpath from a Java JAR file.
* **`get_path_without_cmd()`:**  The use of `shutil.which` multiple times suggests this function manipulates the PATH environment variable to remove directories containing a specific command.
* **`xfail_if_jobname()`:** This function seems to mark tests as expected failures based on the CI job name.

**3. Categorizing Functionality and Connections to Reverse Engineering/Low-Level Concepts**

As I identified the functions, I'd start thinking about how they relate to the prompt's requirements:

* **Reverse Engineering:** Functions like `get_dynamic_section_entry`, `get_soname`, `get_rpath`, and the use of `readelf` are directly related to inspecting binary files, which is a core part of reverse engineering. Frida itself is a dynamic instrumentation tool, heavily used in reverse engineering.
* **Binary/Low-Level:**  Again, the ELF header functions and the use of `readelf` are directly tied to binary formats and low-level operating system concepts.
* **Linux/Android Kernel/Framework:** While not explicitly interacting with kernel code, the reliance on ELF binaries and standard Linux utilities like `readelf` ties these functions to the Linux environment. Frida is also commonly used for Android reverse engineering, so the testing framework would need to be aware of these concepts. The mention of `soname` and `rpath` is relevant in the context of shared libraries, which are fundamental to operating system frameworks.
* **Logic and Assumptions:**  For the `skip` functions, I'd consider the implicit logic – if a tool isn't available, the test might fail or give misleading results, so skipping is a reasonable strategy. For `get_path_without_cmd`, the assumption is that `shutil.which` correctly finds executables.
* **User Errors:**  The `skip` functions indirectly address user errors by preventing tests from failing due to missing dependencies or incorrect environments. The `get_path_without_cmd` function could be used to debug PATH issues.

**4. Providing Examples**

Once the function roles and connections are clear, I would formulate concrete examples for each relevant category. This involves:

* **Reverse Engineering:**  Demonstrating how `get_soname` extracts the shared library name is a good example.
* **Binary/Low-Level:** Explaining the significance of SONAME and RPATH in dynamic linking.
* **Linux/Android:**  Connecting `readelf` to Linux binary analysis.
* **Logic/Assumptions:**  Showing how a `skip` function prevents test failures.
* **User Errors:**  Illustrating the scenario where a test might fail without the `skip` function.

**5. Explaining User Operations and Debugging**

Finally, I would consider how a user might end up interacting with this code, primarily through running tests. The debugging aspect comes from how these helper functions aid in isolating issues during test development.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe some `skip` functions are redundant. **Correction:** Realized that the CI exception in some `skip` functions is important for ensuring tests aren't accidentally skipped in the CI environment, even if a user has those tools installed locally.
* **Initial thought:** Focus too much on the specific implementation details of `mesonbuild`. **Correction:** Shift focus to the broader purpose of the helper functions in the context of testing and their relation to reverse engineering/low-level concepts.
* **Missed connection:**  Initially didn't explicitly link Frida's nature as a dynamic instrumentation tool to the relevance of these helper functions in its testing. **Correction:** Made the connection clearer.

By following these steps, I can systematically analyze the code and provide a comprehensive answer that addresses all aspects of the prompt. The key is to move from a high-level understanding to individual function analysis and then connect those functions back to the broader context of Frida, testing, and reverse engineering.
`frida/subprojects/frida-python/releng/meson/unittests/helpers.py` 是 Frida Python 绑定项目中用于单元测试的辅助模块。它提供了一系列函数，用于简化测试的编写和执行，特别是针对不同环境和依赖项的测试。

以下是该文件的功能列表，并根据你的要求进行了分类和举例说明：

**1. 跳过测试 (Skipping Tests Based on Environment/Dependencies):**

* **`is_ci()`:**
    * **功能:**  判断当前环境是否为持续集成 (CI) 环境。它通过检查 `MESON_CI_JOBNAME` 环境变量来确定。如果该变量已设置且不为 'thirdparty'，则返回 `True`。
    * **与逆向方法的关系:**  在 CI 环境中运行的测试通常需要覆盖更广泛的场景，包括一些在本地开发环境中可能被忽略的情况。例如，在 CI 中可能需要测试针对特定架构或操作系统的 Frida 功能，这与逆向工程师在不同目标平台上调试的需求类似。
    * **二进制底层/Linux/Android:**  CI 环境通常模拟不同的操作系统和架构，这与 Frida 需要支持多种目标环境相关。
    * **逻辑推理:**
        * **假设输入:** `os.environ.get('MESON_CI_JOBNAME')` 返回 'linux-x64'
        * **输出:** `True`
        * **假设输入:** `os.environ.get('MESON_CI_JOBNAME')` 返回 None
        * **输出:** `False`
* **`skip_if_not_base_option(feature)`:**
    * **功能:**  如果当前编译器不支持指定的 base option (Meson 的编译选项)，则跳过该测试。例如，某些编译器可能不支持代码清理 (sanitizer) 选项。
    * **与逆向方法的关系:** 逆向工程师可能需要在不同的编译配置下构建目标程序，以分析不同优化级别或安全特性的影响。此函数模拟了这种场景，确保测试只在支持特定编译选项的环境下运行。
    * **二进制底层:**  编译器选项直接影响生成二进制文件的结构和特性。
    * **逻辑推理:**
        * **假设输入:** `feature` 为 'b_sanitize'，当前 C 编译器支持 sanitizers。
        * **输出:**  不跳过测试。
        * **假设输入:** `feature` 为 'b_sanitize'，当前 C 编译器 (如旧版本的 ICC) 不支持 sanitizers。
        * **输出:**  跳过测试。
* **`skipIfNoPkgconfig(f)`:**
    * **功能:**  如果系统中没有 `pkg-config` 工具，则跳过该测试。除非当前处于 CI 环境。
    * **与逆向方法的关系:** `pkg-config` 用于查找系统中已安装的库的信息，这在逆向工程中也很常见，例如确定目标程序依赖哪些库。
    * **Linux/Android:** `pkg-config` 在 Linux 和 Android 开发中广泛使用。
    * **逻辑推理:**
        * **假设输入:**  `shutil.which('pkg-config')` 返回 `/usr/bin/pkg-config` (非 CI 环境)。
        * **输出:** 不跳过测试。
        * **假设输入:** `shutil.which('pkg-config')` 返回 `None` (非 CI 环境)。
        * **输出:** 跳过测试。
        * **假设输入:** `shutil.which('pkg-config')` 返回 `None` (CI 环境)。
        * **输出:** 不跳过测试。
* **`skipIfNoPkgconfigDep(depname)`:**
    * **功能:**  如果系统中没有 `pkg-config` 工具或者指定的 `pkg-config` 依赖项未找到，则跳过该测试。除非当前处于 CI 环境。
    * **与逆向方法的关系:**  类似于 `skipIfNoPkgconfig`，更具体地检查特定库的可用性。
    * **Linux/Android:**  依赖于 `pkg-config` 生态系统。
    * **逻辑推理:**
        * **假设输入:** `pkg-config` 可用，且 `pkg-config --exists glib-2.0` 返回 0 (表示找到 glib-2.0)。
        * **输出:** 不跳过测试。
        * **假设输入:** `pkg-config` 可用，但 `pkg-config --exists glib-2.0` 返回非 0 (表示未找到 glib-2.0)。
        * **输出:** 跳过测试。
* **`skip_if_no_cmake(f)`:**
    * **功能:**  如果系统中没有 `cmake` 工具，则跳过该测试。除非当前处于 CI 环境。
    * **与逆向方法的关系:** `cmake` 是一个常用的构建系统，逆向工程师可能会遇到使用 `cmake` 构建的项目。
    * **逻辑推理:** 与 `skipIfNoPkgconfig` 类似。
* **`skip_if_not_language(lang)`:**
    * **功能:**  如果系统中没有指定的编程语言的编译器，则跳过该测试。
    * **与逆向方法的关系:**  Frida 可以与多种编程语言进行交互，测试需要覆盖这些语言的绑定。逆向工程师也需要熟悉多种编程语言。
    * **逻辑推理:**
        * **假设输入:** `lang` 为 'c'，系统中安装了 C 编译器。
        * **输出:** 不跳过测试。
        * **假设输入:** `lang` 为 'rust'，系统中没有安装 Rust 编译器。
        * **输出:** 跳过测试。
* **`skip_if_env_set(key)`:**
    * **功能:**  如果指定的环境变量已设置，则跳过该测试。除非当前处于 CI 环境。
    * **与逆向方法的关系:**  某些逆向分析工具或技术可能依赖于特定的环境变量。此函数可以用来避免测试与这些环境冲突。
    * **逻辑推理:**
        * **假设输入:** `key` 为 'FRIDA_TEST_SKIP'，该环境变量未设置 (非 CI 环境)。
        * **输出:** 不跳过测试。
        * **假设输入:** `key` 为 'FRIDA_TEST_SKIP'，该环境变量已设置 (非 CI 环境)。
        * **输出:** 跳过测试。
        * **假设输入:** `key` 为 'FRIDA_TEST_SKIP'，该环境变量已设置 (CI 环境)。
        * **输出:** 不跳过测试 (测试会继续执行，但环境变量会在测试前后被恢复)。
* **`skipIfNoExecutable(exename)`:**
    * **功能:**  如果系统中没有指定的executable，则跳过该测试。
    * **与逆向方法的关系:** 逆向工程经常需要使用各种工具，例如调试器、反汇编器等。
    * **逻辑推理:**
        * **假设输入:** `exename` 为 'gdb'，系统中安装了 gdb。
        * **输出:** 不跳过测试。
        * **假设输入:** `exename` 为 'ida'，系统中没有安装 IDA Pro。
        * **输出:** 跳过测试。

**2. 环境管理:**

* **`is_tarball()`:**
    * **功能:**  判断当前代码是否是从 tarball 包中运行的。它通过检查是否存在 `docs` 目录来判断。
    * **与逆向方法的关系:**  逆向工程师可能会从不同的来源获取 Frida 或目标程序，了解运行环境有助于测试覆盖不同的部署方式。
    * **逻辑推理:**
        * **假设输入:** 存在 `docs` 目录。
        * **输出:** `False`
        * **假设输入:** 不存在 `docs` 目录。
        * **输出:** `True`
* **`chdir(path)`:**
    * **功能:**  一个上下文管理器，用于临时改变当前工作目录。
    * **与逆向方法的关系:**  逆向分析常常需要在特定的目录下执行命令或访问文件。
    * **用户或编程常见的使用错误:**  忘记在操作完成后切换回原来的目录，可能导致后续操作找不到文件或路径错误。
    * **用户操作步骤:**  测试脚本调用 `with chdir("/tmp"):`，然后在该代码块内执行需要特定工作目录的操作。

**3. 二进制文件分析 (Binary File Analysis):**

* **`get_dynamic_section_entry(fname, entry)`:**
    * **功能:**  使用 `readelf` 工具获取 ELF 文件 (Linux 下的可执行文件和共享库) 的动态节 (dynamic section) 中指定条目的值。
    * **与逆向方法的关系:**  动态节包含程序运行时链接和加载的重要信息，例如依赖的共享库、RPATH、RUNPATH 等，这些都是逆向分析的关键信息。
    * **二进制底层/Linux:**  直接操作 ELF 文件格式。
    * **逻辑推理:**
        * **假设输入:** `fname` 指向一个名为 `libtest.so` 的共享库，其动态节包含 `SONAME: [libtest.so.1]`。`entry` 为 'soname'。
        * **输出:** `'libtest.so.1'`
        * **假设输入:** `fname` 指向一个名为 `myprogram` 的可执行文件，其动态节不包含 `RPATH` 条目。`entry` 为 'rpath'。
        * **输出:** `None`
    * **用户或编程常见的使用错误:**  `readelf` 工具未安装会导致测试失败。
* **`get_soname(fname)`:**
    * **功能:**  调用 `get_dynamic_section_entry` 获取 ELF 文件的 SONAME (Shared Object Name)。
    * **与逆向方法的关系:**  SONAME 是共享库的版本标识，用于动态链接器在运行时查找正确的库版本。
    * **二进制底层/Linux:**  依赖于 ELF 文件格式。
* **`get_rpath(fname)`:**
    * **功能:**  调用 `get_dynamic_section_entry` 获取 ELF 文件的 RPATH 或 RUNPATH。它还会过滤掉以 `/nix` 开头的路径，因为这些通常是 NixOS 特有的，不属于通用的 RPATH/RUNPATH。
    * **与逆向方法的关系:**  RPATH 和 RUNPATH 指定了动态链接器在查找共享库时搜索的目录列表。理解这些路径对于逆向分析库的加载过程至关重要。
    * **二进制底层/Linux:**  依赖于 ELF 文件格式和动态链接机制。
* **`get_classpath(fname)`:**
    * **功能:**  从 JAR 文件中读取 `META-INF/MANIFEST.MF` 文件，并解析出 `Class-Path` 属性的值。
    * **与逆向方法的关系:**  在逆向 Java 程序时，了解其 classpath 可以帮助理解类加载顺序和依赖关系。
    * **二进制底层:**  涉及到 ZIP 文件格式和 JAR 文件结构。

**4. 路径处理:**

* **`get_path_without_cmd(cmd, path)`:**
    * **功能:**  从 `path` 环境变量中移除包含指定命令 `cmd` 的目录。
    * **与逆向方法的关系:**  在测试或逆向分析时，可能需要隔离特定的工具版本，或者避免某些路径干扰测试结果。
    * **Linux/Android:**  直接操作 PATH 环境变量。
    * **逻辑推理:**
        * **假设输入:** `cmd` 为 'frida-server'，`path` 为 `/usr/bin:/opt/frida/bin:/usr/local/bin`，且 `/opt/frida/bin/frida-server` 存在。
        * **输出:** `/usr/bin:/usr/local/bin`
    * **用户或编程常见的使用错误:**  提供的 `cmd` 不存在于 `path` 中的任何目录，会导致 `path` 没有变化。

**5. 标记预期失败:**

* **`xfail_if_jobname(name)`:**
    * **功能:**  如果当前 CI job 的名称与指定的 `name` 匹配，则将该测试标记为预期失败 (expected failure)。
    * **与逆向方法的关系:**  在 CI 环境中，某些测试可能已知在特定的 job 配置下会失败，使用此函数可以避免将这些已知失败的测试计为真正的失败。
    * **逻辑推理:**
        * **假设输入:** `os.environ.get('MESON_CI_JOBNAME')` 返回 'windows-x64'，`name` 为 'windows-x64'。
        * **输出:**  返回 `unittest.expectedFailure` 装饰器，该测试将被标记为预期失败。
        * **假设输入:** `os.environ.get('MESON_CI_JOBNAME')` 返回 'linux-x64'，`name` 为 'windows-x64'。
        * **输出:**  返回一个不做任何操作的装饰器，测试正常运行。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者修改了 Frida Python 绑定的代码。**
2. **开发者运行了单元测试。** 这通常是通过在项目根目录下执行类似 `meson test` 或 `pytest` 命令来完成的。
3. **测试框架 (如 pytest) 加载并执行测试文件。**
4. **在执行测试文件时，会导入 `frida/subprojects/frida-python/releng/meson/unittests/helpers.py` 模块。**
5. **测试用例可能会调用 `helpers.py` 中提供的函数。** 例如，一个测试 ELF 文件处理功能的测试可能会调用 `get_soname` 来验证共享库的名称是否正确。
6. **如果在测试运行过程中出现错误，例如测试被意外跳过或断言失败，开发者可以查看测试输出和日志，其中会包含有关哪些 `helpers.py` 函数被调用以及其返回值的线索。** 这有助于开发者理解测试环境和依赖项的状态，从而定位问题。

总而言之，`helpers.py` 是一个用于管理测试环境、简化测试编写和分析二进制文件的实用工具集，它在 Frida Python 绑定的开发和测试过程中扮演着重要的角色。 它的功能与逆向工程的许多方面都有关联，因为它涉及到对二进制文件结构的理解、对操作系统环境的感知以及对各种工具和依赖项的管理。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/unittests/helpers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```