Response:
Let's break down the thought process for analyzing the `helpers.py` file.

**1. Initial Scan and Purpose Identification:**

The first step is to quickly read through the code and identify the core purpose. Keywords like `unittest`, `skipIf`, `is_ci`, and file path components like `unittests` immediately suggest this file is part of a testing framework. The filename `helpers.py` reinforces this, indicating it provides utility functions to aid in testing. The `frida` and `frida-qml` in the path hint at the specific project it's related to.

**2. Categorizing the Functions:**

Next, I would go through each function and try to understand its primary role. I would group them logically. My mental categories would likely be:

* **Skipping Tests:**  Functions starting with `skipIf` clearly fall into this category.
* **Environment Checking:** Functions like `is_ci`, `is_tarball`.
* **System Utility Interaction:**  Functions involving `subprocess`, `shutil`, like `get_dynamic_section_entry`, `get_soname`, `get_rpath`, `get_classpath`, `get_path_without_cmd`.
* **Context Management:**  `chdir`.
* **Test Result Modification:** `xfail_if_jobname`.

**3. Deeper Dive into Functionality and Connections:**

Once categorized, I would analyze each function in more detail, paying attention to:

* **Inputs and Outputs:** What does the function take as arguments and what does it return?
* **Underlying Mechanisms:**  How does the function achieve its purpose? Does it interact with the operating system, external tools, or internal data structures?
* **Conditions and Logic:** What conditions trigger different behaviors within the function?  (e.g., the `if not is_ci()` checks).

**4. Connecting to Reverse Engineering and Binary/Kernel Concepts:**

This is where the domain knowledge comes in. I would specifically look for functions that interact with executables or libraries in a way that is relevant to reverse engineering:

* **`get_dynamic_section_entry`, `get_soname`, `get_rpath`:** These directly relate to the dynamic linking process in ELF binaries, a core concept in reverse engineering for understanding dependencies and library loading. This triggers thoughts about how reverse engineers analyze these sections.
* **`get_classpath`:**  While related to Java archives, understanding classpaths is important for reverse engineering Java applications.
* **`shutil.which`:**  This helps understand if tools are available, which is often a precursor to using reverse engineering tools.

For binary/kernel aspects, the focus would be on functions interacting with low-level system features:

* **ELF analysis:** The `readelf` usage is a clear indicator of dealing with ELF binaries, common on Linux and Android.
* **Environment variables:** Checking environment variables (`os.environ`) is relevant in understanding how processes are configured and can be exploited or analyzed in reverse engineering.

**5. Logical Reasoning and Examples:**

For functions with conditional logic, I would try to create simple "if-then" scenarios:

* **`skipIfNoPkgconfig`:**  If `pkg-config` is not found AND we are not on CI, then skip the test. This helps illustrate the function's behavior.
* **`get_dynamic_section_entry`:** If the `readelf` output contains a line matching the `entry` pattern, extract the value. Otherwise, return `None`.

**6. User/Programming Errors:**

I would consider how a developer or user might misuse these helper functions or encounter issues:

* **Incorrect usage of `skipIf` decorators:** Applying them to inappropriate tests or misunderstanding their conditions.
* **Missing dependencies:** Relying on external tools (like `pkg-config`, `cmake`, `readelf`) without ensuring they are present in the testing environment.

**7. Debugging Scenario:**

To understand how a user might reach this code during debugging, I would think about the typical workflow:

* **Writing or modifying a test:** A developer working on Frida's QML support might add a new test case.
* **Running tests:** They would execute the test suite using Meson.
* **Test failure:** A test might fail, and they would need to examine the test code and the helper functions to understand why. The stack trace would lead them to this file.

**8. Iteration and Refinement:**

Throughout this process, I would iterate and refine my understanding. For example, initially, I might not immediately grasp the significance of `MachineChoice.HOST`. Upon closer inspection and potentially some external research, I would realize its role in specifying the target architecture for compiler detection.

By following these steps, combining code analysis with domain knowledge, and focusing on the purpose, mechanisms, and potential issues, I can generate a comprehensive explanation of the `helpers.py` file, as demonstrated in the provided example answer.
这个文件 `helpers.py` 是 Frida 动态 instrumentation 工具中 `frida-qml` 子项目的单元测试辅助模块。它包含了一系列帮助函数，主要用于简化和管理单元测试的执行和环境准备。

以下是它的功能列表，并根据你的要求进行了分类和举例说明：

**1. 跳过测试 (Skipping Tests):**

* **`is_ci()`:**  判断当前环境是否为持续集成 (CI) 环境。如果环境变量 `MESON_CI_JOBNAME` 已设置且不为 'thirdparty'，则返回 `True`。
    * **与逆向方法的关系：** 在 CI 环境中，可能需要运行更全面的测试，包括一些耗时的或依赖特定环境的测试。在本地开发环境中，为了加快迭代速度，可能需要跳过某些测试。
    * **假设输入与输出：**
        * **输入：** 环境变量 `MESON_CI_JOBNAME` 设置为 'ubuntu-latest'
        * **输出：** `True`
        * **输入：** 环境变量 `MESON_CI_JOBNAME` 未设置
        * **输出：** `False`
* **`skip_if_not_base_option(feature)`:**  创建一个装饰器，用于跳过那些编译器不支持特定基础选项的测试。例如，某些编译器可能不支持 `-fsanitize` 选项。
    * **二进制底层知识：**  涉及到编译器的命令行选项，这些选项直接影响生成的二进制代码。例如，`-fsanitize=address` 启用地址消毒器，用于检测内存错误。
    * **假设输入与输出：**
        * 假设 ICC 编译器不支持 `b_sanitize` 选项。
        * **装饰器应用：** `@skip_if_not_base_option('b_sanitize')` 修饰一个测试函数。
        * **执行时：** 如果当前使用的编译器是 ICC，则该测试会被跳过。
* **`skipIfNoPkgconfig(f)`:** 创建一个装饰器，用于跳过那些需要 `pkg-config` 但当前环境中未安装的测试，除非当前处于 CI 环境。
    * **Linux 知识：** `pkg-config` 是 Linux 系统中用于获取库的编译和链接信息的工具。逆向分析时，理解目标程序依赖哪些库以及如何链接它们非常重要。
    * **假设输入与输出：**
        * **输入：**  非 CI 环境，且系统中未安装 `pkg-config`。
        * **被装饰的测试函数执行时：** 抛出 `unittest.SkipTest('pkg-config not found')` 异常。
* **`skipIfNoPkgconfigDep(depname)`:** 创建一个装饰器，用于跳过那些需要特定 `pkg-config` 依赖项但未找到的测试，除非当前处于 CI 环境。
    * **Linux 知识：** 进一步细化了对 `pkg-config` 依赖项的检查，确保测试环境满足特定库的要求。
    * **假设输入与输出：**
        * **输入：** 非 CI 环境，已安装 `pkg-config`，但系统中未找到名为 'glib-2.0' 的依赖项。
        * **被装饰的测试函数执行时：** 抛出 `unittest.SkipTest('pkg-config dependency glib-2.0 not found.')` 异常。
* **`skip_if_no_cmake(f)`:** 创建一个装饰器，用于跳过那些需要 `cmake` 但当前环境中未安装的测试，除非当前处于 CI 环境。
    * **构建系统知识：** `cmake` 是一个跨平台的构建系统生成器。一些项目可能使用 `cmake` 来管理编译过程。
    * **假设输入与输出：**
        * **输入：** 非 CI 环境，且系统中未安装 `cmake`。
        * **被装饰的测试函数执行时：** 抛出 `unittest.SkipTest('cmake not found')` 异常。
* **`skip_if_not_language(lang)`:** 创建一个装饰器，用于跳过那些需要特定编程语言编译器但未找到的测试。
    * **编程语言知识：** 确保运行测试的机器上安装了所需的编译器（例如 C, C++）。
    * **假设输入与输出：**
        * **输入：** 系统中未安装 Go 语言的编译器。
        * **装饰器应用：** `@skip_if_not_language('go')` 修饰一个测试函数。
        * **执行时：** 抛出 `unittest.SkipTest('No go compiler found.')` 异常。
* **`skip_if_env_set(key)`:** 创建一个装饰器，用于跳过当特定环境变量被设置时运行的测试，除非当前处于 CI 环境。
    * **环境配置：**  某些测试可能依赖于特定的环境配置，或者在某些环境变量存在时会产生冲突。
    * **假设输入与输出：**
        * **输入：** 非 CI 环境，环境变量 `DEBUG_MODE` 被设置。
        * **装饰器应用：** `@skip_if_env_set('DEBUG_MODE')` 修饰一个测试函数。
        * **执行时：** 抛出 `unittest.SkipTest("Env var 'DEBUG_MODE' set, skipping")` 异常。
* **`skipIfNoExecutable(exename)`:** 创建一个装饰器，用于跳过当特定可执行文件未找到时运行的测试。
    * **系统工具依赖：**  某些测试可能依赖于特定的系统工具。
    * **假设输入与输出：**
        * **输入：** 系统中未安装 `adb` (Android Debug Bridge)。
        * **装饰器应用：** `@skipIfNoExecutable('adb')` 修饰一个测试函数。
        * **执行时：** 抛出 `unittest.SkipTest('adb not found')` 异常。

**2. 环境操作:**

* **`chdir(path)`:**  一个上下文管理器，用于临时改变当前工作目录。在 `with` 语句块结束后，会自动恢复到原来的目录。
    * **文件系统操作：**  在测试中，可能需要在特定的目录下执行命令或操作文件。
    * **假设输入与输出：**
        * **输入：** `path` 为 '/tmp'。
        * **执行 `with chdir('/tmp'):` 语句块时：** 当前工作目录被切换到 `/tmp`。
        * **语句块结束后：** 恢复到执行 `with` 语句之前的目录。
* **`is_tarball()`:** 判断当前代码是否是从 tarball 包解压出来的。如果当前目录下不存在 `docs` 目录，则认为是 tarball 解压环境。
    * **构建和发布流程：**  了解代码的来源可以帮助区分不同的测试场景。

**3. 二进制文件分析:**

* **`get_dynamic_section_entry(fname, entry)`:**  从 ELF 文件的动态链接段中获取指定条目的值。
    * **逆向方法：** 动态链接段包含了共享库的依赖信息、加载路径等重要信息。逆向工程师经常分析这个段来了解程序的依赖关系。
    * **二进制底层知识，Linux 知识：**  涉及到 ELF 文件格式，这是 Linux 等系统上可执行文件和共享库的标准格式。
    * **系统工具依赖：**  依赖于 `readelf` 工具。
    * **假设输入与输出：**
        * **输入：** `fname` 为 `/bin/ls`，`entry` 为 'NEEDED'。
        * **输出：**  `/bin/ls` 依赖的共享库列表，例如 'libc.so.6'。
* **`get_soname(fname)`:** 获取 ELF 共享库文件的 SONAME (Shared Object Name)。
    * **逆向方法：** SONAME 是共享库的一个重要标识符，用于动态链接器在运行时查找和加载库。
    * **二进制底层知识，Linux 知识：**  涉及到 ELF 文件格式中 SONAME 的概念。
    * **假设输入与输出：**
        * **输入：** `fname` 为 `/lib/x86_64-linux-gnu/libc.so.6`。
        * **输出：** 'libc.so.6'。
* **`get_rpath(fname)`:** 获取 ELF 可执行文件或共享库的 RPATH (Run-time search path) 或 RUNPATH。
    * **逆向方法：** RPATH 和 RUNPATH 指定了动态链接器在哪些目录下查找共享库。理解这些路径对于分析程序的加载行为至关重要。
    * **二进制底层知识，Linux 知识：** 涉及到 ELF 文件格式中 RPATH 和 RUNPATH 的概念。
    * **假设输入与输出：**
        * **输入：** `fname` 为一个设置了 RPATH 的可执行文件。
        * **输出：**  可执行文件中指定的 RPATH 路径列表，例如 '/opt/mylibs:/usr/local/mylibs'。
* **`get_classpath(fname)`:**  从 Java 的 JAR 文件中获取 Class-Path 属性。
    * **逆向方法：** 对于 Java 应用，Class-Path 指定了依赖的 JAR 文件路径。逆向分析 Java 应用时，需要了解其依赖关系。
    * **假设输入与输出：**
        * **输入：** `fname` 为一个包含 `META-INF/MANIFEST.MF` 文件的 JAR 包。
        * **输出：**  JAR 包 `MANIFEST.MF` 文件中定义的 Class-Path 值，例如 'lib/dependency1.jar lib/dependency2.jar'。

**4. 路径操作:**

* **`get_path_without_cmd(cmd, path)`:** 从给定的 `path` 环境变量中移除包含指定命令 `cmd` 的目录。
    * **环境变量操作：** 用于清理 `PATH` 环境变量，可能在测试中需要隔离某些命令的影响。
    * **假设输入与输出：**
        * **输入：** `cmd` 为 'frida'，`path` 为 '/usr/bin:/usr/local/bin:/opt/frida/bin'，假设系统中 `frida` 可执行文件位于 `/opt/frida/bin`。
        * **输出：** '/usr/bin:/usr/local/bin'。

**5. 测试结果处理:**

* **`xfail_if_jobname(name)`:**  创建一个装饰器，用于标记在特定 CI 任务名称下运行的测试为预期失败 (expected failure)。
    * **持续集成：**  在 CI 环境中，某些测试可能已知会失败，但仍然希望运行它们并记录结果。

**与逆向方法的关系总结：**

这个文件中的一些函数直接服务于对二进制文件的分析，这与逆向工程密切相关：

* **分析 ELF 文件:** `get_dynamic_section_entry`, `get_soname`, `get_rpath` 这些函数帮助提取 ELF 文件中的关键信息，例如依赖的共享库和加载路径，这对于理解程序的运行时行为至关重要。
* **分析 Java 应用:** `get_classpath` 帮助理解 Java 应用的依赖关系，这在逆向 Java 应用时非常有用。
* **环境准备:** 跳过测试的函数可以确保测试在合适的条件下运行，避免因缺少依赖或环境不匹配而导致的误报。

**涉及到二进制底层，linux, android内核及框架的知识的举例说明：**

* **ELF 文件格式:** `get_dynamic_section_entry`, `get_soname`, `get_rpath` 这些函数直接操作 ELF 文件结构，需要了解 ELF 的动态链接段的组织方式和相关条目的含义。
* **动态链接:**  理解共享库的加载机制，包括 SONAME, RPATH, RUNPATH 的作用，对于理解这些函数的功能至关重要。
* **`pkg-config`:**  `skipIfNoPkgconfig` 和 `skipIfNoPkgconfigDep` 涉及到 `pkg-config` 工具的使用，需要了解其在 Linux 系统中管理库依赖的作用。
* **系统调用 (间接):** 虽然代码中没有直接的系统调用，但 `subprocess.check_output` 调用了 `readelf` 工具，而 `readelf` 内部会读取和解析二进制文件，这涉及到操作系统对文件系统的访问。
* **环境变量:** `is_ci`, `skip_if_env_set` 等函数涉及到环境变量的读取和判断，环境变量在 Linux 系统中用于配置进程的行为。

**如果做了逻辑推理，请给出假设输入与输出:**

上述每个函数的功能描述中，都尽可能地给出了假设输入和输出的例子。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **错误地使用了跳过装饰器：**  例如，一个测试实际上不需要 `pkg-config`，但错误地使用了 `@skipIfNoPkgconfig` 装饰器，导致在没有 `pkg-config` 的环境下该测试被不必要地跳过。
* **忘记安装必要的依赖：**  开发者在本地运行测试时，如果没有安装 `cmake` 或 `pkg-config` 等工具，可能会看到很多测试被跳过，这可能会让他们困惑，除非他们理解这些跳过装饰器的作用。
* **环境变量冲突：**  如果开发者在本地设置了某些环境变量，而这些环境变量与测试的假设环境不符，可能会导致使用了 `skip_if_env_set` 的测试被意外跳过。
* **路径问题：**  在使用 `chdir` 上下文管理器时，如果提供的路径不存在或无法访问，可能会导致异常。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **开发者编写或修改了一个 `frida-qml` 的单元测试。** 这个测试可能依赖于某些特定的工具、库或环境配置。
2. **开发者运行 `frida-qml` 的测试套件。** 这通常会使用 Meson 构建系统提供的命令，例如 `meson test` 或 `ninja test`。
3. **Meson 执行测试。** 在执行某个测试之前，测试框架会检查该测试是否被任何装饰器修饰。
4. **如果测试函数被 `skipIfNoPkgconfig` 或其他 `skipIf...` 装饰器修饰，框架会执行相应的检查。** 例如，如果测试被 `@skipIfNoPkgconfig` 修饰，`shutil.which('pkg-config')` 会被调用来检查 `pkg-config` 是否在系统的 `PATH` 中。
5. **如果检查条件不满足（例如，`pkg-config` 未找到），则抛出 `unittest.SkipTest` 异常。**
6. **单元测试框架捕获到这个异常，并记录该测试被跳过。**
7. **在测试结果中，开发者会看到该测试被标记为 "skipped"。**
8. **如果开发者想了解为什么测试被跳过，他们可能会查看测试代码，发现使用了 `skipIfNoPkgconfig` 装饰器。**
9. **为了进一步调试，开发者可能会查看 `frida/subprojects/frida-qml/releng/meson/unittests/helpers.py` 文件中的 `skipIfNoPkgconfig` 函数的实现，了解其跳过测试的逻辑。** 他们会看到 `shutil.which('pkg-config') is None` 是判断是否跳过的关键条件。
10. **开发者可能会检查自己的系统，确认是否安装了 `pkg-config`，以及是否将其路径添加到了 `PATH` 环境变量中。**

总而言之，`helpers.py` 文件提供了一组用于增强 `frida-qml` 单元测试的实用工具，特别是用于管理测试环境和跳过不满足前提条件的测试。它在确保测试的可靠性和减少不必要的错误方面发挥着重要作用。 其中部分功能与逆向工程中对二进制文件的分析和理解程序运行环境的需求紧密相关。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/helpers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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