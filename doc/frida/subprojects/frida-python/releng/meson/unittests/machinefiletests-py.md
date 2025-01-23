Response:
The user wants a summary of the functionality of the provided Python code. The code appears to be a unit test file for the Meson build system, specifically testing the behavior of "native files" and "cross files". These files are used to configure Meson's build process.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Purpose:** The file is named `machinefiletests.py` and resides within a `unittests` directory. This immediately suggests its purpose is to test the functionality related to "machine files" in Meson. The comments in the code further confirm this by mentioning "native files" and "cross files".

2. **Understand "Native Files":** The code creates temporary files (`helper_create_native_file`) and manipulates environment variables. The tests seem to focus on how Meson behaves when these files specify compiler locations, build options, and other configurations. The key takeaway is that native files configure the build for the *host* machine.

3. **Understand "Cross Files":** The `CrossFileTests` class and its methods (`_cross_file_generator`, `test_needs_exe_wrapper_true`, etc.) indicate that cross files are about building for a *target* machine that is different from the host. The tests involve concepts like `exe_wrapper`, which is used when the target architecture cannot directly run host executables.

4. **Analyze Key Functions and Methods:**
    * `setUp`:  Initializes the test environment.
    * `helper_create_native_file`:  Creates temporary native configuration files.
    * `helper_create_binary_wrapper`: Creates wrapper scripts around binaries, useful for mocking and testing different binary behaviors.
    * `helper_for_compiler`:  A helper for testing compiler overrides.
    * `test_*`:  Individual test methods covering various scenarios (finding programs, setting compiler options, handling user options, etc.).
    * `CrossFileTests`:  A separate test suite specifically for cross-compilation scenarios.

5. **Connect to Reverse Engineering (if applicable):** The code manipulates compilers and build processes. In reverse engineering, understanding how software is built and the tools used (compilers, linkers) is crucial. The ability to override compiler settings (demonstrated by the tests) is relevant when analyzing how different compiler flags might affect the generated binary. The `exe_wrapper` concept is directly related to reverse engineering scenarios where the target system cannot directly execute analysis tools.

6. **Connect to Binary/Kernel/Framework Knowledge (if applicable):** The tests involve finding programs (`find_program`), working with different compilers (C, C++, Python, etc.), and dealing with platform-specific issues (Windows `.bat` files, POSIX permissions). This touches upon knowledge of operating systems, compilers, and how executables are invoked. The mention of `pkg-config` relates to how libraries are located and linked, which is a core part of understanding binary dependencies.

7. **Look for Logic and Assumptions:** The tests often make assumptions about the availability of certain tools (`gcc`, `clang`, `python`). The input is the configuration provided through the native or cross files, and the output is Meson's behavior (successfully configuring the build, throwing errors, etc.). The wrapper scripts introduce logic to simulate different binary outputs.

8. **Identify Potential User Errors:** The tests for user options demonstrate how incorrect configuration in native files can lead to errors during Meson's setup. For example, providing the wrong type or value for a project option.

9. **Trace User Steps to Reach the Code:** A developer working on Frida's Python bindings might be adding new features or fixing bugs related to how Meson handles build configurations. They would be writing unit tests to ensure the correctness of their changes. The path `frida/subprojects/frida-python/releng/meson/unittests/machinefiletests.py` suggests this file is specifically for testing the Meson integration within the Frida Python project's release engineering setup.

10. **Synthesize the Summary:** Combine the observations from the previous steps to create a concise summary of the file's functionality. Focus on the key concepts of native files and cross files, their purpose, and the types of scenarios being tested. Highlight any connections to reverse engineering and lower-level system knowledge.

By following these steps, the generated answer accurately captures the essence of the provided Python code and its role within the Frida project's testing framework.
这是frida动态 instrumentation tool的源代码文件，专门用于测试 Meson 构建系统中关于**机器配置文件 (machine files)** 的功能。具体来说，它主要测试了两种类型的机器配置文件：**原生文件 (native files)** 和 **交叉编译文件 (cross files)**。

**功能归纳:**

该文件的主要功能是验证 Meson 构建系统在处理机器配置文件时的行为是否符合预期。它通过创建各种场景，模拟用户提供的不同机器配置文件，并断言 Meson 的处理结果是否正确。

**更细致的功能点包括:**

* **原生文件测试 (NativeFileTests):**
    * **查找程序 (find_program):** 测试通过原生文件指定可执行文件的路径，Meson 是否能正确找到它们。
    * **配置工具依赖 (config_tool_dep):** 测试通过原生文件指定配置工具（如 llvm-config）的路径，Meson 是否能正确识别并使用。
    * **Python 模块 (python3_module, python_module):** 测试通过原生文件指定 Python 解释器路径，Meson 是否能正确找到并使用。
    * **编译器指定 (c_compiler, cpp_compiler 等):** 测试通过原生文件覆盖默认编译器，Meson 是否能正确切换并使用指定的编译器。涵盖了 C, C++, Objective-C, Objective-C++, D, C#, Fortran, Vala, Rust, Java, Swift 等多种语言。
    * **编译器版本检测:** 测试通过模拟编译器输出，验证 Meson 能否正确解析编译器版本信息。
    * **原生文件路径 (native_file_dirs):** 测试通过命令行参数 `--native-file` 指定原生文件路径的功能。
    * **用户选项 (user_options):** 测试通过原生文件设置项目自定义选项的功能，并验证命令行参数的优先级高于原生文件。
    * **内置选项 (builtin_options):** 测试通过原生文件设置 Meson 内置选项（如 `cpp_std`, `default_library`）的功能，包括对主项目和子项目的选项设置。
    * **路径选项 (builtin_options_paths):** 测试通过原生文件设置路径相关的内置选项（如 `bindir`）。
    * **编译参数 (builtin_options_compiler_properties):** 测试通过原生文件设置编译器的特定参数（如 `c_args`）。
    * **Bindgen Clang 参数 (bindgen_clang_arguments):**  针对 Rust 项目，测试通过原生文件设置 `bindgen_clang_arguments` 的功能。

* **交叉编译文件测试 (CrossFileTests):**
    * **`needs_exe_wrapper` 属性:** 测试交叉编译配置文件中 `needs_exe_wrapper` 属性的作用，该属性指示是否需要一个主机上的可执行文件包装器来运行目标平台的程序。
    * **`exe_wrapper` 属性:** 测试交叉编译配置文件中 `exe_wrapper` 属性的作用，指定主机上的可执行文件包装器的路径。
    * **模拟交叉编译环境:** 通过创建临时的交叉编译配置文件，模拟不同的目标平台环境。
    * **测试跳过:** 验证当 `needs_exe_wrapper` 为 `True` 且没有提供 `exe_wrapper` 时，相关的测试会被跳过。

**与逆向方法的关系 (举例说明):**

* **编译器覆盖:** 在逆向工程中，我们可能需要使用特定版本的编译器或者带有特定补丁的编译器来重新编译目标程序，以便更好地理解其行为或引入特定的调试信息。这个测试文件中通过原生文件指定编译器的功能，模拟了这种场景。例如，我们可以创建一个原生文件，指定一个带有特定调试符号输出格式的 GCC 版本，然后使用 Meson 构建目标程序。
* **模拟目标环境:**  在进行动态分析或 Fuzzing 时，可能需要在与目标程序运行环境相似的环境中进行。交叉编译文件的测试模拟了这种场景，可以用来测试 Frida 在交叉编译环境下是否能正确构建和运行。例如，我们可以创建一个交叉编译配置文件，指定目标平台的架构和操作系统，然后使用 Meson 构建 Frida Agent。

**涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

* **可执行文件查找:** `test_find_program` 测试涉及到操作系统如何查找可执行文件（通过 PATH 环境变量等）。这与理解程序执行的底层机制相关。
* **编译器调用:**  测试文件中涉及到各种编译器的调用（gcc, clang, rustc 等），这需要了解编译器的命令行参数和工作原理。在逆向工程中，理解编译器如何将源代码转换为二进制代码是至关重要的。
* **平台差异:**  代码中使用了 `is_windows()`, `is_osx()`, `is_linux()` 等函数来处理不同操作系统之间的差异，例如在 Windows 上使用 `.bat` 文件作为包装器。这体现了对不同操作系统底层机制的了解。
* **交叉编译概念:** `CrossFileTests` 涉及交叉编译的核心概念，即在一个平台上构建在另一个平台上运行的程序。这需要对不同架构的二进制格式、调用约定等有深入的理解。
* **`pkg-config`:**  `test_config_tool_dep` 测试使用了 `pkg-config`，这是一个用于检索已安装库的编译 flags 的工具。理解 `pkg-config` 的工作原理对于理解程序如何链接外部库至关重要。

**逻辑推理 (假设输入与输出):**

* **假设输入 (原生文件):**
  ```ini
  [binaries]
  bash = '/usr/local/bin/mybash'
  ```
  **假设输入 (Meson 命令):**
  ```bash
  meson setup builddir --native-file my_native_file.ini -Dcase=find_program
  ```
  **假设输出:** Meson 在查找 `bash` 命令时，会优先使用 `/usr/local/bin/mybash`，而不是系统默认的 `bash`。测试代码会断言 Meson 的行为符合此预期。

* **假设输入 (交叉编译文件):**
  ```ini
  [binaries]
  c = '/opt/cross-tools/bin/arm-linux-gnueabi-gcc'

  [host_machine]
  system = 'linux'
  cpu_family = 'arm'
  cpu = 'armv7l'
  endian = 'little'
  ```
  **假设输入 (Meson 命令):**
  ```bash
  meson setup builddir --cross-file my_cross_file.ini
  ```
  **假设输出:** Meson 会将目标平台的编译器设置为 `/opt/cross-tools/bin/arm-linux-gnueabi-gcc`，并且目标机器的架构信息会被设置为 ARM。

**用户或编程常见的使用错误 (举例说明):**

* **原生文件中配置错误的用户选项:** 如果用户在原生文件中为项目选项设置了错误的值（例如，一个布尔选项设置为字符串 "yes"），测试代码会捕获 Meson 抛出的错误，并验证错误信息是否符合预期。例如 `test_user_options` 方法就测试了这种情况。
* **交叉编译时缺少 `exe_wrapper`:** 如果一个交叉编译的场景需要运行目标平台的程序 (`needs_exe_wrapper = true`)，但用户没有在交叉编译配置文件中提供 `exe_wrapper`，相关的测试将会被跳过或报错。`test_needs_exe_wrapper_true` 和 `test_cross_exe_passed_no_wrapper` 方法测试了这种情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Frida 开发者修改了与 Meson 构建集成相关的代码。** 例如，他们可能修改了 Meson 如何解析原生文件或交叉编译文件的逻辑。
2. **为了确保修改的正确性，开发者编写或修改了相应的单元测试。** 这个 `machinefiletests.py` 文件就是这类单元测试的集合。
3. **开发者运行 Meson 的测试套件。**  这通常通过执行类似 `meson test` 或特定的测试命令来实现。
4. **如果测试失败，开发者会查看失败的测试用例。** 例如，如果 `test_find_program` 失败，开发者会检查 `self.testcase` 对应的测试项目，以及 `helper_create_native_file` 创建的临时原生文件的内容，来定位问题。
5. **开发者会检查测试用例中使用的断言 (例如 `self.assertEqual`)。**  这些断言指明了预期的行为和实际的行为之间的差异，从而帮助开发者理解 bug 的根源。
6. **通过分析测试代码和失败信息，开发者可以逐步回溯到他们修改的代码，找到导致测试失败的原因并进行修复。**

总而言之，`machinefiletests.py` 是 Frida 项目中用于测试 Meson 构建系统处理机器配置文件功能的重要组成部分，它覆盖了各种使用场景，并能帮助开发者在开发过程中及时发现和修复与构建配置相关的错误。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/unittests/machinefiletests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2021 The Meson development team

from __future__ import annotations

import subprocess
import tempfile
import textwrap
import os
import shutil
import functools
import threading
import sys
from itertools import chain
from unittest import mock, skipIf, SkipTest
from pathlib import Path
import typing as T

import mesonbuild.mlog
import mesonbuild.depfile
import mesonbuild.dependencies.factory
import mesonbuild.envconfig
import mesonbuild.environment
import mesonbuild.coredata
import mesonbuild.modules.gnome
from mesonbuild.mesonlib import (
    MachineChoice, is_windows, is_osx, is_cygwin, is_haiku, is_sunos
)
from mesonbuild.compilers import (
    detect_swift_compiler, compiler_from_language
)
import mesonbuild.modules.pkgconfig


from run_tests import (
    Backend,
    get_fake_env
)

from .baseplatformtests import BasePlatformTests
from .helpers import *

@functools.lru_cache()
def is_real_gnu_compiler(path):
    '''
    Check if the gcc we have is a real gcc and not a macOS wrapper around clang
    '''
    if not path:
        return False
    out = subprocess.check_output([path, '--version'], universal_newlines=True, stderr=subprocess.STDOUT)
    return 'Free Software Foundation' in out

class NativeFileTests(BasePlatformTests):

    def setUp(self):
        super().setUp()
        self.testcase = os.path.join(self.unit_test_dir, '46 native file binary')
        self.current_config = 0
        self.current_wrapper = 0

    def helper_create_native_file(self, values: T.Dict[str, T.Dict[str, T.Union[str, int, float, bool, T.Sequence[T.Union[str, int, float, bool]]]]]) -> str:
        """Create a config file as a temporary file.

        values should be a nested dictionary structure of {section: {key:
        value}}
        """
        filename = os.path.join(self.builddir, f'generated{self.current_config}.config')
        self.current_config += 1
        with open(filename, 'wt', encoding='utf-8') as f:
            for section, entries in values.items():
                f.write(f'[{section}]\n')
                for k, v in entries.items():
                    if isinstance(v, (bool, int, float)):
                        f.write(f"{k}={v}\n")
                    elif isinstance(v, str):
                        f.write(f"{k}='{v}'\n")
                    else:
                        f.write("{}=[{}]\n".format(k, ', '.join([f"'{w}'" for w in v])))
        return filename

    def helper_create_binary_wrapper(self, binary, dir_=None, extra_args=None, **kwargs):
        """Creates a wrapper around a binary that overrides specific values."""
        filename = os.path.join(dir_ or self.builddir, f'binary_wrapper{self.current_wrapper}.py')
        extra_args = extra_args or {}
        self.current_wrapper += 1
        if is_haiku():
            chbang = '#!/bin/env python3'
        else:
            chbang = '#!/usr/bin/env python3'

        with open(filename, 'wt', encoding='utf-8') as f:
            f.write(textwrap.dedent('''\
                {}
                import argparse
                import subprocess
                import sys

                def main():
                    parser = argparse.ArgumentParser()
                '''.format(chbang)))
            for name in chain(extra_args, kwargs):
                f.write('    parser.add_argument("-{0}", "--{0}", action="store_true")\n'.format(name))
            f.write('    args, extra_args = parser.parse_known_args()\n')
            for name, value in chain(extra_args.items(), kwargs.items()):
                f.write(f'    if args.{name}:\n')
                f.write('        print("{}", file=sys.{})\n'.format(value, kwargs.get('outfile', 'stdout')))
                f.write('        sys.exit(0)\n')
            f.write(textwrap.dedent('''
                    ret = subprocess.run(
                        ["{}"] + extra_args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)
                    print(ret.stdout.decode('utf-8'))
                    print(ret.stderr.decode('utf-8'), file=sys.stderr)
                    sys.exit(ret.returncode)

                if __name__ == '__main__':
                    main()
                '''.format(binary)))

        if not is_windows():
            os.chmod(filename, 0o755)
            return filename

        # On windows we need yet another level of indirection, as cmd cannot
        # invoke python files itself, so instead we generate a .bat file, which
        # invokes our python wrapper
        batfile = os.path.join(self.builddir, f'binary_wrapper{self.current_wrapper}.bat')
        with open(batfile, 'wt', encoding='utf-8') as f:
            f.write(fr'@{sys.executable} {filename} %*')
        return batfile

    def helper_for_compiler(self, lang, cb, for_machine = MachineChoice.HOST):
        """Helper for generating tests for overriding compilers for languages
        with more than one implementation, such as C, C++, ObjC, ObjC++, and D.
        """
        env = get_fake_env()
        getter = lambda: compiler_from_language(env, lang, for_machine)
        cc = getter()
        binary, newid = cb(cc)
        env.binaries[for_machine].binaries[lang] = binary
        compiler = getter()
        self.assertEqual(compiler.id, newid)

    def test_multiple_native_files_override(self):
        wrapper = self.helper_create_binary_wrapper('bash', version='foo')
        config = self.helper_create_native_file({'binaries': {'bash': wrapper}})
        wrapper = self.helper_create_binary_wrapper('bash', version='12345')
        config2 = self.helper_create_native_file({'binaries': {'bash': wrapper}})
        self.init(self.testcase, extra_args=[
            '--native-file', config, '--native-file', config2,
            '-Dcase=find_program'])

    # This test hangs on cygwin.
    @skipIf(os.name != 'posix' or is_cygwin(), 'Uses fifos, which are not available on non Unix OSes.')
    def test_native_file_is_pipe(self):
        fifo = os.path.join(self.builddir, 'native.file')
        os.mkfifo(fifo)
        with tempfile.TemporaryDirectory() as d:
            wrapper = self.helper_create_binary_wrapper('bash', d, version='12345')

            def filler():
                with open(fifo, 'w', encoding='utf-8') as f:
                    f.write('[binaries]\n')
                    f.write(f"bash = '{wrapper}'\n")

            thread = threading.Thread(target=filler)
            thread.start()

            self.init(self.testcase, extra_args=['--native-file', fifo, '-Dcase=find_program'])

            thread.join()
            os.unlink(fifo)

            self.init(self.testcase, extra_args=['--wipe'])

    def test_multiple_native_files(self):
        wrapper = self.helper_create_binary_wrapper('bash', version='12345')
        config = self.helper_create_native_file({'binaries': {'bash': wrapper}})
        wrapper = self.helper_create_binary_wrapper('python')
        config2 = self.helper_create_native_file({'binaries': {'python': wrapper}})
        self.init(self.testcase, extra_args=[
            '--native-file', config, '--native-file', config2,
            '-Dcase=find_program'])

    def _simple_test(self, case, binary, entry=None):
        wrapper = self.helper_create_binary_wrapper(binary, version='12345')
        config = self.helper_create_native_file({'binaries': {entry or binary: wrapper}})
        self.init(self.testcase, extra_args=['--native-file', config, f'-Dcase={case}'])

    def test_find_program(self):
        self._simple_test('find_program', 'bash')

    def test_config_tool_dep(self):
        # Do the skip at this level to avoid screwing up the cache
        if mesonbuild.environment.detect_msys2_arch():
            raise SkipTest('Skipped due to problems with LLVM on MSYS2')
        if not shutil.which('llvm-config'):
            raise SkipTest('No llvm-installed, cannot test')
        self._simple_test('config_dep', 'llvm-config')

    def test_python3_module(self):
        self._simple_test('python3', 'python3')

    def test_python_module(self):
        if is_windows():
            # Bat adds extra crap to stdout, so the version check logic in the
            # python module breaks. This is fine on other OSes because they
            # don't need the extra indirection.
            raise SkipTest('bat indirection breaks internal sanity checks.')
        elif is_osx():
            binary = 'python'
        else:
            binary = 'python2'

            # We not have python2, check for it
            for v in ['2', '2.7', '-2.7']:
                try:
                    rc = subprocess.call(['pkg-config', '--cflags', f'python{v}'],
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
                except FileNotFoundError:
                    raise SkipTest('Not running Python 2 tests because pkg-config not found.')
                if rc == 0:
                    break
            else:
                raise SkipTest('Not running Python 2 tests because dev packages not installed.')
        self._simple_test('python', binary, entry='python')

    @skipIf(is_windows(), 'Setting up multiple compilers on windows is hard')
    @skip_if_env_set('CC')
    def test_c_compiler(self):
        def cb(comp):
            if comp.id == 'gcc':
                if not shutil.which('clang'):
                    raise SkipTest('Only one compiler found, cannot test.')
                return 'clang', 'clang'
            if not is_real_gnu_compiler(shutil.which('gcc')):
                raise SkipTest('Only one compiler found, cannot test.')
            return 'gcc', 'gcc'
        self.helper_for_compiler('c', cb)

    @skipIf(is_windows(), 'Setting up multiple compilers on windows is hard')
    @skip_if_env_set('CXX')
    def test_cpp_compiler(self):
        def cb(comp):
            if comp.id == 'gcc':
                if not shutil.which('clang++'):
                    raise SkipTest('Only one compiler found, cannot test.')
                return 'clang++', 'clang'
            if not is_real_gnu_compiler(shutil.which('g++')):
                raise SkipTest('Only one compiler found, cannot test.')
            return 'g++', 'gcc'
        self.helper_for_compiler('cpp', cb)

    @skip_if_not_language('objc')
    @skip_if_env_set('OBJC')
    def test_objc_compiler(self):
        def cb(comp):
            if comp.id == 'gcc':
                if not shutil.which('clang'):
                    raise SkipTest('Only one compiler found, cannot test.')
                return 'clang', 'clang'
            if not is_real_gnu_compiler(shutil.which('gcc')):
                raise SkipTest('Only one compiler found, cannot test.')
            return 'gcc', 'gcc'
        self.helper_for_compiler('objc', cb)

    @skip_if_not_language('objcpp')
    @skip_if_env_set('OBJCXX')
    def test_objcpp_compiler(self):
        def cb(comp):
            if comp.id == 'gcc':
                if not shutil.which('clang++'):
                    raise SkipTest('Only one compiler found, cannot test.')
                return 'clang++', 'clang'
            if not is_real_gnu_compiler(shutil.which('g++')):
                raise SkipTest('Only one compiler found, cannot test.')
            return 'g++', 'gcc'
        self.helper_for_compiler('objcpp', cb)

    @skip_if_not_language('d')
    @skip_if_env_set('DC')
    def test_d_compiler(self):
        def cb(comp):
            if comp.id == 'dmd':
                if shutil.which('ldc'):
                    return 'ldc', 'ldc'
                elif shutil.which('gdc'):
                    return 'gdc', 'gdc'
                else:
                    raise SkipTest('No alternative dlang compiler found.')
            if shutil.which('dmd'):
                return 'dmd', 'dmd'
            raise SkipTest('No alternative dlang compiler found.')
        self.helper_for_compiler('d', cb)

    @skip_if_not_language('cs')
    @skip_if_env_set('CSC')
    def test_cs_compiler(self):
        def cb(comp):
            if comp.id == 'csc':
                if not shutil.which('mcs'):
                    raise SkipTest('No alternate C# implementation.')
                return 'mcs', 'mcs'
            if not shutil.which('csc'):
                raise SkipTest('No alternate C# implementation.')
            return 'csc', 'csc'
        self.helper_for_compiler('cs', cb)

    @skip_if_not_language('fortran')
    @skip_if_env_set('FC')
    def test_fortran_compiler(self):
        def cb(comp):
            if comp.id == 'lcc':
                if shutil.which('lfortran'):
                    return 'lfortran', 'lcc'
                raise SkipTest('No alternate Fortran implementation.')
            elif comp.id == 'gcc':
                if shutil.which('ifort'):
                    # There is an ICC for windows (windows build, linux host),
                    # but we don't support that ATM so lets not worry about it.
                    if is_windows():
                        return 'ifort', 'intel-cl'
                    return 'ifort', 'intel'
                elif shutil.which('flang'):
                    return 'flang', 'flang'
                elif shutil.which('pgfortran'):
                    return 'pgfortran', 'pgi'
                # XXX: there are several other fortran compilers meson
                # supports, but I don't have any of them to test with
                raise SkipTest('No alternate Fortran implementation.')
            if not shutil.which('gfortran'):
                raise SkipTest('No alternate Fortran implementation.')
            return 'gfortran', 'gcc'
        self.helper_for_compiler('fortran', cb)

    def _single_implementation_compiler(self, lang: str, binary: str, version_str: str, version: str) -> None:
        """Helper for languages with a single (supported) implementation.

        Builds a wrapper around the compiler to override the version.
        """
        wrapper = self.helper_create_binary_wrapper(binary, version=version_str)
        env = get_fake_env()
        env.binaries.host.binaries[lang] = [wrapper]
        compiler = compiler_from_language(env, lang, MachineChoice.HOST)
        self.assertEqual(compiler.version, version)

    @skip_if_not_language('vala')
    @skip_if_env_set('VALAC')
    def test_vala_compiler(self):
        self._single_implementation_compiler(
            'vala', 'valac', 'Vala 1.2345', '1.2345')

    @skip_if_not_language('rust')
    @skip_if_env_set('RUSTC')
    def test_rust_compiler(self):
        self._single_implementation_compiler(
            'rust', 'rustc', 'rustc 1.2345', '1.2345')

    @skip_if_not_language('java')
    def test_java_compiler(self):
        self._single_implementation_compiler(
            'java', 'javac', 'javac 9.99.77', '9.99.77')

    @skip_if_not_language('java')
    def test_java_classpath(self):
        if self.backend is not Backend.ninja:
            raise SkipTest('Jar is only supported with Ninja')
        testdir = os.path.join(self.unit_test_dir, '112 classpath')
        self.init(testdir)
        self.build()
        one_build_path = get_classpath(os.path.join(self.builddir, 'one.jar'))
        self.assertIsNone(one_build_path)
        two_build_path = get_classpath(os.path.join(self.builddir, 'two.jar'))
        self.assertEqual(two_build_path, 'one.jar')
        self.install()
        one_install_path = get_classpath(os.path.join(self.installdir, 'usr/bin/one.jar'))
        self.assertIsNone(one_install_path)
        two_install_path = get_classpath(os.path.join(self.installdir, 'usr/bin/two.jar'))
        self.assertIsNone(two_install_path)

    @skip_if_not_language('swift')
    def test_swift_compiler(self):
        wrapper = self.helper_create_binary_wrapper(
            'swiftc', version='Swift 1.2345', outfile='stderr',
            extra_args={'Xlinker': 'macosx_version. PROJECT:ld - 1.2.3'})
        env = get_fake_env()
        env.binaries.host.binaries['swift'] = [wrapper]
        compiler = detect_swift_compiler(env, MachineChoice.HOST)
        self.assertEqual(compiler.version, '1.2345')

    def test_native_file_dirs(self):
        testcase = os.path.join(self.unit_test_dir, '59 native file override')
        self.init(testcase, default_args=False,
                  extra_args=['--native-file', os.path.join(testcase, 'nativefile')])

    def test_native_file_dirs_overridden(self):
        testcase = os.path.join(self.unit_test_dir, '59 native file override')
        self.init(testcase, default_args=False,
                  extra_args=['--native-file', os.path.join(testcase, 'nativefile'),
                              '-Ddef_libdir=liblib', '-Dlibdir=liblib'])

    def test_compile_sys_path(self):
        """Compiling with a native file stored in a system path works.

        There was a bug which caused the paths to be stored incorrectly and
        would result in ninja invoking meson in an infinite loop. This tests
        for that by actually invoking ninja.
        """
        testcase = os.path.join(self.common_test_dir, '1 trivial')

        # It really doesn't matter what's in the native file, just that it exists
        config = self.helper_create_native_file({'binaries': {'bash': 'false'}})

        self.init(testcase, extra_args=['--native-file', config])
        self.build()

    def test_user_options(self):
        testcase = os.path.join(self.common_test_dir, '40 options')
        for opt, value in [('testoption', 'some other val'), ('other_one', True),
                           ('combo_opt', 'one'), ('array_opt', ['two']),
                           ('integer_opt', 0),
                           ('CaseSenSiTivE', 'SOME other Value'),
                           ('CASESENSITIVE', 'some other Value')]:
            config = self.helper_create_native_file({'project options': {opt: value}})
            with self.assertRaises(subprocess.CalledProcessError) as cm:
                self.init(testcase, extra_args=['--native-file', config])
                self.assertRegex(cm.exception.stdout, r'Incorrect value to [a-z]+ option')

    def test_user_options_command_line_overrides(self):
        testcase = os.path.join(self.common_test_dir, '40 options')
        config = self.helper_create_native_file({'project options': {'other_one': True}})
        self.init(testcase, extra_args=['--native-file', config, '-Dother_one=false'])

    def test_user_options_subproject(self):
        testcase = os.path.join(self.unit_test_dir, '78 user options for subproject')

        s = os.path.join(testcase, 'subprojects')
        if not os.path.exists(s):
            os.mkdir(s)
        s = os.path.join(s, 'sub')
        if not os.path.exists(s):
            sub = os.path.join(self.common_test_dir, '40 options')
            shutil.copytree(sub, s)

        for opt, value in [('testoption', 'some other val'), ('other_one', True),
                           ('combo_opt', 'one'), ('array_opt', ['two']),
                           ('integer_opt', 0)]:
            config = self.helper_create_native_file({'sub:project options': {opt: value}})
            with self.assertRaises(subprocess.CalledProcessError) as cm:
                self.init(testcase, extra_args=['--native-file', config])
                self.assertRegex(cm.exception.stdout, r'Incorrect value to [a-z]+ option')

    def test_option_bool(self):
        # Bools are allowed to be unquoted
        testcase = os.path.join(self.common_test_dir, '1 trivial')
        config = self.helper_create_native_file({'built-in options': {'werror': True}})
        self.init(testcase, extra_args=['--native-file', config])
        configuration = self.introspect('--buildoptions')
        for each in configuration:
            # Test that no-per subproject options are inherited from the parent
            if 'werror' in each['name']:
                self.assertEqual(each['value'], True)
                break
        else:
            self.fail('Did not find werror in build options?')

    def test_option_integer(self):
        # Bools are allowed to be unquoted
        testcase = os.path.join(self.common_test_dir, '1 trivial')
        config = self.helper_create_native_file({'built-in options': {'unity_size': 100}})
        self.init(testcase, extra_args=['--native-file', config])
        configuration = self.introspect('--buildoptions')
        for each in configuration:
            # Test that no-per subproject options are inherited from the parent
            if 'unity_size' in each['name']:
                self.assertEqual(each['value'], 100)
                break
        else:
            self.fail('Did not find unity_size in build options?')

    def test_builtin_options(self):
        testcase = os.path.join(self.common_test_dir, '2 cpp')
        config = self.helper_create_native_file({'built-in options': {'cpp_std': 'c++14'}})

        self.init(testcase, extra_args=['--native-file', config])
        configuration = self.introspect('--buildoptions')
        for each in configuration:
            if each['name'] == 'cpp_std':
                self.assertEqual(each['value'], 'c++14')
                break
        else:
            self.fail('Did not find werror in build options?')

    def test_builtin_options_conf_overrides_env(self):
        testcase = os.path.join(self.common_test_dir, '2 cpp')
        config = self.helper_create_native_file({'built-in options': {'pkg_config_path': '/foo'}})

        self.init(testcase, extra_args=['--native-file', config], override_envvars={'PKG_CONFIG_PATH': '/bar'})
        configuration = self.introspect('--buildoptions')
        for each in configuration:
            if each['name'] == 'pkg_config_path':
                self.assertEqual(each['value'], ['/foo'])
                break
        else:
            self.fail('Did not find pkg_config_path in build options?')

    def test_builtin_options_subprojects(self):
        testcase = os.path.join(self.common_test_dir, '98 subproject subdir')
        config = self.helper_create_native_file({'built-in options': {'default_library': 'both', 'c_args': ['-Dfoo']}, 'sub:built-in options': {'default_library': 'static'}})

        self.init(testcase, extra_args=['--native-file', config])
        configuration = self.introspect('--buildoptions')
        found = 0
        for each in configuration:
            # Test that no-per subproject options are inherited from the parent
            if 'c_args' in each['name']:
                # This path will be hit twice, once for build and once for host,
                self.assertEqual(each['value'], ['-Dfoo'])
                found += 1
            elif each['name'] == 'default_library':
                self.assertEqual(each['value'], 'both')
                found += 1
            elif each['name'] == 'sub:default_library':
                self.assertEqual(each['value'], 'static')
                found += 1
        self.assertEqual(found, 4, 'Did not find all three sections')

    def test_builtin_options_subprojects_overrides_buildfiles(self):
        # If the buildfile says subproject(... default_library: shared), ensure that's overwritten
        testcase = os.path.join(self.common_test_dir, '223 persubproject options')
        config = self.helper_create_native_file({'sub2:built-in options': {'default_library': 'shared'}})

        with self.assertRaises((RuntimeError, subprocess.CalledProcessError)) as cm:
            self.init(testcase, extra_args=['--native-file', config])
            if isinstance(cm, RuntimeError):
                check = str(cm.exception)
            else:
                check = cm.exception.stdout
            self.assertIn(check, 'Parent should override default_library')

    def test_builtin_options_subprojects_dont_inherits_parent_override(self):
        # If the buildfile says subproject(... default_library: shared), ensure that's overwritten
        testcase = os.path.join(self.common_test_dir, '223 persubproject options')
        config = self.helper_create_native_file({'built-in options': {'default_library': 'both'}})
        self.init(testcase, extra_args=['--native-file', config])

    def test_builtin_options_compiler_properties(self):
        # the properties section can have lang_args, and those need to be
        # overwritten by the built-in options
        testcase = os.path.join(self.common_test_dir, '1 trivial')
        config = self.helper_create_native_file({
            'built-in options': {'c_args': ['-DFOO']},
            'properties': {'c_args': ['-DBAR']},
        })

        self.init(testcase, extra_args=['--native-file', config])
        configuration = self.introspect('--buildoptions')
        for each in configuration:
            if each['name'] == 'c_args':
                self.assertEqual(each['value'], ['-DFOO'])
                break
        else:
            self.fail('Did not find c_args in build options?')

    def test_builtin_options_compiler_properties_legacy(self):
        # The legacy placement in properties is still valid if a 'built-in
        # options' setting is present, but doesn't have the lang_args
        testcase = os.path.join(self.common_test_dir, '1 trivial')
        config = self.helper_create_native_file({
            'built-in options': {'default_library': 'static'},
            'properties': {'c_args': ['-DBAR']},
        })

        self.init(testcase, extra_args=['--native-file', config])
        configuration = self.introspect('--buildoptions')
        for each in configuration:
            if each['name'] == 'c_args':
                self.assertEqual(each['value'], ['-DBAR'])
                break
        else:
            self.fail('Did not find c_args in build options?')

    def test_builtin_options_paths(self):
        # the properties section can have lang_args, and those need to be
        # overwritten by the built-in options
        testcase = os.path.join(self.common_test_dir, '1 trivial')
        config = self.helper_create_native_file({
            'built-in options': {'bindir': 'foo'},
            'paths': {'bindir': 'bar'},
        })

        self.init(testcase, extra_args=['--native-file', config])
        configuration = self.introspect('--buildoptions')
        for each in configuration:
            if each['name'] == 'bindir':
                self.assertEqual(each['value'], 'foo')
                break
        else:
            self.fail('Did not find bindir in build options?')

    def test_builtin_options_paths_legacy(self):
        testcase = os.path.join(self.common_test_dir, '1 trivial')
        config = self.helper_create_native_file({
            'built-in options': {'default_library': 'static'},
            'paths': {'bindir': 'bar'},
        })

        self.init(testcase, extra_args=['--native-file', config])
        configuration = self.introspect('--buildoptions')
        for each in configuration:
            if each['name'] == 'bindir':
                self.assertEqual(each['value'], 'bar')
                break
        else:
            self.fail('Did not find bindir in build options?')

    @skip_if_not_language('rust')
    def test_bindgen_clang_arguments(self) -> None:
        if self.backend is not Backend.ninja:
            raise SkipTest('Rust is only supported with Ninja')

        testcase = os.path.join(self.rust_test_dir, '12 bindgen')
        config = self.helper_create_native_file({
            'properties': {'bindgen_clang_arguments': 'sentinal'}
        })

        self.init(testcase, extra_args=['--native-file', config])
        targets: T.List[T.Dict[str, T.Any]] = self.introspect('--targets')
        for t in targets:
            if t['id'].startswith('rustmod-bindgen'):
                args: T.List[str] = t['target_sources'][0]['compiler']
                self.assertIn('sentinal', args, msg="Did not find machine file value")
                cargs_start = args.index('--')
                sent_arg = args.index('sentinal')
                self.assertLess(cargs_start, sent_arg, msg='sentinal argument does not come after "--"')
                break
        else:
            self.fail('Did not find a bindgen target')


class CrossFileTests(BasePlatformTests):

    """Tests for cross file functionality not directly related to
    cross compiling.

    This is mainly aimed to testing overrides from cross files.
    """

    def setUp(self):
        super().setUp()
        self.current_config = 0
        self.current_wrapper = 0

    def _cross_file_generator(self, *, needs_exe_wrapper: bool = False,
                              exe_wrapper: T.Optional[T.List[str]] = None) -> str:
        if is_windows():
            raise SkipTest('Cannot run this test on non-mingw/non-cygwin windows')

        return textwrap.dedent(f"""\
            [binaries]
            c = '{shutil.which('gcc' if is_sunos() else 'cc')}'
            ar = '{shutil.which('ar')}'
            strip = '{shutil.which('strip')}'
            exe_wrapper = {str(exe_wrapper) if exe_wrapper is not None else '[]'}

            [properties]
            needs_exe_wrapper = {needs_exe_wrapper}

            [host_machine]
            system = 'linux'
            cpu_family = 'x86'
            cpu = 'i686'
            endian = 'little'
            """)

    def _stub_exe_wrapper(self) -> str:
        return textwrap.dedent('''\
            #!/usr/bin/env python3
            import subprocess
            import sys

            sys.exit(subprocess.run(sys.argv[1:]).returncode)
            ''')

    def test_needs_exe_wrapper_true(self):
        testdir = os.path.join(self.unit_test_dir, '70 cross test passed')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'crossfile'
            with p.open('wt', encoding='utf-8') as f:
                f.write(self._cross_file_generator(needs_exe_wrapper=True))
            self.init(testdir, extra_args=['--cross-file=' + str(p)])
            out = self.run_target('test')
            self.assertRegex(out, r'Skipped:\s*1\s*\n')

    def test_needs_exe_wrapper_false(self):
        testdir = os.path.join(self.unit_test_dir, '70 cross test passed')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'crossfile'
            with p.open('wt', encoding='utf-8') as f:
                f.write(self._cross_file_generator(needs_exe_wrapper=False))
            self.init(testdir, extra_args=['--cross-file=' + str(p)])
            out = self.run_target('test')
            self.assertNotRegex(out, r'Skipped:\s*1\n')

    def test_needs_exe_wrapper_true_wrapper(self):
        testdir = os.path.join(self.unit_test_dir, '70 cross test passed')
        with tempfile.TemporaryDirectory() as d:
            s = Path(d) / 'wrapper.py'
            with s.open('wt', encoding='utf-8') as f:
                f.write(self._stub_exe_wrapper())
            s.chmod(0o774)
            p = Path(d) / 'crossfile'
            with p.open('wt', encoding='utf-8') as f:
                f.write(self._cross_file_generator(
                    needs_exe_wrapper=True,
                    exe_wrapper=[str(s)]))

            self.init(testdir, extra_args=['--cross-file=' + str(p), '-Dexpect=true'])
            out = self.run_target('test')
            self.assertRegex(out, r'Ok:\s*3\s*\n')

    def test_cross_exe_passed_no_wrapper(self):
        testdir = os.path.join(self.unit_test_dir, '70 cross test passed')
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'crossfile'
            with p.open('wt', encoding='utf-8') as f:
                f.write(self._cross_file_generator(needs_exe_wrapper=True))

            self.init(testdir, extra_args=['--cross-file=' + str(p)])
            self.build()
            out = self.run_target('test')
            self.assertRegex(out, r'Skipped:\s*1\s*\n')

    # The test uses mocking and thus requires that the current process is the
    # one to run the Meson steps. If we are using an external test executable
    # (most commonly in Debian autopkgtests) then the mocking won't work.
    @skipIf('MESON_EXE' in os.environ, 'MESON_EXE is defined, cannot use mocking.')
    def test_cross_file_system_paths(self):
        if is_windows():
            raise SkipTest('system crossfile paths not defined for Windows (yet)')

        testdir = os.path.join(self.common_test_dir, '1 trivial')
        cross_content = self._cross_file_generator()
        with tempfile.TemporaryDirectory() as d:
            dir_ = os.path.join(d, 'meson', 'cross')
            os.makedirs(dir_)
            with tempfile.NamedTemporaryFile('w', dir=dir_, delete=False, encoding='utf-8') as f:
                f.write(cross_content)
```