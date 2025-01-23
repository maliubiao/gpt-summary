Response:
The user wants me to analyze a Python file that is part of the Frida dynamic instrumentation tool.
Specifically, this file seems to be related to testing the functionality of "machine files" in the Meson build system, which Frida uses.

Here's a breakdown of the functionalities I need to extract:

1. **Core Functionality:** What does this Python file do in the context of Frida and its build process?
2. **Relationship to Reverse Engineering:** How does this file's functionality relate to the techniques used in reverse engineering?
3. **Low-Level Interactions:** Does this file interact with low-level aspects like the Linux/Android kernel or frameworks?
4. **Logical Reasoning:** Are there any test cases that involve specific inputs and expected outputs?
5. **Common User Errors:** Does this file test or highlight any common mistakes users might make when using Frida or Meson?
6. **User Journey:** How does a user's action eventually lead to the execution of code within this file?
7. **Summary:** A concise overview of the file's purpose.

**Mental Sandbox:**

* **Machine Files in Meson:**  I know Meson uses "machine files" (native and cross files) to define the build environment, including compilers, tools, and target architectures. This file likely tests how Meson handles these files.
* **Frida and Dynamic Instrumentation:** Frida is used to inspect and modify the behavior of running processes. While this test file focuses on the build system, I need to think about how the build process relates to the eventual instrumentation capabilities of Frida.
* **Test Cases:** The file contains numerous functions starting with `test_`. These are individual test cases designed to verify specific aspects of machine file handling.
* **Helper Functions:** Functions like `helper_create_native_file` and `helper_create_binary_wrapper` are clearly utilities for setting up test environments.
* **Focus on Toolchain:** Many tests involve checking compiler detection and overriding. This is fundamental for both native and cross-compilation scenarios.

**Constraint Checklist & Confidence Score:**

1. List the file's functionalities: Yes.
2. Relation to reverse engineering: Yes (requires careful consideration of the link between build tools and instrumentation).
3. Binary/kernel knowledge: Yes (need to identify tests involving compiler behavior and target specifics).
4. Logical reasoning (input/output): Yes (test functions provide input and assert expected behavior).
5. User/programming errors: Yes (tests might implicitly cover incorrect configurations).
6. User journey: Yes (needs to connect user actions to Meson's testing process).
7. Summarize functionality: Yes.

Confidence Score: 4/5 (Slight uncertainty in directly linking build system tests to specific reverse engineering *methods*, but I can make reasonable connections).

**Strategizing the Response:**

I'll structure the response by addressing each of the user's points directly. For the reverse engineering aspect, I'll focus on how configuring the build environment (which this file tests) is crucial for targeting specific architectures or environments that are often the subject of reverse engineering. For low-level interactions, I'll highlight tests that involve compiler flags, target architectures, and cross-compilation settings. The test functions themselves will provide the basis for illustrating logical reasoning. I'll consider how incorrect machine file configurations or command-line arguments could represent common user errors. Finally, I'll describe the typical developer workflow that leads to these tests being run.

Strategizing complete. I will now proceed with generating the response.

这是 `frida/subprojects/frida-gum/releng/meson/unittests/machinefiletests.py` 文件的第一部分，主要功能是**测试 Meson 构建系统中对机器配置文件的处理能力**。这些机器配置文件（包括原生配置文件和交叉编译配置文件）用于指定构建环境的各种参数，例如编译器路径、工具链、构建选项等。

下面根据你的要求，对这部分代码的功能进行详细分析：

**1. 功能列举:**

* **创建和解析原生配置文件:**  `helper_create_native_file` 函数用于创建临时的原生配置文件，该文件采用 INI 格式，可以定义各种构建参数，例如编译器路径、工具程序路径等。测试用例会创建不同的原生配置文件，并用 Meson 进行初始化，验证 Meson 是否能正确解析这些文件并应用其中的配置。
* **创建二进制包装器 (Wrapper):** `helper_create_binary_wrapper` 函数用于创建一个 Python 脚本，作为对实际二进制程序的包装。这个包装器可以模拟不同版本的二进制程序，或者在调用实际程序前后执行一些额外的操作。这在测试 Meson 如何处理不同版本的工具链或特定工具的行为时非常有用。
* **测试 `find_program` 功能:**  测试 Meson 的 `find_program` 功能是否能正确地从原生配置文件中指定的路径找到程序。例如，测试用例 `test_find_program` 通过创建一个指定 `bash` 路径的原生配置文件来验证这一功能。
* **测试依赖查找 (Config Tool Dependency):** 测试 Meson 如何处理通过配置文件指定的依赖关系，例如 `llvm-config`。测试用例 `test_config_tool_dep` 验证了这一点。
* **测试 Python 模块查找:** 测试 Meson 如何查找 Python 解释器以及处理相关的配置。 `test_python3_module` 和 `test_python_module` 就是用于测试这个的。
* **测试编译器切换:**  测试 Meson 是否能根据原生配置文件的指示，切换到不同的编译器。例如，`test_c_compiler`、`test_cpp_compiler` 等测试用例会尝试通过原生配置文件指定不同的 C/C++ 编译器（如 clang 或 gcc）。
* **测试单一实现编译器的版本检测:** 对于像 Vala、Rust、Java 这样的通常只有一个主要实现的语言，测试 Meson 能否正确地从配置文件指定的编译器中获取版本信息。
* **测试 Java classpath:** 测试 Meson 如何处理 Java 的 classpath 配置。
* **测试 Swift 编译器的版本检测:**  测试 Meson 如何解析 Swift 编译器的版本信息，并处理链接器参数。
* **测试原生配置文件路径:** 测试 Meson 是否能正确处理通过命令行参数 `--native-file` 指定的配置文件路径。
* **测试内置选项 (Built-in Options) 的覆盖:** 测试原生配置文件中的 `built-in options` 部分能否覆盖 Meson 的默认构建选项，例如编译器参数、库类型等。
* **测试项目选项 (Project Options) 的覆盖:** 测试原生配置文件能否覆盖项目中定义的选项。
* **测试用户选项 (User Options) 的校验:** 测试原生配置文件能否用于设置用户自定义选项，并验证 Meson 能否正确地校验这些选项的值。
* **测试交叉编译配置文件:**  `CrossFileTests` 类中的测试用例主要关注交叉编译配置文件的处理，例如 `needs_exe_wrapper` 属性的测试，以及执行包装器的测试。

**2. 与逆向方法的关系及举例:**

这个文件本身是构建系统的一部分，主要关注的是如何配置构建环境，而不是直接执行逆向操作。但是，**正确的构建配置是进行逆向分析的前提**。

* **指定目标架构的工具链:** 在进行针对特定架构（例如 ARM、MIPS）的二进制文件逆向时，需要使用相应的交叉编译工具链。原生配置文件可以用来指定这些工具链的路径，确保 Frida 在构建针对这些架构的版本时使用正确的工具。例如，在交叉编译 Frida Gum 到 Android 时，就需要通过配置文件指定 Android NDK 中的编译器路径。
* **模拟目标环境:** 有时候，需要在与目标环境尽可能相似的环境下进行编译和测试。通过创建二进制包装器，可以模拟目标环境下特定工具的行为，例如模拟目标操作系统中 `ls` 命令的输出，以便测试 Frida 在目标环境下的行为。
* **控制编译选项:**  逆向分析可能需要关注特定编译选项对二进制文件结构的影响。通过原生配置文件，可以控制编译器的优化级别、调试信息的生成等选项，以便生成符合逆向分析需求的二进制文件。例如，可以禁用优化 (`-O0`) 以便更容易地理解代码流程。

**3. 涉及的二进制底层，Linux, Android 内核及框架的知识及举例:**

* **二进制底层:**  测试用例中涉及到对编译器 (`gcc`, `clang` 等)、链接器 (`ld`)、归档工具 (`ar`)、strip 工具等二进制工具的调用和配置。这些工具是构建过程中的核心组件，直接操作二进制文件。
* **Linux:**  许多测试用例依赖于 Linux 特有的工具和概念，例如 shell 命令 (`bash`)、管道 (`mkfifo`)、文件权限 (`chmod`)。交叉编译配置文件的格式和内容也与 Linux 系统相关。
* **Android 内核及框架 (间接):** 虽然这个文件没有直接涉及到 Android 内核或框架的代码，但是 Frida 的目标之一是在 Android 平台上进行动态插桩。因此，理解 Android NDK（Native Development Kit）提供的交叉编译工具链以及 Android 系统的某些特性（例如 ART 虚拟机）对于配置 Frida 的 Android 构建至关重要。原生配置文件可以用来指定 Android NDK 中编译器的路径。
* **执行包装器:**  `helper_create_binary_wrapper` 函数创建的包装器脚本使用 `subprocess` 模块来执行其他程序，这涉及到操作系统进程管理的基础知识。

**4. 逻辑推理，假设输入与输出:**

以下举例说明 `test_find_program` 测试用例的逻辑推理：

* **假设输入:**
    * 创建一个名为 `generated0.config` 的原生配置文件，内容如下：
      ```ini
      [binaries]
      bash = '/path/to/fake/bash'
      ```
    * 调用 `self.init(self.testcase, extra_args=['--native-file', config, '-Dcase=find_program'])`。这里的 `self.testcase` 指向包含 `meson.build` 文件的目录，该文件会使用 `find_program('bash')`。
* **预期输出:**
    * Meson 在初始化构建环境时，会读取 `generated0.config` 文件，并将其中的 `bash` 路径 `/path/to/fake/bash` 记录下来。当执行到 `find_program('bash')` 时，Meson 应该返回 `/path/to/fake/bash`。虽然这个测试用例没有直接断言输出，但其目的是验证 Meson 能否正确解析并使用配置文件中的路径信息。

**5. 涉及用户或者编程常见的使用错误及举例:**

* **配置文件格式错误:** 用户可能会在原生配置文件中犯语法错误，例如拼写错误、 секция 名称错误、键值对格式错误等。虽然这个文件没有显式测试这些错误，但 Meson 的解析过程会捕获这些错误并给出提示。
* **指定不存在的工具路径:** 用户可能在配置文件中指定了不存在的编译器或工具程序的路径。例如，在 `generated0.config` 中将 `bash` 的路径设置为一个不存在的文件。Meson 在初始化时可能会报错，或者在后续的构建过程中因为找不到指定的工具而失败。
* **类型不匹配的选项值:** 用户可能为某个选项设置了错误的数据类型的值。例如，如果某个选项需要一个布尔值，用户却提供了一个字符串。测试用例 `test_user_options` 验证了当用户通过原生配置文件设置了与预期类型不符的选项值时，Meson 会抛出错误。

**6. 说明用户操作是如何一步步的到达这里，作为调试线索:**

一个开发人员为了测试 Frida 对特定平台或工具链的兼容性，或者为了验证他们修改的构建系统代码是否正确处理了机器配置文件，可能会执行以下步骤：

1. **修改 Frida 的构建配置或代码:**  开发人员可能修改了 `meson.build` 文件、构建脚本，或者与机器配置文件处理相关的代码。
2. **创建或修改测试用例:** 开发人员可能会创建新的测试用例，或者修改现有的测试用例 (`machinefiletests.py` 中的测试函数) 来覆盖他们的修改或要测试的场景。
3. **运行 Meson 测试:** 开发人员通常会使用 Meson 提供的测试命令来运行测试套件。这可能涉及到以下步骤：
   * 进入 Frida Gum 的构建目录。
   * 执行 `meson test -C <build_directory>` 或者使用 `ninja test`（如果已经生成了构建文件）。
4. **Meson 执行测试用例:**  当运行测试时，Meson 会加载并执行 `machinefiletests.py` 文件中的测试函数。
5. **测试用例执行:**  例如，如果执行 `test_find_program`，则会按照该测试用例的逻辑：
   * 调用 `self.helper_create_native_file` 创建一个临时的原生配置文件。
   * 调用 `self.init` 函数，模拟用户在命令行中使用 `--native-file` 参数指定该配置文件，并设置一个特定的 `-Dcase` 选项。
   * Meson 内部会根据 `--native-file` 读取配置文件，并根据 `-Dcase` 的值执行相应的测试逻辑，例如查找程序。
6. **断言和验证:** 测试用例会使用 `self.assertEqual`、`self.assertTrue` 等断言方法来验证 Meson 的行为是否符合预期。如果断言失败，则说明 Meson 在处理机器配置文件时出现了问题。

**7. 功能归纳:**

总而言之，`frida/subprojects/frida-gum/releng/meson/unittests/machinefiletests.py` 文件的第一部分主要用于测试 Meson 构建系统处理原生配置文件的能力，包括解析配置文件、查找程序、切换编译器、处理构建选项等。这些测试确保了 Frida 的构建系统能够灵活地适应不同的构建环境和工具链，这对于 Frida 跨平台支持和功能的正确性至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/machinefiletests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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