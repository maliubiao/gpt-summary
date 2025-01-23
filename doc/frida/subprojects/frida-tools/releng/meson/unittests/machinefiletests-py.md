Response:
My thinking process to analyze the Python code and fulfill the request went through these steps:

1. **Understand the Core Task:** The primary goal is to analyze a Python file related to testing in the Frida project and describe its functionalities, relating them to reverse engineering, low-level details, and potential user errors.

2. **Identify the File's Purpose:** The file name `machinefiletests.py` and the import of `BasePlatformTests` strongly suggest this file contains unit tests for handling "machine files" in Frida's build system (Meson). Machine files (both native and cross) in Meson define the build environment, including compilers, tools, and target architecture.

3. **Break Down the Code Structure:** I scanned the code for major components:
    * **Imports:** These give hints about dependencies and the file's scope (e.g., `subprocess`, `tempfile`, `os`, `unittest`, `mesonbuild`).
    * **Helper Functions:** Functions like `helper_create_native_file`, `helper_create_binary_wrapper`, and `helper_for_compiler` indicate common setup tasks for the tests.
    * **Test Classes:** `NativeFileTests` and `CrossFileTests` are the core of the unit tests.
    * **Individual Test Methods:** Functions starting with `test_` within the test classes are the individual test cases.

4. **Analyze Key Functions and Test Methods:** I focused on understanding what each significant function and test method does:
    * **`helper_create_native_file`:**  Creates temporary Meson native files (INI-like format) to simulate configuration.
    * **`helper_create_binary_wrapper`:**  Generates wrapper scripts around executables to control their behavior (e.g., simulate different versions). This is crucial for testing how Meson reacts to different tool versions.
    * **`helper_for_compiler`:**  A specialized helper to test overriding compilers for different languages.
    * **Test methods in `NativeFileTests`:** These test various aspects of handling native files, like finding programs, working with config tool dependencies, setting compiler options, handling user options, and dealing with subprojects.
    * **Test methods in `CrossFileTests`:** These focus on testing the behavior of cross-compilation files, particularly the `needs_exe_wrapper` setting.

5. **Identify Connections to Reverse Engineering:**  I considered how the tested functionalities relate to reverse engineering:
    * **Toolchain Manipulation:** Overriding compilers (`test_c_compiler`, `test_cpp_compiler`, etc.) is essential in reverse engineering to use specific toolchains or versions for analysis.
    * **Binary Inspection:** The ability to find programs and analyze their versions (`test_find_program`) is fundamental to understanding the target environment.
    * **Cross-Compilation Context:** The `CrossFileTests` directly address cross-compilation, a common scenario in reverse engineering when analyzing software for different architectures (e.g., analyzing an Android app on a Linux machine).

6. **Identify Connections to Low-Level/Kernel/Framework Knowledge:**
    * **Operating System Differences:** The code explicitly handles differences between operating systems (Windows, macOS, Linux, Haiku, SunOS) using `is_windows()`, `is_osx()`, etc., indicating awareness of OS-specific behaviors.
    * **Compiler Variations:** The tests check for different compiler implementations (GCC, Clang, etc.) and their specific behaviors.
    * **System Paths:** The `test_compile_sys_path` test addresses how Meson handles native files located in system directories.
    * **Cross-Compilation Concepts:**  `CrossFileTests` deal directly with architecture (`cpu_family`, `cpu`, `endian`) which are core to cross-compilation.

7. **Look for Logical Reasoning and Assumptions:**
    * **Assumptions about Tool Availability:** The tests often assume the presence of certain tools (like `bash`, `llvm-config`, various compilers). When these tools are not found, tests are skipped.
    * **Simulation through Wrappers:** The tests use wrapper scripts to simulate different scenarios without needing actual different compiler installations. This is a form of logical abstraction.

8. **Consider Potential User Errors:**
    * **Incorrect Native File Syntax:**  The tests implicitly check for correct native file formatting. Users could easily make mistakes in the INI syntax.
    * **Providing Incorrect Option Values:** The `test_user_options` methods explicitly check how Meson handles invalid user-defined option values specified in native files.
    * **Conflicting Options:**  The tests around subprojects and built-in options demonstrate how Meson resolves conflicts between options defined in different places (native files, project files, command line).

9. **Trace User Operations to Reach This Code:**  I thought about the typical workflow that would involve this code:
    * A developer working on Frida.
    * Making changes to how Frida handles machine files in its build system.
    * Running unit tests (like those in this file) to verify their changes.
    * The developer might use the `--native-file` or `--cross-file` arguments to provide custom configuration files.

10. **Synthesize and Summarize:** Finally, I formulated a concise summary of the file's purpose based on the analysis above.

By following these steps, I was able to break down the complex code into manageable parts, identify the key functionalities, and relate them to the specific areas mentioned in the prompt (reverse engineering, low-level details, etc.). This systematic approach allowed me to generate a comprehensive and accurate description of the Python file's role within the Frida project.
这是文件 `frida/subprojects/frida-tools/releng/meson/unittests/machinefiletests.py` 的源代码，它属于 Frida Dynamic Instrumentation 工具的测试套件。这个文件的主要功能是**测试 Meson 构建系统中处理 "machine files" (机器文件) 的能力**。机器文件在 Meson 中用于配置构建环境，包括指定编译器、工具链以及一些构建选项。

以下是更详细的功能列表：

1. **测试解析和应用 Native Files (本地文件):**
   -  Native files 允许用户在构建时覆盖默认的构建设置，例如指定特定可执行文件的路径、编译器等。
   -  这个文件测试了 Meson 能否正确解析这些 Native files，并应用其中定义的设置。
   -  它创建临时的 Native files，其中包含了各种配置信息，然后运行 Meson 构建来验证这些配置是否生效。

2. **测试解析和应用 Cross Files (交叉编译文件):**
   - Cross files 用于配置交叉编译环境，即在一种架构上构建用于另一种架构的软件。
   - 这个文件测试了 Meson 能否正确解析 Cross files，并应用其中定义的交叉编译设置。
   - 它创建临时的 Cross files，定义目标架构和工具链，并测试 Meson 的行为。

3. **测试查找程序 (find_program):**
   - 测试通过 Native file 指定可执行文件路径后，Meson 能否正确找到该程序。
   - 例如，可以指定 `bash` 解释器的路径，然后测试 Meson 在构建过程中能否正确使用这个指定的 `bash`。

4. **测试配置工具依赖 (config_tool_dep):**
   - 测试通过 Native file 指定配置工具（例如 `llvm-config`）后，Meson 能否正确识别和使用这个工具来获取依赖信息。

5. **测试 Python 模块查找 (python3_module, python_module):**
   - 测试通过 Native file 指定 Python 解释器后，Meson 能否正确找到对应的 Python 解释器，并用于查找 Python 模块。

6. **测试编译器覆盖 (c_compiler, cpp_compiler, objc_compiler 等):**
   - 测试通过 Native file 显式指定不同语言的编译器后，Meson 能否使用这些指定的编译器，而不是系统默认的编译器。
   - 这对于需要使用特定版本或特定供应商的编译器进行构建的情况非常重要。

7. **测试单一实现编译器的版本获取 (vala_compiler, rust_compiler 等):**
   - 对于某些只有一种主要实现的语言，测试通过 Native file 指定编译器后，Meson 能否正确获取其版本信息。

8. **测试 Java 相关的配置 (java_compiler, java_classpath):**
   - 测试通过 Native file 配置 Java 编译器以及 classpath 的能力。

9. **测试 Swift 编译器的版本获取 (swift_compiler):**
   - 测试通过 Native file 指定 Swift 编译器后，Meson 能否正确获取其版本信息。

10. **测试 Native File 路径处理 (native_file_dirs, native_file_dirs_overridden):**
    - 测试 Meson 能否正确处理 Native file 的路径，包括相对路径和绝对路径。

11. **测试在系统路径中使用 Native File (compile_sys_path):**
    - 验证即使 Native file 位于系统的某个路径下，Meson 也能正确读取和应用其配置。

12. **测试用户选项覆盖 (user_options, user_options_command_line_overrides, user_options_subproject):**
    - 测试通过 Native file 覆盖项目定义的构建选项的能力。
    - 同时也测试了命令行参数对 Native file 中选项的覆盖，以及子项目中选项的覆盖。

13. **测试内置选项覆盖 (builtin_options, builtin_options_conf_overrides_env, builtin_options_subprojects 等):**
    - 测试通过 Native file 覆盖 Meson 内置的构建选项，例如 `default_library`、`c_args` 等。
    - 还测试了 Native file 中的内置选项如何覆盖环境变量和子项目中的选项。

14. **测试 `needs_exe_wrapper` 属性 (needs_exe_wrapper_true, needs_exe_wrapper_false, needs_exe_wrapper_true_wrapper):**
    - 专门针对交叉编译，测试 `needs_exe_wrapper` 属性是否能正确指示是否需要一个 host 端的 wrapper 来执行 target 平台的程序。

**与逆向的方法的关系及举例说明:**

- **指定特定的编译器和工具链:** 在逆向工程中，可能需要使用特定版本的编译器或工具链来重新编译目标程序，以便进行调试或分析。Native files 允许逆向工程师精确控制构建环境，例如指定用于编译目标应用的特定版本的 GCC 或 Clang。
  - **举例:** 假设你想逆向分析一个使用旧版本 GCC 编译的二进制文件。你可以创建一个 Native file，其中指定了该旧版本 GCC 的路径，然后在 Frida 的构建过程中使用这个 Native file，以便 Frida 工具能够使用相同的环境。

- **模拟目标环境:**  在分析特定平台的应用程序时，例如 Android 或嵌入式系统，Cross files 可以帮助模拟目标环境。你可以指定目标架构（例如 ARM）和相应的工具链，以便 Frida 构建出能在该目标环境中运行的工具。
  - **举例:**  你想在你的 Linux 开发机上分析一个 Android 应用。你可以创建一个 Cross file，指定 Android NDK 中的 ARM 编译器，然后在构建 Frida 时使用这个 Cross file，这样 Frida 就能生成针对 Android 架构的代码。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

- **可执行文件路径:**  测试中使用了 `helper_create_binary_wrapper` 来创建可执行文件的包装器。这涉及到对操作系统如何查找和执行二进制文件的理解。
  - **举例:**  在 Linux 中，`#!/usr/bin/env python3` shebang 行指定了解释器路径。测试中会确保生成的包装器脚本能够被正确执行。

- **编译器和链接器:**  测试覆盖了各种编译器（C, C++, Objective-C 等），涉及到对编译器工作原理、编译选项、链接过程的理解。
  - **举例:**  测试中会检查通过 Native file 指定的 C++ 编译器 (`g++` 或 `clang++`) 能否被 Meson 正确识别和使用。

- **交叉编译的概念:** `CrossFileTests` 直接涉及到交叉编译，需要理解目标架构、host 架构、target 系统等概念。
  - **举例:**  Cross file 中定义了 `host_machine` 和 `target_machine` 的属性，例如 `cpu_family` 和 `endian`，这些都是底层架构相关的知识。

- **Android NDK:** 在交叉编译 Android 应用时，通常会使用 Android NDK 提供的工具链。Cross files 可以配置使用 NDK 中的编译器和链接器。

**逻辑推理，假设输入与输出:**

- **假设输入:** 一个 Native file 内容如下：
  ```ini
  [binaries]
  bash = '/usr/local/bin/mybash'
  ```
- **测试代码:**  `self.init(self.testcase, extra_args=['--native-file', config, '-Dcase=find_program'])`，其中 `self.testcase` 的构建脚本会尝试查找 `bash` 程序。
- **预期输出:**  Meson 构建系统会使用 `/usr/local/bin/mybash` 而不是系统默认的 `/bin/bash`。测试会验证后续构建步骤是否使用了指定的 `bash` 路径。

**涉及用户或者编程常见的使用错误，举例说明:**

- **Native file 语法错误:** 用户可能会在 Native file 中使用错误的 INI 语法，例如拼写错误、缺少等号或引号。
  - **举例:**  `[binari]\nbash = /usr/bin/bash` (拼写错误) 或 `binaries: {bash: '/usr/bin/bash'}` (使用了 Python 字典语法而不是 INI 语法)。Meson 在解析时会报错，测试框架会捕获这些错误。

- **指定不存在的程序路径:** 用户可能在 Native file 中指定了一个不存在的可执行文件路径。
  - **举例:** `[binaries]\nbash = '/path/to/nonexistent/bash'`。Meson 在尝试使用该程序时可能会失败，测试会模拟这种情况并验证 Meson 的处理方式。

- **覆盖了不应该覆盖的选项:** 用户可能在 Native file 中错误地覆盖了某些关键的构建选项，导致构建失败或产生意外的结果。
  - **举例:**  错误地将 C 编译器的标准设置为一个不存在的标准，例如 `c_std = 'c999'`. 测试会验证 Meson 能否正确处理这些无效的选项，或者给出清晰的错误信息。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **用户想要自定义 Frida 的构建环境:** 用户可能需要使用特定版本的编译器、Python 解释器或其他工具来构建 Frida，或者针对特定的目标平台进行交叉编译。

2. **用户创建或修改 Native file 或 Cross file:**  为了实现自定义，用户会创建一个或多个 Native file 或 Cross file，并在其中编写相应的配置信息。例如，用户可能创建了一个名为 `my_native_config.ini` 的文件，并在其中指定了特定的 GCC 路径。

3. **用户在运行 Meson 配置时使用 `--native-file` 或 `--cross-file` 参数:**  用户在终端中执行类似以下的命令：
   ```bash
   meson setup build --native-file my_native_config.ini
   ```
   或者对于交叉编译：
   ```bash
   meson setup build --cross-file my_cross_config.ini
   ```

4. **Meson 解析并应用这些文件:** Meson 在配置构建系统时，会读取指定的 Native file 或 Cross file，并根据其中的配置信息来设置构建环境。

5. **如果配置过程中出现问题，或者 Frida 的开发者修改了处理 machine file 的逻辑，就需要进行调试:**
   - **开发者修改了 `frida/subprojects/frida-tools/releng/meson/machinefile.py` 或相关的代码:**  这个文件会影响 Meson 如何解析和应用 machine files。
   - **运行 `machinefiletests.py` 中的测试:** 为了验证修改后的代码是否正确工作，开发者会运行 `machinefiletests.py` 中的单元测试。如果测试失败，这将提供调试的线索，指出在处理 machine file 的哪个环节出现了问题。开发者可以查看失败的测试用例，分析其创建的临时 Native file 或 Cross file 的内容，以及测试的预期行为，从而定位 bug。

**归纳一下它的功能 (第1部分):**

总而言之，`machinefiletests.py` 文件的主要功能是**对 Frida 构建系统中处理 Meson 机器文件（Native files 和 Cross files）的逻辑进行全面的单元测试**。它测试了 Meson 能否正确解析、应用和处理各种配置信息，包括程序路径、编译器、构建选项等。这些测试对于确保 Frida 的构建系统能够灵活地适应不同的构建需求和目标平台至关重要，并且有助于防止用户在使用自定义配置时遇到问题。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/unittests/machinefiletests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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