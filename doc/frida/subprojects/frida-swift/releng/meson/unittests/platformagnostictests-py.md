Response:
Let's break down the request and the provided Python code. The user wants a detailed explanation of the `platformagnostictests.py` file within the Frida project. Here's a thought process to generate the comprehensive answer:

1. **Understand the Context:** The filename `platformagnostictests.py` and its location within `frida/subprojects/frida-swift/releng/meson/unittests/` immediately suggest this is a set of unit tests for the Frida dynamic instrumentation tool, specifically focusing on aspects that shouldn't be platform-dependent. The "frida-swift" part hints at interaction with Swift code, although this particular file seems more general. The "meson" directory indicates that Meson is used as the build system.

2. **Identify Core Functionality:**  The first step is to read through the code and categorize what each test function does. I'll create mental or actual notes as I go:

    * `test_relative_find_program`: Tests relative paths in `find_program()`.
    * `test_invalid_option_names`: Checks for reserved/invalid option names in Meson.
    * `test_option_validation`:  Validates option values against min/max/choices.
    * `test_python_dependency_without_pkgconfig`:  Tests finding Python without `pkg-config`.
    * `test_debug_function_outputs_to_meson_log`:  Verifies the `debug()` function output.
    * `test_new_subproject_reconfigure`: Checks reconfiguration with subprojects.
    * `test_update_wrapdb`: Tests updating the WrapDB dependency manager.
    * `test_none_backend`: Tests the "none" build backend.
    * `test_change_backend`: Tests changing the build backend.
    * `test_validate_dirs`: Tests validation of build directories.
    * `test_scripts_loaded_modules`: Checks loaded Python modules in scripts.
    * `test_setup_loaded_modules`: Checks loaded Python modules during `meson setup`.
    * `test_meson_package_cache_dir`: Tests the `MESON_PACKAGE_CACHE_DIR` environment variable.
    * `test_cmake_openssl_not_found_bug`: Tests a specific bug related to CMake and OpenSSL.
    * `test_error_configuring_subdir`: Tests error handling when running Meson in a subdirectory.
    * `test_reconfigure_base_options`: Tests reconfiguring basic options.
    * `test_setup_with_unknown_option`: Tests handling of unknown options.
    * The remaining tests (`test_configure_new_option` through `test_configure_new_option_subproject`) focus on changes to Meson option files and how Meson reacts.

3. **Address Specific Questions:** Now, go through each of the user's specific requests:

    * **Functionality:**  This is where the categorized list of tests comes in handy. I can summarize the purpose of each test.

    * **Relationship to Reverse Engineering:**  This requires more thought. Frida is a reverse engineering tool, but this *specific* test file is about the build system (Meson). The connection is indirect. Meson helps build Frida. Some tests, like those involving dependencies, might indirectly touch on things relevant to reverse engineering (like needing specific libraries). I need to be careful not to overstate the direct connection. Examples should focus on *how these build steps enable reverse engineering*, not the tests themselves being reverse engineering techniques.

    * **Binary/Kernel/Framework Knowledge:** Again, the focus is Meson. However, certain tests *simulate* scenarios where such knowledge is relevant during the Frida build. For example, testing dependency handling is crucial because Frida interacts with the operating system at a low level. Tests about compiler flags also touch on this. I'll need to identify those indirect connections and explain *why* the tested functionality is important in that context.

    * **Logical Inference (Hypothetical Input/Output):**  For each test, consider what input (e.g., specific Meson files, command-line arguments) would lead to a particular output (success, failure, specific log messages). This requires understanding how Meson and Python's `unittest` framework work.

    * **Common User Errors:**  Think about what mistakes a developer or user might make when using Meson to build Frida. This includes things like incorrect option names, invalid option values, messing with the build directory structure, and misunderstanding how reconfiguration works. The tests often directly check for these error conditions.

    * **User Path to this Code (Debugging):** This involves imagining a developer debugging a Meson build issue for Frida. They might be investigating why an option isn't being set correctly, why a dependency isn't found, or why reconfiguration is failing. Tracing the execution flow or looking at Meson's internal logs could lead them to these tests.

4. **Structure the Answer:** Organize the information logically. A good structure would be:

    * **Overall Purpose:** Start with a high-level summary of the file's role.
    * **Detailed Functionality:** List and describe each test function.
    * **Reverse Engineering Connection:** Explain the indirect link and provide examples.
    * **Binary/Kernel/Framework Connection:**  Similarly, explain the relevance of the tested functionality.
    * **Logical Inference:**  Provide input/output examples for a few representative tests.
    * **Common User Errors:**  Illustrate potential mistakes and how the tests catch them.
    * **Debugging Scenario:** Describe how a user might end up looking at this code.

5. **Refine and Elaborate:**  Review the drafted answer and add more details, explanations, and context where needed. Ensure the language is clear and avoids jargon where possible. For example, instead of just saying "tests option validation," explain *what kind* of validation is being done.

6. **Self-Correction/Review:**  Read through the answer as if you were the user asking the question. Does it make sense? Is it comprehensive? Are there any gaps? For instance, initially, I might have focused too much on the Meson details and not enough on the Frida context. I'd then go back and strengthen those connections. Also double-check that the examples are accurate and relevant.

By following these steps, I can create a detailed and helpful answer that addresses all aspects of the user's request.
这是一个名为 `platformagnostictests.py` 的 Python 源代码文件，属于 Frida 动态 instrumentation 工具项目中的 Frida-Swift 子项目，并且位于与构建系统 Meson 相关的单元测试目录中。从名字来看，这个文件包含了一系列与平台无关的测试。

下面我们来详细列举它的功能，并根据你的要求进行分析：

**主要功能:**

这个文件定义了一个名为 `PlatformAgnosticTests` 的 Python 类，它继承自 `BasePlatformTests`。这个类包含了一系列以 `test_` 开头的方法，每个方法都是一个独立的单元测试，用于验证 Frida 构建过程中与平台无关的特定功能。  这些测试主要关注 Meson 构建系统的行为，而不是 Frida 自身的运行时特性。

以下是每个测试方法的功能分解：

* **`test_relative_find_program(self)`:**  测试 `find_program()` 函数使用相对路径时，是否不会在当前工作目录中查找程序。这确保了构建系统的行为符合预期，避免意外地使用工作目录下的同名程序。
* **`test_invalid_option_names(self)`:** 测试当使用保留的或无效的选项名称时，构建系统是否能正确抛出异常。这有助于开发者避免使用错误的选项名称。
* **`test_option_validation(self)`:**  测试用户在 `meson_options.txt` 或 `meson.options` 中定义的选项的验证逻辑，例如检查整数选项是否在指定的最大最小值范围内，以及数组选项的值是否在允许的选择列表中。
* **`test_python_dependency_without_pkgconfig(self)`:** 测试在没有 `pkg-config` 工具的情况下，构建系统是否能够正确处理 Python 依赖。这对于一些没有安装 `pkg-config` 的环境或者需要直接指定 Python 解释器路径的情况很重要。
* **`test_debug_function_outputs_to_meson_log(self)`:** 测试 Meson 构建文件中 `debug()` 函数的输出是否只会被写入到 Meson 的日志文件中，而不会输出到标准输出。这有助于在构建过程中输出调试信息，而不会干扰正常的构建输出。
* **`test_new_subproject_reconfigure(self)`:** 测试在重新配置构建系统时，正确处理新的子项目。这确保了在添加或修改子项目后，构建系统能够正确更新配置。
* **`test_update_wrapdb(self)`:** 测试更新 WrapDB（Meson 的依赖管理工具）的功能。这确保了开发者可以使用最新的依赖信息。
* **`test_none_backend(self)`:** 测试使用 `none` 构建后端的情况。在这种后端下，Meson 不会生成任何实际的构建文件（如 Ninja 文件），主要用于生成安装包等场景。
* **`test_change_backend(self)`:** 测试尝试更改构建后端（例如从 Ninja 切换到 None）的行为。Meson 通常不允许在不清除构建目录的情况下更改后端。
* **`test_validate_dirs(self)`:** 测试构建目录的验证逻辑，例如不允许构建目录是源代码目录的父目录，以及重新配置已存在但可能不完整的构建目录的行为。
* **`test_scripts_loaded_modules(self)`:** 测试在执行构建脚本时，加载的 Python 模块是否在一个可接受的子集中。这旨在控制构建过程中加载的模块数量，提高构建效率。
* **`test_setup_loaded_modules(self)`:**  与上一个测试类似，但关注的是 `meson setup` 阶段加载的 Python 模块。
* **`test_meson_package_cache_dir(self)`:** 测试 `MESON_PACKAGE_CACHE_DIR` 环境变量是否能够正确设置 Meson 的包缓存目录。
* **`test_cmake_openssl_not_found_bug(self)`:** 测试一个特定的关于 CMake 查找 OpenSSL 的 bug 是否已修复。这表明了单元测试也可以用于回归测试，确保之前修复的问题不会再次出现。
* **`test_error_configuring_subdir(self)`:** 测试在子目录中运行 Meson 配置命令但缺少 `project()` 声明时，是否能给出清晰的错误提示。
* **`test_reconfigure_base_options(self)`:** 测试重新配置构建系统时，基本选项（例如 `b_ndebug`, `c_std`）是否能够正确更新，包括在主项目和子项目中的选项。
* **`test_setup_with_unknown_option(self)`:** 测试当在 `meson setup` 命令中使用未知的选项时，构建系统是否会报错。
* **`test_configure_new_option(self)`:** 测试在不重新配置的情况下添加新的构建选项是否能被识别和设置。
* **`test_configure_removed_option(self)`:** 测试尝试设置一个已删除的构建选项时是否会报错。
* **`test_configure_option_changed_constraints(self)`:** 测试在不重新配置的情况下更改构建选项的约束条件（例如最大最小值）是否能生效。
* **`test_configure_meson_options_txt_to_meson_options(self)`:** 测试从 `meson_options.txt` 文件切换到 `meson.options` 文件后，构建系统是否仍然能够正确读取选项。
* **`test_configure_options_file_deleted(self)`:** 测试删除所有选项文件后，尝试设置项目选项是否会报错。
* **`test_configure_options_file_added(self)` 和 `test_configure_options_file_added_old(self)`:** 测试添加新的选项文件（`meson.options` 或 `meson_options.txt`）后，构建系统是否能够识别并加载其中的选项。
* **`test_configure_new_option_subproject(self)`:** 测试在不重新配置的情况下，向子项目添加新的构建选项是否能被识别和设置。

**与逆向方法的关系:**

尽管这个文件主要关注构建系统，但它间接地与逆向方法有关，因为 Frida 本身是一个用于动态 instrumentation 的逆向工程工具。  这些测试确保了 Frida 能够被正确地构建出来，这是进行逆向分析的前提。

**举例说明:**

* **依赖管理:** `test_update_wrapdb` 确保了 Frida 的依赖能够被正确管理。在逆向过程中，你可能需要 Frida 依赖于特定的库（例如用于处理符号的库），如果构建系统不能正确处理这些依赖，Frida 可能无法正常工作，从而影响逆向分析。
* **构建选项:**  某些 Frida 的构建选项可能会影响其功能或性能，例如是否启用某些调试功能。`test_option_validation` 等测试确保了用户提供的构建选项是有效的，避免因错误的选项配置导致 Frida 行为异常，影响逆向结果的准确性。

**涉及二进制底层、Linux、Android 内核及框架的知识:**

这些测试本身并不直接操作二进制代码或内核，但它们确保了构建系统能够正确处理与这些底层概念相关的构建配置。

**举例说明:**

* **交叉编译:** Frida 经常需要交叉编译到不同的目标平台（例如 Android）。构建系统需要正确处理不同平台的编译器、链接器和库的差异。虽然这个文件中的测试是平台无关的，但 Meson 的整体功能（经过其他测试验证）确保了这种交叉编译的正确性。
* **特定平台的依赖:**  Frida 在 Android 平台上可能依赖于特定的 Android 框架库。构建系统需要能够找到并链接这些库。`test_python_dependency_without_pkgconfig` 测试了在更底层的层面上处理依赖的能力，这对于理解如何在各种平台上处理依赖关系是有帮助的。
* **编译器标志:** 构建过程中使用的编译器标志（例如优化级别、调试信息）会直接影响生成的二进制代码。虽然这个文件没有直接测试编译器标志，但 Meson 的选项处理机制（这里被测试）允许用户配置这些标志，从而影响最终 Frida 程序的行为。

**逻辑推理 (假设输入与输出):**

**例子 1: `test_option_validation`**

* **假设输入:** 在 `meson_options.txt` 中定义了一个整数选项 `port`，其最小值为 1000，最大值为 2000，并尝试使用 `-Dport=500` 进行配置。
* **预期输出:** Meson 构建系统应该抛出一个错误，提示 `Value 500 for option "port" is less than minimum value 1000.`

**例子 2: `test_invalid_option_names`**

* **假设输入:** 在 `meson_options.txt` 中定义了一个选项 `c_myoption`。
* **预期输出:** Meson 构建系统应该抛出一个错误，提示 `Option name c_myoption is reserved.`，因为以 `c_` 开头的选项名称是保留给 C 语言相关的选项的。

**涉及用户或编程常见的使用错误:**

这些测试旨在捕获用户在配置和构建 Frida 时可能犯的错误。

**举例说明:**

* **错误的选项名称:** 用户可能拼写错误选项名称，或者使用了保留的选项名称。`test_invalid_option_names` 和 `test_setup_with_unknown_option` 可以检测到这类错误。
* **无效的选项值:** 用户可能为选项提供了超出范围或类型不匹配的值。`test_option_validation` 可以捕获这类错误。
* **在错误的目录下运行 Meson:** 用户可能在子目录中尝试运行 `meson setup`，而没有在顶层目录运行。`test_error_configuring_subdir` 测试了这种情况。
* **尝试在不清除构建目录的情况下更改构建后端:** 用户可能在已经配置了 Ninja 后端的情况下，尝试使用 `meson setup --backend=none`，这通常是不允许的。`test_change_backend` 模拟了这种情况。

**用户操作是如何一步步的到达这里，作为调试线索:**

假设一个 Frida 开发者在尝试构建 Frida 时遇到了问题，例如：

1. **配置错误:** 用户尝试使用 `meson setup build -Dmy_custom_option=invalid_value` 配置 Frida，但 `my_custom_option` 是一个整数选项，而 `invalid_value` 不是一个有效的整数。Meson 报错，提示选项值无效。开发者可能会想到查看 Meson 的选项处理逻辑，从而找到 `test_option_validation` 这个测试。
2. **依赖问题:**  在某个平台上构建 Frida 时，Meson 找不到某个 Python 依赖。开发者可能会怀疑是 `pkg-config` 没有正确工作，或者依赖没有被正确指定。这时，`test_python_dependency_without_pkgconfig` 可能会提供一些线索，帮助理解 Meson 在没有 `pkg-config` 时的行为。
3. **构建缓慢:** 开发者发现 Frida 的构建过程非常缓慢，怀疑是加载了过多的 Python 模块。他们可能会搜索 Meson 相关的性能优化，并找到 `test_scripts_loaded_modules` 和 `test_setup_loaded_modules`，从而了解 Meson 如何控制加载的模块。
4. **切换构建后端失败:** 开发者想尝试使用不同的构建后端，例如从 Ninja 切换到 `none`，但遇到了错误。他们可能会查找关于 Meson 构建后端切换的限制，从而找到 `test_change_backend`。

总而言之，`platformagnostictests.py` 文件是 Frida 构建系统测试套件中的一部分，它专注于验证与平台无关的 Meson 构建功能。这些测试确保了 Frida 能够被正确配置和构建，这对于进行有效的动态 instrumentation 和逆向分析至关重要。  开发者在遇到与构建过程相关的问题时，可能会查看这些测试用例，以理解 Meson 的行为和查找问题根源。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/unittests/platformagnostictests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 The Meson development team
# Copyright © 2024 Intel Corporation

from __future__ import annotations
import json
import os
import pickle
import tempfile
import subprocess
import textwrap
import shutil
from unittest import skipIf, SkipTest
from pathlib import Path

from .baseplatformtests import BasePlatformTests
from .helpers import is_ci
from mesonbuild.mesonlib import EnvironmentVariables, ExecutableSerialisation, MesonException, is_linux, python_command
from mesonbuild.optinterpreter import OptionInterpreter, OptionException
from run_tests import Backend

@skipIf(is_ci() and not is_linux(), "Run only on fast platforms")
class PlatformAgnosticTests(BasePlatformTests):
    '''
    Tests that does not need to run on all platforms during CI
    '''

    def test_relative_find_program(self):
        '''
        Tests that find_program() with a relative path does not find the program
        in current workdir.
        '''
        testdir = os.path.join(self.unit_test_dir, '101 relative find program')
        self.init(testdir, workdir=testdir)

    def test_invalid_option_names(self):
        interp = OptionInterpreter('')

        def write_file(code: str):
            with tempfile.NamedTemporaryFile('w', dir=self.builddir, encoding='utf-8', delete=False) as f:
                f.write(code)
                return f.name

        fname = write_file("option('default_library', type: 'string')")
        self.assertRaisesRegex(OptionException, 'Option name default_library is reserved.',
                               interp.process, fname)

        fname = write_file("option('c_anything', type: 'string')")
        self.assertRaisesRegex(OptionException, 'Option name c_anything is reserved.',
                               interp.process, fname)

        fname = write_file("option('b_anything', type: 'string')")
        self.assertRaisesRegex(OptionException, 'Option name b_anything is reserved.',
                               interp.process, fname)

        fname = write_file("option('backend_anything', type: 'string')")
        self.assertRaisesRegex(OptionException, 'Option name backend_anything is reserved.',
                               interp.process, fname)

        fname = write_file("option('foo.bar', type: 'string')")
        self.assertRaisesRegex(OptionException, 'Option names can only contain letters, numbers or dashes.',
                               interp.process, fname)

        # platlib is allowed, only python.platlib is reserved.
        fname = write_file("option('platlib', type: 'string')")
        interp.process(fname)

    def test_option_validation(self):
        """Test cases that are not catch by the optinterpreter itself."""
        interp = OptionInterpreter('')

        def write_file(code: str):
            with tempfile.NamedTemporaryFile('w', dir=self.builddir, encoding='utf-8', delete=False) as f:
                f.write(code)
                return f.name
        
        fname = write_file("option('intminmax', type: 'integer', value: 10, min: 0, max: 5)")
        self.assertRaisesRegex(MesonException, 'Value 10 for option "intminmax" is more than maximum value 5.',
                               interp.process, fname)

        fname = write_file("option('array', type: 'array', choices : ['one', 'two', 'three'], value : ['one', 'four'])")
        self.assertRaisesRegex(MesonException, 'Value "four" for option "array" is not in allowed choices: "one, two, three"',
                               interp.process, fname)
        
        fname = write_file("option('array', type: 'array', choices : ['one', 'two', 'three'], value : ['four', 'five', 'six'])")
        self.assertRaisesRegex(MesonException, 'Values "four, five, six" for option "array" are not in allowed choices: "one, two, three"',
                               interp.process, fname)

    def test_python_dependency_without_pkgconfig(self):
        testdir = os.path.join(self.unit_test_dir, '103 python without pkgconfig')
        self.init(testdir, override_envvars={'PKG_CONFIG': 'notfound'})

    def test_debug_function_outputs_to_meson_log(self):
        testdir = os.path.join(self.unit_test_dir, '105 debug function')
        log_msg = 'This is an example debug output, should only end up in debug log'
        output = self.init(testdir)

        # Check if message is not printed to stdout while configuring
        self.assertNotIn(log_msg, output)

        # Check if message is written to the meson log
        mesonlog = self.get_meson_log_raw()
        self.assertIn(log_msg, mesonlog)

    def test_new_subproject_reconfigure(self):
        testdir = os.path.join(self.unit_test_dir, '108 new subproject on reconfigure')
        self.init(testdir)
        self.build()

        # Enable the subproject "foo" and reconfigure, this is used to fail
        # because per-subproject builtin options were not initialized:
        # https://github.com/mesonbuild/meson/issues/10225.
        self.setconf('-Dfoo=enabled')
        self.build('reconfigure')

    def check_connectivity(self):
        import urllib
        try:
            with urllib.request.urlopen('https://wrapdb.mesonbuild.com') as p:
                pass
        except urllib.error.URLError as e:
            self.skipTest('No internet connectivity: ' + str(e))

    def test_update_wrapdb(self):
        self.check_connectivity()
        # Write the project into a temporary directory because it will add files
        # into subprojects/ and we don't want to pollute meson source tree.
        with tempfile.TemporaryDirectory() as testdir:
            with Path(testdir, 'meson.build').open('w', encoding='utf-8') as f:
                f.write(textwrap.dedent(
                    '''
                    project('wrap update-db',
                      default_options: ['wrap_mode=forcefallback'])

                    zlib_dep = dependency('zlib')
                    assert(zlib_dep.type_name() == 'internal')
                    '''))
            subprocess.check_call(self.wrap_command + ['update-db'], cwd=testdir)
            self.init(testdir, workdir=testdir)

    def test_none_backend(self):
        testdir = os.path.join(self.python_test_dir, '7 install path')

        self.init(testdir, extra_args=['--backend=none'], override_envvars={'NINJA': 'absolutely false command'})
        self.assertPathDoesNotExist(os.path.join(self.builddir, 'build.ninja'))

        self.run_tests(inprocess=True, override_envvars={})

        out = self._run(self.meson_command + ['install', f'--destdir={self.installdir}'], workdir=self.builddir)
        self.assertNotIn('Only ninja backend is supported to rebuild the project before installation.', out)

        with open(os.path.join(testdir, 'test.json'), 'rb') as f:
            dat = json.load(f)
        for i in dat['installed']:
            self.assertPathExists(os.path.join(self.installdir, i['file']))

    def test_change_backend(self):
        if self.backend != Backend.ninja:
            raise SkipTest('Only useful to test if backend is ninja.')

        testdir = os.path.join(self.python_test_dir, '7 install path')
        self.init(testdir)

        # no-op change works
        self.setconf(f'--backend=ninja')
        self.init(testdir, extra_args=['--reconfigure', '--backend=ninja'])

        # Change backend option is not allowed
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.setconf('-Dbackend=none')
        self.assertIn("ERROR: Tried modify read only option 'backend'", cm.exception.stdout)

        # Reconfigure with a different backend is not allowed
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(testdir, extra_args=['--reconfigure', '--backend=none'])
        self.assertIn("ERROR: Tried modify read only option 'backend'", cm.exception.stdout)

        # Wipe with a different backend is allowed
        self.init(testdir, extra_args=['--wipe', '--backend=none'])

    def test_validate_dirs(self):
        testdir = os.path.join(self.common_test_dir, '1 trivial')

        # Using parent as builddir should fail
        self.builddir = os.path.dirname(self.builddir)
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(testdir)
        self.assertIn('cannot be a parent of source directory', cm.exception.stdout)

        # Reconfigure of empty builddir should work
        self.new_builddir()
        self.init(testdir, extra_args=['--reconfigure'])

        # Reconfigure of not empty builddir should work
        self.new_builddir()
        Path(self.builddir, 'dummy').touch()
        self.init(testdir, extra_args=['--reconfigure'])

        # Setup a valid builddir should update options but not reconfigure
        self.assertEqual(self.getconf('buildtype'), 'debug')
        o = self.init(testdir, extra_args=['-Dbuildtype=release'])
        self.assertIn('Directory already configured', o)
        self.assertNotIn('The Meson build system', o)
        self.assertEqual(self.getconf('buildtype'), 'release')

        # Wipe of empty builddir should work
        self.new_builddir()
        self.init(testdir, extra_args=['--wipe'])

        # Wipe of partial builddir should work
        self.new_builddir()
        Path(self.builddir, 'meson-private').mkdir()
        Path(self.builddir, 'dummy').touch()
        self.init(testdir, extra_args=['--wipe'])

        # Wipe of not empty builddir should fail
        self.new_builddir()
        Path(self.builddir, 'dummy').touch()
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(testdir, extra_args=['--wipe'])
        self.assertIn('Directory is not empty', cm.exception.stdout)

    def test_scripts_loaded_modules(self):
        '''
        Simulate a wrapped command, as done for custom_target() that capture
        output. The script will print all python modules loaded and we verify
        that it contains only an acceptable subset. Loading too many modules
        slows down the build when many custom targets get wrapped.

        This list must not be edited without a clear rationale for why it is
        acceptable to do so!
        '''
        es = ExecutableSerialisation(python_command + ['-c', 'exit(0)'], env=EnvironmentVariables())
        p = Path(self.builddir, 'exe.dat')
        with p.open('wb') as f:
            pickle.dump(es, f)
        cmd = self.meson_command + ['--internal', 'test_loaded_modules', '--unpickle', str(p)]
        p = subprocess.run(cmd, stdout=subprocess.PIPE)
        all_modules = json.loads(p.stdout.splitlines()[0])
        meson_modules = [m for m in all_modules if m.startswith('mesonbuild')]
        expected_meson_modules = [
            'mesonbuild',
            'mesonbuild._pathlib',
            'mesonbuild.utils',
            'mesonbuild.utils.core',
            'mesonbuild.mesonmain',
            'mesonbuild.mlog',
            'mesonbuild.scripts',
            'mesonbuild.scripts.meson_exe',
            'mesonbuild.scripts.test_loaded_modules'
        ]
        self.assertEqual(sorted(expected_meson_modules), sorted(meson_modules))

    def test_setup_loaded_modules(self):
        '''
        Execute a very basic meson.build and capture a list of all python
        modules loaded. We verify that it contains only an acceptable subset.
        Loading too many modules slows down `meson setup` startup time and
        gives a perception that meson is slow.

        Adding more modules to the default startup flow is not an unreasonable
        thing to do as new features are added, but keeping track of them is
        good.
        '''
        testdir = os.path.join(self.unit_test_dir, '116 empty project')

        self.init(testdir)
        self._run(self.meson_command + ['--internal', 'regenerate', '--profile-self', testdir, self.builddir])
        with open(os.path.join(self.builddir, 'meson-logs', 'profile-startup-modules.json'), encoding='utf-8') as f:
                data = json.load(f)['meson']

        with open(os.path.join(testdir, 'expected_mods.json'), encoding='utf-8') as f:
            expected = json.load(f)['meson']['modules']

        self.assertEqual(data['modules'], expected)
        self.assertEqual(data['count'], 68)

    def test_meson_package_cache_dir(self):
        # Copy testdir into temporary directory to not pollute meson source tree.
        testdir = os.path.join(self.unit_test_dir, '118 meson package cache dir')
        srcdir = os.path.join(self.builddir, 'srctree')
        shutil.copytree(testdir, srcdir)
        builddir = os.path.join(srcdir, '_build')
        self.change_builddir(builddir)
        self.init(srcdir, override_envvars={'MESON_PACKAGE_CACHE_DIR': os.path.join(srcdir, 'cache_dir')})

    def test_cmake_openssl_not_found_bug(self):
        """Issue #12098"""
        testdir = os.path.join(self.unit_test_dir, '119 openssl cmake bug')
        self.meson_native_files.append(os.path.join(testdir, 'nativefile.ini'))
        out = self.init(testdir, allow_fail=True)
        self.assertNotIn('Unhandled python exception', out)

    def test_error_configuring_subdir(self):
        testdir = os.path.join(self.common_test_dir, '152 index customtarget')
        out = self.init(os.path.join(testdir, 'subdir'), allow_fail=True)

        self.assertIn('first statement must be a call to project()', out)
        # provide guidance diagnostics by finding a file whose first AST statement is project()
        self.assertIn(f'Did you mean to run meson from the directory: "{testdir}"?', out)

    def test_reconfigure_base_options(self):
        testdir = os.path.join(self.unit_test_dir, '122 reconfigure base options')
        out = self.init(testdir, extra_args=['-Db_ndebug=true'])
        self.assertIn('\nMessage: b_ndebug: true\n', out)
        self.assertIn('\nMessage: c_std: c89\n', out)

        out = self.init(testdir, extra_args=['--reconfigure', '-Db_ndebug=if-release', '-Dsub:b_ndebug=false', '-Dc_std=c99', '-Dsub:c_std=c11'])
        self.assertIn('\nMessage: b_ndebug: if-release\n', out)
        self.assertIn('\nMessage: c_std: c99\n', out)
        self.assertIn('\nsub| Message: b_ndebug: false\n', out)
        self.assertIn('\nsub| Message: c_std: c11\n', out)

    def test_setup_with_unknown_option(self):
        testdir = os.path.join(self.common_test_dir, '1 trivial')

        for option in ('not_an_option', 'b_not_an_option'):
            out = self.init(testdir, extra_args=['--wipe', f'-D{option}=1'], allow_fail=True)
            self.assertIn(f'ERROR: Unknown options: "{option}"', out)

    def test_configure_new_option(self) -> None:
        """Adding a new option without reconfiguring should work."""
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, '40 options'))
        self.init(testdir)
        with open(os.path.join(testdir, 'meson_options.txt'), 'a', encoding='utf-8') as f:
            f.write("option('new_option', type : 'boolean', value : false)")
        self.setconf('-Dnew_option=true')
        self.assertEqual(self.getconf('new_option'), True)

    def test_configure_removed_option(self) -> None:
        """Removing an options without reconfiguring should still give an error."""
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, '40 options'))
        self.init(testdir)
        with open(os.path.join(testdir, 'meson_options.txt'), 'r', encoding='utf-8') as f:
            opts = f.readlines()
        with open(os.path.join(testdir, 'meson_options.txt'), 'w', encoding='utf-8') as f:
            for line in opts:
                if line.startswith("option('neg'"):
                    continue
                f.write(line)
        with self.assertRaises(subprocess.CalledProcessError) as e:
            self.setconf('-Dneg_int_opt=0')
        self.assertIn('Unknown options: "neg_int_opt"', e.exception.stdout)

    def test_configure_option_changed_constraints(self) -> None:
        """Changing the constraints of an option without reconfiguring should work."""
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, '40 options'))
        self.init(testdir)
        with open(os.path.join(testdir, 'meson_options.txt'), 'r', encoding='utf-8') as f:
            opts = f.readlines()
        with open(os.path.join(testdir, 'meson_options.txt'), 'w', encoding='utf-8') as f:
            for line in opts:
                if line.startswith("option('neg'"):
                    f.write("option('neg_int_opt', type : 'integer', min : -10, max : 10, value : -3)\n")
                else:
                    f.write(line)
        self.setconf('-Dneg_int_opt=-10')
        self.assertEqual(self.getconf('neg_int_opt'), -10)

    def test_configure_meson_options_txt_to_meson_options(self) -> None:
        """Changing from a meson_options.txt to meson.options should still be detected."""
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, '40 options'))
        self.init(testdir)
        with open(os.path.join(testdir, 'meson_options.txt'), 'r', encoding='utf-8') as f:
            opts = f.readlines()
        with open(os.path.join(testdir, 'meson_options.txt'), 'w', encoding='utf-8') as f:
            for line in opts:
                if line.startswith("option('neg'"):
                    f.write("option('neg_int_opt', type : 'integer', min : -10, max : 10, value : -3)\n")
                else:
                    f.write(line)
        shutil.move(os.path.join(testdir, 'meson_options.txt'), os.path.join(testdir, 'meson.options'))
        self.setconf('-Dneg_int_opt=-10')
        self.assertEqual(self.getconf('neg_int_opt'), -10)

    def test_configure_options_file_deleted(self) -> None:
        """Deleting all option files should make seting a project option an error."""
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, '40 options'))
        self.init(testdir)
        os.unlink(os.path.join(testdir, 'meson_options.txt'))
        with self.assertRaises(subprocess.CalledProcessError) as e:
            self.setconf('-Dneg_int_opt=0')
        self.assertIn('Unknown options: "neg_int_opt"', e.exception.stdout)

    def test_configure_options_file_added(self) -> None:
        """A new project option file should be detected."""
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, '1 trivial'))
        self.init(testdir)
        with open(os.path.join(testdir, 'meson.options'), 'w', encoding='utf-8') as f:
            f.write("option('new_option', type : 'string', value : 'foo')")
        self.setconf('-Dnew_option=bar')
        self.assertEqual(self.getconf('new_option'), 'bar')

    def test_configure_options_file_added_old(self) -> None:
        """A new project option file should be detected."""
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, '1 trivial'))
        self.init(testdir)
        with open(os.path.join(testdir, 'meson_options.txt'), 'w', encoding='utf-8') as f:
            f.write("option('new_option', type : 'string', value : 'foo')")
        self.setconf('-Dnew_option=bar')
        self.assertEqual(self.getconf('new_option'), 'bar')

    def test_configure_new_option_subproject(self) -> None:
        """Adding a new option to a subproject without reconfiguring should work."""
        testdir = self.copy_srcdir(os.path.join(self.common_test_dir, '43 subproject options'))
        self.init(testdir)
        with open(os.path.join(testdir, 'subprojects/subproject/meson_options.txt'), 'a', encoding='utf-8') as f:
            f.write("option('new_option', type : 'boolean', value : false)")
        self.setconf('-Dsubproject:new_option=true')
        self.assertEqual(self.getconf('subproject:new_option'), True)
```