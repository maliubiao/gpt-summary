Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Skim and Contextual Understanding:**

* **File Path:**  `frida/subprojects/frida-gum/releng/meson/unittests/allplatformstests.py` - This immediately tells us it's part of the Frida project, specifically the "gum" component, related to "releng" (release engineering), uses the Meson build system, and contains unit tests that should run on all platforms.
* **Frida:** Knowing Frida is a dynamic instrumentation toolkit is crucial. This means the tests likely involve interacting with running processes, modifying code, and inspecting memory.
* **Meson:**  Meson is the build system. This implies the code will be testing how Frida's build process works under different scenarios and configurations.
* **"allplatformstests.py":**  This signifies that the tests within are designed to be platform-agnostic to a large extent, although platform-specific checks and skips might exist.

**2. High-Level Functional Areas (Based on Imports and Class Name):**

* **`AllPlatformTests(BasePlatformTests)`:** This inheritance structure points to a common testing framework. `BasePlatformTests` likely provides shared setup and utility functions for platform testing.
* **Imports:**  The imports provide clues about the functionalities being tested. We see modules related to:
    * **Core Python:** `subprocess`, `re`, `json`, `tempfile`, `textwrap`, `os`, `shutil`, `platform`, `pickle`, `zipfile`, `tarfile`, `sys`, `unittest`, `contextlib`, `glob`, `pathlib`, `typing`. This indicates tests involving file system operations, process execution, data manipulation, and general utility functions.
    * **Meson Specific:** `mesonbuild.*`. This is a strong indicator that a significant part of the testing revolves around Meson's features like build options, configuration files, dependencies, targets, introspection, and installation.
    * **Frida Specific (Implicit):** Although no explicit `frida.*` imports are present *in this snippet*, the file path and context strongly imply that the tests, while using Meson, ultimately validate aspects of Frida's build and potentially some of its core functionalities.

**3. Detailed Code Analysis (Iterating Through Functions and Methods):**

* **Helper Functions:**  `temp_filename`, `git_init`, `_git_add_all`. These are utility functions for setting up test environments. `temp_filename` is for creating temporary files, and the git-related functions suggest testing scenarios involving version control.
* **`AllPlatformTests` Class Methods (and their potential relation to Frida and reverse engineering):**

    * **`test_default_options_prefix`:** Testing if setting a default installation prefix works. *Indirectly related to reverse engineering* as proper installation paths are important for tools like Frida to function correctly after being built.
    * **`test_do_conf_file_preserve_newlines`, `test_do_conf_file_by_format`:** Testing the generation of configuration files, a common step in build processes. *Indirectly related* as configuration can influence how Frida is built and how it interacts with target processes.
    * **`test_absolute_prefix_libdir`, `test_libdir_can_be_outside_prefix`, `test_prefix_dependent_defaults`, `test_default_options_prefix_dependent_defaults`:** These test various aspects of setting installation directories. *Indirectly related* for the same reason as `test_default_options_prefix`.
    * **`test_clike_get_library_dirs`:** Tests retrieval of library directories. *Potentially related to reverse engineering* because Frida might need to locate libraries in the target system.
    * **`test_static_library_overwrite`, `test_static_compile_order`:** Testing aspects of static library creation. *Indirectly related* as Frida might be built with or link against static libraries.
    * **`test_replace_unencodable_xml_chars`, `test_replace_unencodable_xml_chars_unit`:** Testing the handling of special characters in XML output (likely for test reports). *Less direct relation* to core Frida functionality, but important for tooling.
    * **`test_run_target_files_path`, `test_run_target_subdir`:** Testing the execution of custom build targets. *Potentially related* if Frida's build process involves custom steps.
    * **`test_install_introspection`, `test_install_subdir_introspection`, `test_install_introspection_multiple_outputs`:**  Testing Meson's ability to inspect installation information. *Important for reverse engineering workflows* as it helps understand where Frida's components are placed after installation.
    * **`read_install_logs`, `test_install_log_content`:** Testing the logging of installed files. *Helpful for debugging installation issues.*
    * **`test_uninstall`:** Testing the uninstallation process. *Basic software management.*
    * **`test_forcefallback`, `test_implicit_forcefallback`, `test_nopromote`, `test_force_fallback_for`, `test_force_fallback_for_nofallback`:** These tests focus on dependency management with Meson's "wrap" feature. *Indirectly related* as Frida likely has dependencies.
    * **`test_testrepeat`, `test_verbose`, `test_long_output`, `test_testsetups`:** These tests are about the execution and reporting of unit tests themselves. *Crucial for the development and maintenance of Frida.*

**4. Identifying Relationships to Reverse Engineering, Binaries, Kernels, and Frameworks:**

* **Reverse Engineering:** Look for tests that involve:
    * **Installation paths:**  Important for locating Frida's tools and libraries.
    * **Dependency handling:** Understanding Frida's dependencies can be relevant for setting up reverse engineering environments.
    * **Execution of targets:**  While not directly reverse engineering, testing custom build steps might involve tools used in the process.
* **Binary/Low-Level:** Look for tests that touch upon:
    * **Static libraries:**  How Frida is linked can affect its behavior.
    * **Compiler flags/options (implicit):** While not explicitly in this snippet, Meson tests often involve testing different compiler settings.
* **Linux/Android Kernel/Framework:**  While the tests aim to be cross-platform, the presence of terms like "prefix," "bindir," "libdir" suggests a focus on traditional Unix-like directory structures, which are relevant to Linux and Android. However, *this specific snippet doesn't show direct interaction with kernel or framework code*.

**5. Logical Reasoning and Examples:**

* For tests involving configuration or installation, imagine different input values (e.g., different prefix paths) and predict the resulting configuration or installed file locations.

**6. Common User Errors:**

*  Think about incorrect command-line arguments, misconfigured build files, or issues with dependencies that users might encounter when building Frida. Some tests (like those with `--wrap-mode`) directly address these scenarios.

**7. Tracing User Actions to the Code:**

*  Imagine a user running `meson setup`, `meson build`, or `meson install` with various options. The tests simulate these actions internally to ensure they work correctly.

**8. Summarization:**

* Finally, synthesize the findings into a concise summary of the file's purpose and key functionalities.

This iterative process of skimming, identifying high-level areas, detailed analysis, and then connecting the code to the broader context of Frida and reverse engineering allows for a comprehensive understanding of the provided code snippet.
这是 frida 动态 instrumentation tool 的源代码文件 `allplatformstests.py` 的第一部分，该文件包含了跨平台的单元测试。 让我们来归纳一下它的功能：

**总体功能：**

这个文件定义了一个名为 `AllPlatformTests` 的 Python 类，它继承自 `BasePlatformTests`。这个类的主要目的是包含一系列单元测试，这些测试旨在验证 frida 构建系统（使用 Meson）在各种平台上的核心功能和行为是否正确。 由于 Frida 需要在不同的操作系统上运行，因此需要确保构建过程和相关功能在所有支持的平台上都能正常工作。

**具体功能点归纳：**

1. **构建系统基础功能测试:**
   - **默认选项 (Default Options):** 测试在 `project()` 中设置默认选项（例如安装前缀 `--prefix`）是否生效。
   - **配置文件 (Configuration Files):** 测试 `do_conf_file` 和 `do_conf_str` 函数，用于生成配置文件，并验证其是否能正确处理换行符和不同的格式 (meson, cmake)。
   - **安装目录 (Installation Directories):** 测试设置绝对路径的安装前缀 (`--prefix`) 和库目录 (`--libdir`) 是否有效，以及库目录是否可以位于前缀之外。
   - **前缀依赖的默认值 (Prefix Dependent Defaults):** 测试当设置安装前缀时，其他相关目录（如 `bindir`, `datadir` 等）是否会设置为相应的默认值。

2. **编译器和链接器行为测试:**
   - **库目录 (Library Directories):** 测试如何获取 C 语言编译器的库目录。
   - **静态库处理 (Static Library Handling):** 测试静态库是否会被正确覆盖而不是追加内容。
   - **编译顺序 (Compile Order):** 测试静态编译和链接时的文件顺序是否是确定的。

3. **输出处理和报告:**
   - **XML 字符处理 (XML Character Handling):** 测试如何替换 XML 中无法编码的字符，确保测试报告的正确性。

4. **运行目标 (Run Targets) 测试:**
   - **运行目录 (Working Directory):** 测试 `run_target` 命令是否在正确的目录下执行目标。

5. **安装相关测试:**
   - **安装信息 (Install Introspection):** 测试 Meson introspection API 是否能正确暴露安装的文件名和目录。
   - **安装日志 (Install Log):** 测试安装日志文件 (`install-log.txt`) 的内容是否与实际安装的文件和目录一致，并验证 `--dry-run` 模式。
   - **卸载 (Uninstall):** 测试卸载功能是否能正确移除已安装的文件和目录。

6. **依赖管理 (Dependency Management) 测试 (通过 Meson Wrap 功能):**
   - **强制回退 (Force Fallback):** 测试在依赖查找失败时，强制使用 wrap 提供的构建定义。
   - **禁止提升 (No Promote):** 测试禁止将 wrap 定义的依赖提升为系统依赖。

7. **测试执行 (Test Execution) 相关测试:**
   - **重复测试 (Test Repeat):** 测试重复运行测试的功能。
   - **详细输出 (Verbose Output):** 测试显示详细测试输出的功能。
   - **长输出处理 (Long Output Handling):** 测试如何处理测试产生的长输出。
   - **测试设置 (Test Setups):** 测试在运行测试前执行设置脚本的功能 (例如使用 Valgrind)。

**与逆向方法的关系：**

虽然这个文件主要关注构建系统的测试，但它间接与逆向方法有关，因为：

* **Frida 是一个逆向工具:**  确保 Frida 能在各种平台上正确构建是其正常运行的基础。
* **安装路径和依赖:** 准确的安装路径和依赖关系对于 Frida 的使用至关重要。逆向工程师需要知道 Frida 的工具和库安装在哪里才能正确使用。例如，测试 `--prefix` 和 `--libdir` 确保了 Frida 的核心组件可以被找到。
* **测试执行:** 单元测试保证了 Frida 核心功能的正确性，这对于依赖 Frida 进行逆向分析的工程师来说非常重要。

**涉及到二进制底层，Linux, Android 内核及框架的知识的说明：**

* **二进制底层:**
    * **静态库处理:** 测试静态库的覆盖行为涉及到底层链接器 (`ar`) 的工作方式，以及如何将目标文件 (`.o`, `.obj`) 打包到静态库中。
    * **编译顺序:**  测试编译顺序涉及到编译器如何处理源文件，这会影响到最终生成的目标代码。
* **Linux/Android 内核及框架:**
    * **安装路径:** 像 `/usr/bin`, `/usr/lib`, `/usr/share` 这样的路径是典型的 Linux 和类 Unix 系统的标准目录结构，Android 也继承了类似的概念。测试这些路径确保 Frida 可以按照预期安装到这些位置。
    * **依赖管理:**  Linux 和 Android 系统都有自己的依赖管理机制。Meson 的 wrap 功能尝试在构建时解决依赖问题，这对于跨平台构建至关重要。
    * **运行目标:** 测试运行目标涉及到在 shell 中执行命令，这与操作系统底层的进程管理有关。

**逻辑推理，假设输入与输出：**

* **测试 `test_default_options_prefix`:**
    * **假设输入:** 在 `meson.build` 文件中设置 `project('myproject', default_options: ['prefix=/absoluteprefix'])`。
    * **预期输出:** 通过 introspection API 查询构建选项，`prefix` 的值应为 `/absoluteprefix`。

* **测试 `test_do_conf_file_preserve_newlines`:**
    * **假设输入:**
        * `in_data`: "@VAR@\n@VAR@\n"
        * `confdata`: `{'VAR': ('foo', 'bar')}`
    * **预期输出:** 生成的配置文件内容为 "foo\nfoo\n"，保留了原始的换行符。

**涉及用户或者编程常见的使用错误，举例说明：**

* **错误的安装路径:** 用户可能错误地指定了 `--prefix` 或 `--libdir` 导致 Frida 安装到了不正确的位置，这会导致 Frida 的工具无法找到所需的库文件。`test_absolute_prefix_libdir` 等测试可以帮助发现构建系统在处理这些路径时的错误。
* **依赖问题:** 用户可能没有安装 Frida 的某些依赖项，或者依赖项的版本不正确。`test_forcefallback` 等测试模拟了在依赖查找失败时的情况，帮助开发者确保构建系统能够优雅地处理这些问题。
* **配置文件错误:**  如果配置文件模板 (`.in` 文件) 中使用了错误的变量或者格式，`test_do_conf_file_by_format` 可以帮助捕获这些错误。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发者修改了 Frida 的构建系统 (`meson.build` 或相关文件)。**
2. **为了验证修改的正确性，开发者运行 Meson 的单元测试。**  这通常通过类似 `meson test` 或特定的测试命令来完成。
3. **Meson 测试框架会加载 `allplatformstests.py` 文件。**
4. **框架会执行 `AllPlatformTests` 类中定义的各个 `test_` 开头的方法。**
5. **如果某个测试失败，开发者会查看测试的输出和日志，以及相关的源代码 (`allplatformstests.py`) 来定位问题。**  例如，如果 `test_default_options_prefix` 失败，开发者会检查 `meson.build` 中 `default_options` 的设置以及 Meson 如何处理这个选项。

**总结：**

`allplatformstests.py` 的第一部分主要负责测试 Frida 构建系统的核心功能，包括选项处理、配置文件生成、安装路径管理、编译器和链接器行为、输出处理、安装和卸载流程以及依赖管理。 这些测试覆盖了构建过程的多个方面，确保 Frida 可以在各种平台上正确构建和安装，这对于 Frida 的正常使用和逆向分析工作至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2021 The Meson development team

import subprocess
import re
import json
import tempfile
import textwrap
import os
import shutil
import platform
import pickle
import zipfile, tarfile
import sys
from unittest import mock, SkipTest, skipIf, skipUnless
from contextlib import contextmanager
from glob import glob
from pathlib import (PurePath, Path)
import typing as T

import mesonbuild.mlog
import mesonbuild.depfile
import mesonbuild.dependencies.base
import mesonbuild.dependencies.factory
import mesonbuild.envconfig
import mesonbuild.environment
import mesonbuild.coredata
import mesonbuild.modules.gnome
from mesonbuild.mesonlib import (
    BuildDirLock, MachineChoice, is_windows, is_osx, is_cygwin, is_dragonflybsd,
    is_sunos, windows_proof_rmtree, python_command, version_compare, split_args, quote_arg,
    relpath, is_linux, git, search_version, do_conf_file, do_conf_str, default_prefix,
    MesonException, EnvironmentException, OptionKey,
    windows_proof_rm
)
from mesonbuild.programs import ExternalProgram

from mesonbuild.compilers.mixins.clang import ClangCompiler
from mesonbuild.compilers.mixins.gnu import GnuCompiler
from mesonbuild.compilers.mixins.intel import IntelGnuLikeCompiler
from mesonbuild.compilers.c import VisualStudioCCompiler, ClangClCCompiler
from mesonbuild.compilers.cpp import VisualStudioCPPCompiler, ClangClCPPCompiler
from mesonbuild.compilers import (
    detect_static_linker, detect_c_compiler, compiler_from_language,
    detect_compiler_for
)
from mesonbuild.linkers import linkers

from mesonbuild.dependencies.pkgconfig import PkgConfigDependency
from mesonbuild.build import Target, ConfigurationData, Executable, SharedLibrary, StaticLibrary
from mesonbuild import mtest
import mesonbuild.modules.pkgconfig
from mesonbuild.scripts import destdir_join

from mesonbuild.wrap.wrap import PackageDefinition, WrapException

from run_tests import (
    Backend, exe_suffix, get_fake_env, get_convincing_fake_env_and_cc
)

from .baseplatformtests import BasePlatformTests
from .helpers import *

@contextmanager
def temp_filename():
    '''A context manager which provides a filename to an empty temporary file.

    On exit the file will be deleted.
    '''

    fd, filename = tempfile.mkstemp()
    os.close(fd)
    try:
        yield filename
    finally:
        try:
            os.remove(filename)
        except OSError:
            pass

def git_init(project_dir):
    # If a user has git configuration init.defaultBranch set we want to override that
    with tempfile.TemporaryDirectory() as d:
        out = git(['--version'], str(d))[1]
    if version_compare(search_version(out), '>= 2.28'):
        extra_cmd = ['--initial-branch', 'master']
    else:
        extra_cmd = []

    subprocess.check_call(['git', 'init'] + extra_cmd, cwd=project_dir, stdout=subprocess.DEVNULL)
    subprocess.check_call(['git', 'config',
                           'user.name', 'Author Person'], cwd=project_dir)
    subprocess.check_call(['git', 'config',
                           'user.email', 'teh_coderz@example.com'], cwd=project_dir)
    _git_add_all(project_dir)

def _git_add_all(project_dir):
    subprocess.check_call('git add *', cwd=project_dir, shell=True,
                          stdout=subprocess.DEVNULL)
    subprocess.check_call(['git', 'commit', '--no-gpg-sign', '-a', '-m', 'I am a project'], cwd=project_dir,
                          stdout=subprocess.DEVNULL)

class AllPlatformTests(BasePlatformTests):
    '''
    Tests that should run on all platforms
    '''

    def test_default_options_prefix(self):
        '''
        Tests that setting a prefix in default_options in project() works.
        Can't be an ordinary test because we pass --prefix to meson there.
        https://github.com/mesonbuild/meson/issues/1349
        '''
        testdir = os.path.join(self.common_test_dir, '87 default options')
        self.init(testdir, default_args=False, inprocess=True)
        opts = self.introspect('--buildoptions')
        for opt in opts:
            if opt['name'] == 'prefix':
                prefix = opt['value']
                break
        else:
            raise self.fail('Did not find option "prefix"')
        self.assertEqual(prefix, '/absoluteprefix')

    def test_do_conf_file_preserve_newlines(self):

        def conf_file(in_data, confdata):
            with temp_filename() as fin:
                with open(fin, 'wb') as fobj:
                    fobj.write(in_data.encode('utf-8'))
                with temp_filename() as fout:
                    do_conf_file(fin, fout, confdata, 'meson')
                    with open(fout, 'rb') as fobj:
                        return fobj.read().decode('utf-8')

        confdata = {'VAR': ('foo', 'bar')}
        self.assertEqual(conf_file('@VAR@\n@VAR@\n', confdata), 'foo\nfoo\n')
        self.assertEqual(conf_file('@VAR@\r\n@VAR@\r\n', confdata), 'foo\r\nfoo\r\n')

    def test_do_conf_file_by_format(self):
        def conf_str(in_data, confdata, vformat):
            (result, missing_variables, confdata_useless) = do_conf_str('configuration_file', in_data, confdata, variable_format = vformat)
            return '\n'.join(result)

        def check_meson_format(confdata, result):
            self.assertEqual(conf_str(['#mesondefine VAR'], confdata, 'meson'), result)

        def check_cmake_format_simple(confdata, result):
            self.assertEqual(conf_str(['#cmakedefine VAR'], confdata, 'cmake'), result)

        def check_cmake_formats_full(confdata, result):
            self.assertEqual(conf_str(['#cmakedefine VAR ${VAR}'], confdata, 'cmake'), result)
            self.assertEqual(conf_str(['#cmakedefine VAR @VAR@'], confdata, 'cmake@'), result)

        def check_formats(confdata, result):
            check_meson_format(confdata, result)
            check_cmake_formats_full(confdata, result)

        confdata = ConfigurationData()
        # Key error as they do not exists
        check_formats(confdata, '/* #undef VAR */\n')

        # Check boolean
        confdata.values = {'VAR': (False, 'description')}
        check_meson_format(confdata, '#undef VAR\n')
        check_cmake_formats_full(confdata, '/* #undef VAR */\n')

        confdata.values = {'VAR': (True, 'description')}
        check_meson_format(confdata, '#define VAR\n')
        check_cmake_format_simple(confdata, '#define VAR\n')
        check_cmake_formats_full(confdata, '#define VAR 1\n')

        # Check string
        confdata.values = {'VAR': ('value', 'description')}
        check_formats(confdata, '#define VAR value\n')

        # Check integer
        confdata.values = {'VAR': (10, 'description')}
        check_formats(confdata, '#define VAR 10\n')

        # Checking if cmakedefine behaves as it does with cmake
        confdata.values = {'VAR': ("var", 'description')}
        self.assertEqual(conf_str(['#cmakedefine VAR @VAR@'], confdata, 'cmake@'), '#define VAR var\n')

        confdata.values = {'VAR': (True, 'description')}
        self.assertEqual(conf_str(['#cmakedefine01 VAR'], confdata, 'cmake'), '#define VAR 1\n')

        confdata.values = {'VAR': (0, 'description')}
        self.assertEqual(conf_str(['#cmakedefine01 VAR'], confdata, 'cmake'), '#define VAR 0\n')
        confdata.values = {'VAR': (False, 'description')}
        self.assertEqual(conf_str(['#cmakedefine01 VAR'], confdata, 'cmake'), '#define VAR 0\n')

        confdata.values = {}
        self.assertEqual(conf_str(['#cmakedefine01 VAR'], confdata, 'cmake'), '#define VAR 0\n')
        self.assertEqual(conf_str(['#cmakedefine VAR @VAR@'], confdata, 'cmake@'), '/* #undef VAR */\n')

        confdata.values = {'VAR': (5, 'description')}
        self.assertEqual(conf_str(['#cmakedefine VAR'], confdata, 'cmake'), '#define VAR\n')

        # Check multiple string with cmake formats
        confdata.values = {'VAR': ('value', 'description')}
        self.assertEqual(conf_str(['#cmakedefine VAR xxx @VAR@ yyy @VAR@'], confdata, 'cmake@'), '#define VAR xxx value yyy value\n')
        self.assertEqual(conf_str(['#define VAR xxx @VAR@ yyy @VAR@'], confdata, 'cmake@'), '#define VAR xxx value yyy value')
        self.assertEqual(conf_str(['#cmakedefine VAR xxx ${VAR} yyy ${VAR}'], confdata, 'cmake'), '#define VAR xxx value yyy value\n')
        self.assertEqual(conf_str(['#define VAR xxx ${VAR} yyy ${VAR}'], confdata, 'cmake'), '#define VAR xxx value yyy value')

        # Handles meson format exceptions
        #   Unknown format
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR xxx'], confdata, 'unknown_format')
        #   More than 2 params in mesondefine
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR xxx'], confdata, 'meson')
        #   Mismatched line with format
        self.assertRaises(MesonException, conf_str, ['#cmakedefine VAR'], confdata, 'meson')
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR'], confdata, 'cmake')
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR'], confdata, 'cmake@')
        #   Dict value in confdata
        confdata.values = {'VAR': (['value'], 'description')}
        self.assertRaises(MesonException, conf_str, ['#mesondefine VAR'], confdata, 'meson')

    def test_absolute_prefix_libdir(self):
        '''
        Tests that setting absolute paths for --prefix and --libdir work. Can't
        be an ordinary test because these are set via the command-line.
        https://github.com/mesonbuild/meson/issues/1341
        https://github.com/mesonbuild/meson/issues/1345
        '''
        testdir = os.path.join(self.common_test_dir, '87 default options')
        # on Windows, /someabs is *not* an absolute path
        prefix = 'x:/someabs' if is_windows() else '/someabs'
        libdir = 'libdir'
        extra_args = ['--prefix=' + prefix,
                      # This can just be a relative path, but we want to test
                      # that passing this as an absolute path also works
                      '--libdir=' + prefix + '/' + libdir]
        self.init(testdir, extra_args=extra_args, default_args=False)
        opts = self.introspect('--buildoptions')
        for opt in opts:
            if opt['name'] == 'prefix':
                self.assertEqual(prefix, opt['value'])
            elif opt['name'] == 'libdir':
                self.assertEqual(libdir, opt['value'])

    def test_libdir_can_be_outside_prefix(self):
        '''
        Tests that libdir is allowed to be outside prefix.
        Must be a unit test for obvious reasons.
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        # libdir being inside prefix is ok
        if is_windows():
            args = ['--prefix', 'x:/opt', '--libdir', 'x:/opt/lib32']
        else:
            args = ['--prefix', '/opt', '--libdir', '/opt/lib32']
        self.init(testdir, extra_args=args)
        self.wipe()
        # libdir not being inside prefix is ok too
        if is_windows():
            args = ['--prefix', 'x:/usr', '--libdir', 'x:/opt/lib32']
        else:
            args = ['--prefix', '/usr', '--libdir', '/opt/lib32']
        self.init(testdir, extra_args=args)
        self.wipe()
        # libdir can be outside prefix even when set via mesonconf
        self.init(testdir)
        if is_windows():
            self.setconf('-Dlibdir=x:/opt', will_build=False)
        else:
            self.setconf('-Dlibdir=/opt', will_build=False)

    def test_prefix_dependent_defaults(self):
        '''
        Tests that configured directory paths are set to prefix dependent
        defaults.
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        expected = {
            '/opt': {'prefix': '/opt',
                     'bindir': 'bin', 'datadir': 'share', 'includedir': 'include',
                     'infodir': 'share/info',
                     'libexecdir': 'libexec', 'localedir': 'share/locale',
                     'localstatedir': 'var', 'mandir': 'share/man',
                     'sbindir': 'sbin', 'sharedstatedir': 'com',
                     'sysconfdir': 'etc'},
            '/usr': {'prefix': '/usr',
                     'bindir': 'bin', 'datadir': 'share', 'includedir': 'include',
                     'infodir': 'share/info',
                     'libexecdir': 'libexec', 'localedir': 'share/locale',
                     'localstatedir': '/var', 'mandir': 'share/man',
                     'sbindir': 'sbin', 'sharedstatedir': '/var/lib',
                     'sysconfdir': '/etc'},
            '/usr/local': {'prefix': '/usr/local',
                           'bindir': 'bin', 'datadir': 'share',
                           'includedir': 'include', 'infodir': 'share/info',
                           'libexecdir': 'libexec',
                           'localedir': 'share/locale',
                           'localstatedir': '/var/local', 'mandir': 'share/man',
                           'sbindir': 'sbin', 'sharedstatedir': '/var/local/lib',
                           'sysconfdir': 'etc'},
            # N.B. We don't check 'libdir' as it's platform dependent, see
            # default_libdir():
        }

        if default_prefix() == '/usr/local':
            expected[None] = expected['/usr/local']

        for prefix in expected:
            args = []
            if prefix:
                args += ['--prefix', prefix]
            self.init(testdir, extra_args=args, default_args=False)
            opts = self.introspect('--buildoptions')
            for opt in opts:
                name = opt['name']
                value = opt['value']
                if name in expected[prefix]:
                    self.assertEqual(value, expected[prefix][name])
            self.wipe()

    def test_default_options_prefix_dependent_defaults(self):
        '''
        Tests that setting a prefix in default_options in project() sets prefix
        dependent defaults for other options, and that those defaults can
        be overridden in default_options or by the command line.
        '''
        testdir = os.path.join(self.common_test_dir, '163 default options prefix dependent defaults')
        expected = {
            '':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/sharedstate'},
            '--prefix=/usr':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/sharedstate'},
            '--sharedstatedir=/var/state':
            {'prefix':         '/usr',
             'sysconfdir':     '/etc',
             'localstatedir':  '/var',
             'sharedstatedir': '/var/state'},
            '--sharedstatedir=/var/state --prefix=/usr --sysconfdir=sysconf':
            {'prefix':         '/usr',
             'sysconfdir':     'sysconf',
             'localstatedir':  '/var',
             'sharedstatedir': '/var/state'},
        }
        for args in expected:
            self.init(testdir, extra_args=args.split(), default_args=False)
            opts = self.introspect('--buildoptions')
            for opt in opts:
                name = opt['name']
                value = opt['value']
                if name in expected[args]:
                    self.assertEqual(value, expected[args][name])
            self.wipe()

    def test_clike_get_library_dirs(self):
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        for d in cc.get_library_dirs(env):
            self.assertTrue(os.path.exists(d))
            self.assertTrue(os.path.isdir(d))
            self.assertTrue(os.path.isabs(d))

    def test_static_library_overwrite(self):
        '''
        Tests that static libraries are never appended to, always overwritten.
        Has to be a unit test because this involves building a project,
        reconfiguring, and building it again so that `ar` is run twice on the
        same static library.
        https://github.com/mesonbuild/meson/issues/1355
        '''
        testdir = os.path.join(self.common_test_dir, '3 static')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        static_linker = detect_static_linker(env, cc)
        if is_windows():
            raise SkipTest('https://github.com/mesonbuild/meson/issues/1526')
        if not isinstance(static_linker, linkers.ArLinker):
            raise SkipTest('static linker is not `ar`')
        # Configure
        self.init(testdir)
        # Get name of static library
        targets = self.introspect('--targets')
        self.assertGreaterEqual(len(targets), 1)
        libname = targets[0]['filename'][0]
        # Build and get contents of static library
        self.build()
        before = self._run(['ar', 't', os.path.join(self.builddir, libname)]).split()
        # Filter out non-object-file contents
        before = [f for f in before if f.endswith(('.o', '.obj'))]
        # Static library should contain only one object
        self.assertEqual(len(before), 1, msg=before)
        # Change the source to be built into the static library
        self.setconf('-Dsource=libfile2.c')
        self.build()
        after = self._run(['ar', 't', os.path.join(self.builddir, libname)]).split()
        # Filter out non-object-file contents
        after = [f for f in after if f.endswith(('.o', '.obj'))]
        # Static library should contain only one object
        self.assertEqual(len(after), 1, msg=after)
        # and the object must have changed
        self.assertNotEqual(before, after)

    def test_static_compile_order(self):
        '''
        Test that the order of files in a compiler command-line while compiling
        and linking statically is deterministic. This can't be an ordinary test
        case because we need to inspect the compiler database.
        https://github.com/mesonbuild/meson/pull/951
        '''
        testdir = os.path.join(self.common_test_dir, '5 linkstatic')
        self.init(testdir)
        compdb = self.get_compdb()
        # Rules will get written out in this order
        self.assertTrue(compdb[0]['file'].endswith("libfile.c"))
        self.assertTrue(compdb[1]['file'].endswith("libfile2.c"))
        self.assertTrue(compdb[2]['file'].endswith("libfile3.c"))
        self.assertTrue(compdb[3]['file'].endswith("libfile4.c"))
        # FIXME: We don't have access to the linker command

    def test_replace_unencodable_xml_chars(self):
        '''
        Test that unencodable xml chars are replaced with their
        printable representation
        https://github.com/mesonbuild/meson/issues/9894
        '''
        # Create base string(\nHello Meson\n) to see valid chars are not replaced
        base_string_invalid = '\n\x48\x65\x6c\x6c\x6f\x20\x4d\x65\x73\x6f\x6e\n'
        base_string_valid = '\nHello Meson\n'
        # Create invalid input from all known unencodable chars
        invalid_string = (
            '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11'
            '\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x7f'
            '\x80\x81\x82\x83\x84\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f'
            '\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e'
            '\x9f\ufdd0\ufdd1\ufdd2\ufdd3\ufdd4\ufdd5\ufdd6\ufdd7\ufdd8'
            '\ufdd9\ufdda\ufddb\ufddc\ufddd\ufdde\ufddf\ufde0\ufde1'
            '\ufde2\ufde3\ufde4\ufde5\ufde6\ufde7\ufde8\ufde9\ufdea'
            '\ufdeb\ufdec\ufded\ufdee\ufdef\ufffe\uffff')
        if sys.maxunicode >= 0x10000:
            invalid_string = invalid_string + (
                '\U0001fffe\U0001ffff\U0002fffe\U0002ffff'
                '\U0003fffe\U0003ffff\U0004fffe\U0004ffff'
                '\U0005fffe\U0005ffff\U0006fffe\U0006ffff'
                '\U0007fffe\U0007ffff\U0008fffe\U0008ffff'
                '\U0009fffe\U0009ffff\U000afffe\U000affff'
                '\U000bfffe\U000bffff\U000cfffe\U000cffff'
                '\U000dfffe\U000dffff\U000efffe\U000effff'
                '\U000ffffe\U000fffff\U0010fffe\U0010ffff')

        valid_string = base_string_valid + repr(invalid_string)[1:-1] + base_string_valid
        invalid_string = base_string_invalid + invalid_string + base_string_invalid
        fixed_string = mtest.replace_unencodable_xml_chars(invalid_string)
        self.assertEqual(fixed_string, valid_string)

    def test_replace_unencodable_xml_chars_unit(self):
        '''
        Test that unencodable xml chars are replaced with their
        printable representation
        https://github.com/mesonbuild/meson/issues/9894
        '''
        if not shutil.which('xmllint'):
            raise SkipTest('xmllint not installed')
        testdir = os.path.join(self.unit_test_dir, '111 replace unencodable xml chars')
        self.init(testdir)
        tests_command_output = self.run_tests()
        junit_xml_logs = Path(self.logdir, 'testlog.junit.xml')
        subprocess.run(['xmllint', junit_xml_logs], check=True)
        # Ensure command output and JSON / text logs are not mangled.
        raw_output_sample = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b'
        assert raw_output_sample in tests_command_output
        text_log = Path(self.logdir, 'testlog.txt').read_text(encoding='utf-8')
        assert raw_output_sample in text_log
        json_log = json.loads(Path(self.logdir, 'testlog.json').read_bytes())
        assert raw_output_sample in json_log['stdout']

    def test_run_target_files_path(self):
        '''
        Test that run_targets are run from the correct directory
        https://github.com/mesonbuild/meson/issues/957
        '''
        testdir = os.path.join(self.common_test_dir, '51 run target')
        self.init(testdir)
        self.run_target('check_exists')
        self.run_target('check-env')
        self.run_target('check-env-ct')

    def test_run_target_subdir(self):
        '''
        Test that run_targets are run from the correct directory
        https://github.com/mesonbuild/meson/issues/957
        '''
        testdir = os.path.join(self.common_test_dir, '51 run target')
        self.init(testdir)
        self.run_target('textprinter')

    def test_install_introspection(self):
        '''
        Tests that the Meson introspection API exposes install filenames correctly
        https://github.com/mesonbuild/meson/issues/829
        '''
        if self.backend is not Backend.ninja:
            raise SkipTest(f'{self.backend.name!r} backend can\'t install files')
        testdir = os.path.join(self.common_test_dir, '8 install')
        self.init(testdir)
        intro = self.introspect('--targets')
        if intro[0]['type'] == 'executable':
            intro = intro[::-1]
        self.assertPathListEqual(intro[0]['install_filename'], ['/usr/lib/libstat.a'])
        self.assertPathListEqual(intro[1]['install_filename'], ['/usr/bin/prog' + exe_suffix])

    def test_install_subdir_introspection(self):
        '''
        Test that the Meson introspection API also contains subdir install information
        https://github.com/mesonbuild/meson/issues/5556
        '''
        testdir = os.path.join(self.common_test_dir, '59 install subdir')
        self.init(testdir)
        intro = self.introspect('--installed')
        expected = {
            'nested_elided/sub': 'share',
            'new_directory': 'share/new_directory',
            'sub/sub1': 'share/sub1',
            'sub1': 'share/sub1',
            'sub2': 'share/sub2',
            'sub3': '/usr/share/sub3',
            'sub_elided': 'share',
            'subdir/sub1': 'share/sub1',
            'subdir/sub_elided': 'share',
        }

        self.assertEqual(len(intro), len(expected))

        # Convert expected to PurePath
        expected_converted = {PurePath(os.path.join(testdir, key)): PurePath(os.path.join(self.prefix, val)) for key, val in expected.items()}
        intro_converted = {PurePath(key): PurePath(val) for key, val in intro.items()}

        for src, dst in expected_converted.items():
            self.assertIn(src, intro_converted)
            self.assertEqual(dst, intro_converted[src])

    def test_install_introspection_multiple_outputs(self):
        '''
        Tests that the Meson introspection API exposes multiple install filenames correctly without crashing
        https://github.com/mesonbuild/meson/pull/4555

        Reverted to the first file only because of https://github.com/mesonbuild/meson/pull/4547#discussion_r244173438
        TODO Change the format to a list officially in a followup PR
        '''
        if self.backend is not Backend.ninja:
            raise SkipTest(f'{self.backend.name!r} backend can\'t install files')
        testdir = os.path.join(self.common_test_dir, '140 custom target multiple outputs')
        self.init(testdir)
        intro = self.introspect('--targets')
        if intro[0]['type'] == 'executable':
            intro = intro[::-1]
        self.assertPathListEqual(intro[0]['install_filename'], ['/usr/include/diff.h', '/usr/bin/diff.sh'])
        self.assertPathListEqual(intro[1]['install_filename'], ['/opt/same.h', '/opt/same.sh'])
        self.assertPathListEqual(intro[2]['install_filename'], ['/usr/include/first.h', None])
        self.assertPathListEqual(intro[3]['install_filename'], [None, '/usr/bin/second.sh'])

    def read_install_logs(self):
        # Find logged files and directories
        with Path(self.builddir, 'meson-logs', 'install-log.txt').open(encoding='utf-8') as f:
            return list(map(lambda l: Path(l.strip()),
                              filter(lambda l: not l.startswith('#'),
                                     f.readlines())))

    def test_install_log_content(self):
        '''
        Tests that the install-log.txt is consistent with the installed files and directories.
        Specifically checks that the log file only contains one entry per file/directory.
        https://github.com/mesonbuild/meson/issues/4499
        '''
        testdir = os.path.join(self.common_test_dir, '59 install subdir')
        self.init(testdir)
        self.install()
        installpath = Path(self.installdir)
        # Find installed files and directories
        expected = {installpath: 0}
        for name in installpath.rglob('*'):
            expected[name] = 0
        logged = self.read_install_logs()
        for name in logged:
            self.assertTrue(name in expected, f'Log contains extra entry {name}')
            expected[name] += 1

        for name, count in expected.items():
            self.assertGreater(count, 0, f'Log is missing entry for {name}')
            self.assertLess(count, 2, f'Log has multiple entries for {name}')

        # Verify that with --dry-run we obtain the same logs but with nothing
        # actually installed
        windows_proof_rmtree(self.installdir)
        self._run(self.meson_command + ['install', '--dry-run', '--destdir', self.installdir], workdir=self.builddir)
        self.assertEqual(logged, self.read_install_logs())
        self.assertFalse(os.path.exists(self.installdir))

        # If destdir is relative to build directory it should install
        # exactly the same files.
        rel_installpath = os.path.relpath(self.installdir, self.builddir)
        self._run(self.meson_command + ['install', '--dry-run', '--destdir', rel_installpath, '-C', self.builddir])
        self.assertEqual(logged, self.read_install_logs())

    def test_uninstall(self):
        exename = os.path.join(self.installdir, 'usr/bin/prog' + exe_suffix)
        dirname = os.path.join(self.installdir, 'usr/share/dir')
        testdir = os.path.join(self.common_test_dir, '8 install')
        self.init(testdir)
        self.assertPathDoesNotExist(exename)
        self.install()
        self.assertPathExists(exename)
        self.uninstall()
        self.assertPathDoesNotExist(exename)
        self.assertPathDoesNotExist(dirname)

    def test_forcefallback(self):
        testdir = os.path.join(self.unit_test_dir, '31 forcefallback')
        self.init(testdir, extra_args=['--wrap-mode=forcefallback'])
        self.build()
        self.run_tests()

    def test_implicit_forcefallback(self):
        testdir = os.path.join(self.unit_test_dir, '96 implicit force fallback')
        with self.assertRaises(subprocess.CalledProcessError):
            self.init(testdir)
        self.init(testdir, extra_args=['--wrap-mode=forcefallback'])
        self.new_builddir()
        self.init(testdir, extra_args=['--force-fallback-for=something'])

    def test_nopromote(self):
        testdir = os.path.join(self.common_test_dir, '98 subproject subdir')
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(testdir, extra_args=['--wrap-mode=nopromote'])
        self.assertIn('dependency subsub found: NO', cm.exception.stdout)

    def test_force_fallback_for(self):
        testdir = os.path.join(self.unit_test_dir, '31 forcefallback')
        self.init(testdir, extra_args=['--force-fallback-for=zlib,foo'])
        self.build()
        self.run_tests()

    def test_force_fallback_for_nofallback(self):
        testdir = os.path.join(self.unit_test_dir, '31 forcefallback')
        self.init(testdir, extra_args=['--force-fallback-for=zlib,foo', '--wrap-mode=nofallback'])
        self.build()
        self.run_tests()

    def test_testrepeat(self):
        testdir = os.path.join(self.common_test_dir, '206 tap tests')
        self.init(testdir)
        self.build()
        self._run(self.mtest_command + ['--repeat=2'])

    def test_verbose(self):
        testdir = os.path.join(self.common_test_dir, '206 tap tests')
        self.init(testdir)
        self.build()
        out = self._run(self.mtest_command + ['--suite', 'verbose'])
        self.assertIn('1/1 subtest 1', out)

    def test_long_output(self):
        testdir = os.path.join(self.common_test_dir, '254 long output')
        self.init(testdir)
        self.build()
        self.run_tests()

        # Ensure lines are found from testlog.txt when not being verbose.

        i = 1
        with open(os.path.join(self.logdir, 'testlog.txt'), encoding='utf-8') as f:
            line = f.readline()
            while line and i < 100001:
                if f'# Iteration {i} to stdout' in line:
                    i += 1
                line = f.readline()
            self.assertEqual(i, 100001)

            i = 1
            while line:
                if f'# Iteration {i} to stderr' in line:
                    i += 1
                line = f.readline()
        self.assertEqual(i, 100001)

        # Ensure lines are found from both testlog.txt and console when being verbose.

        out = self._run(self.mtest_command + ['-v'])
        i = 1
        with open(os.path.join(self.logdir, 'testlog.txt'), encoding='utf-8') as f:
            line = f.readline()
            while line and i < 100001:
                if f'# Iteration {i} to stdout' in line:
                    i += 1
                line = f.readline()
            self.assertEqual(i, 100001)

            i = 1
            while line:
                if f'# Iteration {i} to stderr' in line:
                    i += 1
                line = f.readline()
        self.assertEqual(i, 100001)

        lines = out.split('\n')
        line_number = 0
        i = 1
        while line_number < len(lines) and i < 100001:
            print('---> %s' % lines[line_number])
            if f'# Iteration {i} to stdout' in lines[line_number]:
                i += 1
            line_number += 1
        self.assertEqual(i, 100001)

        line_number = 0
        i = 1
        while line_number < len(lines):
            if f'# Iteration {i} to stderr' in lines[line_number]:
                i += 1
            line_number += 1
        self.assertEqual(i, 100001)


    def test_testsetups(self):
        if not shutil.which('valgrind'):
            raise SkipTest('Valgrind not installed.')
        testdir = os.path.join(self.unit_test_dir, '2 testsetups')
        self.init(testdir)
        self.build()
        # Run tests without setup
        self.run_tests()
        with open(os.path.join(self.logdir, 'testlog.txt'), encoding='utf-8') as f:
            basic_log = f.read()
        # Run buggy test with setup that has env that will make it fail
        self.assertRaises(subprocess.CalledProcessError,
                          self._run, self.mtest_command + ['--setup=valgrind'])
        with open(os.path.join(self.logdir, 'testlog-valgrind.txt'), encoding='utf-8') as f:
            vg_log = f.read()
```