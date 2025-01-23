Response:
The user wants to understand the functionality of the provided Python script `allplatformstests.py`. This script is part of the Frida dynamic instrumentation tool's test suite, specifically for tests that should run on all platforms.

To address the user's request, I need to:

1. **Summarize the script's purpose:** It contains unit tests for Meson, the build system used by Frida.
2. **Identify relationships with reverse engineering:** While the script itself doesn't perform reverse engineering, it tests features of Meson that are crucial for building and managing reverse engineering tools like Frida.
3. **Pinpoint interactions with low-level systems:** The script tests Meson's ability to handle different operating systems, compilers, and build configurations, including those relevant to Linux and Android kernels.
4. **Analyze logical reasoning:** Some tests involve setting up configurations and asserting expected outcomes, which constitutes logical reasoning. I'll provide examples with hypothetical inputs and outputs.
5. **Recognize common user errors:**  The tests implicitly cover scenarios where users might misconfigure their build environment or project files. I need to provide examples of such errors.
6. **Trace user actions leading to this code:** This script is executed as part of the Meson test suite, typically during development or when verifying the build system's integrity.
7. **Finally, provide a concise summary of the script's functionality.**

**Plan:**

- Go through the code section by section, identifying the purpose of each test function.
- Relate the tested functionalities to reverse engineering concepts, low-level system interactions, and potential user errors.
- Formulate examples of logical reasoning, input/output scenarios, and common user mistakes.
- Describe the standard development workflow that would lead to the execution of this script.
- Combine the findings into a comprehensive yet concise summary.
好的，我们来分析一下 `frida/subprojects/frida-qml/releng/meson/unittests/allplatformstests.py` 这个文件的功能。

**核心功能归纳：**

这个 Python 脚本的主要功能是 **定义了一系列的单元测试，用于验证 Meson 构建系统在各种平台上的通用功能和行为是否符合预期。**  它测试的是 Meson 本身的功能，而不是直接测试 Frida 的功能。

**更详细的功能分解和说明：**

1. **Meson 功能测试:** 这个脚本继承自 `BasePlatformTests`，专注于测试 Meson 构建系统的核心特性，这些特性在不同的操作系统（如 Linux、macOS、Windows）上都应该表现一致。

2. **配置选项测试:**  脚本中包含大量测试用例，用于验证 Meson 处理各种配置选项的能力，例如：
    *   `prefix` (安装路径前缀)
    *   `libdir` (库文件安装路径)
    *   `default_options` (项目默认选项)
    *   `wrap-mode` (依赖管理模式)
    *   与安装相关的选项

3. **文件处理测试:** 测试 Meson 处理配置文件的能力，例如：
    *   `do_conf_file`:  测试生成配置文件的功能，包括保留换行符等细节。
    *   `do_conf_file_by_format`: 测试根据不同格式（如 Meson 格式、CMake 格式）生成配置文件的功能。

4. **构建过程测试:**  测试构建过程中的关键环节：
    *   静态库的处理 (`test_static_library_overwrite`, `test_static_compile_order`)：验证静态库是否被正确创建和更新。
    *   编译顺序：确保编译顺序的确定性。

5. **安装过程测试:** 验证 Meson 的安装功能：
    *   `test_install_introspection`, `test_install_subdir_introspection`, `test_install_introspection_multiple_outputs`:  测试 Meson 的内省 API 是否能正确反映安装的文件和目录信息。
    *   `test_install_log_content`: 验证安装日志的正确性和一致性。
    *   `test_uninstall`: 测试卸载功能。

6. **依赖管理测试:** 测试 Meson 的依赖管理特性，特别是 `wrap` 功能：
    *   `test_forcefallback`, `test_implicit_forcefallback`, `test_force_fallback_for`, `test_force_fallback_for_nofallback`, `test_nopromote`: 测试在依赖查找失败时，Meson 如何处理预编译的 "wrap" 文件或回退到源码构建。

7. **测试框架集成测试:** 验证 Meson 内置的测试框架 `mtest` 的功能：
    *   `test_testrepeat`: 测试重复运行测试的功能。
    *   `test_verbose`: 测试详细输出测试结果的功能。
    *   `test_long_output`: 测试处理大量测试输出的功能。
    *   `test_testsetups`: 测试测试用例 setup 功能。

**与逆向方法的关系 (举例说明):**

虽然这个脚本不直接进行逆向操作，但它测试的 Meson 功能对于构建逆向工程工具（如 Frida 本身）至关重要。

*   **构建 Frida 核心库:** Frida 的核心库通常需要编译成动态链接库或静态库。这个脚本中测试的静态库和动态库的处理、编译选项、安装路径等功能，都直接关系到 Frida 核心库能否被正确构建出来。
*   **配置 Frida 的 Agent:** Frida 的 Agent (通常使用 QML 或其他技术编写)  可能需要读取一些配置文件。 `do_conf_file` 相关的测试确保了 Meson 能正确生成这些配置文件。
*   **处理依赖:** Frida 可能依赖其他库。 `wrap` 相关的测试保证了 Meson 在找不到系统库时，能够正确使用预编译的依赖或回退到源码构建，这对于 Frida 在各种环境下的部署非常重要。

**涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

这个脚本间接地涉及到这些知识，因为它测试的 Meson 功能是为了构建能在这些底层环境运行的软件。

*   **二进制文件的生成:**  测试用例会构建可执行文件和库文件，这直接涉及到二进制文件的生成过程。
*   **Linux 系统调用和库:**  Meson 需要能够找到 Linux 系统上的库文件 (`.so` 文件)，并正确链接它们。  测试用例中对 `libdir` 的处理就与此相关。
*   **Android NDK 构建:**  虽然这个脚本没有明确针对 Android，但 Meson 也常用于 Android NDK 项目。  Meson 需要理解 Android 的目录结构和编译规则。
*   **交叉编译:**  Frida 经常需要进行交叉编译，例如在 x86 机器上构建 ARM Android 设备上运行的 Agent。 Meson 的配置选项处理能力对于交叉编译至关重要。

**逻辑推理 (假设输入与输出):**

假设有一个测试用例 `test_default_options_prefix`:

*   **假设输入:**  一个包含 `project('test', default_options: ['prefix=/absoluteprefix'])` 的 `meson.build` 文件。
*   **预期输出:**  通过 Meson 的内省 API (`meson introspect --buildoptions`) 查询到的 `prefix` 选项的值为 `/absoluteprefix`。

这个测试用例通过配置 Meson 项目的默认选项并验证其是否生效，来进行逻辑推理。

**用户或编程常见的使用错误 (举例说明):**

*   **错误的安装路径配置:** 用户可能在 `meson configure` 时错误地设置了 `--prefix` 或 `--libdir`，导致 Frida 的组件安装到错误的位置。  相关的测试用例 (`test_default_options_prefix`, `test_absolute_prefix_libdir`) 就在验证 Meson 是否能正确处理这些配置，从而避免用户的错误。
*   **依赖缺失:** 用户在构建 Frida 时，可能缺少某些依赖库。 `wrap` 相关的测试用例模拟了这种情况，并验证 Meson 能否通过预编译的 "wrap" 文件或回退到源码构建来解决这个问题。
*   **配置文件格式错误:** 用户在编写 Frida Agent 的配置文件时，可能会出现格式错误。 `do_conf_file_by_format` 相关的测试验证了 Meson 生成配置文件的能力，间接地帮助用户避免此类错误。

**用户操作如何一步步到达这里 (调试线索):**

1. **开发 Frida 或其相关组件:**  开发者在修改 Frida 的代码或者 Frida QML 组件的代码时。
2. **运行 Meson 测试套件:** 为了确保修改没有引入 bug，开发者会运行 Meson 的测试套件。这通常涉及到在 Frida 的源代码目录下执行类似 `meson test -C builddir` 的命令。
3. **执行 `allplatformstests.py`:** Meson 测试框架会加载并执行 `allplatformstests.py` 中的所有测试用例。
4. **测试失败 (如果存在):** 如果某个测试用例失败，开发者会查看失败的输出和日志，分析原因。这时，理解 `allplatformstests.py` 中每个测试用例的目的就变得非常重要。

**总结它的功能 (第 1 部分):**

`frida/subprojects/frida-qml/releng/meson/unittests/allplatformstests.py` 是 Frida 项目中用于测试 Meson 构建系统通用功能的关键文件。它通过大量的单元测试，验证了 Meson 在配置选项处理、文件处理、构建过程、安装过程和依赖管理等方面的正确性。这些测试对于确保 Frida 能够跨平台可靠构建至关重要。虽然它不直接进行逆向操作，但它测试的构建功能是构建像 Frida 这样的逆向工程工具的基础。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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