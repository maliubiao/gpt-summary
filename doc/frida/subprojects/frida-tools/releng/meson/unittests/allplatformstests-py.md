Response:
The user wants to understand the functionality of the Python code provided, which is a test suite for the Frida dynamic instrumentation tool. I need to go through the code and identify its main purpose and how it achieves it. I should also look for specific connections to reverse engineering, low-level details, logical reasoning, common user errors, and debugging steps.

Here's a breakdown of the code's functionality:

1. **Testing Meson Build System:** The code is part of Meson's test suite and focuses on testing features that are common across different platforms. Meson is the build system used by Frida.
2. **Unit Tests and Integration Tests:**  It includes various types of tests, from basic configuration checks to more complex scenarios involving building, installing, and running software.
3. **Platform Agnostic Tests:** The name "allplatformstests.py" suggests that the tests within this file are designed to be executed on various operating systems (Linux, macOS, Windows).
4. **Configuration and Introspection Testing:** A significant portion of the tests verifies the behavior of Meson's configuration system, including setting prefixes, library directories, and default options. It also tests Meson's introspection capabilities, which allow examining the build setup.
5. **Build Process Testing:**  Tests cover aspects of the build process, such as static library handling and compile order.
6. **Installation Testing:**  Several tests focus on the installation process, verifying correct file placement and the content of install logs.
7. **Dependency Management Testing (Wrap):**  The code includes tests for Meson's "wrap" feature, which handles external dependencies.
8. **Testing Framework Integration (MTest):** The tests utilize Meson's built-in testing framework (MTest) and verify its functionalities like test repetition, verbose output, and setup scripts.
9. **Error Handling:** The code tests how Meson handles various errors and edge cases.

Now, let's map these functionalities to the user's specific requests:

* **Functionality:**  The file contains a suite of tests for the Meson build system, specifically targeting features that should work consistently across different platforms.
* **Relation to Reverse Engineering:**  While this specific file doesn't directly perform reverse engineering, it tests the build system that is used to create tools like Frida, which is used for dynamic instrumentation and reverse engineering. The ability to correctly build and configure Frida is crucial for reverse engineering workflows.
* **Binary/Kernel/Framework Knowledge:**  Some tests implicitly touch upon these areas. For example, tests related to library directories and static linking involve understanding how binaries are linked and organized. Tests involving installation paths relate to operating system conventions.
* **Logical Reasoning:** Tests like `test_default_options_prefix_dependent_defaults` involve setting up different scenarios and verifying that the output matches expectations based on logical rules.
* **Common User Errors:** Tests related to incorrect configuration options or dependency management cover potential user errors.
* **User Operation to Reach Here:** A developer working on Frida or Meson might run these tests as part of their development process to ensure that changes haven't introduced regressions. This can happen during local development or as part of a CI/CD pipeline.

Based on this analysis, I can now generate the summary for part 1.
这是 `frida/subprojects/frida-tools/releng/meson/unittests/allplatformstests.py` 文件的第一部分，它是一个针对 Frida 动态 Instrumentation 工具的测试文件，更准确地说，是针对 Frida 所使用的构建系统 Meson 的跨平台功能进行测试。

以下是这个文件的主要功能归纳：

1. **Meson 构建系统功能测试:**  该文件包含了多个测试用例，旨在验证 Meson 构建系统在不同平台上的核心功能是否正常工作。这些功能包括但不限于：
    * **配置选项处理:** 测试 Meson 如何处理和应用各种配置选项，例如 `prefix` (安装路径前缀), `libdir` (库文件安装路径) 等。
    * **依赖管理:**  测试 Meson 的依赖管理功能，包括 `wrap` 机制，以及处理强制回退 (`forcefallback`) 和禁止提升 (`nopromote`) 依赖项的情况。
    * **构建过程:**  测试构建过程中静态库的处理、编译顺序等。
    * **安装过程:**  测试软件的安装过程，包括文件和目录的正确安装位置，以及生成安装日志的功能。
    * **卸载功能:** 测试软件的卸载功能。
    * **introspection (内省) API:** 测试 Meson 的内省 API，该 API 允许在构建后检查构建系统的状态，例如已安装的文件名。
    * **配置文件生成:** 测试 `do_conf_file` 和 `do_conf_str` 函数，用于根据配置数据生成配置文件。
    * **测试框架集成:** 测试 Meson 内置的测试框架 `mtest` 的功能，例如重复测试、verbose 输出、以及测试 setup 的功能。
    * **错误处理:**  测试 Meson 如何处理各种错误情况，例如不正确的配置或依赖项问题。

2. **跨平台兼容性验证:** 文件名 `allplatformstests.py` 暗示了这些测试用例的设计目标是在各种操作系统上都能运行，从而验证 Meson 的跨平台兼容性。

3. **辅助函数和上下文管理器:**  文件中定义了一些辅助函数和上下文管理器，例如 `temp_filename` 用于创建和清理临时文件，以及 `git_init` 用于初始化 Git 仓库，这些工具用于简化测试用例的编写。

**与逆向方法的关联举例说明：**

虽然此文件本身不是直接进行逆向的工具，但它测试的是 Frida 使用的构建系统。逆向工程师通常需要自己编译或修改 Frida 工具。确保 Meson 构建系统能够正确处理各种配置和依赖，对于逆向工程师成功构建和使用 Frida 至关重要。

例如，假设一个逆向工程师需要修改 Frida 的源代码并重新编译。如果 Meson 的配置选项处理存在问题（比如 `test_default_options_prefix` 测试的），那么工程师可能无法将 Frida 安装到期望的路径，从而影响其使用。

**涉及二进制底层、Linux、Android 内核及框架的知识的举例说明：**

* **二进制底层:**  `test_static_library_overwrite` 测试用例涉及到静态库的链接和更新，这需要了解二进制文件的组织结构以及静态链接器的工作原理 (例如 `ar` 命令)。
* **Linux:** 很多测试用例涉及到文件路径 (例如 `/usr/bin`, `/usr/lib`)，这些是典型的 Linux 文件系统结构。`test_clike_get_library_dirs` 测试用例会获取 C 编译器的库文件搜索路径，这在 Linux 系统中是很常见的概念。
* **Android 内核及框架:** 虽然此文件没有直接测试 Android 特有的功能，但 Frida 作为一个动态 Instrumentation 工具，在 Android 平台上的应用非常广泛。保证 Meson 在构建 Frida 的 Android 版本时正常工作，对于 Frida 在 Android 上的功能至关重要。

**逻辑推理的假设输入与输出举例说明：**

`test_default_options_prefix_dependent_defaults` 测试用例就包含逻辑推理。

* **假设输入:**  一个 Meson 项目的 `meson.build` 文件中设置了默认的 `prefix` 选项为 `/usr`。
* **逻辑推理:**  根据 Meson 的默认行为，如果 `prefix` 设置为 `/usr`，那么其他一些路径相关的选项 (例如 `bindir`, `sysconfdir`) 应该有相应的默认值 (例如 `bindir` 默认为 `bin`, `sysconfdir` 默认为 `/etc`)。
* **预期输出:**  通过内省 API (`introspect('--buildoptions')`) 获取的构建选项中，`bindir` 的值应为 `bin`，`sysconfdir` 的值应为 `/etc`。

**涉及用户或编程常见的使用错误的举例说明：**

* **配置错误:**  很多测试用例间接地测试了用户可能犯的配置错误。例如，如果用户错误地指定了 `--prefix` 或 `--libdir` 的值，相关的测试用例会验证 Meson 是否能够正确处理这些情况，或者给出相应的错误提示。
* **依赖管理错误:** `test_forcefallback` 和 `test_nopromote` 测试用例模拟了用户在处理依赖项时可能遇到的情况，例如强制使用 wrap 文件或阻止提升子项目依赖。如果用户在 `meson_options.txt` 或命令行中设置了错误的 wrap 模式，这些测试可以帮助发现问题。

**用户操作是如何一步步的到达这里的，作为调试线索：**

1. **开发或修改 Frida:**  一个开发者可能正在为 Frida 添加新功能、修复 bug 或进行性能优化。
2. **运行单元测试:**  为了确保他们的修改没有引入新的问题，开发者会运行 Frida 的单元测试套件。
3. **执行 Meson 测试:**  Frida 使用 Meson 作为构建系统，因此运行 Frida 的测试套件会间接地执行 Meson 相关的测试，包括 `allplatformstests.py` 中的测试用例。
4. **测试失败:**  如果 `allplatformstests.py` 中的某个测试用例失败，这会提供一个调试线索，表明 Meson 的某个跨平台功能可能存在问题，或者与 Frida 的某些更改不兼容。开发者可以查看失败的测试用例，分析其所测试的具体功能，并根据错误信息来定位问题。

总而言之，`allplatformstests.py` 是 Frida 项目中至关重要的一个文件，它通过一系列跨平台测试用例，确保了 Frida 构建系统的稳定性和可靠性，这对于 Frida 的开发、部署和最终被逆向工程师使用都至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共7部分，请归纳一下它的功能

"""
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

"""


```