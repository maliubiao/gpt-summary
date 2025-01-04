Response:
The user wants to understand the functionality of the Python script `linuxliketests.py`. I need to analyze the code and extract its core responsibilities. The prompt also asks for specific connections to reverse engineering, binary/kernel concepts, logical reasoning, user errors, and debugging.

Here's a plan:
1. **Identify the purpose of the script:** Look at the class and function names, imports, and overall structure to understand what kind of tests it performs.
2. **Categorize the tests:** Group the tests based on the functionalities they address (e.g., shared libraries, static libraries, pkg-config, installation).
3. **Relate to reverse engineering:**  See if any tests directly or indirectly involve inspecting compiled binaries or understanding how libraries are linked.
4. **Connect to low-level concepts:** Identify tests that touch upon OS-level features like file permissions, shared library naming conventions (soname), and compiler flags.
5. **Analyze logical reasoning:** Look for tests that set up specific conditions and assert expected outcomes based on Meson's logic.
6. **Identify potential user errors:** Think about how a user might configure Meson incorrectly and how these tests would catch those errors.
7. **Trace user actions:**  Consider the steps a user takes when using Meson and how those actions lead to the execution of these tests.

Based on the code, it seems like this script contains integration tests for Meson on Linux-like operating systems. It verifies various aspects of building and installing software using Meson.
这是 `frida/subprojects/frida-node/releng/meson/unittests/linuxliketests.py` 文件的源代码，它属于 Frida 动态Instrumentation 工具的 Meson 构建系统的单元测试部分，专门针对 Linux 和其他类 Unix 系统。

**它的主要功能是验证 Frida 在 Linux 和类 Unix 环境下的构建和安装行为是否符合预期。**  更具体地说，它测试了 Meson 构建系统的各种功能，确保在这些平台上使用 Frida 时，这些功能能够正确工作。

以下是更详细的功能归纳：

1. **共享库 (Shared Library) 相关测试:**
   - **`test_basic_soname`**: 验证生成的共享库是否具有正确的 `soname`（共享对象名称），这是 Linux 系统中动态链接器识别库的关键。
   - **`test_custom_soname`**: 测试当用户自定义共享库的前缀和后缀时，`soname` 是否仍然被正确设置。
   - **`_test_soname_impl`**:  一个底层的 `soname` 测试实现，涵盖了各种 `version` 和 `soversion` 设置的场景，并验证了符号链接的创建是否正确。
   - **`test_soname`**: 调用 `_test_soname_impl` 测试未安装状态下的 `soname`。
   - **`test_installed_soname`**: 调用 `_test_soname_impl` 测试安装后的 `soname`。

2. **静态库 (Static Library) 相关测试:**
   - **`test_pic`**: 验证当 `b_staticpic` 选项设置为 `true` 时，静态库编译时是否正确添加了 `-fPIC` 标志（用于生成位置无关代码），以及当设置为 `false` 时是否移除了该标志。

3. **Pkg-config 相关测试:**
   - **`test_pkgconfig_gen`**: 测试 Meson 生成的 `.pc` (pkg-config) 文件是否可以被找到，并且包含了正确的版本信息、链接参数和变量。
   - **`test_pkgconfig_gen_deps`**: 验证生成的 pkg-config 文件是否正确处理了依赖关系。
   - **`test_pkgconfig_uninstalled`**: 测试在未安装状态下，pkg-config 是否能够找到相应的依赖。
   - **`test_pkg_unfound`**: 测试当请求一个不存在的 pkg-config 包时，Meson 的行为是否符合预期。
   - **`test_qtdependency_pkgconfig_detection`**: 测试使用 pkg-config 来检测 Qt4 和 Qt5 依赖是否工作正常。

4. **构建目录和符号链接测试:**
   - **`test_symlink_builddir`**: 测试使用符号链接作为构建目录是否能正常工作。

5. **Qt 依赖检测测试:**
   - **`test_qt5dependency_qmake_detection`**: 测试使用 `qmake` 来检测 Qt5 依赖是否工作正常。
   - **`test_qt6dependency_qmake_detection`**: 测试使用 `qmake` 来检测 Qt6 依赖是否工作正常。

6. **编译器标志和标准测试:**
   - **`test_compiler_check_flags_order`**: 验证编译器检查标志是否能覆盖其他标志。
   - **`_test_stds_impl`**: 一个底层的编译器标准测试实现，用于检查各种 C 和 C++ 标准选项是否被编译器正确识别和应用。
   - **`test_compiler_c_stds`**: 调用 `_test_stds_impl` 测试 C 编译器的各种标准选项。
   - **`test_compiler_cpp_stds`**: 调用 `_test_stds_impl` 测试 C++ 编译器的各种标准选项。

7. **Unity 构建测试:**
   - **`test_unity_subproj`**: 测试在包含子项目的构建中使用 Unity 构建功能是否正常工作。

8. **安装和文件权限测试:**
   - **`test_installed_modes`**: 验证通过测试安装的文件是否具有正确的权限模式。
   - **`test_installed_modes_extended`**: 测试使用 `install_mode` 参数安装的文件是否具有指定的权限模式。
   - **`test_install_umask`**: 测试安装过程是否使用了默认的 `umask` (022)。

**与逆向方法的关系举例说明:**

- **`test_basic_soname` 和 `test_custom_soname`**:  在逆向工程中，理解共享库的命名约定 (`soname`) 非常重要。当分析一个程序依赖的动态库时，需要知道库的 `soname` 才能正确地跟踪库的加载和链接。例如，使用 `ldd` 命令可以查看程序依赖的库及其 `soname`。这个测试确保了 Meson 构建的 Frida 库具有正确的 `soname`，这对于 Frida 的正常运行和逆向分析 Frida 的行为至关重要。

**涉及二进制底层，Linux, Android 内核及框架的知识举例说明:**

- **`test_pic`**:  `-fPIC` 标志对于在共享库中生成位置无关代码至关重要。位置无关代码允许共享库在内存中的任意地址加载，这是动态链接的基础。Android 系统广泛使用共享库，因此确保 Frida 的共享库使用 `-fPIC` 编译对于在 Android 上运行 Frida 非常重要。
- **`test_basic_soname` 和 `test_custom_soname`**: `soname` 是 Linux 动态链接器 (`ld-linux.so`) 用来查找和加载共享库的关键信息。内核在加载程序时，会根据程序的依赖信息，使用 `soname` 在文件系统中查找对应的 `.so` 文件。
- **安装和文件权限测试 (`test_installed_modes`, `test_installed_modes_extended`, `test_install_umask`)**: 这些测试直接涉及到 Linux 文件系统的权限模型。理解 Linux 的 `chmod` 和 `umask` 命令以及文件权限的 `rwx` 位对于开发和部署软件至关重要。Frida 需要确保其安装的文件具有适当的权限，以便用户能够执行 Frida 相关的工具和库。

**逻辑推理的假设输入与输出举例:**

- **`test_pic` 的逻辑推理:**
    - **假设输入:** Meson 构建配置文件中 `b_staticpic` 选项设置为 `true`。
    - **预期输出:**  编译静态库的命令中包含 `-fPIC` 标志。
    - **假设输入:** Meson 构建配置文件中 `b_staticpic` 选项设置为 `false`。
    - **预期输出:** 编译静态库的命令中不包含 `-fPIC` 标志。

**涉及用户或者编程常见的使用错误举例说明:**

- **`test_pkgconfig_gen_deps`**: 如果用户在定义 pkg-config 模块的依赖关系时出现错误，例如拼写错误或引用了不存在的包，这个测试可能会失败，因为它会验证生成的 `.pc` 文件中的 `Requires` 和 `Requires.private` 字段是否正确。
- **`test_compiler_c_stds` 和 `test_compiler_cpp_stds`**: 如果用户在 Meson 的 `meson.build` 文件中错误地指定了编译器不支持的 C 或 C++ 标准，这些测试会通过尝试使用这些标准编译代码来检测错误，并确保 Meson 能够正确处理这些无效的选项。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户开发或维护 Frida，并修改了 Frida 的构建系统 (meson.build 文件)。**
2. **为了验证修改的正确性，或者为了确保在 Linux 和类 Unix 系统上 Frida 的构建行为没有被意外破坏，开发者会运行 Frida 的单元测试。**
3. **运行单元测试的命令通常类似于 `python run_tests.py meson/unittests/linuxliketests.py` 或者使用 Meson 提供的测试运行工具。**
4. **当执行到 `linuxliketests.py` 时，脚本中的各个测试函数会被执行。**
5. **如果某个测试失败，例如 `test_basic_soname` 失败，这意味着生成的共享库的 `soname` 不符合预期。**
6. **开发者会查看测试失败的详细信息，例如比较期望的 `soname` 和实际的 `soname`。**
7. **然后，开发者会检查相关的 Meson 构建配置 (例如 `meson.build` 文件中关于共享库定义的代码) 和构建过程中使用的编译器标志，以找出导致 `soname` 错误的原因。**
8. **通过分析测试代码和构建日志，开发者可以逐步缩小问题的范围，最终定位并修复错误。**

**归纳一下它的功能:**

总而言之，`frida/subprojects/frida-node/releng/meson/unittests/linuxliketests.py` 的主要功能是**通过执行一系列单元测试，来验证 Frida 在 Linux 和类 Unix 系统上使用 Meson 构建系统时的各种核心功能是否正常工作，包括共享库处理、静态库编译、pkg-config 集成、Qt 依赖检测、编译器标志处理以及安装过程中的文件权限管理等。** 它的存在是为了确保 Frida 在这些平台上的构建质量和稳定性。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016-2022 The Meson development team

import stat
import subprocess
import re
import tempfile
import textwrap
import os
import shutil
import hashlib
from unittest import mock, skipUnless, SkipTest
from glob import glob
from pathlib import Path
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
    MachineChoice, is_windows, is_osx, is_cygwin, is_openbsd, is_haiku,
    is_sunos, windows_proof_rmtree, version_compare, is_linux,
    OptionKey, EnvironmentException
)
from mesonbuild.compilers import (
    detect_c_compiler, detect_cpp_compiler, compiler_from_language,
)
from mesonbuild.compilers.c import AppleClangCCompiler
from mesonbuild.compilers.cpp import AppleClangCPPCompiler
from mesonbuild.compilers.objc import AppleClangObjCCompiler
from mesonbuild.compilers.objcpp import AppleClangObjCPPCompiler
from mesonbuild.dependencies.pkgconfig import PkgConfigDependency, PkgConfigCLI, PkgConfigInterface
import mesonbuild.modules.pkgconfig

PKG_CONFIG = os.environ.get('PKG_CONFIG', 'pkg-config')


from run_tests import (
    get_fake_env
)

from .baseplatformtests import BasePlatformTests
from .helpers import *

def _prepend_pkg_config_path(path: str) -> str:
    """Prepend a string value to pkg_config_path

    :param path: The path to prepend
    :return: The path, followed by any PKG_CONFIG_PATH already in the environment
    """
    pkgconf = os.environ.get('PKG_CONFIG_PATH')
    if pkgconf:
        return f'{path}{os.path.pathsep}{pkgconf}'
    return path


def _clang_at_least(compiler: 'Compiler', minver: str, apple_minver: T.Optional[str]) -> bool:
    """
    check that Clang compiler is at least a specified version, whether AppleClang or regular Clang

    Parameters
    ----------
    compiler:
        Meson compiler object
    minver: str
        Clang minimum version
    apple_minver: str
        AppleCLang minimum version

    Returns
    -------
    at_least: bool
        Clang is at least the specified version
    """
    if isinstance(compiler, (AppleClangCCompiler, AppleClangCPPCompiler)):
        if apple_minver is None:
            return False
        return version_compare(compiler.version, apple_minver)
    return version_compare(compiler.version, minver)

@skipUnless(not is_windows(), "requires something Unix-like")
class LinuxlikeTests(BasePlatformTests):
    '''
    Tests that should run on Linux, macOS, and *BSD
    '''

    def test_basic_soname(self):
        '''
        Test that the soname is set correctly for shared libraries. This can't
        be an ordinary test case because we need to run `readelf` and actually
        check the soname.
        https://github.com/mesonbuild/meson/issues/785
        '''
        testdir = os.path.join(self.common_test_dir, '4 shared')
        self.init(testdir)
        self.build()
        lib1 = os.path.join(self.builddir, 'libmylib.so')
        soname = get_soname(lib1)
        self.assertEqual(soname, 'libmylib.so')

    def test_custom_soname(self):
        '''
        Test that the soname is set correctly for shared libraries when
        a custom prefix and/or suffix is used. This can't be an ordinary test
        case because we need to run `readelf` and actually check the soname.
        https://github.com/mesonbuild/meson/issues/785
        '''
        testdir = os.path.join(self.common_test_dir, '24 library versions')
        self.init(testdir)
        self.build()
        lib1 = os.path.join(self.builddir, 'prefixsomelib.suffix')
        soname = get_soname(lib1)
        self.assertEqual(soname, 'prefixsomelib.suffix')

    def test_pic(self):
        '''
        Test that -fPIC is correctly added to static libraries when b_staticpic
        is true and not when it is false. This can't be an ordinary test case
        because we need to inspect the compiler database.
        '''
        if is_windows() or is_cygwin() or is_osx():
            raise SkipTest('PIC not relevant')

        testdir = os.path.join(self.common_test_dir, '3 static')
        self.init(testdir)
        compdb = self.get_compdb()
        self.assertIn('-fPIC', compdb[0]['command'])
        self.setconf('-Db_staticpic=false')
        # Regenerate build
        self.build()
        compdb = self.get_compdb()
        self.assertNotIn('-fPIC', compdb[0]['command'])

    @mock.patch.dict(os.environ)
    def test_pkgconfig_gen(self):
        '''
        Test that generated pkg-config files can be found and have the correct
        version and link args. This can't be an ordinary test case because we
        need to run pkg-config outside of a Meson build file.
        https://github.com/mesonbuild/meson/issues/889
        '''
        testdir = os.path.join(self.common_test_dir, '44 pkgconfig-gen')
        self.init(testdir)
        env = get_fake_env(testdir, self.builddir, self.prefix)
        kwargs = {'required': True, 'silent': True}
        os.environ['PKG_CONFIG_LIBDIR'] = self.privatedir
        foo_dep = PkgConfigDependency('libfoo', env, kwargs)
        self.assertTrue(foo_dep.found())
        self.assertEqual(foo_dep.get_version(), '1.0')
        self.assertIn('-lfoo', foo_dep.get_link_args())
        self.assertEqual(foo_dep.get_variable(pkgconfig='foo'), 'bar')
        self.assertPathEqual(foo_dep.get_variable(pkgconfig='datadir'), '/usr/data')

        libhello_nolib = PkgConfigDependency('libhello_nolib', env, kwargs)
        self.assertTrue(libhello_nolib.found())
        self.assertEqual(libhello_nolib.get_link_args(), [])
        self.assertEqual(libhello_nolib.get_compile_args(), [])
        self.assertEqual(libhello_nolib.get_variable(pkgconfig='foo'), 'bar')
        self.assertEqual(libhello_nolib.get_variable(pkgconfig='prefix'), self.prefix)
        impl = libhello_nolib.pkgconfig
        if not isinstance(impl, PkgConfigCLI) or version_compare(impl.pkgbin_version, ">=0.29.1"):
            self.assertEqual(libhello_nolib.get_variable(pkgconfig='escaped_var'), r'hello\ world')
        self.assertEqual(libhello_nolib.get_variable(pkgconfig='unescaped_var'), 'hello world')

        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() in {'gcc', 'clang'}:
            for name in {'ct', 'ct0'}:
                ct_dep = PkgConfigDependency(name, env, kwargs)
                self.assertTrue(ct_dep.found())
                self.assertIn('-lct', ct_dep.get_link_args(raw=True))

    def test_pkgconfig_gen_deps(self):
        '''
        Test that generated pkg-config files correctly handle dependencies
        '''
        testdir = os.path.join(self.common_test_dir, '44 pkgconfig-gen')
        self.init(testdir)
        privatedir1 = self.privatedir

        self.new_builddir()
        testdir = os.path.join(self.common_test_dir, '44 pkgconfig-gen', 'dependencies')
        self.init(testdir, override_envvars={'PKG_CONFIG_LIBDIR': privatedir1})
        privatedir2 = self.privatedir

        env = {
            'PKG_CONFIG_LIBDIR': os.pathsep.join([privatedir1, privatedir2]),
            'PKG_CONFIG_SYSTEM_LIBRARY_PATH': '/usr/lib',
        }
        self._run([PKG_CONFIG, 'dependency-test', '--validate'], override_envvars=env)

        # pkg-config strips some duplicated flags so we have to parse the
        # generated file ourself.
        expected = {
            'Requires': 'libexposed',
            'Requires.private': 'libfoo >= 1.0',
            'Libs': '-L${libdir} -llibmain -pthread -lcustom',
            'Libs.private': '-lcustom2 -L${libdir} -llibinternal',
            'Cflags': '-I${includedir} -pthread -DCUSTOM',
        }
        if is_osx() or is_haiku():
            expected['Cflags'] = expected['Cflags'].replace('-pthread ', '')
        with open(os.path.join(privatedir2, 'dependency-test.pc'), encoding='utf-8') as f:
            matched_lines = 0
            for line in f:
                parts = line.split(':', 1)
                if parts[0] in expected:
                    key = parts[0]
                    val = parts[1].strip()
                    expected_val = expected[key]
                    self.assertEqual(expected_val, val)
                    matched_lines += 1
            self.assertEqual(len(expected), matched_lines)

        cmd = [PKG_CONFIG, 'requires-test']
        out = self._run(cmd + ['--print-requires'], override_envvars=env).strip().split('\n')
        if not is_openbsd():
            self.assertEqual(sorted(out), sorted(['libexposed', 'libfoo >= 1.0', 'libhello']))
        else:
            self.assertEqual(sorted(out), sorted(['libexposed', 'libfoo>=1.0', 'libhello']))

        cmd = [PKG_CONFIG, 'requires-private-test']
        out = self._run(cmd + ['--print-requires-private'], override_envvars=env).strip().split('\n')
        if not is_openbsd():
            self.assertEqual(sorted(out), sorted(['libexposed', 'libfoo >= 1.0', 'libhello']))
        else:
            self.assertEqual(sorted(out), sorted(['libexposed', 'libfoo>=1.0', 'libhello']))

        cmd = [PKG_CONFIG, 'pub-lib-order']
        out = self._run(cmd + ['--libs'], override_envvars=env).strip().split()
        self.assertEqual(out, ['-llibmain2', '-llibinternal'])

        # See common/44 pkgconfig-gen/meson.build for description of the case this test
        with open(os.path.join(privatedir1, 'simple2.pc'), encoding='utf-8') as f:
            content = f.read()
            self.assertIn('Libs: -L${libdir} -lsimple2 -lsimple1', content)
            self.assertIn('Libs.private: -lz', content)

        with open(os.path.join(privatedir1, 'simple3.pc'), encoding='utf-8') as f:
            content = f.read()
            self.assertEqual(1, content.count('-lsimple3'))

        with open(os.path.join(privatedir1, 'simple5.pc'), encoding='utf-8') as f:
            content = f.read()
            self.assertNotIn('-lstat2', content)

    @mock.patch.dict(os.environ)
    def test_pkgconfig_uninstalled(self):
        testdir = os.path.join(self.common_test_dir, '44 pkgconfig-gen')
        self.init(testdir)
        self.build()

        os.environ['PKG_CONFIG_LIBDIR'] = os.path.join(self.builddir, 'meson-uninstalled')
        if is_cygwin():
            os.environ['PATH'] += os.pathsep + self.builddir

        self.new_builddir()
        testdir = os.path.join(self.common_test_dir, '44 pkgconfig-gen', 'dependencies')
        self.init(testdir)
        self.build()
        self.run_tests()

    def test_pkg_unfound(self):
        testdir = os.path.join(self.unit_test_dir, '23 unfound pkgconfig')
        self.init(testdir)
        with open(os.path.join(self.privatedir, 'somename.pc'), encoding='utf-8') as f:
            pcfile = f.read()
        self.assertNotIn('blub_blob_blib', pcfile)

    def test_symlink_builddir(self) -> None:
        '''
        Test using a symlink as either the builddir for "setup" or
        the argument for "-C".
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')

        symdir = f'{self.builddir}-symlink'
        os.symlink(self.builddir, symdir)
        self.addCleanup(os.unlink, symdir)
        self.change_builddir(symdir)

        self.init(testdir)
        self.build()
        self._run(self.mtest_command)

    @skipIfNoPkgconfig
    def test_qtdependency_pkgconfig_detection(self):
        '''
        Test that qt4 and qt5 detection with pkgconfig works.
        '''
        # Verify Qt4 or Qt5 can be found with pkg-config
        qt4 = subprocess.call([PKG_CONFIG, '--exists', 'QtCore'])
        qt5 = subprocess.call([PKG_CONFIG, '--exists', 'Qt5Core'])
        testdir = os.path.join(self.framework_test_dir, '4 qt')
        self.init(testdir, extra_args=['-Dmethod=pkg-config'])
        # Confirm that the dependency was found with pkg-config
        mesonlog = self.get_meson_log_raw()
        if qt4 == 0:
            self.assertRegex(mesonlog,
                             r'Run-time dependency qt4 \(modules: Core\) found: YES 4.* \(pkg-config\)')
        if qt5 == 0:
            self.assertRegex(mesonlog,
                             r'Run-time dependency qt5 \(modules: Core\) found: YES 5.* \(pkg-config\)')

    @skip_if_not_base_option('b_sanitize')
    def test_generate_gir_with_address_sanitizer(self):
        if is_cygwin():
            raise SkipTest('asan not available on Cygwin')
        if is_openbsd():
            raise SkipTest('-fsanitize=address is not supported on OpenBSD')

        testdir = os.path.join(self.framework_test_dir, '7 gnome')
        self.init(testdir, extra_args=['-Db_sanitize=address', '-Db_lundef=false'])
        self.build()

    def test_qt5dependency_qmake_detection(self):
        '''
        Test that qt5 detection with qmake works. This can't be an ordinary
        test case because it involves setting the environment.
        '''
        # Verify that qmake is for Qt5
        if not shutil.which('qmake-qt5'):
            if not shutil.which('qmake'):
                raise SkipTest('QMake not found')
            output = subprocess.getoutput('qmake --version')
            if 'Qt version 5' not in output:
                raise SkipTest('Qmake found, but it is not for Qt 5.')
        # Disable pkg-config codepath and force searching with qmake/qmake-qt5
        testdir = os.path.join(self.framework_test_dir, '4 qt')
        self.init(testdir, extra_args=['-Dmethod=qmake'])
        # Confirm that the dependency was found with qmake
        mesonlog = self.get_meson_log_raw()
        self.assertRegex(mesonlog,
                         r'Run-time dependency qt5 \(modules: Core\) found: YES .* \(qmake\)\n')

    def test_qt6dependency_qmake_detection(self):
        '''
        Test that qt6 detection with qmake works. This can't be an ordinary
        test case because it involves setting the environment.
        '''
        # Verify that qmake is for Qt6
        if not shutil.which('qmake6'):
            if not shutil.which('qmake'):
                raise SkipTest('QMake not found')
            output = subprocess.getoutput('qmake --version')
            if 'Qt version 6' not in output:
                raise SkipTest('Qmake found, but it is not for Qt 6.')
        # Disable pkg-config codepath and force searching with qmake/qmake-qt6
        testdir = os.path.join(self.framework_test_dir, '4 qt')
        self.init(testdir, extra_args=['-Dmethod=qmake'])
        # Confirm that the dependency was found with qmake
        mesonlog = self.get_meson_log_raw()
        self.assertRegex(mesonlog,
                         r'Run-time dependency qt6 \(modules: Core\) found: YES .* \(qmake\)\n')

    def glob_sofiles_without_privdir(self, g):
        files = glob(g)
        return [f for f in files if not f.endswith('.p')]

    def _test_soname_impl(self, libpath, install):
        if is_cygwin() or is_osx():
            raise SkipTest('Test only applicable to ELF and linuxlike sonames')

        testdir = os.path.join(self.unit_test_dir, '1 soname')
        self.init(testdir)
        self.build()
        if install:
            self.install()

        # File without aliases set.
        nover = os.path.join(libpath, 'libnover.so')
        self.assertPathExists(nover)
        self.assertFalse(os.path.islink(nover))
        self.assertEqual(get_soname(nover), 'libnover.so')
        self.assertEqual(len(self.glob_sofiles_without_privdir(nover[:-3] + '*')), 1)

        # File with version set
        verset = os.path.join(libpath, 'libverset.so')
        self.assertPathExists(verset + '.4.5.6')
        self.assertEqual(os.readlink(verset), 'libverset.so.4')
        self.assertEqual(get_soname(verset), 'libverset.so.4')
        self.assertEqual(len(self.glob_sofiles_without_privdir(verset[:-3] + '*')), 3)

        # File with soversion set
        soverset = os.path.join(libpath, 'libsoverset.so')
        self.assertPathExists(soverset + '.1.2.3')
        self.assertEqual(os.readlink(soverset), 'libsoverset.so.1.2.3')
        self.assertEqual(get_soname(soverset), 'libsoverset.so.1.2.3')
        self.assertEqual(len(self.glob_sofiles_without_privdir(soverset[:-3] + '*')), 2)

        # File with version and soversion set to same values
        settosame = os.path.join(libpath, 'libsettosame.so')
        self.assertPathExists(settosame + '.7.8.9')
        self.assertEqual(os.readlink(settosame), 'libsettosame.so.7.8.9')
        self.assertEqual(get_soname(settosame), 'libsettosame.so.7.8.9')
        self.assertEqual(len(self.glob_sofiles_without_privdir(settosame[:-3] + '*')), 2)

        # File with version and soversion set to different values
        bothset = os.path.join(libpath, 'libbothset.so')
        self.assertPathExists(bothset + '.1.2.3')
        self.assertEqual(os.readlink(bothset), 'libbothset.so.1.2.3')
        self.assertEqual(os.readlink(bothset + '.1.2.3'), 'libbothset.so.4.5.6')
        self.assertEqual(get_soname(bothset), 'libbothset.so.1.2.3')
        self.assertEqual(len(self.glob_sofiles_without_privdir(bothset[:-3] + '*')), 3)

        # A shared_module that is not linked to anything
        module = os.path.join(libpath, 'libsome_module.so')
        self.assertPathExists(module)
        self.assertFalse(os.path.islink(module))
        self.assertEqual(get_soname(module), None)

        # A shared_module that is not linked to an executable with link_with:
        module = os.path.join(libpath, 'liblinked_module1.so')
        self.assertPathExists(module)
        self.assertFalse(os.path.islink(module))
        self.assertEqual(get_soname(module), 'liblinked_module1.so')

        # A shared_module that is not linked to an executable with dependencies:
        module = os.path.join(libpath, 'liblinked_module2.so')
        self.assertPathExists(module)
        self.assertFalse(os.path.islink(module))
        self.assertEqual(get_soname(module), 'liblinked_module2.so')

    def test_soname(self):
        self._test_soname_impl(self.builddir, False)

    def test_installed_soname(self):
        libdir = self.installdir + os.path.join(self.prefix, self.libdir)
        self._test_soname_impl(libdir, True)

    def test_compiler_check_flags_order(self):
        '''
        Test that compiler check flags override all other flags. This can't be
        an ordinary test case because it needs the environment to be set.
        '''
        testdir = os.path.join(self.common_test_dir, '36 has function')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cpp = detect_cpp_compiler(env, MachineChoice.HOST)
        Oflag = '-O3'
        OflagCPP = Oflag
        if cpp.get_id() in ('clang', 'gcc'):
            # prevent developers from adding "int main(int argc, char **argv)"
            # to small Meson checks unless these parameters are actually used
            OflagCPP += ' -Werror=unused-parameter'
        env = {'CFLAGS': Oflag,
               'CXXFLAGS': OflagCPP}
        self.init(testdir, override_envvars=env)
        cmds = self.get_meson_log_compiler_checks()
        for cmd in cmds:
            if cmd[0] == 'ccache':
                cmd = cmd[1:]
            # Verify that -I flags from the `args` kwarg are first
            # This is set in the '36 has function' test case
            self.assertEqual(cmd[1], '-I/tmp')
            # Verify that -O3 set via the environment is overridden by -O0
            Oargs = [arg for arg in cmd if arg.startswith('-O')]
            self.assertEqual(Oargs, [Oflag, '-O0'])

    def _test_stds_impl(self, testdir: str, compiler: 'Compiler') -> None:
        has_cpp17 = (compiler.get_id() not in {'clang', 'gcc'} or
                     compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=5.0.0', '>=9.1') or
                     compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=5.0.0'))
        has_cpp2a_c17 = (compiler.get_id() not in {'clang', 'gcc'} or
                         compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=6.0.0', '>=10.0') or
                         compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=8.0.0'))
        has_cpp20 = (compiler.get_id() not in {'clang', 'gcc'} or
                     compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=10.0.0', None) or
                     compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=10.0.0'))
        has_cpp2b = (compiler.get_id() not in {'clang', 'gcc'} or
                     compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=12.0.0', None) or
                     compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=11.0.0'))
        has_cpp23 = (compiler.get_id() not in {'clang', 'gcc'} or
                     compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=17.0.0', None) or
                     compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=11.0.0'))
        has_cpp26 = (compiler.get_id() not in {'clang', 'gcc'} or
                     compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=17.0.0', None) or
                     compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=14.0.0'))
        has_c18 = (compiler.get_id() not in {'clang', 'gcc'} or
                   compiler.get_id() == 'clang' and _clang_at_least(compiler, '>=8.0.0', '>=11.0') or
                   compiler.get_id() == 'gcc' and version_compare(compiler.version, '>=8.0.0'))
        # Check that all the listed -std=xxx options for this compiler work just fine when used
        # https://en.wikipedia.org/wiki/Xcode#Latest_versions
        # https://www.gnu.org/software/gcc/projects/cxx-status.html
        key = OptionKey('std', lang=compiler.language)
        for v in compiler.get_options()[key].choices:
            # we do it like this to handle gnu++17,c++17 and gnu17,c17 cleanly
            # thus, C++ first
            if '++17' in v and not has_cpp17:
                continue
            elif '++2a' in v and not has_cpp2a_c17:  # https://en.cppreference.com/w/cpp/compiler_support
                continue
            elif '++20' in v and not has_cpp20:
                continue
            elif '++2b' in v and not has_cpp2b:
                continue
            elif '++23' in v and not has_cpp23:
                continue
            elif ('++26' in v or '++2c' in v) and not has_cpp26:
                continue
            # now C
            elif '17' in v and not has_cpp2a_c17:
                continue
            elif '18' in v and not has_c18:
                continue
            self.init(testdir, extra_args=[f'-D{key!s}={v}'])
            cmd = self.get_compdb()[0]['command']
            # c++03 and gnu++03 are not understood by ICC, don't try to look for them
            skiplist = frozenset([
                ('intel', 'c++03'),
                ('intel', 'gnu++03')])
            if v != 'none' and not (compiler.get_id(), v) in skiplist:
                cmd_std = f" -std={v} "
                self.assertIn(cmd_std, cmd)
            try:
                self.build()
            except Exception:
                print(f'{key!s} was {v!r}')
                raise
            self.wipe()
        # Check that an invalid std option in CFLAGS/CPPFLAGS fails
        # Needed because by default ICC ignores invalid options
        cmd_std = '-std=FAIL'
        if compiler.language == 'c':
            env_flag_name = 'CFLAGS'
        elif compiler.language == 'cpp':
            env_flag_name = 'CXXFLAGS'
        else:
            raise NotImplementedError(f'Language {compiler.language} not defined.')
        env = {}
        env[env_flag_name] = cmd_std
        with self.assertRaises((subprocess.CalledProcessError, EnvironmentException),
                               msg='C compiler should have failed with -std=FAIL'):
            self.init(testdir, override_envvars = env)
            # ICC won't fail in the above because additional flags are needed to
            # make unknown -std=... options errors.
            self.build()

    def test_compiler_c_stds(self):
        '''
        Test that C stds specified for this compiler can all be used. Can't be
        an ordinary test because it requires passing options to meson.
        '''
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        self._test_stds_impl(testdir, cc)

    def test_compiler_cpp_stds(self):
        '''
        Test that C++ stds specified for this compiler can all be used. Can't
        be an ordinary test because it requires passing options to meson.
        '''
        testdir = os.path.join(self.common_test_dir, '2 cpp')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cpp = detect_cpp_compiler(env, MachineChoice.HOST)
        self._test_stds_impl(testdir, cpp)

    def test_unity_subproj(self):
        testdir = os.path.join(self.common_test_dir, '42 subproject')
        self.init(testdir, extra_args='--unity=subprojects')
        pdirs = glob(os.path.join(self.builddir, 'subprojects/sublib/simpletest*.p'))
        self.assertEqual(len(pdirs), 1)
        self.assertPathExists(os.path.join(pdirs[0], 'simpletest-unity0.c'))
        sdirs = glob(os.path.join(self.builddir, 'subprojects/sublib/*sublib*.p'))
        self.assertEqual(len(sdirs), 1)
        self.assertPathExists(os.path.join(sdirs[0], 'sublib-unity0.c'))
        self.assertPathDoesNotExist(os.path.join(self.builddir, 'user@exe/user-unity.c'))
        self.build()

    def test_installed_modes(self):
        '''
        Test that files installed by these tests have the correct permissions.
        Can't be an ordinary test because our installed_files.txt is very basic.
        '''
        if is_cygwin():
            self.new_builddir_in_tempdir()
        # Test file modes
        testdir = os.path.join(self.common_test_dir, '12 data')
        self.init(testdir)
        self.install()

        f = os.path.join(self.installdir, 'etc', 'etcfile.dat')
        found_mode = stat.filemode(os.stat(f).st_mode)
        want_mode = 'rw-------'
        self.assertEqual(want_mode, found_mode[1:])

        f = os.path.join(self.installdir, 'usr', 'bin', 'runscript.sh')
        statf = os.stat(f)
        found_mode = stat.filemode(statf.st_mode)
        want_mode = 'rwxr-sr-x'
        self.assertEqual(want_mode, found_mode[1:])
        if os.getuid() == 0:
            # The chown failed nonfatally if we're not root
            self.assertEqual(0, statf.st_uid)
            self.assertEqual(0, statf.st_gid)

        f = os.path.join(self.installdir, 'usr', 'share', 'progname',
                         'fileobject_datafile.dat')
        orig = os.path.join(testdir, 'fileobject_datafile.dat')
        statf = os.stat(f)
        statorig = os.stat(orig)
        found_mode = stat.filemode(statf.st_mode)
        orig_mode = stat.filemode(statorig.st_mode)
        self.assertEqual(orig_mode[1:], found_mode[1:])
        self.assertEqual(os.getuid(), statf.st_uid)
        if os.getuid() == 0:
            # The chown failed nonfatally if we're not root
            self.assertEqual(0, statf.st_gid)

        self.wipe()
        # Test directory modes
        testdir = os.path.join(self.common_test_dir, '59 install subdir')
        self.init(testdir)
        self.install()

        f = os.path.join(self.installdir, 'usr', 'share', 'sub1', 'second.dat')
        statf = os.stat(f)
        found_mode = stat.filemode(statf.st_mode)
        want_mode = 'rwxr-x--x'
        self.assertEqual(want_mode, found_mode[1:])
        if os.getuid() == 0:
            # The chown failed nonfatally if we're not root
            self.assertEqual(0, statf.st_uid)

    def test_installed_modes_extended(self):
        '''
        Test that files are installed with correct permissions using install_mode.
        '''
        if is_cygwin():
            self.new_builddir_in_tempdir()
        testdir = os.path.join(self.common_test_dir, '190 install_mode')
        self.init(testdir)
        self.build()
        self.install()

        for fsobj, want_mode in [
                ('bin', 'drwxr-x---'),
                ('bin/runscript.sh', '-rwxr-sr-x'),
                ('bin/trivialprog', '-rwxr-sr-x'),
                ('include', 'drwxr-x---'),
                ('include/config.h', '-rw-rwSr--'),
                ('include/rootdir.h', '-r--r--r--'),
                ('lib', 'drwxr-x---'),
                ('lib/libstat.a', '-rw---Sr--'),
                ('share', 'drwxr-x---'),
                ('share/man', 'drwxr-x---'),
                ('share/man/man1', 'drwxr-x---'),
                ('share/man/man1/foo.1', '-r--r--r--'),
                ('share/sub1', 'drwxr-x---'),
                ('share/sub1/second.dat', '-rwxr-x--x'),
                ('subdir', 'drwxr-x---'),
                ('subdir/data.dat', '-rw-rwSr--'),
        ]:
            f = os.path.join(self.installdir, 'usr', *fsobj.split('/'))
            found_mode = stat.filemode(os.stat(f).st_mode)
            self.assertEqual(want_mode, found_mode,
                             msg=('Expected file %s to have mode %s but found %s instead.' %
                                  (fsobj, want_mode, found_mode)))
        # Ensure that introspect --installed works on all types of files
        # FIXME: also verify the files list
        self.introspect('--installed')

    def test_install_umask(self):
        '''
        Test that files are installed with correct permissions using default
        install umask of 022, regardless of the umask at time the worktree
        was checked out or the build was executed.
        '''
        if is_cygwin():
            self.new_builddir_in_tempdir()
        # Copy source tree to a temporary directory and change permissions
        # there to simulate a checkout with umask 002.
        orig_testdir = os.path.join(self.unit_test_dir, '26 install umask')
        # Create a new testdir under tmpdir.
        tmpdir = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(windows_proof_rmtree, tmpdir)
        testdir = os.path.join(tmpdir, '26 install umask')
        # Copy the tree using shutil.copyfile, which will use the current umask
        # instead of preserving permissions of the old tree.
        save_umask = os.umask(0o002)
        self.addCleanup(os.umask, save_umask)
        shutil.copytree(orig_testdir, testdir, copy_function=shutil.copyfile)
        # Preserve the executable status of subdir/sayhello though.
        os.chmod(os.path.join(testdir, 'subdir', 'sayhello'), 0o775)
        self.init(testdir)
        # Run the build under a 027 umask now.
        os.umask(0o027)
        self.build()
        # And keep umask 027 for the install step too.
        self.install()

        for executable in [
                'bin/prog',
                'share/subdir/sayhello',
        ]:
            f = os.path.join(self.installdir, 'usr', *executable.split('/'))
            found_mode = stat.filemode(os.stat(f).st_mode)
            want_mode = '-rwxr-xr-x'
            self.assertEqual(want_mode, found_mode,
                             msg=('Expected file %s to have mode %s but found %s instead.' %
                                  (executable, want_mode, found_mode)))

        for directory in [
                'usr',
                'usr/bin',
                'usr/include',
                'usr/share',
                'usr/share/man',
                'usr/share/man/man1',
                'usr/share/subdir',
        ]:
            f = os.path.join(self.installdir, *directory.split('/'))
            found_mode = stat.filemode(os.stat(f).st_mode)
            want_mode = 'drwxr-xr-x'
            self.assertEqual(want_mode, found_mode,
                             msg=('Expected directory %s to have mode %s but found %s instead.' %
                                  (directory, want_mode, found_mode)))

        for datafile in [
                'include/sample.h',
                'share/datafile.cat',
                'share/file.dat',
                'share/man/man1/prog.1',
                'share/subdir/datafile.dog',
        ]:
            f = os.path.join(self.installdir, 'usr', *datafile.split('/'))
            found_mode = stat.filemode(os.stat(f).st_mode)
            want_mode = '-rw-r--r--'
            self.assertEqual(want_mode, found_mode,
                             msg=('Expected file %s to have mode %s but found %s instead.' %
                                  (datafile, want_mode, found_mode)))


"""


```