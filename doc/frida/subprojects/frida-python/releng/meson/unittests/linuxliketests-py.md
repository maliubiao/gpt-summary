Response:
The user wants to understand the functionality of the provided Python code snippet, which is a test suite for the Frida dynamic instrumentation tool. I need to analyze the code and identify the features being tested. The request also asks for connections to reverse engineering, low-level concepts, and potential user errors, as well as how a user might reach this code.

Here's a breakdown of the code's functionality:

1. **Testing shared library sonames:** Verifies that shared libraries have the correct soname (shared object name) set, both with default and custom prefixes/suffixes. This is crucial for dynamic linking and versioning.
2. **Testing Position Independent Code (PIC):** Checks if the `-fPIC` compiler flag is correctly applied to static libraries when the `b_staticpic` option is enabled. PIC is essential for shared libraries to be loaded at arbitrary memory addresses.
3. **Testing generated pkg-config files:** Validates that generated `.pc` files (used for package discovery) contain the expected version, link arguments, compile arguments, and dependencies. This ensures that other projects can find and link against the built libraries.
4. **Testing pkg-config dependency handling:**  Examines how dependencies are represented in the generated `.pc` files, including `Requires`, `Requires.private`, `Libs`, `Libs.private`, and `Cflags`.
5. **Testing uninstalled pkg-config:** Checks if pkg-config works correctly against the "uninstalled" build directory, allowing development against uninstalled libraries.
6. **Testing symbolic link build directories:** Verifies that Meson works correctly when the build directory is a symbolic link.
7. **Testing Qt dependency detection using pkg-config and qmake:**  Confirms that Meson can find Qt libraries using both pkg-config and qmake, covering different Qt versions (4, 5, and 6).
8. **Testing Address Sanitizer integration:** Checks if generating GIR (GObject Introspection) files works correctly when the Address Sanitizer (`-Db_sanitize=address`) is enabled. ASan helps detect memory errors.
9. **Testing soname handling with different versioning schemes:**  Examines the creation of symbolic links and the correctness of sonames for libraries with various versioning configurations (version, soversion, or both).
10. **Testing compiler flag order:** Verifies that compiler check flags take precedence over other flags, including those set by environment variables.
11. **Testing compiler standard selection:** Checks if Meson correctly passes the specified C and C++ standard flags (e.g., `-std=c++17`) to the compiler and handles invalid standard options.
12. **Testing unity builds for subprojects:**  Verifies that unity builds (combining multiple source files into a single compilation unit) work correctly for subprojects.
13. **Testing installed file modes (permissions):**  Ensures that installed files and directories have the expected permissions (read, write, execute) set, considering setuid and setgid bits.
14. **Testing custom install modes:** Checks if the `install_mode` setting in `meson.build` is correctly applied to installed files and directories.
15. **Testing install umask:** Verifies that the default install umask (022) is used when installing files, regardless of the umask at build time.

Now, let's address the specific points in the prompt:

*   **Relationship to reverse engineering:** The tests involving sonames, shared libraries, and dependency handling are directly relevant to reverse engineering. Understanding how libraries are linked and their dependencies is crucial for analyzing compiled programs.
*   **Binary/kernel knowledge:** The tests related to PIC, sonames, and file permissions touch upon fundamental concepts of operating systems and binary formats. PIC is related to how code is loaded into memory, sonames are part of the ELF binary format, and file permissions are a core Linux/Unix concept.
*   **Logical reasoning:** The tests often involve setting up specific scenarios (e.g., with and without `b_staticpic`, different versioning schemes) and then asserting the expected outcome (e.g., presence or absence of `-fPIC`, correct soname). The assumptions are based on how Meson is designed to work.
*   **User errors:**  The test that checks for invalid standard options directly addresses a common user error – specifying a C or C++ standard that is not supported by the compiler.
*   **User journey:** A user would likely encounter this code when contributing to the Frida project, specifically when adding new features related to building and packaging on Linux-like systems or when debugging existing build-related issues. They might also be looking at this code to understand how Meson's build system works for inspiration or troubleshooting their own Meson projects.

Finally, let's summarize the functionality of the code.这是 Frida 动态 instrumentation 工具的源代码文件的一部分，主要负责在 Linux、macOS 和 BSD 等类 Unix 系统上测试 Meson 构建系统的特定功能。它专注于验证与共享库、静态库、依赖管理、安装过程以及编译器行为相关的特性。

**具体功能归纳:**

1. **测试共享库的 Soname (Shared Object Name):**  验证使用默认和自定义命名规则时，共享库是否正确设置了 Soname。Soname 是动态链接器用于在运行时查找共享库的关键标识。
2. **测试静态库的 PIC (Position Independent Code):**  检查当 `b_staticpic` 选项启用时，静态库是否正确地添加了 `-fPIC` 编译器标志。PIC 对于创建可以加载到任意内存地址的共享库至关重要。
3. **测试生成的 pkg-config 文件:**  验证 Meson 生成的 pkg-config 文件是否包含正确的版本信息、链接参数、编译参数以及依赖关系。pkg-config 是一个用于获取库的编译和链接信息的标准工具。
4. **测试 pkg-config 依赖处理:** 验证生成的 pkg-config 文件中，依赖关系（例如 `Requires`, `Requires.private`）是否被正确表示。
5. **测试未安装状态的 pkg-config:**  检查在未执行安装步骤的情况下，pkg-config 是否能够正确解析构建目录中的信息。
6. **测试符号链接构建目录:** 验证当构建目录是符号链接时，Meson 是否能正常工作。
7. **测试 Qt 依赖查找 (pkg-config 和 qmake):**  测试 Meson 是否能够使用 pkg-config 和 qmake 工具正确找到 Qt 库的不同版本（Qt4、Qt5、Qt6）。
8. **测试 Address Sanitizer (ASan) 集成:**  检查当启用 Address Sanitizer 进行内存错误检测时，生成 GIR (GObject Introspection) 文件是否正常工作。
9. **测试不同版本控制方案下的 Soname 处理:** 验证当共享库设置了不同的版本号 (version) 和 soversion 时，Soname 和相应的符号链接是否被正确创建。
10. **测试编译器标志顺序:** 验证编译器检查标志的优先级高于其他标志，包括通过环境变量设置的标志。
11. **测试编译器标准选择:** 检查 Meson 是否能正确地将指定的 C 和 C++ 标准标志（例如 `-std=c++17`）传递给编译器，并处理无效的标准选项。
12. **测试子项目的 Unity Build:**  验证为子项目启用 Unity Build（将多个源文件合并为一个编译单元）是否正常工作。
13. **测试已安装文件的权限:**  检查安装后的文件和目录是否具有预期的权限设置，包括 setuid 和 setgid 位。
14. **测试自定义安装模式:**  验证 `meson.build` 文件中设置的 `install_mode` 是否被正确应用到安装的文件和目录。
15. **测试安装 umask:** 验证安装过程是否使用了默认的 umask 值 (022)，而忽略了构建时设置的 umask。

由于这是第 1 部分，它的主要功能是搭建针对类 Unix 系统的构建测试基础，并覆盖了共享库、静态库和依赖管理的关键方面。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
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
```