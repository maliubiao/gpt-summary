Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding of the Request:**

The request asks for an analysis of a specific Python file within the Frida project. The key is to understand its *functionality*,  how it relates to *reverse engineering*, *low-level aspects*, *logic*, *common errors*, and the *user journey* to this code. The decomposed instructions emphasize these specific areas.

**2. High-Level Overview (Skimming the Code):**

My first step is to quickly skim the code to get a general idea of what it does. I notice:

* **Imports:** A lot of imports from `unittest`, `os`, `subprocess`, `glob`, `pathlib`, and various `mesonbuild` modules. This immediately suggests it's part of a testing framework within the Meson build system.
* **Class `LinuxlikeTests`:**  This is the core of the file, inheriting from `BasePlatformTests`. This confirms it's a collection of test cases. The name suggests these tests are specific to Unix-like operating systems.
* **Test Methods:**  Methods starting with `test_` indicate individual test cases. The names of these methods are quite descriptive (e.g., `test_basic_soname`, `test_pkgconfig_gen`, `test_pic`).
* **Helper Functions:** Functions like `_prepend_pkg_config_path` and `_clang_at_least` suggest utility functions used by the tests.
* **Conditional Logic (`if is_windows()`, `skipUnless`, etc.):** The code uses conditional logic to skip tests based on the operating system or specific conditions.

**3. Deconstructing Functionality by Test Case:**

The most effective way to understand the functionality is to analyze each test case individually. I'll go through some examples:

* **`test_basic_soname` and `test_custom_soname`:**  These tests involve building a shared library and then using `get_soname` (presumably a helper function) to verify the shared object name (`.so` file) has the correct name. This relates directly to how shared libraries are named and linked in Unix-like systems, which is relevant to reverse engineering (understanding library dependencies).
* **`test_pic`:** This test checks if the `-fPIC` compiler flag is used when building static libraries. `-fPIC` is crucial for creating position-independent code, essential for shared libraries and often relevant in reverse engineering when analyzing dynamically linked code. This touches on compiler flags and the build process.
* **`test_pkgconfig_gen` and related `test_pkgconfig_*` tests:** These tests focus on `pkg-config`, a standard tool for managing library dependencies in Unix-like systems. They check if generated `.pc` files are correct, have the right version, and handle dependencies properly. Understanding `pkg-config` is important in reverse engineering to understand the dependencies of a binary.
* **`test_symlink_builddir`:** This checks if Meson can handle a symbolic link as the build directory. This is more about the robustness of the build system itself.
* **`test_qtdependency_pkgconfig_detection` and `test_qt*dependency_qmake_detection`:** These tests verify that Meson can find Qt libraries using either `pkg-config` or `qmake`. This is specific to Qt development but highlights Meson's ability to handle external dependencies.
* **`test_generate_gir_with_address_sanitizer`:** This test checks integration with AddressSanitizer (ASan), a memory error detection tool. This is directly relevant to debugging and reverse engineering (identifying memory corruption issues).
* **`_test_soname_impl`, `test_soname`, `test_installed_soname`:** These delve deeper into the specifics of sonames, versioning, and how they are handled during installation. This is important for understanding library compatibility and linking.
* **`test_compiler_check_flags_order`:** This focuses on how Meson prioritizes compiler flags, ensuring that specific check flags override general optimization flags. This is crucial for the correctness of build checks.
* **`_test_stds_impl`, `test_compiler_c_stds`, `test_compiler_cpp_stds`:**  These tests ensure that Meson correctly handles different C and C++ language standards (e.g., `-std=c++17`, `-std=c11`). Understanding language standards is essential for reverse engineering code compiled with specific standards.
* **`test_unity_subproj`:** This tests Meson's "unity build" feature for subprojects, where multiple source files are combined into a single compilation unit to speed up builds.
* **`test_installed_modes` and `test_installed_modes_extended` and `test_install_umask`:** These tests meticulously verify the file permissions (read, write, execute) of installed files and directories. File permissions are a critical security aspect and can be relevant in reverse engineering to understand how a program interacts with the file system.

**4. Connecting to Reverse Engineering, Low-Level Aspects, etc.:**

As I analyzed each test case, I specifically looked for connections to the areas highlighted in the request:

* **Reverse Engineering:** Sonames, `pkg-config`, compiler flags (`-fPIC`, `-O`), language standards, and memory error detection tools (ASan) are all relevant to understanding how binaries are built, linked, and how they might behave.
* **Binary/Low-Level:**  Sonames are a binary-level concept in ELF files. Compiler flags directly influence the generated machine code. Understanding how libraries are linked is fundamental to understanding binary execution.
* **Linux/Android Kernel/Framework:** While this specific file doesn't directly interact with the kernel, the concepts of shared libraries, file permissions, and dependency management are core to these operating systems. The use of `pkg-config` is common in Linux development. The ASan test is also relevant to system-level debugging.
* **Logic and Assumptions:** For example, the `test_pic` test assumes that `-fPIC` will be present in the compiler command when `b_staticpic` is true.
* **User Errors:**  The `test_compiler_*_stds` tests implicitly check for user errors by verifying that invalid standard flags are caught.
* **User Journey/Debugging:** Understanding the test names and what they verify can help a developer (or someone debugging Meson) understand the specific feature being tested and potentially identify the cause of a build issue.

**5. Synthesizing the Information (Drafting the Summary):**

After analyzing the individual components, I started to synthesize the information into a coherent summary. I focused on:

* **The core purpose:** Testing functionality in Unix-like environments.
* **Key areas covered:** Shared libraries, static libraries, dependency management (`pkg-config`), compiler flags, language standards, installation procedures, and memory error detection.
* **Connections to the specific requirements:** Explicitly mentioning the relevance to reverse engineering, low-level concepts, etc.

**6. Refining and Structuring the Output:**

Finally, I structured the output clearly, using headings and bullet points to make it easy to read and understand. I ensured that the language was precise and addressed all aspects of the original request. I also paid attention to the specific request to summarize the functionality in the *first part*.

This iterative process of skimming, detailed analysis of individual components, connecting to the specific requirements, and synthesizing is crucial for understanding complex code and providing a comprehensive analysis.
这是名为 `linuxliketests.py` 的 Python 源代码文件，属于 Frida 动态 instrumentation 工具的测试套件，特别是针对 Linux 和类 Unix 系统的测试。它使用 Meson 构建系统进行构建和测试。

**它的主要功能是：**

1. **测试 Frida 在 Linux 和类 Unix 系统上的构建和功能:**  该文件包含了一系列单元测试，用于验证 Frida 在这些系统上的特定行为和特性是否符合预期。由于 Frida 作为一个跨平台的工具，针对不同平台的特定测试是必要的。

2. **测试与共享库 (`.so`) 相关的特性:** 许多测试关注共享库的构建和属性，例如 `soname` (共享对象名称) 的设置、版本控制以及与链接相关的行为。

3. **测试 `pkg-config` 的集成:**  `pkg-config` 是 Linux 系统中常用的用于管理库依赖的工具。该文件包含了大量测试，验证 Frida 能否正确生成和使用 `pkg-config` 文件，以及处理依赖关系。

4. **测试编译器行为和标志:**  某些测试检查编译器标志是否正确添加，例如 `-fPIC` (用于生成位置无关代码)，以及编译器如何处理不同的 C/C++ 标准。

5. **测试安装过程和文件权限:** 该文件还包含测试，验证 Frida 安装后的文件权限是否正确，包括可执行文件、库文件和数据文件。

6. **测试子项目和统一构建:**  一些测试涉及到 Meson 的子项目功能和统一构建 (unity build) 的特性。

**与逆向方法的关联及举例说明：**

该文件中的许多测试都与逆向工程密切相关，因为 Frida 本身就是一个强大的逆向工具。以下是一些例子：

* **`test_basic_soname` 和 `test_custom_soname`:**  在逆向工程中，理解共享库的 `soname` 非常重要。`soname` 决定了动态链接器在运行时如何找到依赖的库。如果 `soname` 设置不正确，可能导致程序无法正常加载。例如，在分析一个二进制文件时，可以使用 `readelf -d <binary>` 命令查看其依赖的共享库及其 `soname`。如果一个 Frida 脚本依赖于特定的共享库，确保 Frida 能正确找到和加载该库至关重要。这两个测试验证了 Frida 构建的共享库是否设置了正确的 `soname`。

* **`test_pic`:**  位置无关代码 (`-fPIC`) 对于共享库至关重要。共享库需要加载到进程的任意内存地址，而位置无关代码可以实现这一点。逆向工程师经常需要分析共享库，了解其内部结构和功能。确保 Frida 构建的共享库是位置无关的，对于 Frida 的正常工作和安全至关重要。

* **`test_pkgconfig_gen` 和相关测试:** `pkg-config` 用于管理库的编译和链接参数。在逆向工程中，理解目标程序依赖的库及其编译和链接方式可以帮助分析其结构和行为。Frida 脚本可能需要与目标程序使用的相同库进行交互。这些测试确保 Frida 能正确生成和使用 `pkg-config` 信息，这对于 Frida 脚本正确链接和使用目标程序依赖的库非常重要。例如，Frida 脚本可能需要获取目标程序依赖的库的头文件路径或链接库名称。

* **`test_generate_gir_with_address_sanitizer`:** AddressSanitizer (ASan) 是一种内存错误检测工具。在逆向工程中，ASan 可以帮助发现目标程序中的内存泄漏、野指针等安全漏洞。Frida 可以用于在运行时注入 ASan 到目标进程中进行分析。这个测试验证了 Frida 是否能在启用 ASan 的情况下正常生成 GIR (GObject Introspection) 文件，GIR 文件用于在运行时进行反射和动态调用。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

该文件涉及了以下方面的知识：

* **二进制底层:** `soname` 是 ELF 文件格式中的概念，涉及到动态链接器如何加载共享库。`-fPIC` 影响生成的机器码，使其可以在内存中的任意位置加载。

* **Linux 系统:**
    * **共享库 (`.so`):**  测试关注共享库的构建、链接和版本控制，这是 Linux 系统编程的基础知识。
    * **`pkg-config`:**  测试大量使用了 `pkg-config` 工具，这是 Linux 系统中用于管理库依赖的标准工具。
    * **文件权限:**  测试验证了安装后文件的权限设置，这是 Linux 安全模型的重要组成部分。
    * **进程环境:**  测试中修改和检查了环境变量，例如 `PKG_CONFIG_LIBDIR` 和 `PATH`，这涉及到 Linux 进程环境的概念。
    * **系统调用:**  虽然测试代码本身没有直接的系统调用，但它测试的功能（例如共享库加载）最终会涉及到内核的系统调用。

* **Android 内核及框架:** 虽然该文件名为 `linuxliketests.py`，主要关注 Linux，但其中一些概念和工具（例如共享库）也适用于 Android。Frida 也常用于 Android 平台的逆向工程。Android 使用了基于 Linux 内核的操作系统，其动态链接机制与 Linux 类似。

**逻辑推理及假设输入与输出：**

例如，在 `test_pic` 测试中，其逻辑推理是：

* **假设输入:**  构建配置中 `b_staticpic` 选项为 `true`。
* **推理:**  当构建静态库时，并且 `b_staticpic` 为 `true`，编译器命令中应该包含 `-fPIC` 标志。
* **输出:** 检查编译数据库 (compdb) 中，编译静态库的命令是否包含 `-fPIC`。

在 `test_pkgconfig_gen` 测试中：

* **假设输入:**  存在一个定义了 `libfoo` 的 `pkg-config` 文件。
* **推理:**  当 Meson 查找 `libfoo` 依赖时，应该能够通过 `pkg-config` 找到它，并获取其版本和链接参数。
* **输出:**  验证 `PkgConfigDependency('libfoo', ...)` 返回的对象 `foo_dep` 的 `found()` 方法返回 `True`，并且 `get_version()` 返回 `'1.0'`，`get_link_args()` 包含 `'-lfoo'`。

**用户或编程常见的使用错误及举例说明：**

该文件通过测试来预防和发现用户或编程中常见的错误，例如：

* **`soname` 设置错误:** 如果共享库的 `soname` 设置不正确，用户在链接时可能会遇到找不到库的错误。测试确保了 Frida 构建的库的 `soname` 是正确的。
* **`pkg-config` 文件配置错误:** 如果生成的 `pkg-config` 文件中的版本信息、链接参数或依赖关系不正确，用户在使用这些库时可能会遇到编译或链接错误。测试验证了 `pkg-config` 文件的正确性。
* **缺少 `-fPIC` 标志:** 如果在构建共享库时忘记添加 `-fPIC` 标志，可能会导致库加载失败或运行时错误。测试确保在需要时添加了 `-fPIC`。
* **文件权限设置错误:** 如果安装后的文件权限不正确，可能会导致程序无法执行或访问文件。测试验证了安装后文件的权限是否符合预期。
* **C/C++ 标准指定错误:** 如果用户在构建时指定了编译器不支持的 C/C++ 标准，会导致编译失败。测试验证了 Meson 能正确处理不同的标准选项，并能捕获无效的选项。

**用户操作是如何一步步的到达这里，作为调试线索：**

作为一个 Frida 的开发者或贡献者，或者一个想要调试 Frida 构建过程的用户，可能会按照以下步骤到达这个测试文件：

1. **克隆 Frida 的 Git 仓库:**  用户首先会从 GitHub 或其他来源克隆 Frida 的源代码仓库。
2. **浏览源代码目录:** 用户可能会在 `frida` 目录下探索不同的子项目和模块。
3. **进入 `frida-qml` 子项目:**  `frida-qml` 是 Frida 的一个子项目，提供了 QML 接口。用户可能会进入 `frida/subprojects/frida-qml` 目录。
4. **查看构建相关文件:** 用户可能会查看 `releng/meson` 目录，这里包含了与 Meson 构建系统相关的配置。
5. **查找测试文件:** 用户可能会进入 `unittests` 目录，寻找用于单元测试的文件。
6. **定位特定平台的测试:** 用户可能会根据文件名推断 `linuxliketests.py` 包含了针对 Linux 和类 Unix 系统的测试。

**作为调试线索：** 如果 Frida 在 Linux 或 macOS 等系统上构建或运行时出现问题，开发者可能会查看这个文件中的测试用例，以了解哪些功能正在被测试，以及是否有相关的测试用例失败。这可以帮助缩小问题范围，例如：

* 如果与共享库加载有关的问题，可能会查看 `test_basic_soname` 等测试。
* 如果与依赖库查找有关的问题，可能会查看 `test_pkgconfig_gen` 等测试。
* 如果与安装后的权限有关的问题，可能会查看 `test_installed_modes` 等测试。

**归纳一下它的功能 (第 1 部分):**

总而言之，`frida/subprojects/frida-qml/releng/meson/unittests/linuxliketests.py` 文件的主要功能是 **为 Frida 的 `frida-qml` 子项目在 Linux 和类 Unix 系统上提供一组全面的单元测试，用于验证其构建过程、核心功能（特别是与共享库和依赖管理相关的特性）以及安装过程的正确性。这些测试对于确保 Frida 在这些平台上的稳定性和可靠性至关重要，并且与逆向工程实践密切相关。**

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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