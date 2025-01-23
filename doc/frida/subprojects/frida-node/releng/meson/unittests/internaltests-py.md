Response:
The user wants to understand the functionality of the Python file `internaltests.py`. I need to analyze the code and explain what it does. Since it's part of the `frida` project's unit tests, its primary function is to test various internal components and functionalities of the `frida` build system, which is based on `meson`.

Here's a breakdown of what I can infer from the code:

1. **Unit Testing Framework:** The file uses Python's `unittest` module, indicating it's a collection of unit tests.
2. **Testing Targets:** The tests cover various aspects of the `meson` build system as used by `frida`, including:
    * Version number parsing.
    * File mode conversions.
    * Compiler argument handling and manipulation (including deduplication, ordering, and platform-specific arguments).
    * String template substitution for file names.
    * Cross-compilation configurations.
    * List manipulation utilities.
    * Library naming conventions and searching.
    * `pkg-config` integration for dependency management.
3. **Mocking and Fakes:** The code uses `unittest.mock` and defines "fake" environment and compiler options, suggesting it tests functionalities in isolation without relying on a real build environment.
4. **Platform Awareness:** The tests consider different operating systems (Linux, macOS, Windows, etc.) and compiler toolchains (GCC, Clang, MSVC).

Now, let's address the specific questions:

* **Functionality:**  The file contains unit tests for internal utilities and components of the `meson` build system used by `frida`.
* **Relationship to Reversing:** While the file itself doesn't perform direct reverse engineering, it tests the tools used to build `frida`, which *is* a dynamic instrumentation tool used for reverse engineering. The compiler argument tests, for example, ensure that the build system correctly passes necessary flags for creating libraries that `frida` uses for its instrumentation capabilities.
* **Binary, Kernel, Framework Knowledge:** The tests related to compiler arguments, especially those concerning linkers and library searching, touch upon the underlying mechanisms of how executables and libraries are built and linked in different operating systems. The `pkg-config` tests relate to how dependencies (which might involve system libraries or frameworks) are resolved.
* **Logical Reasoning (Hypothetical Input/Output):**  Many test functions perform logical checks. For instance, `test_version_number` takes various string formats as input and asserts the extracted version string as output. The compiler argument tests manipulate lists of arguments and check the final state.
* **Common User Errors:** The tests implicitly cover potential user errors. For example, incorrect cross-compilation configurations or misconfigured dependencies could lead to build failures. The tests ensure that the build system handles these situations correctly.
* **User Steps to Reach Here:** A developer working on the `frida` project or contributing to it would likely run these tests as part of their development workflow to ensure their changes haven't broken existing functionality. This involves navigating to the `frida/subprojects/frida-node/releng/meson/unittests/` directory and running the test suite (likely using a command like `pytest` or similar).

**Summary for Part 1:**  This Python file (`internaltests.py`) contains unit tests for internal utilities and functionalities of the `meson` build system within the `frida` project. It tests aspects like version parsing, file mode handling, compiler argument manipulation, string templating, cross-compilation settings, list utilities, library searching, and `pkg-config` integration. These tests are crucial for ensuring the correctness and robustness of `frida`'s build process.
这是文件 `frida/subprojects/frida-node/releng/meson/unittests/internaltests.py` 的第一部分源代码，它是一个用于测试 `frida` 动态 instrumentation 工具的内部功能的单元测试文件。

**功能归纳:**

总的来说，这个文件的主要功能是**测试 `frida` 项目中使用的 `meson` 构建系统的一些内部工具函数和类的正确性**。它涵盖了各种实用工具，主要集中在构建过程的底层细节和平台差异性处理上。

**更具体的功能点包括:**

1. **版本号解析测试:**  测试 `mesonbuild.mesonlib.search_version` 函数是否能正确地从各种字符串格式中提取版本号。
2. **文件模式转换测试:** 测试 `mesonbuild.mesonlib.FileMode.perms_s_to_bits` 函数是否能正确地将符号表示的文件权限转换为数字表示。
3. **编译器参数处理类测试 (`CompilerArgs`):**  测试 `mesonbuild.compilers.c.ClangCCompiler`, `mesonbuild.compilers.cpp.VisualStudioCPPCompiler`, `mesonbuild.compilers.d.DmdDCompiler`, 和 `mesonbuild.linkers.linkers` 中用于管理编译器和链接器参数的 `CompilerArgs` 类的功能，包括添加、删除、去重、排序等操作，以及针对不同编译器（如 Clang, Visual Studio, DMD）和链接器（如 GNU ld）的特定行为测试。
4. **字符串模板替换测试:** 测试 `mesonbuild.mesonlib.get_filenames_templates_dict` 和 `mesonbuild.mesonlib.substitute_values` 函数，它们用于在构建过程中根据输入输出文件名生成替换字典，并用这些字典来替换命令中的占位符。
5. **跨平台编译配置测试:** 测试在交叉编译场景下，是否能正确地根据配置文件覆盖默认的 `needs_exe_wrapper` 值。
6. **列表操作工具测试:** 测试 `mesonbuild.mesonlib.listify` 和 `mesonbuild.mesonlib.extract_as_list` 这两个列表处理工具函数的功能，包括扁平化列表和提取列表元素。
7. **库文件查找模式测试:** 测试不同操作系统下，查找共享库和静态库时的命名模式 (`mesonbuild.compilers.c.detect_c_compiler` 和其 `get_library_naming` 方法)。
8. **`pkg-config` 集成测试:** 测试 `mesonbuild.dependencies.pkgconfig.PkgConfigDependency` 类在解析 `pkg-config` 输出时，如何正确地提取库文件路径，并处理静态链接库。

**与逆向方法的关联及举例说明:**

虽然这个文件本身不直接进行逆向操作，但它测试的是构建系统的组件，而构建系统最终会生成 `frida` 这个逆向工具本身。

* **编译器参数测试:**  例如，测试 `CompilerArgs` 类确保了在编译 `frida` 的 native 组件时，能够正确地传递必要的编译选项（例如，定义宏、指定头文件路径等）。这些编译选项会直接影响生成的可执行文件或库的行为，逆向工程师在分析这些二进制文件时会遇到这些编译选项的影响。
    * **例子:** 测试中添加和删除 `-I` 参数，模拟了在构建时指定头文件搜索路径的过程。如果头文件路径不正确，`frida` 的某些功能可能无法编译，或者链接到错误的库，这会影响其逆向功能。
* **库文件查找模式测试:** `frida` 依赖于一些系统库或其他第三方库。测试库文件查找模式确保了在不同的操作系统上，`meson` 能够正确找到这些依赖库，并将它们链接到 `frida` 中。这关系到 `frida` 的核心功能是否能够正常运行。
    * **例子:**  测试 OpenBSD 下共享库的查找模式，确保了在 OpenBSD 系统上构建 `frida` 时，能够找到类似 `libfoo.so.6.0` 这样的库。

**涉及二进制底层、Linux, Android 内核及框架的知识及举例说明:**

* **二进制底层:**
    * **文件模式:** 测试文件模式转换涉及到对 Unix 文件系统权限的理解，这是操作系统底层概念。
    * **链接器参数:**  测试 GNU ld 的 `--start-group` 和 `--end-group` 参数，这涉及到链接器如何处理循环依赖的库。
    * **库文件命名约定:** 测试不同平台下共享库（`.so`, `.dylib`, `.dll`）和静态库（`.a`, `.lib`) 的命名约定，这直接关系到二进制文件的链接过程。
* **Linux:**
    * **库文件路径:** 测试中涉及到 `/usr/include`, `/usr/share/include`, `/usr/local/include` 等 Linux 系统常见的头文件和库文件路径。
    * **`pkg-config`:**  `pkg-config` 是 Linux 系统中常用的用于获取库依赖信息的工具。测试 `PkgConfigDependency` 涉及到理解 `pkg-config` 的工作原理以及如何解析其输出。
* **Android 内核及框架:**  虽然这个特定的测试文件没有直接涉及 Android 特定的内核或框架知识，但 `frida` 作为一款动态 instrumentation 工具，其核心功能必然会深入到 Android 系统的底层，例如进程间通信、内存操作、系统调用等。这个构建系统的正确性是 `frida` 能否在 Android 上正常运行的基础。

**逻辑推理 (假设输入与输出):**

* **`test_version_number`:**
    * **假设输入:** 字符串 `"foobar 1.2.3"`
    * **预期输出:** 字符串 `"1.2.3"`
* **`test_mode_symbolic_to_bits`:**
    * **假设输入:** 字符串 `"rwxr-xr-x"`
    * **预期输出:**  `stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH` 的整数值
* **`test_compiler_args_class_clike`:**
    * **假设输入:** 一个 `ClangCCompiler` 实例，并执行 `a += ['-Ifoo', '-Ifoo']`
    * **预期输出:**  编译器参数列表 `['-Ifoo', '-I..', '-I.', '-O3', '-O2']` (假设之前的状态如此，展示了去重功能)
* **`test_string_templates_substitution`:**
    * **假设输入:** `inputs = ['bar/foo.c.in']`, `outputs = ['out.c']`, `cmd = ['@INPUT@.out', '@OUTPUT@']`
    * **预期输出:** `['bar/foo.c.in.out', 'out.c']`

**用户或编程常见的使用错误及举例说明:**

* **编译器参数重复:**  测试 `CompilerArgs` 类的去重功能，避免了用户在构建脚本中意外添加重复的编译器参数，这可能导致构建问题或非预期的行为。
* **字符串模板占位符错误使用:** 测试中会抛出 `MesonException`，例如当输入文件只有一个，却使用了 `@INPUT1@` 这样的占位符，或者在没有输出文件的情况下使用了 `@OUTPUT@` 占位符，这模拟了用户在编写构建脚本时可能犯的错误。
* **库文件依赖配置错误:** `pkg-config` 测试模拟了 `pkg-config` 返回的库路径信息，如果用户配置的 `pkg-config` 信息不正确，可能会导致链接到错误的库或者找不到库。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发或贡献 `frida` 项目:**  一个开发者正在修改 `frida` 的构建系统，或者添加新的功能，这涉及到修改 `meson.build` 文件或者相关的 Python 代码。
2. **运行单元测试:** 为了确保修改没有破坏现有的功能，开发者会运行 `frida` 的单元测试套件。这通常涉及到在命令行中执行特定的命令，例如 `pytest` 或 `meson test`。
3. **测试框架执行:**  当运行单元测试时，测试框架会加载并执行 `frida/subprojects/frida-node/releng/meson/unittests/` 目录下的所有测试文件，包括 `internaltests.py`。
4. **测试用例执行:**  测试框架会依次执行 `InternalTests` 类中定义的各个以 `test_` 开头的方法（例如 `test_version_number`， `test_compiler_args_class_clike` 等）。
5. **断言检查:**  每个测试用例内部会进行各种断言 (`self.assertEqual`, `self.assertRaises` 等)，用来检查被测试的函数或类的行为是否符合预期。如果断言失败，就表明代码存在 bug。

因此，作为调试线索，如果某个 `frida` 的构建过程出现问题，开发者可能会检查这些单元测试是否通过。如果与编译器参数、库文件查找、或者模板替换相关的测试失败，就能缩小问题的范围，定位到可能是这些内部工具函数或类出现了错误。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
# Copyright 2016-2021 The Meson development team

from configparser import ConfigParser
from pathlib import Path
from unittest import mock
import contextlib
import io
import json
import operator
import os
import pickle
import stat
import subprocess
import tempfile
import typing as T
import unittest

import mesonbuild.mlog
import mesonbuild.depfile
import mesonbuild.dependencies.base
import mesonbuild.dependencies.factory
import mesonbuild.envconfig
import mesonbuild.environment
import mesonbuild.modules.gnome
from mesonbuild import coredata
from mesonbuild.compilers.c import ClangCCompiler, GnuCCompiler
from mesonbuild.compilers.cpp import VisualStudioCPPCompiler
from mesonbuild.compilers.d import DmdDCompiler
from mesonbuild.linkers import linkers
from mesonbuild.interpreterbase import typed_pos_args, InvalidArguments, ObjectHolder
from mesonbuild.interpreterbase import typed_pos_args, InvalidArguments, typed_kwargs, ContainerTypeInfo, KwargInfo
from mesonbuild.mesonlib import (
    LibType, MachineChoice, PerMachine, Version, is_windows, is_osx,
    is_cygwin, is_openbsd, search_version, MesonException, OptionKey,
    OptionType
)
from mesonbuild.interpreter.type_checking import in_set_validator, NoneType
from mesonbuild.dependencies.pkgconfig import PkgConfigDependency, PkgConfigInterface, PkgConfigCLI
from mesonbuild.programs import ExternalProgram
import mesonbuild.modules.pkgconfig


from run_tests import (
    FakeCompilerOptions, get_fake_env, get_fake_options
)

from .helpers import *

class InternalTests(unittest.TestCase):

    def test_version_number(self):
        self.assertEqual(search_version('foobar 1.2.3'), '1.2.3')
        self.assertEqual(search_version('1.2.3'), '1.2.3')
        self.assertEqual(search_version('foobar 2016.10.28 1.2.3'), '1.2.3')
        self.assertEqual(search_version('2016.10.28 1.2.3'), '1.2.3')
        self.assertEqual(search_version('foobar 2016.10.128'), '2016.10.128')
        self.assertEqual(search_version('2016.10.128'), '2016.10.128')
        self.assertEqual(search_version('2016.10'), '2016.10')
        self.assertEqual(search_version('2016.10 1.2.3'), '1.2.3')
        self.assertEqual(search_version('oops v1.2.3'), '1.2.3')
        self.assertEqual(search_version('2016.oops 1.2.3'), '1.2.3')
        self.assertEqual(search_version('2016.x'), 'unknown version')
        self.assertEqual(search_version(r'something version is \033[32;2m1.2.0\033[0m.'), '1.2.0')

        # Literal output of mvn
        self.assertEqual(search_version(r'''\
            \033[1mApache Maven 3.8.1 (05c21c65bdfed0f71a2f2ada8b84da59348c4c5d)\033[0m
            Maven home: /nix/store/g84a9wnid2h1d3z2wfydy16dky73wh7i-apache-maven-3.8.1/maven
            Java version: 11.0.10, vendor: Oracle Corporation, runtime: /nix/store/afsnl4ahmm9svvl7s1a0cj41vw4nkmz4-openjdk-11.0.10+9/lib/openjdk
            Default locale: en_US, platform encoding: UTF-8
            OS name: "linux", version: "5.12.17", arch: "amd64", family: "unix"'''),
            '3.8.1')

    def test_mode_symbolic_to_bits(self):
        modefunc = mesonbuild.mesonlib.FileMode.perms_s_to_bits
        self.assertEqual(modefunc('---------'), 0)
        self.assertEqual(modefunc('r--------'), stat.S_IRUSR)
        self.assertEqual(modefunc('---r-----'), stat.S_IRGRP)
        self.assertEqual(modefunc('------r--'), stat.S_IROTH)
        self.assertEqual(modefunc('-w-------'), stat.S_IWUSR)
        self.assertEqual(modefunc('----w----'), stat.S_IWGRP)
        self.assertEqual(modefunc('-------w-'), stat.S_IWOTH)
        self.assertEqual(modefunc('--x------'), stat.S_IXUSR)
        self.assertEqual(modefunc('-----x---'), stat.S_IXGRP)
        self.assertEqual(modefunc('--------x'), stat.S_IXOTH)
        self.assertEqual(modefunc('--S------'), stat.S_ISUID)
        self.assertEqual(modefunc('-----S---'), stat.S_ISGID)
        self.assertEqual(modefunc('--------T'), stat.S_ISVTX)
        self.assertEqual(modefunc('--s------'), stat.S_ISUID | stat.S_IXUSR)
        self.assertEqual(modefunc('-----s---'), stat.S_ISGID | stat.S_IXGRP)
        self.assertEqual(modefunc('--------t'), stat.S_ISVTX | stat.S_IXOTH)
        self.assertEqual(modefunc('rwx------'), stat.S_IRWXU)
        self.assertEqual(modefunc('---rwx---'), stat.S_IRWXG)
        self.assertEqual(modefunc('------rwx'), stat.S_IRWXO)
        # We could keep listing combinations exhaustively but that seems
        # tedious and pointless. Just test a few more.
        self.assertEqual(modefunc('rwxr-xr-x'),
                         stat.S_IRWXU |
                         stat.S_IRGRP | stat.S_IXGRP |
                         stat.S_IROTH | stat.S_IXOTH)
        self.assertEqual(modefunc('rw-r--r--'),
                         stat.S_IRUSR | stat.S_IWUSR |
                         stat.S_IRGRP |
                         stat.S_IROTH)
        self.assertEqual(modefunc('rwsr-x---'),
                         stat.S_IRWXU | stat.S_ISUID |
                         stat.S_IRGRP | stat.S_IXGRP)

    def test_compiler_args_class_none_flush(self):
        cc = ClangCCompiler([], [], 'fake', MachineChoice.HOST, False, mock.Mock())
        a = cc.compiler_args(['-I.'])
        #first we are checking if the tree construction deduplicates the correct -I argument
        a += ['-I..']
        a += ['-I./tests/']
        a += ['-I./tests2/']
        #think this here as assertion, we cannot apply it, otherwise the CompilerArgs would already flush the changes:
        # assertEqual(a, ['-I.', '-I./tests2/', '-I./tests/', '-I..', '-I.'])
        a += ['-I.']
        a += ['-I.', '-I./tests/']
        self.assertEqual(a, ['-I.', '-I./tests/', '-I./tests2/', '-I..'])

        #then we are checking that when CompilerArgs already have a build container list, that the deduplication is taking the correct one
        a += ['-I.', '-I./tests2/']
        self.assertEqual(a, ['-I.', '-I./tests2/', '-I./tests/', '-I..'])

    def test_compiler_args_class_d(self):
        d = DmdDCompiler([], 'fake', MachineChoice.HOST, 'info', 'arch')
        # check include order is kept when deduplicating
        a = d.compiler_args(['-Ifirst', '-Isecond', '-Ithird'])
        a += ['-Ifirst']
        self.assertEqual(a, ['-Ifirst', '-Isecond', '-Ithird'])

    def test_compiler_args_class_clike(self):
        cc = ClangCCompiler([], [], 'fake', MachineChoice.HOST, False, mock.Mock())
        # Test that empty initialization works
        a = cc.compiler_args()
        self.assertEqual(a, [])
        # Test that list initialization works
        a = cc.compiler_args(['-I.', '-I..'])
        self.assertEqual(a, ['-I.', '-I..'])
        # Test that there is no de-dup on initialization
        self.assertEqual(cc.compiler_args(['-I.', '-I.']), ['-I.', '-I.'])

        ## Test that appending works
        a.append('-I..')
        self.assertEqual(a, ['-I..', '-I.'])
        a.append('-O3')
        self.assertEqual(a, ['-I..', '-I.', '-O3'])

        ## Test that in-place addition works
        a += ['-O2', '-O2']
        self.assertEqual(a, ['-I..', '-I.', '-O3', '-O2', '-O2'])
        # Test that removal works
        a.remove('-O2')
        self.assertEqual(a, ['-I..', '-I.', '-O3', '-O2'])
        # Test that de-dup happens on addition
        a += ['-Ifoo', '-Ifoo']
        self.assertEqual(a, ['-Ifoo', '-I..', '-I.', '-O3', '-O2'])

        # .extend() is just +=, so we don't test it

        ## Test that addition works
        # Test that adding a list with just one old arg works and yields the same array
        a = a + ['-Ifoo']
        self.assertEqual(a, ['-Ifoo', '-I..', '-I.', '-O3', '-O2'])
        # Test that adding a list with one arg new and one old works
        a = a + ['-Ifoo', '-Ibaz']
        self.assertEqual(a, ['-Ifoo', '-Ibaz', '-I..', '-I.', '-O3', '-O2'])
        # Test that adding args that must be prepended and appended works
        a = a + ['-Ibar', '-Wall']
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-O3', '-O2', '-Wall'])

        ## Test that reflected addition works
        # Test that adding to a list with just one old arg works and yields the same array
        a = ['-Ifoo'] + a
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-O3', '-O2', '-Wall'])
        # Test that adding to a list with just one new arg that is not pre-pended works
        a = ['-Werror'] + a
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-Werror', '-O3', '-O2', '-Wall'])
        # Test that adding to a list with two new args preserves the order
        a = ['-Ldir', '-Lbah'] + a
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-Ldir', '-Lbah', '-Werror', '-O3', '-O2', '-Wall'])
        # Test that adding to a list with old args does nothing
        a = ['-Ibar', '-Ibaz', '-Ifoo'] + a
        self.assertEqual(a, ['-Ibar', '-Ifoo', '-Ibaz', '-I..', '-I.', '-Ldir', '-Lbah', '-Werror', '-O3', '-O2', '-Wall'])

        ## Test that adding libraries works
        l = cc.compiler_args(['-Lfoodir', '-lfoo'])
        self.assertEqual(l, ['-Lfoodir', '-lfoo'])
        # Adding a library and a libpath appends both correctly
        l += ['-Lbardir', '-lbar']
        self.assertEqual(l, ['-Lbardir', '-Lfoodir', '-lfoo', '-lbar'])
        # Adding the same library again does nothing
        l += ['-lbar']
        self.assertEqual(l, ['-Lbardir', '-Lfoodir', '-lfoo', '-lbar'])

        ## Test that 'direct' append and extend works
        l = cc.compiler_args(['-Lfoodir', '-lfoo'])
        self.assertEqual(l, ['-Lfoodir', '-lfoo'])
        # Direct-adding a library and a libpath appends both correctly
        l.extend_direct(['-Lbardir', '-lbar'])
        self.assertEqual(l, ['-Lfoodir', '-lfoo', '-Lbardir', '-lbar'])
        # Direct-adding the same library again still adds it
        l.append_direct('-lbar')
        self.assertEqual(l, ['-Lfoodir', '-lfoo', '-Lbardir', '-lbar', '-lbar'])
        # Direct-adding with absolute path deduplicates
        l.append_direct('/libbaz.a')
        self.assertEqual(l, ['-Lfoodir', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a'])
        # Adding libbaz again does nothing
        l.append_direct('/libbaz.a')
        self.assertEqual(l, ['-Lfoodir', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a'])


    def test_compiler_args_class_visualstudio(self):
        linker = linkers.MSVCDynamicLinker(MachineChoice.HOST, [])
        # Version just needs to be > 19.0.0
        cc = VisualStudioCPPCompiler([], [], '20.00', MachineChoice.HOST, False, mock.Mock(), 'x64', linker=linker)

        a = cc.compiler_args(cc.get_always_args())
        self.assertEqual(a.to_native(copy=True), ['/nologo', '/showIncludes', '/utf-8', '/Zc:__cplusplus'])

        # Ensure /source-charset: removes /utf-8
        a.append('/source-charset:utf-8')
        self.assertEqual(a.to_native(copy=True), ['/nologo', '/showIncludes', '/Zc:__cplusplus', '/source-charset:utf-8'])

        # Ensure /execution-charset: removes /utf-8
        a = cc.compiler_args(cc.get_always_args() + ['/execution-charset:utf-8'])
        self.assertEqual(a.to_native(copy=True), ['/nologo', '/showIncludes', '/Zc:__cplusplus', '/execution-charset:utf-8'])

        # Ensure /validate-charset- removes /utf-8
        a = cc.compiler_args(cc.get_always_args() + ['/validate-charset-'])
        self.assertEqual(a.to_native(copy=True), ['/nologo', '/showIncludes', '/Zc:__cplusplus', '/validate-charset-'])


    def test_compiler_args_class_gnuld(self):
        ## Test --start/end-group
        linker = linkers.GnuBFDDynamicLinker([], MachineChoice.HOST, '-Wl,', [])
        gcc = GnuCCompiler([], [], 'fake', False, MachineChoice.HOST, mock.Mock(), linker=linker)
        ## Ensure that the fake compiler is never called by overriding the relevant function
        gcc.get_default_include_dirs = lambda: ['/usr/include', '/usr/share/include', '/usr/local/include']
        ## Test that 'direct' append and extend works
        l = gcc.compiler_args(['-Lfoodir', '-lfoo'])
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-lfoo'])
        # Direct-adding a library and a libpath appends both correctly
        l.extend_direct(['-Lbardir', '-lbar'])
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-Wl,--end-group'])
        # Direct-adding the same library again still adds it
        l.append_direct('-lbar')
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '-Wl,--end-group'])
        # Direct-adding with absolute path deduplicates
        l.append_direct('/libbaz.a')
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a', '-Wl,--end-group'])
        # Adding libbaz again does nothing
        l.append_direct('/libbaz.a')
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a', '-Wl,--end-group'])
        # Adding a non-library argument doesn't include it in the group
        l += ['-Lfoo', '-Wl,--export-dynamic']
        self.assertEqual(l.to_native(copy=True), ['-Lfoo', '-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a', '-Wl,--end-group', '-Wl,--export-dynamic'])
        # -Wl,-lfoo is detected as a library and gets added to the group
        l.append('-Wl,-ldl')
        self.assertEqual(l.to_native(copy=True), ['-Lfoo', '-Lfoodir', '-Wl,--start-group', '-lfoo', '-Lbardir', '-lbar', '-lbar', '/libbaz.a', '-Wl,--export-dynamic', '-Wl,-ldl', '-Wl,--end-group'])

    def test_compiler_args_remove_system(self):
        ## Test --start/end-group
        linker = linkers.GnuBFDDynamicLinker([], MachineChoice.HOST, '-Wl,', [])
        gcc = GnuCCompiler([], [], 'fake', False, MachineChoice.HOST, mock.Mock(), linker=linker)
        ## Ensure that the fake compiler is never called by overriding the relevant function
        gcc.get_default_include_dirs = lambda: ['/usr/include', '/usr/share/include', '/usr/local/include']
        ## Test that 'direct' append and extend works
        l = gcc.compiler_args(['-Lfoodir', '-lfoo'])
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-lfoo'])
        ## Test that to_native removes all system includes
        l += ['-isystem/usr/include', '-isystem=/usr/share/include', '-DSOMETHING_IMPORTANT=1', '-isystem', '/usr/local/include']
        self.assertEqual(l.to_native(copy=True), ['-Lfoodir', '-lfoo', '-DSOMETHING_IMPORTANT=1'])

    def test_string_templates_substitution(self):
        dictfunc = mesonbuild.mesonlib.get_filenames_templates_dict
        substfunc = mesonbuild.mesonlib.substitute_values
        ME = mesonbuild.mesonlib.MesonException

        # Identity
        self.assertEqual(dictfunc([], []), {})

        # One input, no outputs
        inputs = ['bar/foo.c.in']
        outputs = []
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0],
             '@PLAINNAME@': 'foo.c.in', '@BASENAME@': 'foo.c'}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@INPUT@.out', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), [inputs[0] + '.out'] + cmd[1:])
        cmd = ['@INPUT0@.out', '@PLAINNAME@.ok', 'strings']
        self.assertEqual(substfunc(cmd, d),
                         [inputs[0] + '.out'] + [d['@PLAINNAME@'] + '.ok'] + cmd[2:])
        cmd = ['@INPUT@', '@BASENAME@.hah', 'strings']
        self.assertEqual(substfunc(cmd, d),
                         inputs + [d['@BASENAME@'] + '.hah'] + cmd[2:])
        cmd = ['@OUTPUT@']
        self.assertRaises(ME, substfunc, cmd, d)

        # One input, one output
        inputs = ['bar/foo.c.in']
        outputs = ['out.c']
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0],
             '@PLAINNAME@': 'foo.c.in', '@BASENAME@': 'foo.c',
             '@OUTPUT@': outputs, '@OUTPUT0@': outputs[0], '@OUTDIR@': '.'}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@INPUT@.out', '@OUTPUT@', 'strings']
        self.assertEqual(substfunc(cmd, d),
                         [inputs[0] + '.out'] + outputs + cmd[2:])
        cmd = ['@INPUT0@.out', '@PLAINNAME@.ok', '@OUTPUT0@']
        self.assertEqual(substfunc(cmd, d),
                         [inputs[0] + '.out', d['@PLAINNAME@'] + '.ok'] + outputs)
        cmd = ['@INPUT@', '@BASENAME@.hah', 'strings']
        self.assertEqual(substfunc(cmd, d),
                         inputs + [d['@BASENAME@'] + '.hah'] + cmd[2:])

        # One input, one output with a subdir
        outputs = ['dir/out.c']
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0],
             '@PLAINNAME@': 'foo.c.in', '@BASENAME@': 'foo.c',
             '@OUTPUT@': outputs, '@OUTPUT0@': outputs[0], '@OUTDIR@': 'dir'}
        # Check dictionary
        self.assertEqual(ret, d)

        # Two inputs, no outputs
        inputs = ['bar/foo.c.in', 'baz/foo.c.in']
        outputs = []
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0], '@INPUT1@': inputs[1]}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@INPUT@', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), inputs + cmd[1:])
        cmd = ['@INPUT0@.out', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), [inputs[0] + '.out'] + cmd[1:])
        cmd = ['@INPUT0@.out', '@INPUT1@.ok', 'strings']
        self.assertEqual(substfunc(cmd, d), [inputs[0] + '.out', inputs[1] + '.ok'] + cmd[2:])
        cmd = ['@INPUT0@', '@INPUT1@', 'strings']
        self.assertEqual(substfunc(cmd, d), inputs + cmd[2:])
        # Many inputs, can't use @INPUT@ like this
        cmd = ['@INPUT@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough inputs
        cmd = ['@INPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Too many inputs
        cmd = ['@PLAINNAME@']
        self.assertRaises(ME, substfunc, cmd, d)
        cmd = ['@BASENAME@']
        self.assertRaises(ME, substfunc, cmd, d)
        # No outputs
        cmd = ['@OUTPUT@']
        self.assertRaises(ME, substfunc, cmd, d)
        cmd = ['@OUTPUT0@']
        self.assertRaises(ME, substfunc, cmd, d)
        cmd = ['@OUTDIR@']
        self.assertRaises(ME, substfunc, cmd, d)

        # Two inputs, one output
        outputs = ['dir/out.c']
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0], '@INPUT1@': inputs[1],
             '@OUTPUT@': outputs, '@OUTPUT0@': outputs[0], '@OUTDIR@': 'dir'}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@OUTPUT@', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), outputs + cmd[1:])
        cmd = ['@OUTPUT@.out', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), [outputs[0] + '.out'] + cmd[1:])
        cmd = ['@OUTPUT0@.out', '@INPUT1@.ok', 'strings']
        self.assertEqual(substfunc(cmd, d), [outputs[0] + '.out', inputs[1] + '.ok'] + cmd[2:])
        # Many inputs, can't use @INPUT@ like this
        cmd = ['@INPUT@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough inputs
        cmd = ['@INPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough outputs
        cmd = ['@OUTPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)

        # Two inputs, two outputs
        outputs = ['dir/out.c', 'dir/out2.c']
        ret = dictfunc(inputs, outputs)
        d = {'@INPUT@': inputs, '@INPUT0@': inputs[0], '@INPUT1@': inputs[1],
             '@OUTPUT@': outputs, '@OUTPUT0@': outputs[0], '@OUTPUT1@': outputs[1],
             '@OUTDIR@': 'dir'}
        # Check dictionary
        self.assertEqual(ret, d)
        # Check substitutions
        cmd = ['some', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), cmd)
        cmd = ['@OUTPUT@', 'ordinary', 'strings']
        self.assertEqual(substfunc(cmd, d), outputs + cmd[1:])
        cmd = ['@OUTPUT0@', '@OUTPUT1@', 'strings']
        self.assertEqual(substfunc(cmd, d), outputs + cmd[2:])
        cmd = ['@OUTPUT0@.out', '@INPUT1@.ok', '@OUTDIR@']
        self.assertEqual(substfunc(cmd, d), [outputs[0] + '.out', inputs[1] + '.ok', 'dir'])
        # Many inputs, can't use @INPUT@ like this
        cmd = ['@INPUT@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough inputs
        cmd = ['@INPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Not enough outputs
        cmd = ['@OUTPUT2@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)
        # Many outputs, can't use @OUTPUT@ like this
        cmd = ['@OUTPUT@.out', 'ordinary', 'strings']
        self.assertRaises(ME, substfunc, cmd, d)

    def test_needs_exe_wrapper_override(self):
        config = ConfigParser()
        config['binaries'] = {
            'c': '\'/usr/bin/gcc\'',
        }
        config['host_machine'] = {
            'system': '\'linux\'',
            'cpu_family': '\'arm\'',
            'cpu': '\'armv7\'',
            'endian': '\'little\'',
        }
        # Can not be used as context manager because we need to
        # open it a second time and this is not possible on
        # Windows.
        configfile = tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8')
        configfilename = configfile.name
        config.write(configfile)
        configfile.flush()
        configfile.close()
        opts = get_fake_options()
        opts.cross_file = (configfilename,)
        env = get_fake_env(opts=opts)
        detected_value = env.need_exe_wrapper()
        os.unlink(configfilename)

        desired_value = not detected_value
        config['properties'] = {
            'needs_exe_wrapper': 'true' if desired_value else 'false'
        }

        configfile = tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8')
        configfilename = configfile.name
        config.write(configfile)
        configfile.close()
        opts = get_fake_options()
        opts.cross_file = (configfilename,)
        env = get_fake_env(opts=opts)
        forced_value = env.need_exe_wrapper()
        os.unlink(configfilename)

        self.assertEqual(forced_value, desired_value)

    def test_listify(self):
        listify = mesonbuild.mesonlib.listify
        # Test sanity
        self.assertEqual([1], listify(1))
        self.assertEqual([], listify([]))
        self.assertEqual([1], listify([1]))
        # Test flattening
        self.assertEqual([1, 2, 3], listify([1, [2, 3]]))
        self.assertEqual([1, 2, 3], listify([1, [2, [3]]]))
        self.assertEqual([1, [2, [3]]], listify([1, [2, [3]]], flatten=False))
        # Test flattening and unholdering
        class TestHeldObj(mesonbuild.mesonlib.HoldableObject):
            def __init__(self, val: int) -> None:
                self._val = val
        class MockInterpreter:
            def __init__(self) -> None:
                self.subproject = ''
                self.environment = None
        heldObj1 = TestHeldObj(1)
        holder1 = ObjectHolder(heldObj1, MockInterpreter())
        self.assertEqual([holder1], listify(holder1))
        self.assertEqual([holder1], listify([holder1]))
        self.assertEqual([holder1, 2], listify([holder1, 2]))
        self.assertEqual([holder1, 2, 3], listify([holder1, 2, [3]]))

    def test_extract_as_list(self):
        extract = mesonbuild.mesonlib.extract_as_list
        # Test sanity
        kwargs = {'sources': [1, 2, 3]}
        self.assertEqual([1, 2, 3], extract(kwargs, 'sources'))
        self.assertEqual(kwargs, {'sources': [1, 2, 3]})
        self.assertEqual([1, 2, 3], extract(kwargs, 'sources', pop=True))
        self.assertEqual(kwargs, {})

        class TestHeldObj(mesonbuild.mesonlib.HoldableObject):
            pass
        class MockInterpreter:
            def __init__(self) -> None:
                self.subproject = ''
                self.environment = None
        heldObj = TestHeldObj()

        # Test unholding
        holder3 = ObjectHolder(heldObj, MockInterpreter())
        kwargs = {'sources': [1, 2, holder3]}
        self.assertEqual(kwargs, {'sources': [1, 2, holder3]})

        # flatten nested lists
        kwargs = {'sources': [1, [2, [3]]]}
        self.assertEqual([1, 2, 3], extract(kwargs, 'sources'))

    def _test_all_naming(self, cc, env, patterns, platform):
        shr = patterns[platform]['shared']
        stc = patterns[platform]['static']
        shrstc = shr + tuple(x for x in stc if x not in shr)
        stcshr = stc + tuple(x for x in shr if x not in stc)
        p = cc.get_library_naming(env, LibType.SHARED)
        self.assertEqual(p, shr)
        p = cc.get_library_naming(env, LibType.STATIC)
        self.assertEqual(p, stc)
        p = cc.get_library_naming(env, LibType.PREFER_STATIC)
        self.assertEqual(p, stcshr)
        p = cc.get_library_naming(env, LibType.PREFER_SHARED)
        self.assertEqual(p, shrstc)
        # Test find library by mocking up openbsd
        if platform != 'openbsd':
            return
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in ['libfoo.so.6.0', 'libfoo.so.5.0', 'libfoo.so.54.0', 'libfoo.so.66a.0b', 'libfoo.so.70.0.so.1',
                      'libbar.so.7.10', 'libbar.so.7.9', 'libbar.so.7.9.3']:
                libpath = Path(tmpdir) / i
                libpath.write_text('', encoding='utf-8')
            found = cc._find_library_real('foo', env, [tmpdir], '', LibType.PREFER_SHARED, lib_prefix_warning=True)
            self.assertEqual(os.path.basename(found[0]), 'libfoo.so.54.0')
            found = cc._find_library_real('bar', env, [tmpdir], '', LibType.PREFER_SHARED, lib_prefix_warning=True)
            self.assertEqual(os.path.basename(found[0]), 'libbar.so.7.10')

    def test_find_library_patterns(self):
        '''
        Unit test for the library search patterns used by find_library()
        '''
        unix_static = ('lib{}.a', '{}.a')
        msvc_static = ('lib{}.a', 'lib{}.lib', '{}.a', '{}.lib')
        # This is the priority list of pattern matching for library searching
        patterns = {'openbsd': {'shared': ('lib{}.so', '{}.so', 'lib{}.so.[0-9]*.[0-9]*', '{}.so.[0-9]*.[0-9]*'),
                                'static': unix_static},
                    'linux': {'shared': ('lib{}.so', '{}.so'),
                              'static': unix_static},
                    'darwin': {'shared': ('lib{}.dylib', 'lib{}.so', '{}.dylib', '{}.so'),
                               'static': unix_static},
                    'cygwin': {'shared': ('cyg{}.dll', 'cyg{}.dll.a', 'lib{}.dll',
                                          'lib{}.dll.a', '{}.dll', '{}.dll.a'),
                               'static': ('cyg{}.a',) + unix_static},
                    'windows-msvc': {'shared': ('lib{}.lib', '{}.lib'),
                                     'static': msvc_static},
                    'windows-mingw': {'shared': ('lib{}.dll.a', 'lib{}.lib', 'lib{}.dll',
                                                 '{}.dll.a', '{}.lib', '{}.dll'),
                                      'static': msvc_static}}
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if is_osx():
            self._test_all_naming(cc, env, patterns, 'darwin')
        elif is_cygwin():
            self._test_all_naming(cc, env, patterns, 'cygwin')
        elif is_windows():
            if cc.get_argument_syntax() == 'msvc':
                self._test_all_naming(cc, env, patterns, 'windows-msvc')
            else:
                self._test_all_naming(cc, env, patterns, 'windows-mingw')
        elif is_openbsd():
            self._test_all_naming(cc, env, patterns, 'openbsd')
        else:
            self._test_all_naming(cc, env, patterns, 'linux')
            env.machines.host.system = 'openbsd'
            self._test_all_naming(cc, env, patterns, 'openbsd')
            env.machines.host.system = 'darwin'
            self._test_all_naming(cc, env, patterns, 'darwin')
            env.machines.host.system = 'cygwin'
            self._test_all_naming(cc, env, patterns, 'cygwin')
            env.machines.host.system = 'windows'
            self._test_all_naming(cc, env, patterns, 'windows-mingw')

    @skipIfNoPkgconfig
    def test_pkgconfig_parse_libs(self):
        '''
        Unit test for parsing of pkg-config output to search for libraries

        https://github.com/mesonbuild/meson/issues/3951
        '''
        def create_static_lib(name):
            if not is_osx():
                name.open('w', encoding='utf-8').close()
                return
            src = name.with_suffix('.c')
            out = name.with_suffix('.o')
            with src.open('w', encoding='utf-8') as f:
                f.write('int meson_foobar (void) { return 0; }')
            # use of x86_64 is hardcoded in run_tests.py:get_fake_env()
            subprocess.check_call(['clang', '-c', str(src), '-o', str(out), '-arch', 'x86_64'])
            subprocess.check_call(['ar', 'csr', str(name), str(out)])

        with tempfile.TemporaryDirectory() as tmpdir:
            pkgbin = ExternalProgram('pkg-config', command=['pkg-config'], silent=True)
            env = get_fake_env()
            compiler = detect_c_compiler(env, MachineChoice.HOST)
            env.coredata.compilers.host = {'c': compiler}
            env.coredata.options[OptionKey('link_args', lang='c')] = FakeCompilerOptions()
            p1 = Path(tmpdir) / '1'
            p2 = Path(tmpdir) / '2'
            p1.mkdir()
            p2.mkdir()
            # libfoo.a is in one prefix
            create_static_lib(p1 / 'libfoo.a')
            # libbar.a is in both prefixes
            create_static_lib(p1 / 'libbar.a')
            create_static_lib(p2 / 'libbar.a')
            # Ensure that we never statically link to these
            create_static_lib(p1 / 'libpthread.a')
            create_static_lib(p1 / 'libm.a')
            create_static_lib(p1 / 'libc.a')
            create_static_lib(p1 / 'libdl.a')
            create_static_lib(p1 / 'librt.a')

            class FakeInstance(PkgConfigCLI):
                def _call_pkgbin(self, args, env=None):
                    if '--libs' not in args:
                        return 0, '', ''
                    if args[-1] == 'foo':
                        return 0, f'-L{p2.as_posix()} -lfoo -L{p1.as_posix()} -lbar', ''
                    if args[-1] == 'bar':
                        return 0, f'-L{p2.as_posix()} -lbar', ''
                    if args[-1] == 'internal':
                        return 0, f'-L{p1.as_posix()} -lpthread -lm -lc -lrt -ldl', ''

            with mock.patch.object(PkgConfigInterface, 'instance') as instance_method:
                instance_method.return_value = FakeInstance(env, MachineChoice.HOST, silent=True)
                kwargs = {'required': True, 'silent': True}
                foo_dep = PkgConfigDependency('foo', env, kwargs)
                self.assertEqual(foo_dep.get_link_args(),
                                 [(p1 / 'libfoo.a').as_posix(), (p2 / 'libbar.a').as_posix()])
                bar_dep = PkgConfigDependency('bar', env, kwargs)
                self.assertEqual(bar_dep.get_link_args(), [(p2 / 'libbar.a').as_posix()])
                internal_dep = PkgConfigDependency('internal', env, kwargs)
                if compiler.get_argument_syntax() == 'msvc':
                    self.assertEqual(internal_dep.get_link_args(), [])
                else:
                    link_args = internal_dep.get_link_args()
                    for link_arg in link_args:
                        for lib in ('pthread', 'm', 'c', 'dl', 'rt'):
                            self.assertNotIn(f'lib{lib}.a', link_arg, msg=lin
```