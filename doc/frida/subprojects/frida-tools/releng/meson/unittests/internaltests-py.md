Response:
The user wants a summary of the Python code provided. I need to identify the main functionalities implemented in this file. Based on the imports and the class `InternalTests`, it seems like this file contains unit tests for various internal components of the `meson` build system.

Here's a breakdown of the observed functionalities:

1. **Version Number Parsing:** Testing the `search_version` function for extracting version numbers from strings.
2. **File Mode Conversion:** Testing the `perms_s_to_bits` function for converting symbolic file permissions to bitwise representation.
3. **Compiler Argument Handling:** Testing the `CompilerArgs` class for managing compiler arguments, including deduplication and ordering. This involves specific tests for Clang, DMD, and Visual Studio compilers, as well as linkers like GNU ld.
4. **String Template Substitution:** Testing the functionality of substituting placeholders in strings with actual values based on input and output file names.
5. **Cross-Compilation Configuration:** Testing the ability to override the `needs_exe_wrapper` setting in cross-compilation configurations.
6. **List Manipulation:** Testing utility functions for converting values to lists and flattening nested lists (`listify`, `extract_as_list`).
7. **Library Naming Conventions:** Testing the logic for determining library file name patterns based on the operating system.
8. **Finding Libraries:** Testing the `_find_library_real` method, including a specific test case for OpenBSD library versioning.
9. **Pkg-config Integration:** Testing the parsing of `pkg-config` output to extract library linking arguments.

Now, I will formulate the summary based on these observations.
这是 `frida/subprojects/frida-tools/releng/meson/unittests/internaltests.py` 文件的前一部分，它是一个 Frida 动态插桩工具的源代码文件，主要功能是 **对 Meson 构建系统内部功能的进行单元测试**。

以下是根据代码内容归纳的功能点：

1. **版本号解析测试 (Version Number Parsing Test):**
    *   测试 `mesonbuild.mesonlib.search_version` 函数，该函数用于从字符串中提取版本号。
    *   **与逆向方法的关系：** 在逆向工程中，经常需要分析二进制文件或库的版本信息，以确定其功能或是否存在已知漏洞。此测试确保了 Meson 构建系统能够正确解析版本号，这对于依赖特定版本库的 Frida 工具构建至关重要。例如，如果 Frida 依赖特定版本的 V8 JavaScript 引擎，Meson 需要能够正确解析 V8 的版本号来决定如何链接。
    *   **二进制底层知识：** 版本号信息通常存储在二进制文件的特定位置或元数据中。
    *   **逻辑推理：**
        *   **假设输入：** 各种包含版本号的字符串，例如 "foobar 1.2.3", "2016.10.128", 或更复杂的包含其他信息的字符串。
        *   **预期输出：** 从输入字符串中提取出的版本号字符串，例如 "1.2.3", "2016.10.128"。
    *   **用户或编程常见错误：** 版本号格式不一致可能导致解析失败。 例如，如果用户提供的版本号格式与预期不符，`search_version` 可能会返回错误的结果或 "unknown version"。

2. **文件模式转换测试 (File Mode Conversion Test):**
    *   测试 `mesonbuild.mesonlib.FileMode.perms_s_to_bits` 函数，该函数将符号表示的文件权限转换为位表示。
    *   **与逆向方法的关系：** 在分析文件系统或进程权限时，理解文件模式至关重要。此测试确保 Meson 能正确处理文件权限，这可能在 Frida 工具部署或与目标进程交互时相关。例如，Frida 可能需要设置特定文件的执行权限。
    *   **Linux 内核知识：** 文件权限是 Linux 内核管理的重要组成部分，涉及到用户、组以及其他用户的读、写、执行权限，以及 SUID、SGID、SVTX 等特殊权限位。
    *   **逻辑推理：**
        *   **假设输入：** 代表文件权限的符号字符串，例如 "rwx------", "---rwxr--"。
        *   **预期输出：** 对应的位表示的整数，可以使用 `stat` 模块中的常量进行比较，例如 `stat.S_IRWXU`, `stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP`。

3. **编译器参数处理测试 (Compiler Arguments Handling Test):**
    *   测试 `mesonbuild.compilers.c.ClangCCompiler`, `mesonbuild.compilers.cpp.VisualStudioCPPCompiler`, `mesonbuild.compilers.d.DmdDCompiler` 等编译器类的 `compiler_args` 方法，以及 `mesonbuild.linkers.linkers` 中链接器类的相关功能。这些测试覆盖了编译器参数的添加、去重、排序等操作。
    *   **与逆向方法的关系：**  在编译和链接 Frida 自身或其扩展时，需要精确控制编译器和链接器的参数，例如指定头文件搜索路径 (`-I`)、库文件搜索路径 (`-L`)、需要链接的库 (`-l`) 等。错误的参数可能导致编译失败或生成的 Frida 工具无法正常工作。
    *   **二进制底层知识：** 编译器和链接器是生成二进制代码的核心工具，理解它们的参数对于理解二进制文件的生成过程至关重要。
    *   **Linux, Windows 平台知识：**  不同的操作系统和编译器使用不同的命令行参数格式和约定。例如，Visual Studio 使用 `/` 前缀，而 GCC/Clang 使用 `-` 前缀。链接库的方式也可能不同，例如 Windows 使用 `.lib` 文件，Linux 使用 `.so` 或 `.a` 文件。
    *   **逻辑推理：**
        *   **假设输入：** 一个编译器参数列表，以及要添加或操作的参数。
        *   **预期输出：**  经过添加、去重、排序等操作后的新的编译器参数列表。 例如，添加重复的 `-I.` 参数后，列表应该只保留一个。
    *   **用户或编程常见错误：**  手动编写构建脚本时，容易出现编译器参数的拼写错误、顺序错误或遗漏必要的参数。

4. **字符串模板替换测试 (String Templates Substitution Test):**
    *   测试 `mesonbuild.mesonlib.get_filenames_templates_dict` 和 `mesonbuild.mesonlib.substitute_values` 函数，这些函数用于创建文件名模板字典，并根据该字典替换字符串中的占位符。
    *   **与逆向方法的关系：** 在 Frida 工具的构建过程中，可能需要根据输入文件的名称生成输出文件的名称，或者在执行命令时动态替换路径等信息。例如，根据 `foo.c.in` 生成 `foo.c`。
    *   **逻辑推理：**
        *   **假设输入：** 输入文件名列表、输出文件名列表以及包含占位符的命令字符串列表。
        *   **预期输出：**  根据输入输出文件名生成的模板字典，以及替换占位符后的命令字符串列表。 例如，如果输入是 `['bar/foo.c.in']`，输出是 `['out.c']`，那么 `"@INPUT@.out"` 应该被替换为 `bar/foo.c.in.out`，`"@OUTPUT@"` 应该被替换为 `out.c`。
    *   **用户或编程常见错误：**  占位符使用错误或输入输出文件数量不匹配会导致替换失败。

5. **跨平台编译 `needs_exe_wrapper` 配置测试 (Cross-Compilation `needs_exe_wrapper` Override Test):**
    *   测试在跨平台编译配置中覆盖 `needs_exe_wrapper` 属性的能力。该属性指示是否需要为目标平台的可执行文件添加包装器。
    *   **与逆向方法的关系：**  当为不同的架构或操作系统构建 Frida 工具时，可能需要在主机上运行目标平台的可执行文件。`needs_exe_wrapper` 的设置会影响到 Frida 构建系统如何处理这种情况。
    *   **逻辑推理：**
        *   **假设输入：** 一个包含跨平台编译配置信息的配置文件。
        *   **预期输出：**  `env.need_exe_wrapper()` 方法返回的值与配置文件中 `needs_exe_wrapper` 的设置一致。

**总结：**

这个代码片段主要测试了 Meson 构建系统在处理版本号、文件权限、编译器和链接器参数以及字符串模板替换等方面的内部逻辑。这些功能是 Frida 工具能够成功构建和部署到不同目标平台的基础。这些测试覆盖了底层操作系统、编译器和链接器的行为，并考虑了用户可能遇到的常见错误情况。它确保了 Meson 在 Frida 构建过程中能够正确地处理各种配置和参数，从而生成可靠的 Frida 工具。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
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
"""


```