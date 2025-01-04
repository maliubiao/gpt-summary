Response:
My thinking process to analyze the Python code and generate the summary goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the provided Python code, specifically focusing on its relationship to reverse engineering, binary/OS internals, logical reasoning, common user errors, and debugging. It also asks how a user might reach this code during debugging.

2. **Initial Scan for Keywords:** I quickly scanned the code for keywords and patterns that relate to the requested areas. I noticed:
    * `unittest`: This is a testing framework, so the primary function is *testing*.
    * `assertEqual`, `assertRaises`: These are test assertions, indicating the code verifies certain conditions.
    * `mesonbuild`: This suggests the code is part of the Meson build system.
    * `compiler`, `linker`, `dependencies`: These relate to the build process and how software components are linked.
    * File operations (`Path`, `tempfile`):  Indicates interaction with the file system.
    * `subprocess`:  Execution of external commands.
    * `stat`: File mode and permission handling.
    * Platform-specific checks (`is_windows`, `is_osx`, etc.):  Suggests the code handles platform differences.
    * The presence of various compiler classes (Clang, GCC, Visual Studio, DMD):  Highlights compiler-specific testing.

3. **Categorize the Tests:** I started grouping the test functions based on the functionality they seem to be testing:
    * **Version Parsing:** `test_version_number`
    * **File Mode Conversion:** `test_mode_symbolic_to_bits`
    * **Compiler Argument Handling:**  `test_compiler_args_class_*` (various compiler types)
    * **String Templating:** `test_string_templates_substitution`
    * **Cross-Compilation:** `test_needs_exe_wrapper_override`
    * **List Manipulation:** `test_listify`, `test_extract_as_list`
    * **Library Naming Conventions:** `test_find_library_patterns`
    * **Pkg-config Integration:** `test_pkgconfig_parse_libs`

4. **Analyze Functionality and Relationships:**  For each category, I analyzed its purpose and its connection to the prompt's requirements:

    * **Testing Framework (Central Function):**  The core purpose is to test the internal workings of the Frida dynamic instrumentation tool (or rather, the Meson build system components it uses).

    * **Reverse Engineering:**  While not directly *performing* reverse engineering, the code tests components used in the build process of tools like Frida. Understanding build systems is crucial for reverse engineers to rebuild, modify, and analyze such tools. The compiler and linker tests are relevant here as these are core to creating the final binary that a reverse engineer analyzes.

    * **Binary/OS Internals:**  The file mode tests, library naming tests (especially platform-specific ones like `.so`, `.dylib`, `.dll`), and cross-compilation tests directly relate to how binaries are structured and handled on different operating systems. The compiler argument tests touch upon low-level compiler flags.

    * **Logical Reasoning:** The tests themselves embody logical reasoning. They set up specific conditions (inputs) and assert expected outcomes (outputs). For example, in the compiler argument tests, the logic of adding, removing, and deduplicating arguments is being tested.

    * **Common User Errors:**  The tests implicitly reveal potential user errors. For instance, incorrect cross-compilation configurations, wrong library paths, or misunderstanding how compiler arguments work could lead to failures that these tests aim to prevent.

    * **Debugging:**  This code *is* for internal testing/debugging of the Frida build system. A developer working on Frida or Meson might run these tests to find bugs. A user might encounter this code in debugging traces or when trying to understand the build process after a failure.

5. **Provide Examples:**  For each relevant category, I brainstormed concrete examples to illustrate the connection:

    * **Reverse Engineering:**  Modifying compiler flags to generate debug symbols or disable optimizations.
    * **Binary/OS Internals:**  The difference between `.so` and `.dylib`, the role of linkers, cross-compilation for Android.
    * **Logical Reasoning:**  Specific input/output scenarios for compiler arguments.
    * **User Errors:**  Incorrect cross-file paths, missing dependencies.

6. **Trace User Steps (Debugging Context):** I considered how a user might end up looking at this specific test file. The most likely scenario is a build failure, leading the user to examine the build system's internal tests for clues.

7. **Structure and Summarize:** Finally, I organized the information into clear sections, as requested in the prompt. I started with a general functional summary and then elaborated on each of the specified areas. I made sure to explicitly state the main function of the code (testing) and then connect the individual tests to the broader context of Frida and its build process. I also made sure to address the "Part 1" constraint and explicitly state that the summary is for the first part.

**Self-Correction/Refinement:**

* **Initial thought:**  Focus heavily on Frida's direct functionalities.
* **Correction:** Realized the code is part of Meson's *testing* framework and primarily tests build system components, not Frida's runtime behavior directly. The connection to Frida is through its build process.
* **Initial thought:**  Provide very technical details about each test.
* **Correction:**  Summarized the *purpose* of each test category and provided relevant examples instead of in-depth technical explanations of the test code itself.
* **Ensured Alignment with "Part 1":**  Double-checked that the summary focused on the overall function and avoided going into excessive detail about individual tests, as subsequent parts might delve deeper.
这是文件 `frida/subprojects/frida-gum/releng/meson/unittests/internaltests.py` 的源代码，它属于 Frida 动态 instrumentation 工具的 Meson 构建系统中用于进行内部单元测试的一部分。这个文件的主要功能是**测试 Meson 构建系统内部的一些核心功能和工具函数的正确性**，这些功能和工具函数被 Frida 项目所使用。

以下是该文件功能的详细归纳：

**主要功能：测试 Meson 构建系统的内部功能**

这个文件包含了多个以 `test_` 开头的函数，每个函数都针对 Meson 构建系统的特定内部功能进行测试。这些测试涵盖了以下几个方面：

1. **版本号解析 (`test_version_number`)**: 测试 `mesonbuild.mesonlib.search_version` 函数能否正确地从各种格式的字符串中提取版本号。

2. **文件模式转换 (`test_mode_symbolic_to_bits`)**: 测试 `mesonbuild.mesonlib.FileMode.perms_s_to_bits` 函数能否将符号表示的文件权限转换为数字表示的权限位。

3. **编译器参数处理 (`test_compiler_args_class_*`)**:  测试 `mesonbuild.compilers.CompilerArgs` 类及其子类（如 `ClangCCompiler`, `DmdDCompiler`, `VisualStudioCPPCompiler`, `GnuCCompiler`）如何处理和组织编译器参数，包括去重、添加、删除、排序等。这涉及到不同编译器的特定行为。

4. **字符串模板替换 (`test_string_templates_substitution`)**: 测试 `mesonbuild.mesonlib.get_filenames_templates_dict` 和 `mesonbuild.mesonlib.substitute_values` 函数，用于将输入输出文件名模式替换为实际的文件名。

5. **跨平台编译配置 (`test_needs_exe_wrapper_override`)**:  测试 Meson 如何根据配置文件判断是否需要在跨平台编译时使用可执行文件包装器。

6. **列表处理工具函数 (`test_listify`, `test_extract_as_list`)**: 测试 `mesonbuild.mesonlib.listify` 和 `mesonbuild.mesonlib.extract_as_list` 这两个用于处理列表的工具函数的行为，包括扁平化列表、提取元素等。

7. **库文件查找模式 (`test_find_library_patterns`)**: 测试 Meson 在不同操作系统下查找共享库和静态库时使用的文件名模式。

8. **Pkg-config 集成测试 (`test_pkgconfig_parse_libs`)**: 测试 Meson 如何解析 `pkg-config` 的输出，以获取库文件的链接参数。

**与逆向方法的关系及举例说明：**

虽然这个文件本身不直接进行逆向操作，但它测试的构建系统功能对于逆向工程师理解和操作目标软件的构建过程至关重要。

*   **理解构建过程**: 逆向工程师经常需要理解目标软件是如何编译和链接的，以便更好地分析其结构和功能。这个文件测试了 Meson 如何处理编译器和链接器参数，这有助于逆向工程师理解编译选项的影响，例如是否开启了优化、是否包含了调试信息等。
    *   **举例**:  逆向工程师可能会分析一个二进制文件，发现其链接了某个特定的库。理解 Meson 的库文件查找模式（`test_find_library_patterns`）可以帮助他们找到该库文件的位置和名称。

*   **修改构建系统**:  在某些情况下，逆向工程师可能需要重新构建目标软件的某个部分，以便进行更深入的分析或修改。了解 Meson 的内部工作原理，尤其是编译器和链接器参数的处理（`test_compiler_args_class_*`），可以帮助他们修改构建脚本以达到目的，例如添加自定义的编译选项或链接额外的库。
    *   **举例**:  逆向工程师可能希望在重新编译 Frida Gum 时禁用某些安全特性或添加调试符号。他们需要修改 Meson 构建脚本，并理解 Meson 如何将这些修改传递给编译器。

**涉及二进制底层、Linux、Android内核及框架的知识及举例说明：**

这个文件的一些测试直接或间接地涉及到二进制底层和操作系统相关的知识：

*   **文件权限 (`test_mode_symbolic_to_bits`)**: 文件权限是操作系统底层概念，用于控制对文件的访问。这个测试确保 Meson 能正确处理不同权限的表示形式。
    *   **举例**: 在 Linux 或 Android 上，可执行文件需要设置特定的执行权限。这个测试确保 Meson 在处理文件权限时不会出错。

*   **共享库和静态库的命名约定 (`test_find_library_patterns`)**:  不同操作系统对共享库（如 `.so` 在 Linux 上，`.dylib` 在 macOS 上，`.dll` 在 Windows 上）和静态库（如 `.a` 或 `.lib`）有不同的命名约定。这个测试确保 Meson 能正确地根据平台查找这些库文件。
    *   **举例**: 在 Android 开发中，理解 `.so` 文件的加载和链接机制对于逆向分析 Native 代码至关重要。这个测试验证了 Meson 在处理这些库文件时的正确性。

*   **编译器和链接器参数 (`test_compiler_args_class_*`)**: 这些参数直接影响生成的二进制文件的结构和行为。例如，`-fPIC` 用于生成位置无关代码，这对于共享库是必要的。链接器参数则决定了如何将不同的目标文件和库文件组合成最终的可执行文件或库文件。
    *   **举例**:  逆向工程师可能会分析 Android 系统服务，这些服务通常以 ELF 格式的二进制文件存在。理解编译器和链接器参数可以帮助他们理解这些服务的构建方式和依赖关系。

*   **跨平台编译 (`test_needs_exe_wrapper_override`)**:  跨平台编译涉及到不同操作系统和架构之间的差异，需要特殊的处理，例如使用可执行文件包装器来在宿主机上执行目标平台的工具。
    *   **举例**:  Frida 需要支持在多种平台上运行，包括 Android。这个测试确保 Meson 能正确处理针对 Android 平台的构建过程。

**逻辑推理及假设输入与输出：**

在每个测试函数中都包含了逻辑推理，通过设定特定的输入，然后断言输出是否符合预期。以下是一个简单的例子：

*   **测试函数**: `test_version_number`
*   **假设输入**: 字符串 `"foobar 1.2.3"`
*   **预期输出**: 字符串 `"1.2.3"`
*   **逻辑推理**: `search_version` 函数应该能够识别并提取出字符串中的版本号部分。

另一个例子：

*   **测试函数**: `test_compiler_args_class_clike`
*   **假设输入**:  调用 `ClangCCompiler` 的 `compiler_args` 方法并传入列表 `['-I.', '-I..']`。
*   **预期输出**: 返回的 `CompilerArgs` 对象包含 `['-I.', '-I..']`。
*   **逻辑推理**: 初始化时，编译器参数应该按照传入的顺序保存。

**涉及用户或者编程常见的使用错误及举例说明：**

虽然这些是内部测试，但它们也间接反映了用户在使用 Meson 构建系统或与 Frida 集成时可能遇到的问题：

*   **错误的编译器参数**:  用户可能在 Meson 构建脚本中指定了不正确的编译器参数，导致编译失败或生成不符合预期的二进制文件。`test_compiler_args_class_*` 测试确保 Meson 能正确处理这些参数，减少因参数处理错误导致的问题。
    *   **举例**:  用户可能错误地添加了重复的头文件搜索路径，或者使用了特定编译器不支持的选项。

*   **库文件依赖问题**:  用户可能在链接时遇到找不到库文件的问题。`test_find_library_patterns` 测试确保 Meson 能在不同平台上正确地查找库文件，帮助用户避免这类问题。
    *   **举例**:  用户可能忘记安装某个依赖库，或者库文件的路径没有正确配置。

*   **跨平台编译配置错误**: 用户在进行跨平台编译时，可能没有正确配置交叉编译工具链或相关的配置文件。`test_needs_exe_wrapper_override` 测试涉及到跨平台编译的配置，有助于确保 Meson 能正确处理这种情况。
    *   **举例**:  用户在为 Android 平台构建 Frida 时，可能没有正确配置 Android NDK 的路径。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

一个开发人员或贡献者在开发 Frida 或 Meson 时，可能会因为以下原因查看或修改这个文件：

1. **修改或添加新的 Meson 功能**:  如果他们修改了 Meson 的内部行为，例如更改了编译器参数的处理方式或库文件查找逻辑，他们需要编写或更新相应的单元测试来验证这些修改的正确性。

2. **修复 Bug**:  如果在使用 Frida 构建过程中发现了与 Meson 相关的问题，例如编译器参数传递错误或库文件找不到，他们可能会查看这个文件来理解 Meson 的相关代码，并编写新的测试用例来重现和修复这个 bug。

3. **代码审查**:  作为代码审查过程的一部分，其他开发者可能会审查这个文件，以确保测试覆盖率足够，测试逻辑正确。

**用户操作步骤到达这里的示例（作为调试线索）：**

假设用户在构建 Frida 时遇到了一个链接错误，提示找不到某个库文件。作为调试线索，用户可能会：

1. **查看构建日志**:  构建日志会显示 Meson 执行的命令，包括编译器和链接器的调用。
2. **分析链接器命令**:  用户可能会注意到链接器命令中缺少了某个库文件的路径，或者使用了错误的库文件名。
3. **检查 Meson 构建脚本**:  用户会查看 `meson.build` 文件，确认是否正确声明了依赖项。
4. **深入 Meson 内部**:  如果问题仍然存在，用户可能会怀疑是 Meson 的库文件查找机制出现了问题，从而查阅 `frida/subprojects/frida-gum/releng/meson/unittests/internaltests.py` 文件中的 `test_find_library_patterns` 测试，以了解 Meson 是如何查找库文件的，并尝试理解问题可能出在哪里。

**总结：该文件的功能是测试 Frida 构建系统所依赖的 Meson 构建系统的内部核心功能和工具函数的正确性。** 这些测试覆盖了版本号解析、文件模式转换、编译器参数处理、字符串模板替换、跨平台编译配置、列表处理工具函数以及库文件查找模式等多个方面，确保了构建过程的稳定性和可靠性。虽然这个文件不是直接进行逆向操作，但它测试的构建系统功能对于逆向工程师理解目标软件的构建过程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/internaltests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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