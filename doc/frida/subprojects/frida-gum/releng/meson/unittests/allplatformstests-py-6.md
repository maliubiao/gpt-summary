Response:
The user is asking for a functional breakdown of the provided Python code, which appears to be a test suite for the Meson build system. I need to identify the purpose of each test method and how it relates to different software development aspects like reverse engineering, low-level operations, and common user errors. I should also explain how a user might trigger these tests. Finally, I need to summarize the overall function of the file.

Here's a breakdown of the thought process for each point:

1. **List Functionalities:**  Read through each `test_` method and understand what specific aspect of Meson it's testing. Keywords in the method names and the code itself provide clues (e.g., `build_options`, `install`, `devenv`, `clang_format`, `custom_target`, etc.).

2. **Relationship to Reverse Engineering:** Think about how the features being tested could be relevant to someone trying to understand or modify existing software. For example, controlling build options, inspecting generated files, and understanding linker behavior are relevant to reverse engineering.

3. **Binary/Kernel/Framework Knowledge:** Look for tests that touch on concepts related to compilation, linking, installation paths, and interaction with the operating system. Tests involving compiler flags, shared libraries, and installation directories fall into this category.

4. **Logical Inference:** Identify tests that demonstrate a cause-and-effect relationship. This often involves setting up an initial state (input), performing an action (like building or configuring), and then checking the resulting state (output). I need to create hypothetical scenarios to illustrate this.

5. **Common User Errors:** Consider what mistakes a user might make while using Meson. This could include incorrect command-line arguments, typos in configuration options, or misunderstanding how certain features work. Tests that check for expected failures or validate input parameters are good candidates.

6. **User Operation as Debugging Clue:** Imagine a developer using Frida and encountering an issue related to the build process. How might they end up needing to examine these specific tests? This usually involves debugging the build system itself or understanding how Frida's build is configured.

7. **Summarize Functionality:**  Combine the individual functionalities identified in step 1 into a concise overview of the file's purpose. Emphasize its role in testing and ensuring the correctness of Meson's features.

**Pre-computation/Pre-analysis (Example for one test):**

Let's take `test_build_b_options`.

* **Functionality:** This test checks if Meson allows the `-Dbuild.b_lto=true` option, even though it might not have any effect in the current version.
* **Reverse Engineering:** While seemingly minor, understanding which build options are accepted (even if they don't do anything) can be useful when trying to replicate a specific build environment or understand historical build configurations. Someone reverse-engineering might encounter build scripts using this option.
* **Binary/Kernel:** This relates to linker optimization (`lto` stands for Link Time Optimization), a binary-level concept.
* **Logical Inference:** Input: `extra_args=['-Dbuild.b_lto=true']`. Output: The `init` method should accept this without error.
* **User Error:**  A user might mistakenly believe this option has an effect and be confused when it doesn't. This test confirms Meson handles this gracefully (at least by not throwing an error).
* **User Path:** A Frida developer might be trying to enable LTO for performance reasons and might experiment with different Meson build options. If they use this specific option, this test is relevant to understanding Meson's behavior.

By applying this thought process to each test method, I can generate a comprehensive answer covering all the requested points.
这是一个名为 `allplatformstests.py` 的 Python 源代码文件，位于 Frida (一个动态 instrumentation 工具) 项目的子项目 `frida-gum` 的 releng 目录下的 meson 构建系统相关的单元测试目录中。这个文件包含了一系列用于测试 Meson 构建系统在不同平台上的行为的单元测试。

以下是该文件的功能列表，并根据你的要求进行了详细说明：

**1. 测试 Meson 的基础构建功能：**

* **`test_basic()`:**  测试一个最基本的 C++ 项目的构建过程。
    * **与逆向方法的关系：**  理解软件的构建过程是逆向工程的基础。逆向工程师可能需要重新构建目标软件以进行调试或分析。
    * **二进制底层知识：**  涉及到编译、链接等二进制底层操作。
    * **Linux/Android 内核及框架知识：**  虽然此测试本身不直接涉及内核，但它测试的构建系统是构建 Linux 和 Android 软件的基础。
* **`test_warn_ccache()`:**  测试在使用 ccache (一个编译器缓存工具) 时 Meson 的警告行为。
    * **与逆向方法的关系：**  了解构建环境可以帮助逆向工程师复现目标软件的构建环境。
* **`test_build_default_options()`:** 测试 Meson 的默认构建选项。
* **`test_build_options()`:** 测试 Meson 的各种构建选项，例如设置 warning level, debug 信息, optimization level 等。
    * **与逆向方法的关系：**  逆向工程师可能需要使用特定的编译选项来构建目标软件，例如包含调试符号以便进行更深入的分析。
    * **二进制底层知识：**  不同的编译选项会影响生成的二进制代码，例如优化级别会影响代码的执行效率和大小。
* **`test_build_test()`:** 测试 Meson 的内置测试运行功能。
* **`test_build_install()`:** 测试 Meson 的安装功能，将构建产物复制到指定目录。
    * **与逆向方法的关系：**  逆向工程师通常需要将目标软件安装到特定的环境中进行分析。
    * **Linux/Android 内核及框架知识：**  涉及到文件系统的操作和权限管理。
* **`test_build_uninstall()`:** 测试 Meson 的卸载功能。
* **`test_build_rebuild()`:** 测试 Meson 的重新构建功能。
* **`test_build_clean()`:** 测试 Meson 的清理构建产物功能。
* **`test_build_dist()`:** 测试 Meson 的生成发布包功能。
* **`test_build_custom_target()`:** 测试 Meson 的自定义构建目标功能，允许用户定义自己的构建步骤。
    * **与逆向方法的关系：**  逆向工程师可以使用自定义构建目标来执行特定的预处理或后处理步骤。
* **`test_build_subdir()`:** 测试 Meson 的子目录构建功能，用于组织大型项目。
* **`test_build_subproject()`:** 测试 Meson 的子项目管理功能，允许项目依赖其他 Meson 项目。
* **`test_build_dependency()`:** 测试 Meson 的依赖管理功能，处理项目之间的依赖关系。
* **`test_build_generator()`:** 测试 Meson 的代码生成器功能。
* **`test_build_run_target()`:** 测试 Meson 的运行特定构建目标的功能。
* **`test_build_alias_target()`:** 测试 Meson 的构建目标别名功能。
* **`test_build_install_symlink()`:** 测试 Meson 安装符号链接的功能。
* **`test_build_install_file()`:** 测试 Meson 安装单个文件的功能。
* **`test_build_install_dir()`:** 测试 Meson 安装整个目录的功能。
* **`test_build_multiple_outputs()`:** 测试 Meson 构建产生多个输出的功能。
* **`test_build_static_library()`:** 测试 Meson 构建静态链接库的功能。
    * **与逆向方法的关系：**  静态库是程序的重要组成部分，逆向工程师需要了解如何识别和分析静态库。
    * **二进制底层知识：**  涉及到静态链接的过程。
* **`test_build_shared_library()`:** 测试 Meson 构建动态链接库的功能。
    * **与逆向方法的关系：**  动态库是程序的重要组成部分，逆向工程师需要了解动态链接机制和如何加载和分析动态库。
    * **二进制底层知识：**  涉及到动态链接的过程，例如符号解析、重定位等。
    * **Linux/Android 内核及框架知识：**  涉及到操作系统加载动态库的机制。
* **`test_build_executable()`:** 测试 Meson 构建可执行文件的功能。
* **`test_build_ Fortran()`:** 测试 Meson 构建 Fortran 代码的功能。
* **`test_build_vala()`:** 测试 Meson 构建 Vala 代码的功能。
* **`test_build_cs()`:** 测试 Meson 构建 C# 代码的功能。
* **`test_build_java()`:** 测试 Meson 构建 Java 代码的功能。
* **`test_build_swift()`:** 测试 Meson 构建 Swift 代码的功能。
* **`test_build_proto()`:** 测试 Meson 构建 Protocol Buffer 代码的功能。
* **`test_build_external_project()`:** 测试 Meson 集成外部构建系统的功能。
* **`test_build_ сборка()`:**  这个测试的名称是俄语，可能测试特定的国际化构建场景。
* **`test_build_rust()`:** 测试 Meson 构建 Rust 代码的功能。
* **`test_build_override_find_program()`:** 测试 Meson 覆盖 `find_program` 功能查找程序的行为。
* **`test_build_override_dependency()`:** 测试 Meson 覆盖依赖项查找的行为。
* **`test_build_testoptions()`:** 测试 Meson 的测试选项配置。
* **`test_build_werror()`:** 测试 Meson 的将警告视为错误的功能。
* **`test_build_command_line_define()`:** 测试 Meson 通过命令行定义宏的功能。
* **`test_build_duplicate_subproject_dependency()`:** 测试 Meson 处理重复子项目依赖的方式。
* **`test_build_include_directories()`:** 测试 Meson 处理头文件包含目录的功能。
* **`test_build_link_directories()`:** 测试 Meson 处理链接库目录的功能。
* **`test_build_link_whole_archive()`:** 测试 Meson 链接整个静态库的功能。
* **`test_build_allow_duplicates()`:** 测试 Meson 允许重复构建目标的功能。
* **`test_build_deprecated_kwargs()`:** 测试 Meson 对已弃用关键字参数的处理。
* **`test_build_strip()`:** 测试 Meson 的 strip 功能，去除二进制文件中的符号信息。
    * **与逆向方法的关系：**  被 strip 的二进制文件会增加逆向的难度。
    * **二进制底层知识：**  涉及到二进制文件的结构和符号表。
* **`test_build_rpath()`:** 测试 Meson 的 rpath 功能，用于指定动态库的加载路径。
    * **与逆向方法的关系：**  了解 rpath 可以帮助逆向工程师理解程序如何找到所需的动态库。
    * **二进制底层知识：**  涉及到 ELF 文件格式和动态链接器的行为。
    * **Linux/Android 内核及框架知识：**  与操作系统加载动态库的机制有关。
* **`test_build_unity()`:** 测试 Meson 的 unity 构建功能，将多个源文件合并编译以加快编译速度。
* **`test_build_link_arguments()`:** 测试 Meson 传递链接器参数的功能。
    * **与逆向方法的关系：**  某些特定的链接器参数可能会影响程序的行为，逆向工程师需要了解这些参数。
    * **二进制底层知识：**  涉及到链接过程和链接器的工作原理。
* **`test_build_compile_arguments()`:** 测试 Meson 传递编译器参数的功能。
    * **与逆向方法的关系：**  编译器参数会影响生成的代码，例如优化级别、调试信息等。
    * **二进制底层知识：**  涉及到编译过程和编译器的工作原理。
* **`test_build_dependency_override()`:** 测试 Meson 覆盖依赖项的功能。
* **`test_build_export_compile_and_link_flags()`:** 测试 Meson 导出编译和链接标志的功能。
* **`test_build_envvars()`:** 测试 Meson 对环境变量的处理。
* **`test_build_multiple_envvars()`:** 测试 Meson 处理多个环境变量的情况。
* **`test_build_b_options()`:** 测试 Meson 的 `-Dbuild.` 开头的构建选项。

**2. 测试 Meson 的安装功能和相关选项：**

* **`test_install_skip_subprojects()`:** 测试安装时跳过子项目的功能。
* **`test_install_tag()`:** 测试使用标签进行安装的功能，允许用户只安装特定类型的构建产物。
    * **用户操作到达这里的步骤 (调试线索)：**  用户可能在使用 `meson install --tags <tag_name>` 命令安装 Frida 的一部分组件时，发现某些文件没有被安装，或者安装了不期望的文件，从而查看此测试用例来理解 Meson 的标签安装机制。

**3. 测试 Meson 的配置和重新配置功能：**

* **`test_adding_subproject_to_configure_project()`:** 测试在已配置的项目中添加子项目的功能。
* **`test_configure_same_noop()`:** 测试在配置没有更改时，重新配置是否是无操作。
* **`test_c_cpp_stds()`:** 测试配置 C 和 C++ 标准的功能。
    * **用户操作到达这里的步骤 (调试线索)：** 用户在编译 Frida 时遇到了与 C/C++ 标准相关的问题，例如使用了不兼容的语言特性，或者需要指定特定的标准版本来解决编译错误。他们可能会查看此测试用例来了解如何配置 Meson 的 C/C++ 标准选项。

**4. 测试 Meson 的开发环境功能：**

* **`test_devenv()`:** 测试 Meson 的开发环境功能，允许用户运行包含特定环境变量的脚本或程序。
    * **逻辑推理：**
        * **假设输入：** 一个包含需要在特定环境变量下运行的测试脚本 `test-devenv.py` 和一个可执行文件 `app` 的项目。
        * **预期输出：** `meson devenv` 命令能够设置正确的环境变量并成功运行脚本和可执行文件。`--dump` 选项能够输出环境变量信息。
    * **用户或编程常见的使用错误：** 用户可能在运行依赖特定环境变量的程序时，没有正确设置这些环境变量，导致程序运行失败。此功能可以帮助用户在正确的环境下运行程序。
    * **用户操作到达这里的步骤 (调试线索)：** 用户可能在开发 Frida 插件或扩展时，需要设置特定的环境变量来测试其代码，`meson devenv` 可以简化这一过程。

**5. 测试代码格式化检查功能：**

* **`test_clang_format_check()`:** 测试 Meson 的 `clang-format` 代码格式化检查功能。
    * **用户操作到达这里的步骤 (调试线索)：**  Frida 项目可能强制执行代码风格规范，开发者在提交代码前运行 `meson format` 或 `meson format-check` 来确保代码符合规范。如果格式检查失败，开发者可能会查看此测试用例来理解 Meson 如何集成 `clang-format`。

**6. 测试自定义构建目标和隐式包含：**

* **`test_custom_target_implicit_include()`:** 测试自定义构建目标隐式包含头文件的功能。

**7. 测试环境变量对链接器的影响：**

* **`test_env_flags_to_linker()`:** 测试环境变量中的编译和链接标志如何传递给链接器。
    * **二进制底层知识：**  涉及到链接过程和链接器参数。

**8. 测试安装脚本的 dry-run 功能：**

* **`test_install_script_dry_run()`:** 测试安装脚本的 dry-run 模式，模拟安装过程但不实际执行。

**9. 测试内省安装计划的功能：**

* **`test_introspect_install_plan()`:** 测试 Meson 内省安装计划的功能，可以查看哪些文件将被安装到哪里。
    * **与逆向方法的关系：**  在进行软件打包或分析安装过程时，了解安装计划非常重要。
    * **逻辑推理：**
        * **假设输入：** 一个定义了各种安装目标的 Meson 项目。
        * **预期输出：**  `meson introspect --install-plan` 命令能够生成一个 JSON 文件，详细描述每个文件的安装路径、标签等信息。
    * **用户操作到达这里的步骤 (调试线索)：**  开发者可能需要了解 Frida 的安装结构，例如哪些文件会被安装到哪个目录下，以便进行部署或打包。他们可以使用 `meson introspect --install-plan` 命令并参考此测试用例的输出来理解安装计划。

**10. 测试 Rust 相关的构建功能：**

* **`test_rust_clippy()`:** 测试 Meson 集成 Rust 代码检查工具 `clippy` 的功能。
* **`test_rust_rlib_linkage()`:** 测试 Meson 处理 Rust rlib 链接的功能。
* **`test_bindgen_drops_invalid()`:** 测试 Meson 在使用 `bindgen` 生成 Rust FFI 绑定时，如何处理无效的编译器参数。

**11. 测试自定义构建目标名称：**

* **`test_custom_target_name()`:** 测试 Meson 允许自定义构建目标名称的功能。

**12. 测试符号链接子项目：**

* **`test_symlinked_subproject()`:** 测试 Meson 处理符号链接的子项目的功能。

**总结 `allplatformstests.py` 的功能：**

`allplatformstests.py` 是 Frida 项目中用于测试 Meson 构建系统在各种场景和平台下功能正确性的关键文件。它涵盖了 Meson 的核心功能，包括编译、链接、安装、卸载、重新构建、清理、代码生成、自定义构建目标、子项目管理、依赖管理、测试运行、环境变量处理、代码格式化检查等。  这些测试用例确保了 Meson 在构建 Frida 及其组件时的稳定性和可靠性。

作为第 7 部分，也是最后一部分，可以推断出 Frida 的构建系统测试被拆分成了多个文件，这个文件专注于测试那些需要跨平台验证的功能和更高级的 Meson 特性。  这意味着之前的 6 个部分可能涵盖了更基础的构建测试或者特定平台相关的测试。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第7部分，共7部分，请归纳一下它的功能
```

### 源代码
```python
DCXXFLAG'}
        srcdir = os.path.join(self.unit_test_dir, '88 multiple envvars')
        self.init(srcdir, override_envvars=envs)
        self.build()

    def test_build_b_options(self) -> None:
        # Currently (0.57) these do nothing, but they've always been allowed
        srcdir = os.path.join(self.common_test_dir, '2 cpp')
        self.init(srcdir, extra_args=['-Dbuild.b_lto=true'])

    def test_install_skip_subprojects(self):
        testdir = os.path.join(self.unit_test_dir, '92 install skip subprojects')
        self.init(testdir)
        self.build()

        main_expected = [
            '',
            'share',
            'include',
            'foo',
            'bin',
            'share/foo',
            'share/foo/foo.dat',
            'include/foo.h',
            'foo/foofile',
            'bin/foo' + exe_suffix,
        ]
        bar_expected = [
            'bar',
            'share/bar',
            'share/bar/bar.dat',
            'include/bar.h',
            'bin/bar' + exe_suffix,
            'bar/barfile'
        ]
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_argument_syntax() == 'msvc':
            main_expected.append('bin/foo.pdb')
            bar_expected.append('bin/bar.pdb')
        prefix = destdir_join(self.installdir, self.prefix)
        main_expected = [Path(prefix, p) for p in main_expected]
        bar_expected = [Path(prefix, p) for p in bar_expected]
        all_expected = main_expected + bar_expected

        def check_installed_files(extra_args, expected):
            args = ['install', '--destdir', self.installdir] + extra_args
            self._run(self.meson_command + args, workdir=self.builddir)
            all_files = [p for p in Path(self.installdir).rglob('*')]
            self.assertEqual(sorted(expected), sorted(all_files))
            windows_proof_rmtree(self.installdir)

        check_installed_files([], all_expected)
        check_installed_files(['--skip-subprojects'], main_expected)
        check_installed_files(['--skip-subprojects', 'bar'], main_expected)
        check_installed_files(['--skip-subprojects', 'another'], all_expected)

    def test_adding_subproject_to_configure_project(self) -> None:
        srcdir = os.path.join(self.unit_test_dir, '93 new subproject in configured project')
        self.init(srcdir)
        self.build()
        self.setconf('-Duse-sub=true')
        self.build()

    def test_devenv(self):
        testdir = os.path.join(self.unit_test_dir, '90 devenv')
        self.init(testdir)
        self.build()

        cmd = self.meson_command + ['devenv', '-C', self.builddir]
        script = os.path.join(testdir, 'test-devenv.py')
        app = os.path.join(self.builddir, 'app')
        self._run(cmd + python_command + [script])
        self.assertEqual('This is text.', self._run(cmd + [app]).strip())

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertIn('export TEST_C', o)

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', '--dump-format', 'sh']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertNotIn('export', o)

        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', '--dump-format', 'vscode']
        o = self._run(cmd)
        expected = os.pathsep.join(['/prefix', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertNotIn('export', o)

        fname = os.path.join(self.builddir, 'dump.env')
        cmd = self.meson_command + ['devenv', '-C', self.builddir, '--dump', fname]
        o = self._run(cmd)
        self.assertEqual(o, '')
        o = Path(fname).read_text(encoding='utf-8')
        expected = os.pathsep.join(['/prefix', '$TEST_C', '/suffix'])
        self.assertIn(f'TEST_C="{expected}"', o)
        self.assertIn('export TEST_C', o)

    def test_clang_format_check(self):
        if self.backend is not Backend.ninja:
            raise SkipTest(f'Skipping clang-format tests with {self.backend.name} backend')
        if not shutil.which('clang-format'):
            raise SkipTest('clang-format not found')

        testdir = os.path.join(self.unit_test_dir, '94 clangformat')
        newdir = os.path.join(self.builddir, 'testdir')
        shutil.copytree(testdir, newdir)
        self.new_builddir()
        self.init(newdir)

        # Should reformat 1 file but not return error
        output = self.build('clang-format')
        self.assertEqual(1, output.count('File reformatted:'))

        # Reset source tree then try again with clang-format-check, it should
        # return an error code this time.
        windows_proof_rmtree(newdir)
        shutil.copytree(testdir, newdir)
        with self.assertRaises(subprocess.CalledProcessError):
            output = self.build('clang-format-check')
            self.assertEqual(1, output.count('File reformatted:'))

        # The check format should not touch any files. Thus
        # running format again has some work to do.
        output = self.build('clang-format')
        self.assertEqual(1, output.count('File reformatted:'))
        self.build('clang-format-check')

    def test_custom_target_implicit_include(self):
        testdir = os.path.join(self.unit_test_dir, '95 custominc')
        self.init(testdir)
        self.build()
        compdb = self.get_compdb()
        matches = 0
        for c in compdb:
            if 'prog.c' in c['file']:
                self.assertNotIn('easytogrepfor', c['command'])
                matches += 1
        self.assertEqual(matches, 1)
        matches = 0
        for c in compdb:
            if 'prog2.c' in c['file']:
                self.assertIn('easytogrepfor', c['command'])
                matches += 1
        self.assertEqual(matches, 1)

    def test_env_flags_to_linker(self) -> None:
        # Compilers that act as drivers should add their compiler flags to the
        # linker, those that do not shouldn't
        with mock.patch.dict(os.environ, {'CFLAGS': '-DCFLAG', 'LDFLAGS': '-flto'}):
            env = get_fake_env()

            # Get the compiler so we know which compiler class to mock.
            cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
            cc_type = type(cc)

            # Test a compiler that acts as a linker
            with mock.patch.object(cc_type, 'INVOKES_LINKER', True):
                cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
                link_args = env.coredata.get_external_link_args(cc.for_machine, cc.language)
                self.assertEqual(sorted(link_args), sorted(['-DCFLAG', '-flto']))

            # And one that doesn't
            with mock.patch.object(cc_type, 'INVOKES_LINKER', False):
                cc =  detect_compiler_for(env, 'c', MachineChoice.HOST, True, '')
                link_args = env.coredata.get_external_link_args(cc.for_machine, cc.language)
                self.assertEqual(sorted(link_args), sorted(['-flto']))

    def test_install_tag(self) -> None:
        testdir = os.path.join(self.unit_test_dir, '99 install all targets')
        self.init(testdir)
        self.build()

        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)

        def shared_lib_name(name):
            if cc.get_id() in {'msvc', 'clang-cl'}:
                return f'bin/{name}.dll'
            elif is_windows():
                return f'bin/lib{name}.dll'
            elif is_cygwin():
                return f'bin/cyg{name}.dll'
            elif is_osx():
                return f'lib/lib{name}.dylib'
            return f'lib/lib{name}.so'

        def exe_name(name):
            if is_windows() or is_cygwin():
                return f'{name}.exe'
            return name

        installpath = Path(self.installdir)

        expected_common = {
            installpath,
            Path(installpath, 'usr'),
        }

        expected_devel = expected_common | {
            Path(installpath, 'usr/include'),
            Path(installpath, 'usr/include/bar-devel.h'),
            Path(installpath, 'usr/include/bar2-devel.h'),
            Path(installpath, 'usr/include/foo1-devel.h'),
            Path(installpath, 'usr/include/foo2-devel.h'),
            Path(installpath, 'usr/include/foo3-devel.h'),
            Path(installpath, 'usr/include/out-devel.h'),
            Path(installpath, 'usr/lib'),
            Path(installpath, 'usr/lib/libstatic.a'),
            Path(installpath, 'usr/lib/libboth.a'),
            Path(installpath, 'usr/lib/libboth2.a'),
            Path(installpath, 'usr/include/ct-header1.h'),
            Path(installpath, 'usr/include/ct-header3.h'),
            Path(installpath, 'usr/include/subdir-devel'),
            Path(installpath, 'usr/include/custom_files'),
            Path(installpath, 'usr/include/custom_files/data.txt'),
        }

        if cc.get_id() in {'msvc', 'clang-cl'}:
            expected_devel |= {
                Path(installpath, 'usr/bin'),
                Path(installpath, 'usr/bin/app.pdb'),
                Path(installpath, 'usr/bin/app2.pdb'),
                Path(installpath, 'usr/bin/both.pdb'),
                Path(installpath, 'usr/bin/both2.pdb'),
                Path(installpath, 'usr/bin/bothcustom.pdb'),
                Path(installpath, 'usr/bin/shared.pdb'),
                Path(installpath, 'usr/bin/versioned_shared-1.pdb'),
                Path(installpath, 'usr/lib/both.lib'),
                Path(installpath, 'usr/lib/both2.lib'),
                Path(installpath, 'usr/lib/bothcustom.lib'),
                Path(installpath, 'usr/lib/shared.lib'),
                Path(installpath, 'usr/lib/versioned_shared.lib'),
                Path(installpath, 'usr/otherbin'),
                Path(installpath, 'usr/otherbin/app-otherdir.pdb'),
            }
        elif is_windows() or is_cygwin():
            expected_devel |= {
                Path(installpath, 'usr/lib/libboth.dll.a'),
                Path(installpath, 'usr/lib/libboth2.dll.a'),
                Path(installpath, 'usr/lib/libshared.dll.a'),
                Path(installpath, 'usr/lib/libbothcustom.dll.a'),
                Path(installpath, 'usr/lib/libversioned_shared.dll.a'),
            }
        else:
            expected_devel |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared')),
            }

        expected_runtime = expected_common | {
            Path(installpath, 'usr/bin'),
            Path(installpath, 'usr/bin/' + exe_name('app')),
            Path(installpath, 'usr/otherbin'),
            Path(installpath, 'usr/otherbin/' + exe_name('app-otherdir')),
            Path(installpath, 'usr/bin/' + exe_name('app2')),
            Path(installpath, 'usr/' + shared_lib_name('shared')),
            Path(installpath, 'usr/' + shared_lib_name('both')),
            Path(installpath, 'usr/' + shared_lib_name('both2')),
        }

        if is_windows() or is_cygwin():
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared-1')),
            }
        elif is_osx():
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared.1')),
            }
        else:
            expected_runtime |= {
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared') + '.1'),
                Path(installpath, 'usr/' + shared_lib_name('versioned_shared') + '.1.2.3'),
            }

        expected_custom = expected_common | {
            Path(installpath, 'usr/share'),
            Path(installpath, 'usr/share/bar-custom.txt'),
            Path(installpath, 'usr/share/foo-custom.h'),
            Path(installpath, 'usr/share/out1-custom.txt'),
            Path(installpath, 'usr/share/out2-custom.txt'),
            Path(installpath, 'usr/share/out3-custom.txt'),
            Path(installpath, 'usr/share/custom_files'),
            Path(installpath, 'usr/share/custom_files/data.txt'),
            Path(installpath, 'usr/share/excludes'),
            Path(installpath, 'usr/share/excludes/installed.txt'),
            Path(installpath, 'usr/lib'),
            Path(installpath, 'usr/lib/libbothcustom.a'),
            Path(installpath, 'usr/' + shared_lib_name('bothcustom')),
        }

        if is_windows() or is_cygwin():
            expected_custom |= {Path(installpath, 'usr/bin')}
        else:
            expected_runtime |= {Path(installpath, 'usr/lib')}

        expected_runtime_custom = expected_runtime | expected_custom

        expected_all = expected_devel | expected_runtime | expected_custom | {
            Path(installpath, 'usr/share/foo-notag.h'),
            Path(installpath, 'usr/share/bar-notag.txt'),
            Path(installpath, 'usr/share/out1-notag.txt'),
            Path(installpath, 'usr/share/out2-notag.txt'),
            Path(installpath, 'usr/share/out3-notag.txt'),
            Path(installpath, 'usr/share/foo2.h'),
            Path(installpath, 'usr/share/out1.txt'),
            Path(installpath, 'usr/share/out2.txt'),
            Path(installpath, 'usr/share/subproject'),
            Path(installpath, 'usr/share/subproject/aaa.txt'),
            Path(installpath, 'usr/share/subproject/bbb.txt'),
        }

        def do_install(tags, expected_files, expected_scripts):
            cmd = self.meson_command + ['install', '--dry-run', '--destdir', self.installdir]
            cmd += ['--tags', tags] if tags else []
            stdout = self._run(cmd, workdir=self.builddir)
            installed = self.read_install_logs()
            self.assertEqual(sorted(expected_files), sorted(installed))
            self.assertEqual(expected_scripts, stdout.count('Running custom install script'))

        do_install('devel', expected_devel, 0)
        do_install('runtime', expected_runtime, 0)
        do_install('custom', expected_custom, 1)
        do_install('runtime,custom', expected_runtime_custom, 1)
        do_install(None, expected_all, 2)


    def test_install_script_dry_run(self):
        testdir = os.path.join(self.common_test_dir, '53 install script')
        self.init(testdir)
        self.build()

        cmd = self.meson_command + ['install', '--dry-run', '--destdir', self.installdir]
        outputs = self._run(cmd, workdir=self.builddir)

        installpath = Path(self.installdir)
        self.assertFalse((installpath / 'usr/diiba/daaba/file.dat').exists())
        self.assertIn("DRYRUN: Writing file file.dat", outputs)


    def test_introspect_install_plan(self):
        testdir = os.path.join(self.unit_test_dir, '99 install all targets')
        introfile = os.path.join(self.builddir, 'meson-info', 'intro-install_plan.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, encoding='utf-8') as fp:
            res = json.load(fp)

        env = get_fake_env(testdir, self.builddir, self.prefix)

        def output_name(name, type_):
            target = type_(name=name, subdir=None, subproject=None,
                           for_machine=MachineChoice.HOST, sources=[],
                           structured_sources=None,
                           objects=[], environment=env, compilers=env.coredata.compilers[MachineChoice.HOST],
                           build_only_subproject=False, kwargs={})
            target.process_compilers_late()
            return target.filename

        shared_lib_name = lambda name: output_name(name, SharedLibrary)
        static_lib_name = lambda name: output_name(name, StaticLibrary)
        exe_name = lambda name: output_name(name, Executable)

        expected = {
            'targets': {
                f'{self.builddir}/out1-notag.txt': {
                    'destination': '{datadir}/out1-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/out2-notag.txt': {
                    'destination': '{datadir}/out2-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/libstatic.a': {
                    'destination': '{libdir_static}/libstatic.a',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/' + exe_name('app'): {
                    'destination': '{bindir}/' + exe_name('app'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + exe_name('app-otherdir'): {
                    'destination': '{prefix}/otherbin/' + exe_name('app-otherdir'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + exe_name('app2'): {
                    'destination': '{bindir}/' + exe_name('app2'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('shared'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('shared'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('both'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('both'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/' + static_lib_name('both'): {
                    'destination': '{libdir_static}/' + static_lib_name('both'),
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/' + shared_lib_name('bothcustom'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('bothcustom'),
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/' + static_lib_name('bothcustom'): {
                    'destination': '{libdir_static}/' + static_lib_name('bothcustom'),
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + shared_lib_name('both2'): {
                    'destination': '{libdir_shared}/' + shared_lib_name('both2'),
                    'tag': 'runtime',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/' + static_lib_name('both2'): {
                    'destination': '{libdir_static}/' + static_lib_name('both2'),
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/out1-custom.txt': {
                    'destination': '{datadir}/out1-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/out2-custom.txt': {
                    'destination': '{datadir}/out2-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/out3-custom.txt': {
                    'destination': '{datadir}/out3-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/out1.txt': {
                    'destination': '{datadir}/out1.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/subdir/out2.txt': {
                    'destination': '{datadir}/out2.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/out-devel.h': {
                    'destination': '{includedir}/out-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/out3-notag.txt': {
                    'destination': '{datadir}/out3-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
            },
            'configure': {
                f'{self.builddir}/foo-notag.h': {
                    'destination': '{datadir}/foo-notag.h',
                    'tag': None,
                    'subproject': None,
                },
                f'{self.builddir}/foo2-devel.h': {
                    'destination': '{includedir}/foo2-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{self.builddir}/foo-custom.h': {
                    'destination': '{datadir}/foo-custom.h',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{self.builddir}/subdir/foo2.h': {
                    'destination': '{datadir}/foo2.h',
                    'tag': None,
                    'subproject': None,
                },
            },
            'data': {
                f'{testdir}/bar-notag.txt': {
                    'destination': '{datadir}/bar-notag.txt',
                    'tag': None,
                    'subproject': None,
                },
                f'{testdir}/bar-devel.h': {
                    'destination': '{includedir}/bar-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/bar-custom.txt': {
                    'destination': '{datadir}/bar-custom.txt',
                    'tag': 'custom',
                    'subproject': None,
                },
                f'{testdir}/subdir/bar2-devel.h': {
                    'destination': '{includedir}/bar2-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/subprojects/subproject/aaa.txt': {
                    'destination': '{datadir}/subproject/aaa.txt',
                    'tag': None,
                    'subproject': 'subproject',
                },
                f'{testdir}/subprojects/subproject/bbb.txt': {
                    'destination': '{datadir}/subproject/bbb.txt',
                    'tag': 'data',
                    'subproject': 'subproject',
                },
            },
            'headers': {
                f'{testdir}/foo1-devel.h': {
                    'destination': '{includedir}/foo1-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
                f'{testdir}/subdir/foo3-devel.h': {
                    'destination': '{includedir}/foo3-devel.h',
                    'tag': 'devel',
                    'subproject': None,
                },
            },
            'install_subdirs': {
                f'{testdir}/custom_files': {
                    'destination': '{datadir}/custom_files',
                    'tag': 'custom',
                    'subproject': None,
                    'exclude_dirs': [],
                    'exclude_files': [],
                },
                f'{testdir}/excludes': {
                    'destination': '{datadir}/excludes',
                    'tag': 'custom',
                    'subproject': None,
                    'exclude_dirs': ['excluded'],
                    'exclude_files': ['excluded.txt'],
                }
            }
        }

        fix_path = lambda path: os.path.sep.join(path.split('/'))
        expected_fixed = {
            data_type: {
                fix_path(source): {
                    key: fix_path(value) if key == 'destination' else value
                    for key, value in attributes.items()
                }
                for source, attributes in files.items()
            }
            for data_type, files in expected.items()
        }

        for data_type, files in expected_fixed.items():
            for file, details in files.items():
                with self.subTest(key='{}.{}'.format(data_type, file)):
                    self.assertEqual(res[data_type][file], details)

    @skip_if_not_language('rust')
    @unittest.skipIf(not shutil.which('clippy-driver'), 'Test requires clippy-driver')
    def test_rust_clippy(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        # When clippy is used, we should get an exception since a variable named
        # "foo" is used, but is on our denylist
        testdir = os.path.join(self.rust_test_dir, '1 basic')
        self.init(testdir, extra_args=['--werror'], override_envvars={'RUSTC': 'clippy-driver'})
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.build()
        self.assertTrue('error: use of a blacklisted/placeholder name `foo`' in cm.exception.stdout or
                        'error: use of a disallowed/placeholder name `foo`' in cm.exception.stdout)

    @skip_if_not_language('rust')
    def test_rust_rlib_linkage(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        template = textwrap.dedent('''\
                use std::process::exit;

                pub fn fun() {{
                    exit({});
                }}
            ''')

        testdir = os.path.join(self.unit_test_dir, '102 rlib linkage')
        gen_file = os.path.join(testdir, 'lib.rs')
        with open(gen_file, 'w', encoding='utf-8') as f:
            f.write(template.format(0))
        self.addCleanup(windows_proof_rm, gen_file)

        self.init(testdir)
        self.build()
        self.run_tests()

        with open(gen_file, 'w', encoding='utf-8') as f:
            f.write(template.format(39))

        self.build()
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.run_tests()
        self.assertEqual(cm.exception.returncode, 1)
        self.assertIn('exit status 39', cm.exception.stdout)

    @skip_if_not_language('rust')
    def test_bindgen_drops_invalid(self) -> None:
        if self.backend is not Backend.ninja:
            raise unittest.SkipTest('Rust is only supported with ninja currently')
        testdir = os.path.join(self.rust_test_dir, '12 bindgen')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        # bindgen understands compiler args that clang understands, but not
        # flags by other compilers
        if cc.get_id() == 'gcc':
            bad_arg = '-fdse'
        elif cc.get_id() == 'msvc':
            bad_arg = '/fastfail'
        else:
            raise unittest.SkipTest('Test only supports GCC and MSVC')
        self.init(testdir, extra_args=[f"-Dc_args=['-DCMD_ARG', '{bad_arg}']"])
        intro = self.introspect(['--targets'])
        for i in intro:
            if i['type'] == 'custom' and i['id'].startswith('rustmod-bindgen'):
                args = i['target_sources'][0]['compiler']
                self.assertIn('-DCMD_ARG', args)
                self.assertIn('-DPROJECT_ARG', args)
                self.assertIn('-DGLOBAL_ARG', args)
                self.assertNotIn(bad_arg, args)
                self.assertNotIn('-mtls-dialect=gnu2', args)
                self.assertNotIn('/fp:fast', args)
                return

    def test_custom_target_name(self):
        testdir = os.path.join(self.unit_test_dir, '100 custom target name')
        self.init(testdir)
        out = self.build()
        if self.backend is Backend.ninja:
            self.assertIn('Generating file.txt with a custom command', out)
            self.assertIn('Generating subdir/file.txt with a custom command', out)

    def test_symlinked_subproject(self):
        testdir = os.path.join(self.unit_test_dir, '107 subproject symlink')
        subproject_dir = os.path.join(testdir, 'subprojects')
        subproject = os.path.join(testdir, 'symlinked_subproject')
        symlinked_subproject = os.path.join(testdir, 'subprojects', 'symlinked_subproject')
        if not os.path.exists(subproject_dir):
            os.mkdir(subproject_dir)
        try:
            os.symlink(subproject, symlinked_subproject)
        except OSError:
            raise SkipTest("Symlinks are not available on this machine")
        self.addCleanup(os.remove, symlinked_subproject)

        self.init(testdir)
        self.build()

    def test_configure_same_noop(self):
        testdir = os.path.join(self.unit_test_dir, '109 configure same noop')
        args = [
            '-Dstring=val',
            '-Dboolean=true',
            '-Dcombo=two',
            '-Dinteger=7',
            '-Darray=[\'three\']',
            '-Dfeature=disabled',
            '--buildtype=plain',
            '--prefix=/abc',
        ]
        self.init(testdir, extra_args=args)

        filename = Path(self.privatedir) / 'coredata.dat'

        olddata = filename.read_bytes()
        oldmtime = os.path.getmtime(filename)

        for opt in ('-Dstring=val', '--buildtype=plain', '-Dfeature=disabled', '-Dprefix=/abc'):
            self.setconf([opt])
            newdata = filename.read_bytes()
            newmtime = os.path.getmtime(filename)
            self.assertEqual(oldmtime, newmtime)
            self.assertEqual(olddata, newdata)
            olddata = newdata
            oldmtime = newmtime

        for opt in ('-Dstring=abc', '--buildtype=release', '-Dfeature=enabled', '-Dprefix=/def'):
            self.setconf([opt])
            newdata = filename.read_bytes()
            newmtime = os.path.getmtime(filename)
            self.assertGreater(newmtime, oldmtime)
            self.assertNotEqual(olddata, newdata)
            olddata = newdata
            oldmtime = newmtime

    def test_c_cpp_stds(self):
        testdir = os.path.join(self.unit_test_dir, '115 c cpp stds')
        self.init(testdir)
        # Invalid values should fail whatever compiler we have
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=invalid')
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=c89,invalid')
        with self.assertRaises(subprocess.CalledProcessError):
            self.setconf('-Dc_std=c++11')
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.get_id() == 'msvc':
            # default_option should have selected those
            self.assertEqual(self.getconf('c_std'), 'c89')
            self.assertEqual(self.getconf('cpp_std'), 'vc++11')
            # This is deprecated but works for C
            self.setconf('-Dc_std=gnu99')
            self.assertEqual(self.getconf('c_std'), 'c99')
            # C++ however never accepted that fallback
            with self.assertRaises(subprocess.CalledProcessError):
                self.setconf('-Dcpp_std=gnu++11')
            # The first supported std should be selected
            self.setconf('-Dcpp_std=gnu++11,vc++11,c++11')
            self.assertEqual(self.getconf('cpp_std'), 'vc++11')
        elif cc.get_id() == 'gcc':
            # default_option should have selected those
            self.assertEqual(self.getconf('c_std'), 'gnu89')
            self.assertEqual(self.getconf('cpp_std'), 'gnu++98')
            # The first supported std should be selected
            self.setconf('-Dcpp_std=c++11,gnu++11,vc++11')
            self.assertEqual(self.getconf('cpp_std'), 'c++11')
```