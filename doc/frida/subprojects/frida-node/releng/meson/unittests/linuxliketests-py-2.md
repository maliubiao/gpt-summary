Response:
The user wants a summary of the functionalities of the Python code provided. I need to go through each test function and explain what it does. I also need to specifically identify aspects related to reverse engineering, binary/kernel level operations, logical reasoning with examples, common user errors, and how a user might reach this code during debugging.

Here's a breakdown of each function:

*   **`test_ldflagdedup`**: Checks if linker flags are correctly deduplicated.
*   **`test_compiler_libs_static_dedup`**: Verifies that standard compiler libraries are not duplicated.
*   **`test_noncross_options`**: Tests if compiler options set in the project are applied during native compilation.
*   **`test_identity_cross`**:  Sets up a cross-compilation scenario where the host and target compilers are the same.
*   **`test_identity_cross_env`**: Similar to the previous test, but specifies the compilers using environment variables.
*   **`test_static_link`**: Tests the process of building and linking against statically linked libraries.
*   **`_check_ld`**: A helper function to check if the correct linker is being used based on environment variables.
*   **`test_ld_environment_variable_bfd`**, **`test_ld_environment_variable_gold`**, **`test_ld_environment_variable_lld`**, **`test_ld_environment_variable_rust`**, **`test_ld_environment_variable_cpp`**, **`test_ld_environment_variable_objc`**, **`test_ld_environment_variable_objcpp`**, **`test_ld_environment_variable_fortran`**, **`test_ld_environment_variable_d`**: These test the `_check_ld` function for different linkers and languages.
*   **`compute_sha256`**:  A utility function to calculate the SHA256 hash of a file.
*   **`test_wrap_with_file_url`**: Tests the functionality of using file URLs for wrap dependencies (external project dependencies).
*   **`test_no_rpath_for_static`**: Checks that rpath is not set for statically linked executables.
*   **`test_lookup_system_after_broken_fallback`**: Tests how Meson handles dependencies when a fallback subproject is broken.
*   **`test_as_link_whole`**: Tests the `-Wl,--whole-archive` and `-Wl,--no-whole-archive` linker flags.
*   **`test_prelinking`**: Tests the prelinking feature, which optimizes library loading.
*   **`do_one_test_with_nativefile`**: A helper function to run tests with a specified native file (defining compiler).
*   **`test_cmake_multilib`**: Tests the handling of multilib paths in CMake projects.
*   **`test_install_strip`**: Tests the `strip` functionality during the installation process to remove debugging symbols.
*   **`test_isystem_default_removal_with_symlink`**: Tests the handling of `isystem` include directories when they are symlinks to default include directories.
*   **`test_freezing`**: Tests a "freezing" mechanism, likely related to build reproducibility.
*   **`test_complex_link_cases`**: Tests various complex linking scenarios involving static and shared libraries.

Now, I need to connect these functionalities to the specific requests about reverse engineering, binary/kernel details, logical reasoning, user errors, and debugging paths.
这是 `frida/subprojects/frida-node/releng/meson/unittests/linuxliketests.py` 文件的第三部分，主要包含了一系列用于测试 Frida 的构建系统 (使用 Meson) 在类 Linux 系统上的功能的单元测试。归纳一下，它的主要功能是：

**对 Frida 构建系统的特定方面进行自动化测试，以确保在类 Linux 环境中构建 Frida Node 绑定时的正确性和稳定性。**

具体来说，这些测试覆盖了以下几个关键方面：

1. **链接器行为和标志处理:** 测试链接器标志的正确生成和去重，例如 `--export-dynamic`，以及对标准库的链接处理。
2. **交叉编译:**  测试在构建平台和目标平台相同时的交叉编译场景。
3. **静态链接:**  测试静态库的构建、安装和链接过程。
4. **链接器选择:**  测试通过环境变量指定不同链接器 (如 `ld.bfd`, `ld.gold`, `ld.lld`) 的功能。
5. **Wrap 文件处理:** 测试使用本地文件 URL 作为 wrap 依赖项的功能。
6. **rpath 处理:**  测试静态链接构建中 `rpath` 的正确处理。
7. **依赖查找:** 测试在回退依赖项失败后，系统依赖项的查找机制。
8. **链接器分组标志:** 测试 `-Wl,--whole-archive` 等链接器分组标志的处理。
9. **预链接 (Prelinking):** 测试预链接功能，以优化库加载。
10. **使用 Native File:**  测试通过 Native File 指定编译器信息的机制，并用于测试 CMake multilib 支持。
11. **安装和剥离 (Stripping):** 测试安装过程中的符号剥离功能。
12. **系统包含目录处理:** 测试对符号链接的系统包含目录的处理。
13. **构建冻结 (Freezing):**  测试构建的冻结机制，可能与构建的可重现性有关。
14. **复杂的链接场景:** 测试各种复杂的静态库和共享库链接组合的场景。

**与逆向的方法的关系及举例说明：**

虽然这个文件本身是构建系统的测试代码，但其测试的功能直接影响 Frida 的构建产物，而 Frida 本身是一个动态插桩工具，常用于逆向工程。

*   **链接器标志 (`test_ldflagdedup`)**:  逆向工程师经常需要理解目标程序加载了哪些库以及符号是如何解析的。`--export-dynamic` 标志确保动态符号表被导出，这对于 Frida 注入代码并调用目标进程的函数至关重要。如果这个标志没有正确处理，Frida 可能无法正常工作。
*   **静态链接 (`test_static_link`, `test_no_rpath_for_static`)**:  理解目标程序是静态链接还是动态链接对于逆向分析至关重要。静态链接的程序将所有依赖库的代码都包含在可执行文件中，而动态链接的程序则依赖于外部共享库。Frida 需要能够处理这两种情况。`rpath` 是动态链接中指定库搜索路径的方式，测试 `test_no_rpath_for_static` 确保静态链接的程序不会错误地设置 `rpath`。
*   **链接器选择 (`test_ld_environment_variable_*`)**:  不同的链接器可能在处理链接过程中的行为有所不同。Frida 需要能够适应不同的链接器，以确保在各种环境下都能正常工作。逆向工程师在分析目标程序时，可能也需要了解目标程序是使用哪个链接器构建的，以更好地理解其加载行为。
*   **符号剥离 (`test_install_strip`)**:  剥离符号的二进制文件会移除调试信息，这会增加逆向分析的难度。Frida 可以在运行时注入代码并与目标进程交互，即使目标程序被剥离了符号，但理解符号的存在与否对于逆向工程师使用 Frida 进行分析仍然重要。

**涉及二进制底层，linux, android内核及框架的知识及举例说明：**

*   **链接器和链接过程**:  所有测试都直接或间接地涉及到链接器的工作原理，这是操作系统底层的一个关键组件，负责将编译后的目标文件组合成可执行文件或共享库。
*   **动态链接和共享库 (`test_ldflagdedup`, `test_static_link`, `test_complex_link_cases`)**:  这些测试涉及到动态链接的概念，这是现代操作系统中共享代码和减少内存占用的一种重要机制。共享库的加载和符号解析是操作系统的重要功能。
*   **`rpath` (`test_no_rpath_for_static`)**:  `rpath` 是 Linux 等系统中用于指定动态链接库搜索路径的机制。理解 `rpath` 对于理解程序运行时如何找到依赖库至关重要。
*   **预链接 (`test_prelinking`)**:  预链接是一种优化技术，旨在减少动态链接库的加载时间。这涉及到对共享库进行地址重定位等底层操作。
*   **符号剥离 (`test_install_strip`)**:  符号剥离是指移除可执行文件和共享库中的调试符号表。这是一种减小文件大小和保护知识产权的常见做法。理解符号表的结构和作用对于逆向工程至关重要。
*   **`.so` 和 `.a` 文件 (`test_static_link`, `test_complex_link_cases`)**: 测试中涉及的 `.so` 文件是共享库 (Shared Object) 文件，`.a` 文件是静态库 (Archive) 文件，这是 Linux 系统中常见的库文件格式。
*   **`LD_LIBRARY_PATH`**: 在 `test_static_link` 中，提到了 `LD_LIBRARY_PATH` 环境变量，这是 Linux 系统中指定动态链接库搜索路径的一种方式。

**逻辑推理及假设输入与输出：**

*   **`test_ldflagdedup`**:
    *   **假设输入**: 一个 `meson.build` 文件，其中定义了多次使用需要添加 `--export-dynamic` 链接器标志的目标。
    *   **预期输出**: 生成的 `build.ninja` 文件中，`--export-dynamic` 标志只出现一次。
*   **`test_compiler_libs_static_dedup`**:
    *   **假设输入**: 一个 `meson.build` 文件，其中定义了需要链接标准库（如 `dl`, `m`, `c`, `rt`）的目标。
    *   **预期输出**: 生成的 `build.ninja` 文件中，`-ldl`, `-lm`, `-lc`, `-lrt` 这些链接器选项在链接命令中只出现一次。
*   **`test_noncross_options`**:
    *   **假设输入**: 一个 `meson.build` 文件，其中通过 `project()` 函数设置了 `c_std` 选项为 `'c99'`。
    *   **预期输出**: 编译命令 (在 `compile_commands.json` 中) 包含了 `-std=c99` 选项。
*   **`test_static_link`**:
    *   **假设输入**: 两个项目，第一个项目构建并安装一个静态库，第二个项目链接这个静态库。
    *   **预期输出**: 第二个项目能够成功构建并运行，证明静态链接成功。
*   **`test_ld_environment_variable_bfd`**:
    *   **假设输入**: 设置环境变量 `CC_LD` 为 `bfd`。
    *   **预期输出**: Meson 检测到的 C 语言链接器是 `ld.bfd`。
*   **`test_wrap_with_file_url`**:
    *   **假设输入**: 一个 wrap 文件，其中定义了使用本地文件 URL 作为源和补丁的回退地址。
    *   **预期输出**:  即使主 URL 无效，Meson 也能成功下载并应用本地的源文件和补丁。
*   **`test_no_rpath_for_static`**:
    *   **假设输入**: 一个构建静态链接可执行文件的 `meson.build` 文件。
    *   **预期输出**: 构建出的可执行文件没有设置 `rpath`。

**涉及用户或者编程常见的使用错误及举例说明：**

*   **重复指定链接器标志 (`test_ldflagdedup`)**: 用户可能在 `meson.build` 文件中或者通过命令行多次添加相同的链接器标志，导致链接错误或不期望的行为。Meson 应该能够正确地去重。
*   **未正确指定依赖库 (`test_static_link`)**: 用户可能忘记链接必要的静态库，导致链接失败。
*   **环境变量设置错误 (`test_ld_environment_variable_*`)**: 用户可能错误地设置了链接器相关的环境变量，导致使用了错误的链接器。
*   **Wrap 文件配置错误 (`test_wrap_with_file_url`)**: 用户可能在 wrap 文件中配置了错误的 URL 或哈希值，导致依赖下载失败。
*   **对静态链接目标设置 `rpath`**: 用户可能错误地尝试对静态链接的目标设置 `rpath`，这是没有意义的，并且可能导致混淆。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

一个用户（开发者或 Frida 贡献者）可能在以下情况下会接触到这个测试文件，并将其作为调试线索：

1. **修改 Frida Node 绑定的构建系统:** 如果开发者正在修改 Frida Node 绑定的构建逻辑，特别是与链接、依赖管理或交叉编译相关的部分，他们可能会运行这些单元测试来验证他们的修改是否引入了错误。
2. **修复构建问题:** 如果用户报告了在特定 Linux 发行版或配置下构建 Frida Node 绑定失败的问题，开发者可能会尝试重现该问题，并检查这些单元测试是否能捕获类似的错误。
3. **添加新功能:** 当向 Frida Node 绑定添加新功能时，可能需要在构建系统中进行相应的调整，开发者会编写或修改相关的单元测试来确保新功能的构建是正确的。
4. **代码审查:**  在代码审查过程中，审查者可能会查看这些单元测试，以确保代码的构建逻辑是健壮和经过测试的。
5. **持续集成 (CI) 系统报告失败:**  Frida 的 CI 系统会自动运行这些单元测试。如果某个测试失败，开发者会查看失败的测试日志和相关的测试代码，以定位问题所在。

**调试步骤可能如下：**

1. **复现问题:** 开发者尝试在本地环境中重现用户报告的构建失败问题。
2. **查看构建日志:**  分析构建日志，查找错误信息，特别是与链接器相关的错误。
3. **运行相关单元测试:**  确定哪个单元测试覆盖了出错的功能点。例如，如果链接器标志处理有问题，可能会运行 `test_ldflagdedup`。
4. **分析单元测试代码:**  查看单元测试的代码，理解其测试的场景和断言，以便更好地理解构建系统的行为。
5. **修改构建代码并重新测试:**  根据单元测试的反馈和对构建日志的分析，修改 Frida Node 绑定的构建代码 (通常是 `meson.build` 文件或相关的 Python 代码)。
6. **运行所有单元测试:**  修改后，运行所有单元测试，确保修复了问题，并且没有引入新的错误。
7. **提交代码:**  如果所有测试都通过，则将修复后的代码提交。

总而言之，这个文件是 Frida 构建系统测试套件的关键组成部分，用于确保 Frida 在类 Linux 环境下的构建质量和稳定性。理解其功能有助于开发者调试构建问题，验证新功能，并维护 Frida 项目的健康发展。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能

"""
lf):
        testdir = os.path.join(self.unit_test_dir, '51 ldflagdedup')
        if is_cygwin() or is_osx():
            raise SkipTest('Not applicable on Cygwin or OSX.')
        env = get_fake_env()
        cc = detect_c_compiler(env, MachineChoice.HOST)
        linker = cc.linker
        if not linker.export_dynamic_args(env):
            raise SkipTest('Not applicable for linkers without --export-dynamic')
        self.init(testdir)
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        max_count = 0
        search_term = '-Wl,--export-dynamic'
        with open(build_ninja, encoding='utf-8') as f:
            for line in f:
                max_count = max(max_count, line.count(search_term))
        self.assertEqual(max_count, 1, 'Export dynamic incorrectly deduplicated.')

    def test_compiler_libs_static_dedup(self):
        testdir = os.path.join(self.unit_test_dir, '55 dedup compiler libs')
        self.init(testdir)
        build_ninja = os.path.join(self.builddir, 'build.ninja')
        with open(build_ninja, encoding='utf-8') as f:
            lines = f.readlines()
        for lib in ('-ldl', '-lm', '-lc', '-lrt'):
            for line in lines:
                if lib not in line:
                    continue
                # Assert that
                self.assertEqual(len(line.split(lib)), 2, msg=(lib, line))

    @skipIfNoPkgconfig
    def test_noncross_options(self):
        # C_std defined in project options must be in effect also when native compiling.
        testdir = os.path.join(self.unit_test_dir, '50 noncross options')
        self.init(testdir, extra_args=['-Dpkg_config_path=' + testdir])
        compdb = self.get_compdb()
        self.assertEqual(len(compdb), 2)
        self.assertRegex(compdb[0]['command'], '-std=c99')
        self.assertRegex(compdb[1]['command'], '-std=c99')
        self.build()

    def test_identity_cross(self):
        testdir = os.path.join(self.unit_test_dir, '60 identity cross')

        constantsfile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        constantsfile.write(textwrap.dedent('''\
            [constants]
            py_ext = '.py'
            '''))
        constantsfile.flush()

        nativefile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        nativefile.write(textwrap.dedent('''\
            [binaries]
            c = ['{}' + py_ext]
            '''.format(os.path.join(testdir, 'build_wrapper'))))
        nativefile.flush()
        self.meson_native_files = [constantsfile.name, nativefile.name]

        crossfile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        crossfile.write(textwrap.dedent('''\
            [binaries]
            c = ['{}' + py_ext]
            '''.format(os.path.join(testdir, 'host_wrapper'))))
        crossfile.flush()
        self.meson_cross_files = [constantsfile.name, crossfile.name]

        # TODO should someday be explicit about build platform only here
        self.init(testdir)

    def test_identity_cross_env(self):
        testdir = os.path.join(self.unit_test_dir, '60 identity cross')
        env = {
            'CC_FOR_BUILD': '"' + os.path.join(testdir, 'build_wrapper.py') + '"',
            'CC': '"' + os.path.join(testdir, 'host_wrapper.py') + '"',
        }
        crossfile = tempfile.NamedTemporaryFile(mode='w', encoding='utf-8')
        crossfile.write('')
        crossfile.flush()
        self.meson_cross_files = [crossfile.name]
        # TODO should someday be explicit about build platform only here
        self.init(testdir, override_envvars=env)

    @skipIfNoPkgconfig
    def test_static_link(self):
        if is_cygwin():
            raise SkipTest("Cygwin doesn't support LD_LIBRARY_PATH.")

        # Build some libraries and install them
        testdir = os.path.join(self.unit_test_dir, '66 static link/lib')
        libdir = os.path.join(self.installdir, self.libdir)
        oldprefix = self.prefix
        self.prefix = self.installdir
        self.init(testdir)
        self.install(use_destdir=False)

        # Test that installed libraries works
        self.new_builddir()
        self.prefix = oldprefix
        meson_args = [f'-Dc_link_args=-L{libdir}',
                      '--fatal-meson-warnings']
        testdir = os.path.join(self.unit_test_dir, '66 static link')
        env = {'PKG_CONFIG_LIBDIR': os.path.join(libdir, 'pkgconfig')}
        self.init(testdir, extra_args=meson_args, override_envvars=env)
        self.build()
        self.run_tests()

    def _check_ld(self, check: str, name: str, lang: str, expected: str) -> None:
        if is_sunos():
            raise SkipTest('Solaris currently cannot override the linker.')
        if not shutil.which(check):
            raise SkipTest(f'Could not find {check}.')
        envvars = [mesonbuild.envconfig.ENV_VAR_PROG_MAP[f'{lang}_ld']]

        # Also test a deprecated variable if there is one.
        if f'{lang}_ld' in mesonbuild.envconfig.DEPRECATED_ENV_PROG_MAP:
            envvars.append(
                mesonbuild.envconfig.DEPRECATED_ENV_PROG_MAP[f'{lang}_ld'])

        for envvar in envvars:
            with mock.patch.dict(os.environ, {envvar: name}):
                env = get_fake_env()
                comp = compiler_from_language(env, lang, MachineChoice.HOST)
                if isinstance(comp, (AppleClangCCompiler, AppleClangCPPCompiler,
                                     AppleClangObjCCompiler, AppleClangObjCPPCompiler)):
                    raise SkipTest('AppleClang is currently only supported with ld64')
                if lang != 'rust' and comp.use_linker_args('bfd', '') == []:
                    raise SkipTest(
                        f'Compiler {comp.id} does not support using alternative linkers')
                self.assertEqual(comp.linker.id, expected)

    def test_ld_environment_variable_bfd(self):
        self._check_ld('ld.bfd', 'bfd', 'c', 'ld.bfd')

    def test_ld_environment_variable_gold(self):
        self._check_ld('ld.gold', 'gold', 'c', 'ld.gold')

    def test_ld_environment_variable_lld(self):
        self._check_ld('ld.lld', 'lld', 'c', 'ld.lld')

    @skip_if_not_language('rust')
    @skipIfNoExecutable('ld.gold')  # need an additional check here because _check_ld checks for gcc
    def test_ld_environment_variable_rust(self):
        self._check_ld('gcc', 'gcc -fuse-ld=gold', 'rust', 'ld.gold')

    def test_ld_environment_variable_cpp(self):
        self._check_ld('ld.gold', 'gold', 'cpp', 'ld.gold')

    @skip_if_not_language('objc')
    def test_ld_environment_variable_objc(self):
        self._check_ld('ld.gold', 'gold', 'objc', 'ld.gold')

    @skip_if_not_language('objcpp')
    def test_ld_environment_variable_objcpp(self):
        self._check_ld('ld.gold', 'gold', 'objcpp', 'ld.gold')

    @skip_if_not_language('fortran')
    def test_ld_environment_variable_fortran(self):
        self._check_ld('ld.gold', 'gold', 'fortran', 'ld.gold')

    @skip_if_not_language('d')
    def test_ld_environment_variable_d(self):
        # At least for me, ldc defaults to gold, and gdc defaults to bfd, so
        # let's pick lld, which isn't the default for either (currently)
        if is_osx():
            expected = 'ld64'
        else:
            expected = 'ld.lld'
        self._check_ld('ld.lld', 'lld', 'd', expected)

    def compute_sha256(self, filename):
        with open(filename, 'rb') as f:
            return hashlib.sha256(f.read()).hexdigest()

    def test_wrap_with_file_url(self):
        testdir = os.path.join(self.unit_test_dir, '72 wrap file url')
        source_filename = os.path.join(testdir, 'subprojects', 'foo.tar.xz')
        patch_filename = os.path.join(testdir, 'subprojects', 'foo-patch.tar.xz')
        wrap_filename = os.path.join(testdir, 'subprojects', 'foo.wrap')
        source_hash = self.compute_sha256(source_filename)
        patch_hash = self.compute_sha256(patch_filename)
        wrap = textwrap.dedent("""\
            [wrap-file]
            directory = foo

            source_url = http://server.invalid/foo
            source_fallback_url = file://{}
            source_filename = foo.tar.xz
            source_hash = {}

            patch_url = http://server.invalid/foo
            patch_fallback_url = file://{}
            patch_filename = foo-patch.tar.xz
            patch_hash = {}
            """.format(source_filename, source_hash, patch_filename, patch_hash))
        with open(wrap_filename, 'w', encoding='utf-8') as f:
            f.write(wrap)
        self.init(testdir)
        self.build()
        self.run_tests()

        windows_proof_rmtree(os.path.join(testdir, 'subprojects', 'packagecache'))
        windows_proof_rmtree(os.path.join(testdir, 'subprojects', 'foo'))
        os.unlink(wrap_filename)

    def test_no_rpath_for_static(self):
        testdir = os.path.join(self.common_test_dir, '5 linkstatic')
        self.init(testdir)
        self.build()
        build_rpath = get_rpath(os.path.join(self.builddir, 'prog'))
        self.assertIsNone(build_rpath)

    def test_lookup_system_after_broken_fallback(self):
        # Just to generate libfoo.pc so we can test system dependency lookup.
        testdir = os.path.join(self.common_test_dir, '44 pkgconfig-gen')
        self.init(testdir)
        privatedir = self.privatedir

        # Write test project where the first dependency() returns not-found
        # because 'broken' subproject does not exit, but that should not prevent
        # the 2nd dependency() to lookup on system.
        self.new_builddir()
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, 'meson.build'), 'w', encoding='utf-8') as f:
                f.write(textwrap.dedent('''\
                    project('test')
                    dependency('notfound', fallback: 'broken', required: false)
                    dependency('libfoo', fallback: 'broken', required: true)
                    '''))
            self.init(d, override_envvars={'PKG_CONFIG_LIBDIR': privatedir})

    def test_as_link_whole(self):
        testdir = os.path.join(self.unit_test_dir, '76 as link whole')
        self.init(testdir)
        with open(os.path.join(self.privatedir, 'bar1.pc'), encoding='utf-8') as f:
            content = f.read()
            self.assertIn('-lfoo', content)
        with open(os.path.join(self.privatedir, 'bar2.pc'), encoding='utf-8') as f:
            content = f.read()
            self.assertNotIn('-lfoo', content)

    def test_prelinking(self):
        # Prelinking currently only works on recently new GNU toolchains.
        # Skip everything else. When support for other toolchains is added,
        # remove limitations as necessary.
        if is_osx():
            raise SkipTest('Prelinking not supported on Darwin.')
        if 'clang' in os.environ.get('CC', 'dummy'):
            raise SkipTest('Prelinking not supported with Clang.')
        testdir = os.path.join(self.unit_test_dir, '86 prelinking')
        env = get_fake_env(testdir, self.builddir, self.prefix)
        cc = detect_c_compiler(env, MachineChoice.HOST)
        if cc.id == "gcc" and not version_compare(cc.version, '>=9'):
            raise SkipTest('Prelinking not supported with gcc 8 or older.')
        self.init(testdir)
        self.build()
        outlib = os.path.join(self.builddir, 'libprelinked.a')
        ar = shutil.which('ar')
        self.assertPathExists(outlib)
        self.assertIsNotNone(ar)
        p = subprocess.run([ar, 't', outlib],
                           stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL,
                           text=True, timeout=1)
        obj_files = p.stdout.strip().split('\n')
        self.assertEqual(len(obj_files), 1)
        self.assertTrue(obj_files[0].endswith('-prelink.o'))

    def do_one_test_with_nativefile(self, testdir, args):
        testdir = os.path.join(self.common_test_dir, testdir)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'nativefile'
            with p.open('wt', encoding='utf-8') as f:
                f.write(f'''[binaries]
                    c = {args}
                    ''')
            self.init(testdir, extra_args=['--native-file=' + str(p)])
            self.build()

    def test_cmake_multilib(self):
        '''
        Test that the cmake module handles multilib paths correctly.
        '''
        # Verify that "gcc -m32" works
        try:
            self.do_one_test_with_nativefile('1 trivial', "['gcc', '-m32']")
        except subprocess.CalledProcessError as e:
            raise SkipTest('Not GCC, or GCC does not have the -m32 option')
        self.wipe()

        # Verify that cmake works
        try:
            self.do_one_test_with_nativefile('../cmake/1 basic', "['gcc']")
        except subprocess.CalledProcessError as e:
            raise SkipTest('Could not build basic cmake project')
        self.wipe()

        # If so, we can test that cmake works with "gcc -m32"
        self.do_one_test_with_nativefile('../cmake/1 basic', "['gcc', '-m32']")

    @skipUnless(is_linux() or is_osx(), 'Test only applicable to Linux and macOS')
    def test_install_strip(self):
        testdir = os.path.join(self.unit_test_dir, '104 strip')
        self.init(testdir)
        self.build()

        destdir = self.installdir + self.prefix
        if is_linux():
            lib = os.path.join(destdir, self.libdir, 'liba.so')
        else:
            lib = os.path.join(destdir, self.libdir, 'liba.dylib')
        install_cmd = self.meson_command + ['install', '--destdir', self.installdir]

        # Check we have debug symbols by default
        self._run(install_cmd, workdir=self.builddir)
        if is_linux():
            # file can detect stripped libraries on linux
            stdout = self._run(['file', '-b', lib])
            self.assertIn('not stripped', stdout)
        else:
            # on macOS we need to query dsymutil instead.
            # Alternatively, check if __dyld_private is defined
            # in the output of nm liba.dylib, but that is not
            # 100% reliable, it needs linking to an external library
            stdout = self._run(['dsymutil', '--dump-debug-map', lib])
            self.assertIn('symbols:', stdout)

        # Check debug symbols got removed with --strip
        self._run(install_cmd + ['--strip'], workdir=self.builddir)
        if is_linux():
            stdout = self._run(['file', '-b', lib])
            self.assertNotIn('not stripped', stdout)
        else:
            stdout = self._run(['dsymutil', '--dump-debug-map', lib])
            self.assertNotIn('symbols:', stdout)

    def test_isystem_default_removal_with_symlink(self):
        env = get_fake_env()
        cpp = detect_cpp_compiler(env, MachineChoice.HOST)
        default_dirs = cpp.get_default_include_dirs()
        default_symlinks = []
        with tempfile.TemporaryDirectory() as tmpdir:
            for i in range(len(default_dirs)):
                symlink = f'{tmpdir}/default_dir{i}'
                default_symlinks.append(symlink)
                os.symlink(default_dirs[i], symlink)
            self.assertFalse(cpp.compiler_args([f'-isystem{symlink}' for symlink in default_symlinks]).to_native())

    def test_freezing(self):
        testdir = os.path.join(self.unit_test_dir, '110 freeze')
        self.init(testdir)
        self.build()
        with self.assertRaises(subprocess.CalledProcessError) as e:
            self.run_tests()
        self.assertNotIn('Traceback', e.exception.output)

    @skipUnless(is_linux(), "Ninja file differs on different platforms")
    def test_complex_link_cases(self):
        testdir = os.path.join(self.unit_test_dir, '114 complex link cases')
        self.init(testdir)
        self.build()
        with open(os.path.join(self.builddir, 'build.ninja'), encoding='utf-8') as f:
            content = f.read()
        # Verify link dependencies, see comments in meson.build.
        self.assertIn('build libt1-s3.a: STATIC_LINKER libt1-s2.a.p/s2.c.o libt1-s3.a.p/s3.c.o\n', content)
        self.assertIn('build t1-e1: c_LINKER t1-e1.p/main.c.o | libt1-s1.a libt1-s3.a\n', content)
        self.assertIn('build libt2-s3.a: STATIC_LINKER libt2-s2.a.p/s2.c.o libt2-s1.a.p/s1.c.o libt2-s3.a.p/s3.c.o\n', content)
        self.assertIn('build t2-e1: c_LINKER t2-e1.p/main.c.o | libt2-s3.a\n', content)
        self.assertIn('build t3-e1: c_LINKER t3-e1.p/main.c.o | libt3-s3.so.p/libt3-s3.so.symbols\n', content)
        self.assertIn('build t4-e1: c_LINKER t4-e1.p/main.c.o | libt4-s2.so.p/libt4-s2.so.symbols libt4-s3.a\n', content)
        self.assertIn('build t5-e1: c_LINKER t5-e1.p/main.c.o | libt5-s1.so.p/libt5-s1.so.symbols libt5-s3.a\n', content)
        self.assertIn('build t6-e1: c_LINKER t6-e1.p/main.c.o | libt6-s2.a libt6-s3.a\n', content)
        self.assertIn('build t7-e1: c_LINKER t7-e1.p/main.c.o | libt7-s3.a\n', content)
        self.assertIn('build t8-e1: c_LINKER t8-e1.p/main.c.o | libt8-s1.a libt8-s2.a libt8-s3.a\n', content)
        self.assertIn('build t9-e1: c_LINKER t9-e1.p/main.c.o | libt9-s1.a libt9-s2.a libt9-s3.a\n', content)
        self.assertIn('build t12-e1: c_LINKER t12-e1.p/main.c.o | libt12-s1.a libt12-s2.a libt12-s3.a\n', content)
        self.assertIn('build t13-e1: c_LINKER t13-e1.p/main.c.o | libt12-s1.a libt13-s3.a\n', content)

"""


```