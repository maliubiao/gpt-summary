Response:
The user wants to understand the functionality of the Python code provided. I need to analyze each test function and describe what it aims to achieve. I should also identify connections to reverse engineering, low-level details (Linux kernel, Android framework), logical reasoning, common user errors, and debugging context. Finally, I need to summarize the overall purpose of this specific file within the Frida project.

Here's a breakdown of how to approach each point:

1. **Functionality:**  Describe the purpose of each `test_...` function. Focus on what aspect of the build system or compiler behavior it's verifying.

2. **Relationship to Reverse Engineering:** Look for tests that might indirectly relate to how Frida works. For example, tests related to dynamic linking (`--export-dynamic`) are relevant because Frida injects into running processes.

3. **Binary/Kernel/Framework Knowledge:** Identify tests that touch upon linking (static vs. shared), compiler flags, or system-level configurations. Tests involving `LD_LIBRARY_PATH` or interactions with system tools like `ar` are good examples.

4. **Logical Reasoning:**  Analyze tests that have conditional logic or assertions based on specific inputs or configurations. For example, testing the deduplication of linker flags involves reasoning about how the build system should handle redundant entries.

5. **User Errors:**  Consider scenarios where incorrect user configurations or commands might lead to the test conditions being met. For instance, accidentally providing duplicate linker flags.

6. **Debugging Context:**  Think about how a developer working on Frida might use these tests to debug build issues. The tests act as specific scenarios to isolate and verify different parts of the build process.

7. **User Operation Flow:** Trace how a user interacting with Frida might indirectly trigger the conditions being tested. This involves thinking about the steps involved in building Frida or projects that use Frida.

8. **Summary of Functionality:**  Combine the individual function descriptions into a concise overview of what this file contributes to the Frida project. Focus on the type of testing it performs.
这是 `frida/subprojects/frida-tools/releng/meson/unittests/linuxliketests.py` 文件的第三部分，主要包含了一系列针对 Linux 或类 Unix 系统环境的单元测试。这些测试主要验证 Frida 工具的构建系统（使用 Meson）在处理各种与链接、编译、依赖以及打包相关的场景时的正确性。

以下是对其中各个测试用例的功能以及与逆向、底层知识、逻辑推理、用户错误和调试线索的分析：

**功能归纳:**

总的来说，这个文件的功能是 **测试 Frida 工具的构建系统在 Linux 或类 Unix 环境下的特定行为和功能**。它涵盖了以下几个主要方面：

* **链接器行为:**  测试链接器标志的正确生成和去重，以及通过环境变量控制链接器的能力。
* **依赖管理:**  测试静态链接库的正确链接，以及在依赖查找失败时的回退机制。
* **编译选项:**  验证编译选项（如 C 标准）在本地编译时的生效。
* **交叉编译:**  测试身份交叉编译的配置。
* **子项目管理:**  测试使用 `wrap` 文件以及 `file://` URL 来管理子项目依赖。
* **静态链接:**  验证静态链接构建的可执行文件没有 RPATH。
* **预链接:**  测试预链接功能是否正常工作。
* **CMake 集成:** 测试 Meson 的 CMake 模块是否能正确处理多架构路径。
* **安装和剥离符号:**  测试安装时是否能正确剥离调试符号。
* **系统包含路径:**  测试当使用符号链接指向默认系统包含目录时，`-isystem` 参数的移除。
* **冻结构建:**  测试构建冻结功能。
* **复杂的链接场景:**  验证在复杂的链接场景下，构建系统生成的链接指令是否正确。

**与逆向方法的关系：**

* **`test_ld_environment_variable_*` 系列测试:**  这些测试验证了可以通过设置环境变量来指定链接器。在逆向工程中，有时需要使用特定的链接器版本或具有特殊功能的链接器来分析或修改二进制文件。例如，使用 `lld` 可以进行更细粒度的控制。Frida 本身也需要在目标进程中加载代码，其加载过程涉及到链接和动态链接。
* **`test_no_rpath_for_static`:** 静态链接的可执行文件通常不依赖于外部共享库的特定路径，这与动态链接的可执行文件形成对比。在逆向分析中，了解目标程序是静态链接还是动态链接是重要的第一步。Frida 注入代码时，需要考虑目标进程的链接方式。
* **`test_install_strip`:**  剥离符号信息会使逆向分析更加困难。攻击者可能也会剥离恶意软件的符号信息来隐藏其内部工作原理。Frida 作为一个动态插桩工具，可以在运行时访问目标进程的内存和符号信息，这可以绕过某些剥离符号的保护措施。

**举例说明:**

* **`test_ld_environment_variable_gold`:**  在逆向某些使用了特定链接器特性编译的二进制文件时，你可能需要在构建 Frida 或相关工具时指定相同的链接器。例如，如果目标二进制文件使用了 `ld.gold` 的某些特定优化，那么在构建 Frida 桥接库时，你也可能需要使用 `ld.gold` 来确保兼容性或进行更精确的控制。

**涉及到二进制底层、Linux、Android 内核及框架的知识：**

* **`test_ldflagdedup`:**  `--export-dynamic` 标志对于动态链接至关重要，它指示链接器将所有全局符号添加到动态符号表，这对于像 Frida 这样的动态插桩工具在运行时查找和调用目标进程的函数是必要的。
* **`test_compiler_libs_static_dedup`:**  `-ldl`, `-lm`, `-lc`, `-lrt` 等是常见的 C 标准库和其他系统库。理解这些库的作用和链接方式对于理解程序的底层行为至关重要。例如，`-ldl` 用于动态加载库，这与 Frida 的代码注入机制密切相关。
* **`test_static_link`:** 静态链接将所有依赖库的代码都嵌入到最终的可执行文件中，而动态链接则依赖于运行时加载共享库。理解这两种链接方式的区别对于分析程序的依赖关系和运行时行为至关重要。
* **`test_no_rpath_for_static`:** RPATH 是动态链接可执行文件中用于指定查找共享库的路径的机制。静态链接的可执行文件不需要 RPATH。
* **`test_prelinking`:** 预链接是一种优化技术，旨在减少程序启动时间。理解预链接的工作原理可以帮助分析程序的加载过程。
* **`test_install_strip`:** 调试符号信息对于调试和逆向工程非常有用。了解如何剥离和保留符号信息对于构建和分析软件至关重要。
* **`test_complex_link_cases`:**  测试中涉及静态库 (`.a`) 和共享库 (`.so`) 的各种链接组合，这直接反映了 Linux 系统下程序链接的复杂性。理解不同类型的库以及它们在链接过程中的作用是进行底层分析的基础。

**举例说明:**

* **`test_ldflagdedup`:**  当 Frida 需要注入到目标进程时，它需要能够访问目标进程的函数和数据。`--export-dynamic` 确保了这些符号在动态链接时被导出，使得 Frida 能够找到它们。在 Android 系统中，Frida 需要与 ART 虚拟机或 Native 代码进行交互，这依赖于正确的符号解析。
* **`test_static_link`:**  在某些嵌入式 Linux 系统或 Android 系统中，为了减小体积或避免依赖问题，可能会使用静态链接。Frida 需要能够适应这种情况。

**逻辑推理 (假设输入与输出):**

* **`test_ldflagdedup`:**
    * **假设输入:** `meson.build` 文件中多次指定了 `-Wl,--export-dynamic` 链接器标志。
    * **预期输出:** 构建系统生成的 `build.ninja` 文件中，`-Wl,--export-dynamic` 只出现一次，说明链接器标志被正确去重。
* **`test_compiler_libs_static_dedup`:**
    * **假设输入:**  `meson.build` 文件中可能多次请求链接 `-ldl`, `-lm`, `-lc`, `-lrt` 等库。
    * **预期输出:**  `build.ninja` 文件中，每个库只被链接一次，即使在输入中多次声明。
* **`test_noncross_options`:**
    * **假设输入:** `meson.build` 中定义了项目级别的 C 标准为 `c99`。
    * **预期输出:**  编译数据库 (`compile_commands.json`) 中记录的编译命令都包含 `-std=c99`。

**用户或编程常见的使用错误：**

* **`test_ldflagdedup`:**  用户可能在 `meson.build` 文件中不小心多次添加了相同的链接器标志，例如：
  ```meson
  executable('myprogram', 'main.c', link_args : '-Wl,--export-dynamic')
  executable('myprogram', 'main.c', link_args : '-Wl,--export-dynamic') # 错误地重复添加
  ```
  这个测试确保了构建系统能够处理这种情况，避免生成重复的链接器标志。
* **`test_static_link`:**  用户可能错误地设置了链接参数，导致静态链接失败或者链接到错误的库。例如，链接时没有指定正确的库搜索路径。
* **`test_wrap_with_file_url`:**  用户在使用 `wrap` 文件管理子项目时，可能提供的本地文件路径不存在或者哈希值不匹配。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **Frida 开发人员修改了构建系统相关的代码。**
2. **为了验证修改的正确性，开发人员运行了单元测试。**
3. **Meson 构建系统会解析 `meson.build` 文件并生成 `build.ninja` 文件。**
4. **`linuxliketests.py` 中的测试用例会读取生成的 `build.ninja` 文件，或者执行构建命令，并检查其输出和行为。**
5. **例如，对于 `test_ldflagdedup`，测试会读取 `build.ninja` 文件，查找 `-Wl,--export-dynamic` 出现的次数。**
6. **如果测试失败，说明最近的构建系统代码修改引入了问题，例如链接器标志没有正确去重。**
7. **开发人员可以根据测试失败的具体信息（例如，`-Wl,--export-dynamic` 出现了多次）来定位问题所在，并检查相关的 Meson 代码逻辑。**

**功能归纳 (总结):**

这个文件的主要功能是 **对 Frida 工具在 Linux 或类 Unix 系统下的构建过程进行细致的单元测试，特别是关注链接器行为、依赖管理、编译选项和子项目处理等方面。** 它通过模拟各种构建场景，验证 Meson 构建系统生成的构建指令和最终产物的正确性，确保 Frida 工具能够在该类系统上可靠地构建和运行。这些测试覆盖了与逆向工程相关的链接特性、底层系统库的使用、以及用户可能遇到的配置错误，为 Frida 的稳定性和正确性提供了保障。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/unittests/linuxliketests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
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
```