Response:
The user wants a summary of the Python code provided, focusing on its functionality and connections to reverse engineering, binary/kernel knowledge, logical reasoning, and common user errors.

**Plan:**

1. **Identify the core purpose of the script:**  The filename `allplatformstests.py` within a `unittests` directory strongly suggests this script contains unit tests for the Frida-gum library.
2. **Analyze the test functions:** Each `test_` prefixed method likely tests a specific feature or aspect of the Frida-gum build system (Meson).
3. **Categorize the functionalities based on the user's request:**
    - **General Functionality:**  Describe what the tests are generally checking (e.g., correct handling of Meson configurations, warnings, introspection).
    - **Relationship to Reverse Engineering:** Look for tests related to introspection, which is a core technique in reverse engineering to understand program structure and behavior.
    - **Binary/Kernel Knowledge:**  While the tests themselves are high-level, consider if any tests implicitly touch upon concepts related to binary formats, operating systems (Linux, Android), or kernel aspects (though this is less likely in these build system tests).
    - **Logical Reasoning:** Identify tests that involve setting up specific conditions (inputs) and verifying expected outcomes (outputs).
    - **Common User Errors:**  Look for tests that might catch common mistakes users make when configuring or building with Meson.
    - **User Steps to Reach This Code:**  Infer the user's path to this script based on the file path.
4. **Synthesize the information into a concise summary (Part 5 of 7).**
这是Frida动态 instrumentation工具的源代码文件 `allplatformstests.py` 的一部分，它是一个单元测试文件，用于测试 Frida-gum (Frida 的一个子项目) 构建系统在不同平台上的行为。

**功能归纳 (第 5 部分):**

这个代码片段主要涵盖了 Frida-gum 构建系统的以下几个方面的单元测试：

* **Meson 版本警告:**  测试当子项目指定了与主项目不兼容的最低 Meson 版本时，是否会正确显示警告信息。
* **配置文件警告:** 测试 `configure_file` 函数在处理配置文件时，对于缺失的变量、重复输出、空配置数据等情况是否会产生正确的警告信息。
* **目录处理:** 测试构建系统在没有指定构建目录时是否会给出明确的错误提示，以及在子目录中进行构建是否正常。
* **构建类型设置:** 测试通过命令行参数设置不同的构建类型 (`debug`, `release`) 以及相关的调试和优化选项是否生效。
* **原生依赖 (pkg-config):** 测试在交叉编译环境下，如何正确使用 `pkg-config` 来查找原生依赖，并处理 `PKG_CONFIG_LIBDIR` 的设置。
* **重新配置和清理:** 测试使用 `--reconfigure` 参数后，构建系统是否能正确重新生成配置，以及 `--wipe` 命令是否能清除构建目录中的生成文件。
* **目标 ID 生成:** 测试构建目标 ID 的生成逻辑是否稳定，以防止意外更改。
* **项目信息内省:** 测试在没有配置构建的情况下，通过内省获取项目信息 (如项目名称、版本、子项目等) 是否正确。
* **子项目目标内省:** 测试内省功能是否能正确识别目标所属的子项目。
* **自定义子项目目录:** 测试构建系统是否支持自定义子项目存放的目录，并在内省时能正确识别。
* **代码格式化 (clang-format):**  测试是否集成了 `clang-format` 代码格式化工具，并能正确地对代码进行格式化。
* **静态代码分析 (clang-tidy):** 测试是否集成了 `clang-tidy` 静态代码分析工具，并能发现代码中的潜在问题。
* **交叉编译标识:** 测试构建系统是否能正确识别并处理使用自身构建的交叉编译配置文件。
* **构建选项内省:** 测试在配置构建前后，内省构建选项信息是否一致。
* **从源代码配置:** 测试直接从源代码目录运行 `meson configure` 命令是否正常。
* **交叉编译专用构建选项内省:** 测试在交叉编译环境下，内省构建选项时是否只显示目标平台的选项。
* **JSON 输出 (扁平模式):** 测试以扁平 JSON 格式输出内省信息是否正确。
* **JSON 输出 (完整模式):** 测试以完整 JSON 格式输出各种内省信息 (如目标、测试、构建选项、依赖等) 的内容和结构是否符合预期。
* **JSON 文件转储与 `--all` 参数一致性:** 测试使用单独的 JSON 文件输出内省信息与使用 `--all` 参数输出所有信息是否一致。
* **`meson-info.json` 内容:** 测试 `meson-info.json` 文件中包含的关键信息是否正确。
* **配置更新内省:** 测试更新构建配置后，内省的构建选项信息是否也随之更新。
* **从源代码内省目标:** 测试在没有配置构建的情况下，从源代码目录内省目标信息是否正确。

**与逆向方法的联系及举例说明:**

* **内省 (Introspection):**  这个文件中的大量测试都与 Meson 的内省功能有关。内省在逆向工程中非常重要，因为它可以帮助我们理解目标程序的结构、依赖关系、编译选项等信息，而无需实际运行程序。
    * **举例:** `test_introspection_target_subproject` 测试了内省功能是否能正确识别目标所属的子项目。在逆向一个复杂的项目时，了解不同库或模块的组织结构非常有帮助，内省功能提供的目标信息可以辅助分析。
    * **举例:** `test_introspect_buildoptions_without_configured_build` 测试了在未配置构建的情况下获取构建选项。逆向工程师可能需要了解目标程序在编译时使用了哪些特定的编译选项，这可以帮助他们理解程序的行为或找到潜在的漏洞。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然这个测试文件主要关注构建系统，但它间接涉及到一些底层概念：

* **二进制文件生成:**  测试最终会生成二进制文件 (如可执行文件、库文件)，尽管测试本身不直接操作这些二进制文件，但其目的是验证构建过程的正确性。
* **编译选项:**  测试中涉及到设置和检查编译选项 (`-Ddebug`, `-Doptimization`, `-Dcpp_std` 等)，这些选项直接影响生成的二进制代码。
* **链接:**  `test_native_dep_pkgconfig` 和 `test_pkg_config_libdir` 涉及到使用 `pkg-config` 查找链接库，这是构建过程中链接步骤的关键。
* **交叉编译:**  `test_native_dep_pkgconfig`, `test_pkg_config_libdir`, `test_identity_cross`, 和 `test_introspect_buildoptions_cross_only` 等测试涉及到交叉编译，这是在 Linux 和 Android 开发中常见的场景，用于在宿主机上构建目标平台 (如 Android 设备) 的程序。
    * **举例:** 在逆向 Android 应用的 native 库时，了解其构建过程中使用的交叉编译工具链和库路径非常重要。这些测试确保了 Meson 能正确处理这些配置。

**逻辑推理及假设输入与输出:**

很多测试都涉及到逻辑推理，即设定特定的构建配置 (假设输入) 并验证最终的构建状态或内省结果 (预期输出)。

* **举例 (test_configure_file_warnings):**
    * **假设输入:** 一个包含 `config.h.in` 和 `nosubst-nocopy2.txt.in` 文件的项目，其中 `config.h.in` 的模板变量 `empty` 未定义，`nosubst-nocopy2.txt.in` 的模板变量 `FOO_BAR` 未定义。
    * **预期输出:**  构建过程会产生包含 "WARNING:.*'empty'.*config.h.in.*not present.*" 和 "WARNING:.*'FOO_BAR'.*nosubst-nocopy2.txt.in.*not present.*" 的警告信息。

* **举例 (test_buildtype_setting):**
    * **假设输入:**  首先不指定任何构建类型，然后分别使用 `-Ddebug=false` 和 `-Doptimization=g` 设置构建选项。
    * **预期输出:**  内省的构建选项会反映这些设置，例如 `debug` 的值会变为 `False`，`optimization` 的值会变为 `g`。

**涉及用户或者编程常见的使用错误及举例说明:**

* **未指定构建目录:** `test_dirs` 测试了当用户忘记指定构建目录时，构建系统是否会给出清晰的错误提示。
* **Meson 版本不兼容:** `test_meson_minimum_version_warning` 测试了当子项目要求的 Meson 版本高于主项目时，是否会发出警告，这可以帮助用户避免因版本不兼容导致的问题。
* **配置文件变量缺失:** `test_configure_file_warnings` 测试了当配置文件模板中使用的变量未定义时，是否会产生警告，帮助用户及时发现配置错误。
* **重复输出配置文件:** `test_configure_file_warnings` 也测试了当多个 `configure_file` 命令尝试输出到同一个文件时，是否会发出警告，避免用户意外覆盖文件。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

一个开发者在开发 Frida-gum 工具时，为了确保构建系统的各个功能在不同平台上都能正常工作，会编写单元测试。这个特定的文件 `allplatformstests.py` 位于 `frida/subprojects/frida-gum/releng/meson/unittests/` 目录下，表明开发者正在测试 Frida-gum 项目中与构建系统 (使用 Meson) 相关的、需要跨平台兼容的功能。

用户（开发者）可能会执行以下步骤来运行这些测试：

1. **进入 Frida-gum 项目的构建目录或源代码目录。**
2. **执行 Meson 提供的测试命令，例如 `meson test` 或特定的测试命令 (取决于具体的测试框架配置)。**
3. **Meson 会自动发现并执行 `unittests` 目录下的测试脚本，包括 `allplatformstests.py`。**
4. **测试脚本会模拟各种构建场景，调用 Frida-gum 的构建系统功能，并断言其行为是否符合预期。**

如果某个测试失败，开发者可以通过查看测试输出、分析测试代码和相关的 Frida-gum 代码来定位问题，`allplatformstests.py` 就是他们调试构建系统问题的线索之一。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```python
| .*WARNING: Project targets '!=0.40'.*'0.44.0': disabler")
        # Subproject has a new-enough meson_version, no warning
        self.assertNotRegex(out, "WARNING: Project targets.*Python")
        # Ensure a summary is printed in the subproject and the outer project
        self.assertRegex(out, r"\| WARNING: Project specifies a minimum meson_version '>=0.40'")
        self.assertRegex(out, r"\| \* 0.44.0: {'disabler'}")
        self.assertRegex(out, "WARNING: Project specifies a minimum meson_version '>=0.45'")
        self.assertRegex(out, " * 0.47.0: {'dict'}")

    def test_configure_file_warnings(self):
        testdir = os.path.join(self.common_test_dir, "14 configure file")
        out = self.init(testdir)
        self.assertRegex(out, "WARNING:.*'empty'.*config.h.in.*not present.*")
        self.assertRegex(out, "WARNING:.*'FOO_BAR'.*nosubst-nocopy2.txt.in.*not present.*")
        self.assertRegex(out, "WARNING:.*'empty'.*config.h.in.*not present.*")
        self.assertRegex(out, "WARNING:.*empty configuration_data.*test.py.in")
        # Warnings for configuration files that are overwritten.
        self.assertRegex(out, "WARNING:.*\"double_output.txt\".*overwrites")
        self.assertRegex(out, "WARNING:.*\"subdir.double_output2.txt\".*overwrites")
        self.assertNotRegex(out, "WARNING:.*no_write_conflict.txt.*overwrites")
        self.assertNotRegex(out, "WARNING:.*@BASENAME@.*overwrites")
        self.assertRegex(out, "WARNING:.*\"sameafterbasename\".*overwrites")
        # No warnings about empty configuration data objects passed to files with substitutions
        self.assertNotRegex(out, "WARNING:.*empty configuration_data.*nosubst-nocopy1.txt.in")
        self.assertNotRegex(out, "WARNING:.*empty configuration_data.*nosubst-nocopy2.txt.in")
        with open(os.path.join(self.builddir, 'nosubst-nocopy1.txt'), 'rb') as f:
            self.assertEqual(f.read().strip(), b'/* #undef FOO_BAR */')
        with open(os.path.join(self.builddir, 'nosubst-nocopy2.txt'), 'rb') as f:
            self.assertEqual(f.read().strip(), b'')

    def test_dirs(self):
        with tempfile.TemporaryDirectory() as containing:
            with tempfile.TemporaryDirectory(dir=containing) as srcdir:
                mfile = os.path.join(srcdir, 'meson.build')
                of = open(mfile, 'w', encoding='utf-8')
                of.write("project('foobar', 'c')\n")
                of.close()
                pc = subprocess.run(self.setup_command,
                                    cwd=srcdir,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL)
                self.assertIn(b'Must specify at least one directory name', pc.stdout)
                with tempfile.TemporaryDirectory(dir=srcdir) as builddir:
                    subprocess.run(self.setup_command,
                                   check=True,
                                   cwd=builddir,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)

    def get_opts_as_dict(self):
        result = {}
        for i in self.introspect('--buildoptions'):
            result[i['name']] = i['value']
        return result

    def test_buildtype_setting(self):
        testdir = os.path.join(self.common_test_dir, '1 trivial')
        self.init(testdir)
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['buildtype'], 'debug')
        self.assertEqual(opts['debug'], True)
        self.setconf('-Ddebug=false')
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['debug'], False)
        self.assertEqual(opts['buildtype'], 'debug')
        self.assertEqual(opts['optimization'], '0')
        self.setconf('-Doptimization=g')
        opts = self.get_opts_as_dict()
        self.assertEqual(opts['debug'], False)
        self.assertEqual(opts['buildtype'], 'debug')
        self.assertEqual(opts['optimization'], 'g')

    @skipIfNoPkgconfig
    @skipIf(is_windows(), 'Help needed with fixing this test on windows')
    def test_native_dep_pkgconfig(self):
        testdir = os.path.join(self.unit_test_dir,
                               '45 native dep pkgconfig var')
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as crossfile:
            crossfile.write(textwrap.dedent(
                '''[binaries]
                pkg-config = '{}'

                [properties]

                [host_machine]
                system = 'linux'
                cpu_family = 'arm'
                cpu = 'armv7'
                endian = 'little'
                '''.format(os.path.join(testdir, 'cross_pkgconfig.py'))))
            crossfile.flush()
            self.meson_cross_files = [crossfile.name]

        env = {'PKG_CONFIG_LIBDIR':  os.path.join(testdir,
                                                  'native_pkgconfig')}
        self.init(testdir, extra_args=['-Dstart_native=false'], override_envvars=env)
        self.wipe()
        self.init(testdir, extra_args=['-Dstart_native=true'], override_envvars=env)

    @skipIfNoPkgconfig
    @skipIf(is_windows(), 'Help needed with fixing this test on windows')
    def test_pkg_config_libdir(self):
        testdir = os.path.join(self.unit_test_dir,
                               '45 native dep pkgconfig var')
        with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as crossfile:
            crossfile.write(textwrap.dedent(
                '''[binaries]
                pkg-config = 'pkg-config'

                [properties]
                pkg_config_libdir = ['{}']

                [host_machine]
                system = 'linux'
                cpu_family = 'arm'
                cpu = 'armv7'
                endian = 'little'
                '''.format(os.path.join(testdir, 'cross_pkgconfig'))))
            crossfile.flush()
            self.meson_cross_files = [crossfile.name]

        env = {'PKG_CONFIG_LIBDIR':  os.path.join(testdir,
                                                  'native_pkgconfig')}
        self.init(testdir, extra_args=['-Dstart_native=false'], override_envvars=env)
        self.wipe()
        self.init(testdir, extra_args=['-Dstart_native=true'], override_envvars=env)

    def __reconfigure(self):
        # Set an older version to force a reconfigure from scratch
        filename = os.path.join(self.privatedir, 'coredata.dat')
        with open(filename, 'rb') as f:
            obj = pickle.load(f)
        obj.version = '0.47.0'
        with open(filename, 'wb') as f:
            pickle.dump(obj, f)

    def test_reconfigure(self):
        testdir = os.path.join(self.unit_test_dir, '47 reconfigure')
        self.init(testdir, extra_args=['-Dopt1=val1', '-Dsub1:werror=true'])
        self.setconf('-Dopt2=val2')

        self.__reconfigure()

        out = self.init(testdir, extra_args=['--reconfigure', '-Dopt3=val3'])
        self.assertRegex(out, 'Regenerating configuration from scratch')
        self.assertRegex(out, 'opt1 val1')
        self.assertRegex(out, 'opt2 val2')
        self.assertRegex(out, 'opt3 val3')
        self.assertRegex(out, 'opt4 default4')
        self.assertRegex(out, 'sub1:werror true')
        self.build()
        self.run_tests()

        # Create a file in builddir and verify wipe command removes it
        filename = os.path.join(self.builddir, 'something')
        open(filename, 'w', encoding='utf-8').close()
        self.assertTrue(os.path.exists(filename))
        out = self.init(testdir, extra_args=['--wipe', '-Dopt4=val4'])
        self.assertFalse(os.path.exists(filename))
        self.assertRegex(out, 'opt1 val1')
        self.assertRegex(out, 'opt2 val2')
        self.assertRegex(out, 'opt3 val3')
        self.assertRegex(out, 'opt4 val4')
        self.assertRegex(out, 'sub1:werror true')
        self.assertTrue(Path(self.builddir, '.gitignore').exists())
        self.build()
        self.run_tests()

    def test_wipe_from_builddir(self):
        testdir = os.path.join(self.common_test_dir, '157 custom target subdir depend files')
        self.init(testdir)
        self.__reconfigure()
        self.init(testdir, extra_args=['--wipe'], workdir=self.builddir)

    def test_target_construct_id_from_path(self):
        # This id is stable but not guessable.
        # The test is supposed to prevent unintentional
        # changes of target ID generation.
        target_id = Target.construct_id_from_path('some/obscure/subdir',
                                                  'target-id', '@suffix')
        self.assertEqual('5e002d3@@target-id@suffix', target_id)
        target_id = Target.construct_id_from_path('subproject/foo/subdir/bar',
                                                  'target2-id', '@other')
        self.assertEqual('81d46d1@@target2-id@other', target_id)

    def test_introspect_projectinfo_without_configured_build(self):
        testfile = os.path.join(self.common_test_dir, '33 run program', 'meson.build')
        res = self.introspect_directory(testfile, '--projectinfo')
        self.assertEqual(set(res['buildsystem_files']), {'meson.build'})
        self.assertEqual(res['version'], 'undefined')
        self.assertEqual(res['descriptive_name'], 'run command')
        self.assertEqual(res['subprojects'], [])

        testfile = os.path.join(self.common_test_dir, '40 options', 'meson.build')
        res = self.introspect_directory(testfile, '--projectinfo')
        self.assertEqual(set(res['buildsystem_files']), {'meson_options.txt', 'meson.build'})
        self.assertEqual(res['version'], 'undefined')
        self.assertEqual(res['descriptive_name'], 'options')
        self.assertEqual(res['subprojects'], [])

        testfile = os.path.join(self.common_test_dir, '43 subproject options', 'meson.build')
        res = self.introspect_directory(testfile, '--projectinfo')
        self.assertEqual(set(res['buildsystem_files']), {'meson_options.txt', 'meson.build'})
        self.assertEqual(res['version'], 'undefined')
        self.assertEqual(res['descriptive_name'], 'suboptions')
        self.assertEqual(len(res['subprojects']), 1)
        subproject_files = {f.replace('\\', '/') for f in res['subprojects'][0]['buildsystem_files']}
        self.assertEqual(subproject_files, {'subprojects/subproject/meson_options.txt', 'subprojects/subproject/meson.build'})
        self.assertEqual(res['subprojects'][0]['name'], 'subproject')
        self.assertEqual(res['subprojects'][0]['version'], 'undefined')
        self.assertEqual(res['subprojects'][0]['descriptive_name'], 'subproject')

    def test_introspect_projectinfo_subprojects(self):
        testdir = os.path.join(self.common_test_dir, '98 subproject subdir')
        self.init(testdir)
        res = self.introspect('--projectinfo')
        expected = {
            'descriptive_name': 'proj',
            'version': 'undefined',
            'subproject_dir': 'subprojects',
            'subprojects': [
                {
                    'descriptive_name': 'sub',
                    'name': 'sub',
                    'version': '1.0'
                },
                {
                    'descriptive_name': 'sub_implicit',
                    'name': 'sub_implicit',
                    'version': '1.0',
                },
                {
                    'descriptive_name': 'sub-novar',
                    'name': 'sub_novar',
                    'version': '1.0',
                },
                {
                    'descriptive_name': 'sub_static',
                    'name': 'sub_static',
                    'version': 'undefined'
                },
                {
                    'descriptive_name': 'subsub',
                    'name': 'subsub',
                    'version': 'undefined'
                },
                {
                    'descriptive_name': 'subsubsub',
                    'name': 'subsubsub',
                    'version': 'undefined'
                },
            ]
        }
        res['subprojects'] = sorted(res['subprojects'], key=lambda i: i['name'])
        self.assertDictEqual(expected, res)

    def test_introspection_target_subproject(self):
        testdir = os.path.join(self.common_test_dir, '42 subproject')
        self.init(testdir)
        res = self.introspect('--targets')

        expected = {
            'sublib': 'sublib',
            'simpletest': 'sublib',
            'user': None
        }

        for entry in res:
            name = entry['name']
            self.assertEqual(entry['subproject'], expected[name])

    def test_introspect_projectinfo_subproject_dir(self):
        testdir = os.path.join(self.common_test_dir, '75 custom subproject dir')
        self.init(testdir)
        res = self.introspect('--projectinfo')

        self.assertEqual(res['subproject_dir'], 'custom_subproject_dir')

    def test_introspect_projectinfo_subproject_dir_from_source(self):
        testfile = os.path.join(self.common_test_dir, '75 custom subproject dir', 'meson.build')
        res = self.introspect_directory(testfile, '--projectinfo')

        self.assertEqual(res['subproject_dir'], 'custom_subproject_dir')

    @skipIfNoExecutable('clang-format')
    def test_clang_format(self):
        if self.backend is not Backend.ninja:
            raise SkipTest(f'Clang-format is for now only supported on Ninja, not {self.backend.name}')
        testdir = os.path.join(self.unit_test_dir, '53 clang-format')

        # Ensure that test project is in git even when running meson from tarball.
        srcdir = os.path.join(self.builddir, 'src')
        shutil.copytree(testdir, srcdir)
        git_init(srcdir)
        testdir = srcdir
        self.new_builddir()

        testfile = os.path.join(testdir, 'prog.c')
        badfile = os.path.join(testdir, 'prog_orig_c')
        goodfile = os.path.join(testdir, 'prog_expected_c')
        testheader = os.path.join(testdir, 'header.h')
        badheader = os.path.join(testdir, 'header_orig_h')
        goodheader = os.path.join(testdir, 'header_expected_h')
        includefile = os.path.join(testdir, '.clang-format-include')
        try:
            shutil.copyfile(badfile, testfile)
            shutil.copyfile(badheader, testheader)
            self.init(testdir)
            self.assertNotEqual(Path(testfile).read_text(encoding='utf-8'),
                                Path(goodfile).read_text(encoding='utf-8'))
            self.assertNotEqual(Path(testheader).read_text(encoding='utf-8'),
                                Path(goodheader).read_text(encoding='utf-8'))

            # test files are not in git so this should do nothing
            self.run_target('clang-format')
            self.assertNotEqual(Path(testfile).read_text(encoding='utf-8'),
                                Path(goodfile).read_text(encoding='utf-8'))
            self.assertNotEqual(Path(testheader).read_text(encoding='utf-8'),
                                Path(goodheader).read_text(encoding='utf-8'))

            # Add an include file to reformat everything
            with open(includefile, 'w', encoding='utf-8') as f:
                f.write('*')
            self.run_target('clang-format')
            self.assertEqual(Path(testheader).read_text(encoding='utf-8'),
                             Path(goodheader).read_text(encoding='utf-8'))
        finally:
            if os.path.exists(testfile):
                os.unlink(testfile)
            if os.path.exists(testheader):
                os.unlink(testheader)
            if os.path.exists(includefile):
                os.unlink(includefile)

    @skipIfNoExecutable('clang-tidy')
    def test_clang_tidy(self):
        if self.backend is not Backend.ninja:
            raise SkipTest(f'Clang-tidy is for now only supported on Ninja, not {self.backend.name}')
        if shutil.which('c++') is None:
            raise SkipTest('Clang-tidy breaks when ccache is used and "c++" not in path.')
        if is_osx():
            raise SkipTest('Apple ships a broken clang-tidy that chokes on -pipe.')
        testdir = os.path.join(self.unit_test_dir, '68 clang-tidy')
        dummydir = os.path.join(testdir, 'dummydir.h')
        self.init(testdir, override_envvars={'CXX': 'c++'})
        out = self.run_target('clang-tidy')
        self.assertIn('cttest.cpp:4:20', out)
        self.assertNotIn(dummydir, out)

    @skipIfNoExecutable('clang-tidy')
    def test_clang_tidy_fix(self):
        if self.backend is not Backend.ninja:
            raise SkipTest(f'Clang-tidy is for now only supported on Ninja, not {self.backend.name}')
        if shutil.which('c++') is None:
            raise SkipTest('Clang-tidy breaks when ccache is used and "c++" not in path.')
        if is_osx():
            raise SkipTest('Apple ships a broken clang-tidy that chokes on -pipe.')
        testdir = os.path.join(self.unit_test_dir, '68 clang-tidy')

        # Ensure that test project is in git even when running meson from tarball.
        srcdir = os.path.join(self.builddir, 'src')
        shutil.copytree(testdir, srcdir)
        git_init(srcdir)
        testdir = srcdir
        self.new_builddir()

        dummydir = os.path.join(testdir, 'dummydir.h')
        testfile = os.path.join(testdir, 'cttest.cpp')
        fixedfile = os.path.join(testdir, 'cttest_fixed.cpp')
        self.init(testdir, override_envvars={'CXX': 'c++'})
        # Make sure test files are different
        self.assertNotEqual(Path(testfile).read_text(encoding='utf-8'),
                            Path(fixedfile).read_text(encoding='utf-8'))
        out = self.run_target('clang-tidy-fix')
        self.assertIn('cttest.cpp:4:20', out)
        self.assertNotIn(dummydir, out)
        # Make sure the test file is fixed
        self.assertEqual(Path(testfile).read_text(encoding='utf-8'),
                         Path(fixedfile).read_text(encoding='utf-8'))

    def test_identity_cross(self):
        testdir = os.path.join(self.unit_test_dir, '69 cross')
        # Do a build to generate a cross file where the host is this target
        self.init(testdir, extra_args=['-Dgenerate=true'])
        self.meson_cross_files = [os.path.join(self.builddir, "crossfile")]
        self.assertTrue(os.path.exists(self.meson_cross_files[0]))
        # Now verify that this is detected as cross
        self.new_builddir()
        self.init(testdir)

    def test_introspect_buildoptions_without_configured_build(self):
        testdir = os.path.join(self.unit_test_dir, '58 introspect buildoptions')
        testfile = os.path.join(testdir, 'meson.build')
        res_nb = self.introspect_directory(testfile, ['--buildoptions'] + self.meson_args)
        self.init(testdir, default_args=False)
        res_wb = self.introspect('--buildoptions')
        self.maxDiff = None
        # XXX: These now generate in a different order, is that okay?
        self.assertListEqual(sorted(res_nb, key=lambda x: x['name']), sorted(res_wb, key=lambda x: x['name']))

    def test_meson_configure_from_source_does_not_crash(self):
        testdir = os.path.join(self.unit_test_dir, '58 introspect buildoptions')
        self._run(self.mconf_command + [testdir])

    def test_introspect_buildoptions_cross_only(self):
        testdir = os.path.join(self.unit_test_dir, '82 cross only introspect')
        testfile = os.path.join(testdir, 'meson.build')
        res = self.introspect_directory(testfile, ['--buildoptions'] + self.meson_args)
        optnames = [o['name'] for o in res]
        self.assertIn('c_args', optnames)
        self.assertNotIn('build.c_args', optnames)

    def test_introspect_json_flat(self):
        testdir = os.path.join(self.unit_test_dir, '56 introspection')
        self.init(testdir, extra_args=['-Dlayout=flat'])
        infodir = os.path.join(self.builddir, 'meson-info')
        self.assertPathExists(infodir)

        with open(os.path.join(infodir, 'intro-targets.json'), encoding='utf-8') as fp:
            targets = json.load(fp)

        for i in targets:
            for out in i['filename']:
                assert os.path.relpath(out, self.builddir).startswith('meson-out')

    def test_introspect_json_dump(self):
        testdir = os.path.join(self.unit_test_dir, '56 introspection')
        self.init(testdir)
        infodir = os.path.join(self.builddir, 'meson-info')
        self.assertPathExists(infodir)

        def assertKeyTypes(key_type_list, obj, strict: bool = True):
            for i in key_type_list:
                if isinstance(i[1], (list, tuple)) and None in i[1]:
                    i = (i[0], tuple(x for x in i[1] if x is not None))
                    if i[0] not in obj or obj[i[0]] is None:
                        continue
                self.assertIn(i[0], obj)
                self.assertIsInstance(obj[i[0]], i[1])
            if strict:
                for k in obj.keys():
                    found = False
                    for i in key_type_list:
                        if k == i[0]:
                            found = True
                            break
                    self.assertTrue(found, f'Key "{k}" not in expected list')

        root_keylist = [
            ('benchmarks', list),
            ('buildoptions', list),
            ('buildsystem_files', list),
            ('compilers', dict),
            ('dependencies', list),
            ('install_plan', dict),
            ('installed', dict),
            ('machines', dict),
            ('projectinfo', dict),
            ('targets', list),
            ('tests', list),
        ]

        test_keylist = [
            ('cmd', list),
            ('env', dict),
            ('name', str),
            ('timeout', int),
            ('suite', list),
            ('is_parallel', bool),
            ('protocol', str),
            ('depends', list),
            ('workdir', (str, None)),
            ('priority', int),
            ('extra_paths', list),
        ]

        buildoptions_keylist = [
            ('name', str),
            ('section', str),
            ('type', str),
            ('description', str),
            ('machine', str),
            ('choices', (list, None)),
            ('value', (str, int, bool, list)),
        ]

        buildoptions_typelist = [
            ('combo', str, [('choices', list)]),
            ('string', str, []),
            ('boolean', bool, []),
            ('integer', int, []),
            ('array', list, []),
        ]

        buildoptions_sections = ['core', 'backend', 'base', 'compiler', 'directory', 'user', 'test']
        buildoptions_machines = ['any', 'build', 'host']

        dependencies_typelist = [
            ('name', str),
            ('type', str),
            ('version', str),
            ('compile_args', list),
            ('link_args', list),
            ('include_directories', list),
            ('sources', list),
            ('extra_files', list),
            ('dependencies', list),
            ('depends', list),
            ('meson_variables', list),
        ]

        targets_typelist = [
            ('name', str),
            ('id', str),
            ('type', str),
            ('defined_in', str),
            ('filename', list),
            ('build_by_default', bool),
            ('target_sources', list),
            ('extra_files', list),
            ('subproject', (str, None)),
            ('dependencies', list),
            ('depends', list),
            ('install_filename', (list, None)),
            ('installed', bool),
            ('vs_module_defs', (str, None)),
            ('win_subsystem', (str, None)),
        ]

        targets_sources_typelist = [
            ('language', str),
            ('compiler', list),
            ('parameters', list),
            ('sources', list),
            ('generated_sources', list),
            ('unity_sources', (list, None)),
        ]

        target_sources_linker_typelist = [
            ('linker', list),
            ('parameters', list),
        ]

        # First load all files
        res = {}
        for i in root_keylist:
            curr = os.path.join(infodir, 'intro-{}.json'.format(i[0]))
            self.assertPathExists(curr)
            with open(curr, encoding='utf-8') as fp:
                res[i[0]] = json.load(fp)

        assertKeyTypes(root_keylist, res)

        # Match target ids to input and output files for ease of reference
        src_to_id = {}
        out_to_id = {}
        name_to_out = {}
        for i in res['targets']:
            print(json.dump(i, sys.stdout))
            out_to_id.update({os.path.relpath(out, self.builddir): i['id']
                              for out in i['filename']})
            name_to_out.update({i['name']: i['filename']})
            for group in i['target_sources']:
                src_to_id.update({os.path.relpath(src, testdir): i['id']
                                  for src in group.get('sources', [])})

        # Check Tests and benchmarks
        tests_to_find = ['test case 1', 'test case 2', 'benchmark 1']
        deps_to_find = {'test case 1': [src_to_id['t1.cpp']],
                        'test case 2': [src_to_id['t2.cpp'], src_to_id['t3.cpp']],
                        'benchmark 1': [out_to_id['file2'], out_to_id['file3'], out_to_id['file4'], src_to_id['t3.cpp']]}
        for i in res['benchmarks'] + res['tests']:
            assertKeyTypes(test_keylist, i)
            if i['name'] in tests_to_find:
                tests_to_find.remove(i['name'])
            self.assertEqual(sorted(i['depends']),
                             sorted(deps_to_find[i['name']]))
        self.assertListEqual(tests_to_find, [])

        # Check buildoptions
        buildopts_to_find = {'cpp_std': 'c++11'}
        for i in res['buildoptions']:
            assertKeyTypes(buildoptions_keylist, i)
            valid_type = False
            for j in buildoptions_typelist:
                if i['type'] == j[0]:
                    self.assertIsInstance(i['value'], j[1])
                    assertKeyTypes(j[2], i, strict=False)
                    valid_type = True
                    break

            self.assertIn(i['section'], buildoptions_sections)
            self.assertIn(i['machine'], buildoptions_machines)
            self.assertTrue(valid_type)
            if i['name'] in buildopts_to_find:
                self.assertEqual(i['value'], buildopts_to_find[i['name']])
                buildopts_to_find.pop(i['name'], None)
        self.assertDictEqual(buildopts_to_find, {})

        # Check buildsystem_files
        bs_files = ['meson.build', 'meson_options.txt', 'sharedlib/meson.build', 'staticlib/meson.build']
        bs_files = [os.path.join(testdir, x) for x in bs_files]
        self.assertPathListEqual(list(sorted(res['buildsystem_files'])), list(sorted(bs_files)))

        # Check dependencies
        dependencies_to_find = ['threads']
        for i in res['dependencies']:
            assertKeyTypes(dependencies_typelist, i)
            if i['name'] in dependencies_to_find:
                dependencies_to_find.remove(i['name'])
        self.assertListEqual(dependencies_to_find, [])

        # Check projectinfo
        self.assertDictEqual(res['projectinfo'], {'version': '1.2.3', 'descriptive_name': 'introspection', 'subproject_dir': 'subprojects', 'subprojects': []})

        # Check targets
        targets_to_find = {
            'sharedTestLib': ('shared library', True, False, 'sharedlib/meson.build',
                              [os.path.join(testdir, 'sharedlib', 'shared.cpp')]),
            'staticTestLib': ('static library', True, False, 'staticlib/meson.build',
                              [os.path.join(testdir, 'staticlib', 'static.c')]),
            'custom target test 1': ('custom', False, False, 'meson.build',
                                     [os.path.join(testdir, 'cp.py')]),
            'custom target test 2': ('custom', False, False, 'meson.build',
                                     name_to_out['custom target test 1']),
            'test1': ('executable', True, True, 'meson.build',
                      [os.path.join(testdir, 't1.cpp')]),
            'test2': ('executable', True, False, 'meson.build',
                      [os.path.join(testdir, 't2.cpp')]),
            'test3': ('executable', True, False, 'meson.build',
                      [os.path.join(testdir, 't3.cpp')]),
            'custom target test 3': ('custom', False, False, 'meson.build',
                                     name_to_out['test3']),
        }
        for i in res['targets']:
            assertKeyTypes(targets_typelist, i)
            if i['name'] in targets_to_find:
                tgt = targets_to_find[i['name']]
                self.assertEqual(i['type'], tgt[0])
                self.assertEqual(i['build_by_default'], tgt[1])
                self.assertEqual(i['installed'], tgt[2])
                self.assertPathEqual(i['defined_in'], os.path.join(testdir, tgt[3]))
                targets_to_find.pop(i['name'], None)
            for j in i['target_sources']:
                if 'compiler' in j:
                    assertKeyTypes(targets_sources_typelist, j)
                    self.assertEqual(j['sources'], [os.path.normpath(f) for f in tgt[4]])
                else:
                    assertKeyTypes(target_sources_linker_typelist, j)
        self.assertDictEqual(targets_to_find, {})

    def test_introspect_file_dump_equals_all(self):
        testdir = os.path.join(self.unit_test_dir, '56 introspection')
        self.init(testdir)
        res_all = self.introspect('--all')
        res_file = {}

        root_keylist = [
            'benchmarks',
            'buildoptions',
            'buildsystem_files',
            'compilers',
            'dependencies',
            'installed',
            'install_plan',
            'machines',
            'projectinfo',
            'targets',
            'tests',
        ]

        infodir = os.path.join(self.builddir, 'meson-info')
        self.assertPathExists(infodir)
        for i in root_keylist:
            curr = os.path.join(infodir, f'intro-{i}.json')
            self.assertPathExists(curr)
            with open(curr, encoding='utf-8') as fp:
                res_file[i] = json.load(fp)

        self.assertEqual(res_all, res_file)

    def test_introspect_meson_info(self):
        testdir = os.path.join(self.unit_test_dir, '56 introspection')
        introfile = os.path.join(self.builddir, 'meson-info', 'meson-info.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, encoding='utf-8') as fp:
            res1 = json.load(fp)

        for i in ['meson_version', 'directories', 'introspection', 'build_files_updated', 'error']:
            self.assertIn(i, res1)

        self.assertEqual(res1['error'], False)
        self.assertEqual(res1['build_files_updated'], True)

    def test_introspect_config_update(self):
        testdir = os.path.join(self.unit_test_dir, '56 introspection')
        introfile = os.path.join(self.builddir, 'meson-info', 'intro-buildoptions.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, encoding='utf-8') as fp:
            res1 = json.load(fp)

        for i in res1:
            if i['name'] == 'cpp_std':
                i['value'] = 'c++14'
            if i['name'] == 'build.cpp_std':
                i['value'] = 'c++14'
            if i['name'] == 'buildtype':
                i['value'] = 'release'
            if i['name'] == 'optimization':
                i['value'] = '3'
            if i['name'] == 'debug':
                i['value'] = False

        self.setconf('-Dcpp_std=c++14')
        self.setconf('-Dbuildtype=release')

        with open(introfile, encoding='utf-8') as fp:
            res2 = json.load(fp)

        self.assertListEqual(res1, res2)

    def test_introspect_targets_from_source(self):
        testdir = os.path.join(self.unit_test_dir, '56 introspection')
        testfile = os.path.join(testdir, 'meson.build')
        introfile = os.path.join(self.builddir, 'meson-info', 'intro-targets.json')
        self.init(testdir)
        self.assertPathExists(introfile)
        with open(introfile, encoding='utf-8') as fp:
            res_wb = json.load(fp)

        res_nb = self.introspect_directory(testfile, ['--targets'] + self.meson_args)

        # Account for differences in output
        res_wb = [i for i in res_wb if i['type'] != 'custom']
        for i in res_wb:
            i['filename'] = [os.path.relpath(x, self.builddir) for x in i['filename']]
            for k in ('install_filename', 'dependencies', 'win_subsystem'):
                if k in i:
                    del
```