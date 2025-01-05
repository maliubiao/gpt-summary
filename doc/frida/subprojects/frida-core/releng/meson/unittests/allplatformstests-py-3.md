Response:
The user wants a summary of the functionalities present in the Python code snippet. I need to go through the code and identify the primary purposes of the tests defined in the `allplatformstests.py` file. These tests seem to focus on validating various aspects of the `meson` build system, particularly related to option handling, subprojects, and command-line arguments.

Here's a breakdown of the functionalities I can identify:

1. **Option Handling:**  Several tests focus on how `meson` handles different types of options (array, string, combo), including setting them via command-line arguments (`-D`, `--`), configuration files, and ensuring changes to option choices are detected.
2. **Executable Names:** Testing the generation of executable names and ensuring they can be targeted specifically during the build process.
3. **Subproject Management:** Tests related to promoting subprojects and their wrap files.
4. **Warning and Error Location:** Verifying that `meson` correctly reports the location of warnings and errors within the project files.
5. **Template Generation:** Testing the `meson init` command for generating project templates in various languages.
6. **Compiler Interaction:** Testing the ability to pass compiler objects to `run_command`.
7. **Target Name Collisions:** Checking for potential target name collisions in flat layout builds.
8. **Build Directory Locking:** Testing the locking mechanism to prevent concurrent access to the build directory.
9. **Module Linking Warnings:** Validating that warnings are issued for incorrect linking against shared modules.
10. **Mixed Language Linking:** Testing compiler checks for mixed-language projects.
11. **`b_ndebug` Option:** Testing the behavior of the `b_ndebug` option in different build types.
12. **Guessed Linker Dependencies:**  Verifying that `meson` can infer dependencies based on linker command lines.
13. **Command-Line Argument Parsing:** Testing the handling of various command-line arguments, including overriding options, handling unknown or malformed options, and setting subproject options.
14. **Warning Level Configuration:** Testing the functionality of the `warning_level` option.
15. **Feature Check Usage in Subprojects:**  Checking how feature requirements are handled in subprojects.

Now, I need to categorize these functionalities according to the user's specific requests: relationship with reverse engineering, interaction with binary/kernel/frameworks, logical reasoning, common user errors, and debugging.
这是 `frida` 动态instrumentation 工具的源代码文件 `frida/subprojects/frida-core/releng/meson/unittests/allplatformstests.py` 的一部分，它主要的功能是 **测试 `meson` 构建系统在各种平台上的行为和功能**。 由于 `frida` 使用 `meson` 作为其构建系统，这个文件通过编写各种测试用例来确保 `frida` 的构建过程能够正确地处理不同的配置和场景。

以下是该代码片段中体现的功能的详细说明，并结合你提出的问题进行分析：

**功能归纳：**

1. **测试数组类型的构建选项 (`test_array_option`)**: 验证 `meson` 是否能正确处理数组类型的构建选项，包括设置默认值、通过命令行指定值、以及限制选项的选择范围。
2. **测试可执行文件名的处理 (`test_executable_names`)**: 确保 `meson` 能正确生成和识别不同后缀的可执行文件名，并能在构建过程中针对特定名称的目标进行编译。
3. **测试自由字符串数组的设置 (`test_free_stringarray_setting`)**: 验证 `meson` 是否允许自由设置字符串数组类型的构建选项。
4. **测试构建选项的动态变化 (`test_options_with_choices_changing`)**:  检验当构建选项的可用值发生变化时，`meson` 是否能够正确地检测并更新这些选项，以及如何处理旧的、不再有效的值。
5. **测试构建选项在构建消息中的显示 (`test_options_listed_in_build_options`)**:  检查在 `meson` 的构建输出中，哪些构建选项会被列出来。
6. **测试子项目的提升 (`test_subproject_promotion`, `test_subproject_promotion_wrap`)**:  验证 `meson` 的子项目提升功能，即将子项目中的源代码或 wrap 文件移动到主项目中的能力。
7. **测试警告信息的位置 (`test_warning_location`)**:  确保 `meson` 能够准确地报告警告信息在源代码文件中的位置。
8. **测试错误信息的位置路径 (`test_error_location_path`)**:  确保 `meson` 能够在错误发生时，提供包含正确文件路径的错误信息。
9. **测试不允许的方法关键字参数 (`test_permitted_method_kwargs`)**:  验证 `meson` 是否能正确检测并报错使用了不允许的关键字参数的方法调用。
10. **测试项目模板的生成 (`test_templates`)**: 验证 `meson init` 命令是否能够为不同的编程语言和目标类型生成正确的项目模板。
11. **测试编译器运行命令 (`test_compiler_run_command`)**:  测试 `meson` 中是否允许将编译器对象传递给 `run_command()` 函数。
12. **测试扁平布局下相同目标名称的处理 (`test_identical_target_name_in_subproject_flat_layout`, `test_identical_target_name_in_subdir_flat_layout`)**: 验证在扁平布局的构建环境中，`meson` 是否能正确处理不同子项目或子目录中同名的构建目标。
13. **测试构建目录锁 (`test_flock`)**: 验证 `meson` 的构建目录锁机制是否正常工作，防止并发构建导致的问题。
14. **测试链接共享模块的警告 (`test_check_module_linking`)**:  检查当一个可执行文件链接到一个共享模块时，`meson` 是否会发出警告。
15. **测试混合语言链接器检查 (`test_mixed_language_linker_check`)**:  验证 `meson` 是否能够正确处理混合编程语言项目中的链接器检查。
16. **测试 `b_ndebug` 构建选项 (`test_ndebug_if_release_disabled`, `test_ndebug_if_release_enabled`)**:  验证在不同的构建类型下，`b_ndebug` 选项是否能正确设置 `NDEBUG` 宏。
17. **测试推测的链接器依赖 (`test_guessed_linker_dependencies`)**:  验证 `meson` 是否能根据最终的链接器命令行推断出库的依赖关系。
18. **测试冲突的命令行选项 (`test_conflicting_d_dash_option`)**:  检查 `meson` 是否能检测到冲突的命令行选项。
19. **测试重复的命令行选项 (`test_same_dash_option_twice`, `test_same_d_option_twice`, `test_same_project_d_option_twice`, `test_same_dash_option_twice_configure`, `test_same_d_option_twice_configure`, `test_same_project_d_option_twice_configure`)**: 验证当同一个选项被多次设置时，`meson` 如何处理。
20. **测试命令行参数的各种用法 (`test_command_line`)**:  测试 `meson` 对各种命令行参数的解析和处理，包括设置构建选项、处理未知或格式错误的选项等。
21. **测试警告级别 0 (`test_warning_level_0`)**:  验证警告级别设置为 0 时 `meson` 的行为。
22. **测试子项目中的功能检查 (`test_feature_check_usage_subprojects`)**: 验证在子项目中，`meson` 如何处理功能检查及其版本需求。

**与逆向方法的关联：**

这些测试本身并不直接涉及逆向工程的具体操作，但它们确保了 `frida` 这个用于动态 instrumentation 的工具能够被正确地构建出来。`frida` 的核心功能是运行时修改程序行为，这在逆向分析中非常关键。

**举例说明：**

假设你正在逆向一个 Android 应用，并希望使用 `frida` 来 hook 某个函数。为了使用 `frida`，你首先需要构建 `frida-core`。这个 `allplatformstests.py` 文件中的测试，例如测试可执行文件名的处理 (`test_executable_names`)，可以确保在构建 `frida` 时，最终生成的可执行文件（例如 `frida-server`）的名称是正确的，这对于你后续在 Android 设备上启动 `frida-server` 至关重要。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

虽然这个 Python 文件本身是高层次的测试代码，但其测试的目标是构建系统，而构建的产物是底层的二进制文件。

**举例说明：**

* **二进制底层：** 测试可执行文件名的处理，最终会影响到生成的二进制文件的名称和结构。
* **Linux：**  某些测试可能涉及到 Linux 特有的文件系统操作或构建约定，例如测试可执行文件后缀 (`exe_suffix`)。
* **Android 内核及框架：** 虽然这里没有直接测试 Android 特有的组件，但 `frida` 本身会运行在 Android 环境中并与内核及框架交互。确保 `frida` 能被正确构建，是其在 Android 上正常工作的前提。例如，`frida-server` 需要在 Android 系统上运行，并与内核进行交互来实现 hook 功能。

**逻辑推理（假设输入与输出）：**

以 `test_array_option` 为例：

* **假设输入：**
    * `meson.build` 文件中定义了一个名为 `list` 的数组选项，允许的值为 `['foo', 'bar', 'oink', 'boink']`。
    * 通过命令行传递 `-Dlist=` 参数。
* **预期输出：**
    * `meson` 配置成功。
    * 通过 `introspect` 命令获取的构建选项信息中，`list` 选项的值为空数组 `[]`。

以 `test_options_with_choices_changing` 为例：

* **假设输入：**
    * 初始 `meson_options.txt` 定义了 `combo` 选项的可用值为 `['a', 'b']`。
    * 构建后，修改 `meson_options.txt` 将 `combo` 选项的可用值更新为 `['b', 'c', 'd']`。
    * 再次构建。
* **预期输出：**
    * 第一次构建时，`combo` 选项的可用值为 `['a', 'b']`。
    * 第二次构建时，`meson` 检测到选项可用值的变化，`combo` 选项的可用值更新为 `['b', 'c', 'd']`，如果之前的配置值不再有效，则会使用默认值。

**涉及用户或编程常见的使用错误：**

* **命令行参数错误：** 例如 `test_conflicting_d_dash_option` 测试了同时使用 `-D` 和 `--` 设置同一个选项，这是用户可能犯的错误。
* **多次设置同一个选项：** `test_same_dash_option_twice` 等测试了用户在命令行中多次设置同一个选项的情况，`meson` 通常会采用最后一次设置的值。
* **使用了不允许的关键字参数：** `test_permitted_method_kwargs` 测试了用户在调用 `meson` 函数时使用了未定义的关键字参数的情况。

**用户操作是如何一步步到达这里的调试线索：**

1. **开发者修改了 `frida-core` 的构建配置或代码。**
2. **开发者运行 `meson` 构建系统来生成构建文件。**
3. **`meson` 在解析构建文件 (`meson.build`) 和选项文件 (`meson_options.txt`) 时，可能会遇到各种情况，例如：**
    * 用户通过命令行传递了构建选项。
    * 子项目需要被提升到主项目中。
    * 代码中存在警告或错误。
    * 需要生成项目模板。
    * 需要处理不同平台的可执行文件名。
4. **为了确保 `meson` 在这些情况下都能正常工作，开发者编写了单元测试，例如这个 `allplatformstests.py` 文件中的测试用例。**
5. **当测试失败时，开发者会查看测试代码和 `meson` 的输出来定位问题。** 例如，如果 `test_array_option` 失败，可能是因为 `meson` 没有正确解析数组类型的构建选项，开发者需要检查相关的 `meson` 代码。

**作为调试线索：**  如果 `frida` 的构建过程出现问题，例如某些构建选项没有生效，或者子项目提升失败，开发者可能会查看这个文件中的相关测试用例，看是否已有的测试覆盖了该场景，或者需要添加新的测试用例来重现和修复问题。

**总结 `allplatformstests.py` 的功能（针对提供的代码片段）：**

这个代码片段主要功能是 **验证 `meson` 构建系统在处理各种构建选项、子项目管理、以及错误和警告报告等方面的功能是否正常**。 它通过模拟各种用户操作和构建场景，确保 `frida` 的构建过程的稳定性和正确性。  这些测试覆盖了从基本的选项设置到更复杂的子项目管理和错误处理等多个方面。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共7部分，请归纳一下它的功能

"""
      if x.get('name') == 'list':
                    return x
            raise Exception(opts)

        expected = {
            'name': 'list',
            'description': 'list',
            'section': 'user',
            'type': 'array',
            'value': [],
            'choices': ['foo', 'bar', 'oink', 'boink'],
            'machine': 'any',
        }
        tdir = os.path.join(self.unit_test_dir, '19 array option')
        self.init(tdir, extra_args='-Dlist=')
        original = get_opt()
        self.assertDictEqual(original, expected)

    def test_executable_names(self):
        testdir = os.path.join(self.unit_test_dir, '121 executable suffix')
        self.init(testdir)
        self.build()
        exe1 = os.path.join(self.builddir, 'foo' + exe_suffix)
        exe2 = os.path.join(self.builddir, 'foo.bin')
        self.assertPathExists(exe1)
        self.assertPathExists(exe2)
        self.assertNotEqual(exe1, exe2)

        # Wipe and run the compile command against the target names
        self.init(testdir, extra_args=['--wipe'])
        self._run([*self.meson_command, 'compile', '-C', self.builddir, './foo'])
        self._run([*self.meson_command, 'compile', '-C', self.builddir, './foo.bin'])
        self.assertPathExists(exe1)
        self.assertPathExists(exe2)
        self.assertNotEqual(exe1, exe2)


    def opt_has(self, name, value):
        res = self.introspect('--buildoptions')
        found = False
        for i in res:
            if i['name'] == name:
                self.assertEqual(i['value'], value)
                found = True
                break
        self.assertTrue(found, "Array option not found in introspect data.")

    def test_free_stringarray_setting(self):
        testdir = os.path.join(self.common_test_dir, '40 options')
        self.init(testdir)
        self.opt_has('free_array_opt', [])
        self.setconf('-Dfree_array_opt=foo,bar', will_build=False)
        self.opt_has('free_array_opt', ['foo', 'bar'])
        self.setconf("-Dfree_array_opt=['a,b', 'c,d']", will_build=False)
        self.opt_has('free_array_opt', ['a,b', 'c,d'])

    # When running under Travis Mac CI, the file updates seem to happen
    # too fast so the timestamps do not get properly updated.
    # Call this method before file operations in appropriate places
    # to make things work.
    def mac_ci_delay(self):
        if is_osx() and is_ci():
            import time
            time.sleep(1)

    def test_options_with_choices_changing(self) -> None:
        """Detect when options like arrays or combos have their choices change."""
        testdir = Path(os.path.join(self.unit_test_dir, '83 change option choices'))
        options1 = str(testdir / 'meson_options.1.txt')
        options2 = str(testdir / 'meson_options.2.txt')

        # Test that old options are changed to the new defaults if they are not valid
        real_options = str(testdir / 'meson_options.txt')
        self.addCleanup(os.unlink, real_options)

        shutil.copy(options1, real_options)
        self.init(str(testdir))
        self.mac_ci_delay()
        shutil.copy(options2, real_options)

        self.build()
        opts = self.introspect('--buildoptions')
        for item in opts:
            if item['name'] == 'combo':
                self.assertEqual(item['value'], 'b')
                self.assertEqual(item['choices'], ['b', 'c', 'd'])
            elif item['name'] == 'array':
                self.assertEqual(item['value'], ['b'])
                self.assertEqual(item['choices'], ['b', 'c', 'd'])

        self.wipe()
        self.mac_ci_delay()

        # When the old options are valid they should remain
        shutil.copy(options1, real_options)
        self.init(str(testdir), extra_args=['-Dcombo=c', '-Darray=b,c'])
        self.mac_ci_delay()
        shutil.copy(options2, real_options)
        self.build()
        opts = self.introspect('--buildoptions')
        for item in opts:
            if item['name'] == 'combo':
                self.assertEqual(item['value'], 'c')
                self.assertEqual(item['choices'], ['b', 'c', 'd'])
            elif item['name'] == 'array':
                self.assertEqual(item['value'], ['b', 'c'])
                self.assertEqual(item['choices'], ['b', 'c', 'd'])

    def test_options_listed_in_build_options(self) -> None:
        """Detect when changed options become listed in build options."""
        testdir = os.path.join(self.unit_test_dir, '113 list build options')

        out = self.init(testdir)
        for line in out.splitlines():
            if line.startswith('Message: Build options:'):
                self.assertNotIn('-Dauto_features=auto', line)
                self.assertNotIn('-Doptional=auto', line)

        self.wipe()
        self.mac_ci_delay()

        out = self.init(testdir, extra_args=['-Dauto_features=disabled', '-Doptional=enabled'])
        for line in out.splitlines():
            if line.startswith('Message: Build options:'):
                self.assertIn('-Dauto_features=disabled', line)
                self.assertIn('-Doptional=enabled', line)

        self.setconf('-Doptional=disabled')
        out = self.build()
        for line in out.splitlines():
            if line.startswith('Message: Build options:'):
                self.assertIn('-Dauto_features=disabled', line)
                self.assertNotIn('-Doptional=enabled', line)
                self.assertIn('-Doptional=disabled', line)

    def test_subproject_promotion(self):
        testdir = os.path.join(self.unit_test_dir, '12 promote')
        workdir = os.path.join(self.builddir, 'work')
        shutil.copytree(testdir, workdir)
        spdir = os.path.join(workdir, 'subprojects')
        s3dir = os.path.join(spdir, 's3')
        scommondir = os.path.join(spdir, 'scommon')
        self.assertFalse(os.path.isdir(s3dir))
        subprocess.check_call(self.wrap_command + ['promote', 's3'],
                              cwd=workdir,
                              stdout=subprocess.DEVNULL)
        self.assertTrue(os.path.isdir(s3dir))
        self.assertFalse(os.path.isdir(scommondir))
        self.assertNotEqual(subprocess.call(self.wrap_command + ['promote', 'scommon'],
                                            cwd=workdir,
                                            stderr=subprocess.DEVNULL), 0)
        self.assertNotEqual(subprocess.call(self.wrap_command + ['promote', 'invalid/path/to/scommon'],
                                            cwd=workdir,
                                            stderr=subprocess.DEVNULL), 0)
        self.assertFalse(os.path.isdir(scommondir))
        subprocess.check_call(self.wrap_command + ['promote', 'subprojects/s2/subprojects/scommon'], cwd=workdir)
        self.assertTrue(os.path.isdir(scommondir))
        promoted_wrap = os.path.join(spdir, 'athing.wrap')
        self.assertFalse(os.path.isfile(promoted_wrap))
        subprocess.check_call(self.wrap_command + ['promote', 'athing'], cwd=workdir)
        self.assertTrue(os.path.isfile(promoted_wrap))
        self.new_builddir()  # Ensure builddir is not parent or workdir
        self.init(workdir)
        self.build()

    def test_subproject_promotion_wrap(self):
        testdir = os.path.join(self.unit_test_dir, '43 promote wrap')
        workdir = os.path.join(self.builddir, 'work')
        shutil.copytree(testdir, workdir)
        spdir = os.path.join(workdir, 'subprojects')

        ambiguous_wrap = os.path.join(spdir, 'ambiguous.wrap')
        self.assertNotEqual(subprocess.call(self.wrap_command + ['promote', 'ambiguous'],
                                            cwd=workdir,
                                            stderr=subprocess.DEVNULL), 0)
        self.assertFalse(os.path.isfile(ambiguous_wrap))
        subprocess.check_call(self.wrap_command + ['promote', 'subprojects/s2/subprojects/ambiguous.wrap'], cwd=workdir)
        self.assertTrue(os.path.isfile(ambiguous_wrap))

    def test_warning_location(self):
        tdir = os.path.join(self.unit_test_dir, '22 warning location')
        out = self.init(tdir)
        for expected in [
            r'meson.build:4: WARNING: Keyword argument "link_with" defined multiple times.',
            r'sub' + os.path.sep + r'meson.build:3: WARNING: Keyword argument "link_with" defined multiple times.',
            r'meson.build:6: WARNING: a warning of some sort',
            r'sub' + os.path.sep + r'meson.build:4: WARNING: subdir warning',
            r'meson.build:7: WARNING: Module SIMD has no backwards or forwards compatibility and might not exist in future releases.',
            r"meson.build:11: WARNING: The variable(s) 'MISSING' in the input file 'conf.in' are not present in the given configuration data.",
        ]:
            with self.subTest(expected):
                self.assertRegex(out, re.escape(expected))

        for wd in [
            self.src_root,
            self.builddir,
            os.getcwd(),
        ]:
            with self.subTest(wd):
                self.new_builddir()
                out = self.init(tdir, workdir=wd)
                expected = os.path.join(relpath(tdir, self.src_root), 'meson.build')
                relwd = relpath(self.src_root, wd)
                if relwd != '.':
                    expected = os.path.join(relwd, expected)
                    expected = '\n' + expected + ':'
                self.assertIn(expected, out)

    def test_error_location_path(self):
        '''Test locations in meson errors contain correct paths'''
        # this list contains errors from all the different steps in the
        # lexer/parser/interpreter we have tests for.
        for (t, f) in [
            ('10 out of bounds', 'meson.build'),
            ('18 wrong plusassign', 'meson.build'),
            ('56 bad option argument', 'meson_options.txt'),
            ('94 subdir parse error', os.path.join('subdir', 'meson.build')),
            ('95 invalid option file', 'meson_options.txt'),
        ]:
            tdir = os.path.join(self.src_root, 'test cases', 'failing', t)

            for wd in [
                self.src_root,
                self.builddir,
                os.getcwd(),
            ]:
                try:
                    self.init(tdir, workdir=wd)
                except subprocess.CalledProcessError as e:
                    expected = os.path.join('test cases', 'failing', t, f)
                    relwd = relpath(self.src_root, wd)
                    if relwd != '.':
                        expected = os.path.join(relwd, expected)
                    expected = '\n' + expected + ':'
                    self.assertIn(expected, e.output)
                else:
                    self.fail('configure unexpectedly succeeded')

    def test_permitted_method_kwargs(self):
        tdir = os.path.join(self.unit_test_dir, '25 non-permitted kwargs')
        with self.assertRaises(subprocess.CalledProcessError) as cm:
            self.init(tdir)
        self.assertIn('ERROR: compiler.has_header_symbol got unknown keyword arguments "prefixxx"', cm.exception.output)

    def test_templates(self):
        ninja = mesonbuild.environment.detect_ninja()
        if ninja is None:
            raise SkipTest('This test currently requires ninja. Fix this once "meson build" works.')

        langs = ['c']
        env = get_fake_env()
        for l in ['cpp', 'cs', 'd', 'java', 'cuda', 'fortran', 'objc', 'objcpp', 'rust', 'vala']:
            try:
                comp = detect_compiler_for(env, l, MachineChoice.HOST, True, '')
                with tempfile.TemporaryDirectory() as d:
                    comp.sanity_check(d, env)
                langs.append(l)
            except EnvironmentException:
                pass

        # The D template fails under mac CI and we don't know why.
        # Patches welcome
        if is_osx():
            langs = [l for l in langs if l != 'd']

        for lang in langs:
            for target_type in ('executable', 'library'):
                with self.subTest(f'Language: {lang}; type: {target_type}'):
                    if is_windows() and lang == 'fortran' and target_type == 'library':
                        # non-Gfortran Windows Fortran compilers do not do shared libraries in a Fortran standard way
                        # see "test cases/fortran/6 dynamic"
                        fc = detect_compiler_for(env, 'fortran', MachineChoice.HOST, True, '')
                        if fc.get_id() in {'intel-cl', 'pgi'}:
                            continue
                    # test empty directory
                    with tempfile.TemporaryDirectory() as tmpdir:
                        self._run(self.meson_command + ['init', '--language', lang, '--type', target_type],
                                  workdir=tmpdir)
                        self._run(self.setup_command + ['--backend=ninja', 'builddir'],
                                  workdir=tmpdir)
                        self._run(ninja,
                                  workdir=os.path.join(tmpdir, 'builddir'))
                # test directory with existing code file
                if lang in {'c', 'cpp', 'd'}:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        with open(os.path.join(tmpdir, 'foo.' + lang), 'w', encoding='utf-8') as f:
                            f.write('int main(void) {}')
                        self._run(self.meson_command + ['init', '-b'], workdir=tmpdir)
                elif lang in {'java'}:
                    with tempfile.TemporaryDirectory() as tmpdir:
                        with open(os.path.join(tmpdir, 'Foo.' + lang), 'w', encoding='utf-8') as f:
                            f.write('public class Foo { public static void main() {} }')
                        self._run(self.meson_command + ['init', '-b'], workdir=tmpdir)

    def test_compiler_run_command(self):
        '''
        The test checks that the compiler object can be passed to
        run_command().
        '''
        testdir = os.path.join(self.unit_test_dir, '24 compiler run_command')
        self.init(testdir)

    def test_identical_target_name_in_subproject_flat_layout(self):
        '''
        Test that identical targets in different subprojects do not collide
        if layout is flat.
        '''
        testdir = os.path.join(self.common_test_dir, '172 identical target name in subproject flat layout')
        self.init(testdir, extra_args=['--layout=flat'])
        self.build()

    def test_identical_target_name_in_subdir_flat_layout(self):
        '''
        Test that identical targets in different subdirs do not collide
        if layout is flat.
        '''
        testdir = os.path.join(self.common_test_dir, '181 same target name flat layout')
        self.init(testdir, extra_args=['--layout=flat'])
        self.build()

    def test_flock(self):
        exception_raised = False
        with tempfile.TemporaryDirectory() as tdir:
            os.mkdir(os.path.join(tdir, 'meson-private'))
            with BuildDirLock(tdir):
                try:
                    with BuildDirLock(tdir):
                        pass
                except MesonException:
                    exception_raised = True
        self.assertTrue(exception_raised, 'Double locking did not raise exception.')

    @skipIf(is_osx(), 'Test not applicable to OSX')
    def test_check_module_linking(self):
        """
        Test that link_with: a shared module issues a warning
        https://github.com/mesonbuild/meson/issues/2865
        (That an error is raised on OSX is exercised by test failing/78)
        """
        tdir = os.path.join(self.unit_test_dir, '30 shared_mod linking')
        out = self.init(tdir)
        msg = ('''DEPRECATION: target prog links against shared module mymod, which is incorrect.
             This will be an error in the future, so please use shared_library() for mymod instead.
             If shared_module() was used for mymod because it has references to undefined symbols,
             use shared_library() with `override_options: ['b_lundef=false']` instead.''')
        self.assertIn(msg, out)

    def test_mixed_language_linker_check(self):
        testdir = os.path.join(self.unit_test_dir, '97 compiler.links file arg')
        self.init(testdir)
        cmds = self.get_meson_log_compiler_checks()
        self.assertEqual(len(cmds), 5)
        # Path to the compilers, gleaned from cc.compiles tests
        cc = cmds[0][0]
        cxx = cmds[1][0]
        # cc.links
        self.assertEqual(cmds[2][0], cc)
        # cxx.links with C source
        self.assertEqual(cmds[3][0], cc)
        self.assertEqual(cmds[4][0], cxx)
        if self.backend is Backend.ninja:
            # updating the file to check causes a reconfigure
            #
            # only the ninja backend is competent enough to detect reconfigured
            # no-op builds without build targets
            self.utime(os.path.join(testdir, 'test.c'))
            self.assertReconfiguredBuildIsNoop()

    def test_ndebug_if_release_disabled(self):
        testdir = os.path.join(self.unit_test_dir, '28 ndebug if-release')
        self.init(testdir, extra_args=['--buildtype=release', '-Db_ndebug=if-release'])
        self.build()
        exe = os.path.join(self.builddir, 'main')
        self.assertEqual(b'NDEBUG=1', subprocess.check_output(exe).strip())

    def test_ndebug_if_release_enabled(self):
        testdir = os.path.join(self.unit_test_dir, '28 ndebug if-release')
        self.init(testdir, extra_args=['--buildtype=debugoptimized', '-Db_ndebug=if-release'])
        self.build()
        exe = os.path.join(self.builddir, 'main')
        self.assertEqual(b'NDEBUG=0', subprocess.check_output(exe).strip())

    def test_guessed_linker_dependencies(self):
        '''
        Test that meson adds dependencies for libraries based on the final
        linker command line.
        '''
        testdirbase = os.path.join(self.unit_test_dir, '29 guessed linker dependencies')
        testdirlib = os.path.join(testdirbase, 'lib')

        extra_args = None
        libdir_flags = ['-L']
        env = get_fake_env(testdirlib, self.builddir, self.prefix)
        if detect_c_compiler(env, MachineChoice.HOST).get_id() in {'msvc', 'clang-cl', 'intel-cl'}:
            # msvc-like compiler, also test it with msvc-specific flags
            libdir_flags += ['/LIBPATH:', '-LIBPATH:']
        else:
            # static libraries are not linkable with -l with msvc because meson installs them
            # as .a files which unix_args_to_native will not know as it expects libraries to use
            # .lib as extension. For a DLL the import library is installed as .lib. Thus for msvc
            # this tests needs to use shared libraries to test the path resolving logic in the
            # dependency generation code path.
            extra_args = ['--default-library', 'static']

        initial_builddir = self.builddir
        initial_installdir = self.installdir

        for libdir_flag in libdir_flags:
            # build library
            self.new_builddir()
            self.init(testdirlib, extra_args=extra_args)
            self.build()
            self.install()
            libbuilddir = self.builddir
            installdir = self.installdir
            libdir = os.path.join(self.installdir, self.prefix.lstrip('/').lstrip('\\'), 'lib')

            # build user of library
            self.new_builddir()
            # replace is needed because meson mangles platform paths passed via LDFLAGS
            self.init(os.path.join(testdirbase, 'exe'),
                      override_envvars={"LDFLAGS": '{}{}'.format(libdir_flag, libdir.replace('\\', '/'))})
            self.build()
            self.assertBuildIsNoop()

            # rebuild library
            exebuilddir = self.builddir
            self.installdir = installdir
            self.builddir = libbuilddir
            # Microsoft's compiler is quite smart about touching import libs on changes,
            # so ensure that there is actually a change in symbols.
            self.setconf('-Dmore_exports=true')
            self.build()
            self.install()
            # no ensure_backend_detects_changes needed because self.setconf did that already

            # assert user of library will be rebuild
            self.builddir = exebuilddir
            self.assertRebuiltTarget('app')

            # restore dirs for the next test case
            self.installdir = initial_builddir
            self.builddir = initial_installdir

    def test_conflicting_d_dash_option(self):
        testdir = os.path.join(self.unit_test_dir, '37 mixed command line args')
        with self.assertRaises((subprocess.CalledProcessError, RuntimeError)) as e:
            self.init(testdir, extra_args=['-Dbindir=foo', '--bindir=bar'])
            # Just to ensure that we caught the correct error
            self.assertIn('as both', e.stderr)

    def _test_same_option_twice(self, arg, args):
        testdir = os.path.join(self.unit_test_dir, '37 mixed command line args')
        self.init(testdir, extra_args=args)
        opts = self.introspect('--buildoptions')
        for item in opts:
            if item['name'] == arg:
                self.assertEqual(item['value'], 'bar')
                return
        raise Exception(f'Missing {arg} value?')

    def test_same_dash_option_twice(self):
        self._test_same_option_twice('bindir', ['--bindir=foo', '--bindir=bar'])

    def test_same_d_option_twice(self):
        self._test_same_option_twice('bindir', ['-Dbindir=foo', '-Dbindir=bar'])

    def test_same_project_d_option_twice(self):
        self._test_same_option_twice('one', ['-Done=foo', '-Done=bar'])

    def _test_same_option_twice_configure(self, arg, args):
        testdir = os.path.join(self.unit_test_dir, '37 mixed command line args')
        self.init(testdir)
        self.setconf(args)
        opts = self.introspect('--buildoptions')
        for item in opts:
            if item['name'] == arg:
                self.assertEqual(item['value'], 'bar')
                return
        raise Exception(f'Missing {arg} value?')

    def test_same_dash_option_twice_configure(self):
        self._test_same_option_twice_configure(
            'bindir', ['--bindir=foo', '--bindir=bar'])

    def test_same_d_option_twice_configure(self):
        self._test_same_option_twice_configure(
            'bindir', ['-Dbindir=foo', '-Dbindir=bar'])

    def test_same_project_d_option_twice_configure(self):
        self._test_same_option_twice_configure(
            'one', ['-Done=foo', '-Done=bar'])

    def test_command_line(self):
        testdir = os.path.join(self.unit_test_dir, '34 command line')

        # Verify default values when passing no args that affect the
        # configuration, and as a bonus, test that --profile-self works.
        out = self.init(testdir, extra_args=['--profile-self', '--fatal-meson-warnings'])
        self.assertNotIn('[default: true]', out)
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('default_library')].value, 'static')
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '1')
        self.assertEqual(obj.options[OptionKey('set_sub_opt')].value, True)
        self.assertEqual(obj.options[OptionKey('subp_opt', 'subp')].value, 'default3')
        self.wipe()

        # warning_level is special, it's --warnlevel instead of --warning-level
        # for historical reasons
        self.init(testdir, extra_args=['--warnlevel=2', '--fatal-meson-warnings'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '2')
        self.setconf('--warnlevel=3')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '3')
        self.setconf('--warnlevel=everything')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, 'everything')
        self.wipe()

        # But when using -D syntax, it should be 'warning_level'
        self.init(testdir, extra_args=['-Dwarning_level=2', '--fatal-meson-warnings'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '2')
        self.setconf('-Dwarning_level=3')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '3')
        self.setconf('-Dwarning_level=everything')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, 'everything')
        self.wipe()

        # Mixing --option and -Doption is forbidden
        with self.assertRaises((subprocess.CalledProcessError, RuntimeError)) as cm:
            self.init(testdir, extra_args=['--warnlevel=1', '-Dwarning_level=3'])
            if isinstance(cm.exception, subprocess.CalledProcessError):
                self.assertNotEqual(0, cm.exception.returncode)
                self.assertIn('as both', cm.exception.output)
            else:
                self.assertIn('as both', str(cm.exception))
        self.init(testdir)
        with self.assertRaises((subprocess.CalledProcessError, RuntimeError)) as cm:
            self.setconf(['--warnlevel=1', '-Dwarning_level=3'])
            if isinstance(cm.exception, subprocess.CalledProcessError):
                self.assertNotEqual(0, cm.exception.returncode)
                self.assertIn('as both', cm.exception.output)
            else:
                self.assertIn('as both', str(cm.exception))
        self.wipe()

        # --default-library should override default value from project()
        self.init(testdir, extra_args=['--default-library=both', '--fatal-meson-warnings'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('default_library')].value, 'both')
        self.setconf('--default-library=shared')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('default_library')].value, 'shared')
        if self.backend is Backend.ninja:
            # reconfigure target works only with ninja backend
            self.build('reconfigure')
            obj = mesonbuild.coredata.load(self.builddir)
            self.assertEqual(obj.options[OptionKey('default_library')].value, 'shared')
        self.wipe()

        # Should fail on unknown options
        with self.assertRaises((subprocess.CalledProcessError, RuntimeError)) as cm:
            self.init(testdir, extra_args=['-Dbad=1', '-Dfoo=2', '-Dwrong_link_args=foo'])
            self.assertNotEqual(0, cm.exception.returncode)
            self.assertIn(msg, cm.exception.output)
        self.wipe()

        # Should fail on malformed option
        msg = "Option 'foo' must have a value separated by equals sign."
        with self.assertRaises((subprocess.CalledProcessError, RuntimeError)) as cm:
            self.init(testdir, extra_args=['-Dfoo'])
            if isinstance(cm.exception, subprocess.CalledProcessError):
                self.assertNotEqual(0, cm.exception.returncode)
                self.assertIn(msg, cm.exception.output)
            else:
                self.assertIn(msg, str(cm.exception))
        self.init(testdir)
        with self.assertRaises((subprocess.CalledProcessError, RuntimeError)) as cm:
            self.setconf('-Dfoo')
            if isinstance(cm.exception, subprocess.CalledProcessError):
                self.assertNotEqual(0, cm.exception.returncode)
                self.assertIn(msg, cm.exception.output)
            else:
                self.assertIn(msg, str(cm.exception))
        self.wipe()

        # It is not an error to set wrong option for unknown subprojects or
        # language because we don't have control on which one will be selected.
        self.init(testdir, extra_args=['-Dc_wrong=1', '-Dwrong:bad=1'])
        self.wipe()

        # Test we can set subproject option
        self.init(testdir, extra_args=['-Dsubp:subp_opt=foo', '--fatal-meson-warnings'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('subp_opt', 'subp')].value, 'foo')
        self.wipe()

        # c_args value should be parsed with split_args
        self.init(testdir, extra_args=['-Dc_args=-Dfoo -Dbar "-Dthird=one two"', '--fatal-meson-warnings'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('args', lang='c')].value, ['-Dfoo', '-Dbar', '-Dthird=one two'])

        self.setconf('-Dc_args="foo bar" one two')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('args', lang='c')].value, ['foo bar', 'one', 'two'])
        self.wipe()

        self.init(testdir, extra_args=['-Dset_percent_opt=myoption%', '--fatal-meson-warnings'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('set_percent_opt')].value, 'myoption%')
        self.wipe()

        # Setting a 2nd time the same option should override the first value
        try:
            self.init(testdir, extra_args=['--bindir=foo', '--bindir=bar',
                                           '-Dbuildtype=plain', '-Dbuildtype=release',
                                           '-Db_sanitize=address', '-Db_sanitize=thread',
                                           '-Dc_args=-Dfoo', '-Dc_args=-Dbar',
                                           '-Db_lundef=false', '--fatal-meson-warnings'])
            obj = mesonbuild.coredata.load(self.builddir)
            self.assertEqual(obj.options[OptionKey('bindir')].value, 'bar')
            self.assertEqual(obj.options[OptionKey('buildtype')].value, 'release')
            self.assertEqual(obj.options[OptionKey('b_sanitize')].value, 'thread')
            self.assertEqual(obj.options[OptionKey('args', lang='c')].value, ['-Dbar'])
            self.setconf(['--bindir=bar', '--bindir=foo',
                          '-Dbuildtype=release', '-Dbuildtype=plain',
                          '-Db_sanitize=thread', '-Db_sanitize=address',
                          '-Dc_args=-Dbar', '-Dc_args=-Dfoo'])
            obj = mesonbuild.coredata.load(self.builddir)
            self.assertEqual(obj.options[OptionKey('bindir')].value, 'foo')
            self.assertEqual(obj.options[OptionKey('buildtype')].value, 'plain')
            self.assertEqual(obj.options[OptionKey('b_sanitize')].value, 'address')
            self.assertEqual(obj.options[OptionKey('args', lang='c')].value, ['-Dfoo'])
            self.wipe()
        except KeyError:
            # Ignore KeyError, it happens on CI for compilers that does not
            # support b_sanitize. We have to test with a base option because
            # they used to fail this test with Meson 0.46 an earlier versions.
            pass

    def test_warning_level_0(self):
        testdir = os.path.join(self.common_test_dir, '207 warning level 0')

        # Verify default values when passing no args
        self.init(testdir)
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '0')
        self.wipe()

        # verify we can override w/ --warnlevel
        self.init(testdir, extra_args=['--warnlevel=1'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '1')
        self.setconf('--warnlevel=0')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '0')
        self.wipe()

        # verify we can override w/ -Dwarning_level
        self.init(testdir, extra_args=['-Dwarning_level=1'])
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '1')
        self.setconf('-Dwarning_level=0')
        obj = mesonbuild.coredata.load(self.builddir)
        self.assertEqual(obj.options[OptionKey('warning_level')].value, '0')
        self.wipe()

    def test_feature_check_usage_subprojects(self):
        testdir = os.path.join(self.unit_test_dir, '40 featurenew subprojects')
        out = self.init(testdir)
        # Parent project warns correctly
        self.assertRegex(out, "WARNING: Project targets '>=0.45'.*'0.47.0': dict")
        # Subprojects warn correctly
        self.assertRegex(out, r"foo\| .*WARNING: Project targets '>=0.40'.*'0.44.0': disabler")
        self.assertRegex(out, r"baz\
"""


```