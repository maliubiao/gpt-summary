Response:
The user wants a summary of the functionality of the provided Python code. The code seems to be part of the test suite for the `meson` build system, specifically testing how `meson` handles various configuration options and project settings.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Functionality:**  The file name `allplatformstests.py` and the presence of `self.init()`, `self.build()`, `self.setconf()`, and `self.introspect()` strongly suggest this is testing the configuration and building processes of `meson`. The tests are checking how `meson` behaves under different scenarios and with different options.

2. **Group Related Tests:**  The code is organized into test methods. Grouping these methods by their apparent purpose will make the summary more coherent. For instance, multiple tests deal with different aspects of command-line options.

3. **Analyze Individual Tests and Extract Key Actions:**  Go through each test method and determine the core action being tested. Examples:
    * `test_array_option`: Tests handling of array-type options.
    * `test_executable_names`: Tests how executable names are handled (suffixes).
    * `test_free_stringarray_setting`: Tests setting string array options.
    * `test_options_with_choices_changing`: Tests how `meson` reacts to changes in option choices.
    * `test_subproject_promotion`: Tests the `promote` command for subprojects.
    * `test_warning_location` and `test_error_location_path`: Tests how warnings and errors are reported with file paths.
    * `test_templates`: Tests the `meson init` command for creating project templates.
    * `test_command_line`:  A large test covering various command-line option scenarios.

4. **Identify Connections to Reverse Engineering, Binary/Kernel, and Logic:**
    * **Reverse Engineering:**  The tests related to executable names, library linking (`test_guessed_linker_dependencies`, `test_check_module_linking`), and compiler flags (`test_mixed_language_linker_check`) have direct relevance to reverse engineering as they deal with the output of the build process and how different components are linked together.
    * **Binary/Kernel:**  Tests involving executable suffixes, shared modules, and compiler-specific flags touch upon binary-level details. The `test_check_module_linking` with its mention of "shared module" points to concepts related to dynamic linking.
    * **Logic/Reasoning:** Tests involving option defaults, overrides, and the interaction of different configuration settings (like `test_command_line`) involve logical reasoning about how the build system should behave.

5. **Look for User/Programming Errors:** Tests that deliberately cause errors (`test_conflicting_d_dash_option`, sections of `test_command_line`) highlight common mistakes users might make when configuring `meson`.

6. **Infer User Steps to Reach the Code:**  The code is part of `meson`'s test suite. The user would be a developer working on `meson` or someone contributing to the project, running the test suite to verify changes or ensure existing functionality.

7. **Formulate the Summary:** Combine the extracted information into a concise summary, grouping related functionalities and highlighting the connections to reverse engineering, binary/kernel aspects, logic, and common user errors.

8. **Address the "Part 4 of 7" Instruction:** Explicitly state that the summary is for the specific file provided and acknowledge the context of it being part of a larger test suite.

9. **Refine and Organize:** Review the summary for clarity and organization, ensuring it directly answers the user's request. Use bullet points or numbered lists for better readability.
这是 `frida` 动态instrumentation 工具中 `meson` 构建系统的一部分测试代码，专门用于测试在各种操作系统平台上 `meson` 构建系统的行为。它的主要功能是 **验证 `meson` 构建系统在处理各种构建配置选项、项目设置和命令时的正确性**。

作为第4部分，它专注于测试 `meson` 构建系统的特定方面，与其他部分共同构成对 `meson` 功能的全面测试。

以下是更详细的功能列举，并根据你的要求进行了分类说明：

**功能归纳：**

该文件的主要功能是 **测试 `meson` 构建系统在各种场景下处理构建选项和项目配置的能力**。 它涵盖了从简单的选项设置到复杂的子项目管理和错误处理等多个方面。

**与逆向的方法的关系 (间接相关，主要测试构建基础设施):**

虽然这个文件本身不直接进行逆向操作，但它测试的 `meson` 构建系统是 `frida` 这样的逆向工具的基础设施。  `frida` 的构建依赖于 `meson` 来管理编译、链接等过程。因此，确保 `meson` 的正确性对于 `frida` 的可靠性至关重要。

* **举例说明:** 如果 `meson` 在处理链接库的选项时存在错误（例如，`test_guessed_linker_dependencies` 测试的场景），可能导致 `frida` 无法正确链接到其依赖的库，从而导致 `frida` 自身无法运行或功能异常。 逆向工程师在尝试使用 `frida` 时会遇到这些构建问题。

**涉及二进制底层，Linux, Android 内核及框架的知识 (间接相关):**

同样，这个文件本身并不直接操作二进制或内核，但它测试的 `meson` 构建系统需要理解这些底层概念。

* **举例说明:**
    * `test_executable_names` 测试了可执行文件的后缀(`.exe` 在 Windows 上)，这涉及到不同操作系统下二进制文件的命名约定。
    * `test_check_module_linking` 涉及到共享模块（shared module）的概念，这与动态链接库有关，是操作系统底层加载和链接二进制文件的机制。在 Linux 和 Android 上，这涉及到 `.so` 文件。
    *  `test_mixed_language_linker_check` 测试了不同语言的编译器如何链接，这涉及到二进制层面上的符号解析和库的依赖关系。

**逻辑推理 (测试用例设计本身包含逻辑):**

这些测试用例的设计本身就包含逻辑推理，以验证在特定输入下 `meson` 是否产生预期的输出或行为。

* **假设输入与输出:**
    * **假设输入:**  `meson.options.txt` 文件定义了一个名为 `list` 的数组选项，其默认值为空，并提供了 `['foo', 'bar', 'oink', 'boink']` 作为可选值。 用户在配置时通过 `-Dlist=`  传入一个空字符串。
    * **预期输出:**  `test_array_option` 断言 `meson` 正确解析了空字符串，并将 `list` 选项的值设置为空列表 `[]`。

    * **假设输入:**  在 `test_options_with_choices_changing` 中，`meson_options.txt` 文件被修改，`combo` 和 `array` 选项的可选值发生了变化。
    * **预期输出:**  `meson` 能够检测到这些变化，并将旧的配置值更新为新的默认值（如果旧值不再有效），或者保持旧值（如果仍然有效）。

**涉及用户或者编程常见的使用错误:**

部分测试用例模拟了用户可能犯的错误，以确保 `meson` 能够正确处理并给出合理的提示或报错。

* **举例说明:**
    * `test_conflicting_d_dash_option` 测试了用户在命令行中同时使用短选项 `-D` 和长选项 `--` 来设置同一个配置项的情况，这是用户常犯的配置错误。  预期的行为是 `meson` 报错。
    * `test_command_line` 中包含了多种用户可能错误的命令行使用方式，例如使用未知的选项、格式错误的选项等。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接运行这个测试文件。这个文件是 `frida` 开发团队或贡献者在开发和维护 `frida` 时运行的自动化测试套件的一部分。

1. **开发者修改了 `meson` 构建相关的代码:**  例如，修改了处理构建选项的逻辑。
2. **开发者运行 `frida` 的测试套件:**  这通常通过一个命令来触发，该命令会执行所有或部分的测试用例。
3. **`pytest` (或其他测试运行器) 执行 `allplatformstests.py`:**  测试运行器会加载并执行这个文件中的各个 `test_` 开头的方法。
4. **特定的测试方法被执行:** 例如，`test_array_option` 方法会被执行，它会模拟 `meson` 的初始化过程，并断言其行为是否符合预期。
5. **如果测试失败:**  开发者会查看测试输出，了解哪个断言失败，并根据失败的断言来定位 `meson` 代码中的问题。 这个测试文件提供了具体的场景和断言，帮助开发者缩小调试范围。

**第4部分功能归纳:**

总的来说，`frida/subprojects/frida-tools/releng/meson/unittests/allplatformstests.py` 文件的第4部分主要专注于 **测试 `meson` 构建系统在处理各种构建配置选项时的行为**，包括：

* **数组选项:**  验证如何设置、读取和处理数组类型的构建选项。
* **可执行文件名:** 测试在不同平台下可执行文件的命名约定。
* **自由格式的字符串数组:** 验证如何设置包含特殊字符的字符串数组选项。
* **选项可选值的变化:**  测试当构建选项的可选值发生变化时，`meson` 如何处理已有的配置。
* **构建选项的列出:**  测试 `meson` 是否正确列出更改过的构建选项。
* **子项目的提升 (promotion):**  测试 `meson promote` 命令的功能，用于将子项目提升到顶层项目。
* **警告和错误的位置信息:**  测试 `meson` 在报告警告和错误时是否包含正确的文件路径和行号。
* **不允许的关键字参数:**  测试 `meson` 是否能够检测到并拒绝在函数调用中使用未允许的关键字参数。
* **项目模板:** 测试 `meson init` 命令创建项目模板的功能。
* **编译器对象的运行命令:**  测试是否可以将编译器对象传递给 `run_command()` 函数。
* **相同目标名称在子项目中的处理 (扁平布局):** 测试在扁平布局下，不同子项目中同名目标是否会冲突。
* **文件锁 (flock):** 测试 `meson` 的文件锁机制是否正常工作。
* **共享模块的链接检查:** 测试链接到共享模块时是否会发出警告。
* **混合语言链接器检查:** 测试 `meson` 如何处理不同语言的链接器。
* **根据构建类型设置 NDEBUG 宏:** 测试根据构建类型 (`release` 或非 `release`) 自动设置 `NDEBUG` 宏的功能。
* **推断的链接器依赖:**  测试 `meson` 是否能够根据链接命令推断库的依赖关系。
* **冲突的命令行选项:**  测试当在命令行中提供冲突的选项时 `meson` 的行为。
* **命令行选项:**  一个综合性的测试，涵盖了各种命令行选项的使用场景，包括默认值、覆盖、错误处理等。
* **警告级别 0:** 测试将警告级别设置为 0 的情况。
* **子项目的功能检查使用情况:** 测试子项目的功能检查的版本兼容性。

总而言之，这个文件是确保 `frida` 的构建系统 (`meson`) 在各种情况下都能正确工作的关键组成部分，间接地保障了 `frida` 工具的可靠性。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共7部分，请归纳一下它的功能
```

### 源代码
```python
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
```