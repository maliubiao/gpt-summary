Response:
The user wants a summary of the functionality of the Python code provided. The code seems to be testing framework for Meson build system, specifically testing how Meson handles different configurations, options, subprojects, and errors.

Here is a breakdown of the code's functionalities:

1. **Option Handling:** Tests various ways Meson handles build options, including setting, overriding, and validating them.
2. **Subproject Management:** Tests functionalities related to Meson subprojects, like promoting them.
3. **Error and Warning Handling:**  Verifies that Meson correctly reports errors and warnings with accurate file locations.
4. **Template Generation:** Checks the `meson init` command for generating project templates for different languages.
5. **Compiler Interaction:** Tests the interaction with compilers, including running commands through the compiler object and checking for linker dependencies.
6. **Build System Features:** Tests specific Meson features like flat layout, locking, and handling of shared modules.
7. **Command-line Argument Parsing:**  Tests how Meson parses and handles command-line arguments, including conflicting arguments.
8. **Configuration Introspection:** Uses `meson introspect` to verify the configured build options.
9. **Build Process:** Executes `meson setup`, `meson compile`, and `meson install` to test the build process.
10. **Reconfiguration Detection:**  Verifies that Meson correctly detects when a reconfiguration is needed.

Now, I will go through each functionality and see if it relates to reverse engineering, binary manipulation, or kernel/framework knowledge. I will also look for logical reasoning, potential user errors, and how a user might reach this code in a debugging scenario.
这是 `frida/subprojects/frida-swift/releng/meson/unittests/allplatformstests.py` 文件的一部分，它是一个针对 Frida 动态 instrumentation 工具的单元测试文件，特别是关于 Meson 构建系统在所有平台上的行为。

**这段代码的主要功能是测试 Meson 构建系统在处理各种配置选项和场景时的正确性。** 它可以被归纳为以下几个方面：

1. **测试数组选项的处理:**  测试如何设置和获取数组类型的构建选项，包括默认值和允许的选择。
2. **测试可执行文件命名:** 验证 Meson 能否正确处理不同后缀的可执行文件，并在指定目标名称时进行编译。
3. **测试构建选项的内省:** 使用 `meson introspect` 命令来检查构建选项的值是否被正确设置。
4. **测试自由字符串数组选项的设置:**  验证可以设置包含逗号的字符串数组类型的构建选项。
5. **测试选项选择的动态变化:**  测试当构建选项的可用选项发生变化时，Meson 是否能正确检测并更新配置，以及如何处理旧的选项值。
6. **测试构建选项的列表显示:** 验证在构建输出中是否正确列出了已更改的构建选项。
7. **测试子项目提升:**  测试将子项目从 `subprojects` 目录移动到项目顶层目录的功能。
8. **测试子项目提升（wrap 文件）:**  测试提升指定 wrap 文件的功能，尤其是在存在同名 wrap 文件时的处理。
9. **测试警告信息的位置:**  验证 Meson 生成的警告信息中，文件路径是否正确。
10. **测试错误信息的位置和路径:** 验证 Meson 生成的错误信息中，文件路径是否正确。
11. **测试不允许的关键字参数:**  验证 Meson 能否正确捕获并报告使用了不允许的关键字参数的错误。
12. **测试项目模板生成:** 验证 `meson init` 命令能否为不同的编程语言和目标类型生成正确的项目模板。
13. **测试编译器运行命令:**  验证可以将编译器对象传递给 `run_command()` 函数。
14. **测试相同目标名称在子项目（扁平布局）中的处理:** 验证在扁平布局下，不同子项目中同名目标不会冲突。
15. **测试相同目标名称在子目录（扁平布局）中的处理:** 验证在扁平布局下，不同子目录中同名目标不会冲突。
16. **测试文件锁:** 验证 Meson 是否使用了文件锁来防止并发构建引起的问题。
17. **测试共享模块链接的警告:** 验证当链接到共享模块时，Meson 会发出警告（在非 macOS 系统上）。
18. **测试混合语言链接器检查:**  验证 Meson 能否正确处理混合语言项目的链接器检查。
19. **测试 `b_ndebug` 选项在不同构建类型下的行为:** 验证 `b_ndebug=if-release` 选项在 `release` 和非 `release` 构建类型下的行为。
20. **测试猜测的链接器依赖:** 验证 Meson 能否根据链接器命令行推断并添加库依赖。
21. **测试冲突的命令行选项:** 验证 Meson 能否检测并报告冲突的命令行选项。
22. **测试相同选项多次设置:** 验证 Meson 能否正确处理命令行或配置中多次设置相同选项的情况，并以最后一次设置为准。
23. **测试命令行选项:**  测试各种命令行选项的正确解析和应用，包括短选项、长选项、以及与 `-D` 选项的混合使用。
24. **测试警告级别 0:** 验证可以将警告级别设置为 0，抑制警告信息。
25. **测试特性检查在子项目中的使用:** 验证在子项目中，关于 Meson 特性版本的检查和警告是否正确。

**与逆向方法的关系举例说明：**

虽然这段代码本身是 Meson 构建系统的测试，与直接的逆向操作关系不大，但它测试了 Frida 的构建过程。Frida 作为一款动态 instrumentation 工具，在逆向工程中扮演着重要的角色。

* **例子：**  `test_executable_names` 测试确保 Frida 的构建过程能够生成可执行文件。在逆向过程中，我们可能需要 attach 到 Frida 构建出的可执行文件或使用其提供的库进行操作。如果构建过程有问题，逆向分析就无法顺利进行。
* **例子：**  `test_subproject_promotion` 测试了 Frida 子项目的管理。Frida 内部可能包含多个子模块，正确构建和组织这些子模块对于 Frida 的正常运行至关重要，这间接影响了逆向人员使用 Frida 的能力。

**涉及到二进制底层、Linux、Android 内核及框架的知识的举例说明：**

* **二进制底层：** `test_executable_names` 间接涉及到二进制底层，因为它测试了可执行文件的生成。可执行文件是二进制格式的，理解其结构对于逆向工程至关重要。`exe_suffix` 变量的使用也暗示了对不同平台可执行文件后缀的考虑，这与操作系统和二进制格式有关。
* **Linux：** 许多测试都在 Linux 环境下运行，例如涉及到文件路径、进程调用等操作。虽然代码本身不直接操作 Linux 内核，但它测试的是在 Linux 环境下构建 Frida 的过程，而 Frida 本身可以用来分析 Linux 系统和应用程序。
* **Android 内核及框架：** Frida 广泛应用于 Android 平台的逆向工程。尽管这段代码没有直接涉及 Android 特有的内核或框架知识，但它确保了 Frida 在构建阶段的正确性，这对于 Frida 在 Android 上的使用至关重要。Frida 能够 hook Android 应用程序的 Java 层和 Native 层，这需要对 Android 框架有一定的了解。

**逻辑推理的假设输入与输出：**

* **测试 `test_options_with_choices_changing`：**
    * **假设输入：**
        * `meson_options.1.txt` 定义了 `combo` 选项的 choices 为 `['a', 'b']`，默认值为 `a`，`array` 选项的 choices 为 `['a', 'b']`，默认值为 `a`。
        * `meson_options.2.txt` 定义了 `combo` 选项的 choices 为 `['b', 'c', 'd']`，默认值为 `b`，`array` 选项的 choices 为 `['b', 'c', 'd']`，默认值为 `b`。
        * 第一次初始化时，使用 `options1`。
        * 第二次初始化时，使用 `options2`，且不传递额外的命令行参数。
    * **预期输出：** `combo` 选项的值为 `b`，choices 为 `['b', 'c', 'd']`。`array` 选项的值为 `['b']`，choices 为 `['b', 'c', 'd']`。这是因为 Meson 检测到选项的 choices 发生了变化，会将旧的无效值更新为新的默认值。

* **测试 `test_options_listed_in_build_options`：**
    * **假设输入：**
        * `meson.build` 文件中定义了 `auto_features` 和 `optional` 两个选项，默认值都是 `auto`。
        * 第一次初始化时不传递额外的命令行参数。
        * 第二次初始化时传递 `-Dauto_features=disabled -Doptional=enabled`。
        * 使用 `setconf('-Doptional=disabled')` 修改配置。
    * **预期输出：**
        * 第一次初始化时，构建输出中不包含 `-Dauto_features=auto` 和 `-Doptional=auto`。
        * 第二次初始化时，构建输出中包含 `-Dauto_features=disabled` 和 `-Doptional=enabled`。
        * `setconf` 后的构建输出中包含 `-Dauto_features=disabled` 和 `-Doptional=disabled`，但不包含 `-Doptional=enabled`。

**涉及用户或编程常见的使用错误的举例说明：**

* **例子：** `test_permitted_method_kwargs` 测试了在 Meson 的函数调用中使用了不允许的关键字参数的情况。这是一个常见的编程错误，Meson 能够捕获并给出明确的错误提示。
* **例子：** `test_conflicting_d_dash_option`, `test_same_dash_option_twice`, `test_same_d_option_twice` 等测试用例，模拟了用户在命令行中传递冲突或重复的构建选项的情况，这是用户在使用构建系统时容易犯的错误。
* **例子：** `test_command_line` 中测试了 `-Dfoo` 这样的 malformed option，这是用户可能错误输入命令行参数的情况。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发 Frida 或其相关组件：**  开发者在修改 Frida 的 Swift 支持或其构建系统时，可能会需要运行这些单元测试来确保修改的正确性。
2. **遇到构建问题：** 当 Frida 的构建过程出现异常时，开发者可能会逐步调试构建脚本和 Meson 的配置。
3. **执行单元测试：** 为了隔离问题，开发者会运行特定的单元测试文件，例如 `allplatformstests.py`，来验证 Meson 在特定场景下的行为是否符合预期。
4. **查看测试代码：** 如果某个测试失败，开发者会查看该测试用例的代码，了解其测试的场景和预期结果。
5. **分析日志和错误信息：** 开发者会分析 Meson 的输出日志和单元测试的错误信息，来定位问题所在。例如，如果 `test_warning_location` 失败，开发者会检查 Meson 生成的警告信息中的文件路径是否正确。
6. **修改代码并重新测试：**  根据分析结果，开发者会修改 Frida 的构建脚本或 Meson 相关的代码，然后重新运行单元测试来验证修复是否有效。

**归纳一下它的功能（第4部分）：**

这段代码主要负责测试 Meson 构建系统在处理各种构建选项、子项目管理、错误和警告信息以及命令行参数时的正确性。它涵盖了选项的设置、内省、动态变化，子项目的提升，错误和警告信息的定位，以及对用户常见错误的使用场景进行验证。这是 Frida 构建系统测试套件的一部分，旨在确保 Frida 在不同平台上的可靠构建。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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