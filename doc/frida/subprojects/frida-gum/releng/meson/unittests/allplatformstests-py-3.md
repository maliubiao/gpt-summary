Response:
The user wants a summary of the functionality of the Python script `allplatformstests.py`. This script appears to be part of the test suite for the Frida dynamic instrumentation tool. I need to analyze the code and identify its key functionalities. The user also asked for specific examples related to reverse engineering, low-level concepts, logical reasoning, common user errors, and debugging.

Here's a breakdown of how to approach each request:

1. **List the functionalities:** I will go through each test function (`test_*`) and summarize its purpose. The setup and utility functions also contribute to the overall functionality.

2. **Relation to reverse engineering:** Frida is a reverse engineering tool. I will look for tests that validate features directly relevant to dynamic instrumentation and code manipulation. Examples might involve testing how Frida interacts with running processes or modifies their behavior.

3. **Binary/kernel/framework knowledge:** Some tests might touch upon how Frida interacts with the operating system at a lower level. I will look for tests related to executable formats, linking, or interactions with the underlying OS.

4. **Logical reasoning:** Tests involving option parsing, conditional logic within the build system, or dependency resolution could fall under this category. I will identify test functions that demonstrate such reasoning.

5. **Common user errors:**  Tests that check for invalid input, incorrect command-line arguments, or misconfigurations are relevant here.

6. **User operation leading to the code:**  This involves understanding how a user interacts with Frida and its build system to trigger the execution of these tests. It likely involves running the test suite.

7. **Summarize the functionality:** After analyzing the individual tests, I will provide a concise summary of the script's overall purpose.
这是 `frida/subprojects/frida-gum/releng/meson/unittests/allplatformstests.py` 文件的第 4 部分，主要功能是**测试 Frida 构建系统 (使用 Meson) 在各种平台上的功能和行为是否符合预期**。它包含了一系列的单元测试，涵盖了 Meson 构建系统的各种特性，以及 Frida 项目如何利用这些特性。

以下是该部分代码更详细的功能分解，并结合了用户提出的各种关联性：

**功能列举：**

* **测试数组选项的默认值和设置:** `test_array_option_empty_string` 测试当数组选项被设置为空字符串时的行为。
* **测试可执行文件名称:** `test_executable_names` 测试在构建过程中生成的可执行文件的命名规则，包括平台特定的后缀。
* **测试获取构建选项:** `opt_has` 是一个辅助方法，用于验证特定的构建选项是否被正确设置。
* **测试自由格式的字符串数组设置:** `test_free_stringarray_setting` 测试如何通过命令行设置自由格式的字符串数组选项。
* **处理 macOS CI 的时间延迟:** `mac_ci_delay` 是一个辅助方法，用于在 macOS CI 环境中引入必要的延迟，以确保文件系统操作的正确性。
* **测试选项的可用选项变化:** `test_options_with_choices_changing` 测试当选项（例如数组或组合框）的可用选项发生变化时，构建系统如何处理。
* **测试在构建选项中列出已更改的选项:** `test_options_listed_in_build_options` 测试当构建选项的值发生变化时，这些变化是否会在构建输出中正确地列出来。
* **测试子项目晋升:** `test_subproject_promotion` 和 `test_subproject_promotion_wrap` 测试将子项目从 `subprojects` 目录提升到项目根目录的功能。
* **测试警告信息的位置:** `test_warning_location` 测试构建过程中产生的警告信息是否包含正确的文件路径和行号。
* **测试错误信息的位置和路径:** `test_error_location_path` 测试构建过程中产生的错误信息是否包含正确的文件路径。
* **测试不允许的方法关键字参数:** `test_permitted_method_kwargs` 测试当 Meson 函数接收到不允许的关键字参数时，是否会产生正确的错误。
* **测试项目模板生成:** `test_templates` 测试使用 `meson init` 命令生成不同语言的项目模板的功能。
* **测试编译器运行命令:** `test_compiler_run_command` 测试是否可以将编译器对象传递给 `run_command()` 函数。
* **测试子项目中相同目标名称的扁平布局:** `test_identical_target_name_in_subproject_flat_layout` 测试在扁平布局下，不同子项目中相同名称的目标是否会冲突。
* **测试子目录中相同目标名称的扁平布局:** `test_identical_target_name_in_subdir_flat_layout` 测试在扁平布局下，不同子目录中相同名称的目标是否会冲突。
* **测试文件锁:** `test_flock` 测试构建目录锁的机制，以防止并发构建冲突。
* **测试模块链接检查:** `test_check_module_linking` 测试链接到共享模块时是否会发出警告。
* **测试混合语言链接器检查:** `test_mixed_language_linker_check` 测试混合语言项目中的链接器行为。
* **测试当 release 被禁用时 ndebug 的行为:** `test_ndebug_if_release_disabled` 测试当构建类型为 release 且 `b_ndebug` 设置为 `if-release` 时的行为。
* **测试当 release 被启用时 ndebug 的行为:** `test_ndebug_if_release_enabled` 测试当构建类型为非 release 且 `b_ndebug` 设置为 `if-release` 时的行为。
* **测试推测的链接器依赖:** `test_guessed_linker_dependencies` 测试 Meson 是否能根据最终的链接器命令行推测出库的依赖关系。
* **测试冲突的 -D 参数:** `test_conflicting_d_dash_option` 测试同时使用短选项 `-D` 和长选项 `--` 设置同一个选项时是否会报错。
* **测试相同选项设置多次:** `test_same_dash_option_twice`, `test_same_d_option_twice`, `test_same_project_d_option_twice`, `test_same_dash_option_twice_configure`, `test_same_d_option_twice_configure`, `test_same_project_d_option_twice_configure` 测试多次设置同一个选项时，最后一个设置是否生效。
* **测试命令行参数:** `test_command_line` 测试通过命令行参数配置构建系统的各种选项，包括默认值、覆盖以及错误处理。
* **测试警告级别 0:** `test_warning_level_0` 测试将警告级别设置为 0 的行为。
* **测试特性检查在子项目中的使用:** `test_feature_check_usage_subprojects` 测试在子项目中进行特性检查时的行为和警告信息。

**与逆向方法的关系及举例说明:**

Frida 是一个动态插桩工具，常用于逆向工程。这个测试文件虽然主要关注构建系统，但其目标是确保 Frida 本身的正确构建。以下是一些关联的例子：

* **可执行文件命名:** `test_executable_names` 确保 Frida 组件（如 frida-server）在不同平台上被正确命名，逆向工程师需要在特定目录下找到这些可执行文件。例如，在 Linux 上可能是 `frida-server`，在 Windows 上可能是 `frida-server.exe`。
* **构建选项:**  Frida 的构建可能包含一些与安全或调试相关的选项。例如，可能会有控制是否启用某些安全特性的构建选项。逆向工程师可能需要了解这些选项，以便构建出适合其分析环境的 Frida 版本。
* **子项目晋升:**  Frida 的结构可能包含多个子项目。`test_subproject_promotion` 确保了构建系统能够正确地管理和组织这些子项目，这有助于理解 Frida 的内部模块结构。
* **混合语言链接:** `test_mixed_language_linker_check` 保证了 Frida 在使用多种编程语言（如 C/C++）构建时，链接过程的正确性。这对于理解 Frida 的底层实现至关重要。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **可执行文件后缀:** `test_executable_names` 中涉及的 `exe_suffix` 变量反映了不同操作系统对可执行文件后缀的约定（例如 Windows 的 `.exe`）。这是底层操作系统知识的一部分。
* **链接器依赖:** `test_guessed_linker_dependencies` 测试 Meson 如何推断库依赖。这涉及到操作系统如何加载和链接动态库的知识，在 Linux 和 Android 中尤为重要。例如，在 Linux 中，链接器会查找 `-L` 指定的目录下的库文件。
* **文件锁:** `test_flock` 使用了文件锁，这是一种操作系统提供的同步机制，用于防止多个进程同时修改同一个文件，这在构建系统中很重要。
* **子项目和库:** Frida 的构建过程可能涉及到编译和链接动态库 (`.so` 在 Linux 上，`.dylib` 在 macOS 上，`.dll` 在 Windows 上)。测试子项目和链接器依赖的功能确保了这些库被正确构建和链接。
* **Android 框架:** 虽然这个特定的测试文件没有直接涉及 Android 内核或框架代码，但 Frida 作为一款动态插桩工具，经常被用于分析 Android 应用和框架。其构建系统的正确性是 Frida 能够正常运行在 Android 平台上的前提。

**逻辑推理及假设输入与输出:**

* **数组选项:** 在 `test_array_option_empty_string` 中，假设输入的命令行参数包含 `-Dlist=`，预期输出是构建选项 `list` 的值为空数组 `[]`。
* **选项可用选项变化:** 在 `test_options_with_choices_changing` 中，假设初始的 `meson_options.txt` 文件定义了 `combo` 选项的可用值为 `['a', 'b', 'c']`，并且用户配置了 `-Dcombo=c`。然后 `meson_options.txt` 被更新，`combo` 的可用值变为 `['b', 'c', 'd']`。预期输出是构建系统能够识别到可用选项的变化，并且保留用户之前的配置 `c`，即使 `a` 不再是有效选项。
* **相同选项设置多次:** 在 `test_same_dash_option_twice` 中，假设用户在命令行中使用了 `--bindir=foo --bindir=bar`。预期输出是最终的 `bindir` 构建选项的值为 `bar`，后一个设置覆盖了前一个。

**涉及用户或编程常见的使用错误及举例说明:**

* **未知的构建选项:** `test_command_line` 中测试了当用户在命令行中指定了未知的构建选项时，构建系统是否会报错。例如，`self.init(testdir, extra_args=['-Dbad=1', '-Dfoo=2', '-Dwrong_link_args=foo'])` 尝试设置一个名为 `bad` 的未知选项，预期会抛出错误。
* **格式错误的选项:** `test_command_line` 测试了当用户提供的选项格式错误时（例如缺少等号），构建系统是否会报错。例如，`self.init(testdir, extra_args=['-Dfoo'])` 尝试设置一个没有值的选项 `foo`，预期会抛出错误。
* **同时使用短选项和长选项:** `test_conflicting_d_dash_option` 测试了同时使用 `-D` 和 `--` 设置同一个选项时是否会报错，这是一种常见的用户错误。
* **多次设置同一选项但期望所有设置都生效:**  测试用例 `test_same_*_option_twice` 明确展示了 Meson 的行为是后设置的值覆盖之前的设置，这与一些用户可能期望的累加行为不同。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida:** 用户从 Frida 的源代码仓库中检出代码，并尝试使用 Meson 构建 Frida。
2. **配置构建系统:** 用户在 Frida 的源代码根目录下运行 `meson setup builddir` 或类似的命令来配置构建系统。这个过程会读取 `meson.build` 和 `meson_options.txt` 文件。
3. **Meson 执行测试:**  Frida 的构建系统配置中包含了运行单元测试的步骤。在构建过程中或者用户显式执行测试命令（例如 `meson test -C builddir`）时，Meson 会执行测试脚本。
4. **执行 `allplatformstests.py`:**  `allplatformstests.py` 是 Frida 测试套件的一部分，Meson 会执行这个 Python 脚本。
5. **运行特定的测试函数:**  脚本中的每个 `test_*` 函数都是一个独立的测试用例。Meson 会依次执行这些测试函数。
6. **测试失败时提供调试线索:** 如果某个测试函数失败，例如 `test_array_option_empty_string` 失败，这意味着当用户尝试通过命令行设置一个空的数组选项时，构建系统的行为可能不符合预期。这会给 Frida 的开发者提供调试线索，让他们去检查相关的 Meson 代码或者 Frida 的构建脚本。

**归纳一下它的功能（第 4 部分）：**

总而言之，`frida/subprojects/frida-gum/releng/meson/unittests/allplatformstests.py` 的第 4 部分主要负责测试 Frida 的构建系统在处理各种构建选项、子项目、警告和错误信息、以及与其他构建工具（如 Ninja）交互时的正确性。它验证了 Meson 构建系统的多个核心特性在 Frida 项目中的应用是否符合预期，并涵盖了用户可能遇到的常见配置场景和潜在错误。这些测试对于确保 Frida 能够在不同平台上正确构建至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/unittests/allplatformstests.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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