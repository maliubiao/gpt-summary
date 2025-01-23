Response:
The user wants a summary of the functionality of the `interpreter.py` file in the Frida project, specifically focusing on how it relates to reverse engineering, low-level concepts (like kernel and Android framework), logical reasoning, common user errors, and debugging.

**Plan:**

1. **High-level overview:** Briefly describe the role of `interpreter.py` in the Meson build system within the Frida context.
2. **Function-by-function analysis:** Go through the methods in the provided code snippet and explain their purpose.
3. **Reverse Engineering Relevance:**  Identify functions that directly or indirectly facilitate reverse engineering tasks.
4. **Low-Level Concepts:** Point out interactions with or implications for binary, Linux, Android kernel/framework aspects.
5. **Logical Reasoning:** Look for functions where the output depends on specific input conditions or involve conditional logic.
6. **User/Programming Errors:** Highlight common mistakes users might make when using the functions.
7. **Debugging Clues:** Explain how users might end up in this part of the code during the build process.
8. **Overall Summary:**  Concisely summarize the main functions of the `interpreter.py` file based on the above points.
这是 Frida 动态 Instrumentation 工具的源代码文件 `frida/releng/meson/mesonbuild/interpreter/interpreter.py` 的一部分。这个文件的主要功能是作为 Meson 构建系统的解释器，负责解析 `meson.build` 文件中的指令，并将其转换为构建系统的具体操作。

**功能归纳 (基于提供的代码片段):**

这段代码主要负责处理 `meson.build` 文件中定义的与构建目标和安装相关的函数，例如创建自定义目标、版本控制标签、子目录处理、安装文件等。

**具体功能列举和相关说明:**

1. **`func_vcs_tag`**:  从版本控制系统 (VCS) 获取标签信息并创建一个自定义目标。
    *   **与逆向的关系:** 在逆向工程中，了解软件的版本信息对于分析漏洞和行为至关重要。这个函数可以帮助在构建过程中将 VCS 标签嵌入到最终的二进制文件中，方便逆向分析人员识别版本。
    *   **二进制底层:** 该功能通过执行外部命令（VCS 命令）来获取信息，这些命令可能涉及到与底层文件系统和版本控制系统交互。
    *   **逻辑推理:** 假设输入一个需要版本控制标签的文件 `input.txt`，并指定输出文件为 `output.txt`，该函数会创建一个自定义构建目标，其命令会读取 `input.txt`，从中提取版本信息（通过 VCS 命令），然后将带有版本标签的信息写入 `output.txt`。如果没有找到 VCS 信息，则会使用 `fallback` 值。
    *   **用户错误:** 用户可能提供的 `command` 无效或无法执行，或者 `replace_string` 不存在于输入文件中。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `vcs_tag()` 函数时会触发此代码。例如：`vcs_tag(input: 'input.txt', output: 'output.txt')`。

2. **`func_subdir_done`**:  引发一个异常，表示当前子目录的处理已完成。
    *   **功能:** 用于提前退出子目录的构建过程。
    *   **与逆向的关系/二进制底层/内核框架:** 此函数本身不直接涉及逆向、二进制或底层知识。
    *   **逻辑推理:**  当 `meson.build` 文件中调用 `subdir_done()` 时，会抛出一个特定的异常，Meson 构建系统会捕获这个异常并停止处理当前的子目录。
    *   **用户错误:**  通常不会直接由用户调用出错。
    *   **调试线索:**  用户可能在某个子目录的 `meson.build` 文件中添加了 `subdir_done()`，希望在特定条件下跳过该子目录的后续构建步骤。

3. **`_validate_custom_target_outputs`**:  验证自定义目标的输出文件名是否合法。
    *   **功能:** 检查自定义目标的输出文件名中是否包含不允许的占位符，尤其是在有多个输入文件时。
    *   **与逆向的关系/二进制底层/内核框架:** 此函数本身不直接涉及逆向、二进制或底层知识。
    *   **逻辑推理:** 如果自定义目标有多个输入，并且输出文件名中包含 `@PLAINNAME@` 或 `@BASENAME@`，则会抛出异常，因为 Meson 无法确定应该使用哪个输入文件的名字。
    *   **用户错误:** 用户在定义 `custom_target` 时，对于有多个输入的情况，错误地在输出文件名中使用了 `@PLAINNAME@` 或 `@BASENAME@`。
    *   **调试线索:**  用户在 `meson.build` 文件中定义 `custom_target` 时，如果输出文件名不符合规范，会触发此验证函数。例如：`custom_target('my_target', input: ['a.c', 'b.c'], output: '@PLAINNAME@.o', command: ...) `。

4. **`func_custom_target`**:  定义一个自定义的构建目标。
    *   **与逆向的关系:** 自定义目标可以用于执行任何构建步骤，包括运行逆向分析工具、生成特定的数据文件供逆向分析使用等。例如，可以创建一个自定义目标来运行 `objdump` 或 `readelf` 来分析二进制文件。
    *   **二进制底层:**  `custom_target` 经常用于处理和生成二进制文件，例如编译源代码、链接目标文件、生成汇编代码等。
    *   **Linux/Android 内核及框架:**  在 Frida 的构建过程中，可能使用 `custom_target` 来编译内核模块、处理 Android 框架相关的资源文件等。
    *   **逻辑推理:** 假设定义一个自定义目标，输入文件是 `input.c`，输出文件是 `output.o`，命令是 `cc -c input.c -o output.o`。这个函数会创建一个构建规则，当需要生成 `output.o` 时，就会执行 `cc -c input.c -o output.o` 命令。
    *   **用户错误:**  用户可能提供的 `command` 无效、输入输出文件路径错误、依赖关系未正确声明等。
    *   **调试线索:** 用户在 `meson.build` 文件中定义 `custom_target()` 函数时会触发此代码。例如：`custom_target('compile_source', input: 'source.c', output: 'source.o', command: ['cc', '-c', 'source.c', '-o', 'source.o'])`。

5. **`func_run_target`**: 定义一个在构建完成后运行的目标。
    *   **与逆向的关系:** 可以创建一个运行目标来执行逆向分析脚本、启动调试器等。例如，可以定义一个运行目标，在构建完成后自动运行 GDB 并加载生成的二进制文件。
    *   **二进制底层:**  运行目标可以执行操作二进制文件的工具。
    *   **Linux/Android 内核及框架:** 可以用于在 Android 环境中启动特定的服务或执行测试。
    *   **逻辑推理:** 假设定义一个运行目标，名称是 `run_analyzer`，命令是 `python analyzer.py output.exe`。构建完成后，会执行 `python analyzer.py output.exe` 命令。
    *   **用户错误:** 提供的命令或脚本不存在或无法执行，依赖的目标未成功构建。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `run_target()` 函数时会触发此代码。例如：`run_target('run_tests', command: ['./test_program'])`。

6. **`func_alias_target`**: 定义一个目标别名，指向其他目标。
    *   **功能:**  方便用户使用一个名字引用多个目标。
    *   **与逆向的关系/二进制底层/内核框架:** 此函数本身不直接涉及逆向、二进制或底层知识。
    *   **逻辑推理:**  定义一个别名 `all`，指向目标 `target1` 和 `target2`。当构建 `all` 时，实际上会构建 `target1` 和 `target2`。
    *   **用户错误:**  别名指向的目标不存在。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `alias_target()` 函数时会触发此代码。例如：`alias_target('my_alias', target1, target2)`。

7. **`func_generator`**: 定义一个生成器，用于根据输入文件生成其他文件。
    *   **与逆向的关系:**  可以用于生成辅助逆向分析的文件，例如根据头文件生成代码骨架，或者根据配置文件生成特定的数据结构。
    *   **二进制底层:** 生成器可能用于生成与二进制格式相关的文件。
    *   **逻辑推理:** 假设定义一个生成器，输入是 `input.xml`，输出规则是 `@BASENAME@.c`，命令是 `xml_to_c input.xml`。对于 `input.xml`，会生成 `input.c` 文件。
    *   **用户错误:**  输出规则不包含 `@BASENAME@` 或 `@PLAINNAME@`，导致无法确定输出文件名。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `generator()` 函数时会触发此代码。例如：`generator(my_generator, input: 'data.in', output: '@BASENAME@.out', arguments: ['data.in'])`。

8. **`func_benchmark` 和 `func_test`**: 定义性能测试和单元测试。
    *   **与逆向的关系:** 可以创建针对逆向工程工具或库的性能测试和单元测试。
    *   **二进制底层:** 测试可能涉及到执行和验证底层二进制代码的行为。
    *   **Linux/Android 内核及框架:** 可以用于测试与特定平台相关的代码。
    *   **逻辑推理:**  定义一个测试，运行可执行文件 `my_program` 并检查其退出代码和输出。
    *   **用户错误:**  测试名称重复，测试的可执行文件不存在。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `benchmark()` 或 `test()` 函数时会触发此代码。例如：`test('my_test', my_executable)`。

9. **`unpack_env_kwarg`**:  处理 `env` 关键字参数，将其转换为 `EnvironmentVariables` 对象。
    *   **功能:** 用于设置构建或运行目标的环境变量。
    *   **与逆向的关系:** 可以设置逆向分析工具运行时的环境变量。
    *   **二进制底层:** 环境变量可以影响程序的执行方式。
    *   **用户错误:** 提供的环境变量格式不正确。
    *   **调试线索:**  在调用任何接受 `env` 参数的函数时，例如 `custom_target` 或 `run_target`。

10. **`make_test`**:  创建一个 `Test` 对象。
    *   **功能:**  将测试的各种参数组合成一个测试对象。
    *   **与逆向的关系:** 用于定义逆向相关工具的测试。
    *   **二进制底层:**  测试对象可能包含执行二进制文件的信息。

11. **`add_test`**: 将创建的 `Test` 对象添加到构建系统的测试列表中。
    *   **功能:**  将测试注册到 Meson 构建系统中。

12. **`func_install_headers`**:  定义安装头文件的规则。
    *   **与逆向的关系:** 安装头文件方便其他程序或库引用，也方便逆向分析人员理解代码结构。
    *   **二进制底层:** 头文件通常定义了二进制接口。
    *   **用户错误:**  指定了不存在的头文件。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `install_headers()` 函数时会触发此代码。例如：`install_headers('myheader.h', subdir: 'include/myproject')`。

13. **`func_install_man`**: 定义安装 man 手册页的规则。
    *   **功能:** 安装程序的帮助文档。
    *   **与逆向的关系:**  man 手册可以提供程序的用法信息。
    *   **用户错误:**  man 文件扩展名不是 1-9 的数字。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `install_man()` 函数时会触发此代码。例如：`install_man('myapp.1')`。

14. **`func_install_emptydir`**: 定义安装空目录的规则。
    *   **功能:** 创建一个空的安装目录。
    *   **与逆向的关系/二进制底层/内核框架:** 此函数本身不直接涉及逆向、二进制或底层知识。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `install_emptydir()` 函数时会触发此代码。例如：`install_emptydir('my_empty_dir')`。

15. **`func_install_symlink`**: 定义安装符号链接的规则。
    *   **功能:**  创建一个指向特定位置的符号链接。
    *   **与逆向的关系:** 可以创建指向库文件或配置文件的符号链接。
    *   **用户错误:**  `pointing_to` 指向的位置不存在。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `install_symlink()` 函数时会触发此代码。例如：`install_symlink('mylib.so', pointing_to: 'libmylib.so.1', install_dir: '/usr/lib')`。

16. **`func_structured_sources`**: 定义结构化的源文件，用于组织源文件。
    *   **功能:**  允许将源文件组织成逻辑组。
    *   **与逆向的关系/二进制底层/内核框架:** 此函数本身不直接涉及逆向、二进制或底层知识。
    *   **用户错误:** 提供了无效的源文件类型。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `structured_sources()` 函数时会触发此代码。例如：`structured_sources(['src/file1.c', 'src/file2.c'], {'headers': 'include/header.h'})`。

17. **`func_subdir`**:  进入一个子目录并解析其 `meson.build` 文件。
    *   **功能:**  允许构建过程进入子目录。
    *   **与逆向的关系/二进制底层/内核框架:**  Frida 的构建过程可能包含多个子目录，每个子目录负责构建不同的组件。
    *   **逻辑推理:** 当 `meson.build` 文件中调用 `subdir('mysubdir')` 时，Meson 会进入 `mysubdir` 目录，并查找和解析该目录下的 `meson.build` 文件。
    *   **用户错误:**  子目录不存在，或者子目录中没有 `meson.build` 文件。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `subdir()` 函数时会触发此代码。例如：`subdir('src')`。

18. **`_warn_kwarg_install_mode_sticky`**:  检查 `install_mode` 参数中是否使用了 sticky bit，并发出警告。
    *   **功能:**  提醒用户 sticky bit 在文件安装中不起作用。
    *   **与逆向的关系/二进制底层/内核框架:**  与逆向、二进制或底层知识没有直接关系。

19. **`func_install_data`**: 定义安装数据文件的规则。
    *   **与逆向的关系:** 可以用于安装逆向分析工具所需的配置文件、数据文件等。
    *   **用户错误:**  `rename` 列表的长度与 `sources` 列表的长度不一致。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `install_data()` 函数时会触发此代码。例如：`install_data('config.ini', install_dir: '/etc/myapp')`。

20. **`install_data_impl`**:  实际执行安装数据文件的操作。
    *   **功能:** 将数据文件复制到安装目录。

21. **`func_install_subdir`**: 定义安装整个子目录的规则。
    *   **功能:** 将一个目录及其内容复制到安装位置。
    *   **与逆向的关系:** 可以用于安装包含逆向分析工具或脚本的目录。
    *   **用户错误:**  指定的子目录不存在。
    *   **调试线索:** 用户在 `meson.build` 文件中调用 `install_subdir()` 函数时会触发此代码。例如：`install_subdir('scripts', install_dir: '/opt/myapp')`。

**用户操作如何一步步到达这里 (作为调试线索):**

1. 用户修改了 Frida 项目的源代码，或者想要构建 Frida。
2. 用户在 Frida 项目的根目录下运行 `meson setup build` 命令来配置构建系统。
3. Meson 构建系统会读取顶层的 `meson.build` 文件。
4. 当 Meson 解析 `meson.build` 文件时，遇到诸如 `vcs_tag()`, `custom_target()`, `subdir()`, `install_headers()` 等函数调用时，就会调用 `interpreter.py` 文件中对应的 `func_xxx` 函数。
5. 例如，如果 `meson.build` 文件中包含了 `custom_target(..., command: ['my_compiler', ...])`，则 `func_custom_target` 函数会被调用，并进一步调用 `self.find_program_impl(['my_compiler'])` 来查找 `my_compiler` 的路径。
6. 如果在处理子目录时，`meson.build` 文件中调用了 `subdir('my_component')`，则 `func_subdir` 函数会被调用，然后 Meson 会继续解析 `my_component/meson.build` 文件。
7. 在安装阶段，如果 `meson.build` 文件中定义了 `install_headers(...)`，则 `func_install_headers` 函数会被调用，Meson 会将指定的头文件复制到安装目录。

总而言之，`interpreter.py` 文件是 Meson 构建系统的核心组成部分，负责解释构建描述文件中的指令，并将其转化为具体的构建操作。用户通过编写 `meson.build` 文件来定义项目的构建方式，而 `interpreter.py` 则负责理解这些定义并执行相应的操作。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
=True),
        MULTI_OUTPUT_KW,
        # Cannot use the COMMAND_KW because command is allowed to be empty
        KwargInfo(
            'command',
            ContainerTypeInfo(list, (str, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex, ExternalProgram, mesonlib.File)),
            listify=True,
            default=[],
        ),
        KwargInfo('fallback', (str, NoneType)),
        KwargInfo('replace_string', str, default='@VCS_TAG@'),
    )
    def func_vcs_tag(self, node: mparser.BaseNode, args: T.List['TYPE_var'], kwargs: 'kwtypes.VcsTag') -> build.CustomTarget:
        if kwargs['fallback'] is None:
            FeatureNew.single_use('Optional fallback in vcs_tag', '0.41.0', self.subproject, location=node)
        fallback = kwargs['fallback'] or self.project_version
        replace_string = kwargs['replace_string']
        regex_selector = '(.*)' # default regex selector for custom command: use complete output
        vcs_cmd = kwargs['command']
        source_dir = os.path.normpath(os.path.join(self.environment.get_source_dir(), self.subdir))
        if vcs_cmd:
            if isinstance(vcs_cmd[0], (str, mesonlib.File)):
                if isinstance(vcs_cmd[0], mesonlib.File):
                    FeatureNew.single_use('vcs_tag with file as the first argument', '0.62.0', self.subproject, location=node)
                maincmd = self.find_program_impl(vcs_cmd[0], required=False)
                if maincmd.found():
                    vcs_cmd[0] = maincmd
            else:
                FeatureNew.single_use('vcs_tag with custom_tgt, external_program, or exe as the first argument', '0.63.0', self.subproject, location=node)
        else:
            vcs = mesonlib.detect_vcs(source_dir)
            if vcs:
                mlog.log('Found {} repository at {}'.format(vcs['name'], vcs['wc_dir']))
                vcs_cmd = vcs['get_rev'].split()
                regex_selector = vcs['rev_regex']
            else:
                vcs_cmd = [' '] # executing this cmd will fail in vcstagger.py and force to use the fallback string
        # vcstagger.py parameters: infile, outfile, fallback, source_dir, replace_string, regex_selector, command...

        self._validate_custom_target_outputs(len(kwargs['input']) > 1, kwargs['output'], "vcs_tag")

        cmd = self.environment.get_build_command() + \
            ['--internal',
             'vcstagger',
             '@INPUT0@',
             '@OUTPUT0@',
             fallback,
             source_dir,
             replace_string,
             regex_selector] + vcs_cmd

        tg = build.CustomTarget(
            kwargs['output'][0],
            self.subdir,
            self.subproject,
            self.environment,
            cmd,
            self.source_strings_to_files(kwargs['input']),
            kwargs['output'],
            self.coredata.is_build_only,
            build_by_default=True,
            build_always_stale=True,
        )
        self.add_target(tg.name, tg)
        return tg

    @FeatureNew('subdir_done', '0.46.0')
    @noPosargs
    @noKwargs
    def func_subdir_done(self, node: mparser.BaseNode, args: TYPE_var, kwargs: TYPE_kwargs) -> T.NoReturn:
        raise SubdirDoneRequest()

    @staticmethod
    def _validate_custom_target_outputs(has_multi_in: bool, outputs: T.Iterable[str], name: str) -> None:
        """Checks for additional invalid values in a custom_target output.

        This cannot be done with typed_kwargs because it requires the number of
        inputs.
        """
        for out in outputs:
            if has_multi_in and ('@PLAINNAME@' in out or '@BASENAME@' in out):
                raise InvalidArguments(f'{name}: output cannot contain "@PLAINNAME@" or "@BASENAME@" '
                                       'when there is more than one input (we can\'t know which to use)')

    @typed_pos_args('custom_target', optargs=[str])
    @typed_kwargs(
        'custom_target',
        COMMAND_KW,
        CT_BUILD_ALWAYS,
        CT_BUILD_ALWAYS_STALE,
        CT_BUILD_BY_DEFAULT,
        CT_INPUT_KW,
        CT_INSTALL_DIR_KW,
        CT_INSTALL_TAG_KW,
        MULTI_OUTPUT_KW,
        DEPENDS_KW,
        DEPEND_FILES_KW,
        DEPFILE_KW,
        ENV_KW.evolve(since='0.57.0'),
        INSTALL_KW,
        INSTALL_MODE_KW.evolve(since='0.47.0'),
        KwargInfo('feed', bool, default=False, since='0.59.0'),
        KwargInfo('capture', bool, default=False),
        KwargInfo('console', bool, default=False, since='0.48.0'),
    )
    def func_custom_target(self, node: mparser.FunctionNode, args: T.Tuple[str],
                           kwargs: 'kwtypes.CustomTarget') -> build.CustomTarget:
        if kwargs['depfile'] and ('@BASENAME@' in kwargs['depfile'] or '@PLAINNAME@' in kwargs['depfile']):
            FeatureNew.single_use('substitutions in custom_target depfile', '0.47.0', self.subproject, location=node)
        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])

        # Don't mutate the kwargs

        build_by_default = kwargs['build_by_default']
        build_always_stale = kwargs['build_always_stale']
        # Remap build_always to build_by_default and build_always_stale
        if kwargs['build_always'] is not None and kwargs['build_always_stale'] is not None:
            raise InterpreterException('CustomTarget: "build_always" and "build_always_stale" are mutually exclusive')

        if build_by_default is None and kwargs['install']:
            build_by_default = True

        elif kwargs['build_always'] is not None:
            if build_by_default is None:
                build_by_default = kwargs['build_always']
            build_always_stale = kwargs['build_by_default']

        # These are nullable so that we can know whether they're explicitly
        # set or not. If they haven't been overwritten, set them to their true
        # default
        if build_by_default is None:
            build_by_default = False
        if build_always_stale is None:
            build_always_stale = False

        name = args[0]
        if name is None:
            # name will default to first output, but we cannot do that yet because
            # they could need substitutions (e.g. @BASENAME@) first. CustomTarget()
            # will take care of setting a proper default but name must be an empty
            # string in the meantime.
            FeatureNew.single_use('custom_target() with no name argument', '0.60.0', self.subproject, location=node)
            name = ''
        inputs = self.source_strings_to_files(kwargs['input'], strict=False)
        command = kwargs['command']
        if command and isinstance(command[0], str):
            command[0] = self.find_program_impl([command[0]])

        if len(inputs) > 1 and kwargs['feed']:
            raise InvalidArguments('custom_target: "feed" keyword argument can only be used with a single input')
        if len(kwargs['output']) > 1 and kwargs['capture']:
            raise InvalidArguments('custom_target: "capture" keyword argument can only be used with a single output')
        if kwargs['capture'] and kwargs['console']:
            raise InvalidArguments('custom_target: "capture" and "console" keyword arguments are mutually exclusive')
        for c in command:
            if kwargs['capture'] and isinstance(c, str) and '@OUTPUT@' in c:
                raise InvalidArguments('custom_target: "capture" keyword argument cannot be used with "@OUTPUT@"')
            if kwargs['feed'] and isinstance(c, str) and '@INPUT@' in c:
                raise InvalidArguments('custom_target: "feed" keyword argument cannot be used with "@INPUT@"')
        if kwargs['install'] and not kwargs['install_dir']:
            raise InvalidArguments('custom_target: "install_dir" keyword argument must be set when "install" is true.')
        if len(kwargs['install_dir']) > 1:
            FeatureNew.single_use('multiple install_dir for custom_target', '0.40.0', self.subproject, location=node)
        if len(kwargs['install_tag']) not in {0, 1, len(kwargs['output'])}:
            raise InvalidArguments('custom_target: install_tag argument must have 0 or 1 outputs, '
                                   'or the same number of elements as the output keyword argument. '
                                   f'(there are {len(kwargs["install_tag"])} install_tags, '
                                   f'and {len(kwargs["output"])} outputs)')

        for t in kwargs['output']:
            self.validate_forbidden_targets(t)
        self._validate_custom_target_outputs(len(inputs) > 1, kwargs['output'], "custom_target")

        tg = build.CustomTarget(
            name,
            self.subdir,
            self.subproject,
            self.environment,
            command,
            inputs,
            kwargs['output'],
            self.coredata.is_build_only,
            build_always_stale=build_always_stale,
            build_by_default=build_by_default,
            capture=kwargs['capture'],
            console=kwargs['console'],
            depend_files=kwargs['depend_files'],
            depfile=kwargs['depfile'],
            extra_depends=kwargs['depends'],
            env=kwargs['env'],
            feed=kwargs['feed'],
            install=kwargs['install'],
            install_dir=kwargs['install_dir'],
            install_mode=install_mode,
            install_tag=kwargs['install_tag'],
            backend=self.backend)
        self.add_target(tg.name, tg)
        return tg

    @typed_pos_args('run_target', str)
    @typed_kwargs(
        'run_target',
        COMMAND_KW,
        DEPENDS_KW,
        ENV_KW.evolve(since='0.57.0'),
    )
    def func_run_target(self, node: mparser.FunctionNode, args: T.Tuple[str],
                        kwargs: 'kwtypes.RunTarget') -> build.RunTarget:
        all_args = kwargs['command'].copy()

        for i in listify(all_args):
            if isinstance(i, ExternalProgram) and not i.found():
                raise InterpreterException(f'Tried to use non-existing executable {i.name!r}')
        if isinstance(all_args[0], str):
            all_args[0] = self.find_program_impl([all_args[0]])
        name = args[0]
        tg = build.RunTarget(name, all_args, kwargs['depends'], self.subdir, self.subproject, self.environment,
                             kwargs['env'])
        self.add_target(name, tg)
        return tg

    @FeatureNew('alias_target', '0.52.0')
    @typed_pos_args('alias_target', str, varargs=build.Target, min_varargs=1)
    @noKwargs
    def func_alias_target(self, node: mparser.BaseNode, args: T.Tuple[str, T.List[build.Target]],
                          kwargs: 'TYPE_kwargs') -> build.AliasTarget:
        name, deps = args
        if any(isinstance(d, build.RunTarget) for d in deps):
            FeatureNew.single_use('alias_target that depends on run_targets', '0.60.0', self.subproject)
        tg = build.AliasTarget(name, deps, self.subdir, self.subproject, self.environment)
        self.add_target(name, tg)
        return tg

    @typed_pos_args('generator', (build.Executable, ExternalProgram))
    @typed_kwargs(
        'generator',
        KwargInfo('arguments', ContainerTypeInfo(list, str, allow_empty=False), required=True, listify=True),
        KwargInfo('output', ContainerTypeInfo(list, str, allow_empty=False), required=True, listify=True),
        DEPFILE_KW,
        DEPENDS_KW,
        KwargInfo('capture', bool, default=False, since='0.43.0'),
    )
    def func_generator(self, node: mparser.FunctionNode,
                       args: T.Tuple[T.Union[build.Executable, ExternalProgram]],
                       kwargs: 'kwtypes.FuncGenerator') -> build.Generator:
        for rule in kwargs['output']:
            if '@BASENAME@' not in rule and '@PLAINNAME@' not in rule:
                raise InvalidArguments('Every element of "output" must contain @BASENAME@ or @PLAINNAME@.')
            if has_path_sep(rule):
                raise InvalidArguments('"output" must not contain a directory separator.')
        if len(kwargs['output']) > 1:
            for o in kwargs['output']:
                if '@OUTPUT@' in o:
                    raise InvalidArguments('Tried to use @OUTPUT@ in a rule with more than one output.')

        gen = build.Generator(args[0], **kwargs)
        self.generators.append(gen)
        return gen

    @typed_pos_args('benchmark', str, (build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex))
    @typed_kwargs('benchmark', *TEST_KWS)
    def func_benchmark(self, node: mparser.BaseNode,
                       args: T.Tuple[str, T.Union[build.Executable, build.Jar, ExternalProgram, mesonlib.File]],
                       kwargs: 'kwtypes.FuncBenchmark') -> None:
        self.add_test(node, args, kwargs, False)

    @typed_pos_args('test', str, (build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex))
    @typed_kwargs('test', *TEST_KWS, KwargInfo('is_parallel', bool, default=True))
    def func_test(self, node: mparser.BaseNode,
                  args: T.Tuple[str, T.Union[build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex]],
                  kwargs: 'kwtypes.FuncTest') -> None:
        self.add_test(node, args, kwargs, True)

    def unpack_env_kwarg(self, kwargs: T.Union[EnvironmentVariables, T.Dict[str, 'TYPE_var'], T.List['TYPE_var'], str]) -> EnvironmentVariables:
        envlist = kwargs.get('env')
        if envlist is None:
            return EnvironmentVariables()
        msg = ENV_KW.validator(envlist)
        if msg:
            raise InvalidArguments(f'"env": {msg}')
        return ENV_KW.convertor(envlist)

    def make_test(self, node: mparser.BaseNode,
                  args: T.Tuple[str, T.Union[build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex]],
                  kwargs: 'kwtypes.BaseTest') -> Test:
        name = args[0]
        if ':' in name:
            mlog.deprecation(f'":" is not allowed in test name "{name}", it has been replaced with "_"',
                             location=node)
            name = name.replace(':', '_')
        exe = args[1]
        if isinstance(exe, ExternalProgram):
            if not exe.found():
                raise InvalidArguments('Tried to use not-found external program as test exe')
        elif isinstance(exe, mesonlib.File):
            exe = self.find_program_impl([exe])
        elif isinstance(exe, build.CustomTarget):
            kwargs.setdefault('depends', []).append(exe)
        elif isinstance(exe, build.CustomTargetIndex):
            kwargs.setdefault('depends', []).append(exe.target)

        env = self.unpack_env_kwarg(kwargs)

        if kwargs['timeout'] <= 0:
            FeatureNew.single_use('test() timeout <= 0', '0.57.0', self.subproject, location=node)

        prj = self.subproject if self.is_subproject() else self.build.project_name

        suite: T.List[str] = []
        for s in kwargs['suite']:
            if s:
                s = ':' + s
            suite.append(prj.replace(' ', '_').replace(':', '_') + s)

        return Test(name,
                    prj,
                    suite,
                    exe,
                    kwargs['depends'],
                    kwargs.get('is_parallel', False),
                    kwargs['args'],
                    env,
                    kwargs['should_fail'],
                    kwargs['timeout'],
                    kwargs['workdir'],
                    kwargs['protocol'],
                    kwargs['priority'],
                    kwargs['verbose'])

    def add_test(self, node: mparser.BaseNode,
                 args: T.Tuple[str, T.Union[build.Executable, build.Jar, ExternalProgram, mesonlib.File, build.CustomTarget, build.CustomTargetIndex]],
                 kwargs: T.Dict[str, T.Any], is_base_test: bool):
        if isinstance(args[1], (build.CustomTarget, build.CustomTargetIndex)):
            FeatureNew.single_use('test with CustomTarget as command', '1.4.0', self.subproject)

        t = self.make_test(node, args, kwargs)
        if is_base_test:
            self.build.tests.append(t)
            mlog.debug('Adding test', mlog.bold(t.name, True))
        else:
            self.build.benchmarks.append(t)
            mlog.debug('Adding benchmark', mlog.bold(t.name, True))

    @typed_pos_args('install_headers', varargs=(str, mesonlib.File))
    @typed_kwargs(
        'install_headers',
        PRESERVE_PATH_KW,
        KwargInfo('subdir', (str, NoneType)),
        INSTALL_MODE_KW.evolve(since='0.47.0'),
        INSTALL_DIR_KW,
        INSTALL_FOLLOW_SYMLINKS,
    )
    def func_install_headers(self, node: mparser.BaseNode,
                             args: T.Tuple[T.List['mesonlib.FileOrString']],
                             kwargs: 'kwtypes.FuncInstallHeaders') -> build.Headers:
        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])
        source_files = self.source_strings_to_files(args[0])
        install_subdir = kwargs['subdir']
        if install_subdir is not None:
            if kwargs['install_dir'] is not None:
                raise InterpreterException('install_headers: cannot specify both "install_dir" and "subdir". Use only "install_dir".')
            if os.path.isabs(install_subdir):
                mlog.deprecation('Subdir keyword must not be an absolute path. This will be a hard error in the next release.')
        else:
            install_subdir = ''

        dirs = collections.defaultdict(list)
        ret_headers = []
        if kwargs['preserve_path']:
            for file in source_files:
                dirname = os.path.dirname(file.fname)
                dirs[dirname].append(file)
        else:
            dirs[''].extend(source_files)

        for childdir in dirs:
            h = build.Headers(dirs[childdir], os.path.join(install_subdir, childdir), kwargs['install_dir'],
                              install_mode, self.subproject,
                              follow_symlinks=kwargs['follow_symlinks'])
            ret_headers.append(h)
            self.build.headers.append(h)

        return ret_headers

    @typed_pos_args('install_man', varargs=(str, mesonlib.File))
    @typed_kwargs(
        'install_man',
        KwargInfo('locale', (str, NoneType), since='0.58.0'),
        INSTALL_MODE_KW.evolve(since='0.47.0'),
        INSTALL_DIR_KW,
    )
    def func_install_man(self, node: mparser.BaseNode,
                         args: T.Tuple[T.List['mesonlib.FileOrString']],
                         kwargs: 'kwtypes.FuncInstallMan') -> build.Man:
        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])
        # We just need to narrow this, because the input is limited to files and
        # Strings as inputs, so only Files will be returned
        sources = self.source_strings_to_files(args[0])
        for s in sources:
            try:
                num = int(s.rsplit('.', 1)[-1])
            except (IndexError, ValueError):
                num = 0
            if not 1 <= num <= 9:
                raise InvalidArguments('Man file must have a file extension of a number between 1 and 9')

        m = build.Man(sources, kwargs['install_dir'], install_mode,
                      self.subproject, kwargs['locale'])
        self.build.man.append(m)

        return m

    @FeatureNew('install_emptydir', '0.60.0')
    @typed_kwargs(
        'install_emptydir',
        INSTALL_MODE_KW,
        KwargInfo('install_tag', (str, NoneType), since='0.62.0')
    )
    def func_install_emptydir(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs) -> None:
        d = build.EmptyDir(args[0], kwargs['install_mode'], self.subproject, kwargs['install_tag'])
        self.build.emptydir.append(d)

        return d

    @FeatureNew('install_symlink', '0.61.0')
    @typed_pos_args('symlink_name', str)
    @typed_kwargs(
        'install_symlink',
        KwargInfo('pointing_to', str, required=True),
        KwargInfo('install_dir', str, required=True),
        INSTALL_TAG_KW,
    )
    def func_install_symlink(self, node: mparser.BaseNode,
                             args: T.Tuple[T.List[str]],
                             kwargs) -> build.SymlinkData:
        name = args[0] # Validation while creating the SymlinkData object
        target = kwargs['pointing_to']
        l = build.SymlinkData(target, name, kwargs['install_dir'],
                              self.subproject, kwargs['install_tag'])
        self.build.symlinks.append(l)
        return l

    @FeatureNew('structured_sources', '0.62.0')
    @typed_pos_args('structured_sources', object, optargs=[dict])
    @noKwargs
    @noArgsFlattening
    def func_structured_sources(
            self, node: mparser.BaseNode,
            args: T.Tuple[object, T.Optional[T.Dict[str, object]]],
            kwargs: 'TYPE_kwargs') -> build.StructuredSources:
        valid_types = (str, mesonlib.File, build.GeneratedList, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)
        sources: T.Dict[str, T.List[T.Union[mesonlib.File, 'build.GeneratedTypes']]] = collections.defaultdict(list)

        for arg in mesonlib.listify(args[0]):
            if not isinstance(arg, valid_types):
                raise InvalidArguments(f'structured_sources: type "{type(arg)}" is not valid')
            if isinstance(arg, str):
                arg = mesonlib.File.from_source_file(self.environment.source_dir, self.subdir, arg)
            sources[''].append(arg)
        if args[1]:
            if '' in args[1]:
                raise InvalidArguments('structured_sources: keys to dictionary argument may not be an empty string.')
            for k, v in args[1].items():
                for arg in mesonlib.listify(v):
                    if not isinstance(arg, valid_types):
                        raise InvalidArguments(f'structured_sources: type "{type(arg)}" is not valid')
                    if isinstance(arg, str):
                        arg = mesonlib.File.from_source_file(self.environment.source_dir, self.subdir, arg)
                    sources[k].append(arg)
        return build.StructuredSources(sources)

    @typed_pos_args('subdir', str)
    @typed_kwargs(
        'subdir',
        KwargInfo(
            'if_found',
            ContainerTypeInfo(list, object),
            validator=lambda a: 'Objects must have a found() method' if not all(hasattr(x, 'found') for x in a) else None,
            since='0.44.0',
            default=[],
            listify=True,
        ),
    )
    def func_subdir(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs: 'kwtypes.Subdir') -> None:
        mesonlib.check_direntry_issues(args)
        if '..' in args[0]:
            raise InvalidArguments('Subdir contains ..')
        if self.subdir == '' and args[0] == self.subproject_dir:
            raise InvalidArguments('Must not go into subprojects dir with subdir(), use subproject() instead.')
        if self.subdir == '' and args[0].startswith('meson-'):
            raise InvalidArguments('The "meson-" prefix is reserved and cannot be used for top-level subdir().')
        if args[0] == '':
            raise InvalidArguments("The argument given to subdir() is the empty string ''. This is prohibited.")
        for i in kwargs['if_found']:
            if not i.found():
                return

        prev_subdir = self.subdir
        subdir = os.path.join(prev_subdir, args[0])
        if os.path.isabs(subdir):
            raise InvalidArguments('Subdir argument must be a relative path.')
        absdir = os.path.join(self.environment.get_source_dir(), subdir)
        symlinkless_dir = os.path.realpath(absdir)
        build_file = os.path.join(symlinkless_dir, 'meson.build')
        if build_file in self.processed_buildfiles:
            raise InvalidArguments(f'Tried to enter directory "{subdir}", which has already been visited.')
        self.processed_buildfiles.add(build_file)
        self.subdir = subdir
        os.makedirs(self.absolute_builddir_path_for(subdir), exist_ok=True)
        buildfilename = os.path.join(self.subdir, environment.build_filename)
        self.build_def_files.add(buildfilename)
        absname = os.path.join(self.environment.get_source_dir(), buildfilename)
        if not os.path.isfile(absname):
            self.subdir = prev_subdir
            raise InterpreterException(f"Nonexistent build file '{buildfilename!s}'")
        with open(absname, encoding='utf-8') as f:
            code = f.read()
        assert isinstance(code, str)
        try:
            codeblock = mparser.Parser(code, absname).parse()
        except mesonlib.MesonException as me:
            me.file = absname
            raise me
        try:
            self.evaluate_codeblock(codeblock)
        except SubdirDoneRequest:
            pass
        self.subdir = prev_subdir

    # This is either ignored on basically any OS nowadays, or silently gets
    # ignored (Solaris) or triggers an "illegal operation" error (FreeBSD).
    # It was likely added "because it exists", but should never be used. In
    # theory it is useful for directories, but we never apply modes to
    # directories other than in install_emptydir.
    def _warn_kwarg_install_mode_sticky(self, mode: FileMode) -> None:
        if mode.perms > 0 and mode.perms & stat.S_ISVTX:
            mlog.deprecation('install_mode with the sticky bit on a file does not do anything and will '
                             'be ignored since Meson 0.64.0', location=self.current_node)
            perms = stat.filemode(mode.perms - stat.S_ISVTX)[1:]
            return FileMode(perms, mode.owner, mode.group)
        else:
            return mode

    @typed_pos_args('install_data', varargs=(str, mesonlib.File))
    @typed_kwargs(
        'install_data',
        KwargInfo('sources', ContainerTypeInfo(list, (str, mesonlib.File)), listify=True, default=[]),
        KwargInfo('rename', ContainerTypeInfo(list, str), default=[], listify=True, since='0.46.0'),
        INSTALL_MODE_KW.evolve(since='0.38.0'),
        INSTALL_TAG_KW.evolve(since='0.60.0'),
        INSTALL_DIR_KW,
        PRESERVE_PATH_KW.evolve(since='0.64.0'),
        INSTALL_FOLLOW_SYMLINKS,
    )
    def func_install_data(self, node: mparser.BaseNode,
                          args: T.Tuple[T.List['mesonlib.FileOrString']],
                          kwargs: 'kwtypes.FuncInstallData') -> build.Data:
        sources = self.source_strings_to_files(args[0] + kwargs['sources'])
        rename = kwargs['rename'] or None
        if rename:
            if len(rename) != len(sources):
                raise InvalidArguments(
                    '"rename" and "sources" argument lists must be the same length if "rename" is given. '
                    f'Rename has {len(rename)} elements and sources has {len(sources)}.')

        install_dir = kwargs['install_dir']
        if not install_dir:
            subdir = self.active_projectname
            install_dir = P_OBJ.OptionString(os.path.join(self.environment.get_datadir(), subdir), os.path.join('{datadir}', subdir))
            if self.is_subproject():
                FeatureNew.single_use('install_data() without install_dir inside of a subproject', '1.3.0', self.subproject,
                                      'This was broken and would install to the project name of the parent project instead',
                                      node)
            if kwargs['preserve_path']:
                FeatureNew.single_use('install_data() with preserve_path and without install_dir', '1.3.0', self.subproject,
                                      'This was broken and would not add the project name to the install path',
                                      node)

        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])
        return self.install_data_impl(sources, install_dir, install_mode, rename, kwargs['install_tag'],
                                      preserve_path=kwargs['preserve_path'],
                                      follow_symlinks=kwargs['follow_symlinks'])

    def install_data_impl(self, sources: T.List[mesonlib.File], install_dir: str,
                          install_mode: FileMode, rename: T.Optional[str],
                          tag: T.Optional[str],
                          install_data_type: T.Optional[str] = None,
                          preserve_path: bool = False,
                          follow_symlinks: T.Optional[bool] = None) -> build.Data:
        install_dir_name = install_dir.optname if isinstance(install_dir, P_OBJ.OptionString) else install_dir
        dirs = collections.defaultdict(list)
        if preserve_path:
            for file in sources:
                dirname = os.path.dirname(file.fname)
                dirs[dirname].append(file)
        else:
            dirs[''].extend(sources)

        ret_data = []
        for childdir, files in dirs.items():
            d = build.Data(files, os.path.join(install_dir, childdir), os.path.join(install_dir_name, childdir),
                           install_mode, self.subproject, rename, tag, install_data_type,
                           follow_symlinks)
            ret_data.append(d)

        self.build.data.extend(ret_data)
        return ret_data

    @typed_pos_args('install_subdir', str)
    @typed_kwargs(
        'install_subdir',
        KwargInfo('install_dir', str, required=True),
        KwargInfo('strip_directory', bool, default=False),
        KwargInfo('exclude_files', ContainerTypeInfo(list, str),
                  default=[], listify=True, since='0.42.0',
                  validator=lambda x: 'cannot be absolute' if any(os.path.isabs(d) for d in x) else None),
        KwargInfo('exclude_directories', ContainerTypeInfo(list, str),
                  default=[], listify=True, since='0.42.0',
                  validator=lambda x: 'cannot be absolute' if any(os.path.isabs(d) for d in x) else None),
        INSTALL_MODE_KW.evolve(since='0.38.0'),
        INSTALL_TAG_KW.evolve(since='0.60.0'),
        INSTALL_FOLLOW_SYMLINKS,
    )
    def func_install_subdir(self, node: mparser.BaseNode, args: T.Tuple[str],
                            kwargs: 'kwtypes.FuncInstallSubdir') -> build.InstallDir:
        exclude = (set(kwargs['exclude_files']), set(kwargs['exclude_directories']))

        srcdir = os.path.join(self.environment.source_dir, self.subdir, args[0])
        if not os.path.isdir(srcdir) or not any(os.listdir(srcdir)):
            FeatureNew.single_use('install_subdir with empty directory', '0.47.0', self.subproject, location=node)
            FeatureDeprecated.single_use('install_subdir with empty directory', '0.60.0', self.subproject,
                                         'It worked by accident and is buggy. Use install_emptydir instead.', node)
        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])

        idir_name = kwargs['install_dir']
        if isinstance(idir_name, P_OBJ.OptionString):
            idir_name = idir_name.optname

        idir = build.InstallDir(
            self.subdir,
            args[0],
            kwargs['install_dir'],
            idir_name,
            install_mode,
            exclude,
            kwargs['strip_directory'],
            self.subproject,
            install_tag=kwargs['install_tag'],
            follow_symlinks=kwargs['follow_symlinks'])
        self.build.install_dirs.append(idir)
        return idir

    @noPosargs
    @typed_kwargs(
        'configure_file',
        DEPFILE_KW.evolve(since='0.52.0'),
        INSTALL_MODE_KW.evolve(since='0.47.0,'),
        INSTALL_TAG_KW.evolve(since='0.60.0'),
        KwargInfo('capture', bool, default=False, since='0.41.0'),
        KwargInfo(
            'command',
            (ContainerTypeInfo(list, (build.Executable, ExternalProgram, compilers.Compiler, mesonlib.File, str), allow_empty=False), NoneType),
            listify=True,
        ),
        KwargInfo(
            'configuration',
            (ContainerTypeInfo(dict, (str, int, bool)), build.ConfigurationData, NoneType),
        ),
        KwargInfo(
            'copy', bool, default=False, since='0.47.0',
            deprecated='0.64.0', deprecated_message='Use fs.copyfile instead',
        ),
        KwargInfo('encoding', str, default='utf-8', since='0.47.0'),
        KwargInfo('format', str, default='meson', since='0.46.0',
                  validator=in_set_validator({'meson', 'cmake', 'cmake@'})),
        KwargInfo(
            'input',
            ContainerTypeInfo(list, (mesonlib.File, str)),
            listif
```