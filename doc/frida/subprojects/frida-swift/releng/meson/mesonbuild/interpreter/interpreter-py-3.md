Response:
The user wants a summary of the functionality of the provided Python code snippet. This code is part of the `interpreter.py` file within the `mesonbuild` project, which is a core component of the Meson build system. The code defines various functions that are called within the Meson build language to define build targets, installation rules, and other aspects of a software project.

Here's a breakdown of how to approach the request:

1. **Identify the Core Functions:**  Scan the code for function definitions (`def func_...`). Each of these functions represents a specific Meson build language command.

2. **Describe Each Function's Purpose:**  For each identified function, summarize its main goal based on its name, arguments, and keywords.

3. **Relate to Reverse Engineering (if applicable):** Consider if any of the functions have direct relevance to reverse engineering tasks. This might involve actions like generating files, running external commands, or manipulating binaries.

4. **Relate to Binary/Kernel Knowledge (if applicable):**  Think about which functions interact with the underlying system at a lower level. This could involve executing commands, handling file permissions, or interacting with the operating system's installation mechanisms.

5. **Analyze Logic and Provide Examples:** For functions that perform logical operations or transformations, create hypothetical input and output scenarios.

6. **Identify Common User Errors:** Based on the function's arguments and logic, anticipate common mistakes users might make when calling these functions in their `meson.build` files.

7. **Explain User Journey:** Describe how a user writing a `meson.build` file would end up triggering the execution of these functions.

8. **Group Functionality for Summarization:** Organize the individual function descriptions into broader categories to provide a concise overview of the file's purpose.
这是 `frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的第 4 部分，该文件是 Frida 动态 instrumentation 工具的源代码文件，它在 Meson 构建系统中负责解释和执行构建定义。基于提供的代码片段，可以归纳出以下功能：

**核心功能归纳 (基于提供的代码片段)：**

这部分代码主要定义了 Meson 构建系统中用于定义各种构建目标和安装规则的内置函数。它涵盖了从获取版本控制信息到定义自定义构建步骤、安装文件和目录等多种功能。

**具体功能列举及说明：**

1. **`func_vcs_tag`**:  用于获取版本控制系统（VCS）的标签信息，并将其写入到文件中。
    * **功能:**  从版本控制系统（如 Git）中提取当前版本标签，并将此标签替换到指定输入文件的特定字符串中，生成输出文件。如果没有找到版本控制信息，则使用预设的 fallback 值。
    * **与逆向方法的关系:**  在逆向工程中，了解目标软件的版本信息非常重要。`vcs_tag` 可以帮助在构建过程中将版本信息嵌入到可执行文件或库中，方便逆向分析时识别版本。
        * **举例:**  一个逆向工程师可能会检查一个二进制文件的特定位置，期望找到版本字符串，而这个字符串可能就是通过 `vcs_tag` 在构建时嵌入的。
    * **涉及二进制底层，Linux, Android 内核及框架的知识:**  此功能依赖于系统上安装的版本控制工具（如 `git`），并且需要在执行构建命令时能够访问到代码仓库。在 Android 环境中，构建系统可能需要在特定的路径或环境中找到这些工具。
    * **逻辑推理:**
        * **假设输入:** 一个包含 `@VCS_TAG@` 占位符的文本文件 `input.txt`，Git 仓库存在，当前分支标签为 `v1.0.0`。
        * **预期输出:** 一个名为 `output.txt` 的文件，其内容与 `input.txt` 相同，但 `@VCS_TAG@` 已被替换为 `v1.0.0`。
    * **用户或编程常见的使用错误:**
        * 用户忘记初始化 Git 仓库，导致 `vcs_tag` 无法找到版本信息。
        * 用户指定的 `replace_string` 在输入文件中不存在，导致替换失败。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `vcs_tag` 函数，指定了输入、输出文件等参数。当 Meson 执行到这一行时，会调用 `func_vcs_tag` 函数。

2. **`func_subdir_done`**:  用于提前结束当前子目录的构建过程。
    * **功能:**  当在子目录的 `meson.build` 文件中调用时，会立即停止该子目录的进一步处理，返回到父目录。
    * **与逆向方法的关系:**  间接相关。如果逆向目标的代码结构复杂，使用了多个子模块，了解构建系统如何处理子目录有助于理解代码的组织结构。
    * **逻辑推理:**  此函数不涉及复杂的逻辑推理，它的作用是控制构建流程。
    * **用户或编程常见的使用错误:**  错误地在不需要提前退出的地方调用 `subdir_done`，导致部分代码没有被构建。
    * **用户操作如何一步步到达这里:** 用户在子目录的 `meson.build` 文件中调用了 `subdir_done()`。

3. **`func_custom_target`**:  用于定义自定义的构建目标，允许执行任意命令。
    * **功能:**  允许用户定义执行任意命令的构建目标。可以指定输入文件、输出文件、依赖项、构建时机等。
    * **与逆向方法的关系:**  非常相关。逆向工程师经常需要执行自定义的脚本或工具来处理二进制文件，例如解压缩、反汇编、修改等。`custom_target` 可以用于集成这些步骤到构建流程中。
        * **举例:**  可以使用 `custom_target` 定义一个目标，该目标使用 `objdump` 命令反汇编一个编译好的二进制文件，并将反汇编结果保存到文件中。
    * **涉及二进制底层，Linux, Android 内核及框架的知识:**  自定义命令可以涉及到任何底层操作，例如调用 shell 命令、操作文件系统、执行特定平台的工具等。在 Android 环境中，可以执行与 Android SDK 相关的工具。
    * **逻辑推理:**
        * **假设输入:**  一个名为 `input.bin` 的二进制文件，一个执行 `objdump -d input.bin > output.asm` 的命令。
        * **预期输出:**  一个包含 `input.bin` 反汇编代码的 `output.asm` 文件。
    * **用户或编程常见的使用错误:**
        * 命令中使用的路径不正确。
        * 没有正确声明输入和输出文件，导致 Meson 无法跟踪依赖关系。
        * 自定义命令执行失败，但 Meson 没有正确处理错误。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `custom_target` 函数，指定了目标名称、执行的命令、输入输出文件等。

4. **`func_run_target`**: 用于定义一个在构建过程完成后执行的目标，通常用于运行测试或部署脚本。
    * **功能:**  定义一个可以执行任意命令的目标，但与 `custom_target` 不同，`run_target` 通常不在构建依赖图中，而是在构建完成后显式触发。
    * **与逆向方法的关系:**  可能相关。可以用于执行逆向分析工具或脚本，例如运行动态分析工具附加到目标进程。
        * **举例:**  可以定义一个 `run_target` 来启动 Frida 脚本附加到一个正在运行的应用程序。
    * **涉及二进制底层，Linux, Android 内核及框架的知识:**  执行的命令可以涉及底层操作，例如启动进程、设置环境变量等。
    * **逻辑推理:**
        * **假设输入:**  一个执行命令 `python analyze.py output.bin` 的 `run_target`，假设 `analyze.py` 分析 `output.bin` 文件。
        * **预期输出:**  执行 `analyze.py` 脚本，并根据脚本内容产生相应的输出。
    * **用户或编程常见的使用错误:**
        * 依赖项没有正确设置，导致 `run_target` 在需要的构建目标完成之前执行。
        * 执行的命令出错，但没有合适的错误处理。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `run_target` 函数，指定了目标名称和要执行的命令。

5. **`func_alias_target`**: 用于创建一个虚拟的目标，它可以依赖于其他目标，用于方便地触发一组构建操作。
    * **功能:**  创建一个别名目标，当构建此别名目标时，其依赖的所有目标也会被构建。
    * **与逆向方法的关系:**  可以用于创建一个包含多个逆向分析步骤的别名目标，方便一键执行。
        * **举例:**  创建一个名为 `reverse` 的别名目标，依赖于反汇编目标、字符串提取目标等。
    * **逻辑推理:**  此函数主要用于组织构建流程，不涉及复杂的逻辑推理。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `alias_target` 函数，指定了别名名称和依赖的目标。

6. **`func_generator`**: 用于定义一个生成器，可以根据输入文件生成多个输出文件。
    * **功能:**  定义一个生成器对象，该对象使用指定的程序和参数，根据一组输入文件生成一组输出文件。输出文件的名称可以使用占位符，如 `@BASENAME@`。
    * **与逆向方法的关系:**  可能相关。可以用于生成辅助逆向分析的文件，例如根据二进制文件生成符号表文件或调用图。
    * **涉及二进制底层，Linux, Android 内核及框架的知识:**  生成器执行的命令可以涉及到处理二进制文件或调用系统工具。
    * **逻辑推理:**
        * **假设输入:**  一个名为 `process.py` 的脚本，一个输入文件 `data.bin`，生成规则为 `@BASENAME@.processed`。
        * **预期输出:**  执行 `process.py data.bin`，生成一个名为 `data.processed` 的文件。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `generator` 函数，指定了生成器程序、参数和输出规则。

7. **`func_benchmark` 和 `func_test`**:  用于定义基准测试和单元测试。
    * **功能:**  定义可执行的测试或基准测试，并指定其属性，如依赖项、参数、超时时间等。
    * **与逆向方法的关系:**  间接相关。确保逆向分析工具的质量和性能，可以使用这些功能来定义测试用例。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `benchmark` 或 `test` 函数。

8. **`func_install_headers`**: 用于定义需要安装的头文件。
    * **功能:**  指定需要安装的头文件及其安装路径。
    * **与逆向方法的关系:**  在逆向分析库文件时，了解其头文件可以帮助理解库的接口和功能。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `install_headers` 函数。

9. **`func_install_man`**: 用于定义需要安装的 man 手册页。
    * **功能:**  指定需要安装的 man 手册页及其安装路径。
    * **与逆向方法的关系:**  提供关于程序或库的文档信息，有助于理解其使用方法。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `install_man` 函数。

10. **`func_install_emptydir`**: 用于定义需要创建的空目录。
    * **功能:**  指定需要在安装时创建的空目录。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `install_emptydir` 函数。

11. **`func_install_symlink`**: 用于定义需要创建的符号链接。
    * **功能:**  指定需要在安装时创建的符号链接及其指向的目标。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `install_symlink` 函数。

12. **`func_structured_sources`**: 用于组织具有特定结构的源文件。
    * **功能:**  将源文件组织成具有特定结构的集合，可以用于后续的构建步骤。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `structured_sources` 函数。

13. **`func_subdir`**:  用于进入子目录并处理其 `meson.build` 文件。
    * **功能:**  指示 Meson 处理指定的子目录中的 `meson.build` 文件。
    * **与逆向方法的关系:**  了解代码的组织结构。
    * **用户操作如何一步步到达这里:** Meson 在处理 `meson.build` 文件时遇到了 `subdir` 函数调用。

14. **`func_install_data`**: 用于定义需要安装的数据文件。
    * **功能:**  指定需要安装的数据文件及其安装路径。
    * **与逆向方法的关系:**  某些逆向工程可能需要处理与目标程序相关的数据文件。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `install_data` 函数。

15. **`func_install_subdir`**: 用于安装整个子目录的内容。
    * **功能:**  将指定的子目录及其内容安装到目标路径。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `install_subdir` 函数。

16. **`func_configure_file`**: 用于根据模板文件和配置数据生成配置文件。
    * **功能:**  根据输入模板文件和提供的配置数据，生成输出配置文件，支持多种格式的配置。
    * **与逆向方法的关系:**  可能用于生成逆向分析工具的配置文件。
    * **用户操作如何一步步到达这里:** 用户在 `meson.build` 文件中调用了 `configure_file` 函数。

总而言之，这段代码定义了 Meson 构建系统中用于声明构建目标、管理依赖关系、执行自定义命令以及定义安装规则的核心功能。它允许开发者以声明式的方式描述软件的构建过程，并提供了灵活的机制来集成各种构建步骤和工具。对于 Frida 这样的动态 instrumentation 工具，这些功能对于定义其构建过程至关重要，包括编译 Frida 的组件、生成配置文件、以及安装最终的工具和库。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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