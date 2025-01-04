Response:
The user wants to understand the functionality of the provided Python code snippet from the `interpreter.py` file within the Frida project. This file seems to be part of Meson's build system integration for Frida. I need to break down the code and explain its purpose, specifically focusing on:

1. **General Functionality**: What does this code do in the context of a build system?
2. **Relevance to Reversing**: How could these functionalities be related to reverse engineering?
3. **Binary/Kernel/Framework Aspects**: Does it interact with low-level concepts, Linux/Android kernels, or frameworks?
4. **Logical Reasoning**: Can I identify assumptions, inputs, and outputs of specific functions?
5. **Common Usage Errors**: What mistakes could a user make while using these functions?
6. **User Journey**: How does a user's action lead to this specific part of the code being executed?
7. **Summary of Functionality**: A concise overview of what this code segment achieves.

Let's go through the code functions one by one and analyze them:

- `func_vcs_tag`: Seems to generate a file containing the version control system tag.
- `func_subdir_done`: Likely signals the completion of processing a subdirectory.
- `_validate_custom_target_outputs`: Validates the output names of custom build targets.
- `func_custom_target`: Defines a custom build target with arbitrary commands.
- `func_run_target`: Defines a target that executes a command.
- `func_alias_target`: Creates an alias for a set of existing targets.
- `func_generator`: Defines a generator that creates output files based on input and commands.
- `func_benchmark`, `func_test`: Define benchmark and test targets, respectively.
- `unpack_env_kwarg`: Processes environment variable settings for tests/benchmarks.
- `make_test`: Creates a test object.
- `add_test`: Adds a test or benchmark to the build definition.
- `func_install_headers`, `func_install_man`, `func_install_emptydir`, `func_install_symlink`, `func_install_data`, `func_install_subdir`: Define how different types of files are installed.
- `func_structured_sources`: Manages structured source files for the build.
- `func_subdir`: Processes a subdirectory within the build system.
- `_warn_kwarg_install_mode_sticky`:  Handles and warns about specific install mode flags.
- `install_data_impl`: Implements the core logic for installing data files.

Now, let's connect these functionalities to the specific requirements of the prompt.
这是 frida 动态 instrumentation 工具的构建系统中，用于解释和执行 `meson.build` 文件的 Python 代码片段。它定义了一系列用于声明构建目标、安装规则和配置的函数。以下是其主要功能以及与逆向、底层知识、逻辑推理和常见错误的相关性：

**功能归纳：**

该代码片段主要负责定义和处理各种构建目标和安装操作。它提供了诸如创建自定义构建步骤、运行命令、定义测试和基准、安装文件（头文件、man 手册、数据文件、子目录）等功能。核心在于解析 `meson.build` 文件中的声明，并将其转化为内部的构建描述，供 Meson 构建系统使用。

**具体功能列举：**

1. **`func_vcs_tag`**:  **获取版本控制系统标签。**
   - **功能:**  创建一个自定义构建目标，该目标会执行一个命令来获取版本控制系统的标签（例如 Git 的 commit hash 或 tag）。获取到的标签会替换输入文件中的特定字符串。
   - **与逆向的关系:** 在逆向分析中，了解目标二进制文件的构建版本非常重要。这个功能可以帮助将构建时的 VCS 信息嵌入到最终的可执行文件中，方便后续逆向人员识别版本。
   - **二进制底层:**  通常会执行如 `git rev-parse HEAD` 这样的命令，这些命令直接与底层的版本控制系统交互。
   - **逻辑推理:**
     - **假设输入:**  一个包含 `@VCS_TAG@` 占位符的模板文件，以及一个用于获取 VCS 标签的命令（例如 `['git', 'describe', '--tags', '--always']`）。
     - **输出:**  一个新的文件，其中 `@VCS_TAG@` 被 VCS 命令的输出替换。
   - **用户错误:**  提供的 VCS 命令不正确或无法执行，导致无法获取标签。例如，在非 Git 仓库中使用了 Git 命令。
   - **用户操作:** 用户在 `meson.build` 文件中调用 `vcs_tag` 函数，指定输入文件、输出文件和获取 VCS 标签的命令。

2. **`func_subdir_done`**: **标记当前子目录处理完成。**
   - **功能:**  用于提前退出当前子目录的 `meson.build` 文件的执行。
   - **与逆向的关系:**  间接相关。通过控制构建流程，可以影响最终生成的文件结构。
   - **用户操作:** 用户在 `meson.build` 文件中调用 `subdir_done()`，表示当前子目录的处理已经完成，Meson 将跳过剩余部分。

3. **`_validate_custom_target_outputs`**: **验证自定义构建目标的输出。**
   - **功能:**  检查自定义构建目标的输出文件名是否包含不允许的占位符，尤其是在有多个输入文件时。
   - **用户错误:**  在自定义构建目标有多个输入时，输出文件名中使用了 `@PLAINNAME@` 或 `@BASENAME@`，导致 Meson 无法确定使用哪个输入文件的名称。

4. **`func_custom_target`**: **定义自定义构建目标。**
   - **功能:**  允许用户定义执行任意命令的构建目标，可以指定输入、输出、依赖等。
   - **与逆向的关系:**  在逆向工程的构建过程中，可能需要执行一些特定的脚本或工具来处理二进制文件，例如解包、签名、混淆等。`custom_target` 可以用于集成这些步骤。
   - **二进制底层/Linux/Android:**  `command` 参数可以执行任何 shell 命令，包括操作二进制文件、调用 Linux 工具或 Android SDK 工具。例如，可以使用 `objcopy` 修改二进制文件节，或者使用 `apksigner` 对 Android APK 进行签名。
   - **逻辑推理:**
     - **假设输入:**  一个输入文件 `input.txt`，一个输出文件名 `output.bin`，以及一个命令 `['my_tool', 'input.txt', 'output.bin']`。
     - **输出:**  当构建系统执行此目标时，会运行 `my_tool input.txt output.bin`，生成 `output.bin`。
   - **用户错误:**  命令参数错误，导致工具执行失败；输入输出路径不正确；依赖关系未正确声明。
   - **用户操作:** 用户在 `meson.build` 文件中调用 `custom_target`，指定目标名称、输入、输出和要执行的命令。

5. **`func_run_target`**: **定义运行目标。**
   - **功能:**  定义一个可以被显式调用的目标，用于执行特定的命令，通常用于测试或部署。
   - **与逆向的关系:**  可以用于定义运行逆向分析工具的命令，例如启动 gdb 或 Frida 脚本来分析目标程序。
   - **二进制底层/Linux/Android:**  可以运行任何可执行程序或脚本，包括与底层系统交互的工具。
   - **用户操作:** 用户在 `meson.build` 文件中调用 `run_target`，指定目标名称和要执行的命令。

6. **`func_alias_target`**: **定义目标别名。**
   - **功能:**  创建一个指向一个或多个现有目标的别名，方便一次性构建多个目标。
   - **用户操作:** 用户在 `meson.build` 文件中调用 `alias_target`，指定别名和要指向的目标。

7. **`func_generator`**: **定义代码生成器。**
   - **功能:**  定义一个生成器，它根据输入文件和给定的命令生成一个或多个输出文件。常用于处理模板文件或自动生成代码。
   - **与逆向的关系:**  在逆向工程中，可能需要根据特定的输入格式生成一些辅助文件或代码片段。
   - **用户操作:** 用户在 `meson.build` 文件中调用 `generator`，指定生成器程序、参数和输出规则。

8. **`func_benchmark`, `func_test`**: **定义基准测试和单元测试。**
   - **功能:**  定义用于执行基准测试和单元测试的目标，可以设置超时、参数等。
   - **与逆向的关系:**  在开发和验证逆向工具或脚本时，可以使用这些功能来自动化测试。
   - **用户操作:** 用户在 `meson.build` 文件中调用 `benchmark` 或 `test`，指定测试名称、可执行文件和相关参数。

9. **`unpack_env_kwarg`**: **解包环境变量参数。**
   - **功能:**  处理测试和基准测试中 `env` 参数指定的环境变量。
   - **用户操作:**  间接操作，当在 `test` 或 `benchmark` 中使用 `env` 关键字时触发。

10. **`make_test`**: **创建测试对象。**
    - **功能:**  根据提供的参数创建一个 `Test` 对象，用于存储测试的配置信息。

11. **`add_test`**: **添加测试或基准测试到构建定义。**
    - **功能:**  将创建的 `Test` 对象添加到构建系统的测试或基准测试列表中。

12. **`func_install_headers`**: **安装头文件。**
    - **功能:**  定义安装头文件的规则，可以指定安装路径和是否保留目录结构。
    - **与逆向的关系:**  如果构建的目标是库或 SDK，需要安装头文件供其他开发者使用，包括逆向工程师。
    - **用户操作:** 用户在 `meson.build` 文件中调用 `install_headers`，指定要安装的头文件和安装路径。

13. **`func_install_man`**: **安装 man 手册。**
    - **功能:**  定义安装 man 手册的规则，可以指定安装路径和语言区域。
    - **用户操作:** 用户在 `meson.build` 文件中调用 `install_man`，指定要安装的 man 手册文件和安装路径。

14. **`func_install_emptydir`**: **安装空目录。**
    - **功能:**  定义安装空目录的规则。
    - **用户操作:** 用户在 `meson.build` 文件中调用 `install_emptydir`，指定要安装的空目录的路径。

15. **`func_install_symlink`**: **安装符号链接。**
    - **功能:** 定义安装符号链接的规则。
    - **用户操作:** 用户在 `meson.build` 文件中调用 `install_symlink`，指定链接名称、指向的目标和安装目录。

16. **`func_install_data`**: **安装数据文件。**
    - **功能:**  定义安装数据文件的规则，可以指定安装路径、重命名规则等。
    - **与逆向的关系:**  一些逆向工具可能依赖特定的数据文件，这些文件可以通过此功能安装。
    - **用户操作:** 用户在 `meson.build` 文件中调用 `install_data`，指定要安装的数据文件和安装路径。

17. **`func_install_subdir`**: **安装子目录。**
    - **功能:**  定义安装整个子目录的规则，可以排除特定文件或目录。
    - **用户操作:** 用户在 `meson.build` 文件中调用 `install_subdir`，指定要安装的子目录和安装路径。

18. **`func_structured_sources`**: **处理结构化源文件。**
    - **功能:**  允许以结构化的方式组织源文件，例如按目录或类型分组。
    - **用户操作:** 用户在 `meson.build` 文件中调用 `structured_sources`，并提供源文件列表或字典。

19. **`func_subdir`**: **处理子目录。**
    - **功能:**  指示 Meson 进入指定的子目录并处理其中的 `meson.build` 文件。
    - **用户操作:** 用户在顶层的 `meson.build` 文件中调用 `subdir`，指定要进入的子目录名称。

20. **`_warn_kwarg_install_mode_sticky`**: **处理并警告 `install_mode` 参数中的 sticky bit。**
    - **功能:**  检查 `install_mode` 参数，如果设置了 sticky bit，会发出警告。
    - **Linux:**  涉及到 Linux 文件权限的知识，sticky bit 在文件上通常没有实际意义。

21. **`install_data_impl`**: **实现安装数据文件的核心逻辑。**
    - **功能:**  执行安装数据文件的具体操作，包括创建目录、复制文件等。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **编写 `meson.build` 文件:** 用户首先需要编写 `meson.build` 文件，其中包含了对上述各种函数的调用，例如 `custom_target()`, `install_data()`, `test()` 等，来定义项目的构建规则和安装方式。
2. **运行 `meson` 命令:** 用户在项目根目录下运行 `meson <build_directory>` 命令来配置构建系统。Meson 会解析 `meson.build` 文件。
3. **解释器执行:** Meson 的解释器（即 `interpreter.py` 文件中的代码）会读取并执行 `meson.build` 文件中的函数调用。
4. **函数调用:** 当解析到例如 `custom_target(...)` 时，会调用 `interpreter.py` 中的 `func_custom_target` 函数，并将 `meson.build` 中提供的参数传递给该函数。
5. **构建目标创建:**  这些函数会创建相应的构建目标对象（例如 `build.CustomTarget`），并将这些对象添加到 Meson 的内部数据结构中。
6. **生成构建系统:**  Meson 根据这些构建目标对象生成实际的构建系统文件（例如 Ninja 构建文件）。
7. **运行构建命令:** 用户运行 `ninja -C <build_directory>` 命令来执行实际的构建过程。

在调试过程中，如果构建出现问题，可以通过查看 Meson 的日志输出，定位到哪个 `meson.build` 文件和哪一行代码导致了错误。理解 `interpreter.py` 中的这些函数的功能，可以帮助理解 Meson 是如何解析 `meson.build` 文件并生成构建计划的。

总而言之，这个代码片段是 Frida 构建系统中至关重要的一部分，它负责将用户在 `meson.build` 文件中定义的意图转化为实际的构建操作。它涵盖了构建系统的核心功能，并且在一定程度上与逆向工程的构建流程和涉及到的底层知识相关。

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
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
"""


```