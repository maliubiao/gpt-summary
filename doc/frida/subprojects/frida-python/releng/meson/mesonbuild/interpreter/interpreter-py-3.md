Response:
The user wants a summary of the functionality of the Python code snippet provided, which is a part of the Meson build system. I need to analyze the code and identify the core responsibilities of this particular file (`interpreter.py`).

Specifically, the request asks for:
- A list of its functions.
- Explanation of its relevance to reverse engineering (if any).
- Explanation of its interaction with low-level components like the Linux kernel, Android, etc. (if any).
- Examples of logical reasoning with input/output.
- Examples of common user errors.
- Explanation of how a user's actions lead to this code being executed.
- A concise summary of its overall function (as part 4 of 6).

Based on the function names and docstrings, this file appears to be responsible for interpreting Meson's build definition files (`meson.build`). It handles various build-related functions like defining targets, running commands, managing dependencies, installing files, and configuring build processes.

Let's break down the functionalities based on the provided code:

1. **Version Control Tagging (`func_vcs_tag`)**:  This function seems to handle fetching version control information (like Git tags) and embedding it into files during the build process.
2. **Subdirectory Management (`func_subdir_done`, `func_subdir`)**: These functions deal with navigating and processing subdirectories within the build project.
3. **Custom Build Targets (`func_custom_target`)**: This is a core function for defining custom build steps with specific commands, inputs, and outputs.
4. **Run Targets (`func_run_target`)**: Defines targets that execute commands but don't produce build artifacts in the traditional sense.
5. **Alias Targets (`func_alias_target`)**: Creates virtual targets that depend on other targets, useful for grouping build actions.
6. **Code Generation (`func_generator`)**:  Manages the generation of source code or other files as part of the build process.
7. **Testing and Benchmarking (`func_benchmark`, `func_test`, `make_test`, `add_test`)**: Functions related to defining and executing tests and benchmarks for the project.
8. **Installation (`func_install_headers`, `func_install_man`, `func_install_emptydir`, `func_install_symlink`, `func_install_data`, `func_install_subdir`, `install_data_impl`)**: These functions handle the installation of various types of files (headers, man pages, data files, subdirectories, symlinks) to the system.
9. **Structured Sources (`func_structured_sources`)**:  Provides a way to organize source files into logical groups.
10. **File Configuration (`func_configure_file`)**:  Handles the generation of configuration files based on templates and build settings.

Now, let's address the specific requirements in the prompt.
这是 frida 动态 instrumentation 工具的源代码文件 `frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py` 的一部分。这个文件是 Meson 构建系统解释器的一部分，负责解析 `meson.build` 文件中的指令，并将其转化为构建系统的具体操作。

根据提供的代码片段，可以归纳出以下功能：

**核心功能：定义构建目标和操作**

这个代码片段主要定义了 Meson 构建系统中用于定义各种构建目标和执行相关操作的函数。这些函数对应于 `meson.build` 文件中可以调用的特定命令。

1. **`func_vcs_tag`**:  获取版本控制系统 (VCS) 的标签信息，并将其嵌入到输出文件中。这通常用于在构建过程中自动生成版本信息。
2. **`func_subdir_done`**:  用于显式地提前结束对当前子目录的处理。
3. **`func_custom_target`**: 定义自定义的构建目标。用户可以指定输入文件、输出文件以及执行的命令。这是 Meson 中非常灵活的一个功能，可以执行任意的构建步骤。
4. **`func_run_target`**: 定义一个执行目标，它会运行指定的命令，但不生成主要的构建产物。这通常用于执行一些辅助脚本或工具。
5. **`func_alias_target`**: 定义一个别名目标，它可以将多个目标组合在一起，方便用户一次性构建或操作这些目标。
6. **`func_generator`**:  定义一个代码生成器。它接收一个可执行文件和参数，根据输入文件生成输出文件。
7. **`func_benchmark`**:  定义一个基准测试。它与 `func_test` 类似，但用于性能测试。
8. **`func_test`**: 定义一个测试。它指定要运行的可执行文件、依赖项、参数等。
9. **`func_install_headers`**:  定义安装头文件的操作。
10. **`func_install_man`**: 定义安装 man 手册页的操作。
11. **`func_install_emptydir`**: 定义安装空目录的操作。
12. **`func_install_symlink`**: 定义安装符号链接的操作。
13. **`func_structured_sources`**:  定义结构化的源文件组织方式，可以对源文件进行分类管理。
14. **`func_subdir`**:  用于进入并处理子目录的 `meson.build` 文件。
15. **`func_install_data`**: 定义安装数据文件的操作。
16. **`func_install_subdir`**: 定义安装整个子目录的操作。

**与逆向方法的关系：**

虽然这个文件本身不直接执行逆向操作，但它定义的构建功能可以被用来构建用于逆向的工具或环境。

*   **构建 frida 工具本身：** 作为 frida 项目的一部分，这个文件参与了 frida 工具的构建过程。frida 作为一个动态 instrumentation 框架，其构建过程就需要用到 Meson 这样的构建系统。
*   **构建逆向分析工具：** 如果用户编写了自己的逆向分析工具，并使用 Meson 作为构建系统，那么这个文件中的函数将被用来定义如何编译、链接和打包这些工具。例如，`func_custom_target` 可以用来定义编译自定义的二进制分析工具的步骤。
*   **处理目标二进制文件：**  虽然这里没有直接体现，但 Meson 构建的目标可能就是需要进行逆向分析的二进制文件。这个文件定义了如何构建这些目标。

**涉及到二进制底层、Linux、Android 内核及框架的知识：**

*   **二进制底层：** `func_custom_target` 允许用户执行任意命令，这些命令可能包括编译、链接等涉及二进制文件生成和处理的操作。例如，可以执行 `gcc` 或 `clang` 来编译 C/C++ 代码成二进制文件。
*   **Linux：**  很多构建过程依赖于 Linux 特有的工具和概念，例如 `install` 命令用于安装文件，这在 `func_install_headers`、`func_install_man` 等函数中体现。安装路径的配置也与 Linux 文件系统结构有关。
*   **Android 内核及框架：**  如果 frida 被构建用于 Android 平台，那么这个文件定义的构建过程可能会涉及到 Android SDK、NDK 中的工具，例如 `aapt` (Android Asset Packaging Tool) 或 `javac` (Java compiler)。虽然代码片段中没有直接体现，但 `func_custom_target` 的灵活性允许用户集成这些工具。例如，可以定义一个自定义目标来处理 Android 的 `.apk` 文件。
*   **执行命令：** `COMMAND_KW` 中定义的命令可以是任何系统命令或可执行程序，这可以包括与操作系统底层交互的工具。

**逻辑推理的假设输入与输出：**

以 `func_vcs_tag` 为例：

*   **假设输入：**
    *   `input`:  一个模板文件，例如 `version.h.in`，其中包含占位符 `@VCS_TAG@`。
    *   `command`:  一个获取 VCS 标签的命令，例如 `git describe --tags --always`。
    *   `output`:  目标输出文件名，例如 `version.h`。
*   **逻辑推理：**
    1. 检查是否提供了 `fallback` 版本，如果没有，则使用项目版本。
    2. 执行 `command` 指定的命令。
    3. 从命令的输出中提取版本标签（默认使用正则表达式 `(.*)` 匹配所有输出）。
    4. 读取输入模板文件 `version.h.in`。
    5. 将模板文件中的 `@VCS_TAG@` 替换为提取到的版本标签。
    6. 将替换后的内容写入输出文件 `version.h`。
*   **假设输出：** 生成一个 `version.h` 文件，其中 `@VCS_TAG@` 被实际的 Git 标签替换，例如：

    ```c
    #define VERSION_STRING "v1.2.3-4-gabcdef"
    ```

以 `func_custom_target` 为例：

*   **假设输入：**
    *   `name`:  目标名称，例如 `my_executable`。
    *   `input`:  源文件列表，例如 `['main.c', 'utils.c']`。
    *   `command`:  编译命令列表，例如 `['gcc', '@INPUT@', '-o', '@OUTPUT@']`。
    *   `output`:  输出文件名列表，例如 `['my_executable']`。
*   **逻辑推理：**
    1. 创建一个自定义目标 `my_executable`。
    2. 指定构建该目标需要输入 `main.c` 和 `utils.c`。
    3. 指定执行的命令是 `gcc main.c utils.c -o my_executable`（`@INPUT@` 和 `@OUTPUT@` 会被自动替换）。
*   **假设输出：**  在构建目录下生成一个名为 `my_executable` 的可执行文件。

**涉及用户或者编程常见的使用错误：**

*   **`func_vcs_tag`**:
    *   **错误的 `command`：** 用户提供的命令无法正确获取 VCS 标签，导致输出文件中版本信息不正确或为空。
    *   **`replace_string` 不匹配：**  用户指定的 `replace_string` 在输入文件中不存在，导致替换失败。
*   **`func_custom_target`**:
    *   **`command` 错误：** 命令拼写错误或参数不正确，导致构建失败。
    *   **输入输出未对应：**  `@INPUT@` 和 `@OUTPUT@` 的使用不当，导致命令无法正确处理输入输出文件。
    *   **循环依赖：**  自定义目标依赖于自身或其他相互依赖的目标，导致构建无限循环。
    *   **多输入时使用 `@PLAINNAME@` 或 `@BASENAME@` 作为输出：** 当有多个输入文件时，`@PLAINNAME@` 和 `@BASENAME@` 无法确定使用哪个输入文件的名称，导致错误。
*   **`func_install_data`**:
    *   **`rename` 列表长度不匹配：**  如果提供了 `rename` 参数，但其列表长度与 `sources` 列表长度不一致，会导致错误。
    *   **安装路径错误：**  指定的安装路径不存在或用户没有写入权限。
*   **`func_subdir`**:
    *   **指定了已经访问过的目录：** 避免无限递归处理目录。
    *   **子目录不存在或缺少 `meson.build` 文件：**  导致构建系统无法进入子目录进行处理。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件：** 用户根据项目需求，编写包含 `vcs_tag()`, `custom_target()`, `install_data()` 等 Meson 函数的 `meson.build` 文件。
2. **用户运行 `meson` 命令配置构建：** 用户在项目根目录下运行 `meson setup builddir` 或类似的命令，指示 Meson 开始解析构建定义。
3. **Meson 解析 `meson.build` 文件：** Meson 的解释器会读取并解析 `meson.build` 文件。当遇到 `vcs_tag()`, `custom_target()` 等函数调用时，就会调用 `frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py` 文件中对应的 `func_vcs_tag`, `func_custom_target` 等方法。
4. **解释器执行相应的操作：** 这些函数会根据用户在 `meson.build` 文件中提供的参数，生成相应的构建指令，并添加到内部的构建图中。
5. **用户运行 `ninja` (或其他后端) 命令进行构建：** 用户在构建目录下运行 `ninja` 或类似的命令，实际执行 Meson 生成的构建指令。

**作为调试线索：** 如果构建过程中出现错误，例如无法找到 VCS 信息、自定义目标执行失败、文件安装位置错误等，开发者可以检查以下内容：

*   **`meson.build` 文件内容：** 确保相关函数的参数正确，例如命令路径、输入输出文件路径等。
*   **Meson 的输出信息：**  Meson 在配置和构建过程中会输出详细的日志信息，可以帮助定位问题。
*   **检查调用的具体函数：**  根据错误信息，可以定位到 `interpreter.py` 文件中具体的函数，例如 `func_vcs_tag` 或 `func_custom_target`，然后分析该函数的逻辑，查看是否有参数错误或逻辑问题。

**归纳一下它的功能：**

这个代码片段是 Meson 构建系统解释器的核心组成部分，**负责解析 `meson.build` 文件中定义的各种构建目标和操作，并将其转换为内部的构建表示形式**。它提供了定义版本控制标签获取、自定义构建步骤、执行命令、管理依赖、安装文件等多种构建功能的方法，是 Meson 将用户定义的构建逻辑转化为实际构建操作的关键环节。这些函数使得用户可以使用简洁的声明式语法来描述复杂的构建过程。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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