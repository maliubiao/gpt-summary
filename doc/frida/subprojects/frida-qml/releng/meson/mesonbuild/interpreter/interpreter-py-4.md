Response:
The user wants to understand the functionality of a specific Python file within the Frida project. I need to analyze the provided code snippet and identify its main responsibilities. The user is particularly interested in how this code relates to reverse engineering, binary manipulation, low-level system interaction (Linux, Android), logical reasoning, common user errors, and debugging.

**Plan:**

1. **Identify Key Functions:** Scan the code for function definitions (starting with `def`).
2. **Analyze Function Purpose:** For each function, understand its role within the larger context of the Frida build system.
3. **Relate to Reverse Engineering:** Determine if any functions directly or indirectly facilitate reverse engineering tasks.
4. **Identify Low-Level Interactions:** Look for functions that deal with file paths, system commands, or environment variables, which could hint at interactions with the operating system or kernel.
5. **Find Logical Reasoning:** Analyze functions that involve conditional logic, data validation, or decision-making based on input.
6. **Identify Potential User Errors:** Consider how incorrect usage of the functions could lead to errors.
7. **Trace User Operations:**  Infer the sequence of user actions that would lead to the execution of these functions within the Frida build process.
8. **Summarize Functionality:**  Provide a concise overview of the file's purpose.
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的一部分，它属于 Frida 工具的构建系统 Meson 的解释器代码。根据提供的代码片段，我们可以归纳出以下功能：

**核心功能：处理 `meson.build` 文件中的构建指令**

这段代码主要负责解析和执行 `meson.build` 文件中的特定函数调用，这些函数用于配置构建过程。具体来说，它处理了与以下方面相关的指令：

1. **`configure_file()` 函数:**
    *   **功能：**  这个函数用于从模板文件生成输出文件，并可以根据配置数据、执行命令或直接复制文件来完成生成。
    *   **逆向关系举例：** 在逆向工程中，可能需要根据不同的目标环境或配置生成不同的配置文件（例如，包含特定地址或密钥的文件）。`configure_file()` 可以根据主机环境或预定义的配置数据，修改模板文件中的占位符，生成目标设备或模拟器所需的配置文件。假设有一个模板文件 `config.in`，其中包含占位符 `@TARGET_API@`。在 `meson.build` 中，可以根据目标平台的不同，设置 `@TARGET_API@` 的值为 Android API 级别，然后使用 `configure_file()` 生成最终的 `config.h` 文件。
    *   **二进制底层/内核/框架知识举例：**  `configure_file()` 可以用于生成包含特定架构定义的头文件。例如，根据目标是 ARM 还是 x86，生成不同的宏定义，这些宏定义会影响到 Frida 运行时在目标设备上的行为，涉及到指令集架构等底层知识。
    *   **逻辑推理：**
        *   **假设输入：** `meson.build` 文件中调用 `configure_file(input: 'my_template.c', output: 'generated.c', configuration: {'VERSION': '1.0'})`
        *   **输出：** 将会生成一个名为 `generated.c` 的文件，其内容是 `my_template.c` 的内容，但所有出现的 `@VERSION@` 占位符会被替换为 `1.0`。
    *   **用户使用错误：** 用户可能忘记指定 `configuration` 字典中的某个在模板文件中使用的变量，导致构建警告或错误。例如，模板文件中有 `@AUTHOR@`，但 `configuration` 中没有 `'AUTHOR'`: '...' 键值对。
    *   **用户操作到达此处：** 用户在项目的根目录下执行 `meson setup build` 命令，Meson 解析 `meson.build` 文件时遇到了 `configure_file()` 函数的调用。

2. **`include_directories()` 函数:**
    *   **功能：**  声明编译时需要包含的头文件目录。
    *   **逆向关系举例：** 在逆向分析 Android 应用时，可能需要包含 Android SDK 或 NDK 中的头文件，以便理解应用的内部结构和 API 调用。`include_directories()` 可以指定这些头文件的路径，使得 Frida 能够正确地编译注入的代码。
    *   **二进制底层/内核/框架知识举例：**  声明内核头文件路径，用于编译与内核交互的 Frida 组件。或者声明 Android framework 的头文件路径，以便在 Frida 脚本中调用 Android framework 的 API。
    *   **逻辑推理：**
        *   **假设输入：** `meson.build` 文件中调用 `include_directories('include', 'src/common')`
        *   **输出：** Meson 会将 `include` 和 `src/common` 目录添加到编译器的头文件搜索路径中。
    *   **用户使用错误：**  用户可能指定了一个不存在的目录作为头文件路径，导致编译失败。
    *   **用户操作到达此处：**  Meson 解析 `meson.build` 文件时遇到了 `include_directories()` 函数的调用。

3. **`add_test_setup()` 函数:**
    *   **功能：**  定义测试的运行环境和配置，例如设置超时时间、运行时的环境变量、是否使用 GDB 等。
    *   **逆向关系举例：** 在开发 Frida 测试用例时，可能需要模拟特定的目标环境或设置特定的环境变量来触发某些行为。`add_test_setup()` 可以用于配置这些测试环境，例如设置一个特定的 Android API level 的模拟器环境。
    *   **二进制底层/内核/框架知识举例：**  可以配置测试在特定的内核版本或 Android 系统版本下运行。
    *   **逻辑推理：**
        *   **假设输入：** `meson.build` 文件中调用 `add_test_setup('slow_tests', timeout_multiplier: 5)`
        *   **输出：**  定义了一个名为 `slow_tests` 的测试设置，该设置下的所有测试的超时时间会乘以 5。
    *   **用户使用错误：**  用户可能为同一个子项目定义了多个默认测试设置 (`is_default: true`)，导致冲突。
    *   **用户操作到达此处：** Meson 解析 `meson.build` 文件时遇到了 `add_test_setup()` 函数的调用。

4. **`add_global_arguments()`, `add_global_link_arguments()`, `add_project_arguments()`, `add_project_link_arguments()` 函数:**
    *   **功能：**  添加全局或项目级别的编译器和链接器参数。
    *   **逆向关系举例：**  在逆向工程中，可能需要在编译 Frida 客户端或代理时添加特定的编译选项，例如启用调试符号 (`-g`) 或禁用某些优化 (`-O0`)，以便进行调试。
    *   **二进制底层/内核/框架知识举例：**  添加与特定架构相关的编译或链接参数。例如，为 ARM 架构添加 `-march=armv7-a` 参数。
    *   **逻辑推理：**
        *   **假设输入：** `meson.build` 文件中调用 `add_project_arguments('-DDEBUG_ENABLED')`
        *   **输出：**  在编译当前项目的所有目标时，都会添加 `-DDEBUG_ENABLED` 宏定义。
    *   **用户使用错误：**  在定义构建目标之后尝试添加全局参数，这是不允许的，因为参数应该在目标定义之前声明。
    *   **用户操作到达此处：** Meson 解析 `meson.build` 文件时遇到了这些添加参数的函数调用。

5. **`add_project_dependencies()` 函数:**
    *   **功能:**  声明项目的依赖项，并自动将依赖项的编译参数和链接参数添加到项目中。
    *   **逆向关系举例:**  如果 Frida 依赖于某个外部库，例如用于处理特定数据格式的库，可以使用此函数声明依赖，Meson 会自动处理该库的头文件路径和链接库。
    *   **二进制底层/内核/框架知识举例:**  依赖项可能是一个特定于操作系统的库。
    *   **逻辑推理:**  根据声明的依赖项，Meson 会查找并配置相应的编译和链接选项。
    *   **用户使用错误:**  在 `add_language()` 之前调用 `add_project_dependencies()` 并指定了该语言的依赖项。
    *   **用户操作到达此处:** Meson 解析 `meson.build` 文件时遇到了 `add_project_dependencies()` 函数的调用。

6. **`environment()` 函数:**
    *   **功能：**  创建一个表示环境变量的对象，用于在构建过程中设置或修改环境变量。
    *   **逆向关系举例：**  在测试 Frida 时，可能需要设置特定的环境变量来模拟目标环境的行为。
    *   **逻辑推理：**
        *   **假设输入：** `meson.build` 文件中调用 `env = environment({'PATH': '/opt/frida/bin:$PATH'})`
        *   **输出：**  创建了一个 `env` 对象，其中 `PATH` 环境变量被修改为包含 `/opt/frida/bin`。
    *   **用户使用错误：**  传递给 `environment()` 函数的参数类型不正确。
    *   **用户操作到达此处：** Meson 解析 `meson.build` 文件时遇到了 `environment()` 函数的调用。

7. **`join_paths()` 函数:**
    *   **功能：**  将多个路径片段连接成一个路径字符串。
    *   **逆向关系举例：**  在构建过程中，可能需要根据不同的组件路径拼接出最终的安装路径或中间文件路径。
    *   **逻辑推理：**
        *   **假设输入：** `meson.build` 文件中调用 `join_paths(get_option('prefix'), 'lib', 'frida')`
        *   **输出：**  返回一个形如 `/usr/local/lib/frida` 的路径字符串，其中 `/usr/local` 是通过 `get_option('prefix')` 获取的用户配置的安装前缀。
    *   **用户使用错误：**  传递给 `join_paths()` 函数的参数数量不足。
    *   **用户操作到达此处：** Meson 解析 `meson.build` 文件时遇到了 `join_paths()` 函数的调用。

8. **`source_strings_to_files()` 函数:**
    *   **功能：**  将表示源文件的字符串转换为 Meson 的 `File` 对象，用于后续的构建操作。
    *   **逆向关系举例：**  在定义需要编译的源文件时，通常会使用字符串表示文件路径，此函数将其转换为 Meson 可以识别和处理的对象。
    *   **逻辑推理：**  根据提供的字符串路径，查找并创建对应的 `File` 对象。
    *   **用户使用错误：**  提供的文件路径不存在或者类型不正确。
    *   **用户操作到达此处：**  在处理如 `executable()`, `shared_library()` 等需要源文件作为输入的函数调用时，会调用此函数。

9. **`add_target()` 函数:**
    *   **功能:**  将定义好的构建目标（例如，可执行文件或共享库）添加到构建系统中。
    *   **逆向关系举例:**  Frida 本身就是一个包含多个可执行文件和共享库的项目，例如 `frida-server` 和各种 Frida 客户端库，这些都是通过 `add_target()` 定义的。
    *   **用户操作到达此处:** Meson 解析 `meson.build` 文件时遇到了定义构建目标的函数调用，例如 `executable()` 或 `shared_library()`。

**总结：**

该文件 `interpreter.py` 的一部分主要负责解释和执行 `meson.build` 文件中用于配置构建过程的函数调用。它处理了文件生成、头文件包含、测试环境设置、编译和链接参数添加、依赖管理、环境变量配置、路径处理以及源文件对象转换等关键任务。 这些功能是 Frida 构建系统的重要组成部分，确保了 Frida 能够在不同的平台上正确地构建和测试。 其中很多功能都与逆向工程实践紧密相关，例如配置生成、指定依赖、设置编译选项等，这些都影响着最终生成的 Frida 工具的行为和特性。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
y=True,
            default=[],
        ),
        # Cannot use shared implementation until None backwards compat is dropped
        KwargInfo('install', (bool, NoneType), since='0.50.0'),
        KwargInfo('install_dir', (str, bool), default='',
                  validator=lambda x: 'must be `false` if boolean' if x is True else None),
        OUTPUT_KW,
        KwargInfo('output_format', str, default='c', since='0.47.0', since_values={'json': '1.3.0'},
                  validator=in_set_validator({'c', 'json', 'nasm'})),
        KwargInfo('macro_name', (str, NoneType), default=None, since='1.3.0'),
    )
    def func_configure_file(self, node: mparser.BaseNode, args: T.List[TYPE_var],
                            kwargs: kwtypes.ConfigureFile):
        actions = sorted(x for x in ['configuration', 'command', 'copy']
                         if kwargs[x] not in [None, False])
        num_actions = len(actions)
        if num_actions == 0:
            raise InterpreterException('Must specify an action with one of these '
                                       'keyword arguments: \'configuration\', '
                                       '\'command\', or \'copy\'.')
        elif num_actions == 2:
            raise InterpreterException('Must not specify both {!r} and {!r} '
                                       'keyword arguments since they are '
                                       'mutually exclusive.'.format(*actions))
        elif num_actions == 3:
            raise InterpreterException('Must specify one of {!r}, {!r}, and '
                                       '{!r} keyword arguments since they are '
                                       'mutually exclusive.'.format(*actions))

        if kwargs['capture'] and not kwargs['command']:
            raise InvalidArguments('configure_file: "capture" keyword requires "command" keyword.')

        install_mode = self._warn_kwarg_install_mode_sticky(kwargs['install_mode'])

        fmt = kwargs['format']
        output_format = kwargs['output_format']
        depfile = kwargs['depfile']

        # Validate input
        inputs = self.source_strings_to_files(kwargs['input'])
        inputs_abs = []
        for f in inputs:
            if isinstance(f, mesonlib.File):
                inputs_abs.append(f.absolute_path(self.environment.source_dir,
                                                  self.environment.build_dir))
                self.add_build_def_file(f)
            else:
                raise InterpreterException('Inputs can only be strings or file objects')

        # Validate output
        output = kwargs['output']
        if inputs_abs:
            values = mesonlib.get_filenames_templates_dict(inputs_abs, None)
            outputs = mesonlib.substitute_values([output], values)
            output = outputs[0]
            if depfile:
                depfile = mesonlib.substitute_values([depfile], values)[0]
        ofile_rpath = self.relative_builddir_path_for(os.path.join(self.subdir, output))
        if ofile_rpath in self.configure_file_outputs:
            mesonbuildfile = os.path.join(self.subdir, 'meson.build')
            current_call = f"{mesonbuildfile}:{self.current_lineno}"
            first_call = "{}:{}".format(mesonbuildfile, self.configure_file_outputs[ofile_rpath])
            mlog.warning('Output file', mlog.bold(ofile_rpath, True), 'for configure_file() at', current_call, 'overwrites configure_file() output at', first_call)
        else:
            self.configure_file_outputs[ofile_rpath] = self.current_lineno
        (ofile_path, ofile_fname) = os.path.split(ofile_rpath)
        ofile_abs = os.path.join(self.environment.build_dir, ofile_path, ofile_fname)

        # Perform the appropriate action
        if kwargs['configuration'] is not None:
            conf = kwargs['configuration']
            if isinstance(conf, dict):
                FeatureNew.single_use('configure_file.configuration dictionary', '0.49.0', self.subproject, location=node)
                for k, v in conf.items():
                    if not isinstance(v, (str, int, bool)):
                        raise InvalidArguments(
                            f'"configuration_data": initial value dictionary key "{k!r}"" must be "str | int | bool", not "{v!r}"')
                conf = build.ConfigurationData(conf)
            mlog.log('Configuring', mlog.bold(output), 'using configuration')
            if len(inputs) > 1:
                raise InterpreterException('At most one input file can given in configuration mode')
            if inputs:
                os.makedirs(self.absolute_builddir_path_for(self.subdir), exist_ok=True)
                file_encoding = kwargs['encoding']
                missing_variables, confdata_useless = \
                    mesonlib.do_conf_file(inputs_abs[0], ofile_abs, conf,
                                          fmt, file_encoding, self.subproject)
                if missing_variables:
                    var_list = ", ".join(repr(m) for m in sorted(missing_variables))
                    mlog.warning(
                        f"The variable(s) {var_list} in the input file '{inputs[0]}' are not "
                        "present in the given configuration data.", location=node)
                if confdata_useless:
                    ifbase = os.path.basename(inputs_abs[0])
                    tv = FeatureNew.get_target_version(self.subproject)
                    if FeatureNew.check_version(tv, '0.47.0'):
                        mlog.warning('Got an empty configuration_data() object and found no '
                                     f'substitutions in the input file {ifbase!r}. If you want to '
                                     'copy a file to the build dir, use the \'copy:\' keyword '
                                     'argument added in 0.47.0', location=node)
            else:
                macro_name = kwargs['macro_name']
                mesonlib.dump_conf_header(ofile_abs, conf, output_format, macro_name)
            conf.used = True
        elif kwargs['command'] is not None:
            if len(inputs) > 1:
                FeatureNew.single_use('multiple inputs in configure_file()', '0.52.0', self.subproject, location=node)
            # We use absolute paths for input and output here because the cwd
            # that the command is run from is 'unspecified', so it could change.
            # Currently it's builddir/subdir for in_builddir else srcdir/subdir.
            values = mesonlib.get_filenames_templates_dict(inputs_abs, [ofile_abs])
            if depfile:
                depfile = os.path.join(self.environment.get_scratch_dir(), depfile)
                values['@DEPFILE@'] = depfile
            # Substitute @INPUT@, @OUTPUT@, etc here.
            _cmd = mesonlib.substitute_values(kwargs['command'], values)
            mlog.log('Configuring', mlog.bold(output), 'with command')
            cmd, *args = _cmd
            res = self.run_command_impl((cmd, args),
                                        {'capture': True, 'check': True, 'env': EnvironmentVariables()},
                                        True)
            if kwargs['capture']:
                dst_tmp = ofile_abs + '~'
                file_encoding = kwargs['encoding']
                with open(dst_tmp, 'w', encoding=file_encoding) as f:
                    f.writelines(res.stdout)
                if inputs_abs:
                    shutil.copymode(inputs_abs[0], dst_tmp)
                mesonlib.replace_if_different(ofile_abs, dst_tmp)
            if depfile:
                mlog.log('Reading depfile:', mlog.bold(depfile))
                with open(depfile, encoding='utf-8') as f:
                    df = DepFile(f.readlines())
                    deps = df.get_all_dependencies(ofile_fname)
                    for dep in deps:
                        self.add_build_def_file(dep)

        elif kwargs['copy']:
            if len(inputs_abs) != 1:
                raise InterpreterException('Exactly one input file must be given in copy mode')
            os.makedirs(self.absolute_builddir_path_for(self.subdir), exist_ok=True)
            shutil.copy2(inputs_abs[0], ofile_abs)

        # Install file if requested, we check for the empty string
        # for backwards compatibility. That was the behaviour before
        # 0.45.0 so preserve it.
        idir = kwargs['install_dir']
        if idir is False:
            idir = ''
            FeatureDeprecated.single_use('configure_file install_dir: false', '0.50.0',
                                         self.subproject, 'Use the `install:` kwarg instead', location=node)
        install = kwargs['install'] if kwargs['install'] is not None else idir != ''
        if install:
            if not idir:
                raise InterpreterException(
                    '"install_dir" must be specified when "install" in a configure_file is true')
            idir_name = idir
            if isinstance(idir_name, P_OBJ.OptionString):
                idir_name = idir_name.optname
            cfile = mesonlib.File.from_built_file(ofile_path, ofile_fname)
            install_tag = kwargs['install_tag']
            self.build.data.append(build.Data([cfile], idir, idir_name, install_mode, self.subproject,
                                              install_tag=install_tag, data_type='configure'))
        return mesonlib.File.from_built_file(self.subdir, output)

    def extract_incdirs(self, kwargs, key: str = 'include_directories') -> T.List[build.IncludeDirs]:
        prospectives = extract_as_list(kwargs, key)
        if key == 'include_directories':
            for i in prospectives:
                if isinstance(i, str):
                    FeatureNew.single_use('include_directories kwarg of type string', '0.50.0', self.subproject,
                                          f'Use include_directories({i!r}) instead', location=self.current_node)
                    break

        result: T.List[build.IncludeDirs] = []
        for p in prospectives:
            if isinstance(p, build.IncludeDirs):
                result.append(p)
            elif isinstance(p, str):
                result.append(self.build_incdir_object([p]))
            else:
                raise InterpreterException('Include directory objects can only be created from strings or include directories.')
        return result

    @typed_pos_args('include_directories', varargs=str)
    @typed_kwargs('include_directories', KwargInfo('is_system', bool, default=False))
    def func_include_directories(self, node: mparser.BaseNode, args: T.Tuple[T.List[str]],
                                 kwargs: 'kwtypes.FuncIncludeDirectories') -> build.IncludeDirs:
        return self.build_incdir_object(args[0], kwargs['is_system'])

    def build_incdir_object(self, incdir_strings: T.List[str], is_system: bool = False) -> build.IncludeDirs:
        if not isinstance(is_system, bool):
            raise InvalidArguments('Is_system must be boolean.')
        src_root = self.environment.get_source_dir()
        absbase_src = os.path.join(src_root, self.subdir)
        absbase_build = self.absolute_builddir_path_for(self.subdir)

        for a in incdir_strings:
            if path_is_in_root(Path(a), Path(src_root)):
                raise InvalidArguments(textwrap.dedent('''\
                    Tried to form an absolute path to a dir in the source tree.
                    You should not do that but use relative paths instead, for
                    directories that are part of your project.

                    To get include path to any directory relative to the current dir do

                    incdir = include_directories(dirname)

                    After this incdir will contain both the current source dir as well as the
                    corresponding build dir. It can then be used in any subdirectory and
                    Meson will take care of all the busywork to make paths work.

                    Dirname can even be '.' to mark the current directory. Though you should
                    remember that the current source and build directories are always
                    put in the include directories by default so you only need to do
                    include_directories('.') if you intend to use the result in a
                    different subdirectory.

                    Note that this error message can also be triggered by
                    external dependencies being installed within your source
                    tree - it's not recommended to do this.
                    '''))
            else:
                try:
                    self.validate_within_subproject(self.subdir, a)
                except InterpreterException:
                    mlog.warning('include_directories sandbox violation!', location=self.current_node)
                    print(textwrap.dedent(f'''\
                        The project is trying to access the directory {a!r} which belongs to a different
                        subproject. This is a problem as it hardcodes the relative paths of these two projects.
                        This makes it impossible to compile the project in any other directory layout and also
                        prevents the subproject from changing its own directory layout.

                        Instead of poking directly at the internals the subproject should be executed and
                        it should set a variable that the caller can then use. Something like:

                        # In subproject
                        some_dep = declare_dependency(include_directories: include_directories('include'))

                        # In subproject wrap file
                        [provide]
                        some = some_dep

                        # In parent project
                        some_dep = dependency('some')
                        executable(..., dependencies: [some_dep])

                        This warning will become a hard error in a future Meson release.
                        '''))
            absdir_src = os.path.join(absbase_src, a)
            absdir_build = os.path.join(absbase_build, a)
            if not os.path.isdir(absdir_src) and not os.path.isdir(absdir_build):
                raise InvalidArguments(f'Include dir {a} does not exist.')
        i = build.IncludeDirs(
            self.subdir, incdir_strings, is_system, is_build_only_subproject=self.coredata.is_build_only)
        return i

    @typed_pos_args('add_test_setup', str)
    @typed_kwargs(
        'add_test_setup',
        KwargInfo('exe_wrapper', ContainerTypeInfo(list, (str, ExternalProgram)), listify=True, default=[]),
        KwargInfo('gdb', bool, default=False),
        KwargInfo('timeout_multiplier', int, default=1),
        KwargInfo('exclude_suites', ContainerTypeInfo(list, str), listify=True, default=[], since='0.57.0'),
        KwargInfo('is_default', bool, default=False, since='0.49.0'),
        ENV_KW,
    )
    def func_add_test_setup(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs: 'kwtypes.AddTestSetup') -> None:
        setup_name = args[0]
        if re.fullmatch('([_a-zA-Z][_0-9a-zA-Z]*:)?[_a-zA-Z][_0-9a-zA-Z]*', setup_name) is None:
            raise InterpreterException('Setup name may only contain alphanumeric characters.')
        if ":" not in setup_name:
            setup_name = f'{(self.subproject if self.subproject else self.build.project_name)}:{setup_name}'

        exe_wrapper: T.List[str] = []
        for i in kwargs['exe_wrapper']:
            if isinstance(i, str):
                exe_wrapper.append(i)
            else:
                if not i.found():
                    raise InterpreterException('Tried to use non-found executable.')
                exe_wrapper += i.get_command()

        timeout_multiplier = kwargs['timeout_multiplier']
        if timeout_multiplier <= 0:
            FeatureNew('add_test_setup() timeout_multiplier <= 0', '0.57.0').use(self.subproject)

        if kwargs['is_default']:
            if self.build.test_setup_default_name is not None:
                raise InterpreterException(f'{self.build.test_setup_default_name!r} is already set as default. '
                                           'is_default can be set to true only once')
            self.build.test_setup_default_name = setup_name
        self.build.test_setups[setup_name] = build.TestSetup(exe_wrapper, kwargs['gdb'], timeout_multiplier, kwargs['env'],
                                                             kwargs['exclude_suites'])

    @typed_pos_args('add_global_arguments', varargs=str)
    @typed_kwargs('add_global_arguments', NATIVE_KW, LANGUAGE_KW)
    def func_add_global_arguments(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        self._add_global_arguments(node, self.build.global_args[kwargs['native']], args[0], kwargs)

    @typed_pos_args('add_global_link_arguments', varargs=str)
    @typed_kwargs('add_global_arguments', NATIVE_KW, LANGUAGE_KW)
    def func_add_global_link_arguments(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        self._add_global_arguments(node, self.build.global_link_args[kwargs['native']], args[0], kwargs)

    @typed_pos_args('add_project_arguments', varargs=str)
    @typed_kwargs('add_project_arguments', NATIVE_KW, LANGUAGE_KW)
    def func_add_project_arguments(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        self._add_project_arguments(node, self.build.projects_args[kwargs['native']], args[0], kwargs)

    @typed_pos_args('add_project_link_arguments', varargs=str)
    @typed_kwargs('add_global_arguments', NATIVE_KW, LANGUAGE_KW)
    def func_add_project_link_arguments(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        self._add_project_arguments(node, self.build.projects_link_args[kwargs['native']], args[0], kwargs)

    @FeatureNew('add_project_dependencies', '0.63.0')
    @typed_pos_args('add_project_dependencies', varargs=dependencies.Dependency)
    @typed_kwargs('add_project_dependencies', NATIVE_KW, LANGUAGE_KW)
    def func_add_project_dependencies(self, node: mparser.FunctionNode, args: T.Tuple[T.List[dependencies.Dependency]], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        for_machine = kwargs['native']
        for lang in kwargs['language']:
            if lang not in self.compilers[for_machine]:
                raise InvalidCode(f'add_project_dependencies() called before add_language() for language "{lang}"')

        for d in dependencies.get_leaf_external_dependencies(args[0]):
            compile_args = list(d.get_compile_args())
            system_incdir = d.get_include_type() == 'system'
            for i in d.get_include_dirs():
                for lang in kwargs['language']:
                    comp = self.coredata.compilers[for_machine][lang]
                    for idir in i.to_string_list(self.environment.get_source_dir(), self.environment.get_build_dir()):
                        compile_args.extend(comp.get_include_args(idir, system_incdir))

            self._add_project_arguments(node, self.build.projects_args[for_machine], compile_args, kwargs)
            self._add_project_arguments(node, self.build.projects_link_args[for_machine], d.get_link_args(), kwargs)

    def _warn_about_builtin_args(self, args: T.List[str]) -> None:
        # -Wpedantic is deliberately not included, since some people want to use it but not use -Wextra
        # see e.g.
        # https://github.com/mesonbuild/meson/issues/3275#issuecomment-641354956
        # https://github.com/mesonbuild/meson/issues/3742
        warnargs = ('/W1', '/W2', '/W3', '/W4', '/Wall', '-Wall', '-Wextra')
        optargs = ('-O0', '-O2', '-O3', '-Os', '-Oz', '/O1', '/O2', '/Os')
        for arg in args:
            if arg in warnargs:
                mlog.warning(f'Consider using the built-in warning_level option instead of using "{arg}".',
                             location=self.current_node)
            elif arg in optargs:
                mlog.warning(f'Consider using the built-in optimization level instead of using "{arg}".',
                             location=self.current_node)
            elif arg == '-Werror':
                mlog.warning(f'Consider using the built-in werror option instead of using "{arg}".',
                             location=self.current_node)
            elif arg == '-g':
                mlog.warning(f'Consider using the built-in debug option instead of using "{arg}".',
                             location=self.current_node)
            # Don't catch things like `-fsanitize-recover`
            elif arg in {'-fsanitize', '/fsanitize'} or arg.startswith(('-fsanitize=', '/fsanitize=')):
                mlog.warning(f'Consider using the built-in option for sanitizers instead of using "{arg}".',
                             location=self.current_node)
            elif arg.startswith('-std=') or arg.startswith('/std:'):
                mlog.warning(f'Consider using the built-in option for language standard version instead of using "{arg}".',
                             location=self.current_node)

    def _add_global_arguments(self, node: mparser.FunctionNode, argsdict: T.Dict[str, T.List[str]],
                              args: T.List[str], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        if self.is_subproject():
            msg = f'Function \'{node.func_name.value}\' cannot be used in subprojects because ' \
                  'there is no way to make that reliable.\nPlease only call ' \
                  'this if is_subproject() returns false. Alternatively, ' \
                  'define a variable that\ncontains your language-specific ' \
                  'arguments and add it to the appropriate *_args kwarg ' \
                  'in each target.'
            raise InvalidCode(msg)
        frozen = self.project_args_frozen or self.global_args_frozen
        self._add_arguments(node, argsdict, frozen, args, kwargs)

    def _add_project_arguments(self, node: mparser.FunctionNode, argsdict: T.Dict[str, T.Dict[str, T.List[str]]],
                               args: T.List[str], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        if self.subproject not in argsdict:
            argsdict[self.subproject] = {}
        self._add_arguments(node, argsdict[self.subproject],
                            self.project_args_frozen, args, kwargs)

    def _add_arguments(self, node: mparser.FunctionNode, argsdict: T.Dict[str, T.List[str]],
                       args_frozen: bool, args: T.List[str], kwargs: 'kwtypes.FuncAddProjectArgs') -> None:
        if args_frozen:
            msg = f'Tried to use \'{node.func_name.value}\' after a build target has been declared.\n' \
                  'This is not permitted. Please declare all arguments before your targets.'
            raise InvalidCode(msg)

        self._warn_about_builtin_args(args)

        for lang in kwargs['language']:
            argsdict[lang] = argsdict.get(lang, []) + args

    @noArgsFlattening
    @typed_pos_args('environment', optargs=[(str, list, dict)])
    @typed_kwargs('environment', ENV_METHOD_KW, ENV_SEPARATOR_KW.evolve(since='0.62.0'))
    def func_environment(self, node: mparser.FunctionNode, args: T.Tuple[T.Union[None, str, T.List['TYPE_var'], T.Dict[str, 'TYPE_var']]],
                         kwargs: 'TYPE_kwargs') -> EnvironmentVariables:
        init = args[0]
        if init is not None:
            FeatureNew.single_use('environment positional arguments', '0.52.0', self.subproject, location=node)
            msg = ENV_KW.validator(init)
            if msg:
                raise InvalidArguments(f'"environment": {msg}')
            if isinstance(init, dict) and any(i for i in init.values() if isinstance(i, list)):
                FeatureNew.single_use('List of string in dictionary value', '0.62.0', self.subproject, location=node)
            return env_convertor_with_method(init, kwargs['method'], kwargs['separator'])
        return EnvironmentVariables()

    @typed_pos_args('join_paths', varargs=str, min_varargs=1)
    @noKwargs
    def func_join_paths(self, node: mparser.BaseNode, args: T.Tuple[T.List[str]], kwargs: 'TYPE_kwargs') -> str:
        parts = args[0]
        other = os.path.join('', *parts[1:]).replace('\\', '/')
        ret = os.path.join(*parts).replace('\\', '/')
        if isinstance(parts[0], P_OBJ.DependencyVariableString) and '..' not in other:
            return P_OBJ.DependencyVariableString(ret)
        elif isinstance(parts[0], P_OBJ.OptionString):
            name = os.path.join(parts[0].optname, other)
            return P_OBJ.OptionString(ret, name)
        else:
            return ret

    def run(self) -> None:
        super().run()
        mlog.log('Build targets in project:', mlog.bold(str(len(self.build.targets))))
        FeatureNew.report(self.subproject)
        FeatureDeprecated.report(self.subproject)
        FeatureBroken.report(self.subproject)
        if not self.is_subproject():
            self.print_extra_warnings()
            self._print_summary()

    def print_extra_warnings(self) -> None:
        # TODO cross compilation
        for c in self.coredata.compilers.host.values():
            if c.get_id() == 'clang':
                self.check_clang_asan_lundef()
                break

    def check_clang_asan_lundef(self) -> None:
        if OptionKey('b_lundef') not in self.coredata.options:
            return
        if OptionKey('b_sanitize') not in self.coredata.options:
            return
        if (self.coredata.options[OptionKey('b_lundef')].value and
                self.coredata.options[OptionKey('b_sanitize')].value != 'none'):
            value = self.coredata.options[OptionKey('b_sanitize')].value
            mlog.warning(textwrap.dedent(f'''\
                    Trying to use {value} sanitizer on Clang with b_lundef.
                    This will probably not work.
                    Try setting b_lundef to false instead.'''),
                location=self.current_node)  # noqa: E128

    # Check that the indicated file is within the same subproject
    # as we currently are. This is to stop people doing
    # nasty things like:
    #
    # f = files('../../master_src/file.c')
    #
    # Note that this is validated only when the file
    # object is generated. The result can be used in a different
    # subproject than it is defined in (due to e.g. a
    # declare_dependency).
    def validate_within_subproject(self, subdir, fname):
        srcdir = Path(self.environment.source_dir)
        builddir = Path(self.environment.build_dir)
        if isinstance(fname, P_OBJ.DependencyVariableString):
            def validate_installable_file(fpath: Path) -> bool:
                installablefiles: T.Set[Path] = set()
                for d in self.build.data:
                    for s in d.sources:
                        installablefiles.add(Path(s.absolute_path(srcdir, builddir)))
                installabledirs = [str(Path(srcdir, s.source_subdir)) for s in self.build.install_dirs]
                if fpath in installablefiles:
                    return True
                for d in installabledirs:
                    if str(fpath).startswith(d):
                        return True
                return False

            norm = Path(fname)
            # variables built from a dep.get_variable are allowed to refer to
            # subproject files, as long as they are scheduled to be installed.
            if validate_installable_file(norm):
                return
        norm = Path(os.path.abspath(Path(srcdir, subdir, fname)))
        if os.path.isdir(norm):
            inputtype = 'directory'
        else:
            inputtype = 'file'
        if InterpreterRuleRelaxation.ALLOW_BUILD_DIR_FILE_REFERENCES in self.relaxations and builddir in norm.parents:
            return
        if srcdir not in norm.parents:
            # Grabbing files outside the source tree is ok.
            # This is for vendor stuff like:
            #
            # /opt/vendorsdk/src/file_with_license_restrictions.c
            return
        project_root = Path(srcdir, self.root_subdir)
        subproject_dir = project_root / self.subproject_dir
        if norm == project_root:
            return
        if project_root not in norm.parents:
            raise InterpreterException(f'Sandbox violation: Tried to grab {inputtype} {norm.name} outside current (sub)project.')
        if subproject_dir == norm or subproject_dir in norm.parents:
            raise InterpreterException(f'Sandbox violation: Tried to grab {inputtype} {norm.name} from a nested subproject.')

    @T.overload
    def source_strings_to_files(self, sources: T.List['mesonlib.FileOrString'], strict: bool = True) -> T.List['mesonlib.File']: ...

    @T.overload
    def source_strings_to_files(self, sources: T.List['mesonlib.FileOrString'], strict: bool = False) -> T.List['mesonlib.FileOrString']: ... # noqa: F811

    @T.overload
    def source_strings_to_files(self, sources: T.List[T.Union[mesonlib.FileOrString, build.GeneratedTypes]]) -> T.List[T.Union[mesonlib.File, build.GeneratedTypes]]: ... # noqa: F811

    @T.overload
    def source_strings_to_files(self, sources: T.List['SourceInputs'], strict: bool = True) -> T.List['SourceOutputs']: ... # noqa: F811

    @T.overload
    def source_strings_to_files(self, sources: T.List[SourcesVarargsType], strict: bool = True) -> T.List['SourceOutputs']: ... # noqa: F811

    def source_strings_to_files(self, sources: T.List['SourceInputs'], strict: bool = True) -> T.List['SourceOutputs']: # noqa: F811
        """Lower inputs to a list of Targets and Files, replacing any strings.

        :param sources: A raw (Meson DSL) list of inputs (targets, files, and
            strings)
        :raises InterpreterException: if any of the inputs are of an invalid type
        :return: A list of Targets and Files
        """
        mesonlib.check_direntry_issues(sources)
        if not isinstance(sources, list):
            sources = [sources]
        results: T.List['SourceOutputs'] = []
        for s in sources:
            if isinstance(s, str):
                if not strict and s.startswith(self.environment.get_build_dir()):
                    results.append(s)
                    mlog.warning(f'Source item {s!r} cannot be converted to File object, because it is a generated file. '
                                 'This will become a hard error in the future.', location=self.current_node)
                else:
                    self.validate_within_subproject(self.subdir, s)
                    results.append(mesonlib.File.from_source_file(self.environment.source_dir, self.subdir, s))
            elif isinstance(s, mesonlib.File):
                results.append(s)
            elif isinstance(s, (build.GeneratedList, build.BuildTarget,
                                build.CustomTargetIndex, build.CustomTarget,
                                build.ExtractedObjects, build.StructuredSources)):
                results.append(s)
            else:
                raise InterpreterException(f'Source item is {s!r} instead of '
                                           'string or File-type object')
        return results

    @staticmethod
    def validate_forbidden_targets(name: str) -> None:
        if name.startswith('meson-internal__'):
            raise InvalidArguments("Target names starting with 'meson-internal__' are reserved "
                                   "for Meson's internal use. Please rename.")
        if name.startswith('meson-') and '.' not in name:
            raise InvalidArguments("Target names starting with 'meson-' and without a file extension "
                                   "are reserved for Meson's internal use. Please rename.")
        if name in coredata.FORBIDDEN_TARGET_NAMES:
            raise InvalidArguments(f"Target name '{name}' is reserved for Meson's "
                                   "internal use. Please rename.")

    def add_target(self, name: str, tobj: build.Target) -> None:
        if self.backend.name == 'none':
            raise InterpreterException('Install-only backend cannot generate target rules, try using `--backend=ninja`.')
        if name == '':
            raise InterpreterException('Target name must not be empty.')
        if name.strip() == '':
            raise InterpreterException('Target name must not consist only of whitespace.')
        if has_path_sep(name):
            pathseg = os.path.join(self
```