Response:
The user wants me to analyze a Python source code file related to the Frida dynamic instrumentation tool.
Specifically, the file `frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py` seems to be part of the Meson build system integration for Frida's Python bindings.

Here's a breakdown of how to approach this:

1. **Understand the context:** This file is part of Meson's interpreter, responsible for processing the `meson.build` files. In Frida's case, it's likely involved in defining how the Python bindings are built.

2. **Identify key functions:** Scan the code for function definitions (`def func_...`). These functions represent the Meson built-in functions that are being implemented or extended here.

3. **Analyze function functionalities:** For each key function, determine what it does. Look at the arguments it takes, the operations it performs, and the data structures it interacts with (e.g., `self.build`, `self.environment`).

4. **Relate to reverse engineering:** Consider if any of these functions directly support or relate to reverse engineering tasks. This could involve configuring build options, handling specific file types, or interacting with system libraries.

5. **Connect to low-level details:**  Look for interactions with operating system concepts (Linux, Android), kernel aspects, or binary formats.

6. **Identify logic and assumptions:** Analyze conditional statements and loops to understand the decision-making processes within the code. Infer the intended inputs and outputs based on the logic.

7. **Find potential user errors:**  Look for error handling (`raise InterpreterException`, `raise InvalidArguments`) and think about the user actions that could trigger these errors.

8. **Trace user actions:**  Consider the steps a user would take when building Frida's Python bindings that would eventually lead to this code being executed. This starts with running the `meson` command.

9. **Summarize the overall functionality:**  Based on the analysis of individual functions, provide a high-level overview of what this part of the Meson interpreter does within the context of Frida.

**Specific Functions to Focus On:**

* `func_configure_file`: This is likely about generating configuration files based on templates.
* `func_include_directories`:  Deals with managing include paths for compilation.
* `func_add_test_setup`:  Seems related to defining test configurations.
* `func_add_global_arguments`, `func_add_project_arguments`: Handling compiler and linker flags.
* `func_environment`: Managing environment variables during the build.
* `func_join_paths`:  A utility for joining file paths.
* `validate_within_subproject`: Security-related, checks if file access is within the project boundaries.
* `source_strings_to_files`: Converts string representations of files to actual file objects.
* `add_target`:  Registers build targets.

**High-Level Plan:**

* Briefly introduce the role of the file within the Meson build process for Frida.
* Detail the functionality of key functions, providing examples where relevant.
* Specifically address the prompts related to reverse engineering, low-level details, logic, user errors, and user actions.
* Finally, summarize the overall functionality of the code snippet.
这是 `frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的一部分，它是 Frida 的 Python 绑定的构建过程中，Meson 构建系统的解释器代码。这段代码主要负责处理 `meson.build` 文件中的特定函数调用，以配置和定义构建过程。

以下是这段代码的主要功能以及与您提出的几个方面的关联：

**功能归纳:**

这段代码主要负责实现 Meson 构建系统中与文件配置、包含目录管理、测试设置、全局和项目级别的编译/链接参数配置以及环境变量管理相关的内置函数。它确保构建配置的正确性、安全性和灵活性。

**具体功能拆解及关联说明:**

1. **`func_configure_file`**:  此函数用于根据输入文件和配置数据生成输出文件。它可以执行以下操作：
    * **配置 (configuration)**:  使用提供的配置数据填充模板文件，生成新的配置文件。
    * **命令 (command)**:  执行外部命令，并将命令的输出写入输出文件。
    * **复制 (copy)**:  简单地复制输入文件到输出路径。
    * **安装 (install)**:  指定生成的文件是否需要安装到系统中。

   **与逆向方法的关系:**
   * **示例:** 在 Frida 的构建过程中，可能需要根据目标平台（例如 Android）的特定信息，生成包含路径、库名称等信息的配置文件。逆向工程师可能需要分析这些生成的配置文件，以了解 Frida 如何与目标系统交互。例如，可以分析生成的头文件来了解 Frida API 的结构。

   **涉及二进制底层，Linux, Android内核及框架的知识:**
   * **示例:**  当为 Android 构建时，`func_configure_file` 可能用于生成包含 Android NDK 路径的配置文件，这涉及到对 Android 文件系统结构和 NDK 工具链的了解。
   * **假设输入与输出:** 假设 `meson.build` 中有如下调用：
     ```python
     configure_file(
         input: 'config.h.in',
         output: 'config.h',
         configuration: {'API_LEVEL': 30}
     )
     ```
     如果 `config.h.in` 内容是 `#define API_LEVEL @API_LEVEL@`, 那么生成的 `config.h` 将会是 `#define API_LEVEL 30`。

   **用户或编程常见的使用错误:**
   * **示例:** 用户忘记指定 `configuration`、`command` 或 `copy` 中的任何一个关键字参数，会导致 `InterpreterException`。
   * **用户操作步骤:** 用户在 `meson.build` 文件中调用 `configure_file()` 函数，但没有提供执行的操作类型。Meson 解析 `meson.build` 文件时会调用 `func_configure_file`，进而抛出异常。

2. **`extract_incdirs` 和 `func_include_directories`**:  这两个函数用于处理包含目录。`func_include_directories` 用于声明包含目录，`extract_incdirs` 用于从关键字参数中提取包含目录信息。

   **与逆向方法的关系:**
   * **示例:** 逆向工程师需要了解目标程序使用了哪些头文件，这些头文件定义了程序使用的结构体、函数等信息。通过分析 Frida 的构建配置，可以找到 Frida 编译时使用的包含目录，从而获取 Frida 相关的头文件。

   **涉及二进制底层，Linux, Android内核及框架的知识:**
   * **示例:** 在为 Linux 或 Android 内核模块构建 Frida 组件时，可能需要包含内核头文件。这些函数会处理这些内核头文件的路径。

   **用户或编程常见的使用错误:**
   * **示例:** 用户提供了不存在的包含目录，会导致 `InvalidArguments` 异常。
   * **用户操作步骤:** 用户在 `meson.build` 中调用 `include_directories('nonexistent_dir')`。Meson 解析时会检查目录是否存在，并抛出异常。

3. **`func_add_test_setup`**:  此函数用于定义测试的设置，例如执行测试的包装器、GDB 支持、超时时间等。

   **与逆向方法的关系:**
   * 虽然不直接用于逆向目标程序，但逆向工程师可以使用 Frida 的测试框架来验证他们编写的 Frida 脚本或模块的功能。了解测试设置有助于理解 Frida 的测试流程。

4. **`func_add_global_arguments`，`func_add_global_link_arguments`，`func_add_project_arguments`，`func_add_project_link_arguments`**: 这些函数用于添加全局或项目级别的编译器和链接器参数。

   **与逆向方法的关系:**
   * **示例:**  Frida 可能需要特定的编译器或链接器标志才能正确构建，例如启用符号信息 (`-g`) 或链接特定的库。逆向工程师可以通过分析这些参数，了解 Frida 构建时的编译选项，这有助于理解其工作原理和潜在的调试方法。

   **涉及二进制底层，Linux, Android内核及框架的知识:**
   * **示例:** 为 Android 构建时，可能需要添加与 Android NDK 相关的编译器和链接器参数，例如指定目标架构 (`-march`) 或链接 Android 系统库。

   **用户或编程常见的使用错误:**
   * **示例:** 在定义目标后尝试添加全局参数，会导致 `InvalidCode` 异常。Meson 要求在声明目标之前定义全局参数。
   * **用户操作步骤:** 用户在 `meson.build` 文件中先调用 `executable()` 定义一个可执行文件目标，然后在之后调用 `add_global_arguments()`。

5. **`func_environment`**: 此函数用于设置构建过程中使用的环境变量。

   **与逆向方法的关系:**
   * **示例:**  某些构建过程可能依赖于特定的环境变量。逆向工程师可能需要了解这些环境变量的设置，以重现 Frida 的构建环境或理解其运行时的某些行为。

6. **`func_join_paths`**:  一个简单的实用函数，用于连接多个路径部分。

7. **`validate_within_subproject`**:  此函数用于验证给定的文件路径是否在当前子项目的范围内，以防止访问外部项目的资源，提高构建的隔离性和安全性。

   **涉及二进制底层，Linux, Android内核及框架的知识:**
   * **示例:**  防止构建脚本意外地访问系统或其他项目的敏感文件。

8. **`source_strings_to_files`**:  此函数将表示源文件的字符串转换为 `mesonlib.File` 对象。它还会进行路径有效性检查。

   **用户或编程常见的使用错误:**
   * **示例:** 用户提供了指向项目外部文件的相对路径，可能导致 `InterpreterException`，因为 Meson 默认不允许访问项目外部的文件。
   * **用户操作步骤:** 在 `meson.build` 中，尝试使用 `files('../../outside_file.c')`。

9. **`add_target`**:  此函数用于向构建系统中添加一个新的构建目标（例如，可执行文件、库）。

   **用户或编程常见的使用错误:**
   * **示例:**  提供了空的目标名称或包含路径分隔符的目标名称，会导致 `InterpreterException`。
   * **用户操作步骤:** 调用 `executable('', ...)` 或 `executable('my/target', ...)`。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户下载 Frida 的源代码。**
2. **用户尝试构建 Frida 的 Python 绑定，通常会执行 `meson setup build` 命令。**
3. **Meson 解析 `frida/subprojects/frida-python/meson.build` 文件。**
4. **在解析过程中，当遇到诸如 `configure_file`、`include_directories` 等 Meson 内置函数时，Meson 内部会调用 `mesonbuild/interpreter/interpreter.py` 文件中对应的 `func_` 开头的函数。**
5. **如果在 `meson.build` 文件中存在语法错误或逻辑错误（例如，提供了不存在的路径、错误的参数类型等），那么这些 `func_` 函数中的错误检查逻辑会被触发，抛出异常并中断构建过程，提供调试信息。**

总而言之，这段代码是 Frida Python 绑定构建过程中的核心组成部分，它负责解释和执行构建配置文件中的指令，确保构建过程的正确性和可配置性。对于逆向工程师而言，理解这段代码有助于了解 Frida 的构建方式、依赖关系以及可能的配置选项。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
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
"""


```