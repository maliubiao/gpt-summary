Response:
The user wants a summary of the functionality of the provided Python code snippet, which is part of the `interpreter.py` file in the Frida dynamic instrumentation tool. I need to analyze the functions defined in this snippet and explain their purpose. I also need to address specific aspects like its relation to reverse engineering, low-level details, logic reasoning, common user errors, and debugging information.

Here's a breakdown of the functions in this snippet:

1. **`func_declare_dependency`**: Declares a dependency with various attributes.
2. **`func_assert`**: Implements an assertion function to check conditions during the build process.
3. **`validate_arguments`**: Checks the number and types of arguments passed to a function.
4. **`func_run_command`**: Executes external commands during the build process.
5. **`run_command_impl`**: Implements the logic for running external commands.
6. **`func_option`**:  Raises an error because options should be defined in the dedicated options file.
7. **`func_subproject`**: Adds a subproject to the build.
8. **`disabled_subproject`**: Handles disabled subprojects.
9. **`do_subproject`**: Orchestrates the process of adding a subproject.
10. **`_do_subproject_meson`**: Handles Meson-based subprojects.
11. **`_do_subproject_cmake`**: Handles CMake-based subprojects.
12. **`_do_subproject_cargo`**: Handles Cargo-based subprojects.
13. **`get_option_internal`**: Retrieves the value of a build option.
14. **`func_get_option`**:  Exposes the `get_option_internal` function to the Meson build language.
15. **`func_configuration_data`**: Creates a configuration data object to store build settings.
16. **`set_backend`**:  Selects and initializes the build backend (e.g., Ninja, Visual Studio).
17. **`func_project`**: Declares the project's name, version, and other metadata.

Now, I'll summarize these functionalities.
这段代码是 `frida-tools` 中 Meson 构建系统的解释器的一部分，它定义了多个在 `meson.build` 文件中可以调用的函数，用于描述软件的构建过程。以下是对这些功能的归纳：

**核心构建描述功能：**

1. **依赖声明 (`func_declare_dependency`):**  用于声明项目所依赖的其他库或组件。它可以指定头文件路径、编译参数、链接参数、库文件、源文件等信息，帮助构建系统正确地链接和编译项目。

2. **断言 (`func_assert`):** 允许在构建脚本中加入断言语句，用于在配置阶段检查某些条件是否满足。如果断言失败，构建过程会报错并停止。这有助于尽早发现配置错误。

3. **命令执行 (`func_run_command`, `run_command_impl`):**  允许在构建过程中执行外部命令。这对于运行代码生成器、执行测试脚本或其他构建辅助工具非常有用。它可以捕获命令的输出，并根据需要检查命令的返回状态。

4. **子项目管理 (`func_subproject`, `disabled_subproject`, `do_subproject`, `_do_subproject_meson`, `_do_subproject_cmake`, `_do_subproject_cargo`):**  提供了管理和包含其他子项目的功能。支持 Meson、CMake 和 Cargo 构建系统的子项目。这使得构建复杂项目时可以将不同的模块组织成独立的子项目。

5. **选项管理 (`func_option`, `get_option_internal`, `func_get_option`):**  用于处理构建选项。`func_option` 本身会抛出异常，因为选项应该定义在专门的选项文件中。`get_option_internal` 和 `func_get_option` 用于在构建脚本中获取用户配置的构建选项的值。

6. **配置数据 (`func_configuration_data`):**  允许创建和管理配置数据对象，这些对象可以在构建过程中用于生成配置文件或其他需要动态配置的文件。

7. **构建后端设置 (`set_backend`):**  负责根据用户配置或自动检测来设置构建后端（例如 Ninja 或 Visual Studio）。

8. **项目定义 (`func_project`):**  用于声明项目的基本信息，如项目名称、版本、许可证等。它还会处理项目级的默认选项和子项目目录的设置。

**与逆向方法的关联举例说明：**

Frida 本身是一个动态插桩工具，常用于逆向工程。虽然这段代码主要关注构建过程，但它间接地支持了逆向分析的构建需求。例如：

*   **依赖声明 (`func_declare_dependency`):**  在构建 Frida 自身或使用 Frida 的项目时，可能需要依赖特定的库（例如，处理调试符号的库）。这个函数确保了这些依赖被正确地链接。在逆向分析中，处理符号信息对于理解目标程序的行为至关重要。

*   **命令执行 (`func_run_command`):**  构建 Frida 时，可能需要执行一些代码生成脚本来生成特定的代码或数据结构。这些生成出的代码或数据结构可能直接用于 Frida 的插桩逻辑，或者用于处理目标进程的内存布局等信息，这与逆向分析直接相关。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明：**

*   **链接参数 (`link_args` in `func_declare_dependency`):**  可能需要指定特定的链接器参数，例如指定共享库的 SONAME，或者控制符号的可见性。这些都涉及到二进制文件的底层结构和链接过程。在 Frida 的构建中，为了让 Frida 可以注入到目标进程，可能需要使用特定的链接参数。

*   **库文件 (`libs` in `func_declare_dependency`):**  Frida 的某些功能可能依赖于底层的操作系统库，例如用于进程间通信的库，或者用于内存管理的库。在 Linux 或 Android 上，这些可能是标准的 libc 库或其他系统库。

*   **运行命令执行 (`func_run_command`):**  在 Android 平台上构建 Frida 的组件时，可能需要执行 `adb` 命令来推送文件到设备或者执行设备上的命令。这直接涉及到 Android 系统的知识。

**逻辑推理的假设输入与输出：**

以 `func_assert` 为例：

**假设输入：**

*   `value`: `False` (布尔值)
*   `message`: `"Something went wrong"` (字符串)

**输出：**

抛出一个 `InterpreterException`，消息为 `"Assert failed: Something went wrong"`。

**假设输入：**

*   `value`: `True` (布尔值)
*   `message`: `None` (空)

**输出：**

构建过程继续进行，不产生任何输出（除了可能产生的 `FeatureNew` 日志）。

**涉及用户或者编程常见的使用错误举例说明：**

*   **类型错误 (`validate_arguments`):**  用户在 `meson.build` 文件中调用函数时，可能会传递错误的参数类型。例如，某个参数期望是字符串，但用户传递了一个整数。`validate_arguments` 函数可以捕获这类错误，并抛出 `InvalidArguments` 异常。

*   **子项目名称错误 (`do_subproject`):** 用户在调用 `subproject()` 函数时，可能会提供无效的子项目名称，例如包含 `..` 或者以 `.` 开头。代码中会检查这些错误并抛出 `InterpreterException`。

*   **尝试在构建描述文件中使用 `option()` (`func_option`):**  Meson 要求选项必须在专门的选项文件中定义。如果用户在 `meson.build` 文件中尝试调用 `option()` 函数，将会触发 `InterpreterException`。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

当用户执行 `meson` 命令来配置项目构建时，Meson 会读取项目根目录下的 `meson.build` 文件以及可能的 `meson_options.txt` 或 `meson.options` 文件。

1. **用户执行 `meson setup builddir`:**  用户在命令行中运行 `meson setup builddir` 命令，指示 Meson 开始配置构建。
2. **Meson 解析 `meson.build`:** Meson 解释器开始解析项目根目录下的 `meson.build` 文件。
3. **调用 `func_project`:**  在 `meson.build` 文件中，通常会首先调用 `project()` 函数来声明项目信息。这会触发 `interpreter.py` 中的 `func_project` 函数的执行。
4. **调用其他函数:**  在 `meson.build` 文件中，可能会调用其他函数，例如 `dependency()` (最终会调用 `func_declare_dependency`)、`run_command()` (调用 `func_run_command`)、`subproject()` (调用 `func_subproject`) 等。
5. **断言失败:** 如果在 `meson.build` 文件中使用了 `assert()` 函数，并且断言的条件为假，就会调用 `func_assert` 函数，并抛出异常，中断配置过程。
6. **外部命令执行失败:** 如果 `func_run_command` 执行的外部命令返回非零的退出码，并且没有设置 `check: false`，则会抛出异常。

调试线索通常包括：

*   **命令行输出:** Meson 会在命令行输出配置过程中的信息和错误。
*   **`meson.log` 文件:**  Meson 会将详细的日志信息写入 `meson.log` 文件，包括每个函数的调用和执行结果。
*   **回溯信息:**  如果发生异常，Meson 会提供回溯信息，指出错误发生的具体位置（例如，哪个 `meson.build` 文件的哪一行）。

这段代码的功能是定义了 Meson 构建系统中用于描述构建过程的核心指令，使得开发者可以使用声明式的方式来定义项目的依赖、构建步骤和配置选项。它在 Frida 这样的复杂项目中扮演着至关重要的角色，确保了项目的正确构建。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能

"""
not v:
                FeatureNew.single_use('empty variable value in declare_dependency', '1.4.0', self.subproject, location=node)
            try:
                p = Path(v)
            except ValueError:
                continue
            else:
                if not self.is_subproject() and srcdir / self.subproject_dir in p.parents:
                    continue
                if p.is_absolute() and p.is_dir() and srcdir / self.root_subdir in [p] + list(Path(os.path.abspath(p)).parents):
                    variables[k] = P_OBJ.DependencyVariableString(v)

        dep = dependencies.InternalDependency(version, incs, compile_args,
                                              link_args, libs, libs_whole, sources, extra_files,
                                              deps, variables, d_module_versions, d_import_dirs,
                                              objects)
        return dep

    @typed_pos_args('assert', bool, optargs=[str])
    @noKwargs
    def func_assert(self, node: mparser.FunctionNode, args: T.Tuple[bool, T.Optional[str]],
                    kwargs: 'TYPE_kwargs') -> None:
        value, message = args
        if message is None:
            FeatureNew.single_use('assert function without message argument', '0.53.0', self.subproject, location=node)

        if not value:
            if message is None:
                from ..ast import AstPrinter
                printer = AstPrinter()
                node.args.arguments[0].accept(printer)
                message = printer.result
            raise InterpreterException('Assert failed: ' + message)

    def validate_arguments(self, args, argcount, arg_types):
        if argcount is not None:
            if argcount != len(args):
                raise InvalidArguments(f'Expected {argcount} arguments, got {len(args)}.')
        for actual, wanted in zip(args, arg_types):
            if wanted is not None:
                if not isinstance(actual, wanted):
                    raise InvalidArguments('Incorrect argument type.')

    # Executables aren't actually accepted, but we allow them here to allow for
    # better error messages when overridden
    @typed_pos_args(
        'run_command',
        (build.Executable, ExternalProgram, compilers.Compiler, mesonlib.File, str),
        varargs=(build.Executable, ExternalProgram, compilers.Compiler, mesonlib.File, str))
    @typed_kwargs(
        'run_command',
        KwargInfo('check', (bool, NoneType), since='0.47.0'),
        KwargInfo('capture', bool, default=True, since='0.47.0'),
        ENV_KW.evolve(since='0.50.0'),
    )
    def func_run_command(self, node: mparser.BaseNode,
                         args: T.Tuple[T.Union[build.Executable, ExternalProgram, compilers.Compiler, mesonlib.File, str],
                                       T.List[T.Union[build.Executable, ExternalProgram, compilers.Compiler, mesonlib.File, str]]],
                         kwargs: 'kwtypes.RunCommand') -> RunProcess:
        return self.run_command_impl(args, kwargs)

    def run_command_impl(self,
                         args: T.Tuple[T.Union[build.Executable, ExternalProgram, compilers.Compiler, mesonlib.File, str],
                                       T.List[T.Union[build.Executable, ExternalProgram, compilers.Compiler, mesonlib.File, str]]],
                         kwargs: 'kwtypes.RunCommand',
                         in_builddir: bool = False) -> RunProcess:
        cmd, cargs = args
        capture = kwargs['capture']
        env = kwargs['env']
        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()

        check = kwargs['check']
        if check is None:
            mlog.warning(implicit_check_false_warning, once=True)
            check = False

        overridden_msg = ('Program {!r} was overridden with the compiled '
                          'executable {!r} and therefore cannot be used during '
                          'configuration')
        expanded_args: T.List[str] = []
        if isinstance(cmd, build.Executable):
            for name, exe in self.build.find_overrides[cmd.for_machine].items():
                if cmd == exe:
                    progname = name
                    break
            else:
                raise InterpreterException(f'Program {cmd.description()!r} is a compiled executable and therefore cannot be used during configuration')
            raise InterpreterException(overridden_msg.format(progname, cmd.description()))
        if isinstance(cmd, ExternalProgram):
            if not cmd.found():
                raise InterpreterException(f'command {cmd.get_name()!r} not found or not executable')
        elif isinstance(cmd, compilers.Compiler):
            exelist = cmd.get_exelist()
            cmd = exelist[0]
            prog = ExternalProgram(cmd, silent=True)
            if not prog.found():
                raise InterpreterException(f'Program {cmd!r} not found or not executable')
            cmd = prog
            expanded_args = exelist[1:]
        else:
            if isinstance(cmd, mesonlib.File):
                cmd = cmd.absolute_path(srcdir, builddir)
            # Prefer scripts in the current source directory
            search_dir = os.path.join(srcdir, self.subdir)
            prog = ExternalProgram(cmd, silent=True, search_dir=search_dir)
            if not prog.found():
                raise InterpreterException(f'Program or command {cmd!r} not found or not executable')
            cmd = prog
        for a in cargs:
            if isinstance(a, str):
                expanded_args.append(a)
            elif isinstance(a, mesonlib.File):
                expanded_args.append(a.absolute_path(srcdir, builddir))
            elif isinstance(a, ExternalProgram):
                expanded_args.append(a.get_path())
            elif isinstance(a, compilers.Compiler):
                FeatureNew.single_use('Compiler object as a variadic argument to `run_command`', '0.61.0', self.subproject, location=self.current_node)
                prog = ExternalProgram(a.exelist[0], silent=True)
                if not prog.found():
                    raise InterpreterException(f'Program {cmd!r} not found or not executable')
                expanded_args.append(prog.get_path())
            else:
                raise InterpreterException(overridden_msg.format(a.name, cmd.description()))

        # If any file that was used as an argument to the command
        # changes, we must re-run the configuration step.
        self.add_build_def_file(cmd.get_path())
        for a in expanded_args:
            if not os.path.isabs(a):
                if in_builddir:
                    a = self.absolute_builddir_path_for(os.path.join(self.subdir, a))
                else:
                    a = os.path.join(srcdir, self.subdir, a)
            self.add_build_def_file(a)

        return RunProcess(cmd, expanded_args, env, srcdir, builddir, self.subdir,
                          self.environment.get_build_command() + ['introspect'],
                          in_builddir=in_builddir, check=check, capture=capture)

    def func_option(self, nodes, args, kwargs):
        raise InterpreterException('Tried to call option() in build description file. All options must be in the option file.')

    @typed_pos_args('subproject', str)
    @typed_kwargs(
        'subproject',
        REQUIRED_KW,
        NATIVE_KW.evolve(since='1.3.0'),
        DEFAULT_OPTIONS.evolve(since='0.38.0'),
        KwargInfo('version', ContainerTypeInfo(list, str), default=[], listify=True),
    )
    def func_subproject(self, nodes: mparser.BaseNode, args: T.Tuple[str], kwargs: kwtypes.Subproject) -> SubprojectHolder:
        kw: kwtypes.DoSubproject = {
            'required': kwargs['required'],
            'default_options': kwargs['default_options'],
            'version': kwargs['version'],
            'options': None,
            'cmake_options': [],
            'for_machine': kwargs['native'],
        }
        return self.do_subproject(args[0], kw)

    def disabled_subproject(self, subp_name: SubProject, disabled_feature: T.Optional[str] = None,
                            exception: T.Optional[Exception] = None,
                            for_machine: MachineChoice = MachineChoice.HOST) -> SubprojectHolder:
        sub = SubprojectHolder(NullSubprojectInterpreter(), os.path.join(self.subproject_dir, subp_name),
                               disabled_feature=disabled_feature, exception=exception)
        self.subprojects[for_machine][subp_name] = sub
        return sub

    def do_subproject(self, subp_name: SubProject, kwargs: kwtypes.DoSubproject, force_method: T.Optional[wrap.Method] = None) -> SubprojectHolder:
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject)
        kwargs['for_machine'] = for_machine = kwargs['for_machine'] if not self.coredata.is_build_only else MachineChoice.BUILD

        if disabled:
            mlog.log('Subproject', mlog.bold(subp_name), ':', 'skipped: feature', mlog.bold(feature), 'disabled')
            return self.disabled_subproject(subp_name, disabled_feature=feature, for_machine=for_machine)

        default_options = {k.evolve(subproject=subp_name): v for k, v in kwargs['default_options'].items()}

        if subp_name == '':
            raise InterpreterException('Subproject name must not be empty.')
        if subp_name[0] == '.':
            raise InterpreterException('Subproject name must not start with a period.')
        if '..' in subp_name:
            raise InterpreterException('Subproject name must not contain a ".." path segment.')
        if os.path.isabs(subp_name):
            raise InterpreterException('Subproject name must not be an absolute path.')
        if has_path_sep(subp_name):
            mlog.warning('Subproject name has a path separator. This may cause unexpected behaviour.',
                         location=self.current_node)
        if subp_name in self.subproject_stack[for_machine]:
            fullstack = self.subproject_stack[for_machine] + [subp_name]
            incpath = ' => '.join(fullstack)
            raise InvalidCode(f'Recursive include of subprojects: {incpath}.')
        if subp_name in self.subprojects[for_machine]:
            subproject = self.subprojects[for_machine][subp_name]
            if required and not subproject.found():
                raise InterpreterException(f'Subproject "{subproject.subdir}" required but not found.')
            if kwargs['version']:
                pv = self.build.subprojects[for_machine][subp_name]
                wanted = kwargs['version']
                if pv == 'undefined' or not mesonlib.version_compare_many(pv, wanted)[0]:
                    raise InterpreterException(f'Subproject {subp_name} version is {pv} but {wanted} required.')
            return subproject

        r = self.environment.wrap_resolver
        try:
            subdir, method = r.resolve(subp_name, force_method)
        except wrap.WrapException as e:
            if not required:
                mlog.log(e)
                mlog.log('Subproject ', mlog.bold(subp_name), 'is buildable:', mlog.red('NO'), '(disabling)')
                return self.disabled_subproject(subp_name, exception=e)
            raise e

        is_build_only = for_machine is MachineChoice.BUILD and self.environment.is_cross_build()
        os.makedirs(os.path.join(self.build.environment.get_build_dir(),
                                 build.compute_build_subdir(subdir, is_build_only)),
                    exist_ok=True)
        self.global_args_frozen = True

        stack = ':'.join(self.subproject_stack[for_machine] + [subp_name])
        m = ['\nExecuting subproject', mlog.bold(stack)]
        if method != 'meson':
            m += ['method', mlog.bold(method)]
        m.extend(['for machine:', mlog.bold(for_machine.get_lower_case_name())])
        mlog.log(*m, '\n', nested=False)

        methods_map: T.Dict[wrap.Method, T.Callable[[SubProject, str, T.Dict[OptionKey, str, kwtypes.DoSubproject]], SubprojectHolder]] = {
            'meson': self._do_subproject_meson,
            'cmake': self._do_subproject_cmake,
            'cargo': self._do_subproject_cargo,
        }

        try:
            return methods_map[method](subp_name, subdir, default_options, kwargs)
        # Invalid code is always an error
        except InvalidCode:
            raise
        except Exception as e:
            if not required:
                with mlog.nested(subp_name):
                    # Suppress the 'ERROR:' prefix because this exception is not
                    # fatal and VS CI treat any logs with "ERROR:" as fatal.
                    mlog.exception(e, prefix=mlog.yellow('Exception:'))
                mlog.log('\nSubproject', mlog.bold(subdir), 'is buildable:', mlog.red('NO'), '(disabling)')
                return self.disabled_subproject(subp_name, exception=e)
            raise e

    def _do_subproject_meson(self, subp_name: SubProject, subdir: str,
                             default_options: T.Dict[OptionKey, str],
                             kwargs: kwtypes.DoSubproject,
                             ast: T.Optional[mparser.CodeBlockNode] = None,
                             build_def_files: T.Optional[T.List[str]] = None,
                             relaxations: T.Optional[T.Set[InterpreterRuleRelaxation]] = None) -> SubprojectHolder:
        for_machine = kwargs['for_machine']
        if for_machine is MachineChoice.BUILD and self.environment.is_cross_build():
            new_build = self.build.copy_for_build_machine()
        else:
            new_build = self.build.copy()

        with mlog.nested(subp_name):
            if ast:
                # Debug print the generated meson file
                from ..ast import AstIndentationGenerator, AstPrinter
                printer = AstPrinter(update_ast_line_nos=True)
                ast.accept(AstIndentationGenerator())
                ast.accept(printer)
                printer.post_process()
                bsubdir = os.path.join(self.build.environment.get_build_dir(),
                                       build.compute_build_subdir(subdir, new_build.environment.coredata.is_build_only))
                os.makedirs(bsubdir, exist_ok=True)
                meson_filename = os.path.join(bsubdir, 'meson.build')
                with open(meson_filename, "w", encoding='utf-8') as f:
                    f.write(printer.result)
                mlog.log('Generated Meson AST:', meson_filename)
                mlog.cmd_ci_include(meson_filename)

            subi = Interpreter(new_build, self.backend, subp_name, subdir, self.subproject_dir,
                               default_options, ast=ast, is_translated=(ast is not None),
                               relaxations=relaxations,
                               user_defined_options=self.user_defined_options)
            # Those lists are shared by all interpreters. That means that
            # even if the subproject fails, any modification that the subproject
            # made to those lists will affect the parent project.
            subi.subprojects = self.subprojects
            subi.modules = self.modules
            subi.holder_map = self.holder_map
            subi.bound_holder_map = self.bound_holder_map
            subi.summary = self.summary

            subi.subproject_stack = PerMachine(self.subproject_stack.build.copy(), self.subproject_stack.host.copy())
            subi.subproject_stack[for_machine].append(subp_name)
            current_active = self.active_projectname
            with mlog.nested_warnings():
                subi.run()
                subi_warnings = mlog.get_warning_count()
            mlog.log('Subproject', mlog.bold(subp_name), 'finished.')

        mlog.log()

        if kwargs['version']:
            pv = subi.project_version
            wanted = kwargs['version']
            if pv == 'undefined' or not mesonlib.version_compare_many(pv, wanted)[0]:
                raise InterpreterException(f'Subproject {subp_name} version is {pv} but {wanted} required.')
        self.active_projectname = current_active
        self.subprojects[for_machine][subp_name] = SubprojectHolder(
            subi, subdir, warnings=subi_warnings, callstack=self.subproject_stack)
        # Duplicates are possible when subproject uses files from project root
        if build_def_files:
            self.build_def_files.update(build_def_files)
        # We always need the subi.build_def_files, to propagate sub-sub-projects
        self.build_def_files.update(subi.build_def_files)
        self.build.merge(subi.build)
        self.build.subprojects[for_machine][subp_name] = subi.project_version
        return self.subprojects[for_machine][subp_name]

    def _do_subproject_cmake(self, subp_name: SubProject, subdir: str,
                             default_options: T.Dict[OptionKey, str],
                             kwargs: kwtypes.DoSubproject) -> SubprojectHolder:
        from ..cmake import CMakeInterpreter
        for_machine = kwargs['for_machine']
        with mlog.nested(subp_name):
            prefix = self.coredata.options[OptionKey('prefix')].value

            from ..modules.cmake import CMakeSubprojectOptions
            options = kwargs.get('options') or CMakeSubprojectOptions()
            cmake_options = kwargs.get('cmake_options', []) + options.cmake_options
            cm_int = CMakeInterpreter(Path(subdir), Path(prefix), self.build.environment, self.backend, for_machine)
            cm_int.initialise(cmake_options)
            cm_int.analyse()

            # Generate a meson ast and execute it with the normal do_subproject_meson
            ast = cm_int.pretend_to_be_meson(options.target_options)
            result = self._do_subproject_meson(
                    subp_name, subdir, default_options,
                    kwargs, ast,
                    [str(f) for f in cm_int.bs_files],
                    relaxations={
                        InterpreterRuleRelaxation.ALLOW_BUILD_DIR_FILE_REFERENCES,
                    }
            )
            result.cm_interpreter = cm_int
        return result

    def _do_subproject_cargo(self, subp_name: SubProject, subdir: str,
                             default_options: T.Dict[OptionKey, str],
                             kwargs: kwtypes.DoSubproject) -> SubprojectHolder:
        from .. import cargo
        FeatureNew.single_use('Cargo subproject', '1.3.0', self.subproject, location=self.current_node)
        with mlog.nested(subp_name):
            ast, options = cargo.interpret(subp_name, subdir, self.environment)
            self.coredata.update_project_options(options, subp_name)
            return self._do_subproject_meson(
                subp_name, subdir, default_options, kwargs, ast,
                # FIXME: Are there other files used by cargo interpreter?
                [os.path.join(subdir, 'Cargo.toml')])

    def get_option_internal(self, optname: str) -> coredata.UserOption:
        key = OptionKey.from_string(optname).evolve(subproject=self.subproject)

        if not key.is_project():
            for opts in [self.coredata.options, compilers.base_options]:
                v = opts.get(key)
                if v is None or v.yielding:
                    v = opts.get(key.as_root())
                if v is not None:
                    assert isinstance(v, coredata.UserOption), 'for mypy'
                    return v

        try:
            opt = self.coredata.options[key]
            if opt.yielding and key.subproject and key.as_root() in self.coredata.options:
                popt = self.coredata.options[key.as_root()]
                if type(opt) is type(popt):
                    opt = popt
                else:
                    # Get class name, then option type as a string
                    opt_type = opt.__class__.__name__[4:][:-6].lower()
                    popt_type = popt.__class__.__name__[4:][:-6].lower()
                    # This is not a hard error to avoid dependency hell, the workaround
                    # when this happens is to simply set the subproject's option directly.
                    mlog.warning('Option {0!r} of type {1!r} in subproject {2!r} cannot yield '
                                 'to parent option of type {3!r}, ignoring parent value. '
                                 'Use -D{2}:{0}=value to set the value for this option manually'
                                 '.'.format(optname, opt_type, self.subproject, popt_type),
                                 location=self.current_node)
            return opt
        except KeyError:
            pass

        raise InterpreterException(f'Tried to access unknown option {optname!r}.')

    @typed_pos_args('get_option', str)
    @noKwargs
    def func_get_option(self, nodes: mparser.BaseNode, args: T.Tuple[str],
                        kwargs: 'TYPE_kwargs') -> T.Union[coredata.UserOption, 'TYPE_var']:
        optname = args[0]
        if ':' in optname:
            raise InterpreterException('Having a colon in option name is forbidden, '
                                       'projects are not allowed to directly access '
                                       'options of other subprojects.')

        if optname_regex.search(optname.split('.', maxsplit=1)[-1]) is not None:
            raise InterpreterException(f'Invalid option name {optname!r}')

        opt = self.get_option_internal(optname)
        if isinstance(opt, coredata.UserFeatureOption):
            opt.name = optname
            return opt
        elif isinstance(opt, coredata.UserOption):
            if isinstance(opt.value, str):
                return P_OBJ.OptionString(opt.value, f'{{{optname}}}')
            return opt.value
        return opt

    @typed_pos_args('configuration_data', optargs=[dict])
    @noKwargs
    def func_configuration_data(self, node: mparser.BaseNode, args: T.Tuple[T.Optional[T.Dict[str, T.Any]]],
                                kwargs: 'TYPE_kwargs') -> build.ConfigurationData:
        initial_values = args[0]
        if initial_values is not None:
            FeatureNew.single_use('configuration_data dictionary', '0.49.0', self.subproject, location=node)
            for k, v in initial_values.items():
                if not isinstance(v, (str, int, bool)):
                    raise InvalidArguments(
                        f'"configuration_data": initial value dictionary key "{k!r}"" must be "str | int | bool", not "{v!r}"')
        return build.ConfigurationData(initial_values)

    def set_backend(self) -> None:
        # The backend is already set when parsing subprojects
        if self.backend is not None:
            return
        from ..backend import backends

        if OptionKey('genvslite') in self.user_defined_options.cmd_line_options.keys():
            # Use of the '--genvslite vsxxxx' option ultimately overrides any '--backend xxx'
            # option the user may specify.
            backend_name = self.coredata.get_option(OptionKey('genvslite'))
            self.backend = backends.get_genvslite_backend(backend_name, self.build, self)
        else:
            backend_name = self.coredata.get_option(OptionKey('backend'))
            self.backend = backends.get_backend_from_name(backend_name, self.build, self)

        if self.backend is None:
            raise InterpreterException(f'Unknown backend "{backend_name}".')
        if backend_name != self.backend.name:
            if self.backend.name.startswith('vs'):
                mlog.log('Auto detected Visual Studio backend:', mlog.bold(self.backend.name))
            if not self.environment.first_invocation:
                raise MesonBugException(f'Backend changed from {backend_name} to {self.backend.name}')
            self.coredata.set_option(OptionKey('backend'), self.backend.name, first_invocation=True)

        # Only init backend options on first invocation otherwise it would
        # override values previously set from command line.
        if self.environment.first_invocation:
            self.coredata.init_backend_options(backend_name)

        options = {k: v for k, v in self.environment.options.items() if k.is_backend()}
        self.coredata.set_options(options)

    @typed_pos_args('project', str, varargs=str)
    @typed_kwargs(
        'project',
        DEFAULT_OPTIONS,
        KwargInfo('meson_version', (str, NoneType)),
        KwargInfo(
            'version',
            (str, mesonlib.File, NoneType, list),
            default='undefined',
            validator=_project_version_validator,
            convertor=lambda x: x[0] if isinstance(x, list) else x,
        ),
        KwargInfo('license', (ContainerTypeInfo(list, str), NoneType), default=None, listify=True),
        KwargInfo('license_files', ContainerTypeInfo(list, str), default=[], listify=True, since='1.1.0'),
        KwargInfo('subproject_dir', str, default='subprojects'),
    )
    def func_project(self, node: mparser.FunctionNode, args: T.Tuple[str, T.List[str]], kwargs: 'kwtypes.Project') -> None:
        proj_name, proj_langs = args
        if ':' in proj_name:
            raise InvalidArguments(f"Project name {proj_name!r} must not contain ':'")

        # This needs to be evaluated as early as possible, as meson uses this
        # for things like deprecation testing.
        if kwargs['meson_version']:
            self.handle_meson_version(kwargs['meson_version'], node)

        # Load "meson.options" before "meson_options.txt", and produce a warning if
        # it is being used with an old version. I have added check that if both
        # exist the warning isn't raised
        option_file = os.path.join(self.source_root, self.subdir, 'meson.options')
        old_option_file = os.path.join(self.source_root, self.subdir, 'meson_options.txt')

        if os.path.exists(option_file):
            if os.path.exists(old_option_file):
                if os.path.samefile(option_file, old_option_file):
                    mlog.debug("Not warning about meson.options with version minimum < 1.1 because meson_options.txt also exists")
                else:
                    raise MesonException("meson.options and meson_options.txt both exist, but are not the same file.")
            else:
                FeatureNew.single_use('meson.options file', '1.1', self.subproject, 'Use meson_options.txt instead')
        else:
            option_file = old_option_file
        if os.path.exists(option_file):
            with open(option_file, 'rb') as f:
                # We want fast  not cryptographically secure, this is just to
                # see if the option file has changed
                self.coredata.options_files[self.subproject] = (option_file, hashlib.sha1(f.read()).hexdigest())
            oi = optinterpreter.OptionInterpreter(self.subproject)
            oi.process(option_file)
            self.coredata.update_project_options(oi.options, self.subproject)
            self.add_build_def_file(option_file)
        else:
            self.coredata.options_files[self.subproject] = None

        if self.subproject:
            self.project_default_options = {k.evolve(subproject=self.subproject): v
                                            for k, v in kwargs['default_options'].items()}
        else:
            self.project_default_options = kwargs['default_options']

        # Do not set default_options on reconfigure otherwise it would override
        # values previously set from command line. That means that changing
        # default_options in a project will trigger a reconfigure but won't
        # have any effect.
        #
        # If this is the first invocation we always need to initialize
        # builtins, if this is a subproject that is new in a re-invocation we
        # need to initialize builtins for that
        if self.environment.first_invocation or (self.subproject != '' and self.subproject not in self.coredata.initialized_subprojects):
            default_options = self.project_default_options.copy()
            default_options.update(self.default_project_options)
            self.coredata.init_builtins(self.subproject)
            self.coredata.initialized_subprojects.add(self.subproject)
        else:
            default_options = {}
        self.coredata.set_default_options(default_options, self.subproject, self.environment)

        if not self.is_subproject():
            self.build.project_name = proj_name
        self.active_projectname = proj_name

        version = kwargs['version']
        if isinstance(version, mesonlib.File):
            FeatureNew.single_use('version from file', '0.57.0', self.subproject, location=node)
            self.add_build_def_file(version)
            ifname = version.absolute_path(self.environment.source_dir,
                                           self.environment.build_dir)
            try:
                ver_data = Path(ifname).read_text(encoding='utf-8').split('\n')
            except FileNotFoundError:
                raise InterpreterException('Version file not found.')
            if len(ver_data) == 2 and ver_data[1] == '':
                ver_data = ver_data[0:1]
            if len(ver_data) != 1:
                raise InterpreterException('Version file must contain exactly one line of text.')
            self.project_version = ver_data[0]
        else:
            self.project_version = version

        if self.build.project_version is None:
            self.build.project_version = self.project_version

        if kwargs['license'] is None:
            proj_license = ['unknown']
            if kwargs['license_files']:
                raise InvalidArguments('Project `license` name must be specified when `license_files` is set')
        else:
            proj_license = kwargs['license']
        proj_license_files = []
        for i in self.source_strings_to_files(kwargs['license_files']):
            ifname = i.absolute_path(self.environment.source_dir,
                                     self.environment.build_dir)
            proj_license_files.append((ifname, i))
        self.build.dep_manifest[proj_name] = build.DepManifest(self.project_version, proj_license,
                                                               proj_license_files, self.subproject)

        for_machine = MachineChoice.BUILD if self.coredata.is_build_only else MachineChoice.HOST

        if self.subproject in self.build.projects[for_machine]:
            raise InvalidCode('Second call to project().')

        # spdirname is the subproject_dir for this project, relative to self.subdir.
        # self.subproject_dir is the subproject_dir for the main project, relative to top source dir.
        spdirname = kwargs['subproject_dir']
        if not isinstance(spdirname, str):
            raise InterpreterException('Subproject_dir must be a string')
        if os.path.isabs(spdirname):
            raise InterpreterException('Subproject_dir must not be an absolute path.')
        if spdirname.startswith('.'):
            raise InterpreterException('Subproject_dir must not begin with a period.')
        if '..' in spdirname:
            raise InterpreterException('Subproject_dir must not contain a ".." segment.')
        if not self.is_subproject():
            self.subproject_dir = spdirname
        self.build.subproject_dir = self.subproject_dir

        # Load wrap files from this (sub)project.
        wrap_mode = self.coredata.get_option(OptionKey('wrap_mode'))
        if not self.is_subproject() or wrap_mode != WrapMode.nopromote:
            subdir = os.path.join(self.subdir, spdirname)
            r = wrap.Resolver(self.environment.get_source_dir(), subdir, self.subproject, wrap_mode)
            if self.is_subproject():
                self.environment.wrap_resolver.merge_wraps(r)
            else:
                self.environment.wrap_resolver = r

        self.build.projects[for_machine][self.subproject] = proj_name

        extra_args: T.List[mlog.TV_Loggable] = []
        if self.is_subproject() and for_machine is MachineChoice.BUILD:
            extra_args.append('(for build machine)')
        mlog.log('Project name:', mlog.bold(proj_name), *extra_args)
        mlog.log('Project version:', mlog.bold(self.project_version))

        if not self.is_subproject():
            # We have to activate VS before adding languages and before calling
            # self.set_backend() otherwise it wouldn't be able to detect which
            # vs backend version we need. But after setting default_options in case
            # the project sets vs backend by default.
            backend = self.coredata.get_option(OptionKey(
"""


```