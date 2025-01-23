Response:
My thought process for summarizing the provided Python code snippet goes like this:

1. **Understand the Goal:** The request asks for a summary of the code's functionality, specifically highlighting its relationship to reverse engineering, low-level aspects (kernel, etc.), logical reasoning, common user errors, and debugging. It also specifies that this is part 2 of a 6-part series, so a concise summary is expected.

2. **Initial Scan and Keyword Identification:** I quickly scanned the code, looking for familiar keywords and function names related to build systems, dependency management, execution, and options. Keywords like `declare_dependency`, `assert`, `run_command`, `subproject`, `option`, `project`,  and `configuration_data` stand out.

3. **Group Related Functions:** I started grouping functions based on their apparent purpose:

    * **Dependency Management:** `func_declare_dependency`
    * **Assertions/Error Handling:** `func_assert`, `validate_arguments`
    * **Executing External Commands:** `func_run_command`, `run_command_impl`
    * **Subproject Handling:** `func_subproject`, `disabled_subproject`, `do_subproject`, `_do_subproject_meson`, `_do_subproject_cmake`, `_do_subproject_cargo`
    * **Option Handling:** `func_option`, `get_option_internal`, `func_get_option`
    * **Project Definition:** `func_project`
    * **Configuration Data:** `func_configuration_data`
    * **Backend Setup:** `set_backend`

4. **Analyze Individual Function Purpose:**  For each group, I tried to understand the specific task of each function. For instance:

    * `func_declare_dependency` clearly deals with defining external dependencies for the project.
    * `func_assert` is a standard assertion function for checking conditions during the build process.
    * `func_run_command` is for executing external programs or commands.
    * The `subproject` related functions manage the inclusion and building of subprojects.
    * The `option` related functions handle project configuration options.
    * `func_project` defines the main project's properties.

5. **Connect to the Request's Specific Points:** Now, I revisited the request's specific areas:

    * **Reverse Engineering:**  I considered how these functions might be relevant. The `run_command` function could be used to execute reverse engineering tools. Dependency declarations might involve libraries used in reverse engineering. Subprojects could be reverse-engineered components.
    * **Binary/Low-Level:**  `run_command` could execute tools that manipulate binaries. The subproject mechanism might handle dependencies with low-level code.
    * **Logical Reasoning:** The `assert` function directly involves logical checks. The conditional logic within functions (like handling different subproject types) also demonstrates reasoning.
    * **User Errors:** The code includes error handling (`InterpreterException`, `InvalidArguments`). I looked for examples of what might trigger these. Incorrect argument types, missing dependencies, or incorrect option usage are possibilities.

6. **Synthesize a Summary:**  Based on the above analysis, I started drafting a concise summary, focusing on the main functionalities. I used bullet points for clarity.

7. **Refine and Add Specific Examples:**  I then refined the summary, adding specific examples where possible to illustrate the connections to reverse engineering, low-level aspects, etc. I made sure to mention the error handling and logical flow.

8. **Address the "Part 2" Aspect:** Knowing this is part of a larger series, I ensured the summary was relatively high-level and didn't go into excessive detail.

9. **Review and Edit:** Finally, I reviewed the summary for clarity, accuracy, and conciseness, making sure it addressed all the points in the original request. I paid attention to using precise language. For instance, instead of just saying "handles subprojects," I elaborated slightly to mention different subproject types (Meson, CMake, Cargo).

Essentially, I followed a process of understanding the code's core purpose, breaking it down into manageable chunks, analyzing each chunk's functionality, and then connecting that functionality to the specific requirements of the request. The iterative refinement process helped to polish the summary and make it more comprehensive yet concise.
好的，根据您提供的 Frida 源代码文件 `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreter.py` 的部分内容，以下是其功能的归纳：

**核心功能归纳 (基于提供的代码片段):**

* **依赖声明 (`func_declare_dependency`):**  该函数负责处理依赖关系的声明。它可以接收各种类型的依赖项，例如头文件路径、编译参数、链接参数、库文件、源文件等，并将其封装成 `InternalDependency` 对象。这对于构建过程至关重要，因为它定义了项目编译和链接所需的外部组件。

* **断言 (`func_assert`):**  提供了一种在构建脚本中进行条件检查的机制。如果断言的条件为假，则会抛出 `InterpreterException`，并可以包含自定义的错误消息。这有助于在早期发现构建脚本中的逻辑错误。

* **执行外部命令 (`func_run_command`, `run_command_impl`):**  允许在构建过程中执行外部命令或程序。它可以接收可执行文件、外部程序、编译器对象、文件路径以及字符串作为命令及其参数。  该功能还支持控制命令执行的属性，例如是否检查返回值 (`check`) 和是否捕获输出 (`capture`)。

* **子项目管理 (`func_subproject`, `disabled_subproject`, `do_subproject`, `_do_subproject_meson`, `_do_subproject_cmake`, `_do_subproject_cargo`):**  该部分代码负责处理子项目的集成和构建。它支持不同类型的子项目（Meson, CMake, Cargo），并能处理子项目的依赖、选项和版本控制。这使得大型项目可以模块化，并重用已有的构建逻辑。

* **选项处理 (`func_option`, `get_option_internal`, `func_get_option`):**  虽然 `func_option` 会抛出异常，但 `get_option_internal` 和 `func_get_option` 用于获取用户定义的构建选项的值。这些选项可以影响构建过程的各个方面。

* **项目定义 (`func_project`):**  用于定义项目的基本属性，如名称、版本、使用的编程语言、许可协议以及子项目目录等。这是任何构建脚本的入口点，用于声明项目的元数据。

* **配置数据 (`func_configuration_data`):**  允许创建和管理配置数据对象，用于在构建过程中存储和传递配置信息。

* **后端设置 (`set_backend`):**  负责根据用户指定的选项或自动检测来设置构建后端 (例如 Ninja, Visual Studio)。构建后端负责实际的编译、链接等操作。

**与逆向方法的关联举例：**

* **`func_run_command`:**  在逆向工程中，我们可能需要执行各种工具，例如反汇编器 (如 `objdump`, `ida`),  调试器 (如 `gdb`, `lldb`),  或者用于分析二进制文件的自定义脚本。`func_run_command` 可以用来集成这些工具到构建流程中。
    * **假设输入:** `run_command('objdump', '-d', 'target_binary')`
    * **输出:**  执行 `objdump -d target_binary` 命令，其输出可能被捕获用于进一步分析或生成报告。

**涉及二进制底层、Linux、Android 内核及框架的知识举例：**

* **`func_declare_dependency` (链接库):**  在构建涉及底层操作的 Frida 组件时，可能需要链接到特定的系统库或内核模块。例如，与 Linux 内核交互可能需要链接 `libkmod`。在 Android 上，可能需要链接到 Bionic C 库或 Android 框架的特定库。
    * **举例:** 声明一个链接到 `libdl` 的依赖： `declare_dependency(libs=['dl'])`。`libdl` 是一个标准的 POSIX 库，用于动态加载库，这在动态插桩场景中非常常见。

* **`func_run_command` (执行内核相关的工具):**  在 Android 或 Linux 环境下，可能需要执行一些与内核交互的工具，例如 `adb` (Android Debug Bridge) 命令来与 Android 设备通信，或者使用 `insmod`/`rmmod` 来加载/卸载内核模块。
    * **假设输入 (Android):** `run_command('adb', 'push', 'frida-agent.so', '/data/local/tmp/')`
    * **输出:** 将 Frida agent 推送到 Android 设备的临时目录。

**逻辑推理的假设输入与输出：**

* **`func_assert`:**  假设我们希望在构建脚本中确保某个重要的环境变量已经被设置。
    * **假设输入:**  `func_assert(os.environ.get('ANDROID_HOME') is not None, '环境变量 ANDROID_HOME 未设置')`
    * **输出:** 如果环境变量 `ANDROID_HOME` 存在，则断言通过，构建继续。否则，抛出 `InterpreterException`，并显示错误消息 "环境变量 ANDROID_HOME 未设置"。

**涉及用户或编程常见的使用错误举例：**

* **`func_run_command` (路径错误):** 用户可能会错误地指定外部命令的路径。
    * **错误示例:** `run_command('my_custom_tool', 'input.txt')`，如果 `my_custom_tool` 不在系统的 PATH 环境变量中，或者当前工作目录中不存在，则会导致命令执行失败。Meson 会尝试查找该命令，如果找不到则会报错。

* **`func_declare_dependency` (类型错误):**  用户可能会传递错误的类型给 `declare_dependency` 的参数。
    * **错误示例:**  `declare_dependency(incs='include_dir')`，这里 `incs` 应该是一个包含头文件路径的列表，而不是单个字符串。Meson 的类型检查会捕获这种错误并抛出 `InvalidArguments` 异常。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户执行 Meson 构建命令:**  通常用户会执行类似 `meson build` 或 `ninja` 命令来触发构建过程。

2. **Meson 解析构建文件:** Meson 首先会解析项目根目录下的 `meson.build` 文件，以及可能存在的 `meson_options.txt` 或 `meson.options` 文件。

3. **遇到 `declare_dependency` 等函数调用:**  在解析 `meson.build` 文件时，Meson 的解释器 (`interpreter.py`) 会逐行执行代码，当遇到诸如 `declare_dependency`, `run_command`, `subproject` 等函数调用时，就会进入到 `interpreter.py` 中相应的函数进行处理。

4. **参数传递和逻辑执行:** 用户在 `meson.build` 文件中传递的参数会被传递到这些函数中。例如，如果用户在 `meson.build` 中写了 `declare_dependency(libs=['mylib'])`，那么 `interpreter.py` 中的 `func_declare_dependency` 函数就会接收到 `libs=['mylib']` 这个参数。

5. **错误发生和调试:** 如果用户在 `meson.build` 中编写了错误的代码（例如，传递了错误的参数类型，或者调用的外部命令不存在），那么 `interpreter.py` 中的错误处理机制（例如 `InterpreterException`, `InvalidArguments`）会被触发，并产生相应的错误信息。这些错误信息可以帮助用户定位问题所在，并作为调试的线索。例如，如果 `run_command` 找不到指定的命令，Meson 会报告 "Program or command '...' not found or not executable"。

**总结：**

总的来说，`interpreter.py` 文件在 Frida 的构建系统中扮演着核心的解释器角色。它负责解析 `meson.build` 文件，处理依赖关系、执行外部命令、管理子项目、处理构建选项以及定义项目属性。它的功能与逆向工程、底层系统交互密切相关，并提供了强大的灵活性来定制构建流程。 开发者在编写 `meson.build` 文件时与此文件中的函数进行交互，任何语法或逻辑错误都会在此文件中被捕获和报告，为调试提供了关键信息。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
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
```