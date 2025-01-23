Response:
The user wants a summary of the functionality of the provided Python code.
This code snippet is part of the `interpreter.py` file in the Frida project, specifically within the `frida-qml` subproject. It seems to be responsible for interpreting the Meson build system's language.

Here's a breakdown of how to approach the task:

1. **Identify the core purpose:** The file is named `interpreter.py`, strongly suggesting its primary function is to interpret Meson build files.

2. **Analyze the functions:** Go through each function definition and understand its role. Look for keywords and patterns that indicate the function's purpose.

3. **Group related functions:** Combine functions that perform similar tasks into logical categories.

4. **Look for interactions with other systems:**  Identify if the code interacts with external systems like compilers, operating systems (Linux, Android), or other build systems (CMake, Cargo).

5. **Note any error handling or validation:**  See if the code performs input validation or handles potential errors.

6. **Consider the context of Frida:**  Remember that this is part of Frida, a dynamic instrumentation toolkit. Look for clues about how the build process might relate to instrumenting processes.

7. **Address the specific questions:** Explicitly answer the questions about reverse engineering, binary/kernel knowledge, logical reasoning, common user errors, and debugging.

8. **Synthesize a concise summary:** Condense the findings into a clear and informative summary.

**Pre-computation and Pre-analysis:**

* **`func_dependency`:** Handles dependency declarations, including internal ones. It deals with include directories, compile/link arguments, libraries, and even other dependencies. This is fundamental for building software.
* **`func_assert`:** Implements an assertion mechanism, likely for validating conditions during the build process.
* **`func_run_command` and `run_command_impl`:**  Executes external commands. This is crucial for running compilers, linkers, and other build tools. The code handles different types of executables (compiled, external, compilers) and file arguments.
* **`func_option`:**  Raises an exception, indicating that options should be defined in a dedicated options file, not directly in the build description.
* **`func_subproject` and related `_do_subproject_*` functions:** Handle the inclusion and management of subprojects, including different build systems like Meson, CMake, and Cargo.
* **`func_get_option` and `get_option_internal`:** Retrieves option values defined for the project or subprojects.
* **`func_configuration_data`:** Creates objects to hold configuration data, useful for generating header files or other configuration files.
* **`set_backend`:**  Determines and configures the build backend (e.g., Ninja, Visual Studio).
* **`func_project`:** Declares the project's metadata (name, version, languages, licenses) and handles the loading of option files.

**Connecting to the Specific Questions:**

* **Reverse Engineering:** The ability to run external commands (`func_run_command`) is relevant. Tools used in reverse engineering could potentially be invoked during the build process. The handling of dependencies is also crucial for understanding the structure of the software being built.
* **Binary/Kernel/Framework Knowledge:** The code interacts with compilers and linkers, which directly deal with generating binary code. The management of dependencies and linking libraries relates to the underlying operating system and potentially kernel interactions. For Android, the build process would need to understand the Android framework.
* **Logical Reasoning:** The conditional logic within functions like `func_assert` and the subproject handling involves logical reasoning based on input values and project structure.
* **User Errors:** The code includes checks for invalid arguments, incorrect option usage, and issues with subproject definitions.
* **Debugging:** Understanding how user actions lead to the execution of these functions is key to debugging build issues. The `func_project` function is a common entry point.

**Drafting the Summary (Internal thought process):**

"Okay, this code is the interpreter for Meson. It handles dependencies, running commands, managing subprojects (including CMake and Cargo ones!), getting options, dealing with project metadata... It seems to be a core part of the build process. It has error checking, so it tries to prevent common mistakes. The subproject stuff is complex, especially with different build systems. Let's put that all together in a concise summary."
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的一部分，它是 Frida 动态 instrumentation 工具中 Meson 构建系统的解释器。  这部分代码主要负责处理 Meson 构建文件中与依赖关系声明、断言、执行外部命令、子项目管理以及项目定义相关的函数。

**功能归纳:**

1. **依赖关系声明 (`func_dependency`):**
   - 处理构建依赖项的声明，包括头文件路径、编译参数、链接参数、库文件、源文件以及其他依赖项。
   - 能够识别项目内部的依赖项，并处理路径相关的逻辑，避免访问到项目外部的目录。
   - 可以处理声明依赖项时的变量。

2. **断言 (`func_assert`):**
   - 提供一种在构建过程中进行条件检查的机制。
   - 如果断言失败，会抛出 `InterpreterException` 异常，并可以包含自定义的消息。
   - 如果没有提供消息，则会尝试打印断言的表达式。

3. **执行外部命令 (`func_run_command`, `run_command_impl`):**
   - 允许在构建过程中执行外部命令，例如编译器、其他构建工具或脚本。
   - 支持多种类型的可执行文件作为命令，包括已编译的目标、外部程序和编译器。
   - 可以捕获命令的输出，并可以设置环境变量。
   - 可以指定命令执行失败时是否报错 (`check` 参数)。
   - 会跟踪作为命令参数的文件，以便在这些文件发生变化时重新运行配置步骤。

4. **子项目管理 (`func_subproject`, `do_subproject`, `_do_subproject_meson`, `_do_subproject_cmake`, `_do_subproject_cargo`):**
   - 允许在当前项目中包含其他 Meson、CMake 或 Cargo 构建的项目作为子项目。
   - 可以指定子项目是否是必需的 (`required`)。
   - 可以为子项目设置默认选项 (`default_options`)。
   - 可以指定所需的子项目版本 (`version`)。
   - 递归地处理子项目依赖，并防止循环依赖。
   - 对于不同类型的子项目 (Meson, CMake, Cargo)，会调用相应的处理函数。

5. **获取选项 (`func_get_option`, `get_option_internal`):**
   - 允许从构建系统中获取已定义的选项的值。
   - 可以获取当前项目或父项目的选项。
   - 针对子项目，会检查选项的访问权限，不允许子项目直接访问其他子项目的选项。
   - 对选项名称进行校验。

6. **配置数据 (`func_configuration_data`):**
   - 创建 `ConfigurationData` 对象，用于存储配置数据，这些数据可以用于生成配置文件。
   - 允许在创建时初始化配置数据。

7. **设置后端 (`set_backend`):**
   - 确定并设置用于实际构建的后端工具 (例如 Ninja, Visual Studio)。
   - 根据用户指定的选项或自动检测来选择后端。

8. **项目定义 (`func_project`):**
   - 定义项目的基本信息，例如项目名称、支持的语言、版本、许可证以及子项目目录。
   - 读取和处理 `meson.options` 或 `meson_options.txt` 文件来设置项目选项。
   - 可以从文件中读取项目版本。
   - 处理项目的许可证信息和许可证文件。
   - 加载项目中的 wrap 文件（用于处理外部依赖）。

**与逆向方法的关联举例说明:**

- **`func_run_command`:** 在逆向工程中，可能需要执行一些外部工具来处理二进制文件，例如反汇编器 (如 `objdump`, `ida`),  代码签名工具，或者用于解包/打包 Android APK 的工具。 `func_run_command` 就可以用来在构建过程中集成这些工具的调用。
  - **假设输入:** `run_command('objdump', '-d', 'my_executable')`
  - **输出:**  一个 `RunProcess` 对象，指示 Meson 在构建时运行 `objdump -d my_executable` 命令。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明:**

- **`func_dependency`:** 当声明链接库时，例如 `libs: ['-lpthread']`，这直接涉及到 Linux 系统中与线程相关的库。在 Android 开发中，可能会链接到 NDK 提供的库，或者 Android Framework 的私有库。
- **`func_run_command`:**  在编译 Android 应用程序时，可能会调用 Android SDK 中的工具，例如 `aapt` (Android Asset Packaging Tool) 来处理资源文件，或者 `dx` 或 `d8` 来将 Java 字节码转换为 Dalvik/ART 字节码。这些工具都与 Android 框架和运行时环境密切相关。
- **`func_project`:**  指定项目支持的语言，例如 `project('MyFridaModule', 'c', 'cpp')`，这决定了要使用的编译器 (gcc/clang) 及其编译选项，这些都直接影响生成的二进制代码。

**逻辑推理的假设输入与输出举例:**

- **`func_assert`:**
  - **假设输入:**  `assert(compiler.has_function('my_important_function'), 'Compiler does not support required function')`，假设 `compiler.has_function('my_important_function')` 返回 `False`。
  - **输出:**  抛出 `InterpreterException`，消息为 "Assert failed: Compiler does not support required function"。

- **`func_subproject`:**
  - **假设输入:**  `subproject('my_external_lib', required: true)`，并且 Meson 无法找到名为 `my_external_lib` 的子项目。
  - **输出:**  抛出 `InterpreterException`，提示找不到必需的子项目。

**涉及用户或者编程常见的使用错误举例说明:**

- **`func_assert`:** 用户可能会忘记添加断言消息，例如 `assert(some_condition)`。代码会提示使用没有消息参数的 `assert` 函数是新特性。
- **`func_run_command`:** 用户可能传递了错误类型的参数，例如将一个整数传递给期望字符串的参数。代码会抛出 `InvalidArguments` 异常，提示参数类型不正确。
- **`func_subproject`:** 用户可能会错误地将子项目名称设置为绝对路径，或者包含 `..` 等非法字符。代码会抛出 `InterpreterException` 指出子项目名称无效。
- **`func_get_option`:** 用户可能会尝试获取不存在的选项，导致 `InterpreterException`。
- **`func_project`:** 在 `meson.build` 文件中多次调用 `project()` 函数会导致 `InvalidCode` 异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户首先需要编写 `meson.build` 文件来描述项目的构建过程，包括定义依赖项、执行命令、包含子项目等。
2. **用户运行 `meson setup` 命令:** 用户在项目根目录下运行 `meson setup <build_directory>` 命令来配置构建环境。
3. **Meson 解析 `meson.build` 文件:** `meson setup` 命令会调用 Meson 的解释器来解析 `meson.build` 文件。
4. **解释器执行相应的函数:** 当解释器遇到例如 `dependency()`, `assert()`, `run_command()`, `subproject()`, `get_option()`, `project()` 等函数调用时，就会调用 `interpreter.py` 文件中相应的 `func_*` 函数。
5. **如果发生错误:** 如果用户在 `meson.build` 文件中使用了错误的语法、提供了无效的参数，或者断言失败，那么在执行到相应的函数时就会抛出异常，并打印错误信息，作为调试线索。例如，如果 `subproject('non_existent_sub')` 被调用且子项目不存在，`func_subproject` 会抛出异常。

**总结这部分代码的功能:**

这部分 `interpreter.py` 文件的核心功能是 **解释和执行 Meson 构建文件中声明的与项目结构、依赖关系、外部命令执行和配置相关的指令**。它负责理解构建作者的意图，并将其转化为构建系统可以理解和执行的操作。  它通过提供一系列内置函数来支持构建过程的各个方面，例如声明依赖、执行外部工具、管理子项目和获取配置选项。同时，它还包含一些错误检查机制，以帮助用户避免常见的构建配置错误。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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