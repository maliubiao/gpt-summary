Response:
The user wants a summary of the functionality of the provided Python code snippet, which is a part of the Frida dynamic instrumentation tool. The code belongs to the `interpreter.py` file within the Meson build system integration of Frida.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the Core Purpose:** The file name and path (`frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/interpreter.py`) suggest this code is responsible for interpreting Meson build files within the Frida project. This interpreter is likely used to configure and generate the build system for Frida.

2. **Analyze Individual Functions:**  Go through each function in the provided snippet and understand its role.

    * `func_declare_dependency`: Handles the declaration of dependencies. It parses the dependency information and creates an `InternalDependency` object. It checks for valid path and variable values.
    * `func_assert`: Implements an assertion function, raising an exception if a condition is false.
    * `validate_arguments`:  A utility function to check the number and types of arguments passed to a function.
    * `func_run_command` and `run_command_impl`:  Execute external commands during the build process. This is crucial for tasks like code generation, testing, etc. It handles different types of commands (executables, external programs, compilers).
    * `func_option`:  Raises an error because options should be defined in option files, not directly in build files.
    * `func_subproject` and `do_subproject`: Handle the inclusion and processing of subprojects within the main project. They manage dependencies, versions, and different build systems (Meson, CMake, Cargo) for subprojects.
    * `disabled_subproject`: Creates a placeholder for a disabled subproject.
    * `_do_subproject_meson`, `_do_subproject_cmake`, `_do_subproject_cargo`:  Implement the specific logic for handling Meson, CMake, and Cargo subprojects, respectively.
    * `get_option_internal` and `func_get_option`:  Retrieve the values of build options. They manage the hierarchy of options between the main project and subprojects.
    * `func_configuration_data`: Creates a `ConfigurationData` object, which can hold configuration settings.
    * `set_backend`:  Determines and sets the build backend (e.g., Ninja, Visual Studio).
    * `func_project`:  Handles the `project()` function call in Meson build files, defining project name, version, languages, and other project-level settings. It also deals with loading option files.

3. **Identify Connections to Reverse Engineering, Binary Level, and Kernel Knowledge:**

    * **Reverse Engineering:** The ability to `run_command` is directly related to reverse engineering. Tools used for analysis, disassembly, or patching could be executed as part of the build process. The `subproject` functionality allows integrating external projects, some of which might be reverse engineering tools or libraries.
    * **Binary Level:**  The code interacts with compilers (`compilers.Compiler`), external programs (`ExternalProgram`), and executables (`build.Executable`). This signifies operations at the binary level, such as compilation and linking. The handling of different subproject types (like Cargo for Rust) also involves binary-level operations.
    * **Kernel/Framework:** While this specific code snippet doesn't directly manipulate kernel code, Frida itself *is* a dynamic instrumentation tool heavily involved with kernel and framework interactions. This Meson code is part of the build process for Frida, so it indirectly supports those capabilities. The `declare_dependency` functionality can handle dependencies on libraries or components that interact with the kernel or specific frameworks (e.g., Android).

4. **Infer Logical Reasoning and Assumptions:**

    * **Dependency Handling:** The code assumes dependencies have versions, include directories, libraries, etc. It performs checks for valid paths and versions. The `subproject` functions implement logic to avoid recursive subproject inclusions.
    * **Command Execution:** The `run_command` functions assume that the provided commands and arguments are valid and executable. They also handle environment variables and capture the output of commands.
    * **Option Handling:** The option functions assume that options are defined in a specific way and follow a hierarchy between projects and subprojects.

5. **Consider User Errors:**

    * **Incorrect Argument Types/Counts:** The `validate_arguments` function highlights a common error: providing the wrong number or type of arguments to a Meson function.
    * **Invalid Option Names:** The code checks for invalid characters in option names.
    * **Incorrect Subproject Configuration:**  Errors in subproject names, recursive inclusions, or missing required subprojects are checked.
    * **Using `option()` in the wrong place:**  The `func_option` enforces that options are defined in option files.
    * **Mixing `meson.options` and `meson_options.txt`:** The code detects and reports errors if both files exist and are different.

6. **Trace User Operations:**  How does a user end up executing this code?

    * **Initial Setup:** The user first installs Meson and configures a build directory (e.g., `meson build`).
    * **Meson Invocation:** When the user runs `meson build`, Meson starts parsing the `meson.build` file in the source directory.
    * **Interpreter Execution:** Meson's interpreter (including this code) processes the `meson.build` file line by line, executing functions like `project()`, `declare_dependency()`, `subproject()`, `run_command()`, etc.
    * **Subproject Entry:** If the `meson.build` file includes `subproject()`, this code handles the logic to find and process the subproject's `meson.build` file.

7. **Synthesize the Summary:** Combine the information gathered in the previous steps into a concise summary of the file's functions. Group related functionalities together (e.g., dependency management, subproject handling, command execution). Emphasize the connections to reverse engineering, binary operations, and kernel knowledge where applicable.

8. **Refine and Organize:** Review the summary for clarity, accuracy, and completeness. Organize the points logically, perhaps starting with the core function and then moving to more specific aspects. Ensure the examples are relevant and easy to understand.
这是 `frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的第 2 部分，主要功能是 Meson 构建系统解释器的核心逻辑，用于解析 `meson.build` 文件，并执行其中定义的构建指令。本部分涵盖了依赖声明、断言、命令执行、子项目处理以及项目定义等关键功能。

以下是本部分代码的功能归纳：

**核心构建逻辑和功能：**

1. **依赖声明 (`func_declare_dependency`):**
   - 用于声明项目依赖。
   - 可以指定依赖的版本、头文件路径、编译参数、链接参数、库文件、源文件等信息。
   - 可以处理依赖项中的变量，并区分项目内和外部的路径。
   - 创建 `InternalDependency` 对象来表示依赖关系。

2. **断言 (`func_assert`):**
   - 提供了一个 `assert` 函数，用于在构建过程中进行条件检查。
   - 如果断言失败，会抛出 `InterpreterException` 异常，可以包含自定义的错误消息。
   - 如果没有提供错误消息，会尝试从断言的表达式中提取信息。

3. **参数验证 (`validate_arguments`):**
   - 一个内部辅助函数，用于验证函数调用时参数的数量和类型是否符合预期。

4. **执行外部命令 (`func_run_command`, `run_command_impl`):**
   - 允许在构建过程中执行外部命令。
   - 可以执行可执行文件、外部程序、编译器以及脚本文件。
   - 支持捕获命令输出 (`capture` 参数)。
   - 支持设置环境变量 (`env` 参数)。
   - 可以指定命令是否需要成功执行 (`check` 参数)。
   - 会跟踪作为命令参数的文件，以便在这些文件发生变化时重新运行构建。
   - 对不同类型的命令参数（字符串、文件、外部程序、编译器）进行处理。

5. **选项处理 (`func_option`):**
   - 此函数被设计为抛出异常。Meson 的设计原则是将构建选项定义在专门的选项文件中（如 `meson_options.txt` 或 `meson.options`），而不是直接在 `meson.build` 文件中。

6. **子项目处理 (`func_subproject`, `do_subproject`, `disabled_subproject`, `_do_subproject_meson`, `_do_subproject_cmake`, `_do_subproject_cargo`):**
   - 允许在主项目中包含和构建其他独立的 Meson、CMake 或 Cargo 项目作为子项目。
   - `func_subproject` 是 `subproject()` 函数的入口，用于声明一个子项目。
   - `do_subproject` 负责处理子项目的查找、版本检查和构建过程。
   - `disabled_subproject` 用于处理被禁用的子项目。
   - `_do_subproject_meson`、`_do_subproject_cmake`、`_do_subproject_cargo` 分别处理 Meson、CMake 和 Cargo 子项目的具体构建流程，包括解析子项目的构建文件和执行构建命令。
   - 可以指定子项目是否是必需的 (`required` 参数)。
   - 可以指定子项目的默认选项 (`default_options` 参数)。
   - 可以指定子项目的版本要求 (`version` 参数)。
   - 实现了递归子项目包含的检测。
   - 集成了 `wrap` 工具来处理子项目的依赖和构建包装器。

7. **获取选项 (`get_option_internal`, `func_get_option`):**
   - 用于获取构建选项的值。
   - `func_get_option` 是 `get_option()` 函数的入口。
   - 可以获取项目级别和子项目级别的选项。
   - 提供了对选项名称格式的验证。
   - 处理了选项值的类型转换。

8. **配置数据 (`func_configuration_data`):**
   - 创建 `ConfigurationData` 对象，用于存储配置数据，这些数据可以在构建过程中使用。
   - 可以通过字典初始化配置数据。

9. **设置构建后端 (`set_backend`):**
   - 确定并设置 Meson 使用的构建后端（例如 Ninja、Visual Studio）。
   - 会根据用户指定的选项或自动检测来选择合适的后端。

10. **项目定义 (`func_project`):**
    - 处理 `project()` 函数调用，用于定义项目的基本信息。
    - 可以设置项目名称、支持的编程语言、版本、许可证、子项目目录等。
    - 负责加载项目级别的选项文件 (`meson_options.txt` 或 `meson.options`)。
    - 处理项目级别的默认选项。
    - 存储项目的版本和许可证信息。
    - 处理子项目目录的设置。
    - 集成了 `wrap` 工具来处理项目的依赖和构建包装器。

**与逆向方法的关系：**

- **执行外部命令 (`func_run_command`):**  在逆向工程中，可能需要在构建过程中运行一些分析工具或脚本。例如：
    - **假设输入:**  在 `meson.build` 中调用 `run_command('objdump', '-d', 'my_executable', capture=True)`。
    - **功能:**  这会执行 `objdump -d my_executable` 命令，并将反汇编结果捕获。
    - **逆向意义:** 可以用于在构建时获取二进制文件的反汇编代码，进行静态分析。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

- **执行外部命令 (`func_run_command`):**  该功能直接涉及到与操作系统底层的交互，需要理解如何执行二进制文件。
    - **编译过程:**  例如，当执行 `run_command(compiler, source_file, '-o', 'output_file')` 时，需要了解编译器的工作原理和命令行参数。
    - **链接过程:** 同样，链接器 (`ld`) 的执行也通过 `run_command` 完成，需要理解二进制文件的链接过程。
- **依赖声明 (`func_declare_dependency`):**
    - **库文件 (`libs`)**:  指定链接时需要用到的库文件，这些库文件通常是二进制形式的。在 Linux 或 Android 环境下，这些可能是 `.so` 文件。
    - **头文件路径 (`incs`)**:  指定头文件的搜索路径，这些头文件定义了二进制接口。
- **子项目处理 (`_do_subproject_cmake`, `_do_subproject_cargo`):**
    - CMake 和 Cargo 都是构建系统，它们最终都会生成二进制文件或库。理解这些构建系统的工作方式有助于理解 Frida 的构建过程。
- **设置构建后端 (`set_backend`):**  选择不同的构建后端（如 Ninja 或 Visual Studio）会影响最终生成二进制文件的方式和格式。

**逻辑推理（假设输入与输出）：**

- **`func_assert`:**
    - **假设输入:** `assert(variable == 5, 'Variable is not 5')`，如果 `variable` 的值不是 5。
    - **输出:** 抛出 `InterpreterException: Assert failed: Variable is not 5`。
- **`func_declare_dependency`:**
    - **假设输入:** `declare_dependency(include_directories: 'include', libraries: 'mylib')`。
    - **输出:** 创建一个 `InternalDependency` 对象，其中包含了头文件路径和库文件的信息。
- **`func_run_command`:**
    - **假设输入:** `run_command('ls', '-l', '/tmp', capture=True)`。
    - **输出:** 执行 `ls -l /tmp` 命令，并返回一个 `RunProcess` 对象，其中包含了命令的执行结果（包括输出）。
- **`func_subproject`:**
    - **假设输入:** `subproject('my_subproject', required: true)`，并且子项目存在。
    - **输出:**  会解析并执行 `my_subproject` 目录下的 `meson.build` 文件，并将子项目的构建结果集成到主项目中。如果子项目不存在或构建失败且 `required` 为 `true`，则会抛出异常。

**涉及用户或编程常见的使用错误：**

- **`func_assert`:**
    - **错误示例:** `assert(variable = 5)`  （将 `==` 误写为 `=`，导致赋值而不是比较）。Meson 可能会报错，但这里的断言逻辑只检查布尔值。
    - **说明:** 用户可能会写出逻辑错误的断言条件。
- **`func_run_command`:**
    - **错误示例:** `run_command('my_script.sh')`，但 `my_script.sh` 没有执行权限。
    - **说明:** 用户可能会尝试执行没有执行权限的文件。
    - **错误示例:** `run_command('non_existent_command')`.
    - **说明:** 用户可能会尝试执行不存在的命令。
    - **错误示例:** 传递了错误类型的参数，例如 `run_command(123)`.
    - **说明:** `typed_pos_args` 装饰器会捕获这种错误。
- **`func_option`:**
    - **错误示例:** 在 `meson.build` 文件中调用 `option('my_option', type: 'string', default: 'value')`.
    - **说明:** 用户尝试在错误的地点定义构建选项。
- **`func_subproject`:**
    - **错误示例:** `subproject('../another_project')` (使用相对路径超出当前项目)。
    - **说明:** 用户可能使用了不合法的子项目路径。
    - **错误示例:** 循环依赖，例如 A 子项目依赖 B 子项目，B 子项目又依赖 A 子项目。
    - **说明:** Meson 会检测并报错。
- **`func_get_option`:**
    - **错误示例:** `get_option('non_existent_option')`.
    - **说明:** 用户尝试获取不存在的构建选项。
    - **错误示例:** 在子项目中尝试直接访问其他子项目的选项 (选项名中包含冒号)。
    - **说明:** Meson 限制了跨子项目直接访问选项。
- **`func_project`:**
    - **错误示例:** 多次调用 `project()` 函数。
    - **说明:** `func_project` 中会检查并抛出 `InvalidCode` 异常。
    - **错误示例:** `project('myproject:')` (项目名称包含冒号)。
    - **说明:** 项目名称有非法字符。

**用户操作如何一步步的到达这里（调试线索）：**

1. **用户编写 `meson.build` 文件:** 用户创建或修改 `meson.build` 文件，其中包含了项目定义、依赖声明、子项目引用、外部命令执行等指令。
2. **用户运行 `meson` 命令:** 用户在项目根目录或构建目录下运行 `meson <build_directory>` 命令来配置构建。
3. **Meson 解析 `meson.build`:** Meson 读取并解析 `meson.build` 文件。
4. **解释器执行:**  `interpreter.py` 中的代码（包括本部分）作为 Meson 的解释器，逐行执行 `meson.build` 文件中的函数调用，例如：
   - 当遇到 `declare_dependency()` 时，会调用 `func_declare_dependency`。
   - 当遇到 `assert()` 时，会调用 `func_assert`。
   - 当遇到 `run_command()` 时，会调用 `func_run_command`。
   - 当遇到 `subproject()` 时，会调用 `func_subproject`，并可能进一步调用 `_do_subproject_meson`、`_do_subproject_cmake` 或 `_do_subproject_cargo`。
   - 当遇到 `project()` 时，会调用 `func_project`。
   - 当遇到 `get_option()` 时，会调用 `func_get_option`。
5. **构建系统生成:** 解释器执行完毕后，Meson 会根据解释结果生成底层的构建系统文件（例如 Ninja 的 `build.ninja` 文件）。

作为调试线索，如果用户在构建过程中遇到错误，例如：

- **断言失败:**  错误信息会指向 `func_assert` 以及断言失败的条件和可能的消息。
- **执行外部命令失败:** 错误信息会包含失败的命令和返回码，可以追溯到 `func_run_command` 的调用。
- **子项目处理错误:** 错误信息会指示哪个子项目处理失败，可以查看 `func_subproject` 及其相关函数的执行过程。
- **选项错误:**  错误信息会指出哪个选项设置或获取时出现问题，可以检查 `func_option` 或 `func_get_option` 的相关逻辑。
- **项目定义错误:** 错误信息会指向 `func_project`，例如重复定义项目或项目名称非法。

总而言之，本部分代码是 Meson 构建系统解释器的核心，负责理解和执行 `meson.build` 文件中定义的高级构建指令，并将这些指令转化为实际的构建操作。它处理了项目依赖、外部命令、子项目管理、选项配置等关键方面，是构建流程的基石。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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