Response:
The user wants a summary of the functionality of the provided Python code. The code is a part of the Meson build system, specifically the interpreter that processes `meson.build` files. I need to analyze the methods in the `Interpreter` class and describe what they do.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file is located in `mesonbuild/interpreter/interpreter.py`, which strongly suggests its primary function is interpreting the build definition language.

2. **Examine the class name:** The main class is `Interpreter`. This confirms the core purpose.

3. **Analyze individual methods:** Go through each method and understand its role. Group related functionalities.

4. **Look for keywords and patterns:**
    * Methods starting with `func_` are likely implementing built-in functions of the Meson language (e.g., `func_message`, `func_find_program`).
    * Methods dealing with languages (e.g., `add_languages`, `add_languages_for`) are related to compiler management.
    * Methods involving "program" (e.g., `find_program_impl`, `program_from_file_for`) are related to finding external executables.
    * Methods with "build" in the name (e.g., `build_target`, `build_library`) are related to defining build targets.
    * Methods with "summary" or "message" deal with user feedback.
    * Methods related to "dependency" handle external library dependencies.
    * Methods related to "error" and "warning" handle reporting issues.

5. **Connect to reverse engineering (if applicable):** Frida is a dynamic instrumentation toolkit used for reverse engineering. While this specific file doesn't directly *perform* instrumentation, it's part of the build process. Understanding how Frida is built can be helpful in reverse engineering it. Specifically, finding external tools (`find_program`) and managing dependencies (`func_dependency`) are relevant to setting up the build environment for a reverse engineering tool.

6. **Connect to low-level concepts (if applicable):** The code deals with compilers, linkers, and different target types (executable, shared library, etc.). These are core concepts in low-level programming and operating systems (Linux, Android). The management of host and build machines also hints at cross-compilation scenarios relevant in Android development.

7. **Identify logical reasoning:**  The `expect_error` function and the logic within `find_program_impl` (checking overrides, system paths, fallback mechanisms) involve conditional logic and decision-making based on various inputs.

8. **Consider user errors:**  The code handles missing programs or dependencies, incorrect function arguments, and overriding already found executables. These are common user errors during the build process.

9. **Trace user actions:**  Think about how a user interacts with Meson. They write a `meson.build` file, and then run `meson setup`. This triggers the interpreter to process the `meson.build` file, which would involve calling the functions in this code.

10. **Structure the summary:**  Organize the findings into logical categories based on the identified functionalities.

11. **Refine the language:** Use clear and concise language to describe the functionality. Provide specific examples where relevant.

By following these steps, I can systematically analyze the code and generate a comprehensive and informative summary that addresses all the user's requests.
这是frida构建系统中负责解释 `meson.build` 文件的关键部分。该文件的核心功能是**解析和执行 `meson.build` 文件中的指令，从而定义项目的构建过程**。

以下是该文件功能的详细列举，并结合您提出的特定角度进行说明：

**主要功能概述：**

1. **构建定义解析和执行:**  `Interpreter` 类负责读取 `meson.build` 文件，解析其中的语法结构（例如函数调用、变量赋值等），并执行这些指令。这是 Meson 构建过程的核心。

2. **项目元数据管理:**  它管理项目的名称、版本、使用的编程语言等基本信息。

3. **编译器管理:**  负责探测和配置用于构建项目的编译器（例如 GCC、Clang、MSVC）。它可以添加和管理不同目标平台（主机和构建平台）的编译器。

4. **依赖项管理:**  处理项目依赖的外部库和程序，包括查找依赖项、处理回退机制等。

5. **构建目标定义:**  允许用户定义各种构建目标，例如可执行文件、静态库、共享库、模块等。

6. **消息和摘要输出:**  提供向用户输出信息（例如消息、警告、错误、构建摘要）的功能。

7. **子项目管理:**  支持包含和管理子项目，使得大型项目可以模块化。

8. **配置选项处理:**  处理用户通过命令行或其他方式提供的配置选项。

9. **环境管理:**  管理构建环境，包括源目录、构建目录等。

**与逆向方法的关系：**

*   **查找外部工具 (`func_find_program`):** 在逆向工程中，经常需要使用各种工具，例如反汇编器、调试器、打包工具等。`func_find_program` 允许在构建脚本中查找这些工具，并确保它们存在且可执行。
    *   **举例说明:**  Frida 的构建过程可能需要查找 `make`、`cmake`、`python` 等工具。`meson.build` 文件中可能会有类似 `program('make')` 的调用来确保 `make` 命令可用。这与逆向分析师在搭建逆向环境时需要确保特定工具存在是类似的。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

*   **编译器和链接器管理 (`add_languages`, `add_languages_for`):**  编译和链接是将源代码转换为可执行二进制文件的关键步骤，涉及到处理目标文件、符号表、库依赖等底层概念。在交叉编译（例如为 Android 构建 Frida）时，需要正确配置目标架构的编译器和链接器。
    *   **举例说明:** 为 Android 构建 Frida 需要使用 Android NDK 提供的交叉编译工具链。`add_languages` 函数会探测或指定这些工具链中的 C/C++ 编译器（例如 `arm-linux-androideabi-gcc` 或 `aarch64-linux-android-clang`）和链接器。
*   **构建目标类型 (`func_executable`, `func_shared_library`, `func_shared_module`):**  这些函数对应于不同类型的二进制输出。理解这些类型（例如，共享库在运行时如何加载，模块的特性）对于理解 Frida 的架构和工作方式至关重要。在 Android 上，Frida 会注入到目标进程中，这通常涉及到共享库或模块的加载。
    *   **举例说明:** Frida 的核心组件 `frida-agent` 通常会被构建为共享库 (`.so` 文件)，以便注入到目标进程中。`func_shared_library` 用于定义如何构建这个共享库，包括源文件、链接的库等。
*   **依赖项查找 (`func_dependency`):** Frida 依赖于一些底层的库，例如 `glib`。在为 Linux 或 Android 构建时，需要找到这些库的头文件和库文件。这个函数处理查找这些依赖项的过程，并可能需要考虑不同的查找方法和平台特定的路径。
    *   **举例说明:** 在为 Android 构建 Frida 时，可能需要找到 Android 系统库或 NDK 提供的库。`func_dependency` 可以配置为查找特定路径或使用 `pkg-config` 等工具来定位这些库。

**逻辑推理 (假设输入与输出):**

*   **`func_find_program`:**
    *   **假设输入:** `meson.build` 文件中包含 `find_program('python3')`。
    *   **假设输出:** 如果系统中存在可执行的 `python3`，该函数将返回一个表示 `python3` 执行路径的对象 (`ExternalProgram` 的实例)。如果找不到，且 `required=True`，则会抛出异常；如果 `required=False`，则返回一个表示未找到程序的对象 (`NonExistingExternalProgram` 的实例)。
*   **`func_dependency`:**
    *   **假设输入:** `meson.build` 文件中包含 `dependency('openssl')`。
    *   **假设输出:** 如果系统中安装了 OpenSSL 开发包，该函数将返回一个表示 OpenSSL 依赖项的对象 (`Dependency` 的实例)，其中包含 OpenSSL 的头文件路径、库文件路径等信息。如果找不到，且没有指定 `allow_fallback` 或回退机制失败，则会抛出异常。

**用户或编程常见的使用错误：**

*   **`func_find_program` 找不到程序:** 用户在 `meson.build` 中使用了 `find_program` 查找一个不存在或不在系统路径中的程序，且没有设置 `required=False`。
    *   **举例说明:**  `find_program('non_existent_tool')` 将会导致构建失败，并提示 "Program 'non_existent_tool' not found or not executable"。
*   **`func_dependency` 找不到依赖项:** 用户声明了一个依赖项，但 Meson 无法在系统中找到对应的开发包。
    *   **举例说明:** `dependency('missing_lib')` 将会导致构建失败，并可能提示类似 "Dependency missing_lib found: NO (tried pkgconfig)" 的信息。
*   **`add_languages` 指定了错误的语言:** 用户尝试添加一个 Meson 不支持的编程语言。
    *   **举例说明:** `add_languages('foobar')` 将会导致构建失败，并提示 "Tried to use unknown language 'foobar'."
*   **重复定义构建目标:** 用户在 `meson.build` 文件中定义了两个同名的构建目标。
    *   **举例说明:** 定义了两个名为 `my_executable` 的可执行文件会导致错误。
*   **在 `expect_error` 上下文中代码执行成功:** 用户使用了 `expect_error` 期望某段代码抛出异常，但实际执行过程中没有抛出任何异常。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户编写 `meson.build` 文件:**  用户根据项目需求编写 `meson.build` 文件，其中包含了项目名称、版本、依赖项、构建目标等信息。
2. **用户运行 `meson setup <build_directory>`:**  用户在终端中执行 `meson setup` 命令，指定构建目录。
3. **Meson 解析 `meson.build`:** Meson 读取 `meson.build` 文件，并将其内容传递给 `interpreter.py` 中的 `Interpreter` 类的实例。
4. **`Interpreter` 执行指令:**  `Interpreter` 类逐行解析和执行 `meson.build` 文件中的指令。
    *   如果遇到 `project()` 函数，会记录项目名称和版本。
    *   如果遇到 `add_languages()` 函数，会尝试探测和配置编译器。
    *   如果遇到 `find_program()` 函数，会尝试在系统中查找指定的程序。
    *   如果遇到 `dependency()` 函数，会尝试查找指定的依赖项。
    *   如果遇到 `executable()`, `shared_library()` 等函数，会定义相应的构建目标。
5. **生成构建系统:**  `Interpreter` 执行完所有指令后，Meson 会根据这些指令生成底层的构建系统（例如 Ninja 构建文件）。

在调试过程中，如果构建失败，可以查看 Meson 的输出日志，其中会包含 `interpreter.py` 中执行的各个函数的信息，以及遇到的错误和警告。例如，如果 `find_program` 找不到某个程序，日志中会显示相关的错误信息，可以帮助用户定位问题。

**归纳其功能 (第3部分):**

作为总共 6 个部分中的第 3 部分，这个 `interpreter.py` 文件主要负责 **构建定义文件的解释和初步处理**。它将用户编写的 `meson.build` 文件转化为 Meson 内部可以理解和处理的数据结构和指令。这个阶段的核心任务包括：

*   **理解项目结构和需求:** 从 `meson.build` 文件中提取项目的基本信息、使用的语言、依赖项和需要构建的目标。
*   **准备构建环境:**  探测和配置必要的构建工具（编译器、链接器等），并检查依赖项的可用性。
*   **初步构建计划:**  根据 `meson.build` 中的定义，构建出一个初步的构建计划，为后续的构建系统生成阶段做准备。

简单来说，`interpreter.py` 就像一个翻译器和初步规划者，它将用户的构建意图转化为 Meson 能够执行的指令，并为实际的构建过程奠定基础。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
'backend'))
            vsenv = self.coredata.get_option(OptionKey('vsenv'))
            force_vsenv = vsenv or backend.startswith('vs')
            mesonlib.setup_vsenv(force_vsenv)

        self.add_languages(proj_langs, True, MachineChoice.HOST)
        self.add_languages(proj_langs, False, MachineChoice.BUILD)

        self.set_backend()
        if not self.is_subproject():
            self.check_stdlibs()

    @typed_kwargs('add_languages', KwargInfo('native', (bool, NoneType), since='0.54.0'), REQUIRED_KW)
    @typed_pos_args('add_languages', varargs=str)
    def func_add_languages(self, node: mparser.FunctionNode, args: T.Tuple[T.List[str]], kwargs: 'kwtypes.FuncAddLanguages') -> bool:
        langs = args[0]
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject)
        native = kwargs['native']

        if disabled:
            for lang in sorted(langs, key=compilers.sort_clink):
                mlog.log('Compiler for language', mlog.bold(lang), 'skipped: feature', mlog.bold(feature), 'disabled')
            return False
        if native is not None:
            return self.add_languages(langs, required, self.machine_from_native_kwarg(kwargs))
        else:
            # absent 'native' means 'both' for backwards compatibility
            tv = FeatureNew.get_target_version(self.subproject)
            if FeatureNew.check_version(tv, '0.54.0'):
                mlog.warning('add_languages is missing native:, assuming languages are wanted for both host and build.',
                             location=node)

            success = self.add_languages(langs, False, MachineChoice.BUILD)
            success &= self.add_languages(langs, required, MachineChoice.HOST)
            return success

    def _stringify_user_arguments(self, args: T.List[TYPE_var], func_name: str) -> T.List[str]:
        try:
            return [stringifyUserArguments(i, self.subproject) for i in args]
        except InvalidArguments as e:
            raise InvalidArguments(f'{func_name}(): {str(e)}')

    @noArgsFlattening
    @noKwargs
    def func_message(self, node: mparser.BaseNode, args, kwargs):
        if len(args) > 1:
            FeatureNew.single_use('message with more than one argument', '0.54.0', self.subproject, location=node)
        args_str = self._stringify_user_arguments(args, 'message')
        self.message_impl(args_str)

    def message_impl(self, args):
        mlog.log(mlog.bold('Message:'), *args)

    @noArgsFlattening
    @FeatureNew('summary', '0.53.0')
    @typed_pos_args('summary', (str, dict), optargs=[object])
    @typed_kwargs(
        'summary',
        KwargInfo('section', str, default=''),
        KwargInfo('bool_yn', bool, default=False),
        KwargInfo('list_sep', (str, NoneType), since='0.54.0')
    )
    def func_summary(self, node: mparser.BaseNode, args: T.Tuple[T.Union[str, T.Dict[str, T.Any]], T.Optional[T.Any]],
                     kwargs: 'kwtypes.Summary') -> None:
        if self.coredata.is_build_only:
            return
        if args[1] is None:
            if not isinstance(args[0], dict):
                raise InterpreterException('Summary first argument must be dictionary.')
            values = args[0]
        else:
            if not isinstance(args[0], str):
                raise InterpreterException('Summary first argument must be string.')
            values = {args[0]: args[1]}
        self.summary_impl(kwargs['section'], values, kwargs)

    def summary_impl(self, section: str, values, kwargs: 'kwtypes.Summary') -> None:
        if self.subproject not in self.summary:
            self.summary[self.subproject] = Summary(self.active_projectname, self.project_version)
        self.summary[self.subproject].add_section(
            section, values, kwargs['bool_yn'], kwargs['list_sep'], self.subproject)

    def _print_subprojects(self, for_machine: MachineChoice) -> None:
        # Add automatic 'Subprojects' section in main project.
        all_subprojects = collections.OrderedDict()
        for name, subp in sorted(self.subprojects[for_machine].items()):
            value = [subp.found()]
            if subp.disabled_feature:
                value += [f'Feature {subp.disabled_feature!r} disabled']
            elif subp.exception:
                value += [str(subp.exception)]
            elif subp.warnings > 0:
                value += [f'{subp.warnings} warnings']
            if subp.callstack:
                stack = ' => '.join(subp.callstack)
                value += [f'(from {stack})']
            all_subprojects[name] = value
        if all_subprojects:
            self.summary_impl(f'Subprojects (for {for_machine.get_lower_case_name()} machine)', all_subprojects,
                              {'bool_yn': True,
                               'list_sep': ' ',
                               })

    def _print_summary(self) -> None:
        self._print_subprojects(MachineChoice.HOST)
        if self.environment.is_cross_build():
            self._print_subprojects(MachineChoice.BUILD)
        # Add automatic section with all user defined options
        if self.user_defined_options:
            values = collections.OrderedDict()
            if self.user_defined_options.cross_file:
                values['Cross files'] = self.user_defined_options.cross_file
            if self.user_defined_options.native_file:
                values['Native files'] = self.user_defined_options.native_file
            sorted_options = sorted(self.user_defined_options.cmd_line_options.items())
            values.update({str(k): v for k, v in sorted_options})
            if values:
                self.summary_impl('User defined options', values, {'bool_yn': False, 'list_sep': None})
        # Print all summaries, main project last.
        mlog.log('')  # newline
        main_summary = self.summary.pop('', None)
        for subp_name, summary in sorted(self.summary.items()):
            if self.subprojects.host[subp_name].found():
                summary.dump()
        if main_summary:
            main_summary.dump()

    @noArgsFlattening
    @FeatureNew('warning', '0.44.0')
    @noKwargs
    def func_warning(self, node, args, kwargs):
        if len(args) > 1:
            FeatureNew.single_use('warning with more than one argument', '0.54.0', self.subproject, location=node)
        args_str = self._stringify_user_arguments(args, 'warning')
        mlog.warning(*args_str, location=node)

    @noArgsFlattening
    @noKwargs
    def func_error(self, node, args, kwargs):
        if len(args) > 1:
            FeatureNew.single_use('error with more than one argument', '0.58.0', self.subproject, location=node)
        args_str = self._stringify_user_arguments(args, 'error')
        raise InterpreterException('Problem encountered: ' + ' '.join(args_str))

    @noArgsFlattening
    @FeatureNew('debug', '0.63.0')
    @noKwargs
    def func_debug(self, node, args, kwargs):
        args_str = self._stringify_user_arguments(args, 'debug')
        mlog.debug('Debug:', *args_str)

    @noKwargs
    @noPosargs
    def func_exception(self, node, args, kwargs):
        raise RuntimeError('unit test traceback :)')

    @typed_pos_args('expect_error', str)
    @typed_kwargs(
        'expect_error',
        KwargInfo('how', str, default='literal', validator=in_set_validator({'literal', 're'})),
    )
    def func_expect_error(self, node: mparser.BaseNode, args: T.Tuple[str], kwargs: TYPE_kwargs) -> ContextManagerObject:
        class ExpectErrorObject(ContextManagerObject):
            def __init__(self, msg: str, how: str, subproject: str) -> None:
                super().__init__(subproject)
                self.msg = msg
                self.how = how

            def __exit__(self, exc_type, exc_val, exc_tb):
                if exc_val is None:
                    raise InterpreterException('Expecting an error but code block succeeded')
                if isinstance(exc_val, mesonlib.MesonException):
                    msg = str(exc_val)
                    if (self.how == 'literal' and self.msg != msg) or \
                       (self.how == 're' and not re.match(self.msg, msg)):
                        raise InterpreterException(f'Expecting error {self.msg!r} but got {msg!r}')
                    return True
        return ExpectErrorObject(args[0], kwargs['how'], self.subproject)

    def add_languages(self, args: T.List[str], required: bool, for_machine: MachineChoice) -> bool:
        success = self.add_languages_for(args, required, for_machine)
        if not self.coredata.is_cross_build():
            self.coredata.copy_build_options_from_regular_ones()
        self._redetect_machines()
        return success

    def should_skip_sanity_check(self, for_machine: MachineChoice) -> bool:
        should = self.environment.properties.host.get('skip_sanity_check', False)
        if not isinstance(should, bool):
            raise InterpreterException('Option skip_sanity_check must be a boolean.')
        if for_machine != MachineChoice.HOST and not should:
            return False
        if not self.environment.is_cross_build() and not should:
            return False
        return should

    def add_languages_for(self, args: T.List[str], required: bool, for_machine: MachineChoice) -> bool:
        args = [a.lower() for a in args]
        langs = set(self.compilers[for_machine].keys())
        langs.update(args)
        # We'd really like to add cython's default language here, but it can't
        # actually be done because the cython compiler hasn't been initialized,
        # so we can't actually get the option yet. Because we can't know what
        # compiler to add by default, and we don't want to add unnecessary
        # compilers we don't add anything for cython here, and instead do it
        # When the first cython target using a particular language is used.
        if 'vala' in langs and 'c' not in langs:
            FeatureNew.single_use('Adding Vala language without C', '0.59.0', self.subproject, location=self.current_node)
            args.append('c')
        if 'nasm' in langs:
            FeatureNew.single_use('Adding NASM language', '0.64.0', self.subproject, location=self.current_node)

        success = True
        for lang in sorted(args, key=compilers.sort_clink):
            if lang in self.compilers[for_machine]:
                continue
            machine_name = 'build' if self.coredata.is_build_only else for_machine.get_lower_case_name()
            comp = self.coredata.compilers[for_machine].get(lang)
            if not comp:
                try:
                    skip_sanity_check = self.should_skip_sanity_check(for_machine)
                    if skip_sanity_check:
                        mlog.log('Cross compiler sanity tests disabled via the cross file.', once=True)
                    comp = compilers.detect_compiler_for(self.environment, lang, for_machine, skip_sanity_check, self.subproject)
                    if comp is None:
                        raise InvalidArguments(f'Tried to use unknown language "{lang}".')
                except mesonlib.MesonException:
                    if not required:
                        mlog.log('Compiler for language',
                                 mlog.bold(lang), 'for the', machine_name,
                                 'machine not found.')
                        success = False
                        continue
                    else:
                        raise
            else:
                # update new values from commandline, if it applies
                self.coredata.process_compiler_options(lang, comp, self.environment, self.subproject)

            # Add per-subproject compiler options. They inherit value from main project.
            if self.subproject:
                options = {}
                for k in comp.get_options():
                    v = copy.copy(self.coredata.options[k])
                    k = k.evolve(subproject=self.subproject)
                    options[k] = v
                self.coredata.add_compiler_options(options, lang, for_machine, self.environment, self.subproject)

            if for_machine == MachineChoice.HOST or self.environment.is_cross_build():
                logger_fun = mlog.log
            else:
                logger_fun = mlog.debug
            logger_fun(comp.get_display_language(), 'compiler for the', machine_name, 'machine:',
                       mlog.bold(' '.join(comp.get_exelist())), comp.get_version_string())
            if comp.linker is not None:
                logger_fun(comp.get_display_language(), 'linker for the', machine_name, 'machine:',
                           mlog.bold(' '.join(comp.linker.get_exelist())), comp.linker.id, comp.linker.version)
            self.build.ensure_static_linker(comp)
            self.compilers[for_machine][lang] = comp

        return success

    def program_from_file_for(self, for_machine: MachineChoice, prognames: T.List[mesonlib.FileOrString]
                              ) -> T.Optional[ExternalProgram]:
        for p in prognames:
            if isinstance(p, mesonlib.File):
                continue # Always points to a local (i.e. self generated) file.
            if not isinstance(p, str):
                raise InterpreterException('Executable name must be a string')
            prog = ExternalProgram.from_bin_list(self.environment, for_machine, p)
            # if the machine file specified something, it may be a regular
            # not-found program but we still want to return that
            if not isinstance(prog, NonExistingExternalProgram):
                return prog
        return None

    def program_from_system(self, args: T.List[mesonlib.FileOrString], search_dirs: T.List[str],
                            extra_info: T.List[mlog.TV_Loggable]) -> T.Optional[ExternalProgram]:
        # Search for scripts relative to current subdir.
        # Do not cache found programs because find_program('foobar')
        # might give different results when run from different source dirs.
        source_dir = os.path.join(self.environment.get_source_dir(), self.subdir)
        for exename in args:
            if isinstance(exename, mesonlib.File):
                if exename.is_built:
                    search_dir = os.path.join(self.environment.get_build_dir(),
                                              exename.subdir)
                else:
                    search_dir = os.path.join(self.environment.get_source_dir(),
                                              exename.subdir)
                exename = exename.fname
                extra_search_dirs = []
            elif isinstance(exename, str):
                search_dir = source_dir
                extra_search_dirs = search_dirs
            else:
                raise InvalidArguments(f'find_program only accepts strings and files, not {exename!r}')
            extprog = ExternalProgram(exename, search_dir=search_dir,
                                      extra_search_dirs=extra_search_dirs,
                                      silent=True)
            if extprog.found():
                extra_info.append(f"({' '.join(extprog.get_command())})")
                return extprog
        return None

    def program_from_overrides(self, command_names: T.List[mesonlib.FileOrString],
                               extra_info: T.List['mlog.TV_Loggable'], for_machine: MachineChoice,
                               ) -> T.Optional[T.Union[ExternalProgram, OverrideProgram, build.Executable]]:
        for name in command_names:
            if not isinstance(name, str):
                continue
            if name in self.build.find_overrides[for_machine]:
                exe = self.build.find_overrides[for_machine][name]
                extra_info.append(mlog.blue('(overridden)'))
                return exe
        return None

    def store_name_lookups(self, command_names: T.List[mesonlib.FileOrString], for_machine: MachineChoice) -> None:
        for name in command_names:
            if isinstance(name, str):
                self.build.searched_programs[for_machine].add(name)

    def add_find_program_override(self, name: str, exe: T.Union[build.Executable, ExternalProgram, 'OverrideProgram'],
                                  for_machine: MachineChoice = MachineChoice.HOST) -> None:
        if name in self.build.searched_programs[for_machine]:
            raise InterpreterException(f'Tried to override finding of executable "{name}" which has already been found.')
        if name in self.build.find_overrides[for_machine]:
            raise InterpreterException(f'Tried to override executable "{name}" which has already been overridden.')
        self.build.find_overrides[for_machine][name] = exe

    def notfound_program(self, args: T.List[mesonlib.FileOrString]) -> ExternalProgram:
        return NonExistingExternalProgram(' '.join(
            [a if isinstance(a, str) else a.absolute_path(self.environment.source_dir, self.environment.build_dir)
             for a in args]))

    # TODO update modules to always pass `for_machine`. It is bad-form to assume
    # the host machine.
    def find_program_impl(self, args: T.List[mesonlib.FileOrString],
                          for_machine: MachineChoice = MachineChoice.HOST,
                          default_options: T.Optional[T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]] = None,
                          required: bool = True, silent: bool = True,
                          wanted: T.Union[str, T.List[str]] = '',
                          search_dirs: T.Optional[T.List[str]] = None,
                          version_func: T.Optional[ProgramVersionFunc] = None
                          ) -> T.Union['ExternalProgram', 'build.Executable', 'OverrideProgram']:
        args = mesonlib.listify(args)

        extra_info: T.List[mlog.TV_Loggable] = []
        progobj = self.program_lookup(args, for_machine, default_options, required, search_dirs, wanted, version_func, extra_info)
        if progobj is None or not self.check_program_version(progobj, wanted, version_func, for_machine, extra_info):
            progobj = self.notfound_program(args)

        if isinstance(progobj, ExternalProgram) and not progobj.found():
            if not silent:
                mlog.log('Program', mlog.bold(progobj.get_name()), 'found:', mlog.red('NO'), *extra_info)
            if required:
                m = 'Program {!r} not found or not executable'
                raise InterpreterException(m.format(progobj.get_name()))
            return progobj

        # Only store successful lookups
        self.store_name_lookups(args, for_machine)
        if not silent:
            mlog.log('Program', mlog.bold(progobj.name), 'found:', mlog.green('YES'), *extra_info)
        if isinstance(progobj, build.Executable):
            progobj.was_returned_by_find_program = True
        return progobj

    def program_lookup(self, args: T.List[mesonlib.FileOrString], for_machine: MachineChoice,
                       default_options: T.Optional[T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]],
                       required: bool,
                       search_dirs: T.List[str],
                       wanted: T.Union[str, T.List[str]],
                       version_func: T.Optional[ProgramVersionFunc],
                       extra_info: T.List[mlog.TV_Loggable]
                       ) -> T.Optional[T.Union[ExternalProgram, build.Executable, OverrideProgram]]:
        progobj = self.program_from_overrides(args, extra_info, for_machine)
        if progobj:
            return progobj

        if args[0] == 'meson':
            # Override find_program('meson') to return what we were invoked with
            return ExternalProgram('meson', self.environment.get_build_command(), silent=True)

        fallback = None
        wrap_mode = self.coredata.get_option(OptionKey('wrap_mode'))
        if wrap_mode != WrapMode.nofallback and self.environment.wrap_resolver:
            fallback = self.environment.wrap_resolver.find_program_provider(args)
        if fallback and wrap_mode == WrapMode.forcefallback:
            return self.find_program_fallback(fallback, args, default_options, required, extra_info, for_machine)

        progobj = self.program_from_file_for(for_machine, args)
        if progobj is None:
            progobj = self.program_from_system(args, search_dirs, extra_info)
        if progobj is None and args[0].endswith('python3'):
            prog = ExternalProgram('python3', mesonlib.python_command, silent=True)
            progobj = prog if prog.found() else None

        if progobj and not self.check_program_version(progobj, wanted, version_func, for_machine, extra_info):
            progobj = None

        if progobj is None and fallback and required:
            progobj = self.notfound_program(args)
            mlog.log('Program', mlog.bold(progobj.get_name()), 'found:', mlog.red('NO'), *extra_info)
            extra_info.clear()
            progobj = self.find_program_fallback(fallback, args, default_options, required, extra_info, for_machine)

        return progobj

    def check_program_version(self, progobj: T.Union[ExternalProgram, build.Executable, OverrideProgram],
                              wanted: T.Union[str, T.List[str]],
                              version_func: T.Optional[ProgramVersionFunc],
                              for_machine: MachineChoice,
                              extra_info: T.List[mlog.TV_Loggable]) -> bool:
        if wanted:
            if version_func:
                version = version_func(progobj)
            elif isinstance(progobj, build.Executable):
                if progobj.subproject:
                    interp = self.subprojects[for_machine][progobj.subproject].held_object
                else:
                    interp = self
                assert isinstance(interp, Interpreter)
                version = interp.project_version
            else:
                version = progobj.get_version(self)
            is_found, not_found, _ = mesonlib.version_compare_many(version, wanted)
            if not is_found:
                extra_info[:0] = ['found', mlog.normal_cyan(version), 'but need:',
                                  mlog.bold(', '.join([f"'{e}'" for e in not_found]))]
                return False
            extra_info.insert(0, mlog.normal_cyan(version))
        return True

    def find_program_fallback(self, fallback: str, args: T.List[mesonlib.FileOrString],
                              default_options: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]],
                              required: bool, extra_info: T.List[mlog.TV_Loggable],
                              for_machine: MachineChoice
                              ) -> T.Optional[T.Union[ExternalProgram, build.Executable, OverrideProgram]]:
        mlog.log('Fallback to subproject', mlog.bold(fallback), 'which provides program',
                 mlog.bold(' '.join(args)))
        sp_kwargs: kwtypes.DoSubproject = {
            'required': required,
            'default_options': default_options or {},
            'version': [],
            'cmake_options': [],
            'options': None,
            'for_machine': for_machine,
        }
        self.do_subproject(fallback, sp_kwargs)
        return self.program_from_overrides(args, extra_info, for_machine)

    @typed_pos_args('find_program', varargs=(str, mesonlib.File), min_varargs=1)
    @typed_kwargs(
        'find_program',
        DISABLER_KW.evolve(since='0.49.0'),
        NATIVE_KW,
        REQUIRED_KW,
        KwargInfo('dirs', ContainerTypeInfo(list, str), default=[], listify=True, since='0.53.0'),
        KwargInfo('version', ContainerTypeInfo(list, str), default=[], listify=True, since='0.52.0'),
        DEFAULT_OPTIONS.evolve(since='1.3.0')
    )
    @disablerIfNotFound
    def func_find_program(self, node: mparser.BaseNode, args: T.Tuple[T.List[mesonlib.FileOrString]],
                          kwargs: 'kwtypes.FindProgram',
                          ) -> T.Union['build.Executable', ExternalProgram, 'OverrideProgram']:
        disabled, required, feature = extract_required_kwarg(kwargs, self.subproject)
        if disabled:
            mlog.log('Program', mlog.bold(' '.join(args[0])), 'skipped: feature', mlog.bold(feature), 'disabled')
            return self.notfound_program(args[0])

        search_dirs = extract_search_dirs(kwargs)
        default_options = kwargs['default_options']
        return self.find_program_impl(args[0], kwargs['native'], default_options=default_options, required=required,
                                      silent=False, wanted=kwargs['version'],
                                      search_dirs=search_dirs)

    # When adding kwargs, please check if they make sense in dependencies.get_dep_identifier()
    @FeatureNewKwargs('dependency', '0.57.0', ['cmake_package_version'])
    @FeatureNewKwargs('dependency', '0.56.0', ['allow_fallback'])
    @FeatureNewKwargs('dependency', '0.54.0', ['components'])
    @FeatureNewKwargs('dependency', '0.52.0', ['include_type'])
    @FeatureNewKwargs('dependency', '0.50.0', ['not_found_message', 'cmake_module_path', 'cmake_args'])
    @FeatureNewKwargs('dependency', '0.49.0', ['disabler'])
    @FeatureNewKwargs('dependency', '0.40.0', ['method'])
    @disablerIfNotFound
    @permittedKwargs(permitted_dependency_kwargs)
    @typed_pos_args('dependency', varargs=str, min_varargs=1)
    @typed_kwargs('dependency', DEFAULT_OPTIONS.evolve(since='0.38.0'), allow_unknown=True)
    def func_dependency(self, node: mparser.BaseNode, args: T.Tuple[T.List[str]], kwargs) -> Dependency:
        # Replace '' by empty list of names
        names = [n for n in args[0] if n]
        if len(names) > 1:
            FeatureNew('dependency with more than one name', '0.60.0').use(self.subproject)
        allow_fallback = kwargs.get('allow_fallback')
        if allow_fallback is not None and not isinstance(allow_fallback, bool):
            raise InvalidArguments('"allow_fallback" argument must be boolean')
        fallback = kwargs.get('fallback')
        default_options = kwargs.get('default_options')
        for_machine = MachineChoice.BUILD if self.coredata.is_build_only else self.machine_from_native_kwarg(kwargs)
        df = DependencyFallbacksHolder(self, names, for_machine, allow_fallback, default_options)
        df.set_fallback(fallback)
        not_found_message = kwargs.get('not_found_message', '')
        if not isinstance(not_found_message, str):
            raise InvalidArguments('The not_found_message must be a string.')
        try:
            d = df.lookup(kwargs)
        except Exception:
            if not_found_message:
                self.message_impl([not_found_message])
            raise
        assert isinstance(d, Dependency)
        if not d.found() and not_found_message:
            self.message_impl([not_found_message])
        # Ensure the correct include type
        if 'include_type' in kwargs:
            wanted = kwargs['include_type']
            if not isinstance(wanted, str):
                raise InvalidArguments('The `include_type` kwarg must be a string')
            actual = d.get_include_type()
            if wanted != actual:
                mlog.debug(f'Current include type of {args[0]} is {actual}. Converting to requested {wanted}')
                d = d.generate_system_dependency(wanted)
        if d.feature_since is not None:
            version, extra_msg = d.feature_since
            FeatureNew.single_use(f'dep {d.name!r} custom lookup', version, self.subproject, extra_msg, node)
        for f in d.featurechecks:
            f.use(self.subproject, node)
        return d

    @FeatureNew('disabler', '0.44.0')
    @noKwargs
    @noPosargs
    def func_disabler(self, node, args, kwargs):
        return Disabler()

    @permittedKwargs(build.known_exe_kwargs)
    @typed_pos_args('executable', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('executable', *EXECUTABLE_KWS, allow_unknown=True)
    def func_executable(self, node: mparser.BaseNode,
                        args: T.Tuple[str, SourcesVarargsType],
                        kwargs: kwtypes.Executable) -> build.Executable:
        return self.build_target(node, args, kwargs, build.Executable)

    @permittedKwargs(build.known_stlib_kwargs)
    @typed_pos_args('static_library', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('static_library', *STATIC_LIB_KWS, allow_unknown=True)
    def func_static_lib(self, node: mparser.BaseNode,
                        args: T.Tuple[str, SourcesVarargsType],
                        kwargs: kwtypes.StaticLibrary) -> build.StaticLibrary:
        return self.build_target(node, args, kwargs, build.StaticLibrary)

    @permittedKwargs(build.known_shlib_kwargs)
    @typed_pos_args('shared_library', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('shared_library', *SHARED_LIB_KWS, allow_unknown=True)
    def func_shared_lib(self, node: mparser.BaseNode,
                        args: T.Tuple[str, SourcesVarargsType],
                        kwargs: kwtypes.SharedLibrary) -> build.SharedLibrary:
        holder = self.build_target(node, args, kwargs, build.SharedLibrary)
        holder.shared_library_only = True
        return holder

    @permittedKwargs(known_library_kwargs)
    @typed_pos_args('both_libraries', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('both_libraries', *LIBRARY_KWS, allow_unknown=True)
    def func_both_lib(self, node: mparser.BaseNode,
                      args: T.Tuple[str, SourcesVarargsType],
                      kwargs: kwtypes.Library) -> build.BothLibraries:
        return self.build_both_libraries(node, args, kwargs)

    @FeatureNew('shared_module', '0.37.0')
    @permittedKwargs(build.known_shmod_kwargs)
    @typed_pos_args('shared_module', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('shared_module', *SHARED_MOD_KWS, allow_unknown=True)
    def func_shared_module(self, node: mparser.BaseNode,
                           args: T.Tuple[str, SourcesVarargsType],
                           kwargs: kwtypes.SharedModule) -> build.SharedModule:
        return self.build_target(node, args, kwargs, build.SharedModule)

    @permittedKwargs(known_library_kwargs)
    @typed_pos_args('library', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('library', *LIBRARY_KWS, allow_unknown=True)
    def func_library(self, node: mparser.BaseNode,
                     args: T.Tuple[str, SourcesVarargsType],
                     kwargs: kwtypes.Library) -> build.Executable:
        return self.build_library(node, args, kwargs)

    @permittedKwargs(build.known_jar_kwargs)
    @typed_pos_args('jar', str, varargs=(str, mesonlib.File, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList, build.ExtractedObjects, build.BuildTarget))
    @typed_kwargs('jar', *JAR_KWS, allow_unknown=True)
    def func_jar(self, node: mparser.BaseNode,
                 args: T.Tuple[str, T.List[T.Union[str, mesonlib.File, build.GeneratedTypes]]],
                 kwargs: kwtypes.Jar) -> build.Jar:
        return self.build_target(node, args, kwargs, build.Jar)

    @FeatureNewKwargs('build_target', '0.40.0', ['link_whole', 'override_options'])
    @permittedKwargs(known_build_target_kwargs)
    @typed_pos_args('build_target', str, varargs=SOURCES_VARARGS)
    @typed_kwargs('build_target', *BUILD_TARGET_KWS, allow_unknown=True)
    def func_build_target(self, node: mparser.BaseNode,
                          args: T.Tuple[str, SourcesVarargsType],
                          kwargs: kwtypes.BuildTarget
                          ) -> T.Union[build.Executable, build.StaticLibrary, build.SharedLibrary,
                                       build.SharedModule, build.BothLibraries, build.Jar]:
        target_type = kwargs['target_type']
        if target_type == 'executable':
            return self.build_target(node, args, kwargs, build.Executable)
        elif target_type == 'shared_library':
            return self.build_target(node, args, kwargs, build.SharedLibrary)
        elif target_type == 'shared_module':
            return self.build_target(node, args, kwargs, build.SharedModule)
        elif target_type == 'static_library':
            return self.build_target(node, args, kwargs, build.StaticLibrary)
        elif target_type == 'both_libraries':
            return self.build_both_libraries(node, args, kwargs)
        elif target_type == 'library':
            return self.build_library(node, args, kwargs)
        return self.build_target(node, args, kwargs, build.Jar)

    @noPosargs
    @typed_kwargs(
        'vcs_tag',
        CT_INPUT_KW.evolve(required
"""


```