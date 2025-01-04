Response:
The user wants to understand the functionality of the provided Python code snippet, which is a part of the `interpreter.py` file within the Frida dynamic instrumentation tool. The request asks for:

1. **Functionality Summary:** A general overview of what the code does.
2. **Relevance to Reverse Engineering:**  How the code relates to reverse engineering techniques, with examples.
3. **Relevance to Low-Level Concepts:**  Connections to binary, Linux/Android kernel/framework knowledge, with examples.
4. **Logical Inference:**  Identification of any logical reasoning within the code, demonstrated with input/output examples.
5. **Common User Errors:**  Examples of mistakes users might make when interacting with this code.
6. **User Journey (Debugging):** How a user might end up at this specific part of the code during debugging.
7. **Concise Summary (Part 3 of 6):** A brief summary of the functionality covered in this particular snippet, keeping in mind it's part of a larger file.

Let's break down the code snippet section by section to address these points:

*   **`func_add_languages`**: Deals with adding programming languages for the build process. This involves detecting and configuring compilers.
*   **`func_message`, `message_impl`**: Handles displaying informational messages to the user during the build.
*   **`func_summary`, `summary_impl`, `_print_subprojects`, `_print_summary`**:  Manages the build summary output, including information about subprojects and user-defined options.
*   **`func_warning`, `func_error`, `func_debug`, `func_exception`**: Implement functions for logging different severity levels of messages (warnings, errors, debug information, and exceptions).
*   **`func_expect_error`**:  Provides a context manager to test for expected errors during the build process.
*   **`add_languages`, `should_skip_sanity_check`, `add_languages_for`**:  Internal methods for handling the addition of languages, including logic for skipping sanity checks in cross-compilation scenarios.
*   **Program Finding Functions (`program_from_file_for`, `program_from_system`, `program_from_overrides`, `store_name_lookups`, `add_find_program_override`, `notfound_program`, `find_program_impl`, `program_lookup`, `check_program_version`, `find_program_fallback`)**:  A significant portion of the code dedicated to locating executable programs required for the build. This involves checking various locations (specified files, system paths, overrides).
*   **`func_find_program`**: The user-facing function for finding programs.
*   **`func_dependency`**: Handles the declaration and lookup of project dependencies.
*   **`func_disabler`**: Provides a way to disable features or dependencies.
*   **Target Building Functions (`func_executable`, `func_static_lib`, `func_shared_lib`, `func_both_lib`, `func_shared_module`, `func_library`, `func_jar`, `func_build_target`)**:  Functions for defining different types of build targets (executables, libraries, etc.).

Now, let's map these functionalities to the user's questions.
This部分代码主要负责 Meson 构建系统解释器中的以下功能：

**1. 语言处理 (`func_add_languages`, `add_languages`, `add_languages_for`):**

*   **功能:**  允许 Meson 项目声明其需要使用的编程语言。这涉及到查找和配置相应的编译器。
*   **与逆向的关系:**  在逆向工程中，可能需要编译一些辅助工具或 hook 代码，这些代码可能使用 C/C++ 等语言。Frida 本身也使用 C/C++ 开发。
    *   **举例:**  一个 Frida 用户可能需要编译一个自定义的 Gadget 或 Agent，它需要 C++ 编译器。`func_add_languages('cpp')` 会确保 Meson 找到并配置 C++ 编译器。
*   **与底层知识的关系:** 编译器是与二进制底层直接相关的工具，它们将高级语言代码转换为机器码。Linux 和 Android 平台上通常使用 GCC 或 Clang 作为 C/C++ 编译器。
    *   **举例:**  当添加 'c' 语言时，Meson 会尝试在系统中查找 GCC 或 Clang，这些编译器能够理解 Linux 和 Android 内核及框架所使用的 C 语言特性。
*   **逻辑推理:**  如果 `native` 参数为 `None`，代码会发出警告，并假设语言同时用于 host 和 build 机器。
    *   **假设输入:** `add_languages(['c'])`，没有指定 `native`。
    *   **输出:**  警告信息，并尝试为 build 和 host 机器添加 C 语言支持。
*   **常见错误:** 用户可能忘记安装所需的编译器。
    *   **举例:**  如果用户在没有安装 C++ 编译器的情况下调用 `add_languages('cpp')`，Meson 会报错，提示找不到 C++ 编译器。
*   **用户操作到达此处:** 用户在 `meson.build` 文件中调用了 `add_languages()` 函数声明项目使用的语言。Meson 解析 `meson.build` 文件时会执行到这里。

**2. 消息、警告、错误和调试输出 (`func_message`, `message_impl`, `func_summary`, `summary_impl`, `_print_subprojects`, `_print_summary`, `func_warning`, `func_error`, `func_debug`, `func_exception`):**

*   **功能:**  提供在构建过程中向用户输出不同级别信息的方式。`message` 用于显示普通消息，`warning` 显示警告，`error` 显示错误并中断构建，`debug` 显示调试信息，`summary` 用于生成构建摘要。
*   **与逆向的关系:**  在构建逆向工程工具或脚本时，输出信息对于调试和理解构建过程至关重要。
    *   **举例:**  一个 Frida 的构建脚本可能在检测到特定依赖项时使用 `message()` 输出信息，或者在配置过程中发现潜在问题时使用 `warning()`。如果发生致命错误，则使用 `error()` 停止构建。
*   **逻辑推理:**  `func_summary` 会根据参数决定如何格式化输出，例如是否显示为布尔值 (`bool_yn`) 或使用特定的分隔符 (`list_sep`)。
    *   **假设输入:** `summary({'enabled': True}, bool_yn=True)`
    *   **输出:**  在构建摘要中显示 "enabled: YES"。
*   **常见错误:** 用户可能误用 `error()` 导致构建意外中断，或者过度使用 `debug()` 产生大量无用的调试信息。
*   **用户操作到达此处:**  用户在 `meson.build` 文件中调用了 `message()`, `warning()`, `error()`, `debug()` 或 `summary()` 函数来输出信息。

**3. 期望错误处理 (`func_expect_error`):**

*   **功能:**  允许在构建脚本中预期某些代码块会抛出错误，用于测试目的。
*   **与逆向的关系:**  在测试逆向工程相关的构建脚本时，可能需要确保在特定条件下会产生预期的错误。
    *   **举例:**  一个 Frida 的测试可能预期在尝试链接到不存在的库时会抛出链接错误，可以使用 `expect_error` 来验证这个行为。
*   **逻辑推理:**  `expect_error` 使用上下文管理器，如果代码块没有抛出错误，或者抛出的错误与预期的不符（根据 `how` 参数的 'literal' 或 're' 模式匹配），则会引发 `InterpreterException`。
    *   **假设输入:**
        ```python
        with expect_error('Some error'):
            # 一些不会抛出 "Some error" 的代码
            pass
        ```
    *   **输出:**  会抛出 `InterpreterException`，因为预期有错误但没有发生，或者发生的错误信息不匹配。
*   **常见错误:**  用户可能错误地编写了预期的错误信息，导致测试失败。
*   **用户操作到达此处:** 用户在 `meson.build` 文件中使用了 `with expect_error():` 语句块。

**4. 查找程序 (`func_find_program`, `find_program_impl`, `program_lookup`, 以及相关的 `program_from_*` 方法):**

*   **功能:**  Meson 提供了一种机制来查找系统中或其他地方存在的外部可执行程序。这对于依赖外部工具的构建系统非常重要。
*   **与逆向的关系:** 逆向工程工具的构建通常依赖于各种辅助工具，例如反汇编器、十六进制编辑器、签名工具等。
    *   **举例:**  一个 Frida 的构建脚本可能需要查找 `python3` 来运行一些脚本，或者查找 `llvm-objdump` 来处理目标文件。`find_program('python3')` 或 `find_program('llvm-objdump')` 会执行查找操作。
*   **与底层知识的关系:**  `find_program` 需要理解不同操作系统查找可执行文件的路径规则 (例如 Linux 的 `$PATH`)。
    *   **举例:**  在 Linux 上，Meson 会在 `$PATH` 环境变量指定的目录中搜索程序。
*   **逻辑推理:**  `program_lookup` 函数会按照一定的顺序查找程序：首先检查用户是否通过 `override` 覆盖了查找结果，然后查找指定的文件，接着在系统路径中搜索，最后考虑 fallback 子项目提供的程序。
*   **常见错误:** 用户可能没有安装所需的外部程序，或者程序没有添加到系统的 `PATH` 环境变量中。
    *   **举例:**  如果 Frida 的构建需要 `adb` 工具，但用户没有安装 Android SDK 并且 `adb` 不在 `PATH` 中，`find_program('adb')` 将会失败。
*   **用户操作到达此处:** 用户在 `meson.build` 文件中调用了 `find_program()` 函数来查找外部程序。

**5. 依赖管理 (`func_dependency`):**

*   **功能:**  允许 Meson 项目声明对其他库或软件包的依赖。
*   **与逆向的关系:**  Frida 的构建可能依赖于其他的库，例如 glib、openssl 等。
    *   **举例:**  `dependency('glib-2.0')` 会尝试查找系统中的 glib 库。
*   **逻辑推理:**  `func_dependency` 允许指定多种查找依赖的方法 (`method`)，例如 pkg-config、cmake 等。它还支持 fallback 到子项目来提供依赖。
*   **常见错误:**  用户可能没有安装所需的依赖库，或者 Meson 无法找到依赖库的配置文件（例如 .pc 文件）。
*   **用户操作到达此处:** 用户在 `meson.build` 文件中调用了 `dependency()` 函数来声明项目依赖。

**6. 禁用器 (`func_disabler`):**

*   **功能:**  提供了一种在特定条件下禁用某些构建特性的机制。
*   **与逆向的关系:**  在构建 Frida 时，可能需要根据不同的平台或配置禁用某些功能。
    *   **举例:**  可能在某些平台上禁用特定的 hook 功能。
*   **用户操作到达此处:** 用户在 `meson.build` 文件中调用了 `disabler()` 函数。

**7. 构建目标定义 (`func_executable`, `func_static_lib`, `func_shared_lib`, `func_both_lib`, `func_shared_module`, `func_library`, `func_jar`, `func_build_target`):**

*   **功能:**  这些函数用于定义不同类型的构建目标，例如可执行文件、静态库、共享库、共享模块和 JAR 文件。
*   **与逆向的关系:**  Frida 本身会构建多种类型的目标，包括 Frida Server（可执行文件）、Gadget（共享库）等。
    *   **举例:**  `executable('frida-server', 'frida-server.c')` 会定义一个名为 `frida-server` 的可执行文件，其源代码是 `frida-server.c`。`shared_library('frida-gadget', 'frida-gadget.c')` 会定义一个名为 `frida-gadget` 的共享库。
*   **用户操作到达此处:** 用户在 `meson.build` 文件中调用这些函数来定义项目的构建目标。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户修改 `meson.build` 文件:**  用户为了构建 Frida 或其扩展，会编辑 `meson.build` 文件来添加、修改或删除构建目标、依赖项、语言声明等。
2. **用户运行 `meson` 命令:** 用户在项目根目录下运行 `meson <build_directory>` 命令来配置构建系统。
3. **Meson 解析 `meson.build`:**  Meson 会读取并解析 `meson.build` 文件。在这个过程中，会执行文件中定义的各种函数，包括这部分代码中的函数。
4. **解释器执行对应函数:** 当 Meson 解析到 `add_languages()`, `message()`, `find_program()`, `dependency()`, `executable()` 等函数时，会调用 `interpreter.py` 文件中对应的 `func_*` 方法。
5. **调试线索:** 如果在构建过程中出现问题，用户可能会设置断点或添加日志输出来跟踪代码的执行流程，从而进入到 `interpreter.py` 文件的这些函数中，以了解构建过程中的具体行为。例如，如果找不到某个程序，用户可能会在 `func_find_program` 中设置断点来查看程序查找的路径和过程。

**功能归纳 (第 3 部分，共 6 部分):**

这部分代码主要负责 Meson 构建系统中**处理项目配置信息和执行构建逻辑的关键部分**。它涵盖了：

*   **声明项目使用的编程语言并配置相应的编译器。**
*   **提供多种方式向用户输出构建过程中的信息，包括消息、警告、错误和调试信息，并生成构建摘要。**
*   **支持预期错误处理，用于测试构建脚本的正确性。**
*   **实现查找外部可执行程序的机制。**
*   **管理项目依赖，并支持多种依赖查找方式。**
*   **提供禁用构建特性的能力。**
*   **定义各种类型的构建目标（可执行文件、库等）。**

总而言之，这部分代码是 Meson 解释器的核心组成部分，它解释 `meson.build` 文件中的声明，并指导 Meson 如何配置和执行构建过程。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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