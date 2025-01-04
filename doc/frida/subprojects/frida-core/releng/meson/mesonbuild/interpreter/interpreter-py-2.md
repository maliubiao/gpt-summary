Response:
The user wants a summary of the functionality of the provided Python code snippet, which is a part of the `interpreter.py` file in the Frida project. Specifically, they are interested in:

1. **General functionalities:** What does this code do?
2. **Relationship to reverse engineering:** How can this code be used in reverse engineering?
3. **Involvement of low-level knowledge:** Does it interact with the binary level, Linux/Android kernel, or frameworks?
4. **Logical reasoning:** Are there any input/output examples based on logic within the code?
5. **Common user errors:** What are some typical mistakes users might make when using this code?
6. **User path to this code:** How does a user's action lead to this code being executed?
7. **Concise summary:** A final, brief overview of the code's purpose.

Let's break down the code section by section to identify these aspects.

**Code Block Analysis and Functionality Identification:**

*   **`func_add_languages`:** This function seems to handle adding programming language support to the build process. It determines if the language is enabled/disabled and for which machine (host/build). It also deals with backward compatibility for the `native` keyword.
*   **`_stringify_user_arguments`:** This utility function converts user-provided arguments to strings, handling potential errors.
*   **`func_message` and `message_impl`:** These functions are for displaying informational messages during the build process.
*   **`func_summary` and `summary_impl`:**  These handle generating a summary report of the build process, including user-defined options and subproject information.
*   **`_print_subprojects` and `_print_summary`:** These functions format and output the summary information, including details about subprojects.
*   **`func_warning`, `func_error`, `func_debug`, `func_exception`:** These functions are for reporting different levels of messages (warnings, errors, debug information, exceptions) during the build.
*   **`func_expect_error`:** This function appears to be for testing purposes, allowing the build script to assert that a specific error occurs within a block of code.
*   **`add_languages` and `add_languages_for`:** These functions manage the detection and configuration of compilers for different programming languages. They interact with the environment to find compilers and handle cross-compilation scenarios.
*   **`should_skip_sanity_check`:** This checks if compiler sanity checks should be skipped, often based on cross-compilation configurations.
*   **`program_from_file_for`, `program_from_system`, `program_from_overrides`:** These functions are responsible for locating executable programs needed for the build process. They search in different locations (defined files, system paths, and overrides).
*   **`store_name_lookups`, `add_find_program_override`:** These functions manage overrides for program lookups, allowing the build system to use specific executables instead of relying on automatic detection.
*   **`notfound_program`:** This creates a placeholder object for programs that couldn't be found.
*   **`find_program_impl` and `program_lookup`:** These are the core functions for finding executable programs. They use the previously mentioned lookup mechanisms and handle version checking.
*   **`check_program_version`:** This function compares the version of a found program against required versions.
*   **`find_program_fallback`:** This handles falling back to building a subproject if a required program isn't found directly.
*   **`func_find_program`:** This is the Meson function exposed to users for finding programs. It wraps the `find_program_impl` with argument parsing and error handling.
*   **`func_dependency`:** This function handles the declaration and resolution of project dependencies, including finding libraries and other required components.
*   **`func_disabler`:**  This likely returns an object that can be used to conditionally disable build features.
*   **`func_executable`, `func_static_lib`, `func_shared_lib`, `func_both_lib`, `func_shared_module`, `func_library`, `func_jar`, `func_build_target`:** These functions define the creation of different types of build targets (executables, libraries, etc.).

**Connecting to Reverse Engineering and Low-Level Aspects:**

The core functionality revolves around the build system. However, certain aspects connect to reverse engineering and low-level details, especially in the context of Frida:

*   **Finding tools:** The `find_program_impl` function can be used to locate tools that are relevant to reverse engineering, such as disassemblers, debuggers (like GDB), or other binary analysis tools.
*   **Cross-compilation:** The handling of host and build machines is crucial for cross-compiling Frida to target different architectures (e.g., building Frida tools on a Linux host to run on an Android device). This inherently involves understanding target system specifics.
*   **Dependency management:** When building Frida, it needs to link against various libraries (e.g., for networking, IPC). The dependency resolution logic (`func_dependency`) plays a key role here. Understanding the dependencies of Frida is important for reverse engineers who want to extend or modify it.
*   **Building shared libraries/modules:** Frida heavily relies on shared libraries and modules that are injected into target processes. The functions for building these (`func_shared_lib`, `func_shared_module`) are directly related to how Frida's core components are created.

**Hypothetical Input and Output (Logical Reasoning):**

*   **Input (in a `meson.build` file):** `find_program('adb')`
*   **Possible Output:** An `ExternalProgram` object representing the `adb` executable, if found in the system's PATH. If not found, and `required=True` (default), it would raise an `InterpreterException`. If `required=False`, it would return a `NonExistingExternalProgram` object.

*   **Input (in a `meson.build` file):** `add_languages('c', 'rust')`
*   **Possible Output:**  This would attempt to find C and Rust compilers. If successful, it would configure the build system to support these languages. The output of the function itself would be `True` if both are found, and potentially `False` if `required=False` and one is missing. Log messages would indicate success or failure.

**Common User Errors:**

*   **Incorrect program name in `find_program`:**  `find_program('my-misspelled-tool')` would fail if the tool doesn't exist.
*   **Missing dependencies:** When declaring a dependency with `dependency('some-lib')`, the build will fail if `some-lib` cannot be found, and the user hasn't provided a fallback or specified `required=False`.
*   **Incorrect keyword arguments:**  Using a keyword argument that isn't supported by a function (e.g., `find_program('tool', non_existent_kwarg='value')`).
*   **Version constraints:** Specifying a version requirement in `find_program` or `dependency` that doesn't match the installed version.

**User Path to This Code (Debugging Clues):**

1. A developer working on Frida starts the build process by running the `meson` command in their build directory.
2. Meson parses the `meson.build` files in the Frida source tree.
3. During parsing, if Meson encounters functions like `find_program`, `dependency`, `add_languages`, or target creation functions (e.g., `executable`, `shared_library`), the corresponding methods in the `Interpreter` class (which this code snippet is part of) are called.
4. For instance, if `find_program('adb')` is encountered, the `func_find_program` method is executed, eventually calling `find_program_impl`.
5. If a dependency cannot be found, and the build fails, the error message might trace back to the `func_dependency` method.
6. If the build configuration needs to add support for a specific language, the `func_add_languages` method is involved.

**Concise Summary of Functionality:**

This code defines a significant part of the Meson build system interpreter responsible for managing project configuration, finding dependencies and tools, and defining build targets (executables, libraries). It handles language support, program lookups, dependency resolution, and the creation of various build artifacts, which are essential for building the Frida dynamic instrumentation toolkit.

这是 frida 动态 instrumentation 工具的源代码文件 `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreter.py` 的一部分，主要负责处理 Meson 构建系统的解释器功能。以下是它的功能归纳：

**核心功能：构建系统配置和解释**

这段代码是 Meson 构建系统解释器的核心组成部分，负责解释 `meson.build` 文件中的指令，并将其转化为实际的构建操作。它管理着项目的配置、依赖查找、编译器选择、目标定义等关键方面。

**具体功能详解：**

1. **语言处理 (`func_add_languages`, `add_languages`, `add_languages_for`):**
    *   **功能:**  允许项目指定需要使用的编程语言（如 C、Rust）。
    *   **逆向相关性:**  在构建 frida-core 时，可能需要指定 C 或 C++ 来编译 native 代码部分，这些 native 代码是 frida 与目标进程交互的基础。例如，frida-agent 的核心通常用 C/C++ 编写。
    *   **底层知识:** 涉及到对编译器（如 GCC, Clang）的调用和配置，以及理解不同编程语言的编译流程。
    *   **逻辑推理 (假设输入与输出):**
        *   **输入:** `add_languages(['c', 'rust'])`
        *   **输出:** 如果系统安装了 C 和 Rust 的编译器，则成功配置构建系统以支持这两种语言。日志会显示找到的编译器信息。如果缺少某个编译器，且 `required=True`，则会抛出异常；如果 `required=False`，则会记录警告信息并继续。

2. **消息和摘要 (`func_message`, `message_impl`, `func_summary`, `summary_impl`, `_print_subprojects`, `_print_summary`):**
    *   **功能:**  提供在构建过程中输出消息、警告、错误和生成构建摘要的功能。摘要会汇总项目信息、用户选项、依赖状态等。
    *   **逆向相关性:**  在调试 frida 的构建过程时，这些消息和摘要可以帮助开发者了解构建状态、排查问题。例如，可以查看是否成功找到了某个依赖库。
    *   **用户操作到达:** 用户在 `meson.build` 文件中使用 `message()` 或 `summary()` 函数，Meson 解析器会调用这些对应的方法。

3. **错误处理 (`func_warning`, `func_error`, `func_debug`, `func_exception`, `func_expect_error`):**
    *   **功能:**  提供报告不同级别错误和调试信息的方式。`func_expect_error` 用于测试，期望某段代码会抛出特定的错误。
    *   **用户或编程常见错误:**
        *   **示例:**  在 `meson.build` 中使用 `error('构建失败，缺少必要文件')` 会导致构建立即停止并显示错误信息。
        *   **用户操作到达:** 用户在 `meson.build` 文件中使用 `warning()` 或 `error()` 函数，或者代码执行过程中遇到异常。

4. **程序查找 (`program_from_file_for`, `program_from_system`, `program_from_overrides`, `store_name_lookups`, `add_find_program_override`, `notfound_program`, `find_program_impl`, `program_lookup`, `check_program_version`, `find_program_fallback`, `func_find_program`):**
    *   **功能:**  负责在系统中查找需要的可执行程序（例如，构建过程中可能需要 `python`、`git` 等工具）。
    *   **逆向相关性:**  frida 的构建可能依赖于一些逆向工程相关的工具，例如在编译 agent 时可能需要一些处理二进制文件的工具。`find_program` 可以用于查找这些工具。
    *   **底层知识:** 涉及到操作系统路径搜索、可执行文件权限等概念。
    *   **逻辑推理 (假设输入与输出):**
        *   **输入:** `find_program('python3')`
        *   **输出:** 如果系统 PATH 中存在 `python3` 可执行文件，则返回一个代表该程序的 `ExternalProgram` 对象。否则，根据 `required` 参数，可能抛出异常或返回一个表示未找到的特殊对象。
    *   **用户或编程常见错误:**
        *   **示例:** `find_program('non_existent_tool')` 如果该工具不存在，且没有设置 `required=False`，会导致构建失败。
        *   **用户操作到达:** 用户在 `meson.build` 文件中使用 `find_program()` 函数来查找工具。

5. **依赖管理 (`func_dependency`):**
    *   **功能:**  声明和查找项目依赖的库或其他组件。
    *   **逆向相关性:**  frida-core 依赖于一些库，例如 GLib、libffi 等。`dependency()` 函数用于查找这些库，确保构建系统能够链接它们。
    *   **底层知识:**  涉及到操作系统库搜索路径、pkg-config 等工具的使用。
    *   **用户或编程常见错误:**
        *   **示例:** `dependency('missing_library')` 如果该库未安装或 Meson 无法找到，且没有提供回退方案，会导致构建失败。
        *   **用户操作到达:** 用户在 `meson.build` 文件中使用 `dependency()` 函数声明依赖。

6. **构建目标定义 (`func_executable`, `func_static_lib`, `func_shared_lib`, `func_both_lib`, `func_shared_module`, `func_library`, `func_jar`, `func_build_target`):**
    *   **功能:**  定义要构建的各种目标类型，如可执行文件、静态库、共享库、模块等。
    *   **逆向相关性:**  frida-core 本身会构建多个共享库（例如 frida-core.so），这些库会被注入到目标进程中。这些函数的调用直接定义了这些核心组件的构建方式。
    *   **用户操作到达:** 用户在 `meson.build` 文件中使用这些函数来定义构建目标。

**与逆向方法的关联举例:**

*   **`find_program('gdb')`:**  frida 的测试或构建脚本可能需要使用 GDB 进行调试或代码分析。`find_program` 可以用来确保 GDB 在构建环境中可用。
*   **构建 frida-agent 的共享库:** `shared_library('frida-agent', sources: agent_sources)`  这行代码会调用 `func_shared_lib` 来构建 frida agent 的动态链接库，这是 frida 注入目标进程的关键组件。

**涉及二进制底层、Linux, Android 内核及框架的知识举例:**

*   **交叉编译 (`add_languages`):**  构建在 Linux 主机上运行，但需要注入到 Android 设备的 frida-agent 时，就需要进行交叉编译。`add_languages` 能够处理为不同目标平台配置编译器。这涉及到对 Android NDK 或其他交叉编译工具链的理解。
*   **共享库构建 (`func_shared_lib`):**  共享库的构建涉及到动态链接、符号导出等底层概念，与 Linux 和 Android 的动态链接器的工作方式密切相关。
*   **程序查找 (针对特定平台工具):**  在为 Android 构建 frida 时，可能需要查找 Android SDK 中的工具，例如 adb。这需要理解 Android 的目录结构和工具链。

**逻辑推理 (假设输入与输出):**

*   **输入:** `find_program(['lldb', 'gdb'], required: false)`
*   **输出:** Meson 会先尝试查找 `lldb`，如果找到则返回其 `ExternalProgram` 对象。如果找不到，则尝试查找 `gdb`，如果找到则返回 `gdb` 的 `ExternalProgram` 对象。如果两者都找不到，由于 `required: false`，不会抛出异常，而是返回一个表示未找到的特殊对象。

**用户或编程常见的使用错误举例:**

*   **忘记安装依赖库:**  如果 `meson.build` 中使用了 `dependency('glib-2.0')`，但系统中没有安装 `glib-2.0` 开发库，构建会失败。
*   **拼写错误的函数名或参数名:**  例如，使用 `fin_program()` 而不是 `find_program()`。
*   **在不支持的上下文中使用了某些函数:** 例如，在定义构建目标之前就尝试使用该目标的属性。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户配置构建环境:** 用户下载 frida 的源代码，并创建一个用于构建的目录。
2. **用户运行 Meson 命令:** 用户在构建目录中运行 `meson setup ..` 命令（假设源代码在上一级目录）。
3. **Meson 解析 `meson.build`:** Meson 开始读取和解析源代码根目录下的 `meson.build` 文件，以及子目录中的 `meson.build` 文件。当解析到 `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreter.py` 对应的代码时，会执行其中的函数。
4. **执行 `add_languages`:**  如果 `meson.build` 文件中调用了 `project()` 函数并指定了语言，例如 `project('frida-core', 'c', 'cpp')`，则会触发 `func_add_languages` 的执行。
5. **执行 `find_program` 和 `dependency`:**  构建系统需要查找编译器、链接器以及依赖库，这时会调用 `func_find_program` 和 `func_dependency`。
6. **执行构建目标定义函数:**  根据 `meson.build` 文件中对可执行文件、库等的定义，会调用 `func_executable`、`func_shared_lib` 等函数。
7. **调试线索:** 如果构建过程中出现错误，例如找不到编译器或依赖库，Meson 的错误信息通常会指示在哪个 `meson.build` 文件以及哪一行代码发生了错误。开发者可以通过查看这些信息，追溯到 `interpreter.py` 中相应的函数调用，从而理解构建过程的哪个环节出了问题。

**功能归纳 (第 3 部分):**

这段代码主要负责 Meson 构建系统的核心解释功能，具体包括：

*   **处理项目语言配置:** 允许指定项目使用的编程语言，并检测相应的编译器。
*   **提供消息和摘要输出机制:**  用于在构建过程中输出信息、警告、错误，并生成构建摘要报告。
*   **管理错误和调试信息:**  提供报告不同级别错误和调试信息的接口。
*   **实现程序查找功能:**  在系统中查找构建所需的各种可执行程序。
*   **处理项目依赖关系:**  声明和查找项目依赖的库和其他组件。
*   **定义构建目标:**  允许声明要构建的可执行文件、库等目标。

总而言之，这段代码是 Meson 构建系统的关键组成部分，负责解析构建脚本，并将其转化为实际的构建操作。它与逆向工程密切相关，因为 frida 的构建过程依赖于它来管理编译、链接以及查找必要的工具和库。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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