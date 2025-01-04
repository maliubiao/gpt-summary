Response:
The user wants a summary of the functionality of the provided Python code, specifically focusing on aspects related to reverse engineering, binary/kernel knowledge, logical reasoning, common user errors, and debugging.

Here's a breakdown of the thought process to achieve the desired summary:

1. **Understand the Context:** The code is part of Frida, a dynamic instrumentation toolkit. The specific file `interpreter.py` within the `meson` build system suggests it's responsible for interpreting Meson build files. This means it handles directives for compiling, linking, finding dependencies, and other build-related tasks.

2. **High-Level Functionality Identification:**  Scan the code for key function names and class structures. Notice functions like `func_add_languages`, `func_find_program`, `func_dependency`, `func_executable`, `func_shared_lib`, etc. These clearly indicate core functionalities related to:
    * Language support and compiler detection.
    * Finding external programs and dependencies.
    * Building different types of targets (executables, libraries).
    * Handling messages, warnings, errors, and summaries.
    * Managing subprojects.

3. **Reverse Engineering Relevance:** Think about how build systems interact with reverse engineering. Key areas emerge:
    * **Finding Programs:**  Tools like debuggers (gdb), disassemblers (objdump), and other reverse engineering utilities might be located using `find_program`. Frida itself, being the context, could be found and used.
    * **Dependencies:** Libraries that Frida or target applications depend on are managed here. Understanding these dependencies is crucial for reverse engineering.
    * **Build Targets:**  The process of creating executables and shared libraries is fundamental to understanding the structure of the target being reverse engineered.

4. **Binary/Kernel/OS Relevance:** Identify code sections dealing with system-level concepts:
    * **Compilers:** Compilers translate source code into machine code (binary). The code explicitly deals with detecting and configuring compilers.
    * **Linking:**  Linking combines compiled code into executables or libraries. The code manages library types (static, shared).
    * **Operating System Interaction:**  Finding programs involves searching the system's PATH. The concept of "host" and "build" machines hints at cross-compilation scenarios.
    * **Subprojects:**  Complex software often uses subprojects, which can represent different modules or libraries, potentially with their own build processes.

5. **Logical Reasoning (Assumptions and Outputs):** Look for functions that make decisions based on inputs:
    * **`add_languages`:**  Assumes the availability of compilers for specified languages. Output is whether the languages were successfully added.
    * **`find_program_impl`:**  Assumes a program exists in the system or specified directories. Output is the `ExternalProgram` object (found or not found).
    * **`func_dependency`:** Assumes a dependency can be located using various methods (pkg-config, CMake, etc.). Output is the `Dependency` object.

6. **Common User Errors:** Consider how a user might misuse the build system:
    * **Incorrect Language Names:** Specifying an invalid language in `add_languages`.
    * **Missing Dependencies:**  Trying to build a target that depends on a program not found by `find_program`.
    * **Incorrect `find_program` Arguments:** Providing wrong program names or paths.
    * **Invalid `dependency` Arguments:**  Misspelling dependency names or providing incorrect fallback information.

7. **Debugging Clues (Path to the Code):** Trace how a user's actions might lead to this code being executed:
    * The user runs the `meson` command to configure a build.
    * Meson parses the `meson.build` file.
    * Directives in `meson.build` like `project()`, `add_languages()`, `find_program()`, `executable()`, etc., call the corresponding `func_*` methods in the `Interpreter` class.

8. **Structure the Summary:** Organize the findings into the categories requested by the user: general functionality, reverse engineering, binary/kernel, logical reasoning, user errors, and debugging.

9. **Refine and Explain:** Provide clear explanations and examples for each category. Use specific function names from the code to illustrate points.

**(Self-Correction during the process):**

* Initially, I might focus too much on the "interpreter" aspect and forget the broader build system context. Remind myself that this code *interprets build instructions*.
* I might overlook the cross-compilation aspect (host vs. build machines). Pay attention to the `MachineChoice` enum and related logic.
* When thinking about reverse engineering, initially I might only think about debugging the *target* application. Realize that understanding the *build process* itself can be valuable for reverse engineering.
*  For logical reasoning, ensure the assumptions and outputs are clearly linked to specific functions and their intended behavior.

By following these steps, the detailed and categorized summary requested by the user can be constructed.
这是 frida 动态 Instrumentation 工具的 `interpreter.py` 文件的第三部分，它主要负责解释和执行 Meson 构建定义文件中的指令。

**归纳一下它的功能:**

这部分代码主要负责处理 Meson 构建文件中与**语言支持、依赖查找、消息输出、摘要信息、错误和警告处理、条件执行以及查找程序**相关的指令。  它构建了项目构建过程的核心逻辑，确保构建系统能够正确地识别编译器，找到所需的依赖，并向用户提供反馈。

**更详细的功能列举:**

* **语言支持 (`func_add_languages`, `add_languages`, `add_languages_for`):**
    * 允许用户在构建定义中指定项目使用的编程语言（例如 C, C++, Python）。
    * 负责检测系统中是否存在指定语言的编译器。
    * 可以根据 `native` 关键字区分是为主机环境还是目标环境添加语言支持。
    * 如果找不到所需的编译器，可以根据 `required` 参数决定是否报错。

* **消息、摘要、警告和错误处理 (`func_message`, `message_impl`, `func_summary`, `summary_impl`, `func_warning`, `func_error`, `func_debug`):**
    * 提供了在构建过程中向用户输出信息的方式 (`message`)，可以用于显示自定义的消息。
    * 允许创建构建摘要 (`summary`)，用于在构建完成后展示关键信息，例如启用的特性、找到的依赖等。
    * 提供了发出警告 (`warning`) 和错误 (`error`) 的机制，用于在构建过程中通知用户潜在的问题或致命错误。
    * 提供了调试输出 (`debug`) 的功能，用于在开发 Meson 构建脚本时进行调试。

* **条件执行 (`func_expect_error`):**
    * 允许用户编写测试，预期某段代码执行会抛出特定的错误。这对于测试构建脚本的错误处理逻辑非常有用。

* **查找程序 (`func_find_program`, `find_program_impl`, `program_lookup`, `program_from_file_for`, `program_from_system`, `program_from_overrides`, `notfound_program`, `check_program_version`, `find_program_fallback`):**
    * 允许用户在构建系统中查找可执行程序，例如编译器、构建工具或其他外部工具。
    * 可以指定查找的程序名和可选的搜索目录 (`dirs`)。
    * 支持查找主机环境和目标环境的程序 (`native` 关键字)。
    * 可以指定所需的程序版本 (`version`)，如果找到的版本不符合要求，则查找失败。
    * 提供了覆盖默认查找行为的机制 (`program_from_overrides`)。
    * 集成了 wrap-resolver 的功能，可以回退到子项目提供的程序 (`find_program_fallback`)。

* **依赖查找 (`func_dependency`):**
    * 允许用户声明项目依赖的外部库或组件。
    * 可以指定多种查找依赖的方法 (`method`)，例如 pkg-config, CMake, 系统库等。
    * 支持指定依赖的版本要求。
    * 可以配置找不到依赖时的行为，例如显示自定义消息 (`not_found_message`)。
    * 允许回退到子项目提供的依赖 (`fallback`)。

* **禁用器 (`func_disabler`):**
    * 提供了一种机制，用于在满足特定条件时禁用构建过程的某些部分。

**与逆向的方法的关系及举例说明:**

* **查找逆向工具:** 在构建 Frida 时，可能需要查找一些逆向工程常用的工具，例如 `objdump`（用于查看目标文件的信息）、`lldb` 或 `gdb`（调试器）等。`func_find_program` 可以用来查找这些工具：
    ```python
    objdump_prog = find_program('objdump')
    gdb_prog = find_program('gdb', native: true) # 查找主机环境的 gdb
    ```
    这使得构建系统能够在必要时使用这些工具进行一些构建时的检查或操作。

* **依赖管理:** Frida 可能依赖一些逆向相关的库，例如 capstone (反汇编引擎)。`func_dependency` 用于查找和管理这些依赖：
    ```python
    capstone_dep = dependency('capstone')
    ```
    了解 Frida 的依赖对于逆向分析 Frida 本身或使用 Frida 进行逆向时排查问题很有帮助。

**涉及到二进制底层，Linux, Android 内核及框架的知识的举例说明:**

* **编译器检测:**  `add_languages` 函数需要检测系统中是否存在 C/C++ 编译器 (例如 GCC, Clang)。这些编译器直接将源代码编译成二进制机器码，这是二进制底层知识的基础。
* **链接器 (Linker):** 在 `add_languages_for` 中，代码会获取编译器的链接器信息 (`comp.linker`)。链接器负责将编译后的目标文件和库文件组合成最终的可执行文件或共享库。理解链接过程对于理解二进制文件的结构至关重要。
* **主机 (Host) 和构建 (Build) 环境:** 代码中多次出现 `MachineChoice.HOST` 和 `MachineChoice.BUILD`。这反映了交叉编译的概念，即在一个平台上（主机）构建出能在另一个平台（目标，例如 Android 设备）上运行的程序。这涉及到对不同架构和操作系统的理解。
* **静态库和共享库 (`func_static_lib`, `func_shared_lib`):**  Frida 本身会生成共享库 (`.so` 文件，在 Linux/Android 上)，用于注入到目标进程。理解静态库和共享库的区别以及它们在操作系统中的加载和链接方式，是理解 Frida 工作原理的基础。

**如果做了逻辑推理，请给出假设输入与输出:**

**假设输入 (针对 `func_add_languages`):**

```python
add_languages(['c', 'python'], required: true)
```

**预期输出:**

* 如果系统中同时安装了 C 编译器和 Python 解释器，则 `add_languages` 函数成功执行，返回 `True`。
* 如果系统中缺少 C 编译器或 Python 解释器，并且 `required` 为 `true`，则会抛出一个 `InterpreterException`，提示缺少相应的编译器。
* 如果 `required` 为 `false`，则会记录一条警告信息，指出缺少相应的编译器，但不会抛出异常，返回 `False`。

**假设输入 (针对 `func_find_program`):**

```python
find_program('adb', dirs: ['/usr/bin', '/opt/android-sdk/platform-tools'])
```

**预期输出:**

* 如果在 `/usr/bin` 或 `/opt/android-sdk/platform-tools` 目录下找到了名为 `adb` 的可执行文件，则 `func_find_program` 会返回一个表示该程序的 `ExternalProgram` 对象。
* 如果在指定的目录下没有找到 `adb`，则会根据是否设置了 `required: true` (默认是 true) 来决定是否抛出 `InterpreterException`。如果没有找到且 `required` 为 `false`，则返回一个表示未找到程序的 `NonExistingExternalProgram` 对象。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **错误的语言名称:** 用户在 `add_languages` 中指定了不存在的语言，例如 `add_languages(['nonexistentlang'])`，会导致构建系统无法找到对应的编译器。
* **`find_program` 找不到程序:** 用户使用 `find_program` 查找一个系统中不存在或者不在默认 PATH 环境变量中的程序，且没有指定正确的搜索目录，会导致构建失败。例如，如果 Android SDK 的 `adb` 工具不在 PATH 中，且用户没有指定 `dirs` 参数，则 `find_program('adb')` 会失败。
* **依赖项名称拼写错误:** 在 `dependency` 函数中，用户可能会拼错依赖项的名称，例如 `dependency('capsonte')`，导致构建系统无法找到正确的依赖库。
* **`version` 参数使用错误:**  用户在 `find_program` 中指定了错误的 `version` 格式，或者指定的版本要求与实际找到的程序版本不匹配，可能导致构建失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户首先会编写一个 `meson.build` 文件，描述项目的构建方式，包括指定使用的语言、依赖项、需要构建的目标等。例如：
   ```python
   project('my_frida_module', 'cpp', 'python')
   capstone_dep = dependency('capstone')
   my_tool = find_program('my_custom_tool')
   executable('my_executable', 'main.cpp')
   ```

2. **用户运行 `meson` 命令:** 用户在项目根目录下运行 `meson build` (或类似的命令) 来配置构建系统。

3. **Meson 解析 `meson.build`:** Meson 工具会读取并解析 `meson.build` 文件，构建一个抽象语法树 (AST)。

4. **调用 `Interpreter`:** Meson 的解释器模块 (包括这个 `interpreter.py` 文件) 会遍历 AST，执行其中定义的各种函数。

5. **执行到相关函数:**
   * 当遇到 `project()` 函数时，可能会间接调用 `add_languages` 来处理指定的编程语言。
   * 当遇到 `dependency('capstone')` 时，会调用 `func_dependency` 来查找 capstone 依赖。
   * 当遇到 `find_program('my_custom_tool')` 时，会调用 `func_find_program` 来查找 `my_custom_tool` 程序。

**作为调试线索:**

当构建过程中出现问题时，例如找不到编译器或依赖项，查看 Meson 的输出日志可以帮助定位问题。日志中会显示调用了哪些 `interpreter.py` 中的函数，以及这些函数的参数和执行结果。例如，如果看到类似 "Compiler for language c not found" 的错误信息，就可以知道问题出在 `add_languages` 函数中，可能是系统缺少 C 编译器，或者配置不正确。类似地，如果看到 "Program 'my_custom_tool' not found" 的错误，则表明 `func_find_program` 没有找到该程序，需要检查程序是否存在或者是否在正确的搜索路径中。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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