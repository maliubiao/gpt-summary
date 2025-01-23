Response:
My thinking process to answer the request about the `interpreter.py` file went through these stages:

1. **Understanding the Core Request:** The user wants to understand the *functionality* of the provided Python code snippet. They are specifically interested in connections to reverse engineering, low-level aspects (kernel, drivers, etc.), logical reasoning within the code, common user errors, and how a user might reach this code. The prompt also emphasizes that this is part 3 of 6 and asks for a summary of the functionality.

2. **Initial Code Scan and Keyword Spotting:** I first scanned the code for keywords and function names that hint at the purpose of the file. I noticed things like:
    * `add_languages`:  Suggests handling compiler setup.
    * `func_message`, `func_warning`, `func_error`, `func_debug`: Indicate logging and user feedback mechanisms.
    * `func_summary`: Points to generating a build summary.
    * `func_find_program`:  Implies searching for external tools.
    * `func_dependency`:  Suggests managing external libraries or dependencies.
    * `func_executable`, `func_static_lib`, `func_shared_lib`, etc.:  Clearly related to building different types of software artifacts.
    * `@typed_kwargs`, `@typed_pos_args`, `@noKwargs`, `@noPosargs`: Decorators related to argument parsing and type checking.
    * `MachineChoice`:  Indicates handling different target architectures (host, build).
    * `mesonlib`, `compilers`, `build`: Imports of other modules, suggesting interactions with the broader Meson build system.

3. **Inferring Overall Purpose:** Based on the keywords, I concluded that this file (`interpreter.py`) is a central part of the Meson build system, specifically responsible for *interpreting* the build instructions defined in `meson.build` files. It manages compilers, dependencies, program discovery, and defines functions that are called from the build scripts.

4. **Addressing Specific Aspects:**

    * **Functionality Listing:** I went through the identified function names and summarized their purpose based on their names and the code within them. I grouped related functionalities (e.g., message/warning/error handling).

    * **Relationship to Reverse Engineering:** I looked for functions or code patterns that would be relevant to someone performing reverse engineering. The most prominent connection is the `func_find_program`. Reverse engineers often need to use external tools (debuggers, disassemblers, etc.) during their analysis. Meson needs a way to locate these tools on the system. I also considered that the build process itself might generate artifacts that a reverse engineer would later analyze (executables, libraries).

    * **Binary/Low-Level, Linux/Android Kernel/Framework:** The compiler management (`add_languages`) is the most direct link here. Compilers translate high-level code into machine code. The code also interacts with the operating system through program execution (`func_find_program`). While the provided snippet doesn't directly manipulate kernel code, it's part of the *tooling* used to build software that *could* interact with the kernel or Android framework. I also noted the `MachineChoice` which is relevant for cross-compilation, often used for embedded systems like Android.

    * **Logical Reasoning (Input/Output):**  Many functions have conditional logic. I chose the `func_add_languages` as a good example because it shows how the function behaves differently based on the `native` keyword argument. I provided a hypothetical input and described the expected logging output.

    * **Common User Errors:** I thought about common mistakes users make when writing build scripts. Incorrectly specifying program names in `find_program` or dependency names in `dependency` are common. I illustrated this with an example of a misspelled program name.

    * **User Path to This Code (Debugging Clues):** I imagined a scenario where a user encounters an error related to a missing program. I then traced back how the Meson build system would likely call `find_program_impl` and eventually the lower-level functions in this file. I emphasized using the Meson logs and potentially stepping through the Python code with a debugger.

    * **Part 3 Summary:** I summarized the core responsibilities of the file, highlighting its role as the "interpreter" of the build definition.

5. **Structuring and Refining the Answer:** I organized the information into clear sections, using headings and bullet points for readability. I tried to use clear and concise language, explaining technical terms where necessary. I double-checked that my examples aligned with the code and the user's request. I made sure to explicitly state when a feature was introduced in a specific Meson version based on the `@FeatureNew` annotations.

This iterative process of scanning, inferring, analyzing specific aspects, and then structuring the answer allowed me to provide a comprehensive and relevant response to the user's request. The code annotations and function names provided significant clues about the file's purpose.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的第三部分。根据提供的代码片段，我们可以归纳一下它的主要功能：

**核心功能：解释和执行 Meson 构建定义**

该文件的核心职责是解释和执行 `meson.build` 文件中的构建指令。它将用户编写的构建描述转化为实际的构建操作。

**具体功能 (基于提供的代码片段)：**

1. **设置构建环境:**
   - `__init__`: 初始化解释器，包括设置后端 (例如 Ninja, Xcode, Visual Studio)，处理 Visual Studio 环境。
   - `add_languages`:  处理项目所需的编程语言，包括主机 (host) 和构建 (build) 机器。它负责检测和配置相应的编译器。

2. **用户交互和反馈:**
   - `func_message`, `message_impl`:  处理 `message()` 函数调用，用于向用户显示信息。
   - `func_summary`, `summary_impl`, `_print_subprojects`, `_print_summary`: 处理 `summary()` 函数调用，用于在构建结束时生成构建摘要报告。
   - `func_warning`: 处理 `warning()` 函数调用，向用户显示警告信息。
   - `func_error`: 处理 `error()` 函数调用，当发生错误时抛出异常并终止构建。
   - `func_debug`: 处理 `debug()` 函数调用，用于输出调试信息。

3. **错误处理:**
   - `func_expect_error`:  用于测试环境，期望代码块执行时抛出特定的错误。

4. **语言处理:**
   - `add_languages`, `add_languages_for`:  负责添加和配置项目所需的编程语言的编译器。它会检测系统上可用的编译器，并根据需要进行设置。

5. **查找程序:**
   - `program_from_file_for`, `program_from_system`, `program_from_overrides`:  用于在系统中查找可执行程序。
   - `find_program_impl`, `program_lookup`:  实现 `find_program()` 函数的功能，允许用户查找系统中的工具或程序。
   - `add_find_program_override`: 允许用户手动覆盖 `find_program()` 的查找结果。
   - `check_program_version`: 检查找到的程序的版本是否符合要求。
   - `find_program_fallback`:  处理使用子项目作为程序查找的后备方案。

6. **依赖管理:**
   - `func_dependency`: 处理 `dependency()` 函数调用，用于查找和配置项目所需的外部依赖库。

7. **构建目标定义:**
   - `func_executable`, `func_static_lib`, `func_shared_lib`, `func_both_lib`, `func_shared_module`, `func_library`, `func_jar`, `func_build_target`: 处理定义不同类型的构建目标（可执行文件、静态库、共享库等）的函数调用。

8. **其他工具函数:**
   - `func_disabler`: 用于创建禁用器对象，可以用于有条件地禁用某些构建特性。

**与逆向方法的关系及举例说明：**

* **查找工具 (find_program):** 逆向工程师经常需要使用各种工具，如反汇编器 (objdump, IDA Pro, Ghidra)，调试器 (gdb, lldb)，或者用于分析二进制文件的其他工具。Meson 的 `find_program()` 函数可以用来查找这些工具，以便在构建过程中或自定义脚本中使用它们。
    * **例子:** 假设你的逆向工程项目需要使用 `objdump` 来提取目标文件的信息。你可以在 `meson.build` 文件中使用 `find_program('objdump')` 来查找它，并将其路径存储在一个变量中，供后续的自定义构建步骤使用。

* **构建自定义工具链:**  逆向某些嵌入式系统或特定架构的软件时，可能需要使用特定的交叉编译工具链。Meson 允许指定不同的编译器，这对于构建逆向分析所需的工具非常有用。
    * **例子:** 你可能需要构建一个用于分析 ARM 架构固件的调试器。你可以配置 Meson 使用 ARM 交叉编译工具链来构建这个调试器。

**涉及二进制底层，Linux, Android内核及框架的知识及举例说明：**

* **编译器和链接器:** `add_languages` 函数涉及到编译器和链接器的检测和配置。编译器将源代码转换为机器码 (二进制)，链接器将不同的目标文件和库文件组合成最终的可执行文件或库文件。这是理解二进制底层的基础。
    * **例子:** 当 Meson 检测到 C 编译器时，它会尝试运行编译器来获取其版本信息和默认选项。这涉及到执行底层的编译器二进制文件。

* **构建目标类型 (Executable, Shared Library, Static Library):** 这些概念直接关联到操作系统如何加载和执行程序，以及库文件的链接方式。理解这些概念是理解操作系统底层运作的关键。
    * **例子:** 构建一个共享库 (`shared_library`) 会生成 `.so` (Linux) 或 `.dylib` (macOS) 文件，这些文件可以在运行时被多个程序加载。理解共享库的加载机制涉及到操作系统底层的动态链接知识。

* **交叉编译 (`MachineChoice.HOST`, `MachineChoice.BUILD`):**  当为 Android 或其他嵌入式系统构建软件时，通常需要在主机上进行交叉编译。Meson 区分了主机和目标机器，并允许分别配置它们的编译器。这需要理解不同架构的指令集和 ABI (Application Binary Interface)。
    * **例子:**  为 Android 构建 Frida Gadget 时，Meson 需要配置 Android NDK 提供的交叉编译工具链。

**逻辑推理及假设输入与输出：**

* **`func_add_languages` 的逻辑分支:**
    * **假设输入:** `args = ['c', 'cpp']`, `kwargs = {'native': True}`
    * **输出:**  `self.add_languages(['c', 'cpp'], True, MachineChoice.HOST)` 将被调用，因为 `native=True` 指示为主机机器添加语言。

    * **假设输入:** `args = ['python']`, `kwargs = {}` (缺少 `native` 参数)
    * **输出:**  会发出一个警告，提示 `add_languages` 缺少 `native:` 参数，并默认同时为主机和构建机器添加 Python 支持。

* **`func_find_program` 的查找顺序:**
    * **假设输入:** `args = ['gdb']`, 系统中安装了 `gdb`。
    * **输出:**  `program_from_overrides` 会首先被检查，如果没有覆盖，则 `program_from_file_for` 检查，然后 `program_from_system` 会找到系统路径下的 `gdb` 可执行文件，并返回表示 `gdb` 的 `ExternalProgram` 对象。

**涉及用户或编程常见的使用错误及举例说明：**

* **`func_find_program` 中程序名拼写错误:**
    * **例子:** 用户在 `meson.build` 中写了 `find_program('gd')` 而不是 `find_program('gdb')`。
    * **结果:** Meson 将无法找到名为 `gd` 的程序，如果 `required=True` (默认情况)，构建将会失败并报错。

* **`func_dependency` 中依赖库名称错误:**
    * **例子:** 用户在 `meson.build` 中写了 `dependency('libpqsl')` 而不是 `dependency('libpq')` (假设用户想链接 PostgreSQL 客户端库)。
    * **结果:** Meson 将无法找到名为 `libpqsl` 的依赖库，构建将会失败并报错，或者会尝试使用回退机制 (如果配置了)。

* **在不适用的上下文中使用了 `native: true/false`:**
    * **例子:**  在没有明确指定目标机器的情况下，错误地使用了 `native: true` 或 `native: false`，导致编译器被错误地添加到主机或构建机器上。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件:** 用户首先创建或修改 `meson.build` 文件，其中包含了项目的构建定义，例如使用了 `find_program()`, `dependency()`, `executable()`, `shared_library()` 等函数。
2. **用户运行 `meson` 命令:** 用户在项目根目录下运行 `meson <build_directory>` 命令来配置构建。
3. **Meson 解析 `meson.build`:**  `meson` 命令会读取并解析 `meson.build` 文件，这个过程涉及到词法分析、语法分析，最终构建出一个抽象语法树 (AST)。
4. **解释器执行 AST:**  `interpreter.py` 文件中的代码负责解释和执行这个 AST。当遇到例如 `find_program('gdb')` 这样的函数调用时，会调用 `func_find_program` 函数。
5. **`func_find_program` 调用 `find_program_impl`:** `func_find_program` 函数会进一步调用 `find_program_impl` 来执行实际的程序查找逻辑。
6. **程序查找过程:** `find_program_impl` 内部会按照一定的顺序 (override -> file -> system) 查找指定的程序。
7. **如果程序未找到:** 如果程序查找失败，并且 `required=True`，则会抛出一个 `InterpreterException`，导致构建失败。

**调试线索:**

* **查看 Meson 的输出:**  Meson 在运行过程中会输出详细的日志信息，包括它尝试查找哪些程序，以及是否成功找到。
* **使用 `--verbose` 或 `--debug` 选项:** 运行 `meson --verbose <build_directory>` 或 `meson --debug <build_directory>` 可以获得更详细的调试信息。
* **检查 `meson-log.txt` 文件:** Meson 会将详细的构建日志写入 `meson-log.txt` 文件中，可以查看该文件了解程序查找的详细过程。
* **使用 Python 调试器:** 对于更复杂的问题，可以尝试使用 Python 调试器 (例如 `pdb`) 来单步执行 `interpreter.py` 中的代码，查看变量的值和执行流程。

**总结一下它的功能 (基于提供的代码片段):**

这部分 `interpreter.py` 文件的主要功能是作为 Meson 构建系统的核心解释器，负责：

* **管理构建环境:**  初始化构建后端，处理项目所需的编程语言和编译器。
* **处理用户交互:**  提供 `message`, `warning`, `error`, `summary` 等函数，用于与用户进行交互和反馈。
* **查找和管理程序:**  实现 `find_program` 功能，允许在系统中查找可执行程序。
* **管理依赖:** 实现 `dependency` 功能，用于查找和配置项目的外部依赖库。
* **定义构建目标:**  处理定义不同类型构建目标（可执行文件、库文件等）的函数调用。
* **提供错误处理机制:**  处理构建过程中的错误和异常。

总之，这个文件是 Meson 构建系统的关键组成部分，它将用户定义的构建规则转化为实际的构建操作，并负责管理构建过程中的各种资源和依赖。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
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
```