Response:
My goal is to analyze the provided Python code snippet from the Frida dynamic instrumentation tool and explain its functionality, relating it to reverse engineering, low-level concepts, and potential user errors. Since this is part 5 of 6, I need to summarize the overall function as well.

Here's a breakdown of my thought process:

1. **Understand the Context:** The filename `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreter.py` strongly suggests this code is part of Meson, a build system used by Frida. The `interpreter.py` part indicates this file likely handles the interpretation of Meson build definitions.

2. **Identify Key Functions:** I will scan the code for defined functions (`def func_...`) and class methods. The names of these functions will provide clues about their purpose.

3. **Analyze Individual Functionality:** For each function, I will try to determine:
    * **Core Purpose:** What is the main task of this function?
    * **Input:** What kind of arguments does it take (positional and keyword)?
    * **Output:** What does it return or what side effects does it have?
    * **Relevance to Reverse Engineering:**  Does this function directly aid in reverse engineering or the building of tools for it?  If so, how?
    * **Low-Level Concepts:** Does it interact with the file system, compilers, linkers, or platform-specific features?
    * **Logic and Assumptions:** Are there conditional statements or loops? What assumptions are made about the input?
    * **Potential User Errors:** What mistakes could a user make when calling this function?
    * **User Journey:** How might a user end up calling this function (within the context of a Meson build file)?

4. **Focus on Key Functions:**
    * `func_configure_file`: This seems crucial for generating configuration files based on templates and user-provided data.
    * `func_include_directories`:  This is essential for managing include paths for compilation.
    * `func_add_test_setup`: Deals with configuring test environments, which is important for quality assurance.
    * `func_add_global_arguments`, `func_add_project_arguments`: These functions handle compiler and linker flags.
    * `func_environment`: Manages environment variables during the build process.
    * `func_join_paths`:  A utility function for manipulating file paths.
    * `run`: Likely the main entry point for interpreting the build definition.
    * `validate_within_subproject`, `source_strings_to_files`, `add_target`: These functions deal with file handling, target management, and security constraints within the build system.

5. **Connect to Reverse Engineering:** I'll look for connections to how these functions could be used in the Frida build process, especially concerning the core functionality of Frida: dynamic instrumentation. This involves building components that interact with target processes, potentially requiring specific compiler flags, include paths for system headers, and configuration files.

6. **Identify Low-Level Concepts:** I will look for interactions with the file system (e.g., creating directories, copying files), compiler and linker options, and references to platform-specific concepts (like Linux or Android).

7. **Infer Logic and Examples:**  For functions with conditional logic, I will create hypothetical input scenarios and predict the output. This helps in understanding the function's behavior.

8. **Pinpoint User Errors:** Based on the function signatures and logic, I will identify common mistakes users might make (e.g., incorrect argument types, missing required arguments, invalid paths).

9. **Trace User Operations:** I will think about the steps a developer would take when writing a Meson build file that would lead to these functions being called. This helps in understanding the practical context.

10. **Synthesize the Summary (Part 5):** Since this is part 5, I will synthesize the functionalities discussed so far, focusing on the higher-level goals they achieve within the build system.

11. **Review and Refine:** I'll review my analysis to ensure accuracy, clarity, and completeness, addressing all the specific points requested in the prompt. I will make sure my examples are relevant and illustrative. I will pay special attention to the "part 5" instruction and ensure my summary reflects that.

**(Self-Correction during the process):**

* **Initial thought:** Maybe focus heavily on the `frida` aspect.
* **Correction:** The code is about Meson, the *build system* used by Frida. The analysis should primarily focus on the build process and how these functions contribute to it. The connection to Frida is through its build system requirements.
* **Initial thought:** Just list the functions.
* **Correction:** The prompt asks for functionality, examples, and connections to reverse engineering, low-level concepts, etc. A simple list isn't sufficient.
* **Initial thought:** Provide overly complex technical details.
* **Correction:** Aim for clarity and explain concepts in a way that is understandable to someone familiar with software development but perhaps not deeply familiar with build systems internals. Use illustrative, concise examples.

By following these steps and continuously refining my understanding, I can provide a comprehensive and accurate analysis of the given code snippet.
这是 `frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreter.py` 文件的一部分，主要关注的是 Meson 构建系统中解释器（Interpreter）的功能。从提供的代码片段来看，它主要定义和实现了多个用于配置构建过程的函数。以下是这些函数的功能归纳以及与逆向、底层知识、逻辑推理和用户错误相关的说明：

**功能列举：**

1. **`func_configure_file`**:
   - **功能**:  用于从模板文件生成配置文件的函数。它可以执行三种操作：
     - **`configuration`**: 使用提供的配置数据字典（`configuration` kwarg）替换输入文件中的变量，生成输出文件。
     - **`command`**:  执行一个命令（`command` kwarg），并将命令的输出写入输出文件。可以捕获命令的输出（`capture` kwarg）。
     - **`copy`**:  简单地将输入文件复制到输出位置。
   - **与逆向的关系**: 在构建 Frida 这样的逆向工具时，可能需要生成一些配置文件，例如，包含 Frida Agent 的配置信息，或者目标进程的配置信息。`func_configure_file` 可以根据不同的构建配置生成这些文件。
   - **底层知识**: 涉及到文件操作（创建目录、读取文件、写入文件）、进程执行（`command` 模式）以及环境变量的管理。
   - **逻辑推理**:
     - **假设输入**: `input='my_config.in'`, `output='my_config.h'`, `configuration={'VERSION': '1.0'}`
     - **输出**:  在构建目录下生成 `my_config.h` 文件，其中 `my_config.in` 中的 `@VERSION@` 占位符会被替换为 `1.0`。
   - **用户错误**:
     - 没有指定任何操作 (`configuration`, `command`, `copy`)。
     - 同时指定了互斥的操作，如同时指定 `configuration` 和 `command`。
     - 在 `command` 模式下使用了 `capture`，但没有提供 `command`。
     - 在 `configuration` 模式下提供了多个输入文件。
   - **用户操作到达此处**: 用户在 `meson.build` 文件中调用 `configure_file()` 函数，并提供相应的参数。例如：
     ```python
     configure_file(
       input: 'my_template.c.in',
       output: 'my_generated.c',
       configuration: {'MY_DEFINE': '123'}
     )
     ```

2. **`func_include_directories`**:
   - **功能**:  用于声明包含目录，这些目录将被添加到编译器的搜索路径中。
   - **与逆向的关系**: Frida 需要包含一些头文件才能与目标进程或操作系统内核进行交互。例如，可能需要包含 Linux 内核头文件或 Android 框架的头文件。
   - **底层知识**: 涉及到编译器的工作原理，以及如何通过 `-I` 或类似的选项指定包含目录。
   - **逻辑推理**:
     - **假设输入**: `include_directories('include')`
     - **输出**:  Meson 会创建一个表示包含目录的对象，并将其添加到编译器的包含路径中。
   - **用户错误**:
     - 提供的路径不存在。
     - 尝试使用绝对路径指向源目录内的文件，应该使用相对路径。
   - **用户操作到达此处**: 用户在 `meson.build` 文件中调用 `include_directories()` 函数，并提供需要包含的目录。例如：
     ```python
     inc = include_directories('src/common')
     executable('my_program', 'main.c', include_directories: inc)
     ```

3. **`func_add_test_setup`**:
   - **功能**:  用于定义测试设置，例如指定测试运行器的封装器、GDB 支持、超时乘数等。
   - **与逆向的关系**: Frida 的构建过程通常包含测试，以验证其功能是否正常。`func_add_test_setup` 可以用于配置这些测试的运行环境。例如，可以使用特定的封装器来运行测试，以便在特定条件下进行调试或性能分析。
   - **底层知识**: 涉及到测试执行环境的配置，可能包括进程启动方式、调试器集成等。
   - **用户错误**:
     - 设置名称包含非法字符。
     - 将 `timeout_multiplier` 设置为非正数（在旧版本 Meson 中）。
     - 多次将 `is_default` 设置为 `True`。
   - **用户操作到达此处**: 用户在 `meson.build` 文件中调用 `add_test_setup()` 函数，定义一个测试环境。例如：
     ```python
     add_test_setup('valgrind', exe_wrapper: ['valgrind', '--leak-check=full'])
     ```

4. **`func_add_global_arguments`, `func_add_project_arguments`**:
   - **功能**:  用于添加全局或项目级别的编译器和链接器参数。
   - **与逆向的关系**:  构建 Frida 可能需要特定的编译器或链接器标志，例如用于启用符号信息、禁用优化、或者链接特定的库。这些函数允许用户在构建系统中指定这些标志。
   - **底层知识**:  涉及到编译器和链接器的命令行选项。
   - **用户错误**:
     - 在声明任何构建目标之后调用这些函数。
     - 在子项目中调用全局参数函数。
   - **用户操作到达此处**: 用户在 `meson.build` 文件中调用 `add_global_arguments()` 或 `add_project_arguments()` 函数，并提供需要添加的参数。例如：
     ```python
     add_global_arguments('-Wall', '-Werror', language: 'c')
     ```

5. **`func_add_global_link_arguments`, `func_add_project_link_arguments`**:
   - **功能**:  类似于上面的函数，但专门用于添加链接器参数。
   - **与逆向的关系**: Frida 可能需要链接特定的库，例如用于进程注入或内存操作的库。
   - **底层知识**:  涉及到链接器的命令行选项。
   - **用户错误**:  与上面类似。
   - **用户操作到达此处**: 用户在 `meson.build` 文件中调用这些函数，提供链接器参数。

6. **`func_add_project_dependencies`**:
   - **功能**:  用于添加项目级别的依赖项，包括传递编译和链接参数。
   - **与逆向的关系**: Frida 可能依赖于其他库或组件。此函数用于声明这些依赖项，并自动处理相关的编译和链接设置。
   - **底层知识**: 涉及到依赖管理、编译和链接过程。
   - **用户错误**: 在为特定语言调用 `add_language()` 之前调用此函数。
   - **用户操作到达此处**: 用户在 `meson.build` 文件中调用 `add_project_dependencies()`，并提供依赖项对象。

7. **`func_environment`**:
   - **功能**:  用于创建和操作环境变量的集合，可以在构建过程中的命令中使用。
   - **与逆向的关系**: 在执行某些构建步骤或测试时，可能需要设置特定的环境变量。例如，可能需要设置 Frida Agent 的搜索路径或其他相关的环境变量。
   - **底层知识**: 涉及到操作系统环境变量的概念。
   - **用户操作到达此处**: 用户在 `meson.build` 文件中调用 `environment()` 函数。

8. **`func_join_paths`**:
   - **功能**:  用于连接多个路径片段，生成一个规范化的路径字符串。
   - **与逆向的关系**: 在构建系统中，经常需要处理文件路径。此函数提供了一种方便的方式来组合路径。
   - **底层知识**: 涉及到文件系统路径的表示。
   - **用户操作到达此处**: 用户在 `meson.build` 文件中调用 `join_paths()` 函数。

9. **`run`**:
   - **功能**:  解释器的主运行函数，执行 `meson.build` 文件中的指令。
   - **与逆向的关系**: 这是 Meson 构建系统的核心部分，负责解析和执行 Frida 的构建定义。
   - **底层知识**: 涉及到构建系统的整体架构和执行流程。

10. **`validate_within_subproject`**:
    - **功能**:  用于验证尝试访问的文件是否在当前子项目内，以防止沙箱逃逸。
    - **与逆向的关系**:  Frida 的构建可能包含多个子项目。此函数确保构建定义不会意外地访问其他子项目的文件，保持构建的隔离性和可维护性。
    - **底层知识**: 涉及到构建系统的安全性和项目结构。
    - **用户错误**: 尝试引用其他子项目中的文件。
    - **用户操作到达此处**: 当 Meson 遇到一个文件引用时，会调用此函数进行验证。

11. **`source_strings_to_files`**:
    - **功能**:  将字符串形式的源文件路径转换为 Meson 的 `File` 对象。
    - **与逆向的关系**:  在构建目标时，需要指定源文件。此函数用于将用户提供的字符串路径转换为 Meson 内部使用的文件对象。
    - **底层知识**: 涉及到文件系统的抽象表示。
    - **用户错误**: 提供无效的文件路径。
    - **用户操作到达此处**: 当 Meson 需要处理源文件列表时，会调用此函数。

12. **`add_target`**:
    - **功能**:  用于向构建系统中添加一个新的构建目标（例如，可执行文件、库）。
    - **与逆向的关系**: Frida 的构建过程会创建多个目标，包括 Frida Agent、命令行工具等。
    - **底层知识**: 涉及到构建系统的核心概念：目标。
    - **用户错误**: 提供空的目标名称或包含路径分隔符的目标名称。
    - **用户操作到达此处**: 用户在 `meson.build` 文件中调用如 `executable()`, `shared_library()` 等函数时，最终会调用 `add_target()`。

**与逆向方法的关联举例：**

- 使用 `func_configure_file` 生成 Frida Agent 的配置文件，其中包含需要注入的目标进程名称或 ID。
- 使用 `func_include_directories` 包含目标操作系统或架构的头文件，以便 Frida 能够正确地与目标系统交互。
- 使用 `func_add_global_arguments` 添加特定的编译器标志，例如 `-fPIC` 用于生成位置无关的代码，这对于动态库注入非常重要。
- 使用 `func_add_global_link_arguments` 链接 Frida 依赖的库，例如用于进程内存操作或符号解析的库。

**涉及的二进制底层、Linux、Android 内核及框架知识举例：**

- **二进制底层**:  编译器和链接器参数直接影响生成二进制文件的结构和特性。例如，使用特定的链接器脚本或标志可以控制内存布局。
- **Linux 内核**:  Frida 可能需要与 Linux 内核进行交互，例如通过 ptrace 系统调用进行进程控制。因此，构建过程中可能需要包含 Linux 内核的头文件。
- **Android 框架**:  在 Android 平台上，Frida 需要与 Android Runtime (ART) 或 Dalvik 虚拟机进行交互。构建过程可能需要包含 Android SDK 或 NDK 提供的头文件和库。

**逻辑推理的假设输入与输出举例 (针对 `func_configure_file`):**

- **假设输入**:
  ```python
  configure_file(
    input: 'version.h.in',
    output: 'version.h',
    configuration: {'MAJOR': 1, 'MINOR': 2, 'PATCH': 3}
  )
  ```
  `version.h.in` 内容：
  ```c
  #define VERSION_MAJOR @MAJOR@
  #define VERSION_MINOR @MINOR@
  #define VERSION_PATCH @PATCH@
  ```
- **输出**: 生成的 `version.h` 文件内容：
  ```c
  #define VERSION_MAJOR 1
  #define VERSION_MINOR 2
  #define VERSION_PATCH 3
  ```

**用户或编程常见的使用错误举例：**

- 在 `func_configure_file` 中，用户可能错误地将 `install` 设置为 `True`，但忘记指定 `install_dir`。
- 在 `func_include_directories` 中，用户可能提供了不存在的目录路径。
- 在 `func_add_global_arguments` 中，用户可能在定义了构建目标之后才添加全局参数，导致 Meson 报错。

**用户操作如何一步步到达这里，作为调试线索：**

1. **编写 `meson.build` 文件**: 用户编写定义 Frida 构建规则的 `meson.build` 文件。
2. **调用 Meson**: 用户在命令行执行 `meson setup builddir` 命令，指示 Meson 解析 `meson.build` 文件。
3. **解释器解析**: Meson 的解释器 (即这里的 `interpreter.py`) 读取并解析 `meson.build` 文件中的函数调用，例如 `configure_file()`, `include_directories()` 等。
4. **执行函数**: 解释器会调用相应的函数 (`func_configure_file`, `func_include_directories` 等)，并传递用户提供的参数。
5. **构建图生成**: 这些函数会操作 Meson 的内部数据结构，构建一个描述构建过程的图。
6. **后端生成**: Meson 根据构建图生成特定构建系统（如 Ninja）的构建文件。

当出现构建错误时，查看错误信息和回溯可以帮助定位到哪个 `meson.build` 文件中的哪个函数调用导致了问题，从而可以检查传递给这些函数的参数是否正确。

**第 5 部分功能归纳：**

这部分代码主要定义了 Meson 构建系统中解释器的一些核心功能，用于处理构建配置和目标定义。它允许用户通过 `meson.build` 文件声明如何生成配置文件、指定包含目录、添加编译器和链接器参数、配置测试环境以及管理项目依赖。这些功能是 Meson 构建系统的基础，使得用户能够灵活地配置和管理复杂的软件构建过程，例如 Frida 这样的动态 instrumentation 工具的构建。这部分代码体现了构建系统对构建过程的抽象和自动化能力，简化了开发者手动编写 Makefile 或类似构建脚本的工作。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/interpreter/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```python
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
```