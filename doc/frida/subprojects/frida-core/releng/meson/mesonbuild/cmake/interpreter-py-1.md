Response:
The user wants a summary of the functionality of the provided Python code. This code seems to be part of a tool that integrates CMake projects into the Meson build system.

Here's a breakdown of the thought process to achieve the summary:

1. **Understand the Context:** The code is located within the `frida` project, specifically under `frida-core/releng/meson/mesonbuild/cmake/interpreter.py`. This immediately suggests that it's related to bridging CMake and Meson.

2. **Identify the Core Class:** The central class is `CMakeInterpreter`. Its methods will define the core functionalities.

3. **Analyze the `__init__` method:** This reveals the fundamental data the interpreter manages: source and build directories, installation prefix, environment, target machine, detected linkers, and interfaces to CMake's file API. It also initializes data structures to store parsed CMake information like project name, version, languages, targets, and generated Meson data.

4. **Examine Key Methods and their Actions:**

    * **`configure`:**  This method's name suggests setting up the CMake project. The code confirms this by finding the CMake executable, preparing a toolchain file, setting CMake arguments, and then running the `cmake` command. It also handles error reporting if CMake configuration fails. The use of `CMakeExecutor` is key here.

    * **`initialise`:** This follows `configure` and is responsible for parsing the output of the CMake configuration. It uses the `CMakeFileAPI` to load build system files and configuration data.

    * **`analyse`:** This method processes the information obtained from CMake. It extracts target information (executables, libraries, custom commands), categorizes them, and builds dependency relationships. The use of `ConverterTarget` and `ConverterCustomTarget` hints at the conversion process.

    * **`pretend_to_be_meson`:** This is a crucial method. The name strongly implies it generates Meson build definitions from the parsed CMake data. A closer look at the code reveals the construction of Meson abstract syntax tree (AST) nodes representing Meson functions like `project`, `executable`, `library`, `custom_target`, and `declare_dependency`. This confirms the CMake-to-Meson translation.

    * **`target_info` and `target_list`:** These methods provide ways to query information about the translated targets, useful for integration with Meson.

5. **Identify Connections to Reverse Engineering, Binary/Kernel Aspects:**  While the code itself doesn't perform direct reverse engineering, its purpose is to facilitate the build process of `frida`, which is a dynamic instrumentation toolkit used for reverse engineering. Therefore, understanding how this code helps build Frida components is the key connection.

6. **Look for Logical Reasoning and Assumptions:** The `pretend_to_be_meson` function involves significant logical mapping between CMake concepts and Meson concepts. The code makes assumptions about how CMake projects are structured and how they should be represented in Meson. The handling of different target types (`executable`, `library`, `custom_target`) and dependencies demonstrates this logic. The example of handling header files in custom targets is a good illustration of reasoning about build order.

7. **Consider Potential User Errors:**  The `configure` method checks for CMake's presence and handles configuration failures. The code also validates CMake arguments. A potential user error would be providing incorrect or incompatible CMake options.

8. **Trace User Interaction (Debugging Clue):**  To reach this code, a user would typically be building a project that uses Meson as its build system and includes a CMake subproject. Meson would then invoke this `CMakeInterpreter` to handle the CMake part. The steps would involve running the `meson` command to configure the build, which would then trigger the CMake configuration and analysis.

9. **Structure the Summary:**  Organize the findings into logical sections covering the main functionalities, connections to reverse engineering/low-level aspects, logical reasoning, potential user errors, and user interaction.

10. **Review and Refine:**  Read through the generated summary to ensure accuracy, clarity, and completeness. Ensure the examples provided are relevant and illustrate the points effectively. For example, the cycle detection in dependencies and the handling of header files in custom targets are important logical inferences the code performs. Highlighting the role in Frida's build process connects it to reverse engineering.

By following these steps, a comprehensive and informative summary can be generated, addressing all aspects of the user's request.
这是 `frida/subprojects/frida-core/releng/meson/mesonbuild/cmake/interpreter.py` 文件的第二部分代码，它延续了第一部分的功能，主要负责 **解析 CMake 构建系统的信息，并将其转换为 Meson 构建系统的表示形式**。

**归纳其功能：**

1. **完成 CMake 项目信息的转换：**
   -  **`pretend_to_be_meson(self, options: TargetOptions) -> CodeBlockNode`:**  这是核心功能。它接收之前分析得到的 CMake 项目信息，并模拟 Meson 构建文件的语法，生成一个 Meson AST (Abstract Syntax Tree) 的代码块。这个过程将 CMake 的目标 (targets)、依赖 (dependencies)、编译选项 (compile options)、链接选项 (link options) 等信息映射到相应的 Meson 函数调用。
   -  它会创建 Meson 的 `project()` 函数调用，声明项目名称、语言和版本。
   -  它会为 CMake 的每个目标（例如可执行文件、静态库、共享库、头文件库、自定义目标）生成相应的 Meson 函数调用，例如 `executable()`, `static_library()`, `shared_library()`, `header_only()`, `custom_target()`, `declare_dependency()` 等。
   -  它会处理目标之间的依赖关系，将 CMake 的依赖关系转换为 Meson 的 `link_with` 和 `depends` 参数。
   -  它会处理编译选项和链接选项，将 CMake 的编译/链接标志转换为 Meson 的 `*_args` 参数。
   -  它会处理包含目录，生成 Meson 的 `include_directories()` 调用。
   -  对于自定义目标，它会生成 `custom_target()` 函数调用，并使用一个内部脚本 `cmake_run_ctgt` 来执行自定义命令。

2. **提供目标信息查询接口：**
   - **`target_info(self, target: str) -> T.Optional[T.Dict[str, str]]`:**  允许查询特定 CMake 目标在转换后对应的 Meson 信息，例如生成的 Meson 变量名、目标类型等。它会尝试根据 CMake 的目标名称和内部映射来查找信息。
   - **`target_list(self) -> T.List[str]`:** 返回所有已转换的 CMake 目标的列表。

**与逆向的方法的关系及举例说明：**

这段代码本身不直接执行逆向操作，但它是 Frida 工具链的一部分，而 Frida 是一个强大的动态插桩工具，广泛应用于逆向工程。这段代码的功能在于帮助 Frida 构建自身，包括其依赖的 CMake 子项目。

**举例说明：**

假设 Frida 的一个 CMake 子项目定义了一个名为 `core` 的共享库。`pretend_to_be_meson` 方法会将 CMake 的库定义转换成类似以下的 Meson 代码：

```meson
core_inc_dir = include_directories(...)
core_sys_dir = include_directories(..., is_system: true)
core_inc = [core_inc_dir, core_sys_dir]
core_src = files(...)
core = shared_library('core', core_src, include_directories: core_inc, ...)
core_dep = declare_dependency(link_with: core, ...)
```

在 Frida 的构建过程中，这段生成的 Meson 代码会被 Meson 构建系统解释执行，从而编译链接出 `core` 共享库，这个库可能是 Frida 核心功能的组成部分，在逆向分析时会被 Frida 加载到目标进程中。

**涉及二进制底层，Linux, Android 内核及框架的知识的举例说明：**

这段代码在处理 CMake 项目时，会涉及到一些底层概念，尽管它本身并不直接操作二进制或内核。

* **链接器 (`self.linkers`)：** 代码会检测 CMake 项目使用的链接器，这与最终生成二进制文件的过程密切相关。不同的平台和架构可能使用不同的链接器（例如 Linux 上的 `ld`，Windows 上的 `link`）。
* **共享库和静态库 (`tgt.meson_func()`)：** 代码需要识别 CMake 目标是共享库还是静态库，并映射到 Meson 对应的函数。这涉及到操作系统加载和链接库的机制。
* **编译选项和链接选项 (`tgt_kwargs`)：** 代码会处理 CMake 的编译和链接选项，例如 `-fPIC`（位置无关代码，用于共享库）、`-l<库名>`（链接库）、`-I<目录>`（包含目录）等。这些选项直接影响最终生成的二进制文件的结构和行为。
* **安装目录 (`tgt_kwargs['install_dir']`)：** 代码会处理安装目录，这涉及到软件部署和操作系统文件系统的知识。在 Linux 和 Android 上，库文件通常安装在特定的系统目录下。

**做了逻辑推理，给出假设输入与输出：**

假设 CMake 子项目中定义了一个名为 `utils` 的静态库，并且依赖于另一个名为 `common` 的头文件库。

**假设输入（CMake 信息，部分模拟）：**

```python
# 假设 ConverterTarget 对象包含以下信息
utils_target = ConverterTarget(..., name='utils', type='STATIC_LIBRARY', sources=['utils.c'], depends=[common_target])
common_target = ConverterTarget(..., name='common', type='INTERFACE_LIBRARY', ...)
```

**输出（`pretend_to_be_meson` 方法生成的 Meson 代码片段）：**

```meson
common_inc_dir = include_directories(...)
common_sys_dir = include_directories(..., is_system: true)
common_inc = [common_inc_dir, common_sys_dir]
common_dep = declare_dependency(include_directories: common_inc)

utils_inc_dir = include_directories(...)
utils_sys_dir = include_directories(..., is_system: true)
utils_inc = [utils_inc_dir, utils_sys_dir]
utils_src = files('utils.c')
utils = static_library('utils', utils_src, include_directories: utils_inc, link_with: common)
utils_dep = declare_dependency(link_with: utils)
```

**涉及用户或者编程常见的使用错误，请举例说明：**

* **CMake 项目配置错误：** 如果 CMake 项目配置本身存在错误，例如依赖项缺失、语法错误等，`CMakeInterpreter` 在配置阶段 (`self.configure`) 可能会失败，并抛出 `CMakeException`。用户需要检查 CMakeLists.txt 文件。
* **不支持的 CMake 特性：**  `CMakeInterpreter` 并非支持所有 CMake 特性。如果 CMake 项目使用了尚未实现的特性，转换过程可能会出错或生成不正确的 Meson 代码。例如，某些复杂的 CMake 模块或特定的生成器表达式可能无法直接映射。
* **依赖循环：** 如果 CMake 项目中存在循环依赖，`pretend_to_be_meson` 方法可能会检测到并抛出 `CMakeException`，提示用户检查依赖关系。
* **自定义目标输出未声明：** 如果自定义目标的输出没有正确声明，后续依赖该输出的目标可能会构建失败。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida 或其包含 CMake 子模块的项目：** 用户通常会使用 Meson 构建系统，执行类似 `meson build` 或 `ninja` 命令。
2. **Meson 检测到 CMake 子项目：** Meson 在解析项目定义文件 (meson.build) 时，会发现使用了 `cmake.subproject()` 函数引入了 CMake 子项目。
3. **Meson 调用 `CMakeTool` 处理 CMake 子项目：** Meson 内部会创建一个 `CMakeTool` 实例来管理 CMake 子项目的构建。
4. **`CMakeTool` 创建 `CMakeInterpreter` 实例：** `CMakeTool` 会创建 `CMakeInterpreter` 的实例，并将 CMake 子项目的相关信息传递给它。
5. **`CMakeInterpreter` 执行配置和分析：**  `CMakeInterpreter` 会依次调用 `configure()` 和 `initialise()` 方法来配置 CMake 子项目，然后调用 `analyse()` 方法来分析 CMake 的构建信息。
6. **`CMakeInterpreter` 调用 `pretend_to_be_meson()` 生成 Meson 代码：** 在分析完成后，`CMakeTool` 会调用 `pretend_to_be_meson()` 方法，将 CMake 的构建信息转换为 Meson 的代码表示。
7. **Meson 使用生成的 Meson 代码构建项目：**  Meson 会将 `pretend_to_be_meson()` 生成的代码添加到主构建图中，并使用 Ninja 等构建工具来执行实际的编译和链接操作。

如果用户在构建过程中遇到与 CMake 子项目相关的问题，例如编译错误或链接错误，那么查看 `frida/subprojects/frida-core/releng/meson/mesonbuild/cmake/interpreter.py` 的日志或调试信息，可以帮助理解 CMake 信息是如何被解析和转换的，从而定位问题所在。例如，查看 `pretend_to_be_meson()` 生成的 Meson 代码是否正确反映了 CMake 的配置和依赖关系。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
mlog.bold(str(self.conflict_map)))
        mlog.log('  -- working_dir:  ', mlog.bold(str(self.working_dir)))
        mlog.log('  -- depends_raw:  ', mlog.bold(str(self.depends_raw)))
        mlog.log('  -- inputs:       ', mlog.bold(str(self.inputs)))
        mlog.log('  -- depends:      ', mlog.bold(str(self.depends)))

class CMakeInterpreter:
    def __init__(self, subdir: Path, install_prefix: Path, env: 'Environment', backend: 'Backend', for_machine: MachineChoice):
        self.subdir = subdir
        self.src_dir = Path(env.get_source_dir(), subdir)
        self.build_dir_rel = subdir / '__CMake_build'
        self.build_dir = Path(env.get_build_dir()) / self.build_dir_rel
        self.install_prefix = install_prefix
        self.env = env
        self.for_machine = for_machine
        self.backend_name = backend.name
        self.linkers: T.Set[str] = set()
        self.fileapi = CMakeFileAPI(self.build_dir)

        # Raw CMake results
        self.bs_files: T.List[Path] = []
        self.codemodel_configs: T.Optional[T.List[CMakeConfiguration]] = None
        self.cmake_stderr: T.Optional[str] = None

        # Analysed data
        self.project_name = ''
        self.project_version = ''
        self.languages: T.List[str] = []
        self.targets: T.List[ConverterTarget] = []
        self.custom_targets: T.List[ConverterCustomTarget] = []
        self.trace: CMakeTraceParser
        self.output_target_map = OutputTargetMap(self.build_dir)

        # Generated meson data
        self.generated_targets: T.Dict[str, T.Dict[str, T.Optional[str]]] = {}
        self.internal_name_map: T.Dict[str, str] = {}

        # Do some special handling for object libraries for certain configurations
        self._object_lib_workaround = False
        if self.backend_name.startswith('vs'):
            for comp in self.env.coredata.compilers[self.for_machine].values():
                if comp.get_linker_id() == 'link':
                    self._object_lib_workaround = True
                    break

    def configure(self, extra_cmake_options: T.List[str]) -> CMakeExecutor:
        # Find CMake
        cmake_exe = CMakeExecutor(self.env, '>=3.14', self.for_machine)
        if not cmake_exe.found():
            raise CMakeException('Unable to find CMake')
        self.trace = CMakeTraceParser(cmake_exe.version(), self.build_dir, self.env, permissive=True)

        preload_file = DataFile('cmake/data/preload.cmake').write_to_private(self.env)
        toolchain = CMakeToolchain(cmake_exe, self.env, self.for_machine, CMakeExecScope.SUBPROJECT, self.build_dir, preload_file)
        toolchain_file = toolchain.write()

        # TODO: drop this check once the deprecated `cmake_args` kwarg is removed
        extra_cmake_options = check_cmake_args(extra_cmake_options)

        cmake_args = []
        cmake_args += cmake_get_generator_args(self.env)
        cmake_args += [f'-DCMAKE_INSTALL_PREFIX={self.install_prefix}']
        cmake_args += extra_cmake_options
        trace_args = self.trace.trace_args()
        cmcmp_args = [f'-DCMAKE_POLICY_WARNING_{x}=OFF' for x in disable_policy_warnings]

        self.fileapi.setup_request()

        # Run CMake
        mlog.log()
        with mlog.nested():
            mlog.log('Configuring the build directory with', mlog.bold('CMake'), 'version', mlog.cyan(cmake_exe.version()))
            mlog.log(mlog.bold('Running CMake with:'), ' '.join(cmake_args))
            mlog.log(mlog.bold('  - build directory:         '), self.build_dir.as_posix())
            mlog.log(mlog.bold('  - source directory:        '), self.src_dir.as_posix())
            mlog.log(mlog.bold('  - toolchain file:          '), toolchain_file.as_posix())
            mlog.log(mlog.bold('  - preload file:            '), preload_file.as_posix())
            mlog.log(mlog.bold('  - trace args:              '), ' '.join(trace_args))
            mlog.log(mlog.bold('  - disabled policy warnings:'), '[{}]'.format(', '.join(disable_policy_warnings)))
            mlog.log()
            self.build_dir.mkdir(parents=True, exist_ok=True)
            os_env = environ.copy()
            os_env['LC_ALL'] = 'C'
            final_args = cmake_args + trace_args + cmcmp_args + toolchain.get_cmake_args() + [self.src_dir.as_posix()]

            cmake_exe.set_exec_mode(print_cmout=True, always_capture_stderr=self.trace.requires_stderr())
            rc, _, self.cmake_stderr = cmake_exe.call(final_args, self.build_dir, env=os_env, disable_cache=True)

        mlog.log()
        h = mlog.green('SUCCEEDED') if rc == 0 else mlog.red('FAILED')
        mlog.log('CMake configuration:', h)
        if rc != 0:
            # get the last CMake error - We only need the message function for this:
            self.trace.functions = {'message': self.trace.functions['message']}
            self.trace.parse(self.cmake_stderr)
            error = f': {self.trace.errors[-1]}' if self.trace.errors else ''
            raise CMakeException(f'Failed to configure the CMake subproject{error}')

        return cmake_exe

    def initialise(self, extra_cmake_options: T.List[str]) -> None:
        # Configure the CMake project to generate the file API data
        self.configure(extra_cmake_options)

        # Parse the result
        self.fileapi.load_reply()

        # Load the buildsystem file list
        cmake_files = self.fileapi.get_cmake_sources()
        self.bs_files = [x.file for x in cmake_files if not x.is_cmake and not x.is_temp]
        self.bs_files = [relative_to_if_possible(x, Path(self.env.get_source_dir())) for x in self.bs_files]
        self.bs_files = [x for x in self.bs_files if not path_is_in_root(x, Path(self.env.get_build_dir()), resolve=True)]
        self.bs_files = list(OrderedSet(self.bs_files))

        # Load the codemodel configurations
        self.codemodel_configs = self.fileapi.get_cmake_configurations()

        self.project_version = self.fileapi.get_project_version()

    def analyse(self) -> None:
        if self.codemodel_configs is None:
            raise CMakeException('CMakeInterpreter was not initialized')

        # Clear analyser data
        self.project_name = ''
        self.languages = []
        self.targets = []
        self.custom_targets = []

        # Parse the trace
        self.trace.parse(self.cmake_stderr)

        # Find all targets
        added_target_names: T.List[str] = []
        for i_0 in self.codemodel_configs:
            for j_0 in i_0.projects:
                if not self.project_name:
                    self.project_name = j_0.name
                for k_0 in j_0.targets:
                    # Avoid duplicate targets from different configurations and known
                    # dummy CMake internal target types
                    if k_0.type not in skip_targets and k_0.name not in added_target_names:
                        added_target_names += [k_0.name]
                        self.targets += [ConverterTarget(k_0, self.env, self.for_machine)]

        # Add interface targets from trace, if not already present.
        # This step is required because interface targets were removed from
        # the CMake file API output.
        api_target_name_list = [x.name for x in self.targets]
        for i_1 in self.trace.targets.values():
            if i_1.type != 'INTERFACE' or i_1.name in api_target_name_list or i_1.imported:
                continue
            dummy = CMakeTarget({
                'name': i_1.name,
                'type': 'INTERFACE_LIBRARY',
                'sourceDirectory': self.src_dir,
                'buildDirectory': self.build_dir,
            })
            self.targets += [ConverterTarget(dummy, self.env, self.for_machine)]

        for i_2 in self.trace.custom_targets:
            self.custom_targets += [ConverterCustomTarget(i_2, self.env, self.for_machine)]

        # generate the output_target_map
        for i_3 in [*self.targets, *self.custom_targets]:
            assert isinstance(i_3, (ConverterTarget, ConverterCustomTarget))
            self.output_target_map.add(i_3)

        # First pass: Basic target cleanup
        object_libs = []
        custom_target_outputs: T.List[str] = []
        for ctgt in self.custom_targets:
            ctgt.postprocess(self.output_target_map, self.src_dir, custom_target_outputs, self.trace)
        for tgt in self.targets:
            tgt.postprocess(self.output_target_map, self.src_dir, self.subdir, self.install_prefix, self.trace)
            if tgt.type == 'OBJECT_LIBRARY':
                object_libs += [tgt]
            self.languages += [x for x in tgt.languages if x not in self.languages]

        # Second pass: Detect object library dependencies
        for tgt in self.targets:
            tgt.process_object_libs(object_libs, self._object_lib_workaround)

        # Third pass: Reassign dependencies to avoid some loops
        for tgt in self.targets:
            tgt.process_inter_target_dependencies()
        for ctgt in self.custom_targets:
            ctgt.process_inter_target_dependencies()

        # Fourth pass: Remove rassigned dependencies
        for tgt in self.targets:
            tgt.cleanup_dependencies()

        mlog.log('CMake project', mlog.bold(self.project_name), mlog.bold(self.project_version), 'has', mlog.bold(str(len(self.targets) + len(self.custom_targets))), 'build targets.')

    def pretend_to_be_meson(self, options: TargetOptions) -> CodeBlockNode:
        if not self.project_name:
            raise CMakeException('CMakeInterpreter was not analysed')

        def token(tid: str = 'string', val: TYPE_mixed = '') -> Token:
            return Token(tid, self.subdir.as_posix(), 0, 0, 0, None, val)

        def symbol(val: str) -> SymbolNode:
            return SymbolNode(token('', val))

        def string(value: str) -> StringNode:
            return StringNode(token(val=value), escape=False)

        def id_node(value: str) -> IdNode:
            return IdNode(token(val=value))

        def number(value: int) -> NumberNode:
            return NumberNode(token(val=str(value)))

        def nodeify(value: TYPE_mixed_list) -> BaseNode:
            if isinstance(value, str):
                return string(value)
            if isinstance(value, Path):
                return string(value.as_posix())
            elif isinstance(value, bool):
                return BooleanNode(token(val=value))
            elif isinstance(value, int):
                return number(value)
            elif isinstance(value, list):
                return array(value)
            elif isinstance(value, BaseNode):
                return value
            raise RuntimeError('invalid type of value: {} ({})'.format(type(value).__name__, str(value)))

        def indexed(node: BaseNode, index: int) -> IndexNode:
            return IndexNode(node, symbol('['), nodeify(index), symbol(']'))

        def array(elements: TYPE_mixed_list) -> ArrayNode:
            args = ArgumentNode(token())
            if not isinstance(elements, list):
                elements = [args]
            args.arguments += [nodeify(x) for x in elements if x is not None]
            return ArrayNode(symbol('['), args, symbol(']'))

        def function(name: str, args: T.Optional[TYPE_mixed_list] = None, kwargs: T.Optional[TYPE_mixed_kwargs] = None) -> FunctionNode:
            args = [] if args is None else args
            kwargs = {} if kwargs is None else kwargs
            args_n = ArgumentNode(token())
            if not isinstance(args, list):
                assert isinstance(args, (str, int, bool, Path, BaseNode))
                args = [args]
            args_n.arguments = [nodeify(x) for x in args if x is not None]
            args_n.kwargs = {id_node(k): nodeify(v) for k, v in kwargs.items() if v is not None}
            func_n = FunctionNode(id_node(name), symbol('('), args_n, symbol(')'))
            return func_n

        def method(obj: BaseNode, name: str, args: T.Optional[TYPE_mixed_list] = None, kwargs: T.Optional[TYPE_mixed_kwargs] = None) -> MethodNode:
            args = [] if args is None else args
            kwargs = {} if kwargs is None else kwargs
            args_n = ArgumentNode(token())
            if not isinstance(args, list):
                assert isinstance(args, (str, int, bool, Path, BaseNode))
                args = [args]
            args_n.arguments = [nodeify(x) for x in args if x is not None]
            args_n.kwargs = {id_node(k): nodeify(v) for k, v in kwargs.items() if v is not None}
            return MethodNode(obj, symbol('.'), id_node(name), symbol('('), args_n, symbol(')'))

        def assign(var_name: str, value: BaseNode) -> AssignmentNode:
            return AssignmentNode(id_node(var_name), symbol('='), value)

        # Generate the root code block and the project function call
        root_cb = CodeBlockNode(token())
        root_cb.lines += [function('project', [self.project_name] + self.languages, {'version': self.project_version} if self.project_version else None)]

        # Add the run script for custom commands

        # Add the targets
        processing: T.List[str] = []
        processed: T.Dict[str, T.Dict[str, T.Optional[str]]] = {}
        name_map: T.Dict[str, str] = {}

        def extract_tgt(tgt: T.Union[ConverterTarget, ConverterCustomTarget, CustomTargetReference]) -> IdNode:
            tgt_name = None
            if isinstance(tgt, (ConverterTarget, ConverterCustomTarget)):
                tgt_name = tgt.name
            elif isinstance(tgt, CustomTargetReference):
                tgt_name = tgt.ctgt.name
            assert tgt_name is not None and tgt_name in processed
            res_var = processed[tgt_name]['tgt']
            return id_node(res_var) if res_var else None

        def detect_cycle(tgt: T.Union[ConverterTarget, ConverterCustomTarget]) -> None:
            if tgt.name in processing:
                raise CMakeException('Cycle in CMake inputs/dependencies detected')
            processing.append(tgt.name)

        def resolve_ctgt_ref(ref: CustomTargetReference) -> T.Union[IdNode, IndexNode]:
            tgt_var = extract_tgt(ref)
            if len(ref.ctgt.outputs) == 1:
                return tgt_var
            else:
                return indexed(tgt_var, ref.index)

        def process_target(tgt: ConverterTarget) -> None:
            detect_cycle(tgt)

            # First handle inter target dependencies
            link_with: T.List[IdNode] = []
            objec_libs: T.List[IdNode] = []
            sources: T.List[Path] = []
            generated: T.List[T.Union[IdNode, IndexNode]] = []
            generated_filenames: T.List[str] = []
            custom_targets: T.List[ConverterCustomTarget] = []
            dependencies: T.List[IdNode] = []
            for i in tgt.link_with:
                assert isinstance(i, ConverterTarget)
                if i.name not in processed:
                    process_target(i)
                link_with += [extract_tgt(i)]
            for i in tgt.object_libs:
                assert isinstance(i, ConverterTarget)
                if i.name not in processed:
                    process_target(i)
                objec_libs += [extract_tgt(i)]
            for i in tgt.depends:
                if not isinstance(i, ConverterCustomTarget):
                    continue
                if i.name not in processed:
                    process_custom_target(i)
                dependencies += [extract_tgt(i)]

            # Generate the source list and handle generated sources
            sources += tgt.sources
            sources += tgt.generated

            for ctgt_ref in tgt.generated_ctgt:
                ctgt = ctgt_ref.ctgt
                if ctgt.name not in processed:
                    process_custom_target(ctgt)
                generated += [resolve_ctgt_ref(ctgt_ref)]
                generated_filenames += [ctgt_ref.filename()]
                if ctgt not in custom_targets:
                    custom_targets += [ctgt]

            # Add all header files from all used custom targets. This
            # ensures that all custom targets are built before any
            # sources of the current target are compiled and thus all
            # header files are present. This step is necessary because
            # CMake always ensures that a custom target is executed
            # before another target if at least one output is used.
            for ctgt in custom_targets:
                for j in ctgt.outputs:
                    if not is_header(j) or j in generated_filenames:
                        continue

                    generated += [resolve_ctgt_ref(ctgt.get_ref(Path(j)))]
                    generated_filenames += [j]

            # Determine the meson function to use for the build target
            tgt_func = tgt.meson_func()
            if not tgt_func:
                raise CMakeException(f'Unknown target type "{tgt.type}"')

            # Determine the variable names
            inc_var = f'{tgt.name}_inc'
            dir_var = f'{tgt.name}_dir'
            sys_var = f'{tgt.name}_sys'
            src_var = f'{tgt.name}_src'
            dep_var = f'{tgt.name}_dep'
            tgt_var = tgt.name

            install_tgt = options.get_install(tgt.cmake_name, tgt.install)

            # Generate target kwargs
            tgt_kwargs: TYPE_mixed_kwargs = {
                'build_by_default': install_tgt,
                'link_args': options.get_link_args(tgt.cmake_name, tgt.link_flags + tgt.link_libraries),
                'link_with': link_with,
                'include_directories': id_node(inc_var),
                'install': install_tgt,
                'override_options': options.get_override_options(tgt.cmake_name, tgt.override_options),
                'objects': [method(x, 'extract_all_objects') for x in objec_libs],
            }

            # Only set if installed and only override if it is set
            if install_tgt and tgt.install_dir:
                tgt_kwargs['install_dir'] = tgt.install_dir

            # Handle compiler args
            for key, val in tgt.compile_opts.items():
                tgt_kwargs[f'{key}_args'] = options.get_compile_args(tgt.cmake_name, key, val)

            # Handle -fPCI, etc
            if tgt_func == 'executable':
                tgt_kwargs['pie'] = tgt.pie
            elif tgt_func == 'static_library':
                tgt_kwargs['pic'] = tgt.pie

            # declare_dependency kwargs
            dep_kwargs: TYPE_mixed_kwargs = {
                'link_args': tgt.link_flags + tgt.link_libraries,
                'link_with': id_node(tgt_var),
                'compile_args': tgt.public_compile_opts,
                'include_directories': id_node(inc_var),
            }

            if dependencies:
                generated += dependencies

            # Generate the function nodes
            dir_node = assign(dir_var, function('include_directories', tgt.includes))
            sys_node = assign(sys_var, function('include_directories', tgt.sys_includes, {'is_system': True}))
            inc_node = assign(inc_var, array([id_node(dir_var), id_node(sys_var)]))
            node_list = [dir_node, sys_node, inc_node]
            if tgt_func == 'header_only':
                del dep_kwargs['link_with']
                dep_node = assign(dep_var, function('declare_dependency', kwargs=dep_kwargs))
                node_list += [dep_node]
                src_var = None
                tgt_var = None
            else:
                src_node = assign(src_var, function('files', sources))
                tgt_node = assign(tgt_var, function(tgt_func, [tgt_var, id_node(src_var), *generated], tgt_kwargs))
                node_list += [src_node, tgt_node]
                if tgt_func in {'static_library', 'shared_library'}:
                    dep_node = assign(dep_var, function('declare_dependency', kwargs=dep_kwargs))
                    node_list += [dep_node]
                elif tgt_func == 'shared_module':
                    del dep_kwargs['link_with']
                    dep_node = assign(dep_var, function('declare_dependency', kwargs=dep_kwargs))
                    node_list += [dep_node]
                else:
                    dep_var = None

            # Add the nodes to the ast
            root_cb.lines += node_list
            processed[tgt.name] = {'inc': inc_var, 'src': src_var, 'dep': dep_var, 'tgt': tgt_var, 'func': tgt_func}
            name_map[tgt.cmake_name] = tgt.name

        def process_custom_target(tgt: ConverterCustomTarget) -> None:
            # CMake allows to specify multiple commands in a custom target.
            # To map this to meson, a helper script is used to execute all
            # commands in order. This additionally allows setting the working
            # directory.

            detect_cycle(tgt)
            tgt_var = tgt.name

            def resolve_source(x: T.Union[str, ConverterTarget, ConverterCustomTarget, CustomTargetReference]) -> T.Union[str, IdNode, IndexNode]:
                if isinstance(x, ConverterTarget):
                    if x.name not in processed:
                        process_target(x)
                    return extract_tgt(x)
                if isinstance(x, ConverterCustomTarget):
                    if x.name not in processed:
                        process_custom_target(x)
                    return extract_tgt(x)
                elif isinstance(x, CustomTargetReference):
                    if x.ctgt.name not in processed:
                        process_custom_target(x.ctgt)
                    return resolve_ctgt_ref(x)
                else:
                    return x

            # Generate the command list
            command: T.List[T.Union[str, IdNode, IndexNode]] = []
            command += mesonlib.get_meson_command()
            command += ['--internal', 'cmake_run_ctgt']
            command += ['-o', '@OUTPUT@']
            if tgt.original_outputs:
                command += ['-O'] + [x.as_posix() for x in tgt.original_outputs]
            command += ['-d', tgt.working_dir.as_posix()]

            # Generate the commands. Subcommands are separated by ';;;'
            for cmd in tgt.command:
                command += [resolve_source(x) for x in cmd] + [';;;']

            tgt_kwargs: TYPE_mixed_kwargs = {
                'input': [resolve_source(x) for x in tgt.inputs],
                'output': tgt.outputs,
                'command': command,
                'depends': [resolve_source(x) for x in tgt.depends],
            }

            root_cb.lines += [assign(tgt_var, function('custom_target', [tgt.name], tgt_kwargs))]
            processed[tgt.name] = {'inc': None, 'src': None, 'dep': None, 'tgt': tgt_var, 'func': 'custom_target'}
            name_map[tgt.cmake_name] = tgt.name

        # Now generate the target function calls
        for ctgt in self.custom_targets:
            if ctgt.name not in processed:
                process_custom_target(ctgt)
        for tgt in self.targets:
            if tgt.name not in processed:
                process_target(tgt)

        self.generated_targets = processed
        self.internal_name_map = name_map
        return root_cb

    def target_info(self, target: str) -> T.Optional[T.Dict[str, str]]:
        # Try resolving the target name
        # start by checking if there is a 100% match (excluding the name prefix)
        prx_tgt = _sanitize_cmake_name(target)
        if prx_tgt in self.generated_targets:
            return self.generated_targets[prx_tgt]
        # check if there exists a name mapping
        if target in self.internal_name_map:
            target = self.internal_name_map[target]
            assert target in self.generated_targets
            return self.generated_targets[target]
        return None

    def target_list(self) -> T.List[str]:
        return list(self.internal_name_map.keys())

"""


```