Response:
The user wants a summary of the functionality of the provided Python code, which is part of the Frida dynamic instrumentation tool and located in `frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/interpreter.py`. The request also specifies constraints related to reverse engineering, low-level details (binary, Linux, Android kernel/framework), logical reasoning, common user errors, and how a user might reach this code.

Here's a breakdown of the thought process to generate the answer:

1. **Understand the Core Purpose:** The file name `interpreter.py` within a `cmake` directory strongly suggests this code is responsible for interpreting CMake projects. The broader context of `frida-node` and `releng/meson` hints at converting or integrating CMake-based subprojects into a Meson build system used by Frida.

2. **High-Level Functionality Extraction (from the class `CMakeInterpreter`):**
    * **Initialization (`__init__`)**: Sets up the interpreter, including paths, environment, and data structures to store CMake project information.
    * **Configuration (`configure`)**:  Executes CMake in a subproject's build directory. This involves finding the CMake executable, setting up toolchain files, and passing necessary arguments.
    * **Initialization (`initialise`)**:  Configures CMake and then parses the generated CMake File API data to extract information about source files, build configurations, and the project version.
    * **Analysis (`analyse`)**:  Parses the CMake trace output and the File API data to extract information about targets (libraries, executables, custom commands), their dependencies, languages used, etc.
    * **Meson Code Generation (`pretend_to_be_meson`)**:  The most complex function. It takes the analyzed CMake project information and generates equivalent Meson build definitions (as an Abstract Syntax Tree). This is the core of the conversion process.
    * **Target Information Retrieval (`target_info`)**:  Allows querying information about a specific target based on its name.
    * **Target List Retrieval (`target_list`)**:  Returns a list of all targets in the CMake project.

3. **Relate to Reverse Engineering:**  Frida is a dynamic instrumentation tool heavily used in reverse engineering. This code helps integrate libraries or components built with CMake into Frida. Examples:
    * Frida might need to include a third-party library (built with CMake) to perform specific analysis.
    * A user reverse-engineering an application using Frida might encounter a component built with CMake, and this code is involved in making that component part of the Frida build.

4. **Identify Low-Level Aspects:**
    * **Binary:**  CMake is used to build binaries (executables, shared libraries). The `CMakeInterpreter` is involved in the process of preparing those binaries for inclusion in Frida. The toolchain setup is crucial for generating platform-specific binaries.
    * **Linux:**  The code interacts with the operating system (e.g., creating directories, executing CMake). The toolchain and build processes are platform-dependent.
    * **Android Kernel/Framework:** Frida runs on Android. This code could be used to integrate CMake-based components that interact with Android's framework or even (less likely directly, but indirectly) with kernel components. The toolchain would need to be configured for Android.

5. **Deduce Logical Reasoning and Hypothetical Input/Output:**
    * **Input:** The `CMakeInterpreter` takes a subdirectory path within the Frida source tree as input. It also receives extra CMake options.
    * **Reasoning:** The code analyzes the CMake project's structure and dependencies. For example, it determines the order in which targets need to be built and how they link together. The `process_target` and `process_custom_target` functions demonstrate complex logic for translating CMake targets to Meson equivalents. The cycle detection in dependencies (`detect_cycle`) is a clear example of logical reasoning.
    * **Output:** The primary output of `pretend_to_be_meson` is an Abstract Syntax Tree representing the Meson build definition for the CMake subproject. This AST is then used by Meson to generate the actual build files (like Ninja build files). `target_info` returns a dictionary containing information about a target.

6. **Consider Common User Errors:**
    * **Incorrect CMake arguments:** Users might provide invalid or conflicting `extra_cmake_options`, leading to CMake configuration failures.
    * **Missing CMake:** If CMake is not installed or not in the system's PATH, the `CMakeExecutor` will fail.
    * **Dependency cycles:**  If the CMake project has circular dependencies, the `detect_cycle` function will raise an error.
    * **Incorrect paths:** Issues with `subdir` or `install_prefix` could lead to problems finding source files or installing the built components.

7. **Trace User Actions to Reach the Code:**
    * A Frida developer wants to include a new feature or component in Frida that is built using CMake.
    * They add the CMake project as a subdirectory within Frida's source tree.
    * They configure Frida's build system (likely using Meson).
    * Meson, when processing the Frida project, encounters a `meson.build` file that instructs it to process the CMake subproject.
    * Meson then instantiates the `CMakeInterpreter` with the relevant subdirectory.
    * The `configure`, `initialise`, `analyse`, and `pretend_to_be_meson` methods are called in sequence to parse the CMake project and generate the Meson equivalents.

8. **Functionality Summary (Part 2 - the concluding statement):**  The core function is to bridge the gap between CMake and Meson. It takes a CMake project and generates equivalent Meson build definitions, allowing CMake-based components to be seamlessly integrated into Frida's Meson-based build system. This involves configuring and analyzing the CMake project and then translating its structure and targets into Meson's syntax.
好的，这是对提供的 Python 源代码文件 `frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/interpreter.py` 的功能归纳（第 2 部分）：

**主要功能总结:**

这个 Python 模块的核心功能是将 CMake 构建的项目信息转换成 Meson 构建系统的表示形式。它通过执行 CMake 并解析其输出（包括 File API 和 trace 信息）来理解 CMake 项目的结构、目标、依赖关系和构建选项，然后生成相应的 Meson 代码片段。

**功能点细化：**

* **生成 Meson 代码 (`pretend_to_be_meson`)**: 这是该模块的核心功能。它基于对 CMake 项目的分析，生成 Meson 构建文件的代码片段（以抽象语法树的形式）。这个过程涉及到：
    * **目标类型映射**: 将 CMake 的目标类型（例如 `EXECUTABLE`, `STATIC_LIBRARY`, `SHARED_LIBRARY`, `CUSTOM_COMMAND`）映射到 Meson 中对应的函数。
    * **依赖关系转换**: 将 CMake 的目标间依赖、库依赖、头文件依赖等转换为 Meson 的依赖声明。
    * **编译选项和链接选项转换**: 将 CMake 中设置的编译选项、链接选项等转换为 Meson 的参数。
    * **自定义命令处理**: 将 CMake 的自定义命令转换为 Meson 的 `custom_target`。为了处理 CMake 自定义命令可能包含多个子命令的情况，它会生成一个辅助脚本来执行这些命令。
    * **文件处理**: 将 CMake 的源文件列表转换为 Meson 的 `files()` 函数调用。
    * **头文件目录处理**: 将 CMake 的头文件包含路径转换为 Meson 的 `include_directories()` 函数调用。
    * **生成中间变量**:  为了组织 Meson 代码，会生成一些中间变量，例如存储头文件目录、源文件列表、依赖对象等。
    * **处理循环依赖**:  检测 CMake 项目中是否存在循环依赖，如果存在则抛出异常。
    * **处理自定义目标引用**:  正确引用自定义目标的输出文件。

* **目标信息查询 (`target_info`)**: 提供一个接口，根据目标名称查询已生成的 Meson 代码中对应目标的信息，例如目标变量名、类型等。

* **目标列表获取 (`target_list`)**:  返回 CMake 项目中所有目标的名称列表。

**与逆向方法的关联 (延续第 1 部分的思路):**

* **自动化构建集成**: 在逆向工程中，可能需要使用 Frida 来操作或hook由 CMake 构建的目标（例如，动态库）。这个模块的功能使得将这些 CMake 构建的组件集成到 Frida 的构建流程中变得自动化。逆向工程师不必手动编写 Meson 构建文件来包含这些组件。
* **动态库加载**:  如果逆向的目标应用依赖于一个用 CMake 构建的动态库，并且这个库被 Frida 集成，那么这个模块就参与了构建这个库的过程，最终使得 Frida 能够在运行时加载并hook这个动态库。

**涉及二进制底层、Linux、Android 内核及框架的知识 (延续第 1 部分的思路):**

* **目标类型映射**:  在将 CMake 的目标类型映射到 Meson 时，需要理解不同目标类型（例如静态库、动态库、可执行文件）在底层二进制构建过程中的差异，以及它们在 Linux 和 Android 等操作系统上的加载和链接方式。
* **链接选项**: 处理 CMake 的链接选项需要理解链接器的工作原理，以及在不同平台（包括 Android）上常用的链接选项。例如，对于 Android，可能需要处理 `-llog` 等链接到 Android 系统库的选项。
* **编译选项**:  处理编译选项需要理解编译器的工作原理，以及在不同平台上的特定编译选项。例如，处理与位置无关代码（PIC）相关的选项。

**逻辑推理的假设输入与输出：**

假设有一个简单的 CMake 项目，包含一个名为 `mylib` 的静态库和一个名为 `myapp` 的可执行文件，`myapp` 链接到 `mylib`。

**假设输入 (经过 `analyse` 阶段):**

* `self.targets` 包含两个 `ConverterTarget` 对象，分别代表 `mylib` 和 `myapp`。
* `mylib` 的 `name` 为 "mylib"， `type` 为 "STATIC_LIBRARY"。
* `myapp` 的 `name` 为 "myapp"， `type` 为 "EXECUTABLE"， `link_with` 包含 `mylib` 的 `ConverterTarget` 对象。
* `self.project_name` 为项目的名称。
* `self.languages` 包含使用的编程语言。

**预期输出 ( `pretend_to_be_meson` 生成的 Meson 代码片段 - 简化版):**

```meson
project('myproject', 'c') # 假设语言是 C

mylib_inc_dir = include_directories('include')
mylib_sys_inc_dir = include_directories(system_include_dirs, is_system : true)
mylib_inc = [mylib_inc_dir, mylib_sys_inc_dir]
mylib_src = files('src/mylib.c')
mylib = static_library('mylib', mylib_src, include_directories: mylib_inc, install : false)
mylib_dep = declare_dependency(link_with : mylib, include_directories : mylib_inc)

myapp_inc_dir = include_directories('include')
myapp_sys_inc_dir = include_directories(system_include_dirs, is_system : true)
myapp_inc = [myapp_inc_dir, myapp_sys_inc_dir]
myapp_src = files('src/myapp.c')
myapp = executable('myapp', myapp_src, link_with : mylib, include_directories: myapp_inc, install : false)
```

**涉及用户或者编程常见的使用错误：**

* **CMake 项目配置错误**: 如果 CMake 项目本身的配置存在错误（例如，未定义的依赖项、错误的源文件路径），`CMakeInterpreter` 在配置或分析阶段可能会失败，并抛出异常。用户需要检查 CMakeLists.txt 文件。
* **不支持的 CMake 特性**:  Meson 可能不支持某些复杂的 CMake 特性或语法。如果 CMake 项目使用了这些特性，`pretend_to_be_meson` 可能会生成不正确的 Meson 代码，或者抛出异常。
* **依赖循环**: 如果 CMake 项目存在循环依赖，`detect_cycle` 函数会捕获到并报错，提示用户需要解决依赖关系问题。
* **自定义命令的复杂性**:  如果 CMake 的自定义命令非常复杂，包含大量的输入输出和命令序列，将其转换为 Meson 的 `custom_target` 可能需要仔细的映射和调整。用户可能需要理解 Meson `custom_target` 的工作方式。
* **文件路径问题**:  在处理源文件、头文件等路径时，如果路径不正确或不一致，会导致生成的 Meson 代码无法找到这些文件。

**用户操作是如何一步步的到达这里，作为调试线索 (延续第 1 部分的思路):**

1. **Frida 构建配置**: 用户在配置 Frida 的构建环境时，Meson 会读取 `meson.build` 文件。
2. **子项目声明**: Frida 的 `meson.build` 文件中可能声明了一个需要集成的 CMake 子项目，并指定了该子项目的路径。
3. **CMakeInterpreter 调用**: Meson 在处理到该子项目时，会实例化 `CMakeInterpreter` 对象，并将子项目的路径等信息传递给它。
4. **配置和分析**: `CMakeInterpreter` 会首先调用 `configure` 方法来执行 CMake 配置，然后调用 `initialise` 方法来加载 CMake File API 数据，接着调用 `analyse` 方法来解析 CMake 项目的信息。
5. **生成 Meson 代码**:  最后，调用 `pretend_to_be_meson` 方法来生成 Meson 构建代码。
6. **调试**: 如果用户在构建 Frida 时遇到与该 CMake 子项目相关的问题，他们可能会查看 `frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/interpreter.py` 的代码，以了解 CMake 项目是如何被解析和转换的，从而找到问题的根源。例如，他们可能会检查生成的 Meson 代码是否正确，或者查看 CMake 的 trace 信息以了解 CMake 配置过程中是否出现错误。他们可能会在 `pretend_to_be_meson` 函数中设置断点，查看 CMake 项目的哪些信息被提取出来，以及如何转换为 Meson 代码。

总而言之，这个 Python 模块是 Frida 构建系统中一个关键的组件，它负责将基于 CMake 构建的外部代码集成到 Frida 的 Meson 构建流程中，从而简化了构建过程，并允许 Frida 利用 CMake 生态系统中的各种库和组件。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/cmake/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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