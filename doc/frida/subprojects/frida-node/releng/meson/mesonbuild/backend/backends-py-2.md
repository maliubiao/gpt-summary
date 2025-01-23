Response:
The user wants to understand the functionality of the provided Python code snippet from `backends.py`, which is part of the Frida dynamic instrumentation tool's build system. I need to analyze each method in the code and explain its purpose, relating it to reverse engineering concepts, low-level details (like kernel/framework knowledge), logical inferences, potential user errors, and how a user might trigger this code during debugging. Finally, I need to summarize the overall functionality of this part of the file.

Here's a breakdown of how I'll approach each method:

1. **`get_dep_info`**: This method seems to gather dependency information for targets. I'll explain how this is crucial for build systems and how it might be used in reverse engineering to understand component relationships.

2. **`get_custom_target_provided_by_generated_source`**: This method likely identifies libraries produced by custom targets. I'll link this to reverse engineering by explaining how generated code is often a target for analysis.

3. **`get_custom_target_provided_libraries`**:  This expands on the previous method, finding libraries provided by custom targets through their generated sources.

4. **`get_custom_target_sources`**: This method retrieves the source files for a custom target. I'll detail the different source types it handles and how this information is fundamental to understanding the build process and, consequently, the target being built.

5. **`get_target_depend_files`**: This method gets explicit dependency files. I'll explain how these are used in build systems to track changes and how this could be relevant in reverse engineering to identify configuration files or data dependencies.

6. **`get_custom_target_output_dir`**: This method determines the output directory for a custom target. I'll note the special case for Xcode and the implications for file locations during the build.

7. **`get_normpath_target`**: This method normalizes a path, which is a standard utility function.

8. **`get_custom_target_dirs`**: This retrieves include directories for custom targets. I'll explain how include paths are vital for compilation and how knowing these paths can be useful when analyzing compiled binaries.

9. **`get_custom_target_dir_include_args`**:  This method generates the compiler arguments for include directories.

10. **`eval_custom_target_command`**: This is a crucial method that evaluates the command to be executed for a custom target. I'll break down how it handles different command arguments and template substitutions, highlighting its significance in understanding the build process of potentially complex components.

11. **`get_introspect_command`**:  This retrieves the command to run the introspection tool.

12. **`get_run_target_env`**: This method sets up the environment variables for running a target, which is important for both building and debugging.

13. **`run_postconf_scripts`**: This method executes post-configuration scripts, and I'll explain how these can be used to further customize the build.

14. **`create_install_data`**: This is a significant method that creates data structures for the installation process. I'll describe the different types of installation data it handles.

15. **`create_install_data_files`**: This method serializes the installation data to a file.

16. **`guess_install_tag`**: This method tries to infer the installation tag for a file.

17. **`generate_target_install`**: This method populates the installation data with information about targets (executables, libraries, etc.). I'll detail how it handles different target types and installation options.

18. **`generate_custom_install_script`**: This method adds custom install scripts to the installation data.

19. **`generate_header_install`**: This method handles the installation of header files.

20. **`generate_man_install`**: This method handles the installation of man pages.

21. **`generate_emptydir_install`**: This method handles the creation of empty directories during installation.

22. **`generate_data_install`**: This method manages the installation of data files.

23. **`generate_symlink_install`**: This method manages the creation of symbolic links during installation.

24. **`generate_subdir_install`**: This method handles the installation of entire subdirectories.

25. **`get_introspection_data`**: This method generates data for introspection, providing details about targets.

26. **`get_devenv`**: This method sets up the development environment variables.

27. **`compiler_to_generator`**: This method seems to be a utility for backends that don't support custom compilers.

For each relevant method, I'll provide examples, particularly focusing on how they relate to reverse engineering, low-level knowledge, potential errors, and debugging workflows. The overall summary will synthesize the functionality of these methods within the build process.
这是 frida 动态Instrumentation 工具的构建系统中，负责处理构建后端逻辑的一部分代码。它主要负责将 Meson 构建系统的抽象表示转换为特定构建后端（例如 Ninja, Xcode, Visual Studio）所需的具体构建指令和文件。

以下是这段代码的功能及其与逆向、底层知识、逻辑推理、用户错误和调试线索的关系：

**核心功能归纳:**

这段代码的主要功能是 **管理和转换构建目标（targets）的信息，以便生成特定构建系统所需的构建文件**。它负责处理各种类型的构建目标（例如：可执行文件、库、自定义目标），并提取和转换其属性，如源文件、依赖、输出路径、安装规则等。

**具体功能分解与举例说明:**

1. **`get_dep_info(self, target: build.Target) -> T.Dict[str, build.Target]`:**
   - **功能:**  获取给定构建目标的所有依赖目标的信息。它遍历目标的依赖列表，并将依赖目标存储在一个字典中，键是目标的 ID。
   - **与逆向的关系:** 在逆向分析中，了解一个二进制文件的依赖关系非常重要。例如，要分析一个可执行文件，需要知道它链接了哪些库。这个函数在构建过程中收集这些信息，虽然不是直接用于逆向，但构建产物的依赖关系是逆向分析的基础。
   - **二进制底层知识:**  依赖关系涉及到链接过程，这是将编译后的目标文件组合成最终可执行文件或库的关键步骤。
   - **逻辑推理:** 假设一个目标 `A` 依赖于目标 `B` 和 `C`，那么 `get_dep_info(A)` 将返回一个字典，其中包含 `B` 和 `C` 的信息，可以通过它们的 ID 访问。
   - **用户操作如何到达这里:** 当 Meson 处理 `build()` 函数中定义的依赖关系时，会调用此函数来解析和记录这些依赖。

2. **`get_custom_target_provided_by_generated_source(self, generated_source: build.CustomTarget) -> 'ImmutableListProtocol[str]'`:**
   - **功能:**  对于一个生成源文件的自定义目标，找出它生成的并且被认为是库文件的输出。
   - **与逆向的关系:**  自定义目标常常用于生成代码，例如使用 `protoc` 生成 C++ 代码。这些生成的代码可能会编译成库。逆向工程师可能需要分析这些生成的库。
   - **二进制底层知识:**  库文件（如 `.so`, `.dll`, `.a`）是包含可重用代码的二进制文件。
   - **逻辑推理:** 如果一个自定义目标 `codegen` 生成了 `libfoo.so`，并且 `self.environment.is_library('libfoo.so')` 返回 True，那么 `get_custom_target_provided_by_generated_source(codegen)` 将返回 `[<build_dir>/<codegen_output_dir>/libfoo.so]`。
   - **用户操作如何到达这里:** 当 Meson 处理定义了生成库文件的自定义目标时，会调用此函数。

3. **`get_custom_target_provided_libraries(self, target: T.Union[build.BuildTarget, build.CustomTarget]) -> 'ImmutableListProtocol[str]'`:**
   - **功能:**  获取一个目标（可以是普通构建目标或自定义目标）通过其生成的源文件提供的库文件列表。
   - **与逆向的关系:** 类似于上一个函数，它帮助追踪由构建过程动态生成的库。
   - **用户操作如何到达这里:**  当 Meson 需要知道一个目标依赖的动态生成的库时，会调用此函数。

4. **`get_custom_target_sources(self, target: build.CustomTarget) -> T.List[str]`:**
   - **功能:** 获取自定义目标的源文件列表。源文件可以是字符串形式的文件名，也可以是其他构建目标（包括其他自定义目标）的输出。
   - **与逆向的关系:**  自定义目标的源代码定义了其行为。即使是生成的源代码，最终也是基于某些输入生成的。这个函数能帮助定位到生成过程的起点。
   - **逻辑推理:**  假设自定义目标 `my_codegen` 的源文件包括字符串 `"input.txt"` 和另一个自定义目标 `schema_gen`。`get_custom_target_sources(my_codegen)` 将返回 `[<build_dir>/input.txt, <build_dir>/<schema_gen_output_dir>/<schema_gen_output>]`。
   - **用户操作如何到达这里:** 当 Meson 需要知道自定义目标的输入，以便确定是否需要重新构建时，会调用此函数。

5. **`get_target_depend_files(self, target: T.Union[build.CustomTarget, build.BuildTarget], absolute_paths: bool = False) -> T.List[str]`:**
   - **功能:**  获取一个目标的显式依赖文件列表。这些文件通常是配置文件或其他不作为源代码编译的依赖。
   - **与逆向的关系:**  这些依赖文件可能包含配置信息、数据文件等，对于理解目标的行为至关重要。例如，一个程序可能依赖于一个配置文件来确定其运行方式。
   - **Linux, Android 内核及框架知识:**  在 Android 开发中，一些构建目标可能依赖于 `.aidl` 文件（用于定义接口）或其他资源文件。
   - **逻辑推理:** 如果一个目标 `app` 声明了依赖文件 `config.ini`，那么 `get_target_depend_files(app)` 将返回 `[<build_dir>/config.ini]` (或绝对路径，取决于 `absolute_paths`)。
   - **用户操作如何到达这里:** 当 Meson 需要追踪依赖文件是否发生变化，从而决定是否需要重新构建目标时，会调用此函数。

6. **`get_custom_target_output_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str`:**
   - **功能:** 获取自定义目标的输出目录。
   - **用户操作如何到达这里:** 当 Meson 需要确定自定义目标输出文件的位置时，会调用此函数。

7. **`get_normpath_target(self, source: str) -> str`:**
   - **功能:**  规范化路径，例如去除多余的斜杠和 `.` 或 `..` 组件。

8. **`get_custom_target_dirs(self, target: build.CustomTarget, compiler: 'Compiler', *, absolute_path: bool = False) -> T.List[str]`:**
   - **功能:** 获取自定义目标生成的头文件所在的目录。
   - **与逆向的关系:**  头文件定义了接口，了解这些头文件可以帮助理解库或模块的功能。
   - **Linux, Android 内核及框架知识:**  在 Android Native 开发中，JNI 头文件会放在特定的生成目录下。
   - **用户操作如何到达这里:** 当 Meson 需要将自定义目标生成的头文件添加到编译器的 include 路径时，会调用此函数。

9. **`get_custom_target_dir_include_args(self, target: build.CustomTarget, compiler: 'Compiler', *, absolute_path: bool = False) -> T.List[str]`:**
   - **功能:**  获取用于指定自定义目标生成的头文件目录的编译器参数（例如 `-I`）。
   - **用户操作如何到达这里:**  在生成构建系统文件时，Meson 会使用此函数来构建编译命令。

10. **`eval_custom_target_command(self, target: build.CustomTarget, absolute_outputs: bool = False) -> T.Tuple[T.List[str], T.List[str], T.List[str]]`:**
    - **功能:**  评估自定义目标的命令。它会将命令中的占位符（如 `@SOURCE_ROOT@`, `@OUTPUT@`）替换为实际的值，并返回输入文件列表、输出文件列表和最终的命令列表。
    - **与逆向的关系:**  自定义目标常常执行代码生成、数据处理等操作。理解这个命令可以揭示构建过程中发生的转换。
    - **Linux, Android 内核及框架知识:**  在 Android 构建中，自定义目标可能执行 `aidl` 编译器、`renderscriptc` 编译器等。
    - **逻辑推理:** 假设自定义目标的命令是 `my_tool @INPUT@ -o @OUTPUT@`，输入是 `input.txt`，输出是 `output.bin`。`eval_custom_target_command(target)` 将返回 `(['<build_dir>/input.txt'], ['<build_dir>/<target_output_dir>/output.bin'], ['my_tool', '<build_dir>/input.txt', '-o', '<build_dir>/<target_output_dir>/output.bin'])`。
    - **用户或编程常见的使用错误:**
        - **错误的占位符:**  如果命令中使用了错误的占位符名称，Meson 将无法正确替换。
        - **缺少依赖:**  自定义目标可能依赖于其他工具或文件，如果在运行命令时找不到这些依赖，会导致构建失败。
        - **输出路径错误:** 如果命令生成的输出文件路径与 Meson 预期的不符，会导致构建系统无法跟踪输出。
    - **用户操作如何到达这里:** 当构建系统需要执行自定义目标时，会调用此函数来准备执行命令。

11. **`get_introspect_command(self) -> str`:**
    - **功能:**  返回用于执行 Meson 内省工具的命令。
    - **与逆向的关系:**  内省工具可以提供关于构建配置和目标的信息，这对于理解项目的结构和依赖关系很有帮助。

12. **`get_run_target_env(self, target: build.RunTarget) -> mesonlib.EnvironmentVariables`:**
    - **功能:**  为运行目标（通常用于测试）设置环境变量。
    - **与逆向的关系:**  在调试或测试过程中，需要设置特定的环境变量来模拟运行环境。

13. **`run_postconf_scripts(self) -> None`:**
    - **功能:**  运行在配置阶段之后执行的脚本。
    - **与逆向的关系:**  这些脚本可以修改构建配置或执行其他自定义操作，了解这些脚本的行为有助于理解最终的构建产物。

14. **`create_install_data(self) -> InstallData`:**
    - **功能:**  创建一个包含安装数据（如要安装的文件、目录、权限等）的对象。这是安装过程的核心数据结构。
    - **用户操作如何到达这里:** 当用户运行 `meson install` 命令时，会触发生成安装数据的过程。

15. **`create_install_data_files(self) -> None`:**
    - **功能:**  将安装数据序列化到文件中。

16. **`guess_install_tag(self, fname: str, outdir: T.Optional[str] = None) -> T.Optional[str]`:**
    - **功能:**  尝试根据文件名和输出目录猜测安装标签（例如 'runtime', 'devel'）。
    - **用户操作如何到达这里:** 当安装数据中缺少某些文件的安装标签时，Meson 会尝试自动推断。

17. **`generate_target_install(self, d: InstallData) -> None`:**
    - **功能:**  将构建目标的安装信息添加到安装数据中。这包括可执行文件、库等。
    - **用户或编程常见的使用错误:**
        - **`install: true` 但未指定安装目录:**  Meson 需要知道文件应该安装到哪里。
        - **安装目录数量与输出文件数量不匹配:**  如果一个目标生成多个输出，需要为每个输出指定是否安装以及安装到哪里。

18. **`generate_custom_install_script(self, d: InstallData) -> None`:**
    - **功能:**  将自定义安装脚本添加到安装数据中。

19. **`generate_header_install(self, d: InstallData) -> None`:**
    - **功能:**  将头文件的安装信息添加到安装数据中。

20. **`generate_man_install(self, d: InstallData) -> None`:**
    - **功能:**  将 man 页面的安装信息添加到安装数据中。

21. **`generate_emptydir_install(self, d: InstallData) -> None`:**
    - **功能:**  将需要创建的空目录的安装信息添加到安装数据中。

22. **`generate_data_install(self, d: InstallData) -> None`:**
    - **功能:**  将数据文件的安装信息添加到安装数据中。

23. **`generate_symlink_install(self, d: InstallData) -> None`:**
    - **功能:**  将符号链接的安装信息添加到安装数据中。

24. **`generate_subdir_install(self, d: InstallData) -> None`:**
    - **功能:**  将需要安装的子目录的安装信息添加到安装数据中。

25. **`get_introspection_data(self, target_id: str, target: build.Target) -> T.List['TargetIntrospectionData']`:**
    - **功能:**  为给定的目标生成用于内省的数据，包括编译器、参数、源文件等。
    - **与逆向的关系:**  这是 Meson 内省功能的基础，可以帮助开发者和逆向工程师了解构建过程的细节。

26. **`get_devenv(self) -> mesonlib.EnvironmentVariables`:**
    - **功能:**  获取用于开发环境的环境变量，例如将构建目录添加到 `PATH` 或 `LD_LIBRARY_PATH`。
    - **与逆向的关系:**  在开发和调试阶段，正确的环境变量设置对于运行构建的二进制文件至关重要。

27. **`compiler_to_generator(...)`:**
    - **功能:**  对于不支持自定义编译器的后端，提供一种将编译器操作转换为生成器的方法。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **配置阶段:** 用户运行 `meson setup builddir` 命令。Meson 读取 `meson.build` 文件并创建内部数据结构来表示构建目标和依赖关系。
2. **生成阶段:** 用户运行 `meson compile -C builddir` 或使用特定后端（如 `ninja`, `xcodebuild`）的命令。
3. **后端处理:** Meson 将其内部表示传递给相应的后端（例如，如果使用 Ninja，则会调用 `NinjaBackend`）。
4. **目标处理:** 后端开始遍历构建目标，并调用 `backends.py` 中的方法来获取每个目标的具体信息，例如源文件、依赖、编译命令等。
5. **自定义目标评估:** 对于自定义目标，`eval_custom_target_command` 会被调用以确定实际要执行的命令。
6. **安装阶段:** 用户运行 `meson install -C builddir`。
7. **安装数据生成:** `create_install_data` 和相关的 `generate_*_install` 函数会被调用，以收集所有需要安装的文件和目录的信息。

**调试线索:**

- 如果构建失败，可以检查 `eval_custom_target_command` 的输出，看生成的命令是否正确。
- 如果安装的文件不正确，可以检查 `generate_target_install` 或其他 `generate_*_install` 函数的逻辑。
- 使用 Meson 的内省功能（`meson introspect`）可以查看构建目标的属性，这会调用 `get_introspection_data`。

**总结:**

这段代码是 Frida 构建系统中至关重要的一部分，它负责将高层次的构建意图转换为低层次的构建指令。它处理了各种构建目标的细节，并为不同后端提供了统一的接口。理解这段代码的功能对于调试构建问题、理解 Frida 的构建过程以及进行与构建系统相关的逆向分析都是非常有帮助的。它涉及到编译、链接、文件系统操作、环境变量等多个方面的知识，是构建系统复杂性的一个体现。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
= arg
            for dep in t.depends:
                assert isinstance(dep, (build.CustomTarget, build.BuildTarget))
                result[dep.get_id()] = dep
        return result

    @lru_cache(maxsize=None)
    def get_custom_target_provided_by_generated_source(self, generated_source: build.CustomTarget) -> 'ImmutableListProtocol[str]':
        libs: T.List[str] = []
        for f in generated_source.get_outputs():
            if self.environment.is_library(f):
                libs.append(os.path.join(self.get_target_dir(generated_source), f))
        return libs

    @lru_cache(maxsize=None)
    def get_custom_target_provided_libraries(self, target: T.Union[build.BuildTarget, build.CustomTarget]) -> 'ImmutableListProtocol[str]':
        libs: T.List[str] = []
        for t in target.get_generated_sources():
            if not isinstance(t, build.CustomTarget):
                continue
            libs.extend(self.get_custom_target_provided_by_generated_source(t))
        return libs

    def get_custom_target_sources(self, target: build.CustomTarget) -> T.List[str]:
        '''
        Custom target sources can be of various object types; strings, File,
        BuildTarget, even other CustomTargets.
        Returns the path to them relative to the build root directory.
        '''
        srcs: T.List[str] = []
        for i in target.get_sources():
            if isinstance(i, str):
                fname = [os.path.join(self.build_to_src, target.get_source_subdir(), i)]
            elif isinstance(i, build.BuildTarget):
                fname = [self.get_target_filename(i)]
            elif isinstance(i, (build.CustomTarget, build.CustomTargetIndex)):
                fname = [os.path.join(self.get_custom_target_output_dir(i), p) for p in i.get_outputs()]
            elif isinstance(i, build.GeneratedList):
                fname = [os.path.join(self.get_target_private_dir(target), p) for p in i.get_outputs()]
            elif isinstance(i, build.ExtractedObjects):
                fname = self.determine_ext_objs(i)
            elif isinstance(i, programs.ExternalProgram):
                assert i.found(), "This shouldn't be possible"
                assert i.path is not None, 'for mypy'
                fname = [i.path]
            else:
                fname = [i.rel_to_builddir(self.build_to_src)]
            if target.absolute_paths:
                fname = [os.path.join(self.environment.get_build_dir(), f) for f in fname]
            srcs += fname
        return srcs

    def get_target_depend_files(self, target: T.Union[build.CustomTarget, build.BuildTarget], absolute_paths: bool = False) -> T.List[str]:
        deps: T.List[str] = []
        for i in target.depend_files:
            if isinstance(i, mesonlib.File):
                if absolute_paths:
                    deps.append(i.absolute_path(self.environment.get_source_dir(),
                                                self.environment.get_build_dir()))
                else:
                    deps.append(i.rel_to_builddir(self.build_to_src))
            else:
                if absolute_paths:
                    deps.append(os.path.join(self.environment.get_source_dir(), target.get_output_subdir(), i))
                else:
                    deps.append(os.path.join(self.build_to_src, target.get_output_subdir(), i))
        return deps

    def get_custom_target_output_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        # The XCode backend is special. A target foo/bar does
        # not go to ${BUILDDIR}/foo/bar but instead to
        # ${BUILDDIR}/${BUILDTYPE}/foo/bar.
        # Currently we set the include dir to be the former,
        # and not the latter. Thus we need this extra customisation
        # point. If in the future we make include dirs et al match
        # ${BUILDDIR}/${BUILDTYPE} instead, this becomes unnecessary.
        return self.get_target_dir(target)

    @lru_cache(maxsize=None)
    def get_normpath_target(self, source: str) -> str:
        return os.path.normpath(source)

    def get_custom_target_dirs(self, target: build.CustomTarget, compiler: 'Compiler', *,
                               absolute_path: bool = False) -> T.List[str]:
        custom_target_include_dirs: T.List[str] = []
        for i in target.get_generated_sources():
            # Generator output goes into the target private dir which is
            # already in the include paths list. Only custom targets have their
            # own target build dir.
            if not isinstance(i, (build.CustomTarget, build.CustomTargetIndex)):
                continue
            idir = self.get_normpath_target(self.get_custom_target_output_dir(i))
            if not idir:
                idir = '.'
            if absolute_path:
                idir = os.path.join(self.environment.get_build_dir(), idir)
            if idir not in custom_target_include_dirs:
                custom_target_include_dirs.append(idir)
        return custom_target_include_dirs

    def get_custom_target_dir_include_args(
            self, target: build.CustomTarget, compiler: 'Compiler', *,
            absolute_path: bool = False) -> T.List[str]:
        incs: T.List[str] = []
        for i in self.get_custom_target_dirs(target, compiler, absolute_path=absolute_path):
            incs += compiler.get_include_args(i, False)
        return incs

    def eval_custom_target_command(
            self, target: build.CustomTarget, absolute_outputs: bool = False) -> \
            T.Tuple[T.List[str], T.List[str], T.List[str]]:
        # We want the outputs to be absolute only when using the VS backend
        # XXX: Maybe allow the vs backend to use relative paths too?
        source_root = self.build_to_src
        build_root = '.'
        outdir = self.get_custom_target_output_dir(target)
        if absolute_outputs:
            source_root = self.environment.get_source_dir()
            build_root = self.environment.get_build_dir()
            outdir = os.path.join(self.environment.get_build_dir(), outdir)
        outputs = [os.path.join(outdir, i) for i in target.get_outputs()]
        inputs = self.get_custom_target_sources(target)
        # Evaluate the command list
        cmd: T.List[str] = []
        for i in target.command:
            if isinstance(i, build.BuildTarget):
                cmd += self.build_target_to_cmd_array(i)
                continue
            elif isinstance(i, build.CustomTarget):
                # GIR scanner will attempt to execute this binary but
                # it assumes that it is in path, so always give it a full path.
                tmp = i.get_outputs()[0]
                i = os.path.join(self.get_custom_target_output_dir(i), tmp)
            elif isinstance(i, mesonlib.File):
                i = i.rel_to_builddir(self.build_to_src)
                if target.absolute_paths or absolute_outputs:
                    i = os.path.join(self.environment.get_build_dir(), i)
            # FIXME: str types are blindly added ignoring 'target.absolute_paths'
            # because we can't know if they refer to a file or just a string
            elif isinstance(i, str):
                if '@SOURCE_ROOT@' in i:
                    i = i.replace('@SOURCE_ROOT@', source_root)
                if '@BUILD_ROOT@' in i:
                    i = i.replace('@BUILD_ROOT@', build_root)
                if '@CURRENT_SOURCE_DIR@' in i:
                    i = i.replace('@CURRENT_SOURCE_DIR@', os.path.join(source_root, target.get_source_subdir()))
                if '@DEPFILE@' in i:
                    if target.depfile is None:
                        msg = f'Custom target {target.name!r} has @DEPFILE@ but no depfile ' \
                              'keyword argument.'
                        raise MesonException(msg)
                    dfilename = os.path.join(outdir, target.depfile)
                    i = i.replace('@DEPFILE@', dfilename)
                if '@PRIVATE_DIR@' in i:
                    if target.absolute_paths:
                        pdir = self.get_target_private_dir_abs(target)
                    else:
                        pdir = self.get_target_private_dir(target)
                    i = i.replace('@PRIVATE_DIR@', pdir)
            else:
                raise RuntimeError(f'Argument {i} is of unknown type {type(i)}')
            cmd.append(i)
        # Substitute the rest of the template strings
        values = mesonlib.get_filenames_templates_dict(inputs, outputs)
        cmd = mesonlib.substitute_values(cmd, values)
        # This should not be necessary but removing it breaks
        # building GStreamer on Windows. The underlying issue
        # is problems with quoting backslashes on Windows
        # which is the seventh circle of hell. The downside is
        # that this breaks custom targets whose command lines
        # have backslashes. If you try to fix this be sure to
        # check that it does not break GST.
        #
        # The bug causes file paths such as c:\foo to get escaped
        # into c:\\foo.
        #
        # Unfortunately we have not been able to come up with an
        # isolated test case for this so unless you manage to come up
        # with one, the only way is to test the building with Gst's
        # setup. Note this in your MR or ping us and we will get it
        # fixed.
        #
        # https://github.com/mesonbuild/meson/pull/737
        cmd = [i.replace('\\', '/') for i in cmd]
        return inputs, outputs, cmd

    def get_introspect_command(self) -> str:
        return ' '.join(shlex.quote(x) for x in self.environment.get_build_command() + ['introspect'])

    def get_run_target_env(self, target: build.RunTarget) -> mesonlib.EnvironmentVariables:
        env = target.env if target.env else mesonlib.EnvironmentVariables()
        if target.default_env:
            env.set('MESON_SOURCE_ROOT', [self.environment.get_source_dir()])
            env.set('MESON_BUILD_ROOT', [self.environment.get_build_dir()])
            env.set('MESON_SUBDIR', [target.get_source_subdir()])
            env.set('MESONINTROSPECT', [self.get_introspect_command()])
        return env

    def run_postconf_scripts(self) -> None:
        from ..scripts.meson_exe import run_exe
        env = {'MESON_SOURCE_ROOT': self.environment.get_source_dir(),
               'MESON_BUILD_ROOT': self.environment.get_build_dir(),
               'MESONINTROSPECT': self.get_introspect_command(),
               }

        for s in self.build.postconf_scripts:
            name = ' '.join(s.cmd_args)
            mlog.log(f'Running postconf script {name!r}')
            rc = run_exe(s, env)
            if rc != 0:
                raise MesonException(f'Postconf script \'{name}\' failed with exit code {rc}.')

    def create_install_data(self) -> InstallData:
        strip_bin = self.environment.lookup_binary_entry(MachineChoice.HOST, 'strip')
        if strip_bin is None:
            if self.environment.is_cross_build():
                mlog.warning('Cross file does not specify strip binary, result will not be stripped.')
            else:
                # TODO go through all candidates, like others
                strip_bin = [detect.defaults['strip'][0]]

        umask = self.environment.coredata.get_option(OptionKey('install_umask'))
        assert isinstance(umask, (str, int)), 'for mypy'

        d = InstallData(self.environment.get_source_dir(),
                        self.environment.get_build_dir(),
                        self.environment.get_prefix(),
                        self.environment.get_libdir(),
                        strip_bin,
                        umask,
                        self.environment.get_build_command() + ['introspect'],
                        self.environment.coredata.version)
        self.generate_depmf_install(d)
        self.generate_target_install(d)
        self.generate_header_install(d)
        self.generate_man_install(d)
        self.generate_emptydir_install(d)
        self.generate_data_install(d)
        self.generate_symlink_install(d)
        self.generate_custom_install_script(d)
        self.generate_subdir_install(d)
        return d

    def create_install_data_files(self) -> None:
        install_data_file = os.path.join(self.environment.get_scratch_dir(), 'install.dat')
        with open(install_data_file, 'wb') as ofile:
            pickle.dump(self.create_install_data(), ofile)

    def guess_install_tag(self, fname: str, outdir: T.Optional[str] = None) -> T.Optional[str]:
        prefix = self.environment.get_prefix()
        bindir = Path(prefix, self.environment.get_bindir())
        libdir = Path(prefix, self.environment.get_libdir())
        incdir = Path(prefix, self.environment.get_includedir())
        _ldir = self.environment.coredata.get_option(mesonlib.OptionKey('localedir'))
        assert isinstance(_ldir, str), 'for mypy'
        localedir = Path(prefix, _ldir)
        dest_path = Path(prefix, outdir, Path(fname).name) if outdir else Path(prefix, fname)
        if bindir in dest_path.parents:
            return 'runtime'
        elif libdir in dest_path.parents:
            if dest_path.suffix in {'.a', '.pc'}:
                return 'devel'
            elif dest_path.suffix in {'.so', '.dll'}:
                return 'runtime'
        elif incdir in dest_path.parents:
            return 'devel'
        elif localedir in dest_path.parents:
            return 'i18n'
        elif 'installed-tests' in dest_path.parts:
            return 'tests'
        elif 'systemtap' in dest_path.parts:
            return 'systemtap'
        mlog.debug('Failed to guess install tag for', dest_path)
        return None

    def generate_target_install(self, d: InstallData) -> None:
        for t in self.build.get_targets().values():
            if not t.should_install():
                continue
            outdirs, install_dir_names, custom_install_dir = t.get_install_dir()
            # Sanity-check the outputs and install_dirs
            num_outdirs, num_out = len(outdirs), len(t.get_outputs())
            if num_outdirs not in {1, num_out}:
                m = 'Target {!r} has {} outputs: {!r}, but only {} "install_dir"s were found.\n' \
                    "Pass 'false' for outputs that should not be installed and 'true' for\n" \
                    'using the default installation directory for an output.'
                raise MesonException(m.format(t.name, num_out, t.get_outputs(), num_outdirs))
            assert len(t.install_tag) == num_out
            install_mode = t.get_custom_install_mode()
            # because mypy gets confused type narrowing in lists
            first_outdir = outdirs[0]
            first_outdir_name = install_dir_names[0]

            # Install the target output(s)
            if isinstance(t, build.BuildTarget):
                # In general, stripping static archives is tricky and full of pitfalls.
                # Wholesale stripping of static archives with a command such as
                #
                #   strip libfoo.a
                #
                # is broken, as GNU's strip will remove *every* symbol in a static
                # archive. One solution to this nonintuitive behaviour would be
                # to only strip local/debug symbols. Unfortunately, strip arguments
                # are not specified by POSIX and therefore not portable. GNU's `-g`
                # option (i.e. remove debug symbols) is equivalent to Apple's `-S`.
                #
                # TODO: Create GNUStrip/AppleStrip/etc. hierarchy for more
                #       fine-grained stripping of static archives.
                can_strip = not isinstance(t, build.StaticLibrary)
                should_strip = can_strip and t.get_option(OptionKey('strip'))
                assert isinstance(should_strip, bool), 'for mypy'
                # Install primary build output (library/executable/jar, etc)
                # Done separately because of strip/aliases/rpath
                if first_outdir is not False:
                    tag = t.install_tag[0] or ('devel' if isinstance(t, build.StaticLibrary) else 'runtime')
                    mappings = t.get_link_deps_mapping(d.prefix)
                    i = TargetInstallData(self.get_target_filename(t), first_outdir,
                                          first_outdir_name,
                                          should_strip, mappings, t.rpath_dirs_to_remove,
                                          t.install_rpath, install_mode, t.subproject,
                                          tag=tag, can_strip=can_strip)
                    d.targets.append(i)

                    for alias, to, tag in t.get_aliases():
                        alias = os.path.join(first_outdir, alias)
                        s = InstallSymlinkData(to, alias, first_outdir, t.subproject, tag, allow_missing=True)
                        d.symlinks.append(s)

                    if isinstance(t, (build.SharedLibrary, build.SharedModule, build.Executable)):
                        # On toolchains/platforms that use an import library for
                        # linking (separate from the shared library with all the
                        # code), we need to install that too (dll.a/.lib).
                        if t.get_import_filename():
                            if custom_install_dir:
                                # If the DLL is installed into a custom directory,
                                # install the import library into the same place so
                                # it doesn't go into a surprising place
                                implib_install_dir = first_outdir
                            else:
                                implib_install_dir = self.environment.get_import_lib_dir()
                            # Install the import library; may not exist for shared modules
                            i = TargetInstallData(self.get_target_filename_for_linking(t),
                                                  implib_install_dir, first_outdir_name,
                                                  False, {}, set(), '', install_mode,
                                                  t.subproject, optional=isinstance(t, build.SharedModule),
                                                  tag='devel')
                            d.targets.append(i)

                        if not should_strip and t.get_debug_filename():
                            debug_file = os.path.join(self.get_target_dir(t), t.get_debug_filename())
                            i = TargetInstallData(debug_file, first_outdir,
                                                  first_outdir_name,
                                                  False, {}, set(), '',
                                                  install_mode, t.subproject,
                                                  optional=True, tag='devel')
                            d.targets.append(i)
                # Install secondary outputs. Only used for Vala right now.
                if num_outdirs > 1:
                    for output, outdir, outdir_name, tag in zip(t.get_outputs()[1:], outdirs[1:], install_dir_names[1:], t.install_tag[1:]):
                        # User requested that we not install this output
                        if outdir is False:
                            continue
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdir, outdir_name, False, {}, set(), None,
                                              install_mode, t.subproject,
                                              tag=tag)
                        d.targets.append(i)
            elif isinstance(t, build.CustomTarget):
                # If only one install_dir is specified, assume that all
                # outputs will be installed into it. This is for
                # backwards-compatibility and because it makes sense to
                # avoid repetition since this is a common use-case.
                #
                # To selectively install only some outputs, pass `false` as
                # the install_dir for the corresponding output by index
                #
                # XXX: this wouldn't be needed if we just always matches outdirs
                # to the length of outputs…
                if num_outdirs == 1 and num_out > 1:
                    if first_outdir is not False:
                        for output, tag in zip(t.get_outputs(), t.install_tag):
                            tag = tag or self.guess_install_tag(output, first_outdir)
                            f = os.path.join(self.get_target_dir(t), output)
                            i = TargetInstallData(f, first_outdir, first_outdir_name,
                                                  False, {}, set(), None, install_mode,
                                                  t.subproject, optional=not t.build_by_default,
                                                  tag=tag)
                            d.targets.append(i)
                else:
                    for output, outdir, outdir_name, tag in zip(t.get_outputs(), outdirs, install_dir_names, t.install_tag):
                        # User requested that we not install this output
                        if outdir is False:
                            continue
                        tag = tag or self.guess_install_tag(output, outdir)
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdir, outdir_name,
                                              False, {}, set(), None, install_mode,
                                              t.subproject, optional=not t.build_by_default,
                                              tag=tag)
                        d.targets.append(i)

    def generate_custom_install_script(self, d: InstallData) -> None:
        d.install_scripts = self.build.install_scripts
        for i in d.install_scripts:
            if not i.tag:
                mlog.debug('Failed to guess install tag for install script:', ' '.join(i.cmd_args))

    def generate_header_install(self, d: InstallData) -> None:
        incroot = self.environment.get_includedir()
        headers = self.build.get_headers()

        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for h in headers:
            outdir = outdir_name = h.get_custom_install_dir()
            if outdir is None:
                subdir = h.get_install_subdir()
                if subdir is None:
                    outdir = incroot
                    outdir_name = '{includedir}'
                else:
                    outdir = os.path.join(incroot, subdir)
                    outdir_name = os.path.join('{includedir}', subdir)

            for f in h.get_sources():
                abspath = f.absolute_path(srcdir, builddir)
                i = InstallDataBase(abspath, outdir, outdir_name, h.get_custom_install_mode(), h.subproject, tag='devel', follow_symlinks=h.follow_symlinks)
                d.headers.append(i)

    def generate_man_install(self, d: InstallData) -> None:
        manroot = self.environment.get_mandir()
        man = self.build.get_man()
        for m in man:
            for f in m.get_sources():
                num = f.split('.')[-1]
                subdir = m.get_custom_install_dir()
                if subdir is None:
                    if m.locale:
                        subdir = os.path.join('{mandir}', m.locale, 'man' + num)
                    else:
                        subdir = os.path.join('{mandir}', 'man' + num)
                fname = f.fname
                if m.locale: # strip locale from file name
                    fname = fname.replace(f'.{m.locale}', '')
                srcabs = f.absolute_path(self.environment.get_source_dir(), self.environment.get_build_dir())
                dstname = os.path.join(subdir, os.path.basename(fname))
                dstabs = dstname.replace('{mandir}', manroot)
                i = InstallDataBase(srcabs, dstabs, dstname, m.get_custom_install_mode(), m.subproject, tag='man')
                d.man.append(i)

    def generate_emptydir_install(self, d: InstallData) -> None:
        emptydir: T.List[build.EmptyDir] = self.build.get_emptydir()
        for e in emptydir:
            tag = e.install_tag or self.guess_install_tag(e.path)
            i = InstallEmptyDir(e.path, e.install_mode, e.subproject, tag)
            d.emptydir.append(i)

    def generate_data_install(self, d: InstallData) -> None:
        data = self.build.get_data()
        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for de in data:
            assert isinstance(de, build.Data)
            subdir = de.install_dir
            subdir_name = de.install_dir_name
            for src_file, dst_name in zip(de.sources, de.rename):
                assert isinstance(src_file, mesonlib.File)
                dst_abs = os.path.join(subdir, dst_name)
                dstdir_name = os.path.join(subdir_name, dst_name)
                tag = de.install_tag or self.guess_install_tag(dst_abs)
                i = InstallDataBase(src_file.absolute_path(srcdir, builddir), dst_abs, dstdir_name,
                                    de.install_mode, de.subproject, tag=tag, data_type=de.data_type,
                                    follow_symlinks=de.follow_symlinks)
                d.data.append(i)

    def generate_symlink_install(self, d: InstallData) -> None:
        links: T.List[build.SymlinkData] = self.build.get_symlinks()
        for l in links:
            assert isinstance(l, build.SymlinkData)
            install_dir = l.install_dir
            name_abs = os.path.join(install_dir, l.name)
            tag = l.install_tag or self.guess_install_tag(name_abs)
            s = InstallSymlinkData(l.target, name_abs, install_dir, l.subproject, tag)
            d.symlinks.append(s)

    def generate_subdir_install(self, d: InstallData) -> None:
        for sd in self.build.get_install_subdirs():
            if sd.from_source_dir:
                from_dir = self.environment.get_source_dir()
            else:
                from_dir = self.environment.get_build_dir()
            src_dir = os.path.join(from_dir,
                                   sd.source_subdir,
                                   sd.installable_subdir).rstrip('/')
            dst_dir = os.path.join(self.environment.get_prefix(),
                                   sd.install_dir)
            dst_name = os.path.join('{prefix}', sd.install_dir)
            if sd.install_dir != sd.install_dir_name:
                dst_name = sd.install_dir_name
            if not sd.strip_directory:
                dst_dir = os.path.join(dst_dir, os.path.basename(src_dir))
                dst_name = os.path.join(dst_name, os.path.basename(src_dir))
            tag = sd.install_tag or self.guess_install_tag(os.path.join(sd.install_dir, 'dummy'))
            i = SubdirInstallData(src_dir, dst_dir, dst_name, sd.install_mode, sd.exclude, sd.subproject, tag,
                                  follow_symlinks=sd.follow_symlinks)
            d.install_subdirs.append(i)

    def get_introspection_data(self, target_id: str, target: build.Target) -> T.List['TargetIntrospectionData']:
        '''
        Returns a list of source dicts with the following format for a given target:
        [
            {
                "language": "<LANG>",
                "compiler": ["result", "of", "comp.get_exelist()"],
                "parameters": ["list", "of", "compiler", "parameters],
                "sources": ["list", "of", "all", "<LANG>", "source", "files"],
                "generated_sources": ["list", "of", "generated", "source", "files"]
            }
        ]

        This is a limited fallback / reference implementation. The backend should override this method.
        '''
        if isinstance(target, (build.CustomTarget, build.BuildTarget)):
            source_list_raw = target.sources
            source_list = []
            for j in source_list_raw:
                if isinstance(j, mesonlib.File):
                    source_list += [j.absolute_path(self.source_dir, self.build_dir)]
                elif isinstance(j, str):
                    source_list += [os.path.join(self.source_dir, j)]
                elif isinstance(j, (build.CustomTarget, build.BuildTarget)):
                    source_list += [os.path.join(self.build_dir, j.get_output_subdir(), o) for o in j.get_outputs()]
            source_list = [os.path.normpath(s) for s in source_list]

            compiler: T.List[str] = []
            if isinstance(target, build.CustomTarget):
                tmp_compiler = target.command
                for j in tmp_compiler:
                    if isinstance(j, mesonlib.File):
                        compiler += [j.absolute_path(self.source_dir, self.build_dir)]
                    elif isinstance(j, str):
                        compiler += [j]
                    elif isinstance(j, (build.BuildTarget, build.CustomTarget)):
                        compiler += j.get_outputs()
                    else:
                        raise RuntimeError(f'Type "{type(j).__name__}" is not supported in get_introspection_data. This is a bug')

            return [{
                'language': 'unknown',
                'compiler': compiler,
                'parameters': [],
                'sources': source_list,
                'generated_sources': []
            }]

        return []

    def get_devenv(self) -> mesonlib.EnvironmentVariables:
        env = mesonlib.EnvironmentVariables()
        extra_paths = set()
        library_paths = set()
        build_machine = self.environment.machines[MachineChoice.BUILD]
        host_machine = self.environment.machines[MachineChoice.HOST]
        need_wine = not build_machine.is_windows() and host_machine.is_windows()
        for t in self.build.get_targets().values():
            in_default_dir = t.should_install() and not t.get_install_dir()[2]
            if t.for_machine != MachineChoice.HOST or not in_default_dir:
                continue
            tdir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(t))
            if isinstance(t, build.Executable):
                # Add binaries that are going to be installed in bindir into PATH
                # so they get used by default instead of searching on system when
                # in developer environment.
                extra_paths.add(tdir)
                if host_machine.is_windows() or host_machine.is_cygwin():
                    # On windows we cannot rely on rpath to run executables from build
                    # directory. We have to add in PATH the location of every DLL needed.
                    library_paths.update(self.determine_windows_extra_paths(t, []))
            elif isinstance(t, build.SharedLibrary):
                # Add libraries that are going to be installed in libdir into
                # LD_LIBRARY_PATH. This allows running system applications using
                # that library.
                library_paths.add(tdir)
        if need_wine:
            # Executable paths should be in both PATH and WINEPATH.
            # - Having them in PATH makes bash completion find it,
            #   and make running "foo.exe" find it when wine-binfmt is installed.
            # - Having them in WINEPATH makes "wine foo.exe" find it.
            library_paths.update(extra_paths)
        if library_paths:
            if need_wine:
                env.prepend('WINEPATH', list(library_paths), separator=';')
            elif host_machine.is_windows() or host_machine.is_cygwin():
                extra_paths.update(library_paths)
            elif host_machine.is_darwin():
                env.prepend('DYLD_LIBRARY_PATH', list(library_paths))
            else:
                env.prepend('LD_LIBRARY_PATH', list(library_paths))
        if extra_paths:
            env.prepend('PATH', list(extra_paths))
        return env

    def compiler_to_generator(self, target: build.BuildTarget,
                              compiler: 'Compiler',
                              sources: _ALL_SOURCES_TYPE,
                              output_templ: str,
                              depends: T.Optional[T.List[T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]]] = None,
                              ) -> build.GeneratedList:
        '''
        Some backends don't support custom compilers. This is a convenience
        method to conve
```