Response:
The user wants to understand the functionality of the provided Python code snippet from `frida/releng/meson/mesonbuild/backend/backends.py`. I need to break down the code, identify its purpose, and relate it to concepts like reverse engineering, binary internals, Linux/Android specifics, logical reasoning, potential errors, and the user's path to this code.

**Plan:**

1. **High-level overview:** Identify the main goal of this file within the Frida project. It seems related to the build system (Meson) and backend processing.
2. **Function-level analysis:** Go through each function and describe its operation.
3. **Reverse engineering relevance:**  Determine if and how any of these functions aid or are related to the process of reverse engineering software. Frida itself is a reverse engineering tool, so the build process must facilitate this.
4. **Binary/Kernel/Framework aspects:** Look for functions that deal with low-level details like compiling, linking, and installing software, which touches upon binary formats and potentially OS-specific functionalities.
5. **Logical reasoning:** Identify functions that perform decisions or transformations based on input. Provide hypothetical input and output examples.
6. **User errors:**  Think about common mistakes a user or developer might make that would cause these functions to be invoked or fail.
7. **User journey:**  Trace back how a user's actions might lead to this specific code being executed. This is likely part of the build process.
8. **Summarization:** Condense the identified functionalities into a concise summary.
This部分代码是 `frida/releng/meson/mesonbuild/backend/backends.py` 文件的一部分，主要负责处理 Meson 构建系统中自定义目标 (Custom Target) 和构建目标 (Build Target) 的相关信息，以便在不同的构建后端（如 Ninja, Xcode 等）生成相应的构建指令。

以下是其功能的详细列表，并结合您提出的要求进行说明：

**主要功能：**

1. **获取依赖关系： `get_target_dependencies(target)`**
   - **功能：**  递归地获取给定目标所依赖的所有其他构建目标和自定义目标。它通过遍历目标的 `depends` 属性来实现。
   - **逆向关系：** 在逆向工程中，了解软件组件之间的依赖关系至关重要。例如，在分析一个二进制文件时，需要知道它链接了哪些库。这个函数在构建过程中提取了这些依赖信息，可以帮助理解最终生成的可执行文件或库的组成。
   - **逻辑推理：**
     - **假设输入：** 一个 `build.BuildTarget` 对象 `targetA`，它依赖于 `build.BuildTarget` 对象 `targetB` 和 `build.CustomTarget` 对象 `targetC`。`targetB` 又依赖于 `build.BuildTarget` 对象 `targetD`。
     - **预期输出：** 一个字典，键是依赖目标的 ID，值是依赖目标的实例，包含 `targetB`, `targetC`, `targetD`。
   - **二进制底层：**  依赖关系最终会影响链接过程，确定哪些库需要被链接到最终的二进制文件中。
   - **用户操作如何到达：**  用户在 `meson.build` 文件中定义了一个目标，并使用 `depends:` 参数指定了它所依赖的其他目标。Meson 解析 `meson.build` 文件后，会创建相应的目标对象，并在构建过程中调用此函数来分析依赖关系。

2. **获取由生成源提供的自定义目标： `get_custom_target_provided_by_generated_source(generated_source)`**
   - **功能：**  确定由一个给定的生成源（通常是一个自定义目标）提供的库文件路径。它检查生成源的输出文件是否是库文件。
   - **逆向关系：**  在逆向过程中，可能需要分析由构建过程生成的中间库文件。这个函数可以帮助定位这些库文件。
   - **编程常见错误：** 如果用户定义的自定义目标生成了库文件，但构建系统未能正确识别，可能是因为库文件的命名约定不符合预期，或者 `environment.is_library(f)` 的判断逻辑有问题。
   - **用户操作如何到达：** 用户在 `meson.build` 文件中定义了一个自定义目标，该目标生成一个库文件，并且其他目标依赖于这个库。

3. **获取自定义目标提供的库： `get_custom_target_provided_libraries(target)`**
   - **功能：** 获取给定目标（可以是构建目标或自定义目标）的所有生成源提供的库文件路径。它遍历目标的生成源，并调用 `get_custom_target_provided_by_generated_source` 获取库文件。
   - **逆向关系：**  类似于上一个函数，帮助定位构建过程中生成的库文件。
   - **用户操作如何到达：** 用户定义了一个目标，该目标依赖于其他自定义目标生成的库。

4. **获取自定义目标的源文件： `get_custom_target_sources(target)`**
   - **功能：** 获取自定义目标的所有源文件路径。源文件可以是字符串、`File` 对象、构建目标或其他的自定义目标。它会将不同类型的源文件转换为相对于构建根目录的路径。
   - **逆向关系：**  在逆向分析中，了解目标是如何构建的，它的源文件是什么非常重要。
   - **二进制底层：**  源文件是编译器的输入，直接影响最终生成的二进制代码。
   - **逻辑推理：**
     - **假设输入：** 一个 `build.CustomTarget` 对象，其源文件包括一个字符串文件名 "input.txt"，一个 `build.BuildTarget` 对象 `libA`，和一个 `build.CustomTarget` 对象 `generator`。
     - **预期输出：**  一个包含路径的列表，例如 `['frida/releng/meson/mesonbuild/input.txt', 'path/to/libA', 'path/to/generator_output1', 'path/to/generator_output2']`。
   - **用户操作如何到达：** 用户在 `meson.build` 文件中定义了一个自定义目标，并使用 `input:` 参数指定了其源文件。源文件可以是多种类型。
   - **编程常见错误：** 如果用户提供的源文件路径不正确，或者依赖的构建目标或自定义目标没有正确生成输出，会导致构建失败。

5. **获取目标的依赖文件： `get_target_depend_files(target, absolute_paths=False)`**
   - **功能：** 获取目标的所有依赖文件路径。依赖文件通常是通过 `configure_file` 或类似的机制生成的配置文件。可以选择返回绝对路径或相对于构建目录的路径。
   - **逆向关系：** 了解目标依赖的配置文件可以帮助理解其运行时行为。
   - **用户操作如何到达：** 用户在 `meson.build` 文件中定义了一个目标，并使用 `depend_files:` 参数指定了它所依赖的文件。

6. **获取自定义目标的输出目录： `get_custom_target_output_dir(target)`**
   - **功能：** 获取自定义目标的输出目录路径。这个函数考虑了特定后端（如 Xcode）的特殊性。
   - **用户操作如何到达：**  当需要获取自定义目标的输出位置时，构建系统会调用此函数。

7. **规范化路径： `get_normpath_target(source)`**
   - **功能：** 使用 `os.path.normpath` 规范化给定的路径字符串。
   - **编程常见错误：** 路径处理不当可能导致跨平台兼容性问题。使用规范化路径可以提高代码的健壮性。

8. **获取自定义目标的包含目录： `get_custom_target_dirs(target, compiler, *, absolute_path=False)`**
   - **功能：** 获取自定义目标生成的头文件所在的目录。这对于需要包含这些头文件的其他目标非常重要。
   - **用户操作如何到达：**  当其他目标需要包含由自定义目标生成的头文件时，构建系统会调用此函数来获取包含目录。

9. **获取自定义目标的包含目录参数： `get_custom_target_dir_include_args(target, compiler, *, absolute_path=False)`**
   - **功能：** 获取将自定义目标的包含目录添加到编译器命令行所需的参数（例如 `-I/path/to/include`）。
   - **二进制底层：**  包含目录参数告诉编译器在哪里查找头文件。
   - **用户操作如何到达：**  在编译依赖于自定义目标生成头文件的目标时，构建系统会调用此函数生成必要的编译器参数。

10. **评估自定义目标的命令： `eval_custom_target_command(target, absolute_outputs=False)`**
    - **功能：** 评估自定义目标的执行命令，包括替换占位符（如 `@SOURCE_ROOT@`, `@OUTPUT@` 等），并返回输入文件列表、输出文件列表和最终的命令列表。
    - **逆向关系：**  了解自定义目标的执行命令可以帮助理解构建过程中执行了哪些操作，例如代码生成、资源处理等。
    - **二进制底层：**  自定义目标可以执行任意 shell 命令，包括编译、链接等底层操作。
    - **逻辑推理：**
        - **假设输入：** 一个 `build.CustomTarget` 对象，其命令为 `['python', 'generator.py', '@INPUT@', '@OUTPUT@']`，输入文件为 `input.txt`，输出文件为 `output.c`。
        - **预期输出：**  `(['frida/releng/meson/mesonbuild/input.txt'], ['path/to/output.c'], ['python', 'generator.py', 'frida/releng/meson/mesonbuild/input.txt', 'path/to/output.c'])`
    - **用户操作如何到达：** 用户在 `meson.build` 文件中定义了一个自定义目标，并使用 `command:` 参数指定了其执行命令。
    - **编程常见错误：** 命令中的占位符使用错误、依赖的文件路径不正确、执行的程序不存在等都会导致自定义目标执行失败。

11. **获取内省命令： `get_introspect_command()`**
    - **功能：** 返回用于内省 Meson 构建系统的命令。
    - **用户操作如何到达：**  当用户或工具需要获取 Meson 构建系统的元数据时，会使用内省命令。

12. **获取运行目标的运行环境： `get_run_target_env(target)`**
    - **功能：** 获取运行特定目标所需的运行环境变量。这包括用户自定义的环境变量以及 Meson 提供的默认环境变量。
    - **用户操作如何到达：**  当使用 `meson run` 命令运行一个目标时，构建系统会调用此函数来设置运行环境。

13. **运行配置后脚本： `run_postconf_scripts()`**
    - **功能：** 执行在配置阶段之后运行的脚本。
    - **用户操作如何到达：** 用户在 `meson.build` 文件中定义了 `postconf_script`。在配置阶段完成后，构建系统会调用此函数来执行这些脚本。
    - **编程常见错误：** 脚本执行失败会导致构建过程出错。

14. **创建安装数据： `create_install_data()`**
    - **功能：** 创建一个包含所有需要安装的文件和目录信息的 `InstallData` 对象。这包括目标文件、头文件、man 手册、数据文件等。
    - **二进制底层：**  涉及到最终生成的可执行文件、库文件等二进制文件的安装位置和权限。
    - **Linux, Android 内核及框架知识：**  安装过程涉及到文件系统的操作，需要了解目标平台的目录结构和安装约定（如 `/usr/bin`, `/usr/lib` 等）。在 Android 上，可能涉及到 APK 的打包和安装。
    - **用户操作如何到达：**  当用户执行 `meson install` 命令时，构建系统会调用此函数来收集所有需要安装的信息。

15. **创建安装数据文件： `create_install_data_files()`**
    - **功能：** 将 `create_install_data()` 创建的 `InstallData` 对象序列化到磁盘上的一个文件中。
    - **用户操作如何到达：**  在执行安装过程之前，构建系统可能会先将安装数据保存到文件，以便后续使用。

16. **猜测安装标签： `guess_install_tag(fname, outdir=None)`**
    - **功能：**  尝试根据文件路径猜测其安装标签（例如 `runtime`, `devel`, `i18n`）。这有助于对安装的文件进行分类。
    - **用户操作如何到达：**  如果用户在定义安装目标时没有明确指定安装标签，构建系统会尝试自动猜测。

17. **生成目标安装信息： `generate_target_install(d)`**
    - **功能：** 将构建目标的安装信息添加到 `InstallData` 对象中。这包括目标文件的安装路径、权限、是否需要 strip 等。
    - **二进制底层：**  涉及到可执行文件、共享库、静态库等不同类型二进制文件的安装处理。
    - **Linux, Android 内核及框架知识：**  共享库的安装可能涉及到 rpath 的设置，这与动态链接器有关。在 Android 上，可能涉及到 so 库的安装位置。
    - **用户操作如何到达：**  当用户执行 `meson install` 命令时，构建系统会调用此函数来处理构建目标的安装。

18. **生成自定义安装脚本信息： `generate_custom_install_script(d)`**
    - **功能：** 将用户定义的自定义安装脚本添加到 `InstallData` 对象中。
    - **用户操作如何到达：** 用户在 `meson.build` 文件中定义了 `install_script`。在安装阶段，构建系统会执行这些脚本。

19. **生成头文件安装信息： `generate_header_install(d)`**
    - **功能：** 将头文件的安装信息添加到 `InstallData` 对象中。这包括头文件的安装路径和权限。
    - **用户操作如何到达：** 用户在 `meson.build` 文件中使用 `install_headers` 定义需要安装的头文件。

20. **生成 man 手册安装信息： `generate_man_install(d)`**
    - **功能：** 将 man 手册的安装信息添加到 `InstallData` 对象中。
    - **用户操作如何到达：** 用户在 `meson.build` 文件中使用 `install_man` 定义需要安装的 man 手册。

21. **生成空目录安装信息： `generate_emptydir_install(d)`**
    - **功能：** 将需要创建的空目录的安装信息添加到 `InstallData` 对象中。
    - **用户操作如何到达：** 用户在 `meson.build` 文件中使用 `install_emptydir` 定义需要创建的空目录。

22. **生成数据文件安装信息： `generate_data_install(d)`**
    - **功能：** 将数据文件的安装信息添加到 `InstallData` 对象中。
    - **用户操作如何到达：** 用户在 `meson.build` 文件中使用 `install_data` 定义需要安装的数据文件。

23. **生成符号链接安装信息： `generate_symlink_install(d)`**
    - **功能：** 将符号链接的安装信息添加到 `InstallData` 对象中。
    - **用户操作如何到达：** 用户在 `meson.build` 文件中使用 `install_symlink` 定义需要创建的符号链接。

24. **生成子目录安装信息： `generate_subdir_install(d)`**
    - **功能：** 将需要安装的子目录的安装信息添加到 `InstallData` 对象中。
    - **用户操作如何到达：** 用户在 `meson.build` 文件中使用 `install_subdir` 定义需要安装的子目录。

25. **获取内省数据： `get_introspection_data(target_id, target)`**
    - **功能：**  为给定的目标返回内省数据，包括语言、编译器、编译参数、源文件和生成源文件。这是一个基本的实现，后端可以覆盖此方法以提供更详细的信息。
    - **用户操作如何到达：**  当用户或工具使用 Meson 的内省功能来获取目标的详细信息时，会调用此函数。

26. **获取开发环境： `get_devenv()`**
    - **功能：** 返回一个包含开发环境所需环境变量的 `EnvironmentVariables` 对象。这包括添加到 `PATH` 和 `LD_LIBRARY_PATH` 的路径。
    - **Linux, Android 内核及框架知识：**  涉及到 Linux 上的动态链接器路径 (`LD_LIBRARY_PATH`) 和 Windows 上的 DLL 搜索路径。
    - **用户操作如何到达：**  当用户需要设置开发环境以便运行或调试构建的程序时，可以使用此函数获取环境变量。

27. **编译器到生成器： `compiler_to_generator(...)`**
    - **功能：**  将编译器命令转换为生成器列表。这在某些不支持自定义编译器的后端中很有用。

**归纳其功能：**

总的来说，这段代码是 Meson 构建系统后端的一部分，**核心功能是管理和处理自定义目标和构建目标的各种信息，特别是关于它们的依赖关系、源文件、输出文件以及安装过程**。 它负责将 Meson 的抽象构建描述转换为特定构建后端（如 Ninja）能够理解的指令。  这段代码深入到了构建过程的细节，涉及到文件路径处理、命令评估、依赖关系分析和安装数据生成等多个方面。它为 Frida 这样的动态 instrumentation 工具的构建提供了基础支持。

作为调试线索，如果构建过程中涉及到自定义目标或安装过程出现问题，例如找不到源文件、命令执行失败、安装路径错误等，那么分析这段代码中相关函数的执行逻辑和输入输出，可以帮助定位问题的根源。例如，检查 `get_custom_target_sources` 返回的源文件路径是否正确，或者 `eval_custom_target_command` 生成的命令是否符合预期。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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