Response:
The user wants to understand the functionality of the Python code provided. I need to break down the code into logical parts and explain what each part does. I should focus on the aspects related to reverse engineering, binary manipulation, and operating system internals as requested. For each function, I'll consider:
1. **Core functionality:** What is the primary purpose of this function?
2. **Relevance to reverse engineering:** Does it help in analyzing or manipulating binaries?
3. **Relevance to binary/OS internals:** Does it interact with low-level concepts like libraries, kernels, or file systems?
4. **Logic and assumptions:**  Are there conditional statements or assumptions about the input?  Can I provide a simple input/output example?
5. **Potential user errors:** How might a user misuse this function or encounter errors while using it?
6. **User interaction flow:** How does a user's action in the build system eventually lead to this code being executed?

**High-level plan:**

1. Read through the code and identify the main classes and functions.
2. For each function, analyze its purpose and relate it to the user's questions.
3. Provide specific examples and explanations for the relevant areas.
4. Summarize the overall functionality of the code.

**Detailed plan:**

* **`_get_dependencies`:** Focus on how it identifies dependencies between build targets, which is relevant for understanding how different parts of a software project are linked.
* **`get_custom_target_provided_by_generated_source` and `get_custom_target_provided_libraries`:**  These functions deal with how custom build steps generate libraries, which is important for reverse engineering scenarios where you might encounter dynamically generated code.
* **`get_custom_target_sources`:** This function retrieves the sources of custom build targets. Understanding where the input for a build step comes from is crucial in reverse engineering. The different types of sources (strings, BuildTarget, CustomTarget, etc.) need to be explained.
* **`get_target_depend_files`:**  This function identifies files that a target depends on. This is directly relevant to reverse engineering, as it helps in understanding the file dependencies of a binary.
* **`get_custom_target_output_dir`:** This function determines where the output of a custom build step is placed. Knowing the output locations is essential for finding the generated artifacts.
* **`get_normpath_target`:** A simple path normalization function, potentially relevant when dealing with file paths in reverse engineering.
* **`get_custom_target_dirs` and `get_custom_target_dir_include_args`:** These functions relate to include directories for custom targets, which are essential for compiling code that depends on the output of these targets.
* **`eval_custom_target_command`:** This is a crucial function. It constructs the actual command that will be executed for a custom build target. This directly relates to understanding the build process and can reveal how specific binaries are generated. The template string substitution (`@SOURCE_ROOT@`, etc.) is important to note.
* **`get_introspect_command`:** Explains how to get introspection data, useful for understanding the build system's configuration.
* **`get_run_target_env`:**  Deals with setting up the environment for running targets, which can be relevant when analyzing how a program behaves under specific environment variables.
* **`run_postconf_scripts`:**  Executes post-configuration scripts, which can perform various setup tasks.
* **`create_install_data` and related `generate_*_install` functions:** These functions are responsible for generating the data needed for the installation process. Understanding the installation process is relevant to reverse engineering as it reveals where files are placed on the system.
* **`guess_install_tag`:**  Attempts to automatically categorize installed files, which can be useful for organizing reverse engineering efforts.
* **`get_introspection_data`:**  Provides a way to retrieve information about the sources, compilers, and parameters used to build a target.
* **`get_devenv`:** Sets up the developer environment, including PATH and library paths, which is relevant when trying to replicate a development setup for analysis.
* **`compiler_to_generator`:**  A utility function for handling custom compilers.

After analyzing each function, I will synthesize the information to create a summary of the code's overall functionality.
这是 `backends.py` 文件的第 3 部分，主要负责生成构建系统后端所需的各种信息，特别是关于自定义目标（CustomTarget）和安装过程的数据。它提供了许多方法来提取和处理构建目标（BuildTarget 和 CustomTarget）的属性，并将这些信息组织成用于生成特定后端构建文件的格式。

以下是该部分代码功能的归纳：

**核心功能：**

1. **依赖关系分析：**
   - `_get_dependencies`:  识别并返回给定目标的所有依赖项（BuildTarget 和 CustomTarget）。这对于理解构建顺序至关重要。

2. **自定义目标输出处理：**
   - `get_custom_target_provided_by_generated_source`: 确定由生成的源文件提供的库文件路径。
   - `get_custom_target_provided_libraries`: 获取自定义目标生成的所有库文件路径。
   - `get_custom_target_sources`:  获取自定义目标的源文件列表，并处理不同类型的源（字符串、文件对象、其他构建目标等），返回相对于构建根目录的路径。
   - `get_target_depend_files`: 获取目标依赖的文件列表，可以是绝对路径或相对于构建目录的路径。
   - `get_custom_target_output_dir`: 获取自定义目标的输出目录。
   - `get_normpath_target`: 对目标路径进行规范化处理。
   - `get_custom_target_dirs`: 获取自定义目标的包含目录列表。
   - `get_custom_target_dir_include_args`:  生成自定义目标的包含目录的编译器参数。
   - `eval_custom_target_command`:  评估自定义目标的执行命令，包括替换占位符（如 `@SOURCE_ROOT@`, `@BUILD_ROOT@` 等），并返回输入、输出和命令列表。

3. **构建系统内省：**
   - `get_introspect_command`: 返回用于获取构建系统内省信息的命令。

4. **运行目标环境设置：**
   - `get_run_target_env`: 获取运行目标所需的的环境变量。

5. **后配置脚本执行：**
   - `run_postconf_scripts`: 运行在配置后需要执行的脚本。

6. **生成安装数据：**
   - `create_install_data`: 创建包含所有安装信息的数据对象 (`InstallData`)，包括目标文件、头文件、man 文件、数据文件、符号链接、自定义安装脚本和子目录安装信息。
   - `create_install_data_files`: 将生成的安装数据序列化到文件中。
   - `guess_install_tag`:  尝试根据文件路径猜测安装标签。
   - `generate_target_install`:  生成目标文件的安装信息。
   - `generate_custom_install_script`: 生成自定义安装脚本的安装信息。
   - `generate_header_install`: 生成头文件的安装信息。
   - `generate_man_install`: 生成 man 页面的安装信息。
   - `generate_emptydir_install`: 生成空目录的安装信息。
   - `generate_data_install`: 生成数据文件的安装信息。
   - `generate_symlink_install`: 生成符号链接的安装信息。
   - `generate_subdir_install`: 生成子目录的安装信息。

7. **获取目标内省数据：**
   - `get_introspection_data`:  获取关于目标构建过程的详细信息，如使用的语言、编译器、编译参数和源文件。

8. **开发环境设置：**
   - `get_devenv`:  生成用于设置开发环境的环境变量，例如添加可执行文件路径到 `PATH`，添加库文件路径到 `LD_LIBRARY_PATH` 等。

9. **编译器到生成器的转换：**
   - `compiler_to_generator`:  提供一种将编译器操作转换为生成器操作的便捷方法，用于不支持自定义编译器的后端。

**与逆向方法的关系及举例说明：**

* **理解构建过程：** `eval_custom_target_command` 可以帮助逆向工程师理解特定二进制文件是如何通过自定义构建步骤生成的。例如，如果一个恶意软件样本是通过自定义脚本打包的，分析这个函数的输出可以揭示打包的步骤和所使用的工具。
    * **假设输入：** 一个名为 `pack_malware` 的 `CustomTarget`，其 `command` 包含 `tar -czvf output.tar.gz input_file`。
    * **输出：** `eval_custom_target_command` 会返回命令列表 `['tar', '-czvf', 'build_dir/output.tar.gz', 'source_dir/input_file']`（路径会根据实际配置而变化），这清晰地展示了打包命令。

* **查找依赖关系：** `_get_dependencies` 可以帮助理解一个二进制文件依赖于哪些其他库或目标。在逆向分析中，了解依赖关系有助于构建完整的分析环境。例如，如果分析一个使用了特定加密库的二进制文件，该函数可以帮助找到该库的构建目标。

* **定位生成的文件：** `get_custom_target_output_dir` 可以帮助逆向工程师找到自定义构建步骤生成的中间或最终文件。例如，如果一个二进制文件是通过先编译 C 代码再进行混淆生成的，这个函数可以帮助定位编译后的未混淆的二进制文件。

* **识别安装位置：** `generate_target_install` 和相关的 `generate_*_install` 函数可以揭示程序在安装时会将哪些文件复制到哪里。这对于分析恶意软件的持久化机制或理解正常软件的部署结构非常重要。例如，可以确定可执行文件是否被安装到 `/usr/bin`，配置文件是否被安装到 `/etc` 等。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **库文件处理：** `get_custom_target_provided_libraries` 涉及到对库文件的识别和处理，这与 Linux 和 Android 等操作系统中动态链接库的概念密切相关。在 Android 中，这可能涉及到 `.so` 文件的生成和安装。
    * **举例：** 如果一个 `CustomTarget` 使用 NDK 编译生成了一个 `.so` 文件，`get_custom_target_provided_libraries` 会返回该 `.so` 文件的路径。

* **可执行文件路径：** `get_devenv` 中将可执行文件路径添加到 `PATH` 环境变量，这直接关系到操作系统如何查找和执行二进制文件。在 Linux 和 Android 中，`PATH` 环境变量的设置是执行命令的基础。

* **库文件搜索路径：** `get_devenv` 中将库文件路径添加到 `LD_LIBRARY_PATH` (Linux) 或类似的变量，这与动态链接器在运行时查找共享库的机制有关。这在 Android 开发中也适用，尽管 Android 有其自己的库加载机制。

* **安装目录：** 代码中多次使用诸如 `{bindir}`、`{libdir}`、`{includedir}` 等占位符，这些代表了 Linux 系统中常见的标准安装目录，例如 `/usr/bin`、`/usr/lib`、`/usr/include`。

* **剥离符号信息：** `create_install_data` 中提到了 `strip_bin`，这涉及到从二进制文件中移除调试符号，减小文件大小。这在发布软件时很常见，但在逆向工程中会增加分析难度。

**逻辑推理、假设输入与输出：**

* **`guess_install_tag`:** 该函数尝试根据文件路径推断安装标签。
    * **假设输入：** 文件路径 `/usr/bin/myprogram`。
    * **输出：** 推断的安装标签可能是 `'runtime'`，因为文件位于 `bindir` 中。
    * **假设输入：** 文件路径 `/usr/include/myheader.h`。
    * **输出：** 推断的安装标签可能是 `'devel'`，因为文件位于 `includedir` 中。

**涉及用户或编程常见的使用错误及举例说明：**

* **`eval_custom_target_command` 中 `@DEPFILE@` 的使用：** 如果用户在自定义目标的命令中使用了 `@DEPFILE@` 占位符，但没有在 `meson.build` 文件中为该目标指定 `depfile` 关键字参数，则会抛出 `MesonException`。
    * **错误示例 (meson.build):**
      ```python
      custom_target('my_target',
          input: 'input.c',
          output: 'output.o',
          command: ['mycompiler', '@INPUT@', '@OUTPUT@', '@DEPFILE@']
      )
      ```
    * **正确示例 (meson.build):**
      ```python
      custom_target('my_target',
          input: 'input.c',
          output: 'output.o',
          command: ['mycompiler', '@INPUT@', '@OUTPUT@', '@DEPFILE@'],
          depfile: 'output.d'
      )
      ```

* **`generate_target_install` 中 `install_dir` 的数量不匹配：** 如果一个目标有多个输出，但提供的 `install_dir` 数量与输出数量不符（既不是 1 也不是输出数量），则会抛出 `MesonException`，提示用户正确指定安装目录。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件：** 用户在项目中定义了构建目标，包括可执行文件、库文件和自定义目标，并指定了它们的属性，如源文件、依赖项、安装位置等。

2. **用户运行 `meson` 命令配置构建：**  `meson` 命令会读取 `meson.build` 文件，解析用户的构建意图，并生成一个内部的构建描述数据结构。

3. **用户运行 `ninja` (或其他后端工具) 构建项目：**  `ninja` (或其他后端工具) 会读取 `meson` 生成的构建描述文件，并根据这些信息执行实际的编译、链接等操作。

4. **`backends.py` 的角色：** 在 `ninja` 构建过程中，或者在执行 `meson install` 命令时，`backends.py` (以及其他后端相关文件) 会被调用，负责将 Meson 的通用构建描述转换为特定后端（如 Ninja、Xcode、Visual Studio）能够理解和执行的构建指令。

5. **到达第 3 部分代码：**  当 Meson 需要处理自定义目标、生成安装数据或进行构建系统内省时，就会执行 `backends.py` 中的相关函数。例如：
    * 当处理一个 `custom_target()` 时，会调用 `eval_custom_target_command` 来生成实际的执行命令。
    * 当用户执行 `meson install` 时，会调用 `create_install_data` 和相关的 `generate_*_install` 函数来生成安装清单。
    * 当用户执行 `meson introspect` 时，会调用 `get_introspection_data` 来获取构建目标的详细信息。

总而言之，`backends.py` 的这一部分是 Meson 构建系统后端的核心组成部分，它负责将高级的构建描述转换为底层的构建指令和安装信息，使得构建过程能够顺利进行。它提供了丰富的接口来查询和操作构建目标的属性，这对于理解构建过程、进行逆向分析以及进行底层的系统开发都非常有价值。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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