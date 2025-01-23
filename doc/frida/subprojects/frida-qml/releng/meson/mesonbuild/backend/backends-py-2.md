Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Understanding the Request:**

The request asks for a functional analysis of the provided Python code, specifically within the context of the Frida dynamic instrumentation tool. Key areas to focus on include:

* **Functionality:** What does the code *do*?
* **Reverse Engineering Relevance:** How does it relate to understanding or modifying software?
* **Binary/Kernel/Framework Interactions:** Does it touch low-level aspects of operating systems?
* **Logic and Reasoning:** Are there conditional statements or data transformations we can analyze?
* **Common Errors:** What mistakes might a user or programmer make when interacting with this code or the system it supports?
* **User Journey:** How does a user's action lead to this code being executed?
* **Summarization:** Condense the overall purpose of the code.

**2. Initial Code Examination (Skimming and Identifying Key Elements):**

The first step is to quickly read through the code, paying attention to:

* **Class and Method Names:**  `Backend`, `get_custom_target_provided_by_generated_source`, `get_custom_target_sources`, `eval_custom_target_command`, `generate_target_install`, etc. These names provide strong hints about the code's purpose.
* **Imports:** `os`, `typing`, `shlex`, `pickle`, `pathlib`, `mesonlib`, `build`, `programs`, `detect`, `mlog`. These tell us about the dependencies and the types of operations being performed (file system interactions, type hinting, shell command manipulation, serialization, path handling, Meson build system objects, external programs, platform detection, logging).
* **Data Structures:** Lists (`T.List`), dictionaries (implicitly in the `get_introspection_data` method), sets, and custom objects (`build.CustomTarget`, `build.BuildTarget`, `InstallData`, etc.).
* **Core Operations:** File path manipulation (`os.path.join`, `os.path.normpath`), string formatting, conditional logic (`if isinstance`), looping (`for`), assertions, caching (`@lru_cache`), command execution (implicitly in `eval_custom_target_command`), and data serialization (`pickle`).

**3. Focusing on Key Functions and Their Interactions:**

Instead of trying to understand every line at once, it's more effective to focus on the most significant functions and how they relate to each other. Some standout functions based on their names and content:

* **`get_custom_target_provided_by_generated_source` and `get_custom_target_provided_libraries`:** These deal with identifying libraries produced by custom build steps. This is relevant to understanding dependencies and the output of build processes.
* **`get_custom_target_sources`:** This function retrieves the input files for custom build targets. This is crucial for understanding what a particular build step operates on.
* **`get_target_depend_files`:** This identifies explicit dependencies of a target. This is vital for understanding build order and potential issues related to missing dependencies.
* **`eval_custom_target_command`:** This function is central to understanding how custom build steps are executed. It involves constructing command-line arguments and handling various types of inputs and outputs.
* **`generate_target_install`:** This function is responsible for determining how built targets (executables, libraries, etc.) are installed. This ties directly to the deployment phase of software.
* **`create_install_data` and related `generate_*_install` functions:** These functions handle the creation of installation metadata, covering various types of installable artifacts (headers, man pages, data files, etc.).

**4. Connecting Functionality to Reverse Engineering:**

With a grasp of what the functions do, the next step is to connect them to reverse engineering concepts. Key connections include:

* **Understanding Build Processes:**  Reverse engineers often need to understand how software was built to make sense of its structure and dependencies. Functions like `get_custom_target_sources`, `eval_custom_target_command`, and `get_target_depend_files` provide insights into the build process.
* **Identifying Libraries and Dependencies:**  Knowing which libraries a program uses is essential for reverse engineering. Functions like `get_custom_target_provided_libraries` are directly relevant here.
* **Analyzing Custom Build Steps:** Software may use custom build steps for code generation or other transformations. Understanding the commands executed by `eval_custom_target_command` can reveal these processes.
* **Understanding Installation Locations:** Knowing where files are installed is crucial for finding and analyzing them. Functions in the `generate_*_install` family provide this information.

**5. Identifying Binary/Kernel/Framework Relevance:**

This requires looking for interactions with lower-level concepts:

* **Library Handling:**  The code deals with shared libraries (`.so`, `.dll`), import libraries, and static archives (`.a`). This directly relates to how operating systems load and link code.
* **Stripping Symbols:** The mention of "strip" relates to removing debugging symbols from binaries, a common practice in software distribution.
* **Installation Paths:**  Paths like `/usr/lib`, `/usr/bin`, etc., are standard locations in Linux systems.
* **Environment Variables:**  The `get_devenv` function manipulates environment variables like `PATH`, `LD_LIBRARY_PATH`, and `DYLD_LIBRARY_PATH`, which are fundamental for program execution.
* **Windows Specifics:** The code handles Windows-specific concepts like import libraries and the need to add library paths to the `PATH` environment variable.

**6. Considering Logic and Reasoning (Hypothetical Inputs and Outputs):**

For functions like `eval_custom_target_command`, we can imagine scenarios:

* **Input:** A `CustomTarget` object representing a code generation step with a command like `protoc --cpp_out=. input.proto`.
* **Output:** The function would construct the actual command-line string, potentially substituting variables like `@SOURCE_ROOT@` and handling different input/output file types.

**7. Identifying Common Errors:**

Looking for potential pitfalls in how users might interact with the build system:

* **Incorrect `install_dir` specifications:** The code explicitly checks for mismatches between the number of outputs and installation directories, highlighting a potential user error.
* **Missing dependencies:** If a custom command relies on a tool not being in the `PATH`, the build might fail. The code doesn't directly handle this, but the context of a build system makes it a relevant consideration.
* **Incorrectly specified custom commands:**  Errors in the command string within a `CustomTarget` can lead to build failures.

**8. Tracing the User Journey:**

Thinking about how a user's actions might lead to this code being executed:

* A developer uses the Meson build system to define how their project is built.
* The `meson.build` file specifies targets, dependencies, and installation rules.
* When the user runs `meson compile` or `meson install`, Meson parses these definitions.
* The `Backend` class and its methods are used to translate the high-level build definitions into platform-specific build instructions (Makefiles, Ninja files, etc.).
* Specifically, when a `CustomTarget` is encountered, or when installation rules are being processed, the methods in this file are likely to be called.

**9. Summarization:**

Finally, condense the analysis into a concise summary that captures the essence of the code's functionality. Focus on the main roles of the class and its key methods in the context of the Frida build process.

This systematic approach, starting with high-level understanding and progressively drilling down into specifics, allows for a comprehensive analysis of the code snippet and its relevance to the broader context of Frida and reverse engineering.
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/backend/backends.py` 文件的第 3 部分，主要包含 `Backend` 类中关于处理构建目标（targets），特别是自定义目标（custom targets）和安装过程的相关功能。

让我们分解一下它的功能，并结合你的问题进行说明：

**核心功能归纳:**

* **处理自定义构建目标 (Custom Targets):** 提供了一系列方法来解析和处理 Meson 构建系统中定义的自定义构建目标。这包括获取其源文件、依赖文件、输出目录以及最重要的——执行命令。
* **生成安装数据 (Install Data):** 负责生成用于安装项目的文件和目录的元数据。这包括可执行文件、库文件、头文件、man 手册、数据文件、符号链接等等。
* **推断安装标签 (Install Tags):** 尝试根据文件路径推断出适合的安装标签（例如 'runtime', 'devel', 'i18n'）。这有助于安装程序（如 `ninja install`）将文件放到合适的目录下。
* **处理不同类型的构建目标:**  能够区分和处理标准构建目标（`BuildTarget`，例如库和可执行文件）和自定义构建目标 (`CustomTarget`)。
* **处理依赖关系:** 识别构建目标之间的依赖关系，包括显式依赖和通过生成的源文件提供的隐式依赖。
* **处理安装路径:**  管理构建输出文件的安装路径，包括默认路径和自定义路径。
* **为开发环境设置环境变量:**  生成用于开发环境的合适环境变量，例如 `PATH`，`LD_LIBRARY_PATH`，以便开发者可以直接运行或测试构建出的程序。
* **代码内省 (Introspection):**  提供获取构建目标元数据的方法，用于其他工具或脚本分析构建过程。

**与逆向方法的关系及举例说明:**

* **理解构建过程:** 逆向工程师经常需要理解目标软件的构建过程，才能更好地分析其结构和行为。`Backend` 类中的方法，特别是处理自定义目标的那些，可以帮助理解软件的构建步骤，例如代码生成、资源打包等。
    * **举例:**  假设逆向一个使用了自定义目标来解密或预处理某些资源文件的程序。通过分析 `eval_custom_target_command` 方法，可以了解到解密或预处理的具体命令和参数，从而为逆向分析提供关键信息。例如，如果命令中使用了某个特定的解密工具和密钥，逆向工程师就可以针对性地进行分析。
* **识别依赖库:** 逆向分析经常需要确定目标程序依赖的库。`get_custom_target_provided_libraries` 和 `get_target_depend_files` 可以帮助识别这些依赖关系，包括由自定义目标生成的库。
    * **举例:**  某个 Android 应用可能使用了一个通过自定义目标编译生成的 native 库。通过分析这些方法，逆向工程师可以找到这个库的路径和名称，并对其进行进一步的分析。
* **分析自定义构建步骤:** 某些软件会使用自定义的构建步骤来混淆代码或进行其他保护。理解这些自定义步骤对于逆向至关重要。
    * **举例:** 一个软件可能使用自定义目标来对某些关键代码进行加密，然后在运行时解密。分析 `eval_custom_target_command` 可以揭示加密的方式和使用的密钥（如果硬编码在命令中）。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

* **处理库文件类型:** 代码中区分了不同类型的库文件，如共享库 (`.so`, `.dll`) 和静态库 (`.a`)。这涉及到操作系统加载和链接二进制文件的底层知识。
    * **举例:**  在 `generate_target_install` 方法中，针对共享库会考虑安装导入库（import library），这在 Windows 系统中很常见，涉及到 PE 文件格式和链接器的知识。
* **处理可执行文件:** 代码中处理可执行文件的安装，这涉及到操作系统如何加载和执行二进制文件。
    * **举例:** `get_devenv` 方法会根据目标平台设置 `PATH`，`LD_LIBRARY_PATH` 等环境变量，这直接关系到操作系统如何查找可执行文件和共享库。在 Android 上，这可能涉及到 `LD_LIBRARY_PATH` 的设置以加载 native 库。
* **处理符号剥离 (Stripping):** 代码中提到了 `strip` 命令，用于移除二进制文件中的调试符号，减小文件大小。这是一种常见的二进制文件处理技术。
    * **举例:** `generate_target_install` 方法中会判断是否需要对目标文件执行 `strip` 命令。
* **安装路径:** 代码中定义了常见的安装路径，如 `/usr/bin`, `/usr/lib`, `/usr/include` 等，这些都是 Linux 和类 Unix 系统中约定的目录结构。在 Android 中，安装路径的概念有所不同，但 build 系统仍然需要处理文件放置的位置。
* **交叉编译:** 代码中提到 `environment.is_cross_build()`，表明 Frida 可能支持交叉编译，这涉及到为不同架构和操作系统的目标构建二进制文件。
    * **举例:** 在交叉编译 Android 上的 Frida 组件时，需要指定 Android NDK 的工具链，并且生成的二进制文件需要符合 Android 的 ABI 规范。

**逻辑推理，假设输入与输出:**

* **假设输入:** 一个 `CustomTarget` 对象，定义了一个将 `.proto` 文件编译成 C++ 代码的步骤。该 `CustomTarget` 对象的 `command` 属性可能包含类似 `['protoc', '--cpp_out=.', '@INPUT@']` 的命令，`sources` 属性包含一个 `.proto` 文件的路径。
* **输出 (在 `eval_custom_target_command` 中):**  该方法会解析这个 `CustomTarget` 对象，并将命令中的 `@INPUT@` 替换为实际的输入文件路径，最终生成一个可执行的命令列表，例如 `['protoc', '--cpp_out=.', 'path/to/input.proto']`。

**涉及用户或者编程常见的使用错误及举例说明:**

* **错误的 `install_dir` 配置:** 用户可能在 `meson.build` 文件中为构建目标的输出指定了错误的安装目录。
    * **举例:**  在 `generate_target_install` 方法中，代码会检查 `outdirs` 和 `t.get_outputs()` 的数量是否一致，如果不一致，则会抛出 `MesonException`，提示用户配置错误。
* **自定义命令错误:** 用户在定义 `CustomTarget` 时，可能编写了错误的命令，导致构建失败。
    * **举例:** 命令中引用的外部程序不存在，或者命令的参数不正确。虽然这段代码本身不直接处理命令执行错误，但在构建过程中会暴露出来。
* **依赖关系未声明:** 用户可能忘记声明自定义目标所依赖的其他目标或文件。
    * **举例:**  一个自定义目标生成代码，而另一个目标需要使用这些生成的代码，但它们之间没有明确的依赖关系。这可能导致构建顺序错误，或者找不到生成的代码。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户在项目根目录下编写 `meson.build` 文件，定义了项目的构建规则，包括构建目标、自定义目标、安装规则等。
2. **用户运行 `meson setup builddir`:** 用户运行 Meson 的配置命令，Meson 会读取 `meson.build` 文件，解析构建定义，并生成构建系统所需的中间文件。
3. **用户运行 `meson compile -C builddir` 或 `ninja -C builddir`:** 用户运行编译命令，构建系统会根据 Meson 生成的配置，执行编译、链接等操作。
4. **处理自定义目标:** 当构建系统遇到一个 `CustomTarget` 时，`backends.py` 中的相关方法，如 `get_custom_target_sources` 和 `eval_custom_target_command` 会被调用，以获取自定义目标的源文件、生成执行命令。
5. **用户运行 `meson install -C builddir` 或 `ninja -C builddir install`:** 用户运行安装命令，将构建产物安装到系统中。
6. **生成安装数据:**  在安装阶段，`backends.py` 中的 `create_install_data` 方法会被调用，该方法会调用各种 `generate_*_install` 方法，例如 `generate_target_install`、`generate_header_install` 等，来生成安装所需的元数据。

作为调试线索，如果构建或安装过程中出现问题，例如自定义目标执行失败，或者文件安装路径错误，可以：

* **检查 `meson.build` 文件中关于 `CustomTarget` 的定义:** 查看命令是否正确，输入输出是否配置正确，依赖是否声明完整。
* **查看 Meson 的构建日志:**  日志中会记录自定义目标的执行命令和输出，可以帮助定位问题。
* **Debug `backends.py` 中的相关代码:**  如果怀疑是 Meson 本身的逻辑问题，可以阅读或调试 `backends.py` 中的代码，例如在 `eval_custom_target_command` 中打印生成的命令，查看是否符合预期。

**总结第 3 部分的功能:**

这部分代码主要负责 **处理构建过程中的目标定义，特别是自定义目标，并生成用于安装阶段的元数据**。它连接了 Meson 构建定义和实际的构建和安装操作，是构建系统后端的核心组成部分，负责将高层次的构建意图转化为底层的操作指令。它深入涉及了二进制文件的处理、操作系统相关的知识，并且需要处理用户可能出现的各种配置错误。对于逆向工程师来说，理解这部分代码有助于深入理解目标软件的构建方式和依赖关系。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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