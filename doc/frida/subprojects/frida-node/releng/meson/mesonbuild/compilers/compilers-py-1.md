Response:
The user wants a summary of the functionality of the provided Python code, focusing on aspects relevant to reverse engineering, low-level programming, and potential user errors. I need to analyze the code and extract its main purposes and how it achieves them.

Here's a breakdown of my thought process:

1. **Identify the Core Class:** The code defines an abstract base class `Compiler`. This suggests that the primary function of this file is to provide a common interface for interacting with different compilers.

2. **Analyze Key Methods:** I'll go through the methods defined in the `Compiler` class and understand their individual roles. This will give me a comprehensive view of the class's capabilities. I'll pay attention to methods related to compilation, linking, and handling compiler arguments.

3. **Look for Reverse Engineering Connections:** I'll specifically search for methods or functionalities that are directly used or relevant in reverse engineering. This might include methods related to debugging information, linking, and potentially even pre-processing.

4. **Identify Low-Level Interactions:** I'll look for methods that interact with the operating system, file system, or handle aspects related to the underlying architecture (like instruction sets). Keywords like "linker," "kernel," "binary," "shared library," etc., will be important here.

5. **Infer Logical Reasoning:**  I need to understand the flow of execution and how different methods interact. I can look for conditional logic and how different inputs might affect the outputs or the execution path.

6. **Consider User Errors:** Based on the methods and their parameters, I'll think about common mistakes a user might make when using this code or when configuring the build process that utilizes it.

7. **Track User Operations (Debugging Clues):**  I need to think about how a user's actions during the build process might lead to the execution of the code in this file. This involves understanding the overall build system (Meson in this case) and how it invokes compiler operations.

8. **Structure the Output:**  I'll organize my findings into the categories requested by the user: functionality, relation to reverse engineering, low-level knowledge, logical reasoning, user errors, and debugging clues.

**Detailed Analysis of Key Methods (and relevant thought process):**

* **`__init__`:**  Sets up the compiler object with essential information like exelist, version, and language. This is fundamental for identifying and managing different compilers.
* **`get_exelist`:** Determines the actual command to execute the compiler, considering potential wrappers like `ccache`. This is relevant to understanding the exact commands being run.
* **`_get_compile_output`:**  Determines the output file name based on the compilation mode (link, compile, preprocess). This is crucial for understanding where intermediate and final files are placed.
* **`get_compiler_args_for_mode`:** Selects the appropriate compiler arguments based on the compilation stage. This is important for understanding how the compiler is being instructed.
* **`compile`:** This is a core method that executes the compiler with given code and arguments. It involves creating temporary files, running the compiler process, and capturing output. This directly relates to the fundamental action of compilation. The use of `Popen_safe_logged` suggests that the execution is monitored and logged, which is helpful for debugging.
* **`cached_compile`:**  Implements caching of compilation results to speed up subsequent builds. This highlights an optimization strategy within the build system.
* **`get_output_args`:** Provides arguments to specify the output file. This is essential for directing the compiler's output.
* **Methods related to linking (`get_link_*`, `build_rpath_args`, etc.):** These methods deal with the linking stage, which is crucial for combining compiled object files into executables or libraries. Understanding these methods is important for reverse engineering as they determine how different parts of the program are connected.
* **Methods related to debugging (`get_compile_debugfile_args`, `get_link_debugfile_args`):** These are directly relevant to reverse engineering as they control the generation of debugging information, which is vital for analysis.
* **Methods related to different compiler features (`get_pic_args`, `get_pie_args`, `get_lto_*`, `sanitizer_*`):** These methods manage various compiler features that affect the generated code's security, performance, and behavior. Understanding these is important for analyzing the characteristics of the compiled binary.
* **`sanity_check`:**  Ensures the compiler is working correctly. This is a fundamental step in setting up the build environment.

**Connecting to the Prompt's Requirements:**

* **Reverse Engineering:** Methods related to debugging symbols, linking (how libraries are combined), and potentially pre-processing (to understand macro expansions) are relevant.
* **Binary/Low-Level:**  Methods dealing with linking, instruction sets, shared libraries, and even the handling of response files point to low-level interactions.
* **Linux/Android Kernel/Framework:** While the code itself doesn't directly interact with the kernel, the compiler and linker it manages are crucial for building software that runs on these platforms. The concepts of shared libraries and linking are fundamental in these environments.
* **Logical Reasoning:** The `compile` and `cached_compile` methods involve conditional logic based on compilation modes and caching status. The selection of compiler arguments based on the mode also demonstrates logical reasoning.
* **User Errors:** Incorrectly specifying compiler arguments, missing dependencies, or misconfiguring the build environment could lead to errors during the compilation process handled by this code.
* **Debugging Clues:** The code's execution is triggered by the build system (Meson) when it needs to compile or link source code. Understanding the Meson build process is key to tracing how the user's actions lead to this code being invoked.

By following these steps, I can generate a comprehensive summary that addresses all aspects of the user's request.
好的，这是对`frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/compilers.py`文件功能的第二部分归纳：

**核心功能归纳 (基于提供的代码片段):**

总的来说，这部分代码延续了 `Compiler` 抽象基类的定义，  **专注于提供编译和链接过程中的更具体和高级的功能，并为不同的编译器实现提供了一个统一的接口。**  它涵盖了更细粒度的编译器和链接器选项控制，以及与构建系统更深层次的集成。

更具体地说，它提供了以下功能：

1. **细粒度的编译和链接选项控制:**  提供了大量的方法来控制编译器和链接器的行为，例如：
    * **调试信息控制:**  `get_compile_debugfile_args`, `get_link_debugfile_name`, `get_link_debugfile_args`, `get_debug_args` 用于处理调试符号的生成和链接。
    * **库链接:** `get_std_shared_lib_link_args`, `get_std_shared_module_link_args`, `get_link_whole_for`, `get_allow_undefined_link_args`, `no_undefined_link_args` 用于控制共享库和模块的链接方式。
    * **指令集控制:** `get_instruction_set_args` 用于指定目标架构的指令集。
    * **RPath 处理:** `build_rpath_args` 用于生成和处理 RPath，这是运行时库查找路径的关键。
    * **静态库/共享库归档:** `get_archive_name`, `get_command_to_archive_shlib` 用于处理库文件的创建。
    * **线程支持:** `thread_flags`, `thread_link_flags` 用于添加线程相关的编译和链接选项。
    * **OpenMP 支持:** `openmp_flags`, `openmp_link_flags` 用于添加 OpenMP 并行计算相关的选项。
    * **符号可见性:** `gnu_symbol_visibility_args` 用于控制符号的可见性。
    * **Windows 子系统:** `get_win_subsystem_args` 用于指定 Windows 可执行文件的子系统。
    * **PIC/PIE:** `get_pic_args`, `get_pie_args`, `get_pie_link_args` 用于控制生成位置无关代码和可执行文件。
    * **优化级别:** `get_optimization_link_args` 用于设置链接阶段的优化级别。
    * **Soname 处理:** `get_soname_args` 用于生成共享库的 Soname。
    * **目标特定链接参数:** `get_target_link_args` 用于获取特定构建目标的链接参数。
    * **依赖项处理:** `get_dependency_compile_args`, `get_dependency_link_args` 用于获取依赖项的编译和链接参数。
    * **覆盖率测试:** `get_coverage_args`, `get_coverage_link_args` 用于添加代码覆盖率测试相关的选项。
    * **断言控制:** `get_assert_args` 用于启用或禁用断言。
    * **C 运行时库 (CRT) 选择:** `get_crt_val`, `get_crt_compile_args`, `get_crt_link_args` 用于控制 Windows 平台的 C 运行时库链接方式。
    * **编译和预处理:** `get_compile_only_args`, `get_preprocess_only_args`, `get_preprocess_to_file_args` 用于控制编译和预处理阶段。
    * **大文件支持:** `get_largefile_args` 用于启用大文件支持。
    * **库目录:** `get_library_dirs` 用于指定库文件的搜索路径。
    * **返回值检查:** `get_return_value` (虽然抛出异常，但意图是获取函数返回值，可能在某些编译器实现中存在)。
    * **Framework 查找 (主要是 macOS):** `find_framework`, `find_framework_paths` 用于查找 macOS 的 Framework。
    * **函数属性检查:** `attribute_check_func`, `get_has_func_attribute_extra_args` 用于检查和处理函数属性。
    * **预编译头文件 (PCH):** `get_pch_suffix`, `get_pch_name`, `get_pch_use_args` 用于处理预编译头文件。
    * **依赖项生成:** `get_dependency_gen_args` 用于生成依赖项信息。
    * **可执行文件链接参数:** `get_std_exe_link_args` 用于获取标准可执行文件的链接参数。
    * **包含路径:** `get_include_args` 用于指定包含路径。
    * **依赖文件:** `depfile_for_object`, `get_depfile_suffix` 用于处理依赖文件。
    * **禁用标准包含:** `get_no_stdinc_args` 用于禁用标准库的自动包含。
    * **警告控制:** `get_warn_args`, `get_werror_args` 用于控制编译器警告。
    * **模块化编译:** `get_module_incdir_args`, `get_module_outdir_args`, `module_name_to_filename` 用于处理模块化编译。
    * **编译器检查参数:** `get_compiler_check_args`, `get_no_optimization_args` 用于在编译器检查时传递特定的参数，例如禁用优化。
    * **构建包装器:** `build_wrapper_args`, `_build_wrapper`, `compiles`, `links` 提供了一种机制来包装编译和链接命令，并支持缓存。
    * **D 语言特性:** `get_feature_args` 用于处理 D 语言的特定特性。
    * **预链接:** `get_prelink_args` 用于执行预链接操作。
    * **响应文件:** `rsp_file_syntax` 用于获取编译器支持的响应文件语法。
    * **静态链接器需求:** `needs_static_linker` 指示是否需要静态链接器。
    * **预处理器:** `get_preprocessor` 用于获取编译器的预处理器。

2. **构建系统集成:** 这些方法旨在与 Meson 构建系统紧密集成，允许 Meson 在不同的平台上使用不同的编译器时，能够以统一的方式控制编译和链接过程。

3. **缓存机制:**  `cached_compile` 方法利用 Meson 的缓存机制来加速构建过程，避免重复编译。

4. **错误处理和抽象:**  `EnvironmentException` 被用于指示某些编译器或语言不支持特定的功能，这体现了抽象基类的设计思想。

**与逆向方法的关联举例说明:**

* **调试信息控制 (`get_compile_debugfile_args`, `get_link_debugfile_args`):** 逆向工程师需要调试符号才能有效地分析二进制文件。这些方法决定了如何生成 `.pdb` (Windows) 或 `.dwarf` (Linux/macOS) 等调试信息文件。例如，如果逆向目标移除了调试符号，理解这些方法的运作方式可以帮助判断是否有可能恢复或重建部分调试信息。
* **链接过程分析 (`get_std_shared_lib_link_args`, `build_rpath_args`):** 逆向分析经常需要理解目标程序依赖哪些共享库以及这些库的加载路径。`get_std_shared_lib_link_args` 决定了如何链接共享库，`build_rpath_args` 则影响运行时库的查找。理解这些可以帮助逆向工程师构建分析环境或理解程序的加载行为。
* **位置无关代码 (PIC/PIE) (`get_pic_args`, `get_pie_args`):** 现代操作系统通常要求共享库和可执行文件使用位置无关代码 (PIC) 和位置无关可执行文件 (PIE) 以提高安全性。逆向工程师需要识别目标是否使用了 PIC/PIE，这会影响反汇编和分析的方式，因为地址可能需要在运行时计算。
* **链接时优化 (LTO) (`get_lto_compile_args`, `get_lto_link_args`):** 链接时优化可以将不同编译单元的代码进行跨模块的优化，这会使逆向分析变得更加复杂，因为函数可能被内联，代码结构可能被重组。理解 LTO 的编译和链接参数可以帮助逆向工程师理解代码优化的程度。
* **响应文件 (`rsp_file_syntax`):**  当编译或链接的参数非常多时，编译器可能会使用响应文件。逆向工程师如果需要重现编译或链接过程，可能需要了解目标编译器是否使用了响应文件以及其语法。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明:**

* **共享库链接 (`get_std_shared_lib_link_args`, `build_rpath_args`):**  在 Linux 和 Android 中，共享库是程序的重要组成部分。`get_std_shared_lib_link_args` 方法会生成类似 `-l<库名>` 的链接器参数，指示链接器链接特定的共享库。`build_rpath_args` 方法则会生成 `-Wl,-rpath,<路径>` 这样的参数，告诉动态链接器在哪里查找共享库。这直接关系到 Linux 和 Android 的动态链接机制。
* **RPath (`build_rpath_args`):**  RPath 是 Linux 系统中用于指定运行时库搜索路径的一种机制。理解 `build_rpath_args` 如何生成 RPath 参数对于理解程序在 Linux 或 Android 上的运行时依赖至关重要。
* **PIC/PIE (`get_pic_args`, `get_pie_args`):**  PIC 是在 Linux 和 Android 等共享库中使用的关键技术，它允许代码在内存中的任意位置加载。PIE 则提高了可执行文件的安全性，防止某些类型的攻击。`get_pic_args` 和 `get_pie_args` 方法生成的参数（例如 `-fPIC`）直接控制了这些特性的启用。
* **Soname (`get_soname_args`):**  Soname 是 Linux 共享库的一个重要属性，用于版本管理。`get_soname_args` 方法生成的参数（例如 `-Wl,-soname,lib<库名>.so.<版本>`）决定了共享库的 Soname。
* **Android Framework:** 虽然代码本身不直接操作 Android 内核或框架，但 Frida 作为动态插桩工具，其编译过程会涉及到与 Android 系统库的链接。理解这里的链接参数有助于理解 Frida 如何与 Android 系统交互。

**逻辑推理的假设输入与输出:**

假设我们正在为一个支持 GNU 风格参数的 C++ 编译器调用 `get_optimization_args` 方法：

* **假设输入:** `optimization_level = '2'` (表示优化级别为 2)。
* **预期输出:** `['-O2']` (GNU C++ 编译器通常使用 `-O` 选项加上数字来表示优化级别)。

假设我们正在为一个 MSVC 编译器调用 `get_optimization_args` 方法：

* **假设输入:** `optimization_level = '2'`
* **预期输出:** `['-O2']` 或 `['/O2']` (MSVC 也可能使用 `/O` 加上数字)。

**用户或编程常见的使用错误举例说明:**

* **错误地配置库路径:** 用户可能错误地配置了库的搜索路径，导致链接器无法找到所需的共享库。例如，在调用 Meson 的 `library()` 函数时，可能传递了错误的 `include_directories` 或 `link_directories`。这最终会导致链接器调用，而 `get_std_shared_lib_link_args` 等方法生成的链接参数可能指向不存在的路径。
* **忘记添加必要的链接库:** 用户可能在链接时忘记添加某些必要的库，导致链接器报错。例如，在使用某个第三方库时，忘记在 Meson 的 `link_with` 参数中指定该库。这会直接影响到 `get_std_shared_lib_link_args` 的效果，因为它不会生成链接该库的参数。
* **混合使用不同编译器的对象文件:**  用户可能尝试将使用不同编译器编译的对象文件链接在一起，这通常会导致链接错误，因为不同编译器生成的对象文件格式可能不兼容。
* **Windows CRT 链接错误:** 在 Windows 上，错误地配置 CRT 链接方式（例如，混合使用静态和动态 CRT）是常见的错误。用户可能在 Meson 的选项中错误地设置了 `cpp_std` 或相关的 CRT 选项，导致 `get_crt_link_args` 生成错误的链接参数。
* **依赖项循环:** 用户可能在项目依赖关系中引入循环，导致构建系统无法正确处理依赖项，最终可能导致链接错误。

**用户操作是如何一步步的到达这里，作为调试线索。**

当用户执行 `meson compile` 或 `ninja` 命令启动构建过程时，Meson 会根据 `meson.build` 文件中的描述来执行构建步骤。以下是一个简化的流程，说明如何到达 `compilers.py` 中的代码：

1. **用户运行 `meson setup builddir`:** Meson 读取 `meson.build` 文件，解析项目结构和构建目标。在这个过程中，Meson 会检测系统中可用的编译器，并根据用户的配置选择合适的编译器。
2. **Meson 确定编译器:** Meson 会实例化与所选语言对应的 `Compiler` 子类（例如，`GccCompiler`, `ClangCompiler`, `MsvcCompiler`）。
3. **用户运行 `meson compile` 或 `ninja`:** 构建系统开始编译源代码。
4. **编译源代码:** 当需要编译一个源文件时，Meson 会调用 `Compiler` 对象的 `compile` 或 `cached_compile` 方法。
5. **生成编译器命令行:** 在 `compile` 方法中，会调用各种 `get_*_args` 方法（例如，`get_compiler_args_for_mode`, `get_output_args`, `get_optimization_args` 等）来构建完整的编译器命令行。
6. **链接目标文件:** 当需要链接生成可执行文件或共享库时，Meson 会调用 `Compiler` 对象的链接相关方法。
7. **生成链接器命令行:** 类似地，会调用各种 `get_*_link_args` 方法（例如，`get_std_shared_lib_link_args`, `get_link_debugfile_args`, `build_rpath_args` 等）来构建链接器命令行。

**作为调试线索:**

* 如果构建失败，并且错误信息指向编译器或链接器命令行参数，那么可以检查 `compilers.py` 文件中生成这些参数的方法，以确定是否生成了正确的参数。
* 可以通过设置 Meson 的详细输出选项（例如，`meson --verbose` 或 Ninja 的 `-v`）来查看实际执行的编译器和链接器命令，并将这些命令与 `compilers.py` 中生成参数的逻辑进行对比。
* 如果怀疑是特定编译器或链接器选项导致的问题，可以直接在 `compilers.py` 中搜索与该选项相关的方法，查看其生成逻辑。
* 可以使用断点调试工具来跟踪 `compilers.py` 中的代码执行流程，查看在构建过程中哪些方法被调用，以及生成的参数值。

总而言之，`frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/compilers.py` 文件的这部分定义了 `Compiler` 类中用于控制编译和链接过程的各种细节的方法，是 Meson 构建系统与底层编译器和链接器交互的关键桥梁。理解这部分代码的功能对于理解 Frida 的构建过程，以及解决与编译和链接相关的构建问题至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
sion only matters if running results; '.exe' is
        # guaranteed to be executable on every platform.
        if mode == CompileCheckMode.LINK:
            suffix = 'exe'
        else:
            suffix = 'obj'
        return os.path.join(dirname, 'output.' + suffix)

    def get_compiler_args_for_mode(self, mode: CompileCheckMode) -> T.List[str]:
        args: T.List[str] = []
        args += self.get_always_args()
        if mode is CompileCheckMode.COMPILE:
            args += self.get_compile_only_args()
        elif mode is CompileCheckMode.PREPROCESS:
            args += self.get_preprocess_only_args()
        else:
            assert mode is CompileCheckMode.LINK
        return args

    def compiler_args(self, args: T.Optional[T.Iterable[str]] = None) -> CompilerArgs:
        """Return an appropriate CompilerArgs instance for this class."""
        return CompilerArgs(self, args)

    @contextlib.contextmanager
    def compile(self, code: 'mesonlib.FileOrString',
                extra_args: T.Union[None, CompilerArgs, T.List[str]] = None,
                *, mode: CompileCheckMode = CompileCheckMode.LINK, want_output: bool = False,
                temp_dir: T.Optional[str] = None) -> T.Iterator[CompileResult]:
        # TODO: there isn't really any reason for this to be a contextmanager

        if mode == CompileCheckMode.PREPROCESS:
            assert not want_output, 'In pre-processor mode, the output is sent to stdout and discarded'

        if extra_args is None:
            extra_args = []

        with TemporaryDirectoryWinProof(dir=temp_dir) as tmpdirname:
            no_ccache = False
            if isinstance(code, str):
                srcname = os.path.join(tmpdirname,
                                       'testfile.' + self.default_suffix)
                with open(srcname, 'w', encoding='utf-8') as ofile:
                    ofile.write(code)
                # ccache would result in a cache miss
                no_ccache = True
                code_debug = f'Code:\n{code}'
            else:
                srcname = code.fname
                code_debug = f'Source file: {srcname}'

            # Construct the compiler command-line
            commands = self.compiler_args()
            commands.append(srcname)

            # Preprocess mode outputs to stdout, so no output args
            if mode != CompileCheckMode.PREPROCESS:
                output = self._get_compile_output(tmpdirname, mode)
                commands += self.get_output_args(output)
            commands.extend(self.get_compiler_args_for_mode(CompileCheckMode(mode)))

            # extra_args must be last because it could contain '/link' to
            # pass args to VisualStudio's linker. In that case everything
            # in the command line after '/link' is given to the linker.
            if extra_args:
                commands += extra_args
            # Generate full command-line with the exelist
            command_list = self.get_exelist(ccache=not no_ccache) + commands.to_native()
            mlog.debug('Running compile:')
            mlog.debug('Working directory: ', tmpdirname)
            mlog.debug(code_debug)
            os_env = os.environ.copy()
            os_env['LC_ALL'] = 'C'
            if no_ccache:
                os_env['CCACHE_DISABLE'] = '1'
            p, stdo, stde = Popen_safe_logged(command_list, msg='Command line', cwd=tmpdirname, env=os_env)

            result = CompileResult(stdo, stde, command_list, p.returncode, input_name=srcname)
            if want_output:
                result.output_name = output
            yield result

    @contextlib.contextmanager
    def cached_compile(self, code: 'mesonlib.FileOrString', cdata: coredata.CoreData, *,
                       extra_args: T.Union[None, T.List[str], CompilerArgs] = None,
                       mode: CompileCheckMode = CompileCheckMode.LINK,
                       temp_dir: T.Optional[str] = None) -> T.Iterator[CompileResult]:
        # TODO: There's isn't really any reason for this to be a context manager

        # Calculate the key
        textra_args: T.Tuple[str, ...] = tuple(extra_args) if extra_args is not None else tuple()
        key: coredata.CompilerCheckCacheKey = (tuple(self.exelist), self.version, code, textra_args, mode)

        # Check if not cached, and generate, otherwise get from the cache
        if key in cdata.compiler_check_cache:
            p = cdata.compiler_check_cache[key]
            p.cached = True
            mlog.debug('Using cached compile:')
            mlog.debug('Cached command line: ', ' '.join(p.command), '\n')
            mlog.debug('Code:\n', code)
            mlog.debug('Cached compiler stdout:\n', p.stdout)
            mlog.debug('Cached compiler stderr:\n', p.stderr)
            yield p
        else:
            with self.compile(code, extra_args=extra_args, mode=mode, want_output=False, temp_dir=temp_dir) as p:
                cdata.compiler_check_cache[key] = p
                yield p

    def get_colorout_args(self, colortype: str) -> T.List[str]:
        # TODO: colortype can probably be an emum
        return []

    # Some compilers (msvc) write debug info to a separate file.
    # These args specify where it should be written.
    def get_compile_debugfile_args(self, rel_obj: str, pch: bool = False) -> T.List[str]:
        return []

    def should_link_pch_object(self) -> bool:
        return False

    def get_link_debugfile_name(self, targetfile: str) -> T.Optional[str]:
        return self.linker.get_debugfile_name(targetfile)

    def get_link_debugfile_args(self, targetfile: str) -> T.List[str]:
        return self.linker.get_debugfile_args(targetfile)

    def get_std_shared_lib_link_args(self) -> T.List[str]:
        return self.linker.get_std_shared_lib_args()

    def get_std_shared_module_link_args(self, options: 'KeyedOptionDictType') -> T.List[str]:
        return self.linker.get_std_shared_module_args(options)

    def get_link_whole_for(self, args: T.List[str]) -> T.List[str]:
        return self.linker.get_link_whole_for(args)

    def get_allow_undefined_link_args(self) -> T.List[str]:
        return self.linker.get_allow_undefined_args()

    def no_undefined_link_args(self) -> T.List[str]:
        return self.linker.no_undefined_args()

    def get_instruction_set_args(self, instruction_set: str) -> T.Optional[T.List[str]]:
        """Compiler arguments needed to enable the given instruction set.

        Return type ay be an empty list meaning nothing needed or None
        meaning the given set is not supported.
        """
        return None

    def build_rpath_args(self, env: 'Environment', build_dir: str, from_dir: str,
                         rpath_paths: T.Tuple[str, ...], build_rpath: str,
                         install_rpath: str) -> T.Tuple[T.List[str], T.Set[bytes]]:
        return self.linker.build_rpath_args(
            env, build_dir, from_dir, rpath_paths, build_rpath, install_rpath)

    def get_archive_name(self, filename: str) -> str:
        return self.linker.get_archive_name(filename)

    def get_command_to_archive_shlib(self) -> T.List[str]:
        if not self.linker:
            return []
        return self.linker.get_command_to_archive_shlib()

    def thread_flags(self, env: 'Environment') -> T.List[str]:
        return []

    def thread_link_flags(self, env: 'Environment') -> T.List[str]:
        return self.linker.thread_flags(env)

    def openmp_flags(self) -> T.List[str]:
        raise EnvironmentException('Language %s does not support OpenMP flags.' % self.get_display_language())

    def openmp_link_flags(self) -> T.List[str]:
        return self.openmp_flags()

    def language_stdlib_only_link_flags(self, env: 'Environment') -> T.List[str]:
        return []

    def gnu_symbol_visibility_args(self, vistype: str) -> T.List[str]:
        return []

    def get_win_subsystem_args(self, value: str) -> T.List[str]:
        # By default the dynamic linker is going to return an empty
        # array in case it either doesn't support Windows subsystems
        # or does not target Windows
        return self.linker.get_win_subsystem_args(value)

    def has_func_attribute(self, name: str, env: 'Environment') -> T.Tuple[bool, bool]:
        raise EnvironmentException(
            f'Language {self.get_display_language()} does not support function attributes.')

    def get_pic_args(self) -> T.List[str]:
        m = 'Language {} does not support position-independent code'
        raise EnvironmentException(m.format(self.get_display_language()))

    def get_pie_args(self) -> T.List[str]:
        m = 'Language {} does not support position-independent executable'
        raise EnvironmentException(m.format(self.get_display_language()))

    def get_pie_link_args(self) -> T.List[str]:
        return self.linker.get_pie_args()

    def get_argument_syntax(self) -> str:
        """Returns the argument family type.

        Compilers fall into families if they try to emulate the command line
        interface of another compiler. For example, clang is in the GCC family
        since it accepts most of the same arguments as GCC. ICL (ICC on
        windows) is in the MSVC family since it accepts most of the same
        arguments as MSVC.
        """
        return 'other'

    def get_profile_generate_args(self) -> T.List[str]:
        raise EnvironmentException(
            '%s does not support get_profile_generate_args ' % self.get_id())

    def get_profile_use_args(self) -> T.List[str]:
        raise EnvironmentException(
            '%s does not support get_profile_use_args ' % self.get_id())

    def remove_linkerlike_args(self, args: T.List[str]) -> T.List[str]:
        rm_exact = ('-headerpad_max_install_names',)
        rm_prefixes = ('-Wl,', '-L',)
        rm_next = ('-L', '-framework',)
        ret: T.List[str] = []
        iargs = iter(args)
        for arg in iargs:
            # Remove this argument
            if arg in rm_exact:
                continue
            # If the argument starts with this, but is not *exactly* this
            # f.ex., '-L' should match ['-Lfoo'] but not ['-L', 'foo']
            if arg.startswith(rm_prefixes) and arg not in rm_prefixes:
                continue
            # Ignore this argument and the one after it
            if arg in rm_next:
                next(iargs)
                continue
            ret.append(arg)
        return ret

    def get_lto_compile_args(self, *, threads: int = 0, mode: str = 'default') -> T.List[str]:
        return []

    def get_lto_link_args(self, *, threads: int = 0, mode: str = 'default',
                          thinlto_cache_dir: T.Optional[str] = None) -> T.List[str]:
        return self.linker.get_lto_args()

    def sanitizer_compile_args(self, value: str) -> T.List[str]:
        return []

    def sanitizer_link_args(self, value: str) -> T.List[str]:
        return self.linker.sanitizer_args(value)

    def get_asneeded_args(self) -> T.List[str]:
        return self.linker.get_asneeded_args()

    def headerpad_args(self) -> T.List[str]:
        return self.linker.headerpad_args()

    def bitcode_args(self) -> T.List[str]:
        return self.linker.bitcode_args()

    def get_optimization_link_args(self, optimization_level: str) -> T.List[str]:
        return self.linker.get_optimization_link_args(optimization_level)

    def get_soname_args(self, env: 'Environment', prefix: str, shlib_name: str,
                        suffix: str, soversion: str,
                        darwin_versions: T.Tuple[str, str]) -> T.List[str]:
        return self.linker.get_soname_args(
            env, prefix, shlib_name, suffix, soversion,
            darwin_versions)

    def get_target_link_args(self, target: 'BuildTarget') -> T.List[str]:
        return target.link_args

    def get_dependency_compile_args(self, dep: 'Dependency') -> T.List[str]:
        return dep.get_compile_args()

    def get_dependency_link_args(self, dep: 'Dependency') -> T.List[str]:
        return dep.get_link_args()

    @classmethod
    def use_linker_args(cls, linker: str, version: str) -> T.List[str]:
        """Get a list of arguments to pass to the compiler to set the linker.
        """
        return []

    def get_coverage_args(self) -> T.List[str]:
        return []

    def get_coverage_link_args(self) -> T.List[str]:
        return self.linker.get_coverage_args()

    def get_assert_args(self, disable: bool) -> T.List[str]:
        """Get arguments to enable or disable assertion.

        :param disable: Whether to disable assertions
        :return: A list of string arguments for this compiler
        """
        return []

    def get_crt_val(self, crt_val: str, buildtype: str) -> str:
        if crt_val in MSCRT_VALS:
            return crt_val
        assert crt_val in {'from_buildtype', 'static_from_buildtype'}

        dbg = 'mdd'
        rel = 'md'
        if crt_val == 'static_from_buildtype':
            dbg = 'mtd'
            rel = 'mt'

        # Match what build type flags used to do.
        if buildtype == 'plain':
            return 'none'
        elif buildtype == 'debug':
            return dbg
        elif buildtype in {'debugoptimized', 'release', 'minsize'}:
            return rel
        else:
            assert buildtype == 'custom'
            raise EnvironmentException('Requested C runtime based on buildtype, but buildtype is "custom".')

    def get_crt_compile_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        raise EnvironmentException('This compiler does not support Windows CRT selection')

    def get_crt_link_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        raise EnvironmentException('This compiler does not support Windows CRT selection')

    def get_compile_only_args(self) -> T.List[str]:
        return []

    def get_preprocess_only_args(self) -> T.List[str]:
        raise EnvironmentException('This compiler does not have a preprocessor')

    def get_preprocess_to_file_args(self) -> T.List[str]:
        return self.get_preprocess_only_args()

    def get_default_include_dirs(self) -> T.List[str]:
        # TODO: This is a candidate for returning an immutable list
        return []

    def get_largefile_args(self) -> T.List[str]:
        '''Enable transparent large-file-support for 32-bit UNIX systems'''
        if not (self.get_argument_syntax() == 'msvc' or self.info.is_darwin()):
            # Enable large-file support unconditionally on all platforms other
            # than macOS and MSVC. macOS is now 64-bit-only so it doesn't
            # need anything special, and MSVC doesn't have automatic LFS.
            # You must use the 64-bit counterparts explicitly.
            # glibc, musl, and uclibc, and all BSD libcs support this. On Android,
            # support for transparent LFS is available depending on the version of
            # Bionic: https://github.com/android/platform_bionic#32-bit-abi-bugs
            # https://code.google.com/p/android/issues/detail?id=64613
            #
            # If this breaks your code, fix it! It's been 20+ years!
            return ['-D_FILE_OFFSET_BITS=64']
            # We don't enable -D_LARGEFILE64_SOURCE since that enables
            # transitionary features and must be enabled by programs that use
            # those features explicitly.
        return []

    def get_library_dirs(self, env: 'Environment',
                         elf_class: T.Optional[int] = None) -> T.List[str]:
        return []

    def get_return_value(self,
                         fname: str,
                         rtype: str,
                         prefix: str,
                         env: 'Environment',
                         extra_args: T.Optional[T.List[str]],
                         dependencies: T.Optional[T.List['Dependency']]) -> T.Union[str, int]:
        raise EnvironmentException(f'{self.id} does not support get_return_value')

    def find_framework(self,
                       name: str,
                       env: 'Environment',
                       extra_dirs: T.List[str],
                       allow_system: bool = True) -> T.Optional[T.List[str]]:
        raise EnvironmentException(f'{self.id} does not support find_framework')

    def find_framework_paths(self, env: 'Environment') -> T.List[str]:
        raise EnvironmentException(f'{self.id} does not support find_framework_paths')

    def attribute_check_func(self, name: str) -> str:
        raise EnvironmentException(f'{self.id} does not support attribute checks')

    def get_pch_suffix(self) -> str:
        raise EnvironmentException(f'{self.id} does not support pre compiled headers')

    def get_pch_name(self, name: str) -> str:
        raise EnvironmentException(f'{self.id} does not support pre compiled headers')

    def get_pch_use_args(self, pch_dir: str, header: str) -> T.List[str]:
        raise EnvironmentException(f'{self.id} does not support pre compiled headers')

    def get_has_func_attribute_extra_args(self, name: str) -> T.List[str]:
        raise EnvironmentException(f'{self.id} does not support function attributes')

    def name_string(self) -> str:
        return ' '.join(self.exelist)

    @abc.abstractmethod
    def sanity_check(self, work_dir: str, environment: 'Environment') -> None:
        """Check that this compiler actually works.

        This should provide a simple compile/link test. Something as simple as:
        ```python
        main(): return 0
        ```
        is good enough here.
        """

    def split_shlib_to_parts(self, fname: str) -> T.Tuple[T.Optional[str], str]:
        return None, fname

    def get_dependency_gen_args(self, outtarget: str, outfile: str) -> T.List[str]:
        return []

    def get_std_exe_link_args(self) -> T.List[str]:
        # TODO: is this a linker property?
        return []

    def get_include_args(self, path: str, is_system: bool) -> T.List[str]:
        return []

    def depfile_for_object(self, objfile: str) -> T.Optional[str]:
        return objfile + '.' + self.get_depfile_suffix()

    def get_depfile_suffix(self) -> str:
        raise EnvironmentException(f'{self.id} does not implement get_depfile_suffix')

    def get_no_stdinc_args(self) -> T.List[str]:
        """Arguments to turn off default inclusion of standard libraries."""
        return []

    def get_warn_args(self, level: str) -> T.List[str]:
        return []

    def get_werror_args(self) -> T.List[str]:
        return []

    @abc.abstractmethod
    def get_optimization_args(self, optimization_level: str) -> T.List[str]:
        pass

    def get_module_incdir_args(self) -> T.Tuple[str, ...]:
        raise EnvironmentException(f'{self.id} does not implement get_module_incdir_args')

    def get_module_outdir_args(self, path: str) -> T.List[str]:
        raise EnvironmentException(f'{self.id} does not implement get_module_outdir_args')

    def module_name_to_filename(self, module_name: str) -> str:
        raise EnvironmentException(f'{self.id} does not implement module_name_to_filename')

    def get_compiler_check_args(self, mode: CompileCheckMode) -> T.List[str]:
        """Arguments to pass the compiler and/or linker for checks.

        The default implementation turns off optimizations.

        Examples of things that go here:
          - extra arguments for error checking
          - Arguments required to make the compiler exit with a non-zero status
            when something is wrong.
        """
        return self.get_no_optimization_args()

    def get_no_optimization_args(self) -> T.List[str]:
        """Arguments to the compiler to turn off all optimizations."""
        return []

    def build_wrapper_args(self, env: 'Environment',
                           extra_args: T.Union[None, CompilerArgs, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]],
                           dependencies: T.Optional[T.List['Dependency']],
                           mode: CompileCheckMode = CompileCheckMode.COMPILE) -> CompilerArgs:
        """Arguments to pass the build_wrapper helper.

        This generally needs to be set on a per-language basis. It provides
        a hook for languages to handle dependencies and extra args. The base
        implementation handles the most common cases, namely adding the
        check_arguments, unwrapping dependencies, and appending extra args.
        """
        if callable(extra_args):
            extra_args = extra_args(mode)
        if extra_args is None:
            extra_args = []
        if dependencies is None:
            dependencies = []

        # Collect compiler arguments
        args = self.compiler_args(self.get_compiler_check_args(mode))
        for d in dependencies:
            # Add compile flags needed by dependencies
            args += d.get_compile_args()
            if mode is CompileCheckMode.LINK:
                # Add link flags needed to find dependencies
                args += d.get_link_args()

        if mode is CompileCheckMode.COMPILE:
            # Add DFLAGS from the env
            args += env.coredata.get_external_args(self.for_machine, self.language)
        elif mode is CompileCheckMode.LINK:
            # Add LDFLAGS from the env
            args += env.coredata.get_external_link_args(self.for_machine, self.language)
        # extra_args must override all other arguments, so we add them last
        args += extra_args
        return args

    @contextlib.contextmanager
    def _build_wrapper(self, code: 'mesonlib.FileOrString', env: 'Environment',
                       extra_args: T.Union[None, CompilerArgs, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                       dependencies: T.Optional[T.List['Dependency']] = None,
                       mode: CompileCheckMode = CompileCheckMode.COMPILE, want_output: bool = False,
                       disable_cache: bool = False) -> T.Iterator[CompileResult]:
        """Helper for getting a cached value when possible.

        This method isn't meant to be called externally, it's mean to be
        wrapped by other methods like compiles() and links().
        """
        args = self.build_wrapper_args(env, extra_args, dependencies, mode)
        if disable_cache or want_output:
            with self.compile(code, extra_args=args, mode=mode, want_output=want_output, temp_dir=env.scratch_dir) as r:
                yield r
        else:
            with self.cached_compile(code, env.coredata, extra_args=args, mode=mode, temp_dir=env.scratch_dir) as r:
                yield r

    def compiles(self, code: 'mesonlib.FileOrString', env: 'Environment', *,
                 extra_args: T.Union[None, T.List[str], CompilerArgs, T.Callable[[CompileCheckMode], T.List[str]]] = None,
                 dependencies: T.Optional[T.List['Dependency']] = None,
                 mode: CompileCheckMode = CompileCheckMode.COMPILE,
                 disable_cache: bool = False) -> T.Tuple[bool, bool]:
        """Run a compilation or link test to see if code can be compiled/linked.

        :returns:
            A tuple of (bool, bool). The first value is whether the check
            succeeded, and the second is whether it was retrieved from a cache
        """
        with self._build_wrapper(code, env, extra_args, dependencies, mode, disable_cache=disable_cache) as p:
            return p.returncode == 0, p.cached

    def links(self, code: 'mesonlib.FileOrString', env: 'Environment', *,
              compiler: T.Optional['Compiler'] = None,
              extra_args: T.Union[None, T.List[str], CompilerArgs, T.Callable[[CompileCheckMode], T.List[str]]] = None,
              dependencies: T.Optional[T.List['Dependency']] = None,
              disable_cache: bool = False) -> T.Tuple[bool, bool]:
        if compiler:
            with compiler._build_wrapper(code, env, dependencies=dependencies, want_output=True) as r:
                objfile = mesonlib.File.from_absolute_file(r.output_name)
                return self.compiles(objfile, env, extra_args=extra_args,
                                     dependencies=dependencies, mode=CompileCheckMode.LINK, disable_cache=True)

        return self.compiles(code, env, extra_args=extra_args,
                             dependencies=dependencies, mode=CompileCheckMode.LINK, disable_cache=disable_cache)

    def get_feature_args(self, kwargs: DFeatures, build_to_src: str) -> T.List[str]:
        """Used by D for extra language features."""
        # TODO: using a TypeDict here would improve this
        raise EnvironmentException(f'{self.id} does not implement get_feature_args')

    def get_prelink_args(self, prelink_name: str, obj_list: T.List[str]) -> T.List[str]:
        raise EnvironmentException(f'{self.id} does not know how to do prelinking.')

    def rsp_file_syntax(self) -> 'RSPFileSyntax':
        """The format of the RSP file that this compiler supports.

        If `self.can_linker_accept_rsp()` returns True, then this needs to
        be implemented
        """
        return self.linker.rsp_file_syntax()

    def get_debug_args(self, is_debug: bool) -> T.List[str]:
        """Arguments required for a debug build."""
        return []

    def needs_static_linker(self) -> bool:
        raise NotImplementedError(f'There is no static linker for {self.language}')

    def get_preprocessor(self) -> Compiler:
        """Get compiler's preprocessor.
        """
        raise EnvironmentException(f'{self.get_id()} does not support preprocessor')

def get_global_options(lang: str,
                       comp: T.Type[Compiler],
                       for_machine: MachineChoice,
                       env: 'Environment') -> 'KeyedOptionDictType':
    """Retrieve options that apply to all compilers for a given language."""
    description = f'Extra arguments passed to the {lang}'
    argkey = OptionKey('args', lang=lang, machine=for_machine)
    largkey = argkey.evolve('link_args')
    envkey = argkey.evolve('env_args')

    comp_key = argkey if argkey in env.options else envkey

    comp_options = env.options.get(comp_key, [])
    link_options = env.options.get(largkey, [])

    cargs = coredata.UserArrayOption(
        f'{lang}_{argkey.name}',
        description + ' compiler',
        comp_options, split_args=True, allow_dups=True)

    largs = coredata.UserArrayOption(
        f'{lang}_{largkey.name}',
        description + ' linker',
        link_options, split_args=True, allow_dups=True)

    if comp.INVOKES_LINKER and comp_key == envkey:
        # If the compiler acts as a linker driver, and we're using the
        # environment variable flags for both the compiler and linker
        # arguments, then put the compiler flags in the linker flags as well.
        # This is how autotools works, and the env vars feature is for
        # autotools compatibility.
        largs.extend_value(comp_options)

    opts: 'KeyedOptionDictType' = {argkey: cargs, largkey: largs}

    return opts

"""


```