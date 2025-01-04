Response:
The user wants a summary of the functionality of the provided Python code snippet, which is part of the `frida-gum` project. I need to identify the key responsibilities of the `Compiler` class and its methods. Since this is the second part of the analysis, I should also consider the context from the first part (though not explicitly provided here).

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The code defines a `Compiler` base class, suggesting it's designed to handle interactions with various compilers.

2. **Analyze the methods:**  Go through the methods and categorize their functionalities:
    * **Compilation:** Methods like `compile`, `cached_compile`, `compiles`, `links`.
    * **Argument Generation:**  Methods starting with `get_` related to compiler and linker flags (e.g., `get_compiler_args_for_mode`, `get_output_args`, `get_pic_args`, `get_link_args`).
    * **Path and Naming:** Methods for handling output file names, debug files, archive names (e.g., `_get_compile_output`, `get_archive_name`, `get_link_debugfile_name`).
    * **Platform/Architecture Specifics:** Methods dealing with instruction sets, RPATH, Windows subsystems (e.g., `get_instruction_set_args`, `build_rpath_args`, `get_win_subsystem_args`).
    * **Linking:** Many methods related to linker flags and behavior (as seen above, and also `get_std_shared_lib_link_args`, `get_link_whole_for`).
    * **Dependency Management:** Methods for handling dependencies' compile and link arguments (e.g., `get_dependency_compile_args`, `get_dependency_link_args`).
    * **Error Handling and Sanity Checks:**  `sanity_check`.
    * **Special Features:** Methods related to LTO, sanitizers, coverage, precompiled headers (e.g., `get_lto_compile_args`, `sanitizer_compile_args`, `get_coverage_args`, methods related to `pch`).
    * **Abstraction and Extensibility:**  Abstract methods (`@abc.abstractmethod`) indicate that subclasses will implement specific compiler behaviors.

3. **Relate to reverse engineering:** Think about how these functionalities are relevant to reverse engineering. Compilers are fundamental to creating the binaries that are then analyzed in reverse engineering. Understanding compiler flags and how they affect the output is crucial.

4. **Relate to low-level concepts:**  Consider aspects related to binary structure, operating systems (Linux, Android), and kernel/framework interactions. Linker flags, RPATH, shared libraries, and debugging symbols are relevant here.

5. **Identify logical reasoning:** Look for conditional logic or decision-making within the methods. The `cached_compile` method is a good example of logic based on cache status.

6. **Identify potential user errors:** Consider how a user might misuse the API or provide incorrect inputs, leading to errors.

7. **Trace user actions:**  Think about the high-level steps a user would take in the `frida` context that would eventually lead to this code being executed. This usually involves configuring the build system.

8. **Synthesize the findings:**  Combine the analysis into a concise summary of the class's purpose and key functions.

**Self-Correction/Refinement:**

* **Focus on Functionality:** Ensure the summary emphasizes *what* the code does rather than just listing methods.
* **Clarity and Conciseness:**  Use clear language and avoid jargon where possible.
* **Examples:** Provide concrete examples to illustrate the connections to reverse engineering and low-level concepts.
* **Address all prompts:** Make sure the summary covers all aspects requested by the user (functionality, reverse engineering, low-level knowledge, logic, user errors, user actions).
* **Context from Part 1:** While not provided, remember that this is part 2. The summary should ideally build upon the understanding of the overall system gained from part 1. If part 1 focused on the setup or initial parsing, part 2 delves into the actual compilation process.

By following these steps, I can create a comprehensive and accurate summary of the provided code snippet.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/compilers.py` 文件 `Compiler` 类的剩余部分，主要负责定义了编译器操作的通用接口和一些默认实现。结合前一部分的内容，我们可以归纳一下它的功能：

**`Compiler` 类的主要功能归纳：**

总的来说，`Compiler` 类在 Meson 构建系统中扮演着**编译器抽象层**的角色。它定义了一组方法，用于描述和执行与各种编程语言编译器相关的操作，使得 Meson 的构建逻辑可以独立于特定的编译器实现。

**核心功能点：**

1. **编译和链接流程管理：**
   - 提供 `compile` 和 `cached_compile` 方法来执行代码的编译和链接过程，并支持缓存以提高效率。
   - `compiles` 和 `links` 方法是对 `_build_wrapper` 的高层封装，用于检查代码是否能成功编译或链接。
   - `_build_wrapper` 方法用于处理编译/链接前的准备工作，例如添加编译选项、处理依赖等。

2. **编译器和链接器参数管理：**
   - 提供了大量的 `get_` 开头的方法，用于生成特定编译器或链接器所需的命令行参数。这些参数涵盖了编译模式、输出路径、调试信息、优化级别、头文件路径、库文件路径、链接选项（如共享库、模块、静态库）、指令集、链接时的 whole archive、允许未定义符号、位置无关代码（PIC/PIE）、链接时优化（LTO）、代码清理器（sanitizer）、覆盖率测试、断言控制等等。
   - `get_compiler_args_for_mode` 根据编译模式（编译、预处理、链接）返回相应的编译器参数。
   - `compiler_args` 方法返回一个 `CompilerArgs` 对象，用于更方便地管理编译器参数。

3. **平台和架构特定支持：**
   - 包含处理不同操作系统和处理器架构的参数生成逻辑，例如 Windows 子系统 (`get_win_subsystem_args`)、指令集 (`get_instruction_set_args`)、大型文件支持 (`get_largefile_args`)。
   - `build_rpath_args` 方法用于生成设置运行时库搜索路径（RPATH）的参数。

4. **依赖管理：**
   - `get_dependency_compile_args` 和 `get_dependency_link_args` 方法用于获取依赖项所需的编译和链接参数。

5. **代码检查和属性支持：**
   - `has_func_attribute` 方法用于检查编译器是否支持特定的函数属性。
   - `attribute_check_func` 用于生成检查属性的特定代码片段。

6. **预编译头文件（PCH）支持：**
   - 提供了 `get_pch_suffix`, `get_pch_name`, `get_pch_use_args` 等方法来处理预编译头文件的相关操作。

7. **模块化编译支持：**
   - `get_module_incdir_args`, `get_module_outdir_args`, `module_name_to_filename` 等方法用于处理模块化编译的相关参数和命名。

8. **构建包装器（Build Wrapper）集成：**
   - `build_wrapper_args` 和 `_build_wrapper` 方法用于集成构建包装器，以便在编译过程中执行额外的操作，例如静态分析或代码覆盖率分析。

9. **静态链接器处理：**
   - `needs_static_linker` 方法用于指示是否需要静态链接器。

10. **预处理器访问：**
    - `get_preprocessor` 方法用于获取编译器的预处理器对象。

11. **其他实用功能：**
    - `get_colorout_args` 用于获取控制彩色输出的参数。
    - `get_archive_name` 用于获取静态库的文件名。
    - `thread_flags` 和 `thread_link_flags` 用于获取线程相关的编译和链接参数。
    - `openmp_flags` 和 `openmp_link_flags` 用于获取 OpenMP 相关的编译和链接参数。
    - `gnu_symbol_visibility_args` 用于设置 GNU 符号可见性。
    - `get_profile_generate_args` 和 `get_profile_use_args` 用于获取性能分析相关的参数。
    - `remove_linkerlike_args` 用于移除类似链接器的参数。
    - `get_lto_compile_args` 和 `get_lto_link_args` 用于获取链接时优化相关的参数。
    - `sanitizer_compile_args` 和 `sanitizer_link_args` 用于获取代码清理器相关的参数。
    - `get_asneeded_args` 用于获取按需链接的参数。
    - `headerpad_args` 用于处理头文件填充。
    - `bitcode_args` 用于获取生成 bitcode 的参数。
    - `get_optimization_link_args` 用于获取链接时的优化参数。
    - `get_soname_args` 用于生成共享库的 soname。
    - `get_target_link_args` 用于获取目标特定的链接参数。
    - `get_coverage_args` 和 `get_coverage_link_args` 用于获取代码覆盖率测试相关的参数。
    - `get_assert_args` 用于控制断言的启用或禁用。
    - `get_crt_compile_args` 和 `get_crt_link_args` 用于处理 Windows CRT 链接。
    - `get_compile_only_args` 和 `get_preprocess_only_args` 用于获取只编译或只预处理的参数。
    - `get_default_include_dirs` 用于获取默认的头文件搜索路径。
    - `get_largefile_args` 用于启用大文件支持。
    - `get_library_dirs` 用于获取库文件搜索路径。
    - `get_return_value` 用于编译并运行代码片段以获取返回值（通常用于特性检测）。
    - `find_framework` 和 `find_framework_paths` 用于查找框架（macOS）。
    - `sanity_check` 是一个抽象方法，要求子类实现用于检查编译器是否正常工作的基本测试。
    - `split_shlib_to_parts` 用于将共享库文件名拆分成前缀和实际文件名。
    - `get_dependency_gen_args` 用于获取生成依赖文件的参数。
    - `get_std_exe_link_args` 和 `get_std_shared_lib_link_args` 用于获取标准可执行文件和共享库的链接参数。
    - `get_include_args` 用于生成包含头文件的参数。
    - `depfile_for_object` 和 `get_depfile_suffix` 用于处理依赖文件。
    - `get_no_stdinc_args` 用于禁用标准库头文件的包含。
    - `get_warn_args` 和 `get_werror_args` 用于控制编译器警告。
    - `get_optimization_args` 是一个抽象方法，用于获取优化级别的参数。
    - `get_compiler_check_args` 和 `get_no_optimization_args` 用于获取编译器检查和禁用优化相关的参数。
    - `get_feature_args` 用于获取特定语言特性的参数。
    - `get_prelink_args` 用于获取预链接的参数。
    - `rsp_file_syntax` 用于获取响应文件语法。
    - `get_debug_args` 用于获取调试构建所需的参数。

**与逆向方法的关联举例：**

* **编译器优化参数 (`get_optimization_args`)**: 逆向工程师需要了解不同优化级别如何影响生成的二进制代码。例如，`-O0` 通常会生成更容易理解的未优化的代码，而 `-O2` 或 `-O3` 会启用各种优化，使得代码更难分析。通过了解这些参数，逆向工程师可以更好地理解目标二进制的生成过程。
* **调试信息参数 (`get_debug_args`, `get_compile_debugfile_args`, `get_link_debugfile_args`)**: 编译器生成的调试信息（例如 DWARF）对于逆向工程至关重要。这些方法控制着调试信息的生成方式和位置，逆向工具（如 GDB）会利用这些信息进行符号解析、断点设置等。
* **位置无关代码参数 (`get_pic_args`, `get_pie_args`, `get_pie_link_args`)**: 了解目标二进制是否使用了 PIC/PIE 对于理解其加载和执行方式至关重要。PIC 代码可以加载到内存的任意位置，常用于共享库，而 PIE 可执行文件可以提高安全性，防止某些类型的漏洞利用。
* **链接器参数 (`get_std_shared_lib_link_args`, `get_link_whole_for`, `get_allow_undefined_link_args`)**: 链接器将不同的目标文件和库文件组合成最终的可执行文件或库文件。逆向工程师需要了解链接过程，例如库的加载顺序、静态链接与动态链接的区别，以及如何处理未定义的符号。`get_link_whole_for` 强制链接静态库中的所有目标文件，这在某些逆向场景下可能需要关注。
* **符号可见性参数 (`gnu_symbol_visibility_args`)**: 这些参数控制着哪些符号（函数、变量等）在共享库中是可见的。逆向工程师需要知道哪些符号可以被外部访问，哪些是内部使用的。

**涉及二进制底层、Linux, Android 内核及框架的知识举例：**

* **链接器参数 (`get_std_shared_lib_link_args`, `build_rpath_args`)**:  共享库的链接和加载是操作系统层面的概念。Linux 和 Android 都使用动态链接器来加载共享库。`build_rpath_args` 生成的 RPATH 信息直接影响着动态链接器在运行时查找共享库的路径，这是理解 Linux 和 Android 系统库加载机制的关键。
* **位置无关代码 (`get_pic_args`)**:  PIC 是在共享库中使用的重要技术，它允许共享库加载到内存的任意地址，而无需修改代码段。这涉及到操作系统内存管理和加载器的知识。
* **Windows 子系统参数 (`get_win_subsystem_args`)**:  这个方法用于指定 Windows 可执行文件的子系统（例如控制台程序或 GUI 程序）。这与 Windows PE 文件格式和操作系统加载器的行为有关。
* **大型文件支持 (`get_largefile_args`)**:  在 32 位 Linux 系统中，处理大于 2GB 的文件需要特殊的编译选项。这涉及到文件系统的底层结构和系统调用。
* **线程相关的参数 (`thread_flags`, `thread_link_flags`)**: 多线程是现代操作系统的重要特性。这些参数涉及到线程库的使用，例如 POSIX 线程（pthreads）。
* **代码覆盖率测试 (`get_coverage_args`, `get_coverage_link_args`)**: 代码覆盖率工具通常需要编译器和链接器的支持来生成用于分析的代码。这涉及到编译器插桩和二进制代码的修改。
* **预链接 (`get_prelink_args`)**: 预链接是一种优化技术，在打包时预先解析库的地址，减少加载时间。这涉及到操作系统加载器的优化。

**逻辑推理的假设输入与输出举例：**

假设输入 `mode` 为 `CompileCheckMode.COMPILE`，那么 `get_compiler_args_for_mode` 方法的输出将包含仅用于编译阶段的参数，例如 `-c`（对于 GCC/Clang）。如果 `mode` 为 `CompileCheckMode.LINK`，则输出将包含链接阶段的参数，例如指定输出文件名的参数。

假设用户调用 `compiles` 方法，传入一段简单的 C 代码字符串 `"int main() { return 0; }" `，并且没有提供额外的参数，那么 `_build_wrapper` 方法会构造一个包含默认编译器执行命令的列表，例如 `['gcc', 'testfile.c', '-o', 'output']`。如果编译成功，`compiles` 方法返回 `(True, False)` (假设没有缓存命中)。如果编译失败，返回 `(False, False)`。

**涉及用户或编程常见的使用错误举例：**

* **未安装编译器：** 用户在没有安装所选编程语言的编译器的情况下尝试构建项目，会导致 `sanity_check` 失败，或者在调用 `compile` 时找不到编译器可执行文件。
* **配置错误的编译器路径：** 用户可能在 Meson 的配置文件中指定了错误的编译器路径，导致 Meson 无法找到正确的编译器。
* **传递了不兼容的编译器参数：** 用户可能通过 `extra_args` 传递了当前编译器不支持的参数，导致编译失败。例如，将 GCC 特有的参数传递给 MSVC 编译器。
* **依赖项缺失：** 如果代码依赖于某个库，但该库没有被正确安装或配置，链接阶段会失败。
* **头文件或库文件路径错误：** 用户可能没有正确设置头文件或库文件的搜索路径，导致编译器或链接器找不到所需的头文件或库文件。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户运行 `meson setup builddir` 命令配置构建系统。** Meson 会读取 `meson.build` 文件，解析项目结构和构建需求。
2. **Meson 根据项目配置，确定需要使用的编程语言和对应的编译器。** 这可能涉及到读取环境变量、查找系统中的编译器等操作。
3. **在处理编译目标时，Meson 会创建 `Compiler` 类的实例。**  具体的编译器类（例如 `GccCompiler`, `ClangCompiler`, `MsvcCompiler`）会继承自 `Compiler` 基类。
4. **Meson 调用 `Compiler` 实例的方法来执行编译和链接操作。** 例如，当需要编译一个源文件时，会调用 `compile` 方法；当需要检查代码是否可以编译时，会调用 `compiles` 方法。
5. **在这些方法内部，会调用各种 `get_` 开头的方法来生成特定的编译器和链接器参数。** 例如，根据目标平台的架构和构建类型，调用 `get_pic_args` 或 `get_debug_args`。
6. **`_build_wrapper` 方法会被调用，处理编译前的准备工作，例如添加依赖项的编译选项。**
7. **最终，会调用底层的进程执行函数（如 `Popen_safe_logged`）来执行编译器命令。**

作为调试线索，如果用户遇到编译错误，可以：

* **检查 Meson 的配置输出：** 查看 Meson 是否找到了正确的编译器。
* **查看详细的编译命令：** Meson 通常会输出实际执行的编译器命令，可以从中分析参数是否正确。
* **使用 `-v` 或 `--verbose` 选项运行 Meson：** 这会提供更详细的构建日志，包括编译器调用的详细信息。
* **检查环境变量：**  某些编译器的行为会受到环境变量的影响。
* **查看 `meson.build` 文件：** 确认是否正确配置了编译选项和依赖项。

总而言之，`frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/compilers.py` 中的 `Compiler` 类是 Meson 构建系统的核心组件之一，它抽象了不同编译器的操作，使得 Meson 能够跨平台和跨编译器工作。 理解这个类的功能对于理解 Meson 的构建流程至关重要，并且有助于调试构建问题，尤其是在涉及到逆向工程、底层系统和特定平台特性时。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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