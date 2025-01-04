Response:
The user wants a functional summary of the provided Python code, which is a part of the Frida dynamic instrumentation tool. The code defines an abstract base class `Compiler` and includes several methods related to compiling and linking code. I need to:

1. **Identify the core functionalities** of the `Compiler` class.
2. **Explain its relevance to reverse engineering**, if any.
3. **Point out any connections to low-level concepts** like binary format, Linux/Android kernel, and frameworks.
4. **Illustrate logical reasoning** within the code with input/output examples.
5. **Highlight potential user errors**.
6. **Describe the user journey** leading to this code.
7. **Provide a concise overall summary**.

**Breakdown of the code's functionalities:**

* **Compilation and Linking:**  The class provides methods to compile source code (`compile`, `cached_compile`) and link object files. It also manages temporary directories during compilation.
* **Compiler Arguments Handling:** Methods like `get_compiler_args_for_mode`, `get_output_args`, and `compiler_args` deal with constructing the command-line arguments for the compiler.
* **Dependency Management:** Methods like `get_dependency_compile_args` and `get_dependency_link_args` handle arguments related to dependencies.
* **Platform-Specific Adjustments:** Methods like `get_largefile_args`, `get_win_subsystem_args`, and `build_rpath_args` suggest handling of platform-specific compilation and linking requirements.
* **Debugging Information:** Methods like `get_compile_debugfile_args` and `get_link_debugfile_args` are related to generating and managing debugging information.
* **Library Handling:** Methods for handling shared libraries (`get_std_shared_lib_link_args`) and static libraries (`get_archive_name`).
* **Code Analysis and Optimization:** Methods related to LTO (`get_lto_compile_args`, `get_lto_link_args`), sanitizers (`sanitizer_compile_args`, `sanitizer_link_args`), and optimization levels (`get_optimization_args`, `get_optimization_link_args`).
* **Error Handling and Checks:** Methods for performing sanity checks (`sanity_check`) and compiler feature checks (`compiles`, `links`).
* **Customization and Extensibility:** The abstract nature of the class and methods like `get_feature_args` indicate a design that allows for customization and extension for different compilers and languages.

**Connections to reverse engineering:** Frida is a dynamic instrumentation toolkit used extensively in reverse engineering. This `Compiler` class is a foundational component for building and linking Frida gadgets or agents that are injected into target processes.

**Low-level considerations:** The code deals with object files, executables, shared libraries (binary formats), interacts with the operating system to execute compiler commands, and has methods specific to Linux and potentially Android (e.g., `build_rpath_args`).

**Logical reasoning:** The `cached_compile` method demonstrates caching logic to avoid redundant compilations. It checks if a compilation result exists in the cache based on a key derived from compiler details, code, and arguments.

**User errors:** Incorrectly specifying compiler arguments or dependencies could lead to compilation or linking failures.

**User journey:** A user would interact with this code indirectly through Frida's build system (Meson). When building a Frida gadget or agent, Meson would use this `Compiler` class (or its concrete implementations) to compile the source code.
这是 `frida/releng/meson/mesonbuild/compilers/compilers.py` 文件的第二部分，延续了第一部分定义的 `Compiler` 抽象基类。我们来归纳一下这部分的功能：

**核心功能归纳：**

1. **代码编译和链接的辅助管理:**  这部分代码继续定义了用于编译和链接代码的通用接口，涵盖了各种编译和链接选项的设置和管理。它为不同的编译器实现提供了一个统一的抽象层。

2. **编译结果缓存:** `cached_compile` 方法实现了编译结果的缓存机制，通过键值对存储编译结果，避免重复编译，提升构建效率。

3. **颜色输出控制:** `get_colorout_args` 方法用于获取控制编译器输出颜色的参数。

4. **调试信息处理:**  定义了获取编译和链接时生成调试信息文件的参数的方法 (`get_compile_debugfile_args`, `get_link_debugfile_args`, `get_link_debugfile_name`)。

5. **共享库和模块链接:** 提供了获取标准共享库和共享模块链接参数的方法 (`get_std_shared_lib_link_args`, `get_std_shared_module_link_args`)。

6. **链接时包含整个静态库:** `get_link_whole_for` 方法用于获取将整个静态库链接进目标文件的参数。

7. **允许未定义符号链接:** `get_allow_undefined_link_args` 和 `no_undefined_link_args` 用于获取允许或禁止未定义符号的链接参数。

8. **指令集支持:** `get_instruction_set_args` 尝试获取启用特定指令集的编译器参数。

9. **运行时库路径 (RPath) 处理:** `build_rpath_args` 方法用于构建 RPath 参数，指定运行时库的查找路径。

10. **静态库归档:**  `get_archive_name` 和 `get_command_to_archive_shlib` 涉及静态库的命名和共享库的归档。

11. **线程和 OpenMP 支持:** `thread_flags`, `thread_link_flags`, `openmp_flags`, `openmp_link_flags` 用于获取线程和 OpenMP 相关的编译和链接参数。

12. **符号可见性控制:** `gnu_symbol_visibility_args` 用于获取控制 GNU 符号可见性的参数。

13. **Windows 子系统配置:** `get_win_subsystem_args` 用于获取配置 Windows 子系统的参数。

14. **函数属性检查:** `has_func_attribute` 方法用于检查编译器是否支持特定的函数属性。

15. **位置无关代码 (PIC) 和位置无关可执行文件 (PIE) 支持:** `get_pic_args` 和 `get_pie_args` 用于获取生成 PIC 和 PIE 代码的参数，`get_pie_link_args` 用于获取链接 PIE 的参数。

16. **编译器参数语法类型:** `get_argument_syntax` 返回编译器的参数语法类型（例如，GCC 或 MSVC）。

17. **性能剖析支持:** `get_profile_generate_args` 和 `get_profile_use_args` 用于获取性能剖析相关的编译和链接参数。

18. **移除链接器风格的参数:** `remove_linkerlike_args` 用于移除编译器参数列表中可能传递给链接器的参数。

19. **链接时优化 (LTO) 支持:** `get_lto_compile_args` 和 `get_lto_link_args` 用于获取 LTO 相关的编译和链接参数。

20. **代码清理器 (Sanitizer) 支持:** `sanitizer_compile_args` 和 `sanitizer_link_args` 用于获取启用代码清理器的编译和链接参数。

21. **按需链接 (`-as-needed`) 支持:** `get_asneeded_args` 用于获取按需链接的参数。

22. **Header Padding:** `headerpad_args` 用于获取 header padding 相关的参数。

23. **Bitcode 支持:** `bitcode_args` 用于获取 bitcode 相关的链接参数。

24. **优化级别链接参数:** `get_optimization_link_args` 用于获取特定优化级别的链接参数。

25. **共享库命名约定 (Soname):** `get_soname_args` 用于生成共享库的 Soname 参数。

26. **目标特定的链接参数:** `get_target_link_args` 用于获取特定构建目标的链接参数。

27. **依赖项的编译和链接参数:** `get_dependency_compile_args` 和 `get_dependency_link_args` 用于获取依赖项需要的编译和链接参数。

28. **指定链接器:** `use_linker_args` 用于获取指定特定链接器的编译器参数。

29. **代码覆盖率支持:** `get_coverage_args` 和 `get_coverage_link_args` 用于获取代码覆盖率相关的编译和链接参数。

30. **断言控制:** `get_assert_args` 用于获取启用或禁用断言的参数。

31. **C 运行时库 (CRT) 选择:** `get_crt_val`, `get_crt_compile_args`, `get_crt_link_args` 涉及选择和配置 Windows C 运行时库。

32. **仅编译和预处理参数:** `get_compile_only_args` 和 `get_preprocess_only_args` 用于获取仅编译和仅预处理的参数。

33. **预处理到文件:** `get_preprocess_to_file_args` 用于获取将预处理结果输出到文件的参数。

34. **默认包含目录:** `get_default_include_dirs` 返回编译器默认的头文件搜索路径。

35. **大文件支持:** `get_largefile_args` 用于启用 32 位 UNIX 系统上的透明大文件支持。

36. **库目录:** `get_library_dirs` 返回链接器搜索库文件的目录。

37. **获取函数返回值:** `get_return_value` 用于在编译时获取函数的返回值（可能用于编译时计算）。

38. **查找 Framework (macOS):** `find_framework` 和 `find_framework_paths` 用于查找 macOS 的 Framework。

39. **属性检查函数:** `attribute_check_func` 用于生成检查特定属性是否支持的代码。

40. **预编译头文件 (PCH) 支持:**  `get_pch_suffix`, `get_pch_name`, `get_pch_use_args`, `get_has_func_attribute_extra_args` 涉及预编译头文件的处理。

41. **编译器名称字符串:** `name_string` 返回编译器的名称字符串。

42. **健全性检查:** `sanity_check` 是一个抽象方法，要求子类实现编译器的基本功能测试。

43. **拆分共享库名称:** `split_shlib_to_parts` 用于将共享库文件名拆分成不同的部分。

44. **生成依赖关系文件参数:** `get_dependency_gen_args` 用于获取生成依赖关系文件的参数。

45. **标准可执行文件链接参数:** `get_std_exe_link_args` 用于获取标准可执行文件的链接参数。

46. **包含目录参数:** `get_include_args` 用于获取指定包含目录的参数。

47. **依赖关系文件后缀:** `depfile_for_object` 和 `get_depfile_suffix` 用于处理依赖关系文件。

48. **禁用标准包含路径:** `get_no_stdinc_args` 用于获取禁用标准库包含路径的参数。

49. **警告级别参数:** `get_warn_args` 用于设置编译器的警告级别。

50. **将警告视为错误:** `get_werror_args` 用于获取将警告视为错误的参数。

51. **优化级别参数:** `get_optimization_args` 是一个抽象方法，要求子类实现获取特定优化级别的编译参数。

52. **模块包含和输出目录参数:** `get_module_incdir_args` 和 `get_module_outdir_args` 涉及模块化编译。

53. **模块名到文件名转换:** `module_name_to_filename` 用于将模块名转换为文件名。

54. **编译器检查参数:** `get_compiler_check_args` 用于获取用于编译器功能检查的参数。

55. **禁用优化参数:** `get_no_optimization_args` 用于获取禁用所有优化的参数。

56. **构建包装器参数:** `build_wrapper_args` 用于获取传递给构建包装器的参数，用于处理依赖项和额外参数。

57. **编译和链接检查:** `compiles` 和 `links` 方法用于执行编译和链接测试，并返回结果和是否使用了缓存。

58. **D 语言特性参数:** `get_feature_args` 用于获取 D 语言特定特性的参数。

59. **预链接参数:** `get_prelink_args` 用于获取预链接的参数。

60. **响应文件语法:** `rsp_file_syntax` 返回编译器支持的响应文件语法。

61. **调试构建参数:** `get_debug_args` 用于获取调试构建所需的参数。

62. **是否需要静态链接器:** `needs_static_linker` 指示是否需要静态链接器。

63. **获取预处理器:** `get_preprocessor` 用于获取编译器的预处理器实例。

64. **获取全局选项:** `get_global_options` 函数用于获取适用于特定语言的所有编译器的全局选项。

**与逆向方法的关联举例说明：**

* **编译 Frida Gadget/Agent:** 在逆向工程中，使用 Frida 时，需要编译用 C/C++ 等语言编写的 Gadget 或 Agent 代码，这些代码会被注入到目标进程中。`Compiler` 类的实例负责执行这个编译过程，例如使用 `compile` 方法编译 Agent 的源代码。
* **代码注入前的准备:**  逆向工程师可能需要编译一些辅助工具或库，以便在注入到目标进程前进行一些预处理或分析。`Compiler` 类提供的功能可以用来编译这些工具。
* **动态库的构建:**  Frida 经常需要操作或加载动态链接库。`get_std_shared_lib_link_args` 等方法用于生成正确的动态库链接参数。

**涉及二进制底层、Linux、Android 内核及框架的知识的举例说明：**

* **二进制底层：**
    * `get_output_args`:  生成的输出文件名（`.o` 或 `.exe`）直接对应编译后的目标文件和可执行文件，这是二进制文件的一种形式。
    * `get_link_debugfile_args`: 涉及生成 `.pdb` (Windows) 或 `.dwo` (Linux) 等调试信息文件，这些文件包含用于调试二进制代码的符号信息。
    * `build_rpath_args`: RPath 是 Linux 等系统上指定动态链接库加载路径的一种机制，直接影响二进制文件的加载和执行。
* **Linux 内核：**
    * `get_largefile_args`: 涉及到 Linux 系统上对大于 2GB 的文件进行操作的支持。
    * `build_rpath_args`:  RPath 是 Linux 系统特性。
* **Android 内核及框架：**
    * 虽然代码没有显式提及 Android 特有的方法，但作为 Frida 的一部分，其编译工具链需要支持 Android 平台的编译。例如，交叉编译到 ARM 架构时，会涉及到不同的编译器选项和链接参数。`get_instruction_set_args` 可以用于指定 ARM 指令集。
    * `build_rpath_args` 在 Android 上也有类似的用途，尽管 Android 有其独特的动态库加载机制。

**逻辑推理的假设输入与输出举例：**

假设输入以下代码字符串和编译模式：

```python
code = 'int main() { return 0; }'
mode = CompileCheckMode.LINK
```

调用 `compile` 方法：

```python
with compiler.compile(code, mode=mode) as result:
    # ... 处理 result
    pass
```

**假设输出：**

* `result.returncode`: 0 (假设编译链接成功)
* `result.stdout`:  编译器和链接器的标准输出信息，可能包含版本信息、警告等。
* `result.stderr`:  编译器和链接器的标准错误信息，如果成功则为空。
* `result.command`:  一个列表，包含了实际执行的编译器和链接器命令，例如 `['gcc', 'testfile.c', '-o', 'output.exe']`（具体命令取决于编译器）。
* `result.output_name`:  `os.path.join(tmpdirname, 'output.exe')` (可执行文件的路径)。

**涉及用户或者编程常见的使用错误举例说明：**

* **未安装编译器:** 如果用户尝试构建 Frida 组件，但系统中没有安装相应的编译器（例如 GCC 或 Clang），`sanity_check` 方法会失败，导致构建过程出错。
* **错误的编译选项:** 用户可能在 Meson 的配置文件中传递了错误的编译选项，导致 `get_compiler_args_for_mode` 等方法生成的命令不正确，最终导致编译失败。例如，传递了目标架构不支持的优化选项。
* **依赖项缺失:** 如果用户编写的代码依赖于某个外部库，但在构建时没有正确指定依赖项，`get_dependency_compile_args` 和 `get_dependency_link_args` 无法获取到正确的参数，导致链接失败。
* **CRT 选择错误 (Windows):**  如果在 Windows 上构建，用户可能错误地配置了 C 运行时库 (`crt_val`)，导致链接时出现 CRT 版本不匹配的错误。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida 或基于 Frida 的项目:** 用户可能执行了 `meson build` 和 `ninja` 命令来构建 Frida 核心库或者使用 Frida 的项目（例如编写了一个 Frida Agent）。
2. **Meson 解析构建配置:** Meson 读取 `meson.build` 文件，确定需要编译哪些源代码文件，以及需要哪些编译选项和依赖项。
3. **Meson 调用相应的编译器:**  对于需要编译的 C/C++ 代码，Meson 会根据配置选择合适的编译器（例如 GCC、Clang 或 MSVC）。
4. **实例化 `Compiler` 子类:** Meson 会实例化与所选编译器对应的 `Compiler` 子类（例如 `GnuCCompiler`, `ClangCCompiler`, `MsvcCompiler`）。
5. **调用 `Compiler` 的方法:**  在编译和链接过程中，Meson 会调用 `Compiler` 实例的各种方法，例如：
    * `get_exelist()`: 获取编译器可执行文件的路径。
    * `get_compiler_args_for_mode()`: 获取特定编译模式的参数。
    * `compile()` 或 `cached_compile()`: 执行实际的编译或链接操作。
    * `get_output_args()`: 获取输出文件名的参数。
6. **如果出现编译错误:** 用户可能会看到 `ninja` 报错，并显示编译器输出的错误信息。为了调试，用户可以查看 `build.ninja` 文件，了解 Meson 生成的具体编译命令。这时，理解 `compilers.py` 中各个方法的作用，特别是那些生成编译器参数的方法，可以帮助用户分析问题所在。例如，检查生成的命令是否包含了预期的头文件搜索路径、链接库路径或特定的宏定义。

总而言之，这部分代码定义了一个抽象的编译器接口，包含了各种编译和链接所需的参数管理和操作，是 Frida 构建系统的核心组件，用于将源代码转换为可执行的二进制文件。理解这部分代码对于调试 Frida 构建过程中的编译和链接问题至关重要。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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