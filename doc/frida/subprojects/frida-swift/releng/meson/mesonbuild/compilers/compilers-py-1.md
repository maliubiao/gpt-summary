Response:
The user wants a summary of the functionalities of the provided Python code. I need to go through the code and identify the main purposes of the classes and methods, particularly focusing on their role in the context of reverse engineering, interaction with binary/low-level details, Linux/Android kernel/framework knowledge, logical reasoning, common user errors, and how a user's actions might lead to this code being executed.

**Plan:**

1. **Identify the Core Class:** The main class appears to be `Compiler`.
2. **Analyze Key Methods:** Examine the methods within the `Compiler` class to understand their individual functions.
3. **Relate to Reverse Engineering:** Look for methods that suggest interaction with compiled code, linking, or debugging information, which are relevant to reverse engineering.
4. **Identify Low-Level/Kernel Interaction:** Search for methods dealing with architecture-specific arguments, linking, or operating system-specific features.
5. **Detect Logical Reasoning:** Look for methods that involve decision-making or conditional logic based on inputs.
6. **Pinpoint Potential User Errors:** Consider how incorrect usage of the compiler or its options might manifest in this code.
7. **Trace User Operations:**  Think about the typical steps a user might take that would involve compiling code using Frida, which would trigger this code.
8. **Synthesize and Summarize:**  Combine the findings into a concise summary addressing all the user's points.
这是 `frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/compilers.py` 文件的第二部分源代码，主要定义了 `Compiler` 抽象基类及其相关辅助功能。结合第一部分的内容，我们可以归纳一下它的功能：

**核心功能：抽象编译器接口**

`Compiler` 类定义了一个抽象接口，用于表示各种编程语言的编译器。它的主要目的是提供一套通用的方法，让构建系统（Meson）能够与不同的编译器进行交互，而无需关心底层的编译器细节。

**具体功能点：**

1. **编译和链接控制：**
   - `compile()` 和 `cached_compile()` 方法用于执行代码的编译和链接过程，支持缓存以提高效率。
   - `get_compiler_args_for_mode()`、`get_output_args()` 等方法用于生成特定编译阶段所需的命令行参数（如编译、预处理、链接）。
   - `get_compile_only_args()`、`get_preprocess_only_args()` 等方法用于获取特定编译步骤的参数。
   - `get_std_shared_lib_link_args()`、`get_std_shared_module_link_args()` 等方法获取标准库链接参数。

2. **编译器特性支持查询：**
   - `has_func_attribute()` 用于检查编译器是否支持特定的函数属性。
   - `get_instruction_set_args()` 用于获取启用特定指令集所需的编译器参数。
   - 提供了检查编译器是否支持 OpenMP、LTO (Link-Time Optimization)、代码清理器 (Sanitizer) 等特性的方法。

3. **调试信息处理：**
   - `get_compile_debugfile_args()` 和 `get_link_debugfile_args()` 用于获取生成调试信息文件的参数。
   - `get_link_debugfile_name()` 用于获取调试信息文件的名称。
   - `get_debug_args()` 用于获取调试构建所需的参数。

4. **依赖管理：**
   - `get_dependency_compile_args()` 和 `get_dependency_link_args()` 用于获取依赖项的编译和链接参数。

5. **库文件处理：**
   - `get_archive_name()` 用于获取静态库的名称。
   - `get_soname_args()` 用于获取共享库的 SONAME 参数。
   - `split_shlib_to_parts()` 用于将共享库文件名拆分成不同的部分。

6. **平台和架构特定处理：**
   - `get_largefile_args()` 用于处理 32 位 UNIX 系统上的大文件支持。
   - `get_win_subsystem_args()` 用于获取 Windows 子系统相关的参数。
   - `build_rpath_args()` 用于构建 RPATH 信息，用于运行时库查找。

7. **错误和警告控制：**
   - `get_warn_args()` 用于设置警告级别。
   - `get_werror_args()` 用于将警告视为错误。
   - `get_assert_args()` 用于启用或禁用断言。

8. **预编译头文件 (PCH) 支持：**
   - 提供了与预编译头文件相关的 `get_pch_suffix()`、`get_pch_name()`、`get_pch_use_args()` 等方法。

9. **代码生成和优化：**
   - `get_optimization_args()` 和 `get_optimization_link_args()` 用于获取优化相关的参数。
   - `get_profile_generate_args()` 和 `get_profile_use_args()` 用于获取性能分析相关的参数。

10. **C 运行时库 (CRT) 选择：**
    - 提供了 `get_crt_compile_args()` 和 `get_crt_link_args()` 用于选择不同的 C 运行时库。

11. **模块化编译支持：**
    - 提供了 `get_module_incdir_args()`、`get_module_outdir_args()`、`module_name_to_filename()` 等方法用于支持模块化编译。

12. **Build Wrapper 机制：**
    - `build_wrapper_args()` 和 `_build_wrapper()` 提供了包裹编译器调用的机制，用于添加额外的参数或处理依赖。

13. **通用工具方法：**
    - `remove_linkerlike_args()` 用于移除类似链接器的参数。
    - `get_include_args()` 用于获取包含目录的参数。
    - `get_no_stdinc_args()` 用于禁用标准库包含。

**与逆向方法的关联及举例：**

- **编译和链接目标代码：**  逆向工程师经常需要编译和链接他们修改过的代码片段或者注入到目标进程的代码。`compile()` 和 `links()` 方法直接用于执行这些操作。例如，逆向 Android 应用时，可能需要编译一个包含 Frida Hook 代码的动态库，然后通过 Frida 注入到目标应用中。
- **获取调试信息：** `get_compile_debugfile_args()` 和 `get_link_debugfile_args()`  对于生成包含调试符号的目标文件至关重要，这使得逆向工程师可以使用调试器（如 GDB 或 LLDB）来分析程序的执行流程和状态。
- **理解链接过程：**  理解 `get_std_shared_lib_link_args()` 等方法可以帮助逆向工程师分析目标程序链接了哪些库，以及这些库在内存中的加载方式，这对于理解程序的依赖关系和潜在的攻击面很有帮助。
- **检查编译器特性：**  `has_func_attribute()` 等方法反映了目标代码编译时所使用的编译器特性。了解这些特性可以帮助逆向工程师更好地理解代码的结构和行为。例如，了解是否使用了某些特定的优化选项可能解释某些代码片段的执行方式。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例：**

- **指令集参数 (`get_instruction_set_args()`):** 该方法允许指定目标代码的指令集架构（例如 ARM、x86），这直接关系到二进制代码的生成和执行。例如，在逆向 Android Native 代码时，需要了解目标设备 CPU 的架构，以便选择正确的反汇编工具和理解汇编指令。
- **链接参数 (`get_std_shared_lib_link_args()`, `get_soname_args()` 等):**  这些方法处理链接器相关的参数，如指定共享库的搜索路径、生成 SONAME 等。这涉及到 Linux 系统中动态链接库的加载机制。在 Android 中，理解这些参数对于分析 ART 虚拟机如何加载和管理 Native 库至关重要。
- **RPATH (`build_rpath_args()`):**  RPATH 用于指定程序运行时查找共享库的路径。理解 RPATH 可以帮助逆向工程师确定目标程序依赖的库的位置，这在分析恶意软件或理解程序行为时很有用。
- **Windows 子系统 (`get_win_subsystem_args()`):** 尽管这个文件路径表明主要关注 Frida Swift，但其父目录结构表明它属于一个更通用的编译器处理模块。这个方法用于处理 Windows 平台上的可执行文件类型（例如 GUI 程序或命令行程序）。
- **大文件支持 (`get_largefile_args()`):**  该方法涉及到在 32 位系统上处理大于 2GB 的文件，这与操作系统底层的文件系统 API 有关。
- **预链接 (`get_prelink_args()`):**  预链接是一种优化技术，用于减少程序启动时间，它涉及到在链接时预先计算符号地址。理解预链接可以帮助逆向工程师理解目标程序的加载过程。

**逻辑推理的假设输入与输出：**

假设输入以下代码片段和一个表示 GCC 编译器的 `Compiler` 对象：

```python
code = 'int main() { return 0; }'
```

调用 `compiler.compile(code)` 方法：

**假设输入：**

- `code`: 字符串 `'int main() { return 0; }'`
- `compiler`: 一个表示 GCC 编译器的 `Compiler` 对象

**可能的输出：**

- 一个 `CompileResult` 对象，其中 `returncode` 为 0 (表示编译成功)。
- 在临时目录下生成一个名为 `output.exe` (在非 Windows 系统上可能是 `output.obj`) 的可执行文件。
- `CompileResult` 对象的 `stdout` 和 `stderr` 属性可能包含 GCC 编译器的输出信息。

**用户或编程常见的使用错误及举例：**

- **传递不兼容的参数：** 用户可能传递了编译器不支持的参数到 `extra_args` 中，例如传递了 MSVC 特有的参数给 GCC 编译器。这会导致编译失败，`CompileResult` 的 `returncode` 将非零，`stderr` 中会包含编译器的错误信息。
- **代码语法错误：** 用户提供的 `code` 字符串可能包含语法错误，导致编译失败。同样，`CompileResult` 的 `returncode` 将非零，`stderr` 中会包含编译器的错误信息，指出错误的位置和类型。
- **依赖项缺失：** 如果编译的代码依赖于某些库，但这些库没有正确配置，链接阶段会失败。`CompileResult` 的 `returncode` 将非零，`stderr` 中会包含链接器的错误信息，指出找不到相关的库。
- **文件路径错误：** 如果 `code` 是一个文件路径，但该文件不存在，则会抛出文件未找到的异常。

**用户操作如何一步步到达这里作为调试线索：**

1. **用户尝试使用 Frida 框架拦截 Swift 代码。**
2. **Frida 需要与目标 Swift 代码进行交互，可能涉及到动态生成或编译一些桥接代码或 Hook 代码。**
3. **Frida 的内部机制会调用 Meson 构建系统来处理编译任务，因为 Frida 使用 Meson 作为其构建工具。**
4. **Meson 会根据配置识别出需要使用哪个编译器（例如，Swift 的编译器或 C/C++ 编译器）。**
5. **Meson 会查找并实例化相应的 `Compiler` 子类，并调用其 `compile()` 或 `links()` 方法。**
6. **在调用 `compile()` 或 `links()` 方法的过程中，会用到 `get_compiler_args_for_mode()` 等方法来构建编译命令。**
7. **如果用户在 Frida 的配置中指定了额外的编译选项，这些选项可能会通过 `extra_args` 参数传递到 `compile()` 方法。**
8. **如果编译过程中出现错误，可以通过查看 `CompileResult` 对象的 `stdout` 和 `stderr` 来获取编译器的输出信息，从而定位问题。**

**功能归纳 (第 2 部分):**

这部分代码主要定义了 `Compiler` 抽象基类，详细描述了编译器需要实现的各种功能接口，涵盖了编译、链接、调试、优化、依赖管理、平台特定处理等多个方面。它为 Meson 构建系统提供了一个统一的方式来与各种不同的编译器进行交互，是 Frida 动态插桩工具中处理代码编译和链接的核心抽象层。通过定义这些接口，Meson 可以根据不同的编程语言和编译器自动生成正确的构建命令，简化了跨平台构建的复杂性。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
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
```