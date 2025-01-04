Response:
The user wants a summary of the functionality of the provided Python code, which is a part of the Frida dynamic instrumentation tool. I need to identify the main purpose of this code and how it relates to逆向 (reverse engineering), binary operations, Linux/Android kernel and framework interactions, logical reasoning, common user errors, and debugging.

**Plan:**

1. **Identify the core functionality:** The code defines an abstract base class `Compiler` and related helper classes for managing compiler invocations and caching.
2. **Analyze its relation to reverse engineering:** Consider how compiling code relates to preparing for dynamic instrumentation or analysis.
3. **Examine interactions with binary/OS aspects:** Look for code dealing with executable creation, linking, and OS-specific configurations.
4. **Scan for logical inferences:** Identify any conditional logic or assumptions made within the code.
5. **Point out potential user errors:** Consider how incorrect usage of the provided methods might lead to problems.
6. **Describe the user journey to reach this code:** Explain the high-level steps a user might take that would lead to the execution of this code.
This部分代码主要定义了一个名为 `Compiler` 的抽象基类，它是用来代表不同编程语言的编译器。它封装了编译和链接操作的通用逻辑，并提供了许多方法来处理与特定编译器相关的细节。

以下是 `Compiler` 类及其相关方法的主要功能归纳：

**核心编译和链接功能:**

*   **`compile(self, code, ...)`:**  负责执行实际的编译过程。它接收源代码（可以是字符串或文件），并调用底层的编译器命令。它处理临时文件的创建、命令行的构建和执行，并返回编译结果（包括标准输出、标准错误和返回码）。
*   **`cached_compile(self, code, cdata, ...)`:**  在 `compile` 的基础上添加了编译结果缓存机制。它可以避免重复编译相同的代码，提高构建速度。
*   **`links(self, code, env, ...)` 和 `compiles(self, code, env, ...)`:**  提供更高级的接口来测试代码是否可以成功编译或链接。它们内部调用 `compile` 或 `cached_compile` 并返回布尔值表示成功与否，以及是否使用了缓存。
*   **`_build_wrapper(self, code, env, ...)`:**  一个内部辅助方法，用于处理编译前的准备工作，例如添加编译选项、处理依赖等，并根据是否需要缓存来调用 `compile` 或 `cached_compile`。

**编译器配置和选项管理:**

*   **`get_exelist(self, ccache=True)`:** 返回编译器的可执行文件路径列表，可以支持使用 `ccache` 来加速编译。
*   **`get_compiler_args_for_mode(self, mode)`:**  根据编译模式（编译、预处理、链接）返回相应的编译器参数。
*   **`get_always_args()`, `get_compile_only_args()`, `get_preprocess_only_args()`:** 返回总是需要添加的、仅编译时需要添加的、仅预处理时需要添加的编译器参数。
*   **`get_output_args(self, outfile)`:** 返回指定输出文件名的编译器参数。
*   **各种 `get_*_args()` 方法:**  提供了获取各种编译器选项的方法，例如优化级别 (`get_optimization_args`)、调试信息 (`get_compile_debugfile_args`, `get_link_debugfile_args`)、线程支持 (`thread_flags`, `thread_link_flags`)、OpenMP (`openmp_flags`, `openmp_link_flags`)、位置无关代码 (`get_pic_args`)、位置无关可执行文件 (`get_pie_args`)、链接器选项 (`get_link_whole_for`, `get_allow_undefined_link_args`) 等。
*   **`build_wrapper_args(self, env, extra_args, dependencies, mode)`:**  构建传递给编译器的完整参数列表，包括用户提供的额外参数和依赖项所需的参数。

**与逆向方法的关系:**

*   **编译是逆向分析的基础:**  在进行动态 instrumentation 或其他逆向分析之前，通常需要目标程序的二进制文件。`Compiler` 类的核心功能就是将源代码编译成可执行的二进制文件或库文件。
*   **编译选项影响逆向分析:**  编译时使用的选项（例如是否包含调试信息）会直接影响逆向分析的难度和效果。`Compiler` 类提供了控制这些选项的方法，例如 `get_debug_args`。
*   **链接过程与库依赖:**  逆向分析时，理解目标程序的库依赖关系很重要。`Compiler` 类处理链接过程，包括指定链接库的路径和名称，这有助于理解目标程序的组成部分。

**举例说明:**

假设我们要逆向一个使用了共享库的程序。`Compiler` 类在编译和链接这个程序时，会使用类似 `get_std_shared_lib_link_args` 或 `get_link_whole_for` 这样的方法来指定如何链接共享库，这有助于我们理解程序依赖了哪些外部库。

**涉及二进制底层、Linux/Android 内核及框架的知识:**

*   **二进制文件的生成:**  编译器的主要任务是将高级语言代码转换成机器可以执行的二进制指令。`Compiler` 类的 `compile` 方法直接操作这个过程。
*   **链接过程:**  链接器将编译产生的多个目标文件和库文件组合成最终的可执行文件或共享库。`Compiler` 类通过其内部的 `linker` 属性来处理链接相关的操作。
*   **共享库和动态链接:**  Linux 和 Android 系统广泛使用共享库。`Compiler` 类提供了 `get_std_shared_lib_link_args` 和 `get_std_shared_module_link_args` 等方法来处理共享库的链接。
*   **位置无关代码 (PIC) 和位置无关可执行文件 (PIE):**  这些是现代操作系统中安全性的重要组成部分。`Compiler` 类提供了 `get_pic_args` 和 `get_pie_args` 方法来启用或禁用这些特性。
*   **RPath:**  用于指定运行时库搜索路径。`Compiler` 类的 `build_rpath_args` 方法用于构建 RPath 参数。
*   **目标文件格式 (.o, .obj):**  编译的中间产物。`Compiler` 类的 `_get_compile_output` 方法用于生成目标文件名。
*   **可执行文件格式 (ELF, PE, Mach-O):**  最终生成的可执行文件格式。虽然 `Compiler` 类本身不直接处理这些格式，但其输出是这些格式的文件。
*   **Windows 子系统:**  `get_win_subsystem_args` 方法用于设置 Windows 可执行文件的子系统类型（例如控制台程序或 GUI 程序）。

**举例说明:**

在 Linux 或 Android 上编译一个共享库时，`Compiler` 可能会使用 `get_soname_args` 方法来设置共享库的 `soname`，这是动态链接器用于查找库的重要标识。在编译 Android 应用程序时，可能会涉及到与 Android 框架相关的链接选项。

**逻辑推理 (假设输入与输出):**

假设有以下输入：

*   `code`:  一个简单的 C++ 源代码字符串 `"int main() { return 0; }"`
*   `mode`: `CompileCheckMode.LINK` (表示进行链接)
*   `extra_args`: `['-Wall']` (添加一个警告选项)

**输出预期:**

`compile` 方法将会执行一个包含以下主要部分的命令行（具体命令会因编译器而异）：

1. 编译器可执行文件路径（例如 `g++`）。
2. 源代码文件名（临时文件，例如 `/tmp/tmpXXXX/testfile.cpp`）。
3. 输出文件名参数和输出文件名（例如 `-o /tmp/tmpXXXX/output.exe`）。
4. 链接模式参数（取决于编译器，可能没有显式参数）。
5. 用户提供的额外参数 `-Wall`。

返回的 `CompileResult` 对象将包含执行命令的标准输出、标准错误以及返回码。对于这段简单的代码，预期返回码为 0 (成功)。

**用户或编程常见的使用错误:**

*   **传递了不兼容的编译选项:**  用户可能会传递某些编译器不支持的选项到 `extra_args` 中，导致编译失败。例如，将 GCC 的选项传递给 MSVC 编译器。
*   **依赖项未正确指定:**  如果代码依赖于其他库，但用户没有通过 `dependencies` 参数正确指定，链接过程将会失败。
*   **环境配置错误:**  编译器可能依赖于某些环境变量或系统库，如果环境配置不正确，会导致编译器无法找到或执行。
*   **尝试预处理不支持预处理的语言:** 调用 `compile` 方法并将 `mode` 设置为 `CompileCheckMode.PREPROCESS`，但底层的编译器实现没有实现预处理功能，会导致异常。

**用户操作到达此处的调试线索:**

用户通常会通过 Meson 构建系统来使用这些编译器相关的代码。以下是一个可能的步骤：

1. **编写 `meson.build` 文件:**  用户定义项目的构建规则，包括指定使用的编程语言、依赖项、编译选项等。
2. **运行 `meson setup`:**  Meson 根据 `meson.build` 文件的内容，探测系统中可用的编译器，并生成构建系统所需的文件。在这个过程中，Meson 会实例化相应的 `Compiler` 子类。
3. **运行 `meson compile` 或 `ninja`:**  实际执行编译过程。Meson 会调用 `Compiler` 类提供的 `compile` 或 `cached_compile` 方法来编译源代码。

在调试过程中，如果编译出错，开发者可能会查看 Meson 的日志输出，其中会包含 `Compiler` 类生成的命令行，从而定位问题。他们也可能需要检查传递给 `compiles` 或 `links` 方法的 `extra_args` 和 `dependencies` 是否正确。

**归纳功能 (第2部分):**

总而言之，`Compiler` 抽象基类及其相关方法在 Frida 的构建系统中扮演着核心角色，它抽象了不同编程语言编译器的差异，提供了一套统一的接口来执行编译和链接操作，并管理各种编译器选项。它与逆向工程紧密相关，因为编译是生成目标二进制文件的必要步骤，而编译选项会影响后续的逆向分析工作。 代码中对二进制底层、操作系统特性（如共享库、PIC/PIE）的考虑，使其能够处理复杂的软件构建场景。同时，它也考虑了性能优化（如编译缓存）和用户可能遇到的常见错误。
Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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