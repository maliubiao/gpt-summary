Response:
The user wants a summary of the functionality of the Python code provided, which is part of the Frida dynamic instrumentation tool. I need to analyze the code and identify its core responsibilities.

Specifically, the user wants to know:
1. **General functionality**: What does this code do?
2. **Relevance to reverse engineering**: How does it relate to the process of analyzing software?
3. **Interaction with low-level systems**: Does it involve knowledge of the binary level, Linux/Android kernels, or frameworks?
4. **Logical reasoning**: Are there examples of input and output based on logical conditions?
5. **Common user errors**: What mistakes could a user make while using this code?
6. **User journey**: How might a user's actions lead to this specific part of the code?
7. **Summary of functionality**: A concise overview of the code's purpose.

This is the second part of the request, so I need to ensure the summary incorporates information from both parts of the code.

Based on the provided code, the core functionality revolves around *compilation*. This Python file defines a base `Compiler` class that provides a framework for interacting with different compilers (like GCC, Clang, MSVC). It handles tasks like:

*   Constructing compiler command-line arguments.
*   Executing the compiler.
*   Caching compilation results.
*   Managing temporary files.
*   Handling different compilation modes (compile, link, preprocess).
*   Providing hooks for language-specific compiler options.

Let's address each of the user's points:

1. **General functionality**: This code defines a base class for representing and interacting with software compilers. It abstracts away the complexities of invoking different compilers and managing their command-line arguments.

2. **Relevance to reverse engineering**: While this specific code doesn't directly perform reverse engineering, it's a fundamental building block for tools that *do*. Frida, the context of this code, is used for dynamic instrumentation, a key technique in reverse engineering. This code would be used to compile small snippets of code that Frida injects into target processes for analysis. For example, a reverse engineer might write a small C function to hook a specific function in an Android application. Frida would use a `Compiler` instance to compile this code on the fly before injecting it.

3. **Interaction with low-level systems**: Yes, this code interacts with low-level systems. It needs to understand how to invoke compilers, which are tools that operate on binary code. The compiler itself generates machine code that directly interacts with the CPU. While this Python code doesn't directly touch the Linux/Android kernel, the *output* of the compilation process does. The code also handles concepts like shared libraries and modules, which are fundamental to how operating systems load and execute code.

4. **Logical reasoning**:  The `compile` and `cached_compile` methods demonstrate logical reasoning. For example, in the `compile` method:
    *   **Input**: `mode` (e.g., `CompileCheckMode.LINK`).
    *   **Output**: The `suffix` of the output file (`.exe` for linking, `.obj` otherwise).
    *   **Logic**: An `if` statement checks the `mode` and sets the `suffix` accordingly.

    Another example is the conditional enabling of ccache disabling based on whether the input is a string or a file.

5. **Common user errors**: A common error might be providing incorrect or incompatible compiler flags through `extra_args`. For instance, passing linker flags when only compiling, or using flags that are not supported by the specific compiler being used. Another error could be related to setting up the build environment correctly, ensuring the compiler executables are in the system's PATH.

6. **User journey**: A user wanting to compile a small piece of C code for injection using Frida might follow these steps:
    1. Write the C code as a string.
    2. Use Frida's API to obtain a `Compiler` instance for the target architecture.
    3. Call the `compile` method of the `Compiler` instance, passing the C code string and potentially some `extra_args`.
    4. The `compile` method would then execute the steps in this Python code to compile the C code.

7. **Summary of functionality**:  This Python code defines the abstract base class for managing and executing software compilers within the Frida framework. It handles the complexities of compiler invocation, argument construction, output management, and caching, providing a consistent interface for compiling code snippets, a crucial step in Frida's dynamic instrumentation process.

I will now generate the final response based on this thought process.
这是frida动态 instrumentation tool的源代码文件 `compilers.py` 的第二部分，延续了第一部分的内容，主要负责定义一个抽象的 `Compiler` 类以及与其编译流程相关的功能。以下是其功能的归纳和相关解释：

**主要功能归纳：**

1. **抽象编译器接口定义:** `Compiler` 类作为一个抽象基类，定义了与各种编译器交互的通用接口。这包括编译、链接、预处理等操作，以及获取编译器特定参数的方法。
2. **编译和链接流程管理:** 提供了 `compile` 和 `cached_compile` 方法来执行代码的编译和链接操作。`cached_compile` 实现了编译结果的缓存，以提高效率。
3. **编译器参数管理:**  定义了多种方法来获取不同编译阶段所需的参数，例如：
    *   `get_compiler_args_for_mode`: 根据编译模式（编译、链接、预处理）获取参数。
    *   `get_output_args`: 获取指定输出文件路径的参数。
    *   `get_compile_only_args`, `get_preprocess_only_args`: 获取仅用于编译或预处理的参数。
    *   `get_link_debugfile_args`, `get_std_shared_lib_link_args` 等：获取链接相关的参数。
    *   以及针对特定功能（如线程、OpenMP、代码覆盖率、LTO、Sanitizer 等）的参数获取方法。
4. **代码编译和链接执行:** `compile` 方法负责创建临时目录，将代码写入文件，构造完整的编译器命令行，并执行编译/链接命令。
5. **编译结果缓存:** `cached_compile` 方法使用缓存来存储和检索编译结果，避免重复编译相同的代码。
6. **跨平台兼容性抽象:**  虽然具体的编译器实现会依赖于平台，但 `Compiler` 类提供了一个通用的接口，使得 Frida 可以在不同平台上使用不同的编译器。
7. **与构建系统集成:** 该代码是 Meson 构建系统的一部分，因此也体现了与构建系统的集成，例如，可以获取构建目录、临时目录等信息。
8. **错误处理和调试支持:**  `compile` 方法会捕获编译器的标准输出和标准错误，并将其包含在 `CompileResult` 对象中，方便调试。
9. **用户自定义选项支持:**  `get_global_options` 函数允许用户通过 Meson 的选项系统传递额外的编译器和链接器参数。

**与逆向的方法的关系及举例说明：**

*   **动态代码生成与编译:** 在动态 instrumentation 中，Frida 经常需要在运行时生成一些代码片段（例如，用于 hook 函数的代码）。`Compiler` 类就负责将这些生成的代码片段编译成目标平台的机器码。
    *   **举例:**  Frida 用户可能编写一个 JavaScript 脚本，用于 hook 某个 Android 应用的 Java 方法。Frida 内部会生成对应的 Native 代码（可能是 C/C++），然后使用 `Compiler` 类将其编译成共享库，并注入到目标进程中执行。
*   **代码注入与执行:** 编译后的代码可以被注入到目标进程中执行。`Compiler` 类的输出（例如，`.so` 文件）就是用于代码注入的载体。
    *   **举例:**  在 Android 逆向中，为了分析某个 Native 函数的行为，可能会编写一小段 C 代码来替换或包装该函数。`Compiler` 类会将这段 C 代码编译成 `.so` 文件，然后 Frida 会将其加载到目标应用的进程空间中。

**涉及二进制底层、Linux、Android内核及框架的知识的举例说明：**

*   **二进制底层:** `Compiler` 类的核心任务是将源代码转换成二进制机器码。它需要了解目标平台的指令集架构（例如 ARM、x86）。
    *   **举例:**  `get_instruction_set_args` 方法就是用来指定目标指令集架构的编译参数。例如，在为 ARM 架构编译时，可能需要传递 `-march=armv7-a` 或 `-march=arm64-v8a` 等参数。
*   **Linux/Android内核:**  编译后的代码最终需要在 Linux 或 Android 内核上运行。`Compiler` 类的一些方法涉及到与操作系统相关的概念，例如共享库、动态链接、RPath 等。
    *   **举例:**  `build_rpath_args` 方法用于生成 RPath 参数，它告诉动态链接器在哪里查找共享库。这在 Linux 和 Android 中是管理动态库依赖的关键。
*   **Android框架:**  在 Android 逆向中，编译的代码可能需要与 Android 框架进行交互。
    *   **举例:**  如果需要 hook Android 框架中的某个 Java 方法，生成的 Native 代码需要能够调用 ART (Android Runtime) 的相关接口。`Compiler` 类需要配置正确的编译选项和链接选项，以确保生成的代码能够正常工作。
*   **共享库和模块:** `get_std_shared_lib_link_args` 和 `get_std_shared_module_link_args` 方法用于获取编译共享库和模块的链接参数，这是 Linux 和 Android 等操作系统中常见的代码组织形式。

**逻辑推理的假设输入与输出举例：**

假设我们调用 `compile` 方法编译一段简单的 C 代码，用于在 Linux 上进行链接（`mode=CompileCheckMode.LINK`）：

*   **假设输入:**
    *   `code`: `"int main() { return 0; }"`
    *   `mode`: `CompileCheckMode.LINK`
    *   `self.default_suffix`: `"c"` (假设是 C 编译器)
    *   `self.get_exelist()`: `["gcc"]`
    *   `self.get_output_args(output)`: `["-o", "/tmp/tmpdir/output.exe"]` (假设临时目录为 `/tmp/tmpdir`)
    *   `self.get_compiler_args_for_mode(CompileCheckMode.LINK)`: `[]` (假设没有额外的链接参数)
*   **逻辑推理:**
    1. 在临时目录中创建 `testfile.c` 文件，内容为 `"int main() { return 0; }"`。
    2. 根据 `mode` 确定输出文件后缀为 `.exe`。
    3. 调用 `self.get_output_args` 获取输出参数 `["-o", "/tmp/tmpdir/output.exe"]`。
    4. 构造编译器命令列表：`["gcc", "testfile.c", "-o", "/tmp/tmpdir/output.exe"]`。
    5. 执行该命令。
*   **可能输出:**
    *   `CompileResult` 对象，其中 `returncode` 为 0 (表示编译成功)，`stdout` 和 `stderr` 可能为空。
    *   在 `/tmp/tmpdir` 目录下生成可执行文件 `output.exe`。

**涉及用户或编程常见的使用错误及举例说明：**

*   **传递错误的编译选项:** 用户可能传递不适用于当前编译器的选项，导致编译失败。
    *   **举例:**  在使用 GCC 编译器时，错误地传递了 MSVC 特有的编译选项 `/Fo`。
*   **缺少必要的依赖库:** 在链接阶段，如果代码依赖的库没有被正确链接，会导致链接失败。
    *   **举例:**  编译使用了 `libssl` 的代码，但没有通过 `-lssl` 显式链接该库。
*   **代码语法错误:** 源代码中存在语法错误，导致编译失败。
    *   **举例:**  C 代码中缺少分号或使用了未定义的变量。
*   **环境配置问题:** 编译器可执行文件不在系统的 PATH 环境变量中，导致 Frida 无法找到编译器。
    *   **举例:**  用户没有安装 GCC，或者 GCC 的路径没有添加到 PATH 中。
*   **缓存问题:**  在修改了代码或编译选项后，由于缓存的存在，可能仍然使用旧的编译结果，导致预期外的行为。用户可能需要清理缓存来解决。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本:** 用户编写了一个 JavaScript 或 Python 脚本，使用 Frida 的 API 来 hook 目标进程的某个函数，或者执行自定义的 Native 代码。
2. **Frida 尝试编译代码:**  如果用户的脚本涉及到动态生成 Native 代码（例如，使用 `Memory.allocUtf8String` 等分配内存，或者需要编译 C 代码注入），Frida 内部会调用相应的编译器接口。
3. **选择合适的编译器:** Frida 会根据目标进程的架构和操作系统，选择合适的 `Compiler` 实现（例如 `GCC`、`Clang`、`MSVC` 的子类）。
4. **调用 `compile` 或 `cached_compile`:**  Frida 内部会调用选定的 `Compiler` 对象的 `compile` 或 `cached_compile` 方法，并将需要编译的代码片段以及相关的编译选项作为参数传递进去。
5. **执行 `compilers.py` 中的代码:**  此时，代码执行流程就进入了 `compilers.py` 文件中 `Compiler` 类的相关方法，例如 `compile` 方法，开始执行编译流程。

作为调试线索，如果用户遇到编译错误，可以检查：

*   Frida 脚本中生成的代码是否正确。
*   Frida 选择的编译器是否正确。
*   传递给 `compile` 方法的 `extra_args` 是否正确。
*   目标系统是否安装了必要的编译器和依赖库。
*   是否需要清理 Frida 的编译缓存。

**归纳一下它的功能（第二部分）：**

`compilers.py` 的第二部分延续了第一部分的功能，主要负责定义了 `Compiler` 抽象基类及其核心的编译和链接流程管理机制。它提供了一个通用的接口，用于与各种不同的编译器进行交互，并处理编译参数的构建、编译命令的执行以及编译结果的缓存。这使得 Frida 能够在运行时动态地编译代码片段，是其动态 instrumentation 能力的关键组成部分。该部分还涵盖了与操作系统底层特性（如共享库、RPath）以及构建系统集成的相关功能。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/compilers.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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