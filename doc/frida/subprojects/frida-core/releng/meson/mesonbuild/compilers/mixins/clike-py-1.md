Response:
The user wants a summary of the functionalities present in the provided Python code snippet. I need to go through each method in the `clike.py` file and explain what it does. I also need to relate these functionalities to reverse engineering, low-level programming (including Linux, Android kernel/framework), logical reasoning (with input/output examples), common user errors, and provide debugging context. Finally, I need to provide a concise summary of the file's overall purpose.

Here's a breakdown of the functionalities and how they relate to the requested aspects:

1. **`_no_prototype_templ()` and `_have_prototype_templ()`:** These create C code snippets for checking function existence.
    *   **Reverse Engineering:** Checking for the existence of specific functions is crucial in reverse engineering to understand the capabilities and dependencies of a binary.
    *   **Low-Level:** This touches on how C code is structured and compiled, which is fundamental to understanding operating system internals.
    *   **Logic:**  If a function name is provided, the output will be compilable code that either calls the function directly or checks if a prototype exists.
2. **`has_function()`:** Determines if a function exists, considering default libraries, headers, and compiler built-ins.
    *   **Reverse Engineering:** Essential for identifying imported functions and compiler-specific intrinsics.
    *   **Low-Level:** Involves understanding how compilers and linkers resolve symbols and how system libraries are structured. The stub check is specific to glibc and Linux.
    *   **Logic:** Input: function name, prefix (includes), environment. Output: Boolean (exists/doesn't exist) and whether the result was cached.
3. **`has_members()`:** Checks if a type has specific members.
    *   **Reverse Engineering:**  Useful for understanding the structure of data types used by a program.
    *   **Low-Level:**  Relates to the layout of structures in memory.
    *   **Logic:** Input: type name, member names, prefix. Output: Boolean and cached status.
4. **`has_type()`:** Checks if a type is defined.
    *   **Reverse Engineering:** Important for determining the data types used in a binary.
    *   **Low-Level:**  Basic C/C++ type system knowledge.
    *   **Logic:** Input: type name, prefix. Output: Boolean and cached status.
5. **`_symbols_have_underscore_prefix_searchbin()`, `_symbols_have_underscore_prefix_define()`, `_symbols_have_underscore_prefix_list()`, `symbols_have_underscore_prefix()`:** These functions determine if the compiler prefixes symbols with an underscore.
    *   **Reverse Engineering:** Crucial for correctly identifying symbols in compiled binaries, especially when dealing with different platforms and compilers.
    *   **Low-Level:** Understanding symbol mangling and linking conventions. Specific to different operating systems (Darwin, Windows) and architectures (x86).
    *   **Logic:** Input: Compiler environment. Output: Boolean (has/doesn't have underscore prefix).
6. **`_get_patterns()`, `get_library_naming()`:**  Determine the naming conventions for libraries (prefixes, suffixes).
    *   **Reverse Engineering:** Needed to locate library files on the file system.
    *   **Low-Level:**  Knowledge of library naming conventions on various operating systems (Linux, Windows, macOS, OpenBSD).
    *   **Logic:** Input: Environment, library type (shared/static). Output: List of possible library name patterns.
7. **`_sort_shlibs_openbsd()`:**  Specifically handles shared library versioning on OpenBSD.
    *   **Low-Level:** Operating system-specific knowledge about library versioning.
8. **`_get_trials_from_pattern()`:** Creates potential library file paths based on a pattern.
9. **`_get_file_from_list()`:** Checks if a library file exists and performs architecture checks on macOS.
    *   **Low-Level:** File system operations and architecture-specific binary checks (lipo on macOS).
10. **`output_is_64bit()`:** Determines if the compiler produces 64-bit binaries.
    *   **Low-Level:**  Pointer size is a key indicator of architecture.
11. **`_find_library_real()`, `_find_library_impl()`, `find_library()`:** Locate library files based on name and search directories.
    *   **Reverse Engineering:**  Essential for finding dependencies of a program.
    *   **Low-Level:** File system searching and understanding linker behavior (-l, -L flags).
    *   **User Errors:** Specifying incorrect `extra_dirs` or `libtype`. Trying to find a library with the wrong prefix (e.g., `foo` instead of `libfoo`).
    *   **Debugging:** If a library isn't found, check the specified `extra_dirs`, the `libtype`, and ensure the library exists with the expected naming convention.
12. **`find_framework_paths()`:**  Gets the standard framework search paths on macOS.
    *   **Low-Level:** macOS-specific knowledge of framework directories.
13. **`_find_framework_real()`, `_find_framework_impl()`, `find_framework()`:** Find macOS frameworks.
    *   **Reverse Engineering:**  Finding framework dependencies.
    *   **Low-Level:** macOS framework linking conventions (-framework, -F flags).
14. **`get_crt_compile_args()`, `get_crt_link_args()`:**  Get compiler/linker arguments related to the C runtime library (CRT).
    *   **Low-Level:**  Understanding the C runtime library and how it's linked.
15. **`thread_flags()`:**  Get compiler flags for enabling threading support.
    *   **Low-Level:** Operating system-specific threading flags (-pthread).
16. **`linker_to_compiler_args()`:** Converts linker arguments to compiler arguments.
17. **`has_arguments()`:** Checks if the compiler accepts certain arguments.
18. **`_has_multi_arguments()`, `has_multi_arguments()`:** Checks if the compiler accepts multiple arguments.
    *   **User Errors:** Incorrectly assuming a compiler flag is supported.
    *   **Debugging:** If compilation fails due to arguments, verify the compiler documentation.
19. **`_has_multi_link_arguments()`, `has_multi_link_arguments()`:** Checks if the linker accepts multiple arguments.
    *   **User Errors:** Incorrectly assuming a linker flag is supported.
    *   **Debugging:** If linking fails due to arguments, verify the linker documentation.
20. **`_concatenate_string_literals()`:**  Handles string literal concatenation in C/C++.
21. **`get_has_func_attribute_extra_args()`:** Gets extra arguments for checking function attributes.
22. **`has_func_attribute()`:** Checks if a function attribute is supported.
    *   **Reverse Engineering:** Identifying compiler-specific function attributes that influence code generation.
    *   **Low-Level:** Understanding compiler extensions and attributes (e.g., `dllimport`, `dllexport`).
23. **`get_assert_args()`:** Gets compiler arguments to disable assertions.
24. **`can_compile()`:** Checks if a source file can be compiled.
25. **`get_preprocessor()`:** Gets a compiler object configured for preprocessing.

**Common User Errors and Debugging:**

*   **Incorrect Library Paths:** When `find_library` fails, users might have specified incorrect `extra_dirs`. Debug by verifying the paths and library names.
*   **Wrong Library Type:** Users might be searching for a static library when a shared library is needed, or vice-versa. Check the `libtype` parameter.
*   **Unsupported Compiler Flags:** `has_arguments` and `has_multi_arguments` can fail if the provided flags are not supported by the compiler. Consult compiler documentation.
*   **Symbol Prefix Issues:**  If linking fails due to symbol not found errors, the `symbols_have_underscore_prefix` functions help diagnose if the compiler is mangling symbols differently than expected.

**User Operation to Reach This Code:**

A user working with Frida might reach this code in the following scenarios:

1. **Building Frida from source:** The Meson build system uses this code to check compiler capabilities and find dependencies during the configuration phase.
2. **Developing Frida modules:** When writing native code that interacts with Frida, the build system might use these checks to ensure compatibility with the target environment.
3. **Troubleshooting build issues:** If the build fails due to missing libraries or unsupported compiler features, developers might investigate the Meson log and trace back to these compiler checks.

**Summary of Functionality:**

This Python code defines a mixin class (`CLikeCompiler`) that provides functionalities for probing the capabilities of C-like compilers (like GCC, Clang, MSVC). It includes methods for checking the existence of functions, types, and members, finding libraries and frameworks, determining symbol naming conventions, and testing compiler and linker argument support. These checks are crucial for build systems like Meson to adapt the build process to the specific compiler and target platform. The mixin handles platform-specific nuances and provides robust mechanisms for ensuring compatibility and finding necessary dependencies.
这是 frida 动态 instrumentation 工具的源代码文件 `frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/mixins/clike.py` 的第 2 部分，主要包含以下功能，延续了第 1 部分的编译器特性检测和处理逻辑：

**编译器特性检测和处理 (延续):**

*   **`_concatenate_string_literals(s: str) -> str`:**
    *   **功能:**  此函数用于将 C/C++ 中相邻的字符串字面量连接起来。例如，将 `"hello" "world"` 转换为 `"helloworld"`。
    *   **底层二进制:** 了解编译器如何处理字符串字面量连接有助于理解生成的二进制代码。
    *   **逻辑推理:** 假设输入是 `'"part1" "part2"'`, 输出将是 `'"part1part2"'`.
*   **`get_has_func_attribute_extra_args(self, name: str) -> T.List[str]`:**
    *   **功能:**  返回在检查特定函数属性是否存在时需要添加到编译器命令的额外参数。例如，对于不支持的属性，通常添加 `-Werror` 将警告提升为错误。
    *   **逆向相关性:** 函数属性（如 `__attribute__((constructor))` 或平台特定的属性）会影响代码生成和行为，逆向分析时需要了解这些属性。
*   **`has_func_attribute(self, name: str, env: 'Environment') -> T.Tuple[bool, bool]`:**
    *   **功能:** 检查编译器是否支持特定的函数属性（例如 `__attribute__((visibility("default")))` 或 Windows 的 `dllimport` / `dllexport`）。
    *   **逆向相关性:** 识别函数属性可以揭示函数的可见性、链接方式等重要信息。例如，`dllimport` 表示函数是从动态链接库导入的。
    *   **逻辑推理:** 假设 `name` 是 `"visibility"`，如果编译器支持该属性，则返回 `(True, False)` (假设未缓存)。
    *   **常见用户错误:** 用户可能错误地假设所有编译器都支持相同的属性。
*   **`get_assert_args(self, disable: bool) -> T.List[str]`:**
    *   **功能:** 根据是否禁用断言，返回相应的编译器参数。例如，禁用断言通常使用 `-DNDEBUG`。
    *   **底层二进制:** 断言的存在与否会影响最终二进制代码的大小和执行效率。
*   **`can_compile(self, src: 'mesonlib.FileOrString') -> bool`:**
    *   **功能:** 判断给定的源代码片段是否能够被当前编译器编译。
    *   **逻辑推理:** 如果 `self.mode` 是 `'PREPROCESSOR'`，则返回 `True`，因为预处理器可以处理任何文件。否则，调用父类的 `can_compile` 方法。
*   **`get_preprocessor(self) -> Compiler`:**
    *   **功能:**  返回一个配置为预处理器的编译器对象。这允许单独使用编译器进行预处理操作。
    *   **底层二进制:** 预处理是编译的第一步，理解预处理器的行为对于理解编译过程至关重要。
    *   **逻辑推理:** 该函数会创建一个新的编译器对象，并修改其执行命令以进行预处理。

**功能归纳:**

总的来说，`clike.py` 的第 2 部分继续定义了用于探测和处理 C-like 编译器的各种特性的方法。这些方法允许构建系统（如 Meson）根据目标编译器及其支持的功能，动态地调整构建过程。

**与逆向方法的联系举例:**

*   **`has_func_attribute`:**  在逆向工程中，如果发现一个二进制文件使用了特定的函数属性，例如 `__attribute__((constructor))`，可以推断出该函数在加载时会被自动执行。
*   **`symbols_have_underscore_prefix`:** 在尝试手动链接或加载动态库时，了解目标平台的符号前缀规则至关重要，否则可能导致符号查找失败。

**涉及二进制底层，Linux, Android 内核及框架的知识的举例:**

*   **`_sort_shlibs_openbsd`:**  专门处理 OpenBSD 上共享库的版本命名规则，这涉及到操作系统特定的文件系统和加载器行为。
*   **`find_framework_paths`:**  特定于 macOS 平台，用于查找 Framework 的路径，这与 macOS 的动态链接机制和系统结构有关。
*   **`thread_flags`:**  `-pthread` 是 Linux 和其他 POSIX 系统上用于启用线程支持的常见编译和链接选项，涉及到操作系统提供的线程库。

**逻辑推理的假设输入与输出:**

*   **`_concatenate_string_literals('"hello "', '"world"')` -> `"hello world"`**
*   **`has_func_attribute('visibility', env)` (假设编译器支持 visibility) -> `(True, False)`**
*   **`get_assert_args(True)` -> `['-DNDEBUG']`**

**涉及用户或者编程常见的使用错误举例:**

*   在 `find_library` 中，如果用户指定的 `extra_dirs` 路径错误，或者库的名称拼写错误，会导致库查找失败。
*   在使用 `has_arguments` 或 `has_multi_arguments` 检查编译器参数时，如果用户使用了编译器不支持的参数，会导致检查失败。
*   用户可能错误地认为所有 C-like 编译器（例如 GCC 和 MSVC）都支持完全相同的函数属性，导致在跨平台构建时出现问题。

**用户操作是如何一步步的到达这里，作为调试线索:**

作为 Frida 的开发者或用户，你可能在以下情况下会涉及到这部分代码：

1. **配置 Frida 的构建环境:** 当你使用 Meson 构建 Frida 时，Meson 会执行各种编译器特性检查，这些检查会调用 `clike.py` 中的方法。如果构建过程中出现关于编译器特性的错误，你可能会查看 Meson 的日志，其中会包含执行的编译器命令和检查结果，从而定位到相关的 `clike.py` 代码。
2. **为 Frida 编写 native 组件:**  如果你正在编写需要编译成 native 代码的 Frida 模块，Frida 的构建系统也会使用这些编译器检查来确保你的代码能够正确地编译和链接。如果编译失败，错误信息可能会指向特定的编译器特性检查。
3. **调试 Frida 的构建问题:** 当 Frida 的构建过程遇到问题时，例如找不到特定的库或不支持某些编译器选项，开发者可能会深入研究 Meson 的构建脚本和相关的编译器检查代码，以找出问题所在。例如，如果 `find_library` 找不到某个库，开发者可能会检查传递给 `find_library` 的 `extra_dirs` 和 `libname` 参数是否正确，以及相关的编译器配置。

总之，`clike.py` 的这一部分是 Frida 构建系统核心组件的一部分，它通过对目标编译器进行细致的探测，确保 Frida 能够跨平台、跨编译器地可靠构建。理解其功能有助于开发者理解 Frida 的构建过程，并在遇到构建问题时进行调试。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
}}'''
        return head, main

    @staticmethod
    def _have_prototype_templ() -> T.Tuple[str, str]:
        """
        Returns a head-er and main() call that uses the headers listed by the
        user for the function prototype while checking if a function exists.
        """
        # Add the 'prefix', aka defines, includes, etc that the user provides
        # This may include, for instance _GNU_SOURCE which must be defined
        # before limits.h, which includes features.h
        head = '{prefix}\n#include <limits.h>\n'
        # We don't know what the function takes or returns, so return it as an int.
        # Just taking the address or comparing it to void is not enough because
        # compilers are smart enough to optimize it away. The resulting binary
        # is not run so we don't care what the return value is.
        main = '''\nint main(void) {{
            void *a = (void*) &{func};
            long long b = (long long) a;
            return (int) b;
        }}'''
        return head, main

    def has_function(self, funcname: str, prefix: str, env: 'Environment', *,
                     extra_args: T.Optional[T.List[str]] = None,
                     dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        """Determine if a function exists.

        First, this function looks for the symbol in the default libraries
        provided by the compiler (stdlib + a few others usually). If that
        fails, it checks if any of the headers specified in the prefix provide
        an implementation of the function, and if that fails, it checks if it's
        implemented as a compiler-builtin.
        """
        if extra_args is None:
            extra_args = []

        # Short-circuit if the check is already provided by the cross-info file
        varname = 'has function ' + funcname
        varname = varname.replace(' ', '_')
        if self.is_cross:
            val = env.properties.host.get(varname, None)
            if val is not None:
                if isinstance(val, bool):
                    return val, False
                raise mesonlib.EnvironmentException(f'Cross variable {varname} is not a boolean.')

        # TODO: we really need a protocol for this,
        #
        # class StrProto(typing.Protocol):
        #    def __str__(self) -> str: ...
        fargs: T.Dict[str, T.Union[str, bool, int]] = {'prefix': prefix, 'func': funcname}

        # glibc defines functions that are not available on Linux as stubs that
        # fail with ENOSYS (such as e.g. lchmod). In this case we want to fail
        # instead of detecting the stub as a valid symbol.
        # We already included limits.h earlier to ensure that these are defined
        # for stub functions.
        stubs_fail = '''
        #if defined __stub_{func} || defined __stub___{func}
        fail fail fail this function is not going to work
        #endif
        '''

        # If we have any includes in the prefix supplied by the user, assume
        # that the user wants us to use the symbol prototype defined in those
        # includes. If not, then try to do the Autoconf-style check with
        # a dummy prototype definition of our own.
        # This is needed when the linker determines symbol availability from an
        # SDK based on the prototype in the header provided by the SDK.
        # Ignoring this prototype would result in the symbol always being
        # marked as available.
        if '#include' in prefix:
            head, main = self._have_prototype_templ()
        else:
            head, main = self._no_prototype_templ()
        templ = head + stubs_fail + main + '\n'

        res, cached = self.links(templ.format(**fargs), env, extra_args=extra_args,
                                 dependencies=dependencies)
        if res:
            return True, cached

        # MSVC does not have compiler __builtin_-s.
        if self.get_id() in {'msvc', 'intel-cl'}:
            return False, False

        # Detect function as a built-in
        #
        # Some functions like alloca() are defined as compiler built-ins which
        # are inlined by the compiler and you can't take their address, so we
        # need to look for them differently. On nice compilers like clang, we
        # can just directly use the __has_builtin() macro.
        fargs['no_includes'] = '#include' not in prefix
        is_builtin = funcname.startswith('__builtin_')
        fargs['is_builtin'] = is_builtin
        fargs['__builtin_'] = '' if is_builtin else '__builtin_'
        t = '''{prefix}
        int main(void) {{

        /* With some toolchains (MSYS2/mingw for example) the compiler
         * provides various builtins which are not really implemented and
         * fall back to the stdlib where they aren't provided and fail at
         * build/link time. In case the user provides a header, including
         * the header didn't lead to the function being defined, and the
         * function we are checking isn't a builtin itself we assume the
         * builtin is not functional and we just error out. */
        #if !{no_includes:d} && !defined({func}) && !{is_builtin:d}
            #error "No definition for {__builtin_}{func} found in the prefix"
        #endif

        #ifdef __has_builtin
            #if !__has_builtin({__builtin_}{func})
                #error "{__builtin_}{func} not found"
            #endif
        #elif ! defined({func})
            {__builtin_}{func};
        #endif
        return 0;
        }}\n'''
        return self.links(t.format(**fargs), env, extra_args=extra_args,
                          dependencies=dependencies)

    def has_members(self, typename: str, membernames: T.List[str],
                    prefix: str, env: 'Environment', *,
                    extra_args: T.Union[None, T.List[str], T.Callable[[CompileCheckMode], T.List[str]]] = None,
                    dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        if extra_args is None:
            extra_args = []
        # Create code that accesses all members
        members = ''.join(f'foo.{member};\n' for member in membernames)
        t = f'''{prefix}
        void bar(void) {{
            {typename} foo;
            {members}
        }}\n'''
        return self.compiles(t, env, extra_args=extra_args,
                             dependencies=dependencies)

    def has_type(self, typename: str, prefix: str, env: 'Environment',
                 extra_args: T.Union[T.List[str], T.Callable[[CompileCheckMode], T.List[str]]], *,
                 dependencies: T.Optional[T.List['Dependency']] = None) -> T.Tuple[bool, bool]:
        t = f'''{prefix}
        void bar(void) {{
            sizeof({typename});
        }}\n'''
        return self.compiles(t, env, extra_args=extra_args,
                             dependencies=dependencies)

    def _symbols_have_underscore_prefix_searchbin(self, env: 'Environment') -> bool:
        '''
        Check if symbols have underscore prefix by compiling a small test binary
        and then searching the binary for the string,
        '''
        symbol_name = b'meson_uscore_prefix'
        code = '''#ifdef __cplusplus
        extern "C" {
        #endif
        void ''' + symbol_name.decode() + ''' (void) {}
        #ifdef __cplusplus
        }
        #endif
        '''
        args = self.get_compiler_check_args(CompileCheckMode.COMPILE)
        n = '_symbols_have_underscore_prefix_searchbin'
        with self._build_wrapper(code, env, extra_args=args, mode=CompileCheckMode.COMPILE, want_output=True) as p:
            if p.returncode != 0:
                raise RuntimeError(f'BUG: Unable to compile {n!r} check: {p.stderr}')
            if not os.path.isfile(p.output_name):
                raise RuntimeError(f'BUG: Can\'t find compiled test code for {n!r} check')
            with open(p.output_name, 'rb') as o:
                for line in o:
                    # Check if the underscore form of the symbol is somewhere
                    # in the output file.
                    if b'_' + symbol_name in line:
                        mlog.debug("Underscore prefix check found prefixed function in binary")
                        return True
                    # Else, check if the non-underscored form is present
                    elif symbol_name in line:
                        mlog.debug("Underscore prefix check found non-prefixed function in binary")
                        return False
        raise RuntimeError(f'BUG: {n!r} check did not find symbol string in binary')

    def _symbols_have_underscore_prefix_define(self, env: 'Environment') -> T.Optional[bool]:
        '''
        Check if symbols have underscore prefix by querying the
        __USER_LABEL_PREFIX__ define that most compilers provide
        for this. Return if functions have underscore prefix or None
        if it was not possible to determine, like when the compiler
        does not set the define or the define has an unexpected value.
        '''
        delim = '"MESON_HAVE_UNDERSCORE_DELIMITER" '
        code = f'''
        #ifndef __USER_LABEL_PREFIX__
        #define MESON_UNDERSCORE_PREFIX unsupported
        #else
        #define MESON_UNDERSCORE_PREFIX __USER_LABEL_PREFIX__
        #endif
        {delim}MESON_UNDERSCORE_PREFIX
        '''
        with self._build_wrapper(code, env, mode=CompileCheckMode.PREPROCESS, want_output=False) as p:
            if p.returncode != 0:
                raise RuntimeError(f'BUG: Unable to preprocess _symbols_have_underscore_prefix_define check: {p.stdout}')
            symbol_prefix = p.stdout.partition(delim)[-1].rstrip()

            mlog.debug(f'Queried compiler for function prefix: __USER_LABEL_PREFIX__ is "{symbol_prefix!s}"')
            if symbol_prefix == '_':
                return True
            elif symbol_prefix == '':
                return False
            else:
                return None

    def _symbols_have_underscore_prefix_list(self, env: 'Environment') -> T.Optional[bool]:
        '''
        Check if symbols have underscore prefix by consulting a hardcoded
        list of cases where we know the results.
        Return if functions have underscore prefix or None if unknown.
        '''
        m = env.machines[self.for_machine]
        # Darwin always uses the underscore prefix, not matter what
        if m.is_darwin():
            return True
        # Windows uses the underscore prefix on x86 (32bit) only
        if m.is_windows() or m.is_cygwin():
            return m.cpu_family == 'x86'
        return None

    def symbols_have_underscore_prefix(self, env: 'Environment') -> bool:
        '''
        Check if the compiler prefixes an underscore to global C symbols
        '''
        # First, try to query the compiler directly
        result = self._symbols_have_underscore_prefix_define(env)
        if result is not None:
            return result

        # Else, try to consult a hardcoded list of cases we know
        # absolutely have an underscore prefix
        result = self._symbols_have_underscore_prefix_list(env)
        if result is not None:
            return result

        # As a last resort, try search in a compiled binary, which is the
        # most unreliable way of checking this, see #5482
        return self._symbols_have_underscore_prefix_searchbin(env)

    def _get_patterns(self, env: 'Environment', prefixes: T.List[str], suffixes: T.List[str], shared: bool = False) -> T.List[str]:
        patterns: T.List[str] = []
        for p in prefixes:
            for s in suffixes:
                patterns.append(p + '{}.' + s)
        if shared and env.machines[self.for_machine].is_openbsd():
            # Shared libraries on OpenBSD can be named libfoo.so.X.Y:
            # https://www.openbsd.org/faq/ports/specialtopics.html#SharedLibs
            #
            # This globbing is probably the best matching we can do since regex
            # is expensive. It's wrong in many edge cases, but it will match
            # correctly-named libraries and hopefully no one on OpenBSD names
            # their files libfoo.so.9a.7b.1.0
            for p in prefixes:
                patterns.append(p + '{}.so.[0-9]*.[0-9]*')
        return patterns

    def get_library_naming(self, env: 'Environment', libtype: LibType, strict: bool = False) -> T.Tuple[str, ...]:
        '''
        Get library prefixes and suffixes for the target platform ordered by
        priority
        '''
        stlibext = ['a']
        # We've always allowed libname to be both `foo` and `libfoo`, and now
        # people depend on it. Also, some people use prebuilt `foo.so` instead
        # of `libfoo.so` for unknown reasons, and may also want to create
        # `foo.so` by setting name_prefix to ''
        if strict and not isinstance(self, VisualStudioLikeCompiler): # lib prefix is not usually used with msvc
            prefixes = ['lib']
        else:
            prefixes = ['lib', '']
        # Library suffixes and prefixes
        if env.machines[self.for_machine].is_darwin():
            shlibext = ['dylib', 'so']
        elif env.machines[self.for_machine].is_windows():
            # FIXME: .lib files can be import or static so we should read the
            # file, figure out which one it is, and reject the wrong kind.
            if isinstance(self, VisualStudioLikeCompiler):
                shlibext = ['lib']
            else:
                shlibext = ['dll.a', 'lib', 'dll']
            # Yep, static libraries can also be foo.lib
            stlibext += ['lib']
        elif env.machines[self.for_machine].is_cygwin():
            shlibext = ['dll', 'dll.a']
            prefixes = ['cyg'] + prefixes
        elif self.id.lower() == 'c6000' or self.id.lower() == 'ti':
            # TI C6000 compiler can use both extensions for static or dynamic libs.
            stlibext = ['a', 'lib']
            shlibext = ['dll', 'so']
        else:
            # Linux/BSDs
            shlibext = ['so']
        # Search priority
        if libtype is LibType.PREFER_SHARED:
            patterns = self._get_patterns(env, prefixes, shlibext, True)
            patterns.extend([x for x in self._get_patterns(env, prefixes, stlibext, False) if x not in patterns])
        elif libtype is LibType.PREFER_STATIC:
            patterns = self._get_patterns(env, prefixes, stlibext, False)
            patterns.extend([x for x in self._get_patterns(env, prefixes, shlibext, True) if x not in patterns])
        elif libtype is LibType.SHARED:
            patterns = self._get_patterns(env, prefixes, shlibext, True)
        else:
            assert libtype is LibType.STATIC
            patterns = self._get_patterns(env, prefixes, stlibext, False)
        return tuple(patterns)

    @staticmethod
    def _sort_shlibs_openbsd(libs: T.List[str]) -> T.List[str]:
        def tuple_key(x: str) -> T.Tuple[int, ...]:
            ver = x.rsplit('.so.', maxsplit=1)[1]
            return tuple(int(i) for i in ver.split('.'))

        filtered: T.List[str] = []
        for lib in libs:
            # Validate file as a shared library of type libfoo.so.X.Y
            ret = lib.rsplit('.so.', maxsplit=1)
            if len(ret) != 2:
                continue
            try:
                tuple(int(i) for i in ret[1].split('.'))
            except ValueError:
                continue
            filtered.append(lib)
        return sorted(filtered, key=tuple_key, reverse=True)

    @classmethod
    def _get_trials_from_pattern(cls, pattern: str, directory: str, libname: str) -> T.List[Path]:
        f = Path(directory) / pattern.format(libname)
        # Globbing for OpenBSD
        if '*' in pattern:
            # NOTE: globbing matches directories and broken symlinks
            # so we have to do an isfile test on it later
            return [Path(x) for x in cls._sort_shlibs_openbsd(glob.glob(str(f)))]
        return [f]

    @staticmethod
    def _get_file_from_list(env: Environment, paths: T.List[Path]) -> T.Optional[Path]:
        '''
        We just check whether the library exists. We can't do a link check
        because the library might have unresolved symbols that require other
        libraries. On macOS we check if the library matches our target
        architecture.
        '''
        for p in paths:
            if p.is_file():

                if env.machines.host.is_darwin() and env.machines.build.is_darwin():
                    # Run `lipo` and check if the library supports the arch we want
                    archs = mesonlib.darwin_get_object_archs(str(p))
                    if not archs or env.machines.host.cpu_family not in archs:
                        mlog.debug(f'Rejected {p}, supports {archs} but need {env.machines.host.cpu_family}')
                        continue

                return p

        return None

    @functools.lru_cache()
    def output_is_64bit(self, env: 'Environment') -> bool:
        '''
        returns true if the output produced is 64-bit, false if 32-bit
        '''
        return self.sizeof('void *', '', env)[0] == 8

    def _find_library_real(self, libname: str, env: 'Environment', extra_dirs: T.List[str], code: str, libtype: LibType, lib_prefix_warning: bool) -> T.Optional[T.List[str]]:
        # First try if we can just add the library as -l.
        # Gcc + co seem to prefer builtin lib dirs to -L dirs.
        # Only try to find std libs if no extra dirs specified.
        # The built-in search procedure will always favour .so and then always
        # search for .a. This is only allowed if libtype is LibType.PREFER_SHARED
        if ((not extra_dirs and libtype is LibType.PREFER_SHARED) or
                libname in self.internal_libs):
            cargs = ['-l' + libname]
            largs = self.get_linker_always_args() + self.get_allow_undefined_link_args()
            extra_args = cargs + self.linker_to_compiler_args(largs)

            if self.links(code, env, extra_args=extra_args, disable_cache=True)[0]:
                return cargs
            # Don't do a manual search for internal libs
            if libname in self.internal_libs:
                return None
        # Not found or we want to use a specific libtype? Try to find the
        # library file itself.
        patterns = self.get_library_naming(env, libtype)
        # try to detect if we are 64-bit or 32-bit. If we can't
        # detect, we will just skip path validity checks done in
        # get_library_dirs() call
        try:
            if self.output_is_64bit(env):
                elf_class = 2
            else:
                elf_class = 1
        except (mesonlib.MesonException, KeyError): # TODO evaluate if catching KeyError is wanted here
            elf_class = 0
        # Search in the specified dirs, and then in the system libraries
        for d in itertools.chain(extra_dirs, self.get_library_dirs(env, elf_class)):
            for p in patterns:
                trials = self._get_trials_from_pattern(p, d, libname)
                if not trials:
                    continue
                trial = self._get_file_from_list(env, trials)
                if not trial:
                    continue
                if libname.startswith('lib') and trial.name.startswith(libname) and lib_prefix_warning:
                    mlog.warning(f'find_library({libname!r}) starting in "lib" only works by accident and is not portable')
                return [trial.as_posix()]
        return None

    def _find_library_impl(self, libname: str, env: 'Environment', extra_dirs: T.List[str],
                           code: str, libtype: LibType, lib_prefix_warning: bool) -> T.Optional[T.List[str]]:
        # These libraries are either built-in or invalid
        if libname in self.ignore_libs:
            return []
        if isinstance(extra_dirs, str):
            extra_dirs = [extra_dirs]
        key = (tuple(self.exelist), libname, tuple(extra_dirs), code, libtype)
        if key not in self.find_library_cache:
            value = self._find_library_real(libname, env, extra_dirs, code, libtype, lib_prefix_warning)
            self.find_library_cache[key] = value
        else:
            value = self.find_library_cache[key]
        if value is None:
            return None
        return value.copy()

    def find_library(self, libname: str, env: 'Environment', extra_dirs: T.List[str],
                     libtype: LibType = LibType.PREFER_SHARED, lib_prefix_warning: bool = True) -> T.Optional[T.List[str]]:
        code = 'int main(void) { return 0; }\n'
        return self._find_library_impl(libname, env, extra_dirs, code, libtype, lib_prefix_warning)

    def find_framework_paths(self, env: 'Environment') -> T.List[str]:
        '''
        These are usually /Library/Frameworks and /System/Library/Frameworks,
        unless you select a particular macOS SDK with the -isysroot flag.
        You can also add to this by setting -F in CFLAGS.
        '''
        # TODO: this really needs to be *AppleClang*, not just any clang.
        if self.id != 'clang':
            raise mesonlib.MesonException('Cannot find framework path with non-clang compiler')
        # Construct the compiler command-line
        commands = self.get_exelist(ccache=False) + ['-v', '-E', '-']
        commands += self.get_always_args()
        # Add CFLAGS/CXXFLAGS/OBJCFLAGS/OBJCXXFLAGS from the env
        commands += env.coredata.get_external_args(self.for_machine, self.language)
        mlog.debug('Finding framework path by running: ', ' '.join(commands), '\n')
        os_env = os.environ.copy()
        os_env['LC_ALL'] = 'C'
        _, _, stde = mesonlib.Popen_safe(commands, env=os_env, stdin=subprocess.PIPE)
        paths: T.List[str] = []
        for line in stde.split('\n'):
            if '(framework directory)' not in line:
                continue
            # line is of the form:
            # ` /path/to/framework (framework directory)`
            paths.append(line[:-21].strip())
        return paths

    def _find_framework_real(self, name: str, env: 'Environment', extra_dirs: T.List[str], allow_system: bool) -> T.Optional[T.List[str]]:
        code = 'int main(void) { return 0; }'
        link_args: T.List[str] = []
        for d in extra_dirs:
            link_args += ['-F' + d]
        # We can pass -Z to disable searching in the system frameworks, but
        # then we must also pass -L/usr/lib to pick up libSystem.dylib
        extra_args = [] if allow_system else ['-Z', '-L/usr/lib']
        link_args += ['-framework', name]
        if self.links(code, env, extra_args=(extra_args + link_args), disable_cache=True)[0]:
            return link_args
        return None

    def _find_framework_impl(self, name: str, env: 'Environment', extra_dirs: T.List[str],
                             allow_system: bool) -> T.Optional[T.List[str]]:
        if isinstance(extra_dirs, str):
            extra_dirs = [extra_dirs]
        key = (tuple(self.exelist), name, tuple(extra_dirs), allow_system)
        if key in self.find_framework_cache:
            value = self.find_framework_cache[key]
        else:
            value = self._find_framework_real(name, env, extra_dirs, allow_system)
            self.find_framework_cache[key] = value
        if value is None:
            return None
        return value.copy()

    def find_framework(self, name: str, env: 'Environment', extra_dirs: T.List[str],
                       allow_system: bool = True) -> T.Optional[T.List[str]]:
        '''
        Finds the framework with the specified name, and returns link args for
        the same or returns None when the framework is not found.
        '''
        # TODO: should probably check for macOS?
        return self._find_framework_impl(name, env, extra_dirs, allow_system)

    def get_crt_compile_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        # TODO: does this belong here or in GnuLike or maybe PosixLike?
        return []

    def get_crt_link_args(self, crt_val: str, buildtype: str) -> T.List[str]:
        # TODO: does this belong here or in GnuLike or maybe PosixLike?
        return []

    def thread_flags(self, env: 'Environment') -> T.List[str]:
        # TODO: does this belong here or in GnuLike or maybe PosixLike?
        host_m = env.machines[self.for_machine]
        if host_m.is_haiku() or host_m.is_darwin():
            return []
        return ['-pthread']

    def linker_to_compiler_args(self, args: T.List[str]) -> T.List[str]:
        return args.copy()

    def has_arguments(self, args: T.List[str], env: 'Environment', code: str,
                      mode: CompileCheckMode) -> T.Tuple[bool, bool]:
        return self.compiles(code, env, extra_args=args, mode=mode)

    def _has_multi_arguments(self, args: T.List[str], env: 'Environment', code: str) -> T.Tuple[bool, bool]:
        new_args: T.List[str] = []
        for arg in args:
            # some compilers, e.g. GCC, don't warn for unsupported warning-disable
            # flags, so when we are testing a flag like "-Wno-forgotten-towel", also
            # check the equivalent enable flag too "-Wforgotten-towel"
            if arg.startswith('-Wno-'):
                new_args.append('-W' + arg[5:])
            if arg.startswith('-Wl,'):
                mlog.warning(f'{arg} looks like a linker argument, '
                             'but has_argument and other similar methods only '
                             'support checking compiler arguments. Using them '
                             'to check linker arguments are never supported, '
                             'and results are likely to be wrong regardless of '
                             'the compiler you are using. has_link_argument or '
                             'other similar method can be used instead.')
            new_args.append(arg)
        return self.has_arguments(new_args, env, code, mode=CompileCheckMode.COMPILE)

    def has_multi_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        return self._has_multi_arguments(args, env, 'extern int i;\nint i;\n')

    def _has_multi_link_arguments(self, args: T.List[str], env: 'Environment', code: str) -> T.Tuple[bool, bool]:
        # First time we check for link flags we need to first check if we have
        # --fatal-warnings, otherwise some linker checks could give some
        # false positive.
        args = self.linker.fatal_warnings() + args
        args = self.linker_to_compiler_args(args)
        return self.has_arguments(args, env, code, mode=CompileCheckMode.LINK)

    def has_multi_link_arguments(self, args: T.List[str], env: 'Environment') -> T.Tuple[bool, bool]:
        return self._has_multi_link_arguments(args, env, 'int main(void) { return 0; }\n')

    @staticmethod
    def _concatenate_string_literals(s: str) -> str:
        pattern = re.compile(r'(?P<pre>.*([^\\]")|^")(?P<str1>([^\\"]|\\.)*)"\s+"(?P<str2>([^\\"]|\\.)*)(?P<post>".*)')
        ret = s
        m = pattern.match(ret)
        while m:
            ret = ''.join(m.group('pre', 'str1', 'str2', 'post'))
            m = pattern.match(ret)
        return ret

    def get_has_func_attribute_extra_args(self, name: str) -> T.List[str]:
        # Most compilers (such as GCC and Clang) only warn about unknown or
        # ignored attributes, so force an error. Overridden in GCC and Clang
        # mixins.
        return ['-Werror']

    def has_func_attribute(self, name: str, env: 'Environment') -> T.Tuple[bool, bool]:
        # Just assume that if we're not on windows that dllimport and dllexport
        # don't work
        m = env.machines[self.for_machine]
        if not (m.is_windows() or m.is_cygwin()):
            if name in {'dllimport', 'dllexport'}:
                return False, False

        return self.compiles(self.attribute_check_func(name), env,
                             extra_args=self.get_has_func_attribute_extra_args(name))

    def get_assert_args(self, disable: bool) -> T.List[str]:
        if disable:
            return ['-DNDEBUG']
        return []

    @functools.lru_cache(maxsize=None)
    def can_compile(self, src: 'mesonlib.FileOrString') -> bool:
        # Files we preprocess can be anything, e.g. .in
        if self.mode == 'PREPROCESSOR':
            return True
        return super().can_compile(src)

    def get_preprocessor(self) -> Compiler:
        if not self.preprocessor:
            self.preprocessor = copy.copy(self)
            self.preprocessor.exelist = self.exelist + self.get_preprocess_to_file_args()
            self.preprocessor.mode = 'PREPROCESSOR'
            self.modes.append(self.preprocessor)
        return self.preprocessor
```