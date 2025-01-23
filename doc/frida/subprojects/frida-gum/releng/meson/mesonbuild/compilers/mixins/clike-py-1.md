Response:
The user is asking for a summary of the functionalities present in the provided Python code snippet. This code belongs to the `clike.py` file within the Frida dynamic instrumentation tool, specifically related to compiler interactions in the Meson build system.

To provide a comprehensive answer, I need to:

1. **Identify the key methods and their purposes**: Analyze each function defined in the class and understand what it does.
2. **Relate to reverse engineering**: Determine if any functionalities directly assist or relate to reverse engineering techniques.
3. **Connect to low-level details**: Check for interactions with binary formats, Linux/Android kernels or frameworks.
4. **Identify logical reasoning**: Look for functions that make decisions based on inputs. Provide example input/output for such cases.
5. **Point out potential user errors**:  Highlight common mistakes users might make when using these functions.
6. **Explain the debugging path**:  Describe how a user might end up interacting with this specific code during the development or usage of Frida.
7. **Summarize the overall functionality**:  Provide a concise summary of the class's role.

Here's a breakdown of the methods and my thoughts on each:

*   `_no_prototype_templ()`: Creates a template to check if a function exists without including any external headers. This is relevant to low-level checks and might be used to detect built-in functions.
*   `_have_prototype_templ()`: Creates a template to check if a function exists by including user-provided headers. This is crucial for checking library functions and user-defined functions.
*   `has_function()`: The core function to determine if a function is available. It checks standard libraries, header files, and compiler built-ins. This is highly relevant to reverse engineering (identifying available functions) and interacts with the compiler's understanding of the system.
*   `has_members()`: Checks if a given type has the specified members. Useful in reverse engineering to understand data structures.
*   `has_type()`: Checks if a given type is defined. Important for compatibility and understanding code structure.
*   `_symbols_have_underscore_prefix_searchbin()`:  Determines if the compiler prefixes symbols with an underscore by inspecting compiled binaries. This is a low-level detail about ABI conventions.
*   `_symbols_have_underscore_prefix_define()`: Checks for the underscore prefix by querying compiler defines. Another low-level ABI detail.
*   `_symbols_have_underscore_prefix_list()`: Uses a hardcoded list to determine the underscore prefix. A practical, albeit less dynamic, approach.
*   `symbols_have_underscore_prefix()`: Orchestrates the different methods to reliably determine the symbol prefix. Crucial for interacting with compiled code at a low level.
*   `_get_patterns()`: Generates filename patterns for libraries based on prefixes and suffixes. Relates to how libraries are named in different operating systems.
*   `get_library_naming()`:  Provides the standard naming conventions for static and shared libraries on the target platform. Directly related to how the linker finds libraries.
*   `_sort_shlibs_openbsd()`: Handles specific shared library naming conventions on OpenBSD. OS-specific knowledge.
*   `_get_trials_from_pattern()`: Generates potential library file paths based on a naming pattern.
*   `_get_file_from_list()`: Checks if a library file exists and performs architecture checks on macOS. OS-specific binary inspection.
*   `output_is_64bit()`: Determines if the compiler produces 64-bit binaries. A fundamental binary property.
*   `_find_library_real()`:  The core logic for finding a library, handling both `-l` style linking and searching for library files in directories.
*   `_find_library_impl()`: Implements caching for `_find_library_real()`.
*   `find_library()`: The public interface for finding libraries.
*   `find_framework_paths()`:  Specifically for macOS, finds the standard framework directories. OS-specific functionality.
*   `_find_framework_real()`:  Locates macOS frameworks.
*   `_find_framework_impl()`: Implements caching for framework finding.
*   `find_framework()`: Public interface for finding frameworks.
*   `get_crt_compile_args()`: Gets compiler arguments related to the C runtime library.
*   `get_crt_link_args()`: Gets linker arguments related to the C runtime library.
*   `thread_flags()`: Provides compiler flags for thread support. OS-specific.
*   `linker_to_compiler_args()`:  Converts linker arguments to compiler arguments.
*   `has_arguments()`:  Checks if the compiler accepts specific arguments.
*   `_has_multi_arguments()`: Handles checking multiple compiler arguments.
*   `has_multi_arguments()`: Public interface for checking multiple compiler arguments.
*   `_has_multi_link_arguments()`: Checks if the linker accepts specific arguments.
*   `has_multi_link_arguments()`: Public interface for checking multiple linker arguments.
*   `_concatenate_string_literals()`:  A utility function to merge string literals.
*   `get_has_func_attribute_extra_args()`: Gets extra arguments for checking function attributes.
*   `has_func_attribute()`: Checks if a function attribute is supported. Important for understanding compiler extensions.
*   `get_assert_args()`: Gets arguments to enable or disable assertions.
*   `can_compile()`: Checks if a source file can be compiled.
*   `get_preprocessor()`: Gets a preprocessor object.

After analyzing each method, I can now structure the response according to the user's requirements.这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/clike.py` 文件的第二个部分，主要包含以下功能：

**核心功能归纳:**

这个代码片段主要定义了一个名为 `CLikeCompiler` 的 mixin 类，旨在为类似 C 的编译器（如 GCC, Clang, MSVC 等）提供一系列用于编译时检查和库查找的通用方法。 这些方法允许 Meson 构建系统能够：

*   **检测编译器特性和目标平台属性：** 例如，检查函数、类型、结构体成员是否存在，确定目标架构是 32 位还是 64 位，以及符号是否带有下划线前缀。
*   **查找库文件和框架：**  提供在各种操作系统上查找静态库、共享库和框架的方法，并考虑不同的命名约定。
*   **检查编译器和链接器参数的支持情况：** 允许 Meson 探测编译器和链接器是否接受特定的命令行参数。
*   **处理函数属性：**  提供检查编译器是否支持特定的函数属性的能力。
*   **提供与 C 运行时库和线程相关的编译/链接参数。**
*   **提供获取预处理器实例的方法。**

**与逆向方法的关系及举例说明:**

这个代码文件本身不是一个直接进行逆向的工具，但其功能对于构建和配置逆向工程工具（如 Frida 本身）至关重要。 逆向工程师在开发 Frida 的模块或扩展时，可能需要与目标进程的库进行交互。  `CLikeCompiler` 提供的功能可以帮助确定目标环境中可用的库和函数，以及如何正确地链接它们。

**举例说明:**

假设逆向工程师想要在 Frida 脚本中调用目标进程中的 `getpid` 函数。  Meson 构建系统可以使用 `CLikeCompiler` 中的 `has_function` 方法来检查目标环境（例如 Android 设备）中是否存在 `getpid` 函数：

```python
# 假设在 Meson 的配置阶段
if compiler.has_function('getpid', '', env):
    print("目标环境存在 getpid 函数")
else:
    print("目标环境不存在 getpid 函数")
```

如果目标环境是 Windows，工程师可能需要查找 `kernel32.dll` 中的 `GetProcessId` 函数。 `CLikeCompiler` 的 `find_library` 方法可以帮助定位 `kernel32.lib` 或 `kernel32.dll.a` (MinGW 环境下)：

```python
# 假设在 Meson 的配置阶段
kernel32_lib = compiler.find_library('kernel32', env, [])
if kernel32_lib:
    print(f"找到 kernel32 库: {kernel32_lib}")
else:
    print("未能找到 kernel32 库")
```

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

*   **二进制底层:** `symbols_have_underscore_prefix` 方法涉及检查编译后的二进制文件，这与理解目标平台的 ABI（应用程序二进制接口）密切相关。不同的平台和编译器可能使用不同的符号修饰规则（例如，在符号前加下划线）。
*   **Linux:**  `get_library_naming` 方法中处理了 Linux 共享库的命名约定（`.so`）。`thread_flags` 方法中使用了 `-pthread` 标志，这是 Linux 上用于支持多线程的常见编译选项。
*   **Android 内核及框架:** 虽然代码中没有直接提及 Android 特有的 API，但 `has_function` 和 `find_library` 等方法可以用于检测 Android 系统库 (如 `libc.so`, `libbinder.so` 等) 中是否存在特定的函数或库。例如，检查 `android_log_print` 函数是否存在可以用于判断目标是否是 Android 环境。
*   **macOS Frameworks:** `find_framework_paths` 和 `find_framework` 方法专门处理 macOS 的 Frameworks，这涉及到 macOS 特有的动态库组织形式。代码中还使用了 `lipo` 命令来检查库是否支持目标架构，这是 macOS 下处理通用二进制文件的常见做法。

**逻辑推理及假设输入与输出:**

**示例：`has_function` 方法**

*   **假设输入:** `funcname="pthread_create"`, `prefix="#include <pthread.h>"`, `env` (包含目标平台信息), `extra_args=None`, `dependencies=None`
*   **逻辑推理:**
    1. 首先尝试直接链接 `-lpthread`，如果成功则返回 `(True, False)` (假设未缓存)。
    2. 如果失败，则编译一个包含 `#include <pthread.h>` 和调用 `pthread_create` 的测试程序，并尝试链接。
    3. 如果链接成功，则返回 `(True, False)`。
    4. 如果仍然失败，可能检查 `pthread_create` 是否是编译器内置函数。
*   **可能输出:** `(True, False)` 如果找到了 `pthread_create` 的定义。 `(False, False)` 如果没有找到。

**涉及用户或编程常见的使用错误及举例说明:**

*   **库名错误:** 用户在使用 `find_library` 时，可能输入错误的库名，例如将 `libssl` 误写成 `ssl`。这将导致 `find_library` 找不到库。
*   **缺少头文件:**  在使用 `has_function` 时，如果 `prefix` 中没有包含所需的头文件，即使函数存在，`has_function` 也可能返回 `False`，因为它无法找到函数的声明。
*   **路径配置错误:**  如果用户提供的 `extra_dirs` 路径不正确，`find_library` 将无法在指定的位置找到库文件。
*   **目标架构不匹配:** 在 macOS 上，如果尝试链接一个只支持其他架构的库，即使文件存在，`_get_file_from_list` 中的架构检查也会拒绝该库。
*   **误用 `has_argument` 检查链接器参数:** 代码中已经有警告指出，`has_argument` 系列方法主要用于检查编译器参数，用于检查链接器参数可能会得到错误的结果，应该使用 `has_multi_link_arguments`。

**用户操作是如何一步步的到达这里，作为调试线索:**

当 Frida 的开发者或贡献者在为新的平台或编译器配置构建系统时，或者当 Meson 构建系统在编译 Frida 的 Gum 库时遇到与编译器或链接器相关的问题，就可能会触发对 `CLikeCompiler` 中方法的调用。

**调试线索示例:**

1. **配置阶段失败:**  如果在 `meson.build` 文件中使用了 `compiler.has_function()` 或 `compiler.find_library()`，并且由于目标环境的特殊性导致这些检查失败，Meson 会抛出错误，指示配置失败。开发者可能需要检查 `CLikeCompiler` 中相关方法的实现，以理解为什么检查失败。
2. **链接错误:**  如果在编译 Frida 的 Gum 库时出现链接错误，例如找不到特定的库或符号，开发者可能需要检查 `CLikeCompiler` 的 `get_library_naming()` 和 `find_library()` 方法，以确认 Meson 是否正确地找到了所需的库文件。
3. **平台兼容性问题:**  当尝试将 Frida 移植到新的操作系统或架构时，可能会遇到与库命名约定、符号修饰或系统调用差异相关的问题。调试这些问题可能需要深入研究 `CLikeCompiler` 中处理特定平台逻辑的代码，例如 `_sort_shlibs_openbsd()` 或 macOS 相关的代码。
4. **构建选项问题:**  如果用户提供的编译选项（例如 CFLAGS）导致编译或链接失败，开发者可能需要检查 `has_arguments()` 或 `has_multi_arguments()` 方法，以确认 Meson 是否正确地检测了这些选项的支持情况。

总而言之，`CLikeCompiler` mixin 类是 Frida 构建系统中处理与 C 语言兼容的编译器交互的核心组件，它提供了一系列用于探测编译器特性、查找库文件和验证编译/链接选项的功能，这对于确保 Frida 能够在各种目标平台上正确构建和运行至关重要。虽然它本身不执行逆向操作，但其功能是构建逆向工程工具的基础。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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