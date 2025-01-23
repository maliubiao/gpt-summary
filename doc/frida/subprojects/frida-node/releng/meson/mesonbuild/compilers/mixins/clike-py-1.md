Response:
The user is asking for a functional breakdown of the provided Python code snippet, which is part of the Frida dynamic instrumentation tool. The specific file is `clike.py`, suggesting it defines functionalities common to C-like compilers.

I need to analyze each method within the class and explain its purpose. Furthermore, I need to connect these functionalities to reverse engineering, binary internals, OS kernels/frameworks, logical reasoning, and common user errors, providing examples where applicable. Finally, I need to summarize the overall purpose of the code.

Here's a plan:

1. **Iterate through each method:** Explain its core function.
2. **Reverse Engineering Relevance:**  Identify how the function aids in reverse engineering tasks (e.g., checking for function existence).
3. **Binary/Kernel/Framework Knowledge:**  Point out aspects that interact with or require understanding of these areas (e.g., checking library existence, handling shared libraries).
4. **Logical Reasoning:**  Analyze methods that perform conditional checks or deductions (e.g., determining symbol prefix).
5. **User/Programming Errors:** Identify potential mistakes users might make that these checks aim to address (e.g., incorrect library paths).
6. **User Journey (Debugging Clue):**  Trace back how a user's actions might lead to this code being executed (e.g., using `meson` to build a project).
7. **Summarize Functionality:** Provide a concise overview of the code's purpose.
这是 Frida 动态注入工具中 `frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/mixins/clike.py` 文件的第二部分源代码。它定义了一个名为 `CLikeCompiler` 的类，该类旨在为 C 风格的编译器提供一系列功能，主要用于在构建过程中进行各种编译器的特性和功能检查。以下是其功能的详细说明：

**核心功能归纳：**

总的来说，`CLikeCompiler` 类的主要功能是提供一系列工具方法，用于在构建时 **探测目标编译器的特性、库的存在性、头文件的可用性、以及进行一些底层的平台相关的检查**。这些检查对于确保构建过程能够正确地配置和生成适用于目标平台的二进制文件至关重要。

**具体功能列举：**

1. **`_have_prototype_templ()` 和 `_no_prototype_templ()`:**
   - **功能:**  生成用于检查函数是否存在的小型 C 代码片段。`_have_prototype_templ` 假设用户提供的头文件中已经声明了函数原型，而 `_no_prototype_templ` 则不作此假设。
   - **与逆向的关系:** 在逆向工程中，需要确定目标程序是否使用了特定的函数。此功能可以通过在构建时检查目标平台上该函数是否存在来辅助判断。
   - **二进制底层/内核/框架知识:** 涉及到 C 语言的函数定义和声明的基本概念。
   - **逻辑推理:** 根据是否在用户提供的 `prefix` 中找到了 `#include` 指令来选择使用哪个模板。
   - **用户错误:** 用户可能忘记在 `prefix` 中包含必要的头文件，导致 `_have_prototype_templ` 无法正确检查函数存在性。

2. **`has_function()`:**
   - **功能:**  判断指定的函数在当前编译器环境下是否存在。它会尝试链接到该函数，如果链接成功则认为函数存在。它还检查该函数是否是编译器的内建函数。
   - **与逆向的关系:**  这是逆向分析中非常重要的一个环节。可以用来确定目标程序依赖哪些库和函数。
   - **二进制底层/内核/框架知识:**  涉及到链接过程，编译器如何查找符号，以及内建函数的概念。对于检查内核函数或框架函数，需要相应的头文件和库。
   - **逻辑推理:** 首先尝试链接标准库，然后检查用户提供的头文件，最后检查是否为内建函数。
   - **假设输入与输出:**
     - **输入:** `funcname="pthread_create"`, `prefix="#include <pthread.h>"`, `env` (构建环境)。
     - **可能输出:** `(True, False)`，表示函数存在且未从缓存中获取结果。
   - **用户错误:** 用户可能拼写错误的函数名，或者提供的 `prefix` 中缺少包含函数声明的头文件。

3. **`has_members()`:**
   - **功能:**  检查指定的结构体或联合体是否包含指定的成员。
   - **与逆向的关系:** 在分析数据结构时很有用。通过检查成员的存在性，可以推断数据结构的布局。
   - **二进制底层知识:** 涉及到 C 语言的结构体和联合体的内存布局。
   - **用户错误:** 用户可能提供了不存在的成员名或者错误的类型名。

4. **`has_type()`:**
   - **功能:**  检查指定的类型名在当前编译器环境下是否有效。
   - **与逆向的关系:** 确定目标程序中使用的数据类型。
   - **二进制底层知识:** 涉及到 C 语言的数据类型。
   - **用户错误:** 用户可能提供了不存在的类型名。

5. **`_symbols_have_underscore_prefix_searchbin()`, `_symbols_have_underscore_prefix_define()`, `_symbols_have_underscore_prefix_list()`, `symbols_have_underscore_prefix()`:**
   - **功能:**  确定当前编译器是否会在全局 C 符号前添加下划线前缀。不同的平台和编译器有不同的命名约定。
   - **与逆向的关系:**  在符号查找和符号重定向时至关重要。例如，在进行动态链接时，需要知道符号的实际名称。
   - **二进制底层/Linux/Android内核及框架知识:** 涉及到不同操作系统和架构的符号命名约定，例如 Windows 系统下 x86 架构的 C 符号通常有下划线前缀。
   - **逻辑推理:**  依次尝试不同的方法来判断前缀：查询编译器预定义宏、查阅已知平台列表、编译并检查二进制文件。
   - **用户操作到达这里:**  Meson 在配置构建环境时会自动执行这些检查。

6. **`_get_patterns()`, `get_library_naming()`:**
   - **功能:**  生成不同平台上共享库和静态库的文件名模式。例如，Linux 下共享库可能是 `libfoo.so`，静态库可能是 `libfoo.a`。Windows 下可能是 `foo.dll` 或 `foo.lib`。
   - **与逆向的关系:**  在逆向工程中，需要定位目标程序依赖的库文件。这些模式可以帮助定位这些库。
   - **二进制底层/Linux/Android内核及框架知识:**  涉及到不同操作系统的库文件命名约定和动态链接的知识。
   - **用户错误:** 用户可能错误地指定了库名或路径，导致 Meson 无法找到库文件。

7. **`_sort_shlibs_openbsd()`:**
   - **功能:**  对 OpenBSD 系统下的共享库文件名进行排序，以便选择最新的版本。OpenBSD 的共享库命名约定包含版本号。
   - **二进制底层/Linux/Android内核及框架知识:**  OpenBSD 特有的共享库版本控制机制。

8. **`_get_trials_from_pattern()`:**
   - **功能:**  根据文件名模式和库名，生成可能的库文件路径列表。

9. **`_get_file_from_list()`:**
   - **功能:**  检查给定的文件路径列表，判断是否存在可用的库文件。在 macOS 上还会检查库文件的架构是否与当前目标架构匹配。
   - **二进制底层知识:**  涉及到文件系统操作和 macOS 下的 Mach-O 文件格式以及架构信息。

10. **`output_is_64bit()`:**
    - **功能:**  判断编译器生成的目标代码是 64 位还是 32 位。
    - **二进制底层知识:**  涉及到指针大小的概念，64 位系统指针通常为 8 字节，32 位系统为 4 字节。

11. **`_find_library_real()`, `_find_library_impl()`, `find_library()`:**
    - **功能:**  在指定的目录和系统默认库路径中查找指定的库文件。
    - **与逆向的关系:**  帮助确定目标程序链接了哪些外部库。
    - **二进制底层/Linux/Android内核及框架知识:**  涉及到库的搜索路径、静态链接和动态链接的知识。
    - **用户错误:** 用户可能提供了错误的库名或库路径。

12. **`find_framework_paths()`, `_find_framework_real()`, `_find_framework_impl()`, `find_framework()`:**
    - **功能:**  在 macOS 系统中查找指定的 Framework。Framework 是 macOS 上组织库和头文件的一种方式。
    - **与逆向的关系:**  在逆向 macOS 应用程序时，需要了解其使用的 Framework。
    - **二进制底层/Linux/Android内核及框架知识:**  macOS 特有的 Framework 概念。
    - **用户操作到达这里:**  当 Meson 构建针对 macOS 平台的项目，并且项目依赖 Framework 时。

13. **`get_crt_compile_args()`, `get_crt_link_args()`:**
    - **功能:**  获取与 C 运行时库（CRT）相关的编译和链接参数。
    - **二进制底层知识:**  涉及到 C 运行时库的概念，例如 `libc`。

14. **`thread_flags()`:**
    - **功能:**  获取用于线程支持的编译标志，例如 `-pthread`。
    - **Linux/Android内核及框架知识:**  涉及到多线程编程和 POSIX 线程标准。

15. **`linker_to_compiler_args()`:**
    - **功能:**  将链接器参数转换为可以传递给编译器的参数。

16. **`has_arguments()`:**
    - **功能:**  检查编译器是否接受指定的编译参数。
    - **用户错误:** 用户可能使用了当前编译器不支持的编译参数。

17. **`_has_multi_arguments()`, `has_multi_arguments()`:**
    - **功能:**  检查编译器是否接受多个编译参数。

18. **`_has_multi_link_arguments()`, `has_multi_link_arguments()`:**
    - **功能:**  检查链接器是否接受多个链接参数。
    - **用户错误:** 用户可能使用了当前链接器不支持的链接参数。

19. **`_concatenate_string_literals()`:**
    - **功能:**  连接 C 风格的字符串字面量。

20. **`get_has_func_attribute_extra_args()`, `has_func_attribute()`:**
    - **功能:**  检查编译器是否支持特定的函数属性，例如 `dllimport` 或 `dllexport`。
    - **与逆向的关系:**  了解函数属性可以帮助理解函数的用途和行为，例如 `dllimport` 表明函数是从动态链接库导入的。
    - **二进制底层知识:**  涉及到编译器扩展和函数属性的概念。

21. **`get_assert_args()`:**
    - **功能:**  获取启用或禁用断言的编译参数，例如 `-DNDEBUG`。

22. **`can_compile()`:**
    - **功能:**  判断给定的源文件是否可以被编译。

23. **`get_preprocessor()`:**
    - **功能:**  获取一个配置为预处理器的编译器实例。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户尝试使用 Frida 构建一个项目或模块，该项目使用了 `frida-node`。**
2. **Meson 作为构建系统被调用来配置构建。**
3. **Meson 在配置阶段会根据目标平台和编译器，实例化相应的编译器对象，其中包括 `CLikeCompiler` 的子类实例。**
4. **在配置过程中，Meson 需要检查编译器的各种特性和功能。**
5. **例如，如果项目代码使用了特定的 C 函数，Meson 可能会调用 `has_function()` 来检查该函数在目标平台上是否存在。**
6. **如果项目依赖于某个外部库，Meson 可能会调用 `find_library()` 来查找该库文件。**
7. **如果目标平台是 macOS 并且项目依赖于 Framework，Meson 可能会调用 `find_framework()`。**
8. **在这些检查过程中，`CLikeCompiler` 类中定义的方法会被调用，以生成测试代码、编译测试代码、链接测试代码，并根据结果判断特性或功能是否存在。**
9. **如果某个检查失败，Meson 可能会抛出错误，指示用户缺少必要的依赖或编译器不支持某些特性。**

总而言之，`CLikeCompiler` 类及其方法在 Frida 的构建过程中扮演着关键角色，负责进行各种编译时检查，确保构建过程的正确性和生成适用于目标平台的二进制文件。 这对于像 Frida 这样的跨平台动态注入工具尤其重要，因为它需要在各种不同的操作系统和架构上运行。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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