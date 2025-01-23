Response:
The user wants to understand the functionality of the provided Python code snippet from the `clike.py` file in the Frida project. This file seems to contain a mixin class that provides common functionalities for C-like compilers within the Meson build system.

Here's a plan to address the user's request:

1. **High-level overview:** Summarize the general purpose of the `ClikeCompilerMixin`.
2. **Functionality breakdown:** Go through each method and explain its role.
3. **Reverse engineering relevance:** Identify methods useful for reverse engineering and provide examples.
4. **Low-level/kernel/framework knowledge:** Highlight methods that interact with or require knowledge of these areas.
5. **Logical reasoning:** Find methods with conditional logic and provide example inputs and outputs.
6. **Common user errors:** Identify potential pitfalls in using these methods.
7. **Debugging context:** Explain how a user might end up interacting with this code during debugging.
8. **Overall summarization:** Concisely restate the mixin's function.
这是 `frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/mixins/clike.py` 文件（Frida 动态 instrumentation 工具的一部分）的第二部分源代码。此文件定义了一个名为 `ClikeCompilerMixin` 的 mixin 类，它为处理类 C 语言的编译器提供了一系列通用功能，这些功能被 Meson 构建系统用于执行各种编译和链接时的检查。

**归纳一下它的功能：**

`ClikeCompilerMixin` 提供了各种用于查询和检查 C-like 编译器的能力和特性的方法。这些方法被 Meson 构建系统用来确定在特定平台上如何正确地编译和链接代码。它抽象了不同编译器的差异，提供了一组统一的接口来进行常见的编译任务和检查。

**具体功能列举：**

* **库查找相关:**
    * `get_library_naming`:  根据目标平台和库类型（静态或动态）返回可能的库命名模式（例如 "libfoo.so", "foo.dll", "libfoo.a"）。
    * `_sort_shlibs_openbsd`: 对 OpenBSD 系统上的共享库列表进行排序，考虑到版本号。
    * `_get_trials_from_pattern`: 根据给定的命名模式，在指定目录下生成可能的库文件路径列表。
    * `_get_file_from_list`: 检查给定路径列表中是否存在实际的文件，并在 macOS 上检查库的架构是否匹配。
    * `output_is_64bit`:  通过编译一个简单的程序并检查 `void *` 的大小来判断编译器生成的是 64 位还是 32 位代码。
    * `_find_library_real`: 执行实际的库查找逻辑，尝试使用 `-l` 链接选项或搜索具体的库文件。
    * `_find_library_impl`: `_find_library_real` 的包装器，带有缓存机制。
    * `find_library`:  查找指定的库，并返回用于链接它的参数（例如库文件的路径或 `-l` 选项）。
    * `find_framework_paths`: (macOS) 查找框架（Framework）的搜索路径。
    * `_find_framework_real`: (macOS) 执行实际的框架查找逻辑。
    * `_find_framework_impl`: `_find_framework_real` 的包装器，带有缓存机制。
    * `find_framework`: (macOS) 查找指定的框架，并返回用于链接它的参数。

* **编译和链接参数处理:**
    * `get_crt_compile_args`: 获取与 C 运行时库相关的编译参数。
    * `get_crt_link_args`: 获取与 C 运行时库相关的链接参数。
    * `thread_flags`: 返回用于启用线程支持的编译/链接标志 (例如 `-pthread`)。
    * `linker_to_compiler_args`: 将链接器参数转换为可以传递给编译器的参数。
    * `has_arguments`:  检查编译器是否接受给定的参数列表。
    * `_has_multi_arguments`: `has_arguments` 的包装器，用于检查多个编译器参数，并考虑了 `-Wno-` 和 `-W` 的情况。
    * `has_multi_arguments`: 检查编译器是否接受多个编译参数。
    * `_has_multi_link_arguments`: 检查链接器是否接受给定的参数列表。
    * `has_multi_link_arguments`: 检查链接器是否接受多个链接参数。

* **编译器特性检查:**
    * `get_has_func_attribute_extra_args`:  获取用于检查函数属性支持的额外编译器参数。
    * `has_func_attribute`: 检查编译器是否支持特定的函数属性（例如 `dllimport`, `dllexport`）。
    * `get_assert_args`: 返回用于启用或禁用 `assert` 宏的编译器参数 (`-DNDEBUG`)。

* **预处理器:**
    * `get_preprocessor`: 返回一个配置为预处理器的编译器实例。

**与逆向的方法的关系及举例说明：**

* **库查找 (`find_library`, `find_framework`):**  在逆向工程中，可能需要链接到特定的库或框架。`ClikeCompilerMixin` 的这些方法可以帮助确定这些库或框架在目标系统上的位置以及如何正确链接它们。
    * **例子:**  如果 Frida 需要链接到 `libssl` 进行安全通信，`find_library('ssl', env, [])` 可以找到 `libssl.so` 或 `libssl.a` 的路径，或者返回 `-lssl` 这样的链接选项。
* **编译器特性检查 (`has_function`, `has_type`, `has_members`, `has_func_attribute`):** 在编写与目标进程交互的代码时，了解目标环境的编译器特性非常重要。例如，需要知道某个函数是否存在，某个类型是否定义，或者是否支持特定的函数属性。
    * **例子:** 在 Frida 脚本中，可能需要调用目标进程中的某个函数。`has_function('pthread_create', '', env)` 可以检查目标系统上是否存在 `pthread_create` 函数。
* **判断目标架构 (`output_is_64bit`):** 在动态插桩中，需要知道目标进程是 32 位还是 64 位，以便正确地处理内存地址和数据类型。
    * **例子:** Frida 需要根据目标进程的架构选择正确的代码注入方法。`output_is_64bit(env)` 可以帮助确定目标架构。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明：**

* **库命名约定 (`get_library_naming`):** 了解不同操作系统（如 Linux、Android、Windows、macOS）上共享库和静态库的命名约定（例如 `.so`, `.dll`, `.a`, `.dylib`）是与底层系统交互的基础。
    * **例子:** 在 Linux 上，动态链接库通常以 `.so` 结尾，而静态库以 `.a` 结尾。Android 上也使用 `.so` 文件。`get_library_naming` 方法会根据目标平台返回相应的后缀。
* **共享库版本 (`_sort_shlibs_openbsd`):**  某些操作系统，如 OpenBSD，其共享库文件名包含版本信息。正确处理这些版本号对于链接到正确的库版本至关重要。
* **框架 (`find_framework_paths`, `find_framework`):**  macOS 系统广泛使用框架，框架是包含库、头文件和资源文件的目录结构。理解框架的概念以及如何查找和链接框架是 macOS 逆向的重要组成部分。
* **线程标志 (`thread_flags`):** 在多线程环境中，需要使用特定的编译器/链接器标志来启用线程支持，例如 Linux 上的 `-pthread`。
* **C 运行时库 (`get_crt_compile_args`, `get_crt_link_args`):**  所有 C 和 C++ 程序都依赖于 C 运行时库。了解如何链接到正确的运行时库对于确保程序的正常运行至关重要。

**如果做了逻辑推理，请给出假设输入与输出：**

* **`has_function(funcname='malloc', prefix='', env=Environment)`:**
    * **假设输入:** `funcname` 为 "malloc"，`prefix` 为空字符串，`env` 是代表当前构建环境的对象。
    * **可能输出:** `(True, False)`。表示 `malloc` 函数存在，且结果不是从缓存中获取的。
* **`find_library(libname='ssl', env=Environment, extra_dirs=[])`:**
    * **假设输入:** `libname` 为 "ssl"，`env` 是代表 Linux 构建环境的对象，`extra_dirs` 为空列表。
    * **可能输出:** `['-lssl']` 或 `['/usr/lib/x86_64-linux-gnu/libssl.so']`。具体取决于系统上 `libssl` 的安装方式和 Meson 的查找策略。
* **`output_is_64bit(env=Environment)`:**
    * **假设输入:** `env` 是代表一个 64 位 Linux 构建环境的对象。
    * **可能输出:** `True`。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

* **在 `find_library` 中提供错误的库名：** 用户可能拼写错误库名，或者尝试查找一个不存在的库。这会导致 `find_library` 返回 `None`。
    * **例子:** `find_library('ssll', env, [])` (注意拼写错误)。
* **在 `has_function` 中提供错误的函数名或缺少必要的头文件：**  如果用户检查一个不存在的函数，或者没有在 `prefix` 中包含定义该函数的头文件，`has_function` 将返回 `False`。
    * **例子:** `has_function('non_existent_function', '', env)`。
* **在交叉编译环境中，假设主机环境的库存在于目标环境：**  用户可能会错误地认为主机系统上的库在目标系统上也可用，而实际上需要为目标平台提供相应的库。
* **在 `find_framework` 中忘记添加额外的搜索路径：** 如果要查找的框架不在标准的系统路径中，用户需要在 `extra_dirs` 参数中指定框架所在的目录。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

用户通常不会直接操作 `clike.py` 文件。他们会通过 Meson 的构建定义文件 (`meson.build`) 来间接地使用这些功能。以下是一些可能导致 Meson 执行到 `clike.py` 中代码的场景：

1. **使用 `find_library()` 或 `dependency()` 函数:** 当 `meson.build` 文件中使用 `find_library()` 函数来查找库，或者使用 `dependency()` 函数来查找依赖项时，Meson 内部会调用 `ClikeCompilerMixin` 中相应的 `find_library` 方法。
2. **使用 `check_function_exists()` 函数:** `meson.build` 文件中的 `check_function_exists()` 函数会调用 `ClikeCompilerMixin` 的 `has_function` 方法来检查函数是否存在。
3. **使用 `check_type_size()` 或 `check_struct_has_members()` 函数:** 这些函数会分别调用 `has_type` 和 `has_members` 方法。
4. **配置依赖项:** 当 Meson 需要确定依赖项的链接方式和编译器标志时，会使用 `ClikeCompilerMixin` 中的方法来检查编译器的特性。
5. **执行 `meson setup` 命令:** 在执行 `meson setup` 命令时，Meson 会探测编译器的能力和特性，这会触发 `ClikeCompilerMixin` 中各种检查方法的调用.

如果在构建过程中遇到链接错误或编译错误，并且怀疑是由于 Meson 无法找到正确的库或编译器特性导致的，开发者可能会查看 Meson 的日志输出，这些日志可能会显示与 `clike.py` 中方法相关的调试信息。例如，如果 `find_library` 失败，日志可能会显示尝试过的库文件路径。

总之，`ClikeCompilerMixin` 是 Meson 构建系统中一个核心组件，它负责抽象不同 C-like 编译器的差异，并提供用于执行各种编译时检查的关键功能，从而确保构建过程的正确性。用户通过 Meson 的高级 API 间接地使用这些功能。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/compilers/mixins/clike.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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