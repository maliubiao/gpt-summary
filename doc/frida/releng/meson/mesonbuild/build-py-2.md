Response:
The user wants me to analyze a Python source code file from the Frida project.
Specifically, they are asking for the functionalities implemented in the code snippet provided.

Here's a plan to address the request:

1. **Identify the main classes and their roles:**  Look for class definitions and their primary responsibilities.
2. **Analyze the methods within the classes:** Understand the actions each method performs.
3. **Relate the functionalities to reverse engineering:** Determine if any functions are directly involved in or facilitate reverse engineering tasks.
4. **Identify interactions with low-level concepts:** Look for code that interacts with binary files, operating systems (Linux, Android), or kernel concepts.
5. **Analyze logical reasoning within the code:** Identify conditional statements and their implications. Provide examples of inputs and outputs based on the logic.
6. **Pinpoint common user errors:** Identify scenarios where incorrect usage of the defined classes or methods could lead to errors.
7. **Trace user actions leading to this code:** Explain how a user interacting with Frida might end up executing this specific part of the code.
8. **Summarize the functionalities:** Provide a concise overview of the code's purpose.
这是 Frida 动态 instrumentation 工具源代码文件 `frida/releng/meson/mesonbuild/build.py` 的第三部分，主要包含了构建目标（Build Targets）的定义和相关操作，特别是关于链接（linking）操作。 让我们逐一分析其功能并关联到逆向、底层知识和常见错误。

**核心功能归纳：**

这部分代码主要负责定义和处理 Frida 项目中各种需要链接的构建目标（例如，库、可执行文件），并确保链接过程的正确性。核心功能包括：

* **管理链接依赖:**  维护构建目标需要链接的其他目标（`link_targets`）和需要完整链接的目标（`link_whole_targets`）。
* **处理外部库依赖:**  强制使用 `dependencies` 关键字来指定外部库，防止在 `link_with` 中误用，以明确区分项目内部构建的库和外部依赖。
* **链接类型检查:**  验证链接目标的类型是否正确（例如，只能链接可链接的目标），并根据目标类型执行不同的链接策略。
* **静态库捆绑:**  当一个静态库链接到另一个内部静态库时，会将被链接库的目标文件捆绑到自身，尤其是在安装时，需要确保所有依赖的未安装静态库的目标文件也被包含进来。
* **PIC (Position Independent Code) 检查:**  防止将非 PIC 的静态库链接到共享库中，这是共享库的基本要求。
* **跨架构链接检查:**  在交叉编译环境中，严格禁止混合不同架构的库进行链接。
* **预编译头文件 (PCH) 处理:**  允许为构建目标指定预编译头文件，提高编译效率。
* **包含目录管理:**  允许添加包含目录，并能指定是否为系统包含目录。
* **确定链接器:**  根据目标使用的编程语言以及依赖库的语言，选择合适的链接器。
* **处理 Rust 相关链接:**  特殊处理 Rust 语言的链接，包括对 Rust ABI 库的链接限制。
* **MSVC 特性处理:**  判断是否使用 MSVC 链接器，用于处理 Windows 平台特定的文件命名和调试信息。
* **共享模块链接警告:**  对链接到共享模块的行为发出警告或报错，并可能自动设置 `force_soname` 属性。
* **处理 Visual Studio 模块定义文件 (`.def`)**: 允许指定 `.def` 文件来控制符号导出。
* **生成器 (Generator) 功能:**  定义了 `Generator` 类，用于描述如何通过外部程序生成文件，并提供了 `GeneratedList` 类来管理生成器的输出。

**与逆向方法的关联及举例：**

* **动态库链接 (`SharedLibrary`)：** Frida 本身就是一个动态库，其核心功能依赖于能够被目标进程加载。这里的链接逻辑确保了 Frida 库依赖的正确性，这对于逆向工程师使用 Frida 脚本注入目标进程至关重要。例如，如果 Frida 库依赖了某个加密库，这里的链接操作会确保该加密库也被正确链接，使得 Frida 能够调用加密功能进行 hook 或数据解密。
* **静态库链接 (`StaticLibrary`) 和完整链接 (`link_whole`)：**  在某些情况下，Frida 可能需要将一些功能编译为静态库，然后完整地链接到 Frida 动态库中。这可以避免符号冲突，或者在某些平台上是必须的操作。例如，某些底层的 hook 实现可能被编译成静态库，然后通过 `link_whole` 链接到 Frida 核心库，确保这些 hook 代码在运行时可用。
* **可执行文件生成 (`Executable`)：**  Frida 工具链中包含一些命令行工具，例如 `frida-server`。这里的 `Executable` 类定义了如何构建这些可执行文件，包括链接必要的库。逆向工程师可以通过运行 `frida-server` 在目标设备上部署 Frida 服务。
* **处理 Rust 代码 (`uses_rust`, `uses_rust_abi`)：**  Frida 的某些组件可能使用 Rust 编写。这部分代码处理了 Rust 代码的链接，例如确保 Rust ABI 兼容性。逆向工程师在使用涉及 Rust 编写的 Frida 模块时，底层的链接操作需要正确处理 Rust 的依赖。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例：**

* **PIC 检查 (`pic` option)：**  位置无关代码 (PIC) 是构建共享库的关键，因为它需要在运行时被加载到任意内存地址。Android 系统广泛使用共享库，因此 Frida 在 Android 上的工作依赖于正确的 PIC 代码生成和链接。例如，当构建 Frida 的 Android 桥接库时，会强制要求所有链接到该库的静态库都必须使用 PIC 编译。
* **动态链接器 (`get_clink_dynamic_linker_and_stdlibs`)：**  Linux 和 Android 系统使用动态链接器加载共享库。这部分代码负责根据目标使用的语言选择合适的链接器，并处理标准库的链接。例如，如果一个 Frida 模块同时使用了 C 和 C++ 代码，链接器需要同时链接 C 和 C++ 的标准库。
* **共享模块 (`SharedModule`) 和 `force_soname`：**  在 Android 上，共享模块 (SharedModule) 的链接顺序非常重要。`force_soname` 属性用于强制为共享模块生成固定的 soname，以便在运行时正确加载。Frida 在 Android 平台上可能使用共享模块来实现某些功能，例如实现特定的 hook 机制。
* **预编译头文件 (`add_pch`)：**  在大型项目中，预编译头文件可以显著加速编译过程。这在编译 Frida 这样复杂的项目时尤为重要。例如，可以为 Frida 的核心 C++ 代码创建一个预编译头文件，包含常用的头文件，从而减少编译时间。
* **可执行文件的后缀 (`suffix`)：**  不同的操作系统和 CPU 架构对可执行文件有不同的后缀名（例如，`.exe` 在 Windows 上，没有后缀在 Linux 上）。这段代码根据目标平台和使用的编译器设置正确的可执行文件后缀。例如，在 Android 上构建 `frida-server` 时，通常没有后缀。

**逻辑推理及假设输入与输出：**

* **假设输入：**  一个名为 `my_frida_module` 的共享库目标，它需要链接到一个名为 `my_hook_lib` 的内部静态库。`my_hook_lib` 并没有设置为安装 (`install=False`)，而 `my_frida_module` 设置为安装 (`install=True`)。
* **逻辑推理：** 代码中的条件 `isinstance(self, StaticLibrary) and self.install and t.is_internal()` 会判断当前目标是否为需要安装的静态库，并且链接的目标是内部库。由于 `my_frida_module` 是共享库，这个条件不满足。但是，代码会继续处理 `SharedLibrary` 链接 `StaticLibrary` 的情况。
* **假设 `my_hook_lib` 没有使用 PIC 编译。**
* **代码中的条件：** `isinstance(self, SharedLibrary) and isinstance(t, StaticLibrary) and not t.pic` 会被触发。
* **输出：**  会抛出一个 `InvalidArguments` 异常，提示用户 `my_hook_lib` 应该使用 PIC 编译。

* **假设输入：**  一个自定义目标 `my_codegen` 生成了一些 C 代码文件。另一个共享库目标 `my_app` 需要链接这些生成的 C 代码。
* **逻辑推理：**  `my_app` 的 `link_with` 参数包含了 `my_codegen`。
* **代码中的条件：**  `isinstance(t, (CustomTarget, CustomTargetIndex))` 会被触发。
* **输出：**  `my_codegen` 会被添加到 `my_app` 的 `link_targets` 列表中。Meson 会在构建 `my_app` 时，确保先构建 `my_codegen`，并将 `my_codegen` 的输出作为链接 `my_app` 的输入。

**用户或编程常见的使用错误及举例：**

* **在 `link_with` 中使用外部库：**  用户可能会错误地将一个通过 `dependency()` 函数找到的外部库添加到 `link_with` 参数中。代码会抛出 `MesonException`，提示用户应该使用 `dependencies` 关键字。
    ```python
    # 错误示例
    mylib = shared_library('mylib', 'mylib.c', link_with: libcrypto)
    ```
    正确的做法是：
    ```python
    libcrypto = dependency('libcrypto')
    mylib = shared_library('mylib', 'mylib.c', dependencies: libcrypto)
    ```
* **将非 PIC 的静态库链接到共享库：**  用户可能会尝试将一个没有使用 `-fPIC` 编译的静态库链接到一个共享库。代码会抛出 `InvalidArguments` 异常，提示用户应该使用 `pic: true` 选项编译静态库。
    ```python
    # 假设 my_static_lib 没有使用 PIC 编译
    my_static_lib = static_library('my_static_lib', 'my_static.c')
    my_shared_lib = shared_library('my_shared_lib', 'my_shared.c', link_with: my_static_lib) # 报错
    ```
    正确的做法是：
    ```python
    my_static_lib = static_library('my_static_lib', 'my_static.c', pic: true)
    my_shared_lib = shared_library('my_shared_lib', 'my_shared.c', link_with: my_static_lib)
    ```
* **在交叉编译中混合不同架构的库：**  在进行交叉编译时，用户可能会尝试链接为主机架构编译的库到为目标架构编译的目标文件中。代码会抛出 `InvalidArguments` 异常，明确指出这是不允许的。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件:** 用户定义了 Frida 项目的构建规则，包括声明需要构建的库、可执行文件以及它们之间的依赖关系。例如，用户可能定义了一个共享库，并使用 `link_with` 或 `dependencies` 关键字指定了其依赖的其他库。
2. **用户运行 `meson` 命令配置构建:** 用户执行 `meson setup builddir` 命令，Meson 会解析 `meson.build` 文件，并根据用户的配置和系统环境生成构建系统所需的文件。
3. **Meson 解析 `meson.build` 文件并创建构建目标对象:**  在解析过程中，当遇到 `shared_library()`、`static_library()` 或 `executable()` 等函数时，Meson 会创建相应的对象，例如 `SharedLibrary`、`StaticLibrary` 或 `Executable` 的实例。这些实例存储了构建目标的各种属性，包括链接依赖。
4. **Meson 处理 `link_with` 和 `dependencies` 参数:** 当处理这些参数时，Meson 会调用这部分代码中的方法，例如 `link_with()` 和 `link_whole()`，来处理链接依赖关系，并进行各种检查，例如类型检查、PIC 检查和跨架构检查。
5. **如果配置或链接参数有误，Meson 抛出异常并停止:**  如果用户在 `meson.build` 文件中指定了错误的链接参数（例如，在 `link_with` 中使用了外部库，或者尝试链接非 PIC 的静态库到共享库），这段代码中的检查逻辑会发现这些错误，并抛出相应的异常，阻止构建过程继续进行。这些异常信息会作为调试线索反馈给用户，帮助用户定位并修复 `meson.build` 文件中的问题。

**这是第3部分，共5部分，请归纳一下它的功能:**

这部分代码（第3部分）的核心功能是 **定义和管理 Frida 项目中各种构建目标的链接过程，并实施各种规则和检查以确保链接的正确性和兼容性**。它处理了内部库和外部库的链接，检查了链接目标的类型和属性，并考虑了跨平台和跨语言链接的特殊情况，为最终生成可用的 Frida 库和工具奠定了基础。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
 raise MesonException(textwrap.dedent('''\
                        An external library was used in link_with keyword argument, which
                        is reserved for libraries built as part of this project. External
                        libraries must be passed using the dependencies keyword argument
                        instead, because they are conceptually "external dependencies",
                        just like those detected with the dependency() function.
                    '''))
                raise InvalidArguments(f'{t!r} is not a target.')
            if not t.is_linkable_target():
                raise InvalidArguments(f"Link target '{t!s}' is not linkable.")
            if isinstance(self, StaticLibrary) and self.install and t.is_internal():
                # When we're a static library and we link_with to an
                # internal/convenience library, promote to link_whole.
                self.link_whole([t], promoted=True)
                continue
            if isinstance(self, SharedLibrary) and isinstance(t, StaticLibrary) and not t.pic:
                msg = f"Can't link non-PIC static library {t.name!r} into shared library {self.name!r}. "
                msg += "Use the 'pic' option to static_library to build with PIC."
                raise InvalidArguments(msg)
            self.check_can_link_together(t)
            self.link_targets.append(t)

    def link_whole(self, targets: T.List[BuildTargetTypes], promoted: bool = False) -> None:
        for t in targets:
            if isinstance(t, (CustomTarget, CustomTargetIndex)):
                if not t.is_linkable_target():
                    raise InvalidArguments(f'Custom target {t!r} is not linkable.')
                if t.links_dynamically():
                    raise InvalidArguments('Can only link_whole custom targets that are static archives.')
            elif not isinstance(t, StaticLibrary):
                raise InvalidArguments(f'{t!r} is not a static library.')
            elif isinstance(self, SharedLibrary) and not t.pic:
                msg = f"Can't link non-PIC static library {t.name!r} into shared library {self.name!r}. "
                msg += "Use the 'pic' option to static_library to build with PIC."
                raise InvalidArguments(msg)
            self.check_can_link_together(t)
            if isinstance(self, StaticLibrary):
                # When we're a static library and we link_whole: to another static
                # library, we need to add that target's objects to ourselves.
                self._bundle_static_library(t, promoted)
                # If we install this static library we also need to include objects
                # from all uninstalled static libraries it depends on.
                if self.install:
                    for lib in t.get_internal_static_libraries():
                        self._bundle_static_library(lib, True)
            self.link_whole_targets.append(t)

    @lru_cache(maxsize=None)
    def get_internal_static_libraries(self) -> OrderedSet[BuildTargetTypes]:
        result: OrderedSet[BuildTargetTypes] = OrderedSet()
        self.get_internal_static_libraries_recurse(result)
        return result

    def get_internal_static_libraries_recurse(self, result: OrderedSet[BuildTargetTypes]) -> None:
        for t in self.link_targets:
            if t.is_internal() and t not in result:
                result.add(t)
                t.get_internal_static_libraries_recurse(result)
        for t in self.link_whole_targets:
            if t.is_internal():
                t.get_internal_static_libraries_recurse(result)

    def _bundle_static_library(self, t: T.Union[BuildTargetTypes], promoted: bool = False) -> None:
        if self.uses_rust():
            # Rustc can bundle static libraries, no need to extract objects.
            self.link_whole_targets.append(t)
        elif isinstance(t, (CustomTarget, CustomTargetIndex)) or t.uses_rust():
            # To extract objects from a custom target we would have to extract
            # the archive, WIP implementation can be found in
            # https://github.com/mesonbuild/meson/pull/9218.
            # For Rust C ABI we could in theory have access to objects, but there
            # are several meson issues that need to be fixed:
            # https://github.com/mesonbuild/meson/issues/10722
            # https://github.com/mesonbuild/meson/issues/10723
            # https://github.com/mesonbuild/meson/issues/10724
            m = (f'Cannot link_whole a custom or Rust target {t.name!r} into a static library {self.name!r}. '
                 'Instead, pass individual object files with the "objects:" keyword argument if possible.')
            if promoted:
                m += (f' Meson had to promote link to link_whole because {self.name!r} is installed but not {t.name!r},'
                      f' and thus has to include objects from {t.name!r} to be usable.')
            raise InvalidArguments(m)
        else:
            self.objects.append(t.extract_all_objects())

    def check_can_link_together(self, t: BuildTargetTypes) -> None:
        links_with_rust_abi = isinstance(t, BuildTarget) and t.uses_rust_abi()
        if not self.uses_rust() and links_with_rust_abi:
            raise InvalidArguments(f'Try to link Rust ABI library {t.name!r} with a non-Rust target {self.name!r}')
        if self.for_machine is not t.for_machine and (not links_with_rust_abi or t.rust_crate_type != 'proc-macro'):
            msg = f'Tried to tied to mix a {t.for_machine} library ("{t.name}") with a {self.for_machine} target "{self.name}"'
            if self.environment.is_cross_build():
                raise InvalidArguments(msg + ' This is not possible in a cross build.')
            else:
                mlog.warning(msg + ' This will fail in cross build.')

    def add_pch(self, language: str, pchlist: T.List[str]) -> None:
        if not pchlist:
            return
        elif len(pchlist) == 1:
            if not is_header(pchlist[0]):
                raise InvalidArguments(f'PCH argument {pchlist[0]} is not a header.')
        elif len(pchlist) == 2:
            if is_header(pchlist[0]):
                if not is_source(pchlist[1]):
                    raise InvalidArguments('PCH definition must contain one header and at most one source.')
            elif is_source(pchlist[0]):
                if not is_header(pchlist[1]):
                    raise InvalidArguments('PCH definition must contain one header and at most one source.')
                pchlist = [pchlist[1], pchlist[0]]
            else:
                raise InvalidArguments(f'PCH argument {pchlist[0]} is of unknown type.')

            if os.path.dirname(pchlist[0]) != os.path.dirname(pchlist[1]):
                raise InvalidArguments('PCH files must be stored in the same folder.')

            FeatureDeprecated.single_use('PCH source files', '0.50.0', self.subproject,
                                         'Only a single header file should be used.')
        elif len(pchlist) > 2:
            raise InvalidArguments('PCH definition may have a maximum of 2 files.')
        for f in pchlist:
            if not isinstance(f, str):
                raise MesonException('PCH arguments must be strings.')
            if not os.path.isfile(os.path.join(self.environment.source_dir, self.get_source_subdir(), f)):
                raise MesonException(f'File {f} does not exist.')
        self.pch[language] = pchlist

    def add_include_dirs(self, args: T.Sequence['IncludeDirs'], set_is_system: T.Optional[str] = None) -> None:
        ids: T.List['IncludeDirs'] = []
        for a in args:
            if not isinstance(a, IncludeDirs):
                raise InvalidArguments('Include directory to be added is not an include directory object.')
            ids.append(a)
        if set_is_system is None:
            set_is_system = 'preserve'
        if set_is_system != 'preserve':
            is_system = set_is_system == 'system'
            ids = [IncludeDirs(x.get_curdir(), x.get_incdirs(), is_system, x.get_extra_build_dirs(), x.is_build_only_subproject) for x in ids]
        self.include_dirs += ids

    def get_aliases(self) -> T.List[T.Tuple[str, str, str]]:
        return []

    def get_langs_used_by_deps(self) -> T.List[str]:
        '''
        Sometimes you want to link to a C++ library that exports C API, which
        means the linker must link in the C++ stdlib, and we must use a C++
        compiler for linking. The same is also applicable for objc/objc++, etc,
        so we can keep using clink_langs for the priority order.

        See: https://github.com/mesonbuild/meson/issues/1653
        '''
        langs: T.List[str] = []

        # Check if any of the external libraries were written in this language
        for dep in self.external_deps:
            if dep.language is None:
                continue
            if dep.language not in langs:
                langs.append(dep.language)
        # Check if any of the internal libraries this target links to were
        # written in this language
        for link_target in itertools.chain(self.link_targets, self.link_whole_targets):
            if isinstance(link_target, (CustomTarget, CustomTargetIndex)):
                continue
            for language in link_target.compilers:
                if language not in langs:
                    langs.append(language)

        return langs

    def get_prelinker(self):
        if self.link_language:
            comp = self.all_compilers[self.link_language]
            return comp
        for l in clink_langs:
            if l in self.compilers:
                try:
                    prelinker = self.all_compilers[l]
                except KeyError:
                    raise MesonException(
                        f'Could not get a prelinker linker for build target {self.name!r}. '
                        f'Requires a compiler for language "{l}", but that is not '
                        'a project language.')
                return prelinker
        raise MesonException(f'Could not determine prelinker for {self.name!r}.')

    def get_clink_dynamic_linker_and_stdlibs(self) -> T.Tuple['Compiler', T.List[str]]:
        '''
        We use the order of languages in `clink_langs` to determine which
        linker to use in case the target has sources compiled with multiple
        compilers. All languages other than those in this list have their own
        linker.
        Note that Vala outputs C code, so Vala sources can use any linker
        that can link compiled C. We don't actually need to add an exception
        for Vala here because of that.
        '''
        # If the user set the link_language, just return that.
        if self.link_language:
            comp = self.all_compilers[self.link_language]
            return comp, comp.language_stdlib_only_link_flags(self.environment)

        # Since dependencies could come from subprojects, they could have
        # languages we don't have in self.all_compilers. Use the global list of
        # all compilers here.
        all_compilers = self.environment.coredata.compilers[self.for_machine]

        # Languages used by dependencies
        dep_langs = self.get_langs_used_by_deps()

        # Pick a compiler based on the language priority-order
        for l in clink_langs:
            if l in self.compilers or l in dep_langs:
                try:
                    linker = all_compilers[l]
                except KeyError:
                    raise MesonException(
                        f'Could not get a dynamic linker for build target {self.name!r}. '
                        f'Requires a linker for language "{l}", but that is not '
                        'a project language.')
                stdlib_args: T.List[str] = self.get_used_stdlib_args(linker.language)
                # Type of var 'linker' is Compiler.
                # Pretty hard to fix because the return value is passed everywhere
                return linker, stdlib_args

        # None of our compilers can do clink, this happens for example if the
        # target only has ASM sources. Pick the first capable compiler.
        for l in clink_langs:
            try:
                comp = self.all_compilers[l]
                return comp, comp.language_stdlib_only_link_flags(self.environment)
            except KeyError:
                pass

        raise AssertionError(f'Could not get a dynamic linker for build target {self.name!r}')

    def get_used_stdlib_args(self, link_language: str) -> T.List[str]:
        all_compilers = self.environment.coredata.compilers[self.for_machine]
        all_langs = set(self.compilers).union(self.get_langs_used_by_deps())
        stdlib_args: T.List[str] = []
        for dl in all_langs:
            if dl != link_language and (dl, link_language) not in self._MASK_LANGS:
                # We need to use all_compilers here because
                # get_langs_used_by_deps could return a language from a
                # subproject
                stdlib_args.extend(all_compilers[dl].language_stdlib_only_link_flags(self.environment))
        return stdlib_args

    def uses_rust(self) -> bool:
        return 'rust' in self.compilers

    def uses_rust_abi(self) -> bool:
        return self.uses_rust() and self.rust_crate_type in {'dylib', 'rlib', 'proc-macro'}

    def uses_fortran(self) -> bool:
        return 'fortran' in self.compilers

    def get_using_msvc(self) -> bool:
        '''
        Check if the dynamic linker is MSVC. Used by Executable, StaticLibrary,
        and SharedLibrary for deciding when to use MSVC-specific file naming
        and debug filenames.

        If at least some code is built with MSVC and the final library is
        linked with MSVC, we can be sure that some debug info will be
        generated. We only check the dynamic linker here because the static
        linker is guaranteed to be of the same type.

        Interesting cases:
        1. The Vala compiler outputs C code to be compiled by whatever
           C compiler we're using, so all objects will still be created by the
           MSVC compiler.
        2. If the target contains only objects, process_compilers guesses and
           picks the first compiler that smells right.
        '''
        # Rustc can use msvc style linkers
        if self.uses_rust():
            compiler = self.all_compilers['rust']
        else:
            compiler, _ = self.get_clink_dynamic_linker_and_stdlibs()
        # Mixing many languages with MSVC is not supported yet so ignore stdlibs.
        return compiler and compiler.get_linker_id() in {'link', 'lld-link', 'xilink', 'optlink'}

    def check_module_linking(self):
        '''
        Warn if shared modules are linked with target: (link_with) #2865
        '''
        for link_target in self.link_targets:
            if isinstance(link_target, SharedModule) and not link_target.force_soname:
                if self.environment.machines[self.for_machine].is_darwin():
                    raise MesonException(
                        f'target {self.name} links against shared module {link_target.name}. This is not permitted on OSX')
                elif self.environment.machines[self.for_machine].is_android() and isinstance(self, SharedModule):
                    # Android requires shared modules that use symbols from other shared modules to
                    # be linked before they can be dlopen()ed in the correct order. Not doing so
                    # leads to a missing symbol error: https://github.com/android/ndk/issues/201
                    link_target.force_soname = True
                else:
                    mlog.deprecation(f'target {self.name} links against shared module {link_target.name}, which is incorrect.'
                                     '\n             '
                                     f'This will be an error in the future, so please use shared_library() for {link_target.name} instead.'
                                     '\n             '
                                     f'If shared_module() was used for {link_target.name} because it has references to undefined symbols,'
                                     '\n             '
                                     'use shared_library() with `override_options: [\'b_lundef=false\']` instead.')
                    link_target.force_soname = True

    def process_vs_module_defs_kw(self, kwargs: T.Dict[str, T.Any]) -> None:
        if kwargs.get('vs_module_defs') is None:
            return

        path: T.Union[str, File, CustomTarget, CustomTargetIndex] = kwargs['vs_module_defs']
        if isinstance(path, str):
            if os.path.isabs(path):
                self.vs_module_defs = File.from_absolute_file(path)
            else:
                self.vs_module_defs = File.from_source_file(self.environment.source_dir, self.subdir, path)
        elif isinstance(path, File):
            # When passing a generated file.
            self.vs_module_defs = path
        elif isinstance(path, (CustomTarget, CustomTargetIndex)):
            # When passing output of a Custom Target
            self.vs_module_defs = File.from_built_file(path.get_output_subdir(), path.get_filename())
        else:
            raise InvalidArguments(
                'vs_module_defs must be either a string, '
                'a file object, a Custom Target, or a Custom Target Index')
        self.process_link_depends(path)

class FileInTargetPrivateDir:
    """Represents a file with the path '/path/to/build/target_private_dir/fname'.
       target_private_dir is the return value of get_target_private_dir which is e.g. 'subdir/target.p'.
    """

    def __init__(self, fname: str):
        self.fname = fname

    def __str__(self) -> str:
        return self.fname

class FileMaybeInTargetPrivateDir:
    """Union between 'File' and 'FileInTargetPrivateDir'"""

    def __init__(self, inner: T.Union[File, FileInTargetPrivateDir]):
        self.inner = inner

    @property
    def fname(self) -> str:
        return self.inner.fname

    def rel_to_builddir(self, build_to_src: str, target_private_dir: str) -> str:
        if isinstance(self.inner, FileInTargetPrivateDir):
            return os.path.join(target_private_dir, self.inner.fname)
        return self.inner.rel_to_builddir(build_to_src)

    def absolute_path(self, srcdir: str, builddir: str) -> str:
        if isinstance(self.inner, FileInTargetPrivateDir):
            raise RuntimeError('Unreachable code')
        return self.inner.absolute_path(srcdir, builddir)

    def __str__(self) -> str:
        return self.fname

class Generator(HoldableObject):
    def __init__(self, exe: T.Union['Executable', programs.ExternalProgram],
                 arguments: T.List[str],
                 output: T.List[str],
                 # how2dataclass
                 *,
                 depfile: T.Optional[str] = None,
                 capture: bool = False,
                 depends: T.Optional[T.List[T.Union[BuildTarget, 'CustomTarget', 'CustomTargetIndex']]] = None,
                 name: str = 'Generator'):
        self.exe = exe
        self.depfile = depfile
        self.capture = capture
        self.depends: T.List[T.Union[BuildTarget, 'CustomTarget', 'CustomTargetIndex']] = depends or []
        self.arglist = arguments
        self.outputs = output
        self.name = name

    def __repr__(self) -> str:
        repr_str = "<{0}: {1}>"
        return repr_str.format(self.__class__.__name__, self.exe)

    def get_exe(self) -> T.Union['Executable', programs.ExternalProgram]:
        return self.exe

    def get_base_outnames(self, inname: str) -> T.List[str]:
        plainname = os.path.basename(inname)
        basename = os.path.splitext(plainname)[0]
        bases = [x.replace('@BASENAME@', basename).replace('@PLAINNAME@', plainname) for x in self.outputs]
        return bases

    def get_dep_outname(self, inname: str) -> T.List[str]:
        if self.depfile is None:
            raise InvalidArguments('Tried to get dep name for rule that does not have dependency file defined.')
        plainname = os.path.basename(inname)
        basename = os.path.splitext(plainname)[0]
        return self.depfile.replace('@BASENAME@', basename).replace('@PLAINNAME@', plainname)

    def get_arglist(self, inname: str) -> T.List[str]:
        plainname = os.path.basename(inname)
        basename = os.path.splitext(plainname)[0]
        return [x.replace('@BASENAME@', basename).replace('@PLAINNAME@', plainname) for x in self.arglist]

    @staticmethod
    def is_parent_path(parent: str, trial: str) -> bool:
        try:
            common = os.path.commonpath((parent, trial))
        except ValueError: # Windows on different drives
            return False
        return pathlib.PurePath(common) == pathlib.PurePath(parent)

    def process_files(self, files: T.Iterable[T.Union[str, File, 'CustomTarget', 'CustomTargetIndex', 'GeneratedList']],
                      state: T.Union['Interpreter', 'ModuleState'],
                      preserve_path_from: T.Optional[str] = None,
                      extra_args: T.Optional[T.List[str]] = None,
                      env: T.Optional[EnvironmentVariables] = None) -> 'GeneratedList':
        # TODO: need a test for a generator in a build-only subproject
        is_build_only: T.Optional[bool] = getattr(state, 'is_build_only_subproject', None)
        if is_build_only is None:
            is_build_only = T.cast('Interpreter', state).coredata.is_build_only
        output = GeneratedList(
            self,
            state.subdir,
            preserve_path_from,
            extra_args=extra_args if extra_args is not None else [],
            env=env if env is not None else EnvironmentVariables(),
            is_build_only_subproject=is_build_only,
        )

        for e in files:
            if isinstance(e, CustomTarget):
                output.depends.add(e)
            if isinstance(e, CustomTargetIndex):
                output.depends.add(e.target)
            if isinstance(e, (CustomTarget, CustomTargetIndex)):
                output.depends.add(e)
                fs = [File.from_built_file(e.get_output_subdir(), f) for f in e.get_outputs()]
            elif isinstance(e, GeneratedList):
                if preserve_path_from:
                    raise InvalidArguments("generator.process: 'preserve_path_from' is not allowed if one input is a 'generated_list'.")
                output.depends.add(e)
                fs = [FileInTargetPrivateDir(f) for f in e.get_outputs()]
            elif isinstance(e, str):
                fs = [File.from_source_file(state.environment.source_dir, state.subdir, e)]
            else:
                fs = [e]

            for f in fs:
                if preserve_path_from:
                    abs_f = f.absolute_path(state.environment.source_dir, state.environment.build_dir)
                    if not self.is_parent_path(preserve_path_from, abs_f):
                        raise InvalidArguments('generator.process: When using preserve_path_from, all input files must be in a subdirectory of the given dir.')
                f = FileMaybeInTargetPrivateDir(f)
                output.add_file(f, state)
        return output


@dataclass(eq=False)
class GeneratedList(HoldableObject):

    """The output of generator.process."""

    generator: Generator
    subdir: str
    preserve_path_from: T.Optional[str]
    extra_args: T.List[str]
    env: T.Optional[EnvironmentVariables]
    is_build_only_subproject: bool

    def __post_init__(self) -> None:
        self.name = self.generator.exe
        self.depends: T.Set[GeneratedTypes] = set()
        self.infilelist: T.List[FileMaybeInTargetPrivateDir] = []
        self.outfilelist: T.List[str] = []
        self.outmap: T.Dict[FileMaybeInTargetPrivateDir, T.List[str]] = {}
        self.extra_depends = []  # XXX: Doesn't seem to be used?
        self.depend_files: T.List[File] = []

        if self.extra_args is None:
            self.extra_args: T.List[str] = []

        if self.env is None:
            self.env: EnvironmentVariables = EnvironmentVariables()

        if isinstance(self.generator.exe, programs.ExternalProgram):
            if not self.generator.exe.found():
                raise InvalidArguments('Tried to use not-found external program as generator')
            path = self.generator.exe.get_path()
            if os.path.isabs(path):
                # Can only add a dependency on an external program which we
                # know the absolute path of
                self.depend_files.append(File.from_absolute_file(path))

    def add_preserved_path_segment(self, infile: FileMaybeInTargetPrivateDir, outfiles: T.List[str], state: T.Union['Interpreter', 'ModuleState']) -> T.List[str]:
        result: T.List[str] = []
        in_abs = infile.absolute_path(state.environment.source_dir, state.environment.build_dir)
        assert os.path.isabs(self.preserve_path_from)
        rel = os.path.relpath(in_abs, self.preserve_path_from)
        path_segment = os.path.dirname(rel)
        for of in outfiles:
            result.append(os.path.join(path_segment, of))
        return result

    def add_file(self, newfile: FileMaybeInTargetPrivateDir, state: T.Union['Interpreter', 'ModuleState']) -> None:
        self.infilelist.append(newfile)
        outfiles = self.generator.get_base_outnames(newfile.fname)
        if self.preserve_path_from:
            outfiles = self.add_preserved_path_segment(newfile, outfiles, state)
        self.outfilelist += outfiles
        self.outmap[newfile] = outfiles

    def get_inputs(self) -> T.List[FileMaybeInTargetPrivateDir]:
        return self.infilelist

    def get_outputs(self) -> T.List[str]:
        return self.outfilelist

    def get_outputs_for(self, filename: FileMaybeInTargetPrivateDir) -> T.List[str]:
        return self.outmap[filename]

    def get_generator(self) -> 'Generator':
        return self.generator

    def get_extra_args(self) -> T.List[str]:
        return self.extra_args

    def get_source_subdir(self) -> str:
        return self.subdir

    def get_output_subdir(self) -> str:
        return compute_build_subdir(self.subdir, self.is_build_only_subproject)


class Executable(BuildTarget):
    known_kwargs = known_exe_kwargs

    typename = 'executable'

    def __init__(
            self,
            name: str,
            subdir: str,
            subproject: SubProject,
            for_machine: MachineChoice,
            sources: T.List['SourceOutputs'],
            structured_sources: T.Optional[StructuredSources],
            objects: T.List[ObjectTypes],
            environment: environment.Environment,
            compilers: T.Dict[str, 'Compiler'],
            build_only_subproject: bool,
            kwargs):
        key = OptionKey('b_pie')
        if 'pie' not in kwargs and key in environment.coredata.options:
            kwargs['pie'] = environment.coredata.options[key].value
        super().__init__(name, subdir, subproject, for_machine, sources, structured_sources, objects,
                         environment, compilers, build_only_subproject, kwargs)
        self.win_subsystem = kwargs.get('win_subsystem') or 'console'
        # Check for export_dynamic
        self.export_dynamic = kwargs.get('export_dynamic', False)
        if not isinstance(self.export_dynamic, bool):
            raise InvalidArguments('"export_dynamic" keyword argument must be a boolean')
        self.implib = kwargs.get('implib')
        if not isinstance(self.implib, (bool, str, type(None))):
            raise InvalidArguments('"export_dynamic" keyword argument must be a boolean or string')
        # Only linkwithable if using export_dynamic
        self.is_linkwithable = self.export_dynamic
        # Remember that this exe was returned by `find_program()` through an override
        self.was_returned_by_find_program = False

        self.vs_module_defs: T.Optional[File] = None
        self.process_vs_module_defs_kw(kwargs)

    def post_init(self) -> None:
        super().post_init()
        machine = self.environment.machines[self.for_machine]
        # Unless overridden, executables have no suffix or prefix. Except on
        # Windows and with C#/Mono executables where the suffix is 'exe'
        if not hasattr(self, 'prefix'):
            self.prefix = ''
        if not hasattr(self, 'suffix'):
            # Executable for Windows or C#/Mono
            if machine.is_windows() or machine.is_cygwin() or 'cs' in self.compilers:
                self.suffix = 'exe'
            elif machine.system.startswith('wasm') or machine.system == 'emscripten':
                self.suffix = 'js'
            elif ('c' in self.compilers and self.compilers['c'].get_id().startswith('armclang') or
                  'cpp' in self.compilers and self.compilers['cpp'].get_id().startswith('armclang')):
                self.suffix = 'axf'
            elif ('c' in self.compilers and self.compilers['c'].get_id().startswith('ccrx') or
                  'cpp' in self.compilers and self.compilers['cpp'].get_id().startswith('ccrx')):
                self.suffix = 'abs'
            elif ('c' in self.compilers and self.compilers['c'].get_id().startswith('xc16')):
                self.suffix = 'elf'
            elif ('c' in self.compilers and self.compilers['c'].get_id() in {'ti', 'c2000', 'c6000'} or
                  'cpp' in self.compilers and self.compilers['cpp'].get_id() in {'ti', 'c2000', 'c6000'}):
                self.suffix = 'out'
            elif ('c' in self.compilers and self.compilers['c'].get_id() in {'mwccarm', 'mwcceppc'} or
                  'cpp' in self.compilers and self.compilers['cpp'].get_id() in {'mwccarm', 'mwcceppc'}):
                self.suffix = 'nef'
            else:
                self.suffix = machine.get_exe_suffix()
        self.filename = self.name
        if self.suffix:
            self.filename += '.' + self.suffix
        self.outputs[0] = self.filename

        # The import library this target will generate
        self.import_filename = None
        # The debugging information file this target will generate
        self.debug_filename = None

        # If using export_dynamic, set the import library name
        if self.export_dynamic:
            implib_basename = self.name + '.exe'
            if isinstance(self.implib, str):
                implib_basename = self.implib
            if machine.is_windows() or machine.is_cygwin():
                if self.get_using_msvc():
                    self.import_filename = f'{implib_basename}.lib'
                else:
                    self.import_filename = f'lib{implib_basename}.a'

        create_debug_file = (
            machine.is_windows()
            and ('cs' in self.compilers or self.uses_rust() or self.get_using_msvc())
            # .pdb file is created only when debug symbols are enabled
            and self.environment.coredata.get_option(OptionKey("debug"))
        )
        if create_debug_file:
            # If the target is has a standard exe extension (i.e. 'foo.exe'),
            # then the pdb name simply becomes 'foo.pdb'. If the extension is
            # something exotic, then include that in the name for uniqueness
            # reasons (e.g. 'foo_com.pdb').
            name = self.name
            if getattr(self, 'suffix', 'exe') != 'exe':
                name += '_' + self.suffix
            self.debug_filename = name + '.pdb'

    def process_kwargs(self, kwargs):
        super().process_kwargs(kwargs)

        self.rust_crate_type = kwargs.get('rust_crate_type') or 'bin'
        if self.rust_crate_type != 'bin':
            raise InvalidArguments('Invalid rust_crate_type: must be "bin" for executables.')

    def get_default_install_dir(self) -> T.Union[T.Tuple[str, str], T.Tuple[None, None]]:
        return self.environment.get_bindir(), '{bindir}'

    def description(self):
        '''Human friendly description of the executable'''
        return self.name

    def type_suffix(self):
        return "@exe"

    def get_import_filename(self) -> T.Optional[str]:
        """
        The name of the import library that will be outputted by the compiler

        Returns None if there is no import library required for this platform
        """
        return self.import_filename

    def get_debug_filename(self) -> T.Optional[str]:
        """
        The name of debuginfo file that will be created by the compiler

        Returns None if the build won't create any debuginfo file
        """
        return self.debug_filename

    def is_linkable_tar
"""


```