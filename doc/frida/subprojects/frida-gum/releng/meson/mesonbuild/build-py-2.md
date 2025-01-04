Response:
The user wants a summary of the Python code provided. I need to identify the main functionalities of this script, relate them to reverse engineering concepts (if applicable), discuss any interaction with low-level aspects (like kernel or hardware), analyze logical reasoning within the code, point out potential user errors, explain how a user might reach this code during a debugging session, and finally, summarize the overall purpose of the script.

Here's a breakdown of the code's functionality:

1. **Library Linking (`link_with`, `link_whole`):**  Manages linking different types of libraries (static, shared, custom) together, including handling platform-specific requirements like Position Independent Code (PIC).
2. **Internal Static Library Management (`get_internal_static_libraries`, `_bundle_static_library`):**  Deals with how static libraries are bundled and linked, especially when one static library depends on another.
3. **Language Handling (`get_langs_used_by_deps`, `get_prelinker`, `get_clink_dynamic_linker_and_stdlibs`, `get_used_stdlib_args`):** Determines the appropriate linker and standard libraries based on the programming languages used in the project and its dependencies.
4. **Precompiled Headers (PCH) (`add_pch`):**  Adds support for precompiled headers to speed up compilation.
5. **Include Directories (`add_include_dirs`):** Manages include directories for compilation.
6. **Compiler and Linker Identification (`uses_rust`, `uses_rust_abi`, `uses_fortran`, `get_using_msvc`):**  Identifies the compilers being used (e.g., Rust, MSVC) to apply specific linking rules.
7. **Shared Module Linking (`check_module_linking`):**  Handles linking against shared modules, addressing platform-specific issues.
8. **Visual Studio Module Definitions (`process_vs_module_defs_kw`):**  Supports the use of Visual Studio module definition files.
9. **File Handling (`FileInTargetPrivateDir`, `FileMaybeInTargetPrivateDir`):** Represents files, potentially in private build directories.
10. **Code Generation (`Generator`, `GeneratedList`):**  Provides a mechanism to generate source code or other files as part of the build process.
11. **Executable Building (`Executable`):**  Defines how executable files are built, including platform-specific settings (like Windows subsystem, export symbols, debugging information).

Now, let's map these to the prompt's requirements.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/build.py` 文件的第三部分，主要定义了 Meson 构建系统中关于目标文件（targets）链接以及代码生成的相关功能。

**功能归纳:**

这部分代码的核心功能是定义了如何在 Meson 构建系统中处理不同类型的构建目标之间的链接关系，以及如何使用生成器（Generator）来生成代码。它涵盖了以下几个主要方面：

1. **库链接管理:**  定义了 `link_with` 和 `link_whole` 方法，用于管理构建目标之间的链接关系。这包括链接静态库、共享库以及自定义目标，并处理了不同库类型之间的兼容性问题，例如将非 PIC 的静态库链接到共享库时会报错。
2. **内部静态库处理:**  提供了处理内部静态库依赖的方法，例如 `get_internal_static_libraries` 和 `_bundle_static_library`，确保在链接时能够正确包含所有必要的静态库对象。
3. **语言相关的链接处理:**  定义了与编程语言相关的链接逻辑，例如根据依赖的语言选择合适的链接器 (`get_clink_dynamic_linker_and_stdlibs`)，并处理不同语言标准库的链接 (`get_used_stdlib_args`)。
4. **预编译头文件 (PCH):**  包含了 `add_pch` 方法，用于添加和管理预编译头文件，以加速编译过程。
5. **包含目录管理:**  提供了 `add_include_dirs` 方法，用于添加编译时的包含目录。
6. **代码生成器 (Generator):**  定义了 `Generator` 类，允许在构建过程中执行外部程序来生成源代码或其他文件。`GeneratedList` 类则用于管理生成器的输出。
7. **可执行文件构建:** 定义了 `Executable` 类，它是 `BuildTarget` 的子类，专门用于处理可执行文件的构建过程，包括设置 Windows 子系统、导出符号、生成导入库和调试信息等。
8. **共享模块链接:** 包含了 `check_module_linking` 方法，用于检查共享模块的链接，并处理一些平台特定的问题，例如在 macOS 上不允许链接共享模块。
9. **Visual Studio 模块定义文件:**  提供了 `process_vs_module_defs_kw` 方法，用于处理 Visual Studio 的模块定义文件 (.def)。

**与逆向方法的关系及举例说明:**

这部分代码与逆向工程存在一定的关联，主要体现在库的链接和可执行文件的构建过程：

* **动态链接库 (SharedLibrary):** 逆向工程师经常需要分析动态链接库，了解其导出的符号和功能。这段代码负责构建动态链接库，逆向工程师可以通过分析构建过程中的链接选项和依赖关系，来推断库的结构和功能。例如，如果使用了 `link_with` 链接了某个特定的库，逆向工程师会关注这个被链接的库，因为它很可能是当前库实现某些功能的依赖。
* **可执行文件 (Executable):** 逆向分析的核心对象通常是可执行文件。这段代码定义了如何构建可执行文件，包括链接哪些库、生成哪些调试信息等。逆向工程师可以通过分析可执行文件的构建方式，例如是否使用了符号导出 (`export_dynamic`)，以及是否生成了调试符号文件 (`.pdb`)，来选择合适的逆向分析策略。例如，如果可执行文件导出了符号，逆向分析会更容易；如果存在 `.pdb` 文件，则可以进行符号调试。
* **导入库 (Import Library):** 在 Windows 平台上，动态链接库通常会生成一个对应的导入库。逆向工程师可以通过分析导入库来了解可执行文件依赖了哪些动态链接库及其导出的函数。这段代码中关于 `implib` 的处理就与此相关。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这段代码涉及到一些底层的概念和操作系统相关的知识：

* **位置无关代码 (PIC):** 为了让共享库能够在内存中的任意位置加载，通常需要生成位置无关代码。代码中检查了将非 PIC 的静态库链接到共享库的情况，并会抛出错误。这与共享库的加载机制密切相关。
* **动态链接器:**  代码中使用了 `get_clink_dynamic_linker_and_stdlibs` 来获取动态链接器。动态链接器是操作系统的一部分，负责在程序运行时加载和链接共享库。
* **标准库链接:**  代码中处理了不同编程语言的标准库链接 (`get_used_stdlib_args`)。标准库是编程语言的基础库，提供了常用的函数和功能。
* **Windows 子系统:**  `Executable` 类中定义了 `win_subsystem` 属性，用于指定 Windows 可执行文件的子系统（例如 console 或 windows）。这与 Windows 操作系统加载和运行可执行文件的方式有关。
* **Android 共享模块链接:**  `check_module_linking` 方法中提到了 Android 平台对共享模块链接的特殊要求，以及 `force_soname` 的使用。这涉及到 Android 系统中共享库的加载和符号查找机制。

**逻辑推理及假设输入与输出:**

代码中存在一些逻辑推理，例如：

* **假设输入:**  在 `link_libraries` 方法中，如果 `link_with` 接收到一个外部库的参数 `t`。
* **输出:**  会抛出一个 `MesonException`，提示用户应该使用 `dependencies` 关键字来链接外部库。

* **假设输入:** 在 `link_whole` 方法中，如果尝试将一个非静态库的目标 `t` 传递给 `link_whole`。
* **输出:** 会抛出一个 `InvalidArguments` 异常，提示 `t` 不是一个静态库。

* **假设输入:** 在 `add_pch` 方法中，如果 `pchlist` 包含两个路径不在同一个目录的文件。
* **输出:** 会抛出一个 `InvalidArguments` 异常，提示 PCH 文件必须存储在同一个文件夹中。

**涉及用户或编程常见的使用错误及举例说明:**

* **使用 `link_with` 链接外部库:**  用户可能会错误地使用 `link_with` 来链接不是当前项目构建的库。代码会检测到这种情况并抛出异常，提示用户应该使用 `dependencies`。
  ```python
  # 错误用法
  executable('my_program', 'main.c', link_with: find_library('external_lib'))

  # 正确用法
  external_dep = dependency('external_lib')
  executable('my_program', 'main.c', dependencies: external_dep)
  ```
* **将非 PIC 静态库链接到共享库:** 用户可能会尝试将一个没有生成位置无关代码的静态库链接到共享库。代码会检测到这种情况并抛出异常，提示用户需要使用 `pic` 选项来构建静态库。
  ```python
  # 假设 libfoo 是一个非 PIC 的静态库
  shared_library('my_shared_lib', 'mylib.c', link_with: libfoo) # 会报错

  # 正确做法是确保 libfoo 构建时使用了 pic: true
  static_library('libfoo', 'foo.c', pic: true)
  shared_library('my_shared_lib', 'mylib.c', link_with: libfoo)
  ```
* **错误的 PCH 文件配置:** 用户可能会提供不正确的 PCH 文件路径或提供多个不同目录下的 PCH 文件。代码会进行检查并抛出相应的异常。

**用户操作如何一步步地到达这里，作为调试线索:**

用户通常通过 `meson` 命令来配置构建系统。当 Meson 处理 `meson.build` 文件时，会解析其中的构建目标定义，包括 `executable`、`shared_library` 等。

1. **编写 `meson.build` 文件:** 用户编写 `meson.build` 文件，其中定义了可执行文件或库的构建规则，包括源文件、依赖项、链接选项等。例如：
   ```python
   project('my_project', 'c')
   executable('my_program', 'main.c', link_with: shared_library('mylib', 'mylib.c'))
   shared_library('mylib', 'mylib.c')
   ```
2. **运行 `meson` 命令:** 用户在项目根目录下运行 `meson build` 命令来配置构建系统。
3. **Meson 解析 `meson.build`:** Meson 解析 `meson.build` 文件，遇到 `executable` 和 `shared_library` 函数时，会创建相应的 `Executable` 和 `SharedLibrary` 对象。
4. **处理链接选项:** 当处理 `link_with` 等链接选项时，Meson 会调用 `Executable` 或 `SharedLibrary` 类的相应方法（例如 `link_libraries`）。
5. **触发异常 (如果存在错误):** 如果用户在 `meson.build` 中使用了错误的链接方式（例如使用 `link_with` 链接外部库），或者存在其他配置错误，这段代码中的检查逻辑会触发相应的异常，并在配置阶段报错。

作为调试线索，如果用户在配置阶段遇到与链接相关的错误，例如 `MesonException` 或 `InvalidArguments`，错误信息通常会指向这段代码中的检查逻辑。用户需要检查 `meson.build` 文件中关于库链接的配置是否正确，例如是否使用了正确的关键字（`dependencies` 而不是 `link_with`），以及链接的库是否满足链接要求（例如静态库是否是 PIC 的）。

总而言之，这部分代码是 Frida 构建系统中使用 Meson 进行构建配置的核心组成部分，负责管理不同构建目标之间的链接关系，处理语言相关的链接细节，并提供了代码生成的能力，确保最终生成的可执行文件和库能够正确链接和运行。它对构建过程的正确性至关重要，并包含了许多针对常见用户错误的检查。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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