Response:
My thinking process to arrive at the summary of the `build.py` file goes like this:

1. **Understand the Context:** The initial prompt states this is part of the Frida dynamic instrumentation tool, specifically within the `mesonbuild` system. This immediately tells me it's about the *build process* of Frida itself. Meson is a build system generator, so this file likely defines how different parts of Frida are compiled and linked.

2. **Identify the Core Entities:**  I scan the code for classes and major function definitions. The key classes I see are:
    * `BuildTarget`:  A foundational class likely representing something that gets built (executable, library, etc.).
    * `FileInTargetPrivateDir`, `FileMaybeInTargetPrivateDir`:  Representing file locations within the build system's private directories.
    * `Generator`:  A mechanism for generating files during the build process (like code generation).
    * `GeneratedList`: Represents the output of a `Generator`.
    * `Executable`: A specific type of `BuildTarget`.

3. **Analyze `BuildTarget` Functionality:** I focus on the methods within `BuildTarget` as it seems central. I look for actions and data manipulations related to building:
    * **Linking:** `link_with`, `link_whole`, `check_can_link_together`. These clearly deal with linking different build outputs.
    * **Dependencies:**  Methods like `get_internal_static_libraries`, `get_internal_static_libraries_recurse` indicate managing dependencies between components.
    * **Language Handling:** `get_langs_used_by_deps`, `get_prelinker`, `get_clink_dynamic_linker_and_stdlibs` show it handles projects with multiple programming languages.
    * **Compiler Options:**  Methods related to PCH (`add_pch`), include directories (`add_include_dirs`).
    * **Output Naming:** Logic around suffixes and prefixes for different platforms.
    * **Module Definitions:** `process_vs_module_defs_kw` suggests handling module definition files (likely for Windows).

4. **Analyze `Generator` Functionality:**  I examine the methods of `Generator`:
    * `process_files`: This seems to be the main method for taking input files and applying the generator to them.
    * `get_exe`, `get_arglist`, `get_base_outnames`:  Accessing information about the generator itself (executable, arguments, output names).

5. **Analyze `Executable` Functionality:** I look at what's specific to executables:
    * `win_subsystem`, `export_dynamic`, `implib`:  Windows-specific linking options.
    * Handling of suffixes (e.g., `.exe`).
    * Management of import libraries (`get_import_filename`) and debug symbols (`get_debug_filename`).

6. **Identify Cross-Cutting Themes:**  As I analyze, I notice recurring themes:
    * **Platform Differences:**  The code handles different operating systems (Windows, Linux, macOS, Android) and architectures (cross-compilation).
    * **Language Interoperability:** It manages linking code written in different languages (C, C++, Rust, etc.).
    * **Error Handling:**  `raise MesonException`, `raise InvalidArguments` indicate error checking.

7. **Synthesize the Summary:** Based on the analysis, I formulate a concise summary capturing the key functionalities:

    * **Core Purpose:**  Build process management using the Meson build system.
    * **Key Entities:**  Defining build targets (executables, libraries), handling file generation, and managing dependencies.
    * **Linking Capabilities:**  Complex logic for linking, including handling static and shared libraries, cross-language linking, and platform-specific linking requirements.
    * **Generator Framework:**  A system for running external tools to generate files.
    * **Executable Specifics:**  Tailored handling for executable creation, especially on Windows.

8. **Refine and Organize:** I ensure the summary is clear, uses appropriate terminology, and is structured logically. I group related functionalities together.

This step-by-step breakdown allows me to understand the purpose and functionality of the code even without running it or having prior knowledge of all the specific details of Frida or Meson. It focuses on identifying the key abstractions and their interactions.
这是 `frida/subprojects/frida-tools/releng/meson/mesonbuild/build.py` 文件的第三部分，主要定义了 Meson 构建系统中用于描述和处理构建目标（targets）的各种类，例如可执行文件（Executable）、库文件（StaticLibrary, SharedLibrary, SharedModule）以及用于生成文件的机制（Generator, GeneratedList）。

**本部分的主要功能归纳如下：**

1. **定义了构建目标类的核心行为：**  `BuildTarget` 类及其子类（如 `Executable`）定义了构建目标的基本属性和操作，例如：
    * **链接 (Linking):**  `link_with`, `link_whole`, `check_can_link_together` 等方法用于处理目标之间的链接关系，包括链接静态库、共享库以及处理 PIC (Position Independent Code) 的需求。
    * **依赖 (Dependencies):** `get_internal_static_libraries`, `get_internal_static_libraries_recurse` 等方法用于管理内部静态库的依赖关系。
    * **语言处理 (Language Handling):** `get_langs_used_by_deps`, `get_prelinker`, `get_clink_dynamic_linker_and_stdlibs` 等方法用于处理多语言项目，确定链接器和标准库。
    * **预编译头 (PCH):** `add_pch` 方法用于添加和处理预编译头文件。
    * **包含目录 (Include Directories):** `add_include_dirs` 方法用于添加编译器的包含目录。
    * **平台特定 (Platform Specific):**  例如处理 Windows 上的模块定义文件 (`process_vs_module_defs_kw`)，以及可执行文件的后缀名。

2. **定义了文件生成机制：** `Generator` 类和 `GeneratedList` 类用于描述和处理通过外部程序生成文件的过程。
    * **`Generator` 类:** 代表一个文件生成器，例如一个代码生成工具，它指定了要执行的程序、参数和输出文件。
    * **`GeneratedList` 类:** 代表 `Generator` 执行后的输出文件列表，包含了依赖关系和输出路径信息。

**与逆向方法的关系及举例说明：**

* **链接分析:** 逆向工程中，理解目标文件是如何链接在一起的至关重要。`BuildTarget` 中的链接相关方法直接反映了构建过程中的链接行为，可以帮助逆向工程师推断不同模块之间的依赖关系和符号解析过程。例如，如果一个逆向分析的目标是一个共享库，分析其 `link_with` 和 `link_whole` 引用的其他库，可以揭示其功能依赖。
* **静态链接和动态链接:**  代码中区分了 `link_with` 和 `link_whole`，分别对应动态链接和静态链接。逆向工程师需要理解这两种链接方式的区别，静态链接会将库的代码直接嵌入到目标文件中，而动态链接则在运行时加载。这会影响逆向分析时查找函数定义和理解代码流程的方式。
* **PIC (Position Independent Code):** 对于共享库，通常需要使用 PIC，以便在不同的内存地址加载。代码中检查了链接静态库到共享库时是否使用了 PIC (`if isinstance(self, SharedLibrary) and isinstance(t, StaticLibrary) and not t.pic:`)。逆向 Android 或 Linux 等系统的共享库时，需要理解 PIC 的工作原理。
* **依赖关系分析:** `get_internal_static_libraries` 等方法揭示了构建过程中的内部依赖关系。逆向工程师在分析一个大型项目时，理解这些依赖关系可以帮助他们缩小分析范围，定位关键模块。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制文件结构:**  代码中处理了不同类型的目标文件（可执行文件、静态库、共享库），这些类型的文件在二进制层面有不同的结构（例如 ELF 或 PE 格式）。理解这些结构对于逆向工程至关重要。
* **链接器行为:**  代码中调用了不同的链接器（例如 MSVC 的 `link`），并且考虑了不同链接器的特性。理解链接器如何解析符号、处理重定位等是深入理解二进制文件的基础。
* **共享库 (SharedLibrary):**  在 Linux 和 Android 系统中，共享库是重要的组成部分。代码中对共享库的链接和依赖处理反映了操作系统加载和管理共享库的方式。
* **动态链接器 (Dynamic Linker):** `get_clink_dynamic_linker_and_stdlibs` 方法涉及到动态链接器的选择。在 Linux 和 Android 上，`ld.so` 是主要的动态链接器。
* **Android 框架:** 代码中提到 Android 需要共享模块在被 `dlopen()` 之前链接，这与 Android 框架中动态库加载的机制有关。
* **预编译头 (PCH):**  预编译头是一种编译器优化技术，可以加速编译过程。理解 PCH 的工作原理可以帮助理解编译产物的结构。

**逻辑推理的假设输入与输出：**

假设有一个 `SharedLibrary` 目标 `libfoo`，它需要链接一个内部的 `StaticLibrary` 目标 `libbar`。

* **假设输入:**
    * `libfoo` 是一个 `SharedLibrary` 实例。
    * `libbar` 是一个 `StaticLibrary` 实例。
    * 调用 `libfoo.link_with([libbar])`。
* **逻辑推理:**
    * 代码会检查 `libbar` 是否是可链接的目标 (`is_linkable_target`)。
    * 代码会检查 `libfoo` 是否为 `StaticLibrary` (本例不是)。
    * 代码会检查 `libfoo` 是否为 `SharedLibrary`，并且 `libbar` 是否为 `StaticLibrary`，并且 `libbar` 是否使用了 PIC (`libbar.pic`)。如果 `libbar.pic` 为 `False`，则会抛出 `InvalidArguments` 异常，因为不能将非 PIC 的静态库链接到共享库中。
    * 如果 `libbar.pic` 为 `True`，则 `libbar` 会被添加到 `libfoo.link_targets` 列表中。
* **预期输出:** 如果 `libbar` 使用了 PIC，则 `libfoo` 的链接目标列表中会包含 `libbar`。否则，会抛出异常。

**用户或编程常见的使用错误及举例说明：**

* **使用 `link_with` 链接外部库:** 代码中明确指出 `link_with` 只能用于链接项目内部构建的库。如果用户尝试使用 `link_with` 链接一个通过 `dependency()` 函数找到的外部库，会抛出 `MesonException`。
    ```python
    # 错误示例
    mylib = shared_library('mylib', 'mylib.c')
    ext_dep = dependency('external_lib')
    # 错误的尝试，应该使用 'dependencies' 参数
    executable('myexe', 'myexe.c', link_with : mylib, ext_dep)
    ```
* **链接非 PIC 的静态库到共享库:**  如上面的逻辑推理所示，这是一个常见的错误。用户忘记为静态库启用 PIC 选项，导致链接失败。
    ```python
    # 错误示例
    static_lib = static_library('static_lib', 'static.c') # 默认不启用 PIC
    shared_lib = shared_library('shared_lib', 'shared.c', link_with : static_lib) # 会抛出异常
    ```
* **PCH 文件不在同一目录:** 代码要求预编译头的头文件和源文件（如果提供）必须在同一目录下。如果用户提供的 PCH 文件不在同一目录，会抛出 `InvalidArguments` 异常。
    ```python
    # 错误示例
    executable('myexe', 'myexe.c', pch : ['include/myheader.h', 'src/myheader.c']) # 假设 myheader.h 和 myheader.c 不在同一目录下，会抛出异常
    ```

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 `meson.build` 文件:** 用户首先需要编写 `meson.build` 文件来描述项目的构建配置，包括定义可执行文件、库文件以及它们之间的依赖关系。例如，用户可能在 `meson.build` 文件中使用了 `shared_library()` 或 `executable()` 函数，并使用了 `link_with` 或 `dependencies` 参数来指定链接的库。
2. **运行 `meson` 命令:** 用户在项目根目录下运行 `meson <build_directory>` 命令来生成构建系统。Meson 会解析 `meson.build` 文件，并根据其中的定义创建内部的数据结构，包括表示构建目标的实例。
3. **运行 `ninja` 或其他构建工具:**  用户进入构建目录并运行 `ninja` (或其他配置的构建工具) 来执行实际的编译和链接过程。
4. **Meson 内部调用 `build.py`:** 在构建过程中，Meson 会调用 `build.py` 文件中的代码来处理各种构建目标的定义和操作。当需要链接目标文件时，就会执行 `BuildTarget` 类中的 `link_with` 或 `link_whole` 等方法。
5. **触发异常或逻辑分支:** 如果用户的 `meson.build` 文件中存在错误的链接配置（例如链接外部库或非 PIC 的静态库），或者提供了不正确的 PCH 文件，那么在执行到 `build.py` 中的相应代码时，就会触发异常或进入特定的逻辑分支，从而进行错误处理或执行特定的链接操作。

例如，如果用户在 `meson.build` 中错误地使用了 `link_with` 链接了一个外部依赖，当 Meson 执行到 `BuildTarget.link_with` 方法时，会满足 `isinstance(t, programs.ExternalLibrary)` 的条件，从而抛出 `MesonException`。这个异常会终止构建过程，并向用户报告错误信息。

**总结本部分的功能：**

本部分 `frida/subprojects/frida-tools/releng/meson/mesonbuild/build.py` 的核心功能是**定义了 Meson 构建系统中用于描述和处理各种构建目标的关键类和方法**。它负责处理构建目标的链接、依赖管理、语言特性、平台特定配置以及文件生成等核心构建逻辑，为 Frida 这样的复杂项目提供了结构化的构建管理能力。理解这部分代码对于理解 Frida 的构建过程和排查构建问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```python
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
```