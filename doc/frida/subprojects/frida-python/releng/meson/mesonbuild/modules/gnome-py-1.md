Response:
The user wants a summary of the functionality of the provided Python code snippet from `fridaDynamic instrumentation tool`.

Here's a breakdown of how to approach this:

1. **Identify the main goal:** The code is part of the `gnome` module in Meson, a build system. This suggests it deals with integrating GNOME technologies into the build process.

2. **Analyze individual functions:**  Go through each function and understand its purpose. Keywords like `generate_gir`, `compile_schemas`, `yelp` give strong hints.

3. **Look for patterns and relationships:** How do these functions interact?  Do they produce outputs that other functions consume?

4. **Connect to the broader context of Frida:**  While the code itself doesn't explicitly mention Frida within the snippet, the user's context indicates it's part of Frida's build process. Think about how GNOME technologies might be used in dynamic instrumentation. GObject introspection (`.gir` files, typelibs) is crucial for interacting with libraries at runtime, which is relevant to Frida.

5. **Consider the user's specific questions:**
    * **Relation to reverse engineering:**  GObject introspection allows tools like Frida to understand the structure and functions of libraries at runtime, a key aspect of reverse engineering.
    * **Binary/kernel knowledge:**  While the Python code itself is high-level, the underlying processes it manages (like compiling schemas or generating `.gir` files) involve interacting with binaries and system libraries.
    * **Logical reasoning:**  The code makes decisions based on input (e.g., whether to install, which directories to use). Identify these decision points.
    * **User errors:**  Consider common mistakes a user might make when using these functions (e.g., incorrect paths, missing dependencies).
    * **User steps to reach the code:**  Think about the actions a developer takes when building software that would trigger this code (e.g., configuring a Meson build, using `gnome.generate_gir`).

6. **Focus on summarizing the functionality of *this specific snippet*:**  The prompt emphasizes summarizing the provided code, not the entire `gnome.py` file.

7. **Structure the summary:** Organize the findings into logical categories, addressing the user's specific points.

**Pre-computation and Pre-analysis (Internal Thought Process):**

* **`generate_gir`:** This clearly generates `.gir` files, which are essential for GObject introspection. It involves scanning source code, linking with libraries, and creating a description of the APIs.
* **`compile_schemas`:** This compiles GSettings schemas, which are used for application configuration in GNOME.
* **`yelp`:**  This seems to handle building and installing documentation using the Yelp help system. It involves processing source files and translations.
* **Helper functions (e.g., `_get_dependencies_flags`, `_scan_include`):** These functions are used internally by the main functions to manage dependencies, include paths, and other build settings.
* **Dependency management:** The code extensively deals with dependencies (both internal and external) needed for building the GNOME components.
* **Installation:**  Several functions have parameters related to installation directories, indicating they manage where the generated files are placed.
* **Error handling:** The code includes checks and raises `MesonException` for various issues.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the technical details of each function. The summary needs to be more high-level, explaining *what* the code does rather than *how* it does it.
* It's important to explicitly link the functionality to Frida's use case, even though it's not directly mentioned in the snippet. The generation of `.gir` files for runtime introspection is the key connection.
*  Ensure the examples are relevant to the specific functions in the snippet.

By following these steps, I can construct a comprehensive and accurate summary that addresses the user's request.
This代码片段是 `frida` 动态 instrumentation 工具中 `frida-python` 子项目下 `releng/meson/mesonbuild/modules/gnome.py` 文件的一部分。它定义了 `gnome` Meson 模块中的一些用于处理 GNOME 相关构建任务的辅助方法。

**功能归纳:**

这段代码主要包含了以下功能：

1. **处理依赖项的标志 (Flags):**  `_get_dependencies_flags_raw` 和 `_get_dependencies_flags` 方法用于获取构建目标依赖项的编译和链接标志 (cflags, ldflags)。 这包括处理内部和外部库的链接标志，并根据是否需要 GIR 信息进行不同的处理。

2. **处理 GIR 目标:** `_unwrap_gir_target` 方法用于验证作为 GIR 生成目标的参数是否为可执行文件或库文件，并检查 GObject-Introspection 的版本是否满足静态库内省的要求。

3. **环境变量管理:** `_devenv_prepend` 和 `postconf_hook` 方法用于管理构建过程中需要设置的环境变量，例如将路径添加到 `GI_TYPELIB_PATH` 中。

4. **查找 GObject-Introspection 工具:** `_get_gir_dep` 方法用于获取 `gobject-introspection-1.0` 依赖项，并查找 `g-ir-scanner` 和 `g-ir-compiler` 这两个工具。

5. **检查 `g-ir-scanner` 的选项:** `_gir_has_option` 方法用于检查 `g-ir-scanner` 是否支持特定的选项。

6. **处理包含目录:** `_scan_include` 方法用于处理 GIR 扫描器需要的包含目录参数，区分字符串路径和 `GirTarget` 对象。

7. **处理语言链接参数:** `_scan_langs` 方法用于获取特定编程语言的链接参数 (例如 `-L` 开头的库路径)。

8. **处理 GIR 目标作为扫描器的输入:** `_scan_gir_targets` 方法用于将构建目标（可执行文件或库文件）转换为 `g-ir-scanner` 能够理解的参数，例如使用 `--program` 或 `--library`。

9. **获取 GIR 目标的语言和编译器信息:** `_get_girtargets_langs_compilers` 方法用于提取构建目标支持的编程语言及其对应的编译器。

10. **获取 GIR 目标的依赖项:** `_get_gir_targets_deps` 方法用于获取构建目标的所有链接依赖项和外部依赖项。

11. **获取 GIR 目标的包含目录:** `_get_gir_targets_inc_dirs` 方法用于获取构建目标的包含目录。

12. **获取语言和编译器的标志:** `_get_langs_compilers_flags` 方法用于根据指定的语言和编译器，获取全局和项目级别的编译标志以及 sanitizers 的相关标志。

13. **生成 GIR 文件列表:** `_make_gir_filelist` 方法用于创建一个文本文件，其中列出了用于生成 GIR 文件的源文件路径。

14. **创建 GirTarget 对象:** `_make_gir_target` 方法用于创建 `GirTarget` 对象，该对象表示一个待生成的 GIR 文件。它负责设置扫描命令、依赖项、安装路径等信息。

15. **创建 TypelibTarget 对象:** `_make_typelib_target` 方法用于创建 `TypelibTarget` 对象，该对象表示一个待编译的 typelib 文件。它负责设置编译命令、依赖项、安装路径等信息。

16. **收集 Typelib 包含目录并更新依赖项:** `_gather_typelib_includes_and_update_depends` 方法用于收集生成 typelib 所需的包含目录，并递归地添加 `GirTarget` 的依赖项。

17. **获取语言的外部参数:** `_get_external_args_for_langs` 方法用于获取特定编程语言的外部参数。

18. **过滤扫描器的编译和链接标志:** `_get_scanner_cflags` 和 `_get_scanner_ldflags` 方法用于过滤出 `g-ir-scanner` 可以接受的编译和链接标志。

**与逆向方法的关系及举例说明:**

这段代码直接关系到逆向工程，因为它涉及到 **GObject Introspection (GIR)**。GIR 是一种技术，允许在运行时自省 GObject 类型的库。

**举例说明:**

* **Frida 使用 GIR 来动态地了解目标进程中 GObject 库的结构和接口。** 通过解析 `.gir` 文件，Frida 可以知道哪些类、方法、信号存在，以及它们的参数和返回值类型。这使得 Frida 能够hook这些函数，调用它们，或者监视它们的行为。
* **`generate_gir` 函数生成 `.gir` 文件。**  逆向工程师可以使用 Frida 加载由 `generate_gir` 生成的 `.gir` 文件，从而能够与目标应用程序中使用了 GObject 的组件进行交互。例如，如果一个应用程序使用了 GTK (基于 GObject 的 GUI 库)，Frida 可以通过加载 GTK 的 `.gir` 文件来 hook GTK 的按钮点击事件。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:** 代码中处理的链接标志 (`-l`, `-L`) 直接影响到二进制文件的链接过程，决定了程序运行时需要链接哪些库。
* **Linux:**  `g-ir-scanner` 和 `g-ir-compiler` 是 Linux 系统上常用的工具，用于生成和编译 GIR 数据。代码中使用了 `Popen_safe` 执行这些外部命令，这是 Linux 编程中常见的操作。
* **Android 框架:** 虽然代码本身没有直接提到 Android 内核，但 Frida 常被用于 Android 平台的逆向分析。Android 框架中也广泛使用了基于 GObject 的库 (例如，某些系统服务或 HAL 层)。因此，生成这些库的 GIR 信息对于 Frida 在 Android 上的应用至关重要。例如，hook Android 系统服务中的 GObject 方法。

**逻辑推理及假设输入与输出:**

**假设输入:**

* `girtargets`: 一个包含要进行内省的共享库的 `build.SharedLibrary` 对象列表。例如，一个名为 `libexample.so` 的共享库。
* `state`: Meson 的 `ModuleState` 对象，包含构建环境信息。
* `internal_ldflags`: 一个包含内部链接标志的列表，例如 `['-L/path/to/internal/lib']`.
* `external_ldflags`: 一个包含外部链接标志的列表，例如 `['-lsqlite3']`.

**代码段:**

```python
        if self._gir_has_option('--extra-library'):
            def fix_ldflags(ldflags: T.Iterable[T.Union[str, T.Tuple[str, str]]]) -> OrderedSet[T.Union[str, T.Tuple[str, str]]]:
                fixed_ldflags: OrderedSet[T.Union[str, T.Tuple[str, str]]] = OrderedSet()
                for ldflag in ldflags:
                    if isinstance(ldflag, str) and ldflag.startswith("-l"):
                        ldflag = ldflag.replace('-l', '--extra-library=', 1)
                    fixed_ldflags.add(ldflag)
                return fixed_ldflags
            internal_ldflags = fix_ldflags(internal_ldflags)
            external_ldflags = fix_ldflags(external_ldflags)
        return cflags, internal_ldflags, external_ldflags, gi_includes, depends
```

**逻辑推理:**

这段代码首先检查 `g-ir-scanner` 是否支持 `--extra-library` 选项。如果支持，它定义了一个 `fix_ldflags` 函数。这个函数遍历传入的链接标志列表，如果发现以 `-l` 开头的字符串标志，就将其替换为以 `--extra-library=` 开头的字符串。这是为了适应 `g-ir-scanner` 对库的指定方式。

**输出:**

* `internal_ldflags`: 如果 `g-ir-scanner` 支持 `--extra-library`，并且原始 `internal_ldflags` 包含 `'-lm'`，那么输出的 `internal_ldflags` 将包含 `'--extra-library=m'`。否则，保持不变。
* `external_ldflags`: 同理，如果 `g-ir-scanner` 支持 `--extra-library`，并且原始 `external_ldflags` 包含 `'-lpthread'`，那么输出的 `external_ldflags` 将包含 `'--extra-library=pthread'`。否则，保持不变。
* `cflags`, `gi_includes`, `depends`: 这部分代码没有修改这些变量，所以它们会原样输出。

**涉及用户或编程常见的使用错误及举例说明:**

* **未安装 GObject-Introspection 工具:** 如果用户的系统上没有安装 `g-ir-scanner` 或 `g-ir-compiler`，Meson 构建过程会报错。
* **GIR 目标类型错误:** 用户在调用 `generate_gir` 函数时，可能会错误地将非可执行文件或库文件作为参数传递，导致 `_unwrap_gir_target` 函数抛出 `MesonException`。
* **依赖项缺失:**  如果用户要内省的库依赖于其他库，但这些依赖项没有被正确地指定，`g-ir-scanner` 可能会失败。
* **包含目录配置错误:** 如果头文件所在的目录没有被正确地添加到包含路径中，`g-ir-scanner` 无法找到所需的头文件，导致 GIR 生成失败。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户配置 Meson 构建:** 用户在项目的 `meson.build` 文件中使用了 `gnome.generate_gir` 函数，并指定了一个或多个可执行文件或共享库作为要生成 GIR 信息的对象。
2. **用户运行 Meson 配置命令:** 用户执行类似 `meson setup builddir` 的命令来配置构建环境。Meson 会解析 `meson.build` 文件，并调用相应的模块方法。
3. **Meson 调用 `gnome.generate_gir`:** 当 Meson 执行到 `gnome.generate_gir` 函数时，会调用该函数内部的逻辑，其中就包含了这个代码片段所在的 `_get_dependencies_flags_raw` 函数。
4. **传递链接标志:** 在处理依赖项时，Meson 会收集构建目标的内部和外部链接标志，并将它们作为参数传递给 `_get_dependencies_flags_raw` 函数。
5. **检查 `g-ir-scanner` 的选项:**  `_gir_has_option('--extra-library')` 会被调用，以确定如何处理链接标志。
6. **（如果需要）修改链接标志:** 如果 `g-ir-scanner` 支持 `--extra-library`，`fix_ldflags` 函数会被调用来修改链接标志。

**调试线索:** 如果用户在构建过程中遇到与 GIR 生成相关的错误，例如 `g-ir-scanner` 找不到库，可以检查以下几点：

* 确保已安装 GObject-Introspection 工具。
* 检查传递给 `generate_gir` 的目标是否是正确的库文件或可执行文件。
* 检查目标库的依赖项是否已正确配置，并且链接标志是否正确。
* 检查是否需要设置额外的环境变量，例如 `LD_LIBRARY_PATH`。
* 检查头文件路径是否已正确添加到包含路径中。

总而言之，这段代码是 Frida 构建过程中处理 GNOME 技术栈的关键部分，负责生成用于运行时自省的 GIR 数据，这对于 Frida 的动态 instrumentation 功能至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/modules/gnome.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
self._gir_has_option('--extra-library'):
            def fix_ldflags(ldflags: T.Iterable[T.Union[str, T.Tuple[str, str]]]) -> OrderedSet[T.Union[str, T.Tuple[str, str]]]:
                fixed_ldflags: OrderedSet[T.Union[str, T.Tuple[str, str]]] = OrderedSet()
                for ldflag in ldflags:
                    if isinstance(ldflag, str) and ldflag.startswith("-l"):
                        ldflag = ldflag.replace('-l', '--extra-library=', 1)
                    fixed_ldflags.add(ldflag)
                return fixed_ldflags
            internal_ldflags = fix_ldflags(internal_ldflags)
            external_ldflags = fix_ldflags(external_ldflags)
        return cflags, internal_ldflags, external_ldflags, gi_includes, depends

    def _get_dependencies_flags(
            self, deps: T.Sequence[T.Union['Dependency', build.BuildTarget, CustomTarget, CustomTargetIndex]],
            state: 'ModuleState',
            depends: T.Sequence[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]],
            include_rpath: bool = False,
            use_gir_args: bool = False,
            ) -> T.Tuple[OrderedSet[str], T.List[str], T.List[str], OrderedSet[str],
                         T.List[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]]]:

        cflags, internal_ldflags_raw, external_ldflags_raw, gi_includes, depends = self._get_dependencies_flags_raw(deps, state, depends, include_rpath, use_gir_args)
        internal_ldflags: T.List[str] = []
        external_ldflags: T.List[str] = []

        # Extract non-deduplicable argument groups out of the tuples.
        for ldflag in internal_ldflags_raw:
            if isinstance(ldflag, str):
                internal_ldflags.append(ldflag)
            else:
                internal_ldflags.extend(ldflag)
        for ldflag in external_ldflags_raw:
            if isinstance(ldflag, str):
                external_ldflags.append(ldflag)
            else:
                external_ldflags.extend(ldflag)

        return cflags, internal_ldflags, external_ldflags, gi_includes, depends

    def _unwrap_gir_target(self, girtarget: T.Union[Executable, build.StaticLibrary, build.SharedLibrary], state: 'ModuleState'
                           ) -> T.Union[Executable, build.StaticLibrary, build.SharedLibrary]:
        if not isinstance(girtarget, (Executable, build.SharedLibrary,
                                      build.StaticLibrary)):
            raise MesonException(f'Gir target must be an executable or library but is "{girtarget}" of type {type(girtarget).__name__}')

        STATIC_BUILD_REQUIRED_VERSION = ">=1.58.1"
        if isinstance(girtarget, (build.StaticLibrary)) and \
           not mesonlib.version_compare(
               self._get_gir_dep(state)[0].get_version(),
               STATIC_BUILD_REQUIRED_VERSION):
            raise MesonException('Static libraries can only be introspected with GObject-Introspection ' + STATIC_BUILD_REQUIRED_VERSION)

        return girtarget

    def _devenv_prepend(self, varname: str, value: str) -> None:
        if self.devenv is None:
            self.devenv = mesonlib.EnvironmentVariables()
        self.devenv.prepend(varname, [value])

    def postconf_hook(self, b: build.Build) -> None:
        if self.devenv is not None:
            b.devenv.append(self.devenv)

    def _get_gir_dep(self, state: 'ModuleState') -> T.Tuple[Dependency, T.Union[Executable, 'ExternalProgram', 'OverrideProgram'],
                                                            T.Union[Executable, 'ExternalProgram', 'OverrideProgram']]:
        if not self.gir_dep:
            self.gir_dep = state.dependency('gobject-introspection-1.0')
            self.giscanner = self._find_tool(state, 'g-ir-scanner')
            self.gicompiler = self._find_tool(state, 'g-ir-compiler')
        return self.gir_dep, self.giscanner, self.gicompiler

    @functools.lru_cache(maxsize=None)
    def _gir_has_option(self, option: str) -> bool:
        exe = self.giscanner
        if isinstance(exe, OverrideProgram):
            # Handle overridden g-ir-scanner
            assert option in {'--extra-library', '--sources-top-dirs'}
            return True
        p, o, _ = Popen_safe(exe.get_command() + ['--help'], stderr=subprocess.STDOUT)
        return p.returncode == 0 and option in o

    # May mutate depends and gir_inc_dirs
    @staticmethod
    def _scan_include(state: 'ModuleState', includes: T.List[T.Union[str, GirTarget]]
                      ) -> T.Tuple[T.List[str], T.List[str], T.List[GirTarget]]:
        ret: T.List[str] = []
        gir_inc_dirs: T.List[str] = []
        depends: T.List[GirTarget] = []

        for inc in includes:
            if isinstance(inc, str):
                ret += [f'--include={inc}']
            elif isinstance(inc, GirTarget):
                gir_inc_dirs .append(os.path.join(state.environment.get_build_dir(), inc.get_source_subdir()))
                ret.append(f"--include-uninstalled={os.path.join(inc.get_source_subdir(), inc.get_basename())}")
                depends.append(inc)

        return ret, gir_inc_dirs, depends

    @staticmethod
    def _scan_langs(state: 'ModuleState', langs: T.Iterable[str]) -> T.List[str]:
        ret: T.List[str] = []

        for lang in langs:
            link_args = state.environment.coredata.get_external_link_args(MachineChoice.HOST, lang)
            for link_arg in link_args:
                if link_arg.startswith('-L'):
                    ret.append(link_arg)

        return ret

    @staticmethod
    def _scan_gir_targets(state: 'ModuleState', girtargets: T.Sequence[build.BuildTarget]) -> T.List[T.Union[str, Executable]]:
        ret: T.List[T.Union[str, Executable]] = []

        for girtarget in girtargets:
            if isinstance(girtarget, Executable):
                ret += ['--program', girtarget]
            else:
                # Because of https://gitlab.gnome.org/GNOME/gobject-introspection/merge_requests/72
                # we can't use the full path until this is merged.
                libpath = os.path.join(girtarget.get_source_subdir(), girtarget.get_filename())
                # Must use absolute paths here because g-ir-scanner will not
                # add them to the runtime path list if they're relative. This
                # means we cannot use @BUILD_ROOT@
                build_root = state.environment.get_build_dir()
                if isinstance(girtarget, build.SharedLibrary):
                    # need to put our output directory first as we need to use the
                    # generated libraries instead of any possibly installed system/prefix
                    # ones.
                    ret += ["-L{}/{}".format(build_root, os.path.dirname(libpath))]
                    libname = girtarget.get_basename()
                else:
                    libname = os.path.join(f"{build_root}/{libpath}")
                ret += ['--library', libname]
                # Needed for the following binutils bug:
                # https://github.com/mesonbuild/meson/issues/1911
                # However, g-ir-scanner does not understand -Wl,-rpath
                # so we need to use -L instead
                for d in state.backend.determine_rpath_dirs(girtarget):
                    d = os.path.join(state.environment.get_build_dir(), d)
                    ret.append('-L' + d)

        return ret

    @staticmethod
    def _get_girtargets_langs_compilers(girtargets: T.Sequence[build.BuildTarget]) -> T.List[T.Tuple[str, 'Compiler']]:
        ret: T.List[T.Tuple[str, 'Compiler']] = []
        for girtarget in girtargets:
            for lang, compiler in girtarget.compilers.items():
                # XXX: Can you use g-i with any other language?
                if lang in {'c', 'cpp', 'objc', 'objcpp', 'd'}:
                    ret.append((lang, compiler))
                    break

        return ret

    @staticmethod
    def _get_gir_targets_deps(girtargets: T.Sequence[build.BuildTarget]
                              ) -> T.List[T.Union[build.BuildTarget, CustomTarget, CustomTargetIndex, Dependency]]:
        ret: T.List[T.Union[build.BuildTarget, CustomTarget, CustomTargetIndex, Dependency]] = []
        for girtarget in girtargets:
            ret += girtarget.get_all_link_deps()
            ret += girtarget.get_external_deps()
        return ret

    @staticmethod
    def _get_gir_targets_inc_dirs(girtargets: T.Sequence[build.BuildTarget]) -> OrderedSet[build.IncludeDirs]:
        ret: OrderedSet = OrderedSet()
        for girtarget in girtargets:
            ret.update(girtarget.get_include_dirs())
        return ret

    @staticmethod
    def _get_langs_compilers_flags(state: 'ModuleState', langs_compilers: T.List[T.Tuple[str, 'Compiler']]
                                   ) -> T.Tuple[T.List[str], T.List[str], T.List[str]]:
        cflags: T.List[str] = []
        internal_ldflags: T.List[str] = []
        external_ldflags: T.List[str] = []

        for lang, compiler in langs_compilers:
            if state.global_args.get(lang):
                cflags += state.global_args[lang]
            if state.project_args.get(lang):
                cflags += state.project_args[lang]
            if mesonlib.OptionKey('b_sanitize') in compiler.base_options:
                sanitize = state.environment.coredata.options[mesonlib.OptionKey('b_sanitize')].value
                cflags += compiler.sanitizer_compile_args(sanitize)
                sanitize = sanitize.split(',')
                # These must be first in ldflags
                if 'address' in sanitize:
                    internal_ldflags += ['-lasan']
                if 'thread' in sanitize:
                    internal_ldflags += ['-ltsan']
                if 'undefined' in sanitize:
                    internal_ldflags += ['-lubsan']
                # FIXME: Linking directly to lib*san is not recommended but g-ir-scanner
                # does not understand -f LDFLAGS. https://bugzilla.gnome.org/show_bug.cgi?id=783892
                # ldflags += compiler.sanitizer_link_args(sanitize)

        return cflags, internal_ldflags, external_ldflags

    @staticmethod
    def _make_gir_filelist(state: 'ModuleState', srcdir: str, ns: str,
                           nsversion: str, girtargets: T.Sequence[build.BuildTarget],
                           libsources: T.Sequence[T.Union[
                               str, mesonlib.File, GeneratedList,
                               CustomTarget, CustomTargetIndex]]
                           ) -> str:
        gir_filelist_dir = state.backend.get_target_private_dir_abs(girtargets[0])
        if not os.path.isdir(gir_filelist_dir):
            os.mkdir(gir_filelist_dir)
        gir_filelist_filename = os.path.join(gir_filelist_dir, f'{ns}_{nsversion}_gir_filelist')

        with open(gir_filelist_filename, 'w', encoding='utf-8') as gir_filelist:
            for s in libsources:
                if isinstance(s, (CustomTarget, CustomTargetIndex)):
                    for custom_output in s.get_outputs():
                        gir_filelist.write(os.path.join(state.environment.get_build_dir(),
                                                        state.backend.get_target_dir(s),
                                                        custom_output) + '\n')
                elif isinstance(s, mesonlib.File):
                    gir_filelist.write(s.rel_to_builddir(state.build_to_src) + '\n')
                elif isinstance(s, GeneratedList):
                    for gen_src in s.get_outputs():
                        gir_filelist.write(os.path.join(srcdir, gen_src) + '\n')
                else:
                    gir_filelist.write(os.path.join(srcdir, s) + '\n')

        return gir_filelist_filename

    @staticmethod
    def _make_gir_target(
            state: 'ModuleState',
            girfile: str,
            scan_command: T.Sequence[T.Union['FileOrString', Executable, ExternalProgram, OverrideProgram]],
            generated_files: T.Sequence[T.Union[str, mesonlib.File, CustomTarget, CustomTargetIndex, GeneratedList]],
            depends: T.Sequence[T.Union['FileOrString', build.BuildTarget, 'build.GeneratedTypes', build.StructuredSources]],
            kwargs: T.Dict[str, T.Any]) -> GirTarget:
        install = kwargs['install_gir']
        if install is None:
            install = kwargs['install']

        install_dir = kwargs['install_dir_gir']
        if install_dir is None:
            install_dir = os.path.join(state.environment.get_datadir(), 'gir-1.0')
        elif install_dir is False:
            install = False

        # g-ir-scanner uses pkg-config to find libraries such as glib. They could
        # be built as subproject in which case we need to trick it to use
        # -uninstalled.pc files Meson generated. It also must respect pkgconfig
        # settings user could have set in machine file, like PKG_CONFIG_LIBDIR,
        # SYSROOT, etc.
        run_env = PkgConfigInterface.get_env(state.environment, MachineChoice.HOST, uninstalled=True)
        # g-ir-scanner uses Python's distutils to find the compiler, which uses 'CC'
        cc_exelist = state.environment.coredata.compilers.host['c'].get_exelist()
        run_env.set('CC', [quote_arg(x) for x in cc_exelist], ' ')
        run_env.merge(kwargs['env'])

        return GirTarget(
            girfile,
            state.subdir,
            state.subproject,
            state.environment,
            scan_command,
            generated_files,
            [girfile],
            state.is_build_only_subproject,
            build_by_default=kwargs['build_by_default'],
            extra_depends=depends,
            install=install,
            install_dir=[install_dir],
            install_tag=['devel'],
            env=run_env,
        )

    @staticmethod
    def _make_typelib_target(state: 'ModuleState', typelib_output: str,
                             typelib_cmd: T.Sequence[T.Union[str, Executable, ExternalProgram, CustomTarget]],
                             generated_files: T.Sequence[T.Union[str, mesonlib.File, CustomTarget, CustomTargetIndex, GeneratedList]],
                             kwargs: T.Dict[str, T.Any]) -> TypelibTarget:
        install = kwargs['install_typelib']
        if install is None:
            install = kwargs['install']

        install_dir = kwargs['install_dir_typelib']
        if install_dir is None:
            install_dir = os.path.join(state.environment.get_libdir(), 'girepository-1.0')
        elif install_dir is False:
            install = False

        return TypelibTarget(
            typelib_output,
            state.subdir,
            state.subproject,
            state.environment,
            typelib_cmd,
            generated_files,
            [typelib_output],
            state.is_build_only_subproject,
            install=install,
            install_dir=[install_dir],
            install_tag=['typelib'],
            build_by_default=kwargs['build_by_default'],
            env=kwargs['env'],
        )

    @staticmethod
    def _gather_typelib_includes_and_update_depends(
            state: 'ModuleState',
            deps: T.Sequence[T.Union[Dependency, build.BuildTarget, CustomTarget, CustomTargetIndex]],
            depends: T.Sequence[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]]
            ) -> T.Tuple[T.List[str], T.List[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]]]:
        # Need to recursively add deps on GirTarget sources from our
        # dependencies and also find the include directories needed for the
        # typelib generation custom target below.
        typelib_includes: T.List[str] = []
        new_depends = list(depends)
        for dep in deps:
            # Add a dependency on each GirTarget listed in dependencies and add
            # the directory where it will be generated to the typelib includes
            if isinstance(dep, InternalDependency):
                for source in dep.sources:
                    if isinstance(source, GirTarget) and source not in depends:
                        new_depends.append(source)
                        subdir = os.path.join(state.environment.get_build_dir(),
                                              source.get_source_subdir())
                        if subdir not in typelib_includes:
                            typelib_includes.append(subdir)
            # Do the same, but for dependencies of dependencies. These are
            # stored in the list of generated sources for each link dep (from
            # girtarget.get_all_link_deps() above).
            # FIXME: Store this in the original form from declare_dependency()
            # so it can be used here directly.
            elif isinstance(dep, build.SharedLibrary):
                for g_source in dep.generated:
                    if isinstance(g_source, GirTarget):
                        subdir = os.path.join(state.environment.get_build_dir(),
                                              g_source.get_source_subdir())
                        if subdir not in typelib_includes:
                            typelib_includes.append(subdir)
            if isinstance(dep, Dependency):
                girdir = dep.get_variable(pkgconfig='girdir', internal='girdir', default_value='')
                assert isinstance(girdir, str), 'for mypy'
                if girdir and girdir not in typelib_includes:
                    typelib_includes.append(girdir)
        return typelib_includes, new_depends

    @staticmethod
    def _get_external_args_for_langs(state: 'ModuleState', langs: T.List[str]) -> T.List[str]:
        ret: T.List[str] = []
        for lang in langs:
            ret += mesonlib.listify(state.environment.coredata.get_external_args(MachineChoice.HOST, lang))
        return ret

    @staticmethod
    def _get_scanner_cflags(cflags: T.Iterable[str]) -> T.Iterable[str]:
        'g-ir-scanner only accepts -I/-D/-U; must ignore all other flags'
        for f in cflags:
            # _FORTIFY_SOURCE depends on / works together with -O, on the other hand this
            # just invokes the preprocessor anyway
            if f.startswith(('-D', '-U', '-I')) and not f.startswith('-D_FORTIFY_SOURCE'):
                yield f

    @staticmethod
    def _get_scanner_ldflags(ldflags: T.Iterable[str]) -> T.Iterable[str]:
        'g-ir-scanner only accepts -L/-l; must ignore -F and other linker flags'
        for f in ldflags:
            if f.startswith(('-L', '-l', '--extra-library')):
                yield f

    @typed_pos_args('gnome.generate_gir', varargs=(Executable, build.SharedLibrary, build.StaticLibrary), min_varargs=1)
    @typed_kwargs(
        'gnome.generate_gir',
        INSTALL_KW,
        _BUILD_BY_DEFAULT.evolve(since='0.40.0'),
        _EXTRA_ARGS_KW,
        ENV_KW.evolve(since='1.2.0'),
        KwargInfo('dependencies', ContainerTypeInfo(list, Dependency), default=[], listify=True),
        KwargInfo('export_packages', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('fatal_warnings', bool, default=False, since='0.55.0'),
        KwargInfo('header', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('identifier_prefix', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('include_directories', ContainerTypeInfo(list, (str, build.IncludeDirs)), default=[], listify=True),
        KwargInfo('includes', ContainerTypeInfo(list, (str, GirTarget)), default=[], listify=True),
        KwargInfo('install_gir', (bool, NoneType), since='0.61.0'),
        KwargInfo('install_dir_gir', (str, bool, NoneType),
                  deprecated_values={False: ('0.61.0', 'Use install_gir to disable installation')},
                  validator=lambda x: 'as boolean can only be false' if x is True else None),
        KwargInfo('install_typelib', (bool, NoneType), since='0.61.0'),
        KwargInfo('install_dir_typelib', (str, bool, NoneType),
                  deprecated_values={False: ('0.61.0', 'Use install_typelib to disable installation')},
                  validator=lambda x: 'as boolean can only be false' if x is True else None),
        KwargInfo('link_with', ContainerTypeInfo(list, (build.SharedLibrary, build.StaticLibrary)), default=[], listify=True),
        KwargInfo('namespace', str, required=True),
        KwargInfo('nsversion', str, required=True),
        KwargInfo('sources', ContainerTypeInfo(list, (str, mesonlib.File, GeneratedList, CustomTarget, CustomTargetIndex)), default=[], listify=True),
        KwargInfo('symbol_prefix', ContainerTypeInfo(list, str), default=[], listify=True),
    )
    def generate_gir(self, state: 'ModuleState', args: T.Tuple[T.List[T.Union[Executable, build.SharedLibrary, build.StaticLibrary]]],
                     kwargs: 'GenerateGir') -> ModuleReturnValue:
        # Ensure we have a C compiler even in C++ projects.
        state.add_language('c', MachineChoice.HOST)

        girtargets = [self._unwrap_gir_target(arg, state) for arg in args[0]]
        if len(girtargets) > 1 and any(isinstance(el, Executable) for el in girtargets):
            raise MesonException('generate_gir only accepts a single argument when one of the arguments is an executable')

        gir_dep, giscanner, gicompiler = self._get_gir_dep(state)

        ns = kwargs['namespace']
        nsversion = kwargs['nsversion']
        libsources = kwargs['sources']

        girfile = f'{ns}-{nsversion}.gir'
        srcdir = os.path.join(state.environment.get_source_dir(), state.subdir)
        builddir = os.path.join(state.environment.get_build_dir(), state.subdir)

        depends: T.List[T.Union['FileOrString', 'build.GeneratedTypes', build.BuildTarget, build.StructuredSources]] = []
        depends.extend(gir_dep.sources)
        depends.extend(girtargets)

        langs_compilers = self._get_girtargets_langs_compilers(girtargets)
        cflags, internal_ldflags, external_ldflags = self._get_langs_compilers_flags(state, langs_compilers)
        deps = self._get_gir_targets_deps(girtargets)
        deps += kwargs['dependencies']
        deps += [gir_dep]
        typelib_includes, depends = self._gather_typelib_includes_and_update_depends(state, deps, depends)
        # ldflags will be misinterpreted by gir scanner (showing
        # spurious dependencies) but building GStreamer fails if they
        # are not used here.
        dep_cflags, dep_internal_ldflags, dep_external_ldflags, gi_includes, depends = \
            self._get_dependencies_flags(deps, state, depends, use_gir_args=True)
        scan_cflags = []
        scan_cflags += list(self._get_scanner_cflags(cflags))
        scan_cflags += list(self._get_scanner_cflags(dep_cflags))
        scan_cflags += list(self._get_scanner_cflags(self._get_external_args_for_langs(state, [lc[0] for lc in langs_compilers])))
        scan_internal_ldflags = []
        scan_internal_ldflags += list(self._get_scanner_ldflags(internal_ldflags))
        scan_internal_ldflags += list(self._get_scanner_ldflags(dep_internal_ldflags))
        scan_external_ldflags = []
        scan_external_ldflags += list(self._get_scanner_ldflags(external_ldflags))
        scan_external_ldflags += list(self._get_scanner_ldflags(dep_external_ldflags))
        girtargets_inc_dirs = self._get_gir_targets_inc_dirs(girtargets)
        inc_dirs = kwargs['include_directories']

        gir_inc_dirs: T.List[str] = []

        scan_command: T.List[T.Union[str, Executable, 'ExternalProgram', 'OverrideProgram']] = [giscanner]
        scan_command += ['--quiet']
        scan_command += ['--no-libtool']
        scan_command += ['--namespace=' + ns, '--nsversion=' + nsversion]
        scan_command += ['--warn-all']
        scan_command += ['--output', '@OUTPUT@']
        scan_command += [f'--c-include={h}' for h in kwargs['header']]
        scan_command += kwargs['extra_args']
        scan_command += ['-I' + srcdir, '-I' + builddir]
        scan_command += state.get_include_args(girtargets_inc_dirs)
        scan_command += ['--filelist=' + self._make_gir_filelist(state, srcdir, ns, nsversion, girtargets, libsources)]
        for l in kwargs['link_with']:
            _cflags, depends = self._get_link_args(state, l, depends, use_gir_args=True)
            scan_command.extend(_cflags)
        _cmd, _ginc, _deps = self._scan_include(state, kwargs['includes'])
        scan_command.extend(_cmd)
        gir_inc_dirs.extend(_ginc)
        depends.extend(_deps)

        scan_command += [f'--symbol-prefix={p}' for p in kwargs['symbol_prefix']]
        scan_command += [f'--identifier-prefix={p}' for p in kwargs['identifier_prefix']]
        scan_command += [f'--pkg-export={p}' for p in kwargs['export_packages']]
        scan_command += ['--cflags-begin']
        scan_command += scan_cflags
        scan_command += ['--cflags-end']
        scan_command += state.get_include_args(inc_dirs)
        scan_command += state.get_include_args(itertools.chain(gi_includes, gir_inc_dirs, inc_dirs), prefix='--add-include-path=')
        scan_command += list(scan_internal_ldflags)
        scan_command += self._scan_gir_targets(state, girtargets)
        scan_command += self._scan_langs(state, [lc[0] for lc in langs_compilers])
        scan_command += list(scan_external_ldflags)

        if self._gir_has_option('--sources-top-dirs'):
            scan_command += ['--sources-top-dirs', os.path.join(state.environment.get_source_dir(), state.root_subdir)]
            scan_command += ['--sources-top-dirs', os.path.join(state.environment.get_build_dir(), state.root_subdir)]

        if '--warn-error' in scan_command:
            FeatureDeprecated.single_use('gnome.generate_gir argument --warn-error', '0.55.0',
                                         state.subproject, 'Use "fatal_warnings" keyword argument', state.current_node)
        if kwargs['fatal_warnings']:
            scan_command.append('--warn-error')

        generated_files = [f for f in libsources if isinstance(f, (GeneratedList, CustomTarget, CustomTargetIndex))]

        scan_target = self._make_gir_target(
            state, girfile, scan_command, generated_files, depends,
            # We have to cast here because mypy can't figure this out
            T.cast('T.Dict[str, T.Any]', kwargs))

        typelib_output = f'{ns}-{nsversion}.typelib'
        typelib_cmd = [gicompiler, scan_target, '--output', '@OUTPUT@']
        typelib_cmd += state.get_include_args(gir_inc_dirs, prefix='--includedir=')

        for incdir in typelib_includes:
            typelib_cmd += ["--includedir=" + incdir]

        typelib_target = self._make_typelib_target(state, typelib_output, typelib_cmd, generated_files, T.cast('T.Dict[str, T.Any]', kwargs))

        self._devenv_prepend('GI_TYPELIB_PATH', os.path.join(state.environment.get_build_dir(), state.subdir))

        rv = [scan_target, typelib_target]

        return ModuleReturnValue(rv, rv)

    @noPosargs
    @typed_kwargs('gnome.compile_schemas', _BUILD_BY_DEFAULT.evolve(since='0.40.0'), DEPEND_FILES_KW)
    def compile_schemas(self, state: 'ModuleState', args: T.List['TYPE_var'], kwargs: 'CompileSchemas') -> ModuleReturnValue:
        srcdir = os.path.join(state.build_to_src, state.subdir)
        outdir = state.subdir

        cmd: T.List[T.Union['ToolType', str]] = [self._find_tool(state, 'glib-compile-schemas'), '--targetdir', outdir, srcdir]
        if state.subdir == '':
            targetname = 'gsettings-compile'
        else:
            targetname = 'gsettings-compile-' + state.subdir.replace('/', '_')
        target_g = CustomTarget(
            targetname,
            state.subdir,
            state.subproject,
            state.environment,
            cmd,
            [],
            ['gschemas.compiled'],
            state.is_build_only_subproject,
            build_by_default=kwargs['build_by_default'],
            depend_files=kwargs['depend_files'],
            description='Compiling gschemas {}',
        )
        self._devenv_prepend('GSETTINGS_SCHEMA_DIR', os.path.join(state.environment.get_build_dir(), state.subdir))
        return ModuleReturnValue(target_g, [target_g])

    @typed_pos_args('gnome.yelp', str, varargs=str)
    @typed_kwargs(
        'gnome.yelp',
        KwargInfo(
            'languages', ContainerTypeInfo(list, str),
            listify=True, default=[],
            deprecated='0.43.0',
            deprecated_message='Use a LINGUAS file in the source directory instead',
        ),
        KwargInfo('media', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('sources', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('symlink_media', bool, default=True),
    )
    def yelp(self, state: 'ModuleState', args: T.Tuple[str, T.List[str]], kwargs: 'Yelp') -> ModuleReturnValue:
        project_id = args[0]
        sources = kwargs['sources']
        if args[1]:
            FeatureDeprecated.single_use('gnome.yelp more than one positional argument', '0.60.0',
                                         state.subproject, 'use the "sources" keyword argument instead.', state.current_node)
        if not sources:
            sources = args[1]
            if not sources:
                raise MesonException('Yelp requires a list of sources')
        elif args[1]:
            mlog.warning('"gnome.yelp" ignores positional sources arguments when the "sources" keyword argument is set')
        sources_files = [mesonlib.File.from_source_file(state.environment.source_dir,
                                                        os.path.join(state.subdir, 'C'),
                                                        s) for s in sources]

        langs = kwargs['languages']
        if not langs:
            langs = read_linguas(os.path.join(state.environment.source_dir, state.subdir))

        media = kwargs['media']
        symlinks = kwargs['symlink_media']
        targets: T.List[T.Union['build.Target', build.Data, build.SymlinkData]] = []
        potargets: T.List[build.RunTarget] = []

        itstool = state.find_program('itstool')
        msgmerge = state.find_program('msgmerge')
        msgfmt = state.find_program('msgfmt')

        install_dir = os.path.join(state.environment.get_datadir(), 'help')
        c_install_dir = os.path.join(install_dir, 'C', project_id)
        c_data = build.Data(sources_files, c_install_dir, c_install_dir,
                            mesonlib.FileMode(), state.subproject, install_tag='doc')
        targets.append(c_data)

        media_files: T.List[mesonlib.File] = []
        for m in media:
            f = mesonlib.File.from_source_file(state.environment.source_dir,
                                               os.path.join(state.subdir, 'C'), m)
            media_files.append(f)
            m_install_dir = os.path.join(c_install_dir, os.path.dirname(m))
            m_data = build.Data([f], m_install_dir, m_install_dir,
                                mesonlib.FileMode(), state.subproject, install_tag='doc')
            targets.append(m_data)

        pot_file = os.path.join('@SOURCE_ROOT@', state.subdir, 'C', project_id + '.pot')
        pot_sources = [os.path.join('@SOURCE_ROOT@', state.subdir, 'C', s) for s in sources]
        pot_args: T.List[T.Union[ExternalProgram, Executable, OverrideProgram, str]] = [itstool, '-o', pot_file]
        pot_args.extend(pot_sources)
        pottarget = build.RunTarget(f'help-{project_id}-pot', pot_args, [],
                                    os.path.join(state.subdir, 'C'), state.subproject,
                                    state.environment)
        targets.append(pottarget)

        for l in langs:
            l_subdir = os.path.join(state.subdir, l)
            l_install_dir = os.path.join(install_dir, l, project_id)

            for i, m in enumerate(media):
                m_dir = os.path.dirname(m)
                m_install_dir = os.path.join(l_install_dir, m_dir)
                l_data: T.Union[build.Data, build.SymlinkData]
                if symlinks:
                    link_target = os.path.join(os.path.relpath(c_install_dir, start=m_install_dir), m)
                    l_data = build.SymlinkData(link_target, os.path.basename(m),
                                               m_install_dir, state.subproject, install_tag='doc')
                else:
                    try:
                        m_file = mesonlib.File.from_source_file(state.environment.source_dir, l_subdir, m)
                    except MesonException:
                        m_file = media_files[i]
             
"""


```