Response:
The user wants to understand the functionality of the provided Python code snippet, which is part of the `gnome.py` module in the Frida dynamic instrumentation tool. I need to analyze the code and identify its primary functions, relating them to reverse engineering, binary manipulation, and interaction with Linux/Android systems if applicable. I also need to look for logical deductions, potential user errors, and how a user might end up using this code. Finally, I need to summarize the identified functionalities.

Here's a breakdown of the code's functionality:

1. **`fix_ldflags` function:** This function modifies linker flags, specifically replacing `-l` with `--extra-library=`. This suggests interaction with external libraries and potentially a need to adjust how these libraries are linked.

2. **`_get_dependencies_flags_raw` and `_get_dependencies_flags` functions:** These functions retrieve compiler flags, linker flags, and include directories for dependencies. This is crucial for building software components that rely on other libraries.

3. **`_unwrap_gir_target` function:** This function validates if a given target is a valid GObject Introspection (GIR) target (executable or library). It also checks the version of `gobject-introspection` for static library introspection.

4. **`_devenv_prepend` and `postconf_hook` functions:** These functions manage environment variables. `_devenv_prepend` adds a value to an environment variable, and `postconf_hook` applies these changes to the build environment.

5. **`_get_gir_dep` function:** This function retrieves dependencies related to GObject Introspection, including the `gobject-introspection` dependency and the `g-ir-scanner` and `g-ir-compiler` tools.

6. **`_gir_has_option` function:** This function checks if the `g-ir-scanner` tool supports a specific option.

7. **`_scan_include` function:** This function processes include paths, distinguishing between regular include directories and those related to other GIR targets.

8. **`_scan_langs` function:** This function extracts linker flags specific to programming languages.

9. **`_scan_gir_targets` function:** This function generates arguments for `g-ir-scanner` related to target libraries or executables. It needs to handle both shared and static libraries, and adjust the library paths.

10. **`_get_girtargets_langs_compilers` function:** This function identifies the programming languages and their compilers used by the GIR targets.

11. **`_get_gir_targets_deps` function:** This function collects all the link-time dependencies of the GIR targets.

12. **`_get_gir_targets_inc_dirs` function:** This function gathers the include directories of the GIR targets.

13. **`_get_langs_compilers_flags` function:** This function retrieves compiler and linker flags based on the programming languages and compilers. It also handles sanitizer flags.

14. **`_make_gir_filelist` function:** This function creates a file list containing the source files for generating the GIR file.

15. **`_make_gir_target` function:** This function creates a custom target for generating the GIR file using `g-ir-scanner`. It handles installation and environment settings.

16. **`_make_typelib_target` function:** This function creates a custom target for generating the typelib file using `g-ir-compiler`. It also handles installation.

17. **`_gather_typelib_includes_and_update_depends` function:** This function gathers include directories needed for typelib generation and updates the dependency list.

18. **`_get_external_args_for_langs` function:** This function retrieves external arguments for specific programming languages.

19. **`_get_scanner_cflags` and `_get_scanner_ldflags` functions:** These functions filter compiler and linker flags to only include those accepted by `g-ir-scanner`.

20. **`generate_gir` function:** This is the main function for generating GIR and typelib files. It orchestrates the use of the other helper functions, taking various arguments related to namespaces, versions, sources, dependencies, and installation.

21. **`compile_schemas` function:** This function compiles GSettings schemas using `glib-compile-schemas`.

22. **`yelp` function:** This function generates documentation using Yelp, a help system for GNOME.

Considering the request, I need to focus on summarizing the functionalities of the provided code snippet, which appears to be primarily within the `generate_gir` function and its helper functions.
This代码片段主要负责**生成 GObject Introspection (GIR) 文件和 Typelib 文件**。GIR 文件是描述 C 语言库的元数据，允许其他语言（如 Python、JavaScript）通过 GObject 系统使用这些库。Typelib 文件是 GIR 文件的编译版本，用于运行时加载。

以下是代码片段中主要功能点的归纳：

1. **处理链接器标志 (Linker Flags):**
    *   `fix_ldflags` 函数会将以 `-l` 开头的链接器标志替换为 `--extra-library=`。这可能是为了适配 `g-ir-scanner` 工具的参数格式，该工具可能需要 `--extra-library` 来指定额外的库。

2. **获取依赖的编译和链接标志:**
    *   `_get_dependencies_flags_raw` 和 `_get_dependencies_flags` 函数递归地获取所有依赖项的编译标志 (cflags)、内部链接器标志 (internal\_ldflags)、外部链接器标志 (external\_ldflags) 以及 GIR 相关的 include 目录。这是确保在生成 GIR 文件时，编译器和链接器能够正确找到所有必要的头文件和库文件。

3. **验证 GIR 目标:**
    *   `_unwrap_gir_target` 函数检查作为 GIR 生成目标的参数是否是可执行文件或库文件 (`Executable`, `build.SharedLibrary`, `build.StaticLibrary`)。它还检查了对于静态库进行自省时，`gobject-introspection` 的版本是否满足最低要求。

4. **管理环境变量:**
    *   `_devenv_prepend` 函数用于在内部维护一个环境变量字典，可以在构建过程中设置或修改环境变量。
    *   `postconf_hook` 函数将这些环境变量应用到最终的构建环境中。

5. **获取 GObject Introspection 依赖:**
    *   `_get_gir_dep` 函数用于获取 `gobject-introspection` 依赖以及 `g-ir-scanner` 和 `g-ir-compiler` 工具的路径。

6. **检查 `g-ir-scanner` 的选项支持:**
    *   `_gir_has_option` 函数检查 `g-ir-scanner` 工具是否支持特定的选项，例如 `--extra-library` 和 `--sources-top-dirs`。

7. **处理 include 目录:**
    *   `_scan_include` 函数处理 include 目录，它能区分普通的字符串 include 路径和 `GirTarget` 类型的 include 目标。对于 `GirTarget`，它会生成用于 `g-ir-scanner` 的 `--include-uninstalled` 参数。

8. **处理语言特定的链接器标志:**
    *   `_scan_langs` 函数获取特定编程语言的链接器标志（例如，通过 `environment.coredata.get_external_link_args` 获取）。

9. **处理 GIR 目标参数:**
    *   `_scan_gir_targets` 函数为 `g-ir-scanner` 生成与目标库或可执行文件相关的参数，例如 `--program` 和 `--library`。它会根据目标类型（可执行文件、共享库、静态库）生成不同的参数，并处理库的路径和 RPATH 设置。

10. **获取 GIR 目标的语言和编译器信息:**
    *   `_get_girtargets_langs_compilers` 函数识别 GIR 目标所使用的编程语言及其对应的编译器。

11. **获取 GIR 目标的依赖:**
    *   `_get_gir_targets_deps` 函数获取 GIR 目标的所有链接依赖。

12. **获取 GIR 目标的 include 目录:**
    *   `_get_gir_targets_inc_dirs` 函数获取 GIR 目标的所有 include 目录。

13. **获取语言和编译器的标志:**
    *   `_get_langs_compilers_flags` 函数根据编程语言和编译器获取相应的编译标志和链接器标志，并处理代码清理工具 (sanitizer) 的相关标志。

14. **创建 GIR 文件列表:**
    *   `_make_gir_filelist` 函数创建一个文本文件，其中列出了生成 GIR 文件所需的所有源文件。

15. **创建 GIR 目标:**
    *   `_make_gir_target` 函数创建一个 `GirTarget` 对象，该对象代表生成 GIR 文件的自定义构建目标。它配置了 `g-ir-scanner` 的命令行参数、依赖项、安装路径等。

16. **创建 Typelib 目标:**
    *   `_make_typelib_target` 函数创建一个 `TypelibTarget` 对象，代表生成 Typelib 文件的自定义构建目标。它配置了 `g-ir-compiler` 的命令行参数、依赖项、安装路径等。

17. **收集 Typelib 的 include 目录并更新依赖:**
    *   `_gather_typelib_includes_and_update_depends` 函数递归地收集生成 Typelib 文件所需的 include 目录，并更新构建目标的依赖项列表，确保在生成 Typelib 之前，所有依赖的 GIR 文件都已生成。

18. **获取语言的外部参数:**
    *   `_get_external_args_for_langs` 函数获取特定编程语言的外部参数。

19. **过滤 `g-ir-scanner` 的编译和链接标志:**
    *   `_get_scanner_cflags` 和 `_get_scanner_ldflags` 函数过滤出 `g-ir-scanner` 可以接受的编译标志（如 `-I`, `-D`, `-U`）和链接器标志（如 `-L`, `-l`, `--extra-library`）。

20. **`generate_gir` 函数:**
    *   这是生成 GIR 文件和 Typelib 文件的核心函数。它接收命名空间、版本、源文件、依赖项等参数，并调用其他辅助函数来构建 `g-ir-scanner` 和 `g-ir-compiler` 的命令行，创建相应的自定义构建目标。

**与逆向方法的联系:**

虽然这段代码本身不是直接用于逆向的工具，但生成的 GIR 文件和 Typelib 文件在**动态分析和逆向工程**中非常有用：

*   **动态分析:** Frida 可以利用 GIR 文件来理解目标进程中使用的 GObject 库的结构和接口。这使得开发者可以使用 Frida 来 hook 这些库的函数，查看参数和返回值，从而进行动态分析。例如，如果一个 Android 应用程序使用了 GLib 库，可以使用 Frida 和 GLib 的 GIR 文件来 hook `g_main_loop_run` 函数，监控主循环的运行状态。
*   **逆向工程:** GIR 文件提供了库的函数签名、结构体定义、枚举类型等信息，这对于理解未知库的功能和接口非常有帮助。逆向工程师可以使用这些信息来辅助分析二进制代码，理解函数的功能和参数的含义。例如，在逆向一个使用 GTK 的应用程序时，GTK 的 GIR 文件可以帮助理解窗口、按钮等 UI 元素的属性和方法。

**涉及二进制底层、Linux、Android 内核及框架的知识:**

*   **二进制底层:**  虽然代码本身是用 Python 编写的，但它最终影响的是如何编译和链接二进制文件。生成的 GIR 文件描述了 C 语言编写的库，这些库最终会被编译成机器码。
*   **Linux:** GObject Introspection 是 Linux 环境下常用的技术，特别是对于 GNOME 桌面环境。代码中涉及到路径、环境变量等都是 Linux 系统相关的概念。
*   **Android 框架:** Android 系统中也使用了 GObject 和相关技术，例如在某些系统服务和组件中。虽然这段代码是 `frida-clr` 的一部分，主要针对 .NET 的集成，但其生成 GIR 文件的过程和原理在其他使用 GObject 的环境中是通用的。生成的 GIR 文件可以用于分析 Android 应用程序中使用的 Native 库。

**逻辑推理的示例:**

假设输入以下参数给 `generate_gir` 函数：

```python
gnome.generate_gir(
    api_library,  # 一个 SharedLibrary 类型的目标
    namespace='MyLib',
    nsversion='1.0',
    sources=['mylib.c'],
    include_directories=['include'],
)
```

**假设输入:**

*   `api_library`: 一个表示名为 `libmylib.so` 的共享库的 `build.SharedLibrary` 对象。
*   `namespace`: "MyLib"
*   `nsversion`: "1.0"
*   `sources`:  包含一个名为 "mylib.c" 的源文件。
*   `include_directories`: 包含一个名为 "include" 的 include 目录。

**逻辑推理:**

1. `_unwrap_gir_target` 函数会验证 `api_library` 是否是一个 `build.SharedLibrary` 对象。
2. `_get_gir_dep` 函数会获取 `gobject-introspection` 的依赖和工具。
3. `_make_gir_filelist` 函数会创建一个包含 `mylib.c` 路径的文件列表。
4. `_make_gir_target` 函数会构造 `g-ir-scanner` 的命令行，其中会包含：
    *   `--namespace=MyLib`
    *   `--nsversion=1.0`
    *   `--output MyLib-1.0.gir`
    *   `--filelist=<filelist_path>`
    *   `-Iinclude`
    *   可能还会包含与 `api_library` 相关的 `--library` 参数。
5. `_make_typelib_target` 函数会构造 `g-ir-compiler` 的命令行，将生成的 `MyLib-1.0.gir` 编译成 `MyLib-1.0.typelib`。

**预期输出:**

*   生成一个名为 `MyLib-1.0.gir` 的文件，其中包含了对 `libmylib.so` 中定义的接口的描述。
*   生成一个名为 `MyLib-1.0.typelib` 的文件，它是 `MyLib-1.0.gir` 的编译版本。

**用户或编程常见的使用错误:**

1. **未安装 `gobject-introspection`:** 如果系统中没有安装 `gobject-introspection` 软件包，`_get_gir_dep` 函数将会失败。
2. **`namespace` 或 `nsversion` 参数缺失或错误:** `generate_gir` 函数强制要求提供 `namespace` 和 `nsversion` 参数，如果缺失将会抛出异常。
3. **提供的 GIR 目标不是可执行文件或库文件:** `_unwrap_gir_target` 函数会检查目标类型，如果不是 `Executable`、`build.SharedLibrary` 或 `build.StaticLibrary`，将会抛出 `MesonException`。
4. **include 目录或源文件路径错误:** 如果 `sources` 或 `include_directories` 参数中提供的路径不正确，`g-ir-scanner` 在扫描代码时可能会找不到文件，导致生成 GIR 文件失败。
5. **依赖项缺失:** 如果要生成 GIR 的库依赖于其他库，但这些依赖没有正确声明或链接，`g-ir-scanner` 可能会报告错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户在项目的根目录下或者子目录下创建 `meson.build` 文件，用于描述项目的构建过程。
2. **用户调用 `gnome.generate_gir` 函数:** 在 `meson.build` 文件中，用户调用了 `gnome.generate_gir` 函数，并传入了相关的参数，例如：

    ```python
    mylib = shared_library('mylib', 'mylib.c',
        install: true,
        include_directories: include_directories('include'))

    gnome.generate_gir(mylib,
        namespace: 'MyLib',
        nsversion: '1.0',
        sources: 'mylib.c',
        include_directories: 'include',
        install_dir_gir: join_paths(get_option('datadir'), 'gir-1.0'),
        install_dir_typelib: join_paths(get_option('libdir'), 'girepository-1.0'))
    ```

3. **用户运行 `meson` 命令配置项目:** 用户在终端中进入项目根目录，运行 `meson setup builddir` 命令，Meson 会读取 `meson.build` 文件，并执行其中的指令。
4. **Meson 执行 `gnome.generate_gir` 函数:** 当 Meson 执行到 `gnome.generate_gir` 函数时，会调用 `frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/gnome.py` 文件中的 `generate_gir` 方法。
5. **代码执行并生成 GIR 和 Typelib 文件:** `generate_gir` 方法会调用其内部的辅助函数，最终生成用于构建 GIR 和 Typelib 文件的自定义目标。
6. **用户运行 `ninja` 或 `meson compile` 命令构建项目:** 用户在构建目录下运行 `ninja` 或 `meson compile` 命令，Ninja (或用户选择的其他后端) 会执行 Meson 生成的构建规则，包括调用 `g-ir-scanner` 和 `g-ir-compiler` 来生成 GIR 和 Typelib 文件。

**总结 `generate_gir` 函数的功能:**

`generate_gir` 函数是 `gnome` Meson 模块中用于生成 GObject Introspection (GIR) 文件和 Typelib 文件的核心功能。它接收一个或多个可执行文件或库作为目标，以及命名空间、版本、源文件、include 目录等信息，并使用 `g-ir-scanner` 和 `g-ir-compiler` 工具来生成描述 C 语言库接口的元数据文件。这些文件对于其他语言绑定和动态分析工具非常重要。该函数还负责处理依赖关系、设置正确的编译和链接标志，以及处理文件的安装。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/modules/gnome.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
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
```