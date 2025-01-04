Response:
The user wants to understand the functionality of the provided Python code snippet from the `frida` project. This file seems to be a Meson module for handling GNOME-related build tasks, specifically concerning GObject Introspection (GIR) and schema compilation.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The filename `gnome.py` and the function names like `generate_gir`, `compile_schemas`, and `yelp` strongly suggest that this module deals with GNOME-specific build processes. The presence of `g-ir-scanner` and `glib-compile-schemas` confirms this.

2. **Analyze Key Functions:** Go through each defined function and understand its purpose:
    * `_get_dependencies_flags`, `_get_dependencies_flags_raw`:  These are likely helper functions to collect compiler and linker flags from dependencies. The logic within them manipulates `-l` flags to `--extra-library`.
    * `_unwrap_gir_target`:  This function checks if a provided target is a valid type for GIR generation (executable or library).
    * `_devenv_prepend`, `postconf_hook`: These manage environment variables, potentially for setting up the build environment for introspection.
    * `_get_gir_dep`:  Fetches dependencies for GObject Introspection tools (`g-ir-scanner`, `g-ir-compiler`).
    * `_gir_has_option`: Checks if `g-ir-scanner` supports a given option.
    * `_scan_include`, `_scan_langs`, `_scan_gir_targets`: These seem to prepare arguments for `g-ir-scanner` based on included files, languages, and target libraries.
    * `_get_girtargets_langs_compilers`, `_get_gir_targets_deps`, `_get_gir_targets_inc_dirs`, `_get_langs_compilers_flags`: These are utility functions to extract information from the target libraries needed for GIR generation.
    * `_make_gir_filelist`: Creates a file listing the source files for introspection.
    * `_make_gir_target`, `_make_typelib_target`: These construct the Meson targets for generating the `.gir` file and the typelib (`.typelib`).
    * `_gather_typelib_includes_and_update_depends`:  Manages dependencies and include paths for typelib generation.
    * `_get_external_args_for_langs`, `_get_scanner_cflags`, `_get_scanner_ldflags`: Functions to filter and prepare compiler and linker flags specifically for the scanner.
    * `generate_gir`: This is the main function for generating GIR files and typelibs. It orchestrates the calls to `g-ir-scanner` and `g-ir-compiler`.
    * `compile_schemas`: Compiles GSettings schemas using `glib-compile-schemas`.
    * `yelp`: Handles the build process for Yelp documentation using `itstool`, `msgmerge`, and `msgfmt`.

3. **Relate to Reverse Engineering:**  Focus on how GIR files are used in reverse engineering:
    * Frida uses GIR to understand the structure and interfaces of libraries. This allows developers to interact with library functions and objects dynamically without needing manual declarations.
    * Example: Hooking a function in a GTK application would rely on Frida understanding the function signature from the GIR file.

4. **Identify Binary/Kernel/Framework Aspects:**
    * **Binary:** The module interacts with compiled libraries and executables (`.so`, `.a`). The linker flags manipulation is directly related to how these binaries are built and linked.
    * **Linux:** Many of the tools mentioned (`glib-compile-schemas`, `itstool`, `msgmerge`, `msgfmt`) are common Linux utilities. The paths used (`/usr/share`, `/usr/lib`) are standard Linux conventions.
    * **Android:**  While the code itself doesn't explicitly mention Android kernel details, the broader context of Frida as a dynamic instrumentation tool makes it highly relevant to Android reverse engineering. Frida can be used to hook into Android framework components. GIR files are used within Android too, though the specific paths and tools might differ slightly.

5. **Look for Logic and Assumptions:**
    * **Assumptions:** The code assumes the presence of GNOME development tools. It also makes assumptions about standard installation directories for GIR files and typelibs.
    * **Logic:**  The `generate_gir` function follows a clear sequence: gather dependencies, prepare scanner commands, execute the scanner, and then compile the typelib. The conditional logic around `--extra-library` shows an attempt to handle different versions or configurations of the introspection tools.

6. **Identify Potential User Errors:**
    * Incorrect paths for source files.
    * Missing dependencies (like `gobject-introspection`).
    * Providing the wrong types of targets to `generate_gir` (e.g., not executables or libraries).
    * Incorrectly specifying namespaces or versions.

7. **Trace User Operations:**  Think about how a developer using Frida would end up using this module:
    * They would be writing a `meson.build` file for a project that uses GNOME technologies.
    * They would call functions like `gnome.generate_gir` to create introspection data for their libraries.
    * Meson would then invoke the functions in this module during the build process.

8. **Synthesize and Structure the Response:** Organize the findings into logical sections as requested by the prompt: functionality, relationship to reverse engineering, binary/kernel/framework aspects, logic/assumptions, user errors, and user path.

9. **Focus on the Specific Snippet:** The initial prompt asks about *this specific code snippet*. While broader knowledge of Frida is helpful, the analysis should primarily focus on the provided code.

10. **Refine and Review:** Read through the generated response to ensure clarity, accuracy, and completeness. Make sure the examples are relevant and easy to understand. For the summary in Part 2,  reiterate the main purpose, which is generating GIR and typelib files, and mention the schema compilation and Yelp documentation functions.
好的，我们来分析一下这段 frida 的源代码文件 `frida/releng/meson/mesonbuild/modules/gnome.py` 的功能，特别是提供的代码片段的功能。

**代码片段功能归纳（第 2 部分）:**

这段代码主要包含了 `gnome.py` 模块中用于处理 GObject Introspection (GIR) 文件生成的逻辑。它定义了几个辅助方法和核心的 `generate_gir` 方法，用于扫描 C/C++ 代码，提取接口信息，并生成 `.gir` 文件和 `.typelib` 文件。

具体来说，这段代码片段的功能包括：

* **处理依赖项标志:** `_get_dependencies_flags` 和 `_get_dependencies_flags_raw` 函数用于获取构建目标依赖的编译和链接标志。 特别地，它会将以 `-l` 开头的链接标志转换为 `--extra-library=` 格式，这可能是为了兼容 `g-ir-scanner` 工具的参数格式。
* **验证 GIR 目标:** `_unwrap_gir_target` 函数确保传递给 GIR 生成的目标是可执行文件或库文件 (共享库或静态库)，并且在处理静态库时会检查 `gobject-introspection` 的版本是否满足最低要求。
* **管理环境变量:** `_devenv_prepend` 和 `postconf_hook` 函数用于在构建过程中设置和管理特定的环境变量，这对于 `g-ir-scanner` 和 `g-ir-compiler` 的正确运行至关重要。
* **获取 GIR 依赖:** `_get_gir_dep` 函数用于获取 `gobject-introspection` 依赖以及 `g-ir-scanner` 和 `g-ir-compiler` 这两个工具的路径。
* **检查 `g-ir-scanner` 的选项支持:** `_gir_has_option` 函数用于检查 `g-ir-scanner` 工具是否支持特定的选项。
* **处理包含目录:** `_scan_include` 函数处理需要包含的头文件目录，并为 `g-ir-scanner` 生成相应的命令行参数。
* **处理语言链接参数:** `_scan_langs` 函数提取特定编程语言的链接参数，并将其添加到 `g-ir-scanner` 的命令行中。
* **处理 GIR 目标:** `_scan_gir_targets` 函数处理作为输入的库文件或可执行文件，并为 `g-ir-scanner` 生成相应的命令行参数，例如 `-L` 和 `--library`。
* **提取语言和编译器信息:** `_get_girtargets_langs_compilers` 函数提取与 GIR 目标相关的编程语言和编译器信息。
* **提取依赖项:** `_get_gir_targets_deps` 函数获取 GIR 目标的所有链接依赖和外部依赖。
* **提取包含目录:** `_get_gir_targets_inc_dirs` 函数获取 GIR 目标的所有包含目录。
* **获取语言和编译器标志:** `_get_langs_compilers_flags` 函数根据编程语言和编译器信息获取相应的编译和链接标志。
* **生成 GIR 文件列表:** `_make_gir_filelist` 函数创建一个文件，其中列出了用于生成 GIR 文件的所有源文件。
* **创建 GIR 目标:** `_make_gir_target` 函数创建一个 Meson 自定义目标 (CustomTarget) 来执行 `g-ir-scanner` 命令，生成 `.gir` 文件。
* **创建 Typelib 目标:** `_make_typelib_target` 函数创建一个 Meson 自定义目标来执行 `g-ir-compiler` 命令，将 `.gir` 文件编译成 `.typelib` 文件。
* **收集 Typelib 包含目录并更新依赖:** `_gather_typelib_includes_and_update_depends` 函数收集生成 typelib 文件所需的包含目录，并更新依赖项列表。
* **获取语言的外部参数:** `_get_external_args_for_langs` 函数获取特定编程语言的外部参数。
* **过滤扫描器的 CFLAGS 和 LDFLAGS:** `_get_scanner_cflags` 和 `_get_scanner_ldflags` 函数过滤出 `g-ir-scanner` 可以接受的 C 预处理器标志和链接器标志。
* **`generate_gir` 函数:** 这是该代码片段的核心函数，用于生成 GIR 文件和 typelib 文件。它接收一系列参数，包括目标库、命名空间、版本、源文件等，并使用 `g-ir-scanner` 和 `g-ir-compiler` 工具链生成最终的文件。

**与逆向方法的关系及举例说明:**

GIR 文件在逆向工程中扮演着重要的角色，尤其是在使用 Frida 进行动态分析时。

* **动态理解库的接口:** GIR 文件描述了共享库的 API，包括函数、结构体、枚举、信号等。Frida 可以解析 GIR 文件，从而在运行时理解目标库的接口，而无需事先知道所有细节。
* **动态调用库函数:** 通过解析 GIR 文件，Frida 可以构造对目标库中函数的调用，即使这些函数没有在当前进程中明确声明。这使得逆向工程师能够与目标程序进行更深入的交互。
* **Hook 函数和信号:**  GIR 文件提供了函数和信号的签名信息，Frida 可以利用这些信息来精确地 hook 函数调用或者监听信号的触发。

**举例说明:**

假设你想逆向一个使用了 GTK 库的应用程序。GTK 库提供了大量的函数用于创建图形用户界面。通过 `gnome.generate_gir`，可以为 GTK 库生成 `Gtk-3.0.gir` 文件。

在你的 Frida 脚本中，你可以使用 `Module.load()` 加载目标进程中的 GTK 库，然后使用 `GObject.Object.wrap()` 和 GIR 信息来操作 GTK 对象，例如：

```javascript
// 假设目标进程加载了 libgtk-3.so.0
const gtkModule = Process.getModuleByName('libgtk-3.so.0');

// 从 GIR 文件中获取 Gtk.Window 的信息
const GtkWindow = GObject.typeByName('GtkWindow');

// 假设你想创建一个新的 Gtk.Window 实例
const window = GtkWindow.$new();

// 从 GIR 文件中获取 Gtk.Window 的 show_all 方法信息
// 并调用该方法显示窗口
window.show_all();
```

在这个例子中，Frida 使用了 GTK 的 GIR 文件来了解 `GtkWindow` 类的结构和方法，从而能够动态地创建和操作 GTK 窗口对象。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:**
    * **链接器标志 (LDFLAGS):** 代码中处理链接器标志 (`-l`, `-L`)，这些标志直接影响二进制文件的链接过程，指定要链接的库以及库的搜索路径。`g-ir-scanner` 需要知道这些信息才能正确地找到目标库的符号。
    * **动态链接库 (.so):** `generate_gir` 的目标通常是共享库，理解动态链接的工作原理对于理解 GIR 的作用至关重要。GIR 描述了这些共享库的接口，使得在运行时可以动态地加载和使用它们。
* **Linux:**
    * **环境变量:** 代码中使用了环境变量 (`GI_TYPELIB_PATH`, `GSETTINGS_SCHEMA_DIR`)，这些是 Linux 系统中常见的配置机制。`g-ir-scanner` 和 `glib-compile-schemas` 等工具依赖于这些环境变量来定位文件和库。
    * **标准路径:** 代码中使用了 Linux 下的标准数据目录 (`/usr/share`) 和库目录 (`/usr/lib`)，用于指定 GIR 文件和 typelib 文件的安装路径。
    * **编译工具链:** 代码中调用了 `g-ir-scanner` 和 `g-ir-compiler`，这些是 GNOME 开发环境中的标准工具。
* **Android 内核及框架:**
    * 虽然这段代码没有直接涉及 Android 内核，但 Frida 作为动态分析工具，经常被用于 Android 平台的逆向工程。Android 框架也使用了类似 GObject Introspection 的机制 (例如，通过 AIDL 定义接口)。理解 GIR 的工作原理可以帮助理解 Android 框架的接口定义和动态调用机制。
    * 在 Android 上，GIR 类似的功能可能由其他工具或机制实现，但其核心思想是提供一种描述接口的方式，以便动态地进行交互。

**逻辑推理及假设输入与输出:**

**假设输入:**

* `girtargets`: 一个包含编译好的 GTK 共享库目标 (`libgtk-3.so`) 的列表。
* `namespace`: 字符串 "Gtk"。
* `nsversion`: 字符串 "3.0"。
* `sources`:  一个包含 GTK 库的 C 头文件 (`gtk.h`, 等) 的列表。

**逻辑推理:**

`generate_gir` 函数会执行以下步骤：

1. 调用 `g-ir-scanner` 工具。
2. 将 `girtargets` 中的库路径作为 `--library` 参数传递给 `g-ir-scanner`。
3. 将 `namespace` 和 `nsversion` 作为 `--namespace` 和 `--nsversion` 参数传递。
4. 将 `sources` 中的头文件路径作为 `-I` 参数传递。
5. `g-ir-scanner` 会解析 `libgtk-3.so` 中的符号信息，并根据提供的头文件生成 `Gtk-3.0.gir` 文件。
6. 调用 `g-ir-compiler` 工具。
7. 将生成的 `Gtk-3.0.gir` 文件作为输入传递给 `g-ir-compiler`。
8. `g-ir-compiler` 将 `Gtk-3.0.gir` 编译成二进制的 `Gtk-3.0.typelib` 文件。

**假设输出:**

* 在构建目录下生成 `Gtk-3.0.gir` 文件，其中包含了 GTK 库的接口描述。
* 在构建目录下生成 `Gtk-3.0.typelib` 文件，这是 `Gtk-3.0.gir` 的二进制表示。

**涉及用户或编程常见的使用错误及举例说明:**

* **缺少依赖:** 用户可能没有安装 `gobject-introspection` 软件包，导致 `state.dependency('gobject-introspection-1.0')` 失败。
    * **错误信息示例:**  Meson 会报告找不到 `gobject-introspection-1.0` 依赖。
* **目标类型错误:** 用户可能将一个普通的源文件而不是编译好的共享库或可执行文件传递给 `generate_gir`。
    * **错误信息示例:** `Gir target must be an executable or library but is ...`
* **命名空间或版本不匹配:** 用户提供的 `namespace` 或 `nsversion` 与目标库的实际情况不符。
    * **后果:** 生成的 GIR 文件可能不完整或不正确，导致 Frida 无法正确解析库的接口。
* **包含目录不正确:** 用户没有提供正确的头文件包含目录，导致 `g-ir-scanner` 无法找到头文件中的声明。
    * **后果:** 生成的 GIR 文件可能缺少类型信息或函数签名。
* **`link_with` 使用错误:**  用户可能链接了错误的库，或者库的版本不兼容，导致 `g-ir-scanner` 无法正确加载符号。

**用户操作是如何一步步到达这里的，作为调试线索:**

1. **编写 `meson.build` 文件:** 用户在他们的项目根目录下创建一个 `meson.build` 文件，用于描述项目的构建过程。
2. **使用 `gnome.generate_gir` 函数:** 在 `meson.build` 文件中，用户调用 `gnome.generate_gir` 函数来生成某个库的 GIR 文件。例如：
   ```python
   gnome = import('gnome')
   gtk = shared_library('gtk', 'gtk.c')
   gnome.generate_gir(gtk,
                      namespace: 'Gtk',
                      nsversion: '3.0',
                      sources: 'gtk.h')
   ```
3. **运行 `meson` 命令:** 用户在项目根目录下运行 `meson build` 命令来配置构建环境。Meson 会解析 `meson.build` 文件，并执行其中的指令。
4. **执行 `gnome.generate_gir`:** 当 Meson 执行到 `gnome.generate_gir` 函数时，它会调用 `frida/releng/meson/mesonbuild/modules/gnome.py` 文件中的 `generate_gir` 方法。
5. **执行 `g-ir-scanner` 和 `g-ir-compiler`:** `generate_gir` 方法会进一步调用系统中的 `g-ir-scanner` 和 `g-ir-compiler` 工具，根据提供的参数生成 GIR 和 typelib 文件。

如果在执行 `meson build` 的过程中出现与 GIR 生成相关的错误，那么调试的起点就是检查 `meson.build` 文件中 `gnome.generate_gir` 函数的参数是否正确，然后逐步检查 `frida/releng/meson/mesonbuild/modules/gnome.py` 中的逻辑，查看哪个环节出了问题，例如依赖是否满足、目标类型是否正确、命令行参数是否正确等等。

希望这个详细的分析对您有所帮助！

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/modules/gnome.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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