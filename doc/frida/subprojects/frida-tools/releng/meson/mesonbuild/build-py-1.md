Response:
Let's break down the thought process for analyzing this Python code snippet.

1. **Understanding the Goal:** The request asks for the functionality of the provided Python code, its relation to reverse engineering, its use of low-level/kernel concepts, any logical inferences, potential user errors, and how a user might reach this code. It also specifies that this is part 2 of a 5-part series and to summarize the functionality.

2. **Initial Scan and Keyword Spotting:**  I first quickly scan the code looking for keywords and patterns that hint at its purpose. I see things like:

    * `elf.objects`:  Suggests dealing with compiled object files, common in linking and executable creation.
    * `structured_sources`, `sources`, `generated`: Indicate handling different kinds of input files for building.
    * `external_deps`, `dependencies`:  Points to managing external libraries and their requirements.
    * `include_dirs`, `link_targets`, `link_whole_targets`, `link_args`, `link_depends`:  Clearly related to the linking process.
    * `pic`, `pie`:  Relate to position-independent code and executables, important for security and shared libraries.
    * `install`, `install_dir`, `install_mode`, `install_rpath`:  Concerned with the installation process.
    * `process_sourcelist`, `process_objectlist`, `process_compilers`, `process_kwargs`, `link`:  These are method names suggesting distinct stages in processing build information.
    * Mentions of `vala`, `rust`, `cython`: Indicate support for different programming languages.

3. **Identifying the Core Functionality:** Based on the keywords, the central theme is the *definition and configuration of a build target*. This code seems responsible for:

    * **Collecting input:** Source files, object files, dependencies, compiler flags, linker flags, include paths, etc.
    * **Processing input:**  Classifying sources, handling different dependency types, validating inputs.
    * **Configuring the build:** Setting flags for PIC/PIE, specifying linking behavior, defining installation details.
    * **Managing dependencies:** Tracking both internal and external dependencies and their associated settings.

4. **Relating to Reverse Engineering:**  I think about how this functionality connects to reverse engineering. Key connections emerge:

    * **Object Files and Linking:**  Reverse engineers often work with compiled binaries and need to understand how they are linked. This code manages the linking process, defining the inputs (object files, libraries) and the process itself.
    * **Dependencies:** Understanding a binary's dependencies is crucial for reverse engineering. This code explicitly manages dependencies, including external libraries. Knowing what libraries are linked can reveal significant functionality.
    * **PIC/PIE:** These concepts are critical for understanding memory layout and security features when reverse engineering. The code configures these attributes.
    * **Debugging Information (`debug_filename`):** Debug symbols are essential for effective reverse engineering with debuggers. This code manages the generation of debugging information.

5. **Connecting to Low-Level/Kernel Concepts:** Now I consider the low-level aspects:

    * **Object Files:**  These are the direct output of compilers and the input to linkers – a fundamental binary concept.
    * **Linking:** This is a core operating system concept, bringing together compiled units.
    * **Libraries (Static and Shared):**  Essential components of operating systems and applications, managed by the linking process.
    * **`rpath`:** This directly manipulates the runtime linker's search paths, a low-level OS mechanism.
    * **PIC/PIE:** These relate to memory management and security features at the kernel level.
    * **Installation:**  Putting files in system directories is a direct interaction with the operating system's file system structure.

6. **Looking for Logical Inferences:**  I examine parts of the code where decisions or transformations occur:

    * **Compiler Selection (`process_compilers`):** The code attempts to automatically determine the necessary compilers based on the source files. This involves some implicit logic.
    * **Dependency Resolution (`add_deps`):**  The code handles different types of dependencies and recursively adds their requirements. This is a logical process of building a dependency graph.
    * **PIC/PIE Determination (`_extract_pic_pie`):**  The code prioritizes command-line arguments, then build options, and finally defaults. This is a clear logical flow.

7. **Considering User Errors:** I think about how a user interacting with this code (indirectly through a build system like Meson) could make mistakes:

    * **Incorrect File Paths:** Providing wrong paths for source files, object files, or extra files.
    * **Type Mismatches:** Providing arguments of the wrong type (e.g., a string where a list is expected).
    * **Missing Dependencies:** Failing to specify necessary dependencies.
    * **Conflicting Options:** Providing incompatible build options.
    * **Using Target Dependencies Incorrectly:** Trying to use a build target directly as a dependency instead of using `link_with`.

8. **Tracing User Steps:** How does a user's action lead to this code being executed?

    * **Meson Build Definition:** The user writes a `meson.build` file that describes the project structure, including targets and their properties.
    * **Meson Configuration:** The user runs `meson setup` to configure the build, parsing the `meson.build` file.
    * **Target Creation:** Meson interprets the `meson.build` and creates internal representations of build targets, likely using classes like the one in the snippet. This code is part of that target creation and configuration process.

9. **Structuring the Explanation:**  Now I organize my findings into the requested sections: functionality, reverse engineering relevance, low-level concepts, logical inferences, user errors, and user steps. I use specific examples from the code to illustrate each point.

10. **Summarizing the Functionality (Part 2):** Finally, I condense the overall purpose of this code snippet into a concise summary, focusing on its role in defining and configuring build targets within the Frida build system.

This iterative process of scanning, identifying key components, connecting them to the broader context, and then organizing the information allows for a comprehensive understanding of the code's function and its significance.
这是 frida 动态 instrumentation 工具中负责构建过程的 Python 代码片段，位于 Meson 构建系统的相关目录中。这个代码片段定义了一个名为 `BuildTarget` 的类，它代表了一个需要被构建的目标（例如，一个库或一个可执行文件）。

**它的主要功能可以归纳为：**

1. **定义构建目标的基础属性：**
   - 存储构建目标的基本信息，如名称 (`name`)、输出文件名 (`filename`)、源代码文件 (`sources`)、生成的源代码文件 (`generated`)、预编译头 (`pch`)、外部依赖 (`external_deps`)、内部链接目标 (`link_targets`) 和需要完整链接的目标 (`link_whole_targets`) 等。
   - 处理各种类型的源文件和对象文件，包括直接提供的源文件、由其他目标生成的文件以及预编译的对象文件。

2. **处理和管理依赖关系：**
   - 维护构建目标的内部和外部依赖列表。
   - 递归地处理依赖关系，确保所有必要的库和头文件都被包含。
   - 区分需要完整链接的依赖（`link_whole_targets`），这对于静态库尤其重要，以确保所有依赖的代码都被包含进来。

3. **配置编译和链接选项：**
   - 存储和管理特定语言的编译参数 (`extra_args`) 和链接参数 (`link_args`).
   - 处理与位置无关代码 (`pic`) 和位置无关可执行文件 (`pie`) 相关的选项。
   - 管理链接依赖的文件 (`link_depends`)。
   - 处理包含目录 (`include_dirs`)，允许指定头文件的搜索路径。

4. **处理安装信息：**
   - 存储构建目标的安装目录 (`install_dir`)、安装模式 (`install_mode`) 和安装标签 (`install_tag`)。
   - 管理运行时库搜索路径 (`rpath`) 的相关设置，包括构建时 (`build_rpath`) 和安装时 (`install_rpath`).

5. **进行输入验证和错误检查：**
   - 检查未知关键字参数，帮助用户发现拼写错误或使用了不支持的选项。
   - 验证源文件是否存在。
   - 检查链接依赖的类型是否正确。

6. **支持多语言构建：**
   - 能够处理多种编程语言的源文件，并根据源文件类型自动选择合适的编译器。
   - 显式处理了 C、C++、Vala、Rust 和 Cython 等语言的特定配置。

**与逆向的方法的关系及举例说明：**

* **处理对象文件 (`elf.objects`)：** 在逆向工程中，经常需要分析已编译的目标文件（`.o` 或 `.obj`），了解其内部结构和函数。这个代码片段处理这些对象文件，说明了 Frida 的构建过程需要将这些编译单元链接在一起。例如，如果 Frida 需要链接一个预先编译好的第三方库，这个库的 `.o` 文件就会被添加到 `self.objects` 中。
* **管理依赖关系 (`link_targets`, `link_whole_targets`)：**  逆向分析时，了解目标程序依赖的库非常重要。Frida 作为一个动态插桩工具，本身也依赖于许多库。这个代码片段管理了这些依赖，例如，Frida 可能依赖于 `glib` 或 `libstdc++` 等库，这些库会被添加到 `link_targets` 中。完整链接的目标 (`link_whole_targets`) 对于静态链接的库至关重要，逆向工程师可能需要关注这些被完整包含进来的代码。
* **处理链接参数 (`link_args`)：** 链接参数会直接影响最终生成的可执行文件或库的行为。逆向工程师可能需要分析链接参数，例如 `-z now` 可以提高安全性，`-fPIC` 用于生成位置无关代码。Frida 的构建过程可能需要传递特定的链接参数来满足其功能需求。
* **处理运行时库搜索路径 (`rpath`)：**  `rpath` 指定了程序运行时查找共享库的路径。逆向工程师可以通过分析 `rpath` 了解程序运行时依赖的库的位置。Frida 可以通过 `build_rpath` 或 `install_rpath` 来配置其运行时库的查找路径。

**涉及到的二进制底层，Linux，Android 内核及框架的知识及举例说明：**

* **二进制底层：**
    * **对象文件 (`elf.objects`)：** 对象文件是编译器输出的二进制文件，包含了机器码、符号表等信息。理解对象文件的结构是理解程序构建过程的基础。
    * **链接 (linking)：**  链接是将多个对象文件和库文件合并成一个可执行文件或共享库的过程。这个代码片段的核心功能之一就是管理链接过程。
    * **位置无关代码 (`pic`) 和位置无关可执行文件 (`pie`)：**  这些是安全性和共享库的关键概念。PIC 允许代码加载到内存的任意位置，这对于共享库至关重要。PIE 提高了可执行文件的安全性，使其在内存中的加载地址随机化，从而降低某些类型的攻击风险。在 Linux 和 Android 上，这些概念尤其重要。
* **Linux：**
    * **共享库 (shared libraries)：**  Linux 系统广泛使用共享库来节省内存和磁盘空间。`link_targets` 和 `rpath` 的处理直接关系到 Linux 中共享库的链接和加载。
    * **预编译头 (`pch`)：**  这是一种优化编译时间的技术，在大型 Linux 项目中很常见。
* **Android 内核及框架：**
    * **Android 上的 PIE：** Android 系统强制要求可执行文件使用 PIE 来提高安全性。这个代码片段中检查了目标平台是否为 Android，并据此设置 `pie` 标志。
    * **动态链接器：**  `rpath` 的设置影响 Android 系统中动态链接器如何找到程序依赖的共享库。Frida 在 Android 上的运行需要正确配置其依赖的库。

**逻辑推理的假设输入与输出举例：**

假设输入 `kwargs` 中包含以下信息：

```python
kwargs = {
    'name': 'frida-agent',
    'sources': ['agent.c', 'core.c'],
    'link_with': ['libuv', 'libsqlite3'],
    'include_directories': ['include'],
    'dependencies': ['glib-2.0'],
    'pic': True,
}
```

**逻辑推理过程：**

1. **`self.process_sourcelist(sources)`:**  会识别 `agent.c` 和 `core.c` 是源代码文件，并将它们添加到 `self.sources` 列表中。
2. **`self.link(link_with)`:** 会将 `libuv` 和 `libsqlite3` (假设它们是已定义的构建目标) 添加到 `self.link_targets` 列表中。
3. **`self.add_include_dirs(include_directories)`:** 会将 `'include'` 添加到 `self.include_dirs` 列表中。
4. **`self.add_deps(dependencies)`:** 会查找名为 `glib-2.0` 的依赖项（可能是外部依赖或内部依赖声明），并将其添加到 `self.external_deps` 或其他相关列表中。如果 `glib-2.0` 声明了任何包含目录，它们也会被添加到 `self.include_dirs` 中。
5. **`self._extract_pic_pie(kwargs, 'pic', 'b_staticpic')`:** 由于 `kwargs` 中显式指定了 `pic=True`，`self.pic` 将被设置为 `True`.

**假设输出 (部分)：**

```python
self.name = 'frida-agent'
self.sources = [<File object for agent.c>, <File object for core.c>]
self.link_targets = [<BuildTarget object for libuv>, <BuildTarget object for libsqlite3>]
self.include_dirs = [<IncludeDirs object for 'include'>, <IncludeDirs object from glib-2.0>]
self.external_deps = [<Dependency object for glib-2.0>]
self.pic = True
```

**用户或编程常见的使用错误举例：**

1. **错误的源文件路径：** 用户在 `sources` 中提供了不存在的源文件路径，例如 `kwargs = {'sources': ['nonexistent.c']}`，会导致程序抛出异常或构建失败。
2. **链接类型错误：** 用户错误地将一个可执行目标放入 `link_with` 中，例如 `kwargs = {'link_with': ['another_executable']}`，这在大多数情况下是无意义的，因为可执行文件通常不被链接为库。代码中的 `if not isinstance(t, (Target, CustomTargetIndex)):` 部分可以捕获某些类型的错误。
3. **遗漏依赖项：** 用户没有在 `dependencies` 中声明所有必要的库，导致链接器报错，提示找不到某些符号。
4. **`install_rpath` 设置错误：**  用户可能设置了错误的 `install_rpath`，导致程序在运行时找不到共享库。例如，指定了一个不存在的路径。
5. **在静态库上错误使用 `gui_app` 或 `win_subsystem`：** 这些参数只对可执行文件有效，如果在静态库上使用会导致 `InvalidArguments` 异常。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 `meson.build` 文件：** 用户首先需要编写一个 `meson.build` 文件来描述如何构建 Frida 的相关组件。在这个文件中，会使用 `library()` 或 `executable()` 等函数来定义构建目标，并使用关键字参数（如 `sources`, `dependencies`, `link_with` 等）来指定目标的属性。

   ```python
   # meson.build
   project('frida-core', 'c')

   frida_agent = library(
       'frida-agent',
       sources = ['agent.c', 'core.c'],
       dependencies = dependency('glib-2.0'),
       link_with = libuv_dep,
       include_directories = include_directories('include'),
       pic = true,
   )
   ```

2. **运行 `meson setup builddir`：** 用户在命令行中运行 `meson setup builddir` 命令，Meson 会读取 `meson.build` 文件，解析项目结构和构建目标。

3. **Meson 解析 `meson.build` 并创建 `BuildTarget` 对象：** 当 Meson 解析到 `library('frida-agent', ...)` 这行代码时，它会创建一个 `BuildTarget` (或者其子类，如 `StaticLibrary`) 的实例，并将 `meson.build` 中提供的关键字参数传递给该类的构造函数。这个代码片段就是 `BuildTarget` 类的 `__init__` 方法，负责接收并处理这些参数。

4. **处理关键字参数：** `self.process_kwargs(kwargs)` 方法会被调用，它会进一步处理传递进来的关键字参数，包括解析源文件列表、处理依赖关系、设置链接选项等。

5. **后续的构建步骤：** 在 `BuildTarget` 对象创建和初始化完成后，Meson 会根据这些信息生成实际的构建命令（例如，调用编译器和链接器），最终完成构建过程。

作为调试线索，如果构建过程中出现问题，例如编译错误或链接错误，开发者可以检查 `meson.build` 文件中相关目标的定义，查看传递给 `BuildTarget` 构造函数的参数是否正确。例如，检查源文件路径是否正确，依赖项是否已正确声明，链接库是否已找到等。此外，Meson 的日志输出也会提供关于构建过程的详细信息，可以帮助定位问题。

**归纳一下它的功能：**

这个代码片段定义了 Frida 构建系统中 `BuildTarget` 类的初始化逻辑，负责接收和处理构建目标（例如库或可执行文件）的各种属性，包括源文件、依赖关系、编译和链接选项以及安装信息。它为后续的构建过程奠定了基础，确保 Meson 能够理解并正确构建项目中的每个目标。它涉及到对多种编程语言、二进制文件结构、操作系统概念（如共享库和链接）的理解和管理。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共5部分，请归纳一下它的功能
```

### 源代码
```python
elf.objects: T.List[ObjectTypes] = []
        self.structured_sources = structured_sources
        self.external_deps: T.List[dependencies.Dependency] = []
        self.include_dirs: T.List['IncludeDirs'] = []
        self.link_language = kwargs.get('link_language')
        self.link_targets: T.List[LibTypes] = []
        self.link_whole_targets: T.List[T.Union[StaticLibrary, CustomTarget, CustomTargetIndex]] = []
        self.depend_files: T.List[File] = []
        self.link_depends = []
        self.added_deps = set()
        self.name_prefix_set = False
        self.name_suffix_set = False
        self.filename = 'no_name'
        # The debugging information file this target will generate
        self.debug_filename = None
        # The list of all files outputted by this target. Useful in cases such
        # as Vala which generates .vapi and .h besides the compiled output.
        self.outputs = [self.filename]
        self.pch: T.Dict[str, T.List[str]] = {}
        self.extra_args: T.DefaultDict[str, T.List[str]] = kwargs.get('language_args', defaultdict(list))
        self.sources: T.List[File] = []
        self.generated: T.List['GeneratedTypes'] = []
        self.extra_files: T.List[File] = []
        self.d_features: DFeatures = {
            'debug': kwargs.get('d_debug', []),
            'import_dirs': kwargs.get('d_import_dirs', []),
            'versions': kwargs.get('d_module_versions', []),
            'unittest': kwargs.get('d_unittest', False),
        }
        self.pic = False
        self.pie = False
        # Track build_rpath entries so we can remove them at install time
        self.rpath_dirs_to_remove: T.Set[bytes] = set()
        self.process_sourcelist(sources)
        # Objects can be:
        # 1. Preexisting objects provided by the user with the `objects:` kwarg
        # 2. Compiled objects created by and extracted from another target
        self.process_objectlist(objects)
        self.process_kwargs(kwargs)
        self.missing_languages = self.process_compilers()

        # self.link_targets and self.link_whole_targets contains libraries from
        # dependencies (see add_deps()). They have not been processed yet because
        # we have to call process_compilers() first and we need to process libraries
        # from link_with and link_whole first.
        # See https://github.com/mesonbuild/meson/pull/11957#issuecomment-1629243208.
        link_targets = extract_as_list(kwargs, 'link_with') + self.link_targets
        link_whole_targets = extract_as_list(kwargs, 'link_whole') + self.link_whole_targets
        self.link_targets.clear()
        self.link_whole_targets.clear()
        self.link(link_targets)
        self.link_whole(link_whole_targets)

        if not any([self.sources, self.generated, self.objects, self.link_whole_targets, self.structured_sources,
                    kwargs.pop('_allow_no_sources', False)]):
            mlog.warning(f'Build target {name} has no sources. '
                         'This was never supposed to be allowed but did because of a bug, '
                         'support will be removed in a future release of Meson')
        self.check_unknown_kwargs(kwargs)
        self.validate_install()
        self.check_module_linking()

    def post_init(self) -> None:
        ''' Initialisations and checks requiring the final list of compilers to be known
        '''
        self.validate_sources()
        if self.structured_sources and any([self.sources, self.generated]):
            raise MesonException('cannot mix structured sources and unstructured sources')
        if self.structured_sources and 'rust' not in self.compilers:
            raise MesonException('structured sources are only supported in Rust targets')
        if self.uses_rust():
            # relocation-model=pic is rustc's default and Meson does not
            # currently have a way to disable PIC.
            self.pic = True
        if 'vala' in self.compilers and self.is_linkable_target():
            self.outputs += [self.vala_header, self.vala_vapi]
            self.install_tag += ['devel', 'devel']
            if self.vala_gir:
                self.outputs.append(self.vala_gir)
                self.install_tag.append('devel')

    def __repr__(self):
        repr_str = "<{0} {1}: {2}>"
        return repr_str.format(self.__class__.__name__, self.get_id(), self.filename)

    def __str__(self):
        return f"{self.name}"

    @property
    def is_unity(self) -> bool:
        unity_opt = self.get_option(OptionKey('unity'))
        return unity_opt == 'on' or (unity_opt == 'subprojects' and self.subproject != '')

    def validate_install(self):
        if self.for_machine is MachineChoice.BUILD and self.install:
            if self.environment.is_cross_build():
                raise InvalidArguments('Tried to install a target for the build machine in a cross build.')
            else:
                mlog.warning('Installing target build for the build machine. This will fail in a cross build.')

    def check_unknown_kwargs(self, kwargs):
        # Override this method in derived classes that have more
        # keywords.
        self.check_unknown_kwargs_int(kwargs, self.known_kwargs)

    def check_unknown_kwargs_int(self, kwargs, known_kwargs):
        unknowns = []
        for k in kwargs:
            if k == 'language_args':
                continue
            if k not in known_kwargs:
                unknowns.append(k)
        if len(unknowns) > 0:
            mlog.warning('Unknown keyword argument(s) in target {}: {}.'.format(self.name, ', '.join(unknowns)))

    def process_objectlist(self, objects):
        assert isinstance(objects, list)
        deprecated_non_objects = []
        for s in objects:
            if isinstance(s, (str, File, ExtractedObjects)):
                self.objects.append(s)
                if not isinstance(s, ExtractedObjects) and not is_object(s):
                    deprecated_non_objects.append(s)
            elif isinstance(s, (CustomTarget, CustomTargetIndex, GeneratedList)):
                non_objects = [o for o in s.get_outputs() if not is_object(o)]
                if non_objects:
                    raise InvalidArguments(f'Generated file {non_objects[0]} in the \'objects\' kwarg is not an object.')
                self.generated.append(s)
            else:
                raise InvalidArguments(f'Bad object of type {type(s).__name__!r} in target {self.name!r}.')
        if deprecated_non_objects:
            FeatureDeprecated.single_use(f'Source file {deprecated_non_objects[0]} in the \'objects\' kwarg is not an object.',
                                         '1.3.0', self.subproject)

    def process_sourcelist(self, sources: T.List['SourceOutputs']) -> None:
        """Split sources into generated and static sources.

        Sources can be:
        1. Preexisting source files in the source tree (static)
        2. Preexisting sources generated by configure_file in the build tree.
           (static as they are only regenerated if meson itself is regenerated)
        3. Sources files generated by another target or a Generator (generated)
        """
        added_sources: T.Set[File] = set() # If the same source is defined multiple times, use it only once.
        for s in sources:
            if isinstance(s, File):
                if s not in added_sources:
                    self.sources.append(s)
                    added_sources.add(s)
            elif isinstance(s, (CustomTarget, CustomTargetIndex, GeneratedList)):
                self.generated.append(s)

    @staticmethod
    def can_compile_remove_sources(compiler: 'Compiler', sources: T.List['FileOrString']) -> bool:
        removed = False
        for s in sources[:]:
            if compiler.can_compile(s):
                sources.remove(s)
                removed = True
        return removed

    def process_compilers_late(self) -> None:
        """Processes additional compilers after kwargs have been evaluated.

        This can add extra compilers that might be required by keyword
        arguments, such as link_with or dependencies. It will also try to guess
        which compiler to use if one hasn't been selected already.
        """
        for lang in self.missing_languages:
            self.compilers[lang] = self.all_compilers[lang]

        # did user override clink_langs for this target?
        link_langs = [self.link_language] if self.link_language else clink_langs

        # If this library is linked against another library we need to consider
        # the languages of those libraries as well.
        if self.link_targets or self.link_whole_targets:
            for t in itertools.chain(self.link_targets, self.link_whole_targets):
                if isinstance(t, (CustomTarget, CustomTargetIndex)):
                    continue # We can't know anything about these.
                for name, compiler in t.compilers.items():
                    if name in link_langs and name not in self.compilers:
                        self.compilers[name] = compiler

        if not self.compilers:
            # No source files or parent targets, target consists of only object
            # files of unknown origin. Just add the first clink compiler
            # that we have and hope that it can link these objects
            for lang in link_langs:
                if lang in self.all_compilers:
                    self.compilers[lang] = self.all_compilers[lang]
                    break

        # Now that we have the final list of compilers we can sort it according
        # to clink_langs and do sanity checks.
        self.compilers = OrderedDict(sorted(self.compilers.items(),
                                            key=lambda t: sort_clink(t[0])))
        self.post_init()

    def process_compilers(self) -> T.List[str]:
        '''
        Populate self.compilers, which is the list of compilers that this
        target will use for compiling all its sources.
        We also add compilers that were used by extracted objects to simplify
        dynamic linker determination.
        Returns a list of missing languages that we can add implicitly, such as
        C/C++ compiler for cython.
        '''
        missing_languages: T.List[str] = []
        if not any([self.sources, self.generated, self.objects, self.structured_sources]):
            return missing_languages
        # Preexisting sources
        sources: T.List['FileOrString'] = list(self.sources)
        generated = self.generated.copy()

        if self.structured_sources:
            for v in self.structured_sources.sources.values():
                for src in v:
                    if isinstance(src, (str, File)):
                        sources.append(src)
                    else:
                        generated.append(src)

        # All generated sources
        for gensrc in generated:
            for s in gensrc.get_outputs():
                # Generated objects can't be compiled, so don't use them for
                # compiler detection. If our target only has generated objects,
                # we will fall back to using the first c-like compiler we find,
                # which is what we need.
                if not is_object(s):
                    sources.append(s)
        for d in self.external_deps:
            for s in d.sources:
                if isinstance(s, (str, File)):
                    sources.append(s)

        # Sources that were used to create our extracted objects
        for o in self.objects:
            if not isinstance(o, ExtractedObjects):
                continue
            compsrcs = o.classify_all_sources(o.srclist, [])
            for comp in compsrcs:
                # Don't add Vala sources since that will pull in the Vala
                # compiler even though we will never use it since we are
                # dealing with compiled C code.
                if comp.language == 'vala':
                    continue
                if comp.language not in self.compilers:
                    self.compilers[comp.language] = comp
        if sources:
            # For each source, try to add one compiler that can compile it.
            #
            # If it has a suffix that belongs to a known language, we must have
            # a compiler for that language.
            #
            # Otherwise, it's ok if no compilers can compile it, because users
            # are expected to be able to add arbitrary non-source files to the
            # sources list
            for s in sources:
                for lang, compiler in self.all_compilers.items():
                    if compiler.can_compile(s):
                        if lang not in self.compilers:
                            self.compilers[lang] = compiler
                        break
                else:
                    if is_known_suffix(s):
                        path = pathlib.Path(str(s)).as_posix()
                        m = f'No {self.for_machine.get_lower_case_name()} machine compiler for {path!r}'
                        raise MesonException(m)

        # If all our sources are Vala, our target also needs the C compiler but
        # it won't get added above.
        if 'vala' in self.compilers and 'c' not in self.compilers:
            self.compilers['c'] = self.all_compilers['c']
        if 'cython' in self.compilers:
            key = OptionKey('language', machine=self.for_machine, lang='cython')
            value = self.get_option(key)

            try:
                self.compilers[value] = self.all_compilers[value]
            except KeyError:
                missing_languages.append(value)

        return missing_languages

    def validate_sources(self):
        if len(self.compilers) > 1 and any(lang in self.compilers for lang in ['cs', 'java']):
            langs = ', '.join(self.compilers.keys())
            raise InvalidArguments(f'Cannot mix those languages into a target: {langs}')

    def process_link_depends(self, sources):
        """Process the link_depends keyword argument.

        This is designed to handle strings, Files, and the output of Custom
        Targets. Notably it doesn't handle generator() returned objects, since
        adding them as a link depends would inherently cause them to be
        generated twice, since the output needs to be passed to the ld_args and
        link_depends.
        """
        sources = listify(sources)
        for s in sources:
            if isinstance(s, File):
                self.link_depends.append(s)
            elif isinstance(s, str):
                self.link_depends.append(
                    File.from_source_file(self.environment.source_dir, self.get_source_subdir(), s))
            elif hasattr(s, 'get_outputs'):
                self.link_depends.append(s)
            else:
                raise InvalidArguments(
                    'Link_depends arguments must be strings, Files, '
                    'or a Custom Target, or lists thereof.')

    def extract_objects(self, srclist: T.List[T.Union['FileOrString', 'GeneratedTypes']]) -> ExtractedObjects:
        sources_set = set(self.sources)
        generated_set = set(self.generated)

        obj_src: T.List['File'] = []
        obj_gen: T.List['GeneratedTypes'] = []
        for src in srclist:
            if isinstance(src, (str, File)):
                if isinstance(src, str):
                    src = File(False, self.subdir, src)
                else:
                    FeatureNew.single_use('File argument for extract_objects', '0.50.0', self.subproject)
                if src not in sources_set:
                    raise MesonException(f'Tried to extract unknown source {src}.')
                obj_src.append(src)
            elif isinstance(src, (CustomTarget, CustomTargetIndex, GeneratedList)):
                FeatureNew.single_use('Generated sources for extract_objects', '0.61.0', self.subproject)
                target = src.target if isinstance(src, CustomTargetIndex) else src
                if src not in generated_set and target not in generated_set:
                    raise MesonException(f'Tried to extract unknown source {target.get_basename()}.')
                obj_gen.append(src)
            else:
                raise MesonException(f'Object extraction arguments must be strings, Files or targets (got {type(src).__name__}).')
        return ExtractedObjects(self, obj_src, obj_gen)

    def extract_all_objects(self, recursive: bool = True) -> ExtractedObjects:
        return ExtractedObjects(self, self.sources, self.generated, self.objects,
                                recursive, pch=True)

    def get_all_link_deps(self) -> ImmutableListProtocol[BuildTargetTypes]:
        return self.get_transitive_link_deps()

    @lru_cache(maxsize=None)
    def get_transitive_link_deps(self) -> ImmutableListProtocol[BuildTargetTypes]:
        result: T.List[Target] = []
        for i in self.link_targets:
            result += i.get_all_link_deps()
        return result

    def get_link_deps_mapping(self, prefix: str) -> T.Mapping[str, str]:
        return self.get_transitive_link_deps_mapping(prefix)

    @lru_cache(maxsize=None)
    def get_transitive_link_deps_mapping(self, prefix: str) -> T.Mapping[str, str]:
        result: T.Dict[str, str] = {}
        for i in self.link_targets:
            mapping = i.get_link_deps_mapping(prefix)
            #we are merging two dictionaries, while keeping the earlier one dominant
            result_tmp = mapping.copy()
            result_tmp.update(result)
            result = result_tmp
        return result

    @lru_cache(maxsize=None)
    def get_link_dep_subdirs(self) -> T.AbstractSet[str]:
        result: OrderedSet[str] = OrderedSet()
        for i in self.link_targets:
            if not isinstance(i, StaticLibrary):
                result.add(i.get_output_subdir())
            result.update(i.get_link_dep_subdirs())
        return result

    def get_default_install_dir(self) -> T.Union[T.Tuple[str, str], T.Tuple[None, None]]:
        return self.environment.get_libdir(), '{libdir}'

    def get_custom_install_dir(self) -> T.List[T.Union[str, Literal[False]]]:
        return self.install_dir

    def get_custom_install_mode(self) -> T.Optional['FileMode']:
        return self.install_mode

    def process_kwargs(self, kwargs):
        self.process_kwargs_base(kwargs)
        self.original_kwargs = kwargs

        self.add_pch('c', extract_as_list(kwargs, 'c_pch'))
        self.add_pch('cpp', extract_as_list(kwargs, 'cpp_pch'))

        if not isinstance(self, Executable) or kwargs.get('export_dynamic', False):
            self.vala_header = kwargs.get('vala_header', self.name + '.h')
            self.vala_vapi = kwargs.get('vala_vapi', self.name + '.vapi')
            self.vala_gir = kwargs.get('vala_gir', None)

        self.link_args = extract_as_list(kwargs, 'link_args')
        for i in self.link_args:
            if not isinstance(i, str):
                raise InvalidArguments('Link_args arguments must be strings.')
        for l in self.link_args:
            if '-Wl,-rpath' in l or l.startswith('-rpath'):
                mlog.warning(textwrap.dedent('''\
                    Please do not define rpath with a linker argument, use install_rpath
                    or build_rpath properties instead.
                    This will become a hard error in a future Meson release.
                '''))
        self.process_link_depends(kwargs.get('link_depends', []))
        # Target-specific include dirs must be added BEFORE include dirs from
        # internal deps (added inside self.add_deps()) to override them.
        inclist = extract_as_list(kwargs, 'include_directories')
        self.add_include_dirs(inclist)
        # Add dependencies (which also have include_directories)
        deplist = extract_as_list(kwargs, 'dependencies')
        self.add_deps(deplist)
        # If an item in this list is False, the output corresponding to
        # the list index of that item will not be installed
        self.install_dir = typeslistify(kwargs.get('install_dir', []),
                                        (str, bool))
        self.install_mode = kwargs.get('install_mode', None)
        self.install_tag = stringlistify(kwargs.get('install_tag', [None]))
        if not isinstance(self, Executable):
            # build_target will always populate these as `None`, which is fine
            if kwargs.get('gui_app') is not None:
                raise InvalidArguments('Argument gui_app can only be used on executables.')
            if kwargs.get('win_subsystem') is not None:
                raise InvalidArguments('Argument win_subsystem can only be used on executables.')
        extra_files = extract_as_list(kwargs, 'extra_files')
        for i in extra_files:
            assert isinstance(i, File)
            if i in self.extra_files:
                continue
            trial = os.path.join(self.environment.get_source_dir(), i.subdir, i.fname)
            if not os.path.isfile(trial):
                raise InvalidArguments(f'Tried to add non-existing extra file {i}.')
            self.extra_files.append(i)
        self.install_rpath: str = kwargs.get('install_rpath', '')
        if not isinstance(self.install_rpath, str):
            raise InvalidArguments('Install_rpath is not a string.')
        self.build_rpath = kwargs.get('build_rpath', '')
        if not isinstance(self.build_rpath, str):
            raise InvalidArguments('Build_rpath is not a string.')
        resources = extract_as_list(kwargs, 'resources')
        for r in resources:
            if not isinstance(r, str):
                raise InvalidArguments('Resource argument is not a string.')
            trial = os.path.join(self.environment.get_source_dir(), self.get_source_subdir(), r)
            if not os.path.isfile(trial):
                raise InvalidArguments(f'Tried to add non-existing resource {r}.')
        self.resources = resources
        if kwargs.get('name_prefix') is not None:
            name_prefix = kwargs['name_prefix']
            if isinstance(name_prefix, list):
                if name_prefix:
                    raise InvalidArguments('name_prefix array must be empty to signify default.')
            else:
                if not isinstance(name_prefix, str):
                    raise InvalidArguments('name_prefix must be a string.')
                self.prefix = name_prefix
                self.name_prefix_set = True
        if kwargs.get('name_suffix') is not None:
            name_suffix = kwargs['name_suffix']
            if isinstance(name_suffix, list):
                if name_suffix:
                    raise InvalidArguments('name_suffix array must be empty to signify default.')
            else:
                if not isinstance(name_suffix, str):
                    raise InvalidArguments('name_suffix must be a string.')
                if name_suffix == '':
                    raise InvalidArguments('name_suffix should not be an empty string. '
                                           'If you want meson to use the default behaviour '
                                           'for each platform pass `[]` (empty array)')
                self.suffix = name_suffix
                self.name_suffix_set = True
        if isinstance(self, StaticLibrary):
            # You can't disable PIC on OS X. The compiler ignores -fno-PIC.
            # PIC is always on for Windows (all code is position-independent
            # since library loading is done differently)
            m = self.environment.machines[self.for_machine]
            if m.is_darwin() or m.is_windows():
                self.pic = True
            else:
                self.pic = self._extract_pic_pie(kwargs, 'pic', 'b_staticpic')
        if isinstance(self, Executable) or (isinstance(self, StaticLibrary) and not self.pic):
            # Executables must be PIE on Android
            if self.environment.machines[self.for_machine].is_android():
                self.pie = True
            else:
                self.pie = self._extract_pic_pie(kwargs, 'pie', 'b_pie')
        self.implicit_include_directories = kwargs.get('implicit_include_directories', True)
        if not isinstance(self.implicit_include_directories, bool):
            raise InvalidArguments('Implicit_include_directories must be a boolean.')
        self.gnu_symbol_visibility = kwargs.get('gnu_symbol_visibility', '')
        if not isinstance(self.gnu_symbol_visibility, str):
            raise InvalidArguments('GNU symbol visibility must be a string.')
        if self.gnu_symbol_visibility != '':
            permitted = ['default', 'internal', 'hidden', 'protected', 'inlineshidden']
            if self.gnu_symbol_visibility not in permitted:
                raise InvalidArguments('GNU symbol visibility arg {} not one of: {}'.format(self.gnu_symbol_visibility, ', '.join(permitted)))

        rust_dependency_map = kwargs.get('rust_dependency_map', {})
        if not isinstance(rust_dependency_map, dict):
            raise InvalidArguments(f'Invalid rust_dependency_map "{rust_dependency_map}": must be a dictionary.')
        if any(not isinstance(v, str) for v in rust_dependency_map.values()):
            raise InvalidArguments(f'Invalid rust_dependency_map "{rust_dependency_map}": must be a dictionary with string values.')
        self.rust_dependency_map = rust_dependency_map

    def _extract_pic_pie(self, kwargs: T.Dict[str, T.Any], arg: str, option: str) -> bool:
        # Check if we have -fPIC, -fpic, -fPIE, or -fpie in cflags
        all_flags = self.extra_args['c'] + self.extra_args['cpp']
        if '-f' + arg.lower() in all_flags or '-f' + arg.upper() in all_flags:
            mlog.warning(f"Use the '{arg}' kwarg instead of passing '-f{arg}' manually to {self.name!r}")
            return True

        k = OptionKey(option)
        if kwargs.get(arg) is not None:
            val = T.cast('bool', kwargs[arg])
        elif k in self.environment.coredata.options:
            val = self.environment.coredata.options[k].value
        else:
            val = False

        if not isinstance(val, bool):
            raise InvalidArguments(f'Argument {arg} to {self.name!r} must be boolean')
        return val

    def get_filename(self) -> str:
        return self.filename

    def get_debug_filename(self) -> T.Optional[str]:
        """
        The name of debuginfo file that will be created by the compiler

        Returns None if the build won't create any debuginfo file
        """
        return self.debug_filename

    def get_outputs(self) -> T.List[str]:
        return self.outputs

    def get_extra_args(self, language: str) -> T.List[str]:
        return self.extra_args[language]

    @lru_cache(maxsize=None)
    def get_dependencies(self) -> OrderedSet[BuildTargetTypes]:
        # Get all targets needed for linking. This includes all link_with and
        # link_whole targets, and also all dependencies of static libraries
        # recursively. The algorithm here is closely related to what we do in
        # get_internal_static_libraries(): Installed static libraries include
        # objects from all their dependencies already.
        result: OrderedSet[BuildTargetTypes] = OrderedSet()
        for t in itertools.chain(self.link_targets, self.link_whole_targets):
            if t not in result:
                result.add(t)
                if isinstance(t, StaticLibrary):
                    t.get_dependencies_recurse(result)
        return result

    def get_dependencies_recurse(self, result: OrderedSet[BuildTargetTypes], include_internals: bool = True) -> None:
        # self is always a static library because we don't need to pull dependencies
        # of shared libraries. If self is installed (not internal) it already
        # include objects extracted from all its internal dependencies so we can
        # skip them.
        include_internals = include_internals and self.is_internal()
        for t in self.link_targets:
            if t in result:
                continue
            if include_internals or not t.is_internal():
                result.add(t)
            if isinstance(t, StaticLibrary):
                t.get_dependencies_recurse(result, include_internals)
        for t in self.link_whole_targets:
            t.get_dependencies_recurse(result, include_internals)

    def get_sources(self):
        return self.sources

    def get_objects(self) -> T.List[T.Union[str, 'File', 'ExtractedObjects']]:
        return self.objects

    def get_generated_sources(self) -> T.List['GeneratedTypes']:
        return self.generated

    def should_install(self) -> bool:
        return self.install

    def has_pch(self) -> bool:
        return bool(self.pch)

    def get_pch(self, language: str) -> T.List[str]:
        return self.pch.get(language, [])

    def get_include_dirs(self) -> T.List['IncludeDirs']:
        return self.include_dirs

    def add_deps(self, deps):
        deps = listify(deps)
        for dep in deps:
            if dep in self.added_deps:
                continue

            if isinstance(dep, dependencies.InternalDependency):
                # Those parts that are internal.
                self.process_sourcelist(dep.sources)
                self.extra_files.extend(f for f in dep.extra_files if f not in self.extra_files)
                self.add_include_dirs(dep.include_directories, dep.get_include_type())
                self.objects.extend(dep.objects)
                self.link_targets.extend(dep.libraries)
                self.link_whole_targets.extend(dep.whole_libraries)
                if dep.get_compile_args() or dep.get_link_args():
                    # Those parts that are external.
                    extpart = dependencies.InternalDependency('undefined',
                                                              [],
                                                              dep.get_compile_args(),
                                                              dep.get_link_args(),
                                                              [], [], [], [], [], {}, [], [], [])
                    self.external_deps.append(extpart)
                # Deps of deps.
                self.add_deps(dep.ext_deps)
            elif isinstance(dep, dependencies.Dependency):
                if dep not in self.external_deps:
                    self.external_deps.append(dep)
                    self.process_sourcelist(dep.get_sources())
                self.add_deps(dep.ext_deps)
            elif isinstance(dep, BuildTarget):
                raise InvalidArguments(f'Tried to use a build target {dep.name} as a dependency of target {self.name}.\n'
                                       'You probably should put it in link_with instead.')
            else:
                # This is a bit of a hack. We do not want Build to know anything
                # about the interpreter so we can't import it and use isinstance.
                # This should be reliable enough.
                if hasattr(dep, 'held_object'):
                    # FIXME: subproject is not a real ObjectHolder so we have to do this by hand
                    dep = dep.held_object
                if hasattr(dep, 'project_args_frozen') or hasattr(dep, 'global_args_frozen'):
                    raise InvalidArguments('Tried to use subproject object as a dependency.\n'
                                           'You probably wanted to use a dependency declared in it instead.\n'
                                           'Access it by calling get_variable() on the subproject object.')
                raise InvalidArguments(f'Argument is of an unacceptable type {type(dep).__name__!r}.\nMust be '
                                       'either an external dependency (returned by find_library() or '
                                       'dependency()) or an internal dependency (returned by '
                                       'declare_dependency()).')

            dep_d_features = dep.d_features

            for feature in ('versions', 'import_dirs'):
                if feature in dep_d_features:
                    self.d_features[feature].extend(dep_d_features[feature])

            self.added_deps.add(dep)

    def get_external_deps(self) -> T.List[dependencies.Dependency]:
        return self.external_deps

    def is_internal(self) -> bool:
        return False

    def link(self, targets: T.List[BuildTargetTypes]) -> None:
        for t in targets:
            if not isinstance(t, (Target, CustomTargetIndex)):
                if isinstance(t, dependencies.ExternalLibrary):
```