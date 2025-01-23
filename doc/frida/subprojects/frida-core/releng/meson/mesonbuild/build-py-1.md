Response:
My thinking process to answer the request about the `build.py` file goes like this:

1. **Understand the Goal:** The request asks for a summary of the file's functionality, relating it to reverse engineering, binary/kernel concepts, logical reasoning, user errors, debugging, and specifically, a concise summary for Part 2.

2. **Initial Scan and Keyword Identification:** I quickly scanned the code, looking for keywords and patterns that suggest the file's purpose. Keywords like `elf.objects`, `sources`, `compilers`, `link_targets`, `dependencies`, `install`, `debug_filename`, `rpath`, `pic`, `pie`, etc., immediately stood out. These hints point towards a build system component responsible for defining how software is compiled and linked.

3. **Identify Core Functionality:** Based on the keywords and structure, I identified the core functionality:
    * **Defining Build Targets:**  The class seems to represent a single build target (like a library or executable).
    * **Source Management:**  It handles various types of source files (static, generated, object files).
    * **Compiler Management:** It determines and manages the compilers used for different languages.
    * **Dependency Management:**  It handles dependencies on other targets and external libraries.
    * **Linking:**  It defines how the target is linked with other libraries.
    * **Installation:** It handles the installation of the built target.
    * **Configuration:** It processes various configuration options passed to the build system.

4. **Relate to Specific Request Points:**  I then systematically went through each requirement of the request:

    * **Reverse Engineering:**  I considered how the information managed by this file is crucial for reverse engineering. The compiled output, debugging symbols, linked libraries, and knowledge of how the code was built are all essential. I brainstormed examples like setting up Frida to hook functions in a specific library.

    * **Binary/Kernel/Android:** I looked for aspects that relate to lower-level concepts. `elf.objects`, `pic`, `pie`, and `rpath` are directly related to binary formats and loading. The mention of Android and handling of specific options for different operating systems also fits here. I thought of examples like how PIC/PIE affects address space layout randomization (ASLR) relevant to kernel security.

    * **Logical Reasoning:**  The processing of different types of sources and dependencies involves logical rules. The handling of `if` conditions and the flow of control in methods like `process_compilers` and `add_deps` demonstrate this. I considered a scenario where a target has no explicit sources but relies on linked libraries.

    * **User Errors:** I looked for error handling and validation within the code (`raise InvalidArguments`). I thought about common mistakes like providing incorrect file paths, mixing source types, or misusing keywords.

    * **Debugging:** I considered how this file is part of the build process and how errors here might manifest. The request to trace how a user arrives at this code relates to understanding the build system's execution flow.

5. **Structure the Answer:** I organized my thoughts into the requested categories. For each category, I provided a brief explanation and then concrete examples from the code.

6. **Focus on Part 2 Summary:** Finally, I distilled the core functionality of the code into a concise summary for Part 2. I focused on the core role of defining and configuring a build target, managing sources, compilers, linking, and dependencies. I aimed for a high-level understanding without getting bogged down in implementation details.

7. **Refinement and Review:** I reread my answer to ensure accuracy, clarity, and completeness. I made sure the examples were relevant and easy to understand. I checked if I had addressed all aspects of the original request.

Essentially, I approached the problem by first understanding the overall purpose of the code, then breaking it down into its constituent parts, and finally connecting those parts to the specific questions asked in the request. The keyword analysis was crucial for quickly grasping the file's domain. The emphasis was on explaining the *what* and *why* rather than just listing code elements.
这是 `frida/subprojects/frida-core/releng/meson/mesonbuild/build.py` 文件中 `Target` 类的一部分源代码。`Target` 类是 Meson 构建系统中表示一个构建目标（例如，库、可执行文件）的核心抽象。

**功能列举:**

这部分代码定义了 `Target` 类的一些核心属性和初始化方法 `__init__`，负责存储和处理构建目标的基本信息，包括：

* **源文件管理:**
    * `elf.objects`: 存储预编译的目标文件。
    * `structured_sources`:  存储结构化源文件（目前主要用于 Rust）。
    * `sources`: 存储普通的源文件。
    * `generated`: 存储由其他构建步骤生成的源文件。
    * `extra_files`: 存储与构建目标相关的额外文件。
    * `process_sourcelist(sources)`: 将提供的源文件列表分类到 `sources` 或 `generated`。
    * `process_objectlist(objects)`: 处理预编译的目标文件列表。
* **依赖管理:**
    * `external_deps`: 存储外部依赖项（例如，系统库）。
    * `include_dirs`: 存储头文件搜索路径。
    * `link_language`:  指定链接时使用的主要语言。
    * `link_targets`: 存储需要链接的其他构建目标。
    * `link_whole_targets`: 存储需要完整链接的其他构建目标（静态库）。
    * `depend_files`: 存储构建目标依赖的文件。
    * `link_depends`: 存储链接时依赖的文件或目标。
    * `added_deps`: 跟踪已添加的依赖项，避免重复添加。
    * `add_deps(deps)`: 添加依赖项，并处理内部和外部依赖。
* **编译选项:**
    * `extra_args`: 存储特定语言的编译器选项。
    * `d_features`: 存储 D 语言特有的编译选项。
    * `pic`:  布尔值，指示是否生成位置无关代码 (Position Independent Code)。
    * `pie`: 布尔值，指示是否生成位置无关可执行文件 (Position Independent Executable)。
    * `process_compilers()`:  确定构建目标需要使用的编译器。
* **输出文件:**
    * `filename`: 构建目标的输出文件名。
    * `debug_filename`:  调试信息文件的名称。
    * `outputs`:  构建目标生成的所有输出文件列表。
* **预编译头文件 (PCH):**
    * `pch`: 存储不同语言的预编译头文件配置。
* **安装信息:**
    * `install`: 布尔值，指示是否安装此构建目标。
    * `install_dir`:  安装目录。
    * `install_mode`: 安装权限。
    * `install_tag`: 安装标签。
    * `install_rpath`: 安装时的 RPATH。
    * `build_rpath`: 构建时的 RPATH。
* **命名约定:**
    * `prefix`:  构建目标名称的前缀。
    * `suffix`:  构建目标名称的后缀。
    * `name_prefix_set`:  指示是否设置了自定义前缀。
    * `name_suffix_set`:  指示是否设置了自定义后缀。
* **其他:**
    * `environment`:  Meson 的环境对象。
    * `subproject`:  如果此目标属于一个子项目，则为子项目名称。
    * `is_unity`:  指示是否使用 Unity 构建。
    * `missing_languages`:  在处理编译器时发现的缺失语言。

**与逆向方法的关系及举例:**

* **了解目标文件的组成 (`elf.objects`, `sources`, `generated`):**  逆向工程师需要知道目标是由哪些源代码和预编译的模块组成的。这有助于理解代码的结构和潜在的入口点。例如，如果逆向一个共享库，了解它是否使用了某些特定的预编译对象可能揭示其依赖关系。
* **调试信息 (`debug_filename`):** 调试信息对于逆向工程至关重要。它包含符号信息，允许调试器将二进制代码映射回源代码。Frida 这样的动态插桩工具也依赖调试信息来定位函数和变量。
* **链接的库 (`link_targets`, `link_whole_targets`):**  逆向分析需要确定目标链接了哪些库。这有助于理解目标的功能范围以及可能利用的系统或第三方接口。例如，如果一个程序链接了 SSL/TLS 库，逆向工程师可能会关注其网络安全相关的行为。
* **位置无关代码 (`pic`, `pie`):**  对于共享库和某些可执行文件，位置无关代码允许它们加载到内存的任意地址，这是现代操作系统安全特性的要求。理解 PIC/PIE 的设置有助于分析内存布局和安全缓解措施。例如，在 Android 平台上，可执行文件通常需要是 PIE。
* **RPATH (`install_rpath`, `build_rpath`):** RPATH 指定了动态链接器搜索共享库的路径。逆向工程师可以通过分析 RPATH 来了解程序运行时会加载哪些库，以及潜在的库劫持风险。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **目标文件 (`elf.objects`):**  涉及到 ELF 文件格式的知识，这是 Linux 系统上可执行文件、共享库和目标文件的标准格式。
* **位置无关代码 (`pic`, `pie`):**  需要理解操作系统（特别是 Linux 和 Android）的内存管理和加载机制。PIC 是共享库的必要条件，PIE 增强了可执行文件的安全性，使其不易受到某些类型的攻击。
* **链接 (`link_targets`, `link_whole_targets`):**  涉及到动态链接和静态链接的概念，以及链接器的工作原理。
* **RPATH (`install_rpath`, `build_rpath`):** 需要理解动态链接器如何查找和加载共享库，以及 RPATH 对此过程的影响。在 Android 上，linker 的行为可能略有不同。
* **Android 特性:** 代码中提到了 Android 平台对于 PIE 的要求 (`if self.environment.machines[self.for_machine].is_android(): self.pie = True`)，体现了对 Android 系统构建要求的理解。

**逻辑推理及假设输入与输出:**

假设有一个构建目标，其 `sources` 包含了 `a.c` 和 `b.cpp`，并且 `link_with` 指定了另一个名为 `mylib` 的构建目标。

**假设输入:**

```python
sources=['a.c', 'b.cpp']
link_with=[mylib_target_object]  # 假设 mylib_target_object 是表示 'mylib' 目标的 Target 对象
```

**逻辑推理:**

* `process_sourcelist(['a.c', 'b.cpp'])` 会将 `a.c` 和 `b.cpp` 分别添加到 `self.sources` 列表中。
* `process_compilers()` 会检查源文件的后缀，判断需要 C 编译器和 C++ 编译器。
* `link([mylib_target_object])` 会将 `mylib_target_object` 添加到 `self.link_targets` 列表中。

**潜在输出 (部分):**

```python
self.sources = [File(False, 'current_subdir', 'a.c'), File(False, 'current_subdir', 'b.cpp')]
self.compilers = {'c': <CCompiler object>, 'cpp': <CPPCompiler object>}
self.link_targets = [<Target object representing 'mylib'>]
```

**用户或编程常见的使用错误及举例:**

* **提供非法的源文件类型:**  如果 `objects` 列表中包含了不是目标文件或可以生成目标文件的类型的项，`process_objectlist` 会抛出 `InvalidArguments` 异常。
    ```python
    # 错误示例：将文本文件添加到 objects
    objects=['my_config.txt']
    ```
* **混合结构化和非结构化源文件:**  如果同时提供了 `structured_sources` 和 `sources` 或 `generated`，会抛出 `MesonException`。
    ```python
    # 错误示例
    structured_sources={'src': ['main.rs']}
    sources=['helper.c']
    ```
* **在 `objects` 中使用生成的非目标文件:** 如果自定义目标生成的文件被添加到 `objects` 中，但这些文件不是目标文件，则会抛出 `InvalidArguments`。
    ```python
    # 错误示例：自定义目标生成头文件
    custom_target('gen_header', output : 'myheader.h', ...)
    executable('myprogram', 'source.c', objects: [custom_target('gen_header')])
    ```
* **`link_depends` 参数类型错误:**  如果 `link_depends` 提供了既不是字符串、`File` 对象也不是 `CustomTarget` 对象的参数，会抛出 `InvalidArguments`。

**用户操作如何一步步到达这里 (调试线索):**

1. **用户编写 `meson.build` 文件:** 用户定义了一个可执行文件或库目标，并指定了源文件、依赖项等。例如：
   ```meson
   executable('myprogram', sources: ['main.c', 'utils.c'], dependencies: dep_zlib)
   ```
2. **用户运行 `meson setup builddir`:** Meson 开始解析 `meson.build` 文件，创建构建系统。
3. **Meson 解析 `executable()` 函数:**  Meson 内部会创建一个 `Executable` 类的实例（`Executable` 继承自 `Target`）。
4. **`Target.__init__` 被调用:**  在创建 `Executable` 实例时，会调用 `Target` 的 `__init__` 方法，传入用户在 `meson.build` 中指定的参数（例如 `sources` 和 `dependencies`）。
5. **`process_sourcelist`、`process_objectlist`、`process_kwargs` 等方法被调用:**  `__init__` 方法内部会调用各种处理函数，例如 `process_sourcelist` 来处理 `sources` 参数，将源文件添加到相应的列表中。如果用户传递了 `objects` 参数，则会调用 `process_objectlist`。

**作为调试线索:**

当构建过程中出现与目标定义相关的问题时（例如，找不到源文件、链接错误），开发者可以查看 `build.py` 中 `Target` 类的相关代码，了解 Meson 是如何处理这些信息的。例如：

* 如果构建时报告找不到源文件，可以检查 `process_sourcelist` 的逻辑，确认 Meson 是否正确解析了 `sources` 参数。
* 如果链接时出现问题，可以检查 `link` 方法和 `add_deps` 方法，了解 Meson 是如何处理链接目标和依赖项的。
* 通过在 `Target.__init__` 或相关方法中添加日志输出，可以跟踪构建目标的属性是如何被设置的。

**归纳一下它的功能 (第2部分):**

这部分 `Target` 类的代码主要负责**构建目标的基本信息初始化和管理**。它接收来自 Meson 构建定义的参数，处理源文件、预编译对象、依赖项等信息，并确定构建目标所需的编译器。这是定义一个构建目标的基础步骤，为后续的编译、链接和安装过程奠定了基础。它抽象了构建目标的关键属性，使得 Meson 能够统一地处理不同类型的构建目标（库、可执行文件等）。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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