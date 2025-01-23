Response:
Let's break down the thought process for analyzing this Python code snippet from Meson's build system.

**1. Initial Understanding: Context is Key**

The very first line gives crucial context: `frida/releng/meson/mesonbuild/build.py`. This tells us we're looking at a core part of the Meson build system, specifically the `build.py` file, likely responsible for defining how build targets (like libraries and executables) are represented and processed. Knowing it's for Frida, a dynamic instrumentation toolkit, might give hints about potential interactions with low-level aspects later, but the core focus is still Meson's build process.

**2. Identifying the Central Entity:**

The code immediately defines a class, though the name isn't present in the snippet. However, the attributes being initialized within `__init__` heavily suggest this class represents a *build target*. Attributes like `sources`, `objects`, `link_targets`, `include_dirs`, `extra_args`, etc., are all standard elements of defining what goes into creating a software artifact.

**3. Dissecting `__init__` (The Constructor):**

The `__init__` method is the entry point and reveals a lot. I'd go through each attribute initialization and ask:

* **What kind of data is this?** (List, dictionary, boolean, etc.)
* **What does the name suggest its purpose is?** (Even if I don't know *exactly*, I can make educated guesses.)
* **Are there any interesting default values or initializations?** (Like `defaultdict(list)` for `extra_args`).
* **Are any methods called within `__init__`?**  These are important for understanding the immediate setup. Here, `process_sourcelist`, `process_objectlist`, `process_kwargs`, and `process_compilers` stand out.

**4. Analyzing Key Methods:**

After understanding the attributes, I'd look at the methods called within `__init__` and other prominent methods in the snippet:

* **`process_sourcelist`:** Clearly deals with categorizing source files (static vs. generated). This is fundamental to any build system.
* **`process_objectlist`:** Handles pre-compiled object files. The warnings about deprecated usage are noteworthy.
* **`process_kwargs`:** This is where many of the build target options are processed. It's a big, important method to understand. I'd look for how different keyword arguments are handled and what attributes they update. The calls to `extract_as_list` and `stringlistify` are patterns to observe.
* **`process_compilers` and `process_compilers_late`:**  Crucial for understanding how Meson determines which compilers are needed for the target. The logic around handling different languages and dependencies is interesting.
* **`link` and `link_whole`:**  These methods deal with linking other libraries. The distinction between the two is worth noting.
* **`get_dependencies` and `get_transitive_link_deps`:**  These highlight the dependency tracking mechanism, essential for correct build order.

**5. Connecting to Reverse Engineering, Binary, Kernel, etc.:**

At this point, I'd start thinking about how these functionalities relate to the specific prompt's requirements:

* **Reverse Engineering:** The mention of Frida immediately brings reverse engineering to mind. The ability to link against libraries (`link_with`), handle pre-compiled objects (`objects`), and control linking arguments (`link_args`) are all relevant to setting up targets for reverse engineering tools or hooking libraries.
* **Binary/Low-Level:**  The concepts of object files, linking, and position-independent code (PIC/PIE) directly relate to binary formats and low-level execution. The `build_rpath` and `install_rpath` are critical for how executables find shared libraries at runtime.
* **Linux/Android Kernel & Frameworks:**  While this snippet doesn't directly touch kernel code, the handling of PIC/PIE is particularly relevant for Android due to security requirements. The concept of shared libraries and their linking is fundamental to both Linux and Android.

**6. Logical Inference and Examples:**

For the logical inference, I would look for specific methods or logic that manipulate data based on input. `process_sourcelist` and `process_objectlist` are good examples. I'd think of a simple input (a list of filenames) and trace how the methods would process them, categorizing them as static or generated.

For user errors, I'd consider common mistakes when defining build targets: incorrect file paths, using the wrong keyword arguments, mixing incompatible language sources, forgetting dependencies, etc.

**7. Tracing User Operations:**

This requires thinking about how a user interacts with Meson. They write a `meson.build` file, which uses Meson's DSL to define targets. The keywords and arguments in the `__init__` and `process_kwargs` methods directly correspond to the syntax a user would use in `meson.build`.

**8. Summarizing the Functionality:**

Finally, I'd synthesize the information gathered into a concise summary, highlighting the core responsibilities of the code snippet.

**Self-Correction/Refinement During the Process:**

* **Initially, I might focus too much on the Frida aspect.**  It's important to remember this is *Meson* code first, used by Frida. The core functionality is about defining build targets.
* **I might get lost in the details of every single attribute.** It's more efficient to focus on the most important ones and the methods that manipulate them.
* **If I don't understand a specific attribute or method, I'd make a note to revisit it or look for related documentation or code.**

By following this structured approach, I can systematically analyze the code snippet and address all aspects of the prompt effectively. The key is to start with the high-level context and gradually drill down into the details, always connecting the code back to its purpose within the larger build system.
这是 Frida 动态 instrumentation 工具源代码文件 `frida/releng/meson/mesonbuild/build.py` 的一部分，它主要定义了构建目标（Build Target）的通用属性和行为。虽然这只是一个片段，但我们可以根据已有的代码推断出其功能，并联系到逆向、底层知识以及常见的用户错误。

**这段代码的主要功能归纳:**

这段代码定义了一个 Python 类，该类作为 Frida 项目中构建目标的基类或核心组件。它负责存储和管理构建目标（例如库、可执行文件）的各种属性，包括：

* **源文件管理:**  维护构建目标所需的源文件列表 (`sources`)，区分结构化源文件 (`structured_sources`) 和普通源文件。
* **目标文件管理:**  记录预编译的目标文件 (`objects`)。
* **依赖关系管理:**  跟踪外部依赖 (`external_deps`) 和内部依赖（通过 `link_targets`, `link_whole_targets` 实现）。
* **包含目录管理:**  存储编译时需要的头文件搜索路径 (`include_dirs`).
* **链接配置:**  存储链接时使用的语言 (`link_language`)，需要链接的其他目标 (`link_targets`, `link_whole_targets`)，以及链接时依赖的文件 (`link_depends`)。
* **输出文件命名:**  定义构建目标的输出文件名 (`filename`)，以及调试信息文件名 (`debug_filename`)。
* **预编译头:**  支持预编译头文件 (`pch`)。
* **编译器参数:**  存储不同语言的额外编译器参数 (`extra_args`)。
* **D语言特性:**  专门处理 D 语言的特性，如 debug 开关、导入目录、版本信息和单元测试。
* **位置无关代码:**  管理生成位置无关代码的选项 (`pic`, `pie`)。
* **安装路径:**  记录构建目标安装时的路径 (`install_dir`) 和权限 (`install_mode`, `install_tag`).
* **其他文件:**  管理需要一起处理的额外文件 (`extra_files`) 和资源文件 (`resources`)。
* **名称前缀/后缀:**  允许设置构建输出的名称前缀 (`prefix`) 和后缀 (`suffix`)。
* **Rust 依赖映射:**  专门处理 Rust 语言的依赖映射 (`rust_dependency_map`)。

**与逆向方法的联系及举例说明:**

* **链接依赖:**  在逆向工程中，我们经常需要分析一个程序依赖的库。这个类中的 `link_targets` 和 `link_whole_targets` 就记录了构建目标链接的其他库。例如，如果 Frida 的一个组件需要使用 `libuv` 库，那么在定义这个组件的构建目标时，`libuv` 就会被添加到 `link_targets` 中。逆向工程师可以通过分析构建脚本或最终的二进制文件来了解这些依赖关系。
* **目标文件 (`objects`):**  逆向工程师有时会分析中间编译产生的 `.o` 或 `.obj` 文件，以了解代码的结构和实现细节。这个类负责管理这些目标文件，方便构建过程中的链接。
* **位置无关代码 (`pic`, `pie`):**  对于共享库和某些可执行文件，生成位置无关代码是常见的做法。这使得库可以加载到内存的任意地址。逆向工程师在分析这些二进制文件时，需要理解 PIC/PIE 的原理。Frida 作为动态 instrumentation 工具，经常需要注入代码到目标进程，理解 PIC/PIE 有助于正确地进行代码注入。
* **调试信息文件名 (`debug_filename`):**  调试信息文件包含了源代码到机器码的映射关系，对于逆向工程中的调试和符号解析至关重要。这个类负责记录生成的调试信息文件名，方便后续的调试工作。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **位置无关代码 (`pic`, `pie`):**  `pic` (Position Independent Code) 主要用于生成共享库，而 `pie` (Position Independent Executable) 用于生成地址空间布局随机化 (ASLR) 的可执行文件。在 Linux 和 Android 中，为了提高安全性，通常会启用 ASLR，因此生成 PIE 的可执行文件是常见的做法。这个类中的 `pic` 和 `pie` 属性直接对应了这些底层的二进制特性。
* **链接过程:**  `link_targets` 和 `link_whole_targets` 涉及到链接器的操作。链接器将不同的目标文件和库组合成最终的可执行文件或共享库。了解链接过程对于理解二进制文件的结构和依赖关系至关重要。
* **安装路径 (`install_dir`):**  在 Linux 和 Android 中，库和可执行文件通常安装在特定的目录下，例如 `/usr/lib`, `/usr/bin`, `/system/lib`, `/system/bin` 等。这个类中的 `install_dir` 属性就定义了构建目标在安装时的目标路径。
* **运行时库路径 (`rpath_dirs_to_remove`, `install_rpath`, `build_rpath`):**  `rpath` (Run-time search path) 用于指定程序运行时查找共享库的路径。这个类中涉及 `rpath` 的属性用于管理构建和安装时的库查找路径。在 Android 开发中，理解库的加载路径对于解决依赖问题非常重要。

**逻辑推理 (假设输入与输出):**

假设我们创建了一个名为 `my_library` 的共享库构建目标，并设置了一些属性：

**假设输入:**

* `name`: "my_library"
* `sources`: [`src/my_library.c`, `src/utils.c`]
* `link_with`: [`other_library`]  (假设 `other_library` 是另一个已定义的构建目标)
* `include_directories`: [`include`]
* `pic`: True

**推断输出 (部分属性):**

* `self.filename`: "libmy_library.so" (根据平台和构建配置可能会有不同)
* `self.sources`:  包含 `File` 类型的对象，分别对应 `src/my_library.c` 和 `src/utils.c`。
* `self.link_targets`: 包含 `other_library` 构建目标的引用。
* `self.include_dirs`:  包含指向 `include` 目录的 `IncludeDirs` 对象。
* `self.pic`: True

**涉及用户或编程常见的使用错误及举例说明:**

* **错误的依赖指定:**  用户可能会将一个可执行文件错误地添加到 `link_targets` 中，导致链接错误。Meson 会在 `add_deps` 方法中进行检查并抛出 `InvalidArguments` 异常，提示用户应该使用 `link_with`。
* **未创建的额外文件:**  用户可能会在 `extra_files` 中指定一个不存在的文件路径，导致构建失败。代码中会检查文件是否存在，如果不存在则抛出 `InvalidArguments` 异常。
* **`install_rpath` 的错误使用:**  用户可能会手动在 `link_args` 中添加 `-rpath` 参数，而不是使用 `install_rpath` 或 `build_rpath` 属性。代码中会检测这种情况并发出警告，提示用户使用推荐的方式。
* **混合不兼容的语言:**  如果用户尝试在一个构建目标中同时编译 C# 和 Java 代码，`validate_sources` 方法会检测到这种情况并抛出 `InvalidArguments` 异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户在项目根目录下创建一个或多个 `meson.build` 文件，并在其中使用 Meson 提供的函数（例如 `shared_library`, `executable`）来定义构建目标，并设置各种属性，例如 `sources`, `dependencies`, `include_directories` 等。
2. **用户运行 `meson setup builddir`:** 用户在命令行执行 `meson setup builddir` 命令，指示 Meson 读取 `meson.build` 文件并生成构建系统所需的文件。
3. **Meson 解析 `meson.build` 文件:**  Meson 的解析器会读取 `meson.build` 文件，并根据用户定义的构建目标和属性，创建相应的对象。当遇到类似 `shared_library('my_library', sources=['src/my_library.c', 'src/utils.c'], link_with=other_lib)` 的语句时，就会创建这个 `build.py` 中定义的类的实例，并将 `sources`, `link_with` 等参数传递给类的 `__init__` 方法。
4. **调用 `__init__` 和其他处理方法:**  在创建构建目标对象时，`__init__` 方法会被调用，初始化各种属性。接着，`process_sourcelist`, `process_objectlist`, `process_kwargs`, `process_compilers` 等方法会被调用，进一步处理用户提供的参数，例如将字符串形式的源文件名转换为 `File` 对象，解析依赖关系，设置编译器参数等。

作为调试线索，如果构建过程中出现与特定构建目标相关的问题（例如链接错误、找不到源文件），开发者可以查看 Meson 生成的中间文件（例如 `build.ninja`）或者使用 Meson 提供的调试工具，来追踪构建目标的属性是如何被设置的，从而找到问题的原因。例如，查看特定构建目标的 `link_args` 或 `include_dirs` 是否正确。

**总结这段代码的功能:**

总而言之，这段 `build.py` 代码片段定义了 Frida 项目中构建目标的基础结构和通用行为。它负责管理构建目标的各种属性，包括源文件、依赖关系、链接配置、输出命名、编译器参数等。它是 Meson 构建系统中表示和操作构建目标的核心组件，为后续的编译、链接和安装过程提供了必要的信息。这段代码体现了构建系统的核心职责：理解用户的构建意图，并将其转化为底层的构建指令。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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