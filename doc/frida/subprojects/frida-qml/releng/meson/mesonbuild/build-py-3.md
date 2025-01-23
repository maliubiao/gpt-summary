Response:
The user wants a summary of the Python code provided, specifically focusing on its functionalities within the context of the Frida dynamic instrumentation tool. I need to identify the purpose of the `build.py` file and the classes it defines. I also need to connect these functionalities to reverse engineering, low-level concepts, and potential user errors, providing illustrative examples.

Here's a breakdown of the code's main components and their relevance:

1. **Base Classes for Build Targets:** `BuildTarget`, `Target`, `SecondLevelHolder` - These define the fundamental structure for representing things that get built (libraries, executables, etc.). They manage properties like name, sources, outputs, dependencies, installation details.
2. **Executable:** `Executable` - Represents an executable program.
3. **Static Library:** `StaticLibrary` - Represents a static library. Key features include handling Rust-specific naming conventions and dependency management.
4. **Shared Library:** `SharedLibrary` - Represents a dynamically linked shared library. This is crucial for Frida as it often involves injecting shared libraries into target processes. It handles versioning, naming conventions across different platforms (Windows, Linux, macOS), and import libraries.
5. **Shared Module:** `SharedModule` -  Represents a shared library intended for `dlopen`-style loading, not direct linking.
6. **Both Libraries:** `BothLibraries` - A container for both static and shared versions of the same library.
7. **Custom Target:** `CustomTarget` - A highly flexible way to define build steps using arbitrary commands. This is vital for complex build processes and integrating external tools.
8. **Compile Target:** `CompileTarget` -  Represents a compilation step without linking. Useful for pre-processing or code generation.
9. **Run Target:** `RunTarget` - Represents a target that executes a command.

**Relevance to the Prompt:**

* **Functionality:** I will list the purpose of each class and its key attributes and methods.
* **Reverse Engineering:** I'll highlight how shared libraries are central to dynamic instrumentation (Frida's core function). I'll also mention how custom targets can be used to run reverse engineering tools.
* **Binary/Low-Level:** I'll discuss how the code handles different library types (`.a`, `.so`, `.dylib`, `.dll`), import libraries, and versioning conventions, reflecting the underlying operating system's handling of binaries. I will also mention the Rust-specific logic.
* **Linux/Android Kernel/Framework:** I'll point out how the code distinguishes between platform-specific library naming and versioning conventions (e.g., `.so` on Linux/Android, `.dylib` on macOS).
* **Logical Inference:** I'll give simple hypothetical input and output examples for some of the functions, like how a filename is constructed.
* **User Errors:** I will point out potential errors related to incorrect keyword arguments or platform-specific naming issues.
* **User Operations/Debugging:** I will explain how a user defining a library in a `meson.build` file would eventually lead to the execution of this Python code.
* **Part 4 Summary:** I will condense the identified functionalities into a concise summary.

**Constraint Checklist & Confidence Score:**
1. 列举一下它的功能: Yes
2. 如果它与逆向的方法有关系，请做出对应的举例说明: Yes
3. 如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明: Yes
4. 如果做了逻辑推理，请给出假设输入与输出: Yes
5. 如果涉及用户或者编程常见的使用错误，请举例说明: Yes
6. 说明用户操作是如何一步步的到达这里，作为调试线索: Yes
7. 这是第4部分，共5部分，请归纳一下它的功能: Yes

Confidence Score: 5/5

Strategizing complete. I will now generate the response based on the outlined points.
这是Frida动态Instrumentation工具的构建系统中负责处理构建目标定义的Python代码文件。它定义了多种类型的构建目标，例如库文件、可执行文件以及自定义构建步骤。

**主要功能归纳:**

1. **定义不同类型的构建目标:** 该文件定义了多个类，分别代表不同类型的构建产物，例如：
    * `Executable`: 可执行文件。
    * `StaticLibrary`: 静态链接库。
    * `SharedLibrary`: 动态链接库。
    * `SharedModule`: 用于 `dlopen` 加载的共享模块。
    * `CustomTarget`: 用户自定义的构建目标，可以执行任意命令。
    * `CompileTarget`: 仅编译源文件但不进行链接的目标。
    * `RunTarget`: 用于执行特定命令的目标。
    * `BothLibraries`: 同时构建静态库和动态库。

2. **管理构建目标的属性:** 每个构建目标类都包含管理其属性的方法和属性，例如：
    * `name`: 构建目标的名称。
    * `sources`: 构建所需的源文件列表。
    * `outputs`: 构建生成的文件列表。
    * `dependencies`: 构建依赖的其他构建目标或外部依赖。
    * `install`: 是否需要安装。
    * 版本信息 (`soversion`, `ltversion`, `darwin_versions`) 用于动态库。
    * 平台特定的前缀和后缀 (`prefix`, `suffix`)。

3. **处理平台特定的构建细节:** 代码中包含针对不同操作系统（Linux, Windows, macOS, Android, Cygwin）的特殊处理，例如：
    * 动态库的文件名和版本命名约定。
    * Windows 下的导入库 (`.lib`) 处理。
    * macOS 下的动态库版本管理。

4. **支持多种编程语言:** 代码能够处理多种编程语言的构建，例如通过检查 `compilers` 字典来确定使用的编译器，并针对 Rust 语言有特殊的处理 (例如 `rust_crate_type`)。

5. **处理依赖关系:** 代码可以定义和管理构建目标之间的依赖关系，确保构建顺序正确。

6. **支持自定义构建步骤:** `CustomTarget` 允许用户定义任意的构建命令，极大地扩展了构建系统的灵活性。

**与逆向方法的关联及举例说明:**

* **动态链接库的生成和注入:**  Frida 的核心功能是动态 instrumentation，这通常涉及到将自定义的动态链接库 (SharedLibrary) 注入到目标进程中。`SharedLibrary` 类的定义和属性管理直接关系到 Frida 能够生成正确格式的动态库。例如，在 Frida 的构建过程中，会使用 `SharedLibrary` 来定义 Frida Agent 的库文件（通常是 `.so` 或 `.dylib`）。这些库文件会被 Frida 核心注入到目标进程中，以执行 instrumentation 代码。
* **自定义构建步骤执行逆向工具:**  `CustomTarget` 可以用于集成各种逆向分析工具到构建流程中。例如，可以创建一个 `CustomTarget` 来运行 `objdump` 或 `readelf` 等工具来分析编译后的二进制文件，提取符号信息或其他元数据。假设输入 `command` 是 `['objdump', '-d', '@INPUT@', '-M', 'intel']`，`sources` 是一个编译后的可执行文件，输出将是该可执行文件的反汇编代码。
* **处理目标平台的二进制格式:** 代码中对不同平台动态库的命名和版本处理，体现了对不同操作系统底层二进制格式的理解。例如，在 macOS 上，动态库的版本号会体现在文件名中 (`libfoo.1.dylib`)，而在 Linux 上则可能是 `libfoo.so.1`。

**涉及二进制底层、Linux, Android内核及框架的知识及举例说明:**

* **动态库的链接和加载:** `SharedLibrary` 类处理了动态库的版本信息 (`soversion`, `ltversion`) 和别名 (aliases)，这些概念直接关联到 Linux 等系统下动态链接器如何找到和加载共享库。例如，`get_aliases` 方法会生成用于链接的未版本化名称 (例如 `libfoo.so`) 到实际版本化库文件 (例如 `libfoo.so.1`) 的软链接。
* **Windows 导入库 (`.lib`):**  `SharedLibrary` 中对 `import_filename` 的处理体现了对 Windows 系统下动态链接的特殊性，即链接时需要一个单独的导入库。
* **Android 的 `.so` 文件:** 代码中针对 `is_android()` 的判断，以及动态库后缀设置为 `.so`，反映了对 Android 系统上共享库的命名约定。Android 系统基于 Linux 内核，其动态库机制与 Linux 类似。
* **静态库的命名约定:** `StaticLibrary` 中提到 Windows 下静态库通常命名为 `libfoo.a` 而不是 `foo.lib`，这反映了不同平台工具链的差异。
* **Rust 的 `rlib` 和 `staticlib`:**  对 Rust 的 `rust_crate_type` 的处理，特别是 `rlib` 和 `staticlib` 的区分，以及 `staticlib` 类型的库需要额外添加 native static libs 的依赖，体现了对 Rust 语言底层库文件类型的理解。

**逻辑推理的假设输入与输出:**

假设有一个 `SharedLibrary` 目标被定义为：

```python
SharedLibrary(
    name='mylib',
    subdir='src',
    subproject='',
    for_machine=MachineChoice.HOST,
    sources=['mylib.c'],
    structured_sources=None,
    objects=[],
    environment=...,
    compilers={'c': ...},
    build_only_subproject=False,
    kwargs={'soversion': '1', 'version': '1.2.3'}
)
```

* **假设输入:**  上述 `SharedLibrary` 对象的 `self`。
* **`determine_filenames()` 的输出 (部分):**
    * 在 Linux 系统上，`self.filename_tpl` 可能是 `'lib{0.name}.so.{0.ltversion}'`，`self.filename` 将会是 `libmylib.so.1.2.3`。
    * `get_aliases()` 方法可能会生成 `('libmylib.so.1', 'libmylib.so.1.2.3', 'runtime')` 和 `('libmylib.so', 'libmylib.so.1', 'devel')` 这样的别名信息。
    * 在 macOS 系统上，`self.filename_tpl` 可能是 `'lib{0.name}.{0.soversion}.dylib'`，`self.filename` 将会是 `libmylib.1.dylib`。

**涉及用户或编程常见的使用错误及举例说明:**

* **在共享模块中指定版本:**  `SharedModule` 的 `__init__` 方法中会检查 `version` 和 `soversion` 关键字参数，如果存在则抛出 `MesonException`。这是因为共享模块通常不应该指定版本信息，因为它们是设计为按需加载的。用户如果错误地为 `shared_module()` 指定了 `version`，就会触发这个错误。
* **Rust 静态库命名不规范:** `StaticLibrary` 中检查 Rust 静态库 (`rlib` 类型) 的名称是否包含空格、句点或短横线，如果包含则抛出 `InvalidArguments`。这是因为 Rust 工具链对 `rlib` 类型的库名有这样的限制。用户如果尝试创建一个名为 `my-lib.rlib` 的静态库，就会遇到这个错误。
* **`rust_abi` 和 `rust_crate_type` 同时使用:**  在 `StaticLibrary` 和 `SharedLibrary` 的 `process_kwargs` 方法中，会检查 `rust_abi` 和 `rust_crate_type` 是否同时被指定，如果同时指定则抛出 `InvalidArguments`，因为这两个关键字是互斥的。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户创建或修改 `meson.build` 文件:** 用户在项目根目录下或者子目录中编写 `meson.build` 文件，使用 Meson 提供的函数来定义构建目标，例如 `shared_library()`, `static_library()`, `executable()`, `custom_target()` 等。
2. **用户运行 `meson` 命令:** 用户在构建目录下运行 `meson <源代码目录>` 命令，Meson 会解析 `meson.build` 文件。
3. **Meson 解析 `meson.build` 文件:** Meson 的解析器会读取 `meson.build` 文件，并根据文件中调用的函数和提供的参数，创建相应的构建目标对象，例如 `SharedLibrary`, `Executable` 的实例。
4. **调用 `build.py` 中的类:** 当 Meson 解析到例如 `shared_library()` 函数时，它会在内部调用 `frida/subprojects/frida-qml/releng/meson/mesonbuild/build.py` 文件中 `SharedLibrary` 类的构造函数 `__init__` 来创建相应的对象。传递给 `shared_library()` 的参数会作为参数传递给 `__init__` 方法。
5. **构建系统处理构建目标:**  后续的构建过程中，Meson 会根据这些构建目标对象的属性和方法，生成实际的构建命令，并交给底层的构建工具 (例如 Ninja) 来执行。

作为调试线索，如果构建过程中出现与特定库文件相关的问题，例如链接错误、找不到库文件等，开发者可以查看 `meson-log.txt` 文件，其中会记录 Meson 的构建过程和调用的 Python 代码。通过分析日志，可以确定是哪个 `SharedLibrary` 或 `StaticLibrary` 对象的定义出现了问题，例如文件名、依赖关系、版本信息是否正确。也可以在 `build.py` 中添加打印语句进行更细致的调试。

**这是第4部分，共5部分，请归纳一下它的功能:**

总而言之，`frida/subprojects/frida-qml/releng/meson/mesonbuild/build.py` 文件的主要功能是**定义 Frida 构建系统中各种构建目标的结构和行为，包括可执行文件、静态库、动态库、共享模块和自定义构建步骤。它负责管理这些目标的属性，处理平台特定的构建细节，支持多种编程语言，并管理构建目标之间的依赖关系，是 Meson 构建系统核心的一部分，确保 Frida 能够正确地构建出各种平台上的二进制文件。**

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```python
get(self):
        return self.is_linkwithable

    def get_command(self) -> 'ImmutableListProtocol[str]':
        """Provides compatibility with ExternalProgram.

        Since you can override ExternalProgram instances with Executables.
        """
        return self.outputs

    def get_path(self) -> str:
        """Provides compatibility with ExternalProgram."""
        return os.path.join(self.subdir, self.filename)

    def found(self) -> bool:
        """Provides compatibility with ExternalProgram."""
        return True


class StaticLibrary(BuildTarget):
    known_kwargs = known_stlib_kwargs

    typename = 'static library'

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
        self.prelink = T.cast('bool', kwargs.get('prelink', False))
        super().__init__(name, subdir, subproject, for_machine, sources, structured_sources, objects,
                         environment, compilers, build_only_subproject, kwargs)

    def post_init(self) -> None:
        super().post_init()
        if 'cs' in self.compilers:
            raise InvalidArguments('Static libraries not supported for C#.')
        if self.uses_rust():
            # See https://github.com/rust-lang/rust/issues/110460
            if self.rust_crate_type == 'rlib' and any(c in self.name for c in ['-', ' ', '.']):
                raise InvalidArguments(f'Rust crate {self.name} type {self.rust_crate_type} does not allow spaces, '
                                       'periods or dashes in the library name due to a limitation of rustc. '
                                       'Replace them with underscores, for example')
            if self.rust_crate_type == 'staticlib':
                # FIXME: In the case of no-std we should not add those libraries,
                # but we have no way to know currently.
                rustc = self.compilers['rust']
                d = dependencies.InternalDependency('undefined', [], [],
                                                    rustc.native_static_libs,
                                                    [], [], [], [], [], {}, [], [], [])
                self.external_deps.append(d)
        # By default a static library is named libfoo.a even on Windows because
        # MSVC does not have a consistent convention for what static libraries
        # are called. The MSVC CRT uses libfoo.lib syntax but nothing else uses
        # it and GCC only looks for static libraries called foo.lib and
        # libfoo.a. However, we cannot use foo.lib because that's the same as
        # the import library. Using libfoo.a is ok because people using MSVC
        # always pass the library filename while linking anyway.
        #
        # See our FAQ for more detailed rationale:
        # https://mesonbuild.com/FAQ.html#why-does-building-my-project-with-msvc-output-static-libraries-called-libfooa
        if not hasattr(self, 'prefix'):
            self.prefix = 'lib'
        if not hasattr(self, 'suffix'):
            if self.uses_rust():
                if self.rust_crate_type == 'rlib':
                    # default Rust static library suffix
                    self.suffix = 'rlib'
                elif self.rust_crate_type == 'staticlib':
                    self.suffix = 'a'
            else:
                self.suffix = 'a'
        self.filename = self.prefix + self.name + '.' + self.suffix
        self.outputs[0] = self.filename

    def get_link_deps_mapping(self, prefix: str) -> T.Mapping[str, str]:
        return {}

    def get_default_install_dir(self) -> T.Union[T.Tuple[str, str], T.Tuple[None, None]]:
        return self.environment.get_static_lib_dir(), '{libdir_static}'

    def type_suffix(self):
        return "@sta"

    def process_kwargs(self, kwargs):
        super().process_kwargs(kwargs)

        rust_abi = kwargs.get('rust_abi')
        rust_crate_type = kwargs.get('rust_crate_type')
        if rust_crate_type:
            if rust_abi:
                raise InvalidArguments('rust_abi and rust_crate_type are mutually exclusive.')
            if rust_crate_type == 'lib':
                self.rust_crate_type = 'rlib'
            elif rust_crate_type in {'rlib', 'staticlib'}:
                self.rust_crate_type = rust_crate_type
            else:
                raise InvalidArguments(f'Crate type {rust_crate_type!r} invalid for static libraries; must be "rlib" or "staticlib"')
        else:
            self.rust_crate_type = 'staticlib' if rust_abi == 'c' else 'rlib'

    def is_linkable_target(self):
        return True

    def is_internal(self) -> bool:
        return not self.install

class SharedLibrary(BuildTarget):
    known_kwargs = known_shlib_kwargs

    typename = 'shared library'

    # Used by AIX to decide whether to archive shared library or not.
    aix_so_archive = True

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
        self.soversion: T.Optional[str] = None
        self.ltversion: T.Optional[str] = None
        # Max length 2, first element is compatibility_version, second is current_version
        self.darwin_versions: T.Optional[T.Tuple[str, str]] = None
        self.vs_module_defs = None
        # The import library this target will generate
        self.import_filename = None
        # The debugging information file this target will generate
        self.debug_filename = None
        # Use by the pkgconfig module
        self.shared_library_only = False
        super().__init__(name, subdir, subproject, for_machine, sources, structured_sources, objects,
                         environment, compilers, build_only_subproject, kwargs)

    def post_init(self) -> None:
        super().post_init()
        if self.uses_rust():
            # See https://github.com/rust-lang/rust/issues/110460
            if self.rust_crate_type != 'cdylib' and any(c in self.name for c in ['-', ' ', '.']):
                raise InvalidArguments(f'Rust crate {self.name} type {self.rust_crate_type} does not allow spaces, '
                                       'periods or dashes in the library name due to a limitation of rustc. '
                                       'Replace them with underscores, for example')

        if not hasattr(self, 'prefix'):
            self.prefix = None
        if not hasattr(self, 'suffix'):
            self.suffix = None
        self.basic_filename_tpl = '{0.prefix}{0.name}.{0.suffix}'
        self.determine_filenames()

    def get_link_deps_mapping(self, prefix: str) -> T.Mapping[str, str]:
        result: T.Dict[str, str] = {}
        mappings = self.get_transitive_link_deps_mapping(prefix)
        old = get_target_macos_dylib_install_name(self)
        if old not in mappings:
            fname = self.get_filename()
            outdirs, _, _ = self.get_install_dir()
            new = os.path.join(prefix, outdirs[0], fname)
            result.update({old: new})
        mappings.update(result)
        return mappings

    def get_default_install_dir(self) -> T.Union[T.Tuple[str, str], T.Tuple[None, None]]:
        return self.environment.get_shared_lib_dir(), '{libdir_shared}'

    def determine_filenames(self):
        """
        See https://github.com/mesonbuild/meson/pull/417 for details.

        First we determine the filename template (self.filename_tpl), then we
        set the output filename (self.filename).

        The template is needed while creating aliases (self.get_aliases),
        which are needed while generating .so shared libraries for Linux.

        Besides this, there's also the import library name (self.import_filename),
        which is only used on Windows since on that platform the linker uses a
        separate library called the "import library" during linking instead of
        the shared library (DLL).
        """
        prefix = ''
        suffix = ''
        create_debug_file = False
        self.filename_tpl = self.basic_filename_tpl
        import_filename_tpl = None
        # NOTE: manual prefix/suffix override is currently only tested for C/C++
        # C# and Mono
        if 'cs' in self.compilers:
            prefix = ''
            suffix = 'dll'
            self.filename_tpl = '{0.prefix}{0.name}.{0.suffix}'
            create_debug_file = True
        # C, C++, Swift, Vala
        # Only Windows uses a separate import library for linking
        # For all other targets/platforms import_filename stays None
        elif self.environment.machines[self.for_machine].is_windows():
            suffix = 'dll'
            if self.uses_rust():
                # Shared library is of the form foo.dll
                prefix = ''
                # Import library is called foo.dll.lib
                import_filename_tpl = '{0.prefix}{0.name}.dll.lib'
                # .pdb file is only created when debug symbols are enabled
                create_debug_file = self.environment.coredata.get_option(OptionKey("debug"))
            elif self.get_using_msvc():
                # Shared library is of the form foo.dll
                prefix = ''
                # Import library is called foo.lib
                import_filename_tpl = '{0.prefix}{0.name}.lib'
                # .pdb file is only created when debug symbols are enabled
                create_debug_file = self.environment.coredata.get_option(OptionKey("debug"))
            # Assume GCC-compatible naming
            else:
                # Shared library is of the form libfoo.dll
                prefix = 'lib'
                # Import library is called libfoo.dll.a
                import_filename_tpl = '{0.prefix}{0.name}.dll.a'
            # Shared library has the soversion if it is defined
            if self.soversion:
                self.filename_tpl = '{0.prefix}{0.name}-{0.soversion}.{0.suffix}'
            else:
                self.filename_tpl = '{0.prefix}{0.name}.{0.suffix}'
        elif self.environment.machines[self.for_machine].is_cygwin():
            suffix = 'dll'
            # Shared library is of the form cygfoo.dll
            # (ld --dll-search-prefix=cyg is the default)
            prefix = 'cyg'
            # Import library is called libfoo.dll.a
            import_prefix = self.prefix if self.prefix is not None else 'lib'
            import_filename_tpl = import_prefix + '{0.name}.dll.a'
            if self.soversion:
                self.filename_tpl = '{0.prefix}{0.name}-{0.soversion}.{0.suffix}'
            else:
                self.filename_tpl = '{0.prefix}{0.name}.{0.suffix}'
        elif self.environment.machines[self.for_machine].is_darwin():
            prefix = 'lib'
            suffix = 'dylib'
            # On macOS, the filename can only contain the major version
            if self.soversion:
                # libfoo.X.dylib
                self.filename_tpl = '{0.prefix}{0.name}.{0.soversion}.{0.suffix}'
            else:
                # libfoo.dylib
                self.filename_tpl = '{0.prefix}{0.name}.{0.suffix}'
        elif self.environment.machines[self.for_machine].is_android():
            prefix = 'lib'
            suffix = 'so'
            # Android doesn't support shared_library versioning
            self.filename_tpl = '{0.prefix}{0.name}.{0.suffix}'
        else:
            prefix = 'lib'
            suffix = 'so'
            if self.ltversion:
                # libfoo.so.X[.Y[.Z]] (.Y and .Z are optional)
                self.filename_tpl = '{0.prefix}{0.name}.{0.suffix}.{0.ltversion}'
            elif self.soversion:
                # libfoo.so.X
                self.filename_tpl = '{0.prefix}{0.name}.{0.suffix}.{0.soversion}'
            else:
                # No versioning, libfoo.so
                self.filename_tpl = '{0.prefix}{0.name}.{0.suffix}'
        if self.prefix is None:
            self.prefix = prefix
        if self.suffix is None:
            self.suffix = suffix
        self.filename = self.filename_tpl.format(self)
        if import_filename_tpl:
            self.import_filename = import_filename_tpl.format(self)
        # There may have been more outputs added by the time we get here, so
        # only replace the first entry
        self.outputs[0] = self.filename
        if create_debug_file:
            self.debug_filename = os.path.splitext(self.filename)[0] + '.pdb'

    def process_kwargs(self, kwargs):
        super().process_kwargs(kwargs)

        if not self.environment.machines[self.for_machine].is_android():
            # Shared library version
            self.ltversion = T.cast('T.Optional[str]', kwargs.get('version'))
            self.soversion = T.cast('T.Optional[str]', kwargs.get('soversion'))
            if self.soversion is None and self.ltversion is not None:
                # library version is defined, get the soversion from that
                # We replicate what Autotools does here and take the first
                # number of the version by default.
                self.soversion = self.ltversion.split('.')[0]
            # macOS, iOS and tvOS dylib compatibility_version and current_version
            self.darwin_versions = T.cast('T.Optional[T.Tuple[str, str]]', kwargs.get('darwin_versions'))
            if self.darwin_versions is None and self.soversion is not None:
                # If unspecified, pick the soversion
                self.darwin_versions = (self.soversion, self.soversion)

        # Visual Studio module-definitions file
        self.process_vs_module_defs_kw(kwargs)

        rust_abi = kwargs.get('rust_abi')
        rust_crate_type = kwargs.get('rust_crate_type')
        if rust_crate_type:
            if rust_abi:
                raise InvalidArguments('rust_abi and rust_crate_type are mutually exclusive.')
            if rust_crate_type == 'lib':
                self.rust_crate_type = 'dylib'
            elif rust_crate_type in {'dylib', 'cdylib', 'proc-macro'}:
                self.rust_crate_type = rust_crate_type
            else:
                raise InvalidArguments(f'Crate type {rust_crate_type!r} invalid for shared libraries; must be "dylib", "cdylib" or "proc-macro"')
        else:
            self.rust_crate_type = 'cdylib' if rust_abi == 'c' else 'dylib'

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

    def get_all_link_deps(self):
        return [self] + self.get_transitive_link_deps()

    def get_aliases(self) -> T.List[T.Tuple[str, str, str]]:
        """
        If the versioned library name is libfoo.so.0.100.0, aliases are:
        * libfoo.so.0 (soversion) -> libfoo.so.0.100.0
        * libfoo.so (unversioned; for linking) -> libfoo.so.0
        Same for dylib:
        * libfoo.dylib (unversioned; for linking) -> libfoo.0.dylib
        """
        aliases: T.List[T.Tuple[str, str, str]] = []
        # Aliases are only useful with .so and .dylib libraries. Also if
        # there's no self.soversion (no versioning), we don't need aliases.
        if self.suffix not in ('so', 'dylib') or not self.soversion:
            return aliases
        # With .so libraries, the minor and micro versions are also in the
        # filename. If ltversion != soversion we create an soversion alias:
        # libfoo.so.0 -> libfoo.so.0.100.0
        # Where libfoo.so.0.100.0 is the actual library
        if self.suffix == 'so' and self.ltversion and self.ltversion != self.soversion:
            alias_tpl = self.filename_tpl.replace('ltversion', 'soversion')
            ltversion_filename = alias_tpl.format(self)
            tag = self.install_tag[0] or 'runtime'
            aliases.append((ltversion_filename, self.filename, tag))
        # libfoo.so.0/libfoo.0.dylib is the actual library
        else:
            ltversion_filename = self.filename
        # Unversioned alias:
        #  libfoo.so -> libfoo.so.0
        #  libfoo.dylib -> libfoo.0.dylib
        tag = self.install_tag[0] or 'devel'
        aliases.append((self.basic_filename_tpl.format(self), ltversion_filename, tag))
        return aliases

    def type_suffix(self):
        return "@sha"

    def is_linkable_target(self):
        return True

# A shared library that is meant to be used with dlopen rather than linking
# into something else.
class SharedModule(SharedLibrary):
    known_kwargs = known_shmod_kwargs

    typename = 'shared module'

    # Used by AIX to not archive shared library for dlopen mechanism
    aix_so_archive = False

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
        if 'version' in kwargs:
            raise MesonException('Shared modules must not specify the version kwarg.')
        if 'soversion' in kwargs:
            raise MesonException('Shared modules must not specify the soversion kwarg.')
        super().__init__(name, subdir, subproject, for_machine, sources,
                         structured_sources, objects, environment, compilers, build_only_subproject, kwargs)
        # We need to set the soname in cases where build files link the module
        # to build targets, see: https://github.com/mesonbuild/meson/issues/9492
        self.force_soname = False

    def get_default_install_dir(self) -> T.Union[T.Tuple[str, str], T.Tuple[None, None]]:
        return self.environment.get_shared_module_dir(), '{moduledir_shared}'

class BothLibraries(SecondLevelHolder):
    def __init__(self, shared: SharedLibrary, static: StaticLibrary) -> None:
        self._preferred_library = 'shared'
        self.shared = shared
        self.static = static
        self.subproject = self.shared.subproject

    def __repr__(self) -> str:
        return f'<BothLibraries: static={repr(self.static)}; shared={repr(self.shared)}>'

    def get_default_object(self) -> BuildTarget:
        if self._preferred_library == 'shared':
            return self.shared
        elif self._preferred_library == 'static':
            return self.static
        raise MesonBugException(f'self._preferred_library == "{self._preferred_library}" is neither "shared" nor "static".')

class CommandBase:

    depend_files: T.List[File]
    dependencies: T.List[T.Union[BuildTarget, 'CustomTarget']]
    subproject: str

    def flatten_command(self, cmd: T.Sequence[T.Union[str, File, programs.ExternalProgram, BuildTargetTypes]]) -> \
            T.List[T.Union[str, File, BuildTarget, 'CustomTarget']]:
        cmd = listify(cmd)
        final_cmd: T.List[T.Union[str, File, BuildTarget, 'CustomTarget']] = []
        for c in cmd:
            if isinstance(c, str):
                final_cmd.append(c)
            elif isinstance(c, File):
                self.depend_files.append(c)
                final_cmd.append(c)
            elif isinstance(c, programs.ExternalProgram):
                if not c.found():
                    raise InvalidArguments('Tried to use not-found external program in "command"')
                path = c.get_path()
                if os.path.isabs(path):
                    # Can only add a dependency on an external program which we
                    # know the absolute path of
                    self.depend_files.append(File.from_absolute_file(path))
                final_cmd += c.get_command()
            elif isinstance(c, (BuildTarget, CustomTarget)):
                self.dependencies.append(c)
                final_cmd.append(c)
            elif isinstance(c, CustomTargetIndex):
                FeatureNew.single_use('CustomTargetIndex for command argument', '0.60', self.subproject)
                self.dependencies.append(c.target)
                final_cmd += self.flatten_command(File.from_built_file(c.get_source_subdir(), c.get_filename()))
            elif isinstance(c, list):
                final_cmd += self.flatten_command(c)
            else:
                raise InvalidArguments(f'Argument {c!r} in "command" is invalid')
        return final_cmd

class CustomTargetBase:
    ''' Base class for CustomTarget and CustomTargetIndex

    This base class can be used to provide a dummy implementation of some
    private methods to avoid repeating `isinstance(t, BuildTarget)` when dealing
    with custom targets.
    '''

    rust_crate_type = ''

    def get_dependencies_recurse(self, result: OrderedSet[BuildTargetTypes], include_internals: bool = True) -> None:
        pass

    def get_internal_static_libraries(self) -> OrderedSet[BuildTargetTypes]:
        return OrderedSet()

    def get_internal_static_libraries_recurse(self, result: OrderedSet[BuildTargetTypes]) -> None:
        pass

class CustomTarget(Target, CustomTargetBase, CommandBase):

    typename = 'custom'

    def __init__(self,
                 name: T.Optional[str],
                 subdir: str,
                 subproject: str,
                 environment: environment.Environment,
                 command: T.Sequence[T.Union[
                     str, BuildTargetTypes, GeneratedList,
                     programs.ExternalProgram, File]],
                 sources: T.Sequence[T.Union[
                     str, File, BuildTargetTypes, ExtractedObjects,
                     GeneratedList, programs.ExternalProgram]],
                 outputs: T.List[str],
                 build_only_subproject: bool,
                 *,
                 build_always_stale: bool = False,
                 build_by_default: T.Optional[bool] = None,
                 capture: bool = False,
                 console: bool = False,
                 depend_files: T.Optional[T.Sequence[FileOrString]] = None,
                 extra_depends: T.Optional[T.Sequence[T.Union[str, SourceOutputs]]] = None,
                 depfile: T.Optional[str] = None,
                 env: T.Optional[EnvironmentVariables] = None,
                 feed: bool = False,
                 install: bool = False,
                 install_dir: T.Optional[T.List[T.Union[str, Literal[False]]]] = None,
                 install_mode: T.Optional[FileMode] = None,
                 install_tag: T.Optional[T.List[T.Optional[str]]] = None,
                 absolute_paths: bool = False,
                 backend: T.Optional['Backend'] = None,
                 description: str = 'Generating {} with a custom command',
                 ):
        # TODO expose keyword arg to make MachineChoice.HOST configurable
        super().__init__(name, subdir, subproject, False, MachineChoice.HOST, environment,
                         build_only_subproject, install, build_always_stale)
        self.sources = list(sources)
        self.outputs = substitute_values(
            outputs, get_filenames_templates_dict(
                get_sources_string_names(sources, backend),
                []))
        self.build_by_default = build_by_default if build_by_default is not None else install
        self.capture = capture
        self.console = console
        self.depend_files = list(depend_files or [])
        self.dependencies: T.List[T.Union[CustomTarget, BuildTarget]] = []
        # must be after depend_files and dependencies
        self.command = self.flatten_command(command)
        self.depfile = depfile
        self.env = env or EnvironmentVariables()
        self.extra_depends = list(extra_depends or [])
        self.feed = feed
        self.install_dir = list(install_dir or [])
        self.install_mode = install_mode
        self.install_tag = _process_install_tag(install_tag, len(self.outputs))
        self.name = name if name else self.outputs[0]
        self.description = description

        # Whether to use absolute paths for all files on the commandline
        self.absolute_paths = absolute_paths

    def get_default_install_dir(self) -> T.Union[T.Tuple[str, str], T.Tuple[None, None]]:
        return None, None

    def __repr__(self):
        repr_str = "<{0} {1}: {2}>"
        return repr_str.format(self.__class__.__name__, self.get_id(), self.command)

    def get_target_dependencies(self) -> T.List[T.Union[SourceOutputs, str]]:
        deps: T.List[T.Union[SourceOutputs, str]] = []
        deps.extend(self.dependencies)
        deps.extend(self.extra_depends)
        for c in self.sources:
            if isinstance(c, CustomTargetIndex):
                deps.append(c.target)
            elif not isinstance(c, programs.ExternalProgram):
                deps.append(c)
        return deps

    def get_transitive_build_target_deps(self) -> T.Set[T.Union[BuildTarget, 'CustomTarget']]:
        '''
        Recursively fetch the build targets that this custom target depends on,
        whether through `command:`, `depends:`, or `sources:` The recursion is
        only performed on custom targets.
        This is useful for setting PATH on Windows for finding required DLLs.
        F.ex, if you have a python script that loads a C module that links to
        other DLLs in your project.
        '''
        bdeps: T.Set[T.Union[BuildTarget, 'CustomTarget']] = set()
        deps = self.get_target_dependencies()
        for d in deps:
            if isinstance(d, BuildTarget):
                bdeps.add(d)
            elif isinstance(d, CustomTarget):
                bdeps.update(d.get_transitive_build_target_deps())
        return bdeps

    def get_dependencies(self):
        return self.dependencies

    def should_install(self) -> bool:
        return self.install

    def get_custom_install_dir(self) -> T.List[T.Union[str, Literal[False]]]:
        return self.install_dir

    def get_custom_install_mode(self) -> T.Optional['FileMode']:
        return self.install_mode

    def get_outputs(self) -> T.List[str]:
        return self.outputs

    def get_filename(self) -> str:
        return self.outputs[0]

    def get_sources(self) -> T.List[T.Union[str, File, BuildTarget, GeneratedTypes, ExtractedObjects, programs.ExternalProgram]]:
        return self.sources

    def get_generated_lists(self) -> T.List[GeneratedList]:
        genlists: T.List[GeneratedList] = []
        for c in self.sources:
            if isinstance(c, GeneratedList):
                genlists.append(c)
        return genlists

    def get_generated_sources(self) -> T.List[GeneratedList]:
        return self.get_generated_lists()

    def get_dep_outname(self, infilenames):
        if self.depfile is None:
            raise InvalidArguments('Tried to get depfile name for custom_target that does not have depfile defined.')
        if infilenames:
            plainname = os.path.basename(infilenames[0])
            basename = os.path.splitext(plainname)[0]
            return self.depfile.replace('@BASENAME@', basename).replace('@PLAINNAME@', plainname)
        else:
            if '@BASENAME@' in self.depfile or '@PLAINNAME@' in self.depfile:
                raise InvalidArguments('Substitution in depfile for custom_target that does not have an input file.')
            return self.depfile

    def is_linkable_output(self, output: str) -> bool:
        if output.endswith(('.a', '.dll', '.lib', '.so', '.dylib')):
            return True
        # libfoo.so.X soname
        if re.search(r'\.so(\.\d+)*$', output):
            return True
        return False

    def is_linkable_target(self) -> bool:
        if len(self.outputs) != 1:
            return False
        return self.is_linkable_output(self.outputs[0])

    def links_dynamically(self) -> bool:
        """Whether this target links dynamically or statically

        Does not assert the target is linkable, just that it is not shared

        :return: True if is dynamically linked, otherwise False
        """
        suf = os.path.splitext(self.outputs[0])[-1]
        return suf not in {'.a', '.lib'}

    def get_link_deps_mapping(self, prefix: str) -> T.Mapping[str, str]:
        return {}

    def get_link_dep_subdirs(self) -> T.AbstractSet[str]:
        return OrderedSet()

    def get_all_link_deps(self):
        return []

    def is_internal(self) -> bool:
        '''
        Returns True if this is a not installed static library.
        '''
        if len(self.outputs) != 1:
            return False
        return CustomTargetIndex(self, self.outputs[0]).is_internal()

    def extract_all_objects(self) -> T.List[T.Union[str, 'ExtractedObjects']]:
        return self.get_outputs()

    def type_suffix(self):
        return "@cus"

    def __getitem__(self, index: int) -> 'CustomTargetIndex':
        return CustomTargetIndex(self, self.outputs[index])

    def __setitem__(self, index, value):
        raise NotImplementedError

    def __delitem__(self, index):
        raise NotImplementedError

    def __iter__(self):
        for i in self.outputs:
            yield CustomTargetIndex(self, i)

    def __len__(self) -> int:
        return len(self.outputs)

class CompileTarget(BuildTarget):
    '''
    Target that only compile sources without linking them together.
    It can be used as preprocessor, or transpiler.
    '''

    typename = 'compile'

    def __init__(self,
                 name: str,
                 subdir: str,
                 subproject: str,
                 environment: environment.Environment,
                 sources: T.List['SourceOutputs'],
                 output_templ: str,
                 compiler: Compiler,
                 backend: Backend,
                 compile_args: T.List[str],
                 include_directories: T.List[IncludeDirs],
                 dependencies: T.List[dependencies.Dependency],
                 depends: T.List[T.Union[BuildTarget, CustomTarget, CustomTargetIndex]],
                 build_only_subproject: bool):
        compilers = {compiler.get_language(): compiler}
        kwargs = {
            'build_by_default': False,
            'language_args': {compiler.language: compile_args},
            'include_directories': include_directories,
            'dependencies': dependencies,
        }
        super().__init__(name, subdir, subproject, compiler.for_machine,
                         sources, None, [], environment, compilers,
                         build_only_subproject, kwargs)
        self.filename = name
        self.compiler = compiler
        self.output_templ = output_templ
        self.outputs = []
        self.sources_map: T.Dict[File, str] = {}
        self.depends = list(depends or [])
        for f in self.sources:
            self._add_output(f)
        for gensrc in self.generated:
            for s in gensrc.get_outputs():
                rel_src = backend.get_target_generated_dir(self, gensrc, s)
                self._add_output(File.from_built_relative(rel_src))

    def type_suffix(self) -> str:
        return "@compile"

    @property
    def is_unity(self) -> bool:
        return False

    def _add_output(self, f: File) -> None:
        plainname = os.path.basename(f.fname)
        basename = os.path.splitext(plainname)[0]
        o = self.output_templ.replace('@BASENAME@', basename).replace('@PLAINNAME@', plainname)
        self.outputs.append(o)
        self.sources_map[f] = o

    def get_generated_headers(self) -> T.List[File]:
        gen_headers: T.List[File] = []
        for dep in self.depends:
            gen_headers += [File(True, dep.subdir, o) for o in dep.get_outputs()]
        return gen_headers

class RunTarget(Target, CommandBase):

    typename
```