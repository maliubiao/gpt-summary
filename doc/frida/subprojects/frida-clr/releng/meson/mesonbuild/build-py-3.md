Response:
The user is asking for a summary of the functionality of a Python file that is part of the Frida dynamic instrumentation tool. The file seems to define classes representing different types of build targets in a build system (likely Meson, based on the file path).

To provide a comprehensive answer, I need to:

1. **Identify the main classes:** Extract the key classes defined in the code and their purpose.
2. **Explain their functionalities:**  Describe what each class does in the context of a build system.
3. **Relate to reverse engineering:** Connect the functionalities to common tasks in reverse engineering where applicable.
4. **Link to low-level concepts:** Identify any connections to binary format, OS kernels, or frameworks.
5. **Analyze logic and assumptions:** If any logic is present (like input processing), provide examples.
6. **Consider user errors:** Think about common mistakes a user might make when interacting with these build definitions.
7. **Explain how a user reaches this code:** Outline the user actions that would trigger the execution of this Python script.
8. **Provide a concise summary:** Condense the information into a brief overview of the file's purpose.

**Breakdown of the Classes and their functionalities:**

* **`Executable`:** Represents an executable program.
    *  Stores information about the executable's name, location, and outputs.
    *  Provides compatibility methods with `ExternalProgram`.
* **`StaticLibrary`:** Represents a static library.
    *  Handles naming conventions for static libraries across different platforms (e.g., `libfoo.a` on Linux/Windows).
    *  Deals with Rust-specific naming and dependency considerations.
    *  Defines the default installation directory for static libraries.
* **`SharedLibrary`:** Represents a shared library (dynamically linked library).
    *  Manages versioning information (soversion, ltversion, Darwin versions).
    *  Handles naming conventions for shared libraries on various platforms (Linux, Windows, macOS).
    *  Deals with import libraries (Windows) and debug symbols.
    *  Generates aliases for versioned shared libraries.
    *  Defines the default installation directory for shared libraries.
* **`SharedModule`:** Represents a shared module (typically loaded with `dlopen`).
    *  Similar to `SharedLibrary` but specifically for modules not directly linked.
    *  Does not support versioning.
    *  Defines the default installation directory for shared modules.
* **`BothLibraries`:**  A container for both static and shared versions of the same library.
    *  Allows selection of the preferred library type.
* **`CommandBase`:**  Provides functionality for processing command-line arguments, including handling files, external programs, and build targets.
    *  Flattens a command into a list of strings and dependencies.
* **`CustomTargetBase`:** A base class for custom build targets.
* **`CustomTarget`:** Represents a user-defined build step with a custom command.
    *  Allows arbitrary commands to be executed as part of the build process.
    *  Handles dependencies and outputs.
    *  Supports installation and custom installation directories.
* **`CompileTarget`:** Represents a build target that only compiles sources without linking.
    *  Useful for pre-processing or transpilation.
* **`RunTarget`:** (Class definition is incomplete in the provided snippet, but it likely represents a target that executes a program.)

**Connecting to Reverse Engineering, Low-Level Concepts, and Logic:**

* **Reverse Engineering:**
    * `SharedLibrary` and `Executable` are directly relevant as they represent the output artifacts often analyzed in reverse engineering. The versioning information in `SharedLibrary` can be crucial for understanding compatibility and updates.
    * `CustomTarget` can be used to define custom steps in a build process that involve reverse engineering tools (e.g., disassemblers, decompilers).
    * The handling of import libraries in `SharedLibrary` is important for understanding Windows DLL dependencies.
* **Binary/Low-Level:**
    * The filename suffixes (`.so`, `.dll`, `.a`, `.dylib`) and prefixes (`lib`) directly relate to binary formats and OS conventions for libraries.
    * The discussion of import libraries on Windows and sonames on Linux touches upon linker behavior and how shared libraries are loaded at runtime.
* **Linux/Android Kernel & Framework:**
    * The specific handling of `.so` files and versioning relates to Linux shared library conventions.
    * The `SharedModule` class is pertinent to how modules are loaded dynamically in Linux.
    * The special handling of Android shared libraries shows awareness of Android's specific build system.
* **Logic and Assumptions:**
    * The `flatten_command` function in `CommandBase` demonstrates logic for handling different types of command arguments. **Hypothetical Input:** `command=['gcc', 'source.c', target]` where `target` is a `BuildTarget` instance. **Hypothetical Output:** `['gcc', 'source.c', 'output_filename_of_target']`, and the `target` is added to the `dependencies` list.
    * The naming logic in `StaticLibrary` and `SharedLibrary` makes assumptions about standard library naming conventions on different platforms.

**User Errors and How to Reach the Code:**

* **User Errors:**
    * Incorrectly specifying `rust_abi` and `rust_crate_type` together in `StaticLibrary` or `SharedLibrary`.
    * Using spaces, periods, or dashes in Rust crate names when the crate type doesn't allow it.
    * Specifying `version` or `soversion` for a `SharedModule`.
    * Incorrectly using placeholders like `@BASENAME@` in `depfile` for a `CustomTarget` without input files.
* **User Journey:**
    1. A developer working on the Frida project modifies a build definition in a `meson.build` file.
    2. This `meson.build` file uses functions like `executable()`, `static_library()`, `shared_library()`, or `custom_target()` to define build targets.
    3. Meson parses these `meson.build` files.
    4. During the parsing and processing of these build definitions, Meson instantiates the classes defined in `build.py` (like `Executable`, `StaticLibrary`, `SharedLibrary`, `CustomTarget`) to represent the defined targets.
    5. This specific file, `frida/subprojects/frida-clr/releng/meson/mesonbuild/build.py`, is being executed by Meson as it processes the build definitions related to the Frida CLR subproject.

**Summary of Functionality (Part 4):**

This part of `build.py` in the Frida project defines several classes that represent different types of build targets within the Meson build system. These classes encapsulate the specific characteristics and build procedures for executables, static libraries, shared libraries, and custom build steps. They handle platform-specific naming conventions, versioning, dependencies, and installation procedures. This code is crucial for translating the high-level build definitions in `meson.build` files into the actual steps required to compile and link the Frida CLR components.

这是 Frida 动态 instrumentation 工具源代码文件 `frida/subprojects/frida-clr/releng/meson/mesonbuild/build.py` 的一部分，主要定义了多种构建目标（Build Target）的类，用于描述如何构建软件的不同组件。以下是其功能的归纳：

**核心功能：定义和管理不同类型的构建目标**

这个文件主要负责定义了多种用于表示软件构建过程中的不同目标的 Python 类。这些类继承自更基础的 `Target` 类（可能在其他文件中定义），并添加了特定于各种构建目标类型的属性和方法。

以下是各个类的主要功能：

1. **`Executable(BuildTarget)`**:  表示一个可执行文件。
    * 存储可执行文件的名称、子目录和输出路径。
    * 提供了与 `ExternalProgram` 兼容的方法，可能用于处理依赖的外部程序。
    * `get_command()` 方法返回用于执行该可执行文件的命令（这与逆向分析中运行目标程序进行动态分析有关）。
    * `get_path()` 方法返回可执行文件的路径。

2. **`StaticLibrary(BuildTarget)`**: 表示一个静态库。
    * 处理静态库的命名约定，例如在 Windows 上通常是 `libfoo.a`。
    * 针对 Rust 语言的静态库，会处理其特定的命名约定和依赖关系。例如，会检查 `rust_crate_type` 并根据其值设置文件名后缀。
    * `get_default_install_dir()` 方法定义了静态库的默认安装目录。
    *  **与逆向的关系举例**: 在逆向工程中，静态库可能包含一些算法或者数据结构实现，逆向分析师需要提取和理解这些代码。`StaticLibrary` 类的定义确保了这些库在构建时被正确命名和处理。

3. **`SharedLibrary(BuildTarget)`**: 表示一个共享库（动态链接库）。
    * 处理共享库的版本信息（`soversion`, `ltversion`, `darwin_versions`），这对于库的兼容性非常重要。
    * 根据不同的操作系统（Windows, Linux, macOS）设置不同的文件名约定和后缀（`.dll`, `.so`, `.dylib`）。
    * 处理 Windows 上的导入库 (`import_filename`) 和调试符号文件 (`debug_filename`)。
    * `get_link_deps_mapping()` 方法用于获取链接依赖的映射关系，这对于理解库的依赖关系至关重要。
    * `get_default_install_dir()` 方法定义了共享库的默认安装目录。
    * `get_aliases()` 方法生成共享库的别名，例如 `libfoo.so` 指向 `libfoo.so.1`，这在 Linux 系统中很常见。
    * **与逆向的关系举例**: 共享库是逆向分析的常见目标。逆向分析师需要理解库的导出函数、依赖关系以及内部实现。`SharedLibrary` 类的定义确保了这些库在构建时被正确命名、版本化和链接。

4. **`SharedModule(SharedLibrary)`**: 表示一个共享模块，通常用于 `dlopen` 等动态加载机制。
    * 与 `SharedLibrary` 类似，但通常不进行版本控制。
    * `get_default_install_dir()` 方法定义了共享模块的默认安装目录。
    * **涉及二进制底层、Linux 内核及框架的知识**:  `SharedModule` 的概念直接关联到 Linux 等操作系统中动态加载模块的机制，这涉及到操作系统底层的加载器和链接器。

5. **`BothLibraries(SecondLevelHolder)`**: 表示同时构建静态库和共享库的情况。
    * 允许指定首选的库类型（静态或共享）。

6. **`CommandBase`**: 提供处理命令的基础功能。
    * `flatten_command()` 方法将命令列表中的字符串、文件、外部程序和构建目标展开成一个扁平的列表，并跟踪依赖的文件和目标。
    * **逻辑推理**: 假设输入 `command=['gcc', 'source.c', my_executable]`，其中 `my_executable` 是一个 `Executable` 实例。`flatten_command` 的输出将是 `['gcc', 'source.c', 'path/to/my_executable']`，并且 `my_executable` 会被添加到 `self.dependencies` 列表中。

7. **`CustomTargetBase`**:  作为 `CustomTarget` 和 `CustomTargetIndex` 的基类，提供一些共享的功能。

8. **`CustomTarget(Target, CustomTargetBase, CommandBase)`**: 表示一个自定义的构建目标，允许用户执行任意命令。
    * `command` 属性定义了要执行的命令。
    * `sources` 属性定义了命令的输入。
    * `outputs` 属性定义了命令的输出。
    * `get_target_dependencies()` 方法获取当前自定义目标的依赖项。
    * `get_transitive_build_target_deps()` 方法递归获取所有依赖的构建目标，这在需要设置环境变量（例如 `PATH`）来运行自定义命令时非常有用。
    * `get_dep_outname()` 方法用于获取依赖文件 (`depfile`) 的名称，支持基于输入文件名的替换。
    * **与逆向的关系举例**:  可以使用 `CustomTarget` 来定义执行反汇编器、脱壳工具或自定义脚本的构建步骤。
    * **涉及用户或编程常见的使用错误**: 如果 `depfile` 中使用了 `@BASENAME@` 或 `@PLAINNAME@` 占位符，但 `CustomTarget` 没有输入文件，会导致错误。
    * **用户操作是如何一步步的到达这里，作为调试线索**: 用户在 `meson.build` 文件中定义了一个 `custom_target()`，当 Meson 处理这个 `meson.build` 文件时，会创建 `CustomTarget` 的实例。如果构建过程中 `custom_target()` 定义的命令执行失败，调试时就需要查看 `CustomTarget` 实例的 `command`、`sources` 和 `outputs` 属性，以确定问题所在。

9. **`CompileTarget(BuildTarget)`**: 表示一个只编译源文件但不进行链接的构建目标。
    * `compiler` 属性指定使用的编译器。
    * `output_templ` 属性定义了编译输出文件的模板。
    * `_add_output()` 方法根据源文件名和模板生成输出文件名。
    * **与逆向的关系举例**:  在逆向过程中，可能需要单独编译某些代码片段以便进行更深入的分析。`CompileTarget` 能够实现这种需求。

**总结一下它的功能 (第 4 部分)**:

这部分 `build.py` 文件的主要功能是定义了用于描述软件构建过程中各种目标的 Python 类。这些类封装了不同类型构建目标（如可执行文件、静态库、共享库、自定义目标等）的特定属性和行为，包括命名约定、版本管理、依赖关系处理以及安装路径配置。这些定义是 Meson 构建系统理解和执行构建指令的关键组成部分，并直接关联到软件构建的底层细节，例如二进制文件的命名和链接方式。对于 Frida 这样的工具，正确定义和管理这些构建目标是成功构建和部署其各个组件的基础。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
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
"""


```