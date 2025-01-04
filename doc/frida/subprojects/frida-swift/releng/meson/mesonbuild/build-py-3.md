Response:
The user wants a summary of the Python code provided. I need to identify the main classes and their functionalities. I should also look for connections to reverse engineering, binary manipulation, OS-level details, and potential usage errors. Finally, I need to describe how a user might reach this code during a debugging session.

**Plan:**

1. Identify the key classes: `Executable`, `StaticLibrary`, `SharedLibrary`, `SharedModule`, `BothLibraries`, `CustomTarget`, `CompileTarget`, and `RunTarget`.
2. For each class, summarize its purpose and main methods.
3. Analyze each class for connections to:
    *   Reverse engineering (e.g., manipulation of binary files, dynamic analysis)
    *   Binary/low-level operations
    *   Linux/Android kernel and framework
    *   Logic or reasoning
    *   Common user errors
4. Explain how a user might interact with this code through the Frida toolchain.
这是 `frida/subprojects/frida-swift/releng/meson/mesonbuild/build.py` 文件的第四部分，主要定义了 Meson 构建系统中用于描述不同类型的构建目标（targets）的类。以下是对这部分代码功能的归纳：

**功能归纳：**

这部分代码主要定义了以下构建目标类型：

1. **`StaticLibrary(BuildTarget)`**: 表示静态链接库。
2. **`SharedLibrary(BuildTarget)`**: 表示共享链接库。
3. **`SharedModule(SharedLibrary)`**: 表示共享模块，通常用于动态加载（如 `dlopen`）。
4. **`BothLibraries(SecondLevelHolder)`**: 用于表示同时构建静态库和共享库的情况。
5. **`CustomTarget(Target, CustomTargetBase, CommandBase)`**: 表示用户自定义的构建目标，可以通过任意命令来生成输出。
6. **`CompileTarget(BuildTarget)`**: 表示仅编译源文件而不进行链接的构建目标。
7. **`RunTarget(Target, CommandBase)`**: (虽然这部分代码没有完整包含 `RunTarget` 的定义，但从类名和继承关系可以推断出) 表示执行特定命令的构建目标。

这些类都继承自 `BuildTarget` 或其子类，并扩展了特定的属性和方法，用于描述不同类型构建目标的特性，例如：

*   **输出文件名和路径**: 如何命名和定位生成的库文件。
*   **依赖关系**:  与其他构建目标或外部库的依赖关系。
*   **安装规则**:  如何以及安装到哪里。
*   **编译和链接选项**:  特定于库类型的编译和链接参数。
*   **版本信息**:  共享库的版本控制信息 (soversion, ltversion, darwin\_versions)。

**与逆向方法的关系及举例说明：**

这些类本身是构建系统的一部分，并不直接执行逆向操作。但是，它们定义了如何构建用于逆向工程的工具和库。

*   **`SharedLibrary`**: Frida 自身就是一个动态链接库，它的核心功能需要被注入到目标进程中。`SharedLibrary` 类定义了如何构建 Frida 的共享库文件（例如 `.so` 或 `.dylib`）。
    *   **例子**: Frida 的核心库 `frida-core.so` 就是通过 `SharedLibrary` 类定义的规则构建出来的。逆向工程师使用 Frida 时，会将这个库注入到目标进程。
*   **`StaticLibrary`**: 一些 Frida 的组件可能会被编译成静态库，然后链接到其他模块中。
    *   **例子**: 一些用于处理特定架构的低级代码可能会被编译成静态库。
*   **`CustomTarget`**: 用户可以使用 `CustomTarget` 定义一些预处理或后处理步骤，这些步骤可能涉及到二进制文件的操作。
    *   **例子**: 可以使用 `CustomTarget` 定义一个脚本，用于从编译好的共享库中提取特定的元数据，这在 Frida 的开发过程中可能会用到。

**涉及二进制底层，Linux, Android内核及框架的知识及举例说明：**

*   **二进制底层**:
    *   `StaticLibrary` 和 `SharedLibrary` 的构建涉及到链接器如何将目标文件组合成库文件，这直接关系到二进制文件的布局和符号解析。
    *   `SharedLibrary` 中关于 `soversion` 和 `ltversion` 的处理是 Linux 共享库版本控制的标准，这直接影响到二进制文件的命名和加载。
    *   针对 Windows 平台，`SharedLibrary` 类处理了 import library (`.lib`) 的生成，这是 Windows 下动态链接的机制。
*   **Linux**:
    *   `SharedLibrary` 类中对 `.so` 文件名的处理（`libfoo.so.X.Y.Z`）以及别名 (aliases) 的生成是 Linux 共享库的标准做法。
    *   `SharedModule` 专门用于构建可以通过 `dlopen` 加载的模块，这是 Linux 下动态加载库的机制。
*   **Android内核及框架**:
    *   `SharedLibrary` 类中针对 Android 平台的文件名处理（`libfoo.so`，不支持版本控制）反映了 Android 系统对共享库的特定处理方式。
    *   Frida 经常需要与 Android 框架进行交互，例如 hook Java 方法。构建 Frida 的 Android 组件会涉及到与 Android SDK 和 NDK 的交互。

**逻辑推理及假设输入与输出：**

*   **`SharedLibrary.determine_filenames()`**:  这个方法根据操作系统和用户配置（例如是否指定了 `soversion` 或 `ltversion`）来推断共享库的输出文件名。
    *   **假设输入**:  `name='mylib'`, `soversion='1'`, 运行在 Linux 系统上。
    *   **输出**: `self.filename` 将会是 `libmylib.so.1`，可能会生成别名 `libmylib.so` 指向 `libmylib.so.1`。
*   **`CustomTarget.flatten_command()`**: 这个方法将用户提供的命令列表展开，处理其中的不同类型的参数（字符串、文件、构建目标等），并提取依赖关系。
    *   **假设输入**: `command=['gcc', 'src.c', '-o', '$BUILD_DIR/output']`, 其中 `$BUILD_DIR` 是一个 Meson 预定义的变量。
    *   **输出**: `self.command` 将会是展开后的命令列表，例如 `['gcc', 'src.c', '-o', '/path/to/build/output']`，并且 `self.depend_files` 可能会包含 `src.c` 对应的 `File` 对象。

**用户或编程常见的使用错误及举例说明：**

*   **`StaticLibrary`**:
    *   **错误**: 在创建 Rust 静态库时，库名包含 `-`, ` `, `.` 等字符，并且 `rust_crate_type` 是 `rlib`。
    *   **原因**: Rust 的 `rlib` crate 类型有这个限制，会导致编译错误。Meson 会抛出 `InvalidArguments` 异常。
    *   **解决方法**:  将库名中的特殊字符替换为下划线。
*   **`SharedLibrary`**:
    *   **错误**:  在创建共享模块 (`SharedModule`) 时，尝试指定 `version` 或 `soversion` 参数。
    *   **原因**: 共享模块通常用于动态加载，不需要版本控制，指定版本信息会导致 `MesonException`。
    *   **解决方法**:  移除 `version` 或 `soversion` 参数。
*   **`CustomTarget`**:
    *   **错误**: 在 `depfile` 路径中使用 `@BASENAME@` 或 `@PLAINNAME@` 占位符，但 `custom_target` 没有输入文件 (`sources` 为空)。
    *   **原因**: 这些占位符需要在有输入文件的情况下才能被替换，否则会导致 `InvalidArguments` 异常。
    *   **解决方法**:  要么提供输入文件，要么修改 `depfile` 路径，移除这些占位符。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件**: 用户定义项目构建规则，包括要构建的静态库、共享库、自定义目标等。例如，使用 `static_library()`, `shared_library()`, `custom_target()` 等函数。
2. **用户运行 `meson` 命令**: Meson 工具读取 `meson.build` 文件，解析构建意图。在这个过程中，会创建这些类的实例来表示定义的构建目标。
3. **Meson 解析 `meson.build`**: 当 Meson 解析到 `static_library('mylib', sources=['a.c', 'b.c'])` 这样的语句时，会创建一个 `StaticLibrary` 类的实例，并将库名、源文件等信息传递给构造函数。
4. **构建系统生成构建文件**: Meson 根据创建的构建目标对象，生成底层的构建文件（例如 Ninja 构建文件）。
5. **用户运行 `ninja` 命令**: Ninja 工具读取构建文件，执行实际的编译和链接操作。
6. **调试线索**: 如果在构建过程中出现问题，例如链接错误或自定义命令执行失败，开发者可能需要查看 Meson 生成的构建文件，了解具体的编译和链接命令，以及目标文件的依赖关系。而这些信息最初来源于这些 Python 类中定义的规则和属性。

例如，如果在构建一个共享库时出现版本控制相关的问题，开发者可能会查看 `SharedLibrary` 类的 `determine_filenames()` 方法，理解 Meson 是如何生成共享库文件名的。如果自定义目标执行失败，开发者可能会查看 `CustomTarget` 类的 `flatten_command()` 方法，确认 Meson 传递给 shell 的命令是否正确。

总而言之，这部分代码是 Meson 构建系统的核心组成部分，它定义了各种构建目标的抽象表示，Meson 基于这些抽象表示来生成实际的构建指令。对于 Frida 这样的复杂项目，理解这些类的功能有助于理解其构建过程。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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