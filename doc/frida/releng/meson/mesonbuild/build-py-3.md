Response:
The user wants to understand the functionality of the Python code provided, which seems to be part of the build system for the Frida dynamic instrumentation tool. The request has several specific requirements:

1. **List Functionality:** Describe what the code does.
2. **Relevance to Reverse Engineering:**  Identify connections to reverse engineering techniques.
3. **Low-Level Details:** Point out any involvement with binary, Linux, Android kernel/framework concepts.
4. **Logical Inference:** Provide examples of input and output based on logical deductions within the code.
5. **Common Usage Errors:** Illustrate potential mistakes users might make when using this code.
6. **User Journey:** Explain how a user might interact with Frida to eventually execute this code.
7. **Summary of Functionality:**  A concluding summary of the code's purpose.
8. **Part of a Series:** Acknowledge that this is part 4 of a 5-part series.

**Mental Sandbox:**

* **High-Level Understanding:** The code defines various classes related to building software components (libraries, executables, custom targets) using the Meson build system. It seems to manage the different stages and configurations involved in creating these components.
* **Reverse Engineering Link:**  Frida is a reverse engineering tool, so the code likely deals with generating the necessary binaries and libraries that Frida uses for instrumentation. The concept of shared libraries and their versioning is directly relevant.
* **Low-Level Aspects:** The code mentions platform-specific details (Windows DLLs, Linux SOs, macOS DYLIBs), linking, and potentially the structure of executables and libraries. The handling of import libraries on Windows is a low-level detail.
* **Logical Inference:** We can analyze the `process_kwargs` methods of different classes to infer how input parameters affect the output file names and linking behavior.
* **User Errors:**  Misconfiguring library names, providing incompatible arguments (e.g., both `rust_abi` and `rust_crate_type`), or incorrect versioning could be common errors.
* **User Journey:** A user would likely interact with Frida through its command-line interface or Python API, which would then trigger the build system (Meson) to compile and link the necessary Frida components, eventually leading to the execution of this `build.py` script.
* **Summary:** The core function is to define how different types of build targets are created and managed within the Frida project using Meson.

**Constraint Checklist & Confidence Score:**

1. List functionality: Yes
2. Reverse engineering link: Yes
3. Low-level details: Yes
4. Logical inference: Yes
5. Common usage errors: Yes
6. User journey: Yes
7. Summary: Yes
8. Part of a series: Yes

Confidence Score: 5/5 - I am confident I can address all aspects of the request.

**Plan of Action:**

1. **Summarize the Purpose:** Start with a high-level description of the file's role in the Frida build process.
2. **Break Down Classes:** Describe the function of each major class (`Executable`, `StaticLibrary`, `SharedLibrary`, `CustomTarget`, etc.).
3. **Connect to Reverse Engineering:** Explain how the concepts of shared libraries and custom targets relate to Frida's instrumentation capabilities.
4. **Highlight Low-Level Details:** Point out examples of platform-specific filename handling, versioning, and the concept of import libraries. Mention the Rust ABI and crate type considerations.
5. **Illustrate Logical Inference:**  Provide an example of how setting the `soversion` for a shared library affects its output filename on Linux and macOS.
6. **Demonstrate User Errors:** Give examples of incorrect argument combinations when defining build targets.
7. **Describe the User Journey:** Explain the steps a user takes when using Frida that lead to the execution of this build script.
8. **Provide a Concise Summary:**  Reiterate the main function of the script.

Planning complete. Proceeding with response generation.
这是 `frida/releng/meson/mesonbuild/build.py` 文件的第四部分，该文件是 Frida 动态 Instrumentation 工具的源代码。从代码片段来看，它主要定义了各种用于描述构建目标的类，这些构建目标是使用 Meson 构建系统构建 Frida 的基本单元。

**文件功能归纳 (第 4 部分):**

本部分代码主要定义了以下用于描述不同类型构建目标的 Python 类：

* **`StaticLibrary`**: 表示静态链接库。
* **`SharedLibrary`**: 表示动态链接库（共享库）。
* **`SharedModule`**:  表示用于 `dlopen` 而不是链接到其他程序的共享模块。
* **`BothLibraries`**: 表示同时构建静态库和动态库。
* **`CommandBase`**:  一个基类，用于处理命令执行中的依赖关系和参数扁平化。
* **`CustomTargetBase`**: 自定义目标基类，提供一些默认方法。
* **`CustomTarget`**: 表示一个自定义构建目标，允许执行任意命令来生成输出文件。
* **`CompileTarget`**: 表示只编译源文件但不进行链接的目标。
* **`RunTarget`**:  （尽管代码片段未完整展示 `RunTarget`，但可以推断它用于定义执行特定命令的目标，可能用于测试或其他构建后任务）。

**与逆向方法的关系及举例:**

Frida 是一个用于动态分析和逆向工程的工具，而这些构建目标直接关系到 Frida 本身的构建过程。

* **`SharedLibrary` (动态链接库):** Frida 本身很可能包含多个动态链接库，这些库会被注入到目标进程中以实现 Instrumentation。例如，Frida 的 Agent 通常以动态链接库的形式存在。
    * **举例:**  Frida 的 Agent 可以被构建为一个 `SharedLibrary`，其源代码包含了用于 Hook 函数、修改内存等逆向操作的代码。Meson 会根据 `SharedLibrary` 类的定义，生成构建这个 Agent 动态库所需的 Makefile 或 Ninja 文件。

* **`CustomTarget` (自定义构建目标):**  在 Frida 的构建过程中，可能需要执行一些特定的脚本或工具来生成代码、处理资源文件或执行其他构建相关的任务。`CustomTarget` 允许定义这些自定义步骤。
    * **举例:**  可能有一个 `CustomTarget` 用于将一些 JavaScript 代码打包成 Frida Agent 可以加载的格式。这个自定义目标可能会执行一个 Node.js 脚本来完成打包工作。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

这些类的设计和实现反映了对底层构建流程和不同操作系统特性的理解。

* **二进制底层:**
    * **静态库 (`StaticLibrary`) 和动态库 (`SharedLibrary`)**:  这些概念本身就涉及到二进制文件的链接方式。静态库的代码会被直接链接到最终的可执行文件中，而动态库则在运行时加载。
    * **导入库 (`import_filename` in `SharedLibrary`)**: 在 Windows 上，动态链接库通常有一个对应的导入库（.lib 文件），链接器在链接时使用它来解析符号。`SharedLibrary` 类中对 `import_filename` 的处理体现了对 Windows PE 格式的理解。
    * **符号版本控制 (`soversion`, `ltversion`, `darwin_versions` in `SharedLibrary`)**:  动态库的版本控制是避免库冲突的重要机制。`SharedLibrary` 类中的这些属性用于处理 Linux、macOS 等平台上的动态库版本命名约定。

* **Linux:**
    * **`.so` 后缀 (`SharedLibrary`)**:  Linux 上动态链接库的常用后缀是 `.so`。
    * **`get_aliases()` in `SharedLibrary`**:  在 Linux 上，为了向后兼容，通常会创建一些符号链接（aliases）指向特定版本的动态库。`get_aliases()` 方法就是用于生成这些链接的。

* **Android 内核及框架:**
    * **`.so` 后缀 (`SharedLibrary` on Android)**: Android 上动态链接库的后缀也是 `.so`。
    * **`SharedLibrary` 中对 `soversion` 的处理**: 代码中提到 Android 不支持共享库的版本控制，这反映了 Android 构建系统的一些特点。

**逻辑推理及假设输入与输出:**

* **假设输入 (对于 `SharedLibrary`):**
    ```python
    SharedLibrary(
        name='myfridalib',
        subdir='src',
        subproject=...,
        for_machine=...,
        sources=[...],
        structured_sources=None,
        objects=[...],
        environment=...,
        compilers=...,
        build_only_subproject=False,
        kwargs={'soversion': '1', 'version': '1.2.3'}
    )
    ```
* **逻辑推理:** `SharedLibrary` 的 `process_kwargs` 方法会解析 `soversion` 和 `version`。如果提供了 `version`，并且 `soversion` 未提供，则 `soversion` 会从 `version` 的第一个数字提取出来。
* **预期输出 (在 Linux 上):** `determine_filenames()` 方法会根据 `soversion` 生成文件名，例如 `libmyfridalib.so.1`。`get_aliases()` 方法可能会生成 `libmyfridalib.so` 指向 `libmyfridalib.so.1` 的别名。

* **假设输入 (对于 `CustomTarget`):**
    ```python
    CustomTarget(
        name='generate_agent_code',
        subdir='build-scripts',
        subproject=...,
        environment=...,
        command=['python', 'generate_agent.py', '@OUTPUT@'],
        sources=['agent_template.js'],
        outputs=['frida-agent.js']
    )
    ```
* **逻辑推理:**  `CustomTarget` 定义了一个执行 Python 脚本 `generate_agent.py` 的命令，该脚本以 `agent_template.js` 为输入，并生成 `frida-agent.js`。`@OUTPUT@` 是 Meson 提供的占位符，会被替换为输出文件名。
* **预期输出:** Meson 会生成相应的构建规则，执行 `python generate_agent.py frida-agent.js` 命令。

**涉及用户或编程常见的使用错误及举例:**

* **`StaticLibrary` 中的错误:**
    * **同时使用 `rust_abi` 和 `rust_crate_type`:** 代码会抛出 `InvalidArguments` 异常。
    * **Rust crate 类型为 `rlib` 时，库名包含 `-`, ` `, `.`:**  由于 `rustc` 的限制，会导致错误，代码会给出提示。

* **`SharedLibrary` 中的错误:**
    * **同时使用 `rust_abi` 和 `rust_crate_type`:**  与静态库类似。
    * **指定了 `version` 或 `soversion` 给 `SharedModule`:** 代码会抛出 `MesonException`，因为共享模块通常不需要版本控制。

* **`CustomTarget` 中的错误:**
    * **`depfile` 定义了，但 `command` 中没有输入文件:**  如果 `depfile` 中使用了 `@BASENAME@` 或 `@PLAINNAME@` 占位符，但 `CustomTarget` 没有输入文件，则会抛出 `InvalidArguments`。
    * **`command` 中使用了找不到的外部程序:** 如果 `programs.ExternalProgram` 的实例在 `command` 中，但该程序在系统中找不到，则会抛出 `InvalidArguments`。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户尝试构建 Frida:** 用户通常会从 Frida 的源代码仓库克隆代码，然后使用 Meson 进行配置和构建，例如：
   ```bash
   git clone https://github.com/frida/frida.git
   cd frida
   meson setup build
   cd build
   ninja
   ```
2. **Meson 解析 `meson.build` 文件:** 当用户执行 `meson setup build` 时，Meson 会读取项目根目录下的 `meson.build` 文件以及子目录中的 `meson.build` 文件。这些文件中定义了如何构建 Frida 的各个组件，包括可执行文件、库、自定义目标等。
3. **遇到构建目标定义:**  在解析 `meson.build` 文件时，Meson 会遇到类似 `shared_library()`, `static_library()`, `custom_target()` 等函数调用，这些函数会创建 `SharedLibrary`, `StaticLibrary`, `CustomTarget` 等类的实例。
4. **`build.py` 文件的作用:** Meson 内部会使用 `mesonbuild/build.py` 文件中的类来表示和管理这些构建目标。当需要处理特定的构建目标时，Meson 会调用这些类的方法，例如 `determine_filenames()` 来确定输出文件名，或者 `get_command()` 来获取执行的命令。
5. **调试线索:** 如果构建过程中出现与特定库或自定义目标相关的问题，例如文件名错误、依赖缺失、命令执行失败等，开发人员可能会查看 `build.py` 文件中相应类的定义和逻辑，以理解 Meson 是如何处理这些构建目标的，并找到问题的原因。例如，如果一个动态库的版本号没有正确生成，可以检查 `SharedLibrary` 类的 `process_kwargs` 和 `determine_filenames` 方法。

**总结 (第 4 部分):**

`frida/releng/meson/mesonbuild/build.py` 文件的这部分代码定义了 Meson 构建系统中用于描述各种构建目标的关键类，包括静态库、动态库、共享模块和自定义目标。这些类包含了构建目标所需的属性和方法，例如文件名、依赖关系、编译选项、安装路径等。它们抽象了底层的构建细节，使得 Frida 的构建过程能够跨平台且易于管理。 这些类的设计也体现了对操作系统底层特性、二进制文件格式以及逆向工程相关概念的理解。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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