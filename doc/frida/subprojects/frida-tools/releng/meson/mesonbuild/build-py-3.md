Response:
My goal is to analyze the Python code provided and extract its functionalities, relating them to reverse engineering, low-level concepts, and potential user errors. Here's a breakdown of my thought process:

1. **Understand the Request:** The core request is to describe the functionality of the given Python code snippet, which appears to be part of the Meson build system used by Frida. I need to identify what the code does, how it relates to reverse engineering concepts, low-level details, and common user errors. The request specifically mentions this is part 4 of 5, hinting at a larger context.

2. **Initial Scan and Class Identification:** I'll start by scanning the code for class definitions. This will give me a high-level overview of the different components being defined. The main classes I see are:
    * `Executable`
    * `StaticLibrary`
    * `SharedLibrary`
    * `SharedModule`
    * `BothLibraries`
    * `CommandBase`
    * `CustomTargetBase`
    * `CustomTarget`
    * `CompileTarget`
    * `RunTarget`

3. **Focus on Key Classes:**  Based on the class names, I can infer their general purpose within a build system. `Executable`, `StaticLibrary`, and `SharedLibrary` are clearly about building different types of software artifacts. `CustomTarget` provides flexibility for arbitrary build steps. `CompileTarget` is specifically for compilation without linking. `RunTarget` is likely for defining targets that execute commands.

4. **Analyze Individual Class Functionality:** I will now go through each class and its methods, trying to understand its specific role.

    * **`Executable`:**  Represents an executable file. The methods suggest it handles output paths, checking if it can be linked against, and compatibility with `ExternalProgram`.

    * **`StaticLibrary`:** Focuses on building static libraries. The code handles naming conventions (prefix, suffix), Rust-specific details (crate types), and potential naming conflicts. The `get_default_install_dir` and `type_suffix` methods are related to how and where the library is installed and identified.

    * **`SharedLibrary`:** Deals with shared libraries (DLLs, SOs, DYLIBs). It's more complex, handling versioning (`soversion`, `ltversion`, `darwin_versions`), import libraries (`import_filename`), debug symbols (`debug_filename`), and platform-specific naming conventions. The `determine_filenames` method is crucial for understanding how the output filenames are generated. `get_aliases` is interesting as it shows how symbolic links are created for versioned shared libraries.

    * **`SharedModule`:** Seems to be a specialized form of `SharedLibrary` intended for `dlopen` (dynamic loading) scenarios, explicitly disallowing versioning.

    * **`BothLibraries`:** Represents a scenario where both a static and shared library might be built for the same component, allowing the build system to choose the appropriate one.

    * **`CommandBase`:** Provides a helper function `flatten_command` to process command lists, resolving files, external programs, and build targets. This is crucial for `CustomTarget`.

    * **`CustomTargetBase`:**  A base class for `CustomTarget` and `CustomTargetIndex`, likely for shared functionality.

    * **`CustomTarget`:** Offers a generic way to define custom build steps. It takes a command to execute, input sources, and defines the output. It handles dependencies, installation, and output naming. The methods like `get_target_dependencies`, `get_transitive_build_target_deps`, and the `__getitem__` and iterator methods are important for understanding how custom targets interact with the rest of the build system.

    * **`CompileTarget`:**  Specialized for compiling sources without linking. It manages output filenames based on a template and tracks dependencies.

    * **`RunTarget`:** (Incomplete) This likely defines targets that execute commands after building.

5. **Relating to Reverse Engineering:** Now I'll consider how these classes relate to reverse engineering.

    * **`SharedLibrary` and `SharedModule`:** These are directly relevant as reverse engineers often analyze and interact with shared libraries (e.g., hooking functions). Understanding versioning and naming conventions is crucial. The mention of import libraries on Windows is also important.

    * **`StaticLibrary`:** While not directly loaded at runtime like shared libraries, static libraries can be part of the final executable, and their contents might be analyzed.

    * **`CustomTarget`:**  This is powerful. Reverse engineering build processes might involve custom steps (e.g., disassembling, running analysis tools) which could be defined using `CustomTarget`.

6. **Identifying Low-Level Concepts:**

    * **Binary Layout:** The handling of prefixes, suffixes, and versioning in `StaticLibrary` and `SharedLibrary` directly relates to the binary layout and naming conventions on different operating systems (Linux `.so`, macOS `.dylib`, Windows `.dll`).

    * **Linking:** The concepts of static vs. dynamic linking, import libraries, and sonames are fundamental to understanding how executables and libraries are combined.

    * **Operating System Differences:** The code explicitly handles platform-specific naming conventions for libraries (Windows, macOS, Linux, Android, Cygwin).

    * **Kernel/Framework Knowledge:** While not explicitly manipulating kernel structures here, the output of these build processes (libraries, executables) directly interacts with the OS kernel and frameworks (e.g., Android's framework for `.so` libraries).

7. **Logical Reasoning (Assumptions and Outputs):**

    * **`StaticLibrary` and Rust:** If `rust_crate_type` is `rlib` and the name contains '-', ' ', or '.', it raises an error. This assumes the Rust compiler has this limitation.

    * **`SharedLibrary` and Versioning:** If `soversion` is provided on macOS, the filename will include the major version. This assumes the macOS dynamic linker uses this convention.

8. **Common User Errors:**

    * **`StaticLibrary` and C#:** Trying to build a C# static library will raise an error, assuming C# doesn't support this directly.

    * **`StaticLibrary` and Rust Naming:** Using invalid characters in Rust `rlib` names will cause an error.

    * **`SharedModule` and Versioning:** Attempting to specify `version` or `soversion` for a `SharedModule` will raise an error.

    * **`CustomTarget` and `depfile`:**  Incorrect use of `@BASENAME@` or `@PLAINNAME@` in `depfile` without input files will cause an error.

9. **User Path to this Code (Debugging Clues):** A user would typically reach this code by defining build targets (libraries, executables, custom targets) in their `meson.build` file. If a build fails, and the error message points to issues within the library or custom target definitions (e.g., invalid naming, versioning conflicts), a developer might need to examine this `build.py` code to understand how Meson is processing their build instructions. The stack trace during a build error would lead a developer here.

10. **Summarize Functionality (Part 4 of 5):** This part of the `build.py` file in Frida's Meson setup defines the core building blocks for creating different types of software components: executables and various kinds of libraries (static, shared, and loadable modules). It encapsulates the logic for handling platform-specific naming conventions, versioning, dependencies, and custom build steps. It acts as an abstraction layer over the underlying compilers and linkers, providing a consistent way to define and build software components regardless of the target platform. It lays the groundwork for the higher-level build orchestration that will likely be covered in other parts.

By following these steps, I can systematically analyze the code and generate a comprehensive explanation that addresses all the points in the request.
这是 `frida/subprojects/frida-tools/releng/meson/mesonbuild/build.py` 文件的源代码片段，它定义了 Frida 项目中用于构建不同类型目标（targets）的 Python 类。这些类是 Meson 构建系统用来描述如何编译和链接源代码的蓝图。

以下是该代码片段中定义的主要类及其功能：

**核心构建目标类:**

* **`Executable(BuildTarget)`:**  代表一个可执行文件。
    * **功能:** 定义如何构建一个可执行程序，包括源文件、链接的库等。
    * **与逆向的关系:**  Frida 本身是一个动态插桩工具，其核心就是与目标进程的可执行文件进行交互。这个类定义了 Frida 工具自身的可执行文件是如何构建的。
    * **二进制底层知识:**  涉及链接器、程序入口点、操作系统加载可执行文件的机制。
    * **Linux/Android 内核/框架知识:**  在 Linux 和 Android 上，涉及 ELF 文件格式、动态链接器 (ld-linux.so, linker64 等)、系统调用接口等。
    * **假设输入与输出:** 假设输入是 C/C++ 源文件列表、链接的库列表。输出是一个平台特定的可执行文件（如 Linux 上的 ELF 文件，Windows 上的 PE 文件）。
    * **用户错误:**  常见的用户错误是在 `meson.build` 文件中错误地指定了源文件路径或链接的库，导致编译或链接失败。
    * **调试线索:** 用户在构建 Frida 工具时，如果构建可执行文件时出现问题，错误信息会指向这个类相关的构建步骤。

* **`StaticLibrary(BuildTarget)`:** 代表一个静态库（例如 `.a` 文件）。
    * **功能:** 定义如何构建一个静态库，多个目标可以链接到这个库。
    * **与逆向的关系:** 静态库经常被逆向工程师分析以了解其功能，或者在开发 Frida 插件时链接。
    * **二进制底层知识:**  涉及目标代码的归档格式。
    * **Linux/Android 内核/框架知识:**  在 Linux 上，涉及 `.a` 文件的格式和 `ar` 工具的使用。
    * **假设输入与输出:** 假设输入是 C/C++ 源文件列表。输出是一个静态库文件。
    * **用户错误:**  常见的用户错误是在 `meson.build` 文件中尝试为不支持的语言（如 C#）创建静态库。
    * **调试线索:** 用户在构建依赖静态库的目标时遇到问题，可能会追溯到静态库的构建过程。

* **`SharedLibrary(BuildTarget)`:** 代表一个共享库（例如 `.so`，`.dll`，`.dylib` 文件）。
    * **功能:** 定义如何构建一个共享库，可以在运行时被多个程序加载。
    * **与逆向的关系:**  共享库是 Frida 插桩的主要目标。逆向工程师需要理解共享库的加载、符号解析等机制。Frida Agent 通常就是一个共享库。
    * **二进制底层知识:**  涉及动态链接、符号表、重定位、平台特定的共享库格式（ELF, PE, Mach-O）。
    * **Linux/Android 内核/框架知识:**  在 Linux/Android 上，涉及 `dlopen`, `dlsym` 等系统调用，以及 Android 的 ART 运行时加载共享库的机制。
    * **假设输入与输出:** 假设输入是 C/C++ 源文件列表，可能的版本信息。输出是一个平台特定的共享库文件，可能带有版本号。
    * **用户错误:**  常见的用户错误包括版本号设置不正确、依赖的共享库找不到等。
    * **调试线索:** Frida 工具或 Agent 在运行时加载共享库失败，或者符号找不到，可能与这个类的定义有关。

* **`SharedModule(SharedLibrary)`:**  代表一个共享模块，通常用于 `dlopen` 等动态加载场景。
    * **功能:**  与 `SharedLibrary` 类似，但通常不进行链接，主要用于运行时加载。
    * **与逆向的关系:**  Frida 可以加载任意的共享模块到目标进程中。
    * **二进制底层知识:**  与 `SharedLibrary` 类似。
    * **Linux/Android 内核/框架知识:**  与 `SharedLibrary` 类似。
    * **假设输入与输出:**  与 `SharedLibrary` 类似，但不包含版本信息。
    * **用户错误:**  尝试为共享模块指定版本号会导致错误。
    * **调试线索:**  用户尝试用 Frida 加载一个模块失败，可能与模块的构建方式有关。

* **`BothLibraries(SecondLevelHolder)`:**  表示同时构建静态库和共享库的情况。
    * **功能:** 允许构建系统根据需要选择链接静态库或共享库。
    * **与逆向的关系:**  某些情况下，开发者可能提供静态库和共享库两种选择。
    * **假设输入与输出:**  输入是构建静态库和共享库所需的源文件和其他配置。输出是对应的静态库和共享库文件。

**其他辅助类:**

* **`CommandBase`:** 提供处理命令行的通用功能，例如展开包含文件、程序和构建目标的命令。
* **`CustomTargetBase`:**  自定义构建目标的基类。
* **`CustomTarget(Target, CustomTargetBase, CommandBase)`:** 代表一个自定义的构建目标，允许执行任意命令。
    * **功能:**  可以执行任何指定的命令来生成输出文件。
    * **与逆向的关系:**  在 Frida 的构建过程中，可能需要执行一些自定义的脚本或工具，例如生成代码、处理文件等。
    * **假设输入与输出:**  输入是需要执行的命令、依赖的文件。输出是执行命令后生成的文件。
    * **用户错误:**  自定义命令错误、依赖文件路径不正确等。
    * **调试线索:**  自定义构建步骤失败，错误信息会包含执行的命令和相关的输出。

* **`CompileTarget(BuildTarget)`:**  代表一个只进行编译但不链接的目标。
    * **功能:**  用于预处理、编译但不生成最终的可执行文件或库。
    * **与逆向的关系:**  可能用于生成中间代码或者进行静态分析。
    * **假设输入与输出:**  输入是源文件和编译参数。输出是编译后的目标文件（`.o` 等）。

* **`RunTarget(Target, CommandBase)`:** (代码片段未完整展示)  通常代表一个需要执行的命令或脚本作为构建过程的一部分。

**功能归纳 (作为第 4 部分):**

这个代码片段的主要功能是 **定义了 Frida 项目中各种构建目标的结构和属性，包括可执行文件、静态库、共享库和自定义构建步骤。** 它抽象了构建过程中的关键概念，并提供了用于配置这些目标的 Python 类。这些类允许 Meson 构建系统理解如何根据给定的源文件、依赖项和其他参数来生成最终的二进制文件。

**与逆向方法的关系举例:**

* **`SharedLibrary`:**  Frida Agent 本身就是一个共享库。逆向工程师使用 Frida 来加载 Agent 到目标进程，并利用 Agent 提供的功能进行内存读取、函数 Hook 等操作。这个类定义了 Frida Agent 的构建方式，包括其输出文件名、版本信息等，这些对于理解和使用 Frida 非常重要。例如，`determine_filenames` 方法展示了共享库在不同平台上的命名规则，这有助于逆向工程师在目标系统上找到 Frida Agent 文件。
* **`CustomTarget`:** 在 Frida 的构建过程中，可能需要使用 `CustomTarget` 来执行一些预处理脚本，例如从 IDL 文件生成代码，或者生成特定的配置文件。逆向工程师可能需要分析这些自定义构建步骤，以了解 Frida 的内部工作原理或如何扩展 Frida 的功能。

**涉及二进制底层、Linux、Android 内核及框架的知识举例:**

* **`SharedLibrary` 的 `determine_filenames` 方法:**  该方法根据目标操作系统（Windows, Linux, macOS, Android）设置共享库的前缀（`lib`）、后缀（`.so`, `.dll`, `.dylib`）以及版本号的命名规则。这直接涉及到不同操作系统下二进制文件的底层格式和加载机制。例如，在 Linux 上，共享库可能包含 `soversion` 和 `ltversion`，而在 Android 上则没有。
* **`StaticLibrary` 中处理 Rust crate 类型:**  代码中检查了 Rust 静态库的 crate 类型（`rlib`, `staticlib`）以及名称是否包含非法字符。这涉及到 Rust 语言的底层库构建机制。
* **`SharedLibrary` 中处理 Windows 的 import library:**  在 Windows 上，链接器需要一个 `.lib` 导入库来链接到 DLL。`SharedLibrary` 类中处理了 `import_filename` 的生成，这反映了 Windows PE 文件格式和动态链接的特定需求。

**逻辑推理的假设输入与输出举例:**

* **`StaticLibrary` 和 Rust crate 命名:**
    * **假设输入:** `name = "my-rust-crate"`, `rust_crate_type = "rlib"`
    * **输出:**  会抛出 `InvalidArguments` 异常，因为 `rlib` 类型的 Rust crate 名称不允许包含短横线 `-`。
* **`SharedLibrary` 和 macOS 版本号:**
    * **假设输入:** `name = "mylib"`, `soversion = "1"` (在 macOS 上构建)
    * **输出:** `filename` 将被设置为 `libmylib.1.dylib`，符合 macOS 的 dylib 命名约定。

**涉及用户或编程常见的使用错误举例:**

* **`StaticLibrary` 不支持 C#:**  用户尝试使用 `meson.build` 为 C# 代码创建静态库会触发 `InvalidArguments` 异常。
* **`SharedModule` 指定版本号:** 用户尝试为 `SharedModule` 设置 `version` 或 `soversion` 关键字参数会导致 `MesonException`。
* **`CustomTarget` 的 `depfile` 路径错误:** 用户在 `CustomTarget` 中使用 `@BASENAME@` 或 `@PLAINNAME@` 占位符，但没有提供输入源文件，会导致 `InvalidArguments` 异常。

**用户操作如何一步步的到达这里 (作为调试线索):**

1. 用户编写 `meson.build` 文件来描述项目的构建方式。
2. 用户在 `meson.build` 文件中使用了 `executable()`, `static_library()`, `shared_library()`, `shared_module()`, 或 `custom_target()` 等函数来定义构建目标。
3. 用户运行 `meson setup builddir` 来配置构建环境。
4. 用户运行 `ninja -C builddir` 或类似的命令来实际执行构建。
5. 如果构建过程中出现与定义目标相关的问题（例如，库的命名不符合规范，依赖项找不到，自定义命令执行失败），Meson 会调用 `build.py` 中相应的类的逻辑。
6. 如果出现异常或错误，Meson 的错误信息可能会指向这个 `build.py` 文件以及相关的类和方法，帮助用户定位问题。例如，如果用户错误地命名了一个 Rust 静态库，错误信息可能会指出 `StaticLibrary` 类的 `post_init` 方法中抛出了 `InvalidArguments` 异常。

**功能归纳 (第 4 部分):**

总而言之，`frida/subprojects/frida-tools/releng/meson/mesonbuild/build.py` 的这个代码片段是 Frida 项目构建系统的核心组成部分，负责定义各种构建目标的类型、属性和构建方式。它深入涉及到二进制文件的底层结构、不同操作系统的构建约定以及编程语言的特定构建需求。理解这些类的功能对于理解 Frida 的构建过程、进行问题排查以及进行定制化开发至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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