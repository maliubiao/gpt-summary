Response:
The user is asking for a summary of the functionality of the provided Python code snippet. This is the fourth part of a five-part series, so the summary should focus on the code present in this specific segment. I need to identify the classes and their methods, and infer their purpose within the context of a build system, specifically for dynamic instrumentation (as indicated by "frida").

Here's a breakdown of the code and its apparent functions:

1. **`Executable` Class:** Represents an executable file.
    *   `__init__`: Initializes the executable with name, subdirectory, subproject, machine type, sources, structured sources, objects, environment, compilers, build-only flag, and keyword arguments.
    *   `post_init`: Performs post-initialization tasks.
    *   `get`: Returns whether the executable is "linkwithable".
    *   `get_command`: Returns the output path(s) of the executable (for compatibility with `ExternalProgram`).
    *   `get_path`: Returns the full path to the executable.
    *   `found`: Indicates if the executable is found (always `True` in this context).

2. **`StaticLibrary` Class:** Represents a static library.
    *   `known_kwargs`: Defines supported keyword arguments.
    *   `__init__`: Initializes the static library, including handling `prelink`.
    *   `post_init`: Handles post-initialization, including checks for C# support and handling Rust library specifics (name restrictions, linking with native static libs). It also sets the default prefix and suffix for the library name.
    *   `get_link_deps_mapping`: Returns an empty dictionary (likely overridden in subclasses).
    *   `get_default_install_dir`: Returns the default installation directory for static libraries.
    *   `type_suffix`: Returns a suffix for the target type.
    *   `process_kwargs`: Processes keyword arguments, particularly for Rust-specific options (`rust_abi`, `rust_crate_type`).
    *   `is_linkable_target`: Indicates if it's a linkable target.
    *   `is_internal`: Checks if the library is not meant for installation.

3. **`SharedLibrary` Class:** Represents a shared library.
    *   `known_kwargs`: Defines supported keyword arguments.
    *   `__init__`: Initializes the shared library, including attributes for versioning (`soversion`, `ltversion`, `darwin_versions`), module definitions (`vs_module_defs`), import filename, debug filename, and a flag for shared library only.
    *   `post_init`: Handles post-initialization, including checks for Rust library name restrictions and setting default prefix and suffix.
    *   `get_link_deps_mapping`:  Returns a mapping of old to new install names for linking dependencies, particularly for macOS dylibs.
    *   `get_default_install_dir`: Returns the default installation directory for shared libraries.
    *   `determine_filenames`: Determines the filename, import filename, and debug filename based on the platform and specified versions. This is a complex method handling different naming conventions across operating systems (Windows, Cygwin, macOS, Linux, Android).
    *   `process_kwargs`: Processes keyword arguments, including versioning, Visual Studio module definitions, and Rust-specific options.
    *   `get_import_filename`: Returns the name of the import library (if any).
    *   `get_debug_filename`: Returns the name of the debug information file (if any).
    *   `get_all_link_deps`: Returns a list containing the library itself and its transitive link dependencies.
    *   `get_aliases`: Generates aliases for versioned shared libraries (e.g., `libfoo.so` pointing to `libfoo.so.1`).
    *   `type_suffix`: Returns a suffix for the target type.
    *   `is_linkable_target`: Indicates if it's a linkable target.

4. **`SharedModule` Class:** Represents a shared module (intended for `dlopen`).
    *   `known_kwargs`: Defines supported keyword arguments.
    *   `__init__`: Initializes the shared module, raising errors if versioning kwargs are provided.
    *   `get_default_install_dir`: Returns the default installation directory for shared modules.

5. **`BothLibraries` Class:**  Represents a situation where both a shared and static version of a library are built.
    *   `__init__`: Initializes with the shared and static library objects.
    *   `__repr__`:  Provides a string representation.
    *   `get_default_object`: Returns the preferred library (either shared or static).

6. **`CommandBase` Class:**  Provides a base for classes that execute commands.
    *   `flatten_command`: Takes a command as a sequence of strings, files, programs, or build targets and resolves them into a flat list of strings, files, and build targets, while also populating `depend_files` and `dependencies`.

7. **`CustomTargetBase` Class:**  Provides a base class for `CustomTarget` and `CustomTargetIndex`.
    *   Contains dummy implementations for methods related to dependency recursion and internal static libraries.

8. **`CustomTarget` Class:** Represents a custom build target defined by a user-specified command.
    *   `__init__`: Initializes the custom target with its name, subdirectory, subproject, environment, command, sources, outputs, and various other options like installation, dependencies, and environment variables.
    *   `get_default_install_dir`: Returns `None` (custom targets often specify their install location).
    *   `__repr__`: Provides a string representation.
    *   `get_target_dependencies`: Returns a list of immediate dependencies.
    *   `get_transitive_build_target_deps`: Recursively finds build targets this custom target depends on.
    *   `get_dependencies`: Returns the direct dependencies.
    *   `should_install`: Indicates if the target should be installed.
    *   `get_custom_install_dir`: Returns the custom install directory.
    *   `get_custom_install_mode`: Returns the custom install mode.
    *   `get_outputs`: Returns the output filenames.
    *   `get_filename`: Returns the first output filename.
    *   `get_sources`: Returns the source files.
    *   `get_generated_lists`: Returns generated lists from the sources.
    *   `get_generated_sources`: Alias for `get_generated_lists`.
    *   `get_dep_outname`:  Generates the dependency file output name based on the `depfile` template.
    *   `is_linkable_output`: Checks if an output file is likely a linkable artifact.
    *   `is_linkable_target`: Checks if the custom target produces a single linkable output.
    *   `links_dynamically`: Guesses if the output is dynamically linked based on the file extension.
    *   `get_link_deps_mapping`: Returns an empty dictionary (likely overridden).
    *   `get_link_dep_subdirs`: Returns an empty set.
    *   `get_all_link_deps`: Returns an empty list.
    *   `is_internal`: Checks if the target is a non-installed static library.
    *   `extract_all_objects`: Returns the outputs.
    *   `type_suffix`: Returns a suffix for the target type.
    *   `__getitem__`, `__setitem__`, `__delitem__`, `__iter__`, `__len__`: Implement sequence-like behavior for accessing outputs via `CustomTargetIndex`.

9. **`CompileTarget` Class:** Represents a target that compiles sources but does not link them.
    *   `__init__`: Initializes the compile target with its name, subdirectory, subproject, environment, sources, output template, compiler, backend, compile arguments, include directories, dependencies, and depends.
    *   `type_suffix`: Returns a suffix for the target type.
    *   `is_unity`: Indicates if it's a unity build (always `False` here).
    *   `_add_output`: Adds an output based on the output template and source filename.
    *   `get_generated_headers`: Returns generated headers from dependencies.

**Overall Functionality:**

This code defines various types of build targets within the Meson build system. It provides abstractions for:

*   **Executables:** Representing compiled applications.
*   **Static Libraries:** Collections of compiled object code linked together.
*   **Shared Libraries:** Dynamically linked libraries that can be loaded at runtime.
*   **Shared Modules:** Similar to shared libraries but specifically intended for dynamic loading (e.g., plugins).
*   **Custom Targets:** Allowing users to define arbitrary build steps using shell commands.
*   **Compile Targets:**  For compilation without linking, useful for pre-processing or code generation.

The code manages target properties like:

*   **Sources:** Input files for the build process.
*   **Outputs:** Files generated by the build process.
*   **Dependencies:** Other build targets or external libraries required.
*   **Installation:** Whether the target should be installed and where.
*   **Versioning:**  For shared libraries, managing version information.
*   **Platform-specific naming conventions:**  Handling differences in how libraries are named on different operating systems.

The `CommandBase` class facilitates the execution of commands associated with custom targets by flattening command arguments and tracking dependencies.

The structure suggests a component within a larger build system responsible for defining and managing different types of build artifacts. The naming conventions and features (like versioning for shared libraries) are typical of build systems.
这是 `frida/subprojects/frida-node/releng/meson/mesonbuild/build.py` 文件的一部分，它定义了 Meson 构建系统中各种类型的构建目标（Build Targets）。以下是它的功能归纳：

**主要功能：定义和管理不同类型的构建目标**

这个代码片段的核心功能是定义了多种 Meson 构建系统中可以存在的构建目标类型，例如：

*   **Executable (可执行文件):**  表示最终的可执行程序。
*   **StaticLibrary (静态库):** 表示静态链接库。
*   **SharedLibrary (共享库):** 表示动态链接库。
*   **SharedModule (共享模块):**  表示用于运行时动态加载的共享库（例如插件）。
*   **BothLibraries (同时构建静态库和共享库):**  表示同时构建一个库的静态和共享版本。
*   **CustomTarget (自定义目标):**  允许用户定义任意的构建命令。
*   **CompileTarget (编译目标):**  表示只编译源文件而不进行链接的目标。

**每个构建目标类都包含了以下信息和功能：**

*   **类型名称 (`typename`)**:  用于标识构建目标的类型。
*   **已知关键字参数 (`known_kwargs`)**:  定义了创建该类型目标时可以使用的关键字参数。
*   **初始化方法 (`__init__`)**:  用于初始化构建目标实例，接收名称、源文件、依赖、编译器等信息。
*   **后初始化方法 (`post_init`)**:  在初始化之后执行一些额外的处理，例如设置默认的文件名前缀和后缀。
*   **获取命令 (`get_command`)**:  对于 `Executable`，返回执行该程序的命令。
*   **获取路径 (`get_path`)**:  对于 `Executable`，返回可执行文件的路径。
*   **是否找到 (`found`)**:  对于 `Executable`，表示该文件是否找到（这里始终返回 `True`）。
*   **获取链接依赖映射 (`get_link_deps_mapping`)**:  用于获取链接依赖项的路径映射关系，主要用于共享库。
*   **获取默认安装目录 (`get_default_install_dir`)**:  定义了该类型目标在安装时的默认目录。
*   **类型后缀 (`type_suffix`)**:  返回一个表示目标类型的后缀字符串。
*   **处理关键字参数 (`process_kwargs`)**:  处理创建目标时传入的关键字参数，例如版本信息、Rust 相关配置等。
*   **是否可链接目标 (`is_linkable_target`)**:  判断该目标是否可以被链接到其他目标。
*   **是否内部目标 (`is_internal`)**:  判断该目标是否是仅在内部构建而不进行安装的。
*   **确定文件名 (`determine_filenames`)**:  对于 `SharedLibrary`，根据平台和版本信息确定最终的文件名、导入库文件名等。
*   **获取导入库文件名 (`get_import_filename`)**:  对于 `SharedLibrary`，获取 Windows 平台上的导入库文件名。
*   **获取调试文件名 (`get_debug_filename`)**:  对于 `SharedLibrary`，获取调试信息文件名。
*   **获取所有链接依赖 (`get_all_link_deps`)**:  返回该目标的所有链接依赖。
*   **获取别名 (`get_aliases`)**:  对于 `SharedLibrary`，生成版本化的共享库的别名。
*   **获取目标依赖 (`get_target_dependencies`)**:  对于 `CustomTarget`，获取目标的直接依赖项。
*   **获取传递的构建目标依赖 (`get_transitive_build_target_deps`)**:  对于 `CustomTarget`，递归获取所有依赖的构建目标。
*   **是否应该安装 (`should_install`)**:  对于 `CustomTarget`，判断该目标是否应该被安装。
*   **获取自定义安装目录 (`get_custom_install_dir`)**:  对于 `CustomTarget`，获取自定义的安装目录。
*   **获取输出 (`get_outputs`)**:  获取构建目标生成的所有输出文件。
*   **获取源文件 (`get_sources`)**:  获取构建目标的源文件。
*   **获取依赖输出名称 (`get_dep_outname`)**:  对于 `CustomTarget`，根据模板生成依赖文件的输出名称。
*   **是否动态链接 (`links_dynamically`)**:  对于 `CustomTarget`，判断输出是否是动态链接的。
*   **提取所有对象 (`extract_all_objects`)**:  对于 `CustomTarget`，返回所有输出。
*   **添加输出 (`_add_output`)**:  对于 `CompileTarget`，添加输出文件。
*   **获取生成的头文件 (`get_generated_headers`)**:  对于 `CompileTarget`，获取依赖项生成的头文件。

**与其他逆向方法的关系：**

这些构建目标类型与逆向工程的方法息息相关，因为逆向工程经常需要分析和操作二进制文件、库和可执行程序。

*   **Executable:** 逆向工程师分析的目标通常是可执行文件，例如使用反汇编器（IDA Pro, Ghidra）或调试器（GDB, LLDB）来理解其代码逻辑。
*   **StaticLibrary 和 SharedLibrary:**  逆向工程师需要了解程序使用的库，分析其提供的功能，寻找漏洞或理解程序行为。共享库的动态加载机制也是逆向分析的一个重要方面。
*   **SharedModule:**  对插件或模块的逆向分析可以揭示其功能和与其他主程序的交互方式。Frida 本身就经常被用来注入和分析正在运行的进程，包括加载的共享模块。
*   **CustomTarget:** 虽然 `CustomTarget` 本身不直接代表逆向方法，但它可以被用来定义构建过程中与逆向相关的工具，例如，可以使用 `CustomTarget` 来运行一个脚本，该脚本会对某个二进制文件进行预处理或分析。

**举例说明与逆向的关系：**

假设一个逆向工程师想要分析一个使用了自定义加密算法的程序。

1. **可执行文件 (Executable):** 逆向工程师会首先分析主程序的 `Executable` 文件，寻找入口点和关键函数。
2. **共享库 (SharedLibrary):** 加密算法可能被封装在一个独立的共享库中。逆向工程师需要分析这个 `SharedLibrary` 来理解加密的具体实现。他们可能会使用 Frida 来 hook 这个库中的加密函数，观察输入输出。
3. **自定义目标 (CustomTarget):**  在 Frida 的构建过程中，可能使用 `CustomTarget` 来运行一个脚本，该脚本会提取共享库中的符号信息，方便后续的 hook 操作。或者，一个逆向工程师可以使用 `CustomTarget` 在构建过程中集成一个静态分析工具来检查代码中的潜在漏洞。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

*   **二进制底层:** 这些构建目标最终都会生成二进制文件（可执行文件、库文件）。理解 ELF (Linux) 或 Mach-O (macOS) 等二进制文件格式对于逆向工程至关重要。
*   **Linux 内核:**  共享库的加载和链接机制是 Linux 内核的一部分。理解动态链接器（`ld-linux.so`）的工作原理对于分析程序依赖和 hook 技术非常重要。
*   **Android 内核及框架:** 在 Android 平台上，共享库通常是 `.so` 文件。理解 Android 的 Bionic Libc 和 ART 虚拟机对于逆向 Android 应用和 Native 代码至关重要。Frida 也经常被用于分析 Android 平台上的应用。

**举例说明涉及到的知识：**

*   **`SharedLibrary` 的 `determine_filenames` 方法:**  这个方法需要根据不同的操作系统（Linux, macOS, Windows, Android）来确定共享库的文件名格式（例如 Linux 的 `libfoo.so.1`, macOS 的 `libfoo.1.dylib`, Windows 的 `foo.dll`）。这直接涉及到不同操作系统下二进制文件的命名约定和动态链接机制。
*   **`SharedLibrary` 的 `get_aliases` 方法:**  在 Linux 上，为了实现版本控制，共享库会有多个文件名别名。例如，`libfoo.so` 可能指向 `libfoo.so.1`，而 `libfoo.so.1` 又指向 `libfoo.so.1.2.3`。理解这些别名对于理解库的依赖关系和运行时加载非常重要。
*   **`SharedModule` 的应用场景:**  在 Android 上，应用程序经常会加载 Native 的共享模块来实现特定的功能。使用 Frida 可以 attach 到 Android 进程并 hook 这些模块中的函数。

**逻辑推理、假设输入与输出：**

以 `StaticLibrary` 的 `process_kwargs` 方法为例：

**假设输入:**

```python
kwargs = {'rust_crate_type': 'rlib'}
```

**逻辑推理:**

该方法会检查 `kwargs` 中是否存在 `rust_crate_type`。如果存在，则会根据其值设置 `self.rust_crate_type`。在这个例子中，`rust_crate_type` 是 `rlib`，所以 `self.rust_crate_type` 将被设置为 `rlib`。

**输出:**

`self.rust_crate_type` 的值为 `'rlib'`。

**用户或编程常见的使用错误：**

*   **在 `SharedModule` 中指定版本信息:** `SharedModule` 类在初始化时会检查是否指定了 `version` 或 `soversion` 关键字参数。这是因为共享模块通常不进行版本控制，错误地指定版本信息会导致 `MesonException`。
    *   **错误示例:**  在 `meson.build` 文件中定义 `shared_module` 时：
        ```python
        shared_module('my_module', 'module.c', version='1.0')
        ```
    *   **错误提示:**  `MesonException('Shared modules must not specify the version kwarg.')`

*   **在 `StaticLibrary` 中使用 C#:**  `StaticLibrary` 的 `post_init` 方法会检查是否存在 C# 编译器。静态库通常不用于 C#，如果尝试创建 C# 的静态库会抛出 `InvalidArguments` 异常。
    *   **错误示例:** 在 `meson.build` 文件中定义 `static_library` 时，源文件是 C# 文件。
    *   **错误提示:** `InvalidArguments('Static libraries not supported for C#.')`

*   **`CustomTarget` 中 `depfile` 路径不正确:** 如果在 `CustomTarget` 中使用了 `depfile` 并且路径不正确，会导致构建系统无法正确跟踪依赖关系。

**用户操作是如何一步步到达这里的，作为调试线索：**

1. **编写 `meson.build` 文件:** 用户首先会编写 `meson.build` 文件来描述他们的项目结构和构建规则。在这个文件中，他们会使用 `executable()`, `static_library()`, `shared_library()`, `shared_module()` 或 `custom_target()` 等函数来定义不同类型的构建目标。
2. **运行 `meson` 命令:** 用户在项目根目录下运行 `meson <builddir>` 命令来配置构建系统。Meson 会解析 `meson.build` 文件，并根据其中的定义创建相应的构建目标对象。
3. **Meson 解析 `meson.build`:**  当 Meson 解析到定义构建目标的函数时，例如 `shared_library('mylib', 'mylib.c')`，它会在 `mesonbuild/build.py` 文件中找到 `SharedLibrary` 类，并创建一个 `SharedLibrary` 的实例。
4. **调用初始化方法:**  创建实例时，会调用 `SharedLibrary` 的 `__init__` 方法，传入名称、源文件等信息。
5. **调用后初始化方法:**  接着会调用 `post_init` 方法执行额外的初始化操作，例如设置默认文件名。
6. **运行 `ninja` 或其他后端命令:** 用户运行 `ninja` (或其他配置的后端工具) 命令来执行实际的构建过程。
7. **构建系统使用构建目标信息:** Ninja 会读取 Meson 生成的构建信息，这些信息包含了各个构建目标的属性和构建规则。例如，对于一个 `SharedLibrary` 目标，Ninja 会知道它的源文件、依赖库、输出路径等。

**调试线索:** 如果在构建过程中遇到与特定构建目标类型相关的问题，例如链接错误或找不到共享库，可以查看 `mesonbuild/build.py` 中对应类的定义，了解其属性和处理逻辑，从而更好地理解构建系统的行为。例如，如果共享库的版本信息配置错误，可以查看 `SharedLibrary` 的 `process_kwargs` 和 `determine_filenames` 方法。

**归纳一下它的功能（第 4 部分）：**

这部分代码主要负责定义 Meson 构建系统中各种不同类型的构建目标，包括可执行文件、静态库、共享库、共享模块、同时构建的库、自定义目标和编译目标。每个构建目标类都封装了该类型目标的属性、行为和构建规则，并处理了平台相关的细节（例如共享库的命名约定）。这些类是 Meson 构建系统核心组件，用于抽象和管理构建过程中的各种产物。这些定义使得 Meson 能够理解用户的构建意图，并生成相应的构建指令，最终完成项目的编译和链接。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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