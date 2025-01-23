Response:
The user wants to understand the functionality of the Python code provided, specifically the `build.py` file within the Frida project related to Meson builds. I need to:

1. **List the functionalities** present in the code.
2. **Identify connections to reverse engineering**, providing examples.
3. **Point out interactions with binary, Linux/Android kernel/frameworks**, giving examples.
4. **Analyze logical reasoning** within the code and provide hypothetical input/output.
5. **Illustrate common user/programming errors** that the code aims to prevent.
6. **Explain the user steps** leading to the execution of this code.
7. **Summarize the overall purpose** of the code.

Based on the code, it seems to define classes and methods related to building software projects, handling dependencies, linking libraries, and generating build configurations using the Meson build system. It deals with different types of build targets like static libraries, shared libraries, executables, and custom targets. It also manages precompiled headers and code generation.

**Functionalities:**

* Handling linking of different types of build targets (static, shared, custom).
* Managing dependencies between build targets.
* Dealing with external libraries and their dependencies.
* Supporting linking with Rust code and handling Rust ABI.
* Managing precompiled headers.
* Handling include directories.
* Determining the appropriate linker based on the languages used.
* Checking for module linking issues.
* Processing Visual Studio module definition files.
* Generating files using external programs (generators).
* Defining executable build targets, including handling Windows-specific subsystems and import libraries.

**Reverse Engineering Relevance:**

The functionalities related to linking, dependencies, and handling different library types are directly relevant to reverse engineering. When analyzing a binary, understanding its dependencies, linked libraries, and how different modules interact is crucial.

* **Example:** Frida, being a dynamic instrumentation toolkit, often injects code into running processes. The code here ensures that when Frida's components are built, dependencies on libraries like `glib` or `v8` are correctly handled. A reverse engineer analyzing Frida would need to know these dependencies to understand how Frida interacts with the target process.

**Binary/Kernel/Framework Relevance:**

The code deals with binary-level concepts like linking (static vs. shared), handling different object file formats (e.g., PIC), and platform-specific build requirements (like Windows import libraries). It also touches upon operating system concepts when handling shared modules and their linking behavior on different platforms (Linux, Android, macOS).

* **Example (Binary):** The code checks if a non-PIC (Position Independent Code) static library is being linked into a shared library. This is a binary-level concern because shared libraries need to be loaded at arbitrary memory addresses, requiring their code to be position independent.
* **Example (Linux/Android):** The code mentions handling shared modules on Android and the need for specific linking order to avoid missing symbol errors when using `dlopen`. This relates directly to the dynamic linking mechanisms of the Linux and Android kernels and their respective user-space libraries.

**Logical Reasoning (Hypothetical Input/Output):**

Consider the `link_with` function.

* **Input:** A `SharedLibrary` target `A` and a `StaticLibrary` target `B` are passed to `A.link_with([B])`.
* **Logic:** The function checks if `B` is an external library. If not, it checks if `B` is linkable. If `A` is a `StaticLibrary` and `B` is internal, it calls `link_whole`. If `A` is a `SharedLibrary` and `B` is a non-PIC `StaticLibrary`, it raises an error. Otherwise, it appends `B` to `A`'s `link_targets`.
* **Output:** Depending on the types and properties of `A` and `B`, either an error is raised, `B` is added to `A`'s linking list, or `link_whole` is called.

**User/Programming Errors:**

* **Example:** The code explicitly checks if an external library is passed to the `link_with` keyword argument. This prevents users from incorrectly specifying external dependencies, which should be handled through the `dependencies` keyword. If a user tried `shared_library('mylib', sources, link_with: external_lib)`, it would raise an error, guiding the user to use `dependencies: external_lib` instead.
* **Example:** The code prevents linking a non-PIC static library into a shared library. This is a common mistake that would lead to runtime linking errors.

**User Steps to Reach Here (Debugging Clue):**

A developer using Frida and the Meson build system would interact with this code during the project configuration and build process.

1. **Developer writes a `meson.build` file:** This file describes the project's structure, targets, dependencies, and build rules.
2. **Developer uses Meson commands:**  Commands like `meson setup builddir` are used to configure the build. Meson parses the `meson.build` files.
3. **Meson executes build scripts:** During the configuration phase, Meson might execute Python scripts like `build.py` to process build target definitions and resolve dependencies.
4. **Error occurs during configuration:** If the developer makes a mistake in the `meson.build` file (e.g., incorrectly specifying dependencies), the Python code in `build.py` might raise an exception, halting the configuration process and providing an error message.

**Summary of Functionality:**

This Python code defines the build logic for Frida components using the Meson build system. It handles the intricacies of linking different types of libraries and executables, managing dependencies (both internal and external), supporting cross-language linking (like Rust), and enforcing platform-specific build requirements. It ensures that the build process is correct and prevents common errors related to linking and dependency management.

这是 Frida 动态Instrumentation 工具的构建系统中负责处理构建目标（Build Targets）定义和相互链接的 Python 代码文件。它主要负责定义各种构建目标（如库、可执行文件）的属性和行为，并处理它们之间的依赖关系和链接过程。

以下是其功能的详细列举和相关说明：

**功能列举：**

1. **定义和处理构建目标的链接行为 (`link_with`, `link_whole`)：**
   -  允许将其他构建目标链接到当前构建目标。
   -  区分内部构建目标和外部库，并强制使用 `dependencies` 参数来引入外部库，防止混淆。
   -  处理静态库和共享库之间的链接，特别是对于非 PIC（位置无关代码）的静态库链接到共享库的情况会报错。
   -  `link_whole` 用于将静态库的所有对象文件都链接进来，尤其是在静态库链接到另一个内部静态库时。

2. **管理内部静态库的依赖关系 (`get_internal_static_libraries`, `get_internal_static_libraries_recurse`)：**
   -  递归地获取一个构建目标所依赖的所有内部静态库。
   -  用于处理静态库的打包和链接，确保所有必要的对象文件都被包含进去。

3. **静态库对象文件的捆绑 (`_bundle_static_library`)：**
   -  将一个静态库的所有对象文件提取出来，添加到当前构建目标的对象列表中。
   -  对于 Rust 静态库或自定义目标，目前存在限制，可能无法直接提取对象文件，会抛出异常或使用其他机制处理。

4. **检查构建目标之间的链接兼容性 (`check_can_link_together`)：**
   -  检查尝试链接的两个构建目标是否兼容，例如，防止将 Rust ABI 库与非 Rust 目标链接。
   -  检查跨架构编译时尝试链接不同架构的库，并发出警告或错误。

5. **处理预编译头文件 (PCH) (`add_pch`)：**
   -  允许为构建目标指定预编译头文件，可以是一个头文件或者一个头文件和一个源文件。
   -  检查 PCH 文件的有效性，例如文件是否存在、类型是否正确等。

6. **管理包含目录 (`add_include_dirs`)：**
   -  允许为构建目标添加包含目录，可以指定是否为系统包含目录。

7. **确定链接器 (`get_clink_dynamic_linker_and_stdlibs`)：**
   -  根据构建目标使用的编程语言和依赖库的语言，选择合适的链接器。
   -  处理多种语言混合编译的情况，并选择优先级最高的链接器。
   -  考虑依赖库所使用的语言，确保链接时包含正确的标准库。

8. **获取使用的标准库参数 (`get_used_stdlib_args`)：**
   -  获取在链接过程中需要使用的标准库链接参数，例如当链接 C++ 代码时，需要链接 C++ 标准库。

9. **判断是否使用了特定语言 (`uses_rust`, `uses_rust_abi`, `uses_fortran`)：**
   -  方便地判断构建目标是否使用了特定的编程语言，例如 Rust 或 Fortran。

10. **判断是否使用 MSVC 链接器 (`get_using_msvc`)：**
    -  判断最终的链接器是否是 MSVC（或与其兼容的链接器），用于处理 Windows 平台特定的文件命名和调试信息生成。

11. **检查共享模块的链接 (`check_module_linking`)：**
    -  检查是否错误地将共享模块（shared_module）链接到其他目标。在某些平台上（如 macOS），这是不允许的，而在 Android 上需要特殊处理。

12. **处理 Visual Studio 模块定义文件 (`process_vs_module_defs_kw`)：**
    -  允许为构建目标指定 Visual Studio 的模块定义文件 (.def)。

13. **定义文件在目标私有目录的表示 (`FileInTargetPrivateDir`, `FileMaybeInTargetPrivateDir`)：**
    -  用于表示生成器生成的文件，这些文件可能位于构建目录的特定于目标的私有子目录中。

14. **定义代码生成器 (`Generator`)：**
    -  允许使用外部程序生成代码或其他文件。
    -  定义生成器的执行命令、输入输出、依赖关系等。

15. **表示生成器输出的文件列表 (`GeneratedList`)：**
    -  封装生成器生成的输出文件列表，并管理其依赖关系和路径信息。

16. **定义可执行文件构建目标 (`Executable`)：**
    -  继承自 `BuildTarget`，并添加了可执行文件特有的属性，例如 Windows 子系统 (`win_subsystem`)、导出动态符号 (`export_dynamic`)、导入库 (`implib`) 等。
    -  处理可执行文件的后缀名，根据操作系统和编译器类型进行设置。
    -  处理导入库和调试信息文件的命名。

**与逆向方法的关系：**

该文件与逆向方法密切相关，因为它定义了 Frida 工具自身的构建过程。理解 Frida 的构建方式有助于逆向工程师了解 Frida 的内部结构和工作原理。

* **举例说明：**
    - 当逆向工程师想要了解 Frida 是如何注入代码到目标进程时，理解 Frida 的哪些组件是静态链接的，哪些是动态链接的，可以帮助他们定位注入的关键代码。`link_with` 和 `link_whole` 等功能就直接影响了最终二进制文件的组成。
    -  如果逆向工程师需要修改 Frida 的某些行为，他们可能需要重新编译 Frida。理解 `meson.build` 文件以及 `build.py` 中定义的构建规则是至关重要的。
    -  `get_clink_dynamic_linker_and_stdlibs` 功能决定了 Frida 使用哪个链接器。不同的链接器在处理符号和库依赖方面可能有所不同，这对于理解 Frida 如何与目标进程的库交互非常重要。
    -  `check_module_linking` 中提到的共享模块链接问题，在逆向分析动态链接库时也需要考虑。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

代码中涉及了许多与二进制底层、Linux 和 Android 相关的概念：

* **二进制底层：**
    - **PIC (Position Independent Code)：** 代码中检查了将非 PIC 静态库链接到共享库的情况，因为共享库需要在运行时加载到任意内存地址，因此其代码必须是位置无关的。
    - **静态链接与动态链接：**  `link_with` 和 `link_whole` 区分了静态链接和动态链接的行为。静态链接将所有依赖库的代码都包含到最终的可执行文件中，而动态链接则在运行时加载依赖库。
    - **导入库 (`implib`)：** 在 Windows 平台上，当生成动态链接库时，会生成一个导入库，用于在编译时帮助链接器找到库的符号。
    - **调试信息文件 (`debug_filename`)：**  在编译时生成，用于在调试器中进行源码级别的调试。

* **Linux 内核及框架：**
    - **共享库 (`SharedLibrary`)：** Linux 系统中动态链接库的概念。
    - **动态链接器：** 代码中需要确定使用哪个动态链接器进行链接，这与 Linux 的动态链接机制有关。

* **Android 内核及框架：**
    - **共享模块 (`SharedModule`)：** Android 中用于插件化的动态链接库。代码中提到了 Android 平台对共享模块链接顺序的特殊要求，以避免 `dlopen` 时出现符号找不到的错误。这直接关系到 Android 的动态链接器和加载机制。

* **举例说明：**
    -  关于非 PIC 静态库链接到共享库的检查，体现了对共享库加载机制的理解。
    -  处理 Android 共享模块的链接顺序，直接反映了对 Android 系统动态链接器行为的了解。

**逻辑推理 (假设输入与输出)：**

假设有一个 `SharedLibrary` 目标 `mylib` 和一个 `StaticLibrary` 目标 `mystaticlib`，都在同一个 Meson 项目中。

* **假设输入：**
    ```python
    # meson.build
    mylib = shared_library('mylib', 'mylib.c')
    mystaticlib = static_library('mystaticlib', 'mystaticlib.c')
    executable('myexe', 'myexe.c', link_with: mylib, dependencies: mystaticlib)
    ```
* **逻辑推理：**
    - 在处理 `executable('myexe', ...)` 时，`link_with: mylib` 会调用 `link_with` 方法，由于 `mylib` 是项目内部的共享库，它将被添加到 `myexe` 的 `link_targets` 列表中。
    - `dependencies: mystaticlib` 会处理 `mystaticlib`，它会被添加到 `myexe` 的依赖列表中，链接器会确保在链接 `myexe` 时找到 `mystaticlib`。
* **预期输出：**
    - 构建系统会生成 `mylib` 的共享库文件，`mystaticlib` 的静态库文件，以及最终的可执行文件 `myexe`，该可执行文件在运行时会动态链接到 `mylib`，并在链接时包含了 `mystaticlib` 中的代码（取决于链接方式）。

**用户或者编程常见的使用错误：**

1. **将外部库错误地传递给 `link_with`：**
   - **错误示例：** `executable('myexe', 'myexe.c', link_with: find_library('external'))`
   - **错误说明：** `link_with` 应该用于链接项目内部构建的目标。外部库应该使用 `dependencies` 参数。
   - **代码处理：** 代码会抛出 `MesonException`，提示用户使用 `dependencies`。

2. **尝试将非 PIC 静态库链接到共享库：**
   - **错误示例：**  创建一个非 PIC 的静态库，并尝试将其链接到一个共享库。
   - **错误说明：** 共享库需要在运行时加载到任意地址，因此其依赖的代码也应该是位置无关的。
   - **代码处理：** 代码会抛出 `InvalidArguments` 异常，提示用户使用 `pic` 选项来构建静态库。

3. **在跨架构编译时尝试链接不兼容架构的库：**
   - **错误示例：** 在为 ARM 架构编译时，尝试链接一个为 x86 架构构建的库。
   - **错误说明：** 不同架构的二进制代码无法直接链接在一起。
   - **代码处理：** 代码会抛出 `InvalidArguments` 异常，并提示这是跨架构编译不允许的操作。

4. **错误地将共享模块链接到其他目标：**
   - **错误示例：** `executable('myexe', 'myexe.c', link_with: shared_module('mymodule', 'mymodule.c'))`
   - **错误说明：** 共享模块通常用于插件，不应该像普通共享库那样链接。
   - **代码处理：** 代码会发出警告或在某些平台上抛出异常，并建议使用 `shared_library`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件：** 用户根据项目需求，在 `meson.build` 文件中定义可执行文件、库以及它们之间的依赖关系和链接方式。这涉及到使用 `executable()`, `shared_library()`, `static_library()` 等 Meson 构建目标函数，并使用 `link_with`, `dependencies` 等关键字参数。
2. **用户运行 Meson 配置命令：** 用户在命令行执行 `meson setup <build_directory>` 来配置构建环境。Meson 会读取 `meson.build` 文件并执行其中的 Python 代码，包括 `build.py`。
3. **Meson 解析和执行构建定义：** Meson 会解析 `meson.build` 文件中定义的构建目标，并调用 `build.py` 中相应的类和方法来处理这些定义。例如，当遇到 `executable()` 函数时，会创建 `Executable` 类的实例，并调用其 `process_kwargs` 等方法。
4. **处理链接关系：** 当处理 `link_with` 或 `dependencies` 等关键字参数时，会调用 `link_with` 或相关的处理函数，这些函数会进行各种检查和处理，如前面所述的错误检查。
5. **发生错误：** 如果用户在 `meson.build` 文件中使用了错误的链接方式或依赖关系，例如将外部库传递给 `link_with`，那么 `build.py` 中的代码会检测到这些错误并抛出异常。
6. **显示错误信息：** Meson 会捕获这些异常，并在终端显示相应的错误信息，帮助用户定位问题。

因此，当用户在配置构建时遇到与链接相关的错误，查看错误信息中涉及到的 `link_with`、`dependencies` 以及相关的构建目标类型，可以帮助他们理解 `build.py` 中哪些检查失败了，从而修正 `meson.build` 文件。

**归纳一下它的功能：**

总而言之，`frida/subprojects/frida-node/releng/meson/mesonbuild/build.py` 文件的核心功能是**定义 Frida 项目中各种构建目标（可执行文件、静态库、共享库等）的构建逻辑，并严格管理和检查它们之间的链接关系和依赖关系，以确保构建过程的正确性和可靠性**。它通过一系列的检查和处理，防止用户犯常见的链接错误，并处理平台特定的构建需求，为 Frida 的成功编译奠定基础。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能
```

### 源代码
```python
raise MesonException(textwrap.dedent('''\
                        An external library was used in link_with keyword argument, which
                        is reserved for libraries built as part of this project. External
                        libraries must be passed using the dependencies keyword argument
                        instead, because they are conceptually "external dependencies",
                        just like those detected with the dependency() function.
                    '''))
                raise InvalidArguments(f'{t!r} is not a target.')
            if not t.is_linkable_target():
                raise InvalidArguments(f"Link target '{t!s}' is not linkable.")
            if isinstance(self, StaticLibrary) and self.install and t.is_internal():
                # When we're a static library and we link_with to an
                # internal/convenience library, promote to link_whole.
                self.link_whole([t], promoted=True)
                continue
            if isinstance(self, SharedLibrary) and isinstance(t, StaticLibrary) and not t.pic:
                msg = f"Can't link non-PIC static library {t.name!r} into shared library {self.name!r}. "
                msg += "Use the 'pic' option to static_library to build with PIC."
                raise InvalidArguments(msg)
            self.check_can_link_together(t)
            self.link_targets.append(t)

    def link_whole(self, targets: T.List[BuildTargetTypes], promoted: bool = False) -> None:
        for t in targets:
            if isinstance(t, (CustomTarget, CustomTargetIndex)):
                if not t.is_linkable_target():
                    raise InvalidArguments(f'Custom target {t!r} is not linkable.')
                if t.links_dynamically():
                    raise InvalidArguments('Can only link_whole custom targets that are static archives.')
            elif not isinstance(t, StaticLibrary):
                raise InvalidArguments(f'{t!r} is not a static library.')
            elif isinstance(self, SharedLibrary) and not t.pic:
                msg = f"Can't link non-PIC static library {t.name!r} into shared library {self.name!r}. "
                msg += "Use the 'pic' option to static_library to build with PIC."
                raise InvalidArguments(msg)
            self.check_can_link_together(t)
            if isinstance(self, StaticLibrary):
                # When we're a static library and we link_whole: to another static
                # library, we need to add that target's objects to ourselves.
                self._bundle_static_library(t, promoted)
                # If we install this static library we also need to include objects
                # from all uninstalled static libraries it depends on.
                if self.install:
                    for lib in t.get_internal_static_libraries():
                        self._bundle_static_library(lib, True)
            self.link_whole_targets.append(t)

    @lru_cache(maxsize=None)
    def get_internal_static_libraries(self) -> OrderedSet[BuildTargetTypes]:
        result: OrderedSet[BuildTargetTypes] = OrderedSet()
        self.get_internal_static_libraries_recurse(result)
        return result

    def get_internal_static_libraries_recurse(self, result: OrderedSet[BuildTargetTypes]) -> None:
        for t in self.link_targets:
            if t.is_internal() and t not in result:
                result.add(t)
                t.get_internal_static_libraries_recurse(result)
        for t in self.link_whole_targets:
            if t.is_internal():
                t.get_internal_static_libraries_recurse(result)

    def _bundle_static_library(self, t: T.Union[BuildTargetTypes], promoted: bool = False) -> None:
        if self.uses_rust():
            # Rustc can bundle static libraries, no need to extract objects.
            self.link_whole_targets.append(t)
        elif isinstance(t, (CustomTarget, CustomTargetIndex)) or t.uses_rust():
            # To extract objects from a custom target we would have to extract
            # the archive, WIP implementation can be found in
            # https://github.com/mesonbuild/meson/pull/9218.
            # For Rust C ABI we could in theory have access to objects, but there
            # are several meson issues that need to be fixed:
            # https://github.com/mesonbuild/meson/issues/10722
            # https://github.com/mesonbuild/meson/issues/10723
            # https://github.com/mesonbuild/meson/issues/10724
            m = (f'Cannot link_whole a custom or Rust target {t.name!r} into a static library {self.name!r}. '
                 'Instead, pass individual object files with the "objects:" keyword argument if possible.')
            if promoted:
                m += (f' Meson had to promote link to link_whole because {self.name!r} is installed but not {t.name!r},'
                      f' and thus has to include objects from {t.name!r} to be usable.')
            raise InvalidArguments(m)
        else:
            self.objects.append(t.extract_all_objects())

    def check_can_link_together(self, t: BuildTargetTypes) -> None:
        links_with_rust_abi = isinstance(t, BuildTarget) and t.uses_rust_abi()
        if not self.uses_rust() and links_with_rust_abi:
            raise InvalidArguments(f'Try to link Rust ABI library {t.name!r} with a non-Rust target {self.name!r}')
        if self.for_machine is not t.for_machine and (not links_with_rust_abi or t.rust_crate_type != 'proc-macro'):
            msg = f'Tried to tied to mix a {t.for_machine} library ("{t.name}") with a {self.for_machine} target "{self.name}"'
            if self.environment.is_cross_build():
                raise InvalidArguments(msg + ' This is not possible in a cross build.')
            else:
                mlog.warning(msg + ' This will fail in cross build.')

    def add_pch(self, language: str, pchlist: T.List[str]) -> None:
        if not pchlist:
            return
        elif len(pchlist) == 1:
            if not is_header(pchlist[0]):
                raise InvalidArguments(f'PCH argument {pchlist[0]} is not a header.')
        elif len(pchlist) == 2:
            if is_header(pchlist[0]):
                if not is_source(pchlist[1]):
                    raise InvalidArguments('PCH definition must contain one header and at most one source.')
            elif is_source(pchlist[0]):
                if not is_header(pchlist[1]):
                    raise InvalidArguments('PCH definition must contain one header and at most one source.')
                pchlist = [pchlist[1], pchlist[0]]
            else:
                raise InvalidArguments(f'PCH argument {pchlist[0]} is of unknown type.')

            if os.path.dirname(pchlist[0]) != os.path.dirname(pchlist[1]):
                raise InvalidArguments('PCH files must be stored in the same folder.')

            FeatureDeprecated.single_use('PCH source files', '0.50.0', self.subproject,
                                         'Only a single header file should be used.')
        elif len(pchlist) > 2:
            raise InvalidArguments('PCH definition may have a maximum of 2 files.')
        for f in pchlist:
            if not isinstance(f, str):
                raise MesonException('PCH arguments must be strings.')
            if not os.path.isfile(os.path.join(self.environment.source_dir, self.get_source_subdir(), f)):
                raise MesonException(f'File {f} does not exist.')
        self.pch[language] = pchlist

    def add_include_dirs(self, args: T.Sequence['IncludeDirs'], set_is_system: T.Optional[str] = None) -> None:
        ids: T.List['IncludeDirs'] = []
        for a in args:
            if not isinstance(a, IncludeDirs):
                raise InvalidArguments('Include directory to be added is not an include directory object.')
            ids.append(a)
        if set_is_system is None:
            set_is_system = 'preserve'
        if set_is_system != 'preserve':
            is_system = set_is_system == 'system'
            ids = [IncludeDirs(x.get_curdir(), x.get_incdirs(), is_system, x.get_extra_build_dirs(), x.is_build_only_subproject) for x in ids]
        self.include_dirs += ids

    def get_aliases(self) -> T.List[T.Tuple[str, str, str]]:
        return []

    def get_langs_used_by_deps(self) -> T.List[str]:
        '''
        Sometimes you want to link to a C++ library that exports C API, which
        means the linker must link in the C++ stdlib, and we must use a C++
        compiler for linking. The same is also applicable for objc/objc++, etc,
        so we can keep using clink_langs for the priority order.

        See: https://github.com/mesonbuild/meson/issues/1653
        '''
        langs: T.List[str] = []

        # Check if any of the external libraries were written in this language
        for dep in self.external_deps:
            if dep.language is None:
                continue
            if dep.language not in langs:
                langs.append(dep.language)
        # Check if any of the internal libraries this target links to were
        # written in this language
        for link_target in itertools.chain(self.link_targets, self.link_whole_targets):
            if isinstance(link_target, (CustomTarget, CustomTargetIndex)):
                continue
            for language in link_target.compilers:
                if language not in langs:
                    langs.append(language)

        return langs

    def get_prelinker(self):
        if self.link_language:
            comp = self.all_compilers[self.link_language]
            return comp
        for l in clink_langs:
            if l in self.compilers:
                try:
                    prelinker = self.all_compilers[l]
                except KeyError:
                    raise MesonException(
                        f'Could not get a prelinker linker for build target {self.name!r}. '
                        f'Requires a compiler for language "{l}", but that is not '
                        'a project language.')
                return prelinker
        raise MesonException(f'Could not determine prelinker for {self.name!r}.')

    def get_clink_dynamic_linker_and_stdlibs(self) -> T.Tuple['Compiler', T.List[str]]:
        '''
        We use the order of languages in `clink_langs` to determine which
        linker to use in case the target has sources compiled with multiple
        compilers. All languages other than those in this list have their own
        linker.
        Note that Vala outputs C code, so Vala sources can use any linker
        that can link compiled C. We don't actually need to add an exception
        for Vala here because of that.
        '''
        # If the user set the link_language, just return that.
        if self.link_language:
            comp = self.all_compilers[self.link_language]
            return comp, comp.language_stdlib_only_link_flags(self.environment)

        # Since dependencies could come from subprojects, they could have
        # languages we don't have in self.all_compilers. Use the global list of
        # all compilers here.
        all_compilers = self.environment.coredata.compilers[self.for_machine]

        # Languages used by dependencies
        dep_langs = self.get_langs_used_by_deps()

        # Pick a compiler based on the language priority-order
        for l in clink_langs:
            if l in self.compilers or l in dep_langs:
                try:
                    linker = all_compilers[l]
                except KeyError:
                    raise MesonException(
                        f'Could not get a dynamic linker for build target {self.name!r}. '
                        f'Requires a linker for language "{l}", but that is not '
                        'a project language.')
                stdlib_args: T.List[str] = self.get_used_stdlib_args(linker.language)
                # Type of var 'linker' is Compiler.
                # Pretty hard to fix because the return value is passed everywhere
                return linker, stdlib_args

        # None of our compilers can do clink, this happens for example if the
        # target only has ASM sources. Pick the first capable compiler.
        for l in clink_langs:
            try:
                comp = self.all_compilers[l]
                return comp, comp.language_stdlib_only_link_flags(self.environment)
            except KeyError:
                pass

        raise AssertionError(f'Could not get a dynamic linker for build target {self.name!r}')

    def get_used_stdlib_args(self, link_language: str) -> T.List[str]:
        all_compilers = self.environment.coredata.compilers[self.for_machine]
        all_langs = set(self.compilers).union(self.get_langs_used_by_deps())
        stdlib_args: T.List[str] = []
        for dl in all_langs:
            if dl != link_language and (dl, link_language) not in self._MASK_LANGS:
                # We need to use all_compilers here because
                # get_langs_used_by_deps could return a language from a
                # subproject
                stdlib_args.extend(all_compilers[dl].language_stdlib_only_link_flags(self.environment))
        return stdlib_args

    def uses_rust(self) -> bool:
        return 'rust' in self.compilers

    def uses_rust_abi(self) -> bool:
        return self.uses_rust() and self.rust_crate_type in {'dylib', 'rlib', 'proc-macro'}

    def uses_fortran(self) -> bool:
        return 'fortran' in self.compilers

    def get_using_msvc(self) -> bool:
        '''
        Check if the dynamic linker is MSVC. Used by Executable, StaticLibrary,
        and SharedLibrary for deciding when to use MSVC-specific file naming
        and debug filenames.

        If at least some code is built with MSVC and the final library is
        linked with MSVC, we can be sure that some debug info will be
        generated. We only check the dynamic linker here because the static
        linker is guaranteed to be of the same type.

        Interesting cases:
        1. The Vala compiler outputs C code to be compiled by whatever
           C compiler we're using, so all objects will still be created by the
           MSVC compiler.
        2. If the target contains only objects, process_compilers guesses and
           picks the first compiler that smells right.
        '''
        # Rustc can use msvc style linkers
        if self.uses_rust():
            compiler = self.all_compilers['rust']
        else:
            compiler, _ = self.get_clink_dynamic_linker_and_stdlibs()
        # Mixing many languages with MSVC is not supported yet so ignore stdlibs.
        return compiler and compiler.get_linker_id() in {'link', 'lld-link', 'xilink', 'optlink'}

    def check_module_linking(self):
        '''
        Warn if shared modules are linked with target: (link_with) #2865
        '''
        for link_target in self.link_targets:
            if isinstance(link_target, SharedModule) and not link_target.force_soname:
                if self.environment.machines[self.for_machine].is_darwin():
                    raise MesonException(
                        f'target {self.name} links against shared module {link_target.name}. This is not permitted on OSX')
                elif self.environment.machines[self.for_machine].is_android() and isinstance(self, SharedModule):
                    # Android requires shared modules that use symbols from other shared modules to
                    # be linked before they can be dlopen()ed in the correct order. Not doing so
                    # leads to a missing symbol error: https://github.com/android/ndk/issues/201
                    link_target.force_soname = True
                else:
                    mlog.deprecation(f'target {self.name} links against shared module {link_target.name}, which is incorrect.'
                                     '\n             '
                                     f'This will be an error in the future, so please use shared_library() for {link_target.name} instead.'
                                     '\n             '
                                     f'If shared_module() was used for {link_target.name} because it has references to undefined symbols,'
                                     '\n             '
                                     'use shared_library() with `override_options: [\'b_lundef=false\']` instead.')
                    link_target.force_soname = True

    def process_vs_module_defs_kw(self, kwargs: T.Dict[str, T.Any]) -> None:
        if kwargs.get('vs_module_defs') is None:
            return

        path: T.Union[str, File, CustomTarget, CustomTargetIndex] = kwargs['vs_module_defs']
        if isinstance(path, str):
            if os.path.isabs(path):
                self.vs_module_defs = File.from_absolute_file(path)
            else:
                self.vs_module_defs = File.from_source_file(self.environment.source_dir, self.subdir, path)
        elif isinstance(path, File):
            # When passing a generated file.
            self.vs_module_defs = path
        elif isinstance(path, (CustomTarget, CustomTargetIndex)):
            # When passing output of a Custom Target
            self.vs_module_defs = File.from_built_file(path.get_output_subdir(), path.get_filename())
        else:
            raise InvalidArguments(
                'vs_module_defs must be either a string, '
                'a file object, a Custom Target, or a Custom Target Index')
        self.process_link_depends(path)

class FileInTargetPrivateDir:
    """Represents a file with the path '/path/to/build/target_private_dir/fname'.
       target_private_dir is the return value of get_target_private_dir which is e.g. 'subdir/target.p'.
    """

    def __init__(self, fname: str):
        self.fname = fname

    def __str__(self) -> str:
        return self.fname

class FileMaybeInTargetPrivateDir:
    """Union between 'File' and 'FileInTargetPrivateDir'"""

    def __init__(self, inner: T.Union[File, FileInTargetPrivateDir]):
        self.inner = inner

    @property
    def fname(self) -> str:
        return self.inner.fname

    def rel_to_builddir(self, build_to_src: str, target_private_dir: str) -> str:
        if isinstance(self.inner, FileInTargetPrivateDir):
            return os.path.join(target_private_dir, self.inner.fname)
        return self.inner.rel_to_builddir(build_to_src)

    def absolute_path(self, srcdir: str, builddir: str) -> str:
        if isinstance(self.inner, FileInTargetPrivateDir):
            raise RuntimeError('Unreachable code')
        return self.inner.absolute_path(srcdir, builddir)

    def __str__(self) -> str:
        return self.fname

class Generator(HoldableObject):
    def __init__(self, exe: T.Union['Executable', programs.ExternalProgram],
                 arguments: T.List[str],
                 output: T.List[str],
                 # how2dataclass
                 *,
                 depfile: T.Optional[str] = None,
                 capture: bool = False,
                 depends: T.Optional[T.List[T.Union[BuildTarget, 'CustomTarget', 'CustomTargetIndex']]] = None,
                 name: str = 'Generator'):
        self.exe = exe
        self.depfile = depfile
        self.capture = capture
        self.depends: T.List[T.Union[BuildTarget, 'CustomTarget', 'CustomTargetIndex']] = depends or []
        self.arglist = arguments
        self.outputs = output
        self.name = name

    def __repr__(self) -> str:
        repr_str = "<{0}: {1}>"
        return repr_str.format(self.__class__.__name__, self.exe)

    def get_exe(self) -> T.Union['Executable', programs.ExternalProgram]:
        return self.exe

    def get_base_outnames(self, inname: str) -> T.List[str]:
        plainname = os.path.basename(inname)
        basename = os.path.splitext(plainname)[0]
        bases = [x.replace('@BASENAME@', basename).replace('@PLAINNAME@', plainname) for x in self.outputs]
        return bases

    def get_dep_outname(self, inname: str) -> T.List[str]:
        if self.depfile is None:
            raise InvalidArguments('Tried to get dep name for rule that does not have dependency file defined.')
        plainname = os.path.basename(inname)
        basename = os.path.splitext(plainname)[0]
        return self.depfile.replace('@BASENAME@', basename).replace('@PLAINNAME@', plainname)

    def get_arglist(self, inname: str) -> T.List[str]:
        plainname = os.path.basename(inname)
        basename = os.path.splitext(plainname)[0]
        return [x.replace('@BASENAME@', basename).replace('@PLAINNAME@', plainname) for x in self.arglist]

    @staticmethod
    def is_parent_path(parent: str, trial: str) -> bool:
        try:
            common = os.path.commonpath((parent, trial))
        except ValueError: # Windows on different drives
            return False
        return pathlib.PurePath(common) == pathlib.PurePath(parent)

    def process_files(self, files: T.Iterable[T.Union[str, File, 'CustomTarget', 'CustomTargetIndex', 'GeneratedList']],
                      state: T.Union['Interpreter', 'ModuleState'],
                      preserve_path_from: T.Optional[str] = None,
                      extra_args: T.Optional[T.List[str]] = None,
                      env: T.Optional[EnvironmentVariables] = None) -> 'GeneratedList':
        # TODO: need a test for a generator in a build-only subproject
        is_build_only: T.Optional[bool] = getattr(state, 'is_build_only_subproject', None)
        if is_build_only is None:
            is_build_only = T.cast('Interpreter', state).coredata.is_build_only
        output = GeneratedList(
            self,
            state.subdir,
            preserve_path_from,
            extra_args=extra_args if extra_args is not None else [],
            env=env if env is not None else EnvironmentVariables(),
            is_build_only_subproject=is_build_only,
        )

        for e in files:
            if isinstance(e, CustomTarget):
                output.depends.add(e)
            if isinstance(e, CustomTargetIndex):
                output.depends.add(e.target)
            if isinstance(e, (CustomTarget, CustomTargetIndex)):
                output.depends.add(e)
                fs = [File.from_built_file(e.get_output_subdir(), f) for f in e.get_outputs()]
            elif isinstance(e, GeneratedList):
                if preserve_path_from:
                    raise InvalidArguments("generator.process: 'preserve_path_from' is not allowed if one input is a 'generated_list'.")
                output.depends.add(e)
                fs = [FileInTargetPrivateDir(f) for f in e.get_outputs()]
            elif isinstance(e, str):
                fs = [File.from_source_file(state.environment.source_dir, state.subdir, e)]
            else:
                fs = [e]

            for f in fs:
                if preserve_path_from:
                    abs_f = f.absolute_path(state.environment.source_dir, state.environment.build_dir)
                    if not self.is_parent_path(preserve_path_from, abs_f):
                        raise InvalidArguments('generator.process: When using preserve_path_from, all input files must be in a subdirectory of the given dir.')
                f = FileMaybeInTargetPrivateDir(f)
                output.add_file(f, state)
        return output


@dataclass(eq=False)
class GeneratedList(HoldableObject):

    """The output of generator.process."""

    generator: Generator
    subdir: str
    preserve_path_from: T.Optional[str]
    extra_args: T.List[str]
    env: T.Optional[EnvironmentVariables]
    is_build_only_subproject: bool

    def __post_init__(self) -> None:
        self.name = self.generator.exe
        self.depends: T.Set[GeneratedTypes] = set()
        self.infilelist: T.List[FileMaybeInTargetPrivateDir] = []
        self.outfilelist: T.List[str] = []
        self.outmap: T.Dict[FileMaybeInTargetPrivateDir, T.List[str]] = {}
        self.extra_depends = []  # XXX: Doesn't seem to be used?
        self.depend_files: T.List[File] = []

        if self.extra_args is None:
            self.extra_args: T.List[str] = []

        if self.env is None:
            self.env: EnvironmentVariables = EnvironmentVariables()

        if isinstance(self.generator.exe, programs.ExternalProgram):
            if not self.generator.exe.found():
                raise InvalidArguments('Tried to use not-found external program as generator')
            path = self.generator.exe.get_path()
            if os.path.isabs(path):
                # Can only add a dependency on an external program which we
                # know the absolute path of
                self.depend_files.append(File.from_absolute_file(path))

    def add_preserved_path_segment(self, infile: FileMaybeInTargetPrivateDir, outfiles: T.List[str], state: T.Union['Interpreter', 'ModuleState']) -> T.List[str]:
        result: T.List[str] = []
        in_abs = infile.absolute_path(state.environment.source_dir, state.environment.build_dir)
        assert os.path.isabs(self.preserve_path_from)
        rel = os.path.relpath(in_abs, self.preserve_path_from)
        path_segment = os.path.dirname(rel)
        for of in outfiles:
            result.append(os.path.join(path_segment, of))
        return result

    def add_file(self, newfile: FileMaybeInTargetPrivateDir, state: T.Union['Interpreter', 'ModuleState']) -> None:
        self.infilelist.append(newfile)
        outfiles = self.generator.get_base_outnames(newfile.fname)
        if self.preserve_path_from:
            outfiles = self.add_preserved_path_segment(newfile, outfiles, state)
        self.outfilelist += outfiles
        self.outmap[newfile] = outfiles

    def get_inputs(self) -> T.List[FileMaybeInTargetPrivateDir]:
        return self.infilelist

    def get_outputs(self) -> T.List[str]:
        return self.outfilelist

    def get_outputs_for(self, filename: FileMaybeInTargetPrivateDir) -> T.List[str]:
        return self.outmap[filename]

    def get_generator(self) -> 'Generator':
        return self.generator

    def get_extra_args(self) -> T.List[str]:
        return self.extra_args

    def get_source_subdir(self) -> str:
        return self.subdir

    def get_output_subdir(self) -> str:
        return compute_build_subdir(self.subdir, self.is_build_only_subproject)


class Executable(BuildTarget):
    known_kwargs = known_exe_kwargs

    typename = 'executable'

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
        key = OptionKey('b_pie')
        if 'pie' not in kwargs and key in environment.coredata.options:
            kwargs['pie'] = environment.coredata.options[key].value
        super().__init__(name, subdir, subproject, for_machine, sources, structured_sources, objects,
                         environment, compilers, build_only_subproject, kwargs)
        self.win_subsystem = kwargs.get('win_subsystem') or 'console'
        # Check for export_dynamic
        self.export_dynamic = kwargs.get('export_dynamic', False)
        if not isinstance(self.export_dynamic, bool):
            raise InvalidArguments('"export_dynamic" keyword argument must be a boolean')
        self.implib = kwargs.get('implib')
        if not isinstance(self.implib, (bool, str, type(None))):
            raise InvalidArguments('"export_dynamic" keyword argument must be a boolean or string')
        # Only linkwithable if using export_dynamic
        self.is_linkwithable = self.export_dynamic
        # Remember that this exe was returned by `find_program()` through an override
        self.was_returned_by_find_program = False

        self.vs_module_defs: T.Optional[File] = None
        self.process_vs_module_defs_kw(kwargs)

    def post_init(self) -> None:
        super().post_init()
        machine = self.environment.machines[self.for_machine]
        # Unless overridden, executables have no suffix or prefix. Except on
        # Windows and with C#/Mono executables where the suffix is 'exe'
        if not hasattr(self, 'prefix'):
            self.prefix = ''
        if not hasattr(self, 'suffix'):
            # Executable for Windows or C#/Mono
            if machine.is_windows() or machine.is_cygwin() or 'cs' in self.compilers:
                self.suffix = 'exe'
            elif machine.system.startswith('wasm') or machine.system == 'emscripten':
                self.suffix = 'js'
            elif ('c' in self.compilers and self.compilers['c'].get_id().startswith('armclang') or
                  'cpp' in self.compilers and self.compilers['cpp'].get_id().startswith('armclang')):
                self.suffix = 'axf'
            elif ('c' in self.compilers and self.compilers['c'].get_id().startswith('ccrx') or
                  'cpp' in self.compilers and self.compilers['cpp'].get_id().startswith('ccrx')):
                self.suffix = 'abs'
            elif ('c' in self.compilers and self.compilers['c'].get_id().startswith('xc16')):
                self.suffix = 'elf'
            elif ('c' in self.compilers and self.compilers['c'].get_id() in {'ti', 'c2000', 'c6000'} or
                  'cpp' in self.compilers and self.compilers['cpp'].get_id() in {'ti', 'c2000', 'c6000'}):
                self.suffix = 'out'
            elif ('c' in self.compilers and self.compilers['c'].get_id() in {'mwccarm', 'mwcceppc'} or
                  'cpp' in self.compilers and self.compilers['cpp'].get_id() in {'mwccarm', 'mwcceppc'}):
                self.suffix = 'nef'
            else:
                self.suffix = machine.get_exe_suffix()
        self.filename = self.name
        if self.suffix:
            self.filename += '.' + self.suffix
        self.outputs[0] = self.filename

        # The import library this target will generate
        self.import_filename = None
        # The debugging information file this target will generate
        self.debug_filename = None

        # If using export_dynamic, set the import library name
        if self.export_dynamic:
            implib_basename = self.name + '.exe'
            if isinstance(self.implib, str):
                implib_basename = self.implib
            if machine.is_windows() or machine.is_cygwin():
                if self.get_using_msvc():
                    self.import_filename = f'{implib_basename}.lib'
                else:
                    self.import_filename = f'lib{implib_basename}.a'

        create_debug_file = (
            machine.is_windows()
            and ('cs' in self.compilers or self.uses_rust() or self.get_using_msvc())
            # .pdb file is created only when debug symbols are enabled
            and self.environment.coredata.get_option(OptionKey("debug"))
        )
        if create_debug_file:
            # If the target is has a standard exe extension (i.e. 'foo.exe'),
            # then the pdb name simply becomes 'foo.pdb'. If the extension is
            # something exotic, then include that in the name for uniqueness
            # reasons (e.g. 'foo_com.pdb').
            name = self.name
            if getattr(self, 'suffix', 'exe') != 'exe':
                name += '_' + self.suffix
            self.debug_filename = name + '.pdb'

    def process_kwargs(self, kwargs):
        super().process_kwargs(kwargs)

        self.rust_crate_type = kwargs.get('rust_crate_type') or 'bin'
        if self.rust_crate_type != 'bin':
            raise InvalidArguments('Invalid rust_crate_type: must be "bin" for executables.')

    def get_default_install_dir(self) -> T.Union[T.Tuple[str, str], T.Tuple[None, None]]:
        return self.environment.get_bindir(), '{bindir}'

    def description(self):
        '''Human friendly description of the executable'''
        return self.name

    def type_suffix(self):
        return "@exe"

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

    def is_linkable_tar
```