Response:
My thought process for analyzing the Python code and generating the response involved several steps:

1. **Understanding the Request:** I first broke down the request into its core components: analyze the provided Python code snippet, identify its functions, relate it to reverse engineering (if applicable), identify low-level/kernel/framework aspects, detect logical reasoning with input/output examples, spot potential user errors, trace how a user might reach this code, and finally, summarize the code's functionality. The "part 3 of 5" indicated a larger context within the Frida project.

2. **Initial Code Scan and Keyword Recognition:** I quickly scanned the code, looking for keywords and patterns that hinted at its purpose. Terms like `link_with`, `link_whole`, `StaticLibrary`, `SharedLibrary`, `CustomTarget`, `PCH`, `include_dirs`, `Generator`, `Executable`,  `environment`, `compiler`, `linker`,  `rust`, and `windows` stood out. These suggested the code deals with the build process of software, specifically handling linking dependencies, managing different library types, and supporting various build systems and languages.

3. **Function-by-Function Analysis:** I then went through each method (`def`) in the provided snippet:

    * **`link_with` and `link_whole`:** These clearly handle linking dependencies between build targets. The code checks for compatibility (e.g., linking static libraries into shared libraries), external vs. internal libraries, and PIC requirements.
    * **`get_internal_static_libraries` (and `_recurse`):**  This indicates the code tracks and retrieves internal static libraries that a target depends on. The use of `@lru_cache` suggests optimization to avoid redundant computations.
    * **`_bundle_static_library`:** This function deals with incorporating the objects of static libraries into another static library. The comments regarding Rust and custom targets highlighted limitations and ongoing development in this area.
    * **`check_can_link_together`:** This enforces compatibility rules between linked targets, considering factors like Rust ABI and cross-compilation.
    * **`add_pch`:** This manages precompiled headers, a common optimization technique in C/C++ builds. The error checking here helps catch common user mistakes.
    * **`add_include_dirs`:** This adds include directories for the compiler, essential for finding header files.
    * **`get_aliases`:**  Returns an empty list, suggesting this functionality might be present in other parts of the class or project.
    * **`get_langs_used_by_deps`:**  Determines the programming languages involved in the dependencies, which is crucial for selecting the correct linker and standard libraries.
    * **`get_prelinker` and `get_clink_dynamic_linker_and_stdlibs`:** These functions are central to selecting the appropriate linker based on the languages used in the target and its dependencies. The `clink_langs` variable implies a priority order for linkers.
    * **`get_used_stdlib_args`:** Retrieves standard library linking flags based on the involved languages.
    * **`uses_rust`, `uses_rust_abi`, `uses_fortran`:**  Simple checks for language usage.
    * **`get_using_msvc`:** Detects if the MSVC linker is being used, relevant for Windows-specific build considerations.
    * **`check_module_linking`:** Addresses specific issues related to linking shared modules, particularly on macOS and Android.
    * **`process_vs_module_defs_kw`:** Handles Visual Studio module definition files.
    * **`FileInTargetPrivateDir`, `FileMaybeInTargetPrivateDir`:** These classes seem to represent file paths within the build system's internal structure.
    * **`Generator` and `GeneratedList`:** These are related to generating files as part of the build process, often used for tasks like code generation.
    * **`Executable`:**  This class represents an executable program being built. It inherits from `BuildTarget` and adds executable-specific details like Windows subsystem, export dynamic symbols, and handling of import libraries and debug symbols (.pdb files).

4. **Connecting to the Request's Specific Points:**  As I analyzed each function, I consciously considered how it related to the request's prompts:

    * **Reverse Engineering:**  Linking and understanding dependencies are fundamental to reverse engineering, as it helps understand how different code components interact. The `export_dynamic` flag is directly relevant as it controls which symbols are available for dynamic linking, something a reverse engineer would analyze.
    * **Binary/Low-Level/Kernel/Framework:**  Concepts like static and shared libraries, PIC (Position Independent Code), linkers, standard libraries, and OS-specific details (Windows subsystems, macOS/Android shared module linking) are all low-level or operating system related.
    * **Logical Reasoning:**  The conditional checks within `link_with`, `link_whole`, and `check_can_link_together` demonstrate logical reasoning. I formulated input/output examples to illustrate these checks.
    * **User Errors:**  The error messages within the code (e.g., when linking incompatible libraries or using `link_with` incorrectly) directly indicate potential user errors. I created examples of such errors.
    * **User Journey/Debugging:** I considered how a user might interact with a build system (like Meson) and trigger the code. Actions like defining dependencies or using specific keywords would lead to this code being executed.

5. **Synthesizing and Structuring the Response:**  Once I had a good understanding of the code's functionalities and their connections to the request's points, I started structuring the response:

    * **Overall Function:** I began with a high-level summary of the code's purpose.
    * **Detailed Functions:**  I listed and explained the purpose of each significant function.
    * **Reverse Engineering Relevance:** I provided specific examples of how the code relates to reverse engineering techniques.
    * **Low-Level Concepts:** I elaborated on the binary, kernel, and framework concepts present in the code.
    * **Logical Reasoning Examples:** I presented clear input and output scenarios to illustrate the code's logic.
    * **Common User Errors:** I provided concrete examples of mistakes users might make when interacting with the build system.
    * **User Journey:** I described the steps a user might take to reach this code, emphasizing the build process and dependency management.
    * **Summary:** I concluded with a concise summary of the code's main responsibilities.

6. **Refinement and Clarity:**  I reviewed the generated response for clarity, accuracy, and completeness. I ensured that the explanations were easy to understand and that the examples were relevant and illustrative. I also made sure to address all parts of the original request.

This iterative process of code analysis, connection to the request, and structured summarization allowed me to generate a comprehensive and informative response to the prompt. The "part 3 of 5" hint helped me understand that this code is likely part of a larger build system within the Frida project, focusing on the linking and dependency management aspects.
好的，我们来分析一下 `frida/subprojects/frida-python/releng/meson/mesonbuild/build.py` 这个文件中的代码片段。

**代码功能归纳:**

这段代码主要负责处理软件构建过程中的**链接 (linking)** 环节，特别是针对不同类型的库 (静态库、共享库) 和目标 (可执行文件、自定义目标) 之间的依赖关系。它定义了如何将不同的编译产物组合成最终的可执行文件或库。

**更具体的功能点:**

1. **管理链接依赖 (`link_with`):**
   -  允许将其他内部构建的目标 (如库) 链接到当前目标。
   -  强制区分内部库 (`link_with`) 和外部库 (必须使用 `dependencies` 关键字)。这是一个重要的设计决策，有助于保持构建系统的清晰和一致性。
   -  进行多种类型检查，确保链接的目标是可链接的 (`is_linkable_target()`)。
   -  处理静态库链接到其他静态库的情况，如果当前目标是静态库且要链接到内部静态库，则会使用 `link_whole` 将其提升。
   -  禁止将非 PIC (Position Independent Code) 的静态库链接到共享库，因为这会导致运行时错误。
   -  调用 `check_can_link_together()` 进行更深层次的链接兼容性检查。

2. **管理完整链接 (`link_whole`):**
   -  允许将静态库或特定的自定义目标完整地链接到当前目标。
   -  对可以进行完整链接的目标类型进行限制 (必须是静态库或特定的自定义目标)。
   -  同样禁止将非 PIC 的静态库完整链接到共享库。
   -  如果当前目标是静态库，且使用了 `link_whole` 链接到另一个静态库，会将被链接静态库的对象文件捆绑到当前静态库中 (`_bundle_static_library`)。
   -  如果安装了当前静态库，还会递归地捆绑其依赖的未安装的内部静态库的对象文件。

3. **获取内部静态库 (`get_internal_static_libraries`, `get_internal_static_libraries_recurse`):**
   -  提供方法来递归地获取当前目标依赖的所有内部静态库。这对于静态库的打包和管理非常重要。

4. **捆绑静态库对象 (`_bundle_static_library`):**
   -  负责将一个静态库中的所有对象文件提取出来，并添加到当前目标的 `objects` 列表中。
   -  对于 Rust 语言编写的静态库，由于 `rustc` 可以直接处理，所以不需要提取对象。
   -  对自定义目标和 Rust 目标进行限制，因为直接提取其对象文件可能比较复杂 (代码中提到了正在进行的开发工作)。

5. **检查链接兼容性 (`check_can_link_together`):**
   -  检查要链接的目标之间是否存在兼容性问题，例如尝试将 Rust ABI 库链接到非 Rust 目标，或者尝试混合不同架构 (machine) 的库。
   -  对于跨平台编译，会严格禁止混合不同架构的库。

6. **处理预编译头文件 (PCH, `add_pch`):**
   -  允许为目标添加预编译头文件，以加速编译过程。
   -  验证 PCH 参数的有效性 (必须是头文件，最多包含一个源文件)。
   -  检查 PCH 文件是否存在于源代码目录中。

7. **添加包含目录 (`add_include_dirs`):**
   -  允许为目标添加额外的头文件搜索路径。
   -  确保添加的是 `IncludeDirs` 对象。
   -  可以设置包含目录是系统目录还是用户目录。

8. **获取依赖使用的语言 (`get_langs_used_by_deps`):**
   -  确定当前目标依赖的库所使用的编程语言。这对于选择正确的链接器和链接标准库至关重要。

9. **获取预链接器 (`get_prelinker`):**
   -  根据目标的编程语言选择合适的预链接器。

10. **获取 C 风格的动态链接器和标准库参数 (`get_clink_dynamic_linker_and_stdlibs`):**
    -  选择合适的动态链接器 (如 GCC 的 `ld` 或 Clang 的 `lld`)，并获取链接标准库所需的参数。
    -  根据目标和其依赖所使用的语言优先级来选择链接器。

11. **获取使用的标准库参数 (`get_used_stdlib_args`):**
    -  获取链接当前目标时需要链接的其他语言的标准库。

12. **检查是否使用特定语言 (`uses_rust`, `uses_rust_abi`, `uses_fortran`):**
    -  提供便捷的方法来判断目标是否使用了特定的编程语言。

13. **判断是否使用 MSVC (`get_using_msvc`):**
    -  判断链接器是否是 MSVC (Microsoft Visual C++)，这会影响文件命名和调试信息的处理。

14. **检查模块链接 (`check_module_linking`):**
    -  对链接到共享模块的目标发出警告或错误，因为在某些平台上 (如 macOS) 这是不允许的。

15. **处理 Visual Studio 模块定义文件 (`process_vs_module_defs_kw`):**
    -  允许指定 Visual Studio 的 `.def` 文件，用于控制 DLL 的导出符号。

16. **表示目标私有目录中的文件 (`FileInTargetPrivateDir`, `FileMaybeInTargetPrivateDir`):**
    -  定义了用于表示构建过程中生成的、位于目标私有目录中的文件的类。

17. **代码生成器 (`Generator`, `GeneratedList`):**
    -  `Generator` 类表示一个外部程序，用于生成代码或其他文件。
    -  `GeneratedList` 类表示 `Generator` 生成的文件列表，并管理其依赖关系。

18. **可执行文件 (`Executable`):**
    -  `Executable` 类继承自 `BuildTarget`，表示要构建的可执行文件。
    -  包含可执行文件特有的属性，如 Windows 子系统、是否导出动态符号、导入库名称、调试信息文件名等。
    -  处理可执行文件的后缀名和输出文件名。

**与逆向方法的关系及举例:**

这段代码直接参与了构建 Frida 工具的过程，而 Frida 本身就是一个动态插桩工具，常用于逆向工程、安全分析和动态调试。

* **动态链接分析:**  `link_with` 和 `link_whole` 等功能直接关系到最终生成的可执行文件或库的动态链接关系。逆向工程师可以使用 Frida 连接到目标进程，并分析其加载的库以及符号的解析过程。这段代码保证了 Frida 的 Python 绑定能够正确地链接到 Frida 的核心库。
* **符号导出 (`export_dynamic`):** `Executable` 类中的 `export_dynamic` 属性决定了可执行文件中的哪些符号可以被动态链接器访问。如果 Frida 的 Python 绑定需要导出某些符号供其他 Frida 组件使用，这个设置就非常关键。逆向工程师可能会关注哪些符号被导出，以了解 Frida 的内部结构和交互方式。
* **导入库 (`implib`):** 在 Windows 平台上，动态链接库通常需要导入库 (`.lib` 文件)。这段代码处理了生成和链接导入库的逻辑。逆向工程师在分析 Windows 程序时，经常会查看其导入表，了解它依赖哪些 DLL 及其导出的函数。
* **调试信息 (`debug_filename`):** 代码中提到了生成 `.pdb` 调试信息文件的逻辑。逆向工程师在调试 Frida 或其注入的目标进程时，会使用这些调试信息来定位代码位置、查看变量值等。
* **模块定义文件 (`vs_module_defs`):** 对于 Windows DLL 的构建，模块定义文件可以精确控制导出的符号。逆向工程师分析 DLL 时，如果存在 `.def` 文件，可以从中了解 DLL 的接口。

**二进制底层、Linux/Android 内核及框架的知识及举例:**

这段代码涉及到多个与操作系统底层和构建过程相关的概念：

* **静态库 vs. 共享库:** 代码区分了静态库 (`StaticLibrary`) 和共享库 (`SharedLibrary`) 的链接方式。静态库在链接时会被完整地复制到可执行文件中，而共享库在运行时才会被加载。这是操作系统加载和链接二进制文件的基本概念。
* **PIC (Position Independent Code):** 代码中强制要求共享库的依赖库使用 PIC。PIC 使得代码可以加载到内存的任意地址，这是共享库在不同进程中共享内存的基础。
* **链接器 (Linker):**  `get_clink_dynamic_linker_and_stdlibs` 等函数涉及到选择合适的链接器。链接器是操作系统工具链的关键组成部分，负责将编译后的目标文件组合成最终的可执行文件或库。
* **标准库 (Standard Libraries):** 代码需要确定需要链接哪些标准库 (`get_used_stdlib_args`)，例如 C 语言的 `libc` 或 C++ 的 `libstdc++`。这些库提供了程序运行所需的基本功能。
* **Windows 子系统 (`win_subsystem`):** `Executable` 类中定义了 `win_subsystem`，用于指定 Windows 可执行文件的类型 (例如控制台程序或 GUI 程序)。这直接影响操作系统如何启动和管理进程。
* **macOS/Android 共享模块 (`check_module_linking`):** 代码中特别处理了 macOS 和 Android 平台上共享模块的链接问题。这反映了不同操作系统在动态链接机制上的差异。

**逻辑推理及假设输入与输出:**

以下是一些逻辑推理的例子：

**假设输入:**

* 一个 `SharedLibrary` 目标 `libfoo` 尝试使用 `link_with` 链接一个 `StaticLibrary` 目标 `libbar`，并且 `libbar` 没有启用 PIC 选项。

**输出:**

```
raise InvalidArguments(msg)
```
其中 `msg` 会包含类似 "Can't link non-PIC static library 'libbar' into shared library 'libfoo'. Use the 'pic' option to static_library to build with PIC." 的错误信息。

**假设输入:**

* 一个 `StaticLibrary` 目标 `libA` 使用 `link_with` 链接另一个 `StaticLibrary` 目标 `libB`。

**输出:**

`libA` 的 `link_whole_targets` 列表会包含 `libB`，并且如果 `libA` 被安装，还会递归地将 `libB` 的依赖的内部静态库也添加到 `libA` 的 `link_whole_targets` 中。

**假设输入:**

* 在跨平台编译环境下，一个为 `host` 平台编译的目标尝试链接一个为 `target` 平台编译的库。

**输出:**

```
raise InvalidArguments(msg + ' This is not possible in a cross build.')
```
其中 `msg` 会包含类似 "Tried to tied to mix a target library ("...") with a host target "..." " 的错误信息。

**用户或编程常见的使用错误及举例:**

1. **错误地使用 `link_with` 链接外部库:**

   ```python
   # 错误示例
   mylib = shared_library('mylib', sources, link_with: find_library('pthread'))
   ```

   **报错信息:**
   ```
   An external library was used in link_with keyword argument, which
   is reserved for libraries built as part of this project. External
   libraries must be passed using the dependencies keyword argument
   instead, because they are conceptually "external dependencies",
   just like those detected with the dependency() function.
   ```

   **正确用法:**
   ```python
   mylib = shared_library('mylib', sources, dependencies: find_library('pthread'))
   ```

2. **尝试将非 PIC 的静态库链接到共享库:**

   ```python
   # 假设 libbar 是一个非 PIC 的静态库
   libfoo = shared_library('libfoo', sources, link_with: libbar)
   ```

   **报错信息:**
   ```
   Can't link non-PIC static library 'libbar' into shared library 'libfoo'. Use the 'pic' option to static_library to build with PIC.
   ```

3. **PCH 文件参数错误:**

   ```python
   # 错误示例：提供了两个源文件作为 PCH
   executable('myexe', 'main.c', pch: ['myheader.h', 'myheader.c'])
   ```

   **报错信息:**
   ```
   PCH definition must contain one header and at most one source.
   ```

**用户操作是如何一步步的到达这里，作为调试线索:**

作为一个 Frida 的开发者或者用户，在构建 Frida 的 Python 绑定时，Meson 构建系统会解析 `meson.build` 文件，其中定义了各种构建目标及其依赖关系。当 Meson 处理到需要链接库的步骤时，例如 `shared_library()` 或 `executable()` 函数调用中使用了 `link_with` 或 `link_whole` 关键字，就会调用到这段 `build.py` 中的代码。

**调试线索:**

1. **查看 `meson.build` 文件:** 检查 `shared_library` 或 `executable` 等函数调用中 `link_with` 或 `link_whole` 关键字的使用是否正确，确保链接的是项目内部构建的目标，而不是外部库。
2. **检查静态库的 PIC 选项:** 如果报错提示无法将非 PIC 的静态库链接到共享库，需要检查相关 `static_library()` 函数调用中是否设置了 `pic: true` 选项。
3. **查看 Meson 的构建日志:**  Meson 会输出详细的构建日志，其中包含了链接器的调用命令和错误信息。这些信息可以帮助定位链接错误。
4. **使用 Meson 的内省功能:** Meson 提供了内省 API，可以用来查询构建目标的属性和依赖关系，帮助理解构建过程中的链接行为。

**第3部分功能归纳:**

这段代码是 Frida Python 绑定构建系统中负责**管理和验证构建目标之间链接关系**的核心部分。它确保了不同类型的库和目标能够正确地链接在一起，处理了平台特定的链接需求，并提供了对预编译头文件和包含目录的管理。其主要目的是保证最终生成的 Frida Python 绑定库或可执行文件能够正确地加载和运行，并且避免了常见的链接错误。它体现了构建系统在软件开发中的重要性，特别是对于像 Frida 这样涉及动态链接和底层操作的工具。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/build.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
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
"""


```