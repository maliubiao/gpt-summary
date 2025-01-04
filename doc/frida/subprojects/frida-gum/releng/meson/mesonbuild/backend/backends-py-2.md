Response:
The user wants to understand the functionality of the provided Python code snippet from the `backends.py` file in the Frida dynamic instrumentation tool. I need to analyze each method in the class and explain its purpose. I should also relate the functionalities to reverse engineering, binary internals, Linux/Android kernel/framework knowledge, logical reasoning, common user errors, and the steps a user might take to reach this code. Finally, I need to summarize the overall function of this code.

Here's a plan:
1. **Iterate through each method:**  Analyze its code to understand its input, processing, and output.
2. **Relate to reverse engineering:** Identify methods that deal with target files, dependencies, and execution, which are relevant to reverse engineering.
3. **Connect to binary internals/kernel:** Look for operations that involve file paths, library handling, and potentially OS-specific concepts.
4. **Identify logical reasoning:** Check for conditional statements and data transformations within the methods. Formulate input-output examples if possible.
5. **Pinpoint potential user errors:** Analyze how incorrect user configuration or project setup might lead to issues within these methods.
6. **Trace user actions:**  Think about the build process in Frida and how different stages might call these backend functions.
7. **Summarize the functionality:**  Provide a concise overview of the role of this code within the larger Frida project.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/backend/backends.py` 文件的一部分，它主要定义了 Meson 构建系统的后端（backend）的通用功能。这个后端负责将 Meson 的抽象构建描述转换为特定构建系统（如 Ninja, Xcode, Visual Studio）所需的具体文件（如 build.ninja, project.pbxproj, .vcxproj）。

以下是代码片段中各个函数的功能以及它们与逆向、二进制底层、Linux/Android 内核及框架的知识的关系，逻辑推理，用户错误和用户操作路径的说明：

**1. `get_all_dependencies(self, target: T.Union[build.BuildTarget, build.CustomTarget]) -> T.Dict[str, T.Union[build.BuildTarget, build.CustomTarget]]`**

* **功能:**  获取给定构建目标（`target`）的所有依赖项，并以字典形式返回，其中键是依赖项的 ID，值是依赖项对象本身。
* **与逆向的关系:** 在逆向工程中，理解目标文件的依赖关系至关重要。这个函数可以帮助确定一个可执行文件或库依赖于哪些其他库或目标，这对于分析程序的加载过程和运行时行为很有用。
    * **举例:** 如果一个逆向工程师想分析 `frida-agent`，他们需要知道它链接了哪些库。这个函数可以提供这些信息。
* **与二进制底层的关系:** 依赖关系直接影响二进制文件的链接过程。这个函数处理的依赖项最终会影响生成的可执行文件或库的结构。
* **逻辑推理:**
    * **假设输入:** 一个 `build.BuildTarget` 对象，表示一个名为 `my_executable` 的可执行文件，它依赖于 `libcrypto.so` 和一个自定义目标 `generate_config.py`。
    * **预期输出:** 一个字典，包含 `libcrypto.so` 的 `build.BuildTarget` 对象和 `generate_config.py` 的 `build.CustomTarget` 对象。
* **用户操作路径:**  Meson 在处理 `meson.build` 文件时，会解析 `dependencies` 关键字，创建 `build.BuildTarget` 和 `build.CustomTarget` 对象，并将它们存储起来。当后端需要生成构建系统文件时，会调用此函数来获取依赖关系信息。

**2. `get_custom_target_provided_by_generated_source(self, generated_source: build.CustomTarget) -> 'ImmutableListProtocol[str]'`**

* **功能:**  对于一个生成源文件的自定义目标（`generated_source`），返回该目标生成的库文件路径列表。
* **与逆向的关系:** 某些自定义目标可能会生成动态库。逆向工程师需要知道这些生成库的位置以便进行进一步的分析或加载。
    * **举例:** 一个自定义目标使用 `protoc` 生成 gRPC 库。这个函数可以返回生成的 `.so` 或 `.dll` 文件的路径。
* **与二进制底层的关系:** 此函数识别生成的库文件，这些文件是二进制代码的一部分，会被链接到其他目标。
* **逻辑推理:**
    * **假设输入:** 一个 `build.CustomTarget` 对象，代表一个使用 `cmake` 生成 `mylib.so` 的目标。
    * **预期输出:**  一个包含 `mylib.so` 完整路径的列表。
* **用户操作路径:**  用户在 `meson.build` 文件中定义了一个生成库的自定义目标。Meson 在构建过程中执行该目标，并将生成的库信息存储起来。后端会调用此函数来获取这些库的路径。

**3. `get_custom_target_provided_libraries(self, target: T.Union[build.BuildTarget, build.CustomTarget]) -> 'ImmutableListProtocol[str]'`**

* **功能:**  获取一个目标（`target`）通过其生成的源文件提供的所有库文件路径列表。这会遍历目标生成的所有源文件，并调用 `get_custom_target_provided_by_generated_source` 来获取库文件。
* **与逆向的关系:** 类似于上一个函数，但范围更广，因为它考虑了目标生成的所有源文件，而不仅仅是特定的生成源目标。
* **与二进制底层的关系:** 涉及识别和跟踪生成的二进制库文件。
* **逻辑推理:**
    * **假设输入:** 一个 `build.BuildTarget` 对象，它使用一个自定义目标生成了一些源文件，而该自定义目标又生成了一个库 `helper.so`。
    * **预期输出:**  一个包含 `helper.so` 完整路径的列表。
* **用户操作路径:**  用户在 `meson.build` 中定义了一个使用自定义目标生成源文件的构建目标。后端需要知道这些生成的源文件是否包含库，以便正确处理链接。

**4. `get_custom_target_sources(self, target: build.CustomTarget) -> T.List[str]`**

* **功能:**  获取自定义目标（`target`）的所有源文件路径列表。源文件可以是字符串、`File` 对象、`BuildTarget` 对象甚至其他的 `CustomTarget` 对象。它负责将不同类型的源表示转换为相对于构建根目录的路径。
* **与逆向的关系:**  在逆向工程中，了解目标构建所使用的所有源文件是理解其功能和实现的起点。
    * **举例:**  一个自定义目标使用一个 C++ 文件和一个 Python 脚本作为输入。这个函数会返回这两个文件的路径。
* **与二进制底层的关系:**  虽然此函数不直接操作二进制数据，但它列出了生成二进制文件的输入源。
* **与 Linux, Android 内核及框架的知识的关系:**  如果自定义目标的源文件涉及到与内核或框架交互的代码，那么这个函数会列出这些代码的位置。
* **逻辑推理:**
    * **假设输入:** 一个 `build.CustomTarget` 对象，它使用 `input.c` 文件和一个 `build.BuildTarget` 类型的预编译库 `mylib.a` 作为源。
    * **预期输出:**  一个包含 `input.c` 相对于构建根目录的路径，以及 `mylib.a` 的完整构建路径的列表。
* **常见用户错误:**
    * **错误的路径:** 用户可能在 `meson.build` 文件中提供了错误的源文件路径。
    * **忘记声明依赖:** 用户可能忘记将一个 `BuildTarget` 或 `CustomTarget` 声明为自定义目标的依赖，导致构建失败。
* **用户操作路径:** 用户在 `meson.build` 文件中定义一个自定义目标，并在 `input` 列表中指定其源文件。后端在生成构建系统文件时会调用此函数来获取源文件列表。

**5. `get_target_depend_files(self, target: T.Union[build.CustomTarget, build.BuildTarget], absolute_paths: bool = False) -> T.List[str]`**

* **功能:**  获取目标（`target`）的所有依赖文件路径列表。这些依赖文件通常是由用户显式声明的，用于触发目标在这些文件更改时重新构建。可以选择返回绝对路径或相对于构建目录的路径。
* **与逆向的关系:**  依赖文件可以包括配置文件、脚本或其他数据文件，这些文件可能会影响最终生成的可执行文件或库的行为。
    * **举例:** 一个可执行文件依赖于一个配置文件 `config.ini`。这个函数会返回 `config.ini` 的路径。
* **与二进制底层的关系:**  依赖文件中的内容可能会被嵌入到二进制文件中，或者在运行时被加载。
* **逻辑推理:**
    * **假设输入:** 一个 `build.BuildTarget` 对象，它依赖于一个位于源代码目录下的 `data.txt` 文件。 `absolute_paths` 为 `False`。
    * **预期输出:**  一个包含 `data.txt` 相对于构建根目录的路径的列表。
* **用户操作路径:** 用户在 `meson.build` 文件中使用 `depend_files` 关键字声明目标的依赖文件。后端会调用此函数来获取这些依赖文件的路径，以便在构建系统中设置正确的依赖关系。

**6. `get_custom_target_output_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str`**

* **功能:**  获取自定义目标（`target`）的输出目录路径。这个函数特别处理了 Xcode 后端的特殊情况，其中目标的输出目录结构与其它后端不同。
* **与逆向的关系:** 逆向工程师需要知道目标文件的输出位置才能进行分析。
* **与二进制底层的关系:**  输出目录是生成二进制文件存放的地方。
* **用户操作路径:**  后端需要知道自定义目标的输出目录来生成构建规则，以便将生成的文件放置在正确的位置。

**7. `get_normpath_target(self, source: str) -> str`**

* **功能:**  规范化给定的路径字符串（`source`），例如将 `a//b/./c` 转换为 `a/b/c`。
* **与逆向的关系:**  在处理文件路径时，规范化路径可以避免因路径表示不一致而导致的问题。
* **与二进制底层的关系:**  文件路径是操作系统访问二进制文件的关键。
* **逻辑推理:**
    * **假设输入:** 字符串 `"path/../to//file.txt"`
    * **预期输出:** 字符串 `"to/file.txt"`
* **用户操作路径:**  在处理用户提供的或从 `meson.build` 文件解析出的路径时，后端可能会调用此函数来确保路径的规范性。

**8. `get_custom_target_dirs(self, target: build.CustomTarget, compiler: 'Compiler', *, absolute_path: bool = False) -> T.List[str]`**

* **功能:**  获取自定义目标（`target`）的头文件搜索目录列表。这些目录包括由自定义目标生成的其他自定义目标的输出目录。
* **与逆向的关系:**  了解头文件搜索路径对于理解程序如何找到包含的头文件以及如何进行编译至关重要。
* **与二进制底层的关系:**  头文件包含了编译所需的类型定义和函数声明。
* **逻辑推理:**
    * **假设输入:** 一个自定义目标 `A` 生成了一些头文件，另一个自定义目标 `B` 依赖于 `A`，并需要包含 `A` 生成的头文件。
    * **预期输出:**  一个包含自定义目标 `A` 的输出目录路径的列表。
* **用户操作路径:**  当一个自定义目标生成头文件，并且另一个目标需要包含这些头文件时，Meson 会使用此函数来设置正确的头文件搜索路径。

**9. `get_custom_target_dir_include_args(self, target: build.CustomTarget, compiler: 'Compiler', *, absolute_path: bool = False) -> T.List[str]`**

* **功能:**  获取用于指定自定义目标（`target`）的头文件搜索目录的编译器参数列表（例如，`-I/path/to/headers`）。
* **与逆向的关系:**  类似于上一个函数，它直接关系到编译过程中的头文件查找。
* **与二进制底层的关系:**  编译器参数直接影响二进制文件的生成。
* **用户操作路径:**  在生成编译命令时，后端会调用此函数来获取正确的头文件搜索路径参数。

**10. `eval_custom_target_command(self, target: build.CustomTarget, absolute_outputs: bool = False) -> T.Tuple[T.List[str], T.List[str], T.List[str]]`**

* **功能:**  评估自定义目标（`target`）的命令列表，并返回输入文件列表、输出文件列表和最终的命令列表（已替换了模板字符串）。
* **与逆向的关系:**  自定义目标的命令可能包含用于生成代码、处理二进制文件或执行其他与逆向相关的任务的工具。
    * **举例:**  自定义命令可能调用 `objdump` 来分析一个目标文件。
* **与二进制底层的关系:**  此函数处理生成二进制文件的具体命令。
* **与 Linux, Android 内核及框架的知识的关系:**  自定义命令可能会调用与内核或框架交互的工具，例如用于编译 Android AIDL 文件的命令。
* **逻辑推理:**
    * **假设输入:** 一个自定义目标，其命令为 `['python', 'my_script.py', '@INPUT@', '@OUTPUT@']`，输入文件为 `input.txt`，输出文件为 `output.txt`。
    * **预期输出:**  输入文件列表 `['input.txt']`，输出文件列表 `['output.txt']`，命令列表 `['python', 'my_script.py', 'input.txt', 'output.txt']`。
* **常见用户错误:**
    * **错误的命令语法:**  用户可能在 `meson.build` 文件中编写了错误的命令语法。
    * **模板字符串使用错误:**  用户可能错误地使用了 `@INPUT@`, `@OUTPUT@` 等模板字符串。
    * **依赖缺失:** 自定义命令依赖的外部程序可能没有安装或不在 PATH 环境变量中。
* **用户操作路径:**  用户在 `meson.build` 文件中定义一个自定义目标，并指定其执行的命令。后端在构建过程中需要执行这些命令，因此会调用此函数来获取可执行的命令列表。

**11. `get_introspect_command(self) -> str`**

* **功能:**  返回用于 Meson 自省（introspection）的完整命令字符串。
* **与逆向的关系:**  Meson 的自省功能可以提供关于构建过程的详细信息，这对于理解构建结构和依赖关系很有用。
* **用户操作路径:** 当用户运行 `meson introspect` 命令时，后端会使用此函数来构建实际执行的命令。

**12. `get_run_target_env(self, target: build.RunTarget) -> mesonlib.EnvironmentVariables`**

* **功能:**  获取运行目标（`RunTarget`）所需的运行时环境变量。
* **与逆向的关系:**  运行时环境变量可以影响程序的行为。理解运行目标的环境变量对于调试和分析其行为很重要。
    * **举例:**  一个运行目标可能需要设置 `LD_LIBRARY_PATH` 才能找到所需的动态库。
* **与 Linux, Android 内核及框架的知识的关系:**  环境变量如 `LD_LIBRARY_PATH` 在 Linux 系统中用于指定动态库的搜索路径。
* **用户操作路径:**  当用户定义一个运行目标并在构建后执行它时，后端会使用此函数来设置运行环境。

**13. `run_postconf_scripts(self) -> None`**

* **功能:**  执行构建配置后脚本（postconf scripts）。
* **与逆向的关系:**  配置后脚本可以执行一些最终的配置步骤，这些步骤可能会影响最终生成的可执行文件或库。
* **用户操作路径:** 用户可以在 `meson.build` 文件中定义配置后脚本。在配置阶段结束后，后端会调用此函数来执行这些脚本.

**14. `create_install_data(self) -> InstallData`**

* **功能:**  创建一个包含所有安装数据（目标文件、头文件、man 页面等）的 `InstallData` 对象。
* **与逆向的关系:**  安装数据包含了最终安装到系统中的所有文件，逆向工程师需要知道这些文件的位置。
* **用户操作路径:**  当用户运行 `meson install` 命令时，后端会调用此函数来收集需要安装的所有文件信息。

**15. `create_install_data_files(self) -> None`**

* **功能:**  将 `create_install_data` 生成的 `InstallData` 对象序列化到文件中。
* **用户操作路径:**  这是安装过程中的一个中间步骤，用于保存安装信息。

**16. `guess_install_tag(self, fname: str, outdir: T.Optional[str] = None) -> T.Optional[str]`**

* **功能:**  根据文件名和输出目录猜测安装标签（例如，`runtime`, `devel`, `i18n`）。
* **与逆向的关系:**  安装标签可以帮助区分不同类型的文件，例如运行时库和开发头文件。
* **逻辑推理:**
    * **假设输入:** 文件名 `libmylib.so`，输出目录 `/usr/lib`.
    * **预期输出:** `'runtime'`.
    * **假设输入:** 文件名 `mylib.h`，输出目录 `/usr/include`.
    * **预期输出:** `'devel'`.
* **用户操作路径:**  在生成安装清单时，如果目标没有明确指定安装标签，后端会尝试猜测。

**17. `generate_target_install(self, d: InstallData) -> None`**

* **功能:**  将构建目标（例如，可执行文件、库）的安装信息添加到 `InstallData` 对象中。
* **与逆向的关系:**  确定哪些目标文件会被安装以及安装到哪里。
* **用户操作路径:**  作为 `create_install_data` 的一部分被调用。

**18. `generate_custom_install_script(self, d: InstallData) -> None`**

* **功能:**  将自定义安装脚本的信息添加到 `InstallData` 对象中。
* **用户操作路径:**  作为 `create_install_data` 的一部分被调用。

**19. `generate_header_install(self, d: InstallData) -> None`**

* **功能:**  将头文件的安装信息添加到 `InstallData` 对象中。
* **与逆向的关系:**  头文件对于理解库的接口至关重要。
* **用户操作路径:**  作为 `create_install_data` 的一部分被调用。

**20. `generate_man_install(self, d: InstallData) -> None`**

* **功能:**  将 man 页面的安装信息添加到 `InstallData` 对象中。
* **用户操作路径:**  作为 `create_install_data` 的一部分被调用。

**21. `generate_emptydir_install(self, d: InstallData) -> None`**

* **功能:**  将需要创建的空目录的安装信息添加到 `InstallData` 对象中。
* **用户操作路径:**  作为 `create_install_data` 的一部分被调用。

**22. `generate_data_install(self, d: InstallData) -> None`**

* **功能:**  将数据文件的安装信息添加到 `InstallData` 对象中。
* **用户操作路径:**  作为 `create_install_data` 的一部分被调用。

**23. `generate_symlink_install(self, d: InstallData) -> None`**

* **功能:**  将符号链接的安装信息添加到 `InstallData` 对象中。
* **用户操作路径:**  作为 `create_install_data` 的一部分被调用。

**24. `generate_subdir_install(self, d: InstallData) -> None`**

* **功能:**  将需要安装的子目录的信息添加到 `InstallData` 对象中。
* **用户操作路径:**  作为 `create_install_data` 的一部分被调用。

**25. `get_introspection_data(self, target_id: str, target: build.Target) -> T.List['TargetIntrospectionData']`**

* **功能:**  返回给定目标的自省数据，包括语言、编译器、参数和源文件列表。这是一个基础实现，后端应该覆盖它以提供更详细的信息。
* **与逆向的关系:**  提供构建目标的详细编译信息，有助于理解目标的构建过程和所使用的工具。
* **用户操作路径:**  当用户请求特定目标的自省信息时（例如，使用 `meson introspect --target <target_name>`），会调用此函数。

**26. `get_devenv(self) -> mesonlib.EnvironmentVariables`**

* **功能:**  获取开发环境所需的额外环境变量，例如用于查找本地构建的库和可执行文件的路径。
* **与逆向的关系:**  方便在开发环境中运行和调试本地构建的可执行文件和库。
* **与 Linux, Android 内核及框架的知识的关系:**  涉及到如 `PATH`, `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH` 等环境变量的管理。
* **用户操作路径:**  当用户激活 Meson 的开发环境时，会调用此函数来设置环境变量。

**27. `compiler_to_generator(self, target: build.BuildTarget, compiler: 'Compiler', sources: _ALL_SOURCES_TYPE, output_templ: str, depends: T.Optional[T.List[T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]]] = None) -> build.GeneratedList`**

* **功能:**  对于不支持自定义编译器的后端，提供一个方便的方法来将编译器调用转换为生成器（generator）。

**总结一下它的功能:**

这个代码片段是 Meson 构建系统后端的核心部分，它定义了处理构建目标、依赖关系、源文件、自定义命令和安装过程的通用逻辑。它负责将 Meson 的抽象构建描述转换为特定构建系统所需的具体信息。这包括：

* **管理构建目标的依赖关系。**
* **处理自定义目标的源文件和输出。**
* **评估自定义目标的执行命令。**
* **生成安装数据，包括目标文件、头文件、数据文件等。**
* **提供构建过程的自省信息。**
* **管理开发环境的环境变量。**

这些功能对于 Frida 这样的动态 Instrumentation 工具至关重要，因为它需要构建和管理各种组件，包括 gum 库本身以及用于目标进程注入和代码执行的组件。理解这些构建过程对于逆向分析 Frida 本身或使用 Frida 进行逆向分析都是很有帮助的。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/backend/backends.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
= arg
            for dep in t.depends:
                assert isinstance(dep, (build.CustomTarget, build.BuildTarget))
                result[dep.get_id()] = dep
        return result

    @lru_cache(maxsize=None)
    def get_custom_target_provided_by_generated_source(self, generated_source: build.CustomTarget) -> 'ImmutableListProtocol[str]':
        libs: T.List[str] = []
        for f in generated_source.get_outputs():
            if self.environment.is_library(f):
                libs.append(os.path.join(self.get_target_dir(generated_source), f))
        return libs

    @lru_cache(maxsize=None)
    def get_custom_target_provided_libraries(self, target: T.Union[build.BuildTarget, build.CustomTarget]) -> 'ImmutableListProtocol[str]':
        libs: T.List[str] = []
        for t in target.get_generated_sources():
            if not isinstance(t, build.CustomTarget):
                continue
            libs.extend(self.get_custom_target_provided_by_generated_source(t))
        return libs

    def get_custom_target_sources(self, target: build.CustomTarget) -> T.List[str]:
        '''
        Custom target sources can be of various object types; strings, File,
        BuildTarget, even other CustomTargets.
        Returns the path to them relative to the build root directory.
        '''
        srcs: T.List[str] = []
        for i in target.get_sources():
            if isinstance(i, str):
                fname = [os.path.join(self.build_to_src, target.get_source_subdir(), i)]
            elif isinstance(i, build.BuildTarget):
                fname = [self.get_target_filename(i)]
            elif isinstance(i, (build.CustomTarget, build.CustomTargetIndex)):
                fname = [os.path.join(self.get_custom_target_output_dir(i), p) for p in i.get_outputs()]
            elif isinstance(i, build.GeneratedList):
                fname = [os.path.join(self.get_target_private_dir(target), p) for p in i.get_outputs()]
            elif isinstance(i, build.ExtractedObjects):
                fname = self.determine_ext_objs(i)
            elif isinstance(i, programs.ExternalProgram):
                assert i.found(), "This shouldn't be possible"
                assert i.path is not None, 'for mypy'
                fname = [i.path]
            else:
                fname = [i.rel_to_builddir(self.build_to_src)]
            if target.absolute_paths:
                fname = [os.path.join(self.environment.get_build_dir(), f) for f in fname]
            srcs += fname
        return srcs

    def get_target_depend_files(self, target: T.Union[build.CustomTarget, build.BuildTarget], absolute_paths: bool = False) -> T.List[str]:
        deps: T.List[str] = []
        for i in target.depend_files:
            if isinstance(i, mesonlib.File):
                if absolute_paths:
                    deps.append(i.absolute_path(self.environment.get_source_dir(),
                                                self.environment.get_build_dir()))
                else:
                    deps.append(i.rel_to_builddir(self.build_to_src))
            else:
                if absolute_paths:
                    deps.append(os.path.join(self.environment.get_source_dir(), target.get_output_subdir(), i))
                else:
                    deps.append(os.path.join(self.build_to_src, target.get_output_subdir(), i))
        return deps

    def get_custom_target_output_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        # The XCode backend is special. A target foo/bar does
        # not go to ${BUILDDIR}/foo/bar but instead to
        # ${BUILDDIR}/${BUILDTYPE}/foo/bar.
        # Currently we set the include dir to be the former,
        # and not the latter. Thus we need this extra customisation
        # point. If in the future we make include dirs et al match
        # ${BUILDDIR}/${BUILDTYPE} instead, this becomes unnecessary.
        return self.get_target_dir(target)

    @lru_cache(maxsize=None)
    def get_normpath_target(self, source: str) -> str:
        return os.path.normpath(source)

    def get_custom_target_dirs(self, target: build.CustomTarget, compiler: 'Compiler', *,
                               absolute_path: bool = False) -> T.List[str]:
        custom_target_include_dirs: T.List[str] = []
        for i in target.get_generated_sources():
            # Generator output goes into the target private dir which is
            # already in the include paths list. Only custom targets have their
            # own target build dir.
            if not isinstance(i, (build.CustomTarget, build.CustomTargetIndex)):
                continue
            idir = self.get_normpath_target(self.get_custom_target_output_dir(i))
            if not idir:
                idir = '.'
            if absolute_path:
                idir = os.path.join(self.environment.get_build_dir(), idir)
            if idir not in custom_target_include_dirs:
                custom_target_include_dirs.append(idir)
        return custom_target_include_dirs

    def get_custom_target_dir_include_args(
            self, target: build.CustomTarget, compiler: 'Compiler', *,
            absolute_path: bool = False) -> T.List[str]:
        incs: T.List[str] = []
        for i in self.get_custom_target_dirs(target, compiler, absolute_path=absolute_path):
            incs += compiler.get_include_args(i, False)
        return incs

    def eval_custom_target_command(
            self, target: build.CustomTarget, absolute_outputs: bool = False) -> \
            T.Tuple[T.List[str], T.List[str], T.List[str]]:
        # We want the outputs to be absolute only when using the VS backend
        # XXX: Maybe allow the vs backend to use relative paths too?
        source_root = self.build_to_src
        build_root = '.'
        outdir = self.get_custom_target_output_dir(target)
        if absolute_outputs:
            source_root = self.environment.get_source_dir()
            build_root = self.environment.get_build_dir()
            outdir = os.path.join(self.environment.get_build_dir(), outdir)
        outputs = [os.path.join(outdir, i) for i in target.get_outputs()]
        inputs = self.get_custom_target_sources(target)
        # Evaluate the command list
        cmd: T.List[str] = []
        for i in target.command:
            if isinstance(i, build.BuildTarget):
                cmd += self.build_target_to_cmd_array(i)
                continue
            elif isinstance(i, build.CustomTarget):
                # GIR scanner will attempt to execute this binary but
                # it assumes that it is in path, so always give it a full path.
                tmp = i.get_outputs()[0]
                i = os.path.join(self.get_custom_target_output_dir(i), tmp)
            elif isinstance(i, mesonlib.File):
                i = i.rel_to_builddir(self.build_to_src)
                if target.absolute_paths or absolute_outputs:
                    i = os.path.join(self.environment.get_build_dir(), i)
            # FIXME: str types are blindly added ignoring 'target.absolute_paths'
            # because we can't know if they refer to a file or just a string
            elif isinstance(i, str):
                if '@SOURCE_ROOT@' in i:
                    i = i.replace('@SOURCE_ROOT@', source_root)
                if '@BUILD_ROOT@' in i:
                    i = i.replace('@BUILD_ROOT@', build_root)
                if '@CURRENT_SOURCE_DIR@' in i:
                    i = i.replace('@CURRENT_SOURCE_DIR@', os.path.join(source_root, target.get_source_subdir()))
                if '@DEPFILE@' in i:
                    if target.depfile is None:
                        msg = f'Custom target {target.name!r} has @DEPFILE@ but no depfile ' \
                              'keyword argument.'
                        raise MesonException(msg)
                    dfilename = os.path.join(outdir, target.depfile)
                    i = i.replace('@DEPFILE@', dfilename)
                if '@PRIVATE_DIR@' in i:
                    if target.absolute_paths:
                        pdir = self.get_target_private_dir_abs(target)
                    else:
                        pdir = self.get_target_private_dir(target)
                    i = i.replace('@PRIVATE_DIR@', pdir)
            else:
                raise RuntimeError(f'Argument {i} is of unknown type {type(i)}')
            cmd.append(i)
        # Substitute the rest of the template strings
        values = mesonlib.get_filenames_templates_dict(inputs, outputs)
        cmd = mesonlib.substitute_values(cmd, values)
        # This should not be necessary but removing it breaks
        # building GStreamer on Windows. The underlying issue
        # is problems with quoting backslashes on Windows
        # which is the seventh circle of hell. The downside is
        # that this breaks custom targets whose command lines
        # have backslashes. If you try to fix this be sure to
        # check that it does not break GST.
        #
        # The bug causes file paths such as c:\foo to get escaped
        # into c:\\foo.
        #
        # Unfortunately we have not been able to come up with an
        # isolated test case for this so unless you manage to come up
        # with one, the only way is to test the building with Gst's
        # setup. Note this in your MR or ping us and we will get it
        # fixed.
        #
        # https://github.com/mesonbuild/meson/pull/737
        cmd = [i.replace('\\', '/') for i in cmd]
        return inputs, outputs, cmd

    def get_introspect_command(self) -> str:
        return ' '.join(shlex.quote(x) for x in self.environment.get_build_command() + ['introspect'])

    def get_run_target_env(self, target: build.RunTarget) -> mesonlib.EnvironmentVariables:
        env = target.env if target.env else mesonlib.EnvironmentVariables()
        if target.default_env:
            env.set('MESON_SOURCE_ROOT', [self.environment.get_source_dir()])
            env.set('MESON_BUILD_ROOT', [self.environment.get_build_dir()])
            env.set('MESON_SUBDIR', [target.get_source_subdir()])
            env.set('MESONINTROSPECT', [self.get_introspect_command()])
        return env

    def run_postconf_scripts(self) -> None:
        from ..scripts.meson_exe import run_exe
        env = {'MESON_SOURCE_ROOT': self.environment.get_source_dir(),
               'MESON_BUILD_ROOT': self.environment.get_build_dir(),
               'MESONINTROSPECT': self.get_introspect_command(),
               }

        for s in self.build.postconf_scripts:
            name = ' '.join(s.cmd_args)
            mlog.log(f'Running postconf script {name!r}')
            rc = run_exe(s, env)
            if rc != 0:
                raise MesonException(f'Postconf script \'{name}\' failed with exit code {rc}.')

    def create_install_data(self) -> InstallData:
        strip_bin = self.environment.lookup_binary_entry(MachineChoice.HOST, 'strip')
        if strip_bin is None:
            if self.environment.is_cross_build():
                mlog.warning('Cross file does not specify strip binary, result will not be stripped.')
            else:
                # TODO go through all candidates, like others
                strip_bin = [detect.defaults['strip'][0]]

        umask = self.environment.coredata.get_option(OptionKey('install_umask'))
        assert isinstance(umask, (str, int)), 'for mypy'

        d = InstallData(self.environment.get_source_dir(),
                        self.environment.get_build_dir(),
                        self.environment.get_prefix(),
                        self.environment.get_libdir(),
                        strip_bin,
                        umask,
                        self.environment.get_build_command() + ['introspect'],
                        self.environment.coredata.version)
        self.generate_depmf_install(d)
        self.generate_target_install(d)
        self.generate_header_install(d)
        self.generate_man_install(d)
        self.generate_emptydir_install(d)
        self.generate_data_install(d)
        self.generate_symlink_install(d)
        self.generate_custom_install_script(d)
        self.generate_subdir_install(d)
        return d

    def create_install_data_files(self) -> None:
        install_data_file = os.path.join(self.environment.get_scratch_dir(), 'install.dat')
        with open(install_data_file, 'wb') as ofile:
            pickle.dump(self.create_install_data(), ofile)

    def guess_install_tag(self, fname: str, outdir: T.Optional[str] = None) -> T.Optional[str]:
        prefix = self.environment.get_prefix()
        bindir = Path(prefix, self.environment.get_bindir())
        libdir = Path(prefix, self.environment.get_libdir())
        incdir = Path(prefix, self.environment.get_includedir())
        _ldir = self.environment.coredata.get_option(mesonlib.OptionKey('localedir'))
        assert isinstance(_ldir, str), 'for mypy'
        localedir = Path(prefix, _ldir)
        dest_path = Path(prefix, outdir, Path(fname).name) if outdir else Path(prefix, fname)
        if bindir in dest_path.parents:
            return 'runtime'
        elif libdir in dest_path.parents:
            if dest_path.suffix in {'.a', '.pc'}:
                return 'devel'
            elif dest_path.suffix in {'.so', '.dll'}:
                return 'runtime'
        elif incdir in dest_path.parents:
            return 'devel'
        elif localedir in dest_path.parents:
            return 'i18n'
        elif 'installed-tests' in dest_path.parts:
            return 'tests'
        elif 'systemtap' in dest_path.parts:
            return 'systemtap'
        mlog.debug('Failed to guess install tag for', dest_path)
        return None

    def generate_target_install(self, d: InstallData) -> None:
        for t in self.build.get_targets().values():
            if not t.should_install():
                continue
            outdirs, install_dir_names, custom_install_dir = t.get_install_dir()
            # Sanity-check the outputs and install_dirs
            num_outdirs, num_out = len(outdirs), len(t.get_outputs())
            if num_outdirs not in {1, num_out}:
                m = 'Target {!r} has {} outputs: {!r}, but only {} "install_dir"s were found.\n' \
                    "Pass 'false' for outputs that should not be installed and 'true' for\n" \
                    'using the default installation directory for an output.'
                raise MesonException(m.format(t.name, num_out, t.get_outputs(), num_outdirs))
            assert len(t.install_tag) == num_out
            install_mode = t.get_custom_install_mode()
            # because mypy gets confused type narrowing in lists
            first_outdir = outdirs[0]
            first_outdir_name = install_dir_names[0]

            # Install the target output(s)
            if isinstance(t, build.BuildTarget):
                # In general, stripping static archives is tricky and full of pitfalls.
                # Wholesale stripping of static archives with a command such as
                #
                #   strip libfoo.a
                #
                # is broken, as GNU's strip will remove *every* symbol in a static
                # archive. One solution to this nonintuitive behaviour would be
                # to only strip local/debug symbols. Unfortunately, strip arguments
                # are not specified by POSIX and therefore not portable. GNU's `-g`
                # option (i.e. remove debug symbols) is equivalent to Apple's `-S`.
                #
                # TODO: Create GNUStrip/AppleStrip/etc. hierarchy for more
                #       fine-grained stripping of static archives.
                can_strip = not isinstance(t, build.StaticLibrary)
                should_strip = can_strip and t.get_option(OptionKey('strip'))
                assert isinstance(should_strip, bool), 'for mypy'
                # Install primary build output (library/executable/jar, etc)
                # Done separately because of strip/aliases/rpath
                if first_outdir is not False:
                    tag = t.install_tag[0] or ('devel' if isinstance(t, build.StaticLibrary) else 'runtime')
                    mappings = t.get_link_deps_mapping(d.prefix)
                    i = TargetInstallData(self.get_target_filename(t), first_outdir,
                                          first_outdir_name,
                                          should_strip, mappings, t.rpath_dirs_to_remove,
                                          t.install_rpath, install_mode, t.subproject,
                                          tag=tag, can_strip=can_strip)
                    d.targets.append(i)

                    for alias, to, tag in t.get_aliases():
                        alias = os.path.join(first_outdir, alias)
                        s = InstallSymlinkData(to, alias, first_outdir, t.subproject, tag, allow_missing=True)
                        d.symlinks.append(s)

                    if isinstance(t, (build.SharedLibrary, build.SharedModule, build.Executable)):
                        # On toolchains/platforms that use an import library for
                        # linking (separate from the shared library with all the
                        # code), we need to install that too (dll.a/.lib).
                        if t.get_import_filename():
                            if custom_install_dir:
                                # If the DLL is installed into a custom directory,
                                # install the import library into the same place so
                                # it doesn't go into a surprising place
                                implib_install_dir = first_outdir
                            else:
                                implib_install_dir = self.environment.get_import_lib_dir()
                            # Install the import library; may not exist for shared modules
                            i = TargetInstallData(self.get_target_filename_for_linking(t),
                                                  implib_install_dir, first_outdir_name,
                                                  False, {}, set(), '', install_mode,
                                                  t.subproject, optional=isinstance(t, build.SharedModule),
                                                  tag='devel')
                            d.targets.append(i)

                        if not should_strip and t.get_debug_filename():
                            debug_file = os.path.join(self.get_target_dir(t), t.get_debug_filename())
                            i = TargetInstallData(debug_file, first_outdir,
                                                  first_outdir_name,
                                                  False, {}, set(), '',
                                                  install_mode, t.subproject,
                                                  optional=True, tag='devel')
                            d.targets.append(i)
                # Install secondary outputs. Only used for Vala right now.
                if num_outdirs > 1:
                    for output, outdir, outdir_name, tag in zip(t.get_outputs()[1:], outdirs[1:], install_dir_names[1:], t.install_tag[1:]):
                        # User requested that we not install this output
                        if outdir is False:
                            continue
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdir, outdir_name, False, {}, set(), None,
                                              install_mode, t.subproject,
                                              tag=tag)
                        d.targets.append(i)
            elif isinstance(t, build.CustomTarget):
                # If only one install_dir is specified, assume that all
                # outputs will be installed into it. This is for
                # backwards-compatibility and because it makes sense to
                # avoid repetition since this is a common use-case.
                #
                # To selectively install only some outputs, pass `false` as
                # the install_dir for the corresponding output by index
                #
                # XXX: this wouldn't be needed if we just always matches outdirs
                # to the length of outputs…
                if num_outdirs == 1 and num_out > 1:
                    if first_outdir is not False:
                        for output, tag in zip(t.get_outputs(), t.install_tag):
                            tag = tag or self.guess_install_tag(output, first_outdir)
                            f = os.path.join(self.get_target_dir(t), output)
                            i = TargetInstallData(f, first_outdir, first_outdir_name,
                                                  False, {}, set(), None, install_mode,
                                                  t.subproject, optional=not t.build_by_default,
                                                  tag=tag)
                            d.targets.append(i)
                else:
                    for output, outdir, outdir_name, tag in zip(t.get_outputs(), outdirs, install_dir_names, t.install_tag):
                        # User requested that we not install this output
                        if outdir is False:
                            continue
                        tag = tag or self.guess_install_tag(output, outdir)
                        f = os.path.join(self.get_target_dir(t), output)
                        i = TargetInstallData(f, outdir, outdir_name,
                                              False, {}, set(), None, install_mode,
                                              t.subproject, optional=not t.build_by_default,
                                              tag=tag)
                        d.targets.append(i)

    def generate_custom_install_script(self, d: InstallData) -> None:
        d.install_scripts = self.build.install_scripts
        for i in d.install_scripts:
            if not i.tag:
                mlog.debug('Failed to guess install tag for install script:', ' '.join(i.cmd_args))

    def generate_header_install(self, d: InstallData) -> None:
        incroot = self.environment.get_includedir()
        headers = self.build.get_headers()

        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for h in headers:
            outdir = outdir_name = h.get_custom_install_dir()
            if outdir is None:
                subdir = h.get_install_subdir()
                if subdir is None:
                    outdir = incroot
                    outdir_name = '{includedir}'
                else:
                    outdir = os.path.join(incroot, subdir)
                    outdir_name = os.path.join('{includedir}', subdir)

            for f in h.get_sources():
                abspath = f.absolute_path(srcdir, builddir)
                i = InstallDataBase(abspath, outdir, outdir_name, h.get_custom_install_mode(), h.subproject, tag='devel', follow_symlinks=h.follow_symlinks)
                d.headers.append(i)

    def generate_man_install(self, d: InstallData) -> None:
        manroot = self.environment.get_mandir()
        man = self.build.get_man()
        for m in man:
            for f in m.get_sources():
                num = f.split('.')[-1]
                subdir = m.get_custom_install_dir()
                if subdir is None:
                    if m.locale:
                        subdir = os.path.join('{mandir}', m.locale, 'man' + num)
                    else:
                        subdir = os.path.join('{mandir}', 'man' + num)
                fname = f.fname
                if m.locale: # strip locale from file name
                    fname = fname.replace(f'.{m.locale}', '')
                srcabs = f.absolute_path(self.environment.get_source_dir(), self.environment.get_build_dir())
                dstname = os.path.join(subdir, os.path.basename(fname))
                dstabs = dstname.replace('{mandir}', manroot)
                i = InstallDataBase(srcabs, dstabs, dstname, m.get_custom_install_mode(), m.subproject, tag='man')
                d.man.append(i)

    def generate_emptydir_install(self, d: InstallData) -> None:
        emptydir: T.List[build.EmptyDir] = self.build.get_emptydir()
        for e in emptydir:
            tag = e.install_tag or self.guess_install_tag(e.path)
            i = InstallEmptyDir(e.path, e.install_mode, e.subproject, tag)
            d.emptydir.append(i)

    def generate_data_install(self, d: InstallData) -> None:
        data = self.build.get_data()
        srcdir = self.environment.get_source_dir()
        builddir = self.environment.get_build_dir()
        for de in data:
            assert isinstance(de, build.Data)
            subdir = de.install_dir
            subdir_name = de.install_dir_name
            for src_file, dst_name in zip(de.sources, de.rename):
                assert isinstance(src_file, mesonlib.File)
                dst_abs = os.path.join(subdir, dst_name)
                dstdir_name = os.path.join(subdir_name, dst_name)
                tag = de.install_tag or self.guess_install_tag(dst_abs)
                i = InstallDataBase(src_file.absolute_path(srcdir, builddir), dst_abs, dstdir_name,
                                    de.install_mode, de.subproject, tag=tag, data_type=de.data_type,
                                    follow_symlinks=de.follow_symlinks)
                d.data.append(i)

    def generate_symlink_install(self, d: InstallData) -> None:
        links: T.List[build.SymlinkData] = self.build.get_symlinks()
        for l in links:
            assert isinstance(l, build.SymlinkData)
            install_dir = l.install_dir
            name_abs = os.path.join(install_dir, l.name)
            tag = l.install_tag or self.guess_install_tag(name_abs)
            s = InstallSymlinkData(l.target, name_abs, install_dir, l.subproject, tag)
            d.symlinks.append(s)

    def generate_subdir_install(self, d: InstallData) -> None:
        for sd in self.build.get_install_subdirs():
            if sd.from_source_dir:
                from_dir = self.environment.get_source_dir()
            else:
                from_dir = self.environment.get_build_dir()
            src_dir = os.path.join(from_dir,
                                   sd.source_subdir,
                                   sd.installable_subdir).rstrip('/')
            dst_dir = os.path.join(self.environment.get_prefix(),
                                   sd.install_dir)
            dst_name = os.path.join('{prefix}', sd.install_dir)
            if sd.install_dir != sd.install_dir_name:
                dst_name = sd.install_dir_name
            if not sd.strip_directory:
                dst_dir = os.path.join(dst_dir, os.path.basename(src_dir))
                dst_name = os.path.join(dst_name, os.path.basename(src_dir))
            tag = sd.install_tag or self.guess_install_tag(os.path.join(sd.install_dir, 'dummy'))
            i = SubdirInstallData(src_dir, dst_dir, dst_name, sd.install_mode, sd.exclude, sd.subproject, tag,
                                  follow_symlinks=sd.follow_symlinks)
            d.install_subdirs.append(i)

    def get_introspection_data(self, target_id: str, target: build.Target) -> T.List['TargetIntrospectionData']:
        '''
        Returns a list of source dicts with the following format for a given target:
        [
            {
                "language": "<LANG>",
                "compiler": ["result", "of", "comp.get_exelist()"],
                "parameters": ["list", "of", "compiler", "parameters],
                "sources": ["list", "of", "all", "<LANG>", "source", "files"],
                "generated_sources": ["list", "of", "generated", "source", "files"]
            }
        ]

        This is a limited fallback / reference implementation. The backend should override this method.
        '''
        if isinstance(target, (build.CustomTarget, build.BuildTarget)):
            source_list_raw = target.sources
            source_list = []
            for j in source_list_raw:
                if isinstance(j, mesonlib.File):
                    source_list += [j.absolute_path(self.source_dir, self.build_dir)]
                elif isinstance(j, str):
                    source_list += [os.path.join(self.source_dir, j)]
                elif isinstance(j, (build.CustomTarget, build.BuildTarget)):
                    source_list += [os.path.join(self.build_dir, j.get_output_subdir(), o) for o in j.get_outputs()]
            source_list = [os.path.normpath(s) for s in source_list]

            compiler: T.List[str] = []
            if isinstance(target, build.CustomTarget):
                tmp_compiler = target.command
                for j in tmp_compiler:
                    if isinstance(j, mesonlib.File):
                        compiler += [j.absolute_path(self.source_dir, self.build_dir)]
                    elif isinstance(j, str):
                        compiler += [j]
                    elif isinstance(j, (build.BuildTarget, build.CustomTarget)):
                        compiler += j.get_outputs()
                    else:
                        raise RuntimeError(f'Type "{type(j).__name__}" is not supported in get_introspection_data. This is a bug')

            return [{
                'language': 'unknown',
                'compiler': compiler,
                'parameters': [],
                'sources': source_list,
                'generated_sources': []
            }]

        return []

    def get_devenv(self) -> mesonlib.EnvironmentVariables:
        env = mesonlib.EnvironmentVariables()
        extra_paths = set()
        library_paths = set()
        build_machine = self.environment.machines[MachineChoice.BUILD]
        host_machine = self.environment.machines[MachineChoice.HOST]
        need_wine = not build_machine.is_windows() and host_machine.is_windows()
        for t in self.build.get_targets().values():
            in_default_dir = t.should_install() and not t.get_install_dir()[2]
            if t.for_machine != MachineChoice.HOST or not in_default_dir:
                continue
            tdir = os.path.join(self.environment.get_build_dir(), self.get_target_dir(t))
            if isinstance(t, build.Executable):
                # Add binaries that are going to be installed in bindir into PATH
                # so they get used by default instead of searching on system when
                # in developer environment.
                extra_paths.add(tdir)
                if host_machine.is_windows() or host_machine.is_cygwin():
                    # On windows we cannot rely on rpath to run executables from build
                    # directory. We have to add in PATH the location of every DLL needed.
                    library_paths.update(self.determine_windows_extra_paths(t, []))
            elif isinstance(t, build.SharedLibrary):
                # Add libraries that are going to be installed in libdir into
                # LD_LIBRARY_PATH. This allows running system applications using
                # that library.
                library_paths.add(tdir)
        if need_wine:
            # Executable paths should be in both PATH and WINEPATH.
            # - Having them in PATH makes bash completion find it,
            #   and make running "foo.exe" find it when wine-binfmt is installed.
            # - Having them in WINEPATH makes "wine foo.exe" find it.
            library_paths.update(extra_paths)
        if library_paths:
            if need_wine:
                env.prepend('WINEPATH', list(library_paths), separator=';')
            elif host_machine.is_windows() or host_machine.is_cygwin():
                extra_paths.update(library_paths)
            elif host_machine.is_darwin():
                env.prepend('DYLD_LIBRARY_PATH', list(library_paths))
            else:
                env.prepend('LD_LIBRARY_PATH', list(library_paths))
        if extra_paths:
            env.prepend('PATH', list(extra_paths))
        return env

    def compiler_to_generator(self, target: build.BuildTarget,
                              compiler: 'Compiler',
                              sources: _ALL_SOURCES_TYPE,
                              output_templ: str,
                              depends: T.Optional[T.List[T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]]] = None,
                              ) -> build.GeneratedList:
        '''
        Some backends don't support custom compilers. This is a convenience
        method to conve
"""


```