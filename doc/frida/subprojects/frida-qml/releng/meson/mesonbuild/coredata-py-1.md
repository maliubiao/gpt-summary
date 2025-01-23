Response:
My thought process for analyzing the `coredata.py` file goes through these stages:

1. **Understanding the Goal:** The request is to understand the *functionality* of this specific Python file within the larger Frida project. I need to identify what tasks this file handles, its relationship to reverse engineering (Frida's domain), and any connections to low-level concepts.

2. **Initial Code Scan and Keyword Identification:** I quickly scan the code, looking for recognizable patterns and keywords. Things that jump out are:
    * **Imports:** `configparser`, `os`, `pickle`, `argparse`, `shlex`, which suggest handling configuration files, file system operations, serialization, command-line arguments, and shell commands.
    * **Class Names:** `CoreData`, `BuiltinOption`, `CmdLineFileParser`, `MachineFileParser`. These are key structures I need to understand.
    * **Function Names:**  Many functions relate to "options" (`add_builtin_option`, `init_backend_options`, `get_option`, `set_option`, `set_options`, `set_default_options`, etc.). This strongly indicates the file is central to managing build configurations and settings. Other functions like `load`, `save`, `read_cmd_line_file`, and `parse_machine_files` point to data persistence and loading.
    * **Constants:** `BUILTIN_OPTIONS`, `BUILTIN_OPTIONS_PER_MACHINE`, `BUILTIN_DIR_OPTIONS`, `BUILTIN_CORE_OPTIONS`. These suggest predefined configuration settings.

3. **Focusing on Key Classes and Their Roles:**

    * **`CoreData`:** This seems like the central data structure. It holds build configuration information (`options`, `cross_files`, `native_files`, dependency information, caches). The methods within this class are about manipulating and accessing this data.
    * **`BuiltinOption`:**  This clearly represents a single configurable option with its type, description, default value, etc. It's a blueprint for creating option instances.
    * **`CmdLineFileParser`:**  This deals with parsing configuration files, likely those passed via the command line. The override of `optionxform` is interesting – it suggests a need to preserve the case of option names.
    * **`MachineFileParser`:** This parses machine-specific configuration files, possibly for cross-compilation setups. The handling of `@GLOBAL_SOURCE_ROOT@` and `@DIRNAME@` indicates path manipulation.

4. **Connecting to Frida and Reverse Engineering:** I now think about how these components relate to Frida's core purpose. Frida is a dynamic instrumentation toolkit. This means it needs to be configured for different target environments (OS, architecture, etc.). The "options" managed by this file are likely settings that control how Frida is built and how it interacts with target processes. Cross-compilation, a common need for targeting mobile or embedded devices, is explicitly handled. The options related to debugging (`debug`), optimization (`optimization`), and potentially compiler/linker flags are relevant to how Frida's components are built.

5. **Identifying Relationships to Low-Level Concepts:** Cross-compilation directly connects to different target architectures. The mention of "host machine" and "build machine" reinforces this. The presence of options like `libdir`, `includedir`, etc., indicates the file deals with standard build system concepts. The handling of linker processes (`backend_max_links`) points to the build process itself. While the code itself doesn't directly manipulate kernel code, the *purpose* of Frida (dynamic instrumentation) is deeply tied to OS internals and potentially kernel interactions. The "native file" likely refers to files defining the target environment for cross-compilation.

6. **Inferring Logic and Examples:** Based on the function names and data structures, I can infer the logic. For example, `set_option` validates and sets option values, potentially triggering deprecation warnings or errors. `get_option` retrieves option values. The `_set_others_from_buildtype` method shows a logical dependency between `buildtype` and other options like `optimization` and `debug`. I can then construct simple examples of how these functions might be used and the expected inputs/outputs.

7. **Considering User Errors and Debugging:**  The code includes error handling (e.g., `MesonException` for unknown options). The `read_cmd_line_file` and `write_cmd_line_file` functions suggest a mechanism for persisting and loading command-line options, which can be a source of errors if the file is corrupted or manually edited incorrectly. The step-by-step user action leading to this code involves configuring and building Frida, especially when using command-line options or cross-compilation.

8. **Structuring the Summary:** Finally, I organize my findings into the requested categories: functionality, relationship to reverse engineering, low-level aspects, logical inference, user errors, and debugging. I use the identified keywords, class roles, and inferred logic to create a coherent description of the file's purpose and how it fits into the larger Frida ecosystem.

By following these steps, I can systematically analyze the code snippet and arrive at a comprehensive understanding of its function and relevance to Frida's purpose. The iterative process of scanning, focusing, connecting, and inferring is crucial for understanding non-trivial codebases.
这是 `frida/subprojects/frida-qml/releng/meson/mesonbuild/coredata.py` 文件的第二部分，它主要负责**管理和处理 Meson 构建系统的核心数据，特别是关于构建选项（options）的管理**。

**归纳其功能如下：**

1. **内置选项管理:**
   - 加载和注册 Meson 的内置选项（`BUILTIN_OPTIONS`, `BUILTIN_OPTIONS_PER_MACHINE`），这些选项控制着构建过程的各个方面，如安装路径、构建类型、优化级别等。
   - 提供了添加内置选项的方法 (`add_builtin_option`)，可以根据目标机器的不同添加选项。

2. **后端选项初始化:**
   - 针对不同的构建后端（如 ninja, Visual Studio）初始化特定的选项 (`init_backend_options`)。例如，对于 ninja，可以设置最大链接器进程数。

3. **选项获取和设置:**
   - 提供了获取选项值的方法 (`get_option`)，可以获取内置选项的值。
   - 提供了设置选项值的方法 (`set_option`)，用于修改选项的值，并且会处理选项的废弃 (`deprecated`) 情况，并可能发出警告。
   - 在设置选项时，会处理一些特殊选项，如 `prefix`，并根据其值来调整其他路径相关的选项。

4. **构建类型相关选项同步:**
   - 提供根据 `buildtype` 选项自动设置其他相关选项（如 `optimization` 和 `debug`）的功能 (`_set_others_from_buildtype`)。

5. **外部参数管理:**
   - 允许获取和管理特定语言和目标机器的外部编译和链接参数 (`get_external_args`, `get_external_link_args`)。

6. **子项目选项管理:**
   - 提供了更新子项目选项的方法 (`update_project_options`)，确保子项目的选项被正确设置，并防止子项目修改其他项目的选项。

7. **跨平台构建支持:**
   - 提供了判断是否是跨平台构建的方法 (`is_cross_build`)。
   - 提供了从常规构建选项复制到构建机器选项的方法 (`copy_build_options_from_regular_ones`)。

8. **批量设置选项:**
   - 提供了批量设置选项的方法 (`set_options`)，可以一次性设置多个选项的值。

9. **默认选项设置:**
   - 提供了设置默认选项的方法 (`set_default_options`)，用于在没有用户指定时使用默认值。

10. **编译器选项处理:**
    - 提供了添加编译器特定选项的方法 (`add_compiler_options`)。
    - 提供了处理编译器基本选项的方法 (`process_compiler_options`)，并能根据用户设置发出警告（如关于 `b_bitcode` 选项）。

11. **命令行文件处理:**
    - 提供了读取和写入命令行选项到文件 (`cmd_line.txt`) 的功能 (`read_cmd_line_file`, `write_cmd_line_file`, `update_cmd_line_file`)，用于持久化构建配置。
    - 提供了格式化命令行选项的方法 (`format_cmd_line_options`)。

12. **Machine 文件处理:**
    - 包含了 `MachineFileParser` 类，用于解析 machine 文件，这些文件通常用于定义交叉编译环境的配置。

13. **核心数据加载和保存:**
    - 提供了加载和保存 `CoreData` 对象的功能 (`load`, `save`)，使用 pickle 进行序列化。

14. **命令行参数注册:**
    - 提供了将内置选项注册到 `argparse` 的功能 (`register_builtin_arguments`)，使得用户可以通过命令行指定这些选项。

15. **命令行选项解析:**
    - 提供了从命令行参数创建选项字典的功能 (`create_options_dict`, `parse_cmd_line_options`)。

16. **内置选项类 (`BuiltinOption`):**
    - 定义了内置选项的结构和行为，包括类型、描述、默认值等，并提供了将其添加到 `argparse` 的方法。

**与逆向方法的关系及举例:**

虽然这个文件本身不直接执行逆向操作，但它是 Frida 构建过程的一部分，而 Frida 是一个动态插桩工具，广泛用于逆向工程。这个文件配置的构建选项会影响 Frida 的构建方式，从而间接影响逆向工作。

* **例1：构建类型 (`buildtype`) 和调试符号 (`debug`)**
    - 如果用户设置 `buildtype=debug`，`coredata.py` 会设置 `debug=True`。这将导致 Frida 的库和工具在构建时包含调试符号。
    - 逆向时，拥有调试符号可以更容易地理解 Frida 内部的工作原理，进行断点调试和变量查看。

* **例2：优化级别 (`optimization`)**
    - 用户可以通过 `optimization` 选项选择不同的优化级别。
    - 对于 Frida 自身的开发和调试，较低的优化级别可能更方便，因为代码更接近源代码。
    - 对于 Frida 的发布版本，较高的优化级别可以提高性能，但这可能会使逆向分析更复杂。

* **例3：安装路径 (`prefix`, `bindir`, `libdir` 等)**
    - 这些选项决定了 Frida 的工具和库将被安装到哪里。
    - 逆向工程师需要知道 Frida 的安装位置才能运行 Frida 的工具或加载 Frida 的库到目标进程中进行插桩。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

这个文件本身主要是配置管理，但其配置的选项会直接影响到编译、链接过程，以及最终生成的二进制文件，这与底层知识密切相关。

* **例1：链接器选项 (`backend_max_links`)**
    - `backend_max_links` 选项控制并行运行的链接器进程数量。这直接涉及到二进制文件的链接过程，一个将多个编译后的目标文件合并成最终可执行文件或库的底层操作。

* **例2：库类型 (`default_library`)**
    - 用户可以选择构建共享库 (`shared`)、静态库 (`static`) 或两者都构建 (`both`)。这涉及到不同类型的二进制文件，以及它们在操作系统中的加载和链接方式。在 Linux 和 Android 中，共享库的加载涉及到动态链接器，而静态库则在编译时被链接到可执行文件中。

* **例3：安装路径选项 (`libdir`, `bindir`)**
    - 这些选项定义了库文件和可执行文件在文件系统中的位置，这与 Linux 文件系统层次标准 (FHS) 相关。在 Android 中，库文件的位置也遵循一定的约定。

* **例4：交叉编译配置 (通过 machine 文件)**
    - machine 文件用于配置交叉编译环境，例如指定目标系统的编译器、链接器、系统库路径等。这涉及到对不同操作系统和架构的深入理解。例如，在为 Android 构建 Frida 时，需要指定 Android NDK 中的工具链和目标架构。

**逻辑推理的假设输入与输出:**

* **假设输入:** 用户在命令行中执行 `meson setup build -Dbuildtype=release -Dprefix=/opt/frida`
* **逻辑推理:** `parse_cmd_line_options` 函数会解析这些参数，然后 `set_options` 函数会调用 `set_option` 来设置 `buildtype` 和 `prefix` 选项。
    - 设置 `buildtype=release` 会触发 `_set_others_from_buildtype('release')`，进而设置 `optimization=3` 和 `debug=False`。
    - 设置 `prefix=/opt/frida` 会导致后续与路径相关的选项（如 `bindir`, `libdir`）的默认值基于 `/opt/frida` 计算。
* **输出:** `coredata.options` 中会包含以下（及其他）键值对：
    ```
    OptionKey('buildtype'): UserComboOption(..., value='release', ...)
    OptionKey('prefix'): UserStringOption(..., value='/opt/frida', ...)
    OptionKey('optimization'): UserComboOption(..., value='3', ...)
    OptionKey('debug'): UserBooleanOption(..., value=False, ...)
    OptionKey('bindir'): UserStringOption(..., value='/opt/frida/bin', ...)
    OptionKey('libdir'): UserStringOption(..., value='/opt/frida/lib', ...)
    ```

**涉及用户或编程常见的使用错误及举例:**

* **例1：拼写错误的选项名:**
    - **用户操作:** 执行 `meson setup build -Dbuilt_type=release`
    - **错误:** `parse_cmd_line_options` 或后续的 `set_options` 会因为找不到名为 `built_type` 的选项而抛出 `MesonException`，提示用户未知的选项。

* **例2：选项值类型错误:**
    - **用户操作:** 执行 `meson setup build -Ddebug=maybe`
    - **错误:** `set_option` 在尝试将字符串 `"maybe"` 设置给布尔类型的 `debug` 选项时会失败，因为类型不匹配，可能抛出 `MesonException`。

* **例3：尝试修改只读选项:**
    - **用户操作:** 执行 `meson setup build -Dbackend=make` (假设 `backend` 是只读选项)
    - **错误:** `set_option` 会检查选项的 `readonly` 属性，如果为 `True` 并且不是首次调用，则会抛出 `MesonException`，提示用户不能修改只读选项。

* **例4：依赖 `prefix` 的选项未正确设置:**
    - **用户操作:** 在没有设置 `prefix` 的情况下，尝试设置一个依赖 `prefix` 的路径选项，例如直接设置 `bindir`。
    - **潜在问题:** 虽然可以直接设置，但如果用户的意图是让其他路径选项相对于某个自定义 `prefix`，那么直接设置可能不会达到预期效果。

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户执行 `meson setup build [options]` 命令:** 这是配置 Meson 构建系统的第一步。命令行中传递的选项（通过 `-D` 参数）会被 `parse_cmd_line_options` 函数解析。
2. **`meson setup` 阶段加载已有的构建配置 (如果存在):** `read_cmd_line_file` 函数会尝试读取之前保存的命令行选项，以便在重新配置时保留用户的设置。
3. **`CoreData` 对象被创建或加载:** 在 `meson setup` 过程中，会创建或加载 `CoreData` 对象，用于存储构建配置。
4. **内置选项被注册:** `register_builtin_arguments` 函数将内置选项添加到 `argparse`，用于命令行解析。
5. **命令行选项被解析并设置:** `parse_cmd_line_options` 将命令行参数转换为选项字典，然后 `set_options` 函数会遍历这些选项并调用 `set_option` 来设置 `CoreData` 对象中的选项值.
6. **处理 `buildtype` 选项:** 如果用户设置了 `buildtype`，`_set_others_from_buildtype` 函数会被调用，以根据预定义的规则设置相关的优化和调试选项。
7. **保存配置:** 在 `meson setup` 完成后，`save` 函数会将 `CoreData` 对象保存到磁盘，包括所有设置的选项。

**作为调试线索：** 如果用户报告构建问题，例如使用了错误的优化级别或安装路径不正确，调试人员可以检查以下内容：

* **用户的 `meson setup` 命令:** 查看用户传递了哪些 `-D` 选项。
* **`meson-private/cmd_line.txt` 文件:** 查看实际保存的命令行选项。
* **`meson-private/coredata.dat` 文件:** 反序列化这个文件，查看 `coredata.options` 中存储的选项值，确认选项是否被正确设置。
* **Meson 的输出日志:** 查看 Meson 在配置过程中是否输出了任何关于选项的警告或错误信息。

通过这些步骤，可以追踪用户操作如何影响 `coredata.py` 中的选项设置，从而帮助诊断构建问题。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
values
        for key, opt in BUILTIN_OPTIONS.items():
            self.add_builtin_option(self.options, key.evolve(subproject=subproject), opt)
        for for_machine in iter(MachineChoice):
            for key, opt in BUILTIN_OPTIONS_PER_MACHINE.items():
                self.add_builtin_option(self.options, key.evolve(subproject=subproject, machine=for_machine), opt)

    @staticmethod
    def add_builtin_option(opts_map: 'MutableKeyedOptionDictType', key: OptionKey,
                           opt: 'BuiltinOption') -> None:
        if key.subproject:
            if opt.yielding:
                # This option is global and not per-subproject
                return
            value = opts_map[key.as_root()].value
        else:
            value = None
        opts_map[key] = opt.init_option(key, value, default_prefix())

    def init_backend_options(self, backend_name: str) -> None:
        if backend_name == 'ninja':
            self.options[OptionKey('backend_max_links')] = UserIntegerOption(
                'backend_max_links',
                'Maximum number of linker processes to run or 0 for no '
                'limit',
                (0, None, 0))
        elif backend_name.startswith('vs'):
            self.options[OptionKey('backend_startup_project')] = UserStringOption(
                'backend_startup_project',
                'Default project to execute in Visual Studio',
                '')

    def get_option(self, key: OptionKey) -> T.Union[T.List[str], str, int, bool, WrapMode]:
        try:
            v = self.options[key].value
            if key.name == 'wrap_mode':
                return WrapMode[v]
            return v
        except KeyError:
            pass

        try:
            v = self.options[key.as_root()]
            if v.yielding:
                if key.name == 'wrap_mode':
                    return WrapMode[v.value]
                return v.value
        except KeyError:
            pass

        raise MesonException(f'Tried to get unknown builtin option {str(key)}')

    def set_option(self, key: OptionKey, value, first_invocation: bool = False) -> bool:
        dirty = False
        if key.is_builtin():
            if key.name == 'prefix':
                value = self.sanitize_prefix(value)
            else:
                prefix = self.options[OptionKey('prefix')].value
                value = self.sanitize_dir_option_value(prefix, key, value)

        try:
            opt = self.options[key]
        except KeyError:
            raise MesonException(f'Tried to set unknown builtin option {str(key)}')

        if opt.deprecated is True:
            mlog.deprecation(f'Option {key.name!r} is deprecated')
        elif isinstance(opt.deprecated, list):
            for v in opt.listify(value):
                if v in opt.deprecated:
                    mlog.deprecation(f'Option {key.name!r} value {v!r} is deprecated')
        elif isinstance(opt.deprecated, dict):
            def replace(v):
                newvalue = opt.deprecated.get(v)
                if newvalue is not None:
                    mlog.deprecation(f'Option {key.name!r} value {v!r} is replaced by {newvalue!r}')
                    return newvalue
                return v
            newvalue = [replace(v) for v in opt.listify(value)]
            value = ','.join(newvalue)
        elif isinstance(opt.deprecated, str):
            # Option is deprecated and replaced by another. Note that a project
            # option could be replaced by a built-in or module option, which is
            # why we use OptionKey.from_string(newname) instead of
            # key.evolve(newname). We set the value on both the old and new names,
            # assuming they accept the same value. That could for example be
            # achieved by adding the values from old option as deprecated on the
            # new option, for example in the case of boolean option is replaced
            # by a feature option with a different name.
            newname = opt.deprecated
            newkey = OptionKey.from_string(newname).evolve(subproject=key.subproject)
            mlog.deprecation(f'Option {key.name!r} is replaced by {newname!r}')
            dirty |= self.set_option(newkey, value, first_invocation)

        changed = opt.set_value(value)
        if changed and opt.readonly and not first_invocation:
            raise MesonException(f'Tried modify read only option {str(key)!r}')
        dirty |= changed

        if key.name == 'buildtype':
            dirty |= self._set_others_from_buildtype(value)

        return dirty

    def clear_cache(self) -> None:
        self.deps.host.clear()
        self.deps.build.clear()
        self.compiler_check_cache.clear()
        self.run_check_cache.clear()

    def get_nondefault_buildtype_args(self) -> T.List[T.Union[T.Tuple[str, str, str], T.Tuple[str, bool, bool]]]:
        result: T.List[T.Union[T.Tuple[str, str, str], T.Tuple[str, bool, bool]]] = []
        value = self.options[OptionKey('buildtype')].value
        if value == 'plain':
            opt = 'plain'
            debug = False
        elif value == 'debug':
            opt = '0'
            debug = True
        elif value == 'debugoptimized':
            opt = '2'
            debug = True
        elif value == 'release':
            opt = '3'
            debug = False
        elif value == 'minsize':
            opt = 's'
            debug = True
        else:
            assert value == 'custom'
            return []
        actual_opt = self.options[OptionKey('optimization')].value
        actual_debug = self.options[OptionKey('debug')].value
        if actual_opt != opt:
            result.append(('optimization', actual_opt, opt))
        if actual_debug != debug:
            result.append(('debug', actual_debug, debug))
        return result

    def _set_others_from_buildtype(self, value: str) -> bool:
        dirty = False

        if value == 'plain':
            opt = 'plain'
            debug = False
        elif value == 'debug':
            opt = '0'
            debug = True
        elif value == 'debugoptimized':
            opt = '2'
            debug = True
        elif value == 'release':
            opt = '3'
            debug = False
        elif value == 'minsize':
            opt = 's'
            debug = True
        else:
            assert value == 'custom'
            return False

        dirty |= self.options[OptionKey('optimization')].set_value(opt)
        dirty |= self.options[OptionKey('debug')].set_value(debug)

        return dirty

    @staticmethod
    def is_per_machine_option(optname: OptionKey) -> bool:
        if optname.subproject and optname.is_project():
            return True
        if optname.as_host() in BUILTIN_OPTIONS_PER_MACHINE:
            return True
        return optname.lang is not None

    def get_external_args(self, for_machine: MachineChoice, lang: str) -> T.List[str]:
        # mypy cannot analyze type of OptionKey
        return T.cast('T.List[str]', self.options[OptionKey('args', machine=for_machine, lang=lang)].value)

    def get_external_link_args(self, for_machine: MachineChoice, lang: str) -> T.List[str]:
        # mypy cannot analyze type of OptionKey
        return T.cast('T.List[str]', self.options[OptionKey('link_args', machine=for_machine, lang=lang)].value)

    def update_project_options(self, options: 'MutableKeyedOptionDictType', subproject: SubProject) -> None:
        for key, value in options.items():
            if not key.is_project():
                continue
            if key not in self.options:
                self.options[key] = value
                continue
            if key.subproject != subproject:
                raise MesonBugException(f'Tried to set an option for subproject {key.subproject} from {subproject}!')

            oldval = self.options[key]
            if type(oldval) is not type(value):
                self.options[key] = value
            elif oldval.choices != value.choices:
                # If the choices have changed, use the new value, but attempt
                # to keep the old options. If they are not valid keep the new
                # defaults but warn.
                self.options[key] = value
                try:
                    value.set_value(oldval.value)
                except MesonException:
                    mlog.warning(f'Old value(s) of {key} are no longer valid, resetting to default ({value.value}).',
                                 fatal=False)

        # Find any extranious keys for this project and remove them
        for key in list(self.options.keys() - options.keys()):
            if key.is_project() and key.subproject == subproject:
                del self.options[key]

    def is_cross_build(self, when_building_for: MachineChoice = MachineChoice.HOST) -> bool:
        if when_building_for == MachineChoice.BUILD:
            return False
        return len(self.cross_files) > 0

    def copy_build_options_from_regular_ones(self) -> bool:
        dirty = False
        assert not self.is_cross_build()
        for k in BUILTIN_OPTIONS_PER_MACHINE:
            o = self.options[k]
            dirty |= self.options[k.as_build()].set_value(o.value)
        for bk, bv in self.options.items():
            if bk.machine is MachineChoice.BUILD:
                hk = bk.as_host()
                try:
                    hv = self.options[hk]
                    dirty |= bv.set_value(hv.value)
                except KeyError:
                    continue

        return dirty

    def set_options(self, options: T.Dict[OptionKey, T.Any], subproject: str = '', first_invocation: bool = False) -> bool:
        dirty = False
        if not self.is_cross_build():
            options = {k: v for k, v in options.items() if k.machine is not MachineChoice.BUILD}
        # Set prefix first because it's needed to sanitize other options
        pfk = OptionKey('prefix')
        if pfk in options:
            prefix = self.sanitize_prefix(options[pfk])
            dirty |= self.options[OptionKey('prefix')].set_value(prefix)
            for key in BUILTIN_DIR_NOPREFIX_OPTIONS:
                if key not in options:
                    dirty |= self.options[key].set_value(BUILTIN_OPTIONS[key].prefixed_default(key, prefix))

        unknown_options: T.List[OptionKey] = []
        for k, v in options.items():
            if k == pfk:
                continue
            elif k in self.options:
                dirty |= self.set_option(k, v, first_invocation)
            elif k.machine != MachineChoice.BUILD and k.type != OptionType.COMPILER:
                unknown_options.append(k)
        if unknown_options:
            unknown_options_str = ', '.join(sorted(str(s) for s in unknown_options))
            sub = f'In subproject {subproject}: ' if subproject else ''
            raise MesonException(f'{sub}Unknown options: "{unknown_options_str}"')

        if not self.is_cross_build():
            dirty |= self.copy_build_options_from_regular_ones()

        return dirty

    def set_default_options(self, default_options: T.MutableMapping[OptionKey, str], subproject: str, env: 'Environment') -> None:
        from .compilers import base_options

        # Main project can set default options on subprojects, but subprojects
        # can only set default options on themselves.
        # Preserve order: if env.options has 'buildtype' it must come after
        # 'optimization' if it is in default_options.
        options: T.MutableMapping[OptionKey, T.Any] = OrderedDict()
        for k, v in default_options.items():
            if not subproject or k.subproject == subproject:
                options[k] = v
        options.update(env.options)
        env.options = options

        # Create a subset of options, keeping only project and builtin
        # options for this subproject.
        # Language and backend specific options will be set later when adding
        # languages and setting the backend (builtin options must be set first
        # to know which backend we'll use).
        options = OrderedDict()

        for k, v in env.options.items():
            # If this is a subproject, don't use other subproject options
            if k.subproject and k.subproject != subproject:
                continue
            # If the option is a builtin and is yielding then it's not allowed per subproject.
            #
            # Always test this using the HOST machine, as many builtin options
            # are not valid for the BUILD machine, but the yielding value does
            # not differ between them even when they are valid for both.
            if subproject and k.is_builtin() and self.options[k.evolve(subproject='', machine=MachineChoice.HOST)].yielding:
                continue
            # Skip base, compiler, and backend options, they are handled when
            # adding languages and setting backend.
            if k.type in {OptionType.COMPILER, OptionType.BACKEND}:
                continue
            if k.type == OptionType.BASE and k.as_root() in base_options:
                # set_options will report unknown base options
                continue
            options[k] = v

        self.set_options(options, subproject=subproject, first_invocation=env.first_invocation)

    def add_compiler_options(self, options: MutableKeyedOptionDictType, lang: str, for_machine: MachineChoice,
                             env: Environment, subproject: str) -> None:
        for k, o in options.items():
            value = env.options.get(k)
            if value is not None:
                o.set_value(value)
                if not subproject:
                    self.options[k] = o  # override compiler option on reconfigure
            self.options.setdefault(k, o)

            if subproject:
                sk = k.evolve(subproject=subproject)
                value = env.options.get(sk) or value
                if value is not None:
                    o.set_value(value)
                    self.options[sk] = o  # override compiler option on reconfigure
                self.options.setdefault(sk, o)

    def add_lang_args(self, lang: str, comp: T.Type['Compiler'],
                      for_machine: MachineChoice, env: 'Environment') -> None:
        """Add global language arguments that are needed before compiler/linker detection."""
        from .compilers import compilers
        # These options are all new at this point, because the compiler is
        # responsible for adding its own options, thus calling
        # `self.options.update()`` is perfectly safe.
        self.options.update(compilers.get_global_options(lang, comp, for_machine, env))

    def process_compiler_options(self, lang: str, comp: Compiler, env: Environment, subproject: str) -> None:
        from . import compilers

        self.add_compiler_options(comp.get_options(), lang, comp.for_machine, env, subproject)

        enabled_opts: T.List[OptionKey] = []
        for key in comp.base_options:
            if subproject:
                skey = key.evolve(subproject=subproject)
            else:
                skey = key
            if skey not in self.options:
                self.options[skey] = copy.deepcopy(compilers.base_options[key])
                if skey in env.options:
                    self.options[skey].set_value(env.options[skey])
                    enabled_opts.append(skey)
                elif subproject and key in env.options:
                    self.options[skey].set_value(env.options[key])
                    enabled_opts.append(skey)
                if subproject and key not in self.options:
                    self.options[key] = copy.deepcopy(self.options[skey])
            elif skey in env.options:
                self.options[skey].set_value(env.options[skey])
            elif subproject and key in env.options:
                self.options[skey].set_value(env.options[key])
        self.emit_base_options_warnings(enabled_opts)

    def emit_base_options_warnings(self, enabled_opts: T.List[OptionKey]) -> None:
        if OptionKey('b_bitcode') in enabled_opts:
            mlog.warning('Base option \'b_bitcode\' is enabled, which is incompatible with many linker options. Incompatible options such as \'b_asneeded\' have been disabled.', fatal=False)
            mlog.warning('Please see https://mesonbuild.com/Builtin-options.html#Notes_about_Apple_Bitcode_support for more details.', fatal=False)

class CmdLineFileParser(configparser.ConfigParser):
    def __init__(self) -> None:
        # We don't want ':' as key delimiter, otherwise it would break when
        # storing subproject options like "subproject:option=value"
        super().__init__(delimiters=['='], interpolation=None)

    def read(self, filenames: T.Union['StrOrBytesPath', T.Iterable['StrOrBytesPath']], encoding: T.Optional[str] = 'utf-8') -> T.List[str]:
        return super().read(filenames, encoding)

    def optionxform(self, optionstr: str) -> str:
        # Don't call str.lower() on keys
        return optionstr

class MachineFileParser():
    def __init__(self, filenames: T.List[str], sourcedir: str) -> None:
        self.parser = CmdLineFileParser()
        self.constants: T.Dict[str, T.Union[str, bool, int, T.List[str]]] = {'True': True, 'False': False}
        self.sections: T.Dict[str, T.Dict[str, T.Union[str, bool, int, T.List[str]]]] = {}

        for fname in filenames:
            with open(fname, encoding='utf-8') as f:
                content = f.read()
                content = content.replace('@GLOBAL_SOURCE_ROOT@', sourcedir)
                content = content.replace('@DIRNAME@', os.path.dirname(fname))
                try:
                    self.parser.read_string(content, fname)
                except configparser.Error as e:
                    raise EnvironmentException(f'Malformed machine file: {e}')

        # Parse [constants] first so they can be used in other sections
        if self.parser.has_section('constants'):
            self.constants.update(self._parse_section('constants'))

        for s in self.parser.sections():
            if s == 'constants':
                continue
            self.sections[s] = self._parse_section(s)

    def _parse_section(self, s: str) -> T.Dict[str, T.Union[str, bool, int, T.List[str]]]:
        self.scope = self.constants.copy()
        section: T.Dict[str, T.Union[str, bool, int, T.List[str]]] = {}
        for entry, value in self.parser.items(s):
            if ' ' in entry or '\t' in entry or "'" in entry or '"' in entry:
                raise EnvironmentException(f'Malformed variable name {entry!r} in machine file.')
            # Windows paths...
            value = value.replace('\\', '\\\\')
            try:
                ast = mparser.Parser(value, 'machinefile').parse()
                if not ast.lines:
                    raise EnvironmentException('value cannot be empty')
                res = self._evaluate_statement(ast.lines[0])
            except MesonException as e:
                raise EnvironmentException(f'Malformed value in machine file variable {entry!r}: {str(e)}.')
            except KeyError as e:
                raise EnvironmentException(f'Undefined constant {e.args[0]!r} in machine file variable {entry!r}.')
            section[entry] = res
            self.scope[entry] = res
        return section

    def _evaluate_statement(self, node: mparser.BaseNode) -> T.Union[str, bool, int, T.List[str]]:
        if isinstance(node, (mparser.BaseStringNode)):
            return node.value
        elif isinstance(node, mparser.BooleanNode):
            return node.value
        elif isinstance(node, mparser.NumberNode):
            return node.value
        elif isinstance(node, mparser.ParenthesizedNode):
            return self._evaluate_statement(node.inner)
        elif isinstance(node, mparser.ArrayNode):
            # TODO: This is where recursive types would come in handy
            return [self._evaluate_statement(arg) for arg in node.args.arguments]
        elif isinstance(node, mparser.IdNode):
            return self.scope[node.value]
        elif isinstance(node, mparser.ArithmeticNode):
            l = self._evaluate_statement(node.left)
            r = self._evaluate_statement(node.right)
            if node.operation == 'add':
                if (isinstance(l, str) and isinstance(r, str)) or \
                   (isinstance(l, list) and isinstance(r, list)):
                    return l + r
            elif node.operation == 'div':
                if isinstance(l, str) and isinstance(r, str):
                    return os.path.join(l, r)
        raise EnvironmentException('Unsupported node type')

def parse_machine_files(filenames: T.List[str], sourcedir: str):
    parser = MachineFileParser(filenames, sourcedir)
    return parser.sections

def get_cmd_line_file(build_dir: str) -> str:
    return os.path.join(build_dir, 'meson-private', 'cmd_line.txt')

def read_cmd_line_file(build_dir: str, options: SharedCMDOptions) -> None:
    filename = get_cmd_line_file(build_dir)
    if not os.path.isfile(filename):
        return

    config = CmdLineFileParser()
    config.read(filename)

    # Do a copy because config is not really a dict. options.cmd_line_options
    # overrides values from the file.
    d = {OptionKey.from_string(k): v for k, v in config['options'].items()}
    d.update(options.cmd_line_options)
    options.cmd_line_options = d

    properties = config['properties']
    if not options.cross_file:
        options.cross_file = ast.literal_eval(properties.get('cross_file', '[]'))
    if not options.native_file:
        # This will be a string in the form: "['first', 'second', ...]", use
        # literal_eval to get it into the list of strings.
        options.native_file = ast.literal_eval(properties.get('native_file', '[]'))

def write_cmd_line_file(build_dir: str, options: SharedCMDOptions) -> None:
    filename = get_cmd_line_file(build_dir)
    config = CmdLineFileParser()

    properties: OrderedDict[str, str] = OrderedDict()
    if options.cross_file:
        properties['cross_file'] = options.cross_file
    if options.native_file:
        properties['native_file'] = options.native_file

    config['options'] = {str(k): str(v) for k, v in options.cmd_line_options.items()}
    config['properties'] = properties
    with open(filename, 'w', encoding='utf-8') as f:
        config.write(f)

def update_cmd_line_file(build_dir: str, options: SharedCMDOptions) -> None:
    filename = get_cmd_line_file(build_dir)
    config = CmdLineFileParser()
    config.read(filename)
    config['options'].update({str(k): str(v) for k, v in options.cmd_line_options.items()})
    with open(filename, 'w', encoding='utf-8') as f:
        config.write(f)

def format_cmd_line_options(options: SharedCMDOptions) -> str:
    cmdline = ['-D{}={}'.format(str(k), v) for k, v in options.cmd_line_options.items()]
    if options.cross_file:
        cmdline += [f'--cross-file={f}' for f in options.cross_file]
    if options.native_file:
        cmdline += [f'--native-file={f}' for f in options.native_file]
    return ' '.join([shlex.quote(x) for x in cmdline])

def major_versions_differ(v1: str, v2: str) -> bool:
    v1_major, v1_minor = v1.rsplit('.', 1)
    v2_major, v2_minor = v2.rsplit('.', 1)
    # Major version differ, or one is development version but not the other.
    return v1_major != v2_major or ('99' in {v1_minor, v2_minor} and v1_minor != v2_minor)

def load(build_dir: str, suggest_reconfigure: bool = True) -> CoreData:
    filename = os.path.join(build_dir, 'meson-private', 'coredata.dat')
    return pickle_load(filename, 'Coredata', CoreData, suggest_reconfigure)


def save(obj: CoreData, build_dir: str) -> str:
    filename = os.path.join(build_dir, 'meson-private', 'coredata.dat')
    prev_filename = filename + '.prev'
    tempfilename = filename + '~'
    if major_versions_differ(obj.version, version):
        raise MesonException('Fatal version mismatch corruption.')
    if os.path.exists(filename):
        import shutil
        shutil.copyfile(filename, prev_filename)
    with open(tempfilename, 'wb') as f:
        pickle.dump(obj, f)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tempfilename, filename)
    return filename


def register_builtin_arguments(parser: argparse.ArgumentParser) -> None:
    for n, b in BUILTIN_OPTIONS.items():
        b.add_to_argparse(str(n), parser, '')
    for n, b in BUILTIN_OPTIONS_PER_MACHINE.items():
        b.add_to_argparse(str(n), parser, ' (just for host machine)')
        b.add_to_argparse(str(n.as_build()), parser, ' (just for build machine)')
    parser.add_argument('-D', action='append', dest='projectoptions', default=[], metavar="option",
                        help='Set the value of an option, can be used several times to set multiple options.')

def create_options_dict(options: T.List[str], subproject: str = '') -> T.Dict[OptionKey, str]:
    result: T.OrderedDict[OptionKey, str] = OrderedDict()
    for o in options:
        try:
            (key, value) = o.split('=', 1)
        except ValueError:
            raise MesonException(f'Option {o!r} must have a value separated by equals sign.')
        k = OptionKey.from_string(key)
        if subproject:
            k = k.evolve(subproject=subproject)
        result[k] = value
    return result

def parse_cmd_line_options(args: SharedCMDOptions) -> None:
    args.cmd_line_options = create_options_dict(args.projectoptions)

    # Merge builtin options set with --option into the dict.
    for key in chain(
            BUILTIN_OPTIONS.keys(),
            (k.as_build() for k in BUILTIN_OPTIONS_PER_MACHINE.keys()),
            BUILTIN_OPTIONS_PER_MACHINE.keys(),
    ):
        name = str(key)
        value = getattr(args, name, None)
        if value is not None:
            if key in args.cmd_line_options:
                cmdline_name = BuiltinOption.argparse_name_to_arg(name)
                raise MesonException(
                    f'Got argument {name} as both -D{name} and {cmdline_name}. Pick one.')
            args.cmd_line_options[key] = value
            delattr(args, name)


_U = T.TypeVar('_U', bound=UserOption[_T])

class BuiltinOption(T.Generic[_T, _U]):

    """Class for a builtin option type.

    There are some cases that are not fully supported yet.
    """

    def __init__(self, opt_type: T.Type[_U], description: str, default: T.Any, yielding: bool = True, *,
                 choices: T.Any = None, readonly: bool = False):
        self.opt_type = opt_type
        self.description = description
        self.default = default
        self.choices = choices
        self.yielding = yielding
        self.readonly = readonly

    def init_option(self, name: 'OptionKey', value: T.Optional[T.Any], prefix: str) -> _U:
        """Create an instance of opt_type and return it."""
        if value is None:
            value = self.prefixed_default(name, prefix)
        keywords = {'yielding': self.yielding, 'value': value}
        if self.choices:
            keywords['choices'] = self.choices
        o = self.opt_type(name.name, self.description, **keywords)
        o.readonly = self.readonly
        return o

    def _argparse_action(self) -> T.Optional[str]:
        # If the type is a boolean, the presence of the argument in --foo form
        # is to enable it. Disabling happens by using -Dfoo=false, which is
        # parsed under `args.projectoptions` and does not hit this codepath.
        if isinstance(self.default, bool):
            return 'store_true'
        return None

    def _argparse_choices(self) -> T.Any:
        if self.opt_type is UserBooleanOption:
            return [True, False]
        elif self.opt_type is UserFeatureOption:
            return UserFeatureOption.static_choices
        return self.choices

    @staticmethod
    def argparse_name_to_arg(name: str) -> str:
        if name == 'warning_level':
            return '--warnlevel'
        else:
            return '--' + name.replace('_', '-')

    def prefixed_default(self, name: 'OptionKey', prefix: str = '') -> T.Any:
        if self.opt_type in [UserComboOption, UserIntegerOption]:
            return self.default
        try:
            return BUILTIN_DIR_NOPREFIX_OPTIONS[name][prefix]
        except KeyError:
            pass
        return self.default

    def add_to_argparse(self, name: str, parser: argparse.ArgumentParser, help_suffix: str) -> None:
        kwargs = OrderedDict()

        c = self._argparse_choices()
        b = self._argparse_action()
        h = self.description
        if not b:
            h = '{} (default: {}).'.format(h.rstrip('.'), self.prefixed_default(name))
        else:
            kwargs['action'] = b
        if c and not b:
            kwargs['choices'] = c
        kwargs['default'] = argparse.SUPPRESS
        kwargs['dest'] = name

        cmdline_name = self.argparse_name_to_arg(name)
        parser.add_argument(cmdline_name, help=h + help_suffix, **kwargs)


# Update `docs/markdown/Builtin-options.md` after changing the options below
# Also update mesonlib._BUILTIN_NAMES. See the comment there for why this is required.
# Please also update completion scripts in $MESONSRC/data/shell-completions/
BUILTIN_DIR_OPTIONS: T.Dict['OptionKey', 'BuiltinOption'] = OrderedDict([
    (OptionKey('prefix'),          BuiltinOption(UserStringOption, 'Installation prefix', default_prefix())),
    (OptionKey('bindir'),          BuiltinOption(UserStringOption, 'Executable directory', 'bin')),
    (OptionKey('datadir'),         BuiltinOption(UserStringOption, 'Data file directory', default_datadir())),
    (OptionKey('includedir'),      BuiltinOption(UserStringOption, 'Header file directory', default_includedir())),
    (OptionKey('infodir'),         BuiltinOption(UserStringOption, 'Info page directory', default_infodir())),
    (OptionKey('libdir'),          BuiltinOption(UserStringOption, 'Library directory', default_libdir())),
    (OptionKey('licensedir'),      BuiltinOption(UserStringOption, 'Licenses directory', '')),
    (OptionKey('libexecdir'),      BuiltinOption(UserStringOption, 'Library executable directory', default_libexecdir())),
    (OptionKey('localedir'),       BuiltinOption(UserStringOption, 'Locale data directory', default_localedir())),
    (OptionKey('localstatedir'),   BuiltinOption(UserStringOption, 'Localstate data directory', 'var')),
    (OptionKey('mandir'),          BuiltinOption(UserStringOption, 'Manual page directory', default_mandir())),
    (OptionKey('sbindir'),         BuiltinOption(UserStringOption, 'System executable directory', default_sbindir())),
    (OptionKey('sharedstatedir'),  BuiltinOption(UserStringOption, 'Architecture-independent data directory', 'com')),
    (OptionKey('sysconfdir'),      BuiltinOption(UserStringOption, 'Sysconf data directory', default_sysconfdir())),
])

BUILTIN_CORE_OPTIONS: T.Dict['OptionKey', 'BuiltinOption'] = OrderedDict([
    (OptionKey('auto_features'),   BuiltinOption(UserFeatureOption, "Override value of all 'auto' features", 'auto')),
    (OptionKey('backend'),         BuiltinOption(UserComboOption, 'Backend to use', 'ninja', choices=backendlist,
                                                 readonly=True)),
    (OptionKey('genvslite'),
     BuiltinOption(
         UserComboOption,
         'Setup multiple buildtype-suffixed ninja-backend build directories, '
         'and a [builddir]_vs containing a Visual Studio meta-backend with multiple configurations that calls into them',
         'vs2022',
         choices=genvslitelist)
     ),
    (OptionKey('buildtype'),       BuiltinOption(UserComboOption, 'Build type to use', 'debug',
                                                 choices=buildtypelist)),
    (OptionKey('debug'),           BuiltinOption(UserBooleanOption, 'Enable debug symbols and other information', True)),
    (OptionKey('default_library'), BuiltinOption(UserComboOption, 'Default library type', 'shared', choices=['shared', 'static', 'both'],
                                                 yielding=False)),
    (OptionKey('errorlogs'),       BuiltinOption(UserBooleanOption, "Whether to print the logs from failing tests", True)),
    (OptionKey('install_umask'),   BuiltinOption(UserUmaskOption, 'Default umask to apply on permissions of installed files', '022')),
    (OptionKey('layout'),          BuiltinOption(UserComboOption, 'Build directory layout', 'mirror', choices=['mirror', 'flat'])),
    (OptionKey('optimization'),    BuiltinOption(UserComboOption, 'Optimization level', '0', choices=['plain', '0', 'g', '1', '2', '3', 's'])),
    (OptionKey('prefer_static'),   BuiltinO
```