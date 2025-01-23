Response:
My thinking process to answer the prompt about `coredata.py` goes like this:

1. **Understand the Goal:** The primary goal is to describe the functionality of the provided Python code snippet, relate it to reverse engineering (if applicable), low-level concepts, and common user errors, ultimately summarizing its purpose. The prompt specifically asks for the *functionality* of this part of the file.

2. **Initial Scan for Keywords:** I quickly scan the code for recurring keywords and patterns. I see terms like:
    * `options`, `BUILTIN_OPTIONS`, `UserOption`, `OptionKey` - suggesting this code manages configuration options.
    * `prefix`, `bindir`, `libdir` -  hints at installation directories.
    * `buildtype`, `debug`, `optimization` - point to build-related settings.
    * `backend`, `ninja`, `vs` - indicate build systems.
    * `cross_file`, `native_file` - suggest cross-compilation capabilities.
    * `set_option`, `get_option` -  confirm option management.
    * `MachineChoice`, `MachineFileParser` - point to handling different machine architectures.
    * `cmd_line.txt` - suggests reading/writing command-line arguments.
    * `pickle`, `load`, `save` - indicate persistence of data.

3. **Identify Core Functionality Areas:** Based on the keywords, I can group the functionalities:
    * **Option Management:** This seems central. The code defines and manages various build and installation options. This includes built-in options and potentially project-specific options.
    * **Build System Integration:**  The mention of backends like `ninja` and `vs` implies integration with different build systems.
    * **Cross-Compilation Support:** The `cross_file` and `native_file` handling clearly points to support for building for different target architectures.
    * **Configuration Persistence:** The use of `pickle` indicates that the configuration data is saved and loaded.
    * **Command-Line Argument Handling:**  The code reads and writes a `cmd_line.txt` file, showing it manages command-line options.
    * **Machine Configuration:** The `MachineFileParser` suggests loading configuration from external files, likely specific to target machines.

4. **Detailed Analysis of Key Functions and Structures:** Now I go through the code more carefully, focusing on how the identified functionalities are implemented:
    * **`CoreData` Class:** This appears to be the main data structure holding all the configuration information. The methods within it perform operations on this data.
    * **`BUILTIN_OPTIONS` and `BUILTIN_OPTIONS_PER_MACHINE`:** These dictionaries likely define the standard set of configurable options.
    * **`OptionKey`:** This class is used to identify and categorize options (e.g., by name, subproject, machine).
    * **`UserOption` subclasses:** These represent different types of options (string, boolean, combo, etc.).
    * **`set_option` and `get_option`:**  These are the primary methods for interacting with options. I note the logic for handling deprecated options.
    * **`init_backend_options`:** This shows how backend-specific options are added.
    * **`MachineFileParser`:** I examine how machine files are parsed and how constants and sections are handled.
    * **`read_cmd_line_file` and `write_cmd_line_file`:**  I understand how command-line options are saved and loaded.

5. **Relate to Reverse Engineering, Low-Level, etc.:**  As I analyze, I consider the connections to the specified areas:
    * **Reverse Engineering:** Frida is a dynamic instrumentation tool, often used in reverse engineering. The configuration options in this file would directly impact how Frida is built and potentially how it interacts with target processes. For example, debug symbols (`debug` option) are crucial for debugging Frida itself or the target application.
    * **Binary/Low-Level:** Options like `optimization` directly influence the compiled binary's performance and size. Linker options (`backend_max_links`) are low-level build settings.
    * **Linux/Android Kernel/Framework:** While this specific file doesn't directly interact with the kernel, the build process it configures will eventually produce binaries that *do*. Options related to installation directories (`libdir`, etc.) are standard Linux concepts. For Android, while not explicitly mentioned *here*, Frida is used on Android, and its build process would need to accommodate Android's specific environment.
    * **Logical Reasoning:** The `set_option` method has conditional logic based on option names (like `buildtype`) to set other related options. This demonstrates internal dependencies and logic.

6. **Identify User Errors:** I think about common mistakes users might make:
    * **Incorrect option names:** Typos when using `-D`.
    * **Invalid option values:**  Providing a string when an integer is expected, or an invalid choice for a combo option.
    * **Conflicting options:** Setting options that contradict each other.
    * **Trying to modify read-only options:**  Attempting to change settings that are fixed after the initial configuration.

7. **Trace User Actions:** I consider how a user would interact with Meson to reach this code:
    * Running `meson setup` would be the primary entry point.
    * Command-line arguments (`-D`, `--cross-file`, etc.) would be parsed and processed.
    * Machine files might be specified.
    * Previous configuration data would be loaded.

8. **Synthesize and Summarize:** Finally, I synthesize the information gathered and write the summary, focusing on the main purpose of the code: managing the configuration and state of a Meson-based build system. I ensure I address all aspects of the prompt.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the individual functions. I then realize the importance of understanding the overall data flow and the role of the `CoreData` class.
* I might overlook some of the connections to reverse engineering or low-level details. Rereading the prompt helps me to specifically look for those relationships.
* I ensure that my examples of user errors and user actions are concrete and illustrate the concepts.

By following this structured approach, I can effectively analyze the code and provide a comprehensive and accurate answer to the prompt.
这是 `frida/subprojects/frida-core/releng/meson/mesonbuild/coredata.py` 文件中 `CoreData` 类的部分源代码。 `CoreData` 类在 Meson 构建系统中扮演着核心的角色，它负责存储和管理构建过程中的各种配置数据和状态信息。

**此部分代码的功能归纳：**

这部分代码主要负责 **管理和操作构建系统的配置选项 (Options)**。 具体来说，它涵盖了以下几个关键功能：

1. **内置选项的管理：**
   - 定义和注册 Meson 的内置选项 (`BUILTIN_OPTIONS`, `BUILTIN_OPTIONS_PER_MACHINE`)，这些选项控制着构建过程的通用行为，例如安装路径、构建类型、优化级别等。
   - 提供了添加内置选项到选项字典 (`self.options`) 的方法 (`add_builtin_option`)。
   - 区分了全局选项和每个机器 (host/build) 的选项。

2. **后端特定选项的初始化：**
   - 提供了针对特定构建后端（如 Ninja 和 Visual Studio）初始化选项的方法 (`init_backend_options`)。例如，为 Ninja 设置最大链接器进程数，为 Visual Studio 设置启动项目。

3. **选项值的获取和设置：**
   - 提供了获取选项值的方法 (`get_option`)，可以根据 `OptionKey` 获取对应的值。
   - 提供了设置选项值的方法 (`set_option`)，并处理了选项的废弃 (deprecation) 情况，包括警告用户和替换为新选项。
   - 在设置 `buildtype` 选项时，会自动同步设置相关的 `optimization` 和 `debug` 选项。

4. **缓存清理：**
   - 提供了清理依赖关系和编译器/运行检查缓存的方法 (`clear_cache`)。

5. **根据构建类型获取非默认参数：**
   - 提供了根据当前 `buildtype` 获取与默认值不同的 `optimization` 和 `debug` 参数的方法 (`get_nondefault_buildtype_args`)。

6. **跨平台构建支持：**
   - 提供了判断是否为交叉编译的方法 (`is_cross_build`)。
   - 提供了复制常规构建选项到构建机器选项的方法 (`copy_build_options_from_regular_ones`)。

7. **项目选项的更新：**
   - 提供了更新子项目选项的方法 (`update_project_options`)，确保子项目只能修改自己的选项。

8. **批量设置选项：**
   - 提供了批量设置选项的方法 (`set_options`)，可以一次性设置多个选项，并处理未知选项的情况。

9. **设置默认选项：**
   - 提供了设置默认选项的方法 (`set_default_options`)，允许项目或子项目设置其选项的默认值。

10. **编译器选项的处理：**
    - 提供了添加编译器特定选项的方法 (`add_compiler_options`)。
    - 提供了添加与语言相关的全局参数的方法 (`add_lang_args`)。
    - 提供了处理编译器选项的完整流程 (`process_compiler_options`)，包括添加基本选项和发出警告。

11. **机器特定选项的判断：**
    - 提供了判断一个选项是否是每个机器特定选项的方法 (`is_per_machine_option`)。

12. **获取外部参数和链接参数：**
    - 提供了获取特定机器和语言的外部编译参数 (`get_external_args`) 和链接参数 (`get_external_link_args`) 的方法.

**与逆向方法的关系：**

Frida 是一个动态插桩工具，广泛应用于逆向工程。 `coredata.py` 中管理的选项直接影响 Frida 的构建方式，从而间接地影响其逆向能力。

* **`buildtype` 和 `debug` 选项：**  在逆向工程中，通常需要构建带有调试符号的 Frida (`buildtype=debug`)，这样在调试 Frida 自身或分析目标程序时能提供更详细的信息。
* **`optimization` 选项：**  优化级别会影响 Frida 的性能。在某些场景下，可能需要构建未优化的 Frida (`optimization=0`) 以方便调试，而在其他性能敏感的场景下，则需要构建优化后的版本。
* **交叉编译选项 (`cross_file`)：**  如果需要在非开发主机上运行 Frida (例如在 Android 设备上)，则需要进行交叉编译。`coredata.py` 负责管理交叉编译相关的配置。

**举例说明：**

假设逆向工程师想要构建一个用于 Android 设备的 Frida 版本。他需要使用 Meson 进行配置，并指定交叉编译配置文件。`coredata.py` 中的相关功能会被调用：

1. 用户运行 `meson setup --cross-file android.cross`，其中 `android.cross` 是一个描述 Android 目标平台信息的配置文件。
2. Meson 会解析 `android.cross` 文件，并将相关信息存储在 `CoreData` 对象中。
3. 当需要设置编译器的选项时，`coredata.py` 中的 `is_cross_build` 方法会返回 `True`，表明正在进行交叉编译。
4. 后续的编译器和链接器选项的设置会考虑到目标平台的特性，例如使用 Android NDK 提供的工具链。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层：**  `optimization` 选项直接影响生成的二进制代码的结构和性能。不同的优化级别会影响指令的选择、寄存器的使用、代码的布局等底层细节。
* **Linux：**  安装路径选项 (`prefix`, `bindir`, `libdir` 等) 是 Linux 文件系统层级标准 (FHS) 的体现。`coredata.py` 负责管理这些路径，确保 Frida 安装到正确的位置。
* **Android 内核及框架：** 虽然 `coredata.py` 本身不直接操作内核，但构建用于 Android 的 Frida 需要理解 Android 的架构。交叉编译配置文件会指定目标 Android 平台的 ABI (Application Binary Interface)，例如 ARMv7 或 ARM64，这直接关系到生成的二进制代码如何在 Android 系统上运行。

**逻辑推理：**

假设输入以下用户操作：

```bash
meson setup builddir -Dbuildtype=release -Ddefault_library=static
```

`coredata.py` 中的 `set_options` 方法会被调用，并进行以下逻辑推理：

1. 解析 `-Dbuildtype=release`，找到 `OptionKey('buildtype')` 并将其值设置为 `'release'`。
2. `set_option` 方法会检测到 `buildtype` 发生变化，并调用 `_set_others_from_buildtype('release')`。
3. 在 `_set_others_from_buildtype` 中，根据 `'release'` 的值，推断出 `optimization` 应该设置为 `'3'`，`debug` 应该设置为 `False`。
4. 解析 `-Ddefault_library=static`，找到 `OptionKey('default_library')` 并将其值设置为 `'static'`。

最终，`CoreData` 对象中会存储以下选项值（部分）：

```
options = {
    OptionKey('buildtype'): UserComboOption(..., value='release'),
    OptionKey('optimization'): UserComboOption(..., value='3'),
    OptionKey('debug'): UserBooleanOption(..., value=False),
    OptionKey('default_library'): UserComboOption(..., value='static'),
    ...
}
```

**用户或编程常见的使用错误：**

1. **拼写错误的选项名：**  用户可能在命令行中使用 `-Dbytldupe=debug` 而不是 `-Dbuildtype=debug`。`coredata.py` 中的 `set_options` 方法会抛出异常，提示未知选项。
2. **提供无效的选项值：**  例如，对于 `buildtype` 选项，用户可能尝试设置一个不存在的值，如 `-Dbuildtype=fastbuild`。`set_option` 方法会检查选项的 `choices` 并抛出异常。
3. **尝试修改只读选项：**  某些内置选项是只读的，例如 `backend`。如果用户尝试在重新配置时修改它，`set_option` 方法会抛出异常。
4. **在子项目中设置其他子项目的选项：**  `update_project_options` 方法会检查选项的 `subproject` 属性，防止子项目修改不属于自己的选项。

**用户操作如何一步步到达这里作为调试线索：**

当开发者在使用 Meson 构建 Frida 时遇到问题，例如构建失败或配置错误，他们可能会需要查看 `coredata.py` 的执行过程。以下是可能的步骤：

1. **用户运行 `meson setup builddir [options]`：** 这是 Meson 构建的入口点。
2. **Meson 解析命令行参数：**  命令行中 `-D` 开头的选项会被解析，并传递给 `coredata.py` 中的函数进行处理。
3. **读取 `meson_options.txt` 和默认值：**  Meson 会读取项目根目录下的 `meson_options.txt` 文件以获取项目定义的选项，并加载内置选项的默认值。
4. **创建 `CoreData` 对象：**  在配置过程的早期，会创建 `CoreData` 对象来存储构建配置信息。
5. **调用 `set_options` 或 `set_default_options`：**  根据用户提供的命令行参数和项目定义的选项，相应的函数会被调用来设置 `CoreData` 对象中的选项值。
6. **保存 `CoreData` 到文件：**  配置完成后，`CoreData` 对象会被序列化并保存到 `builddir/meson-private/coredata.dat` 文件中。

作为调试线索，开发者可以：

* **检查 `coredata.dat` 文件：**  可以使用 `pickle` 模块加载该文件，查看实际存储的选项值，判断是否与预期一致。
* **在 `coredata.py` 中添加日志输出：**  在关键函数（如 `set_option`）中添加 `print` 语句，观察选项的设置过程和中间状态。
* **使用 Meson 的 `--verbose` 选项：**  可以获取更详细的构建日志，其中可能包含与选项处理相关的信息。

总而言之，`frida/subprojects/frida-core/releng/meson/mesonbuild/coredata.py` 中的这部分代码是 Meson 构建系统管理配置选项的核心，它直接影响着 Frida 的构建方式和最终产物的特性，与逆向工程、底层二进制、Linux/Android 平台都有着密切的联系。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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