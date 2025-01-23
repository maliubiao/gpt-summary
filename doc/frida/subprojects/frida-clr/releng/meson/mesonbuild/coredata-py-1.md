Response:
Let's break down the thought process for analyzing this Python code and generating the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `coredata.py` file within the Frida project, specifically in relation to reverse engineering, low-level concepts, and potential user errors. The prompt also emphasizes debugging clues and a summary of the file's purpose.

**2. Initial Code Scan and High-Level Understanding:**

My first step is always to quickly skim the code to get a general idea of what it's doing. I look for:

* **Imports:**  `os`, `configparser`, `ast`, `pickle`, `argparse`, etc. These hint at the types of operations performed (file handling, configuration parsing, serialization, command-line argument handling).
* **Class Definitions:** `CoreData`, `CmdLineFileParser`, `MachineFileParser`, `BuiltinOption`. These are the main building blocks of the code.
* **Key Data Structures:**  Dictionaries like `options`, `BUILTIN_OPTIONS`, `BUILTIN_OPTIONS_PER_MACHINE`. These likely store configuration information.
* **Function Names:**  `init_options`, `get_option`, `set_option`, `load`, `save`. These reveal the main actions the code performs.

From this initial scan, I can infer that the file is related to managing configuration data for the build process of the Frida CLR subproject. It deals with options, both built-in and project-specific, and handles loading and saving this configuration.

**3. Deeper Dive into Key Classes and Functions:**

Next, I'll examine the most important parts in more detail:

* **`CoreData`:** This appears to be the central class. I note its attributes (`options`, `deps`, `cross_files`, `compiler_check_cache`, etc.) which store different aspects of the build configuration. The `init_options` method seems crucial for setting up the initial options. The presence of `get_option` and `set_option` confirms its role in managing option values.
* **`BuiltinOption`:** This class clearly defines the structure of built-in configuration options, including their type, description, default value, and whether they are read-only. The `add_to_argparse` method suggests these options can be set from the command line.
* **`CmdLineFileParser` and `MachineFileParser`:** These classes handle reading configuration from files. `CmdLineFileParser` appears to read simple key-value pairs, while `MachineFileParser` is more complex, handling constants and potentially evaluating expressions. The references to "cross-file" and "native-file" are significant.
* **`load` and `save`:** These functions use `pickle` to serialize and deserialize the `CoreData` object, allowing the configuration to be persisted across build invocations.

**4. Connecting to Reverse Engineering and Low-Level Concepts:**

Now, I start thinking about how this code relates to the specific aspects mentioned in the prompt:

* **Reverse Engineering:**  The connection here lies in *how* Frida is used. Frida is a dynamic instrumentation toolkit, often used for reverse engineering. The configuration managed by this file directly influences Frida's behavior. For example, build type (debug/release) and optimization level will affect the generated Frida agent, which is then used for reverse engineering tasks. The "cross-file" and "native-file" options are direct links to building Frida for different target architectures, a common requirement in reverse engineering.
* **Binary/Low-Level:** The `link_args` option directly manipulates the linker, which is a crucial part of the binary creation process. The handling of different operating systems (Linux, Android) is suggested by the mention of kernel and framework knowledge, even if not explicitly coded *in this file*. The `install_umask` option affects file permissions at a low level.
* **Linux/Android Kernel and Framework:** While the code itself doesn't directly interact with the kernel, the *purpose* of Frida heavily involves interacting with process memory, function hooks, and other low-level system aspects. The configuration options managed here indirectly support those interactions. Building for Android implies understanding the Android framework.

**5. Identifying Logic and Assumptions:**

I look for conditional logic and how data is transformed:

* **`set_option`:** This function has logic for handling deprecated options, which involves potentially updating other options.
* **`_set_others_from_buildtype`:** This shows a clear dependency between the `buildtype` option and the `optimization` and `debug` options. This is a logical inference made by the code.
* **`is_cross_build`:** This function checks the presence of cross-compilation files to determine if it's a cross-build scenario.

**6. Spotting Potential User Errors:**

I consider common mistakes users might make when configuring the build:

* **Incorrect option values:** Providing invalid values for options (e.g., a string for an integer option).
* **Typos in option names:**  Trying to set an option that doesn't exist.
* **Conflicting options:** Setting options that are mutually exclusive or have unintended side effects.
* **Modifying read-only options:** Attempting to change options that are meant to be fixed.

**7. Tracing User Operations:**

I consider the typical workflow of a Frida user/developer:

1. **Clone the Frida repository.**
2. **Navigate to the `frida-clr` subdirectory.**
3. **Run the Meson configuration command (`meson setup build`).** This is where command-line options (`-D`) and potentially cross/native files are specified.
4. **Meson reads the `meson.build` files and processes the configuration.**  This is when `coredata.py` comes into play.
5. **Meson saves the configuration in `meson-private/coredata.dat`.**
6. **Later build commands (e.g., `ninja`) use this saved configuration.**

**8. Structuring the Response:**

Finally, I organize the information into a clear and structured answer, addressing each part of the prompt:

* **Functionality:** List the key functions and what they do.
* **Reverse Engineering Relevance:**  Explain how the configuration affects Frida's capabilities.
* **Binary/Low-Level Relevance:** Highlight the connections to linking, system directories, and low-level interactions.
* **Logic and Assumptions:** Provide examples of logical deductions and the relationship between options.
* **User Errors:**  Give concrete examples of common mistakes.
* **User Operations:**  Outline the steps that lead to this file being used.
* **Summary:**  Provide a concise overview of the file's role.

By following these steps, I can thoroughly analyze the code and generate a comprehensive and informative response that addresses all aspects of the prompt. The process involves understanding the code's structure, purpose, and how it fits into the broader context of the Frida project and reverse engineering.
好的，让我们来归纳一下`frida/subprojects/frida-clr/releng/meson/mesonbuild/coredata.py`文件的功能，这是第二部分的内容：

**归纳 `coredata.py` 的功能（第二部分）**

这部分代码主要负责处理和管理 Meson 构建系统中的配置选项，包括内置选项、项目选项和编译器选项。它涉及到选项的读取、设置、验证、持久化以及与命令行参数的交互。

**主要功能点：**

1. **添加和管理内置选项:**
    *   `init_options`: 初始化所有内置选项，包括通用的和特定于不同机器类型的选项（主机、构建）。
    *   `add_builtin_option`:  将单个内置选项添加到选项字典中。

2. **处理后端特定的选项:**
    *   `init_backend_options`:  为特定的构建后端（如 Ninja, Visual Studio）初始化其特有的选项。例如，Ninja 的最大链接器进程数，Visual Studio 的默认启动项目。

3. **读取和获取选项值:**
    *   `get_option`:  根据 `OptionKey` 获取选项的值。它会处理子项目和全局选项的情况，并处理 `wrap_mode` 枚举类型的转换。

4. **设置和验证选项值:**
    *   `set_option`:  设置选项的值，并进行一系列的验证和处理：
        *   处理 `prefix` 选项，用于规范化路径。
        *   检查选项是否已弃用，并发出警告或进行替换。
        *   防止修改只读选项。
        *   根据 `buildtype` 的值自动设置其他相关选项（如 `optimization` 和 `debug`）。

5. **清理缓存:**
    *   `clear_cache`: 清理依赖关系和编译器/运行检查的缓存。

6. **获取非默认构建类型参数:**
    *   `get_nondefault_buildtype_args`:  比较当前的优化级别和调试设置与基于 `buildtype` 的默认值，返回不同的参数。

7. **根据构建类型设置其他选项:**
    *   `_set_others_from_buildtype`: 根据 `buildtype` 的值设置 `optimization` 和 `debug` 选项。

8. **判断选项是否与机器类型相关:**
    *   `is_per_machine_option`: 判断一个选项是否是针对特定机器类型（主机、构建）的。

9. **获取外部参数和链接参数:**
    *   `get_external_args`: 获取特定机器和语言的外部编译器参数。
    *   `get_external_link_args`: 获取特定机器和语言的外部链接器参数。

10. **更新项目选项:**
    *   `update_project_options`: 更新或添加特定子项目的项目选项，并处理选项类型不匹配或选项选择发生变化的情况。

11. **判断是否是交叉编译:**
    *   `is_cross_build`:  检查是否存在交叉编译配置文件来判断是否是交叉编译。

12. **从常规选项复制构建选项:**
    *   `copy_build_options_from_regular_ones`:  在非交叉编译的情况下，将主机机器的选项值复制到构建机器的选项。

13. **批量设置选项:**
    *   `set_options`:  批量设置多个选项的值，包括内置选项和项目选项。它会处理 `prefix` 选项的特殊情况，并检查未知选项。

14. **设置默认选项:**
    *   `set_default_options`:  设置项目或子项目的默认选项，并与环境变量中的选项合并。它会过滤掉不适用于当前子项目的选项。

15. **添加编译器选项:**
    *   `add_compiler_options`:  添加特定语言和机器类型的编译器选项。

16. **添加语言参数:**
    *   `add_lang_args`: 添加在编译器/链接器检测之前需要的全局语言参数。

17. **处理编译器选项:**
    *   `process_compiler_options`:  处理特定语言编译器的选项，包括基本选项和特定于编译器的选项。

18. **发出基本选项警告:**
    *   `emit_base_options_warnings`:  针对某些基本选项组合发出警告，例如启用 bitcode 时禁用某些链接器选项。

**与逆向的关系：**

*   **构建类型 (`buildtype`) 和优化级别 (`optimization`)**: 这些选项直接影响最终生成的可执行文件和库的特性。在逆向工程中，分析 release 版本的二进制文件与 debug 版本的难度差异很大。Debug 版本包含调试符号，更容易进行分析和调试。通过设置 `buildtype=debug`，逆向工程师可以构建一个更易于分析的版本。
*   **交叉编译配置 (`cross_file`)**:  Frida 经常被用于在与开发环境不同的目标设备上进行动态插桩，例如 Android 或 iOS 设备。`cross_file` 指定了交叉编译的配置文件，允许为目标架构构建 Frida 组件。逆向工程师需要为目标设备构建 Frida Agent，才能在目标设备上运行 Frida 脚本。
*   **外部参数 (`get_external_args`) 和链接参数 (`get_external_link_args`)**:  这些选项允许在编译和链接过程中传递额外的参数。逆向工程师可能需要使用特定的编译器或链接器标志来解决特定的兼容性问题或启用特定的功能，以便更好地与目标环境交互。例如，在为特定版本的 Android 系统构建 Frida 时，可能需要传递特定的 NDK 参数。

**与二进制底层、Linux、Android 内核及框架的知识关系：**

*   **链接器参数 (`link_args`)**:  这些参数直接传递给链接器，控制着二进制文件的生成过程，例如库的链接方式、符号表的处理等。理解链接过程和链接器参数对于理解二进制文件的结构至关重要。
*   **安装目录 (`prefix`, `bindir`, `libdir` 等)**: 这些选项决定了 Frida 组件在目标系统上的安装位置。理解文件系统的布局对于在目标设备上部署和运行 Frida 是必要的。在 Android 上，安装路径可能需要根据设备的具体情况进行调整。
*   **交叉编译 (`cross_file`)**:  进行交叉编译需要深入了解目标平台的体系结构、ABI (Application Binary Interface)、系统库等。为 Android 构建 Frida 需要了解 Android NDK 以及 Android 系统的构建机制。
*   **构建类型 (`buildtype`)**:  Debug 版本的构建通常包含调试符号，这些符号与二进制文件的内存布局、函数调用栈等底层细节相关。理解这些信息有助于逆向工程师进行动态分析和调试。

**逻辑推理的例子：**

*   **假设输入:** 用户设置了 `buildtype=release`。
*   **输出:**  `_set_others_from_buildtype` 函数会被调用，并将 `optimization` 设置为 `'3'`，`debug` 设置为 `False`。这是基于预定义的逻辑，`release` 构建类型通常意味着高优化和禁用调试信息。

**用户或编程常见的使用错误：**

*   **设置未知的选项:** 用户在命令行或配置文件中尝试设置一个 Meson 不认识的选项名，`set_options` 函数会抛出 `MesonException`。
    *   **例子:**  用户输入 `meson setup build -Dunknow_option=true`，会导致错误，因为 `unknow_option` 不是内置选项或项目选项。
*   **为只读选项赋值:**  某些内置选项是只读的，用户尝试修改它们会导致 `MesonException`。
    *   **例子:**  用户尝试通过命令行修改 `backend` 选项（通常在第一次配置时确定），如 `meson setup build -Dbackend=cmake`，会导致错误。
*   **为选项设置无效的值:**  用户为选项设置了类型不匹配或超出允许范围的值。
    *   **例子:**  `optimization` 选项的允许值为 `['plain', '0', 'g', '1', '2', '3', 's']`，用户如果设置 `meson setup build -Doptimization=invalid`，`set_option` 会抛出异常。
*   **在子项目中设置全局选项:**  一些内置选项是全局的，不应该在子项目中设置。代码会检查 `opt.yielding` 属性来判断是否是全局选项。

**用户操作如何一步步到达这里（调试线索）：**

1. **用户执行 `meson setup build [options]` 命令:** 这是 Meson 配置构建环境的入口点。用户可以通过命令行选项 `-D` 设置各种构建选项。
2. **Meson 解析命令行参数:** Meson 会解析用户提供的选项，并将这些选项存储在 `SharedCMDOptions` 对象中。
3. **Meson 读取 `meson.build` 文件:** Meson 会读取项目根目录和子目录下的 `meson.build` 文件，了解项目的构建结构和依赖关系。
4. **创建 `CoreData` 对象:**  在配置过程中，Meson 会创建一个 `CoreData` 对象来存储构建配置信息。
5. **调用 `coredata.py` 中的函数:**
    *   `init_options` 会被调用以初始化内置选项。
    *   如果用户在命令行提供了选项，`parse_cmd_line_options` 会被调用来解析这些选项。
    *   `set_options` 会被调用来应用用户提供的选项。
    *   如果涉及到子项目，`update_project_options` 会被调用来处理子项目的选项。
    *   如果涉及到交叉编译，会读取 `cross_file`，并可能影响后续的选项设置。
6. **保存 `CoreData` 到文件:**  配置完成后，`CoreData` 对象会被序列化并保存到 `build_dir/meson-private/coredata.dat` 文件中，以便后续构建步骤使用。

**总结:**

`coredata.py` 文件的这部分主要负责 Meson 构建系统中核心配置选项的管理。它定义、读取、设置、验证和持久化各种构建选项，包括内置选项、项目选项和编译器选项。它还处理了与命令行参数的交互，并支持交叉编译等高级功能。理解这个文件对于理解 Meson 构建系统的运作方式以及如何配置 Frida 的构建至关重要，尤其是在进行逆向工程、需要针对特定目标平台构建 Frida 时。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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