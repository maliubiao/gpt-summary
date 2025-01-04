Response:
The user wants a summary of the functionalities of the Python code provided, which is a part of the Frida dynamic instrumentation tool. I need to analyze the code and identify its main tasks, relating them to reverse engineering, low-level programming, kernel interaction, and potential user errors.

Here's a breakdown of the thought process:

1. **Identify the Core Purpose:** The file `coredata.py` within the `mesonbuild` directory strongly suggests that this code manages and stores configuration data for the build system. Meson is the build system used by Frida. Therefore, the core purpose is handling configuration options.

2. **Analyze Key Classes and Functions:**  I'll go through the code and identify the major classes and functions and what they do.

    * **`CoreData` class:** This seems to be the central data structure holding all the configuration information. It manages various types of options (builtin, project, compiler, etc.). Key methods include:
        * `__init__`: Initialization, including setting up default options.
        * `add_builtin_options`: Adding predefined options.
        * `init_backend_options`: Setting backend-specific options.
        * `get_option`, `set_option`: Accessing and modifying option values.
        * `update_project_options`: Handling options specific to subprojects.
        * Methods related to cross-compilation.
        * Methods related to compiler options.
        * Methods for saving and loading the configuration.
    * **`BuiltinOption` class:**  Defines the structure and behavior of built-in configuration options.
    * **`CmdLineFileParser` class:**  Handles parsing configuration options from command-line files.
    * **`MachineFileParser` class:**  Handles parsing machine-specific configuration files (like cross-compilation definitions).
    * **Helper functions:** `parse_machine_files`, `read_cmd_line_file`, `write_cmd_line_file`, `load`, `save`, etc. These functions perform specific tasks related to managing and persisting the configuration.

3. **Relate to Reverse Engineering:** Frida is a reverse engineering tool. How does this configuration code relate?
    * **Cross-compilation:** Frida is often used to target different architectures (e.g., instrumenting an Android app from a Linux desktop). The configuration needs to handle cross-compilation settings.
    * **Backend selection:** Frida likely supports different backends for building its components. The configuration manages this.
    * **Compiler/linker options:**  Frida's build process involves compiling code. Configuration options for compilers and linkers are crucial.

4. **Relate to Binary/Low-Level, Linux/Android Kernel/Framework:**
    * **Cross-compilation settings:** This directly relates to different CPU architectures and operating systems.
    * **Compiler/linker flags:** These flags directly impact the generated binary code and how it interacts with the operating system and kernel.
    * **Installation directories:** The configuration specifies where Frida's components will be installed, which is relevant to system-level integration.

5. **Identify Logical Reasoning:**
    * **`_set_others_from_buildtype`:** This function infers debug and optimization levels based on the selected `buildtype`. This is a clear example of logical reasoning.
    * **Handling deprecated options:** The code checks for deprecated options and might issue warnings or automatically update the configuration.

6. **Consider User Errors:**
    * **Invalid option values:** The code performs type checking and validation on option values.
    * **Setting read-only options:** The code prevents modifying read-only options after the initial configuration.
    * **Unknown options:** The code detects and reports errors when users try to set options that don't exist.
    * **Conflicting options:** The code checks for conflicts between command-line options and options set in configuration files.

7. **Trace User Operations:** How does a user's action lead to this code being executed?
    * **Running `meson` command:**  This is the entry point to the build system.
    * **Passing command-line arguments:** Options specified with `-D` or other flags will be parsed and processed by this code.
    * **Using cross/native files:** If the user specifies `--cross-file` or `--native-file`, the parsing logic in this file will handle them.
    * **Reconfiguring the build:** If the user modifies configuration and runs `meson` again, this code will be involved in updating the configuration.

8. **Synthesize the Summary:** Based on the above analysis, I'll formulate a concise summary of the file's functionalities.

**(Self-Correction/Refinement):** Initially, I might focus too much on individual functions. It's important to step back and identify the overarching purpose. Also, explicitly linking the functionalities to the context of Frida and reverse engineering is crucial for answering the prompt fully. I need to make sure to provide concrete examples for each category (reverse engineering, low-level, user errors, etc.).
好的，让我们来归纳一下 `frida/subprojects/frida-swift/releng/meson/mesonbuild/coredata.py` 文件的功能，作为第 2 部分的总结。

**核心功能归纳：**

这个 `coredata.py` 文件的核心职责是**管理和存储 Meson 构建系统的核心配置数据 (CoreData)**。它负责处理各种构建选项，包括内置选项、项目选项、编译器选项等，并提供了一系列方法来读取、设置、验证和持久化这些选项。

更具体地说，其功能可以概括为：

1. **定义和管理内置构建选项 (Built-in Options):**
   -  定义了 Meson 预设的各种构建选项，例如安装路径 (`prefix`, `bindir` 等)、构建类型 (`buildtype`)、优化级别 (`optimization`)、调试信息 (`debug`) 等。
   -  每个内置选项都有类型 (`UserStringOption`, `UserBooleanOption` 等)、描述、默认值等属性。
   -  支持区分主机 (host) 和构建 (build) 机器的选项。

2. **处理和存储构建选项的值:**
   -  维护一个字典 (`self.options`) 来存储所有生效的构建选项及其值。
   -  能够从命令行参数、配置文件 (如 `cmd_line.txt`) 和机器描述文件 (`cross_file`, `native_file`) 中读取选项值。
   -  提供了 `get_option` 和 `set_option` 方法来获取和设置选项的值。

3. **支持项目特定的构建选项 (Project Options):**
   -  允许项目（包括子项目）定义自己的构建选项。
   -  能够更新和管理子项目的选项，并防止子项目之间选项的互相干扰。

4. **处理编译器和语言相关的构建选项 (Compiler and Language Options):**
   -  能够添加和管理特定编译器或编程语言的选项（例如，C++ 编译器的 `-std` 选项）。
   -  在编译器的检测和配置过程中，会加载和处理相关的选项。

5. **支持交叉编译 (Cross-Compilation):**
   -  能够读取和解析交叉编译配置文件 (`cross_file`)，其中包含了目标平台的配置信息。
   -  区分主机 (host) 和目标 (target) 机器的选项，并分别进行管理。

6. **持久化和加载构建配置:**
   -  使用 `pickle` 模块将当前的构建配置数据 (`CoreData` 对象) 保存到磁盘上的 `coredata.dat` 文件中。
   -  提供了 `load` 和 `save` 函数来加载和保存构建配置，以便在后续的构建过程中重用。

7. **处理用户提供的命令行选项:**
   -  解析用户通过 `-D` 命令行参数提供的选项。
   -  处理通过特定参数（如 `--prefix` 等）设置的内置选项。

8. **处理默认选项:**
   -  允许项目设置默认的构建选项。
   -  处理默认选项的优先级和覆盖规则。

9. **提供选项的元数据和校验:**
   -  存储选项的描述信息，用于生成帮助信息等。
   -  进行基本的选项值校验，例如检查是否为允许的选择值。

10. **处理已弃用的选项 (Deprecated Options):**
    -  能够识别和处理已弃用的选项，发出警告信息，甚至自动替换为新的选项。

**与逆向方法的关系举例说明：**

* **交叉编译配置:** 在进行针对 Android 或 iOS 设备的逆向工程时，Frida 需要编译针对目标平台的 agent 代码。`coredata.py` 中对 `cross_file` 的处理和对不同机器 (host vs. target) 选项的管理，直接支持了这种跨平台构建过程。例如，用户可以通过 `--cross-file` 指定一个 Android 的工具链配置文件，`coredata.py` 会解析该文件，设置目标平台的编译器、链接器路径等信息，从而让 Frida 能够正确地构建在 Android 上运行的 agent。

**涉及到二进制底层，Linux, Android 内核及框架的知识举例说明：**

* **编译器和链接器选项:**  `coredata.py` 中处理的编译器选项（例如 `-O2` 优化级别，`-g` 调试信息）和链接器选项（例如链接静态库或共享库）直接影响最终生成的二进制代码。这些选项的选择会影响程序的性能、大小以及是否包含调试信息，这都是底层二进制相关的概念。
* **安装路径配置:** `bindir`, `libdir` 等选项定义了 Frida 组件安装到目标系统的位置。对于 Linux 和 Android 系统，这些路径通常有特定的含义和约定，例如 `/usr/bin` 用于存放可执行文件，`/usr/lib` 用于存放库文件。正确配置这些路径对于 Frida 的正常运行至关重要。
* **交叉编译工具链:**  交叉编译配置涉及到指定目标平台的编译器、链接器以及相关的系统库路径。这些工具链是与目标平台的内核和框架紧密相关的。例如，在为 Android 构建 Frida agent 时，需要使用 Android NDK 提供的工具链，其中包含了针对 Android 内核和 Bionic C 库的编译器和链接器。

**逻辑推理的假设输入与输出举例说明：**

假设用户设置了 `buildtype` 为 `debug`，而没有显式设置 `optimization` 和 `debug` 选项。

* **假设输入:** `options = {'buildtype': 'debug'}`
* **`_set_others_from_buildtype` 函数的逻辑推理:**
    -  `buildtype` 为 `debug`。
    -  根据预设的逻辑，`debug` 构建类型应该启用调试信息 (`debug = True`)，优化级别设置为最低 (`opt = '0'`)。
    -  比较当前 `optimization` 和 `debug` 选项的值与推理出的值。
    -  如果当前 `optimization` 不是 `'0'`，则设置 `optimization` 为 `'0'`，并标记 `dirty` 为 `True`。
    -  如果当前 `debug` 不是 `True`，则设置 `debug` 为 `True`，并标记 `dirty` 为 `True`。
* **输出:**  如果初始状态 `optimization` 为 `'2'` 且 `debug` 为 `False`，则 `dirty` 为 `True`，并且 `self.options['optimization'].value` 将被设置为 `'0'`，`self.options['debug'].value` 将被设置为 `True`。

**用户或编程常见的使用错误举例说明：**

* **设置未知的构建选项:** 用户在命令行中使用 `-Dunknown_option=value`，`coredata.py` 的 `set_options` 函数会检查是否存在该选项，如果不存在，则会抛出 `MesonException`，提示用户该选项未知。
* **尝试修改只读选项:**  某些内置选项（例如 `backend`）被设置为只读。如果用户尝试在初始配置之后修改这些选项，例如在 `meson_options.txt` 中设置 `backend = 'other_backend'`，`set_option` 函数会检查选项的 `readonly` 属性，并抛出 `MesonException`。
* **选项值类型错误:**  如果某个选项期望一个布尔值，而用户提供了一个字符串，例如 `-Ddebug=not_a_bool`，则在解析和设置选项值的过程中可能会出错，具体取决于选项类型的处理方式。Meson 的选项系统会尽力进行类型转换和校验，但错误的类型可能会导致不可预测的行为或错误。
* **交叉编译配置文件错误:**  如果用户提供的 `cross_file` 格式不正确，或者包含了无效的配置项，`MachineFileParser` 在解析该文件时会抛出 `EnvironmentException`。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户执行 `meson` 命令:** 这是配置构建系统的入口点。
2. **Meson 解析命令行参数:**  Meson 会解析用户提供的命令行参数，包括 `-D` 选项、`--cross-file`、`--native-file` 等。
3. **加载已存在的构建配置 (如果存在):** 如果之前已经配置过构建系统，Meson 会尝试加载 `build_dir/meson-private/coredata.dat` 文件，其中包含了之前的构建配置。
4. **处理命令行选项:**  `parse_cmd_line_options` 函数会被调用，将命令行参数转换为选项字典。
5. **处理配置文件:**  如果指定了交叉编译或本地编译配置文件，`MachineFileParser` 会被用来解析这些文件。
6. **调用 `CoreData` 的方法设置选项:**  例如，`set_options` 方法会被调用，根据命令行参数和配置文件中的值来更新 `CoreData` 对象中的选项。
7. **保存构建配置:**  配置完成后，`save` 函数会被调用，将更新后的 `CoreData` 对象保存到 `coredata.dat` 文件中。

作为调试线索，如果用户在配置过程中遇到问题，例如配置选项没有生效，或者出现了意外的构建行为，可以检查以下几点：

* **检查 `meson_log.txt`:** Meson 的日志文件会记录选项的设置过程和任何警告或错误信息。
* **检查 `build_dir/meson-private/cmd_line.txt`:** 该文件存储了上次配置时使用的命令行选项。
* **检查 `build_dir/meson-private/coredata.dat`:**  可以使用 `pickle` 模块加载该文件，查看最终生效的选项值。
* **逐步执行 `coredata.py` 中的代码:** 使用 Python 调试器（如 `pdb`）可以跟踪选项的读取、设置和验证过程，找出问题的根源。例如，可以在 `set_option` 函数中设置断点，查看选项的值是如何被修改的。

希望这个归纳能够帮助你更好地理解 `coredata.py` 文件的功能。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
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
"""


```