Response:
The user wants to understand the functionality of the Python code provided, which is a part of the Frida dynamic instrumentation tool. The code is located in `frida/releng/meson/mesonbuild/coredata.py`.

Here's a plan to address the user's request:

1. **Identify the Core Purpose:**  Scan the code for keywords and patterns that reveal its main function. Look for class names, method names, and variable names that suggest a specific role.
2. **Break Down Functionality:**  Go through the key classes and methods, explaining what they do.
3. **Relate to Reverse Engineering:**  Analyze if any parts of the code are directly related to or facilitate reverse engineering tasks. Provide examples if found.
4. **Identify Low-Level/Kernel Aspects:** Look for mentions of operating systems (Linux, Android), kernel concepts, or interactions with binary data.
5. **Analyze Logic and Inference:**  Examine methods that perform conditional logic or calculations based on inputs. Create hypothetical inputs and outputs.
6. **Spot Potential User Errors:**  Identify areas where incorrect user input or actions could lead to errors or unexpected behavior. Provide examples.
7. **Trace User Actions:**  Consider how a user interacting with Frida might indirectly trigger the execution of this code.
8. **Summarize Functionality (Part 2):**  Concisely summarize the key responsibilities of the code, as this is part 2 of a 3-part request.

**Pre-computation/Analysis:**

* The code heavily involves managing build options and configurations for the Meson build system.
* Keywords like `OptionKey`, `UserStringOption`, `UserBooleanOption`, `BuiltinOption`, and `CoreData` are central.
* The code handles both built-in and project-specific options.
* It deals with cross-compilation scenarios.
* It interacts with configuration files and command-line arguments.

**Self-Correction/Refinement:**

* Initially, I might focus too much on the specific details of each option. The request asks for the *functionality*, so I need to abstract away some of the fine-grained details and focus on the broader purpose of option management.
* The "reverse engineering" aspect might be indirect. The build configuration can influence how Frida is built, which in turn affects its capabilities for reverse engineering.
* When giving examples for user errors, I need to think from the perspective of a user trying to configure the build, not necessarily a developer working on Frida's internals.

Let's start by identifying the core purpose and then proceed with the other points.
这是 `frida/releng/meson/mesonbuild/coredata.py` 文件的第二部分代码。结合第一部分，我们可以继续分析其功能：

**延续第一部分， `coredata.py` 文件主要负责管理 Frida 构建系统的配置数据，包括各种构建选项。**

**核心功能（基于第二部分代码）：**

1. **处理编译器选项:**
   - `add_compiler_options`:  将特定语言（如 C, C++）的编译器提供的选项添加到核心数据中。这允许根据所使用的编译器配置构建过程。
   - `add_lang_args`: 添加在编译器/链接器检测之前需要的全局语言参数。
   - `process_compiler_options`: 处理编译器的选项，包括基础选项，并发出与基础选项相关的警告。

2. **管理构建机器（Build Machine）和宿主机（Host Machine）的选项:**
   - `is_per_machine_option`: 判断一个选项是否是针对特定机器（构建机器或宿主机）的。
   - `get_external_args` 和 `get_external_link_args`:  获取特定机器和语言的外部编译器和链接器参数。
   - `copy_build_options_from_regular_ones`: 将常规（宿主机）选项的值复制到构建机器的选项中，这在非交叉编译时执行。

3. **处理项目特定的选项:**
   - `update_project_options`: 更新或添加子项目定义的选项。如果子项目的选项与已有的选项类型不同或选项的可用值改变，会进行相应的处理。

4. **处理交叉编译:**
   - `is_cross_build`: 判断当前是否为交叉编译。
   - 在 `set_options` 中，会根据是否为交叉编译来过滤掉构建机器的选项。

5. **读取和写入命令行选项到文件:**
   - `CmdLineFileParser`:  一个自定义的配置文件解析器，用于读取命令行选项。
   - `MachineFileParser`:  用于解析机器描述文件，这些文件通常用于配置交叉编译环境。
   - `get_cmd_line_file`, `read_cmd_line_file`, `write_cmd_line_file`, `update_cmd_line_file`:  负责将命令行选项持久化到文件中，以便在后续构建或重新配置时加载。
   - `format_cmd_line_options`:  将命令行选项格式化为字符串。

6. **处理 Meson 版本变更:**
   - `major_versions_differ`:  检查当前 Meson 版本与上次保存的 `coredata` 文件的 Meson 版本是否主要版本不同，以防止不兼容。

7. **加载和保存核心数据:**
   - `load`: 从文件中加载 `CoreData` 对象。
   - `save`: 将 `CoreData` 对象保存到文件。

8. **注册和解析内置参数:**
   - `register_builtin_arguments`: 将内置选项注册到 `argparse` 中，以便可以通过命令行参数进行设置。
   - `create_options_dict`:  从字符串列表创建选项字典。
   - `parse_cmd_line_options`:  解析命令行选项。

9. **定义内置选项:**
   - `BuiltinOption`:  一个类，用于定义内置构建选项的类型、描述、默认值等。
   - `BUILTIN_DIR_OPTIONS`, `BUILTIN_CORE_OPTIONS`:  定义了各种内置的目录选项和核心选项。

**与逆向方法的关系及举例说明:**

* **构建类型的配置会影响生成的 Frida Agent 的特性。** 例如，使用 `buildtype=debug` 构建的 Frida 会包含调试符号，这在逆向分析时非常有用，因为可以方便地使用调试器进行跟踪和断点调试。而 `buildtype=release` 构建的版本则会进行优化，体积更小，但调试信息较少。
  * **举例：** 用户在构建 Frida 时，可以选择 `meson build -Dbuildtype=debug` 来生成包含调试信息的 Frida Agent，方便后续的逆向工作，比如使用 gdb 调试 Frida Agent 的行为。

* **交叉编译配置会影响目标平台的 Frida Agent 的构建。** 在进行 Android 或 iOS 等平台的逆向时，需要针对目标平台进行交叉编译。`coredata.py` 中处理交叉编译相关的选项和配置，确保 Frida 能够在目标平台上运行。
  * **举例：** 用户想要逆向一个 Android 应用，需要使用 Android 版本的 Frida。这需要在构建 Frida 时提供一个 Android 的交叉编译配置文件，`coredata.py` 会解析这个文件中的信息，配置编译工具链和目标平台相关的选项。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

* **链接器参数 (`link_args`) 会直接影响生成的二进制文件的链接过程。**  例如，可以指定链接的库，或者传递特定的链接器标志。这与 Frida Agent 如何与目标进程交互的底层机制有关。
  * **举例：**  在某些平台上，可能需要传递特定的链接器参数来确保 Frida Agent 可以注入到目标进程中。这些参数可以通过配置选项传递到 `coredata.py` 进行处理。

* **安装目录 (`prefix`, `libdir`, `bindir` 等) 的配置决定了 Frida 工具和库的安装位置。** 这关系到操作系统的文件系统结构和 Frida 的部署方式。
  * **举例：**  在 Linux 系统上，用户可以通过设置 `prefix=/opt/frida` 来将 Frida 安装到 `/opt/frida` 目录下。`coredata.py` 负责管理这些目录选项。

* **构建类型 (`buildtype`) 会影响编译器的优化级别和调试信息的生成。** 这直接影响到最终生成的二进制代码的效率和可调试性。
  * **举例：**  选择 `buildtype=release` 通常会启用编译器的代码优化选项，生成的二进制代码执行效率更高，但可能更难调试。这涉及到编译器的工作原理和二进制代码的生成过程。

**逻辑推理及假设输入与输出:**

* **假设输入：** 用户在命令行中执行 `meson configure -Dbuildtype=release -Doptimization=3`。
* **逻辑推理：** `parse_cmd_line_options` 会解析这些参数，并将 `buildtype` 的值设置为 'release'，`optimization` 的值设置为 '3'。 `set_options` 方法会被调用，并根据这些值更新 `self.options` 字典中对应的 `OptionKey` 的值。`_set_others_from_buildtype` 方法可能会被调用，以确保 `debug` 选项的值与 `buildtype` 保持一致（例如，当 `buildtype` 为 'release' 时，`debug` 通常为 `False`）。
* **输出：** `self.options[OptionKey('buildtype')]` 的 `value` 属性将为 'release'，`self.options[OptionKey('optimization')]` 的 `value` 属性将为 '3'，并且 `self.options[OptionKey('debug')]` 的 `value` 属性很可能被设置为 `False`。

**用户或编程常见的使用错误及举例说明:**

* **设置了未知的构建选项：** 用户在命令行中输入了 Meson 不识别的选项名称。
  * **举例：** `meson configure -Dunknown_option=value`。`set_options` 方法会检查传入的选项，如果 `unknown_option` 不在已知的内置选项或项目选项中，会抛出 `MesonException`，提示 "Unknown options: "unknown_option""。

* **尝试修改只读选项：**  某些内置选项是只读的，用户尝试在重新配置时修改这些选项会导致错误。
  * **举例：**  `backend` 选项通常是只读的。如果用户尝试在已经配置过的构建目录中执行 `meson configure -Dbackend=cmake`，`set_option` 方法会检测到该选项是只读的，并抛出 `MesonException`，提示 "Tried modify read only option 'backend'"。

* **选项值不合法：**  用户为某个选项设置了不符合其类型或可用值的取值。
  * **举例：** `meson configure -Dbuildtype=invalid_type`。 `set_option` 方法在尝试设置 `buildtype` 选项的值时，会检查 'invalid_type' 是否在 `buildtypelist` 中，如果不在，则会因为 `UserComboOption` 的值校验失败而抛出异常。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户执行 `meson configure [build directory] [options]` 命令。**  这是启动 Meson 构建系统配置阶段的关键步骤。
2. **Meson 解析命令行参数。**  `argparse` 模块会解析用户提供的选项，包括 `-D` 开头的项目选项和 `--` 开头的内置选项。
3. **`parse_cmd_line_options` 函数被调用。**  这个函数负责将解析后的命令行选项存储到 `SharedCMDOptions` 对象中。
4. **`CoreData` 对象被创建或加载。** 如果是首次配置，会创建一个新的 `CoreData` 对象。如果已经配置过，则会从 `meson-private/coredata.dat` 文件中加载。
5. **`set_options` 方法被调用。**  这个方法接收解析后的命令行选项，并更新 `CoreData` 对象中的选项值。在 `set_options` 内部，会调用 `set_option` 来处理单个选项的设置。
6. **在 `set_option` 内部，会根据选项的类型进行不同的处理。** 例如，会检查选项是否是内置选项，是否是只读的，选项的值是否合法等等。
7. **如果涉及到编译器选项，`process_compiler_options` 方法会被调用。**  这个方法会处理特定语言的编译器提供的选项。
8. **如果涉及到交叉编译，会解析交叉编译配置文件。**  `MachineFileParser` 用于解析这些文件。

因此，当你在调试 Meson 构建配置问题时，如果怀疑是由于配置选项引起的，可以关注 `meson configure` 命令的执行过程，以及 `coredata.py` 中 `parse_cmd_line_options` 和 `set_options` 等方法的执行情况。查看传递给这些方法的参数，可以帮助你理解选项是如何被解析和应用的。

**归纳一下它的功能 (第二部分):**

这部分代码延续了 `coredata.py` 的核心功能，即 **管理 Frida 构建系统的各种配置选项**。 具体来说，它专注于：

* **处理和管理编译器相关的选项，包括语言特定的参数。**
* **区分和处理针对不同机器（构建机器和宿主机）的选项，特别是针对交叉编译场景。**
* **允许子项目定义和更新自己的构建选项。**
* **读取和写入命令行选项到文件，实现配置的持久化。**
* **处理 Meson 版本变更，防止因版本不兼容导致的问题。**
* **提供加载和保存核心配置数据的功能。**
* **注册和解析命令行参数，使得用户可以通过命令行灵活地配置构建过程。**
* **定义了各种内置的构建选项及其属性。**

总而言之，这部分代码是 Meson 构建系统中负责配置管理的关键组件，它确保了 Frida 可以根据用户的需求和目标平台进行正确地构建。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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