Response:
My goal is to analyze the provided Python code snippet and explain its functionality, particularly in the context of reverse engineering, low-level interactions, and potential user errors. The code is a part of Meson build system, specifically dealing with configuration options.

Here's a breakdown of my thought process:

1. **Identify the Core Functionality:** The file `coredata.py` within the `frida-gum` project's Meson build system suggests it handles the storage and management of core build data, including configuration options. The code confirms this, as it defines classes and functions for handling built-in options, user-defined options, and loading/saving this data.

2. **Scan for Key Concepts and Structures:** I look for classes and functions that reveal the purpose of the code. `CoreData`, `BuiltinOption`, `UserOption` subclasses (like `UserStringOption`, `UserBooleanOption`), `OptionKey`, `set_option`, `get_option`, and the loading/saving functions (`load`, `save`) are all important indicators.

3. **Analyze Function by Function (and Class by Class):**

   * **`CoreData`:** This class is the central data container. I note its members like `options`, `deps`, `compiler_check_cache`, `run_check_cache`, `cross_files`, and `version`. The methods within `CoreData` seem to revolve around managing these members, particularly the `options` dictionary.

   * **`BuiltinOption`:**  This represents pre-defined build options. I pay attention to how they're initialized (`init_option`), their properties (`yielding`, `readonly`), and how they interact with command-line arguments (`add_to_argparse`).

   * **`UserOption` subclasses:** These represent different data types for options (string, boolean, integer, etc.). I note how they store and validate values.

   * **`OptionKey`:** This seems to be a way to uniquely identify an option, potentially including context like subproject and machine architecture.

   * **`set_option` and `get_option`:** These are crucial for accessing and modifying option values. The logic within `set_option`, especially the handling of deprecated options, is interesting.

   * **Loading and Saving (`load`, `save`):** These functions use `pickle` to persist the `CoreData` object. This is a key observation for understanding how Meson stores its configuration.

   * **Command-line option parsing (`CmdLineFileParser`, `MachineFileParser`, `parse_cmd_line_options`, `create_options_dict`):** This reveals how user-provided options are processed. The distinction between command-line arguments and configuration files is important.

4. **Connect to Reverse Engineering (if applicable):**  I consider how the manipulation of build options might relate to reverse engineering. For instance:

   * **`debug` option:** Enabling this adds debug symbols, crucial for debugging reversed binaries.
   * **`optimization` option:** This affects the level of code optimization, impacting the difficulty of reverse engineering. Lower optimization often makes the code easier to follow.
   * **Cross-compilation options (related to `cross_files`):** These are relevant when reverse engineering targets for different architectures.
   * The ability to define custom compiler/linker flags (`args`, `link_args`) can be used to inject specific behavior or facilitate analysis during reverse engineering.

5. **Connect to Low-Level Concepts:** I look for interactions with operating system features or binary formats:

   * **File paths and directories:** Options like `prefix`, `bindir`, `libdir` directly relate to the file system structure of the installed software.
   * **Linker options (`backend_max_links`):**  This is a direct interaction with the linking process.
   * **Cross-compilation (`is_cross_build`):** This involves building for a target architecture different from the host.

6. **Identify Logic and Assumptions:**

   * The handling of deprecated options in `set_option` involves conditional logic.
   * The `_set_others_from_buildtype` method shows how changing the `buildtype` option can affect other related options.
   * The code assumes a specific structure for option keys and values.

7. **Consider User Errors:**  I think about common mistakes users might make:

   * Incorrect option names or values.
   * Trying to set read-only options after the initial configuration.
   * Providing conflicting options (e.g., via `-D` and dedicated command-line flags).
   * Issues with machine files.

8. **Trace User Actions:** I consider how a user interacts with Meson to reach this code:

   * Running `meson setup` to configure the build.
   * Providing command-line arguments like `-D` or `--option`.
   * Using cross-compilation files.
   * Reconfiguring an existing build.

9. **Synthesize and Summarize:** Finally, I consolidate my findings into a concise description of the file's functionality, relating it to the specified areas (reverse engineering, low-level details, logic, user errors, and user interaction). I focus on the core purpose of managing build options and how this ties into the broader Meson build process.

By following this structured approach, I can effectively analyze the code, extract relevant information, and provide a comprehensive explanation. The iterative nature of examining the code, connecting it to the prompt's requirements, and refining the understanding is key to generating a good response.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/coredata.py` 文件的第二部分，其主要功能是**管理和存储构建系统的核心数据，特别是各种构建选项**。它负责处理内置选项、项目选项，以及从命令行、配置文件中读取和写入选项值。

以下是更详细的功能分解和与您要求的对应说明：

**核心功能归纳：**

* **定义和管理构建选项:**  `CoreData` 类是核心，它存储了所有构建选项及其值。它区分了内置选项（`BUILTIN_OPTIONS`, `BUILTIN_OPTIONS_PER_MACHINE`）和项目特定的选项。
* **处理选项的设置和获取:** 提供了 `set_option` 和 `get_option` 方法来设置和获取选项的值。
* **处理选项的默认值:** 负责初始化选项的默认值，并考虑了 `prefix` 选项对其他目录选项的影响。
* **支持不同机器类型的选项:**  通过 `MachineChoice` 枚举，支持为主机（host）和构建机（build）设置不同的选项。
* **处理交叉编译:** 提供了 `is_cross_build` 方法来判断是否是交叉编译，并能根据是否交叉编译来过滤构建机（build machine）的选项。
* **从多种来源加载选项:**  可以从命令行参数、meson选项文件 (`cmd_line.txt`) 和机器描述文件加载选项。
* **将选项持久化到文件:** 使用 `pickle` 将 `CoreData` 对象保存到 `coredata.dat` 文件中，以便在后续构建中重用。
* **处理选项的弃用和替换:** `set_option` 方法包含处理已弃用选项的逻辑，可以发出警告或者将旧选项的值迁移到新的选项。
* **与构建类型相关联的选项:**  `_set_others_from_buildtype` 方法演示了如何根据 `buildtype` 选项的值自动设置其他相关选项（例如 `optimization` 和 `debug`）。
* **处理编译器特定的选项:** 提供了 `add_compiler_options` 和 `process_compiler_options` 方法来处理编译器相关的选项。
* **处理默认选项:** `set_default_options` 方法允许项目或子项目设置默认选项。

**与逆向方法的关系及举例说明：**

* **控制编译输出的调试信息：** `debug` 选项直接影响编译后的二进制文件中是否包含调试符号。逆向工程师通常会偏好包含调试符号的版本，以便更容易地使用调试器（如GDB或LLDB）进行分析。例如，如果 Frida 基于此代码进行构建，设置 `-Ddebug=true` 会生成带有调试符号的 Frida Gum 库，方便逆向 Frida Gum 本身。
* **控制代码优化级别：** `optimization` 选项影响编译器对代码的优化程度。高优化级别会使代码更难阅读和理解，但性能更高。逆向工程师有时会尝试使用未优化的版本，以便更清晰地了解代码的执行流程。例如，设置 `-Doptimization=0` 可以降低 Frida Gum 的优化级别，使其更容易进行静态分析。
* **影响库的类型（静态或动态）：** `default_library` 选项决定了默认情况下构建的库是静态库还是动态库。这会影响最终应用程序的链接方式和依赖关系，逆向工程师需要了解这些信息。例如，如果 Frida Gum 以静态库形式链接到目标进程，逆向工程师需要分析整个 Frida Gum 代码；如果是动态库，则可以单独分析 Frida Gum 的 `.so` 文件。
* **自定义编译器/链接器参数：** `get_external_args` 和 `get_external_link_args` 允许用户指定额外的编译器和链接器参数。这可以用于插入特定的标志，例如用于生成代码覆盖率信息的标志，或者用于禁用某些安全特性以便更容易进行逆向。例如，可以设置 `-Dc_args=-fno-stack-protector` 来禁用栈保护，方便分析潜在的缓冲区溢出漏洞。

**涉及到二进制底层、Linux、Android内核及框架的知识及举例说明：**

* **文件系统路径：**  诸如 `prefix`, `bindir`, `libdir` 等选项定义了安装路径，这些路径在 Linux 和 Android 系统中具有标准含义。例如，`libdir` 通常是共享库的安装位置，逆向工程师需要知道这些路径才能找到 Frida Gum 的库文件。
* **构建类型（`buildtype`）：**  不同的构建类型（如 `debug`, `release`）会影响编译器和链接器的行为，例如是否启用调试符号、优化级别等，这些都与二进制文件的最终形式密切相关。在 Android 开发中，`debug` 版本通常用于开发和调试，包含更多的日志和调试信息。
* **安装权限 (`install_umask`)：**  此选项设置安装文件的默认权限掩码，这是 Linux 文件系统权限的基础概念。
* **链接器行为 (`backend_max_links`)：**  `backend_max_links` 选项控制链接器的并行进程数，链接是生成最终可执行文件或库的关键步骤。
* **交叉编译（`is_cross_build`, `cross_files`）：**  交叉编译是指在一个平台上构建可在另一个平台上运行的代码。Frida 作为一款跨平台工具，其构建过程可能涉及交叉编译，尤其是在针对 Android 等嵌入式系统时。`cross_files` 定义了目标平台的构建环境。
* **编译器和链接器标志 (`get_external_args`, `get_external_link_args`)：**  这些方法允许用户传递特定于编译器和链接器的命令行参数。理解这些参数对于理解二进制文件的构建过程至关重要。例如，在 Android 开发中，可能需要指定特定的 NDK 工具链路径或架构相关的标志。

**逻辑推理及假设输入与输出：**

* **假设输入：** 用户在命令行中执行 `meson setup builddir -Dbuildtype=release -Doptimization=3`。
* **逻辑推理：** `set_options` 方法会被调用，解析命令行参数。`set_option` 方法会依次处理 `buildtype` 和 `optimization` 选项。当设置 `buildtype` 为 `release` 时，`_set_others_from_buildtype` 方法会被调用，它会根据 `release` 的定义将 `optimization` 设置为 '3'，即使命令行中已经显式设置了。
* **输出：**  `coredata.options` 中 `OptionKey('buildtype')` 的值将是 `'release'`，`OptionKey('optimization')` 的值将是 `'3'`。

* **假设输入：** 用户尝试设置一个只读选项，例如 `meson configure -Dbackend=cmake` （假设 `backend` 是只读的）。
* **逻辑推理：** `set_option` 方法会被调用，检查 `OptionKey('backend')` 对应的 `BuiltinOption` 的 `readonly` 属性。由于 `backend` 是只读的，且不是首次调用，会触发异常。
* **输出：**  程序会抛出一个 `MesonException`，提示用户无法修改只读选项。

**用户或编程常见的使用错误及举例说明：**

* **拼写错误的选项名称：** 用户在命令行中输入 `meson setup builddir -Ddebg=true`（将 `debug` 拼写错误）。`set_options` 方法会检查提供的选项是否存在于已知的选项列表中，如果找不到 `debg`，则会抛出 `MesonException`，提示未知的选项。
* **提供错误的选项值类型：**  例如，如果某个选项需要一个整数，用户却提供了字符串 `meson setup builddir -Dbackend_max_links=abc`。`set_option` 方法在尝试设置选项值时会进行类型检查，如果类型不匹配，可能会抛出异常。
* **在子项目中设置全局选项：**  某些内置选项是全局的，不能在子项目中单独设置。如果用户尝试在子项目中设置这样的选项，`add_builtin_option` 方法中的检查会阻止设置。
* **尝试修改只读选项：**  如前所述，尝试在 `meson configure` 阶段修改被标记为 `readonly` 的选项会导致错误。
* **不理解选项之间的依赖关系：**  例如，修改 `buildtype` 可能会自动修改 `optimization` 和 `debug`，用户可能没有意识到这一点。

**用户操作如何一步步地到达这里，作为调试线索：**

1. **用户执行 `meson setup builddir [options]` 命令:**  这是配置构建系统的第一步。命令行中提供的 `-D` 参数会被解析，传递给 `create_options_dict` 和 `parse_cmd_line_options`，最终存储在 `SharedCMDOptions` 对象中。
2. **`meson setup` 内部会创建 `CoreData` 对象:**  在配置过程中，会创建一个 `CoreData` 实例来存储构建信息。
3. **加载已存在的 `coredata.dat` (如果存在):** 如果之前已经配置过，会尝试加载 `builddir/meson-private/coredata.dat` 中的数据。
4. **注册内置参数:** `register_builtin_arguments` 函数会将内置选项添加到 `argparse` 解析器中，以便可以从命令行接收这些选项。
5. **解析命令行选项:** `parse_cmd_line_options` 函数会将命令行中提供的 `-D` 选项和内置选项的值解析出来，存储在 `SharedCMDOptions` 中。
6. **设置默认选项:** `set_default_options` 函数会处理项目定义的默认选项和环境变量中的选项。
7. **处理命令行提供的选项:** `set_options` 函数会遍历 `SharedCMDOptions` 中的选项，并调用 `set_option` 来设置 `CoreData` 对象中的选项值。
8. **保存 `CoreData` 对象:**  配置完成后，`save` 函数会将 `CoreData` 对象序列化并保存到 `builddir/meson-private/coredata.dat` 文件中。

作为调试线索，如果用户在配置过程中遇到问题，例如选项设置不生效或出现错误，可以检查以下内容：

* **`builddir/meson-private/cmd_line.txt` 文件：**  该文件记录了用户在命令行中提供的选项。
* **`builddir/meson-private/coredata.dat` 文件：**  这是一个二进制文件，但可以使用 pickle 工具查看其内容，了解最终生效的选项值。
* **meson 的输出信息：**  Meson 在配置过程中会输出一些信息，包括选项的设置情况和警告/错误信息。

总而言之，`coredata.py` 的这一部分是 Frida 构建系统的核心配置管理模块，它负责处理各种构建选项，并与底层的操作系统概念、编译器和链接器行为紧密相关。理解这部分代码的功能对于理解 Frida 的构建过程以及排查构建问题至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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