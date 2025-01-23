Response:
Let's break down the thought process to analyze this Python code snippet from `coredata.py`.

**1. Understanding the Goal:**

The request asks for a breakdown of the code's functionality, specifically looking for connections to reverse engineering, low-level concepts (kernel, etc.), logical reasoning, potential user errors, and how a user might reach this code. It's also the second part of a three-part analysis, so the final summary should be concise.

**2. Initial Code Scan and High-Level Interpretation:**

The first step is to quickly scan the code to get a general idea of what it's doing. Keywords like "options," "built-in," "backend," "compiler," "cross-build," and "machine file" stand out. This suggests the code is responsible for managing configuration settings within the Meson build system.

**3. Identifying Key Classes and Functions:**

Next, focus on the main classes and functions:

* **`CoreData`:** This seems to be the central data structure holding the configuration.
* **`BuiltinOption`:**  Represents individual configurable options.
* **`CmdLineFileParser`:**  Handles reading options from a command-line file.
* **`MachineFileParser`:**  Parses configuration from machine-specific files (likely for cross-compilation).
* **`load` and `save`:**  Functions for persisting `CoreData`.
* Functions like `set_option`, `get_option`, `add_compiler_options`, etc. point to specific aspects of option management.

**4. Analyzing Functionality Group by Group:**

Now, delve into the details, focusing on the functionality of different sections of the code.

* **Built-in Options (`BUILTIN_DIR_OPTIONS`, `BUILTIN_CORE_OPTIONS`, etc.):**  These are predefined configuration settings. Think of them as standard build system options (install prefix, build type, optimization level, etc.).

* **Option Management (`add_builtin_option`, `init_backend_options`, `get_option`, `set_option`):** This section deals with how options are stored, retrieved, and modified. The logic for handling deprecated options is interesting.

* **Build Type Logic (`get_nondefault_buildtype_args`, `_set_others_from_buildtype`):** This handles the relationships between high-level build types (debug, release) and underlying compiler/linker flags.

* **Cross-Compilation (`is_cross_build`, `get_external_args`, `get_external_link_args`, `copy_build_options_from_regular_ones`):** This is crucial for compiling for different target architectures.

* **Command-Line and Machine Files (`CmdLineFileParser`, `MachineFileParser`, `read_cmd_line_file`, `write_cmd_line_file`):**  These handle loading configuration from different sources. The machine file parsing logic with variable substitution is noteworthy.

* **Saving and Loading (`load`, `save`):**  Essential for persisting configuration across Meson invocations.

* **Command-Line Argument Handling (`register_builtin_arguments`, `create_options_dict`, `parse_cmd_line_options`):**  This connects the code to the command-line interface.

**5. Connecting to the Prompt's Requirements:**

As you analyze the code, constantly refer back to the prompt's specific questions:

* **Reverse Engineering:**  Think about how these configuration options might affect the final binary. For example, disabling optimizations (`-Doptimization=0`) or enabling debug symbols (`-Ddebug=true`) are common for reverse engineering. Cross-compilation itself is a key aspect, as it involves targeting different architectures.

* **Binary/Low-Level/Kernel/Framework:** Consider how options like linker arguments (`link_args`) or compiler arguments (`args`) directly influence the generated machine code and linking process. Cross-compilation necessitates understanding different ABIs and system libraries.

* **Logical Reasoning:**  Look for conditional logic and how inputs affect outputs. The `_set_others_from_buildtype` function is a good example of this. Consider what happens if a user sets conflicting options.

* **User Errors:** Identify scenarios where users might make mistakes. Setting unknown options, providing invalid values, or misunderstanding the interaction between different options are potential errors.

* **User Journey:** Imagine the steps a user takes to run Meson. They might run `meson setup`, passing various command-line arguments (`-D` options, `--cross-file`, etc.). This input eventually gets processed by this code. Reconfiguring an existing build is another path.

**6. Formulating Examples:**

Once you've identified connections, create concrete examples to illustrate them. For instance:

* **Reverse Engineering:** Show how `-Ddebug=true` leads to more debugging information.
* **Low-Level:** Explain how `link_args` are passed to the linker.
* **Logical Reasoning:**  Illustrate the input/output of `_set_others_from_buildtype`.
* **User Error:** Show what happens if a user types `-Dinvalid_option=value`.

**7. Structuring the Answer:**

Organize the findings into a clear and structured response, addressing each point in the prompt. Use headings and bullet points to improve readability.

**8. Summarizing for Part 2:**

Since this is part 2 of 3, the final summary should be a concise overview of the code's primary function: managing and storing configuration data for the Meson build system.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about storing options."
* **Correction:** "Actually, it's more complex. It handles built-in defaults, user overrides, cross-compilation settings, and integrates with command-line arguments and configuration files."

* **Initial thought:** "The reverse engineering connection is weak."
* **Correction:** "No, the options controlling debug symbols, optimization levels, and the ability to cross-compile are directly relevant to reverse engineering."

By following this detailed thought process, you can systematically analyze the code and generate a comprehensive and accurate response that addresses all aspects of the prompt.
这是 frida 动态 instrumentation 工具的源代码文件 `coredata.py` 的第二部分，主要负责管理和存储 Meson 构建系统的核心数据，特别是关于构建选项（options）的处理。

**功能归纳:**

该文件的核心功能是**管理和持久化 Meson 构建系统的配置选项**。它定义了如何存储、读取、设置和验证各种构建选项，包括内置选项、项目选项以及与编译器相关的选项。它还处理了从命令行和配置文件中读取选项，以及在重新配置时更新选项。

**详细功能列举:**

1. **内置选项管理:**
   - 定义和存储 Meson 的内置选项，例如安装路径 (`prefix`, `bindir` 等)、构建类型 (`buildtype`)、优化级别 (`optimization`) 等。
   - 为每个内置选项定义类型（字符串、布尔值、枚举等）、描述和默认值。
   - 允许根据不同的目标机器（host, build）设置不同的内置选项。

2. **选项的添加和初始化:**
   - 提供方法 `add_builtin_option` 来向选项字典中添加内置选项。
   - 在初始化时，为内置选项设置默认值。

3. **后端特定选项:**
   - 允许为特定的构建后端（如 Ninja, Visual Studio）初始化特定的选项，例如 Ninja 的最大链接进程数 (`backend_max_links`) 和 Visual Studio 的启动项目 (`backend_startup_project`)。

4. **选项的获取和设置:**
   - 提供 `get_option` 方法来获取指定选项的值。
   - 提供 `set_option` 方法来设置指定选项的值，并进行一些验证和处理（例如，路径前缀处理、已弃用选项的处理）。

5. **选项的持久化:**
   - 使用 `pickle` 模块将 `CoreData` 对象（包含所有选项）保存到磁盘 (`coredata.dat`)，以便在后续的构建过程中恢复。
   - 提供 `load` 和 `save` 函数来加载和保存 `CoreData` 对象。

6. **从命令行和配置文件读取选项:**
   - 使用 `CmdLineFileParser` 解析命令行选项文件 (`cmd_line.txt`)。
   - 使用 `MachineFileParser` 解析机器描述文件（用于交叉编译）。
   - 提供函数来读取和写入命令行选项到文件。

7. **处理项目选项:**
   - 允许项目自定义选项，并将其存储在 `self.options` 中。
   - 提供 `update_project_options` 方法来更新项目选项。

8. **交叉编译支持:**
   - 提供 `is_cross_build` 方法来判断是否为交叉编译。
   - 允许为不同的目标机器设置不同的选项。
   - 提供方法 `get_external_args` 和 `get_external_link_args` 来获取特定目标机器和语言的外部编译和链接参数。

9. **构建类型处理:**
   - 提供方法根据构建类型（如 `debug`, `release`）自动设置相关的优化和调试选项。

10. **编译器选项处理:**
    - 提供 `add_compiler_options` 和 `process_compiler_options` 方法来添加和处理与特定编译器相关的选项。
    - 允许为不同的语言（C, C++ 等）设置不同的编译器选项。

11. **选项的校验和弃用处理:**
    - 在设置选项时，检查选项是否已弃用，并发出警告或替换为新的选项。

**与逆向方法的关联及举例说明:**

该文件直接影响到最终生成的可执行文件的特性，这些特性对于逆向分析至关重要。

* **调试符号 (`debug` 选项):**
   - **说明:** 当 `debug` 选项设置为 `True` 时，编译器和链接器会生成包含调试信息的二进制文件。这些信息包括变量名、函数名、源代码行号等，极大地辅助逆向工程师理解程序的执行流程和内部状态。
   - **举例:** 如果逆向一个 Android 应用的原生库，如果构建时启用了调试符号，逆向工程师可以使用诸如 `GDB` 或 `LLDB` 等调试器来单步执行代码，查看变量值，设置断点，从而更容易理解代码逻辑和发现漏洞。

* **优化级别 (`optimization` 选项):**
   - **说明:** 优化级别会影响编译器生成的机器码的效率和结构。高优化级别会使代码更难阅读和理解，因为编译器会进行各种代码变换，例如内联函数、循环展开、寄存器优化等。
   - **举例:** 如果一个恶意软件的构建使用了高优化级别 (`-Doptimization=3`)，逆向工程师在反汇编代码时会发现代码结构更加复杂，控制流更加难以追踪，增加了分析的难度。相反，低优化级别 (`-Doptimization=0`) 生成的代码更接近源代码，更容易理解。

* **构建类型 (`buildtype` 选项):**
   - **说明:** 构建类型通常会预设一些常用的选项组合，例如 `debug` 类型会启用调试符号并禁用优化，`release` 类型会禁用调试符号并启用优化。
   - **举例:** 在分析一个 Android 系统框架库时，如果知道其构建类型为 `debugoptimized`，逆向工程师可以预期其中既包含一定的调试信息，也进行了一定程度的优化，从而在分析策略上有所侧重。

* **库类型 (`default_library` 选项):**
   - **说明:** 该选项决定了构建动态库 (`shared`) 还是静态库 (`static`)。动态库需要在运行时加载，静态库则会被链接到可执行文件中。
   - **举例:** 逆向一个使用了大量静态库的 Linux 程序时，逆向工程师需要分析一个体积较大的可执行文件，其中包含了所有静态库的代码。而如果使用动态库，则需要分别分析主程序和各个动态库。

* **编译器和链接器参数 (`args`, `link_args` 选项):**
   - **说明:** 这些选项允许开发者直接传递参数给编译器和链接器，可以影响二进制文件的各种属性，例如安全特性（如 PIE, Stack Canaries）、代码生成方式等。
   - **举例:** 如果构建一个 Android 原生库时使用了 `-fPIE` 编译选项（通过 `args` 传递），生成的动态库会启用地址空间布局随机化 (ASLR)，这会增加逆向分析和漏洞利用的难度，因为每次加载库的地址都是随机的。

**涉及的二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:**
    - **链接器 (`backend_max_links` 选项):** 限制链接器进程数涉及到二进制文件的链接过程，链接是将编译后的目标文件组合成最终可执行文件的过程。
    - **目标文件格式:** 不同的平台和架构有不同的目标文件格式 (例如 ELF, Mach-O, PE)，这些格式决定了二进制文件的结构和元数据，例如符号表、重定位信息等，而这些信息受到编译和链接选项的影响。

* **Linux:**
    - **安装路径 (`prefix`, `bindir`, `libdir` 等):** 这些选项定义了文件在 Linux 文件系统中的安装位置，理解这些路径对于分析已安装的程序至关重要。
    - **动态链接:** Linux 系统中动态库的加载和链接过程受到构建选项的影响，例如是否生成位置无关代码 (PIC)。
    - **用户权限 (`install_umask` 选项):**  安装文件的权限设置会影响程序的运行和安全性。

* **Android 内核及框架:**
    - **交叉编译:**  Frida 通常用于对 Android 应用进行动态 instrumentation，这通常涉及到交叉编译，即在 PC 上构建运行在 Android 设备上的代码。`MachineFileParser` 用于解析目标 Android 设备的配置信息。
    - **共享库 (`default_library=shared`):** Android 应用和框架大量使用共享库 (.so 文件)，理解如何构建和加载这些库是分析 Android 系统的关键。
    - **编译器标志:** Android 系统及其组件的构建使用了特定的编译器标志，例如用于控制代码生成、ABI 兼容性等的标志。

**逻辑推理、假设输入与输出:**

* **假设输入:** 用户设置了 `buildtype=release`。
* **逻辑推理:** `_set_others_from_buildtype` 函数会根据 `release` 构建类型，将 `optimization` 选项设置为 `'3'` (或类似的代表 release 优化的值)，并将 `debug` 选项设置为 `False`。
* **输出:** `self.options[OptionKey('optimization')]` 的值为 `'3'`，`self.options[OptionKey('debug')]` 的值为 `False`。

* **假设输入:** 用户设置了一个已弃用的选项 `old_option=value`，并且 `BuiltinOption` 中定义了 `deprecated='new_option'`。
* **逻辑推理:** `set_option` 函数会检测到该选项已弃用，发出弃用警告，并将 `new_option` 的值也设置为 `value`。
* **输出:** 控制台会显示关于 `old_option` 弃用的警告，并且 `self.options[OptionKey('new_option')]` 的值会被设置为 `value`。

**用户或编程常见的使用错误及举例说明:**

* **设置了未知的内置选项:**
   - **操作:** 用户在运行 `meson setup` 时使用了 `-Dunknown_option=value`。
   - **错误:** `set_options` 函数会遍历用户提供的选项，如果发现 `unknown_option` 不在 `self.options` 中，并且不是编译器选项，则会抛出 `MesonException`，提示用户该选项未知。

* **设置了类型不匹配的选项值:**
   - **操作:** 用户尝试将一个字符串值赋给一个期望布尔值的选项，例如 `-Ddebug=not_a_boolean`。
   - **错误:** `UserBooleanOption` 的 `set_value` 方法会尝试将输入转换为布尔值，如果转换失败，会抛出异常。

* **在子项目中设置了全局选项:**
   - **操作:** 用户在一个子项目的 `meson.build` 文件中尝试设置一个不应该在子项目中设置的全局选项（`yielding=True` 的选项）。
   - **错误:** `add_builtin_option` 函数会检查选项的 `yielding` 属性，如果为 `True` 且 `key.subproject` 存在，则会直接返回，阻止该选项被设置。

* **尝试修改只读选项:**
   - **操作:** 用户尝试通过命令行或配置文件修改一个被标记为 `readonly=True` 的选项。
   - **错误:** `set_option` 函数在选项被标记为只读且不是首次调用时会抛出 `MesonException`。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户执行 `meson setup <build_directory>`:**  这是 Meson 构建过程的起点，用于配置构建环境。
2. **Meson 解析命令行参数:** Meson 会解析用户通过命令行传递的 `-D<option>=<value>` 参数，以及 `--cross-file` 和 `--native-file` 等参数。
3. **加载或创建 `coredata.dat`:** 如果是首次配置，会创建一个新的 `CoreData` 对象。如果是重新配置，会尝试加载已存在的 `coredata.dat` 文件。
4. **读取命令行选项文件 (`cmd_line.txt`):** 如果存在，Meson 会读取该文件中的选项。
5. **读取机器描述文件 (如果指定):** 如果用户使用了 `--cross-file` 或 `--native-file`，Meson 会解析这些文件中的配置信息。
6. **调用 `coredata.py` 中的函数:**
   - `register_builtin_arguments` 被调用以注册内置的命令行参数。
   - `parse_cmd_line_options` 被调用以解析命令行选项。
   - `create_options_dict` 用于将命令行选项转换为字典。
   - `CoreData` 的构造函数会被调用，初始化选项。
   - `set_options` 被调用，将解析到的选项设置到 `CoreData` 对象中。
   - `add_builtin_option` 被调用，添加内置选项。
   - `set_option` 被调用，设置单个选项的值，并进行验证和处理。
7. **保存 `CoreData`:**  配置完成后，`save` 函数会将 `CoreData` 对象保存到 `coredata.dat` 文件中。

**作为调试线索:** 如果在 Meson 配置过程中出现与选项相关的错误，例如“未知选项”或“类型不匹配”，开发者可以检查以下内容：

* **用户传递的命令行参数是否正确。**
* **`cmd_line.txt` 文件中的内容是否正确。**
* **机器描述文件中的语法是否正确。**
* **`coredata.py` 中定义的内置选项是否与用户尝试设置的选项匹配。**
* **选项的类型定义是否正确，以及用户提供的值是否符合类型要求。**

**功能归纳:**

`frida/subprojects/frida-tools/releng/meson/mesonbuild/coredata.py` 文件的这部分代码主要负责 **管理和持久化 Meson 构建系统的配置选项，包括内置选项、项目选项和编译器选项，并处理从命令行和配置文件中读取选项的过程，为后续的构建过程提供必要的配置信息。** 它是 Meson 构建系统配置管理的核心组件。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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