Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The primary goal is to analyze the provided Python code (`mconf.py`) and describe its functionality, especially its relevance to reverse engineering, low-level operations, debugging, and potential user errors.

2. **Initial Scan for Key Terms and Concepts:**  A quick read reveals terms like "builddir," "options," "clearcache," "meson.build," "subproject," "compiler," "linker," "introspection," and "coredata." These immediately hint at a build system configuration tool. The presence of `frida` in the path suggests it's specific to the Frida instrumentation framework.

3. **High-Level Functionality Identification:**  The script seems to be responsible for:
    * Reading and displaying configuration options.
    * Allowing users to modify these options.
    * Persisting the changes.
    * Handling subprojects and their configurations.
    * Potentially clearing cached data.
    * Providing a formatted output of configuration settings.

4. **Deconstructing the Code - Key Classes and Functions:**

    * **`add_arguments`:**  This function clearly sets up command-line arguments for the script, such as the build directory and the `clearcache` option.
    * **`ConfException`:** A custom exception type, indicating errors specific to this configuration process.
    * **`Conf` Class:** This is the core class. Its `__init__` method handles loading existing configurations or initializing a new one based on the provided build directory. It deals with `meson.build` and `meson.options` files, suggesting interaction with the Meson build system.
    * **`clear_cache`:**  A straightforward function to clear cached state.
    * **`set_options`:**  Handles setting new configuration options based on user input.
    * **`save`:**  Persists the configuration changes. The comment about not writing the build file is important.
    * **`print_aligned`:** Focuses on formatting the output nicely for the user. The use of `textwrap` and terminal size detection is key here.
    * **`split_options_per_subproject`:** Deals with organizing options for projects that have subcomponents.
    * **`add_line`, `add_option`, `add_title`, `add_section`:** Helper functions for formatting the output.
    * **`print_options`:** Iterates through options and uses the formatting helpers to display them.
    * **`print_conf`:** The main function to display all configuration details, including core properties, project options, compiler options, etc. It also handles subprojects.
    * **`print_nondefault_buildtype_options`:**  Highlights options that deviate from the default values for the selected build type.
    * **`run_impl`:**  The core logic for running the configuration process, handling loading, setting, saving, and displaying options. It includes error handling.
    * **`run`:** The entry point for the script, parsing command-line arguments and calling `run_impl`.

5. **Connecting to Reverse Engineering:**  The core connection lies in **controlling the build process**. By modifying options, reverse engineers can:
    * **Change compiler flags:**  Enable debugging symbols, disable optimizations, or use specific architectures.
    * **Modify linking behavior:**  Link against specific libraries, influence symbol visibility.
    * **Adjust feature options:**  Enable or disable specific functionalities of the target software, which can be crucial for isolating specific behaviors during analysis.
    * **Influence subproject builds:**  Configure dependencies and components in a specific way.

6. **Identifying Low-Level, Kernel, and Framework Relevance:**
    * **Compiler and Linker Options:**  Directly influence the generated binary code. These are low-level aspects of software development.
    * **Target Architecture:**  Options related to cross-compilation (`is_cross_build`) and machine choices (HOST, BUILD) touch upon the underlying hardware architecture.
    * **Subprojects and Dependencies:**  Understanding how different components are built and linked is important for reverse engineering complex systems. Frida itself often interacts with system libraries and potentially kernel components.
    * **Android Context (Implied):** While not explicitly Android kernel code, Frida is heavily used in Android reverse engineering. The ability to configure Frida's build likely impacts how it interacts with the Android framework and potentially lower-level system components.

7. **Logical Inference (Hypothetical Input/Output):**
    * **Input:** `python mconf.py --builddir=my_build --opt target_platform=android`
    * **Output:** The script would load the configuration in `my_build`, set the `target_platform` option to `android`, save the changes, and then display the updated configuration.

8. **Identifying User Errors:**
    * **Specifying the Source Directory Instead of the Build Directory:** The script explicitly checks for this and provides a warning. This is a common mistake for users new to build systems.
    * **Trying to Modify Options Without a Valid Build Directory:** The script prevents this and throws an error.
    * **Incorrect Option Syntax:** While the script doesn't explicitly handle this in the provided snippet, incorrect option names or values passed via the command line would likely be caught by the underlying Meson framework or the `set_options` method.

9. **Tracing User Operations (Debugging Clues):**
    * **User runs `meson setup build_dir`:** This creates the build directory and the initial configuration files.
    * **User wants to change a build option:** They run `python frida/subprojects/frida-node/releng/meson/mesonbuild/mconf.py build_dir --opt enable_feature_x=false`.
    * **The `mconf.py` script is executed:** It loads the configuration from `build_dir`, parses the command-line options, sets the `enable_feature_x` option to `false`, saves the changes, and might display the updated configuration.

10. **Refining and Structuring the Answer:** After this detailed analysis, the next step is to organize the findings into a clear and comprehensive answer, using headings and examples where appropriate. This involves summarizing the functionality, explaining the connections to reverse engineering and low-level concepts, providing the hypothetical input/output, listing potential user errors, and outlining the debugging scenario. It's important to use clear language and avoid overly technical jargon where possible.
这个 Python 脚本 `mconf.py` 是 Frida 工具链中用于配置构建选项的工具。它允许用户查看和修改 Frida 项目及其子项目的构建配置。由于它位于 Frida 的节点绑定（frida-node）的构建相关目录中，因此它很可能与配置 Frida 的 Node.js 绑定有关，但其核心功能是通用的 Meson 构建系统配置管理。

以下是 `mconf.py` 的功能列表，并结合逆向、底层、内核、用户错误和调试线索进行说明：

**功能列表:**

1. **读取和显示构建配置:**
   - 它读取 Meson 构建系统的配置文件（通常位于 `meson-private/coredata.dat`），这些文件包含了项目的各种构建选项。
   - 它能够以结构化的、易于阅读的方式（通过 `print_aligned` 函数实现对齐输出）将这些选项展示给用户，包括选项的名称、当前值（或默认值，如果只指定了源码目录）、可能的值以及描述。
   - **与逆向的关系:** 逆向工程师可以使用此工具来查看目标软件或 Frida 本身的构建配置。例如，他们可以查看是否启用了调试符号、代码优化级别、目标架构等，这些信息对于理解二进制文件的行为至关重要。
     - **举例说明:** 假设逆向工程师想要调试 Frida 与目标进程的交互，他们可以使用 `mconf.py` 查看是否启用了 Frida 的调试功能 (`--opt debug=true`)。

2. **修改构建配置选项:**
   - 允许用户通过命令行参数（`--opt <option>=<value>`）来修改构建选项的值。
   - 修改后的选项会被保存到配置文件中，并在下次构建时生效。
   - **与逆向的关系:** 逆向工程师可以通过修改构建选项来定制 Frida 的行为，以便更好地进行分析。
     - **举例说明:**  逆向工程师可能需要 Frida 连接到特定端口或使用特定的传输协议。他们可以使用 `mconf.py` 修改相关的 Frida 选项，例如 `frida:listen_host` 和 `frida:listen_port`。

3. **处理子项目配置:**
   - 能够识别和管理包含子项目的构建配置。
   - 可以分别显示和修改主项目和各个子项目的构建选项。
   - **涉及到二进制底层/Linux:**  子项目可能代表着 Frida 的不同组件，例如核心引擎、各种语言绑定等。配置这些子项目涉及到它们各自的编译和链接过程，这直接关系到最终生成的二进制文件的结构和依赖关系。在 Linux 环境下，这可能涉及到共享库的链接、头文件的包含路径等底层细节。

4. **清除缓存:**
   - 提供了 `--clearcache` 选项，用于清除 Meson 的缓存。这在解决构建问题时很有用，例如当依赖项更新后需要强制重新检测。
   - **与逆向的关系:**  当构建环境发生变化（例如，更新了依赖库），可能会导致 Frida 的行为异常。清除缓存可以帮助确保 Frida 基于最新的环境进行构建，从而避免一些由旧缓存引起的问题。

5. **显示默认值:**
   - 如果只提供了源码目录而不是构建目录，`mconf.py` 会显示项目选项的默认值。
   - **与逆向的关系:** 了解默认值可以帮助逆向工程师理解在没有自定义配置的情况下，Frida 的预期行为。

6. **友好的输出格式:**
   - 使用 `textwrap` 模块进行文本换行，保持输出的可读性。
   - 使用颜色高亮显示不同类型的信息（选项名、值、描述等）。

**涉及到的知识领域举例:**

* **二进制底层:**
    - **编译器和链接器选项:** `mconf.py` 可以配置传递给编译器（如 GCC, Clang）和链接器的标志，这些标志直接影响生成的二进制文件的机器码、符号表、优化级别等底层细节。 例如，通过修改 `-O` 选项来控制代码优化级别，或者通过 `-g` 选项添加调试符号。
    - **目标架构:** 可以配置目标架构（例如 x86, ARM），这决定了生成的二进制文件运行的硬件平台。

* **Linux:**
    - **共享库:** Frida 及其组件可能以共享库的形式存在。`mconf.py` 的配置可能影响这些库的构建和链接方式。
    - **文件系统路径:**  配置选项中可能包含文件系统路径，例如安装目录、库搜索路径等。

* **Android 内核及框架 (虽然脚本本身不直接操作内核):**
    - 虽然这个脚本主要关注 Frida 的构建，但 Frida 本身广泛应用于 Android 逆向。通过配置 Frida 的构建选项，可以影响 Frida 在 Android 设备上的行为。例如，配置 Frida Server 的监听地址和端口，或者选择不同的注入方法。
    - Frida 的工作原理涉及到与 Android 系统进程的交互，甚至可能需要注入到 Zygote 进程来拦截应用启动。构建配置可能会影响这些底层交互的方式。

**逻辑推理 (假设输入与输出):**

假设用户想要查看 Frida 是否启用了 DTrace 支持。

* **假设输入:** `python frida/subprojects/frida-node/releng/meson/mesonbuild/mconf.py build`  (假设 `build` 是已存在的 Frida 构建目录)
* **可能输出 (部分):**  在 "Core options" 或 "Project options" 部分，可能会有类似以下的输出：

```
  DTrace Support    false         [true, false]  Enable DTrace probes
```

如果用户想要启用 DTrace 支持，可以执行：

* **假设输入:** `python frida/subprojects/frida-node/releng/meson/mesonbuild/mconf.py build --opt dtrace=true`
* **预期输出:**  `mconf.py` 会将 `dtrace` 选项的值设置为 `true` 并保存。再次运行不带 `--opt` 的命令，将会看到：

```
  DTrace Support    true          [true, false]  Enable DTrace probes
```

**用户或编程常见的使用错误举例:**

1. **指定错误的构建目录:** 用户可能指定了一个不是 Meson 构建目录的路径，或者指定了源码目录而不是构建目录。`mconf.py` 会抛出 `ConfException` 并提示用户。
   - **错误信息示例:** `ConfException: Directory /path/to/source is neither a Meson build directory nor a project source directory.`

2. **拼写错误的选项名:** 用户在命令行中输入的选项名可能与实际存在的选项名不符。虽然 `mconf.py` 本身可能不会立即报错，但在后续的构建过程中，Meson 可能会发出警告或错误。

3. **提供无效的选项值:** 用户可能为某个选项提供了不合法的值。例如，一个布尔类型的选项被赋予了 "yes" 而不是 "true" 或 "false"。`mconf.py` 的 `set_options` 方法会尝试解析这些值，如果解析失败，可能会引发错误。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户首先需要有一个 Frida 的构建目录。** 这通常通过运行 `meson setup <build_directory>` 命令来创建，该命令在 Frida 的源代码目录下执行。

2. **用户在尝试构建或使用 Frida 时遇到问题，或者想要定制 Frida 的构建方式。** 这可能促使他们去查看或修改构建配置。

3. **用户可能会查看 Frida 的文档或社区资源，了解到可以使用 `mconf.py` 来管理构建选项。**

4. **用户打开终端，导航到 `frida/subprojects/frida-node/releng/meson/mesonbuild/` 目录 (或者从其他地方执行时提供正确的脚本路径)。**

5. **用户运行 `python mconf.py <build_directory>` 来查看当前的配置。**

6. **用户根据需要，使用 `python mconf.py <build_directory> --opt <option>=<value>` 来修改特定的选项。**

7. **如果用户在修改后遇到问题，他们可能会再次运行 `python mconf.py <build_directory>` 来确认选项是否已正确更改。**

作为调试线索，如果用户报告了构建相关的问题，首先可以让他们运行 `mconf.py` 并查看当前的构建配置，以排除配置错误的可能性。例如，检查是否启用了正确的后端、目标平台、调试选项等。

总而言之，`mconf.py` 是 Frida 构建系统中一个关键的配置管理工具，它允许用户查看和调整构建选项，这对于理解和定制 Frida 的行为，尤其是在逆向工程场景中，是非常有用的。它涉及到编译、链接等底层的概念，并且能够影响 Frida 在不同平台（包括 Linux 和 Android）上的构建方式。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/mconf.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2014-2016 The Meson development team
# Copyright © 2023-2024 Intel Corporation

from __future__ import annotations

import itertools
import hashlib
import shutil
import os
import textwrap
import typing as T
import collections

from . import build
from . import coredata
from . import environment
from . import mesonlib
from . import mintro
from . import mlog
from .ast import AstIDGenerator, IntrospectionInterpreter
from .mesonlib import MachineChoice, OptionKey
from .optinterpreter import OptionInterpreter

if T.TYPE_CHECKING:
    from typing_extensions import Protocol
    import argparse

    class CMDOptions(coredata.SharedCMDOptions, Protocol):

        builddir: str
        clearcache: bool
        pager: bool

    # cannot be TV_Loggable, because non-ansidecorators do direct string concat
    LOGLINE = T.Union[str, mlog.AnsiDecorator]

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: 'argparse.ArgumentParser') -> None:
    coredata.register_builtin_arguments(parser)
    parser.add_argument('builddir', nargs='?', default='.')
    parser.add_argument('--clearcache', action='store_true', default=False,
                        help='Clear cached state (e.g. found dependencies)')
    parser.add_argument('--no-pager', action='store_false', dest='pager',
                        help='Do not redirect output to a pager')

def stringify(val: T.Any) -> str:
    if isinstance(val, bool):
        return str(val).lower()
    elif isinstance(val, list):
        s = ', '.join(stringify(i) for i in val)
        return f'[{s}]'
    elif val is None:
        return ''
    else:
        return str(val)


class ConfException(mesonlib.MesonException):
    pass


class Conf:
    def __init__(self, build_dir: str):
        self.build_dir = os.path.abspath(os.path.realpath(build_dir))
        if 'meson.build' in [os.path.basename(self.build_dir), self.build_dir]:
            self.build_dir = os.path.dirname(self.build_dir)
        self.build = None
        self.max_choices_line_length = 60
        self.name_col: T.List[LOGLINE] = []
        self.value_col: T.List[LOGLINE] = []
        self.choices_col: T.List[LOGLINE] = []
        self.descr_col: T.List[LOGLINE] = []
        self.all_subprojects: T.Set[str] = set()

        if os.path.isdir(os.path.join(self.build_dir, 'meson-private')):
            self.build = build.load(self.build_dir)
            self.source_dir = self.build.environment.get_source_dir()
            self.coredata = self.build.environment.coredata
            self.default_values_only = False

            # if the option file has been updated, reload it
            # This cannot handle options for a new subproject that has not yet
            # been configured.
            for sub, options in self.coredata.options_files.items():
                if options is not None and os.path.exists(options[0]):
                    opfile = options[0]
                    with open(opfile, 'rb') as f:
                        ophash = hashlib.sha1(f.read()).hexdigest()
                        if ophash != options[1]:
                            oi = OptionInterpreter(sub)
                            oi.process(opfile)
                            self.coredata.update_project_options(oi.options, sub)
                            self.coredata.options_files[sub] = (opfile, ophash)
                else:
                    opfile = os.path.join(self.source_dir, 'meson.options')
                    if not os.path.exists(opfile):
                        opfile = os.path.join(self.source_dir, 'meson_options.txt')
                    if os.path.exists(opfile):
                        oi = OptionInterpreter(sub)
                        oi.process(opfile)
                        self.coredata.update_project_options(oi.options, sub)
                        with open(opfile, 'rb') as f:
                            ophash = hashlib.sha1(f.read()).hexdigest()
                        self.coredata.options_files[sub] = (opfile, ophash)
                    else:
                        self.coredata.update_project_options({}, sub)
        elif os.path.isfile(os.path.join(self.build_dir, environment.build_filename)):
            # Make sure that log entries in other parts of meson don't interfere with the JSON output
            with mlog.no_logging():
                self.source_dir = os.path.abspath(os.path.realpath(self.build_dir))
                intr = IntrospectionInterpreter(self.source_dir, '', 'ninja', visitors = [AstIDGenerator()])
                intr.analyze()
            self.coredata = intr.coredata
            self.default_values_only = True
        else:
            raise ConfException(f'Directory {build_dir} is neither a Meson build directory nor a project source directory.')

    def clear_cache(self) -> None:
        self.coredata.clear_cache()

    def set_options(self, options: T.Dict[OptionKey, str]) -> bool:
        return self.coredata.set_options(options)

    def save(self) -> None:
        # Do nothing when using introspection
        if self.default_values_only:
            return
        coredata.save(self.coredata, self.build_dir)
        # We don't write the build file because any changes to it
        # are erased when Meson is executed the next time, i.e. when
        # Ninja is run.

    def print_aligned(self) -> None:
        """Do the actual printing.

        This prints the generated output in an aligned, pretty form. it aims
        for a total width of 160 characters, but will use whatever the tty
        reports it's value to be. Though this is much wider than the standard
        80 characters of terminals, and even than the newer 120, compressing
        it to those lengths makes the output hard to read.

        Each column will have a specific width, and will be line wrapped.
        """
        total_width = shutil.get_terminal_size(fallback=(160, 0))[0]
        _col = max(total_width // 5, 20)
        last_column = total_width - (3 * _col) - 3
        four_column = (_col, _col, _col, last_column if last_column > 1 else _col)

        for line in zip(self.name_col, self.value_col, self.choices_col, self.descr_col):
            if not any(line):
                mlog.log('')
                continue

            # This is a header, like `Subproject foo:`,
            # We just want to print that and get on with it
            if line[0] and not any(line[1:]):
                mlog.log(line[0])
                continue

            def wrap_text(text: LOGLINE, width: int) -> mlog.TV_LoggableList:
                raw = text.text if isinstance(text, mlog.AnsiDecorator) else text
                indent = ' ' if raw.startswith('[') else ''
                wrapped_ = textwrap.wrap(raw, width, subsequent_indent=indent)
                # We cast this because https://github.com/python/mypy/issues/1965
                # mlog.TV_LoggableList does not provide __len__ for stringprotocol
                if isinstance(text, mlog.AnsiDecorator):
                    wrapped = T.cast('T.List[LOGLINE]', [mlog.AnsiDecorator(i, text.code) for i in wrapped_])
                else:
                    wrapped = T.cast('T.List[LOGLINE]', wrapped_)
                # Add padding here to get even rows, as `textwrap.wrap()` will
                # only shorten, not lengthen each item
                return [str(i) + ' ' * (width - len(i)) for i in wrapped]

            # wrap will take a long string, and create a list of strings no
            # longer than the size given. Then that list can be zipped into, to
            # print each line of the output, such the that columns are printed
            # to the right width, row by row.
            name = wrap_text(line[0], four_column[0])
            val = wrap_text(line[1], four_column[1])
            choice = wrap_text(line[2], four_column[2])
            desc = wrap_text(line[3], four_column[3])
            for l in itertools.zip_longest(name, val, choice, desc, fillvalue=''):
                items = [l[i] if l[i] else ' ' * four_column[i] for i in range(4)]
                mlog.log(*items)

    def split_options_per_subproject(self, options: 'coredata.KeyedOptionDictType') -> T.Dict[str, 'coredata.MutableKeyedOptionDictType']:
        result: T.Dict[str, 'coredata.MutableKeyedOptionDictType'] = {}
        for k, o in options.items():
            if k.subproject:
                self.all_subprojects.add(k.subproject)
            result.setdefault(k.subproject, {})[k] = o
        return result

    def _add_line(self, name: LOGLINE, value: LOGLINE, choices: LOGLINE, descr: LOGLINE) -> None:
        if isinstance(name, mlog.AnsiDecorator):
            name.text = ' ' * self.print_margin + name.text
        else:
            name = ' ' * self.print_margin + name
        self.name_col.append(name)
        self.value_col.append(value)
        self.choices_col.append(choices)
        self.descr_col.append(descr)

    def add_option(self, name: str, descr: str, value: T.Any, choices: T.Any) -> None:
        value = stringify(value)
        choices = stringify(choices)
        self._add_line(mlog.green(name), mlog.yellow(value), mlog.blue(choices), descr)

    def add_title(self, title: str) -> None:
        newtitle = mlog.cyan(title)
        descr = mlog.cyan('Description')
        value = mlog.cyan('Default Value' if self.default_values_only else 'Current Value')
        choices = mlog.cyan('Possible Values')
        self._add_line('', '', '', '')
        self._add_line(newtitle, value, choices, descr)
        self._add_line('-' * len(newtitle), '-' * len(value), '-' * len(choices), '-' * len(descr))

    def add_section(self, section: str) -> None:
        self.print_margin = 0
        self._add_line('', '', '', '')
        self._add_line(mlog.normal_yellow(section + ':'), '', '', '')
        self.print_margin = 2

    def print_options(self, title: str, options: 'coredata.KeyedOptionDictType') -> None:
        if not options:
            return
        if title:
            self.add_title(title)
        auto = T.cast('coredata.UserFeatureOption', self.coredata.options[OptionKey('auto_features')])
        for k, o in sorted(options.items()):
            printable_value = o.printable_value()
            root = k.as_root()
            if o.yielding and k.subproject and root in self.coredata.options:
                printable_value = '<inherited from main project>'
            if isinstance(o, coredata.UserFeatureOption) and o.is_auto():
                printable_value = auto.printable_value()
            self.add_option(str(root), o.description, printable_value, o.choices)

    def print_conf(self, pager: bool) -> None:
        if pager:
            mlog.start_pager()

        def print_default_values_warning() -> None:
            mlog.warning('The source directory instead of the build directory was specified.')
            mlog.warning('Only the default values for the project are printed.')

        if self.default_values_only:
            print_default_values_warning()
            mlog.log('')

        mlog.log('Core properties:')
        mlog.log('  Source dir', self.source_dir)
        if not self.default_values_only:
            mlog.log('  Build dir ', self.build_dir)

        dir_option_names = set(coredata.BUILTIN_DIR_OPTIONS)
        test_option_names = {OptionKey('errorlogs'),
                             OptionKey('stdsplit')}

        dir_options: 'coredata.MutableKeyedOptionDictType' = {}
        test_options: 'coredata.MutableKeyedOptionDictType' = {}
        core_options: 'coredata.MutableKeyedOptionDictType' = {}
        module_options: T.Dict[str, 'coredata.MutableKeyedOptionDictType'] = collections.defaultdict(dict)
        for k, v in self.coredata.options.items():
            if k in dir_option_names:
                dir_options[k] = v
            elif k in test_option_names:
                test_options[k] = v
            elif k.module:
                # Ignore module options if we did not use that module during
                # configuration.
                if self.build and k.module not in self.build.modules:
                    continue
                module_options[k.module][k] = v
            elif k.is_builtin():
                core_options[k] = v

        host_core_options = self.split_options_per_subproject({k: v for k, v in core_options.items() if k.machine is MachineChoice.HOST})
        build_core_options = self.split_options_per_subproject({k: v for k, v in core_options.items() if k.machine is MachineChoice.BUILD})
        host_compiler_options = self.split_options_per_subproject({k: v for k, v in self.coredata.options.items() if k.is_compiler() and k.machine is MachineChoice.HOST})
        build_compiler_options = self.split_options_per_subproject({k: v for k, v in self.coredata.options.items() if k.is_compiler() and k.machine is MachineChoice.BUILD})
        project_options = self.split_options_per_subproject({k: v for k, v in self.coredata.options.items() if k.is_project()})
        show_build_options = self.default_values_only or self.build.environment.is_cross_build()

        self.add_section('Main project options')
        self.print_options('Core options', host_core_options[''])
        if show_build_options:
            self.print_options('', build_core_options[''])
        self.print_options('Backend options', {k: v for k, v in self.coredata.options.items() if k.is_backend()})
        self.print_options('Base options', {k: v for k, v in self.coredata.options.items() if k.is_base()})
        self.print_options('Compiler options', host_compiler_options.get('', {}))
        if show_build_options:
            self.print_options('', build_compiler_options.get('', {}))
        for mod, mod_options in module_options.items():
            self.print_options(f'{mod} module options', mod_options)
        self.print_options('Directories', dir_options)
        self.print_options('Testing options', test_options)
        self.print_options('Project options', project_options.get('', {}))
        for subproject in sorted(self.all_subprojects):
            if subproject == '':
                continue
            self.add_section('Subproject ' + subproject)
            if subproject in host_core_options:
                self.print_options('Core options', host_core_options[subproject])
            if subproject in build_core_options and show_build_options:
                self.print_options('', build_core_options[subproject])
            if subproject in host_compiler_options:
                self.print_options('Compiler options', host_compiler_options[subproject])
            if subproject in build_compiler_options and show_build_options:
                self.print_options('', build_compiler_options[subproject])
            if subproject in project_options:
                self.print_options('Project options', project_options[subproject])
        self.print_aligned()

        # Print the warning twice so that the user shouldn't be able to miss it
        if self.default_values_only:
            mlog.log('')
            print_default_values_warning()

        self.print_nondefault_buildtype_options()

    def print_nondefault_buildtype_options(self) -> None:
        mismatching = self.coredata.get_nondefault_buildtype_args()
        if not mismatching:
            return
        mlog.log("\nThe following option(s) have a different value than the build type default\n")
        mlog.log('               current   default')
        for m in mismatching:
            mlog.log(f'{m[0]:21}{m[1]:10}{m[2]:10}')

def run_impl(options: CMDOptions, builddir: str) -> int:
    print_only = not options.cmd_line_options and not options.clearcache
    c = None
    try:
        c = Conf(builddir)
        if c.default_values_only and not print_only:
            raise mesonlib.MesonException('No valid build directory found, cannot modify options.')
        if c.default_values_only or print_only:
            c.print_conf(options.pager)
            return 0

        save = False
        if options.cmd_line_options:
            save = c.set_options(options.cmd_line_options)
            coredata.update_cmd_line_file(builddir, options)
        if options.clearcache:
            c.clear_cache()
            save = True
        if save:
            c.save()
            mintro.update_build_options(c.coredata, c.build.environment.info_dir)
            mintro.write_meson_info_file(c.build, [])
    except ConfException as e:
        mlog.log('Meson configurator encountered an error:')
        if c is not None and c.build is not None:
            mintro.write_meson_info_file(c.build, [e])
        raise e
    except BrokenPipeError:
        # Pager quit before we wrote everything.
        pass
    return 0

def run(options: CMDOptions) -> int:
    coredata.parse_cmd_line_options(options)
    builddir = os.path.abspath(os.path.realpath(options.builddir))
    return run_impl(options, builddir)
```