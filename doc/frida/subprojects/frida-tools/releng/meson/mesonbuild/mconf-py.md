Response:
Let's break down the thought process for analyzing the provided Python code. The goal is to understand its functionality and relate it to reverse engineering, binary internals, Linux/Android concepts, logical reasoning, potential user errors, and debugging.

**1. Initial Skim and Purpose Identification:**

The first step is to quickly read through the code to get a general idea of its purpose. Keywords like "meson," "options," "builddir," "clearcache," "print," and the file path itself (`frida/subprojects/frida-tools/releng/meson/mesonbuild/mconf.py`) strongly suggest this is a configuration tool for the Frida framework, likely using the Meson build system. The `mconf.py` part reinforces that it's related to *configuration*.

**2. Deconstructing the Code into Key Sections:**

Next, we can divide the code into logical sections to analyze each part more thoroughly. Common sections in Python code like this include:

* **Imports:** What external libraries does it rely on? This gives clues about its capabilities (e.g., `hashlib` for checksums, `os` for file system interaction, `textwrap` for formatting).
* **Argument Parsing (`add_arguments`):** How does the tool take input from the user? This reveals command-line options.
* **Core Class (`Conf`):** This is the heart of the tool. We need to examine its methods and attributes.
* **Helper Functions (`stringify`, `run_impl`, `run`):** These perform specific tasks.
* **Exception Handling (`ConfException`):** How does it handle errors?

**3. Analyzing the `Conf` Class in Detail:**

This class is crucial, so a detailed analysis is needed:

* **`__init__`:** How is the class initialized?  It reads the build directory, loads existing build information or introspects a source directory if no build exists. This suggests it can both modify existing configurations and display default options. The logic around `meson.build` and `meson-private` is important for understanding how it identifies a build directory. The handling of `meson.options` files indicates it deals with project-specific settings.
* **`clear_cache`:**  Straightforward – clears cached dependency information.
* **`set_options`:**  Modifies configuration options. The return value suggests it indicates whether changes were made.
* **`save`:** Persists the changes to the build directory. The comment about not writing the build file is important.
* **`print_aligned`:**  Formats and displays the configuration information. The use of `textwrap` and `shutil.get_terminal_size` highlights its focus on user-friendly output in the terminal.
* **`split_options_per_subproject`:**  Organizes options by subproject, indicating support for modular builds.
* **`_add_line`, `add_option`, `add_title`, `add_section`:** These are helper methods for building the formatted output.
* **`print_options`:**  Iterates through and displays options, handling different types of options (core, compiler, project, etc.). The special handling of `UserFeatureOption` is worth noting.
* **`print_conf`:**  The main function for printing the configuration. It organizes options into categories and calls `print_options`. It also handles the case where only default values are available.
* **`print_nondefault_buildtype_options`:**  Identifies options that deviate from the default for the selected build type.

**4. Connecting to the Prompts:**

As we analyze the code, we actively think about how it relates to the specific questions in the prompt:

* **Functionality:** Summarize the purpose of each method and the overall goal of the script.
* **Reverse Engineering:**  How could this tool be used in reverse engineering?  Changing build options could affect how a target application is built and linked, potentially influencing its behavior during analysis. Seeing default and current options helps understand the build setup.
* **Binary/Linux/Android:**  Identify code snippets that touch on these areas. For example, compiler options directly relate to binary generation. The mention of subprojects hints at how larger projects (like Frida, which can target Android) are organized.
* **Logical Reasoning:**  Look for conditional logic and branching. Consider what happens under different scenarios (e.g., providing a build directory vs. a source directory). The `if/elif/else` structure in `__init__` is a good example.
* **User Errors:**  Think about common mistakes a user might make. Providing the source directory instead of the build directory is explicitly handled.
* **User Steps and Debugging:**  Trace the execution flow from the command line to the core functions. Imagine how a user would invoke this script and how it interacts with the Meson build system.

**5. Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each point in the prompt. Use headings and bullet points for readability. Provide concrete examples where possible. For instance, when discussing compiler options, mention specific options like optimization levels or debugging flags.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this script directly manipulates binaries. **Correction:**  The code focuses on *configuration* before the build process. It influences how binaries are created, but doesn't directly modify them.
* **Initial thought:** The subproject handling is just for organization. **Refinement:** Subprojects are a key feature of Meson, allowing for modularity and dependency management, which can be relevant in reverse engineering by understanding project structure.
* **Overlooking details:** Initially, I might skim over the `print_nondefault_buildtype_options` function. **Correction:** Upon closer inspection, this function reveals important information about deviations from default build settings, which is relevant for understanding build behavior.

By following these steps, breaking down the code, and constantly relating it back to the prompt's questions, we can arrive at a comprehensive and accurate understanding of the `mconf.py` script.
这个Python源代码文件 `mconf.py` 是 Frida 动态插桩工具中，用于管理和显示 Meson 构建系统配置选项的工具。它的主要功能是允许用户查看和修改 Frida 项目的构建配置，例如编译器选项、依赖项、功能开关等。

下面详细列举其功能，并根据你的要求进行说明：

**1. 显示当前构建配置:**

*   **功能:**  读取已存在的 Meson 构建目录（`builddir`），解析 `meson-private/coredata.dat` 文件，该文件存储了项目的配置信息。然后，它格式化并显示这些配置选项及其当前值。
*   **与逆向的关系:** 了解目标程序是如何构建的，可以为逆向分析提供重要的上下文信息。例如：
    *   **编译器优化级别:**  如果构建使用了 `-O0` (无优化)，逆向分析可能会更容易，因为代码结构更接近源代码。如果使用了 `-O3` (最高优化)，代码会被大量优化和内联，逆向难度会增加。
    *   **调试符号:** 是否启用了调试符号 (`-g`) 会极大地影响逆向调试的体验。有调试符号可以更容易地定位代码位置和变量。
    *   **链接库:**  了解链接了哪些库，可以帮助逆向工程师识别程序可能使用的功能和技术，以及潜在的攻击面。
*   **二进制底层/Linux/Android:** 编译器选项直接影响生成的二进制代码的结构和性能。例如，`-march=` 指定了目标 CPU 架构，这与二进制的指令集有关。在 Android 开发中，了解 NDK 构建选项对于分析 Native 代码至关重要。
*   **逻辑推理:**
    *   **假设输入:**  用户在终端中运行 `meson conf build`，其中 `build` 是一个已经存在的 Frida 构建目录。
    *   **预期输出:**  终端会显示一个格式化的表格，列出 Frida 项目的各种配置选项，包括 "Core properties" (如源代码目录、构建目录) 和不同类别的选项 (如 "Main project options", "Compiler options", "Project options" 等)，以及它们的当前值。
*   **用户错误:** 如果用户指定的 `builddir` 不是一个有效的 Meson 构建目录，程序会抛出 `ConfException` 并提示错误信息："Directory {build_dir} is neither a Meson build directory nor a project source directory."
*   **用户操作到达这里:** 用户通常在已经使用 `meson setup build` 创建了一个构建目录后，想要查看或修改构建选项时，会运行 `meson conf build` 命令。`meson` 命令会调用 `mesonbuild/mconf.py` 脚本。

**2. 修改构建配置:**

*   **功能:** 允许用户通过命令行选项修改构建配置。例如，用户可以使用 `--option=value` 的形式来设置或更改某个配置项的值。修改后的配置会保存到 `meson-private/coredata.dat` 文件中。
*   **与逆向的关系:** 修改构建配置可以用于构建不同版本的 Frida，以适应不同的逆向分析需求。例如：
    *   **禁用特定功能:**  在分析特定功能时，可以禁用其他功能以简化分析范围。
    *   **启用调试功能:**  构建包含更多调试信息的 Frida 版本，有助于深入理解其内部工作原理。
*   **二进制底层/Linux/Android:**  修改编译器选项 (例如，更改优化级别) 会直接影响最终生成的 Frida 库或可执行文件的二进制代码。在 Android 环境中，修改 NDK 相关的配置会影响 Frida Agent 的构建。
*   **逻辑推理:**
    *   **假设输入:** 用户运行 `meson conf -Dbuildtype=debug build`。
    *   **预期输出:**  `buildtype` 选项的值会被设置为 `debug`，这通常会影响编译器优化级别和是否包含调试符号。下次构建时，会使用这些新的配置。
*   **用户错误:**
    *   **拼写错误:** 如果用户输入的选项名称拼写错误，`set_options` 方法可能会忽略该选项，或者 Meson 会在后续构建过程中报错。
    *   **无效的值:**  如果用户为某个选项提供了无效的值（例如，布尔值选项输入了 "yes" 而不是 "true"），`set_options` 方法会进行验证，如果验证失败，会拒绝修改。
*   **用户操作到达这里:** 用户在想要调整 Frida 的构建方式时，例如更改构建类型、启用/禁用某些功能，会使用 `meson conf` 命令加上相应的选项。

**3. 清除缓存:**

*   **功能:**  通过 `--clearcache` 选项，用户可以清除 Meson 的缓存状态，例如已找到的依赖项信息。这在解决构建问题时有时很有用，可以强制 Meson 重新检测依赖项。
*   **与逆向的关系:**  在某些情况下，错误的依赖项缓存可能导致构建失败或生成不正确的 Frida 版本，影响逆向分析的工具链。清除缓存可以帮助解决这类问题。
*   **用户操作到达这里:** 当遇到与依赖项相关的构建问题，或者在修改了系统环境后需要 Meson 重新检测依赖项时，用户会使用 `meson conf --clearcache build` 命令。

**4. 格式化输出:**

*   **功能:**  `print_aligned` 方法负责将配置选项以表格的形式在终端中整齐地显示，提高可读性。它会根据终端的宽度进行自适应调整。
*   **用户操作到达这里:** 当用户运行 `meson conf build` 时，`print_conf` 方法会调用 `print_aligned` 来显示配置信息。

**5. 处理子项目配置:**

*   **功能:**  `split_options_per_subproject` 方法用于将配置选项按子项目进行划分。Frida 项目可能包含多个子项目，每个子项目可能有自己的配置选项。
*   **与逆向的关系:**  理解 Frida 的模块化结构以及各个子项目的配置，有助于更精确地定位需要分析的代码和功能。
*   **用户操作到达这里:**  当 Frida 项目配置包含子项目时，`print_conf` 方法会调用 `split_options_per_subproject` 来组织选项，并在输出中分别显示每个子项目的配置。

**6. 处理只显示默认值的情况:**

*   **功能:** 如果用户在源代码目录而不是构建目录中运行 `meson conf`，`Conf` 类的初始化会进入不同的分支，只读取 `meson.options` 文件，并标记 `default_values_only` 为 `True`。此时，`print_conf` 方法会显示选项的默认值，并给出警告信息。
*   **与逆向的关系:** 了解 Frida 的默认配置可以帮助理解其设计意图和预期行为。
*   **用户错误:** 用户可能会错误地在源代码目录运行 `meson conf`。程序会给出警告，提示用户应该在构建目录中运行以查看或修改实际的构建配置。

**与二进制底层，linux, android内核及框架的知识的联系:**

*   **编译器选项 (Compiler options):**  这些选项直接传递给编译器 (如 GCC, Clang)，控制着二进制代码的生成方式，例如优化级别 (`-O`), 目标架构 (`-march`), 调试信息 (`-g`) 等。这直接关系到最终生成的 Frida 库或可执行文件的二进制结构和性能。在 Android NDK 构建中，会涉及到针对 ARM 或 ARM64 架构的编译选项。
*   **链接器选项 (Backend options):**  例如，链接类型 (静态或动态链接)，影响最终二进制文件的依赖关系和大小。
*   **目标操作系统和架构 (Core properties):**  配置中会指定目标操作系统 (Linux, Android, macOS, Windows) 和 CPU 架构 (x86, x86_64, ARM, ARM64)。这些信息决定了 Frida 将如何构建，以及它将运行在哪些平台上。
*   **Android 特有选项:**  可能存在与 Android NDK 构建相关的选项，例如指定 `target_sdk` 版本，或者与 Android 平台特定的库或框架的链接配置。
*   **模块化设计 (Subprojects):**  Frida 作为一个复杂的工具，很可能采用了模块化的设计。通过子项目来组织代码和配置，可以更好地管理依赖关系和构建流程。了解这些子项目的配置有助于理解 Frida 的内部结构。

**用户操作一步步到达这里的调试线索:**

1. **用户打开终端。**
2. **用户 `cd` 到 Frida 的构建目录 (例如 `frida/build`).** 或者错误地 `cd` 到了源代码目录。
3. **用户输入命令 `meson conf [选项]`.**  例如：
    *   `meson conf` (查看当前配置)
    *   `meson conf -Dbuildtype=release` (设置构建类型为 release)
    *   `meson conf --clearcache` (清除缓存)
4. **Meson 工具接收到 `conf` 命令，会调用 `mesonbuild/mconf.py` 脚本。**
5. **`mconf.py` 的 `run` 函数被执行。**
6. **`run` 函数调用 `coredata.parse_cmd_line_options` 解析命令行选项。**
7. **`run` 函数确定要操作的构建目录。**
8. **`run` 函数调用 `run_impl` 函数，传入解析后的选项和构建目录。**
9. **在 `run_impl` 函数中，`Conf` 类被实例化，尝试加载或读取配置信息。**
    *   如果构建目录存在，它会读取 `meson-private/coredata.dat`。
    *   如果只提供了源代码目录，它会读取 `meson.options` 并设置 `default_values_only`。
10. **根据用户是否提供了命令行选项，执行相应的操作：**
    *   如果提供了选项 (`options.cmd_line_options`)，调用 `c.set_options` 修改配置。
    *   如果提供了 `--clearcache`，调用 `c.clear_cache`。
    *   如果只是查看配置，调用 `c.print_conf`。
11. **`print_conf` 函数会组织并格式化配置信息，最终调用 `c.print_aligned` 将结果输出到终端。**
12. **如果修改了配置，`c.save` 函数会将更改保存到 `meson-private/coredata.dat`。**

总而言之，`mconf.py` 是 Frida 项目中一个重要的配置管理工具，它允许用户查看和修改构建选项，从而影响最终生成的 Frida 工具的行为和特性。理解其功能对于构建定制化的 Frida 版本以适应不同的逆向分析场景至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/mconf.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```