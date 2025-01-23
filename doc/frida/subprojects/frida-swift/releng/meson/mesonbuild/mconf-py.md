Response:
Let's break down the thought process for analyzing this Python script. The request asks for several things: functionality, relation to reverse engineering, low-level details, logical reasoning, common errors, and user path. Here’s a step-by-step approach:

1. **Understand the Core Purpose:**  The first lines indicate this is part of the Frida project, specifically related to configuration (`mconf.py`) and integrated with Meson (a build system). The presence of `builddir` arguments and options like `--clearcache` strongly suggest it's about managing build settings.

2. **Identify Key Classes and Functions:** Scan the code for class and function definitions. The main actors seem to be:
    * `Conf`:  This is likely the central class managing the configuration state.
    * `add_arguments`: Handles command-line argument parsing.
    * `stringify`:  Converts values to strings for display.
    * `run_impl` and `run`:  Entry points for executing the configuration logic.
    * Various `print_*` methods: Responsible for displaying configuration information.

3. **Analyze Functionality by Section:** Go through the code block by block, understanding what each part does.

    * **Imports:**  Note the imported modules (`itertools`, `hashlib`, `os`, `textwrap`, `typing`, etc.). These hint at the script's operations (string manipulation, file operations, type hinting). The imports from the same directory (`. build`, `. coredata`) are also crucial for understanding dependencies within the Frida/Meson context.

    * **`add_arguments`:** Clearly for defining command-line options. The presence of `builddir`, `--clearcache`, and `--no-pager` tells us about the user interface.

    * **`stringify`:**  A utility for formatting output, handling booleans and lists specifically.

    * **`Conf` Class (Constructor `__init__`)**: This is where the core logic resides. Pay attention to how it determines the build directory, loads existing configurations (if present), or initializes for a new configuration. The logic for handling `meson.build` and `meson-private` is important. The handling of `meson.options` and the hashing mechanism for detecting changes is also notable. The fallback to introspection when a build directory isn't found is key.

    * **`clear_cache`, `set_options`, `save`:**  These methods deal with modifying and persisting the configuration. The comment in `save` about not writing the build file is a detail to note.

    * **`print_aligned`:** Focus on how it formats the output using `textwrap` and `shutil.get_terminal_size`. This shows attention to user experience.

    * **`split_options_per_subproject`:**  Indicates the script handles multi-project builds.

    * **`_add_line`, `add_option`, `add_title`, `add_section`, `print_options`:**  These are the building blocks for generating the configuration display. Notice how they use color codes (`mlog.green`, `mlog.yellow`, etc.).

    * **`print_conf`:** This is the main function for displaying the configuration. Observe how it organizes options into categories (core, backend, compiler, etc.) and handles subprojects. The warning about default values is important.

    * **`print_nondefault_buildtype_options`:**  Handles a specific case of highlighting differences from default build type options.

    * **`run_impl` and `run`:**  These orchestrate the entire process, handling argument parsing, error handling, and calling the `Conf` methods.

4. **Address Specific Questions:** Now, go back through the identified functionality and explicitly answer each part of the request:

    * **Functionality:** Summarize the actions the script performs (managing build configurations, displaying options, etc.).

    * **Reverse Engineering:**  Think about *how* this relates to reverse engineering. The ability to inspect and modify build options is crucial for controlling how software is built, which directly impacts what a reverse engineer encounters. Consider examples like enabling debug symbols or changing optimization levels.

    * **Binary/Low-Level/Kernel/Framework:** Look for clues related to these areas. While the script itself doesn't directly interact with the kernel, the *options* it manages can significantly influence the compiled binary and how it interacts with the OS. Think about compiler flags, linking options, and potentially framework-specific settings.

    * **Logical Reasoning:**  Identify places where the script makes decisions. The `if/elif/else` block in the `Conf` constructor determining how to load configuration is a prime example. Formulate assumptions about inputs (e.g., providing a source directory vs. a build directory) and predict the output.

    * **User Errors:**  Consider common mistakes a user might make. Providing the source directory instead of the build directory is a clear one, and the script explicitly handles this. Forgetting to configure before trying to modify options is another potential error.

    * **User Path/Debugging:** Trace the steps a user would take to reach this code. The command-line invocation of `mesonconf` is the starting point. Explain how the arguments are parsed and how the script then proceeds to load and display/modify the configuration.

5. **Structure the Output:** Organize the findings logically, using clear headings and bullet points. Provide specific code snippets where relevant. Explain the connections between different parts of the code and how they relate to the questions asked.

6. **Review and Refine:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check if all parts of the original request have been addressed. Ensure the language is precise and avoids jargon where possible. For instance, initially, I might just say "it loads options." Refining this to "it loads existing build configurations from `meson-private` if available, or reads default options from `meson.options` in the source directory" is much more informative.

This structured approach ensures that all aspects of the request are considered systematically and that the analysis is comprehensive and well-organized.
这是一个名为 `mconf.py` 的 Python 源代码文件，位于 Frida 项目的子项目 `frida-swift` 的构建系统相关目录中。它的主要功能是提供一个命令行界面，用于**查看和修改 Meson 构建系统的配置选项**。

以下是其功能的详细列表，并结合您提出的各种关系进行说明：

**1. 查看和修改构建选项:**

*   **功能:**  该脚本允许用户查看当前构建目录的 Meson 配置选项及其值。如果提供了命令行参数，它还可以修改这些选项。
*   **与逆向的关系:**  在逆向工程中，了解目标软件的构建配置非常重要。例如，是否启用了调试符号（debug symbols）、优化级别、是否使用了特定的编译器标志等，都会影响逆向分析的难度和方法。通过 `mconf.py`，逆向工程师可以查看 Frida 构建时的配置，从而更好地理解 Frida 的行为和特性。
    *   **举例:**  如果 Frida 构建时启用了调试符号 (`buildtype=debug`),  逆向工程师在分析 Frida 进程时就能更容易地定位到源代码级别的错误和逻辑。反之，如果构建类型是发布版本 (`buildtype=release`)，代码经过了优化和混淆，逆向难度会大大增加。
*   **涉及二进制底层知识:**  构建选项直接影响最终生成的二进制文件的内容。例如，编译器优化选项会影响指令的排列、寄存器的使用、以及是否进行内联等。链接器选项会影响库的链接方式、符号表的生成等。
    *   **举例:** 查看编译器选项，如 `-fPIC` (Position Independent Code)，可以了解 Frida 是否被编译为位置无关代码，这对于理解共享库的加载和地址空间布局至关重要。

**2. 清除缓存:**

*   **功能:**  `--clearcache` 选项允许用户清除 Meson 缓存的状态，例如已找到的依赖项信息。
*   **与逆向的关系:**  在 Frida 的开发和调试过程中，可能需要强制 Meson 重新检测依赖项或配置。这在解决构建问题或者尝试不同版本的依赖项时很有用。虽然不直接用于逆向目标程序，但它是 Frida 工具链的一部分，影响着 Frida 本身的构建。
*   **涉及 Linux 知识:** Meson 缓存通常存储在构建目录的 `meson-private` 文件夹下。清除缓存涉及到删除或修改这些文件。

**3. 处理不同的构建目录和源目录:**

*   **功能:** 脚本可以处理两种情况：
    *   指定一个 Meson **构建目录** (`builddir`)：在这种情况下，脚本会加载现有的构建配置，并允许查看和修改。
    *   指定一个 Meson **源目录** (`builddir`)：在这种情况下，脚本只显示项目选项的默认值，因为还没有实际的构建配置。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 用户运行 `mesonconf build`，其中 `build` 是一个已存在的 Meson 构建目录。
    *   **预期输出:** 脚本会显示 `build` 目录中配置的各种选项的当前值，例如编译器、构建类型、安装目录等。
    *   **假设输入:** 用户运行 `mesonconf /path/to/frida/source`，其中 `/path/to/frida/source` 是 Frida 的源代码目录，但尚未在该目录下运行过 `meson` 命令。
    *   **预期输出:** 脚本会显示 Frida 项目在 `meson.options` 文件中定义的各种选项的默认值，并提示用户该目录不是一个构建目录。
*   **涉及用户或编程常见的使用错误:**
    *   **错误:** 用户可能错误地将源代码目录作为 `mesonconf` 的参数，期望修改构建配置。
    *   **脚本行为:**  `mconf.py` 会检测到这种情况，并只显示默认值，并给出警告信息 "The source directory instead of the build directory was specified."。

**4. 加载和保存构建配置:**

*   **功能:**  脚本使用 `build.load()` 加载现有的构建配置，并使用 `coredata.save()` 保存修改后的配置。
*   **涉及 Linux 知识:** 构建配置通常存储在构建目录的 `meson-private/coredata.dat` 文件中。加载和保存涉及到读取和写入该文件。
*   **涉及二进制底层知识:** `coredata.dat` 文件通常以二进制格式存储配置信息，这需要相应的序列化和反序列化操作。

**5. 处理子项目:**

*   **功能:**  脚本能够处理包含子项目的构建配置，并分别显示和修改主项目和子项目的选项。
*   **涉及 Android 框架知识 (如果 Frida-Swift 用于 Android):** 在 Android 开发中，常常会将不同的模块或组件作为子项目进行管理。Frida-Swift 如果用于 hook Android 应用程序，可能需要处理与 Android NDK 或其他 Android 相关组件的集成，这些可能会作为子项目存在。

**6. 格式化输出:**

*   **功能:** 脚本使用 `textwrap` 和 `shutil.get_terminal_size` 来格式化输出，使其更易读。
*   **用户操作是如何一步步的到达这里，作为调试线索:**
    1. 用户在终端中输入命令 `mesonconf`，可能带有可选的构建目录参数和选项，例如 `mesonconf build --buildtype=debug`。
    2. 操作系统执行 `mesonconf` 脚本。
    3. `add_arguments` 函数解析命令行参数，将用户提供的构建目录、选项等信息传递给脚本。
    4. `run` 函数调用 `run_impl`，并将解析后的参数传递给它。
    5. `run_impl` 函数创建 `Conf` 类的实例，传入构建目录。
    6. `Conf` 类的 `__init__` 方法会检查构建目录是否存在，并尝试加载已有的构建配置（如果存在）。如果只提供了源代码目录，则会加载默认选项。
    7. 如果用户提供了命令行选项 (如 `--buildtype=debug`)，`run_impl` 会调用 `c.set_options()` 来修改配置。
    8. `c.print_conf()` 函数负责格式化并输出当前的配置信息，包括核心属性、各种类型的选项（核心选项、编译器选项、模块选项等）以及子项目选项。
    9. 如果启用了分页器 (`--no-pager` 未使用)，输出会通过 `mlog.start_pager()` 传递给分页程序（如 `less`）。
    10. 如果出现错误，例如找不到构建目录，`run_impl` 会捕获 `ConfException` 并输出错误信息。

**7. 涉及编程常见的使用错误:**

*   **错误:** 用户尝试在没有运行过 `meson` 命令的源代码目录下运行 `mesonconf` 并尝试修改选项。
*   **脚本行为:**  脚本会抛出 `mesonlib.MesonException('No valid build directory found, cannot modify options.')`。

**总结:**

`mconf.py` 是 Frida 构建系统中一个关键的实用工具，它允许开发者和用户方便地查看和调整构建配置。这对于理解 Frida 的构建方式、解决构建问题以及针对特定目标环境进行定制非常重要。从逆向的角度来看，理解 Frida 的构建配置有助于更好地分析其行为和特性。脚本的功能涉及文件操作、命令行参数解析、数据加载和保存、格式化输出等编程基础，并与 Meson 构建系统紧密结合。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/mconf.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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