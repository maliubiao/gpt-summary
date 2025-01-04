Response:
Let's break down the thought process for analyzing this Python code and answering the user's questions.

**1. Understanding the Goal:**

The core goal is to analyze the functionality of `mconf.py`, a file within the Frida project's build system (Meson), and connect its features to concepts like reverse engineering, low-level details, and user interaction.

**2. Initial Code Scan and Keyword Spotting:**

First, I'd quickly scan the code for prominent keywords and structures to get a general idea of its purpose. I'd look for:

* **Imports:**  `os`, `shutil`, `hashlib`, `argparse`, `textwrap`, etc. These hint at file system operations, command-line argument parsing, text manipulation, and hashing. The imports from within the `.meson` package (like `build`, `coredata`, `environment`) are crucial for understanding its role in the build process.
* **Class Definitions:** `Conf`, `ConfException`. This suggests the code is object-oriented and deals with configuration management.
* **Function Definitions:**  `add_arguments`, `stringify`, `set_options`, `save`, `print_conf`, `run`, `run_impl`. These are the action verbs of the script and hint at different stages of the configuration process.
* **String Literals:**  Looking for informative strings like "builddir", "--clearcache", "meson.build", "Current Value", "Possible Values", etc., provides context about the script's user interface and data handling.
* **Comments:** The SPDX license and copyright information are standard. The comment about adding arguments to completion scripts is a valuable detail.
* **Conditional Logic (`if`, `elif`, `else`):** These indicate decision points in the code's execution flow. For instance, checking if a directory is a Meson build directory.
* **Loops (`for`):** These suggest iteration over collections of data, such as options or subprojects.

**3. Deeper Dive into Key Functions and Classes:**

After the initial scan, I'd focus on the central elements:

* **`Conf` Class:** This is clearly the core of the configuration logic. I'd pay attention to:
    * `__init__`:  How it initializes the configuration object, especially the logic for detecting build directories and loading existing configuration or introspection data. The handling of `meson.options` and `meson_options.txt` is important.
    * `set_options`: How it updates configuration based on user input.
    * `save`:  How it persists the configuration. The comment about not writing the build file is a key piece of information.
    * `print_conf`: The complex logic for formatting and displaying the configuration. The use of `textwrap` and `mlog` (Meson's logging) is relevant.
    * `split_options_per_subproject`: How it organizes options for subprojects.

* **`add_arguments` function:** This clearly defines the command-line interface of the script.

* **`run` and `run_impl` functions:** These represent the entry point and main execution flow of the script. The error handling with `try...except` is also important.

**4. Connecting to User Questions (The "Why"):**

With a solid understanding of the code's mechanics, I'd address each of the user's specific questions:

* **Functionality:** This involves summarizing what the code does. I'd focus on the main tasks: loading, displaying, modifying, and saving build configurations.

* **Relation to Reverse Engineering:** This requires thinking about how build configuration affects the final binary. Compiler flags, optimization levels, and debugging symbols are key connections.

* **Binary/Low-Level, Linux/Android Kernel/Framework:**  This involves identifying code sections or concepts related to the underlying system. Compiler options are the primary connection here, influencing how code is compiled and linked. Subproject handling might touch on library dependencies.

* **Logical Reasoning (Input/Output):** This requires identifying key decision points and predicting the outcome based on inputs. The logic for detecting build directories and the conditional printing of options are good examples.

* **Common Usage Errors:**  This involves thinking about how a user might misuse the script. Providing the wrong directory or trying to modify options when only introspection data is available are good examples.

* **User Operation to Reach This Point:** This requires tracing the typical Meson workflow. Running `meson setup` followed by `meson configure` is the most common path.

**5. Structuring the Answer:**

Finally, I'd organize the information logically, using clear headings and bullet points to address each of the user's questions systematically. Providing specific code snippets and explaining their relevance enhances clarity.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This script just displays configuration."  **Correction:**  Realized it also *modifies* and *saves* configuration based on command-line arguments.
* **Initial thought:** "Reverse engineering is far removed from this." **Correction:** Understood that build configuration directly impacts the *output* of the build process, which is what reverse engineers analyze. Compiler flags and debugging symbols became key connections.
* **Overlooking details:** Initially missed the nuances of subproject handling. Revisited the code and saw the `split_options_per_subproject` function.
* **Ambiguity in "binary bottom layer":** Realized the user might be thinking of direct memory manipulation. Clarified that the connection here is primarily through *compiler options* that affect the binary structure, not direct low-level coding within this script.

By following this thought process, breaking down the code, and systematically addressing each part of the user's request, I could generate a comprehensive and accurate answer.
这个Python源代码文件 `mconf.py` 是 Frida 动态 instrumentation 工具中用于配置构建选项的工具。它基于 Meson 构建系统，并允许用户查看和修改项目的构建配置。

以下是它的功能列表，并结合你的问题进行详细说明：

**1. 查看当前构建配置 (Inspection):**

* **功能:**  允许用户查看当前项目的构建配置选项及其值。这包括核心选项、编译器选项、模块选项、目录设置、测试选项以及项目自定义选项。
* **逆向关系:** 了解构建配置对于逆向工程至关重要。例如：
    * **调试符号 (Debug Symbols):**  如果构建配置启用了调试符号（例如，通过 `-Dbuildtype=debug` 或特定的编译器 flag 如 `-g`），逆向工程师可以更容易地调试目标程序，因为符号信息提供了函数名、变量名和代码行号等。`mconf.py` 可以显示 `-Dbuildtype` 的当前值，或者编译器相关的调试选项。
    * **优化级别 (Optimization Level):** 构建配置中的优化级别（例如，`-Dbuildtype=release` 通常会启用优化，而 `-Dbuildtype=debug` 则不会）会显著影响二进制代码的结构和可读性。高优化级别的代码更难逆向。`mconf.py` 可以展示当前的优化设置。
    * **架构和目标平台 (Architecture and Target Platform):** 构建配置会指定目标架构（如 x86, ARM）和操作系统。这对于逆向工程至关重要，因为不同架构和操作系统的二进制格式和调用约定不同。`mconf.py` 可以显示 `-Dhost_machine` 和 `-Dbuild_machine` 等信息。
* **二进制底层/内核/框架:**  某些构建选项可能直接影响生成的二进制文件的底层特性或与操作系统内核/框架的交互：
    * **链接器选项 (Linker Options):**  构建配置可能包含影响链接过程的选项，例如指定链接的库文件或设置安全相关的选项（如 ASLR, PIE）。这些选项直接影响最终可执行文件的结构和加载方式。
    * **操作系统特定的配置:**  对于 Android 平台，构建配置可能涉及到 NDK 的使用、目标 API 级别等，这些都直接关联到 Android 框架。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 用户在 Frida 的构建目录下运行 `meson configure` 或 `mesonconf`。
    * **输出:** `mconf.py` 将加载当前的构建配置，并按照类别（核心选项、编译器选项等）整齐地列出所有可配置的选项及其当前值。

**2. 修改构建配置 (Configuration):**

* **功能:** 允许用户通过命令行参数修改项目的构建配置选项。
* **逆向关系:** 修改构建配置可以为逆向工程创建更友好的环境：
    * **启用调试符号:**  逆向工程师可以通过 `meson configure -Dbuildtype=debug` 或修改相应的编译器选项来启用调试符号，从而方便调试。
    * **禁用优化:** 通过 `meson configure -Dbuildtype=plain` 或调整优化级别，可以生成更容易理解和分析的二进制代码。
* **二进制底层/内核/框架:**  用户可以通过修改构建选项来影响 Frida 与底层系统或框架的交互方式。例如，可以配置 Frida 的运行时行为或选择特定的 hook 引擎。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 用户在构建目录下运行 `meson configure -Doption1=value1 -Doption2=value2`。
    * **输出:** `mconf.py` 会解析这些命令行参数，更新相应的构建配置选项，并保存更改。下次构建时，将使用新的配置。
* **用户或编程常见的使用错误:**
    * **错误的选项名称:** 用户可能会输入不存在的选项名称，导致配置失败或被忽略。Meson 通常会给出警告或错误提示。
    * **选项值类型不匹配:**  某些选项有特定的值类型要求（例如，布尔值、字符串、列表）。如果用户提供的值类型不正确，可能会导致配置错误。
    * **在源代码目录运行 `meson configure` 并尝试修改:** 代码中会检查是否在构建目录运行。如果在源代码目录运行，它只会显示默认值，并且不允许修改配置。

**3. 清除缓存 (Cache Clearing):**

* **功能:**  通过 `--clearcache` 选项，用户可以清除 Meson 的缓存。
* **逆向关系:**  在某些情况下，旧的构建缓存可能导致构建行为异常或影响逆向分析的结果。清除缓存可以确保构建过程从一个干净的状态开始。例如，当依赖项的版本发生变化时，清除缓存可以强制 Meson 重新检测。
* **二进制底层/内核/框架:**  缓存可能包含关于已找到的库、编译器信息等，清除缓存会迫使 Meson 重新探测这些信息，这可能间接影响到最终的二进制文件。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** 用户在构建目录下运行 `meson configure --clearcache`。
    * **输出:** `mconf.py` 将指示 Meson 清除其内部缓存，包括已找到的依赖项信息等。

**4. 与 Meson 构建系统的集成:**

* `mconf.py` 依赖于 Meson 的核心组件，如 `coredata` (存储构建配置数据), `environment` (提供环境信息), `optinterpreter` (解析选项文件) 等。
* 它读取和写入 Meson 的内部配置数据，确保配置的持久化。
* **用户操作到达这里的步骤 (调试线索):**
    1. **初始化构建:** 用户通常首先在项目的源代码目录下运行 `meson setup <build_directory>` 来创建一个构建目录。
    2. **配置构建 (到达 `mconf.py` 的入口):**  用户在构建目录下运行 `meson configure` 或 `mesonconf`。实际上，`meson configure` 命令会调用 `mconf.py` 来处理配置相关的操作。
    3. **修改配置 (可选):** 用户可以在 `meson configure` 命令后添加 `-D<option>=<value>` 参数来修改特定的构建选项。
    4. **清除缓存 (可选):** 用户可以使用 `meson configure --clearcache` 来清除缓存。

**5. 代码结构和关键部分:**

* **`Conf` 类:**  负责加载、存储和操作构建配置数据。
    * `__init__`: 初始化配置对象，加载已有的构建配置或从源代码目录进行内省。
    * `set_options`:  根据用户提供的选项更新配置数据。
    * `save`: 将修改后的配置保存到磁盘。
    * `print_conf`:  负责格式化并打印当前的构建配置。
* **`add_arguments` 函数:**  定义了 `meson configure` 命令可以接受的命令行参数。
* **`run_impl` 和 `run` 函数:**  是脚本的入口点，处理命令行参数并调用 `Conf` 类的方法来完成配置操作。

**举例说明涉及的知识点:**

* **二进制底层:**  构建选项中的编译器 flags（例如，`-march`, `-mtune`, `-mabi`）直接影响生成的机器码指令集和二进制文件的布局。链接器选项（例如，`-L`, `-l`) 控制着库的链接，这直接影响最终可执行文件的依赖关系和加载过程。
* **Linux 内核:**  一些构建选项可能涉及到与 Linux 内核的交互，例如，选择特定的系统调用接口或启用特定的内核功能支持。
* **Android 内核及框架:**  在构建 Android 相关的组件时，构建选项可能涉及到 NDK 的路径、目标 API 级别、ABI 过滤等，这些都与 Android 的底层内核和框架紧密相关。
* **逻辑推理 (更复杂的例子):**
    * **假设输入:**  用户在一个之前使用 `-Dbuildtype=debug` 配置过的构建目录下运行 `meson configure -Dbuildtype=release`。
    * **输出:** `mconf.py` 将会检测到 `buildtype` 选项的值发生了变化，并将配置更新为 `release`。这意味着编译器将会启用优化，并且调试符号可能不会被包含在最终的二进制文件中。
* **用户或编程常见的使用错误 (更具体的例子):**
    * 用户尝试设置一个布尔类型的选项为字符串 `"yes"` 而不是 `true` 或 `false`，可能会导致 Meson 报错或将该选项视为字符串而不是布尔值。
    * 用户在子项目的构建目录下运行 `meson configure`，可能会导致意想不到的结果，因为子项目的配置通常由主项目控制。

总而言之，`mconf.py` 是 Frida 构建流程中一个关键的工具，它允许用户查看和定制构建过程的各个方面。理解其功能对于逆向工程人员来说非常重要，因为构建配置直接影响最终生成的可执行文件的特性，从而影响逆向分析的难易程度和结果。

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/mconf.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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