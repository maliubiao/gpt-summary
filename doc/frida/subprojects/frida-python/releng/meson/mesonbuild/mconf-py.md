Response:
Let's break down the thought process for analyzing this Python code. The request asks for several things, requiring a multi-faceted approach.

**1. Understanding the Core Purpose:**

* **Initial Scan:**  The filename `mconf.py` within `frida/subprojects/frida-python/releng/meson/mesonbuild` strongly suggests this is related to *configuration* within the Meson build system, specifically for the Frida Python bindings. The `conf` likely stands for "configuration."
* **`# SPDX-License-Identifier: Apache-2.0`:** This immediately tells us it's open-source and hints at the development context.
* **Imports:** The imports like `build`, `coredata`, `environment`, `mesonlib`, `mintro`, `ast`, `optinterpreter` are key. These point to various parts of the Meson build system. We can infer that this module interacts with the build state, project options, environment information, and the abstract syntax tree of Meson build files.
* **`class Conf:`:** This is the central class. The `__init__` method is crucial for understanding how it's initialized and what data it loads. The logic within `__init__` branches based on whether it's in a build directory or a source directory. This distinction is important.
* **Methods like `clear_cache`, `set_options`, `save`, `print_conf`:** These suggest actions the `Conf` class can perform related to configuration.

**2. Identifying Key Functionality:**

* **Loading Configuration:**  The `__init__` method handles loading existing build configurations or introspecting a source directory to get default values. It checks for `meson-private` and `meson.build` files.
* **Displaying Configuration:** The `print_conf` method and its helper methods (`add_title`, `add_section`, `add_option`, `print_aligned`) are responsible for formatting and presenting the configuration options to the user. The colored output using `mlog` is also noticeable.
* **Modifying Configuration:** The `set_options` method allows changing configuration values based on user input. The `save` method persists these changes.
* **Handling Subprojects:** The code clearly handles configuration options for subprojects, indicating a hierarchical build structure.
* **Command-Line Interface:** The `add_arguments` and `run` functions suggest this module is intended to be executed from the command line. The use of `argparse` confirms this.

**3. Connecting to Reverse Engineering (as requested):**

* **Dynamic Instrumentation (Frida Context):** Knowing this is part of Frida is crucial. Frida is a dynamic instrumentation toolkit. The configuration managed by this code likely influences *how* Frida itself is built and potentially *how* Frida instruments target processes.
* **Modifying Build Options:**  Changing options like compiler flags, enabled features, or dependencies directly affects the resulting Frida binaries. This is a key step in preparing a Frida build for specific reverse engineering tasks. For example, enabling debug symbols or certain instrumentation modules.
* **Target Architecture/OS:**  Build systems often handle cross-compilation. Configuration options would specify the target architecture (e.g., ARM, x86) and operating system (e.g., Android, Linux), critical for building Frida that can target a specific device.

**4. Identifying Connections to Binary/Kernel/Framework (as requested):**

* **Compiler Options:**  Compiler flags managed by this configuration directly impact the generated binary code. For instance, `-fPIC` for position-independent code is essential for shared libraries, a common component in dynamic instrumentation.
* **Dependencies:**  Frida likely depends on other libraries. The configuration would manage these dependencies. Some dependencies might be related to low-level system interaction or specific platform frameworks.
* **Target System Details (Android/Linux):**  Configuration options might specify paths to Android SDKs, NDKs, or specific kernel headers needed for building Frida components that interact with the Android or Linux kernel. Options for specific Android framework versions or architectures would also fall here.

**5. Inferring Logic and Examples (as requested):**

* **Input/Output of `set_options`:**  The function takes a dictionary of `OptionKey` to string values. The output is a boolean indicating whether any options were actually changed. *Example:* Input: `{'apis': 'qnx', 'ssl': 'openssl'}`. Output: `True` (if these differ from the current config).
* **Input/Output of `print_conf`:** This is harder to give a precise input/output without a specific project. However, the input is the current configuration state. The output is the formatted text displayed to the user, showing the options and their values.

**6. Identifying User Errors (as requested):**

* **Specifying the wrong directory:** The code checks if the provided directory is a build or source directory. Providing a completely unrelated directory is a common error.
* **Incorrect option names:**  The `set_options` method relies on valid `OptionKey` values. Typing an option name incorrectly will lead to no change or potentially an error.
* **Invalid option values:**  Each option has a specific type (string, boolean, list, etc.) and possibly a set of allowed values. Providing an incorrect type or value (e.g., setting a boolean option to "maybe") is an error.

**7. Tracing User Actions (as requested):**

* The user would likely execute a command like `mesonconf` or a similar command provided by the Frida build system.
* They might provide the build directory as an argument: `mesonconf build`.
* They might use command-line options to change settings: `mesonconf -Dapis=qnx build`.
* If they provide a source directory instead of a build directory, they'll see the warning about default values.
* The `--clearcache` option would be a specific action to clear the cached state.

**Self-Correction/Refinement During Analysis:**

* **Initial Assumption:** I might initially focus too much on the Frida-specific context. However, the code is clearly part of the *Meson build system*. The Frida connection provides the *purpose* but the *mechanism* is Meson's configuration management.
* **Overlooking details:** I might initially miss the nuances of how subprojects are handled or the specifics of the different option types (`is_builtin`, `is_compiler`, etc.). Paying attention to the loops and conditional logic reveals these details.
* **Ambiguity:**  Some parts of the code (like the exact content of `coredata`) might be abstract. I need to focus on the *interactions* with these objects rather than trying to know their internal structure. The type hints (`T.Dict`, `coredata.KeyedOptionDictType`) are helpful here.

By following these steps, combining code analysis with an understanding of the domain (build systems, reverse engineering), and systematically addressing each part of the request, a comprehensive and accurate analysis can be achieved.
This Python code file, `mconf.py`, is part of the Meson build system, specifically within the Frida project's Python bindings setup. Its primary function is to provide a command-line interface for viewing and modifying the configuration options of a Meson project.

Here's a breakdown of its functionalities:

**1. Viewing Configuration Options:**

* **Listing Options:** The script can display all available configuration options for the project. This includes core Meson options, project-specific options, and options related to specific modules or subprojects.
* **Displaying Current and Default Values:** It shows the current value of each option and its default value (if the script is run against the source directory instead of a build directory).
* **Showing Possible Values:** For options with a limited set of choices (e.g., boolean, enumerated types), it displays the possible values.
* **Formatted Output:** The output is formatted in a user-friendly, aligned manner, making it easy to read the option names, values, choices, and descriptions.
* **Subproject Handling:** It can display options for the main project and its subprojects separately.

**2. Modifying Configuration Options:**

* **Setting Options via Command Line:** The script allows users to modify configuration options directly through command-line arguments (e.g., `--option_name=new_value`).
* **Clearing Cache:** It provides an option to clear the Meson's cached state, forcing it to re-evaluate dependencies and settings.
* **Saving Changes:** Modified options are saved to the build directory's configuration files.

**3. Introspection (Read-Only Mode):**

* **Default Values from Source:** When run against a source directory (instead of a build directory), it operates in introspection mode. In this mode, it reads the `meson.options` or `meson_options.txt` files and displays the default values of the project's options. It cannot modify options in this mode.

**Relationship to Reverse Engineering:**

Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. `mconf.py` plays a crucial role in setting up the Frida Python bindings and potentially the core Frida library itself. Here's how it relates to reverse engineering:

* **Customizing Frida's Build:**  Reverse engineers might need specific build configurations of Frida to suit their needs. For example:
    * **Enabling/Disabling Features:**  Frida has various features and modules. This script allows enabling or disabling them during the build process. For instance, a reverse engineer might disable certain network-related features if they are focusing on local process analysis.
    * **Setting Compiler Flags:**  Advanced users might want to tweak compiler flags for optimization or debugging purposes. This script indirectly influences this by setting build options that Meson then uses to invoke the compiler. For example, setting an option to include debug symbols (`-g`) in the Frida binaries.
    * **Specifying Dependencies:**  While typically handled automatically, in some advanced scenarios, a reverse engineer might need to specify specific versions or locations of dependencies.

**Example:**

Let's say a reverse engineer wants to build the Frida Python bindings with the QNX operating system API enabled and using OpenSSL for TLS:

1. **Navigate to the Frida Python build directory:**  The user would first need to be in a directory where Meson has been used to configure the build (the "build directory").
2. **Run `mesonconf` with specific options:**
   ```bash
   mesonconf -Dapis=qnx -Dssl=openssl
   ```
   Here, `-Dapis=qnx` sets the `apis` option to `qnx`, and `-Dssl=openssl` sets the `ssl` option to `openssl`. These are likely Frida-specific options defined in its `meson_options.txt` file.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

This script interacts with these low-level aspects indirectly through the Meson build system and the configuration options it manages:

* **Binary Bottom (Compilation):**
    * **Compiler Choice:**  Meson configuration can influence which compiler (e.g., GCC, Clang) is used to build the Frida binaries.
    * **Compiler Flags:** As mentioned earlier, build options set through `mesonconf` translate to compiler flags that affect the generated machine code.
    * **Linker Flags:** Similarly, it can influence linker flags, affecting how the final executables and libraries are linked.

* **Linux/Android Kernel:**
    * **System Dependencies:** Frida often relies on system libraries and headers. Configuration options might point to the location of these dependencies on Linux or Android systems.
    * **Kernel Features:** Some Frida features might require specific kernel capabilities. Build options could be used to conditionally enable or disable these features based on the target kernel.
    * **Android NDK/SDK:** When building Frida for Android, configuration options will point to the Android NDK (Native Development Kit) and SDK (Software Development Kit), which contain the tools and libraries needed to build native Android components.

* **Android Framework:**
    * **Framework APIs:**  Frida on Android often interacts with the Android framework. Build options might specify the target Android API level or enable/disable components that interact with specific framework services.

**Example:**

If building Frida for an Android device, the user might need to configure the path to the Android NDK:

```bash
mesonconf -Dandroid_ndk=/path/to/android-ndk
```

**Logical Reasoning and Assumptions:**

* **Assumption:** The script assumes that it is being run within a valid Meson project (either a build directory or a source directory containing a `meson.build` or `meson_options.txt` file).
* **Input:** The script takes the build directory as an argument (defaulting to the current directory). It also accepts command-line arguments to modify options.
* **Output:**
    * When viewing configuration: It prints a formatted table of options and their values to the console.
    * When modifying configuration: It writes changes to files within the build directory. The output to the console confirms the changes made.
    * When an error occurs (e.g., invalid build directory): It prints an error message.

**User and Programming Common Mistakes:**

* **Running `mesonconf` in the wrong directory:**  A common mistake is running the script in a directory that is neither a Meson build directory nor a source directory. This will result in a `ConfException`.
    ```
    # Incorrect: Running in a random directory
    cd /home/user/documents
    mesonconf build  # This will likely fail

    # Correct: Running in the build directory
    cd /path/to/frida-python/build
    mesonconf
    ```
* **Typing option names incorrectly:**  If a user types an option name wrong in the command line, the script might not recognize it or might create a new, unintended option (depending on Meson's behavior).
    ```bash
    # Incorrect: Typo in option name
    mesonconf -Dapiss=qnx  # Intended 'apis'
    ```
* **Providing invalid values for options:**  If an option expects a boolean value and the user provides a string, or if an option has a limited set of choices and the user provides an invalid choice, the script might throw an error or silently ignore the invalid value (depending on the option's definition).
    ```bash
    # Incorrect: Providing a string for a boolean option
    mesonconf -Denable_feature=maybe  # Assuming 'enable_feature' is a boolean
    ```
* **Trying to modify options when running against the source directory:**  Users might mistakenly try to set options when running `mesonconf` against the source directory. This will not work, as the script operates in read-only introspection mode in this case.

**User Operations to Reach Here (Debugging Clues):**

1. **Initial Project Setup:** The user likely started by downloading or cloning the Frida repository or a related project using Frida.
2. **Creating a Build Directory:**  They then created a separate build directory (it's good practice to keep build files separate from source files).
   ```bash
   mkdir build
   cd build
   ```
3. **Configuring the Build with Meson:**  The user executed the `meson` command to configure the build, pointing it to the source directory.
   ```bash
   meson ..
   ```
4. **Realizing the Need to Change Options:**  During or after the initial configuration, the user might realize they need to adjust some build settings (e.g., enable a specific feature, change the compiler).
5. **Invoking `mesonconf`:** To view or modify these options, the user would then run the `mesonconf` command, typically from within the build directory.
   ```bash
   mesonconf  # To view options
   mesonconf -Doption_name=new_value  # To modify an option
   ```
6. **Debugging:** If the build fails or doesn't behave as expected, the user might use `mesonconf` to inspect the current configuration and identify any incorrect settings.

In summary, `mconf.py` provides a vital interface for users to interact with the Meson build system in the context of the Frida project. It allows them to customize the build process, which is particularly relevant for reverse engineers who often require specific build configurations for their tasks.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/mconf.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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