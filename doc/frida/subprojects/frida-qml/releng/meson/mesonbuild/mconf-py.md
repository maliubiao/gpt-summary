Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The immediate request is to analyze the `mconf.py` file and explain its functionality, especially concerning reverse engineering, low-level details, and common usage errors. The context provided ("fridaDynamic instrumentation tool") is crucial for framing the analysis.

2. **Identify Key Components:**  The first step in understanding a Python script is to look at the imports and the main classes and functions.

    * **Imports:**  These give hints about the script's dependencies and purposes. Keywords like `hashlib`, `shutil`, `os`, `textwrap` suggest file manipulation, terminal interaction, and string formatting. Imports from `.`, like `build`, `coredata`, `environment`, `mesonlib`, `mintro`, `ast`, `optinterpreter`, point to the Meson build system's internal structure.

    * **`add_arguments`:** This function suggests the script is designed to be run from the command line, taking arguments.

    * **`Conf` class:** This is likely the core logic of the script. The `__init__` method is a good starting point to understand its setup.

    * **`run_impl` and `run`:** These functions likely handle the execution flow of the script.

3. **Analyze the `Conf` Class:** This is the heart of the script.

    * **`__init__`:**  The initialization logic is crucial. It checks for existing Meson build directories (`meson-private`) or attempts to introspect a source directory. This duality is key to understanding the script's purpose: it can operate on existing build configurations *or* extract information from a source directory. The code dealing with `coredata.options_files` and `OptionInterpreter` suggests it manages build options.

    * **`clear_cache`, `set_options`, `save`:** These methods clearly relate to modifying and persisting build configuration.

    * **`print_aligned`, `_add_line`, `add_option`, `add_title`, `add_section`, `print_options`, `print_conf`:** This set of methods strongly suggests the script's primary function is to display configuration information in a formatted way. The use of `mlog` indicates interaction with Meson's logging system.

    * **`split_options_per_subproject`:** This suggests the script handles projects with subprojects and organizes options accordingly.

    * **`print_nondefault_buildtype_options`:** This indicates a feature to highlight deviations from default build type settings.

4. **Analyze `run_impl` and `run`:** These functions manage the command-line execution. `run` parses command-line arguments, and `run_impl` instantiates the `Conf` class and handles different execution paths (printing config vs. modifying it). The error handling (`try...except`) is also important to note.

5. **Connect to the Prompt's Questions:** Now, revisit the specific questions in the prompt and map the identified functionalities to them.

    * **Functionality:**  Summarize the key actions: loading/inspecting build configuration, displaying options, modifying options, clearing cache.

    * **Reverse Engineering:**  Consider how displaying configuration relates to reverse engineering. Frida is for dynamic instrumentation, and understanding build options can reveal how a target application was built, providing valuable context for instrumentation. Example: knowing if ASLR is enabled.

    * **Binary/Low-Level/Kernel/Framework:**  Look for clues in the code. The script *doesn't* directly interact with binaries, the kernel, or Android frameworks. Instead, it deals with the *build configuration* that *influences* these things. The connection is indirect. Explain this distinction carefully. Examples: compiler flags, architecture settings, dependency choices.

    * **Logic/Input/Output:** The logic is primarily about parsing and displaying data. Think about the inputs (build directory, command-line arguments) and the outputs (formatted configuration information). Hypothesize scenarios like an unconfigured build directory.

    * **User Errors:** Identify potential mistakes users could make. Examples: running in the wrong directory, trying to modify options in a source directory, providing invalid option values.

    * **User Journey/Debugging:** Describe the typical command a user would run to reach this code (`meson conf`). Explain how this script can be a debugging tool to understand the current or default configuration.

6. **Structure the Answer:** Organize the findings logically, addressing each point in the prompt. Use clear headings and bullet points for readability. Provide concrete examples to illustrate the connections to reverse engineering and low-level concepts.

7. **Refine and Review:**  Read through the analysis, ensuring it's accurate, comprehensive, and easy to understand. Check for any ambiguities or missing points. For instance, explicitly state that this script *doesn't* perform dynamic instrumentation itself, but aids in understanding the environment for tools like Frida. Ensure the examples are relevant to Frida's use cases.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the code structure.
* **Correction:** Shift focus to the *purpose* of the code and how it relates to the broader context of Meson and Frida.

* **Initial thought:** Assume direct interaction with binaries.
* **Correction:** Recognize that the script operates at the build configuration level, influencing the final binaries but not directly manipulating them.

* **Initial thought:**  Provide very technical explanations of each line of code.
* **Correction:**  Focus on the higher-level functionality and its implications, avoiding excessive low-level detail unless specifically relevant to the prompt's questions.

By following this process, moving from understanding the code's structure to its purpose and then connecting it back to the specific questions in the prompt, a comprehensive and accurate analysis can be achieved.
This Python script, `mconf.py`, is a part of the Meson build system and specifically functions as a **configuration tool** for Meson projects. It allows users to view and modify the build options of a project. Given its location within the Frida project's structure (`frida/subprojects/frida-qml/releng/meson/mesonbuild/mconf.py`), it's tailored for managing the configuration of the Frida QML subproject within the larger Frida ecosystem.

Here's a breakdown of its functionalities and how they relate to your questions:

**Functionalities of `mconf.py`:**

1. **Loading Build Configuration:**
   - It can load the existing build configuration from a Meson build directory. This includes options set during the initial `meson` command.
   - It can also operate on a source directory to display the default configuration options before a build directory is created.

2. **Displaying Configuration Options:**
   - It presents a formatted list of all available build options for the project and its subprojects.
   - For each option, it shows:
     - The option's name.
     - The current value (or default value if operating on a source directory).
     - The possible values the option can take.
     - A description of the option's purpose.
   - It categorizes options into sections like "Core options," "Compiler options," "Project options," etc., making it easier to navigate.

3. **Modifying Configuration Options:**
   - It allows users to set new values for build options via command-line arguments.
   - These changes are then saved to the build configuration.

4. **Clearing Cached State:**
   - The `--clearcache` option allows users to clear cached information, such as found dependencies. This can be useful when dependencies have been updated or if Meson is incorrectly detecting them.

5. **Handling Subproject Options:**
   - It correctly handles and displays options specific to subprojects within the main project.

6. **Displaying Non-Default Build Type Options:**
   - It highlights options whose values differ from the default values associated with the selected build type (e.g., `debug`, `release`).

**Relationship to Reverse Engineering:**

`mconf.py` indirectly aids reverse engineering efforts by providing insights into how the target software (in this case, aspects of Frida) was built. Understanding the build configuration can reveal crucial information about the target environment and potential security mitigations.

**Example:**

- **Hypothesis:** A reverse engineer suspects that Address Space Layout Randomization (ASLR) might be disabled in a particular Frida component.
- **Using `mconf.py`:**  They would navigate to the Frida QML build directory (or source directory) and run:
  ```bash
  python path/to/frida/subprojects/frida-qml/releng/meson/mesonbuild/mconf.py build  # Replace 'build' with the actual build directory name
  ```
- **Output:** The output would list various options. The reverse engineer would look for options related to security features, such as compiler flags or build-time settings that influence ASLR. For instance, they might find an option like:
  ```
  c_args            []                  Possible Values: ... Extra arguments passed to the C compiler.
  ```
- **Inference:** By examining the `c_args`, the reverse engineer might see if flags like `-fPIE -pie` (position-independent executable flags related to ASLR) are present or absent. Similarly, architecture-related options might reveal if 32-bit or 64-bit compilation affects ASLR defaults.

**Binary/Low-Level, Linux, Android Kernel, and Framework Knowledge:**

While `mconf.py` itself doesn't directly interact with the binary, kernel, or frameworks, the *options* it manages directly influence these aspects:

**Examples:**

- **Compiler Flags (`c_args`, `cpp_args`, `link_args`):** These options directly control how the C/C++ compiler and linker operate. They determine things like optimization levels (`-O0`, `-O2`, `-Os`), debugging information (`-g`), security features (`-fstack-protector-strong`), and architecture-specific settings (e.g., `-march=armv7-a` for ARM architecture). This directly impacts the generated binary code.

- **Build Type (`buildtype`):** Options like `debug`, `release`, `plain` affect compiler optimizations and the inclusion of debugging symbols, which are crucial for debugging and reverse engineering.

- **Default Library Type (`default_library`):**  This option determines whether shared libraries (`.so` on Linux/Android) or static libraries (`.a`) are built by default. This has implications for how the final application is linked and deployed.

- **Backend (`backend`):** While less directly low-level, the choice of build backend (like `ninja` or `make`) can influence the build process and the structure of the generated build files.

- **Machine Architecture (`host_machine`, `build_machine`):**  Cross-compilation settings managed by Meson affect the target architecture for which the binaries are being built (e.g., ARM, x86, x64). This is fundamental for understanding the binary's instruction set and execution environment.

- **Dependencies:** The options related to finding and using dependencies (like libraries) influence which external code is linked into the final binary. Understanding these dependencies is crucial for analyzing the software's functionality.

**Logic Inference (Hypothetical Input and Output):**

**Scenario:** User wants to enable a specific debugging feature in the Frida QML component. The option is named `enable_qml_debug`.

**Hypothetical Input:**

```bash
python path/to/frida/subprojects/frida-qml/releng/meson/mesonbuild/mconf.py build -Denable_qml_debug=true
```

**Hypothetical Output (Snippet showing the change):**

```
Project options:
  enable_qml_debug   false               Possible Values: [true, false]  Enable verbose debugging output for QML.
                                         => true
```

The tool would parse the command-line argument `-Denable_qml_debug=true`, update the corresponding option in the build configuration, and (if `print_conf` were called afterwards) display the updated value.

**User or Programming Common Usage Errors:**

1. **Running in the Wrong Directory:** A common error is running `mconf.py` outside of a valid Meson build directory or source directory.
   - **Error Message:**  `Directory <path> is neither a Meson build directory nor a project source directory.`

2. **Typos in Option Names:**  If the user types an option name incorrectly, the tool will not recognize it.
   - **No immediate error during modification:**  The tool might not throw an error when trying to *set* an invalid option via the command line, but the change won't be saved or reflected. It might show a warning in some cases, but it depends on Meson's option parsing logic.

3. **Providing Invalid Values:**  Users might provide a value that is not in the list of possible values for an option.
   - **Error Message:** Meson will typically raise an error when it tries to validate the option value during the configuration or build process, not necessarily directly in `mconf.py`. The error might look like: `meson.build:xx: error: Option '<option_name>' must be one of <possible_values> but is '<provided_value>'.`

4. **Trying to Modify Options in a Source Directory:** If the user runs `mconf.py` on a source directory and tries to modify options, the changes won't be persisted because there's no build configuration to modify yet.
   - **Warning Message (likely):** The script might print a warning like "The source directory instead of the build directory was specified. Only the default values for the project are printed." and the modification will be ignored.

**User Operation Steps to Reach `mconf.py` as a Debugging Clue:**

1. **Initial `meson` Configuration:** A user starts by configuring a Frida QML build:
   ```bash
   meson setup build_frida_qml path/to/frida/subprojects/frida-qml
   cd build_frida_qml
   ```

2. **Realizing the Need to Change Options:**  During development, debugging, or when adapting Frida QML, the user might need to adjust build options. For example, they might want to enable more verbose logging or disable certain optimizations.

3. **Discovering `mconf.py`:**  The user might find information about `mconf.py` in Meson's documentation or by exploring the `mesonbuild` directory within the Frida source tree.

4. **Running `mconf.py` to View Options:** To see the current configuration, the user executes:
   ```bash
   python path/to/frida/subprojects/frida-qml/releng/meson/mesonbuild/mconf.py .
   ```
   (Assuming they are in the `build_frida_qml` directory, `.` refers to the current directory which is the build directory).

5. **Running `mconf.py` to Modify Options:** To change an option, the user uses the `-D` flag:
   ```bash
   python path/to/frida/subprojects/frida-qml/releng/meson/mesonbuild/mconf.py . -Denable_qml_debug=true
   ```

6. **Re-running `mconf.py` to Verify:** The user might run the view command again to confirm the option has been changed.

7. **Subsequent Build:** After modifying the options, the user typically needs to rebuild the project for the changes to take effect:
   ```bash
   ninja
   ```

By examining the use of `mconf.py` and the options being toggled, a debugger or reverse engineer can understand how the software was configured, which can be a critical piece of information for troubleshooting or analysis. For instance, if a bug only appears when a specific optimization is enabled, the use of `mconf.py` to set that optimization level becomes a relevant debugging clue.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/mconf.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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