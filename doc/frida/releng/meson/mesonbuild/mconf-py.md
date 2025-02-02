Response:
My thinking process for analyzing the `mconf.py` code goes like this:

1. **Understand the Purpose:** The filename `mconf.py` within the `frida/releng/meson/mesonbuild` path strongly suggests this is part of Meson's configuration system, likely for modifying build options. The presence of "frida" hints this is tailored for the Frida project's build process.

2. **Identify Key Classes and Functions:** I scan the code for prominent class and function definitions. The most important ones I spot immediately are:
    * `Conf`: This class likely handles the core configuration logic, loading, modifying, and displaying options.
    * `add_arguments`:  This clearly deals with parsing command-line arguments.
    * `stringify`:  A utility function for converting values to strings.
    * `ConfException`: A custom exception for configuration errors.
    * `run_impl` and `run`: These seem to be the entry points for executing the configuration logic.

3. **Analyze the `Conf` Class:** This is the heart of the code. I break down its `__init__` method:
    * **Initialization:** It initializes the build directory, handles cases where the build directory is also the source directory, and sets up variables for storing option information.
    * **Loading Existing Configuration:**  It checks for a `meson-private` directory, indicating an existing build. If found, it loads the build information, source directory, and core data (options). It also handles reloading options if the option files have changed. This immediately tells me it's dealing with persistent configuration.
    * **Handling Source-Only Runs:** If no `meson-private` is found but a `meson.build` exists, it performs introspection to get the default options. This signifies the ability to view default settings even without a configured build.
    * **Error Handling:** If neither is found, it raises a `ConfException`.

4. **Examine Other `Conf` Methods:** I go through the other methods in the `Conf` class:
    * `clear_cache`, `set_options`, `save`: These clearly handle modifying and persisting configuration.
    * `print_aligned`, `_add_line`, `add_option`, `add_title`, `add_section`, `print_options`: These are all related to displaying the configuration options in a user-friendly format. The use of `mlog` (likely Meson's logging module) confirms this. The `print_aligned` function's handling of terminal width is interesting.
    * `split_options_per_subproject`: This indicates support for projects with subprojects, a common practice in larger builds.
    * `print_conf`: This method orchestrates the printing of all configuration information, separating options by category (core, compiler, project, etc.).
    * `print_nondefault_buildtype_options`: This suggests a mechanism for highlighting options that deviate from the default values for the selected build type.

5. **Analyze `run_impl` and `run`:**
    * `run_impl`: This function instantiates the `Conf` class and handles the main logic: printing the configuration if no modifications are requested, applying command-line options, clearing the cache, and saving changes.
    * `run`: This is a thin wrapper that parses command-line arguments using `coredata.parse_cmd_line_options` and then calls `run_impl`.

6. **Connect to Frida and Reverse Engineering:**  At this stage, I start considering the "frida" context. Frida is a dynamic instrumentation toolkit used heavily in reverse engineering and security research. Knowing this helps interpret how this configuration tool fits into that context:
    * **Target Customization:**  The ability to configure build options is crucial for tailoring Frida's behavior for different target platforms (Android, iOS, Linux, etc.) and specific reverse engineering tasks. Options might control which features are included, how the agent is built, or debugging settings.
    * **Kernel and Framework Interaction:**  Since Frida often interacts deeply with the target system's kernel and frameworks, the configuration likely includes options related to these interactions. For example, options might specify kernel module loading, hooking mechanisms, or communication protocols.

7. **Address Specific Prompts:** Now I go through the specific questions in the prompt:
    * **Functions:** I list the functions I identified earlier and briefly describe their purpose.
    * **Reverse Engineering Relation:** I explicitly connect the configuration to Frida's use cases in reverse engineering, explaining how it allows users to customize Frida's behavior. I provide examples of potential relevant options.
    * **Binary, Linux, Android:** I consider options that would directly impact Frida's interaction with the underlying system. Examples include compiler flags, architecture settings, kernel module options, and Android-specific settings.
    * **Logic and Assumptions:** I look for conditional logic (like checking for `meson-private`) and make assumptions about input and output. For example, if a build directory is provided, it loads and displays options; if a source directory is provided, it shows defaults.
    * **User Errors:** I think about common mistakes a user might make, such as trying to modify options without being in a build directory. The code explicitly handles this with an exception.
    * **User Operation and Debugging:**  I trace the user's steps to reach this code, starting with running a Meson command (likely `meson configure`) and explain how this script is involved in displaying and modifying those configurations.

8. **Refine and Organize:** Finally, I structure my analysis clearly, using headings and bullet points to make it easy to read and understand. I ensure I've addressed all aspects of the prompt and provide concrete examples where necessary. I double-check my understanding of the code and its connection to Frida.
This Python code, located at `frida/releng/meson/mesonbuild/mconf.py`, is a module within the Meson build system specifically designed for configuring build options. Since it's part of Frida's build process, these options directly influence how Frida is built and behaves. Let's break down its functionalities and their relevance to different areas:

**Core Functionalities:**

1. **Loading and Displaying Build Options:**
   - It loads existing build configurations from a build directory (`meson-private`) or introspects default options from a source directory (`meson.build`).
   - It presents these options to the user in a formatted, readable way, including the option name, current/default value, possible values, and a description.
   - It categorizes options into sections like "Core options," "Compiler options," "Project options," and "Subproject options."

2. **Modifying Build Options:**
   - It allows users to change build options through command-line arguments.
   - It validates and sets these new option values.
   - It saves the updated configuration to the build directory.

3. **Cache Management:**
   - It provides a `--clearcache` option to clear cached state, which might be necessary when dependencies or build tools change.

4. **Subproject Handling:**
   - It correctly handles options for subprojects within a larger build, allowing configuration of individual components.

5. **Default Value Handling:**
   - It can display default option values if only the source directory is provided (without a prior configuration).

6. **Build Type Awareness:**
   - It can highlight options that have been explicitly set to a value different from the default value for the current build type (e.g., Debug, Release).

**Relationship to Reverse Engineering (with Frida Context):**

This module is directly related to reverse engineering because it configures *Frida*, a dynamic instrumentation toolkit heavily used in reverse engineering. The build options managed by this script determine:

* **Target Platforms:** Options might specify which operating systems and architectures Frida will be built for (e.g., Android, iOS, Linux, Windows, x86, ARM). This is crucial for targeting specific devices or software for reverse engineering.
* **Frida Components:** Options can control which components of Frida are included in the build. For instance, one might choose to include or exclude certain scripting language bindings or specific instrumentation modules.
* **Debugging and Development Settings:** Options could enable or disable debugging features within Frida itself, aiding in its development and troubleshooting.
* **Communication Protocols:** Options might define how the Frida client communicates with the agent running on the target process.
* **Code Optimization Levels:**  For release builds of Frida, optimization options would be set to maximize performance. For development or debugging builds, optimization might be disabled.

**Example:**

Imagine you want to build Frida specifically for an Android device with an ARM architecture. You might use command-line options like:

```bash
meson configure builddir -Dfrida_host_arch=x86_64 -Dfrida_target_arch=arm64 -Dbuildtype=release
```

This `mconf.py` script would process these options, setting `frida_host_arch` and `frida_target_arch` accordingly, ensuring that the resulting Frida binaries are built for the correct architecture.

**Involvement of Binary, Linux, Android Kernel & Framework Knowledge:**

This module indirectly relies on these concepts by managing options that directly impact how Frida interacts with these lower levels:

* **Binary Level:**
    * **Compiler Flags:** Options might control compiler flags (e.g., `-O2` for optimization, `-g` for debugging symbols) that directly affect the generated binary code of Frida.
    * **Architecture-Specific Code:** Options related to target architecture (ARM, x86) dictate which parts of Frida's architecture-specific code are compiled and included.

* **Linux Kernel:**
    * **Kernel Module Support:** Frida often uses kernel modules for advanced instrumentation. Build options could control whether to build and include these modules.
    * **System Call Interception:** Frida's ability to intercept system calls might be influenced by build options related to the underlying hooking mechanisms.

* **Android Kernel & Framework:**
    * **Android Specific Components:** Building Frida for Android requires specific components and libraries. Build options would manage the inclusion and configuration of these.
    * **SELinux/Security Context:** Options might be relevant to how Frida interacts with Android's security features like SELinux.
    * **ART (Android Runtime) Integration:** Frida's ability to instrument Android applications relies on interacting with the ART. Build options could affect how this integration is implemented.

**Example:**

An option like `-Dfrida_module_support=true` could enable the building of Frida's kernel module components on Linux. On Android, options might control how Frida injects into processes, potentially needing adjustments depending on the Android version and security policies.

**Logical Reasoning (Hypothetical Input & Output):**

**Assumption:** The user wants to see the current configuration of an existing Frida build in the `my_frida_build` directory.

**Input (Command):**

```bash
mesonconf my_frida_build
```

**Expected Output:**

The script would load the configuration from `my_frida_build/meson-private/coredata.dat` (or similar) and then print a formatted list of the current build options to the terminal. This output would resemble:

```
Core properties:
  Source dir /path/to/frida/source
  Build dir  /path/to/my_frida_build

Main project options:
------------------------------------------------------------------------------------------------------------------------------------
             Option             Current Value Possible Values
------------------------------- ------------- --------------- -----------------------------------------------------------------------
  frida:host_arch             x86_64        ['x86', 'x86_64', 'arm', 'arm64']
  frida:target_arch           arm64         ['x86', 'x86_64', 'arm', 'arm64']
  buildtype                   release       ['plain', 'debug', 'debugoptimized', 'release', 'minsize']
  ... more options ...
```

**User or Programming Common Usage Errors:**

1. **Running `mesonconf` in the Source Directory (Intended for Build Directory):**

   If a user runs `mesonconf` directly in the Frida source directory (where `meson.build` is located) without a prior build configuration, the script will detect this.

   **Example Command:**

   ```bash
   cd /path/to/frida/source
   mesonconf .
   ```

   **Outcome:** The script will enter the "introspection" mode and only display the *default* values of the options, not any previously set configurations. It will also likely print a warning:

   ```
   The source directory instead of the build directory was specified.
   Only the default values for the project are printed.
   ```

2. **Typos in Option Names:**

   If a user tries to set an option with a misspelled name on the command line:

   **Example Command:**

   ```bash
   meson configure builddir -Dfrida_targe_arch=arm64  # Typo: "targe" instead of "target"
   ```

   **Outcome:** The `mconf.py` script (or the underlying Meson framework) will likely raise an error indicating that the option is not recognized.

3. **Providing Invalid Values for Options:**

   If a user provides a value that is not within the allowed possible values for an option:

   **Example Command (assuming `frida_optimization_level` has limited choices):**

   ```bash
   meson configure builddir -Dfrida_optimization_level=super_high
   ```

   **Outcome:** The script will likely raise an error, stating that `super_high` is not a valid value for the `frida_optimization_level` option, and it might suggest the valid options.

**How User Operations Lead Here (Debugging Clues):**

A user typically interacts with `mconf.py` indirectly through the `meson` command-line tool. Here's a step-by-step process and how it might lead to this script:

1. **Initial Configuration:** The user starts by configuring the Frida build using the `meson configure` command, specifying a build directory:

   ```bash
   meson configure my_frida_build
   ```

   Internally, Meson parses the `meson.build` file, discovers the available options, and stores the initial configuration in the `my_frida_build` directory (specifically within `meson-private`).

2. **Viewing Configuration:** The user wants to see the current build options. They use the `mesonconf` command, providing the build directory:

   ```bash
   mesonconf my_frida_build
   ```

   This command directly invokes the `mconf.py` script. The script loads the configuration data from `my_frida_build`, formats it, and prints it to the terminal.

3. **Modifying Configuration:** The user decides to change a build option. They use `meson configure` again, this time with the `-D` flag to specify the option and its new value:

   ```bash
   meson configure my_frida_build -Dbuildtype=debug
   ```

   Although the primary entry point is `meson`, internally, Meson needs to update the configuration. While `mconf.py` isn't directly called for setting options *during the initial `meson configure`*, it plays a crucial role in *subsequent* configuration changes via `meson configure` and when explicitly invoked with `mesonconf`. Meson uses similar mechanisms to load and modify the configuration data as implemented in `mconf.py`.

4. **Troubleshooting:** If the build fails or behaves unexpectedly, a developer might use `mesonconf` to inspect the current option settings to identify any misconfigurations that could be causing the issue. This makes `mconf.py` a valuable tool in the debugging process.

In summary, `frida/releng/meson/mesonbuild/mconf.py` is a vital component of Frida's build system, responsible for managing and displaying build options. It directly influences how Frida is built and its capabilities, making it highly relevant to reverse engineering efforts. Understanding its functionality is crucial for anyone building or customizing Frida.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/mconf.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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