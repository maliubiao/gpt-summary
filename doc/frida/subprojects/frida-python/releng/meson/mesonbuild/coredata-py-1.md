Response:
Let's break down the thought process for summarizing the functionality of the `coredata.py` file.

1. **Understand the Goal:** The primary goal is to describe what this Python file *does* within the Frida project. The prompt specifically asks for functionalities, relationships to reverse engineering, low-level concepts, logic, potential errors, user interaction, and finally a summary.

2. **Initial Scan and Keywords:**  Read through the code, looking for prominent class and function names. Keywords like `Options`, `BuiltinOption`, `UserOption`, `set_option`, `get_option`, `parse`, `load`, `save`, `buildtype`, `prefix`, `cross_file`, `native_file`, `compiler`, `linker` immediately jump out. These give a high-level idea that the file manages configuration settings.

3. **Identify Core Responsibilities:** Based on the keywords and initial scan, the central theme seems to be *managing and persisting build configuration options*. This involves:
    * Defining available options (built-in and project-specific).
    * Storing the values of these options.
    * Reading and writing these options to/from files.
    * Providing mechanisms to set and retrieve option values.
    * Handling different types of options (string, boolean, integer, combo, feature).

4. **Analyze Key Classes:** Focus on the main classes:
    * `CoreData`: This seems to be the central data structure holding all the configuration information. It contains the `options` dictionary.
    * `BuiltinOption`:  Defines the structure of pre-defined, core Meson options.
    * `UserOption` (and its subclasses like `UserStringOption`, `UserBooleanOption`, etc.): Represents user-configurable options.
    * `OptionKey`:  A way to uniquely identify options (considering subprojects and machine types).
    * `CmdLineFileParser`:  Handles reading options from command-line argument files.
    * `MachineFileParser`: Handles reading options from machine description files (used for cross-compilation).

5. **Trace Data Flow:** Follow how options are handled:
    * **Definition:** `BUILTIN_OPTIONS`, `BUILTIN_OPTIONS_PER_MACHINE` define the built-in options. Project options are likely defined elsewhere and integrated.
    * **Initialization:**  `add_builtin_option` adds built-in options to the `CoreData`.
    * **Setting:** `set_option` handles setting option values, including validation, deprecation warnings, and handling dependencies (like `buildtype` affecting `optimization` and `debug`).
    * **Getting:** `get_option` retrieves option values.
    * **Persistence:** `save` and `load` handle saving and loading the `CoreData` to a file.
    * **Command-line Input:** `parse_cmd_line_options`, `read_cmd_line_file` process options from the command line and files.
    * **Machine Files:** `parse_machine_files` processes cross-compilation settings.

6. **Identify Connections to Reverse Engineering, Low-Level Details, and Logic:**
    * **Reverse Engineering:**  Frida is a dynamic instrumentation tool used for reverse engineering. The configuration options managed by this file directly influence how Frida is built and potentially how it interacts with target processes. Options related to debugging symbols (`debug`), optimization levels (`optimization`), and potentially compiler/linker flags directly impact the resulting Frida binaries, which is relevant to reverse engineering efforts. Cross-compilation (`cross_file`) is also a key aspect in targeting different architectures, crucial for reverse engineering on various platforms.
    * **Low-Level:** The code interacts with the file system (`os.path`), uses pickling for serialization (`pickle`), and mentions linker processes. The concept of "host" and "build" machines is relevant to cross-compilation, a lower-level build system concern.
    * **Logic:**  The `set_option` function contains conditional logic to handle deprecation, replacement of options, and the interplay between `buildtype`, `optimization`, and `debug`. The handling of subproject options and machine-specific options involves logical checks.

7. **Consider User Interaction and Errors:**
    * **User Interaction:** Users interact with these settings through command-line arguments (`-D`), cross/native files, and potentially through IDEs that integrate with Meson.
    * **Errors:**  The code explicitly raises `MesonException` for unknown options, trying to modify read-only options, and malformed machine files. Deprecation warnings are also a form of user feedback.

8. **Construct Examples:**  Based on the understanding of the code, create concrete examples for each aspect requested in the prompt. Think of common scenarios a user might encounter (setting a build type, using a cross-file, making a typo in an option name).

9. **Synthesize the Summary:**  Combine the key responsibilities identified earlier into a concise summary. Focus on the "what" and "why" of the file.

10. **Review and Refine:**  Read through the summary and examples to ensure they are accurate, clear, and address all aspects of the prompt. Check for any inconsistencies or areas that need further clarification. For instance, initially, I might have just said "manages options," but refining it to "manages and *persists* build configuration options" adds more detail.

This iterative process of scanning, analyzing, tracing, identifying connections, considering user interaction, and synthesizing allows for a comprehensive understanding and summarization of the code's functionality.
This is the second part of the analysis of the `coredata.py` file in the Frida project. Building on the previous analysis, we will continue exploring its functionalities.

Here's a breakdown of the remaining functions and their purpose:

**Functionalities:**

* **`add_compiler_options(self, options: MutableKeyedOptionDictType, lang: str, for_machine: MachineChoice, env: Environment, subproject: str) -> None`:**
    * **Purpose:** Adds compiler-specific options to the `CoreData`. It merges options defined by the compiler with those already present in the environment's options, prioritizing environment settings. It handles both top-level project options and subproject-specific compiler options.
    * **Logic:**
        * Iterates through the compiler's options.
        * Checks if the option is already in the environment's options. If so, it sets the compiler option's value to the environment's value.
        * Stores the compiler option in `self.options`.
        * If it's a subproject, it also checks for subproject-specific compiler options in the environment and updates accordingly.

* **`add_lang_args(self, lang: str, comp: T.Type['Compiler'], for_machine: MachineChoice, env: 'Environment') -> None`:**
    * **Purpose:** Adds global language-specific arguments to the `CoreData`. These are arguments that need to be available even before the compiler is fully detected.
    * **Relationship to Compiler/Linker:** This function interacts directly with the `Compiler` class to retrieve these global arguments. These arguments are likely fundamental compiler or linker flags required for basic functionality.
    * **Binary Underlying/Linux/Android Kernel/Framework:**  These arguments could include paths to standard libraries, system headers, or flags that influence how the compiler interacts with the operating system or target architecture.
    * **Logic:**  It calls a static method `get_global_options` on the `Compiler` class to retrieve these arguments and directly updates the `self.options` dictionary.

* **`process_compiler_options(self, lang: str, comp: Compiler, env: Environment, subproject: str) -> None`:**
    * **Purpose:** Orchestrates the process of adding and configuring compiler options, including base options.
    * **Logic:**
        * Calls `add_compiler_options` to add the compiler's specific options.
        * Iterates through the compiler's `base_options` (common options like optimization level, debug flags).
        * Prioritizes options set in the environment (both top-level and subproject-specific).
        * If a base option is not already in `self.options`, it creates a copy from the compiler's default base options.
        * Calls `emit_base_options_warnings` to check for potential conflicts or issues related to base options.

* **`emit_base_options_warnings(self, enabled_opts: T.List[OptionKey]) -> None`:**
    * **Purpose:** Issues warnings related to certain base options that might have compatibility issues.
    * **Example:**  It specifically checks if bitcode is enabled (`b_bitcode`) and warns about potential linker incompatibility issues.
    * **User/Programming Common Errors:** Users might enable options like bitcode without realizing the potential downsides with other linker options. This function proactively warns them.

* **`class CmdLineFileParser(configparser.ConfigParser)`:**
    * **Purpose:** A custom parser for reading command-line options from a file. It inherits from `configparser.ConfigParser` but overrides some default behaviors.
    * **Logic:**
        * It doesn't treat `:` as a key delimiter, allowing for options like "subproject:option=value".
        * It preserves the case of option names (doesn't automatically convert to lowercase).

* **`class MachineFileParser()`:**
    * **Purpose:** Parses machine description files, which are used for cross-compilation to define settings for the target machine.
    * **Relationship to Reverse Engineering:** Machine files are crucial for cross-compiling Frida to target architectures like ARM (commonly used in Android and iOS devices), which is essential for reverse engineering on those platforms.
    * **Binary Underlying/Linux/Android Kernel/Framework:** These files define aspects like the target architecture, operating system, compiler paths, and linker flags, which are all deeply tied to the underlying binary format and the target OS.
    * **Logic:**
        * Reads the file content and performs basic string substitutions (`@GLOBAL_SOURCE_ROOT@`, `@DIRNAME@`).
        * Parses a `[constants]` section first to define variables that can be used in other sections.
        * Parses other sections, evaluating expressions and assigning values to variables.
        * Supports basic arithmetic and string/list concatenation in the configuration values.
        * Handles errors in the file format.

    **Example of Logic:**
    * **Hypothetical Input (Machine File):**
      ```
      [constants]
      target_arch = arm64
      cc = /opt/toolchain/bin/aarch64-linux-gnu-gcc

      [binaries]
      c_compiler = @cc@
      ```
    * **Output (Parsed Data):**
      ```python
      {
          'binaries': {
              'c_compiler': '/opt/toolchain/bin/aarch64-linux-gnu-gcc'
          },
          'constants': {
              'target_arch': 'arm64',
              'cc': '/opt/toolchain/bin/aarch64-linux-gnu-gcc'
          }
      }
      ```

* **`parse_machine_files(filenames: T.List[str], sourcedir: str)`:**
    * **Purpose:** A helper function to create and use the `MachineFileParser`.

* **`get_cmd_line_file(build_dir: str) -> str`:**
    * **Purpose:** Constructs the path to the command-line options file.

* **`read_cmd_line_file(build_dir: str, options: SharedCMDOptions) -> None`:**
    * **Purpose:** Reads command-line options from a file and merges them with the currently parsed options.
    * **User Operation:** When Meson is run, it might save the command-line options used in a previous configuration to this file. Subsequent runs can then load these options, allowing users to reconfigure with the same settings.
    * **Debugging Clue:** If a build is behaving unexpectedly, checking this file can reveal if some options were unintentionally persisted from a previous configuration.

* **`write_cmd_line_file(build_dir: str, options: SharedCMDOptions) -> None`:**
    * **Purpose:** Writes the current command-line options to a file.

* **`update_cmd_line_file(build_dir: str, options: SharedCMDOptions) -> None`:**
    * **Purpose:** Updates the existing command-line options file with new options.

* **`format_cmd_line_options(options: SharedCMDOptions) -> str`:**
    * **Purpose:** Formats the command-line options into a string suitable for displaying or logging.

* **`major_versions_differ(v1: str, v2: str) -> bool`:**
    * **Purpose:** Checks if two version strings have different major versions. This is used to detect potential incompatibility issues between different Meson versions.

* **`load(build_dir: str, suggest_reconfigure: bool = True) -> CoreData`:**
    * **Purpose:** Loads the persisted `CoreData` object from a file in the build directory using `pickle`.
    * **User Operation:** When re-running Meson in an existing build directory, it loads the previous configuration from this file.
    * **Debugging Clue:** If configuration seems corrupted, checking if the `coredata.dat` file exists and its contents can be a debugging step.

* **`save(obj: CoreData, build_dir: str) -> str`:**
    * **Purpose:** Saves the current `CoreData` object to a file in the build directory using `pickle`. It also handles creating backups to prevent data loss in case of errors.
    * **Logic:** It checks for major version differences to prevent loading incompatible configurations.

* **`register_builtin_arguments(parser: argparse.ArgumentParser) -> None`:**
    * **Purpose:** Registers the built-in Meson options with the `argparse` module, allowing them to be used as command-line arguments.
    * **User Operation:** This is how users can specify built-in options like `--prefix`, `--buildtype`, etc., when running Meson.

* **`create_options_dict(options: T.List[str], subproject: str = '') -> T.Dict[OptionKey, str]`:**
    * **Purpose:** Parses a list of strings in the format "option=value" into a dictionary of `OptionKey` to value.

* **`parse_cmd_line_options(args: SharedCMDOptions) -> None`:**
    * **Purpose:** Parses the command-line options provided by the user and populates the `SharedCMDOptions` object.
    * **User Operation:** This function processes the `-D` arguments and dedicated options like `--cross-file` passed to the Meson command.
    * **User/Programming Common Errors:** It checks for conflicts between using `-D` and the dedicated command-line arguments for the same built-in option.

* **`class BuiltinOption(T.Generic[_T, _U])`:**
    * **Purpose:** Represents a built-in Meson configuration option. It defines the type of the option, its description, default value, possible choices, and whether it's read-only.
    * **Logic:** It provides methods for initializing the actual option object (`init_option`), adding it to `argparse` (`add_to_argparse`), and determining its default value.

**归纳一下它的功能 (Summary of its functionality):**

This part of `coredata.py` focuses on the **management and persistence of build configuration options**, particularly those related to **compilers, language settings, and cross-compilation**. It defines how compiler-specific options are added and merged with global settings, handles language-specific arguments, and provides mechanisms for parsing and storing options from command-line files and machine description files. It also includes functionality for warning users about potential issues with certain option combinations and manages the saving and loading of the entire configuration state to disk. This ensures that Meson can remember and reuse configurations across multiple invocations. Crucially, it bridges the gap between user-provided input (command-line arguments, machine files) and the internal representation of build settings within Meson.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/coredata.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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