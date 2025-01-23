Response:
The user wants a summary of the functionalities in the provided Python code snippet, focusing on aspects related to reverse engineering, binary manipulation, Linux/Android kernel and framework knowledge, logical inferences, potential user errors, and debugging.

**Plan:**

1. **High-level Overview:** Briefly describe the general purpose of the code.
2. **Function-by-function Analysis:**  Iterate through the defined functions, explaining their purpose and highlighting relevant connections to the requested areas.
3. **Reverse Engineering Connections:** Identify functions or code patterns that could be used or are related to reverse engineering tasks.
4. **Binary/Kernel/Framework Aspects:** Point out any functions that interact with low-level binary data, operating system features (especially Linux and potentially Android), or system frameworks.
5. **Logical Inferences:** Analyze functions that perform conditional logic or data manipulation based on assumptions or rules. Provide example inputs and outputs if applicable.
6. **User Error Examples:**  Identify scenarios where incorrect usage or input could lead to errors.
7. **Debugging Clues:** Explain how a user might reach this code during a debugging session in Frida.
8. **Overall Summary:**  Provide a concise summary of the code's primary functions.

**Detailed Function Analysis (and connections):**

*   `get_version_from_string(text: str) -> str`:  Likely used to extract version information from strings. *No direct reverse engineering, binary, kernel, or framework connection.*  *Logical inference: Input is a string, output is a version string or 'unknown version'.* *User error: Providing a string without version information.* *Debugging: Might be reached when Frida tries to determine the version of a target application or library.*
*   `default_libdir() -> str`, `default_libexecdir() -> str`, etc.: These functions determine default directory paths based on the operating system. *OS-specific (Linux, Windows, macOS, Haiku, etc.).* *Logical inference: Based on OS detection functions (e.g., `is_debianlike()`), returns different paths.* *User error: Incorrect OS detection.* *Debugging:  Might be called during Frida's initialization to locate libraries and executables.*
*   `has_path_sep(name: str, sep: str = '/\\') -> bool`: Checks for path separators. *Generic utility function.* *Logical inference: Returns `True` if a separator is found, `False` otherwise.* *User error: Providing a path with an unexpected separator.* *Debugging: Could be used in path validation logic.*
*   `quote_arg(arg: str) -> str`, `split_args(cmd: str) -> T.List[str]`, `join_args(args: T.Iterable[str]) -> str`:  Functions for handling command-line arguments, with platform-specific implementations (Windows vs. others). *OS-specific (Windows).* *Logical inference:  `quote_arg` adds quotes if needed, `split_args` splits a command line into arguments, `join_args` combines arguments into a string.* *User error: Providing incorrectly formatted command-line arguments.* *Debugging: Used when Frida executes external commands.*
*   `do_replacement(regex: T.Pattern[str], line: str, variable_format: Literal['meson', 'cmake', 'cmake@'], confdata: T.Union[T.Dict[str, T.Tuple[str, T.Optional[str]]], 'ConfigurationData']) -> T.Tuple[str, T.Set[str]]`:  Performs string substitution based on regular expressions and configuration data. *Potentially relevant to reverse engineering if used to modify code or data strings.* *Logical inference:  Replaces placeholders in a string with values from `confdata`.* *User error: Incorrect regular expressions or missing variables in `confdata`.* *Debugging:  Part of the configuration file processing logic.*
*   `do_define(regex: T.Pattern[str], line: str, confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], subproject: T.Optional[SubProject] = None) -> str`:  Handles `#define` directives in configuration files. *Could be relevant if configuration influences how Frida interacts with target processes.* *Logical inference: Based on the value in `confdata`, generates `#define` or `#undef` statements.* *User error:  Incorrectly formatted `#define` directives or missing configuration values.* *Debugging:  Part of the configuration file processing.*
*   `get_variable_regex(variable_format: Literal['meson', 'cmake', 'cmake@'] = 'meson') -> T.Pattern[str]`: Returns a regular expression for finding variables in configuration files. *Related to the above two functions.* *Logical inference: Returns different regex patterns based on the `variable_format`.*
*   `do_conf_str(src: str, data: T.List[str], confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], subproject: T.Optional[SubProject] = None) -> T.Tuple[T.List[str], T.Set[str], bool]`: Processes a list of strings (representing a configuration file) and performs substitutions and `#define` handling. *Core configuration processing logic.* *Logical inference:  Combines `do_replacement` and `do_define`.* *User error:  Mix of Meson and CMake syntax in the same file.* *Debugging:  Called when processing configuration files.*
*   `do_conf_file(src: str, dst: str, confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], encoding: str = 'utf-8', subproject: T.Optional[SubProject] = None) -> T.Tuple[T.Set[str], bool]`: Reads a configuration file, processes it, and writes the output to a destination file. *File I/O and configuration processing.* *User error:  File not found or write permissions issues.* *Debugging:  Called when processing configuration files.*
*   `dump_conf_header(ofilename: str, cdata: ConfigurationData, output_format: Literal['c', 'nasm', 'json'], macro_name: T.Optional[str]) -> None`, `_dump_c_header(...)`: Writes configuration data to a header file (C, NASM, or JSON). *Relevant if Frida's behavior is configured through header files.* *Binary relevance for NASM output.* *Logical inference: Formats the output based on `output_format`.* *User error:  Invalid `output_format`.* *Debugging:  Used to generate configuration header files.*
*   `replace_if_different(dst: str, dst_tmp: str) -> None`:  Replaces a file only if the contents have changed. *Optimization to avoid unnecessary rebuilds.* *No direct reverse engineering, binary, kernel, or framework connection.*
*   `listify(item: T.Any, flatten: bool = True) -> T.List[T.Any]`, `listify_array_value(...)`, `extract_as_list(...)`, `typeslistify(...)`, `stringlistify(...)`:  Utility functions for handling and converting data into lists with type checking. *Generic utility functions.*
*   `expand_arguments(args: T.Iterable[str]) -> T.Optional[T.List[str]]`: Expands command-line arguments from files (starting with `@`). *Useful for handling large command lines.* *User error:  Specifying a non-existent argument file.* *Debugging:  Used when Frida executes commands with argument files.*
*   `partition(...)`:  Splits an iterable based on a predicate. *Generic utility function.*
*   `Popen_safe(...)`, `Popen_safe_legacy(...)`, `Popen_safe_logged(...)`:  Wrappers around `subprocess.Popen` for executing external commands safely and logging. *Crucial for interacting with other tools and processes.* *OS interaction.* *Potential reverse engineering use if Frida interacts with debuggers or other analysis tools.* *User error:  Incorrect command-line arguments or missing executables.* *Debugging:  Central to Frida's interaction with external programs.*
*   `iter_regexin_iter(...)`: Searches for regex matches in a list of strings. *Generic utility function.*
*   `_substitute_values_check_errors(...)`, `substitute_values(...)`:  Functions for substituting template values in commands. *Core logic for dynamic command generation.* *Reverse engineering relevance if modifying or inspecting commands.* *User error:  Incorrect template usage.* *Debugging:  Used when constructing commands to execute.*
*   `get_filenames_templates_dict(...)`: Creates a dictionary of template values based on input and output file names. *Used in conjunction with `substitute_values`.*
*   `_make_tree_writable(...)`, `windows_proof_rmtree(...)`, `windows_proof_rm(...)`, `TemporaryDirectoryWinProof`: Functions for robust file and directory removal, especially on Windows. *OS-specific (Windows).* *Handles potential file locking issues.*
*   `detect_subprojects(...)`:  Detects subprojects based on directory structure. *Build system related.*


This Python code file, `universal.py`, from the Frida project, provides a collection of utility functions designed to handle various cross-platform tasks and data manipulations necessary for the build and execution of Frida. Here's a breakdown of its functionality:

**Core Functionalities:**

*   **Operating System Detection and Path Handling:**  It includes functions like `is_windows()`, `is_linux()`, `is_debianlike()`, etc., to determine the current operating system. Based on this, it provides functions like `default_libdir()`, `default_libexecdir()`, `default_prefix()`, etc., to determine platform-specific default directory paths for libraries, executables, and other resources.
*   **Version String Extraction:** The `get_version_from_string()` function attempts to extract version numbers from text strings using regular expressions.
*   **Command-Line Argument Handling:**  It provides functions (`quote_arg()`, `split_args()`, `join_args()`) for properly quoting and splitting command-line arguments, with specific handling for Windows due to its different command-line parsing rules.
*   **Configuration File Processing:** A significant portion of the code deals with processing configuration files. This includes:
    *   **Template Substitution:**  The `do_replacement()` function substitutes variables (in the format `@variable@` or `${variable}`) within a string based on a provided dictionary of configuration data.
    *   **`#define` Directive Handling:** The `do_define()` function processes `#mesondefine` or `#cmakedefine` directives in configuration files, generating corresponding C preprocessor definitions based on the configuration data.
    *   **Combined Processing:** The `do_conf_str()` and `do_conf_file()` functions read configuration file content (either as a string or from a file), perform variable substitutions and `#define` processing, and write the result to a new file.
    *   **Header File Generation:** The `dump_conf_header()` and `_dump_c_header()` functions generate C, NASM, or JSON header files containing the configuration data as preprocessor macros or JSON objects.
*   **File System Operations:** It includes functions like `replace_if_different()` to efficiently update files only if their content has changed, and platform-aware functions for robustly removing files and directories (`windows_proof_rmtree()`, `windows_proof_rm()`) to handle potential locking issues on Windows.
*   **List Manipulation:** Several utility functions (`listify()`, `listify_array_value()`, `extract_as_list()`, `typeslistify()`, `stringlistify()`) are provided for converting various data types into lists and ensuring type consistency.
*   **External Process Execution:** The `Popen_safe()`, `Popen_safe_legacy()`, and `Popen_safe_logged()` functions provide wrappers around `subprocess.Popen` for executing external commands. These wrappers handle encoding issues and provide logging of the executed commands and their output.
*   **Template-Based Command Generation:** The `substitute_values()` and `get_filenames_templates_dict()` functions work together to dynamically generate command-line arguments by substituting template strings (like `@INPUT@`, `@OUTPUT@`, `@BASENAME@`) with actual file paths and other derived values.
*   **Subproject Detection:** The `detect_subprojects()` function helps in identifying subdirectories that represent subprojects within the Frida build system.

**Relationship to Reverse Engineering:**

Several functionalities in this file have indirect but important connections to reverse engineering:

*   **Configuration:** The configuration file processing capabilities are crucial for setting up Frida's behavior and how it interacts with target processes during instrumentation. Reverse engineers might need to understand or modify these configurations.
    *   **Example:**  A configuration file might specify the location of certain libraries or the behavior of specific Frida modules. Understanding how these configurations are processed is important for customizing Frida's behavior for reverse engineering tasks.
*   **External Process Execution:** Frida often relies on external tools (like debuggers or other analysis tools) during its operation. The `Popen_safe()` family of functions facilitates this interaction.
    *   **Example:**  Frida might launch a debugger to attach to a process or execute a disassembler to analyze code. Understanding how Frida executes these external tools can be relevant for advanced reverse engineering workflows.
*   **Template-Based Command Generation:**  When interacting with external tools, Frida uses template substitution to generate the correct command-line arguments based on the target process and files. This mechanism is essential for automating reverse engineering tasks.
    *   **Example:**  When using Frida to dump memory, the output file name might be dynamically generated using templates like `@OUTPUT@`.

**Involvement of Binary, Linux, Android Kernel, and Framework Knowledge:**

*   **Binary:**
    *   The NASM header generation (`dump_conf_header()` with `output_format='nasm'`) directly deals with binary-level assembly language configuration.
    *   When Frida interacts with external tools (using `Popen_safe()`), these tools might operate on binary files.
*   **Linux:**
    *   The OS detection and default path functions (`default_libdir()`, etc.) have specific logic for Linux distributions (e.g., Debian-like systems checking for multiarch paths).
    *   Interactions with external commands on Linux are handled by `Popen_safe()`.
*   **Android Kernel and Framework (Indirect):**
    *   While not explicitly manipulating kernel code in this file, Frida often targets Android applications. The configuration and external process execution mechanisms are used to interact with the Android environment.
    *   The ability to determine default library paths is relevant for finding shared libraries in the Android framework.

**Logical Inferences (Hypothetical):**

*   **`get_version_from_string()`:**
    *   **Input:** `"Some software version 1.23.45-beta"`
    *   **Output:** `"1.23.45-beta"`
    *   **Input:** `"This has no version"`
    *   **Output:** `"unknown version"`
*   **`default_libdir()` (on a Debian-based Linux system):**
    *   **Assumption:** `dpkg-architecture -qDEB_HOST_MULTIARCH` returns `arm-linux-gnueabihf`
    *   **Output:** `"lib/arm-linux-gnueabihf"`
*   **`has_path_sep()`:**
    *   **Input:** `"path/to/file"`, `"/"`
    *   **Output:** `True`
    *   **Input:** `"path\\to\\file"`, `"/"`
    *   **Output:** `False`
    *   **Input:** `"path\\to\\file"`, `"\\"`
    *   **Output:** `True`

**User or Programming Common Usage Errors:**

*   **Incorrect Configuration Syntax:** Providing malformed `#mesondefine` or `#cmakedefine` lines in configuration files will raise a `MesonException`.
    *   **Example:** `#mesondefine MY_VAR` (missing the value).
*   **Missing Configuration Variables:**  If a template variable is used in a configuration file but not defined in the `confdata`, the `do_replacement()` function will add it to the `missing_variables` set. This might lead to unexpected behavior or incomplete configuration.
*   **Mixing Configuration Formats:**  Using `#mesondefine` in a file intended for CMake processing (or vice-versa) will result in an error.
*   **Incorrect Command-Line Argument Quoting:**  Manually constructing command lines passed to `Popen_safe()` with incorrect quoting can lead to the external command failing. The `quote_arg()` function is designed to prevent this.
*   **Specifying Non-Existent Files in Templates:** If a template like `@INPUT@` refers to a file that doesn't exist, the external command might fail.
*   **File Permission Errors:** When processing or generating configuration files, insufficient file permissions can lead to `MesonException` during file read or write operations.

**User Operation Steps to Reach Here (Debugging Clues):**

A user would likely interact with this code indirectly through Frida's build system or when Frida is executing and processing configuration files. Here are some scenarios:

1. **Building Frida from Source:** When building Frida using Meson, the build system will process various configuration files (`.ini`, `.cmake`, etc.). The functions in this file, especially those related to configuration processing (`do_conf_file()`, `dump_conf_header()`), will be called to generate necessary header files and configuration settings for Frida's components.
2. **Frida Agent or Tool Execution:**  When a Frida agent or tool is executed, it might rely on configuration files to determine its behavior or the location of necessary resources. The functions in this file will be involved in reading and processing these configuration files.
3. **Using Frida's CLI Tools:** If a Frida CLI tool needs to execute external commands (e.g., interacting with debuggers), the `Popen_safe()` family of functions and the template substitution mechanisms will be used to construct and execute those commands.
4. **Developing Frida Modules or Bindings:**  Developers working on Frida modules or language bindings might encounter this code if they need to generate configuration files or interact with external processes as part of their module's functionality.

**Summary of Functionality:**

In essence, `universal.py` in Frida provides a foundational set of platform-aware utility functions for:

*   **System interaction:** Detecting the OS, handling paths, executing external commands.
*   **Configuration management:** Reading, processing, and generating configuration files.
*   **Data manipulation:** Handling lists, strings, and command-line arguments.

These functionalities are crucial for ensuring Frida can be built and run reliably across different operating systems and for managing its internal configuration and interactions with external tools.

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
n that happens, it can be
    # considered an achievement in itself.
    #
    # This regex is reaching magic levels. If it ever needs
    # to be updated, do not complexify but convert to something
    # saner instead.
    # We'll demystify it a bit with a verbose definition.
    version_regex = re.compile(r"""
    (?<!                # Zero-width negative lookbehind assertion
        (
            \d          # One digit
            | \.        # Or one period
        )               # One occurrence
    )
    # Following pattern must not follow a digit or period
    (
        \d{1,2}         # One or two digits
        (
            \.\d+       # Period and one or more digits
        )+              # One or more occurrences
        (
            -[a-zA-Z0-9]+   # Hyphen and one or more alphanumeric
        )?              # Zero or one occurrence
    )                   # One occurrence
    """, re.VERBOSE)
    match = version_regex.search(text)
    if match:
        return match.group(0)

    # try a simpler regex that has like "blah 2020.01.100 foo" or "blah 2020.01 foo"
    version_regex = re.compile(r"(\d{1,4}\.\d{1,4}\.?\d{0,4})")
    match = version_regex.search(text)
    if match:
        return match.group(0)

    return 'unknown version'


def default_libdir() -> str:
    if is_debianlike():
        try:
            pc = subprocess.Popen(['dpkg-architecture', '-qDEB_HOST_MULTIARCH'],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL)
            (stdo, _) = pc.communicate()
            if pc.returncode == 0:
                archpath = stdo.decode().strip()
                return 'lib/' + archpath
        except Exception:
            pass
    if is_freebsd() or is_irix():
        return 'lib'
    if os.path.isdir('/usr/lib64') and not os.path.islink('/usr/lib64'):
        return 'lib64'
    return 'lib'


def default_libexecdir() -> str:
    if is_haiku():
        return 'lib'
    # There is no way to auto-detect this, so it must be set at build time
    return 'libexec'


def default_prefix() -> str:
    if is_windows():
        return 'c:/'
    if is_haiku():
        return '/boot/system/non-packaged'
    return '/usr/local'


def default_datadir() -> str:
    if is_haiku():
        return 'data'
    return 'share'


def default_includedir() -> str:
    if is_haiku():
        return 'develop/headers'
    return 'include'


def default_infodir() -> str:
    if is_haiku():
        return 'documentation/info'
    return 'share/info'


def default_localedir() -> str:
    if is_haiku():
        return 'data/locale'
    return 'share/locale'


def default_mandir() -> str:
    if is_haiku():
        return 'documentation/man'
    return 'share/man'


def default_sbindir() -> str:
    if is_haiku():
        return 'bin'
    return 'sbin'


def default_sysconfdir() -> str:
    if is_haiku():
        return 'settings'
    return 'etc'


def has_path_sep(name: str, sep: str = '/\\') -> bool:
    'Checks if any of the specified @sep path separators are in @name'
    for each in sep:
        if each in name:
            return True
    return False


if is_windows():
    # shlex.split is not suitable for splitting command line on Window (https://bugs.python.org/issue1724822);
    # shlex.quote is similarly problematic. Below are "proper" implementations of these functions according to
    # https://docs.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments and
    # https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/

    _whitespace = ' \t\n\r'
    _find_unsafe_char = re.compile(fr'[{_whitespace}"]').search

    def quote_arg(arg: str) -> str:
        if arg and not _find_unsafe_char(arg):
            return arg

        result = '"'
        num_backslashes = 0
        for c in arg:
            if c == '\\':
                num_backslashes += 1
            else:
                if c == '"':
                    # Escape all backslashes and the following double quotation mark
                    num_backslashes = num_backslashes * 2 + 1

                result += num_backslashes * '\\' + c
                num_backslashes = 0

        # Escape all backslashes, but let the terminating double quotation
        # mark we add below be interpreted as a metacharacter
        result += (num_backslashes * 2) * '\\' + '"'
        return result

    def split_args(cmd: str) -> T.List[str]:
        result: T.List[str] = []
        arg = ''
        num_backslashes = 0
        num_quotes = 0
        in_quotes = False
        for c in cmd:
            if c == '\\':
                num_backslashes += 1
            else:
                if c == '"' and not num_backslashes % 2:
                    # unescaped quote, eat it
                    arg += (num_backslashes // 2) * '\\'
                    num_quotes += 1
                    in_quotes = not in_quotes
                elif c in _whitespace and not in_quotes:
                    if arg or num_quotes:
                        # reached the end of the argument
                        result.append(arg)
                        arg = ''
                        num_quotes = 0
                else:
                    if c == '"':
                        # escaped quote
                        num_backslashes = (num_backslashes - 1) // 2

                    arg += num_backslashes * '\\' + c

                num_backslashes = 0

        if arg or num_quotes:
            result.append(arg)

        return result
else:
    def quote_arg(arg: str) -> str:
        return shlex.quote(arg)

    def split_args(cmd: str) -> T.List[str]:
        return shlex.split(cmd)


def join_args(args: T.Iterable[str]) -> str:
    return ' '.join([quote_arg(x) for x in args])


def do_replacement(regex: T.Pattern[str], line: str,
                   variable_format: Literal['meson', 'cmake', 'cmake@'],
                   confdata: T.Union[T.Dict[str, T.Tuple[str, T.Optional[str]]], 'ConfigurationData']) -> T.Tuple[str, T.Set[str]]:
    missing_variables: T.Set[str] = set()
    if variable_format == 'cmake':
        start_tag = '${'
        backslash_tag = '\\${'
    else:
        start_tag = '@'
        backslash_tag = '\\@'

    def variable_replace(match: T.Match[str]) -> str:
        # Pairs of escape characters before '@' or '\@'
        if match.group(0).endswith('\\'):
            num_escapes = match.end(0) - match.start(0)
            return '\\' * (num_escapes // 2)
        # Single escape character and '@'
        elif match.group(0) == backslash_tag:
            return start_tag
        # Template variable to be replaced
        else:
            varname = match.group(1)
            var_str = ''
            if varname in confdata:
                var, _ = confdata.get(varname)
                if isinstance(var, str):
                    var_str = var
                elif variable_format.startswith("cmake") and isinstance(var, bool):
                    var_str = str(int(var))
                elif isinstance(var, int):
                    var_str = str(var)
                else:
                    msg = f'Tried to replace variable {varname!r} value with ' \
                          f'something other than a string or int: {var!r}'
                    raise MesonException(msg)
            else:
                missing_variables.add(varname)
            return var_str
    return re.sub(regex, variable_replace, line), missing_variables

def do_define(regex: T.Pattern[str], line: str, confdata: 'ConfigurationData',
              variable_format: Literal['meson', 'cmake', 'cmake@'], subproject: T.Optional[SubProject] = None) -> str:
    cmake_bool_define = False
    if variable_format != "meson":
        cmake_bool_define = "cmakedefine01" in line

    def get_cmake_define(line: str, confdata: 'ConfigurationData') -> str:
        arr = line.split()

        if cmake_bool_define:
            (v, desc) = confdata.get(arr[1])
            return str(int(bool(v)))

        define_value: T.List[str] = []
        for token in arr[2:]:
            try:
                v, _ = confdata.get(token)
                define_value += [str(v)]
            except KeyError:
                define_value += [token]
        return ' '.join(define_value)

    arr = line.split()
    if len(arr) != 2:
        if variable_format == 'meson':
            raise MesonException('#mesondefine does not contain exactly two tokens: %s' % line.strip())
        elif subproject is not None:
            from ..interpreterbase.decorators import FeatureNew
            FeatureNew.single_use('cmakedefine without exactly two tokens', '0.54.1', subproject)

    varname = arr[1]
    try:
        v, _ = confdata.get(varname)
    except KeyError:
        if cmake_bool_define:
            return '#define %s 0\n' % varname
        else:
            return '/* #undef %s */\n' % varname

    if isinstance(v, str) or variable_format != "meson":
        if variable_format == 'meson':
            result = v
        else:
            if not cmake_bool_define and not v:
                return '/* #undef %s */\n' % varname

            result = get_cmake_define(line, confdata)
        result = f'#define {varname} {result}'.strip() + '\n'
        result, _ = do_replacement(regex, result, variable_format, confdata)
        return result
    elif isinstance(v, bool):
        if v:
            return '#define %s\n' % varname
        else:
            return '#undef %s\n' % varname
    elif isinstance(v, int):
        return '#define %s %d\n' % (varname, v)
    else:
        raise MesonException('#mesondefine argument "%s" is of unknown type.' % varname)

def get_variable_regex(variable_format: Literal['meson', 'cmake', 'cmake@'] = 'meson') -> T.Pattern[str]:
    # Only allow (a-z, A-Z, 0-9, _, -) as valid characters for a define
    # Also allow escaping '@' with '\@'
    if variable_format in {'meson', 'cmake@'}:
        regex = re.compile(r'(?:\\\\)+(?=\\?@)|\\@|@([-a-zA-Z0-9_]+)@')
    else:
        regex = re.compile(r'(?:\\\\)+(?=\\?\$)|\\\${|\${([-a-zA-Z0-9_]+)}')
    return regex

def do_conf_str(src: str, data: T.List[str], confdata: 'ConfigurationData',
                variable_format: Literal['meson', 'cmake', 'cmake@'],
                subproject: T.Optional[SubProject] = None) -> T.Tuple[T.List[str], T.Set[str], bool]:
    def line_is_valid(line: str, variable_format: str) -> bool:
        if variable_format == 'meson':
            if '#cmakedefine' in line:
                return False
        else: # cmake format
            if '#mesondefine' in line:
                return False
        return True

    regex = get_variable_regex(variable_format)

    search_token = '#mesondefine'
    if variable_format != 'meson':
        search_token = '#cmakedefine'

    result: T.List[str] = []
    missing_variables: T.Set[str] = set()
    # Detect when the configuration data is empty and no tokens were found
    # during substitution so we can warn the user to use the `copy:` kwarg.
    confdata_useless = not confdata.keys()
    for line in data:
        if line.lstrip().startswith(search_token):
            confdata_useless = False
            line = do_define(regex, line, confdata, variable_format, subproject)
        else:
            if not line_is_valid(line, variable_format):
                raise MesonException(f'Format error in {src}: saw "{line.strip()}" when format set to "{variable_format}"')
            line, missing = do_replacement(regex, line, variable_format, confdata)
            missing_variables.update(missing)
            if missing:
                confdata_useless = False
        result.append(line)

    return result, missing_variables, confdata_useless

def do_conf_file(src: str, dst: str, confdata: 'ConfigurationData',
                 variable_format: Literal['meson', 'cmake', 'cmake@'],
                 encoding: str = 'utf-8', subproject: T.Optional[SubProject] = None) -> T.Tuple[T.Set[str], bool]:
    try:
        with open(src, encoding=encoding, newline='') as f:
            data = f.readlines()
    except Exception as e:
        raise MesonException(f'Could not read input file {src}: {e!s}')

    (result, missing_variables, confdata_useless) = do_conf_str(src, data, confdata, variable_format, subproject)
    dst_tmp = dst + '~'
    try:
        with open(dst_tmp, 'w', encoding=encoding, newline='') as f:
            f.writelines(result)
    except Exception as e:
        raise MesonException(f'Could not write output file {dst}: {e!s}')
    shutil.copymode(src, dst_tmp)
    replace_if_different(dst, dst_tmp)
    return missing_variables, confdata_useless

CONF_C_PRELUDE = '''/*
 * Autogenerated by the Meson build system.
 * Do not edit, your changes will be lost.
 */

{}

'''

CONF_NASM_PRELUDE = '''; Autogenerated by the Meson build system.
; Do not edit, your changes will be lost.

'''

def _dump_c_header(ofile: T.TextIO,
                   cdata: ConfigurationData,
                   output_format: Literal['c', 'nasm'],
                   macro_name: T.Optional[str]) -> None:
    format_desc: T.Callable[[str], str]
    if output_format == 'c':
        if macro_name:
            prelude = CONF_C_PRELUDE.format('#ifndef {0}\n#define {0}'.format(macro_name))
        else:
            prelude = CONF_C_PRELUDE.format('#pragma once')
        prefix = '#'
        format_desc = lambda desc: f'/* {desc} */\n'
    else:  # nasm
        prelude = CONF_NASM_PRELUDE
        prefix = '%'
        format_desc = lambda desc: '; ' + '\n; '.join(desc.splitlines()) + '\n'

    ofile.write(prelude)
    for k in sorted(cdata.keys()):
        (v, desc) = cdata.get(k)
        if desc:
            ofile.write(format_desc(desc))
        if isinstance(v, bool):
            if v:
                ofile.write(f'{prefix}define {k}\n\n')
            else:
                ofile.write(f'{prefix}undef {k}\n\n')
        elif isinstance(v, (int, str)):
            ofile.write(f'{prefix}define {k} {v}\n\n')
        else:
            raise MesonException('Unknown data type in configuration file entry: ' + k)
    if output_format == 'c' and macro_name:
        ofile.write('#endif\n')


def dump_conf_header(ofilename: str, cdata: ConfigurationData,
                     output_format: Literal['c', 'nasm', 'json'],
                     macro_name: T.Optional[str]) -> None:
    ofilename_tmp = ofilename + '~'
    with open(ofilename_tmp, 'w', encoding='utf-8') as ofile:
        if output_format == 'json':
            data = {k: v[0] for k, v in cdata.values.items()}
            json.dump(data, ofile, sort_keys=True)
        else:  # c, nasm
            _dump_c_header(ofile, cdata, output_format, macro_name)

    replace_if_different(ofilename, ofilename_tmp)


def replace_if_different(dst: str, dst_tmp: str) -> None:
    # If contents are identical, don't touch the file to prevent
    # unnecessary rebuilds.
    different = True
    try:
        with open(dst, 'rb') as f1, open(dst_tmp, 'rb') as f2:
            if f1.read() == f2.read():
                different = False
    except FileNotFoundError:
        pass
    if different:
        os.replace(dst_tmp, dst)
    else:
        os.unlink(dst_tmp)


def listify(item: T.Any, flatten: bool = True) -> T.List[T.Any]:
    '''
    Returns a list with all args embedded in a list if they are not a list.
    This function preserves order.
    @flatten: Convert lists of lists to a flat list
    '''
    if not isinstance(item, list):
        return [item]
    result: T.List[T.Any] = []
    for i in item:
        if flatten and isinstance(i, list):
            result += listify(i, flatten=True)
        else:
            result.append(i)
    return result

def listify_array_value(value: T.Union[str, T.List[str]], shlex_split_args: bool = False) -> T.List[str]:
    if isinstance(value, str):
        if value.startswith('['):
            try:
                newvalue = ast.literal_eval(value)
            except ValueError:
                raise MesonException(f'malformed value {value}')
        elif value == '':
            newvalue = []
        else:
            if shlex_split_args:
                newvalue = split_args(value)
            else:
                newvalue = [v.strip() for v in value.split(',')]
    elif isinstance(value, list):
        newvalue = value
    else:
        raise MesonException(f'"{value}" should be a string array, but it is not')
    assert isinstance(newvalue, list)
    return newvalue

def extract_as_list(dict_object: T.Dict[_T, _U], key: _T, pop: bool = False) -> T.List[_U]:
    '''
    Extracts all values from given dict_object and listifies them.
    '''
    fetch: T.Callable[[_T], _U] = dict_object.get
    if pop:
        fetch = dict_object.pop
    # If there's only one key, we don't return a list with one element
    return listify(fetch(key) or [], flatten=True)


def typeslistify(item: 'T.Union[_T, T.Sequence[_T]]',
                 types: 'T.Union[T.Type[_T], T.Tuple[T.Type[_T]]]') -> T.List[_T]:
    '''
    Ensure that type(@item) is one of @types or a
    list of items all of which are of type @types
    '''
    if isinstance(item, types):
        item = T.cast('T.List[_T]', [item])
    if not isinstance(item, list):
        raise MesonException('Item must be a list or one of {!r}, not {!r}'.format(types, type(item)))
    for i in item:
        if i is not None and not isinstance(i, types):
            raise MesonException('List item must be one of {!r}, not {!r}'.format(types, type(i)))
    return item


def stringlistify(item: T.Union[T.Any, T.Sequence[T.Any]]) -> T.List[str]:
    return typeslistify(item, str)


def expand_arguments(args: T.Iterable[str]) -> T.Optional[T.List[str]]:
    expended_args: T.List[str] = []
    for arg in args:
        if not arg.startswith('@'):
            expended_args.append(arg)
            continue

        args_file = arg[1:]
        try:
            with open(args_file, encoding='utf-8') as f:
                extended_args = f.read().split()
            expended_args += extended_args
        except Exception as e:
            mlog.error('Expanding command line arguments:',  args_file, 'not found')
            mlog.exception(e)
            return None
    return expended_args


def partition(pred: T.Callable[[_T], object], iterable: T.Iterable[_T]) -> T.Tuple[T.Iterator[_T], T.Iterator[_T]]:
    """Use a predicate to partition entries into false entries and true
    entries.

    >>> x, y = partition(is_odd, range(10))
    >>> (list(x), list(y))
    ([0, 2, 4, 6, 8], [1, 3, 5, 7, 9])
    """
    t1, t2 = tee(iterable)
    return (t for t in t1 if not pred(t)), (t for t in t2 if pred(t))


def Popen_safe(args: T.List[str], write: T.Optional[str] = None,
               stdin: T.Union[None, T.TextIO, T.BinaryIO, int] = subprocess.DEVNULL,
               stdout: T.Union[None, T.TextIO, T.BinaryIO, int] = subprocess.PIPE,
               stderr: T.Union[None, T.TextIO, T.BinaryIO, int] = subprocess.PIPE,
               **kwargs: T.Any) -> T.Tuple['subprocess.Popen[str]', str, str]:
    import locale
    encoding = locale.getpreferredencoding()
    # Stdin defaults to DEVNULL otherwise the command run by us here might mess
    # up the console and ANSI colors will stop working on Windows.
    # If write is not None, set stdin to PIPE so data can be sent.
    if write is not None:
        stdin = subprocess.PIPE

    try:
        if not sys.stdout.encoding or encoding.upper() != 'UTF-8':
            p, o, e = Popen_safe_legacy(args, write=write, stdin=stdin, stdout=stdout, stderr=stderr, **kwargs)
        else:
            p = subprocess.Popen(args, universal_newlines=True, encoding=encoding, close_fds=False,
                                 stdin=stdin, stdout=stdout, stderr=stderr, **kwargs)
            o, e = p.communicate(write)
    except OSError as oserr:
        if oserr.errno == errno.ENOEXEC:
            raise MesonException(f'Failed running {args[0]!r}, binary or interpreter not executable.\n'
                                 'Possibly wrong architecture or the executable bit is not set.')
        raise
    # Sometimes the command that we run will call another command which will be
    # without the above stdin workaround, so set the console mode again just in
    # case.
    mlog.setup_console()
    return p, o, e


def Popen_safe_legacy(args: T.List[str], write: T.Optional[str] = None,
                      stdin: T.Union[None, T.TextIO, T.BinaryIO, int] = subprocess.DEVNULL,
                      stdout: T.Union[None, T.TextIO, T.BinaryIO, int] = subprocess.PIPE,
                      stderr: T.Union[None, T.TextIO, T.BinaryIO, int] = subprocess.PIPE,
                      **kwargs: T.Any) -> T.Tuple['subprocess.Popen[str]', str, str]:
    p = subprocess.Popen(args, universal_newlines=False, close_fds=False,
                         stdin=stdin, stdout=stdout, stderr=stderr, **kwargs)
    input_: T.Optional[bytes] = None
    if write is not None:
        input_ = write.encode('utf-8')
    o, e = p.communicate(input_)
    if o is not None:
        if sys.stdout.encoding is not None:
            o = o.decode(encoding=sys.stdout.encoding, errors='replace').replace('\r\n', '\n')
        else:
            o = o.decode(errors='replace').replace('\r\n', '\n')
    if e is not None:
        if sys.stderr is not None and sys.stderr.encoding:
            e = e.decode(encoding=sys.stderr.encoding, errors='replace').replace('\r\n', '\n')
        else:
            e = e.decode(errors='replace').replace('\r\n', '\n')
    return p, o, e


def Popen_safe_logged(args: T.List[str], msg: str = 'Called', **kwargs: T.Any) -> T.Tuple['subprocess.Popen[str]', str, str]:
    '''
    Wrapper around Popen_safe that assumes standard piped o/e and logs this to the meson log.
    '''
    try:
        p, o, e = Popen_safe(args, **kwargs)
    except Exception as excp:
        mlog.debug('-----------')
        mlog.debug(f'{msg}: `{join_args(args)}` -> {excp}')
        raise

    rc, out, err = p.returncode, o.strip(), e.strip()
    mlog.debug('-----------')
    mlog.debug(f'{msg}: `{join_args(args)}` -> {rc}')
    if out:
        mlog.debug(f'stdout:\n{out}\n-----------')
    if err:
        mlog.debug(f'stderr:\n{err}\n-----------')
    return p, o, e


def iter_regexin_iter(regexiter: T.Iterable[str], initer: T.Iterable[str]) -> T.Optional[str]:
    '''
    Takes each regular expression in @regexiter and tries to search for it in
    every item in @initer. If there is a match, returns that match.
    Else returns False.
    '''
    for regex in regexiter:
        for ii in initer:
            if not isinstance(ii, str):
                continue
            match = re.search(regex, ii)
            if match:
                return match.group()
    return None


def _substitute_values_check_errors(command: T.List[str], values: T.Dict[str, T.Union[str, T.List[str]]]) -> None:
    # Error checking
    inregex: T.List[str] = ['@INPUT([0-9]+)?@', '@PLAINNAME@', '@BASENAME@']
    outregex: T.List[str] = ['@OUTPUT([0-9]+)?@', '@OUTDIR@']
    if '@INPUT@' not in values:
        # Error out if any input-derived templates are present in the command
        match = iter_regexin_iter(inregex, command)
        if match:
            raise MesonException(f'Command cannot have {match!r}, since no input files were specified')
    else:
        if len(values['@INPUT@']) > 1:
            # Error out if @PLAINNAME@ or @BASENAME@ is present in the command
            match = iter_regexin_iter(inregex[1:], command)
            if match:
                raise MesonException(f'Command cannot have {match!r} when there is '
                                     'more than one input file')
        # Error out if an invalid @INPUTnn@ template was specified
        for each in command:
            if not isinstance(each, str):
                continue
            match2 = re.search(inregex[0], each)
            if match2 and match2.group() not in values:
                m = 'Command cannot have {!r} since there are only {!r} inputs'
                raise MesonException(m.format(match2.group(), len(values['@INPUT@'])))
    if '@OUTPUT@' not in values:
        # Error out if any output-derived templates are present in the command
        match = iter_regexin_iter(outregex, command)
        if match:
            raise MesonException(f'Command cannot have {match!r} since there are no outputs')
    else:
        # Error out if an invalid @OUTPUTnn@ template was specified
        for each in command:
            if not isinstance(each, str):
                continue
            match2 = re.search(outregex[0], each)
            if match2 and match2.group() not in values:
                m = 'Command cannot have {!r} since there are only {!r} outputs'
                raise MesonException(m.format(match2.group(), len(values['@OUTPUT@'])))


def substitute_values(command: T.List[str], values: T.Dict[str, T.Union[str, T.List[str]]]) -> T.List[str]:
    '''
    Substitute the template strings in the @values dict into the list of
    strings @command and return a new list. For a full list of the templates,
    see get_filenames_templates_dict()

    If multiple inputs/outputs are given in the @values dictionary, we
    substitute @INPUT@ and @OUTPUT@ only if they are the entire string, not
    just a part of it, and in that case we substitute *all* of them.

    The typing of this function is difficult, as only @OUTPUT@ and @INPUT@ can
    be lists, everything else is a string. However, TypeDict cannot represent
    this, as you can have optional keys, but not extra keys. We end up just
    having to us asserts to convince type checkers that this is okay.

    https://github.com/python/mypy/issues/4617
    '''

    def replace(m: T.Match[str]) -> str:
        v = values[m.group(0)]
        assert isinstance(v, str), 'for mypy'
        return v

    # Error checking
    _substitute_values_check_errors(command, values)

    # Substitution
    outcmd: T.List[str] = []
    rx_keys = [re.escape(key) for key in values if key not in ('@INPUT@', '@OUTPUT@')]
    value_rx = re.compile('|'.join(rx_keys)) if rx_keys else None
    for vv in command:
        more: T.Optional[str] = None
        if not isinstance(vv, str):
            outcmd.append(vv)
        elif '@INPUT@' in vv:
            inputs = values['@INPUT@']
            if vv == '@INPUT@':
                outcmd += inputs
            elif len(inputs) == 1:
                outcmd.append(vv.replace('@INPUT@', inputs[0]))
            else:
                raise MesonException("Command has '@INPUT@' as part of a "
                                     "string and more than one input file")
        elif '@OUTPUT@' in vv:
            outputs = values['@OUTPUT@']
            if vv == '@OUTPUT@':
                outcmd += outputs
            elif len(outputs) == 1:
                outcmd.append(vv.replace('@OUTPUT@', outputs[0]))
            else:
                raise MesonException("Command has '@OUTPUT@' as part of a "
                                     "string and more than one output file")

        # Append values that are exactly a template string.
        # This is faster than a string replace.
        elif vv in values:
            o = values[vv]
            assert isinstance(o, str), 'for mypy'
            more = o
        # Substitute everything else with replacement
        elif value_rx:
            more = value_rx.sub(replace, vv)
        else:
            more = vv

        if more is not None:
            outcmd.append(more)

    return outcmd


def get_filenames_templates_dict(inputs: T.List[str], outputs: T.List[str]) -> T.Dict[str, T.Union[str, T.List[str]]]:
    '''
    Create a dictionary with template strings as keys and values as values for
    the following templates:

    @INPUT@  - the full path to one or more input files, from @inputs
    @OUTPUT@ - the full path to one or more output files, from @outputs
    @OUTDIR@ - the full path to the directory containing the output files

    If there is only one input file, the following keys are also created:

    @PLAINNAME@ - the filename of the input file
    @BASENAME@ - the filename of the input file with the extension removed

    If there is more than one input file, the following keys are also created:

    @INPUT0@, @INPUT1@, ... one for each input file

    If there is more than one output file, the following keys are also created:

    @OUTPUT0@, @OUTPUT1@, ... one for each output file
    '''
    values: T.Dict[str, T.Union[str, T.List[str]]] = {}
    # Gather values derived from the input
    if inputs:
        # We want to substitute all the inputs.
        values['@INPUT@'] = inputs
        for (ii, vv) in enumerate(inputs):
            # Write out @INPUT0@, @INPUT1@, ...
            values[f'@INPUT{ii}@'] = vv
        if len(inputs) == 1:
            # Just one value, substitute @PLAINNAME@ and @BASENAME@
            values['@PLAINNAME@'] = plain = os.path.basename(inputs[0])
            values['@BASENAME@'] = os.path.splitext(plain)[0]
    if outputs:
        # Gather values derived from the outputs, similar to above.
        values['@OUTPUT@'] = outputs
        for (ii, vv) in enumerate(outputs):
            values[f'@OUTPUT{ii}@'] = vv
        # Outdir should be the same for all outputs
        values['@OUTDIR@'] = os.path.dirname(outputs[0])
        # Many external programs fail on empty arguments.
        if values['@OUTDIR@'] == '':
            values['@OUTDIR@'] = '.'
    return values


def _make_tree_writable(topdir: str) -> None:
    # Ensure all files and directories under topdir are writable
    # (and readable) by owner.
    for d, _, files in os.walk(topdir):
        os.chmod(d, os.stat(d).st_mode | stat.S_IWRITE | stat.S_IREAD)
        for fname in files:
            fpath = os.path.join(d, fname)
            if os.path.isfile(fpath):
                os.chmod(fpath, os.stat(fpath).st_mode | stat.S_IWRITE | stat.S_IREAD)


def windows_proof_rmtree(f: str) -> None:
    # On Windows if anyone is holding a file open you can't
    # delete it. As an example an anti virus scanner might
    # be scanning files you are trying to delete. The only
    # way to fix this is to try again and again.
    delays = [0.1, 0.1, 0.2, 0.2, 0.2, 0.5, 0.5, 1, 1, 1, 1, 2]
    writable = False
    for d in delays:
        try:
            # Start by making the tree writable.
            if not writable:
                _make_tree_writable(f)
                writable = True
        except PermissionError:
            time.sleep(d)
            continue
        try:
            shutil.rmtree(f)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(d)
    # Try one last time and throw if it fails.
    shutil.rmtree(f)


def windows_proof_rm(fpath: str) -> None:
    """Like windows_proof_rmtree, but for a single file."""
    if os.path.isfile(fpath):
        os.chmod(fpath, os.stat(fpath).st_mode | stat.S_IWRITE | stat.S_IREAD)
    delays = [0.1, 0.1, 0.2, 0.2, 0.2, 0.5, 0.5, 1, 1, 1, 1, 2]
    for d in delays:
        try:
            os.unlink(fpath)
            return
        except FileNotFoundError:
            return
        except OSError:
            time.sleep(d)
    os.unlink(fpath)


class TemporaryDirectoryWinProof(TemporaryDirectory):
    """
    Like TemporaryDirectory, but cleans things up using
    windows_proof_rmtree()
    """

    def __exit__(self, exc: T.Any, value: T.Any, tb: T.Any) -> None:
        try:
            super().__exit__(exc, value, tb)
        except OSError:
            windows_proof_rmtree(self.name)

    def cleanup(self) -> None:
        try:
            super().cleanup()
        except OSError:
            windows_proof_rmtree(self.name)


def detect_subprojects(spdir_name: str, current_dir: str = '',
                       result: T.Optional[T.Dict[str, T.List[str]]] = None) -> T.Dict[str, T.List[str]]:
    if result is None:
        result = {}
    spdir = os.path.join(current_dir, spdir_name)
    if not os.path.exists(spdir):
        return result
    for trial in glob(os.path.join(spdir, '*')):
        basename = os.path.basename(trial)
        if trial == 'packagecache':
            continue
        append_this = True
        if os.path.isdir(trial):
            detect_subprojects(spdir_name, trial, result)
        elif trial.endswith('.wrap') and os.path.isfile(trial):
            basename = os.path.splitext(basename)[0]
        else:
            append_this = False
        if append_this:
            if basename in result:
                result[basename].appe
```