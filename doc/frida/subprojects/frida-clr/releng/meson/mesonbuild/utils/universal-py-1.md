Response:
My thought process to analyze the provided Python code and generate the summary goes like this:

1. **Understand the Goal:** The request asks for a functional summary of the given Python code, highlighting its relevance to reverse engineering, low-level details (kernel, OS), logical reasoning, common user errors, and debugging contexts. It also specifies this is part 2 of 3, implying a broader context, although that's not immediately actionable for *this* part.

2. **Initial Skim for High-Level Structure:** I quickly scanned the code, noticing the `import` statements (`re`, `subprocess`, `os`, etc.) indicating common utility functions. I also noted the presence of many distinct function definitions. This suggests the file is a collection of utility functions rather than a single, large piece of logic.

3. **Categorize Functions by Functionality:**  I began to mentally group functions based on their apparent purpose:
    * **Version Parsing:** `detect_version()`. This is straightforward string manipulation using regular expressions.
    * **Path/Directory Handling:** `default_libdir()`, `default_libexecdir()`, `default_prefix()`, etc. These seem to determine default locations based on the operating system.
    * **String/Argument Manipulation:** `has_path_sep()`, `quote_arg()`, `split_args()`, `join_args()`. These deal with processing command-line arguments, especially handling platform differences (Windows).
    * **Configuration File Processing:** `do_replacement()`, `do_define()`, `get_variable_regex()`, `do_conf_str()`, `do_conf_file()`, `dump_conf_header()`. This is a significant portion, dealing with reading, modifying, and writing configuration files, likely for build systems.
    * **List/Data Structure Manipulation:** `listify()`, `listify_array_value()`, `extract_as_list()`, `typeslistify()`, `stringlistify()`. These functions focus on normalizing and manipulating list-like data.
    * **Process Execution:** `expand_arguments()`, `partition()`, `Popen_safe()`, `Popen_safe_legacy()`, `Popen_safe_logged()`. These functions are about running external commands and handling their input/output.
    * **String/Pattern Matching:** `iter_regexin_iter()`. This is a utility for finding regex matches within a list of strings.
    * **Template Substitution:** `_substitute_values_check_errors()`, `substitute_values()`, `get_filenames_templates_dict()`. These functions handle replacing placeholders in strings, common in build systems and code generation.
    * **File System Operations (with robustness):** `_make_tree_writable()`, `windows_proof_rmtree()`, `windows_proof_rm()`, `TemporaryDirectoryWinProof()`, `replace_if_different()`. These focus on file system operations, specifically addressing issues on Windows.
    * **Subproject Detection:** `detect_subprojects()`. This appears to search for subproject directories.

4. **Address Specific Requirements:**  Now, I revisit the request's specific points for each function group:

    * **Reverse Engineering:** The code itself doesn't perform direct reverse engineering. However, the configuration file processing and the ability to execute external commands (`Popen_safe`) are *used* in reverse engineering tools. Frida, the context of this code, *is* a reverse engineering tool. The string manipulation could be relevant for parsing disassembled code or data.
    * **Binary/Low-Level/OS Details:** The OS-specific path functions (e.g., `default_libdir()`) and the Windows-specific argument handling (`quote_arg`, `split_args`) and robust file system operations (`windows_proof_rmtree`) directly relate to this. The `Popen_safe` functions also interact with the operating system's process management.
    * **Logical Reasoning:**  The configuration file processing involves conditional logic (if-else) based on variable values. The template substitution uses regular expressions and string manipulation based on the presence of specific markers.
    * **User Errors:** The configuration file processing is a prime area for user errors (incorrect syntax, missing variables). Incorrectly formatted command-line arguments (especially on Windows) are another source. The code includes error handling (e.g., `try-except` blocks) that can reveal these errors.
    * **Debugging:** Understanding how the configuration file processing works, how commands are executed, and how arguments are parsed is crucial for debugging build issues or problems with the target application when using Frida. The logging in `Popen_safe_logged` is a direct debugging aid.
    * **Assumptions and Outputs:** For functions like `detect_version`, I could easily create example inputs and expected outputs. For configuration file processing, I can imagine example configuration files and the resulting output.

5. **Synthesize the Summary:**  Based on the categorization and the addressing of specific requirements, I started drafting the summary, grouping related functionalities and providing examples where requested. I made sure to mention the overarching theme of being a collection of utility functions within the Frida project.

6. **Refine and Organize:** I reviewed the summary for clarity, conciseness, and accuracy. I ensured the examples were relevant and easy to understand. I also made sure to explicitly address each point from the original request. I noted the "Part 2 of 3" but acknowledged its limited impact on *this* specific file analysis. I tried to use clear and concise language, avoiding jargon where possible, or explaining it if necessary.

This iterative process of understanding, categorizing, addressing specific points, synthesizing, and refining allowed me to produce the comprehensive summary provided in the initial example. The key was breaking down the code into manageable parts and then connecting those parts back to the specific requirements of the prompt.
This Python code file, `universal.py`, part of the Frida dynamic instrumentation tool, provides a collection of utility functions used throughout the Frida build system (specifically within the `frida-clr` subproject's Meson build setup). Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Operating System Detection and Handling:**
   - Functions like `is_windows()`, `is_linux()`, `is_android()`, `is_haiku()`, `is_debianlike()`, `is_freebsd()`, `is_irix()`: These determine the underlying operating system, allowing for platform-specific logic in other parts of the build system.
   - **Relation to Reverse Engineering:** While not directly involved in reverse engineering *methods*, knowing the target OS is crucial for building Frida components that will run on that OS. Frida needs to be compiled differently for Windows, Linux, Android, etc.
   - **Binary/Low-Level/OS Knowledge:** These functions directly rely on knowledge of different operating system identifiers and how to access them (e.g., `sys.platform`).

2. **Version String Parsing:**
   - `detect_version(text: str) -> str`: This function extracts version numbers from a given text string using regular expressions. It tries two different regex patterns to handle various version formats.
   - **Logical Reasoning:** The function uses regular expressions to match patterns. It assumes that version numbers typically consist of digits and periods, potentially with hyphens and alphanumeric characters for pre-release identifiers.
   - **Example:**
     - Input: `"Frida version 16.4.7-rc.1 is now available"`
     - Output: `"16.4.7-rc.1"`
     - Input: `"Some other string with 2023.10.200 in it"`
     - Output: `"2023.10.200"`
     - Input: `"No version here"`
     - Output: `"unknown version"`

3. **Default Directory Path Determination:**
   - Functions like `default_libdir()`, `default_libexecdir()`, `default_prefix()`, `default_datadir()`, etc.: These functions determine the standard installation paths for libraries, executables, data files, etc., based on the detected operating system.
   - **Binary/Low-Level/OS Knowledge:** These functions encode knowledge of filesystem layout conventions on different operating systems (e.g., `/usr/lib` vs. `/usr/lib64` on Linux, or the typical structure on Haiku). The use of `dpkg-architecture` on Debian-like systems demonstrates interaction with package management tools.

4. **Command-Line Argument Handling (Especially for Windows):**
   - `has_path_sep(name: str, sep: str = '/\\') -> bool`: Checks if a string contains path separators.
   - `quote_arg(arg: str) -> str`:  Quotes a command-line argument appropriately for the shell, with special handling for Windows command-line quoting rules (which are more complex than simple shlex quoting).
   - `split_args(cmd: str) -> T.List[str]`: Splits a command-line string into a list of arguments, again with specific handling for Windows command-line parsing.
   - `join_args(args: T.Iterable[str]) -> str`: Joins a list of arguments into a command-line string, quoting as necessary.
   - **Relation to Reverse Engineering:** When Frida interacts with external processes (which is common during instrumentation), it needs to construct and parse command lines correctly. This is especially important on Windows due to its different quoting conventions.
   - **User/Programming Errors:** Incorrect quoting of arguments can lead to commands failing or behaving unexpectedly. For example, on Windows, spaces in file paths need to be handled carefully.
   - **Example:**
     - Input `quote_arg("C:\\Program Files\\My App\\app.exe")` on Windows might output `"C:\\Program Files\\My App\\app.exe"` or a more complex quoted string depending on the content.
     - Input `split_args('"C:\\Program Files\\My App\\app.exe" -option "value with space"')` on Windows would correctly split the quoted path and the quoted value.

5. **Configuration File Processing (Template Substitution and Defines):**
   - `do_replacement(regex: T.Pattern[str], line: str, variable_format: Literal['meson', 'cmake', 'cmake@'], confdata: T.Union[T.Dict[str, T.Tuple[str, T.Optional[str]]], 'ConfigurationData']) -> T.Tuple[str, T.Set[str]]`:  Replaces variables (in the format `@variable@` or `${variable}`) in a string based on a provided dictionary of configuration data.
   - `do_define(regex: T.Pattern[str], line: str, confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], subproject: T.Optional[SubProject] = None) -> str`: Processes `#mesondefine` or `#cmakedefine` lines in configuration files, setting preprocessor definitions based on the configuration data.
   - `get_variable_regex(variable_format: Literal['meson', 'cmake', 'cmake@'] = 'meson') -> T.Pattern[str]`: Returns a regular expression to match variables based on the specified format (Meson or CMake).
   - `do_conf_str(src: str, data: T.List[str], confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], subproject: T.Optional[SubProject] = None) -> T.Tuple[T.List[str], T.Set[str], bool]`: Processes a list of strings as a configuration file, performing variable replacement and define processing.
   - `do_conf_file(src: str, dst: str, confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], encoding: str = 'utf-8', subproject: T.Optional[SubProject] = None) -> T.Tuple[T.Set[str], bool]`: Reads a configuration file, processes it, and writes the result to a destination file.
   - `dump_conf_header(ofilename: str, cdata: ConfigurationData, output_format: Literal['c', 'nasm', 'json'], macro_name: T.Optional[str]) -> None`: Dumps configuration data into a header file (C, NASM, or JSON format).
   - **Logical Reasoning:** These functions implement logic for parsing configuration file syntax, looking up variable values, and generating output based on those values.
   - **User/Programming Errors:**
     - Incorrect syntax in configuration files (`#mesondefine` without two tokens).
     - Referencing undefined variables in the configuration. The `do_replacement` function tracks `missing_variables`.
     - Using the wrong variable format (e.g., CMake syntax in a Meson file).
   - **Example:**
     - Assuming `confdata = {'MY_VARIABLE': ('my_value', 'Description of MY_VARIABLE')}`
     - Input line to `do_replacement`: `"This is the @MY_VARIABLE@"` with `variable_format='meson'`
     - Output: `"This is the my_value"`
     - Input line to `do_define`: `"#mesondefine USE_FEATURE"` with `confdata = {'USE_FEATURE': (True, 'Whether to use the feature')}`
     - Output: `"#define USE_FEATURE\n"`

6. **File System Operations with Robustness:**
   - `replace_if_different(dst: str, dst_tmp: str) -> None`:  Replaces a destination file with a temporary file only if the contents are different, to avoid unnecessary rebuilds.
   - `windows_proof_rmtree(f: str) -> None`: A robust version of `shutil.rmtree` for Windows, which retries deletion multiple times with delays to handle potential file locking issues.
   - `windows_proof_rm(fpath: str) -> None`: A robust version of `os.unlink` for Windows.
   - `TemporaryDirectoryWinProof`: A context manager for creating temporary directories that uses `windows_proof_rmtree` for cleanup.
   - **Binary/Low-Level/OS Knowledge:** These functions address specific limitations and quirks of the Windows operating system related to file deletion.
   - **User/Programming Errors:** These functions help mitigate errors caused by file locking issues on Windows, which are common.

7. **List and Data Structure Manipulation:**
   - `listify(item: T.Any, flatten: bool = True) -> T.List[T.Any]`: Ensures an item is a list, optionally flattening nested lists.
   - `listify_array_value(value: T.Union[str, T.List[str]], shlex_split_args: bool = False) -> T.List[str]`: Converts a string or list into a list of strings, handling comma-separated strings or optionally splitting using `shlex`.
   - `extract_as_list(dict_object: T.Dict[_T, _U], key: _T, pop: bool = False) -> T.List[_U]`: Extracts values from a dictionary into a list.
   - `typeslistify(item: 'T.Union[_T, T.Sequence[_T]]', types: 'T.Union[T.Type[_T], T.Tuple[T.Type[_T]]]') -> T.List[_T]`: Ensures an item is of a specific type or a list of items of that type.
   - `stringlistify(item: T.Union[T.Any, T.Sequence[T.Any]]) -> T.List[str]`:  Specifically ensures an item is a string or a list of strings.
   - **Logical Reasoning:** These functions perform basic data transformations and type checking.
   - **User/Programming Errors:** These functions help prevent type errors by ensuring data is in the expected format.

8. **Process Execution Helpers:**
   - `expand_arguments(args: T.Iterable[str]) -> T.Optional[T.List[str]]`: Expands arguments that start with `@` by reading the contents of the specified file and splitting it into arguments.
   - `partition(pred: T.Callable[[_T], object], iterable: T.Iterable[_T]) -> T.Tuple[T.Iterator[_T], T.Iterator[_T]]`: Splits an iterable into two iterators based on a predicate function.
   - `Popen_safe(args: T.List[str], ...)`: A wrapper around `subprocess.Popen` that handles encoding and potential `OSError` related to executable permissions.
   - `Popen_safe_legacy(...)`: A fallback for `Popen_safe` with more explicit encoding handling.
   - `Popen_safe_logged(args: T.List[str], msg: str = 'Called', **kwargs: T.Any) -> T.Tuple['subprocess.Popen[str]', str, str]`:  A wrapper around `Popen_safe` that logs the command being executed and its output.
   - **Relation to Reverse Engineering:** Frida often needs to execute external tools (e.g., compilers, linkers, other helper scripts). These functions provide a safer and more consistent way to do that.
   - **Binary/Low-Level/OS Knowledge:** `Popen_safe` deals with the underlying operating system's process creation mechanisms. The error handling for `ENOEXEC` directly relates to understanding executable file permissions.
   - **User/Programming Errors:**  `Popen_safe` helps catch errors like trying to execute a non-executable file. The logging in `Popen_safe_logged` is useful for debugging issues with external commands.

9. **Template String Substitution:**
   - `iter_regexin_iter(regexiter: T.Iterable[str], initer: T.Iterable[str]) -> T.Optional[str]`:  Searches for any of the provided regular expressions in a list of strings.
   - `_substitute_values_check_errors(command: T.List[str], values: T.Dict[str, T.Union[str, T.List[str]]]) -> None`: Performs error checking before substituting template values.
   - `substitute_values(command: T.List[str], values: T.Dict[str, T.Union[str, T.List[str]]]) -> T.List[str]`: Substitutes template strings (like `@INPUT@`, `@OUTPUT@`, `@BASENAME@`) in a command with actual values.
   - `get_filenames_templates_dict(inputs: T.List[str], outputs: T.List[str]) -> T.Dict[str, T.Union[str, T.List[str]]]`: Creates a dictionary of template string values based on input and output file paths.
   - **Relation to Reverse Engineering:** When building Frida or its components, these functions are used to generate command lines for tools, specifying input and output files, etc.
   - **Logical Reasoning:** These functions implement string manipulation logic based on identifying specific template patterns.
   - **User/Programming Errors:**  `_substitute_values_check_errors` helps catch errors like using input/output templates when no input/output files are specified or using single-file templates when multiple files are present.

10. **Subproject Detection:**
    - `detect_subprojects(spdir_name: str, current_dir: str = '', result: T.Optional[T.Dict[str, T.List[str]]] = None) -> T.Dict[str, T.List[str]]`: Recursively searches for subprojects (likely based on the presence of `.wrap` files) within a specified directory.
    - **Relation to Reverse Engineering:** Frida can have dependencies managed as subprojects. This function helps the build system locate these dependencies.
    - **Binary/Low-Level/OS Knowledge:** This interacts with the filesystem to traverse directories and identify files.

**User Operation to Reach This Code:**

A user would not directly interact with this Python file during the normal usage of Frida. This file is part of the *build system*. A user's actions would indirectly lead to this code being executed during the following scenarios:

1. **Building Frida from Source:** When a user clones the Frida repository and runs the build commands (likely using Meson), the Meson build system will execute this Python file as part of its configuration and build process.
2. **Developing Frida:** Developers working on Frida itself will interact with this file if they need to modify the build system's logic, particularly anything related to OS detection, command-line handling, or configuration file processing.
3. **Potentially when using `frida-compile` or similar tools:** If Frida has build tools that pre-process files or generate code, this file's functionalities might be used internally.

**Debugging Clues:**

If there are issues during the Frida build process, understanding the functionalities of this file can provide debugging clues:

- **OS-Specific Build Failures:** If the build fails on a particular operating system, the OS detection functions and the default path determination functions are good places to investigate.
- **Command Execution Errors:** If external commands fail during the build, the `Popen_safe` and argument handling functions might be involved. Looking at the logged output from `Popen_safe_logged` can be crucial.
- **Configuration Errors:** If the build fails due to incorrect configuration, the configuration file processing functions are the relevant area. Examining the content of generated configuration files can help.
- **File System Issues on Windows:** If the build fails on Windows with file deletion errors, the `windows_proof_rmtree` functions are the likely area to investigate.

**Summary of Functionalities (Part 2):**

This part of the `universal.py` file primarily focuses on **configuration file processing and robust file system operations, particularly for Windows**. It provides functions to:

- **Parse and process configuration files** in different formats (Meson and CMake), performing variable substitution and defining preprocessor macros.
- **Dump configuration data** into header files in various formats (C, NASM, JSON).
- Implement **robust file system operations** like safe file replacement and reliable deletion on Windows to handle potential file locking issues.
- Offer utilities for **manipulating lists and data structures**, ensuring data integrity during the build process.

These functionalities are crucial for ensuring that Frida can be built correctly and reliably across different operating systems and build environments.

Prompt: 
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
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
"""


```