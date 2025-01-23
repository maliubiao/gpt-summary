Response:
The user wants a summary of the functionalities of the Python code provided. I need to go through each function and class, understand its purpose, and then summarize the overall capabilities of the module.

Here's a breakdown of the functions and their potential functionalities:

- **`is_windows`, `is_linux`, `is_osx`, `is_android`, `is_haiku`, `is_freebsd`, `is_irix`, `is_openbsd`, `is_netbsd`, `is_sunos`, `is_cygwin`, `is_debianlike`:** These functions are platform detection utilities.
- **`get_compiler_sys_name`:** This likely retrieves the system name used by compilers.
- **` host_machine`, `target_machine`:** These probably return information about the host and target machines.
- **`which`:** A standard utility to find the executable path of a command.
- **`get_cmake_toolchain_file`:** This function appears to locate CMake toolchain files, useful for cross-compilation.
- **`get_wine_short_path`:**  This likely converts Windows paths to their short (8.3) format, potentially for compatibility with older tools.
- **`can_run_host_binaries`:** This checks if host binaries can be executed on the target.
- **`detect_cpu_family`:**  Identifies the CPU family.
- **`detect_cpu`:** Detects the specific CPU.
- **`detect_machine_cpu_family`:** Detects the machine's CPU family.
- **`detect_machine_cpu`:** Detects the machine's specific CPU.
- **`strip_quotes`:** Removes leading and trailing quotes from a string.
- **`get_version_from_string`:**  Extracts version information from a string using regular expressions.
- **`default_libdir`, `default_libexecdir`, `default_prefix`, `default_datadir`, `default_includedir`, `default_infodir`, `default_localedir`, `default_mandir`, `default_sbindir`, `default_sysconfdir`:** These provide default directory paths based on the operating system.
- **`has_path_sep`:** Checks if a string contains path separators.
- **`quote_arg`, `split_args`, `join_args`:** Functions for correctly quoting and splitting command-line arguments, with platform-specific implementations for Windows.
- **`do_replacement`:** Performs variable substitution in a string using different syntax (Meson, CMake).
- **`do_define`:** Handles `#mesondefine` and `#cmakedefine` directives for creating preprocessor definitions.
- **`get_variable_regex`:** Returns a regular expression for matching variables based on the format.
- **`do_conf_str`:** Processes a list of strings, performing variable substitutions and `#define` handling.
- **`do_conf_file`:** Reads a file, performs configuration string processing, and writes the result to another file.
- **`CONF_C_PRELUDE`, `CONF_NASM_PRELUDE`:** String constants for header file preludes.
- **`_dump_c_header`, `dump_conf_header`:**  Functions for generating C and NASM header files from configuration data.
- **`replace_if_different`:**  Replaces a file only if its content has changed.
- **`listify`, `listify_array_value`, `extract_as_list`, `typeslistify`, `stringlistify`:** Functions for ensuring data is in list format and checking types.
- **`expand_arguments`:** Expands command-line arguments from files (e.g., `@arg_file`).
- **`partition`:**  Splits an iterable based on a predicate.
- **`Popen_safe`, `Popen_safe_legacy`, `Popen_safe_logged`:** Wrappers around `subprocess.Popen` for safer execution, handling encoding and logging.
- **`iter_regexin_iter`:** Searches for regular expressions within an iterable of strings.
- **`_substitute_values_check_errors`, `substitute_values`:** Functions for substituting template strings in commands with provided values.
- **`get_filenames_templates_dict`:** Creates a dictionary of template strings and their corresponding filename/path values.
- **`_make_tree_writable`, `windows_proof_rmtree`, `windows_proof_rm`, `TemporaryDirectoryWinProof`:** Utilities for handling file system operations on Windows, dealing with potential permission issues.
- **`detect_subprojects`:** Detects subprojects within a given directory.

Based on this analysis, the primary function of this module seems to be providing a set of utility functions for the Frida build system, specifically focusing on cross-platform compatibility, command execution, and configuration file processing.
这是frida动态Instrumentation工具的源代码文件 `frida/subprojects/frida-swift/releng/meson/mesonbuild/utils/universal.py` 的第二部分，该文件主要提供了一系列跨平台的通用工具函数，用于处理各种构建相关的任务。

**功能归纳：**

这部分代码主要集中在以下几个方面：

1. **配置文件的处理和生成:**
    *   `do_replacement`:  实现对字符串中的变量进行替换，支持 Meson 和 CMake 两种不同的变量格式。
    *   `do_define`: 处理 `#mesondefine` 和 `#cmakedefine` 指令，用于生成 C/C++ 预处理器宏定义。
    *   `get_variable_regex`:  根据指定的变量格式生成对应的正则表达式，用于匹配变量。
    *   `do_conf_str`:  处理字符串列表，进行变量替换和宏定义处理。
    *   `do_conf_file`:  读取配置文件，调用 `do_conf_str` 进行处理，并将结果写入目标文件。
    *   `CONF_C_PRELUDE`, `CONF_NASM_PRELUDE`: 定义了生成的 C 和 NASM 头文件的开头注释。
    *   `_dump_c_header`, `dump_conf_header`:  根据配置数据生成 C 或 NASM 格式的头文件。

2. **文件操作工具:**
    *   `replace_if_different`:  比较两个文件的内容，如果不同则进行替换，用于避免不必要的重新构建。

3. **数据类型处理和转换:**
    *   `listify`: 将任何类型的输入转换为列表。
    *   `listify_array_value`:  将字符串或字符串列表转换为列表，支持解析类似 `[a, b, c]` 的字符串。
    *   `extract_as_list`: 从字典中提取值并转换为列表。
    *   `typeslistify`: 确保输入是指定类型或指定类型的列表。
    *   `stringlistify`: 确保输入是字符串或字符串列表。

4. **命令行参数处理:**
    *   `expand_arguments`:  展开包含 `@` 符号的文件路径，读取文件内容作为命令行参数。
    *   `partition`:  根据谓词函数将可迭代对象分割为两个迭代器。

5. **进程管理和命令执行:**
    *   `Popen_safe`, `Popen_safe_legacy`, `Popen_safe_logged`:  对 `subprocess.Popen` 的封装，提供更安全和方便的进程执行方式，处理编码问题和日志记录。

6. **字符串匹配和替换:**
    *   `iter_regexin_iter`:  在一个字符串列表中查找是否存在匹配任何给定正则表达式的字符串。
    *   `_substitute_values_check_errors`, `substitute_values`:  将命令字符串中的模板变量替换为实际的值。
    *   `get_filenames_templates_dict`:  根据输入和输出文件名生成用于替换的模板变量字典。

7. **Windows 平台特定的文件操作增强:**
    *   `_make_tree_writable`:  递归地设置目录及其下所有文件为可写。
    *   `windows_proof_rmtree`:  在 Windows 平台上安全地删除目录树，处理权限问题。
    *   `windows_proof_rm`:  在 Windows 平台上安全地删除单个文件，处理权限问题。
    *   `TemporaryDirectoryWinProof`:  继承自 `tempfile.TemporaryDirectory`，使用 `windows_proof_rmtree` 进行清理。

8. **子项目检测:**
    *   `detect_subprojects`:  在指定目录下查找子项目。

**与逆向方法的关联及举例说明:**

*   **配置文件处理和生成:** 在逆向工程中，经常需要修改或生成目标程序的配置文件以达到特定的目的，例如修改 hook 点、设置调试参数等。`do_conf_file` 和相关的函数可以用于生成修改后的配置文件。
    *   **举例:** Frida 脚本可能需要修改目标应用的某个配置，以启用特定的调试功能。可以使用 `do_conf_file` 函数，读取原始配置文件，修改其中的关键参数，然后生成新的配置文件并替换原始文件。

*   **命令行参数处理:** 在 Frida 脚本中，经常需要执行一些外部命令，例如启动目标应用、调用辅助工具等。`expand_arguments` 可以方便地从文件中读取命令行参数，`quote_arg` 和 `split_args` 可以帮助构造和解析命令行。
    *   **举例:**  一个 Frida 脚本需要使用 `adb` 命令来启动 Android 上的目标应用，并将一些参数传递给 `adb`。可以使用 `quote_arg` 来确保参数被正确引用，然后使用 `Popen_safe` 执行 `adb` 命令。

*   **进程管理和命令执行:**  Frida 本身就需要与目标进程进行交互，并且可能需要启动或监控其他进程。`Popen_safe` 等函数可以用于安全地执行外部命令，获取输出，并处理错误。
    *   **举例:**  一个 Frida 脚本可能需要调用一个独立的脚本或工具来分析目标应用的内存或执行特定的操作。可以使用 `Popen_safe` 来执行这个外部工具，并获取其输出结果。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

*   **平台检测 (`is_windows`, `is_linux`, `is_android` 等):** 这些函数是跨平台构建的关键，因为不同的操作系统在文件路径、命令行参数等方面都有差异。在逆向工程中，针对不同平台的应用，可能需要使用不同的工具和技术。
    *   **举例:**  Frida 脚本可能需要根据目标应用运行的平台来选择不同的 hook 方法或者使用不同的辅助工具。例如，在 Android 上可能需要使用 `adb`，而在 iOS 上可能需要使用 `idevicediagnostics`。

*   **默认目录 (`default_libdir`, `default_libexecdir` 等):**  了解不同平台的标准目录结构对于定位目标文件（例如库文件）非常重要。
    *   **举例:**  在 Android 平台上，目标应用的 so 库通常位于 `/data/app/<package_name>/lib/<arch>` 目录下。Frida 脚本可以使用这些默认路径来定位并加载目标库。

*   **命令行参数处理 (`quote_arg`, `split_args`):** 不同平台对命令行参数的解析规则可能不同，尤其是在处理包含空格或特殊字符的参数时。Windows 平台有其独特的命令行解析规则。
    *   **举例:**  在向目标应用传递包含空格的参数时，需要在 Windows 上使用双引号进行引用，而在 Linux 上可能使用单引号或转义符。`quote_arg` 可以帮助开发者生成平台兼容的命令行。

*   **进程管理 (`Popen_safe`):** 执行外部命令是逆向工程中常见的操作。需要考虑不同平台的命令执行方式和错误处理。
    *   **举例:**  在 Android 上，可以使用 `adb shell` 命令执行一些 shell 命令来操作目标应用或设备。`Popen_safe` 可以用于执行 `adb shell` 命令并获取其输出。

*   **Windows 平台特定的文件操作增强 (`windows_proof_rmtree`, `windows_proof_rm`):** Windows 的文件系统权限管理和文件锁定机制与其他平台有所不同。这些函数是为了解决在 Windows 上删除文件或目录时可能遇到的权限问题。
    *   **举例:**  在清理 Frida 运行时生成的一些临时文件时，由于某些进程可能正在访问这些文件，直接删除可能会失败。`windows_proof_rmtree` 可以多次尝试删除，以应对这种情况。

**逻辑推理、假设输入与输出:**

*   **`do_replacement`:**
    *   **假设输入:** `regex` 匹配 `@VAR@` 的正则表达式，`line` 为 `"The value is @VAR@"`, `variable_format` 为 `'meson'`, `confdata` 为 `{'VAR': ('123', 'The variable value')}`。
    *   **输出:** `("The value is 123", set())`

*   **`do_define`:**
    *   **假设输入:** `regex` 匹配变量的正则表达式，`line` 为 `"#mesondefine MY_FLAG"`, `confdata` 为 `{'MY_FLAG': (True, 'My flag')}`, `variable_format` 为 `'meson'`。
    *   **输出:** `"// My flag\n#define MY_FLAG\n"`

*   **`get_filenames_templates_dict`:**
    *   **假设输入:** `inputs` 为 `["/path/to/input.txt"]`, `outputs` 为 `["/path/to/output.bin"]`。
    *   **输出:** `{'@INPUT@': ['/path/to/input.txt'], '@OUTPUT@': ['/path/to/output.bin'], '@OUTDIR@': '/path/to', '@PLAINNAME@': 'input.txt', '@BASENAME@': 'input'}`

**用户或编程常见的使用错误及举例说明:**

*   **`do_replacement`:** 如果 `confdata` 中没有定义 `line` 中使用的变量，`missing_variables` 集合将包含该变量名。如果用户期望替换成功，但变量未定义，将会导致错误的结果。
    *   **举例:**  用户在配置文件中使用了 `@MY_UNDEFINED_VAR@`，但在构建系统中没有定义 `MY_UNDEFINED_VAR`，导致替换失败。

*   **`do_define`:**  `#mesondefine` 指令后面必须跟恰好两个 token（指令本身和变量名），否则会抛出 `MesonException`。
    *   **举例:**  用户在配置文件中写了 `"#mesondefine MY_FLAG with extra words"`, 这将导致构建失败。

*   **`Popen_safe`:**  用户可能会忘记处理 `Popen_safe` 返回的 `returncode`，从而忽略命令执行的失败。
    *   **举例:**  用户使用 `Popen_safe` 执行了一个可能失败的外部命令，但没有检查返回值，导致后续操作基于错误的前提进行。

*   **`get_filenames_templates_dict` 和 `substitute_values`:** 如果在有多个输入文件的情况下，命令字符串中使用了 `@PLAINNAME@` 或 `@BASENAME@`，将会抛出 `MesonException`，因为这些模板只在单输入文件时有意义。
    *   **举例:**  用户尝试对多个源文件进行编译，命令字符串中使用了 `@BASENAME@.o`，这会导致错误，因为 `@BASENAME@` 对于每个输入文件都是不同的，但模板只有一个。

**用户操作是如何一步步的到达这里，作为调试线索。**

作为 Frida 的一部分，这个 `universal.py` 文件通常在 Frida 的构建过程中被 Meson 构建系统调用。以下是一个可能的用户操作路径：

1. **用户修改了 Frida Swift 模块的相关代码或配置文件。**
2. **用户运行 Meson 构建命令（例如 `meson setup builddir` 或 `meson compile -C builddir`）。**
3. **Meson 构建系统会解析 `frida/subprojects/frida-swift/meson.build` 文件。**
4. **在 `meson.build` 文件中，可能会使用 `configure_file` 函数来处理配置文件。**
5. **`configure_file` 函数内部会调用 `mesonbuild.utils.universal.do_conf_file` 函数。**
6. **`do_conf_file` 函数会读取指定的输入文件，并根据配置数据调用 `do_replacement` 和 `do_define` 等函数进行处理。**
7. **如果配置文件中使用了变量替换或宏定义，相关的正则表达式函数（如 `get_variable_regex`）也会被调用。**
8. **如果构建过程中需要执行外部命令，例如编译 Swift 代码，`Popen_safe` 等函数会被调用。**

因此，如果用户在 Frida Swift 模块的构建过程中遇到与配置文件处理、命令执行或平台兼容性相关的问题，可以查看这个 `universal.py` 文件中的相关函数，以了解具体的实现逻辑和可能的错误原因。例如，如果生成的配置文件内容不正确，可能是 `do_replacement` 或 `do_define` 函数的逻辑有问题，或者配置数据本身存在错误。如果外部命令执行失败，可以检查 `Popen_safe` 的调用参数和返回值。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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