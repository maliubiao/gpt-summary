Response:
The user wants a summary of the Python code provided, focusing on its functionality, relationship to reverse engineering, use of low-level concepts, logical reasoning, potential user errors, and how a user might end up using this code.

Here's a breakdown of how to approach this:

1. **High-Level Functionality:** Understand the core purpose of the `universal.py` file within the Frida context. The path `frida/subprojects/frida-core/releng/meson/mesonbuild/utils/universal.py` strongly suggests it's a utility module used during the build process (using Meson).

2. **Analyze Individual Functions:** Go through each function and understand what it does. Group them by their apparent purpose:
    - Version parsing (`detect_version`)
    - Path/directory handling (`default_libdir`, `default_libexecdir`, etc.)
    - String/argument manipulation (`has_path_sep`, `quote_arg`, `split_args`, `join_args`)
    - Configuration file processing (`do_replacement`, `do_define`, `do_conf_str`, `do_conf_file`, `dump_conf_header`)
    - Process execution (`Popen_safe`, `Popen_safe_legacy`, `Popen_safe_logged`)
    - List manipulation (`listify`, `listify_array_value`, `extract_as_list`, `typeslistify`, `stringlistify`)
    - Argument expansion (`expand_arguments`)
    - Iteration utilities (`partition`, `iter_regexin_iter`)
    - Template substitution (`substitute_values`, `get_filenames_templates_dict`)
    - File system operations (`replace_if_different`, `windows_proof_rmtree`, `windows_proof_rm`, `TemporaryDirectoryWinProof`, `detect_subprojects`)

3. **Relate to Reverse Engineering:** Identify functions that might be indirectly useful in a reverse engineering context. For example, anything that deals with manipulating strings, paths, or executing external processes.

4. **Identify Low-Level Concepts:** Look for interactions with the operating system, particularly Linux and Android, and handling of binary data or system calls (though not directly visible in this code).

5. **Analyze Logical Reasoning:** Determine if any functions involve conditional logic or decision-making based on input. Provide example inputs and expected outputs.

6. **Consider User Errors:** Think about how a user interacting with Frida or the build system might trigger errors handled by this code, or misuse the functions provided.

7. **Trace User Interaction:**  Imagine the steps a developer would take to build Frida, and where this utility module would be involved.

8. **Synthesize a Summary:** Combine the findings from the above steps into a concise summary of the file's purpose and key functionalities.

**Self-Correction/Refinement during the thought process:**

- Initially, I might focus heavily on the "reverse engineering" aspect. However, upon closer inspection, the code is primarily build-related. Adjust the emphasis accordingly.
- Some functions seem very specific to the build system (e.g., `do_conf_file`). It's important to acknowledge this context rather than trying to fit everything into a reverse engineering framework.
- The regular expressions for version detection are quite intricate. It's worth noting their complexity and purpose without getting bogged down in the details of the regex itself.
- The Windows-specific functions for file deletion are interesting. Highlight the reason for their existence (handling file locking).
- The template substitution functions are crucial for understanding how build configurations are generated. Emphasize their role.

By following these steps, I can generate a comprehensive and accurate summary of the `universal.py` file as requested by the user.
这是 `frida/subprojects/frida-core/releng/meson/mesonbuild/utils/universal.py` 文件的第二部分代码。在第一部分中，我们看到了它主要包含了一些用于判断操作系统类型、获取默认路径以及进行字符串处理的通用工具函数。

现在我们来分析第二部分的功能：

**1. 命令行参数处理 (针对 Windows 和非 Windows)：**

   - **`quote_arg(arg: str) -> str`**:  对命令行参数进行引用，以确保在传递给 shell 时被正确解析。
     - **Windows 版本：** 实现了符合 Windows 命令行参数解析规则的引用逻辑，处理了反斜杠和双引号的转义。这与逆向工程中的命令行工具分析相关，例如，如果你在逆向分析一个通过命令行接收参数的 Windows 程序，理解参数是如何被引用的可以帮助你构造有效的测试用例。
       - **举例：** 假设你要分析的 Windows 程序 `target.exe` 接收一个包含空格和引号的参数。使用 `quote_arg` 可以生成 `target.exe "argument with spaces and \"quotes\""` 这样的字符串，确保 `target.exe` 正确接收。
     - **非 Windows 版本：** 直接使用 `shlex.quote`。
   - **`split_args(cmd: str) -> T.List[str]`**: 将命令行字符串分割成参数列表。
     - **Windows 版本：** 实现了符合 Windows 命令行参数解析规则的分割逻辑，处理了引号和转义。 这对于逆向分析时解析目标程序启动的子进程的命令行非常有用。
       - **举例：** 如果你通过 Frida hook 捕获到 Windows 程序启动了一个进程，命令行是 `"child.exe" -a "value with space" -b other_value`，`split_args` 可以将其解析为 `['child.exe', '-a', 'value with space', '-b', 'other_value']`。
     - **非 Windows 版本：** 直接使用 `shlex.split`。
   - **`join_args(args: T.Iterable[str]) -> str`**: 将参数列表连接成一个命令行字符串，使用 `quote_arg` 对每个参数进行引用。这在你需要构造并执行外部命令时很有用，例如，在 Frida 脚本中调用系统工具。
     - **举例：**  `join_args(['ls', '-l', 'path with space'])` 将生成 `'ls' '-l' 'path with space'` (在非 Windows 系统上，引号可能不同)。

**2. 配置文件的处理：**

   - **`do_replacement(regex: T.Pattern[str], line: str, variable_format: Literal['meson', 'cmake', 'cmake@'], confdata: T.Union[T.Dict[str, T.Tuple[str, T.Optional[str]]], 'ConfigurationData']) -> T.Tuple[str, T.Set[str]]`**: 在文本行中根据正则表达式替换变量。支持 Meson 和 CMake 两种变量格式。
     - **逻辑推理：**
       - **假设输入：** `regex` 匹配 `@VAR@` 或 `${VAR}`，`line` 是 `The value is @MY_VAR@.`, `variable_format` 是 `'meson'`，`confdata` 是 `{'MY_VAR': ('test_value', 'description')}`。
       - **输出：** `('The value is test_value.', set())`
       - **假设输入：**  `regex` 匹配 `${VAR}`，`line` 是 `The value is \${MY_VAR}.`, `variable_format` 是 `'cmake'`。
       - **输出：** `('The value is ${MY_VAR}.', set())`  （`\` 转义了 `${`）
       - **用户错误：** 如果 `confdata` 中没有 `MY_VAR`，则会返回带有未替换变量的字符串，并且 `missing_variables` 集合中会包含 `MY_VAR`。
   - **`do_define(regex: T.Pattern[str], line: str, confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], subproject: T.Optional[SubProject] = None) -> str`**: 处理配置文件中的 `#mesondefine` 或 `#cmakedefine` 指令，根据 `confdata` 中的值生成 C 预处理器宏定义。
     - **二进制底层知识：** 这直接关系到编译过程中的宏定义，这些宏定义会影响最终生成的二进制代码。逆向工程师在分析二进制文件时，了解编译时的宏定义可以帮助理解代码的行为。
     - **逻辑推理：**
       - **假设输入：** `line` 是 `#mesondefine MY_FEATURE true`, `confdata` 是 `{'MY_FEATURE': (True, 'Enable my feature')}`, `variable_format` 是 `'meson'`。
       - **输出：** `#define MY_FEATURE\n`
       - **假设输入：** `line` 是 `#cmakedefine ENABLE_LOGGING 1`, `confdata` 是 `{'ENABLE_LOGGING': (True, 'Enable logging')}`, `variable_format` 是 `'cmake'`。
       - **输出：** `#define ENABLE_LOGGING 1\n`
       - **用户错误：** 如果 `#mesondefine` 后面的变量名在 `confdata` 中找不到，会生成 `/* #undef VARNAME */` 的注释，除非是 CMake 的布尔定义，会定义为 0。
   - **`get_variable_regex(variable_format: Literal['meson', 'cmake', 'cmake@'] = 'meson') -> T.Pattern[str]`**: 根据指定的格式返回用于匹配变量的正则表达式。
   - **`do_conf_str(src: str, data: T.List[str], confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], subproject: T.Optional[SubProject] = None) -> T.Tuple[T.List[str], T.Set[str], bool]`**: 处理配置文件内容（列表形式），进行变量替换和宏定义处理。
     - **用户操作到达这里：** Meson 构建系统在处理 `configure_file()` 函数时，会读取源文件内容，并调用此函数进行处理。
   - **`do_conf_file(src: str, dst: str, confdata: 'ConfigurationData', variable_format: Literal['meson', 'cmake', 'cmake@'], encoding: str = 'utf-8', subproject: T.Optional[SubProject] = None) -> T.Tuple[T.Set[str], bool]`**: 处理单个配置文件，读取文件内容，调用 `do_conf_str` 进行处理，并将结果写入目标文件。
     - **用户操作到达这里：** 用户在 `meson.build` 文件中使用 `configure_file()` 函数指定要处理的配置文件及其目标路径和配置数据。Meson 在构建过程中会执行这个操作。
   - **`CONF_C_PRELUDE` 和 `CONF_NASM_PRELUDE`**: 定义了生成的 C 和汇编头文件的序言，包含版权信息和宏定义保护。
   - **`_dump_c_header(ofile: T.TextIO, cdata: ConfigurationData, output_format: Literal['c', 'nasm'], macro_name: T.Optional[str]) -> None`**: 将配置数据以 C 或汇编头文件的格式写入文件。
   - **`dump_conf_header(ofilename: str, cdata: ConfigurationData, output_format: Literal['c', 'nasm', 'json'], macro_name: T.Optional[str]) -> None`**: 将配置数据导出为 C/汇编头文件或 JSON 文件。
     - **用户操作到达这里：** 用户在 `meson.build` 文件中使用 `configuration_data()` 创建配置数据对象，并使用 `write_header()` 方法指定输出头文件的路径和格式。

**3. 文件操作工具：**

   - **`replace_if_different(dst: str, dst_tmp: str) -> None`**: 仅当临时文件内容与目标文件内容不同时才替换目标文件，避免不必要的重新编译。
   - **`listify(item: T.Any, flatten: bool = True) -> T.List[T.Any]`**: 将任何类型的项转换为列表。
   - **`listify_array_value(value: T.Union[str, T.List[str]], shlex_split_args: bool = False) -> T.List[str]`**: 将字符串或字符串列表转换为字符串列表，并可以根据需要使用 `shlex.split` 分割字符串。
   - **`extract_as_list(dict_object: T.Dict[_T, _U], key: _T, pop: bool = False) -> T.List[_U]`**: 从字典中提取指定键的值并转换为列表。
   - **`typeslistify(item: 'T.Union[_T, T.Sequence[_T]]', types: 'T.Union[T.Type[_T], T.Tuple[T.Type[_T]]]') -> T.List[_T]`**: 确保给定的项或项列表是指定的类型。
   - **`stringlistify(item: T.Union[T.Any, T.Sequence[T.Any]]) -> T.List[str]`**: 确保给定的项或项列表是字符串类型。

**归纳一下第二部分的功能：**

这部分代码主要负责处理构建过程中的配置文件和命令行参数。它提供了以下核心功能：

1. **命令行参数的引用和分割**，特别是针对 Windows 平台做了特殊处理，这对于 Frida 在不同平台上执行外部命令至关重要。
2. **配置文件的读取、解析和处理**，支持 Meson 和 CMake 两种配置格式，能够进行变量替换和宏定义生成，用于生成最终的配置文件（通常是 C/C++ 头文件）。
3. **提供了一些通用的文件和列表操作工具函数**，用于简化构建过程中的数据处理。

这些功能是 Frida 构建系统的重要组成部分，确保了在不同平台和配置下能够正确生成构建所需的各种文件。与逆向工程的关联主要体现在理解目标程序构建过程中的配置和命令行参数，这有助于更深入地理解其行为。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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