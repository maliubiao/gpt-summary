Response:
The user wants a summary of the functionality of the provided Python code snippet, focusing on aspects relevant to reverse engineering, binary interaction, Linux/Android internals, logical reasoning, common user errors, and debugging.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose:** The code is located in `frida/releng/meson/mesonbuild/utils/universal.py`. The `mesonbuild` part strongly suggests this is related to the Meson build system. The `frida` prefix indicates this is used within the Frida project. Thus, the primary function is to provide utility functions for the Frida build process.

2. **Categorize the functions:**  Scan through the code and group functions by their apparent purpose. This involves recognizing patterns and naming conventions. Some initial categories might be:
    * OS detection (is_windows, is_linux, etc.)
    * Path manipulation (default_libdir, default_prefix, has_path_sep)
    * Command-line argument handling (quote_arg, split_args, join_args, expand_arguments)
    * File manipulation (do_conf_file, dump_conf_header, replace_if_different, windows_proof_rmtree, TemporaryDirectoryWinProof)
    * String/List manipulation (listify, listify_array_value, extract_as_list, typeslistify, stringlistify)
    * External process execution (Popen_safe, Popen_safe_logged)
    * Template substitution (do_replacement, do_define, get_variable_regex, do_conf_str, substitute_values, get_filenames_templates_dict)
    * Other utilities (version_string, partition, iter_regexin_iter, detect_subprojects)

3. **Analyze each category for relevance to the specified areas:**

    * **Reverse Engineering:**  The template substitution functions (`do_conf_file`, `dump_conf_header`, `substitute_values`) are key. Frida, being a dynamic instrumentation tool, needs to inject code and potentially configure targets. These functions likely handle the generation of configuration files or code snippets that are used during the instrumentation process. The `Popen_safe` family of functions is also relevant as it's how Frida might interact with external tools or the target process itself.

    * **Binary/Low-Level:** The OS detection and path manipulation functions are foundational for dealing with different binary layouts on various platforms. The file manipulation functions are used for creating and modifying binary files or libraries. The command-line argument handling is important for launching processes with specific arguments, crucial when interacting with the target application or operating system.

    * **Linux/Android Kernel/Framework:** The OS detection (`is_linux`, `is_android`), and functions like `default_libdir` (which has specific logic for Debian-like systems) directly relate to Linux. While not explicitly kernel-level code, this utility helps manage the build process for components that *do* interact with the kernel or Android framework.

    * **Logical Reasoning:** The template substitution functions involve conditional logic based on the presence and values of variables. The argument parsing and splitting functions also implement specific rules. The `replace_if_different` function makes a decision based on comparing file contents.

    * **User/Programming Errors:** The template substitution functions can raise exceptions if variables are missing or of the wrong type. The command-line argument handling has specific rules that, if violated, will lead to errors. File I/O operations are prone to errors if paths are incorrect or permissions are wrong. The `_substitute_values_check_errors` function explicitly performs error checking.

    * **Debugging:**  Understanding how configuration files are generated and how commands are constructed is crucial for debugging Frida's build process. The `Popen_safe_logged` function provides logging, which is a key debugging tool. The paths taken by the conditional logic in functions like `default_libdir` can be debugging clues.

    * **User Operation to Reach Here:** This requires considering the Frida build process. A user would typically download the Frida source code and then use Meson to configure and build it. The `meson` command would internally call these utility functions. Configuration options provided to Meson would influence the paths and variables used.

4. **Illustrate with examples:** For each area, provide concrete examples based on the functions. For instance, for reverse engineering, explain how template substitution might be used to generate code that calls specific functions in a target library.

5. **Address the "Part 2" request:** Since this is part 2 of a 3-part analysis, summarize the core functionality identified in the previous steps. Emphasize that this file provides general utility functions for the Frida build system, focusing on cross-platform compatibility, file manipulation, and template processing.

6. **Refine and organize:** Structure the answer clearly, using headings and bullet points to make it easy to read and understand. Ensure the language is precise and avoids jargon where possible. Double-check that all aspects of the prompt are addressed.
这是 `frida/releng/meson/mesonbuild/utils/universal.py` 文件的功能归纳，作为第二部分，它主要提供了一系列用于 Frida 构建过程的通用工具函数。这些函数涵盖了操作系统检测、路径处理、命令行参数处理、文件操作、模板替换、进程执行等多个方面，旨在提高构建系统的可移植性和效率。

以下是对其主要功能的归纳：

**核心功能:**

1. **操作系统和环境检测:**
    *   提供了一系列 `is_` 开头的函数 (如 `is_windows`, `is_linux`, `is_haiku` 等) 用于检测当前操作系统，以便根据不同的平台执行不同的构建逻辑。
    *   提供获取默认路径的函数 (如 `default_libdir`, `default_prefix` 等)，这些路径会因操作系统而异。

2. **路径和文件操作:**
    *   `has_path_sep`: 检查字符串是否包含路径分隔符。
    *   `replace_if_different`: 仅当文件内容不同时才替换目标文件，以避免不必要的重建。
    *   `dump_conf_header`: 将配置数据以 C 头文件、NASM 汇编或 JSON 格式写入文件。
    *   `do_conf_file`, `do_conf_str`: 处理配置文件，进行变量替换和条件定义。
    *   `windows_proof_rmtree`, `windows_proof_rm`, `TemporaryDirectoryWinProof`: 针对 Windows 平台，提供更可靠的删除文件和目录的函数，处理 Windows 下文件可能被占用的情况。

3. **命令行参数处理:**
    *   `quote_arg`:  正确地引用命令行参数，特别是针对 Windows 平台的特殊处理。
    *   `split_args`:  将命令行字符串分割成参数列表，同样有针对 Windows 的特殊实现。
    *   `join_args`:  将参数列表连接成命令行字符串。
    *   `expand_arguments`:  展开以 `@` 开头的文件中的命令行参数。

4. **数据结构和类型处理:**
    *   `listify`:  确保输入为列表，如果不是则转换为列表。
    *   `listify_array_value`: 将字符串或列表转换为字符串列表，并支持解析类似数组的字符串。
    *   `extract_as_list`: 从字典中提取值并转换为列表。
    *   `typeslistify`: 检查输入是否为指定类型或指定类型的列表。
    *   `stringlistify`: 确保输入为字符串或字符串列表。

5. **模板替换:**
    *   `do_replacement`:  在字符串中根据正则表达式进行变量替换。
    *   `do_define`:  处理 `#mesondefine` 和 `#cmakedefine` 指令，根据配置数据生成 C 宏定义。
    *   `get_variable_regex`:  获取用于匹配变量的正则表达式，支持 Meson 和 CMake 两种格式。
    *   `substitute_values`:  将模板字符串替换为实际值，支持 `@INPUT@`, `@OUTPUT@` 等多种模板。
    *   `get_filenames_templates_dict`:  根据输入输出文件列表生成包含模板字符串的字典。

6. **进程执行:**
    *   `Popen_safe`:  安全地执行子进程，并捕获其输出和错误。它处理了不同操作系统的编码问题。
    *   `Popen_safe_legacy`:  `Popen_safe` 的旧版本，用于处理特定编码情况。
    *   `Popen_safe_logged`:  执行子进程并记录其输出和返回码，方便调试。

7. **其他实用工具:**
    *   `version_string`: 从文本中提取版本号。
    *   `partition`:  根据谓词函数将可迭代对象划分为两个迭代器。
    *   `iter_regexin_iter`:  在一个可迭代对象的每个元素中搜索另一个可迭代对象中的正则表达式。
    *   `detect_subprojects`:  检测子项目目录。

**与逆向方法的关联举例说明:**

*   **模板替换用于生成 Frida Agent 代码片段:** 在构建 Frida Agent 时，可能需要根据目标进程的架构、操作系统等信息生成特定的代码片段。`do_replacement` 和 `do_conf_file` 等函数可以读取包含占位符的模板文件，然后根据配置信息填充这些占位符，生成最终的 Agent 代码。例如，可能需要根据目标是 32 位还是 64 位来定义不同的宏。

*   **命令行参数处理用于启动 Frida 进程:**  Frida 的客户端通常需要通过命令行参数指定目标进程、要加载的脚本等信息。`quote_arg` 和 `join_args` 可以确保这些参数被正确地传递给 Frida 进程，特别是处理包含空格或特殊字符的参数。

*   **进程执行用于与目标进程交互:**  Frida 本身需要启动并与目标进程通信。`Popen_safe` 等函数可能被用于执行一些辅助工具，例如在 Android 上启动 `adb` 命令来与设备通信。

**涉及二进制底层，Linux, Android 内核及框架的知识的举例说明:**

*   **`default_libdir()` 函数:** 在 Linux 系统上，特别是 Debian 系，该函数会使用 `dpkg-architecture` 命令来获取目标架构的多架构路径 (例如 `lib/x86_64-linux-gnu`)。这涉及到 Linux 发行版的二进制文件组织结构知识。在 Android 上，动态库的路径也需要根据架构来确定，虽然代码中没有直接体现 Android 特有的逻辑，但这些通用的路径处理函数为处理 Android 构建提供了基础。

*   **`dump_conf_header()` 函数生成 C 头文件:**  Frida 的某些组件可能使用 C/C++ 编写，需要根据构建配置生成包含宏定义的头文件。这些宏定义可能控制着代码的编译选项、特性开关等，直接影响最终生成的二进制文件的行为。

*   **`Popen_safe()` 函数的编码处理:** 该函数考虑了不同操作系统的默认编码，特别是 Windows 和 Linux 的差异。这对于确保与外部进程的交互不会因为编码问题而出现乱码或错误至关重要，尤其是在处理二进制数据或系统调用时。

**逻辑推理的假设输入与输出:**

**假设输入 (对于 `do_replacement` 函数):**

*   `regex`:  编译后的正则表达式对象，例如 `re.compile(r'@VAR@')`
*   `line`:  字符串 `"The value of VAR is @VAR@"`
*   `variable_format`: `"meson"`
*   `confdata`:  字典 `{'VAR': ('123', 'The variable VAR')}`

**输出:**

*   `("The value of VAR is 123", set())`

**说明:**  `do_replacement` 函数会将 `line` 中的 `@VAR@` 替换为 `confdata` 中 `VAR` 对应的值 `123`。返回的第二个元素是一个空集合，表示没有缺失的变量。

**涉及用户或者编程常见的使用错误举例说明:**

*   **在配置文件中使用错误的变量格式:**  如果用户在 Meson 构建的配置文件中使用了 CMake 风格的变量 `@VAR@` 而不是 Meson 风格的 `@VAR@`，`do_replacement` 函数将无法正确替换，可能导致构建失败或运行时错误。

*   **`#mesondefine` 指令格式错误:** 如果用户在配置文件中使用 `#mesondefine` 指令时，提供的 token 数量不是两个 (例如 `#mesondefine MY_VAR`)，`do_define` 函数会抛出 `MesonException`。

*   **使用未定义的变量进行替换:** 如果在 `do_replacement` 或 `do_define` 中使用的变量名在 `confdata` 中不存在，`do_replacement` 会返回原始字符串，并将缺失的变量名添加到返回的集合中，这可能会导致构建结果不符合预期。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户下载 Frida 源代码:** 用户首先需要获取 Frida 的源代码，通常是通过 Git 克隆仓库。
2. **用户配置构建环境:** 用户需要在本地机器上安装 Meson 和 Ninja (或其他 Meson 支持的构建后端)。
3. **用户运行 Meson 配置命令:** 用户在 Frida 源代码目录下运行 `meson setup builddir` 命令，其中 `builddir` 是构建目录。
4. **Meson 解析 `meson.build` 文件:** Meson 会读取项目根目录下的 `meson.build` 文件以及其他相关的 `meson` 文件，这些文件描述了项目的构建规则。
5. **调用配置生成相关的函数:** 在解析 `meson.build` 文件的过程中，可能会调用到需要生成配置文件的函数，例如 `configure_file`。
6. **`configure_file` 函数调用 `do_conf_file`:**  `configure_file` 函数会读取模板配置文件，并调用 `frida/releng/meson/mesonbuild/utils/universal.py` 中的 `do_conf_file` 函数来进行变量替换和生成最终的配置文件。
7. **`do_conf_file` 函数执行变量替换:**  `do_conf_file` 函数会读取配置文件内容，根据提供的配置数据 ( `confdata` ) 和变量格式，调用 `do_replacement` 和 `do_define` 函数来替换变量和处理宏定义。

**调试线索:** 如果用户在 Frida 的构建过程中遇到与配置文件生成相关的问题，例如生成的配置文件中变量没有被正确替换，可以按照以下步骤进行调试：

*   **检查 `meson.build` 文件:** 确认 `configure_file` 函数的调用是否正确，模板文件路径和输出文件路径是否正确。
*   **检查配置文件模板:**  确认模板文件中使用的变量格式是否与 Meson 或 CMake 的约定一致。
*   **检查配置数据 (`confdata`):**  确认传递给 `do_conf_file` 的配置数据是否包含了所需的变量及其正确的值。
*   **使用 Meson 的调试输出:**  Meson 提供了一些调试选项，可以查看构建过程中的详细信息，例如 `-Ddebug=true`。
*   **查看生成的临时文件:**  `do_conf_file` 函数会先生成一个临时文件 ( `dst_tmp` )，可以查看这个临时文件的内容，确认变量替换是否按预期进行。

总而言之，`frida/releng/meson/mesonbuild/utils/universal.py` 提供了一组基础的、跨平台的工具函数，支撑着 Frida 的构建过程，涵盖了从操作系统检测到进程执行的多个方面，并处理了构建过程中常见的任务，例如配置文件生成和命令行参数处理。了解这些函数的功能有助于理解 Frida 的构建系统，并在遇到构建问题时提供调试思路。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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