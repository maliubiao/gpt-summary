Response:
The user wants a summary of the functionality of the provided Python code. I need to analyze each function and class in the code and describe its purpose. I also need to identify any relationships to reverse engineering, low-level operations, Linux/Android internals, logical reasoning, potential user errors, and how a user might interact with this code.

Here's a breakdown of the code's components and potential connections:

1. **`group_trials_by_basename(trials: T.List[str]) -> T.Dict[str, T.List[str]]`**: This function groups a list of strings based on their base filenames. It could be used in a reverse engineering context to organize test results or libraries.

2. **`substring_is_in_list(substr: str, strlist: T.List[str]) -> bool`**:  A simple utility to check if a substring exists within any string in a list. This might be used for filtering or searching through names or paths, relevant in reverse engineering.

3. **`OrderedSet(T.MutableSet[_T])`**:  A custom set implementation that preserves the order of insertion. This could be useful for maintaining the order of libraries or test cases, which can be important in certain reverse engineering scenarios.

4. **`relpath(path: str, start: str) -> str`**: Calculates the relative path between two paths, handling potential Windows drive letter issues. Path manipulation is fundamental in build systems and relevant in understanding file system interactions during reverse engineering.

5. **`path_is_in_root(path: Path, root: Path, resolve: bool = False) -> bool`**: Checks if a given path is within a specified root directory. This is common in build systems for ensuring file organization and can be useful in reverse engineering to understand the project structure.

6. **`relative_to_if_possible(path: Path, root: Path, resolve: bool = False) -> Path`**:  Similar to `relpath`, but returns the original path if a relative path cannot be determined.

7. **`LibType(enum.IntEnum)`**:  An enumeration defining different types of libraries (shared, static, etc.). This is core to building software and understanding the linking process, relevant in reverse engineering.

8. **`ProgressBarFallback` and `ProgressBarTqdm`**: Implementations for displaying progress bars. User interaction during build processes triggers these.

9. **`RealPathAction(argparse.Action)`**: A custom argparse action to resolve paths to their absolute, real paths. Command-line arguments are a primary user interaction point.

10. **`get_wine_shortpath(winecmd: T.List[str], wine_paths: T.List[str], workdir: T.Optional[str] = None) -> str`**:  Specifically deals with shortening paths for Wine environments due to path length limitations. This involves interaction with the Wine compatibility layer, relevant when reverse engineering or building for Windows from a non-Windows environment. It touches upon subprocess execution and environment variables.

11. **`run_once(func: T.Callable[..., _T]) -> T.Callable[..., _T]`**: A decorator to ensure a function is executed only once. This can be useful for initialization or resource management.

12. **`generate_list(func: T.Callable[..., T.Generator[_T, None, None]]) -> T.Callable[..., T.List[_T]]`**: A decorator to convert a generator function into a function that returns a list.

13. **`OptionType(enum.IntEnum)`**: Enumerates different types of build options.

14. **`_classify_argument(key: 'OptionKey') -> OptionType`**:  Categorizes build options.

15. **`OptionKey`**: A class representing a build option key, allowing for structured access to option information (name, subproject, etc.). This is fundamental to the Meson build system.

16. **`pickle_load(filename: str, object_name: str, object_type: T.Type[_PL], suggest_reconfigure: bool = True) -> _PL`**: Loads Python objects from pickle files, with error handling for corruption and version mismatches. This is part of the build system's state management.

17. **`first(iter: T.Iterable[_T], predicate: T.Callable[[_T], bool]) -> T.Optional[_T]`**:  Finds the first element in an iterable that satisfies a given condition.

I will now synthesize these observations into a structured summary addressing the user's specific requests.
这是 `frida/subprojects/frida-swift/releng/meson/mesonbuild/utils/universal.py` 文件的第 3 部分，该文件是 Frida 动态instrumentation 工具的一部分。根据提供的代码片段，以下是其功能的归纳：

**主要功能归纳:**

该文件的主要功能是提供各种通用的实用工具函数和类，用于 Frida 构建系统的其他部分。这些工具涵盖了文件系统操作、集合操作、进度显示、命令行参数处理、Wine 环境适配以及构建选项管理等方面。

**详细功能列表:**

*   **集合操作:**
    *   **`OrderedSet` 类:**  实现了一个有序的集合，它会记住元素被添加的顺序。这在需要保持元素顺序的场景下非常有用，例如处理依赖关系或执行顺序。
    *   **`difference(self, set_: T.Iterable[_T]) -> 'OrderedSet[_T]'` 和 `difference_update(self, iterable: T.Iterable[_T]) -> None`:**  提供了计算集合差集的功能。

*   **文件系统操作:**
    *   **`relpath(path: str, start: str) -> str`:**  计算从 `start` 路径到 `path` 的相对路径。它特别处理了 Windows 跨驱动器的情况，如果无法计算相对路径则返回原始绝对路径。
    *   **`path_is_in_root(path: Path, root: Path, resolve: bool = False) -> bool`:** 检查给定的 `path` 是否位于 `root` 目录下。可以选择是否先解析路径的符号链接。
    *   **`relative_to_if_possible(path: Path, root: Path, resolve: bool = False) -> Path`:** 尝试计算 `path` 相对于 `root` 的相对路径，如果失败则返回原始 `path`。

*   **枚举类型:**
    *   **`LibType(enum.IntEnum)`:** 定义了库的类型，包括 `SHARED` (共享库), `STATIC` (静态库), `PREFER_SHARED` (优先共享库), `PREFER_STATIC` (优先静态库)。

*   **进度显示:**
    *   **`ProgressBarFallback` 类:**  当 `tqdm` 库不可用时，提供一个简单的文本进度条回退实现。
    *   **`ProgressBarTqdm` 类:**  如果安装了 `tqdm` 库，则使用 `tqdm` 提供更丰富的进度条显示，特别针对下载类型的进度条进行了优化。
    *   **`ProgressBar` 类型别名:**  根据 `tqdm` 的可用性，指向 `ProgressBarTqdm` 或 `ProgressBarFallback`。

*   **命令行参数处理:**
    *   **`RealPathAction(argparse.Action)` 类:**  一个自定义的 `argparse` Action，用于将命令行参数指定的路径转换为绝对的、真实的路径。

*   **Wine 环境适配:**
    *   **`get_wine_shortpath(winecmd: T.List[str], wine_paths: T.List[str], workdir: T.Optional[str] = None) -> str`:**  用于处理 Wine 环境中路径长度限制的问题。它尝试将路径缩短，优先使用相对于 `workdir` 的相对路径，并将绝对路径转换为 Windows 短路径格式。如果 Wine 版本高于 6.4，则直接返回原始路径，因为该版本已修复此限制。

*   **函数装饰器:**
    *   **`run_once(func: T.Callable[..., _T]) -> T.Callable[..., _T]`:**  一个装饰器，确保被装饰的函数只执行一次，并缓存其返回值。
    *   **`generate_list(func: T.Callable[..., T.Generator[_T, None, None]]) -> T.Callable[..., T.List[_T]]`:**  一个装饰器，将一个生成器函数转换为返回列表的函数。

*   **构建选项管理:**
    *   **`OptionType(enum.IntEnum)`:** 定义了构建选项的类型，例如 `BUILTIN` (内置选项), `BACKEND` (后端选项), `BASE` (基础选项), `COMPILER` (编译器选项), `PROJECT` (项目选项)。
    *   **`_classify_argument(key: 'OptionKey') -> OptionType`:**  根据 `OptionKey` 的属性，对其进行分类，返回对应的 `OptionType`。
    *   **`OptionKey` 类:**  表示一个构建选项的键。它包含了选项的名称、子项目、目标机器、语言、模块等信息，并提供了用于解析和操作选项键的方法。

*   **持久化:**
    *   **`pickle_load(filename: str, object_name: str, object_type: T.Type[_PL], suggest_reconfigure: bool = True) -> _PL`:**  从 pickle 文件中加载 Python 对象，并进行错误处理，包括文件损坏、类型不匹配以及 Meson 版本不兼容等情况。

*   **迭代器工具:**
    *   **`first(iter: T.Iterable[_T], predicate: T.Callable[[_T], bool]) -> T.Optional[_T]`:**  在可迭代对象中查找第一个满足给定谓词的元素。

**与逆向方法的关联及举例:**

*   **`group_trials_by_basename`:** 在逆向工程中，可能需要批量测试多个二进制文件或库。这个函数可以用来将测试结果按照文件名进行分组，方便分析每个二进制文件的测试情况。
    *   **假设输入:** `trials = ["test_moduleA.log", "test_moduleB.log", "test_moduleA_v2.log"]`
    *   **输出:** `{"test_moduleA": ["test_moduleA.log", "test_moduleA_v2.log"], "test_moduleB": ["test_moduleB.log"]}`

*   **`OrderedSet`:**  在分析动态库加载顺序时，可以使用 `OrderedSet` 来记录加载的库，并保持其加载的先后顺序。这对于理解程序的行为和依赖关系至关重要。

*   **`relpath` 和 `path_is_in_root`:** 在逆向分析复杂的软件项目时，理解文件结构非常重要。这两个函数可以帮助确定某个文件是否属于项目的某个特定部分，或者计算相关路径。

*   **`LibType`:** 了解目标程序依赖的是共享库还是静态库，对于逆向分析和漏洞研究非常重要。共享库需要考虑运行时加载和动态链接，而静态库则会将代码直接编译到可执行文件中。

**涉及二进制底层，Linux, Android内核及框架的知识及举例:**

*   **`LibType`:**  涉及到共享库和静态库的概念，这是操作系统和链接器的基础知识。在 Linux 和 Android 中，动态链接器负责在程序运行时加载共享库。
*   **`get_wine_shortpath`:**  直接涉及到 Windows 操作系统和 Wine 兼容层。Wine 尝试在 Linux 系统上运行 Windows 程序，需要处理两者在文件路径表示上的差异。对 Windows 短路径的了解是底层操作系统知识的一部分。
*   **`pickle_load`:**  涉及到 Python 对象的序列化和反序列化，这在很多框架和系统中用于持久化数据或传递状态。理解对象在内存中的表示以及如何将其转换为二进制形式是底层知识的一部分。

**逻辑推理的举例说明:**

*   **`substring_is_in_list`:**
    *   **假设输入:** `substr = "error"`, `strlist = ["file_not_found", "an_error_occurred", "success"]`
    *   **输出:** `True` (因为 "an\_error\_occurred" 包含 "error")

*   **`path_is_in_root`:**
    *   **假设输入:** `path = Path("/home/user/project/src/file.c")`, `root = Path("/home/user/project")`
    *   **输出:** `True`

**涉及用户或编程常见的使用错误及举例说明:**

*   **`relpath`:** 用户可能会提供不相关的路径，导致无法计算相对路径，虽然该函数会返回绝对路径避免崩溃，但可能会产生非预期的结果。
    *   **用户操作:** 在构建脚本中，错误地指定了源文件路径和构建目录的起始路径。

*   **`pickle_load`:**
    *   **常见错误:** 用户可能尝试使用旧版本的 Meson 构建的缓存文件。
    *   **错误信息:**  `f"{object_name} file {filename!r} references functions or classes that don't exist. This probably means that it was generated with an old version of meson."`。
    *   **调试线索:**  用户报告构建错误，查看错误日志发现 pickle 加载失败，提示版本不兼容。

*   **`get_wine_shortpath`:**
    *   **常见错误:**  用户的 Wine 环境配置不正确，导致无法执行 `wine` 命令。
    *   **错误信息:** `Could not shorten WINEPATH: [Errno 2] No such file or directory: 'wine'` (或其他与 `subprocess.CalledProcessError` 相关的错误)。
    *   **调试线索:**  在 Windows 构建过程中，出现与路径相关的错误，并且日志中显示无法执行 `wine` 命令。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户执行 Frida 的构建命令:** 用户在他们的开发环境中，尝试构建 Frida，例如使用 `meson setup build` 或 `ninja` 命令。
2. **Meson 构建系统执行:** Meson 读取项目的 `meson.build` 文件，并开始配置和生成构建文件。
3. **处理 Frida Swift 子项目:** 在处理 Frida 的 Swift 子项目时，Meson 会执行与该子项目相关的构建逻辑。
4. **调用 `universal.py` 中的工具函数:**  在 Swift 子项目的构建过程中，可能需要进行文件路径处理、库类型判断、进度显示等操作。这时，Meson 会调用 `frida/subprojects/frida-swift/releng/meson/mesonbuild/utils/universal.py` 文件中定义的函数。
5. **例如，`get_wine_shortpath` 的调用:** 如果用户在非 Windows 系统上构建针对 Windows 的 Frida 组件，并且依赖的库路径很长，Meson 可能会调用 `get_wine_shortpath` 来缩短路径以适应 Wine 的限制。
6. **发生错误:** 如果用户的 Wine 环境没有正确配置，或者使用的 Meson 版本与缓存文件不兼容，则可能会在执行到 `get_wine_shortpath` 或 `pickle_load` 等函数时发生错误。
7. **查看错误信息和堆栈跟踪:** 用户会看到构建失败的错误信息，其中可能包含与 `universal.py` 文件相关的堆栈跟踪信息，指示错误发生在哪个函数。
8. **分析调试线索:**  通过查看错误信息，例如 "Could not shorten WINEPATH" 或 pickle 加载失败的提示，结合堆栈跟踪，可以定位到 `universal.py` 文件中的具体函数，并进一步分析问题的原因，例如 Wine 环境配置问题或 Meson 版本不兼容。

总而言之，`universal.py` 文件提供了一系列底层且通用的工具，服务于 Frida 构建系统的各个环节。用户通常不会直接与这个文件交互，但他们的构建操作会间接地触发这些工具函数的执行，当出现构建错误时，这个文件中的代码和错误信息会成为重要的调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/utils/universal.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
nd(trial)
            else:
                result[basename] = [trial]
    return result


def substring_is_in_list(substr: str, strlist: T.List[str]) -> bool:
    for s in strlist:
        if substr in s:
            return True
    return False


class OrderedSet(T.MutableSet[_T]):
    """A set that preserves the order in which items are added, by first
    insertion.
    """
    def __init__(self, iterable: T.Optional[T.Iterable[_T]] = None):
        self.__container: T.OrderedDict[_T, None] = collections.OrderedDict()
        if iterable:
            self.update(iterable)

    def __contains__(self, value: object) -> bool:
        return value in self.__container

    def __iter__(self) -> T.Iterator[_T]:
        return iter(self.__container.keys())

    def __len__(self) -> int:
        return len(self.__container)

    def __repr__(self) -> str:
        # Don't print 'OrderedSet("")' for an empty set.
        if self.__container:
            return 'OrderedSet([{}])'.format(
                ', '.join(repr(e) for e in self.__container.keys()))
        return 'OrderedSet()'

    def __reversed__(self) -> T.Iterator[_T]:
        return reversed(self.__container.keys())

    def add(self, value: _T) -> None:
        self.__container[value] = None

    def discard(self, value: _T) -> None:
        if value in self.__container:
            del self.__container[value]

    def move_to_end(self, value: _T, last: bool = True) -> None:
        self.__container.move_to_end(value, last)

    def pop(self, last: bool = True) -> _T:
        item, _ = self.__container.popitem(last)
        return item

    def update(self, iterable: T.Iterable[_T]) -> None:
        for item in iterable:
            self.__container[item] = None

    def difference(self, set_: T.Iterable[_T]) -> 'OrderedSet[_T]':
        return type(self)(e for e in self if e not in set_)

    def difference_update(self, iterable: T.Iterable[_T]) -> None:
        for item in iterable:
            self.discard(item)

def relpath(path: str, start: str) -> str:
    # On Windows a relative path can't be evaluated for paths on two different
    # drives (i.e. c:\foo and f:\bar).  The only thing left to do is to use the
    # original absolute path.
    try:
        return os.path.relpath(path, start)
    except (TypeError, ValueError):
        return path

def path_is_in_root(path: Path, root: Path, resolve: bool = False) -> bool:
    # Check whether a path is within the root directory root
    try:
        if resolve:
            path.resolve().relative_to(root.resolve())
        else:
            path.relative_to(root)
    except ValueError:
        return False
    return True

def relative_to_if_possible(path: Path, root: Path, resolve: bool = False) -> Path:
    try:
        if resolve:
            return path.resolve().relative_to(root.resolve())
        else:
            return path.relative_to(root)
    except ValueError:
        return path

class LibType(enum.IntEnum):

    """Enumeration for library types."""

    SHARED = 0
    STATIC = 1
    PREFER_SHARED = 2
    PREFER_STATIC = 3


class ProgressBarFallback:  # lgtm [py/iter-returns-non-self]
    '''
    Fallback progress bar implementation when tqdm is not found

    Since this class is not an actual iterator, but only provides a minimal
    fallback, it is safe to ignore the 'Iterator does not return self from
    __iter__ method' warning.
    '''
    def __init__(self, iterable: T.Optional[T.Iterable[str]] = None, total: T.Optional[int] = None,
                 bar_type: T.Optional[str] = None, desc: T.Optional[str] = None,
                 disable: T.Optional[bool] = None):
        if iterable is not None:
            self.iterable = iter(iterable)
            return
        self.total = total
        self.done = 0
        self.printed_dots = 0
        self.disable = not mlog.colorize_console() if disable is None else disable
        if not self.disable:
            if self.total and bar_type == 'download':
                print('Download size:', self.total)
            if desc:
                print(f'{desc}: ', end='')

    # Pretend to be an iterator when called as one and don't print any
    # progress
    def __iter__(self) -> T.Iterator[str]:
        return self.iterable

    def __next__(self) -> str:
        return next(self.iterable)

    def print_dot(self) -> None:
        if not self.disable:
            print('.', end='')
            sys.stdout.flush()
        self.printed_dots += 1

    def update(self, progress: int) -> None:
        self.done += progress
        if not self.total:
            # Just print one dot per call if we don't have a total length
            self.print_dot()
            return
        ratio = int(self.done / self.total * 10)
        while self.printed_dots < ratio:
            self.print_dot()

    def close(self) -> None:
        if not self.disable:
            print()

try:
    from tqdm import tqdm
except ImportError:
    # ideally we would use a typing.Protocol here, but it's part of typing_extensions until 3.8
    ProgressBar: T.Union[T.Type[ProgressBarFallback], T.Type[ProgressBarTqdm]] = ProgressBarFallback
else:
    class ProgressBarTqdm(tqdm):
        def __init__(self, *args: T.Any, bar_type: T.Optional[str] = None, **kwargs: T.Any) -> None:
            if bar_type == 'download':
                kwargs.update({'unit': 'B',
                               'unit_scale': True,
                               'unit_divisor': 1024,
                               'leave': True,
                               'bar_format': '{l_bar}{bar}| {n_fmt}/{total_fmt} {rate_fmt} eta {remaining}',
                               })

            else:
                kwargs.update({'leave': False,
                               'bar_format': '{l_bar}{bar}| {n_fmt}/{total_fmt} eta {remaining}',
                               })
            super().__init__(*args, **kwargs)

    ProgressBar = ProgressBarTqdm


class RealPathAction(argparse.Action):
    def __init__(self, option_strings: T.List[str], dest: str, default: str = '.', **kwargs: T.Any):
        default = os.path.abspath(os.path.realpath(default))
        super().__init__(option_strings, dest, nargs=None, default=default, **kwargs)

    def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace,
                 values: T.Union[str, T.Sequence[T.Any], None], option_string: T.Optional[str] = None) -> None:
        assert isinstance(values, str)
        setattr(namespace, self.dest, os.path.abspath(os.path.realpath(values)))


def get_wine_shortpath(winecmd: T.List[str], wine_paths: T.List[str],
                       workdir: T.Optional[str] = None) -> str:
    '''
    WINEPATH size is limited to 1024 bytes which can easily be exceeded when
    adding the path to every dll inside build directory. See
    https://bugs.winehq.org/show_bug.cgi?id=45810.

    To shorten it as much as possible we use path relative to `workdir`
    where possible and convert absolute paths to Windows shortpath (e.g.
    "/usr/x86_64-w64-mingw32/lib" to "Z:\\usr\\X86_~FWL\\lib").

    This limitation reportedly has been fixed with wine >= 6.4
    '''

    # Remove duplicates
    wine_paths = list(OrderedSet(wine_paths))

    # Check if it's already short enough
    wine_path = ';'.join(wine_paths)
    if len(wine_path) <= 1024:
        return wine_path

    # Check if we have wine >= 6.4
    from ..programs import ExternalProgram
    wine = ExternalProgram('wine', winecmd, silent=True)
    if version_compare(wine.get_version(), '>=6.4'):
        return wine_path

    # Check paths that can be reduced by making them relative to workdir.
    rel_paths: T.List[str] = []
    if workdir:
        abs_paths: T.List[str] = []
        for p in wine_paths:
            try:
                rel = Path(p).relative_to(workdir)
                rel_paths.append(str(rel))
            except ValueError:
                abs_paths.append(p)
        wine_paths = abs_paths

    if wine_paths:
        # BAT script that takes a list of paths in argv and prints semi-colon separated shortpaths
        with NamedTemporaryFile('w', suffix='.bat', encoding='utf-8', delete=False) as bat_file:
            bat_file.write('''
            @ECHO OFF
            for %%x in (%*) do (
                echo|set /p=;%~sx
            )
            ''')
        try:
            stdout = subprocess.check_output(winecmd + ['cmd', '/C', bat_file.name] + wine_paths,
                                             encoding='utf-8', stderr=subprocess.DEVNULL)
            stdout = stdout.strip(';')
            if stdout:
                wine_paths = stdout.split(';')
            else:
                mlog.warning('Could not shorten WINEPATH: empty stdout')
        except subprocess.CalledProcessError as e:
            mlog.warning(f'Could not shorten WINEPATH: {str(e)}')
        finally:
            os.unlink(bat_file.name)
    wine_path = ';'.join(rel_paths + wine_paths)
    if len(wine_path) > 1024:
        mlog.warning('WINEPATH exceeds 1024 characters which could cause issues')
    return wine_path


def run_once(func: T.Callable[..., _T]) -> T.Callable[..., _T]:
    ret: T.List[_T] = []

    @wraps(func)
    def wrapper(*args: T.Any, **kwargs: T.Any) -> _T:
        if ret:
            return ret[0]

        val = func(*args, **kwargs)
        ret.append(val)
        return val

    return wrapper


def generate_list(func: T.Callable[..., T.Generator[_T, None, None]]) -> T.Callable[..., T.List[_T]]:
    @wraps(func)
    def wrapper(*args: T.Any, **kwargs: T.Any) -> T.List[_T]:
        return list(func(*args, **kwargs))

    return wrapper


class OptionType(enum.IntEnum):

    """Enum used to specify what kind of argument a thing is."""

    BUILTIN = 0
    BACKEND = 1
    BASE = 2
    COMPILER = 3
    PROJECT = 4

# This is copied from coredata. There is no way to share this, because this
# is used in the OptionKey constructor, and the coredata lists are
# OptionKeys...
_BUILTIN_NAMES = {
    'prefix',
    'bindir',
    'datadir',
    'includedir',
    'infodir',
    'libdir',
    'licensedir',
    'libexecdir',
    'localedir',
    'localstatedir',
    'mandir',
    'sbindir',
    'sharedstatedir',
    'sysconfdir',
    'auto_features',
    'backend',
    'buildtype',
    'debug',
    'default_library',
    'errorlogs',
    'genvslite',
    'install_umask',
    'layout',
    'optimization',
    'prefer_static',
    'stdsplit',
    'strip',
    'unity',
    'unity_size',
    'warning_level',
    'werror',
    'wrap_mode',
    'force_fallback_for',
    'pkg_config_path',
    'cmake_prefix_path',
    'vsenv',
}


def _classify_argument(key: 'OptionKey') -> OptionType:
    """Classify arguments into groups so we know which dict to assign them to."""

    if key.name.startswith('b_'):
        return OptionType.BASE
    elif key.lang is not None:
        return OptionType.COMPILER
    elif key.name in _BUILTIN_NAMES or key.module:
        return OptionType.BUILTIN
    elif key.name.startswith('backend_'):
        assert key.machine is MachineChoice.HOST, str(key)
        return OptionType.BACKEND
    else:
        assert key.machine is MachineChoice.HOST or key.subproject, str(key)
        return OptionType.PROJECT


@total_ordering
class OptionKey:

    """Represents an option key in the various option dictionaries.

    This provides a flexible, powerful way to map option names from their
    external form (things like subproject:build.option) to something that
    internally easier to reason about and produce.
    """

    __slots__ = ['name', 'subproject', 'machine', 'lang', '_hash', 'type', 'module']

    name: str
    subproject: str
    machine: MachineChoice
    lang: T.Optional[str]
    _hash: int
    type: OptionType
    module: T.Optional[str]

    def __init__(self, name: str, subproject: str = '',
                 machine: MachineChoice = MachineChoice.HOST,
                 lang: T.Optional[str] = None,
                 module: T.Optional[str] = None,
                 _type: T.Optional[OptionType] = None):
        # the _type option to the constructor is kinda private. We want to be
        # able tos ave the state and avoid the lookup function when
        # pickling/unpickling, but we need to be able to calculate it when
        # constructing a new OptionKey
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'subproject', subproject)
        object.__setattr__(self, 'machine', machine)
        object.__setattr__(self, 'lang', lang)
        object.__setattr__(self, 'module', module)
        object.__setattr__(self, '_hash', hash((name, subproject, machine, lang, module)))
        if _type is None:
            _type = _classify_argument(self)
        object.__setattr__(self, 'type', _type)

    def __setattr__(self, key: str, value: T.Any) -> None:
        raise AttributeError('OptionKey instances do not support mutation.')

    def __getstate__(self) -> T.Dict[str, T.Any]:
        return {
            'name': self.name,
            'subproject': self.subproject,
            'machine': self.machine,
            'lang': self.lang,
            '_type': self.type,
            'module': self.module,
        }

    def __setstate__(self, state: T.Dict[str, T.Any]) -> None:
        """De-serialize the state of a pickle.

        This is very clever. __init__ is not a constructor, it's an
        initializer, therefore it's safe to call more than once. We create a
        state in the custom __getstate__ method, which is valid to pass
        splatted to the initializer.
        """
        # Mypy doesn't like this, because it's so clever.
        self.__init__(**state)  # type: ignore

    def __hash__(self) -> int:
        return self._hash

    def _to_tuple(self) -> T.Tuple[str, OptionType, str, str, MachineChoice, str]:
        return (self.subproject, self.type, self.lang or '', self.module or '', self.machine, self.name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, OptionKey):
            return self._to_tuple() == other._to_tuple()
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, OptionKey):
            return self._to_tuple() < other._to_tuple()
        return NotImplemented

    def __str__(self) -> str:
        out = self.name
        if self.lang:
            out = f'{self.lang}_{out}'
        if self.machine is MachineChoice.BUILD:
            out = f'build.{out}'
        if self.module:
            out = f'{self.module}.{out}'
        if self.subproject:
            out = f'{self.subproject}:{out}'
        return out

    def __repr__(self) -> str:
        return f'OptionKey({self.name!r}, {self.subproject!r}, {self.machine!r}, {self.lang!r}, {self.module!r}, {self.type!r})'

    @classmethod
    def from_string(cls, raw: str) -> 'OptionKey':
        """Parse the raw command line format into a three part tuple.

        This takes strings like `mysubproject:build.myoption` and Creates an
        OptionKey out of them.
        """
        try:
            subproject, raw2 = raw.split(':')
        except ValueError:
            subproject, raw2 = '', raw

        module = None
        for_machine = MachineChoice.HOST
        try:
            prefix, raw3 = raw2.split('.')
            if prefix == 'build':
                for_machine = MachineChoice.BUILD
            else:
                module = prefix
        except ValueError:
            raw3 = raw2

        from ..compilers import all_languages
        if any(raw3.startswith(f'{l}_') for l in all_languages):
            lang, opt = raw3.split('_', 1)
        else:
            lang, opt = None, raw3
        assert ':' not in opt
        assert '.' not in opt

        return cls(opt, subproject, for_machine, lang, module)

    def evolve(self, name: T.Optional[str] = None, subproject: T.Optional[str] = None,
               machine: T.Optional[MachineChoice] = None, lang: T.Optional[str] = '',
               module: T.Optional[str] = '') -> 'OptionKey':
        """Create a new copy of this key, but with altered members.

        For example:
        >>> a = OptionKey('foo', '', MachineChoice.Host)
        >>> b = OptionKey('foo', 'bar', MachineChoice.Host)
        >>> b == a.evolve(subproject='bar')
        True
        """
        # We have to be a little clever with lang here, because lang is valid
        # as None, for non-compiler options
        return OptionKey(
            name if name is not None else self.name,
            subproject if subproject is not None else self.subproject,
            machine if machine is not None else self.machine,
            lang if lang != '' else self.lang,
            module if module != '' else self.module
        )

    def as_root(self) -> 'OptionKey':
        """Convenience method for key.evolve(subproject='')."""
        return self.evolve(subproject='')

    def as_build(self) -> 'OptionKey':
        """Convenience method for key.evolve(machine=MachineChoice.BUILD)."""
        return self.evolve(machine=MachineChoice.BUILD)

    def as_host(self) -> 'OptionKey':
        """Convenience method for key.evolve(machine=MachineChoice.HOST)."""
        return self.evolve(machine=MachineChoice.HOST)

    def is_backend(self) -> bool:
        """Convenience method to check if this is a backend option."""
        return self.type is OptionType.BACKEND

    def is_builtin(self) -> bool:
        """Convenience method to check if this is a builtin option."""
        return self.type is OptionType.BUILTIN

    def is_compiler(self) -> bool:
        """Convenience method to check if this is a builtin option."""
        return self.type is OptionType.COMPILER

    def is_project(self) -> bool:
        """Convenience method to check if this is a project option."""
        return self.type is OptionType.PROJECT

    def is_base(self) -> bool:
        """Convenience method to check if this is a base option."""
        return self.type is OptionType.BASE


def pickle_load(filename: str, object_name: str, object_type: T.Type[_PL], suggest_reconfigure: bool = True) -> _PL:
    load_fail_msg = f'{object_name} file {filename!r} is corrupted.'
    extra_msg = ' Consider reconfiguring the directory with "meson setup --reconfigure".' if suggest_reconfigure else ''
    try:
        with open(filename, 'rb') as f:
            obj = pickle.load(f)
    except (pickle.UnpicklingError, EOFError):
        raise MesonException(load_fail_msg + extra_msg)
    except (TypeError, ModuleNotFoundError, AttributeError):
        raise MesonException(
            f"{object_name} file {filename!r} references functions or classes that don't "
            "exist. This probably means that it was generated with an old "
            "version of meson." + extra_msg)

    if not isinstance(obj, object_type):
        raise MesonException(load_fail_msg + extra_msg)

    # Because these Protocols are not available at runtime (and cannot be made
    # available at runtime until we drop support for Python < 3.8), we have to
    # do a bit of hackery so that mypy understands what's going on here
    version: str
    if hasattr(obj, 'version'):
        version = T.cast('_VerPickleLoadable', obj).version
    else:
        version = T.cast('_EnvPickleLoadable', obj).environment.coredata.version

    from ..coredata import version as coredata_version
    from ..coredata import major_versions_differ, MesonVersionMismatchException
    if major_versions_differ(version, coredata_version):
        raise MesonVersionMismatchException(version, coredata_version, extra_msg)
    return obj


def first(iter: T.Iterable[_T], predicate: T.Callable[[_T], bool]) -> T.Optional[_T]:
    """Find the first entry in an iterable where the given predicate is true

    :param iter: The iterable to search
    :param predicate: A finding function that takes an element from the iterable
        and returns True if found, otherwise False
    :return: The first found element, or None if it is not found
    """
    for i in iter:
        if predicate(i):
            return i
    return None
```