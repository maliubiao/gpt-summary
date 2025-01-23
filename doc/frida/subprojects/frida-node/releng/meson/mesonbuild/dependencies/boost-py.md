Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Understanding the Goal:**

The core request is to analyze a Python file (`boost.py`) within the Frida instrumentation framework. The prompt asks for its functionalities, its relation to reverse engineering, its use of low-level concepts, logical inferences, common user errors, and how a user might reach this code during debugging. Crucially, it's marked as "Part 1," meaning a summary of its main functions is required at the end of this part.

**2. Initial Skim and Keyword Identification:**

First, I'd quickly scan the code for keywords and recognizable patterns. This helps establish the general domain and purpose. Some initial observations:

* **`SPDX-License-Identifier: Apache-2.0` and `Copyright`:**  Indicates open-source licensing.
* **`from __future__ import annotations`:**  Python 3.7+ feature for forward references in type hints.
* **`import re`, `dataclasses`, `functools`, `typing`, `pathlib`:** Standard Python libraries, hinting at regular expressions, data structures, function manipulation, type hinting, and file system operations.
* **`from .. import ...`:** Indicates this file is part of a larger package (`frida`).
* **`DependencyException`, `SystemDependency`, `PkgConfigDependency`:**  Suggests this code deals with managing external dependencies, particularly Boost.
* **`BOOST_ROOT`:** An environment variable commonly associated with Boost installations.
* **Comments about Windows, Unix, macOS, library naming conventions (e.g., `-mt`, `-gd`):**  Highlights platform-specific considerations for Boost libraries.
* **`BoostIncludeDir`, `BoostLibraryFile`, `BoostDependency`:**  Custom classes clearly related to Boost.

**3. Deeper Dive into Key Classes and Functions:**

Next, I'd focus on the main classes and their methods:

* **`BoostIncludeDir`:**  Represents a Boost include directory. It stores the path and parses the Boost version from the directory name. This is fundamental for locating the correct headers.
* **`BoostLibraryFile`:** This is where the bulk of the parsing and analysis of individual Boost library files happens. I'd note:
    * The complex logic for extracting information from library filenames (static/shared, debug/release, multithreading, toolset, version, architecture).
    * The regular expressions used for parsing.
    * The `mod_name_matches`, `version_matches`, `arch_matches`, `vscrt_matches` methods – these are critical for determining if a found library meets the required criteria.
    * `get_compiler_args` and `get_link_args` – the ultimate goal is to provide the correct compiler and linker flags.
* **`BoostDependency`:** This is the main class responsible for finding and configuring Boost. Key observations:
    * The constructor takes `environment` and `kwargs`, suggesting it's integrated with a larger build system (likely Meson, given the file path).
    * It handles different ways of specifying Boost locations (environment variables, machine files, system paths, pkg-config).
    * `detect_roots`, `detect_inc_dirs`, `detect_lib_dirs`, `detect_libraries` – the core functions for locating Boost components.
    * `filter_libraries` – crucial for selecting the right library variants based on build settings.
    * The `run_check` method orchestrates the process of finding headers and matching libraries.

**4. Connecting to the Prompt's Questions:**

As I understand the code, I'd start mapping it to the specific questions in the prompt:

* **Functionality:**  The primary function is clearly to find and configure the Boost C++ library for a build process. This involves locating headers and appropriate library files based on build settings (static/shared, debug/release, multithreading).
* **Reverse Engineering:** While not directly involved in *executing* or *analyzing* binaries, correctly linking against libraries like Boost is a *prerequisite* for many reverse engineering tools (including Frida itself). Boost provides essential utilities for various tasks. An example could be Frida using Boost.Asio for network communication.
* **Binary/Kernel/Framework:** The code interacts with the *file system* (a low-level concept). It deals with library naming conventions specific to Linux, Windows, and macOS. The logic for architecture detection (`boost_arch_map`) and handling platform-specific library tags (`-mt`, `-gd`, compiler versions) is relevant here. The handling of `vscrt` on Windows relates to the Visual Studio runtime, a framework concept.
* **Logical Inference:** The code makes inferences based on file names and directory structures. For example, it assumes files in `lib*` directories are libraries. It infers the Boost version from the presence of `boost/version.hpp`. *Hypothetical Input/Output:* If `BOOST_ROOT` points to a directory with headers in `include/boost-1_75/boost` and libraries in `lib`, and the requested module is `filesystem`, the code should locate these and provide the correct include paths and linker flags for `libboost_filesystem`.
* **User Errors:**  Common errors include:
    * Incorrect `BOOST_ROOT` environment variable.
    * Missing or misconfigured Boost installation.
    * Requesting modules that aren't installed.
    * Mismatched build settings (e.g., trying to link against static Boost libraries when building a shared library).
* **User Journey:** A user would interact with this code by trying to build a project that depends on Boost. The build system (Meson, in this case) would invoke this `boost.py` script to find and configure Boost. Debugging might involve checking the output of the build process for errors related to missing Boost components or incorrect linker flags.

**5. Structuring the Answer (and Handling "Part 1"):**

Finally, I'd organize the information into a coherent answer, following the structure of the prompt. Since it's "Part 1," I'd focus on summarizing the core functionality at the end.

**Self-Correction/Refinement:**

During the process, I might realize I've missed something or misunderstood a detail. For example, initially, I might not have fully grasped the nuances of the different Boost library naming conventions on different platforms. Reading the comments in the code carefully and potentially doing a quick search about Boost library naming would help correct this. I'd also double-check that my examples are relevant and clear. The "Part 1" instruction is a crucial constraint, reminding me to provide a concise summary of the *main* purpose in this first part.
这是 frida 动态 instrumentation 工具中用于检测和配置 Boost C++ 库的 Python 脚本。 Boost 是一个广泛使用的 C++ 库集合，提供了很多功能，例如智能指针、多线程、文件系统操作等。这个脚本的目标是在构建 frida 时找到系统中安装的 Boost 库，并将其配置信息（头文件路径、库文件路径、编译参数、链接参数）提供给构建系统 (Meson)。

**以下是它的主要功能：**

1. **检测 Boost 根目录：** 脚本会尝试通过多种方式找到 Boost 的安装根目录，包括：
    * 检查环境变量 `BOOST_ROOT`。
    * 查找特定的目录结构（例如，`include/boost` 或 `boost` 目录下包含 `version.hpp`）。
    * 检查 `.pc` 文件（用于 `pkg-config` 工具）。
    * 搜索常见的系统路径（例如 `/usr/include`, `/usr/local/include` 等）。
    * 在 Windows 上查找常见的安装位置 (例如 `C:/Boost`, `C:/Program Files/boost`).
    * 读取构建机器配置文件中指定的路径 (`boost_includedir`, `boost_librarydir`, `boost_root`).

2. **识别 Boost 头文件目录和版本：** 一旦找到潜在的根目录，脚本会查找包含 `boost/version.hpp` 文件的目录，并解析该文件以确定 Boost 的版本号。

3. **查找 Boost 库文件：** 在潜在的库文件目录下（例如 `lib`, `lib64` 等），脚本会遍历所有文件，并尝试识别 Boost 库文件。它会根据文件名中的模式（例如 `libboost_<module>.so`, `boost_<module>.lib`）和后缀（`.so`, `.a`, `.lib`, `.dll` 等）来判断是否是 Boost 库文件。

4. **解析 Boost 库文件名：**  脚本会解析 Boost 库文件的名称，提取出关键信息，例如：
    * **模块名:** 例如 `atomic`, `chrono`, `filesystem` 等。
    * **是否静态链接:** 通过文件名后缀判断 (`.a` 或 `.lib` 通常表示静态库)。
    * **工具链:**  文件名中可能包含编译器信息，例如 `vc141`。
    * **架构:** 文件名中可能包含架构信息，例如 `x32`, `x64`。
    * **Boost 版本 (库版本):**  文件名中可能包含 Boost 版本号，例如 `1_67`。
    * **是否多线程:**  文件名中可能包含 `-mt` 标记。
    * **运行时库类型:**  文件名中可能包含运行时库标记，例如 `s` (static runtime), `g` (debug runtime)。
    * **Debug/Release:** 文件名中可能包含 `d` 或不包含来区分 debug 和 release 版本。

5. **根据需求过滤 Boost 库：** 脚本会根据用户在构建配置中指定的需求（例如，需要哪些 Boost 模块，是静态链接还是动态链接，是否需要多线程支持，Debug 或 Release 版本）来过滤找到的库文件。

6. **生成编译和链接参数：**  根据找到的头文件目录和库文件，脚本会生成相应的编译参数（例如 `-I/path/to/boost/include`）和链接参数（例如 `/path/to/libboost_filesystem.so` 或 `/path/to/boost_filesystem.lib`）。

7. **处理 Boost 模块依赖：**  如果用户指定了需要 `thread` 模块，脚本会尝试查找系统线程库作为子依赖。

**与逆向方法的关系：**

* **依赖库支持:**  很多逆向工程工具和框架，包括 Frida 本身，都依赖于一些通用的 C++ 库来完成特定的任务。Boost 作为一个功能丰富的库，经常被用在这些工具的开发中。例如：
    * **字符串处理:** Boost.StringAlgo 提供了很多高效的字符串操作函数。
    * **数据结构:** Boost.Container 提供了高级容器。
    * **多线程:** Boost.Thread 用于实现并发操作。
    * **文件系统操作:** Boost.Filesystem 用于跨平台的文件和目录操作。
    * **网络编程:** Boost.Asio 用于网络通信。
    * **JSON 处理:** Boost.PropertyTree 可以用于解析和生成 JSON 数据，这在与目标进程通信时可能很有用。

    **举例说明:** 如果 Frida 的某个模块需要进行跨平台的文件路径操作，它很可能会使用 Boost.Filesystem 提供的 API。这个 `boost.py` 脚本的功能就是确保在编译 Frida 时，能够正确找到并链接 Boost.Filesystem 库。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层:**
    * **静态库 vs. 动态库:** 脚本需要区分静态库（`.a`, `.lib`）和动态库（`.so`, `.dll`），这涉及到链接器的工作方式和二进制文件的结构。
    * **ABI (Application Binary Interface):**  脚本解析库文件名中的 `-mt`, `-gd` 等标记，这些标记与 ABI 相关，影响库的兼容性。例如，多线程库和非多线程库的 ABI 不同。
    * **架构 (Architecture):** 脚本会根据目标架构（例如 x86, x64, ARM）选择合适的库文件。

* **Linux:**
    * **共享库命名规范:** 脚本理解 Linux 下共享库的命名约定，例如 `libboost_<module>.so.1.66.0`。
    * **系统库路径:** 脚本会搜索常见的 Linux 系统库路径（例如 `/usr/lib`, `/usr/local/lib`）。
    * **`pkg-config`:** 脚本使用 `PkgConfigDependency` 来查找 Boost，这依赖于 Linux 系统上的 `pkg-config` 工具。

* **Android 内核及框架:**
    * 虽然此脚本本身不直接与 Android 内核交互，但 Frida 作为动态 instrumentation 工具，经常被用于 Android 平台的逆向和安全分析。正确链接 Boost 库是 Frida 在 Android 上运行的基础。
    * Android NDK 开发中也经常使用 Boost 库。

**逻辑推理：**

* **假设输入:** 用户在构建 Frida 时指定需要 `filesystem` 和 `thread` 两个 Boost 模块，并且指定使用动态链接。
* **输出:** 脚本会搜索系统，找到包含 `boost/version.hpp` 的头文件目录，并解析出 Boost 版本。然后，它会查找与指定模块和链接类型匹配的动态库文件，例如 `libboost_filesystem.so` 和 `libboost_thread.so`。最终，脚本会生成包含 Boost 头文件路径的编译参数（例如 `-I/usr/include/boost`）和包含 Boost 库文件路径的链接参数（例如 `-L/usr/lib -lboost_filesystem -lboost_thread`）。如果找不到所需的模块或匹配的库文件，脚本会将相应的模块添加到 `modules_missing` 列表中，并可能导致构建失败。

**用户或编程常见的使用错误：**

* **`BOOST_ROOT` 环境变量设置错误：** 用户可能设置了错误的 `BOOST_ROOT` 路径，导致脚本无法找到 Boost。
    * **举例:** 用户将 `BOOST_ROOT` 设置为 `/opt/boost`，但实际 Boost 安装在 `/usr/local/boost`。
* **缺少所需的 Boost 模块：** 用户在构建配置中指定了某个 Boost 模块，但系统中没有安装该模块的库文件。
    * **举例:** 用户需要 `asio` 模块，但只安装了 Boost 的核心组件，没有安装 `libboost_asio`。
* **Boost 版本不兼容：**  用户系统中安装的 Boost 版本与 Frida 的要求不兼容。
* **混合使用静态库和动态库的配置不当：**  用户可能错误地配置了同时链接静态库和动态库，导致链接冲突。
* **在 Windows 上缺少预编译的库文件或与编译器不匹配：** Windows 上 Boost 的预编译库文件可能需要与特定的 Visual Studio 版本和运行时库链接。
    * **举例:** 用户使用 MSVC 2019 编译，但系统中只有为 MSVC 2017 编译的 Boost 库。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户尝试构建 Frida:** 用户通常会执行类似于 `meson build` 或 `ninja` 命令来构建 Frida。
2. **构建系统解析 `meson.build` 文件:** Meson 会读取 Frida 项目的 `meson.build` 文件，该文件描述了项目的依赖关系，包括 Boost。
3. **Meson 调用 `boost.py` 脚本:** 当 Meson 处理到 Boost 依赖时，它会调用 `frida/subprojects/frida-node/releng/meson/mesonbuild/dependencies/boost.py` 脚本来查找和配置 Boost。
4. **脚本执行并尝试查找 Boost:**  `boost.py` 脚本会按照其内部的逻辑（搜索环境变量、目录、`.pc` 文件等）来查找 Boost 的安装。
5. **如果查找失败或配置不正确，构建过程可能会报错:**  Meson 会根据 `boost.py` 的输出判断 Boost 是否找到以及配置是否正确。如果找不到或者配置有问题，Meson 会输出错误信息，指示 Boost 相关的错误。
6. **用户检查构建日志或调试信息:**  为了诊断 Boost 相关的问题，用户可能会查看构建日志，其中会包含 `boost.py` 脚本的执行过程和输出信息，例如找到的头文件路径、库文件路径，以及缺失的模块等。

**归纳一下它的功能（第 1 部分）：**

总的来说，`frida/subprojects/frida-node/releng/meson/mesonbuild/dependencies/boost.py` 的主要功能是在 Frida 的构建过程中自动检测系统中安装的 Boost C++ 库，并提取其配置信息（头文件路径、库文件路径、编译/链接参数）以供构建系统使用。 它负责处理不同操作系统、Boost 安装方式和用户配置需求带来的复杂性，确保 Frida 可以正确地链接到所需的 Boost 库。

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/dependencies/boost.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2013-2020 The Meson development team

from __future__ import annotations

import re
import dataclasses
import functools
import typing as T
from pathlib import Path

from .. import mlog
from .. import mesonlib

from .base import DependencyException, SystemDependency
from .detect import packages
from .pkgconfig import PkgConfigDependency
from .misc import threads_factory

if T.TYPE_CHECKING:
    from ..envconfig import Properties
    from ..environment import Environment

# On windows 3 directory layouts are supported:
# * The default layout (versioned) installed:
#   - $BOOST_ROOT/include/boost-x_x/boost/*.hpp
#   - $BOOST_ROOT/lib/*.lib
# * The non-default layout (system) installed:
#   - $BOOST_ROOT/include/boost/*.hpp
#   - $BOOST_ROOT/lib/*.lib
# * The pre-built binaries from sf.net:
#   - $BOOST_ROOT/boost/*.hpp
#   - $BOOST_ROOT/lib<arch>-<compiler>/*.lib where arch=32/64 and compiler=msvc-14.1
#
# Note that we should also try to support:
# mingw-w64 / Windows : libboost_<module>-mt.a            (location = <prefix>/mingw64/lib/)
#                       libboost_<module>-mt.dll.a
#
# The `modules` argument accept library names. This is because every module that
# has libraries to link against also has multiple options regarding how to
# link. See for example:
# * http://www.boost.org/doc/libs/1_65_1/libs/test/doc/html/boost_test/usage_variants.html
# * http://www.boost.org/doc/libs/1_65_1/doc/html/stacktrace/configuration_and_build.html
# * http://www.boost.org/doc/libs/1_65_1/libs/math/doc/html/math_toolkit/main_tr1.html

# **On Unix**, official packaged versions of boost libraries follow the following schemes:
#
# Linux / Debian:   libboost_<module>.so -> libboost_<module>.so.1.66.0
# Linux / Red Hat:  libboost_<module>.so -> libboost_<module>.so.1.66.0
# Linux / OpenSuse: libboost_<module>.so -> libboost_<module>.so.1.66.0
# Win   / Cygwin:   libboost_<module>.dll.a                                 (location = /usr/lib)
#                   libboost_<module>.a
#                   cygboost_<module>_1_64.dll                              (location = /usr/bin)
# Win   / VS:       boost_<module>-vc<ver>-mt[-gd]-<arch>-1_67.dll          (location = C:/local/boost_1_67_0)
# Mac   / homebrew: libboost_<module>.dylib + libboost_<module>-mt.dylib    (location = /usr/local/lib)
# Mac   / macports: libboost_<module>.dylib + libboost_<module>-mt.dylib    (location = /opt/local/lib)
#
# Its not clear that any other abi tags (e.g. -gd) are used in official packages.
#
# On Linux systems, boost libs have multithreading support enabled, but without the -mt tag.
#
# Boost documentation recommends using complex abi tags like "-lboost_regex-gcc34-mt-d-1_36".
# (See http://www.boost.org/doc/libs/1_66_0/more/getting_started/unix-variants.html#library-naming)
# However, its not clear that any Unix distribution follows this scheme.
# Furthermore, the boost documentation for unix above uses examples from windows like
#   "libboost_regex-vc71-mt-d-x86-1_34.lib", so apparently the abi tags may be more aimed at windows.
#
# We follow the following strategy for finding modules:
# A) Detect potential boost root directories (uses also BOOST_ROOT env var)
# B) Foreach candidate
#   1. Look for the boost headers (boost/version.pp)
#   2. Find all boost libraries
#     2.1 Add all libraries in lib*
#     2.2 Filter out non boost libraries
#     2.3 Filter the remaining libraries based on the meson requirements (static/shared, etc.)
#     2.4 Ensure that all libraries have the same boost tag (and are thus compatible)
#   3. Select the libraries matching the requested modules

@dataclasses.dataclass(eq=False, order=False)
class UnknownFileException(Exception):
    path: Path

@functools.total_ordering
class BoostIncludeDir():
    def __init__(self, path: Path, version_int: int):
        self.path = path
        self.version_int = version_int
        major = int(self.version_int / 100000)
        minor = int((self.version_int / 100) % 1000)
        patch = int(self.version_int % 100)
        self.version = f'{major}.{minor}.{patch}'
        self.version_lib = f'{major}_{minor}'

    def __repr__(self) -> str:
        return f'<BoostIncludeDir: {self.version} -- {self.path}>'

    def __lt__(self, other: object) -> bool:
        if isinstance(other, BoostIncludeDir):
            return (self.version_int, self.path) < (other.version_int, other.path)
        return NotImplemented

@functools.total_ordering
class BoostLibraryFile():
    # Python libraries are special because of the included
    # minor version in the module name.
    boost_python_libs = ['boost_python', 'boost_numpy']
    reg_python_mod_split = re.compile(r'(boost_[a-zA-Z]+)([0-9]*)')

    reg_abi_tag = re.compile(r'^s?g?y?d?p?n?$')
    reg_ver_tag = re.compile(r'^[0-9_]+$')

    def __init__(self, path: Path):
        self.path = path
        self.name = self.path.name

        # Initialize default properties
        self.static = False
        self.toolset = ''
        self.arch = ''
        self.version_lib = ''
        self.mt = True

        self.runtime_static = False
        self.runtime_debug = False
        self.python_debug = False
        self.debug = False
        self.stlport = False
        self.deprecated_iostreams = False

        # Post process the library name
        name_parts = self.name.split('.')
        self.basename = name_parts[0]
        self.suffixes = name_parts[1:]
        self.vers_raw = [x for x in self.suffixes if x.isdigit()]
        self.suffixes = [x for x in self.suffixes if not x.isdigit()]
        self.nvsuffix = '.'.join(self.suffixes)  # Used for detecting the library type
        self.nametags = self.basename.split('-')
        self.mod_name = self.nametags[0]
        if self.mod_name.startswith('lib'):
            self.mod_name = self.mod_name[3:]

        # Set library version if possible
        if len(self.vers_raw) >= 2:
            self.version_lib = '{}_{}'.format(self.vers_raw[0], self.vers_raw[1])

        # Detecting library type
        if self.nvsuffix in {'so', 'dll', 'dll.a', 'dll.lib', 'dylib'}:
            self.static = False
        elif self.nvsuffix in {'a', 'lib'}:
            self.static = True
        else:
            raise UnknownFileException(self.path)

        # boost_.lib is the dll import library
        if self.basename.startswith('boost_') and self.nvsuffix == 'lib':
            self.static = False

        # Process tags
        tags = self.nametags[1:]
        # Filter out the python version tag and fix modname
        if self.is_python_lib():
            tags = self.fix_python_name(tags)
        if not tags:
            return

        # Without any tags mt is assumed, however, an absence of mt in the name
        # with tags present indicates that the lib was built without mt support
        self.mt = False
        for i in tags:
            if i == 'mt':
                self.mt = True
            elif len(i) == 3 and i[1:] in {'32', '64'}:
                self.arch = i
            elif BoostLibraryFile.reg_abi_tag.match(i):
                self.runtime_static = 's' in i
                self.runtime_debug = 'g' in i
                self.python_debug = 'y' in i
                self.debug = 'd' in i
                self.stlport = 'p' in i
                self.deprecated_iostreams = 'n' in i
            elif BoostLibraryFile.reg_ver_tag.match(i):
                self.version_lib = i
            else:
                self.toolset = i

    def __repr__(self) -> str:
        return f'<LIB: {self.abitag} {self.mod_name:<32} {self.path}>'

    def __lt__(self, other: object) -> bool:
        if isinstance(other, BoostLibraryFile):
            return (
                self.mod_name, self.static, self.version_lib, self.arch,
                not self.mt, not self.runtime_static,
                not self.debug, self.runtime_debug, self.python_debug,
                self.stlport, self.deprecated_iostreams,
                self.name,
            ) < (
                other.mod_name, other.static, other.version_lib, other.arch,
                not other.mt, not other.runtime_static,
                not other.debug, other.runtime_debug, other.python_debug,
                other.stlport, other.deprecated_iostreams,
                other.name,
            )
        return NotImplemented

    def __eq__(self, other: object) -> bool:
        if isinstance(other, BoostLibraryFile):
            return self.name == other.name
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.name)

    @property
    def abitag(self) -> str:
        abitag = ''
        abitag += 'S' if self.static else '-'
        abitag += 'M' if self.mt else '-'
        abitag += ' '
        abitag += 's' if self.runtime_static else '-'
        abitag += 'g' if self.runtime_debug else '-'
        abitag += 'y' if self.python_debug else '-'
        abitag += 'd' if self.debug else '-'
        abitag += 'p' if self.stlport else '-'
        abitag += 'n' if self.deprecated_iostreams else '-'
        abitag += ' ' + (self.arch or '???')
        abitag += ' ' + (self.toolset or '?')
        abitag += ' ' + (self.version_lib or 'x_xx')
        return abitag

    def is_boost(self) -> bool:
        return any(self.name.startswith(x) for x in ['libboost_', 'boost_'])

    def is_python_lib(self) -> bool:
        return any(self.mod_name.startswith(x) for x in BoostLibraryFile.boost_python_libs)

    def fix_python_name(self, tags: T.List[str]) -> T.List[str]:
        # Handle the boost_python naming madness.
        # See https://github.com/mesonbuild/meson/issues/4788 for some distro
        # specific naming variations.
        other_tags: T.List[str] = []

        # Split the current modname into the base name and the version
        m_cur = BoostLibraryFile.reg_python_mod_split.match(self.mod_name)
        cur_name = m_cur.group(1)
        cur_vers = m_cur.group(2)

        # Update the current version string if the new version string is longer
        def update_vers(new_vers: str) -> None:
            nonlocal cur_vers
            new_vers = new_vers.replace('_', '')
            new_vers = new_vers.replace('.', '')
            if not new_vers.isdigit():
                return
            if len(new_vers) > len(cur_vers):
                cur_vers = new_vers

        for i in tags:
            if i.startswith('py'):
                update_vers(i[2:])
            elif i.isdigit():
                update_vers(i)
            elif len(i) >= 3 and i[0].isdigit and i[2].isdigit() and i[1] == '.':
                update_vers(i)
            else:
                other_tags += [i]

        self.mod_name = cur_name + cur_vers
        return other_tags

    def mod_name_matches(self, mod_name: str) -> bool:
        if self.mod_name == mod_name:
            return True
        if not self.is_python_lib():
            return False

        m_cur = BoostLibraryFile.reg_python_mod_split.match(self.mod_name)
        m_arg = BoostLibraryFile.reg_python_mod_split.match(mod_name)

        if not m_cur or not m_arg:
            return False

        if m_cur.group(1) != m_arg.group(1):
            return False

        cur_vers = m_cur.group(2)
        arg_vers = m_arg.group(2)

        # Always assume python 2 if nothing is specified
        if not arg_vers:
            arg_vers = '2'

        return cur_vers.startswith(arg_vers)

    def version_matches(self, version_lib: str) -> bool:
        # If no version tag is present, assume that it fits
        if not self.version_lib or not version_lib:
            return True
        return self.version_lib == version_lib

    def arch_matches(self, arch: str) -> bool:
        # If no version tag is present, assume that it fits
        if not self.arch or not arch:
            return True
        return self.arch == arch

    def vscrt_matches(self, vscrt: str) -> bool:
        # If no vscrt tag present, assume that it fits  ['/MD', '/MDd', '/MT', '/MTd']
        if not vscrt:
            return True
        if vscrt in {'/MD', '-MD'}:
            return not self.runtime_static and not self.runtime_debug
        elif vscrt in {'/MDd', '-MDd'}:
            return not self.runtime_static and self.runtime_debug
        elif vscrt in {'/MT', '-MT'}:
            return (self.runtime_static or not self.static) and not self.runtime_debug
        elif vscrt in {'/MTd', '-MTd'}:
            return (self.runtime_static or not self.static) and self.runtime_debug

        mlog.warning(f'Boost: unknown vscrt tag {vscrt}. This may cause the compilation to fail. Please consider reporting this as a bug.', once=True)
        return True

    def get_compiler_args(self) -> T.List[str]:
        args: T.List[str] = []
        if self.mod_name in boost_libraries:
            libdef = boost_libraries[self.mod_name]
            if self.static:
                args += libdef.static
            else:
                args += libdef.shared
            if self.mt:
                args += libdef.multi
            else:
                args += libdef.single
        return args

    def get_link_args(self) -> T.List[str]:
        return [self.path.as_posix()]

class BoostDependency(SystemDependency):
    def __init__(self, environment: Environment, kwargs: T.Dict[str, T.Any]) -> None:
        super().__init__('boost', environment, kwargs, language='cpp')
        buildtype = environment.coredata.get_option(mesonlib.OptionKey('buildtype'))
        assert isinstance(buildtype, str)
        self.debug = buildtype.startswith('debug')
        self.multithreading = kwargs.get('threading', 'multi') == 'multi'

        self.boost_root: T.Optional[Path] = None
        self.explicit_static = 'static' in kwargs

        # Extract and validate modules
        self.modules: T.List[str] = mesonlib.extract_as_list(kwargs, 'modules')
        for i in self.modules:
            if not isinstance(i, str):
                raise DependencyException('Boost module argument is not a string.')
            if i.startswith('boost_'):
                raise DependencyException('Boost modules must be passed without the boost_ prefix')

        self.modules_found: T.List[str] = []
        self.modules_missing: T.List[str] = []

        # Do we need threads?
        if 'thread' in self.modules:
            if not self._add_sub_dependency(threads_factory(environment, self.for_machine, {})):
                self.is_found = False
                return

        # Try figuring out the architecture tag
        self.arch = environment.machines[self.for_machine].cpu_family
        self.arch = boost_arch_map.get(self.arch, None)

        # First, look for paths specified in a machine file
        props = self.env.properties[self.for_machine]
        if any(x in self.env.properties[self.for_machine] for x in
               ['boost_includedir', 'boost_librarydir', 'boost_root']):
            self.detect_boost_machine_file(props)
            return

        # Finally, look for paths from .pc files and from searching the filesystem
        self.detect_roots()

    def check_and_set_roots(self, roots: T.List[Path], use_system: bool) -> None:
        roots = list(mesonlib.OrderedSet(roots))
        for j in roots:
            #   1. Look for the boost headers (boost/version.hpp)
            mlog.debug(f'Checking potential boost root {j.as_posix()}')
            inc_dirs = self.detect_inc_dirs(j)
            inc_dirs = sorted(inc_dirs, reverse=True)  # Prefer the newer versions

            # Early abort when boost is not found
            if not inc_dirs:
                continue

            lib_dirs = self.detect_lib_dirs(j, use_system)
            self.is_found = self.run_check(inc_dirs, lib_dirs)
            if self.is_found:
                self.boost_root = j
                break

    def detect_boost_machine_file(self, props: 'Properties') -> None:
        """Detect boost with values in the machine file or environment.

        The machine file values are defaulted to the environment values.
        """
        # XXX: if we had a TypedDict we wouldn't need this
        incdir = props.get('boost_includedir')
        assert incdir is None or isinstance(incdir, str)
        libdir = props.get('boost_librarydir')
        assert libdir is None or isinstance(libdir, str)

        if incdir and libdir:
            inc_dir = Path(incdir)
            lib_dir = Path(libdir)

            if not inc_dir.is_absolute() or not lib_dir.is_absolute():
                raise DependencyException('Paths given for boost_includedir and boost_librarydir in machine file must be absolute')

            mlog.debug('Trying to find boost with:')
            mlog.debug(f'  - boost_includedir = {inc_dir}')
            mlog.debug(f'  - boost_librarydir = {lib_dir}')

            return self.detect_split_root(inc_dir, lib_dir)

        elif incdir or libdir:
            raise DependencyException('Both boost_includedir *and* boost_librarydir have to be set in your machine file (one is not enough)')

        rootdir = props.get('boost_root')
        # It shouldn't be possible to get here without something in boost_root
        assert rootdir

        raw_paths = mesonlib.stringlistify(rootdir)
        paths = [Path(x) for x in raw_paths]
        if paths and any(not x.is_absolute() for x in paths):
            raise DependencyException('boost_root path given in machine file must be absolute')

        self.check_and_set_roots(paths, use_system=False)

    def run_check(self, inc_dirs: T.List[BoostIncludeDir], lib_dirs: T.List[Path]) -> bool:
        mlog.debug('  - potential library dirs: {}'.format([x.as_posix() for x in lib_dirs]))
        mlog.debug('  - potential include dirs: {}'.format([x.path.as_posix() for x in inc_dirs]))

        #   2. Find all boost libraries
        libs: T.List[BoostLibraryFile] = []
        for i in lib_dirs:
            libs = self.detect_libraries(i)
            if libs:
                mlog.debug(f'  - found boost library dir: {i}')
                # mlog.debug('  - raw library list:')
                # for j in libs:
                #     mlog.debug('    - {}'.format(j))
                break
        libs = sorted(set(libs))

        modules = ['boost_' + x for x in self.modules]
        for inc in inc_dirs:
            mlog.debug(f'  - found boost {inc.version} include dir: {inc.path}')
            f_libs = self.filter_libraries(libs, inc.version_lib)

            mlog.debug('  - filtered library list:')
            for j in f_libs:
                mlog.debug(f'    - {j}')

            #   3. Select the libraries matching the requested modules
            not_found: T.List[str] = []
            selected_modules: T.List[BoostLibraryFile] = []
            for mod in modules:
                found = False
                for l in f_libs:
                    if l.mod_name_matches(mod):
                        selected_modules += [l]
                        found = True
                        break
                if not found:
                    not_found += [mod]

            # log the result
            mlog.debug('  - found:')
            comp_args: T.List[str] = []
            link_args: T.List[str] = []
            for j in selected_modules:
                c_args = j.get_compiler_args()
                l_args = j.get_link_args()
                mlog.debug('    - {:<24} link={} comp={}'.format(j.mod_name, str(l_args), str(c_args)))
                comp_args += c_args
                link_args += l_args

            comp_args = list(mesonlib.OrderedSet(comp_args))
            link_args = list(mesonlib.OrderedSet(link_args))

            self.modules_found = [x.mod_name for x in selected_modules]
            self.modules_found = [x[6:] for x in self.modules_found]
            self.modules_found = sorted(set(self.modules_found))
            self.modules_missing = not_found
            self.modules_missing = [x[6:] for x in self.modules_missing]
            self.modules_missing = sorted(set(self.modules_missing))

            # if we found all modules we are done
            if not not_found:
                self.version = inc.version
                self.compile_args = ['-I' + inc.path.as_posix()]
                self.compile_args += comp_args
                self.compile_args += self._extra_compile_args()
                self.compile_args = list(mesonlib.OrderedSet(self.compile_args))
                self.link_args = link_args
                mlog.debug(f'  - final compile args: {self.compile_args}')
                mlog.debug(f'  - final link args:    {self.link_args}')
                return True

            # in case we missed something log it and try again
            mlog.debug('  - NOT found:')
            for mod in not_found:
                mlog.debug(f'    - {mod}')

        return False

    def detect_inc_dirs(self, root: Path) -> T.List[BoostIncludeDir]:
        candidates: T.List[Path] = []
        inc_root = root / 'include'

        candidates += [root / 'boost']
        candidates += [inc_root / 'boost']
        if inc_root.is_dir():
            for i in inc_root.iterdir():
                if not i.is_dir() or not i.name.startswith('boost-'):
                    continue
                candidates += [i / 'boost']
        candidates = [x for x in candidates if x.is_dir()]
        candidates = [x / 'version.hpp' for x in candidates]
        candidates = [x for x in candidates if x.exists()]
        return [self._include_dir_from_version_header(x) for x in candidates]

    def detect_lib_dirs(self, root: Path, use_system: bool) -> T.List[Path]:
        # First check the system include paths. Only consider those within the
        # given root path

        if use_system:
            system_dirs_t = self.clib_compiler.get_library_dirs(self.env)
            system_dirs = [Path(x) for x in system_dirs_t]
            system_dirs = [x.resolve() for x in system_dirs if x.exists()]
            system_dirs = [x for x in system_dirs if mesonlib.path_is_in_root(x, root)]
            system_dirs = list(mesonlib.OrderedSet(system_dirs))

            if system_dirs:
                return system_dirs

        # No system include paths were found --> fall back to manually looking
        # for library dirs in root
        dirs: T.List[Path] = []
        subdirs: T.List[Path] = []
        for i in root.iterdir():
            if i.is_dir() and i.name.startswith('lib'):
                dirs += [i]

        # Some distros put libraries not directly inside /usr/lib but in /usr/lib/x86_64-linux-gnu
        for i in dirs:
            for j in i.iterdir():
                if j.is_dir() and j.name.endswith('-linux-gnu'):
                    subdirs += [j]

        # Filter out paths that don't match the target arch to avoid finding
        # the wrong libraries. See https://github.com/mesonbuild/meson/issues/7110
        if not self.arch:
            return dirs + subdirs

        arch_list_32 = ['32', 'i386']
        arch_list_64 = ['64']

        raw_list = dirs + subdirs
        no_arch = [x for x in raw_list if not any(y in x.name for y in arch_list_32 + arch_list_64)]

        matching_arch: T.List[Path] = []
        if '32' in self.arch:
            matching_arch = [x for x in raw_list if any(y in x.name for y in arch_list_32)]
        elif '64' in self.arch:
            matching_arch = [x for x in raw_list if any(y in x.name for y in arch_list_64)]

        return sorted(matching_arch) + sorted(no_arch)

    def filter_libraries(self, libs: T.List[BoostLibraryFile], lib_vers: str) -> T.List[BoostLibraryFile]:
        # MSVC is very picky with the library tags
        vscrt = ''
        try:
            crt_val = self.env.coredata.options[mesonlib.OptionKey('b_vscrt')].value
            buildtype = self.env.coredata.options[mesonlib.OptionKey('buildtype')].value
            vscrt = self.clib_compiler.get_crt_compile_args(crt_val, buildtype)[0]
        except (KeyError, IndexError, AttributeError):
            pass

        # mlog.debug('    - static: {}'.format(self.static))
        # mlog.debug('    - not explicit static: {}'.format(not self.explicit_static))
        # mlog.debug('    - mt: {}'.format(self.multithreading))
        # mlog.debug('    - version: {}'.format(lib_vers))
        # mlog.debug('    - arch: {}'.format(self.arch))
        # mlog.debug('    - vscrt: {}'.format(vscrt))
        libs = [x for x in libs if x.static == self.static or not self.explicit_static]
        libs = [x for x in libs if x.mt == self.multithreading]
        libs = [x for x in libs if x.version_matches(lib_vers)]
        libs = [x for x in libs if x.arch_matches(self.arch)]
        libs = [x for x in libs if x.vscrt_matches(vscrt)]
        libs = [x for x in libs if x.nvsuffix != 'dll']  # Only link to import libraries

        # Only filter by debug when we are building in release mode. Debug
        # libraries are automatically preferred through sorting otherwise.
        if not self.debug:
            libs = [x for x in libs if not x.debug]

        # Take the abitag from the first library and filter by it. This
        # ensures that we have a set of libraries that are always compatible.
        if not libs:
            return []
        abitag = libs[0].abitag
        libs = [x for x in libs if x.abitag == abitag]

        return libs

    def detect_libraries(self, libdir: Path) -> T.List[BoostLibraryFile]:
        libs: T.Set[BoostLibraryFile] = set()
        for i in libdir.iterdir():
            if not i.is_file():
                continue
            if not any(i.name.startswith(x) for x in ['libboost_', 'boost_']):
                continue
            # Windows binaries from SourceForge ship with PDB files alongside
            # DLLs (#8325).  Ignore them.
            if i.name.endswith('.pdb'):
                continue

            try:
                libs.add(BoostLibraryFile(i.resolve()))
            except UnknownFileException as e:
                mlog.warning('Boost: ignoring unknown file {} under lib directory'.format(e.path.name))

        return [x for x in libs if x.is_boost()]  # Filter out no boost libraries

    def detect_split_root(self, inc_dir: Path, lib_dir: Path) -> None:
        boost_inc_dir = None
        for j in [inc_dir / 'version.hpp', inc_dir / 'boost' / 'version.hpp']:
            if j.is_file():
                boost_inc_dir = self._include_dir_from_version_header(j)
                break
        if not boost_inc_dir:
            self.is_found = False
            return

        self.is_found = self.run_check([boost_inc_dir], [lib_dir])

    def detect_roots(self) -> None:
        roots: T.List[Path] = []

        # Try getting the BOOST_ROOT from a boost.pc if it exists. This primarily
        # allows BoostDependency to find boost from Conan. See #5438
        try:
            boost_pc = PkgConfigDependency('boost', self.env, {'required': False})
            if boost_pc.found():
                boost_root = boost_pc.get_variable(pkgconfig='prefix')
                if boost_root:
                    roots += [Path(boost_root)]
        except DependencyException:
            pass

        # Add roots from system paths
        inc_paths = [Path(x) for x in self.clib_compiler.get_default_include_dirs()]
        inc_paths = [x.parent for x in inc_paths if x.exists()]
        inc_paths = [x.resolve() for x in inc_paths]
        roots += inc_paths

        # Add system paths
        if self.env.machines[self.for_machine].is_windows():
            # Where boost built from source actually installs it
            c_root = Path('C:/Boost')
            if c_root.is_dir():
                roots += [c_root]

            # Where boost documentation says it should be
            prog_files = Path('C:/Program Files/boost')
            # Where boost prebuilt binaries are
            local_boost = Path('C:/local')

            candidates: T.List[Path] = []
            if prog_files.is_dir():
                candidates += [*prog_files.iterdir()]
            if local_boost.is_dir():
                candidates += [*local_boost.iterdir()]

            roots += [x for x in candidates if x.name.lower().startswith('boost') and x.is_dir()]
        else:
            tmp: T.List[Path] = []

            # Add some default system paths
            tmp += [Path('/opt/local')]
            tmp += [Path('/usr/local/opt/boost')]
            tmp += [Path('/usr/local')]
            tmp += [Path('/usr')]

            # Cleanup paths
            tmp = [x for x in tmp if x.is_dir()]
            tmp = [x.resolve() for x in tmp]
            roots += tmp

        self.check_and_set_roots(roots, use_system=True)

    def log_details(self) -> str:
        res = ''
        if self.modules_found:
            res += 'found: ' + ', '.join(self.modules_found)
        if self.modules_missing:
            if res:
                res += ' | '
            res += 'missing: ' + ', '.join(self.modules_missing)
        return res

    def log_info(self) -> str:
        if self.boost_root:
            return self.boost_root.as_posix()
        return ''

    def _include_dir_from_version_header(self, hfile: Path) -> BoostIncludeDir:
        # Extract the version with a regex. Using clib_compiler.get_define would
        # also work, however, this is slower (since it the compiler has to be
        # invoked) and overkill since the layout of the header is always the same.
        assert hfile.exists()
        raw = hfile.read_text(encoding='utf-8')
        m = re.search(r'#define\s+BOOST_VERSION\s+([0-9]+)', raw)
        if not m:
            mlog.debug(f'Failed to extract version information from {hfile}')
            return BoostIncludeDir(hfile.parents[1], 0)
        return BoostIncludeDir(hfile.parents[1], int(m.group(1)))

    def _extra_compile_args(self) -> T.List[str]:
        # BOOST_ALL_DYN_LINK should not be required with the known defines below
        return ['-DBOOST_ALL_NO_LIB']  # Disable automatic linking

packages['boost'] = BoostDependency

# See https://www.boost.org/doc/libs/1_72_0/more/getting_started/unix-variants.html#library-naming
# See https://mesonbuild.com/Reference-tables.html#cpu-families
boost_arch_map = {
    'aarch64': 'a64',
    'arc': 'a32',
    'arm': 'a32',
    'ia64': 'i64',
    'mips': 'm32',
    'mips64': 'm64',
    'ppc': 'p32',
    'ppc64': 'p64',
    'sparc': 's32',
    'sparc64': 's64',
    'x86': 'x32',
    'x86_64': 'x64',
}


####      ---- BEGIN GENERATED ----      ####
#                                           #
# Generated with tools/boost_names.py:
#  - boost version:   1.73.0
#  - modules found:   159
#  - libraries found: 43
#

class BoostLibrary():
    def __init__(self, name: str, shared: T.List[str], static: T.List[str], single: T.List[str], multi: T.List[str]):
        self.name = name
        self.shared = shared
        self.static = static
        self.single = single
        self.multi = multi

class BoostModule():
    def __init__(self, name: str, key: str, desc: str, libs: T.List[str]):
        self.name = name
        self.key = key
        self.desc = desc
        self.libs = libs


# dict of all know libraries with additional compile options
boost_libraries = {
    'boost_atomic': BoostLibrary(
        name='boost_atomic',
        shared=['-DBOOST_ATOMIC_DYN_LINK=1'],
        static=['-DBOOST_ATOMIC_STATIC_LINK=1'],
        single=[],
        multi=[],
    ),
    'boost_chrono': BoostLibrary(
        name='boost_chrono',
        shared=['-DBOOST_CHRONO_DYN_LINK=1'],
        static=['-DBOOST_CHRONO_STATIC_LINK=1'],
        single=['-DBOOST_CHRONO_THREAD_DISABLED'],
        multi=[],
    ),
    'boost_container': BoostLibrary(
        name='boost_container',
        shared=['-DBOOST_CONTAINER_DYN_LINK=1'],
        static=['-DBOOST_CONTAINER_STATIC_LINK=1'],
        single=[],
        multi=[],
    ),
    'boost_context': BoostLibrary(
        name='boost_context',
        shared=['-DBOOST_CONTEXT_DYN_LINK=1'],
        static=[],
        single=[],
        multi=[],
    ),
    'boost_contract': BoostLibrary(
        name='boost_contract',
        shared=['-DBOOST_CONTRACT_DYN_LINK'],
        static=['-DBOOST_CONTRACT_STATIC_LINK'],
        single=['-DBOOST_CONTRACT_DISABLE_THREADS'],
        multi=[],
    ),
    'boost_coroutine': BoostLibrary(
        name='boost_coroutine',
        shared=['-DBOOST_COROUTINES_DYN_LINK=1'],
        static=[],
        single=[],
        multi=[],
    ),
    'boost_date_time': BoostLibrary(
        name='boost_date_time',
        shared=['-DBOOST_DATE_TIME_DYN_LINK=1'],
        static=[],
        single=[],
        multi=[],
    ),
    'boost_exception': BoostLibrary(
```