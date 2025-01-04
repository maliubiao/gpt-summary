Response:
My goal is to provide a comprehensive summary of the Python code snippet, addressing all the specific requirements outlined in the prompt. Here's a breakdown of my thought process:

1. **Understanding the Core Task:** The code is a Meson module (`pkgconfig`) designed to generate `.pc` files (pkg-config files). Pkg-config files are metadata files used by build systems to find information about installed libraries, like include paths, library names, and dependencies.

2. **Dissecting the Code - Key Components:** I scanned the code for key classes and functions:
    * `PkgConfigModule`: The main module class, inheriting from `NewExtensionModule`. This signifies it's a Meson extension.
    * `DependenciesHelper`:  A helper class to manage dependencies (libraries, requires, cflags) in a structured way. This is crucial for understanding how the `.pc` file content is built.
    * `MetaData`:  A simple dataclass to store metadata about generated `.pc` files, particularly useful for handling deprecation warnings.
    * `generate()`: The core method invoked by Meson users to create `.pc` files. It takes various arguments to customize the generated file.
    * Helper functions like `_process_libs`, `_process_reqs`, `_add_lib_dependencies`, `_generate_pkgconfig_file`, etc., which handle the details of processing libraries, dependencies, and generating the actual file content.

3. **Identifying Core Functionality:** Based on the key components, I identified the main functions of the module:
    * Generating `.pc` files based on provided information.
    * Handling dependencies (both public and private).
    * Including library linking flags and compiler flags.
    * Specifying required packages and their versions.
    * Customizing the `.pc` file with variables.
    * Supporting uninstalled builds.
    * Managing conflicts between packages.

4. **Relating to Reverse Engineering:** I considered how generating `.pc` files connects to reverse engineering. The key link is that `.pc` files provide information about *how* a library is built and how to link against it. This information is crucial for:
    * **Static Analysis:** Understanding the dependencies and build configuration of a target library can be part of static analysis during reverse engineering.
    * **Dynamic Analysis (indirectly):** While `.pc` files aren't directly used during runtime, they define how a program links to libraries. Understanding these links can be important when analyzing a program's behavior. Frida itself uses dynamic instrumentation, and understanding how the target application is built (via `.pc` files) can be helpful for crafting hooks and understanding the runtime environment.

5. **Identifying Low-Level/Kernel/Framework Connections:**  I looked for aspects of the code that interact with lower levels of the system:
    * **Library Linking:** The code explicitly deals with library paths (`-L`), library names (`-l`), and linking whole archives (`link_whole_targets`). This directly relates to how executables and libraries are built by the linker, a fundamental part of the OS.
    * **Include Paths (`-I`):**  The generation of `Cflags` includes handling include paths, which are essential for the C/C++ preprocessor to find header files. This touches on the compilation process.
    * **Dependencies:** The concept of dependencies itself is a core OS and software engineering concept. The `.pc` files describe dependencies between software components.
    * **Uninstalled Builds:** The code handles the scenario where the library isn't yet installed to the system, which requires understanding the build directory structure.
    * **Android (Implicit):** Although not explicitly mentioned in *this* snippet, given the file path `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/pkgconfig.py`, it's highly probable that this module is used in the context of building Frida, which often targets Android. Therefore, the concepts of shared libraries, linking, and dependencies are directly relevant to the Android framework.

6. **Logical Reasoning and Input/Output:** I thought about the flow of the `generate()` function and the `DependenciesHelper`.
    * **Input:** The `generate()` function takes various keyword arguments like `libraries`, `requires`, `version`, `name`, `description`, etc. It can optionally take a main library as a positional argument.
    * **Processing:**  The `DependenciesHelper` processes these inputs, resolving dependencies, collecting library paths and flags, and formatting the information.
    * **Output:** The primary output is a `.pc` file written to the build directory. The content of this file is structured according to the pkg-config specification.

7. **Common User Errors:** I considered potential mistakes a user might make when using this module:
    * **Missing `name` or `description`:** If a library isn't provided as a positional argument, these are mandatory.
    * **Incorrect dependency specifications:** Providing invalid library names or incorrect version requirements.
    * **Mixing `dataonly` with library/dependency options:** The `dataonly` option restricts which keywords can be used.
    * **Incorrect install directories:**  Although the module tries to infer them, users might have custom installation layouts.

8. **User Path to Execution (Debugging):** I traced the possible steps a user might take to reach this code:
    * Writing a `meson.build` file.
    * Using the `pkgconfig.generate()` function within the `meson.build` file.
    * Running the `meson` command to configure the build.
    * If there's an error in the `pkgconfig.generate()` call, Meson will execute this Python code, potentially leading to debugging within this module.

9. **Structuring the Summary:** Finally, I organized my findings into the requested categories:
    * **Functionality:** A high-level overview of what the module does.
    * **Relationship to Reverse Engineering:** Explicitly connecting the module's purpose to reverse engineering concepts.
    * **Binary/Kernel/Framework Knowledge:** Highlighting the low-level aspects involved.
    * **Logical Reasoning:** Describing the input, processing, and output.
    * **Common Usage Errors:** Providing concrete examples of mistakes.
    * **User Path:** Explaining how a user's actions lead to the execution of this code.
    * **Summary of Functionality (Part 1):**  A concise recap of the main purpose of the module as requested for the first part of the prompt.

By following these steps, I aimed to provide a detailed and accurate explanation of the provided Python code, addressing all the specific points raised in the prompt. The key was to understand the purpose of the code within the context of a build system and its relationship to the broader software development process, including elements relevant to reverse engineering and low-level system interactions.
好的，让我们来分析一下 `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/pkgconfig.py` 文件的功能。

**功能归纳（第 1 部分）**

这个 Python 文件是 Meson 构建系统中一个名为 `pkgconfig` 的模块的源代码。它的主要功能是：

1. **生成 `.pc` 文件（pkg-config 文件）：**  这是其核心功能。Pkg-config 是一种用于在编译时检索有关已安装库信息的标准方法。`.pc` 文件包含了库的名称、版本、描述、编译和链接所需的标志（如头文件路径、库文件路径、依赖项等）。

2. **管理库的依赖关系：**  模块能够处理库之间的依赖关系，包括公共依赖和私有依赖。它可以将这些依赖信息写入生成的 `.pc` 文件中，以便其他项目在链接时能够正确地找到所需的库。

3. **处理不同类型的库：**  该模块可以处理各种类型的库，包括：
    * 共享库 (`.so` 或 `.dll`)
    * 静态库 (`.a` 或 `.lib`)
    * 自定义目标（`CustomTarget` 或 `CustomTargetIndex`，代表由 Meson 构建的非标准库文件）
    * 外部依赖（通过 `dependencies.Dependency` 对象表示，例如系统中已安装的其他库）

4. **定义编译和链接标志：**  模块允许指定库的编译标志（`Cflags`）和链接标志（通过 `Libs` 和 `Libs.private` 字段）。

5. **支持未安装的构建：**  模块可以生成用于“未安装”构建的 `.pc` 文件，这种情况下，库可能尚未安装到系统目录，而是存在于构建目录中。

6. **自定义 `.pc` 文件内容：**  模块提供了灵活的方式来定制生成的 `.pc` 文件，包括：
    * 设置名称、版本、描述、URL 等基本信息。
    * 定义所需的其他软件包及其版本要求。
    * 添加自定义的变量。
    * 指定与其他软件包的冲突。

7. **处理头文件包含路径：**  模块负责将正确的头文件包含路径添加到 `.pc` 文件的 `Cflags` 字段中。

8. **处理 `name_prefix` 和 `name_suffix`：**  对于具有前缀（如 `lib`）或后缀的库名，模块会进行特殊处理，以确保生成的 `.pc` 文件能够被正确解析。

9. **支持 `dataonly` 模式：**  在 `dataonly` 模式下，生成的 `.pc` 文件只包含元数据信息，不包含库相关的链接和编译标志，这对于描述只包含数据的软件包很有用。

接下来，我们将针对您提出的其他问题进行更深入的分析。

**与逆向方法的关系及举例说明**

`.pc` 文件本身不是直接用于逆向工程的工具，但它提供的元数据信息对于逆向分析师来说非常有价值：

* **了解目标软件的依赖关系：** 通过分析目标软件依赖的 `.pc` 文件，逆向工程师可以快速了解目标软件所使用的库。这有助于确定潜在的攻击面、使用的算法、以及可能存在的漏洞（例如，已知的第三方库漏洞）。

* **识别使用的库版本：** `.pc` 文件中包含库的版本信息。这对于确定是否存在已知漏洞至关重要，因为某些库的特定版本可能存在安全缺陷。

* **定位库文件和头文件：** `.pc` 文件提供了库文件和头文件的路径。这对于进行更深入的动态或静态分析非常有用。例如，在 GDB 中调试时，可以利用这些路径加载符号表；在进行静态分析时，可以找到头文件以了解库的接口和数据结构。

**举例说明：**

假设一个逆向工程师正在分析一个使用了 `libssl` 库的二进制文件。他可能会查找系统中 `libssl` 的 `.pc` 文件（通常名为 `libssl.pc`）。通过查看该文件，他可以获得以下信息：

```
prefix=/usr
exec_prefix=${prefix}
libdir=${exec_prefix}/lib/x86_64-linux-gnu
includedir=${prefix}/include

Name: OpenSSL
Description: Secure Sockets Layer and cryptography libraries
Version: 1.1.1k
Requires.private: zlib
Libs: -L${libdir} -lssl -lcrypto
Cflags: -I${includedir}
```

* **依赖关系 (`Requires.private: zlib`)：**  他知道 `libssl` 依赖于 `zlib` 库。
* **版本 (`Version: 1.1.1k`)：** 他可以查阅该版本的 `libssl` 是否存在已知的安全漏洞。
* **库文件路径 (`Libs: -L${libdir} -lssl -lcrypto`)：** 他知道链接时需要链接 `libssl` 和 `libcrypto` 库。`${libdir}` 会被展开为 `/usr/lib/x86_64-linux-gnu`。
* **头文件路径 (`Cflags: -I${includedir}`)：** 他知道 `libssl` 的头文件位于 `/usr/include` 目录下。

这些信息可以帮助逆向工程师更好地理解目标二进制文件，并为后续的分析工作提供基础。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明**

该模块虽然是用 Python 编写的，但其目的是生成用于构建过程的文件，而构建过程最终会产生二进制文件，并与操作系统内核和框架交互。

* **二进制底层：**
    * **链接标志 (`-l`, `-L`)：**  `.pc` 文件中的 `Libs` 字段直接对应于链接器（如 `ld`）使用的标志，用于指定要链接的库文件及其搜索路径。这是二进制可执行文件构建的关键步骤。
    * **库文件路径：** 指向实际的二进制库文件（`.so`、`.a` 等）。

* **Linux：**
    * **标准库路径：** 在 Linux 系统中，库文件通常安装在 `/usr/lib`、`/usr/lib64` 等标准路径下。`.pc` 文件中的 `${libdir}` 变量通常会指向这些路径。
    * **Pkg-config 工具：**  `.pc` 文件是 Linux 生态系统中用于查找库信息的标准机制。`pkg-config` 命令会解析这些文件来获取构建信息。

* **Android 内核及框架（推测）：**
    * **共享库 (`.so`)：** Android 系统大量使用共享库。Frida 作为一款动态 instrumentation 工具，经常用于 Android 平台的分析和调试。因此，此模块很可能被用于生成与 Android 平台上的库相关的 `.pc` 文件。
    * **Android NDK：** 如果 Frida 需要编译与 Android 原生代码交互的部分，则会涉及到 Android NDK (Native Development Kit)。`.pc` 文件可以用于描述 NDK 提供的库。
    * **系统库依赖：** Android 框架依赖于底层的 Linux 内核和各种系统库。`.pc` 文件可以描述这些依赖关系。

**举例说明：**

在 Android 开发中，如果一个 native 模块依赖于 `liblog`（Android 系统日志库），那么可能会生成一个 `liblog.pc` 文件，其中可能包含类似的信息：

```
prefix=/path/to/android/ndk/sysroot/usr
exec_prefix=${prefix}
libdir=${exec_prefix}/lib
includedir=${prefix}/include

Name: liblog
Description: Android system logging library
Version: ...
Libs: -L${libdir} -llog
Cflags: -I${includedir}
```

这个 `.pc` 文件告诉构建系统，要链接 `liblog` 库，需要在 `${libdir}`（Android NDK 的 sysroot 路径下的 lib 目录）中查找名为 `liblog.so` 的文件，并且需要包含 `${includedir}` 下的头文件。

**逻辑推理、假设输入与输出**

假设我们调用 `pkgconfig.generate()` 方法，并提供以下参数：

**假设输入：**

```python
pkgconfig.generate(
    meson.shared_library('mylib', 'mylib.c'),
    name='mylib',
    version='1.0',
    description='My awesome library',
    url='https://example.com/mylib',
    libraries=['dependency1', meson.static_library('static_dep', 'static_dep.c')],
    requires=['dependency2 >= 2.0'],
    cflags=['-DMY_MACRO'],
    subdirs=['include/mylib'],
    variables={'prefix': '/opt/mylib'}
)
```

**逻辑推理：**

1. `meson.shared_library('mylib', 'mylib.c')`：定义了一个名为 `mylib` 的共享库作为主要目标。
2. `name='mylib'`, `version='1.0'`, `description='My awesome library'`, `url='https://example.com/mylib'`：设置了 `.pc` 文件的基本元数据。
3. `libraries=['dependency1', meson.static_library('static_dep', 'static_dep.c')]`：指定了 `mylib` 链接时需要的其他库，包括一个名为 `dependency1` 的外部依赖和一个名为 `static_dep` 的静态库。
4. `requires=['dependency2 >= 2.0']`：指定了 `mylib` 依赖于 `dependency2`，且版本必须大于等于 2.0。
5. `cflags=['-DMY_MACRO']`：指定了编译 `mylib` 时需要的 C 编译器标志。
6. `subdirs=['include/mylib']`：指定了头文件所在的子目录。
7. `variables={'prefix': '/opt/mylib'}`：定义了一个自定义变量 `prefix`。

**预期输出（`mylib.pc` 文件的内容）：**

```
prefix=/opt/mylib
includedir=${prefix}/include

Name: mylib
Description: My awesome library
URL: https://example.com/mylib
Version: 1.0
Requires: dependency2 >= 2.0
Libs: -L${libdir} -lmylib -ldependency1 -L${libdir} -lstatic_dep
Cflags: -I${includedir}/mylib -DMY_MACRO
```

**解释：**

* `prefix` 变量被设置为 `/opt/mylib`。
* `includedir` 被设置为 `${prefix}/include`，即 `/opt/mylib/include`。
* `Requires` 字段包含了指定的依赖及其版本要求。
* `Libs` 字段包含了链接 `mylib` 和其依赖所需的标志。注意，静态库 `static_dep` 也被添加到了 `Libs` 中。
* `Cflags` 字段包含了指定的编译器标志和头文件包含路径。

**涉及用户或者编程常见的使用错误及举例说明**

1. **缺少必要的参数：** 如果在没有提供库作为位置参数的情况下调用 `pkgconfig.generate()`，则必须提供 `name` 和 `description` 关键字参数。否则会抛出异常。

   ```python
   # 错误：缺少 name 和 description
   pkgconfig.generate()

   # 正确：提供 name 和 description
   pkgconfig.generate(name='mylib', description='My library')
   ```

2. **`dataonly` 模式下使用不兼容的参数：**  如果在 `dataonly=True` 的情况下使用了 `libraries`、`requires`、`cflags` 等与库相关的参数，会导致错误。

   ```python
   # 错误：在 dataonly 模式下使用了 libraries
   pkgconfig.generate(name='mydataset', description='My dataset', dataonly=True, libraries=['somelib'])

   # 正确：在 dataonly 模式下只使用元数据相关的参数
   pkgconfig.generate(name='mydataset', description='My dataset', dataonly=True)
   ```

3. **错误的依赖项指定：**  如果 `requires` 中指定的依赖项名称拼写错误或版本格式不正确，可能导致其他项目在尝试使用该 `.pc` 文件时出现问题。

   ```python
   # 错误：依赖项名称拼写错误
   pkgconfig.generate(meson.shared_library('mylib', 'mylib.c'), requires=['depndency_typo'])

   # 错误：版本格式不正确
   pkgconfig.generate(meson.shared_library('mylib', 'mylib.c'), requires=['dependency=wrong_format'])

   # 正确：
   pkgconfig.generate(meson.shared_library('mylib', 'mylib.c'), requires=['dependency >= 1.0'])
   ```

4. **未安装构建的路径问题：**  在未安装的构建中，如果依赖项的 `.pc` 文件没有正确生成或者路径配置不当，可能导致链接错误。

5. **变量引用错误：**  在自定义变量中引用不存在的变量或内置目录选项时，可能导致生成的 `.pc` 文件中的值不正确。

**说明用户操作是如何一步步的到达这里，作为调试线索**

1. **编写 `meson.build` 文件：** 用户首先需要编写一个 `meson.build` 文件来描述项目的构建过程。
2. **使用 `pkgconfig.generate()`：** 在 `meson.build` 文件中，用户调用 `meson.get_compiler('c').create_shared_library()` 或类似的函数来定义库，并使用 `pkgconfig.generate()` 函数来生成对应的 `.pc` 文件。

   ```python
   project('myproject', 'c')
   mylib = meson.shared_library('mylib', 'mylib.c')
   pkgconfig.generate(
       mylib,
       name='mylib',
       version='1.0'
   )
   ```

3. **运行 `meson` 命令配置构建：**  用户在项目根目录下运行 `meson setup builddir` 命令来配置构建。Meson 会解析 `meson.build` 文件，并执行其中的 Python 代码，包括 `pkgconfig.generate()` 调用。

4. **`pkgconfig.generate()` 执行：** 当执行到 `pkgconfig.generate()` 时，Meson 会调用 `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/pkgconfig.py` 文件中的 `generate` 方法。

5. **可能的调试场景：**

   * **配置错误：** 如果用户在 `pkgconfig.generate()` 中传递了错误的参数类型或值，例如，将字符串传递给需要库对象的位置，或者使用了不兼容的 `dataonly` 参数，Meson 会在执行 `generate` 方法时抛出异常。调试器会停在这个 Python 文件中，显示出错的代码行。
   * **依赖问题：** 如果生成的 `.pc` 文件中的依赖关系不正确，例如，缺少了某些依赖项或版本要求错误，那么在其他项目尝试使用这个 `.pc` 文件进行构建时可能会失败。虽然错误不直接发生在 `pkgconfig.py` 中，但理解这个模块的工作原理有助于排查依赖问题。
   * **自定义变量问题：** 如果自定义变量的定义或使用不正确，例如，引用了不存在的变量，生成的 `.pc` 文件可能不符合预期，需要检查 `pkgconfig.py` 中的变量处理逻辑。

总而言之，当用户在 Meson 构建过程中需要生成或使用 `.pc` 文件来描述库的信息时，`frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/pkgconfig.py` 文件就会被 Meson 执行。如果构建配置出现错误，或者生成的 `.pc` 文件存在问题，开发人员可能会需要查看或调试这个文件。

希望这个详细的分析对您有所帮助！

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/pkgconfig.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2015-2022 The Meson development team

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePath
import os
import typing as T

from . import NewExtensionModule, ModuleInfo
from . import ModuleReturnValue
from .. import build
from .. import dependencies
from .. import mesonlib
from .. import mlog
from ..coredata import BUILTIN_DIR_OPTIONS
from ..dependencies.pkgconfig import PkgConfigDependency, PkgConfigInterface
from ..interpreter.type_checking import D_MODULE_VERSIONS_KW, INSTALL_DIR_KW, VARIABLES_KW, NoneType
from ..interpreterbase import FeatureNew, FeatureDeprecated
from ..interpreterbase.decorators import ContainerTypeInfo, KwargInfo, typed_kwargs, typed_pos_args

if T.TYPE_CHECKING:
    from typing_extensions import TypedDict

    from . import ModuleState
    from .. import mparser
    from ..interpreter import Interpreter

    ANY_DEP = T.Union[dependencies.Dependency, build.BuildTargetTypes, str]
    LIBS = T.Union[build.LibTypes, str]

    class GenerateKw(TypedDict):

        version: T.Optional[str]
        name: T.Optional[str]
        filebase: T.Optional[str]
        description: T.Optional[str]
        url: str
        subdirs: T.List[str]
        conflicts: T.List[str]
        dataonly: bool
        libraries: T.List[ANY_DEP]
        libraries_private: T.List[ANY_DEP]
        requires: T.List[T.Union[str, build.StaticLibrary, build.SharedLibrary, dependencies.Dependency]]
        requires_private: T.List[T.Union[str, build.StaticLibrary, build.SharedLibrary, dependencies.Dependency]]
        install_dir: T.Optional[str]
        d_module_versions: T.List[T.Union[str, int]]
        extra_cflags: T.List[str]
        variables: T.Dict[str, str]
        uninstalled_variables: T.Dict[str, str]
        unescaped_variables: T.Dict[str, str]
        unescaped_uninstalled_variables: T.Dict[str, str]


_PKG_LIBRARIES: KwargInfo[T.List[T.Union[str, dependencies.Dependency, build.SharedLibrary, build.StaticLibrary, build.CustomTarget, build.CustomTargetIndex]]] = KwargInfo(
    'libraries',
    ContainerTypeInfo(list, (str, dependencies.Dependency,
                             build.SharedLibrary, build.StaticLibrary,
                             build.CustomTarget, build.CustomTargetIndex)),
    default=[],
    listify=True,
)

_PKG_REQUIRES: KwargInfo[T.List[T.Union[str, build.SharedLibrary, build.StaticLibrary, dependencies.Dependency]]] = KwargInfo(
    'requires',
    ContainerTypeInfo(list, (str, build.SharedLibrary, build.StaticLibrary, dependencies.Dependency)),
    default=[],
    listify=True,
)


def _as_str(obj: object) -> str:
    assert isinstance(obj, str)
    return obj


@dataclass
class MetaData:

    filebase: str
    display_name: str
    location: mparser.BaseNode
    warned: bool = False


class DependenciesHelper:
    def __init__(self, state: ModuleState, name: str, metadata: T.Dict[str, MetaData]) -> None:
        self.state = state
        self.name = name
        self.metadata = metadata
        self.pub_libs: T.List[LIBS] = []
        self.pub_reqs: T.List[str] = []
        self.priv_libs: T.List[LIBS] = []
        self.priv_reqs: T.List[str] = []
        self.cflags: T.List[str] = []
        self.version_reqs: T.DefaultDict[str, T.Set[str]] = defaultdict(set)
        self.link_whole_targets: T.List[T.Union[build.CustomTarget, build.CustomTargetIndex, build.StaticLibrary]] = []
        self.uninstalled_incdirs: mesonlib.OrderedSet[str] = mesonlib.OrderedSet()

    def add_pub_libs(self, libs: T.List[ANY_DEP]) -> None:
        p_libs, reqs, cflags = self._process_libs(libs, True)
        self.pub_libs = p_libs + self.pub_libs # prepend to preserve dependencies
        self.pub_reqs += reqs
        self.cflags += cflags

    def add_priv_libs(self, libs: T.List[ANY_DEP]) -> None:
        p_libs, reqs, _ = self._process_libs(libs, False)
        self.priv_libs = p_libs + self.priv_libs
        self.priv_reqs += reqs

    def add_pub_reqs(self, reqs: T.List[T.Union[str, build.StaticLibrary, build.SharedLibrary, dependencies.Dependency]]) -> None:
        self.pub_reqs += self._process_reqs(reqs)

    def add_priv_reqs(self, reqs: T.List[T.Union[str, build.StaticLibrary, build.SharedLibrary, dependencies.Dependency]]) -> None:
        self.priv_reqs += self._process_reqs(reqs)

    def _check_generated_pc_deprecation(self, obj: T.Union[build.CustomTarget, build.CustomTargetIndex, build.StaticLibrary, build.SharedLibrary]) -> None:
        if obj.get_id() in self.metadata:
            return
        data = self.metadata[obj.get_id()]
        if data.warned:
            return
        mlog.deprecation('Library', mlog.bold(obj.name), 'was passed to the '
                         '"libraries" keyword argument of a previous call '
                         'to generate() method instead of first positional '
                         'argument.', 'Adding', mlog.bold(data.display_name),
                         'to "Requires" field, but this is a deprecated '
                         'behaviour that will change in a future version '
                         'of Meson. Please report the issue if this '
                         'warning cannot be avoided in your case.',
                         location=data.location)
        data.warned = True

    def _process_reqs(self, reqs: T.Sequence[T.Union[str, build.StaticLibrary, build.SharedLibrary, dependencies.Dependency]]) -> T.List[str]:
        '''Returns string names of requirements'''
        processed_reqs: T.List[str] = []
        for obj in mesonlib.listify(reqs):
            if not isinstance(obj, str):
                FeatureNew.single_use('pkgconfig.generate requirement from non-string object', '0.46.0', self.state.subproject)
            if (isinstance(obj, (build.CustomTarget, build.CustomTargetIndex, build.SharedLibrary, build.StaticLibrary))
                    and obj.get_id() in self.metadata):
                self._check_generated_pc_deprecation(obj)
                processed_reqs.append(self.metadata[obj.get_id()].filebase)
            elif isinstance(obj, PkgConfigDependency):
                if obj.found():
                    processed_reqs.append(obj.name)
                    self.add_version_reqs(obj.name, obj.version_reqs)
            elif isinstance(obj, str):
                name, version_req = self.split_version_req(obj)
                processed_reqs.append(name)
                self.add_version_reqs(name, [version_req] if version_req is not None else None)
            elif isinstance(obj, dependencies.Dependency) and not obj.found():
                pass
            elif isinstance(obj, dependencies.ExternalDependency) and obj.name == 'threads':
                pass
            else:
                raise mesonlib.MesonException('requires argument not a string, '
                                              'library with pkgconfig-generated file '
                                              f'or pkgconfig-dependency object, got {obj!r}')
        return processed_reqs

    def add_cflags(self, cflags: T.List[str]) -> None:
        self.cflags += mesonlib.stringlistify(cflags)

    def _add_uninstalled_incdirs(self, incdirs: T.List[build.IncludeDirs], subdir: T.Optional[str] = None) -> None:
        for i in incdirs:
            curdir = i.get_curdir()
            for d in i.get_incdirs():
                path = os.path.join(curdir, d)
                self.uninstalled_incdirs.add(path)
        if subdir is not None:
            self.uninstalled_incdirs.add(subdir)

    def _process_libs(
            self, libs: T.List[ANY_DEP], public: bool
            ) -> T.Tuple[T.List[T.Union[str, build.SharedLibrary, build.StaticLibrary, build.CustomTarget, build.CustomTargetIndex]], T.List[str], T.List[str]]:
        libs = mesonlib.listify(libs)
        processed_libs: T.List[T.Union[str, build.SharedLibrary, build.StaticLibrary, build.CustomTarget, build.CustomTargetIndex]] = []
        processed_reqs: T.List[str] = []
        processed_cflags: T.List[str] = []
        for obj in libs:
            if (isinstance(obj, (build.CustomTarget, build.CustomTargetIndex, build.SharedLibrary, build.StaticLibrary))
                    and obj.get_id() in self.metadata):
                self._check_generated_pc_deprecation(obj)
                processed_reqs.append(self.metadata[obj.get_id()].filebase)
            elif isinstance(obj, dependencies.ExternalDependency) and obj.name == 'valgrind':
                pass
            elif isinstance(obj, PkgConfigDependency):
                if obj.found():
                    processed_reqs.append(obj.name)
                    self.add_version_reqs(obj.name, obj.version_reqs)
            elif isinstance(obj, dependencies.InternalDependency):
                if obj.found():
                    if obj.objects:
                        raise mesonlib.MesonException('.pc file cannot refer to individual object files.')
                    processed_libs += obj.get_link_args()
                    processed_cflags += obj.get_compile_args()
                    self._add_lib_dependencies(obj.libraries, obj.whole_libraries, obj.ext_deps, public, private_external_deps=True)
                    self._add_uninstalled_incdirs(obj.get_include_dirs())
            elif isinstance(obj, dependencies.Dependency):
                if obj.found():
                    processed_libs += obj.get_link_args()
                    processed_cflags += obj.get_compile_args()
            elif isinstance(obj, build.SharedLibrary) and obj.shared_library_only:
                # Do not pull dependencies for shared libraries because they are
                # only required for static linking. Adding private requires has
                # the side effect of exposing their cflags, which is the
                # intended behaviour of pkg-config but force Debian to add more
                # than needed build deps.
                # See https://bugs.freedesktop.org/show_bug.cgi?id=105572
                processed_libs.append(obj)
                self._add_uninstalled_incdirs(obj.get_include_dirs(), obj.get_source_subdir())
            elif isinstance(obj, (build.SharedLibrary, build.StaticLibrary)):
                processed_libs.append(obj)
                self._add_uninstalled_incdirs(obj.get_include_dirs(), obj.get_source_subdir())
                # If there is a static library in `Libs:` all its deps must be
                # public too, otherwise the generated pc file will never be
                # usable without --static.
                self._add_lib_dependencies(obj.link_targets,
                                           obj.link_whole_targets,
                                           obj.external_deps,
                                           isinstance(obj, build.StaticLibrary) and public)
            elif isinstance(obj, (build.CustomTarget, build.CustomTargetIndex)):
                if not obj.is_linkable_target():
                    raise mesonlib.MesonException('library argument contains a not linkable custom_target.')
                FeatureNew.single_use('custom_target in pkgconfig.generate libraries', '0.58.0', self.state.subproject)
                processed_libs.append(obj)
            elif isinstance(obj, str):
                processed_libs.append(obj)
            else:
                raise mesonlib.MesonException(f'library argument of type {type(obj).__name__} not a string, library or dependency object.')

        return processed_libs, processed_reqs, processed_cflags

    def _add_lib_dependencies(
            self, link_targets: T.Sequence[build.BuildTargetTypes],
            link_whole_targets: T.Sequence[T.Union[build.StaticLibrary, build.CustomTarget, build.CustomTargetIndex]],
            external_deps: T.List[dependencies.Dependency],
            public: bool,
            private_external_deps: bool = False) -> None:
        add_libs = self.add_pub_libs if public else self.add_priv_libs
        # Recursively add all linked libraries
        for t in link_targets:
            # Internal libraries (uninstalled static library) will be promoted
            # to link_whole, treat them as such here.
            if t.is_internal():
                # `is_internal` shouldn't return True for anything but a
                # StaticLibrary, or a CustomTarget that is a StaticLibrary
                assert isinstance(t, (build.StaticLibrary, build.CustomTarget, build.CustomTargetIndex)), 'for mypy'
                self._add_link_whole(t, public)
            else:
                add_libs([t])
        for t in link_whole_targets:
            self._add_link_whole(t, public)
        # And finally its external dependencies
        if private_external_deps:
            self.add_priv_libs(T.cast('T.List[ANY_DEP]', external_deps))
        else:
            add_libs(T.cast('T.List[ANY_DEP]', external_deps))

    def _add_link_whole(self, t: T.Union[build.CustomTarget, build.CustomTargetIndex, build.StaticLibrary], public: bool) -> None:
        # Don't include static libraries that we link_whole. But we still need to
        # include their dependencies: a static library we link_whole
        # could itself link to a shared library or an installed static library.
        # Keep track of link_whole_targets so we can remove them from our
        # lists in case a library is link_with and link_whole at the same time.
        # See remove_dups() below.
        self.link_whole_targets.append(t)
        if isinstance(t, build.BuildTarget):
            self._add_lib_dependencies(t.link_targets, t.link_whole_targets, t.external_deps, public)

    def add_version_reqs(self, name: str, version_reqs: T.Optional[T.List[str]]) -> None:
        if version_reqs:
            # Note that pkg-config is picky about whitespace.
            # 'foo > 1.2' is ok but 'foo>1.2' is not.
            # foo, bar' is ok, but 'foo,bar' is not.
            self.version_reqs[name].update(version_reqs)

    def split_version_req(self, s: str) -> T.Tuple[str, T.Optional[str]]:
        for op in ['>=', '<=', '!=', '==', '=', '>', '<']:
            pos = s.find(op)
            if pos > 0:
                return s[0:pos].strip(), s[pos:].strip()
        return s, None

    def format_vreq(self, vreq: str) -> str:
        # vreq are '>=1.0' and pkgconfig wants '>= 1.0'
        for op in ['>=', '<=', '!=', '==', '=', '>', '<']:
            if vreq.startswith(op):
                return op + ' ' + vreq[len(op):]
        return vreq

    def format_reqs(self, reqs: T.List[str]) -> str:
        result: T.List[str] = []
        for name in reqs:
            vreqs = self.version_reqs.get(name, None)
            if vreqs:
                result += [name + ' ' + self.format_vreq(vreq) for vreq in sorted(vreqs)]
            else:
                result += [name]
        return ', '.join(result)

    def remove_dups(self) -> None:
        # Set of ids that have already been handled and should not be added any more
        exclude: T.Set[str] = set()

        # We can't just check if 'x' is excluded because we could have copies of
        # the same SharedLibrary object for example.
        def _ids(x: T.Union[str, build.CustomTarget, build.CustomTargetIndex, build.StaticLibrary, build.SharedLibrary]) -> T.Iterable[str]:
            if isinstance(x, str):
                yield x
            else:
                if x.get_id() in self.metadata:
                    yield self.metadata[x.get_id()].display_name
                yield x.get_id()

        # Exclude 'x' in all its forms and return if it was already excluded
        def _add_exclude(x: T.Union[str, build.CustomTarget, build.CustomTargetIndex, build.StaticLibrary, build.SharedLibrary]) -> bool:
            was_excluded = False
            for i in _ids(x):
                if i in exclude:
                    was_excluded = True
                else:
                    exclude.add(i)
            return was_excluded

        # link_whole targets are already part of other targets, exclude them all.
        for t in self.link_whole_targets:
            _add_exclude(t)

        # Mypy thinks these overlap, but since List is invariant they don't,
        # `List[str]`` is not a valid input to `List[str | BuildTarget]`.
        # pylance/pyright gets this right, but for mypy we have to ignore the
        # error
        @T.overload
        def _fn(xs: T.List[str], libs: bool = False) -> T.List[str]: ...  # type: ignore

        @T.overload
        def _fn(xs: T.List[LIBS], libs: bool = False) -> T.List[LIBS]: ...

        def _fn(xs: T.Union[T.List[str], T.List[LIBS]], libs: bool = False) -> T.Union[T.List[str], T.List[LIBS]]:
            # Remove duplicates whilst preserving original order
            result = []
            for x in xs:
                # Don't de-dup unknown strings to avoid messing up arguments like:
                # ['-framework', 'CoreAudio', '-framework', 'CoreMedia']
                known_flags = ['-pthread']
                cannot_dedup = libs and isinstance(x, str) and \
                    not x.startswith(('-l', '-L')) and \
                    x not in known_flags
                if not cannot_dedup and _add_exclude(x):
                    continue
                result.append(x)
            return result

        # Handle lists in priority order: public items can be excluded from
        # private and Requires can excluded from Libs.
        self.pub_reqs = _fn(self.pub_reqs)
        self.pub_libs = _fn(self.pub_libs, True)
        self.priv_reqs = _fn(self.priv_reqs)
        self.priv_libs = _fn(self.priv_libs, True)
        # Reset exclude list just in case some values can be both cflags and libs.
        exclude = set()
        self.cflags = _fn(self.cflags)

class PkgConfigModule(NewExtensionModule):

    INFO = ModuleInfo('pkgconfig')

    # Track already generated pkg-config files This is stored as a class
    # variable so that multiple `import()`s share metadata
    devenv: T.Optional[mesonlib.EnvironmentVariables] = None
    _metadata: T.ClassVar[T.Dict[str, MetaData]] = {}

    def __init__(self) -> None:
        super().__init__()
        self.methods.update({
            'generate': self.generate,
        })

    def postconf_hook(self, b: build.Build) -> None:
        if self.devenv is not None:
            b.devenv.append(self.devenv)

    def _get_lname(self, l: T.Union[build.SharedLibrary, build.StaticLibrary, build.CustomTarget, build.CustomTargetIndex],
                   msg: str, pcfile: str) -> str:
        if isinstance(l, (build.CustomTargetIndex, build.CustomTarget)):
            basename = os.path.basename(l.get_filename())
            name = os.path.splitext(basename)[0]
            if name.startswith('lib'):
                name = name[3:]
            return name
        # Nothing special
        if not l.name_prefix_set:
            return l.name
        # Sometimes people want the library to start with 'lib' everywhere,
        # which is achieved by setting name_prefix to '' and the target name to
        # 'libfoo'. In that case, try to get the pkg-config '-lfoo' arg correct.
        if l.prefix == '' and l.name.startswith('lib'):
            return l.name[3:]
        # If the library is imported via an import library which is always
        # named after the target name, '-lfoo' is correct.
        if isinstance(l, build.SharedLibrary) and l.import_filename:
            return l.name
        # In other cases, we can't guarantee that the compiler will be able to
        # find the library via '-lfoo', so tell the user that.
        mlog.warning(msg.format(l.name, 'name_prefix', l.name, pcfile))
        return l.name

    def _escape(self, value: T.Union[str, PurePath]) -> str:
        '''
        We cannot use quote_arg because it quotes with ' and " which does not
        work with pkg-config and pkgconf at all.
        '''
        # We should always write out paths with / because pkg-config requires
        # spaces to be quoted with \ and that messes up on Windows:
        # https://bugs.freedesktop.org/show_bug.cgi?id=103203
        if isinstance(value, PurePath):
            value = value.as_posix()
        return value.replace(' ', r'\ ')

    def _make_relative(self, prefix: T.Union[PurePath, str], subdir: T.Union[PurePath, str]) -> str:
        prefix = PurePath(prefix)
        subdir = PurePath(subdir)
        try:
            libdir = subdir.relative_to(prefix)
        except ValueError:
            libdir = subdir
        # pathlib joining makes sure absolute libdir is not appended to '${prefix}'
        return ('${prefix}' / libdir).as_posix()

    def _generate_pkgconfig_file(self, state: ModuleState, deps: DependenciesHelper,
                                 subdirs: T.List[str], name: str,
                                 description: str, url: str, version: str,
                                 pcfile: str, conflicts: T.List[str],
                                 variables: T.List[T.Tuple[str, str]],
                                 unescaped_variables: T.List[T.Tuple[str, str]],
                                 uninstalled: bool = False, dataonly: bool = False,
                                 pkgroot: T.Optional[str] = None) -> None:
        coredata = state.environment.get_coredata()
        referenced_vars = set()
        optnames = [x.name for x in BUILTIN_DIR_OPTIONS.keys()]

        if not dataonly:
            # includedir is always implied, although libdir may not be
            # needed for header-only libraries
            referenced_vars |= {'prefix', 'includedir'}
            if deps.pub_libs or deps.priv_libs:
                referenced_vars |= {'libdir'}
        # also automatically infer variables referenced in other variables
        implicit_vars_warning = False
        redundant_vars_warning = False
        varnames = set()
        varstrings = set()
        for k, v in variables + unescaped_variables:
            varnames |= {k}
            varstrings |= {v}
        for optname in optnames:
            optvar = f'${{{optname}}}'
            if any(x.startswith(optvar) for x in varstrings):
                if optname in varnames:
                    redundant_vars_warning = True
                else:
                    # these 3 vars were always "implicit"
                    if dataonly or optname not in {'prefix', 'includedir', 'libdir'}:
                        implicit_vars_warning = True
                    referenced_vars |= {'prefix', optname}
        if redundant_vars_warning:
            FeatureDeprecated.single_use('pkgconfig.generate variable for builtin directories', '0.62.0',
                                         state.subproject, 'They will be automatically included when referenced',
                                         state.current_node)
        if implicit_vars_warning:
            FeatureNew.single_use('pkgconfig.generate implicit variable for builtin directories', '0.62.0',
                                  state.subproject, location=state.current_node)

        if uninstalled:
            outdir = os.path.join(state.environment.build_dir, 'meson-uninstalled')
            if not os.path.exists(outdir):
                os.mkdir(outdir)
            prefix = PurePath(state.environment.get_build_dir())
            srcdir = PurePath(state.environment.get_source_dir())
        else:
            outdir = state.environment.scratch_dir
            prefix = PurePath(_as_str(coredata.get_option(mesonlib.OptionKey('prefix'))))
            if pkgroot:
                pkgroot_ = PurePath(pkgroot)
                if not pkgroot_.is_absolute():
                    pkgroot_ = prefix / pkgroot
                elif prefix not in pkgroot_.parents:
                    raise mesonlib.MesonException('Pkgconfig prefix cannot be outside of the prefix '
                                                  'when pkgconfig.relocatable=true. '
                                                  f'Pkgconfig prefix is {pkgroot_.as_posix()}.')
                prefix = PurePath('${pcfiledir}', os.path.relpath(prefix, pkgroot_))
        fname = os.path.join(outdir, pcfile)
        with open(fname, 'w', encoding='utf-8') as ofile:
            for optname in optnames:
                if optname in referenced_vars - varnames:
                    if optname == 'prefix':
                        ofile.write('prefix={}\n'.format(self._escape(prefix)))
                    else:
                        dirpath = PurePath(_as_str(coredata.get_option(mesonlib.OptionKey(optname))))
                        ofile.write('{}={}\n'.format(optname, self._escape('${prefix}' / dirpath)))
            if uninstalled and not dataonly:
                ofile.write('srcdir={}\n'.format(self._escape(srcdir)))
            if variables or unescaped_variables:
                ofile.write('\n')
            for k, v in variables:
                ofile.write('{}={}\n'.format(k, self._escape(v)))
            for k, v in unescaped_variables:
                ofile.write(f'{k}={v}\n')
            ofile.write('\n')
            ofile.write(f'Name: {name}\n')
            if len(description) > 0:
                ofile.write(f'Description: {description}\n')
            if len(url) > 0:
                ofile.write(f'URL: {url}\n')
            ofile.write(f'Version: {version}\n')
            reqs_str = deps.format_reqs(deps.pub_reqs)
            if len(reqs_str) > 0:
                ofile.write(f'Requires: {reqs_str}\n')
            reqs_str = deps.format_reqs(deps.priv_reqs)
            if len(reqs_str) > 0:
                ofile.write(f'Requires.private: {reqs_str}\n')
            if len(conflicts) > 0:
                ofile.write('Conflicts: {}\n'.format(' '.join(conflicts)))

            def generate_libs_flags(libs: T.List[LIBS]) -> T.Iterable[str]:
                msg = 'Library target {0!r} has {1!r} set. Compilers ' \
                      'may not find it from its \'-l{2}\' linker flag in the ' \
                      '{3!r} pkg-config file.'
                Lflags = []
                for l in libs:
                    if isinstance(l, str):
                        yield l
                    else:
                        install_dir: T.Union[str, bool]
                        if uninstalled:
                            install_dir = os.path.dirname(state.backend.get_target_filename_abs(l))
                        else:
                            _i = l.get_custom_install_dir()
                            install_dir = _i[0] if _i else None
                        if install_dir is False:
                            continue
                        if isinstance(l, build.BuildTarget) and 'cs' in l.compilers:
                            if isinstance(install_dir, str):
                                Lflag = '-r{}/{}'.format(self._escape(self._make_relative(prefix, install_dir)), l.filename)
                            else:  # install_dir is True
                                Lflag = '-r${libdir}/%s' % l.filename
                        else:
                            if isinstance(install_dir, str):
                                Lflag = '-L{}'.format(self._escape(self._make_relative(prefix, install_dir)))
                            else:  # install_dir is True
                                Lflag = '-L${libdir}'
                        if Lflag not in Lflags:
                            Lflags.append(Lflag)
                            yield Lflag
                        lname = self._get_lname(l, msg, pcfile)
                        # If using a custom suffix, the compiler may not be able to
                        # find the library
                        if isinstance(l, build.BuildTarget) and l.name_suffix_set:
                            mlog.warning(msg.format(l.name, 'name_suffix', lname, pcfile))
                        if isinstance(l, (build.CustomTarget, build.CustomTargetIndex)) or 'cs' not in l.compilers:
                            yield f'-l{lname}'

            if len(deps.pub_libs) > 0:
                ofile.write('Libs: {}\n'.format(' '.join(generate_libs_flags(deps.pub_libs))))
            if len(deps.priv_libs) > 0:
                ofile.write('Libs.private: {}\n'.format(' '.join(generate_libs_flags(deps.priv_libs))))

            cflags: T.List[str] = []
            if uninstalled:
                for d in deps.uninstalled_incdirs:
                    for basedir in ['${prefix}', '${srcdir}']:
                        path = self._escape(PurePath(basedir, d).as_posix())
                        cflags.append(f'-I{path}')
            else:
                for d in subdirs:
                    if d == '.':
                        cflags.append('-I${includedir}')
                    else:
                        cflags.append(self._escape(PurePath('-I${includedir}') / d))
            cflags += [self._escape(f) for f in deps.cflags]
            if cflags and not dataonly:
                ofile.write('Cflags: {}\n'.format(' '.join(cflags)))

    @typed_pos_args('pkgconfig.generate', optargs=[(build.SharedLibrary, build.StaticLibrary)])
    @typed_kwargs(
        'pkgconfig.generate',
        D_MODULE_VERSIONS_KW.evolve(since='0.43.0'),
        INSTALL_DIR_KW,
        KwargInfo('conflicts', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('dataonly', bool, default=False, since='0.54.0'),
        KwargInfo('description', (str, NoneType)),
        KwargInfo('extra_cflags', ContainerTypeInfo(list, str), default=[], listify=True, since='0.42.0'),
        KwargInfo('filebase', (str, NoneType), validator=lambda x: 'must not be an empty string' if x == '' else None),
        KwargInfo('name', (str, NoneType), validator=lambda x: 'must not be an empty string' if x == '' else None),
        KwargInfo('subdirs', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('url', str, default=''),
        KwargInfo('version', (str, NoneType)),
        VARIABLES_KW.evolve(name="unescaped_uninstalled_variables", since='0.59.0'),
        VARIABLES_KW.evolve(name="unescaped_variables", since='0.59.0'),
        VARIABLES_KW.evolve(name="uninstalled_variables", since='0.54.0', since_values={dict: '0.56.0'}),
        VARIABLES_KW.evolve(since='0.41.0', since_values={dict: '0.56.0'}),
        _PKG_LIBRARIES,
        _PKG_LIBRARIES.evolve(name='libraries_private'),
        _PKG_REQUIRES,
        _PKG_REQUIRES.evolve(name='requires_private'),
    )
    def generate(self, state: ModuleState,
                 args: T.Tuple[T.Optional[T.Union[build.SharedLibrary, build.StaticLibrary]]],
                 kwargs: GenerateKw) -> ModuleReturnValue:
        if state.is_build_only_subproject:
            return ModuleReturnValue(None, [])

        default_version = state.project_version
        default_install_dir: T.Optional[str] = None
        default_description: T.Optional[str] = None
        default_name: T.Optional[str] = None
        mainlib: T.Optional[T.Union[build.SharedLibrary, build.StaticLibrary]] = None
        default_subdirs = ['.']
        if args[0]:
            FeatureNew.single_use('pkgconfig.generate optional positional argument', '0.46.0', state.subproject)
            mainlib = args[0]
            default_name = mainlib.name
            default_description = state.project_name + ': ' + mainlib.name
            install_dir = mainlib.get_custom_install_dir()
            if install_dir and isinstance(install_dir[0], str):
                default_install_dir = os.path.join(install_dir[0], 'pkgconfig')
        else:
            if kwargs['version'] is None:
                FeatureNew.single_use('pkgconfig.generate implicit version keyword', '0.46.0', state.subproject)
            msg = ('pkgconfig.generate: if a library is not passed as a '
                   'positional argument, the {!r} keyword argument is '
                   'required.')
            if kwargs['name'] is None:
                raise build.InvalidArguments(msg.format('name'))
            if kwargs['description'] is None:
                raise build.InvalidArguments(msg.format('description'))

        dataonly = kwargs['dataonly']
        if dataonly:
            default_subdirs = []
            blocked_vars = ['libraries', 'libraries_private', 'requires_private', 'extra_cflags', 'subdirs']
            # Mypy can't figure out that this TypedDict index is correct, without repeating T.Literal for the entire list
            if any(kwargs[k] for k in blocked_vars):  # type: ignore
                raise mesonlib.MesonException(f'Cannot combine dataonly with any of {blocked_vars}')
            default_install_dir = os.path.join(state.environment.get_da
"""


```