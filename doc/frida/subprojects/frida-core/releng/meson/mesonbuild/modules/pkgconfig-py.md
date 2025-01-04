Response:
The user wants a summary of the Python code provided, focusing on its functionalities and connections to reverse engineering, low-level operations, Linux/Android specifics, logical reasoning, common user errors, and debugging.

**Plan:**

1. **Identify the primary function:** The code is a Meson module named `pkgconfig` used to generate `.pc` files.
2. **Break down functionalities:** Analyze the methods and classes to list what the module does.
3. **Connect to reverse engineering:** Think about how `.pc` files are used in the context of libraries and how this relates to reverse engineering (e.g., finding dependencies).
4. **Relate to low-level/OS/Android:** Identify any parts of the code dealing with paths, libraries, dependencies, which might touch upon OS concepts.
5. **Look for logical reasoning:**  Examine conditional statements and data processing to infer input/output scenarios.
6. **Identify potential user errors:** Consider common mistakes when using the `pkgconfig.generate` function.
7. **Trace the user's path:**  Imagine how a user ends up calling this code.
8. **Summarize the functionalities.**
这是 Frida 动态 instrumentation 工具中 `pkgconfig.py` 模块的功能归纳：

**主要功能:**

该 Python 模块 (位于 `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/pkgconfig.py`) 的主要功能是**生成 `.pc` (pkg-config) 文件**。`.pc` 文件包含了关于软件库（library）的元数据，例如库的名称、版本、描述、依赖关系、编译和链接选项等。这些文件被构建系统（如 `pkg-config` 工具）用来在编译和链接其他依赖于该库的软件时查找必要的信息。

**详细功能点:**

1. **定义和注册 Meson 模块:**  该代码定义了一个名为 `PkgConfigModule` 的 Meson 扩展模块，使其可以在 Meson 构建脚本中使用。
2. **`generate` 方法:** 这是该模块的核心方法，用于生成 `.pc` 文件。它接收各种参数，用于描述要生成 `.pc` 文件的库及其依赖关系。
3. **处理库依赖:**  `generate` 方法能够处理各种类型的库依赖，包括：
    *   **内部库 (Internal Libraries):**  项目中构建的其他库。
    *   **外部库 (External Libraries):**  系统上已安装的库，可以通过 `dependency()` 函数找到。
    *   **自定义目标 (Custom Targets):**  通过 `custom_target()` 定义的构建产物。
4. **处理库的公共和私有依赖:**  区分库的公共 (`libraries`, `requires`) 和私有 (`libraries_private`, `requires_private`) 依赖，并在生成的 `.pc` 文件中分别列出。
5. **处理编译和链接选项:**  提取库的编译选项 (`extra_cflags`) 和链接选项，并将它们写入 `.pc` 文件。
6. **处理版本信息:**  可以指定库的版本 (`version`)，以及依赖库的版本要求 (`requires` 中的版本约束)。
7. **定义变量:**  允许用户在 `.pc` 文件中定义自定义变量 (`variables`, `uninstalled_variables`, `unescaped_variables`, `unescaped_uninstalled_variables`)。
8. **处理安装目录:**  可以指定 `.pc` 文件的安装目录 (`install_dir`)。
9. **处理冲突关系:**  可以指定与其他软件包的冲突关系 (`conflicts`)。
10. **支持 `dataonly` 模式:**  允许生成只包含元数据的 `.pc` 文件，不包含库依赖和编译/链接选项。
11. **处理子目录:**  允许指定头文件的子目录 (`subdirs`)。
12. **处理未安装状态:**  可以生成用于未安装状态的 `.pc` 文件，这些文件会指向构建目录下的文件。
13. **移除重复依赖:**  通过 `remove_dups` 方法，可以移除在处理依赖关系时产生的重复项，确保 `.pc` 文件的简洁性。

**与逆向方法的关联及举例:**

`.pc` 文件在逆向工程中扮演着辅助角色，主要体现在 **理解目标软件的依赖关系** 上。

*   **例子:**  假设你要逆向一个使用了 Frida 核心库的应用程序。通过查看 Frida 核心库的 `.pc` 文件（如果存在并可访问），你可以了解它依赖于哪些其他库 (例如 GLib, libxml2)。这可以帮助你构建逆向环境，例如在调试器中加载必要的符号文件。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

该模块在以下方面涉及到相关知识：

*   **二进制底层:**  `.pc` 文件中包含的链接选项 (`-l`) 直接关联到链接器如何找到和链接二进制库文件。
*   **Linux:**
    *   `.pc` 文件是 Linux 系统上管理库依赖的标准方式之一，`pkg-config` 工具是 Linux 上常用的工具。
    *   模块中处理路径时使用了 `os.path` 模块，这是与操作系统文件系统交互的基础。
*   **Android:** 虽然 Android 使用自己的构建系统（如 Soong），但 `pkg-config` 仍然可以用于描述 Native 代码的依赖关系。Frida 本身也需要在 Android 上运行，因此理解 `.pc` 文件的作用是有意义的。
*   **库的类型:** 代码中区分了共享库 (`build.SharedLibrary`) 和静态库 (`build.StaticLibrary`)，这直接关联到二进制链接的不同方式。

**逻辑推理及假设输入与输出:**

假设用户在 `meson.build` 文件中调用了 `pkgconfig.generate` 方法，如下所示：

```python
libfoo = shared_library('foo', 'foo.c')
glib_dep = dependency('glib-2.0')

pkgconfig.generate(
    libfoo,
    name: 'libfoo',
    description: 'A test library',
    version: '1.0',
    libraries: glib_dep,
    requires: 'bar >= 2.0'
)
```

*   **假设输入:**  上述 `meson.build` 代码片段。
*   **逻辑推理:** `pkgconfig.generate` 方法会根据提供的参数，以及 `libfoo` 和 `glib_dep` 对象的信息，生成一个名为 `libfoo.pc` 的文件。
*   **预期输出 (部分):**  生成的 `libfoo.pc` 文件可能包含以下内容：

    ```
    prefix=/usr/local
    libdir=${prefix}/lib
    includedir=${prefix}/include

    Name: libfoo
    Description: A test library
    Version: 1.0
    Requires: bar >= 2.0, glib-2.0
    Libs: -L${libdir} -lfoo
    Cflags: -I${includedir}
    ```

**用户或编程常见的使用错误及举例:**

1. **缺少必要的参数:**  如果 `generate` 方法没有以位置参数传递库对象，则必须提供 `name` 和 `description` 关键字参数。否则会抛出 `build.InvalidArguments` 异常。
    *   **错误示例:** `pkgconfig.generate(version: '1.0')`  (缺少库对象或 `name`/`description`)
2. **`dataonly` 模式与库依赖参数混用:**  在 `dataonly` 模式下，不能使用 `libraries`, `libraries_private`, `requires_private`, `extra_cflags`, `subdirs` 等参数。
    *   **错误示例:** `pkgconfig.generate(name: 'data', description: 'Data only', dataonly: true, libraries: libfoo)`
3. **提供了空的 `filebase` 或 `name`:**  `filebase` 和 `name` 参数不能为空字符串。
    *   **错误示例:** `pkgconfig.generate(libfoo, name: '')`
4. **`pkgconfig` 前缀超出 `prefix`:** 当设置 `relocatable=true` 时，`pkgroot` 必须是 `prefix` 的父目录或相同目录。
5. **在 `requires` 中使用非字符串、库或依赖对象:**  `requires` 参数中的元素必须是字符串、通过 `pkgconfig.generate` 生成 `.pc` 文件的库、或者 `pkgconfig` 依赖对象。
    *   **错误示例:**  `pkgconfig.generate(libfoo, requires: 123)`

**用户操作如何一步步到达这里，作为调试线索:**

1. **用户编写 `meson.build` 文件:** 用户在项目的 `meson.build` 文件中编写构建规则，其中包括使用 `shared_library` 或 `static_library` 定义库，并使用 `pkgconfig.generate` 函数来生成该库的 `.pc` 文件。
2. **用户运行 Meson 配置:**  用户在命令行中执行 `meson setup builddir`，Meson 会解析 `meson.build` 文件。
3. **Meson 解析 `pkgconfig.generate` 调用:** 当 Meson 解析到 `pkgconfig.generate` 的调用时，会加载 `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/pkgconfig.py` 模块。
4. **执行 `generate` 方法:** Meson 将根据 `meson.build` 文件中提供的参数调用 `generate` 方法。
5. **如果在 `generate` 方法中发生错误:** 例如，用户没有提供必要的参数，或者参数类型不正确，Python 解释器会抛出异常。
6. **调试线索:**  为了调试这类问题，用户可以：
    *   检查 `meson.build` 文件中 `pkgconfig.generate` 的参数是否正确。
    *   查看 Meson 的输出日志，通常会包含错误信息和调用堆栈。
    *   如果需要更深入的调试，可以在 `pkgconfig.py` 文件中添加 `print` 语句来跟踪代码执行流程和变量值。

总而言之，`frida/subprojects/frida-core/releng/meson/mesonbuild/modules/pkgconfig.py` 模块的主要职责是自动化生成库的 `.pc` 文件，这对于库的发布和被其他项目依赖至关重要。 它封装了处理各种依赖关系、编译选项和版本信息的逻辑，简化了 `.pc` 文件的创建过程。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/pkgconfig.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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