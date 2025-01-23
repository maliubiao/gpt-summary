Response:
The user wants to understand the functionality of the provided Python code. This code is a module within the Meson build system, specifically designed to handle tasks related to GNOME and GLib development.

Here's a breakdown of the thought process to analyze the code and answer the user's request:

1. **Identify the Core Purpose:** The first lines of the code clearly state its purpose: "This module provides helper functions for Gnome/GLib related functionality such as gobject-introspection, gresources and gtk-doc". This immediately tells us the module's domain.

2. **Scan for Key Functions:** Look for the `class GnomeModule(ExtensionModule):` and its methods. These methods represent the primary functionalities offered by the module. The `methods.update({...})` dictionary lists the names of these functions:
    - `post_install`
    - `compile_resources`
    - `generate_gir`
    - `compile_schemas`
    - `yelp`
    - `gtkdoc`
    - `gtkdoc_html_dir`
    - `gdbus_codegen`
    - `mkenums`
    - `mkenums_simple`
    - `genmarshal`
    - `generate_vapi`

3. **Understand Each Function's Role (Based on Name and Arguments):**  Try to infer the purpose of each function based on its name and the arguments it accepts (the `typed_kwargs` and `typed_pos_args` decorators are very helpful here).
    - `post_install`: Likely deals with actions performed after the main build process, like updating icon caches or schemas.
    - `compile_resources`:  Seems to handle the compilation of GNOME resources (`.gresource` files).
    - `generate_gir`: Probably involved in generating GObject Introspection (GIR) files, which are used for language bindings.
    - `compile_schemas`: Likely compiles GLib schemas.
    - `yelp`:  Might be related to building Yelp documentation.
    - `gtkdoc`:  Deals with generating GTK documentation using gtk-doc.
    - `gtkdoc_html_dir`:  Potentially retrieves the output directory for GTK documentation.
    - `gdbus_codegen`:  Likely generates code from GDBus interface descriptions.
    - `mkenums`/`mkenums_simple`:  Probably generate C/C++ code for enumerations.
    - `genmarshal`:  Might be used for generating marshalling code for GObject properties and signals.
    - `generate_vapi`:  Seems to generate Vala API files from GIR files.

4. **Look for Interactions with Reverse Engineering:**  Consider how the listed functionalities could be relevant to reverse engineering. Think about the information generated or processed by these tools.
    - **GIR files:**  Contain metadata about libraries, including function signatures and object structures, which can be invaluable for understanding how software works.
    - **GDBus code:**  Reveals inter-process communication interfaces, which are crucial for understanding component interactions.
    - **Compiled resources:** Might contain embedded data or logic that could be analyzed.

5. **Identify Low-Level and Kernel Interactions:**  Search for keywords or function names that suggest interactions with the operating system or lower levels.
    - The module uses tools like `gio-querymodules`, `glib-compile-schemas`, `update-desktop-database`, `update-mime-database`. These tools directly interact with the system to update its state.
    - The compilation of resources and schemas can involve manipulating binary data.
    - The generation of marshalling code touches on memory layout and data representation.

6. **Analyze Logic and Assumptions:**  Look at the conditional statements and the way the code handles different scenarios. For example, the warnings about GLib versions indicate that the module has to account for different environmental conditions. The checks for tool availability (`state.find_tool`) and dependency versions are also logical decisions.

7. **Consider User Errors:** Think about how a user might misuse these functions or encounter common problems. For example, providing incorrect file paths, missing dependencies, or using incompatible GLib versions.

8. **Trace User Steps (Debugging Clues):** Imagine a developer using Meson. How would they end up calling these specific functions? They would typically:
    - Have a Meson project (`meson.build`).
    - Include the `gnome` module in their `meson.build` file (implicitly by using the functions).
    - Call the functions from the `gnome` module within their `meson.build` file, passing arguments as needed.
    - Run the `meson` command to configure the build system.

9. **Synthesize and Summarize:**  Combine the findings into a concise summary of the module's functionality.

**Self-Correction/Refinement:** Initially, I might only focus on the direct outputs (like GIR files). However, realizing that the *process* of generating those files, the dependencies involved, and the system interactions are also important functionalities helps to provide a more complete picture. Also, the distinction between direct reverse engineering relevance and more indirect utility (like understanding system setup through post-install scripts) is crucial.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/gnome.py` 文件的第一部分，主要定义了 Meson 构建系统中用于处理 GNOME 相关任务的模块。它的核心功能是提供了一系列辅助函数，用于集成和使用各种 GNOME 和 GLib 的工具，以便在构建过程中生成代码、文档、资源等。

**以下是该部分代码的主要功能归纳：**

1. **定义 GNOME 模块:**  声明了一个名为 `GnomeModule` 的类，继承自 `ExtensionModule`，这是 Meson 中定义扩展模块的标准方式。这个类将包含所有与 GNOME 功能相关的构建方法。

2. **工具查找:** 提供了 `_find_tool` 方法，用于查找系统上安装的 GNOME 相关工具，例如 `gio-querymodules`, `glib-compile-resources`, `g-ir-scanner` 等。它会根据工具名称查找对应的依赖（例如 `gio-2.0` 或 `gobject-introspection-1.0`），并尝试找到可执行文件。

3. **`post_install` 函数:**  定义了一个 `post_install` 方法，用于在构建完成后执行一些安装后的任务，例如：
    - 使用 `glib-compile-schemas` 编译 GLib 模式文件。
    - 使用 `gio-querymodules` 更新 GIO 模块缓存。
    - 使用 `gtk-update-icon-cache` 更新 GTK 图标缓存。
    - 使用 `update-desktop-database` 更新桌面数据库。
    - 使用 `update-mime-database` 更新 MIME 数据库。

4. **`compile_resources` 函数:** 定义了一个 `compile_resources` 方法，用于使用 `glib-compile-resources` 工具编译 GNOME 资源文件 (`.gresource`)。它可以生成 C 或 C++ 代码，或者直接生成 `.gresource` 二进制文件。

5. **`generate_gir` 函数:**  虽然这部分代码没有完整展示 `generate_gir` 的实现，但从导入和类型提示可以看出，这个函数的目标是使用 `g-ir-scanner` 和 `g-ir-compiler` 工具生成 GObject Introspection (GIR) 文件。GIR 文件描述了库的 API，用于生成其他语言的绑定。

6. **`compile_schemas` 函数:** 同样，虽然实现未完整展示，但从名称推断，此函数负责使用 `glib-compile-schemas` 编译 GLib 模式文件。

7. **`yelp` 函数:**  从类型提示可以看出，这个函数可能用于处理 Yelp 文档的构建。

8. **`gtkdoc` 函数:** 定义了一个 `gtkdoc` 方法，用于集成 gtk-doc 工具来生成 GTK 库的文档。

9. **`gtkdoc_html_dir` 函数:**  可能用于获取生成的 GTK 文档的 HTML 输出目录。

10. **`gdbus_codegen` 函数:**  定义了一个 `gdbus_codegen` 方法，用于使用 `gdbus-codegen` 工具从 GDBus XML 接口描述文件生成代码。

11. **`mkenums` 和 `mkenums_simple` 函数:**  定义了用于生成 C/C++ 枚举类型代码的方法，可以使用不同的模板和配置。

12. **`genmarshal` 函数:** 定义了一个 `genmarshal` 方法，用于使用 `glib-genmarshal` 工具生成用于 GObject 属性和信号的编组代码。

13. **`generate_vapi` 函数:** 定义了一个 `generate_vapi` 方法，用于从 GIR 文件生成 Vala API 定义文件 (`.vapi`)。

14. **辅助功能:**  包含一些辅助方法和常量，例如：
    - `_get_native_glib_version`: 获取本地系统安装的 GLib 版本。
    - `__print_gresources_warning`: 在 GLib 版本过低时发出关于 `gresource` 依赖问题的警告。
    - `_print_gdbus_warning`:  发出关于旧版本 GLib 使用 `gdbus_codegen` 生成代码时需要添加 include 目录的警告。
    - `_get_gresource_dependencies`:  用于获取 `gresource` 文件的依赖项。
    - `_get_link_args`:  用于构建链接参数。
    - `_get_dependencies_flags_raw`:  用于获取依赖项的编译和链接标志。

15. **类型定义:**  使用了 `typing` 模块定义了各种类型别名 (`TypedDict`)，用于增强代码的可读性和类型检查，例如 `PostInstall`, `CompileResources`, `GenerateGir` 等，这些类型定义了各个函数可以接受的关键字参数。

**与逆向方法的关系及举例说明：**

- **GObject Introspection (GIR) 文件:** `generate_gir` 函数生成的 GIR 文件对于逆向工程非常有用。GIR 文件包含了库的元数据，包括结构体定义、函数签名、枚举类型等。逆向工程师可以使用这些信息来理解库的 API，从而更好地分析使用了该库的程序。例如，Frida 本身就可以利用 GIR 文件来动态调用目标进程中的函数。假设目标程序使用了 GLib 库，逆向工程师可以使用 Frida 加载 GLib 的 GIR 文件，然后通过 Frida 脚本直接调用 GLib 的函数，例如操作字符串或数据结构。

- **GDBus 代码:** `gdbus_codegen` 生成的代码定义了应用程序通过 D-Bus 进行进程间通信的接口。逆向工程师可以通过分析这些生成的代码来了解应用程序提供的服务和可以接收的消息，从而理解应用程序的组件交互方式。例如，如果一个 Android 应用程序使用 GDBus 与后台服务通信，逆向工程师可以通过分析生成的代码来确定可以发送哪些命令到服务，以及服务会返回什么数据。

- **编译的资源文件:** `compile_resources` 生成的二进制资源文件可能包含应用程序使用的图像、UI 定义或其他数据。逆向工程师可能需要提取和分析这些资源以了解应用程序的外观和行为。例如，一个桌面应用程序的 `.gresource` 文件可能包含了它的图标和窗口布局，逆向工程师可以通过工具（如 `gresource extract`）提取这些资源进行查看。

**涉及二进制底层，Linux, Android 内核及框架的知识的举例说明：**

- **二进制底层:** 编译资源和生成编组代码涉及到将高级数据结构和逻辑转换为二进制表示。`compile_resources` 将 XML 描述的资源转换为二进制数据。`genmarshal` 生成的代码负责在函数调用时将参数打包成二进制格式，以及在接收返回值时进行解包。

- **Linux:** 许多 GNOME 工具和库是 Linux 桌面环境的核心组件。例如，D-Bus 是 Linux 系统上常用的进程间通信机制，`gdbus_codegen` 就与 D-Bus 相关。`glib-compile-schemas` 操作的是 Linux 系统中存储应用配置的模式文件。

- **Android 框架:** 虽然 GNOME 主要用于桌面环境，但 GLib 及其相关技术有时也会在 Android 上使用。例如，某些 Android 系统组件或第三方库可能会使用 GLib 的数据结构或 IPC 机制。如果 Frida 分析的目标是 Android 上的使用了 GLib 的 native 代码，那么理解这些 GNOME 模块的功能仍然是有帮助的。

**逻辑推理的假设输入与输出：**

**假设输入 `compile_resources` 函数：**

```python
gnome.compile_resources(
    'my-resources',
    'resources.xml',
    c_name: 'MyResources',
    export: true,
    install: true,
    install_dir: 'share/my-app'
)
```

**逻辑推理：**

- Meson 会调用 `compile_resources` 函数。
- `glib-compile-resources` 工具会被调用。
- 输入文件是 `resources.xml`。
- 生成的 C 代码中的资源名称前缀将是 `MyResources`。
- 生成的头文件将会被安装。
- 资源头文件和包含资源数据的 C 代码将被生成。
- 生成的头文件将被安装到 `share/my-app/include` 目录（假设这是默认的头文件安装位置）。
- 生成的包含资源数据的 C 代码不会被直接安装，但会被编译到程序中。

**输出：**

- 生成一个名为 `my-resources.c` 或 `my-resources.cpp` 的源文件，其中包含了编译后的资源数据。
- 生成一个名为 `my-resources.h` 的头文件，其中声明了访问这些资源的外部符号。
- 在安装阶段，`my-resources.h` 会被复制到 `share/my-app/include` 目录。

**涉及用户或者编程常见的使用错误及举例说明：**

- **忘记安装依赖:** 用户可能在使用 `gnome.generate_gir` 前没有安装 `gobject-introspection` 软件包，导致 `g-ir-scanner` 找不到。Meson 在配置阶段会报错提示缺少依赖。

- **`compile_resources` 的输入文件路径错误:** 用户可能在 `compile_resources` 中提供了错误的 `resources.xml` 文件路径，导致 `glib-compile-resources` 无法找到输入文件，构建失败。

- **`gdbus_codegen` 的接口 XML 文件格式错误:** 用户提供的 GDBus 接口 XML 文件可能存在语法错误，导致 `gdbus-codegen` 解析失败。

- **在旧版本的 GLib 中使用 `compile_resources` 的 `dependencies` 参数:**  代码中提到了 GLib 的版本问题。在旧版本中，`compile_resources` 的 `dependencies` 参数可能无法正常工作，因为 `glib-compile-resources` 的行为不一致。用户如果使用了不兼容的特性，可能会遇到构建错误或者运行时问题。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 `meson.build` 文件:** 用户在其项目的根目录下创建或编辑 `meson.build` 文件。
2. **使用 `gnome` 模块的函数:** 在 `meson.build` 文件中，用户调用了 `gnome` 模块提供的函数，例如 `gnome.compile_resources()`, `gnome.generate_gir()` 等，并传递了相应的参数。
3. **运行 `meson` 命令:** 用户在项目根目录下打开终端，并执行 `meson setup builddir` 或 `meson configure builddir` 命令（其中 `builddir` 是构建目录）。
4. **Meson 解析 `meson.build`:** Meson 读取并解析 `meson.build` 文件。当遇到 `gnome.compile_resources()` 等调用时，Meson 会加载 `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/gnome.py` 模块。
5. **调用相应的模块方法:** Meson 根据用户在 `meson.build` 文件中的调用，执行 `GnomeModule` 类中对应的方法，例如 `compile_resources`。
6. **参数传递和处理:** 用户在 `meson.build` 中提供的参数会作为参数传递给 `compile_resources` 等方法。
7. **执行外部工具:**  `compile_resources` 方法内部会调用系统上的 `glib-compile-resources` 工具，并将相关的参数传递给它。

作为调试线索，如果用户在使用 GNOME 模块时遇到问题，例如构建错误，可以：

- **检查 `meson.build` 文件:**  确认 `gnome` 模块的函数调用是否正确，参数是否传递正确。
- **查看 Meson 的输出:** Meson 的输出会显示执行的命令和任何错误信息，可以帮助定位问题。
- **确认依赖是否安装:**  检查系统中是否安装了所需的 GNOME 工具和库（例如 `glib-compile-resources`, `gobject-introspection`）。
- **检查 GLib 版本:** 如果涉及到 `gresource` 或 `gdbus_codegen`，需要注意 GLib 的版本是否满足要求。
- **逐步调试 `meson.build`:**  可以使用 `meson introspect` 等命令来查看 Meson 的内部状态，帮助理解构建过程。

总而言之，该部分代码是 Frida 项目中用于集成 GNOME 相关构建任务的关键组件，它通过封装 GNOME 工具，简化了在 Meson 构建系统中生成代码、文档和资源的过程。理解其功能对于理解 Frida 的构建流程以及如何与 GNOME 生态系统交互至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/gnome.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2015-2016 The Meson development team

'''This module provides helper functions for Gnome/GLib related
functionality such as gobject-introspection, gresources and gtk-doc'''
from __future__ import annotations

import copy
import itertools
import functools
import os
import subprocess
import textwrap
import typing as T

from . import (
    ExtensionModule, GirTarget, GResourceHeaderTarget, GResourceTarget, ModuleInfo,
    ModuleReturnValue, TypelibTarget, VapiTarget,
)
from .. import build
from .. import interpreter
from .. import mesonlib
from .. import mlog
from ..build import CustomTarget, CustomTargetIndex, Executable, GeneratedList, InvalidArguments
from ..dependencies import Dependency, InternalDependency
from ..dependencies.pkgconfig import PkgConfigDependency, PkgConfigInterface
from ..interpreter.type_checking import DEPENDS_KW, DEPEND_FILES_KW, ENV_KW, INSTALL_DIR_KW, INSTALL_KW, NoneType, DEPENDENCY_SOURCES_KW, in_set_validator
from ..interpreterbase import noPosargs, noKwargs, FeatureNew, FeatureDeprecated
from ..interpreterbase import typed_kwargs, KwargInfo, ContainerTypeInfo
from ..interpreterbase.decorators import typed_pos_args
from ..mesonlib import (
    MachineChoice, MesonException, OrderedSet, Popen_safe, join_args, quote_arg
)
from ..programs import OverrideProgram
from ..scripts.gettext import read_linguas

if T.TYPE_CHECKING:
    from typing_extensions import Literal, TypedDict

    from . import ModuleState
    from ..build import BuildTarget
    from ..compilers import Compiler
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_var, TYPE_kwargs
    from ..mesonlib import FileOrString
    from ..programs import ExternalProgram

    class PostInstall(TypedDict):
        glib_compile_schemas: bool
        gio_querymodules: T.List[str]
        gtk_update_icon_cache: bool
        update_desktop_database: bool
        update_mime_database: bool

    class CompileSchemas(TypedDict):

        build_by_default: bool
        depend_files: T.List[FileOrString]

    class Yelp(TypedDict):

        languages: T.List[str]
        media: T.List[str]
        sources: T.List[str]
        symlink_media: bool

    class CompileResources(TypedDict):

        build_by_default: bool
        c_name: T.Optional[str]
        dependencies: T.List[T.Union[mesonlib.File, CustomTarget, CustomTargetIndex]]
        export: bool
        extra_args: T.List[str]
        gresource_bundle: bool
        install: bool
        install_dir: T.Optional[str]
        install_header: bool
        source_dir: T.List[str]

    class GenerateGir(TypedDict):

        build_by_default: bool
        dependencies: T.List[Dependency]
        export_packages: T.List[str]
        extra_args: T.List[str]
        fatal_warnings: bool
        header: T.List[str]
        identifier_prefix: T.List[str]
        include_directories: T.List[T.Union[build.IncludeDirs, str]]
        includes: T.List[T.Union[str, GirTarget]]
        install: bool
        install_dir_gir: T.Optional[str]
        install_dir_typelib: T.Optional[str]
        link_with: T.List[T.Union[build.SharedLibrary, build.StaticLibrary]]
        namespace: str
        nsversion: str
        sources: T.List[T.Union[FileOrString, build.GeneratedTypes]]
        symbol_prefix: T.List[str]

    class GtkDoc(TypedDict):

        src_dir: T.List[T.Union[str, build.IncludeDirs]]
        main_sgml: str
        main_xml: str
        module_version: str
        namespace: str
        mode: Literal['xml', 'smgl', 'auto', 'none']
        html_args: T.List[str]
        scan_args: T.List[str]
        scanobjs_args: T.List[str]
        fixxref_args: T.List[str]
        mkdb_args: T.List[str]
        content_files: T.List[T.Union[build.GeneratedTypes, FileOrString]]
        ignore_headers: T.List[str]
        install_dir: T.List[str]
        check: bool
        install: bool
        gobject_typesfile: T.List[FileOrString]
        html_assets: T.List[FileOrString]
        expand_content_files: T.List[FileOrString]
        c_args: T.List[str]
        include_directories: T.List[T.Union[str, build.IncludeDirs]]
        dependencies: T.List[T.Union[Dependency, build.SharedLibrary, build.StaticLibrary]]

    class GdbusCodegen(TypedDict):

        sources: T.List[FileOrString]
        extra_args: T.List[str]
        interface_prefix: T.Optional[str]
        namespace: T.Optional[str]
        object_manager: bool
        build_by_default: bool
        annotations: T.List[T.List[str]]
        install_header: bool
        install_dir: T.Optional[str]
        docbook: T.Optional[str]
        autocleanup: Literal['all', 'none', 'objects', 'default']

    class GenMarshal(TypedDict):

        build_always: T.Optional[str]
        build_always_stale: T.Optional[bool]
        build_by_default: T.Optional[bool]
        depend_files: T.List[mesonlib.File]
        extra_args: T.List[str]
        install_dir: T.Optional[str]
        install_header: bool
        internal: bool
        nostdinc: bool
        prefix: T.Optional[str]
        skip_source: bool
        sources: T.List[FileOrString]
        stdinc: bool
        valist_marshallers: bool

    class GenerateVapi(TypedDict):

        sources: T.List[T.Union[str, GirTarget]]
        install_dir: T.Optional[str]
        install: bool
        vapi_dirs: T.List[str]
        metadata_dirs: T.List[str]
        gir_dirs: T.List[str]
        packages: T.List[T.Union[str, InternalDependency]]

    class _MkEnumsCommon(TypedDict):

        install_header: bool
        install_dir: T.Optional[str]
        identifier_prefix: T.Optional[str]
        symbol_prefix: T.Optional[str]

    class MkEnumsSimple(_MkEnumsCommon):

        sources: T.List[FileOrString]
        header_prefix: str
        decorator: str
        function_prefix: str
        body_prefix: str

    class MkEnums(_MkEnumsCommon):

        sources: T.List[T.Union[FileOrString, build.GeneratedTypes]]
        c_template: T.Optional[FileOrString]
        h_template: T.Optional[FileOrString]
        comments: T.Optional[str]
        eprod: T.Optional[str]
        fhead: T.Optional[str]
        fprod: T.Optional[str]
        ftail: T.Optional[str]
        vhead: T.Optional[str]
        vprod: T.Optional[str]
        vtail: T.Optional[str]
        depends: T.List[T.Union[BuildTarget, CustomTarget, CustomTargetIndex]]

    ToolType = T.Union[Executable, ExternalProgram, OverrideProgram]


# Differs from the CustomTarget version in that it straight defaults to True
_BUILD_BY_DEFAULT: KwargInfo[bool] = KwargInfo(
    'build_by_default', bool, default=True,
)

_EXTRA_ARGS_KW: KwargInfo[T.List[str]] = KwargInfo(
    'extra_args',
    ContainerTypeInfo(list, str),
    default=[],
    listify=True,
)

_MK_ENUMS_COMMON_KWS: T.List[KwargInfo] = [
    INSTALL_KW.evolve(name='install_header'),
    INSTALL_DIR_KW,
    KwargInfo('identifier_prefix', (str, NoneType)),
    KwargInfo('symbol_prefix', (str, NoneType)),
]

def annotations_validator(annotations: T.List[T.Union[str, T.List[str]]]) -> T.Optional[str]:
    """Validate gdbus-codegen annotations argument"""

    badlist = 'must be made up of 3 strings for ELEMENT, KEY, and VALUE'

    if not annotations:
        return None
    elif all(isinstance(annot, str) for annot in annotations):
        if len(annotations) == 3:
            return None
        else:
            return badlist
    elif not all(isinstance(annot, list) for annot in annotations):
        for c, annot in enumerate(annotations):
            if not isinstance(annot, list):
                return f'element {c+1} must be a list'
    else:
        for c, annot in enumerate(annotations):
            if len(annot) != 3 or not all(isinstance(i, str) for i in annot):
                return f'element {c+1} {badlist}'
    return None

# gresource compilation is broken due to the way
# the resource compiler and Ninja clash about it
#
# https://github.com/ninja-build/ninja/issues/1184
# https://bugzilla.gnome.org/show_bug.cgi?id=774368
gresource_dep_needed_version = '>= 2.51.1'

class GnomeModule(ExtensionModule):

    INFO = ModuleInfo('gnome')

    def __init__(self, interpreter: 'Interpreter') -> None:
        super().__init__(interpreter)
        self.gir_dep: T.Optional[Dependency] = None
        self.giscanner: T.Optional[T.Union[ExternalProgram, Executable, OverrideProgram]] = None
        self.gicompiler: T.Optional[T.Union[ExternalProgram, Executable, OverrideProgram]] = None
        self.install_glib_compile_schemas = False
        self.install_gio_querymodules: T.List[str] = []
        self.install_gtk_update_icon_cache = False
        self.install_update_desktop_database = False
        self.install_update_mime_database = False
        self.devenv: T.Optional[mesonlib.EnvironmentVariables] = None
        self.native_glib_version: T.Optional[str] = None
        self.methods.update({
            'post_install': self.post_install,
            'compile_resources': self.compile_resources,
            'generate_gir': self.generate_gir,
            'compile_schemas': self.compile_schemas,
            'yelp': self.yelp,
            'gtkdoc': self.gtkdoc,
            'gtkdoc_html_dir': self.gtkdoc_html_dir,
            'gdbus_codegen': self.gdbus_codegen,
            'mkenums': self.mkenums,
            'mkenums_simple': self.mkenums_simple,
            'genmarshal': self.genmarshal,
            'generate_vapi': self.generate_vapi,
        })

    def _get_native_glib_version(self, state: 'ModuleState') -> str:
        if self.native_glib_version is None:
            glib_dep = PkgConfigDependency('glib-2.0', state.environment,
                                           {'native': True, 'required': False})
            if glib_dep.found():
                self.native_glib_version = glib_dep.get_version()
            else:
                mlog.warning('Could not detect glib version, assuming 2.54. '
                             'You may get build errors if your glib is older.')
                self.native_glib_version = '2.54'
        return self.native_glib_version

    @mesonlib.run_once
    def __print_gresources_warning(self, state: 'ModuleState') -> None:
        if not mesonlib.version_compare(self._get_native_glib_version(state),
                                        gresource_dep_needed_version):
            mlog.warning('GLib compiled dependencies do not work reliably with \n'
                         'the current version of GLib. See the following upstream issue:',
                         mlog.bold('https://bugzilla.gnome.org/show_bug.cgi?id=774368'),
                         once=True, fatal=False)

    @staticmethod
    def _print_gdbus_warning() -> None:
        mlog.warning('Code generated with gdbus_codegen() requires the root directory be added to\n'
                     '  include_directories of targets with GLib < 2.51.3:',
                     mlog.bold('https://github.com/mesonbuild/meson/issues/1387'),
                     once=True, fatal=False)

    @staticmethod
    def _find_tool(state: 'ModuleState', tool: str) -> 'ToolType':
        tool_map = {
            'gio-querymodules': 'gio-2.0',
            'glib-compile-schemas': 'gio-2.0',
            'glib-compile-resources': 'gio-2.0',
            'gdbus-codegen': 'gio-2.0',
            'glib-genmarshal': 'glib-2.0',
            'glib-mkenums': 'glib-2.0',
            'g-ir-scanner': 'gobject-introspection-1.0',
            'g-ir-compiler': 'gobject-introspection-1.0',
        }
        depname = tool_map[tool]
        varname = tool.replace('-', '_')
        return state.find_tool(tool, depname, varname)

    @typed_kwargs(
        'gnome.post_install',
        KwargInfo('glib_compile_schemas', bool, default=False),
        KwargInfo('gio_querymodules', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo('gtk_update_icon_cache', bool, default=False),
        KwargInfo('update_desktop_database', bool, default=False, since='0.59.0'),
        KwargInfo('update_mime_database', bool, default=False, since='0.64.0'),
    )
    @noPosargs
    @FeatureNew('gnome.post_install', '0.57.0')
    def post_install(self, state: 'ModuleState', args: T.List['TYPE_var'], kwargs: 'PostInstall') -> ModuleReturnValue:
        rv: T.List['mesonlib.ExecutableSerialisation'] = []
        datadir_abs = os.path.join(state.environment.get_prefix(), state.environment.get_datadir())
        if kwargs['glib_compile_schemas'] and not self.install_glib_compile_schemas:
            self.install_glib_compile_schemas = True
            prog = self._find_tool(state, 'glib-compile-schemas')
            schemasdir = os.path.join(datadir_abs, 'glib-2.0', 'schemas')
            script = state.backend.get_executable_serialisation([prog, schemasdir])
            script.skip_if_destdir = True
            rv.append(script)
        for d in kwargs['gio_querymodules']:
            if d not in self.install_gio_querymodules:
                self.install_gio_querymodules.append(d)
                prog = self._find_tool(state, 'gio-querymodules')
                moduledir = os.path.join(state.environment.get_prefix(), d)
                script = state.backend.get_executable_serialisation([prog, moduledir])
                script.skip_if_destdir = True
                rv.append(script)
        if kwargs['gtk_update_icon_cache'] and not self.install_gtk_update_icon_cache:
            self.install_gtk_update_icon_cache = True
            prog = state.find_program('gtk4-update-icon-cache', required=False)
            found = isinstance(prog, Executable) or prog.found()
            if not found:
                prog = state.find_program('gtk-update-icon-cache')
            icondir = os.path.join(datadir_abs, 'icons', 'hicolor')
            script = state.backend.get_executable_serialisation([prog, '-q', '-t', '-f', icondir])
            script.skip_if_destdir = True
            rv.append(script)
        if kwargs['update_desktop_database'] and not self.install_update_desktop_database:
            self.install_update_desktop_database = True
            prog = state.find_program('update-desktop-database')
            appdir = os.path.join(datadir_abs, 'applications')
            script = state.backend.get_executable_serialisation([prog, '-q', appdir])
            script.skip_if_destdir = True
            rv.append(script)
        if kwargs['update_mime_database'] and not self.install_update_mime_database:
            self.install_update_mime_database = True
            prog = state.find_program('update-mime-database')
            appdir = os.path.join(datadir_abs, 'mime')
            script = state.backend.get_executable_serialisation([prog, appdir])
            script.skip_if_destdir = True
            rv.append(script)
        return ModuleReturnValue(None, rv)

    @typed_pos_args('gnome.compile_resources', str, (str, mesonlib.File, CustomTarget, CustomTargetIndex, GeneratedList))
    @typed_kwargs(
        'gnome.compile_resources',
        _BUILD_BY_DEFAULT,
        _EXTRA_ARGS_KW,
        INSTALL_KW,
        INSTALL_KW.evolve(name='install_header', since='0.37.0'),
        INSTALL_DIR_KW,
        KwargInfo('c_name', (str, NoneType)),
        KwargInfo('dependencies', ContainerTypeInfo(list, (mesonlib.File, CustomTarget, CustomTargetIndex)), default=[], listify=True),
        KwargInfo('export', bool, default=False, since='0.37.0'),
        KwargInfo('gresource_bundle', bool, default=False, since='0.37.0'),
        KwargInfo('source_dir', ContainerTypeInfo(list, str), default=[], listify=True),
    )
    def compile_resources(self, state: 'ModuleState', args: T.Tuple[str, 'FileOrString'],
                          kwargs: 'CompileResources') -> 'ModuleReturnValue':
        self.__print_gresources_warning(state)
        glib_version = self._get_native_glib_version(state)

        glib_compile_resources = self._find_tool(state, 'glib-compile-resources')
        cmd: T.List[T.Union['ToolType', str]] = [glib_compile_resources, '@INPUT@']

        source_dirs = kwargs['source_dir']
        dependencies = kwargs['dependencies']

        target_name, input_file = args

        # Validate dependencies
        subdirs: T.List[str] = []
        depends: T.List[T.Union[CustomTarget, CustomTargetIndex]] = []
        for dep in dependencies:
            if isinstance(dep, mesonlib.File):
                subdirs.append(dep.subdir)
            else:
                depends.append(dep)
                subdirs.append(dep.get_source_subdir())
                if not mesonlib.version_compare(glib_version, gresource_dep_needed_version):
                    m = 'The "dependencies" argument of gnome.compile_resources() cannot\n' \
                        'be used with the current version of glib-compile-resources due to\n' \
                        '<https://bugzilla.gnome.org/show_bug.cgi?id=774368>'
                    raise MesonException(m)

        if not mesonlib.version_compare(glib_version, gresource_dep_needed_version):
            # Resource xml files generated at build-time cannot be used with
            # gnome.compile_resources() because we need to scan the xml for
            # dependencies. Use configure_file() instead to generate it at
            # configure-time
            if isinstance(input_file, mesonlib.File):
                # glib-compile-resources will be run inside the source dir,
                # so we need either 'src_to_build' or the absolute path.
                # Absolute path is the easiest choice.
                if input_file.is_built:
                    ifile = os.path.join(state.environment.get_build_dir(), input_file.subdir, input_file.fname)
                else:
                    ifile = os.path.join(input_file.subdir, input_file.fname)

            elif isinstance(input_file, (CustomTarget, CustomTargetIndex, GeneratedList)):
                raise MesonException('Resource xml files generated at build-time cannot be used with '
                                     'gnome.compile_resources() in the current version of glib-compile-resources '
                                     'because we need to scan the xml for dependencies due to '
                                     '<https://bugzilla.gnome.org/show_bug.cgi?id=774368>\nUse '
                                     'configure_file() instead to generate it at configure-time.')
            else:
                ifile = os.path.join(state.subdir, input_file)

            depend_files, depends, subdirs = self._get_gresource_dependencies(
                state, ifile, source_dirs, dependencies)

        # Make source dirs relative to build dir now
        source_dirs = [os.path.join(state.build_to_src, state.subdir, d) for d in source_dirs]
        # Ensure build directories of generated deps are included
        source_dirs += subdirs
        # Always include current directory, but after paths set by user
        source_dirs.append(os.path.join(state.build_to_src, state.subdir))

        # Clean up duplicate directories
        source_dirs = list(OrderedSet(os.path.normpath(dir) for dir in source_dirs))

        for source_dir in source_dirs:
            cmd += ['--sourcedir', source_dir]

        if kwargs['c_name']:
            cmd += ['--c-name', kwargs['c_name']]
        if not kwargs['export']:
            cmd += ['--internal']

        cmd += ['--generate', '--target', '@OUTPUT@']
        cmd += kwargs['extra_args']

        gresource = kwargs['gresource_bundle']
        if gresource:
            output = f'{target_name}.gresource'
            name = f'{target_name}_gresource'
        else:
            if 'c' in state.environment.coredata.compilers.host:
                output = f'{target_name}.c'
                name = f'{target_name}_c'
            elif 'cpp' in state.environment.coredata.compilers.host:
                output = f'{target_name}.cpp'
                name = f'{target_name}_cpp'
            else:
                raise MesonException('Compiling GResources into code is only supported in C and C++ projects')

        if kwargs['install'] and not gresource:
            raise MesonException('The install kwarg only applies to gresource bundles, see install_header')

        install_header = kwargs['install_header']
        if install_header and gresource:
            raise MesonException('The install_header kwarg does not apply to gresource bundles')
        if install_header and not kwargs['export']:
            raise MesonException('GResource header is installed yet export is not enabled')

        depfile: T.Optional[str] = None
        target_cmd: T.List[T.Union['ToolType', str]]
        if not mesonlib.version_compare(glib_version, gresource_dep_needed_version):
            # This will eventually go out of sync if dependencies are added
            target_cmd = cmd
        else:
            depfile = f'{output}.d'
            depend_files = []
            target_cmd = copy.copy(cmd) + ['--dependency-file', '@DEPFILE@']
        target_c = GResourceTarget(
            name,
            state.subdir,
            state.subproject,
            state.environment,
            target_cmd,
            [input_file],
            [output],
            state.is_build_only_subproject,
            build_by_default=kwargs['build_by_default'],
            depfile=depfile,
            depend_files=depend_files,
            extra_depends=depends,
            install=kwargs['install'],
            install_dir=[kwargs['install_dir']] if kwargs['install_dir'] else [],
            install_tag=['runtime'],
        )
        target_c.source_dirs = source_dirs

        if gresource: # Only one target for .gresource files
            return ModuleReturnValue(target_c, [target_c])

        install_dir = kwargs['install_dir'] or state.environment.coredata.get_option(mesonlib.OptionKey('includedir'))
        assert isinstance(install_dir, str), 'for mypy'
        target_h = GResourceHeaderTarget(
            f'{target_name}_h',
            state.subdir,
            state.subproject,
            state.environment,
            cmd,
            [input_file],
            [f'{target_name}.h'],
            state.is_build_only_subproject,
            build_by_default=kwargs['build_by_default'],
            extra_depends=depends,
            install=install_header,
            install_dir=[install_dir],
            install_tag=['devel'],
        )
        rv = [target_c, target_h]
        return ModuleReturnValue(rv, rv)

    @staticmethod
    def _get_gresource_dependencies(
            state: 'ModuleState', input_file: str, source_dirs: T.List[str],
            dependencies: T.Sequence[T.Union[mesonlib.File, CustomTarget, CustomTargetIndex]]
            ) -> T.Tuple[T.List[mesonlib.FileOrString], T.List[T.Union[CustomTarget, CustomTargetIndex]], T.List[str]]:

        cmd = ['glib-compile-resources',
               input_file,
               '--generate-dependencies']

        # Prefer generated files over source files
        cmd += ['--sourcedir', state.subdir] # Current build dir
        for source_dir in source_dirs:
            cmd += ['--sourcedir', os.path.join(state.subdir, source_dir)]

        try:
            pc, stdout, stderr = Popen_safe(cmd, cwd=state.environment.get_source_dir())
        except (FileNotFoundError, PermissionError):
            raise MesonException('Could not execute glib-compile-resources.')
        if pc.returncode != 0:
            m = f'glib-compile-resources failed to get dependencies for {cmd[1]}:\n{stderr}'
            mlog.warning(m)
            raise subprocess.CalledProcessError(pc.returncode, cmd)

        raw_dep_files: T.List[str] = stdout.split('\n')[:-1]

        depends: T.List[T.Union[CustomTarget, CustomTargetIndex]] = []
        subdirs: T.List[str] = []
        dep_files: T.List[mesonlib.FileOrString] = []
        for resfile in raw_dep_files.copy():
            resbasename = os.path.basename(resfile)
            for dep in dependencies:
                if isinstance(dep, mesonlib.File):
                    if dep.fname != resbasename:
                        continue
                    raw_dep_files.remove(resfile)
                    dep_files.append(dep)
                    subdirs.append(dep.subdir)
                    break
                elif isinstance(dep, (CustomTarget, CustomTargetIndex)):
                    fname = None
                    outputs = {(o, os.path.basename(o)) for o in dep.get_outputs()}
                    for o, baseo in outputs:
                        if baseo == resbasename:
                            fname = o
                            break
                    if fname is not None:
                        raw_dep_files.remove(resfile)
                        depends.append(dep)
                        subdirs.append(dep.get_source_subdir())
                        break
            else:
                # In generate-dependencies mode, glib-compile-resources doesn't raise
                # an error for missing resources but instead prints whatever filename
                # was listed in the input file.  That's good because it means we can
                # handle resource files that get generated as part of the build, as
                # follows.
                #
                # If there are multiple generated resource files with the same basename
                # then this code will get confused.
                try:
                    f = mesonlib.File.from_source_file(state.environment.get_source_dir(),
                                                       ".", resfile)
                except MesonException:
                    raise MesonException(
                        f'Resource "{resfile}" listed in "{input_file}" was not found. '
                        'If this is a generated file, pass the target that generates '
                        'it to gnome.compile_resources() using the "dependencies" '
                        'keyword argument.')
                raw_dep_files.remove(resfile)
                dep_files.append(f)
        dep_files.extend(raw_dep_files)
        return dep_files, depends, subdirs

    def _get_link_args(self, state: 'ModuleState',
                       lib: T.Union[build.SharedLibrary, build.StaticLibrary],
                       depends: T.Sequence[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]],
                       include_rpath: bool = False,
                       use_gir_args: bool = False
                       ) -> T.Tuple[T.List[str], T.List[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]]]:
        link_command: T.List[str] = []
        new_depends = list(depends)
        # Construct link args
        if isinstance(lib, build.SharedLibrary):
            libdir = os.path.join(state.environment.get_build_dir(), state.backend.get_target_dir(lib))
            link_command.append('-L' + libdir)
            if include_rpath:
                link_command.append('-Wl,-rpath,' + libdir)
            new_depends.append(lib)
            # Needed for the following binutils bug:
            # https://github.com/mesonbuild/meson/issues/1911
            # However, g-ir-scanner does not understand -Wl,-rpath
            # so we need to use -L instead
            for d in state.backend.determine_rpath_dirs(lib):
                d = os.path.join(state.environment.get_build_dir(), d)
                link_command.append('-L' + d)
                if include_rpath:
                    link_command.append('-Wl,-rpath,' + d)
        if use_gir_args and self._gir_has_option('--extra-library'):
            link_command.append('--extra-library=' + lib.name)
        else:
            link_command.append('-l' + lib.name)
        return link_command, new_depends

    def _get_dependencies_flags_raw(
            self, deps: T.Sequence[T.Union['Dependency', build.BuildTarget, CustomTarget, CustomTargetIndex]],
            state: 'ModuleState',
            depends: T.Sequence[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]],
            include_rpath: bool,
            use_gir_args: bool,
            ) -> T.Tuple[OrderedSet[str], OrderedSet[T.Union[str, T.Tuple[str, str]]], OrderedSet[T.Union[str, T.Tuple[str, str]]], OrderedSet[str],
                         T.List[T.Union[build.BuildTarget, 'build.GeneratedTypes', 'FileOrString', build.StructuredSources]]]:
        cflags: OrderedSet[str] = OrderedSet()
        # External linker flags that can't be de-duped reliably because they
        # require two args in order, such as -framework AVFoundation will be stored as a tuple.
        internal_ldflags: OrderedSet[T.Union[str, T.Tuple[str, str]]] = OrderedSet()
        external_ldflags: OrderedSet[T.Union[str, T.Tuple[str, str]]] = OrderedSet()
        gi_includes: OrderedSet[str] = OrderedSet()
        deps = mesonlib.listify(deps)
        depends = list(depends)

        for dep in deps:
            if isinstance(dep, Dependency):
                girdir = dep.get_variable(pkgconfig='girdir', internal='girdir', default_value='')
                if girdir:
                    assert isinstance(girdir, str), 'for mypy'
                    gi_includes.update([girdir])
            if isinstance(dep, InternalDependency):
                cflags.update(dep.get_compile_args())
                cflags.update(state.get_include_args(dep.include_directories))
                for lib in dep.libraries:
                    if isinstance(lib, build.SharedLibrary):
                        _ld, depends = self._get_link_args(state, lib, depends, include_rpath)
                        internal_ldflags.update(_ld)
                        libdepflags = self._get_dependencies_flags_raw(lib.get_external_deps(), state, depends, include_rpath,
                                                                       use_gir_args)
                        cflags.update(libdepflags[0])
                        internal_ldflags.update(libdepflags[1])
                        external_ldflags.update(libdepflags[2])
                        gi_includes.update(libdepflags[3])
                        depends = libdepflags[4]
                extdepflags = self._get_dependencies_flags_raw(dep.ext_deps, state, depends, include_rpath,
                                                               use_gir_args)
                cflags.update(extdepflags[0])
                internal_ldflags.update(extdepflags[1])
                external_ldflags.update(extdepflags[2])
                gi_includes.update(extdepflags[3])
                depends = extdepflags[4]
                for source in dep.sources:
                    if isinstance(source, GirTarget):
                        gi_includes.update([os.path.join(state.environment.get_build_dir(),
                                            source.get_source_subdir())])
            # This should be any dependency other than an internal one.
            elif isinstance(dep, Dependency):
                cflags.update(dep.get_compile_args())
                ldflags = iter(dep.get_link_args(raw=True))
                for flag in ldflags:
                    if (os.path.isabs(flag) and
                            # For PkgConfigDependency only:
                            getattr(dep, 'is_libtool', False)):
                        lib_dir = os.path.dirname(flag)
                        external_ldflags.update([f'-L{lib_dir}'])
                        if include_rpath:
                            external_ldflags.update([f'-Wl,-rpath {lib_dir}'])
                        libname = os.path.basename(flag)
                        if libname.startswith("lib"):
                            libname = libname[3:]
                        libname = libname.split(".so")[0]
                        flag = f"-l{libname}"
                    # FIXME: Hack to avoid passing some compiler options in
                    if flag.startswith("-W"):
                        continue
                    # If it's a framework arg, slurp the framework name too
                    # to preserve the order of arguments
                    if flag == '-framework':
                        external_ldflags.update([(flag, next(ldflags))])
                    else:
                        external_ldflags.update([flag])
            elif isinstance(dep, (build.StaticLibrary, build.SharedLibrary)):
                cflags.update(state.get_include_args(dep.get_include_dirs()))
                depends.append(dep)
            else:
                mlog.log(f'dependency {dep!r} not handled to build gir files')
                continue

        if use_gir_args and
```