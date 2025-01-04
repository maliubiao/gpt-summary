Response:
Let's break down the thought process for analyzing the provided Python code.

1. **Understand the Goal:** The request is to analyze the `i18n.py` file from the Frida project. The core goal is to understand its functionality, especially in relation to reverse engineering, low-level concepts, and potential user errors. We also need to trace how a user might interact with this code.

2. **Initial Code Scan (High-Level):**  Quickly read through the code to identify key components:
    * Imports:  `os`, `shlex`, `typing`, `mesonbuild` modules. This suggests it's part of a larger build system (Meson).
    * Class `I18nModule`: This is the main focus. It inherits from `ExtensionModule`, confirming it's a Meson module.
    * Methods within `I18nModule`: `merge_file`, `gettext`, `itstool_join`. These are the primary functions provided by this module.
    * Data structures: `PRESET_ARGS`, `tools`. These hold configuration and external program information.
    * Type hints: Extensive use of `typing` and `TypedDict`. This makes the code easier to understand and analyze.

3. **Analyze Each Method:**  Dive deeper into each method to understand its specific purpose:

    * **`merge_file`:**  The name suggests merging translation files. Keywords like `input`, `output`, `po_dir`, and `type` (xml, desktop) confirm this. It uses `msgfmt` (a gettext utility) to do the merging. The logic involves constructing a command-line to run `msgfmthelper`.

    * **`gettext`:** This method seems to handle the overall gettext workflow. It takes a package name and supports various options like languages, data directories, and presets. It interacts with several gettext tools (`msgfmt`, `msginit`, `msgmerge`, `xgettext`). It generates targets for creating `.pot` files (templates), `.mo` files (compiled translations), and updating `.po` files.

    * **`itstool_join`:** This method uses `itstool` to join translation files. It appears to be specific to a tool called `itstool` which likely deals with XML translation. It takes `.mo` files as input and combines them with ITS (Internationalization Tag Set) files.

4. **Identify Connections to Reverse Engineering:**

    * **Dynamic Instrumentation (Frida Context):** Remember the file context (Frida). Internationalization is crucial for user interfaces, including those within applications Frida might interact with. Being able to modify or analyze translations could reveal information about application behavior or expose vulnerabilities.
    * **`.mo` files:** These are compiled binary translation files. Understanding how they are generated is relevant for reverse engineers who might want to inspect or modify translations within an application.
    * **`gettext` in general:**  This is a standard localization framework. Reverse engineers often encounter it when analyzing applications. Understanding how `gettext` works is essential for understanding how an application supports multiple languages.

5. **Identify Connections to Low-Level Concepts:**

    * **Binary Files (`.mo`):**  Mention that `.mo` files are binary and require specific tools for manipulation.
    * **Linux/Android Kernel and Framework (Indirect):** Explain that while the Python code itself isn't kernel-level, the *results* (the generated translation files) are used by applications running on these systems. Localization is a fundamental aspect of OS and framework design.
    * **Command-line Tools:** The heavy reliance on external programs like `msgfmt`, `itstool`, etc., highlights the interaction with the underlying operating system.

6. **Logical Reasoning (Assumptions and Outputs):**

    * **`merge_file`:** Focus on how the input list of files is combined into a single output file using `msgfmt`.
    * **`gettext`:** Explain the generation of `.pot` files from source code and the compilation of `.po` to `.mo`. Highlight the language-specific output directories.
    * **`itstool_join`:** Explain how it combines multiple `.mo` files and ITS files.

7. **User Errors:**

    * **Incorrect `install_dir`:**  Emphasize the requirement for `install_dir` when `install` is true.
    * **Missing tools:** Highlight the warnings issued when gettext tools are not found.
    * **Incorrect tool versions:** Specifically mention the `msgfmt` version requirement in `merge_file`.
    * **Incorrect input/output paths:** Standard file system errors.

8. **Debugging Trace:**  Think about the steps a user would take to trigger this code:

    * **Writing a `meson.build` file:** This is the entry point for Meson. The user would need to include `i18n.merge_file`, `i18n.gettext`, or `i18n.itstool_join` calls in their build definition.
    * **Running `meson`:** This command parses the `meson.build` file and executes the build logic, including the Python module.
    * **Examining the build log:**  Errors or warnings from this module would appear in the Meson build log.

9. **Structure and Clarity:** Organize the analysis into clear sections based on the prompt's requirements. Use examples to illustrate concepts. Maintain a consistent tone and level of detail.

10. **Review and Refine:**  Read through the analysis to ensure accuracy, completeness, and clarity. Check for any logical gaps or inconsistencies. For instance, initially, I might not have explicitly linked the `.mo` files to reverse engineering, but on review, connecting the dots about application behavior and localization becomes important. Similarly, clarifying the *indirect* link to the kernel and framework is crucial.
好的，让我们详细分析一下 `frida/releng/meson/mesonbuild/modules/i18n.py` 这个文件的功能。

**文件功能概览**

这个 Python 文件是 Frida 项目中 Meson 构建系统的一个模块，专门用于处理国际化（i18n）和本地化（l10n）相关的功能。它提供了一系列方法，帮助开发者在构建过程中提取、合并和编译翻译文件。

具体来说，这个模块主要负责以下任务：

1. **合并翻译文件 (`merge_file` 方法):** 将多个翻译文件（通常是 `.po` 文件）合并成一个或多个最终的翻译文件，例如 `.mo` 文件。这在需要将针对不同组件或功能的翻译文件整合到一个应用程序中时非常有用。

2. **Gettext 处理 (`gettext` 方法):**  集成 Gettext 工具链，用于从源代码中提取需要翻译的文本，生成 `.pot` 模板文件，并根据已有的 `.po` 文件编译生成 `.mo` 文件。Gettext 是一个广泛使用的国际化框架。

3. **itstool 集成 (`itstool_join` 方法):** 集成 `itstool` 工具，用于将 `.mo` 文件与 ITS (Internationalization Tag Set) 文件合并。ITS 是一种用于 XML 和其他基于文本的文档的国际化和本地化的标准。

**与逆向方法的关联**

国际化和本地化在逆向工程中扮演着重要的角色。理解和修改应用程序的翻译可以帮助逆向工程师：

* **理解应用程序的功能和行为:**  通过分析翻译文本，可以更深入地了解应用程序的用户界面、错误消息和内部逻辑。例如，某个特定的翻译字符串可能暗示了某个隐藏的功能或模块的存在。
* **发现安全漏洞:** 有时，翻译字符串中可能包含敏感信息，例如内部 API 端点、调试信息或者不安全的提示。逆向工程师可以通过分析这些字符串来发现潜在的安全漏洞。
* **修改应用程序的行为:**  通过替换或修改翻译文件，逆向工程师可以修改应用程序的显示文本，例如修改错误消息、添加调试信息或者进行欺骗性的修改。

**`i18n.py` 与逆向的举例说明：**

假设一个逆向工程师正在分析一个使用了 Gettext 进行国际化的应用程序。

1. **使用 `gettext` 生成的 `.mo` 文件：**  逆向工程师可能会提取应用程序的 `.mo` 文件。这些文件包含了编译后的翻译字符串。通过反编译 `.mo` 文件，逆向工程师可以查看应用程序支持的语言以及对应的翻译文本。
2. **修改 `.mo` 文件：** 逆向工程师可以使用工具修改 `.mo` 文件中的翻译字符串，例如将某个错误消息改成更有利于调试的信息，或者将某个功能描述修改成误导性的内容，以观察应用程序的行为。
3. **分析 `merge_file` 的输入：** 如果逆向工程师能够获取到构建过程中的 `.po` 文件（`merge_file` 的输入），他们可以分析这些文件，了解开发者是如何组织和管理翻译的，以及可能存在的未完成或有问题的翻译。

**涉及二进制底层、Linux、Android 内核及框架的知识**

虽然 `i18n.py` 本身是一个 Python 脚本，运行在构建系统层面，但它处理的对象和最终的产物与二进制底层、操作系统和框架密切相关：

* **`.mo` 文件 (二进制底层):**  `.mo` 文件是二进制文件，包含了编译后的消息目录。应用程序在运行时会加载这些文件以实现本地化。理解 `.mo` 文件的结构对于逆向工程和修改翻译至关重要。
* **Gettext 在 Linux/Android 中的应用:** Gettext 是 Linux 和 Android 系统中常见的国际化框架。理解 Gettext 的工作原理，例如 `gettext()` 函数如何查找和加载翻译，有助于理解应用程序的本地化机制。
* **Android Framework 的本地化:** Android 框架本身也使用了国际化机制。`i18n.py` 生成的翻译文件最终可能被打包到 Android 应用程序的 APK 文件中，并由 Android 系统的本地化服务加载和使用。
* **内核层面的语言设置:** 操作系统内核层面也会有语言和区域设置。应用程序的本地化行为通常会受到这些设置的影响。

**`i18n.py` 与相关知识的举例说明：**

* **`.mo` 文件结构:**  `i18n.py` 使用 `msgfmt` 工具生成 `.mo` 文件。了解 `.mo` 文件的 magic number、header 和消息条目的结构，有助于逆向工程师解析和修改这些二进制文件。
* **`bindtextdomain()` 和 `dgettext()`:**  在 Linux 或 Android 应用程序中，通常会使用 `bindtextdomain()` 函数来指定消息目录的位置，并使用 `dgettext()` 函数来获取特定域的翻译字符串。`i18n.py` 的输出结果（`.mo` 文件）会被这些函数使用。
* **Android 的 `Resources` 和 `Locale`:** 在 Android 开发中，翻译字符串通常存储在 `res/values-<locale>` 目录下。虽然 `i18n.py` 主要处理 Gettext 格式，但理解 Android 的资源管理机制有助于理解整个本地化流程。

**逻辑推理 (假设输入与输出)**

让我们针对 `merge_file` 和 `gettext` 方法进行逻辑推理：

**`merge_file` 方法:**

* **假设输入:**
    * `input`:  包含两个 `.po` 文件的列表，例如 `['zh_CN.po', 'zh_TW.po']`。
    * `output`:  字符串 `'combined.mo'`。
    * `po_dir`: 字符串 `'locales'`。
    * `type`: 字符串 `'desktop'`。
* **预期输出:**
    * 创建一个 Meson `CustomTarget` 对象，该对象会调用 `msgfmthelper` 脚本。
    * 该 `CustomTarget` 的命令会包含 `msgfmt` 工具的路径，以及输入和输出文件的信息，并指定输出类型为 `desktop`。
    * 最终在构建目录下会生成一个名为 `combined.mo` 的文件，它包含了 `zh_CN.po` 和 `zh_TW.po` 中翻译的合并结果。

**`gettext` 方法:**

* **假设输入:**
    * `args`:  包含一个字符串，表示包名，例如 `['my_app']`。
    * `languages`: 包含一个语言代码列表，例如 `['zh_CN', 'en_US']`。
* **预期输出:**
    * 创建多个 Meson `CustomTarget` 和 `RunTarget` 对象。
    * 创建一个名为 `my_app-pot` 的 `RunTarget`，用于生成 `.pot` 模板文件。
    * 为每个指定的语言创建一个 `CustomTarget`，例如 `my_app-zh_CN.mo` 和 `my_app-en_US.mo`，用于将对应的 `.po` 文件编译成 `.mo` 文件。
    * 创建一个名为 `my_app-update-po` 的 `RunTarget`，用于更新 `.po` 文件。
    * 最终在构建目录下会生成 `my_app.pot` 文件以及 `zh_CN/LC_MESSAGES/my_app.mo` 和 `en_US/LC_MESSAGES/my_app.mo` 等编译后的翻译文件。

**用户或编程常见的使用错误**

使用 `i18n.py` 模块时，用户可能会遇到以下错误：

1. **缺少必要的工具:**  如果系统中没有安装 Gettext 工具链（例如 `msgfmt`, `msginit`, `msgmerge`, `xgettext`）或 `itstool`，Meson 构建过程可能会报错或发出警告。
   * **示例:**  如果未安装 `msgfmt`，调用 `merge_file` 或 `gettext` 可能会抛出异常。

2. **`install_dir` 未设置:** 当 `merge_file` 或 `itstool_join` 的 `install` 参数设置为 `True` 时，必须同时设置 `install_dir` 参数，指定翻译文件安装的目标目录。
   * **示例:**  调用 `i18n.merge_file(..., install=True)` 但没有指定 `install_dir` 会导致 `InvalidArguments` 异常。

3. **`po_dir` 参数缺失:** `merge_file` 方法需要 `po_dir` 参数来指定 `.po` 文件所在的目录。
   * **示例:**  调用 `i18n.merge_file()` 时没有提供 `po_dir` 参数会导致 `TypeError`。

4. **`mo_targets` 参数缺失或错误:**  `itstool_join` 方法需要 `mo_targets` 参数，它应该是一个包含 `CustomTarget` 对象的列表，这些对象表示要合并的 `.mo` 文件。
   * **示例:**  调用 `i18n.itstool_join()` 时没有提供 `mo_targets` 参数或提供了错误的类型会导致 `TypeError` 或逻辑错误。

5. **指定的语言不存在:** 在 `gettext` 方法中，如果指定的语言代码没有对应的 `.po` 文件，编译过程可能会发出警告或错误。
   * **示例:**  如果 `languages=['fr_FR']` 但项目目录下没有 `fr_FR.po` 文件，`msgfmt` 可能会报错。

6. **工具版本不兼容:**  `merge_file` 方法会检查 `msgfmt` 的版本，如果版本低于要求的最低版本，则会抛出异常。
   * **示例:**  如果使用的 `msgfmt` 版本低于 0.19 (对于 `type='desktop'`) 或 0.19.7 (对于 `type='xml'`)，会抛出 `MesonException`。

**用户操作是如何一步步到达这里的 (作为调试线索)**

作为一个调试线索，以下步骤展示了用户操作如何最终触发 `i18n.py` 中的代码：

1. **编写 `meson.build` 文件:**  用户在其项目的根目录下创建一个 `meson.build` 文件，这是 Meson 构建系统的核心配置文件。
2. **使用 `i18n` 模块的函数:**  在 `meson.build` 文件中，用户调用了 `i18n` 模块提供的函数，例如 `i18n.merge_file()` 或 `i18n.gettext()`，来定义项目的国际化构建规则。
   ```python
   i18n = import('i18n')

   # 使用 merge_file 合并翻译文件
   i18n.merge_file(
       input=['zh_CN.po', 'zh_TW.po'],
       output='combined.mo',
       po_dir='locales',
       type='desktop',
       install=True,
       install_dir=join_paths(get_option('localedir'), 'my_app')
   )

   # 使用 gettext 处理
   i18n.gettext('my_app', languages=['zh_CN', 'en_US'])
   ```
3. **运行 `meson` 命令:** 用户在项目根目录下打开终端，并执行 `meson setup builddir` 命令（或类似的命令）来配置构建环境。Meson 会解析 `meson.build` 文件。
4. **Meson 解析和执行 `i18n.py`:** 当 Meson 解析到 `import('i18n')` 时，它会加载 `frida/releng/meson/mesonbuild/modules/i18n.py` 文件。
5. **调用 `i18n` 模块的方法:**  在解析 `meson.build` 文件时，Meson 会执行用户调用的 `i18n.merge_file()` 或 `i18n.gettext()` 等方法。
6. **执行方法内部的逻辑:** 例如，如果调用了 `i18n.merge_file()`，该方法会检查参数，查找 `msgfmt` 工具，并创建一个 `CustomTarget` 对象，该对象会在实际构建阶段执行 `msgfmthelper` 脚本来合并翻译文件。
7. **运行 `ninja` 或其他构建工具:** 用户执行 `ninja -C builddir` 命令（或其他配置的构建工具命令）来开始实际的构建过程。
8. **执行 `CustomTarget`:**  当构建工具执行到由 `i18n.merge_file()` 创建的 `CustomTarget` 时，会调用相应的命令来合并翻译文件。

通过这些步骤，用户的操作最终会触发 `i18n.py` 文件中的代码执行，从而完成国际化相关的构建任务。如果构建过程中出现错误，例如缺少工具或参数配置错误，Meson 会在这些步骤中抛出异常或警告，帮助用户定位问题。

Prompt: 
```
这是目录为frida/releng/meson/mesonbuild/modules/i18n.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2016 The Meson development team

from __future__ import annotations

from os import path
import shlex
import typing as T

from . import ExtensionModule, ModuleReturnValue, ModuleInfo
from .. import build
from .. import mesonlib
from .. import mlog
from ..interpreter.type_checking import CT_BUILD_BY_DEFAULT, CT_INPUT_KW, INSTALL_TAG_KW, OUTPUT_KW, INSTALL_DIR_KW, INSTALL_KW, NoneType, in_set_validator
from ..interpreterbase import FeatureNew, InvalidArguments
from ..interpreterbase.decorators import ContainerTypeInfo, KwargInfo, noPosargs, typed_kwargs, typed_pos_args
from ..programs import ExternalProgram
from ..scripts.gettext import read_linguas

if T.TYPE_CHECKING:
    from typing_extensions import Literal, TypedDict

    from . import ModuleState
    from ..build import Target
    from ..interpreter import Interpreter
    from ..interpreterbase import TYPE_var

    class MergeFile(TypedDict):

        input: T.List[T.Union[
            str, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex,
            build.ExtractedObjects, build.GeneratedList, ExternalProgram,
            mesonlib.File]]
        output: str
        build_by_default: bool
        install: bool
        install_dir: T.Optional[str]
        install_tag: T.Optional[str]
        args: T.List[str]
        data_dirs: T.List[str]
        po_dir: str
        type: Literal['xml', 'desktop']

    class Gettext(TypedDict):

        args: T.List[str]
        data_dirs: T.List[str]
        install: bool
        install_dir: T.Optional[str]
        languages: T.List[str]
        preset: T.Optional[str]

    class ItsJoinFile(TypedDict):

        input: T.List[T.Union[
            str, build.BuildTarget, build.CustomTarget, build.CustomTargetIndex,
            build.ExtractedObjects, build.GeneratedList, ExternalProgram,
            mesonlib.File]]
        output: str
        build_by_default: bool
        install: bool
        install_dir: T.Optional[str]
        install_tag: T.Optional[str]
        its_files: T.List[str]
        mo_targets: T.List[T.Union[build.BuildTarget, build.CustomTarget, build.CustomTargetIndex]]


_ARGS: KwargInfo[T.List[str]] = KwargInfo(
    'args',
    ContainerTypeInfo(list, str),
    default=[],
    listify=True,
)

_DATA_DIRS: KwargInfo[T.List[str]] = KwargInfo(
    'data_dirs',
    ContainerTypeInfo(list, str),
    default=[],
    listify=True
)

PRESET_ARGS = {
    'glib': [
        '--from-code=UTF-8',
        '--add-comments',

        # https://developer.gnome.org/glib/stable/glib-I18N.html
        '--keyword=_',
        '--keyword=N_',
        '--keyword=C_:1c,2',
        '--keyword=NC_:1c,2',
        '--keyword=g_dcgettext:2',
        '--keyword=g_dngettext:2,3',
        '--keyword=g_dpgettext2:2c,3',

        '--flag=N_:1:pass-c-format',
        '--flag=C_:2:pass-c-format',
        '--flag=NC_:2:pass-c-format',
        '--flag=g_dngettext:2:pass-c-format',
        '--flag=g_strdup_printf:1:c-format',
        '--flag=g_string_printf:2:c-format',
        '--flag=g_string_append_printf:2:c-format',
        '--flag=g_error_new:3:c-format',
        '--flag=g_set_error:4:c-format',
        '--flag=g_markup_printf_escaped:1:c-format',
        '--flag=g_log:3:c-format',
        '--flag=g_print:1:c-format',
        '--flag=g_printerr:1:c-format',
        '--flag=g_printf:1:c-format',
        '--flag=g_fprintf:2:c-format',
        '--flag=g_sprintf:2:c-format',
        '--flag=g_snprintf:3:c-format',
    ]
}


class I18nModule(ExtensionModule):

    INFO = ModuleInfo('i18n')

    def __init__(self, interpreter: 'Interpreter'):
        super().__init__(interpreter)
        self.methods.update({
            'merge_file': self.merge_file,
            'gettext': self.gettext,
            'itstool_join': self.itstool_join,
        })
        self.tools: T.Dict[str, T.Optional[T.Union[ExternalProgram, build.Executable]]] = {
            'itstool': None,
            'msgfmt': None,
            'msginit': None,
            'msgmerge': None,
            'xgettext': None,
        }

    @staticmethod
    def _get_data_dirs(state: 'ModuleState', dirs: T.Iterable[str]) -> T.List[str]:
        """Returns source directories of relative paths"""
        src_dir = path.join(state.environment.get_source_dir(), state.subdir)
        return [path.join(src_dir, d) for d in dirs]

    @FeatureNew('i18n.merge_file', '0.37.0')
    @noPosargs
    @typed_kwargs(
        'i18n.merge_file',
        CT_BUILD_BY_DEFAULT,
        CT_INPUT_KW,
        KwargInfo('install_dir', (str, NoneType)),
        INSTALL_TAG_KW,
        OUTPUT_KW,
        INSTALL_KW,
        _ARGS.evolve(since='0.51.0'),
        _DATA_DIRS.evolve(since='0.41.0'),
        KwargInfo('po_dir', str, required=True),
        KwargInfo('type', str, default='xml', validator=in_set_validator({'xml', 'desktop'})),
    )
    def merge_file(self, state: 'ModuleState', args: T.List['TYPE_var'], kwargs: 'MergeFile') -> ModuleReturnValue:
        if kwargs['install'] and not kwargs['install_dir']:
            raise InvalidArguments('i18n.merge_file: "install_dir" keyword argument must be set when "install" is true.')

        if self.tools['msgfmt'] is None or not self.tools['msgfmt'].found():
            self.tools['msgfmt'] = state.find_program('msgfmt', for_machine=mesonlib.MachineChoice.BUILD)
        if isinstance(self.tools['msgfmt'], ExternalProgram):
            try:
                have_version = self.tools['msgfmt'].get_version()
            except mesonlib.MesonException as e:
                raise mesonlib.MesonException('i18n.merge_file requires GNU msgfmt') from e
            want_version = '>=0.19' if kwargs['type'] == 'desktop' else '>=0.19.7'
            if not mesonlib.version_compare(have_version, want_version):
                msg = f'i18n.merge_file requires GNU msgfmt {want_version} to produce files of type: ' + kwargs['type'] + f' (got: {have_version})'
                raise mesonlib.MesonException(msg)
        podir = path.join(state.build_to_src, state.subdir, kwargs['po_dir'])

        ddirs = self._get_data_dirs(state, kwargs['data_dirs'])
        datadirs = '--datadirs=' + ':'.join(ddirs) if ddirs else None

        command: T.List[T.Union[str, build.BuildTarget, build.CustomTarget,
                                build.CustomTargetIndex, 'ExternalProgram', mesonlib.File]] = []
        command.extend(state.environment.get_build_command())
        command.extend([
            '--internal', 'msgfmthelper',
            '--msgfmt=' + self.tools['msgfmt'].get_path(),
        ])
        if datadirs:
            command.append(datadirs)
        command.extend(['@INPUT@', '@OUTPUT@', kwargs['type'], podir])
        if kwargs['args']:
            command.append('--')
            command.extend(kwargs['args'])

        build_by_default = kwargs['build_by_default']
        if build_by_default is None:
            build_by_default = kwargs['install']

        install_tag = [kwargs['install_tag']] if kwargs['install_tag'] is not None else None

        ct = build.CustomTarget(
            '',
            state.subdir,
            state.subproject,
            state.environment,
            command,
            kwargs['input'],
            [kwargs['output']],
            state.is_build_only_subproject,
            build_by_default=build_by_default,
            install=kwargs['install'],
            install_dir=[kwargs['install_dir']] if kwargs['install_dir'] is not None else None,
            install_tag=install_tag,
            description='Merging translations for {}',
        )

        return ModuleReturnValue(ct, [ct])

    @typed_pos_args('i18n.gettext', str)
    @typed_kwargs(
        'i18n.gettext',
        _ARGS,
        _DATA_DIRS.evolve(since='0.36.0'),
        INSTALL_KW.evolve(default=True),
        INSTALL_DIR_KW.evolve(since='0.50.0'),
        KwargInfo('languages', ContainerTypeInfo(list, str), default=[], listify=True),
        KwargInfo(
            'preset',
            (str, NoneType),
            validator=in_set_validator(set(PRESET_ARGS)),
            since='0.37.0',
        ),
    )
    def gettext(self, state: 'ModuleState', args: T.Tuple[str], kwargs: 'Gettext') -> ModuleReturnValue:
        for tool, strict in [('msgfmt', True), ('msginit', False), ('msgmerge', False), ('xgettext', False)]:
            if self.tools[tool] is None:
                self.tools[tool] = state.find_program(tool, required=False, for_machine=mesonlib.MachineChoice.BUILD)
            # still not found?
            if not self.tools[tool].found():
                if strict:
                    mlog.warning('Gettext not found, all translation (po) targets will be ignored.',
                                 once=True, location=state.current_node)
                    return ModuleReturnValue(None, [])
                else:
                    mlog.warning(f'{tool!r} not found, maintainer targets will not work',
                                 once=True, fatal=False, location=state.current_node)
        packagename = args[0]
        pkg_arg = f'--pkgname={packagename}'

        languages = kwargs['languages']
        lang_arg = '--langs=' + '@@'.join(languages) if languages else None

        _datadirs = ':'.join(self._get_data_dirs(state, kwargs['data_dirs']))
        datadirs = f'--datadirs={_datadirs}' if _datadirs else None

        extra_args = kwargs['args']
        targets: T.List['Target'] = []
        gmotargets: T.List['build.CustomTarget'] = []

        preset = kwargs['preset']
        if preset:
            preset_args = PRESET_ARGS[preset]
            extra_args = list(mesonlib.OrderedSet(preset_args + extra_args))

        extra_arg = '--extra-args=' + '@@'.join(extra_args) if extra_args else None

        source_root = path.join(state.source_root, state.root_subdir)
        subdir = path.relpath(state.subdir, start=state.root_subdir) if state.subdir else None

        potargs = state.environment.get_build_command() + ['--internal', 'gettext', 'pot', pkg_arg]
        potargs.append(f'--source-root={source_root}')
        if subdir:
            potargs.append(f'--subdir={subdir}')
        if datadirs:
            potargs.append(datadirs)
        if extra_arg:
            potargs.append(extra_arg)
        if self.tools['xgettext'].found():
            potargs.append('--xgettext=' + self.tools['xgettext'].get_path())
        pottarget = build.RunTarget(packagename + '-pot', potargs, [], state.subdir, state.subproject,
                                    state.environment, default_env=False)
        targets.append(pottarget)

        install = kwargs['install']
        install_dir = kwargs['install_dir'] or state.environment.coredata.get_option(mesonlib.OptionKey('localedir'))
        assert isinstance(install_dir, str), 'for mypy'
        if not languages:
            languages = read_linguas(path.join(state.environment.source_dir, state.subdir))
        for l in languages:
            po_file = mesonlib.File.from_source_file(state.environment.source_dir,
                                                     state.subdir, l+'.po')
            gmotarget = build.CustomTarget(
                f'{packagename}-{l}.mo',
                path.join(state.subdir, l, 'LC_MESSAGES'),
                state.subproject,
                state.environment,
                [self.tools['msgfmt'], '-o', '@OUTPUT@', '@INPUT@'],
                [po_file],
                [f'{packagename}.mo'],
                state.is_build_only_subproject,
                install=install,
                # We have multiple files all installed as packagename+'.mo' in different install subdirs.
                # What we really wanted to do, probably, is have a rename: kwarg, but that's not available
                # to custom_targets. Crude hack: set the build target's subdir manually.
                # Bonus: the build tree has something usable as an uninstalled bindtextdomain() target dir.
                install_dir=[path.join(install_dir, l, 'LC_MESSAGES')],
                install_tag=['i18n'],
                description='Building translation {}',
            )
            targets.append(gmotarget)
            gmotargets.append(gmotarget)

        allgmotarget = build.AliasTarget(packagename + '-gmo', gmotargets, state.subdir, state.subproject,
                                         state.environment)
        targets.append(allgmotarget)

        updatepoargs = state.environment.get_build_command() + ['--internal', 'gettext', 'update_po', pkg_arg]
        updatepoargs.append(f'--source-root={source_root}')
        if subdir:
            updatepoargs.append(f'--subdir={subdir}')
        if lang_arg:
            updatepoargs.append(lang_arg)
        if datadirs:
            updatepoargs.append(datadirs)
        if extra_arg:
            updatepoargs.append(extra_arg)
        for tool in ['msginit', 'msgmerge']:
            if self.tools[tool].found():
                updatepoargs.append(f'--{tool}=' + self.tools[tool].get_path())
        updatepotarget = build.RunTarget(packagename + '-update-po', updatepoargs, [], state.subdir, state.subproject,
                                         state.environment, default_env=False)
        targets.append(updatepotarget)

        return ModuleReturnValue([gmotargets, pottarget, updatepotarget], targets)

    @FeatureNew('i18n.itstool_join', '0.62.0')
    @noPosargs
    @typed_kwargs(
        'i18n.itstool_join',
        CT_BUILD_BY_DEFAULT,
        CT_INPUT_KW,
        KwargInfo('install_dir', (str, NoneType)),
        INSTALL_TAG_KW,
        OUTPUT_KW,
        INSTALL_KW,
        _ARGS.evolve(),
        KwargInfo('its_files', ContainerTypeInfo(list, str)),
        KwargInfo('mo_targets', ContainerTypeInfo(list, build.CustomTarget), required=True),
    )
    def itstool_join(self, state: 'ModuleState', args: T.List['TYPE_var'], kwargs: 'ItsJoinFile') -> ModuleReturnValue:
        if kwargs['install'] and not kwargs['install_dir']:
            raise InvalidArguments('i18n.itstool_join: "install_dir" keyword argument must be set when "install" is true.')

        if self.tools['itstool'] is None:
            self.tools['itstool'] = state.find_program('itstool', for_machine=mesonlib.MachineChoice.BUILD)
        mo_targets = kwargs['mo_targets']
        its_files = kwargs.get('its_files', [])

        mo_fnames = []
        for target in mo_targets:
            mo_fnames.append(path.join(target.get_source_subdir(), target.get_outputs()[0]))

        command: T.List[T.Union[str, build.BuildTarget, build.CustomTarget,
                                build.CustomTargetIndex, 'ExternalProgram', mesonlib.File]] = []
        command.extend(state.environment.get_build_command())

        itstool_cmd = self.tools['itstool'].get_command()
        # TODO: python 3.8 can use shlex.join()
        command.extend([
            '--internal', 'itstool', 'join',
            '-i', '@INPUT@',
            '-o', '@OUTPUT@',
            '--itstool=' + ' '.join(shlex.quote(c) for c in itstool_cmd),
        ])
        if its_files:
            for fname in its_files:
                if not path.isabs(fname):
                    fname = path.join(state.environment.source_dir, state.subdir, fname)
                command.extend(['--its', fname])
        command.extend(mo_fnames)

        build_by_default = kwargs['build_by_default']
        if build_by_default is None:
            build_by_default = kwargs['install']

        install_tag = [kwargs['install_tag']] if kwargs['install_tag'] is not None else None

        ct = build.CustomTarget(
            '',
            state.subdir,
            state.subproject,
            state.environment,
            command,
            kwargs['input'],
            [kwargs['output']],
            state.is_build_only_subproject,
            build_by_default=build_by_default,
            extra_depends=mo_targets,
            install=kwargs['install'],
            install_dir=[kwargs['install_dir']] if kwargs['install_dir'] is not None else None,
            install_tag=install_tag,
            description='Merging translations for {}',
        )

        return ModuleReturnValue(ct, [ct])


def initialize(interp: 'Interpreter') -> I18nModule:
    return I18nModule(interp)

"""

```