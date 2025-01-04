Response:
Let's break down the thought process for analyzing this Python code and generating the response.

**1. Understanding the Goal:**

The core request is to understand the functionality of the `i18n.py` module within the Frida tooling and relate it to various software development and system aspects. The prompt specifically asks for:

* Functionality listing.
* Relevance to reverse engineering.
* Connections to low-level, Linux/Android kernel/framework knowledge.
* Logic reasoning examples (input/output).
* Common user errors.
* Debugging clues related to how a user might reach this code.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code and identify key terms, function names, and data structures. This gives a high-level understanding of what the module does. Keywords that stand out include:

* `i18n`: Obvious indication of internationalization (translation).
* `gettext`, `merge_file`, `itstool_join`: These look like the main functions provided by the module.
* `po`, `mo`: Standard file extensions for gettext translation files.
* `msgfmt`, `msginit`, `msgmerge`, `xgettext`, `itstool`: These are external programs often used in the gettext workflow.
* `languages`:  Clearly related to different language translations.
* `install`, `install_dir`:  Indicates handling of installation processes.
* `CustomTarget`, `RunTarget`, `AliasTarget`: Meson build system concepts.
* `ExternalProgram`:  Interaction with external tools.
* `PRESET_ARGS`:  Configuration for specific libraries (like GLib).

**3. Deeper Dive into Functionality (Method by Method):**

Next, each function is examined in detail:

* **`merge_file`:**  The name suggests combining translation files. The keyword arguments (`input`, `output`, `po_dir`, `type`) and the use of `msgfmt` confirm it's about generating compiled translation files (`.mo` files) from source files (likely `.po` files). The `type` argument (`xml`, `desktop`) hints at different formatting needs.

* **`gettext`:**  This function appears to be more comprehensive. The arguments (`packagename`, `languages`) and the use of `xgettext`, `msginit`, `msgmerge`, and `msgfmt` indicate a full gettext workflow: extracting translatable strings, initializing new translations, merging existing translations, and compiling them. The `preset` argument suggests pre-configured settings for specific libraries.

* **`itstool_join`:**  The name and the presence of `itstool` suggest handling XML translation, potentially for documentation. The `mo_targets` argument indicates it takes already compiled translation files as input.

**4. Connecting to Reverse Engineering:**

This requires thinking about *how* translation relates to reverse engineering. The key is the concept of string analysis. Reverse engineers often look at strings within a binary to understand its functionality.

* **Identifying strings:**  Translation files contain the original strings and their translated counterparts. These can be valuable for understanding the UI or internal messages of a program being reverse-engineered.
* **Language targeting:**  Knowing which languages an application supports can provide clues about its intended audience and potentially reveal different versions or regional variations.

**5. Linking to Low-Level/Kernel Concepts:**

This involves considering where internationalization touches the system level.

* **Locale settings:**  The operating system's locale settings determine the language used by applications. The `i18n` module likely helps configure applications to respect these settings.
* **Character encoding (UTF-8):**  The code mentions UTF-8, a fundamental concept for handling text in different languages. Incorrect encoding can lead to garbled text.
* **System calls (indirectly):** While this module doesn't make direct system calls, the compiled translation files are used by libraries that *do* make system calls to retrieve the correct translated strings based on the current locale.

**6. Constructing Logic Reasoning Examples:**

This involves choosing a function and creating a hypothetical scenario. For `gettext`, a simple case is to imagine a project name and a target language, and then predict the names of the generated `.po` and `.mo` files.

**7. Identifying Common User Errors:**

This comes from understanding the typical workflow and potential pitfalls of using gettext and build systems.

* **Missing tools:**  Forgetting to install `gettext` or `itstool`.
* **Incorrect arguments:**  Providing the wrong file paths or options.
* **Misconfiguration:**  Problems with `install_dir` or language lists.

**8. Tracing User Actions (Debugging Clues):**

This involves imagining the steps a developer would take to use these functions within a Meson build file. Starting with `meson.build`, calling `i18n.gettext` or `i18n.merge_file`, and then potentially encountering errors during the build process are key points.

**9. Structuring the Response:**

Finally, the information needs to be organized clearly, following the structure requested in the prompt. Using headings, bullet points, and code snippets makes the explanation easier to understand.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps focus too much on the technical details of Meson.
* **Correction:**  Shift focus to the *purpose* of the module and its relation to the broader themes of the prompt (reverse engineering, low-level details, etc.).
* **Initial thought:**  Provide overly technical examples.
* **Correction:**  Simplify examples to be more illustrative and less bogged down in complex Meson syntax.
* **Initial thought:**  Assume deep knowledge of gettext.
* **Correction:**  Briefly explain the core concepts of gettext for broader understanding.

By following these steps, the detailed and comprehensive response addressing all aspects of the prompt can be constructed. The key is to move from a surface-level understanding to a deeper analysis of the code's purpose and its interactions within the larger software ecosystem.
这是 `frida-tools` 项目中负责国际化（i18n）的 Meson 构建系统模块的源代码文件。其主要功能是帮助开发者在 Frida 工具中集成和管理多语言支持。

以下是其功能的详细列表，并结合了您提出的各项关联性：

**功能列表：**

1. **`merge_file` 函数:**
   - **功能:**  合并多个翻译文件（通常是 `.po` 文件）到一个输出文件（通常是 `.xml` 或 `.desktop` 格式的翻译文件）。
   - **逆向关联:**  在逆向工程中，如果目标软件使用了这种合并的翻译文件格式，逆向工程师可能需要理解这种合并过程，以便找到所有相关的翻译字符串。例如，对于使用 `desktop` 类型的应用程序，理解如何将独立的 `.po` 文件合并成最终的 `.desktop` 文件中的 `Name[locale]` 或 `Description[locale]` 字段至关重要。
   - **二进制底层:**  此函数最终会调用 `msgfmt` 工具，这是一个二进制工具，用于将 `.po` 文件编译成二进制的 `.mo` 文件。虽然 `merge_file` 本身不直接操作二进制，但它为生成最终的、可能被二进制程序加载的翻译数据做准备。
   - **Linux/Android:**  `.desktop` 文件格式是 Linux 桌面环境的标准，用于描述应用程序的元数据，包括本地化的名称和描述。在 Android 中，虽然不直接使用 `.desktop` 文件，但资源文件中的字符串本地化也遵循类似的原则。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:**  `po_dir='po'`, `type='desktop'`, `input=['po/zh_CN.po', 'po/en_US.po']`, `output='merged.desktop'`
     - **预期输出:**  将 `po/zh_CN.po` 和 `po/en_US.po` 中的翻译信息合并到 `merged.desktop` 文件中，例如包含 `Name[zh_CN]=...` 和 `Name[en_US]=...` 这样的字段。
   - **用户错误:**
     - **错误示例:**  忘记设置 `install_dir` 并且设置了 `install=true`，会导致安装时不知道安装到哪个目录。
     - **调试线索:** 用户在配置构建系统时，在 `meson.build` 文件中调用 `i18n.merge_file` 函数，但提供的参数不完整或不正确。

2. **`gettext` 函数:**
   - **功能:**  处理基于 `gettext` 的国际化工作流程。它会生成 `.pot` 文件（可移植对象模板），并为每种语言生成对应的 `.po` 文件和编译后的 `.mo` 文件。
   - **逆向关联:**  `gettext` 是一个广泛使用的国际化框架。逆向工程师经常会遇到使用 `gettext` 的程序。理解 `gettext` 的工作原理，包括 `.po` 和 `.mo` 文件的结构，是分析这些程序本地化机制的关键。可以通过查看 `.mo` 文件来找到程序的本地化字符串。
   - **二进制底层:**  `msgfmt` 工具将 `.po` 文件编译成二进制的 `.mo` 文件，这些 `.mo` 文件会被应用程序在运行时加载，以根据用户的语言环境显示相应的文本。这涉及到文件 I/O 和可能涉及内存映射等底层操作。
   - **Linux/Android:**  `gettext` 在 Linux 和 Android 环境中都很常见。Android NDK 也支持 `gettext`。应用程序可以使用 `gettext` API 来加载和使用 `.mo` 文件中的翻译。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `packagename='my-app'`, `languages=['zh_CN', 'en_US']`
     - **预期输出:**  会生成 `my-app.pot` 模板文件，以及 `zh_CN/LC_MESSAGES/my-app.mo` 和 `en_US/LC_MESSAGES/my-app.mo` 两个编译后的翻译文件。
   - **用户错误:**
     - **错误示例:**  拼写错误的 `preset` 参数（例如，将 `glib` 拼写成 `glb`），会导致无法使用预定义的关键字。
     - **调试线索:** 用户在 `meson.build` 文件中调用 `i18n.gettext` 时，提供的 `languages` 列表不正确，或者没有安装必要的 `gettext` 工具链（如 `msgfmt`, `xgettext` 等）。

3. **`itstool_join` 函数:**
   - **功能:**  使用 `itstool` 工具将翻译文件（`.po`）合并到 XML 文件中，通常用于文档的本地化。
   - **逆向关联:**  虽然主要用于文档，但在某些情况下，软件的配置或数据文件可能使用 XML 格式，并且这些 XML 文件需要本地化。理解 `itstool` 的合并过程有助于逆向工程师找到这些本地化的文本。
   - **二进制底层:**  `itstool` 本身是一个工具，它会读取和写入 XML 文件，这涉及到文件 I/O 和 XML 解析等操作。
   - **Linux/Android:**  XML 文件在 Linux 和 Android 中都有广泛应用，例如 Android 的资源文件就是 XML 格式。`itstool` 可以用于本地化这些 XML 文件中的文本。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** `input=['doc.xml']`, `output='doc.xml.merged'`, `mo_targets=['zh_CN.mo']`, `its_files=['rules.its']`
     - **预期输出:**  `doc.xml.merged` 文件将包含来自 `doc.xml` 的内容，并根据 `zh_CN.mo` 中的翻译和 `rules.its` 文件中定义的规则进行本地化。
   - **用户错误:**
     - **错误示例:**  `mo_targets` 列表为空或包含不存在的目标，导致 `itstool` 无法找到翻译数据。
     - **调试线索:** 用户在 `meson.build` 中调用 `i18n.itstool_join` 时，提供的输入文件路径或 `mo_targets` 不正确，或者系统上没有安装 `itstool`。

**与逆向方法的举例说明:**

* **分析本地化字符串:** 逆向工程师可以使用工具查看编译后的 `.mo` 文件（由 `gettext` 生成）或合并后的 XML 文件（由 `merge_file` 或 `itstool_join` 生成），以了解应用程序支持的语言以及其中的本地化字符串。这些字符串可以提供关于程序功能和用户界面的重要信息。
* **查找语言切换逻辑:**  理解 `gettext` 的工作方式可以帮助逆向工程师找到应用程序中处理语言切换的逻辑。例如，可以查找加载特定 `.mo` 文件的 API 调用。
* **理解资源文件结构:** 对于使用 XML 资源文件的应用程序，理解 `itstool` 的合并规则可以帮助逆向工程师解析本地化的资源文件。

**涉及到二进制底层，Linux, Android内核及框架的知识的举例说明:**

* **`msgfmt` 的二进制编译:**  `merge_file` 和 `gettext` 都依赖于 `msgfmt` 工具，这是一个将文本格式的 `.po` 文件编译成二进制格式 `.mo` 文件的程序。这个编译过程涉及到字符编码处理、数据结构转换等底层操作。
* **`gettext` API 在 Linux/Android 中的使用:**  应用程序在 Linux 或 Android 运行时，会使用 `gettext` 提供的 API（例如 `gettext()`, `dgettext()`) 来查找并加载与当前用户语言环境匹配的 `.mo` 文件中的翻译字符串。这涉及到操作系统底层的 locale 设置和文件系统操作。
* **Android 的资源管理:**  虽然 `i18n.py` 主要关注 `gettext` 流程，但它生成的本地化文件最终会以某种形式被应用程序使用。在 Android 中，本地化字符串通常存储在 `res/values-<locale>` 目录下的 XML 文件中。理解 Android 的资源加载机制是理解这些本地化字符串如何被使用的关键。

**逻辑推理的假设输入与输出 (已在功能列表中给出)。**

**涉及用户或编程常见的使用错误举例说明 (已在功能列表中给出)。**

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者想要为其 Frida 工具添加多语言支持。**
2. **开发者决定使用 `gettext` 或类似的国际化方案。**
3. **开发者需要在 Frida 的构建系统 (Meson) 中集成这些工具。**
4. **开发者会查看 Meson 的文档，寻找处理国际化的模块。**
5. **开发者会找到 `i18n` 模块，并开始在 `meson.build` 文件中使用 `i18n.gettext`, `i18n.merge_file`, 或 `i18n.itstool_join` 函数。**
6. **如果在构建过程中出现错误，或者生成的本地化文件不符合预期，开发者可能会查看 `frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/i18n.py` 的源代码，以理解这些函数是如何工作的。**
7. **例如，如果开发者发现合并后的 `.desktop` 文件中的某些字段没有正确本地化，他们可能会检查 `merge_file` 函数的实现，查看它是如何调用 `msgfmt` 以及传递哪些参数。**
8. **又或者，如果开发者在使用 `gettext` 时遇到问题，例如 `.mo` 文件没有被正确生成，他们可能会查看 `gettext` 函数，了解它如何调用 `xgettext`, `msginit`, 和 `msgfmt`。**

总而言之，`frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/i18n.py` 文件是 Frida 工具国际化流程的核心，它利用 Meson 构建系统的扩展机制，封装了常用的国际化工具，并提供了方便的接口供开发者使用。理解其功能和实现细节，对于进行 Frida 工具的开发、调试，甚至对使用了类似国际化方案的目标软件进行逆向工程都有一定的帮助。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/modules/i18n.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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