Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its functionality, connections to reverse engineering, low-level details, logic, potential errors, and debugging context.

**1. Initial Skim and Keyword Identification:**

First, I'd quickly skim the code looking for recognizable keywords and patterns. Things that immediately jump out:

* `i18n`: This strongly suggests internationalization and localization (translation).
* `gettext`, `msgfmt`, `msginit`, `msgmerge`, `xgettext`, `itstool`: These are all standard tools in the GNU gettext suite and related for managing translations.
* `merge_file`, `itstool_join`, `gettext`: These seem to be the main functions provided by this module.
* `po`, `mo`: These are common file extensions for gettext translation files (Portable Object and Machine Object).
* `xml`, `desktop`: These seem to be types of files being processed.
* `install`, `install_dir`, `install_tag`:  Relate to the installation process of the translated files.
* `build_by_default`: Controls whether the target is built by default.
* `args`, `data_dirs`:  Configuration options passed to the underlying tools.
* `ExternalProgram`, `CustomTarget`, `RunTarget`, `AliasTarget`: These are Meson build system concepts.
* `state`: This is likely a context object provided by Meson, containing information about the current build environment.
* `interpreter`:  Indicates this is a Meson module.

**2. Analyzing Core Functions:**

Next, I'd focus on understanding what each of the main functions does:

* **`merge_file`:**  The name suggests combining multiple translation-related files into a single output. The keywords `msgfmt`, `po_dir`, `type` (xml/desktop) strongly point to compiling `.po` files into binary `.mo` files. The `msgfmthelper` internal command further reinforces this.

* **`gettext`:** This function seems more complex. The use of `xgettext` suggests extracting translatable strings from source code. The creation of `RunTarget` for `pot` and `update_po` indicates the standard gettext workflow of creating a template `.pot` file and updating existing `.po` files. The generation of individual `.mo` files for each language confirms the translation process.

* **`itstool_join`:** This function incorporates `itstool`, a tool for integrating translations into XML documents. It takes `.mo` files as input (`mo_targets`) and combines them with ITS (Internationalization Tag Set) files.

**3. Identifying Connections to Reverse Engineering:**

With the basic understanding of the functions, I'd consider how they relate to reverse engineering.

* **Dynamic Instrumentation (Frida):** Frida often works with applications that have internationalization support. Understanding how translations are handled can be crucial for reverse engineering efforts:
    * **Language Switching:**  Being able to force an application to use a specific language can help isolate specific code paths or UI elements.
    * **String Identification:**  Knowing how translatable strings are stored and loaded can aid in identifying important code sections or user-facing features.
    * **Security Analysis:** Incorrect handling of internationalized strings can sometimes lead to vulnerabilities.

* **Binary Level:**  `.mo` files are binary files. Understanding their structure (message IDs, translated strings) could be relevant if you need to manually inspect or modify translations.

**4. Exploring Low-Level and Kernel/Framework Connections:**

* **Linux:** The gettext tools (`msgfmt`, etc.) are standard Linux utilities. The file paths and directory structures (`LC_MESSAGES`) are also Linux conventions.
* **Android:** Android also uses gettext for internationalization, though its implementation might have Android-specific layers. The concepts of `.po` and `.mo` files would still apply.
* **Kernel/Framework:** While this module itself doesn't directly interact with the kernel, the *results* of its work (the `.mo` files) are used by applications running on the operating system, including frameworks and potentially kernel-level components (though less likely for direct kernel interaction).

**5. Logical Reasoning (Input/Output):**

For each function, I'd imagine a simple scenario to understand the flow:

* **`merge_file`:**  Input: a list of `.po` files, output: a single merged `.mo` file.
* **`gettext`:** Input: a package name, list of languages, source code. Output: `.pot` file, updated `.po` files, individual `.mo` files for each language.
* **`itstool_join`:** Input:  XML files, `.mo` files, ITS files. Output:  Translated XML files.

**6. Identifying User/Programming Errors:**

I'd consider common mistakes developers might make when using these functions:

* **`merge_file`:**  Forgetting `install_dir` when `install` is true. Incorrect `po_dir`. Providing incompatible file types as input.
* **`gettext`:**  Incorrect package name. Missing or incorrect language codes. Forgetting to install the resulting `.mo` files.
* **`itstool_join`:**  Providing incorrect paths to ITS files. Mismatched `.mo` files for the XML being processed.

**7. Tracing User Actions (Debugging Context):**

To understand how a user might end up in this code, I'd think about the typical software development/build process:

1. **Developer writes code with translatable strings.**
2. **Developer uses gettext tools (or a build system like Meson) to extract these strings into `.po` files.** This is where `i18n.gettext` comes in.
3. **Translators provide translations in the `.po` files.**
4. **The build system (Meson, using `i18n.merge_file` or similar) compiles the `.po` files into binary `.mo` files.**
5. **If the project uses XML and ITS, `i18n.itstool_join` might be used to integrate translations into XML files.**
6. **During the build process, if something goes wrong with the translation steps, the developer or build system might need to examine this `i18n.py` module to understand the error.** This could involve setting breakpoints or logging within this code.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This looks like it just compiles translations."
* **Correction:** "No, `gettext` also handles the *extraction* of translatable strings, which is a crucial first step."

* **Initial thought:**  "This is purely about application-level translation."
* **Refinement:** "While primarily for applications, understanding translation mechanisms can be relevant in reverse engineering lower-level components that might have some form of internationalization (e.g., error messages)."

By following these steps, combining code analysis with domain knowledge (gettext, build systems, reverse engineering), and iteratively refining the understanding, I can arrive at a comprehensive explanation of the module's functionality and its relevance in different contexts.
这个文件 `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/i18n.py` 是 Frida 动态 instrumentation 工具链中，用于处理国际化 (i18n) 相关任务的 Meson 构建系统的模块。它提供了一系列函数，用于在构建过程中集成和管理软件的本地化 (l10n) 资源。

**主要功能：**

1. **`merge_file`**: 将多个翻译文件合并成一个。这通常用于将不同部分的翻译文件（例如，来自不同源文件或子模块的翻译）组合成一个最终的机器对象 (`.mo`) 文件。

2. **`gettext`**:  处理 `gettext` 相关的任务，这是 Linux 和其他类 Unix 系统上进行软件国际化的标准工具集。它涵盖了从源代码中提取可翻译字符串，到生成最终的机器对象文件的整个流程。

3. **`itstool_join`**: 使用 `itstool` 工具将翻译应用于 XML 文件。`itstool` 是一种工具，用于将 gettext 的翻译集成到 XML 文档中，常用于 GNOME 桌面环境的应用程序。

**与逆向方法的关联及举例：**

国际化处理与逆向工程存在一定的关联，尤其是在理解软件的用户界面和文本内容时。

* **语言切换分析**: 逆向工程师可能会关注程序如何加载和选择不同的语言包。通过分析 `gettext` 函数的调用和生成的 `.mo` 文件，可以了解程序支持哪些语言，以及在运行时如何切换语言。例如，可以通过 Frida hook `bindtextdomain` 或 `dgettext` 等函数来监控程序加载的语言包和使用的翻译字符串。

* **字符串定位**:  在逆向分析中，定位程序中的关键字符串（例如，错误消息、提示信息）是常见的任务。`gettext` 函数负责从源代码中提取这些字符串。逆向工程师可以通过分析 `.po` 文件（包含原始字符串和对应的翻译）来找到感兴趣的字符串的原始形式，然后在二进制文件中搜索这些原始字符串的引用，从而定位相关的代码逻辑。

* **动态翻译修改**:  利用 Frida，可以 hook `dgettext` 等函数，并在运行时修改程序返回的翻译字符串。这可以用于调试目的，例如，将某些难以触发的错误消息的翻译修改为更容易识别的内容，或者在不修改二进制文件的情况下汉化软件。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例：**

虽然这个 Python 模块本身运行在构建系统层面，但它处理的任务与运行时环境息息相关。

* **二进制底层 (`.mo` 文件)**: `merge_file` 和 `gettext` 的最终目标是生成 `.mo` 文件，这是一种二进制格式，包含了消息 ID 和对应的翻译。了解 `.mo` 文件的结构对于某些逆向任务可能有用，例如，手动解析 `.mo` 文件以提取所有翻译字符串，或者修改 `.mo` 文件以实现自定义翻译。

* **Linux**: `gettext` 工具集是 Linux 环境下的标准。这个模块大量使用了 `msgfmt`、`msginit`、`msgmerge`、`xgettext` 等命令，这些都是 Linux 系统中用于处理国际化的工具。理解这些工具的工作原理有助于理解此模块的功能。

* **Android**: Android 系统也支持 `gettext` 风格的本地化，尽管其实现可能基于 Android 的资源管理系统。理解 `gettext` 的原理有助于理解 Android 应用的本地化机制。例如，Android 使用 `.xml` 资源文件存储字符串，但仍然有工具可以将 `gettext` 的 `.po` 文件转换为 Android 的资源格式。

* **内核及框架 (间接相关)**: 虽然这个模块不直接与内核交互，但它生成的本地化资源被应用程序使用。这些应用程序可能运行在 Linux 或 Android 的用户空间，并可能调用操作系统或框架提供的本地化 API。例如，glib 库提供了 `gettext` 的封装，应用程序可以通过 glib 的 API 来加载和使用翻译。

**逻辑推理（假设输入与输出）：**

**`merge_file` 示例：**

* **假设输入:**
    * `input`: `['zh_CN/module_a.po', 'zh_CN/module_b.po']` (两个简体中文的 `.po` 文件)
    * `output`: `zh_CN/LC_MESSAGES/my_app.mo`
    * `po_dir`: `zh_CN`
    * `type`: `desktop`

* **预期输出:**
    * 生成一个名为 `zh_CN/LC_MESSAGES/my_app.mo` 的二进制文件，其中包含了 `module_a.po` 和 `module_b.po` 中的所有翻译。

**`gettext` 示例：**

* **假设输入:**
    * `args`: `['my_app']` (包名)
    * `languages`: `['zh_CN', 'fr_FR']` (需要生成的语言列表)
    * 源代码中包含使用了 `gettext` 函数 (`_()`, `N_()`, 等) 标记的可翻译字符串。

* **预期输出:**
    * 生成一个 `.pot` 文件（例如，`my_app.pot`），其中包含了从源代码中提取的所有原始可翻译字符串。
    * 如果 `zh_CN.po` 和 `fr_FR.po` 文件不存在，则会创建这两个文件，并使用 `.pot` 文件的内容进行初始化。
    * 分别为 `zh_CN` 和 `fr_FR` 生成 `zh_CN/LC_MESSAGES/my_app.mo` 和 `fr_FR/LC_MESSAGES/my_app.mo` 文件。

**`itstool_join` 示例：**

* **假设输入:**
    * `input`: `['help.xml']` (需要翻译的 XML 文件)
    * `output`: `help.zh_CN.xml`
    * `mo_targets`: 指向 `gettext` 生成的 `zh_CN/LC_MESSAGES/my_app.mo` 目标的列表。
    * `its_files`: `['translation.its']` (ITS 规则文件)

* **预期输出:**
    * 生成 `help.zh_CN.xml` 文件，其中 `help.xml` 中符合 ITS 规则的文本内容已经被替换为 `zh_CN/LC_MESSAGES/my_app.mo` 中对应的翻译。

**涉及用户或者编程常见的使用错误及举例：**

* **`merge_file`**:
    * **错误:**  未设置 `install_dir` 但设置了 `install=True`。
    * **后果:** Meson 构建系统会报错，提示缺少必要的安装目录信息。
    * **代码示例触发点:** `if kwargs['install'] and not kwargs['install_dir']:`

* **`gettext`**:
    * **错误:**  指定的语言代码 (`languages`) 不存在对应的 `.po` 文件，且 `msginit` 工具未找到。
    * **后果:**  可能无法正确初始化新的翻译文件，或者构建过程会发出警告。
    * **代码示例触发点:** `if self.tools['msginit'] is None or not self.tools['msginit'].found():`

* **`itstool_join`**:
    * **错误:**  `mo_targets` 列表为空或指向不存在的 `.mo` 文件。
    * **后果:** `itstool` 可能无法找到翻译，或者构建过程会出错。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **开发者配置 Meson 构建系统:**  在 `meson.build` 文件中，开发者会使用 `i18n` 模块提供的函数来定义国际化相关的构建目标。例如：
   ```python
   i18n = import('i18n')
   my_po = i18n.gettext('my_app', languages: ['zh_CN', 'fr_FR'])
   install_translation(my_po)
   ```

2. **运行 Meson 配置:** 开发者在项目根目录下运行 `meson setup builddir` 命令来配置构建环境。Meson 会解析 `meson.build` 文件，并执行其中的 Python 代码，包括加载 `i18n.py` 模块。

3. **运行 Meson 构建:** 开发者运行 `meson compile -C builddir` 命令来开始构建过程。在构建过程中，Meson 会根据 `i18n.gettext` 等函数的定义，调用相应的 gettext 工具来生成 `.po` 和 `.mo` 文件。

4. **构建失败或出现国际化相关问题:** 如果在构建过程中，与国际化相关的步骤失败（例如，找不到 `msgfmt` 工具，`.po` 文件格式错误等），或者应用程序运行时无法正确加载翻译，开发者可能需要调试构建过程。

5. **查看 Meson 日志和构建脚本:** 开发者会查看 Meson 的构建日志，了解具体的错误信息。日志中可能会显示调用 `i18n.py` 中函数的堆栈信息。

6. **检查 `i18n.py` 源代码:**  为了理解错误原因，开发者可能会查看 `frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/i18n.py` 的源代码，分析各个函数的功能和逻辑，例如：
   * 检查 `gettext` 函数是否正确找到了 `msgfmt` 等工具。
   * 检查 `merge_file` 函数的参数是否正确传递。
   * 确认 `itstool_join` 函数是否正确处理了 ITS 规则和 `.mo` 文件。

7. **使用断点或日志输出进行调试:**  如果只是查看代码还不足以定位问题，开发者可能会在 `i18n.py` 文件中添加临时的 `print()` 语句或使用 Meson 提供的调试工具来跟踪变量的值和执行流程。

通过以上步骤，开发者可以逐步定位到 `i18n.py` 文件，并利用其源代码作为调试线索，理解构建系统中国际化处理的细节，最终解决构建或运行时出现的国际化相关问题。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/modules/i18n.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```