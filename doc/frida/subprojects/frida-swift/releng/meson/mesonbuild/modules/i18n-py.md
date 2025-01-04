Response:
Let's break down the thought process for analyzing this Python code for the Frida project.

**1. Understanding the Goal:**

The primary request is to understand the functionality of the `i18n.py` file within the Frida project's build system (Meson). Specifically, the request asks about its relation to reverse engineering, binary internals, OS-level concepts, logical reasoning, user errors, and how a user might reach this code.

**2. Initial Code Scan and High-Level Interpretation:**

* **Keywords:**  The filename `i18n.py` immediately suggests internationalization (localization). The presence of functions like `merge_file`, `gettext`, and `itstool_join` reinforces this. Keywords like `translations`, `languages`, `po_dir`, and the use of `msgfmt`, `msginit`, etc., are strong indicators.
* **Meson Context:**  The code imports from `..build`, `..mesonlib`, and `..interpreter.*`, clearly indicating this is a Meson module. Meson is a build system, so this code is involved in the build process of the Frida project, specifically for handling localization.
* **Function Breakdown (Initial Guess):**
    * `merge_file`: Likely merges translation files (like `.po` files) into a single output file.
    * `gettext`: Probably handles the overall gettext workflow, including extracting translatable strings and generating message catalogs (`.mo` files).
    * `itstool_join`: Seems to integrate `itstool`, a tool for translating XML documents.

**3. Detailed Code Analysis and Feature Extraction:**

Now, let's go through each function and key parts of the code to identify specific functionalities and their connections to the requested areas.

* **Imports and Setup:**
    * Imports like `os.path`, `shlex`, and `typing` are standard Python fare.
    * The `ExtensionModule` inheritance confirms its role in Meson.
    * The `self.methods.update(...)` registers the module's functions, which are the core functionalities.
    * The `self.tools` dictionary shows the external programs this module depends on (GNU gettext tools and `itstool`). This is a direct link to system-level tools and potentially OS dependencies.

* **`_get_data_dirs`:** This utility function is crucial for understanding how the module handles file paths. It resolves relative paths within the source tree.

* **`merge_file`:**
    * **Functionality:**  Merges multiple input files (could be source files or generated files) to create a single output file, primarily for localization data. It uses `msgfmt` to compile `.po` files into binary `.mo` files.
    * **Reverse Engineering:**  While not directly a reverse engineering *tool*, the output of this process (`.mo` files) is what reverse engineers might encounter when analyzing localized software. Understanding this process helps in understanding the structure of localized applications.
    * **Binary/OS:**  `msgfmt` is a binary executable, and the generated `.mo` files are binary message catalogs. The code checks for the version of `msgfmt`, indicating awareness of specific tool capabilities.
    * **Logic:**  The construction of the `command` list demonstrates a clear logic for invoking `msgfmt` with the correct arguments. The conditional inclusion of `datadirs` is a simple logical decision.
    * **User Errors:**  Forgetting to set `install_dir` when `install` is true is a common user error the code explicitly checks for.
    * **User Path:** A user working on localizing their Frida component would use this function in their `meson.build` file.

* **`gettext`:**
    * **Functionality:** This is the central function for the gettext workflow. It generates `.pot` (template) files, updates `.po` files, and compiles them into `.mo` files.
    * **Reverse Engineering:**  Understanding the structure and content of `.pot` and `.po` files is useful in reverse engineering localized software. Knowing how these files are generated can inform analysis.
    * **Binary/OS:**  Relies on `xgettext`, `msginit`, `msgmerge`, and `msgfmt` – all binary executables. The `localedir` option connects to standard OS conventions for storing locale data.
    * **Logic:** The code logically constructs commands for each gettext tool. The handling of `preset` arguments demonstrates conditional logic.
    * **User Errors:** If gettext tools are not installed, the process will fail (though the code provides warnings). Incorrect language codes or file paths could also lead to errors.
    * **User Path:** Developers integrating localization into their Frida modules would call this function, specifying the package name and potentially languages.

* **`itstool_join`:**
    * **Functionality:**  Merges translations for XML files using `itstool`. This is specific to XML-based localization.
    * **Reverse Engineering:**  If a reverse engineer encounters localized XML data, understanding how `itstool` integrates translations is relevant.
    * **Binary/OS:**  Depends on the `itstool` binary.
    * **Logic:**  Constructs the command to run `itstool` with appropriate input and output files.
    * **User Errors:**  Incorrect paths to ITS files or missing `mo_targets` are potential errors.
    * **User Path:** Projects using XML for localization would use this function to combine translations.

* **`PRESET_ARGS`:** This dictionary hardcodes common gettext arguments for libraries like GLib. This simplifies configuration and shows an awareness of common localization practices.

* **`initialize`:** The standard way Meson modules are initialized.

**4. Connecting to the Request's Specific Questions:**

* **Reverse Engineering:**  The output files (`.mo`), the structure of `.po` files, and the knowledge of how these are generated are all relevant to reverse engineering localized applications.
* **Binary/OS:**  The reliance on external tools like `msgfmt`, `xgettext`, and `itstool`, and the handling of installation directories (`localedir`) directly involve binary executables and OS conventions.
* **Linux, Android Kernel/Framework:** While this code itself doesn't directly interact with the kernel, the *purpose* of localization is highly relevant to user-facing applications on Linux and Android. The `localedir` is a standard Linux concept. Frida, being a dynamic instrumentation tool, is often used on these platforms.
* **Logical Reasoning:** The conditional execution of commands, the handling of optional arguments, and the construction of file paths demonstrate logical reasoning.
* **User Errors:** The code anticipates and handles some common user errors (e.g., missing `install_dir`).
* **User Path (Debugging Clues):** The examples provided in the initial decomposition illustrate how a user would interact with these functions in their `meson.build` file. If a build fails in this module, examining the arguments passed to these functions in the `meson.build` would be the first step in debugging.

**5. Refinement and Output Generation:**

Finally, organize the extracted information into a clear and structured answer, addressing each point in the original request with relevant code snippets and explanations. Use clear language and provide concrete examples where applicable. This leads to the comprehensive answer provided previously.
这个文件 `i18n.py` 是 Frida 动态 instrumentation 工具中 Meson 构建系统的一个模块，专门用于处理国际化 (i18n) 和本地化 (l10n) 相关的功能。它提供了一组函数，帮助开发者在构建 Frida 组件时集成和管理翻译。

以下是它的主要功能：

**1. `merge_file` 函数:**

* **功能:** 将多个输入文件（通常是翻译文件，例如 `.po` 文件）合并成一个单一的输出文件（通常是二进制的 `.mo` 文件）。这个 `.mo` 文件包含了应用程序在运行时使用的已编译的翻译数据。
* **逆向关系举例:**
    * **场景:** 逆向工程师在分析一个已经本地化的 Frida 组件时，可能会遇到 `.mo` 文件。理解 `merge_file` 的功能可以帮助他们理解这些 `.mo` 文件是如何生成的，以及其中包含了哪些语言的翻译。通过分析 `.mo` 文件的结构，他们可以提取出应用程序支持的语言和对应的翻译文本。
    * **假设输入:** 一组 `.po` 文件，例如 `frida-core-zh_CN.po`, `frida-core-ja.po`。
    * **预期输出:** 一个或多个 `.mo` 文件，例如 `zh_CN/LC_MESSAGES/frida-core.mo`, `ja/LC_MESSAGES/frida-core.mo`。
* **二进制底层知识:** `merge_file` 内部调用了 `msgfmt` 命令，这是一个 GNU gettext 工具，负责将文本格式的 `.po` 文件编译成二进制的 `.mo` 文件。理解 `.mo` 文件的二进制格式对于逆向分析这些文件至关重要。
* **Linux/Android 内核及框架知识:**  `.mo` 文件通常被放置在符合 FHS (Filesystem Hierarchy Standard) 的路径下，例如 `/usr/share/locale/<lang>/LC_MESSAGES/`。在 Android 上，路径可能有所不同，但概念类似。`merge_file` 函数的 `install_dir` 参数允许指定安装路径，这涉及到对这些操作系统文件系统结构的理解。
* **用户/编程常见使用错误:**
    * **错误:** 用户忘记设置 `install_dir` 参数，但设置了 `install=True`。
    * **后果:** Meson 会报错，因为需要知道将编译后的 `.mo` 文件安装到哪个目录下。
    * **调试线索:** 用户在 `meson.build` 文件中调用 `i18n.merge_file` 时，忘记添加 `install_dir` 参数。Meson 在解析 `meson.build` 文件时会检查参数的有效性并抛出异常。

**2. `gettext` 函数:**

* **功能:**  处理更全面的 gettext 工作流。它可以生成 `.pot` (Portable Object Template) 文件，用于提取源代码中的可翻译字符串，并可以更新或创建特定语言的 `.po` 文件。它还会调用 `msgfmt` 来编译 `.po` 文件。
* **逆向关系举例:**
    * **场景:** 逆向工程师想要为一个尚未完全本地化的 Frida 组件添加新的语言支持。他们可以使用 `gettext` 生成的 `.pot` 文件作为模板，创建新的 `.po` 文件，并翻译其中的字符串。理解 `gettext` 的流程可以帮助他们更有效地进行本地化工作。
    * **假设输入:**  Frida 组件的源代码目录，以及想要支持的目标语言列表（例如 `['es', 'de']`）。
    * **预期输出:**  一个 `.pot` 文件（包含所有可翻译字符串），以及对应语言的 `.po` 文件（如果尚不存在）。
* **二进制底层知识:** `gettext` 内部会调用多个 GNU gettext 工具，例如 `xgettext` (用于从源代码中提取字符串), `msginit` (用于创建新的 `.po` 文件), `msgmerge` (用于将新的翻译合并到已有的 `.po` 文件)。理解这些工具的功能和工作原理涉及到对编译和链接过程的了解。
* **Linux/Android 内核及框架知识:** `gettext` 函数生成的 `.mo` 文件最终会被应用程序加载。在 Linux 和 Android 系统中，通常使用 `gettext()` 或相关的 API 来实现运行时翻译查找。理解这些 API 的工作方式有助于理解 `gettext` 在整个本地化流程中的作用。
* **逻辑推理:**
    * **假设输入:**  `preset='glib'`。
    * **预期输出:** `gettext` 函数会使用预定义的 GLib 相关的 `xgettext` 参数，例如 `--keyword=_`, `--keyword=N_` 等，来更精确地提取 GLib 风格的代码中的可翻译字符串。
* **用户/编程常见使用错误:**
    * **错误:**  项目中没有安装必要的 gettext 工具（例如 `xgettext`, `msgfmt`）。
    * **后果:**  `gettext` 函数会发出警告，并且相关的翻译目标可能会被忽略。
    * **调试线索:**  用户在构建 Frida 时，终端会显示 "Gettext not found, all translation (po) targets will be ignored." 这样的警告信息。

**3. `itstool_join` 函数:**

* **功能:**  用于处理基于 XML 的翻译。它使用 `itstool` 工具将翻译应用到 XML 文件中。
* **逆向关系举例:**
    * **场景:** 某些 Frida 组件可能使用 XML 文件来存储用户界面或其他数据，并且这些 XML 文件需要被翻译。逆向工程师可能需要分析这些已翻译的 XML 文件，或者理解如何将新的翻译添加到这些文件中。了解 `itstool_join` 的功能有助于理解这个过程。
    * **假设输入:** 一个或多个包含待翻译文本的 XML 文件，以及对应的 `.mo` 翻译文件。
    * **预期输出:**  已合并翻译的 XML 文件。
* **二进制底层知识:**  `itstool` 本身是一个独立的工具，它解析 XML 文件并根据提供的 `.mo` 文件进行翻译替换。理解 XML 的结构以及 `itstool` 的工作方式涉及到对文本处理和本地化技术的理解。
* **Linux/Android 内核及框架知识:**  虽然 `itstool` 不直接与内核交互，但它处理的 XML 文件可能被用于配置应用程序的用户界面或行为，这与操作系统提供的框架和服务有关。
* **用户/编程常见使用错误:**
    * **错误:**  传递给 `itstool_join` 的 `mo_targets` 参数不正确，或者指向了错误的 `.mo` 文件。
    * **后果:**  `itstool` 可能无法找到正确的翻译，或者合并过程会失败。
    * **调试线索:**  构建过程可能会报错，提示找不到对应的翻译文件，或者输出的 XML 文件没有被正确翻译。

**用户操作如何一步步到达这里 (调试线索):**

1. **开发者决定为 Frida 的某个组件添加或更新翻译。**
2. **他们修改源代码，添加需要翻译的字符串，并使用 gettext 相关的宏或函数进行标记。**
3. **他们在该组件的 `meson.build` 文件中调用 `i18n.gettext` 函数，指定包名和其他选项，以便 Meson 构建系统能够生成 `.pot` 文件并管理 `.po` 文件的更新。**
4. **翻译人员使用工具（例如 Poedit 或命令行工具）编辑生成的 `.po` 文件，提供目标语言的翻译。**
5. **开发者在 `meson.build` 文件中调用 `i18n.merge_file` 函数，指定要合并的 `.po` 文件和输出的 `.mo` 文件名。**
6. **如果涉及到 XML 文件的翻译，开发者可能会在 `meson.build` 文件中使用 `i18n.itstool_join` 函数，将 `.mo` 文件应用到 XML 文件中。**
7. **当开发者运行 `meson` 命令配置构建，然后运行 `ninja` 命令进行实际构建时，Meson 会解析 `meson.build` 文件，执行 `i18n.py` 模块中的相应函数，调用底层的 gettext 工具，最终生成编译好的翻译文件。**

**总结:**

`frida/subprojects/frida-swift/releng/meson/mesonbuild/modules/i18n.py` 是 Frida 项目构建系统中负责处理国际化和本地化的关键模块。它封装了 gettext 和 itstool 等工具的使用，为开发者提供了一个方便的接口来管理翻译流程。理解这个模块的功能对于逆向分析已本地化的 Frida 组件、为其添加新的语言支持，以及调试构建过程中的翻译相关问题都非常有帮助。 它涉及到对二进制文件格式、操作系统文件系统结构以及底层编译工具链的理解。

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/modules/i18n.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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