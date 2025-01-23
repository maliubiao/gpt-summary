Response:
The user wants to understand the functionality of the provided Python code, which is a Meson module for internationalization (i18n). I need to break down its functions and explain them in the context of reverse engineering, low-level systems, and common usage errors.

Here's a plan:

1. **Identify Core Functions:**  Look for the key methods within the `I18nModule` class.
2. **Explain Each Function:** Describe what each function does in the context of i18n.
3. **Reverse Engineering Relevance:**  Analyze how these i18n tools and processes can be relevant to reverse engineering (e.g., understanding localized applications, finding strings).
4. **Low-Level Relevance:** Examine any interactions with the operating system (Linux, Android), kernel, or binary formats.
5. **Logical Reasoning:**  Where applicable, create hypothetical inputs and outputs for functions.
6. **Common Usage Errors:** Identify potential mistakes users might make when using this module.
7. **Debugging Clues:**  Explain how a user might end up interacting with this specific code during debugging.
这个文件 `i18n.py` 是 Frida 动态 Instrumentation 工具链中负责国际化（i18n）功能的 Meson 构建系统的模块。它的主要功能是帮助开发者在构建 Frida 相关项目时集成和管理软件的本地化翻译。

以下是它的主要功能和相关说明：

**主要功能：**

1. **`merge_file`**:  合并翻译文件。
   - **功能**:  将多个输入文件（通常是 XML 或 desktop 文件）与翻译文件（`.po` 文件）合并，生成最终的、包含本地化信息的输出文件。
   - **与逆向方法的关系**:  在逆向工程中，理解软件的本地化有助于分析其功能和用户界面。如果一个被逆向的程序使用了 `merge_file` 生成本地化文件，那么分析这些合并后的文件可以揭示不同语言版本的字符串和资源，从而更深入地理解程序的行为。
   - **二进制底层，Linux, Android内核及框架的知识**:  此功能依赖于 `msgfmt` 工具，这是一个 GNU gettext 工具链的一部分，用于将 `.po` 文件编译成二进制的 `.mo` 文件。`.mo` 文件是一种二进制格式，操作系统或应用程序可以直接读取并加载翻译数据。在 Linux 和 Android 系统中，应用程序通常使用 `gettext` 库来加载这些 `.mo` 文件，实现多语言支持。
   - **逻辑推理**:
     - **假设输入**:
       - `input`:  一个 XML 文件 `appdata.xml`，其中包含需要翻译的字符串占位符。
       - `po_dir`:  字符串 "po"，指示 `.po` 文件所在的子目录。
       - `output`: 字符串 "appdata.xml"。
     - **预期输出**:  生成一个新的 `appdata.xml` 文件，其中的占位符被替换成了对应语言的翻译文本。
   - **用户或编程常见的使用错误**:
     - 未设置 `install_dir` 却设置了 `install=True`，导致安装目标位置不明确。
     - 提供的 `.po` 文件与输入文件不匹配，导致翻译缺失或错误。
   - **用户操作是如何一步步的到达这里，作为调试线索**:
     - 开发者在 `meson.build` 文件中调用了 `i18n.merge_file()` 函数，例如：
       ```python
       i18n = import('i18n')
       i18n.merge_file(
           input: 'src/appdata.xml.in',
           output: 'appdata.xml',
           po_dir: 'po',
           install: true,
           install_dir: get_option('datadir') / 'metainfo',
           type: 'xml'
       )
       ```
     - 当 Meson 构建系统处理这个 `meson.build` 文件时，会执行 `i18n.py` 中的 `merge_file` 方法。
     - 如果构建过程中出现与本地化相关的问题（例如，`msgfmt` 找不到或版本不兼容），开发者可能会查看构建日志，发现错误信息指向这个 `merge_file` 函数。

2. **`gettext`**:  处理 gettext 相关的任务。
   - **功能**:  用于管理 gettext 的工作流程，包括提取需要翻译的字符串（生成 `.pot` 文件），更新翻译文件（`.po` 文件），并将翻译文件编译成二进制的 `.mo` 文件。
   - **与逆向方法的关系**:  逆向工程师经常需要分析程序中的字符串，以理解程序的功能和交互。`gettext` 生成的 `.pot` 和 `.po` 文件包含了这些可翻译的字符串。分析这些文件可以帮助逆向工程师快速定位程序中的关键文本信息，而无需深入分析二进制代码。
   - **二进制底层，Linux, Android内核及框架的知识**:  此功能依赖于 GNU gettext 工具链，包括 `xgettext`（提取字符串），`msginit`（初始化新的翻译文件），`msgmerge`（合并翻译文件），和 `msgfmt`（编译翻译文件）。这些工具在 Linux 和 Android 开发中被广泛用于实现应用程序的国际化。
   - **逻辑推理**:
     - **假设输入**:
       - `args`: 包含包名，例如 `['my-app']`。
       - `languages`: 包含需要支持的语言列表，例如 `['zh_CN', 'fr']`。
     - **预期输出**:
       - 生成一个 `.pot` 文件 (`my-app.pot`)，其中包含从源代码中提取的可翻译字符串。
       - 为每种指定的语言生成或更新对应的 `.po` 文件 (`zh_CN.po`, `fr.po`)。
       - 为每种语言编译生成 `.mo` 文件 (`zh_CN/LC_MESSAGES/my-app.mo`, `fr/LC_MESSAGES/my-app.mo`)。
   - **用户或编程常见的使用错误**:
     - 忘记在源代码中标记需要翻译的字符串（例如，使用 `_()` 函数）。
     - 提供的语言代码不正确，导致无法生成或更新对应的 `.po` 文件。
     - gettext 工具链未安装或不在 PATH 环境变量中。
   - **用户操作是如何一步步的到达这里，作为调试线索**:
     - 开发者在 `meson.build` 文件中调用了 `i18n.gettext()` 函数，例如：
       ```python
       i18n = import('i18n')
       i18n.gettext('my-app', languages: ['zh_CN', 'fr'])
       ```
     - 如果构建过程中出现与翻译相关的问题（例如，缺少某种语言的翻译，或者 `.mo` 文件生成失败），开发者可能会检查构建日志，发现调用了 `i18n.gettext()`，并进一步分析相关的 gettext 工具是否正确执行。

3. **`itstool_join`**: 使用 `itstool` 合并翻译。
   - **功能**:  用于处理使用 `itstool` 工具的翻译流程，特别是合并 XML 文件和 `.po` 文件。 `itstool` 是一个用于翻译 XML 文档的工具。
   - **与逆向方法的关系**:  一些软件（特别是使用 XML 格式存储数据的软件）会使用 `itstool` 进行翻译。逆向工程师可能需要分析 `itstool` 处理过的文件，以了解不同语言版本的 XML 数据和本地化信息。
   - **二进制底层，Linux, Android内核及框架的知识**:  此功能依赖于 `itstool` 工具，它本身可能涉及到 XML 文件的解析和处理。在某些框架中，XML 文件被用于配置和数据存储，理解其本地化方式有助于理解应用程序的国际化策略。
   - **逻辑推理**:
     - **假设输入**:
       - `input`:  一个或多个 XML 文件。
       - `mo_targets`:  由 `gettext` 生成的 `.mo` 目标列表。
       - `output`:  合并后的 XML 文件名。
     - **预期输出**:  生成一个新的 XML 文件，其中包含了根据提供的 `.mo` 文件进行翻译后的内容。
   - **用户或编程常见的使用错误**:
     - `mo_targets` 参数中提供的 `.mo` 文件与输入 XML 文件不匹配。
     - `itstool` 工具未安装或不在 PATH 环境变量中。
   - **用户操作是如何一步步的到达这里，作为调试线索**:
     - 开发者在 `meson.build` 文件中调用了 `i18n.itstool_join()` 函数，例如：
       ```python
       i18n = import('i18n')
       mo_targets = i18n.gettext('my-docs', languages: ['zh_CN', 'fr'])[0]
       i18n.itstool_join(
           input: 'src/user-manual.xml.in',
           output: 'user-manual.xml',
           mo_targets: mo_targets,
           install: true,
           install_dir: get_option('docdir')
       )
       ```
     - 如果在使用 `itstool` 合并翻译时遇到问题，例如输出的 XML 文件翻译不正确，开发者可能会检查构建日志，确认 `i18n.itstool_join()` 的调用和相关的 `.mo` 文件是否正确。

**涉及到的关键概念和工具：**

* **GNU gettext**:  一套用于编写多语言程序的工具和库。
* **`.po` 文件 (Portable Object)**:  文本文件，包含原始字符串及其对应的翻译。
* **`.mo` 文件 (Machine Object)**:  `.po` 文件的二进制编译版本，应用程序可以直接读取。
* **`.pot` 文件 (Portable Object Template)**:  作为翻译模板的 `.po` 文件，通常由 `xgettext` 生成。
* **`msgfmt`**:  gettext 工具，用于将 `.po` 文件编译成 `.mo` 文件。
* **`msginit`**:  gettext 工具，用于创建新的 `.po` 文件。
* **`msgmerge`**:  gettext 工具，用于将新的翻译字符串合并到现有的 `.po` 文件中。
* **`xgettext`**:  gettext 工具，用于从源代码中提取可翻译的字符串。
* **`itstool`**:  一个用于翻译 XML 文件的工具。
* **Meson**:  一个构建系统，用于自动化软件构建过程。

**总结**:

`i18n.py` 模块在 Frida 的构建过程中扮演着重要的角色，它自动化了与软件国际化相关的任务，例如提取翻译字符串、合并翻译文件和编译翻译文件。理解这个模块的功能有助于理解 Frida 如何支持多语言，并在逆向分析 Frida 或使用 Frida 的目标程序时，能够更好地理解其本地化策略和文本信息。

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/modules/i18n.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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