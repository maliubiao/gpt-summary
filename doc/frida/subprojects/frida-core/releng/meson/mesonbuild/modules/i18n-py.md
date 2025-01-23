Response:
Let's break down the thought process for analyzing the provided Python code.

1. **Understand the Purpose:** The first step is to identify the core function of the code. The file path (`frida/subprojects/frida-core/releng/meson/mesonbuild/modules/i18n.py`) and the presence of "i18n" in the filename strongly suggest this module deals with internationalization (i18n) within the Frida build system (using Meson). The copyright also points to the Meson development team.

2. **Identify Key Concepts and Libraries:**  Scan the imports. `os.path`, `shlex`, `typing` are general Python. The imports starting with `.` (`. import ...`) indicate this is part of a larger Meson project. Key Meson concepts that jump out are:
    * `ExtensionModule`, `ModuleReturnValue`, `ModuleInfo`:  This confirms it's a Meson module.
    * `build.BuildTarget`, `build.CustomTarget`, etc.: These represent build artifacts and actions within Meson.
    * `mesonlib`: Meson utility functions.
    * `interpreter`:  Interaction with the Meson interpreter.
    * `ExternalProgram`: Represents external tools used in the build process.

3. **Analyze Class Structure:**  The `I18nModule` class is the central component. Note its inheritance from `ExtensionModule`. The `__init__` method shows that it registers several methods: `merge_file`, `gettext`, and `itstool_join`. It also manages a dictionary `self.tools` for storing found external programs.

4. **Examine Individual Methods:**  Now, dive into each method:

    * **`_get_data_dirs`:** A simple helper to resolve relative paths to absolute source paths.

    * **`merge_file`:** This looks like it combines multiple translation files into a single output file. Key observations:
        * It uses `msgfmt` (part of gettext) for merging.
        * It handles different output types (`xml`, `desktop`).
        * It creates a `build.CustomTarget` to perform the merging.
        * It has arguments for installation.

    * **`gettext`:** This seems to be the main function for handling gettext-based localization. Key observations:
        * It finds several gettext utilities (`msgfmt`, `msginit`, `msgmerge`, `xgettext`).
        * It generates `.pot` files (translation templates).
        * It compiles `.po` files into `.mo` files (compiled translations).
        * It creates `build.RunTarget` for running gettext commands and `build.CustomTarget` for compiling `.mo` files.
        * It supports a `preset` argument for common gettext configurations (like GLib).
        * It handles installation of `.mo` files.

    * **`itstool_join`:** This method uses `itstool` to merge translations, likely for XML-based documentation. Key observations:
        * It depends on existing `.mo` files (`mo_targets`).
        * It uses `build.CustomTarget`.

5. **Relate to Reverse Engineering:**  Consider how these functions relate to reverse engineering:

    * **Binary Analysis:**  While the *module itself* doesn't directly analyze binaries, the *output* of these functions (translation files) can be crucial for reverse engineers. Localized strings are often the first point of contact for understanding the functionality of a program.
    * **Dynamic Analysis (Frida Context):** Since this is within Frida's source, the localization of Frida itself is relevant. Reverse engineers using Frida might benefit from localized error messages or UI elements (if Frida has one). Understanding Frida's internal strings can aid in developing Frida scripts.
    * **Android Context:**  Android uses gettext for system-level localization. This module could be used to handle the localization of Frida components running on Android.

6. **Connect to Binary Underpinnings, Linux/Android Kernels/Frameworks:**

    * **Binary:** `.mo` files are binary. The `msgfmt` tool compiles text-based `.po` files into this binary format.
    * **Linux:** Gettext is a standard part of most Linux distributions. The tools used here (`msgfmt`, `xgettext`, etc.) are common Linux utilities.
    * **Android:** Android's framework uses gettext (or a similar mechanism) for localization. Frida running on Android needs to integrate with this.

7. **Look for Logic and Assumptions:**

    * **Assumptions:** The code assumes the availability of gettext tools. It also assumes a specific structure for translation files.
    * **Logic:** The workflow is: extract translatable strings -> create `.pot` template -> translate into `.po` files -> compile into `.mo` files -> merge (optionally).

8. **Identify Potential User Errors:**

    * Incorrect paths for input files.
    * Missing required gettext tools.
    * Incorrect `install_dir`.
    * Not understanding the dependencies between different steps.

9. **Trace User Operations:** How does a user get here?

    * A developer working on Frida wants to add or update translations.
    * They modify source code with translatable strings.
    * They run Meson to configure the build.
    * Meson, encountering the `i18n` module calls, will execute the functions within this module to generate the necessary translation files.
    *  The user might also directly interact with Meson to trigger specific translation-related targets.

10. **Review the Code for Specific Keywords and Patterns:**  Look for keywords like `install`, `output`, `input`, and the names of external tools. This helps solidify the understanding of each function's role. The type hints are also very helpful in understanding the expected data types.

By following these steps, we can systematically analyze the code and address all the requirements of the prompt. The key is to combine general programming knowledge with an understanding of the specific domain (internationalization and the Meson build system).
This Python code file, located at `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/i18n.py`, is a **Meson build system module** specifically designed to handle **internationalization (i18n)** within the Frida project. It provides functionalities to manage and process translation files, making Frida available in multiple languages.

Here's a breakdown of its functions:

**1. `merge_file`:**

* **Functionality:** This function takes multiple input files (which can be source files, build targets, or custom targets) and merges them into a single output file. It's primarily used for merging translated data into resource files.
* **Relationship to Reverse Engineering:** While not directly a reverse engineering tool, understanding how strings are merged and stored can be helpful. A reverse engineer might look at the output of this process to find localized strings within Frida.
* **Binary/Low-Level/Kernel/Framework Knowledge:**
    * It uses the `msgfmt` tool, which is part of the gettext suite and is responsible for compiling `.po` (text-based translation) files into binary `.mo` files. This involves understanding binary formats for storing translated strings.
    * The output file format (`xml` or `desktop`) dictates how the merged data is structured, requiring knowledge of these formats.
* **Logical Reasoning (Example):**
    * **Hypothetical Input:**  `input=['fr.po', 'es.po'], output='translations.xml', po_dir='po', type='xml'`
    * **Hypothetical Output:** A `translations.xml` file containing the merged content of `fr.po` and `es.po`, organized according to the XML structure expected by the application, with metadata pointing to the 'po' directory.
* **User/Programming Errors:**
    * **Incorrect `po_dir`:** If the `po_dir` doesn't point to the directory containing the `.po` files, the merge operation will fail.
    * **Mismatched `type` and input files:** Providing `.po` files when `type` is 'desktop' (which might expect `.desktop` entry translations) could lead to errors.
* **User Operation to Reach Here (Debugging Clue):** A developer working on Frida localization would:
    1. Create or update `.po` files in the `po` directory.
    2. The `meson.build` file would call `i18n.merge_file` specifying these `.po` files as input.
    3. During the `meson compile` step, this function is executed. If there's an error, the stack trace would lead back to this `merge_file` function.

**2. `gettext`:**

* **Functionality:** This is the core function for handling gettext-based translation workflows. It automates tasks like:
    * Generating `.pot` (Portable Object Template) files by extracting translatable strings from the source code using `xgettext`.
    * Updating existing `.po` files with new or changed strings using `msgmerge`.
    * Initializing new `.po` files for new languages using `msginit`.
    * Compiling `.po` files into binary `.mo` files using `msgfmt`.
* **Relationship to Reverse Engineering:**  This is directly related to the strings a reverse engineer will encounter. The `.mo` files are what the application uses at runtime to display localized text. Understanding this process helps in locating and interpreting these strings.
* **Binary/Low-Level/Kernel/Framework Knowledge:**
    * Heavily relies on the gettext toolchain (`xgettext`, `msginit`, `msgmerge`, `msgfmt`). Understanding how these tools work, especially the binary format of `.mo` files, is crucial.
    * On Linux and Android, gettext is a common localization framework. This function is designed to integrate with that ecosystem. The generated `.mo` files are typically placed in standard locations (`/usr/share/locale` on Linux, within the app's assets on Android).
* **Logical Reasoning (Example):**
    * **Hypothetical Input:** `gettext('myprogram', languages=['fr', 'de'])`
    * **Hypothetical Output:**
        * A `myprogram.pot` file containing all translatable strings extracted from the source.
        * `fr.po` and `de.po` files (either newly created or updated) containing the translations for French and German respectively.
        * `myprogram-fr.mo` and `myprogram-de.mo` files (binary) compiled from the `.po` files.
* **User/Programming Errors:**
    * **Missing gettext tools:** If `xgettext`, `msginit`, `msgmerge`, or `msgfmt` are not installed or in the system's PATH, the process will fail.
    * **Incorrect keyword arguments:**  Providing invalid language codes or incorrect data directories can lead to errors.
    * **Conflicts during merge:** If translators have made significant changes to `.po` files, `msgmerge` might encounter conflicts that need manual resolution.
* **User Operation to Reach Here (Debugging Clue):**
    1. A developer adds translatable strings to the Frida codebase.
    2. The `meson.build` file calls `i18n.gettext` with the project name and target languages.
    3. Running `meson compile` triggers the execution of this function, which in turn calls the gettext tools. Errors during any of these steps will lead back to this function.

**3. `itstool_join`:**

* **Functionality:** This function uses `itstool` (Inline Translation Tool) to merge translations, primarily for XML-based documentation. It combines translated content from `.mo` files into XML files.
* **Relationship to Reverse Engineering:**  If Frida's documentation is localized using `itstool`, reverse engineers analyzing Frida's internals might encounter localized documentation strings.
* **Binary/Low-Level/Kernel/Framework Knowledge:**
    * Relies on `itstool`, which understands XML structure and how to embed translated content.
    * It works with `.mo` files generated by the `gettext` function, demonstrating a dependency between these functionalities.
* **Logical Reasoning (Example):**
    * **Hypothetical Input:** `itstool_join(input=['doc.xml'], output='doc.fr.xml', mo_targets=[fr_mo_target])` where `fr_mo_target` is the build target for the French `.mo` file.
    * **Hypothetical Output:** `doc.fr.xml`, a version of `doc.xml` with the translatable elements replaced with their French translations from the specified `.mo` file.
* **User/Programming Errors:**
    * **`itstool` not found:** If `itstool` is not installed.
    * **Incorrect `mo_targets`:** Providing incorrect or missing `.mo` file targets will prevent the translations from being applied.
    * **Malformed XML:**  If the input XML files are not well-formed, `itstool` might fail.
* **User Operation to Reach Here (Debugging Clue):**
    1. Translators provide `.po` files for documentation.
    2. The `meson.build` file uses `i18n.gettext` to generate `.mo` files for documentation.
    3. The `meson.build` file then calls `i18n.itstool_join` to merge these `.mo` files into the XML documentation. Errors during this merge will point to this function.

**Common Aspects and Additional Notes:**

* **Meson Integration:** This module is tightly integrated with the Meson build system. It uses Meson's concepts like `CustomTarget`, `RunTarget`, `ExternalProgram`, and dependency management.
* **Error Handling:** The code includes basic error checking, like ensuring that `install_dir` is provided when `install` is true.
* **Presets:** The `gettext` function supports presets (like 'glib') to automatically configure common gettext settings for specific libraries or frameworks.
* **Debugging:**  If any of these functions encounter errors during the build process, Meson will typically provide error messages indicating the failing step and potentially the arguments passed to the function.

**Relationship to Frida and Reverse Engineering (Specific Examples):**

* **Frida's User Interface:** If Frida has a graphical user interface or command-line interface with text output, this module is responsible for ensuring that this text can be displayed in different languages. A reverse engineer examining Frida might look at the `.mo` files generated by `gettext` to understand the messages and labels within Frida.
* **Frida's Error Messages:** When Frida encounters errors, the messages displayed to the user might be localized. The `gettext` function ensures that these error messages are available in different languages. A reverse engineer analyzing Frida's behavior might find these localized error strings insightful.
* **Frida's Documentation:** If Frida's documentation is being localized (using `itstool_join`), a reverse engineer reading the documentation might encounter localized versions, aiding in understanding Frida's features in their preferred language.

In summary, this `i18n.py` module is a crucial part of Frida's build process, enabling its internationalization. While not a direct reverse engineering tool itself, understanding its functions and outputs is valuable for reverse engineers who want to analyze Frida, understand its localized aspects, or even contribute to its translation efforts.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/i18n.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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