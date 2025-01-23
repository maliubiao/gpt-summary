Response:
Let's break down the thought process for analyzing the provided Python code.

**1. Initial Understanding and Context:**

The first step is to recognize the code's location and purpose. The path `frida/subprojects/frida-node/releng/meson/mesonbuild/modules/i18n.py` tells us a lot:

* **Frida:** This is part of the Frida dynamic instrumentation toolkit. This immediately suggests a connection to reverse engineering and interacting with running processes.
* **subprojects/frida-node:** This specifies that it's related to Frida's Node.js bindings. This hints at the code being involved in the build process for those bindings.
* **releng/meson:** This points to release engineering and the Meson build system. Meson is a build system that focuses on speed and correctness.
* **mesonbuild/modules/i18n.py:** This confirms it's a Meson module specifically for internationalization (i18n).

Therefore, the core function of this code is likely to manage the translation of text within the Frida Node.js bindings during the build process.

**2. High-Level Functionality Identification:**

Reading the class `I18nModule` and its methods reveals the main functionalities:

* **`merge_file`:** This seems to combine multiple translation files (likely `.po` files) into a single output file. The keywords like `input`, `output`, `po_dir`, `type` (xml, desktop) are key indicators.
* **`gettext`:** This is a standard i18n tool. This method likely generates `.pot` files (template files for translations) and compiles `.po` files into binary `.mo` files. The `languages` keyword is a strong clue.
* **`itstool_join`:**  This suggests the use of `itstool`, a tool for merging translations with XML files. The keywords `its_files` and `mo_targets` confirm this.

**3. Connecting to Reverse Engineering:**

With the knowledge that this is part of Frida, the connection to reverse engineering becomes clearer:

* **User Interfaces:** Software often has user interfaces. These interfaces need to be localized for different languages. Frida, being used for inspecting and manipulating software, might interact with localized applications.
* **String Analysis:** Reverse engineers often analyze strings within binaries to understand functionality. Understanding how translations are handled can be part of this process.
* **Dynamic Instrumentation:**  Frida's core functionality involves injecting code into running processes. If a process displays localized text, Frida might interact with the localization mechanisms.

**4. Identifying Binary/Kernel/Framework Connections:**

The use of tools like `msgfmt`, `msginit`, `msgmerge`, and `xgettext` indicates interaction with standard GNU gettext utilities. These utilities often work at a lower level, dealing with:

* **Binary Files (.mo):** Compiled translation files are binary.
* **File System:** The code manipulates files and directories for storing translations.
* **Potentially System Locale:**  While not directly in this code, the output of these tools is used by applications, which often rely on the operating system's locale settings.

**5. Logical Inference (Hypothetical Inputs/Outputs):**

For each function, consider a simple scenario:

* **`merge_file`:**
    * **Input:** Two `.po` files (`en.po`, `fr.po`) in a `po` directory.
    * **Output:** A combined XML file (`translations.xml`).
    * **Reasoning:** The function takes a list of input files and merges them into a single output, specifying the output format.
* **`gettext`:**
    * **Input:** Package name "my_app".
    * **Output:**
        * `my_app.pot` (template file).
        * `my_app-en.mo`, `my_app-fr.mo` (compiled translation files for English and French).
    * **Reasoning:** This function generates the template and compiles translations for specified languages.
* **`itstool_join`:**
    * **Input:** An XML file (`my_app.xml`), English and French `.mo` files.
    * **Output:** A merged XML file with translations integrated.
    * **Reasoning:** Itstool combines XML content with binary translation files.

**6. Common User Errors:**

Think about what could go wrong when using these functions:

* **Incorrect Paths:** Providing wrong paths to input files or the `po_dir`.
* **Missing Tools:** Not having the required gettext tools installed on the system.
* **Incorrect Language Codes:**  Specifying invalid language codes.
* **Conflicting Options:** Using mutually exclusive options.
* **Permissions:**  Not having write permissions to the output directory.

**7. Debugging Scenario (Path to the Code):**

Imagine a developer is working on localizing the Frida Node.js bindings and encounters an issue with the translations not being included correctly. Here's a possible debugging path:

1. **Build Failure:** The build process fails with an error related to translation files.
2. **Meson Output:** The Meson build system provides error messages indicating issues with the `i18n` module.
3. **Inspecting `meson.build`:** The developer examines the `meson.build` files to see how the `i18n` module is used (e.g., calls to `i18n.merge_file`, `i18n.gettext`).
4. **Tracing the Code:**  To understand the error, the developer might need to look at the source code of the `i18n` module itself (the provided code). This could be done by:
    * Finding the module file in the Frida source tree.
    * Using an IDE to step through the code during the build process (if possible).
    * Adding print statements to the `i18n.py` file to track variables and execution flow.

**Self-Correction/Refinement During Analysis:**

* **Initially, I might have focused too much on the "Frida" aspect.** While relevant, it's important to first understand the *direct* functionality of the Python code itself.
* **I might have missed the nuances of the different gettext tools.** Realizing that `msgfmt` compiles, `msginit` initializes, `msgmerge` updates, and `xgettext` extracts is crucial.
* **The `preset` keyword in `gettext` might have been initially unclear.** Recognizing that it provides predefined sets of arguments for different frameworks (like GLib) is important.

By following this structured approach, I can effectively analyze the code, understand its purpose, and connect it to the broader context of Frida and internationalization. The detailed breakdown helps in answering the specific questions about reverse engineering, binary/kernel/framework knowledge, logical inference, user errors, and debugging paths.
This Python code defines a Meson build system module named `i18n` for handling internationalization (i18n) tasks. Let's break down its functionalities and address your specific questions.

**Functionalities:**

The `i18n` module provides several functions to manage translations within a software project:

1. **`merge_file`:**
   - Merges multiple translation files (likely `.po` files) into a single output file, which can be in XML or Desktop Entry format.
   - Uses the `msgfmt` tool to perform the merge.
   - Allows specifying input files, output file name, installation directory, build-by-default status, and additional arguments for `msgfmt`.

2. **`gettext`:**
   - Manages the generation of translation template files (`.pot`) and the compilation of translation files (`.po` to `.mo`).
   - Uses `xgettext` to extract translatable strings from source code and create `.pot` files.
   - Uses `msginit` to initialize new `.po` files for a language.
   - Uses `msgmerge` to update existing `.po` files with new translations from the `.pot` file.
   - Uses `msgfmt` to compile `.po` files into binary `.mo` files, which are used by applications at runtime.
   - Supports specifying the package name, languages to process, installation directory, and preset arguments for different libraries (like GLib).

3. **`itstool_join`:**
   - Merges translations from `.mo` files into XML files using the `itstool` utility.
   - This is particularly useful for projects using XML-based documentation where translations need to be applied to the XML structure.
   - Requires specifying the input XML file, output file name, `.mo` files, and optional ITS (Internationalization Tool Suite) files.

**Relationship to Reverse Engineering:**

This module has indirect but relevant connections to reverse engineering:

* **String Analysis:** Reverse engineers often analyze strings within a binary to understand its functionality or identify vulnerabilities. Understanding how a program handles translations (using gettext, for example) can be part of this analysis. Knowing that a program uses `.mo` files for translations helps the reverse engineer locate and potentially analyze these files to understand the program's user-facing text.
* **Localization Exploits (Less Common):** In rare cases, vulnerabilities might arise from how a program handles different locales or character encodings. While this module itself doesn't introduce such vulnerabilities, understanding the i18n process is a prerequisite for identifying them.
* **Modifying Application Behavior:** Reverse engineers might want to change the displayed text of an application. Knowing that translations are stored in `.mo` files allows them to potentially modify these files (or intercept their loading) to alter the application's interface.

**Example:**

Imagine a reverse engineer is analyzing a closed-source application and wants to understand a specific error message. They might:

1. **Identify the use of gettext:**  By observing the file structure or runtime behavior, they might suspect the application uses gettext for translations.
2. **Locate `.mo` files:** They would look for `.mo` files within the application's installation directory or data folders.
3. **Analyze `.mo` files:** They would use tools to inspect the contents of the `.mo` file, potentially finding the error message in different languages and understanding the context of the error.

**In this specific code, the module helps *build* the translated versions of the Frida Node.js bindings, making them available in different languages. This facilitates a better user experience for international users of Frida.**

**Binary Bottom, Linux, Android Kernel/Framework Knowledge:**

This module interacts with the following:

* **Binary Files (`.mo`):** The `gettext` function compiles human-readable `.po` files into binary `.mo` files. These `.mo` files are loaded by the application at runtime using functions like `bindtextdomain` and `gettext` (or their equivalents). Understanding the binary format of `.mo` files is relevant for tools that directly manipulate translations.
* **Linux Environment:** The gettext tools (`msgfmt`, `xgettext`, etc.) are standard utilities in many Linux distributions. This module relies on these tools being present in the build environment.
* **File System:** The module manipulates files and directories to create, merge, and install translation files. Understanding file system paths and permissions is necessary.
* **Installation Directories:** The module allows specifying installation directories for the translated files. On Linux, these are typically standard locations like `/usr/share/locale`.
* **Potentially Android:** While not explicitly Android-specific in this code, Frida itself runs on Android. The translated Node.js bindings built using this module would be deployed on Android devices. The Android framework has its own localization mechanisms (using `strings.xml` files), but projects using technologies like Node.js might rely on gettext-like solutions.

**Example:**

When the `gettext` function compiles a `.po` file into a `.mo` file, it's creating a binary representation that the operating system's localization libraries can efficiently load. This involves understanding file formats and potentially byte ordering.

**Logical Inference (Hypothetical Input and Output):**

Let's consider the `gettext` function:

**Hypothetical Input:**

```python
i18n.gettext(
    'my_app',
    languages=['en', 'fr'],
    data_dirs=['po'],
    install_dir='/usr/share/locale'
)
```

**Assumptions:**

* There's a directory named `po` in the source directory containing `en.po` and `fr.po` files.
* The source code contains translatable strings that `xgettext` can extract.

**Likely Output:**

1. **A target named `my_app-pot`:** This target, when built, will run `xgettext` to generate `my_app.pot` (a template file) based on the source code.
2. **Two targets named `my_app-en.mo` and `my_app-fr.mo`:** These targets, when built, will compile `en.po` and `fr.po` into `my_app.mo` (likely placed in subdirectories like `en/LC_MESSAGES/` and `fr/LC_MESSAGES/` within the build directory).
3. **An alias target named `my_app-gmo`:** This acts as a convenient way to build all the `.mo` files at once.
4. **A target named `my_app-update-po`:** This target will run `msgmerge` to update the `.po` files with any new strings found in the updated `my_app.pot`.
5. **Installation:** If `install=True` (default), the `my_app.mo` files will be installed to `/usr/share/locale/en/LC_MESSAGES/` and `/usr/share/locale/fr/LC_MESSAGES/`.

**User or Programming Common Usage Errors:**

1. **Incorrect `po_dir` in `merge_file`:** If the `po_dir` keyword argument doesn't point to the actual directory containing the `.po` files, the merge operation will fail.

   **Example:**

   ```python
   i18n.merge_file(
       input=...,
       output='translations.xml',
       po_dir='wrong_po_dir',  # Incorrect path
       type='xml'
   )
   ```

2. **Missing gettext tools:** If the required gettext tools (`msgfmt`, `xgettext`, etc.) are not installed or not in the system's PATH, the `gettext` function will issue warnings and potentially skip building translation targets.

3. **Incorrect language codes in `gettext`:** Providing invalid language codes in the `languages` list will lead to errors when trying to find or create the corresponding `.po` files.

   **Example:**

   ```python
   i18n.gettext('my_app', languages=['en', 'zz'])  # 'zz' is not a valid language code
   ```

4. **Forgetting to run the `update-po` target:** After adding new translatable strings to the source code, developers need to run the `update-po` target generated by `gettext` to update the `.po` files before compiling them.

**User Operation Steps to Reach This Code (Debugging Scenario):**

Imagine a developer working on the Frida Node.js bindings and encountering an issue with translations not being included in the build:

1. **Modifying Source Code with New Strings:** The developer adds new user-facing strings to the JavaScript or C++ code of the Frida Node.js bindings.
2. **Running the Build System:** The developer executes the Meson build command (e.g., `meson build` followed by `ninja -C build`).
3. **Observing Missing Translations:** After building and potentially installing the bindings, the developer notices that the new strings are not translated in the application using the bindings.
4. **Checking Build Output:** The developer examines the build output and might see warnings related to the `i18n` module or the gettext tools.
5. **Inspecting `meson.build` Files:** The developer navigates to the `frida/subprojects/frida-node/releng/meson/` directory and examines the `meson.build` file. They find calls to the `i18n` module, specifically `i18n.gettext` or `i18n.merge_file`.
6. **Suspecting Issues with Translation Generation:** The developer suspects that the translation files (`.po` or merged XML) are not being generated or updated correctly.
7. **Examining `i18n.py`:** To understand how the translation process is implemented, the developer opens the `frida/subprojects/frida-node/releng/meson/mesonbuild/modules/i18n.py` file (the code you provided) to analyze the logic of the `merge_file`, `gettext`, and `itstool_join` functions.
8. **Debugging:** The developer might then try the following:
   - Ensure the gettext tools are installed and in the PATH.
   - Verify the `po_dir` and language codes are correct in the `meson.build` file.
   - Manually run the `update-po` target to see if the `.po` files are being updated.
   - Add print statements within the `i18n.py` code to trace the execution and variable values during the build process.

By understanding the code in `i18n.py`, the developer can gain insights into how translations are handled in the Frida Node.js build process and identify the root cause of the missing translations.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/modules/i18n.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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