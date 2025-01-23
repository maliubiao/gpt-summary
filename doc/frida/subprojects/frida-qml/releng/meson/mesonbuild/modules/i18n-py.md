Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding of the Code's Purpose:**

The file path `frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/i18n.py` and the `SPDX-License-Identifier: Apache-2.0` header immediately suggest this is part of a larger build system (Meson) and deals with internationalization (i18n). The "frida-qml" part indicates it's specific to the Qt-based UI of the Frida dynamic instrumentation tool.

**2. Core Functionality - Identifying the Main Methods:**

The `I18nModule` class is the central piece. Looking at the `__init__` method, the `self.methods.update(...)` line reveals the key functionalities provided by this module: `merge_file`, `gettext`, and `itstool_join`.

**3. Analyzing Each Function Individually:**

* **`merge_file`:** The name suggests combining translation files. The docstring and keyword arguments confirm this. It takes input files, an output name, and deals with installation. The mention of `msgfmt` and types like 'xml' and 'desktop' indicate it's about generating compiled message catalogs (MO files) for different contexts.

* **`gettext`:** This is a standard i18n tool. The arguments (package name), languages, and the use of tools like `xgettext`, `msginit`, `msgmerge`, and `msgfmt` clearly point to the workflow of extracting translatable strings, initializing new translations, merging updates, and compiling them.

* **`itstool_join`:**  The name and the mention of `itstool` suggest it's related to the `itstool` utility, which is used to merge translations with XML files, particularly for documentation. The `mo_targets` argument ties it to the output of the `gettext` function.

**4. Looking for Connections to Reverse Engineering and Security:**

This requires connecting the dots between i18n and reverse engineering:

* **String Analysis:**  Reverse engineers often look at strings within binaries to understand functionality. i18n deals with *user-facing* strings. So, the generated MO files contain the translations of these strings. This makes them a target for analysis to understand the application's UI and potentially discover hidden features or vulnerabilities (though indirectly).

* **Localization Issues:** Incorrect or incomplete translations can sometimes expose internal logic or reveal development practices. While not a direct reverse engineering *technique*, it can be an *observation* during analysis.

* **Frida Context:**  Knowing this is part of Frida is crucial. Frida is a dynamic instrumentation tool. This means it can inject code and intercept function calls in running processes. The i18n module is responsible for *localizing Frida's own UI*. This is important for usability but less directly related to *instrumenting target applications*. However, one could *theoretically* use Frida to hook into the localization functions of a target application, but this module itself doesn't provide that.

**5. Identifying Links to Binary/OS Concepts:**

* **`msgfmt` and MO files:** These are binary files. Understanding how `msgfmt` compiles translations into a binary format is relevant to low-level analysis.

* **Linux/Android Context:**  The mention of `localedir` and the typical structure of locale directories (`/usr/share/locale`, etc.) links to these operating systems. Android also has its own localization mechanisms, though the core gettext concepts are similar. The generated MO files would be deployed according to the platform's conventions.

* **`itstool` and XML:** `itstool` often works with XML files, which are structured data. This is a common format in many software systems, including configuration files and document formats.

**6. Logical Reasoning and Input/Output Examples:**

For each function, it's helpful to imagine a simple use case:

* **`merge_file`:** Input: a `.po` file and some XML files. Output: a merged XML file with translations.

* **`gettext`:** Input: a package name and source code. Output: a `.pot` file (template), individual `.po` files for each language, and compiled `.mo` files.

* **`itstool_join`:** Input: XML files and `.mo` files. Output: Merged XML files with translations applied.

**7. Common Usage Errors:**

Thinking about how a developer might misuse these functions is important:

* **Missing `install_dir`:** Forgetting to specify where to install the generated files.
* **Incorrect dependencies:** Not ensuring the necessary gettext tools are installed.
* **Mismatched versions:** Using an older `msgfmt` with newer features.
* **Incorrect `po_dir`:**  Specifying the wrong location for the translation files.
* **Typos in language codes:**  Leading to missing or incorrect translations.

**8. Tracing User Actions (Debugging):**

To understand how execution reaches this code, one needs to think about the Meson build process:

1. **`meson.build` file:** The user would call functions from this module (e.g., `i18n.gettext()`) in their `meson.build` file.
2. **Meson execution:** When the user runs `meson compile`, Meson parses the `meson.build` file.
3. **Module loading:** Meson loads the `i18n.py` module.
4. **Function call:**  Meson executes the `i18n.gettext()` (or other i18n functions) based on the user's `meson.build`.
5. **Parameter validation:** The `@typed_kwargs` decorators handle input validation.
6. **Tool execution:** The code finds and executes the necessary external tools (`msgfmt`, `xgettext`, etc.).
7. **Target creation:** Meson creates build targets (e.g., custom targets) based on the function calls.
8. **Compilation:** During the actual build process (e.g., with `ninja`), these targets are executed, generating the translation files.

**Self-Correction/Refinement during the Process:**

* **Initial focus might be too broad:** Initially, I might think about all aspects of reverse engineering. However, realizing the direct link is more about *analyzing the translated strings* rather than some core binary manipulation helps to narrow the focus.

* **Overlooking Frida specifics:** Remembering that this is within the Frida context is important. While the i18n module itself doesn't directly instrument applications, it's part of the Frida *tooling*.

* **Clarifying the role of Meson:** Emphasizing that this code is part of the *build system* and not the *runtime* of the application is crucial for understanding its purpose.

By following these steps, moving from a high-level understanding to detailed analysis of each function, and then connecting it to the broader contexts of reverse engineering, binary analysis, and the Frida tool, we can generate a comprehensive explanation of the code's functionality.
This Python code file, located within the Meson build system for Frida's QML components, is responsible for providing internationalization (i18n) functionalities. It helps developers manage and integrate translations into their software. Let's break down its features and connections:

**Core Functionalities:**

1. **`merge_file`:**
   - **Purpose:** This function merges multiple input files (which can be source files, build targets, or other generated files) into a single output file. Its primary use in the i18n context is to combine translated message files (like `.po` files) into a final, ready-to-use format (like `.xml` or `.desktop` files).
   - **Functionality:**
     - Takes a list of input files (`input`).
     - Specifies the output file name (`output`).
     - Determines if the target should be built by default (`build_by_default`).
     - Controls installation (`install`, `install_dir`, `install_tag`).
     - Accepts additional arguments for the merging process (`args`).
     - Specifies directories containing data needed for merging (`data_dirs`).
     - Requires the path to the directory containing the `.po` files (`po_dir`).
     - Defines the output file type (`type`, either 'xml' or 'desktop').
   - **Underlying Mechanism:** It uses a custom Meson command (`msgfmthelper`) which internally leverages the `msgfmt` tool from the GNU gettext suite. `msgfmt` compiles `.po` files into binary `.mo` files, but this function seems to use it indirectly for other file formats.

2. **`gettext`:**
   - **Purpose:** This function implements the standard GNU gettext workflow for managing software translations. It helps extract translatable strings from source code, create translation templates (`.pot` files), and compile translations into binary message catalogs (`.mo` files).
   - **Functionality:**
     - Takes the package name as the first argument.
     - Allows specifying extra arguments for the gettext tools (`args`).
     - Defines directories to search for translatable strings (`data_dirs`).
     - Controls installation of the generated `.mo` files (`install`, `install_dir`).
     - Specifies the languages to generate translations for (`languages`).
     - Offers presets for common gettext configurations (like 'glib').
   - **Underlying Mechanism:** It orchestrates the execution of several external tools from the gettext suite:
     - `xgettext`: Extracts translatable strings from source code to create `.pot` files.
     - `msginit`: Initializes new translations by creating `.po` files from a `.pot` template.
     - `msgmerge`: Updates existing `.po` files with new strings from a `.pot` template.
     - `msgfmt`: Compiles `.po` files into binary `.mo` files, which are used by the application at runtime to load translations.

3. **`itstool_join`:**
   - **Purpose:** This function integrates translations into XML-based documentation using `itstool`. `itstool` is a tool specifically designed for this purpose.
   - **Functionality:**
     - Takes a list of input XML files (`input`).
     - Specifies the output XML file name (`output`).
     - Controls build and installation settings similar to `merge_file`.
     - Accepts additional arguments for `itstool` (`args`).
     - Requires a list of ITS (Internationalization Tool Suite) files (`its_files`), which provide rules for how to extract and apply translations within XML.
     - Importantly, it requires a list of previously generated message catalog targets (`mo_targets`) created by the `gettext` function.
   - **Underlying Mechanism:** It directly uses the `itstool` command-line tool to merge the translations from the `.mo` files into the input XML files based on the rules defined in the ITS files.

**Relationship to Reverse Engineering:**

This module has indirect but relevant connections to reverse engineering:

* **String Analysis:** Reverse engineers often analyze the strings present within an application's binary to understand its functionality, identify debugging symbols, or look for potential vulnerabilities. The `.mo` files generated by the `gettext` function contain all the user-facing strings of the application in different languages. Analyzing these `.mo` files can provide insights into the application's features and messages without needing to fully disassemble and understand the code.

   **Example:** A reverse engineer might examine the English `.mo` file of a Frida gadget to see what error messages or logging statements are present. This could hint at internal states or security mechanisms.

* **Localization Vulnerabilities:** While less common, vulnerabilities can arise from incorrect or incomplete localization. For example, if a translation introduces a format string vulnerability or exposes sensitive information, a reverse engineer might discover this by examining the generated translation files.

   **Example:** Imagine a translation accidentally includes a debug log message with internal paths. A reverse engineer analyzing the `.mo` file might discover these paths.

* **Understanding UI Elements:** The translated strings directly correspond to the elements visible in the user interface. Examining these strings can help a reverse engineer understand the structure and flow of the application's UI, even without running it.

   **Example:** By looking at the translations in the `frida-qml` context, a reverse engineer can understand the various options and dialogs available in Frida's QML-based user interface.

**Binary 底层, Linux, Android 内核及框架 的知识:**

* **Binary 底层 (`.mo` files):** The `gettext` function ultimately produces `.mo` files. These are binary files in a specific format that the application's localization library (e.g., `gettext` on Linux) understands. Understanding the structure of `.mo` files is a low-level binary analysis task.

   **Example:** A reverse engineer might need to parse a `.mo` file manually if standard tools are unavailable or if they are looking for specific patterns or vulnerabilities within the binary structure of the translation catalog.

* **Linux:** The `gettext` suite is a standard part of many Linux distributions. The `localedir` option mentioned in the code refers to the standard location on Linux systems where locale data (including `.mo` files) is installed (e.g., `/usr/share/locale`).

   **Example:** When the `install` option is True in the `gettext` function, the generated `.mo` files will likely be installed under a subdirectory of `/usr/share/locale`, following the standard Linux locale directory structure.

* **Android:** While Android doesn't directly use the GNU `gettext` suite in its core framework, the concepts of internationalization and message catalogs are similar. Android uses its own resource system (`.xml` files in `res/values-*`) for managing translations. However, applications built with native code (like parts of Frida) might choose to use `gettext` or similar libraries on Android as well.

   **Example:** If Frida's QML interface uses `gettext` on Android, the generated `.mo` files would need to be packaged within the Android application's APK and loaded appropriately. The `install_dir` parameter would be crucial for specifying where these files should go within the APK or on the device.

* **Frameworks (Frida QML):** This code is specifically within the `frida-qml` subdirectory, indicating it's related to Frida's user interface built using the Qt QML framework. Qt has its own mechanisms for handling translations (using `.ts` and `.qm` files), which are conceptually similar to `.po` and `.mo` files. This module likely bridges the gap between the standard `gettext` workflow and Qt's translation system, or it might be used for localizing parts of the Frida UI that don't directly use Qt's built-in translation features.

**逻辑推理 (假设输入与输出):**

**`merge_file` Example:**

* **假设输入:**
    - `input`: `['zh_CN.po', 'en_US.po']` (files in the current source directory)
    - `output`: `frida.xml`
    - `po_dir`: `po`
    - `type`: `xml`
* **预期输出:** A custom target in Meson will be created. When built, this target will execute a command that uses `msgfmt` (indirectly via `msgfmthelper`) to merge the contents of `zh_CN.po` and `en_US.po` (likely after some conversion) into a single XML file named `frida.xml` in the build directory.

**`gettext` Example:**

* **假设输入:**
    - Package name: `frida-core`
    - `languages`: `['zh_CN', 'fr_FR']`
* **预期输出:**
    - A `.pot` template file (`frida-core.pot`) will be generated in the build directory, containing all translatable strings extracted from the source code.
    - Two `.po` files will be created (or updated): `zh_CN.po` and `fr_FR.po` in their respective language subdirectories (e.g., `zh_CN/LC_MESSAGES/`).
    - Two `.mo` files will be compiled: `zh_CN/LC_MESSAGES/frida-core.mo` and `fr_FR/LC_MESSAGES/frida-core.mo` in the build directory.
    - If `install=True`, these `.mo` files will be installed under the appropriate locale directories on the system (e.g., `/usr/share/locale/zh_CN/LC_MESSAGES/frida-core.mo`).

**`itstool_join` Example:**

* **假设输入:**
    - `input`: `['manual.xml']`
    - `output`: `manual.xml`
    - `mo_targets`: A list containing the build targets for `frida-core-zh_CN.mo` and `frida-core-fr_FR.mo` (generated by `gettext`).
    - `its_files`: `['translate.its']`
* **预期输出:** A custom target will be created. When built, this target will execute `itstool` to merge the translations from the `.mo` files into `manual.xml`, potentially creating `zh_CN/manual.xml` and `fr_FR/manual.xml` in the build directory, guided by the rules in `translate.its`.

**用户或编程常见的使用错误:**

* **`merge_file`:**
    - **Forgetting `po_dir`:** If the user doesn't specify the `po_dir`, the script won't know where to find the `.po` files, leading to an error.
    - **Incorrect `input` types:** Providing input that isn't a valid file, build target, etc., will cause Meson to fail.
    - **Missing `install_dir` when `install=True`:** If the user wants to install the merged file but doesn't specify where, the script will raise an `InvalidArguments` exception.
* **`gettext`:**
    - **Not having gettext tools installed:** If the necessary gettext tools (`xgettext`, `msgfmt`, etc.) are not in the system's PATH, the `state.find_program()` calls will fail, and the translation process will not work.
    - **Incorrect language codes:**  Using invalid language codes in the `languages` list will result in incorrect or missing translations.
    - **Conflicting `args`:** Providing conflicting or incorrect arguments to the underlying gettext tools might cause them to fail.
* **`itstool_join`:**
    - **Missing `mo_targets`:**  If the user forgets to provide the list of `.mo` file targets generated by `gettext`, `itstool` won't have any translations to merge.
    - **Incorrect `its_files` paths:** If the paths to the ITS files are wrong, `itstool` won't be able to apply the translation rules.
    - **`install_dir` issues (similar to `merge_file`).**

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **Developer wants to add or update translations in Frida's QML interface.**
2. **The developer modifies translatable strings in the source code.**
3. **The developer runs a Meson command (e.g., `meson compile` or a custom target related to translations).**
4. **Meson parses the `meson.build` files.**
5. **In the relevant `meson.build` file (likely within the `frida/subprojects/frida-qml` directory), there will be calls to functions from the `i18n` module.**  For example:
   - `i18n.gettext('frida-qml', ...)` to manage the overall translation process.
   - `i18n.merge_file(...)` to combine translated resources into a specific format.
   - `i18n.itstool_join(...)` to integrate translations into XML documentation.
6. **When Meson encounters these calls, it loads the `frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/i18n.py` file.**
7. **The corresponding function (`merge_file`, `gettext`, or `itstool_join`) within the `I18nModule` class is executed.**
8. **The function interacts with the Meson build environment (`state`), finds necessary external tools (like `msgfmt`, `xgettext`, `itstool`), and creates custom build targets that encapsulate the translation steps.**
9. **If the user encounters an error during the build process related to translations, they might investigate the execution of these `i18n` module functions.** They might:
   - **Check the arguments passed to the `i18n` functions in the `meson.build` file.** Are the paths correct? Are the language codes valid?
   - **Verify that the required gettext and itstool utilities are installed and in the PATH.**
   - **Examine the generated build commands** (Meson often shows these during verbose builds) to see how the external tools are being invoked.
   - **Set breakpoints within the `i18n.py` code** (if debugging the Meson build system itself) to understand the flow of execution and the values of variables.

Therefore, this `i18n.py` file is a crucial part of Frida's build system, specifically for managing the localization of its QML-based user interface and documentation. Understanding its functions is essential for developers working on translations or troubleshooting translation-related build issues within the Frida project.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/modules/i18n.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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