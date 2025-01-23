Response:
Let's break down the thought process for analyzing this Python code and answering the prompt's questions.

**1. Initial Understanding and Purpose:**

The first step is to understand the *overall goal* of this code. The docstring clearly states it's a module for the Meson build system to handle Qt-related tasks for the Frida dynamic instrumentation tool. Keywords like "Qt," "compile," "resources," "UI," "moc," and "translations" immediately signal its function. The file path also gives context: `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/qt.py`. This means it's part of the Frida project, specifically dealing with Qt within their build system.

**2. Deconstructing the Functionality (Method by Method):**

Next, I'd go through the class `QtBaseModule` and its methods. This is where the core functionality resides. For each method, I'd ask:

* **What does this method do?** (Look at the method name, docstring, and code.)
* **What are its inputs (arguments)?**
* **What are its outputs (return value)?**
* **What external tools or dependencies does it interact with?** (e.g., `moc`, `uic`, `rcc`, `lrelease`).
* **Are there any specific configurations or options?** (Keywords arguments).

**Example - `compile_resources`:**

* **What does it do?** Compiles Qt resource files (`.qrc`) into C++ source files.
* **Inputs:** `sources` (list of `.qrc` files), `name` (optional output file name), `extra_args`.
* **Outputs:** A list of `build.CustomTarget` objects, representing the compilation steps.
* **Tools:** `rcc` (Qt Resource Compiler).
* **Options:** `name`, `extra_args`.

**3. Identifying Relationships with Reverse Engineering:**

Now, consider how this functionality connects to reverse engineering. Frida is a dynamic instrumentation tool, heavily used in reverse engineering. Qt is a UI framework. So, if a target application uses Qt, this module becomes relevant.

* **`compile_ui`:**  Compiling `.ui` files (created with Qt Designer) directly relates to understanding the application's user interface structure *without needing the source code*. Reverse engineers can analyze the generated header files to understand the UI elements, their layout, and potentially associated logic.
* **`compile_moc`:** The Meta-Object Compiler (`moc`) is essential for Qt's signals and slots mechanism, which is a core part of inter-object communication. Reverse engineers analyzing a Qt application would need to understand how these signals and slots work. This compilation step generates code that facilitates this mechanism.
* **`compile_resources`:**  Qt resource files often embed images, icons, and other data within the application. Reverse engineers might need to extract or understand these resources. This compilation step bundles them into the executable.
* **`compile_translations`:**  Understanding the localized strings of an application can be crucial for reverse engineering, especially for identifying functionalities or potential vulnerabilities.

**4. Considering Binary/Kernel/Framework Aspects:**

Think about the underlying systems and technologies involved.

* **Binary Underpinnings:** The output of these compilation steps (C++ files) is eventually compiled into the final application binary. Understanding the purpose of these steps helps understand the structure of the resulting binary.
* **Linux/Android:** Frida is commonly used on Linux and Android. While this specific module doesn't directly interact with the kernel, it's part of building applications that *run* on these kernels. Qt itself has platform-specific aspects. The build system needs to handle these differences.
* **Frameworks (Qt):**  The entire module is deeply embedded within the Qt framework. It leverages Qt's tools and concepts (signals/slots, resources, UI design).

**5. Logical Reasoning (Assumptions and Outputs):**

For logical reasoning, consider simple scenarios:

* **Input:** A single `.ui` file named `mainwindow.ui`.
* **Assumption:** The `compile_ui` method is called.
* **Output:** A header file named `ui_mainwindow.h` will be generated in the build directory.

* **Input:** A `.qrc` file listing several image files.
* **Assumption:** The `compile_resources` method is called.
* **Output:** A C++ source file containing the embedded image data will be created.

**6. Identifying User/Programming Errors:**

Think about common mistakes when using these functionalities:

* **Incorrect paths:**  Specifying the wrong path to a `.ui`, `.qrc`, or `.ts` file.
* **Missing Qt tools:** Not having the `moc`, `uic`, `rcc`, or `lrelease` executables in the system's PATH or the specified `bindir`.
* **Mixing `ts_files` and `qresource`:** The `compile_translations` method explicitly forbids this.
* **Forgetting `install_dir` when `install=True`:** A clear error condition.

**7. Tracing User Operations (Debugging Clues):**

Consider how a developer might end up in this code:

1. **Project Setup:** A developer is building a Frida component that uses Qt. They have a `meson.build` file to configure the build.
2. **Using Qt Functionality:**  In the `meson.build` file, they use the `qt` module's functions like `qt.compile_ui()`, `qt.compile_resources()`, etc.
3. **Meson Execution:** When the developer runs `meson compile`, Meson parses the `meson.build` file.
4. **Module Invocation:** Meson encounters the `qt.*` calls and loads the `qt.py` module.
5. **Method Execution:** The corresponding methods within `qt.py` are executed to perform the Qt-related build tasks.
6. **Potential Error/Debugging:** If there's an issue (e.g., a missing Qt tool), an exception might be raised within this code, leading the developer to examine the traceback and potentially this source file.

**Self-Correction/Refinement During Analysis:**

* **Initially, I might overlook the `_detect_tools` method.** Recognizing its importance in finding the Qt tools is crucial.
* **The nuances of handling different Qt versions (4 vs. 5) and the logic for finding the correct tool executables might require closer inspection.**
* **Understanding the role of `build.CustomTarget` and `build.GeneratedList` in Meson's build process is important for comprehending the outputs of these methods.**
* **Double-checking the conditions under which certain features were added (e.g., `preserve_paths`) based on the `@FeatureNew` decorators enhances accuracy.**

By following this structured approach, combining code analysis with domain knowledge (Frida, Qt, build systems, reverse engineering), and thinking about potential user interactions and errors, one can effectively understand the functionality and significance of this Python module.
This Python code defines a Meson module named `qt` that provides functionalities for building Qt-based projects. It's designed to be used within the Frida project's build system, managed by Meson. Let's break down its features and their relevance.

**Core Functionalities:**

1. **Detecting Qt Tools (`_detect_tools`, `compilers_detect`, `has_tools`):**
   - **Function:**  This module can automatically locate essential Qt development tools like `moc` (Meta-Object Compiler), `uic` (UI Compiler), `rcc` (Resource Compiler), and `lrelease` (Linguist Release Tool). It searches in specified directories or the system's PATH. It also verifies that the detected tools match the specified Qt version.
   - **Relevance to Reverse Engineering:** While not directly a reverse engineering *method*, ensuring the correct build tools are used is crucial for building Frida itself. Frida often needs to interact with and understand the internals of applications, some of which might be built with Qt. Having the right Qt build environment allows Frida developers to create tools that can effectively instrument and analyze these Qt applications.
   - **Binary/Linux/Android:** The tool detection likely involves checking environment variables (`PATH`), and potentially standard locations for Qt installations on Linux and Android.
   - **Logical Reasoning:**
     - **Assumption:** User has Qt installed.
     - **Input:**  The desired Qt version (e.g., Qt 5).
     - **Output:** Boolean indicating whether all required Qt tools are found and their paths are stored.
   - **User Errors:**
     - Not having Qt installed or not having the Qt bin directory in their system's PATH.
     - Installing multiple Qt versions and the module picking up the wrong one.
   - **Debugging:** A user might reach this code if the Frida build fails due to missing Qt tools. The error messages from Meson would indicate a problem during the tool detection phase.

2. **Compiling Qt Resources (`compile_resources`, `_compile_resources_impl`):**
   - **Function:** Takes `.qrc` (Qt Resource Collection) files as input and uses the `rcc` tool to generate C++ source files containing the embedded resources (images, icons, translations, etc.).
   - **Relevance to Reverse Engineering:**  Applications often embed resources. By compiling these resources, Frida can potentially access and analyze this embedded data at runtime. Understanding the resources can give insights into the application's functionality and appearance.
   - **Binary:** The output of `rcc` is C++ code that gets compiled into the final binary. Reverse engineers might need to understand how these resources are packed and accessed.
   - **Logical Reasoning:**
     - **Input:** A list of `.qrc` files.
     - **Output:**  Generated C++ source files (e.g., `qt5-myresources.cpp`).
   - **User Errors:**
     - Providing invalid `.qrc` files with incorrect XML structure.
     - Resources referenced in the `.qrc` file not existing.
   - **Debugging:**  If resource loading in Frida tools fails, or if the build process reports errors related to `rcc`, a developer might trace back to this part of the code.

3. **Compiling Qt User Interfaces (`compile_ui`, `_compile_ui_impl`):**
   - **Function:** Takes `.ui` files (created with Qt Designer) and uses the `uic` tool to generate C++ header files. These header files define the classes and objects representing the user interface.
   - **Relevance to Reverse Engineering:** Understanding the UI structure of an application is fundamental for reverse engineering GUI applications. These generated header files reveal the widgets, layouts, and connections defined in the `.ui` files, allowing Frida to interact with UI elements programmatically.
   - **Binary:** The generated header files are included during the compilation of other parts of the Frida code that interact with Qt applications.
   - **Logical Reasoning:**
     - **Input:** A list of `.ui` files.
     - **Output:** Generated C++ header files (e.g., `ui_mainwindow.h`).
   - **User Errors:**
     - Providing invalid `.ui` files.
     - Incorrectly referencing the generated UI classes in other parts of the code.
   - **Debugging:** Issues with interacting with UI elements of a target application or build errors related to UI classes would lead a developer here.

4. **Compiling Qt Meta-Object Code (`compile_moc`, `_compile_moc_impl`):**
   - **Function:** Takes C++ header files or source files containing Qt-specific constructs (like `Q_OBJECT`, signals, slots, etc.) and uses the `moc` tool to generate additional C++ code. This generated code provides the meta-object system functionality (runtime type information, dynamic properties, etc.).
   - **Relevance to Reverse Engineering:** The meta-object system is crucial to Qt's functionality, especially for signals and slots, which are a common way for objects to communicate. Understanding how signals and slots are implemented is vital for instrumenting and hooking Qt applications. Frida leverages this information to intercept and modify object interactions.
   - **Binary:** The `moc`-generated code is compiled and linked into the final binary, enabling Qt's dynamic features.
   - **Logical Reasoning:**
     - **Input:** A list of header or source files containing Qt meta-object declarations.
     - **Output:** Generated C++ source files (e.g., `moc_mysource.cpp`).
   - **User Errors:**
     - Forgetting to include the `Q_OBJECT` macro in classes that use signals or slots.
     - Incorrectly defining signals and slots.
   - **Debugging:**  If Frida tools fail to interact with Qt signals and slots, or if there are build errors related to missing meta-object information, this code would be a point of investigation.

5. **Preprocessing (`preprocess`):**
   - **Function:** Acts as a convenience function to combine the functionality of `compile_resources`, `compile_ui`, and `compile_moc` in a single step.
   - **Relevance to Reverse Engineering:** Streamlines the build process for Frida components that use multiple Qt features.
   - **Logical Reasoning:** Based on the inputs provided, it internally calls the other compilation functions.
   - **User Errors:**  Similar to the individual compilation functions.

6. **Compiling Qt Translations (`compile_translations`):**
   - **Function:** Takes `.ts` (Qt Translation Source) files and uses the `lrelease` tool to generate `.qm` (Qt Message) files, which are the binary format of translations used by Qt applications.
   - **Relevance to Reverse Engineering:** Understanding the different language versions of an application can be helpful in reverse engineering, especially when looking for specific strings or identifying features based on localized names. Frida might need to interact with or analyze localized strings.
   - **Binary:** The `.qm` files are often loaded dynamically by the application to provide translations.
   - **Logical Reasoning:**
     - **Input:** A list of `.ts` files.
     - **Output:** Generated `.qm` files.
   - **User Errors:**
     - Providing invalid `.ts` files.
     - Incorrectly configuring the application to load the generated `.qm` files.
   - **Debugging:** If Frida tools need to interact with localized strings and the translations are not being built correctly, this code is relevant.

**Relationship to Binary, Linux, Android Kernel & Framework:**

- **Binary:** This code directly contributes to the creation of executable binaries by invoking compilers and tools that generate object code and link them together.
- **Linux/Android:** Frida is heavily used on Linux and Android. This module helps build Frida components that can run on these platforms and interact with Qt applications running on them. The tool detection might involve looking for Qt installations in typical Linux/Android locations.
- **Kernel:** While this module doesn't directly interact with the kernel, it's part of building user-space tools (Frida) that can instrument and analyze processes running on top of the kernel.
- **Framework (Qt):** The entire module is deeply tied to the Qt framework. It relies on Qt's build tools, file formats (`.ui`, `.qrc`, `.ts`), and concepts (meta-object system, resources, translations).

**User Operation as a Debugging Clue:**

A developer working on Frida and using Qt might reach this code in the following steps:

1. **Writing Frida Code:** They are writing a Frida gadget or tool that needs to interact with a Qt application.
2. **Integrating Qt:** Their Frida code includes Qt headers or uses Qt classes.
3. **Configuring the Build:** They have a `meson.build` file that uses the `qt` module to handle the Qt-related build steps. They might be using functions like `qt.compile_ui()`, `qt.compile_resources()`, `qt.compile_moc()`, or `qt.compile_translations()`.
4. **Running Meson:** They execute Meson to configure the build system.
5. **Building Frida:** They execute the build command (e.g., `ninja`).
6. **Error Occurs:** If the build fails during a Qt-related step (e.g., `moc` failing, `uic` not found), Meson's error messages will often point to the specific function call in the `meson.build` file that caused the issue.
7. **Tracing the Error:** The developer might then examine the `frida/subprojects/frida-core/releng/meson/mesonbuild/modules/qt.py` file to understand how the specific Qt tool is being invoked, what arguments are being passed, and what could be going wrong. They might add print statements or use a debugger to step through the code and diagnose the problem.

**Example of Logical Reasoning (Specific Function):**

Let's take `compile_ui`:

- **Hypothetical Input:** `qt.compile_ui(sources: ['mainwindow.ui'])` in `meson.build`.
- **Processing in `qt.py`:** The `compile_ui` function in `qt.py` is called. It detects the `uic` tool. It then calls `uic` with the `mainwindow.ui` file as input and instructs it to generate a header file named `ui_mainwindow.h` in the build directory.
- **Output:**  A file named `ui_mainwindow.h` is created in the build directory. This file contains C++ code defining the UI elements from `mainwindow.ui`.

**Example of User/Programming Error:**

- **Scenario:** A developer uses `qt.compile_moc()` but forgets to include the necessary include directories where the Qt headers are located.
- **Error in `qt.py` (or called tool):** The `moc` tool will likely fail with errors indicating that it cannot find Qt header files like `QObject`.
- **Debugging:** The developer would realize they need to add the correct include paths to the `include_directories` keyword argument of `qt.compile_moc()`.

In summary, this `qt.py` module is a crucial part of Frida's build system, specifically handling the integration of Qt. Its functionalities directly support the development of Frida tools that can understand, interact with, and analyze Qt-based applications, which is a significant aspect of dynamic instrumentation and reverse engineering.

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/modules/qt.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2015 The Meson development team
# Copyright © 2021-2023 Intel Corporation

from __future__ import annotations

import os
import shutil
import typing as T
import xml.etree.ElementTree as ET

from . import ModuleReturnValue, ExtensionModule
from .. import build
from .. import coredata
from .. import mlog
from ..dependencies import find_external_dependency, Dependency, ExternalLibrary, InternalDependency
from ..mesonlib import MesonException, File, version_compare, Popen_safe
from ..interpreter import extract_required_kwarg
from ..interpreter.type_checking import INSTALL_DIR_KW, INSTALL_KW, NoneType
from ..interpreterbase import ContainerTypeInfo, FeatureDeprecated, KwargInfo, noPosargs, FeatureNew, typed_kwargs
from ..programs import NonExistingExternalProgram

if T.TYPE_CHECKING:
    from . import ModuleState
    from ..dependencies.qt import QtPkgConfigDependency, QmakeQtDependency
    from ..interpreter import Interpreter
    from ..interpreter import kwargs
    from ..mesonlib import FileOrString
    from ..programs import ExternalProgram

    QtDependencyType = T.Union[QtPkgConfigDependency, QmakeQtDependency]

    from typing_extensions import TypedDict

    class ResourceCompilerKwArgs(TypedDict):

        """Keyword arguments for the Resource Compiler method."""

        name: T.Optional[str]
        sources: T.Sequence[T.Union[FileOrString, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList]]
        extra_args: T.List[str]
        method: str

    class UICompilerKwArgs(TypedDict):

        """Keyword arguments for the Ui Compiler method."""

        sources: T.Sequence[T.Union[FileOrString, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList]]
        extra_args: T.List[str]
        method: str
        preserve_paths: bool

    class MocCompilerKwArgs(TypedDict):

        """Keyword arguments for the Moc Compiler method."""

        sources: T.Sequence[T.Union[FileOrString, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList]]
        headers: T.Sequence[T.Union[FileOrString, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList]]
        extra_args: T.List[str]
        method: str
        include_directories: T.List[T.Union[str, build.IncludeDirs]]
        dependencies: T.List[T.Union[Dependency, ExternalLibrary]]
        preserve_paths: bool

    class PreprocessKwArgs(TypedDict):

        sources: T.List[FileOrString]
        moc_sources: T.List[T.Union[FileOrString, build.CustomTarget]]
        moc_headers: T.List[T.Union[FileOrString, build.CustomTarget]]
        qresources: T.List[FileOrString]
        ui_files: T.List[T.Union[FileOrString, build.CustomTarget]]
        moc_extra_arguments: T.List[str]
        rcc_extra_arguments: T.List[str]
        uic_extra_arguments: T.List[str]
        include_directories: T.List[T.Union[str, build.IncludeDirs]]
        dependencies: T.List[T.Union[Dependency, ExternalLibrary]]
        method: str
        preserve_paths: bool

    class HasToolKwArgs(kwargs.ExtractRequired):

        method: str

    class CompileTranslationsKwArgs(TypedDict):

        build_by_default: bool
        install: bool
        install_dir: T.Optional[str]
        method: str
        qresource: T.Optional[str]
        rcc_extra_arguments: T.List[str]
        ts_files: T.List[T.Union[str, File, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList]]

class QtBaseModule(ExtensionModule):
    _tools_detected = False
    _rcc_supports_depfiles = False
    _moc_supports_depfiles = False

    def __init__(self, interpreter: 'Interpreter', qt_version: int = 5):
        ExtensionModule.__init__(self, interpreter)
        self.qt_version = qt_version
        # It is important that this list does not change order as the order of
        # the returned ExternalPrograms will change as well
        self.tools: T.Dict[str, T.Union[ExternalProgram, build.Executable]] = {
            'moc': NonExistingExternalProgram('moc'),
            'uic': NonExistingExternalProgram('uic'),
            'rcc': NonExistingExternalProgram('rcc'),
            'lrelease': NonExistingExternalProgram('lrelease'),
        }
        self.methods.update({
            'has_tools': self.has_tools,
            'preprocess': self.preprocess,
            'compile_translations': self.compile_translations,
            'compile_resources': self.compile_resources,
            'compile_ui': self.compile_ui,
            'compile_moc': self.compile_moc,
        })

    def compilers_detect(self, state: 'ModuleState', qt_dep: 'QtDependencyType') -> None:
        """Detect Qt (4 or 5) moc, uic, rcc in the specified bindir or in PATH"""
        wanted = f'== {qt_dep.version}'

        def gen_bins() -> T.Generator[T.Tuple[str, str], None, None]:
            for b in self.tools:
                if qt_dep.bindir:
                    yield os.path.join(qt_dep.bindir, b), b
                if qt_dep.libexecdir:
                    yield os.path.join(qt_dep.libexecdir, b), b
                # prefer the (official) <tool><version> or (unofficial) <tool>-qt<version>
                # of the tool to the plain one, as we
                # don't know what the unsuffixed one points to without calling it.
                yield f'{b}{qt_dep.qtver}', b
                yield f'{b}-qt{qt_dep.qtver}', b
                yield b, b

        for b, name in gen_bins():
            if self.tools[name].found():
                continue

            if name == 'lrelease':
                arg = ['-version']
            elif version_compare(qt_dep.version, '>= 5'):
                arg = ['--version']
            else:
                arg = ['-v']

            # Ensure that the version of qt and each tool are the same
            def get_version(p: T.Union[ExternalProgram, build.Executable]) -> str:
                _, out, err = Popen_safe(p.get_command() + arg)
                if name == 'lrelease' or not qt_dep.version.startswith('4'):
                    care = out
                else:
                    care = err
                return care.rsplit(' ', maxsplit=1)[-1].replace(')', '').strip()

            p = state.find_program(b, required=False,
                                   version_func=get_version,
                                   wanted=wanted)
            if p.found():
                self.tools[name] = p

    def _detect_tools(self, state: 'ModuleState', method: str, required: bool = True) -> None:
        if self._tools_detected:
            return
        self._tools_detected = True
        mlog.log(f'Detecting Qt{self.qt_version} tools')
        kwargs = {'required': required, 'modules': 'Core', 'method': method}
        # Just pick one to make mypy happy
        qt = T.cast('QtPkgConfigDependency', find_external_dependency(f'qt{self.qt_version}', state.environment, kwargs))
        if qt.found():
            # Get all tools and then make sure that they are the right version
            self.compilers_detect(state, qt)
            if version_compare(qt.version, '>=5.15.0'):
                self._moc_supports_depfiles = True
            else:
                mlog.warning('moc dependencies will not work properly until you move to Qt >= 5.15', fatal=False)
            if version_compare(qt.version, '>=5.14.0'):
                self._rcc_supports_depfiles = True
            else:
                mlog.warning('rcc dependencies will not work properly until you move to Qt >= 5.14:',
                             mlog.bold('https://bugreports.qt.io/browse/QTBUG-45460'), fatal=False)
        else:
            suffix = f'-qt{self.qt_version}'
            self.tools['moc'] = NonExistingExternalProgram(name='moc' + suffix)
            self.tools['uic'] = NonExistingExternalProgram(name='uic' + suffix)
            self.tools['rcc'] = NonExistingExternalProgram(name='rcc' + suffix)
            self.tools['lrelease'] = NonExistingExternalProgram(name='lrelease' + suffix)

    @staticmethod
    def _qrc_nodes(state: 'ModuleState', rcc_file: 'FileOrString') -> T.Tuple[str, T.List[str]]:
        abspath: str
        if isinstance(rcc_file, str):
            abspath = os.path.join(state.environment.source_dir, state.subdir, rcc_file)
        else:
            abspath = rcc_file.absolute_path(state.environment.source_dir, state.environment.build_dir)
        rcc_dirname = os.path.dirname(abspath)

        # FIXME: what error are we actually trying to check here? (probably parse errors?)
        try:
            tree = ET.parse(abspath)
            root = tree.getroot()
            result: T.List[str] = []
            for child in root[0]:
                if child.tag != 'file':
                    mlog.warning("malformed rcc file: ", os.path.join(state.subdir, str(rcc_file)))
                    break
                elif child.text is None:
                    raise MesonException(f'<file> element without a path in {os.path.join(state.subdir, str(rcc_file))}')
                else:
                    result.append(child.text)

            return rcc_dirname, result
        except MesonException:
            raise
        except Exception:
            raise MesonException(f'Unable to parse resource file {abspath}')

    def _parse_qrc_deps(self, state: 'ModuleState',
                        rcc_file_: T.Union['FileOrString', build.CustomTarget, build.CustomTargetIndex, build.GeneratedList]) -> T.List[File]:
        result: T.List[File] = []
        inputs: T.Sequence['FileOrString'] = []
        if isinstance(rcc_file_, (str, File)):
            inputs = [rcc_file_]
        else:
            inputs = rcc_file_.get_outputs()

        for rcc_file in inputs:
            rcc_dirname, nodes = self._qrc_nodes(state, rcc_file)
            for resource_path in nodes:
                # We need to guess if the pointed resource is:
                #   a) in build directory -> implies a generated file
                #   b) in source directory
                #   c) somewhere else external dependency file to bundle
                #
                # Also from qrc documentation: relative path are always from qrc file
                # So relative path must always be computed from qrc file !
                if os.path.isabs(resource_path):
                    # a)
                    if resource_path.startswith(os.path.abspath(state.environment.build_dir)):
                        resource_relpath = os.path.relpath(resource_path, state.environment.build_dir)
                        result.append(File(is_built=True, subdir='', fname=resource_relpath))
                    # either b) or c)
                    else:
                        result.append(File(is_built=False, subdir=state.subdir, fname=resource_path))
                else:
                    path_from_rcc = os.path.normpath(os.path.join(rcc_dirname, resource_path))
                    # a)
                    if path_from_rcc.startswith(state.environment.build_dir):
                        result.append(File(is_built=True, subdir=state.subdir, fname=resource_path))
                    # b)
                    else:
                        result.append(File(is_built=False, subdir=state.subdir, fname=path_from_rcc))
        return result

    @FeatureNew('qt.has_tools', '0.54.0')
    @noPosargs
    @typed_kwargs(
        'qt.has_tools',
        KwargInfo('required', (bool, coredata.UserFeatureOption), default=False),
        KwargInfo('method', str, default='auto'),
    )
    def has_tools(self, state: 'ModuleState', args: T.Tuple, kwargs: 'HasToolKwArgs') -> bool:
        method = kwargs.get('method', 'auto')
        # We have to cast here because TypedDicts are invariant, even though
        # ExtractRequiredKwArgs is a subset of HasToolKwArgs, type checkers
        # will insist this is wrong
        disabled, required, feature = extract_required_kwarg(kwargs, state.subproject, default=False)
        if disabled:
            mlog.log('qt.has_tools skipped: feature', mlog.bold(feature), 'disabled')
            return False
        self._detect_tools(state, method, required=False)
        for tool in self.tools.values():
            if not tool.found():
                if required:
                    raise MesonException('Qt tools not found')
                return False
        return True

    @FeatureNew('qt.compile_resources', '0.59.0')
    @noPosargs
    @typed_kwargs(
        'qt.compile_resources',
        KwargInfo('name', (str, NoneType)),
        KwargInfo(
            'sources',
            ContainerTypeInfo(list, (File, str, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList), allow_empty=False),
            listify=True,
            required=True,
        ),
        KwargInfo('extra_args', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('method', str, default='auto')
    )
    def compile_resources(self, state: 'ModuleState', args: T.Tuple, kwargs: 'ResourceCompilerKwArgs') -> ModuleReturnValue:
        """Compile Qt resources files.

        Uses CustomTargets to generate .cpp files from .qrc files.
        """
        if any(isinstance(s, (build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)) for s in kwargs['sources']):
            FeatureNew.single_use('qt.compile_resources: custom_target or generator for "sources" keyword argument',
                                  '0.60.0', state.subproject, location=state.current_node)
        out = self._compile_resources_impl(state, kwargs)
        return ModuleReturnValue(out, [out])

    def _compile_resources_impl(self, state: 'ModuleState', kwargs: 'ResourceCompilerKwArgs') -> T.List[build.CustomTarget]:
        # Avoid the FeatureNew when dispatching from preprocess
        self._detect_tools(state, kwargs['method'])
        if not self.tools['rcc'].found():
            err_msg = ("{0} sources specified and couldn't find {1}, "
                       "please check your qt{2} installation")
            raise MesonException(err_msg.format('RCC', f'rcc-qt{self.qt_version}', self.qt_version))

        # List of generated CustomTargets
        targets: T.List[build.CustomTarget] = []

        # depfile arguments
        DEPFILE_ARGS: T.List[str] = ['--depfile', '@DEPFILE@'] if self._rcc_supports_depfiles else []

        name = kwargs['name']
        sources: T.List['FileOrString'] = []
        for s in kwargs['sources']:
            if isinstance(s, (str, File)):
                sources.append(s)
            else:
                sources.extend(s.get_outputs())
        extra_args = kwargs['extra_args']

        # If a name was set generate a single .cpp file from all of the qrc
        # files, otherwise generate one .cpp file per qrc file.
        if name:
            qrc_deps: T.List[File] = []
            for s in sources:
                qrc_deps.extend(self._parse_qrc_deps(state, s))

            res_target = build.CustomTarget(
                name,
                state.subdir,
                state.subproject,
                state.environment,
                self.tools['rcc'].get_command() + ['-name', name, '-o', '@OUTPUT@'] + extra_args + ['@INPUT@'] + DEPFILE_ARGS,
                sources,
                [f'{name}.cpp'],
                state.is_build_only_subproject,
                depend_files=qrc_deps,
                depfile=f'{name}.d',
                description='Compiling Qt resources {}',
            )
            targets.append(res_target)
        else:
            for rcc_file in sources:
                qrc_deps = self._parse_qrc_deps(state, rcc_file)
                if isinstance(rcc_file, str):
                    basename = os.path.basename(rcc_file)
                else:
                    basename = os.path.basename(rcc_file.fname)
                name = f'qt{self.qt_version}-{basename.replace(".", "_")}'
                res_target = build.CustomTarget(
                    name,
                    state.subdir,
                    state.subproject,
                    state.environment,
                    self.tools['rcc'].get_command() + ['-name', '@BASENAME@', '-o', '@OUTPUT@'] + extra_args + ['@INPUT@'] + DEPFILE_ARGS,
                    [rcc_file],
                    [f'{name}.cpp'],
                    state.is_build_only_subproject,
                    depend_files=qrc_deps,
                    depfile=f'{name}.d',
                    description='Compiling Qt resources {}',
                )
                targets.append(res_target)

        return targets

    @FeatureNew('qt.compile_ui', '0.59.0')
    @noPosargs
    @typed_kwargs(
        'qt.compile_ui',
        KwargInfo(
            'sources',
            ContainerTypeInfo(list, (File, str, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList), allow_empty=False),
            listify=True,
            required=True,
        ),
        KwargInfo('extra_args', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('method', str, default='auto'),
        KwargInfo('preserve_paths', bool, default=False, since='1.4.0'),
    )
    def compile_ui(self, state: ModuleState, args: T.Tuple, kwargs: UICompilerKwArgs) -> ModuleReturnValue:
        """Compile UI resources into cpp headers."""
        if any(isinstance(s, (build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)) for s in kwargs['sources']):
            FeatureNew.single_use('qt.compile_ui: custom_target or generator for "sources" keyword argument',
                                  '0.60.0', state.subproject, location=state.current_node)
        out = self._compile_ui_impl(state, kwargs)
        return ModuleReturnValue(out, [out])

    def _compile_ui_impl(self, state: ModuleState, kwargs: UICompilerKwArgs) -> build.GeneratedList:
        # Avoid the FeatureNew when dispatching from preprocess
        self._detect_tools(state, kwargs['method'])
        if not self.tools['uic'].found():
            err_msg = ("{0} sources specified and couldn't find {1}, "
                       "please check your qt{2} installation")
            raise MesonException(err_msg.format('UIC', f'uic-qt{self.qt_version}', self.qt_version))

        preserve_path_from = os.path.join(state.source_root, state.subdir) if kwargs['preserve_paths'] else None
        # TODO: This generator isn't added to the generator list in the Interpreter
        gen = build.Generator(
            self.tools['uic'],
            kwargs['extra_args'] + ['-o', '@OUTPUT@', '@INPUT@'],
            ['ui_@BASENAME@.h'],
            name=f'Qt{self.qt_version} ui')
        return gen.process_files(kwargs['sources'], state, preserve_path_from)

    @FeatureNew('qt.compile_moc', '0.59.0')
    @noPosargs
    @typed_kwargs(
        'qt.compile_moc',
        KwargInfo(
            'sources',
            ContainerTypeInfo(list, (File, str, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)),
            listify=True,
            default=[],
        ),
        KwargInfo(
            'headers',
            ContainerTypeInfo(list, (File, str, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)),
            listify=True,
            default=[]
        ),
        KwargInfo('extra_args', ContainerTypeInfo(list, str), listify=True, default=[]),
        KwargInfo('method', str, default='auto'),
        KwargInfo('include_directories', ContainerTypeInfo(list, (build.IncludeDirs, str)), listify=True, default=[]),
        KwargInfo('dependencies', ContainerTypeInfo(list, (Dependency, ExternalLibrary)), listify=True, default=[]),
        KwargInfo('preserve_paths', bool, default=False, since='1.4.0'),
    )
    def compile_moc(self, state: ModuleState, args: T.Tuple, kwargs: MocCompilerKwArgs) -> ModuleReturnValue:
        if any(isinstance(s, (build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)) for s in kwargs['headers']):
            FeatureNew.single_use('qt.compile_moc: custom_target or generator for "headers" keyword argument',
                                  '0.60.0', state.subproject, location=state.current_node)
        if any(isinstance(s, (build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)) for s in kwargs['sources']):
            FeatureNew.single_use('qt.compile_moc: custom_target or generator for "sources" keyword argument',
                                  '0.60.0', state.subproject, location=state.current_node)
        out = self._compile_moc_impl(state, kwargs)
        return ModuleReturnValue(out, [out])

    def _compile_moc_impl(self, state: ModuleState, kwargs: MocCompilerKwArgs) -> T.List[build.GeneratedList]:
        # Avoid the FeatureNew when dispatching from preprocess
        self._detect_tools(state, kwargs['method'])
        if not self.tools['moc'].found():
            err_msg = ("{0} sources specified and couldn't find {1}, "
                       "please check your qt{2} installation")
            raise MesonException(err_msg.format('MOC', f'uic-qt{self.qt_version}', self.qt_version))

        if not (kwargs['headers'] or kwargs['sources']):
            raise build.InvalidArguments('At least one of the "headers" or "sources" keyword arguments must be provided and not empty')

        inc = state.get_include_args(include_dirs=kwargs['include_directories'])
        compile_args: T.List[str] = []
        for dep in kwargs['dependencies']:
            compile_args.extend(a for a in dep.get_all_compile_args() if a.startswith(('-I', '-F', '-D')))
            if isinstance(dep, InternalDependency):
                for incl in dep.include_directories:
                    compile_args.extend(f'-I{i}' for i in incl.to_string_list(self.interpreter.source_root, self.interpreter.environment.build_dir))

        output: T.List[build.GeneratedList] = []

        # depfile arguments (defaults to <output-name>.d)
        DEPFILE_ARGS: T.List[str] = ['--output-dep-file'] if self._moc_supports_depfiles else []

        arguments = kwargs['extra_args'] + DEPFILE_ARGS + inc + compile_args + ['@INPUT@', '-o', '@OUTPUT@']
        preserve_path_from = os.path.join(state.source_root, state.subdir) if kwargs['preserve_paths'] else None
        if kwargs['headers']:
            moc_gen = build.Generator(
                self.tools['moc'], arguments, ['moc_@BASENAME@.cpp'],
                depfile='moc_@BASENAME@.cpp.d',
                name=f'Qt{self.qt_version} moc header')
            output.append(moc_gen.process_files(kwargs['headers'], state, preserve_path_from))
        if kwargs['sources']:
            moc_gen = build.Generator(
                self.tools['moc'], arguments, ['@BASENAME@.moc'],
                depfile='@BASENAME@.moc.d',
                name=f'Qt{self.qt_version} moc source')
            output.append(moc_gen.process_files(kwargs['sources'], state, preserve_path_from))

        return output

    # We can't use typed_pos_args here, the signature is ambiguous
    @typed_kwargs(
        'qt.preprocess',
        KwargInfo('sources', ContainerTypeInfo(list, (File, str)), listify=True, default=[], deprecated='0.59.0'),
        KwargInfo('qresources', ContainerTypeInfo(list, (File, str)), listify=True, default=[]),
        KwargInfo('ui_files', ContainerTypeInfo(list, (File, str, build.CustomTarget)), listify=True, default=[]),
        KwargInfo('moc_sources', ContainerTypeInfo(list, (File, str, build.CustomTarget)), listify=True, default=[]),
        KwargInfo('moc_headers', ContainerTypeInfo(list, (File, str, build.CustomTarget)), listify=True, default=[]),
        KwargInfo('moc_extra_arguments', ContainerTypeInfo(list, str), listify=True, default=[], since='0.44.0'),
        KwargInfo('rcc_extra_arguments', ContainerTypeInfo(list, str), listify=True, default=[], since='0.49.0'),
        KwargInfo('uic_extra_arguments', ContainerTypeInfo(list, str), listify=True, default=[], since='0.49.0'),
        KwargInfo('method', str, default='auto'),
        KwargInfo('include_directories', ContainerTypeInfo(list, (build.IncludeDirs, str)), listify=True, default=[]),
        KwargInfo('dependencies', ContainerTypeInfo(list, (Dependency, ExternalLibrary)), listify=True, default=[]),
        KwargInfo('preserve_paths', bool, default=False, since='1.4.0'),
    )
    def preprocess(self, state: ModuleState, args: T.List[T.Union[str, File]], kwargs: PreprocessKwArgs) -> ModuleReturnValue:
        _sources = args[1:]
        if _sources:
            FeatureDeprecated.single_use('qt.preprocess positional sources', '0.59', state.subproject, location=state.current_node)
        # List is invariant, os we have to cast...
        sources = T.cast('T.List[T.Union[str, File, build.GeneratedList, build.CustomTarget]]',
                         _sources + kwargs['sources'])
        for s in sources:
            if not isinstance(s, (str, File)):
                raise build.InvalidArguments('Variadic arguments to qt.preprocess must be Strings or Files')
        method = kwargs['method']

        if kwargs['qresources']:
            # custom output name set? -> one output file, multiple otherwise
            rcc_kwargs: ResourceCompilerKwArgs = {'name': '', 'sources': kwargs['qresources'], 'extra_args': kwargs['rcc_extra_arguments'], 'method': method}
            if args:
                name = args[0]
                if not isinstance(name, str):
                    raise build.InvalidArguments('First argument to qt.preprocess must be a string')
                rcc_kwargs['name'] = name
            sources.extend(self._compile_resources_impl(state, rcc_kwargs))

        if kwargs['ui_files']:
            ui_kwargs: UICompilerKwArgs = {
                'sources': kwargs['ui_files'],
                'extra_args': kwargs['uic_extra_arguments'],
                'method': method,
                'preserve_paths': kwargs['preserve_paths'],
            }
            sources.append(self._compile_ui_impl(state, ui_kwargs))

        if kwargs['moc_headers'] or kwargs['moc_sources']:
            moc_kwargs: MocCompilerKwArgs = {
                'extra_args': kwargs['moc_extra_arguments'],
                'sources': kwargs['moc_sources'],
                'headers': kwargs['moc_headers'],
                'include_directories': kwargs['include_directories'],
                'dependencies': kwargs['dependencies'],
                'method': method,
                'preserve_paths': kwargs['preserve_paths'],
            }
            sources.extend(self._compile_moc_impl(state, moc_kwargs))

        return ModuleReturnValue(sources, [sources])

    @FeatureNew('qt.compile_translations', '0.44.0')
    @noPosargs
    @typed_kwargs(
        'qt.compile_translations',
        KwargInfo('build_by_default', bool, default=False),
        INSTALL_KW,
        INSTALL_DIR_KW,
        KwargInfo('method', str, default='auto'),
        KwargInfo('qresource', (str, NoneType), since='0.56.0'),
        KwargInfo('rcc_extra_arguments', ContainerTypeInfo(list, str), listify=True, default=[], since='0.56.0'),
        KwargInfo('ts_files', ContainerTypeInfo(list, (str, File, build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)), listify=True, default=[]),
    )
    def compile_translations(self, state: 'ModuleState', args: T.Tuple, kwargs: 'CompileTranslationsKwArgs') -> ModuleReturnValue:
        ts_files = kwargs['ts_files']
        if any(isinstance(s, (build.CustomTarget, build.CustomTargetIndex, build.GeneratedList)) for s in ts_files):
            FeatureNew.single_use('qt.compile_translations: custom_target or generator for "ts_files" keyword argument',
                                  '0.60.0', state.subproject, location=state.current_node)
        if kwargs['install'] and not kwargs['install_dir']:
            raise MesonException('qt.compile_translations: "install_dir" keyword argument must be set when "install" is true.')
        qresource = kwargs['qresource']
        if qresource:
            if ts_files:
                raise MesonException('qt.compile_translations: Cannot specify both ts_files and qresource')
            if os.path.dirname(qresource) != '':
                raise MesonException('qt.compile_translations: qresource file name must not contain a subdirectory.')
            qresource_file = File.from_built_file(state.subdir, qresource)
            infile_abs = os.path.join(state.environment.source_dir, qresource_file.relative_name())
            outfile_abs = os.path.join(state.environment.build_dir, qresource_file.relative_name())
            os.makedirs(os.path.dirname(outfile_abs), exist_ok=True)
            shutil.copy2(infile_abs, outfile_abs)
            self.interpreter.add_build_def_file(infile_abs)

            _, nodes = self._qrc_nodes(state, qresource_file)
            for c in nodes:
                if c.endswith('.qm'):
                    ts_files.append(c.rstrip('.qm') + '.ts')
                else:
                    raise MesonException(f'qt.compile_translations: qresource can only contain qm files, found {c}')
            results = self.preprocess(state, [], {'qresources': qresource_file, 'rcc_extra_arguments': kwargs['rcc_extra_arguments']})
        self._detect_tools(state, kwargs['method'])
        translations: T.List[build.CustomTarget] = []
        for ts in ts_files:
            if not self.tools['lrelease'].found():
                raise MesonException('qt.compile_translations: ' +
                                     self.tools['lrelease'].name + ' not found')
            if qresource:
                # In this case we know that ts_files is always a List[str], as
                # it's generated above and no ts_files are passed in. However,
                # mypy can't figure that out so we use assert to assure it that
                # what we're doing is safe
                assert isinstance(ts, str), 'for mypy'
                outdir = os.path.dirname(os.path.normpath(os.path.join(state.subdir, ts)))
                ts = os.path.basename(ts)
            else:
                outdir = state.subdir
            cmd: T.List[T.Union[ExternalProgram, build.Executable, str]] = [self.tools['lrelease'], '@INPUT@', '-qm', '@OUTPUT@']
            lrelease_target = build.CustomTarget(
                f'qt{self.qt_version}-compile-{ts}',
                outdir,
                state.subproject,
                state.environment,
                cmd,
                [ts],
                ['@BASENAME@.qm'],
                state.is_build_only_subproject,
                install=kwargs['install'],
                install_dir=[kwargs['install_dir']],
                install_tag=['i18n'],
                build_by_default=kwargs['build_by_default'],
                description='Compiling Qt translations {}',
            )
            translations.append(lrelease_target)
        if qresource:
            return ModuleReturnValue(results.return_value[0], [results.new_objects, translations])
        else:
            return ModuleReturnValue(translations, [translations])
```