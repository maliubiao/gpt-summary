Response:
The user is asking for a summary of the provided Python code, which is a part of the Frida dynamic instrumentation tool and specifically handles the generation of Xcode project files. I need to identify the key functionalities of this code snippet, relate it to reverse engineering concepts, highlight its interactions with low-level systems (if any), mention any logical assumptions or user errors it addresses, and describe the user path to reach this code.

**Plan:**

1. **Identify Core Functionality:**  Focus on what the code does – generating Xcode project files. Pinpoint the classes and methods that contribute to this.
2. **Reverse Engineering Relevance:**  Consider how generating Xcode projects aids reverse engineering workflows (e.g., inspecting code structure, debugging).
3. **Low-Level Interactions:** Look for mentions of operating systems (like macOS, implied by Xcode), file formats (like Mach-O), or any direct interaction with kernel/framework concepts (though this specific snippet seems high-level).
4. **Logical Inferences:**  Analyze how the code maps Meson build definitions to Xcode project structure. Identify any assumptions made about the input.
5. **User Errors:**  Think about common mistakes users might make in their Meson build setup that could lead to issues handled by this code.
6. **User Journey:** Trace back how a user's action (likely initiating a build with the Xcode backend) leads to this code being executed.
7. **Summarize Functionality:** Concisely describe the primary purpose of the code.这是frida动态 instrumentation tool中负责生成Xcode项目文件的代码。它主要的功能可以归纳为以下几点：

1. **将Meson构建定义转换为Xcode项目结构:**  这段代码读取Meson的构建描述（例如 `meson.build` 文件中定义的 targets, sources, dependencies 等），并将其转换为 Xcode 理解的 `.xcodeproj` 项目文件的格式。这包括生成 Xcode 项目文件所需的各种 section，如 `PBXProject`, `PBXNativeTarget`, `PBXSourcesBuildPhase` 等。

2. **管理Xcode项目元素的唯一ID:**  Xcode 项目文件中的每个元素（例如文件引用、构建目标、构建阶段等）都需要一个唯一的 ID。这段代码负责生成和管理这些 ID，以确保项目文件的正确性。

3. **映射文件类型到Xcode类型:**  不同的文件类型在 Xcode 中有不同的表示。代码中 `XCODETYPEMAP` 字典用于将常见的源代码文件扩展名（如 `.c`, `.cpp`, `.swift`）映射到 Xcode 对应的类型标识符（如 `sourcecode.c.c`, `sourcecode.swift`）。

4. **处理构建配置:**  代码中包含了对不同构建类型（如 debug, release）的处理，并将 Meson 的构建选项映射到 Xcode 的构建设置。

5. **处理依赖关系:**  代码能够识别 Meson 中定义的 targets 之间的依赖关系，并在生成的 Xcode 项目中正确地表示这些依赖，例如通过 `PBXTargetDependency` section。

6. **处理自定义构建目标 (Custom Targets):**  Meson 允许用户定义自定义的构建步骤。这段代码也能够将这些自定义目标转换为 Xcode 的 shell script build phases。

7. **处理生成的文件 (Generated Sources):** 对于通过 Meson 的 `generator` 功能生成的文件，代码会创建相应的 Xcode 构建文件和文件引用。

**它与逆向的方法的关系：**

这段代码本身并不直接进行逆向操作，但它生成的 Xcode 项目是逆向工程师进行动态分析的重要工具。

*   **举例说明:**  假设逆向工程师想要分析一个 iOS 应用程序。他们可以使用 Frida 来 hook 该应用程序的运行时行为。为了方便地查看和管理 Frida 的脚本以及相关的应用程序源码，可以将 Frida 的相关配置和脚本包含在 Xcode 项目中。这段代码生成的 Xcode 项目文件就能帮助实现这一点，让逆向工程师可以在 Xcode 的集成开发环境中编写、调试和管理 Frida 脚本。通过 Xcode，他们可以更方便地查看代码结构，设置断点，并进行单步调试，从而理解应用程序的内部工作原理。

**涉及到二进制底层，linux, android内核及框架的知识：**

这段代码本身是高级语言 Python 编写的，主要处理 Xcode 项目文件的生成逻辑，**不直接涉及**二进制底层、Linux 或 Android 内核及框架的知识。  它所服务的 Frida 工具本身才大量涉及到这些底层知识。

**做了逻辑推理：**

这段代码做了很多逻辑推理，主要是基于 Meson 的构建定义来推断并生成正确的 Xcode 项目结构。

*   **假设输入与输出:**
    *   **假设输入:** 一个定义了名为 `my_library` 的共享库 target 的 `meson.build` 文件，以及一些源文件（如 `a.c`, `b.cpp`）。
    *   **输出:** 生成的 Xcode 项目文件 (`.xcodeproj`) 中会包含一个名为 `my_library` 的 target，并且该 target 的 "Build Phases" 中会包含一个 "Sources" 阶段，其中列出了 `a.c` 和 `b.cpp` 这两个源文件，并且它们的 Xcode 类型会根据 `XCODETYPEMAP` 被正确地设置为 `sourcecode.c.c` 和 `sourcecode.cpp.cpp`。

**涉及用户或者编程常见的使用错误：**

这段代码本身不太容易导致用户的直接使用错误，因为它是在 Meson 构建过程中自动执行的。但是，Meson 配置中的错误可能导致生成的 Xcode 项目不正确。

*   **举例说明:**  如果用户在 `meson.build` 文件中错误地声明了源文件的类型（例如，将一个 C++ 文件声明为 C 文件），那么这段代码会根据 Meson 的错误信息生成 Xcode 项目文件，但在 Xcode 中编译时可能会报错，因为 Xcode 会尝试使用错误的编译器处理该文件。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

用户通常通过以下步骤到达这里：

1. **编写 `meson.build` 文件:** 用户编写 Meson 的构建定义文件，描述项目的结构、依赖和构建方式。
2. **配置构建环境:** 用户在命令行中使用 `meson` 命令配置构建环境，**并指定 Xcode 作为后端**，例如：`meson setup builddir -Dbackend=xcode`。
3. **执行构建:** 用户使用 `ninja` 或 `meson compile` 命令触发构建过程。
4. **Meson 调用后端:** Meson 的核心逻辑会解析 `meson.build` 文件，并根据指定的后端 (`xcode`) 调用 `frida/releng/meson/mesonbuild/backend/xcodebackend.py` 这个脚本。
5. **代码执行:**  `XCodeBackend` 类的实例会被创建，其 `generate` 方法会被调用，开始生成 Xcode 项目文件的过程。

**归纳一下它的功能 (第1部分):**

这段代码的主要功能是作为 Frida 构建系统的一部分，负责将 Meson 的项目构建定义转换成 Xcode 可以理解的项目文件格式。它通过生成 Xcode 项目所需的各种 section 和元素，并管理它们的唯一 ID，使得用户可以使用 Xcode IDE 来查看、构建和调试 Frida 项目或依赖于 Frida 的项目。这对于需要在 macOS 或 iOS 平台上进行逆向分析和动态 instrumentation 的场景尤其重要。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/backend/xcodebackend.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2014-2021 The Meson development team

from __future__ import annotations

import functools, uuid, os, operator
import typing as T

from . import backends
from .. import build
from .. import mesonlib
from .. import mlog
from ..mesonlib import MesonBugException, MesonException, OptionKey

if T.TYPE_CHECKING:
    from ..interpreter import Interpreter

INDENT = '\t'
XCODETYPEMAP = {'c': 'sourcecode.c.c',
                'a': 'archive.ar',
                'cc': 'sourcecode.cpp.cpp',
                'cxx': 'sourcecode.cpp.cpp',
                'cpp': 'sourcecode.cpp.cpp',
                'c++': 'sourcecode.cpp.cpp',
                'm': 'sourcecode.c.objc',
                'mm': 'sourcecode.cpp.objcpp',
                'h': 'sourcecode.c.h',
                'hpp': 'sourcecode.cpp.h',
                'hxx': 'sourcecode.cpp.h',
                'hh': 'sourcecode.cpp.hh',
                'inc': 'sourcecode.c.h',
                'swift': 'sourcecode.swift',
                'dylib': 'compiled.mach-o.dylib',
                'o': 'compiled.mach-o.objfile',
                's': 'sourcecode.asm',
                'asm': 'sourcecode.asm',
                'metal': 'sourcecode.metal',
                'glsl': 'sourcecode.glsl',
                }
LANGNAMEMAP = {'c': 'C',
               'cpp': 'CPLUSPLUS',
               'objc': 'OBJC',
               'objcpp': 'OBJCPLUSPLUS',
               'swift': 'SWIFT_'
               }
OPT2XCODEOPT = {'plain': None,
                '0': '0',
                'g': '0',
                '1': '1',
                '2': '2',
                '3': '3',
                's': 's',
                }
BOOL2XCODEBOOL = {True: 'YES', False: 'NO'}
LINKABLE_EXTENSIONS = {'.o', '.a', '.obj', '.so', '.dylib'}

class FileTreeEntry:

    def __init__(self) -> None:
        self.subdirs: T.Dict[str, FileTreeEntry] = {}
        self.targets: T.List[build.BuildTarget] = []

class PbxArray:
    def __init__(self) -> None:
        self.items: T.List[PbxArrayItem] = []

    def add_item(self, item: T.Union[PbxArrayItem, str], comment: str = '') -> None:
        if isinstance(item, PbxArrayItem):
            self.items.append(item)
        else:
            self.items.append(PbxArrayItem(item, comment))

    def write(self, ofile: T.TextIO, indent_level: int) -> None:
        ofile.write('(\n')
        indent_level += 1
        for i in self.items:
            if i.comment:
                ofile.write(indent_level*INDENT + f'{i.value} {i.comment},\n')
            else:
                ofile.write(indent_level*INDENT + f'{i.value},\n')
        indent_level -= 1
        ofile.write(indent_level*INDENT + ');\n')

class PbxArrayItem:
    def __init__(self, value: str, comment: str = ''):
        self.value = value
        if comment:
            if '/*' in comment:
                self.comment = comment
            else:
                self.comment = f'/* {comment} */'
        else:
            self.comment = comment

class PbxComment:
    def __init__(self, text: str):
        assert isinstance(text, str)
        assert '/*' not in text
        self.text = f'/* {text} */'

    def write(self, ofile: T.TextIO, indent_level: int) -> None:
        ofile.write(f'\n{self.text}\n')

class PbxDictItem:
    def __init__(self, key: str, value: T.Union[PbxArray, PbxDict, str, int], comment: str = ''):
        self.key = key
        self.value = value
        if comment:
            if '/*' in comment:
                self.comment = comment
            else:
                self.comment = f'/* {comment} */'
        else:
            self.comment = comment

class PbxDict:
    def __init__(self) -> None:
        # This class is a bit weird, because we want to write PBX dicts in
        # defined order _and_ we want to write intermediate comments also in order.
        self.keys: T.Set[str] = set()
        self.items: T.List[T.Union[PbxDictItem, PbxComment]] = []

    def add_item(self, key: str, value: T.Union[PbxArray, PbxDict, str, int], comment: str = '') -> None:
        assert key not in self.keys
        item = PbxDictItem(key, value, comment)
        self.keys.add(key)
        self.items.append(item)

    def has_item(self, key: str) -> bool:
        return key in self.keys

    def add_comment(self, comment: PbxComment) -> None:
        assert isinstance(comment, PbxComment)
        self.items.append(comment)

    def write(self, ofile: T.TextIO, indent_level: int) -> None:
        ofile.write('{\n')
        indent_level += 1
        for i in self.items:
            if isinstance(i, PbxComment):
                i.write(ofile, indent_level)
            elif isinstance(i, PbxDictItem):
                if isinstance(i.value, (str, int)):
                    if i.comment:
                        ofile.write(indent_level*INDENT + f'{i.key} = {i.value} {i.comment};\n')
                    else:
                        ofile.write(indent_level*INDENT + f'{i.key} = {i.value};\n')
                elif isinstance(i.value, PbxDict):
                    if i.comment:
                        ofile.write(indent_level*INDENT + f'{i.key} {i.comment} = ')
                    else:
                        ofile.write(indent_level*INDENT + f'{i.key} = ')
                    i.value.write(ofile, indent_level)
                elif isinstance(i.value, PbxArray):
                    if i.comment:
                        ofile.write(indent_level*INDENT + f'{i.key} {i.comment} = ')
                    else:
                        ofile.write(indent_level*INDENT + f'{i.key} = ')
                    i.value.write(ofile, indent_level)
                else:
                    print(i)
                    print(i.key)
                    print(i.value)
                    raise RuntimeError('missing code')
            else:
                print(i)
                raise RuntimeError('missing code2')

        indent_level -= 1
        ofile.write(indent_level*INDENT + '}')
        if indent_level == 0:
            ofile.write('\n')
        else:
            ofile.write(';\n')

class XCodeBackend(backends.Backend):

    name = 'xcode'

    def __init__(self, build: T.Optional[build.Build], interpreter: T.Optional[Interpreter]):
        super().__init__(build, interpreter)
        self.project_uid = self.environment.coredata.lang_guids['default'].replace('-', '')[:24]
        self.buildtype = T.cast('str', self.environment.coredata.get_option(OptionKey('buildtype')))
        self.project_conflist = self.gen_id()
        self.maingroup_id = self.gen_id()
        self.all_id = self.gen_id()
        self.all_buildconf_id = self.gen_id()
        self.buildtypes = [self.buildtype]
        self.test_id = self.gen_id()
        self.test_command_id = self.gen_id()
        self.test_buildconf_id = self.gen_id()
        self.regen_id = self.gen_id()
        self.regen_command_id = self.gen_id()
        self.regen_buildconf_id = self.gen_id()
        self.regen_dependency_id = self.gen_id()
        self.top_level_dict = PbxDict()
        self.generator_outputs = {}
        self.arch = self.build.environment.machines.host.cpu
        if self.arch == 'aarch64':
            self.arch = 'arm64'
        # In Xcode files are not accessed via their file names, but rather every one of them
        # gets an unique id. More precisely they get one unique id per target they are used
        # in. If you generate only one id per file and use them, compilation will work but the
        # UI will only show the file in one target but not the others. Thus they key is
        # a tuple containing the target and filename.
        self.buildfile_ids = {}
        # That is not enough, though. Each target/file combination also gets a unique id
        # in the file reference section. Because why not. This means that a source file
        # that is used in two targets gets a total of four unique ID numbers.
        self.fileref_ids = {}

    def write_pbxfile(self, top_level_dict, ofilename) -> None:
        tmpname = ofilename + '.tmp'
        with open(tmpname, 'w', encoding='utf-8') as ofile:
            ofile.write('// !$*UTF8*$!\n')
            top_level_dict.write(ofile, 0)
        os.replace(tmpname, ofilename)

    def gen_id(self) -> str:
        return str(uuid.uuid4()).upper().replace('-', '')[:24]

    @functools.lru_cache(maxsize=None)
    def get_target_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        dirname = os.path.join(target.get_source_subdir(), T.cast('str', self.environment.coredata.get_option(OptionKey('buildtype'))))
        #os.makedirs(os.path.join(self.environment.get_build_dir(), dirname), exist_ok=True)
        return dirname

    def get_custom_target_output_dir(self, target: T.Union[build.Target, build.CustomTargetIndex]) -> str:
        dirname = target.get_output_subdir()
        os.makedirs(os.path.join(self.environment.get_build_dir(), dirname), exist_ok=True)
        return dirname

    def object_filename_from_source(self, target: build.BuildTarget, source: mesonlib.FileOrString, targetdir: T.Optional[str] = None) -> str:
        # Xcode has the following naming scheme:
        # projectname.build/debug/prog@exe.build/Objects-normal/x86_64/func.o
        project = self.build.project_name
        buildtype = self.buildtype
        tname = target.get_id()
        if isinstance(source, mesonlib.File):
            source = source.fname
        stem = os.path.splitext(os.path.basename(source))[0]
        # Append "build" before the actual object path to match OBJROOT
        obj_path = f'build/{project}.build/{buildtype}/{tname}.build/Objects-normal/{self.arch}/{stem}.o'
        return obj_path

    def determine_swift_dep_dirs(self, target: build.BuildTarget) -> T.List[str]:
        result: T.List[str] = []
        for l in target.link_targets:
            # Xcode does not recognize our private directories, so we have to use its build directories instead.
            result.append(os.path.join(self.environment.get_build_dir(), self.get_target_dir(l)))
        return result

    def generate(self, capture: bool = False, vslite_ctx: dict = None) -> None:
        # Check for (currently) unexpected capture arg use cases -
        if capture:
            raise MesonBugException('We do not expect the xcode backend to generate with \'capture = True\'')
        if vslite_ctx:
            raise MesonBugException('We do not expect the xcode backend to be given a valid \'vslite_ctx\'')
        self.serialize_tests()
        # Cache the result as the method rebuilds the array every time it is called.
        self.build_targets = self.build.get_build_targets()
        self.custom_targets = self.build.get_custom_targets()
        self.generate_filemap()
        self.generate_buildstylemap()
        self.generate_build_phase_map()
        self.generate_build_configuration_map()
        self.generate_build_configurationlist_map()
        self.generate_project_configurations_map()
        self.generate_buildall_configurations_map()
        self.generate_test_configurations_map()
        self.generate_native_target_map()
        self.generate_native_frameworks_map()
        self.generate_custom_target_map()
        self.generate_generator_target_map()
        self.generate_source_phase_map()
        self.generate_target_dependency_map()
        self.generate_pbxdep_map()
        self.generate_containerproxy_map()
        self.generate_target_file_maps()
        self.generate_build_file_maps()
        self.proj_dir = os.path.join(self.environment.get_build_dir(), self.build.project_name + '.xcodeproj')
        os.makedirs(self.proj_dir, exist_ok=True)
        self.proj_file = os.path.join(self.proj_dir, 'project.pbxproj')
        objects_dict = self.generate_prefix(self.top_level_dict)
        objects_dict.add_comment(PbxComment('Begin PBXAggregateTarget section'))
        self.generate_pbx_aggregate_target(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXAggregateTarget section'))
        objects_dict.add_comment(PbxComment('Begin PBXBuildFile section'))
        self.generate_pbx_build_file(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXBuildFile section'))
        objects_dict.add_comment(PbxComment('Begin PBXBuildStyle section'))
        self.generate_pbx_build_style(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXBuildStyle section'))
        objects_dict.add_comment(PbxComment('Begin PBXContainerItemProxy section'))
        self.generate_pbx_container_item_proxy(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXContainerItemProxy section'))
        objects_dict.add_comment(PbxComment('Begin PBXFileReference section'))
        self.generate_pbx_file_reference(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXFileReference section'))
        objects_dict.add_comment(PbxComment('Begin PBXFrameworksBuildPhase section'))
        self.generate_pbx_frameworks_buildphase(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXFrameworksBuildPhase section'))
        objects_dict.add_comment(PbxComment('Begin PBXGroup section'))
        self.generate_pbx_group(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXGroup section'))
        objects_dict.add_comment(PbxComment('Begin PBXNativeTarget section'))
        self.generate_pbx_native_target(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXNativeTarget section'))
        objects_dict.add_comment(PbxComment('Begin PBXProject section'))
        self.generate_pbx_project(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXProject section'))
        objects_dict.add_comment(PbxComment('Begin PBXShellScriptBuildPhase section'))
        self.generate_pbx_shell_build_phase(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXShellScriptBuildPhase section'))
        objects_dict.add_comment(PbxComment('Begin PBXSourcesBuildPhase section'))
        self.generate_pbx_sources_build_phase(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXSourcesBuildPhase section'))
        objects_dict.add_comment(PbxComment('Begin PBXTargetDependency section'))
        self.generate_pbx_target_dependency(objects_dict)
        objects_dict.add_comment(PbxComment('End PBXTargetDependency section'))
        objects_dict.add_comment(PbxComment('Begin XCBuildConfiguration section'))
        self.generate_xc_build_configuration(objects_dict)
        objects_dict.add_comment(PbxComment('End XCBuildConfiguration section'))
        objects_dict.add_comment(PbxComment('Begin XCConfigurationList section'))
        self.generate_xc_configurationList(objects_dict)
        objects_dict.add_comment(PbxComment('End XCConfigurationList section'))
        self.generate_suffix(self.top_level_dict)
        self.write_pbxfile(self.top_level_dict, self.proj_file)
        self.generate_regen_info()

    def get_xcodetype(self, fname: str) -> str:
        extension = fname.split('.')[-1]
        if extension == 'C':
            extension = 'cpp'
        xcodetype = XCODETYPEMAP.get(extension.lower())
        if not xcodetype:
            xcodetype = 'sourcecode.unknown'
        return xcodetype

    def generate_filemap(self) -> None:
        self.filemap = {} # Key is source file relative to src root.
        self.target_filemap = {}
        for name, t in self.build_targets.items():
            for s in t.sources:
                if isinstance(s, mesonlib.File):
                    s = os.path.join(s.subdir, s.fname)
                    self.filemap[s] = self.gen_id()
            for o in t.objects:
                if isinstance(o, str):
                    o = os.path.join(t.subdir, o)
                    self.filemap[o] = self.gen_id()
            for e in t.extra_files:
                if isinstance(e, mesonlib.File):
                    e = os.path.join(e.subdir, e.fname)
                    self.filemap[e] = self.gen_id()
                else:
                    e = os.path.join(t.subdir, e)
                    self.filemap[e] = self.gen_id()
            self.target_filemap[name] = self.gen_id()

    def generate_buildstylemap(self) -> None:
        self.buildstylemap = {self.buildtype: self.gen_id()}

    def generate_build_phase_map(self) -> None:
        for tname, t in self.build_targets.items():
            # generate id for our own target-name
            t.buildphasemap = {}
            t.buildphasemap[tname] = self.gen_id()
            # each target can have it's own Frameworks/Sources/..., generate id's for those
            t.buildphasemap['Frameworks'] = self.gen_id()
            t.buildphasemap['Resources'] = self.gen_id()
            t.buildphasemap['Sources'] = self.gen_id()

    def generate_build_configuration_map(self) -> None:
        self.buildconfmap = {}
        for t in self.build_targets:
            bconfs = {self.buildtype: self.gen_id()}
            self.buildconfmap[t] = bconfs
        for t in self.custom_targets:
            bconfs = {self.buildtype: self.gen_id()}
            self.buildconfmap[t] = bconfs

    def generate_project_configurations_map(self) -> None:
        self.project_configurations = {self.buildtype: self.gen_id()}

    def generate_buildall_configurations_map(self) -> None:
        self.buildall_configurations = {self.buildtype: self.gen_id()}

    def generate_test_configurations_map(self) -> None:
        self.test_configurations = {self.buildtype: self.gen_id()}

    def generate_build_configurationlist_map(self) -> None:
        self.buildconflistmap = {}
        for t in self.build_targets:
            self.buildconflistmap[t] = self.gen_id()
        for t in self.custom_targets:
            self.buildconflistmap[t] = self.gen_id()

    def generate_native_target_map(self) -> None:
        self.native_targets = {}
        for t in self.build_targets:
            self.native_targets[t] = self.gen_id()

    def generate_custom_target_map(self) -> None:
        self.shell_targets = {}
        self.custom_target_output_buildfile = {}
        self.custom_target_output_fileref = {}
        for tname, t in self.custom_targets.items():
            self.shell_targets[tname] = self.gen_id()
            if not isinstance(t, build.CustomTarget):
                continue
            (srcs, ofilenames, cmd) = self.eval_custom_target_command(t)
            for o in ofilenames:
                self.custom_target_output_buildfile[o] = self.gen_id()
                self.custom_target_output_fileref[o] = self.gen_id()

    def generate_generator_target_map(self) -> None:
        # Generator objects do not have natural unique ids
        # so use a counter.
        self.generator_fileref_ids = {}
        self.generator_buildfile_ids = {}
        for tname, t in self.build_targets.items():
            generator_id = 0
            for genlist in t.generated:
                if not isinstance(genlist, build.GeneratedList):
                    continue
                self.gen_single_target_map(genlist, tname, t, generator_id)
                generator_id += 1
        # FIXME add outputs.
        for tname, t in self.custom_targets.items():
            generator_id = 0
            for genlist in t.sources:
                if not isinstance(genlist, build.GeneratedList):
                    continue
                self.gen_single_target_map(genlist, tname, t, generator_id)
                generator_id += 1

    def gen_single_target_map(self, genlist, tname, t, generator_id) -> None:
        k = (tname, generator_id)
        assert k not in self.shell_targets
        self.shell_targets[k] = self.gen_id()
        ofile_abs = []
        for i in genlist.get_inputs():
            for o_base in genlist.get_outputs_for(i):
                o = os.path.join(self.get_target_private_dir(t), o_base)
                ofile_abs.append(os.path.join(self.environment.get_build_dir(), o))
        assert k not in self.generator_outputs
        self.generator_outputs[k] = ofile_abs
        buildfile_ids = []
        fileref_ids = []
        for i in range(len(ofile_abs)):
            buildfile_ids.append(self.gen_id())
            fileref_ids.append(self.gen_id())
        self.generator_buildfile_ids[k] = buildfile_ids
        self.generator_fileref_ids[k] = fileref_ids

    def generate_native_frameworks_map(self) -> None:
        self.native_frameworks = {}
        self.native_frameworks_fileref = {}
        for t in self.build_targets.values():
            for dep in t.get_external_deps():
                if dep.name == 'appleframeworks':
                    for f in dep.frameworks:
                        self.native_frameworks[f] = self.gen_id()
                        self.native_frameworks_fileref[f] = self.gen_id()

    def generate_target_dependency_map(self) -> None:
        self.target_dependency_map = {}
        for tname, t in self.build_targets.items():
            for target in t.link_targets:
                if isinstance(target, build.CustomTargetIndex):
                    k = (tname, target.target.get_basename())
                    if k in self.target_dependency_map:
                        continue
                else:
                    k = (tname, target.get_basename())
                    assert k not in self.target_dependency_map
                self.target_dependency_map[k] = self.gen_id()
        for tname, t in self.custom_targets.items():
            k = tname
            assert k not in self.target_dependency_map
            self.target_dependency_map[k] = self.gen_id()

    def generate_pbxdep_map(self) -> None:
        self.pbx_dep_map = {}
        self.pbx_custom_dep_map = {}
        for t in self.build_targets:
            self.pbx_dep_map[t] = self.gen_id()
        for t in self.custom_targets:
            self.pbx_custom_dep_map[t] = self.gen_id()

    def generate_containerproxy_map(self) -> None:
        self.containerproxy_map = {}
        for t in self.build_targets:
            self.containerproxy_map[t] = self.gen_id()

    def generate_target_file_maps(self) -> None:
        self.generate_target_file_maps_impl(self.build_targets)
        self.generate_target_file_maps_impl(self.custom_targets)

    def generate_target_file_maps_impl(self, targets) -> None:
        for tname, t in targets.items():
            for s in t.sources:
                if isinstance(s, mesonlib.File):
                    s = os.path.join(s.subdir, s.fname)
                if not isinstance(s, str):
                    continue
                k = (tname, s)
                assert k not in self.buildfile_ids
                self.buildfile_ids[k] = self.gen_id()
                assert k not in self.fileref_ids
                self.fileref_ids[k] = self.gen_id()
            if not hasattr(t, 'objects'):
                continue
            for o in t.objects:
                if isinstance(o, build.ExtractedObjects):
                    # Extracted objects do not live in "the Xcode world".
                    continue
                if isinstance(o, mesonlib.File):
                    o = os.path.join(o.subdir, o.fname)
                if isinstance(o, str):
                    o = os.path.join(t.subdir, o)
                    k = (tname, o)
                    assert k not in self.buildfile_ids
                    self.buildfile_ids[k] = self.gen_id()
                    assert k not in self.fileref_ids
                    self.fileref_ids[k] = self.gen_id()
                else:
                    raise RuntimeError('Unknown input type ' + str(o))
            for e in t.extra_files:
                if isinstance(e, mesonlib.File):
                    e = os.path.join(e.subdir, e.fname)
                if isinstance(e, str):
                    e = os.path.join(t.subdir, e)
                    k = (tname, e)
                    assert k not in self.buildfile_ids
                    self.buildfile_ids[k] = self.gen_id()
                    assert k not in self.fileref_ids
                    self.fileref_ids[k] = self.gen_id()

    def generate_build_file_maps(self) -> None:
        for buildfile in self.interpreter.get_build_def_files():
            assert isinstance(buildfile, str)
            self.buildfile_ids[buildfile] = self.gen_id()
            self.fileref_ids[buildfile] = self.gen_id()

    def generate_source_phase_map(self) -> None:
        self.source_phase = {}
        for t in self.build_targets:
            self.source_phase[t] = self.gen_id()

    def generate_pbx_aggregate_target(self, objects_dict: PbxDict) -> None:
        self.custom_aggregate_targets = {}
        self.build_all_tdep_id = self.gen_id()
        target_dependencies = []
        custom_target_dependencies = []
        for tname, t in self.get_build_by_default_targets().items():
            if isinstance(t, build.CustomTarget):
                custom_target_dependencies.append(self.pbx_custom_dep_map[t.get_id()])
            elif isinstance(t, build.BuildTarget):
                target_dependencies.append(self.pbx_dep_map[t.get_id()])
        aggregated_targets = []
        aggregated_targets.append((self.all_id, 'ALL_BUILD',
                                   self.all_buildconf_id,
                                   [],
                                   [self.regen_dependency_id] + target_dependencies + custom_target_dependencies))
        aggregated_targets.append((self.test_id,
                                   'RUN_TESTS',
                                   self.test_buildconf_id,
                                   [self.test_command_id],
                                   [self.regen_dependency_id, self.build_all_tdep_id]))
        aggregated_targets.append((self.regen_id,
                                   'REGENERATE',
                                   self.regen_buildconf_id,
                                   [self.regen_command_id],
                                   []))
        for tname, t in self.build.get_custom_targets().items():
            ct_id = self.gen_id()
            self.custom_aggregate_targets[tname] = ct_id
            build_phases = []
            dependencies = [self.regen_dependency_id]
            generator_id = 0
            for d in t.dependencies:
                if isinstance(d, build.CustomTarget):
                    dependencies.append(self.pbx_custom_dep_map[d.get_id()])
                elif isinstance(d, build.BuildTarget):
                    dependencies.append(self.pbx_dep_map[d.get_id()])
            for s in t.sources:
                if isinstance(s, build.GeneratedList):
                    build_phases.append(self.shell_targets[(tname, generator_id)])
                    for d in s.depends:
                        dependencies.append(self.pbx_custom_dep_map[d.get_id()])
                    generator_id += 1
                elif isinstance(s, build.ExtractedObjects):
                    source_target_id = self.pbx_dep_map[s.target.get_id()]
                    if source_target_id not in dependencies:
                        dependencies.append(source_target_id)
            build_phases.append(self.shell_targets[tname])
            aggregated_targets.append((ct_id, tname, self.buildconflistmap[tname], build_phases, dependencies))

        # Sort objects by ID before writing
        sorted_aggregated_targets = sorted(aggregated_targets, key=operator.itemgetter(0))
        for t in sorted_aggregated_targets:
            agt_dict = PbxDict()
            name = t[1]
            buildconf_id = t[2]
            build_phases = t[3]
            dependencies = t[4]
            agt_dict.add_item('isa', 'PBXAggregateTarget')
            agt_dict.add_item('buildConfigurationList', buildconf_id, f'Build configuration list for PBXAggregateTarget "{name}"')
            bp_arr = PbxArray()
            agt_dict.add_item('buildPhases', bp_arr)
            for bp in build_phases:
                bp_arr.add_item(bp, 'ShellScript')
            dep_arr = PbxArray()
            agt_dict.add_item('dependencies', dep_arr)
            for td in dependencies:
                dep_arr.add_item(td, 'PBXTargetDependency')
            agt_dict.add_item('name', f'"{name}"')
            agt_dict.add_item('productName', f'"{name}"')
            objects_dict.add_item(t[0], agt_dict, name)

    def generate_pbx_build_file(self, objects_dict: PbxDict) -> None:
        for tname, t in self.build_targets.items():
            for dep in t.get_external_deps():
                if dep.name == 'appleframeworks':
                    for f in dep.frameworks:
                        fw_dict = PbxDict()
                        fwkey = self.native_frameworks[f]
                        if fwkey not in objects_dict.keys:
                            objects_dict.add_item(fwkey, fw_dict, f'{f}.framework in Frameworks')
                        fw_dict.add_item('isa', 'PBXBuildFile')
                        fw_dict.add_item('fileRef', self.native_frameworks_fileref[f], f)

            for s in t.sources:
                in_build_dir = False
                if isinstance(s, mesonlib.File):
                    if s.is_built:
                        in_build_dir = True
                    s = os.path.join(s.subdir, s.fname)

                if not isinstance(s, str):
                    continue
                sdict = PbxDict()
                k = (tname, s)
                idval = self.buildfile_ids[k]
                fileref = self.fileref_ids[k]
                if in_build_dir:
                    fullpath = os.path.join(self.environment.get_build_dir(), s)
                else:
                    fullpath = os.path.join(self.environment.get_source_dir(), s)
                sdict.add_item('isa', 'PBXBuildFile')
                sdict.add_item('fileRef', fileref, fullpath)
                objects_dict.add_item(idval, sdict)

            for o in t.objects:
                if isinstance(o, build.ExtractedObjects):
                    # Object files are not source files as such. We add them
                    # by hand in linker flags. It is also not particularly
                    # clear how to define build files in Xcode's file format.
                    continue
                if isinstance(o, mesonlib.File):
                    o = os.path.join(o.subdir, o.fname)
                elif isinstance(o, str):
                    o = os.path.join(t.subdir, o)
                idval = self.buildfile_ids[(tname, o)]
                k = (tname, o)
                fileref = self.fileref_ids[k]
                assert o not in self.filemap
                self.filemap[o] = idval
                fullpath = os.path.join(self.environment.get_source_dir(), o)
                fullpath2 = fullpath
                o_dict = PbxDict()
                objects_dict.add_item(idval, o_dict, fullpath)
                o_dict.add_item('isa', 'PBXBuildFile')
                o_dict.add_item('fileRef', fileref, fullpath2)

            generator_id = 0
            for g in t.generated:
                if not isinstance(g, build.GeneratedList):
                    continue
                self.create_generator_shellphase(objects_dict, tname, generator_id)
                generator_id += 1

        # Custom targets are shell build phases in Xcode terminology.
        for tname, t in self.custom_targets.items():
            if not isinstance(t, build.CustomTarget):
                continue
            (srcs, ofilenames, cmd) = self.eval_custom_target_command(t)
            for o in ofilenames:
                custom_dict = PbxDict()
                objects_dict.add_item(self.custom_target_output_buildfile[o], custom_dict, f'/* {o} */')
                custom_dict.add_item('isa', 'PBXBuildFile')
                custom_dict.add_item('fileRef', self.custom_target_output_fileref[o])
            generator_id = 0
            for g in t.sources:
                if not isinstance(g, build.GeneratedList):
                    continue
                self.create_generator_shellphase(objects_dict, tname, generator_id)
                generator_id += 1

    def create_generator_shellphase(self, objects_dict, tname, generator_id) -> None:
        file_ids = self.generator_buildfile_ids[(tname, generator_id)]
        ref_ids = self.generator_fileref_ids[(tname, generator_id)]
        assert len(ref_ids) == len(file_ids)
        for file_o, ref_id in zip(file_ids, ref_ids):
            odict = PbxDict()
            objects_dict.add_item(file_o, odict)
            odict.add_item('isa', 'PBXBuildFile')
            odict.add_item('fileRef', ref_id)

    def generate_pbx_build_style(self, objects_dict: PbxDict) -> None:
        # FIXME: Xcode 9 and later does not uses PBXBuildStyle and it
```