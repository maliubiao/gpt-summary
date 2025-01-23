Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:** The request asks for the *functionality* of the script, its relation to reverse engineering, low-level details, logical reasoning, common errors, and how a user might reach this script. This requires a multi-faceted approach.

**2. Initial Code Scan and Keyword Spotting:**  The first step is to read through the code, looking for keywords and structure. I'm looking for:

* **Imports:** `os`, `json`, `re`, `sys`, `shutil`, `pathlib`, `argparse`. These suggest file system interaction, JSON parsing, regular expressions, system calls, and command-line argument parsing.
* **Function Definitions:** This is where the main logic resides. I note functions like `array_arg`, `validate_builddir`, `parse_introspect_data`, `ParsedTargetName`, `get_target_from_intro_data`, `generate_target_names_ninja`, `get_parsed_args_ninja`, `generate_target_name_vs`, `get_parsed_args_vs`, `get_parsed_args_xcode`, `add_arguments`, and `run`.
* **Key Data Structures:** `defaultdict`, `Path`, `List`, `Dict`.
* **Error Handling:** `MesonException` is frequently used.
* **Logging:**  `mlog` is used for informational and warning messages.
* **External Processes:** Calls to `detect_ninja`, `msbuild`, `xcodebuild`.
* **Conditional Logic:** `if/elif/else` blocks for handling different build backends.

**3. Deconstructing the Functionality - Function by Function:**  Now I examine each function more closely:

* **`array_arg`:**  Simple: converts a string to a list of strings, likely for handling command-line arguments that accept multiple values.
* **`validate_builddir`:** Checks if the provided directory looks like a valid Meson build directory by looking for `coredata.dat`. This is crucial for ensuring the script is run in the correct context.
* **`parse_introspect_data`:** Reads and parses `intro-targets.json`. This file likely contains information about build targets, which is key for understanding how the script identifies what to build. The use of `defaultdict` is interesting – it suggests multiple targets can have the same name.
* **`ParsedTargetName`:**  Parses a target string (e.g., `my_lib:shared_library`). It extracts the name, type, and path. The static method `_is_valid_type` defines the recognized target types.
* **`get_target_from_intro_data`:**  The core of target resolution. It tries to find a matching target in the introspected data based on the parsed target name. It handles cases where the full name, base name, type, and path are specified. The logic to handle ambiguous names and provide suggestions is important.
* **`generate_target_names_ninja`:**  Takes a parsed target name and the introspected data and generates the corresponding Ninja build targets (usually output file paths).
* **`get_parsed_args_ninja`:**  Constructs the command-line arguments for the Ninja build tool based on the user's options. It handles job count, load average, verbosity, specific targets, and the `clean` command.
* **`generate_target_name_vs`:** Similar to `generate_target_names_ninja` but for Visual Studio's MSBuild. It normalizes target names for MSBuild.
* **`get_parsed_args_vs`:** Constructs the command-line arguments for MSBuild, including handling solution files (`.sln`), specific targets, cleaning, job count, and verbosity. It also handles a special case for "run" targets on the VS backend.
* **`get_parsed_args_xcode`:** Constructs command-line arguments for Xcode's `xcodebuild`.
* **`add_arguments`:** Uses `argparse` to define the command-line options for the script.
* **`run`:** The main function. It validates the build directory, loads build data, detects the build backend (Ninja, VS, Xcode), calls the appropriate function to generate the backend-specific command, and then executes that command. It also handles environment setup for Visual Studio.

**4. Connecting to the Request's Specific Points:**

* **Functionality:**  Summarize the purpose of each function and the overall goal of the script (to provide a backend-agnostic way to compile Meson projects).
* **Reverse Engineering:** Look for points where understanding the *output* of a build process or the *structure* of compiled artifacts is relevant. The parsing of `intro-targets.json` and the target name resolution are key here. The handling of different target types (executable, library, etc.) is also relevant.
* **Binary/Low-Level, Linux, Android Kernel/Framework:**  Consider if the script *directly* interacts with these. In this case, it primarily *orchestrates* build tools that do. However, the *concepts* of executables, shared libraries, and the differences between build systems (Ninja, MSBuild, Xcode) are related to how code is compiled and linked at a lower level. Frida's use case of dynamic instrumentation would involve these concepts.
* **Logical Reasoning:**  Focus on the decision-making processes in the code. The target name resolution, the selection of the correct backend command, and the handling of different options are examples of logical reasoning. Constructing a simple input and predicting the output demonstrates this.
* **User/Programming Errors:** Identify common mistakes users might make when using the script (invalid build directory, incorrect target names, conflicting options).
* **User Operation to Reach Here:** Trace back the steps a user would take in a typical Frida development workflow to end up using this script. This involves the Meson build system.

**5. Structuring the Answer:** Organize the findings into clear sections, addressing each point of the request systematically. Use clear and concise language. Provide concrete examples where possible.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the script directly compiles code.
* **Correction:**  Realize it's a *meta-build system* tool – it invokes other build systems.
* **Initial thought:** The low-level aspects are minimal.
* **Refinement:** Acknowledge that while this script doesn't directly manipulate binaries, the *concepts* it deals with (executables, libraries) are fundamental to low-level programming. Also, the *purpose* of Frida (dynamic instrumentation) directly involves interacting with running processes at a lower level.
* **Consider adding diagrams or more detailed examples:**  Decide that clear, concise explanations with focused examples are sufficient for this request.

By following this systematic approach, I can thoroughly analyze the script and provide a comprehensive answer that addresses all aspects of the prompt.
这个 `mcompile.py` 文件是 Frida 动态 instrumentation 工具中，用于构建项目的入口脚本，它提供了一个与具体构建系统（如 Ninja, Visual Studio, Xcode）无关的编译接口。其核心功能是解析用户指定的构建目标，并将其转换为底层构建系统能够理解的命令。

以下是它的具体功能及其与你提出的几个方面的关系：

**1. 功能列表:**

* **解析命令行参数:** 使用 `argparse` 模块解析用户在命令行中提供的参数，例如要构建的目标、是否清理、并行任务数等。
* **验证构建目录:** 检查当前工作目录或用户指定的目录是否是一个有效的 Meson 构建目录。
* **读取构建信息:** 从 Meson 生成的 `meson-info/intro-targets.json` 文件中读取关于构建目标的信息，例如目标名称、类型、输出文件路径等。
* **解析目标名称:** 将用户提供的目标名称字符串（例如 `frida-agent/agent.so:shared_library`）解析成结构化的信息，包括路径、名称、后缀和类型。
* **查找目标信息:** 根据解析后的目标名称，在读取的构建信息中查找匹配的目标。
* **生成底层构建命令:** 根据当前使用的构建后端（Ninja, Visual Studio, Xcode），将抽象的目标信息转换为特定构建工具的命令行参数。
* **执行底层构建命令:** 使用 `subprocess` 模块执行生成的构建命令。
* **处理构建环境:** 对于 Visual Studio 构建，它能够自动激活 MSVC 编译器环境。
* **提供统一的编译接口:** 允许用户使用一致的命令来构建项目，而无需关心底层使用的是哪个构建系统。

**2. 与逆向方法的联系 (举例说明):**

该脚本本身不是直接进行逆向操作的工具，但它是构建 Frida 组件的重要一环，而 Frida 本身是一个强大的逆向工程和动态分析工具。

* **构建 Frida Agent:**  用户可能会使用 `mcompile.py` 来构建 Frida Agent (通常是共享库或动态链接库)，这个 Agent 会被注入到目标进程中进行代码分析和修改。 例如，用户可能会执行类似 `python mcompile.py frida-agent/agent.so:shared_library` 的命令来构建 Agent。这个 Agent 构建完成后，就可以使用 Frida 的 API 将其加载到目标进程中，进行 hook、跟踪等逆向分析操作。
* **构建测试用例:**  在开发 Frida 组件时，通常会编写测试用例。`mcompile.py` 可以用于构建这些测试用例，以便验证 Frida 组件的功能是否正常。这些测试用例可能涉及到对目标二进制代码的行为进行断言和检查，这与逆向分析中的行为分析密切相关。

**3. 涉及到二进制底层, Linux, Android内核及框架的知识 (举例说明):**

虽然脚本本身是用 Python 编写的，但它所构建的目标 (Frida 组件) 往往涉及到二进制底层知识，并且在特定的操作系统和平台上运行。

* **共享库/动态链接库 (.so):**  在 Linux 和 Android 上，Frida Agent 通常被构建成共享库 (`.so`) 文件。`mcompile.py` 需要理解如何构建这种类型的二进制文件，这涉及到链接器、符号表、动态链接等底层知识。
* **可执行文件:**  如果构建的是 Frida 的命令行工具或测试程序，那么最终会生成可执行文件。构建过程需要处理程序的入口点、内存布局等二进制层面的细节。
* **Android Framework:**  Frida 经常被用于 Android 平台的逆向分析。`mcompile.py` 可能需要根据 Android 的构建规则来处理编译过程，例如使用 Android NDK 进行编译，处理不同的架构 (ARM, ARM64, x86)，以及链接到 Android 的系统库。
* **内核交互 (间接):**  Frida 最终会在目标进程中运行，并可能与操作系统内核进行交互（例如进行系统调用 hook）。虽然 `mcompile.py` 不直接涉及内核编程，但它构建的 Frida 组件的功能会涉及到内核层面的知识。

**4. 逻辑推理 (假设输入与输出):**

假设用户在 Frida 的构建目录下执行以下命令：

```bash
python subprojects/frida-clr/releng/meson/mesonbuild/mcompile.py frida-core
```

**假设输入:**

* 当前工作目录是 Frida 的构建目录。
* `frida-core` 是一个在 `meson.build` 文件中定义的目标名称，可能是一个静态库或共享库。
* 当前构建后端是 Ninja。

**逻辑推理过程:**

1. **解析参数:** `mcompile.py` 解析到目标 `frida-core`。
2. **验证构建目录:** 脚本会检查构建目录下是否存在 `meson-private/coredata.dat` 文件，确认是有效的 Meson 构建目录。
3. **读取构建信息:**  脚本读取 `meson-info/intro-targets.json` 文件，查找名为 `frida-core` 的目标信息。
4. **解析目标名称:**  目标名称 `frida-core` 被解析。
5. **查找目标信息:**  在 `intro-targets.json` 中找到 `frida-core` 的相关信息，包括其类型（例如 `static_library`）和输出文件路径（例如 `libfrida-core.a`）。
6. **生成 Ninja 命令:** 根据 Ninja 后端，生成类似以下的命令：
   ```bash
   ninja libfrida-core.a
   ```
7. **执行 Ninja 命令:**  脚本使用 `subprocess` 执行生成的 Ninja 命令。

**预期输出:**

* 终端会显示 Ninja 构建 `frida-core` 目标的输出信息，包括编译和链接过程。
* 在构建目录下会生成 `libfrida-core.a` 文件（如果目标类型是静态库）。

**5. 涉及用户或者编程常见的使用错误 (举例说明):**

* **在非构建目录下运行:** 用户可能在没有执行过 `meson` 配置的源代码目录下直接运行 `mcompile.py`，导致 `validate_builddir` 函数抛出异常，提示找不到 `coredata.dat` 文件。
* **指定不存在的目标:** 用户可能拼写错误目标名称，或者指定了一个在 `meson.build` 文件中没有定义的目标，导致 `get_target_from_intro_data` 函数找不到目标，抛出异常。 例如，执行 `python mcompile.py frida-cor` (少了个 `e`)。
* **同时使用 `--clean` 和指定目标:** 用户可能同时使用了 `--clean` 参数和指定了要构建的目标，这在逻辑上是冲突的，因为清理会删除构建产物。脚本会检查这种情况并抛出异常。
* **在 Visual Studio 环境下构建 `run` 类型的目标指定多个目标:**  由于 MSBuild 的限制，当构建 `run` 类型的目标时，一次只能指定一个目标。如果用户尝试在 Visual Studio 环境下使用 `mcompile.py` 构建多个 `run` 类型的目标，会抛出异常。
* **权限问题:** 在某些情况下，用户可能没有执行底层构建工具（如 `ninja`, `msbuild`, `xcodebuild`) 的权限。

**6. 说明用户操作是如何一步步的到达这里，作为调试线索:**

当 Frida 的构建过程出现问题时，开发者可能会尝试手动运行 `mcompile.py` 来调试构建过程，或者查看其生成的底层构建命令。以下是用户可能到达这里的步骤：

1. **尝试构建 Frida:** 用户通常会先尝试使用顶层的构建命令，例如 `meson compile -C build` 或 `ninja -C build`。
2. **构建失败:** 如果构建过程中出现错误，例如编译错误、链接错误等，用户可能会查看构建日志以获取更多信息。
3. **分析构建日志:**  构建日志中可能会显示 `mcompile.py` 生成的底层构建命令，或者提示与特定目标的构建有关的错误。
4. **尝试手动运行 `mcompile.py`:**  为了更精细地控制构建过程或复现特定的构建错误，用户可能会尝试直接调用 `mcompile.py` 脚本，并传入特定的目标名称和选项。
5. **查看 `mcompile.py` 源码:**  如果用户想要了解 `mcompile.py` 的具体工作方式，例如目标是如何被解析和转换为底层构建命令的，他们可能会直接查看这个脚本的源代码，以获取更深入的理解。
6. **修改 `mcompile.py` (不推荐，除非是 Frida 开发者):** 在极少数情况下，如果用户认为 `mcompile.py` 存在 bug 或者需要进行定制，他们可能会尝试修改这个脚本。但这通常只适用于 Frida 的开发者或对 Meson 构建系统有深入了解的用户。

总而言之，`mcompile.py` 在 Frida 的构建系统中扮演着一个关键的桥梁角色，它将用户对构建目标的抽象描述转换为底层构建系统能够执行的具体命令，使得 Frida 的构建过程更加统一和易于管理。了解其功能和工作原理对于理解 Frida 的构建流程和进行问题排查非常有帮助。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/mcompile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright 2020 The Meson development team

from __future__ import annotations

"""Entrypoint script for backend agnostic compile."""

import os
import json
import re
import sys
import shutil
import typing as T
from collections import defaultdict
from pathlib import Path

from . import mlog
from . import mesonlib
from .mesonlib import MesonException, RealPathAction, join_args, listify_array_value, setup_vsenv
from mesonbuild.environment import detect_ninja
from mesonbuild import build

if T.TYPE_CHECKING:
    import argparse

def array_arg(value: str) -> T.List[str]:
    return listify_array_value(value)

def validate_builddir(builddir: Path) -> None:
    if not (builddir / 'meson-private' / 'coredata.dat').is_file():
        raise MesonException(f'Current directory is not a meson build directory: `{builddir}`.\n'
                             'Please specify a valid build dir or change the working directory to it.\n'
                             'It is also possible that the build directory was generated with an old\n'
                             'meson version. Please regenerate it in this case.')

def parse_introspect_data(builddir: Path) -> T.Dict[str, T.List[dict]]:
    """
    Converts a List of name-to-dict to a dict of name-to-dicts (since names are not unique)
    """
    path_to_intro = builddir / 'meson-info' / 'intro-targets.json'
    if not path_to_intro.exists():
        raise MesonException(f'`{path_to_intro.name}` is missing! Directory is not configured yet?')
    with path_to_intro.open(encoding='utf-8') as f:
        schema = json.load(f)

    parsed_data: T.Dict[str, T.List[dict]] = defaultdict(list)
    for target in schema:
        parsed_data[target['name']] += [target]
    return parsed_data

class ParsedTargetName:
    full_name = ''
    base_name = ''
    name = ''
    type = ''
    path = ''
    suffix = ''

    def __init__(self, target: str):
        self.full_name = target
        split = target.rsplit(':', 1)
        if len(split) > 1:
            self.type = split[1]
            if not self._is_valid_type(self.type):
                raise MesonException(f'Can\'t invoke target `{target}`: unknown target type: `{self.type}`')

        split = split[0].rsplit('/', 1)
        if len(split) > 1:
            self.path = split[0]
            self.name = split[1]
        else:
            self.name = split[0]

        split = self.name.rsplit('.', 1)
        if len(split) > 1:
            self.base_name = split[0]
            self.suffix = split[1]
        else:
            self.base_name = split[0]

    @staticmethod
    def _is_valid_type(type: str) -> bool:
        # Amend docs in Commands.md when editing this list
        allowed_types = {
            'executable',
            'static_library',
            'shared_library',
            'shared_module',
            'custom',
            'alias',
            'run',
            'jar',
        }
        return type in allowed_types

def get_target_from_intro_data(target: ParsedTargetName, builddir: Path, introspect_data: T.Dict[str, T.Any]) -> T.Dict[str, T.Any]:
    if target.name not in introspect_data and target.base_name not in introspect_data:
        raise MesonException(f'Can\'t invoke target `{target.full_name}`: target not found')

    intro_targets = introspect_data[target.name]
    # if target.name doesn't find anything, try just the base name
    if not intro_targets:
        intro_targets = introspect_data[target.base_name]
    found_targets: T.List[T.Dict[str, T.Any]] = []

    resolved_bdir = builddir.resolve()

    if not target.type and not target.path and not target.suffix:
        found_targets = intro_targets
    else:
        for intro_target in intro_targets:
            # Parse out the name from the id if needed
            intro_target_name = intro_target['name']
            split = intro_target['id'].rsplit('@', 1)
            if len(split) > 1:
                split = split[0].split('@@', 1)
                if len(split) > 1:
                    intro_target_name = split[1]
                else:
                    intro_target_name = split[0]
            if ((target.type and target.type != intro_target['type'].replace(' ', '_')) or
                (target.name != intro_target_name) or
                (target.path and intro_target['filename'] != 'no_name' and
                 Path(target.path) != Path(intro_target['filename'][0]).relative_to(resolved_bdir).parent)):
                continue
            found_targets += [intro_target]

    if not found_targets:
        raise MesonException(f'Can\'t invoke target `{target.full_name}`: target not found')
    elif len(found_targets) > 1:
        suggestions: T.List[str] = []
        for i in found_targets:
            i_name = i['name']
            split = i['id'].rsplit('@', 1)
            if len(split) > 1:
                split = split[0].split('@@', 1)
                if len(split) > 1:
                    i_name = split[1]
                else:
                    i_name = split[0]
            p = Path(i['filename'][0]).relative_to(resolved_bdir).parent / i_name
            t = i['type'].replace(' ', '_')
            suggestions.append(f'- ./{p}:{t}')
        suggestions_str = '\n'.join(suggestions)
        raise MesonException(f'Can\'t invoke target `{target.full_name}`: ambiguous name.'
                             f' Add target type and/or path:\n{suggestions_str}')

    return found_targets[0]

def generate_target_names_ninja(target: ParsedTargetName, builddir: Path, introspect_data: dict) -> T.List[str]:
    intro_target = get_target_from_intro_data(target, builddir, introspect_data)

    if intro_target['type'] in {'alias', 'run'}:
        return [target.name]
    else:
        return [str(Path(out_file).relative_to(builddir.resolve())) for out_file in intro_target['filename']]

def get_parsed_args_ninja(options: 'argparse.Namespace', builddir: Path) -> T.Tuple[T.List[str], T.Optional[T.Dict[str, str]]]:
    runner = detect_ninja()
    if runner is None:
        raise MesonException('Cannot find ninja.')

    cmd = runner
    if not builddir.samefile('.'):
        cmd.extend(['-C', builddir.as_posix()])

    # If the value is set to < 1 then don't set anything, which let's
    # ninja/samu decide what to do.
    if options.jobs > 0:
        cmd.extend(['-j', str(options.jobs)])
    if options.load_average > 0:
        cmd.extend(['-l', str(options.load_average)])

    if options.verbose:
        cmd.append('-v')

    cmd += options.ninja_args

    # operands must be processed after options/option-arguments
    if options.targets:
        intro_data = parse_introspect_data(builddir)
        for t in options.targets:
            cmd.extend(generate_target_names_ninja(ParsedTargetName(t), builddir, intro_data))
    if options.clean:
        cmd.append('clean')

    return cmd, None

def generate_target_name_vs(target: ParsedTargetName, builddir: Path, introspect_data: dict) -> str:
    intro_target = get_target_from_intro_data(target, builddir, introspect_data)

    assert intro_target['type'] not in {'alias', 'run'}, 'Should not reach here: `run` targets must be handle above'

    # Normalize project name
    # Source: https://docs.microsoft.com/en-us/visualstudio/msbuild/how-to-build-specific-targets-in-solutions-by-using-msbuild-exe
    target_name = re.sub(r"[\%\$\@\;\.\(\)']", '_', intro_target['id'])
    rel_path = Path(intro_target['filename'][0]).relative_to(builddir.resolve()).parent
    if rel_path != Path('.'):
        target_name = str(rel_path / target_name)
    return target_name

def get_parsed_args_vs(options: 'argparse.Namespace', builddir: Path) -> T.Tuple[T.List[str], T.Optional[T.Dict[str, str]]]:
    slns = list(builddir.glob('*.sln'))
    assert len(slns) == 1, 'More than one solution in a project?'
    sln = slns[0]

    cmd = ['msbuild']

    if options.targets:
        intro_data = parse_introspect_data(builddir)
        has_run_target = any(
            get_target_from_intro_data(ParsedTargetName(t), builddir, intro_data)['type'] in {'alias', 'run'}
            for t in options.targets)

        if has_run_target:
            # `run` target can't be used the same way as other targets on `vs` backend.
            # They are defined as disabled projects, which can't be invoked as `.sln`
            # target and have to be invoked directly as project instead.
            # Issue: https://github.com/microsoft/msbuild/issues/4772

            if len(options.targets) > 1:
                raise MesonException('Only one target may be specified when `run` target type is used on this backend.')
            intro_target = get_target_from_intro_data(ParsedTargetName(options.targets[0]), builddir, intro_data)
            proj_dir = Path(intro_target['filename'][0]).parent
            proj = proj_dir/'{}.vcxproj'.format(intro_target['id'])
            cmd += [str(proj.resolve())]
        else:
            cmd += [str(sln.resolve())]
            cmd.extend(['-target:{}'.format(generate_target_name_vs(ParsedTargetName(t), builddir, intro_data)) for t in options.targets])
    else:
        cmd += [str(sln.resolve())]

    if options.clean:
        cmd.extend(['-target:Clean'])

    # In msbuild `-maxCpuCount` with no number means "detect cpus", the default is `-maxCpuCount:1`
    if options.jobs > 0:
        cmd.append(f'-maxCpuCount:{options.jobs}')
    else:
        cmd.append('-maxCpuCount')

    if options.load_average:
        mlog.warning('Msbuild does not have a load-average switch, ignoring.')

    if not options.verbose:
        cmd.append('-verbosity:minimal')

    cmd += options.vs_args

    # Remove platform from env if set so that msbuild does not
    # pick x86 platform when solution platform is Win32
    env = os.environ.copy()
    env.pop('PLATFORM', None)

    return cmd, env

def get_parsed_args_xcode(options: 'argparse.Namespace', builddir: Path) -> T.Tuple[T.List[str], T.Optional[T.Dict[str, str]]]:
    runner = 'xcodebuild'
    if not shutil.which(runner):
        raise MesonException('Cannot find xcodebuild, did you install XCode?')

    # No argument to switch directory
    os.chdir(str(builddir))

    cmd = [runner, '-parallelizeTargets']

    if options.targets:
        for t in options.targets:
            cmd += ['-target', t]

    if options.clean:
        if options.targets:
            cmd += ['clean']
        else:
            cmd += ['-alltargets', 'clean']
        # Otherwise xcodebuild tries to delete the builddir and fails
        cmd += ['-UseNewBuildSystem=FALSE']

    if options.jobs > 0:
        cmd.extend(['-jobs', str(options.jobs)])

    if options.load_average > 0:
        mlog.warning('xcodebuild does not have a load-average switch, ignoring')

    if options.verbose:
        # xcodebuild is already quite verbose, and -quiet doesn't print any
        # status messages
        pass

    cmd += options.xcode_args
    return cmd, None

# Note: when adding arguments, please also add them to the completion
# scripts in $MESONSRC/data/shell-completions/
def add_arguments(parser: 'argparse.ArgumentParser') -> None:
    """Add compile specific arguments."""
    parser.add_argument(
        'targets',
        metavar='TARGET',
        nargs='*',
        default=None,
        help='Targets to build. Target has the following format: [PATH_TO_TARGET/]TARGET_NAME.TARGET_SUFFIX[:TARGET_TYPE].')
    parser.add_argument(
        '--clean',
        action='store_true',
        help='Clean the build directory.'
    )
    parser.add_argument('-C', dest='wd', action=RealPathAction,
                        help='directory to cd into before running')

    parser.add_argument(
        '-j', '--jobs',
        action='store',
        default=0,
        type=int,
        help='The number of worker jobs to run (if supported). If the value is less than 1 the build program will guess.'
    )
    parser.add_argument(
        '-l', '--load-average',
        action='store',
        default=0,
        type=float,
        help='The system load average to try to maintain (if supported).'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show more verbose output.'
    )
    parser.add_argument(
        '--ninja-args',
        type=array_arg,
        default=[],
        help='Arguments to pass to `ninja` (applied only on `ninja` backend).'
    )
    parser.add_argument(
        '--vs-args',
        type=array_arg,
        default=[],
        help='Arguments to pass to `msbuild` (applied only on `vs` backend).'
    )
    parser.add_argument(
        '--xcode-args',
        type=array_arg,
        default=[],
        help='Arguments to pass to `xcodebuild` (applied only on `xcode` backend).'
    )

def run(options: 'argparse.Namespace') -> int:
    bdir = Path(options.wd)
    validate_builddir(bdir)
    if options.targets and options.clean:
        raise MesonException('`TARGET` and `--clean` can\'t be used simultaneously')

    b = build.load(options.wd)
    cdata = b.environment.coredata
    need_vsenv = T.cast('bool', cdata.get_option(mesonlib.OptionKey('vsenv')))
    if setup_vsenv(need_vsenv):
        mlog.log(mlog.green('INFO:'), 'automatically activated MSVC compiler environment')

    cmd: T.List[str] = []
    env: T.Optional[T.Dict[str, str]] = None

    backend = cdata.get_option(mesonlib.OptionKey('backend'))
    assert isinstance(backend, str)
    mlog.log(mlog.green('INFO:'), 'autodetecting backend as', backend)
    if backend == 'ninja':
        cmd, env = get_parsed_args_ninja(options, bdir)
    elif backend.startswith('vs'):
        cmd, env = get_parsed_args_vs(options, bdir)
    elif backend == 'xcode':
        cmd, env = get_parsed_args_xcode(options, bdir)
    else:
        raise MesonException(
            f'Backend `{backend}` is not yet supported by `compile`. Use generated project files directly instead.')

    mlog.log(mlog.green('INFO:'), 'calculating backend command to run:', join_args(cmd))
    p, *_ = mesonlib.Popen_safe(cmd, stdout=sys.stdout.buffer, stderr=sys.stderr.buffer, env=env)

    return p.returncode
```