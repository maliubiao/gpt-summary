Response:
Let's break down the thought process for analyzing this Python script.

1. **Understanding the Goal:** The request asks for a functional analysis of `mcompile.py`, focusing on its relation to reverse engineering, low-level operations, reasoning, potential errors, and how users might reach this code. The key is to extract the *purpose* and *impact* of the script.

2. **Initial Skim and Keyword Spotting:** I'd first quickly read through the code, looking for recognizable keywords and structures. Things that would jump out are:
    * `mesonbuild`: Indicates interaction with the Meson build system.
    * `ninja`, `msbuild`, `xcodebuild`: Names of common build tools.
    * `targets`:  Suggests building specific components.
    * `clean`: Indicates a cleanup operation.
    * `introspect`: Likely related to inspecting build system metadata.
    * `os`, `sys`, `shutil`: Standard Python libraries for system interaction.
    * `json`: For parsing structured data.
    * Error handling (`MesonException`).

3. **Dissecting Key Functions:**  Next, I'd focus on the major functions and their roles:
    * `validate_builddir`:  Basic sanity check – ensures the script is run within a valid Meson build directory.
    * `parse_introspect_data`: This is crucial. The name suggests it reads information *about* the build targets. This is where reverse engineering connections will likely be strongest.
    * `ParsedTargetName`:  A helper class to break down how users specify targets. Important for understanding user input.
    * `get_target_from_intro_data`:  This function uses the introspected data to *find* a specific target based on user input. This is where ambiguity resolution happens.
    * `generate_target_names_ninja`, `generate_target_name_vs`: These functions seem to translate the user's target specification into the *specific commands* understood by the underlying build tools (Ninja, MSBuild).
    * `get_parsed_args_ninja`, `get_parsed_args_vs`, `get_parsed_args_xcode`: These are the core logic for constructing the command-line arguments for each supported build backend. They take user options and translate them.
    * `add_arguments`: Defines the command-line interface (what options users can provide).
    * `run`: The main execution function – orchestrates everything, including backend detection and command execution.

4. **Connecting to Reverse Engineering:** The `introspect_data` and the process of mapping user-friendly target names to internal build system representations are key to the reverse engineering connection. The script helps bridge the gap between high-level build intentions and the low-level outputs. I'd think about how a reverse engineer might use this to build specific parts of a larger project.

5. **Identifying Low-Level Interactions:**  The calls to `os.chdir`, `subprocess.Popen_safe` (via `mesonlib`), and the manipulation of environment variables (`setup_vsenv`, `env.pop('PLATFORM')`) are the primary indicators of low-level interaction. The interaction with specific build tools like Ninja, MSBuild, and Xcode also falls into this category.

6. **Analyzing Logic and Reasoning:**  The `get_target_from_intro_data` function contains the most complex logic for matching target names, types, and paths. The handling of ambiguous target names and the generation of suggestions demonstrates conditional reasoning. I would formulate simple examples to test the logic in my head (e.g., a target with the same name in different subdirectories).

7. **Pinpointing Potential User Errors:**  The script has explicit error handling for invalid build directories, missing introspection data, and ambiguous target names. These become the basis for common user errors. Thinking about how a user might misspell a target name or forget to configure the build directory is crucial.

8. **Tracing User Actions:**  The `add_arguments` function is the starting point. Users interact with this script through command-line arguments. I'd imagine a user typing `meson compile my_target` and then trace how that input flows through the parsing and target resolution logic. Debugging scenarios would involve the user encountering errors and needing to understand the target naming conventions or the need for a clean build.

9. **Structuring the Answer:**  Finally, I'd organize the findings into the requested categories:
    * **Functionality:** Provide a high-level overview of what the script does.
    * **Reverse Engineering:** Explain the connection through target introspection and selective building. Provide a concrete example.
    * **Low-Level Knowledge:** Detail the interactions with the OS, build tools, and environment. Give specific examples related to Linux, Android, or kernel concepts if applicable (though this script is more about general build processes than platform-specific kernel details).
    * **Logical Reasoning:** Describe the target resolution process and provide hypothetical input/output.
    * **User Errors:** List common mistakes and their causes.
    * **User Journey:** Explain how a user interacts with the script and how they might end up using it, including debugging scenarios.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This script just runs the build tool."  **Correction:** It's more than that. It *manages* the execution of the build tool by parsing user input and generating the correct commands.
* **Initial thought:** "The reverse engineering link is weak." **Correction:** The ability to build *specific targets* is a crucial aspect of reverse engineering, allowing analysts to focus on particular components.
* **Overemphasis on Kernel/Android:** While Frida does relate to these, this specific script is about the *build process*, which is more general. Adjust the focus accordingly.
* **Clarity of Examples:** Ensure the examples are clear, concise, and directly illustrate the point being made.

By following this structured approach, including iterative refinement, I can effectively analyze the Python script and provide a comprehensive answer that addresses all the requirements of the prompt.
这个Python脚本 `mcompile.py` 是 Frida 动态 Instrumentation 工具链中用于编译构建目标的核心脚本。它抽象了不同构建后端（如 Ninja, MSBuild, Xcode）的编译过程，为用户提供了一个统一的命令行接口来触发构建。

以下是它的主要功能：

**1. 统一的编译入口:**
   - `mcompile.py` 作为一个入口点，允许用户通过统一的命令格式 (`meson compile [targets]`) 来构建项目，而无需关心底层使用的是哪个构建系统。
   - 它解析用户提供的目标 (`targets`)，并将其转换为特定构建系统可以理解的格式。

**2. 支持多种构建后端:**
   - 它支持 Ninja, Visual Studio (MSBuild) 和 Xcode 这三种主要的构建后端。
   - 根据 Meson 配置中选择的后端，`mcompile.py` 会调用相应的后端工具 (`ninja`, `msbuild`, `xcodebuild`)。

**3. 目标构建:**
   - 用户可以指定要构建的特定目标 (`targets`)。目标可以是可执行文件、静态库、共享库、自定义目标等。
   - 脚本会解析目标名称，包括路径、基本名称、后缀和类型，并使用 Meson 的内省数据来找到匹配的目标。

**4. 清理构建目录:**
   - 通过 `--clean` 选项，用户可以清理构建目录，删除之前构建生成的文件。

**5. 并行构建控制:**
   - 通过 `-j` 或 `--jobs` 选项，用户可以指定并行构建的作业数量，提高构建速度。
   - 通过 `-l` 或 `--load-average` 选项，可以尝试维持系统负载平均值（部分后端支持）。

**6. 传递后端特定参数:**
   - 通过 `--ninja-args`, `--vs-args`, `--xcode-args` 选项，用户可以将特定的参数传递给底层的构建工具。

**7. 环境变量处理:**
   - 它会根据需要自动激活 Visual Studio 编译器的环境变量 (`setup_vsenv`)。

**8. 错误处理:**
   - 它会检查构建目录的有效性，处理目标未找到、目标名称歧义等错误情况。

**与逆向方法的关系及举例说明:**

`mcompile.py` 与逆向工程有密切关系，因为它负责构建用于逆向分析的工具和目标。

**例子:**

假设 Frida 的某个组件是用 Swift 编写的，并且在 `frida/subprojects/frida-swift` 目录下。逆向工程师可能只想构建与 Swift 相关的部分，而不是整个 Frida 工具链。

1. **指定目标构建:** 逆向工程师可以使用类似以下的命令来构建特定的 Swift 目标：
   ```bash
   meson compile frida-swift  # 构建名为 frida-swift 的目标 (如果存在)
   meson compile releng/frida-swift-tests # 构建位于 releng 目录下的 frida-swift-tests 目标
   ```
   `mcompile.py` 会解析这些目标名称，并根据 Meson 的配置和内省数据，生成对应的构建命令，例如传递给 `ninja` 或 `msbuild`。

2. **清理特定目标:** 在修改代码后，逆向工程师可能需要清理与特定目标相关的文件：
   ```bash
   meson compile --clean frida-swift
   ```
   虽然 `mcompile.py` 本身没有直接清理特定目标的功能（`--clean` 是清理整个构建目录），但理解目标的概念对于进行有针对性的构建和清理是至关重要的。

**涉及到二进制底层，Linux, Android内核及框架的知识的举例说明:**

`mcompile.py` 本身是一个高级别的构建脚本，它抽象了底层的细节。然而，它构建的目标（Frida 的组件）会深入到二进制底层和操作系统内核/框架。

**例子:**

1. **二进制底层 (编译产物):**  `mcompile.py` 的最终输出是二进制文件，例如可执行文件 (`.exe`, 无后缀) 或共享库 (`.so`, `.dylib`, `.dll`)。这些文件包含了机器码，是操作系统可以直接执行的指令。逆向工程师会使用反汇编器 (如 IDA Pro, Ghidra) 或调试器 (如 gdb, lldb) 来分析这些二进制文件的底层结构和行为。

2. **Linux 内核 (构建 Frida Agent):** Frida Agent 通常会被注入到目标进程中。在 Linux 上，Frida Agent 可能需要与 Linux 内核交互，例如通过 `ptrace` 系统调用来控制目标进程。`mcompile.py` 构建的 Frida Agent 的代码可能会包含与这些内核接口交互的部分。

3. **Android 框架 (构建 Frida Server):** 在 Android 上，Frida Server 运行在 Android 系统进程中，需要与 Android 框架（如 ART 虚拟机）交互。`mcompile.py` 构建的 Frida Server 的代码会涉及到 Android 的 Binder IPC 机制，以及与 Dalvik/ART 虚拟机的交互。

**逻辑推理的假设输入与输出:**

假设 `meson.build` 文件中定义了以下目标：

```meson
executable('my-tool', 'my_tool.c')
shared_library('my-lib', 'my_lib.c')
```

**假设输入:**

```bash
meson compile my-tool
```

**逻辑推理:**

1. `mcompile.py` 解析命令行参数，识别出要构建的目标是 `my-tool`。
2. 它读取构建目录中的 Meson 内省数据 (`intro-targets.json`)，查找名为 `my-tool` 且类型为 `executable` 的目标。
3. 它确定当前配置的构建后端（例如，Ninja）。
4. 它生成特定于 Ninja 的构建命令，例如：`ninja my-tool`（这只是一个简化的例子，实际命令会包含更多细节，如构建目录）。

**假设输出 (脚本行为):**

`mcompile.py` 会执行类似于 `ninja my-tool` 的命令。Ninja 会根据 `build.ninja` 文件中的规则编译 `my_tool.c` 并生成可执行文件 `my-tool`。

**涉及用户或者编程常见的使用错误的举例说明:**

1. **在非构建目录下运行:** 用户可能在没有运行过 `meson setup` 的目录中尝试运行 `meson compile`。
   - **错误信息:** `Current directory is not a meson build directory: ...`
   - **原因:** `mcompile.py` 依赖于构建目录下的 `meson-private/coredata.dat` 文件来判断是否是有效的 Meson 构建目录。

2. **拼写错误或目标不存在:** 用户可能输入了错误的目标名称。
   - **错误信息:** `Can't invoke target 'mty-tool': target not found`
   - **原因:** `mcompile.py` 在 Meson 的内省数据中找不到匹配的目标。

3. **目标名称歧义:** 如果存在多个同名但类型或路径不同的目标，用户只提供名称会导致歧义。
   - **错误信息:** `Can't invoke target 'my-lib': ambiguous name. Add target type and/or path:`
   - **原因:** `mcompile.py` 找到了多个匹配的目标，无法确定用户想要构建哪一个。

4. **同时使用 `--clean` 和指定目标:** 用户可能同时想清理并构建特定目标，这在逻辑上是冲突的。
   - **错误信息:** `'TARGET' and '--clean' can't be used simultaneously`
   - **原因:** 清理操作是针对整个构建目录的，而指定目标是针对特定组件的。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **安装 Frida (或相关开发环境):** 用户首先需要安装 Frida 或配置一个可以构建 Frida 组件的开发环境。这通常涉及到安装 Python, pip, Meson, Ninja (或其他构建工具) 等。

2. **克隆 Frida 源代码:** 用户需要获取 Frida 的源代码，例如通过 Git 克隆 GitHub 仓库。

3. **配置构建 (meson setup):** 用户需要进入 Frida 源代码目录，并创建一个构建目录，然后使用 `meson setup <build_directory>` 命令来配置构建系统。这个步骤会生成 `build.ninja` 等构建文件，以及 `meson-info` 目录下的内省数据。

4. **尝试构建 (meson compile):** 用户现在想要构建 Frida 的某个部分或全部。他们会使用 `meson compile` 命令。

5. **指定目标 (可选):** 如果用户只想构建特定的组件，他们会在 `meson compile` 命令后面添加目标名称，例如 `meson compile frida-swift-tests`。

6. **遇到错误或问题:** 如果构建过程中出现错误，或者用户只想构建特定的部分，他们可能会查看 `mcompile.py` 的输出来理解发生了什么。例如，如果目标名称拼写错误，`mcompile.py` 会报错。

7. **查看 `mcompile.py` 源代码 (为了理解构建过程):** 高级用户或开发者可能会查看 `mcompile.py` 的源代码，以深入了解 Frida 的构建过程，例如：
   - 理解目标名称是如何解析的。
   - 了解如何指定构建参数。
   - 调试构建问题。

因此，用户到达 `mcompile.py` 通常是通过执行 `meson compile` 命令触发的。理解 `mcompile.py` 的功能和逻辑，可以帮助用户更有效地构建 Frida，并解决构建过程中遇到的问题。当出现构建错误时，查看 `mcompile.py` 的输出来理解目标解析、后端命令等信息，可以作为调试的线索。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/mcompile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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