Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The prompt asks for the functionality of `mcompile.py`, its relation to reverse engineering, its involvement with low-level aspects, logical inferences, potential user errors, and how a user might reach this code.

2. **Initial Code Scan and High-Level Purpose:**  Quickly read through the imports and top-level definitions. Keywords like `compile`, `ninja`, `msbuild`, `xcodebuild`, `targets`, `clean`, `builddir`, `meson` strongly suggest this script is a build tool orchestrator within the Meson build system. It appears to take user-provided targets and options and translate them into commands for specific build backends.

3. **Deconstruct Functionality by Sections:**  Go through the code section by section, noting the purpose of each function and class:

    * **Imports:** Identify necessary libraries (os, json, re, sys, shutil, pathlib, etc.) and their potential uses (file system operations, JSON parsing, regular expressions, etc.). The imports from `.`, `mesonlib`, and `mesonbuild` indicate internal Meson dependencies.
    * **`array_arg`:**  Simple helper to convert string arrays to lists.
    * **`validate_builddir`:** Checks if the provided directory is a valid Meson build directory. This is crucial for any Meson operation.
    * **`parse_introspect_data`:** Reads and parses `intro-targets.json`. This file likely contains information about the build targets defined by Meson. This is key to understanding how the script identifies and manipulates targets.
    * **`ParsedTargetName`:**  A class to parse and represent the structure of a target name provided by the user. This helps standardize how targets are handled.
    * **`get_target_from_intro_data`:**  Crucial function. It takes a parsed target name and the introspected data to find the *actual* target definition within Meson. It handles ambiguity and provides helpful suggestions.
    * **`generate_target_names_ninja`:** Translates a Meson target name into the corresponding Ninja build target name(s). This is backend-specific logic.
    * **`get_parsed_args_ninja`:**  Constructs the Ninja command-line arguments based on user options and Meson target information.
    * **`generate_target_name_vs`:** Similar to `generate_target_names_ninja`, but for Visual Studio/MSBuild. Note the different naming conventions.
    * **`get_parsed_args_vs`:** Constructs the MSBuild command-line arguments.
    * **`get_parsed_args_xcode`:** Constructs the `xcodebuild` command-line arguments.
    * **`add_arguments`:** Defines the command-line arguments that `mcompile.py` accepts. This is essential for user interaction.
    * **`run`:** The main execution function. It validates the build directory, loads Meson build data, determines the backend, calls the appropriate `get_parsed_args` function, and then executes the generated build command.

4. **Relate to Reverse Engineering:** Think about how this script could be relevant to someone doing reverse engineering. The key is that it *builds* software. Reverse engineers often need to build the target software to analyze it, debug it, or modify it. Frida itself is a reverse engineering tool, so its build process is inherently related.

5. **Identify Low-Level Aspects:** Look for interactions with the operating system, file system, and build tools. The calls to `os.chdir`, `shutil.which`, and the construction of command-line arguments for native build systems (Ninja, MSBuild, Xcodebuild) are indicators. Consider the environment variable manipulation (`setup_vsenv`).

6. **Analyze Logical Inferences:** Focus on the conditional logic and data transformations. How does the script decide which build system to use? How does it handle different target types? How does it translate user input into backend-specific commands? The `if/elif/else` structure in `run` and the logic in `get_target_from_intro_data` are key areas. Consider potential edge cases (e.g., ambiguous target names).

7. **Consider User Errors:**  Think about common mistakes users might make when using a build tool: specifying an invalid build directory, trying to clean and build simultaneously, providing incorrect target names, not having the required build tools installed.

8. **Trace User Actions:**  Imagine a user wanting to build a Frida component. They would likely:

    * Navigate to the Frida build directory.
    * Run a command like `python ./frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py some_target`.
    * Potentially add options like `-j`, `-v`, or `--clean`.

9. **Structure the Answer:** Organize the findings into logical categories based on the prompt's questions. Use clear and concise language, providing specific examples from the code.

10. **Review and Refine:**  Read through the generated answer to ensure accuracy, completeness, and clarity. Check for any missing points or areas that could be explained better. For example, initially, I might not have explicitly linked the target types to reverse engineering – realizing that certain target types are more relevant for inspection comes from a second pass. Similarly, the debugging angle became clearer upon revisiting the "user reaches here" section.
这个Python脚本 `mcompile.py` 是 Frida 动态 instrumentation 工具构建过程中用于编译目标文件的通用入口点。它的主要功能是根据 Meson 构建系统的配置，调用相应的后端构建工具（如 Ninja、MSBuild 或 Xcodebuild）来编译指定的构建目标。

以下是该脚本的详细功能列表，并结合逆向、底层知识、逻辑推理、用户错误和调试线索进行说明：

**1. 功能概述:**

* **目标编译:**  接收用户指定的构建目标 (targets)，并将其转换为后端构建工具能够理解的格式，然后执行编译命令。
* **清理构建:** 支持清理 (clean) 构建目录，移除之前构建生成的文件。
* **后端抽象:** 作为一个与后端无关的编译入口，根据 Meson 的配置自动选择并调用合适的后端构建工具（Ninja, MSBuild, Xcodebuild）。
* **参数传递:**  允许用户通过命令行选项传递参数给后端的构建工具。
* **多任务支持:** 支持并行编译 (jobs)，可以指定并发执行的编译任务数量。
* **负载控制:**  提供负载平均 (load-average) 控制，尽量维持系统负载在一定水平（尽管部分后端可能不支持）。
* **详细输出:**  提供 verbose 模式，显示更详细的构建输出。

**2. 与逆向方法的关系及举例:**

* **构建 Frida 组件:** 作为 Frida 项目的一部分，`mcompile.py` 用于构建 Frida 的各种组件，例如 frida-core (核心库)、frida-server (服务器端)、frida-node (Node.js 绑定) 等。逆向工程师在开发 Frida 相关的工具或扩展时，需要使用此脚本来编译他们编写的代码。
    * **举例:**  假设一个逆向工程师修改了 frida-core 的源码，需要重新编译 frida-core 库。他会进入 Frida 的构建目录，然后使用 `python ./frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py frida-core` 命令来触发编译。

* **编译目标程序进行 hook:** 虽然 `mcompile.py` 本身不直接进行 hook 操作，但它是构建可以进行 hook 的 Frida 组件的关键步骤。逆向工程师构建了 Frida 后，才能使用 Frida 去 hook 目标进程。
    * **举例:**  逆向工程师使用 Frida 的 Node.js 绑定 (frida-node) 开发了一个脚本来 hook 某个 Android 应用。他首先需要确保 frida-node 已经成功构建，这其中就包含了 `mcompile.py` 的执行。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **构建原生库 (.so, .dll, .dylib):**  `mcompile.py` 的核心功能是编译生成各种平台上的原生库文件，这些库文件包含了机器码，是操作系统直接执行的二进制代码。这涉及到编译器、链接器等底层工具链的使用。
    * **举例:**  编译 `frida-core` 会生成 `frida-agent.so` (Linux/Android) 或 `frida-agent.dylib` (macOS) 等动态链接库。

* **平台特定的构建过程:**  脚本会根据 Meson 的配置和目标平台，调用不同的后端构建工具。例如，在 Linux 上通常使用 Ninja，在 Windows 上使用 MSBuild，在 macOS 上使用 Xcodebuild。这些构建工具的运行机制和参数是平台特定的。
    * **举例:**  在 Android 上构建 Frida Server 时，`mcompile.py` 可能会调用 Ninja，并传递 Android NDK 提供的交叉编译工具链路径和参数。

* **理解目标文件的类型:** 脚本可以处理不同类型的构建目标，例如可执行文件 (`executable`)、静态库 (`static_library`)、动态库 (`shared_library`)、共享模块 (`shared_module`) 等。这些类型对应着不同的二进制文件结构和链接方式。
    * **举例:**  `frida-server` 是一个可执行文件，而 `frida-core` 通常是一个动态链接库。

* **Android 框架 (间接):** 虽然 `mcompile.py` 本身不直接操作 Android 内核或框架，但它构建的 Frida 组件 (例如 `frida-server`) 会在 Android 系统上运行，并与 Android 的运行时环境和框架进行交互。
    * **举例:**  编译好的 `frida-server` 运行在 Android 设备上，需要利用 Android 的进程管理、权限控制等机制。

**4. 逻辑推理及假设输入与输出:**

* **假设输入:**  用户在 Linux 系统上，并且已经配置好了 Frida 的构建环境，包括安装了 Ninja 和其他必要的工具链。用户在 Frida 的构建目录下执行命令： `python ./frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py frida-core -j4`
* **逻辑推理:**
    1. `validate_builddir` 会检查当前目录是否是有效的 Meson 构建目录。
    2. `parse_introspect_data` 会读取 `meson-info/intro-targets.json`，获取所有已定义的构建目标信息。
    3. `ParsedTargetName("frida-core")` 会解析目标名称。
    4. `get_target_from_intro_data` 会在 `intro-targets.json` 中查找名为 `frida-core` 的目标。
    5. 由于后端配置是 Ninja，`get_parsed_args_ninja` 会被调用。
    6. `generate_target_names_ninja` 会根据 `frida-core` 的类型，生成对应的 Ninja 构建目标名称（可能是一个或多个）。
    7. `get_parsed_args_ninja` 会构建 Ninja 的命令行，例如： `ninja -C <build_dir> -j 4 <frida-core_ninja_target>`
    8. `mesonlib.Popen_safe` 会执行这个 Ninja 命令。
* **输出:**  如果编译成功，会显示 Ninja 的构建输出，最终在构建目录下生成 `frida-core` 对应的库文件 (例如 `frida-agent.so`)。如果编译失败，会显示 Ninja 的错误信息。

**5. 涉及用户或编程常见的使用错误及举例:**

* **未在构建目录下执行:** 用户可能在错误的目录下执行 `mcompile.py`，导致 `validate_builddir` 抛出异常。
    * **错误示例:** 用户在 `/home/user` 目录下执行了 `python ./frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py frida-core`，但没有先 `cd` 到 Frida 的构建目录。

* **指定不存在的目标:** 用户可能输入了 Meson 配置中不存在的构建目标名称。
    * **错误示例:** `python ./frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py non_existent_target` 会导致 `get_target_from_intro_data` 抛出异常。

* **同时使用 `--clean` 和指定目标:** 用户可能错误地同时指定了要构建的目标和清理操作。
    * **错误示例:** `python ./frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py frida-core --clean` 会导致 `run` 函数中抛出 `MesonException`。

* **缺少必要的构建工具:**  如果用户的系统上没有安装配置 Meson 时指定的后端构建工具（例如没有安装 Ninja），`get_parsed_args_ninja` 等函数会抛出异常。
    * **错误示例:**  在没有安装 Ninja 的 Linux 系统上，执行 `mcompile.py` 并尝试构建会报错。

* **传递了错误的后端参数:** 用户可能给 `--ninja-args`、`--vs-args` 或 `--xcode-args` 传递了不合法的参数，这会导致后端构建工具执行失败。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要构建 Frida 的 Node.js 绑定 `frida-node`：

1. **配置构建环境:** 用户首先会按照 Frida 的构建文档，安装必要的依赖，例如 Python、Meson、Node.js、npm 等。
2. **获取 Frida 源码:** 用户会通过 Git 克隆 Frida 的代码仓库。
3. **创建构建目录并配置:** 用户会在 Frida 源码目录下创建一个构建目录（例如 `build`），然后使用 `meson setup build` 命令配置构建系统。Meson 会读取 `meson.build` 文件，生成构建所需的文件，包括 `meson-info/intro-targets.json`。
4. **尝试构建 frida-node:** 用户进入构建目录 (`cd build`)，然后尝试构建 `frida-node`。这通常可以通过命令 `python ../frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py` 或更具体的 `python ../frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py frida-node` 来完成。  这里的脚本路径是相对于构建目录的。
5. **`mcompile.py` 的执行:**
    * 用户执行的命令会调用 Python 解释器来运行 `mcompile.py` 脚本。
    * `validate_builddir` 会检查 `build` 目录的有效性。
    * `parse_introspect_data` 读取 `build/meson-info/intro-targets.json`。
    * 如果指定了目标 (`frida-node`)，`ParsedTargetName` 和 `get_target_from_intro_data` 会找到对应的构建目标信息。
    * `run` 函数根据 Meson 配置选择后端（例如 Ninja）。
    * `get_parsed_args_ninja` 构建 Ninja 的命令行。
    * `mesonlib.Popen_safe` 执行 Ninja 命令，开始编译 `frida-node`。

**调试线索:**

* **检查当前工作目录:** 确保用户在正确的 Meson 构建目录下执行 `mcompile.py`。
* **查看 `meson-info/intro-targets.json`:** 这个文件包含了所有可用的构建目标信息，可以用来确认目标名称是否正确。
* **检查 Meson 的配置:** 查看 `meson_options.txt` 或使用 `meson configure` 命令查看 Meson 的配置，确认选择了正确的后端构建工具。
* **查看构建日志:**  如果构建失败，查看 Ninja、MSBuild 或 Xcodebuild 的详细输出信息，可以帮助定位编译错误。
* **确认构建工具是否安装:** 确保系统中安装了配置 Meson 时所选的后端构建工具。
* **逐步调试 `mcompile.py`:**  可以使用 Python 的调试器 (如 `pdb`) 逐步执行 `mcompile.py` 的代码，查看变量的值和程序的执行流程，帮助理解构建命令是如何生成的。

总而言之，`mcompile.py` 是 Frida 构建过程中的一个关键组件，它抽象了不同后端构建工具的细节，为用户提供了一个统一的编译入口。理解它的功能和工作流程对于开发和调试 Frida 相关的代码至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/mesonbuild/mcompile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```