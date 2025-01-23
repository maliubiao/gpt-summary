Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Context:** The first step is to recognize what this script is and where it fits. The comment at the top clearly states it's part of the Frida dynamic instrumentation tool, specifically the `mcompile.py` file within the Meson build system setup. This tells us it's related to the *compilation* process of Frida.

2. **Identify the Core Functionality:** The name `mcompile.py` strongly suggests a compilation-related function. Reading the initial comments reinforces this: "Entrypoint script for backend agnostic compile." This means it's designed to handle compilation regardless of the underlying build system (like Ninja, MSBuild, Xcode).

3. **High-Level Overview of the Code:**  A quick skim reveals imports related to operating systems, JSON, regular expressions, system interaction, file paths, and a few custom modules (`mlog`, `mesonlib`, `mesonbuild`). This indicates it interacts with the filesystem, processes configuration data (likely from Meson), and potentially executes external commands.

4. **Key Functions and Their Roles:** Now, we need to analyze the important functions:

    * **`array_arg`:**  Simple helper to convert a string to a list. Likely for command-line argument parsing.
    * **`validate_builddir`:**  Crucial for ensuring the script is run from a valid Meson build directory. It checks for the existence of `coredata.dat`.
    * **`parse_introspect_data`:**  This function is key. The name and the file it reads (`intro-targets.json`) strongly suggest it's reading information about the *targets* defined in the Meson build system. The output is a dictionary mapping target names to lists of target dictionaries. This is vital for understanding *what* can be compiled.
    * **`ParsedTargetName`:** A class to parse the target names provided by the user on the command line. It breaks down the name, type, path, and suffix. This is necessary for interpreting user input correctly.
    * **`get_target_from_intro_data`:**  This function takes a parsed target name and the introspected data and tries to find the corresponding target information. It handles ambiguity by suggesting more specific ways to name the target.
    * **`generate_target_names_ninja`, `generate_target_name_vs`:** These functions take a target and the introspected data and generate the specific command-line arguments required by the respective build systems (Ninja, MSBuild) to build that target. Notice the difference in output format.
    * **`get_parsed_args_ninja`, `get_parsed_args_vs`, `get_parsed_args_xcode`:** These are the core logic for each backend. They take the command-line options and the build directory and construct the appropriate command-line invocation for the underlying build tool (Ninja, MSBuild, Xcode). They handle options like `-j`, `-l`, `--clean`, and backend-specific arguments.
    * **`add_arguments`:**  Defines the command-line arguments that `mcompile.py` accepts.
    * **`run`:** The main entry point. It orchestrates the whole process: validates the build directory, loads build data, determines the backend, calls the appropriate `get_parsed_args` function, and then executes the resulting command.

5. **Connecting to the Prompts:** Now, go back to the initial request and address each point:

    * **Functionality:** Summarize the purpose of each key function identified in the previous step. Emphasize the backend-agnostic compilation.
    * **Relationship to Reverse Engineering:**  This is where knowledge of Frida comes in. Frida is used for dynamic instrumentation, often in the context of reverse engineering. The compilation process builds the tools that Frida uses to interact with target processes. Think about the *output* of the compilation: libraries, executables that Frida injects or uses. Give concrete examples like building a specific shared library that will be injected.
    * **Binary/Kernel/Framework Knowledge:**  Consider the nature of Frida's work. It operates at a low level, interacting with processes, memory, and sometimes the kernel. The compilation process produces binaries that need to work within these environments. Mention aspects like shared libraries, kernel modules (though this script itself doesn't *compile* kernel modules directly, Frida *uses* them), and framework-specific aspects (like on Android).
    * **Logical Reasoning (Input/Output):** Focus on the `get_parsed_args_*` functions. Think about how user-provided target names are translated into build system commands. Create a simple example: "User wants to build `my_executable` on the Ninja backend."  Show how the script would use introspection to find the output file path and construct the Ninja command.
    * **User Errors:** Look at the validation steps. What could a user do wrong? Not being in the build directory, providing an invalid target name, trying to clean and build simultaneously.
    * **User Operations as Debugging:** Trace the execution flow from the user running `frida compile` with specific arguments, through the parsing, introspection, and command generation steps. This helps understand how to debug issues.

6. **Refine and Organize:** Structure the answer logically, using headings and bullet points to make it easy to read. Ensure the explanations are clear and concise. Avoid overly technical jargon where simpler terms suffice. Review and correct any errors or ambiguities.

This systematic approach – understanding the context, identifying core functionality, analyzing key components, and then specifically addressing each part of the prompt – is essential for effectively analyzing and explaining code.
这个 `mcompile.py` 文件是 Frida 动态 instrumentation 工具中负责编译的脚本，它属于 Meson 构建系统的一部分。它的主要功能是提供一个**与后端构建系统无关的编译入口点**。这意味着用户可以使用相同的命令来编译 Frida 的组件，而不需要关心底层使用的是 Ninja、MSBuild 还是 Xcode。

以下是它的功能详细列表，并结合了与逆向、二进制底层、Linux/Android 内核及框架知识、逻辑推理、用户错误以及调试线索的说明：

**功能列表及相关说明：**

1. **解析命令行参数:**
   - 使用 `argparse` 模块定义和解析用户在命令行中提供的参数，例如要编译的目标 (`TARGET`)、是否清理 (`--clean`)、并发任务数 (`-j`)、以及传递给特定后端构建系统的参数 (`--ninja-args`, `--vs-args`, `--xcode-args`)。
   - **用户操作如何到达这里：** 用户在终端中运行类似 `frida compile my_target` 或 `frida compile --clean` 的命令时，`mcompile.py` 脚本会被调用，并解析这些命令行参数。

2. **验证构建目录:**
   - `validate_builddir` 函数检查当前工作目录是否是一个有效的 Meson 构建目录，通过查找 `meson-private/coredata.dat` 文件来判断。
   - **用户或编程常见的使用错误：** 如果用户在没有配置 Meson 构建的环境下直接运行 `frida compile`，或者在错误的目录下运行，该函数会抛出 `MesonException` 提示用户。
   - **调试线索：** 如果用户报告 `frida compile` 提示“Current directory is not a meson build directory”，那么首先要检查用户是否在正确的构建目录下。

3. **读取 Meson 内省数据:**
   - `parse_introspect_data` 函数读取 `meson-info/intro-targets.json` 文件，该文件包含了 Meson 构建系统中定义的所有目标的信息，如名称、类型、输出文件路径等。
   - **与逆向的方法有关系：** 在逆向工程中，我们经常需要针对特定的目标进行编译，例如一个特定的共享库或者可执行文件。Meson 的内省数据提供了这些目标的信息，使得 `mcompile.py` 可以根据目标名称找到对应的构建规则。
   - **逻辑推理（假设输入与输出）：**
     - **假设输入：** `intro-targets.json` 中包含一个名为 `agent.so` 的 `shared_library` 类型的目标，其输出路径为 `frida/build/frida-core/libagent.so`。
     - **输出：** `parse_introspect_data` 函数会返回一个字典，其中键包含 `agent.so`，值包含一个列表，列表中的字典包含该目标的详细信息，如 `name: 'agent.so'`, `type: 'shared library'`, `filename: ['frida/build/frida-core/libagent.so']`。

4. **解析目标名称:**
   - `ParsedTargetName` 类用于解析用户提供的目标名称字符串，例如 `core/agent.so:shared_library`。它可以提取目标的名称、类型、路径和后缀。
   - **用户或编程常见的使用错误：** 用户可能输入错误的或者不完整的目标名称，例如只输入 `agent`，而 Meson 中可能存在多个名为 `agent` 的目标（不同类型或路径）。`ParsedTargetName` 可以帮助识别这些错误。

5. **从内省数据中获取目标信息:**
   - `get_target_from_intro_data` 函数根据解析后的目标名称，在 Meson 的内省数据中查找匹配的目标信息。它可以处理模糊的目标名称，并给出更精确的建议。
   - **与逆向的方法有关系：** 当我们需要编译特定的 Frida 组件（例如一个注入到目标进程的 Agent），我们需要知道这个 Agent 的构建目标名称。`get_target_from_intro_data` 帮助 `mcompile.py` 找到这个目标的信息。

6. **生成特定后端构建系统的命令:**
   - `generate_target_names_ninja`, `generate_target_name_vs` 等函数根据不同的后端构建系统（Ninja, MSBuild）的语法，生成用于编译特定目标的命令参数。
   - **涉及到二进制底层：** 编译过程最终会生成二进制文件，例如可执行文件、共享库等。这些函数生成的命令会指示构建系统如何将源代码编译、链接成这些二进制文件。
   - **涉及到 Linux/Android 内核及框架的知识：** Frida 经常需要在 Linux 和 Android 平台上运行，并且与目标进程的内存和 API 进行交互。编译过程可能涉及到特定平台的编译选项、链接库，以及与 Android Framework 相关的组件。例如，编译用于 Android 的 Frida Agent 时，可能需要链接 Android NDK 提供的库。
   - **逻辑推理（假设输入与输出）：**
     - **假设输入：** 用户想使用 Ninja 编译名为 `agent.so` 的共享库，且已成功通过 `get_target_from_intro_data` 获取了该目标的信息。
     - **输出：** `generate_target_names_ninja` 函数可能会返回类似 `['frida/build/frida-core/libagent.so']` 的列表，这是 Ninja 构建 `agent.so` 所需的目标文件路径。

7. **构建特定后端构建系统的参数:**
   - `get_parsed_args_ninja`, `get_parsed_args_vs`, `get_parsed_args_xcode` 函数根据用户提供的选项和要编译的目标，构建完整的后端构建命令。它们会考虑并发任务数、清理选项以及传递给后端构建系统的额外参数。
   - **涉及到二进制底层：** 这些函数生成的命令最终会调用底层的编译器（如 GCC, Clang, MSVC）和链接器，来完成二进制文件的构建过程。
   - **涉及到 Linux/Android 内核及框架的知识：**  针对不同的平台和目标，构建命令会包含不同的编译选项和链接器选项，以确保生成的二进制文件能在目标平台上正确运行，并能与内核或框架进行交互。例如，编译 Android 平台上的 Frida 组件可能需要指定架构（arm, arm64, x86, x86_64）和 Android API Level。

8. **执行构建命令:**
   - `run` 函数是脚本的主入口点，它负责调用上述函数，最终使用 `mesonlib.Popen_safe` 安全地执行构建命令。
   - **调试线索：** 如果编译过程中出现错误，`run` 函数执行的命令及其输出（标准输出和标准错误）是重要的调试信息来源。可以通过 `-v` 或后端构建系统提供的 verbose 选项来获取更详细的构建日志。

**与逆向方法的关系举例说明：**

假设逆向工程师想要修改 Frida 的一个核心组件，例如负责进程注入的模块。他们会：

1. 修改相关的源代码文件。
2. 使用 `frida compile core/injector.so:shared_library` 命令来编译这个特定的共享库。
3. `mcompile.py` 会解析目标名称 `core/injector.so:shared_library`。
4. 通过读取 `intro-targets.json` 找到 `injector.so` 目标的构建信息。
5. 根据当前的后端构建系统（例如 Ninja），生成相应的编译命令，例如 `ninja frida/build/frida-core/libinjector.so`。
6. 执行该命令，生成修改后的 `injector.so` 文件。

**涉及到二进制底层、Linux/Android 内核及框架的知识的举例说明：**

- **二进制底层：** 编译过程中，编译器会将 C/C++ 代码转换为机器码，链接器会将不同的目标文件和库文件链接在一起，生成最终的二进制文件。`mcompile.py` 间接地参与了这个过程，因为它负责生成调用编译器和链接器的命令。
- **Linux 内核：** 如果 Frida 的某些组件需要与 Linux 内核交互（尽管 `mcompile.py` 本身不直接编译内核模块），编译选项可能需要考虑内核头文件的路径、特定的内核编译标志等。
- **Android 框架：** 编译用于 Android 平台的 Frida 组件时，例如 Frida Server 或 Agent，需要链接 Android 的 C 库、libart 等框架库。`mcompile.py` 生成的构建命令会包含指向 Android NDK 库的路径，并可能设置特定的架构和 API Level。

**逻辑推理的假设输入与输出举例说明：**

假设用户运行 `frida compile my-agent`，并且 Meson 的内省数据中存在两个名为 `my-agent` 的目标：一个是 `executable` 类型，路径为 `tools/my-agent`；另一个是 `shared_library` 类型，路径为 `agents/my-agent`。

- **假设输入：** 用户命令 `frida compile my-agent`。
- **`parse_introspect_data` 输出：** 包含两个 `my-agent` 的目标信息。
- **`get_target_from_intro_data` 的逻辑推理：** 由于目标名称 `my-agent` 是模糊的，`get_target_from_intro_data` 会检测到存在多个匹配项，并抛出一个 `MesonException`，提示用户提供更明确的目标信息，例如 `tools/my-agent:executable` 或 `agents/my-agent:shared_library`。

**涉及用户或编程常见的使用错误举例说明：**

- **用户不在构建目录下：** 用户在没有运行过 `meson` 命令生成构建文件的情况下，直接运行 `frida compile`，`validate_builddir` 会抛出异常。
- **输入不存在的目标名称：** 用户输入了一个在 `intro-targets.json` 中不存在的目标名称，`get_target_from_intro_data` 会抛出异常，提示目标未找到。
- **同时使用 `--clean` 和指定目标：** 用户运行 `frida compile --clean my_target`，`run` 函数会检查到这种情况并抛出异常，因为清理操作通常不需要指定特定目标。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户下载或克隆了 Frida 的源代码。**
2. **用户创建了一个构建目录（例如 `build`）并进入该目录。**
3. **用户运行 `meson ..` 或 `meson` 命令来配置构建系统。** 这会生成 `meson-private` 目录和 `meson-info` 目录，其中包含 `intro-targets.json` 等文件。
4. **用户想要编译 Frida 的某个组件，例如一个测试工具或者一个 Agent。**
5. **用户在终端中运行 `frida compile <目标名称>` 命令。**
6. **系统执行 `mcompile.py` 脚本。**
7. **`mcompile.py` 首先调用 `validate_builddir` 检查当前目录是否是有效的构建目录。**
8. **然后，`parse_introspect_data` 读取 `intro-targets.json` 获取所有目标的信息。**
9. **`ParsedTargetName` 解析用户提供的目标名称。**
10. **`get_target_from_intro_data` 根据解析后的目标名称在内省数据中查找匹配的目标。**
11. **`get_parsed_args_ninja` (或其他后端对应的函数) 根据查找到的目标信息和用户提供的选项，生成后端构建系统的命令。**
12. **最后，`run` 函数执行生成的构建命令。**

作为调试线索，如果用户报告编译问题，可以按照这个步骤逐一排查：

- 检查用户是否在正确的构建目录下。
- 检查 `meson-info/intro-targets.json` 文件是否存在且内容是否正确，以确认 Meson 配置是否成功。
- 检查用户输入的目标名称是否正确，并且存在于 `intro-targets.json` 中。
- 检查生成的构建命令是否符合预期，可以通过添加 `-v` 参数来查看更详细的构建日志。
- 查看后端构建系统的输出，以获取更底层的错误信息。

### 提示词
```
这是目录为frida/subprojects/frida-core/releng/meson/mesonbuild/mcompile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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