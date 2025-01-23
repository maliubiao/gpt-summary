Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The core request is to analyze the `mcompile.py` script, which is part of Frida, and explain its functionalities, its connection to reverse engineering, its use of low-level concepts, its logical reasoning, potential errors, and how a user might reach this code.

**2. Initial Skim and Keyword Recognition:**

A quick skim reveals key terms and patterns:

* `mesonbuild`:  This immediately suggests a build system is involved.
* `ninja`, `msbuild`, `xcodebuild`: These are popular build tools, indicating the script's role is to orchestrate builds using different backends.
* `targets`: The script clearly deals with building specific targets.
* `builddir`: The concept of a build directory is central to build systems.
* `introspect_data`: This hints at introspection capabilities, where the build system provides information about targets.
* `clean`: A standard build system operation.
* `jobs`, `load-average`:  Parameters related to parallel builds.
* `frida`: The context provided in the prompt.

**3. Functional Breakdown (Step-by-step analysis of the code):**

Now, a more detailed reading is needed, breaking down the script's logic function by function:

* **Imports:** Identify the necessary libraries and modules. Notice `os`, `json`, `re`, `sys`, `shutil`, `pathlib`, `collections`. These give clues about file system operations, data parsing, regular expressions, and more.
* **Helper Functions (`array_arg`, `validate_builddir`):** Understand their purpose. `array_arg` handles list-like arguments, and `validate_builddir` checks if a directory is a valid Meson build directory.
* **`parse_introspect_data`:** This function loads and parses a JSON file (`intro-targets.json`). The name suggests it reads information *about* the targets that can be built. The return type (`defaultdict(list)`) is important.
* **`ParsedTargetName`:** This class parses a target string (e.g., `my_executable:executable`) into its components (name, type, path, suffix). This is crucial for understanding how the script identifies targets.
* **`get_target_from_intro_data`:** This function takes a parsed target name and the introspected data and tries to find the corresponding target information. The logic for handling ambiguous target names is important.
* **`generate_target_names_ninja`, `generate_target_name_vs`:** These functions generate the specific command-line arguments needed for each build tool based on the target information. This highlights the backend-specific nature of the script.
* **`get_parsed_args_ninja`, `get_parsed_args_vs`, `get_parsed_args_xcode`:** These are the core functions for constructing the actual build commands for each backend. They take the command-line options and the build directory as input. Pay close attention to how they translate the generic options (`-j`, `--clean`, etc.) into backend-specific flags. Notice the handling of `run` targets in `get_parsed_args_vs`.
* **`add_arguments`:** This sets up the command-line argument parser.
* **`run`:** This is the main function. It orchestrates the entire process: validation, loading build data, determining the backend, constructing the command, and executing it. The `setup_vsenv` call is important for understanding environment setup on Windows.

**3. Connecting to Reverse Engineering:**

After understanding the basic functionality, consider how this relates to reverse engineering:

* **Dynamic Instrumentation (Frida Context):** The prompt mentions Frida. This immediately links the build process to the creation of tools used for dynamic analysis. The built binaries are likely the agents or libraries Frida injects into processes.
* **Targeting Specific Components:** The ability to build specific targets allows developers of Frida tools to build only the parts they are working on, which is essential for a complex project. Building shared libraries (`.so`, `.dylib`) is relevant as these are often injected.
* **Custom Targets:** The support for `custom` targets suggests flexibility in the build process, which can be useful for building tools with specialized needs.

**4. Identifying Low-Level Concepts:**

Look for code elements that touch on lower-level aspects:

* **Executable, Shared Library, etc.:** These are fundamental binary concepts.
* **Linux, Android:** While not explicitly coded, the supported backends (`ninja`, used extensively on Linux and Android) and the mention of shared libraries strongly imply these platforms are involved. The lack of explicit kernel/framework interaction *within this script* is important to note – this script *builds* tools that *interact* with these.
* **File Paths and System Calls:** The script manipulates file paths and executes external commands (`ninja`, `msbuild`, `xcodebuild`), which involve system calls.

**5. Logical Reasoning and Examples:**

For logical reasoning, focus on the conditional logic and data transformations:

* **Target Name Parsing:**  How does `ParsedTargetName` handle different input formats? Create examples of input and the resulting parsed components.
* **Target Resolution:** How does `get_target_from_intro_data` find the correct target, especially when names are ambiguous? Construct scenarios with multiple targets and how the filtering logic works.
* **Backend Command Generation:**  For a given set of options and targets, what command will be generated for each backend? Show the mapping of generic options to backend-specific flags.

**6. Common User Errors:**

Think about how a user might misuse the tool:

* **Incorrect Build Directory:** The `validate_builddir` function directly addresses this.
* **Typos in Target Names:**  The target parsing and resolution logic can help identify these.
* **Conflicting Options:** The check for using both `--clean` and specific targets is an example of error prevention.
* **Backend-Specific Misunderstandings:** Users might try to use Ninja arguments with the Visual Studio backend.

**7. Tracing User Actions:**

Imagine the steps a developer would take to reach this code:

1. **Modifying Frida Code:** A developer might be changing a Frida component.
2. **Running the Build System:** They would typically use a command like `meson compile` or `ninja` within the build directory.
3. **`meson compile` Invokes `mcompile.py`:**  The `meson` command acts as a frontend, and for the `compile` subcommand, it executes `mcompile.py`.
4. **Parsing Arguments:** `mcompile.py` parses the arguments provided to `meson compile`.
5. **Backend Selection and Execution:** Based on the configured backend, it calls the appropriate `get_parsed_args_*` function and executes the build tool.

**8. Review and Refine:**

After the initial analysis, review and refine the explanations. Ensure clarity, accuracy, and completeness. Double-check the code for any missed details or nuances. For example, the handling of `run` targets in the VS backend is a specific detail to highlight.

By following this systematic approach, you can thoroughly analyze the Python script and address all aspects of the prompt. The key is to combine code reading with an understanding of the broader context of build systems and the specific application (Frida).
这是一个Frida动态 Instrumentation工具的源代码文件，名为 `mcompile.py`，其主要功能是提供一个与构建后端无关的编译入口点。 简单来说，它允许用户通过一个统一的命令来编译项目，而无需关心底层使用的具体构建系统（如 Ninja, MSBuild, Xcodebuild）。

以下是该文件的详细功能列表和相关说明：

**主要功能:**

1. **统一的编译入口:**  `mcompile.py` 提供了一个统一的命令行界面，用户可以使用 `meson compile` 命令来触发构建，而不需要直接调用底层的构建工具。

2. **构建目录验证:**  `validate_builddir` 函数会检查当前目录是否是一个有效的 Meson 构建目录，通过查找 `meson-private/coredata.dat` 文件来判断。这可以防止用户在错误的目录下运行编译命令。

3. **目标（Target）解析:**
   - `parse_introspect_data` 函数读取 Meson 生成的 `intro-targets.json` 文件，该文件包含了项目中定义的所有构建目标的信息。
   - `ParsedTargetName` 类用于解析用户提供的目标名称字符串，例如 `my_executable:executable`，并将其分解为名称、类型、路径和后缀等部分。这使得用户可以更灵活地指定要构建的目标。

4. **根据目标名称获取目标信息:** `get_target_from_intro_data` 函数根据解析后的目标名称，在 `intro-targets.json` 的数据中查找匹配的目标信息。它可以处理目标名称的歧义性，并向用户提供更精确的指定方式。

5. **生成特定构建后端的命令:**
   - `generate_target_names_ninja`, `generate_target_name_vs` 等函数负责根据目标信息生成特定于构建后端（Ninja, MSBuild）的命令行参数。例如，对于 Ninja，它会生成输出文件的相对路径；对于 MSBuild，它会生成 MSBuild 的 target 名称。
   - `get_parsed_args_ninja`, `get_parsed_args_vs`, `get_parsed_args_xcode` 函数根据用户提供的选项和要构建的目标，构建完整的底层构建工具命令（例如 `ninja`, `msbuild`, `xcodebuild`）。

6. **处理通用编译选项:**  该脚本解析诸如 `-j` (jobs/并行编译数), `-l` (load average/系统负载), `-v` (verbose/详细输出), `--clean` (清理构建) 等通用编译选项，并将其转换为特定构建工具的相应参数。

7. **支持传递后端特定参数:**  通过 `--ninja-args`, `--vs-args`, `--xcode-args` 参数，用户可以将额外的参数直接传递给底层的构建工具。

8. **执行底层构建命令:** `run` 函数是主入口点，它负责加载构建信息，选择合适的后端命令生成函数，并最终使用 `subprocess.Popen_safe` 执行底层的构建命令。

**与逆向方法的关系及举例:**

`mcompile.py` 本身不直接执行逆向操作，但它是 Frida 工具链的一部分，用于编译 Frida 的组件，而 Frida 正是一个强大的动态 Instrumentation 框架，广泛应用于逆向工程。

**举例说明:**

假设你正在开发一个基于 Frida 的脚本，需要编译一个自定义的 Frida gadget (一个共享库，会被注入到目标进程中)。

1. **定义构建目标:**  在 Frida 的 `meson.build` 文件中，你会定义一个构建目标，例如一个名为 `my_gadget` 的 `shared_library`。

2. **使用 `meson compile`:**  你会在 Frida 的构建目录下执行 `meson compile my_gadget:shared_library`。

3. **`mcompile.py` 的作用:**
   - `mcompile.py` 会解析你提供的目标 `my_gadget:shared_library`。
   - 它会读取 `intro-targets.json`，找到 `my_gadget` 这个共享库目标的相关信息，例如输出路径。
   - 它会根据你配置的构建后端（例如 Ninja），生成相应的构建命令，例如 `ninja my_gadget.so`。
   - 最终，`mcompile.py` 会执行 `ninja my_gadget.so` 命令，编译生成你的 Frida gadget。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例:**

`mcompile.py` 脚本本身并不直接操作二进制底层或内核，但它构建的软件（Frida 和其组件）会深入到这些层面。

**举例说明:**

- **二进制底层:**  当编译 Frida gadget 时，编译器和链接器会将源代码转换为机器码，生成特定架构（如 ARM, x86）的二进制代码。`mcompile.py` 负责驱动这个编译过程。
- **Linux/Android 内核:** Frida 的 Agent 和 Gadget 需要与目标进程交互，这通常涉及到系统调用。编译出的 Frida 组件会包含与 Linux 或 Android 内核交互的代码。
- **Android 框架:** Frida 可以 hook Android 应用的 Java 层方法。编译出的 Frida 脚本会利用 Android 框架提供的 API 来实现 hook 和其他操作。`mcompile.py` 确保这些组件能够正确地构建出来。

**逻辑推理及假设输入与输出:**

**假设输入:**

- 当前工作目录是一个有效的 Meson 构建目录。
- 用户执行命令: `meson compile my_executable`
- `intro-targets.json` 中存在一个名为 `my_executable` 的可执行文件目标。
- 当前配置的构建后端是 Ninja。

**输出:**

- `mcompile.py` 会解析目标名称 `my_executable`。
- 它会读取 `intro-targets.json`，找到 `my_executable` 的输出路径，例如 `build/my_executable`。
- 它会生成 Ninja 命令: `ninja build/my_executable`。
- 最终会执行该 Ninja 命令。

**假设输入 (目标名称歧义):**

- 当前工作目录是一个有效的 Meson 构建目录。
- 用户执行命令: `meson compile my_lib`
- `intro-targets.json` 中存在一个名为 `my_lib` 的静态库和一个名为 `my_lib` 的共享库。
- 当前配置的构建后端是 Ninja。

**输出:**

- `mcompile.py` 会检测到目标名称 `my_lib` 存在歧义。
- 它会输出类似以下的错误信息，提示用户提供更详细的目标类型或路径：
  ```
  ERROR: Can't invoke target `my_lib`: ambiguous name. Add target type and/or path:
  - ./subproject/mylib:static_library
  - ./subproject/mylib:shared_library
  ```

**涉及用户或编程常见的使用错误及举例:**

1. **在错误的目录下运行 `meson compile`:**  用户可能在非 Meson 构建目录下执行 `meson compile`，导致 `validate_builddir` 抛出异常。
   ```
   Traceback (most recent call last):
     ...
   mesonbuild.mesonlib.MesonException: Current directory is not a meson build directory: `/home/user/project`.
   Please specify a valid build dir or change the working directory to it.
   It is also possible that the build directory was generated with an old
   meson version. Please regenerate it in this case.
   ```

2. **拼写错误的目标名称:** 用户可能拼写错误目标名称，导致 `get_target_from_intro_data` 找不到目标。
   ```
   Traceback (most recent call last):
     ...
   mesonbuild.mesonlib.MesonException: Can't invoke target `my_executible`: target not found
   ```

3. **同时使用 `--clean` 和指定目标:** 用户可能尝试同时清理构建目录并构建特定目标，这是不被允许的。
   ```
   Traceback (most recent call last):
     ...
   mesonbuild.mesonlib.MesonException: `TARGET` and `--clean` can't be used simultaneously
   ```

4. **为错误的后端传递参数:** 用户可能尝试将 Ninja 的参数传递给 MSBuild 后端，这些参数会被忽略或导致错误。虽然 `mcompile.py` 不会直接报错，但底层的构建工具可能会报错。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

假设用户想要编译一个名为 `my_agent.so` 的 Frida Agent（一个共享库）。以下是可能的操作步骤，最终会执行到 `mcompile.py`：

1. **修改 Agent 代码:** 用户修改了 `my_agent.c` 或相关的源代码文件。
2. **进入构建目录:** 用户通过命令行进入 Frida 的构建目录，例如 `cd frida/build`。
3. **执行编译命令:** 用户执行 `meson compile my_agent.so:shared_module` 命令。

**调试线索:**

当用户执行 `meson compile my_agent.so:shared_module` 时，`meson` 命令会：

1. **解析命令行参数:** `meson` 会识别出 `compile` 子命令和目标 `my_agent.so:shared_module`。
2. **查找 `mcompile.py`:** `meson` 会知道 `compile` 子命令对应的处理脚本是 `frida/releng/meson/mesonbuild/mcompile.py`。
3. **调用 `mcompile.py`:** `meson` 会调用 `mcompile.py`，并将解析出的参数传递给它。
4. **`mcompile.py` 的执行:**
   - `mcompile.py` 的 `run` 函数会被执行。
   - `validate_builddir` 会验证当前目录是否是有效的构建目录。
   - `parse_introspect_data` 会读取 `intro-targets.json`。
   - `ParsedTargetName` 会解析 `my_agent.so:shared_module`。
   - `get_target_from_intro_data` 会在 `intro-targets.json` 中查找 `my_agent.so` 的共享模块目标信息。
   - `get_parsed_args_ninja` (假设后端是 Ninja) 会根据目标信息和选项生成 Ninja 命令，例如 `ninja my_agent.so`。
   - `Popen_safe` 会执行生成的 Ninja 命令。

如果用户在编译过程中遇到错误，例如 `target not found`，可以检查以下内容：

- **目标名称是否正确:** 用户在 `meson compile` 命令中输入的目标名称是否与 `meson.build` 文件中定义的一致。
- **目标类型是否正确:** 是否指定了正确的目标类型（例如 `shared_module`, `executable`）。
- **构建目录是否正确:** 当前工作目录是否是 Frida 的构建目录。
- **`intro-targets.json` 是否存在:**  Meson 是否成功生成了 `intro-targets.json` 文件。

总而言之，`mcompile.py` 在 Frida 的构建系统中扮演着重要的角色，它提供了一个抽象层，简化了用户与底层构建工具的交互，并为 Frida 组件的编译提供了统一的入口。理解它的功能有助于理解 Frida 的构建流程，并在遇到编译问题时提供有价值的调试线索。

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/mcompile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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