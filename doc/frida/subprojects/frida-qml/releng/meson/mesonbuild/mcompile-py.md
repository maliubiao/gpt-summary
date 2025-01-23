Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Purpose:** The first step is to grasp the overall goal of the script. The docstring clearly states it's the "entrypoint script for backend agnostic compile" within the Frida project. This means it's responsible for taking high-level compile commands and translating them into specific instructions for different build systems (like Ninja, MSBuild, Xcode).

2. **Identify Key Components:**  Scan the code for important elements. Look for:
    * Imports:  These tell us the script's dependencies and what kind of operations it performs (e.g., `os`, `json`, `subprocess`, path manipulation via `pathlib`).
    * Function Definitions:  These are the building blocks of the script's logic. Pay attention to names like `validate_builddir`, `parse_introspect_data`, `get_target_from_intro_data`, `get_parsed_args_ninja`, etc. These often indicate core functionalities.
    * Class Definitions: `ParsedTargetName` stands out. This suggests the script needs to parse and understand how targets are specified.
    * Conditional Logic: Look for `if/elif/else` statements, especially around backend selection.
    * Argument Parsing:  The `add_arguments` function points to command-line argument handling.

3. **Analyze Core Functionality - Backend Agnostic Compilation:**  The script's central role is bridging the gap between a generic "compile" command and the specifics of each build system. This leads to the following observations:
    * **`validate_builddir`:**  Ensures the script is run within a properly initialized Meson build directory. This is crucial for finding the necessary configuration files.
    * **`parse_introspect_data`:** Reads `intro-targets.json`. This file contains metadata about the build targets defined in the `meson.build` files. This is how the script knows what targets exist and their properties.
    * **`ParsedTargetName`:**  Parses the user-provided target string, allowing for specifications like target name, path, and type. This normalization is key for backend independence.
    * **`get_target_from_intro_data`:**  Matches the parsed target name with the information from `intro-targets.json`. This resolves the user's abstract target specification to concrete target details.
    * **`generate_target_names_ninja`, `generate_target_name_vs`:** These functions (and the implied `get_parsed_args_xcode`) are the *backend-specific* parts. They take the abstract target information and translate it into the syntax understood by each build system.
    * **`get_parsed_args_ninja`, `get_parsed_args_vs`, `get_parsed_args_xcode`:**  Construct the actual command-line commands to be executed for each backend, including options like job count, verbosity, and specific arguments.
    * **`run`:** The main function orchestrates everything. It validates the build directory, loads build information, determines the backend, calls the appropriate `get_parsed_args_*` function, and executes the resulting command.

4. **Connect to Reverse Engineering:** Think about how this script aids or is related to reverse engineering. Frida is a dynamic instrumentation toolkit, commonly used for reverse engineering. The compilation process is necessary to build the Frida components that will be used for instrumentation. The script manages the build process of these tools.

5. **Identify Low-Level and Kernel/Framework Aspects:**  Consider when the script interacts with the underlying system.
    * **Build Systems (Ninja, MSBuild, Xcode):**  These are tools that compile code into executables or libraries, which are fundamental at the binary level.
    * **Operating System Interaction (`os`, `subprocess`):** The script interacts with the OS to execute build commands.
    * **File System Operations (`pathlib`, `shutil`):** The script needs to locate and manipulate files within the build directory.
    * **Environment Variables (`os.environ`):**  The script manipulates environment variables, particularly for MSBuild.

6. **Analyze Logical Reasoning:** Look for places where the script makes decisions or transformations based on input.
    * **Target Name Parsing:** The `ParsedTargetName` class performs logical parsing of the target string.
    * **Target Resolution:** `get_target_from_intro_data` uses logic to find the correct target based on name, type, and path.
    * **Backend Selection:** The `run` function uses the configured backend to choose the appropriate command generation logic.

7. **Consider User Errors:**  Think about how a user might misuse the script or encounter errors. The script has built-in checks and helpful error messages.
    * **Invalid Build Directory:** `validate_builddir` catches this.
    * **Target Not Found/Ambiguous:** `get_target_from_intro_data` handles these cases with informative messages.
    * **Conflicting Arguments:** The check in `run` for using both `--clean` and target names is an example.
    * **Backend-Specific Limitations:** The MSBuild section regarding `run` targets highlights a limitation and potential user confusion.

8. **Trace User Interaction:** Imagine the steps a user would take to reach this script. They would:
    * Install Frida and its dependencies.
    * Navigate to the Frida project directory.
    * Run `meson setup build` to configure the build.
    * Navigate to the `build` directory.
    * Run a command like `meson compile` or `python path/to/mcompile.py`.

9. **Structure the Answer:**  Organize the findings into the requested categories: functionality, reverse engineering relevance, low-level/kernel/framework knowledge, logical reasoning, user errors, and user interaction. Use clear examples and explanations.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on the compilation process itself.
* **Correction:** Realize the script is *managing* the compilation, not performing the actual compilation (that's done by Ninja, MSBuild, etc.). Shift focus to the orchestration and translation aspects.
* **Initial thought:**  Overlook the `ParsedTargetName` class.
* **Correction:**  Recognize its importance in normalizing target specifications and making the compilation backend-agnostic.
* **Initial thought:**  Assume the user is directly running `mcompile.py`.
* **Correction:**  Remember that `meson compile` is the more common entry point, and `mcompile.py` is invoked internally. Adjust the "User Interaction" section accordingly.
* **Review and Clarity:**  Read through the generated answer to ensure it's clear, concise, and accurately reflects the script's behavior. Add more specific examples where needed.
This Python script, `mcompile.py`, is a core component of Frida's build system, specifically designed to handle the compilation process in a backend-agnostic way. This means it can trigger builds using different underlying build tools like Ninja, MSBuild (for Visual Studio), and Xcode, without requiring the user to know the specific commands for each.

Here's a breakdown of its functionality:

**1. Core Functionality: Backend-Agnostic Compilation Management**

* **Parses Command-Line Arguments:** It uses `argparse` to handle command-line options like specifying target names, cleaning the build, setting the number of parallel jobs, and passing backend-specific arguments.
* **Validates Build Directory:**  It checks if the current directory (or the one specified with `-C`) is a valid Meson build directory by looking for the `meson-private/coredata.dat` file.
* **Introspects Meson Build Data:** It reads `meson-info/intro-targets.json` to get information about the targets defined in the `meson.build` files. This allows it to understand the available targets, their types (executable, library, etc.), and their output filenames.
* **Resolves Target Names:** It provides a `ParsedTargetName` class to parse user-provided target strings, which can include the target name, path, and type. This helps in uniquely identifying the target even if there are multiple targets with the same base name.
* **Generates Backend-Specific Build Commands:** Based on the backend configured in the Meson build (e.g., Ninja, vs, xcode), it constructs the appropriate command-line arguments for the underlying build tool.
* **Executes the Build Command:** It uses `subprocess.Popen_safe` to execute the generated build command.
* **Handles Cleaning:**  It supports a `--clean` option to trigger the clean command for the selected backend.
* **Handles Parallel Builds:** It allows specifying the number of parallel jobs (`-j`) to speed up the build process, passing this option to the underlying build tool.
* **Manages Environment Variables (for MSBuild):** It handles setting up the Visual Studio environment variables when building with the `vs` backend.

**2. Relationship with Reverse Engineering**

This script plays a crucial role in the development and building of Frida itself, which is a powerful tool for dynamic instrumentation and reverse engineering. Here's how it relates:

* **Building Frida Components:**  Frida consists of various components (e.g., the core library, QML bindings, command-line tools). This script is responsible for compiling these components from their source code.
* **Facilitating Tool Development:** Developers working on Frida or tools that use Frida rely on this script to build their projects. Reverse engineers often develop custom scripts and tools using Frida, and they would use a similar build process managed by this script (or a similar one in their project).

**Example:**

Let's say a reverse engineer wants to build the Frida QML bindings after making some changes to the source code. They would typically navigate to the `frida/subprojects/frida-qml/build` directory (assuming they've already run `meson setup`) and then execute a command like:

```bash
meson compile
```

Behind the scenes, Meson would invoke this `mcompile.py` script. `mcompile.py` would:

1. **Validate the build directory.**
2. **Read `meson-info/intro-targets.json`** to understand the targets within the QML subproject.
3. **Determine the configured backend** (e.g., Ninja).
4. **Generate Ninja commands** to compile the QML-related source code into libraries or other necessary artifacts.
5. **Execute the Ninja command.**

**3. Involvement of Binary 底层, Linux, Android Kernel & Framework Knowledge**

While `mcompile.py` itself doesn't directly interact with the binary level or the kernel, it's a vital part of a system that *does*.

* **Binary 底层 (Binary Low-Level):** The ultimate output of the compilation process managed by this script is binary code (executables, shared libraries, etc.). The compilation process itself involves translating source code into machine code that the processor can understand. The choice of backend (like the specific compiler used by Ninja or MSBuild) heavily influences the generated binary.
* **Linux:** When building on Linux, this script will likely use tools like `gcc` or `clang` (via Ninja) to compile the code. These compilers have deep knowledge of the Linux kernel's ABI (Application Binary Interface) and system calls. The generated binaries will interact with the Linux kernel.
* **Android Kernel & Framework:**  If Frida is being built for Android, the compilation process will target the Android NDK (Native Development Kit). This involves using compilers that generate ARM or x86 binaries compatible with Android. The compiled Frida components will interact with the Android runtime environment (like ART - Android Runtime) and potentially make system calls to the underlying Linux kernel. The QML bindings themselves might interact with Android's UI framework.

**Example:**

If a user builds the Frida server (`frida-server`) for an Android device, `mcompile.py` (through the chosen backend) will orchestrate the compilation of C/C++ code into an ELF binary that can run on the Android device. This process involves:

* **Compiler Flags:** Setting compiler flags specific to the target Android architecture.
* **Linking:** Linking against necessary libraries provided by the Android NDK.
* **ABI Compatibility:** Ensuring the generated binary adheres to the Android ABI.

**4. Logical Reasoning**

The script employs logical reasoning in several places:

* **Target Name Resolution:** The `get_target_from_intro_data` function uses logic to find the correct target based on the provided name, type, and path. It handles cases where the target name is ambiguous.
    * **Assumption:** The `intro-targets.json` file accurately reflects the defined targets.
    * **Input:** A `ParsedTargetName` object and the introspected data.
    * **Output:** A dictionary representing the target information or raising an exception if not found or ambiguous.
* **Backend Selection:** The `run` function uses a conditional structure (`if/elif/else`) to determine which backend-specific command generation function to call based on the configured backend.
    * **Assumption:** The `coredata` contains the correct backend information.
    * **Input:** The configured backend name.
    * **Output:** Execution of the appropriate `get_parsed_args_*` function.

**5. User or Programming Common Usage Errors**

* **Running the script outside a Meson build directory:** The `validate_builddir` function checks for this and raises a `MesonException`.
    * **Error Message:** "Current directory is not a meson build directory: `{builddir}`.\nPlease specify a valid build dir or change the working directory to it.\nIt is also possible that the build directory was generated with an old\nmeson version. Please regenerate it in this case."
* **Specifying a non-existent target:** The `get_target_from_intro_data` function will raise a `MesonException` if the target cannot be found in the introspected data.
    * **Example:** `meson compile non_existent_target`
    * **Error Message:** "Can't invoke target `non_existent_target`: target not found"
* **Ambiguous target names:** If multiple targets have the same name but different types or paths, the script will raise an error asking for more specific information.
    * **Example:**  If you have both an executable and a library named "my_module".
    * **Error Message:** "Can't invoke target `my_module`: ambiguous name. Add target type and/or path:\n- ./path/to/executable:executable\n- ./path/to/library:shared_library"
* **Using `--clean` with specific targets:** The script prevents this combination as it's generally illogical to clean and build specific targets simultaneously.
    * **Example:** `meson compile --clean my_target`
    * **Error Message:** "`TARGET` and `--clean` can't be used simultaneously"
* **Providing invalid arguments to backend-specific options:**  If you provide incorrect arguments to `--ninja-args`, `--vs-args`, or `--xcode-args`, the underlying build tool will likely fail with its own error message. `mcompile.py` itself doesn't validate these arguments extensively.

**6. User Operation Steps to Reach Here (as a Debugging Clue)**

1. **Install Frida and its dependencies:** The user would have followed the installation instructions for their platform, which involves installing Meson, Python, and potentially other build tools.
2. **Clone the Frida repository:** If they are modifying Frida's source code, they would have cloned the Git repository.
3. **Navigate to the Frida project root directory:**  The user would open a terminal and navigate to the root directory of the Frida project.
4. **Create a build directory:** Typically, they would create a separate build directory: `mkdir build`
5. **Navigate into the build directory:** `cd build`
6. **Run Meson setup:** This configures the build system: `meson setup ..` (assuming the source is in the parent directory). This step generates the `meson-private` and `meson-info` directories, including `intro-targets.json`.
7. **Attempt to compile:** The user would then run the `meson compile` command. This command internally executes the `mcompile.py` script located at `frida/subprojects/frida-qml/releng/meson/mesonbuild/mcompile.py` (or a similar path for other subprojects).

**Debugging Scenario:** If a user reports a compilation error, understanding these steps helps in:

* **Verifying the build environment:** Ensure they have a correctly set up Meson build directory.
* **Checking Meson configuration:**  Examine the `meson_options.txt` and the output of the `meson setup` command to see the configured backend and options.
* **Reproducing the error:** Try to replicate the exact `meson compile` command the user executed.
* **Examining the generated backend commands:** If necessary, you could modify `mcompile.py` temporarily to print the generated Ninja, MSBuild, or Xcode commands to see exactly what's being executed.

In summary, `mcompile.py` is a crucial piece of Frida's build infrastructure, providing a unified interface for compiling the project across different platforms and build systems. It handles the complexities of target resolution, backend-specific command generation, and error handling, making the build process more user-friendly and maintainable. Its functionality is essential for developers and reverse engineers working with Frida.

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/mcompile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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