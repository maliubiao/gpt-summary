Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The request asks for the functionality of `mcompile.py`, its relevance to reverse engineering, its interaction with low-level systems, any logical reasoning it performs, potential user errors, and how a user might reach this code. The key is to treat this like reverse-engineering the purpose of the script itself.

2. **High-Level Overview (Skimming):** First, quickly scan the imports and the overall structure. Notice keywords like "compile," "targets," "ninja," "msbuild," "xcodebuild," "builddir," "introspect."  This immediately suggests it's a script for building software projects managed by Meson. The multiple backend mentions indicate it adapts to different build systems.

3. **Core Functionality Identification:** Focus on the `run()` function as the main entry point. Trace the execution flow. It validates the build directory, loads build data, determines the backend, and then calls backend-specific functions (`get_parsed_args_ninja`, `get_parsed_args_vs`, `get_parsed_args_xcode`). This reveals the core function:  taking Meson build information and generating the appropriate command-line invocation for the underlying build system.

4. **Backend-Specific Logic:** Examine the `get_parsed_args_*` functions.
    * **Ninja:**  Notice the direct manipulation of `ninja` command-line arguments (`-j`, `-l`, `-v`). The crucial part is `generate_target_names_ninja`, which interacts with introspected build data to find the actual output files for a target.
    * **MSBuild:**  It deals with `.sln` files and target names within Visual Studio solutions. The `generate_target_name_vs` function shows how Meson target names are translated to MSBuild target names. The handling of "run" targets differently is a key detail.
    * **Xcode:** Uses `xcodebuild` and similar argument passing.

5. **Introspection and Target Resolution:** The `parse_introspect_data` and `get_target_from_intro_data` functions are vital. They explain how `mcompile.py` figures out *what* to build. It reads Meson's internal representation of targets and resolves user-provided target names (which can be ambiguous) to specific build outputs. The `ParsedTargetName` class is also key here, showing how target strings are parsed.

6. **Reverse Engineering Relevance:** Consider how this relates to reverse engineering. While the script *builds*, understanding its logic is helpful in reverse engineering *the build process*.
    * **Identifying Build Products:** Knowing how targets are resolved helps pinpoint the location of compiled binaries or libraries.
    * **Understanding Dependencies:** Although not explicitly in this script, the concept of targets implies dependencies, which are important for understanding the structure of a software project being reverse-engineered.
    * **Build System Specifics:** Recognizing the interaction with Ninja, MSBuild, and Xcode can guide reverse engineers to look for build system-specific configurations or behaviors.

7. **Low-Level/Kernel Aspects:**  The script itself doesn't directly interact with the Linux kernel or Android kernel at the code level. However:
    * **Binary Compilation:**  The *purpose* of the script is to invoke compilers and linkers that *do* generate binaries, which are the subject of reverse engineering.
    * **Platform Specifics:** The backend choices (Ninja, MSBuild, Xcode) inherently deal with platform-specific compilation. MSBuild is heavily tied to Windows. Xcode to macOS/iOS.
    * **Process Execution:** The `Popen_safe` function interacts with the operating system to launch the build tools.

8. **Logical Reasoning:**  Focus on decision points and data transformations:
    * **Target Name Resolution:**  The logic in `get_target_from_intro_data` to handle ambiguous target names is a form of logical reasoning based on available build information.
    * **Backend Selection:** The script decides which backend to use based on Meson's configuration.
    * **Argument Generation:** The `get_parsed_args_*` functions logically construct the command-line arguments for the respective build tools.

9. **User Errors:** Look for error handling and assumptions:
    * **Invalid Build Directory:** The `validate_builddir` function explicitly checks for a valid Meson setup.
    * **Target Not Found/Ambiguous:** The `get_target_from_intro_data` function handles these scenarios.
    * **Conflicting Arguments:** The check in `run()` for using both `TARGETS` and `--clean` demonstrates error prevention.
    * **Missing Build Tools:** The checks for `ninja` and `xcodebuild` highlight dependencies.

10. **User Path to Code:** Imagine a user wanting to compile a Frida project.
    1. They would have a Frida source code directory.
    2. They would run `meson <source_dir> <build_dir>` to configure the build.
    3. They would then run `meson compile` (or simply `ninja` or `msbuild` directly in the build directory).
    4. `meson compile` internally calls this `mcompile.py` script. The arguments passed to `meson compile` are parsed by `argparse` and passed to the `run` function.

11. **Refine and Organize:**  Structure the findings into the requested categories (functionality, reverse engineering, low-level, logic, errors, user path). Use clear and concise language, providing specific code examples where relevant.

**Self-Correction/Refinement:**

* **Initial thought:** "This script just runs the compiler."  **Correction:** It's an abstraction layer over different build systems, making it more versatile than a direct compiler invocation.
* **Overlook:** Initially, I might miss the nuance of the "run" target handling in MSBuild. **Correction:** Closer reading reveals the special handling due to its disabled project nature.
* **Clarity:** Ensure the explanation of target name resolution is clear and mentions the role of `intro-targets.json`.

By following this structured analysis, examining the code details, and constantly relating back to the original request, you can generate a comprehensive and accurate explanation of the script's functionality.
This Python script, `mcompile.py`, is a core component of the Frida dynamic instrumentation toolkit's build process, specifically for handling the compilation phase. It acts as a unified interface to trigger the underlying build system (like Ninja, MSBuild, or Xcode) that Meson has configured for the project.

Here's a breakdown of its functionality:

**Core Functionality:**

1. **Abstracts Build System Invocation:**  The primary goal of `mcompile.py` is to provide a consistent way to compile Frida, regardless of the actual build system Meson has chosen (Ninja, Visual Studio, Xcode, etc.). It reads Meson's configuration and translates user commands into the appropriate commands for the underlying build tool.

2. **Targeted Compilation:** It allows users to specify specific targets to build instead of building the entire project. Targets can be executables, libraries, or custom build rules defined in the Meson build files.

3. **Clean Operations:** It provides a `--clean` option to remove previously built artifacts, effectively starting the compilation from scratch.

4. **Parallel Builds:** It supports parallel builds using the `-j` or `--jobs` option, allowing for faster compilation by utilizing multiple processor cores.

5. **Load Average Management:** It includes an option `-l` or `--load-average` to try and maintain a specific system load average, though the effectiveness depends on the underlying build system's support.

6. **Verbose Output:** The `-v` or `--verbose` flag enables more detailed output from the underlying build system, helpful for debugging.

7. **Passing Arguments to Backend:** It allows passing custom arguments directly to the underlying build system (Ninja, MSBuild, Xcode) using `--ninja-args`, `--vs-args`, and `--xcode-args`.

8. **Build Directory Management:** It expects to be run within or pointed to a valid Meson build directory. It validates the build directory's integrity.

9. **Introspection of Build Targets:** It uses Meson's introspection data (specifically `intro-targets.json`) to understand the available build targets and their properties (type, output files, etc.). This is crucial for resolving user-provided target names.

**Relationship to Reverse Engineering:**

While `mcompile.py` itself is a build tool, understanding its functionality can be indirectly helpful in reverse engineering:

* **Identifying Build Products:**  When reverse engineering a Frida component, knowing how it was built and what its build targets are can help locate the relevant compiled binaries (executables, shared libraries, etc.). `mcompile.py` helps understand how target names map to output files.
    * **Example:** If you see a target named `frida-core` being built, `mcompile.py` (through introspection) helps determine the actual output file (e.g., `libfrida-core.so` on Linux) and its location within the build directory.

* **Understanding Build Dependencies:** Although not directly handled by `mcompile.py`, the concept of "targets" implies dependencies. Knowing the target structure can give clues about how different parts of Frida are linked together, which is relevant when analyzing inter-component communication or dependencies during reverse engineering.

**Involvement of Binary底层, Linux, Android Kernel & Framework:**

* **Binary 底层 (Binary Low-Level):** `mcompile.py`'s ultimate goal is to generate machine code (binaries). It orchestrates the compilation and linking process, which are fundamental to creating executable code. It doesn't directly manipulate binary data, but it's the tool that triggers the tools that do.

* **Linux/Android Kernel:**
    * **Compilation for Specific Architectures:** Frida can be built for various architectures (x86, ARM, etc.). The underlying build system, invoked by `mcompile.py`, uses compilers and linkers configured for the target architecture. For Android, this often involves cross-compilation.
    * **Shared Libraries (.so):** On Linux and Android, Frida heavily relies on shared libraries. `mcompile.py` builds these libraries. Understanding the structure and dependencies of these libraries is essential for reverse engineering Frida's interaction with the operating system.
    * **Kernel Modules (Potentially):** While not explicitly shown in this snippet, Frida can sometimes involve kernel modules. The build process orchestrated by `mcompile.py` would handle compiling and packaging these modules.

* **Android Framework:**
    * **Dex Compilation:** When building Frida components for Android, the underlying build process will involve compiling Java/Kotlin code into Dalvik Executable (DEX) bytecode. Although `mcompile.py` doesn't perform this directly, it triggers the tools that do.
    * **Native Libraries for Android:** Frida often includes native code (.so files) for Android. `mcompile.py` manages the compilation of these native libraries.

**Logical Reasoning with Assumptions:**

* **Assumption:** The script assumes a valid Meson build environment has been set up in the specified directory.
    * **Input:**  A user runs `python mcompile.py -C /path/to/frida/build`.
    * **Reasoning:** The `validate_builddir` function checks for the existence of `meson-private/coredata.dat`.
    * **Output:** If the file exists, the script proceeds. If not, it raises a `MesonException`.

* **Assumption:** Target names provided by the user can be ambiguous.
    * **Input:** A user runs `python mcompile.py frida-core`.
    * **Reasoning:** The `get_target_from_intro_data` function uses the introspected data to find all targets with the name "frida-core".
    * **Output:** If multiple targets with the same name exist (but different types or paths), the script will raise a `MesonException` indicating ambiguity and suggesting more specific target names.

* **Assumption:** The user intends to build for the configured backend.
    * **Input:** The Meson configuration has set the backend to "ninja". The user runs `python mcompile.py`.
    * **Reasoning:** The script reads the `backend` option from Meson's configuration.
    * **Output:** The `get_parsed_args_ninja` function is called to generate Ninja-specific build commands.

**User/Programming Common Usage Errors:**

1. **Running in the Wrong Directory:**
   * **Error:** Running `python mcompile.py` outside of a valid Meson build directory.
   * **Result:** The `validate_builddir` function will raise a `MesonException` like: "Current directory is not a meson build directory: `.`"

2. **Specifying Invalid Targets:**
   * **Error:** Providing a target name that doesn't exist in the Meson build configuration (e.g., a typo).
   * **Result:** The `get_target_from_intro_data` function will raise a `MesonException` like: "Can't invoke target `invalid-target`: target not found".

3. **Ambiguous Target Names:**
   * **Error:** Providing a target name that matches multiple targets with different types or paths.
   * **Result:** The `get_target_from_intro_data` function will raise a `MesonException` indicating ambiguity and suggesting more specific target names (e.g., including the path or target type).

4. **Using `--clean` with Specific Targets:**
   * **Error:** Running `python mcompile.py --clean my_target`.
   * **Result:** The script explicitly checks for this combination and raises a `MesonException`: "`TARGET` and `--clean` can't be used simultaneously".

5. **Forgetting to Configure with Meson First:**
   * **Error:** Trying to run `python mcompile.py` before running `meson` to configure the build directory.
   * **Result:** The `validate_builddir` function or the attempt to read `intro-targets.json` will fail, as these files are created by the `meson` configuration step.

**User Operation Steps to Reach Here (Debugging Context):**

Let's imagine a user is trying to build a specific Frida component and encounters an error during the compilation:

1. **User Modifies Frida Source Code:** The user might have made changes to a Frida source file in `frida/`.

2. **User Navigates to the Build Directory:** The user opens their terminal and changes the directory to their Frida build directory (the one they created when running `meson`). For example: `cd frida/build`.

3. **User Attempts to Build:** The user tries to compile, potentially targeting a specific component:
   * They might run: `meson compile` (which implicitly calls `mcompile.py`).
   * Or, they might try to build a specific target: `meson compile frida-core`.
   * Or, if they are using Ninja directly, they might run: `ninja frida-core`. However, `mcompile.py` can be invoked independently.

4. **Error Occurs During Compilation:** The underlying build system (invoked by `mcompile.py`) encounters an error (e.g., a compilation error in C code, a linking error).

5. **User Investigates the Error:** The error messages often point to the failing build command. If the user is running `meson compile`, they might not see the exact command.

6. **To Understand the Underlying Command (Debugging):** The user might want to see the exact command being executed. This is where they might start to investigate `mcompile.py`. They might:
   * **Read the `meson compile` documentation:** Realize it uses `mcompile.py`.
   * **Examine the `meson` script itself:** Trace how it calls `mcompile.py`.
   * **Look at the verbose output:** Running `meson compile -v` will show the command executed by `mcompile.py`.

7. **User Might Directly Invoke `mcompile.py` (for debugging or advanced usage):**  In some cases, a developer might directly invoke `mcompile.py` with specific arguments to isolate a build issue or test certain scenarios. For example:
   * `python frida/subprojects/frida-gum/releng/meson/mesonbuild/mcompile.py -C /path/to/frida/build frida-core -v`

By understanding the code in `mcompile.py`, the user can gain insight into:

* **How Meson translates their high-level `meson compile` command into low-level build system commands.**
* **How target names are resolved.**
* **What arguments are being passed to the underlying build tool (Ninja, MSBuild, etc.).**

This knowledge can be crucial for debugging complex build issues or for understanding the overall build process of Frida.

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/mcompile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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