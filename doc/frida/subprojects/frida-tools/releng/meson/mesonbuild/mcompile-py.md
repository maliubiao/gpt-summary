Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The initial request asks for the functionality of the script `mcompile.py`, its relation to reverse engineering, its low-level interactions, logical reasoning, potential errors, and how a user reaches this point. The core idea is to understand what this script *does* in the context of Frida.

**2. Initial Read-Through and Keyword Identification:**

The first step is a quick skim of the code, looking for prominent keywords and patterns:

* **`import` statements:**  These immediately reveal dependencies and areas of functionality: `os`, `json`, `re`, `sys`, `shutil`, `typing`, `collections`, `pathlib`. Specifically, `mesonbuild` points to this script being part of the Meson build system.
* **Function definitions:**  Functions like `validate_builddir`, `parse_introspect_data`, `get_target_from_intro_data`, `generate_target_names_ninja`, `get_parsed_args_vs`, `get_parsed_args_xcode`, `add_arguments`, and `run` suggest distinct modules of functionality.
* **Arguments parsing:** The presence of `argparse` and `add_arguments` indicates this is a command-line tool.
* **Backend mentions:**  References to "ninja", "vs" (Visual Studio), and "xcode" strongly imply this script orchestrates builds for different build systems.
* **Target concept:** The frequent use of "target" suggests the script is about building specific components of a project.
* **Error handling:** `raise MesonException` points to custom error handling within the Meson framework.
* **File system operations:**  `Path`, `.is_file()`, `.exists()`, `.open()`, `.glob()` indicate interaction with the file system.
* **Process execution:** `mesonlib.Popen_safe` suggests executing external commands.

**3. Deconstructing Function by Function:**

After the initial scan, it's helpful to analyze each function individually:

* **`validate_builddir`:** Checks if the provided directory is a valid Meson build directory.
* **`parse_introspect_data`:** Reads a JSON file (`intro-targets.json`) to get information about build targets.
* **`ParsedTargetName`:**  A class to parse and represent the structure of a target name (including path, base name, suffix, and type).
* **`get_target_from_intro_data`:**  Matches a user-provided target name with the information parsed from `intro-targets.json`. Crucially, it handles ambiguity and provides suggestions.
* **`generate_target_names_ninja`, `get_parsed_args_ninja`:**  Specifically for the Ninja build system. Generates the command-line arguments for Ninja based on user input and introspection data.
* **`generate_target_name_vs`, `get_parsed_args_vs`:**  Similar to the Ninja functions, but for Visual Studio (MSBuild). Handles special cases like "run" targets.
* **`get_parsed_args_xcode`:**  The same for Xcode.
* **`add_arguments`:** Defines the command-line arguments the script accepts.
* **`run`:**  The main execution logic: validates the build directory, loads build data, determines the backend, calls the appropriate `get_parsed_args_*` function, and executes the build command.

**4. Identifying Core Functionality:**

From the function analysis, the core functionality emerges:

* **Abstraction over build systems:** The script acts as a unified interface for building projects configured with Meson, regardless of the underlying build system (Ninja, MSBuild, Xcode).
* **Targeted compilation:** It allows users to build specific targets instead of the entire project.
* **Command-line argument parsing:**  It provides a set of command-line options for controlling the build process (jobs, verbosity, clean).
* **Backend-specific argument handling:** It translates generic options into the specific syntax required by each build system.

**5. Connecting to Reverse Engineering (and other aspects):**

Now, the prompt asks for specific connections:

* **Reverse Engineering:**  The crucial link is Frida. Frida is a *dynamic instrumentation* toolkit. This script, being part of `frida-tools`, is involved in *building* Frida itself. Reverse engineers often need to build tools (like Frida) or components of systems they are analyzing. The example of building the `frida-server` is direct.
* **Binary/Low-level:**  The script doesn't directly manipulate binary code. However, it orchestrates the *compilation* process, which ultimately produces binaries. It interacts with build tools that *do* deal with low-level details. The mention of linking and object files reinforces this. The backend-specific nature also implies handling compiler-specific flags and linking procedures.
* **Linux/Android Kernel/Framework:** While the script itself isn't kernel code, Frida is often used to interact with these systems. This script builds the tools used for that interaction. The example of building a shared library for Android is relevant.
* **Logical Reasoning:** The `get_target_from_intro_data` function demonstrates logical reasoning. It makes assumptions about target names and tries to resolve ambiguities. The input/output example illustrates this.
* **User Errors:** The validation of the build directory and the conflict between `--clean` and specific targets are examples of preventing common user mistakes.
* **User Steps to Reach Here:** The `frida compile` command is the direct entry point. The breakdown of the Meson configuration process provides context.

**6. Structuring the Answer:**

Finally, the information needs to be structured clearly, addressing each point in the prompt. Using headings and bullet points makes the answer more readable. Providing concrete examples is crucial for illustrating the concepts.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Is this script directly involved in *injecting* into processes?  **Correction:** No, it's part of the *build* process for Frida. Focus on compilation.
* **Overemphasis on specific build systems:** While understanding Ninja/MSBuild/Xcode is important, the *abstraction* provided by this script is the key.
* **Vagueness:**  Avoid general statements. Provide specific examples (like target name formats, error messages, and command-line examples).

By following this systematic approach, we can analyze the script effectively and address all aspects of the prompt.
This Python script, `mcompile.py`, is a crucial part of Frida's build process, specifically within the Meson build system. Its primary function is to provide a **backend-agnostic interface for compiling Frida components**. This means it allows users to trigger the compilation process without needing to directly interact with the underlying build system (like Ninja, Visual Studio, or Xcode).

Let's break down its functionalities based on your questions:

**1. Functionalities:**

* **Targeted Compilation:** The script allows users to specify specific targets to build. A "target" in this context could be an executable, a shared library, or a custom build step defined in the Meson build files.
* **Build System Abstraction:** It hides the complexities of different build systems (Ninja, MSBuild for Visual Studio, Xcode) from the user. The user provides a target name, and the script translates that into the appropriate commands for the underlying build system.
* **Cleaning the Build Directory:** It provides an option to clean the build directory, removing previously built files.
* **Parallel Compilation:** It supports specifying the number of parallel jobs to use during compilation, potentially speeding up the build process.
* **Passing Arguments to Backend:** It allows users to pass specific arguments directly to the underlying build system (e.g., Ninja arguments, MSBuild arguments).
* **Error Handling:** It includes basic error handling, such as checking if the current directory is a valid Meson build directory.
* **Logging:** It uses the `mlog` module for logging information about the build process.

**2. Relationship with Reverse Engineering:**

This script is indirectly related to reverse engineering. Frida is a powerful tool used extensively in reverse engineering for dynamic analysis, instrumentation, and hooking into running processes. `mcompile.py` is essential for **building the Frida tools themselves**, which are then used for reverse engineering tasks.

**Example:**

A reverse engineer might want to modify the Frida server or client to add custom functionality for their analysis. They would:

1. **Modify the Frida source code.**
2. **Use `mcompile.py` to rebuild the Frida components.**  For example, they might target the `frida-server` executable for a specific platform. The script would handle the compilation process using the appropriate compiler and linker for that platform.
3. **Deploy and use the modified Frida tools** for their reverse engineering tasks.

**3. Involvement of Binary底层, Linux, Android 内核及框架知识:**

While `mcompile.py` itself doesn't directly interact with binary code or the kernel, it's a crucial step in the process of building software that *does*.

* **Binary 底层 (Binary Low-level):**
    * **Compilation:** The script triggers the compiler (like GCC, Clang, or MSVC) which translates source code into machine code (binary).
    * **Linking:** It invokes the linker, which combines compiled object files into executables or libraries. These output files are the binary artifacts used by Frida.
    * **Target Architecture:** The Meson configuration (which `mcompile.py` relies on) specifies the target architecture (e.g., x86, ARM, ARM64). The compilation process is tailored to this architecture, producing specific binary instructions.

* **Linux:**
    * **Build Tools:** On Linux, `mcompile.py` often invokes build tools like `ninja` or `make`, which are standard build system utilities on Linux.
    * **Shared Libraries:**  Frida often uses shared libraries (.so files on Linux) for its core functionality and extensions. `mcompile.py` handles the compilation and linking of these shared libraries.

* **Android 内核及框架 (Android Kernel and Framework):**
    * **Frida Server on Android:** Building the `frida-server` for Android is a common use case. This involves cross-compilation, where code is compiled on a different platform (e.g., a Linux machine) for the Android target. `mcompile.py` orchestrates this process, using the Android NDK (Native Development Kit) and its toolchain.
    * **Android Libraries:**  Frida interacts with Android's framework (like `zygote`, `app_process`) and often needs to build shared libraries that are compatible with the Android runtime environment.

**Example:**

When building `frida-server` for Android, `mcompile.py` would:

1. Read the Meson build configuration for the Android target.
2. Invoke the appropriate compiler from the Android NDK (e.g., `aarch64-linux-android-clang++`).
3. Provide the necessary compiler flags and include paths for Android development.
4. Link the compiled object files to create the `frida-server` executable that can run on Android.

**4. Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input:**

```bash
python3 frida/subprojects/frida-tools/releng/meson/mesonbuild/mcompile.py frida-server
```

**Assumptions:**

* You are in the root of the Frida build directory.
* The Meson build has been configured previously (e.g., using `meson setup build`).
* The default backend is Ninja.

**Logical Reasoning within `mcompile.py`:**

1. **Parse Target Name:** The script parses the input `frida-server` as the target.
2. **Load Build Data:** It reads the `meson-info/intro-targets.json` file to find information about the `frida-server` target. This file contains metadata about all defined build targets.
3. **Determine Backend:** It reads the configured backend from the Meson core data (likely "ninja" in this case).
4. **Generate Ninja Commands:** Based on the target name and the Ninja backend, it constructs the appropriate Ninja command. This might involve looking up the output file paths associated with `frida-server` in the introspection data.
5. **Execute Ninja:** It executes the Ninja command.

**Hypothetical Output (Observed in the terminal):**

```
INFO: autodetecting backend as ninja
INFO: calculating backend command to run: ninja -C build frida-server
[some number]/[total number] Compiling src/frida-server/main.c
... (Compilation output) ...
[some number]/[total number] Linking build/frida-server
```

**5. User or Programming Common Usage Errors:**

* **Running from the Wrong Directory:**
    * **Error:** `MesonException: Current directory is not a meson build directory: ...`
    * **Explanation:**  The script checks for the presence of `meson-private/coredata.dat`. If this file is missing, it means you're not in a valid Meson build directory.
    * **User Action:** The user needs to navigate to the build directory (the one created by `meson setup`).

* **Specifying an Invalid Target Name:**
    * **Error:** `MesonException: Can't invoke target 'invalid-target': target not found`
    * **Explanation:** The user has provided a target name that doesn't exist in the Meson build definition.
    * **User Action:** The user needs to check the Meson `meson.build` files to find the correct target name. They can also use `meson introspect --targets` to list available targets.

* **Using `--clean` with Specific Targets:**
    * **Error:** `MesonException: 'TARGET' and '--clean' can't be used simultaneously`
    * **Explanation:** Cleaning the build directory removes all built files. It doesn't make sense to specify a specific target to build while also cleaning everything.
    * **User Action:** The user should either use `--clean` alone to clean the entire build or specify targets to build without the `--clean` option.

* **Forgetting to Run `meson setup` First:**
    * **Error:**  Potentially a missing `meson-info/intro-targets.json` file error or other build system errors.
    * **Explanation:** The `mcompile.py` script relies on the metadata generated by the `meson setup` command. If `meson setup` hasn't been run, this metadata won't exist.
    * **User Action:** The user must first run `meson setup <build_directory>` to configure the build before attempting to compile.

**6. User Operations to Reach `mcompile.py` (Debugging Clue):**

The most common way a user would directly interact with `mcompile.py` is through the `frida compile` command provided by the Frida development tools.

**Steps:**

1. **Clone the Frida Repository:** The user clones the Frida Git repository.
2. **Navigate to the Frida Directory:** They change their current directory to the root of the Frida repository.
3. **Create a Build Directory:** They create a separate directory for the build (e.g., `mkdir build`).
4. **Configure the Build with Meson:** They run `meson setup build` (or `meson setup` if they are already in the desired build directory). This step reads the `meson.build` files and generates the necessary build system files (like `build.ninja` for the Ninja backend).
5. **Attempt to Compile:**  The user then uses the `frida compile` command, often with a specific target:
   ```bash
   frida compile frida-server
   ```
   or
   ```bash
   frida compile -C build  # If they are not in the build directory
   ```

**What `frida compile` Does:**

The `frida compile` command is a convenience wrapper provided by the Frida tooling. Internally, it:

1. **Locates the `mcompile.py` script:** It knows the relative path to this script within the Frida repository.
2. **Executes `mcompile.py`:** It calls the Python interpreter to run `mcompile.py`, passing along any arguments provided by the user (like the target name).

**As a debugging clue, if a user is encountering issues related to compilation, you might ask them:**

* "What command did you use to trigger the compilation?" (Likely `frida compile ...`)
* "What is the output of that command?" (This will show any error messages from `mcompile.py` or the underlying build system).
* "Have you run `meson setup` in the build directory?"
* "Are you in the correct build directory when running the command?"
* "What target are you trying to build?"

By understanding how users typically reach `mcompile.py`, you can better diagnose and resolve build-related problems within the Frida development environment.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/mcompile.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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