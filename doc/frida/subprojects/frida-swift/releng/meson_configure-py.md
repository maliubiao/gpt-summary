Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `meson_configure.py` script, focusing on its functionality, relevance to reverse engineering, interaction with low-level systems, logical reasoning, potential user errors, and how a user might reach this script.

**2. Initial Scan and High-Level Purpose:**

The filename (`meson_configure.py`) and the imports (`argparse`, `subprocess`, `mesonbuild`) strongly suggest this script is involved in the configuration stage of a build process, specifically using the Meson build system. The `frida/subprojects/frida-swift/releng/` path indicates this is part of the Frida project, likely for configuring the Swift bindings.

**3. Deconstructing Functionality (Core Logic):**

* **Argument Parsing (`argparse`):** The script starts by defining command-line arguments using `argparse`. Key arguments like `--prefix`, `--build`, `--host`, `--enable-symbols`, `--enable-shared`, and `--without-prebuilds` immediately stand out as configuration options. The presence of `meson_options_file` and `register_meson_options` suggests it also handles project-specific Meson options.
* **Configuration Logic (`configure` function):** This is the heart of the script. It takes parsed arguments and performs the actual configuration. Key steps include:
    * Determining source and build directories.
    * Detecting the target platform (build and host machines).
    * Handling prebuilt dependencies (`deps` module).
    * Generating Meson configuration files (`.machine`).
    * Calling the Meson build system (`call_selected_meson`).
    * Creating out-of-tree Makefiles.
    * Saving configuration data.
* **Dependency Management (`deps` module):**  The script heavily relies on a `deps` module. The names `ensure_toolchain`, `ensure_sdk`, `query_supported_bundle_types`, and `detect_cache_dir` imply this module manages downloading or finding prebuilt dependencies (toolchains, SDKs).
* **Machine Specification (`MachineSpec`):**  The `MachineSpec` class is used to represent build and host platforms, encapsulating architecture, OS, and potentially other relevant information.
* **Meson Integration:** The script directly interacts with Meson by calling its `setup` command and passing various options. It also reads `meson.options` to expose project-specific configuration.

**4. Connecting to Reverse Engineering:**

This is where the prompt requires more specific thought.

* **Dynamic Instrumentation (Frida's core):**  The script is part of Frida, a dynamic instrumentation tool. Configuration is a prerequisite for building Frida, which is directly used for reverse engineering.
* **Target Platforms (Android, Linux):** The mention of `--host` and the likely use of Frida on Android and Linux devices connect the configuration process to reverse engineering specific platforms. Cross-compilation is a common scenario.
* **Debugging Symbols (`--enable-symbols`):** Enabling debug symbols is crucial for effective reverse engineering and debugging.
* **Shared Libraries (`--enable-shared`):** Understanding how shared libraries are built and loaded is important for reverse engineering.
* **Prebuilt Dependencies (Toolchains, SDKs):** The ability to build Frida against specific SDKs (e.g., Android SDK) is directly relevant to reverse engineering on those platforms.

**5. Identifying Low-Level Aspects:**

* **Binary Output (Symbols, Shared Libraries):**  The `--enable-symbols` and `--enable-shared` options directly influence the generated binaries.
* **Linux/Android Kernels/Frameworks (SDKs):**  The handling of SDKs, especially the distinction between build and host SDKs in cross-compilation scenarios, points to interaction with target operating system frameworks.
* **Toolchains (Compilers, Linkers):** The script manages toolchains, which are fundamental for compiling code for specific architectures and operating systems.
* **Cross-Compilation:**  The `--build` and `--host` options and the logic around them are core to cross-compilation, a common practice when targeting embedded systems like Android.
* **Environment Variables:** The script reads and uses environment variables (e.g., `VSCMD_ARG_TGT_ARCH`), indicating awareness of the build environment.

**6. Logical Reasoning and Hypothetical Inputs/Outputs:**

This involves considering the "if-then-else" flows within the script.

* **Build Directory Logic:** If the build directory exists and contains a `build.ninja`, the script assumes it's already configured and exits.
* **Prebuilt Dependency Logic:** The script checks the `--without-prebuilds` option and attempts to download or use prebuilt toolchains and SDKs accordingly. If a required prebuilt isn't found, it raises an error.
* **Cross-Compilation Detection:** The script compares `build_machine` and `host_machine` to determine if it's a cross-compilation scenario.
* **Meson Option Generation:** The script dynamically generates Meson options based on the command-line arguments and the parsed `meson.options` file.

For input/output examples, consider scenarios like:

* **Input:** `./releng/meson_configure.py . --prefix=/usr/local`
* **Output:** (Successful configuration in the `./build` directory with installation prefix `/usr/local`).
* **Input:** `./releng/meson_configure.py . --host=arm64-android` (cross-compiling for Android).
* **Output:** (Configuration using an Android toolchain and SDK).
* **Input:** `./releng/meson_configure.py . --without-prebuilds=toolchain`
* **Output:** (Configuration assuming a toolchain is available on the system's PATH).

**7. Common User Errors:**

Think about what could go wrong from a user's perspective.

* **Running in the wrong directory:** Running the script outside the source directory.
* **Not installing dependencies:** Missing system dependencies required by Meson or the build process.
* **Incorrect `--host` specification:** Providing an invalid or unsupported target architecture.
* **Conflicting options:**  Using options that are mutually exclusive or lead to an invalid configuration.
* **Network issues:** Problems downloading prebuilt dependencies.
* **Wiping the build directory incorrectly:** Manually deleting files instead of using Meson's clean command.

**8. Tracing User Actions (Debugging Perspective):**

Imagine a user encountering an issue and needing to debug.

* **Starting Point:** The user likely wants to build Frida for a specific purpose (e.g., reverse engineering an Android app).
* **First Step:**  They would typically follow the project's build instructions, which would involve running the `meson_configure.py` script.
* **Common Issues:**  Errors during configuration, like missing dependencies or toolchain problems, would lead them to examine the script's output and potentially its code.
* **Debugging Techniques:**  They might add print statements, inspect environment variables, or try different command-line options. The script's error messages often guide them towards solutions (e.g., suggesting `--without-prebuilds` or running `deps.py`).

**9. Structuring the Answer:**

Finally, organize the findings into the requested categories: functionality, reverse engineering relevance, low-level aspects, logical reasoning, user errors, and debugging. Use clear headings and examples to illustrate each point. The iterative process of scanning, deconstructing, connecting, and refining helps build a comprehensive understanding of the script's role and inner workings.
This Python script, `meson_configure.py`, is a crucial part of the Frida build process. Its primary function is to **configure the build environment** for Frida's Swift bindings using the Meson build system. It acts as a wrapper around Meson, simplifying the configuration process and handling platform-specific requirements and dependencies.

Here's a breakdown of its functionalities:

**1. Parsing Command-Line Arguments:**

* It uses `argparse` to define and parse various command-line options that control the build process. These options include:
    * `--prefix`:  Specifies the installation directory.
    * `--build`: Defines the machine architecture and operating system for the build process.
    * `--host`: Specifies the target machine architecture and operating system for cross-compilation.
    * `--enable-symbols`:  Enables the inclusion of debugging symbols in the built binaries.
    * `--enable-shared`: Enables the building of shared libraries instead of static libraries.
    * `--with-meson`: Allows the user to choose between the internal (subproject) Meson implementation or a system-wide installation.
    * `--without-prebuilds`: Excludes the usage of prebuilt dependency bundles for specified types (e.g., toolchain, SDK).
    * Project-specific options defined in `meson.options` or `meson_options.txt`.

**2. Determining Build and Host Environments:**

* It uses the `MachineSpec` class to represent the build and host machines, parsing the `--build` and `--host` arguments. If not provided, it attempts to detect the local system's specifications.
* It handles cross-compilation scenarios where the build machine differs from the host machine.

**3. Managing Dependencies (using the `deps` module):**

* It interacts with a `deps` module to manage external dependencies like toolchains and SDKs.
* It can download and extract prebuilt dependency bundles based on the target platform and user options.
* It provides options to exclude specific prebuilt bundles using `--without-prebuilds`.
* It handles cases where prebuilt dependencies are not available, potentially suggesting building from source.

**4. Generating Meson Configuration:**

* It generates Meson configuration files (native and cross-compilation files) based on the detected and specified build/host environments.
* It sets various Meson options, including:
    * `prefix`: Installation prefix.
    * `default_library`:  Whether to build shared or static libraries.
    * Optimization flags based on the target machine.
    * Whether to strip debug symbols.
* It integrates project-specific options defined in `meson.options`.

**5. Calling the Meson Build System:**

* It executes the `meson setup` command with the generated configuration files and options.
* It handles whether to use the internal Meson submodule or a system-wide installation.

**6. Creating Out-of-Tree Build Files:**

* It generates `BSDmakefile` and `Makefile` (and `make.bat` on Windows) in the build directory, allowing users to initiate the build process using standard `make` commands. These Makefiles essentially delegate to the Meson-generated build system.

**7. Saving Configuration Information:**

* It saves relevant configuration details (Meson settings, build/host machine specifications, allowed prebuilds, dependency locations) into a `frida-env.dat` file using `pickle`. This file is likely used by other Frida scripts and build processes.

**Relationship to Reverse Engineering:**

This script plays a vital role in enabling reverse engineering with Frida:

* **Building Frida:**  Frida is a dynamic instrumentation toolkit, and this script configures the build process necessary to compile and install Frida on various platforms (Linux, Android, etc.). Without a properly configured build environment, you cannot build and use Frida for reverse engineering.
* **Targeting Specific Platforms:** The `--host` option is crucial for cross-compiling Frida to target specific architectures and operating systems like Android. Reverse engineers often need to analyze applications on different platforms than their development machine.
    * **Example:** To reverse engineer an Android application, you would use this script with the `--host` option specifying the Android architecture (e.g., `--host=arm64-android`). This ensures Frida is built to run on an Android device.
* **Enabling Debugging Symbols:** The `--enable-symbols` option is essential for reverse engineering as it includes debugging information in the Frida binaries. This makes it easier to debug Frida itself or understand its behavior when interacting with target processes. Debug symbols are invaluable when using debuggers like GDB or LLDB.
    * **Example:**  If you are developing a Frida script and it's crashing, building Frida with `--enable-symbols` allows you to step through the Frida code and pinpoint the issue.
* **Shared Libraries:** The `--enable-shared` option determines how Frida's components are linked. Shared libraries are the typical way software is distributed and loaded on many systems. Understanding how Frida's shared libraries are built is important for understanding its architecture and how it interacts with target processes.
* **Prebuilt Dependencies:** The script's ability to handle prebuilt toolchains and SDKs significantly simplifies the process of building Frida for different platforms. This is particularly important for complex environments like Android, where setting up the correct build tools can be challenging.

**Involvement of Binary Underpinnings, Linux/Android Kernel & Frameworks:**

This script interacts with these low-level aspects in several ways:

* **Toolchains:** The script manages the selection and use of appropriate toolchains (compilers, linkers, etc.) for the target architecture. This is fundamental to generating executable binaries from source code. Different architectures (ARM, x86) and operating systems require specific toolchains.
    * **Example:** When targeting Android, the script will attempt to use the Android NDK (Native Development Kit) toolchain. This involves locating the NDK and configuring Meson to use its compilers and linkers.
* **SDKs (Software Development Kits):** For cross-compilation, especially to platforms like Android, the script needs access to the target platform's SDK. The SDK provides header files, libraries, and other resources necessary to build software that interacts with the target operating system's APIs.
    * **Example:** When building for Android, the script might download or locate the Android SDK, which contains the necessary header files for interacting with the Android framework.
* **Operating System Specifics:** The script uses `platform.system()` to detect the host operating system and potentially adjust the build process accordingly (e.g., generating `make.bat` on Windows).
* **Cross-Compilation:** The entire logic around the `--build` and `--host` options directly addresses the complexities of cross-compilation, where the build system needs to be configured to produce binaries for a different architecture and operating system than the one it's running on.
* **Environment Variables:** The script interacts with environment variables like `VSCMD_ARG_TGT_ARCH` (on Windows) to get information about the build environment. This is a common way to pass information to build systems.
* **File System Operations:** The script creates directories, copies files, and writes to files, all fundamental operations related to managing the build environment on the underlying operating system.

**Logical Reasoning and Hypothetical Input/Output:**

Let's consider some examples:

**Hypothetical Input 1:**

```bash
./releng/meson_configure.py . --prefix=/opt/frida --host=arm-linux-gnueabihf --enable-shared
```

**Assumptions:**

* The script is run from the Frida source directory.
* The user has a suitable ARM Linux toolchain available (either via prebuilt or system installation).

**Logical Reasoning:**

1. The script parses the arguments:
   - `prefix`: `/opt/frida` (installation directory)
   - `host`: `arm-linux-gnueabihf` (target architecture is ARM for Linux)
   - `enable-shared`: True (build shared libraries)
2. It detects that this is a cross-compilation scenario because the host is different from the build machine (assuming the build machine is not ARM Linux).
3. It attempts to find or download a prebuilt toolchain and potentially an SDK for `arm-linux-gnueabihf`. If `--without-prebuilds` is not specified.
4. It generates a Meson cross-compilation file targeting ARM Linux.
5. It calls `meson setup` with the appropriate options, including `-Dprefix=/opt/frida` and `-Ddefault_library=shared`.

**Hypothetical Output 1:**

* A `build` directory is created.
* Meson configuration files are generated inside the `build` directory.
* `BSDmakefile`, `Makefile` are created in the `build` directory.
* If prebuilt dependencies were used, they would have been downloaded and extracted.
* The `frida-env.dat` file would contain information about the ARM Linux host and the chosen configuration.

**Hypothetical Input 2:**

```bash
./releng/meson_configure.py . --enable-symbols
```

**Assumptions:**

* The script is run from the Frida source directory.
* The target is the local machine (no `--host` specified).

**Logical Reasoning:**

1. The script parses the arguments: `enable-symbols`: True.
2. It detects that the build and host machines are the same (local build).
3. It generates a Meson native configuration file.
4. It calls `meson setup` with the option `-Dstrip=false` (or similar, depending on the exact Meson implementation) to include debug symbols.

**Hypothetical Output 2:**

* A `build` directory is created.
* Meson configuration files are generated inside the `build` directory.
* `BSDmakefile`, `Makefile` are created in the `build` directory.
* The resulting Frida binaries built using this configuration will contain debugging symbols.

**User or Programming Common Usage Errors:**

* **Running the script outside the source directory:** The script expects to find `meson.options` (or `meson_options.txt`) in the source directory. Running it elsewhere will lead to an error.
    * **Example Error:** `FileNotFoundError: [Errno 2] No such file or directory: 'meson.options'`
* **Not having Meson installed or in the PATH:** The script relies on the Meson build system. If it's not installed or the `meson` executable is not in the system's PATH, the script will fail.
    * **Example Error:**  If using system Meson: `FileNotFoundError: [Errno 2] No such file or directory: 'meson'`
* **Providing an invalid `--host` string:** The `MachineSpec.parse` function might raise an exception if the `--host` string is not in a recognizable format.
    * **Example Error:** `ValueError: Invalid machine spec: 'invalid-host'`
* **Network issues preventing download of prebuilt dependencies:** If the script tries to download prebuilt toolchains or SDKs and the network connection fails, it will result in an error.
    * **Example Error:**  Exceptions related to network timeouts or file download failures.
* **Trying to use prebuilt dependencies without the necessary tools (e.g., `tar`):** The script might rely on certain system tools to extract prebuilt archives. If these tools are missing, the process will fail.
    * **Example Error:** `FileNotFoundError: [Errno 2] No such file or directory: 'tar'`
* **Mixing `--without-prebuilds` incorrectly:**  Specifying an invalid or unsupported bundle type for `--without-prebuilds` will cause an `argparse.ArgumentTypeError`.
    * **Example Error:** `argparse.ArgumentTypeError: invalid bundle type: 'invalid-bundle' (choose from 'toolchain', 'sdk:build', 'sdk:host')`
* **Wiping the build directory incorrectly:** If the user manually deletes the `build` directory instead of using Meson's `meson distclean` command, it might lead to inconsistencies in subsequent configurations.

**User Operations Leading to This Script (Debugging Clues):**

A user would typically reach this script as part of the Frida build process. Here's a likely sequence of steps:

1. **Cloning the Frida repository:** The user would have cloned the Frida Git repository, which includes this `meson_configure.py` script within the `frida/subprojects/frida-swift/releng/` directory.
2. **Navigating to the Frida source directory:** The user would change their current directory to the root of the Frida repository.
3. **Attempting to build Frida:**  The user would likely consult the Frida documentation or build instructions, which would guide them to run the `meson_configure.py` script.
4. **Running the `meson_configure.py` script:** The user would execute the script from the command line, potentially with specific options depending on their target platform and desired build configuration. This is the point where the script's logic comes into play.

**As a debugging clue:**

* If a user reports issues during the Frida build process, especially during the configuration stage, this `meson_configure.py` script is a prime suspect.
* Examining the command-line arguments used by the user when running the script is crucial. Incorrect or missing arguments can lead to configuration errors.
* Checking the output of the script for error messages can provide valuable insights into what went wrong (e.g., missing dependencies, invalid options).
* Investigating the contents of the generated `build` directory, including the Meson log files (`meson-log.txt`) and the generated configuration files, can reveal details about the configured environment.
* Examining the `frida-env.dat` file can help understand the final configuration that was saved.
* If prebuilt dependencies are involved, checking the `deps` directory (or the configured cache directory) can help determine if the necessary bundles were downloaded correctly.

In summary, `meson_configure.py` is the entry point for configuring the Frida Swift bindings build process. It orchestrates the interaction with Meson, manages dependencies, and allows users to customize the build for various platforms and scenarios, playing a foundational role in enabling Frida's dynamic instrumentation capabilities, often used in reverse engineering.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson_configure.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
import argparse
import os
from pathlib import Path
import pickle
import platform
import re
import shlex
import shutil
import subprocess
import sys
from typing import Any, Callable, Optional

RELENG_DIR = Path(__file__).resolve().parent
SCRIPTS_DIR = RELENG_DIR / "meson-scripts"

sys.path.insert(0, str(RELENG_DIR / "meson"))
import mesonbuild.interpreter
from mesonbuild.coredata import UserArrayOption, UserBooleanOption, \
        UserComboOption, UserFeatureOption, UserOption, UserStringOption

from . import deps, env
from .machine_spec import MachineSpec
from .progress import ProgressCallback, print_progress


def main():
    default_sourcedir = Path(sys.argv.pop(1))
    sourcedir = Path(os.environ.get("MESON_SOURCE_ROOT", default_sourcedir)).resolve()

    workdir = Path(os.getcwd())
    if workdir == sourcedir:
        default_builddir = sourcedir / "build"
    else:
        default_builddir = workdir
    builddir = Path(os.environ.get("MESON_BUILD_ROOT", default_builddir)).resolve()

    parser = argparse.ArgumentParser(prog="configure",
                                     add_help=False)
    opts = parser.add_argument_group(title="generic options")
    opts.add_argument("-h", "--help",
                      help="show this help message and exit",
                      action="help")
    opts.add_argument("--prefix",
                      help="install files in PREFIX",
                      metavar="PREFIX",
                      type=parse_prefix)
    opts.add_argument("--build",
                      help="configure for building on BUILD",
                      metavar="BUILD",
                      type=MachineSpec.parse)
    opts.add_argument("--host",
                      help="cross-compile to build binaries to run on HOST",
                      metavar="HOST",
                      type=MachineSpec.parse)
    opts.add_argument("--enable-symbols",
                      help="build binaries with debug symbols included (default: disabled)",
                      action="store_true")
    opts.add_argument("--enable-shared",
                      help="enable building shared libraries (default: disabled)",
                      action="store_true")
    opts.add_argument("--with-meson",
                      help="which Meson implementation to use (default: internal)",
                      choices=["internal", "system"],
                      dest="meson",
                      default="internal")
    opts.add_argument(f"--without-prebuilds",
                      help="do not make use of prebuilt bundles",
                      metavar="{" + ",".join(query_supported_bundle_types(include_wildcards=True)) + "}",
                      type=parse_bundle_type_set,
                      default=set())
    opts.add_argument("extra_meson_options",
                      nargs="*",
                      help=argparse.SUPPRESS)

    meson_options_file = sourcedir / "meson.options"
    if not meson_options_file.exists():
        meson_options_file = sourcedir / "meson_options.txt"
    if meson_options_file.exists():
        meson_group = parser.add_argument_group(title="project-specific options")
        meson_opts = register_meson_options(meson_options_file, meson_group)

    options = parser.parse_args()

    if builddir.exists():
        if (builddir / "build.ninja").exists():
            print(f"Already configured. Wipe .{os.sep}{builddir.relative_to(workdir)} to reconfigure.",
                  file=sys.stderr)
            sys.exit(1)

    default_library = "shared" if options.enable_shared else "static"

    allowed_prebuilds = set(query_supported_bundle_types(include_wildcards=False)) - options.without_prebuilds

    try:
        configure(sourcedir,
                  builddir,
                  options.prefix,
                  options.build,
                  options.host,
                  os.environ,
                  "included" if options.enable_symbols else "stripped",
                  default_library,
                  allowed_prebuilds,
                  options.meson,
                  collect_meson_options(options))
    except Exception as e:
        print(e, file=sys.stderr)
        if isinstance(e, subprocess.CalledProcessError):
            for label, data in [("Output", e.output),
                                ("Stderr", e.stderr)]:
                if data:
                    print(f"{label}:\n\t| " + "\n\t| ".join(data.strip().split("\n")), file=sys.stderr)
        sys.exit(1)


def configure(sourcedir: Path,
              builddir: Path,
              prefix: Optional[str] = None,
              build_machine: Optional[MachineSpec] = None,
              host_machine: Optional[MachineSpec] = None,
              environ: dict[str, str] = os.environ,
              debug_symbols: str = "stripped",
              default_library: str = "static",
              allowed_prebuilds: set[str] = None,
              meson: str = "internal",
              extra_meson_options: list[str] = [],
              call_meson: Callable = env.call_meson,
              on_progress: ProgressCallback = print_progress):
    if prefix is None:
        prefix = env.detect_default_prefix()

    project_vscrt = detect_project_vscrt(sourcedir)

    if build_machine is None:
        build_machine = MachineSpec.make_from_local_system()
    build_machine = build_machine.default_missing(recommended_vscrt=project_vscrt)

    if host_machine is None:
        host_machine = build_machine
    else:
        host_machine = host_machine.default_missing(recommended_vscrt=project_vscrt)

    if host_machine.os == "windows":
        vs_arch = environ.get("VSCMD_ARG_TGT_ARCH")
        if vs_arch == "x86":
            host_machine = host_machine.evolve(arch=vs_arch)

    build_machine = build_machine.maybe_adapt_to_host(host_machine)

    if allowed_prebuilds is None:
        allowed_prebuilds = set(query_supported_bundle_types(include_wildcards=False))

    call_selected_meson = lambda argv, *args, **kwargs: call_meson(argv,
                                                                   use_submodule=meson == "internal",
                                                                   *args,
                                                                   **kwargs)

    meson_options = [
        f"-Dprefix={prefix}",
        f"-Ddefault_library={default_library}",
        *host_machine.meson_optimization_options,
    ]
    if debug_symbols == "stripped" and host_machine.toolchain_can_strip:
        meson_options += ["-Dstrip=true"]

    deps_dir = deps.detect_cache_dir(sourcedir)

    allow_prebuilt_toolchain = "toolchain" in allowed_prebuilds
    if allow_prebuilt_toolchain:
        try:
            toolchain_prefix, _ = deps.ensure_toolchain(build_machine, deps_dir, on_progress=on_progress)
        except deps.BundleNotFoundError as e:
            raise_toolchain_not_found(e)
    else:
        if project_depends_on_vala_compiler(sourcedir):
            toolchain_prefix = deps.query_toolchain_prefix(build_machine, deps_dir)
            vala_compiler = env.detect_toolchain_vala_compiler(toolchain_prefix, build_machine)
            if vala_compiler is None:
                build_vala_compiler(toolchain_prefix, deps_dir, call_selected_meson)
        else:
            toolchain_prefix = None

    is_cross_build = host_machine != build_machine

    build_sdk_prefix = None
    required = {"sdk:build"}
    if not is_cross_build:
        required.add("sdk:host")
    if allowed_prebuilds.issuperset(required):
        try:
            build_sdk_prefix, _ = deps.ensure_sdk(build_machine, deps_dir, on_progress=on_progress)
        except deps.BundleNotFoundError as e:
            raise_sdk_not_found(e, "build", build_machine)

    host_sdk_prefix = None
    if is_cross_build and "sdk:host" in allowed_prebuilds:
        try:
            host_sdk_prefix, _ = deps.ensure_sdk(host_machine, deps_dir, on_progress=on_progress)
        except deps.BundleNotFoundError as e:
            raise_sdk_not_found(e, "host", host_machine)

    build_config, host_config = \
            env.generate_machine_configs(build_machine,
                                         host_machine,
                                         environ,
                                         toolchain_prefix,
                                         build_sdk_prefix,
                                         host_sdk_prefix,
                                         call_selected_meson,
                                         default_library,
                                         builddir)

    meson_options += [f"--native-file={build_config.machine_file}"]
    if host_config is not build_config:
        meson_options += [f"--cross-file={host_config.machine_file}"]

    setup_env = host_config.make_merged_environment(environ)
    setup_env["FRIDA_ALLOWED_PREBUILDS"] = ",".join(allowed_prebuilds)

    call_selected_meson(["setup"] + meson_options + extra_meson_options + [builddir],
                        cwd=sourcedir,
                        env=setup_env,
                        check=True)

    shutil.copy(SCRIPTS_DIR / "BSDmakefile", builddir)
    (builddir / "Makefile").write_text(generate_out_of_tree_makefile(sourcedir), encoding="utf-8")
    if platform.system() == "Windows":
        (builddir / "make.bat").write_text(generate_out_of_tree_make_bat(sourcedir), encoding="utf-8")

    (builddir / "frida-env.dat").write_bytes(pickle.dumps({
        "meson": meson,
        "build": build_config,
        "host": host_config if host_config is not build_config else None,
        "allowed_prebuilds": allowed_prebuilds,
        "deps": deps_dir,
    }))


def parse_prefix(raw_prefix: str) -> Path:
    prefix = Path(raw_prefix)
    if not prefix.is_absolute():
        prefix = Path(os.getcwd()) / prefix
    return prefix


def query_supported_bundle_types(include_wildcards: bool) -> list[str]:
    for e in deps.Bundle:
        identifier = e.name.lower()
        if e == deps.Bundle.SDK:
            if include_wildcards:
                yield identifier
            yield identifier + ":build"
            yield identifier + ":host"
        else:
            yield identifier


def query_supported_bundle_type_values() -> list[deps.Bundle]:
    return [e for e in deps.Bundle]


def parse_bundle_type_set(raw_array: str) -> list[str]:
    supported_types = list(query_supported_bundle_types(include_wildcards=True))
    result = set()
    for element in raw_array.split(","):
        bundle_type = element.strip()
        if bundle_type not in supported_types:
            pretty_choices = "', '".join(supported_types)
            raise argparse.ArgumentTypeError(f"invalid bundle type: '{bundle_type}' (choose from '{pretty_choices}')")
        if bundle_type == "sdk":
            result.add("sdk:build")
            result.add("sdk:host")
        else:
            result.add(bundle_type)
    return result


def raise_toolchain_not_found(e: Exception):
    raise ToolchainNotFoundError("\n".join([
        f"Unable to download toolchain: {e}",
        "",
        "Specify --without-prebuilds=toolchain to only use tools on your PATH.",
        "",
        "Another option is to do what Frida's CI does:",
        "",
        "    ./releng/deps.py build --bundle=toolchain",
        "",
        "This produces a tarball in ./deps which gets picked up if you retry `./configure`.",
        "You may also want to make a backup of it for future reuse.",
    ]))


def raise_sdk_not_found(e: Exception, kind: str, machine: MachineSpec):
    raise SDKNotFoundError("\n".join([
        f"Unable to download SDK: {e}",
        "",
        f"Specify --without-prebuilds=sdk:{kind} to build dependencies from source code.",
        "",
        "Another option is to do what Frida's CI does:",
        "",
        f"    ./releng/deps.py build --bundle=sdk --host={machine.identifier}",
        "",
        "This produces a tarball in ./deps which gets picked up if you retry `./configure`.",
        "You may also want to make a backup of it for future reuse.",
    ]))


def generate_out_of_tree_makefile(sourcedir: Path) -> str:
    m = ((SCRIPTS_DIR / "Makefile").read_text(encoding="utf-8")
            .replace("sys.argv[1]", "r'" + str(RELENG_DIR.parent) + "'")
            .replace('"$(shell pwd)"', shlex.quote(str(sourcedir)))
            .replace("./build", "."))
    return re.sub(r"git-submodules:.+?(?=\.PHONY:)", "", m, flags=re.MULTILINE | re.DOTALL)


def generate_out_of_tree_make_bat(sourcedir: Path) -> str:
    m = ((SCRIPTS_DIR / "make.bat").read_text(encoding="utf-8")
            .replace("sys.argv[1]", "r'" + str(RELENG_DIR.parent) + "'")
            .replace('"%dp0%"', '"' + str(sourcedir) + '"')
            .replace('.\\build', "\"%dp0%\""))
    return re.sub(r"if not exist .+?(?=endlocal)", "", m, flags=re.MULTILINE | re.DOTALL)


def register_meson_options(meson_option_file: Path, group: argparse._ArgumentGroup):
    interpreter = mesonbuild.optinterpreter.OptionInterpreter(subproject="")
    interpreter.process(meson_option_file)

    for key, opt in interpreter.options.items():
        name = key.name
        pretty_name = name.replace("_", "-")

        if isinstance(opt, UserFeatureOption):
            if opt.value != "enabled":
                action = "enable"
                value_to_set = "enabled"
            else:
                action = "disable"
                value_to_set = "disabled"
            group.add_argument(f"--{action}-{pretty_name}",
                               action="append_const",
                               const=f"-D{name}={value_to_set}",
                               dest="main_meson_options",
                               **parse_option_meta(name, action, opt))
            if opt.value == "auto":
                group.add_argument(f"--disable-{pretty_name}",
                                   action="append_const",
                                   const=f"-D{name}=disabled",
                                   dest="main_meson_options",
                                   **parse_option_meta(name, "disable", opt))
        elif isinstance(opt, UserBooleanOption):
            if not opt.value:
                action = "enable"
                value_to_set = "true"
            else:
                action = "disable"
                value_to_set = "false"
            group.add_argument(f"--{action}-{pretty_name}",
                               action="append_const",
                               const=f"-D{name}={value_to_set}",
                               dest="main_meson_options",
                               **parse_option_meta(name, action, opt))
        elif isinstance(opt, UserComboOption):
            group.add_argument(f"--with-{pretty_name}",
                               choices=opt.choices,
                               dest="meson_option:" + name,
                               **parse_option_meta(name, "with", opt))
        elif isinstance(opt, UserArrayOption):
            group.add_argument(f"--with-{pretty_name}",
                               dest="meson_option:" + name,
                               type=make_array_option_value_parser(opt),
                               **parse_option_meta(name, "with", opt))
        else:
            group.add_argument(f"--with-{pretty_name}",
                               dest="meson_option:" + name,
                               **parse_option_meta(name, "with", opt))


def parse_option_meta(name: str,
                      action: str,
                      opt: UserOption[Any]):
    params = {}

    if isinstance(opt, UserStringOption):
        default_value = repr(opt.value)
        metavar = name.upper()
    elif isinstance(opt, UserArrayOption):
        default_value = ",".join(opt.value)
        metavar = "{" + ",".join(opt.choices) + "}"
    elif isinstance(opt, UserComboOption):
        default_value = opt.value
        metavar = "{" + "|".join(opt.choices) + "}"
    else:
        default_value = str(opt.value).lower()
        metavar = name.upper()

    if not (isinstance(opt, UserFeatureOption) \
            and opt.value == "auto" \
            and action == "disable"):
        text = f"{help_text_from_meson(opt.description)} (default: {default_value})"
        if action == "disable":
            text = "do not " + text
        params["help"] = text
    params["metavar"] = metavar

    return params


def help_text_from_meson(description: str) -> str:
    if description:
        return description[0].lower() + description[1:]
    return description


def collect_meson_options(options: argparse.Namespace) -> list[str]:
    result = []

    for raw_name, raw_val in vars(options).items():
        if raw_val is None:
            continue
        if raw_name == "main_meson_options":
            result += raw_val
        if raw_name.startswith("meson_option:"):
            name = raw_name[13:]
            val = raw_val if isinstance(raw_val, str) else ",".join(raw_val)
            result += [f"-D{name}={val}"]

    result += options.extra_meson_options

    return result


def make_array_option_value_parser(opt: UserOption[Any]) -> Callable[[str], list[str]]:
    return lambda v: parse_array_option_value(v, opt)


def parse_array_option_value(v: str, opt: UserArrayOption) -> list[str]:
    vals = [v.strip() for v in v.split(",")]

    choices = opt.choices
    for v in vals:
        if v not in choices:
            pretty_choices = "', '".join(choices)
            raise argparse.ArgumentTypeError(f"invalid array value: '{v}' (choose from '{pretty_choices}')")

    return vals


def detect_project_vscrt(sourcedir: Path) -> Optional[str]:
    m = next(re.finditer(r"project\(([^)]+\))", read_meson_build(sourcedir)), None)
    if m is not None:
        project_args = m.group(1)
        m = next(re.finditer("'b_vscrt=([^']+)'", project_args), None)
        if m is not None:
            return m.group(1)
    return None


def project_depends_on_vala_compiler(sourcedir: Path) -> bool:
    return "'vala'" in read_meson_build(sourcedir)


def read_meson_build(sourcedir: Path) -> str:
    return (sourcedir / "meson.build").read_text(encoding="utf-8")


def build_vala_compiler(toolchain_prefix: Path, deps_dir: Path, call_selected_meson: Callable):
    print("Building Vala compiler...", flush=True)

    workdir = deps_dir / "src"
    workdir.mkdir(parents=True, exist_ok=True)

    git = lambda *args, **kwargs: subprocess.run(["git", *args],
                                                 **kwargs,
                                                 capture_output=True,
                                                 encoding="utf-8")
    vala_checkout = workdir / "vala"
    if vala_checkout.exists():
        shutil.rmtree(vala_checkout)
    vala_pkg = deps.load_dependency_parameters().packages["vala"]
    deps.clone_shallow(vala_pkg, vala_checkout, git)

    run_kwargs = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "encoding": "utf-8",
        "check": True,
    }
    call_selected_meson([
                            "setup",
                            f"--prefix={toolchain_prefix}",
                            "-Doptimization=2",
                            "build",
                        ],
                        cwd=vala_checkout,
                        **run_kwargs)
    call_selected_meson(["install"],
                        cwd=vala_checkout / "build",
                        **run_kwargs)


class ToolchainNotFoundError(Exception):
    pass


class SDKNotFoundError(Exception):
    pass

"""

```