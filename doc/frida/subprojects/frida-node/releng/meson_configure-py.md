Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:**

The core task is to analyze the `meson_configure.py` script, a build configuration tool for Frida. The request asks for its functionalities and connections to reverse engineering, low-level details, and potential user errors.

**2. Initial Skim and Keyword Identification:**

A quick scan reveals keywords and phrases that hint at the script's purpose:

* `argparse`:  Indicates command-line argument parsing.
* `meson`:  Suggests the script interacts with the Meson build system.
* `builddir`, `sourcedir`, `prefix`: Common build system concepts.
* `cross-compile`, `build`, `host`:  Points to cross-compilation capabilities.
* `symbols`, `shared`: Build options.
* `prebuilds`, `toolchain`, `sdk`: Management of pre-built dependencies.
* `linux`, `android`, `kernel`, `framework`: Explicit mentions of target platforms.
* `reverse engineering`, `binary`, `low-level`: Keywords from the request.

**3. Dissecting the Main Function (`main()`):**

This is the entry point. Let's trace its actions:

* **Argument Parsing:**  The script uses `argparse` to handle command-line options like `--prefix`, `--build`, `--host`, etc. This immediately suggests user interaction and configuration.
* **Directory Setup:** It determines source and build directories, showing awareness of where the build process happens.
* **Meson Options:** It reads `meson.options` (or `meson_options.txt`) to load project-specific build options. This is crucial for customizing the Frida build.
* **Configuration Call:**  It calls the `configure()` function, passing the parsed options. This is where the core logic resides.

**4. Analyzing the `configure()` Function (The Heart of the Script):**

This is where the real work happens. Let's analyze its steps:

* **Default Prefix:** Sets a default installation directory.
* **Machine Specification (`MachineSpec`):**  Crucially, it uses `MachineSpec` to represent build and host environments. This is key for cross-compilation.
* **Toolchain and SDK Management:**  The script deals with pre-built toolchains and SDKs. The `--without-prebuilds` option and the `deps` module are central to this. This is a strong link to low-level concerns, as toolchains and SDKs provide the compilers, linkers, and libraries necessary for building binaries for specific platforms.
* **Machine Configuration Generation:** It generates Meson "native" and "cross" files. These files tell Meson about the build and host environments, especially important for cross-compilation.
* **Meson Invocation:**  It calls the Meson command-line tool (`meson setup`). This is the core step that uses all the gathered information to configure the build.
* **Makefile Generation:** It creates `Makefile` and `make.bat` files, making it easier to invoke the build process.
* **Environment Saving:** It saves configuration details in `frida-env.dat` for later use.

**5. Connecting to the Request's Specific Points:**

* **Reverse Engineering:**  Frida itself is a dynamic instrumentation tool used in reverse engineering. This script *configures the build* of Frida. The ability to build Frida with debug symbols (`--enable-symbols`) is directly relevant to reverse engineering, as it makes debugging and analysis easier. The focus on target architectures (`--host`) also aligns with the need to analyze software on different platforms.
* **Binary/Low-Level/Kernel/Framework:**
    * **Binary:** The entire purpose is to build binary executables and libraries.
    * **Low-Level:**  The management of toolchains and SDKs is a low-level concern. Cross-compilation inherently deals with different architectures and ABIs.
    * **Linux/Android Kernel/Framework:**  The `MachineSpec` likely handles details specific to these platforms (e.g., compiler flags, library paths). The `--host` option lets you target Android.
* **Logical Reasoning:**
    * **Input:**  Command-line arguments, environment variables, contents of `meson.options`.
    * **Output:**  A configured build directory with `build.ninja`, `Makefile`, etc. The `frida-env.dat` file also represents output.
    * **Example:** If `--host=android,arm64` is given, the script will fetch or use an Android ARM64 toolchain and configure Meson for that target.
* **User Errors:**
    * **Incorrect Arguments:** Providing invalid `--prefix` paths or incorrect `--build`/`--host` specifications.
    * **Missing Dependencies:** If pre-built toolchains or SDKs are unavailable, the script will error out. The error messages guide the user toward solutions (like using `--without-prebuilds` or building the dependencies manually).
    * **Already Configured:** Trying to run the script in an already configured build directory.
* **User Journey/Debugging:** A user would typically:
    1. Clone the Frida repository.
    2. Navigate to the `frida/subprojects/frida-node/releng/` directory.
    3. Run `./meson_configure.py <path_to_frida_root> [options]`. The script's output (or errors) would be their first clue to success or failure.

**6. Iteration and Refinement:**

After the initial analysis, review the code for specific examples and deeper insights. For instance, look at how `MachineSpec` is used, the logic for handling pre-built dependencies, and the specific Meson options being set. The error handling sections are good places to find examples of user mistakes.

**7. Structuring the Output:**

Organize the findings into clear categories based on the request's requirements (Functionality, Reverse Engineering, Low-Level Details, Logical Reasoning, User Errors, User Journey). Use bullet points and examples to make the information easy to understand.

By following these steps, combining a high-level understanding with detailed code inspection, and connecting the script's actions to the request's specific points, we arrive at a comprehensive analysis like the example provided in the prompt.
This Python script, `meson_configure.py`, located within the Frida project's build system for the Node.js bindings, is responsible for **configuring the build environment** using the Meson build system. It acts as a higher-level configuration tool that simplifies and standardizes the setup process for building Frida's Node.js addon across various platforms and configurations.

Here's a breakdown of its functionalities:

**1. Parsing Command-Line Arguments:**

* It uses `argparse` to handle command-line options provided by the user. These options control various aspects of the build process.
* **Examples:** `--prefix` (installation directory), `--build` (target build machine), `--host` (target host machine for cross-compiling), `--enable-symbols` (include debug symbols), `--enable-shared` (build shared libraries), `--without-prebuilds` (exclude specific prebuilt dependencies).

**2. Determining Source and Build Directories:**

* It intelligently determines the source directory and build directory. It defaults to creating a `build` directory within the source directory unless the `MESON_BUILD_ROOT` environment variable is set.

**3. Handling Prebuilt Dependencies (Toolchain and SDK):**

* It interacts with the `deps` module to manage prebuilt toolchains and SDKs. This is crucial for cross-compilation and for providing necessary build tools without requiring users to install them separately.
* It checks for supported prebuilt bundles and allows users to exclude specific ones using `--without-prebuilds`.
* **Example:** If building for Android on an x86 Linux host, it might download a prebuilt Android NDK (SDK) and a compatible toolchain.

**4. Configuring for Cross-Compilation:**

* It supports cross-compilation by allowing users to specify `--build` and `--host` architectures.
* It uses the `MachineSpec` class to represent and manipulate build and host machine specifications, handling details like operating system, architecture, and potentially the Visual Studio CRT (for Windows).

**5. Generating Meson Configuration Files:**

* It generates Meson "native" and "cross" files based on the provided options and detected environment. These files tell Meson how to configure the build for the target platform.

**6. Invoking Meson:**

* It calls the Meson build system (`meson setup`) with the appropriate options and environment variables. This is the core step that configures the actual build.
* It can use either an internal Meson implementation or the system's Meson installation based on the `--with-meson` option.

**7. Generating Out-of-Tree Makefiles (Optional):**

* It generates `Makefile` and `make.bat` files in the build directory, providing a familiar interface for building the project using `make`.

**8. Saving Configuration Information:**

* It saves the configuration details (like Meson options, build/host machine specifications, and allowed prebuilds) into a `frida-env.dat` file using `pickle`. This allows other scripts or tools to retrieve the configuration later.

**Relationship to Reverse Engineering:**

This script is directly related to reverse engineering because it sets up the build environment for **Frida itself**, which is a powerful dynamic instrumentation toolkit heavily used in reverse engineering.

* **Building Frida with Debug Symbols:** The `--enable-symbols` option is crucial for reverse engineers who want to debug Frida itself or the code they are instrumenting with Frida. Debug symbols allow debuggers to map memory addresses back to source code, making analysis much easier.
* **Cross-Compilation for Target Platforms:**  Reverse engineers often need to analyze software on different platforms (e.g., Android, iOS, embedded Linux). This script's ability to configure cross-compilation is essential for building Frida agents that run on these target devices.
* **Customizing the Build:**  Reverse engineers might need specific build configurations for their analysis. This script provides options to control which features are enabled, whether shared libraries are built, and other aspects of the build process.

**Examples Related to Binary/Low-Level, Linux, Android Kernel & Framework:**

* **Binary Level:** The script ultimately orchestrates the compilation and linking of binary executables and libraries for Frida. Options like `--enable-shared` directly affect the type of binary artifacts produced.
* **Linux Kernel:** When building Frida for Linux, this script (through Meson and the toolchain) will use the standard Linux system libraries and headers. The choice of compiler and linker (determined by the toolchain) is a low-level concern handled during configuration.
* **Android Kernel & Framework:**
    * **Cross-compilation for Android:**  If you use `--host android,arm64` (or a similar specification), the script will ensure that the Android NDK (which contains the Android system libraries and headers) is used for compilation.
    * **Toolchain Selection:** The script, via the `deps` module, might download a specific Android toolchain (e.g., aarch64-linux-android-clang) that contains the compiler, linker, and other tools necessary to build binaries that run on the Android kernel.
    * **SDK Handling:**  The script manages the Android SDK, which provides access to the Android framework APIs. This allows Frida to interact with the Android runtime environment.
    * **Example:**  If building Frida for Android, the `host_machine` specification will trigger the selection of an appropriate Android toolchain. The generated Meson cross-compilation file will specify the compiler and linker from that toolchain, along with the necessary sysroot (the directory containing the Android system libraries).

**Logical Reasoning: Assumptions, Inputs & Outputs:**

**Assumption Example:**

* **Assumption:** If the `--host` option is provided, the user intends to cross-compile.
* **Input:** `--host android,arm64`
* **Output:** The script will attempt to locate or download an Android ARM64 toolchain and configure Meson for cross-compilation to that target. The generated `meson_options.txt` or similar internal Meson data structures will reflect the target architecture and operating system.

**Another Example:**

* **Assumption:** If `--enable-symbols` is given, the user wants debug information included in the built binaries.
* **Input:** `--enable-symbols`
* **Output:** The script will add the `-Dbuildtype=debug` option (or a similar mechanism depending on the Meson project setup) to the Meson configuration, instructing the compiler and linker to include debug symbols.

**User or Programming Common Usage Errors:**

* **Incorrect Toolchain or SDK:** If the user tries to cross-compile without the necessary toolchain or SDK available (and prebuilds are not used or available), the script will likely fail during the Meson setup stage. The error message might indicate missing compilers or libraries.
* **Conflicting Options:** Providing conflicting options (e.g., trying to enable both static and shared linking in a way that's not supported by the build system).
* **Incorrect Machine Specification:** Providing an invalid `--build` or `--host` string that the `MachineSpec.parse()` function cannot understand.
* **Trying to Reconfigure:** Running the script again in the same build directory without cleaning it first. The script detects an existing configuration and prompts the user to wipe the build directory.
* **Permissions Issues:** Not having write permissions to the specified build directory or the prebuilt dependency cache.

**User Operation Steps to Reach This Script (Debugging Context):**

1. **Cloning the Frida Repository:** A developer or user would first clone the Frida repository from GitHub.
2. **Navigating to the Frida Node.js Bindings Directory:** They would navigate to the `frida/subprojects/frida-node/releng/` directory in their terminal.
3. **Attempting to Build Frida's Node.js Addon:** Typically, they would try to build the addon using a command like `npm install` or a similar Node.js build command from the `frida/subprojects/frida-node/` directory.
4. **Build Process Invokes `meson_configure.py`:** The Node.js build process (likely through a `preinstall` script or similar) would invoke `meson_configure.py` to set up the underlying native build environment. This is often done automatically.
5. **Manual Invocation for Customization or Debugging:** A developer might also manually invoke `meson_configure.py` directly from the `releng` directory to:
    * **Customize Build Options:**  Pass specific arguments like `--prefix`, `--host`, `--enable-symbols`.
    * **Troubleshoot Build Issues:** If the automated build fails, they might run the script manually to see the output and errors more directly.
    * **Experiment with Different Configurations:** Try different build settings to understand their impact.

**As a Debugging Clue:** If a user encounters build errors when trying to install the `frida` Node.js package, examining the output of `meson_configure.py` (or attempting to run it manually) can provide valuable insights:

* **Check for Errors in Argument Parsing:** Did the user provide valid options?
* **Dependency Issues:** Did the script fail to find or download necessary prebuilt toolchains or SDKs?
* **Meson Configuration Errors:** Did Meson itself report any errors during the setup phase?
* **Environment Problems:** Are there issues with environment variables or the detected build/host environment?

By understanding the functionality of `meson_configure.py`, developers and users can better diagnose and resolve issues related to building Frida's Node.js bindings.

### 提示词
```
这是目录为frida/subprojects/frida-node/releng/meson_configure.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```