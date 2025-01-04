Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Core Purpose:**

The first step is to read the initial lines and the `main()` function to grasp the script's primary goal. Keywords like "configure," "meson," "build," "host," and the handling of command-line arguments immediately suggest this script is responsible for setting up a build environment, likely using the Meson build system. The file path `frida/subprojects/frida-gum/releng/meson_configure.py` reinforces this, as "releng" often stands for release engineering or related tasks.

**2. Deconstructing the Functionality (Top-Down):**

After understanding the core purpose, I'd go through the major functions, starting with `main()`. For each function, I'd ask:

* **What are its inputs?** (Arguments, environment variables)
* **What does it do?** (Core logic, calls to other functions)
* **What are its outputs?** (Return values, side effects like file creation)

**For `main()`:**

* **Inputs:** Command-line arguments, environment variables (`MESON_SOURCE_ROOT`, `MESON_BUILD_ROOT`).
* **Does:** Parses arguments, determines source and build directories, handles the "already configured" case, calls the `configure()` function.
* **Outputs:**  Exits the script (potentially with an error code), prints messages to stderr.

**For `configure()`:**

* **Inputs:**  Numerous arguments specifying directories, machine specifications (build, host), environment, build options (debug symbols, shared libraries), allowed prebuilds, and a `call_meson` function.
* **Does:** Detects default prefix, determines project's Visual Studio CRT (Windows specific), sets up `MachineSpec` objects, handles prebuilt dependencies (toolchain, SDK), generates Meson configuration files (`native-file`, `cross-file`), calls the Meson `setup` command, creates Makefiles and a `frida-env.dat` file.
* **Outputs:** Potentially raises exceptions, creates build configuration files and Makefiles.

**3. Identifying Key Areas based on the Prompt's Requirements:**

Now, I'd focus on the specific aspects requested in the prompt:

* **Functionality:**  This is addressed by the deconstruction above.
* **Relationship to Reverse Engineering:** I look for actions that facilitate inspecting or manipulating running processes. The configuration of build options like debug symbols (`--enable-symbols`) and the concept of building shared libraries (which can be injected) are relevant. The prebuilt toolchains and SDKs are tools *used* in reverse engineering workflows, even if this script isn't directly performing reverse engineering.
* **Binary/Low-Level/Kernel/Framework:** I search for code that interacts with operating system features, hardware architecture, or specific frameworks like Android. The `MachineSpec` class, the handling of cross-compilation (`--host`), and mentions of Windows (`VSCMD_ARG_TGT_ARCH`) and SDKs point to this.
* **Logic Reasoning:**  Look for conditional statements, loops, and any decision-making based on input. The handling of default values, checking for existing build directories, and the logic for enabling/disabling features based on options are examples. I'd try to trace the flow for specific inputs.
* **User Errors:** Consider what could go wrong from a user's perspective. Incorrect command-line arguments, missing dependencies, and attempting to configure an already configured project are common errors.
* **User Path to this Script (Debugging):**  Think about the context in which this script is used. It's part of the Frida build process. A user would typically run this after cloning the Frida repository to set up the build. Failed builds or a desire to customize the build would lead them here for debugging.

**4. Deep Dive into Specific Code Sections:**

Once the high-level understanding is there, I'd zoom in on specific code blocks:

* **Argument Parsing:** How are command-line options defined and processed?  This tells me what the user can control.
* **`MachineSpec`:**  What information does it encapsulate? How is it used to tailor the build?
* **Dependency Handling (`deps` module):** How are prebuilt toolchains and SDKs managed?  This connects to the "binary/low-level" aspect.
* **Meson Integration:** How is Meson invoked? What options are passed to it?
* **Makefile Generation:**  What is the purpose of these Makefiles?  How do they relate to the build process?

**5. Formulating Examples:**

For each area (reverse engineering, low-level, logic, errors), I'd create concrete examples:

* **Reverse Engineering:** Emphasize debug symbols, shared libraries for injection.
* **Low-Level:** Explain cross-compilation, the role of toolchains and SDKs, and platform-specific logic.
* **Logic:** Choose simple scenarios, like enabling a feature or handling default values, and trace the code flow.
* **User Errors:**  Pick common mistakes like invalid arguments or trying to reconfigure.

**6. Structuring the Answer:**

Finally, I'd organize the information logically, using the prompt's questions as a guide. Clear headings and bullet points make the answer easier to read and understand. I'd start with a summary of the script's purpose, then address each specific requirement with explanations and examples.

**Self-Correction/Refinement:**

Throughout this process, I'd continually review and refine my understanding. For example, if I initially missed the significance of the `deps` module, I'd go back and investigate it further. If an example wasn't clear, I'd try to rephrase it or provide more context. I'd also ensure that the examples directly relate to the code and the prompt's questions.
这个Python脚本 `meson_configure.py` 的主要功能是**配置 Frida 工具链的构建环境**。它是一个用于 Frida 项目的自定义配置脚本，基于 Meson 构建系统，用于生成构建系统所需的配置文件。

让我们详细列举它的功能，并结合你的问题进行分析：

**1. 解析命令行参数：**

*   脚本使用 `argparse` 模块来处理用户提供的命令行参数，例如 `--prefix`（安装路径），`--build`（构建平台），`--host`（目标平台），`--enable-symbols`（启用调试符号），`--enable-shared`（启用共享库）等。
*   这些参数允许用户自定义 Frida 的构建方式，例如交叉编译到不同的目标架构。

**与逆向方法的关系：**

*   **启用调试符号 (`--enable-symbols`)**:  这直接关系到逆向工程。启用调试符号后，生成的可执行文件和库会包含调试信息，例如变量名、函数名、行号等。这使得使用调试器（如 GDB 或 LLDB）来分析 Frida 运行时行为变得更加容易。逆向工程师可以使用这些信息来理解代码逻辑、查找漏洞或分析恶意软件的行为。
    *   **举例说明：** 逆向工程师想要调试 Frida Gum 引擎的某个特定功能。在配置 Frida 时，他们会使用 `--enable-symbols` 选项。这样，在 Gum 引擎的动态库被加载到目标进程后，他们可以使用 GDB 并设置断点在特定的函数上，并查看局部变量的值，从而更深入地理解其工作原理。
*   **构建共享库 (`--enable-shared`)**:  Frida 的核心功能之一是动态注入代码到目标进程。通常，Frida 的 Agent 部分会以共享库的形式注入到目标进程中。因此，`--enable-shared` 选项直接影响了 Frida 是否能够以这种方式工作。
    *   **举例说明：**  逆向工程师想要编写一个 Frida 脚本来 hook 某个 Android 应用的特定函数。为了实现这一点，他们需要 Frida Gum 能够构建成共享库，以便可以将其注入到目标 Android 进程中。

**2. 处理构建和宿主平台信息：**

*   使用 `MachineSpec` 类来解析和表示构建平台 (`--build`) 和宿主平台 (`--host`) 的信息。这对于交叉编译至关重要。
*   脚本能够检测本地系统信息作为默认的构建平台。

**涉及到二进制底层，Linux, Android内核及框架的知识：**

*   **交叉编译 (`--host`)**:  交叉编译是指在一个平台上编译出可以在另一个平台上运行的代码。Frida 经常需要交叉编译到不同的架构（例如，在 x86-64 Linux 上编译运行在 ARM Android 设备上的 Frida Gum）。这涉及到对目标平台的 CPU 架构、操作系统、ABI（应用程序二进制接口）等底层细节的理解。
    *   **举例说明：** 逆向工程师在 Linux PC 上开发 Frida 脚本，目标是在运行 Android 的 ARM 设备上使用。他们需要使用 `--host` 参数指定目标平台为 ARM Android，例如 `--host=arm64-android`。脚本会根据这个参数配置交叉编译工具链和相关的构建选项。
*   **工具链 (Toolchain)**: 脚本会尝试使用预构建的工具链，或者在必要时构建 Vala 编译器。工具链是一组用于编译、汇编和链接代码的程序，对于交叉编译来说，需要为目标平台准备合适的工具链。
    *   **举例说明：** 当交叉编译到 Android 时，需要使用 Android NDK (Native Development Kit) 提供的工具链，其中包括针对 ARM 或 AArch64 架构的编译器和链接器。
*   **SDK (Software Development Kit)**: 脚本也会处理预构建的 SDK。对于 Frida 来说，SDK 可能包含目标平台的头文件、库文件等，这些是在编译过程中需要的。
    *   **举例说明：**  在为 Android 构建 Frida 时，需要 Android SDK 中提供的头文件来访问 Android 系统的 API。
*   **`.meson` 配置文件 (e.g., `native-file`, `cross-file`)**: 脚本会生成 Meson 构建系统使用的配置文件，这些文件包含了针对构建平台和宿主平台的详细信息，例如编译器路径、链接器选项、系统库路径等。这些配置直接映射到二进制文件的生成过程。
*   **环境变量 (Environment Variables)**: 脚本会读取和设置环境变量，例如 `VSCMD_ARG_TGT_ARCH` (Windows 下用于指定目标架构)，`FRIDA_ALLOWED_PREBUILDS` 等。这些环境变量会影响构建过程中的工具选择和行为。

**3. 管理预构建依赖：**

*   脚本使用了 `deps` 模块来管理预构建的依赖项，例如工具链和 SDK。
*   它允许用户通过 `--without-prebuilds` 参数禁用某些预构建依赖的使用。
*   如果找不到预构建的依赖，脚本会提供有用的提示信息，指导用户如何获取或构建它们。

**如果做了逻辑推理，请给出假设输入与输出：**

*   **假设输入：** 用户执行命令 `./releng/meson_configure.py . --enable-symbols --host=arm64-linux-gnu`
*   **逻辑推理：**
    *   脚本解析命令行参数，得知用户想要在当前目录下配置构建（`.` 表示当前源码目录）。
    *   用户启用了调试符号 (`--enable-symbols`)。
    *   目标平台是 `arm64-linux-gnu`，表示交叉编译到 64 位 ARM Linux 系统。
    *   脚本会检查是否存在 `build` 目录，如果存在并且已经配置过，则会报错退出。
    *   脚本会尝试找到或下载适用于 `arm64-linux-gnu` 的工具链和 SDK 预构建包。
    *   脚本会生成 Meson 的 `native-file` 和 `cross-file`，其中 `cross-file` 会包含针对 `arm64-linux-gnu` 平台的编译器和链接器配置。
*   **输出：**
    *   如果一切顺利，会在当前目录下创建 `build` 目录，并在其中生成 Meson 构建文件 (`build.ninja`) 和相关的配置文件（`native-file`, `cross-file`）。
    *   如果找不到预构建的工具链或 SDK，可能会输出错误信息，并建议用户如何解决。
    *   会创建 `BSDmakefile`, `Makefile`, 和 `frida-env.dat` 文件在 `build` 目录下。

**4. 生成构建系统文件：**

*   脚本调用 Meson 构建系统 (`meson setup`) 来生成实际的构建文件 (`build.ninja`)。
*   它还会生成一些辅助的 Makefile 文件 (`Makefile`, `BSDmakefile`, `make.bat`)，方便用户进行构建操作。
*   生成一个 `frida-env.dat` 文件，用于存储构建环境信息，供后续构建步骤使用。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

*   **错误的命令行参数：** 用户输入了无效的 `--host` 值，例如 `--host=invalid-platform`。脚本在解析参数时会报错，因为 `MachineSpec.parse` 无法识别该平台标识符。
*   **重复配置：** 用户在已经配置过 `build` 目录后，再次运行配置脚本，且没有清理 `build` 目录。脚本会检测到 `build.ninja` 文件已存在，并提示用户已配置过，需要清理 `build` 目录才能重新配置。
*   **缺少依赖：** 用户禁用了预构建 (`--without-prebuilds=toolchain`)，但系统上没有安装必要的编译工具链。Meson 在执行 `setup` 阶段会因为找不到编译器而报错。
*   **权限问题：** 用户没有权限在指定的 `--prefix` 目录下进行安装操作。在后续的 `meson install` 阶段会报错。
*   **环境变量问题：** 在 Windows 上进行交叉编译时，如果 `VSCMD_ARG_TGT_ARCH` 环境变量设置不正确，可能会导致配置错误的目标架构。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **下载 Frida 源代码：** 用户首先需要从 GitHub 或其他来源获取 Frida 的源代码。这通常涉及到使用 `git clone` 命令。
2. **进入 Frida Gum 目录：** Frida 的 Gum 引擎是其核心组件。用户需要进入 `frida/subprojects/frida-gum` 目录。
3. **运行配置脚本：** 用户想要配置 Frida Gum 的构建环境。他们会在 `frida/subprojects/frida-gum/releng` 目录下找到 `meson_configure.py` 脚本，并尝试运行它。
4. **指定构建选项：** 用户可能会根据自己的需求指定一些构建选项，例如：
    *   **基本配置：**  `./meson_configure.py ..`  （配置在父目录下创建一个名为 `build` 的构建目录）
    *   **启用调试符号：** `./meson_configure.py .. --enable-symbols`
    *   **交叉编译到 Android：** `./meson_configure.py .. --host=arm64-android`
    *   **自定义安装路径：** `./meson_configure.py .. --prefix=/opt/frida`
5. **遇到问题或想要了解配置过程：** 如果配置过程中出现错误，或者用户想要了解 Frida 的构建配置是如何进行的，他们可能会查看 `meson_configure.py` 脚本的源代码，以理解每个选项的作用以及脚本的执行逻辑。
6. **调试线索：**  当构建出现问题时，查看 `meson_configure.py` 的源代码可以帮助用户理解：
    *   脚本是如何解析命令行参数的，他们是否使用了正确的参数。
    *   脚本依赖哪些外部工具或库，例如 Meson、编译器、链接器等。
    *   脚本是如何处理预构建依赖的，是否需要手动安装某些依赖。
    *   生成的 Meson 配置文件中包含了哪些关键信息，例如编译器路径和链接器选项。

总而言之，`meson_configure.py` 是 Frida 构建流程的关键入口点，它负责根据用户的配置选项和系统环境，生成 Meson 构建系统所需的配置文件，从而为后续的编译、链接和安装过程奠定基础。它涉及到与操作系统、编译器工具链、目标平台架构等多个底层的交互。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/releng/meson_configure.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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