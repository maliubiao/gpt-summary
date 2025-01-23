Response:
Let's break down the thought process for analyzing this Python script.

**1. Understanding the Goal:** The request asks for a functional summary of the `deps.py` script, highlighting connections to reverse engineering, low-level details, logical reasoning, user errors, and debugging context. The "Part 1" indication suggests this is a high-level overview.

**2. Initial Scan and Keyword Recognition:**  A quick read-through reveals important keywords and structures:

*   `argparse`:  Indicates command-line interface functionality.
*   `sync`, `roll`, `build`, `wait`, `bump`: These look like the main commands the script performs.
*   `Bundle`, `MachineSpec`, `PackageSpec`: Data classes likely representing different types of dependencies, target architectures, and individual packages.
*   `urllib.request`, `tarfile`, `subprocess`:  Indicates interaction with the network, archive handling, and execution of external commands.
*   Paths and file operations:  The script clearly manages files and directories.
*   Environment variables:  References to `FRIDA_DEPS`.
*   Conditional logic (`if`, `else`, `try`, `except`):  The script makes decisions based on various factors.

**3. Deconstructing the Main Functionality (the `main()` function and its subparsers):**

*   **`sync`:** This immediately suggests synchronizing dependencies. The arguments (`bundle`, `host`, `location`) point to *what* dependency, *for what target*, and *where to put it*.
*   **`roll`:**  The name "roll" combined with `--build` and `--activate` suggests a build-and-deploy process. It likely builds dependencies if they're not already available and then potentially "activates" them (updates a configuration).
*   **`build`:** This is the core compilation step. The options `--only` and `--exclude` indicate fine-grained control over which packages are built.
*   **`wait`:** This likely involves waiting for some kind of build process to complete, possibly on a remote server.
*   **`bump`:**  A version bumping mechanism.

**4. Identifying Key Classes and Data Structures:**

*   **`Bundle`:** An `Enum` suggests a limited set of dependency types (likely SDK, Toolchain, etc.).
*   **`MachineSpec`:**  This class likely encapsulates information about target operating systems and architectures. The `make_from_local_system()` and `parse()` methods are clues.
*   **`PackageSpec`:** This likely defines the attributes of an individual dependency package (name, URL, version, dependencies, build options).

**5. Connecting to Reverse Engineering Concepts:**

*   **Prebuilt Dependencies:** The core function of the script is managing prebuilt dependencies. This is highly relevant to reverse engineering because tools like Frida often rely on specific libraries and components for different target platforms.
*   **Target Architectures:** The `MachineSpec` and the handling of different OS/arch combinations are crucial for reverse engineering, as tools need to be built for the specific system they'll be interacting with.
*   **Toolchains:** The concept of a "toolchain" (compilers, linkers, etc.) is fundamental in software development and reverse engineering. Having a way to manage different toolchains for different targets is essential.

**6. Identifying Low-Level and Kernel/Framework Connections:**

*   **Binary Artifacts:** The script downloads, extracts, and packages binary files. This is inherently low-level.
*   **Operating System Specifics:** The conditional logic based on `machine.os` (Windows, Apple, Linux) shows awareness of OS differences in build processes and file handling.
*   **`pkgconfig`:**  Mentioning `pkg_config_path` indicates interaction with a common mechanism for finding library dependencies, often used in Linux environments.

**7. Recognizing Logical Reasoning:**

*   **Dependency Resolution:** The script has logic to figure out the order in which packages need to be built based on their dependencies. The `graphlib` import confirms this.
*   **Conditional Building:** The `when` attributes in `PackageSpec` and `PackageOption` show that the script conditionally includes or excludes packages and build options.
*   **Caching:** The script checks for existing versions and avoids redownloading or rebuilding if possible.

**8. Anticipating User Errors:**

*   **Incorrect Command-line Arguments:**  The `argparse` library is used to validate input, but users could still provide incorrect bundle names or machine specifications. The `parse_bundle_option_value` function handles this specifically.
*   **Missing Dependencies/Network Issues:** The script handles `urllib.error.HTTPError`, suggesting potential network problems or missing files.
*   **Incorrect Environment Configuration:** While not explicitly shown in this snippet, misconfigured environment variables (like `FRIDA_DEPS`) could lead to problems.

**9. Tracing User Operations (Debugging Clues):**

*   The script is invoked from the command line. The `argparse` setup clearly defines the entry points and the expected arguments.
*   The file paths and directory names (e.g., `frida/subprojects/frida-clr/releng/deps.py`) give context about where this script lives within the Frida project.
*   The logging/printing statements (e.g., "Downloading SDK...", "Building...") provide feedback on the script's progress.

**10. Structuring the Summary (Iterative Process):**

The initial thoughts are often scattered. The next step is to organize them logically:

*   Start with the high-level purpose.
*   Describe the main commands and their functions.
*   Detail the key data structures and their roles.
*   Address each specific requirement of the prompt (reverse engineering, low-level details, etc.) with examples from the code.
*   Provide examples for logical reasoning, user errors, and debugging.
*   Finally, summarize the overall functionality.

**Self-Correction/Refinement:**

*   Initially, I might have just listed the commands. But the prompt asks for *functionality*. So, elaborating on what each command *does* is important.
*   I might have overlooked the significance of `graphlib`. Realizing it's for dependency resolution is a key insight.
*   The connection to reverse engineering might not be immediately obvious. Thinking about *why* Frida needs these dependencies is the crucial link.

By following these steps, breaking down the code, and actively looking for connections to the prompt's requirements, a comprehensive and accurate summary can be generated.
这是Frida动态 instrumentation工具的一个Python脚本文件，位于`frida/subprojects/frida-clr/releng/`目录下，主要用于管理Frida CLR桥接组件的预构建依赖。以下是其功能的归纳：

**核心功能：管理和构建预构建依赖**

`deps.py` 脚本的主要职责是确保 Frida CLR 组件所需的各种依赖项（例如，编译工具链、SDK）能够被正确地下载、构建和管理。它提供了一组命令行工具，用于：

1. **同步 (sync):**  下载或更新特定目标平台（`host`）的预构建依赖包（`bundle`，如 SDK 或工具链）到指定的本地文件系统位置（`location`）。如果本地已存在旧版本，则会删除并重新下载。

2. **滚动 (roll):**  负责构建并上传预构建的依赖项。它会检查指定目标平台（`host`）的依赖包是否已存在于远程仓库（S3）。如果不存在，则会触发构建（在`build`参数指定的平台），然后上传到远程仓库，并可能执行一些后处理脚本。

3. **构建 (build):**  实际执行预构建依赖的编译过程。可以指定要构建的依赖包类型 (`--bundle`)，构建平台 (`--build`) 和目标平台 (`--host`)。 还可以选择只构建或排除特定的软件包。

4. **等待 (wait):**  可能用于等待某个预构建依赖项可用。

5. **版本递增 (bump):**  用于更新依赖项的版本号。

**与逆向方法的关系及举例说明：**

*   **依赖管理：** Frida 作为一款动态插桩工具，需要与目标进程的运行时环境进行交互。对于 .NET 应用程序，Frida CLR 需要与 CLR 运行时环境交互。这些交互通常依赖于特定的库和头文件。`deps.py` 确保了构建 Frida CLR 所需的这些依赖项是可用的且版本正确。
    *   **举例：** 在逆向一个使用特定 .NET Framework 版本的应用程序时，Frida CLR 可能需要针对该版本编译的依赖项才能正常工作。`deps.py` 可以用来下载或构建与该 .NET Framework 版本相匹配的依赖。

*   **目标平台支持：** 逆向工作经常需要在不同的操作系统和架构上进行。`deps.py` 允许指定目标平台 (`host`) 和构建平台 (`build`)，这使得 Frida CLR 能够被构建成适应不同的目标环境。
    *   **举例：**  如果需要在 Android 设备上逆向一个 Unity 游戏（使用 IL2CPP），则需要为 Android 架构构建 Frida CLR 的依赖项。可以通过 `deps.py` 指定 Android 平台来下载或构建相应的依赖。

**涉及二进制底层、Linux、Android内核及框架的知识及举例说明：**

*   **工具链管理：** 脚本中涉及 "toolchain" 的概念，这指的是编译和链接代码所需要的工具集合，例如编译器 (gcc, clang)、链接器 (ld) 等。不同平台需要不同的工具链。
    *   **举例：**  为 Android 构建依赖项可能需要 Android NDK (Native Development Kit) 中的工具链。`deps.py` 负责下载和管理这些工具链。

*   **SDK 管理：**  脚本中也涉及 "SDK" (Software Development Kit) 的概念。对于不同的平台，SDK 包含了开发所需的库、头文件等。
    *   **举例：**  为 Android 构建可能需要 Android SDK 中的特定库文件。`deps.py` 负责下载和管理这些 SDK。

*   **平台特定的构建选项：**  脚本中可能会根据目标平台的不同设置不同的编译选项。例如，Windows 和 Linux 的编译过程和库文件格式有所不同。
    *   **举例：**  在为 Windows 构建时，可能需要处理 DLL 文件的生成和链接；在 Linux 上，可能需要处理共享库 (.so) 的生成。

*   **与构建系统的交互 (Meson):**  脚本中调用了 `env.call_meson`，这表明 Frida CLR 的构建系统使用了 Meson。Meson 是一个跨平台的构建系统，能够根据不同的平台生成相应的构建文件（如 Ninja 构建文件）。
    *   **举例：**  `deps.py` 使用 Meson 来配置构建过程，指定编译选项、依赖项路径等。Meson 会根据目标平台生成对应的构建指令。

**逻辑推理的假设输入与输出：**

*   **假设输入:** 用户执行命令 `python deps.py sync sdk windows-x86_64 ./my_deps`
*   **逻辑推理:** 脚本会解析命令，识别出要同步的是 SDK (`bundle=Bundle.SDK`)，目标平台是 Windows 64 位 (`host=MachineSpec(os='windows', arch='x86_64', ...)`），本地路径是 `./my_deps`。然后，它会查找与 Windows 64 位 SDK 对应的远程包 URL 和文件名，并尝试下载到 `./my_deps` 目录。
*   **假设输出:** 如果远程仓库存在对应的 SDK 包，则会下载并解压到 `./my_deps` 目录。如果本地已存在旧版本，则先删除旧版本。如果下载失败（例如 404 错误），则会抛出 `BundleNotFoundError` 异常。

**用户或编程常见的使用错误及举例说明：**

*   **错误的 bundle 名称:** 用户可能会输入错误的 bundle 名称，例如 `python deps.py sync ksd ...`，由于 `ksd` 不是有效的 `Bundle` 枚举值，脚本会抛出 `argparse.ArgumentTypeError`。
*   **错误的 host 平台标识:** 用户可能会输入无法解析的平台标识，例如 `python deps.py sync sdk wimdows-x86 ...`，`MachineSpec.parse` 函数会抛出异常。
*   **网络问题:** 在 `sync` 或 `roll` 命令中，如果无法连接到远程仓库或下载文件时，会抛出 `urllib.error.HTTPError` 异常。
*   **权限问题:** 如果指定的本地路径没有写入权限，脚本在尝试创建或写入文件时会遇到 `PermissionError`。

**用户操作如何一步步到达这里，作为调试线索：**

1. **开发或贡献 Frida CLR:**  用户可能正在尝试构建或修改 Frida CLR 的代码。
2. **查阅构建文档:**  Frida CLR 的构建文档可能会指示用户运行 `deps.py` 脚本来准备构建环境。
3. **执行构建命令:** 用户根据文档指示，执行类似于 `python deps.py sync sdk linux-x86_64 ./deps` 这样的命令。
4. **遇到构建错误:** 如果在构建过程中遇到依赖项缺失或版本不匹配的问题，用户可能会检查 `deps.py` 的执行情况，查看是否成功下载和安装了所需的依赖。
5. **调试 `deps.py`:** 用户可能会阅读 `deps.py` 的源代码，了解其工作原理，或者在脚本中添加打印语句来调试问题，例如检查下载的 URL、解压的路径等。

**归纳一下它的功能 (Part 1):**

`deps.py` 是 Frida CLR 项目中用于管理预构建依赖项的关键脚本。它提供了一组命令行工具，用于同步、构建和管理不同目标平台的依赖包（如 SDK 和工具链）。这确保了 Frida CLR 能够正确地构建和运行在各种操作系统和架构上，这对于动态插桩和逆向工程至关重要。该脚本涉及对不同平台构建工具链和 SDK 的管理，并利用 Meson 构建系统进行配置和编译。用户可以通过命令行操作来管理这些依赖，但常见的错误包括输入错误的参数或遇到网络问题。作为调试线索，理解 `deps.py` 的工作流程有助于诊断 Frida CLR 构建过程中遇到的依赖问题。

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/deps.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```python
#!/usr/bin/env python3
from __future__ import annotations
import argparse
import base64
from configparser import ConfigParser
import dataclasses
from dataclasses import dataclass, field
from enum import Enum
import graphlib
import itertools
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from typing import Callable, Iterator, Optional, Mapping, Sequence, Union
import urllib.request

RELENG_DIR = Path(__file__).resolve().parent
ROOT_DIR = RELENG_DIR.parent

if __name__ == "__main__":
    # TODO: Refactor
    sys.path.insert(0, str(ROOT_DIR))
sys.path.insert(0, str(RELENG_DIR / "tomlkit"))

from tomlkit.toml_file import TOMLFile

from releng import env
from releng.progress import Progress, ProgressCallback, print_progress
from releng.machine_spec import MachineSpec


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    default_machine = MachineSpec.make_from_local_system().identifier

    bundle_opt_kwargs = {
        "help": "bundle (default: sdk)",
        "type": parse_bundle_option_value,
    }
    machine_opt_kwargs = {
        "help": f"os/arch (default: {default_machine})",
        "type": MachineSpec.parse,
    }

    command = subparsers.add_parser("sync", help="ensure prebuilt dependencies are up-to-date")
    command.add_argument("bundle", **bundle_opt_kwargs)
    command.add_argument("host", **machine_opt_kwargs)
    command.add_argument("location", help="filesystem location", type=Path)
    command.set_defaults(func=lambda args: sync(args.bundle, args.host, args.location.resolve()))

    command = subparsers.add_parser("roll", help="build and upload prebuilt dependencies if needed")
    command.add_argument("bundle", **bundle_opt_kwargs)
    command.add_argument("host", **machine_opt_kwargs)
    command.add_argument("--build", default=default_machine, **machine_opt_kwargs)
    command.add_argument("--activate", default=False, action='store_true')
    command.add_argument("--post", help="post-processing script")
    command.set_defaults(func=lambda args: roll(args.bundle, args.build, args.host, args.activate,
                                                Path(args.post) if args.post is not None else None))

    command = subparsers.add_parser("build", help="build prebuilt dependencies")
    command.add_argument("--bundle", default=Bundle.SDK, **bundle_opt_kwargs)
    command.add_argument("--build", default=default_machine, **machine_opt_kwargs)
    command.add_argument("--host", default=default_machine, **machine_opt_kwargs)
    command.add_argument("--only", help="only build packages A, B, and C", metavar="A,B,C",
                         type=parse_set_option_value)
    command.add_argument("--exclude", help="exclude packages A, B, and C", metavar="A,B,C",
                         type=parse_set_option_value, default=set())
    command.add_argument("-v", "--verbose", help="be verbose", action="store_true")
    command.set_defaults(func=lambda args: build(args.bundle, args.build, args.host,
                                                 args.only, args.exclude, args.verbose))

    command = subparsers.add_parser("wait", help="wait for prebuilt dependencies if needed")
    command.add_argument("bundle", **bundle_opt_kwargs)
    command.add_argument("host", **machine_opt_kwargs)
    command.set_defaults(func=lambda args: wait(args.bundle, args.host))

    command = subparsers.add_parser("bump", help="bump dependency versions")
    command.set_defaults(func=lambda args: bump())

    args = parser.parse_args()
    if 'func' in args:
        try:
            args.func(args)
        except CommandError as e:
            print(e, file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_usage(file=sys.stderr)
        sys.exit(1)


def parse_bundle_option_value(raw_bundle: str) -> Bundle:
    try:
        return Bundle[raw_bundle.upper()]
    except KeyError:
        choices = "', '".join([e.name.lower() for e in Bundle])
        raise argparse.ArgumentTypeError(f"invalid choice: {raw_bundle} (choose from '{choices}')")


def parse_set_option_value(v: str) -> set[str]:
    return set([v.strip() for v in v.split(",")])


def query_toolchain_prefix(machine: MachineSpec,
                           cache_dir: Path) -> Path:
    if machine.os == "windows":
        identifier = "windows-x86" if machine.arch in {"x86", "x86_64"} else machine.os_dash_arch
    else:
        identifier = machine.identifier
    return cache_dir / f"toolchain-{identifier}"


def ensure_toolchain(machine: MachineSpec,
                     cache_dir: Path,
                     version: Optional[str] = None,
                     on_progress: ProgressCallback = print_progress) -> tuple[Path, SourceState]:
    toolchain_prefix = query_toolchain_prefix(machine, cache_dir)
    state = sync(Bundle.TOOLCHAIN, machine, toolchain_prefix, version, on_progress)
    return (toolchain_prefix, state)


def query_sdk_prefix(machine: MachineSpec,
                     cache_dir: Path) -> Path:
    return cache_dir / f"sdk-{machine.identifier}"


def ensure_sdk(machine: MachineSpec,
               cache_dir: Path,
               version: Optional[str] = None,
               on_progress: ProgressCallback = print_progress) -> tuple[Path, SourceState]:
    sdk_prefix = query_sdk_prefix(machine, cache_dir)
    state = sync(Bundle.SDK, machine, sdk_prefix, version, on_progress)
    return (sdk_prefix, state)


def detect_cache_dir(sourcedir: Path) -> Path:
    raw_location = os.environ.get("FRIDA_DEPS", None)
    if raw_location is not None:
        location = Path(raw_location)
    else:
        location = sourcedir / "deps"
    return location


def sync(bundle: Bundle,
         machine: MachineSpec,
         location: Path,
         version: Optional[str] = None,
         on_progress: ProgressCallback = print_progress) -> SourceState:
    state = SourceState.PRISTINE

    if version is None:
        version = load_dependency_parameters().deps_version

    bundle_nick = bundle.name.lower() if bundle != Bundle.SDK else bundle.name

    if location.exists():
        try:
            cached_version = (location / "VERSION.txt").read_text(encoding="utf-8").strip()
            if cached_version == version:
                return state
        except:
            pass
        shutil.rmtree(location)
        state = SourceState.MODIFIED

    (url, filename) = compute_bundle_parameters(bundle, machine, version)

    local_bundle = location.parent / filename
    if local_bundle.exists():
        on_progress(Progress("Deploying local {}".format(bundle_nick)))
        archive_path = local_bundle
        archive_is_temporary = False
    else:
        if bundle == Bundle.SDK:
            on_progress(Progress(f"Downloading SDK {version} for {machine.identifier}"))
        else:
            on_progress(Progress(f"Downloading {bundle_nick} {version}"))
        try:
            with urllib.request.urlopen(url) as response, \
                    tempfile.NamedTemporaryFile(delete=False) as archive:
                shutil.copyfileobj(response, archive)
                archive_path = Path(archive.name)
                archive_is_temporary = True
            on_progress(Progress(f"Extracting {bundle_nick}"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise BundleNotFoundError(f"missing bundle at {url}") from e
            raise e

    try:
        staging_dir = location.parent / f"_{location.name}"
        if staging_dir.exists():
            shutil.rmtree(staging_dir)
        staging_dir.mkdir(parents=True)

        with tarfile.open(archive_path, "r:xz") as tar:
            tar.extractall(staging_dir)

        suffix_len = len(".frida.in")
        raw_location = location.as_posix()
        for f in staging_dir.rglob("*.frida.in"):
            target = f.parent / f.name[:-suffix_len]
            f.write_text(f.read_text(encoding="utf-8").replace("@FRIDA_TOOLROOT@", raw_location),
                         encoding="utf-8")
            f.rename(target)

        staging_dir.rename(location)
    finally:
        if archive_is_temporary:
            archive_path.unlink()

    return state


def roll(bundle: Bundle,
         build_machine: MachineSpec,
         host_machine: MachineSpec,
         activate: bool,
         post: Optional[Path]):
    params = load_dependency_parameters()
    version = params.deps_version

    if activate and bundle == Bundle.SDK:
        configure_bootstrap_version(version)

    (public_url, filename) = compute_bundle_parameters(bundle, host_machine, version)

    # First do a quick check to avoid hitting S3 in most cases.
    request = urllib.request.Request(public_url)
    request.get_method = lambda: "HEAD"
    try:
        with urllib.request.urlopen(request) as r:
            return
    except urllib.request.HTTPError as e:
        if e.code != 404:
            raise CommandError("network error") from e

    s3_url = "s3://build.frida.re/deps/{version}/{filename}".format(version=version, filename=filename)

    # We will most likely need to build, but let's check S3 to be certain.
    r = subprocess.run(["aws", "s3", "ls", s3_url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8")
    if r.returncode == 0:
        return
    if r.returncode != 1:
        raise CommandError(f"unable to access S3: {r.stdout.strip()}")

    artifact = build(bundle, build_machine, host_machine)

    if post is not None:
        post_script = RELENG_DIR / post
        if not post_script.exists():
            raise CommandError("post-processing script not found")

        subprocess.run([
                           sys.executable, post_script,
                           "--bundle=" + bundle.name.lower(),
                           "--host=" + host_machine.identifier,
                           "--artifact=" + str(artifact),
                           "--version=" + version,
                       ],
                       check=True)

    subprocess.run(["aws", "s3", "cp", artifact, s3_url], check=True)

    # Use the shell for Windows compatibility, where npm generates a .bat script.
    subprocess.run("cfcli purge " + public_url, shell=True, check=True)

    if activate and bundle == Bundle.TOOLCHAIN:
        configure_bootstrap_version(version)


def build(bundle: Bundle,
          build_machine: MachineSpec,
          host_machine: MachineSpec,
          only_packages: Optional[set[str]] = None,
          excluded_packages: set[str] = set(),
          verbose: bool = False) -> Path:
    builder = Builder(bundle, build_machine, host_machine, verbose)
    try:
        return builder.build(only_packages, excluded_packages)
    except subprocess.CalledProcessError as e:
        print(e, file=sys.stderr)
        if e.stdout is not None:
            print("\n=== stdout ===\n" + e.stdout, file=sys.stderr)
        if e.stderr is not None:
            print("\n=== stderr ===\n" + e.stderr, file=sys.stderr)
        sys.exit(1)


class Builder:
    def __init__(self,
                 bundle: Bundle,
                 build_machine: MachineSpec,
                 host_machine: MachineSpec,
                 verbose: bool):
        self._bundle = bundle
        self._host_machine = host_machine.default_missing()
        self._build_machine = build_machine.default_missing().maybe_adapt_to_host(self._host_machine)
        self._verbose = verbose
        self._default_library = "static"

        self._params = load_dependency_parameters()
        self._cachedir = detect_cache_dir(ROOT_DIR)
        self._workdir = self._cachedir / "src"

        self._toolchain_prefix: Optional[Path] = None
        self._build_config: Optional[env.MachineConfig] = None
        self._host_config: Optional[env.MachineConfig] = None
        self._build_env: dict[str, str] = {}
        self._host_env: dict[str, str] = {}

        self._ansi_supported = os.environ.get("TERM") != "dumb" \
                    and (self._build_machine.os != "windows" or "WT_SESSION" in os.environ)

    def build(self,
              only_packages: Optional[list[str]],
              excluded_packages: set[str]) -> Path:
        started_at = time.time()
        prepare_ended_at = None
        clone_time_elapsed = None
        build_time_elapsed = None
        build_ended_at = None
        packaging_ended_at = None
        try:
            all_packages = {i: self._resolve_package(p) for i, p in self._params.packages.items() \
                    if self._can_build(p)}
            if only_packages is not None:
                toplevel_packages = [all_packages[identifier] for identifier in only_packages]
                selected_packages = self._resolve_dependencies(toplevel_packages, all_packages)
            elif self._bundle is Bundle.TOOLCHAIN:
                toplevel_packages = [p for p in all_packages.values() if p.scope == "toolchain"]
                selected_packages = self._resolve_dependencies(toplevel_packages, all_packages)
            else:
                selected_packages = {i: p for i, p, in all_packages.items() if p.scope is None}
            selected_packages = {i: p for i, p in selected_packages.items() if i not in excluded_packages}

            packages = [selected_packages[i] for i in iterate_package_ids_in_dependency_order(selected_packages.values())]
            all_deps = itertools.chain.from_iterable([pkg.dependencies for pkg in packages])
            deps_for_build_machine = {dep.identifier for dep in all_deps if dep.for_machine == "build"}

            self._prepare()
            prepare_ended_at = time.time()

            clone_time_elapsed = 0
            build_time_elapsed = 0
            for pkg in packages:
                self._print_package_banner(pkg)

                t1 = time.time()
                self._clone_repo_if_needed(pkg)
                t2 = time.time()
                clone_time_elapsed += t2 - t1

                machines = [self._host_machine]
                if pkg.identifier in deps_for_build_machine:
                    machines += [self._build_machine]
                self._build_package(pkg, machines)
                t3 = time.time()
                build_time_elapsed += t3 - t2
            build_ended_at = time.time()

            artifact_file = self._package()
            packaging_ended_at = time.time()
        finally:
            ended_at = time.time()

            if prepare_ended_at is not None:
                self._print_summary_banner()
                print("      Total: {}".format(format_duration(ended_at - started_at)))

            if prepare_ended_at is not None:
                print("    Prepare: {}".format(format_duration(prepare_ended_at - started_at)))

            if clone_time_elapsed is not None:
                print("      Clone: {}".format(format_duration(clone_time_elapsed)))

            if build_time_elapsed is not None:
                print("      Build: {}".format(format_duration(build_time_elapsed)))

            if packaging_ended_at is not None:
                print("  Packaging: {}".format(format_duration(packaging_ended_at - build_ended_at)))

            print("", flush=True)

        return artifact_file

    def _can_build(self, pkg: PackageSpec) -> bool:
        return self._evaluate_condition(pkg.when)

    def _resolve_package(self, pkg: PackageSpec) -> bool:
        resolved_opts = [opt for opt in pkg.options if self._evaluate_condition(opt.when)]
        resolved_deps = [dep for dep in pkg.dependencies if self._evaluate_condition(dep.when)]
        return dataclasses.replace(pkg,
                                   options=resolved_opts,
                                   dependencies=resolved_deps)

    def _resolve_dependencies(self,
                              packages: Sequence[PackageSpec],
                              all_packages: Mapping[str, PackageSpec]) -> dict[str, PackageSpec]:
        result = {p.identifier: p for p in packages}
        for p in packages:
            self._resolve_package_dependencies(p, all_packages, result)
        return result

    def _resolve_package_dependencies(self,
                                      package: PackageSpec,
                                      all_packages: Mapping[str, PackageSpec],
                                      resolved_packages: Mapping[str, PackageSpec]):
        for dep in package.dependencies:
            identifier = dep.identifier
            if identifier in resolved_packages:
                continue
            p = all_packages[identifier]
            resolved_packages[identifier] = p
            self._resolve_package_dependencies(p, all_packages, resolved_packages)

    def _evaluate_condition(self, cond: Optional[str]) -> bool:
        if cond is None:
            return True
        global_vars = {
            "Bundle": Bundle,
            "bundle": self._bundle,
            "machine": self._host_machine,
        }
        return eval(cond, global_vars)

    def _prepare(self):
        self._toolchain_prefix, toolchain_state = \
                ensure_toolchain(self._build_machine,
                                 self._cachedir,
                                 version=self._params.bootstrap_version)
        if toolchain_state == SourceState.MODIFIED:
            self._wipe_build_state()

        envdir = self._get_builddir_container()
        envdir.mkdir(parents=True, exist_ok=True)

        menv = {**os.environ}

        if self._bundle is Bundle.TOOLCHAIN:
            extra_ldflags = []
            if self._host_machine.is_apple:
                symfile = envdir / "toolchain-executable.symbols"
                symfile.write_text("# No exported symbols.\n", encoding="utf-8")
                extra_ldflags += [f"-Wl,-exported_symbols_list,{symfile}"]
            elif self._host_machine.os != "windows":
                verfile = envdir / "toolchain-executable.version"
                verfile.write_text("\n".join([
                                                 "{",
                                                 "  global:",
                                                 "    # FreeBSD needs these two:",
                                                 "    __progname;",
                                                 "    environ;",
                                                 "",
                                                 "  local:",
                                                 "    *;",
                                                 "};",
                                                 ""
                                             ]),
                                   encoding="utf-8")
                extra_ldflags += [f"-Wl,--version-script,{verfile}"]
            if extra_ldflags:
                menv["LDFLAGS"] = shlex.join(extra_ldflags + shlex.split(menv.get("LDFLAGS", "")))

        build_sdk_prefix = None
        host_sdk_prefix = None

        self._build_config, self._host_config = \
                env.generate_machine_configs(self._build_machine,
                                             self._host_machine,
                                             menv,
                                             self._toolchain_prefix,
                                             build_sdk_prefix,
                                             host_sdk_prefix,
                                             self._call_meson,
                                             self._default_library,
                                             envdir)
        self._build_env = self._build_config.make_merged_environment(os.environ)
        self._host_env = self._host_config.make_merged_environment(os.environ)

    def _clone_repo_if_needed(self, pkg: PackageSpec):
        sourcedir = self._get_sourcedir(pkg)

        git = lambda *args, **kwargs: subprocess.run(["git", *args],
                                                     **kwargs,
                                                     capture_output=True,
                                                     encoding="utf-8")

        if sourcedir.exists():
            self._print_status(pkg.name, "Reusing existing checkout")
            current_rev = git("rev-parse", "FETCH_HEAD", cwd=sourcedir, check=True).stdout.strip()
            if current_rev != pkg.version:
                self._print_status(pkg.name, "WARNING: Checkout does not match version in deps.toml")
        else:
            self._print_status(pkg.name, "Cloning")
            clone_shallow(pkg, sourcedir, git)

    def _wipe_build_state(self):
        for path in (self._get_outdir(), self._get_builddir_container()):
            if path.exists():
                self._print_status(path.relative_to(self._workdir).as_posix(), "Wiping")
                shutil.rmtree(path)

    def _build_package(self, pkg: PackageSpec, machines: Sequence[MachineSpec]):
        for machine in machines:
            manifest_path = self._get_manifest_path(pkg, machine)
            action = "skip" if manifest_path.exists() else "build"

            message = "Building" if action == "build" else "Already built"
            message += f" for {machine.identifier}"
            self._print_status(pkg.name, message)

            if action == "build":
                self._build_package_for_machine(pkg, machine)
                assert manifest_path.exists()

    def _build_package_for_machine(self, pkg: PackageSpec, machine: MachineSpec):
        sourcedir = self._get_sourcedir(pkg)
        builddir = self._get_builddir(pkg, machine)

        prefix = self._get_prefix(machine)
        libdir = prefix / "lib"

        strip = "true" if machine.toolchain_can_strip else "false"

        if builddir.exists():
            shutil.rmtree(builddir)

        machine_file_opts = [f"--native-file={self._build_config.machine_file}"]
        pc_opts = [f"-Dpkg_config_path={prefix / machine.libdatadir / 'pkgconfig'}"]
        if self._host_config is not self._build_config and machine is self._host_machine:
            machine_file_opts += [f"--cross-file={self._host_config.machine_file}"]
            pc_path_for_build = self._get_prefix(self._build_machine) / self._build_machine.libdatadir / "pkgconfig"
            pc_opts += [f"-Dbuild.pkg_config_path={pc_path_for_build}"]

        menv = self._host_env if machine is self._host_machine else self._build_env

        meson_kwargs = {
            "env": menv,
            "check": True,
        }
        if not self._verbose:
            meson_kwargs["capture_output"] = True
            meson_kwargs["encoding"] = "utf-8"

        self._call_meson([
                             "setup",
                             builddir,
                             *machine_file_opts,
                             f"-Dprefix={prefix}",
                             f"-Dlibdir={libdir}",
                             *pc_opts,
                             f"-Ddefault_library={self._default_library}",
                             f"-Dbackend=ninja",
                             *machine.meson_optimization_options,
                             f"-Dstrip={strip}",
                             *[opt.value for opt in pkg.options],
                         ],
                         cwd=sourcedir,
                         **meson_kwargs)

        self._call_meson(["install"],
                         cwd=builddir,
                         **meson_kwargs)

        manifest_lines = []
        install_locations = json.loads(self._call_meson(["introspect", "--installed"],
                                                        cwd=builddir,
                                                        capture_output=True,
                                                        encoding="utf-8",
                                                        env=menv).stdout)
        for installed_path in install_locations.values():
            manifest_lines.append(Path(installed_path).relative_to(prefix).as_posix())
        manifest_lines.sort()
        manifest_path = self._get_manifest_path(pkg, machine)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

    def _call_meson(self, argv, *args, **kwargs):
        if self._verbose and argv[0] in {"setup", "install"}:
            vanilla_env = os.environ
            meson_env = kwargs["env"]
            changed_env = {k: v for k, v in meson_env.items() if k not in vanilla_env or v != vanilla_env[k]}

            indent = "  "
            env_summary = f" \\\n{indent}".join([f"{k}={shlex.quote(v)}" for k, v in changed_env.items()])
            argv_summary = f" \\\n{3 * indent}".join([str(arg) for arg in argv])

            print(f"> {env_summary} \\\n{indent}meson {argv_summary}", flush=True)

        return env.call_meson(argv, use_submodule=True, *args, **kwargs)

    def _package(self):
        outfile = self._cachedir / f"{self._bundle.name.lower()}-{self._host_machine.identifier}.tar.xz"

        self._print_packaging_banner()
        with tempfile.TemporaryDirectory(prefix="frida-deps") as raw_tempdir:
            tempdir = Path(raw_tempdir)

            self._print_status(outfile.name, "Staging files")
            if self._bundle is Bundle.TOOLCHAIN:
                self._stage_toolchain_files(tempdir)
            else:
                self._stage_sdk_files(tempdir)

            self._adjust_manifests(tempdir)
            self._adjust_files_containing_hardcoded_paths(tempdir)

            (tempdir / "VERSION.txt").write_text(self._params.deps_version + "\n", encoding="utf-8")

            self._print_status(outfile.name, "Assembling")
            with tarfile.open(outfile, "w:xz") as tar:
                tar.add(tempdir, ".")

            self._print_status(outfile.name, "All done")

        return outfile

    def _stage_toolchain_files(self, location: Path) -> list[Path]:
        if self._host_machine.os == "windows":
            toolchain_prefix = self._toolchain_prefix
            mixin_files = [f for f in self._walk_plain_files(toolchain_prefix)
                           if self._file_should_be_mixed_into_toolchain(f)]
            copy_files(toolchain_prefix, mixin_files, location)

        prefix = self._get_prefix(self._host_machine)
        files = [f for f in self._walk_plain_files(prefix)
                 if self._file_is_toolchain_related(f)]
        copy_files(prefix, files, location)

    def _stage_sdk_files(self, location: Path) -> list[Path]:
        prefix = self._get_prefix(self._host_machine)
        files = [f for f in self._walk_plain_files(prefix)
                 if self._file_is_sdk_related(f)]
        copy_files(prefix, files, location)

    def _adjust_files_containing_hardcoded_paths(self, bundledir: Path):
        prefix = self._get_prefix(self._host_machine)

        raw_prefixes = [str(prefix)]
        if self._host_machine.os == "windows":
            raw_prefixes.append(prefix.as_posix())

        for f in self._walk_plain_files(bundledir):
            filepath = bundledir / f
            try:
                text = filepath.read_text(encoding="utf-8")

                new_text = text
                is_pcfile = filepath.suffix == ".pc"
                replacement = "${frida_sdk_prefix}" if is_pcfile else "@FRIDA_TOOLROOT@"
                for p in raw_prefixes:
                    new_text = new_text.replace(p, replacement)

                if new_text != text:
                    filepath.write_text(new_text, encoding="utf-8")
                    if not is_pcfile:
                        filepath.rename(filepath.parent / f"{f.name}.frida.in")
            except UnicodeDecodeError:
                pass

    @staticmethod
    def _walk_plain_files(rootdir: Path) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                f = Path(dirpath) / filename
                if f.is_symlink():
                    continue
                yield f.relative_to(rootdir)

    @staticmethod
    def _adjust_manifests(bundledir: Path):
        for manifest_path in (bundledir / "manifest").glob("*.pkg"):
            lines = []

            prefix = manifest_path.parent.parent
            for entry in manifest_path.read_text(encoding="utf-8").strip().split("\n"):
                if prefix.joinpath(entry).exists():
                    lines.append(entry)

            if lines:
                lines.sort()
                manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            else:
                manifest_path.unlink()

    def _file_should_be_mixed_into_toolchain(self, f: Path) -> bool:
        parts = f.parts
        if parts[0] == "VERSION.txt":
            return False
        if parts[0] == "bin":
            stem = f.stem
            return stem in {"bison", "flex", "m4", "nasm", "vswhere"} or stem.startswith("msys-")
        if parts[0] == "manifest":
            return False

        if self._file_is_vala_toolchain_related(f):
            return False

        return True

    def _file_is_toolchain_related(self, f: Path) -> bool:
        if self._file_is_vala_toolchain_related(f):
            return True

        parts = f.parts
        if parts[0] == "bin":
            if f.suffix == ".pdb":
                return False
            stem = f.stem
            if stem in {"gdbus", "gio", "gobject-query", "gsettings"}:
                return False
            if stem.startswith("gspawn-"):
                return False
            return True
        if parts[0] == "manifest":
            return True

        return False

    def _file_is_vala_toolchain_related(self, f: Path) -> bool:
        if f.suffix in {".vapi", ".deps"}:
            return True

        name = f.name
        if f.suffix == self._host_machine.executable_suffix:
            return name.startswith("vala") or name.startswith("vapi") or name.startswith("gen-introspect")
        if f.parts[0] == "bin" and name.startswith("vala-gen-introspect"):
            return True

        return False

    def _file_is_sdk_related(self, f: Path) -> bool:
        suffix = f.suffix
        if suffix == ".pdb":
            return False
        if suffix in [".vapi", ".deps"]:
            return True

        parts = f.parts
        if parts[0] == "bin":
            return f.name.startswith("v8-mksnapshot-")

        return "share" not in parts

    def _get_outdir(self) -> Path:
        return self._workdir / f"_{self._bundle.name.lower()}.out"

    def _get_sourcedir(self, pkg: PackageSpec) -> Path:
        return self._workdir / pkg.identifier

    def _get_builddir(self, pkg: PackageSpec, machine: MachineSpec) -> Path:
        return self._get_builddir_container() / machine.identifier / pkg.identifier

    def _get_builddir_container(self) -> Path:
        return self._workdir / f"_{self._bundle.name.lower()}.tmp"

    def _get_prefix(self, machine: MachineSpec) -> Path:
        return self._get_outdir() / machine.identifier

    def _get_manifest_path(self, pkg: PackageSpec, machine: MachineSpec) -> Path:
        return self._get_prefix(machine) / "manifest" / f"{pkg.identifier}.pkg"

    def _print_package_banner(self, pkg: PackageSpec):
        if self._ansi_supported:
            print("\n".join([
                "",
                "╭────",
                f"│ 📦 \033[1m{pkg.name}\033[0m",
                "├───────────────────────────────────────────────╮",
                f"│ URL: {pkg.url}",
                f"│ CID: {pkg.version}",
                "├───────────────────────────────────────────────╯",
            ]), flush=True)
        else:
            print("\n".join([
                "",
                f"# {pkg.name}",
                f"- URL: {pkg.url}",
                f"- CID: {pkg.version}",
            ]), flush=True)

    def _print_packaging_banner(self):
        if self._ansi_supported:
            print("\n".join([
                "",
                "╭────",
                f"│ 🏗️  \033[1mPackaging\033[0m",
                "├───────────────────────────────────────────────╮",
            ]), flush=True)
        else:
            print("\n".join([
                "",
                f"# Packaging",
            ]), flush=True)

    def _print_summary_banner(self):
        if self._ansi_supported:
            print("\n".join([
                "",
                "╭────",
                f"│ 🎉 \033[1mDone\033[0m",
                "├───────────────────────────────────────────────╮",
            ]), flush=True)
        else:
            print("\n".join([
                "",
                f"# Done",
```