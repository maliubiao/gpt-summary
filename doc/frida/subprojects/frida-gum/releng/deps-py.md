Response:
Let's break down the thought process for analyzing the provided Python script `deps.py`.

**1. Initial Understanding: What is the script's purpose?**

The script name `deps.py` and the context "fridaDynamic instrumentation tool" immediately suggest it deals with dependencies. The presence of functions like `sync`, `roll`, and `build` reinforces this idea. It seems responsible for managing pre-built dependencies required by Frida.

**2. Deconstructing the Code: Identifying Key Functions and Concepts**

I'll go through the code section by section, noting important functions, data structures, and modules used.

* **Imports:**  Standard Python libraries like `argparse`, `os`, `pathlib`, `subprocess`, `urllib`, and more specialized ones like `tomlkit` and custom modules (`releng`). These imports hint at the script's functionality (command-line parsing, file system operations, external process execution, network operations, and configuration management).
* **`main()` function:** This is the entry point. It uses `argparse` to define command-line arguments and subcommands: `sync`, `roll`, `build`, `wait`, `bump`. This confirms the script is designed to be run from the command line with different actions.
* **`sync()`:** This function handles downloading and extracting pre-built dependency bundles. Keywords like "downloading", "extracting", and handling local files are important. The mention of "VERSION.txt" suggests versioning is managed.
* **`roll()`:** This function seems to automate the process of building and uploading dependencies. It checks for the existence of bundles on a remote storage (S3) and triggers a build if necessary. The use of `aws` CLI commands is significant.
* **`build()`:** This is the core function for compiling dependencies. It utilizes a `Builder` class.
* **`Builder` class:**  This class encapsulates the complex build logic. Key aspects are:
    * Handling different `Bundle` types (SDK, Toolchain).
    * Supporting cross-compilation (build machine vs. host machine).
    * Using Meson as the build system.
    * Managing source code (cloning Git repositories).
    * Packaging the built artifacts.
    * The concept of "manifest" files to track installed components.
* **Helper Functions:** Functions like `parse_bundle_option_value`, `parse_set_option_value`, `query_toolchain_prefix`, `ensure_toolchain`, `detect_cache_dir`, `compute_bundle_parameters` provide supporting functionality for parsing arguments, locating resources, and generating URLs.
* **`Bundle` Enum:** Defines the different types of dependency bundles (SDK, Toolchain).
* **`MachineSpec` Class:**  Represents the operating system and architecture. This is crucial for handling platform-specific dependencies.
* **`SourceState` Enum:** Tracks whether the local copy of a dependency is pristine or modified.
* **Configuration:** The script interacts with TOML files (through `tomlkit`) for dependency parameters.
* **Environment Variables:** The script uses `FRIDA_DEPS` to determine the cache directory.

**3. Relating to Reverse Engineering, Binary Analysis, and System Knowledge**

Now, I connect the identified functionalities to the requested areas:

* **Reverse Engineering:**
    * Frida is a reverse engineering tool, and this script manages *its* dependencies. Thus, it indirectly supports reverse engineering by ensuring Frida has the necessary components.
    * The `sync` and `roll` commands ensure up-to-date dependency versions, which might be crucial for specific reverse engineering tasks that rely on certain Frida features.
    * The `build` command allows building specific components, which a developer or advanced user might need for custom Frida setups or debugging.
* **Binary Analysis:**
    * The script deals with pre-built binaries (downloading them) and the process of building them. Understanding the build process can be valuable in binary analysis, especially when encountering issues or needing to understand how a particular component is compiled.
    * The toolchain dependencies managed by this script include compilers and linkers, which are fundamental to understanding how binaries are created.
* **Linux/Android Kernel and Framework:**
    * The script explicitly handles different operating systems (Windows, Linux, macOS) and architectures.
    * The "SDK" bundle likely includes libraries and headers needed to interact with the target system, including potentially Android frameworks.
    * The toolchain includes compilers and other tools necessary to build software for these platforms.
    * The script's logic for handling machine specifications (`MachineSpec`) and conditional compilation based on the target OS and architecture directly relates to kernel and framework differences.

**4. Logical Reasoning (Hypothetical Input/Output)**

I consider a few scenarios:

* **`sync sdk linux/x86_64 ./my_deps`:**  The script would download the SDK bundle for Linux 64-bit, extract it to the `./my_deps` directory, and potentially update a "VERSION.txt" file. Output would be progress messages.
* **`build --bundle toolchain --build windows/x86_64 --host linux/x86_64`:**  This would initiate a cross-compilation build of the toolchain for Windows 64-bit, running on a Linux 64-bit host. Output would be detailed build logs from Meson and Git.

**5. User/Programming Errors**

I think about common mistakes:

* **Incorrect Arguments:**  Providing an invalid bundle name (`sync invalid_bundle ...`). The `parse_bundle_option_value` function explicitly handles this with an `argparse.ArgumentTypeError`.
* **Missing Dependencies:** If the `aws` CLI is not installed when running `roll`, the script would fail.
* **Network Issues:**  If there are network problems during downloads, the script would raise exceptions.
* **Incorrect Environment:**  If `FRIDA_DEPS` points to a non-existent or incorrect directory.

**6. User Operation to Reach the Script**

I imagine the steps:

1. A user needs to build Frida from source or ensure its dependencies are up-to-date.
2. They navigate to the Frida source directory (`frida/`).
3. They then go to the `frida-gum/releng/` directory.
4. They execute the `deps.py` script from the command line with specific arguments (e.g., `python deps.py sync sdk linux/x86_64 deps`).

**7. Summarizing Functionality (Part 1)**

Based on the analysis so far, I would summarize the functionality as:

> The `deps.py` script is a command-line tool for managing pre-built dependencies required by the Frida dynamic instrumentation framework. It provides functionalities to:
>
> * **Synchronize (sync):** Download and extract pre-built dependency bundles for a specified target operating system and architecture. It manages versions and handles local copies.
> * **Roll (roll):**  Automate the process of building and uploading dependency bundles to a remote storage (likely S3). It checks if a bundle needs to be built before triggering the build process.
> * **Build (build):**  Compile dependency packages for specified build and host machines using the Meson build system. It supports building specific packages or excluding others.
> * **Wait (wait):**  (Although not fully analyzed yet, the name suggests it waits for dependencies to become available).
> * **Bump (bump):** (Likely for updating dependency versions).
>
> The script uses configuration files (TOML), environment variables, and interacts with external tools like Git and the AWS CLI. It supports cross-compilation and handles platform-specific build requirements.

This detailed breakdown and thought process allows for a comprehensive understanding of the script's purpose and its connections to the broader context of Frida and system-level software development.
好的，让我们对 `frida/subprojects/frida-gum/releng/deps.py` 文件的第一部分代码进行功能归纳和分析。

**功能归纳：**

`deps.py` 脚本的主要功能是管理 Frida 工具的预构建依赖项。它提供了一组命令行工具，用于：

1. **同步 (sync):**  下载并提取指定操作系统和架构的预构建依赖项包到本地文件系统。
2. **构建 (build):**  从源代码构建预构建的依赖项包。这允许在没有预构建包可用时或者需要自定义构建时使用。
3. **滚动 (roll):**  自动化构建和上传预构建依赖项的过程。它会检查是否需要构建，如果需要则进行构建，然后上传到云存储（S3），并清除 CDN 缓存。
4. **等待 (wait):**  等待指定操作系统和架构的预构建依赖项可用。
5. **更新 (bump):**  更新依赖项的版本信息（具体实现未在提供的代码中体现）。

**详细功能分析与举例说明：**

**1. 逆向方法的关系：**

* **功能：同步 (sync)**
    * **说明：** Frida 是一个动态插桩工具，常用于逆向工程。`sync` 命令确保 Frida 运行时所需的依赖项（例如，特定平台的库、工具链等）是最新的。
    * **举例：** 假设你要在 Android 设备上使用 Frida 进行逆向分析。你需要同步 Android 平台的 SDK 依赖项。你可以运行类似 `python deps.py sync sdk android/arm64 ./frida_deps` 的命令，将 Android ARM64 的 SDK 下载到 `frida_deps` 目录。

* **功能：构建 (build)**
    * **说明：** 当没有预构建的依赖项可用，或者你需要修改某些依赖项的构建选项时，`build` 命令就派上用场。这与逆向中自定义工具或库的行为有相似之处。
    * **举例：**  如果你发现某个 Frida 的依赖库存在 bug，并且你已经修改了它的源代码。你可以使用 `build` 命令针对你的修改重新构建这个依赖项，例如 `python deps.py build --bundle sdk --build linux/x86_64 --host linux/x86_64 --only some_problematic_lib`。

* **功能：滚动 (roll)**
    * **说明：**  对于 Frida 的开发者或维护者来说，`roll` 命令用于发布新的 Frida 版本或更新依赖项。这涉及到构建、测试和部署的过程，类似于发布一个逆向分析工具的更新。
    * **举例：**  Frida 的开发者在更新了某个核心依赖库后，可以使用 `roll` 命令构建针对所有支持平台的依赖包，并将它们上传到服务器供用户下载。

**2. 二进制底层、Linux、Android 内核及框架的知识：**

* **操作系统和架构 (MachineSpec):**
    * **说明：** 脚本大量使用了 `MachineSpec` 类来表示不同的操作系统和架构（例如 `linux/x86_64`, `android/arm`）。这直接关系到二进制程序的兼容性和运行环境。
    * **举例：**  在 `sync` 或 `build` 命令中，你需要指定目标 `host` 机器的 `MachineSpec`，例如 `android/arm64`，表明你需要下载或构建适用于 Android 64 位 ARM 架构的依赖项。这涉及到对 Android 系统架构的理解。

* **工具链 (Toolchain):**
    * **说明：**  脚本中提到了 `Bundle.TOOLCHAIN`，指的是构建特定平台二进制文件所需的编译器、链接器等工具的集合。这与操作系统底层和内核开发密切相关。
    * **举例：**  构建 Android 平台的 Frida 依赖项需要 Android NDK 中的工具链。脚本可能会下载或使用预先配置好的 Android 工具链。

* **SDK (SDK):**
    * **说明：**  `Bundle.SDK` 通常包含特定平台的开发库、头文件等。对于 Android 逆向，这可能包括 Android SDK 中的一些组件或 Frida 定制的 SDK。
    * **举例：**  同步 Android SDK 依赖项会获取 Frida 在 Android 上运行时需要的库文件，这些库可能与 Android 框架层交互。

* **文件系统路径和操作:**
    * **说明：**  脚本使用 `pathlib` 模块进行文件和目录操作，例如创建、删除、重命名、读取文件等。这涉及到对不同操作系统文件系统结构的理解。
    * **举例：**  `sync` 命令会将下载的压缩包解压到指定的 `location` 目录。脚本需要处理不同操作系统下路径的表示方式。

* **进程执行 (subprocess):**
    * **说明：**  `roll` 和 `build` 命令会使用 `subprocess` 模块执行外部命令，例如 `aws s3 cp` 用于上传文件，以及 Meson 构建系统。
    * **举例：**  在构建依赖项时，脚本会调用 Meson 命令行工具来配置和编译源代码。这需要理解构建系统的使用。

**3. 逻辑推理 (假设输入与输出):**

* **假设输入:** `python deps.py sync sdk windows/x86_64 ./win_deps`
* **输出:**  脚本会尝试从预定义的 URL 下载适用于 Windows 64 位的 SDK 依赖包，并将其解压到当前目录下的 `win_deps` 文件夹中。屏幕上会显示下载和解压的进度信息。如果在 `win_deps` 目录下存在旧版本的 SDK，则会被删除。

* **假设输入:** `python deps.py build --bundle toolchain --build linux/arm --host linux/arm`
* **输出:** 脚本会尝试构建 Linux ARM 架构的工具链依赖项。这会涉及到克隆相关的源代码仓库，配置构建环境，然后使用编译器进行编译。输出会包含编译过程中的详细日志信息，最终将构建产物安装到指定目录。

**4. 用户或编程常见的使用错误：**

* **错误的 Bundle 类型:** 用户可能输入了不存在的 bundle 类型，例如 `python deps.py sync invalid_bundle ...`，`parse_bundle_option_value` 函数会捕获这个错误并给出提示信息。
* **错误的操作系统/架构:** 用户可能输入了不支持的操作系统和架构组合，`MachineSpec.parse` 可能会抛出异常。
* **网络问题:**  在 `sync` 或 `roll` 过程中，如果网络连接出现问题，下载文件可能会失败，导致脚本报错。
* **权限问题:**  脚本在创建或写入文件时，如果用户没有足够的权限，会导致操作失败。
* **缺少依赖工具:**  `roll` 命令依赖于 `aws` 命令行工具，如果用户没有安装，脚本会报错。
* **`location` 路径不存在或不可写:**  在 `sync` 命令中，如果指定的 `location` 路径不存在或者用户没有写入权限，脚本会出错。

**5. 用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Frida 时遇到了依赖项相关的问题，例如：

1. **Frida 运行时报错，提示缺少某些库文件。** 这可能意味着本地的依赖项不完整或版本不正确。
2. **用户想要为新的平台构建 Frida。** 这需要构建针对该平台的依赖项。
3. **用户是 Frida 的开发者，正在更新或修改某个依赖库。** 他需要重新构建并发布更新的依赖项。

为了解决这些问题，用户可能会执行以下步骤：

1. **查阅 Frida 的文档或开发指南，了解依赖项的管理方式。**  文档可能会指向 `deps.py` 脚本。
2. **导航到 Frida 源代码的 `frida/subprojects/frida-gum/releng/` 目录。**
3. **根据具体需求，执行 `deps.py` 脚本的相应命令。** 例如，使用 `sync` 命令同步依赖项，或使用 `build` 命令构建依赖项。
4. **如果出现错误，查看脚本的输出信息，根据错误提示进行调试。** 例如，检查网络连接、确认指定的操作系统和架构是否正确、检查是否安装了必要的工具等。

**总结（针对第 1 部分代码）：**

`deps.py` 的第一部分代码主要定义了脚本的入口 (`main` 函数)，以及处理命令行参数和分发到不同子命令的逻辑。它还定义了一些核心的辅助函数，例如解析 bundle 类型、解析操作系统和架构、查询工具链和 SDK 的路径，以及执行同步操作的 `sync` 函数。 核心概念如 `Bundle` 枚举和 `MachineSpec` 类也在这一部分被定义，为后续的依赖项管理操作提供了基础。  总而言之，这部分代码构建了脚本的骨架，并实现了最基础的依赖项同步功能。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/deps.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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