Response:
The user wants to understand the functionality of the provided Python script, `deps.py`, which is part of the Frida dynamic instrumentation tool. They are particularly interested in how this script relates to reverse engineering, binary manipulation, Linux/Android kernel and framework knowledge, logical reasoning, potential user errors, and debugging.

To address this, I will:

1. **Analyze the code structure and functions:** Identify the main components and their purpose.
2. **Connect to reverse engineering concepts:** Explain how dependency management and pre-built components can aid in reverse engineering tasks.
3. **Identify interactions with low-level systems:** Pinpoint parts of the code dealing with toolchains, SDKs, and platform-specific configurations.
4. **Look for logical reasoning:** Analyze conditional statements and decision-making processes within the code.
5. **Identify potential user errors:** Think about common mistakes users might make when interacting with such a script.
6. **Trace the execution flow:** Consider how a user's actions could lead to the execution of different parts of the script.
7. **Summarize the core functionality:** Provide a concise overview of what the script does.
This Python script, `deps.py`, is a dependency management tool for the Frida project. Its primary function is to ensure that the necessary pre-built components (like toolchains and SDKs) for building Frida on various target platforms are available and up-to-date. It automates the process of downloading, building, and organizing these dependencies.

Here's a breakdown of its key functionalities:

**Core Functionalities:**

1. **Synchronization (`sync` command):** This is the core function for ensuring dependencies are present.
   - It checks if a local copy of the dependency exists at a specified `location`.
   - It compares the version of the local copy with the desired `version`.
   - If the local copy is outdated or missing, it downloads a pre-built bundle (either a toolchain or an SDK) from a remote location (likely an S3 bucket based on later code).
   - It extracts the downloaded bundle to the `location`.
   - It handles replacement of placeholders like `@FRIDA_TOOLROOT@` within extracted files, suggesting these files might contain hardcoded paths that need adjustment for the local environment.

2. **Rolling (`roll` command):** This function is responsible for building and uploading pre-built dependencies if they are missing remotely.
   - It first checks if a pre-built bundle for a given `bundle`, `host` (target machine), and the current dependency `version` exists remotely (likely on S3 and a CDN).
   - If the bundle is not found remotely, it triggers a local build using the `build` function.
   - It can optionally execute a `post-processing script` after building.
   - Finally, it uploads the built artifact to the remote location and purges the CDN cache.

3. **Building (`build` command):** This function handles the local building of dependency packages.
   - It utilizes a `Builder` class to manage the build process.
   - It takes parameters like the `bundle` type (SDK or toolchain), the `build` machine specification, and the `host` machine specification.
   - It allows for building only specific packages (`--only`) or excluding certain packages (`--exclude`).
   - It uses Meson as the build system.

4. **Waiting (`wait` command):**  This function likely waits for pre-built dependencies to become available. While the code doesn't explicitly show the waiting logic, its name suggests it might poll a remote location until a specific bundle is present.

5. **Bumping (`bump` command):** This function is responsible for updating dependency versions. The provided snippet doesn't show the implementation, but it would likely involve modifying a configuration file (like `deps.toml`) with new versions.

**Relationship to Reverse Engineering:**

This script is crucial for setting up the environment necessary for Frida to function, which is a powerful tool for dynamic instrumentation and reverse engineering.

* **Pre-built Toolchains:**  Reverse engineering often involves analyzing and manipulating compiled code. Having pre-built toolchains (compilers, linkers, debuggers) for different target architectures (like ARM, x86 on Linux, Android, Windows) simplifies the process of building Frida's components that interact with the target system. For instance, if you are reverse engineering an Android application on an ARM device, Frida needs to be built with an ARM cross-compilation toolchain. This script ensures that toolchain is available.
* **Pre-built SDKs:**  SDKs (Software Development Kits) provide necessary libraries and headers for building software targeting specific platforms. For example, an Android SDK provides access to the Android framework APIs. Frida needs access to these SDKs to interact with the target operating system's functionalities during runtime instrumentation.

**Example:** Imagine you want to use Frida to inspect the internal workings of a native library in an Android application. You would need to build the Frida agent that runs inside the application's process. This build process requires the Android NDK (Native Development Kit, which is part of the SDK) and a suitable cross-compilation toolchain for ARM. This `deps.py` script ensures these dependencies are available on your development machine before you attempt to build the Frida agent.

**Involvement of Binary 底层, Linux, Android 内核及框架 Knowledge:**

The script directly interacts with these concepts:

* **Binary 底层 (Binary Low-Level):** The script deals with toolchains that produce and manipulate binary executables. The concept of cross-compilation, where you build binaries for a different architecture than your host machine, is central. The script handles downloading and organizing these architecture-specific toolchains.
* **Linux:** The script includes logic specific to Linux (e.g., handling of shared library version scripts with `-Wl,--version-script`). It also interacts with common Linux tools like `tar`, `shutil`, and `subprocess`.
* **Android Kernel and Framework:** When dealing with the "sdk" bundle, the script is concerned with obtaining the Android SDK, which contains components related to the Android framework. Frida, when used on Android, often interacts with the Dalvik/ART runtime and the Android system services, requiring knowledge of the Android framework. The script sets up the prerequisites for building Frida components that interact at this level.

**Example:** The script's handling of `LDFLAGS` and the generation of version scripts for Linux toolchains directly relates to how shared libraries are built and linked in the Linux environment. Similarly, downloading and managing the Android SDK is directly tied to interacting with the Android framework.

**Logical Reasoning:**

The script uses logical reasoning in several places:

* **Conditional Checks:**  The `if` statements throughout the code (e.g., checking for existing files, comparing versions, checking the operating system) represent logical decisions about what actions to take.
* **Dependency Resolution:** The `Builder` class's `_resolve_dependencies` function performs a graph traversal to determine the order in which packages need to be built based on their dependencies. This involves logical deduction about the relationships between different components.
* **Platform-Specific Logic:** The script uses `if machine.os == "windows":` or similar checks to apply different logic based on the target operating system. This is a form of rule-based reasoning.

**Example (Hypothetical Input and Output for `sync`):**

**Input:**
```python
# Assuming the script is run with the following arguments:
python deps.py sync sdk android/arm64 ./my_frida_deps
```

**Assumptions:**

* `deps.toml` (a likely configuration file not shown) specifies the latest version of the Android SDK.
* The directory `./my_frida_deps/sdk-android-arm64` does not exist or has an outdated version.
* A pre-built Android SDK bundle for the specified version and architecture exists on the remote server.

**Output:**

The script would perform the following steps:

1. Determine the desired SDK version from `deps.toml`.
2. Construct the URL for the pre-built Android SDK bundle for the `android/arm64` target.
3. Display a progress message: "Downloading SDK <version> for android/arm64".
4. Download the bundle to a temporary location.
5. Display a progress message: "Extracting sdk".
6. Extract the contents of the downloaded bundle to `./my_frida_deps/sdk-android-arm64`.
7. Potentially replace placeholders like `@FRIDA_TOOLROOT@` in the extracted files with the actual path.
8. Create a `VERSION.txt` file inside `./my_frida_deps/sdk-android-arm64` containing the downloaded version.

**User or Programming Common Usage Errors:**

* **Incorrect Bundle Name:** Providing an invalid bundle name (e.g., `python deps.py sync invalid_bundle ...`) would lead to an `argparse.ArgumentTypeError` as handled by the `parse_bundle_option_value` function.
* **Invalid Machine Specification:**  Providing an incorrect OS/architecture combination (e.g., `python deps.py sync sdk linux/blah ...`) would cause `MachineSpec.parse` to raise an error.
* **Network Issues:** If the remote server is unavailable or there are network connectivity problems, the download process in the `sync` and `roll` functions would fail, potentially raising `urllib.error.HTTPError` or other network-related exceptions.
* **Missing Dependencies for Building:** If a user attempts to run the `build` command without the necessary system-level dependencies (like `git`, `meson`, `ninja`), the build process will fail. The script itself doesn't handle installing these system dependencies.
* **Incorrect Environment Variables:**  The script uses environment variables (e.g., `FRIDA_DEPS`). If these are set incorrectly, the script might look for dependencies in the wrong location.

**Example of User Action Leading Here (Debugging Scenario):**

Let's say a developer is trying to build Frida for an Android device. They might execute a build command like:

```bash
./build.sh android
```

This `build.sh` script (not shown) likely contains logic to invoke the `deps.py` script to ensure the necessary Android SDK is available. The `build.sh` script might call `deps.py` with the `sync` command:

```bash
python frida/subprojects/frida-tools/releng/deps.py sync sdk android/arm64 ./deps
```

If the Android SDK is not present or is outdated in the `./deps` directory, the `sync` function within `deps.py` would be executed. If a download error occurs during this process, the user would see an error message related to the network or the missing bundle. This leads the developer to investigate network connectivity or the correctness of the Frida version and target architecture they are trying to build for.

**Summary of Functionality (Part 1):**

The `deps.py` script is a dependency management tool for Frida. Its primary functions are to synchronize (download and update), roll (build and upload), and build pre-built dependency bundles (toolchains and SDKs) required for building Frida on various target platforms. It automates the process of obtaining and organizing these essential components, ensuring a consistent and reproducible build environment for Frida development. It interacts with remote servers to fetch pre-built binaries and uses platform-specific logic for handling different operating systems.

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/deps.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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