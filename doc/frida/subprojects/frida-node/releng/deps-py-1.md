Response:
The user wants to understand the functionality of the Python script `deps.py`. They are specifically interested in:
1. **General functionalities:** What does the script do?
2. **Relevance to reverse engineering:** How does it relate to the process of analyzing software?
3. **Involvement of low-level concepts:** Does it interact with binary data, Linux/Android kernel, or frameworks?
4. **Logical reasoning:** Can we infer inputs and outputs based on the code?
5. **Common user errors:** What mistakes might users make when using this script?
6. **User journey to this script:** How does a user end up executing this code?
7. **Summary of functionalities:** A concise overview of what the script does.

Let's break down the code section by section to address these points.

**Imports and Constants:** The script imports standard Python libraries like `os`, `time`, `subprocess`, `urllib`, `json`, `base64`, `shutil`, `re`, `graphlib`, `configparser`, and types from `typing` and `dataclasses`. It also defines some constants like `RELENG_DIR`, `DEPS_TOML_PATH`, and `BUNDLE_URL`. These hints suggest the script deals with managing dependencies, downloading files, interacting with Git, and possibly GitHub.

**`Ansi` Class:** This class seems to handle colored output in the terminal, checking for ANSI support. This is purely for user interface enhancement and doesn't directly relate to the core functionality.

**`wait` Function:** This function takes a `Bundle` and `MachineSpec` as input. It calculates a URL and filename based on these inputs and a dependency version. It then repeatedly tries to make a HEAD request to the URL until it succeeds or gets a non-404 error. This clearly indicates the function's purpose is to wait for a dependency bundle to become available at a specified URL.

**`bump` Function:** This function iterates through defined packages (likely from a configuration file). For each package, it checks if its version in the configuration matches the latest commit on its GitHub repository. If not, it updates the configuration file (`deps.toml`) and commits the changes to Git. This suggests a functionality to "bump" or update the versions of dependencies.

**`bump_wraps` Function:** This function focuses on "wrap" files within the subprojects of a dependency. It fetches the content of these wrap files, parses them, and checks if the referenced revision of another dependency matches the currently defined version. If there's a mismatch, it updates the wrap file and commits the changes. This further reinforces the dependency management aspect, specifically for nested dependencies managed by "wrap" files.

**Helper Functions:** Several helper functions are defined:
- `identifier_from_wrap_filename`: Extracts the identifier from a wrap filename.
- `compute_bundle_parameters`: Generates the URL and filename for a dependency bundle.
- `load_dependency_parameters`: Reads and parses the `deps.toml` file, loading dependency information.
- `iterate_package_ids_in_dependency_order`: Determines the order in which dependencies should be processed based on their dependencies on each other.
- `configure_bootstrap_version`: Updates the bootstrap version in the `deps.toml` file.
- `query_repo_commits`, `query_repo_trees`, `query_github_api`, `make_github_url`, `make_github_auth_header`: These functions interact with the GitHub API to fetch information about repositories (commits, trees).
- `clone_shallow`: Clones a Git repository with a shallow history.
- `parse_option`, `parse_dependency`: Parse option and dependency specifications from the configuration.
- `copy_files`: Copies files from one directory to another.
- `format_duration`: Formats a duration in seconds into HH:MM:SS.

**Data Classes and Enums:** The script defines several data classes (`DependencyParameters`, `PackageSpec`, `OptionSpec`, `DependencySpec`) and enums (`Bundle`, `SourceState`). These structures are used to organize and represent the dependency information.

**Main Block:** The `if __name__ == "__main__":` block suggests the script can be executed directly. However, the provided snippet doesn't include the `main()` function's definition, so we can't determine the exact entry point or command-line arguments.

Now, let's address the specific questions:

**Functionalities:** The script primarily focuses on managing dependencies for the Frida project. It can:
- Wait for dependency bundles to become available.
- Check for updates to dependency versions.
- Update dependency versions in the `deps.toml` configuration file.
- Update revisions of nested dependencies specified in `.wrap` files.
- Interact with the GitHub API to retrieve information about repositories.
- Clone Git repositories.

**Relationship to Reverse Engineering:**
- **Dependency Management:** In reverse engineering, tools often rely on external libraries and components. This script ensures that the correct versions of these dependencies are used and up-to-date. For example, Frida itself might depend on specific versions of libraries like V8 or Capstone. This script helps manage those dependencies.
- **Toolchain and SDK:** The mention of `Bundle.TOOLCHAIN` and `Bundle.SDK` suggests this script is involved in managing the build environment for Frida. A correct toolchain is crucial for compiling and packaging Frida, which is used for dynamic instrumentation in reverse engineering.
- **Example:** If a new version of a dependency (e.g., a JavaScript engine) is released with security fixes, this script can be used to update the Frida project to use the latest version, ensuring the security of Frida itself.

**Involvement of Low-Level Concepts:**
- **Binary Data:** While the script itself is in Python, it deals with downloading and managing binary bundles (like toolchains). The `.tar.xz` extension indicates compressed binary archives.
- **Linux and Android Kernel/Framework:** Frida often targets Linux and Android. The script likely manages dependencies that are specific to these operating systems or interact with their frameworks. For example, a dependency might be a library that interacts with the Android Binder IPC system.
- **Git and GitHub:** The script heavily uses Git for version control and interacts with GitHub for retrieving dependency information. This is fundamental for managing software projects, including those involved in reverse engineering.

**Logical Reasoning (Assumptions):**
- **Input:** If the `deps.toml` file specifies an outdated version for a dependency, and the GitHub repository for that dependency has a newer commit, the `bump()` function will:
    - **Output:** Update the `version` field in `deps.toml` for that dependency to the latest commit SHA.
    - **Output:** Create a Git commit with a message like "deps: Bump <dependency_name> to <latest_sha>".
- **Input:** If a `.wrap` file in a subproject refers to an older revision of another Frida dependency, the `bump_wraps()` function will:
    - **Output:** Update the `revision` field in the `.wrap` file to the current version of the referenced dependency.
    - **Output:** Create a Git commit within the subproject with a message like "subprojects: Bump <dependency_name> to <dependency_version>".

**Common User Errors:**
- **Incorrect or Missing `GH_USERNAME` and `GH_TOKEN`:** The script uses environment variables for GitHub authentication. If these are not set correctly, API requests to GitHub will fail.
    - **Error:**  Likely a `KeyError` when accessing the environment variables or an authentication error from the GitHub API.
- **Network Issues:**  The script relies on network connectivity to download bundles and communicate with GitHub. Network problems will cause failures.
    - **Error:** `urllib.error.URLError` or `urllib.error.HTTPError`.
- **Corrupted `deps.toml`:** Manually editing the `deps.toml` file incorrectly can lead to parsing errors.
    - **Error:**  Likely a `toml.TomlDecodeError`.
- **Git Issues:** Problems with the local Git repository (e.g., uncommitted changes, conflicts) can interfere with the `bump()` and `bump_wraps()` functions.
    - **Error:**  `subprocess.CalledProcessError` from the `run()` function.

**User Journey to This Script:**
1. **Developing or Maintaining Frida:** A developer working on Frida or one of its components would need to ensure dependencies are managed correctly.
2. **Running a Dependency Update Command:**  The user would likely execute a command that triggers this script. The exact command is not in the provided snippet, but it might be something like `python releng/deps.py bump` or a similar command integrated into the project's build system (e.g., a Makefile or a dedicated script).
3. **Automated Build Process:** This script could also be part of an automated build or continuous integration (CI) system that periodically checks for and updates dependencies.

**Summary of Functionalities (Part 2):** This part of the script focuses on:
- **Updating dependency versions:** The `bump()` and `bump_wraps()` functions are the core of this functionality. They compare the currently used versions with the latest available versions (typically from GitHub) and update the configuration files accordingly.
- **Managing nested dependencies:** The `bump_wraps()` function specifically handles dependencies that are included as subprojects using "wrap" files, ensuring consistency across the project.
- **Interacting with Git and GitHub:** The script automates the process of updating dependency versions by directly modifying configuration files and committing the changes to a Git repository. This streamlines the dependency management workflow.

这是 `frida/subprojects/frida-node/releng/deps.py` 文件的第二部分，延续了第一部分的功能，主要侧重于 **更新依赖版本** 和 **管理嵌套依赖**。以下是对其功能的详细解释，并结合您提出的问题进行说明：

**功能归纳（延续第一部分）：**

* **等待依赖包:** `wait(bundle: Bundle, machine: MachineSpec)` 函数的功能是等待指定的依赖包（`bundle`，例如 `TOOLCHAIN` 或 `SDK`）在指定的机器架构（`machine`）的构建完成后可以下载。它会不断尝试请求该依赖包的下载地址，直到成功或者遇到非 404 错误。

* **更新顶级依赖版本 (Bump):** `bump()` 函数的核心功能是检查并更新 `deps.toml` 文件中定义的顶级依赖项的版本。它会遍历每个依赖项，查询其在 GitHub 上的最新提交 SHA，如果 `deps.toml` 中的版本落后，则更新 `deps.toml` 文件，并将更改提交到 Git。

* **更新嵌套依赖版本 (Bump Wraps):** `bump_wraps(identifier: str, packages: Mapping[str, PackageSpec], run: Callable)` 函数负责更新子项目 (`subprojects`) 中 `.wrap` 文件里指定的嵌套依赖的版本。它会读取 `.wrap` 文件的内容，检查其中 `revision` 字段是否与当前定义的依赖版本一致，如果不一致则更新 `.wrap` 文件，并将更改提交到子项目的 Git 仓库。

* **辅助函数:**  定义了一系列辅助函数，用于从 `.wrap` 文件名提取标识符 (`identifier_from_wrap_filename`)，计算依赖包的 URL 和文件名 (`compute_bundle_parameters`)，加载依赖参数 (`load_dependency_parameters`)，按依赖顺序迭代包 ID (`iterate_package_ids_in_dependency_order`)，配置 bootstrap 版本 (`configure_bootstrap_version`)，查询 GitHub API (`query_repo_commits`, `query_repo_trees`, `query_github_api`)，构建 GitHub API URL 和认证头 (`make_github_url`, `make_github_auth_header`)，浅克隆 Git 仓库 (`clone_shallow`)，解析配置选项和依赖 (`parse_option`, `parse_dependency`)，复制文件 (`copy_files`)，以及格式化时间 (`format_duration`)。

* **数据类和枚举:**  定义了用于表示依赖参数、包规范、选项规范、依赖规范以及构建包类型的类和枚举。

**与逆向方法的关系：**

* **依赖管理：** 在逆向工程中，工具往往依赖于特定的库和组件。这个脚本确保了 Frida 使用的依赖项版本是最新的并且是兼容的。例如，Frida 可能会依赖于特定版本的 V8 JavaScript 引擎或 Capstone 反汇编库。`bump()` 和 `bump_wraps()` 保证了这些依赖是最新的，这对于工具的稳定性和安全性至关重要。
* **Toolchain 和 SDK：** `Bundle.TOOLCHAIN` 和 `Bundle.SDK` 的存在表明这个脚本参与管理 Frida 的构建环境。一个正确的 toolchain 是编译 Frida 的基础，而 Frida 本身是动态分析和逆向的重要工具。保持 toolchain 的更新可以避免编译错误或与新系统的不兼容问题。
* **示例:** 假设 Frida 依赖的一个反汇编库中存在安全漏洞。通过运行 `bump()`，该脚本可以检测到该库的新版本，并自动更新 `deps.toml` 和相关 `.wrap` 文件，从而修复潜在的安全问题。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

* **二进制包下载：** `wait()` 函数下载的依赖包通常是编译好的二进制文件 (`.tar.xz`)，例如特定平台的 toolchain 或 SDK。
* **目标平台：**  `MachineSpec` 包含了操作系统和架构信息，例如 `windows-x86` 或 `android-arm64`。这意味着脚本需要处理针对不同操作系统和架构的依赖。这隐含了对不同操作系统底层结构和 ABI 的理解。
* **Android 框架：** 虽然脚本本身没有直接操作 Android 内核或框架的代码，但它管理的依赖项很可能包含与 Android 框架交互的库。例如，Frida 可以 hook Android 系统服务，这需要依赖于能够理解 Android 框架内部机制的库。
* **Git 仓库和构建系统：** 脚本通过 Git 管理依赖版本，这在 Linux 和 Android 开发中非常常见。构建这些平台的软件通常需要依赖各种库和工具。

**逻辑推理：**

* **假设输入:** `deps.toml` 中 `libuv` 的 `version` 为 `v1.44.1`，而 GitHub 上 `frida/libuv` 仓库的 `main` 分支最新 commit SHA 为 `abcdefg1234567890`。
* **输出:** 运行 `bump()` 后，`deps.toml` 中 `libuv` 的 `version` 将被更新为 `abcdefg1234567890`，并且会生成一个 Git commit，消息为 "deps: Bump libuv to abcdefg1"。

* **假设输入:** `frida-node/subprojects/frida-core.wrap` 文件中 `frida-gum` 的 `revision` 为 `16.0.0`，而 `deps.toml` 中 `frida-gum` 的 `version` 为 `16.0.5`。
* **输出:** 运行 `bump_wraps()` 后，`frida-node/subprojects/frida-core.wrap` 文件中 `frida-gum` 的 `revision` 将被更新为 `16.0.5`，并且在 `frida-node` 仓库中会生成一个 Git commit，消息可能为 "subprojects: Bump frida-gum to 16.0.5"。

**涉及用户或者编程常见的使用错误：**

* **GitHub 认证问题：** 如果环境变量 `GH_USERNAME` 或 `GH_TOKEN` 未设置或设置错误，脚本在查询 GitHub API 时会失败。
    * **错误示例:** 运行 `bump()` 时，会抛出类似 `KeyError: 'GH_USERNAME'` 或 `urllib.error.HTTPError: HTTP Error 401: Unauthorized` 的异常。
* **网络连接问题：**  如果网络连接不稳定或无法访问 GitHub，脚本在下载依赖或查询 API 时会失败。
    * **错误示例:** 运行 `wait()` 或 `bump()` 时，会抛出类似 `urllib.error.URLError: <urlopen error timed out>` 的异常。
* **`deps.toml` 文件格式错误：** 如果用户手动修改 `deps.toml` 文件，可能引入语法错误，导致脚本解析失败。
    * **错误示例:** 运行任何需要加载 `deps.toml` 的函数时，会抛出类似 `toml.decoder.TomlDecodeError` 的异常。
* **Git 操作冲突：** 在运行 `bump()` 或 `bump_wraps()` 之前，如果本地 Git 仓库存在未提交的更改或存在冲突，脚本的 Git 操作可能会失败。
    * **错误示例:** 运行 `bump()` 或 `bump_wraps()` 时，会抛出 `subprocess.CalledProcessError`，显示 Git 命令执行失败，例如 "Your local changes to the following files would be overwritten by checkout"。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **Frida 开发或维护者需要更新依赖项：**  开发者可能意识到某个依赖项有新的版本发布，修复了 bug 或引入了新功能，或者安全团队要求更新存在安全漏洞的依赖项。
2. **运行依赖更新命令：**  开发者会执行一个特定的命令来触发 `deps.py` 脚本。这个命令可能是一个 Makefile 目标，或者是一个专门的脚本（例如 `python releng/deps.py bump`）。
3. **脚本执行 `bump()` 函数：**  该命令会调用 `deps.py` 中的 `bump()` 函数。
4. **`bump()` 函数遍历依赖项并查询 GitHub：**  `bump()` 函数会读取 `deps.toml`，然后针对每个依赖项，使用其 `url` 信息构建 GitHub API 请求，查询最新的 commit SHA。
5. **检测到版本不一致并更新 `deps.toml`：**  如果 GitHub 上的版本比 `deps.toml` 中记录的版本新，`bump()` 函数会修改 `deps.toml` 文件，更新对应的 `version` 字段。
6. **提交 Git 更改：**  `bump()` 函数会使用 `git add` 和 `git commit` 命令将 `deps.toml` 的更改提交到本地 Git 仓库。
7. **可能触发 `bump_wraps()`：** 在更新了顶级依赖的版本后，可能需要更新子项目中引用这些依赖的 `.wrap` 文件，此时可能会执行 `bump_wraps()` 函数来保持版本一致性。

总而言之，这个脚本是 Frida 项目中用于自动化管理依赖项版本的重要工具，它通过与 GitHub API 和本地 Git 仓库交互，确保项目使用的依赖项是最新的，并简化了依赖更新的流程。

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/deps.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
          ]), flush=True)

    def _print_status(self, scope: str, *args):
        status = " ".join([str(arg) for arg in args])
        if self._ansi_supported:
            print(f"│ \033[1m{scope}\033[0m :: {status}", flush=True)
        else:
            print(f"# {scope} :: {status}", flush=True)


def wait(bundle: Bundle, machine: MachineSpec):
    params = load_dependency_parameters()
    (url, filename) = compute_bundle_parameters(bundle, machine, params.deps_version)

    request = urllib.request.Request(url)
    request.get_method = lambda: "HEAD"
    started_at = time.time()
    while True:
        try:
            with urllib.request.urlopen(request) as r:
                return
        except urllib.request.HTTPError as e:
            if e.code != 404:
                return
        print("Waiting for: {}  Elapsed: {}  Retrying in 5 minutes...".format(url, int(time.time() - started_at)), flush=True)
        time.sleep(5 * 60)


def bump():
    def run(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
        return subprocess.run(argv,
                              capture_output=True,
                              encoding="utf-8",
                              check=True,
                              **kwargs)

    packages = load_dependency_parameters().packages
    for identifier in iterate_package_ids_in_dependency_order(packages.values()):
        pkg = packages[identifier]
        print(f"# Checking {pkg.name}")
        assert pkg.url.startswith("https://github.com/frida/"), f"{pkg.url}: unhandled URL"

        bump_wraps(identifier, packages, run)

        latest = query_repo_commits(identifier)["sha"]
        if pkg.version == latest:
            print(f"\tdeps.toml is up-to-date")
        else:
            print(f"\tdeps.toml is outdated")
            print(f"\t\tcurrent: {pkg.version}")
            print(f"\t\t latest: {latest}")

            f = TOMLFile(DEPS_TOML_PATH)
            config = f.read()
            config[identifier]["version"] = latest
            f.write(config)

            run(["git", "add", "deps.toml"], cwd=RELENG_DIR)
            run(["git", "commit", "-m" f"deps: Bump {pkg.name} to {latest[:7]}"], cwd=RELENG_DIR)

            packages = load_dependency_parameters().packages

        print("")


def bump_wraps(identifier: str,
               packages: Mapping[str, PackageSpec],
               run: Callable):
    root = query_repo_trees(identifier)
    subp_dir = next((t for t in root["tree"] if t["path"] == "subprojects"), None)
    if subp_dir is None or subp_dir["type"] != "tree":
        print("\tno wraps to bump")
        return

    all_wraps = [(entry, identifier_from_wrap_filename(entry["path"]))
                 for entry in query_github_api(subp_dir["url"])["tree"]
                 if entry["type"] == "blob" and entry["path"].endswith(".wrap")]
    relevant_wraps = [(blob, packages[identifier])
                      for blob, identifier in all_wraps
                      if identifier in packages]
    if not relevant_wraps:
        print(f"\tno relevant wraps, only: {', '.join([blob['path'] for blob, _ in all_wraps])}")
        return

    pending_wraps: list[tuple[str, str, PackageSpec]] = []
    for blob, spec in relevant_wraps:
        filename = blob["path"]

        response = query_github_api(blob["url"])
        assert response["encoding"] == "base64"
        data = base64.b64decode(response["content"])

        config = ConfigParser()
        config.read_file(data.decode("utf-8").split("\n"))

        if "wrap-git" not in config:
            print(f"\tskipping {filename} as it's not wrap-git")
            continue
        source = config["wrap-git"]

        url = source["url"]
        if not url.startswith("https://github.com/frida/"):
            print(f"\tskipping {filename} as URL is external: {url}")
            continue

        revision = source["revision"]
        if revision == spec.version:
            continue

        pending_wraps.append((filename, revision, spec))
    if not pending_wraps:
        print(f"\tall wraps up-to-date")
        return

    workdir = detect_cache_dir(ROOT_DIR) / "src"
    workdir.mkdir(parents=True, exist_ok=True)

    sourcedir = workdir / identifier
    if sourcedir.exists():
        shutil.rmtree(sourcedir)
    run(["git", "clone", "--depth", "1", f"git@github.com:frida/{identifier}.git"], cwd=workdir)

    subpdir = sourcedir / "subprojects"
    revision_pattern = re.compile(r"^(?P<key_equals>\s*revision\s*=\s*)\S+$", re.MULTILINE)
    for filename, revision, dep in pending_wraps:
        wrapfile = subpdir / filename
        old_config = wrapfile.read_text(encoding="utf-8")
        # Would be simpler to use ConfigParser to write it back out, but we
        # want to preserve the particular style to keep our patches minimal.
        new_config = revision_pattern.sub(fr"\g<key_equals>{dep.version}", old_config)
        wrapfile.write_text(new_config, encoding="utf-8")

        run(["git", "add", filename], cwd=subpdir)

        action = "Pin" if revision == "main" else "Bump"
        run(["git", "commit", "-m" f"subprojects: {action} {dep.name} to {dep.version[:7]}"], cwd=sourcedir)

        print(f"\tdid {action.lower()} {filename} to {dep.version} (from {revision})")

    run(["git", "push"], cwd=sourcedir)


def identifier_from_wrap_filename(filename: str) -> str:
    return filename.split(".", maxsplit=1)[0]


def compute_bundle_parameters(bundle: Bundle,
                              machine: MachineSpec,
                              version: str) -> tuple[str, str]:
    if bundle == Bundle.TOOLCHAIN and machine.os == "windows":
        os_arch_config = "windows-x86" if machine.arch in {"x86", "x86_64"} else machine.os_dash_arch
    else:
        os_arch_config = machine.identifier
    filename = f"{bundle.name.lower()}-{os_arch_config}.tar.xz"
    url = BUNDLE_URL.format(version=version, filename=filename)
    return (url, filename)


def load_dependency_parameters() -> DependencyParameters:
    config = TOMLFile(DEPS_TOML_PATH).read()

    packages = {}
    for identifier, pkg in config.items():
        if identifier == "dependencies":
            continue
        packages[identifier] = PackageSpec(identifier,
                                           pkg["name"],
                                           pkg["version"],
                                           pkg["url"],
                                           list(map(parse_option, pkg.get("options", []))),
                                           list(map(parse_dependency, pkg.get("dependencies", []))),
                                           pkg.get("scope"),
                                           pkg.get("when"))

    p = config["dependencies"]
    return DependencyParameters(p["version"], p["bootstrap_version"], packages)


def iterate_package_ids_in_dependency_order(packages: Sequence[PackageSpec]) -> Iterator[str]:
    ts = graphlib.TopologicalSorter({pkg.identifier: {dep.identifier for dep in pkg.dependencies}
                                     for pkg in packages})
    return ts.static_order()


def configure_bootstrap_version(version: str):
    f = TOMLFile(DEPS_TOML_PATH)
    config = f.read()
    config["dependencies"]["bootstrap_version"] = version
    f.write(config)


def query_repo_commits(repo: str,
                       organization: str = "frida",
                       branch: str = "main") -> dict:
    return query_github_api(make_github_url(f"/repos/{organization}/{repo}/commits/{branch}"))


def query_repo_trees(repo: str,
                     organization: str = "frida",
                     branch: str = "main") -> dict:
    return query_github_api(make_github_url(f"/repos/{organization}/{repo}/git/trees/{branch}"))


def query_github_api(url: str) -> dict:
    request = urllib.request.Request(url)
    request.add_header("Authorization", make_github_auth_header())
    with urllib.request.urlopen(request) as r:
        return json.load(r)


def make_github_url(path: str) -> str:
    return "https://api.github.com" + path


def make_github_auth_header() -> str:
    return "Basic " + base64.b64encode(":".join([
                                           os.environ["GH_USERNAME"],
                                           os.environ["GH_TOKEN"]
                                       ]).encode("utf-8")).decode("utf-8")


def clone_shallow(pkg: PackageSpec, outdir: Path, call_git: Callable):
    outdir.mkdir(parents=True, exist_ok=True)
    git = lambda *args: call_git(*args, cwd=outdir, check=True)
    git("init")
    git("remote", "add", "origin", pkg.url)
    git("fetch", "--depth", "1", "origin", pkg.version)
    git("checkout", "FETCH_HEAD")
    git("submodule", "update", "--init", "--recursive", "--depth", "1")


def parse_option(v: Union[str, dict]) -> OptionSpec:
    if isinstance(v, str):
        return OptionSpec(v)
    return OptionSpec(v["value"], v.get("when"))


def parse_dependency(v: Union[str, dict]) -> OptionSpec:
    if isinstance(v, str):
        return DependencySpec(v)
    return DependencySpec(v["id"], v.get("for_machine"), v.get("when"))


def copy_files(fromdir: Path,
               files: list[Path],
               todir: Path):
    for filename in files:
        src = fromdir / filename
        dst = todir / filename
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(src, dst, follow_symlinks=False)


def format_duration(duration_in_seconds: float) -> str:
    hours, remainder = divmod(duration_in_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return "{:02d}:{:02d}:{:02d}".format(int(hours), int(minutes), int(seconds))


class CommandError(Exception):
    pass


DEPS_TOML_PATH = RELENG_DIR / "deps.toml"

BUNDLE_URL = "https://build.frida.re/deps/{version}/{filename}"


class Bundle(Enum):
    TOOLCHAIN = 1,
    SDK = 2,


class BundleNotFoundError(Exception):
    pass


class SourceState(Enum):
    PRISTINE = 1,
    MODIFIED = 2,


@dataclass
class DependencyParameters:
    deps_version: str
    bootstrap_version: str
    packages: dict[str, PackageSpec]


@dataclass
class PackageSpec:
    identifier: str
    name: str
    version: str
    url: str
    options: list[OptionSpec] = field(default_factory=list)
    dependencies: list[DependencySpec] = field(default_factory=list)
    scope: Optional[str] = None
    when: Optional[str] = None


@dataclass
class OptionSpec:
    value: str
    when: Optional[str] = None


@dataclass
class DependencySpec:
    identifier: str
    for_machine: str = "host"
    when: Optional[str] = None


if __name__ == "__main__":
    main()

"""


```