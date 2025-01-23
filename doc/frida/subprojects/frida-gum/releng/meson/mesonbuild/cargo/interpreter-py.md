Response:
Let's break down the thought process for analyzing the provided Python code. The request asks for several things, so a structured approach is necessary.

**1. Understanding the Core Task:**

The initial docstring and the filename clearly indicate this code is about converting Cargo (Rust's build system) `Cargo.toml` files into Meson (another build system) instructions. This is the central purpose.

**2. Identifying Key Functions and Data Structures:**

I'd scan the code for major functions and classes. This helps in understanding the workflow and the types of data being manipulated.

* **Data Classes:** `Package`, `Dependency`, `BuildTarget`, `Library`, `Binary`, `Test`, `Benchmark`, `Example`, `Manifest`. These represent the structure of `Cargo.toml` in Python. Notice how they map to Cargo concepts.
* **Core Functions:**
    * `load_toml`:  Handles reading the `Cargo.toml` file. The fallback mechanism for older Python versions using `toml2json` is important.
    * `_convert_manifest`: Takes the raw TOML data and converts it into the `Manifest` data class.
    * `_load_manifests`:  Handles loading manifests, including workspace members (sub-projects).
    * `_create_project`, `_create_features`, `_create_dependencies`, `_create_meson_subdir`, `_create_lib`: These functions generate Meson code (AST - Abstract Syntax Tree) based on the parsed Cargo manifest. They are crucial for the conversion process.
    * `interpret`: This seems to be the main entry point, orchestrating the conversion.
* **Helper Functions:** `fixup_meson_varname`, `_fixup_raw_mappings`, `_version_to_api`, `_dependency_name`, `_dependency_varname`, `_option_name`, `_options_varname`, `_extra_args_varname`, `_extra_deps_varname`, `_process_feature`. These perform specific transformations or lookups.

**3. Analyzing Functionality and Relating to the Request:**

Now, I'd go through the functions and classes, keeping the request's points in mind:

* **Functionality:**  The core functionality is TOML parsing and translation to Meson AST. It handles dependencies, features, targets (libraries, binaries, etc.), and workspace management. The fallback for older Python versions is a detail to note.
* **Reverse Engineering Relevance:** The conversion process is directly related to reverse engineering. By converting the build instructions, you gain insights into how a Rust project is structured, its dependencies, and build targets. This information is valuable for analyzing the final binaries.
* **Binary/Kernel/Framework Relevance:**  The code itself doesn't directly interact with the binary's *execution*. However, the *build process* it describes is essential for creating the binary. It handles linking dependencies (which are often compiled code), and the `crate_type` specifies the kind of output (static/shared library, executable). The interaction with the underlying system happens *during the build*, guided by these instructions. The `rust_abi` setting is a direct link to binary interface concerns. The interaction with the filesystem (`os.path.join`, `glob`) is also relevant to the underlying OS. While it doesn't directly manipulate Linux or Android kernel code, it lays the groundwork for building software that *runs* on those platforms.
* **Logical Reasoning:** The `_process_feature` function performs logical reasoning. It takes a feature and recursively determines the other features and dependencies that need to be enabled. The example input/output provided in the analysis directly stems from understanding how this function operates.
* **User/Programming Errors:** The code has error handling for missing `tomllib`/`toml2json` and malformed `Cargo.toml`. The check for consistent feature sets across dependency configurations is a key area for potential user errors, and the code explicitly addresses this.
* **User Journey/Debugging Clues:**  To reach this code, a user would likely be using Frida's build system, which uses Meson. The process of incorporating a Rust component or subproject into Frida's build would trigger the execution of this script. Debugging clues involve checking the `Cargo.toml` for correctness, ensuring the necessary TOML parser is installed, and looking at Meson's output for errors related to dependency resolution or feature flags.

**4. Structuring the Output:**

Finally, I would organize the information into the requested categories:

* **功能 (Functions):** List the main tasks the script performs.
* **与逆向方法的关系 (Relationship with Reverse Engineering):** Explain how the build information is useful for reverse engineering.
* **二进制底层，Linux, Android 内核及框架的知识 (Binary, Linux, Android Kernel/Framework Knowledge):** Discuss the aspects of the code that relate to building and the underlying operating system, even if it's indirect.
* **逻辑推理 (Logical Reasoning):** Focus on the `_process_feature` function and provide a clear example.
* **用户或者编程常见的使用错误 (Common User/Programming Errors):** Highlight potential issues like incorrect `Cargo.toml` or dependency conflicts.
* **用户操作是如何一步步的到达这里，作为调试线索 (User Actions and Debugging Clues):** Describe the steps that lead to this code being executed and how that information can be used for debugging.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  The code just parses TOML.
* **Correction:** It does more than just parse; it *translates* the information into Meson's syntax and logic. This translation is the core functionality.
* **Initial thought:**  The binary relevance is only about linking.
* **Refinement:**  The `crate_type` also dictates the *kind* of binary artifact produced (library, executable), which is a significant binary-level detail. The `rust_abi` is directly about binary interface compatibility.
* **Initial thought:** The user errors are only about syntax.
* **Refinement:** The dependency feature consistency check highlights a more complex, semantic error that can occur during the build process.

By following these steps, systematically analyzing the code, and keeping the specific questions in mind, I can generate a comprehensive and accurate response like the example provided.
这是 `frida/subprojects/frida-gum/releng/meson/mesonbuild/cargo/interpreter.py` 文件的功能分析。这个 Python 脚本的主要目的是**将 Cargo (Rust 的构建工具) 的 `Cargo.toml` 文件中的定义转换为 Meson 构建系统的抽象语法树 (AST)**。

以下是其功能的详细列表，并根据您的要求进行了分类说明：

**功能 (Functions):**

1. **解析 `Cargo.toml` 文件:**
   - 使用 `tomllib` (Python 3.11+) 或 `tomli` (早期版本) 库来读取和解析 `Cargo.toml` 文件。
   - 如果找不到这两个库，会尝试使用 `toml2json` 命令行工具将 TOML 转换为 JSON 再进行解析。这提供了一种兼容性回退方案。
   - 它会检查解析后的内容是否为字典，确保 `Cargo.toml` 文件的基本结构正确。

2. **转换 Cargo 数据结构为 Python 对象:**
   - 定义了多个 `dataclasses` (如 `Package`, `Dependency`, `Library`, `Binary` 等) 来表示 `Cargo.toml` 文件中的不同部分，并填充默认值。
   - 函数如 `_convert_manifest` 和 `Dependency.from_raw` 负责将解析后的原始数据转换为这些更易于操作的 Python 对象。
   - `_fixup_raw_mappings` 函数用于调整 Cargo 的命名约定 (例如将 `-` 替换为 `_`)，使其更符合 Python 的习惯。

3. **处理 Cargo Workspace:**
   - 如果 `Cargo.toml` 文件定义了一个 workspace，它会遍历 `workspace.members` 指定的子目录，并解析每个子目录中的 `Cargo.toml` 文件。
   - 支持 `workspace.exclude` 来排除特定的成员。

4. **处理 Cargo Feature Flags:**
   - 解析 `[features]` 部分定义的 feature flags。
   - `_process_feature` 函数负责分析每个 feature 的依赖关系，包括其他 feature 和依赖项。
   - 生成 Meson 代码来处理 feature 的启用和禁用，以及它们对依赖项的影响。

5. **生成 Meson AST:**
   - 使用 `builder.Builder` 类来构建 Meson 的抽象语法树。
   - 创建 `project()` 函数调用，定义 Meson 项目的基本信息 (名称、语言、版本、许可等)。
   - 创建 `dependency()` 函数调用来声明 Rust 依赖项，并处理版本约束、feature flags 等。
   - 生成代码来处理 Rust 的 crate 类型 (library, binary, example, test, benchmark)。
   - 生成 `subdir('meson')` 调用，允许 Cargo 子项目在 `meson/meson.build` 文件中添加额外的 Meson 构建逻辑。

6. **处理依赖关系:**
   - 解析 `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` 部分定义的依赖项。
   - 将 Cargo 的版本约束转换为 Meson 理解的格式。
   - 处理可选依赖 (optional dependencies)。
   - 检查依赖项的 feature flags 是否与当前项目的配置一致，如果不一致则报错。

7. **处理 Rust Target 类型:**
   - 支持多种 Rust target 类型，包括 library (`lib`), binary (`bin`), example (`example`), test (`test`), benchmark (`bench`)。
   - 根据 target 类型的不同，生成不同的 Meson 构建规则 (例如 `static_library`, `shared_library`, `executable`)。

**与逆向方法的关系 (Relationship with Reverse Engineering):**

这个脚本与逆向工程有间接但重要的关系：

- **理解目标软件的构建方式:** 通过分析 `Cargo.toml` 文件并将其转换为 Meson 构建脚本，逆向工程师可以更好地理解目标 Rust 软件的构建过程。这包括：
    - **依赖关系:** 了解软件依赖了哪些外部库 (crates)，以及这些库的版本和来源。这对于分析软件的功能和潜在的安全漏洞至关重要。 **例如，如果一个逆向工程师想要了解某个 Frida 组件使用了哪些加密库，他可以查看对应的 `Cargo.toml` 文件，并使用此脚本理解 Frida 的构建系统如何引入这些依赖。**
    - **Feature Flags:** 理解软件使用了哪些 feature flags 可以揭示软件的不同编译配置和功能变体。 **例如，某个 feature flag 可能会控制是否启用调试符号，这对于逆向分析来说是关键信息。**
    - **Target 类型:**  知道哪些 crates 被编译为库，哪些被编译为可执行文件，有助于理解软件的模块化结构。
    - **构建选项:**  虽然脚本本身不处理 `build.rs`，但它为理解构建过程提供了一个基础，并提示可能存在更复杂的构建逻辑。

- **辅助构建和修改:**  逆向工程师可能需要重新构建目标软件，例如添加调试代码、修改某些功能或修复漏洞。理解其构建系统是必要的步骤。虽然此脚本是单向的 (Cargo to Meson)，但它展示了如何将 Cargo 的定义转化为可执行的构建指令，为手动修改构建系统提供了参考。

**涉及到二进制底层，Linux, Android 内核及框架的知识 (Binary, Linux, Android Kernel/Framework Knowledge):**

虽然脚本本身是用 Python 编写的高级代码，但它所处理的信息与二进制底层、Linux/Android 系统密切相关：

- **Crate 类型和链接:**  脚本根据 `crate_type` (如 `lib`, `rlib`, `dylib`, `cdylib`, `bin`) 生成不同的 Meson 构建指令。这些类型直接对应于编译生成的二进制文件的类型 (静态库、动态库、可执行文件)。这涉及到操作系统对不同类型二进制文件的加载和链接机制。 **例如，当 `crate_type` 为 `cdylib` 时，生成的 Meson 代码会设置 `rust_abi='c'`，这表明生成的动态库需要与 C 代码兼容，这涉及到二进制接口 (ABI) 的知识。**
- **依赖项链接:**  脚本处理依赖项时，会生成 Meson 代码来链接这些依赖库。这涉及到操作系统的动态链接器如何找到和加载共享库。在 Linux 和 Android 上，这涉及到对共享库路径 (`LD_LIBRARY_PATH`) 和相关机制的理解。
- **目标平台:** 虽然脚本本身不直接指定目标平台，但 Frida 作为动态插桩工具，其构建过程需要考虑目标操作系统 (如 Linux, Android)。此脚本作为 Frida 构建系统的一部分，其输出的 Meson 构建脚本最终会针对特定的目标平台进行配置和编译。
- **系统调用和 API:**  虽然不直接体现在此脚本中，但被构建的 Rust 代码最终会通过系统调用或框架 API 与操作系统内核或框架进行交互。理解构建过程有助于理解最终二进制文件与底层系统的交互方式。

**逻辑推理 (Logical Reasoning):**

脚本中 `_process_feature` 函数进行了逻辑推理，用于分析 Cargo feature flags 的依赖关系。

**假设输入:**

```python
cargo = Manifest(
    package=Package(name="my_crate", version="0.1.0"),
    dependencies={},
    dev_dependencies={},
    build_dependencies={},
    lib=Library(name="my_crate", path="src/lib.rs"),
    bin=[],
    test=[],
    bench=[],
    example=[],
    features={
        "feature_a": ["dep:dependency_x", "feature_b"],
        "feature_b": ["dependency_y/feat_y"],
        "feature_c": [],
    },
    target={},
    subdir="",
)
feature_name = "feature_a"
```

**输出 (调用 `_process_feature(cargo, feature_name)`):**

```python
features, dep_features, required_deps = _process_feature(cargo, feature_name)
print(f"Enabled Features: {features}")
print(f"Dependency Features: {dep_features}")
print(f"Required Dependencies: {required_deps}")
```

**预期输出:**

```
Enabled Features: {'feature_a', 'feature_b'}
Dependency Features: {'dependency_y': {'feat_y'}}
Required Dependencies: {'dependency_x'}
```

**解释:**

- 当处理 `feature_a` 时，它依赖于 `dep:dependency_x` (意味着需要 `dependency_x`) 和 `feature_b`.
- 处理 `feature_b` 时，它依赖于 `dependency_y/feat_y` (意味着需要在 `dependency_y` 上启用 `feat_y` feature)。
- 因此，最终 `feature_a` 的启用会导致 `feature_a` 和 `feature_b` 被启用，需要 `dependency_x`，并且需要在 `dependency_y` 上启用 `feat_y`。

**用户或者编程常见的使用错误 (Common User/Programming Errors):**

1. **`Cargo.toml` 文件格式错误:** 如果 `Cargo.toml` 文件不符合 TOML 语法，脚本在解析时会抛出 `MesonException`。 **例如，忘记闭合字符串引号或者使用了无效的键值对。用户在构建 Frida 时，如果修改了某个 Rust 组件的 `Cargo.toml` 引入了语法错误，就会导致构建失败。**
2. **缺少 `tomllib` 或 `tomli` 库，且未安装 `toml2json`:** 如果运行脚本的 Python 环境缺少必要的 TOML 解析库，且 `toml2json` 命令也无法找到，脚本会抛出 `MesonException`。 **用户在较旧的 Python 环境中构建 Frida 时，可能需要手动安装 `tomli` 或确保 `toml2json` 在其 PATH 环境变量中。**
3. **依赖项版本冲突:** 虽然此脚本主要负责转换，但它生成的 Meson 代码最终会传递给 Meson 进行依赖项解析。如果 `Cargo.toml` 中指定的依赖项版本与其他依赖项产生冲突，Meson 构建过程会失败。 **用户在修改 Frida 的依赖项版本时，可能会引入版本冲突，导致构建失败。**
4. **Feature flag 配置错误:** 用户可能在 Meson 构建时错误地配置了 feature flags，导致与 `Cargo.toml` 中定义的依赖关系不一致。脚本中对依赖项 feature 的检查可以捕获这类错误。 **例如，用户可能在 Meson 配置中禁用了某个 feature，但该 feature 是某个依赖项所必需的，脚本会检测到这种不一致并报错。**

**用户操作是如何一步步的到达这里，作为调试线索 (User Actions and Debugging Clues):**

1. **用户尝试构建 Frida:** 用户执行 Frida 的构建命令，例如使用 Meson 进行构建 (`meson setup _build` 和 `ninja -C _build`).
2. **Meson 处理子项目:** 当 Meson 构建系统处理 Frida 的 `frida-gum` 子项目时，它会发现该子项目包含 Rust 代码，并需要处理其 `Cargo.toml` 文件。
3. **调用 `interpreter.py`:** Meson 构建系统会调用 `frida/subprojects/frida-gum/releng/meson/mesonbuild/cargo/interpreter.py` 脚本来解析 `Cargo.toml` 文件并生成相应的 Meson 构建指令。
4. **脚本执行和错误:** 如果 `Cargo.toml` 文件存在错误，或者缺少必要的依赖库，此脚本会抛出异常并导致 Meson 构建过程失败。

**调试线索:**

- **查看 Meson 的构建日志:**  Meson 的构建日志通常会显示调用此脚本时的参数和任何抛出的异常信息。
- **检查 `Cargo.toml` 文件:**  确认 `Cargo.toml` 文件是否符合 TOML 语法，并且依赖项和 feature 定义是否正确。
- **检查 Python 环境:** 确认运行构建的 Python 环境中是否安装了 `tomllib` 或 `tomli` 库，或者 `toml2json` 命令是否可用。
- **手动运行脚本 (谨慎):**  在某些情况下，可以尝试手动运行 `interpreter.py` 脚本，并提供 `Cargo.toml` 文件的路径作为输入，以便更直接地观察脚本的执行过程和错误信息。但这需要对脚本的输入和输出有一定的了解。
- **检查 Meson 选项:**  确认 Meson 的构建选项是否与 `Cargo.toml` 中的 feature 定义一致。

总而言之，`interpreter.py` 是 Frida 构建过程中一个关键的桥梁，它将 Rust 项目的声明式构建配置转换为 Meson 的命令式构建指令，使得 Frida 能够集成和构建 Rust 组件。理解此脚本的功能有助于理解 Frida 的构建流程，并在遇到构建问题时提供调试线索。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/mesonbuild/cargo/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
# SPDX-License-Identifier: Apache-2.0
# Copyright © 2022-2024 Intel Corporation

"""Interpreter for converting Cargo Toml definitions to Meson AST

There are some notable limits here. We don't even try to convert something with
a build.rs: there's so few limits on what Cargo allows a build.rs (basically
none), and no good way for us to convert them. In that case, an actual meson
port will be required.
"""

from __future__ import annotations
import dataclasses
import glob
import importlib
import itertools
import json
import os
import shutil
import collections
import typing as T

from . import builder
from . import version
from ..mesonlib import MesonException, Popen_safe, OptionKey
from .. import coredata

if T.TYPE_CHECKING:
    from types import ModuleType

    from . import manifest
    from .. import mparser
    from ..environment import Environment
    from ..coredata import KeyedOptionDictType

# tomllib is present in python 3.11, before that it is a pypi module called tomli,
# we try to import tomllib, then tomli,
# TODO: add a fallback to toml2json?
tomllib: T.Optional[ModuleType] = None
toml2json: T.Optional[str] = None
for t in ['tomllib', 'tomli']:
    try:
        tomllib = importlib.import_module(t)
        break
    except ImportError:
        pass
else:
    # TODO: it would be better to use an Executable here, which could be looked
    # up in the cross file or provided by a wrap. However, that will have to be
    # passed in externally, since we don't have (and I don't think we should),
    # have access to the `Environment` for that in this module.
    toml2json = shutil.which('toml2json')


def load_toml(filename: str) -> T.Dict[object, object]:
    if tomllib:
        with open(filename, 'rb') as f:
            raw = tomllib.load(f)
    else:
        if toml2json is None:
            raise MesonException('Could not find an implementation of tomllib, nor toml2json')

        p, out, err = Popen_safe([toml2json, filename])
        if p.returncode != 0:
            raise MesonException('toml2json failed to decode output\n', err)

        raw = json.loads(out)

    if not isinstance(raw, dict):
        raise MesonException("Cargo.toml isn't a dictionary? How did that happen?")

    return raw


def fixup_meson_varname(name: str) -> str:
    """Fixup a meson variable name

    :param name: The name to fix
    :return: the fixed name
    """
    return name.replace('-', '_')


# Pylance can figure out that these do not, in fact, overlap, but mypy can't
@T.overload
def _fixup_raw_mappings(d: manifest.BuildTarget) -> manifest.FixedBuildTarget: ...  # type: ignore

@T.overload
def _fixup_raw_mappings(d: manifest.LibTarget) -> manifest.FixedLibTarget: ...  # type: ignore

@T.overload
def _fixup_raw_mappings(d: manifest.Dependency) -> manifest.FixedDependency: ...

def _fixup_raw_mappings(d: T.Union[manifest.BuildTarget, manifest.LibTarget, manifest.Dependency]
                        ) -> T.Union[manifest.FixedBuildTarget, manifest.FixedLibTarget,
                                     manifest.FixedDependency]:
    """Fixup raw cargo mappings to ones more suitable for python to consume.

    This does the following:
    * replaces any `-` with `_`, cargo likes the former, but python dicts make
      keys with `-` in them awkward to work with
    * Convert Dependndency versions from the cargo format to something meson
      understands

    :param d: The mapping to fix
    :return: the fixed string
    """
    raw = {fixup_meson_varname(k): v for k, v in d.items()}
    if 'version' in raw:
        assert isinstance(raw['version'], str), 'for mypy'
        raw['version'] = version.convert(raw['version'])
    return T.cast('T.Union[manifest.FixedBuildTarget, manifest.FixedLibTarget, manifest.FixedDependency]', raw)


@dataclasses.dataclass
class Package:

    """Representation of a Cargo Package entry, with defaults filled in."""

    name: str
    version: str
    description: T.Optional[str] = None
    resolver: T.Optional[str] = None
    authors: T.List[str] = dataclasses.field(default_factory=list)
    edition: manifest.EDITION = '2015'
    rust_version: T.Optional[str] = None
    documentation: T.Optional[str] = None
    readme: T.Optional[str] = None
    homepage: T.Optional[str] = None
    repository: T.Optional[str] = None
    license: T.Optional[str] = None
    license_file: T.Optional[str] = None
    keywords: T.List[str] = dataclasses.field(default_factory=list)
    categories: T.List[str] = dataclasses.field(default_factory=list)
    workspace: T.Optional[str] = None
    build: T.Optional[str] = None
    links: T.Optional[str] = None
    exclude: T.List[str] = dataclasses.field(default_factory=list)
    include: T.List[str] = dataclasses.field(default_factory=list)
    publish: bool = True
    metadata: T.Dict[str, T.Dict[str, str]] = dataclasses.field(default_factory=dict)
    default_run: T.Optional[str] = None
    autobins: bool = True
    autoexamples: bool = True
    autotests: bool = True
    autobenches: bool = True


@dataclasses.dataclass
class Dependency:

    """Representation of a Cargo Dependency Entry."""

    name: dataclasses.InitVar[str]
    version: T.List[str]
    registry: T.Optional[str] = None
    git: T.Optional[str] = None
    branch: T.Optional[str] = None
    rev: T.Optional[str] = None
    path: T.Optional[str] = None
    optional: bool = False
    package: str = ''
    default_features: bool = True
    features: T.List[str] = dataclasses.field(default_factory=list)
    api: str = dataclasses.field(init=False)

    def __post_init__(self, name: str) -> None:
        self.package = self.package or name
        # Extract wanted API version from version constraints.
        api = set()
        for v in self.version:
            if v.startswith(('>=', '==')):
                api.add(_version_to_api(v[2:].strip()))
            elif v.startswith('='):
                api.add(_version_to_api(v[1:].strip()))
        if not api:
            self.api = '0'
        elif len(api) == 1:
            self.api = api.pop()
        else:
            raise MesonException(f'Cannot determine minimum API version from {self.version}.')

    @classmethod
    def from_raw(cls, name: str, raw: manifest.DependencyV) -> Dependency:
        """Create a dependency from a raw cargo dictionary"""
        if isinstance(raw, str):
            return cls(name, version.convert(raw))
        return cls(name, **_fixup_raw_mappings(raw))


@dataclasses.dataclass
class BuildTarget:

    name: str
    crate_type: T.List[manifest.CRATE_TYPE] = dataclasses.field(default_factory=lambda: ['lib'])
    path: dataclasses.InitVar[T.Optional[str]] = None

    # https://doc.rust-lang.org/cargo/reference/cargo-targets.html#the-test-field
    # True for lib, bin, test
    test: bool = True

    # https://doc.rust-lang.org/cargo/reference/cargo-targets.html#the-doctest-field
    # True for lib
    doctest: bool = False

    # https://doc.rust-lang.org/cargo/reference/cargo-targets.html#the-bench-field
    # True for lib, bin, benchmark
    bench: bool = True

    # https://doc.rust-lang.org/cargo/reference/cargo-targets.html#the-doc-field
    # True for libraries and binaries
    doc: bool = False

    harness: bool = True
    edition: manifest.EDITION = '2015'
    required_features: T.List[str] = dataclasses.field(default_factory=list)
    plugin: bool = False


@dataclasses.dataclass
class Library(BuildTarget):

    """Representation of a Cargo Library Entry."""

    doctest: bool = True
    doc: bool = True
    path: str = os.path.join('src', 'lib.rs')
    proc_macro: bool = False
    crate_type: T.List[manifest.CRATE_TYPE] = dataclasses.field(default_factory=lambda: ['lib'])
    doc_scrape_examples: bool = True


@dataclasses.dataclass
class Binary(BuildTarget):

    """Representation of a Cargo Bin Entry."""

    doc: bool = True


@dataclasses.dataclass
class Test(BuildTarget):

    """Representation of a Cargo Test Entry."""

    bench: bool = True


@dataclasses.dataclass
class Benchmark(BuildTarget):

    """Representation of a Cargo Benchmark Entry."""

    test: bool = True


@dataclasses.dataclass
class Example(BuildTarget):

    """Representation of a Cargo Example Entry."""

    crate_type: T.List[manifest.CRATE_TYPE] = dataclasses.field(default_factory=lambda: ['bin'])


@dataclasses.dataclass
class Manifest:

    """Cargo Manifest definition.

    Most of these values map up to the Cargo Manifest, but with default values
    if not provided.

    Cargo subprojects can contain what Meson wants to treat as multiple,
    interdependent, subprojects.

    :param subdir: the subdirectory that this cargo project is in
    :param path: the path within the cargo subproject.
    """

    package: Package
    dependencies: T.Dict[str, Dependency]
    dev_dependencies: T.Dict[str, Dependency]
    build_dependencies: T.Dict[str, Dependency]
    lib: Library
    bin: T.List[Binary]
    test: T.List[Test]
    bench: T.List[Benchmark]
    example: T.List[Example]
    features: T.Dict[str, T.List[str]]
    target: T.Dict[str, T.Dict[str, Dependency]]
    subdir: str
    path: str = ''

    def __post_init__(self) -> None:
        self.features.setdefault('default', [])


def _convert_manifest(raw_manifest: manifest.Manifest, subdir: str, path: str = '') -> Manifest:
    # This cast is a bit of a hack to deal with proc-macro
    lib = _fixup_raw_mappings(raw_manifest.get('lib', {}))

    # We need to set the name field if it's not set manually,
    # including if other fields are set in the lib section
    lib.setdefault('name', raw_manifest['package']['name'])

    pkg = T.cast('manifest.FixedPackage',
                 {fixup_meson_varname(k): v for k, v in raw_manifest['package'].items()})

    return Manifest(
        Package(**pkg),
        {k: Dependency.from_raw(k, v) for k, v in raw_manifest.get('dependencies', {}).items()},
        {k: Dependency.from_raw(k, v) for k, v in raw_manifest.get('dev-dependencies', {}).items()},
        {k: Dependency.from_raw(k, v) for k, v in raw_manifest.get('build-dependencies', {}).items()},
        Library(**lib),
        [Binary(**_fixup_raw_mappings(b)) for b in raw_manifest.get('bin', {})],
        [Test(**_fixup_raw_mappings(b)) for b in raw_manifest.get('test', {})],
        [Benchmark(**_fixup_raw_mappings(b)) for b in raw_manifest.get('bench', {})],
        [Example(**_fixup_raw_mappings(b)) for b in raw_manifest.get('example', {})],
        raw_manifest.get('features', {}),
        {k: {k2: Dependency.from_raw(k2, v2) for k2, v2 in v.get('dependencies', {}).items()}
         for k, v in raw_manifest.get('target', {}).items()},
        subdir,
        path,
    )


def _load_manifests(subdir: str) -> T.Dict[str, Manifest]:
    filename = os.path.join(subdir, 'Cargo.toml')
    raw = load_toml(filename)

    manifests: T.Dict[str, Manifest] = {}

    raw_manifest: T.Union[manifest.Manifest, manifest.VirtualManifest]
    if 'package' in raw:
        raw_manifest = T.cast('manifest.Manifest', raw)
        manifest_ = _convert_manifest(raw_manifest, subdir)
        manifests[manifest_.package.name] = manifest_
    else:
        raw_manifest = T.cast('manifest.VirtualManifest', raw)

    if 'workspace' in raw_manifest:
        # XXX: need to verify that python glob and cargo globbing are the
        # same and probably write  a glob implementation. Blarg

        # We need to chdir here to make the glob work correctly
        pwd = os.getcwd()
        os.chdir(subdir)
        members: T.Iterable[str]
        try:
            members = itertools.chain.from_iterable(
                glob.glob(m) for m in raw_manifest['workspace']['members'])
        finally:
            os.chdir(pwd)
        if 'exclude' in raw_manifest['workspace']:
            members = (x for x in members if x not in raw_manifest['workspace']['exclude'])

        for m in members:
            filename = os.path.join(subdir, m, 'Cargo.toml')
            raw = load_toml(filename)

            raw_manifest = T.cast('manifest.Manifest', raw)
            man = _convert_manifest(raw_manifest, subdir, m)
            manifests[man.package.name] = man

    return manifests


def _version_to_api(version: str) -> str:
    # x.y.z -> x
    # 0.x.y -> 0.x
    # 0.0.x -> 0
    vers = version.split('.')
    if int(vers[0]) != 0:
        return vers[0]
    elif len(vers) >= 2 and int(vers[1]) != 0:
        return f'0.{vers[1]}'
    return '0'


def _dependency_name(package_name: str, api: str) -> str:
    basename = package_name[:-3] if package_name.endswith('-rs') else package_name
    return f'{basename}-{api}-rs'


def _dependency_varname(package_name: str) -> str:
    return f'{fixup_meson_varname(package_name)}_dep'


_OPTION_NAME_PREFIX = 'feature-'


def _option_name(feature: str) -> str:
    # Add a prefix to avoid collision with Meson reserved options (e.g. "debug")
    return _OPTION_NAME_PREFIX + feature


def _options_varname(depname: str) -> str:
    return f'{fixup_meson_varname(depname)}_options'


def _extra_args_varname() -> str:
    return 'extra_args'


def _extra_deps_varname() -> str:
    return 'extra_deps'


def _create_project(cargo: Manifest, build: builder.Builder) -> T.List[mparser.BaseNode]:
    """Create a function call

    :param cargo: The Manifest to generate from
    :param build: The AST builder
    :return: a list nodes
    """
    args: T.List[mparser.BaseNode] = []
    args.extend([
        build.string(cargo.package.name),
        build.string('rust'),
    ])
    kwargs: T.Dict[str, mparser.BaseNode] = {
        'version': build.string(cargo.package.version),
        # Always assume that the generated meson is using the latest features
        # This will warn when when we generate deprecated code, which is helpful
        # for the upkeep of the module
        'meson_version': build.string(f'>= {coredata.stable_version}'),
        'default_options': build.array([build.string(f'rust_std={cargo.package.edition}')]),
    }
    if cargo.package.license:
        kwargs['license'] = build.string(cargo.package.license)
    elif cargo.package.license_file:
        kwargs['license_files'] = build.string(cargo.package.license_file)

    return [build.function('project', args, kwargs)]


def _process_feature(cargo: Manifest, feature: str) -> T.Tuple[T.Set[str], T.Dict[str, T.Set[str]], T.Set[str]]:
    # Set of features that must also be enabled if this feature is enabled.
    features: T.Set[str] = set()
    # Map dependency name to a set of features that must also be enabled on that
    # dependency if this feature is enabled.
    dep_features: T.Dict[str, T.Set[str]] = collections.defaultdict(set)
    # Set of dependencies that are required if this feature is enabled.
    required_deps: T.Set[str] = set()
    # Set of features that must be processed recursively.
    to_process: T.Set[str] = {feature}
    while to_process:
        f = to_process.pop()
        if '/' in f:
            dep, dep_f = f.split('/', 1)
            if dep[-1] == '?':
                dep = dep[:-1]
            else:
                required_deps.add(dep)
            dep_features[dep].add(dep_f)
        elif f.startswith('dep:'):
            required_deps.add(f[4:])
        elif f not in features:
            features.add(f)
            to_process.update(cargo.features.get(f, []))
            # A feature can also be a dependency
            if f in cargo.dependencies:
                required_deps.add(f)
    return features, dep_features, required_deps


def _create_features(cargo: Manifest, build: builder.Builder) -> T.List[mparser.BaseNode]:
    # https://doc.rust-lang.org/cargo/reference/features.html#the-features-section

    # Declare a dict that map enabled features to true. One for current project
    # and one per dependency.
    ast: T.List[mparser.BaseNode] = []
    ast.append(build.assign(build.dict({}), 'features'))
    for depname in cargo.dependencies:
        ast.append(build.assign(build.dict({}), _options_varname(depname)))

    # Declare a dict that map required dependencies to true
    ast.append(build.assign(build.dict({}), 'required_deps'))

    for feature in cargo.features:
        # if get_option(feature)
        #   required_deps += {'dep': true, ...}
        #   features += {'foo': true, ...}
        #   xxx_options += {'feature-foo': true, ...}
        #   ...
        # endif
        features, dep_features, required_deps = _process_feature(cargo, feature)
        lines: T.List[mparser.BaseNode] = [
            build.plusassign(
                build.dict({build.string(d): build.bool(True) for d in required_deps}),
                'required_deps'),
            build.plusassign(
                build.dict({build.string(f): build.bool(True) for f in features}),
                'features'),
        ]
        for depname, enabled_features in dep_features.items():
            lines.append(build.plusassign(
                build.dict({build.string(_option_name(f)): build.bool(True) for f in enabled_features}),
                _options_varname(depname)))

        ast.append(build.if_(build.function('get_option', [build.string(_option_name(feature))]), build.block(lines)))

    ast.append(build.function('message', [
        build.string('Enabled features:'),
        build.method('keys', build.identifier('features'))],
    ))

    return ast


def _create_dependencies(cargo: Manifest, build: builder.Builder) -> T.List[mparser.BaseNode]:
    ast: T.List[mparser.BaseNode] = []
    for name, dep in cargo.dependencies.items():
        # xxx_options += {'feature-default': true, ...}
        extra_options: T.Dict[mparser.BaseNode, mparser.BaseNode] = {
            build.string(_option_name('default')): build.bool(dep.default_features),
        }
        for f in dep.features:
            extra_options[build.string(_option_name(f))] = build.bool(True)
        ast.append(build.plusassign(build.dict(extra_options), _options_varname(name)))

        kw = {
            'version': build.array([build.string(s) for s in dep.version]),
            'default_options': build.identifier(_options_varname(name)),
        }
        if dep.optional:
            kw['required'] = build.method('get', build.identifier('required_deps'), [
                build.string(name), build.bool(False)
            ])

        # Lookup for this dependency with the features we want in default_options kwarg.
        #
        # However, this subproject could have been previously configured with a
        # different set of features. Cargo collects the set of features globally
        # but Meson can only use features enabled by the first call that triggered
        # the configuration of that subproject.
        #
        # Verify all features that we need are actually enabled for that dependency,
        # otherwise abort with an error message. The user has to set the corresponding
        # option manually with -Dxxx-rs:feature-yyy=true, or the main project can do
        # that in its project(..., default_options: ['xxx-rs:feature-yyy=true']).
        ast.extend([
            # xxx_dep = dependency('xxx', version : ..., default_options : xxx_options)
            build.assign(
                build.function(
                    'dependency',
                    [build.string(_dependency_name(dep.package, dep.api))],
                    kw,
                ),
                _dependency_varname(dep.package),
            ),
            # if xxx_dep.found()
            build.if_(build.method('found', build.identifier(_dependency_varname(dep.package))), build.block([
                # actual_features = xxx_dep.get_variable('features', default_value : '').split(',')
                build.assign(
                    build.method(
                        'split',
                        build.method(
                            'get_variable',
                            build.identifier(_dependency_varname(dep.package)),
                            [build.string('features')],
                            {'default_value': build.string('')}
                        ),
                        [build.string(',')],
                    ),
                    'actual_features'
                ),
                # needed_features = []
                # foreach f, _ : xxx_options
                #   needed_features += f.substring(8)
                # endforeach
                build.assign(build.array([]), 'needed_features'),
                build.foreach(['f', 'enabled'], build.identifier(_options_varname(name)), build.block([
                    build.if_(build.identifier('enabled'), build.block([
                        build.plusassign(
                            build.method('substring', build.identifier('f'), [build.number(len(_OPTION_NAME_PREFIX))]),
                            'needed_features'),
                    ])),
                ])),
                # foreach f : needed_features
                #   if f not in actual_features
                #     error()
                #   endif
                # endforeach
                build.foreach(['f'], build.identifier('needed_features'), build.block([
                    build.if_(build.not_in(build.identifier('f'), build.identifier('actual_features')), build.block([
                        build.function('error', [
                            build.string('Dependency'),
                            build.string(_dependency_name(dep.package, dep.api)),
                            build.string('previously configured with features'),
                            build.identifier('actual_features'),
                            build.string('but need'),
                            build.identifier('needed_features'),
                        ])
                    ]))
                ])),
            ])),
        ])
    return ast


def _create_meson_subdir(cargo: Manifest, build: builder.Builder) -> T.List[mparser.BaseNode]:
    # Allow Cargo subprojects to add extra Rust args in meson/meson.build file.
    # This is used to replace build.rs logic.

    # extra_args = []
    # extra_deps = []
    # fs = import('fs')
    # if fs.is_dir('meson')
    #  subdir('meson')
    # endif
    return [
        build.assign(build.array([]), _extra_args_varname()),
        build.assign(build.array([]), _extra_deps_varname()),
        build.assign(build.function('import', [build.string('fs')]), 'fs'),
        build.if_(build.method('is_dir', build.identifier('fs'), [build.string('meson')]),
                  build.block([build.function('subdir', [build.string('meson')])]))
    ]


def _create_lib(cargo: Manifest, build: builder.Builder, crate_type: manifest.CRATE_TYPE) -> T.List[mparser.BaseNode]:
    dependencies: T.List[mparser.BaseNode] = []
    dependency_map: T.Dict[mparser.BaseNode, mparser.BaseNode] = {}
    for name, dep in cargo.dependencies.items():
        dependencies.append(build.identifier(_dependency_varname(dep.package)))
        if name != dep.package:
            dependency_map[build.string(fixup_meson_varname(dep.package))] = build.string(name)

    rust_args: T.List[mparser.BaseNode] = [
        build.identifier('features_args'),
        build.identifier(_extra_args_varname())
    ]

    dependencies.append(build.identifier(_extra_deps_varname()))

    posargs: T.List[mparser.BaseNode] = [
        build.string(fixup_meson_varname(cargo.package.name)),
        build.string(cargo.lib.path),
    ]

    kwargs: T.Dict[str, mparser.BaseNode] = {
        'dependencies': build.array(dependencies),
        'rust_dependency_map': build.dict(dependency_map),
        'rust_args': build.array(rust_args),
    }

    lib: mparser.BaseNode
    if cargo.lib.proc_macro or crate_type == 'proc-macro':
        lib = build.method('proc_macro', build.identifier('rust'), posargs, kwargs)
    else:
        if crate_type in {'lib', 'rlib', 'staticlib'}:
            target_type = 'static_library'
        elif crate_type in {'dylib', 'cdylib'}:
            target_type = 'shared_library'
        else:
            raise MesonException(f'Unsupported crate type {crate_type}')
        if crate_type in {'staticlib', 'cdylib'}:
            kwargs['rust_abi'] = build.string('c')
        lib = build.function(target_type, posargs, kwargs)

    # features_args = []
    # foreach f, _ : features
    #   features_args += ['--cfg', 'feature="' + f + '"']
    # endforeach
    # lib = xxx_library()
    # dep = declare_dependency()
    # meson.override_dependency()
    return [
        build.assign(build.array([]), 'features_args'),
        build.foreach(['f', '_'], build.identifier('features'), build.block([
            build.plusassign(
                build.array([
                    build.string('--cfg'),
                    build.plus(build.string('feature="'), build.plus(build.identifier('f'), build.string('"'))),
                ]),
                'features_args')
            ])
        ),
        build.assign(lib, 'lib'),
        build.assign(
            build.function(
                'declare_dependency',
                kw={
                    'link_with': build.identifier('lib'),
                    'variables': build.dict({
                        build.string('features'): build.method('join', build.string(','), [build.method('keys', build.identifier('features'))]),
                    })
                },
            ),
            'dep'
        ),
        build.method(
            'override_dependency',
            build.identifier('meson'),
            [
                build.string(_dependency_name(cargo.package.name, _version_to_api(cargo.package.version))),
                build.identifier('dep'),
            ],
        ),
    ]


def interpret(subp_name: str, subdir: str, env: Environment) -> T.Tuple[mparser.CodeBlockNode, KeyedOptionDictType]:
    # subp_name should be in the form "foo-0.1-rs"
    package_name = subp_name.rsplit('-', 2)[0]
    manifests = _load_manifests(os.path.join(env.source_dir, subdir))
    cargo = manifests.get(package_name)
    if not cargo:
        raise MesonException(f'Cargo package {package_name!r} not found in {subdir}')

    filename = os.path.join(cargo.subdir, cargo.path, 'Cargo.toml')
    build = builder.Builder(filename)

    # Generate project options
    options: T.Dict[OptionKey, coredata.UserOption] = {}
    for feature in cargo.features:
        key = OptionKey(_option_name(feature), subproject=subp_name)
        enabled = feature == 'default'
        options[key] = coredata.UserBooleanOption(key.name, f'Cargo {feature} feature', enabled)

    ast = _create_project(cargo, build)
    ast += [build.assign(build.function('import', [build.string('rust')]), 'rust')]
    ast += _create_features(cargo, build)
    ast += _create_dependencies(cargo, build)
    ast += _create_meson_subdir(cargo, build)

    # Libs are always auto-discovered and there's no other way to handle them,
    # which is unfortunate for reproducability
    if os.path.exists(os.path.join(env.source_dir, cargo.subdir, cargo.path, cargo.lib.path)):
        for crate_type in cargo.lib.crate_type:
            ast.extend(_create_lib(cargo, build, crate_type))

    return build.block(ast), options
```