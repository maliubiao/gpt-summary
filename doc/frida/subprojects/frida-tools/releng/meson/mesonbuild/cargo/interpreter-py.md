Response:
Let's break down the thought process for analyzing this Python code.

**1. Initial Understanding and Core Purpose:**

The very first lines, especially the docstring, are crucial. It clearly states this script's purpose: "Interpreter for converting Cargo Toml definitions to Meson AST". This immediately tells us it's about translating between two build systems: Rust's Cargo and the Meson Build System. The limitations mentioned (not handling `build.rs`) are also important context.

**2. Identifying Key Data Structures and Concepts:**

Scanning through the code, I looked for classes and dataclasses. These often represent the core data models. I see `Package`, `Dependency`, `BuildTarget`, `Library`, `Binary`, `Test`, `Benchmark`, `Example`, and `Manifest`. These names strongly suggest they correspond to concepts in Cargo's `Cargo.toml` file. The `Manifest` class seems to be the central representation of a `Cargo.toml`.

**3. Tracing the Flow of Information:**

I started to mentally trace how the code might process a `Cargo.toml`. The `load_toml` function clearly reads the `Cargo.toml` file. The `_convert_manifest` function then takes the raw data and transforms it into the `Manifest` object. The `_load_manifests` function handles the possibility of workspaces (multiple packages in one directory).

**4. Connecting to Build System Concepts:**

Knowing the code is about build systems, I began connecting the identified classes and functions to common build system operations:

* **Dependencies:** The `Dependency` class and the `_create_dependencies` function are obviously about managing project dependencies.
* **Targets (Libraries, Binaries, etc.):** The various `*Target` classes represent buildable outputs. The `_create_lib` function clearly generates Meson code for building a library.
* **Features:** The `features` attribute in `Manifest` and the `_create_features` function point to Cargo's feature system for conditional compilation.
* **Project Definition:** The `_create_project` function handles the basic project setup in Meson.
* **Subdirectories:** The `_create_meson_subdir` function indicates a way to integrate custom Meson build logic.

**5. Identifying Potential "Hooks" for Frida/Reverse Engineering:**

Knowing this is part of Frida, a dynamic instrumentation tool, I looked for parts that might be relevant to interacting with or understanding running processes. While this specific file *deals with build configuration*, the fact that Frida *uses* this to understand Rust projects means this information could be used to:

* **Identify Libraries and Binaries:** Knowing the names and locations of libraries and binaries is crucial for attaching Frida to processes or injecting code.
* **Understand Dependencies:** Understanding a target's dependencies can help in analyzing its behavior or potential vulnerabilities.
* **Map Features to Code:** Knowing which features are enabled can help in understanding which parts of the code are active.

**6. Looking for Lower-Level Interactions:**

I searched for terms like "binary," "linux," "android," "kernel," or "framework." While this specific file doesn't *directly* interact with these, it *prepares the way* for Frida to interact with compiled Rust code that might run on these platforms. The `rust_abi='c'` in `_create_lib` for `staticlib` and `cdylib` is a subtle hint of interacting with lower-level C interfaces.

**7. Analyzing Logic and Potential Errors:**

I looked for conditional statements (`if`), loops (`foreach`, `while`), and error handling (`raise MesonException`). The feature processing logic in `_process_feature` and the dependency checking in `_create_dependencies` seemed complex and potential areas for errors. The checks for `tomllib` and `toml2json` indicate a fallback mechanism, suggesting potential user errors if neither is available.

**8. Considering the User's Perspective and Debugging:**

I imagined how a user might end up in this code. They would be trying to use Frida with a Rust project. If the Meson build process fails during the Cargo to Meson conversion, they might need to understand this code to debug the issue. The checks for missing `tomllib` or `toml2json`, or inconsistencies in feature configurations, provide potential debugging clues.

**9. Structuring the Output:**

Finally, I organized my findings into the requested categories: functionality, reverse engineering relevance, low-level details, logical reasoning, user errors, and debugging. I tried to provide concrete examples where possible to illustrate the points.

**Self-Correction/Refinement:**

Initially, I might have focused too much on the direct "dynamic instrumentation" aspect. I had to shift my focus to the *build system translation* aspect that this specific file handles. The connection to Frida is more indirect – this code *enables* Frida to work with Rust projects by understanding their build structure. I also refined my explanations to be more specific and less general. For instance, instead of just saying "handles dependencies," I explained *how* it handles dependencies and the potential issues it checks for.
这个Python源代码文件 `interpreter.py` 是 Frida 工具链中 `frida-tools` 子项目的一部分，负责将 Rust 项目的 Cargo.toml 配置文件转换为 Meson 构建系统的抽象语法树（AST）。 简而言之，它的主要功能是**解析 Rust 项目的依赖关系、构建目标和其他配置信息，并将其转化为 Meson 可以理解的格式，以便 Frida 可以构建和集成这些 Rust 组件。**

以下是更详细的功能列表，并根据你的要求进行了分类说明：

**主要功能:**

1. **解析 Cargo.toml 文件:**
   - 使用 `tomllib` (Python 3.11+) 或 `tomli` 库解析 Cargo.toml 文件，将其内容加载为 Python 字典。
   - 如果 `tomllib` 和 `tomli` 都不存在，则尝试使用外部程序 `toml2json` 将 TOML 转换为 JSON 进行解析。
   - 处理 Cargo.toml 文件的不同部分，如 `package`, `dependencies`, `dev-dependencies`, `build-dependencies`, `lib`, `bin`, `test`, `bench`, `example`, `features`, `target` 等。

2. **将 Cargo 数据结构映射到 Python 对象:**
   - 定义了一系列 Python dataclass (如 `Package`, `Dependency`, `Library`, `Binary`, `Manifest` 等) 来表示 Cargo.toml 中的概念。
   - 将解析后的 Cargo.toml 数据转换为这些 Python 对象，方便后续处理。

3. **处理 Cargo 工作区 (Workspace):**
   - 能够识别和解析 Cargo 工作区，处理包含多个 crate 的项目。
   - 根据 `workspace.members` 和 `workspace.exclude` 配置，找到所有相关的 Cargo.toml 文件并进行解析。

4. **转换 Cargo 依赖版本:**
   - 将 Cargo 依赖的版本字符串（例如 `"^1.0"`, `">= 1.2"`) 转换为 Meson 构建系统可以理解的格式。

5. **处理 Cargo Features:**
   - 解析 Cargo 的 feature 配置，理解 feature 之间的依赖关系。
   - 生成 Meson 构建选项，允许用户在构建时启用或禁用特定的 Cargo feature。
   - 在 Meson 构建过程中，根据启用的 feature 配置，设置 Rust 编译器的参数。

6. **生成 Meson 构建系统的 AST:**
   - 使用 `builder.py` 模块提供的工具，将解析后的 Cargo 配置信息转换为 Meson 构建脚本的抽象语法树（AST）。
   - 生成的 AST 包括 `project()` 定义，`dependency()` 声明，各种构建目标 (libraries, binaries, examples 等) 的定义，以及 feature 相关的条件逻辑。

7. **处理自定义的 Meson 构建逻辑:**
   - 允许 Cargo 子项目在 `meson/meson.build` 文件中定义额外的 Meson 构建逻辑，用于补充或替代 `build.rs` 的功能。

**与逆向方法的关系及举例说明:**

这个文件本身并不直接执行逆向操作，但它为 Frida 动态插桩 Rust 代码奠定了基础。通过理解 Rust 项目的构建结构和依赖关系，Frida 可以在运行时注入代码、hook 函数、修改内存等，从而实现对 Rust 程序的动态分析和逆向。

**举例说明:**

假设一个 Rust 程序 `target_app` 依赖于一个名为 `helper_lib` 的库。 `interpreter.py` 会解析 `target_app` 的 `Cargo.toml` 文件，识别出对 `helper_lib` 的依赖。然后，Frida 可以利用这些信息：

- **定位库文件:**  知道 `helper_lib` 的名称和版本，Frida 可以更容易地找到编译后的库文件 (`.so` 或 `.dll`)。
- **解析符号信息:**  理解库的构建方式有助于 Frida 加载和解析库的符号信息，从而可以按名称 hook 库中的函数。
- **理解内存布局:**  掌握库的依赖关系和链接方式，有助于 Frida 理解目标进程的内存布局，进行更精确的内存操作。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

虽然这个 Python 文件本身不直接操作二进制或内核，但它处理的 Rust 代码最终会编译成二进制文件，并在特定的操作系统 (包括 Linux 和 Android) 上运行。  `interpreter.py` 的工作间接涉及以下方面：

- **二进制文件类型:** 它需要识别不同类型的 Rust 构建目标 (`lib`, `bin`, `cdylib`, `staticlib` 等)，这些最终对应于不同的二进制文件类型（共享库、可执行文件、C 兼容的动态库等）。
- **ABI (Application Binary Interface):**  在生成 Meson 构建脚本时，它会考虑 Rust 的 ABI，例如 `rust_abi='c'` 用于生成可以与 C 代码互操作的库。这在跨语言调用和底层系统交互中至关重要。
- **操作系统特定的构建配置:**  虽然这个文件不直接处理操作系统细节，但它生成的 Meson 构建脚本会根据目标操作系统（Linux, Android 等）进行调整，例如链接器选项、库路径等。
- **Android Framework (间接):** 如果被插桩的 Rust 代码运行在 Android 上，并与 Android Framework 进行交互，那么理解这些 Rust 代码的构建方式有助于 Frida 在运行时与 Android Framework 进行交互。

**举例说明:**

- 当处理 `cdylib` 类型的库时，`interpreter.py` 生成的 Meson 构建脚本会包含 `rust_abi = 'c'` 这样的设置，这表明该库旨在通过 C FFI (Foreign Function Interface) 与其他语言或系统组件进行交互，这在底层编程中很常见。

**逻辑推理及假设输入与输出:**

`interpreter.py` 中存在一些逻辑推理，例如：

- **版本号处理:**  它会根据 Cargo 依赖的版本约束字符串 (`>=`, `==`, `=`) 推断出最低的 API 版本。
  - **假设输入:**  依赖的版本字符串为 `">= 1.2.3"`
  - **输出:**  推断出的 API 版本可能为 `1` (根据 `_version_to_api` 函数的逻辑)。
- **Feature 处理:** 它会递归地解析 feature 的依赖关系，确定启用某个 feature 后需要同时启用的其他 feature 和依赖项。
  - **假设输入:**  `Cargo.toml` 中定义了 feature `A` 依赖于 feature `B`，feature `B` 依赖于依赖项 `C`.
  - **输出:**  如果用户启用了 feature `A`，那么 `interpreter.py` 会生成相应的 Meson 构建配置，确保 feature `B` 和依赖项 `C` 也被处理。

**用户或编程常见的使用错误及举例说明:**

- **缺少必要的依赖工具:** 如果用户的系统中没有安装 `tomllib` (对于 Python < 3.11) 或 `tomli`，也没有安装 `toml2json`，`interpreter.py` 会抛出 `MesonException`。
  - **错误信息:**  `Could not find an implementation of tomllib, nor toml2json`
  - **用户操作:**  用户需要安装 `tomli` 或确保系统中存在 `toml2json` 可执行文件。
- **Cargo.toml 文件格式错误:** 如果 Cargo.toml 文件不是一个有效的 TOML 字典，解析过程会失败。
  - **错误信息:**  `Cargo.toml isn't a dictionary? How did that happen?`
  - **用户操作:**  用户需要检查并修复 Cargo.toml 文件中的语法错误。
- **Feature 配置冲突:** 如果 Cargo 项目的 feature 配置存在循环依赖或其他不一致的情况，`interpreter.py` 的 feature 处理逻辑可能会遇到问题，但代码中似乎有避免无限循环的机制。
- **依赖项 API 版本不匹配:** 如果依赖项的版本约束导致无法确定唯一的最低 API 版本，会抛出异常。
  - **错误信息:**  `Cannot determine minimum API version from ...`
  - **用户操作:**  用户需要修改依赖项的版本约束，使其更明确。
- **Meson 构建配置不一致:**  如果之前使用不同的 feature 配置构建过依赖项，并且当前构建需要的 feature 没有被启用，`interpreter.py` 会检测到并报错。
  - **错误信息:**  `Dependency ... previously configured with features ... but need ...`
  - **用户操作:**  用户需要在 Meson 构建时显式地启用所需的 feature，或者在主项目的 `project()` 定义中设置 `default_options`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

通常，用户不会直接调用或运行 `interpreter.py`。 它是 Frida 工具链内部运作的一部分。用户操作的路径可能是这样的：

1. **用户尝试使用 Frida 对一个 Rust 编写的目标程序进行插桩。**  这可能涉及到使用 Frida 的命令行工具 (如 `frida`) 或 Python API。
2. **Frida 需要理解目标程序的构建结构和依赖关系。**  如果目标程序是一个 Rust 项目，Frida 会尝试找到并解析目标程序及其依赖项的 `Cargo.toml` 文件。
3. **Frida 的构建系统（可能是 Meson）需要配置目标 Rust 项目。**  为了将 Rust 代码集成到 Frida 的构建流程中，需要将 Cargo 的配置转换为 Meson 的配置。
4. **`interpreter.py` 被调用。**  当 Frida 的构建系统处理一个 Rust 子项目时，会调用 `interpreter.py` 来解析该子项目的 `Cargo.toml` 文件并生成相应的 Meson 构建脚本。
5. **如果解析或转换过程中发生错误，用户可能会看到相关的错误信息。**  这些错误信息可能指向 `interpreter.py` 中抛出的异常，例如无法找到 `tomllib` 或 `toml2json`，或者 `Cargo.toml` 文件格式错误。

**作为调试线索:**

- 如果用户在使用 Frida 时遇到与 Rust 项目相关的构建错误，可以查看错误信息是否指向 `interpreter.py` 中抛出的异常。
- 如果错误信息提到无法找到 `tomllib` 或 `toml2json`，则说明用户的环境中缺少这些依赖项。
- 如果错误信息提到 `Cargo.toml` 文件解析错误，则需要检查该文件的语法。
- 如果错误信息与 feature 配置有关，则需要检查 Cargo.toml 文件中的 feature 定义以及在 Meson 构建时启用的 feature。
- 理解 `interpreter.py` 的功能和它处理的 Cargo.toml 内容，可以帮助用户更好地理解 Frida 是如何理解 Rust 项目的，从而更有效地调试插桩过程中的问题。

总而言之，`interpreter.py` 是 Frida 工具链中一个关键的桥梁，它将 Rust 生态的构建配置信息转换到 Frida 的构建系统中，使得 Frida 能够更好地与 Rust 代码进行交互和插桩。

### 提示词
```
这是目录为frida/subprojects/frida-tools/releng/meson/mesonbuild/cargo/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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