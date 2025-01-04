Response:
Let's break down the thought process for analyzing this Python code and fulfilling the request.

**1. Initial Understanding of the Code's Purpose:**

The docstring at the beginning is key:  "Interpreter for converting Cargo Toml definitions to Meson AST."  This immediately tells us the code's core function: taking a `Cargo.toml` file (Rust's build manifest) and generating a Meson build definition. Meson is another build system, often used in cross-platform projects.

**2. Identifying Key Data Structures and Classes:**

I scan the code for `dataclass`. These define the core data models representing the different parts of a `Cargo.toml` file: `Package`, `Dependency`, `BuildTarget`, `Library`, `Binary`, `Test`, `Benchmark`, `Example`, and `Manifest`. Understanding these structures is crucial to understanding how the code interprets the `Cargo.toml`.

**3. Tracing the Conversion Process:**

I look for the main function that orchestrates the conversion. The `interpret` function stands out. It takes the subproject name, subdirectory, and the Meson environment as input. It loads the `Cargo.toml` using `_load_manifests`, then uses a `builder.Builder` (which likely generates Meson AST nodes) to create the Meson representation.

**4. Pinpointing Core Functionalities:**

I go through the functions called within `interpret` and other significant functions:

* `load_toml`: Handles parsing the `Cargo.toml` file. It cleverly tries `tomllib` (Python 3.11+) and falls back to `tomli` or even an external `toml2json` tool. This reveals potential dependencies and flexibility.
* `_convert_manifest`: Transforms the raw TOML data into the structured `Manifest` dataclass.
* `_create_project`, `_create_features`, `_create_dependencies`, `_create_meson_subdir`, `_create_lib`:  These functions are responsible for generating specific parts of the Meson build definition based on the `Manifest` data. The names are quite descriptive.

**5. Connecting to Reverse Engineering:**

I consider how this code relates to reverse engineering. The key link is *dynamic instrumentation*. Frida, the tool this code belongs to, is a dynamic instrumentation framework. By interpreting `Cargo.toml`, this code allows Frida to *build and integrate* Rust code into its instrumentation capabilities. Examples of reverse engineering connections emerge:

* **Hooking Rust Code:** Frida can hook into functions in Rust libraries built using this interpreter.
* **Analyzing Rust Binaries:**  The ability to build Rust binaries within Frida's context means those binaries can be analyzed using other Frida features.
* **Understanding Rust Dependencies:**  Knowing how this code handles dependencies is relevant for understanding the architecture of Rust-based targets.

**6. Identifying Binary/Kernel/Framework Connections:**

I look for clues about low-level interactions. The `rust` import suggests interaction with the Rust toolchain. The mention of "crate types" (`lib`, `rlib`, `dylib`, etc.) points to the different ways Rust code can be compiled and linked, which is a binary-level concern. The handling of dependencies and linking is also a core concept in binary executable generation. While the *code itself* doesn't directly manipulate kernel internals, the *purpose* within Frida strongly suggests its output is used for interacting with running processes, which often involves kernel-level mechanisms (especially on Android).

**7. Looking for Logic and Assumptions:**

I examine the conditional logic (`if` statements, loops) to understand the code's decision-making. The handling of features and optional dependencies shows logical processing. The version conversion logic (`version.convert`) and API version extraction (`_version_to_api`) indicate assumptions about semantic versioning.

**8. Spotting Potential User Errors:**

I think about how a user might incorrectly set up a `Cargo.toml` file or the build environment:

* **Missing `Cargo.toml`:** The code expects a `Cargo.toml` file.
* **Invalid `Cargo.toml` Syntax:** The TOML parsing might fail.
* **Inconsistent Feature Requirements:** The code explicitly checks for feature consistency between the current project and its dependencies, highlighting a potential user error.
* **Missing Dependencies:** If the dependencies specified in `Cargo.toml` aren't available, the build will fail.

**9. Tracing the User's Path (Debugging Clues):**

I imagine how a developer using Frida might end up with this code being executed:

1. **Setting up a Frida project:** The user would likely have a directory structure where they're integrating Rust code with Frida.
2. **Having a `Cargo.toml`:** The Rust code would have its build manifest.
3. **Frida's build system encounters the Rust subproject:**  Frida's build process (likely using Meson) would identify the need to process the Rust code.
4. **This `interpreter.py` is invoked:**  Meson would call this script to translate the `Cargo.toml` into Meson build instructions.

This step-by-step thinking helps connect the code to the larger context of Frida's usage.

**10. Refining and Structuring the Answer:**

Finally, I organize the findings into the requested categories, providing specific code snippets and explanations to support each point. I ensure the language is clear and avoids jargon where possible, while still being technically accurate. I prioritize the most significant functionalities and connections to reverse engineering and low-level concepts.
This Python script, `interpreter.py`, is part of Frida's build system, specifically for handling Rust subprojects that use Cargo as their build manager. Its primary function is to **translate the information from a `Cargo.toml` file (Rust's package manifest) into a format that Meson, Frida's primary build system, can understand and use.**  This allows Frida to incorporate Rust code into its dynamic instrumentation capabilities.

Let's break down its functionalities based on your request:

**1. Core Functionality: Converting Cargo Definitions to Meson AST**

* **Parsing `Cargo.toml`:** The script's central task is to read and parse the `Cargo.toml` file. It handles the standard TOML format using libraries like `tomllib` (Python 3.11+) or `tomli`. It also has a fallback mechanism to use an external `toml2json` tool if the Python libraries are unavailable.
* **Data Modeling:** It defines Python dataclasses (like `Package`, `Dependency`, `Library`, `Binary`, `Manifest`) that represent the various sections and elements within a `Cargo.toml` file. This provides a structured way to work with the parsed data.
* **Generating Meson Abstract Syntax Tree (AST):** The script uses a `builder.Builder` (from the same directory) to create Meson AST nodes. These nodes represent the build instructions for Meson. This involves generating Meson functions like `project()`, `dependency()`, `static_library()`, `shared_library()`, `proc_macro()`, and managing dependencies and features.
* **Handling Workspaces:** It supports Cargo workspaces, which allow multiple Rust packages within a single repository. It iterates through the workspace members and processes their individual `Cargo.toml` files.
* **Feature Management:** It parses the `[features]` section of `Cargo.toml` and translates them into Meson options. This allows users to enable or disable specific features during the Frida build process.
* **Dependency Management:** It extracts dependency information (including versions, optional dependencies, and feature requirements) and creates corresponding Meson dependency objects.

**2. Relationship with Reverse Engineering**

This script is directly related to reverse engineering because it enables the integration of Rust code into Frida, a powerful dynamic instrumentation tool used extensively in reverse engineering.

* **Example:** Imagine you are reverse-engineering a mobile application that includes some core logic implemented in Rust. By having the ability to build and incorporate this Rust code using Frida (enabled by this script), you can:
    * **Hook functions within the Rust libraries:** Frida can inject code to intercept and modify the behavior of Rust functions within the target application.
    * **Inspect memory and data structures used by the Rust code:** Frida allows you to read and manipulate memory regions used by the Rust components of the application.
    * **Trace execution flow through the Rust code:** Frida can help you understand how the Rust code is being executed.
    * **Fuzz test the Rust components:** You could use Frida to feed various inputs to the Rust code and observe its behavior for vulnerabilities.

**3. Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge**

While the Python script itself doesn't directly interact with the binary bottom or kernel, its *purpose* and the tool it belongs to (Frida) are heavily reliant on this knowledge.

* **Binary Bottom:** The script generates build instructions for Rust code, which ultimately results in compiled binaries (libraries, executables). Understanding different Rust crate types (like `lib`, `rlib`, `dylib`, `cdylib`, `proc-macro`) and their binary representations is crucial for the correct generation of Meson build rules. The script handles different library types (`static_library`, `shared_library`) based on the Cargo crate type.
* **Linux and Android Kernel/Framework:** Frida, at its core, operates by injecting code into running processes. This involves understanding process memory management, inter-process communication (IPC), and system calls, which are fundamental concepts in operating system kernels (like Linux and the Android kernel). When Frida instruments Rust code built using this script, it operates within the context of these kernel-level mechanisms.
* **Android Framework:** If the Rust code is part of an Android application, understanding the Android framework (e.g., ART runtime, Binder IPC) becomes relevant when using Frida to instrument it. This script ensures that the Rust components can be built and integrated into the Android environment for Frida's use.

**4. Logical Reasoning: Assumptions, Inputs, and Outputs**

* **Assumption:** The script assumes the existence of a valid `Cargo.toml` file in the specified subdirectory. It also assumes the availability of a Rust toolchain in the environment where the build is performed.
* **Input:** The primary input is the path to the subdirectory containing the `Cargo.toml` file.
* **Output:** The script's output is a list of Meson AST nodes. This AST represents the build instructions for the Rust subproject, telling Meson how to compile and link the Rust code, handle dependencies, and integrate it into the larger Frida build.

**Example of Input and Output:**

**Hypothetical Input (`Cargo.toml`):**

```toml
[package]
name = "my-rust-lib"
version = "0.1.0"

[dependencies]
libc = "0.2"
```

**Logical Reasoning within the Script (simplified):**

1. The script parses the `[package]` section and extracts the name "my-rust-lib" and version "0.1.0".
2. It parses the `[dependencies]` section and finds a dependency on the "libc" crate with version "0.2".
3. It uses the `builder.Builder` to create Meson AST nodes:
    * A `project()` call with the name and language.
    * A `dependency()` call for the "libc" crate, potentially looking up a pre-existing Meson dependency definition for "libc".
    * A `static_library()` or `shared_library()` call to build the "my-rust-lib" crate, linking against the "libc" dependency.

**Hypothetical Output (simplified Meson AST representation):**

```python
[
    FunctionCallNode(
        'project',
        [StringNode('my-rust-lib'), StringNode('rust')],
        {'version': StringNode('0.1.0')}
    ),
    AssignNode(
        IdentifierNode('libc_dep'),
        FunctionCallNode('dependency', [StringNode('libc')], {'version': StringNode('>=0.2')})
    ),
    AssignNode(
        IdentifierNode('lib'),
        FunctionCallNode(
            'static_library',
            [StringNode('my_rust_lib'), StringNode('src/lib.rs')],
            {'dependencies': ArrayNode([IdentifierNode('libc_dep')])}
        )
    )
]
```

**5. Common User or Programming Errors**

* **Invalid `Cargo.toml` Syntax:** If the `Cargo.toml` file has syntax errors, the TOML parsing will fail, leading to a `MesonException`.
    * **Example:** Forgetting a closing quote for a string or using an invalid key name.
* **Missing Dependencies:** If the `Cargo.toml` specifies dependencies that are not available (e.g., not in the crates.io registry and no other source is specified), the Rust build process initiated by Meson will fail.
    * **Example:** A typo in the dependency name or forgetting to add a required dependency.
* **Feature Mismatches:** The script explicitly checks for consistency in enabled features between the current project and its dependencies. If a dependency requires a feature that is not enabled in the current project (or vice-versa), it will raise an error.
    * **Example:**  A dependency might have a feature "secure-hashing" enabled, but the main project's build configuration doesn't enable this feature for that dependency.
* **Incorrectly Specified Paths:** If the `path` for a library or binary in `Cargo.toml` is incorrect, the build will fail because the source files cannot be found.
* **Attempting to Use `build.rs`:** The script explicitly states that it doesn't handle `build.rs` files. If a Cargo project relies on a `build.rs` for custom build logic, a manual Meson port will be required. This is a common misunderstanding for users expecting automatic conversion of complex Cargo setups.

**6. User Operations Leading to This Script (Debugging Clues)**

A user would typically arrive at this script indirectly as part of the Frida build process. Here's a possible sequence of events:

1. **Setting up a Frida development environment:** The user would be working on the Frida codebase or a project that extends Frida's functionality.
2. **Introducing a Rust subproject:** The user decides to incorporate some Rust code into Frida or their Frida extension. This involves creating a directory with a `Cargo.toml` file defining the Rust project.
3. **Running the Frida build system (Meson):** The user executes Meson commands (e.g., `meson setup _build`, `ninja -C _build`) to configure and build Frida.
4. **Meson encounters the Rust subproject:** During the Meson configuration phase, it detects the presence of the `Cargo.toml` file in the designated subdirectory.
5. **Meson invokes `interpreter.py`:** Meson calls this `interpreter.py` script, passing the subdirectory path as an argument. This is done to translate the `Cargo.toml` into Meson-understandable build instructions.
6. **The script processes `Cargo.toml`:** The `interpreter.py` script parses the `Cargo.toml` and generates the Meson AST.
7. **Meson uses the generated AST:** Meson incorporates the generated AST into its overall build graph, knowing how to build the Rust components.
8. **Rust code is compiled:** During the build phase, Meson executes the necessary `rustc` commands to compile the Rust code according to the generated build rules.

**Debugging Clue:** If a user encounters errors related to building Rust subprojects within Frida, examining the Meson log output will often reveal if `interpreter.py` was involved and if any errors occurred during its execution (e.g., TOML parsing errors, feature mismatches). Looking at the generated Meson files in the build directory can also provide insights into how the `Cargo.toml` was translated.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/cargo/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
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

"""

```