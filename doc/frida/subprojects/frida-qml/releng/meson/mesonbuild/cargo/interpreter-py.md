Response:
Let's break down the thought process for analyzing this Python code and fulfilling the user's request.

1. **Understanding the Core Request:** The user wants a comprehensive analysis of a Python file (`interpreter.py`) from the Frida project. The analysis should cover functionality, relationship to reverse engineering, low-level details, logical reasoning, common errors, and debugging information.

2. **Initial Skim and Identification of Key Areas:** A quick read reveals keywords like "Cargo," "Toml," "Meson," "Rust," "dependencies," "features," and "build." This immediately suggests the script is involved in converting Rust project definitions (Cargo.toml) into Meson build system instructions. The presence of "frida" in the file path hints at its role within the Frida ecosystem.

3. **Functional Breakdown (Instruction 1):**
    * **Core Function:** The primary goal is to interpret `Cargo.toml` files and generate Meson build definitions. This involves parsing the TOML, understanding Cargo concepts (packages, dependencies, features, targets), and translating them into Meson's syntax.
    * **Handling Build Scripts:** Acknowledging the limitation of not handling `build.rs` is crucial.
    * **Dependency Management:**  The code deals with different types of dependencies (normal, dev, build) and their version constraints.
    * **Feature Management:** A significant portion focuses on processing and enabling/disabling Cargo features.
    * **Target Handling:**  It identifies and configures different build targets like libraries, binaries, examples, tests, and benchmarks.
    * **Subproject Support:** The code handles multi-crate Rust projects (workspaces).
    * **Extensibility:** The mechanism for incorporating extra arguments and dependencies from a `meson/meson.build` file hints at an extensibility point.

4. **Reverse Engineering Relationship (Instruction 2):**
    * **Dynamic Instrumentation:** The context of "frida" is key here. Frida is a dynamic instrumentation toolkit. This script likely facilitates building and integrating Rust components within Frida.
    * **Example:**  A concrete example is needed. Imagine a Frida gadget (a library injected into a process). This gadget might be written in Rust, and this script would be used to build that gadget using the Rust toolchain and integrate it into Frida's build process.

5. **Low-Level/Kernel/Framework Knowledge (Instruction 3):**
    * **Binary Artifacts:** Building Rust code inherently produces binary artifacts (libraries, executables).
    * **Linking:** The concept of linking Rust libraries into larger systems (like Frida) is relevant.
    * **Operating System APIs:**  While not explicitly in this *script*, the *output* of the build process (facilitated by this script) would interact with OS APIs. Mentioning this connection is important.
    * **Kernel/Framework Modules:**  Again, while not directly in the script's *logic*, the *purpose* of the built artifacts within Frida relates to interacting with or extending the behavior of applications running on operating systems (potentially involving kernel-level interactions).

6. **Logical Reasoning (Instruction 4):**
    * **Feature Enablement:** The logic for processing features is a prime candidate for illustrating logical reasoning.
    * **Input:**  A `Cargo.toml` with features and dependencies. Example: `features = { "foo" = ["dep:bar", "baz"], "baz" = [] }`, `dependencies = { "bar" = "1.0" }`.
    * **Output:** How the script would determine which features and dependencies are enabled when a specific feature (e.g., "foo") is activated. This involves tracing the recursive nature of feature dependencies.

7. **Common Usage Errors (Instruction 5):**
    * **Missing `toml2json`:** The fallback mechanism highlights a potential error if neither `tomllib` nor `toml2json` is available.
    * **Conflicting Features:** The error handling for previously configured dependencies with different feature sets is a significant point. It demonstrates a scenario where the user might encounter build failures due to inconsistent feature requirements.
    * **Incorrect `Cargo.toml`:**  Basic errors like invalid TOML syntax are always possible.

8. **User Operation/Debugging (Instruction 6):**
    * **Starting Point:**  The user is typically working within the Frida project's source tree.
    * **Subproject Configuration:** The integration with Meson points to the user running Meson to configure the build.
    * **Meson Invocation:** The `meson` command is the entry point.
    * **Subproject Discovery:** Meson would discover the `frida-qml` subproject.
    * **Interpreter Execution:** Meson would invoke this `interpreter.py` script to process the `Cargo.toml` in the subproject.
    * **Debugging Points:**  Points where the user might need to debug include: availability of TOML parsers, correctness of `Cargo.toml`, feature activation, and dependency resolution.

9. **Structuring the Output:** Organize the information clearly using headings and bullet points to make it easy to read and understand. Provide code examples where relevant.

10. **Review and Refine:**  Read through the generated analysis to ensure accuracy, completeness, and clarity. Check if all aspects of the user's request have been addressed. For instance, ensure the examples are concrete and illustrative.
This Python script, located at `frida/subprojects/frida-qml/releng/meson/mesonbuild/cargo/interpreter.py`, is a crucial part of the Frida project's build system. Its primary function is to **interpret `Cargo.toml` files** (the manifest format for Rust projects) and **translate them into Meson Abstract Syntax Trees (AST)**. Meson is a build system generator that Frida uses. This script allows Frida to incorporate and build Rust-based components within its overall build process.

Here's a breakdown of its functionalities with examples related to reverse engineering, low-level concepts, logical reasoning, common errors, and debugging:

**Functionalities:**

1. **Parsing `Cargo.toml`:**
   - The script reads and parses `Cargo.toml` files using either the built-in `tomllib` (Python 3.11+) or the external `tomli` library. It also has a fallback mechanism using the `toml2json` command-line tool if neither of those is available.
   - It extracts information about the Rust package, its dependencies, build targets (libraries, binaries, examples, tests, benchmarks), features, and other metadata.

2. **Mapping Cargo Concepts to Meson:**
   - It maps Cargo's package definitions, dependencies, and build targets to corresponding Meson concepts. For example, a Cargo library (`[lib]`) is translated into a Meson `static_library` or `shared_library` call.
   - It handles the conversion of Cargo's version specifications to formats understood by Meson.
   - It manages Cargo features, allowing users to enable or disable them during the Meson configuration.

3. **Generating Meson AST:**
   - The script uses a `builder.py` module (also within the same directory) to construct the Meson AST. This AST represents the build instructions for Meson to generate the final build system (like Ninja).
   - It generates Meson function calls like `project()`, `dependency()`, `static_library()`, `shared_library()`, and `override_dependency()`.

4. **Handling Dependencies:**
   - It parses dependency information from `Cargo.toml`, including version requirements, optional dependencies, and feature requirements for dependencies.
   - It translates these into Meson `dependency()` calls.
   - It includes logic to verify that the features requested for dependencies are actually enabled in the previously configured dependency.

5. **Managing Features:**
   - It extracts feature definitions from `Cargo.toml` and creates Meson options (using `get_option()`).
   - It uses conditional logic (`if get_option(...)`) in the generated Meson code to enable or disable specific code paths or dependencies based on the selected features.

6. **Supporting Cargo Workspaces:**
   - It can handle Rust projects organized as workspaces, where multiple related crates reside in subdirectories. It iterates through the workspace members and processes their individual `Cargo.toml` files.

7. **Providing Extensibility:**
   - It looks for a `meson` subdirectory within the Cargo project. If found, it executes `subdir('meson')`, allowing the Cargo project to provide custom Meson build logic beyond what this script automatically generates. This is a way to handle cases where a `build.rs` file exists (which this script doesn't directly interpret).

**Relationship to Reverse Engineering:**

This script directly relates to reverse engineering when Frida is used to instrument and analyze applications that might contain Rust components. Here's how:

* **Building Frida Gadgets/Agents in Rust:** Developers often write Frida gadgets or agents (small pieces of code injected into target processes) using Rust for its performance and safety features. This script is essential for building these Rust components as part of the larger Frida build.
    * **Example:** Imagine a Frida gadget written in Rust that hooks a specific function in an Android application's native library. The `Cargo.toml` for this gadget would be processed by this script to generate the necessary Meson build instructions to compile the Rust code into a shared library that Frida can load.
* **Analyzing Applications with Embedded Rust:** When reverse engineering an application, you might encounter parts written in Rust. To understand and potentially modify or interact with this Rust code using Frida, you need to be able to build it in a compatible way. This script facilitates that process.
    * **Example:** If a mobile game's anti-tampering mechanisms are implemented in Rust and integrated via a library, this script would be involved in building that Rust library if you were trying to build a custom Frida build that includes specific interactions with that anti-tampering code.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

While the Python script itself is high-level, the *outcome* of its execution and the context in which it operates heavily involve low-level and platform-specific knowledge:

* **Binary Artifacts:** The script's purpose is to generate instructions to build binary artifacts (e.g., shared libraries `.so` on Linux/Android, `.dylib` on macOS, `.dll` on Windows) from Rust source code. These binaries are the fundamental units of execution on these platforms.
* **Linking:** The script manages dependencies between Rust crates. This translates to linking these compiled crates together into a final executable or library. Understanding linking concepts (static vs. dynamic linking) is crucial for debugging build issues.
* **Operating System APIs:** When Frida instruments a process, it interacts with the underlying operating system's APIs (e.g., `ptrace` on Linux, system calls on Android). The Rust code built using this script might also directly or indirectly interact with these APIs.
* **Linux/Android Shared Libraries:** Frida often injects shared libraries into processes. The Rust code built through this script is frequently compiled into shared libraries that Frida can load and execute within the target process's address space.
* **Android Framework:** Frida on Android can interact with the Android framework (e.g., ART runtime, system services). Rust components built using this script might be designed to hook into or interact with these framework components.
    * **Example:** A Frida agent written in Rust might use low-level techniques to hook into the Android Runtime (ART) to intercept calls to specific Java methods. The compilation of this Rust agent relies on this script.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider a simplified `Cargo.toml`:

```toml
# frida/subprojects/my-rust-gadget/Cargo.toml
[package]
name = "my-rust-gadget"
version = "0.1.0"
edition = "2021"

[dependencies]
log = "0.4"

[features]
default = ["enable_logging"]
enable_logging = ["log/std"]
```

**Hypothetical Input to the Script:**

* The path to the `Cargo.toml` file: `frida/subprojects/my-rust-gadget/Cargo.toml`
* The subdirectory: `frida/subprojects/my-rust-gadget`

**Hypothetical Output (Snippet of Generated Meson AST):**

```python
# ... (other Meson code) ...
rust = import('rust')
features = {}
if get_option('feature-enable_logging'):
  features += {'enable_logging': true}
  features += {'default': true}
required_deps = {}
my_rust_gadget_options = {'feature-default': true}
log_dep = dependency('log-0-rs', version : ['>= 0.4'], default_options : my_rust_gadget_options)
lib = rust.static_library('my_rust_gadget', 'src/lib.rs', dependencies : [log_dep], rust_args : features_args)
meson.override_dependency('my-rust-gadget-0-rs', declare_dependency(link_with : lib))
# ... (rest of the Meson code) ...
```

**Explanation of the Logic:**

* The script identifies the package name and version.
* It creates a Meson option `feature-enable_logging` based on the `features` section in `Cargo.toml`.
* It uses an `if` statement to conditionally enable the `enable_logging` feature based on the Meson option's value.
* It declares a dependency on the `log` crate.
* It generates a `rust.static_library()` call to build the Rust library.
* It uses `meson.override_dependency()` to make the built Rust library available as a Meson dependency.

**Common User/Programming Errors and Examples:**

1. **Missing `toml` Parsing Libraries:**
   - **Error:** If neither `tomllib` nor `tomli` is installed, and `toml2json` is not in the system's PATH, the script will raise a `MesonException('Could not find an implementation of tomllib, nor toml2json')`.
   - **User Action:** The user needs to install one of the TOML parsing libraries (e.g., `pip install tomli`) or ensure `toml2json` is available.

2. **Incorrect `Cargo.toml` Syntax:**
   - **Error:** If the `Cargo.toml` file has invalid TOML syntax, the parsing step will fail, leading to a `tomllib.TOMLDecodeError` (or similar error from `tomli` or `toml2json`).
   - **User Action:** The user needs to carefully review the `Cargo.toml` file for syntax errors (e.g., missing quotes, incorrect indentation).

3. **Feature Conflicts or Missing Dependencies:**
   - **Error:** If a Cargo feature depends on another crate that isn't listed as a dependency, or if there are circular feature dependencies, the Rust build process (invoked by Meson) will likely fail.
   - **User Action:** The user needs to ensure all dependencies are correctly declared in `Cargo.toml` and resolve any feature conflicts.

4. **Version Mismatches:**
   - **Error:** If the version constraints specified in `Cargo.toml` for dependencies are incompatible with the versions available in the Rust registry (crates.io) or local sources, the build will fail.
   - **User Action:** The user needs to adjust the version requirements in `Cargo.toml` or ensure the correct versions of dependencies are available.

5. **Issues with `build.rs` (Not Directly Handled):**
   - **Limitation:** This script explicitly states it doesn't handle `build.rs` files. If a Cargo package relies on a `build.rs` script for code generation or custom build logic, this script won't automatically translate that.
   - **User Action:** The user would need to either port the logic from `build.rs` to a Meson build script within the `meson` subdirectory or find an alternative way to achieve the same build steps within the Meson framework.

**User Operations Leading to This Script's Execution (Debugging Clues):**

1. **Cloning the Frida Repository:** A developer working with Frida would typically start by cloning the Frida GitHub repository.

2. **Navigating to the Frida QML Subproject:** If the developer is working on or with the Frida QML interface, they would navigate to the `frida/subprojects/frida-qml` directory.

3. **Configuring the Build with Meson:** The user would then run the Meson configuration command from the root of the Frida repository (or a designated build directory):
   ```bash
   meson setup build
   ```
   or potentially target a specific subproject:
   ```bash
   meson setup build frida/subprojects/frida-qml
   ```

4. **Meson Discovering the `cargo.py` Interpreter:** Meson will analyze the `meson.build` file within the `frida-qml` subproject (or its parent directories). This `meson.build` file will likely contain a call to a custom Meson function or module that utilizes this `interpreter.py` script to process the `Cargo.toml` file in that subproject.

5. **`interpreter.py` Processing `Cargo.toml`:** When Meson encounters the instruction to process the Rust project, it will invoke this `interpreter.py` script, passing the path to the `Cargo.toml` file and other relevant context.

6. **Debugging Points:**
   - **Check if Meson is correctly installed and configured.**
   - **Verify the `meson.build` file in the Frida QML subproject correctly calls the Rust integration logic.**
   - **Inspect the output of the `meson setup` command for any errors related to parsing `Cargo.toml` or resolving dependencies.**
   - **Manually run the `interpreter.py` script with a sample `Cargo.toml` (though this requires setting up the correct environment and dependencies).**
   - **Use Meson's introspection capabilities to examine the generated build system and understand how the Rust components are being integrated.**

In summary, this script acts as a bridge between the Rust ecosystem (via `Cargo.toml`) and the Meson build system used by Frida. It's crucial for integrating Rust-based components into Frida and plays a significant role in enabling dynamic instrumentation and reverse engineering of applications that incorporate Rust code.

Prompt: 
```
这是目录为frida/subprojects/frida-qml/releng/meson/mesonbuild/cargo/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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