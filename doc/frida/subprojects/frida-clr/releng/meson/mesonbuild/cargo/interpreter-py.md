Response:
Let's break down the thought process for analyzing this Python code for Frida.

**1. Understanding the Goal:** The primary goal is to analyze a specific Python file within the Frida project, identify its functionalities, and connect them to relevant technical domains like reverse engineering, low-level operations, and potential user errors.

**2. Initial Reading and High-Level Understanding:**

* **File Path:** `frida/subprojects/frida-clr/releng/meson/mesonbuild/cargo/interpreter.py`  This immediately suggests the file is involved in integrating Rust (Cargo) projects into the Frida build system, which uses Meson. The "clr" part hints at some interaction with the .NET Common Language Runtime, but the core of *this* file seems to be about general Cargo handling.
* **Comments:** The initial comments are crucial:
    * "Interpreter for converting Cargo Toml definitions to Meson AST": This is the core function. It takes Cargo's `Cargo.toml` and turns it into Meson instructions.
    * The note about `build.rs` being ignored is important. It sets a boundary for the file's capabilities.
* **Imports:** The imports give clues about the dependencies and functionalities used:
    * `dataclasses`:  Indicates the use of data classes for structured data.
    * `glob`, `os`, `shutil`: Standard file system operations.
    * `importlib`: Dynamic module loading (used for `tomllib`).
    * `itertools`, `collections`, `typing`: Utility and type hinting.
    * `.`:  Imports from within the same directory (`builder`, `version`).
    * `..mesonlib`: Imports from Meson-specific libraries.
    * `..`: Imports from parent directories (`manifest`, `mparser`, `environment`, `coredata`).
* **Key Structures:**  Scanning for classes and functions provides a skeleton of the file's organization. `Package`, `Dependency`, `BuildTarget`, `Library`, `Binary`, `Manifest`, `_convert_manifest`, `_load_manifests`, `_create_project`, etc. are key building blocks.

**3. Detailed Analysis - Function by Function (Iterative Process):**

For each function/class, ask:

* **What does it do?**  Read the docstrings and code carefully.
* **What are its inputs and outputs?** Identify parameters and return types.
* **How does it relate to Cargo?**  Does it handle `Cargo.toml` elements?
* **How does it relate to Meson?** Does it generate Meson AST nodes?
* **Are there any connections to reverse engineering, low-level, kernels, etc.?**  This requires drawing inferences. For example, handling dependency versions could be relevant to ensuring compatibility in a reverse engineering context.
* **Are there any potential user errors?** Look for assumptions, error handling, or places where user input could be wrong.
* **How might a user reach this code?**  Think about the build process.

**Example of Detailed Analysis for `load_toml`:**

* **What it does:** Loads a `Cargo.toml` file.
* **Inputs:** `filename` (string).
* **Outputs:** A dictionary.
* **Cargo Relation:** Directly parses `Cargo.toml`.
* **Meson Relation:**  The output is used to create the Meson representation.
* **Reverse Engineering:** Indirectly relevant because `Cargo.toml` describes the build of a target that *could* be reverse engineered.
* **Low-Level:** Deals with file I/O, which is relatively low-level. The fallback to `toml2json` if `tomllib` isn't available is a practical consideration.
* **User Error:** If the `Cargo.toml` is malformed, it will raise a `MesonException`. Also, if neither `tomllib` nor `toml2json` is available, the build will fail.
* **User Path:**  When Meson processes a Frida build and encounters a Cargo subproject, it will call this function to read the `Cargo.toml`.

**4. Connecting to Key Concepts:**

* **Reverse Engineering:**  Consider *why* Frida needs to understand Cargo. It's because Frida often instruments software built with Rust. Understanding dependencies, build targets, and features is essential for correctly setting up the instrumentation environment.
* **Binary/Low-Level:** The code doesn't directly manipulate binaries in this file, but it's part of a toolchain that ultimately produces binaries. The handling of different crate types (`lib`, `bin`, `cdylib`, etc.) touches upon binary output formats.
* **Linux/Android Kernel/Framework:**  While this specific file isn't deeply involved with kernel specifics, the broader Frida context is. Rust is used for system-level programming, and Frida instruments processes on these platforms. Understanding how Rust projects are built is a prerequisite.
* **Logic and Assumptions:** Identify places where the code makes decisions based on the `Cargo.toml` content (e.g., feature processing). Consider the assumptions made (e.g., no `build.rs`).

**5. Structuring the Answer:**

Organize the findings logically. Start with a high-level overview of the file's purpose. Then, break down the functionality into key areas, providing specific examples and connections to the technical domains.

* **Functionality:** List the main tasks the code performs.
* **Reverse Engineering Relevance:** Explain how the code supports reverse engineering workflows.
* **Binary/Low-Level Relevance:** Highlight interactions with binary concepts.
* **Kernel/Framework Relevance:** Connect to the broader context of Frida's targets.
* **Logical Reasoning:** Illustrate the code's decision-making with examples.
* **User Errors:** Point out common mistakes users might make.
* **User Path:** Describe the sequence of actions that lead to this code being executed.

**Self-Correction/Refinement during Analysis:**

* **Initial Oversimplification:**  Initially, one might just say "it parses Cargo.toml."  Refine this by digging into *what* aspects of `Cargo.toml` are handled and *how*.
* **Missing Connections:**  Actively look for connections between the code and the target domains. Don't just describe the code in isolation. Ask "so what?" and "why is this relevant to Frida?".
* **Clarity and Examples:**  Ensure the explanations are clear and use concrete examples from the code to illustrate the points. For instance, instead of just saying "it handles dependencies," show how the `Dependency` class and the dependency processing logic work.

By following this systematic approach, moving from high-level understanding to detailed analysis, and constantly connecting the code back to the core requirements, a comprehensive and insightful answer can be constructed.
This Python file, `interpreter.py`, is part of the Frida dynamic instrumentation toolkit and plays a crucial role in integrating Rust-based components (built with Cargo) into Frida's build system, which uses Meson. It essentially translates the declarative configuration of a Rust project defined in `Cargo.toml` into instructions that Meson can understand and use to build the Rust code.

Here's a breakdown of its functionality:

**1. Parsing `Cargo.toml`:**

* **Functionality:** The primary function of this file is to read and interpret `Cargo.toml` files, which are the manifest files for Rust projects. It uses the `tomllib` or `tomli` library (or falls back to `toml2json`) to parse the TOML format into Python dictionaries.
* **Reverse Engineering Relevance:** Understanding the dependencies and build targets defined in `Cargo.toml` is crucial in a reverse engineering context. It reveals what external libraries a Rust binary relies on and what different build artifacts (libraries, binaries, examples, tests, benchmarks) exist within the project.
    * **Example:** If you are reverse engineering a Frida gadget written in Rust, analyzing its `Cargo.toml` will tell you what crates (Rust libraries) it uses, which could provide hints about its functionality and potential attack surfaces.
* **Binary/Low-Level Relevance:**  `Cargo.toml` specifies the `crate-type` (e.g., `lib`, `bin`, `cdylib`, `proc-macro`). This directly relates to the type of binary artifact produced (static library, executable, dynamic library for C interop, procedural macro).
* **User Path:** When Meson encounters a Frida subproject that contains a `Cargo.toml` file, it will invoke this `interpreter.py` to process it.

**2. Converting Cargo Definitions to Meson AST (Abstract Syntax Tree):**

* **Functionality:**  It translates the information from `Cargo.toml` into Meson's build language. This involves creating Meson function calls (`project`, `dependency`, library/binary definitions, etc.) represented as Meson AST nodes.
* **Reverse Engineering Relevance:** By understanding how Cargo definitions are translated to Meson, developers working on Frida can ensure that the Rust components are built correctly and integrated seamlessly into the larger Frida build. This is vital for creating and distributing Frida gadgets or components written in Rust.
* **Linux, Android Kernel & Framework Knowledge:**
    * **Shared Libraries (`cdylib`):**  The code handles `cdylib` crate types, which are used to create shared libraries that can be loaded by other languages (like C/C++ used in Frida's core or Android's framework).
    * **Dependencies:** The code manages dependencies between Rust crates. This is relevant because Frida gadgets or modules often depend on other Rust libraries for specific functionalities. On Android, this might involve dependencies that interact with Android system libraries or frameworks.
* **Logical Reasoning:** The code makes decisions based on the content of `Cargo.toml`.
    * **Assumption:** The code assumes that if a directory named "meson" exists within the Cargo subproject, it contains additional Meson build instructions to handle cases not directly representable in `Cargo.toml` (like complex build.rs logic).
    * **Input:** A `Cargo.toml` file for a Rust library named "my-rust-lib" with a dependency on the "log" crate.
    * **Output:** Meson AST nodes that:
        * Define a Meson project named "my-rust-lib".
        * Declare a dependency on the "log" crate, potentially specifying version constraints.
        * Define how to build the "my-rust-lib" library.

**3. Handling Dependencies:**

* **Functionality:** It parses the `dependencies`, `dev-dependencies`, and `build-dependencies` sections of `Cargo.toml`. It understands different ways to specify dependencies (version strings, Git repositories, local paths). It also handles optional dependencies and features.
* **Reverse Engineering Relevance:**  Knowing the dependencies of a Rust binary is crucial for reverse engineering. It helps identify the functionalities the binary relies on and potential vulnerabilities in those dependencies.
* **User Path:** When processing the `dependencies` section of `Cargo.toml`, this code is executed to create corresponding Meson `dependency()` calls.

**4. Handling Features:**

* **Functionality:** It processes Cargo features, which allow conditional compilation of code. It translates these features into Meson options that users can enable or disable during the build process.
* **Reverse Engineering Relevance:** Understanding the available features of a Rust crate can reveal different functionalities or build configurations. This is useful when reverse engineering to understand how different parts of the code can be activated.
* **Logical Reasoning:** The `_process_feature` function recursively determines the implications of enabling a specific feature, including other required features and dependencies.
    * **Input:** A `Cargo.toml` with a feature named "my-feature" that enables the "log" dependency.
    * **Output:** Meson code that creates a build option "feature-my-feature" and conditionally adds the "log" dependency if the option is enabled.

**5. Defining Build Targets (Libraries, Binaries, Examples, Tests, Benchmarks):**

* **Functionality:** It parses the `[lib]`, `[[bin]]`, `[[example]]`, `[[test]]`, and `[[bench]]` sections of `Cargo.toml` to define how to build different types of artifacts.
* **Reverse Engineering Relevance:** This directly shows what executable binaries, libraries, examples, tests, and benchmarks are part of the Rust project. This is fundamental information for a reverse engineer.
* **Binary/Low-Level Relevance:** The `crate-type` of libraries (e.g., `rlib`, `dylib`) dictates how they are linked and used. Binaries are the executables themselves.
* **User Path:** When the code encounters sections defining build targets in `Cargo.toml`, it generates the corresponding Meson build rules to compile and link those targets.

**6. Handling Platform-Specific Dependencies (Targets):**

* **Functionality:** It parses the `[target.'cfg(…)'.dependencies]` section, which allows specifying dependencies that are only used when building for specific target platforms or configurations.
* **Reverse Engineering Relevance:** This can reveal platform-specific code and dependencies, which is crucial when reverse engineering software that behaves differently on different operating systems or architectures (like Android vs. Linux).

**7. Dealing with `build.rs` Limitations:**

* **Functionality:** The code explicitly acknowledges that it doesn't attempt to interpret `build.rs` files. `build.rs` allows arbitrary Rust code to be executed during the build process, making it very difficult to automatically translate to Meson.
* **Reverse Engineering Relevance:**  If a Rust project relies heavily on a `build.rs`, this interpreter will not fully capture its build logic. Reverse engineers might need to examine the `build.rs` separately to understand the full build process.
* **User Path:** If a Cargo project has a `build.rs`, the logic in this file will effectively ignore it, and a manual Meson port might be required for more complex build steps.

**8. Potential User Errors and Debugging:**

* **Malformed `Cargo.toml`:** If the `Cargo.toml` file is not valid TOML, the `load_toml` function will raise a `MesonException`. This is a common user error when manually editing `Cargo.toml`.
* **Missing `tomllib` or `tomli`:**  If neither of these libraries is installed and `toml2json` is also not found, the code will raise a `MesonException`. This indicates a missing dependency for the build system.
* **Inconsistent Features in Dependencies:** The code includes logic to verify that the features requested for a dependency are actually enabled in the configured dependency. If there's a mismatch, it will raise an error. This can happen if a user tries to build a project with feature combinations that are not compatible.
    * **Example:** A user might try to build a crate that depends on "another-crate" with the "feature-a" enabled, but "another-crate" was previously configured (perhaps in a different subproject) without "feature-a".
* **User Path Leading to Errors:**
    1. A user clones a Frida project with Rust components.
    2. The user attempts to build the project using Meson (`meson setup build`, `ninja -C build`).
    3. Meson encounters a subproject with a `Cargo.toml`.
    4. `interpreter.py` is invoked to process the `Cargo.toml`.
    5. If the `Cargo.toml` is malformed or dependencies are missing, an error is raised by this Python script, halting the build process. The error message will likely point to the location in the `Cargo.toml` or the missing dependency.

**In summary, `interpreter.py` acts as a bridge between the Rust ecosystem (Cargo) and the Meson build system within Frida. It parses Rust project configurations and translates them into Meson instructions, enabling the seamless integration of Rust components into the larger Frida project. This process is essential for building and distributing Frida, which often includes Rust-based gadgets or core components.**

### 提示词
```
这是目录为frida/subprojects/frida-clr/releng/meson/mesonbuild/cargo/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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