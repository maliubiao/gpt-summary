Response:
Let's break down the thought process for analyzing this Python code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided Python code (`interpreter.py`) within the context of the Frida dynamic instrumentation tool. The prompt also asks for specific connections to reverse engineering, low-level details, logical reasoning, common errors, and debugging context.

**2. Initial Code Scan and High-Level Understanding:**

The first step is to quickly scan the code to get a general idea of what it does. Keywords like "Cargo," "Toml," "Meson," "AST," "dependency," "features," and function names like `load_toml`, `_convert_manifest`, `_create_project`, `_create_dependencies`, etc., immediately suggest that this code is about converting Cargo project definitions (likely in `Cargo.toml` files) into Meson build system instructions. The initial comments also confirm this.

**3. Deeper Dive into Key Sections:**

Next, focus on understanding the purpose of specific code blocks and functions:

* **Import Statements:** Identify the external libraries and internal modules used. `tomllib`/`tomli` for TOML parsing, `json` for JSON (fallback), `os`, `shutil`, `glob`, and internal modules like `builder`, `version`, `mesonlib`, `coredata`. This gives clues about the operations performed (file system interaction, parsing, building).
* **`load_toml` Function:** Understands how Cargo.toml files are read. It prefers `tomllib` but falls back to `tomli` or even `toml2json` if necessary. This tells us about how the input data is acquired.
* **Data Classes (Package, Dependency, Manifest, etc.):** These define the structure for representing Cargo project information in Python. Pay attention to the fields and their types. This is crucial for understanding the data being processed.
* **`_convert_manifest` Function:** This is the core logic for transforming the raw TOML data into the structured `Manifest` object. Notice the use of `_fixup_raw_mappings` to handle naming conventions.
* **`_create_project`, `_create_features`, `_create_dependencies`, `_create_lib` Functions:** These are responsible for generating the Meson AST nodes. Analyze what Meson functions are being called (`project`, `dependency`, `static_library`, `shared_library`, `proc_macro`, `declare_dependency`, `override_dependency`, etc.) and what arguments are being passed. This is where the conversion logic happens.
* **`interpret` Function:** This is the main entry point for the conversion process. It orchestrates loading the manifest, building the Meson AST, and defining project options.

**4. Connecting to the Prompt's Specific Questions:**

Now, systematically address each part of the prompt:

* **Functionality:** Summarize the core purpose: converting Cargo project definitions to Meson build files. Mention key aspects like handling dependencies, features, and library creation.
* **Relationship to Reverse Engineering:**  Think about *why* someone working with Frida might need this. Frida instruments binaries. Cargo is used to build Rust code. Therefore, this code helps build Rust libraries that could be targets for Frida instrumentation. Example: Instrumenting a Rust library used by an Android app.
* **Binary/Low-Level/Kernel/Framework Knowledge:** Look for clues in the code. The mention of "crate_type" (`lib`, `bin`, `rlib`, `dylib`, `cdylib`, `proc-macro`) directly relates to Rust's compilation model and the types of binary artifacts produced. `staticlib`, `dylib`, `cdylib` are related to linking and shared libraries, which are fundamental at the OS level. The discussion of proc-macros is a more advanced Rust concept related to compile-time code generation.
* **Logical Reasoning (Hypothetical Input/Output):** Consider a simple `Cargo.toml` example and trace how the code would process it, imagining the resulting Meson code. Focus on the transformation of dependencies, features, and the creation of library targets.
* **Common Usage Errors:** Think about what could go wrong. Missing dependencies, incorrect feature specifications, and issues with the `toml2json` fallback are potential problems. The code itself checks for inconsistencies in feature configurations of dependencies, indicating a potential user error.
* **User Operation and Debugging:**  Imagine the steps a developer would take to use this tool. They'd likely be building a project that includes Rust code managed by Cargo. When the Meson build system encounters a Cargo project, it would trigger this `interpreter.py` script. Debugging would involve inspecting the `Cargo.toml`, the generated Meson files, and potentially stepping through the Python code.

**5. Structuring the Answer:**

Organize the findings into clear sections corresponding to the prompt's questions. Use bullet points, code snippets (where relevant), and clear explanations to convey the information effectively.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe this code directly manipulates binaries. **Correction:** The code focuses on *build system integration*, not direct binary manipulation. It *prepares* the build process for Rust code that *will* produce binaries.
* **Initial thought:**  The `toml2json` fallback is just a minor detail. **Refinement:** Emphasize that this indicates a dependency on external tools and potential error points.
* **Initial thought:** The feature processing is complex. **Refinement:** Break down the `_process_feature` function's logic into smaller steps (identifying required features, dependency features, and recursive processing).

By following this structured approach, combining code analysis with an understanding of the surrounding context (Frida, Cargo, Meson), and systematically addressing each part of the prompt, a comprehensive and accurate answer can be generated.
This Python script, `interpreter.py`, is a crucial component of Frida's build system for handling Rust projects managed by Cargo. Its primary function is to **translate Cargo manifest files (`Cargo.toml`) into Meson build system instructions**. This allows Frida's build process, which uses Meson, to understand how to build Rust components.

Here's a breakdown of its functionalities and their relation to the concepts you mentioned:

**1. Functionality: Parsing and Interpreting Cargo Manifests**

* **Loading `Cargo.toml`:** The script starts by attempting to load the `Cargo.toml` file using the `tomllib` or `tomli` libraries (for parsing TOML). If these aren't available, it falls back to using an external `toml2json` command-line tool. This demonstrates a practical approach to handling dependencies and different environments.
* **Data Structures for Cargo Concepts:** It defines Python data classes (`Package`, `Dependency`, `BuildTarget`, `Library`, `Binary`, `Manifest`, etc.) that mirror the structure and concepts found in a `Cargo.toml` file. This includes information about the package name, version, dependencies, build targets (libraries, binaries, examples, tests, benchmarks), and features.
* **Converting Raw Data:** The `_convert_manifest` function takes the raw parsed TOML data and populates these data classes, performing necessary transformations like replacing hyphens with underscores in variable names (`fixup_meson_varname`) for better Python compatibility and converting Cargo dependency version strings into a format Meson understands.
* **Handling Workspaces:** The script can handle Cargo workspaces, which are projects containing multiple related crates. It recursively loads and interprets the `Cargo.toml` files in the workspace members.

**2. Functionality: Generating Meson AST (Abstract Syntax Tree)**

* **Meson Builder:** It uses a `builder.Builder` class (likely defined in a related module) to construct the Meson AST. The AST represents the build instructions in a structured format that Meson can process.
* **Creating Project Definition:** The `_create_project` function generates the Meson `project()` function call, defining the project name, language (Rust), version, and default options (like the Rust edition).
* **Handling Features:** The `_create_features` function translates Cargo features into Meson options. It creates boolean options for each feature and uses conditional logic to enable dependencies and other features based on which options are enabled. This is a key aspect of managing conditional compilation in Rust.
* **Defining Dependencies:** The `_create_dependencies` function translates Cargo dependencies into Meson `dependency()` calls. It handles different dependency sources (crates.io, git, path) and also considers optional dependencies and feature flags. It includes logic to verify that the required features of a dependency are actually enabled.
* **Defining Build Targets (Libraries and Binaries):** The `_create_lib` function generates Meson instructions for building Rust libraries, considering different crate types (like `lib`, `rlib`, `dylib`, `cdylib`, `proc-macro`). It uses the Meson `rust.static_library`, `rust.shared_library`, and `rust.proc_macro` functions. Similarly, there would be logic (though not explicitly shown in the extract) for handling binaries, examples, tests, and benchmarks.
* **Handling Extra Arguments and Dependencies:** The `_create_meson_subdir` function allows Cargo subprojects to define additional Rust arguments and dependencies in a `meson/meson.build` file within the Cargo project. This provides a way to extend the generated Meson build instructions manually.
* **Overriding Dependencies:** The script uses `meson.override_dependency()` to tell Meson to use the generated Rust library as a dependency when other parts of the project depend on it.

**Relationship to Reverse Engineering:**

* **Building Instrumentation Targets:** This script plays a vital role in building the Rust components of Frida itself, as well as any Rust libraries that a user might want to instrument using Frida. By correctly translating the `Cargo.toml`, it ensures that the Rust code is built in a way that Frida can interact with.
* **Understanding Target Structure:** When reverse engineering a target application that uses Rust, understanding its dependencies and build process (often defined by `Cargo.toml`) is crucial. This script shows how a build system interprets that information, providing insights into the target's architecture.
* **Identifying Dependencies:** The script explicitly extracts and defines the dependencies of a Rust project. In reverse engineering, identifying the libraries a target application uses is a fundamental step.

**Examples related to Reverse Engineering:**

* **Scenario:** You are reverse engineering an Android application that includes a native library written in Rust. The library's build process is defined by a `Cargo.toml`.
* **How this script helps:** Frida's build system would use this script to parse the library's `Cargo.toml` and build the `.so` file for the Android target. This `.so` file is what you would then load into Frida to perform dynamic instrumentation.
* **Example:** If the `Cargo.toml` specifies a dependency on the `openssl-sys` crate, this script will ensure that the necessary OpenSSL libraries are linked correctly when building the Rust library, allowing your Frida scripts to interact with code that uses OpenSSL within the target application.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

* **Crate Types and Linking:** The script explicitly handles different Rust crate types (`lib`, `rlib`, `dylib`, `cdylib`).
    * **`rlib` (Rust static library):** These are linked into other Rust crates.
    * **`dylib` (Dynamic library):** These are shared libraries that can be loaded at runtime on Linux and other platforms. This is directly related to the concept of shared objects (`.so` files on Linux, `.dylib` on macOS, `.dll` on Windows).
    * **`cdylib` (C dynamic library):** These are dynamic libraries with a C-compatible ABI, often used for interoperability with other languages. This is crucial for building native libraries that can be loaded by Android's framework.
    * **`proc-macro` (Procedural macro):** These are Rust code snippets that run at compile time to generate other Rust code.
* **Dependency Management:**  The handling of dependencies is fundamentally about linking different binary artifacts together. On Linux and Android, this involves linking against `.so` files.
* **Android Native Libraries:** When building Rust code for Android, the `cdylib` crate type is often used to create a shared library that can be loaded by the Android runtime. This script ensures that the `Cargo.toml` directives for building such libraries are correctly translated into Meson instructions.
* **System Libraries:** Dependencies like `openssl-sys` or `libc` directly interact with the underlying operating system (Linux kernel on Android) and its standard C library. This script orchestrates the linking of these system libraries.

**Examples:**

* **`crate_type = ["cdylib"]`:**  This in the `Cargo.toml` tells the script to build a dynamic library with a C ABI, which is exactly what's needed for a native Android library that can be loaded by the Dalvik/ART runtime.
* **Dependencies on `libc` or `ndk-sys`:** If the `Cargo.toml` includes dependencies that provide access to the C standard library or Android NDK functions, this script will ensure that the appropriate system libraries are linked during the build process, allowing the Rust code to interact with the Android framework or kernel.

**Logical Reasoning (Hypothetical Input and Output):**

**Hypothetical Input (`Cargo.toml`):**

```toml
[package]
name = "my_rust_lib"
version = "0.1.0"

[dependencies]
log = "0.4"

[lib]
crate-type = ["cdylib"]
```

**Likely Output (Snippet of generated Meson code):**

```meson
project('my_rust_lib', 'rust', version: '0.1.0', meson_version: '>= ...')

rust = import('rust')

# ... (feature definitions, dependency definitions for 'log') ...

lib = rust.shared_library('my_rust_lib', 'src/lib.rs',
  dependencies: [log_dep], # Assuming 'log_dep' is the Meson dependency object for the 'log' crate
  rust_abi: 'c'
)

dep = declare_dependency(
  link_with: lib,
  variables: {'features': meson.project_meson_version()} # Simplified for brevity
)
meson.override_dependency('my-rust-lib-0', dep) # Assuming API version 0
```

**Explanation:**

* The script reads the `package` information to create the Meson `project()` call.
* It identifies the `log` dependency and generates the necessary Meson code to fetch and link it.
* Because `crate-type = ["cdylib"]`, it calls `rust.shared_library` with `rust_abi: 'c'`, indicating a C-compatible dynamic library.
* It declares a Meson dependency object (`dep`) representing the built Rust library and uses `meson.override_dependency` to make it available to other parts of the Frida build.

**Common Usage Errors:**

* **Incorrect `Cargo.toml` Syntax:** If the `Cargo.toml` file has syntax errors, the TOML parsing libraries will fail, and the script will likely raise an exception.
    * **Example:** Missing quotes around a string value, incorrect indentation.
* **Missing Dependencies:** If the `Cargo.toml` refers to a dependency that cannot be found (e.g., a typo in the dependency name or the dependency doesn't exist in the specified registry), the Meson build will fail when trying to resolve that dependency.
    * **Example:** `[dependencies]\n  my_typoed_crate = "1.0"`
* **Feature Conflicts:** If different parts of the project or its dependencies require conflicting features, the build might fail. The script attempts to detect some feature inconsistencies.
    * **Example:** Two dependencies requiring mutually exclusive features.
* **Problems with `toml2json` Fallback:** If the system relies on the `toml2json` tool and it's not installed or not in the system's PATH, the script will raise an error.
* **Mismatched Meson and Rust Versions:** While not directly a user error within the `Cargo.toml`, inconsistencies between the Meson version used by Frida and the Rust toolchain version specified in the `Cargo.toml` (e.g., `rust-version`) could lead to build problems.

**User Operation and Debugging Lineage:**

1. **Developer wants to build Frida (or a Frida module with Rust components):** The process starts when a developer attempts to build Frida or a project that includes Rust code managed by Cargo and integrated with Frida's build system.
2. **Meson encounters a Cargo project:** During the Meson configuration phase, when Meson encounters a subdirectory containing a `Cargo.toml` file, it recognizes it as a Rust project.
3. **Meson calls the `interpreter.py` script:** Meson is configured to call this `interpreter.py` script to handle the Cargo project. The script is passed the subdirectory path.
4. **`interpreter.py` loads and parses `Cargo.toml`:** The script begins by trying to load the `Cargo.toml` file in the specified subdirectory.
5. **Errors during parsing or interpretation:** If there are errors in the `Cargo.toml` (syntax, missing dependencies, etc.), the script will raise an exception, stopping the Meson configuration process. This provides the developer with the first indication of a problem. The error message might point to the specific line in the `Cargo.toml` or indicate a dependency resolution failure.
6. **Successful interpretation and Meson AST generation:** If the `Cargo.toml` is valid, the script proceeds to generate the Meson AST representing the build instructions for the Rust project.
7. **Meson proceeds with the build:** Meson then uses the generated AST to execute the build process, calling the Rust compiler (`rustc`) and linker (`ld`) as needed.
8. **Errors during Rust compilation or linking:**  If there are errors during the actual Rust compilation or linking (e.g., Rust code errors, linking issues with system libraries), the Rust compiler or linker will report these errors. These errors are separate from the `interpreter.py` itself but are a consequence of the build instructions generated by it.
9. **Debugging:**
    * **Inspect `Cargo.toml`:** The first step in debugging is usually to carefully examine the `Cargo.toml` file for syntax errors, typos in dependency names, or incorrect version specifications.
    * **Check Meson logs:** Meson typically provides logs that show the commands it executes, including the calls to the Rust compiler. Examining these logs can help pinpoint compilation or linking errors.
    * **Examine the generated Meson files:**  While not always straightforward, looking at the actual `.meson` files generated by this script can sometimes provide insights into how the `Cargo.toml` was translated and if there are any unexpected build instructions.
    * **Run `cargo build` directly:**  To isolate issues related to the `interpreter.py` script, developers can often try building the Rust project directly using `cargo build` from within the Rust project's directory. If `cargo build` fails, the problem lies within the Rust project itself, not the Meson integration. If `cargo build` succeeds but the Meson build fails, it suggests an issue with the translation performed by `interpreter.py`.

In essence, `interpreter.py` acts as a bridge between the Rust ecosystem (managed by Cargo) and the Meson build system used by Frida. It's a critical piece for ensuring that Rust components can be seamlessly integrated into the larger Frida project.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/cargo/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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