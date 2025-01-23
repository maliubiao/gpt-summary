Response:
Let's break down the request and the provided Python code step-by-step to construct a comprehensive answer.

**1. Understanding the Goal:**

The request asks for a detailed explanation of a specific Python file (`interpreter.py`) within the Frida project. The explanation needs to cover:

* **Functionality:** What does the code do?
* **Relevance to Reversing:** How can this code be used or how does it relate to reverse engineering?
* **Low-Level Concepts:**  Does it touch upon binaries, Linux/Android kernels, or frameworks?
* **Logical Reasoning:** Are there any assumptions and corresponding inputs/outputs?
* **User Errors:** What mistakes can a user make while using this?
* **Debugging:** How does a user end up interacting with this code, providing debugging clues?

**2. Initial Code Scan and High-Level Understanding:**

The first few lines are crucial:

```python
"""Interpreter for converting Cargo Toml definitions to Meson AST

There are some notable limits here. We don't even try to convert something with
a build.rs: there's so few limits on what Cargo allows a build.rs (basically
none), and no good way for us to convert them. In that case, an actual meson
port will be required.
"""
```

This immediately tells us the core function: converting `Cargo.toml` files (used by Rust projects) into Meson Abstract Syntax Trees (AST). Meson is a build system. The comment about `build.rs` highlights a limitation and a situation where manual intervention is needed.

**3. Analyzing Imports and Dependencies:**

The imports provide further clues:

* `dataclasses`, `glob`, `importlib`, `itertools`, `json`, `os`, `shutil`, `collections`, `typing`: Standard Python libraries for data handling, file system operations, etc.
* `.builder`, `.version`, `..mesonlib`, `..coredata`: Local modules within the Frida project, likely related to Meson integration.
* `tomllib` and `tomli`: Libraries for parsing TOML files (the format of `Cargo.toml`). The code handles cases where `tomllib` (Python 3.11+) is available or falls back to `tomli`. It also mentions `toml2json` as a potential fallback.

**4. Deeper Dive into Functions and Classes:**

Now, let's go through the significant parts of the code:

* **`load_toml(filename)`:** Handles loading and parsing `Cargo.toml`. Crucially, it deals with the availability of TOML parsing libraries. This points to potential user errors if TOML libraries are missing.
* **`fixup_meson_varname(name)`:**  Simple string manipulation to convert Rust-style names (with hyphens) to Python/Meson-friendly names (with underscores).
* **`_fixup_raw_mappings(d)`:**  Fixes up data structures read from the TOML file, specifically handling version strings.
* **`Package`, `Dependency`, `BuildTarget`, `Library`, `Binary`, `Test`, `Benchmark`, `Example`, `Manifest`:** These are dataclasses representing the structure of a `Cargo.toml` file. They model the different sections and entries within it.
* **`_convert_manifest(raw_manifest, subdir, path)`:**  Transforms the raw parsed TOML data into the `Manifest` dataclass structure.
* **`_load_manifests(subdir)`:**  Loads `Cargo.toml` files, handling both single-package and workspace scenarios (where a project can contain multiple sub-crates). It uses `glob` to find member crates.
* **Helper functions like `_version_to_api`, `_dependency_name`, `_dependency_varname`, `_option_name`, `_options_varname`, `_extra_args_varname`, `_extra_deps_varname`:** These assist in generating Meson-specific names and handling dependency information.
* **`_create_project(cargo, build)`:** Creates the Meson `project()` call, defining basic project information.
* **`_process_feature(cargo, feature)`:**  Analyzes Cargo features (conditional compilation flags) and determines the dependencies and other features that need to be enabled.
* **`_create_features(cargo, build)`:** Generates Meson code to handle Cargo features as Meson options.
* **`_create_dependencies(cargo, build)`:** Generates Meson code to declare dependencies on other Rust crates, handling versioning and feature requirements. It includes logic to verify that required features are enabled in dependent crates.
* **`_create_meson_subdir(cargo, build)`:**  Looks for a `meson` subdirectory within the Cargo project, allowing for custom Meson build logic (a way to work around the limitations of automatic `build.rs` conversion).
* **`_create_lib(cargo, build, crate_type)`:** Generates Meson code to build Rust libraries. It distinguishes between different library crate types (`lib`, `rlib`, `dylib`, etc.) and handles proc-macros.
* **`interpret(subp_name, subdir, env)`:** The main function that orchestrates the conversion process. It loads the manifest, creates the Meson AST, and defines Meson options based on Cargo features.

**5. Connecting to the Request's Specific Points:**

Now, let's map the code analysis to the requested points:

* **Functionality:** Clearly, the main function is to translate `Cargo.toml` into Meson build instructions. This automates the process of building Rust components within a larger project managed by Meson.

* **Relevance to Reversing:** This is where Frida comes in. Frida is a dynamic instrumentation toolkit. It allows you to inject JavaScript into running processes to observe and modify their behavior. Rust is often used for building security-sensitive components or libraries. By integrating Rust builds into a Meson-based Frida build system, this `interpreter.py` enables:
    * **Building Frida Gadgets/Agents in Rust:**  Developers can write Frida components in Rust and use this tool to integrate them into the Frida build.
    * **Reverse Engineering Rust Binaries:** While this script doesn't *directly* reverse engineer, it simplifies the process of *building* the target Rust components. Having the build system in place can be helpful when you need to recompile with debug symbols or make modifications for analysis. For example, you might modify the Rust code and rebuild it to test a hypothesis about its behavior.

* **Binary/Low-Level, Linux/Android Kernel/Framework:**
    * **Binary Bottom Line:**  The output of this script (Meson build files) ultimately instructs the compiler (rustc) to produce *binary* artifacts (libraries, executables).
    * **Linux/Android:** Frida often targets Linux and Android. Rust is a cross-platform language, but the specific *use* of Frida on these platforms means the generated Rust code (and thus this script) is relevant to those environments. While the script itself doesn't directly interact with the kernel, the *libraries* it builds might (e.g., if they interact with system calls). Frida, in its operation, *does* interact with the kernel to perform instrumentation.
    * **Framework:**  On Android, this could relate to interacting with the Android framework (e.g., instrumenting Java code by building a native Rust library that bridges to Frida's Java bindings).

* **Logical Reasoning (Assumptions and Inputs/Outputs):**
    * **Assumption:** The primary assumption is that the `Cargo.toml` file is well-formed and follows the Cargo specification. The script explicitly states it *doesn't* handle `build.rs` files, implying that projects relying heavily on custom build scripts won't be automatically converted.
    * **Input:** A `Cargo.toml` file.
    * **Output:** A set of Meson build definitions (AST), which will be written to `meson.build` files when Meson is run. These definitions describe how to compile the Rust code.

* **User Errors:**
    * **Missing TOML Libraries:** If `tomllib` or `tomli` (or `toml2json`) are not installed, the script will fail.
    * **Incorrect `Cargo.toml`:**  If the `Cargo.toml` file has syntax errors or violates the Cargo specification, the TOML parsing will fail.
    * **Using `build.rs`:**  If the Rust project uses a `build.rs` file for custom build logic, this script won't be able to handle it automatically. The user will need to manually create the equivalent Meson build logic.
    * **Feature Name Collisions:** If Cargo feature names conflict with Meson's reserved option names, the prefixing logic (`feature-`) is used to avoid this. However, manual adjustments might be needed in complex cases.
    * **Dependency Feature Conflicts:** The script attempts to detect if a dependency was previously configured with different features. If so, it throws an error, requiring the user to explicitly enable the necessary features through Meson options. This prevents subtle build issues.

* **User Operation and Debugging:**
    1. **Frida Development:** A developer wants to integrate a Rust component into their Frida project.
    2. **Cargo Subproject:** They create a Rust crate (with a `Cargo.toml`) within a subdirectory of the main Frida project.
    3. **Meson Configuration:** When Meson is run to configure the Frida build, it encounters the subdirectory containing the `Cargo.toml`.
    4. **`interpreter.py` Invocation:** Meson (or a Frida-specific build script) will invoke this `interpreter.py` script, passing the subdirectory path.
    5. **Error Scenario (Debugging Clue):** If the user sees an error message related to "Could not find an implementation of tomllib", it indicates they need to install the `tomli` package (if on Python < 3.11). If they see errors about feature mismatches in dependencies, it suggests they need to explicitly enable those features using Meson's `-D` option. If the build fails silently for a project with a `build.rs`, the user needs to manually create the Meson equivalents.

**Constructing the Answer:**

By following these steps, we can construct a well-structured and detailed answer that addresses all aspects of the request, providing context, examples, and debugging guidance. The key is to break down the code into logical components and then connect those components to the broader context of Frida, reverse engineering, and build systems.
This Python code (`interpreter.py`) is a crucial part of the Frida build system, specifically for integrating Rust-based components into projects managed by Meson. Its primary function is to **interpret `Cargo.toml` files (the manifest files for Rust crates) and convert their definitions into Meson Abstract Syntax Tree (AST) nodes**. This allows Meson to understand how to build the Rust code.

Here's a breakdown of its functionalities with examples related to reverse engineering, low-level concepts, logical reasoning, user errors, and debugging:

**Functionalities:**

1. **Parsing `Cargo.toml`:** The code reads and parses `Cargo.toml` files, which define a Rust crate's metadata, dependencies, build targets (libraries, binaries, examples, tests, benchmarks), and features. It uses the `tomllib` or `tomli` library for this. If neither is available, it attempts to use `toml2json` as a fallback.
    * **Reverse Engineering Relevance:** Understanding the dependencies and build targets of a Rust crate is a fundamental step in reverse engineering it. The `Cargo.toml` reveals what external libraries the crate uses and what kind of output it produces (e.g., a library to be linked or an executable).

2. **Representing Cargo Data Structures:** It defines Python dataclasses (`Package`, `Dependency`, `BuildTarget`, `Library`, `Binary`, `Test`, `Benchmark`, `Example`, `Manifest`) to represent the various sections and entries within a `Cargo.toml` file.
    * **Reverse Engineering Relevance:** These dataclasses provide a structured way to access and manipulate the information extracted from the `Cargo.toml`. This can be useful in automated analysis or build processes for reverse engineering targets.

3. **Converting Cargo Definitions to Meson AST:** The core functionality is translating the parsed Cargo information into Meson's build system language. This involves creating Meson function calls (`project`, `dependency`, `static_library`, `shared_library`, `proc_macro`, etc.) and data structures (arrays, dictionaries).
    * **Reverse Engineering Relevance:** This enables integrating Rust components into a larger project built with Meson. For reverse engineering Frida itself or building Frida gadgets in Rust, this conversion is essential.

4. **Handling Dependencies:** It parses dependency information from `Cargo.toml`, including version requirements, optional dependencies, and features. It then translates these into Meson `dependency()` calls.
    * **Reverse Engineering Relevance:**  Identifying the dependencies of a Rust crate is crucial for understanding its functionality and potential vulnerabilities. This code helps in setting up the build environment to include those dependencies.

5. **Managing Features:** Cargo features allow for conditional compilation. This code converts Cargo features into Meson options, allowing users to enable or disable specific features during the build process.
    * **Reverse Engineering Relevance:** Analyzing how different features affect the compiled binary can reveal hidden functionalities or conditional logic within the code. Being able to control these features during the build is valuable for targeted analysis.

6. **Handling Different Crate Types:** It distinguishes between different types of Rust crates (library, binary, proc-macro) and generates the appropriate Meson build commands for each.
    * **Reverse Engineering Relevance:** Knowing the crate type is essential. A library will be linked into another program, while a binary is an executable. Proc-macros are code that runs during compilation and can significantly alter the code being compiled.

7. **Providing a Mechanism for Custom Build Logic:** While it doesn't automatically convert `build.rs` files, it provides a way to include custom Meson build logic in a `meson` subdirectory within the Cargo project. This allows users to handle cases where automatic conversion is not feasible.
    * **Reverse Engineering Relevance:**  Some Rust projects rely heavily on `build.rs` for code generation or custom build steps. This mechanism provides a way to integrate such projects into the Meson build, albeit requiring manual effort.

**Relationship to Reverse Engineering (Examples):**

* **Building Frida Gadgets in Rust:** If a developer wants to write a Frida gadget (a small program injected into a target process) in Rust, they would create a Rust crate with a `Cargo.toml`. Meson, using this `interpreter.py`, will then be able to build that gadget alongside the core Frida components.
* **Analyzing a Rust Library:**  Imagine you're reverse engineering a closed-source application that uses a Rust library. If you have access to the library's `Cargo.toml` (or can reconstruct it), you could use this code (indirectly, through the Frida build system) to understand its dependencies and build it yourself, potentially with debug symbols, for easier analysis with tools like GDB or lldb.
* **Investigating Feature Flags:** If a Rust binary has conditional logic controlled by feature flags, this code helps in setting up the build environment to compile the binary with specific feature combinations, allowing you to analyze different execution paths.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge (Examples):**

* **Binary Bottom Line:** Ultimately, this code leads to the creation of binary files (executables or libraries). The `crate_type` field in `Cargo.toml` directly influences whether a static library, a dynamic library, or an executable is produced. The choice of `rust_abi` for certain crate types (`staticlib`, `cdylib`) directly relates to binary compatibility at the ABI level.
* **Linux & Android:** Frida heavily targets Linux and Android. When building Rust components for Frida on these platforms, this code will generate Meson build instructions that are appropriate for those operating systems. This might involve linking against system libraries or handling platform-specific build options.
* **Kernel (Indirect):** While this code doesn't directly interact with the Linux or Android kernel, the Rust code it helps build might. For instance, a Frida gadget could use system calls to interact with the kernel. The choice of crate type and dependencies can influence how the resulting binary interacts with the underlying operating system.
* **Framework (Android):**  When building Frida components for Android, the generated Rust code might need to interact with the Android framework (e.g., through JNI to call Java APIs). The dependencies specified in `Cargo.toml` might include crates that provide bindings to Android framework components.

**Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input (`Cargo.toml`):**

```toml
[package]
name = "my-rust-lib"
version = "0.1.0"

[dependencies]
log = "0.4"
regex = "1.5"

[lib]
crate-type = ["cdylib"]
```

**Expected Output (Conceptual Meson AST - simplified):**

```meson
project('my-rust-lib', 'rust')
rust = import('rust')

log_dep = dependency('log', version : ['>=0.4'])
regex_dep = dependency('regex', version : ['>=1.5'])

my_rust_lib = rust.shared_library('my_rust_lib', 'src/lib.rs',
  dependencies : [log_dep, regex_dep],
  rust_abi : 'c'
)

meson.override_dependency('my-rust-lib-0', declare_dependency(link_with : my_rust_lib))
```

**Explanation:**

* The input `Cargo.toml` defines a Rust library named "my-rust-lib" with dependencies on "log" and "regex", built as a "cdylib" (C-compatible dynamic library).
* The output Meson AST defines a Meson project, imports the Rust module, declares dependencies on the "log" and "regex" crates, and then creates a shared library target using the `rust.shared_library` function, linking against the declared dependencies and specifying the 'c' ABI. Finally, it overrides the generic dependency name with the specific built target.

**User or Programming Common Usage Errors (Examples):**

1. **Missing `tomllib` or `tomli`:** If the user's Python environment doesn't have these libraries installed, the script will raise a `MesonException`.
   ```
   # Error in Meson output:
   Could not find an implementation of tomllib, nor toml2json
   ```
   **Debugging:** Install the missing library: `pip install tomli` (for older Python versions).

2. **Incorrect `Cargo.toml` Syntax:** If the `Cargo.toml` file has syntax errors, the TOML parsing will fail.
   ```
   # Error in Meson output (likely originating from the toml library):
   toml.decoder.TomlDecodeError: Unexpected character: '=' at line 3 column 1
   ```
   **Debugging:** Carefully review the `Cargo.toml` file for syntax errors, referring to the TOML specification.

3. **Using `build.rs` without Manual Meson Configuration:** If the Rust crate relies on a `build.rs` script for custom build logic, this script won't automatically convert it.
   ```
   # No explicit error, but the build might fail or produce unexpected results
   ```
   **Debugging:** The user needs to manually create the equivalent Meson build logic within a `meson` subdirectory or directly in the main `meson.build` file. The comment in the code explicitly mentions this limitation.

4. **Feature Name Collisions:** While the code tries to avoid collisions by prefixing feature names with "feature-", manual intervention might be needed if there are complex scenarios or if the user tries to access these options directly in unexpected ways.
   ```
   # Potential issues if a Cargo feature has the same name as a built-in Meson option
   ```
   **Debugging:**  Carefully choose feature names in `Cargo.toml` and be aware of Meson's reserved option names.

5. **Dependency Feature Mismatches:** If a dependency is used with a specific feature enabled in one part of the project but another part requires a different set of features for the same dependency, this can lead to errors. The code includes logic to detect this.
   ```
   # Error in Meson output:
   Dependency <dependency_name> previously configured with features [...] but need [...]
   ```
   **Debugging:** The user needs to ensure that the required features for a dependency are consistently enabled across the project, potentially using Meson's `default_options` in the `project()` call or by explicitly setting feature options.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **Frida Project Setup:** A developer is working on the Frida project or a project that uses Frida as a dependency.
2. **Adding a Rust Component:** They decide to add a new feature or component written in Rust.
3. **Creating a Cargo Crate:** They create a new directory within the project structure and create a `Cargo.toml` file describing their Rust code.
4. **Integrating with Meson:** They need to integrate this Rust crate into the overall build process managed by Meson. This typically involves adding a `subdir()` call in the main `meson.build` file that points to the directory containing the `Cargo.toml`.
5. **Running Meson:** When the developer runs `meson setup build` (or a similar command) to configure the build, Meson will encounter the `subdir()` call for the Rust component.
6. **`interpreter.py` Execution:** Meson's build system for Rust (defined elsewhere in the Frida codebase) will identify the `Cargo.toml` file in the specified subdirectory and invoke this `interpreter.py` script to parse the `Cargo.toml` and generate the necessary Meson build definitions.
7. **Potential Errors:** If any of the usage errors mentioned above occur (missing libraries, incorrect `Cargo.toml`, etc.), the errors will surface during this `meson setup` phase, providing clues about what went wrong in the interpretation of the `Cargo.toml`.

In summary, `interpreter.py` acts as a bridge between the Rust ecosystem (via `Cargo.toml`) and the Meson build system. It automates the process of including Rust code in larger Meson-managed projects like Frida, which is crucial for developing and extending Frida's capabilities, often in the context of dynamic instrumentation and reverse engineering.

### 提示词
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/cargo/interpreter.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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