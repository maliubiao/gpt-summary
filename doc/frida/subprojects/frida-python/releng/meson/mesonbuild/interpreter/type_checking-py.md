Response:
Let's break down the thought process for analyzing this Python code snippet.

**1. Initial Understanding of the Goal:**

The request asks for a functional breakdown of the provided Python code, specifically `type_checking.py` within the Frida project. Key aspects to identify are its purpose, relationship to reverse engineering, low-level details, logic, error handling, and how users might trigger this code.

**2. High-Level Overview & Core Functionality:**

Immediately, the name `type_checking.py` and the docstring "Helpers for strict type checking" strongly suggest this file's primary role: enforcing type constraints on function arguments within the Frida build system. It uses the `mesonbuild` framework, which is a build system generator.

**3. Identifying Key Components:**

* **Imports:**  The imports provide clues about the file's interactions. Libraries like `typing`, `itertools`, `os`, `re` are standard. The imports from `..` indicate interaction with other modules within the `mesonbuild` structure (e.g., `compilers`, `build`, `coredata`).
* **Type Aliases:**  The `NoneType`, `_FullEnvInitValueType`, `PkgConfigDefineType`, and `SourcesVarargsType` definitions are crucial for understanding the specific types being handled. They make the code more readable and help with static analysis.
* **Validators:** Functions like `in_set_validator`, `_language_validator`, `_install_mode_validator`, `variables_validator`, etc., are explicitly designed to validate the input arguments of other functions. This is a core part of the type-checking functionality.
* **Convertors:**  Functions like `_install_mode_convertor`, `_lower_strlist`, `variables_convertor`, `env_convertor_with_method`, `_override_options_convertor`, and `_pkgconfig_define_convertor` transform the input values into a more usable format. They often work in conjunction with validators.
* **`KwargInfo` Objects:** These are the central data structures. Each `KwargInfo` instance represents a specific keyword argument, along with its expected type, default value, validators, convertors, and other metadata. The consistent naming convention (e.g., `LANGUAGE_KW`, `INSTALL_MODE_KW`) makes them easy to identify.
* **Categorized `KwargInfo` Lists:** The code organizes `KwargInfo` objects into lists like `TEST_KWS`, `EXECUTABLE_KWS`, `SHARED_LIB_KWS`, etc. This indicates that different types of build targets or functions have specific sets of valid arguments.

**4. Analyzing Individual Functions and `KwargInfo` Objects (Iterative Process):**

For each validator and convertor, ask:

* **What type of input does it expect?** (Check the function signature and the corresponding `KwargInfo` definition).
* **What rules does it enforce?** (Examine the logic within the validator).
* **What transformation does it perform?** (Examine the logic within the convertor).
* **What `KwargInfo` is it associated with?** (Look for where the validator/convertor is used in the `KwargInfo` definition).

For each `KwargInfo` object, ask:

* **What is the name of the keyword argument?**
* **What are the allowed types?**
* **What is the default value?**
* **Are there any validators or convertors associated with it?**
* **Are there any versioning constraints (e.g., `since`, `deprecated`)?**

**5. Connecting to Reverse Engineering (and other domains):**

Think about how the enforced types and constraints relate to the larger process of building and using Frida:

* **Binary Bottom Layer:**  The `win_subsystem` and Darwin versioning keywords directly affect how executables are built for different operating systems. The linking options (`link_with`, `link_whole`) control how different binary components are combined.
* **Linux/Android Kernel & Framework:** While this specific file doesn't directly interact with the kernel, the build process it helps manage *does*. Frida's ability to instrument processes at runtime relies on being built correctly for the target OS and architecture. The `native` keyword and cross-compilation settings are relevant here.
* **Logical Reasoning:** The validators themselves embody logical rules. For example, the `_output_validator` checks for empty strings, whitespace-only strings, and path separators in output filenames. The `_validate_darwin_versions` ensures that version numbers are in the correct format.
* **User Errors:** The validators directly prevent common user errors, such as providing incorrect types for arguments, using invalid values for specific options, or creating duplicate output filenames.

**6. Examples and Scenarios:**

Based on the analysis, construct concrete examples to illustrate the different aspects:

* **Reverse Engineering:**  Illustrate how the `link_with` and architecture-related keywords are relevant.
* **Low-Level Details:**  Demonstrate how `win_subsystem` or Darwin versioning affect binary creation.
* **Logic:**  Show a validator's input and output, illustrating the rule being enforced.
* **User Errors:**  Give examples of incorrect argument types or values that the validators would catch.
* **User Path:**  Trace a hypothetical user action (e.g., calling a Frida build function with a specific argument) and explain how the code in this file would be invoked.

**7. Structuring the Output:**

Organize the findings into clear sections, as shown in the provided example answer. Use headings and bullet points to make the information easy to read and understand.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  "This is just about basic type checking."  **Correction:** Realize the validators and convertors are more sophisticated and enforce specific rules related to the Frida build process.
* **Struggling to understand a specific `KwargInfo`:**  Go back to the imports and related modules to understand the context of the keyword argument.
* **Overlooking a connection to reverse engineering:**  Revisit the purpose of Frida and how the build process supports its functionality.

By following this structured approach, combining code analysis with understanding the broader context of Frida and its build system, it's possible to generate a comprehensive and insightful explanation of the `type_checking.py` file.
This Python file, `type_checking.py`, located within the Frida project's build system (specifically the Meson build system integration for the Python bindings), serves as a central repository for **defining and enforcing strict type checking rules for keyword arguments** used in various functions within the Frida build process.

Here's a breakdown of its functionalities:

**1. Defining Valid Argument Types and Constraints:**

* **Using `KwargInfo`:** The core mechanism is the `KwargInfo` class. It encapsulates information about a specific keyword argument, including:
    * `name`: The name of the keyword argument (e.g., 'sources', 'language').
    * `types`:  The allowed data types for the argument (e.g., `str`, `list`, `bool`, custom classes like `File`, `BuildTarget`).
    * `default`:  The default value if the argument is not provided.
    * `required`: Whether the argument is mandatory.
    * `validator`: A function to perform custom validation on the argument's value.
    * `convertor`: A function to transform the argument's value into a more suitable format.
    * `listify`:  Indicates if a single value should be automatically converted into a list.
    * `since`/`deprecated`: Versioning information for the argument.

* **Type Aliases:** The file defines type aliases (e.g., `NoneType`, `_FullEnvInitValueType`, `SourcesVarargsType`) to improve code readability and make type hints more expressive.

**2. Implementing Custom Validation Logic:**

* The file contains various **validator functions** (functions whose names often end with `_validator`). These functions take an argument's value as input and return an error message (string) if the value is invalid, or `None` if it's valid. Examples include:
    * `in_set_validator`: Checks if a string value is one of the allowed choices.
    * `_language_validator`: Validates that the provided languages are known compiler languages.
    * `_install_mode_validator`: Enforces the specific format for the `install_mode` argument.
    * `variables_validator`: Checks the format of environment variables passed as strings or dictionaries.
    * `_output_validator`: Ensures output filenames are valid and don't contain path separators.
    * `_validate_shlib_version`: Verifies the format of shared library version strings.
    * Many more specific validators for arguments related to different build targets (executables, libraries, etc.).

**3. Implementing Argument Conversion:**

* The file also includes **convertor functions** (functions whose names often end with `_convertor`). These functions transform the input value into a desired format. Examples include:
    * `_install_mode_convertor`: Converts the DSL-like `install_mode` list into a `FileMode` object.
    * `_lower_strlist`: Converts a list of strings to lowercase.
    * `variables_convertor`: Parses environment variables from strings or dictionaries into a dictionary.
    * `env_convertor_with_method` and `_env_convertor`:  Handles the conversion of environment variables provided in various formats into an `EnvironmentVariables` object.
    * `_override_options_convertor`: Converts different representations of override options into a dictionary.
    * `_pkgconfig_define_convertor`: Transforms a list of strings into a tuple of key-value pairs for pkg-config definitions.

**4. Defining Keyword Arguments for Different Build Constructs:**

* The file defines various `KwargInfo` instances for common and specific keyword arguments used in functions like:
    * Compiler-related functions (e.g., `add_compiler`, `add_*_args`).
    * Build target definitions (e.g., `executable`, `shared_library`, `static_library`, `custom_target`).
    * Test definitions.
    * Dependency declarations.
    * And many others.

* These `KwargInfo` instances are often grouped into lists (e.g., `TEST_KWS`, `EXECUTABLE_KWS`, `SHARED_LIB_KWS`) based on the context where those arguments are used. This organization helps in applying the correct type checking rules to different parts of the build system.

**Relationship to Reverse Engineering:**

This file, while not directly performing reverse engineering, plays a crucial role in ensuring that Frida, a powerful dynamic instrumentation toolkit used extensively in reverse engineering, is built correctly. Here are some examples of how the type checking relates:

* **`link_with_KW` and `LINK_WHOLE_KW`:** These keyword arguments control how different libraries and build targets are linked together. In reverse engineering, you often need to link Frida with specific libraries (e.g., libraries containing hooking logic or communication protocols). Incorrectly specifying these arguments could lead to linking errors and a non-functional Frida build. For example, when building Frida for Android, you might need to link against specific system libraries, and this validation ensures those are specified correctly.

* **`RUST_CRATE_TYPE_KW` and `RUST_ABI_KW`:**  Frida uses Rust for some of its components. These keywords ensure that the Rust crates (libraries or executables) are built with the correct type (e.g., `dylib` for a dynamic library that can be loaded by Frida) and ABI (Application Binary Interface). Incorrect types would prevent Frida from loading or using these Rust components.

* **`win_subsystem` in `EXECUTABLE_KWS`:**  When building Frida for Windows, the `win_subsystem` argument determines whether the executable is a console application or a GUI application. This is crucial for the correct functioning of Frida tools on Windows.

* **`_DARWIN_VERSIONS_KW` in `SHARED_LIB_KWS`:** When building Frida for macOS or iOS, specifying the correct deployment target versions is critical for compatibility. This validation helps prevent building libraries that won't run on the intended target OS versions.

**Binary Bottom Layer, Linux, Android Kernel & Framework Knowledge:**

The type checking in this file reflects knowledge of the underlying systems and build processes:

* **Binary Formats and Linking:**  The validation of linking arguments (`link_with`, `link_whole`) and the distinction between static and shared libraries directly relates to how binaries are structured and linked at a low level.

* **Operating System Specifics:** Arguments like `win_subsystem` (Windows), `darwin_versions` (macOS/iOS), and the general handling of shared library versions (`soversion`, `version`) demonstrate an understanding of platform-specific binary conventions and linking mechanisms.

* **Compiler and Language Specifics:** The `LANGUAGE_KW` and the `_*_args` keyword arguments for different languages (C, C++, Rust, etc.) show awareness of how different compilers are invoked and the command-line arguments they accept.

* **Android Considerations (Implicit):** While not explicitly named "Android" in most arguments, the concepts of shared libraries, linking dependencies, and target architectures are fundamental to building Frida for Android. The build system as a whole (of which this file is a part) handles the specifics of cross-compiling for Android.

**Logical Reasoning (Hypothetical Input and Output):**

Let's take the `_output_validator` as an example:

**Hypothetical Input:** `outputs = ["my_output", "another_output", "my_output"]`

**Logical Reasoning:** The validator iterates through the `outputs` list, keeping track of seen outputs. It detects that "my_output" appears twice.

**Output:** The validator function would return the string: `"contains 'my_output' multiple times, but no duplicates are allowed."`

**Hypothetical Input:** `outputs = ["valid_name", "good.output"]`

**Logical Reasoning:** The validator checks each output name. Neither is empty, whitespace-only, nor contains path separators.

**Output:** The validator function would return `None`.

**User or Programming Common Usage Errors:**

This file helps prevent common errors users or developers might make when writing Frida build definitions:

* **Incorrect Data Types:**  Trying to pass a string to an argument that expects a list of files, or a boolean when an integer is required. The `KwargInfo` type definitions catch these errors.

* **Invalid Argument Values:** Providing a language that the build system doesn't know about, specifying an invalid shared library version format, or using incorrect syntax for environment variables. The validator functions catch these errors.

* **Missing Required Arguments:** Forcing users to provide mandatory arguments through the `required=True` setting in `KwargInfo`.

* **Typos in Argument Names:** While not directly handled by this file, the strict definitions make it easier for the build system to detect unrecognized keyword arguments.

**User Operation and Debugging Clues:**

A user might encounter the type checking defined in this file through various actions:

1. **Running `meson` to configure the Frida build:** Meson will process the build definitions (likely in `meson.build` files) and use the `KwargInfo` definitions and validators in this file to check the arguments passed to Frida's build functions.

2. **Running `ninja` to build Frida:** If the Meson configuration phase passed, the build process might still fail if there are inconsistencies in how build targets are defined, and these inconsistencies might stem from incorrect argument types that were not caught during configuration (though the goal is to catch them early).

**Debugging Clues:**

If a user encounters an error related to type checking, the error message will often originate from one of the validator functions in this file. For example:

* **"must be one of ..."**:  This likely comes from the `in_set_validator`.
* **"unknown languages: ..."**: This indicates an issue with the `_language_validator`.
* **"Output must not contain a path segment."**:  Points to the `_output_validator`.

**To trace how a user's action reaches this file:**

1. **Identify the Meson function being called:** Look at the error message or the build definition file (`meson.build`) to see which Frida build function (e.g., `executable()`, `shared_library()`, `custom_target()`) is being called with incorrect arguments.

2. **Find the corresponding `KwargInfo` definitions:** Search within `type_checking.py` for the `KwargInfo` instances associated with the arguments of that function.

3. **Examine the `validator` and `convertor`:**  Understand what checks and transformations are being applied to the arguments.

4. **Review the user's input:** Compare the user's provided arguments with the expected types and formats defined in the `KwargInfo` and enforced by the validators.

By understanding the structure and logic of `type_checking.py`, developers and advanced users can diagnose and fix issues related to argument validation in the Frida build system, ensuring that Frida is built correctly for its intended purpose in dynamic instrumentation and reverse engineering.

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/mesonbuild/interpreter/type_checking.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright © 2021 Intel Corporation

"""Helpers for strict type checking."""

from __future__ import annotations
import itertools, os, re
import typing as T

from .. import compilers
from ..build import (CustomTarget, BuildTarget,
                     CustomTargetIndex, ExtractedObjects, GeneratedList, IncludeDirs,
                     BothLibraries, SharedLibrary, StaticLibrary, Jar, Executable, StructuredSources)
from ..coredata import UserFeatureOption
from ..dependencies import Dependency, InternalDependency
from ..interpreterbase.decorators import KwargInfo, ContainerTypeInfo
from ..mesonlib import (File, FileMode, MachineChoice, listify, has_path_sep,
                        OptionKey, EnvironmentVariables)
from ..programs import ExternalProgram

# Helper definition for type checks that are `Optional[T]`
NoneType: T.Type[None] = type(None)

if T.TYPE_CHECKING:
    from typing_extensions import Literal

    from ..build import ObjectTypes
    from ..interpreterbase import TYPE_var
    from ..mesonlib import EnvInitValueType

    _FullEnvInitValueType = T.Union[EnvironmentVariables, T.List[str], T.List[T.List[str]], EnvInitValueType, str, None]
    PkgConfigDefineType = T.Optional[T.Tuple[T.Tuple[str, str], ...]]
    SourcesVarargsType = T.List[T.Union[str, File, CustomTarget, CustomTargetIndex, GeneratedList, StructuredSources, ExtractedObjects, BuildTarget]]


def in_set_validator(choices: T.Set[str]) -> T.Callable[[str], T.Optional[str]]:
    """Check that the choice given was one of the given set."""

    def inner(check: str) -> T.Optional[str]:
        if check not in choices:
            return f"must be one of {', '.join(sorted(choices))}, not {check}"
        return None

    return inner


def _language_validator(l: T.List[str]) -> T.Optional[str]:
    """Validate language keyword argument.

    Particularly for functions like `add_compiler()`, and `add_*_args()`
    """
    diff = {a.lower() for a in l}.difference(compilers.all_languages)
    if diff:
        return f'unknown languages: {", ".join(diff)}'
    return None


def _install_mode_validator(mode: T.List[T.Union[str, bool, int]]) -> T.Optional[str]:
    """Validate the `install_mode` keyword argument.

    This is a rather odd thing, it's a scalar, or an array of 3 values in the form:
    [(str | False), (str | int | False) = False, (str | int | False) = False]
    where the second and third components are not required and default to False.
    """
    if not mode:
        return None
    if True in mode:
        return 'components can only be permission strings, numbers, or False'
    if len(mode) > 3:
        return 'may have at most 3 elements'

    perms = mode[0]
    if not isinstance(perms, (str, bool)):
        return 'first component must be a permissions string or False'

    if isinstance(perms, str):
        if not len(perms) == 9:
            return ('permissions string must be exactly 9 characters in the form rwxr-xr-x,'
                    f' got {len(perms)}')
        for i in [0, 3, 6]:
            if perms[i] not in {'-', 'r'}:
                return f'permissions character {i+1} must be "-" or "r", not {perms[i]}'
        for i in [1, 4, 7]:
            if perms[i] not in {'-', 'w'}:
                return f'permissions character {i+1} must be "-" or "w", not {perms[i]}'
        for i in [2, 5]:
            if perms[i] not in {'-', 'x', 's', 'S'}:
                return f'permissions character {i+1} must be "-", "s", "S", or "x", not {perms[i]}'
        if perms[8] not in {'-', 'x', 't', 'T'}:
            return f'permission character 9 must be "-", "t", "T", or "x", not {perms[8]}'

        if len(mode) >= 2 and not isinstance(mode[1], (int, str, bool)):
            return 'second component can only be a string, number, or False'
        if len(mode) >= 3 and not isinstance(mode[2], (int, str, bool)):
            return 'third component can only be a string, number, or False'

    return None


def _install_mode_convertor(mode: T.Optional[T.List[T.Union[str, bool, int]]]) -> FileMode:
    """Convert the DSL form of the `install_mode` keyword argument to `FileMode`"""

    if not mode:
        return FileMode()

    # This has already been validated by the validator. False denotes "use
    # default". mypy is totally incapable of understanding it, because
    # generators clobber types via homogeneous return. But also we *must*
    # convert the first element different from the rest
    m1 = mode[0] if isinstance(mode[0], str) else None
    rest = (m if isinstance(m, (str, int)) else None for m in mode[1:])

    return FileMode(m1, *rest)


def _lower_strlist(input: T.List[str]) -> T.List[str]:
    """Lower a list of strings.

    mypy (but not pyright) gets confused about using a lambda as the convertor function
    """
    return [i.lower() for i in input]


def _validate_shlib_version(val: T.Optional[str]) -> T.Optional[str]:
    if val is not None and not re.fullmatch(r'[0-9]+(\.[0-9]+){0,2}', val):
        return (f'Invalid Shared library version "{val}". '
                'Must be of the form X.Y.Z where all three are numbers. Y and Z are optional.')
    return None


def variables_validator(contents: T.Union[str, T.List[str], T.Dict[str, str]]) -> T.Optional[str]:
    if isinstance(contents, str):
        contents = [contents]
    if isinstance(contents, dict):
        variables = contents
    else:
        variables = {}
        for v in contents:
            try:
                key, val = v.split('=', 1)
            except ValueError:
                return f'variable {v!r} must have a value separated by equals sign.'
            variables[key.strip()] = val.strip()
    for k, v in variables.items():
        if not k:
            return 'empty variable name'
        if any(c.isspace() for c in k):
            return f'invalid whitespace in variable name {k!r}'
    return None


def variables_convertor(contents: T.Union[str, T.List[str], T.Dict[str, str]]) -> T.Dict[str, str]:
    if isinstance(contents, str):
        contents = [contents]
    if isinstance(contents, dict):
        return contents
    variables = {}
    for v in contents:
        key, val = v.split('=', 1)
        variables[key.strip()] = val.strip()
    return variables


NATIVE_KW = KwargInfo(
    'native', bool,
    default=False,
    convertor=lambda n: MachineChoice.BUILD if n else MachineChoice.HOST)

LANGUAGE_KW = KwargInfo(
    'language', ContainerTypeInfo(list, str, allow_empty=False),
    listify=True,
    required=True,
    validator=_language_validator,
    convertor=_lower_strlist)

INSTALL_MODE_KW: KwargInfo[T.List[T.Union[str, bool, int]]] = KwargInfo(
    'install_mode',
    ContainerTypeInfo(list, (str, bool, int)),
    listify=True,
    default=[],
    validator=_install_mode_validator,
    convertor=_install_mode_convertor,
)

REQUIRED_KW: KwargInfo[T.Union[bool, UserFeatureOption]] = KwargInfo(
    'required',
    (bool, UserFeatureOption),
    default=True,
    # TODO: extract_required_kwarg could be converted to a convertor
)

DISABLER_KW: KwargInfo[bool] = KwargInfo('disabler', bool, default=False)

def _env_validator(value: T.Union[EnvironmentVariables, T.List['TYPE_var'], T.Dict[str, 'TYPE_var'], str, None],
                   only_dict_str: bool = True) -> T.Optional[str]:
    def _splitter(v: str) -> T.Optional[str]:
        split = v.split('=', 1)
        if len(split) == 1:
            return f'"{v}" is not two string values separated by an "="'
        return None

    if isinstance(value, str):
        v = _splitter(value)
        if v is not None:
            return v
    elif isinstance(value, list):
        for i in listify(value):
            if not isinstance(i, str):
                return f"All array elements must be a string, not {i!r}"
            v = _splitter(i)
            if v is not None:
                return v
    elif isinstance(value, dict):
        # We don't need to spilt here, just do the type checking
        for k, dv in value.items():
            if only_dict_str:
                if any(i for i in listify(dv) if not isinstance(i, str)):
                    return f"Dictionary element {k} must be a string or list of strings not {dv!r}"
            elif isinstance(dv, list):
                if any(not isinstance(i, str) for i in dv):
                    return f"Dictionary element {k} must be a string, bool, integer or list of strings, not {dv!r}"
            elif not isinstance(dv, (str, bool, int)):
                return f"Dictionary element {k} must be a string, bool, integer or list of strings, not {dv!r}"
    # We know that otherwise we have an EnvironmentVariables object or None, and
    # we're okay at this point
    return None

def _options_validator(value: T.Union[EnvironmentVariables, T.List['TYPE_var'], T.Dict[str, 'TYPE_var'], str, None]) -> T.Optional[str]:
    # Reusing the env validator is a little overkill, but nicer than duplicating the code
    return _env_validator(value, only_dict_str=False)

def split_equal_string(input: str) -> T.Tuple[str, str]:
    """Split a string in the form `x=y`

    This assumes that the string has already been validated to split properly.
    """
    a, b = input.split('=', 1)
    return (a, b)

# Split _env_convertor() and env_convertor_with_method() to make mypy happy.
# It does not want extra arguments in KwargInfo convertor callable.
def env_convertor_with_method(value: _FullEnvInitValueType,
                              init_method: Literal['set', 'prepend', 'append'] = 'set',
                              separator: str = os.pathsep) -> EnvironmentVariables:
    if isinstance(value, str):
        return EnvironmentVariables(dict([split_equal_string(value)]), init_method, separator)
    elif isinstance(value, list):
        return EnvironmentVariables(dict(split_equal_string(v) for v in listify(value)), init_method, separator)
    elif isinstance(value, dict):
        return EnvironmentVariables(value, init_method, separator)
    elif value is None:
        return EnvironmentVariables()
    return value

def _env_convertor(value: _FullEnvInitValueType) -> EnvironmentVariables:
    return env_convertor_with_method(value)

ENV_KW: KwargInfo[T.Union[EnvironmentVariables, T.List, T.Dict, str, None]] = KwargInfo(
    'env',
    (EnvironmentVariables, list, dict, str, NoneType),
    validator=_env_validator,
    convertor=_env_convertor,
)

DEPFILE_KW: KwargInfo[T.Optional[str]] = KwargInfo(
    'depfile',
    (str, type(None)),
    validator=lambda x: 'Depfile must be a plain filename with a subdirectory' if has_path_sep(x) else None
)

# TODO: CustomTargetIndex should be supported here as well
DEPENDS_KW: KwargInfo[T.List[T.Union[BuildTarget, CustomTarget]]] = KwargInfo(
    'depends',
    ContainerTypeInfo(list, (BuildTarget, CustomTarget)),
    listify=True,
    default=[],
)

DEPEND_FILES_KW: KwargInfo[T.List[T.Union[str, File]]] = KwargInfo(
    'depend_files',
    ContainerTypeInfo(list, (File, str)),
    listify=True,
    default=[],
)

COMMAND_KW: KwargInfo[T.List[T.Union[str, BuildTarget, CustomTarget, CustomTargetIndex, ExternalProgram, File]]] = KwargInfo(
    'command',
    # TODO: should accept CustomTargetIndex as well?
    ContainerTypeInfo(list, (str, BuildTarget, CustomTarget, CustomTargetIndex, ExternalProgram, File), allow_empty=False),
    required=True,
    listify=True,
    default=[],
)

def _override_options_convertor(raw: T.Union[str, T.List[str], T.Dict[str, T.Union[str, int, bool, T.List[str]]]]) -> T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]]:
    if isinstance(raw, str):
        raw = [raw]
    if isinstance(raw, list):
        output: T.Dict[OptionKey, T.Union[str, int, bool, T.List[str]]] = {}
        for each in raw:
            k, v = split_equal_string(each)
            output[OptionKey.from_string(k)] = v
        return output
    return {OptionKey.from_string(k): v for k, v in raw.items()}


OVERRIDE_OPTIONS_KW: KwargInfo[T.Union[str, T.Dict[str, T.Union[str, int, bool, T.List[str]]], T.List[str]]] = KwargInfo(
    'override_options',
    (str, ContainerTypeInfo(list, str), ContainerTypeInfo(dict, (str, int, bool, list))),
    default={},
    validator=_options_validator,
    convertor=_override_options_convertor,
    since_values={dict: '1.2.0'},
)


def _output_validator(outputs: T.List[str]) -> T.Optional[str]:
    output_set = set(outputs)
    if len(output_set) != len(outputs):
        seen = set()
        for el in outputs:
            if el in seen:
                return f"contains {el!r} multiple times, but no duplicates are allowed."
            seen.add(el)
    for i in outputs:
        if i == '':
            return 'Output must not be empty.'
        elif i.strip() == '':
            return 'Output must not consist only of whitespace.'
        elif has_path_sep(i):
            return f'Output {i!r} must not contain a path segment.'
        elif '@INPUT' in i:
            return f'output {i!r} contains "@INPUT", which is invalid. Did you mean "@PLAINNAME@" or "@BASENAME@?'

    return None

MULTI_OUTPUT_KW: KwargInfo[T.List[str]] = KwargInfo(
    'output',
    ContainerTypeInfo(list, str, allow_empty=False),
    listify=True,
    required=True,
    default=[],
    validator=_output_validator,
)

OUTPUT_KW: KwargInfo[str] = KwargInfo(
    'output',
    str,
    required=True,
    validator=lambda x: _output_validator([x])
)

CT_INPUT_KW: KwargInfo[T.List[T.Union[str, File, ExternalProgram, BuildTarget, CustomTarget, CustomTargetIndex, ExtractedObjects, GeneratedList]]] = KwargInfo(
    'input',
    ContainerTypeInfo(list, (str, File, ExternalProgram, BuildTarget, CustomTarget, CustomTargetIndex, ExtractedObjects, GeneratedList)),
    listify=True,
    default=[],
)

CT_INSTALL_TAG_KW: KwargInfo[T.List[T.Union[str, bool]]] = KwargInfo(
    'install_tag',
    ContainerTypeInfo(list, (str, bool)),
    listify=True,
    default=[],
    since='0.60.0',
    convertor=lambda x: [y if isinstance(y, str) else None for y in x],
)

INSTALL_TAG_KW: KwargInfo[T.Optional[str]] = KwargInfo('install_tag', (str, NoneType))

INSTALL_FOLLOW_SYMLINKS: KwargInfo[T.Optional[bool]] = KwargInfo(
    'follow_symlinks',
    (bool, NoneType),
    since='1.3.0',
)

INSTALL_KW = KwargInfo('install', bool, default=False)

CT_INSTALL_DIR_KW: KwargInfo[T.List[T.Union[str, Literal[False]]]] = KwargInfo(
    'install_dir',
    ContainerTypeInfo(list, (str, bool)),
    listify=True,
    default=[],
    validator=lambda x: 'must be `false` if boolean' if True in x else None,
)

CT_BUILD_BY_DEFAULT: KwargInfo[T.Optional[bool]] = KwargInfo('build_by_default', (bool, type(None)), since='0.40.0')

CT_BUILD_ALWAYS: KwargInfo[T.Optional[bool]] = KwargInfo(
    'build_always', (bool, NoneType),
    deprecated='0.47.0',
    deprecated_message='combine build_by_default and build_always_stale instead.',
)

CT_BUILD_ALWAYS_STALE: KwargInfo[T.Optional[bool]] = KwargInfo(
    'build_always_stale', (bool, NoneType),
    since='0.47.0',
)

INSTALL_DIR_KW: KwargInfo[T.Optional[str]] = KwargInfo('install_dir', (str, NoneType))

INCLUDE_DIRECTORIES: KwargInfo[T.List[T.Union[str, IncludeDirs]]] = KwargInfo(
    'include_directories',
    ContainerTypeInfo(list, (str, IncludeDirs)),
    listify=True,
    default=[],
)

DEFAULT_OPTIONS = OVERRIDE_OPTIONS_KW.evolve(name='default_options')

ENV_METHOD_KW = KwargInfo('method', str, default='set', since='0.62.0',
                          validator=in_set_validator({'set', 'prepend', 'append'}))

ENV_SEPARATOR_KW = KwargInfo('separator', str, default=os.pathsep)

DEPENDENCIES_KW: KwargInfo[T.List[Dependency]] = KwargInfo(
    'dependencies',
    # InternalDependency is a subclass of Dependency, but we want to
    # print it in error messages
    ContainerTypeInfo(list, (Dependency, InternalDependency)),
    listify=True,
    default=[],
)

D_MODULE_VERSIONS_KW: KwargInfo[T.List[T.Union[str, int]]] = KwargInfo(
    'd_module_versions',
    ContainerTypeInfo(list, (str, int)),
    listify=True,
    default=[],
)

_link_with_error = '''can only be self-built targets, external dependencies (including libraries) must go in "dependencies".'''

# Allow Dependency for the better error message? But then in other cases it will list this as one of the allowed types!
LINK_WITH_KW: KwargInfo[T.List[T.Union[BothLibraries, SharedLibrary, StaticLibrary, CustomTarget, CustomTargetIndex, Jar, Executable]]] = KwargInfo(
    'link_with',
    ContainerTypeInfo(list, (BothLibraries, SharedLibrary, StaticLibrary, CustomTarget, CustomTargetIndex, Jar, Executable, Dependency)),
    listify=True,
    default=[],
    validator=lambda x: _link_with_error if any(isinstance(i, Dependency) for i in x) else None,
)

def link_whole_validator(values: T.List[T.Union[StaticLibrary, CustomTarget, CustomTargetIndex, Dependency]]) -> T.Optional[str]:
    for l in values:
        if isinstance(l, (CustomTarget, CustomTargetIndex)) and l.links_dynamically():
            return f'{type(l).__name__} returning a shared library is not allowed'
        if isinstance(l, Dependency):
            return _link_with_error
    return None

LINK_WHOLE_KW: KwargInfo[T.List[T.Union[BothLibraries, StaticLibrary, CustomTarget, CustomTargetIndex]]] = KwargInfo(
    'link_whole',
    ContainerTypeInfo(list, (BothLibraries, StaticLibrary, CustomTarget, CustomTargetIndex, Dependency)),
    listify=True,
    default=[],
    validator=link_whole_validator,
)

DEPENDENCY_SOURCES_KW: KwargInfo[T.List[T.Union[str, File, CustomTarget, CustomTargetIndex, GeneratedList]]] = KwargInfo(
    'sources',
    ContainerTypeInfo(list, (str, File, CustomTarget, CustomTargetIndex, GeneratedList)),
    listify=True,
    default=[],
)

SOURCES_VARARGS = (str, File, CustomTarget, CustomTargetIndex, GeneratedList, StructuredSources, ExtractedObjects, BuildTarget)

BT_SOURCES_KW: KwargInfo[SourcesVarargsType] = KwargInfo(
    'sources',
    (NoneType, ContainerTypeInfo(list, SOURCES_VARARGS)),
    listify=True,
    default=[],
)

VARIABLES_KW: KwargInfo[T.Dict[str, str]] = KwargInfo(
    'variables',
    # str is listified by validator/convertor, cannot use listify=True here because
    # that would listify dict too.
    (str, ContainerTypeInfo(list, str), ContainerTypeInfo(dict, str)), # type: ignore
    validator=variables_validator,
    convertor=variables_convertor,
    default={},
)

PRESERVE_PATH_KW: KwargInfo[bool] = KwargInfo('preserve_path', bool, default=False, since='0.63.0')

TEST_KWS: T.List[KwargInfo] = [
    KwargInfo('args', ContainerTypeInfo(list, (str, File, BuildTarget, CustomTarget, CustomTargetIndex)),
              listify=True, default=[]),
    KwargInfo('should_fail', bool, default=False),
    KwargInfo('timeout', int, default=30),
    KwargInfo('workdir', (str, NoneType), default=None,
              validator=lambda x: 'must be an absolute path' if not os.path.isabs(x) else None),
    KwargInfo('protocol', str,
              default='exitcode',
              validator=in_set_validator({'exitcode', 'tap', 'gtest', 'rust'}),
              since_values={'gtest': '0.55.0', 'rust': '0.57.0'}),
    KwargInfo('priority', int, default=0, since='0.52.0'),
    # TODO: env needs reworks of the way the environment variable holder itself works probably
    ENV_KW,
    DEPENDS_KW.evolve(since='0.46.0'),
    KwargInfo('suite', ContainerTypeInfo(list, str), listify=True, default=['']),  # yes, a list of empty string
    KwargInfo('verbose', bool, default=False, since='0.62.0'),
]

# Cannot have a default value because we need to check that rust_crate_type and
# rust_abi are mutually exclusive.
RUST_CRATE_TYPE_KW: KwargInfo[T.Union[str, None]] = KwargInfo(
    'rust_crate_type', (str, NoneType),
    since='0.42.0',
    since_values={'proc-macro': '0.62.0'},
    deprecated='1.3.0',
    deprecated_message='Use rust_abi or rust.proc_macro() instead.',
    validator=in_set_validator({'bin', 'lib', 'rlib', 'dylib', 'cdylib', 'staticlib', 'proc-macro'}))

RUST_ABI_KW: KwargInfo[T.Union[str, None]] = KwargInfo(
    'rust_abi', (str, NoneType),
    since='1.3.0',
    validator=in_set_validator({'rust', 'c'}))

_VS_MODULE_DEFS_KW: KwargInfo[T.Optional[T.Union[str, File, CustomTarget, CustomTargetIndex]]] = KwargInfo(
    'vs_module_defs',
    (str, File, CustomTarget, CustomTargetIndex, NoneType),
    since_values={CustomTargetIndex: '1.3.0'}
)

_BASE_LANG_KW: KwargInfo[T.List[str]] = KwargInfo(
    'UNKNOWN',
    ContainerTypeInfo(list, (str)),
    listify=True,
    default=[],
)

_LANGUAGE_KWS: T.List[KwargInfo[T.List[str]]] = [
    _BASE_LANG_KW.evolve(name=f'{lang}_args')
    for lang in compilers.all_languages - {'rust', 'vala', 'java'}
]
# Cannot use _BASE_LANG_KW here because Vala is special for types
_LANGUAGE_KWS.append(KwargInfo(
    'vala_args', ContainerTypeInfo(list, (str, File)), listify=True, default=[]))
_LANGUAGE_KWS.append(_BASE_LANG_KW.evolve(name='rust_args', since='0.41.0'))

# We need this deprecated values more than the non-deprecated values. So we'll evolve them out elsewhere.
_JAVA_LANG_KW: KwargInfo[T.List[str]] = _BASE_LANG_KW.evolve(
    name='java_args',
    deprecated='1.3.0',
    deprecated_message='This does not, and never has, done anything. It should be removed'
)

def _objects_validator(vals: T.List[ObjectTypes]) -> T.Optional[str]:
    non_objects: T.List[str] = []

    for val in vals:
        if isinstance(val, (str, File, ExtractedObjects)):
            continue
        else:
            non_objects.extend(o for o in val.get_outputs() if not compilers.is_object(o))

    if non_objects:
        return f'{", ".join(non_objects)!r} are not objects'

    return None


# Applies to all build_target like classes
_ALL_TARGET_KWS: T.List[KwargInfo] = [
    OVERRIDE_OPTIONS_KW,
    KwargInfo('build_by_default', bool, default=True, since='0.38.0'),
    KwargInfo('extra_files', ContainerTypeInfo(list, (str, File)), default=[], listify=True),
    # Accursed. We allow this for backwards compat and warn in the interpreter.
    KwargInfo('install', object, default=False),
    INSTALL_MODE_KW,
    KwargInfo('implicit_include_directories', bool, default=True, since='0.42.0'),
    NATIVE_KW,
    KwargInfo('resources', ContainerTypeInfo(list, str), default=[], listify=True),
    KwargInfo(
        'objects',
        ContainerTypeInfo(list, (str, File, CustomTarget, CustomTargetIndex, GeneratedList, ExtractedObjects)),
        listify=True,
        default=[],
        validator=_objects_validator,
        since_values={
            ContainerTypeInfo(list, (GeneratedList, CustomTarget, CustomTargetIndex)):
                ('1.1.0', 'generated sources as positional "objects" arguments')
        },
    ),
]


def _name_validator(arg: T.Optional[T.Union[str, T.List]]) -> T.Optional[str]:
    if isinstance(arg, list) and arg:
        return 'must be empty when passed as an array to signify the default value.'
    return None


def _name_suffix_validator(arg: T.Optional[T.Union[str, T.List]]) -> T.Optional[str]:
    if arg == '':
        return 'must not be a empty string. An empty array may be passed if you want Meson to use the default behavior.'
    return _name_validator(arg)


_NAME_PREFIX_KW: KwargInfo[T.Optional[T.Union[str, T.List]]] = KwargInfo(
    'name_prefix',
    (str, NoneType, list),
    validator=_name_validator,
    convertor=lambda x: None if isinstance(x, list) else x,
)


# Applies to all build_target classes except jar
_BUILD_TARGET_KWS: T.List[KwargInfo] = [
    *_ALL_TARGET_KWS,
    *_LANGUAGE_KWS,
    BT_SOURCES_KW,
    INCLUDE_DIRECTORIES.evolve(name='d_import_dirs'),
    _NAME_PREFIX_KW,
    _NAME_PREFIX_KW.evolve(name='name_suffix', validator=_name_suffix_validator),
    RUST_CRATE_TYPE_KW,
    KwargInfo('d_debug', ContainerTypeInfo(list, (str, int)), default=[], listify=True),
    D_MODULE_VERSIONS_KW,
    KwargInfo('d_unittest', bool, default=False),
    KwargInfo(
        'rust_dependency_map',
        ContainerTypeInfo(dict, str),
        default={},
        since='1.2.0',
    ),
    KwargInfo('build_rpath', str, default='', since='0.42.0'),
    KwargInfo(
        'gnu_symbol_visibility',
        str,
        default='',
        validator=in_set_validator({'', 'default', 'internal', 'hidden', 'protected', 'inlineshidden'}),
        since='0.48.0',
    ),
    KwargInfo('install_rpath', str, default=''),
    KwargInfo(
        'link_depends',
        ContainerTypeInfo(list, (str, File, CustomTarget, CustomTargetIndex, BuildTarget)),
        default=[],
        listify=True,
    ),
    KwargInfo(
        'link_language',
        (str, NoneType),
        validator=in_set_validator(set(compilers.all_languages)),
        since='0.51.0',
    ),
]

def _validate_win_subsystem(value: T.Optional[str]) -> T.Optional[str]:
    if value is not None:
        if re.fullmatch(r'(boot_application|console|efi_application|efi_boot_service_driver|efi_rom|efi_runtime_driver|native|posix|windows)(,\d+(\.\d+)?)?', value) is None:
            return f'Invalid value for win_subsystem: {value}.'
    return None


def _validate_darwin_versions(darwin_versions: T.List[T.Union[str, int]]) -> T.Optional[str]:
    if len(darwin_versions) > 2:
        return f"Must contain between 0 and 2 elements, not {len(darwin_versions)}"
    if len(darwin_versions) == 1:
        darwin_versions = 2 * darwin_versions
    for v in darwin_versions:
        if isinstance(v, int):
            v = str(v)
        if not re.fullmatch(r'[0-9]+(\.[0-9]+){0,2}', v):
            return 'must be X.Y.Z where X, Y, Z are numbers, and Y and Z are optional'
        try:
            parts = v.split('.')
        except ValueError:
            return f'badly formed value: "{v}, not in X.Y.Z form'
        if len(parts) in {1, 2, 3} and int(parts[0]) > 65535:
            return 'must be X.Y.Z where X is [0, 65535] and Y, Z are optional'
        if len(parts) in {2, 3} and int(parts[1]) > 255:
            return 'must be X.Y.Z where Y is [0, 255] and Y, Z are optional'
        if len(parts) == 3 and int(parts[2]) > 255:
            return 'must be X.Y.Z where Z is [0, 255] and Y, Z are optional'
    return None


def _convert_darwin_versions(val: T.List[T.Union[str, int]]) -> T.Optional[T.Tuple[str, str]]:
    if not val:
        return None
    elif len(val) == 1:
        v = str(val[0])
        return (v, v)
    return (str(val[0]), str(val[1]))


_DARWIN_VERSIONS_KW: KwargInfo[T.List[T.Union[str, int]]] = KwargInfo(
    'darwin_versions',
    ContainerTypeInfo(list, (str, int)),
    default=[],
    listify=True,
    validator=_validate_darwin_versions,
    convertor=_convert_darwin_versions,
    since='0.48.0',
)

# Arguments exclusive to Executable. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_EXECUTABLE_KWS: T.List[KwargInfo] = [
    KwargInfo('export_dynamic', (bool, NoneType), since='0.45.0'),
    KwargInfo('gui_app', (bool, NoneType), deprecated='0.56.0', deprecated_message="Use 'win_subsystem' instead"),
    KwargInfo('implib', (bool, str, NoneType), since='0.42.0'),
    KwargInfo('pie', (bool, NoneType)),
    KwargInfo(
        'win_subsystem',
        (str, NoneType),
        convertor=lambda x: x.lower() if isinstance(x, str) else None,
        validator=_validate_win_subsystem,
    ),
]

# The total list of arguments used by Executable
EXECUTABLE_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_EXECUTABLE_KWS,
    _VS_MODULE_DEFS_KW.evolve(since='1.3.0', since_values=None),
    _JAVA_LANG_KW,
]

# Arguments exclusive to library types
_EXCLUSIVE_LIB_KWS: T.List[KwargInfo] = [
    RUST_ABI_KW,
]

# Arguments exclusive to StaticLibrary. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_STATIC_LIB_KWS: T.List[KwargInfo] = [
    KwargInfo('prelink', bool, default=False, since='0.57.0'),
    KwargInfo('pic', (bool, NoneType), since='0.36.0'),
]

# The total list of arguments used by StaticLibrary
STATIC_LIB_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_STATIC_LIB_KWS,
    *_EXCLUSIVE_LIB_KWS,
    _JAVA_LANG_KW,
]

# Arguments exclusive to SharedLibrary. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_SHARED_LIB_KWS: T.List[KwargInfo] = [
    _DARWIN_VERSIONS_KW,
    KwargInfo('soversion', (str, int, NoneType), convertor=lambda x: str(x) if x is not None else None),
    KwargInfo('version', (str, NoneType), validator=_validate_shlib_version),
]

# The total list of arguments used by SharedLibrary
SHARED_LIB_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_SHARED_LIB_KWS,
    *_EXCLUSIVE_LIB_KWS,
    _VS_MODULE_DEFS_KW,
    _JAVA_LANG_KW,
]

# Arguments exclusive to SharedModule. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_SHARED_MOD_KWS: T.List[KwargInfo] = []

# The total list of arguments used by SharedModule
SHARED_MOD_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_SHARED_MOD_KWS,
    *_EXCLUSIVE_LIB_KWS,
    _VS_MODULE_DEFS_KW,
    _JAVA_LANG_KW,
]

# Arguments exclusive to JAR. These are separated to make integrating
# them into build_target easier
_EXCLUSIVE_JAR_KWS: T.List[KwargInfo] = [
    KwargInfo('main_class', str, default=''),
    KwargInfo('java_resources', (StructuredSources, NoneType), since='0.62.0'),
    _JAVA_LANG_KW.evolve(deprecated=None, deprecated_message=None),
]

# The total list of arguments used by JAR
JAR_KWS = [
    *_ALL_TARGET_KWS,
    *_EXCLUSIVE_JAR_KWS,
    KwargInfo(
        'sources',
        ContainerTypeInfo(list, (str, File, CustomTarget, CustomTargetIndex, GeneratedList, ExtractedObjects, BuildTarget)),
        listify=True,
        default=[],
    ),
    *[a.evolve(deprecated='1.3.0', deprecated_message='This argument has never done anything in jar(), and should be removed')
      for a in _LANGUAGE_KWS],
]

_SHARED_STATIC_ARGS: T.List[KwargInfo[T.List[str]]] = [
    *[l.evolve(name=l.name.replace('_', '_static_'), since='1.3.0')
      for l in _LANGUAGE_KWS],
    *[l.evolve(name=l.name.replace('_', '_shared_'), since='1.3.0')
      for l in _LANGUAGE_KWS],
]

# Arguments used by both_library and library
LIBRARY_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_LIB_KWS,
    *_EXCLUSIVE_SHARED_LIB_KWS,
    *_EXCLUSIVE_SHARED_MOD_KWS,
    *_EXCLUSIVE_STATIC_LIB_KWS,
    *_SHARED_STATIC_ARGS,
    _VS_MODULE_DEFS_KW,
    _JAVA_LANG_KW,
]

# Arguments used by build_Target
BUILD_TARGET_KWS = [
    *_BUILD_TARGET_KWS,
    *_EXCLUSIVE_SHARED_LIB_KWS,
    *_EXCLUSIVE_SHARED_MOD_KWS,
    *_EXCLUSIVE_STATIC_LIB_KWS,
    *_EXCLUSIVE_EXECUTABLE_KWS,
    *_SHARED_STATIC_ARGS,
    *[a.evolve(deprecated='1.3.0', deprecated_message='The use of "jar" in "build_target()" is deprecated, and this argument is only used by jar()')
      for a in _EXCLUSIVE_JAR_KWS],
    KwargInfo(
        'target_type',
        str,
        required=True,
        validator=in_set_validator({
            'executable', 'shared_library', 'static_library', 'shared_module',
            'both_libraries', 'library', 'jar'
        }),
        since_values={
            'shared_module': '0.51.0',
        },
        deprecated_values={
            'jar': ('1.3.0', 'use the "jar()" function directly'),
        }
    )
]

def _pkgconfig_define_convertor(x: T.List[str]) -> PkgConfigDefineType:
    if x:
        keys = itertools.islice(x, 0, None, 2)
        vals = itertools.islice(x, 1, None, 2)
        return tuple(zip(keys, vals))
    return None

PKGCONFIG_DEFINE_KW: KwargInfo = KwargInfo(
    'pkgconfig_define',
    ContainerTypeInfo(list, str, pairs=True),
    default=[],
    convertor=_pkgconfig_define_convertor,
)

"""

```