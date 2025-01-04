Response:
My thought process for analyzing the `type_checking.py` file goes like this:

1. **Understand the Goal:** The filename and the initial comment clearly state the purpose: "Helpers for strict type checking." This immediately tells me the file isn't about implementing core functionality of Frida, but rather ensuring the *correct usage* of its build system, Meson.

2. **Identify Key Concepts:** I skim the imports to get a high-level understanding of what types are being checked. I see imports related to:
    * **Meson Build System (`mesonbuild`)**:  `CustomTarget`, `BuildTarget`, `SharedLibrary`, etc. These are the fundamental building blocks Meson uses.
    * **Compilers (`compilers`)**: This suggests the type checking will involve verifying language-specific configurations.
    * **Dependencies (`dependencies`)**:  Indicates type checks for external libraries and components.
    * **Data Structures (`typing`, `itertools`)**:  Used for defining and manipulating type information.
    * **OS/File System (`os`)**:  Likely used for path manipulation and environment variable handling.
    * **Regular Expressions (`re`)**: Used for validating string formats (like library versions).

3. **Analyze Core Functionalities (Functions):** I go through the defined functions, paying attention to their names, arguments, and return types:
    * **Validators (`in_set_validator`, `_language_validator`, `_install_mode_validator`, etc.)**: These functions take an input and return `None` if it's valid or an error string if it's invalid. This is a standard validation pattern.
    * **Convertors (`_install_mode_convertor`, `_lower_strlist`, `variables_convertor`, `env_convertor_with_method`, `_override_options_convertor`, `_pkgconfig_define_convertor`, etc.)**: These functions take an input and transform it into a desired type. This is important for converting user-provided data into Meson's internal representation.
    * **Helper Functions (`split_equal_string`)**: Utility functions for specific data transformations.

4. **Analyze Key Concepts (KwargInfo):** The frequent use of `KwargInfo` stands out. I recognize this as a way to define and manage keyword arguments for Meson's build functions. Each `KwargInfo` instance holds information about:
    * **Name**: The keyword argument name.
    * **Type**: The expected data type.
    * **Default Value**: A default value if the argument is not provided.
    * **Validator**: A function to check the validity of the input.
    * **Convertor**: A function to transform the input into the desired type.
    * **Other Metadata**:  `required`, `since`, `deprecated`, etc., for managing argument behavior across Meson versions.

5. **Identify Relationships to Reverse Engineering, Binaries, Kernels, Frameworks:** I specifically look for connections to the prompt's keywords.
    * **Reverse Engineering:** The file itself doesn't *perform* reverse engineering. However, it *supports* the Frida project, which is a dynamic instrumentation toolkit heavily used in reverse engineering. The type checks ensure that Frida's build system is used correctly.
    * **Binary/Low-Level:** The presence of arguments related to linking (`link_with`, `link_whole`), shared library versions (`soversion`, `version`), and executable subsystems (`win_subsystem`) directly touches on binary and low-level aspects of software development.
    * **Linux/Android Kernel/Framework:** While the file doesn't directly interact with kernels, it supports the building of software that *can* interact with them. The presence of platform-specific options (like Darwin versions) and the general nature of Frida as an instrumentation tool hint at this indirect connection.

6. **Look for Logic and Examples:** The validators and convertors implement logical checks and transformations. I imagine example inputs and how the validators would react (e.g., an invalid language string, a malformed version string). The `KwargInfo` definitions provide implicit input/output examples through their type information and default values.

7. **Consider User Errors:** I think about common mistakes users might make when writing Meson build files. This includes:
    * Providing arguments of the wrong type.
    * Using incorrect string formats (e.g., for versions or environment variables).
    * Providing conflicting arguments.
    * Using arguments that are deprecated or only available in specific Meson versions.

8. **Trace User Operations:** I consider how a user might end up triggering this code. The path `frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/type_checking.py` suggests this file is part of the Meson interpreter used by the Frida Swift bindings. A user would interact with this by:
    * Writing a `meson.build` file for their Frida Swift project.
    * Running `meson` to configure the build. This is where the interpreter, including this type-checking module, would be executed to validate the `meson.build` file.

9. **Structure the Answer:**  Finally, I organize my findings into a clear and structured answer, addressing each part of the prompt. I start with a general summary, then go into specific functionalities, providing examples and linking them back to reverse engineering, low-level aspects, user errors, and the user workflow.

By following these steps, I can effectively analyze the provided Python code and understand its role within the larger Frida project and its connection to the concepts mentioned in the prompt.
This Python file, `type_checking.py`, plays a crucial role in the Frida dynamic instrumentation tool's build system, which is based on Meson. Its primary function is to enforce **strict type checking** for the arguments passed to various Meson build functions. This ensures that the build system is configured correctly and avoids common errors.

Here's a breakdown of its functionalities:

**1. Defining and Validating Keyword Arguments for Meson Build Functions:**

   - The file extensively uses the `KwargInfo` class to define the expected type, default value, validation rules, and conversion logic for keyword arguments used in Meson's build definitions (like `executable`, `shared_library`, `custom_target`, etc.).
   - **Functionality:** It acts as a schema or specification for the allowed keyword arguments and their types for various Meson functions.
   - **Examples:**
     - `LANGUAGE_KW = KwargInfo('language', ContainerTypeInfo(list, str, allow_empty=False), listify=True, required=True, validator=_language_validator, convertor=_lower_strlist)` defines that the `language` keyword argument should be a non-empty list of strings, validates the language names using `_language_validator`, and converts them to lowercase using `_lower_strlist`.
     - `OUTPUT_KW = KwargInfo('output', str, required=True, validator=lambda x: _output_validator([x]))` defines that the `output` keyword argument should be a string and validates it using `_output_validator`.

**2. Implementing Custom Validators and Convertors:**

   - The file defines numerous validator functions (e.g., `in_set_validator`, `_language_validator`, `_install_mode_validator`, `_output_validator`) that check if the provided argument values conform to specific rules.
   - It also defines convertor functions (e.g., `_install_mode_convertor`, `_lower_strlist`, `variables_convertor`, `_override_options_convertor`) that transform the input values into the desired format for Meson.
   - **Functionality:** These functions ensure data integrity and consistency within the build system.
   - **Examples:**
     - `in_set_validator({'set', 'prepend', 'append'})` creates a validator that ensures a string argument is one of the allowed values: "set", "prepend", or "append".
     - `_install_mode_convertor` takes a list representing file permissions and converts it into a `FileMode` object.

**3. Defining Type Information for Complex Argument Types:**

   - The `ContainerTypeInfo` class is used to specify the type of elements within lists or dictionaries used as arguments.
   - **Functionality:**  This provides more granular type checking for collections.
   - **Example:** `ContainerTypeInfo(list, str, allow_empty=False)` specifies that a keyword argument should be a list containing strings and cannot be empty.

**4. Handling Environment Variables:**

   - Functions like `_env_validator` and `env_convertor_with_method` are used to validate and convert environment variable settings passed as arguments.
   - **Functionality:** Allows setting and manipulating environment variables during the build process.

**5. Supporting Different Types of Build Targets:**

   - The file defines sets of `KwargInfo` for various Meson build target types (e.g., `EXECUTABLE_KWS`, `SHARED_LIB_KWS`, `STATIC_LIB_KWS`, `JAR_KWS`, `BUILD_TARGET_KWS`).
   - **Functionality:**  Ensures that each build target type receives the correct and valid arguments.

**6. Handling Dependencies and Linking:**

   - `DEPENDENCIES_KW`, `LINK_WITH_KW`, and `LINK_WHOLE_KW` define and validate arguments related to project dependencies and linking libraries.
   - **Functionality:** Ensures that dependencies are correctly specified and that linking is performed with valid target types.

**7. Supporting Testing:**

   - `TEST_KWS` defines the keyword arguments for Meson's `test` function.
   - **Functionality:** Allows specifying test arguments, timeouts, protocols, and other test-related settings.

**8. Managing Platform-Specific Options:**

   - Arguments like `_DARWIN_VERSIONS_KW` and the handling of Windows subsystems (`_validate_win_subsystem`) demonstrate the support for platform-specific build configurations.

**Relationship to Reverse Engineering:**

This file directly supports the building of Frida, a powerful dynamic instrumentation toolkit used extensively in reverse engineering. By ensuring the correct configuration of the build system, it helps developers and users create and deploy Frida components effectively.

**Examples of Reverse Engineering Relevance:**

- **Building Frida Gadget for Android/iOS:** When building the Frida gadget (a shared library injected into target processes), the `SHARED_LIB_KWS` would be relevant. This includes options for setting the library version (`version`, `soversion`), and platform-specific settings like Darwin versions for iOS. The type checking ensures that these options are provided in the correct format, preventing build errors.
- **Creating Custom Tools with Frida's Python Bindings:**  While this file is about building the core Frida components, the principle of type checking is also important when developing tools that interact with Frida's Python bindings. Incorrect argument types passed to Frida's API could lead to runtime errors.

**Involvement of Binary Bottom, Linux, Android Kernel, and Framework Knowledge:**

- **Binary Bottom:** The file deals with concepts directly related to binary files:
    - **Linking:**  `LINK_WITH_KW`, `LINK_WHOLE_KW` ensure that the correct types of binary artifacts (shared libraries, static libraries, executables) are linked together.
    - **Library Versions:** `_validate_shlib_version` validates the format of shared library version strings, which are crucial for binary compatibility.
    - **Executable Subsystems:** `_validate_win_subsystem` validates the Windows subsystem for executables, affecting how the operating system loads and runs the binary.
- **Linux/Android Kernel and Framework:**
    - **Shared Libraries:**  Building Frida often involves creating shared libraries that are loaded into processes on Linux or Android. The options for shared libraries are directly relevant to how these libraries are handled by the operating system's dynamic linker.
    - **Platform-Specific Options:** The presence of `_DARWIN_VERSIONS_KW` indicates awareness of macOS/iOS specifics. Similarly, the general structure of the build system would need to accommodate Android-specific build requirements if Frida is being built for Android.
    - **Instrumentation Context:** While this file doesn't directly interact with the kernel, the entire purpose of Frida is to instrument processes at runtime, which fundamentally relies on understanding operating system concepts and process memory management.

**Logical Reasoning with Assumptions and Outputs:**

Let's consider the `_language_validator` function:

**Assumption:** A user provides a list of strings for the `language` keyword argument in a Meson build file.

**Input:** `l = ["C", "Cpp", "java"]`

**Logic:**
1. The function converts the input list to lowercase: `{"c", "cpp", "java"}`.
2. It compares this set with the set of all known languages in `compilers.all_languages`.
3. If all elements in the input set are present in the known languages set, the function returns `None` (indicating validity).

**Output (assuming "java" is a valid language in `compilers.all_languages`):** `None`

**Input (example of an invalid input):** `l = ["Python", "C++"]`

**Logic:**
1. The function converts the input list to lowercase: `{"python", "c++"}`.
2. It finds the difference between this set and the set of known languages. Let's assume "python" is not a recognized compiler language in this context.
3. The function returns a string indicating the unknown languages.

**Output:** `"unknown languages: python"`

**User and Programming Errors:**

- **Incorrect Type:** A common error is providing an argument of the wrong type. For example, providing an integer for the `output` keyword, which expects a string. The type checking would catch this immediately.
  - **Example:** In `meson.build`: `executable('my_program', sources : 'main.c', output : 123)` would be flagged as an error because `output` expects a string.
- **Invalid String Format:** Providing a string that doesn't match the expected format.
  - **Example:**  Providing an invalid shared library version: `shared_library('my_lib', 'lib.c', version : '1.0')` (missing the minor version). The `_validate_shlib_version` would catch this.
- **Using Deprecated Arguments:**  The `KwargInfo` includes metadata for deprecation. If a user uses a deprecated argument, the type checking system can issue a warning or error.
  - **Example:** Using the `gui_app` argument for executables (deprecated in favor of `win_subsystem`).
- **Providing Conflicting Arguments:**  In some cases, certain arguments might be mutually exclusive or have dependencies. While this file primarily focuses on type checking, some validators might also catch simple conflicts.

**User Operation Steps to Reach This File (as a Debugging Clue):**

1. **User Writes a `meson.build` File:** The user creates a `meson.build` file to define the build process for their Frida component (e.g., a Swift binding extension).
2. **User Runs `meson setup builddir`:** The user executes the `meson` command to configure the build in a specified build directory.
3. **Meson Interpreter Starts:** The `meson` command launches the Meson interpreter, which parses the `meson.build` file.
4. **Meson Interprets Build Definitions:** When the interpreter encounters functions like `executable()`, `shared_library()`, or `custom_target()`, it needs to process the provided keyword arguments.
5. **Type Checking is Invoked:** For each keyword argument, Meson uses the `KwargInfo` definitions and associated validators and convertors defined in `type_checking.py` to verify the argument's type and format.
6. **Error Reporting (if any):** If a type mismatch or validation error is found, the interpreter will raise an error message, indicating the problematic argument and the reason for the error. This helps the user debug their `meson.build` file.

Therefore, this `type_checking.py` file acts as a gatekeeper, ensuring the integrity and correctness of the build configuration for Frida and its components, which is crucial for a complex project like a dynamic instrumentation toolkit.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/mesonbuild/interpreter/type_checking.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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