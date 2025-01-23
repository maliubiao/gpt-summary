Response:
Let's break down the thought process to analyze the provided Python code snippet.

**1. Initial Understanding: The Purpose of the File**

The first lines of the code itself are crucial:

```python
"""
# SPDX-License-Identifier: Apache-2.0
# Copyright © 2021 Intel Corporation

"""Helpers for strict type checking."""
```

This immediately tells us the core function: `type checking`. It's a helper module within a larger system (Frida/Meson). The "strict" implies a desire for robust and error-free configurations.

**2. Identifying Key Components: Imports and Definitions**

Next, I'd scan the import statements and top-level definitions:

* **Imports:** `itertools`, `os`, `re`, `typing`, and specific imports from `..`. This suggests interaction with:
    * Iteration and data manipulation (`itertools`).
    * Operating system functionalities (`os`).
    * Regular expressions for pattern matching (`re`).
    * Static type hinting (`typing`).
    * Internal Meson build system components (`..`).

* **`NoneType`:** A helpful alias for the `type(None)`.

* **Conditional Typing (`if T.TYPE_CHECKING`):**  This signals that the code uses type hints for static analysis but these hints won't affect runtime behavior. It lists various types related to Meson's build system.

* **Functions with `_validator` suffix:** These functions likely enforce constraints on input values. The names provide hints about what they validate (e.g., `in_set_validator`, `_language_validator`, `_install_mode_validator`).

* **Functions with `_convertor` suffix:** These functions likely transform input values into a desired format (e.g., `_install_mode_convertor`, `variables_convertor`).

* **`KwargInfo` objects:** This is a central concept. These objects appear to define the expected types, validation rules, and conversion logic for keyword arguments in Meson build definitions. The naming convention (e.g., `NATIVE_KW`, `LANGUAGE_KW`) is also informative.

* **Lists of `KwargInfo` (e.g., `TEST_KWS`, `EXECUTABLE_KWS`):** These likely represent the allowed keyword arguments for specific Meson functions or build targets.

**3. Analyzing Function Functionality (Examples):**

I'd pick a few representative functions to understand their logic in detail:

* **`in_set_validator`:**  Simple, takes a set of allowed strings and returns a validator that checks if an input string is within that set. This is a common pattern for enforcing choices.

* **`_language_validator`:** Checks if the provided language list contains valid compiler languages. This connects to Meson's ability to handle different programming languages.

* **`_install_mode_validator` and `_install_mode_convertor`:** These handle the complex `install_mode` argument, which involves file permissions. The validator enforces the syntax, and the converter transforms it into a `FileMode` object. This relates to how files are installed on the target system.

* **`variables_validator` and `variables_convertor`:** These handle environment variables, checking the format and converting them into a dictionary. This ties into how build processes can be configured with environment settings.

**4. Identifying Connections to Reverse Engineering, Binaries, Kernels, etc.:**

Now, I'd specifically look for clues connecting the code to the topics mentioned in the prompt:

* **Reverse Engineering:** The functions dealing with shared libraries (`_validate_shlib_version`), symbol visibility (`gnu_symbol_visibility`), and link dependencies (`LINK_WITH_KW`, `LINK_WHOLE_KW`) are relevant. These concepts are important when analyzing and manipulating compiled binaries.

* **Binary/Low-Level:**  `install_mode` directly deals with file permissions, which is a low-level OS concept. The handling of shared library versions and symbol visibility is also close to the binary level.

* **Linux/Android Kernels/Frameworks:** While not explicitly referencing kernel code, the concepts of shared libraries, executables, and installation directories are fundamental in both Linux and Android. The `win_subsystem` argument suggests cross-platform considerations, but the core functionality aligns with typical OS build processes.

**5. Logical Reasoning and Examples:**

For logical reasoning, I'd pick a validator and converter and imagine input/output:

* **`in_set_validator({'a', 'b'})`:**
    * Input: `"a"` -> Output: `None` (valid)
    * Input: `"c"` -> Output: `"must be one of a, b, not c"` (invalid)

* **`_install_mode_convertor(['rwxr-xr-x', 'user', 755])`:**
    * Output:  A `FileMode` object representing the given permissions and ownership.

**6. Common User Errors:**

I'd think about how users might misuse the Meson build system and how this code helps prevent those errors:

* Providing an invalid language in `language`.
* Incorrectly formatting the `install_mode`.
* Having duplicate output names.
* Providing invalid characters in environment variable names.

**7. Tracing User Actions (Debugging Clues):**

I'd imagine a user defining a Meson build file (`meson.build`) and calling functions like `executable()`, `shared_library()`, or `custom_target()`. The keyword arguments they provide to these functions would be processed by the `KwargInfo` objects and their associated validators and converters in this `type_checking.py` file. If validation fails, Meson would likely report an error message based on the output of the validator functions.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** Maybe this file directly interacts with the compiler.
* **Correction:**  The imports suggest it's more about *validating the build configuration* before the compiler is invoked.

* **Initial thought:** The examples need to be very technical and low-level.
* **Refinement:** While some aspects are low-level, focusing on the *user-facing* errors and the purpose of validation makes the explanation more accessible.

By following this structured approach, I could systematically analyze the code and address all the points raised in the prompt. The key is to combine reading the code with understanding the context of Frida and Meson.
This Python code file, `type_checking.py`, located within the Frida dynamic instrumentation tool's build system (Meson), plays a crucial role in ensuring the correctness and consistency of build definitions. It defines helpers and structures for performing strict type checking on the keyword arguments passed to various Meson build functions.

Here's a breakdown of its functionalities:

**1. Defining and Validating Keyword Arguments:**

* **`KwargInfo` Class:** This is a central class used to define the expected type, default value, validation rules, and conversion logic for keyword arguments used in Meson's build functions (like `executable`, `shared_library`, `custom_target`, etc.).
* **Specific `KwargInfo` Instances:** The file defines numerous instances of `KwargInfo` for various keyword arguments, such as:
    * `NATIVE_KW`:  For the `native` argument (boolean indicating native vs. host architecture).
    * `LANGUAGE_KW`: For the `language` argument (list of programming languages).
    * `INSTALL_MODE_KW`: For the `install_mode` argument (specifying file permissions during installation).
    * `SOURCES_VARARGS`: For the `sources` argument (files or targets used as input).
    * `DEPENDENCIES_KW`: For the `dependencies` argument (other build targets or external libraries).
    * Many more, covering a wide range of build configuration options.
* **Validators (`*_validator` functions):** The code includes functions like `in_set_validator`, `_language_validator`, `_install_mode_validator`, `variables_validator`, `_output_validator`, etc. These functions are associated with `KwargInfo` instances and are responsible for checking if the provided argument value conforms to the expected type and constraints. For example, `in_set_validator` checks if a string is one of the allowed choices, and `_language_validator` verifies that the specified languages are valid.
* **Converters (`*_convertor` functions):** Functions like `_install_mode_convertor`, `variables_convertor`, `_pkgconfig_define_convertor` are used to transform the input argument value into a desired format. For instance, `_install_mode_convertor` converts the user-provided `install_mode` representation into a `FileMode` object.

**2. Enforcing Data Types and Constraints:**

The primary function of this file is to enforce strict type checking. This helps prevent common errors in build definitions, leading to more robust and predictable builds. By defining the expected types for keyword arguments, Meson can catch type mismatches early on. The validators add an extra layer of constraint checking, ensuring that the values are not only of the correct type but also satisfy specific rules (e.g., valid language names, correct file permission string format).

**3. Relationship to Reverse Engineering:**

This file has indirect but important relationships to reverse engineering, primarily through the build process of Frida itself:

* **Building Frida:** Frida is a reverse engineering tool. This `type_checking.py` file is part of the mechanism used to build Frida. Ensuring a correct build is the first step in having a functional reverse engineering tool. For example, if the shared library build step (using arguments validated here) is misconfigured, Frida might not function correctly.
* **Targeting Specific Architectures:** The `NATIVE_KW` and related logic touch on cross-compilation, which is relevant when reverse engineering targets with different architectures (e.g., analyzing an ARM Android app on an x86 machine). The type checking ensures that the correct build settings are applied for the target architecture.
* **Library Dependencies:**  Reverse engineering often involves understanding how libraries are linked and used. The validation of `DEPENDENCIES_KW` and `LINK_WITH_KW` ensures that Frida's own dependencies are correctly specified during its build process. While this file doesn't directly reverse engineer anything, it ensures the integrity of the tool used for that purpose.
* **Shared Libraries and Versions:** The `_validate_shlib_version` function is directly related to how shared libraries are built and versioned. This is a fundamental concept in reverse engineering, as understanding library versions and compatibility is often crucial. If Frida needs to load or interact with other libraries, the correct build settings (validated here) become important.

**Example of Relationship to Reverse Engineering:**

Imagine a Frida developer wants to add a new feature that requires linking against a specific version of a library. They would modify Frida's build files (likely using Meson). When specifying the dependency, they might use a function like `declare_dependency()` and provide the library information as keyword arguments. The `type_checking.py` file would validate the provided library name, version, and other relevant details. If the developer mistypes the library name or provides an incorrect version format, the validators in this file would catch the error, preventing a potentially broken build of Frida.

**4. Relationship to Binary Underlying, Linux, Android Kernel & Framework:**

* **File Permissions (`INSTALL_MODE_KW`):** The validation and conversion of `install_mode` directly relate to file system permissions, a fundamental concept in Linux and Android. The code checks for valid permission string formats (e.g., "rwxr-xr-x").
* **Shared Libraries and Executables:** The type checking for building shared libraries (`SHARED_LIB_KWS`) and executables (`EXECUTABLE_KWS`) is directly tied to how these binary formats are handled on Linux and Android. Arguments like `soversion`, `version`, `implib`, and `win_subsystem` (though targeting Windows) are relevant to the properties of these binary files.
* **Environment Variables (`ENV_KW`):**  The validation and conversion of environment variables are important for setting up the build environment, which can influence how binaries are linked and executed on Linux and Android.
* **Target Types:** The validation of `target_type` in `BUILD_TARGET_KWS` ensures that the correct type of binary (executable, shared library, etc.) is being built, which is essential for understanding how the resulting code will be loaded and executed on the target OS.
* **Darwin Versions (`_DARWIN_VERSIONS_KW`):** While not directly Linux or Android, the handling of Darwin (macOS/iOS) versions demonstrates the build system's awareness of platform-specific binary requirements.

**Example of Relationship to Binary Underlying/Linux/Android:**

When building Frida for an Android target, the build process needs to create shared library files (`.so`). The `SHARED_LIB_KWS` defines and validates the keyword arguments used for this process. Arguments like `soversion` (shared object version) are crucial for library management on Linux and Android. If a developer incorrectly specifies the `soversion`, the validator `_validate_shlib_version` will flag the error, preventing the creation of a potentially misconfigured shared library that might cause issues when Frida is loaded on an Android device.

**5. Logical Reasoning (Hypothetical Input and Output):**

**Assumption:** A user is defining a custom build target using the `custom_target()` function in Meson.

**Hypothetical Input:**

```python
custom_target(
    'my_script',
    input = 'input.txt',
    output = 'output.log',
    command = ['python', 'my_script.py', '@INPUT@', '@OUTPUT@'],
    install = True,
    install_dir = '/opt/my_app/logs',
    install_mode = ['rwxr--r--']
)
```

**Processing by `type_checking.py`:**

* **`CT_INPUT_KW` validation:** Checks if `'input.txt'` is a valid input type (string, File, etc.).
* **`OUTPUT_KW` validation:** Checks if `'output.log'` is a valid output name (no path separators).
* **`COMMAND_KW` validation:** Verifies that the `command` is a list and contains valid elements (strings, build targets, etc.).
* **`INSTALL_KW` validation:** Checks if `install` is a boolean.
* **`CT_INSTALL_DIR_KW` validation:** Checks if `/opt/my_app/logs` is a valid installation directory.
* **`INSTALL_MODE_KW` validation:** The `_install_mode_validator` would be called on `['rwxr--r--']`.
    * **Input to `_install_mode_validator`:** `['rwxr--r--']`
    * **Output of `_install_mode_validator`:** `None` (since "rwxr--r--" is a valid permission string)
* **`INSTALL_MODE_KW` conversion:** The `_install_mode_convertor` would be called.
    * **Input to `_install_mode_convertor`:** `['rwxr--r--']`
    * **Output of `_install_mode_convertor`:** A `FileMode` object representing the permissions `rwxr--r--`.

**6. User or Programming Common Usage Errors:**

* **Incorrect Type for `sources`:**  User provides an integer instead of a list of strings or File objects.
    * **Example:** `executable('my_program', sources=123)`
    * **Error Caught:**  The `BT_SOURCES_KW` would expect a list or None, and the type checker would flag an error.
* **Invalid Language Name:** User provides an unsupported language in the `language` argument.
    * **Example:** `executable('my_program', sources='main.c', language=['cobol'])`
    * **Error Caught:** The `_language_validator` would be called and return an error message because "cobol" is not in the list of known languages.
* **Malformed `install_mode`:** User provides an incorrect format for the install mode string.
    * **Example:** `install_mode = ['rwxr-xr']` (missing a character)
    * **Error Caught:** The `_install_mode_validator` would detect that the string length is not 9 and return an error message.
* **Duplicate Output Names:** User specifies the same output name multiple times in a `custom_target`.
    * **Example:** `custom_target('my_target', output=['a.txt', 'a.txt'], ...)`
    * **Error Caught:** The `_output_validator` would identify the duplicate and return an error message.
* **Invalid Character in Environment Variable Name:** User tries to set an environment variable with a space in its name.
    * **Example:** `env = {'MY VARIABLE': 'value'}`
    * **Error Caught:** The `variables_validator` would identify the space and return an error message.

**7. User Operation Steps to Reach This Code (Debugging Clues):**

1. **User Creates or Modifies a `meson.build` file:** This file describes the build process using Meson's domain-specific language.
2. **User Executes `meson setup builddir`:** This command interprets the `meson.build` file and configures the build.
3. **Meson Parses the `meson.build` file:** During parsing, Meson encounters function calls like `executable()`, `shared_library()`, `custom_target()`, etc.
4. **Keyword Arguments are Passed:** The user-provided arguments (e.g., `sources`, `language`, `install_mode`) are passed as keyword arguments to these functions.
5. **Argument Validation:** Before these functions proceed with the build logic, the Meson interpreter uses the `KwargInfo` definitions and associated validators in `type_checking.py` to validate the types and values of these keyword arguments.
6. **Error Reporting (if any):** If any validation fails (e.g., an incorrect type, an invalid value), the validator function returns an error message, which Meson then reports to the user, halting the configuration process and providing information about the error.

**In Summary:**

`type_checking.py` is a foundational part of Frida's build system, powered by Meson. It ensures the correctness and consistency of build definitions by rigorously validating the keyword arguments used in Meson's build functions. This plays a vital role in preventing common errors, leading to more reliable and predictable builds of Frida, the dynamic instrumentation tool used for reverse engineering and security analysis. While it doesn't directly perform reverse engineering, its correct functioning is essential for building the tools that do.

### 提示词
```
这是目录为frida/releng/meson/mesonbuild/interpreter/type_checking.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```