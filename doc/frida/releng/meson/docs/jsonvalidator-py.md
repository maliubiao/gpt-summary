Response:
Let's break down the thought process for analyzing the Python script and generating the response.

**1. Understanding the Goal:**

The core request is to analyze a Python script, understand its purpose, and connect it to the context of Frida, reverse engineering, low-level details, and potential user errors. The prompt also asks about the steps to reach this script, indicating a debugging/investigation context.

**2. Initial Code Scan (High-Level):**

I first skimmed the code, identifying key elements:

* **Imports:** `argparse`, `json`, `pathlib`, `copy`, `typing`. This immediately suggests command-line arguments, JSON handling, file system operations, and type hinting.
* **Function Definitions:**  `assert_has_typed_keys`, `validate_base_obj`, `validate_type`, `validate_arg`, `validate_function`, `validate_object`, `main`. The names of these functions are quite descriptive and suggest a validation process for different types of data structures.
* **Global Variable:** `root`. This hints at a central data structure being validated.
* **`main()` function:**  Parses command-line arguments, reads a JSON file, and calls the validation functions.

**3. Identifying the Core Functionality:**

The repeated use of `assert` statements, the function names like `validate_...`, and the handling of a JSON file strongly indicate that the script is a **validator for JSON documents**. Specifically, it seems to be validating the structure and types of data within a JSON file.

**4. Connecting to the Frida Context:**

The prompt explicitly mentions Frida and reverse engineering. The filename `jsonvalidator.py` within a directory structure containing `frida`, `releng`, `meson`, and `docs` gives context. Meson is a build system. This suggests that the JSON file being validated likely describes some aspect of Frida's API or functionality, used for documentation generation or other build-related processes. This connection is crucial for answering the "reverse engineering" aspect.

**5. Deeper Dive into Validation Functions:**

I then looked at the individual validation functions:

* **`assert_has_typed_keys`:** Checks if a dictionary has the expected keys and if the values associated with those keys are of the expected types. This is the fundamental building block of the validation process.
* **`validate_base_obj`:** Validates common fields like `name`, `description`, `since`, etc., likely present in all top-level objects within the JSON.
* **`validate_type`:**  Validates the structure of type information, including references to other objects.
* **`validate_arg`:** Validates function arguments, including their types, whether they are required, and default values.
* **`validate_function`:** Validates functions, including their return types, arguments, and optional details.
* **`validate_object`:** Validates objects, including their methods, inheritance, and type.

**6. Identifying Connections to Reverse Engineering, Low-Level, and Kernel:**

The validation functions and the context of Frida hinted at these connections:

* **Reverse Engineering:** Frida is a dynamic instrumentation toolkit used for reverse engineering. The JSON likely describes the API that Frida exposes to interact with target processes. Validating this API definition ensures consistency and correctness.
* **Binary/Low-Level:** Frida interacts with processes at a low level. The JSON might describe data structures or function signatures that mirror underlying binary structures or system calls.
* **Linux/Android Kernel/Framework:** Frida is often used on Linux and Android. The API described in the JSON might expose ways to interact with kernel functionalities or Android framework components.

**7. Constructing Examples and Scenarios:**

Based on the understanding of the validation logic, I started formulating examples:

* **Logic/Inference:** The `validate_type` function recursively validates nested types. I created a simple nested type example to illustrate this.
* **User/Programming Errors:** I considered common mistakes when creating or modifying the JSON documentation, such as missing required fields, incorrect types, or extra keys.

**8. Tracing User Operations (Debugging Context):**

To address the "how to reach here" question, I thought about the likely development workflow:

1. Someone modifies the Frida codebase, potentially adding new features or changing existing ones.
2. This might involve updating the documentation of the Frida API.
3. The documentation is likely stored in a structured format, like JSON.
4. A build or testing process would use this script to validate the JSON documentation before publishing or incorporating it.
5. A developer encountering a validation error would then need to look at this script to understand why their changes caused the validation to fail.

**9. Structuring the Response:**

Finally, I organized the findings into the categories requested by the prompt:

* **Functionality:** A concise summary of the script's purpose.
* **Relationship to Reverse Engineering:**  Explaining how validating the Frida API definition is relevant to reverse engineering.
* **Connections to Low-Level/Kernel/Framework:**  Providing examples of how the validated JSON relates to these aspects.
* **Logic/Inference Examples:** Demonstrating the recursive type validation.
* **User/Programming Errors:**  Illustrating common mistakes.
* **User Operations as Debugging Clues:**  Outlining the typical steps that lead to encountering this script in a debugging scenario.

**Self-Correction/Refinement:**

During this process, I might have initially focused too much on the individual `assert` statements. I then realized the bigger picture was about validating the structure of a documentation file. I also made sure to explicitly connect the validation steps to the *meaning* of the data being validated within the Frida context, not just describing the code's mechanics. I also tried to make the examples as concrete and easy to understand as possible.
`jsonvalidator.py` 是一个用于验证 Frida 动态插桩工具的 JSON 格式文档的 Python 脚本。这个脚本的主要目的是确保 JSON 文档的结构和数据类型符合预定义的模式，从而保证文档的质量和一致性。

**以下是它的功能列表：**

1. **读取 JSON 文档：** 脚本接收一个 JSON 文件路径作为命令行参数，并读取该文件的内容。
2. **基本结构验证：** 验证 JSON 根对象是否包含预期的键，例如 `version_major`, `version_minor`, `meson_version`, `functions`, `objects`, 和 `objects_by_type`，并且这些键对应的值是否为预期的类型 (例如，整数、字符串、字典)。
3. **类型检查：** 脚本使用 `isinstance` 函数来严格检查 JSON 对象中各个字段的数据类型。例如，确保 `name` 和 `description` 字段是字符串，`notes` 和 `warnings` 字段是列表。
4. **键值存在性验证：**  使用 `assert set(data.keys()).issuperset(keys.keys())` 来确保 JSON 对象包含所有必需的键。
5. **对象和函数验证：** 脚本定义了 `validate_object` 和 `validate_function` 函数，用于递归地验证 JSON 文档中描述的对象和函数的结构。这包括：
    * **基本属性验证：** 验证 `name`, `description`, `since`, `deprecated`, `notes`, `warnings` 等通用属性的存在和类型。
    * **参数验证：** 验证函数的参数 (`posargs`, `optargs`, `kwargs`, `varargs`) 的类型、是否必需、默认值等。
    * **返回值验证：** 验证函数的返回值类型。
    * **对象属性验证：** 验证对象的 `object_type`（例如，`ELEMENTARY`, `BUILTIN`, `MODULE`, `RETURNED`）、继承关系 (`extends`)、包含的方法 (`methods`) 等。
6. **类型引用验证：** 验证类型定义 (`holds`) 中引用的对象是否存在于根对象的 `objects` 字段中。
7. **对象类型一致性验证：** 验证 `objects_by_type` 中列出的对象类型与 `objects` 中定义的 `object_type` 是否一致。
8. **模块定义验证：** 验证模块中定义的对象是否正确地关联到对应的模块。

**与逆向方法的关联及举例说明：**

该脚本本身不直接执行逆向操作，但它验证的 JSON 文档很可能描述了 Frida 的 API。Frida 作为动态插桩工具，其核心功能是通过 API 与目标进程进行交互。这些 API 允许逆向工程师：

* **读取和修改内存：**  JSON 文档可能会描述用于读取和写入目标进程内存的函数，例如 `Memory.readByteArray()`, `Memory.writeByteArray()` 等。文档会定义这些函数的参数（目标地址、大小）和返回值（读取的字节数组）。
* **调用函数：** JSON 文档可能定义了可以远程调用目标进程中函数的 API，例如 `NativeFunction()`, `Interceptor.attach()`。文档会详细说明需要提供的参数类型、返回值类型等。
* **Hook 函数：**  JSON 文档会描述用于 Hook (拦截) 目标进程函数的 API，例如 `Interceptor.attach()`。文档会定义参数，例如要 Hook 的函数地址、回调函数等。
* **枚举模块和导出函数：** JSON 文档可能描述用于枚举目标进程加载的模块和导出函数的 API，例如 `Process.enumerateModules()`, `Module.enumerateExports()`。文档会定义返回值类型，例如模块对象的列表或导出函数对象的列表。

**举例说明：**

假设 JSON 文档中描述了 `Memory.readByteArray()` 函数如下：

```json
{
  "name": "Memory.readByteArray",
  "description": "Reads bytes from memory.",
  "since": "9.0",
  "returns": [
    {
      "obj": "ByteArray",
      "holds": []
    }
  ],
  "returns_str": "ByteArray",
  "posargs": {
    "address": {
      "name": "address",
      "description": "The memory address to read from.",
      "type": [
        {
          "obj": "NativePointer",
          "holds": []
        }
      ],
      "type_str": "NativePointer",
      "required": true
    },
    "length": {
      "name": "length",
      "description": "The number of bytes to read.",
      "type": [
        {
          "obj": "Number",
          "holds": []
        }
      ],
      "type_str": "Number",
      "required": true
    }
  },
  "optargs": {},
  "kwargs": {},
  "varargs": null,
  "arg_flattening": false
}
```

`jsonvalidator.py` 会验证：

* `name` 是字符串 "Memory.readByteArray"。
* `description` 是字符串。
* `returns` 是一个包含一个元素的列表。
* `returns[0]['obj']` 是字符串 "ByteArray"。
* `posargs` 是一个字典，包含 "address" 和 "length" 两个键。
* `posargs['address']['type'][0]['obj']` 是字符串 "NativePointer"。
* `posargs['length']['type'][0]['obj']` 是字符串 "Number"。
* 所有其他的类型信息和约束也符合预期。

通过验证这样的文档，可以确保 Frida 的使用者能够准确地理解和使用这些用于逆向工程的 API。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

Frida 作为一个动态插桩工具，其 API 往往会涉及到与操作系统底层交互的概念。JSON 文档中对这些 API 的描述也会反映这些知识：

* **二进制底层：**
    * **内存地址 (NativePointer):**  API 参数中常见的 `NativePointer` 类型直接对应于进程的虚拟内存地址。验证其类型确保用户传递的参数是表示内存地址的正确类型。
    * **字节数组 (ByteArray):** 用于表示从内存中读取的数据或要写入内存的数据。JSON 文档中会定义 API 如何处理这些字节数组。
    * **函数地址：**  在 Hook 函数或调用函数时，需要提供目标函数的内存地址。JSON 文档会描述这些参数的类型。

* **Linux/Android 内核及框架：**
    * **系统调用：** Frida 的某些 API 可能会封装底层的系统调用。例如，用于内存操作的 API 最终可能会调用 `mmap`, `read`, `write` 等系统调用。虽然 JSON 文档不直接描述系统调用，但其描述的 API 功能与这些底层机制紧密相关。
    * **进程和线程：**  Frida 允许操作目标进程的线程。JSON 文档可能会描述与进程和线程相关的 API，例如枚举线程、获取线程上下文等。
    * **Android Framework：** 在 Android 平台上，Frida 可以 Hook Java 层和 Native 层的函数。JSON 文档可能会描述与 Android Framework 组件（例如，`Activity`, `Service`）交互的 API。

**举例说明：**

假设 JSON 文档中描述了用于获取当前线程 ID 的 API：

```json
{
  "name": "Process.getCurrentThreadId",
  "description": "Gets the ID of the current thread.",
  "since": "10.0",
  "returns": [
    {
      "obj": "Number",
      "holds": []
    }
  ],
  "returns_str": "Number",
  "posargs": {},
  "optargs": {},
  "kwargs": {},
  "varargs": null,
  "arg_flattening": false
}
```

这个 API 涉及到操作系统底层的线程概念。在 Linux 或 Android 上，线程 ID 是操作系统内核维护的一个标识符。`jsonvalidator.py` 确保 `returns` 的类型是 `Number`，这与线程 ID 的类型一致。

**逻辑推理、假设输入与输出：**

脚本主要进行的是结构和类型验证，逻辑推理体现在对嵌套结构和类型引用的处理上。

**假设输入：** 一个包含嵌套类型定义的 JSON 片段。

```json
{
  "objects": {
    "NativePointer": {
      "name": "NativePointer",
      "description": "Represents a native pointer.",
      "object_type": "BUILTIN",
      "methods": {}
    },
    "ByteArray": {
      "name": "ByteArray",
      "description": "Represents a byte array.",
      "object_type": "BUILTIN",
      "methods": {}
    }
  },
  "functions": {
    "Memory.readBytes": {
      "name": "Memory.readBytes",
      "description": "Reads bytes from memory.",
      "returns": [
        {
          "obj": "ByteArray",
          "holds": []
        }
      ],
      "returns_str": "ByteArray",
      "posargs": {
        "address": {
          "name": "address",
          "description": "The memory address to read from.",
          "type": [
            {
              "obj": "NativePointer",
              "holds": []
            }
          ],
          "type_str": "NativePointer",
          "required": true
        }
      }
    }
  }
}
```

**`validate_function` 函数在处理 `Memory.readBytes` 时的逻辑推理：**

1. 检查 `returns` 字段是一个列表，并且非空。
2. 遍历 `returns` 列表，对每个元素调用 `validate_type`。
3. 在 `validate_type` 中，检查 `obj` 的值 "ByteArray" 是否存在于 `root['objects']` 中。
4. 检查 `posargs` 字段是一个字典，并且非空。
5. 遍历 `posargs` 字典，对每个参数调用 `validate_arg`。
6. 在 `validate_arg` 中，检查 `type` 字段是一个列表，并且非空。
7. 遍历 `type` 列表，对每个类型定义调用 `validate_type`。
8. 在对 "address" 参数的类型进行 `validate_type` 时，检查 `obj` 的值 "NativePointer" 是否存在于 `root['objects']` 中。

**预期输出：** 如果 JSON 结构正确，类型定义有效，则脚本执行成功，返回 0。如果存在任何验证错误，脚本会抛出 `AssertionError` 异常，并指出错误的位置和类型。例如，如果 `objects` 中没有定义 "ByteArray" 对象，则会抛出类似以下的错误：

```
root.functions.Memory.readBytes: 'ByteArray'
```

**涉及用户或者编程常见的使用错误及举例说明：**

用户或开发者在编写或修改 Frida 的 JSON 文档时，可能会犯以下错误，而此脚本可以帮助检测这些错误：

1. **缺少必需的字段：** 例如，在定义一个函数时，忘记添加 `description` 字段。

   **错误示例：**
   ```json
   {
     "name": "MyFunction",
     "returns": [...]
   }
   ```
   **`jsonvalidator.py` 报错：** `root.MyFunction: DIFF: {'description'}`

2. **字段类型错误：** 例如，将一个应该为字符串的字段设置为数字。

   **错误示例：**
   ```json
   {
     "name": "MyObject",
     "description": 123,
     "object_type": "ELEMENTARY"
   }
   ```
   **`jsonvalidator.py` 报错：** `root.MyObject: type(description: 123) != <class 'str'>`

3. **类型引用错误：** 在 `returns` 或参数的 `type` 中引用了不存在的对象类型。

   **错误示例：**
   ```json
   {
     "name": "AnotherFunction",
     "returns": [
       {
         "obj": "NonExistentType",
         "holds": []
       }
     ]
   }
   ```
   **`jsonvalidator.py` 报错：** `root.AnotherFunction: 'NonExistentType'`

4. **`objects_by_type` 中的信息不一致：** 例如，将一个 `object_type` 为 "MODULE" 的对象错误地添加到 `elementary` 列表中。

   **错误示例：**
   ```json
   {
     "objects_by_type": {
       "elementary": ["MyModule"],
       "builtins": [],
       "returned": [],
       "modules": {}
     },
     "objects": {
       "MyModule": {
         "name": "MyModule",
         "description": "...",
         "object_type": "MODULE",
         "methods": {}
       }
     }
   }
   ```
   **`jsonvalidator.py` 报错：** `root.objects.MyModule: MyModule` (因为 `MyModule` 的 `object_type` 是 `MODULE`，不应该出现在 `elementary` 列表中)

5. **额外的、未预期的字段：**  虽然不一定会导致程序错误，但可能表明文档结构存在偏差。

   **错误示例：**
   ```json
   {
     "name": "MyFunction",
     "description": "...",
     "returns": [],
     "extra_field": "This should not be here"
   }
   ```
   **`jsonvalidator.py` 报错：** `root.MyFunction has extra keys: {'extra_field'}`

**说明用户操作是如何一步步的到达这里，作为调试线索：**

假设一个 Frida 的开发者正在添加或修改 Frida 的 API，并需要更新相应的 JSON 文档。以下是可能的操作步骤，最终导致需要运行 `jsonvalidator.py` 进行验证：

1. **修改 Frida 源代码：** 开发者在 C++, JavaScript 或 Python 代码中实现了新的 API 功能或修改了现有功能。
2. **更新 JSON 文档：** 开发者需要修改或创建位于 `frida/releng/meson/docs/` 目录下的 JSON 文档，以反映代码的更改。这可能涉及到添加新的函数定义、修改现有函数的参数或返回值类型、添加新的对象类型等。
3. **构建 Frida：** 开发者使用 Meson 构建系统编译 Frida。构建过程中可能包含一个步骤，用于验证 JSON 文档的有效性。
4. **运行 `jsonvalidator.py`：**  Meson 构建系统会调用 `jsonvalidator.py` 脚本，并将更新后的 JSON 文档的路径作为命令行参数传递给它。
   ```bash
   python3 frida/releng/meson/docs/jsonvalidator.py frida/releng/meson/docs/frida.json
   ```
5. **发现验证错误：** 如果开发者在修改 JSON 文档时犯了任何上述的常见错误，`jsonvalidator.py` 将会抛出 `AssertionError` 异常，并指出错误的位置和类型。
6. **调试和修复：** 开发者根据 `jsonvalidator.py` 的错误信息，回到 JSON 文档中定位并修复错误。例如，如果提示缺少 `description` 字段，开发者会在相应的函数定义中添加该字段。
7. **重新构建：** 修复错误后，开发者会重新构建 Frida，再次运行 `jsonvalidator.py` 进行验证，直到所有错误都消除为止。

因此，当开发者在构建 Frida 时遇到与 `jsonvalidator.py` 相关的错误，这通常意味着他们在更新 Frida 的 API 文档时引入了格式或类型错误。`jsonvalidator.py` 的输出为他们提供了调试的线索，帮助他们定位并修复文档中的问题。

Prompt: 
```
这是目录为frida/releng/meson/docs/jsonvalidator.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 The Meson development team

import argparse
import json
from pathlib import Path
from copy import deepcopy

import typing as T

T_None = type(None)

# Global root object
root: dict

def assert_has_typed_keys(path: str, data: dict, keys: T.Dict[str, T.Any]) -> dict:
    assert set(data.keys()).issuperset(keys.keys()), f'{path}: DIFF: {set(data.keys()).difference(keys.keys())}'
    res = dict()
    for key, val in keys.items():
        cur = data.pop(key)
        assert isinstance(cur, val), f'{path}: type({key}: {cur}) != {val}'
        res[key] = cur
    return res

def validate_base_obj(path: str, name: str, obj: dict) -> None:
    expected: T.Dict[str, T.Any] = {
        'name': str,
        'description': str,
        'since': (str, T_None),
        'deprecated': (str, T_None),
        'notes': list,
        'warnings': list,
    }
    cur = assert_has_typed_keys(f'{path}.{name}', obj, expected)
    assert cur['name'],                                            f'{path}.{name}'
    assert cur['description'],                                     f'{path}.{name}'
    assert cur['name'] == name,                                    f'{path}.{name}'
    assert all(isinstance(x, str) and x for x in cur['notes']),    f'{path}.{name}'
    assert all(isinstance(x, str) and x for x in cur['warnings']), f'{path}.{name}'

def validate_type(path: str, typ: dict) -> None:
    expected: T.Dict[str, T.Any] = {
        'obj': str,
        'holds': list,
    }
    cur = assert_has_typed_keys(path, typ, expected)
    assert not typ, f'{path} has extra keys: {typ.keys()}'
    assert cur['obj'] in root['objects'], path
    for i in cur['holds']:
        validate_type(path, i)

def validate_arg(path: str, name: str, arg: dict) -> None:
    validate_base_obj(path, name, arg)
    expected: T.Dict[str, T.Any] = {
        'type': list,
        'type_str': str,
        'required': bool,
        'default': (str, T_None),
        'min_varargs': (int, T_None),
        'max_varargs': (int, T_None),
    }
    cur = assert_has_typed_keys(f'{path}.{name}', arg, expected)
    assert not arg, f'{path}.{name} has extra keys: {arg.keys()}'
    assert cur['type'], f'{path}.{name}'
    assert cur['type_str'], f'{path}.{name}'
    for i in cur['type']:
        validate_type(f'{path}.{name}', i)
    if cur['min_varargs'] is not None:
        assert cur['min_varargs'] > 0, f'{path}.{name}'
    if cur['max_varargs'] is not None:
        assert cur['max_varargs'] > 0, f'{path}.{name}'

def validate_function(path: str, name: str, func: dict) -> None:
    validate_base_obj(path, name, func)
    expected: T.Dict[str, T.Any] = {
        'returns': list,
        'returns_str': str,
        'example': (str, T_None),
        'posargs': dict,
        'optargs': dict,
        'kwargs': dict,
        'varargs': (dict, T_None),
        'arg_flattening': bool,
    }
    cur = assert_has_typed_keys(f'{path}.{name}', func, expected)
    assert not func, f'{path}.{name} has extra keys: {func.keys()}'
    assert cur['returns'], f'{path}.{name}'
    assert cur['returns_str'], f'{path}.{name}'
    for i in cur['returns']:
        validate_type(f'{path}.{name}', i)
    for k, v in cur['posargs'].items():
        validate_arg(f'{path}.{name}', k, v)
    for k, v in cur['optargs'].items():
        validate_arg(f'{path}.{name}', k, v)
    for k, v in cur['kwargs'].items():
        validate_arg(f'{path}.{name}', k, v)
    if cur['varargs']:
        validate_arg(f'{path}.{name}', cur['varargs']['name'], cur['varargs'])

def validate_object(path: str, name: str, obj: dict) -> None:
    validate_base_obj(path, name, obj)
    expected: T.Dict[str, T.Any] = {
        'example': (str, T_None),
        'object_type': str,
        'methods': dict,
        'is_container': bool,
        'extends': (str, T_None),
        'returned_by': list,
        'extended_by': list,
        'defined_by_module': (str, T_None),
    }
    cur = assert_has_typed_keys(f'{path}.{name}', obj, expected)
    assert not obj, f'{path}.{name} has extra keys: {obj.keys()}'
    for key, val in cur['methods'].items():
        validate_function(f'{path}.{name}', key, val)
    if cur['extends'] is not None:
        assert cur['extends'] in root['objects'], f'{path}.{name}'
    assert all(isinstance(x, str) for x in cur['returned_by']), f'{path}.{name}'
    assert all(isinstance(x, str) for x in cur['extended_by']), f'{path}.{name}'
    assert all(x in root['objects'] for x in cur['extended_by']), f'{path}.{name}'
    if cur['defined_by_module'] is not None:
        assert cur['defined_by_module'] in root['objects'], f'{path}.{name}'
        assert cur['object_type'] == 'RETURNED', f'{path}.{name}'
        assert root['objects'][cur['defined_by_module']]['object_type'] == 'MODULE', f'{path}.{name}'
        assert name in root['objects_by_type']['modules'][cur['defined_by_module']], f'{path}.{name}'
        return
    assert cur['object_type'] in {'ELEMENTARY', 'BUILTIN', 'MODULE', 'RETURNED'}, f'{path}.{name}'
    if cur['object_type'] == 'ELEMENTARY':
        assert name in root['objects_by_type']['elementary'], f'{path}.{name}'
    if cur['object_type'] == 'BUILTIN':
        assert name in root['objects_by_type']['builtins'], f'{path}.{name}'
    if cur['object_type'] == 'RETURNED':
        assert name in root['objects_by_type']['returned'], f'{path}.{name}'
    if cur['object_type'] == 'MODULE':
        assert name in root['objects_by_type']['modules'], f'{path}.{name}'

def main() -> int:
    global root

    parser = argparse.ArgumentParser(description='Meson JSON docs validator')
    parser.add_argument('doc_file', type=Path, help='The JSON docs to validate')
    args = parser.parse_args()

    root_tmp = json.loads(args.doc_file.read_text(encoding='utf-8'))
    root = deepcopy(root_tmp)
    assert isinstance(root, dict)

    expected: T.Dict[str, T.Any] = {
        'version_major': int,
        'version_minor': int,
        'meson_version': str,
        'functions': dict,
        'objects': dict,
        'objects_by_type': dict,
    }
    cur = assert_has_typed_keys('root', root_tmp, expected)
    assert not root_tmp, f'root has extra keys: {root_tmp.keys()}'

    refs = cur['objects_by_type']
    expected = {
        'elementary': list,
        'builtins': list,
        'returned': list,
        'modules': dict,
    }
    assert_has_typed_keys(f'root.objects_by_type', refs, expected)
    assert not refs, f'root.objects_by_type has extra keys: {refs.keys()}'
    assert all(isinstance(x, str) for x in root['objects_by_type']['elementary'])
    assert all(isinstance(x, str) for x in root['objects_by_type']['builtins'])
    assert all(isinstance(x, str) for x in root['objects_by_type']['returned'])
    assert all(isinstance(x, str) for x in root['objects_by_type']['modules'])
    assert all(x in root['objects'] for x in root['objects_by_type']['elementary'])
    assert all(x in root['objects'] for x in root['objects_by_type']['builtins'])
    assert all(x in root['objects'] for x in root['objects_by_type']['returned'])
    assert all(x in root['objects'] for x in root['objects_by_type']['modules'])
    assert all(root['objects'][x]['object_type'] == 'ELEMENTARY' for x in root['objects_by_type']['elementary'])
    assert all(root['objects'][x]['object_type'] == 'BUILTIN'    for x in root['objects_by_type']['builtins'])
    assert all(root['objects'][x]['object_type'] == 'RETURNED'   for x in root['objects_by_type']['returned'])
    assert all(root['objects'][x]['object_type'] == 'MODULE'     for x in root['objects_by_type']['modules'])

    # Check that module references are correct
    assert all(all(isinstance(x, str)                           for x in v) for k, v in root['objects_by_type']['modules'].items())
    assert all(all(x in root['objects']                         for x in v) for k, v in root['objects_by_type']['modules'].items())
    assert all(all(root['objects'][x]['defined_by_module'] == k for x in v) for k, v in root['objects_by_type']['modules'].items())

    for key, val in cur['functions'].items():
        validate_function('root', key, val)
    for key, val in cur['objects'].items():
        validate_object('root', key, val)

    return 0

if __name__ == '__main__':
    raise SystemExit(main())

"""

```