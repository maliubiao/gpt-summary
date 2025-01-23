Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The first step is to read the problem description carefully and identify the core request: understand what the `jsonvalidator.py` script does. The context clues (Frida, dynamic instrumentation, Meson) hint at a validation role within a larger build or documentation system.

2. **Initial Code Scan - Identify Top-Level Structure:** Quickly scan the code to identify the major components:
    * Imports: `argparse`, `json`, `pathlib`, `copy`, `typing`. This suggests it takes command-line arguments, processes JSON data, and deals with file paths. The `typing` import indicates use of type hints for clarity and potentially static analysis.
    * Global Variable: `root`. This suggests the script will load the entire JSON structure into this variable for processing.
    * Functions: `assert_has_typed_keys`, `validate_base_obj`, `validate_type`, `validate_arg`, `validate_function`, `validate_object`, `main`. These function names clearly indicate a validation process, broken down by data structure.
    * `main()` function: This is the entry point, which parses arguments, loads the JSON, and then calls the validation functions.

3. **Analyze Key Functions - Focus on Validation Logic:**  Now, delve into the core validation functions. Look for patterns and common themes:
    * **`assert_has_typed_keys`:** This is a helper function that enforces the presence of specific keys and checks their types. It's a crucial part of the validation.
    * **`validate_base_obj`:** This function validates common fields found in various JSON objects (`name`, `description`, etc.). This suggests a common structure for different elements in the JSON schema.
    * **`validate_type`:** This function seems to validate the structure of "type" definitions, likely nested. It checks if the referenced objects exist in the `root`.
    * **`validate_arg`:** This validates function arguments, checking their type, whether they are required, default values, and varargs information.
    * **`validate_function`:** This validates function definitions, including return types, arguments (positional, optional, keyword, variable), and examples.
    * **`validate_object`:** This is the most complex validation function, dealing with different types of objects (elementary, built-in, module, returned). It checks for methods, inheritance, and where the object is defined.

4. **Connect the Dots - Understand the Flow:**  Trace the execution flow starting from `main()`:
    * `main()` loads the JSON file.
    * It validates the top-level structure (`version_major`, `functions`, `objects`, etc.).
    * It then iterates through the `functions` and `objects` and calls the corresponding validation functions.
    * The validation functions recursively call other validation functions (e.g., `validate_function` calls `validate_arg`, `validate_type`).

5. **Infer Purpose and Functionality:** Based on the analysis, conclude that the script's primary function is to validate the structure and data types of a JSON file. This JSON file likely describes the API of something, given the presence of "functions" and "objects."  The "since," "deprecated," "notes," and "warnings" fields point towards documentation.

6. **Address Specific Questions:** Now, systematically answer the specific questions in the prompt:

    * **Functionality:** Summarize the role of each main function and the overall goal of the script.
    * **Relationship to Reverse Engineering:**  Think about *why* you would need this kind of validation. If you're dynamically instrumenting code (like Frida does), you need a way to describe the API you're interacting with. This JSON could be that description, and validation ensures its correctness. Examples could involve hooking functions or accessing object properties based on this JSON.
    * **Binary/Kernel/Framework Knowledge:**  Consider what kind of data this JSON might describe. Function signatures, object structures, module organization – these concepts are relevant to understanding how software is built and how Frida interacts with it at a lower level. Think about how function arguments and return values relate to binary interfaces (ABIs).
    * **Logical Inference:**  Look for conditional logic and assertions. Consider what would happen if the input JSON violated the expected schema. The assertions provide clear failure points. Create simple "good" and "bad" input examples to illustrate the validation process.
    * **Common Usage Errors:**  Think about mistakes developers might make when *creating* the JSON file. Incorrect types, missing required fields, typos in object names – these are common errors a validator would catch.
    * **User Path to Execution:**  Imagine the steps involved in using Frida and how this script fits in. Someone likely generates this JSON documentation, and this script is run as part of a build or testing process to ensure the documentation is correct. The file path provides a strong clue about the location within the Frida project.

7. **Refine and Organize:** Structure the answer clearly, using headings and bullet points to make it easy to read. Explain technical terms if necessary. Ensure the examples are concrete and illustrate the points being made.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  "This just validates JSON."  **Correction:**  It's validating JSON *with a specific schema* related to Frida's API. The function and object names are strong indicators.
* **Stuck on a Function:** If unsure about a function's purpose, reread its code, paying attention to the assertions and the data it manipulates. Refer back to the function's docstring or surrounding code for context (though this script lacks explicit docstrings).
* **Missing a Connection:** If struggling to connect the script to reverse engineering, think about the *purpose* of Frida. It's about interacting with running processes. How does one know *what* to interact with?  The JSON likely provides that information.
* **Vague Examples:**  If the examples are too abstract, try to create more concrete scenarios, such as a specific function with particular argument types.

By following these steps, combining code analysis with domain knowledge (even a little bit about Frida helps), and continually refining the understanding, you can arrive at a comprehensive and accurate explanation of the script's functionality.
这是一个Frida动态Instrumentation工具的源代码文件，名为`jsonvalidator.py`，其主要功能是**验证一个JSON文件是否符合预期的结构和类型定义**。 这个JSON文件很可能用于描述 Frida 中 Swift 桥接相关的 API，包括函数、对象、参数等信息。

下面列举一下它的功能，并根据你的要求进行举例说明：

**功能列表:**

1. **读取 JSON 文件:**  脚本接收一个 JSON 文件路径作为命令行参数，并读取其内容。
2. **基本结构验证:** 验证 JSON 根对象是否包含预期的键，如 `version_major`，`version_minor`，`meson_version`，`functions`，`objects`，`objects_by_type`，并检查这些键对应的值的类型是否正确。
3. **对象验证 (`validate_object`):**
    * 验证每个对象的 `name`，`description`，`since`，`deprecated`，`notes`，`warnings` 等基本属性的类型和存在性。
    * 验证 `object_type` 是否为预期的值 (`ELEMENTARY`, `BUILTIN`, `MODULE`, `RETURNED`)。
    * 验证 `methods` 字段，递归调用 `validate_function` 来验证每个方法。
    * 验证继承关系 (`extends`) 和被继承关系 (`extended_by`) 的正确性。
    * 验证对象是否被其他对象返回 (`returned_by`)。
    * 验证模块定义 (`defined_by_module`) 的正确性。
4. **函数验证 (`validate_function`):**
    * 验证每个函数的 `name`，`description`，`since`，`deprecated`，`notes`，`warnings` 等基本属性。
    * 验证 `returns` 和 `returns_str` 字段，确保返回值类型描述正确。
    * 验证 `posargs` (位置参数)，`optargs` (可选参数)，`kwargs` (关键字参数)，`varargs` (可变参数) 字段，递归调用 `validate_arg` 来验证每个参数。
    * 验证 `example` 字段 (示例代码) 的类型。
5. **参数验证 (`validate_arg`):**
    * 验证每个参数的 `name`，`description`，`since`，`deprecated`，`notes`，`warnings` 等基本属性。
    * 验证 `type` (参数类型列表) 和 `type_str` (参数类型字符串) 字段。
    * 验证 `required` (是否必需)，`default` (默认值)，`min_varargs` (最小可变参数数量)，`max_varargs` (最大可变参数数量) 等属性。
    * 递归调用 `validate_type` 来验证参数类型。
6. **类型验证 (`validate_type`):**
    * 验证类型定义中的 `obj` 字段 (引用的对象名) 是否在已定义的对象列表中。
    * 验证 `holds` 字段 (如果类型是容器，包含的子类型)，递归调用 `validate_type` 进行验证。
7. **类型键值对验证 (`assert_has_typed_keys`):** 这是一个辅助函数，用于检查字典中是否包含预期的键，并且这些键对应的值的类型是否符合预期。如果缺少键或者类型不匹配，会抛出断言错误。
8. **命令行参数解析:** 使用 `argparse` 模块解析命令行参数，目前只接受一个参数：JSON 文档的文件路径。

**与逆向方法的关系及举例说明:**

此脚本与逆向工程密切相关，因为它验证的 JSON 文件很可能描述了 Frida 可以用来与目标进程中的 Swift 代码进行交互的接口。

**举例说明:**

假设目标应用程序是用 Swift 编写的，并且你想使用 Frida Hook 其中的一个函数。为了方便开发者，Frida 提供了一种方式来描述这些 Swift 函数的签名、参数和返回值等信息。这个 JSON 文件就是这种描述。

```json
{
  "version_major": 1,
  "version_minor": 0,
  "meson_version": "0.60.0",
  "functions": {
    "greet": {
      "name": "greet",
      "description": "Greets a person.",
      "since": "1.0",
      "deprecated": null,
      "notes": [],
      "warnings": [],
      "returns": [
        {
          "obj": "String",
          "holds": []
        }
      ],
      "returns_str": "String",
      "example": "greet(name: \"World\")",
      "posargs": {
        "name": {
          "name": "name",
          "description": "The name of the person to greet.",
          "since": "1.0",
          "deprecated": null,
          "notes": [],
          "warnings": [],
          "type": [
            {
              "obj": "String",
              "holds": []
            }
          ],
          "type_str": "String",
          "required": true,
          "default": null,
          "min_varargs": null,
          "max_varargs": null
        }
      },
      "optargs": {},
      "kwargs": {},
      "varargs": null,
      "arg_flattening": false
    }
  },
  "objects": {
    "String": {
      "name": "String",
      "description": "A string object.",
      "since": "1.0",
      "deprecated": null,
      "notes": [],
      "warnings": [],
      "example": null,
      "object_type": "BUILTIN",
      "methods": {},
      "is_container": false,
      "extends": null,
      "returned_by": [],
      "extended_by": [],
      "defined_by_module": null
    }
  },
  "objects_by_type": {
    "elementary": [],
    "builtins": [
      "String"
    ],
    "returned": [],
    "modules": {}
  }
}
```

这个 JSON 文件描述了一个名为 `greet` 的 Swift 函数，它接收一个名为 `name` 的字符串参数，并返回一个字符串。Frida 可以解析这个 JSON 文件，然后允许用户使用类似 `greet(name: "Frida")` 的方式在目标进程中调用这个 Swift 函数。

`jsonvalidator.py` 的作用就是确保这个 JSON 文件的结构和类型定义是正确的，例如：

* 确保 `greet` 函数的 `returns` 字段是一个包含对象类型为 "String" 的列表。
* 确保 `greet` 函数的 `posargs` 中 `name` 参数的类型也是 "String"。
* 确保 "String" 对象被正确地定义为 "BUILTIN" 类型。

如果 JSON 文件写错了，例如将 `name` 参数的 `type` 写成了 `["Int"]`，那么 `jsonvalidator.py` 就会报错，防止 Frida 基于错误的描述与目标进程交互，从而避免潜在的错误和崩溃。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明:**

虽然 `jsonvalidator.py` 本身是用 Python 编写的，并不直接操作二进制底层或内核，但它验证的 JSON 数据反映了 Frida 与目标进程进行交互时需要了解的底层信息。

**举例说明:**

* **函数签名:** JSON 文件中 `functions` 节点的描述（参数类型、返回值类型）直接对应于 Swift 函数在编译后的二进制代码中的符号和调用约定。Frida 需要这些信息才能正确地调用目标函数，并解析其参数和返回值。
* **对象结构:**  对于更复杂的对象，JSON 文件可能会描述对象的成员变量和方法。这些信息反映了对象在内存中的布局，Frida 可以利用这些信息来读取和修改对象的属性，或者调用对象的方法。这涉及到对目标进程内存布局的理解，这是二进制底层知识的一部分。
* **模块:** JSON 文件中的 `modules` 和 `defined_by_module` 字段反映了代码的模块化组织。在 Linux 和 Android 等系统中，代码通常以动态链接库 (shared libraries) 的形式存在。Frida 需要知道目标函数或对象属于哪个模块，才能在内存中找到它们。
* **类型系统:** JSON 文件中对类型的描述反映了 Swift 的类型系统。Frida 需要理解这些类型，才能在 JavaScript 或 Python 等脚本语言中正确地表示和操作这些 Swift 对象。

**逻辑推理及假设输入与输出:**

`jsonvalidator.py` 的主要逻辑是基于对 JSON 结构的模式匹配和类型检查。

**假设输入:**

一个包含错误的 JSON 文件，例如：

```json
{
  "version_major": "1",  // 错误：应该是整数
  "version_minor": 0,
  "meson_version": "0.60.0",
  "functions": {
    "greet": {
      "name": "greet",
      "description": "Greets a person.",
      // 缺少 returns 字段
      "returns_str": "String",
      "example": "greet(name: \"World\")",
      "posargs": {
        "name": {
          "name": "name",
          "description": "The name of the person to greet.",
          "since": "1.0",
          "deprecated": null,
          "notes": [],
          "warnings": [],
          "type": [
            {
              "obj": "String",
              "holds": []
            }
          ],
          "type_str": "String",
          "required": true,
          "default": null,
          "min_varargs": null,
          "max_varargs": null
        }
      },
      "optargs": {},
      "kwargs": {},
      "varargs": null,
      "arg_flattening": false
    }
  },
  "objects": {
    "String": {
      "name": "String",
      "description": "A string object.",
      "since": "1.0",
      "deprecated": null,
      "notes": [],
      "warnings": [],
      "example": null,
      "object_type": "BUILTIN",
      "methods": {},
      "is_container": false,
      "extends": null,
      "returned_by": [],
      "extended_by": [],
      "defined_by_module": null
    }
  },
  "objects_by_type": {
    "elementary": [],
    "builtins": [
      "String"
    ],
    "returned": [],
    "modules": {}
  }
}
```

**预期输出:**

脚本会抛出断言错误，指出 JSON 文件中的错误：

* `root: type(version_major: 1) != <class 'int'>` (因为 "version_major" 的值是字符串而不是整数)
* `root.greet: DIFF: {'returns'}` (因为 "greet" 函数缺少了 "returns" 键)

**如果涉及用户或者编程常见的使用错误，请举例说明:**

常见的使用错误通常发生在创建或修改 JSON 文件时。

**举例说明:**

1. **类型错误:** 用户将一个本应是字符串的值写成了数字，或者将一个数组写成了对象。
   ```json
   {
     "functions": {
       "myFunction": {
         "returns": "String", // 错误：应该是一个包含类型定义的列表
         "returns_str": "String",
         // ...
       }
     }
   }
   ```
   `jsonvalidator.py` 会报错：`root.myFunction: type(returns: String) != <class 'list'>`

2. **缺少必需的键:** 用户忘记在对象或函数定义中添加必要的字段。
   ```json
   {
     "functions": {
       "myFunction": {
         "name": "myFunction",
         // 缺少 description 字段
         "returns": [ { "obj": "void", "holds": [] } ],
         "returns_str": "void"
         // ...
       }
     }
   }
   ```
   `jsonvalidator.py` 会报错：`root.myFunction: DIFF: {'description'}`

3. **拼写错误:** 用户在键名或对象名中输入了错误的拼写。
   ```json
   {
     "objects": {
       "Striing": { // 错误拼写
         "name": "Striing",
         "object_type": "BUILTIN"
         // ...
       }
     },
     "functions": {
       "myFunction": {
         "returns": [ { "obj": "Striing", "holds": [] } ], // 引用了错误的拼写
         "returns_str": "Striing"
         // ...
       }
     }
   }
   ```
   `jsonvalidator.py` 可能会在验证函数返回值类型时报错：`root.myFunction: root.Striing` (因为找不到名为 "Striing" 的对象)。

4. **不一致的类型引用:**  `type` 字段和 `type_str` 字段描述不一致。
   ```json
   {
     "functions": {
       "myFunction": {
         "posargs": {
           "param1": {
             "type": [ { "obj": "Int", "holds": [] } ],
             "type_str": "String" // 错误：与 type 不一致
             // ...
           }
         }
       }
     }
   }
   ```
   `jsonvalidator.py` 会报错，指出 `type` 的实际类型与 `type_str` 描述的类型不符。

**说明用户操作是如何一步步的到达这里，作为调试线索。**

1. **Frida 开发或维护者需要更新或添加对 Swift API 的支持。** 这可能涉及到新的 Swift 版本发布，或者需要在 Frida 中暴露更多的 Swift 功能。
2. **开发者手动编写或工具生成描述 Swift API 的 JSON 文件。** 这个 JSON 文件会包含函数、对象、参数等的详细信息。
3. **为了确保 JSON 文件的正确性，开发者会运行 `jsonvalidator.py` 脚本。**  他们可能会在命令行中执行类似以下命令：
   ```bash
   ./jsonvalidator.py path/to/swift_api_description.json
   ```
4. **如果 JSON 文件格式正确，脚本会成功执行，不产生任何输出。**
5. **如果 JSON 文件中存在错误，脚本会抛出包含详细错误信息的断言错误。** 例如：
   ```
   Traceback (most recent call last):
     File "./jsonvalidator.py", line 45, in assert_has_typed_keys
       assert isinstance(cur, val), f'{path}: type({key}: {cur}) != {val}'
   AssertionError: root: type(version_major: 1) != <class 'int'>
   ```
6. **开发者根据错误信息，检查 JSON 文件中对应的位置，并修复错误。** 例如，将 `"version_major": "1"` 修改为 `"version_major": 1`。
7. **开发者重新运行 `jsonvalidator.py`，直到所有错误都被修复。**

这个过程是 Frida 开发流程的一部分，用于确保 Frida 能够准确地理解和操作目标进程中的 Swift 代码。 `jsonvalidator.py` 作为一个静态分析工具，在集成到 Frida 中之前就捕获了潜在的错误，提高了 Frida 的稳定性和可靠性。  其存在于 `frida/subprojects/frida-swift/releng/meson/docs/` 路径下也说明了它与 Frida 的 Swift 支持以及构建系统 (Meson) 的文档生成过程相关。

### 提示词
```
这是目录为frida/subprojects/frida-swift/releng/meson/docs/jsonvalidator.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```