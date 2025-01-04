Response:
Let's break down the thought process for analyzing this Python code. The goal is to understand its functionality, its relation to reverse engineering, its use of lower-level concepts, its logic, potential errors, and how someone might end up interacting with it.

**1. Initial Skim and Keyword Spotting:**

The first step is to quickly read through the code, paying attention to keywords and structure. Key observations:

* **File Path:** `frida/releng/meson/docs/refman/loaderyaml.py`  This immediately suggests this code is related to the documentation generation process for Frida, using Meson as a build system. The "refman" part strongly indicates it's loading data to create a reference manual.
* **Imports:**  `loaderbase`, `model`, `mlog`, `mesonlib`, `pathlib`, `typing`, `strictyaml`, `yaml`. These imports reveal dependencies and the kind of work being done:
    * `loaderbase`, `model`: Likely define the structure and base class for loading data.
    * `mlog`:  Probably for logging during the loading process.
    * `mesonlib`:  Helper functions within the Meson build system.
    * `pathlib`:  Working with file paths.
    * `typing`: Type hints for better code clarity and maintainability.
    * `strictyaml`, `yaml`:  Crucially, the code handles both strict and less strict YAML parsing.
* **Classes:** `Template`, `StrictTemplate`, `FastTemplate`, `LoaderYAML`. This points to a design pattern involving different ways to handle YAML templates. The `LoaderYAML` class is the main actor.
* **Data Structures:** Dictionaries (`T.Dict`), Lists (`T.List`). The code heavily uses these to represent the structure of the YAML data.
* **YAML Loading:**  The presence of `strictyaml` and `yaml` and the `_load` function clearly indicate this code is responsible for parsing YAML files.
* **"feature_check", "posarg", "varargs", "kwarg", "function", "object":** These terms within the `Template` classes strongly suggest the YAML files describe the API elements of Frida.

**2. Deconstructing the Classes:**

Next, focus on understanding the purpose of each class:

* **`Template`:**  A base class likely defining the expected structure of the YAML data. It acts as a blueprint.
* **`StrictTemplate`:**  Uses `strictyaml` to enforce a strict schema for the YAML files. This is important for data integrity and preventing errors. The detailed schema definitions using `strictyaml.Map`, `Str`, `Seq`, etc., provide a precise understanding of the expected YAML structure.
* **`FastTemplate`:**  A less strict version using the standard `yaml` library. This might be for faster loading or handling less formally defined YAML. It uses default values to fill in missing information.
* **`LoaderYAML`:** The core class. It orchestrates the loading of YAML files from specified directories (`functions`, `elementary`, `objects`, etc.) and uses either the `StrictTemplate` or `FastTemplate` depending on the `strict` flag.

**3. Analyzing Key Methods:**

Focus on the most important methods within `LoaderYAML`:

* **`__init__`:** Initializes the loader, setting up file paths and choosing the template based on the `strict` flag. The logic for conditional import and `_load` function assignment is significant.
* **`_fix_default`:**  A small utility to ensure default boolean values are converted to strings.
* **`_process_function_base`:**  The heart of function/method parsing. It extracts arguments (positional, optional, variable, keyword), parses their types, and creates `Function` or `Method` objects. The handling of `kwargs_inherit` is also important.
* **`_load_function`:** Loads a single function definition from a YAML file.
* **`_load_object`:** Loads an object definition, including its methods. It recursively calls `_process_function_base` for each method.
* **`_load_module`:**  Loads a module, which can contain a main module definition and definitions for returned objects.
* **`load_impl`:** The main entry point for loading all YAML files and constructing the `ReferenceManual` object.

**4. Connecting to Reverse Engineering, Low-Level Concepts, and Reasoning:**

Now, connect the code's functionality to the prompt's specific questions:

* **Reverse Engineering:** Frida is a dynamic instrumentation toolkit heavily used in reverse engineering. This code loads the documentation for Frida's API. Understanding the API is crucial for anyone using Frida to inspect and modify running processes – a core reverse engineering activity. The examples of `frida.attach()`, `Process.enumerate_modules()`, and `Interceptor.attach()` demonstrate how knowledge of this API is fundamental to Frida's use in reverse engineering.
* **Binary/Low-Level, Linux/Android Kernel/Framework:**  While this specific code *doesn't directly* manipulate binary code or interact with the kernel, *it documents the tools that do*. Frida itself operates at a low level, injecting code into processes, hooking functions, and interacting with system calls. The documented API provides the interface for these low-level operations. The examples highlight API elements (`Process`, `Module`, `Interceptor`) that represent or interact with these low-level components.
* **Logical Reasoning:**  Consider the `strict` flag. If `strict` is true, the code uses `strictyaml` for rigorous validation. If false, it uses the more lenient `yaml` library and assumes default values. The `_process_function_base` method makes logical decisions about how to handle different types of arguments. The inheritance mechanisms (`posargs_inherit`, `kwargs_inherit`) also involve logical steps to merge definitions. The input/output example shows how the YAML structure maps to the Python objects created.

**5. Identifying Potential Errors and User Actions:**

Think about how things could go wrong:

* **YAML Syntax Errors:** If a user manually edits the YAML files and introduces syntax errors, the loading process will fail. The `strictyaml` mode will catch many of these.
* **Schema Violations (Strict Mode):**  Even with correct syntax, the YAML might not conform to the defined schema in `StrictTemplate`. This will also cause errors in strict mode.
* **Missing Files:** If the YAML files are not in the expected directory structure, the loader will fail to find them.
* **Incorrect Data Types:**  If the YAML specifies an incorrect data type for an argument (e.g., a string instead of an integer), the parsing might fail or produce unexpected results. `strictyaml` helps prevent this.
* **Case Sensitivity (Potentially):** While not explicitly mentioned in the code, YAML can be case-sensitive for keys. Inconsistent casing could lead to errors.

**6. Tracing User Actions:**

Consider how a developer would end up interacting with this code:

* **Modifying Frida's Documentation:**  The most likely scenario is someone updating the documentation for Frida's API. They would edit the YAML files in the specified directories.
* **Running the Documentation Build Process:** This code is part of the documentation generation process. A developer would trigger this process (likely as part of the Meson build) to generate updated documentation after modifying the YAML files.
* **Debugging Documentation Issues:** If the generated documentation is incorrect, a developer might need to examine this `loaderyaml.py` code to understand how the YAML files are parsed and processed.

**7. Refinement and Structuring the Answer:**

Finally, organize the findings into a clear and structured answer, addressing each part of the prompt. Use clear examples to illustrate the concepts. Ensure to highlight the connections to reverse engineering, low-level details, and potential pitfalls.

This systematic approach, starting with a broad overview and gradually drilling down into specifics, combined with considering the context and purpose of the code, allows for a comprehensive understanding and the ability to answer the prompt effectively.
好的，让我们来详细分析一下 `frida/releng/meson/docs/refman/loaderyaml.py` 文件的功能和相关知识点。

**文件功能概述**

这个 Python 文件的主要功能是从 YAML 文件中加载 Frida 动态 instrumentation 工具的 API 参考手册信息，并将其转换为特定的 Python 对象结构。这些 Python 对象结构随后可以被用于生成最终的文档（例如，HTML 或 Markdown）。

具体来说，`loaderyaml.py` 做了以下事情：

1. **定义数据模型:**  定义了一系列 Python 类 (`Type`, `PosArg`, `VarArgs`, `Kwarg`, `Function`, `Method`, `ObjectType`, `Object`, `ReferenceManual`) 来表示 Frida API 的各种元素，例如函数、方法、对象、参数等等。这些类构成了一个结构化的数据模型，用于存储从 YAML 文件中读取的信息。

2. **定义 YAML 加载模板:** 定义了 `Template`、`StrictTemplate` 和 `FastTemplate` 类，用于指定 YAML 文件的结构和字段。
   - `StrictTemplate` 使用 `strictyaml` 库进行严格的 YAML 校验，确保 YAML 文件的格式符合预定义的规范。
   - `FastTemplate` 使用 `yaml` 库进行更快速的加载，但校验相对宽松。

3. **实现 YAML 加载器:** `LoaderYAML` 类是核心的加载器。
   - 它接收 YAML 文件所在的目录和是否使用严格模式的标志作为参数。
   - 它会遍历指定的目录（`functions`, `elementary`, `objects`, `builtins`, `modules`），读取对应的 YAML 文件。
   - 根据选择的模板（`StrictTemplate` 或 `FastTemplate`），使用相应的库（`strictyaml` 或 `yaml`）解析 YAML 文件内容。
   - 将解析后的数据映射到之前定义的数据模型类 (`Function`, `Object` 等) 的实例。

4. **处理继承和引用:** 代码中涉及到参数继承 (`posargs_inherit`, `optargs_inherit`, `varargs_inherit`, `kwargs_inherit`) 和对象继承 (`extends`) 的处理，允许在不同的 YAML 文件之间共享和复用定义。

5. **构建参考手册对象:** 最终，`load_impl` 方法会将加载的所有函数、对象等信息组织成一个 `ReferenceManual` 对象，这个对象包含了 Frida API 的完整结构化描述。

**与逆向方法的联系**

`loaderyaml.py` 本身不是直接进行逆向的工具，但它为理解和使用 Frida 提供了基础，而 Frida 是一个强大的动态逆向工具。

**举例说明:**

假设在 Frida 的某个版本中添加了一个新的函数 `frida.spawn(program, ...)` 用于启动新的进程并进行 attach。为了将这个新函数添加到 Frida 的官方文档中，开发者需要：

1. **创建或修改 YAML 文件:** 在 `frida/releng/meson/docs/refman/meson/functions/spawn.yaml` (文件名可能不同) 创建一个新的 YAML 文件来描述 `frida.spawn` 函数。这个文件会包含函数的名称、描述、参数、返回值等信息。

   ```yaml
   name: spawn
   description: Spawns a new process and attaches to it.
   since: "15.0.0"  # 假设是 15.0.0 版本新增的
   returns: Process
   posargs:
     program:
       type: str
       description: The path to the executable to spawn.
     argv:
       type: "[str]"
       description: An optional list of arguments to pass to the spawned process.
       default: []
   optargs:
     cwd:
       type: str
       description: The working directory for the new process.
     envp:
       type: "{str: str}"
       description: A dictionary of environment variables for the new process.
   ```

2. **`loaderyaml.py` 解析 YAML:** 当构建 Frida 的文档时，`loaderyaml.py` 会读取 `spawn.yaml` 文件，并根据其内容创建一个 `Function` 类的实例。这个 `Function` 对象会包含 `name` 为 "spawn"，`returns` 的类型为 `Process`，以及 `posargs` 和 `optargs` 中定义的参数信息。

3. **生成文档:**  后续的文档生成工具会使用 `loaderyaml.py` 生成的 `ReferenceManual` 对象，从中提取 `frida.spawn` 函数的信息，并将其渲染到最终的文档中，供用户查阅。

因此，`loaderyaml.py` 的作用是确保 Frida 的 API 文档能够准确地反映 Frida 的功能，这对于逆向工程师理解和使用 Frida 来分析目标程序至关重要。

**涉及二进制底层、Linux、Android 内核及框架的知识**

虽然 `loaderyaml.py` 本身不直接操作二进制或与内核交互，但它所描述的 Frida API 背后涉及大量的底层知识。

**举例说明:**

* **`Type: Process`**:  在 YAML 文件中，`frida.spawn` 函数的返回值类型是 `Process`。这个 `Process` 类型在 Frida 的代码中对应着一个代表目标进程的对象。Frida 需要使用操作系统提供的 API (如 Linux 的 `fork`, `execve` 或 Android 的 `ProcessBuilder`) 来创建新的进程。
* **`Type: "[str]"` (参数类型)**:  `argv` 参数的类型是字符串列表。这意味着 Frida 需要将这些字符串参数正确地传递给新创建的进程。这涉及到操作系统对于进程参数的约定和格式。
* **`frida.attach(pid)`**: 另一个常见的 Frida 函数，用于连接到一个正在运行的进程。这需要 Frida 能够与目标进程建立通信，可能涉及到进程间通信 (IPC) 机制，例如在 Linux 上可能是 `ptrace` 系统调用，在 Android 上可能涉及到特定的 Binder 机制。
* **Hooking 函数:** Frida 的核心功能之一是 hook 目标进程中的函数。文档中描述的 `Interceptor.attach(target, onEnter, onLeave)` API 背后，Frida 需要修改目标进程的内存，替换函数的入口点指令，以便在函数执行时能够跳转到 Frida 注入的代码。这涉及到对目标架构 (例如 ARM, x86) 的指令集的理解，以及操作系统内存管理和代码注入的知识。

因此，`loaderyaml.py` 描述的 API 虽然是高层次的抽象，但其底层的实现却深深依赖于对操作系统、内核以及二进制执行机制的深刻理解。

**逻辑推理的假设输入与输出**

假设我们有一个描述 Frida `Memory` 对象的 YAML 文件 `memory.yaml` (在 `objects` 目录下):

**假设输入 (`memory.yaml`):**

```yaml
name: Memory
long_name: frida.Memory
description: Provides access to the memory of a process.
since: "12.0.0"
methods:
  - name: readByteArray
    description: Reads an array of bytes from memory.
    returns: "bytes"
    posargs:
      address:
        type: "NativePointer"
        description: The address to read from.
      size:
        type: "int"
        description: The number of bytes to read.
  - name: writeByteArray
    description: Writes an array of bytes to memory.
    returns: "void"
    posargs:
      address:
        type: "NativePointer"
        description: The address to write to.
      data:
        type: "bytes"
        description: The bytes to write.
```

**`loaderyaml.py` 的处理过程:**

1. `LoaderYAML` 初始化并找到 `objects` 目录。
2. 它读取 `memory.yaml` 文件。
3. 使用配置的模板（假设是 `StrictTemplate`），校验 YAML 格式是否正确。
4. 创建一个 `Object` 类的实例，其 `name` 为 "Memory"，`long_name` 为 "frida.Memory"，`description` 为 "Provides access to the memory of a process."。
5. 遍历 `methods` 列表。
6. 对于 `readByteArray` 方法，创建一个 `Method` 类的实例，包含其 `name`, `description`, `returns` 类型为 `bytes`，以及 `posargs` 中定义的 `address` 和 `size` 参数及其类型和描述。
7. 对于 `writeByteArray` 方法，类似地创建一个 `Method` 类的实例。

**假设输出 (部分 Python 对象结构):**

```python
ReferenceManual(
    # ... 其他对象和函数
    objects=[
        # ... 其他对象
        Object(
            name='Memory',
            long_name='frida.Memory',
            description='Provides access to the memory of a process.',
            since='12.0.0',
            methods=[
                Method(
                    name='readByteArray',
                    description='Reads an array of bytes from memory.',
                    returns=Type(name='bytes'),
                    posargs=[
                        PosArg(name='address', type=Type(name='NativePointer'), description='The address to read from.'),
                        PosArg(name='size', type=Type(name='int'), description='The number of bytes to read.')
                    ],
                    optargs=[],
                    varargs=None,
                    kwargs={}
                ),
                Method(
                    name='writeByteArray',
                    description='Writes an array of bytes to memory.',
                    returns=Type(name='void'),
                    posargs=[
                        PosArg(name='address', type=Type(name='NativePointer'), description='The address to write to.'),
                        PosArg(name='data', type=Type(name='bytes'), description='The bytes to write.')
                    ],
                    optargs=[],
                    varargs=None,
                    kwargs={}
                )
            ],
            # ... 其他属性
        ),
        # ... 其他对象
    ]
)
```

**用户或编程常见的使用错误**

1. **YAML 格式错误:** 用户手动编辑 YAML 文件时，可能会引入语法错误，例如缩进不正确、冒号后面缺少空格、使用了无效的 YAML 结构等。如果启用了严格模式，`strictyaml` 会抛出异常，指出具体的错误位置。

   **例子:**

   ```yaml
   name: spawn
   description: Spawns a new process
   returns: Process  # 缺少缩进可能导致解析错误
   ```

2. **类型定义错误:** YAML 文件中定义的类型名称可能与 `model.py` 中定义的类型不匹配。

   **例子:**

   ```yaml
   posargs:
     pid:
       type: Integer  # 应该使用 "int" (假设 model.py 中定义的是 "int")
       description: The process ID to attach to.
   ```

3. **缺少必要的字段:** 在严格模式下，如果 YAML 文件缺少了 `StrictTemplate` 中定义的必要字段，加载过程会失败。

   **例子:**

   ```yaml
   name: attach  # 缺少 description 字段
   returns: Session
   ```

4. **继承关系错误:** 如果 `extends` 字段指定了一个不存在的对象，或者继承的对象的结构不兼容，可能会导致加载错误。

5. **使用了保留字或非法字符作为参数名或方法名。**

**用户操作如何一步步到达这里 (调试线索)**

假设开发者在为 Frida 添加新的功能或修改现有功能，并需要更新 API 文档。以下是可能的操作步骤：

1. **修改 Frida 的 C/C++ 或 Python 代码:** 开发者实现了新的 API 功能或修改了现有 API 的行为。

2. **更新或创建 YAML 文件:** 为了反映代码的更改，开发者需要编辑 `frida/releng/meson/docs/refman/meson` 目录下的 YAML 文件。例如，添加新的函数描述文件，或者修改现有函数描述文件的参数、返回值等信息。

3. **运行文档生成命令:**  Frida 使用 Meson 构建系统。开发者可能会运行一个类似于以下的命令来生成文档：

   ```bash
   meson compile -C builddir
   meson test -C builddir doc  # 假设有一个名为 "doc" 的测试目标用于生成文档
   # 或者更直接的命令，如果知道生成文档的具体命令
   ```

4. **Meson 构建系统调用 `loaderyaml.py`:**  在文档生成过程中，Meson 构建系统会执行相关的脚本，其中会调用 `loaderyaml.py` 脚本。

5. **`loaderyaml.py` 加载 YAML 文件:** `loaderyaml.py` 根据配置（严格模式或快速模式）读取并解析 YAML 文件。

6. **如果出现错误，开发者需要调试:**
   - **查看构建日志:**  Meson 会输出构建日志，其中可能包含 `loaderyaml.py` 抛出的异常信息，例如 YAML 格式错误或类型不匹配。
   - **检查 YAML 文件:** 开发者需要仔细检查修改过的 YAML 文件，确认语法和结构是否正确，是否缺少必要的字段，类型定义是否匹配。
   - **查看 `loaderyaml.py` 代码:** 如果错误信息不够明确，开发者可能需要查看 `loaderyaml.py` 的源代码，理解其加载逻辑和校验规则，以便找到问题所在。
   - **使用 IDE 或调试器:** 开发者可以使用 Python IDE 或调试器来单步执行 `loaderyaml.py` 的代码，查看变量的值，了解加载过程中具体哪个 YAML 文件或哪个字段导致了错误。
   - **临时修改代码:**  为了定位问题，开发者可能会临时修改 `loaderyaml.py` 的代码，例如添加 `print()` 语句来输出中间变量的值，或者注释掉部分校验逻辑。

总而言之，`loaderyaml.py` 在 Frida 的文档生成流程中扮演着关键的角色，它负责将结构化的 API 描述从 YAML 文件加载到 Python 对象中，为后续的文档生成提供数据基础。理解其功能和工作原理，对于参与 Frida 开发和维护文档的开发者来说非常重要。

Prompt: 
```
这是目录为frida/releng/meson/docs/refman/loaderyaml.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 The Meson development team

from .loaderbase import LoaderBase
from .model import (
    Type,
    PosArg,
    VarArgs,
    Kwarg,
    Function,
    Method,
    ObjectType,
    Object,
    ReferenceManual,
)

from mesonbuild import mlog
from mesonbuild import mesonlib

from pathlib import Path
import typing as T

class Template:
    d_feature_check: T.Dict[str, T.Any] = {}
    s_posarg: T.Dict[str, T.Any] = {}
    s_varargs: T.Dict[str, T.Any] = {}
    s_kwarg: T.Dict[str, T.Any] = {}
    s_function: T.Dict[str, T.Any] = {}
    s_object: T.Dict[str, T.Any] = {}

class StrictTemplate(Template):
    def __init__(self) -> None:
        from strictyaml import Map, MapPattern, Optional, Str, Seq, Int, Bool, EmptyList, OrValidator # type: ignore[import-untyped]

        d_named_object = {
            'name': Str(),
            'description': Str(),
        }

        d_feture_check = {
            Optional('since', default=''): Str(),
            Optional('deprecated', default=''): Str(),
        }

        self.s_posarg = Map({
            **d_feture_check,
            'description': Str(),
            'type': Str(),
            Optional('default', default=''): Str(),
        })

        self.s_varargs = Map({
            **d_named_object, **d_feture_check,
            'type': Str(),
            Optional('min_varargs', default=-1): Int(),
            Optional('max_varargs', default=-1): Int(),
        })

        self.s_kwarg = Map({
            **d_feture_check,
            'type': Str(),
            'description': Str(),
            Optional('required', default=False): Bool(),
            Optional('default', default=''): Str(),
        })

        self.s_function = Map({
            **d_named_object, **d_feture_check,
            'returns': Str(),
            Optional('notes', default=[]): OrValidator(Seq(Str()), EmptyList()),
            Optional('warnings', default=[]): OrValidator(Seq(Str()), EmptyList()),
            Optional('example', default=''): Str(),
            Optional('posargs'): MapPattern(Str(), self.s_posarg),
            Optional('optargs'): MapPattern(Str(), self.s_posarg),
            Optional('varargs'): self.s_varargs,
            Optional('posargs_inherit', default=''): Str(),
            Optional('optargs_inherit', default=''): Str(),
            Optional('varargs_inherit', default=''): Str(),
            Optional('kwargs'): MapPattern(Str(), self.s_kwarg),
            Optional('kwargs_inherit', default=[]): OrValidator(OrValidator(Seq(Str()), EmptyList()), Str()),
            Optional('arg_flattening', default=True): Bool(),
        })

        self.s_object = Map({
            **d_named_object, **d_feture_check,
            'long_name': Str(),
            Optional('extends', default=''): Str(),
            Optional('notes', default=[]): OrValidator(Seq(Str()), EmptyList()),
            Optional('warnings', default=[]): OrValidator(Seq(Str()), EmptyList()),
            Optional('example', default=''): Str(),
            Optional('methods'): Seq(self.s_function),
            Optional('is_container', default=False): Bool()
        })

class FastTemplate(Template):
    d_feature_check: T.Dict[str, T.Any] = {
        'since': '',
        'deprecated': '',
    }

    s_posarg = {
        **d_feature_check,
        'default': '',
    }

    s_varargs: T.Dict[str, T.Any] = {
        **d_feature_check,
        'min_varargs': -1,
        'max_varargs': -1,
    }

    s_kwarg = {
        **d_feature_check,
        'required': False,
        'default': '',
    }

    s_function = {
        **d_feature_check,
        'notes': [],
        'warnings': [],
        'example': '',
        'posargs': {},
        'optargs': {},
        'varargs': None,
        'posargs_inherit': '',
        'optargs_inherit': '',
        'varargs_inherit': '',
        'kwargs': {},
        'kwargs_inherit': [],
        'arg_flattening': True,
    }

    s_object = {
        **d_feature_check,
        'extends': '',
        'notes': [],
        'warnings': [],
        'example': '',
        'methods': [],
        'is_container': False,
    }

class LoaderYAML(LoaderBase):
    def __init__(self, yaml_dir: Path, strict: bool=True) -> None:
        super().__init__()
        self.yaml_dir = yaml_dir
        self.func_dir = self.yaml_dir / 'functions'
        self.elem_dir = self.yaml_dir / 'elementary'
        self.objs_dir = self.yaml_dir / 'objects'
        self.builtin_dir = self.yaml_dir / 'builtins'
        self.modules_dir = self.yaml_dir / 'modules'
        self.strict = strict

        template: Template
        if self.strict:
            import strictyaml
            def loader(file: str, template: T.Any, label: str) -> T.Dict:
                r: T.Dict = strictyaml.load(file, template, label=label).data
                return r

            self._load = loader
            template = StrictTemplate()
        else:
            import yaml
            from yaml import CLoader
            def loader(file: str, template: T.Any, label: str) -> T.Dict:
                return {**template, **yaml.load(file, Loader=CLoader)}

            self._load = loader
            template = FastTemplate()

        self.template = template

    def _fix_default(self, v: T.Dict) -> None:
        if v["default"] is False:
            v["default"] = "false"
        elif v["default"] is True:
            v["default"] = "true"
        else:
            v["default"] = str(v["default"])

    def _process_function_base(self, raw: T.Dict, obj: T.Optional[Object] = None) -> Function:
        # Handle arguments
        posargs = raw.pop('posargs', {})
        optargs = raw.pop('optargs', {})
        varargs = raw.pop('varargs', None)
        kwargs = raw.pop('kwargs', {})

        # Fix kwargs_inherit
        if isinstance(raw['kwargs_inherit'], str):
            raw['kwargs_inherit'] = [raw['kwargs_inherit']]

        # Parse args
        posargs_mapped: T.List[PosArg] = []
        optargs_mapped: T.List[PosArg] = []
        varargs_mapped: T.Optional[VarArgs] = None
        kwargs_mapped: T.Dict[str, Kwarg] = {}

        for k, v in posargs.items():
            if not self.strict:
                v = {**self.template.s_posarg, **v}
                self._fix_default(v)
            v['type'] = Type(v['type'])
            posargs_mapped += [PosArg(name=k, **v)]

        for k, v in optargs.items():
            if not self.strict:
                v = {**self.template.s_posarg, **v}
                self._fix_default(v)
            v['type'] = Type(v['type'])
            optargs_mapped += [PosArg(name=k, **v)]

        for k, v in kwargs.items():
            if not self.strict:
                v = {**self.template.s_kwarg, **v}
                self._fix_default(v)
            v['type'] = Type(v['type'])
            kwargs_mapped[k] = Kwarg(name=k, **v)

        if varargs is not None:
            if not self.strict:
                varargs = {**self.template.s_varargs, **varargs}
            varargs['type'] = Type(varargs['type'])
            varargs_mapped = VarArgs(**varargs)

        raw['returns'] = Type(raw['returns'])

        # Build function object
        if obj is not None:
            return Method(
                posargs=posargs_mapped,
                optargs=optargs_mapped,
                varargs=varargs_mapped,
                kwargs=kwargs_mapped,
                obj=obj,
                **raw,
            )
        return Function(
            posargs=posargs_mapped,
            optargs=optargs_mapped,
            varargs=varargs_mapped,
            kwargs=kwargs_mapped,
            **raw,
        )

    def _load_function(self, path: Path, obj: T.Optional[Object] = None) -> Function:
        path_label = path.relative_to(self.yaml_dir).as_posix()
        mlog.log('Loading', mlog.bold(path_label))
        raw = self._load(self.read_file(path), self.template.s_function, label=path_label)
        return self._process_function_base(raw)

    def _load_object(self, obj_type: ObjectType, path: Path) -> Object:
        path_label = path.relative_to(self.yaml_dir).as_posix()
        mlog.log(f'Loading', mlog.bold(path_label))
        raw = self._load(self.read_file(path), self.template.s_object, label=path_label)

        def as_methods(mlist: T.List[Function]) -> T.List[Method]:
            res: T.List[Method] = []
            for i in mlist:
                assert isinstance(i, Method)
                res += [i]
            return res

        methods = raw.pop('methods', [])
        obj = Object(methods=[], obj_type=obj_type, **raw)

        newmethods = []
        for x in methods:
            if not self.strict:
                x = {**self.template.s_function, **x}
            newmethods += [self._process_function_base(x, obj)]
        obj.methods = as_methods(newmethods)
        return obj

    def _load_module(self, path: Path) -> T.List[Object]:
        assert path.is_dir()
        module = self._load_object(ObjectType.MODULE, path / 'module.yaml')
        objs = []
        for p in path.iterdir():
            if p.name == 'module.yaml':
                continue
            obj = self._load_object(ObjectType.RETURNED, p)
            obj.defined_by_module = module
            objs += [obj]
        return [module, *objs]

    def load_impl(self) -> ReferenceManual:
        mlog.log('Loading YAML reference manual')
        with mlog.nested():
            manual = ReferenceManual(
                functions=[self._load_function(x) for x in self.func_dir.iterdir()],
                objects=mesonlib.listify([
                    [self._load_object(ObjectType.ELEMENTARY, x) for x in self.elem_dir.iterdir()],
                    [self._load_object(ObjectType.RETURNED, x) for x in self.objs_dir.iterdir()],
                    [self._load_object(ObjectType.BUILTIN, x) for x in self.builtin_dir.iterdir()],
                    [self._load_module(x) for x in self.modules_dir.iterdir()]
                ], flatten=True)
            )

            if not self.strict:
                mlog.warning('YAML reference manual loaded using the best-effort fastyaml loader.  Results are not guaranteed to be stable or correct.')

            return manual

"""

```