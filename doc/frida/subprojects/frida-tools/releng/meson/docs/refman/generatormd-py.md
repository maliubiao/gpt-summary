Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding - What is this?**

The first line is crucial: "这是目录为frida/subprojects/frida-tools/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件". This tells us:

* **Context:** This script is part of the Frida dynamic instrumentation tool.
* **Location:** It resides within the documentation generation pipeline (`docs/refman`).
* **Purpose:** It's a Python script named `generatormd.py`. The "md" likely suggests it generates Markdown.

**2. High-Level Functionality - What does it do?**

Skimming the code reveals key imports and class names:

* `from .generatorbase import GeneratorBase`:  This indicates inheritance and a base class likely handles common generation tasks.
* `import re`, `import json`: Standard Python libraries for regular expressions and JSON handling, suggesting data manipulation and output formatting.
* `from .model import ...`:  Imports from a `model.py` file. This strongly suggests the script works with a structured representation of data – likely documentation elements like functions, classes, methods, etc.
* `from pathlib import Path`:  For interacting with the file system.
* `from textwrap import dedent`: For cleaning up multi-line strings.
* `import typing as T`: For type hinting, aiding readability and maintainability.
* `class GeneratorMD(GeneratorBase)`: The core class responsible for the Markdown generation.

Based on these, the primary function seems to be: **Taking a structured representation of Frida's API and generating Markdown documentation files.**

**3. Detailed Functionality - How does it do it?**

Now, we examine the methods of the `GeneratorMD` class:

* `__init__`: Initializes the generator, taking paths for sitemap and link definitions as input. This hints at integrating with a larger documentation system.
* `_gen_filename`: Generates output filenames based on input identifiers, ensuring a consistent naming scheme.
* `_gen_object_file_id`: Creates unique IDs for documentation objects, crucial for linking and sitemap generation.
* `_link_to_object`: Generates placeholder tags (e.g., `[[@ObjectName]]`, `[[FunctionName]]`) that are likely processed later by a documentation tool (Hotdoc, as mentioned in the comments). This is a key mechanism for cross-referencing.
* `_write_file`: Writes content to a Markdown file.
* `_write_template`: Uses a templating engine (Chevron) to generate Markdown from data and templates. This separates content from presentation.
* `_gen_func_or_method`:  The most complex method, responsible for formatting function and method documentation, including signatures, arguments, descriptions, examples, etc. It handles different argument types (positional, optional, keyword, variable).
* `_write_object`:  Generates Markdown for classes/objects, including their methods and inheritance relationships.
* `_write_functions`: Generates a page for standalone functions.
* `_root_refman_docs`: Generates the main index page of the reference manual.
* `generate`:  The main entry point, orchestrating the generation of all documentation files.
* `_configure_sitemap`: Updates a sitemap file with the generated Markdown file locations. This is vital for navigation within the documentation.
* `_generate_link_def`: Creates a JSON file that maps the placeholder tags (e.g., `@ObjectName`) to their actual file locations. This is how the documentation tool resolves the links.

**4. Connecting to Reverse Engineering, Binary, Kernel, etc.**

This requires connecting the *purpose* of Frida to the *mechanics* of the script:

* **Frida's Purpose:** Dynamic instrumentation means inspecting and modifying running processes. This often involves interacting with a program's internals, including its functions, objects, and data structures.
* **Script's Output:** The script generates *documentation* for Frida's API. This API is what allows users to *perform* dynamic instrumentation.

Therefore, the connection lies in documenting the *tools* used for reverse engineering.

* **Reverse Engineering:** The generated documentation describes how to use Frida's functions and methods to interact with target processes, which is a core part of reverse engineering. Examples can illustrate how to use Frida to inspect function arguments or hook function calls.
* **Binary/Low-Level:**  Frida operates at a low level, interacting with memory and system calls. The documentation might describe functions that allow reading and writing memory or intercepting system calls.
* **Linux/Android Kernel/Framework:** Frida supports these platforms. The documentation may include platform-specific functions or methods related to interacting with kernel components or Android framework services.

**5. Logic Reasoning (Input/Output)**

This involves understanding the data flow:

* **Input:** The script takes a `ReferenceManual` object (created elsewhere) as input. This object likely contains the parsed and structured representation of the Frida API. The sitemap and link definition input files are also important.
* **Processing:** The script iterates through the elements in the `ReferenceManual` (functions, objects, etc.) and uses templates and formatting logic to generate Markdown.
* **Output:** The primary output is a set of Markdown files, a modified sitemap file, and a link definition JSON file.

**6. Common User Errors**

This requires thinking about how someone might use the *documentation* generated by this script:

* **Misunderstanding Function Signatures:** Incorrectly using documented functions due to misinterpreting argument types or order.
* **Not Understanding Object Relationships:**  Trying to call a method on an object that doesn't inherit it.
* **Ignoring Notes and Warnings:**  Missing important caveats or limitations of specific API elements.

**7. User Operations Leading Here (Debugging Clues)**

This is about understanding how this script fits into the larger Frida development process:

* A developer modifies Frida's code, adding or changing API elements.
* The developer updates the documentation source (likely in a format the `model.py` understands).
* The Meson build system detects changes in the documentation and runs the `generatormd.py` script as part of the documentation generation step.
* If there's an error in the generated documentation, a developer might need to examine this script to understand why.

By following these steps, we can systematically analyze the Python script and extract the required information. The key is to understand the script's context, purpose, internal workings, and connections to the broader project and its users.
好的，让我们来详细分析一下 `frida/subprojects/frida-tools/releng/meson/docs/refman/generatormd.py` 这个 Python 脚本的功能。

**核心功能：**

这个脚本的主要功能是 **根据 Frida 的 API 定义生成 Markdown 格式的参考手册文档**。它属于 Frida 工具链中用于构建文档的一部分，具体来说是为 Meson 构建系统生成 Frida API 的参考文档。

**功能分解：**

1. **读取 API 模型数据:**  脚本依赖于 `from .model import ...` 导入的各种类，如 `ReferenceManual`, `Function`, `Object` 等。这些类定义了 Frida API 的结构化表示。在脚本运行之前，很可能存在其他步骤（可能是其他 Python 脚本或 Meson 构建逻辑）解析 Frida 的源代码或某种 API 定义文件，并将结果填充到这些模型类中。

2. **生成 Markdown 文件:** 脚本的核心任务是将这些结构化的 API 数据转换成易于阅读的 Markdown 文件。它通过以下方式实现：
   - **组织文件结构:**  使用 `_gen_filename` 方法为不同的 API 组件（如根目录、模块、对象、函数）生成规范的文件名。
   - **生成对象文档:** `_write_object` 方法负责为每个 API 对象（例如类、模块）生成独立的 Markdown 文件，包含对象的描述、方法、继承关系等信息。
   - **生成函数文档:** `_gen_func_or_method` 方法负责为每个函数或方法生成详细的 Markdown 文档，包括签名、参数、返回值、描述、示例等。
   - **生成根目录文档:** `_root_refman_docs` 方法生成参考手册的根目录文件，其中会列出所有模块、内置对象、函数等，并提供链接。
   - **使用模板:** 脚本使用了 `chevron` 模板引擎（通过 `_write_template` 方法）来将数据渲染到预定义的 Markdown 模板中，这样可以将文档的结构和内容分离。

3. **生成链接定义:** `_generate_link_def` 方法生成一个 JSON 文件，用于定义文档内部的链接。这个文件会被 Hotdoc (Frida 使用的文档生成工具) 解析，将类似 `[[@ObjectName]]` 或 `[[FunctionName]]` 的占位符替换成实际的 HTML 链接。

4. **配置站点地图 (Sitemap):** `_configure_sitemap` 方法将生成的 Markdown 文件的信息添加到站点地图文件中。站点地图用于指导文档生成工具（如 Hotdoc）如何组织和索引生成的 HTML 页面。

**与逆向方法的关系：**

这个脚本本身并不直接执行逆向操作，但它生成的文档是逆向工程师使用 Frida 进行动态分析的关键资源。

* **API 参考:**  逆向工程师需要了解 Frida 提供的各种函数和方法才能编写 Frida 脚本来操控目标进程。`generatormd.py` 生成的文档提供了这些 API 的详细说明，包括参数类型、返回值、功能描述等。
* **理解 Frida 功能:**  通过阅读参考手册，逆向工程师可以了解 Frida 的各种能力，例如进程注入、函数 Hook、内存读写、代码修改等，并学习如何使用相应的 API 实现这些功能。
* **快速查找:**  结构化的 Markdown 文档和生成的链接使得逆向工程师可以快速查找需要的 API 信息。

**举例说明:**

假设 Frida 提供了一个名为 `Interceptor.attach` 的方法，用于 Hook 目标进程中的函数。`generatormd.py` 可能会生成类似以下的 Markdown 文档片段：

```markdown
### Interceptor.attach

```cpp
void attach(NativePointer target, object callbacks)
```

Attaches to the function at the specified `target` address.

**参数：**

* `target`: `NativePointer` - The address of the function to attach to.
* `callbacks`: `object` - An object containing callback functions to be invoked before and/or after the target function is executed.

**示例：**

```javascript
Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
  onEnter: function (args) {
    console.log('Opening file:', args[0].readUtf8String());
  },
  onLeave: function (retval) {
    console.log('File descriptor:', retval);
  }
});
```

逆向工程师通过阅读这份文档，可以了解到 `Interceptor.attach` 的用法，包括需要传入目标地址和回调对象，以及如何使用 `onEnter` 和 `onLeave` 回调来在函数执行前后进行操作。

**涉及二进制底层、Linux、Android 内核及框架的知识：**

虽然脚本本身是高级的 Python 代码，但它生成的文档内容深刻地关联着底层的知识。

* **二进制底层:**  Frida 的许多 API 都直接操作内存地址、寄存器等二进制层面的概念。文档中会涉及到 `NativePointer` 类型，它代表了进程内存中的地址。Hook 技术本身也涉及到修改二进制代码或指令。
* **Linux/Android 内核:**  Frida 可以在 Linux 和 Android 平台上运行，并与操作系统内核进行交互。一些 Frida 的 API 可能涉及到系统调用、进程管理、内存管理等内核概念。
* **Android 框架:**  在 Android 平台上，Frida 可以 Hook Java 层的方法。文档中会描述如何使用 Frida 与 Android 框架进行交互，例如 Hook Activity 的生命周期方法或 Service 的回调函数。

**举例说明:**

文档中可能会描述一个名为 `Memory.readByteArray(address, length)` 的函数，用于读取指定地址的内存数据。这直接涉及到进程的内存布局和二进制数据。在 Android 上，可能会有描述如何使用 `Java.use("className")` 来获取 Java 类的引用，这直接关联到 Android 虚拟机的运行机制。

**逻辑推理 (假设输入与输出)：**

假设 `model.py` 构建了一个 `ReferenceManual` 对象，其中包含了对 `Interceptor.attach` 方法的描述，如下所示（简化版）：

```python
# 假设的 model.py 中的数据结构
function_attach = Function(
    name="attach",
    description="Attaches to a function.",
    returns=Type("void"),
    args=[
        PosArg(name="target", type=Type("NativePointer"), description="The address to attach."),
        PosArg(name="callbacks", type=Type("object"), description="Callbacks object."),
    ],
    obj=interceptor_object  # 关联到 Interceptor 对象
)

interceptor_object = Object(
    name="Interceptor",
    description="Provides function interception capabilities.",
    methods=[function_attach]
)

reference_manual = ReferenceManual(
    objects=[interceptor_object]
)
```

当 `generatormd.py` 处理这个 `reference_manual` 时，它会：

1. **识别 `interceptor_object`:**  它会根据对象的类型（可能是 `ObjectType.BUILTIN` 或其他）和名称生成一个唯一的文件 ID，例如 `root.builtin.Interceptor.md`。
2. **为 `Interceptor` 对象生成 Markdown:** 在 `_write_object` 方法中，它会提取 `Interceptor` 的描述，并遍历其 `methods` 列表。
3. **为 `attach` 方法生成 Markdown:** 在 `_gen_func_or_method` 方法中，它会提取 `attach` 方法的名称、参数、返回值和描述，并根据预定义的模板生成 Markdown 代码块。
4. **生成链接:**  会生成 `[[Interceptor.attach]]` 这样的链接占位符，并在 `_generate_link_def` 中将其映射到 `root_builtin_Interceptor.html#Interceptorattach` (假设经过 Hotdoc 处理后的文件名)。

**假设输入:** 上述简化的 `ReferenceManual` 对象。

**预期输出 (部分):**

* **`root_builtin_Interceptor.md` (片段):**
  ```markdown
  ## Interceptor

  Provides function interception capabilities.

  ### attach

  ```cpp
  void attach(NativePointer target, object callbacks)
  ```

  Attaches to the function at the specified `target` address.

  **参数：**

  * `target`: `NativePointer` - The address to attach to.
  * `callbacks`: `object` - An object containing callback functions to be invoked before and/or after the target function is executed.
  ```

* **`refman_links.json` (片段):**
  ```json
  {
    "@Interceptor": "root_builtin_Interceptor.html",
    "Interceptor.attach": "root_builtin_Interceptor.html#Interceptorattach"
  }
  ```

**用户或编程常见的使用错误 (如果涉及)：**

这个脚本本身是文档生成工具，直接的用户交互较少。但它在开发过程中可能会遇到一些错误：

1. **API 模型数据不完整或错误:** 如果 `model.py` 提供的 API 数据缺少必要的字段（例如，函数缺少描述或参数类型），`generatormd.py` 生成的文档也会不完整。
2. **模板错误:** 如果 Mustache 模板文件存在语法错误，`chevron` 渲染过程会失败。
3. **文件路径配置错误:**  如果在初始化 `GeneratorMD` 时提供的 `sitemap_out`、`sitemap_in` 或 `link_def_out` 路径不正确，会导致文件生成到错误的位置或无法读取输入文件。
4. **编码问题:**  在读取或写入文件时，如果编码设置不正确，可能会导致乱码。脚本中指定了 `encoding='ascii'`，这可能是一个潜在的问题，如果 API 描述中包含非 ASCII 字符。

**举例说明:**

如果 `model.py` 中 `Interceptor.attach` 方法的 `target` 参数的 `description` 字段为空，那么生成的 Markdown 文档中关于 `target` 参数的描述部分将会缺失。

**用户操作如何一步步地到达这里，作为调试线索：**

作为一个开发人员，当你需要调试 `generatormd.py` 时，你可能经历以下步骤：

1. **观察到文档错误:**  用户报告文档中缺少某个函数的描述，或者链接失效。
2. **定位到生成错误的文档部分:**  确定是哪个 API 的文档出了问题。
3. **追溯文档生成流程:**  意识到 Frida 使用 Meson 构建系统生成文档。
4. **查看 Meson 构建文件:**  查找与文档生成相关的目标或命令。你可能会找到执行 `generatormd.py` 的相关调用。
5. **检查 `generatormd.py` 的日志或输出:**  如果构建系统有详细的日志，你可以查看 `generatormd.py` 的执行过程，看是否有报错信息。
6. **检查 API 模型数据:**  查看生成文档所依赖的 `model.py` 生成的 API 数据，确认数据是否正确。
7. **调试 `generatormd.py` 代码:**  如果怀疑是 `generatormd.py` 本身的逻辑问题，你可能会添加打印语句或使用调试器来单步执行代码，查看数据处理过程。
8. **检查模板文件:**  确认相关的 Mustache 模板文件是否正确。
9. **检查文件路径配置:**  核对传递给 `GeneratorMD` 的文件路径是否正确。

总而言之，`generatormd.py` 是 Frida 文档生成流程中的一个关键环节，它负责将结构化的 API 数据转换成用户友好的 Markdown 格式参考手册，这对于 Frida 的使用者，尤其是逆向工程师，来说是至关重要的资源。理解其功能有助于我们更好地理解 Frida 的文档生成过程和如何使用 Frida 进行逆向分析。

Prompt: 
```
这是目录为frida/subprojects/frida-tools/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 The Meson development team

from .generatorbase import GeneratorBase
import re
import json

from .model import (
    ReferenceManual,
    Function,
    Method,
    Object,
    ObjectType,
    Type,
    DataTypeInfo,
    ArgBase,
    PosArg,
    VarArgs,
    Kwarg,
)

from pathlib import Path
from textwrap import dedent
import typing as T

from mesonbuild import mlog

PlaceholderTypes = T.Union[None, str, bool]
FunctionDictType = T.Dict[
    str,
    T.Union[
        PlaceholderTypes,
        T.Dict[str, PlaceholderTypes],
        T.Dict[str, T.Dict[str, PlaceholderTypes]],
        T.Dict[str, T.List[T.Dict[str, PlaceholderTypes]]],
        T.List[T.Dict[str, PlaceholderTypes]],
        T.List[str],
    ]
]

_ROOT_BASENAME = 'Reference-manual'

_OBJ_ID_MAP = {
    ObjectType.ELEMENTARY: 'elementary',
    ObjectType.BUILTIN: 'builtin',
    ObjectType.MODULE: 'module',
    ObjectType.RETURNED: 'returned',
}

# Indent all but the first line with 4*depth spaces.
# This function is designed to be used with `dedent`
# and fstrings where multiline strings are used during
# the string interpolation.
def smart_indent(raw: str, depth: int = 3) -> str:
    lines = raw.split('\n')
    first_line = lines[0]
    lines = [' ' * (4 * depth) + x for x in lines]
    lines[0] = first_line  # Do not indent the first line
    return '\n'.join(lines)

def code_block(code: str) -> str:
    code = dedent(code)
    return f'<pre><code class="language-meson">{code}</code></pre>'

class GeneratorMD(GeneratorBase):
    def __init__(self, manual: ReferenceManual, sitemap_out: Path, sitemap_in: Path, link_def_out: Path, enable_modules: bool) -> None:
        super().__init__(manual)
        self.sitemap_out = sitemap_out.resolve()
        self.sitemap_in = sitemap_in.resolve()
        self.link_def_out = link_def_out.resolve()
        self.out_dir = self.sitemap_out.parent
        self.enable_modules = enable_modules
        self.generated_files: T.Dict[str, str] = {}

    # Utility functions
    def _gen_filename(self, file_id: str, *, extension: str = 'md') -> str:
        parts = file_id.split('.')
        assert parts[0] == 'root'
        assert all([x for x in parts])
        parts[0] = _ROOT_BASENAME
        parts = [re.sub(r'[0-9]+_', '', x) for x in parts]
        return f'{"_".join(parts)}.{extension}'

    def _gen_object_file_id(self, obj: Object) -> str:
        '''
            Deterministically generate a unique file ID for the Object.

            This ID determines where the object will be inserted in the sitemap.
        '''
        if obj.obj_type == ObjectType.RETURNED and obj.defined_by_module is not None:
            base = self._gen_object_file_id(obj.defined_by_module)
            return f'{base}.{obj.name}'
        return f'root.{_OBJ_ID_MAP[obj.obj_type]}.{obj.name}'

    def _link_to_object(self, obj: T.Union[Function, Object], in_code_block: bool = False) -> str:
        '''
            Generate a palaceholder tag for the function/method/object documentation.
            This tag is then replaced in the custom hotdoc plugin.
        '''
        prefix = '#' if in_code_block else ''
        if isinstance(obj, Object):
            return f'[[{prefix}@{obj.name}]]'
        elif isinstance(obj, Method):
            return f'[[{prefix}{obj.obj.name}.{obj.name}]]'
        elif isinstance(obj, Function):
            return f'[[{prefix}{obj.name}]]'
        else:
            raise RuntimeError(f'Invalid argument {obj}')

    def _write_file(self, data: str, file_id: str) -> None:#
        ''' Write the data to disk and store the id for the generated data '''

        self.generated_files[file_id] = self._gen_filename(file_id)
        out_file = self.out_dir / self.generated_files[file_id]
        out_file.write_text(data, encoding='ascii')
        mlog.log('Generated', mlog.bold(out_file.name))

    def _write_template(self, data: T.Dict[str, T.Any], file_id: str, template_name: T.Optional[str] = None) -> None:
        ''' Render the template mustache files and write the result '''
        template_dir = Path(__file__).resolve().parent / 'templates'
        template_name = template_name or file_id
        template_name = f'{template_name}.mustache'
        template_file = template_dir / template_name

        # Import here, so that other generators don't also depend on it
        import chevron
        result = chevron.render(
            template=template_file.read_text(encoding='utf-8'),
            data=data,
            partials_path=template_dir.as_posix(),
            warn=True,
        )

        self._write_file(result, file_id)


    # Actual generator functions
    def _gen_func_or_method(self, func: Function) -> FunctionDictType:
        def render_type(typ: Type, in_code_block: bool = False) -> str:
            def data_type_to_str(dt: DataTypeInfo) -> str:
                base = self._link_to_object(dt.data_type, in_code_block)
                if dt.holds:
                    return f'{base}[{render_type(dt.holds, in_code_block)}]'
                return base
            assert typ.resolved
            return ' | '.join([data_type_to_str(x) for x in typ.resolved])

        def len_stripped(s: str) -> int:
            s = s.replace(']]', '')
            # I know, this regex is ugly but it works.
            return len(re.sub(r'\[\[(#|@)*([^\[])', r'\2', s))

        def arg_anchor(arg: ArgBase) -> str:
            return f'{func.name}_{arg.name.replace("<", "_").replace(">", "_")}'

        def render_signature() -> str:
            # Skip a lot of computations if the function does not take any arguments
            if not any([func.posargs, func.optargs, func.kwargs, func.varargs]):
                return f'{render_type(func.returns, True)} {func.name}()'

            signature = dedent(f'''\
                # {self.brief(func)}
                {render_type(func.returns, True)} {func.name}(
            ''')

            # Calculate maximum lengths of the type and name
            all_args: T.List[ArgBase] = []
            all_args += func.posargs
            all_args += func.optargs
            all_args += [func.varargs] if func.varargs else []

            max_type_len = 0
            max_name_len = 0
            if all_args:
                max_type_len = max([len_stripped(render_type(x.type)) for x in all_args])
                max_name_len = max([len(x.name) for x in all_args])

            # Generate some common strings
            def prepare(arg: ArgBase, link: bool = True) -> T.Tuple[str, str, str, str]:
                type_str = render_type(arg.type, True)
                type_len = len_stripped(type_str)
                type_space = ' ' * (max_type_len - type_len)
                name_space = ' ' * (max_name_len - len(arg.name))
                name_str = f'<b>{arg.name.replace("<", "&lt;").replace(">", "&gt;")}</b>'
                if link:
                    name_str = f'<a href="#{arg_anchor(arg)}">{name_str}</a>'

                return type_str, type_space, name_str, name_space

            for i in func.posargs:
                type_str, type_space, name_str, name_space = prepare(i)
                signature += f'  {type_str}{type_space} {name_str},{name_space}     # {self.brief(i)}\n'

            for i in func.optargs:
                type_str, type_space, name_str, name_space = prepare(i)
                signature += f'  {type_str}{type_space} [{name_str}],{name_space}   # {self.brief(i)}\n'

            if func.varargs:
                type_str, type_space, name_str, name_space = prepare(func.varargs, link=False)
                signature += f'  {type_str}{type_space} {name_str}...,{name_space}  # {self.brief(func.varargs)}\n'

            # Abort if there are no kwargs
            if not func.kwargs:
                return signature + ')'

            # Only add this separator if there are any posargs
            if all_args:
                signature += '\n  # Keyword arguments:\n'

            # Recalculate lengths for kwargs
            all_args = list(func.kwargs.values())
            max_type_len = max([len_stripped(render_type(x.type)) for x in all_args])
            max_name_len = max([len(x.name) for x in all_args])

            for kwarg in self.sorted_and_filtered(list(func.kwargs.values())):
                type_str, type_space, name_str, name_space = prepare(kwarg)
                required = ' <i>[required]</i> ' if kwarg.required else '            '
                required = required if any([x.required for x in func.kwargs.values()]) else ''
                signature += f'  {name_str}{name_space} : {type_str}{type_space} {required} # {self.brief(kwarg)}\n'

            return signature + ')'

        def gen_arg_data(arg: T.Union[PosArg, Kwarg, VarArgs], *, optional: bool = False) -> T.Dict[str, PlaceholderTypes]:
            data: T.Dict[str, PlaceholderTypes] = {
                'row-id': arg_anchor(arg),
                'name': arg.name,
                'type': render_type(arg.type),
                'description': arg.description,
                'since': arg.since or None,
                'deprecated': arg.deprecated or None,
                'optional': optional,
                'default': None,
            }

            if isinstance(arg, VarArgs):
                data.update({
                    'min': str(arg.min_varargs) if arg.min_varargs > 0 else '0',
                    'max': str(arg.max_varargs) if arg.max_varargs > 0 else 'infinity',
                })
            if isinstance(arg, (Kwarg, PosArg)):
                data.update({'default': arg.default or None})
            if isinstance(arg, Kwarg):
                data.update({'required': arg.required})
            return data

        mname = f'\\{func.name}' if func.name == '[index]' else func.name

        data: FunctionDictType = {
            'name': f'{func.obj.name}.{mname}' if isinstance(func, Method) else func.name,
            'base_level': '##' if isinstance(func, Method) else '#',
            'type_name_upper': 'Method' if isinstance(func, Method) else 'Function',
            'type_name': 'method' if isinstance(func, Method) else 'function',
            'description': func.description,
            'notes': func.notes,
            'warnings': func.warnings,
            'example': func.example or None,
            'signature_level': 'h4' if isinstance(func, Method) else 'h3',
            'signature': render_signature(),
            'has_args': bool(func.posargs or func.optargs or func.kwargs or func.varargs),
            # Merge posargs and optargs by generating the *[optional]* tag for optargs
            'posargs': {
                'args': [gen_arg_data(x) for x in func.posargs] + [gen_arg_data(x, optional=True) for x in func.optargs]
            } if func.posargs or func.optargs else None,
            'kwargs':  {'args': [gen_arg_data(x) for x in self.sorted_and_filtered(list(func.kwargs.values()))]} if func.kwargs else None,
            'varargs': gen_arg_data(func.varargs) if func.varargs else None,
            'arg_flattening': func.arg_flattening,

            # For the feature taggs template
            'since': func.since or None,
            'deprecated': func.deprecated or None,
            'optional': False,
            'default': None
        }

        return data

    def _write_object(self, obj: Object) -> None:
        data = {
            'name': obj.name,
            'title': obj.long_name if obj.obj_type == ObjectType.RETURNED else obj.name,
            'description': obj.description,
            'notes': obj.notes,
            'warnings': obj.warnings,
            'long_name': obj.long_name,
            'obj_type_name': _OBJ_ID_MAP[obj.obj_type].capitalize(),
            'example': obj.example or None,
            'has_methods': bool(obj.methods),
            'has_inherited_methods': bool(obj.inherited_methods),
            'has_subclasses': bool(obj.extended_by),
            'is_returned': bool(obj.returned_by),
            'extends': obj.extends_obj.name if obj.extends_obj else None,
            'returned_by': [self._link_to_object(x) for x in self.sorted_and_filtered(obj.returned_by)],
            'extended_by': [self._link_to_object(x) for x in self.sorted_and_filtered(obj.extended_by)],
            'methods': [self._gen_func_or_method(m) for m in self.sorted_and_filtered(obj.methods)],
            'inherited_methods': [self._gen_func_or_method(m) for m in self.sorted_and_filtered(obj.inherited_methods)],
        }

        self._write_template(data, self._gen_object_file_id(obj), 'object')

    def _write_functions(self) -> None:
        data = {'functions': [self._gen_func_or_method(x) for x in self.functions]}
        self._write_template(data, 'root.functions')

    def _root_refman_docs(self) -> None:
        def gen_obj_links(objs: T.List[Object]) -> T.List[T.Dict[str, str]]:
            ret: T.List[T.Dict[str, str]] = []
            for o in objs:
                ret += [{'indent': '', 'link': self._link_to_object(o), 'brief': self.brief(o)}]
                for m in self.sorted_and_filtered(o.methods):
                    ret += [{'indent': '  ', 'link': self._link_to_object(m), 'brief': self.brief(m)}]
                if o.obj_type == ObjectType.MODULE and self.extract_returned_by_module(o):
                    tmp = gen_obj_links(self.extract_returned_by_module(o))
                    tmp = [{**x, 'indent': '  ' + x['indent']} for x in tmp]
                    ret += [{'indent': '  ', 'link': '**New objects:**', 'brief': ''}]
                    ret += [*tmp]
            return ret

        data = {
            'root': self._gen_filename('root'),
            'elementary': gen_obj_links(self.elementary),
            'returned': gen_obj_links(self.returned),
            'builtins': gen_obj_links(self.builtins),
            'modules': gen_obj_links(self.modules),
            'functions': [{'indent': '', 'link': self._link_to_object(x), 'brief': self.brief(x)} for x in self.functions],
            'enable_modules': self.enable_modules,
        }

        dummy = {'root': self._gen_filename('root')}

        self._write_template(data, 'root')
        self._write_template({**dummy, 'name': 'Elementary types'}, f'root.{_OBJ_ID_MAP[ObjectType.ELEMENTARY]}', 'dummy')
        self._write_template({**dummy, 'name': 'Builtin objects'},  f'root.{_OBJ_ID_MAP[ObjectType.BUILTIN]}',    'dummy')
        self._write_template({**dummy, 'name': 'Returned objects'}, f'root.{_OBJ_ID_MAP[ObjectType.RETURNED]}',   'dummy')

        if self.enable_modules:
            self._write_template({**dummy, 'name': 'Modules'},          f'root.{_OBJ_ID_MAP[ObjectType.MODULE]}',     'dummy')


    def generate(self) -> None:
        mlog.log('Generating markdown files...')
        with mlog.nested():
            self._write_functions()
            for obj in self.objects:
                if not self.enable_modules and (obj.obj_type == ObjectType.MODULE or obj.defined_by_module is not None):
                    continue
                self._write_object(obj)
            self._root_refman_docs()
            self._configure_sitemap()
            self._generate_link_def()

    def _configure_sitemap(self) -> None:
        '''
            Replaces the `@REFMAN_PLACEHOLDER@` placeholder with the reference
            manual sitemap. The structure of the sitemap is derived from the
            file IDs.
        '''
        raw = self.sitemap_in.read_text(encoding='utf-8')
        out = ''
        for l in raw.split('\n'):
            if '@REFMAN_PLACEHOLDER@' not in l:
                out += f'{l}\n'
                continue
            mlog.log('Generating', mlog.bold(self.sitemap_out.as_posix()))
            base_indent = l.replace('@REFMAN_PLACEHOLDER@', '')
            for k in sorted(self.generated_files.keys()):
                indent = base_indent + '\t' * k.count('.')
                out += f'{indent}{self.generated_files[k]}\n'
        self.sitemap_out.write_text(out, encoding='utf-8')

    def _generate_link_def(self) -> None:
        '''
            Generate the link definition file for the refman_links hotdoc
            plugin. The plugin is then responsible for replacing the [[tag]]
            tags with custom HTML elements.
        '''
        data: T.Dict[str, str] = {}

        # Objects and methods
        for obj in self.objects:
            obj_file = self._gen_filename(self._gen_object_file_id(obj), extension='html')
            data[f'@{obj.name}'] = obj_file
            for m in obj.methods:
                data[f'{obj.name}.{m.name}'] = f'{obj_file}#{obj.name}{m.name}'

        # Functions
        funcs_file = self._gen_filename('root.functions', extension='html')
        for fn in self.functions:
            data[fn.name] = f'{funcs_file}#{fn.name}'

        self.link_def_out.write_text(json.dumps(data, indent=2), encoding='utf-8')

"""

```