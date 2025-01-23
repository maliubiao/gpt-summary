Response:
Let's break down the thought process for analyzing this Python script.

1. **Understand the Goal:** The first step is to recognize what this script is intended to do. The filename `generatormd.py` and the presence of terms like "ReferenceManual", "Function", "Object", and the output file extension ".md" strongly suggest this script is involved in generating documentation in Markdown format. The context within the `frida` project, specifically in the `releng/meson/docs/refman/` directory, reinforces this – it's about generating the reference manual.

2. **Identify Key Classes and Their Roles:**  Scan the imports and class definitions. The `GeneratorMD` class stands out as the main actor. The imports like `ReferenceManual`, `Function`, `Object`, etc., from the `model.py` file indicate this script processes a structured representation of the API. The presence of `GeneratorBase` suggests an inheritance structure, implying shared functionality with other potential documentation generators.

3. **Analyze the `GeneratorMD` Class Methods:** Go through the methods within `GeneratorMD` one by one. Pay attention to:
    * **`__init__`:**  Initialization of the generator, setting up input and output paths, and flags. The `enable_modules` flag is interesting, hinting at conditional behavior.
    * **`_gen_filename`:**  How output filenames are constructed. Notice the logic for removing numbers and the `_ROOT_BASENAME`.
    * **`_gen_object_file_id`:**  Crucial for creating unique identifiers for objects, which likely map to sections in the documentation. The recursive call for `ObjectType.RETURNED` is noteworthy.
    * **`_link_to_object`:**  Generating special tags `[[...]]`. This immediately signals a custom processing step later in the documentation pipeline.
    * **`_write_file` and `_write_template`:**  Core output mechanisms. The use of `chevron` for templating is a key detail.
    * **`_gen_func_or_method`:**  Detailed logic for formatting function and method documentation. The handling of different argument types (`posargs`, `optargs`, `kwargs`, `varargs`) is significant. The `render_type` function and the calculations for maximum lengths suggest careful formatting.
    * **`_write_object`:**  Generating documentation for objects, including their methods.
    * **`_write_functions`:**  Generating a separate section for standalone functions.
    * **`_root_refman_docs`:**  Creating the main index or table of contents. The `gen_obj_links` function and handling of modules are important.
    * **`generate`:** The main entry point, orchestrating the generation process.
    * **`_configure_sitemap`:**  How the generated Markdown files are organized into a navigable structure. The placeholder replacement mechanism is vital.
    * **`_generate_link_def`:**  Generating a JSON file containing mappings for the custom `[[...]]` tags.

4. **Identify Key Concepts and Their Implications:**  As you analyze the methods, connect them to broader concepts:
    * **API Documentation Generation:** The core purpose.
    * **Markdown:** The output format.
    * **Templating (Mustache/Chevron):**  Separating content from presentation.
    * **Sitemap:**  Organizing the generated documentation for navigation.
    * **Link Resolution:** The custom `[[...]]` tags and the `link_def_out` file indicate a post-processing step to create hyperlinks.
    * **Modules:** The `enable_modules` flag points to a modular structure in the documented API.

5. **Relate to Reverse Engineering:** Think about how documentation aids reverse engineering. Clear API documentation makes it easier to understand the functionality of a target system, identify entry points, and understand data structures. The detail in documenting function arguments and return types is particularly relevant.

6. **Connect to Low-Level Concepts:** Consider areas where this documentation process might touch on lower levels:
    * **Binary Structure:**  While the *generator* doesn't directly interact with binaries, the *documented API* likely does. The function and object names often correspond to concepts within the underlying binary.
    * **Operating System Concepts (Linux/Android):**  If Frida is documenting APIs related to system interaction, the documentation would reflect those concepts (e.g., process management, memory access).
    * **Kernel/Framework Knowledge:**  Similarly, the APIs might expose interfaces to kernel functionality or specific frameworks (like Android's runtime).

7. **Infer Logic and Examples:** For functions like `_gen_filename` and `_gen_object_file_id`, try to mentally trace how different inputs would lead to different outputs. This helps in understanding the logic. For example, how a nested module's ID is constructed.

8. **Consider User Errors:** Think about potential mistakes a user might make during the documentation generation process or when using the generated documentation. Misconfigured input files or incorrect usage of the custom link tags are possibilities.

9. **Trace User Operations (Debugging Context):**  Imagine how a developer working on Frida might end up looking at this specific file. They might be:
    * Debugging the documentation generation process itself.
    * Modifying the documentation structure or format.
    * Adding documentation for new Frida features.
    * Investigating why links are broken or incorrect.

10. **Structure the Answer:** Organize the findings into logical categories like "Functionality," "Relationship to Reverse Engineering," "Binary/Kernel Knowledge," etc., as requested in the prompt. Use clear and concise language, providing specific examples where possible. Use bullet points and formatting to improve readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just generates Markdown."  **Correction:**  It generates Markdown *with custom tags*, implying further processing.
* **Initial thought:** "The filenames are simple." **Correction:** There's specific logic to handle the root and numbered parts of the file IDs.
* **Initial thought:** "The linking is standard Markdown." **Correction:** The `[[...]]` syntax indicates a custom linking mechanism.

By following these steps, you can systematically analyze the provided code and extract the necessary information to answer the prompt effectively.
这个 Python 脚本 `generatormd.py` 是 Frida 工具链中负责生成参考手册文档的模块，它将结构化的 API 定义（由 `frida/subprojects/frida-gum/releng/meson/docs/refman/model.py` 定义）转换为 Markdown 格式的文档。

以下是它的功能列表，并结合了与逆向、二进制底层、Linux/Android 内核及框架、逻辑推理、用户错误以及调试线索的说明：

**主要功能：**

1. **读取 API 模型:**  该脚本接收一个 `ReferenceManual` 对象作为输入，这个对象包含了 Frida API 的结构化描述，包括类、方法、函数、参数、返回值等信息。

2. **生成 Markdown 文件:** 遍历 API 模型中的各种元素（模块、类、函数等），并将它们的信息格式化为 Markdown 文本。每个主要的 API 元素（如模块、类）通常会生成一个独立的 Markdown 文件。

3. **生成索引和导航:**  生成主索引文件 (`Reference-manual.md`)，其中包含指向各个模块、类和函数的链接，方便用户浏览文档。它还负责生成 `sitemap.txt` 文件，用于构建文档的网站导航。

4. **处理继承关系:**  能够识别和处理类之间的继承关系，并在文档中清晰地展示哪些方法是继承自父类的。

5. **处理函数和方法的签名:**  将函数和方法的签名（包括参数类型、名称、返回值类型）以易于阅读的格式生成到 Markdown 文档中。

6. **处理参数和返回值:**  详细记录函数和方法的参数（包括类型、描述、是否可选、默认值等）和返回值类型及描述。

7. **处理关键字参数 (kwargs):**  能够区分和记录 Python 中的关键字参数，并标记哪些是必需的。

8. **处理可变参数 (*args, **kwargs):**  能够处理和记录函数中的可变位置参数和关键字参数。

9. **生成代码示例:**  如果 API 模型中提供了代码示例，该脚本会将其嵌入到 Markdown 文档中，方便用户理解如何使用相关的 API。

10. **生成链接占位符:** 使用 `[[@object_name]]` 或 `[[object_name.method_name]]` 这样的占位符来链接到文档中的其他部分。这些占位符会在后续的处理步骤中被替换为实际的 Markdown 链接。

11. **生成链接定义文件:**  生成一个 `link_def.json` 文件，该文件定义了占位符到实际 Markdown 文件路径的映射关系，供后续的文档处理工具使用。

12. **使用模板:**  使用 `chevron` 库进行模板渲染，将 API 数据填充到预定义的 Markdown 模板中，实现代码和数据分离。

**与逆向方法的关系：**

* **API 文档作为逆向的起点:**  Frida 本身是一个动态插桩工具，用于运行时分析和修改程序行为。它的 API 文档对于想要使用 Frida 进行逆向工程的开发者至关重要。 `generatormd.py` 生成的文档帮助逆向工程师了解 Frida 提供的各种功能，例如如何附加到进程、hook 函数、读取和修改内存等。
    * **举例说明:**  假设逆向工程师想要使用 Frida 监控某个 Android 应用中特定函数的调用。他们会查阅 Frida 的 API 文档，找到相关的函数，例如 `Interceptor.attach()`, `NativeFunction()`, 或者 `Module.findExportByName()`. `generatormd.py` 生成的文档会详细说明这些函数的功能、参数和用法，从而指导逆向工程师编写 Frida 脚本。

**涉及二进制底层、Linux/Android 内核及框架的知识：**

* **API 反映底层概念:** Frida 的 API 往往抽象了底层的操作系统和体系结构概念。 `generatormd.py` 生成的文档中涉及的类和方法名称经常与这些底层概念相关。
    * **举例说明 (二进制底层):**  `Memory.readByteArray()`, `Memory.writeByteArray()` 等函数直接操作进程的内存空间，这涉及到对二进制数据结构的理解。文档会说明如何指定内存地址和读取/写入的字节数。
    * **举例说明 (Linux/Android 内核):**  Frida 可以用来 hook 系统调用。文档中可能会包含与系统调用相关的 API，例如如何获取系统调用的参数。在 Android 上，Frida 可以与 ART (Android Runtime) 交互，文档可能会包含与 ART 相关的类和方法。
    * **举例说明 (Android 框架):** Frida 可以 hook Android 应用的 Java 层代码。文档会包含与 Java 类和方法操作相关的 API，例如如何调用 Java 方法、访问 Java 对象字段等。

**逻辑推理 (假设输入与输出):**

假设 `model.py` 中定义了一个简单的 `Counter` 类，包含一个 `increment` 方法：

**假设输入 (API 模型 - 简化):**

```python
# 假设在 model.py 中
class Counter(Object):
    def __init__(self, name="Counter", description="A simple counter object."):
        super().__init__(name, description, ObjectType.ELEMENTARY)
        self.add_method(Function(
            name="increment",
            description="Increments the counter value.",
            returns=Type.from_string("void"),
            obj=self
        ))
```

**逻辑推理过程:**

`generatormd.py` 会：

1. **识别 `Counter` 对象:**  读取到 `ObjectType.ELEMENTARY` 的 `Counter` 对象。
2. **创建 Markdown 文件名:** 根据 `_gen_object_file_id()` 生成类似 `Reference-manual_elementary_Counter.md` 的文件名。
3. **生成对象文档:**  在 Markdown 文件中生成 `Counter` 的标题和描述。
4. **处理方法:** 识别 `increment` 方法。
5. **生成方法签名:**  根据 `increment` 方法的定义生成类似 `void increment()` 的签名。
6. **生成方法描述:**  将 "Increments the counter value." 添加到文档中。
7. **生成链接占位符:** 如果文档中其他地方需要链接到 `Counter` 或 `Counter.increment`，会生成 `[[@Counter]]` 或 `[[Counter.increment]]` 这样的占位符。

**假设输出 (部分 Markdown 内容 - `Reference-manual_elementary_Counter.md`):**

```markdown
# Counter

A simple counter object.

## Methods

### `increment`

```cpp
void increment()
```

Increments the counter value.
```

**涉及用户或编程常见的使用错误：**

* **API 模型不完整或错误:** 如果 `model.py` 中的 API 定义不完整或存在错误，`generatormd.py` 生成的文档也会不准确。例如，如果某个函数的参数类型定义错误，文档中显示的类型也会错误。
* **模板错误:** 如果模板文件（.mustache）存在语法错误，`chevron` 渲染时会出错，导致文档生成失败或格式混乱。
* **链接占位符未正确替换:** 如果后续的文档处理步骤未能正确处理 `[[...]]` 占位符，会导致文档中出现未解析的链接。
* **`sitemap.txt` 配置错误:**  如果 `sitemap_in` 文件配置错误，会导致生成的 `sitemap.txt` 结构不正确，影响网站导航。
* **文件路径错误:**  如果在运行脚本时，输入或输出的文件路径配置错误，会导致脚本无法找到输入文件或无法写入输出文件。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **Frida 开发或构建过程:**  开发者通常会在 Frida 的开发或构建过程中触发文档生成。这通常是构建系统（例如 Meson）的一部分。
2. **Meson 构建系统:**  Meson 会读取 `meson.build` 文件，其中定义了构建规则，包括文档生成。
3. **`meson.build` 调用 `generatormd.py`:**  `meson.build` 文件中会指定如何调用 `generatormd.py` 脚本，并传递必要的参数，例如 API 模型文件路径、输出目录、sitemap 输入/输出路径等。
4. **`generatormd.py` 执行:**  脚本读取 API 模型，遍历 API 定义，并根据模板生成 Markdown 文件。
5. **可能的用户调试场景:**
    * **文档未更新:**  如果开发者修改了 Frida 的 API，但生成的文档没有反映这些修改，他们可能会检查 `generatormd.py` 的逻辑，查看是否正确解析了新的 API 定义。
    * **链接错误:**  如果文档中的链接指向了错误的位置，开发者可能会检查 `_link_to_object()` 函数的生成逻辑以及 `link_def.json` 文件的内容。
    * **格式问题:**  如果生成的 Markdown 文档格式不正确，例如代码块没有正确渲染，开发者可能会检查模板文件和 `_gen_func_or_method()` 等函数的格式化逻辑。
    * **构建错误:**  如果在构建过程中文档生成失败，开发者会查看 Meson 的构建日志，定位到 `generatormd.py` 的执行过程，并检查传递给脚本的参数是否正确。他们可能会手动运行 `generatormd.py` 脚本进行调试。

总而言之，`generatormd.py` 是 Frida 文档生成流程的关键组成部分，它负责将 API 的结构化描述转换为用户可以阅读的 Markdown 文档，这对于 Frida 的使用者，特别是进行逆向工程的开发者来说至关重要。 了解这个脚本的功能和工作原理有助于理解 Frida 的文档生成流程，并在遇到文档问题时进行调试。

### 提示词
```
这是目录为frida/subprojects/frida-gum/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```python
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
```