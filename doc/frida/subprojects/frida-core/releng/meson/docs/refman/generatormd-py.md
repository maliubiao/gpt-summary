Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding: What is the Goal?**

The first step is to read the introductory comments and get the high-level purpose. The comments clearly state that this script, `generatormd.py`, is part of the Frida project and is responsible for generating Markdown documentation for the Frida API reference manual. It uses the Meson build system.

**2. Core Functionality: How Does it Achieve the Goal?**

Next, I look for the main logic. The class `GeneratorMD` inherits from `GeneratorBase`, suggesting a pattern for documentation generation. The `generate()` method seems to be the entry point. I see calls to methods like `_write_functions()`, `_write_object()`, and `_root_refman_docs()`. These clearly indicate the script's primary function: to take structured information about Frida's API and output Markdown files.

**3. Key Data Structures and Models:**

I then examine the imports. The `from .model import ...` line is crucial. It tells me that the script operates on objects defined in `model.py`. These objects (like `ReferenceManual`, `Function`, `Object`, etc.) represent the structure of the API documentation. This is a common design pattern – separate the data model from the generation logic.

**4. Markdown Generation Details:**

I look at how the Markdown is actually created. The `_write_file()` and `_write_template()` methods are key. `_write_file()` directly writes strings to files. `_write_template()` uses the `chevron` library for templating (Mustache). This means the script likely has `.mustache` files defining the structure of the Markdown, with placeholders filled in by the script. The `_gen_filename()` method shows how output filenames are constructed.

**5. Linking and Cross-Referencing:**

The `_link_to_object()` method and the generation of `link_def_out` suggest a mechanism for creating internal links within the documentation. The `[[@object_name]]` syntax is interesting – it looks like a custom tag that's later processed. The `_generate_link_def()` method creates a JSON file mapping these tags to actual URLs.

**6. Sitemap Generation:**

The `_configure_sitemap()` method manipulates a sitemap file. This indicates the script is also responsible for organizing the generated Markdown files into a navigable structure.

**7. Relationship to Reverse Engineering:**

Now, I start thinking about how this relates to reverse engineering. Frida is a dynamic instrumentation tool *used* in reverse engineering. This script generates the *documentation* for Frida. Therefore, while this script itself doesn't *perform* reverse engineering, the documentation it creates is *essential* for anyone using Frida for reverse engineering. Examples of API elements useful for reverse engineering (found later in the code via method names and the data model) would be things related to process manipulation, memory access, hooking, etc.

**8. Low-Level/Kernel/Framework Connections:**

I scan the code for hints about interactions with the OS. While this script primarily deals with documentation generation, the *subject matter* – the Frida API – definitely interacts with the OS. I keep this in mind but note that this script doesn't *directly* interact with the kernel or frameworks. The *documentation* will describe functions that *do* interact with those levels.

**9. Logic and Assumptions:**

I examine the conditional logic. For instance, the handling of different `ObjectType` in `_gen_object_file_id()` and the conditional inclusion of modules based on `enable_modules`. I also consider the assumptions made, like the input data conforming to the `model.py` definitions.

**10. Potential User Errors:**

I think about common mistakes a user might make. Incorrectly configuring the input data for the generator is a likely scenario. Also, issues with the templating system (Mustache files) could arise.

**11. Debugging Clues (How to Reach This Code):**

Finally, I trace the steps that would lead to the execution of this script. It's part of the Frida build process, specifically within the documentation generation phase. The user would likely be running Meson commands to build Frida's documentation.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** Maybe this script *directly* interacts with the kernel. **Correction:**  Realized it's documentation generation, so its interaction is indirect – it describes APIs that do the kernel interaction.
* **Initial thought:** Focused heavily on the code's direct actions. **Correction:**  Shifted focus to *why* this code exists and its role in the larger Frida ecosystem, especially its relevance to reverse engineering.
* **Overlooked:** Initially didn't fully appreciate the importance of the data model (`model.py`). **Correction:**  Recognized that the structure defined in `model.py` is the input to this script.

By following this systematic approach, I can thoroughly analyze the code and provide a comprehensive answer that addresses all aspects of the prompt. The key is to start with the high-level purpose and gradually delve into the details, constantly connecting the code back to its context within the Frida project and its relevance to reverse engineering.
这是 `frida/subprojects/frida-core/releng/meson/docs/refman/generatormd.py` 文件的源代码，它是一个用于 Frida 动态 instrumentation 工具的参考手册文档生成器。这个脚本使用 Markdown 格式生成文档。以下是它的功能分解和相关说明：

**主要功能:**

1. **读取 API 模型:**  这个脚本依赖于一个预先存在的 Frida API 模型（在其他地方定义和生成），该模型描述了 Frida 的各种类、方法、函数、参数和返回值等信息。

2. **生成 Markdown 文档:**  它遍历 API 模型中的数据，并根据预定义的模板（可能使用 Mustache 模板引擎，见 `_write_template` 函数）将这些信息转换成 Markdown 格式的文档。

3. **组织文档结构:**  它负责将不同的 API 元素（如模块、类、函数）组织成合适的 Markdown 文件，并生成一个 sitemap (`_configure_sitemap`) 来方便导航。

4. **生成链接定义:**  为了在生成的 Markdown 文档中实现内部链接，它会生成一个链接定义文件 (`_generate_link_def`)，用于将特定的标记（如 `[[@ObjectName]]`）映射到相应的文档位置。这通常与 Hotdoc 等文档工具配合使用。

**与逆向方法的关系:**

这个脚本本身并不直接执行逆向操作，但它生成的文档是 Frida 用户进行逆向工程的重要参考资料。

* **示例:** 假设 Frida 提供了一个名为 `Process.enumerateModules()` 的方法，用于枚举目标进程加载的模块。`generatormd.py` 会从 API 模型中读取关于 `Process.enumerateModules()` 的信息（参数、返回值、描述等），然后生成相应的 Markdown 文档，解释如何使用这个方法。逆向工程师在分析一个程序时，需要了解目标进程加载了哪些模块，这时就可以查阅 Frida 的文档，找到 `Process.enumerateModules()` 并了解其用法。

**涉及二进制底层、Linux、Android 内核及框架的知识:**

虽然这个脚本是高级的 Python 代码，但它所处理的数据和生成的文档内容是高度关联到底层知识的。

* **二进制底层:**  Frida 允许用户读取和修改进程的内存。文档中关于 `Memory.read*()` 和 `Memory.write*()` 系列函数的说明，涉及到对进程地址空间的理解，以及不同数据类型的二进制表示。
* **Linux 内核:** Frida 在 Linux 上运行需要与内核进行交互，例如通过 `ptrace` 系统调用进行进程注入和控制。文档中关于进程操作、信号处理等方面的 API 说明，反映了对 Linux 内核概念的抽象。
* **Android 内核及框架:** Frida 广泛用于 Android 平台的逆向工程。文档中关于 Android 特有的 API，例如与 ART 虚拟机交互、hook Java 方法、访问系统服务的说明，都需要理解 Android 框架的运作方式。
    * **示例:** 文档中可能会有关于 `Java.perform()` 函数的说明，该函数允许在 Android 进程的 Java 虚拟机上下文中执行代码。这需要理解 Android 的 Dalvik 或 ART 虚拟机的工作原理。

**逻辑推理 (假设输入与输出):**

假设 API 模型中定义了一个 `Function` 对象，表示 Frida 的一个全局函数 `send(data)`，其定义如下：

```json
{
  "name": "send",
  "description": "Sends data back to the host.",
  "returns": {
    "type": "void"
  },
  "posargs": [
    {
      "name": "data",
      "type": {
        "names": ["any"]
      },
      "description": "The data to send."
    }
  ]
}
```

`generatormd.py` 处理这个对象后，可能会生成如下 Markdown 代码片段（简化）：

```markdown
### send()

```
# Sends data back to the host.
void send(
  <b>data</b>            # The data to send.
)
```

**用户或编程常见的使用错误:**

* **API 模型不完整或错误:** 如果生成文档所依赖的 API 模型本身存在错误或信息缺失，生成的文档也会不准确或不完整。这可能是由于 Frida 的 API 定义不正确或者模型生成过程出现问题。
* **模板错误:**  如果 Mustache 模板文件中的语法错误，或者模板逻辑与 API 模型的结构不匹配，会导致文档生成失败或生成格式错误的 Markdown。
* **链接错误:**  如果在 `_generate_link_def` 中生成的链接映射不正确，或者在 Markdown 中使用的链接标记有误，会导致文档中的内部链接失效。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **开发者修改了 Frida 的 C/C++ 代码或 Python 绑定:**  Frida 的 API 变更通常会导致 API 模型的更新。
2. **运行 API 模型生成器:**  开发者会运行一个专门的工具（可能不是这个 `generatormd.py` 文件）来分析 Frida 的源代码并生成 API 模型。
3. **运行文档生成脚本 (`generatormd.py`):**  开发者或者 CI/CD 系统会执行 `generatormd.py` 脚本，通常是通过 Meson 构建系统触发。例如，可能会有类似 `meson compile -C builddir` 或 `ninja -C builddir` 的命令，其中会包含生成文档的目标。
4. **Meson 构建系统调用 `generatormd.py`:** Meson 会根据 `meson.build` 文件中的定义，知道需要运行 `generatormd.py` 脚本来生成 Markdown 文档。Meson 会将必要的参数传递给这个脚本，例如 API 模型文件的路径、输出目录等。
5. **`generatormd.py` 读取 API 模型并生成 Markdown 文件:**  脚本会读取生成的 API 模型数据，根据模板生成 Markdown 文件，并将其保存到指定的输出目录。
6. **文档发布:** 生成的 Markdown 文件可能会被进一步处理（例如使用 Hotdoc）并发布到 Frida 的官方文档网站。

**调试线索:**

如果文档出现问题，可以按照以下线索进行调试：

* **检查 API 模型:** 确认 API 模型是否包含了期望的信息，并且信息是正确的。
* **检查 `generatormd.py` 的日志输出:** 查看脚本运行时是否有错误或警告信息。
* **检查 Mustache 模板文件:** 确认模板语法是否正确，并且能够正确处理 API 模型中的数据。
* **检查生成的 Markdown 文件:** 查看生成的 Markdown 文件内容，确认格式是否正确，链接是否有效。
* **检查 Meson 的构建配置:** 确认 Meson 的构建配置是否正确，以及是否正确调用了 `generatormd.py` 脚本。

总而言之，`generatormd.py` 是 Frida 文档生成流程中的一个关键环节，它将结构化的 API 数据转换为用户友好的 Markdown 格式文档，对于 Frida 的用户（包括逆向工程师）来说至关重要。它虽然不直接参与逆向操作，但它生成的内容是进行逆向分析的基础参考。

Prompt: 
```
这是目录为frida/subprojects/frida-core/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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