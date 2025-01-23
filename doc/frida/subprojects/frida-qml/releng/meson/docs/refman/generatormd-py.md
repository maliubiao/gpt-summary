Response:
Let's break down the thought process for analyzing the `generatormd.py` script.

1. **Understanding the Core Purpose:** The filename `generatormd.py` and the import of `GeneratorBase` immediately suggest this script is responsible for generating documentation in Markdown format. The "fridaDynamic instrumentation tool" context confirms it's generating documentation for the Frida project. The `releng/meson/docs/refman` path pinpoints its role in generating the reference manual.

2. **Dissecting Imports:** Examining the imports reveals the script's dependencies and functionalities:
    * `.generatorbase`:  Likely contains common logic for documentation generators within the Frida project.
    * `re`: Regular expressions for string manipulation, probably used for file naming.
    * `json`:  For generating the `link_def.json` file.
    * `.model`:  Crucial. This strongly indicates a data model exists that represents the structure of the documentation (functions, methods, objects, etc.). This will be the primary input to the generator.
    * `pathlib.Path`:  For handling file paths in a platform-independent way.
    * `textwrap.dedent`:  For cleaning up multi-line strings in code examples.
    * `typing as T`:  For type hinting, improving code readability and maintainability.
    * `mesonbuild.mlog`: For logging messages during the generation process.
    * `chevron`: A templating engine (likely Mustache) for generating Markdown from structured data.

3. **Analyzing Key Classes and Functions:**

    * **`GeneratorMD` Class:** This is the main class doing the work. Its `__init__` method shows it takes the parsed documentation data (`ReferenceManual`), input/output paths for sitemap and link definitions, and a flag for enabling modules.
    * **File Naming (`_gen_filename`):**  The logic here is critical for organizing the generated documentation. It transforms logical IDs into human-readable filenames. The regex suggests cleaning up numbering prefixes.
    * **Object Linking (`_link_to_object`):** This function generates placeholder tags (`[[...]]`) which are later processed by a custom Hotdoc plugin. This is a key point related to Frida's documentation infrastructure.
    * **File Writing (`_write_file`, `_write_template`):**  These functions handle saving the generated Markdown to disk. `_write_template` leverages the `chevron` library, confirming the template-based approach.
    * **Function/Method Generation (`_gen_func_or_method`):**  This is a complex function responsible for formatting the documentation for individual functions and methods. It handles argument lists, return types, descriptions, examples, etc. The detailed formatting logic (padding, links) is important.
    * **Object Generation (`_write_object`):**  Similar to function generation but for objects. It includes sections for methods (including inherited ones), subclasses, etc.
    * **Root Reference Manual Generation (`_root_refman_docs`):** This creates the top-level index page, linking to different sections (elementary types, builtins, modules, functions).
    * **Sitemap Configuration (`_configure_sitemap`):** This function takes an input sitemap and inserts the generated documentation structure into it. The placeholder mechanism is interesting.
    * **Link Definition Generation (`_generate_link_def`):** This creates the `link_def.json` file, which maps the placeholder tags to actual URLs within the generated documentation. This is essential for the custom Hotdoc plugin to work.
    * **`generate` Method:**  The main entry point for the generation process. It orchestrates the creation of individual files and the sitemap/link definitions.

4. **Connecting to Reverse Engineering, Binary/Kernel, and User Errors:**

    * **Reverse Engineering:**  Frida is a dynamic instrumentation tool heavily used in reverse engineering. The documentation for Frida *itself* is crucial for reverse engineers using it. The examples need to reflect common reverse engineering tasks.
    * **Binary/Kernel/Framework:**  Frida often interacts with the low-level aspects of operating systems and applications. The documentation may contain references to concepts like processes, threads, memory, etc. The examples should showcase this interaction.
    * **User Errors:** Common mistakes when using Frida (and thus when interpreting the documentation) might involve incorrect function calls, wrong argument types, or misunderstanding object relationships. The documentation should strive for clarity and potentially highlight common pitfalls.

5. **Logical Reasoning (Input/Output):**

    * **Input:**  The primary input is the `ReferenceManual` object. This object is presumably created by parsing some form of structured documentation source (likely in the Frida project).
    * **Output:** The script outputs a set of Markdown files, a sitemap file, and a link definition JSON file. The structure of the Markdown files reflects the organization of the input `ReferenceManual`.

6. **Debugging Clues (User Operations):**

    * The file path `frida/subprojects/frida-qml/releng/meson/docs/refman/generatormd.py` provides a strong clue. A user would likely be working within the Frida source code, probably in the context of building the documentation. The steps involve:
        1. Cloning the Frida repository.
        2. Installing necessary build tools (including Meson).
        3. Navigating to the build directory.
        4. Running a Meson command to build the documentation (e.g., `meson compile docs`).
        5. If errors occur during documentation generation, the user might inspect the logs or directly examine the `generatormd.py` script.

By following these steps, a comprehensive understanding of the script's functionality and its relation to the broader Frida project can be achieved. The process involves both code analysis and contextual awareness of Frida's purpose and usage.
这个 `generatormd.py` 文件是 Frida 动态 instrumentation 工具的一部分，它的主要功能是**将 Frida 的 API 文档转换为 Markdown 格式**。这个过程是 Frida 文档构建流程的一部分，使用了 Meson 构建系统。

以下是它的详细功能分解和与逆向、底层、逻辑推理以及用户错误的关联：

**主要功能:**

1. **读取 Frida API 模型:**  该脚本接收一个 `ReferenceManual` 对象作为输入。这个对象包含了 Frida API 的结构化信息，例如类、方法、函数、参数、返回值等。这些信息很可能来自其他工具解析 Frida 的源代码或专门的文档描述文件。
2. **生成 Markdown 文件:** 脚本遍历 `ReferenceManual` 中的 API 元素（对象、函数等），并根据预定义的模板将这些信息转换成 Markdown 格式的文件。每个类、模块或独立的函数都会生成一个或多个 Markdown 文件。
3. **组织文档结构:**  脚本负责生成文档的目录结构和导航信息。通过 `_gen_filename` 函数生成有意义的文件名，并通过 `_configure_sitemap` 函数将生成的 Markdown 文件组织到 `sitemap.txt` 文件中，以便文档查看器（例如 HotDoc）能够正确加载和显示文档。
4. **生成链接定义:**  脚本还会生成一个 `link_def.json` 文件，用于定义文档内部的链接。它将特定的标识符（例如 `[[@ObjectName]]` 或 `[[FunctionName]]`) 映射到实际的 Markdown 文件和锚点，使得文档中的交叉引用能够正常工作。
5. **使用模板生成:**  脚本使用了 `chevron` 库，这是一个 Mustache 模板引擎的实现。这意味着文档的结构和格式是在 `.mustache` 模板文件中定义的，脚本将 API 数据填充到这些模板中生成最终的 Markdown 文件。

**与逆向方法的关联:**

* **API 文档是逆向的基础:** Frida 是一个用于动态分析和逆向工程的工具。它的 API 文档对于想要使用 Frida 进行代码注入、hook 函数、查看内存等操作的逆向工程师至关重要。`generatormd.py` 生成的文档直接帮助逆向工程师理解 Frida 提供的功能和如何使用这些功能。
* **示例说明:** 假设 Frida 提供了一个函数 `Interceptor.attach(target, callbacks)` 用于 hook 目标函数。`generatormd.py` 会生成关于这个函数的 Markdown 文档，其中会包含：
    * 函数签名：`Interceptor.attach(target: Address | Module | String, callbacks: { onEnter?: Function, onLeave?: Function })`
    * 参数说明：`target` 参数可以是内存地址、模块对象或函数名称字符串，`callbacks` 参数是一个包含 `onEnter` 和 `onLeave` 回调函数的对象。
    * 功能描述：解释 `Interceptor.attach` 的作用，即在目标函数执行前后插入自定义的代码。
    * 使用示例：展示如何在 Frida 脚本中使用 `Interceptor.attach` 来 hook 一个特定的函数，例如：
      ```javascript
      Interceptor.attach(Module.getExportByName(null, 'open'), {
        onEnter: function(args) {
          console.log('Calling open with filename:', args[0].readUtf8String());
        },
        onLeave: function(retval) {
          console.log('open returned:', retval);
        }
      });
      ```
    逆向工程师通过阅读这样的文档，就能理解如何使用 Frida 的 API 来监控和修改目标程序的行为。

**涉及二进制底层、Linux、Android 内核及框架的知识:**

* **底层数据类型:**  在生成的文档中，可能会出现像 `Address`、`Module` 这样的类型。这些类型直接映射到二进制程序的内存地址和加载的模块，是理解程序底层结构的关键。
* **系统调用和 API:** Frida 经常用于 hook 系统调用或特定平台的 API。文档中关于这些 API 的描述和示例，会涉及到 Linux 或 Android 的内核及框架知识。例如，文档可能会解释如何使用 Frida hook Android 的 `open` 系统调用或者 `ActivityManager` 框架中的方法。
* **内存操作:** Frida 允许直接读写进程内存。文档中关于 `Memory.read*` 和 `Memory.write*` 等函数的描述，直接涉及到二进制层面的内存布局和数据表示。
* **示例说明:**
    * 文档可能会解释 `Module.getBaseAddress()` 函数返回指定模块在内存中的起始地址，这是一个与二进制加载器和内存管理相关的概念。
    * 关于 Android 逆向的示例可能会展示如何使用 Frida hook `System.loadLibrary` 来监控 Native 库的加载，这涉及到 Android 框架的知识。
    * 文档可能会解释 `ptr()` 函数可以将一个 JavaScript 的数值转换为 Frida 的 `NativePointer` 对象，用于进行底层的内存操作。

**逻辑推理:**

* **假设输入:** 假设 `ReferenceManual` 对象中包含了关于 `Module` 类的信息，其中包括一个 `getExportByName(name)` 方法，用于获取模块中指定名称的导出函数的地址。
* **输出:** `generatormd.py` 会根据模板生成类似以下的 Markdown 文档片段：
  ```markdown
  ### `getExportByName(name)`

  **Signature:**

  ```meson
  function getExportByName(name: String): NativePointer
  ```

  **Description:**

  Returns the address of the exported function with the given `name`.

  **Arguments:**

  * **`name`**: The name of the exported function.

  **Returns:**

  The address of the exported function as a `NativePointer`.

  **Example:**

  ```javascript
  const openPtr = Module.getExportByName(null, 'open');
  console.log('Address of open:', openPtr);
  ```
  这里进行了逻辑推理，将 `ReferenceManual` 中关于 `getExportByName` 方法的结构化信息转换为符合 Markdown 语法的文本，并包含代码块和参数说明等。

**涉及用户或编程常见的使用错误:**

* **类型错误:** 文档中明确指出参数的类型，可以帮助用户避免传递错误类型的参数。例如，如果文档说明 `Interceptor.attach` 的 `target` 参数需要一个 `Address` 对象，用户就不应该传递一个字符串，除非文档允许。
* **参数顺序和数量错误:** 文档中的函数签名清楚地列出了参数的顺序和数量，防止用户调用函数时参数不匹配。
* **理解返回值:** 文档会说明函数的返回值类型和含义，避免用户对返回值做出错误的假设。例如，文档会说明 `Module.getExportByName` 返回的是一个 `NativePointer` 对象，如果函数找不到导出的函数，可能会返回 `null` 或抛出异常。
* **示例说明:**
    * 如果用户尝试调用 `Interceptor.attach("my_function", {})`，但文档说明 `target` 参数对于全局函数需要使用 `Module.getExportByName(null, "my_function")` 获取地址，那么用户就会犯类型错误。
    * 如果用户错误地以为 `Module.getBaseAddress()` 返回的是模块的大小，而不是起始地址，就会在使用时出现逻辑错误。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者修改了 Frida 的 C/C++ 或 QML 代码:** Frida 的 API 可能会随着代码的更新而变化。
2. **开发者更新了 Frida 的文档描述文件:** Frida 可能使用某种中间格式（例如 JSON 或 YAML）来描述 API，开发者需要更新这些文件以反映代码的更改。
3. **触发 Frida 的构建过程:**  通常是通过运行 Meson 构建命令，例如 `meson compile docs`。
4. **Meson 构建系统执行 `generatormd.py` 脚本:** Meson 会根据构建配置，调用 `generatormd.py` 脚本来生成 Markdown 文档。此时，`ReferenceManual` 对象已经被之前的步骤创建并传递给该脚本。
5. **如果文档生成出现错误:** 开发者可能会查看构建日志，其中会包含 `generatormd.py` 脚本的执行信息和可能的错误信息。
6. **开发者可能会查看 `generatormd.py` 的源代码:** 为了理解文档生成的过程或修复错误，开发者可能会打开 `frida/subprojects/frida-qml/releng/meson/docs/refman/generatormd.py` 文件来查看其实现逻辑。
7. **调试线索:** 如果生成的文档不正确（例如，参数描述错误，链接失效），开发者可能会：
    * 检查 `ReferenceManual` 的生成过程，看是否 API 信息解析有误。
    * 检查 `generatormd.py` 中的模板文件 (`.mustache`)，看模板的逻辑是否正确。
    * 检查 `generatormd.py` 的代码，看生成 Markdown 的逻辑是否有错误，例如文件命名规则、链接生成规则等。
    * 检查 `sitemap.txt` 和 `link_def.json` 的内容，看文档结构和链接是否正确。

总而言之，`generatormd.py` 在 Frida 的开发流程中扮演着关键的角色，它将结构化的 API 信息转化为用户友好的文档，这对于 Frida 的使用者，尤其是逆向工程师来说至关重要。理解这个脚本的功能和它与 Frida 其他部分的联系，有助于理解 Frida 的构建过程和文档生成机制。

### 提示词
```
这是目录为frida/subprojects/frida-qml/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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