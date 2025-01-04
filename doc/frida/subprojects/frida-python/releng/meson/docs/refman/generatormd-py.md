Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding: What is the script's purpose?**

The file path `frida/subprojects/frida-python/releng/meson/docs/refman/generatormd.py` gives a lot of context. Keywords like "frida-python," "docs," "refman," and "generatormd" immediately suggest this script is involved in generating the reference manual documentation for the Python bindings of the Frida dynamic instrumentation tool. The "md" in the name strongly hints that it generates Markdown files.

**2. Core Functionality Identification: Reading the Code**

Now, let's scan the code for key elements and actions:

* **Imports:** Libraries like `pathlib`, `textwrap`, `typing`, `re`, and `json` indicate file system operations, string manipulation, type hinting, regular expressions, and JSON handling. The import of `chevron` suggests template rendering. The import from the same directory (`.generatorbase`, `.model`) hints at a structured approach to the data being processed.

* **Class `GeneratorMD`:** This is the main class doing the work. Its methods will reveal the core logic.

* **`__init__`:**  Initialization takes a `ReferenceManual` object, output paths, and a flag `enable_modules`. This suggests the script receives structured data about the API and configuration settings.

* **`_gen_filename`:**  This function clearly generates output filenames based on an internal `file_id`. The manipulation of the `_ROOT_BASENAME` is important.

* **`_gen_object_file_id`:** This generates unique IDs for documentation objects, crucial for linking. The logic for `ObjectType.RETURNED` is a detail to note.

* **`_link_to_object`:** This creates placeholders for links within the documentation. The `[[...]]` format is significant.

* **`_write_file` and `_write_template`:** These are the output functions. `_write_template` uses the `chevron` library for rendering, confirming the use of templates.

* **`_gen_func_or_method`:** This is a complex function. It processes function and method data to generate Markdown content, including signatures, argument descriptions, and return types. The detailed formatting logic (calculating `max_type_len`, `max_name_len`) indicates attention to presentation.

* **`_write_object`:** This function handles the documentation generation for objects (classes, modules).

* **`_write_functions`:**  Handles generating documentation for standalone functions.

* **`_root_refman_docs`:** This seems to generate the main index page for the reference manual, including links to different sections.

* **`generate`:** This is the main entry point, orchestrating the generation of different parts of the documentation.

* **`_configure_sitemap`:**  This modifies a sitemap file by inserting generated file paths. The `@REFMAN_PLACEHOLDER@` is a clear indication of this process.

* **`_generate_link_def`:** This creates a JSON file containing mappings for the placeholder links (`[[...]]`).

**3. Relating to Reverse Engineering Concepts:**

With the core functionality understood, connect it to reverse engineering:

* **Dynamic Instrumentation:** The script is part of Frida, a *dynamic* instrumentation tool. This means it interacts with running processes. The documentation generated helps users understand how to *use* Frida to instrument and analyze software.

* **API Documentation:** Reverse engineers often need to understand the API of a library or framework they are analyzing. This script *creates* that documentation for Frida's Python bindings. Understanding Frida's Python API is crucial for scripting instrumentation tasks.

* **Binary Undocumented Functionality:** While the script doesn't *directly* analyze binaries, the *result* (the documentation) helps reverse engineers understand Frida's capabilities, which *are* used to analyze binaries.

**4. Identifying Binary/Kernel/Framework Involvement:**

* **Frida's Core:** Frida itself interacts with the underlying operating system (Linux, Android) and its kernel to perform instrumentation. The Python bindings provide a higher-level interface to this functionality. The documentation generated reflects these capabilities (e.g., attaching to processes, hooking functions).

* **Android Specifics:**  Frida is heavily used on Android. The documentation might include details about interacting with Android-specific frameworks (like ART, the Android runtime).

**5. Logic and Reasoning (Hypothetical Input/Output):**

Think about the input `ReferenceManual` object. What kind of data would it contain?

* **Input (Hypothetical):** The `ReferenceManual` would likely have data structures representing classes, functions, methods, their arguments, return types, descriptions, etc. This data would probably be parsed from some source (likely Python docstrings or a structured data format).

* **Output (Clear):** The output is a set of Markdown files organized into a reference manual structure. Specific examples of generated Markdown for a function or a class can be imagined based on the `_gen_func_or_method` and `_write_object` logic.

**6. Common Usage Errors:**

Consider how a *developer* using this script might make mistakes:

* **Incorrectly formatted docstrings:**  If the input data (presumably derived from docstrings) is malformed, the generated documentation might be incorrect or incomplete.
* **Missing information:**  If descriptions or type hints are missing in the source code, the documentation will lack details.
* **Configuration errors:**  Incorrect output paths or `enable_modules` settings could lead to the documentation being generated in the wrong location or with the wrong content.

**7. Debugging Steps to Reach the Script:**

Trace the actions that would lead to executing this script:

* A developer working on Frida's Python bindings needs to update the API documentation.
* They would likely use a build system (like Meson, as indicated by the file path) to generate the documentation.
* The Meson build configuration would specify the `generatormd.py` script as a step in the documentation generation process.
* Running the Meson build command would invoke this script with the necessary input data and configuration.

**Self-Correction/Refinement during the thought process:**

* Initially, I might have focused too much on the technical details of the Markdown generation. It's important to step back and understand the *purpose* of the script within the larger Frida ecosystem.
*  Realizing the connection to *dynamic* instrumentation and reverse engineering is crucial for a complete answer.
*  Thinking about the input and output data structures helps to solidify understanding of the script's function.
*  Considering potential errors and the developer workflow provides practical context.
这个 Python 脚本 `generatormd.py` 的主要功能是为 Frida 动态 instrumentation 工具的 Python 绑定生成 Markdown 格式的参考手册文档。它读取一个描述 Frida Python API 的数据模型，并将其转换为一系列 Markdown 文件，这些文件可以被诸如 Hotdoc 之类的文档生成工具处理，最终生成用户可阅读的 HTML 文档。

让我们详细列举一下它的功能，并根据你的要求进行说明：

**功能列表:**

1. **读取 API 数据模型:**  脚本接收一个 `ReferenceManual` 对象作为输入，这个对象包含了 Frida Python API 的结构化信息，包括模块、类（对象）、函数、方法、参数、返回值等。

2. **生成 Markdown 文件:**  脚本根据 API 数据模型中的信息，生成一系列独立的 Markdown 文件。每个模块、类、函数都有可能对应一个或多个 Markdown 文件。

3. **组织文档结构:**  脚本通过生成特定的文件名和目录结构来组织文档。它使用 `_gen_filename` 和 `_gen_object_file_id` 方法来生成有意义且唯一的 Markdown 文件名。

4. **生成对象文档:**  对于 API 中的每个对象（类、模块等），脚本会生成包含其描述、属性、方法等的 Markdown 内容。`_write_object` 方法负责处理对象文档的生成。

5. **生成函数和方法文档:**  脚本会为 API 中的每个函数和方法生成详细的文档，包括签名、参数列表、返回值、示例代码等。`_gen_func_or_method` 方法负责处理函数和方法的文档生成。

6. **生成链接占位符:**  脚本在生成的 Markdown 文档中使用 `[[...]]` 格式的占位符来表示内部链接，例如链接到其他对象或函数的文档。`_link_to_object` 方法负责生成这些占位符。

7. **处理继承关系:**  对于有继承关系的对象，脚本能够生成包含继承方法的信息。

8. **处理模块:**  如果启用了模块支持 (`enable_modules`)，脚本会生成模块的文档。

9. **生成根目录文档:**  脚本会生成一个根目录的 Markdown 文件，作为整个参考手册的入口。

10. **配置站点地图 (Sitemap):** 脚本会读取一个站点地图模板文件 (`sitemap_in`)，并将生成的 Markdown 文件的路径插入到模板中，生成最终的站点地图文件 (`sitemap_out`)。这用于指导文档生成工具如何组织和链接各个页面。

11. **生成链接定义文件:** 脚本生成一个 JSON 文件 (`link_def_out`)，其中包含了占位符链接 (`[[...]]`) 到实际生成的文件和锚点的映射关系。这个文件会被 Hotdoc 插件使用，将占位符替换为正确的 HTML 链接。

12. **使用模板引擎:** 脚本使用 `chevron` 模板引擎来渲染 Markdown 内容，使得文档的生成更加灵活和可维护。

**与逆向方法的关系 (举例说明):**

虽然这个脚本本身不直接参与二进制的逆向过程，但它生成的文档对于使用 Frida 进行逆向工程至关重要。

**举例说明:**

* **Hooking 函数:** 假设逆向工程师想要使用 Frida 的 Python API 来 hook 一个应用程序的特定函数。他们需要知道 Frida 提供的哪些类和方法可以实现这个目标。`generatormd.py` 生成的文档会详细描述 `frida.Interceptor` 类的 `attach()` 方法、`replace()` 方法、`enter` 和 `leave` 钩子等，包括它们的参数、返回值和使用方式。逆向工程师可以通过阅读这些文档，了解如何使用 Frida API 来编写 hook 脚本。例如，文档可能会展示如何使用 `frida.Interceptor.attach()` 来指定要 hook 的函数地址或符号名称。

* **内存操作:** Frida 提供了在目标进程内存中读取和写入数据的能力。`generatormd.py` 生成的文档会解释 `frida.Process.read_bytes()` 和 `frida.Process.write_bytes()` 等方法的使用方法，包括需要提供的地址、长度等参数。逆向工程师可以通过阅读这些文档，学习如何使用 Frida API 来检查或修改目标进程的内存状态。

* **调用脚本:**  逆向工程师需要知道如何将他们的 Python 脚本加载到 Frida 中并执行。文档会解释 `frida.attach()`、`session.create_script()` 和 `script.load()` 等 API 的用法。

**涉及到二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

虽然脚本本身是用 Python 编写的，并且专注于文档生成，但它所描述的 Frida Python API 背后涉及大量的底层知识：

* **进程操作 (Linux/Android):** Frida 需要能够 attach 到目标进程，这涉及到操作系统提供的进程管理 API，例如 Linux 的 `ptrace` 系统调用或 Android 的类似机制。文档中关于 `frida.attach()` 的描述虽然是 Python 接口，但其底层操作直接与操作系统内核交互。

* **内存管理 (Linux/Android):** Frida 可以在目标进程的内存中分配和释放空间，读取和写入数据。文档中关于内存操作的 API (如 `read_bytes`, `write_bytes`) 背后是操作系统提供的内存管理机制。

* **动态链接和符号解析:** Frida 可以通过函数名称或地址来 hook 函数。这需要理解动态链接器如何加载和解析库，以及符号表的结构。文档中提到的如何指定 hook 的目标函数（通过名称或地址）就反映了这些底层概念。

* **Android Runtime (ART):** 在 Android 平台上，Frida 经常用于 hook ART 虚拟机中的方法。文档可能会描述如何使用 Frida API 与 ART 交互，例如获取类的信息、调用 Java 方法等。这涉及到对 Android 框架和 ART 内部机制的理解。

* **指令集架构:**  虽然 Python API 是跨平台的，但 Frida 的核心组件需要在目标架构上运行。文档中可能会间接涉及到指令集架构的概念，例如在讨论如何理解和修改汇编代码时。

**逻辑推理 (假设输入与输出):**

假设 `ReferenceManual` 对象包含以下简化信息：

**输入 (假设):**

```python
# 简化的 ReferenceManual 结构
class ReferenceManual:
    def __init__(self):
        self.functions = [
            Function(name="sleep", description="Pauses execution for a specified number of seconds.", returns=Type("void"))
        ]
        self.objects = [
            Object(name="Process", description="Represents a running process.", obj_type=ObjectType.BUILTIN,
                   methods=[
                       Method(name="read_bytes", description="Reads bytes from the process memory.", returns=Type("bytes"),
                              posargs=[PosArg(name="address", type=Type("int"), description="Memory address to read from."),
                                       PosArg(name="count", type=Type("int"), description="Number of bytes to read.")])
                   ])
        ]
```

**输出 (部分生成的 Markdown 内容):**

* **`Reference-manual_functions.md` (片段):**

```markdown
### sleep

```
<pre><code class="language-meson">
void sleep()
</code></pre>

Pauses execution for a specified number of seconds.
```

* **`Reference-manual_builtin_Process.md` (片段):**

```markdown
## Process

Represents a running process.

### Methods

#### read_bytes

```
<pre><code class="language-meson">
bytes read_bytes(
  int address,          # Memory address to read from.
  int count             # Number of bytes to read.
)
</code></pre>

Reads bytes from the process memory.
```

**用户或编程常见的使用错误 (举例说明):**

* **API 使用错误:**  用户可能会错误地使用 Frida Python API 中的函数或方法，例如传递错误的参数类型或数量。`generatormd.py` 生成的文档可以帮助用户避免这些错误。例如，如果用户在调用 `Process.read_bytes` 时传递了字符串类型的 `address` 参数，文档中明确说明 `address` 应该是 `int` 类型，可以帮助用户发现错误。

* **理解概念错误:**  用户可能对 Frida 的某些概念理解不足，例如 session、script 等。文档可以提供清晰的解释和示例，帮助用户正确理解和使用 Frida。

* **环境配置问题:**  虽然文档本身不解决环境配置问题，但清晰的 API 文档可以帮助用户诊断由配置错误引起的问题。例如，如果用户无法 attach 到目标进程，查阅 `frida.attach()` 的文档可能会提供关于权限或其他限制的信息。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发者修改了 Frida Python API 的代码:**  当 Frida Python 绑定的开发者添加、修改或删除了 API 中的功能时，他们需要更新相应的文档。

2. **开发者更新 API 数据模型或源代码:**  Frida 的文档通常是从源代码中的注释或单独的 API 定义文件生成的。开发者需要确保这些信息是最新的。

3. **开发者运行构建文档的命令:**  Frida 项目使用 Meson 作为构建系统。开发者会执行类似 `meson compile -C builddir` 或 `ninja -C builddir` 的命令来构建项目，其中可能包含生成文档的步骤。

4. **Meson 构建系统调用 `generatormd.py` 脚本:**  Meson 的配置文件 (`meson.build`) 会指定如何生成文档，通常会调用 `generatormd.py` 脚本，并将必要的参数传递给它，例如 API 数据模型的位置、输出目录等。

5. **`generatormd.py` 脚本读取 API 数据模型并生成 Markdown 文件:**  脚本会按照其逻辑，读取 API 数据，并根据模板生成一系列 Markdown 文件。

6. **文档生成工具 (例如 Hotdoc) 处理 Markdown 文件:**  生成的 Markdown 文件会被其他文档生成工具（如 Hotdoc）处理，将其转换为最终的 HTML 文档。

**作为调试线索:**

如果生成的文档出现错误或与实际 API 不符，开发者可以通过以下步骤进行调试：

1. **检查 `ReferenceManual` 对象的生成过程:**  确定传递给 `generatormd.py` 的 `ReferenceManual` 对象是否包含了正确的 API 信息。

2. **检查 `generatormd.py` 脚本的逻辑:**  分析脚本的源代码，特别是 `_gen_func_or_method` 和 `_write_object` 等方法，查看是否存在逻辑错误导致文档生成不正确。

3. **检查模板文件:**  查看 `templates` 目录下的模板文件，确认模板是否正确地渲染了 API 数据。

4. **对比生成的 Markdown 文件与预期结果:**  检查生成的 Markdown 文件，看哪些部分生成错误，从而定位问题所在。

5. **检查 Hotdoc 的配置和处理过程:**  如果 Markdown 文件本身没有问题，那么可能是 Hotdoc 的配置或处理过程出现了错误。

总而言之，`generatormd.py` 是 Frida 文档生成流程中的一个关键环节，它负责将结构化的 API 信息转换为用户可读的 Markdown 文档，这对于 Frida 的使用者，尤其是进行逆向工程的工程师来说，是极其重要的参考资料。

Prompt: 
```
这是目录为frida/subprojects/frida-python/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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