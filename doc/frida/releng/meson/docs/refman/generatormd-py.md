Response:
Let's break down the thought process to analyze this Python script.

**1. Understanding the Context:**

The first step is recognizing the script's location (`frida/releng/meson/docs/refman/generatormd.py`) and the "fridaDynamic instrumentation tool" mention. This immediately signals that the script is part of Frida's build process, specifically related to generating documentation. The `meson` directory further confirms that Meson is the build system being used. The `docs/refman` suggests it's generating the reference manual.

**2. High-Level Functionality Identification:**

The filename `generatormd.py` strongly hints at "generate Markdown". The imports confirm this:

* `generatorbase.GeneratorBase`:  Indicates this class inherits from a base class, likely providing common documentation generation functionalities.
* `re`, `json`: Standard Python libraries for regular expressions and JSON handling, suggesting text processing and data serialization.
* `model`:  Crucially, this import suggests a separate module defines the data structure of the documentation elements (functions, objects, methods, etc.). This is a key architectural element.
* `pathlib.Path`: For file system operations.
* `textwrap.dedent`: For cleaning up multi-line strings.
* `typing as T`: For type hinting, enhancing code readability and maintainability.
* `mesonbuild.mlog`: Frida's internal logging system.
* `chevron`:  A templating engine (like Mustache), used for generating the final output from data.

**3. Core Class and Methods Analysis:**

The central class is `GeneratorMD`. Let's examine its key methods:

* `__init__`:  Initializes the generator, taking paths for sitemap input/output, link definitions, and an `enable_modules` flag. It also initializes `self.generated_files` to track generated files.
* `_gen_filename`:  Clearly responsible for creating output filenames based on a file ID. The regex suggests cleaning up numerical prefixes.
* `_gen_object_file_id`: Generates unique IDs for objects, crucial for creating consistent links and sitemap structure. The logic for "returned" objects is interesting and hints at how nested documentation structures are handled.
* `_link_to_object`:  Generates placeholder tags like `[[@object_name]]` or `[[object.method_name]]`. The comment explicitly mentions these are replaced later, likely by a custom tool. This is a *key* point for understanding how Frida integrates this documentation into its larger system.
* `_write_file`:  Writes the generated content to disk.
* `_write_template`: Uses the `chevron` library to render Mustache templates with provided data. This is the core mechanism for generating the Markdown output.
* `_gen_func_or_method`:  This is a complex method, responsible for structuring the data for functions and methods to be used in the templates. It handles argument rendering, type formatting, and generates anchors for linking. The detailed logic here shows significant effort is put into making the documentation clear and consistent.
* `_write_object`:  Generates the documentation for objects, including their methods and inherited methods.
* `_write_functions`:  Generates a page listing standalone functions.
* `_root_refman_docs`:  Generates the main index page of the reference manual, linking to different sections (elementary types, builtins, modules, etc.).
* `generate`: The main entry point for the generation process, orchestrating the writing of functions, objects, and the root document, as well as configuring the sitemap and link definitions.
* `_configure_sitemap`:  Updates a sitemap file by inserting the generated file paths at a placeholder.
* `_generate_link_def`:  Creates a JSON file mapping the placeholder tags (like `[[@object_name]]`) to the actual file paths and anchors. This is crucial for the hotdoc plugin.

**4. Connecting to Reverse Engineering and Frida:**

Now, map the functionality to reverse engineering and Frida:

* **Frida's Core:** Frida instruments running processes. This documentation generator is for the *API* that developers use to interact with Frida. Understanding the functions, objects, and methods documented here is essential for anyone writing Frida scripts to perform reverse engineering tasks.
* **Dynamic Instrumentation:** The generated documentation describes the tools available for *dynamically* inspecting and modifying application behavior.
* **Binary/OS Interaction:**  The documented API likely includes functions and objects that interact with the underlying operating system (Linux, Android) and binary structures (memory, processes, threads). While the Python script *itself* doesn't directly manipulate binaries, the *documentation it generates* is about an API that *does*.

**5. Identifying Potential Issues and User Errors:**

Think about how a developer might misuse Frida or how the documentation generation itself could have flaws:

* **Incorrect API Usage:**  The documentation aims to prevent this. If the documentation is unclear or inaccurate, users might call functions with incorrect arguments or misunderstand their behavior.
* **Type Errors:** The detailed type information in the generated documentation helps avoid type errors in user scripts.
* **Understanding Object Relationships:** The documentation of objects, their methods, and inheritance is crucial for using Frida's API correctly. Misunderstanding these relationships could lead to errors.
* **Build System Issues:**  While not a direct user error in Frida scripting, problems with the documentation generation process itself (e.g., missing documentation, broken links) would hinder users.

**6. Tracing User Interaction (Debugging Clues):**

Imagine a developer trying to understand how to use a particular Frida function. The path to this script goes something like this:

1. **User needs documentation:** A developer wants to use a specific Frida feature or understand a function's behavior.
2. **Searches Frida documentation:** They navigate to the official Frida documentation website.
3. **Finds a function/method/object:** They locate the documentation for the relevant API element.
4. **Underlying process:** Behind the scenes, the documentation they are viewing was generated by scripts like `generatormd.py`. If there's an error in the documentation (typo, inaccurate description, broken link), the problem might originate from this script or the data it processes.
5. **Debugging:** If a documentation issue is suspected, a Frida developer might examine the source code of `generatormd.py` to understand how the documentation is generated and identify potential bugs in the generation process.

**7. Logical Inference and Assumptions:**

Consider the assumptions and logic within the script:

* **Model Consistency:** The script assumes the data in the `model` module is accurate and complete. Errors in the model will propagate to the documentation.
* **Template Accuracy:**  The Mustache templates are assumed to correctly render the data provided by the Python script.
* **Hotdoc Plugin Functionality:** The script relies on the `refman_links` hotdoc plugin to correctly interpret the `[[tag]]` placeholders.

By following these steps – understanding the context, analyzing the code structure and key methods, connecting it to the broader project, considering potential issues, and tracing user interactions – you can effectively analyze a complex script like this and provide a comprehensive explanation of its purpose and functionality.
This Python script, `generatormd.py`, is a crucial part of the Frida dynamic instrumentation tool's build process. It's responsible for **generating the Markdown files that constitute Frida's reference manual**. It takes structured data about Frida's API (functions, classes, methods, etc.) and transforms it into human-readable Markdown format for the official documentation.

Let's break down its functionalities and connections:

**Core Functionalities:**

1. **Data Input:**  The script takes a `ReferenceManual` object as input. This object, likely built from parsing source code or structured data files, contains a model of Frida's API, including:
    * **Functions:** Global functions available in Frida's scripting environment.
    * **Objects:** Classes or data structures exposed by Frida (e.g., `Process`, `Thread`, `Module`).
    * **Methods:** Functions associated with specific objects.
    * **Types:** Data types used in the API.
    * **Arguments:** Details about function and method parameters (name, type, description, optionality).
    * **Return Values:** Information about what functions and methods return.
    * **Descriptions, Notes, Warnings, Examples:**  Descriptive text for each API element.

2. **Markdown Generation:** The core purpose of the script is to convert this structured API data into Markdown files. It iterates through the functions, objects, and methods in the `ReferenceManual` and generates corresponding Markdown files.

3. **File Organization and Naming:** It defines a systematic way to name and organize the generated Markdown files (e.g., `Reference-manual_functions.md`, `Reference-manual_module_Process.md`). The `_gen_filename` and `_gen_object_file_id` methods handle this logic.

4. **Cross-linking:**  It generates special placeholder tags like `[[@ObjectName]]` and `[[ObjectName.methodName]]` within the Markdown. These tags are later processed by a custom "hotdoc" plugin to create hyperlinks between different parts of the documentation. The `_link_to_object` method is responsible for this.

5. **Sitemap Generation:** The script updates a sitemap file (`sitemap_out`) by inserting the paths to the generated Markdown files. This sitemap is used by the documentation system to create the table of contents and navigation.

6. **Link Definition Generation:** It creates a JSON file (`link_def_out`) that maps the placeholder tags (like `[[@ObjectName]]`) to the actual file paths and anchor points within the generated HTML. This is essential for the hotdoc plugin to resolve the links.

7. **Templating:** It utilizes the `chevron` library (a Mustache template engine) to generate the Markdown content. This allows for separating the data from the presentation logic, making the generation process more maintainable. Templates are located in the `templates` directory.

**Relationship to Reverse Engineering:**

This script is **indirectly** related to reverse engineering. It doesn't perform reverse engineering itself. However, it generates the documentation for **Frida**, which is a powerful tool extensively used for dynamic reverse engineering. The documentation generated by this script helps reverse engineers understand how to use Frida's API to:

* **Inspect process memory:** Documenting functions for reading and writing memory, finding memory regions, etc.
* **Hook functions:** Documenting functions for intercepting function calls, modifying arguments and return values.
* **Trace execution:** Documenting functions for tracking code execution flow.
* **Interact with application internals:** Documenting objects and methods that represent processes, threads, modules, and other internal application components.

**Example:**

Imagine a reverse engineer wants to hook the `open` system call on an Android application using Frida. They would consult the documentation generated by this script (among other files). They might find:

* **`Interceptor` object:**  The documentation would describe the `Interceptor` object, its purpose (intercepting function calls), and its methods.
* **`Interceptor.attach()` method:** The documentation would detail how to use the `attach()` method to hook a function, including the required arguments (e.g., the address of the function to hook, callback functions for before and after the original function call).
* **`NativePointer` object:** The documentation would explain how to represent memory addresses using the `NativePointer` object, which might be needed to specify the address of `open`.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

While the Python script itself doesn't directly manipulate binaries or interact with the kernel, the **API it documents does**. Therefore, an understanding of these concepts is crucial for **designing and using the Frida API** that this script documents.

* **Binary Bottom:**  The Frida API exposes functionalities to interact with the low-level details of a running process's binary, such as memory layout, code sections, and function addresses. The documentation generated here makes these concepts accessible through the Frida API.
* **Linux & Android Kernel:** Frida often interacts with the underlying operating system kernel. For example, hooking system calls like `open` directly involves kernel interactions. The documentation might indirectly mention concepts related to system calls, process management, memory management, which are fundamental to kernel understanding.
* **Android Framework:** When used on Android, Frida can interact with the Android runtime environment (ART) and the various framework services. The documentation might describe objects and methods that allow interaction with Java classes, methods, and Android system services.

**Logical Inference (Hypothetical Input & Output):**

**Hypothetical Input (part of the `ReferenceManual` object):**

```python
# Inside the model.py file (conceptual)
class Function:
    def __init__(self, name, description, returns, args):
        self.name = name
        self.description = description
        self.returns = returns
        self.args = args

class Type:
    def __init__(self, name):
        self.name = name

# ... more definitions ...

my_function = Function(
    name="read_memory",
    description="Reads bytes from the specified memory address.",
    returns=Type("ByteArray"),
    args=[
        ArgBase(name="address", type=Type("NativePointer"), description="The memory address to read from."),
        ArgBase(name="size", type=Type("Number"), description="The number of bytes to read."),
    ]
)
```

**Hypothetical Output (generated Markdown snippet):**

```markdown
### `read_memory`

Reads bytes from the specified memory address.

```
<pre><code class="language-meson">
ByteArray read_memory(
  NativePointer <b>address</b>,      # The memory address to read from.
  Number      <b>size</b>          # The number of bytes to read.
)
</code></pre>
```

This shows how the structured data about the `read_memory` function is transformed into a formatted Markdown section.

**User or Programming Common Usage Errors:**

This script aims to *prevent* user errors by providing clear documentation. However, errors can occur during the documentation generation process itself or if the underlying data is incorrect.

* **Broken Links:** If the `_gen_object_file_id` logic is flawed or the hotdoc plugin configuration is incorrect, the generated links between documentation pages might be broken. A user clicking a link would get a "page not found" error.
* **Incorrect Type Information:** If the `Type` information in the input model is wrong, the generated documentation might mislead users about the expected types of arguments or return values, leading to programming errors in their Frida scripts. For example, if an argument is documented as a `Number` but actually requires a `String`, users will encounter runtime errors.
* **Missing Documentation:** If an API element is present in the code but missing in the input `ReferenceManual`, it won't be documented, making it harder for users to discover and use that functionality.
* **Typos and Grammatical Errors:**  While not directly related to the script's logic, typos in the descriptions and other text can confuse users.

**User Operation to Reach This Script (Debugging Clues):**

A developer working on Frida's documentation would interact with this script indirectly as part of the build process. Here's a likely sequence:

1. **Modify Frida's Source Code:** A developer adds or changes a function, object, or method in Frida's C++, JavaScript, or Python code.
2. **Update API Model:**  The process to generate the `ReferenceManual` object (the input to this script) would need to be run. This might involve parsing the source code and extracting API information.
3. **Run the Documentation Build:** The developer would execute a command (likely using `meson`) to build the Frida documentation. This command would trigger the execution of `generatormd.py`.
4. **`generatormd.py` Executes:** This script reads the `ReferenceManual` object and generates the Markdown files in the specified output directory.
5. **Hotdoc Processing:** Another tool (the "hotdoc" plugin mentioned in the comments) processes the generated Markdown files, resolves the placeholder links, and creates the final HTML documentation.
6. **View Documentation:** The developer (or a user) views the generated HTML documentation on a website or locally.

**As a debugging clue:** If a user reports an error in the documentation (e.g., a broken link, incorrect information), a developer might:

* **Inspect the generated Markdown file:** Check the raw Markdown output of `generatormd.py` to see if the link or information is generated correctly.
* **Examine the `ReferenceManual` object:** Verify that the input data to `generatormd.py` is accurate.
* **Debug `generatormd.py`:** If the issue seems to originate within the script's logic, a developer might add print statements or use a debugger to step through the code and understand how the Markdown is being generated.
* **Investigate the hotdoc plugin:** If the Markdown seems correct, the issue might lie in how the hotdoc plugin is processing the placeholders.

In summary, `generatormd.py` is a vital link in the chain of creating Frida's documentation. It translates the technical details of Frida's API into a user-friendly format, playing a key role in enabling reverse engineers to effectively use the tool.

### 提示词
```
这是目录为frida/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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