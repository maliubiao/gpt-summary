Response:
Let's break down the thought process for analyzing this Python script.

1. **Understanding the Goal:** The very first thing is to recognize the script's purpose. The filename `generatormd.py` and the presence of `GeneratorMD` class strongly suggest it's responsible for generating Markdown files. The surrounding directory structure (`frida/subprojects/frida-node/releng/meson/docs/refman/`) gives context – it's part of Frida's build process, specifically for generating the reference manual documentation.

2. **High-Level Structure and Key Classes:** I'd scan the imports first. `GeneratorBase`, `re`, `json`, `pathlib`, `textwrap`, `typing`, and `mesonbuild.mlog` provide clues about the script's functionalities. The core of the script is the `GeneratorMD` class. I'd note its inheritance from `GeneratorBase`, suggesting a shared structure or functionality with other generators.

3. **Core Functionality Breakdown (Step-by-Step):**  I'd then go through the `GeneratorMD` class method by method:

    * **`__init__`:**  This is the constructor. I'd identify the key instance variables being initialized: `manual`, `sitemap_out`, `sitemap_in`, `link_def_out`, `out_dir`, `enable_modules`, and `generated_files`. These directly point to the inputs, outputs, and core configuration of the generator.

    * **Utility Functions (`_gen_filename`, `_gen_object_file_id`, `_link_to_object`, `_write_file`, `_write_template`):**  These are helper functions. I'd analyze what each does.
        * `_gen_filename`: How are Markdown filenames generated? It seems to follow a specific pattern based on file IDs.
        * `_gen_object_file_id`: How are unique IDs generated for documentation objects? This is important for linking.
        * `_link_to_object`: How are links to other parts of the documentation created? The `[[...]]` syntax stands out as a placeholder.
        * `_write_file`:  Simple file writing.
        * `_write_template`:  Template rendering using `chevron`. This is a significant detail. It means the content isn't just hardcoded; it's dynamically generated from templates.

    * **Core Generation Logic (`_gen_func_or_method`, `_write_object`, `_write_functions`, `_root_refman_docs`):** These are the heart of the generation process.
        * `_gen_func_or_method`:  This seems responsible for formatting documentation for functions and methods. The complex `render_signature` function catches my eye. It handles different argument types (positional, optional, keyword, variadic).
        * `_write_object`: Generates documentation for objects (classes, modules). It includes information about methods, inheritance, etc.
        * `_write_functions`:  Handles documentation for standalone functions.
        * `_root_refman_docs`: Generates the main index page of the reference manual. The nested `gen_obj_links` function is interesting for how it structures the links.

    * **Main `generate` Method:** This orchestrates the entire generation process. It calls the other `_write_*` methods in a specific order. The calls to `_configure_sitemap` and `_generate_link_def` indicate finalization steps.

    * **Finalization (`_configure_sitemap`, `_generate_link_def`):**
        * `_configure_sitemap`:  This fills in a placeholder in an existing sitemap file. This connects the generated Markdown files into a navigable structure.
        * `_generate_link_def`: Creates a JSON file mapping the `[[tag]]` placeholders to actual file paths and anchors. This is crucial for the custom hotdoc plugin to resolve the links.

4. **Connecting to the Prompts:** Now that I understand the code, I can address the specific questions:

    * **Functionality:**  Summarize the purpose of each key method and the overall goal of generating Markdown documentation.

    * **Relation to Reversing:**  Think about *how* this documentation is used in reverse engineering. Frida is a dynamic instrumentation tool. The documentation describes the API, which is *essential* for anyone using Frida to inspect and modify running processes. Examples would be looking up function names, arguments, and return types.

    * **Binary/Kernel/Framework Knowledge:** Consider what underlying concepts are being documented. Frida interacts with processes at a low level. The documentation likely describes functions and objects that represent aspects of the operating system, memory, threads, etc. Think about concepts like processes, memory addresses, system calls (even if not directly mentioned in *this* script, the *documentation* will).

    * **Logic and Assumptions:** Analyze `_gen_func_or_method` closely. The argument handling, the formatting, the conditional logic based on argument types – these are areas where assumptions are made about the input data (the `manual` object). Hypothesize input and output based on this.

    * **User Errors:**  Imagine how a user interacting with the *documentation* might encounter issues. Broken links, incorrect parameter descriptions, missing documentation – these are potential problems. Think about what could go wrong *during the documentation generation process* that would lead to these errors.

    * **User Path to this Script:** This requires tracing back the build process. The directory structure (`meson`) is a major hint. Users wouldn't directly run this script. They'd trigger the build system (Meson) which, in turn, would execute this script as part of generating the documentation.

5. **Refinement and Examples:**  Finally, flesh out the answers with specific examples drawn from the code and the broader context of Frida. For instance, when discussing reverse engineering, mention specific Frida functions that might be documented. When talking about binary knowledge, mention concepts like memory addresses or function pointers.

This systematic approach, starting with understanding the high-level goal and progressively digging into the details, allows for a comprehensive analysis of the script and its relation to the provided prompts.
This Python script, `generatormd.py`, is a crucial part of the Frida dynamic instrumentation tool's documentation generation process. It's specifically responsible for **generating the Reference Manual in Markdown format**. It takes structured data representing the Frida API and transforms it into human-readable Markdown files.

Let's break down its functionalities based on your requests:

**1. Functionality of `generatormd.py`:**

* **Reads API Definition:** It takes a `ReferenceManual` object as input, which presumably contains a structured representation of Frida's API (classes, methods, functions, etc.). This data likely comes from parsing source code or some intermediate representation.
* **Generates Markdown Files:**  It iterates through the API definitions and generates individual Markdown files for different components (modules, classes, functions).
* **Creates Table of Contents (Sitemap):** It updates a sitemap file (`sitemap_out`) by inserting links to the generated Markdown files. This creates the navigation structure for the documentation.
* **Generates Link Definitions:** It creates a JSON file (`link_def_out`) that maps placeholder tags (like `[[@ObjectName]]` or `[[functionName]]`) to the actual file paths and anchors within the generated documentation. This is used by a custom Hotdoc plugin to resolve cross-references.
* **Uses Templates:** It utilizes Jinja2 templates (indicated by the `.mustache` extension and the use of the `chevron` library) to structure the Markdown content. This allows for separation of content and presentation logic.
* **Handles Different API Element Types:** It has specific logic to handle functions, methods, and objects (classes/modules), including their arguments, return types, descriptions, examples, and deprecation status.
* **Supports Modules:** It has a flag (`enable_modules`) to control whether documentation for modules is generated.
* **Provides Code Formatting:** It includes functions like `code_block` and `smart_indent` to format code snippets within the documentation.

**2. Relationship with Reverse Engineering:**

This script is **directly related to reverse engineering**. Frida is a dynamic instrumentation toolkit heavily used in reverse engineering for:

* **Analyzing Program Behavior:** Reverse engineers use Frida to hook functions, inspect arguments and return values, and trace program execution. The generated documentation provides the crucial API reference needed to write Frida scripts for these tasks.
* **Understanding Internal Structures:**  The documentation describes the objects and methods exposed by Frida, which often represent internal data structures and functionalities of the target application or system.
* **Modifying Program Behavior:** Frida allows for runtime modification of program execution. The documentation details the functions and methods available to inject custom logic and alter program flow.

**Example:**

Let's say a reverse engineer wants to hook the `open` system call on a Linux system using Frida. They would consult the generated documentation to find the relevant Frida API. They might look for functions related to hooking or system calls. The documentation might show a function like `Interceptor.attach(address, { onEnter: function(args) { ... }, onLeave: function(retval) { ... } })`. The documentation generated by this script would detail:

* **`Interceptor.attach`**: Its purpose (hooking a function at a given address).
* **`address`**:  The expected type (e.g., a `NativePointer` representing the memory address of the `open` function). This might involve knowledge of how to find the address of `open` (e.g., by resolving it from a library).
* **`callbacks`**: The structure of the object containing `onEnter` and `onLeave` functions.
* **`args` in `onEnter`**: How the arguments of the hooked function are made available (likely as a `NativePointer` array). The documentation would specify the order and types of arguments for the `open` system call (e.g., `pathname`, `flags`, `mode`).
* **`retval` in `onLeave`**: How the return value of the hooked function is accessed.

Without this documentation, using Frida effectively for reverse engineering would be significantly harder.

**3. Relationship with Binary Underpinnings, Linux/Android Kernel & Framework:**

This script indirectly relates to these low-level concepts because the **API it documents interacts with them**.

* **Binary Level:** Frida operates at the binary level, injecting code and manipulating memory. The documentation describes functions that take memory addresses as arguments (`NativePointer`), allowing interaction with raw binary data.
* **Linux/Android Kernel:** Frida can be used to instrument applications running on Linux and Android. The documentation might describe functions for interacting with kernel objects or making system calls. For example, functions to enumerate processes, threads, or modules rely on underlying kernel mechanisms.
* **Android Framework:** On Android, Frida can interact with the Android Runtime (ART) and various framework components. The documentation might detail how to hook Java methods, access object properties, or interact with system services.

**Example:**

The documentation might contain a function like `Process.enumerateModules()`. This function's implementation within Frida would involve interacting with the operating system's API to list loaded libraries (like iterating through `/proc/[pid]/maps` on Linux or using Android's debugging interfaces). The *documentation* doesn't implement this, but it describes the *interface* that abstracts these low-level details.

**4. Logical Reasoning (Hypothetical Input & Output):**

**Hypothetical Input:**

Let's assume the `ReferenceManual` object contains the following simplified information about a fictional Frida function:

```python
from .model import Function, Type, DataTypeInfo, PosArg

my_function = Function(
    name="myFunction",
    description="This is a test function.",
    returns=Type(resolved=[DataTypeInfo(data_type="void")]),
    posargs=[
        PosArg(name="input_value", type=Type(resolved=[DataTypeInfo(data_type="int")]), description="The input integer.")
    ]
)
```

**Hypothetical Output (Snippet of Generated Markdown):**

```markdown
### myFunction

This is a test function.

<pre><code class="language-meson">
void myFunction(
  int <b>input_value</b>,       # The input integer.
)
</code></pre>

#### Arguments:

| Name        | Type | Description         | Optional | Default |
|-------------|------|---------------------|----------|---------|
| input_value | int  | The input integer. |          |         |
```

**Explanation:**

The script would:

* Take the `Function` object as input.
* Use the `render_signature` method to format the function signature, including the return type and argument.
* Use the `gen_arg_data` method to create the table of arguments.
* Embed this information within a larger Markdown file using a template.

**5. User or Programming Common Usage Errors:**

* **Incorrect API Usage:**  Users might try to use a function with the wrong number or types of arguments. The generated documentation helps prevent this by clearly outlining the expected parameters. If the documentation is wrong, it can lead to frustration and incorrect script behavior.
* **Misunderstanding Return Types:**  Users might assume a function returns a specific type when it returns something else. Clear documentation of return types is crucial.
* **Using Deprecated Features:** The documentation highlights deprecated functions or arguments. Ignoring these warnings can lead to code that breaks in future Frida versions.
* **Typos in Function/Method Names:**  While the documentation itself doesn't directly cause this, clear and accurate naming in the documentation helps users avoid typos when writing their Frida scripts.

**Example of User Error due to potentially incorrect documentation:**

Imagine the documentation for `Interceptor.attach` incorrectly states that the `onEnter` callback receives arguments as a simple list of values, instead of a `NativePointer` array. A user relying on this incorrect documentation might write code that tries to access the arguments as if they were directly available integers or strings, leading to errors when the code attempts to dereference invalid memory locations.

**6. User Path to This Script (Debugging Clues):**

A user would typically not interact with this script directly. The path to this script is part of the **Frida development and build process**. Here's how one might encounter it as a debugging clue:

1. **Encountering Documentation Issues:** A user might notice discrepancies or errors in the official Frida documentation.
2. **Reporting the Issue:**  They might report this issue to the Frida developers.
3. **Developer Investigation:** A developer investigating the documentation issue would likely trace the documentation generation process.
4. **Finding the Script:** They would navigate the Frida source code to find the relevant documentation generation scripts. The directory structure (`frida/subprojects/frida-node/releng/meson/docs/refman/`) is a strong clue. The filename `generatormd.py` clearly indicates its purpose.
5. **Analyzing the Script:** The developer would then analyze this script to understand how the problematic documentation is being generated. They might look for the specific code responsible for generating the incorrect information.
6. **Identifying the Source of Error:** The error could be in:
    * **The `ReferenceManual` data:** The input data might be incorrect.
    * **The logic within `generatormd.py`:** There might be a bug in how it processes the data or renders the Markdown.
    * **The templates:** The Jinja2 templates might have errors in their formatting or logic.

**In summary, `generatormd.py` is a critical component in the Frida ecosystem, responsible for creating the essential reference manual that empowers users to effectively utilize Frida for dynamic instrumentation and, consequently, reverse engineering. Its connection to low-level concepts is indirect but significant, as the documented API provides the interface to interact with these underlying systems.**

Prompt: 
```
这是目录为frida/subprojects/frida-node/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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