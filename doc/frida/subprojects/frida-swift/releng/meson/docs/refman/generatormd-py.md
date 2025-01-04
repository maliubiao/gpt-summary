Response:
Let's break down the thought process for analyzing this Python script.

**1. Initial Understanding - What is this file about?**

The very first lines give a huge clue: `frida/subprojects/frida-swift/releng/meson/docs/refman/generatormd.py`. This tells us:

* **Frida:**  It's related to the Frida dynamic instrumentation toolkit.
* **Swift:**  Specifically, it's part of the Frida integration for Swift.
* **releng:** This likely means "release engineering," suggesting it's involved in the build and release process.
* **meson:**  The build system being used is Meson.
* **docs/refman:** This is clearly for generating documentation, specifically a reference manual.
* **generatormd.py:**  The name strongly implies it generates Markdown (`.md`) files.

Therefore, the core purpose is to generate the Frida Swift API documentation in Markdown format, likely for publication on a website.

**2. High-Level Functionality - What does it *do*?**

Scanning the class `GeneratorMD` and its methods reveals the main actions:

* **Initialization (`__init__`)**: Sets up paths for input and output files (sitemap, link definitions), and stores the `ReferenceManual` object.
* **Filename Generation (`_gen_filename`)**: Creates output filenames based on object IDs.
* **Object ID Generation (`_gen_object_file_id`)**:  Creates unique IDs for objects to organize documentation.
* **Linking (`_link_to_object`)**: Generates placeholder tags that will be later replaced with actual links.
* **File Writing (`_write_file`)**: Writes the generated Markdown content to files.
* **Template Rendering (`_write_template`)**: Uses Jinja-like templates (Chevron) to generate content.
* **Function/Method Generation (`_gen_func_or_method`)**:  Formats documentation for individual functions and methods, including signatures, arguments, and descriptions. This is a *key* part.
* **Object Generation (`_write_object`)**: Formats documentation for objects (classes, modules, etc.), including their methods.
* **Root Reference Manual Generation (`_root_refman_docs`)**: Creates the main index page of the reference manual.
* **Sitemap Configuration (`_configure_sitemap`)**: Integrates the generated files into a sitemap for navigation.
* **Link Definition Generation (`_generate_link_def`)**: Creates a JSON file mapping placeholder tags to actual file locations.
* **Main Generation (`generate`)**: Orchestrates the entire documentation generation process.

**3. Connecting to Reverse Engineering:**

* **Dynamic Instrumentation:** Frida's core purpose is dynamic instrumentation. This documentation *describes* the API used to *perform* reverse engineering tasks like hooking functions, inspecting memory, and tracing execution. The generated documentation becomes a reference for users *doing* reverse engineering with Frida.
* **API Reference:**  Reverse engineers often need to understand the APIs of the systems they are analyzing. Frida provides its own API for interacting with the target process. This script generates the documentation for that API.
* **Binary/Low-Level Knowledge:** While the *script itself* doesn't directly manipulate bits or interact with the kernel, the *API it documents* absolutely does. The documented functions allow users to interact with processes at a low level.

**4. Identifying Binary/Kernel/Framework Connections (through the documented API):**

Even though the *generator* doesn't do these things directly, the *documentation it creates* is about tools that *do*. This is a crucial distinction. Examples would come from the *API being documented*, but we can infer likely areas:

* **Process Interaction:** Functions to attach to processes, detach, enumerate threads, etc.
* **Memory Manipulation:** Functions to read and write memory in the target process.
* **Code Injection/Hooking:** Functions to intercept and modify the execution of code in the target process.
* **Swift Runtime:** Since this is `frida-swift`, the API will likely have features specific to interacting with the Swift runtime environment.
* **Android/Linux Context:** Given Frida's wide usage, the API likely has functions that operate within the context of these operating systems.

**5. Logical Reasoning (Hypothetical Input/Output):**

To demonstrate logical reasoning, we can pick a function like `_gen_func_or_method`.

* **Input (Hypothetical):** A `Function` object representing a function named `send` with a string argument `message` and a boolean return value.
* **Processing:** The function would format the signature, argument details, and description based on the `Function` object's attributes. It would use template rendering to produce Markdown.
* **Output (Hypothetical):** A Markdown snippet like:

```markdown
### send
```
```meson
Bool send(
  String message,     # The message to send
)
```

This showcases the script's logic in transforming structured data into formatted documentation.

**6. Common Usage Errors:**

* **Incorrectly formatted input data:** The `ReferenceManual` object likely comes from parsing some structured data (like JSON or YAML). Errors in that data would lead to incorrect documentation.
* **Template errors:** Mistakes in the Mustache templates could cause rendering issues.
* **Path configuration:** Incorrect paths for input or output files would cause the script to fail.
* **Misunderstanding the placeholders:** Users might try to directly use the `[[tag]]` placeholders without realizing they are processed later by a hotdoc plugin.

**7. Debugging Clues - How to arrive at this script:**

Imagine a user wanting to understand how Frida's Swift API for hooking functions works. Their likely path might be:

1. **Start with Frida's main documentation:**  Look for a Swift API section.
2. **Find the generated reference manual:**  Navigate to the relevant part of the documentation website.
3. **Notice inconsistencies or errors:**  Maybe a function's parameters are unclear or the description is wrong.
4. **Investigate the source of the documentation:** Realize that the documentation is generated.
5. **Look for the generation scripts:** Explore the Frida repository and find the `generatormd.py` script within the `frida-swift` and documentation-related directories.
6. **Examine the script:**  Read the code to understand how the documentation is created and where the data comes from.

This step-by-step process highlights how a user might end up looking at this specific script while trying to debug or understand the Frida Swift documentation.

By following these steps, we can systematically analyze the code, understand its purpose, and connect it to broader concepts like reverse engineering and low-level system interaction, even if the script itself doesn't directly perform those actions. The key is to understand the *context* and the *purpose* of the generated output.
This Python script, `generatormd.py`, is part of the Frida dynamic instrumentation tool's build process, specifically for generating the reference manual documentation for the Frida Swift API. It uses the Meson build system.

Here's a breakdown of its functions:

**Core Functionality: Generating Markdown Documentation**

The primary function of `generatormd.py` is to take a structured representation of the Frida Swift API (likely generated from source code annotations or a similar process) and transform it into a series of Markdown files. These Markdown files then form the basis of the official reference manual.

Here's a breakdown of its key actions:

1. **Reading API Definition:** It receives a `ReferenceManual` object as input. This object likely contains a structured representation of the Frida Swift API, including information about modules, classes, functions, methods, arguments, return types, descriptions, examples, etc.

2. **Generating Markdown Files:**  It iterates through the elements of the `ReferenceManual` (modules, objects, functions) and generates individual Markdown files for each.

3. **Structuring Documentation:** It organizes the documentation into a hierarchy of files and sections. This is evident in functions like `_gen_filename` (creating file names based on object types and names) and the logic in `_root_refman_docs` for generating the main index.

4. **Formatting API Elements:** It formats the descriptions, signatures, arguments, and return types of API elements into readable Markdown. The `_gen_func_or_method` function is central to this, handling the formatting of function and method documentation.

5. **Creating Links:** It generates internal links within the documentation using placeholder tags like `[[@object_name]]` and `[[object_name.method_name]]`. These placeholders are later replaced with actual HTML links by a hotdoc plugin. The `_link_to_object` function handles this.

6. **Using Templates:** It employs Mustache templates (`.mustache` files) to generate the Markdown content. This allows for separation of logic and presentation.

7. **Generating Sitemap:** It contributes to generating a sitemap (`sitemap_out`) which helps structure the navigation of the documentation website.

8. **Generating Link Definitions:** It creates a `link_def_out` file (likely in JSON format) that maps the internal placeholder tags to the actual file locations. This is used by the hotdoc plugin.

**Relationship to Reverse Engineering:**

This script directly supports reverse engineering by generating the documentation for the Frida Swift API. Reverse engineers use Frida to:

* **Inspect running processes:** Examine memory, call stacks, and function arguments.
* **Hook functions:** Intercept function calls, modify arguments and return values, and trace execution flow.
* **Perform dynamic analysis:** Understand the behavior of software at runtime.

The generated reference manual is crucial for reverse engineers to understand how to use the Frida Swift API to achieve these goals. For example:

* **Example:** A reverse engineer wants to hook the `-[NSString stringWithUTF8String:]` method in an iOS application. They would consult the generated documentation to understand the correct syntax for hooking Objective-C methods using the Frida Swift API, including how to specify the class name (`NSString`) and the method signature.

**Involvement of Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

While the script itself is primarily concerned with text manipulation and template rendering, it's intrinsically linked to these lower-level concepts because **the API it documents interacts directly with them**.

* **Binary Bottom:** The Frida API allows interaction with the raw binary code of a process. The documentation generated by this script describes functions that let users read and write memory at specific addresses, disassemble instructions, and inject code.
    * **Example:** The documentation might detail a function to read bytes from a specific memory address within a running process. This directly relates to the binary layout and memory management of the target application.

* **Linux/Android Kernel:** Frida often operates at a level that requires understanding of the underlying operating system kernel. The documentation might include details about how Frida interacts with kernel features for process attachment, memory access, and signal handling. For `frida-swift`, the interaction with the Darwin/XNU kernel on iOS/macOS is relevant.
    * **Example:**  The documentation could describe functions related to inter-process communication (IPC) or system calls, which are fundamental concepts in operating system kernels.

* **Android Framework:** When used on Android, Frida can interact with the Android runtime (ART) and framework services. The documentation for `frida-swift` on Android would explain how to hook Java methods, interact with Android system services, and inspect the state of the Android framework.
    * **Example:** The documentation could detail how to hook a specific method within the `android.app.Activity` class, allowing a reverse engineer to intercept and analyze application lifecycle events.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the `_gen_func_or_method` function.

**Hypothetical Input:** A `Function` object representing a Frida Swift API function named `readCStringUtf8` with the following attributes:

* `name`: "readCStringUtf8"
* `description`: "Reads a null-terminated C string from the specified memory address, assuming UTF-8 encoding."
* `posargs`: A list containing one `PosArg` object:
    * `name`: "address"
    * `type`: A `Type` object representing a pointer (e.g., `NativePointer`)
    * `description`: "The memory address to read from."
* `returns`: A `Type` object representing a string (`String`).
* `example`: A string containing an example code snippet.

**Processing:** The `_gen_func_or_method` function would:

1. Format the function signature: `String readCStringUtf8(NativePointer address)`
2. Generate a section for the argument:
   ```markdown
   #### `address`
   Type: `NativePointer`

   The memory address to read from.
   ```
3. Include the function description.
4. Include the example code snippet.

**Hypothetical Output (Markdown Snippet):**

```markdown
### readCStringUtf8

```meson
String readCStringUtf8(
  NativePointer address,     # The memory address to read from
)
```

Reads a null-terminated C string from the specified memory address, assuming UTF-8 encoding.

#### Arguments

* `address`: `NativePointer`
  The memory address to read from.

#### Returns

`String`

#### Example

```swift
let address: NativePointer = ...
let cString = Process.readCStringUtf8(at: address)
print("Read C string: \(cString)")
```
```

**Common Usage Errors & Debugging Clues:**

Users of the Frida Swift API might encounter errors due to incorrect usage. This script helps generate documentation that aims to prevent these errors. Here are some potential user errors and how debugging might lead back to this script:

* **Incorrect Function Call Syntax:** A user might misspell a function name or provide arguments in the wrong order. The generated documentation clearly shows the correct syntax.
    * **Debugging Clue:** If a user reports an error about an undefined function or type mismatch, a developer might examine `generatormd.py` to ensure the function signature is being generated correctly and matches the actual API.

* **Misunderstanding Argument Types:** A user might pass an integer when a pointer is expected. The documentation specifies the expected types for each argument.
    * **Debugging Clue:** If a user reports an error related to incorrect argument types, a developer might check the `_gen_func_or_method` function to see how argument types are extracted and displayed in the documentation.

* **Not Understanding Return Values:** A user might not know what to expect as the result of a function call. The documentation clearly states the return type and provides a description.
    * **Debugging Clue:** If a user is confused about the return value of a function, a developer might look at how the `returns` attribute of the `Function` object is processed in `_gen_func_or_method`.

**User Operation to Reach This Script (Debugging Scenario):**

1. **User encounters an issue:** A reverse engineer is trying to use a specific function in the Frida Swift API but gets an error or unexpected behavior.
2. **User consults the documentation:** They go to the official Frida documentation website and look up the relevant function.
3. **User finds an error in the documentation:** They notice a typo in the function signature, an incorrect description, or a missing argument.
4. **User reports the documentation error:** They might file an issue on the Frida project's issue tracker.
5. **Developer investigates:** A developer working on Frida Swift examines the reported issue.
6. **Developer traces the documentation generation:** They know the documentation is generated from source code or a structured data format. They identify `generatormd.py` as the script responsible for generating the Markdown for the reference manual.
7. **Developer examines `generatormd.py`:** They look at how the specific function's documentation is generated, checking the logic in `_gen_func_or_method`, the input data (the `ReferenceManual` object), and the relevant Mustache templates.
8. **Developer fixes the issue:** They might correct an error in the source data, the generation logic in `generatormd.py`, or the Mustache template.

In summary, `generatormd.py` is a crucial part of the Frida Swift development process, enabling the creation of accurate and comprehensive documentation that is essential for reverse engineers to effectively utilize the Frida Swift API for dynamic analysis and instrumentation, which inherently involves interacting with the binary level, operating system kernels, and application frameworks.

Prompt: 
```
这是目录为frida/subprojects/frida-swift/releng/meson/docs/refman/generatormd.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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