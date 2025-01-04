Response:
Let's break down the thought process for analyzing this Python script and fulfilling the prompt's requirements.

**1. Initial Understanding and Goal:**

The first step is to understand the overall purpose of the script. The filename `generate-bindings.py` and the context of Frida (dynamic instrumentation tool) strongly suggest that this script is responsible for generating code that bridges the gap between different parts of Frida. Specifically, "bindings" usually imply connecting a higher-level language (like JavaScript, implied by `gumjs`) with lower-level C/C++ code (`gum`).

**2. High-Level Structure Analysis:**

Next, I'd scan the main functions and their calls to grasp the flow:

* `main`: Entry point, takes output and source directories as arguments, calls `generate_and_write_bindings`.
* `generate_and_write_bindings`: This is the core function. It iterates through `binding_params` (writer, relocator) and `flavor_combos` (architectures and their variants). It calls `generate_umbrellas` and `generate_bindings`. Finally, it aggregates and writes output files.
* `generate_umbrellas`:  Generates "umbrella" include files for different runtimes (quick, v8) and sections.
* `generate_bindings`:  Calls `parse_api` to understand the C API and then generates bindings for different runtimes (quick, v8) and also generates TypeScript definitions (`tsds`) and documentation (`docs`).
* `generate_quick_bindings` and `generate_v8_bindings`: These likely generate the core bridging code for the "quickjs" and "V8" JavaScript engines respectively.

**3. Deeper Dive into Key Functions:**

Now, it's time to examine the core logic:

* **`binding_params` and `flavor_combos`:** These lists define the scope of the binding generation. We see "writer" and "relocator" as key components and various architectures (x86, arm, arm64, mips) with potential flavor variations (thumb for arm).
* **`generate_umbrellas` and `generate_umbrella`:**  These functions create `#include` files with conditional compilation (`#ifdef`) based on architecture. This is a common C/C++ technique for supporting multiple platforms in a single codebase.
* **`generate_bindings`:** The `parse_api` function (not shown but crucial) likely parses C header files to extract information about structures, functions, and their arguments. The rest of the function then uses this parsed information to generate the actual binding code for different JavaScript engines and generate type definitions and documentation.
* **`generate_quick_bindings`:**  This function seems to generate code specifically for the "quickjs" runtime. The function names like `generate_quick_wrapper_code`, `generate_quick_fields`, `generate_quick_methods`, etc., strongly suggest different parts of the binding code are being generated. The code within `generate_quick_wrapper_code` deals with argument parsing, type conversion, and calling the underlying C functions.
* **`generate_v8_bindings`:** (Not shown in the provided snippet, but the structure suggests it would be similar to `generate_quick_bindings` but adapted for the V8 engine.)

**4. Connecting to Prompt Requirements:**

Now, I'd go through each requirement of the prompt:

* **Functionality:**  Summarize the actions of the script based on the structural analysis.
* **Relationship to Reverse Engineering:**  Look for keywords and concepts relevant to reverse engineering. The terms "writer" and "relocator" hint at code manipulation. The architecture-specific logic is also a strong indicator. Think about how these components could be used in a dynamic instrumentation context.
* **Binary/Low-Level/Kernel/Framework:**  Identify mentions of architectures, register types, memory addresses, and interactions with underlying systems. The `#include` directives for architecture-specific headers are a key clue.
* **Logical Reasoning (Hypothetical Input/Output):**  Consider the inputs (source and output directories) and the expected outputs (generated `.inc`, `.d.ts`, and `.md` files). Think about how the loops and conditional logic would affect the output filenames and content.
* **User/Programming Errors:**  Look for potential issues like incorrect command-line arguments or missing header files.
* **User Operation and Debugging:**  Trace back how a user's actions (e.g., running a Frida script) might eventually lead to this binding generation process. Consider the compilation or build process of Frida.

**5. Structuring the Answer:**

Finally, organize the findings into a coherent answer, addressing each point of the prompt with clear explanations and examples where requested. Use headings and bullet points to improve readability. The provided "example answer" structure is a good model.

**Self-Correction/Refinement During Analysis:**

* **Initial thought:**  Maybe the script directly instruments code.
* **Correction:**  The name `generate-bindings` suggests it *creates* the infrastructure for instrumentation, not the instrumentation itself.
* **Initial thought:**  The script only works on Linux.
* **Correction:** While Linux is mentioned, the architecture-agnostic nature of the script (through conditional compilation) implies potential support for other operating systems, even though the *generated* code might interact with OS-specific features.
* **Realization:** The `parse_api` function is crucial even though its code isn't provided. Acknowledging its importance is key to a complete understanding.

By following this structured analysis, moving from high-level understanding to detailed examination, and constantly relating back to the prompt's requirements, a comprehensive and accurate answer can be constructed.
好的，这是对你提供的 `frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py` 源代码文件的第一部分的功能归纳：

**功能归纳：**

这个 Python 脚本的主要功能是**为 Frida 的 Gum 库（一个用于代码检测和操作的库）生成特定于 JavaScript 引擎（QuickJS 和 V8）的绑定代码、TypeScript 类型定义以及 API 参考文档。**  它通过解析 Gum 库的 C 头文件，提取接口信息，然后根据这些信息生成 JavaScript 可以直接调用的代码，以及相应的类型声明和文档说明。

**更具体地说，这个脚本做了以下几件事情：**

1. **定义要生成的绑定:** 通过 `binding_params` 定义了要生成绑定的 Gum 库组件，目前看来是 `writer` 和 `relocator`。每个组件还可以指定需要忽略的 C 函数或方法。
2. **定义支持的架构和指令集:** 通过 `flavor_combos` 定义了要支持的 CPU 架构（x86, arm, arm64, mips）以及相应的指令集变体（例如 arm 的 thumb 模式）。
3. **生成“伞状”包含文件:**  `generate_umbrellas` 函数负责生成 C 语言的包含文件 (`.inc`)，这些文件会根据当前的目标架构和指令集，包含相应的具体实现代码。这样可以在编译时选择性地包含特定架构的代码。
4. **解析 C 头文件并生成绑定:** `generate_and_write_bindings` 函数读取指定架构和组件的 C 头文件（例如 `gumarmwriter.h`），并使用 `generate_bindings` 函数来生成实际的绑定代码。
5. **为不同的 JavaScript 引擎生成绑定:** `generate_bindings` 函数会分别调用 `generate_quick_bindings` 和 `generate_v8_bindings` 为 QuickJS 和 V8 这两个 JavaScript 引擎生成不同的绑定代码。这些绑定代码使得 JavaScript 可以调用 Gum 库的 C 函数。
6. **生成 TypeScript 类型定义:** `generate_bindings` 函数还会调用 `generate_tsds` 来生成 TypeScript 的类型定义文件 (`.d.ts`)，这些文件可以为使用 Frida 的 JavaScript 代码提供类型检查和代码提示。
7. **生成 API 参考文档:** `generate_bindings` 函数还会调用 `generate_docs` 来生成 API 的参考文档 (`.md`)，用于描述 Gum 库的 JavaScript 接口。
8. **组织和写入输出文件:**  脚本会将生成的绑定代码、类型定义和文档写入到指定的输出目录中。

**与逆向方法的联系及举例说明：**

这个脚本是 Frida 工具链的一部分，而 Frida 本身就是一个强大的动态逆向工程工具。 它生成的核心绑定代码直接用于在运行时与目标进程的内存进行交互、修改代码、Hook 函数等操作。

**举例说明：**

* **`writer` 组件:**  `writer` 组件通常用于在目标进程的内存中生成或修改代码。通过这个脚本生成的 JavaScript 绑定，逆向工程师可以使用 JavaScript 代码来创建一个 `Writer` 对象，然后在目标进程的内存中写入指令序列，从而实现动态修改程序行为的目的。 例如，你可以使用 `writer` 来插入一段新的代码，跳转到你的代码，然后再跳回原来的位置，从而实现对某个函数的 Hook。
* **`relocator` 组件:** `relocator` 组件用于将一段机器码从一个内存地址重定位到另一个内存地址。在逆向过程中，当你想把一段代码注入到目标进程的某个位置时，可能需要使用 `relocator` 来调整代码中的绝对地址，使其在新位置也能正确运行。这个脚本生成的绑定就允许逆向工程师在 JavaScript 中方便地使用 `relocator` 完成这个任务。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

这个脚本本身虽然是用 Python 编写，但它生成的代码和处理的数据都与二进制底层、操作系统内核和框架息息相关。

**举例说明：**

* **二进制底层知识:**
    * **架构和指令集 (`flavor_combos`):** 脚本需要了解不同的 CPU 架构（如 x86、ARM）和它们的指令集变体（如 ARM 的 Thumb 模式）。生成的绑定代码需要根据这些架构和指令集的特点进行适配，例如，在 Thumb 模式下，指令的编码方式和寻址方式与 ARM 模式有所不同。
    * **寄存器操作:** `generate_quick_parse_register_array_element` 函数生成的代码会解析 JavaScript 传递的寄存器名称，并将其转换为底层的寄存器表示。这需要了解目标架构的寄存器命名约定。
* **Linux/Android 内核及框架知识:**
    * **内存地址:** `writer` 组件生成的代码允许在指定的内存地址写入数据，这直接涉及到进程的虚拟地址空间管理。
    * **函数调用约定:**  生成的绑定代码需要遵循目标平台的函数调用约定（例如，参数如何传递、返回值如何处理）。虽然代码中没有直接体现，但底层的 Gum 库和生成的绑定代码都必须考虑这些。
    * **系统调用:**  在 Frida 的某些使用场景下，通过生成的绑定，JavaScript 代码最终可能会触发系统调用，与操作系统内核进行交互。

**逻辑推理及假设输入与输出：**

脚本中包含一些逻辑推理，主要是关于如何根据架构和指令集生成不同的代码。

**假设输入：**

假设 `argv` 为 `['generate-bindings.py', '/tmp/output', '/path/to/frida-gum/src']`

* `output_dir`: `/tmp/output` （生成的绑定文件将写入这个目录）
* `source_dir`: `/path/to/frida-gum/src` （Gum 库的源代码目录，包含头文件）

**预期输出（部分）：**

在 `/tmp/output` 目录下会生成以下文件（以及更多）：

* `gumquickcodewriter-arm.inc`:  用于 QuickJS 引擎的 ARM 架构 `writer` 组件的绑定代码片段。
* `gumquickcodewriter-thumb.inc`: 用于 QuickJS 引擎的 ARM 架构 Thumb 指令集 `writer` 组件的绑定代码片段。
* `gumv8codewriter-arm64.inc`: 用于 V8 引擎的 ARM64 架构 `writer` 组件的绑定代码片段。
* `api-types.d.ts`:  包含所有生成的绑定组件的 TypeScript 类型定义。
* `api-reference.md`:  包含所有生成的绑定组件的 API 参考文档。

这些 `.inc` 文件会包含 C 代码片段，其中会包含类似 `#ifdef HAVE_ARM` 的预编译指令，以及对底层 Gum 库函数的调用。`.d.ts` 文件会包含 TypeScript 的接口和类型声明，用于描述 JavaScript 中可用的 Gum 库对象和方法。`.md` 文件会包含对这些接口的文本描述。

**涉及用户或者编程常见的使用错误及举例说明：**

* **错误的命令行参数:** 用户在运行脚本时，如果提供的 `output_dir` 或 `source_dir` 路径不正确，脚本可能会报错或无法找到必要的头文件。
    * **示例:** 运行 `python generate-bindings.py /wrong/output /another/wrong/path`  会导致脚本因为找不到源文件而失败。
* **缺少依赖:** 脚本的运行可能依赖于某些 Python 库（虽然这个脚本本身看起来依赖很少）。如果缺少必要的库，Python 解释器会报错。
* **Gum 库源代码结构变更:** 如果 Gum 库的头文件路径或命名方式发生变化，但脚本没有及时更新，会导致脚本无法找到头文件，从而生成错误的绑定或失败。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **Frida 开发人员或贡献者** 需要修改或添加 Gum 库的功能。
2. 为了让 JavaScript 可以使用这些新的或修改后的功能，他们需要更新 JavaScript 的绑定。
3. 开发人员会**手动运行** `generate-bindings.py` 脚本。
4. 他们会提供正确的 `output_dir` (Frida 源代码树中存放生成文件的位置) 和 `source_dir` (Frida Gum 库的源代码目录)。
5. 脚本读取 Gum 库的 C 头文件。
6. 如果脚本报错，开发人员需要检查：
    * **命令行参数是否正确。**
    * **Gum 库的源代码路径是否正确。**
    * **相关的 C 头文件是否存在于指定的路径。**
    * **脚本内部的逻辑是否正确，例如，对于新的 Gum 库组件，是否在 `binding_params` 中添加了相应的配置。**
    * **对于新的架构或指令集，是否在 `flavor_combos` 中添加了相应的配置，并且 Gum 库中也存在对应的头文件。**

总的来说，这个脚本是 Frida 工具链中至关重要的一部分，它负责将底层的 C/C++ 代码接口桥接到 JavaScript 环境，使得逆向工程师可以使用高级语言方便地进行动态代码分析和操作。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
from __future__ import unicode_literals, print_function
import codecs
import os
import re
import sys


def main(argv):
    output_dir, source_dir = argv[1:]
    generate_and_write_bindings(output_dir, source_dir)

def generate_and_write_bindings(output_dir, source_dir):
    binding_params = [
        ("writer", { 'ignore': ['new', 'ref', 'unref', 'init', 'clear', 'reset',
                                'set_target_cpu', 'set_target_abi', 'set_target_os',
                                'cur', 'offset', 'flush', 'get_cpu_register_for_nth_argument'] }),
        ("relocator", { 'ignore': ['new', 'ref', 'unref', 'init', 'clear', 'reset',
                                   'read_one', 'is_eob_instruction', 'eob', 'eoi', 'can_relocate'] }),
    ]

    flavor_combos = [
        ("x86", "x86"),
        ("arm", "arm"),
        ("arm", "thumb"),
        ("arm64", "arm64"),
        ("mips", "mips"),
    ]

    tsds = {}
    docs = {}

    for name, options in binding_params:
        for filename, code in generate_umbrellas(name, flavor_combos).items():
            with codecs.open(os.path.join(output_dir, filename), "w", 'utf-8') as f:
                f.write(code)

        for arch, flavor in flavor_combos:
            api_header_path = os.path.join(source_dir, "arch-" + arch, "gum{0}{1}.h".format(flavor, name))
            with codecs.open(api_header_path, "r", 'utf-8') as f:
                api_header = f.read().replace("\r", "")

            bindings = generate_bindings(name, arch, flavor, api_header, options)

            for filename, code in bindings.code.items():
                with codecs.open(os.path.join(output_dir, filename), "w", 'utf-8') as f:
                    f.write(code)

            tsds.update(bindings.tsds)
            docs.update(bindings.docs)

    tsd_sections = []
    doc_sections = []
    for arch, flavor in flavor_combos:
        for name, options in binding_params:
            tsd_sections.append(tsds["{0}-{1}.d.ts".format(flavor, name)])
            doc_sections.append(docs["{0}-{1}.md".format(flavor, name)])
        if flavor != "arm":
            tsd_sections.append(tsds["{0}-enums.d.ts".format(arch)])
            doc_sections.append(docs["{0}-enums.md".format(arch)])

    tsd_source = "\n\n".join(tsd_sections)
    with codecs.open(os.path.join(output_dir, "api-types.d.ts"), "w", 'utf-8') as f:
        f.write(tsd_source)

    api_reference = "\n\n".join(doc_sections)
    with codecs.open(os.path.join(output_dir, "api-reference.md"), "w", 'utf-8') as f:
        f.write(api_reference)

def generate_umbrellas(name, flavor_combos):
    umbrellas = {}
    for runtime in ["quick", "v8"]:
        for section in ["", "-fields", "-methods", "-init", "-dispose"]:
            filename, code = generate_umbrella(runtime, name, section, flavor_combos)
            umbrellas[filename] = code
    return umbrellas

def generate_umbrella(runtime, name, section, flavor_combos):
    lines = []

    arch_defines = {
        "x86": "HAVE_I386",
        "arm": "HAVE_ARM",
        "arm64": "HAVE_ARM64",
        "mips": "HAVE_MIPS",
    }

    current_arch = None
    for arch, flavor in flavor_combos:
        if arch != current_arch:
            if current_arch is not None:
                lines.extend([
                    "#endif",
                    "",
                ])
            lines.extend([
                "#ifdef " + arch_defines[arch],
                "",
            ])
            current_arch = arch

        lines.append("# include \"gum{0}code{1}{2}-{3}.inc\"".format(runtime, name, section, flavor))

        if section == "-methods":
            if flavor == "thumb":
                lines.extend(generate_alias_definitions("special", runtime, name, flavor))
            else:
                lines.extend(generate_alias_definitions("default", runtime, name, flavor))
                if flavor != "arm":
                    lines.extend(generate_alias_definitions("special", runtime, name, flavor))

    lines.append("#endif")

    filename = "gum{0}code{1}{2}.inc".format(runtime, name, section)
    code = "\n".join(lines)

    return (filename, code)

def generate_alias_definitions(alias, runtime, name, flavor):
    alias_function_prefix = "gum_{0}_{1}_{2}".format(runtime, alias, name)
    wrapper_function_prefix = "gum_{0}_{1}_{2}".format(runtime, flavor, name)
    impl_function_prefix = "gum_{0}_{1}".format(flavor, name)

    params = {
        "name_uppercase": name.upper(),
        "alias_class_name": to_camel_case("{0}_{1}".format(flavor, name), start_high=True),
        "alias_field_prefix": "{0}_{1}".format(flavor, name),
        "alias_struct_name": to_camel_case(alias_function_prefix, start_high=True),
        "alias_function_prefix": alias_function_prefix,
        "wrapper_macro_prefix": "GUM_{0}_{1}_{2}".format(runtime.upper(), alias.upper(), name.upper()),
        "wrapper_struct_name": to_camel_case(wrapper_function_prefix, start_high=True),
        "wrapper_function_prefix": wrapper_function_prefix,
        "impl_struct_name": to_camel_case(impl_function_prefix, start_high=True),
        "persistent_suffix": "_persistent" if runtime == "v8" else ""
    }

    return """
#define {wrapper_macro_prefix}_CLASS_NAME "{alias_class_name}"
#define {wrapper_macro_prefix}_FIELD {alias_field_prefix}

typedef {wrapper_struct_name} {alias_struct_name};
typedef {impl_struct_name} {alias_struct_name}Impl;

#define _{alias_function_prefix}_new{persistent_suffix} _{wrapper_function_prefix}_new{persistent_suffix}
#define _{alias_function_prefix}_release{persistent_suffix} _{wrapper_function_prefix}_release{persistent_suffix}
#define _{alias_function_prefix}_init _{wrapper_function_prefix}_init
#define _{alias_function_prefix}_finalize _{wrapper_function_prefix}_finalize
#define _{alias_function_prefix}_gc_mark _{wrapper_function_prefix}_gc_mark
#define _{alias_function_prefix}_reset _{wrapper_function_prefix}_reset
""".format(**params).split("\n")

class Bindings(object):
    def __init__(self, code, tsds, docs):
        self.code = code
        self.tsds = tsds
        self.docs = docs

def generate_bindings(name, arch, flavor, api_header, options):
    api = parse_api(name, arch, flavor, api_header, options)

    code = {}
    code.update(generate_quick_bindings(name, arch, flavor, api))
    code.update(generate_v8_bindings(name, arch, flavor, api))

    tsds = generate_tsds(name, arch, flavor, api)

    docs = generate_docs(name, arch, flavor, api)

    return Bindings(code, tsds, docs)

def generate_quick_bindings(name, arch, flavor, api):
    component = Component(name, arch, flavor, "quick")
    return {
        "gumquickcode{0}-{1}.inc".format(name, flavor): generate_quick_wrapper_code(component, api),
        "gumquickcode{0}-fields-{1}.inc".format(name, flavor): generate_quick_fields(component),
        "gumquickcode{0}-methods-{1}.inc".format(name, flavor): generate_quick_methods(component),
        "gumquickcode{0}-init-{1}.inc".format(name, flavor): generate_quick_init_code(component),
        "gumquickcode{0}-dispose-{1}.inc".format(name, flavor): generate_quick_dispose_code(component),
    }

def generate_quick_wrapper_code(component, api):
    lines = [
        "/* Auto-generated, do not edit. */",
        "",
        "#include <string.h>",
    ]

    conversion_decls, conversion_code = generate_conversion_methods(component, generate_quick_enum_parser)
    if len(conversion_decls) > 0:
        lines.append("")
        lines.extend(conversion_decls)

    lines.append("")

    lines.extend(generate_quick_base_methods(component))

    for method in api.instance_methods:
        args = method.args

        is_put_array = method.is_put_array
        if method.is_put_call:
            array_item_type = "GumArgument"
            array_item_parse_logic = generate_quick_parse_call_arg_array_element(component)
        elif method.is_put_regs:
            array_item_type = api.native_register_type
            array_item_parse_logic = generate_quick_parse_register_array_element(component)

        lines.extend([
            "GUMJS_DEFINE_FUNCTION ({0}_{1})".format(component.gumjs_function_prefix, method.name),
            "{",
            "  {0} * parent;".format(component.module_struct_name),
            "  {0} * self;".format(component.wrapper_struct_name),
        ])

        for arg in args:
            type_raw = arg.type_raw
            if type_raw == "$array":
                type_raw = "JSValue"
            lines.append("  {0} {1};".format(type_raw, arg.name_raw))
            converter = arg.type_converter
            if converter is not None:
                if converter == "bytes":
                    lines.extend([
                        "  const guint8 * {0};".format(arg.name),
                        "  gsize {0}_size;".format(arg.name)
                    ])
                elif converter == "label":
                    lines.append("  gconstpointer {0};".format(arg.name))
                else:
                    lines.append("  {0} {1};".format(arg.type, arg.name))
        if is_put_array:
            lines.extend([
                "  guint items_length, items_index;",
                "  {0} * items;".format(array_item_type),
                "  JSValue element_val = JS_NULL;",
                "  const char * element_str = NULL;",
            ])

        if method.return_type == "void":
            return_capture = ""
        else:
            lines.append("  {0} result;".format(method.return_type))
            return_capture = "result = "

        lines.extend([
            "",
            "  parent = gumjs_get_parent_module (core);",
            "",
            "  if (!_{0}_get (ctx, this_val, parent, &self))".format(component.wrapper_function_prefix),
            "    goto propagate_exception;",
        ])

        if len(args) > 0:
            arglist_signature = "".join([arg.type_format for arg in args])
            arglist_pointers = ", ".join(["&" + arg.name_raw for arg in args])

            lines.extend([
                "",
                "  if (!_gum_quick_args_parse (args, \"{0}\", {1}))".format(arglist_signature, arglist_pointers),
                "    goto propagate_exception;",
            ])

        args_needing_conversion = [arg for arg in args if arg.type_converter is not None]
        if len(args_needing_conversion) > 0:
            lines.append("")
            for arg in args_needing_conversion:
                converter = arg.type_converter
                if converter == "label":
                    lines.append("  {value} = {wrapper_function_prefix}_resolve_label (self, {value_raw});".format(
                        value=arg.name,
                        value_raw=arg.name_raw,
                        wrapper_function_prefix=component.wrapper_function_prefix))
                elif converter == "address":
                    lines.append("  {value} = GUM_ADDRESS ({value_raw});".format(
                        value=arg.name,
                        value_raw=arg.name_raw))
                elif converter == "bytes":
                    lines.append("  {value} = g_bytes_get_data ({value_raw}, &{value}_size);".format(
                        value=arg.name,
                        value_raw=arg.name_raw))
                else:
                    lines.append("  if (!gum_parse_{arch}_{type} (ctx, {value_raw}, &{value}))\n    goto propagate_exception;".format(
                        value=arg.name,
                        value_raw=arg.name_raw,
                        arch=component.arch,
                        type=arg.type_converter))

        if is_put_array:
            lines.extend(generate_quick_parse_array_elements(array_item_type, array_item_parse_logic).split("\n"))

        impl_function_name = "{0}_{1}".format(component.impl_function_prefix, method.name)

        arglist = ["self->impl"]
        if method.needs_calling_convention_arg:
            arglist.append("GUM_CALL_CAPI")
        for arg in args:
            if arg.type_converter == "bytes":
                arglist.extend([arg.name, arg.name + "_size"])
            else:
                arglist.append(arg.name)
        if is_put_array:
            impl_function_name += "_array"
            arglist.insert(len(arglist) - 1, "items_length")

        lines.extend([
            "",
            "  {0}{1} ({2});".format(return_capture, impl_function_name, ", ".join(arglist))
        ])

        error_targets = []

        if method.return_type == "gboolean" and method.name.startswith("put_"):
            lines.extend([
                "",
                "  if (!result)",
                "    goto invalid_argument;",
                "",
                "  return JS_UNDEFINED;",
            ])
            error_targets.extend([
                "invalid_argument:",
                "  {",
                "    _gum_quick_throw_literal (ctx, \"invalid argument\");",
                "    goto propagate_exception;",
                "  }",
            ])
        elif method.return_type == "void":
            lines.append("")
            lines.append("  return JS_UNDEFINED;")
        else:
            lines.append("")
            if method.return_type == "gboolean":
                lines.append("  return JS_NewBool (ctx, result);")
            elif method.return_type == "guint":
                lines.append("  return JS_NewInt64 (ctx, result);")
            elif method.return_type == "gpointer":
                lines.append("  return _gum_quick_native_pointer_new (ctx, result, core);")
            elif method.return_type == "GumAddress":
                lines.append("  return _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (result), core);")
            elif method.return_type == "cs_insn *":
                target = "\n".join([
                    "self->impl->input_start + (result->address -",
                    "          (self->impl->input_pc -",
                    "            (self->impl->input_cur - self->impl->input_start)))",
                ])
                if component.flavor == "thumb":
                    target = "GSIZE_TO_POINTER (GPOINTER_TO_SIZE ({0}) | 1)".format(target)
                lines.extend([
                    "  if (result != NULL)",
                    "  {",
                    "    return _gum_quick_instruction_new (ctx, result, FALSE,",
                    "        {0},".format(target),
                    "        self->impl->capstone, parent->instruction, NULL);",
                    "  }",
                    "  else",
                    "  {",
                    "    return JS_NULL;",
                    "  }",
                ])
            else:
                raise ValueError("Unsupported return type: {0}".format(method.return_type))

        lines.append("")
        lines.extend(error_targets)
        lines.extend([
            "propagate_exception:",
            "  {",
        ])
        if is_put_array:
            lines.extend([
                "    JS_FreeCString (ctx, element_str);",
                "    JS_FreeValue (ctx, element_val);",
                "",
            ])
        lines.extend([
            "    return JS_EXCEPTION;",
            "  }",
            "}",
            ""
        ])

    prefix = component.gumjs_function_prefix
    lines.extend([
        "static const JSClassDef {0}_def =".format(prefix),
        "{",
        "  .class_name = \"{0}\",".format(component.gumjs_class_name),
        "  .finalizer = {0}_finalize,".format(prefix),
        "  .gc_mark = {0}_gc_mark,".format(prefix),
        "};",
        "",
        "static const JSCFunctionListEntry {0}_entries[] =".format(prefix),
        "{",
    ])
    if component.name == "writer":
        lines.extend([
            "  JS_CGETSET_DEF (\"base\", {0}_get_base, NULL),".format(prefix),
            "  JS_CGETSET_DEF (\"code\", {0}_get_code, NULL),".format(prefix),
            "  JS_CGETSET_DEF (\"pc\", {0}_get_pc, NULL),".format(prefix),
            "  JS_CGETSET_DEF (\"offset\", {0}_get_offset, NULL),".format(prefix),
            "  JS_CFUNC_DEF (\"reset\", 0, {0}_reset),".format(prefix),
            "  JS_CFUNC_DEF (\"dispose\", 0, {0}_dispose),".format(prefix),
            "  JS_CFUNC_DEF (\"flush\", 0, {0}_flush),".format(prefix),
        ])
    elif component.name == "relocator":
        lines.extend([
            "  JS_CGETSET_DEF (\"input\", {0}_get_input, NULL),".format(prefix),
            "  JS_CGETSET_DEF (\"eob\", {0}_get_eob, NULL),".format(prefix),
            "  JS_CGETSET_DEF (\"eoi\", {0}_get_eoi, NULL),".format(prefix),
            "  JS_CFUNC_DEF (\"reset\", 0, {0}_reset),".format(prefix),
            "  JS_CFUNC_DEF (\"dispose\", 0, {0}_dispose),".format(prefix),
            "  JS_CFUNC_DEF (\"readOne\", 0, {0}_read_one),".format(prefix),
        ])

    for method in api.instance_methods:
        lines.append("  JS_CFUNC_DEF (\"{0}\", 0, {1}_{2}),".format(
            method.name_js,
            component.gumjs_function_prefix,
            method.name
        ))

    lines.extend([
        "};",
        ""
    ])

    lines.extend(conversion_code)

    return "\n".join(lines)

def generate_quick_parse_array_elements(item_type, parse_item):
    return """
  if (!_gum_quick_array_get_length (ctx, items_value, core, &items_length))
    goto propagate_exception;
  items = g_newa ({item_type}, items_length);

  for (items_index = 0; items_index != items_length; items_index++)
  {{
    {item_type} * item = &items[items_index];

    element_val = JS_GetPropertyUint32 (ctx, items_value, items_index);
    if (JS_IsException (element_val))
      goto propagate_exception;
{parse_item}

    JS_FreeValue (ctx, element_val);
    element_val = JS_NULL;
  }}""".format(item_type=item_type, parse_item=parse_item)

def generate_quick_parse_call_arg_array_element(component):
    return """
    if (JS_IsString (element_val))
    {{
      {register_type} r;

      element_str = JS_ToCString (ctx, element_val);
      if (element_str == NULL)
        goto propagate_exception;

      if (!gum_parse_{arch}_register (ctx, element_str, &r))
        goto propagate_exception;

      item->type = GUM_ARG_REGISTER;
      item->value.reg = r;

      JS_FreeCString (ctx, element_str);
      element_str = NULL;
    }}
    else
    {{
      gpointer ptr;

      if (!_gum_quick_native_pointer_parse (ctx, element_val, core, &ptr))
        goto propagate_exception;

      item->type = GUM_ARG_ADDRESS;
      item->value.address = GUM_ADDRESS (ptr);
    }}""".format(arch=component.arch, register_type=component.register_type)

def generate_quick_parse_register_array_element(component):
    return """
    if (!JS_IsString (element_val))
      goto invalid_argument;

    {{
      {register_type} reg;

      element_str = JS_ToCString (ctx, element_val);
      if (element_str == NULL)
        goto propagate_exception;

      if (!gum_parse_{arch}_register (ctx, element_str, &reg))
        goto propagate_exception;

      *item = reg;

      JS_FreeCString (ctx, element_str);
      element_str = NULL;
    }}""".format(arch=component.arch, register_type=component.register_type)

def generate_quick_fields(component):
    return """  JSClassID {flavor}_{name}_class;
  JSValue {flavor}_{name}_proto;""".format(**component.__dict__)

def generate_quick_methods(component):
    params = dict(component.__dict__)

    extra_fields = ""
    if component.name == "writer":
        extra_fields = "\n  GHashTable * labels;"
    if component.name == "relocator":
        extra_fields = "\n  GumQuickInstructionValue * input;"

    params["extra_fields"] = extra_fields

    template = """\
#include <gum/arch-{arch}/gum{flavor}{name}.h>

typedef struct _{wrapper_struct_name} {wrapper_struct_name};

struct _{wrapper_struct_name}
{{
  JSValue wrapper;
  {impl_struct_name} * impl;{extra_fields}
  JSContext * ctx;
}};

G_GNUC_INTERNAL JSValue _gum_quick_{flavor}_{name}_new (JSContext * ctx, {impl_struct_name} * impl, {module_struct_name} * parent, {wrapper_struct_name} ** {flavor}_{name});
G_GNUC_INTERNAL gboolean _gum_quick_{flavor}_{name}_get (JSContext * ctx, JSValue val, {module_struct_name} * parent, {wrapper_struct_name} ** writer);

G_GNUC_INTERNAL void _gum_quick_{flavor}_{name}_init ({wrapper_struct_name} * self, JSContext * ctx, {module_struct_name} * parent);
G_GNUC_INTERNAL void _gum_quick_{flavor}_{name}_finalize ({wrapper_struct_name} * self);
G_GNUC_INTERNAL void _gum_quick_{flavor}_{name}_gc_mark ({wrapper_struct_name} * self);
G_GNUC_INTERNAL void _gum_quick_{flavor}_{name}_reset ({wrapper_struct_name} * self, {impl_struct_name} * impl);
"""
    return template.format(**params)

def generate_quick_init_code(component):
    return """\
  _gum_quick_create_class (ctx, &{gumjs_function_prefix}_def, core,
      &self->{gumjs_field_prefix}_class, &proto);
  self->{gumjs_field_prefix}_proto = JS_DupValue (ctx, proto);
  ctor = JS_NewCFunction2 (ctx, {gumjs_function_prefix}_construct,
      {gumjs_function_prefix}_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, {gumjs_function_prefix}_entries,
      G_N_ELEMENTS ({gumjs_function_prefix}_entries));
  JS_DefinePropertyValueStr (ctx, ns, {gumjs_function_prefix}_def.class_name, ctor,
      JS_PROP_C_W_E);
""".format(**component.__dict__)

def generate_quick_dispose_code(component):
    return """\
  JS_FreeValue (ctx, self->{gumjs_field_prefix}_proto);
  self->{gumjs_field_prefix}_proto = JS_NULL;
""".format(**component.__dict__)

def generate_quick_base_methods(component):
    if component.name == "writer":
        return generate_quick_writer_base_methods(component)
    elif component.name == "relocator":
        return generate_quick_relocator_base_methods(component)

def generate_quick_writer_base_methods(component):
    template = """\
static {wrapper_struct_name} * {wrapper_function_prefix}_alloc (JSContext * ctx, {module_struct_name} * module);
static void {wrapper_function_prefix}_dispose ({wrapper_struct_name} * self);
static gboolean {gumjs_function_prefix}_parse_constructor_args (GumQuickArgs * args,
    gpointer * code_address, GumAddress * pc, gboolean * pc_specified);

JSValue
_gum_quick_{flavor}_writer_new (
    JSContext * ctx,
    {impl_struct_name} * impl,
    {module_struct_name} * parent,
    {wrapper_struct_name} ** writer)
{{
  JSValue wrapper;
  {wrapper_struct_name} * w;

  wrapper = JS_NewObjectClass (ctx, parent->{flavor}_writer_class);

  w = {wrapper_function_prefix}_alloc (ctx, parent);
  w->impl = (impl != NULL) ? {impl_function_prefix}_ref (impl) : NULL;

  JS_SetOpaque (wrapper, w);

  if (writer != NULL)
    *writer = w;

  return wrapper;
}}

gboolean
_gum_quick_{flavor}_writer_get (
    JSContext * ctx,
    JSValue val,
    {module_struct_name} * parent,
    {wrapper_struct_name} ** writer)
{{
  {wrapper_struct_name} * w;

  if (!_gum_quick_unwrap (ctx, val, parent->{flavor}_writer_class, parent->core,
      (gpointer *) &w))
    return FALSE;

  if (w->impl == NULL)
  {{
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }}

  *writer = w;
  return TRUE;
}}

void
_{wrapper_function_prefix}_init (
    {wrapper_struct_name} * self,
    JSContext * ctx,
    {module_struct_name} * parent)
{{
  self->wrapper = JS_NULL;
  self->impl = NULL;
  self->ctx = ctx;
  self->labels = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
}}

void
_{wrapper_function_prefix}_finalize ({wrapper_struct_name} * self)
{{
  _gum_quick_{flavor}_writer_reset (self, NULL);
  g_hash_table_unref (self->labels);
}}

void
_{wrapper_function_prefix}_reset (
    {wrapper_struct_name} * self,
    {impl_struct_name} * impl)
{{
  if (impl != NULL)
    {impl_function_prefix}_ref (impl);
  if (self->impl != NULL)
    {impl_function_prefix}_unref (self->impl);
  self->impl = impl;

  g_hash_table_remove_all (self->labels);
}}

static {wrapper_struct_name} *
{wrapper_function_prefix}_alloc (JSContext * ctx,
                                 {module_struct_name} * module)
{{
  {wrapper_struct_name} * writer;

  writer = g_slice_new ({wrapper_struct_name});
  _{wrapper_function_prefix}_init (writer, ctx, module);

  return writer;
}}

static void
{wrapper_function_prefix}_dispose ({wrapper_struct_name} * self)
{{
  _{wrapper_function_prefix}_reset (self, NULL);
}}

static void
{wrapper_function_prefix}_free ({wrapper_struct_name} * self)
{{
  _{wrapper_function_prefix}_finalize (self);

  g_slice_free ({wrapper_struct_name}, self);
}}

{label_resolver}

GUMJS_DEFINE_CONSTRUCTOR ({gumjs_function_prefix}_construct)
{{
  {module_struct_name} * parent;
  JSValue wrapper;
  gpointer code_address;
  GumAddress pc;
  gboolean pc_specified;
  JSValue proto;
  {wrapper_struct_name} * writer;

  parent = gumjs_get_parent_module (core);

  if (!{gumjs_function_prefix}_parse_constructor_args (args, &code_address, &pc,
      &pc_specified))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, parent->{flavor}_writer_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

  writer = {wrapper_function_prefix}_alloc (ctx, parent);
  writer->wrapper = wrapper;
  writer->impl = {impl_function_prefix}_new (code_address);
  writer->impl->flush_on_destroy = FALSE;
  if (pc_specified)
    writer->impl->pc = pc;

  JS_SetOpaque (wrapper, writer);

  return wrapper;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_reset)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;
  gpointer code_address;
  GumAddress pc;
  gboolean pc_specified;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  if (!{gumjs_function_prefix}_parse_constructor_args (args, &code_address, &pc,
      &pc_specified))
    return JS_EXCEPTION;

  {impl_function_prefix}_flush (self->impl);

  {impl_function_prefix}_reset (self->impl, code_address);
  if (pc_specified)
    self->impl->pc = pc;

  g_hash_table_remove_all (self->labels);

  return JS_UNDEFINED;
}}

static gboolean
{gumjs_function_prefix}_parse_constructor_args (
    GumQuickArgs * args,
    gpointer * code_address,
    GumAddress * pc,
    gboolean * pc_specified)
{{
  JSContext * ctx = args->ctx;
  JSValue options;

  options = JS_NULL;
  if (!_gum_quick_args_parse (args, "p|O", code_address, &options))
    return FALSE;

  *pc = 0;
  *pc_specified = FALSE;

  if (!JS_IsNull (options))
  {{
    GumQuickCore * core = args->core;
    JSValue val;

    val = JS_GetProperty (ctx, options, GUM_QUICK_CORE_ATOM (core, pc));
    if (JS_IsException (val))
      return FALSE;

    if (!JS_IsUndefined (val))
    {{
      gboolean valid;
      gpointer p;

      valid = _gum_quick_native_pointer_get (ctx, val, core, &p);
      JS_FreeValue (ctx, val);
      if (!valid)
        return FALSE;

      *pc = GUM_ADDRESS (p);
      *pc_specified = TRUE;
    }}

  }}

  return TRUE;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_dispose)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  {impl_function_prefix}_flush (self->impl);

  {wrapper_function_prefix}_dispose (self);

  return JS_UNDEFINED;
}}

GUMJS_DEFINE_FINALIZER ({gumjs_function_prefix}_finalize)
{{
  {wrapper_struct_name} * w;

  w = JS_GetOpaque (val, gumjs_get_parent_module (core)->{flavor}_writer_class);
  if (w == NULL)
    return;

  {wrapper_function_prefix}_free (w);
}}

GUMJS_DEFINE_GC_MARKER ({gumjs_function_prefix}_gc_mark)
{{
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_flush)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;
  gboolean success;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  success = {impl_function_prefix}_flush (self->impl);
  if (!success)
    return _gum_quick_throw_literal (ctx, "unable to resolve references");

  return JS_UNDEFINED;
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_base)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, self->impl->base, core);
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_code)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, self->impl->code, core);
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_pc)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (self->impl->pc),
      core);
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_offset)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return JS_NewInt32 (ctx, {impl_function_prefix}_offset (self->impl));
}}
"""
    params = dict(component.__dict__)

    params["label_resolver"] = """static gconstpointer
{wrapper_function_prefix}_resolve_label ({wrapper_struct_name} * self,
    const gchar * str)
{{
  gchar * label = g_hash_table_lookup (self->labels, str);
  if (label != NULL)
    return label;

  label = g_strdup (str);
  g_hash_table_add (self->labels, label);
  return label;
}}""".format(**params)

    return template.format(**params).split("\n")

def generate_quick_relocator_base_methods(component):
    template = """\
static {wrapper_struct_name} * {wrapper_function_prefix}_alloc (JSContext * ctx, {module_struct_name} * module);
static void {wrapper_function_prefix}_dispose ({wrapper_struct_name} * self);
static gboolean {gumjs_function_prefix}_parse_constructor_args (GumQuickArgs * args,
    gconstpointer * input_code, {writer_wrapper_struct_name} ** writer, {module_struct_name} * parent);

JSValue
_gum_quick_{flavor}_relocator_new (
    JSContext * ctx,
    {impl_struct_name} * impl,
    {module_struct_name} * parent,
    {wrapper_struct_name} ** relocator)
{{
  JSValue wrapper;
  {wrapper_struct_name} * r;

  wrapper = JS_NewObjectClass (ctx, parent->{flavor}_relocator_class);

  r = {wrapper_function_prefix}_alloc (ctx, parent);
  r->impl = (impl != NULL) ? {impl_function_prefix}_ref (impl) : NULL;

  JS_SetOpaque (wrapper, r);

  if (relocator != NULL)
    *relocator = r;

  return wrapper;
}}

gboolean
_gum_quick_{flavor}_relocator_get (
    JSContext * ctx,
    JSValue val,
    {module_struct_name} * parent,
    {wrapper_struct_name} ** relocator)
{{
  {wrapper_struct_name} * r;

  if (!_gum_quick_unwrap (ctx, val, parent->{flavor}_relocator_class, parent->core,
      (gpointer *) &r))
    return FALSE;

  if (r->impl == NULL)
  {{
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }}

  *relocator = r;
  return TRUE;
}}

void
_{wrapper_function_prefix}_init (
    {wrapper_struct_name} * self,
    JSContext * ctx,
    {module_struct_name} * parent)
{{
  self->wrapper = JS_NULL;
  self->impl = NULL;
  _gum_quick_instruction_new (ctx, NULL, TRUE, NULL, 0, parent->instruction,
      &self->input);
  self->ctx = ctx;
}}

void
_{wrapper_function_prefix}_finalize ({wrapper_struct_name} * self)
{{
  _{wrapper_function_prefix}_reset (self, NULL);

  JS_FreeValue (self->ctx, self->input->wrapper);
}}

void
_{wrapper_function_prefix}_reset (
    {wrapper_struct_name} * self,
    {impl_struct_name} * impl)
{{
  if (impl != NULL)
    {impl_function_prefix}_ref (impl);
  if (self->impl != NULL)
    {impl_function_prefix}_unref (self->impl);
  self->impl = impl;

  self->input->insn = NULL;
}}

static {wrapper_struct_name} *
{wrapper_function_prefix}_alloc (JSContext * ctx,
                                 {module_struct_name} * parent)
{{
  {wrapper_struct_name} * relocator;

  relocator = g_slice_new ({wrapper_struct_name});
  _{wrapper_function_prefix}_init (relocator, ctx, parent);

  return relocator;
}}

static void
{wrapper_function_prefix}_dispose ({wrapper_struct_name} * self)
{{
  _{wrapper_function_prefix}_reset (self, NULL);
}}

static void
{wrapper_funct
"""


```