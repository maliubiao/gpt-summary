Response:
The user wants a summary of the functionalities of the Python script `generate-bindings.py`, specifically focusing on the code snippet provided in the second part of the decomposed question.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The code snippet defines functions and structures related to managing a JavaScript object that wraps a native "relocator" object. The core actions revolve around creating, initializing, resetting, disposing, and garbage collecting these wrapper objects. It also includes functionality to read and access input related to the relocation process.

2. **Relate to Dynamic Instrumentation:** The term "relocator" and the actions of reading input strongly suggest this code is involved in inspecting and manipulating code at runtime. This is central to dynamic instrumentation.

3. **Analyze Individual Functions:**
    * `_free`: Deals with memory management, freeing the native relocator.
    * `_construct`:  Creates the JavaScript wrapper object and links it to the native relocator. It takes input code and a writer object as arguments.
    * `_reset`: Resets the native relocator with new input code and a writer.
    * `_parse_constructor_args`: Extracts the input code and writer object from the JavaScript constructor arguments.
    * `_dispose`:  Disposes of the wrapper object.
    * `_finalize`:  Handles final cleanup before garbage collection.
    * `_gc_mark`:  Marks associated objects for garbage collection.
    * `_read_one`: Reads a single unit of input, likely an instruction, for relocation.
    * `_get_input`:  Provides access to the current input being processed.
    * `_get_eob`, `_get_eoi`: Indicate the end of the input buffer or the end of instructions, respectively.

4. **Connect to Reverse Engineering:** The ability to read and interpret code (`_read_one`, `_get_input`) is a fundamental aspect of reverse engineering. Understanding how code is structured and executed is crucial for analysis.

5. **Infer Underlying Technologies:** The code uses `g_slice_free`, hinting at GLib usage, common in Linux development. The mention of "input code" and "writer" suggests an underlying system for representing and modifying binary data. The use of "relocator" implies dealing with memory addresses and potentially patching or modifying code at runtime, which often involves understanding memory layouts and code structures within processes (relevant to operating systems like Linux and Android).

6. **Consider Potential User Errors:** Misunderstanding the constructor arguments (order, types) is a common programming error. Forgetting to dispose of objects could lead to memory leaks. Incorrect usage of the reset function could lead to unexpected behavior if not provided with valid input.

7. **Trace User Operations (Debugging Context):**  A user would interact with the Frida API in JavaScript. They might create a relocator object, provide it with binary code and a writer, step through the code using `read_one`, and then potentially reset it. This path leads to the execution of the functions in the provided snippet.

8. **Formulate Hypotheses for Input/Output:**
    * **Constructor:** Input would be raw binary data (as `input_code`) and a writer object. Output would be a newly created JavaScript object wrapping the native relocator.
    * **`reset`:** Input would be new binary data and a writer. Output would likely be `undefined` as it modifies the existing object.
    * **`read_one`:** Input is the current state of the relocator. Output is the number of units read (likely 1 if successful, 0 if at the end). It also updates the internal state to point to the next instruction.

9. **Synthesize the Summary:** Combine the observations into a concise summary, highlighting the key functionalities and their relevance to dynamic instrumentation and potentially reverse engineering.

10. **Review and Refine:** Check the summary for clarity, accuracy, and completeness based on the provided code snippet. Ensure it addresses all parts of the user's request.
这是 `frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py` 文件的第二部分代码，主要定义了用于操作和管理一个名为 "relocator" 的对象的 JavaScript 绑定。 这个 "relocator" 对象在 Frida Gum 引擎中负责处理代码重定位的相关操作。

**功能归纳:**

这部分代码的主要功能是为 JavaScript 环境提供操作底层 C++ "relocator" 对象的接口，包括：

* **创建 (Construction):**  允许在 JavaScript 中创建新的 "relocator" 对象，并将其与底层的 C++ 对象关联起来。构造函数接收需要重定位的代码和用于写入重定位后代码的 "writer" 对象作为参数。
* **重置 (Resetting):**  提供方法来重置现有的 "relocator" 对象，使其能够处理新的代码和写入器。
* **销毁 (Disposal):**  提供方法来释放 JavaScript 和 C++ 层面的 "relocator" 对象所占用的资源。
* **读取 (Reading):**  允许逐步读取需要重定位的代码，并获取当前读取到的指令信息。
* **访问属性 (Accessing Properties):**  提供方法来获取 "relocator" 对象的状态信息，例如是否到达代码末尾 (EOB, EOI) 以及当前的输入。
* **垃圾回收 (Garbage Collection):**  定义了垃圾回收相关的函数，确保当 JavaScript 端的对象不再被引用时，底层的 C++ 对象也能被正确释放。

**与逆向方法的关系及举例说明:**

这部分代码与逆向工程密切相关，因为它提供了操作代码重定位的功能，这是动态分析和代码修改的核心技术。

* **动态代码修改:**  "relocator" 负责读取原始代码，并根据需要调整代码中的地址引用，以便将代码放置到内存中的新位置。逆向工程师可以使用 Frida 提供的 API 创建一个 "relocator"，读取目标进程中的代码，并利用其提供的功能来修改代码，例如插入 Hook 代码、修改函数行为等。

    **举例说明:** 假设逆向工程师想要 Hook 一个函数 `target_function`。他可以使用 Frida 读取 `target_function` 的汇编代码，创建一个 "relocator" 对象，并使用 "writer" 对象在代码的开头写入跳转到 Hook 函数的指令。 "relocator" 负责调整原始 `target_function` 中的地址，确保其在新的内存位置也能正常工作。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这部分代码虽然是 JavaScript 绑定，但其背后的 C++ 实现以及它所操作的对象都与底层的知识息息相关：

* **二进制底层:**  "relocator" 需要理解不同架构 (例如 ARM, x86) 的指令格式和编码，才能正确地读取和重定位代码。 `_read_one` 函数读取的指令 (`self->input->insn`) 就是二进制格式的机器码。
* **Linux/Android 内核:** 代码重定位涉及到内存管理和地址空间的理解。在 Linux 和 Android 中，进程拥有独立的地址空间，"relocator" 需要知道如何将代码映射到新的内存地址，并更新代码中的相对或绝对地址。
* **框架知识:** 在 Android 框架中，ART (Android Runtime) 使用 Dex 字节码。虽然这里没有直接提及 Dex，但 Frida 也可以用于分析和修改 ART 运行时的行为，而代码重定位是其中的关键技术。

    **举例说明:** `get_input_target_expression` 的计算 (`self->impl->input_cur - self->input->insn->size`) 涉及指针运算和指令大小的获取，这都是与二进制指令结构和内存布局直接相关的底层操作。对于 Thumb 架构 (`component.flavor == "thumb"`),  地址的最低位会被设置为 1，用于标记 Thumb 指令，这体现了对特定 CPU 架构的二进制指令编码的理解。

**逻辑推理、假设输入与输出:**

* **假设输入 (构造函数 `_construct`):**
    * `input_code`: 指向一段二进制代码的指针。
    * `writer`: 一个 "writer" 对象，用于写入重定位后的代码。
* **输出:**
    * 一个新的 JavaScript "relocator" 对象，该对象内部关联了一个 C++ 的重定位器实例，并已初始化可以处理提供的 `input_code`。

* **假设输入 (`_reset` 函数):**
    * `this_val`:  当前的 "relocator" JavaScript 对象。
    * `args`:  包含新的 `input_code` 和 `writer` 的参数。
* **输出:**
    * `JS_UNDEFINED`: 表示重置操作已完成，并且没有返回特定的值。内部状态会被更新以处理新的代码。

* **假设输入 (`_read_one` 函数):**
    * `this_val`:  当前的 "relocator" JavaScript 对象。
* **输出:**
    * 一个整数，表示读取的字节数。如果成功读取了一条指令，则返回该指令的长度；如果到达代码末尾，则返回 0。同时，内部状态会更新，指向下一条待读取的指令。

**用户或编程常见的使用错误及举例说明:**

* **构造函数参数错误:**  用户可能传递错误的参数类型或顺序给 "relocator" 的构造函数，例如将 "writer" 对象放在 "input_code" 之前，或者传递一个不是二进制数据的对象作为 "input_code"。这会导致 `_gumjs_function_prefix}_parse_constructor_args` 返回 `FALSE`，构造函数抛出异常。
* **未初始化 "writer":**  如果用户在创建 "relocator" 时使用的 "writer" 对象没有被正确初始化，可能会导致重定位过程出错或崩溃。
* **重复 `dispose`:**  用户可能多次调用 `dispose` 方法，导致尝试释放已经被释放的内存，这可能会引发错误。
* **在 `dispose` 后使用:**  尝试在调用 `dispose` 方法之后继续使用 "relocator" 对象，会导致访问无效内存。

**用户操作如何一步步到达这里作为调试线索:**

1. **编写 Frida 脚本:** 用户首先会编写一个 JavaScript 脚本，使用 Frida 的 API 与目标进程进行交互。
2. **获取目标代码:**  脚本可能会使用 `Process.enumerateModules()` 或 `Memory.readByteArray()` 等 API 获取目标进程中的一段二进制代码。
3. **创建 Writer:**  脚本会创建一个 `Gum.Writer` 对象，用于写入修改后的代码。
4. **创建 Relocator:** 脚本会创建一个 `Gum.Relocator` 对象，并将之前获取的代码和创建的 `Writer` 对象作为参数传递给构造函数。  这会触发 `generate-bindings.py` 生成的 `_construct` 函数。
5. **读取和重定位代码:** 脚本可能会调用 `relocator.readOne()` 逐步读取代码，并根据需要使用 `writer` 写入修改后的代码。
6. **处理完成和释放资源:** 脚本可能会调用 `relocator.dispose()` 来释放资源。

在调试过程中，如果用户在创建或使用 `Relocator` 对象时遇到错误，例如构造函数抛出异常或 `readOne` 返回意外的值，那么就可以检查 `generate-bindings.py` 生成的这些绑定函数的行为，例如检查 `_parse_constructor_args` 是否正确解析了参数，或者 `_read_one` 是否正确地读取了指令。  断点可以设置在这些函数内部来追踪执行流程和变量值。

总而言之，这部分代码是 Frida Gum 引擎 JavaScript 绑定的核心组成部分，它将底层的代码重定位功能暴露给 JavaScript 环境，使得逆向工程师能够方便地进行动态代码分析和修改。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
ion_prefix}_free ({wrapper_struct_name} * self)
{{
  _{wrapper_function_prefix}_finalize (self);

  g_slice_free ({wrapper_struct_name}, self);
}}

GUMJS_DEFINE_CONSTRUCTOR ({gumjs_function_prefix}_construct)
{{
  {module_struct_name} * parent;
  JSValue wrapper;
  gconstpointer input_code;
  {writer_wrapper_struct_name} * writer;
  JSValue proto;
  {wrapper_struct_name} * relocator;

  parent = gumjs_get_parent_module (core);

  if (!{gumjs_function_prefix}_parse_constructor_args (args, &input_code, &writer,
      parent))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, parent->{flavor}_relocator_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

  relocator = {wrapper_function_prefix}_alloc (ctx, parent);
  relocator->wrapper = wrapper;
  relocator->impl = {impl_function_prefix}_new (input_code, writer->impl);

  JS_SetOpaque (wrapper, relocator);

  return wrapper;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_reset)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;
  gconstpointer input_code;
  {writer_wrapper_struct_name} * writer;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  if (!{gumjs_function_prefix}_parse_constructor_args (args, &input_code, &writer,
      parent))
    return JS_EXCEPTION;

  {impl_function_prefix}_reset (self->impl, input_code, writer->impl);

  self->input->insn = NULL;

  return JS_UNDEFINED;
}}

static gboolean
{gumjs_function_prefix}_parse_constructor_args (
    GumQuickArgs * args,
    gconstpointer * input_code,
    {writer_wrapper_struct_name} ** writer,
    {module_struct_name} * parent)
{{
  JSValue writer_object;

  if (!_gum_quick_args_parse (args, "pO", input_code, &writer_object))
    return FALSE;

  if (!_gum_quick_{flavor}_writer_get (args->ctx, writer_object, parent->writer,
      writer))
    return FALSE;

  return TRUE;
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_dispose)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  {wrapper_function_prefix}_dispose (self);

  return JS_UNDEFINED;
}}

GUMJS_DEFINE_FINALIZER ({gumjs_function_prefix}_finalize)
{{
  {wrapper_struct_name} * r;

  r = JS_GetOpaque (val, gumjs_get_parent_module (core)->{flavor}_relocator_class);
  if (r == NULL)
    return;

  {wrapper_function_prefix}_free (r);
}}

GUMJS_DEFINE_GC_MARKER ({gumjs_function_prefix}_gc_mark)
{{
  {wrapper_struct_name} * r;

  r = JS_GetOpaque (val, gumjs_get_parent_module (core)->{flavor}_relocator_class);
  if (r == NULL)
    return;

  JS_MarkValue (rt, r->input->wrapper, mark_func);
}}

GUMJS_DEFINE_FUNCTION ({gumjs_function_prefix}_read_one)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;
  guint n_read;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  n_read = {impl_function_prefix}_read_one (self->impl, &self->input->insn);
  if (n_read != 0)
  {{
    self->input->target = {get_input_target_expression};
  }}

  return JS_NewInt32 (ctx, n_read);
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_input)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  if (self->input->insn == NULL)
    return JS_NULL;

  return JS_DupValue (ctx, self->input->wrapper);
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_eob)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return JS_NewBool (ctx, {impl_function_prefix}_eob (self->impl));
}}

GUMJS_DEFINE_GETTER ({gumjs_function_prefix}_get_eoi)
{{
  {module_struct_name} * parent;
  {wrapper_struct_name} * self;

  parent = gumjs_get_parent_module (core);

  if (!_{wrapper_function_prefix}_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return JS_NewBool (ctx, {impl_function_prefix}_eoi (self->impl));
}}
"""

    target = "self->impl->input_cur - self->input->insn->size"
    if component.flavor == "thumb":
        target = "GSIZE_TO_POINTER (GPOINTER_TO_SIZE ({0}) | 1)".format(target)

    params = {
        "writer_wrapper_struct_name": component.wrapper_struct_name.replace("Relocator", "Writer"),
        "get_input_target_expression": target,
    }
    params.update(component.__dict__)

    return template.format(**params).split("\n")

def generate_quick_enum_parser(name, type, prefix, values):
    common_decls, common_code = generate_enum_parser(name, type, prefix, values)

    params = {
        'name': name,
        'result_identifier': name.split("_")[-1].replace("register", "reg"),
        'description': name.replace("_", " "),
        'type': type,
    }

    decls = [
        "static gboolean gum_parse_{name} (JSContext * ctx, const gchar * name, {type} * {result_identifier});".format(**params)
    ] + common_decls

    code = """\
static gboolean
gum_parse_{name} (
    JSContext * ctx,
    const gchar * name,
    {type} * {result_identifier})
{{
  if (!gum_try_parse_{name} (name, {result_identifier}))
  {{
    _gum_quick_throw_literal (ctx, "invalid {description}");
    return FALSE;
  }}

  return TRUE;
}}
""".format(**params).split("\n") + common_code

    return (decls, code)

def generate_v8_bindings(name, arch, flavor, api):
    component = Component(name, arch, flavor, "v8")
    return {
        "gumv8code{0}-{1}.inc".format(name, flavor): generate_v8_wrapper_code(component, api),
        "gumv8code{0}-fields-{1}.inc".format(name, flavor): generate_v8_fields(component),
        "gumv8code{0}-methods-{1}.inc".format(name, flavor): generate_v8_methods(component),
        "gumv8code{0}-init-{1}.inc".format(name, flavor): generate_v8_init_code(component),
        "gumv8code{0}-dispose-{1}.inc".format(name, flavor): generate_v8_dispose_code(component),
    }

def generate_v8_wrapper_code(component, api):
    lines = [
        "/* Auto-generated, do not edit. */",
        "",
        "#include <string>",
        "#include <string.h>",
    ]

    conversion_decls, conversion_code = generate_conversion_methods(component, generate_v8_enum_parser)
    if len(conversion_decls) > 0:
        lines.append("")
        lines.extend(conversion_decls)

    lines.append("")

    lines.extend(generate_v8_base_methods(component))

    for method in api.instance_methods:
        args = method.args

        is_put_array = method.is_put_array
        if method.is_put_call:
            array_item_type = "GumArgument"
            array_item_parse_logic = generate_v8_parse_call_arg_array_element(component, api)
        elif method.is_put_regs:
            array_item_type = api.native_register_type
            array_item_parse_logic = generate_v8_parse_register_array_element(component, api)

        lines.extend([
            "GUMJS_DEFINE_CLASS_METHOD ({0}_{1}, {2})".format(component.gumjs_function_prefix, method.name, component.wrapper_struct_name),
            "{",
            "  if (!{0}_check (self, isolate))".format(component.wrapper_function_prefix),
            "    return;",
        ])

        if len(args) > 0:
            lines.append("")

            for arg in args:
                type_raw = arg.type_raw_for_cpp()
                if type_raw == "$array":
                    type_raw = "Local<Array>"
                lines.append("  {0} {1};".format(type_raw, arg.name_raw_for_cpp()))

            arglist_signature = "".join([arg.type_format_for_cpp() for arg in args])
            arglist_pointers = ", ".join(["&" + arg.name_raw_for_cpp() for arg in args])

            lines.extend([
                "  if (!_gum_v8_args_parse (args, \"{0}\", {1}))".format(arglist_signature, arglist_pointers),
                "    return;",
            ])

        args_needing_conversion = [arg for arg in args if arg.type_converter_for_cpp() is not None]
        if len(args_needing_conversion) > 0:
            lines.append("")
            for arg in args_needing_conversion:
                converter = arg.type_converter_for_cpp()
                if converter == "label":
                    lines.append("  auto {value} = {wrapper_function_prefix}_resolve_label (self, {value_raw});".format(
                        value=arg.name,
                        value_raw=arg.name_raw_for_cpp(),
                        wrapper_function_prefix=component.wrapper_function_prefix))
                elif converter == "address":
                    lines.append("  auto {value} = GUM_ADDRESS ({value_raw});".format(
                        value=arg.name,
                        value_raw=arg.name_raw_for_cpp()))
                elif converter == "bytes":
                    lines.extend([
                        "  gsize {0}_size;".format(arg.name),
                        "  auto {value} = (const guint8 *) g_bytes_get_data ({value_raw}, &{value}_size);".format(
                            value=arg.name,
                            value_raw=arg.name_raw_for_cpp()),
                    ])
                else:
                    lines.extend([
                        "  {0} {1};".format(arg.type, arg.name),
                        "  if (!gum_parse_{arch}_{type} (isolate, {value_raw}, &{value}))".format(
                            value=arg.name,
                            value_raw=arg.name_raw_for_cpp(),
                            arch=component.arch,
                            type=arg.type_converter_for_cpp()),
                        "    return;",
                    ])

        if is_put_array:
            lines.extend(generate_v8_parse_array_elements(array_item_type, array_item_parse_logic).split("\n"))

        impl_function_name = "{0}_{1}".format(component.impl_function_prefix, method.name)

        arglist = ["self->impl"]
        if method.needs_calling_convention_arg:
            arglist.append("GUM_CALL_CAPI")
        for arg in args:
            if arg.type_converter_for_cpp() == "bytes":
                arglist.extend([arg.name, arg.name + "_size"])
            else:
                arglist.append(arg.name)
        if is_put_array:
            impl_function_name += "_array"
            arglist.insert(len(arglist) - 1, "items_length")

        if method.return_type == "void":
            return_capture = ""
        else:
            return_capture = "auto result = "

        lines.extend([
            "",
            "  {0}{1} ({2});".format(return_capture, impl_function_name, ", ".join(arglist))
        ])

        if method.return_type == "gboolean" and method.name.startswith("put_"):
            lines.extend([
                "  if (!result)",
                "    _gum_v8_throw_ascii_literal (isolate, \"invalid argument\");",
            ])
        elif method.return_type != "void":
            lines.append("")
            if method.return_type == "gboolean":
                lines.append("  info.GetReturnValue ().Set (!!result);")
            elif method.return_type == "guint":
                lines.append("  info.GetReturnValue ().Set ((uint32_t) result);")
            elif method.return_type == "gpointer":
                lines.append("  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (result, core));")
            elif method.return_type == "GumAddress":
                lines.append("  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (GSIZE_TO_POINTER (result), core));")
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
                    "    info.GetReturnValue ().Set (_gum_v8_instruction_new (self->impl->capstone, result, FALSE,",
                    "        {0}, module->instruction));".format(target),
                    "  }",
                    "  else",
                    "  {",
                    "    info.GetReturnValue ().SetNull ();"
                    "  }",
                ])
            else:
                raise ValueError("Unsupported return type: {0}".format(method.return_type))

        args_needing_cleanup = [arg for arg in args if arg.type_converter_for_cpp() == "bytes"]
        if len(args_needing_cleanup) > 0:
            lines.append("")
            for arg in args_needing_cleanup:
                lines.append("  g_bytes_unref ({0});".format(arg.name_raw_for_cpp()))

        lines.extend([
            "}",
            ""
        ])

    lines.extend([
        "static const GumV8Function {0}_functions[] =".format(component.gumjs_function_prefix),
        "{",
        "  {{ \"reset\", {0}_reset }},".format(component.gumjs_function_prefix),
        "  {{ \"dispose\", {0}_dispose }},".format(component.gumjs_function_prefix),
    ])
    if component.name == "writer":
        lines.append("  {{ \"flush\", {0}_flush }},".format(component.gumjs_function_prefix))
    elif component.name == "relocator":
        lines.append("  {{ \"readOne\", {0}_read_one }},".format(component.gumjs_function_prefix))

    for method in api.instance_methods:
        lines.append("  {{ \"{0}\", {1}_{2} }},".format(
            method.name_js,
            component.gumjs_function_prefix,
            method.name
        ))

    lines.extend([
        "",
        "  { NULL, NULL }",
        "};",
        ""
    ])

    lines.extend(conversion_code)

    return "\n".join(lines)

def generate_v8_parse_array_elements(item_type, parse_item):
    return """
  auto context = isolate->GetCurrentContext ();

  uint32_t items_length = items_value->Length ();
  auto items = g_newa ({item_type}, items_length);

  for (uint32_t items_index = 0; items_index != items_length; items_index++)
  {{
    {item_type} * item = &items[items_index];
{parse_item}
  }}""".format(item_type=item_type, parse_item=parse_item)

def generate_v8_parse_call_arg_array_element(component, api):
    return """
    auto value = items_value->Get (context, items_index).ToLocalChecked ();
    if (value->IsString ())
    {{
      item->type = GUM_ARG_REGISTER;

      String::Utf8Value value_as_utf8 (isolate, value);
      {native_register_type} value_as_reg;
      if (!gum_parse_{arch}_register (isolate, *value_as_utf8, &value_as_reg))
        return;
      item->value.reg = value_as_reg;
    }}
    else
    {{
      item->type = GUM_ARG_ADDRESS;

      gpointer ptr;
      if (!_gum_v8_native_pointer_parse (value, &ptr, core))
        return;
      item->value.address = GUM_ADDRESS (ptr);
    }}""".format(arch=component.arch, native_register_type=api.native_register_type)

def generate_v8_parse_register_array_element(component, api):
    return """
    auto value = items_value->Get (context, items_index).ToLocalChecked ();
    if (!value->IsString ())
    {{
      _gum_v8_throw_ascii_literal (isolate, "expected an array with register names");
      return;
    }}

    String::Utf8Value value_as_utf8 (isolate, value);
    {native_register_type} value_as_reg;
    if (!gum_parse_{arch}_register (isolate, *value_as_utf8, &value_as_reg))
      return;

    *item = value_as_reg;""".format(arch=component.arch, native_register_type=api.native_register_type)

def generate_v8_fields(component):
    return """\
  GHashTable * {flavor}_{name}s;
  v8::Global<v8::FunctionTemplate> * {flavor}_{name};""".format(**component.__dict__)

def generate_v8_methods(component):
    params = dict(component.__dict__)

    if component.name == "writer":
        extra_fields = "\n  GHashTable * labels;"
    elif component.name == "relocator":
        extra_fields = "\n  GumV8InstructionValue * input;"

    params["extra_fields"] = extra_fields

    template = """\
#include <gum/arch-{arch}/gum{flavor}{name}.h>

struct {wrapper_struct_name}
{{
  v8::Global<v8::Object> * object;
  {impl_struct_name} * impl;{extra_fields}
  {module_struct_name} * module;
}};

G_GNUC_INTERNAL gboolean _gum_v8_{flavor}_writer_get (v8::Local<v8::Value> value,
    {impl_struct_name} ** writer, {module_struct_name} * module);

G_GNUC_INTERNAL {wrapper_struct_name} * _{wrapper_function_prefix}_new_persistent ({module_struct_name} * module);
G_GNUC_INTERNAL void _{wrapper_function_prefix}_release_persistent ({wrapper_struct_name} * {name});
G_GNUC_INTERNAL void _{wrapper_function_prefix}_init ({wrapper_struct_name} * self, {module_struct_name} * module);
G_GNUC_INTERNAL void _{wrapper_function_prefix}_finalize ({wrapper_struct_name} * self);
G_GNUC_INTERNAL void _{wrapper_function_prefix}_reset ({wrapper_struct_name} * self, {impl_struct_name} * impl);"""
    return template.format(**params)

def generate_v8_init_code(component):
    return """\
  auto {flavor}_{name} = _gum_v8_create_class ("{gumjs_class_name}",
      {gumjs_function_prefix}_construct, scope, module, isolate);
  _gum_v8_class_add ({flavor}_{name}, {gumjs_function_prefix}_values, module,
      isolate);
  _gum_v8_class_add ({flavor}_{name}, {gumjs_function_prefix}_functions, module,
      isolate);
  self->{flavor}_{name} =
      new Global<FunctionTemplate> (isolate, {flavor}_{name});

  self->{flavor}_{name}s = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) {wrapper_function_prefix}_free);
""".format(**component.__dict__)

def generate_v8_dispose_code(component):
    return """\
  g_hash_table_unref (self->{flavor}_{name}s);
  self->{flavor}_{name}s = NULL;

  delete self->{flavor}_{name};
  self->{flavor}_{name} = nullptr;
""".format(**component.__dict__)

def generate_v8_base_methods(component):
    if component.name == "writer":
        return generate_v8_writer_base_methods(component)
    elif component.name == "relocator":
        return generate_v8_relocator_base_methods(component)

def generate_v8_writer_base_methods(component):
    template = """\
static {wrapper_struct_name} * {wrapper_function_prefix}_alloc (GumV8CodeWriter * module);
static void {wrapper_function_prefix}_dispose ({wrapper_struct_name} * self);
static void {wrapper_function_prefix}_mark_weak ({wrapper_struct_name} * self);
static void {wrapper_function_prefix}_on_weak_notify (
    const WeakCallbackInfo<{wrapper_struct_name}> & info);
static gboolean {gumjs_function_prefix}_parse_constructor_args (const GumV8Args * args,
    gpointer * code_address, GumAddress * pc, gboolean * pc_specified);
static gboolean {wrapper_function_prefix}_check ({wrapper_struct_name} * self,
    Isolate * isolate);

gboolean
_gum_v8_{flavor}_writer_get (
    v8::Local<v8::Value> value,
    {impl_struct_name} ** writer,
    {module_struct_name} * module)
{{
  auto isolate = module->core->isolate;

  auto writer_class = Local<FunctionTemplate>::New (isolate,
      *module->{flavor}_writer);
  if (!writer_class->HasInstance (value))
  {{
    _gum_v8_throw_ascii_literal (isolate, "expected {flavor} writer");
    return FALSE;
  }}

  auto wrapper = ({wrapper_struct_name} *)
      value.As<Object> ()->GetAlignedPointerFromInternalField (0);
  if (!{wrapper_function_prefix}_check (wrapper, isolate))
    return FALSE;

  *writer = wrapper->impl;
  return TRUE;
}}

{wrapper_struct_name} *
_{wrapper_function_prefix}_new_persistent (GumV8CodeWriter * module)
{{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto writer = {wrapper_function_prefix}_alloc (module);

  auto writer_class = Local<FunctionTemplate>::New (isolate,
      *module->{flavor}_writer);

  auto writer_value = External::New (isolate, writer);
  Local<Value> argv[] = {{ writer_value }};

  auto object = writer_class->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, G_N_ELEMENTS (argv), argv).ToLocalChecked ();

  writer->object = new Global<Object> (isolate, object);

  return writer;
}}

void
_{wrapper_function_prefix}_release_persistent ({wrapper_struct_name} * writer)
{{
  {wrapper_function_prefix}_dispose (writer);

  {wrapper_function_prefix}_mark_weak (writer);
}}

void
_{wrapper_function_prefix}_init (
    {wrapper_struct_name} * self,
    {module_struct_name} * module)
{{
  self->object = nullptr;
  self->impl = NULL;
  self->labels = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  self->module = module;
}}

void
_{wrapper_function_prefix}_finalize ({wrapper_struct_name} * self)
{{
  _{wrapper_function_prefix}_reset (self, NULL);

  g_hash_table_unref (self->labels);

  delete self->object;
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
{wrapper_function_prefix}_alloc (GumV8CodeWriter * module)
{{
  {wrapper_struct_name} * writer;

  writer = g_slice_new ({wrapper_struct_name});
  _{wrapper_function_prefix}_init (writer, module);

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

static void
{wrapper_function_prefix}_mark_weak ({wrapper_struct_name} * self)
{{
  self->object->SetWeak (self, {wrapper_function_prefix}_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->module->{flavor}_{name}s, self);
}}

{label_resolver}
static void
{wrapper_function_prefix}_on_weak_notify (
    const WeakCallbackInfo<{wrapper_struct_name}> & info)
{{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->module->{flavor}_{name}s, self);
}}

static gboolean
{wrapper_function_prefix}_check (
    {wrapper_struct_name} * self,
    Isolate * isolate)
{{
  if (self->impl == NULL)
  {{
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return FALSE;
  }}

  return TRUE;
}}

GUMJS_DEFINE_CONSTRUCTOR ({gumjs_function_prefix}_construct)
{{
  if (!info.IsConstructCall ())
  {{
    _gum_v8_throw_ascii_literal (isolate,
        "use constructor syntax to create a new instance");
    return;
  }}

  {wrapper_struct_name} * writer;

  if (info.Length () == 1 && info[0]->IsExternal ())
  {{
    writer = ({wrapper_struct_name} *) info[0].As<External> ()->Value ();
  }}
  else
  {{
    gpointer code_address;
    GumAddress pc;
    gboolean pc_specified;
    if (!{gumjs_function_prefix}_parse_constructor_args (args, &code_address, &pc,
        &pc_specified))
      return;

    writer = {wrapper_function_prefix}_alloc (module);

    writer->object = new Global<Object> (isolate, wrapper);
    {wrapper_function_prefix}_mark_weak (writer);

    writer->impl = {impl_function_prefix}_new (code_address);
    writer->impl->flush_on_destroy = FALSE;
    if (pc_specified)
      writer->impl->pc = pc;
  }}

  wrapper->SetAlignedPointerInInternalField (0, writer);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_reset, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  gpointer code_address;
  GumAddress pc;
  gboolean pc_specified;
  if (!{gumjs_function_prefix}_parse_constructor_args (args, &code_address, &pc,
      &pc_specified))
    return;

  {impl_function_prefix}_flush (self->impl);

  {impl_function_prefix}_reset (self->impl, code_address);
  if (pc_specified)
    self->impl->pc = pc;

  g_hash_table_remove_all (self->labels);
}}

static gboolean
{gumjs_function_prefix}_parse_constructor_args (
    const GumV8Args * args,
    gpointer * code_address,
    GumAddress * pc,
    gboolean * pc_specified)
{{
  auto isolate = args->core->isolate;

  Local<Object> options;
  if (!_gum_v8_args_parse (args, "p|O", code_address, &options))
    return FALSE;

  *pc = 0;
  *pc_specified = FALSE;

  if (!options.IsEmpty ())
  {{
    auto context = isolate->GetCurrentContext ();

    Local<Value> pc_value;
    if (!options->Get (context, _gum_v8_string_new_ascii (isolate, "pc"))
        .ToLocal (&pc_value))
    {{
      return FALSE;
    }}

    if (!pc_value->IsUndefined ())
    {{
      gpointer raw_value;
      if (!_gum_v8_native_pointer_get (pc_value, &raw_value, args->core))
        return FALSE;
      *pc = GUM_ADDRESS (raw_value);
      *pc_specified = TRUE;
    }}
  }}

  return TRUE;
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_dispose, {wrapper_struct_name})
{{
  if (self->impl != NULL)
    {impl_function_prefix}_flush (self->impl);

  {wrapper_function_prefix}_dispose (self);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_flush, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  auto success = {impl_function_prefix}_flush (self->impl);
  if (!success)
    _gum_v8_throw_ascii_literal (isolate, "unable to resolve references");
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_base, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (self->impl->base, core));
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_code, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (self->impl->code, core));
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_pc, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (self->impl->pc), core));
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_offset, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set ({impl_function_prefix}_offset (self->impl));
}}

static const GumV8Property {gumjs_function_prefix}_values[] =
{{
  {{ "base", {gumjs_function_prefix}_get_base, NULL }},
  {{ "code", {gumjs_function_prefix}_get_code, NULL }},
  {{ "pc", {gumjs_function_prefix}_get_pc, NULL }},
  {{ "offset", {gumjs_function_prefix}_get_offset, NULL }},

  {{ NULL, NULL, NULL }}
}};
"""

    params = dict(component.__dict__)

    params["label_resolver"] = """
static gconstpointer
{wrapper_function_prefix}_resolve_label ({wrapper_struct_name} * self,
    const std::string & str)
{{
  gchar * label = (gchar *) g_hash_table_lookup (self->labels, str.c_str ());
  if (label != NULL)
    return label;

  label = g_strdup (str.c_str ());
  g_hash_table_add (self->labels, label);
  return label;
}}
""".format(**params)

    return template.format(**params).split("\n")

def generate_v8_relocator_base_methods(component):
    template = """\
static {wrapper_struct_name} * {wrapper_function_prefix}_alloc (GumV8CodeRelocator * module);
static void {wrapper_function_prefix}_dispose ({wrapper_struct_name} * self);
static void {wrapper_function_prefix}_mark_weak ({wrapper_struct_name} * self);
static void {wrapper_function_prefix}_on_weak_notify (
    const WeakCallbackInfo<{wrapper_struct_name}> & info);
static gboolean {wrapper_function_prefix}_check ({wrapper_struct_name} * self,
    Isolate * isolate);
static gboolean {gumjs_function_prefix}_parse_constructor_args (const GumV8Args * args,
    gconstpointer * input_code, {writer_impl_struct_name} ** writer,
    GumV8CodeRelocator * module);

gboolean
_gum_v8_{flavor}_relocator_get (
    v8::Local<v8::Value> value,
    {impl_struct_name} ** relocator,
    {module_struct_name} * module)
{{
  auto isolate = module->core->isolate;

  auto relocator_class = Local<FunctionTemplate>::New (isolate,
      *module->{flavor}_relocator);
  if (!relocator_class->HasInstance (value))
  {{
    _gum_v8_throw_ascii_literal (isolate, "expected {flavor} relocator");
    return FALSE;
  }}

  auto relocator_wrapper = ({wrapper_struct_name} *)
      value.As<Object> ()->GetAlignedPointerFromInternalField (0);
  if (!{wrapper_function_prefix}_check (relocator_wrapper, isolate))
    return FALSE;

  *relocator = relocator_wrapper->impl;
  return TRUE;
}}

{wrapper_struct_name} *
_{wrapper_function_prefix}_new_persistent (GumV8CodeRelocator * module)
{{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto relocator = {wrapper_function_prefix}_alloc (module);

  auto relocator_class = Local<FunctionTemplate>::New (isolate,
      *module->{flavor}_relocator);

  auto relocator_value = External::New (isolate, relocator);
  Local<Value> argv[] = {{ relocator_value }};

  auto object = relocator_class->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, G_N_ELEMENTS (argv), argv).ToLocalChecked ();

  relocator->object = new Global<Object> (isolate, object);

  return relocator;
}}

void
_{wrapper_function_prefix}_release_persistent ({wrapper_struct_name} * relocator)
{{
  {wrapper_function_prefix}_dispose (relocator);

  {wrapper_function_prefix}_mark_weak (relocator);
}}

void
_{wrapper_function_prefix}_init (
    {wrapper_struct_name} * self,
    {module_struct_name} * module)
{{
  self->object = nullptr;
  self->impl = NULL;
  self->input = _gum_v8_instruction_new_persistent (module->instruction);
  self->module = module;
}}

void
_{wrapper_function_prefix}_finalize ({wrapper_struct_name} * self)
{{
  _{wrapper_function_prefix}_reset (self, NULL);

  _gum_v8_instruction_release_persistent (self->input);

  delete self->object;
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
{wrapper_function_prefix}_alloc (GumV8CodeRelocator * module)
{{
  {wrapper_struct_name} * relocator;

  relocator = g_slice_new ({wrapper_struct_name});
  _{wrapper_function_prefix}_init (relocator, module);

  return relocator;
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

static void
{wrapper_function_prefix}_mark_weak ({wrapper_struct_name} * self)
{{
  self->object->SetWeak (self, {wrapper_function_prefix}_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->module->{flavor}_{name}s, self);
}}

static void
{wrapper_function_prefix}_on_weak_notify (
    const WeakCallbackInfo<{wrapper_struct_name}> & info)
{{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->module->{flavor}_{name}s, self);
}}

static gboolean
{wrapper_function_prefix}_check (
    {wrapper_struct_name} * self,
    Isolate * isolate)
{{
  if (self->impl == NULL)
  {{
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return FALSE;
  }}

  return TRUE;
}}

GUMJS_DEFINE_CONSTRUCTOR ({gumjs_function_prefix}_construct)
{{
  if (!info.IsConstructCall ())
  {{
    _gum_v8_throw_ascii_literal (isolate,
        "use constructor syntax to create a new instance");
    return;
  }}

  {wrapper_struct_name} * relocator;

  if (info.Length () == 1 && info[0]->IsExternal ())
  {{
    relocator = ({wrapper_struct_name} *) info[0].As<External> ()->Value ();
  }}
  else
  {{
    gconstpointer input_code;
    {writer_impl_struct_name} * writer;
    if (!{gumjs_function_prefix}_parse_constructor_args (args, &input_code, &writer, module))
      return;

    relocator = {wrapper_function_prefix}_alloc (module);

    relocator->object = new Global<Object> (isolate, wrapper);
    {wrapper_function_prefix}_mark_weak (relocator);

    relocator->impl = {impl_
"""


```