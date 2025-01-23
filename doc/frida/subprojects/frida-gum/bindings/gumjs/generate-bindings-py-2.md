Response:
The user wants me to analyze a Python file that seems to generate C++ bindings for a Frida component related to code generation and relocation.

I need to:
1. **List the functionalities** of the Python script.
2. **Explain its relevance to reverse engineering**, providing examples.
3. **Connect it to binary, Linux, Android kernel/framework concepts**, with examples.
4. **Describe logical inferences** with input/output examples.
5. **Illustrate common usage errors**.
6. **Detail the user path** to this script as a debugging step.
7. **Summarize the script's function** (as this is part 3 of 4).

Let's break down the code section by section to identify its purpose and how it achieves it.

**Core Functionalities:**
- Generates C++ code for V8 bindings (JavaScript API for Frida).
- Handles different architectures (x86, ARM, ARM64, MIPS) and flavors (like Thumb for ARM).
- Defines classes for `writer` (code generation) and `relocator` (code relocation).
- Generates methods for these classes, mapping to underlying C/C++ implementations.
- Creates enum parsers for various architecture-specific constants (registers, instructions, condition codes, etc.).
- Generates TypeScript definition files (`.d.ts`) for the JavaScript API.
- Generates API documentation in Markdown format.

**Relationship to Reverse Engineering:**
- The `writer` class is crucial for dynamically generating code during reverse engineering. This allows injecting custom logic into a running process.
- The `relocator` class helps in moving code snippets from one memory location to another, adjusting addresses as needed. This is essential for code patching and instrumentation.

**Binary, Linux, Android Kernel/Framework Concepts:**
- **Binary底层:** The script deals with generating machine code instructions, which are the fundamental building blocks of executables. The register enums and instruction ID enums directly correspond to the binary instruction set of different architectures.
- **Linux/Android内核:** Frida often operates within the address space of a running process on Linux or Android. The generated code might interact with system calls or kernel structures. The `put_breakpoint` function directly relates to kernel debugging mechanisms.
- **Android框架:**  When targeting Android, Frida can interact with the Dalvik/ART runtime. While not directly visible in this code snippet, the generated bindings could be used to manipulate objects, call methods, or hook framework functions.

**Logical Inferences:**
- **Input:**  The script takes high-level descriptions of classes, methods, and enums as input (likely from a configuration file or directly within the script, though not shown in the provided snippet).
- **Output:** It outputs C++ source code, TypeScript definition files, and Markdown documentation. The naming conventions (`gumjs_function_prefix`, `wrapper_struct_name`) suggest a systematic approach to generating the bindings.

**Common Usage Errors:**
- Incorrectly specifying register names or instruction mnemonics when using the generated API in JavaScript.
- Passing incorrect argument types or numbers to the generated methods.
- Forgetting to call `flush()` on the `writer`, leading to incomplete code generation.
- Using the `relocator` on incompatible code or without proper setup of the output `writer`.

**User Operation and Debugging:**
1. A developer wants to use Frida to dynamically instrument a target process.
2. They decide to use the Gum library within Frida for low-level code manipulation.
3. They need a JavaScript interface to interact with Gum's C/C++ functionalities.
4. The `generate-bindings.py` script is executed (likely as part of Frida's build process or when generating specific bindings) to create this JavaScript interface.
5. If there's an issue with the generated bindings (e.g., a missing method, incorrect type definitions), a developer might investigate this script to understand how the bindings are created and identify potential errors in its logic or configuration.

**Summary of Functionality (Part 3):**

This part of the `generate-bindings.py` script focuses on **generating the C++ source code for the JavaScript bindings of the `relocator` class**. It defines the C++ methods that will be exposed to JavaScript, allowing users to interact with the code relocation functionalities provided by Frida's Gum library. This includes methods for creating, resetting, and disposing of relocator instances, reading instructions, and accessing information about the input code. It also defines how constructor arguments are parsed and how the underlying C++ implementation is accessed.

This part of the `generate-bindings.py` script focuses on generating C++ source code for the V8 (JavaScript engine) bindings of a specific component within Frida-Gum. Based on the naming conventions and the code structure, this component appears to be a **"relocator"**.

Here's a breakdown of its functionalities as shown in this snippet:

**Functionalities:**

1. **Class Definition:** It defines the C++ class structure and methods for a JavaScript accessible object, likely named something like `GumJsRelocator` (derived from the template variables). This class wraps the underlying C++ implementation of the relocator.

2. **Constructor Binding (`{gumjs_function_prefix}_new`):**
   - It creates a new instance of the relocator when the corresponding JavaScript constructor is called.
   - It takes `input_code` (the memory address of the code to relocate) and a `writer` object (representing the destination where the relocated code will be written) as arguments.
   - It sets an internal field in the V8 wrapper object to store the underlying C++ relocator instance.

3. **Reset Binding (`{gumjs_function_prefix}_reset`):**
   - It provides a way to recycle an existing relocator instance with new input code and a new writer.
   - This avoids the overhead of creating a new object from scratch.

4. **Argument Parsing (`{gumjs_function_prefix}_parse_constructor_args`):**
   - It handles the conversion of JavaScript arguments passed to the constructor into the appropriate C++ types (`gconstpointer` for `input_code` and a pointer to the writer implementation).
   - It uses Frida's internal helper functions (`_gum_v8_args_parse` and `_gum_v8_{flavor}_writer_get`) for argument validation and type conversion.

5. **Dispose Binding (`{gumjs_function_prefix}_dispose`):**
   - It provides a mechanism to explicitly release the resources held by the relocator object when it's no longer needed.

6. **Read One Instruction Binding (`{gumjs_function_prefix}_read_one`):**
   - It implements the functionality to read the next instruction from the input code.
   - It calls the underlying C++ implementation's `_read_one` function.
   - It updates an internal state (`self->input->insn`) with the read instruction.
   - It calculates and stores the target address of the instruction (likely the address of the instruction in the original code).
   - It returns the number of bytes read.

7. **Input Getter Binding (`{gumjs_function_prefix}_get_input`):**
   - It provides a way to access the last read instruction from the JavaScript side.
   - It returns the instruction object if one has been read, otherwise it returns `null`.

8. **End of Block Getter Binding (`{gumjs_function_prefix}_get_eob`):**
   - It exposes a property indicating whether the relocator has reached the end of a basic block (e.g., a branch instruction).

9. **End of Input Getter Binding (`{gumjs_function_prefix}_get_eoi`):**
   - It exposes a property indicating whether the relocator has reached the end of the input code.

10. **Property Definition (`{gumjs_function_prefix}_values`):**
    - It defines the properties that are accessible from JavaScript, mapping the getter functions to property names like "input", "eob", and "eoi".

**Relationship to Reverse Engineering:**

Yes, this code is directly related to reverse engineering methods.

*   **Code Relocation:** The core function is to relocate code. In reverse engineering, you often need to move code snippets to different memory locations for instrumentation or analysis without breaking execution due to hardcoded addresses. This relocator helps in adjusting those addresses.
    *   **Example:** Imagine you want to insert a hook function at the beginning of another function. You would use the relocator to copy the original function's prologue to a new location, then insert a jump to your hook, and finally jump back to the relocated prologue. The relocator ensures that any relative jumps or calls within the prologue are adjusted to the new memory addresses.

*   **Dynamic Instrumentation:** This code is part of Frida, a dynamic instrumentation toolkit. Dynamic instrumentation involves modifying the behavior of a running program without needing its source code. The relocator is a key component in enabling this by allowing the manipulation of code at runtime.

**Binary 底层, Linux, Android 内核及框架的知识:**

*   **Binary 底层:**
    *   The script deals with concepts like "input code" and "instruction." This directly relates to the raw bytes of machine code in an executable.
    *   The `read_one` function is about parsing and understanding the structure of individual machine code instructions.
    *   The calculation of `target` address (`self->impl->input_cur - self->input->insn->size`) and the handling of Thumb mode (`GSIZE_TO_POINTER (GPOINTER_TO_SIZE ({0}) | 1)`) directly relate to the architecture-specific details of instruction encoding and addressing. Thumb mode is a compact instruction set for ARM processors.

*   **Linux/Android 内核:**
    *   Frida often operates by injecting an agent into a running process. The "input code" being relocated likely resides within the memory space of this process.
    *   The ability to read and manipulate code in memory requires understanding the memory management mechanisms of the operating system kernel.

*   **Android 框架:**
    *   On Android, Frida can be used to instrument applications running on the Dalvik/ART virtual machine. The code being relocated could be native code within the application or even parts of the ART runtime itself.

**逻辑推理 (假设输入与输出):**

Let's assume:

*   **Input:**
    *   `input_code`: A memory address `0x1000` pointing to the start of a sequence of ARM instructions.
    *   `writer`: A `GumJsWriter` instance associated with a memory buffer starting at `0x2000`.

*   **Hypothetical JavaScript Usage:**
    ```javascript
    const relocator = new GumRelocator(ptr('0x1000'), writer);
    let bytesRead = relocator.readOne();
    console.log("Bytes read:", bytesRead);
    console.log("Input instruction:", relocator.input);
    console.log("End of block:", relocator.eob);
    console.log("End of input:", relocator.eoi);
    ```

*   **Output (Conceptual):**
    *   `bytesRead`: Would be the size of the first instruction at `0x1000` (e.g., 4 bytes for a standard ARM instruction).
    *   `relocator.input`: Would be a JavaScript object representing the disassembled instruction read from `0x1000`. This object would contain details like the instruction's opcode, operands, and size.
    *   `relocator.eob`: Would be `true` if the instruction at `0x1000` is a branch instruction (e.g., `B`, `BL`), and `false` otherwise.
    *   `relocator.eoi`: Would be `false` initially, as there's likely more code to read after the first instruction.

**用户或编程常见的使用错误:**

*   **Incorrect Writer:** Passing a `writer` object that is not properly initialized or is pointing to an invalid memory location could lead to crashes or unexpected behavior when the relocator tries to write the relocated code.
*   **Memory Access Violations:** If the `input_code` points to memory that is not readable, the `read_one` function might fail or cause a segmentation fault.
*   **Forgetting to Check `eoi`:** Continuously calling `readOne()` after `eoi` is `true` would not read any new instructions and might lead to unexpected states or errors in subsequent relocation steps.
*   **Misunderstanding `eob`:** Assuming that `eob` being `true` always means the end of a function. `eob` simply indicates a branch instruction, which might occur within a function as well.

**用户操作是如何一步步的到达这里，作为调试线索:**

1. A user is writing a Frida script to instrument a target process.
2. They need to move a block of code from one location to another, for example, to insert a custom hook function.
3. They use the `Memory.readCode()` function to get a `NativePointer` to the code they want to relocate.
4. They create a `MemoryAllocation` to allocate a new buffer for the relocated code.
5. They create a `GumWriter` instance associated with the newly allocated buffer.
6. They then create a `GumRelocator` instance, providing the `NativePointer` to the original code and the `GumWriter` instance.
7. While stepping through the relocation process using the JavaScript API (e.g., calling `relocator.readOne()`, `relocator.writeOne()`), they encounter an issue – perhaps the relocated code is not functioning correctly, or Frida throws an error.
8. As a debugging step, they might want to understand the underlying C++ implementation of the `GumRelocator` and how it reads the instructions. This leads them to investigate the Frida source code, specifically the `frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py` script, to see how the JavaScript bindings for `GumRelocator` are generated and what the corresponding C++ functions are.

**归纳一下它的功能 (作为第3部分):**

As the third part of a four-part generation process, this section of `generate-bindings.py` is responsible for **generating the C++ source code that bridges the gap between the JavaScript API of the `GumRelocator` class and its underlying C++ implementation within Frida-Gum**. It defines the V8-specific methods that handle JavaScript calls to create, reset, interact with, and manage the lifecycle of `GumRelocator` objects. This ensures that JavaScript developers can effectively utilize Frida's code relocation capabilities within their instrumentation scripts.

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/generate-bindings.py的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能
```

### 源代码
```python
function_prefix}_new (input_code, writer);
  }}

  wrapper->SetAlignedPointerInInternalField (0, relocator);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_reset, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  gconstpointer input_code;
  {writer_impl_struct_name} * writer;
  if (!{gumjs_function_prefix}_parse_constructor_args (args, &input_code, &writer, module))
    return;

  {impl_function_prefix}_reset (self->impl, input_code, writer);

  self->input->insn = NULL;
}}

static gboolean
{gumjs_function_prefix}_parse_constructor_args (
    const GumV8Args * args,
    gconstpointer * input_code,
    {writer_impl_struct_name} ** writer,
    {module_struct_name} * module)
{{
  Local<Object> writer_object;
  if (!_gum_v8_args_parse (args, "pO", input_code, &writer_object))
    return FALSE;

  if (!_gum_v8_{flavor}_writer_get (writer_object, writer, module->writer))
    return FALSE;

  return TRUE;
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_dispose, {wrapper_struct_name})
{{
  {wrapper_function_prefix}_dispose (self);
}}

GUMJS_DEFINE_CLASS_METHOD ({gumjs_function_prefix}_read_one, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  uint32_t n_read = {impl_function_prefix}_read_one (self->impl, &self->input->insn);
  if (n_read != 0)
  {{
    self->input->target = {get_input_target_expression};
  }}

  info.GetReturnValue ().Set (n_read);
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_input, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  if (self->input->insn != NULL)
  {{
    info.GetReturnValue ().Set (
        Local<Object>::New (isolate, *self->input->object));
  }}
  else
  {{
    info.GetReturnValue ().SetNull ();
  }}
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_eob, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set (!!{impl_function_prefix}_eob (self->impl));
}}

GUMJS_DEFINE_CLASS_GETTER ({gumjs_function_prefix}_get_eoi, {wrapper_struct_name})
{{
  if (!{wrapper_function_prefix}_check (self, isolate))
    return;

  info.GetReturnValue ().Set (!!{impl_function_prefix}_eoi (self->impl));
}}

static const GumV8Property {gumjs_function_prefix}_values[] =
{{
  {{ "input", {gumjs_function_prefix}_get_input, NULL }},
  {{ "eob", {gumjs_function_prefix}_get_eob, NULL }},
  {{ "eoi", {gumjs_function_prefix}_get_eoi, NULL }},

  {{ NULL, NULL, NULL }}
}};
"""

    target = "self->impl->input_cur - self->input->insn->size"
    if component.flavor == "thumb":
        target = "GSIZE_TO_POINTER (GPOINTER_TO_SIZE ({0}) | 1)".format(target)

    params = {
        "writer_impl_struct_name": to_camel_case('gum_{0}_writer'.format(component.flavor), start_high=True),
        "get_input_target_expression": target,
    }
    params.update(component.__dict__)

    return template.format(**params).split("\n")

def generate_v8_enum_parser(name, type, prefix, values):
    common_decls, common_code = generate_enum_parser(name, type, prefix, values)

    params = {
        'name': name,
        'description': name.replace("_", " "),
        'type': type,
    }

    decls = [
        "static gboolean gum_parse_{name} (Isolate * isolate, const std::string & name, {type} * value);".format(**params)
    ] + common_decls

    code = """\
static gboolean
gum_parse_{name} (
    Isolate * isolate,
    const std::string & name,
    {type} * value)
{{
  if (!gum_try_parse_{name} (name.c_str (), value))
  {{
    _gum_v8_throw_literal (isolate, "invalid {description}");
    return FALSE;
  }}

  return TRUE;
}}
""".format(**params).split("\n") + common_code

    return (decls, code)

arch_names = {
    "x86": "x86",
    "arm": "ARM",
    "arm64": "AArch64",
    "mips": "MIPS",
}

writer_enums = {
    "x86": [
        ("x86_register", "GumX86Reg", "GUM_X86_", [
            "xax", "xcx", "xdx", "xbx", "xsp", "xbp", "xsi", "xdi",
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
            "xip", "eip", "rip",
        ]),
        ("x86_instruction_id", "x86_insn", "X86_INS_", [
            "jo", "jno", "jb", "jae", "je", "jne", "jbe", "ja", "js", "jns",
            "jp", "jnp", "jl", "jge", "jle", "jg", "jcxz", "jecxz", "jrcxz",
        ]),
        ("x86_branch_hint", "GumBranchHint", "GUM_", [
            "no-hint", "likely", "unlikely",
        ]),
        ("x86_pointer_target", "GumX86PtrTarget", "GUM_X86_PTR_", [
            "byte", "dword", "qword",
        ]),
    ],
    "arm": [
        ("arm_register", "arm_reg", "ARM_REG_", [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "sp", "lr", "sb", "sl", "fp", "ip", "pc",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
            "s10", "s11", "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19",
            "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29",
            "s30", "s31",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9",
            "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19",
            "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29",
            "d30", "d31",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9",
            "q10", "q11", "q12", "q13", "q14", "q15",
        ]),
        ("arm_system_register", "arm_sysreg", "ARM_SYSREG_", [
            "apsr-nzcvq",
        ]),
        ("arm_condition_code", "arm_cc", "ARM_CC_", [
            "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
            "hi", "ls", "ge", "lt", "gt", "le", "al",
        ]),
        ("arm_shifter", "arm_shifter", "ARM_SFT_", [
            "asr", "lsl", "lsr", "ror", "rrx", "asr-reg", "lsl-reg", "lsr-reg",
            "ror-reg", "rrx-reg",
        ]),
    ],
    "thumb": [],
    "arm64": [
        ("arm64_register", "arm64_reg", "ARM64_REG_", [
            "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9",
            "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17", "x18", "x19",
            "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27", "x28", "x29",
            "x30",
            "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8", "w9",
            "w10", "w11", "w12", "w13", "w14", "w15", "w16", "w17", "w18", "w19",
            "w20", "w21", "w22", "w23", "w24", "w25", "w26", "w27", "w28", "w29",
            "w30",
            "sp", "lr", "fp",
            "wsp", "wzr", "xzr", "nzcv", "ip0", "ip1",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9",
            "s10", "s11", "s12", "s13", "s14", "s15", "s16", "s17", "s18", "s19",
            "s20", "s21", "s22", "s23", "s24", "s25", "s26", "s27", "s28", "s29",
            "s30", "s31",
            "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7", "d8", "d9",
            "d10", "d11", "d12", "d13", "d14", "d15", "d16", "d17", "d18", "d19",
            "d20", "d21", "d22", "d23", "d24", "d25", "d26", "d27", "d28", "d29",
            "d30", "d31",
            "q0", "q1", "q2", "q3", "q4", "q5", "q6", "q7", "q8", "q9",
            "q10", "q11", "q12", "q13", "q14", "q15", "q16", "q17", "q18", "q19",
            "q20", "q21", "q22", "q23", "q24", "q25", "q26", "q27", "q28", "q29",
            "q30", "q31",
        ]),
        ("arm64_condition_code", "arm64_cc", "ARM64_CC_", [
            "eq", "ne", "hs", "lo", "mi", "pl", "vs", "vc",
            "hi", "ls", "ge", "lt", "gt", "le", "al", "nv",
        ]),
        ("arm64_index_mode", "GumArm64IndexMode", "GUM_INDEX_", [
            "post-adjust", "signed-offset", "pre-adjust",
        ]),
    ],
    "mips": [
        ("mips_register", "mips_reg", "MIPS_REG_", [
            "v0", "v1", "a0", "a1", "a2", "a3",
            "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
            "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
            "t8", "t9",
            "k0", "k1",
            "gp", "sp", "fp", "s8", "ra",
            "hi", "lo", "zero", "at",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
            "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
            "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
            "30", "31",
        ]),
    ],
}

def generate_conversion_methods(component, generate_parser):
    decls = []
    code = []

    if component.name == "writer":
        for enum in writer_enums[component.flavor]:
            d, c = generate_parser(*enum)
            decls += d
            code += c

    return (decls, code)

def generate_enum_parser(name, type, prefix, values):
    decls = [
        "static gboolean gum_try_parse_{name} (const gchar * name, {type} * value);".format(name=name, type=type)
    ]

    statements = []
    for i, value in enumerate(values):
        statements.extend([
            f"  if (strcmp (name, \"{value}\") == 0)",
            "  {",
            "    *value = {}{};".format(prefix, value.upper().replace("-", "_")),
            "    return TRUE;",
            "  }",
        ])

    code = """\
static gboolean
gum_try_parse_{name} (
    const gchar * name,
    {type} * value)
{{
{statements}

  return FALSE;
}}
""".format(
        name=name,
        type=type,
        statements="\n".join(statements),
    )

    return (decls, code.split("\n"))

def generate_tsds(name, arch, flavor, api):
    tsds = {}
    tsds.update(generate_class_type_definitions(name, arch, flavor, api))
    tsds.update(generate_enum_type_definitions(name, arch, flavor, api))
    return tsds

def generate_class_type_definitions(name, arch, flavor, api):
    lines = []

    class_name = to_camel_case("{0}_{1}".format(flavor, name), start_high=True)
    writer_class_name = to_camel_case("{0}_writer".format(flavor, "writer"), start_high=True)

    params = {
        "arch": arch,
        "arch_name": arch_names[arch],
        "arch_namespace": arch.title(),
        "class_name": class_name,
        "writer_class_name": writer_class_name,
    }

    if name == "writer":
        class_description = "Generates machine code for {0}.".format(arch)
    else:
        class_description = "Relocates machine code for {0}.".format(arch)

    lines.extend([
        "/**",
        " * " + class_description,
        " */",
        "declare class {0} {{".format(class_name),
    ])

    if name == "writer":
        lines.extend("""\
    /**
     * Creates a new code writer for generating {arch_name} machine code
     * written directly to memory at `codeAddress`.
     *
     * @param codeAddress Memory address to write generated code to.
     * @param options Options for customizing code generation.
     */
    constructor(codeAddress: NativePointerValue, options?: {class_name}Options);

    /**
     * Recycles instance.
     */
    reset(codeAddress: NativePointerValue, options?: {class_name}Options): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Resolves label references and writes pending data to memory. You
     * should always call this once you've finished generating code. It
     * is usually also desirable to do this between pieces of unrelated
     * code, e.g. when generating multiple functions in one go.
     */
    flush(): void;

    /**
     * Memory location of the first byte of output.
     */
    base: NativePointer;

    /**
     * Memory location of the next byte of output.
     */
    code: NativePointer;

    /**
     * Program counter at the next byte of output.
     */
    pc: NativePointer;

    /**
     * Current offset in bytes.
     */
    offset: number;""".format(**params).split("\n"))
    elif name == "relocator":
        lines.extend("""\
    /**
     * Creates a new code relocator for copying {arch_name} instructions
     * from one memory location to another, taking care to adjust
     * position-dependent instructions accordingly.
     *
     * @param inputCode Source address to copy instructions from.
     * @param output {writer_class_name} pointed at the desired target memory
     *               address.
     */
    constructor(inputCode: NativePointerValue, output: {writer_class_name});

    /**
     * Recycles instance.
     */
    reset(inputCode: NativePointerValue, output: {writer_class_name}): void;

    /**
     * Eagerly cleans up memory.
     */
    dispose(): void;

    /**
     * Latest `Instruction` read so far. Starts out `null` and changes
     * on every call to `readOne()`.
     */
    input: Instruction | null;

    /**
     * Indicates whether end-of-block has been reached, i.e. we've
     * reached a branch of any kind, like CALL, JMP, BL, RET.
     */
    eob: boolean;

    /**
     * Indicates whether end-of-input has been reached, e.g. we've
     * reached JMP/B/RET, an instruction after which there may or may
     * not be valid code.
     */
    eoi: boolean;

    /**
     * Reads the next instruction into the relocator's internal buffer
     * and returns the number of bytes read so far, including previous
     * calls.
     *
     * You may keep calling this method to keep buffering, or immediately
     * call either `writeOne()` or `skipOne()`. Or, you can buffer up
     * until the desired point and then call `writeAll()`.
     *
     * Returns zero when end-of-input is reached, which means the `eoi`
     * property is now `true`.
     */
    readOne(): number;""".format(**params).split("\n"))

    for method in api.instance_methods:
        arg_names = [arg.name_js for arg in method.args]

        description = ""
        if method.name.startswith("put_"):
            if method.name == "put_label":
                description = """Puts a label at the current position, where `id` is an identifier
     * that may be referenced in past and future `put*Label()` calls"""
            elif method.name.startswith("put_call") and "_with_arguments" in method.name:
                description = """Puts code needed for calling a C function with the specified `args`"""
                arg_names[-1] = "args"
            elif method.name.startswith("put_call") and "_with_aligned_arguments" in method.name:
                description = """Like `putCallWithArguments()`, but also
     * ensures that the argument list is aligned on a 16 byte boundary"""
                arg_names[-1] = "args"
            elif method.name == "put_branch_address":
                description = "Puts code needed for branching/jumping to the given address"
            elif method.name in ("put_push_regs", "put_pop_regs"):
                if method.name.startswith("put_push_"):
                    mnemonic = "PUSH"
                else:
                    mnemonic = "POP"
                description = """Puts a {mnemonic} instruction with the specified registers""".format(mnemonic=mnemonic)
                arg_names[-1] = "regs"
            elif method.name == "put_push_all_x_registers":
                description = """Puts code needed for pushing all X registers on the stack"""
            elif method.name == "put_push_all_q_registers":
                description = """Puts code needed for pushing all Q registers on the stack"""
            elif method.name == "put_pop_all_x_registers":
                description = """Puts code needed for popping all X registers off the stack"""
            elif method.name == "put_pop_all_q_registers":
                description = """Puts code needed for popping all Q registers off the stack"""
            elif method.name == "put_prologue_trampoline":
                description = "Puts a minimal sized trampoline for vectoring to the given address"
            elif method.name == "put_ldr_reg_ref":
                description = """Puts an LDR instruction with a dangling data reference,
     * returning an opaque ref value that should be passed to `putLdrRegValue()`
     * at the desired location"""
            elif method.name == "put_ldr_reg_value":
                description = """Puts the value and updates the LDR instruction
     * from a previous `putLdrRegRef()`"""
            elif method.name == "put_breakpoint":
                description = "Puts an OS/architecture-specific breakpoint instruction"
            elif method.name == "put_padding":
                description = "Puts `n` guard instruction"
            elif method.name == "put_nop_padding":
                description = "Puts `n` NOP instructions"
            elif method.name == "put_instruction":
                description = "Puts a raw instruction"
            elif method.name == "put_instruction_wide":
                description = "Puts a raw Thumb-2 instruction"
            elif method.name == "put_u8":
                description = "Puts a uint8"
            elif method.name == "put_s8":
                description = "Puts an int8"
            elif method.name == "put_bytes":
                description = "Puts raw data"
            elif method.name.endswith("no_auth"):
                opcode = method.name.split("_")[1].upper()
                description = """Puts {0} instruction expecting a raw pointer without
     * any authentication bits""".format(make_indefinite(opcode))
            else:
                types = set(["reg", "imm", "offset", "indirect", "short", "near", "ptr", "base", "index", "scale", "address", "label", "u8", "i32", "u32", "u64"])
                opcode = " ".join(filter(lambda token: token not in types, method.name.split("_")[1:])).upper()
                description = "Puts {0} instruction".format(make_indefinite(opcode))
                if method.name.endswith("_label"):
                    description += """ referencing `labelId`, defined by a past
     * or future `putLabel()`"""
        elif method.name == "skip":
            description = "Skips `nBytes`"
        elif method.name == "peek_next_write_insn":
            description = "Peeks at the next `Instruction` to be written or skipped".format(**params)
        elif method.name == "peek_next_write_source":
            description = "Peeks at the address of the next instruction to be written or skipped"
        elif method.name.startswith("skip_one"):
            description = "Skips the instruction that would have been written next"
            if method.name.endswith("_no_label"):
                description += """,
     * but without a label for internal use. This breaks relocation of branches to
     * locations inside the relocated range, and is an optimization for use-cases
     * where all branches are rewritten (e.g. Frida's Stalker)"""
        elif method.name.startswith("write_one"):
            description = "Writes the next buffered instruction"
            if method.name.endswith("_no_label"):
                description += """, but without a
     * label for internal use. This breaks relocation of branches to locations
     * inside the relocated range, and is an optimization for use-cases where all
     * branches are rewritten (e.g. Frida's Stalker)"""
        elif method.name == "copy_one":
            description = """Copies out the next buffered instruction without advancing the
     * output cursor, allowing the same instruction to be written out
     * multiple times"""
        elif method.name.startswith("write_all"):
            description = "Writes all buffered instructions"
        elif method.name == "can_branch_directly_between":
            description = """Determines whether a direct branch is possible between the two
     * given memory locations"""
        elif method.name == "commit_label":
            description = """Commits the first pending reference to the given label, returning
     * `true` on success. Returns `false` if the given label hasn't been
     * defined yet, or there are no more pending references to it"""
        elif method.name == "sign":
            description = "Signs the given pointer value"

        p = {}
        p.update(params)
        p.update({
            "method_name": method.name_js,
            "method_arglist": ", ".join([n + ": " + t for n, t in zip(arg_names, [arg.type_ts for arg in method.args])]),
            "method_return_type": method.return_type_ts,
            "method_description": description,
        })

        lines.extend("""\

    /**
     * {method_description}.
     */
    {method_name}({method_arglist}): {method_return_type};""".format(**p).split("\n"))

    lines.append("}")

    if name == "writer":
        lines.extend("""
interface {class_name}Options {{
    /**
     * Specifies the initial program counter, which is useful when
     * generating code to a scratch buffer. This is essential when using
     * `Memory.patchCode()` on iOS, which may provide you with a
     * temporary location that later gets mapped into memory at the
     * intended memory location.
     */
    pc?: NativePointer | undefined;
}}""".format(**params).split("\n"))

        if flavor != "thumb":
            lines.extend([
                "",
                "type {arch_namespace}CallArgument = {arch_namespace}Register | number | UInt64 | Int64 | NativePointerValue;".format(**params),
            ])

    return {
        "{0}-{1}.d.ts".format(flavor, name): "\n".join(lines),
    }

def generate_enum_type_definitions(name, arch, flavor, api):
    lines = []

    for name, type, prefix, values in writer_enums[arch]:
        name_ts = to_camel_case(name, start_high=True)
        name_components = name.replace("_", " ").title().split(" ")

        if len(lines) > 0:
            lines.append("")

        values_ts = " | ".join(["\"{0}\"".format(val) for val in values])
        raw_decl = "type {0} = {1};".format(name_ts, values_ts)
        lines.extend(reflow_enum_declaration(raw_decl))

    return {
        "{0}-enums.d.ts".format(arch): "\n".join(lines),
    }

def reflow_enum_declaration(decl):
    if len(decl.split(" | ")) <= 3:
        return [decl]

    first_line, rest = decl.split(" = ", 1)

    values = rest.rstrip(";").split(" | ")

    return [first_line + " ="] + ["    | {0}".format(val) for val in values] + ["    ;"]

def generate_docs(name, arch, flavor, api):
    docs = {}
    docs.update(generate_class_api_reference(name, arch, flavor, api))
    docs.update(generate_enum_api_reference(name, arch, flavor, api))
    return docs

def generate_class_api_reference(name, arch, flavor, api):
    lines = []

    class_name = to_camel_case("{0}_{1}".format(flavor, name), start_high=True)
    writer_class_name = to_camel_case("{0}_writer".format(flavor, "writer"), start_high=True)

    params = {
        "arch": arch,
        "arch_name": arch_names[arch],
        "class_name": class_name,
        "writer_class_name": writer_class_name,
        "writer_class_link_indefinite": "{0} [{1}](#{2})".format(
            make_indefinite_qualifier(writer_class_name),
            writer_class_name,
            writer_class_name.lower()),
        "instruction_link": "[Instruction](#instruction)",
    }

    lines.extend([
        "## {0}".format(class_name),
        "",
    ])

    if name == "writer":
        lines.extend("""\
+   `new {class_name}(codeAddress[, {{ pc: ptr('0x1234') }}])`: create a new code
    writer for generating {arch_name} machine code written directly to memory at
    `codeAddress`, specified as a NativePointer.
    The second argument is an optional options object where the initial program
    counter may be specified, which is useful when generating code to a scratch
    buffer. This is essential when using `Memory.patchCode()` on iOS, which may
    provide you with a temporary location that later gets mapped into memory at
    the intended memory location.

-   `reset(codeAddress[, {{ pc: ptr('0x1234') }}])`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `flush()`: resolve label references and write pending data to memory. You
    should always call this once you've finished generating code. It is usually
    also desirable to do this between pieces of unrelated code, e.g. when
    generating multiple functions in one go.

-   `base`: memory location of the first byte of output, as a NativePointer

-   `code`: memory location of the next byte of output, as a NativePointer

-   `pc`: program counter at the next byte of output, as a NativePointer

-   `offset`: current offset as a JavaScript Number
""".format(**params).split("\n"))
    elif name == "relocator":
        lines.extend("""\
+   `new {class_name}(inputCode, output)`: create a new code relocator for
    copying {arch_name} instructions from one memory location to another, taking
    care to adjust position-dependent instructions accordingly.
    The source address is specified by `inputCode`, a NativePointer.
    The destination is given by `output`, {writer_class_link_indefinite} pointed
    at the desired target memory address.

-   `reset(inputCode, output)`: recycle instance

-   `dispose()`: eagerly clean up memory

-   `input`: latest {instruction_link} read so far. Starts out `null`
    and changes on every call to `readOne()`.

-   `eob`: boolean indicating whether end-of-block has been reached, i.e. we've
    reached a branch of any kind, like CALL, JMP, BL, RET.

-   `eoi`: boolean indicating whether end-of-input has been reached, e.g. we've
    reached JMP/B/RET, an instruction after which there may or may not be valid
    code.

-   `readOne()`: read the next instruction into the relocator's internal buffer
    and return the number of bytes read so far, including previous calls.
    You may keep calling this method to keep buffering, or immediately call
    either `writeOne()` or `skipOne()`. Or, you can buffer up until the desired
    point and then call `writeAll()`.
    Returns zero when end-of-input is reached, which means the `eoi` property is
    now `true`.
""".format(**params).split("\n"))

    for method in api.instance_methods:
        arg_names = [arg.name_js for arg in method.args]

        description = ""
        if method.name.startswith("put_"):
            if method.name == "put_label":
                description = """put a label at the current position, where `id` is a string
    that may be referenced in past and future `put*Label()` calls"""
            elif method.name.startswith("put_call") and "_with_arguments" in method.name:
                description = """put code needed for calling a C
    function with the specified `args`, specified as a JavaScript array where
    each element is either a string specifying the register, or a Number or
    NativePointer specifying the immediate value."""
                arg_names[-1] = "args"
            elif method.name.startswith("put_call") and "_with_aligned_arguments" in method.name:
                description = """like above, but also
    ensures that the argument list is aligned on a 16 byte boundary"""
                arg_names[-1] = "args"
            elif method.name == "put_branch_address":
                description = """put code needed for branching/jumping to the
    given address"""
            elif method.name in ("put_push_regs", "put_pop_regs"):
                if method.name.startswith("put_push_"):
                    mnemonic = "PUSH"
                else:
                    mnemonic = "POP"
                description = """put a {mnemonic} instruction with the specified registers,
    specified as a JavaScript array where each element is a string specifying
    the register name.""".format(mnemonic=mnemonic)
                arg_names[-1] = "regs"
            elif method.name == "put_push_all_x_registers":
                description = """put code needed for pushing all X registers on the stack"""
            elif method.name == "put_push_all_q_registers":
                description = """put code needed for pushing all Q registers on the stack"""
            elif method.name == "put_pop_all_x_registers":
                description = """put code needed for popping all X registers off the stack"""
            elif method.name == "put_pop_all_q_registers":
                description = """put code needed for popping all Q registers off the stack"""
            elif method.name == "put_prologue_trampoline":
                description = """put a minimal sized trampoline for
    vectoring to the given address"""
            elif method.name == "put_ldr_reg_ref":
                description = """put an LDR instruction with a dangling data reference,
    returning an opaque ref value that should be passed to `putLdrRegValue()`
    at the desired location"""
            elif method.name == "put_ldr_reg_value":
                description = """put the value and update the LDR instruction
    from a previous `putLdrRegRef()`"""
            elif method.name == "put_breakpoint":
                description = "put an OS/architecture-specific breakpoint instruction"
            elif method.name == "put_padding":
                description = "put `n` guard instruction"
            elif method.name == "put_nop_padding":
                description = "put `n` NOP instructions"
            elif method.name == "put_instruction":
                description = "put a raw instruction as a JavaScript Number"
            elif method.name == "put_instruction_wide":
                description = "put a raw Thumb-2 instruction from\n    two JavaScript Number values"
            elif method.name == "put_u8":
                description = "put a uint8"
            elif method.name == "put_s8":
                description = "put an int8"
            elif method.name == "put_bytes":
                description = "put raw data from the provided ArrayBuffer"
            elif method.name.endswith("no_auth"):
                opcode = method.name.split("_")[1].upper()
                description = """put {0} instruction expecting a raw pointer
    without any authentication bits""".format(make_indefinite(opcode))
            else:
                types = set(["reg", "imm", "offset", "indirect", "short", "near", "ptr", "base", "index", "scale", "address", "label", "u8", "i32", "u32", "u64"])
                opcode = " ".join(filter(lambda token: token not in types, method.name.split("_")[1:])).upper()
                description = "put {0} instruction".format(make_indefinite(opcode))
                if method.name.endswith("_label"):
                    description += """
    referencing `labelId`, defined by a past or future `putLabel()`"""
        elif method.name == "skip":
            description = "skip `nBytes`"
        elif method.name == "peek_next_write_insn":
            description = "peek at the next {instruction_link} to be\n    written or skipped".format(**params)
        elif method.name == "peek_next_write_source":
            description = "peek at the address of the next instruction to be\n    written or skipped"
        elif method.name.startswith("skip_one"):
            description = "skip the instruction that would have been written next"
            if method.name.endswith("_no_label"):
                description += """,
    but without a label for internal use. This breaks relocation of branches to
    locations inside the relocated range, and is an optimization for use-cases
    where all branches are rewritten (e.g. Frida's Stalker)."""
        elif method.name.startswith("write_one"):
            description = "write the next buffered instruction"
            if method.name.endswith("_no_label"):
                description += """, but without a
    label for internal use. This breaks relocation of branches to locations
    inside the relocated range, and is an optimization for use-cases where all
    branches are rewritten (e.g. Frida's Stalker)."""
        elif method.name == "copy_one":
            description = """copy out the next buffered instruction without advancing the
    output cursor, allowing the same instruction to be written out multiple
    times"""
        elif method.name.startswith("write_all"):
            description = "write all buffered instructions"
        elif method.name == "can_branch_directly_between":
            description = """determine whether a direct branch is
    possible between the two given memory locations"""
        elif method.name == "commit_label":
            description = """commit the first pending reference to the given label,
    returning `true` on success. Returns `false` if the given label hasn't been
    defined yet, or there are no more pending references to it."
```