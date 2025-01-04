Response:
Let's break down the thought process for analyzing this C++ code snippet.

**1. Understanding the Goal:**

The request asks for an analysis of a specific C++ file (`gumv8instruction.cpp`) within the Frida framework. The key aspects to identify are its functionality, its relationship to reverse engineering, its connection to low-level concepts, any logical inferences it makes, potential user errors, and how a user would end up interacting with this code.

**2. Initial Scan and Keywords:**

My first step would be to quickly scan the code, looking for recognizable patterns and keywords. I see:

* `#include`: Standard C++ includes.
* `Copyright`, `Licence`:  Indicates the nature of the code.
* `#define`: Macros, potentially for configuration or convenience. `GUMJS_MODULE_NAME Instruction` is important.
* `using namespace v8;`:  Immediately tells me this code interacts with the V8 JavaScript engine.
* Function declarations with `GUMJS_DECLARE_FUNCTION`, `GUMJS_DECLARE_GETTER`: Suggests a binding layer between C++ and JavaScript.
* `cs_insn`, `capstone`:  These strongly point to the use of the Capstone disassembly library.
* Platform-specific `#if defined (HAVE_I386)`, `#elif defined (HAVE_ARM)`, etc.:  Indicates platform-dependent code, likely for handling instruction details of different architectures.
* `Local<...>`, `Global<...>`: V8-specific types for managing JavaScript objects within C++.
* `g_slice_new`, `g_slice_free`, `g_hash_table_new_full`:  GLib usage for memory management and data structures.
* Function names like `gumjs_instruction_parse`, `gumjs_instruction_get_address`, `gumjs_instruction_to_string`:  Suggest the operations this module performs.

**3. Deeper Dive into Functionality:**

Based on the keywords and function names, I can start to infer the core purpose:

* **Instruction Representation:** The code seems to be responsible for representing and manipulating individual machine code instructions. The `GumV8InstructionValue` structure likely holds the details of an instruction.
* **Disassembly:** The use of Capstone strongly suggests the primary function is disassembling raw bytes of code into a structured representation. The `gumjs_instruction_parse` function is a key indicator.
* **JavaScript Binding:** The `GUMJS_...` macros and the `v8::` namespace clearly indicate this C++ code is exposing instruction information to JavaScript. This is a core part of Frida's dynamic instrumentation capabilities.
* **Attribute Access:** The `gumjs_instruction_get_*` functions expose various properties of an instruction (address, size, mnemonic, operands, registers, groups) to JavaScript.
* **Platform Support:** The `#if defined` blocks highlight architecture-specific parsing of instruction operands.

**4. Connecting to Reverse Engineering:**

With the understanding of the functionality, the connection to reverse engineering becomes clear:

* **Dynamic Analysis:** Frida is a dynamic instrumentation tool, and this code is a crucial component for inspecting code as it executes.
* **Instruction Inspection:**  Reverse engineers need to understand the individual instructions being executed. This code provides a way to get detailed information about those instructions programmatically.
* **Hooking and Modification:** While this specific file doesn't *perform* hooking, it provides the foundation for understanding the code at a specific point, which is essential for setting hooks and potentially modifying execution.

**5. Identifying Low-Level Concepts:**

The code touches on several low-level concepts:

* **Machine Code:**  The fundamental input is raw bytes representing machine instructions.
* **Instruction Set Architectures (ISAs):** The platform-specific code deals with the details of x86, ARM, and ARM64 instruction formats.
* **Registers:** The code explicitly extracts information about accessed, read, and written registers.
* **Memory Operands:** It parses the components of memory operands (base, index, displacement, scale).
* **Disassembly:** The core function is converting raw bytes into human-readable assembly instructions.
* **Memory Management:**  The use of `gum_ensure_code_readable` suggests interactions with memory protection mechanisms.

**6. Logical Inferences (Hypothetical Input/Output):**

I can create a hypothetical scenario:

* **Input (JavaScript):** A JavaScript call to a Frida function (likely part of the `Instruction` module) with a memory address as input (e.g., `Instruction.parse(ptr("0x400000"))`).
* **Processing (C++):**
    * `gumjs_instruction_parse` is called.
    * The address is validated.
    * `cs_disasm` (from Capstone) is used to disassemble the bytes at that address.
    * A `GumV8InstructionValue` object is created, populated with the disassembled instruction data.
    * Platform-specific operand parsing functions are called (e.g., `gum_arm_parse_operands`).
* **Output (JavaScript):** A JavaScript object representing the instruction, with properties like `address`, `mnemonic`, `opStr`, and `operands`. The `operands` property would be an array of objects, each describing an operand (register, immediate, memory).

**7. Common User Errors:**

Thinking about how a user might interact with this API reveals potential errors:

* **Invalid Memory Address:** Providing an address that doesn't point to valid executable code would lead to an error from Capstone or within Frida's memory checks.
* **Incorrect Architecture:** If Frida is configured for the wrong architecture, the disassembly might be incorrect.
* **Accessing Invalid Properties:**  While the code tries to handle invalid instructions gracefully, attempting to access properties of an invalid instruction object could lead to errors.

**8. Tracing User Operations:**

To understand how a user reaches this code, I'd consider typical Frida workflows:

1. **Frida Scripting:** The user writes a JavaScript script using Frida's API.
2. **`Process.getModuleByName()`/`Module.base`/`Module.findExportByName()`:** The user identifies a target memory location (e.g., the start of a function).
3. **`Instruction.parse(address)`:** The user calls a Frida function (exposed through the JavaScript binding) that internally calls `gumjs_instruction_parse` in this C++ code.
4. **Accessing Instruction Properties:** The user then accesses properties like `instruction.mnemonic`, `instruction.operands`, etc., which call the corresponding `gumjs_instruction_get_*` functions in the C++ code.

**9. Iterative Refinement:**

Throughout this process, I would revisit the code, cross-referencing function calls and data structures to refine my understanding. For example, noticing the `SetWeak` calls and the `gum_v8_instruction_on_weak_notify` function would lead me to investigate Frida's object lifecycle management.

This systematic approach of scanning, identifying keywords, inferring functionality, connecting to the broader context, and considering user interactions helps in creating a comprehensive analysis of the provided code.
这个C++源代码文件 `gumv8instruction.cpp` 是 Frida 动态Instrumentation 工具中 `frida-gum` 组件的一部分，专门负责处理和表示机器指令的信息，并将其暴露给 JavaScript 环境（通过 V8 引擎）。它的主要功能是：

**1. 指令解析与表示:**

* **`gumjs_instruction_parse(args)`:**  这是将一个内存地址处的机器指令解析成一个 JavaScript 可访问的 `Instruction` 对象的入口点。
    * 它接收一个表示内存地址的参数。
    * 它使用 Capstone 反汇编引擎 (`cs_disasm`) 将该地址处的二进制代码反汇编成一条指令。
    * 它创建一个 `GumV8InstructionValue` 对象来存储指令的详细信息。
    * 它将这个 C++ 对象包装成一个 JavaScript 对象，并通过 V8 引擎返回给 JavaScript 代码。

* **`GumV8InstructionValue` 结构体:**  这个结构体存储了单条指令的各种属性，例如：
    * `insn`: 指向 Capstone 反汇编后的 `cs_insn` 结构体的指针，包含了指令的原始信息。
    * `owns_memory`:  指示 `insn` 指向的内存是否由该对象拥有，用于管理内存释放。
    * `target`:  指令所在的原始内存地址。
    * `module`: 指向所属的 `GumV8Instruction` 模块的指针。
    * `object`:  指向对应的 JavaScript 对象的 `Global` 指针，用于在 C++ 和 JavaScript 之间保持关联。

**2. 指令属性访问 (Getters):**

该文件定义了一系列 getter 函数，用于从 `GumV8InstructionValue` 对象中提取指令的各种属性，并将其转换为 JavaScript 可以访问的形式：

* **`gumjs_instruction_get_address`:** 获取指令的内存地址。
* **`gumjs_instruction_get_next`:**  计算下一条指令的内存地址。
* **`gumjs_instruction_get_size`:** 获取指令的字节大小。
* **`gumjs_instruction_get_mnemonic`:** 获取指令的助记符 (例如 "mov", "add", "jmp")。
* **`gumjs_instruction_get_op_str`:** 获取指令的操作数字符串 (例如 "rax, rbx", "[rsp+8]")。
* **`gumjs_instruction_get_operands`:**  获取指令操作数的详细信息，以 JavaScript 对象的数组形式返回。
* **`gumjs_instruction_get_regs_accessed`:** 获取指令访问的寄存器，包括读和写，以 JavaScript 对象的形式返回，包含 `read` 和 `written` 两个属性，每个属性都是一个寄存器名称的数组。
* **`gumjs_instruction_get_regs_read`:** 获取指令读取的寄存器，以 JavaScript 字符串数组返回。
* **`gumjs_instruction_get_regs_written`:** 获取指令写入的寄存器，以 JavaScript 字符串数组返回。
* **`gumjs_instruction_get_groups`:** 获取指令所属的组 (例如 "jump", "call")，以 JavaScript 字符串数组返回。

**3. 指令操作:**

* **`gumjs_instruction_to_string`:**  将指令格式化成一个可读的字符串 (例如 "mov rax, rbx")。

**与逆向方法的关联及举例说明:**

这个文件与逆向工程的核心方法紧密相关，即**代码分析**。通过解析和表示机器指令，它为逆向工程师提供了程序执行流程的底层视图。

**举例说明:**

假设在逆向一个程序时，你想知道地址 `0x7fffc0000800` 处的指令是什么。你可以使用 Frida 的 JavaScript API：

```javascript
const instruction = Instruction.parse(ptr('0x7fffc0000800'));
console.log(instruction.mnemonic); // 输出指令的助记符，例如 "mov"
console.log(instruction.opStr);  // 输出指令的操作数，例如 "rax, rbx"
console.log(instruction.operands); // 输出操作数的详细信息，例如：
                                  // [ { type: 'reg', value: 'rax', size: 8, access: 'rw' },
                                  //   { type: 'reg', value: 'rbx', size: 8, access: 'r' } ]
console.log(instruction.regsRead); // 输出读取的寄存器，例如 [ 'rbx' ]
console.log(instruction.regsWritten); // 输出写入的寄存器，例如 [ 'rax' ]
```

这个例子展示了如何使用 `Instruction.parse` 获取指令对象，并访问其属性来了解指令的具体操作。这对于理解程序的功能、查找漏洞、分析恶意代码等逆向任务至关重要。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层知识:**
    * **机器指令格式:** 代码需要理解不同架构 (x86, ARM, ARM64, MIPS) 的机器指令编码格式，以便正确地解析操作数、寄存器等信息。这体现在条件编译 `#if defined (HAVE_I386)` 等分支中，针对不同架构有不同的操作数解析逻辑。
    * **寄存器和内存寻址:** 代码需要知道不同架构下的通用寄存器名称和内存寻址模式，以便正确地解释指令的操作数。例如，解析内存操作数时，需要区分基址寄存器、索引寄存器、比例因子和偏移量。

* **Linux/Android 内核及框架知识:**
    * **内存地址空间:** `Instruction.parse` 接收的是内存地址，需要理解进程的地址空间布局，代码段、数据段、堆栈等。
    * **代码执行模型:**  Frida 的工作原理是注入到目标进程，并 hook 函数。理解代码在进程中的执行方式，以及指令指针 (IP/PC) 的移动，对于动态 instrumentation 非常重要。`gumjs_instruction_get_next` 就体现了这种理解。
    * **Thumb/ARM 模式 (ARM 架构):**  在 ARM 架构中，指令可以是 32 位的 ARM 指令或 16 位的 Thumb 指令。`gumjs_instruction_parse` 中根据目标地址的最低位来判断当前是 ARM 模式还是 Thumb 模式，并设置 Capstone 的模式选项。

**举例说明:**

在 ARM 架构中，`gumjs_instruction_parse` 中有以下代码片段：

```c++
#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (module->capstone, CS_OPT_MODE,
      (((GPOINTER_TO_SIZE (target) & 1) == 1) ? CS_MODE_THUMB : CS_MODE_ARM) |
      CS_MODE_V8 | GUM_DEFAULT_CS_ENDIAN);
#endif
```

这段代码展示了：

1. **地址对齐:** `address = GPOINTER_TO_SIZE (target) & ~1;`  Thumb 指令通常是 16 位对齐的，因此会清除最低位。
2. **模式判断:** `((GPOINTER_TO_SIZE (target) & 1) == 1) ? CS_MODE_THUMB : CS_MODE_ARM`  检查目标地址的最低位，如果是 1，则认为是 Thumb 模式，否则是 ARM 模式。
3. **Capstone 配置:** `cs_option` 函数用于配置 Capstone 反汇编引擎的模式，使其能够正确解析当前地址的指令。

**逻辑推理及假设输入与输出:**

* **假设输入:** 一个指向有效机器指令的内存地址，例如 `0x401000`，假设该地址处的二进制数据代表一条 x86 的 `mov eax, 0x10` 指令。
* **逻辑推理:**
    1. `gumjs_instruction_parse` 被调用，传入地址 `0x401000`。
    2. Capstone 被调用，对 `0x401000` 处的二进制数据进行反汇编。
    3. Capstone 解析出助记符为 "mov"，操作数字符串为 "eax, 0x10"。
    4. `gum_parse_operands` 函数会被调用，解析操作数。
    5. 对于 x86 架构，`gum_x86_parse_memory_operand_value` 等函数可能被调用来进一步解析内存操作数（如果存在）。
    6. 创建一个 `GumV8InstructionValue` 对象，存储解析出的信息。
* **输出 (通过 JavaScript 访问):**
    * `instruction.mnemonic`  将是字符串 "mov"。
    * `instruction.opStr` 将是字符串 "eax, 0x10"。
    * `instruction.operands` 将是一个包含两个对象的数组：
        * `{ type: 'reg', value: 'eax', size: 4, access: 'w' }`
        * `{ type: 'imm', value: 16, size: ?, access: 'r' }` ( `size` 的值取决于具体的实现和 Capstone 的信息)
    * `instruction.regsWritten` 将是包含字符串 "eax" 的数组。
    * `instruction.regsRead` 可能为空数组，因为这条指令只写寄存器。

**用户或编程常见的使用错误及举例说明:**

* **传入无效的内存地址:** 如果用户传入的地址没有映射到任何有效的代码页，或者指向的是数据而不是代码，Capstone 反汇编可能会失败，`gumjs_instruction_parse` 会抛出异常 "invalid instruction"。
    * **例子:**  `Instruction.parse(ptr('0xdeadbeef'))`，假设 `0xdeadbeef` 不是有效的代码地址。

* **在不支持的架构上使用:** 虽然代码支持多种架构，但如果在 Frida 没有正确配置或者目标进程的架构与 Frida 期望的不符，可能会导致解析错误。

* **尝试访问无效指令的属性:**  如果 `Instruction.parse` 因为某种原因返回了一个表示无效指令的对象（虽然代码中做了检查），尝试访问其属性可能会导致错误。
    * **例子:**
    ```javascript
    let instruction = Instruction.parse(ptr('0xinvalid_address'));
    if (instruction) { // 虽然这里做了判断，但如果内部状态错误...
        console.log(instruction.mnemonic); // 可能导致错误
    }
    ```

* **假设所有指令都具有所有属性:** 并非所有指令都有操作数、读写寄存器等。用户应该根据指令的具体类型来访问相应的属性。例如，对于一个简单的 `ret` 指令，其 `operands` 数组可能为空。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:** 用户编写一个 JavaScript 脚本，使用 Frida 的 API 来进行动态 instrumentation。
2. **获取代码地址:**  脚本可能需要获取目标进程中某个函数的地址，例如使用 `Module.findExportByName()` 或直接硬编码地址。
3. **调用 `Instruction.parse()`:**  脚本调用 `Instruction.parse(address)` 函数，将获取到的代码地址作为参数传递进去。
4. **`gumjs_instruction_parse()` 被调用:**  Frida 的 JavaScript 绑定层将 JavaScript 调用转换为对 C++ 函数 `gumjs_instruction_parse()` 的调用。
5. **参数解析和校验:** `gumjs_instruction_parse()` 函数会解析传入的参数（内存地址）。
6. **调用 Capstone 反汇编:**  `gumjs_instruction_parse()` 内部会调用 Capstone 库的 `cs_disasm()` 函数，对指定地址的内存进行反汇编。
7. **创建 `GumV8InstructionValue` 对象:** 反汇编成功后，会创建一个 `GumV8InstructionValue` 对象来存储指令信息。
8. **解析指令细节:**  根据目标架构，会调用相应的函数（例如 `gum_x86_parse_operands`, `gum_arm_parse_operands` 等）来解析指令的操作数、寄存器等详细信息。
9. **创建 JavaScript 对象并返回:**  `GumV8InstructionValue` 对象会被包装成一个 V8 的 JavaScript 对象，并返回给 JavaScript 脚本。
10. **访问指令属性:**  JavaScript 脚本可以访问返回的指令对象的属性（例如 `mnemonic`, `opStr`, `operands`），这些属性的访问会调用对应的 getter 函数（例如 `gumjs_instruction_get_mnemonic`）。

**作为调试线索:** 如果在 Frida 脚本中调用 `Instruction.parse()` 遇到问题，例如抛出异常或者返回的指令信息不正确，可以按照以下步骤进行调试：

1. **检查传入 `Instruction.parse()` 的地址是否正确，并且指向有效的代码。** 可以使用 Frida 的内存操作 API 或目标进程的调试工具来验证。
2. **检查 Frida 是否正确连接到目标进程，并且目标进程的架构与 Frida 期望的架构一致。**
3. **如果反汇编失败，可以尝试使用其他反汇编工具（例如 `objdump`, `ida pro`）来确认该地址处的指令是否确实是有效的。**
4. **在 `gumjs_instruction_parse()` 函数中设置断点，查看 Capstone 的反汇编结果，以及 `GumV8InstructionValue` 对象的内容。**
5. **检查针对特定架构的操作数解析函数（例如 `gum_x86_parse_memory_operand_value`）是否正确处理了目标指令的操作数格式。**
6. **查看 Frida 的日志输出，可能会有与反汇编或 V8 引擎相关的错误信息。**

总而言之，`gumv8instruction.cpp` 文件是 Frida 中用于低级别代码分析的关键组件，它利用 Capstone 反汇编引擎将二进制指令转换为结构化的信息，并通过 V8 引擎暴露给 JavaScript，为 Frida 脚本提供了强大的代码检查和理解能力，是实现动态 instrumentation 的基础。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8instruction.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2014-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 EvilWind <evilwind@protonmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8instruction.h"

#include "gumv8macros.h"

#include <string.h>

#define GUMJS_MODULE_NAME Instruction

#define GUM_INSTRUCTION_FOOTPRINT_ESTIMATE 256

using namespace v8;

GUMJS_DECLARE_FUNCTION (gumjs_instruction_parse)

static GumV8InstructionValue * gum_v8_instruction_alloc (
    GumV8Instruction * module);
static void gum_v8_instruction_dispose (GumV8InstructionValue * self);
static void gum_v8_instruction_free (GumV8InstructionValue * self);
GUMJS_DECLARE_GETTER (gumjs_instruction_get_address)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_next)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_size)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_mnemonic)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_op_str)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_operands)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_regs_accessed)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_regs_read)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_regs_written)
GUMJS_DECLARE_GETTER (gumjs_instruction_get_groups)
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_string)
static void gum_v8_instruction_on_weak_notify (
    const WeakCallbackInfo<GumV8InstructionValue> & info);

static Local<Array> gum_parse_operands (const cs_insn * insn,
    GumV8Instruction * module);

#if defined (HAVE_I386)
static Local<Object> gum_x86_parse_memory_operand_value (const x86_op_mem * mem,
    GumV8Instruction * module);
#elif defined (HAVE_ARM)
static Local<Object> gum_arm_parse_memory_operand_value (const arm_op_mem * mem,
    GumV8Instruction * module);
static Local<Object> gum_arm_parse_shift_details (const cs_arm_op * op,
    GumV8Instruction * module);
static const gchar * gum_arm_shifter_to_string (arm_shifter type);
#elif defined (HAVE_ARM64)
static Local<Object> gum_arm64_parse_memory_operand_value (
    const arm64_op_mem * mem, GumV8Instruction * module);
static Local<Object> gum_arm64_parse_shift_details (const cs_arm64_op * op,
    GumV8Instruction * module);
static const gchar * gum_arm64_shifter_to_string (arm64_shifter type);
static const gchar * gum_arm64_extender_to_string (arm64_extender ext);
static const gchar * gum_arm64_vas_to_string (arm64_vas vas);
#elif defined (HAVE_MIPS)
static Local<Object> gum_mips_parse_memory_operand_value (
    const mips_op_mem * mem, GumV8Instruction * module);
#endif

static Local<Array> gum_parse_regs (const uint16_t * regs, uint8_t count,
    GumV8Instruction * module);

static Local<Array> gum_parse_groups (const uint8_t * groups, uint8_t count,
    GumV8Instruction * module);

static const gchar * gum_access_type_to_string (uint8_t access_type);

static const GumV8Function gumjs_instruction_module_functions[] =
{
  { "_parse", gumjs_instruction_parse },

  { NULL, NULL }
};

static const GumV8Property gumjs_instruction_values[] =
{
  { "address", gumjs_instruction_get_address, NULL },
  { "next", gumjs_instruction_get_next, NULL },
  { "size", gumjs_instruction_get_size, NULL },
  { "mnemonic", gumjs_instruction_get_mnemonic, NULL },
  { "opStr", gumjs_instruction_get_op_str, NULL },
  { "operands", gumjs_instruction_get_operands, NULL },
  { "regsAccessed", gumjs_instruction_get_regs_accessed, NULL },
  { "regsRead", gumjs_instruction_get_regs_read, NULL },
  { "regsWritten", gumjs_instruction_get_regs_written, NULL },
  { "groups", gumjs_instruction_get_groups, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_instruction_functions[] =
{
  { "toString", gumjs_instruction_to_string },

  { NULL, NULL }
};

void
_gum_v8_instruction_init (GumV8Instruction * self,
                          GumV8Core * core,
                          Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  gum_cs_arch_register_native ();
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &self->capstone);
  cs_option (self->capstone, CS_OPT_DETAIL, CS_OPT_ON);

  auto module = External::New (isolate, self);

  auto klass = _gum_v8_create_class ("Instruction", nullptr, scope, module,
      isolate);
  _gum_v8_class_add_static (klass, gumjs_instruction_module_functions, module,
      isolate);
  _gum_v8_class_add (klass, gumjs_instruction_values, module, isolate);
  _gum_v8_class_add (klass, gumjs_instruction_functions, module, isolate);
  self->klass = new Global<FunctionTemplate> (isolate, klass);
}

void
_gum_v8_instruction_realize (GumV8Instruction * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  self->instructions = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_instruction_free);

  auto klass = Local<FunctionTemplate>::New (isolate, *self->klass);
  auto object = klass->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->template_object = new Global<Object> (isolate, object);
}

void
_gum_v8_instruction_dispose (GumV8Instruction * self)
{
  g_hash_table_unref (self->instructions);
  self->instructions = NULL;

  delete self->template_object;
  self->template_object = nullptr;

  delete self->klass;
  self->klass = nullptr;
}

void
_gum_v8_instruction_finalize (GumV8Instruction * self)
{
  cs_close (&self->capstone);
}

Local<Object>
_gum_v8_instruction_new (csh capstone,
                         const cs_insn * insn,
                         gboolean is_owned,
                         gconstpointer target,
                         GumV8Instruction * module)
{
  auto value = _gum_v8_instruction_new_persistent (module);

  if (is_owned)
  {
    value->insn = insn;
  }
  else
  {
    g_assert (capstone != 0);

    cs_insn * insn_copy = cs_malloc (capstone);
    cs_detail * detail_copy = insn_copy->detail;
    memcpy (insn_copy, insn, sizeof (cs_insn));
    insn_copy->detail = detail_copy;
    if (detail_copy != NULL)
      memcpy (detail_copy, insn->detail, sizeof (cs_detail));

    value->insn = insn_copy;
  }
  value->owns_memory = TRUE;
  value->target = target;

  value->object->SetWeak (value, gum_v8_instruction_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (module->instructions, value);

  return Local<Object>::New (module->core->isolate, *value->object);
}

GumV8InstructionValue *
_gum_v8_instruction_new_persistent (GumV8Instruction * module)
{
  auto isolate = module->core->isolate;

  auto value = gum_v8_instruction_alloc (module);

  auto template_object = Local<Object>::New (isolate, *module->template_object);
  auto object = template_object->Clone ();
  value->object = new Global<Object> (isolate, object);
  object->SetAlignedPointerInInternalField (0, value);

  return value;
}

void
_gum_v8_instruction_release_persistent (GumV8InstructionValue * value)
{
  gum_v8_instruction_dispose (value);

  value->object->SetWeak (value, gum_v8_instruction_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (value->module->instructions, value);
}

static GumV8InstructionValue *
gum_v8_instruction_alloc (GumV8Instruction * module)
{
  auto value = g_slice_new (GumV8InstructionValue);
  value->object = nullptr;
  value->insn = NULL;
  value->owns_memory = FALSE;
  value->target = NULL;
  value->module = module;

  module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      GUM_INSTRUCTION_FOOTPRINT_ESTIMATE);

  return value;
}

static void
gum_v8_instruction_dispose (GumV8InstructionValue * self)
{
  if (self->owns_memory && self->insn != NULL)
  {
    cs_free ((cs_insn *) self->insn, 1);
    self->insn = NULL;
  }
}

static void
gum_v8_instruction_free (GumV8InstructionValue * self)
{
  gum_v8_instruction_dispose (self);

  self->module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -GUM_INSTRUCTION_FOOTPRINT_ESTIMATE);

  delete self->object;

  g_slice_free (GumV8InstructionValue, self);
}

static gboolean
gum_v8_instruction_check_valid (GumV8InstructionValue * self,
                                Isolate * isolate)
{
  if (self->insn == NULL)
  {
    _gum_v8_throw (isolate, "invalid operation");
    return FALSE;
  }

  return TRUE;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_parse)
{
  gpointer target;
  if (!_gum_v8_args_parse (args, "p", &target))
    return;

  target = gum_strip_code_pointer (target);

  uint64_t address;
#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (module->capstone, CS_OPT_MODE,
      (((GPOINTER_TO_SIZE (target) & 1) == 1) ? CS_MODE_THUMB : CS_MODE_ARM) |
      CS_MODE_V8 | GUM_DEFAULT_CS_ENDIAN);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  const gsize max_instruction_size = 16;

  gum_ensure_code_readable (GSIZE_TO_POINTER (address), max_instruction_size);

  cs_insn * insn;
  if (cs_disasm (module->capstone, (uint8_t *) GSIZE_TO_POINTER (address),
      max_instruction_size, address, 1, &insn) == 0)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid instruction");
    return;
  }

  info.GetReturnValue ().Set (
      _gum_v8_instruction_new (module->capstone, insn, TRUE, target, module));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_address, GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (self->insn->address), core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_next, GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  auto next = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (self->target) + self->insn->size);

  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (next, core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_size, GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (self->insn->size);
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_mnemonic,
    GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (
      _gum_v8_string_new_ascii (isolate, self->insn->mnemonic));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_op_str, GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (
      _gum_v8_string_new_ascii (isolate, self->insn->op_str));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_operands,
                           GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (gum_parse_operands (self->insn, module));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_regs_accessed,
                           GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  cs_regs regs_read, regs_write;
  uint8_t regs_read_count, regs_write_count;

  if (cs_regs_access (module->capstone, self->insn,
        regs_read, &regs_read_count,
        regs_write, &regs_write_count) != 0)
  {
    _gum_v8_throw (isolate, "not yet supported on this architecture");
    return;
  }

  auto result = Object::New (core->isolate);

  _gum_v8_object_set (result, "read",
      gum_parse_regs (regs_read, regs_read_count, module), core);

  _gum_v8_object_set (result, "written",
      gum_parse_regs (regs_write, regs_write_count, module), core);

  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_regs_read,
                           GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  auto detail = self->insn->detail;

  info.GetReturnValue ().Set (gum_parse_regs (detail->regs_read,
      detail->regs_read_count, module));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_regs_written,
                           GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  auto detail = self->insn->detail;

  info.GetReturnValue ().Set (gum_parse_regs (detail->regs_write,
      detail->regs_write_count, module));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_instruction_get_groups,
                           GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  auto detail = self->insn->detail;

  info.GetReturnValue ().Set (gum_parse_groups (detail->groups,
      detail->groups_count, module));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_instruction_to_string, GumV8InstructionValue)
{
  if (!gum_v8_instruction_check_valid (self, isolate))
    return;

  const cs_insn * insn = self->insn;

  if (*insn->op_str != '\0')
  {
    auto str = g_strconcat (insn->mnemonic, " ", insn->op_str, NULL);
    info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
    g_free (str);
  }
  else
  {
    info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate,
        insn->mnemonic));
  }
}

static void
gum_v8_instruction_on_weak_notify (
    const WeakCallbackInfo<GumV8InstructionValue> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->instructions, self);
}

#if defined (HAVE_I386)

static Local<Array>
gum_parse_operands (const cs_insn * insn,
                    GumV8Instruction * module)
{
  auto core = module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();
  auto capstone = module->capstone;
  auto x86 = &insn->detail->x86;

  uint8_t op_count = x86->op_count;

  auto elements = Array::New (isolate, op_count);

  for (uint8_t op_index = 0; op_index != op_count; op_index++)
  {
    auto op = &x86->operands[op_index];

    auto element = Object::New (isolate);

    auto type_key = "type";
    auto value_key = "value";

    switch (op->type)
    {
      case X86_OP_REG:
        _gum_v8_object_set_ascii (element, type_key, "reg", core);
        _gum_v8_object_set_ascii (element, value_key,
            cs_reg_name (capstone, op->reg), core);
        break;
      case X86_OP_IMM:
        _gum_v8_object_set_ascii (element, type_key, "imm", core);
        _gum_v8_object_set (element, value_key,
            _gum_v8_int64_new (op->imm, core), core);
        break;
      case X86_OP_MEM:
        _gum_v8_object_set_ascii (element, type_key, "mem", core);
        _gum_v8_object_set (element, value_key,
            gum_x86_parse_memory_operand_value (&op->mem, module), core);
        break;
      default:
        g_assert_not_reached ();
    }

    _gum_v8_object_set_uint (element, "size", op->size, core);

    _gum_v8_object_set_ascii (element, "access",
        gum_access_type_to_string (op->access), core);

    elements->Set (context, op_index, element).Check ();
  }

  return elements;
}

static Local<Object>
gum_x86_parse_memory_operand_value (const x86_op_mem * mem,
                                    GumV8Instruction * module)
{
  auto core = module->core;
  auto capstone = module->capstone;

  auto result = Object::New (core->isolate);

  if (mem->segment != X86_REG_INVALID)
  {
    _gum_v8_object_set_ascii (result, "segment",
        cs_reg_name (capstone, mem->segment), core);
  }

  if (mem->base != X86_REG_INVALID)
  {
    _gum_v8_object_set_ascii (result, "base",
        cs_reg_name (capstone, mem->base), core);
  }

  if (mem->index != X86_REG_INVALID)
  {
    _gum_v8_object_set_ascii (result, "index",
        cs_reg_name (capstone, mem->index), core);
  }

  _gum_v8_object_set_int (result, "scale", mem->scale, core);

  _gum_v8_object_set_int (result, "disp", mem->disp, core);

  return result;
}

#elif defined (HAVE_ARM)

static Local<Array>
gum_parse_operands (const cs_insn * insn,
                    GumV8Instruction * module)
{
  auto core = module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();
  auto capstone = module->capstone;
  auto arm = &insn->detail->arm;

  uint8_t op_count = arm->op_count;

  auto elements = Array::New (isolate, op_count);

  for (uint8_t op_index = 0; op_index != op_count; op_index++)
  {
    auto op = &arm->operands[op_index];

    auto element = Object::New (isolate);

    auto type_key = "type";
    auto value_key = "value";

    switch (op->type)
    {
      case ARM_OP_REG:
        _gum_v8_object_set_ascii (element, type_key, "reg", core);
        _gum_v8_object_set_ascii (element, value_key,
            cs_reg_name (capstone, op->reg), core);
        break;
      case ARM_OP_IMM:
        _gum_v8_object_set_ascii (element, type_key, "imm", core);
        _gum_v8_object_set_int (element, value_key, op->imm, core);
        break;
      case ARM_OP_MEM:
        _gum_v8_object_set_ascii (element, type_key, "mem", core);
        _gum_v8_object_set (element, value_key,
            gum_arm_parse_memory_operand_value (&op->mem, module), core);
        break;
      case ARM_OP_FP:
        _gum_v8_object_set_ascii (element, type_key, "fp", core);
        _gum_v8_object_set (element, value_key, Number::New (isolate, op->fp),
            core);
        break;
      case ARM_OP_CIMM:
        _gum_v8_object_set_ascii (element, type_key, "cimm", core);
        _gum_v8_object_set_int (element, value_key, op->imm, core);
        break;
      case ARM_OP_PIMM:
        _gum_v8_object_set_ascii (element, type_key, "pimm", core);
        _gum_v8_object_set_int (element, value_key, op->imm, core);
        break;
      case ARM_OP_SETEND:
        _gum_v8_object_set_ascii (element, type_key, "setend", core);
        _gum_v8_object_set_ascii (element, value_key,
            (op->setend == ARM_SETEND_BE) ? "be" : "le", core);
        break;
      case ARM_OP_SYSREG:
        _gum_v8_object_set_ascii (element, type_key, "sysreg", core);
        _gum_v8_object_set_ascii (element, value_key,
            cs_reg_name (capstone, op->reg), core);
        break;
      default:
        g_assert_not_reached ();
    }

    if (op->shift.type != ARM_SFT_INVALID)
    {
      _gum_v8_object_set (element, "shift",
          gum_arm_parse_shift_details (op, module), core);
    }

    if (op->vector_index != -1)
    {
      _gum_v8_object_set_uint (element, "vectorIndex", op->vector_index, core);
    }

    _gum_v8_object_set (element, "subtracted",
        Boolean::New (isolate, op->subtracted), core);

    _gum_v8_object_set_ascii (element, "access",
        gum_access_type_to_string (op->access), core);

    elements->Set (context, op_index, element).Check ();
  }

  return elements;
}

static Local<Object>
gum_arm_parse_memory_operand_value (const arm_op_mem * mem,
                                    GumV8Instruction * module)
{
  auto core = module->core;
  auto capstone = module->capstone;

  auto result = Object::New (core->isolate);

  if (mem->base != ARM_REG_INVALID)
  {
    _gum_v8_object_set_ascii (result, "base",
        cs_reg_name (capstone, mem->base), core);
  }

  if (mem->index != ARM_REG_INVALID)
  {
    _gum_v8_object_set_ascii (result, "index",
        cs_reg_name (capstone, mem->index), core);
  }

  _gum_v8_object_set_int (result, "scale", mem->scale, core);

  _gum_v8_object_set_int (result, "disp", mem->disp, core);

  return result;
}

static Local<Object>
gum_arm_parse_shift_details (const cs_arm_op * op,
                             GumV8Instruction * module)
{
  auto core = module->core;

  auto result = Object::New (core->isolate);

  _gum_v8_object_set_ascii (result, "type",
      gum_arm_shifter_to_string (op->shift.type), core);

  _gum_v8_object_set_uint (result, "value", op->shift.value, core);

  return result;
}

static const gchar *
gum_arm_shifter_to_string (arm_shifter type)
{
  switch (type)
  {
    case ARM_SFT_ASR: return "asr";
    case ARM_SFT_LSL: return "lsl";
    case ARM_SFT_LSR: return "lsr";
    case ARM_SFT_ROR: return "ror";
    case ARM_SFT_RRX: return "rrx";
    case ARM_SFT_ASR_REG: return "asr-reg";
    case ARM_SFT_LSL_REG: return "lsl-reg";
    case ARM_SFT_LSR_REG: return "lsr-reg";
    case ARM_SFT_ROR_REG: return "ror-reg";
    case ARM_SFT_RRX_REG: return "rrx-reg";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

#elif defined (HAVE_ARM64)

static Local<Array>
gum_parse_operands (const cs_insn * insn,
                    GumV8Instruction * module)
{
  auto core = module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();
  auto capstone = module->capstone;
  auto arm64 = &insn->detail->arm64;

  uint8_t op_count = arm64->op_count;

  auto elements = Array::New (isolate, op_count);

  for (uint8_t op_index = 0; op_index != op_count; op_index++)
  {
    const cs_arm64_op * op = &arm64->operands[op_index];

    auto element = Object::New (isolate);

    auto type_key = "type";
    auto value_key = "value";

    switch (op->type)
    {
      case ARM64_OP_REG:
        _gum_v8_object_set_ascii (element, type_key, "reg", core);
        _gum_v8_object_set_ascii (element, value_key,
            cs_reg_name (capstone, op->reg), core);
        break;
      case ARM64_OP_IMM:
        _gum_v8_object_set_ascii (element, type_key, "imm", core);
        _gum_v8_object_set (element, value_key,
            _gum_v8_int64_new (op->imm, core), core);
        break;
      case ARM64_OP_MEM:
        _gum_v8_object_set_ascii (element, type_key, "mem", core);
        _gum_v8_object_set (element, value_key,
            gum_arm64_parse_memory_operand_value (&op->mem, module), core);
        break;
      case ARM64_OP_FP:
        _gum_v8_object_set_ascii (element, type_key, "fp", core);
        _gum_v8_object_set (element, value_key, Number::New (isolate, op->fp),
            core);
        break;
      case ARM64_OP_CIMM:
        _gum_v8_object_set_ascii (element, type_key, "cimm", core);
        _gum_v8_object_set (element, value_key,
            _gum_v8_int64_new (op->imm, core), core);
        break;
      case ARM64_OP_REG_MRS:
        _gum_v8_object_set_ascii (element, type_key, "reg-mrs", core);
        _gum_v8_object_set_ascii (element, value_key,
            cs_reg_name (capstone, op->reg), core);
        break;
      case ARM64_OP_REG_MSR:
        _gum_v8_object_set_ascii (element, type_key, "reg-msr", core);
        _gum_v8_object_set_ascii (element, value_key,
            cs_reg_name (capstone, op->reg), core);
        break;
      case ARM64_OP_PSTATE:
        _gum_v8_object_set_ascii (element, type_key, "pstate", core);
        _gum_v8_object_set_uint (element, value_key, op->pstate, core);
        break;
      case ARM64_OP_SYS:
        _gum_v8_object_set_ascii (element, type_key, "sys", core);
        _gum_v8_object_set_uint (element, value_key, op->sys, core);
        break;
      case ARM64_OP_PREFETCH:
        _gum_v8_object_set_ascii (element, type_key, "prefetch", core);
        _gum_v8_object_set_uint (element, value_key, op->prefetch, core);
        break;
      case ARM64_OP_BARRIER:
        _gum_v8_object_set_ascii (element, type_key, "barrier", core);
        _gum_v8_object_set_uint (element, value_key, op->barrier, core);
        break;
      default:
        g_assert_not_reached ();
    }

    if (op->shift.type != ARM64_SFT_INVALID)
    {
      _gum_v8_object_set (element, "shift",
          gum_arm64_parse_shift_details (op, module), core);
    }

    if (op->ext != ARM64_EXT_INVALID)
    {
      _gum_v8_object_set_ascii (element, "ext",
          gum_arm64_extender_to_string (op->ext), core);
    }

    if (op->vas != ARM64_VAS_INVALID)
    {
      _gum_v8_object_set_ascii (element, "vas",
          gum_arm64_vas_to_string (op->vas), core);
    }

    if (op->vector_index != -1)
    {
      _gum_v8_object_set_uint (element, "vectorIndex", op->vector_index, core);
    }

    _gum_v8_object_set_ascii (element, "access",
        gum_access_type_to_string (op->access), core);

    elements->Set (context, op_index, element).Check ();
  }

  return elements;
}

static Local<Object>
gum_arm64_parse_memory_operand_value (const arm64_op_mem * mem,
                                      GumV8Instruction * module)
{
  auto core = module->core;
  auto capstone = module->capstone;

  auto result = Object::New (core->isolate);

  if (mem->base != ARM64_REG_INVALID)
  {
    _gum_v8_object_set_ascii (result, "base",
        cs_reg_name (capstone, mem->base), core);
  }

  if (mem->index != ARM64_REG_INVALID)
  {
    _gum_v8_object_set_ascii (result, "index",
        cs_reg_name (capstone, mem->index), core);
  }

  _gum_v8_object_set_int (result, "disp", mem->disp, core);

  return result;
}

static Local<Object>
gum_arm64_parse_shift_details (const cs_arm64_op * op,
                               GumV8Instruction * module)
{
  auto core = module->core;

  auto result = Object::New (core->isolate);

  _gum_v8_object_set_ascii (result, "type",
      gum_arm64_shifter_to_string (op->shift.type), core);

  _gum_v8_object_set_uint (result, "value", op->shift.value, core);

  return result;
}

static const gchar *
gum_arm64_shifter_to_string (arm64_shifter type)
{
  switch (type)
  {
    case ARM64_SFT_LSL: return "lsl";
    case ARM64_SFT_MSL: return "msl";
    case ARM64_SFT_LSR: return "lsr";
    case ARM64_SFT_ASR: return "asr";
    case ARM64_SFT_ROR: return "ror";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

static const gchar *
gum_arm64_extender_to_string (arm64_extender ext)
{
  switch (ext)
  {
    case ARM64_EXT_UXTB: return "uxtb";
    case ARM64_EXT_UXTH: return "uxth";
    case ARM64_EXT_UXTW: return "uxtw";
    case ARM64_EXT_UXTX: return "uxtx";
    case ARM64_EXT_SXTB: return "sxtb";
    case ARM64_EXT_SXTH: return "sxth";
    case ARM64_EXT_SXTW: return "sxtw";
    case ARM64_EXT_SXTX: return "sxtx";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

static const gchar *
gum_arm64_vas_to_string (arm64_vas vas)
{
  switch (vas)
  {
    case ARM64_VAS_8B:  return "8b";
    case ARM64_VAS_16B: return "16b";
    case ARM64_VAS_4H:  return "4h";
    case ARM64_VAS_8H:  return "8h";
    case ARM64_VAS_2S:  return "2s";
    case ARM64_VAS_4S:  return "4s";
    case ARM64_VAS_1D:  return "1d";
    case ARM64_VAS_2D:  return "2d";
    case ARM64_VAS_1Q:  return "1q";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

#elif defined (HAVE_MIPS)

static Local<Array>
gum_parse_operands (const cs_insn * insn,
                    GumV8Instruction * module)
{
  auto core = module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();
  auto capstone = module->capstone;
  auto mips = &insn->detail->mips;

  uint8_t op_count = mips->op_count;

  auto elements = Array::New (isolate, op_count);

  for (uint8_t op_index = 0; op_index != op_count; op_index++)
  {
    auto op = &mips->operands[op_index];

    auto element = Object::New (isolate);

    auto type_key = "type";
    auto value_key = "value";

    switch (op->type)
    {
      case MIPS_OP_REG:
        _gum_v8_object_set_ascii (element, type_key, "reg", core);
        _gum_v8_object_set_ascii (element, value_key,
            cs_reg_name (capstone, op->reg), core);
        break;
      case MIPS_OP_IMM:
        _gum_v8_object_set_ascii (element, type_key, "imm", core);
        _gum_v8_object_set_int (element, value_key, op->imm, core);
        break;
      case MIPS_OP_MEM:
        _gum_v8_object_set_ascii (element, type_key, "mem", core);
        _gum_v8_object_set (element, value_key,
            gum_mips_parse_memory_operand_value (&op->mem, module), core);
        break;
      default:
        g_assert_not_reached ();
    }

    elements->Set (context, op_index, element).Check ();
  }

  return elements;
}

static Local<Object>
gum_mips_parse_memory_operand_value (const mips_op_mem * mem,
                                     GumV8Instruction * module)
{
  auto core = module->core;
  auto capstone = module->capstone;

  auto result = Object::New (core->isolate);

  if (mem->base != MIPS_REG_INVALID)
  {
    _gum_v8_object_set_ascii (result, "base",
        cs_reg_name (capstone, mem->base), core);
  }

  _gum_v8_object_set_int (result, "disp", mem->disp, core);

  return result;
}

#endif

static Local<Array>
gum_parse_regs (const uint16_t * regs,
                uint8_t count,
                GumV8Instruction * module)
{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();
  auto capstone = module->capstone;

  auto elements = Array::New (isolate, count);

  for (uint8_t reg_index = 0; reg_index != count; reg_index++)
  {
    auto name = cs_reg_name (capstone, regs[reg_index]);

    elements->Set (context, reg_index,
        _gum_v8_string_new_ascii (isolate, name)).Check ();
  }

  return elements;
}

static Local<Array>
gum_parse_groups (const uint8_t * groups,
                  uint8_t count,
                  GumV8Instruction * module)
{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();
  auto capstone = module->capstone;

  auto elements = Array::New (isolate, count);

  for (uint8_t group_index = 0; group_index != count; group_index++)
  {
    auto name = cs_group_name (capstone, groups[group_index]);

    elements->Set (context, group_index,
        _gum_v8_string_new_ascii (isolate, name)).Check ();
  }

  return elements;
}

static const gchar *
gum_access_type_to_string (uint8_t access_type)
{
  switch (access_type)
  {
    case CS_AC_INVALID:            return "";
    case CS_AC_READ:               return "r";
    case CS_AC_WRITE:              return "w";
    case CS_AC_READ | CS_AC_WRITE: return "rw";
    default:
      g_assert_not_reached ();
  }

  return NULL;
}

"""

```