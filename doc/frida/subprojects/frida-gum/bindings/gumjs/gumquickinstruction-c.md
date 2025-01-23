Response:
Let's break down the thought process to analyze the C code for `gumquickinstruction.c`.

**1. Understanding the Goal:**

The core request is to understand the functionality of this C file within the Frida context. Specifically, we need to identify:

* **Core Functionality:** What does this code *do*?
* **Relationship to Reversing:** How does it help in reverse engineering?
* **Low-Level Concepts:** What Linux/Android/binary concepts are involved?
* **Logical Reasoning:** Are there any logical assumptions or transformations?
* **Common User Errors:** How might a programmer misuse this?
* **Debugging Context:** How does a user arrive at this code during debugging?

**2. Initial Code Scan and High-Level Interpretation:**

The file name `gumquickinstruction.c` and the presence of `gumjs` prefixes immediately suggest this code bridges Frida's core (likely written in C/C++) with JavaScript. The "instruction" part indicates it deals with machine code instructions.

Scanning the `#include` statements confirms this:

* `gumquickinstruction.h`:  Likely defines the data structures and function prototypes for this module.
* `gumquickmacros.h`:  Probably contains helpful macros used throughout the Gum library.
* `<string.h>`: Standard C string manipulation.

The `GUMJS_DECLARE_*` macros strongly suggest this code exposes functionality to JavaScript. These likely define functions that can be called from the Frida JavaScript API.

**3. Deeper Dive into Key Sections:**

* **Function Declarations (`GUMJS_DECLARE_FUNCTION`, `GUMJS_DECLARE_GETTER`, etc.):** These are the entry points from the JavaScript side. We can list these out to understand the available operations:
    * `gumjs_instruction_parse`:  The crucial function for analyzing instructions.
    * `gumjs_instruction_construct`, `gumjs_instruction_finalize`:  Lifecycle management of the JavaScript `Instruction` object.
    * `gumjs_instruction_get_address`, `get_next`, `get_size`, etc.:  Getters for instruction properties.
    * `gumjs_instruction_to_string`, `gumjs_instruction_to_json`:  String and JSON representations.

* **Static Functions (`gum_parse_operands`, `gum_x86_parse_memory_operand_value`, etc.):** These are helper functions for breaking down the instruction details. The architecture-specific prefixes (`gum_x86_`, `gum_arm_`, `gum_arm64_`, `gum_mips_`) are a big clue that this code handles instruction parsing for different CPU architectures.

* **Data Structures (`gumjs_instruction_def`, `gumjs_instruction_module_entries`, `gumjs_instruction_entries`):** These are used to define the JavaScript class and its methods/properties.

* **Initialization (`_gum_quick_instruction_init`):** This function sets up the Capstone disassembler and registers the JavaScript class.

* **The `_gum_quick_instruction_new` and `_gum_quick_instruction_get` Functions:** These manage the creation and retrieval of the C-side `GumQuickInstructionValue` object, which holds the disassembled instruction data.

* **Architecture-Specific Operand Parsing:** The `gum_parse_operands` function and its architecture-specific helpers are responsible for dissecting the operands of an instruction (registers, immediate values, memory addresses, etc.).

**4. Connecting to Reverse Engineering:**

The ability to parse and inspect individual instructions is fundamental to reverse engineering. The provided functions directly support this:

* **Disassembly:**  `gumjs_instruction_parse` takes a memory address and returns an `Instruction` object, effectively disassembling the code.
* **Instruction Details:** The getters allow access to properties like `mnemonic`, `opStr`, `operands`, `regsRead`, `regsWritten`, providing detailed information about the instruction.
* **Dynamic Analysis:** Frida's ability to inject and execute JavaScript means this instruction parsing can happen *during* program execution, allowing for dynamic analysis.

**5. Identifying Low-Level Concepts:**

* **Machine Code:** The core subject of this code.
* **Instruction Set Architecture (ISA):**  The architecture-specific parsing highlights the differences between ISAs (x86, ARM, ARM64, MIPS).
* **Registers:**  The code identifies accessed, read, and written registers.
* **Memory Addressing:** The parsing of memory operands involves understanding base registers, index registers, scales, and displacements.
* **Disassembler (Capstone):**  The code explicitly uses the Capstone library for disassembling machine code.
* **Linux/Android Memory Management:**  `gum_ensure_code_readable` suggests an awareness of memory protection and the need to ensure the target memory is accessible.
* **Calling Conventions (implicitly):** Understanding register usage is crucial for understanding function calls.

**6. Logical Reasoning and Assumptions:**

* **Input:** A memory address where an instruction is located.
* **Output:** An `Instruction` object in JavaScript, containing a structured representation of the disassembled instruction.
* **Assumption:** The memory at the given address contains valid machine code for the target architecture.
* **Logical Transformation:** The C code takes raw bytes of machine code and transforms them into a more human-readable and programmatically accessible object.

**7. Considering User Errors:**

* **Invalid Memory Address:** Passing an address that doesn't point to executable code will likely result in an error.
* **Incorrect Architecture:** If Frida is running on a different architecture than the target process, disassembly will fail or be incorrect.
* **Misinterpreting Operands:** Users might need to understand the nuances of different operand types and addressing modes.

**8. Tracing User Operations:**

The user would typically reach this code through Frida's JavaScript API:

1. **Attaching to a Process:** Use `Frida.attach()` to connect to the target process.
2. **Getting a Code Location:**  Obtain a memory address of interest (e.g., from a function's entry point).
3. **Using `Instruction.parse()`:** Call `Instruction.parse(address)` in the Frida console or a script. This directly invokes the `gumjs_instruction_parse` function in the C code.
4. **Accessing Instruction Properties:** The returned `Instruction` object can then be inspected using its properties (e.g., `instruction.mnemonic`, `instruction.operands`).

**Self-Correction/Refinement During Analysis:**

Initially, one might just focus on the JavaScript bindings. However, noticing the architecture-specific code blocks is crucial for understanding the full scope. Also, understanding the role of Capstone is important. Recognizing the use of `g_slice_new` and `g_slice_free` suggests memory management considerations. Finally, linking the C code back to the user's JavaScript interaction provides the necessary context.
This C source file, `gumquickinstruction.c`, for the Frida dynamic instrumentation tool provides the functionality to **parse and analyze individual machine code instructions** within a target process. It acts as a bridge between Frida's core C/C++ code and its JavaScript API, allowing JavaScript users to inspect disassembled instructions.

Here's a breakdown of its functions and their relation to the topics you mentioned:

**1. Core Functionality:**

* **Disassembling Instructions:** The primary function is to take a memory address within a target process and disassemble the instruction located there. It uses the Capstone disassembly library (`cs_disasm`) for this purpose.
* **Representing Instructions in JavaScript:** It creates JavaScript objects that represent individual instructions. These objects have properties like:
    * `address`: The memory address of the instruction.
    * `next`: The memory address of the next instruction.
    * `size`: The size of the instruction in bytes.
    * `mnemonic`: The symbolic name of the instruction (e.g., "mov", "add", "jmp").
    * `opStr`: The operands of the instruction as a string (e.g., "eax, 0x10").
    * `operands`: A structured representation of the operands, broken down into their types and values.
    * `regsAccessed`, `regsRead`, `regsWritten`: Lists of registers accessed, read from, and written to by the instruction.
    * `groups`:  Instruction groups the instruction belongs to (e.g., jump, call, arithmetic).
* **Providing String and JSON Representations:** It allows converting the instruction object to a human-readable string (`toString`) and a JSON representation (`toJSON`).

**2. Relationship with Reverse Engineering:**

This file is **fundamental** to reverse engineering using Frida. Here's how:

* **Dynamic Disassembly:**  Traditional static analysis involves disassembling the entire binary. Frida allows for *dynamic* disassembly – examining instructions as they are about to be executed or have just been executed. This is invaluable for understanding code flow in complex scenarios, especially when dealing with dynamically generated code or obfuscation.
    * **Example:** A reverse engineer can use Frida to hook a function and, within the hook, use `Instruction.parse(address)` to examine the instruction at the current execution point. This helps in understanding the function's logic step-by-step.

* **Instruction Analysis:**  By providing access to the individual components of an instruction (operands, registers), it enables deeper analysis of the instruction's behavior.
    * **Example:**  A reverse engineer can identify which registers are being read and written, which can reveal how data is being manipulated. They can also analyze memory operands to understand data access patterns.

* **Identifying Code Patterns:**  Analyzing instruction groups can help identify common code patterns (e.g., recognizing jump instructions to understand control flow, or identifying cryptographic operations based on instruction groups).

**3. Binary Underlying, Linux, Android Kernel & Framework:**

This code interacts with these low-level concepts:

* **Binary Underlying:**
    * **Machine Code:** The core purpose is to interpret raw binary machine code instructions.
    * **Instruction Set Architecture (ISA):** The code includes architecture-specific logic (e.g., `#ifdef HAVE_I386`, `#elif defined (HAVE_ARM)`) to handle the nuances of different ISAs like x86, ARM, ARM64, and MIPS. This is crucial because instruction formats and operand types vary significantly between architectures.
    * **Registers:** It deals directly with CPU registers, identifying them by their names and understanding their roles in instructions.
    * **Memory Addressing:**  It parses memory operands, understanding how memory addresses are calculated using base registers, index registers, scales, and displacements.

* **Linux/Android Kernel & Framework:**
    * **Memory Access:** The `gum_ensure_code_readable` function hints at interaction with the operating system's memory management. It likely checks if the Frida process has permission to read the memory region where the instruction resides.
    * **Process Context:** Frida operates within the context of a target process. This code is used to inspect the instructions *within* that process's memory space.
    * **System Calls (Indirectly):** While this specific file might not directly make system calls, the information gathered here is often used in conjunction with Frida's hooking mechanisms, which *do* interact with the kernel through system calls.
    * **Android's ART/Dalvik (Indirectly):** When analyzing Android applications, this code can be used to inspect the native code portions of the application, including code generated by the ART or Dalvik virtual machines.

**4. Logical Reasoning and Assumptions:**

* **Assumption:** The memory address provided to `gumjs_instruction_parse` points to a valid, executable instruction for the target architecture.
* **Input:** A memory address (pointer `target`).
* **Processing:**
    1. The code determines the architecture based on compile-time flags and potentially runtime information.
    2. It uses Capstone to disassemble the bytes at the given address.
    3. It creates a JavaScript object and populates its properties with the disassembled instruction's details.
* **Output:** A JavaScript object representing the instruction, or an exception if disassembly fails.

**5. User or Programming Common Usage Errors:**

* **Providing an Invalid Memory Address:** If the user provides an address that doesn't contain executable code or is outside the process's memory space, `cs_disasm` will likely fail, and Frida will throw an error (e.g., "invalid instruction").
    * **Example:** `Instruction.parse(0xdeadbeef)` if this address is not within the target process's code section.

* **Assuming the Correct Architecture:** If the user tries to parse instructions from a process with a different architecture than what Frida is configured for, the disassembly will be incorrect or fail. Frida usually handles this automatically when attaching, but manual parsing might lead to errors.

* **Misinterpreting Operand Types:** The `operands` property provides structured information, but users might misunderstand the meaning of different operand types (e.g., immediate values, register operands, memory operands with different addressing modes).

* **Not Checking for Disassembly Errors:** Users should be prepared to handle cases where disassembly fails.

**6. User Operation to Reach Here (Debugging Clues):**

A user interacting with Frida to reach this code would typically follow these steps:

1. **Attach to a Process:** The user starts by attaching Frida to a running process using `frida` command-line tool or programmatically via the Frida API (e.g., `frida.attach('process_name')`).

2. **Identify a Code Location:** The user needs a memory address of interest. This could be:
   * **A function's entry point:** Obtained by resolving a symbol name (e.g., `Module.getExportByName('module_name', 'function_name').address`).
   * **The current instruction pointer during a breakpoint:** When a breakpoint hits, the current instruction pointer can be accessed.
   * **An address obtained through static analysis or other means.**

3. **Use `Instruction.parse()`:** In the Frida console or a JavaScript script, the user calls the `Instruction.parse()` method, passing the memory address as an argument.
   * **Example in Frida console:** `Instruction.parse(ptr("0x12345678"))`

4. **Inspect the Result:** The `Instruction.parse()` method returns a JavaScript object. The user can then inspect its properties to analyze the instruction:
   * **Example:**
     ```javascript
     const instr = Instruction.parse(ptr("0x12345678"));
     console.log(instr.mnemonic);
     console.log(instr.opStr);
     console.log(instr.operands);
     ```

**In summary, `gumquickinstruction.c` is a crucial component of Frida that empowers reverse engineers and security researchers to dynamically analyze the behavior of software by dissecting and understanding individual machine code instructions.** It bridges the gap between low-level binary execution and high-level JavaScript analysis.

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickinstruction.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2020-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 EvilWind <evilwind@protonmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickinstruction.h"

#include "gumquickmacros.h"

#include <string.h>

GUMJS_DECLARE_FUNCTION (gumjs_instruction_parse)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_instruction_construct)
GUMJS_DECLARE_FINALIZER (gumjs_instruction_finalize)
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
GUMJS_DECLARE_FUNCTION (gumjs_instruction_to_json)

static JSValue gum_parse_operands (JSContext * ctx, const cs_insn * insn,
    csh cs, GumQuickCore * core);

#if defined (HAVE_I386)
static JSValue gum_x86_parse_memory_operand_value (JSContext * ctx,
    const x86_op_mem * mem, csh cs, GumQuickCore * core);
#elif defined (HAVE_ARM)
static JSValue gum_arm_parse_memory_operand_value (JSContext * ctx,
    const arm_op_mem * mem, csh cs, GumQuickCore * core);
static JSValue gum_arm_parse_shift_details (JSContext * ctx,
    const cs_arm_op * op, GumQuickCore * core);
static const gchar * gum_arm_shifter_to_string (arm_shifter type);
#elif defined (HAVE_ARM64)
static JSValue gum_arm64_parse_memory_operand_value (JSContext * ctx,
    const arm64_op_mem * mem, csh cs, GumQuickCore * core);
static JSValue gum_arm64_parse_shift_details (JSContext * ctx,
    const cs_arm64_op * op, GumQuickCore * core);
static const gchar * gum_arm64_shifter_to_string (arm64_shifter type);
static const gchar * gum_arm64_extender_to_string (arm64_extender ext);
static const gchar * gum_arm64_vas_to_string (arm64_vas vas);
#elif defined (HAVE_MIPS)
static JSValue gum_mips_parse_memory_operand_value (JSContext * ctx,
    const mips_op_mem * mem, csh cs, GumQuickCore * core);
#endif

static JSValue gum_parse_regs (JSContext * ctx, const uint16_t * regs,
    uint8_t count, csh cs);

static JSValue gum_parse_groups (JSContext * ctx, const uint8_t * groups,
    uint8_t count, csh cs);

G_GNUC_UNUSED static JSValue gum_access_type_to_string (JSContext * ctx,
    uint8_t access_type);

static const JSClassDef gumjs_instruction_def =
{
  .class_name = "Instruction",
  .finalizer = gumjs_instruction_finalize,
};

static const JSCFunctionListEntry gumjs_instruction_module_entries[] =
{
  JS_CFUNC_DEF ("_parse", 0, gumjs_instruction_parse),
};

static const JSCFunctionListEntry gumjs_instruction_entries[] =
{
  JS_CGETSET_DEF ("address", gumjs_instruction_get_address, NULL),
  JS_CGETSET_DEF ("next", gumjs_instruction_get_next, NULL),
  JS_CGETSET_DEF ("size", gumjs_instruction_get_size, NULL),
  JS_CGETSET_DEF ("mnemonic", gumjs_instruction_get_mnemonic, NULL),
  JS_CGETSET_DEF ("opStr", gumjs_instruction_get_op_str, NULL),
  JS_CGETSET_DEF ("operands", gumjs_instruction_get_operands, NULL),
  JS_CGETSET_DEF ("regsAccessed", gumjs_instruction_get_regs_accessed, NULL),
  JS_CGETSET_DEF ("regsRead", gumjs_instruction_get_regs_read, NULL),
  JS_CGETSET_DEF ("regsWritten", gumjs_instruction_get_regs_written, NULL),
  JS_CGETSET_DEF ("groups", gumjs_instruction_get_groups, NULL),
  JS_CFUNC_DEF ("toString", 0, gumjs_instruction_to_string),
  JS_CFUNC_DEF ("toJSON", 0, gumjs_instruction_to_json),
};

void
_gum_quick_instruction_init (GumQuickInstruction * self,
                             JSValue ns,
                             GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  gum_cs_arch_register_native ();
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &self->capstone);
  cs_option (self->capstone, CS_OPT_DETAIL, CS_OPT_ON);

  _gum_quick_core_store_module_data (core, "instruction", self);

  _gum_quick_create_class (ctx, &gumjs_instruction_def, core,
      &self->instruction_class, &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_instruction_construct,
      gumjs_instruction_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_instruction_module_entries,
      G_N_ELEMENTS (gumjs_instruction_module_entries));
  JS_SetPropertyFunctionList (ctx, proto, gumjs_instruction_entries,
      G_N_ELEMENTS (gumjs_instruction_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_instruction_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_instruction_dispose (GumQuickInstruction * self)
{
}

void
_gum_quick_instruction_finalize (GumQuickInstruction * self)
{
  cs_close (&self->capstone);
}

static GumQuickInstruction *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "instruction");
}

JSValue
_gum_quick_instruction_new (JSContext * ctx,
                            const cs_insn * insn,
                            gboolean is_owned,
                            gconstpointer target,
                            csh capstone,
                            GumQuickInstruction * parent,
                            GumQuickInstructionValue ** instruction)
{
  JSValue wrapper;
  GumQuickInstructionValue * v;

  wrapper = JS_NewObjectClass (ctx, parent->instruction_class);

  v = g_slice_new (GumQuickInstructionValue);
  v->wrapper = wrapper;
  if (is_owned)
  {
    v->insn = insn;
  }
  else
  {
    cs_insn * insn_copy;
    cs_detail * detail_copy;

    g_assert (capstone != 0);

    insn_copy = cs_malloc (capstone);
    detail_copy = insn_copy->detail;
    memcpy (insn_copy, insn, sizeof (cs_insn));
    insn_copy->detail = detail_copy;
    if (detail_copy != NULL)
      memcpy (detail_copy, insn->detail, sizeof (cs_detail));

    v->insn = insn_copy;
  }
  v->owns_memory = insn != NULL;
  v->target = target;

  JS_SetOpaque (wrapper, v);

  if (instruction != NULL)
    *instruction = v;

  return wrapper;
}

gboolean
_gum_quick_instruction_get (JSContext * ctx,
                            JSValue val,
                            GumQuickInstruction * parent,
                            GumQuickInstructionValue ** instruction)
{
  GumQuickInstructionValue * v;

  if (!_gum_quick_unwrap (ctx, val, parent->instruction_class, parent->core,
      (gpointer *) &v))
    return FALSE;

  if (v->insn == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *instruction = v;
  return TRUE;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_parse)
{
  GumQuickInstruction * self;
  gpointer target;
  uint64_t address;
  const gsize max_instruction_size = 16;
  cs_insn * insn;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "p", &target))
    return JS_EXCEPTION;

  target = gum_strip_code_pointer (target);

#ifdef HAVE_ARM
  address = GPOINTER_TO_SIZE (target) & ~1;
  cs_option (self->capstone, CS_OPT_MODE,
      (((GPOINTER_TO_SIZE (target) & 1) == 1) ? CS_MODE_THUMB : CS_MODE_ARM) |
      CS_MODE_V8 | GUM_DEFAULT_CS_ENDIAN);
#else
  address = GPOINTER_TO_SIZE (target);
#endif

  gum_ensure_code_readable (GSIZE_TO_POINTER (address), max_instruction_size);

  if (cs_disasm (self->capstone, (uint8_t *) GSIZE_TO_POINTER (address),
      max_instruction_size, address, 1, &insn) == 0)
  {
    return _gum_quick_throw_literal (ctx, "invalid instruction");
  }

  return _gum_quick_instruction_new (ctx, insn, TRUE, target, self->capstone,
      self, NULL);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_instruction_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FINALIZER (gumjs_instruction_finalize)
{
  GumQuickInstructionValue * v;

  v = JS_GetOpaque (val, gumjs_get_parent_module (core)->instruction_class);
  if (v == NULL)
    return;

  if (v->owns_memory && v->insn != NULL)
    cs_free ((cs_insn *) v->insn, 1);

  g_slice_free (GumQuickInstructionValue, v);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_address)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (self->insn->address), core);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_next)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (GPOINTER_TO_SIZE (self->target) + self->insn->size),
      core);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_size)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return JS_NewInt32 (ctx, self->insn->size);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_mnemonic)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return JS_NewString (ctx, self->insn->mnemonic);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_op_str)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return JS_NewString (ctx, self->insn->op_str);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_operands)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  return gum_parse_operands (ctx, self->insn, parent->capstone, parent->core);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_regs_accessed)
{
  JSValue result;
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;
  csh capstone;
  cs_regs regs_read, regs_write;
  uint8_t regs_read_count, regs_write_count;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  capstone = parent->capstone;

  if (cs_regs_access (capstone, self->insn,
        regs_read, &regs_read_count,
        regs_write, &regs_write_count) != 0)
  {
    return _gum_quick_throw_literal (ctx,
        "not yet supported on this architecture");
  }

  result = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, result,
      GUM_QUICK_CORE_ATOM (core, read),
      gum_parse_regs (ctx, regs_read, regs_read_count, capstone),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, result,
      GUM_QUICK_CORE_ATOM (core, written),
      gum_parse_regs (ctx, regs_write, regs_write_count, capstone),
      JS_PROP_C_W_E);

  return result;
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_regs_read)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;
  const cs_detail * d;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  d = self->insn->detail;

  return gum_parse_regs (ctx, d->regs_read, d->regs_read_count,
      parent->capstone);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_regs_written)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;
  const cs_detail * d;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  d = self->insn->detail;

  return gum_parse_regs (ctx, d->regs_write, d->regs_write_count,
      parent->capstone);
}

GUMJS_DEFINE_GETTER (gumjs_instruction_get_groups)
{
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;
  const cs_detail * d;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  d = self->insn->detail;

  return gum_parse_groups (ctx, d->groups, d->groups_count, parent->capstone);
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_to_string)
{
  JSValue result;
  GumQuickInstruction * parent;
  GumQuickInstructionValue * self;
  const cs_insn * insn;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_instruction_get (ctx, this_val, parent, &self))
    return JS_EXCEPTION;

  insn = self->insn;

  if (insn->op_str[0] == '\0')
  {
    result = JS_NewString (ctx, insn->mnemonic);
  }
  else
  {
    gchar * str;

    str = g_strconcat (insn->mnemonic, " ", insn->op_str, NULL);
    result = JS_NewString (ctx, str);
    g_free (str);
  }

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_instruction_to_json)
{
  JSValue result;
  guint i;

  result = JS_NewObject (ctx);

  for (i = 0; i != G_N_ELEMENTS (gumjs_instruction_entries); i++)
  {
    const JSCFunctionListEntry * e = &gumjs_instruction_entries[i];
    JSValue val;

    if (e->def_type != JS_DEF_CGETSET)
      continue;

    val = JS_GetPropertyStr (ctx, this_val, e->name);
    if (JS_IsException (val))
      goto propagate_exception;
    JS_SetPropertyStr (ctx, result, e->name, val);
  }

  return result;

propagate_exception:
  {
    JS_FreeValue (ctx, result);

    return JS_EXCEPTION;
  }
}

#if defined (HAVE_I386)

static JSValue
gum_parse_operands (JSContext * ctx,
                    const cs_insn * insn,
                    csh cs,
                    GumQuickCore * core)
{
  JSValue result;
  const cs_x86 * x86 = &insn->detail->x86;
  uint8_t i;

  result = JS_NewArray (ctx);

  for (i = 0; i != x86->op_count; i++)
  {
    const cs_x86_op * op = &x86->operands[i];
    JSValue op_obj;
    const gchar * type;
    JSValue val;

    op_obj = JS_NewObject (ctx);

    switch (op->type)
    {
      case X86_OP_REG:
        type = "reg";
        val = JS_NewString (ctx, cs_reg_name (cs, op->reg));
        break;
      case X86_OP_IMM:
        type = "imm";
        val = _gum_quick_int64_new (ctx, op->imm, core);
        break;
      case X86_OP_MEM:
        type = "mem";
        val = gum_x86_parse_memory_operand_value (ctx, &op->mem, cs, core);
        break;
      default:
        type = NULL;
        val = JS_NULL;
        g_assert_not_reached ();
    }

    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, type),
        JS_NewString (ctx, type),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, value),
        val,
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, size),
        JS_NewInt32 (ctx, op->size),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, access),
        gum_access_type_to_string (ctx, op->access),
        JS_PROP_C_W_E);

    JS_DefinePropertyValueUint32 (ctx, result, i, op_obj, JS_PROP_C_W_E);
  }

  return result;
}

static JSValue
gum_x86_parse_memory_operand_value (JSContext * ctx,
                                    const x86_op_mem * mem,
                                    csh cs,
                                    GumQuickCore * core)
{
  JSValue val = JS_NewObject (ctx);

  if (mem->segment != X86_REG_INVALID)
  {
    JS_DefinePropertyValue (ctx, val,
        GUM_QUICK_CORE_ATOM (core, segment),
        JS_NewString (ctx, cs_reg_name (cs, mem->segment)),
        JS_PROP_C_W_E);
  }
  if (mem->base != X86_REG_INVALID)
  {
    JS_DefinePropertyValue (ctx, val,
        GUM_QUICK_CORE_ATOM (core, base),
        JS_NewString (ctx, cs_reg_name (cs, mem->base)),
        JS_PROP_C_W_E);
  }
  if (mem->index != X86_REG_INVALID)
  {
    JS_DefinePropertyValue (ctx, val,
        GUM_QUICK_CORE_ATOM (core, index),
        JS_NewString (ctx, cs_reg_name (cs, mem->index)),
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, val,
      GUM_QUICK_CORE_ATOM (core, scale),
      JS_NewInt32 (ctx, mem->scale),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, val,
      GUM_QUICK_CORE_ATOM (core, disp),
      JS_NewInt64 (ctx, mem->disp),
      JS_PROP_C_W_E);

  return val;
}

#elif defined (HAVE_ARM)

static JSValue
gum_parse_operands (JSContext * ctx,
                    const cs_insn * insn,
                    csh cs,
                    GumQuickCore * core)
{
  JSValue result;
  const cs_arm * arm = &insn->detail->arm;
  uint8_t i;

  result = JS_NewArray (ctx);

  for (i = 0; i != arm->op_count; i++)
  {
    const cs_arm_op * op = &arm->operands[i];
    JSValue op_obj;
    const gchar * type;
    JSValue val;

    op_obj = JS_NewObject (ctx);

    switch (op->type)
    {
      case ARM_OP_REG:
        type = "reg";
        val = JS_NewString (ctx, cs_reg_name (cs, op->reg));
        break;
      case ARM_OP_IMM:
        type = "imm";
        val = JS_NewInt32 (ctx, op->imm);
        break;
      case ARM_OP_MEM:
        type = "mem";
        val = gum_arm_parse_memory_operand_value (ctx, &op->mem, cs, core);
        break;
      case ARM_OP_FP:
        type = "fp";
        val = JS_NewFloat64 (ctx, op->fp);
        break;
      case ARM_OP_CIMM:
        type = "cimm";
        val = JS_NewInt32 (ctx, op->imm);
        break;
      case ARM_OP_PIMM:
        type = "pimm";
        val = JS_NewInt32 (ctx, op->imm);
        break;
      case ARM_OP_SETEND:
        type = "setend";
        val = JS_NewString (ctx, (op->setend == ARM_SETEND_BE) ? "be" : "le");
        break;
      case ARM_OP_SYSREG:
        type = "sysreg";
        val = JS_NewString (ctx, cs_reg_name (cs, op->reg));
        break;
      default:
        g_assert_not_reached ();
    }

    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, type),
        JS_NewString (ctx, type),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, value),
        val,
        JS_PROP_C_W_E);
    if (op->shift.type != ARM_SFT_INVALID)
    {
      JS_DefinePropertyValue (ctx, op_obj,
          GUM_QUICK_CORE_ATOM (core, shift),
          gum_arm_parse_shift_details (ctx, op, core),
          JS_PROP_C_W_E);
    }
    if (op->vector_index != -1)
    {
      JS_DefinePropertyValue (ctx, op_obj,
          GUM_QUICK_CORE_ATOM (core, vectorIndex),
          JS_NewInt32 (ctx, op->vector_index),
          JS_PROP_C_W_E);
    }
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, subtracted),
        JS_NewBool (ctx, op->subtracted),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, access),
        gum_access_type_to_string (ctx, op->access),
        JS_PROP_C_W_E);

    JS_DefinePropertyValueUint32 (ctx, result, i, op_obj, JS_PROP_C_W_E);
  }

  return result;
}

static JSValue
gum_arm_parse_memory_operand_value (JSContext * ctx,
                                    const arm_op_mem * mem,
                                    csh cs,
                                    GumQuickCore * core)
{
  JSValue val = JS_NewObject (ctx);

  if (mem->base != ARM_REG_INVALID)
  {
    JS_DefinePropertyValue (ctx, val,
        GUM_QUICK_CORE_ATOM (core, base),
        JS_NewString (ctx, cs_reg_name (cs, mem->base)),
        JS_PROP_C_W_E);
  }
  if (mem->index != ARM_REG_INVALID)
  {
    JS_DefinePropertyValue (ctx, val,
        GUM_QUICK_CORE_ATOM (core, index),
        JS_NewString (ctx, cs_reg_name (cs, mem->index)),
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, val,
      GUM_QUICK_CORE_ATOM (core, scale),
      JS_NewInt32 (ctx, mem->scale),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, val,
      GUM_QUICK_CORE_ATOM (core, disp),
      JS_NewInt32 (ctx, mem->disp),
      JS_PROP_C_W_E);

  return val;
}

static JSValue
gum_arm_parse_shift_details (JSContext * ctx,
                             const cs_arm_op * op,
                             GumQuickCore * core)
{
  JSValue shift = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, shift,
      GUM_QUICK_CORE_ATOM (core, type),
      JS_NewString (ctx, gum_arm_shifter_to_string (op->shift.type)),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, shift,
      GUM_QUICK_CORE_ATOM (core, value),
      JS_NewInt64 (ctx, op->shift.value),
      JS_PROP_C_W_E);

  return shift;
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

static JSValue
gum_parse_operands (JSContext * ctx,
                    const cs_insn * insn,
                    csh cs,
                    GumQuickCore * core)
{
  JSValue result;
  const cs_arm64 * arm64 = &insn->detail->arm64;
  uint8_t i;

  result = JS_NewArray (ctx);

  for (i = 0; i != arm64->op_count; i++)
  {
    const cs_arm64_op * op = &arm64->operands[i];
    JSValue op_obj;
    const gchar * type;
    JSValue val;

    op_obj = JS_NewObject (ctx);

    switch (op->type)
    {
      case ARM64_OP_REG:
        type = "reg";
        val = JS_NewString (ctx, cs_reg_name (cs, op->reg));
        break;
      case ARM64_OP_IMM:
        type = "imm";
        val = _gum_quick_int64_new (ctx, op->imm, core);
        break;
      case ARM64_OP_MEM:
        type = "mem";
        val = gum_arm64_parse_memory_operand_value (ctx, &op->mem, cs, core);
        break;
      case ARM64_OP_FP:
        type = "fp";
        val = JS_NewFloat64 (ctx, op->fp);
        break;
      case ARM64_OP_CIMM:
        type = "cimm";
        val = _gum_quick_int64_new (ctx, op->imm, core);
        break;
      case ARM64_OP_REG_MRS:
        type = "reg-mrs";
        val = JS_NewString (ctx, cs_reg_name (cs, op->reg));
        break;
      case ARM64_OP_REG_MSR:
        type = "reg-msr";
        val = JS_NewString (ctx, cs_reg_name (cs, op->reg));
        break;
      case ARM64_OP_PSTATE:
        type = "pstate";
        val = JS_NewInt32 (ctx, op->pstate);
        break;
      case ARM64_OP_SYS:
        type = "sys";
        val = JS_NewInt64 (ctx, op->sys);
        break;
      case ARM64_OP_PREFETCH:
        type = "prefetch";
        val = JS_NewInt32 (ctx, op->prefetch);
        break;
      case ARM64_OP_BARRIER:
        type = "barrier";
        val = JS_NewInt32 (ctx, op->barrier);
        break;
      default:
        g_assert_not_reached ();
    }

    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, type),
        JS_NewString (ctx, type),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, value),
        val,
        JS_PROP_C_W_E);
    if (op->shift.type != ARM64_SFT_INVALID)
    {
      JS_DefinePropertyValue (ctx, op_obj,
          GUM_QUICK_CORE_ATOM (core, shift),
          gum_arm64_parse_shift_details (ctx, op, core),
          JS_PROP_C_W_E);
    }
    if (op->ext != ARM64_EXT_INVALID)
    {
      JS_DefinePropertyValue (ctx, op_obj,
          GUM_QUICK_CORE_ATOM (core, ext),
          JS_NewString (ctx, gum_arm64_extender_to_string (op->ext)),
          JS_PROP_C_W_E);
    }
    if (op->vas != ARM64_VAS_INVALID)
    {
      JS_DefinePropertyValue (ctx, op_obj,
          GUM_QUICK_CORE_ATOM (core, vas),
          JS_NewString (ctx, gum_arm64_vas_to_string (op->vas)),
          JS_PROP_C_W_E);
    }
    if (op->vector_index != -1)
    {
      JS_DefinePropertyValue (ctx, op_obj,
          GUM_QUICK_CORE_ATOM (core, vectorIndex),
          JS_NewInt32 (ctx, op->vector_index),
          JS_PROP_C_W_E);
    }
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, access),
        gum_access_type_to_string (ctx, op->access),
        JS_PROP_C_W_E);

    JS_DefinePropertyValueUint32 (ctx, result, i, op_obj, JS_PROP_C_W_E);
  }

  return result;
}

static JSValue
gum_arm64_parse_memory_operand_value (JSContext * ctx,
                                      const arm64_op_mem * mem,
                                      csh cs,
                                      GumQuickCore * core)
{
  JSValue val = JS_NewObject (ctx);

  if (mem->base != ARM64_REG_INVALID)
  {
    JS_DefinePropertyValue (ctx, val,
        GUM_QUICK_CORE_ATOM (core, base),
        JS_NewString (ctx, cs_reg_name (cs, mem->base)),
        JS_PROP_C_W_E);
  }
  if (mem->index != ARM64_REG_INVALID)
  {
    JS_DefinePropertyValue (ctx, val,
        GUM_QUICK_CORE_ATOM (core, index),
        JS_NewString (ctx, cs_reg_name (cs, mem->index)),
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, val,
      GUM_QUICK_CORE_ATOM (core, disp),
      JS_NewInt32 (ctx, mem->disp),
      JS_PROP_C_W_E);

  return val;
}

static JSValue
gum_arm64_parse_shift_details (JSContext * ctx,
                               const cs_arm64_op * op,
                               GumQuickCore * core)
{
  JSValue shift = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, shift,
      GUM_QUICK_CORE_ATOM (core, type),
      JS_NewString (ctx, gum_arm64_shifter_to_string (op->shift.type)),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, shift,
      GUM_QUICK_CORE_ATOM (core, value),
      JS_NewInt64 (ctx, op->shift.value),
      JS_PROP_C_W_E);

  return shift;
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

static JSValue
gum_parse_operands (JSContext * ctx,
                    const cs_insn * insn,
                    csh cs,
                    GumQuickCore * core)
{
  JSValue result;
  const cs_mips * mips = &insn->detail->mips;
  uint8_t i;

  result = JS_NewArray (ctx);

  for (i = 0; i != mips->op_count; i++)
  {
    const cs_mips_op * op = &mips->operands[i];
    JSValue op_obj;
    const gchar * type;
    JSValue val;

    op_obj = JS_NewObject (ctx);

    switch (op->type)
    {
      case MIPS_OP_REG:
        type = "reg";
        val = JS_NewString (ctx, cs_reg_name (cs, op->reg));
        break;
      case MIPS_OP_IMM:
        type = "imm";
        val = JS_NewInt64 (ctx, op->imm);
        break;
      case MIPS_OP_MEM:
        type = "mem";
        val = gum_mips_parse_memory_operand_value (ctx, &op->mem, cs, core);
        break;
      default:
        g_assert_not_reached ();
    }

    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, type),
        JS_NewString (ctx, type),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, op_obj,
        GUM_QUICK_CORE_ATOM (core, value),
        val,
        JS_PROP_C_W_E);

    JS_DefinePropertyValueUint32 (ctx, result, i, op_obj, JS_PROP_C_W_E);
  }

  return result;
}

static JSValue
gum_mips_parse_memory_operand_value (JSContext * ctx,
                                     const mips_op_mem * mem,
                                     csh cs,
                                     GumQuickCore * core)
{
  JSValue val = JS_NewObject (ctx);

  if (mem->base != MIPS_REG_INVALID)
  {
    JS_DefinePropertyValue (ctx, val,
        GUM_QUICK_CORE_ATOM (core, base),
        JS_NewString (ctx, cs_reg_name (cs, mem->base)),
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, val,
      GUM_QUICK_CORE_ATOM (core, disp),
      JS_NewInt64 (ctx, mem->disp),
      JS_PROP_C_W_E);

  return val;
}

#endif

static JSValue
gum_parse_regs (JSContext * ctx,
                const uint16_t * regs,
                uint8_t count,
                csh cs)
{
  JSValue r;
  uint8_t i;

  r = JS_NewArray (ctx);

  for (i = 0; i != count; i++)
  {
    JS_DefinePropertyValueUint32 (ctx, r, i,
        JS_NewString (ctx, cs_reg_name (cs, regs[i])),
        JS_PROP_C_W_E);
  }

  return r;
}

static JSValue
gum_parse_groups (JSContext * ctx,
                  const uint8_t * groups,
                  uint8_t count,
                  csh cs)
{
  JSValue g;
  uint8_t i;

  g = JS_NewArray (ctx);

  for (i = 0; i != count; i++)
  {
    JS_DefinePropertyValueUint32 (ctx, g, i,
        JS_NewString (ctx, cs_group_name (cs, groups[i])),
        JS_PROP_C_W_E);
  }

  return g;
}

static JSValue
gum_access_type_to_string (JSContext * ctx,
                           uint8_t access_type)
{
  const gchar * str = NULL;

  switch (access_type)
  {
    case CS_AC_INVALID:
      str = "";
      break;
    case CS_AC_READ:
      str = "r";
      break;
    case CS_AC_WRITE:
      str = "w";
      break;
    case CS_AC_READ | CS_AC_WRITE:
      str = "rw";
      break;
    default:
      g_assert_not_reached ();
  }

  return JS_NewString (ctx, str);
}
```