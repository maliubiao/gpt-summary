Response:
Let's break down the thought process for analyzing this C++ code snippet.

1. **Understanding the Goal:** The overarching goal is to explain the functionality of the given C++ code, which is part of V8's debugging infrastructure for GDB. This means we need to explain *what* it does and *why*.

2. **Initial Scan and Keywords:**  A quick scan reveals several key terms: `gdb-jit.cc`, `DWARF`, `JIT`, `JITCodeEntry`, `JITDescriptor`, `__jit_debug_register_code`, `ELF`, `MachO`, `LineInfo`, `UnwindInfo`. These immediately suggest the code is related to:
    * **Debugging:**  `gdb` and `DWARF` are strong indicators.
    * **Just-In-Time Compilation:**  `JIT` is central.
    * **Executable Formats:** `ELF` and `MachO` indicate handling of different operating system executable structures.
    * **Code Management:** `JITCodeEntry` and `JITDescriptor` point to managing information about compiled code.
    * **Line Number Information:** `LineInfo` is likely about mapping code offsets to source code lines.
    * **Stack Unwinding:** `UnwindInfo` suggests handling how debuggers can trace back the call stack.

3. **Decomposition by Class/Structure:**  The code is organized into classes and structures. Analyzing each one individually is a good strategy:

    * **`DebugSection` (Base Class):**  This is abstract. The key takeaway is that it defines an interface for writing debug information. The virtual `WriteBodyInternal` function is the core of this interface.

    * **`DebugInfoSection`:** Focus on the data it writes: `.debug_info`. It contains information about the "compile unit" (likely a function or script), its address range (`DW_AT_LOW_PC`, `DW_AT_HIGH_PC`), and a reference to line number information (`DW_AT_STMT_LIST`).

    * **`DebugAbbrevSection`:** This writes to `.debug_abbrev`. The constants like `DW_TAG_COMPILE_UNIT`, `DW_AT_NAME`, `DW_FORM_STRING` are DWARF abbreviations. This section defines how the information in `.debug_info` (and other sections) is structured and interpreted. The `WriteVariableAbbreviation` function is interesting; it handles how variables (parameters, local variables) are described.

    * **`DebugLineSection`:**  Writes to `.debug_line`. The `DW_LNS_*` constants are DWARF line number opcodes. The core logic involves iterating through `LineInfo::PCInfo` and generating a compact representation of the mapping between program counter values and source code lines. The handling of special opcodes is an optimization for size.

    * **`UnwindInfoSection` (x64 only):**  Writes to `.eh_frame` (ELF) or `__eh_frame` (MachO). The `DW_CFA_*` constants are DWARF CFI (Call Frame Information) instructions. This section describes how the stack frame is laid out at different points in the function's execution, allowing debuggers to unwind the stack. The different `WriteFDEState...` methods correspond to different points in the function's prologue/epilogue.

    * **`JITDescriptor` and `JITCodeEntry`:** These are data structures used by GDB to track JIT-compiled code. `JITDescriptor` is the main entry point for GDB. `JITCodeEntry` represents a single block of JIT-compiled code and holds the address and size of the debug information.

3. **Understanding the GDB Interaction:**  The global variables `__jit_debug_descriptor` and the function `__jit_debug_register_code` are crucial for the GDB integration. The comments clearly indicate their purpose: GDB inspects the descriptor and places breakpoints in the registration function. The `JITAction` enum defines the actions GDB is notified about.

4. **Logic Flow and Key Functions:**

    * **`CreateELFObject`:**  This function orchestrates the creation of the debug information. It creates either an ELF or MachO object based on the platform, adds the code section, the DWARF sections, and then writes everything to a buffer.
    * **`RegisterCodeEntry` and `UnregisterCodeEntry`:** These functions manage the linked list of `JITCodeEntry` structures and update the `__jit_debug_descriptor`, triggering the GDB notification.
    * **`EventHandler`:** This function is called when V8's JIT compiler adds, moves, or removes code. It's the main entry point for integrating with the JIT code events. The `CODE_ADDED` case is where the debug information is generated and registered. The `CODE_START_LINE_INFO_RECORDING`, `CODE_ADD_LINE_POS_INFO`, and `CODE_END_LINE_INFO_RECORDING` cases handle the collection of line number information.

5. **Considering Edge Cases and Alternatives:**

    * **Torque:** The prompt explicitly asks about `.tq` files. Since the file is `.cc`, it's C++, not Torque.
    * **JavaScript Relevance:** The code directly relates to debugging JavaScript code in V8. The connection is that this C++ code generates the debug information that allows developers to step through and inspect JavaScript code using GDB.
    * **Error Handling:** The code doesn't show explicit error handling in the debug information generation. This is typical for debug information generation, where the focus is on providing the information, and failures might lead to a lack of debugging capabilities rather than a program crash.
    * **Common Programming Errors:**  While the C++ code itself isn't directly causing *JavaScript* errors, if the generated debug information is incorrect, it can lead to misleading debugging experiences (e.g., stepping to the wrong line, incorrect variable values).

6. **Structuring the Explanation:**  A logical structure for the explanation would be:

    * **Overall Function:** Briefly describe the high-level purpose.
    * **Core Components:** Explain the key classes and structures and their roles.
    * **GDB Integration:** Detail how the code interacts with GDB.
    * **Workflow:** Describe the sequence of actions when code is compiled.
    * **JavaScript Relevance (with example):** Show how this relates to debugging JavaScript.
    * **Assumptions and Outputs:** Provide concrete examples of input and output.
    * **Common Errors:** Illustrate potential debugging issues caused by incorrect debug information.
    * **Summary:**  Reiterate the main function in a concise way.

7. **Refinement and Clarity:** After drafting the initial explanation, review it for clarity, accuracy, and completeness. Ensure that technical terms are explained (or at least their purpose is clear in context). Use code examples (even simple ones) to illustrate the JavaScript connection. Pay attention to the "part 2 of 2" instruction and provide a good summary.

By following this systematic approach, we can effectively analyze and explain the functionality of complex C++ code like the provided snippet.
好的，这是对 `v8/src/diagnostics/gdb-jit.cc` 代码的功能归纳：

**核心功能：为 V8 的 JIT (Just-In-Time) 编译代码生成调试信息，以便 GDB (GNU Debugger) 能够调试这些动态生成的代码。**

**详细功能分解：**

1. **生成 DWARF 调试信息：**  代码的主要目标是生成符合 DWARF (Debugging With Attributed Record Formats) 标准的调试信息。DWARF 是一种通用的调试数据格式，GDB 可以理解和利用它来调试程序。

2. **支持 ELF 和 Mach-O 格式：** 代码根据不同的操作系统平台 (Linux/Unix 使用 ELF，macOS 使用 Mach-O) 生成相应的调试信息结构。

3. **生成 `.debug_info` Section：** 包含关于编译单元（通常是函数或脚本）的基本信息，例如其在内存中的起始和结束地址、名称以及关联的行号信息。

4. **生成 `.debug_abbrev` Section：** 定义了 `.debug_info` 中使用的缩写代码，用于紧凑地表示调试信息的结构。它定义了各种 DWARF 标签 (Tags)、属性 (Attributes) 和形式 (Forms)。

5. **生成 `.debug_line` Section：**  关键部分，用于将 JIT 编译后的机器码的地址映射回源代码的行号。这使得在 GDB 中可以按源代码行进行断点设置和单步执行。

6. **生成 `.eh_frame` Section (x64)：**  在 x64 架构上生成异常处理帧信息 (Exception Handling Frame)。这部分信息描述了函数调用栈的结构，允许 GDB 在程序崩溃或遇到断点时回溯调用栈。它包含了 CFI (Call Frame Information) 指令，用于描述如何在栈帧之间移动。

7. **GDB JIT 接口：** 代码实现了 GDB 的 JIT 接口，允许 V8 运行时通知 GDB 新生成的 JIT 代码。
    * **`JITDescriptor` 和 `JITCodeEntry` 结构：** 用于描述 JIT 代码的元数据，例如代码的起始地址、大小以及包含调试信息的内存地址。
    * **`__jit_debug_register_code()` 函数：**  V8 调用此函数通知 GDB 有新的 JIT 代码需要调试。GDB 会在这个函数上设置断点。
    * **`__jit_debug_descriptor` 变量：** GDB 会检查这个全局变量的内容，获取 JIT 代码的信息。

8. **代码注册和注销：**  代码维护了一个 JIT 代码条目的链表 (`__jit_debug_descriptor.first_entry_`)，并在 JIT 代码生成或移除时动态地注册和注销这些条目。

9. **行号信息管理 (`LineInfo`)：**  使用 `LineInfo` 类来存储和管理代码地址与源代码位置之间的映射关系。  通过 `JitCodeEvent` API 接收 V8 引擎发出的行号信息，并将其写入 `.debug_line` section。

10. **处理代码移动和移除事件：** 虽然理论上支持，但注释表明，启用 GDB JIT 接口应该禁用代码压缩，这意味着 `CODE_MOVED` 事件不应该发生。`CODE_REMOVED` 事件的处理方式是在添加新代码时，移除任何与新代码地址范围重叠的现有条目。

**如果 `v8/src/diagnostics/gdb-jit.cc` 以 `.tq` 结尾：**

那么它将是一个 **V8 Torque 源代码**。Torque 是 V8 用于定义内置函数和运行时函数的领域特定语言。 Torque 代码会被编译成 C++ 代码，然后被 V8 使用。

**与 JavaScript 的功能关系及示例：**

`gdb-jit.cc` 的功能直接关系到调试 JavaScript 代码。当 V8 运行 JavaScript 代码时，它会将部分代码编译成机器码以提高性能 (JIT)。如果没有 `gdb-jit.cc` 生成的调试信息，GDB 就无法理解这些动态生成的机器码，也就无法进行有效的调试，例如：

```javascript
function add(a, b) {
  return a + b; // 假设我们想在这里设置断点
}

let result = add(5, 3);
console.log(result);
```

当 GDB 附加到 V8 进程并尝试在这个 JavaScript 代码的第 2 行设置断点时，`gdb-jit.cc` 生成的调试信息会告诉 GDB：

*  `add` 函数对应的 JIT 代码在内存中的哪个地址范围。
*  JavaScript 源代码的第 2 行对应于该内存地址范围内的哪个或哪些机器码指令。

这样，GDB 才能准确地在对应的机器码指令上设置断点，并在程序执行到该行时暂停。

**代码逻辑推理、假设输入与输出：**

假设 V8 编译了以下 JavaScript 函数：

```javascript
function myFunction(x) {
  let y = x * 2;
  return y + 1;
}
```

**假设输入：**

* `CodeDescription` 对象包含了 `myFunction` 的元数据：
    * 代码起始地址：`0x12345000`
    * 代码大小：`0x100` 字节
    * 关联的 `SharedFunctionInfo` 对象
    * `LineInfo` 对象，包含以下映射关系（简化）：
        * 代码偏移 `0`  -> 源代码行 `1` (函数开始)
        * 代码偏移 `0x20` -> 源代码行 `2` (`let y = ...`)
        * 代码偏移 `0x80` -> 源代码行 `3` (`return y + 1`)

**可能的输出（部分 `.debug_line` 内容的简化表示）：**

`.debug_line` section 会包含类似以下的指令，用于描述代码地址和源代码行号的对应关系：

* `设置地址 0x12345000` (指示接下来的行号信息从这个地址开始)
* `行号 1， 代码偏移 0`
* `代码前进 0x20` (代码指针前进 0x20 字节)
* `行号 2` (行号变为 2)
* `代码前进 0x60`
* `行号 3`

**涉及用户常见的编程错误及示例：**

`gdb-jit.cc` 本身不直接防止用户编写错误的 JavaScript 代码。但是，它提供的调试能力可以帮助用户更容易地定位和修复这些错误。例如：

```javascript
function calculateAverage(arr) {
  let sum = 0;
  for (let i = 0; i < arr.lenght; i++) { // 错误：应该是 arr.length
    sum += arr[i];
  }
  return sum / arr.length;
}

let numbers = [1, 2, 3, 4, 5];
let average = calculateAverage(numbers);
console.log(average);
```

在这个例子中，`arr.lenght` 是一个拼写错误。如果没有调试器，用户可能很难发现这个错误。但是，如果使用 GDB 并启用了 JIT 调试，用户可以在 `for` 循环内部设置断点，观察 `i` 的值和数组的访问情况，从而快速发现 `arr.lenght` 是 `undefined`，进而定位错误。

**总结（对第 2 部分的归纳）：**

这部分代码主要负责生成和管理 DWARF 调试信息的具体内容，包括：

* **定义了用于表示调试信息的各种 DWARF section 的结构和写入逻辑。**  例如，如何写入编译单元信息、变量信息、以及最重要的代码地址到源代码行号的映射。
* **实现了与 GDB JIT 接口的交互，**  用于注册和注销 JIT 编译的代码，以便 GDB 能够感知并调试这些代码。
* **处理与行号信息相关的事件，**  将 V8 提供的行号信息转换为 DWARF `.debug_line` section 的格式。
* **针对 x64 架构，还包含了生成 `.eh_frame` section 的逻辑，**  用于支持堆栈回溯。

总而言之，这部分代码是 V8 的 JIT 调试能力的核心组成部分，它将 V8 动态生成的机器码与 JavaScript 源代码联系起来，使得开发者可以使用 GDB 这样的标准调试工具来调试高性能的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/diagnostics/gdb-jit.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/diagnostics/gdb-jit.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
}

    w->WriteULEB128(0);  // Terminate the compile unit.
    size.set(static_cast<uint32_t>(w->position() - start));
    return true;
  }

 private:
  CodeDescription* desc_;
};

class DebugAbbrevSection : public DebugSection {
 public:
  explicit DebugAbbrevSection(CodeDescription* desc)
#ifdef __ELF
      : ELFSection(".debug_abbrev", TYPE_PROGBITS, 1),
#else
      : MachOSection("__debug_abbrev", "__DWARF", 1,
                     MachOSection::S_REGULAR | MachOSection::S_ATTR_DEBUG),
#endif
        desc_(desc) {
  }

  // DWARF2 standard, figure 14.
  enum DWARF2Tags {
    DW_TAG_FORMAL_PARAMETER = 0x05,
    DW_TAG_POINTER_TYPE = 0xF,
    DW_TAG_COMPILE_UNIT = 0x11,
    DW_TAG_STRUCTURE_TYPE = 0x13,
    DW_TAG_BASE_TYPE = 0x24,
    DW_TAG_SUBPROGRAM = 0x2E,
    DW_TAG_VARIABLE = 0x34
  };

  // DWARF2 standard, figure 16.
  enum DWARF2ChildrenDetermination { DW_CHILDREN_NO = 0, DW_CHILDREN_YES = 1 };

  // DWARF standard, figure 17.
  enum DWARF2Attribute {
    DW_AT_LOCATION = 0x2,
    DW_AT_NAME = 0x3,
    DW_AT_BYTE_SIZE = 0xB,
    DW_AT_STMT_LIST = 0x10,
    DW_AT_LOW_PC = 0x11,
    DW_AT_HIGH_PC = 0x12,
    DW_AT_ENCODING = 0x3E,
    DW_AT_FRAME_BASE = 0x40,
    DW_AT_TYPE = 0x49
  };

  // DWARF2 standard, figure 19.
  enum DWARF2AttributeForm {
    DW_FORM_ADDR = 0x1,
    DW_FORM_BLOCK4 = 0x4,
    DW_FORM_STRING = 0x8,
    DW_FORM_DATA4 = 0x6,
    DW_FORM_BLOCK = 0x9,
    DW_FORM_DATA1 = 0xB,
    DW_FORM_FLAG = 0xC,
    DW_FORM_REF4 = 0x13
  };

  void WriteVariableAbbreviation(Writer* w, int abbreviation_code,
                                 bool has_value, bool is_parameter) {
    w->WriteULEB128(abbreviation_code);
    w->WriteULEB128(is_parameter ? DW_TAG_FORMAL_PARAMETER : DW_TAG_VARIABLE);
    w->Write<uint8_t>(DW_CHILDREN_NO);
    w->WriteULEB128(DW_AT_NAME);
    w->WriteULEB128(DW_FORM_STRING);
    if (has_value) {
      w->WriteULEB128(DW_AT_TYPE);
      w->WriteULEB128(DW_FORM_REF4);
      w->WriteULEB128(DW_AT_LOCATION);
      w->WriteULEB128(DW_FORM_BLOCK4);
    }
    w->WriteULEB128(0);
    w->WriteULEB128(0);
  }

  bool WriteBodyInternal(Writer* w) override {
    int current_abbreviation = 1;
    bool extra_info = desc_->has_scope_info();
    DCHECK(desc_->IsLineInfoAvailable());
    w->WriteULEB128(current_abbreviation++);
    w->WriteULEB128(DW_TAG_COMPILE_UNIT);
    w->Write<uint8_t>(extra_info ? DW_CHILDREN_YES : DW_CHILDREN_NO);
    w->WriteULEB128(DW_AT_NAME);
    w->WriteULEB128(DW_FORM_STRING);
    w->WriteULEB128(DW_AT_LOW_PC);
    w->WriteULEB128(DW_FORM_ADDR);
    w->WriteULEB128(DW_AT_HIGH_PC);
    w->WriteULEB128(DW_FORM_ADDR);
    w->WriteULEB128(DW_AT_STMT_LIST);
    w->WriteULEB128(DW_FORM_DATA4);
    w->WriteULEB128(0);
    w->WriteULEB128(0);

    if (extra_info) {
      Tagged<ScopeInfo> scope = desc_->scope_info();
      int params = scope->ParameterCount();
      int context_slots = scope->ContextLocalCount();
      // The real slot ID is internal_slots + context_slot_id.
      int internal_slots = Context::MIN_CONTEXT_SLOTS;
      // Total children is params + context_slots + internal_slots + 2
      // (__function and __context).

      // The extra duplication below seems to be necessary to keep
      // gdb from getting upset on OSX.
      w->WriteULEB128(current_abbreviation++);  // Abbreviation code.
      w->WriteULEB128(DW_TAG_SUBPROGRAM);
      w->Write<uint8_t>(DW_CHILDREN_YES);
      w->WriteULEB128(DW_AT_NAME);
      w->WriteULEB128(DW_FORM_STRING);
      w->WriteULEB128(DW_AT_LOW_PC);
      w->WriteULEB128(DW_FORM_ADDR);
      w->WriteULEB128(DW_AT_HIGH_PC);
      w->WriteULEB128(DW_FORM_ADDR);
      w->WriteULEB128(DW_AT_FRAME_BASE);
      w->WriteULEB128(DW_FORM_BLOCK4);
      w->WriteULEB128(0);
      w->WriteULEB128(0);

      w->WriteULEB128(current_abbreviation++);
      w->WriteULEB128(DW_TAG_STRUCTURE_TYPE);
      w->Write<uint8_t>(DW_CHILDREN_NO);
      w->WriteULEB128(DW_AT_BYTE_SIZE);
      w->WriteULEB128(DW_FORM_DATA1);
      w->WriteULEB128(DW_AT_NAME);
      w->WriteULEB128(DW_FORM_STRING);
      w->WriteULEB128(0);
      w->WriteULEB128(0);

      for (int param = 0; param < params; ++param) {
        WriteVariableAbbreviation(w, current_abbreviation++, true, true);
      }

      for (int internal_slot = 0; internal_slot < internal_slots;
           ++internal_slot) {
        WriteVariableAbbreviation(w, current_abbreviation++, false, false);
      }

      for (int context_slot = 0; context_slot < context_slots; ++context_slot) {
        WriteVariableAbbreviation(w, current_abbreviation++, false, false);
      }

      // The function.
      WriteVariableAbbreviation(w, current_abbreviation++, true, false);

      // The context.
      WriteVariableAbbreviation(w, current_abbreviation++, true, false);

      w->WriteULEB128(0);  // Terminate the sibling list.
    }

    w->WriteULEB128(0);  // Terminate the table.
    return true;
  }

 private:
  CodeDescription* desc_;
};

class DebugLineSection : public DebugSection {
 public:
  explicit DebugLineSection(CodeDescription* desc)
#ifdef __ELF
      : ELFSection(".debug_line", TYPE_PROGBITS, 1),
#else
      : MachOSection("__debug_line", "__DWARF", 1,
                     MachOSection::S_REGULAR | MachOSection::S_ATTR_DEBUG),
#endif
        desc_(desc) {
  }

  // DWARF2 standard, figure 34.
  enum DWARF2Opcodes {
    DW_LNS_COPY = 1,
    DW_LNS_ADVANCE_PC = 2,
    DW_LNS_ADVANCE_LINE = 3,
    DW_LNS_SET_FILE = 4,
    DW_LNS_SET_COLUMN = 5,
    DW_LNS_NEGATE_STMT = 6
  };

  // DWARF2 standard, figure 35.
  enum DWARF2ExtendedOpcode {
    DW_LNE_END_SEQUENCE = 1,
    DW_LNE_SET_ADDRESS = 2,
    DW_LNE_DEFINE_FILE = 3
  };

  bool WriteBodyInternal(Writer* w) override {
    // Write prologue.
    Writer::Slot<uint32_t> total_length = w->CreateSlotHere<uint32_t>();
    uintptr_t start = w->position();

    // Used for special opcodes
    const int8_t line_base = 1;
    const uint8_t line_range = 7;
    const int8_t max_line_incr = (line_base + line_range - 1);
    const uint8_t opcode_base = DW_LNS_NEGATE_STMT + 1;

    w->Write<uint16_t>(2);  // Field version.
    Writer::Slot<uint32_t> prologue_length = w->CreateSlotHere<uint32_t>();
    uintptr_t prologue_start = w->position();
    w->Write<uint8_t>(1);            // Field minimum_instruction_length.
    w->Write<uint8_t>(1);            // Field default_is_stmt.
    w->Write<int8_t>(line_base);     // Field line_base.
    w->Write<uint8_t>(line_range);   // Field line_range.
    w->Write<uint8_t>(opcode_base);  // Field opcode_base.
    w->Write<uint8_t>(0);            // DW_LNS_COPY operands count.
    w->Write<uint8_t>(1);            // DW_LNS_ADVANCE_PC operands count.
    w->Write<uint8_t>(1);            // DW_LNS_ADVANCE_LINE operands count.
    w->Write<uint8_t>(1);            // DW_LNS_SET_FILE operands count.
    w->Write<uint8_t>(1);            // DW_LNS_SET_COLUMN operands count.
    w->Write<uint8_t>(0);            // DW_LNS_NEGATE_STMT operands count.
    w->Write<uint8_t>(0);            // Empty include_directories sequence.
    w->WriteString(desc_->GetFilename().get());  // File name.
    w->WriteULEB128(0);                          // Current directory.
    w->WriteULEB128(0);                          // Unknown modification time.
    w->WriteULEB128(0);                          // Unknown file size.
    w->Write<uint8_t>(0);
    prologue_length.set(static_cast<uint32_t>(w->position() - prologue_start));

    WriteExtendedOpcode(w, DW_LNE_SET_ADDRESS, sizeof(intptr_t));
    w->Write<intptr_t>(desc_->CodeStart());
    w->Write<uint8_t>(DW_LNS_COPY);

    intptr_t pc = 0;
    intptr_t line = 1;
    bool is_statement = true;

    std::vector<LineInfo::PCInfo>* pc_info = desc_->lineinfo()->pc_info();
    std::sort(pc_info->begin(), pc_info->end(), &ComparePCInfo);

    for (size_t i = 0; i < pc_info->size(); i++) {
      LineInfo::PCInfo* info = &pc_info->at(i);
      DCHECK(info->pc_ >= pc);

      // Reduce bloating in the debug line table by removing duplicate line
      // entries (per DWARF2 standard).
      intptr_t new_line = desc_->GetScriptLineNumber(info->pos_);
      if (new_line == line) {
        continue;
      }

      // Mark statement boundaries.  For a better debugging experience, mark
      // the last pc address in the function as a statement (e.g. "}"), so that
      // a user can see the result of the last line executed in the function,
      // should control reach the end.
      if ((i + 1) == pc_info->size()) {
        if (!is_statement) {
          w->Write<uint8_t>(DW_LNS_NEGATE_STMT);
        }
      } else if (is_statement != info->is_statement_) {
        w->Write<uint8_t>(DW_LNS_NEGATE_STMT);
        is_statement = !is_statement;
      }

      // Generate special opcodes, if possible.  This results in more compact
      // debug line tables.  See the DWARF 2.0 standard to learn more about
      // special opcodes.
      uintptr_t pc_diff = info->pc_ - pc;
      intptr_t line_diff = new_line - line;

      // Compute special opcode (see DWARF 2.0 standard)
      intptr_t special_opcode =
          (line_diff - line_base) + (line_range * pc_diff) + opcode_base;

      // If special_opcode is less than or equal to 255, it can be used as a
      // special opcode.  If line_diff is larger than the max line increment
      // allowed for a special opcode, or if line_diff is less than the minimum
      // line that can be added to the line register (i.e. line_base), then
      // special_opcode can't be used.
      if ((special_opcode >= opcode_base) && (special_opcode <= 255) &&
          (line_diff <= max_line_incr) && (line_diff >= line_base)) {
        w->Write<uint8_t>(special_opcode);
      } else {
        w->Write<uint8_t>(DW_LNS_ADVANCE_PC);
        w->WriteSLEB128(pc_diff);
        w->Write<uint8_t>(DW_LNS_ADVANCE_LINE);
        w->WriteSLEB128(line_diff);
        w->Write<uint8_t>(DW_LNS_COPY);
      }

      // Increment the pc and line operands.
      pc += pc_diff;
      line += line_diff;
    }
    // Advance the pc to the end of the routine, since the end sequence opcode
    // requires this.
    w->Write<uint8_t>(DW_LNS_ADVANCE_PC);
    w->WriteSLEB128(desc_->CodeSize() - pc);
    WriteExtendedOpcode(w, DW_LNE_END_SEQUENCE, 0);
    total_length.set(static_cast<uint32_t>(w->position() - start));
    return true;
  }

 private:
  void WriteExtendedOpcode(Writer* w, DWARF2ExtendedOpcode op,
                           size_t operands_size) {
    w->Write<uint8_t>(0);
    w->WriteULEB128(operands_size + 1);
    w->Write<uint8_t>(op);
  }

  static bool ComparePCInfo(const LineInfo::PCInfo& a,
                            const LineInfo::PCInfo& b) {
    if (a.pc_ == b.pc_) {
      if (a.is_statement_ != b.is_statement_) {
        return !b.is_statement_;
      }
      return false;
    }
    return a.pc_ < b.pc_;
  }

  CodeDescription* desc_;
};

#if V8_TARGET_ARCH_X64

class UnwindInfoSection : public DebugSection {
 public:
  explicit UnwindInfoSection(CodeDescription* desc);
  bool WriteBodyInternal(Writer* w) override;

  int WriteCIE(Writer* w);
  void WriteFDE(Writer* w, int);

  void WriteFDEStateOnEntry(Writer* w);
  void WriteFDEStateAfterRBPPush(Writer* w);
  void WriteFDEStateAfterRBPSet(Writer* w);
  void WriteFDEStateAfterRBPPop(Writer* w);

  void WriteLength(Writer* w, Writer::Slot<uint32_t>* length_slot,
                   int initial_position);

 private:
  CodeDescription* desc_;

  // DWARF3 Specification, Table 7.23
  enum CFIInstructions {
    DW_CFA_ADVANCE_LOC = 0x40,
    DW_CFA_OFFSET = 0x80,
    DW_CFA_RESTORE = 0xC0,
    DW_CFA_NOP = 0x00,
    DW_CFA_SET_LOC = 0x01,
    DW_CFA_ADVANCE_LOC1 = 0x02,
    DW_CFA_ADVANCE_LOC2 = 0x03,
    DW_CFA_ADVANCE_LOC4 = 0x04,
    DW_CFA_OFFSET_EXTENDED = 0x05,
    DW_CFA_RESTORE_EXTENDED = 0x06,
    DW_CFA_UNDEFINED = 0x07,
    DW_CFA_SAME_VALUE = 0x08,
    DW_CFA_REGISTER = 0x09,
    DW_CFA_REMEMBER_STATE = 0x0A,
    DW_CFA_RESTORE_STATE = 0x0B,
    DW_CFA_DEF_CFA = 0x0C,
    DW_CFA_DEF_CFA_REGISTER = 0x0D,
    DW_CFA_DEF_CFA_OFFSET = 0x0E,

    DW_CFA_DEF_CFA_EXPRESSION = 0x0F,
    DW_CFA_EXPRESSION = 0x10,
    DW_CFA_OFFSET_EXTENDED_SF = 0x11,
    DW_CFA_DEF_CFA_SF = 0x12,
    DW_CFA_DEF_CFA_OFFSET_SF = 0x13,
    DW_CFA_VAL_OFFSET = 0x14,
    DW_CFA_VAL_OFFSET_SF = 0x15,
    DW_CFA_VAL_EXPRESSION = 0x16
  };

  // System V ABI, AMD64 Supplement, Version 0.99.5, Figure 3.36
  enum RegisterMapping {
    // Only the relevant ones have been added to reduce clutter.
    AMD64_RBP = 6,
    AMD64_RSP = 7,
    AMD64_RA = 16
  };

  enum CFIConstants {
    CIE_ID = 0,
    CIE_VERSION = 1,
    CODE_ALIGN_FACTOR = 1,
    DATA_ALIGN_FACTOR = 1,
    RETURN_ADDRESS_REGISTER = AMD64_RA
  };
};

void UnwindInfoSection::WriteLength(Writer* w,
                                    Writer::Slot<uint32_t>* length_slot,
                                    int initial_position) {
  uint32_t align = (w->position() - initial_position) % kSystemPointerSize;

  if (align != 0) {
    for (uint32_t i = 0; i < (kSystemPointerSize - align); i++) {
      w->Write<uint8_t>(DW_CFA_NOP);
    }
  }

  DCHECK_EQ((w->position() - initial_position) % kSystemPointerSize, 0);
  length_slot->set(static_cast<uint32_t>(w->position() - initial_position));
}

UnwindInfoSection::UnwindInfoSection(CodeDescription* desc)
#ifdef __ELF
    : ELFSection(".eh_frame", TYPE_X86_64_UNWIND, 1),
#else
    : MachOSection("__eh_frame", "__TEXT", sizeof(uintptr_t),
                   MachOSection::S_REGULAR),
#endif
      desc_(desc) {
}

int UnwindInfoSection::WriteCIE(Writer* w) {
  Writer::Slot<uint32_t> cie_length_slot = w->CreateSlotHere<uint32_t>();
  uint32_t cie_position = static_cast<uint32_t>(w->position());

  // Write out the CIE header. Currently no 'common instructions' are
  // emitted onto the CIE; every FDE has its own set of instructions.

  w->Write<uint32_t>(CIE_ID);
  w->Write<uint8_t>(CIE_VERSION);
  w->Write<uint8_t>(0);  // Null augmentation string.
  w->WriteSLEB128(CODE_ALIGN_FACTOR);
  w->WriteSLEB128(DATA_ALIGN_FACTOR);
  w->Write<uint8_t>(RETURN_ADDRESS_REGISTER);

  WriteLength(w, &cie_length_slot, cie_position);

  return cie_position;
}

void UnwindInfoSection::WriteFDE(Writer* w, int cie_position) {
  // The only FDE for this function. The CFA is the current RBP.
  Writer::Slot<uint32_t> fde_length_slot = w->CreateSlotHere<uint32_t>();
  int fde_position = static_cast<uint32_t>(w->position());
  w->Write<int32_t>(fde_position - cie_position + 4);

  w->Write<uintptr_t>(desc_->CodeStart());
  w->Write<uintptr_t>(desc_->CodeSize());

  WriteFDEStateOnEntry(w);
  WriteFDEStateAfterRBPPush(w);
  WriteFDEStateAfterRBPSet(w);
  WriteFDEStateAfterRBPPop(w);

  WriteLength(w, &fde_length_slot, fde_position);
}

void UnwindInfoSection::WriteFDEStateOnEntry(Writer* w) {
  // The first state, just after the control has been transferred to the the
  // function.

  // RBP for this function will be the value of RSP after pushing the RBP
  // for the previous function. The previous RBP has not been pushed yet.
  w->Write<uint8_t>(DW_CFA_DEF_CFA_SF);
  w->WriteULEB128(AMD64_RSP);
  w->WriteSLEB128(-kSystemPointerSize);

  // The RA is stored at location CFA + kCallerPCOffset. This is an invariant,
  // and hence omitted from the next states.
  w->Write<uint8_t>(DW_CFA_OFFSET_EXTENDED);
  w->WriteULEB128(AMD64_RA);
  w->WriteSLEB128(StandardFrameConstants::kCallerPCOffset);

  // The RBP of the previous function is still in RBP.
  w->Write<uint8_t>(DW_CFA_SAME_VALUE);
  w->WriteULEB128(AMD64_RBP);

  // Last location described by this entry.
  w->Write<uint8_t>(DW_CFA_SET_LOC);
  w->Write<uint64_t>(
      desc_->GetStackStateStartAddress(CodeDescription::POST_RBP_PUSH));
}

void UnwindInfoSection::WriteFDEStateAfterRBPPush(Writer* w) {
  // The second state, just after RBP has been pushed.

  // RBP / CFA for this function is now the current RSP, so just set the
  // offset from the previous rule (from -8) to 0.
  w->Write<uint8_t>(DW_CFA_DEF_CFA_OFFSET);
  w->WriteULEB128(0);

  // The previous RBP is stored at CFA + kCallerFPOffset. This is an invariant
  // in this and the next state, and hence omitted in the next state.
  w->Write<uint8_t>(DW_CFA_OFFSET_EXTENDED);
  w->WriteULEB128(AMD64_RBP);
  w->WriteSLEB128(StandardFrameConstants::kCallerFPOffset);

  // Last location described by this entry.
  w->Write<uint8_t>(DW_CFA_SET_LOC);
  w->Write<uint64_t>(
      desc_->GetStackStateStartAddress(CodeDescription::POST_RBP_SET));
}

void UnwindInfoSection::WriteFDEStateAfterRBPSet(Writer* w) {
  // The third state, after the RBP has been set.

  // The CFA can now directly be set to RBP.
  w->Write<uint8_t>(DW_CFA_DEF_CFA);
  w->WriteULEB128(AMD64_RBP);
  w->WriteULEB128(0);

  // Last location described by this entry.
  w->Write<uint8_t>(DW_CFA_SET_LOC);
  w->Write<uint64_t>(
      desc_->GetStackStateStartAddress(CodeDescription::POST_RBP_POP));
}

void UnwindInfoSection::WriteFDEStateAfterRBPPop(Writer* w) {
  // The fourth (final) state. The RBP has been popped (just before issuing a
  // return).

  // The CFA can is now calculated in the same way as in the first state.
  w->Write<uint8_t>(DW_CFA_DEF_CFA_SF);
  w->WriteULEB128(AMD64_RSP);
  w->WriteSLEB128(-kSystemPointerSize);

  // The RBP
  w->Write<uint8_t>(DW_CFA_OFFSET_EXTENDED);
  w->WriteULEB128(AMD64_RBP);
  w->WriteSLEB128(StandardFrameConstants::kCallerFPOffset);

  // Last location described by this entry.
  w->Write<uint8_t>(DW_CFA_SET_LOC);
  w->Write<uint64_t>(desc_->CodeEnd());
}

bool UnwindInfoSection::WriteBodyInternal(Writer* w) {
  uint32_t cie_position = WriteCIE(w);
  WriteFDE(w, cie_position);
  return true;
}

#endif  // V8_TARGET_ARCH_X64

static void CreateDWARFSections(CodeDescription* desc, Zone* zone,
                                DebugObject* obj) {
  if (desc->IsLineInfoAvailable()) {
    obj->AddSection(zone->New<DebugInfoSection>(desc));
    obj->AddSection(zone->New<DebugAbbrevSection>(desc));
    obj->AddSection(zone->New<DebugLineSection>(desc));
  }
#if V8_TARGET_ARCH_X64
  obj->AddSection(zone->New<UnwindInfoSection>(desc));
#endif
}

// -------------------------------------------------------------------
// Binary GDB JIT Interface as described in
//   http://sourceware.org/gdb/onlinedocs/gdb/Declarations.html
extern "C" {
enum JITAction { JIT_NOACTION = 0, JIT_REGISTER_FN, JIT_UNREGISTER_FN };

struct JITCodeEntry {
  JITCodeEntry* next_;
  JITCodeEntry* prev_;
  Address symfile_addr_;
  uint64_t symfile_size_;
};

struct JITDescriptor {
  uint32_t version_;
  uint32_t action_flag_;
  JITCodeEntry* relevant_entry_;
  JITCodeEntry* first_entry_;
};

// GDB will place breakpoint into this function.
// To prevent GCC from inlining or removing it we place noinline attribute
// and inline assembler statement inside.
void __attribute__((noinline)) __jit_debug_register_code() { __asm__(""); }

// GDB will inspect contents of this descriptor.
// Static initialization is necessary to prevent GDB from seeing
// uninitialized descriptor.
JITDescriptor __jit_debug_descriptor = {1, 0, nullptr, nullptr};

#ifdef OBJECT_PRINT
void __gdb_print_v8_object(TaggedBase object) {
  StdoutStream os;
  Print(object, os);
  os << std::flush;
}
#endif
}

static JITCodeEntry* CreateCodeEntry(Address symfile_addr,
                                     uintptr_t symfile_size) {
  JITCodeEntry* entry = static_cast<JITCodeEntry*>(
      base::Malloc(sizeof(JITCodeEntry) + symfile_size));

  entry->symfile_addr_ = reinterpret_cast<Address>(entry + 1);
  entry->symfile_size_ = symfile_size;
  MemCopy(reinterpret_cast<void*>(entry->symfile_addr_),
          reinterpret_cast<void*>(symfile_addr), symfile_size);

  entry->prev_ = entry->next_ = nullptr;

  return entry;
}

static void DestroyCodeEntry(JITCodeEntry* entry) { base::Free(entry); }

static void RegisterCodeEntry(JITCodeEntry* entry) {
  entry->next_ = __jit_debug_descriptor.first_entry_;
  if (entry->next_ != nullptr) entry->next_->prev_ = entry;
  __jit_debug_descriptor.first_entry_ = __jit_debug_descriptor.relevant_entry_ =
      entry;

  __jit_debug_descriptor.action_flag_ = JIT_REGISTER_FN;
  __jit_debug_register_code();
}

static void UnregisterCodeEntry(JITCodeEntry* entry) {
  if (entry->prev_ != nullptr) {
    entry->prev_->next_ = entry->next_;
  } else {
    __jit_debug_descriptor.first_entry_ = entry->next_;
  }

  if (entry->next_ != nullptr) {
    entry->next_->prev_ = entry->prev_;
  }

  __jit_debug_descriptor.relevant_entry_ = entry;
  __jit_debug_descriptor.action_flag_ = JIT_UNREGISTER_FN;
  __jit_debug_register_code();
}

static JITCodeEntry* CreateELFObject(CodeDescription* desc, Isolate* isolate) {
#ifdef __MACH_O
  Zone zone(isolate->allocator(), ZONE_NAME);
  MachO mach_o(&zone);
  Writer w(&mach_o);

  const uint32_t code_alignment = static_cast<uint32_t>(kCodeAlignment);
  static_assert(code_alignment == kCodeAlignment,
                "Unsupported code alignment value");
  mach_o.AddSection(zone.New<MachOTextSection>(
      code_alignment, desc->CodeStart(), desc->CodeSize()));

  CreateDWARFSections(desc, &zone, &mach_o);

  mach_o.Write(&w, desc->CodeStart(), desc->CodeSize());
#else
  Zone zone(isolate->allocator(), ZONE_NAME);
  ELF elf(&zone);
  Writer w(&elf);

  size_t text_section_index = elf.AddSection(zone.New<FullHeaderELFSection>(
      ".text", ELFSection::TYPE_NOBITS, kCodeAlignment, desc->CodeStart(), 0,
      desc->CodeSize(), ELFSection::FLAG_ALLOC | ELFSection::FLAG_EXEC));

  CreateSymbolsTable(desc, &zone, &elf, text_section_index);

  CreateDWARFSections(desc, &zone, &elf);

  elf.Write(&w);
#endif

  return CreateCodeEntry(reinterpret_cast<Address>(w.buffer()), w.position());
}

// Like base::AddressRegion::StartAddressLess but also compares |end| when
// |begin| is equal.
struct AddressRegionLess {
  bool operator()(const base::AddressRegion& a,
                  const base::AddressRegion& b) const {
    if (a.begin() == b.begin()) return a.end() < b.end();
    return a.begin() < b.begin();
  }
};

using CodeMap = std::map<base::AddressRegion, JITCodeEntry*, AddressRegionLess>;

static CodeMap* GetCodeMap() {
  // TODO(jgruber): Don't leak.
  static CodeMap* code_map = nullptr;
  if (code_map == nullptr) code_map = new CodeMap();
  return code_map;
}

static uint32_t HashCodeAddress(Address addr) {
  static const uintptr_t kGoldenRatio = 2654435761u;
  return static_cast<uint32_t>((addr >> kCodeAlignmentBits) * kGoldenRatio);
}

static base::HashMap* GetLineMap() {
  static base::HashMap* line_map = nullptr;
  if (line_map == nullptr) {
    line_map = new base::HashMap();
  }
  return line_map;
}

static void PutLineInfo(Address addr, LineInfo* info) {
  base::HashMap* line_map = GetLineMap();
  base::HashMap::Entry* e = line_map->LookupOrInsert(
      reinterpret_cast<void*>(addr), HashCodeAddress(addr));
  if (e->value != nullptr) delete static_cast<LineInfo*>(e->value);
  e->value = info;
}

static LineInfo* GetLineInfo(Address addr) {
  void* value = GetLineMap()->Remove(reinterpret_cast<void*>(addr),
                                     HashCodeAddress(addr));
  return static_cast<LineInfo*>(value);
}

static void AddUnwindInfo(CodeDescription* desc) {
#if V8_TARGET_ARCH_X64
  if (desc->is_function()) {
    // To avoid propagating unwinding information through
    // compilation pipeline we use an approximation.
    // For most use cases this should not affect usability.
    static const int kFramePointerPushOffset = 1;
    static const int kFramePointerSetOffset = 4;
    static const int kFramePointerPopOffset = -3;

    uintptr_t frame_pointer_push_address =
        desc->CodeStart() + kFramePointerPushOffset;

    uintptr_t frame_pointer_set_address =
        desc->CodeStart() + kFramePointerSetOffset;

    uintptr_t frame_pointer_pop_address =
        desc->CodeEnd() + kFramePointerPopOffset;

    desc->SetStackStateStartAddress(CodeDescription::POST_RBP_PUSH,
                                    frame_pointer_push_address);
    desc->SetStackStateStartAddress(CodeDescription::POST_RBP_SET,
                                    frame_pointer_set_address);
    desc->SetStackStateStartAddress(CodeDescription::POST_RBP_POP,
                                    frame_pointer_pop_address);
  } else {
    desc->SetStackStateStartAddress(CodeDescription::POST_RBP_PUSH,
                                    desc->CodeStart());
    desc->SetStackStateStartAddress(CodeDescription::POST_RBP_SET,
                                    desc->CodeStart());
    desc->SetStackStateStartAddress(CodeDescription::POST_RBP_POP,
                                    desc->CodeEnd());
  }
#endif  // V8_TARGET_ARCH_X64
}

static base::LazyMutex mutex = LAZY_MUTEX_INITIALIZER;

static std::optional<std::pair<CodeMap::iterator, CodeMap::iterator>>
GetOverlappingRegions(CodeMap* map, const base::AddressRegion region) {
  DCHECK_LT(region.begin(), region.end());

  if (map->empty()) return {};

  // Find the first overlapping entry.

  // If successful, points to the first element not less than `region`. The
  // returned iterator has the key in `first` and the value in `second`.
  auto it = map->lower_bound(region);
  auto start_it = it;

  if (it == map->end()) {
    start_it = map->begin();
    // Find the first overlapping entry.
    for (; start_it != map->end(); ++start_it) {
      if (start_it->first.end() > region.begin()) {
        break;
      }
    }
  } else if (it != map->begin()) {
    for (--it; it != map->begin(); --it) {
      if ((*it).first.end() <= region.begin()) break;
      start_it = it;
    }
    if (it == map->begin() && it->first.end() > region.begin()) {
      start_it = it;
    }
  }

  if (start_it == map->end()) {
    return {};
  }

  // Find the first non-overlapping entry after `region`.

  const auto end_it = map->lower_bound({region.end(), 0});

  // Return a range containing intersecting regions.

  if (std::distance(start_it, end_it) < 1)
    return {};  // No overlapping entries.

  return {{start_it, end_it}};
}

// Remove entries from the map that intersect the given address region,
// and deregister them from GDB.
static void RemoveJITCodeEntries(CodeMap* map,
                                 const base::AddressRegion region) {
  if (auto overlap = GetOverlappingRegions(map, region)) {
    auto start_it = overlap->first;
    auto end_it = overlap->second;
    for (auto it = start_it; it != end_it; it++) {
      JITCodeEntry* old_entry = (*it).second;
      UnregisterCodeEntry(old_entry);
      DestroyCodeEntry(old_entry);
    }

    map->erase(start_it, end_it);
  }
}

// Insert the entry into the map and register it with GDB.
static void AddJITCodeEntry(CodeMap* map, const base::AddressRegion region,
                            JITCodeEntry* entry, bool dump_if_enabled,
                            const char* name_hint) {
#if defined(DEBUG) && !V8_OS_WIN
  static int file_num = 0;
  if (v8_flags.gdbjit_dump && dump_if_enabled) {
    static const int kMaxFileNameSize = 64;
    char file_name[64];

    SNPrintF(base::Vector<char>(file_name, kMaxFileNameSize),
             "/tmp/elfdump%s%d.o", (name_hint != nullptr) ? name_hint : "",
             file_num++);
    WriteBytes(file_name, reinterpret_cast<uint8_t*>(entry->symfile_addr_),
               static_cast<int>(entry->symfile_size_));
  }
#endif

  auto result = map->emplace(region, entry);
  DCHECK(result.second);  // Insertion happened.
  USE(result);

  RegisterCodeEntry(entry);
}

static void AddCode(const char* name, base::AddressRegion region,
                    Tagged<SharedFunctionInfo> shared, LineInfo* lineinfo,
                    Isolate* isolate, bool is_function) {
  DisallowGarbageCollection no_gc;
  CodeDescription code_desc(name, region, shared, lineinfo, is_function);

  CodeMap* code_map = GetCodeMap();
  RemoveJITCodeEntries(code_map, region);

  if (!v8_flags.gdbjit_full && !code_desc.IsLineInfoAvailable()) {
    delete lineinfo;
    return;
  }

  AddUnwindInfo(&code_desc);
  JITCodeEntry* entry = CreateELFObject(&code_desc, isolate);

  delete lineinfo;

  const char* name_hint = nullptr;
  bool should_dump = false;
  if (v8_flags.gdbjit_dump) {
    if (strlen(v8_flags.gdbjit_dump_filter) == 0) {
      name_hint = name;
      should_dump = true;
    } else if (name != nullptr) {
      name_hint = strstr(name, v8_flags.gdbjit_dump_filter);
      should_dump = (name_hint != nullptr);
    }
  }
  AddJITCodeEntry(code_map, region, entry, should_dump, name_hint);
}

void EventHandler(const v8::JitCodeEvent* event) {
  if (!v8_flags.gdbjit) return;
  if ((event->code_type != v8::JitCodeEvent::JIT_CODE) &&
      (event->code_type != v8::JitCodeEvent::WASM_CODE)) {
    return;
  }
  base::MutexGuard lock_guard(mutex.Pointer());
  switch (event->type) {
    case v8::JitCodeEvent::CODE_ADDED: {
      Address addr = reinterpret_cast<Address>(event->code_start);
      LineInfo* lineinfo = GetLineInfo(addr);
      std::string event_name(event->name.str, event->name.len);
      // It's called UnboundScript in the API but it's a SharedFunctionInfo.
      Tagged<SharedFunctionInfo> shared =
          event->script.IsEmpty() ? Tagged<SharedFunctionInfo>()
                                  : *Utils::OpenDirectHandle(*event->script);
      Isolate* isolate = reinterpret_cast<Isolate*>(event->isolate);
      bool is_function = false;
      // TODO(zhin): See if we can use event->code_type to determine
      // is_function, the difference currently is that JIT_CODE is SparkPlug,
      // TurboProp, TurboFan, whereas CodeKindIsOptimizedJSFunction is only
      // TurboProp and TurboFan. is_function is used for AddUnwindInfo, and the
      // prologue that SP generates probably matches that of TP/TF, so we can
      // use event->code_type here instead of finding the Code.
      // TODO(zhin): Rename is_function to be more accurate.
      if (event->code_type == v8::JitCodeEvent::JIT_CODE) {
        Tagged<Code> lookup_result =
            isolate->heap()->FindCodeForInnerPointer(addr);
        is_function = CodeKindIsOptimizedJSFunction(lookup_result->kind());
      }
      AddCode(event_name.c_str(), {addr, event->code_len}, shared, lineinfo,
              isolate, is_function);
      break;
    }
    case v8::JitCodeEvent::CODE_MOVED:
      // Enabling the GDB JIT interface should disable code compaction.
      UNREACHABLE();
    case v8::JitCodeEvent::CODE_REMOVED:
      // Do nothing.  Instead, adding code causes eviction of any entry whose
      // address range intersects the address range of the added code.
      break;
    case v8::JitCodeEvent::CODE_ADD_LINE_POS_INFO: {
      LineInfo* line_info = reinterpret_cast<LineInfo*>(event->user_data);
      line_info->SetPosition(static_cast<intptr_t>(event->line_info.offset),
                             static_cast<int>(event->line_info.pos),
                             event->line_info.position_type ==
                                 v8::JitCodeEvent::STATEMENT_POSITION);
      break;
    }
    case v8::JitCodeEvent::CODE_START_LINE_INFO_RECORDING: {
      v8::JitCodeEvent* mutable_event = const_cast<v8::JitCodeEvent*>(event);
      mutable_event->user_data = new LineInfo();
      break;
    }
    case v8::JitCodeEvent::CODE_END_LINE_INFO_RECORDING: {
      LineInfo* line_info = reinterpret_cast<LineInfo*>(event->user_data);
      PutLineInfo(reinterpret_cast<Address>(event->code_start), line_info);
      break;
    }
  }
}

void AddRegionForTesting(const base::AddressRegion region) {
  // For testing purposes we don't care about JITCodeEntry, pass nullptr.
  auto result = GetCodeMap()->emplace(region, nullptr);
  DCHECK(result.second);  // Insertion happened.
  USE(result);
}

void ClearCodeMapForTesting() { GetCodeMap()->clear(); }

size_t NumOverlapEntriesForTesting(const base::AddressRegion region) {
  if (auto overlaps = GetOverlappingRegions(GetCodeMap(), region)) {
    return std::distance(overlaps->first, overlaps->second);
  }
  return 0;
}

#endif
}  // namespace GDBJITInterface
}  // namespace internal
}  // namespace v8

#undef __MACH_O
#undef __ELF
```