Response:
Let's break down the thought process for analyzing the C++ code and generating the explanation.

1. **Understand the Goal:** The request is to analyze a C++ source file (`safepoint-table.cc`) and describe its functionality, its relation to JavaScript (if any), provide examples, and discuss potential programming errors.

2. **Initial Code Scan and Keyword Identification:** Read through the code, looking for key terms and patterns. Terms like "Safepoint," "Table," "PC," "stack," "registers," "deoptimization," "assembler," and "bytecode" stand out. The `#include` directives reveal dependencies on other V8 components.

3. **Identify the Core Concept: Safepoints:** The name of the file itself, `safepoint-table.cc`, is a strong indicator of its primary purpose. The code confirms this, with classes named `SafepointTable` and `SafepointTableBuilder`. The term "safepoint" immediately brings to mind the idea of locations in code where the runtime system can safely interrupt execution.

4. **Analyze `SafepointTable`:**
    * **Constructor:** Examine the constructors. They take arguments like `pc` (program counter), `code`, and `instruction_start`. This suggests the table is associated with specific code. The WebAssembly constructor hints at broader applicability beyond just optimized JavaScript code.
    * **Data Members:** Look at the data members initialized in the constructor (`instruction_start_`, `safepoint_table_address_`, `stack_slots_`, `length_`, `entry_configuration_`). These provide clues about the information stored in the table. `stack_slots_` suggests information about the stack frame, `length_` the number of entries, and `entry_configuration_` how entries are structured.
    * **Key Methods:**  Analyze the functions:
        * `find_return_pc`: Seems to find the program counter associated with a return address.
        * `TryFindEntry` and `FindEntry`:  Crucial for locating a safepoint entry based on a given program counter. The "Try" version suggests it might return a null or invalid entry if not found.
        * `Print`:  Used for debugging, showing the table's contents.

5. **Analyze `SafepointTableBuilder`:**
    * **Purpose:** The name "Builder" clearly indicates its role in *creating* the `SafepointTable`.
    * **`DefineSafepoint`:**  This is the primary way to add safepoint information during code generation. It takes an `Assembler` and a `pc_offset`.
    * **`UpdateDeoptimizationInfo`:**  Deoptimization is a key concept in V8. This function links safepoints to deoptimization information.
    * **`Emit`:** This is the crucial method that writes the actual safepoint table data into the generated code. It involves calculating sizes and encoding information efficiently. Pay attention to the data structures written (stack slots, length, configuration, entries, bitmaps).
    * **`RemoveDuplicates`:**  An optimization step to reduce the table size.

6. **Connect to JavaScript:** The code mentions "deoptimization." This is a fundamental concept in JIT compilation. When optimized code makes assumptions that become invalid, the runtime needs to "deoptimize" back to a safer, but slower, execution mode (often interpreted bytecode). Safepoints are essential for this process, allowing the runtime to unwind the stack and restore the necessary state.

7. **Infer Functionality:** Based on the analysis, the core functionality is:
    * **Mapping Code Locations to Runtime State:** The safepoint table maps specific points in the generated machine code to information about the state of the program at that point, particularly regarding stack slots holding references and register contents.
    * **Supporting Deoptimization:**  A crucial part of enabling optimized code execution and handling situations where optimizations are no longer valid.
    * **Garbage Collection Safety:** By identifying stack slots and registers holding object references, the garbage collector can safely operate without accidentally collecting live objects.

8. **Develop Examples:**
    * **JavaScript Triggering Deoptimization:**  Think about common scenarios that lead to deoptimization (e.g., changing object types, exceeding inlining limits). Create a simple JavaScript example that illustrates this.
    * **Conceptual Example of Table Lookup:**  Illustrate how, given a program counter, the `SafepointTable` can be used to find the associated information.

9. **Identify Potential Errors:** Consider how developers might misuse or misunderstand the concepts related to safepoints, even if they don't directly interact with this C++ code. Common errors relate to:
    * **Incorrectly assuming immutability:**  Changing object types after optimization.
    * **Performance issues related to excessive deoptimization:**  Writing code that frequently triggers deoptimization.

10. **Structure the Explanation:** Organize the findings into logical sections as requested: functionality, Torque (check for file extension), JavaScript relation, code logic, and common errors. Use clear and concise language.

11. **Refine and Review:** Read through the explanation, ensuring accuracy and clarity. Double-check assumptions and inferences against the code. Ensure the JavaScript example and the code logic example are easy to understand. Make sure the explanation flows well and addresses all parts of the prompt.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe the table is only for garbage collection.
* **Correction:** The presence of "deoptimization" and "trampoline" strongly suggests a broader role in JIT optimization and runtime management.

* **Initial thought:**  Focus heavily on the bit manipulation in `Emit`.
* **Refinement:** While important for understanding the encoding, the high-level functionality and purpose are more crucial for the explanation requested by the prompt. Don't get bogged down in implementation details unless directly relevant to the user's understanding.

* **Initial thought:**  The JavaScript examples need to directly show how to *access* the safepoint table.
* **Correction:**  Developers generally don't interact with the safepoint table directly. The examples should focus on *triggering* the mechanisms that *use* the safepoint table (like deoptimization).

By following this structured approach, combining code analysis with knowledge of V8 internals, and refining the explanation along the way, we can arrive at a comprehensive and accurate answer to the request.
The C++ source file `v8/src/codegen/safepoint-table.cc` defines the implementation for managing and representing safepoint tables in V8's code generation pipeline. Here's a breakdown of its functionality:

**Core Functionality: Managing Safepoints**

The primary purpose of this file is to define the `SafepointTable` and `SafepointTableBuilder` classes, which are crucial for:

1. **Recording Safepoint Information:**  During code generation (specifically within Turbofan, V8's optimizing compiler), the `SafepointTableBuilder` is used to mark specific points in the generated machine code as "safepoints."

2. **Storing Runtime State at Safepoints:**  At each safepoint, the table records information about the runtime state of the program at that precise instruction. This includes:
   - **Which stack slots hold tagged pointers (references to JavaScript objects).** This is crucial for the garbage collector to identify live objects during collection.
   - **Which registers hold tagged pointers.** Similar to stack slots, this informs the garbage collector about live object references in registers.
   - **Information related to deoptimization.**  If the optimized code needs to be abandoned (deoptimized) due to assumptions becoming invalid, the safepoint table helps in restoring the correct program state. This includes the offset of the "trampoline" code to jump to for deoptimization and an index into the deoptimization data.

3. **Facilitating Garbage Collection:** The garbage collector uses the information in the safepoint table to accurately scan the stack and registers, identifying all live JavaScript objects. This prevents premature collection of objects that are still in use.

4. **Supporting Deoptimization:** When deoptimization is needed, the runtime uses the safepoint table to:
   - Find the correct state to restore (registers and stack).
   - Identify the point in the unoptimized code to resume execution.

**If `v8/src/codegen/safepoint-table.cc` ended with `.tq`:**

If the filename ended in `.tq`, it would indicate that the file is written in **Torque**, V8's domain-specific language for defining built-in functions and compiler intrinsics. Torque code is statically typed and compiles down to C++ code. In this case, the fundamental functionality would likely remain the same (managing safepoints), but the implementation details and syntax would be different, using Torque's specific constructs.

**Relationship with JavaScript and Examples:**

The `SafepointTable` has a direct and crucial relationship with JavaScript execution, although JavaScript developers don't directly interact with it. Here's how:

1. **Garbage Collection:** When the JavaScript engine needs to perform garbage collection, it relies on the safepoint tables of all currently executing optimized code to accurately identify live objects. Without this information, the garbage collector could mistakenly free objects that are still being used, leading to crashes or undefined behavior.

2. **Deoptimization:** When optimized JavaScript code makes assumptions that are later violated (e.g., a variable's type changes unexpectedly), the engine needs to deoptimize back to less optimized code. Safepoint tables are essential for this process, allowing the engine to safely unwind the stack and restore the necessary state.

**JavaScript Example (Conceptual):**

Imagine the following JavaScript code:

```javascript
function add(x, y) {
  return x + y;
}

let a = 5;
let b = 10;
let result = add(a, b); // This might be optimized.

// Later, we might do something that invalidates assumptions:
b = "hello";
let result2 = add(a, b); // Now the optimized version might need to deoptimize.
```

When the first call to `add(a, b)` is executed, V8's optimizing compiler (Turbofan) might generate optimized machine code assuming `x` and `y` are always numbers. The `SafepointTableBuilder` would be used during the compilation of `add` to mark points where it's safe to pause execution for garbage collection or deoptimization.

If, later, we assign the string "hello" to `b`, the assumption made by the optimized code for the second call to `add(a, b)` becomes invalid. At a safepoint, the engine can detect this type change and use the safepoint table to:

- **Identify the location of the tagged values `a` and `b` on the stack or in registers.** This allows the garbage collector to know these are live objects if a GC occurs at this point.
- **Find the deoptimization information associated with this safepoint.** This information tells the engine how to transition back to a less optimized version of `add` (or even the interpreter) where string concatenation is handled correctly.

**Code Logic Inference (Hypothetical Input and Output):**

Let's consider the `TryFindEntry` function.

**Hypothetical Input:**

- `instruction_start_`: The starting address of the code containing the safepoint table (e.g., `0x1000`).
- `length_`: The number of entries in the safepoint table (e.g., `3`).
- Safepoint entries in the table (simplified representation):
    - Entry 0: `pc_offset`: 10, `trampoline_pc`: -1
    - Entry 1: `pc_offset`: 25, `trampoline_pc`: 50
    - Entry 2: `pc_offset`: 40, `trampoline_pc`: -1
- `pc` (the program counter we're looking for): `0x1018`

**Logic:**

1. `pc_offset` is calculated: `0x1018 - 0x1000 = 0x18` (decimal 24).
2. The function iterates through the safepoint entries:
   - **Entry 0:** `entry.pc()` (which is `pc_offset`) is 10. `24 > 10`.
   - **Entry 1:** `entry.pc()` is 25. `24 <= 25`. The condition `GetEntry(i + 1).pc() > pc_offset` is not checked because `i` is not the last entry. However, since `entry.pc()` (25) is greater than `pc_offset` (24), the function checks `if (entry.pc() > pc_offset)`. This condition is true, so it returns an empty `SafepointEntry`.

**Hypothetical Output:**

- An empty `SafepointEntry` (meaning no exact match was found, but the search stopped at the entry whose PC offset was the first one greater than the target PC offset).

**Another Hypothetical Input:**

- `pc`: `0x1028`

**Logic:**

1. `pc_offset` is `0x28` (decimal 40).
2. Iteration:
   - **Entry 0:** `40 > 10`.
   - **Entry 1:** `40 > 25`.
   - **Entry 2:** `entry.pc()` is 40. `40 <= 40`. Since this is the last entry, the second part of the condition `|| GetEntry(i + 1).pc() > pc_offset` is not evaluated. The function returns `entry`.

**Hypothetical Output:**

- The `SafepointEntry` for Entry 2.

**Common Programming Errors (Relating to the Concepts):**

While developers don't directly program with `SafepointTable`, understanding its purpose helps avoid performance pitfalls and unexpected behavior:

1. **Assuming Type Stability in Optimized Code:** If JavaScript code relies on the optimizing compiler making assumptions about variable types, and these assumptions are frequently invalidated, it can lead to **frequent deoptimizations**. This can significantly impact performance as the engine constantly switches between optimized and unoptimized code.

   ```javascript
   function process(data) {
     for (let i = 0; i < data.length; i++) {
       // If 'data' sometimes contains numbers and sometimes strings,
       // the optimized code might deoptimize frequently.
       console.log(data[i] * 2);
     }
   }

   process([1, 2, 3]); // Optimized for numbers
   process(["a", "b", "c"]); // Now needs to deoptimize
   ```

2. **Creating Functions with Polymorphic Arguments:** Functions that are called with arguments of different types can be harder to optimize effectively. The compiler might need to generate more complex code or deoptimize more often.

   ```javascript
   function handleValue(value) {
     if (typeof value === 'number') {
       return value + 1;
     } else if (typeof value === 'string') {
       return value.toUpperCase();
     }
   }

   console.log(handleValue(5));
   console.log(handleValue("test"));
   ```

3. **Over-reliance on Dynamic Features in Performance-Critical Sections:** Features like `eval`, `with`, and frequent changes to object shapes can hinder optimization and lead to more deoptimizations.

**In Summary:**

`v8/src/codegen/safepoint-table.cc` is a fundamental piece of V8's code generation infrastructure. It enables safe garbage collection and deoptimization by providing a structured way to record and retrieve runtime state information at specific points in the generated machine code. While JavaScript developers don't directly interact with this code, understanding its role helps in writing more performant and stable JavaScript code by avoiding patterns that lead to frequent deoptimizations.

Prompt: 
```
这是目录为v8/src/codegen/safepoint-table.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/safepoint-table.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2011 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/safepoint-table.h"

#include <iomanip>

#include "src/codegen/assembler-inl.h"
#include "src/codegen/macro-assembler.h"
#include "src/deoptimizer/deoptimizer.h"
#include "src/diagnostics/disasm.h"
#include "src/execution/frames-inl.h"
#include "src/utils/ostreams.h"

#if V8_ENABLE_WEBASSEMBLY
#include "src/wasm/wasm-code-manager.h"
#endif  // V8_ENABLE_WEBASSEMBLY

namespace v8 {
namespace internal {

SafepointTable::SafepointTable(Isolate* isolate, Address pc, Tagged<Code> code)
    : SafepointTable(code->InstructionStart(isolate, pc),
                     code->safepoint_table_address()) {
  DCHECK(code->is_turbofanned());
}

SafepointTable::SafepointTable(Isolate* isolate, Address pc,
                               Tagged<GcSafeCode> code)
    : SafepointTable(code->InstructionStart(isolate, pc),
                     code->safepoint_table_address()) {
  DCHECK(code->is_turbofanned());
}

#if V8_ENABLE_WEBASSEMBLY
SafepointTable::SafepointTable(const wasm::WasmCode* code)
    : SafepointTable(
          code->instruction_start(),
          code->instruction_start() + code->safepoint_table_offset()) {}
#endif  // V8_ENABLE_WEBASSEMBLY

SafepointTable::SafepointTable(Address instruction_start,
                               Address safepoint_table_address)
    : instruction_start_(instruction_start),
      safepoint_table_address_(safepoint_table_address),
      stack_slots_(base::Memory<SafepointTableStackSlotsField_t>(
          safepoint_table_address + kStackSlotsOffset)),
      length_(base::Memory<int>(safepoint_table_address + kLengthOffset)),
      entry_configuration_(base::Memory<uint32_t>(safepoint_table_address +
                                                  kEntryConfigurationOffset)) {}

int SafepointTable::find_return_pc(int pc_offset) {
  for (int i = 0; i < length(); i++) {
    SafepointEntry entry = GetEntry(i);
    if (entry.trampoline_pc() == pc_offset || entry.pc() == pc_offset) {
      return entry.pc();
    }
  }
  UNREACHABLE();
}

SafepointEntry SafepointTable::TryFindEntry(Address pc) const {
  int pc_offset = static_cast<int>(pc - instruction_start_);

  // Check if the PC is pointing at a trampoline.
  if (has_deopt_data()) {
    int candidate = -1;
    for (int i = 0; i < length_; ++i) {
      int trampoline_pc = GetEntry(i).trampoline_pc();
      if (trampoline_pc != -1 && trampoline_pc <= pc_offset) candidate = i;
      if (trampoline_pc > pc_offset) break;
    }
    if (candidate != -1) return GetEntry(candidate);
  }

  for (int i = 0; i < length_; ++i) {
    SafepointEntry entry = GetEntry(i);
    if (i == length_ - 1 || GetEntry(i + 1).pc() > pc_offset) {
      if (entry.pc() > pc_offset) return {};
      return entry;
    }
  }
  return {};
}

SafepointEntry SafepointTable::FindEntry(Address pc) const {
  SafepointEntry result = TryFindEntry(pc);
  CHECK(result.is_initialized());
  return result;
}

// static
SafepointEntry SafepointTable::FindEntry(Isolate* isolate,
                                         Tagged<GcSafeCode> code, Address pc) {
  SafepointTable table(isolate, pc, code);
  return table.FindEntry(pc);
}

void SafepointTable::Print(std::ostream& os) const {
  os << "Safepoints (stack slots = " << stack_slots_
     << ", entries = " << length_ << ", byte size = " << byte_size() << ")\n";

  for (int index = 0; index < length_; index++) {
    SafepointEntry entry = GetEntry(index);
    os << reinterpret_cast<const void*>(instruction_start_ + entry.pc()) << " "
       << std::setw(6) << std::hex << entry.pc() << std::dec;

    if (!entry.tagged_slots().empty()) {
      os << "  slots (sp->fp): ";
      uint32_t i = 0;
      for (uint8_t bits : entry.tagged_slots()) {
        for (int bit = 0; bit < kBitsPerByte && i < stack_slots_; ++bit, ++i) {
          os << ((bits >> bit) & 1);
        }
      }
      // The tagged slots bitfield ends at the min stack slot (rounded up to the
      // nearest byte) -- we might have some slots left over in the stack frame
      // before the fp, so print zeros for those.
      for (; i < stack_slots_; ++i) {
        os << 0;
      }
    }

    if (entry.tagged_register_indexes() != 0) {
      os << "  registers: ";
      uint32_t register_bits = entry.tagged_register_indexes();
      int bits = 32 - base::bits::CountLeadingZeros32(register_bits);
      for (int j = bits - 1; j >= 0; --j) {
        os << ((register_bits >> j) & 1);
      }
    }

    if (entry.has_deoptimization_index()) {
      os << "  deopt " << std::setw(6) << entry.deoptimization_index()
         << " trampoline: " << std::setw(6) << std::hex
         << entry.trampoline_pc();
    }
    os << "\n";
  }
}

SafepointTableBuilder::Safepoint SafepointTableBuilder::DefineSafepoint(
    Assembler* assembler, int pc_offset) {
  pc_offset = pc_offset ? pc_offset : assembler->pc_offset_for_safepoint();
  entries_.emplace_back(zone_, pc_offset);
  return SafepointTableBuilder::Safepoint(&entries_.back(), this);
}

int SafepointTableBuilder::UpdateDeoptimizationInfo(int pc, int trampoline,
                                                    int start,
                                                    int deopt_index) {
  DCHECK_NE(SafepointEntry::kNoTrampolinePC, trampoline);
  DCHECK_NE(SafepointEntry::kNoDeoptIndex, deopt_index);
  auto it = entries_.begin() + start;
  DCHECK(std::any_of(it, entries_.end(),
                     [pc](auto& entry) { return entry.pc == pc; }));
  int index = start;
  while (it->pc != pc) ++it, ++index;
  it->trampoline = trampoline;
  it->deopt_index = deopt_index;
  return index;
}

void SafepointTableBuilder::Emit(Assembler* assembler, int stack_slot_count) {
  DCHECK_LT(max_stack_index_, stack_slot_count);

#ifdef DEBUG
  int last_pc = -1;
  int last_trampoline = -1;
  for (const EntryBuilder& entry : entries_) {
    // Entries are ordered by PC.
    DCHECK_LT(last_pc, entry.pc);
    last_pc = entry.pc;
    // Trampoline PCs are increasing, and larger than regular PCs.
    if (entry.trampoline != SafepointEntry::kNoTrampolinePC) {
      DCHECK_LT(last_trampoline, entry.trampoline);
      DCHECK_LT(entries_.back().pc, entry.trampoline);
      last_trampoline = entry.trampoline;
    }
    // An entry either has trampoline and deopt index, or none of the two.
    DCHECK_EQ(entry.trampoline == SafepointEntry::kNoTrampolinePC,
              entry.deopt_index == SafepointEntry::kNoDeoptIndex);
  }
#endif  // DEBUG

  RemoveDuplicates();

  // The encoding is compacted by translating stack slot indices s.t. they
  // start at 0. See also below.
  int tagged_slots_size = stack_slot_count - min_stack_index();

#if V8_TARGET_ARCH_ARM || V8_TARGET_ARCH_ARM64
  // We cannot emit a const pool within the safepoint table.
  Assembler::BlockConstPoolScope block_const_pool(assembler);
#endif

  // Make sure the safepoint table is properly aligned. Pad with nops.
  assembler->Align(InstructionStream::kMetadataAlignment);
  assembler->RecordComment(";;; Safepoint table.");
  set_safepoint_table_offset(assembler->pc_offset());

  // Compute the required sizes of the fields.
  int used_register_indexes = 0;
  static_assert(SafepointEntry::kNoTrampolinePC == -1);
  int max_pc = SafepointEntry::kNoTrampolinePC;
  static_assert(SafepointEntry::kNoDeoptIndex == -1);
  int max_deopt_index = SafepointEntry::kNoDeoptIndex;
  for (const EntryBuilder& entry : entries_) {
    used_register_indexes |= entry.register_indexes;
    max_pc = std::max(max_pc, std::max(entry.pc, entry.trampoline));
    max_deopt_index = std::max(max_deopt_index, entry.deopt_index);
  }

  // Derive the bytes and bools for the entry configuration from the values.
  auto value_to_bytes = [](int value) {
    DCHECK_LE(0, value);
    if (value == 0) return 0;
    if (value <= 0xff) return 1;
    if (value <= 0xffff) return 2;
    if (value <= 0xffffff) return 3;
    return 4;
  };
  bool has_deopt_data = max_deopt_index != -1;
  int register_indexes_size = value_to_bytes(used_register_indexes);
  // Add 1 so all values (including kNoDeoptIndex and kNoTrampolinePC) are
  // non-negative.
  static_assert(SafepointEntry::kNoDeoptIndex == -1);
  static_assert(SafepointEntry::kNoTrampolinePC == -1);
  int pc_size = value_to_bytes(max_pc + 1);
  int deopt_index_size = value_to_bytes(max_deopt_index + 1);
  int tagged_slots_bytes =
      (tagged_slots_size + kBitsPerByte - 1) / kBitsPerByte;

  // Add a CHECK to ensure we never overflow the space in the bitfield, even for
  // huge functions which might not be covered by tests.
  CHECK(SafepointTable::RegisterIndexesSizeField::is_valid(
      register_indexes_size));
  CHECK(SafepointTable::PcSizeField::is_valid(pc_size));
  CHECK(SafepointTable::DeoptIndexSizeField::is_valid(deopt_index_size));
  CHECK(SafepointTable::TaggedSlotsBytesField::is_valid(tagged_slots_bytes));

  uint32_t entry_configuration =
      SafepointTable::HasDeoptDataField::encode(has_deopt_data) |
      SafepointTable::RegisterIndexesSizeField::encode(register_indexes_size) |
      SafepointTable::PcSizeField::encode(pc_size) |
      SafepointTable::DeoptIndexSizeField::encode(deopt_index_size) |
      SafepointTable::TaggedSlotsBytesField::encode(tagged_slots_bytes);

  // Emit the table header.
  static_assert(SafepointTable::kStackSlotsOffset == 0 * kIntSize);
  static_assert(SafepointTable::kLengthOffset == 1 * kIntSize);
  static_assert(SafepointTable::kEntryConfigurationOffset == 2 * kIntSize);
  static_assert(SafepointTable::kHeaderSize == 3 * kIntSize);
  int length = static_cast<int>(entries_.size());
  assembler->dd(stack_slot_count);
  assembler->dd(length);
  assembler->dd(entry_configuration);

  auto emit_bytes = [assembler](int value, int bytes) {
    DCHECK_LE(0, value);
    for (; bytes > 0; --bytes, value >>= 8) assembler->db(value);
    DCHECK_EQ(0, value);
  };
  // Emit entries, sorted by pc offsets.
  for (const EntryBuilder& entry : entries_) {
    emit_bytes(entry.pc, pc_size);
    if (has_deopt_data) {
      // Add 1 so all values (including kNoDeoptIndex and kNoTrampolinePC) are
      // non-negative.
      static_assert(SafepointEntry::kNoDeoptIndex == -1);
      static_assert(SafepointEntry::kNoTrampolinePC == -1);
      emit_bytes(entry.deopt_index + 1, deopt_index_size);
      emit_bytes(entry.trampoline + 1, pc_size);
    }
    emit_bytes(entry.register_indexes, register_indexes_size);
  }

  // Emit bitmaps of tagged stack slots. Note the slot list is reversed in the
  // encoding.
  // TODO(jgruber): Avoid building a reversed copy of the bit vector.
  ZoneVector<uint8_t> bits(tagged_slots_bytes, 0, zone_);
  for (const EntryBuilder& entry : entries_) {
    std::fill(bits.begin(), bits.end(), 0);

    // Run through the indexes and build a bitmap.
    for (int idx : *entry.stack_indexes) {
      // The encoding is compacted by translating stack slot indices s.t. they
      // start at 0. See also above.
      const int adjusted_idx = idx - min_stack_index();
      DCHECK_GT(tagged_slots_size, adjusted_idx);
      int index = tagged_slots_size - 1 - adjusted_idx;
      int byte_index = index >> kBitsPerByteLog2;
      int bit_index = index & (kBitsPerByte - 1);
      bits[byte_index] |= (1u << bit_index);
    }

    // Emit the bitmap for the current entry.
    for (uint8_t byte : bits) assembler->db(byte);
  }
}

void SafepointTableBuilder::RemoveDuplicates() {
  // Remove any duplicate entries, i.e. succeeding entries that are identical
  // except for the PC. During lookup, we will find the first entry whose PC is
  // not larger than the PC at hand, and find the first non-duplicate.

  if (entries_.size() < 2) return;

  auto is_identical_except_for_pc = [](const EntryBuilder& entry1,
                                       const EntryBuilder& entry2) {
    if (entry1.deopt_index != entry2.deopt_index) return false;
    DCHECK_EQ(entry1.trampoline, entry2.trampoline);
    return entry1.register_indexes == entry2.register_indexes &&
           entry1.stack_indexes->Equals(*entry2.stack_indexes);
  };

  auto remaining_it = entries_.begin();
  auto end = entries_.end();

  for (auto it = entries_.begin(); it != end; ++remaining_it) {
    if (remaining_it != it) *remaining_it = *it;
    // Merge identical entries.
    do {
      ++it;
    } while (it != end && is_identical_except_for_pc(*it, *remaining_it));
  }

  entries_.erase(remaining_it, end);
}

}  // namespace internal
}  // namespace v8

"""

```