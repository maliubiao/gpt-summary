Response: Let's break down the thought process for analyzing this C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for the functionality of the `constant-pool.cc` file within V8 and how it relates to JavaScript. This means identifying the core purpose of the code and connecting it to high-level JavaScript concepts.

2. **Initial Code Scan - Identify Key Classes:** The first step is to scan the code and identify the main classes and their roles. The prominent classes are:
    * `ConstantPoolBuilder`: This class seems to be involved in *building* or *managing* something called a "constant pool". The name suggests it's about storing constants.
    * `ConstantPool`:  Another class related to constant pools, likely responsible for the actual emission and management during assembly.
    * `ConstantPoolEntry`:  Represents an individual entry within the constant pool.

3. **Focus on `ConstantPoolBuilder`:**  Since the file is named `constant-pool.cc`, and the first part of the code defines `ConstantPoolBuilder`, it's a good place to start.

4. **Analyze `ConstantPoolBuilder` Methods:**  Go through the methods of `ConstantPoolBuilder` to understand its actions:
    * `ConstantPoolBuilder` (constructor): Takes `ptr_reach_bits` and `double_reach_bits`. These likely relate to how far away the constants can be accessed.
    * `NextAccess`: Determines the "access" type for a new entry (REGULAR or OVERFLOWED). This hints at different ways constants might be accessed depending on distance or capacity.
    * `AddEntry`: Adds an entry to the pool. It checks for merging (sharing) of constants. This is an important optimization.
    * `EmitSharedEntries`: Emits the shared constants.
    * `EmitGroup`: Emits a group of constants based on access type.
    * `Emit`: The main emission function, tying everything together. It handles alignment and potentially emitting in different groups.

5. **Infer `ConstantPoolBuilder` Functionality:** From the methods, we can infer that `ConstantPoolBuilder` is responsible for:
    * Collecting constants (integers and doubles).
    * Optimizing by sharing identical constants.
    * Organizing constants into groups based on access reach (REGULAR and OVERFLOWED).
    * Managing the layout of the constant pool in memory.

6. **Focus on `ConstantPool`:** The second part of the code defines `ConstantPool`.

7. **Analyze `ConstantPool` Methods:**  Similar to `ConstantPoolBuilder`, analyze its methods:
    * `ConstantPool` (constructor): Takes an `Assembler*`. This suggests it works closely with the assembly process.
    * `RecordEntry`/`RecordKey`:  Records constants as they are encountered during code generation.
    * `GetRelocInfoStatusFor`: Checks if a constant can be deduplicated.
    * `EmitAndClear`: Emits the constant pool into the generated code. It handles alignment and potentially adding a jump instruction to avoid falling into the pool.
    * `Clear`: Resets the constant pool.
    * `StartBlock`/`EndBlock`: Mechanisms to temporarily prevent constant pool emission.
    * `ShouldEmitNow`: Decides if the constant pool should be emitted based on distance and other factors.
    * `ComputeSize`: Calculates the size of the constant pool.

8. **Infer `ConstantPool` Functionality:**  From these methods, we can infer that `ConstantPool` is responsible for:
    * Keeping track of constants used in the generated code.
    * Deciding *when* and *how* to insert the constant pool into the generated assembly.
    * Optimizing by deduplicating constants.
    * Ensuring proper alignment of the constant pool in memory.

9. **Connect to JavaScript:**  Now, the critical part: how does this relate to JavaScript?  Think about what kind of constants are used in JavaScript execution:
    * **Numbers:**  JavaScript numbers are often represented as doubles.
    * **Small Integers:**  V8 might optimize small integers.
    * **String Literals (Indirectly):** While not directly stored in the constant pool as strings, pointers to string objects in the heap could be.
    * **Function Addresses/Pointers:** When calling functions, the addresses need to be available.
    * **Object Properties (Indirectly):**  Pointers to property names or metadata could be in the constant pool.

10. **Formulate the Core Functionality:**  Combine the insights about `ConstantPoolBuilder` and `ConstantPool` to summarize the overall functionality:  The code manages a storage area (the constant pool) for frequently used values (constants) within the generated machine code. This optimizes code by:
    * Reducing code size by reusing constants.
    * Improving performance by allowing quick access to these values.

11. **Create a JavaScript Example:** Choose a simple JavaScript scenario that demonstrates the use of constants:
    * **Basic Arithmetic:** Simple calculations involve numeric constants.
    * **String Literals:**  Strings are often used directly in code.
    * **Function Calls:**  Demonstrates the need for function addresses.

12. **Explain the Connection:**  Relate the JavaScript example back to the C++ code. Explain that when V8 compiles this JavaScript, the constants (numbers, potentially string pointers, and function addresses) will be placed into the constant pool managed by the code in `constant-pool.cc`. The generated machine code will then access these constants from the pool, rather than embedding them directly in the instructions.

13. **Refine and Organize:** Review the summary and example for clarity and accuracy. Ensure the language is accessible and avoids overly technical jargon where possible. Structure the explanation logically.

**Self-Correction/Refinement During the Process:**

* **Initial Thought:**  Maybe the constant pool stores *all* JavaScript values. **Correction:** Realize that heap-allocated objects like strings are likely handled differently. The constant pool probably stores pointers to these objects or immutable values like numbers and function addresses.
* **Considering Architectures:** Notice the `#if defined(...)` blocks. This indicates architecture-specific implementations. While the core concept is the same, the details of how the constant pool is managed and emitted can vary. Acknowledge this in the summary.
* **Simplifying the Explanation:**  Avoid getting bogged down in the details of `RelocInfo`, `Assembler`, etc., unless absolutely necessary for understanding the core concept. Focus on the *what* and *why* rather than the *how* at a low level.
* **Choosing the Right JavaScript Example:** Initially considered a more complex example with objects. **Correction:** Opted for a simpler example to clearly illustrate the basic concept of constant usage.

By following these steps, combining code analysis with knowledge of JavaScript compilation, and performing some self-correction, we can arrive at a comprehensive and accurate explanation of the `constant-pool.cc` file's functionality and its connection to JavaScript.
This C++ source code file, `constant-pool.cc`, located in the `v8/src/codegen` directory, is responsible for **managing and emitting a constant pool during the code generation process in V8**.

Here's a breakdown of its functionality:

**Core Functionality:**

* **Storing Constants:** The constant pool is a dedicated area in the generated machine code where frequently used constant values (like numbers, addresses, etc.) are stored. This avoids embedding the same constant value multiple times directly within the instructions, saving space.
* **Optimizing Constant Access:**  Instead of having immediate values in instructions, the instructions reference the constant pool. This can be more efficient, especially for larger constants or when the same constant is used many times.
* **Handling Different Constant Types:** The code differentiates between different types of constants, primarily integers/pointers (`INTPTR`) and double-precision floating-point numbers (`DOUBLE`).
* **Managing Access Reach:** The code takes into account the "reach" of constants, meaning how far away from the instruction they can be accessed. This is important for instruction encoding limitations on different architectures. It distinguishes between "regular" reach and situations where a larger offset or a different access method is needed (indicated by `OVERFLOWED`).
* **Constant Sharing (Deduplication):** The `ConstantPoolBuilder` attempts to merge identical constants to further reduce the size of the constant pool. This optimization is crucial for code density.
* **Emitting the Constant Pool:** The code provides mechanisms to actually write the constant pool data into the generated code stream at a suitable location. It handles alignment requirements (e.g., doubles often need to be aligned to 8-byte boundaries).
* **Patching Instructions:**  After the constant pool is emitted, the code needs to go back and "patch" the instructions that were using placeholders for the constant values. It replaces these placeholders with the correct offsets into the newly created constant pool.
* **Architecture-Specific Implementation:** The code uses preprocessor directives (`#if defined(...)`) to handle differences in how constant pools are managed on various CPU architectures (e.g., PPC64, ARM64, RISC-V). This indicates that the optimal strategy for constant pool management can vary depending on the target platform.
* **Dynamic Emission:** The `ConstantPool` class (used in architectures like ARM64 and RISC-V) implements a more dynamic approach, deciding when to emit the constant pool based on factors like the distance to the first usage of a constant and the size of the pool. This helps optimize code layout and avoid exceeding instruction reach limitations.

**Relationship to JavaScript:**

This code directly relates to JavaScript performance and code size. When the V8 JavaScript engine compiles JavaScript code into machine code, it identifies constant values within the JavaScript. These constants are then managed and stored in the constant pool using the logic implemented in this file.

**JavaScript Examples:**

Here are a few ways JavaScript code can lead to entries in the constant pool:

1. **Numeric Constants:**

   ```javascript
   function add(a) {
     return a + 10; // The constant '10' might be placed in the constant pool
   }

   function calculateArea(radius) {
     return 3.14159 * radius * radius; // '3.14159' is a floating-point constant
   }
   ```

   When V8 compiles these functions, the numeric literals `10` and `3.14159` are likely candidates for being stored in the constant pool. The generated machine code will then load these values from the pool when executing the addition and multiplication operations.

2. **String Literals (Indirectly - Pointers):**

   ```javascript
   function greet(name) {
     console.log("Hello, " + name + "!"); // "Hello, " and "!" are string literals
   }
   ```

   While the actual string data is stored in the V8 heap, the *pointers* to these string objects might be placed in the constant pool. The generated code would load the pointer from the constant pool to access the string data.

3. **Function Addresses/Pointers (For Calls):**

   ```javascript
   function square(x) {
     return x * x;
   }

   function applyOperation(value, operation) {
     return operation(value); // 'operation' holds a function reference
   }

   let result = applyOperation(5, square); // The address of the 'square' function
   ```

   When V8 compiles the `applyOperation` function, it needs the address of the `square` function to perform the call. This function address is a constant value and could be stored in the constant pool.

4. **Small Integers and Object Literals (Optimizations):**

   While less direct, V8's internal optimizations might represent small integers or even pointers to parts of object literals in the constant pool for faster access.

**In essence, the `constant-pool.cc` file plays a crucial role in optimizing the generated machine code for JavaScript execution by efficiently managing and accessing constant values. It helps reduce code size and potentially improve performance by making constant access faster.**

### 提示词
```
这是目录为v8/src/codegen/constant-pool.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2018 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/codegen/constant-pool.h"
#include "src/codegen/assembler-arch.h"
#include "src/codegen/assembler-inl.h"

namespace v8 {
namespace internal {

#if defined(V8_TARGET_ARCH_PPC64)

ConstantPoolBuilder::ConstantPoolBuilder(int ptr_reach_bits,
                                         int double_reach_bits) {
  info_[ConstantPoolEntry::INTPTR].entries.reserve(64);
  info_[ConstantPoolEntry::INTPTR].regular_reach_bits = ptr_reach_bits;
  info_[ConstantPoolEntry::DOUBLE].regular_reach_bits = double_reach_bits;
}

ConstantPoolEntry::Access ConstantPoolBuilder::NextAccess(
    ConstantPoolEntry::Type type) const {
  const PerTypeEntryInfo& info = info_[type];

  if (info.overflow()) return ConstantPoolEntry::OVERFLOWED;

  int dbl_count = info_[ConstantPoolEntry::DOUBLE].regular_count;
  int dbl_offset = dbl_count * kDoubleSize;
  int ptr_count = info_[ConstantPoolEntry::INTPTR].regular_count;
  int ptr_offset = ptr_count * kSystemPointerSize + dbl_offset;

  if (type == ConstantPoolEntry::DOUBLE) {
    // Double overflow detection must take into account the reach for both types
    int ptr_reach_bits = info_[ConstantPoolEntry::INTPTR].regular_reach_bits;
    if (!is_uintn(dbl_offset, info.regular_reach_bits) ||
        (ptr_count > 0 &&
         !is_uintn(ptr_offset + kDoubleSize - kSystemPointerSize,
                   ptr_reach_bits))) {
      return ConstantPoolEntry::OVERFLOWED;
    }
  } else {
    DCHECK(type == ConstantPoolEntry::INTPTR);
    if (!is_uintn(ptr_offset, info.regular_reach_bits)) {
      return ConstantPoolEntry::OVERFLOWED;
    }
  }

  return ConstantPoolEntry::REGULAR;
}

ConstantPoolEntry::Access ConstantPoolBuilder::AddEntry(
    ConstantPoolEntry* entry, ConstantPoolEntry::Type type) {
  DCHECK(!emitted_label_.is_bound());
  PerTypeEntryInfo& info = info_[type];
  const int entry_size = ConstantPoolEntry::size(type);
  bool merged = false;

  if (entry->sharing_ok()) {
    // Try to merge entries
    std::vector<ConstantPoolEntry>::iterator it = info.shared_entries.begin();
    int end = static_cast<int>(info.shared_entries.size());
    for (int i = 0; i < end; i++, it++) {
      if ((entry_size == kSystemPointerSize)
              ? entry->value() == it->value()
              : entry->value64() == it->value64()) {
        // Merge with found entry.
        entry->set_merged_index(i);
        merged = true;
        break;
      }
    }
  }

  // By definition, merged entries have regular access.
  DCHECK(!merged || entry->merged_index() < info.regular_count);
  ConstantPoolEntry::Access access =
      (merged ? ConstantPoolEntry::REGULAR : NextAccess(type));

  // Enforce an upper bound on search time by limiting the search to
  // unique sharable entries which fit in the regular section.
  if (entry->sharing_ok() && !merged && access == ConstantPoolEntry::REGULAR) {
    info.shared_entries.push_back(*entry);
  } else {
    info.entries.push_back(*entry);
  }

  // We're done if we found a match or have already triggered the
  // overflow state.
  if (merged || info.overflow()) return access;

  if (access == ConstantPoolEntry::REGULAR) {
    info.regular_count++;
  } else {
    info.overflow_start = static_cast<int>(info.entries.size()) - 1;
  }

  return access;
}

void ConstantPoolBuilder::EmitSharedEntries(Assembler* assm,
                                            ConstantPoolEntry::Type type) {
  PerTypeEntryInfo& info = info_[type];
  std::vector<ConstantPoolEntry>& shared_entries = info.shared_entries;
  const int entry_size = ConstantPoolEntry::size(type);
  int base = emitted_label_.pos();
  DCHECK_GT(base, 0);
  int shared_end = static_cast<int>(shared_entries.size());
  std::vector<ConstantPoolEntry>::iterator shared_it = shared_entries.begin();
  for (int i = 0; i < shared_end; i++, shared_it++) {
    int offset = assm->pc_offset() - base;
    shared_it->set_offset(offset);  // Save offset for merged entries.
    if (entry_size == kSystemPointerSize) {
      assm->dp(shared_it->value());
    } else {
      assm->dq(shared_it->value64());
    }
    DCHECK(is_uintn(offset, info.regular_reach_bits));

    // Patch load sequence with correct offset.
    assm->PatchConstantPoolAccessInstruction(shared_it->position(), offset,
                                             ConstantPoolEntry::REGULAR, type);
  }
}

void ConstantPoolBuilder::EmitGroup(Assembler* assm,
                                    ConstantPoolEntry::Access access,
                                    ConstantPoolEntry::Type type) {
  PerTypeEntryInfo& info = info_[type];
  const bool overflow = info.overflow();
  std::vector<ConstantPoolEntry>& entries = info.entries;
  std::vector<ConstantPoolEntry>& shared_entries = info.shared_entries;
  const int entry_size = ConstantPoolEntry::size(type);
  int base = emitted_label_.pos();
  DCHECK_GT(base, 0);
  int begin;
  int end;

  if (access == ConstantPoolEntry::REGULAR) {
    // Emit any shared entries first
    EmitSharedEntries(assm, type);
  }

  if (access == ConstantPoolEntry::REGULAR) {
    begin = 0;
    end = overflow ? info.overflow_start : static_cast<int>(entries.size());
  } else {
    DCHECK(access == ConstantPoolEntry::OVERFLOWED);
    if (!overflow) return;
    begin = info.overflow_start;
    end = static_cast<int>(entries.size());
  }

  std::vector<ConstantPoolEntry>::iterator it = entries.begin();
  if (begin > 0) std::advance(it, begin);
  for (int i = begin; i < end; i++, it++) {
    // Update constant pool if necessary and get the entry's offset.
    int offset;
    ConstantPoolEntry::Access entry_access;
    if (!it->is_merged()) {
      // Emit new entry
      offset = assm->pc_offset() - base;
      entry_access = access;
      if (entry_size == kSystemPointerSize) {
        assm->dp(it->value());
      } else {
        assm->dq(it->value64());
      }
    } else {
      // Retrieve offset from shared entry.
      offset = shared_entries[it->merged_index()].offset();
      entry_access = ConstantPoolEntry::REGULAR;
    }

    DCHECK(entry_access == ConstantPoolEntry::OVERFLOWED ||
           is_uintn(offset, info.regular_reach_bits));

    // Patch load sequence with correct offset.
    assm->PatchConstantPoolAccessInstruction(it->position(), offset,
                                             entry_access, type);
  }
}

// Emit and return size of pool.
int ConstantPoolBuilder::Emit(Assembler* assm) {
  bool emitted = emitted_label_.is_bound();
  bool empty = IsEmpty();

  if (!emitted) {
    // Mark start of constant pool.  Align if necessary.
    if (!empty) assm->DataAlign(kDoubleSize);
    assm->bind(&emitted_label_);
    if (!empty) {
      // Emit in groups based on access and type.
      // Emit doubles first for alignment purposes.
      EmitGroup(assm, ConstantPoolEntry::REGULAR, ConstantPoolEntry::DOUBLE);
      EmitGroup(assm, ConstantPoolEntry::REGULAR, ConstantPoolEntry::INTPTR);
      if (info_[ConstantPoolEntry::DOUBLE].overflow()) {
        assm->DataAlign(kDoubleSize);
        EmitGroup(assm, ConstantPoolEntry::OVERFLOWED,
                  ConstantPoolEntry::DOUBLE);
      }
      if (info_[ConstantPoolEntry::INTPTR].overflow()) {
        EmitGroup(assm, ConstantPoolEntry::OVERFLOWED,
                  ConstantPoolEntry::INTPTR);
      }
    }
  }

  return !empty ? (assm->pc_offset() - emitted_label_.pos()) : 0;
}

#endif  // defined(V8_TARGET_ARCH_PPC64)

#if defined(V8_TARGET_ARCH_ARM64)

// Constant Pool.

ConstantPool::ConstantPool(Assembler* assm) : assm_(assm) {}
ConstantPool::~ConstantPool() { DCHECK_EQ(blocked_nesting_, 0); }

RelocInfoStatus ConstantPool::RecordEntry(uint32_t data,
                                          RelocInfo::Mode rmode) {
  ConstantPoolKey key(data, rmode);
  CHECK(key.is_value32());
  return RecordKey(std::move(key), assm_->pc_offset());
}

RelocInfoStatus ConstantPool::RecordEntry(uint64_t data,
                                          RelocInfo::Mode rmode) {
  ConstantPoolKey key(data, rmode);
  CHECK(!key.is_value32());
  return RecordKey(std::move(key), assm_->pc_offset());
}

RelocInfoStatus ConstantPool::RecordKey(ConstantPoolKey key, int offset) {
  RelocInfoStatus write_reloc_info = GetRelocInfoStatusFor(key);
  if (write_reloc_info == RelocInfoStatus::kMustRecord) {
    if (key.is_value32()) {
      if (entry32_count_ == 0) first_use_32_ = offset;
      ++entry32_count_;
    } else {
      if (entry64_count_ == 0) first_use_64_ = offset;
      ++entry64_count_;
    }
  }
  entries_.insert(std::make_pair(key, offset));

  if (Entry32Count() + Entry64Count() > ConstantPool::kApproxMaxEntryCount) {
    // Request constant pool emission after the next instruction.
    SetNextCheckIn(1);
  }

  return write_reloc_info;
}

RelocInfoStatus ConstantPool::GetRelocInfoStatusFor(
    const ConstantPoolKey& key) {
  if (key.AllowsDeduplication()) {
    auto existing = entries_.find(key);
    if (existing != entries_.end()) {
      return RelocInfoStatus::kMustOmitForDuplicate;
    }
  }
  return RelocInfoStatus::kMustRecord;
}

void ConstantPool::EmitAndClear(Jump require_jump) {
  DCHECK(!IsBlocked());
  // Prevent recursive pool emission.
  Assembler::BlockPoolsScope block_pools(assm_, PoolEmissionCheck::kSkip);
  Alignment require_alignment =
      IsAlignmentRequiredIfEmittedAt(require_jump, assm_->pc_offset());
  int size = ComputeSize(require_jump, require_alignment);
  Label size_check;
  assm_->bind(&size_check);
  assm_->RecordConstPool(size);

  // Emit the constant pool. It is preceded by an optional branch if
  // {require_jump} and a header which will:
  //  1) Encode the size of the constant pool, for use by the disassembler.
  //  2) Terminate the program, to try to prevent execution from accidentally
  //     flowing into the constant pool.
  //  3) align the 64bit pool entries to 64-bit.
  // TODO(all): Make the alignment part less fragile. Currently code is
  // allocated as a byte array so there are no guarantees the alignment will
  // be preserved on compaction. Currently it works as allocation seems to be
  // 64-bit aligned.

  Label after_pool;
  if (require_jump == Jump::kRequired) assm_->b(&after_pool);

  assm_->RecordComment("[ Constant Pool");
  EmitPrologue(require_alignment);
  if (require_alignment == Alignment::kRequired) assm_->Align(kInt64Size);
  EmitEntries();
  assm_->RecordComment("]");

  if (after_pool.is_linked()) assm_->bind(&after_pool);

  DCHECK_EQ(assm_->SizeOfCodeGeneratedSince(&size_check), size);
  Clear();
}

void ConstantPool::Clear() {
  entries_.clear();
  first_use_32_ = -1;
  first_use_64_ = -1;
  entry32_count_ = 0;
  entry64_count_ = 0;
  next_check_ = 0;
  old_next_check_ = 0;
}

void ConstantPool::StartBlock() {
  if (blocked_nesting_ == 0) {
    // Prevent constant pool checks from happening by setting the next check to
    // the biggest possible offset.
    old_next_check_ = next_check_;
    next_check_ = kMaxInt;
  }
  ++blocked_nesting_;
}

void ConstantPool::EndBlock() {
  --blocked_nesting_;
  if (blocked_nesting_ == 0) {
    DCHECK(IsInImmRangeIfEmittedAt(assm_->pc_offset()));
    // Restore the old next_check_ value if it's less than the current
    // next_check_. This accounts for any attempt to emit pools sooner whilst
    // pools were blocked.
    next_check_ = std::min(next_check_, old_next_check_);
  }
}

bool ConstantPool::IsBlocked() const { return blocked_nesting_ > 0; }

void ConstantPool::SetNextCheckIn(size_t instructions) {
  next_check_ =
      assm_->pc_offset() + static_cast<int>(instructions * kInstrSize);
}

void ConstantPool::EmitEntries() {
  for (auto iter = entries_.begin(); iter != entries_.end();) {
    DCHECK(iter->first.is_value32() || IsAligned(assm_->pc_offset(), 8));
    auto range = entries_.equal_range(iter->first);
    bool shared = iter->first.AllowsDeduplication();
    for (auto it = range.first; it != range.second; ++it) {
      SetLoadOffsetToConstPoolEntry(it->second, assm_->pc(), it->first);
      if (!shared) Emit(it->first);
    }
    if (shared) Emit(iter->first);
    iter = range.second;
  }
}

void ConstantPool::Emit(const ConstantPoolKey& key) {
  if (key.is_value32()) {
    assm_->dd(key.value32());
  } else {
    assm_->dq(key.value64());
  }
}

bool ConstantPool::ShouldEmitNow(Jump require_jump, size_t margin) const {
  if (IsEmpty()) return false;
  if (Entry32Count() + Entry64Count() > ConstantPool::kApproxMaxEntryCount) {
    return true;
  }
  // We compute {dist32/64}, i.e. the distance from the first instruction
  // accessing a 32bit/64bit entry in the constant pool to any of the
  // 32bit/64bit constant pool entries, respectively. This is required because
  // we do not guarantee that entries are emitted in order of reference, i.e. it
  // is possible that the entry with the earliest reference is emitted last.
  // The constant pool should be emitted if either of the following is true:
  // (A) {dist32/64} will be out of range at the next check in.
  // (B) Emission can be done behind an unconditional branch and {dist32/64}
  // exceeds {kOpportunityDist*}.
  // (C) {dist32/64} exceeds the desired approximate distance to the pool.
  int worst_case_size = ComputeSize(Jump::kRequired, Alignment::kRequired);
  size_t pool_end_32 = assm_->pc_offset() + margin + worst_case_size;
  size_t pool_end_64 = pool_end_32 - Entry32Count() * kInt32Size;
  if (Entry64Count() != 0) {
    // The 64-bit constants are always emitted before the 32-bit constants, so
    // we subtract the size of the 32-bit constants from {size}.
    size_t dist64 = pool_end_64 - first_use_64_;
    bool next_check_too_late = dist64 + 2 * kCheckInterval >= kMaxDistToPool64;
    bool opportune_emission_without_jump =
        require_jump == Jump::kOmitted && (dist64 >= kOpportunityDistToPool64);
    bool approximate_distance_exceeded = dist64 >= kApproxDistToPool64;
    if (next_check_too_late || opportune_emission_without_jump ||
        approximate_distance_exceeded) {
      return true;
    }
  }
  if (Entry32Count() != 0) {
    size_t dist32 = pool_end_32 - first_use_32_;
    bool next_check_too_late = dist32 + 2 * kCheckInterval >= kMaxDistToPool32;
    bool opportune_emission_without_jump =
        require_jump == Jump::kOmitted && (dist32 >= kOpportunityDistToPool32);
    bool approximate_distance_exceeded = dist32 >= kApproxDistToPool32;
    if (next_check_too_late || opportune_emission_without_jump ||
        approximate_distance_exceeded) {
      return true;
    }
  }
  return false;
}

int ConstantPool::ComputeSize(Jump require_jump,
                              Alignment require_alignment) const {
  int size_up_to_marker = PrologueSize(require_jump);
  int alignment = require_alignment == Alignment::kRequired ? kInstrSize : 0;
  size_t size_after_marker =
      Entry32Count() * kInt32Size + alignment + Entry64Count() * kInt64Size;
  return size_up_to_marker + static_cast<int>(size_after_marker);
}

Alignment ConstantPool::IsAlignmentRequiredIfEmittedAt(Jump require_jump,
                                                       int pc_offset) const {
  int size_up_to_marker = PrologueSize(require_jump);
  if (Entry64Count() != 0 &&
      !IsAligned(pc_offset + size_up_to_marker, kInt64Size)) {
    return Alignment::kRequired;
  }
  return Alignment::kOmitted;
}

bool ConstantPool::IsInImmRangeIfEmittedAt(int pc_offset) {
  // Check that all entries are in range if the pool is emitted at {pc_offset}.
  // This ignores kPcLoadDelta (conservatively, since all offsets are positive),
  // and over-estimates the last entry's address with the pool's end.
  Alignment require_alignment =
      IsAlignmentRequiredIfEmittedAt(Jump::kRequired, pc_offset);
  size_t pool_end_32 =
      pc_offset + ComputeSize(Jump::kRequired, require_alignment);
  size_t pool_end_64 = pool_end_32 - Entry32Count() * kInt32Size;
  bool entries_in_range_32 =
      Entry32Count() == 0 || (pool_end_32 < first_use_32_ + kMaxDistToPool32);
  bool entries_in_range_64 =
      Entry64Count() == 0 || (pool_end_64 < first_use_64_ + kMaxDistToPool64);
  return entries_in_range_32 && entries_in_range_64;
}

ConstantPool::BlockScope::BlockScope(Assembler* assm, size_t margin)
    : pool_(&assm->constpool_) {
  pool_->assm_->EmitConstPoolWithJumpIfNeeded(margin);
  pool_->StartBlock();
}

ConstantPool::BlockScope::BlockScope(Assembler* assm, PoolEmissionCheck check)
    : pool_(&assm->constpool_) {
  DCHECK_EQ(check, PoolEmissionCheck::kSkip);
  pool_->StartBlock();
}

ConstantPool::BlockScope::~BlockScope() { pool_->EndBlock(); }

void ConstantPool::MaybeCheck() {
  if (assm_->pc_offset() >= next_check_) {
    Check(Emission::kIfNeeded, Jump::kRequired);
  }
}

#endif  // defined(V8_TARGET_ARCH_ARM64)

#if defined(V8_TARGET_ARCH_RISCV64) || defined(V8_TARGET_ARCH_RISCV32)

// Constant Pool.

ConstantPool::ConstantPool(Assembler* assm) : assm_(assm) {}
ConstantPool::~ConstantPool() { DCHECK_EQ(blocked_nesting_, 0); }

RelocInfoStatus ConstantPool::RecordEntry(uint32_t data,
                                          RelocInfo::Mode rmode) {
  ConstantPoolKey key(data, rmode);
  CHECK(key.is_value32());
  return RecordKey(std::move(key), assm_->pc_offset());
}

RelocInfoStatus ConstantPool::RecordEntry(uint64_t data,
                                          RelocInfo::Mode rmode) {
  ConstantPoolKey key(data, rmode);
  CHECK(!key.is_value32());
  return RecordKey(std::move(key), assm_->pc_offset());
}

RelocInfoStatus ConstantPool::RecordKey(ConstantPoolKey key, int offset) {
  RelocInfoStatus write_reloc_info = GetRelocInfoStatusFor(key);
  if (write_reloc_info == RelocInfoStatus::kMustRecord) {
    if (key.is_value32()) {
      if (entry32_count_ == 0) first_use_32_ = offset;
      ++entry32_count_;
    } else {
      if (entry64_count_ == 0) first_use_64_ = offset;
      ++entry64_count_;
    }
  }
  entries_.insert(std::make_pair(key, offset));

  if (Entry32Count() + Entry64Count() > ConstantPool::kApproxMaxEntryCount) {
    // Request constant pool emission after the next instruction.
    SetNextCheckIn(1);
  }

  return write_reloc_info;
}

RelocInfoStatus ConstantPool::GetRelocInfoStatusFor(
    const ConstantPoolKey& key) {
  if (key.AllowsDeduplication()) {
    auto existing = entries_.find(key);
    if (existing != entries_.end()) {
      return RelocInfoStatus::kMustOmitForDuplicate;
    }
  }
  return RelocInfoStatus::kMustRecord;
}

void ConstantPool::EmitAndClear(Jump require_jump) {
  DCHECK(!IsBlocked());
  // Prevent recursive pool emission.
  Assembler::BlockPoolsScope block_pools(assm_, PoolEmissionCheck::kSkip);
  Alignment require_alignment =
      IsAlignmentRequiredIfEmittedAt(require_jump, assm_->pc_offset());
  int size = ComputeSize(require_jump, require_alignment);
  Label size_check;
  assm_->bind(&size_check);
  assm_->RecordConstPool(size);

  // Emit the constant pool. It is preceded by an optional branch if
  // {require_jump} and a header which will:
  //  1) Encode the size of the constant pool, for use by the disassembler.
  //  2) Terminate the program, to try to prevent execution from accidentally
  //     flowing into the constant pool.
  //  3) align the 64bit pool entries to 64-bit.
  // TODO(all): Make the alignment part less fragile. Currently code is
  // allocated as a byte array so there are no guarantees the alignment will
  // be preserved on compaction. Currently it works as allocation seems to be
  // 64-bit aligned.
  DEBUG_PRINTF("\tConstant Pool start\n")
  Label after_pool;
  if (require_jump == Jump::kRequired) assm_->b(&after_pool);

  assm_->RecordComment("[ Constant Pool");

  EmitPrologue(require_alignment);
  if (require_alignment == Alignment::kRequired) assm_->DataAlign(kInt64Size);
  EmitEntries();
  assm_->RecordComment("]");
  assm_->bind(&after_pool);
  DEBUG_PRINTF("\tConstant Pool end\n")

  DCHECK_LE(assm_->SizeOfCodeGeneratedSince(&size_check) - size, 3);
  Clear();
}

void ConstantPool::Clear() {
  entries_.clear();
  first_use_32_ = -1;
  first_use_64_ = -1;
  entry32_count_ = 0;
  entry64_count_ = 0;
  next_check_ = 0;
}

void ConstantPool::StartBlock() {
  if (blocked_nesting_ == 0) {
    // Prevent constant pool checks from happening by setting the next check to
    // the biggest possible offset.
    next_check_ = kMaxInt;
  }
  ++blocked_nesting_;
}

void ConstantPool::EndBlock() {
  --blocked_nesting_;
  if (blocked_nesting_ == 0) {
    DCHECK(IsInImmRangeIfEmittedAt(assm_->pc_offset()));
    // Make sure a check happens quickly after getting unblocked.
    next_check_ = 0;
  }
}

bool ConstantPool::IsBlocked() const { return blocked_nesting_ > 0; }

void ConstantPool::SetNextCheckIn(size_t instructions) {
  next_check_ =
      assm_->pc_offset() + static_cast<int>(instructions * kInstrSize);
}

void ConstantPool::EmitEntries() {
  for (auto iter = entries_.begin(); iter != entries_.end();) {
    DCHECK(iter->first.is_value32() || IsAligned(assm_->pc_offset(), 8));
    auto range = entries_.equal_range(iter->first);
    bool shared = iter->first.AllowsDeduplication();
    for (auto it = range.first; it != range.second; ++it) {
      SetLoadOffsetToConstPoolEntry(it->second, assm_->pc(), it->first);
      if (!shared) Emit(it->first);
    }
    if (shared) Emit(iter->first);
    iter = range.second;
  }
}

void ConstantPool::Emit(const ConstantPoolKey& key) {
  if (key.is_value32()) {
    assm_->dd(key.value32());
  } else {
    assm_->dq(key.value64());
  }
}

bool ConstantPool::ShouldEmitNow(Jump require_jump, size_t margin) const {
  if (IsEmpty()) return false;
  if (Entry32Count() + Entry64Count() > ConstantPool::kApproxMaxEntryCount) {
    return true;
  }
  // We compute {dist32/64}, i.e. the distance from the first instruction
  // accessing a 32bit/64bit entry in the constant pool to any of the
  // 32bit/64bit constant pool entries, respectively. This is required because
  // we do not guarantee that entries are emitted in order of reference, i.e. it
  // is possible that the entry with the earliest reference is emitted last.
  // The constant pool should be emitted if either of the following is true:
  // (A) {dist32/64} will be out of range at the next check in.
  // (B) Emission can be done behind an unconditional branch and {dist32/64}
  // exceeds {kOpportunityDist*}.
  // (C) {dist32/64} exceeds the desired approximate distance to the pool.
  int worst_case_size = ComputeSize(Jump::kRequired, Alignment::kRequired);
  size_t pool_end_32 = assm_->pc_offset() + margin + worst_case_size;
  size_t pool_end_64 = pool_end_32 - Entry32Count() * kInt32Size;
  if (Entry64Count() != 0) {
    // The 64-bit constants are always emitted before the 32-bit constants, so
    // we subtract the size of the 32-bit constants from {size}.
    size_t dist64 = pool_end_64 - first_use_64_;
    bool next_check_too_late = dist64 + 2 * kCheckInterval >= kMaxDistToPool64;
    bool opportune_emission_without_jump =
        require_jump == Jump::kOmitted && (dist64 >= kOpportunityDistToPool64);
    bool approximate_distance_exceeded = dist64 >= kApproxDistToPool64;
    if (next_check_too_late || opportune_emission_without_jump ||
        approximate_distance_exceeded) {
      return true;
    }
  }
  if (Entry32Count() != 0) {
    size_t dist32 = pool_end_32 - first_use_32_;
    bool next_check_too_late = dist32 + 2 * kCheckInterval >= kMaxDistToPool32;
    bool opportune_emission_without_jump =
        require_jump == Jump::kOmitted && (dist32 >= kOpportunityDistToPool32);
    bool approximate_distance_exceeded = dist32 >= kApproxDistToPool32;
    if (next_check_too_late || opportune_emission_without_jump ||
        approximate_distance_exceeded) {
      return true;
    }
  }
  return false;
}

int ConstantPool::ComputeSize(Jump require_jump,
                              Alignment require_alignment) const {
  int size_up_to_marker = PrologueSize(require_jump);
  int alignment = require_alignment == Alignment::kRequired ? kInstrSize : 0;
  size_t size_after_marker =
      Entry32Count() * kInt32Size + alignment + Entry64Count() * kInt64Size;
  return size_up_to_marker + static_cast<int>(size_after_marker);
}

Alignment ConstantPool::IsAlignmentRequiredIfEmittedAt(Jump require_jump,
                                                       int pc_offset) const {
  int size_up_to_marker = PrologueSize(require_jump);
  if (Entry64Count() != 0 &&
      !IsAligned(pc_offset + size_up_to_marker, kInt64Size)) {
    return Alignment::kRequired;
  }
  return Alignment::kOmitted;
}

bool ConstantPool::IsInImmRangeIfEmittedAt(int pc_offset) {
  // Check that all entries are in range if the pool is emitted at {pc_offset}.
  // This ignores kPcLoadDelta (conservatively, since all offsets are positive),
  // and over-estimates the last entry's address with the pool's end.
  Alignment require_alignment =
      IsAlignmentRequiredIfEmittedAt(Jump::kRequired, pc_offset);
  size_t pool_end_32 =
      pc_offset + ComputeSize(Jump::kRequired, require_alignment);
  size_t pool_end_64 = pool_end_32 - Entry32Count() * kInt32Size;
  bool entries_in_range_32 =
      Entry32Count() == 0 || (pool_end_32 < first_use_32_ + kMaxDistToPool32);
  bool entries_in_range_64 =
      Entry64Count() == 0 || (pool_end_64 < first_use_64_ + kMaxDistToPool64);
  return entries_in_range_32 && entries_in_range_64;
}

ConstantPool::BlockScope::BlockScope(Assembler* assm, size_t margin)
    : pool_(&assm->constpool_) {
  pool_->assm_->EmitConstPoolWithJumpIfNeeded(margin);
  pool_->StartBlock();
}

ConstantPool::BlockScope::BlockScope(Assembler* assm, PoolEmissionCheck check)
    : pool_(&assm->constpool_) {
  DCHECK_EQ(check, PoolEmissionCheck::kSkip);
  pool_->StartBlock();
}

ConstantPool::BlockScope::~BlockScope() { pool_->EndBlock(); }

void ConstantPool::MaybeCheck() {
  if (assm_->pc_offset() >= next_check_) {
    Check(Emission::kIfNeeded, Jump::kRequired);
  }
}

#endif  // defined(V8_TARGET_ARCH_RISCV64) || defined(V8_TARGET_ARCH_RISCV32)

}  // namespace internal
}  // namespace v8
```