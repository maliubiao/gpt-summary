Response:
The user wants to understand the functionality of a specific C++ source code file in the V8 JavaScript engine. They've provided a snippet and are asking for a summary, similar to what would be expected for the second part of a six-part explanation.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Function:** The filename `instruction-selector-loong64.cc` strongly suggests this code is responsible for selecting specific LoongArch 64-bit instructions to implement higher-level operations within the V8 compiler. The presence of `Visit...` methods confirms this, as these are typical patterns in compiler instruction selection phases.

2. **Analyze the Code Snippet:**
    * **`GetStoreOpcode`:** This function takes a `MachineRepresentation` and returns a LoongArch store instruction opcode. It handles various data types, including floats, integers of different sizes, and tagged pointers. The `switch` statement is the core logic.
    * **`VisitLoad`:** This method handles loading values from memory. It determines the appropriate load opcode based on the data type and potential memory protection mechanisms.
    * **`VisitProtectedLoad`:**  This seems like a specialized version of `VisitLoad` for protected memory accesses.
    * **`VisitStorePair`:** This is marked as `UNREACHABLE`, suggesting it's not currently implemented for LoongArch.
    * **`VisitStore`:** This is the most complex part of the snippet. It handles storing values to memory, including logic for write barriers (for garbage collection) and optimized handling of external constants and root register accesses. It also chooses the store opcode based on the data representation.
    * **`VisitProtectedStore`:** Similar to `VisitProtectedLoad`, likely for protected memory writes.
    * **`VisitWord32And`, `VisitWord64And`, etc.:** These methods handle bitwise logical operations. The code includes optimizations that try to map common patterns of bitwise operations and shifts to more efficient LoongArch instructions like `Bstrpick` and `Bstrins`.
    * **`VisitWord32Shl`, `VisitWord64Shl`, etc.:** These methods handle shift operations, including optimizations for combining shifts with bitmasks.
    * **`VisitInt32Add`, `VisitInt64Add`, etc.:** These methods handle arithmetic operations, again with optimizations, such as using the `Alsl` instruction for add-shift combinations.

3. **Infer Overall Functionality:** Based on the individual methods, the file's main purpose is to translate V8's intermediate representation (IR) of operations into concrete LoongArch 64-bit machine instructions. This involves:
    * **Opcode Selection:** Choosing the correct LoongArch instruction based on the operation and data type.
    * **Optimization:** Identifying patterns in the IR that can be implemented more efficiently using specific LoongArch instructions.
    * **Memory Access Handling:**  Dealing with loading and storing data, including considerations for memory protection and garbage collection write barriers.
    * **Instruction Emission:**  Generating the final machine code.

4. **Address Specific Questions in the Prompt:**
    * **`.tq` extension:**  The code snippet is C++, not Torque, so the answer is no.
    * **Relationship to JavaScript:** This code directly enables the execution of JavaScript. It's the bridge between the abstract JavaScript operations and the concrete hardware instructions. An example would be a JavaScript addition (`a + b`) being translated by `VisitInt32Add` or `VisitInt64Add` into a LoongArch `add.w` or `add.d` instruction.
    * **Code Logic Reasoning (Assumption/Output):**  For `GetStoreOpcode`, if the input is `MachineRepresentation::kWord32`, the output will be `kLoong64St_w`. For the bitwise operations, input could be IR nodes representing `a & b`, and the output would be a LoongArch `and` instruction (potentially optimized).
    * **Common Programming Errors:**  This part of the compiler doesn't directly *cause* common *user* programming errors. However, incorrect logic here *could* lead to incorrect code generation, which would manifest as unexpected behavior in the JavaScript program. A subtle bug in the write barrier logic, for example, could lead to memory corruption.
    * **Part 2 Summary:** Focus on the key functions within this specific snippet – primarily the load, store, and basic arithmetic/logical operations, highlighting the opcode selection and optimization aspects.

5. **Structure the Answer:** Organize the information logically, addressing each point from the prompt. Start with a high-level summary and then go into more detail about the specific functionalities. Use clear and concise language.

By following these steps, a comprehensive and accurate answer can be constructed that addresses all aspects of the user's request.
这是 V8 源代码文件 `v8/src/compiler/backend/loong64/instruction-selector-loong64.cc` 的第二部分，其主要功能是 **将 V8 的中间表示 (IR) 转换为 LoongArch 64 位架构的机器指令**。

让我们分解一下代码片段的功能：

**1. `GetStoreOpcode(MachineRepresentation rep)` 函数:**

* **功能:**  根据给定的 `MachineRepresentation` (机器表示，例如 `kFloat32`, `kWord64`, `kTagged`)，返回对应的 LoongArch 存储指令的操作码 (InstructionCode)。
* **代码逻辑推理:**
    * **假设输入:** `MachineRepresentation::kWord32`
    * **输出:** `kLoong64St_w` (LoongArch 存储字 (32位) 的指令)
    * **假设输入:** `MachineRepresentation::kTagged`
    * **输出:** `kLoong64StoreCompressTagged` (LoongArch 存储压缩标签指针的指令)
* **与 JavaScript 的关系:** 当 JavaScript 代码需要将一个值存储到内存中时，V8 的编译器会生成相应的 IR 节点。`GetStoreOpcode` 函数会根据存储值的类型（例如，一个数字、一个对象引用）选择正确的 LoongArch 存储指令。
    * **JavaScript 示例:**
      ```javascript
      let x = 10;
      let obj = { value: 20 };
      ```
      当执行这两行代码时，编译器会生成存储 `x` (可能是 `kWord32` 或 `kWord64` 表示) 和 `obj` (可能是 `kTagged` 表示) 的指令。

**2. `VisitLoad(node_t node)` 函数:**

* **功能:** 处理 IR 中的 Load 节点，生成对应的 LoongArch 加载指令。它会根据加载值的类型调用 `GetLoadOpcode` (代码片段中未包含，但逻辑类似)。同时，它还会处理受保护内存访问的情况。
* **代码逻辑推理:**  `VisitLoad` 根据 `load.loaded_rep()` 获取加载的数据类型，然后调用 `GetLoadOpcode` 获取相应的加载指令码。 对于受保护的内存访问，它会设置 `AccessModeField` 以指示是否需要处理空指针解引用或其他越界错误。

**3. `VisitProtectedLoad(node_t node)` 函数:**

* **功能:**  专门处理受保护的 Load 节点，它直接调用了 `VisitLoad`，表明在指令选择层面，受保护加载和普通加载的主要区别在于指令码中 `AccessModeField` 的设置。

**4. `VisitStorePair(node_t node)` 函数:**

* **功能:**  处理存储一对值的节点。当前实现为 `UNREACHABLE()`，表示 LoongArch 平台尚未实现该功能。

**5. `VisitStore(typename Adapter::node_t node)` 函数:**

* **功能:** 处理 IR 中的 Store 节点，生成对应的 LoongArch 存储指令。这是该代码片段中最复杂的部分。
* **主要逻辑:**
    * **获取存储信息:** 从 `store_view` 中获取存储的基地址、索引、值以及存储的数据类型 (`rep`) 和写入屏障类型 (`write_barrier_kind`)。
    * **写入屏障处理:** 如果需要写入屏障 (用于垃圾回收)，则会生成带有写入屏障的存储指令 (`kArchStoreWithWriteBarrier` 或 `kArchStoreIndirectWithWriteBarrier`)。写入屏障用于确保垃圾回收器能够正确追踪对象引用。
    * **优化:**
        * **外部常量和根寄存器:** 尝试优化存储到基于外部常量或根寄存器的内存位置的情况，使用更高效的寻址模式 (`kMode_Root`)。
    * **普通存储:** 如果不需要写入屏障，则根据 `rep` 调用 `GetStoreOpcode` 获取存储指令码，并根据基地址和索引是否为立即数选择不同的寻址模式 (`kMode_MRI` 或 `kMode_MRR`)。
    * **受保护存储:**  处理带有陷阱的存储，设置 `AccessModeField` 以指示是否需要在空指针解引用时触发陷阱。
* **与 JavaScript 的关系:** 当 JavaScript 代码执行赋值操作时，例如 `object.property = value;` 或 `array[index] = value;`，`VisitStore` 函数负责生成将 `value` 存储到 `object.property` 或 `array[index]` 所在内存位置的 LoongArch 指令。
* **用户常见的编程错误:** 如果编译器或运行时系统在处理写入屏障时出现错误，可能会导致内存损坏，这在 JavaScript 中会表现为意外的程序行为或崩溃。例如，如果写入屏障没有正确记录一个对象引用的更新，垃圾回收器可能会错误地回收该对象，导致后续访问时出现问题。

**6. `VisitProtectedStore(node_t node)` 函数:**

* **功能:** 专门处理受保护的 Store 节点，它直接调用了 `VisitStore`，与 `VisitProtectedLoad` 类似，主要区别在于指令码中 `AccessModeField` 的设置。

**7. `VisitWord32And(node)`，`VisitWord64And(node)` 等位运算函数:**

* **功能:**  处理按位与、或、异或等运算。这些函数会尝试进行一些优化，例如将特定的按位与和移位操作组合成更高效的 LoongArch 指令 (`kLoong64Bstrpick_w`, `kLoong64Bstrins_w`)。
* **与 JavaScript 的关系:**  当 JavaScript 代码中使用位运算符 (如 `&`, `|`, `^`) 时，这些函数负责将其转换为对应的 LoongArch 指令。
    * **JavaScript 示例:**
      ```javascript
      let a = 0b1010;
      let b = 0b1100;
      let c = a & b; // 按位与
      ```
      `VisitWord32And` (或 `VisitWord64And`，取决于变量的大小) 会处理 `a & b` 的操作。

**8. `VisitWord32Shl(node)`，`VisitWord64Shr(node)` 等移位运算函数:**

* **功能:** 处理左移、右移等移位运算，同样会尝试进行优化，例如将移位与掩码操作组合成 `Bstrpick` 指令。
* **与 JavaScript 的关系:**  当 JavaScript 代码中使用移位运算符 (`<<`, `>>`, `>>>`) 时，这些函数负责将其转换为对应的 LoongArch 指令.

**9. `VisitInt32Add(node)`，`VisitInt64Sub(node)` 等算术运算函数:**

* **功能:** 处理加法、减法等算术运算，部分函数会尝试进行特定于 LoongArch 的优化，例如使用 `kLoong64Alsl_w` (带移位的加法) 指令。
* **与 JavaScript 的关系:** 当 JavaScript 代码执行算术运算时，这些函数负责将其转换为对应的 LoongArch 指令。

**归纳一下它的功能 (作为第 2 部分):**

这部分代码主要负责 **LoongArch 架构下的基本指令选择**，涵盖了：

* **内存访问指令的选择:**  根据数据类型和是否需要写入屏障，选择合适的加载和存储指令。
* **基本算术和逻辑运算指令的选择:** 将 V8 IR 中的加减乘除、位运算、移位等操作转换为对应的 LoongArch 指令。
* **特定于 LoongArch 的指令优化:** 尝试将一些常见的操作模式 (例如，带掩码的移位、带移位的加法) 映射到更高效的 LoongArch 指令，以提升性能。
* **处理受保护的内存访问:**  为加载和存储操作添加对受保护内存访问的支持。

总而言之，这部分代码是 V8 编译器后端将高级语言操作转换为底层硬件指令的关键组成部分，它确保了 JavaScript 代码能够在 LoongArch 64 位架构上正确高效地执行。

### 提示词
```
这是目录为v8/src/compiler/backend/loong64/instruction-selector-loong64.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/backend/loong64/instruction-selector-loong64.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
switch (rep) {
    case MachineRepresentation::kFloat32:
      return kLoong64Fst_s;
    case MachineRepresentation::kFloat64:
      return kLoong64Fst_d;
    case MachineRepresentation::kBit:
    case MachineRepresentation::kWord8:
      return kLoong64St_b;
    case MachineRepresentation::kWord16:
      return kLoong64St_h;
    case MachineRepresentation::kWord32:
      return kLoong64St_w;
    case MachineRepresentation::kWord64:
      return kLoong64St_d;
    case MachineRepresentation::kTaggedSigned:
    case MachineRepresentation::kTaggedPointer:
    case MachineRepresentation::kTagged:
      return kLoong64StoreCompressTagged;
    case MachineRepresentation::kCompressedPointer:
    case MachineRepresentation::kCompressed:
#ifdef V8_COMPRESS_POINTERS
      return kLoong64StoreCompressTagged;
#else
      UNREACHABLE();
#endif
    case MachineRepresentation::kSandboxedPointer:
      return kLoong64StoreEncodeSandboxedPointer;
    case MachineRepresentation::kIndirectPointer:
      return kLoong64StoreIndirectPointer;
    case MachineRepresentation::kFloat16:
      UNIMPLEMENTED();
    case MachineRepresentation::kMapWord:
    case MachineRepresentation::kNone:
    case MachineRepresentation::kSimd128:
    case MachineRepresentation::kSimd256:
    case MachineRepresentation::kProtectedPointer:
      // We never store directly to protected pointers from generated code.
      UNREACHABLE();
  }
}
}  // namespace

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitLoad(node_t node) {
  {
    auto load = this->load_view(node);
    LoadRepresentation load_rep = load.loaded_rep();
    InstructionCode opcode = kArchNop;

    if constexpr (Adapter::IsTurboshaft) {
      opcode = GetLoadOpcode(load.ts_loaded_rep(), load.ts_result_rep());
    } else {
      opcode = GetLoadOpcode(load_rep);
    }

    bool traps_on_null;
    if (load.is_protected(&traps_on_null)) {
      if (traps_on_null) {
        opcode |=
            AccessModeField::encode(kMemoryAccessProtectedNullDereference);
      } else {
        opcode |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
      }
    }

    EmitLoad(this, node, opcode);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedLoad(node_t node) {
  VisitLoad(node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStorePair(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitStore(typename Adapter::node_t node) {
  Loong64OperandGeneratorT<Adapter> g(this);
  typename Adapter::StoreView store_view = this->store_view(node);
  DCHECK_EQ(store_view.displacement(), 0);
  node_t base = store_view.base();
  node_t index = this->value(store_view.index());
  node_t value = store_view.value();

  WriteBarrierKind write_barrier_kind =
      store_view.stored_rep().write_barrier_kind();
  const MachineRepresentation rep = store_view.stored_rep().representation();

  if (v8_flags.enable_unconditional_write_barriers &&
      CanBeTaggedOrCompressedPointer(rep)) {
    write_barrier_kind = kFullWriteBarrier;
  }

  // TODO(loong64): I guess this could be done in a better way.
  if (write_barrier_kind != kNoWriteBarrier &&
      !v8_flags.disable_write_barriers) {
    DCHECK(CanBeTaggedOrCompressedOrIndirectPointer(rep));
    AddressingMode addressing_mode;
    InstructionOperand inputs[4];
    size_t input_count = 0;
    inputs[input_count++] = g.UseUniqueRegister(base);
    // OutOfLineRecordWrite uses the index in an arithmetic instruction, so we
    // must check kArithmeticImm as well as kLoadStoreImm64.
    if (g.CanBeImmediate(index, kLoong64Add_d)) {
      inputs[input_count++] = g.UseImmediate(index);
      addressing_mode = kMode_MRI;
    } else {
      inputs[input_count++] = g.UseUniqueRegister(index);
      addressing_mode = kMode_MRR;
    }
    inputs[input_count++] = g.UseUniqueRegister(value);
    RecordWriteMode record_write_mode =
        WriteBarrierKindToRecordWriteMode(write_barrier_kind);
    InstructionCode code;
    if (rep == MachineRepresentation::kIndirectPointer) {
      DCHECK_EQ(write_barrier_kind, kIndirectPointerWriteBarrier);
      // In this case we need to add the IndirectPointerTag as additional input.
      code = kArchStoreIndirectWithWriteBarrier;
      IndirectPointerTag tag = store_view.indirect_pointer_tag();
      inputs[input_count++] = g.UseImmediate64(static_cast<int64_t>(tag));
    } else {
      code = kArchStoreWithWriteBarrier;
    }
    code |= AddressingModeField::encode(addressing_mode);
    code |= RecordWriteModeField::encode(record_write_mode);
    if (store_view.is_store_trap_on_null()) {
      code |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
    }
    Emit(code, 0, nullptr, input_count, inputs);
    return;
  }

  MachineRepresentation approx_rep = rep;
  InstructionCode code;
  if constexpr (Adapter::IsTurboshaft) {
    code = GetStoreOpcode(store_view.ts_stored_rep());
  } else {
    code = GetStoreOpcode(approx_rep);
  }

  std::optional<ExternalReference> external_base;
  if constexpr (Adapter::IsTurboshaft) {
    ExternalReference value;
    if (this->MatchExternalConstant(base, &value)) {
      external_base = value;
    }
  } else {
    ExternalReferenceMatcher m(base);
    if (m.HasResolvedValue()) {
      external_base = m.ResolvedValue();
    }
  }

  std::optional<int64_t> constant_index;
  if (this->valid(store_view.index())) {
    node_t index = this->value(store_view.index());
    constant_index = g.GetOptionalIntegerConstant(index);
  }
  if (external_base.has_value() && constant_index.has_value() &&
      CanAddressRelativeToRootsRegister(*external_base)) {
    ptrdiff_t const delta =
        *constant_index +
        MacroAssemblerBase::RootRegisterOffsetForExternalReference(
            isolate(), *external_base);
    // Check that the delta is a 32-bit integer due to the limitations of
    // immediate operands.
    if (is_int32(delta)) {
      Emit(code | AddressingModeField::encode(kMode_Root), g.NoOutput(),
           g.UseImmediate(static_cast<int32_t>(delta)),
           g.UseRegisterOrImmediateZero(value));
      return;
    }
  }

  if (this->is_load_root_register(base)) {
    // This will only work if {index} is a constant.
    Emit(code | AddressingModeField::encode(kMode_Root), g.NoOutput(),
         g.UseImmediate(index), g.UseRegisterOrImmediateZero(value));
    return;
  }

  if (store_view.is_store_trap_on_null()) {
    code |= AccessModeField::encode(kMemoryAccessProtectedNullDereference);
  } else if (store_view.access_kind() ==
             MemoryAccessKind::kProtectedByTrapHandler) {
    code |= AccessModeField::encode(kMemoryAccessProtectedMemOutOfBounds);
  }

  if (g.CanBeImmediate(index, code)) {
    Emit(code | AddressingModeField::encode(kMode_MRI), g.NoOutput(),
         g.UseRegister(base), g.UseImmediate(index),
         g.UseRegisterOrImmediateZero(value));
  } else {
    Emit(code | AddressingModeField::encode(kMode_MRR), g.NoOutput(),
         g.UseRegister(base), g.UseRegister(index),
         g.UseRegisterOrImmediateZero(value));
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitProtectedStore(node_t node) {
  VisitStore(node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32And(
    turboshaft::OpIndex node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64And32, true, kLoong64And32);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32And(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.left().IsWord32Shr() && CanCover(node, m.left().node()) &&
      m.right().HasResolvedValue()) {
    uint32_t mask = m.right().ResolvedValue();
    uint32_t mask_width = base::bits::CountPopulation(mask);
    uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
    if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));

      // Select Bstrpick_w for And(Shr(x, imm), mask) where the mask is in the
      // least significant bits.
      Int32BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        // Any shift value can match; int32 shifts use `value % 32`.
        uint32_t lsb = mleft.right().ResolvedValue() & 0x1F;

        // Bstrpick_w cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use Bstrpick_w with a smaller mask and the remaining bits will
        // be zeros.
        if (lsb + mask_width > 32) mask_width = 32 - lsb;

        Emit(kLoong64Bstrpick_w, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()), g.TempImmediate(lsb),
             g.TempImmediate(mask_width));
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  if (m.right().HasResolvedValue()) {
    uint32_t mask = m.right().ResolvedValue();
    uint32_t shift = base::bits::CountPopulation(~mask);
    uint32_t msb = base::bits::CountLeadingZeros32(~mask);
    if (shift != 0 && shift != 32 && msb + shift == 32) {
      // Insert zeros for (x >> K) << K => x & ~(2^K - 1) expression reduction
      // and remove constant loading of inverted mask.
      Emit(kLoong64Bstrins_w, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.TempImmediate(0),
           g.TempImmediate(shift));
      return;
    }
  }
  VisitBinop(this, node, kLoong64And32, true, kLoong64And32);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64And(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64And, true, kLoong64And);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64And(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int64BinopMatcher m(node);
  if (m.left().IsWord64Shr() && CanCover(node, m.left().node()) &&
      m.right().HasResolvedValue()) {
    uint64_t mask = m.right().ResolvedValue();
    uint32_t mask_width = base::bits::CountPopulation(mask);
    uint32_t mask_msb = base::bits::CountLeadingZeros64(mask);
    if ((mask_width != 0) && (mask_msb + mask_width == 64)) {
      // The mask must be contiguous, and occupy the least-significant bits.
      DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));

      // Select Bstrpick_d for And(Shr(x, imm), mask) where the mask is in the
      // least significant bits.
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        // Any shift value can match; int64 shifts use `value % 64`.
        uint32_t lsb =
            static_cast<uint32_t>(mleft.right().ResolvedValue() & 0x3F);

        // Bstrpick_d cannot extract bits past the register size, however since
        // shifting the original value would have introduced some zeros we can
        // still use Bstrpick_d with a smaller mask and the remaining bits will
        // be zeros.
        if (lsb + mask_width > 64) mask_width = 64 - lsb;

        if (lsb == 0 && mask_width == 64) {
          Emit(kArchNop, g.DefineSameAsFirst(node), g.Use(mleft.left().node()));
        } else {
          Emit(kLoong64Bstrpick_d, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(lsb),
               g.TempImmediate(static_cast<int32_t>(mask_width)));
        }
        return;
      }
      // Other cases fall through to the normal And operation.
    }
  }
  if (m.right().HasResolvedValue()) {
    uint64_t mask = m.right().ResolvedValue();
    uint32_t shift = base::bits::CountPopulation(~mask);
    uint32_t msb = base::bits::CountLeadingZeros64(~mask);
    if (shift != 0 && shift < 32 && msb + shift == 64) {
      // Insert zeros for (x >> K) << K => x & ~(2^K - 1) expression reduction
      // and remove constant loading of inverted mask. Dins cannot insert bits
      // past word size, so shifts smaller than 32 are covered.
      Emit(kLoong64Bstrins_d, g.DefineSameAsFirst(node),
           g.UseRegister(m.left().node()), g.TempImmediate(0),
           g.TempImmediate(shift));
      return;
    }
  }
  VisitBinop(this, node, kLoong64And, true, kLoong64And);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Or(node_t node) {
  VisitBinop(this, node, kLoong64Or32, true, kLoong64Or32);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Or(node_t node) {
  VisitBinop(this, node, kLoong64Or, true, kLoong64Or);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    // TODO(LOONG_dev): May could be optimized like in Turbofan.
    VisitBinop(this, node, kLoong64Xor32, true, kLoong64Xor32);
  } else {
    Int32BinopMatcher m(node);
    if (m.left().IsWord32Or() && CanCover(node, m.left().node()) &&
        m.right().Is(-1)) {
      Int32BinopMatcher mleft(m.left().node());
      if (!mleft.right().HasResolvedValue()) {
        Loong64OperandGeneratorT<Adapter> g(this);
        Emit(kLoong64Nor32, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(mleft.right().node()));
        return;
      }
    }
    if (m.right().Is(-1)) {
      // Use Nor for bit negation and eliminate constant loading for xori.
      Loong64OperandGeneratorT<Adapter> g(this);
      Emit(kLoong64Nor32, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.TempImmediate(0));
      return;
    }
    VisitBinop(this, node, kLoong64Xor32, true, kLoong64Xor32);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Xor(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    // TODO(LOONG_dev): May could be optimized like in Turbofan.
    VisitBinop(this, node, kLoong64Xor, true, kLoong64Xor);
  } else {
    Int64BinopMatcher m(node);
    if (m.left().IsWord64Or() && CanCover(node, m.left().node()) &&
        m.right().Is(-1)) {
      Int64BinopMatcher mleft(m.left().node());
      if (!mleft.right().HasResolvedValue()) {
        Loong64OperandGeneratorT<Adapter> g(this);
        Emit(kLoong64Nor, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(mleft.right().node()));
        return;
      }
    }
    if (m.right().Is(-1)) {
      // Use Nor for bit negation and eliminate constant loading for xori.
      Loong64OperandGeneratorT<Adapter> g(this);
      Emit(kLoong64Nor, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.TempImmediate(0));
      return;
    }
    VisitBinop(this, node, kLoong64Xor, true, kLoong64Xor);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Shl(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitRRO(this, kLoong64Sll_w, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Shl(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().IsWord32And() && CanCover(node, m.left().node()) &&
      m.right().IsInRange(1, 31)) {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    Int32BinopMatcher mleft(m.left().node());
    // Match Word32Shl(Word32And(x, mask), imm) to Sll_w where the mask is
    // contiguous, and the shift immediate non-zero.
    if (mleft.right().HasResolvedValue()) {
      uint32_t mask = mleft.right().ResolvedValue();
      uint32_t mask_width = base::bits::CountPopulation(mask);
      uint32_t mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_width != 0) && (mask_msb + mask_width == 32)) {
        uint32_t shift = m.right().ResolvedValue();
        DCHECK_EQ(0u, base::bits::CountTrailingZeros32(mask));
        DCHECK_NE(0u, shift);
        if ((shift + mask_width) >= 32) {
          // If the mask is contiguous and reaches or extends beyond the top
          // bit, only the shift is needed.
          Emit(kLoong64Sll_w, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()),
               g.UseImmediate(m.right().node()));
          return;
        }
      }
    }
  }
  VisitRRO(this, kLoong64Sll_w, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Shr(node_t node) {
  VisitRRO(this, kLoong64Srl_w, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Shr(Node* node) {
  Int32BinopMatcher m(node);
  if (m.left().IsWord32And() && m.right().HasResolvedValue()) {
    uint32_t lsb = m.right().ResolvedValue() & 0x1F;
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() &&
        mleft.right().ResolvedValue() != 0) {
      // Select Bstrpick_w for Shr(And(x, mask), imm) where the result of the
      // mask is shifted into the least-significant bits.
      uint32_t mask = (mleft.right().ResolvedValue() >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros32(mask);
      if ((mask_msb + mask_width + lsb) == 32) {
        Loong64OperandGeneratorT<TurbofanAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros32(mask));
        Emit(kLoong64Bstrpick_w, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()), g.TempImmediate(lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  }
  VisitRRO(this, kLoong64Srl_w, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord32Sar(
    turboshaft::OpIndex node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitRRO(this, kLoong64Sra_w, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord32Sar(Node* node) {
  Int32BinopMatcher m(node);
  if (CanCover(node, m.left().node())) {
    Loong64OperandGeneratorT<TurbofanAdapter> g(this);
    if (m.left().IsWord32Shl()) {
      Int32BinopMatcher mleft(m.left().node());
      if (m.right().HasResolvedValue() && mleft.right().HasResolvedValue()) {
        uint32_t sar = m.right().ResolvedValue();
        uint32_t shl = mleft.right().ResolvedValue();
        if ((sar == shl) && (sar == 16)) {
          Emit(kLoong64Ext_w_h, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()));
          return;
        } else if ((sar == shl) && (sar == 24)) {
          Emit(kLoong64Ext_w_b, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()));
          return;
        } else if ((sar == shl) && (sar == 32)) {
          Emit(kLoong64Sll_w, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()), g.TempImmediate(0));
          return;
        }
      }
    } else if (m.left().IsTruncateInt64ToInt32()) {
      Emit(kLoong64Sra_w, g.DefineAsRegister(node),
           g.UseRegister(m.left().InputAt(0)),
           g.UseOperand(node->InputAt(1), kLoong64Sra_w));
      return;
    }
  }
  VisitRRO(this, kLoong64Sra_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Shl(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    using namespace turboshaft;  // NOLINT(build/namespaces)
    const ShiftOp& shift_op = this->Get(node).template Cast<ShiftOp>();
    const Operation& lhs = this->Get(shift_op.left());
    const Operation& rhs = this->Get(shift_op.right());
    if ((lhs.Is<Opmask::kChangeInt32ToInt64>() ||
         lhs.Is<Opmask::kChangeUint32ToUint64>()) &&
        rhs.Is<Opmask::kWord32Constant>()) {
      int64_t shift_by = rhs.Cast<ConstantOp>().signed_integral();
      if (base::IsInRange(shift_by, 32, 63) &&
          CanCover(node, shift_op.left())) {
        Loong64OperandGeneratorT<Adapter> g(this);
        // There's no need to sign/zero-extend to 64-bit if we shift out the
        // upper 32 bits anyway.
        Emit(kLoong64Sll_d, g.DefineAsRegister(node),
             g.UseRegister(lhs.Cast<ChangeOp>().input()),
             g.UseImmediate(shift_by));
        return;
      }
    }
    VisitRRO(this, kLoong64Sll_d, node);
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);
    if ((m.left().IsChangeInt32ToInt64() ||
         m.left().IsChangeUint32ToUint64()) &&
        m.right().IsInRange(32, 63) && CanCover(node, m.left().node())) {
      // There's no need to sign/zero-extend to 64-bit if we shift out the upper
      // 32 bits anyway.
      Emit(kLoong64Sll_d, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()->InputAt(0)),
           g.UseImmediate(m.right().node()));
      return;
    }
    if (m.left().IsWord64And() && CanCover(node, m.left().node()) &&
        m.right().IsInRange(1, 63)) {
      // Match Word64Shl(Word64And(x, mask), imm) to Sll_d where the mask is
      // contiguous, and the shift immediate non-zero.
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue()) {
        uint64_t mask = mleft.right().ResolvedValue();
        uint32_t mask_width = base::bits::CountPopulation(mask);
        uint32_t mask_msb = base::bits::CountLeadingZeros64(mask);
        if ((mask_width != 0) && (mask_msb + mask_width == 64)) {
          uint64_t shift = m.right().ResolvedValue();
          DCHECK_EQ(0u, base::bits::CountTrailingZeros64(mask));
          DCHECK_NE(0u, shift);

          if ((shift + mask_width) >= 64) {
            // If the mask is contiguous and reaches or extends beyond the top
            // bit, only the shift is needed.
            Emit(kLoong64Sll_d, g.DefineAsRegister(node),
                 g.UseRegister(mleft.left().node()),
                 g.UseImmediate(m.right().node()));
            return;
          }
        }
      }
    }
    VisitRRO(this, kLoong64Sll_d, node);
  }
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Shr(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitRRO(this, kLoong64Srl_d, node);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitWord64Shr(Node* node) {
  Int64BinopMatcher m(node);
  if (m.left().IsWord64And() && m.right().HasResolvedValue()) {
    uint32_t lsb = m.right().ResolvedValue() & 0x3F;
    Int64BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() &&
        mleft.right().ResolvedValue() != 0) {
      // Select Bstrpick_d for Shr(And(x, mask), imm) where the result of the
      // mask is shifted into the least-significant bits.
      uint64_t mask = (mleft.right().ResolvedValue() >> lsb) << lsb;
      unsigned mask_width = base::bits::CountPopulation(mask);
      unsigned mask_msb = base::bits::CountLeadingZeros64(mask);
      if ((mask_msb + mask_width + lsb) == 64) {
        Loong64OperandGeneratorT<TurbofanAdapter> g(this);
        DCHECK_EQ(lsb, base::bits::CountTrailingZeros64(mask));
        Emit(kLoong64Bstrpick_d, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()), g.TempImmediate(lsb),
             g.TempImmediate(mask_width));
        return;
      }
    }
  }
  VisitRRO(this, kLoong64Srl_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Sar(node_t node) {
    if (TryEmitExtendingLoad(this, node, node)) return;

    Int64BinopMatcher m(node);
    if (m.left().IsChangeInt32ToInt64() && m.right().HasResolvedValue() &&
        is_uint5(m.right().ResolvedValue()) &&
        CanCover(node, m.left().node())) {
      if ((m.left().InputAt(0)->opcode() != IrOpcode::kLoad &&
           m.left().InputAt(0)->opcode() != IrOpcode::kLoadImmutable) ||
          !CanCover(m.left().node(), m.left().InputAt(0))) {
        Loong64OperandGeneratorT<Adapter> g(this);
        Emit(kLoong64Sra_w, g.DefineAsRegister(node),
             g.UseRegister(m.left().node()->InputAt(0)),
             g.UseImmediate(m.right().node()));
        return;
      }
    }

    VisitRRO(this, kLoong64Sra_d, node);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitWord64Sar(node_t node) {
  using namespace turboshaft;  // NOLINT(build/namespaces)
  if (TryEmitExtendingLoad(this, node, node)) return;

  // Select Sbfx(x, imm, 32-imm) for Word64Sar(ChangeInt32ToInt64(x), imm)
  // where possible
  const ShiftOp& shiftop = Get(node).Cast<ShiftOp>();
  const Operation& lhs = Get(shiftop.left());

  int64_t constant_rhs;
  if (lhs.Is<Opmask::kChangeInt32ToInt64>() &&
      MatchIntegralWord64Constant(shiftop.right(), &constant_rhs) &&
      is_uint5(constant_rhs) && CanCover(node, shiftop.left())) {
    OpIndex input = lhs.Cast<ChangeOp>().input();
    if (!Get(input).Is<LoadOp>() || !CanCover(shiftop.left(), input)) {
      Loong64OperandGeneratorT<TurboshaftAdapter> g(this);
      int right = static_cast<int>(constant_rhs);
      Emit(kLoong64Sra_w, g.DefineAsRegister(node), g.UseRegister(input),
           g.UseImmediate(right));
      return;
    }
  }

  VisitRRO(this, kLoong64Sra_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Rol(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ror(node_t node) {
  VisitRRO(this, kLoong64Rotr_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ror(node_t node) {
  VisitRRO(this, kLoong64Rotr_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBits(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32ReverseBytes(node_t node) {
  VisitRR(this, kLoong64ByteSwap32, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64ReverseBytes(node_t node) {
  VisitRR(this, kLoong64ByteSwap64, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitSimd128ReverseBytes(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Clz(node_t node) {
  VisitRR(this, kLoong64Clz_w, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Clz(node_t node) {
  VisitRR(this, kLoong64Clz_d, node);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Ctz(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord32Popcnt(node_t node) {
  UNREACHABLE();
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitWord64Popcnt(node_t node) {
  UNREACHABLE();
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Add(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64Add_w, true, kLoong64Add_w);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Add(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);

  // Select Alsl_w for (left + (left_of_right << imm)).
  if (m.right().opcode() == IrOpcode::kWord32Shl &&
      CanCover(node, m.left().node()) && CanCover(node, m.right().node())) {
    Int32BinopMatcher mright(m.right().node());
    if (mright.right().HasResolvedValue() && !m.left().HasResolvedValue()) {
      int32_t shift_value =
          static_cast<int32_t>(mright.right().ResolvedValue());
      if (shift_value > 0 && shift_value <= 31) {
        Emit(kLoong64Alsl_w, g.DefineAsRegister(node),
             g.UseRegister(mright.left().node()),
             g.UseRegister(m.left().node()), g.TempImmediate(shift_value));
        return;
      }
    }
  }

  // Select Alsl_w for ((left_of_left << imm) + right).
  if (m.left().opcode() == IrOpcode::kWord32Shl &&
      CanCover(node, m.right().node()) && CanCover(node, m.left().node())) {
    Int32BinopMatcher mleft(m.left().node());
    if (mleft.right().HasResolvedValue() && !m.right().HasResolvedValue()) {
      int32_t shift_value = static_cast<int32_t>(mleft.right().ResolvedValue());
      if (shift_value > 0 && shift_value <= 31) {
        Emit(kLoong64Alsl_w, g.DefineAsRegister(node),
             g.UseRegister(mleft.left().node()),
             g.UseRegister(m.right().node()), g.TempImmediate(shift_value));
        return;
      }
    }
  }

  VisitBinop(this, node, kLoong64Add_w, true, kLoong64Add_w);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Add(node_t node) {
  if constexpr (Adapter::IsTurboshaft) {
    // TODO(LOONG_dev): May could be optimized like in Turbofan.
    VisitBinop(this, node, kLoong64Add_d, true, kLoong64Add_d);
  } else {
    Loong64OperandGeneratorT<Adapter> g(this);
    Int64BinopMatcher m(node);

    // Select Alsl_d for (left + (left_of_right << imm)).
    if (m.right().opcode() == IrOpcode::kWord64Shl &&
        CanCover(node, m.left().node()) && CanCover(node, m.right().node())) {
      Int64BinopMatcher mright(m.right().node());
      if (mright.right().HasResolvedValue() && !m.left().HasResolvedValue()) {
        int32_t shift_value =
            static_cast<int32_t>(mright.right().ResolvedValue());
        if (shift_value > 0 && shift_value <= 31) {
          Emit(kLoong64Alsl_d, g.DefineAsRegister(node),
               g.UseRegister(mright.left().node()),
               g.UseRegister(m.left().node()), g.TempImmediate(shift_value));
          return;
        }
      }
    }

    // Select Alsl_d for ((left_of_left << imm) + right).
    if (m.left().opcode() == IrOpcode::kWord64Shl &&
        CanCover(node, m.right().node()) && CanCover(node, m.left().node())) {
      Int64BinopMatcher mleft(m.left().node());
      if (mleft.right().HasResolvedValue() && !m.right().HasResolvedValue()) {
        int32_t shift_value =
            static_cast<int32_t>(mleft.right().ResolvedValue());
        if (shift_value > 0 && shift_value <= 31) {
          Emit(kLoong64Alsl_d, g.DefineAsRegister(node),
               g.UseRegister(mleft.left().node()),
               g.UseRegister(m.right().node()), g.TempImmediate(shift_value));
          return;
        }
      }
    }

    VisitBinop(this, node, kLoong64Add_d, true, kLoong64Add_d);
  }
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt32Sub(node_t node) {
  VisitBinop(this, node, kLoong64Sub_w);
}

template <typename Adapter>
void InstructionSelectorT<Adapter>::VisitInt64Sub(node_t node) {
  VisitBinop(this, node, kLoong64Sub_d);
}

template <>
void InstructionSelectorT<TurboshaftAdapter>::VisitInt32Mul(node_t node) {
  // TODO(LOONG_dev): May could be optimized like in Turbofan.
  VisitBinop(this, node, kLoong64Mul_w, true, kLoong64Mul_w);
}

template <>
void InstructionSelectorT<TurbofanAdapter>::VisitInt32Mul(Node* node) {
  Loong64OperandGeneratorT<TurbofanAdapter> g(this);
  Int32BinopMatcher m(node);
  if (m.right().HasResolvedValue() && m.right().ResolvedValue() > 0) {
    uint32_t value = static_cast<uint32_t>(m.right().ResolvedValue());
    if (base::bits::IsPowerOfTwo(value)) {
      Emit(kLoong64Sll_w | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value - 1) && value - 1 > 0 &&
        value - 1 <= 31) {
      Emit(kLoong64Alsl_w, g.DefineAsRegister(node),
           g.UseRegister(m.left().node()), g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value - 1)));
      return;
    }
    if (base::bits::IsPowerOfTwo(value + 1)) {
      InstructionOperand temp = g.TempRegister();
      Emit(kLoong64Sll_w | AddressingModeField::encode(kMode_None), temp,
           g.UseRegister(m.left().node()),
           g.TempImmediate(base::bits::WhichPowerOfTwo(value + 1)));
      Emit(kLoong64Sub_w | AddressingModeField::encode(kMode_None),
           g.DefineAsRegister(node), temp, g.UseRegister(m.left().node()));
      return;
    }
  }
  Node* left = node->InputAt(0);
  Node* right = node->InputAt(1);
  if (CanCover(node, left) && CanCover(node, right)) {
    if (left->opcode() == IrOpcode::kWord64Sar &&
        right->opcode() == IrOpcode::kWord64Sar) {
      Int64BinopM
```