Response: The user wants a summary of the C++ code provided.
The code seems to be part of the Liftoff compiler for WebAssembly in V8.
It defines how certain WebAssembly instructions are compiled into machine code.
The current part (part 5 of 7) focuses on memory and table related instructions, as well as reference type instructions (structs, arrays, strings, rtts).

To illustrate the connection to JavaScript, I can show how a WebAssembly instruction handled in this code snippet might be used in a JavaScript context when executing WebAssembly.
这个C++代码文件 `v8/src/wasm/baseline/liftoff-compiler.cc` 的第5部分，主要负责 **WebAssembly 指令的编译实现，特别是与内存操作、表操作以及引用类型相关的指令**。

**主要功能归纳:**

1. **内存操作指令的编译:**
   - `MemoryInit`:  实现 `memory.init` 指令，将数据段的内容复制到线性内存中。
   - `DataDrop`: 实现 `data.drop` 指令，释放数据段资源。
   - `MemoryCopy`: 实现 `memory.copy` 指令，在不同的内存区域之间复制数据。
   - `MemoryFill`: 实现 `memory.fill` 指令，用指定的值填充内存区域。

2. **表操作指令的编译:**
   - `TableInit`: 实现 `table.init` 指令，将元素段的内容复制到表中。
   - `ElemDrop`: 实现 `elem.drop` 指令，释放元素段资源。
   - `TableCopy`: 实现 `table.copy` 指令，在不同的表之间复制元素。
   - `TableGrow`: 实现 `table.grow` 指令，增加表的大小。
   - `TableSize`: 实现 `table.size` 指令，获取表的大小。
   - `TableFill`: 实现 `table.fill` 指令，用指定的值填充表。

3. **引用类型相关指令的编译:**
   - **结构体 (Struct):**
     - `StructNew`: 实现 `struct.new` 和 `struct.new_default` 指令，创建新的结构体实例。
     - `StructGet`: 实现 `struct.get` 指令，获取结构体字段的值。
     - `StructSet`: 实现 `struct.set` 指令，设置结构体字段的值。
   - **数组 (Array):**
     - `ArrayNew`: 实现 `array.new` 和 `array.new_default` 指令，创建新的数组实例。
     - `ArrayFill`: 实现 `array.fill` 指令，用指定的值填充数组。
     - `ArrayGet`: 实现 `array.get` 指令，获取数组元素的值。
     - `ArraySet`: 实现 `array.set` 指令，设置数组元素的值。
     - `ArrayLen`: 实现 `array.len` 指令，获取数组的长度。
     - `ArrayCopy`: 实现 `array.copy` 指令，在不同的数组之间复制元素。
     - `ArrayNewFixed`: 实现 `array.new_fixed` 指令，创建具有固定大小和初始元素的数组。
     - `ArrayNewSegment`: 实现 `array.new_segment` 指令，从元素段创建数组。
     - `ArrayInitSegment`: 实现 `array.init_segment` 指令，使用元素段初始化数组。
   - **i31 类型:**
     - `RefI31`: 实现 `ref.i31` 指令，将 i32 值转换为 i31ref。
     - `I31GetS`: 实现 `i31.get_s` 指令，将有符号 i31ref 转换为 i32。
     - `I31GetU`: 实现 `i31.get_u` 指令，将无符号 i31ref 转换为 i32。
   - **RTT (运行时类型信息):**
     - `RttCanon`:  获取指定类型的规范 RTT。
     - `RefTest`: 实现 `ref.test` 指令，检查对象是否是指定类型的实例。
     - `RefCast`: 实现 `ref.cast` 指令，将对象转换为指定类型，如果转换失败则抛出异常。
     - `BrOnCast`: 实现 `br_on_cast` 指令，如果类型转换成功则跳转。
     - `BrOnCastFail`: 实现 `br_on_cast_fail` 指令，如果类型转换失败则跳转。
   - **抽象类型检查和转换:** 针对 `eq`, `i31`, `struct`, `array`, `string` 等抽象类型进行类型检查和转换。
   - **字符串 (String):**
     - `StringNewWtf8`, `StringNewWtf8Array`: 从 UTF-8 编码的内存或数组创建字符串。
     - `StringNewWtf16`, `StringNewWtf16Array`: 从 UTF-16 编码的内存或数组创建字符串。
     - `StringConst`: 创建常量字符串。
     - `StringMeasureWtf8`: 测量 UTF-8 字符串的长度。

4. **辅助功能:**
   - `IndexToVarStateSaturating`, `PopIndexToVarStateSaturating`:  处理栈顶索引，并对 32 位平台上 64 位的值进行饱和处理。
   - `MatchingMemTypeOnTopOfStack`, `MatchingAddressTypeOnTopOfStack`, `MatchingMemType`: 用于调试，检查栈顶值的类型是否与预期一致。
   - `LoadSmi`, `LoadSmiConstant`: 加载 Small Integer (Smi) 常量。
   - `CallBuiltin`: 调用 V8 的内置函数。
   - `RegisterDebugSideTableEntry`: 记录调试信息。
   - `MaybeEmitNullCheck`:  根据策略发出空值检查。
   - `BoundsCheckArray`: 执行数组越界检查。
   - `LoadObjectField`, `StoreObjectField`:  加载和存储对象的字段。
   - `ArrayFillImpl`: 数组填充的实际实现。
   - `SubtypeCheck`: 执行子类型检查。
   - 各种 `AbstractTypeCheck`, `AbstractTypeCast`, `BrOnAbstractType`, `BrOnNonAbstractType` 等模板函数，用于实现抽象类型的检查和分支逻辑。

**与 JavaScript 的关系及示例:**

WebAssembly 模块通常在 JavaScript 环境中加载和执行。当 JavaScript 调用 WebAssembly 模块的函数时，Liftoff 编译器编译的指令会被执行。

例如，WebAssembly 的 `memory.fill` 指令允许用一个给定的值填充一段线性内存。在 JavaScript 中，你可以通过 `WebAssembly.Memory` 对象访问和操作 WebAssembly 的线性内存。

**WebAssembly 代码示例:**

```wasm
(module
  (memory (export "memory") 1)
  (func (export "fillMemory") (param $offset i32) (param $value i32) (param $length i32)
    local.get $offset
    local.get $value
    local.get $length
    memory.fill
  )
)
```

**JavaScript 代码示例:**

```javascript
const wasmCode = await fetch('your_module.wasm');
const wasmInstance = await WebAssembly.instantiateStreaming(wasmCode);
const memory = wasmInstance.instance.exports.memory;
const fillMemory = wasmInstance.instance.exports.fillMemory;

const offset = 10;
const value = 42; // 要填充的值
const length = 5;

fillMemory(offset, value, length);

// 检查内存是否被填充
const buffer = new Uint8Array(memory.buffer, offset, length);
console.log(buffer); // 输出: Uint8Array(5) [ 42, 42, 42, 42, 42 ]
```

在这个例子中，当 JavaScript 调用 `fillMemory` 函数时，`liftoff-compiler.cc` 的 `MemoryFill` 函数会生成相应的机器码，以执行 `memory.fill` 指令，从而修改 WebAssembly 模块的线性内存。JavaScript 可以通过 `memory.buffer` 查看内存的变化。

总而言之，这个代码文件的第 5 部分是 Liftoff 编译器实现 WebAssembly 功能的关键组成部分，它将高级的 WebAssembly 指令转换为底层的机器码，使得 JavaScript 环境能够高效地执行 WebAssembly 代码。

### 提示词
```
这是目录为v8/src/wasm/baseline/liftoff-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```
kMaxUint32 if the high word had any
  // bits set.
  VarState IndexToVarStateSaturating(int stack_index, LiftoffRegList* pinned) {
    DCHECK_LE(0, stack_index);
    DCHECK_LT(stack_index, __ cache_state()->stack_height());
    VarState& slot = __ cache_state()->stack_state.end()[-1 - stack_index];
    const bool is_mem64 = slot.kind() == kI64;
    // For memory32 on a 32-bit system or memory64 on a 64-bit system, there is
    // nothing to do.
    if ((kSystemPointerSize == kInt64Size) == is_mem64) {
      if (slot.is_reg()) pinned->set(slot.reg());
      return slot;
    }

    // {kI64} constants will be stored as 32-bit integers in the {VarState} and
    // will be sign-extended later. Hence we can return constants if they are
    // positive (such that sign-extension and zero-extension are identical).
    if (slot.is_const() && (kIntPtrKind == kI32 || slot.i32_const() >= 0)) {
      return {kIntPtrKind, slot.i32_const(), 0};
    }

    LiftoffRegister reg = __ LoadToModifiableRegister(slot, *pinned);
    // For memory32 on 64-bit hosts, zero-extend.
    if constexpr (Is64()) {
      DCHECK(!is_mem64);  // Handled above.
      __ emit_u32_to_uintptr(reg.gp(), reg.gp());
      pinned->set(reg);
      return {kIntPtrKind, reg, 0};
    }

    // For memory64 on 32-bit systems, saturate the low word.
    DCHECK(is_mem64);  // Other cases are handled above.
    DCHECK_EQ(kSystemPointerSize, kInt32Size);
    pinned->set(reg.low());
    Label ok;
    FREEZE_STATE(frozen);
    __ emit_cond_jump(kZero, &ok, kI32, reg.high().gp(), no_reg, frozen);
    __ LoadConstant(reg.low(), WasmValue{kMaxUInt32});
    __ emit_jump(&ok);
    __ bind(&ok);
    return {kIntPtrKind, reg.low(), 0};
  }

  // Same as {PopIndexToVarState}, but saturates 64-bit values on 32-bit
  // platforms like {IndexToVarStateSaturating}.
  VarState PopIndexToVarStateSaturating(LiftoffRegList* pinned) {
    VarState result = IndexToVarStateSaturating(0, pinned);
    __ DropValues(1);
    return result;
  }

  // The following functions are to be used inside a DCHECK. They always return
  // true and will fail internally on a detected inconsistency.
#ifdef DEBUG
  // Checks that the top-of-stack value matches the declared memory (64-bit or
  // 32-bit).
  bool MatchingMemTypeOnTopOfStack(const WasmMemory* memory) {
    return MatchingAddressTypeOnTopOfStack(memory->is_memory64());
  }

  // Checks that the top-of-stack value matches the expected bitness.
  bool MatchingAddressTypeOnTopOfStack(bool expect_64bit_value) {
    DCHECK_LT(0, __ cache_state()->stack_height());
    ValueKind expected_kind = expect_64bit_value ? kI64 : kI32;
    DCHECK_EQ(expected_kind, __ cache_state()->stack_state.back().kind());
    return true;
  }

  bool MatchingMemType(const WasmMemory* memory, int stack_index) {
    DCHECK_LE(0, stack_index);
    DCHECK_LT(stack_index, __ cache_state()->stack_state.size());
    ValueKind expected_kind = memory->is_memory64() ? kI64 : kI32;
    DCHECK_EQ(expected_kind,
              __ cache_state()->stack_state.end()[-1 - stack_index].kind());
    return true;
  }
#endif

  void MemoryInit(FullDecoder* decoder, const MemoryInitImmediate& imm,
                  const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register mem_offsets_high_word = no_reg;
    LiftoffRegList pinned;
    VarState size = __ PopVarState();
    if (size.is_reg()) pinned.set(size.reg());
    VarState src = __ PopVarState();
    if (src.is_reg()) pinned.set(src.reg());
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory.memory));
    VarState dst = PopIndexToVarState(&mem_offsets_high_word, &pinned);

    Register instance_data = __ cache_state() -> cached_instance_data;
    if (instance_data == no_reg) {
      instance_data = __ GetUnusedRegister(kGpReg, pinned).gp();
      __ LoadInstanceDataFromFrame(instance_data);
    }
    pinned.set(instance_data);

    // TODO(crbug.com/41480344): The stack state in the OOL code should reflect
    // the state before popping any values (for a better debugging experience).
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapMemOutOfBounds);
    if (mem_offsets_high_word != no_reg) {
      // If any high word has bits set, jump to the OOB trap.
      FREEZE_STATE(trapping);
      __ emit_cond_jump(kNotZero, trap_label, kI32, mem_offsets_high_word,
                        no_reg, trapping);
      pinned.clear(mem_offsets_high_word);
    }

    LiftoffRegister result =
        GenerateCCall(kI32,
                      {{kIntPtrKind, LiftoffRegister{instance_data}, 0},
                       {kI32, static_cast<int32_t>(imm.memory.index), 0},
                       dst,
                       src,
                       {kI32, static_cast<int32_t>(imm.data_segment.index), 0},
                       size},
                      ExternalReference::wasm_memory_init());
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kEqual, trap_label, kI32, result.gp(), no_reg, trapping);
  }

  void DataDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    LiftoffRegList pinned;

    Register seg_size_array =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(seg_size_array, DataSegmentSizes, pinned);

    LiftoffRegister seg_index =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    // Scale the seg_index for the array access.
    __ LoadConstant(
        seg_index,
        WasmValue(wasm::ObjectAccess::ElementOffsetInTaggedFixedUInt32Array(
            imm.index)));

    // Set the length of the segment to '0' to drop it.
    LiftoffRegister null_reg = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(null_reg, WasmValue(0));
    __ Store(seg_size_array, seg_index.gp(), 0, null_reg, StoreType::kI32Store,
             pinned);
  }

  void MemoryCopy(FullDecoder* decoder, const MemoryCopyImmediate& imm,
                  const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register mem_offsets_high_word = no_reg;
    LiftoffRegList pinned;

    // The type of {size} is the min of {src} and {dst} (where {kI32 < kI64}).
    DCHECK(
        MatchingAddressTypeOnTopOfStack(imm.memory_dst.memory->is_memory64() &&
                                        imm.memory_src.memory->is_memory64()));
    VarState size = PopIndexToVarState(&mem_offsets_high_word, &pinned);
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory_src.memory));
    VarState src = PopIndexToVarState(&mem_offsets_high_word, &pinned);
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory_dst.memory));
    VarState dst = PopIndexToVarState(&mem_offsets_high_word, &pinned);

    Register instance_data = __ cache_state() -> cached_instance_data;
    if (instance_data == no_reg) {
      instance_data = __ GetUnusedRegister(kGpReg, pinned).gp();
      __ LoadInstanceDataFromFrame(instance_data);
    }
    pinned.set(instance_data);

    // TODO(crbug.com/41480344): The stack state in the OOL code should reflect
    // the state before popping any values (for a better debugging experience).
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapMemOutOfBounds);
    DCHECK_IMPLIES(Is64(), mem_offsets_high_word == no_reg);
    if (!Is64() && mem_offsets_high_word != no_reg) {
      // If any high word has bits set, jump to the OOB trap.
      FREEZE_STATE(trapping);
      __ emit_cond_jump(kNotZero, trap_label, kI32, mem_offsets_high_word,
                        no_reg, trapping);
    }

    LiftoffRegister result =
        GenerateCCall(kI32,
                      {{kIntPtrKind, LiftoffRegister{instance_data}, 0},
                       {kI32, static_cast<int32_t>(imm.memory_dst.index), 0},
                       {kI32, static_cast<int32_t>(imm.memory_src.index), 0},
                       dst,
                       src,
                       size},
                      ExternalReference::wasm_memory_copy());
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kEqual, trap_label, kI32, result.gp(), no_reg, trapping);
  }

  void MemoryFill(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register mem_offsets_high_word = no_reg;
    LiftoffRegList pinned;
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory));
    VarState size = PopIndexToVarState(&mem_offsets_high_word, &pinned);
    VarState value = __ PopVarState();
    if (value.is_reg()) pinned.set(value.reg());
    DCHECK(MatchingMemTypeOnTopOfStack(imm.memory));
    VarState dst = PopIndexToVarState(&mem_offsets_high_word, &pinned);

    Register instance_data = __ cache_state() -> cached_instance_data;
    if (instance_data == no_reg) {
      instance_data = __ GetUnusedRegister(kGpReg, pinned).gp();
      __ LoadInstanceDataFromFrame(instance_data);
    }
    pinned.set(instance_data);

    // TODO(crbug.com/41480344): The stack state in the OOL code should reflect
    // the state before popping any values (for a better debugging experience).
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapMemOutOfBounds);
    if (mem_offsets_high_word != no_reg) {
      // If any high word has bits set, jump to the OOB trap.
      FREEZE_STATE(trapping);
      __ emit_cond_jump(kNotZero, trap_label, kI32, mem_offsets_high_word,
                        no_reg, trapping);
    }

    LiftoffRegister result =
        GenerateCCall(kI32,
                      {{kIntPtrKind, LiftoffRegister{instance_data}, 0},
                       {kI32, static_cast<int32_t>(imm.index), 0},
                       dst,
                       value,
                       size},
                      ExternalReference::wasm_memory_fill());
    FREEZE_STATE(trapping);
    __ emit_cond_jump(kEqual, trap_label, kI32, result.gp(), no_reg, trapping);
  }

  void LoadSmi(LiftoffRegister reg, int value) {
    Address smi_value = Smi::FromInt(value).ptr();
    using smi_type = std::conditional_t<kSmiKind == kI32, int32_t, int64_t>;
    __ LoadConstant(reg, WasmValue{static_cast<smi_type>(smi_value)});
  }

  VarState LoadSmiConstant(int32_t constant, LiftoffRegList* pinned) {
    if constexpr (kSmiKind == kI32) {
      int32_t smi_const = static_cast<int32_t>(Smi::FromInt(constant).ptr());
      return VarState{kI32, smi_const, 0};
    } else {
      LiftoffRegister reg = pinned->set(__ GetUnusedRegister(kGpReg, *pinned));
      LoadSmi(reg, constant);
      return VarState{kSmiKind, reg, 0};
    }
  }

  void TableInit(FullDecoder* decoder, const TableInitImmediate& imm,
                 const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    VarState table_index = LoadSmiConstant(imm.table.index, &pinned);
    VarState segment_index =
        LoadSmiConstant(imm.element_segment.index, &pinned);
    VarState extract_shared_data = LoadSmiConstant(0, &pinned);

    VarState size = __ PopVarState();
    if (size.is_reg()) pinned.set(size.reg());
    VarState src = __ PopVarState();
    if (src.is_reg()) pinned.set(src.reg());
    Register index_high_word = no_reg;
    VarState dst = PopIndexToVarState(&index_high_word, &pinned);

    // Trap if any bit in high word was set.
    CheckHighWordEmptyForTableType(decoder, index_high_word, &pinned);

    CallBuiltin(
        Builtin::kWasmTableInit,
        MakeSig::Params(kIntPtrKind, kI32, kI32, kSmiKind, kSmiKind, kSmiKind),
        {dst, src, size, table_index, segment_index, extract_shared_data},
        decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
  }

  void ElemDrop(FullDecoder* decoder, const IndexImmediate& imm) {
    LiftoffRegList pinned;
    Register element_segments =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(element_segments, ElementSegments, pinned);

    LiftoffRegister seg_index =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(
        seg_index,
        WasmValue(
            wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(imm.index)));

    // Mark the segment as dropped by setting it to the empty fixed array.
    Register empty_fixed_array =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    __ LoadFullPointer(
        empty_fixed_array, kRootRegister,
        IsolateData::root_slot_offset(RootIndex::kEmptyFixedArray));

    __ StoreTaggedPointer(element_segments, seg_index.gp(), 0,
                          empty_fixed_array, pinned);
  }

  void TableCopy(FullDecoder* decoder, const TableCopyImmediate& imm,
                 const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register index_high_word = no_reg;
    LiftoffRegList pinned;

    VarState table_src_index = LoadSmiConstant(imm.table_src.index, &pinned);
    VarState table_dst_index = LoadSmiConstant(imm.table_dst.index, &pinned);
    VarState extract_shared_data = LoadSmiConstant(0, &pinned);

    VarState size = PopIndexToVarState(&index_high_word, &pinned);
    VarState src = PopIndexToVarState(&index_high_word, &pinned);
    VarState dst = PopIndexToVarState(&index_high_word, &pinned);

    // Trap if any bit in the combined high words was set.
    CheckHighWordEmptyForTableType(decoder, index_high_word, &pinned);

    CallBuiltin(
        Builtin::kWasmTableCopy,
        MakeSig::Params(kIntPtrKind, kIntPtrKind, kIntPtrKind, kSmiKind,
                        kSmiKind, kSmiKind),
        {dst, src, size, table_dst_index, table_src_index, extract_shared_data},
        decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
  }

  void TableGrow(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value&, const Value&, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister table_index_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(table_index_reg, imm.index);
    VarState table_index(kSmiKind, table_index_reg, 0);
    // If `delta` is, OOB table.grow should return -1.
    VarState delta = PopIndexToVarStateSaturating(&pinned);
    VarState value = __ PopVarState();
    VarState extract_shared_data(kI32, 0, 0);

    CallBuiltin(Builtin::kWasmTableGrow,
                MakeSig::Returns(kSmiKind).Params(kSmiKind, kIntPtrKind, kI32,
                                                  kRefNull),
                {table_index, delta, extract_shared_data, value},
                decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
    __ SmiToInt32(kReturnRegister0);
    if (imm.table->is_table64()) {
      LiftoffRegister result64 = LiftoffRegister(kReturnRegister0);
      if (kNeedI64RegPair) {
        result64 = LiftoffRegister::ForPair(kReturnRegister0, kReturnRegister1);
      }
      __ emit_type_conversion(kExprI64SConvertI32, result64,
                              LiftoffRegister(kReturnRegister0), nullptr);
      __ PushRegister(kI64, result64);
    } else {
      __ PushRegister(kI32, LiftoffRegister(kReturnRegister0));
    }
  }

  void TableSize(FullDecoder* decoder, const TableIndexImmediate& imm, Value*) {
    // We have to look up instance->tables[table_index].length.

    LiftoffRegList pinned;
    // Get the number of calls array address.
    Register tables = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LOAD_TAGGED_PTR_INSTANCE_FIELD(tables, Tables, pinned);

    Register table = tables;
    __ LoadTaggedPointer(
        table, tables, no_reg,
        ObjectAccess::ElementOffsetInTaggedFixedArray(imm.index));

    int length_field_size = WasmTableObject::kCurrentLengthOffsetEnd -
                            WasmTableObject::kCurrentLengthOffset + 1;

    Register result = table;
    __ Load(LiftoffRegister(result), table, no_reg,
            wasm::ObjectAccess::ToTagged(WasmTableObject::kCurrentLengthOffset),
            length_field_size == 4 ? LoadType::kI32Load : LoadType::kI64Load);

    __ SmiUntag(result);

    if (imm.table->is_table64()) {
      LiftoffRegister result64 = LiftoffRegister(result);
      if (kNeedI64RegPair) {
        result64 = LiftoffRegister::ForPair(
            result, __ GetUnusedRegister(kGpReg, pinned).gp());
      }
      __ emit_type_conversion(kExprI64SConvertI32, result64,
                              LiftoffRegister(result), nullptr);
      __ PushRegister(kI64, result64);
    } else {
      __ PushRegister(kI32, LiftoffRegister(result));
    }
  }

  void TableFill(FullDecoder* decoder, const TableIndexImmediate& imm,
                 const Value&, const Value&, const Value&) {
    FUZZER_HEAVY_INSTRUCTION;
    Register high_words = no_reg;
    LiftoffRegList pinned;

    VarState table_index = LoadSmiConstant(imm.index, &pinned);
    VarState extract_shared_data{kI32, 0, 0};

    VarState count = PopIndexToVarState(&high_words, &pinned);
    VarState value = __ PopVarState();
    if (value.is_reg()) pinned.set(value.reg());
    VarState start = PopIndexToVarState(&high_words, &pinned);
    // Trap if any bit in the combined high words was set.
    CheckHighWordEmptyForTableType(decoder, high_words, &pinned);

    CallBuiltin(
        Builtin::kWasmTableFill,
        MakeSig::Params(kIntPtrKind, kIntPtrKind, kI32, kSmiKind, kRefNull),
        {start, count, extract_shared_data, table_index, value},
        decoder->position());

    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 bool initial_values_on_stack) {
    LiftoffRegister rtt = RttCanon(imm.index, {});

    CallBuiltin(Builtin::kWasmAllocateStructWithRtt,
                MakeSig::Returns(kRef).Params(kRtt, kI32),
                {VarState{kRtt, rtt, 0},
                 VarState{kI32, WasmStruct::Size(imm.struct_type), 0}},
                decoder->position());

    LiftoffRegister obj(kReturnRegister0);
    LiftoffRegList pinned{obj};

    for (uint32_t i = imm.struct_type->field_count(); i > 0;) {
      i--;
      int offset = StructFieldOffset(imm.struct_type, i);
      ValueType field_type = imm.struct_type->field(i);
      LiftoffRegister value = pinned.set(
          initial_values_on_stack
              ? __ PopToRegister(pinned)
              : __ GetUnusedRegister(reg_class_for(field_type.kind()), pinned));
      if (!initial_values_on_stack) {
        if (!CheckSupportedType(decoder, field_type.kind(), "default value")) {
          return;
        }
        SetDefaultValue(value, field_type);
      }
      // Skipping the write barrier is safe as long as:
      // (1) {obj} is freshly allocated, and
      // (2) {obj} is in new-space (not pretenured).
      StoreObjectField(decoder, obj.gp(), no_reg, offset, value, false, pinned,
                       field_type.kind(), LiftoffAssembler::kSkipWriteBarrier);
      pinned.clear(value);
    }
    // If this assert fails then initialization of padding field might be
    // necessary.
    static_assert(Heap::kMinObjectSizeInTaggedWords == 2 &&
                      WasmStruct::kHeaderSize == 2 * kTaggedSize,
                  "empty struct might require initialization of padding field");
    __ PushRegister(kRef, obj);
  }

  void StructNew(FullDecoder* decoder, const StructIndexImmediate& imm,
                 const Value args[], Value* result) {
    StructNew(decoder, imm, true);
  }

  void StructNewDefault(FullDecoder* decoder, const StructIndexImmediate& imm,
                        Value* result) {
    StructNew(decoder, imm, false);
  }

  void StructGet(FullDecoder* decoder, const Value& struct_obj,
                 const FieldImmediate& field, bool is_signed, Value* result) {
    const StructType* struct_type = field.struct_imm.struct_type;
    ValueKind field_kind = struct_type->field(field.field_imm.index).kind();
    if (!CheckSupportedType(decoder, field_kind, "field load")) return;
    int offset = StructFieldOffset(struct_type, field.field_imm.index);
    LiftoffRegList pinned;
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));

    auto [explicit_check, implicit_check] =
        null_checks_for_struct_op(struct_obj.type, field.field_imm.index);

    if (explicit_check) {
      MaybeEmitNullCheck(decoder, obj.gp(), pinned, struct_obj.type);
    }
    LiftoffRegister value =
        __ GetUnusedRegister(reg_class_for(field_kind), pinned);
    LoadObjectField(decoder, value, obj.gp(), no_reg, offset, field_kind,
                    is_signed, implicit_check, pinned);
    __ PushRegister(unpacked(field_kind), value);
  }

  void StructSet(FullDecoder* decoder, const Value& struct_obj,
                 const FieldImmediate& field, const Value& field_value) {
    const StructType* struct_type = field.struct_imm.struct_type;
    ValueKind field_kind = struct_type->field(field.field_imm.index).kind();
    int offset = StructFieldOffset(struct_type, field.field_imm.index);
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));

    auto [explicit_check, implicit_check] =
        null_checks_for_struct_op(struct_obj.type, field.field_imm.index);

    if (explicit_check) {
      MaybeEmitNullCheck(decoder, obj.gp(), pinned, struct_obj.type);
    }

    StoreObjectField(decoder, obj.gp(), no_reg, offset, value, implicit_check,
                     pinned, field_kind);
  }

  void ArrayNew(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                bool initial_value_on_stack) {
    FUZZER_HEAVY_INSTRUCTION;
    // Max length check.
    {
      LiftoffRegister length =
          __ LoadToRegister(__ cache_state()->stack_state.end()[-1], {});
      Label* trap_label =
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapArrayTooLarge);
      FREEZE_STATE(trapping);
      __ emit_i32_cond_jumpi(kUnsignedGreaterThan, trap_label, length.gp(),
                             WasmArray::MaxLength(imm.array_type), trapping);
    }
    ValueType elem_type = imm.array_type->element_type();
    ValueKind elem_kind = elem_type.kind();
    int elem_size = value_kind_size(elem_kind);
    // Allocate the array.
    {
      LiftoffRegister rtt = RttCanon(imm.index, {});
      CallBuiltin(Builtin::kWasmAllocateArray_Uninitialized,
                  MakeSig::Returns(kRef).Params(kRtt, kI32, kI32),
                  {VarState{kRtt, rtt, 0},
                   __ cache_state()->stack_state.end()[-1],  // length
                   VarState{kI32, elem_size, 0}},
                  decoder->position());
    }

    LiftoffRegister obj(kReturnRegister0);
    LiftoffRegList pinned{obj};
    LiftoffRegister length = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister value =
        pinned.set(__ GetUnusedRegister(reg_class_for(elem_kind), pinned));
    if (initial_value_on_stack) {
      __ PopToFixedRegister(value);
    } else {
      if (!CheckSupportedType(decoder, elem_kind, "default value")) return;
      SetDefaultValue(value, elem_type);
    }

    LiftoffRegister index = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    __ LoadConstant(index, WasmValue(int32_t{0}));

    // Initialize the array's elements.
    // Skipping the write barrier is safe as long as:
    // (1) {obj} is freshly allocated, and
    // (2) {obj} is in new-space (not pretenured).
    ArrayFillImpl(decoder, pinned, obj, index, value, length, elem_kind,
                  LiftoffAssembler::kSkipWriteBarrier);

    __ PushRegister(kRef, obj);
  }

  void ArrayNew(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                const Value& length_value, const Value& initial_value,
                Value* result) {
    ArrayNew(decoder, imm, true);
  }

  void ArrayNewDefault(FullDecoder* decoder, const ArrayIndexImmediate& imm,
                       const Value& length, Value* result) {
    ArrayNew(decoder, imm, false);
  }

  void ArrayFill(FullDecoder* decoder, ArrayIndexImmediate& imm,
                 const Value& array, const Value& /* index */,
                 const Value& /* value */, const Value& /* length */) {
    FUZZER_HEAVY_INSTRUCTION;
    {
      // Null check.
      LiftoffRegList pinned;
      LiftoffRegister array_reg = pinned.set(__ PeekToRegister(3, pinned));
      if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
        MaybeEmitNullCheck(decoder, array_reg.gp(), pinned, array.type);
      }

      // Bounds checks.
      Label* trap_label =
          AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapArrayOutOfBounds);
      LiftoffRegister array_length =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      bool implicit_null_check =
          array.type.is_nullable() &&
          null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
      LoadObjectField(decoder, array_length, array_reg.gp(), no_reg,
                      ObjectAccess::ToTagged(WasmArray::kLengthOffset), kI32,
                      false, implicit_null_check, pinned);
      LiftoffRegister index = pinned.set(__ PeekToRegister(2, pinned));
      LiftoffRegister length = pinned.set(__ PeekToRegister(0, pinned));
      LiftoffRegister index_plus_length =
          pinned.set(__ GetUnusedRegister(kGpReg, pinned));
      DCHECK(index_plus_length != array_length);
      __ emit_i32_add(index_plus_length.gp(), length.gp(), index.gp());
      FREEZE_STATE(frozen);
      __ emit_cond_jump(kUnsignedGreaterThan, trap_label, kI32,
                        index_plus_length.gp(), array_length.gp(), frozen);
      // Guard against overflow.
      __ emit_cond_jump(kUnsignedGreaterThan, trap_label, kI32, index.gp(),
                        index_plus_length.gp(), frozen);
    }

    LiftoffRegList pinned;
    LiftoffRegister length = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
    LiftoffRegister index = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));

    ArrayFillImpl(decoder, pinned, obj, index, value, length,
                  imm.array_type->element_type().kind(),
                  LiftoffAssembler::kNoSkipWriteBarrier);
  }

  void ArrayGet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index_val,
                bool is_signed, Value* result) {
    LiftoffRegList pinned;
    LiftoffRegister index = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister array = pinned.set(__ PopToRegister(pinned));
    if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      MaybeEmitNullCheck(decoder, array.gp(), pinned, array_obj.type);
    }
    bool implicit_null_check =
        array_obj.type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
    BoundsCheckArray(decoder, implicit_null_check, array, index, pinned);
    ValueKind elem_kind = imm.array_type->element_type().kind();
    if (!CheckSupportedType(decoder, elem_kind, "array load")) return;
    int elem_size_shift = value_kind_size_log2(elem_kind);
    if (elem_size_shift != 0) {
      __ emit_i32_shli(index.gp(), index.gp(), elem_size_shift);
    }
    LiftoffRegister value =
        __ GetUnusedRegister(reg_class_for(elem_kind), pinned);
    LoadObjectField(decoder, value, array.gp(), index.gp(),
                    wasm::ObjectAccess::ToTagged(WasmArray::kHeaderSize),
                    elem_kind, is_signed, false, pinned);
    __ PushRegister(unpacked(elem_kind), value);
  }

  void ArraySet(FullDecoder* decoder, const Value& array_obj,
                const ArrayIndexImmediate& imm, const Value& index_val,
                const Value& value_val) {
    LiftoffRegList pinned;
    LiftoffRegister value = pinned.set(__ PopToRegister(pinned));
    DCHECK_EQ(reg_class_for(imm.array_type->element_type().kind()),
              value.reg_class());
    LiftoffRegister index = pinned.set(__ PopToModifiableRegister(pinned));
    LiftoffRegister array = pinned.set(__ PopToRegister(pinned));
    if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      MaybeEmitNullCheck(decoder, array.gp(), pinned, array_obj.type);
    }
    bool implicit_null_check =
        array_obj.type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
    BoundsCheckArray(decoder, implicit_null_check, array, index, pinned);
    ValueKind elem_kind = imm.array_type->element_type().kind();
    int elem_size_shift = value_kind_size_log2(elem_kind);
    if (elem_size_shift != 0) {
      __ emit_i32_shli(index.gp(), index.gp(), elem_size_shift);
    }
    StoreObjectField(decoder, array.gp(), index.gp(),
                     wasm::ObjectAccess::ToTagged(WasmArray::kHeaderSize),
                     value, false, pinned, elem_kind);
  }

  void ArrayLen(FullDecoder* decoder, const Value& array_obj, Value* result) {
    LiftoffRegList pinned;
    LiftoffRegister obj = pinned.set(__ PopToRegister(pinned));
    if (null_check_strategy_ == compiler::NullCheckStrategy::kExplicit) {
      MaybeEmitNullCheck(decoder, obj.gp(), pinned, array_obj.type);
    }
    LiftoffRegister len = __ GetUnusedRegister(kGpReg, pinned);
    int kLengthOffset = wasm::ObjectAccess::ToTagged(WasmArray::kLengthOffset);
    bool implicit_null_check =
        array_obj.type.is_nullable() &&
        null_check_strategy_ == compiler::NullCheckStrategy::kTrapHandler;
    LoadObjectField(decoder, len, obj.gp(), no_reg, kLengthOffset, kI32,
                    false /* is_signed */, implicit_null_check, pinned);
    __ PushRegister(kI32, len);
  }

  void ArrayCopy(FullDecoder* decoder, const Value& dst, const Value& dst_index,
                 const Value& src, const Value& src_index,
                 const ArrayIndexImmediate& src_imm, const Value& length) {
    // TODO(14034): Unify implementation with TF: Implement this with
    // GenerateCCallWithStackBuffer. Remove runtime function and builtin in
    // wasm.tq.
    CallBuiltin(Builtin::kWasmArrayCopy,
                MakeSig::Params(kI32, kI32, kI32, kRefNull, kRefNull),
                // Builtin parameter order:
                // [dst_index, src_index, length, dst, src].
                {__ cache_state()->stack_state.end()[-4],
                 __ cache_state()->stack_state.end()[-2],
                 __ cache_state()->stack_state.end()[-1],
                 __ cache_state()->stack_state.end()[-5],
                 __ cache_state()->stack_state.end()[-3]},
                decoder->position());
    __ DropValues(5);
  }

  void ArrayNewFixed(FullDecoder* decoder, const ArrayIndexImmediate& array_imm,
                     const IndexImmediate& length_imm,
                     const Value* /* elements */, Value* /* result */) {
    LiftoffRegister rtt = RttCanon(array_imm.index, {});
    ValueKind elem_kind = array_imm.array_type->element_type().kind();
    int32_t elem_count = length_imm.index;
    // Allocate the array.
    CallBuiltin(Builtin::kWasmAllocateArray_Uninitialized,
                MakeSig::Returns(kRef).Params(kRtt, kI32, kI32),
                {VarState{kRtt, rtt, 0}, VarState{kI32, elem_count, 0},
                 VarState{kI32, value_kind_size(elem_kind), 0}},
                decoder->position());

    // Initialize the array with stack arguments.
    LiftoffRegister array(kReturnRegister0);
    if (!CheckSupportedType(decoder, elem_kind, "array.new_fixed")) return;
    for (int i = elem_count - 1; i >= 0; i--) {
      LiftoffRegList pinned{array};
      LiftoffRegister element = pinned.set(__ PopToRegister(pinned));
      int offset =
          WasmArray::kHeaderSize + (i << value_kind_size_log2(elem_kind));
      // Skipping the write barrier is safe as long as:
      // (1) {array} is freshly allocated, and
      // (2) {array} is in new-space (not pretenured).
      StoreObjectField(decoder, array.gp(), no_reg,
                       wasm::ObjectAccess::ToTagged(offset), element, false,
                       pinned, elem_kind, LiftoffAssembler::kSkipWriteBarrier);
    }

    // Push the array onto the stack.
    __ PushRegister(kRef, array);
  }

  void ArrayNewSegment(FullDecoder* decoder,
                       const ArrayIndexImmediate& array_imm,
                       const IndexImmediate& segment_imm,
                       const Value& /* offset */, const Value& /* length */,
                       Value* /* result */) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister rtt = pinned.set(RttCanon(array_imm.index, pinned));

    LiftoffRegister is_element_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(is_element_reg,
            array_imm.array_type->element_type().is_reference());

    LiftoffRegister extract_shared_data_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(extract_shared_data_reg, 0);

    CallBuiltin(
        Builtin::kWasmArrayNewSegment,
        MakeSig::Returns(kRef).Params(kI32, kI32, kI32, kSmiKind, kSmiKind,
                                      kRtt),
        {
            VarState{kI32, static_cast<int>(segment_imm.index), 0},  // segment
            __ cache_state()->stack_state.end()[-2],                 // offset
            __ cache_state()->stack_state.end()[-1],                 // length
            VarState{kSmiKind, is_element_reg, 0},           // is_element
            VarState{kSmiKind, extract_shared_data_reg, 0},  // shared
            VarState{kRtt, rtt, 0}                           // rtt
        },
        decoder->position());

    // Pop parameters from the value stack.
    __ DropValues(2);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result(kReturnRegister0);
    __ PushRegister(kRef, result);
  }

  void ArrayInitSegment(FullDecoder* decoder,
                        const ArrayIndexImmediate& array_imm,
                        const IndexImmediate& segment_imm,
                        const Value& /* array */,
                        const Value& /* array_index */,
                        const Value& /* segment_offset*/,
                        const Value& /* length */) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister segment_index_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(segment_index_reg, static_cast<int32_t>(segment_imm.index));

    LiftoffRegister is_element_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(is_element_reg,
            array_imm.array_type->element_type().is_reference());

    LiftoffRegister extract_shared_data_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(extract_shared_data_reg, 0);

    // Builtin parameter order: array_index, segment_offset, length,
    //                          segment_index, array.
    CallBuiltin(Builtin::kWasmArrayInitSegment,
                MakeSig::Params(kI32, kI32, kI32, kSmiKind, kSmiKind, kSmiKind,
                                kRefNull),
                {__ cache_state()->stack_state.end()[-3],
                 __ cache_state()->stack_state.end()[-2],
                 __ cache_state()->stack_state.end()[-1],
                 VarState{kSmiKind, segment_index_reg, 0},
                 VarState{kSmiKind, is_element_reg, 0},
                 VarState{kSmiKind, extract_shared_data_reg, 0},
                 __ cache_state()->stack_state.end()[-4]},
                decoder->position());
    __ DropValues(4);
  }

  void RefI31(FullDecoder* decoder, const Value& input, Value* result) {
    LiftoffRegister src = __ PopToRegister();
    LiftoffRegister dst = __ GetUnusedRegister(kGpReg, {src}, {});
    if constexpr (SmiValuesAre31Bits()) {
      static_assert(kSmiTag == 0);
      __ emit_i32_shli(dst.gp(), src.gp(), kSmiTagSize);
    } else {
      DCHECK(SmiValuesAre32Bits());
      // Set the topmost bit to sign-extend the second bit. This way,
      // interpretation in JS (if this value escapes there) will be the same as
      // i31.get_s.
      __ emit_i64_shli(dst, src, kSmiTagSize + kSmiShiftSize + 1);
      __ emit_i64_sari(dst, dst, 1);
    }
    __ PushRegister(kRef, dst);
  }

  void I31GetS(FullDecoder* decoder, const Value& input, Value* result) {
    LiftoffRegList pinned;
    LiftoffRegister src = pinned.set(__ PopToRegister());
    MaybeEmitNullCheck(decoder, src.gp(), pinned, input.type);
    LiftoffRegister dst = __ GetUnusedRegister(kGpReg, {src}, {});
    if constexpr (SmiValuesAre31Bits()) {
      __ emit_i32_sari(dst.gp(), src.gp(), kSmiTagSize);
    } else {
      DCHECK(SmiValuesAre32Bits());
      // The topmost bit is already sign-extended.
      // Liftoff expects that the upper half of any i32 value in a register
      // is zeroed out, not sign-extended from the lower half.
      __ emit_i64_shri(dst, src, kSmiTagSize + kSmiShiftSize);
    }
    __ PushRegister(kI32, dst);
  }

  void I31GetU(FullDecoder* decoder, const Value& input, Value* result) {
    LiftoffRegList pinned;
    LiftoffRegister src = pinned.set(__ PopToRegister());
    MaybeEmitNullCheck(decoder, src.gp(), pinned, input.type);
    LiftoffRegister dst = __ GetUnusedRegister(kGpReg, {src}, {});
    if constexpr (SmiValuesAre31Bits()) {
      __ emit_i32_shri(dst.gp(), src.gp(), kSmiTagSize);
    } else {
      DCHECK(SmiValuesAre32Bits());
      // Remove topmost bit.
      __ emit_i64_shli(dst, src, 1);
      __ emit_i64_shri(dst, dst, kSmiTagSize + kSmiShiftSize + 1);
    }
    __ PushRegister(kI32, dst);
  }

  LiftoffRegister RttCanon(ModuleTypeIndex type_index, LiftoffRegList pinned) {
    LiftoffRegister rtt = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LOAD_TAGGED_PTR_INSTANCE_FIELD(rtt.gp(), ManagedObjectMaps, pinned);
    __ LoadTaggedPointer(
        rtt.gp(), rtt.gp(), no_reg,
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(type_index.index));
    return rtt;
  }

  enum NullSucceeds : bool {  // --
    kNullSucceeds = true,
    kNullFails = false
  };

  // Falls through on match (=successful type check).
  // Returns the register containing the object.
  void SubtypeCheck(const WasmModule* module, Register obj_reg,
                    ValueType obj_type, Register rtt_reg, ValueType rtt_type,
                    Register scratch_null, Register scratch2, Label* no_match,
                    NullSucceeds null_succeeds,
                    const FreezeCacheState& frozen) {
    Label match;
    bool is_cast_from_any = obj_type.is_reference_to(HeapType::kAny);

    // Skip the null check if casting from any and not {null_succeeds}.
    // In that case the instance type check will identify null as not being a
    // wasm object and fail.
    if (obj_type.is_nullable() && (!is_cast_from_any || null_succeeds)) {
      __ emit_cond_jump(kEqual, null_succeeds ? &match : no_match,
                        obj_type.kind(), obj_reg, scratch_null, frozen);
    }
    Register tmp1 = scratch_null;  // Done with null checks.

    // Add Smi check if the source type may store a Smi (i31ref or JS Smi).
    ValueType i31ref = ValueType::Ref(HeapType::kI31);
    // Ref.extern can also contain Smis, however there isn't any type that
    // could downcast to ref.extern.
    DCHECK(!rtt_type.is_reference_to(HeapType::kExtern));
    // Ref.i31 check has its own implementation.
    DCHECK(!rtt_type.is_reference_to(HeapType::kI31));
    if (IsSubtypeOf(i31ref, obj_type, module)) {
      Label* i31_target =
          IsSubtypeOf(i31ref, rtt_type, module) ? &match : no_match;
      __ emit_smi_check(obj_reg, i31_target, LiftoffAssembler::kJumpOnSmi,
                        frozen);
    }

    __ LoadMap(tmp1, obj_reg);
    // {tmp1} now holds the object's map.

    if (module->type(rtt_type.ref_index()).is_final) {
      // In this case, simply check for map equality.
      __ emit_cond_jump(kNotEqual, no_match, rtt_type.kind(), tmp1, rtt_reg,
                        frozen);
    } else {
      // Check for rtt equality, and if not, check if the rtt is a struct/array
      // rtt.
      __ emit_cond_jump(kEqual, &match, rtt_type.kind(), tmp1, rtt_reg, frozen);

      if (is_cast_from_any) {
        // Check for map being a map for a wasm object (struct, array, func).
        __ Load(LiftoffRegister(scratch2), tmp1, no_reg,
                wasm::ObjectAccess::ToTagged(Map::kInstanceTypeOffset),
                LoadType::kI32Load16U);
        __ emit_i32_subi(scratch2, scratch2, FIRST_WASM_OBJECT_TYPE);
        __ emit_i32_cond_jumpi(kUnsignedGreaterThan, no_match, scratch2,
                               LAST_WASM_OBJECT_TYPE - FIRST_WASM_OBJECT_TYPE,
                               frozen);
      }

      // Constant-time subtyping check: load exactly one candidate RTT from the
      // supertypes list.
      // Step 1: load the WasmTypeInfo into {tmp1}.
      constexpr int kTypeInfoOffset = wasm::ObjectAccess::ToTagged(
          Map::kConstructorOrBackPointerOrNativeContextOffset);
      __ LoadTaggedPointer(tmp1, tmp1, no_reg, kTypeInfoOffset);
      // Step 2: check the list's length if needed.
      uint32_t rtt_depth = GetSubtypingDepth(module, rtt_type.ref_index());
      if (rtt_depth >= kMinimumSupertypeArraySize) {
        LiftoffRegister list_length(scratch2);
        int offset =
            ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesLengthOffset);
        __ LoadSmiAsInt32(list_length, tmp1, offset);
        __ emit_i32_cond_jumpi(kUnsignedLessThanEqual, no_match,
                               list_length.gp(), rtt_depth, frozen);
      }
      // Step 3: load the candidate list slot into {tmp1}, and compare it.
      __ LoadTaggedPointer(
          tmp1, tmp1, no_reg,
          ObjectAccess::ToTagged(WasmTypeInfo::kSupertypesOffset +
                                 rtt_depth * kTaggedSize));
      __ emit_cond_jump(kNotEqual, no_match, rtt_type.kind(), tmp1, rtt_reg,
                        frozen);
    }

    // Fall through to {match}.
    __ bind(&match);
  }

  void RefTest(FullDecoder* decoder, ModuleTypeIndex ref_index,
               const Value& obj, Value* /* result_val */, bool null_succeeds) {
    Label return_false, done;
    LiftoffRegList pinned;
    LiftoffRegister rtt_reg = pinned.set(RttCanon(ref_index, pinned));
    LiftoffRegister obj_reg = pinned.set(__ PopToRegister(pinned));
    Register scratch_null =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    LiftoffRegister result = pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    if (obj.type.is_nullable()) {
      LoadNullValueForCompare(scratch_null, pinned, obj.type);
    }

    {
      FREEZE_STATE(frozen);
      SubtypeCheck(decoder->module_, obj_reg.gp(), obj.type, rtt_reg.gp(),
                   ValueType::Rtt(ref_index), scratch_null, result.gp(),
                   &return_false, null_succeeds ? kNullSucceeds : kNullFails,
                   frozen);

      __ LoadConstant(result, WasmValue(1));
      // TODO(jkummerow): Emit near jumps on platforms that have them.
      __ emit_jump(&done);

      __ bind(&return_false);
      __ LoadConstant(result, WasmValue(0));
      __ bind(&done);
    }
    __ PushRegister(kI32, result);
  }

  void RefTestAbstract(FullDecoder* decoder, const Value& obj, HeapType type,
                       Value* result_val, bool null_succeeds) {
    switch (type.representation()) {
      case HeapType::kEq:
        return AbstractTypeCheck<&LiftoffCompiler::EqCheck>(obj, null_succeeds);
      case HeapType::kI31:
        return AbstractTypeCheck<&LiftoffCompiler::I31Check>(obj,
                                                             null_succeeds);
      case HeapType::kStruct:
        return AbstractTypeCheck<&LiftoffCompiler::StructCheck>(obj,
                                                                null_succeeds);
      case HeapType::kArray:
        return AbstractTypeCheck<&LiftoffCompiler::ArrayCheck>(obj,
                                                               null_succeeds);
      case HeapType::kString:
        return AbstractTypeCheck<&LiftoffCompiler::StringCheck>(obj,
                                                                null_succeeds);
      case HeapType::kNone:
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
      case HeapType::kNoExn:
        DCHECK(null_succeeds);
        return EmitIsNull(kExprRefIsNull, obj.type);
      case HeapType::kAny:
        // Any may never need a cast as it is either implicitly convertible or
        // never convertible for any given type.
      default:
        UNREACHABLE();
    }
  }

  void RefCast(FullDecoder* decoder, ModuleTypeIndex ref_index,
               const Value& obj, Value* result, bool null_succeeds) {
    if (v8_flags.experimental_wasm_assume_ref_cast_succeeds) return;

    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapIllegalCast);
    LiftoffRegList pinned;
    LiftoffRegister rtt_reg = pinned.set(RttCanon(ref_index, pinned));
    LiftoffRegister obj_reg = pinned.set(__ PopToRegister(pinned));
    Register scratch_null =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    Register scratch2 = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    if (obj.type.is_nullable()) {
      LoadNullValueForCompare(scratch_null, pinned, obj.type);
    }

    {
      FREEZE_STATE(frozen);
      NullSucceeds on_null = null_succeeds ? kNullSucceeds : kNullFails;
      SubtypeCheck(decoder->module_, obj_reg.gp(), obj.type, rtt_reg.gp(),
                   ValueType::Rtt(ref_index), scratch_null, scratch2,
                   trap_label, on_null, frozen);
    }
    __ PushRegister(obj.type.kind(), obj_reg);
  }

  void RefCastAbstract(FullDecoder* decoder, const Value& obj, HeapType type,
                       Value* result_val, bool null_succeeds) {
    switch (type.representation()) {
      case HeapType::kEq:
        return AbstractTypeCast<&LiftoffCompiler::EqCheck>(obj, decoder,
                                                           null_succeeds);
      case HeapType::kI31:
        return AbstractTypeCast<&LiftoffCompiler::I31Check>(obj, decoder,
                                                            null_succeeds);
      case HeapType::kStruct:
        return AbstractTypeCast<&LiftoffCompiler::StructCheck>(obj, decoder,
                                                               null_succeeds);
      case HeapType::kArray:
        return AbstractTypeCast<&LiftoffCompiler::ArrayCheck>(obj, decoder,
                                                              null_succeeds);
      case HeapType::kString:
        return AbstractTypeCast<&LiftoffCompiler::StringCheck>(obj, decoder,
                                                               null_succeeds);
      case HeapType::kNone:
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
      case HeapType::kNoExn:
        DCHECK(null_succeeds);
        return AssertNullTypecheck(decoder, obj, result_val);
      case HeapType::kAny:
        // Any may never need a cast as it is either implicitly convertible or
        // never convertible for any given type.
      default:
        UNREACHABLE();
    }
  }

  void BrOnCast(FullDecoder* decoder, ModuleTypeIndex ref_index,
                const Value& obj, Value* /* result_on_branch */, uint32_t depth,
                bool null_succeeds) {
    // Avoid having sequences of branches do duplicate work.
    if (depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(depth)->br_merge()->arity, {});
    }

    Label cont_false;
    LiftoffRegList pinned;
    LiftoffRegister rtt_reg = pinned.set(RttCanon(ref_index, pinned));
    LiftoffRegister obj_reg = pinned.set(__ PeekToRegister(0, pinned));
    Register scratch_null =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    Register scratch2 = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    if (obj.type.is_nullable()) {
      LoadNullValue(scratch_null, kWasmAnyRef);
    }
    FREEZE_STATE(frozen);

    NullSucceeds null_handling = null_succeeds ? kNullSucceeds : kNullFails;
    SubtypeCheck(decoder->module_, obj_reg.gp(), obj.type, rtt_reg.gp(),
                 ValueType::Rtt(ref_index), scratch_null, scratch2, &cont_false,
                 null_handling, frozen);

    BrOrRet(decoder, depth);

    __ bind(&cont_false);
  }

  void BrOnCastFail(FullDecoder* decoder, ModuleTypeIndex ref_index,
                    const Value& obj, Value* /* result_on_fallthrough */,
                    uint32_t depth, bool null_succeeds) {
    // Avoid having sequences of branches do duplicate work.
    if (depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(depth)->br_merge()->arity, {});
    }

    Label cont_branch, fallthrough;
    LiftoffRegList pinned;
    LiftoffRegister rtt_reg = pinned.set(RttCanon(ref_index, pinned));
    LiftoffRegister obj_reg = pinned.set(__ PeekToRegister(0, pinned));
    Register scratch_null =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    Register scratch2 = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    if (obj.type.is_nullable()) {
      LoadNullValue(scratch_null, kWasmAnyRef);
    }
    FREEZE_STATE(frozen);

    NullSucceeds null_handling = null_succeeds ? kNullSucceeds : kNullFails;
    SubtypeCheck(decoder->module_, obj_reg.gp(), obj.type, rtt_reg.gp(),
                 ValueType::Rtt(ref_index), scratch_null, scratch2,
                 &cont_branch, null_handling, frozen);
    __ emit_jump(&fallthrough);

    __ bind(&cont_branch);
    BrOrRet(decoder, depth);

    __ bind(&fallthrough);
  }

  void BrOnCastAbstract(FullDecoder* decoder, const Value& obj, HeapType type,
                        Value* result_on_branch, uint32_t depth,
                        bool null_succeeds) {
    switch (type.representation()) {
      case HeapType::kEq:
        return BrOnAbstractType<&LiftoffCompiler::EqCheck>(obj, decoder, depth,
                                                           null_succeeds);
      case HeapType::kI31:
        return BrOnAbstractType<&LiftoffCompiler::I31Check>(obj, decoder, depth,
                                                            null_succeeds);
      case HeapType::kStruct:
        return BrOnAbstractType<&LiftoffCompiler::StructCheck>(
            obj, decoder, depth, null_succeeds);
      case HeapType::kArray:
        return BrOnAbstractType<&LiftoffCompiler::ArrayCheck>(
            obj, decoder, depth, null_succeeds);
      case HeapType::kString:
        return BrOnAbstractType<&LiftoffCompiler::StringCheck>(
            obj, decoder, depth, null_succeeds);
      case HeapType::kNone:
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
      case HeapType::kNoExn:
        DCHECK(null_succeeds);
        return BrOnNull(decoder, obj, depth, /*pass_null_along_branch*/ true,
                        nullptr);
      case HeapType::kAny:
        // Any may never need a cast as it is either implicitly convertible or
        // never convertible for any given type.
      default:
        UNREACHABLE();
    }
  }

  void BrOnCastFailAbstract(FullDecoder* decoder, const Value& obj,
                            HeapType type, Value* result_on_fallthrough,
                            uint32_t depth, bool null_succeeds) {
    switch (type.representation()) {
      case HeapType::kEq:
        return BrOnNonAbstractType<&LiftoffCompiler::EqCheck>(
            obj, decoder, depth, null_succeeds);
      case HeapType::kI31:
        return BrOnNonAbstractType<&LiftoffCompiler::I31Check>(
            obj, decoder, depth, null_succeeds);
      case HeapType::kStruct:
        return BrOnNonAbstractType<&LiftoffCompiler::StructCheck>(
            obj, decoder, depth, null_succeeds);
      case HeapType::kArray:
        return BrOnNonAbstractType<&LiftoffCompiler::ArrayCheck>(
            obj, decoder, depth, null_succeeds);
      case HeapType::kString:
        return BrOnNonAbstractType<&LiftoffCompiler::StringCheck>(
            obj, decoder, depth, null_succeeds);
      case HeapType::kNone:
      case HeapType::kNoExtern:
      case HeapType::kNoFunc:
      case HeapType::kNoExn:
        DCHECK(null_succeeds);
        return BrOnNonNull(decoder, obj, nullptr, depth,
                           /*drop_null_on_fallthrough*/ false);
      case HeapType::kAny:
        // Any may never need a cast as it is either implicitly convertible or
        // never convertible for any given type.
      default:
        UNREACHABLE();
    }
  }

  struct TypeCheck {
    Register obj_reg = no_reg;
    ValueType obj_type;
    Register tmp = no_reg;
    Label* no_match;
    bool null_succeeds;

    TypeCheck(ValueType obj_type, Label* no_match, bool null_succeeds)
        : obj_type(obj_type),
          no_match(no_match),
          null_succeeds(null_succeeds) {}

    Register null_reg() { return tmp; }       // After {Initialize}.
    Register instance_type() { return tmp; }  // After {LoadInstanceType}.
  };

  enum PopOrPeek { kPop, kPeek };

  void Initialize(TypeCheck& check, PopOrPeek pop_or_peek, ValueType type) {
    LiftoffRegList pinned;
    if (pop_or_peek == kPop) {
      check.obj_reg = pinned.set(__ PopToRegister(pinned)).gp();
    } else {
      check.obj_reg = pinned.set(__ PeekToRegister(0, pinned)).gp();
    }
    check.tmp = pinned.set(__ GetUnusedRegister(kGpReg, pinned)).gp();
    if (check.obj_type.is_nullable()) {
      LoadNullValue(check.null_reg(), type);
    }
  }
  void LoadInstanceType(TypeCheck& check, const FreezeCacheState& frozen,
                        Label* on_smi) {
    // The check for null_succeeds == true has to be handled by the caller!
    // TODO(mliedtke): Reiterate the null_succeeds case once all generic cast
    // instructions are implemented.
    if (!check.null_succeeds && check.obj_type.is_nullable()) {
      __ emit_cond_jump(kEqual, check.no_match, kRefNull, check.obj_reg,
                        check.null_reg(), frozen);
    }
    __ emit_smi_check(check.obj_reg, on_smi, LiftoffAssembler::kJumpOnSmi,
                      frozen);
    __ LoadMap(check.instance_type(), check.obj_reg);
    __ Load(LiftoffRegister(check.instance_type()), check.instance_type(),
            no_reg, wasm::ObjectAccess::ToTagged(Map::kInstanceTypeOffset),
            LoadType::kI32Load16U);
  }

  // Abstract type checkers. They all fall through on match.
  void StructCheck(TypeCheck& check, const FreezeCacheState& frozen) {
    LoadInstanceType(check, frozen, check.no_match);
    LiftoffRegister instance_type(check.instance_type());
    __ emit_i32_cond_jumpi(kNotEqual, check.no_match, check.instance_type(),
                           WASM_STRUCT_TYPE, frozen);
  }

  void ArrayCheck(TypeCheck& check, const FreezeCacheState& frozen) {
    LoadInstanceType(check, frozen, check.no_match);
    LiftoffRegister instance_type(check.instance_type());
    __ emit_i32_cond_jumpi(kNotEqual, check.no_match, check.instance_type(),
                           WASM_ARRAY_TYPE, frozen);
  }

  void I31Check(TypeCheck& check, const FreezeCacheState& frozen) {
    __ emit_smi_check(check.obj_reg, check.no_match,
                      LiftoffAssembler::kJumpOnNotSmi, frozen);
  }

  void EqCheck(TypeCheck& check, const FreezeCacheState& frozen) {
    Label match;
    LoadInstanceType(check, frozen, &match);
    // We're going to test a range of WasmObject instance types with a single
    // unsigned comparison.
    Register tmp = check.instance_type();
    __ emit_i32_subi(tmp, tmp, FIRST_WASM_OBJECT_TYPE);
    __ emit_i32_cond_jumpi(kUnsignedGreaterThan, check.no_match, tmp,
                           LAST_WASM_OBJECT_TYPE - FIRST_WASM_OBJECT_TYPE,
                           frozen);
    __ bind(&match);
  }

  void StringCheck(TypeCheck& check, const FreezeCacheState& frozen) {
    LoadInstanceType(check, frozen, check.no_match);
    LiftoffRegister instance_type(check.instance_type());
    __ emit_i32_cond_jumpi(kUnsignedGreaterThanEqual, check.no_match,
                           check.instance_type(), FIRST_NONSTRING_TYPE, frozen);
  }

  using TypeChecker = void (LiftoffCompiler::*)(TypeCheck& check,
                                                const FreezeCacheState& frozen);

  template <TypeChecker type_checker>
  void AbstractTypeCheck(const Value& object, bool null_succeeds) {
    Label match, no_match, done;
    TypeCheck check(object.type, &no_match, null_succeeds);
    Initialize(check, kPop, object.type);
    LiftoffRegister result(check.tmp);
    {
      FREEZE_STATE(frozen);

      if (null_succeeds && check.obj_type.is_nullable()) {
        __ emit_cond_jump(kEqual, &match, kRefNull, check.obj_reg,
                          check.null_reg(), frozen);
      }

      (this->*type_checker)(check, frozen);

      __ bind(&match);
      __ LoadConstant(result, WasmValue(1));
      // TODO(jkummerow): Emit near jumps on platforms that have them.
      __ emit_jump(&done);

      __ bind(&no_match);
      __ LoadConstant(result, WasmValue(0));
      __ bind(&done);
    }
    __ PushRegister(kI32, result);
  }

  template <TypeChecker type_checker>
  void AbstractTypeCast(const Value& object, FullDecoder* decoder,
                        bool null_succeeds) {
    Label match;
    Label* trap_label =
        AddOutOfLineTrap(decoder, Builtin::kThrowWasmTrapIllegalCast);
    TypeCheck check(object.type, trap_label, null_succeeds);
    Initialize(check, kPeek, object.type);
    FREEZE_STATE(frozen);

    if (null_succeeds && check.obj_type.is_nullable()) {
      __ emit_cond_jump(kEqual, &match, kRefNull, check.obj_reg,
                        check.null_reg(), frozen);
    }
    (this->*type_checker)(check, frozen);
    __ bind(&match);
  }

  template <TypeChecker type_checker>
  void BrOnAbstractType(const Value& object, FullDecoder* decoder,
                        uint32_t br_depth, bool null_succeeds) {
    // Avoid having sequences of branches do duplicate work.
    if (br_depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(br_depth)->br_merge()->arity, {});
    }

    Label no_match, match;
    TypeCheck check(object.type, &no_match, null_succeeds);
    Initialize(check, kPeek, object.type);
    FREEZE_STATE(frozen);

    if (null_succeeds && check.obj_type.is_nullable()) {
      __ emit_cond_jump(kEqual, &match, kRefNull, check.obj_reg,
                        check.null_reg(), frozen);
    }

    (this->*type_checker)(check, frozen);
    __ bind(&match);
    BrOrRet(decoder, br_depth);

    __ bind(&no_match);
  }

  template <TypeChecker type_checker>
  void BrOnNonAbstractType(const Value& object, FullDecoder* decoder,
                           uint32_t br_depth, bool null_succeeds) {
    // Avoid having sequences of branches do duplicate work.
    if (br_depth != decoder->control_depth() - 1) {
      __ PrepareForBranch(decoder->control_at(br_depth)->br_merge()->arity, {});
    }

    Label no_match, end;
    TypeCheck check(object.type, &no_match, null_succeeds);
    Initialize(check, kPeek, object.type);
    FREEZE_STATE(frozen);

    if (null_succeeds && check.obj_type.is_nullable()) {
      __ emit_cond_jump(kEqual, &end, kRefNull, check.obj_reg, check.null_reg(),
                        frozen);
    }

    (this->*type_checker)(check, frozen);
    __ emit_jump(&end);

    __ bind(&no_match);
    BrOrRet(decoder, br_depth);

    __ bind(&end);
  }

  void StringNewWtf8(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                     const unibrow::Utf8Variant variant, const Value& offset,
                     const Value& size, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    VarState memory_var{kI32, static_cast<int>(imm.index), 0};

    LiftoffRegister variant_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(variant_reg, static_cast<int32_t>(variant));
    VarState variant_var(kSmiKind, variant_reg, 0);

    VarState& size_var = __ cache_state()->stack_state.end()[-1];

    DCHECK(MatchingMemType(imm.memory, 1));
    VarState address = IndexToVarStateSaturating(1, &pinned);

    CallBuiltin(
        Builtin::kWasmStringNewWtf8,
        MakeSig::Returns(kRefNull).Params(kIntPtrKind, kI32, kI32, kSmiKind),
        {address, size_var, memory_var, variant_var}, decoder->position());
    __ DropValues(2);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringNewWtf8Array(FullDecoder* decoder,
                          const unibrow::Utf8Variant variant,
                          const Value& array, const Value& start,
                          const Value& end, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister array_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-3], pinned));
    MaybeEmitNullCheck(decoder, array_reg.gp(), pinned, array.type);
    VarState array_var(kRef, array_reg, 0);

    LiftoffRegister variant_reg =
        pinned.set(__ GetUnusedRegister(kGpReg, pinned));
    LoadSmi(variant_reg, static_cast<int32_t>(variant));
    VarState variant_var(kSmiKind, variant_reg, 0);

    CallBuiltin(Builtin::kWasmStringNewWtf8Array,
                MakeSig::Returns(kRefNull).Params(kI32, kI32, kRef, kSmiKind),
                {
                    __ cache_state()->stack_state.end()[-2],  // start
                    __ cache_state()->stack_state.end()[-1],  // end
                    array_var,
                    variant_var,
                },
                decoder->position());
    __ cache_state()->stack_state.pop_back(3);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringNewWtf16(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                      const Value& offset, const Value& size, Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    VarState memory_var{kI32, static_cast<int32_t>(imm.index), 0};

    VarState& size_var = __ cache_state()->stack_state.end()[-1];

    LiftoffRegList pinned;
    DCHECK(MatchingMemType(imm.memory, 1));
    VarState address = IndexToVarStateSaturating(1, &pinned);

    CallBuiltin(Builtin::kWasmStringNewWtf16,
                MakeSig::Returns(kRef).Params(kI32, kIntPtrKind, kI32),
                {memory_var, address, size_var}, decoder->position());
    __ DropValues(2);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringNewWtf16Array(FullDecoder* decoder, const Value& array,
                           const Value& start, const Value& end,
                           Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;

    LiftoffRegister array_reg = pinned.set(
        __ LoadToRegister(__ cache_state()->stack_state.end()[-3], pinned));
    MaybeEmitNullCheck(decoder, array_reg.gp(), pinned, array.type);
    VarState array_var(kRef, array_reg, 0);

    CallBuiltin(Builtin::kWasmStringNewWtf16Array,
                MakeSig::Returns(kRef).Params(kRef, kI32, kI32),
                {
                    array_var,
                    __ cache_state()->stack_state.end()[-2],  // start
                    __ cache_state()->stack_state.end()[-1],  // end
                },
                decoder->position());
    __ cache_state()->stack_state.pop_back(3);
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringConst(FullDecoder* decoder, const StringConstImmediate& imm,
                   Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    VarState index_var{kI32, static_cast<int32_t>(imm.index), 0};

    CallBuiltin(Builtin::kWasmStringConst, MakeSig::Returns(kRef).Params(kI32),
                {index_var}, decoder->position());
    RegisterDebugSideTableEntry(decoder, DebugSideTableBuilder::kDidSpill);

    LiftoffRegister result_reg(kReturnRegister0);
    __ PushRegister(kRef, result_reg);
  }

  void StringMeasureWtf8(FullDecoder* decoder,
                         const unibrow::Utf8Variant variant, const Value& str,
                         Value* result) {
    FUZZER_HEAVY_INSTRUCTION;
    LiftoffRegList pinned;
    LiftoffRegister string_reg = pinned.set(__ PopToRegister(pinned));
    MaybeEmitNullCheck(decoder, string_reg.gp(), pinned, str.type);
    VarState string_var(kRef, string_reg, 0);

    Builtin builtin;
    switch (variant) {
      case unibrow::Utf8Variant::kUtf8:
        builtin = Builtin::kWasmStringMeasureUtf8;
        break;
      case unibrow::Utf8Variant::kLossyUtf8:
      case unibrow::Utf8Variant::kWtf8:
        builtin = Builtin::kWasmStringMeasureWtf8;
        break;
      case unibrow::Utf8Variant::kUtf8NoTrap:
        UNREACHABLE();
    }
    CallBuiltin(builtin, MakeSig::Returns(kI32).Params(kRef),
                {
                    string_var,
                },
                decoder->position());
```