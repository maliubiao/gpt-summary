Response: The user is asking for a summary of the functionality of the provided C++ code snippet from the file `v8/src/compiler/wasm-compiler.cc`. This is part 3 of a 6-part request.

The code snippet seems to be focused on the `WasmGraphBuilder` class, which is responsible for building the graph representation of WebAssembly code. It includes functions for:

1. **Memory Access:**  Getting the current memory size, performing bounds checks, loading and storing data from memory (including lane-wise and transformed loads), and handling unaligned accesses. It also seems to have specific logic for asm.js memory access.
2. **Runtime Calls:**  Building calls to runtime functions, including those requiring a JavaScript context.
3. **Global Variables:** Getting and setting the values of global variables, considering mutability and import status.
4. **Table Operations:** Getting and setting elements in tables.
5. **Tracing:** Inserting calls for tracing function entry, exit, and memory operations.
6. **SIMD Operations:**  Generating nodes for various SIMD (vector) operations.
7. **Helper Functions:**  Functions for converting between data types (like Int64 to BigInt), setting source positions, and creating machine signatures.

I should focus on summarizing these core functionalities and, if possible, illustrate the connection to JavaScript using examples. Given this is part 3, I should not repeat information covered in previous parts (though I don't have access to them).
这段C++代码是`WasmGraphBuilder`类的一部分，它负责在V8的TurboFan编译器中构建WebAssembly代码的图表示（中间表示）。 这部分代码主要关注以下功能：

**1. 内存操作 (Memory Operations):**

* **`CurrentMemoryPages`:**  获取当前WebAssembly内存的页数。
* **`BoundsCheckMem`:**  插入代码以进行内存访问的边界检查。这包括检查索引是否越界，并根据配置（例如，是否启用trap handler）生成相应的trap或条件分支。
* **`LoadMem` 和 `StoreMem`:**  从WebAssembly内存中加载和存储数据。 这包括处理不同的数据类型、对齐方式，以及在必要时插入边界检查。 针对SIMD类型（如`v128`）也有专门的处理。
* **`LoadLane` 和 `StoreLane`:**  加载和存储SIMD向量中的特定通道（lane）。
* **`LoadTransform`:**  执行加载并进行转换，例如将较小的整数类型扩展到SIMD向量中。
* **`BuildAsmjsLoadMem` 和 `BuildAsmjsStoreMem`:**  处理asm.js风格的内存加载和存储，其语义与WebAssembly略有不同（例如，越界访问返回特定值或被忽略）。

**2. 运行时调用 (Runtime Calls):**

* **`BuildCallToRuntimeWithContext` 和 `BuildCallToRuntime`:**  生成调用V8运行时函数的代码。这些函数通常用于执行一些无法直接用机器码表达的操作，例如BigInt的转换或某些边界检查。

**3. 全局变量操作 (Global Variable Operations):**

* **`GlobalGet`:**  获取WebAssembly全局变量的值。
* **`GlobalSet`:**  设置WebAssembly全局变量的值。
* **`GetGlobalBaseAndOffset`:**  计算全局变量的基地址和偏移量，这取决于全局变量的可变性、导入状态和类型。

**4. 表操作 (Table Operations):**

* **`TableGet`:**  获取WebAssembly表中的元素。
* **`TableSet`:**  设置WebAssembly表中的元素。

**5. 代码追踪 (Tracing):**

* **`TraceFunctionEntry` 和 `TraceFunctionExit`:**  插入调用运行时函数的代码，用于在函数入口和出口进行追踪。
* **`TraceMemoryOperation`:**  插入代码以追踪内存操作，用于调试和性能分析。

**6. SIMD操作 (SIMD Operations):**

* 提供了大量的 `Build...` 和 `SimdOp` 函数来生成各种SIMD（单指令多数据）操作的节点，例如向量的加法、减法、乘法、比较、类型转换等。 例如 `BuildF64x2Ceil` 用于计算双精度浮点向量的向上取整。

**与JavaScript的关系（使用JavaScript举例说明）:**

WebAssembly 旨在与 JavaScript 无缝集成。 `wasm-compiler.cc` 中构建的图最终会生成机器码，这些机器码可以直接被 JavaScript 调用，反之亦然。

* **内存访问:** WebAssembly 模块可以创建 `WebAssembly.Memory` 实例，JavaScript 可以通过 `buffer` 属性访问其底层的 `ArrayBuffer`。  `WasmGraphBuilder` 生成的内存访问代码确保了在 WebAssembly 中对这块内存的安全访问。

```javascript
// JavaScript
const memory = new WebAssembly.Memory({ initial: 1 });
const wasmBytes = new Uint8Array([
  // ... wasm 二进制代码，包含一个存储操作
]);
const wasmModule = new WebAssembly.Module(wasmBytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, { /* imports */ });

// 假设 wasm 模块中有一个函数将值 42 存储到内存地址 0
// WasmGraphBuilder 会生成类似的代码来执行这个存储操作

// 在 JavaScript 中可以查看内存是否被修改
const view = new Uint8Array(memory.buffer);
console.log(view[0]); // 可能输出 42
```

* **运行时调用:** 当 WebAssembly 代码需要执行一些高级操作（例如类型转换，或者某些平台不支持的SIMD操作），`WasmGraphBuilder` 会生成调用 V8 运行时函数的代码。 这些运行时函数是用 C++ 实现的，与 V8 的 JavaScript 引擎紧密集成。 例如，将 WebAssembly 的 64 位整数转换为 JavaScript 的 BigInt 对象就需要运行时调用。

```javascript
// JavaScript
const wasmBytes = new Uint8Array([
  // ... wasm 二进制代码，包含一个返回 i64 的函数
]);
const wasmModule = new WebAssembly.Module(wasmBytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, { /* imports */ });

// 假设 wasm 模块中有一个函数 getI64 返回一个 64 位整数
const i64Value = wasmInstance.exports.getI64();

// 如果架构不支持原生 64 位整数操作，WasmGraphBuilder 可能会生成
// 调用运行时函数的代码将 i64Value 转换为 JavaScript 的 BigInt
console.log(typeof i64Value); // 可能输出 "bigint"
```

* **全局变量:** WebAssembly 模块可以声明全局变量，这些变量可以通过 JavaScript 的 `WebAssembly.Instance.exports` 访问。 `WasmGraphBuilder` 生成的代码负责在 WebAssembly 中读取和写入这些全局变量。

```javascript
// JavaScript
const wasmBytes = new Uint8Array([
  // ... wasm 二进制代码，包含一个导出的全局变量
]);
const wasmModule = new WebAssembly.Module(wasmBytes);
const wasmInstance = new WebAssembly.Instance(wasmModule, { /* imports */ });

// 假设 wasm 模块中导出了一个名为 myGlobal 的全局变量
console.log(wasmInstance.exports.myGlobal.value);

wasmInstance.exports.setMyGlobal(100); // 假设有设置全局变量的导出函数
console.log(wasmInstance.exports.myGlobal.value);
```

总而言之，这段 `wasm-compiler.cc` 中的代码是 WebAssembly 代码编译的关键部分，它将 WebAssembly 的抽象指令转换为底层的机器码操作，并处理了与 JavaScript 互操作的各种细节，包括内存管理、类型转换和调用约定。

Prompt: 
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共6部分，请归纳一下它的功能

"""
offset));
}

Node* WasmGraphBuilder::CurrentMemoryPages(const wasm::WasmMemory* memory) {
  // CurrentMemoryPages can not be called from asm.js.
  DCHECK_EQ(wasm::kWasmOrigin, env_->module->origin);

  Node* mem_size = MemSize(memory->index);
  Node* result =
      gasm_->WordShr(mem_size, gasm_->IntPtrConstant(wasm::kWasmPageSizeLog2));
  result = memory->is_memory64() ? gasm_->BuildChangeIntPtrToInt64(result)
                                 : gasm_->BuildTruncateIntPtrToInt32(result);
  return result;
}

// Only call this function for code which is not reused across instantiations,
// as we do not patch the embedded js_context.
Node* WasmGraphBuilder::BuildCallToRuntimeWithContext(Runtime::FunctionId f,
                                                      Node* js_context,
                                                      Node** parameters,
                                                      int parameter_count) {
  const Runtime::Function* fun = Runtime::FunctionForId(f);
  auto call_descriptor = Linkage::GetRuntimeCallDescriptor(
      mcgraph()->zone(), f, fun->nargs, Operator::kNoProperties,
      CallDescriptor::kNoFlags);
  // The CEntryStub is loaded from the IsolateRoot so that generated code is
  // Isolate independent. At the moment this is only done for CEntryStub(1).
  Node* isolate_root = BuildLoadIsolateRoot();
  DCHECK_EQ(1, fun->result_size);
  auto centry_id = Builtin::kWasmCEntry;
  int builtin_slot_offset = IsolateData::BuiltinSlotOffset(centry_id);
  Node* centry_stub =
      gasm_->Load(MachineType::Pointer(), isolate_root, builtin_slot_offset);
  // TODO(titzer): allow arbitrary number of runtime arguments
  // At the moment we only allow 5 parameters. If more parameters are needed,
  // increase this constant accordingly.
  static const int kMaxParams = 5;
  DCHECK_GE(kMaxParams, parameter_count);
  Node* inputs[kMaxParams + 6];
  int count = 0;
  inputs[count++] = centry_stub;
  for (int i = 0; i < parameter_count; i++) {
    inputs[count++] = parameters[i];
  }
  inputs[count++] =
      mcgraph()->ExternalConstant(ExternalReference::Create(f));  // ref
  inputs[count++] = Int32Constant(fun->nargs);                    // arity
  inputs[count++] = js_context;                                   // js_context
  inputs[count++] = effect();
  inputs[count++] = control();

  return gasm_->Call(call_descriptor, count, inputs);
}

Node* WasmGraphBuilder::BuildCallToRuntime(Runtime::FunctionId f,
                                           Node** parameters,
                                           int parameter_count) {
  return BuildCallToRuntimeWithContext(f, NoContextConstant(), parameters,
                                       parameter_count);
}

void WasmGraphBuilder::GetGlobalBaseAndOffset(const wasm::WasmGlobal& global,
                                              Node** base, Node** offset) {
  if (global.mutability && global.imported) {
    Node* imported_mutable_globals = LOAD_INSTANCE_FIELD(
        ImportedMutableGlobals, MachineType::TaggedPointer());
    Node* field_offset = Int32Constant(
        wasm::ObjectAccess::ElementOffsetInTaggedFixedAddressArray(
            global.index));
    if (global.type.is_reference()) {
      // Load the base from the ImportedMutableGlobalsBuffer of the instance.
      Node* buffers = LOAD_INSTANCE_FIELD(ImportedMutableGlobalsBuffers,
                                          MachineType::TaggedPointer());
      *base = gasm_->LoadFixedArrayElementAny(buffers, global.index);

      Node* index = gasm_->LoadFromObject(
          MachineType::Int32(), imported_mutable_globals, field_offset);
      // For this case, {index} gives the index of the global in the buffer.
      // From the index, calculate the actual offset in the FixedArray. This is
      // kHeaderSize + (index * kTaggedSize).
      *offset = gasm_->IntAdd(
          gasm_->IntMul(index, gasm_->IntPtrConstant(kTaggedSize)),
          gasm_->IntPtrConstant(
              wasm::ObjectAccess::ToTagged(FixedArray::OffsetOfElementAt(0))));
    } else {
      *base = gasm_->LoadFromObject(kMaybeSandboxedPointer,
                                    imported_mutable_globals, field_offset);
      *offset = gasm_->IntPtrConstant(0);
    }
  } else if (global.type.is_reference()) {
    *base =
        LOAD_INSTANCE_FIELD(TaggedGlobalsBuffer, MachineType::TaggedPointer());
    *offset = gasm_->IntPtrConstant(
        wasm::ObjectAccess::ElementOffsetInTaggedFixedArray(global.offset));
  } else {
    *base = LOAD_INSTANCE_FIELD(GlobalsStart, MachineType::Pointer());
    *offset = gasm_->IntPtrConstant(global.offset);
  }
}

Node* WasmGraphBuilder::GlobalGet(uint32_t index) {
  const wasm::WasmGlobal& global = env_->module->globals[index];
  if (global.type == wasm::kWasmS128) has_simd_ = true;
  Node* base = nullptr;
  Node* offset = nullptr;
  GetGlobalBaseAndOffset(global, &base, &offset);
  MachineType mem_type = global.type.machine_type();
  return global.mutability ? gasm_->LoadFromObject(mem_type, base, offset)
                           : gasm_->LoadImmutable(mem_type, base, offset);
}

void WasmGraphBuilder::GlobalSet(uint32_t index, Node* val) {
  const wasm::WasmGlobal& global = env_->module->globals[index];
  if (global.type == wasm::kWasmS128) has_simd_ = true;
  Node* base = nullptr;
  Node* offset = nullptr;
  GetGlobalBaseAndOffset(global, &base, &offset);
  ObjectAccess access(global.type.machine_type(), global.type.is_reference()
                                                      ? kFullWriteBarrier
                                                      : kNoWriteBarrier);
  gasm_->StoreToObject(access, base, offset, val);
}

Node* WasmGraphBuilder::TableGet(uint32_t table_index, Node* index,
                                 wasm::WasmCodePosition position) {
  const wasm::WasmTable& table = env_->module->tables[table_index];
  bool is_funcref = IsSubtypeOf(table.type, wasm::kWasmFuncRef, env_->module);
  auto stub =
      is_funcref ? Builtin::kWasmTableGetFuncRef : Builtin::kWasmTableGet;

  TableTypeToUintPtrOrOOBTrap(table.address_type, {&index}, position);
  return gasm_->CallBuiltinThroughJumptable(
      stub, Operator::kNoThrow, gasm_->IntPtrConstant(table_index), index);
}

void WasmGraphBuilder::TableSet(uint32_t table_index, Node* index, Node* val,
                                wasm::WasmCodePosition position) {
  const wasm::WasmTable& table = env_->module->tables[table_index];
  bool is_funcref = IsSubtypeOf(table.type, wasm::kWasmFuncRef, env_->module);
  auto stub =
      is_funcref ? Builtin::kWasmTableSetFuncRef : Builtin::kWasmTableSet;
  TableTypeToUintPtrOrOOBTrap(table.address_type, {&index}, position);
  gasm_->CallBuiltinThroughJumptable(stub, Operator::kNoThrow,
                                     gasm_->IntPtrConstant(table_index),
                                     gasm_->Int32Constant(0), index, val);
}

// Insert code to bounds check a memory access if necessary. Return the
// bounds-checked index, which is guaranteed to have (the equivalent of)
// {uintptr_t} representation.
std::pair<Node*, BoundsCheckResult> WasmGraphBuilder::BoundsCheckMem(
    const wasm::WasmMemory* memory, uint8_t access_size, Node* index,
    uintptr_t offset, wasm::WasmCodePosition position,
    EnforceBoundsCheck enforce_check, AlignmentCheck alignment_check) {
  DCHECK_LE(1, access_size);

  wasm::BoundsCheckStrategy bounds_checks = memory->bounds_checks;

  // The function body decoder already validated that the access is not
  // statically OOB.
  DCHECK(base::IsInBounds<uintptr_t>(offset, access_size,
                                     memory->max_memory_size));

  // Convert the index to uintptr.
  Node* converted_index = index;
  if (!memory->is_memory64()) {
    converted_index = gasm_->BuildChangeUint32ToUintPtr(index);
  } else if (kSystemPointerSize == kInt32Size) {
    // Only use the low word for the following bounds check.
    converted_index = gasm_->TruncateInt64ToInt32(index);
  }

  UintPtrMatcher constant_index(converted_index);
  // Do alignment checks only for > 1 byte accesses (otherwise they trivially
  // pass).
  const uintptr_t align_mask = access_size - 1;
  if (static_cast<bool>(alignment_check) && align_mask != 0) {
    // Don't emit an alignment check if the index is a constant.
    // TODO(wasm): a constant match is also done above in {BoundsCheckMem}.
    if (constant_index.HasResolvedValue()) {
      uintptr_t effective_offset = constant_index.ResolvedValue() + offset;
      if ((effective_offset & align_mask) != 0) {
        // statically known to be unaligned; trap.
        TrapIfEq32(wasm::kTrapUnalignedAccess, Int32Constant(0), 0, position);
      }
    } else {
      // Unlike regular memory accesses, atomic memory accesses should trap if
      // the effective offset is misaligned.
      // TODO(wasm): this addition is redundant with one inserted by
      // {MemBuffer}.
      Node* effective_offset =
          gasm_->IntAdd(MemBuffer(memory->index, offset), converted_index);

      Node* cond =
          gasm_->WordAnd(effective_offset, gasm_->IntPtrConstant(align_mask));
      TrapIfFalse(wasm::kTrapUnalignedAccess,
                  gasm_->Word32Equal(cond, Int32Constant(0)), position);
    }
  }

  // If no bounds checks should be performed (for testing), just return the
  // converted index and assume it to be in-bounds.
  if (bounds_checks == wasm::kNoBoundsChecks) {
    return {converted_index, BoundsCheckResult::kInBounds};
  }

  if (memory->is_memory64() && kSystemPointerSize == kInt32Size) {
    // In memory64 mode on 32-bit systems, the upper 32 bits need to be zero to
    // succeed the bounds check.
    DCHECK_EQ(wasm::kExplicitBoundsChecks, bounds_checks);
    Node* high_word =
        gasm_->TruncateInt64ToInt32(gasm_->Word64Shr(index, Int32Constant(32)));
    TrapIfTrue(wasm::kTrapMemOutOfBounds, high_word, position);
  }

  // The accessed memory is [index + offset, index + end_offset].
  // Check that the last read byte (at {index + end_offset}) is in bounds.
  // 1) Check that {end_offset < mem_size}. This also ensures that we can safely
  //    compute {effective_size} as {mem_size - end_offset)}.
  //    {effective_size} is >= 1 if condition 1) holds.
  // 2) Check that {index + end_offset < mem_size} by
  //    - computing {effective_size} as {mem_size - end_offset} and
  //    - checking that {index < effective_size}.

  uintptr_t end_offset = offset + access_size - 1u;
  DCHECK_LT(end_offset, memory->max_memory_size);

  if (constant_index.HasResolvedValue() &&
      end_offset <= memory->min_memory_size &&
      constant_index.ResolvedValue() < memory->min_memory_size - end_offset) {
    // The input index is a constant and everything is statically within
    // bounds of the smallest possible memory.
    return {converted_index, BoundsCheckResult::kInBounds};
  }

  if (bounds_checks == wasm::kTrapHandler &&
      enforce_check == EnforceBoundsCheck::kCanOmitBoundsCheck) {
    if (memory->is_memory64()) {
      // Bounds check `index` against `max_mem_size - end_offset`, such that
      // at runtime `index + end_offset` will be within `max_mem_size`, where
      // the trap handler can handle out-of-bound accesses.
      Node* cond = gasm_->Uint64LessThan(
          converted_index, Int64Constant(memory->max_memory_size - end_offset));
      TrapIfFalse(wasm::kTrapMemOutOfBounds, cond, position);
    }
    return {converted_index, BoundsCheckResult::kTrapHandler};
  }

  Node* mem_size = MemSize(memory->index);

  Node* end_offset_node = mcgraph_->UintPtrConstant(end_offset);
  if (end_offset > memory->min_memory_size) {
    // The end offset is larger than the smallest memory.
    // Dynamically check the end offset against the dynamic memory size.
    Node* cond = gasm_->UintLessThan(end_offset_node, mem_size);
    TrapIfFalse(wasm::kTrapMemOutOfBounds, cond, position);
  }

  // This produces a positive number since {end_offset <= min_size <= mem_size}.
  Node* effective_size = gasm_->IntSub(mem_size, end_offset_node);

  // Introduce the actual bounds check.
  Node* cond = gasm_->UintLessThan(converted_index, effective_size);
  TrapIfFalse(wasm::kTrapMemOutOfBounds, cond, position);
  return {converted_index, BoundsCheckResult::kDynamicallyChecked};
}

const Operator* WasmGraphBuilder::GetSafeLoadOperator(
    int offset, wasm::ValueTypeBase type) {
  int alignment = offset % type.value_kind_size();
  MachineType mach_type = type.machine_type();
  if (COMPRESS_POINTERS_BOOL && mach_type.IsTagged()) {
    // We are loading tagged value from off-heap location, so we need to load
    // it as a full word otherwise we will not be able to decompress it.
    mach_type = MachineType::Pointer();
  }
  if (alignment == 0 || mcgraph()->machine()->UnalignedLoadSupported(
                            type.machine_representation())) {
    return mcgraph()->machine()->Load(mach_type);
  }
  return mcgraph()->machine()->UnalignedLoad(mach_type);
}

const Operator* WasmGraphBuilder::GetSafeStoreOperator(
    int offset, wasm::ValueTypeBase type) {
  int alignment = offset % type.value_kind_size();
  MachineRepresentation rep = type.machine_representation();
  if (COMPRESS_POINTERS_BOOL && IsAnyTagged(rep)) {
    // We are storing tagged value to off-heap location, so we need to store
    // it as a full word otherwise we will not be able to decompress it.
    rep = MachineType::PointerRepresentation();
  }
  if (alignment == 0 || mcgraph()->machine()->UnalignedStoreSupported(rep)) {
    StoreRepresentation store_rep(rep, WriteBarrierKind::kNoWriteBarrier);
    return mcgraph()->machine()->Store(store_rep);
  }
  UnalignedStoreRepresentation store_rep(rep);
  return mcgraph()->machine()->UnalignedStore(store_rep);
}

void WasmGraphBuilder::TraceFunctionEntry(wasm::WasmCodePosition position) {
  Node* call = BuildCallToRuntime(Runtime::kWasmTraceEnter, nullptr, 0);
  SetSourcePosition(call, position);
}

void WasmGraphBuilder::TraceFunctionExit(base::Vector<Node*> vals,
                                         wasm::WasmCodePosition position) {
  Node* info = gasm_->IntPtrConstant(0);
  size_t num_returns = vals.size();
  if (num_returns == 1) {
    wasm::ValueType return_type = function_sig_->GetReturn(0);
    MachineRepresentation rep = return_type.machine_representation();
    int size = ElementSizeInBytes(rep);
    info = gasm_->StackSlot(size, size);

    gasm_->Store(StoreRepresentation(rep, kNoWriteBarrier), info,
                 Int32Constant(0), vals[0]);
  }

  Node* call = BuildCallToRuntime(Runtime::kWasmTraceExit, &info, 1);
  SetSourcePosition(call, position);
}

void WasmGraphBuilder::TraceMemoryOperation(bool is_store,
                                            MachineRepresentation rep,
                                            Node* index, uintptr_t offset,
                                            wasm::WasmCodePosition position) {
  int kAlign = 4;  // Ensure that the LSB is 0, such that this looks like a Smi.
  TNode<RawPtrT> info =
      gasm_->StackSlot(sizeof(wasm::MemoryTracingInfo), kAlign);

  Node* effective_offset = gasm_->IntAdd(gasm_->UintPtrConstant(offset), index);
  auto store = [&](int field_offset, MachineRepresentation rep, Node* data) {
    gasm_->Store(StoreRepresentation(rep, kNoWriteBarrier), info,
                 Int32Constant(field_offset), data);
  };
  // Store effective_offset, is_store, and mem_rep.
  store(offsetof(wasm::MemoryTracingInfo, offset),
        MachineType::PointerRepresentation(), effective_offset);
  store(offsetof(wasm::MemoryTracingInfo, is_store),
        MachineRepresentation::kWord8, Int32Constant(is_store ? 1 : 0));
  store(offsetof(wasm::MemoryTracingInfo, mem_rep),
        MachineRepresentation::kWord8, Int32Constant(static_cast<int>(rep)));

  Node* args[] = {info};
  Node* call =
      BuildCallToRuntime(Runtime::kWasmTraceMemory, args, arraysize(args));
  SetSourcePosition(call, position);
}

namespace {
LoadTransformation GetLoadTransformation(
    MachineType memtype, wasm::LoadTransformationKind transform) {
  switch (transform) {
    case wasm::LoadTransformationKind::kSplat: {
      if (memtype == MachineType::Int8()) {
        return LoadTransformation::kS128Load8Splat;
      } else if (memtype == MachineType::Int16()) {
        return LoadTransformation::kS128Load16Splat;
      } else if (memtype == MachineType::Int32()) {
        return LoadTransformation::kS128Load32Splat;
      } else if (memtype == MachineType::Int64()) {
        return LoadTransformation::kS128Load64Splat;
      }
      break;
    }
    case wasm::LoadTransformationKind::kExtend: {
      if (memtype == MachineType::Int8()) {
        return LoadTransformation::kS128Load8x8S;
      } else if (memtype == MachineType::Uint8()) {
        return LoadTransformation::kS128Load8x8U;
      } else if (memtype == MachineType::Int16()) {
        return LoadTransformation::kS128Load16x4S;
      } else if (memtype == MachineType::Uint16()) {
        return LoadTransformation::kS128Load16x4U;
      } else if (memtype == MachineType::Int32()) {
        return LoadTransformation::kS128Load32x2S;
      } else if (memtype == MachineType::Uint32()) {
        return LoadTransformation::kS128Load32x2U;
      }
      break;
    }
    case wasm::LoadTransformationKind::kZeroExtend: {
      if (memtype == MachineType::Int32()) {
        return LoadTransformation::kS128Load32Zero;
      } else if (memtype == MachineType::Int64()) {
        return LoadTransformation::kS128Load64Zero;
      }
      break;
    }
  }
  UNREACHABLE();
}

MemoryAccessKind GetMemoryAccessKind(MachineGraph* mcgraph,
                                     MachineRepresentation memrep,
                                     BoundsCheckResult bounds_check_result) {
  if (bounds_check_result == BoundsCheckResult::kTrapHandler) {
    // Protected instructions do not come in an 'unaligned' flavor, so the trap
    // handler can currently only be used on systems where all memory accesses
    // are allowed to be unaligned.
    DCHECK(memrep == MachineRepresentation::kWord8 ||
           mcgraph->machine()->UnalignedLoadSupported(memrep));
    return MemoryAccessKind::kProtectedByTrapHandler;
  }
  if (memrep != MachineRepresentation::kWord8 &&
      !mcgraph->machine()->UnalignedLoadSupported(memrep)) {
    return MemoryAccessKind::kUnaligned;
  }
  return MemoryAccessKind::kNormal;
}
}  // namespace

Node* WasmGraphBuilder::LoadLane(const wasm::WasmMemory* memory,
                                 wasm::ValueType type, MachineType memtype,
                                 Node* value, Node* index, uintptr_t offset,
                                 uint32_t alignment, uint8_t laneidx,
                                 wasm::WasmCodePosition position) {
  has_simd_ = true;
  Node* load;
  uint8_t access_size = memtype.MemSize();
  BoundsCheckResult bounds_check_result;
  std::tie(index, bounds_check_result) = BoundsCheckMem(
      memory, access_size, index, offset, position,
      EnforceBoundsCheck::kCanOmitBoundsCheck, AlignmentCheck::kNo);

  MemoryAccessKind load_kind = GetMemoryAccessKind(
      mcgraph_, memtype.representation(), bounds_check_result);

  load = SetEffect(graph()->NewNode(
      mcgraph()->machine()->LoadLane(load_kind, memtype, laneidx),
      MemBuffer(memory->index, offset), index, value, effect(), control()));

  if (load_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    SetSourcePosition(load, position);
  }
  if (v8_flags.trace_wasm_memory) {
    // TODO(14259): Implement memory tracing for multiple memories.
    CHECK_EQ(0, memory->index);
    TraceMemoryOperation(false, memtype.representation(), index, offset,
                         position);
  }

  return load;
}

Node* WasmGraphBuilder::LoadTransform(const wasm::WasmMemory* memory,
                                      wasm::ValueType type, MachineType memtype,
                                      wasm::LoadTransformationKind transform,
                                      Node* index, uintptr_t offset,
                                      uint32_t alignment,
                                      wasm::WasmCodePosition position) {
  has_simd_ = true;

  // Wasm semantics throw on OOB. Introduce explicit bounds check and
  // conditioning when not using the trap handler.

  // Load extends always load 8 bytes.
  uint8_t access_size = transform == wasm::LoadTransformationKind::kExtend
                            ? 8
                            : memtype.MemSize();
  BoundsCheckResult bounds_check_result;
  std::tie(index, bounds_check_result) = BoundsCheckMem(
      memory, access_size, index, offset, position,
      EnforceBoundsCheck::kCanOmitBoundsCheck, AlignmentCheck::kNo);

  LoadTransformation transformation = GetLoadTransformation(memtype, transform);
  MemoryAccessKind load_kind = GetMemoryAccessKind(
      mcgraph_, memtype.representation(), bounds_check_result);

  Node* load = SetEffect(graph()->NewNode(
      mcgraph()->machine()->LoadTransform(load_kind, transformation),
      MemBuffer(memory->index, offset), index, effect(), control()));

  if (load_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    SetSourcePosition(load, position);
  }

  if (v8_flags.trace_wasm_memory) {
    // TODO(14259): Implement memory tracing for multiple memories.
    CHECK_EQ(0, memory->index);
    TraceMemoryOperation(false, memtype.representation(), index, offset,
                         position);
  }
  return load;
}

Node* WasmGraphBuilder::LoadMem(const wasm::WasmMemory* memory,
                                wasm::ValueType type, MachineType memtype,
                                Node* index, uintptr_t offset,
                                uint32_t alignment,
                                wasm::WasmCodePosition position) {
  if (memtype.representation() == MachineRepresentation::kSimd128) {
    has_simd_ = true;
  }

  // Wasm semantics throw on OOB. Introduce explicit bounds check and
  // conditioning when not using the trap handler.
  BoundsCheckResult bounds_check_result;
  std::tie(index, bounds_check_result) = BoundsCheckMem(
      memory, memtype.MemSize(), index, offset, position,
      EnforceBoundsCheck::kCanOmitBoundsCheck, AlignmentCheck::kNo);

  Node* mem_start = MemBuffer(memory->index, offset);
  Node* load;
  switch (GetMemoryAccessKind(mcgraph_, memtype.representation(),
                              bounds_check_result)) {
    case MemoryAccessKind::kUnaligned:
      load = gasm_->LoadUnaligned(memtype, mem_start, index);
      break;
    case MemoryAccessKind::kProtectedByTrapHandler:
      load = gasm_->ProtectedLoad(memtype, mem_start, index);
      SetSourcePosition(load, position);
      break;
    case MemoryAccessKind::kNormal:
      load = gasm_->Load(memtype, mem_start, index);
      break;
  }

#if defined(V8_TARGET_BIG_ENDIAN)
  load = BuildChangeEndiannessLoad(load, memtype, type);
#endif

  if (type == wasm::kWasmI64 &&
      ElementSizeInBytes(memtype.representation()) < 8) {
    // TODO(titzer): TF zeroes the upper bits of 64-bit loads for subword sizes.
    load = memtype.IsSigned()
               ? gasm_->ChangeInt32ToInt64(load)     // sign extend
               : gasm_->ChangeUint32ToUint64(load);  // zero extend
  }

  if (v8_flags.trace_wasm_memory) {
    // TODO(14259): Implement memory tracing for multiple memories.
    CHECK_EQ(0, memory->index);
    TraceMemoryOperation(false, memtype.representation(), index, offset,
                         position);
  }

  return load;
}

void WasmGraphBuilder::StoreLane(const wasm::WasmMemory* memory,
                                 MachineRepresentation mem_rep, Node* index,
                                 uintptr_t offset, uint32_t alignment,
                                 Node* val, uint8_t laneidx,
                                 wasm::WasmCodePosition position,
                                 wasm::ValueType type) {
  has_simd_ = true;
  BoundsCheckResult bounds_check_result;
  std::tie(index, bounds_check_result) = BoundsCheckMem(
      memory, i::ElementSizeInBytes(mem_rep), index, offset, position,
      wasm::kPartialOOBWritesAreNoops ? EnforceBoundsCheck::kCanOmitBoundsCheck
                                      : EnforceBoundsCheck::kNeedsBoundsCheck,
      AlignmentCheck::kNo);
  MemoryAccessKind load_kind =
      GetMemoryAccessKind(mcgraph_, mem_rep, bounds_check_result);

  Node* store = SetEffect(graph()->NewNode(
      mcgraph()->machine()->StoreLane(load_kind, mem_rep, laneidx),
      MemBuffer(memory->index, offset), index, val, effect(), control()));

  if (load_kind == MemoryAccessKind::kProtectedByTrapHandler) {
    SetSourcePosition(store, position);
  }
  if (v8_flags.trace_wasm_memory) {
    // TODO(14259): Implement memory tracing for multiple memories.
    CHECK_EQ(0, memory->index);
    TraceMemoryOperation(true, mem_rep, index, offset, position);
  }
}

void WasmGraphBuilder::StoreMem(const wasm::WasmMemory* memory,
                                MachineRepresentation mem_rep, Node* index,
                                uintptr_t offset, uint32_t alignment, Node* val,
                                wasm::WasmCodePosition position,
                                wasm::ValueType type) {
  if (mem_rep == MachineRepresentation::kSimd128) {
    has_simd_ = true;
  }

  BoundsCheckResult bounds_check_result;
  std::tie(index, bounds_check_result) = BoundsCheckMem(
      memory, i::ElementSizeInBytes(mem_rep), index, offset, position,
      wasm::kPartialOOBWritesAreNoops ? EnforceBoundsCheck::kCanOmitBoundsCheck
                                      : EnforceBoundsCheck::kNeedsBoundsCheck,
      AlignmentCheck::kNo);

#if defined(V8_TARGET_BIG_ENDIAN)
  val = BuildChangeEndiannessStore(val, mem_rep, type);
#endif

  Node* mem_start = MemBuffer(memory->index, offset);
  switch (GetMemoryAccessKind(mcgraph_, mem_rep, bounds_check_result)) {
    case MemoryAccessKind::kUnaligned:
      gasm_->StoreUnaligned(UnalignedStoreRepresentation{mem_rep}, mem_start,
                            index, val);
      break;
    case MemoryAccessKind::kProtectedByTrapHandler: {
      Node* store = gasm_->ProtectedStore(mem_rep, mem_start, index, val);
      SetSourcePosition(store, position);
      if (mem_rep == MachineRepresentation::kSimd128) {
        graph()->RecordSimdStore(store);
      }
      break;
    }
    case MemoryAccessKind::kNormal: {
      Node* store = gasm_->Store(StoreRepresentation{mem_rep, kNoWriteBarrier},
                                 mem_start, index, val);
      if (mem_rep == MachineRepresentation::kSimd128) {
        graph()->RecordSimdStore(store);
      }
      break;
    }
  }

  if (v8_flags.trace_wasm_memory) {
    // TODO(14259): Implement memory tracing for multiple memories.
    CHECK_EQ(0, memory->index);
    TraceMemoryOperation(true, mem_rep, index, offset, position);
  }
}

Node* WasmGraphBuilder::BuildAsmjsLoadMem(MachineType type, Node* index) {
  DCHECK_NOT_NULL(instance_cache_);
  DCHECK_EQ(1, env_->module->memories.size());
  Node* mem_start = MemStart(0);
  Node* mem_size = MemSize(0);

  // Asm.js semantics are defined in terms of typed arrays, hence OOB
  // reads return {undefined} coerced to the result type (0 for integers, NaN
  // for float and double).
  // Note that we check against the memory size ignoring the size of the
  // stored value, which is conservative if misaligned. Technically, asm.js
  // should never have misaligned accesses.
  // Technically, we should do a signed 32-to-ptr extension here. However,
  // that is an explicit instruction, whereas unsigned extension is implicit.
  // Since the difference is only observable for memories larger than 2 GiB,
  // and since we disallow such memories, we can use unsigned extension.
  index = gasm_->BuildChangeUint32ToUintPtr(index);
  Diamond bounds_check(graph(), mcgraph()->common(),
                       gasm_->UintLessThan(index, mem_size), BranchHint::kTrue);
  bounds_check.Chain(control());

  Node* load = graph()->NewNode(mcgraph()->machine()->Load(type), mem_start,
                                index, effect(), bounds_check.if_true);
  SetEffectControl(bounds_check.EffectPhi(load, effect()), bounds_check.merge);

  Node* oob_value;
  switch (type.representation()) {
    case MachineRepresentation::kWord8:
    case MachineRepresentation::kWord16:
    case MachineRepresentation::kWord32:
      oob_value = Int32Constant(0);
      break;
    case MachineRepresentation::kWord64:
      oob_value = Int64Constant(0);
      break;
    case MachineRepresentation::kFloat32:
      oob_value = Float32Constant(std::numeric_limits<float>::quiet_NaN());
      break;
    case MachineRepresentation::kFloat64:
      oob_value = Float64Constant(std::numeric_limits<double>::quiet_NaN());
      break;
    default:
      UNREACHABLE();
  }

  return bounds_check.Phi(type.representation(), load, oob_value);
}

Node* WasmGraphBuilder::BuildAsmjsStoreMem(MachineType type, Node* index,
                                           Node* val) {
  DCHECK_NOT_NULL(instance_cache_);
  DCHECK_EQ(1, env_->module->memories.size());
  Node* mem_start = MemStart(0);
  Node* mem_size = MemSize(0);

  // Asm.js semantics are to ignore OOB writes.
  // Note that we check against the memory size ignoring the size of the
  // stored value, which is conservative if misaligned. Technically, asm.js
  // should never have misaligned accesses.
  // See {BuildAsmJsLoadMem} for background on using an unsigned extension
  // here.
  index = gasm_->BuildChangeUint32ToUintPtr(index);
  Diamond bounds_check(graph(), mcgraph()->common(),
                       gasm_->UintLessThan(index, mem_size), BranchHint::kTrue);
  bounds_check.Chain(control());

  const Operator* store_op = mcgraph()->machine()->Store(StoreRepresentation(
      type.representation(), WriteBarrierKind::kNoWriteBarrier));
  Node* store = graph()->NewNode(store_op, mem_start, index, val, effect(),
                                 bounds_check.if_true);
  SetEffectControl(bounds_check.EffectPhi(store, effect()), bounds_check.merge);
  return val;
}

Node* WasmGraphBuilder::BuildF64x2Ceil(Node* input) {
  MachineType type = MachineType::Simd128();
  ExternalReference ref = ExternalReference::wasm_f64x2_ceil();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64x2Floor(Node* input) {
  MachineType type = MachineType::Simd128();
  ExternalReference ref = ExternalReference::wasm_f64x2_floor();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64x2Trunc(Node* input) {
  MachineType type = MachineType::Simd128();
  ExternalReference ref = ExternalReference::wasm_f64x2_trunc();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF64x2NearestInt(Node* input) {
  MachineType type = MachineType::Simd128();
  ExternalReference ref = ExternalReference::wasm_f64x2_nearest_int();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32x4Ceil(Node* input) {
  MachineType type = MachineType::Simd128();
  ExternalReference ref = ExternalReference::wasm_f32x4_ceil();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32x4Floor(Node* input) {
  MachineType type = MachineType::Simd128();
  ExternalReference ref = ExternalReference::wasm_f32x4_floor();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32x4Trunc(Node* input) {
  MachineType type = MachineType::Simd128();
  ExternalReference ref = ExternalReference::wasm_f32x4_trunc();
  return BuildCFuncInstruction(ref, type, input);
}

Node* WasmGraphBuilder::BuildF32x4NearestInt(Node* input) {
  MachineType type = MachineType::Simd128();
  ExternalReference ref = ExternalReference::wasm_f32x4_nearest_int();
  return BuildCFuncInstruction(ref, type, input);
}

void WasmGraphBuilder::PrintDebugName(Node* node) {
  PrintF("#%d:%s", node->id(), node->op()->mnemonic());
}

Graph* WasmGraphBuilder::graph() { return mcgraph()->graph(); }

Zone* WasmGraphBuilder::graph_zone() { return graph()->zone(); }

template <typename T>
Signature<MachineRepresentation>* CreateMachineSignature(
    Zone* zone, const Signature<T>* sig, wasm::CallOrigin origin) {
  Signature<MachineRepresentation>::Builder builder(zone, sig->return_count(),
                                                    sig->parameter_count());
  for (auto ret : sig->returns()) {
    if (origin == wasm::kCalledFromJS) {
      builder.AddReturn(MachineRepresentation::kTagged);
    } else {
      builder.AddReturn(ret.machine_representation());
    }
  }

  for (auto param : sig->parameters()) {
    if (origin == wasm::kCalledFromJS) {
      // Parameters coming from JavaScript are always tagged values. Especially
      // when the signature says that it's an I64 value, then a BigInt object is
      // provided by JavaScript, and not two 32-bit parameters.
      builder.AddParam(MachineRepresentation::kTagged);
    } else {
      builder.AddParam(param.machine_representation());
    }
  }
  return builder.Get();
}

template Signature<MachineRepresentation>* CreateMachineSignature(
    Zone*, const Signature<wasm::ValueType>*, wasm::CallOrigin);
template Signature<MachineRepresentation>* CreateMachineSignature(
    Zone*, const Signature<wasm::CanonicalValueType>*, wasm::CallOrigin);

void WasmGraphBuilder::LowerInt64(Signature<MachineRepresentation>* sig) {
  if (mcgraph()->machine()->Is64()) return;
  Int64Lowering r(mcgraph()->graph(), mcgraph()->machine(), mcgraph()->common(),
                  gasm_->simplified(), mcgraph()->zone(), sig);
  r.LowerGraph();
}

void WasmGraphBuilder::LowerInt64(wasm::CallOrigin origin) {
  Signature<MachineRepresentation>* machine_sig =
      function_sig_ != nullptr
          ? CreateMachineSignature(mcgraph()->zone(), function_sig_, origin)
          : CreateMachineSignature(mcgraph()->zone(), wrapper_sig_, origin);
  LowerInt64(machine_sig);
}

Node* WasmGraphBuilder::BuildChangeInt64ToBigInt(Node* input,
                                                 StubCallMode stub_mode) {
  if (mcgraph()->machine()->Is64()) {
    return gasm_->CallBuiltin(Builtin::kI64ToBigInt, Operator::kEliminatable,
                              input);
  } else {
    Node* low_word = gasm_->TruncateInt64ToInt32(input);
    Node* high_word = gasm_->TruncateInt64ToInt32(
        gasm_->Word64Shr(input, gasm_->Int32Constant(32)));
    return gasm_->CallBuiltin(Builtin::kI32PairToBigInt,
                              Operator::kEliminatable, low_word, high_word);
  }
}

void WasmGraphBuilder::SetSourcePosition(Node* node,
                                         wasm::WasmCodePosition position) {
  DCHECK_NE(position, wasm::kNoCodePosition);
  if (source_position_table_) {
    source_position_table_->SetSourcePosition(
        node, SourcePosition(position, inlining_id_));
  }
}

Node* WasmGraphBuilder::S128Zero() {
  has_simd_ = true;
  return graph()->NewNode(mcgraph()->machine()->S128Zero());
}

Node* WasmGraphBuilder::SimdOp(wasm::WasmOpcode opcode, Node* const* inputs) {
  has_simd_ = true;
  switch (opcode) {
    case wasm::kExprF64x2Splat:
      return graph()->NewNode(mcgraph()->machine()->F64x2Splat(), inputs[0]);
    case wasm::kExprF64x2Abs:
      return graph()->NewNode(mcgraph()->machine()->F64x2Abs(), inputs[0]);
    case wasm::kExprF64x2Neg:
      return graph()->NewNode(mcgraph()->machine()->F64x2Neg(), inputs[0]);
    case wasm::kExprF64x2Sqrt:
      return graph()->NewNode(mcgraph()->machine()->F64x2Sqrt(), inputs[0]);
    case wasm::kExprF64x2Add:
      return graph()->NewNode(mcgraph()->machine()->F64x2Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Sub:
      return graph()->NewNode(mcgraph()->machine()->F64x2Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Mul:
      return graph()->NewNode(mcgraph()->machine()->F64x2Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Div:
      return graph()->NewNode(mcgraph()->machine()->F64x2Div(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Min:
      return graph()->NewNode(mcgraph()->machine()->F64x2Min(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Max:
      return graph()->NewNode(mcgraph()->machine()->F64x2Max(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Eq:
      return graph()->NewNode(mcgraph()->machine()->F64x2Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Ne:
      return graph()->NewNode(mcgraph()->machine()->F64x2Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Lt:
      return graph()->NewNode(mcgraph()->machine()->F64x2Lt(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Le:
      return graph()->NewNode(mcgraph()->machine()->F64x2Le(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Gt:
      return graph()->NewNode(mcgraph()->machine()->F64x2Lt(), inputs[1],
                              inputs[0]);
    case wasm::kExprF64x2Ge:
      return graph()->NewNode(mcgraph()->machine()->F64x2Le(), inputs[1],
                              inputs[0]);
    case wasm::kExprF64x2Qfma:
      return graph()->NewNode(mcgraph()->machine()->F64x2Qfma(), inputs[0],
                              inputs[1], inputs[2]);
    case wasm::kExprF64x2Qfms:
      return graph()->NewNode(mcgraph()->machine()->F64x2Qfms(), inputs[0],
                              inputs[1], inputs[2]);
    case wasm::kExprF64x2Pmin:
      return graph()->NewNode(mcgraph()->machine()->F64x2Pmin(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Pmax:
      return graph()->NewNode(mcgraph()->machine()->F64x2Pmax(), inputs[0],
                              inputs[1]);
    case wasm::kExprF64x2Ceil:
      // Architecture support for F64x2Ceil and Float64RoundUp is the same.
      if (!mcgraph()->machine()->Float64RoundUp().IsSupported())
        return BuildF64x2Ceil(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F64x2Ceil(), inputs[0]);
    case wasm::kExprF64x2Floor:
      // Architecture support for F64x2Floor and Float64RoundDown is the same.
      if (!mcgraph()->machine()->Float64RoundDown().IsSupported())
        return BuildF64x2Floor(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F64x2Floor(), inputs[0]);
    case wasm::kExprF64x2Trunc:
      // Architecture support for F64x2Trunc and Float64RoundTruncate is the
      // same.
      if (!mcgraph()->machine()->Float64RoundTruncate().IsSupported())
        return BuildF64x2Trunc(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F64x2Trunc(), inputs[0]);
    case wasm::kExprF64x2NearestInt:
      // Architecture support for F64x2NearestInt and Float64RoundTiesEven is
      // the same.
      if (!mcgraph()->machine()->Float64RoundTiesEven().IsSupported())
        return BuildF64x2NearestInt(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F64x2NearestInt(),
                              inputs[0]);
    case wasm::kExprF64x2ConvertLowI32x4S:
      return graph()->NewNode(mcgraph()->machine()->F64x2ConvertLowI32x4S(),
                              inputs[0]);
    case wasm::kExprF64x2ConvertLowI32x4U:
      return graph()->NewNode(mcgraph()->machine()->F64x2ConvertLowI32x4U(),
                              inputs[0]);
    case wasm::kExprF64x2PromoteLowF32x4:
      return graph()->NewNode(mcgraph()->machine()->F64x2PromoteLowF32x4(),
                              inputs[0]);
    case wasm::kExprF32x4Splat:
      return graph()->NewNode(mcgraph()->machine()->F32x4Splat(), inputs[0]);
    case wasm::kExprF32x4SConvertI32x4:
      return graph()->NewNode(mcgraph()->machine()->F32x4SConvertI32x4(),
                              inputs[0]);
    case wasm::kExprF32x4UConvertI32x4:
      return graph()->NewNode(mcgraph()->machine()->F32x4UConvertI32x4(),
                              inputs[0]);
    case wasm::kExprF32x4Abs:
      return graph()->NewNode(mcgraph()->machine()->F32x4Abs(), inputs[0]);
    case wasm::kExprF32x4Neg:
      return graph()->NewNode(mcgraph()->machine()->F32x4Neg(), inputs[0]);
    case wasm::kExprF32x4Sqrt:
      return graph()->NewNode(mcgraph()->machine()->F32x4Sqrt(), inputs[0]);
    case wasm::kExprF32x4Add:
      return graph()->NewNode(mcgraph()->machine()->F32x4Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Sub:
      return graph()->NewNode(mcgraph()->machine()->F32x4Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Mul:
      return graph()->NewNode(mcgraph()->machine()->F32x4Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Div:
      return graph()->NewNode(mcgraph()->machine()->F32x4Div(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Min:
      return graph()->NewNode(mcgraph()->machine()->F32x4Min(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Max:
      return graph()->NewNode(mcgraph()->machine()->F32x4Max(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Eq:
      return graph()->NewNode(mcgraph()->machine()->F32x4Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Ne:
      return graph()->NewNode(mcgraph()->machine()->F32x4Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Lt:
      return graph()->NewNode(mcgraph()->machine()->F32x4Lt(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Le:
      return graph()->NewNode(mcgraph()->machine()->F32x4Le(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Gt:
      return graph()->NewNode(mcgraph()->machine()->F32x4Lt(), inputs[1],
                              inputs[0]);
    case wasm::kExprF32x4Ge:
      return graph()->NewNode(mcgraph()->machine()->F32x4Le(), inputs[1],
                              inputs[0]);
    case wasm::kExprF32x4Qfma:
      return graph()->NewNode(mcgraph()->machine()->F32x4Qfma(), inputs[0],
                              inputs[1], inputs[2]);
    case wasm::kExprF32x4Qfms:
      return graph()->NewNode(mcgraph()->machine()->F32x4Qfms(), inputs[0],
                              inputs[1], inputs[2]);
    case wasm::kExprF32x4Pmin:
      return graph()->NewNode(mcgraph()->machine()->F32x4Pmin(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Pmax:
      return graph()->NewNode(mcgraph()->machine()->F32x4Pmax(), inputs[0],
                              inputs[1]);
    case wasm::kExprF32x4Ceil:
      // Architecture support for F32x4Ceil and Float32RoundUp is the same.
      if (!mcgraph()->machine()->Float32RoundUp().IsSupported())
        return BuildF32x4Ceil(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F32x4Ceil(), inputs[0]);
    case wasm::kExprF32x4Floor:
      // Architecture support for F32x4Floor and Float32RoundDown is the same.
      if (!mcgraph()->machine()->Float32RoundDown().IsSupported())
        return BuildF32x4Floor(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F32x4Floor(), inputs[0]);
    case wasm::kExprF32x4Trunc:
      // Architecture support for F32x4Trunc and Float32RoundTruncate is the
      // same.
      if (!mcgraph()->machine()->Float32RoundTruncate().IsSupported())
        return BuildF32x4Trunc(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F32x4Trunc(), inputs[0]);
    case wasm::kExprF32x4NearestInt:
      // Architecture support for F32x4NearestInt and Float32RoundTiesEven is
      // the same.
      if (!mcgraph()->machine()->Float32RoundTiesEven().IsSupported())
        return BuildF32x4NearestInt(inputs[0]);
      return graph()->NewNode(mcgraph()->machine()->F32x4NearestInt(),
                              inputs[0]);
    case wasm::kExprF32x4DemoteF64x2Zero:
      return graph()->NewNode(mcgraph()->machine()->F32x4DemoteF64x2Zero(),
                              inputs[0]);
    case wasm::kExprI64x2Splat:
      return graph()->NewNode(mcgraph()->machine()->I64x2Splat(), inputs[0]);
    case wasm::kExprI64x2Abs:
      return graph()->NewNode(mcgraph()->machine()->I64x2Abs(), inputs[0]);
    case wasm::kExprI64x2Neg:
      return graph()->NewNode(mcgraph()->machine()->I64x2Neg(), inputs[0]);
    case wasm::kExprI64x2SConvertI32x4Low:
      return graph()->NewNode(mcgraph()->machine()->I64x2SConvertI32x4Low(),
                              inputs[0]);
    case wasm::kExprI64x2SConvertI32x4High:
      return graph()->NewNode(mcgraph()->machine()->I64x2SConvertI32x4High(),
                              inputs[0]);
    case wasm::kExprI64x2UConvertI32x4Low:
      return graph()->NewNode(mcgraph()->machine()->I64x2UConvertI32x4Low(),
                              inputs[0]);
    case wasm::kExprI64x2UConvertI32x4High:
      return graph()->NewNode(mcgraph()->machine()->I64x2UConvertI32x4High(),
                              inputs[0]);
    case wasm::kExprI64x2BitMask:
      return graph()->NewNode(mcgraph()->machine()->I64x2BitMask(), inputs[0]);
    case wasm::kExprI64x2Shl:
      return graph()->NewNode(mcgraph()->machine()->I64x2Shl(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2ShrS:
      return graph()->NewNode(mcgraph()->machine()->I64x2ShrS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Add:
      return graph()->NewNode(mcgraph()->machine()->I64x2Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Sub:
      return graph()->NewNode(mcgraph()->machine()->I64x2Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Mul:
      return graph()->NewNode(mcgraph()->machine()->I64x2Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Eq:
      return graph()->NewNode(mcgraph()->machine()->I64x2Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2Ne:
      return graph()->NewNode(mcgraph()->machine()->I64x2Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2LtS:
      return graph()->NewNode(mcgraph()->machine()->I64x2GtS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI64x2LeS:
      return graph()->NewNode(mcgraph()->machine()->I64x2GeS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI64x2GtS:
      return graph()->NewNode(mcgraph()->machine()->I64x2GtS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2GeS:
      return graph()->NewNode(mcgraph()->machine()->I64x2GeS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2ShrU:
      return graph()->NewNode(mcgraph()->machine()->I64x2ShrU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI64x2ExtMulLowI32x4S:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtMulLowI32x4S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtMulHighI32x4S:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtMulHighI32x4S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtMulLowI32x4U:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtMulLowI32x4U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI64x2ExtMulHighI32x4U:
      return graph()->NewNode(mcgraph()->machine()->I64x2ExtMulHighI32x4U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4Splat:
      return graph()->NewNode(mcgraph()->machine()->I32x4Splat(), inputs[0]);
    case wasm::kExprI32x4SConvertF32x4:
      return graph()->NewNode(mcgraph()->machine()->I32x4SConvertF32x4(),
                              inputs[0]);
    case wasm::kExprI32x4UConvertF32x4:
      return graph()->NewNode(mcgraph()->machine()->I32x4UConvertF32x4(),
                              inputs[0]);
    case wasm::kExprI32x4SConvertI16x8Low:
      return graph()->NewNode(mcgraph()->machine()->I32x4SConvertI16x8Low(),
                              inputs[0]);
    case wasm::kExprI32x4SConvertI16x8High:
      return graph()->NewNode(mcgraph()->machine()->I32x4SConvertI16x8High(),
                              inputs[0]);
    case wasm::kExprI32x4Neg:
      return graph()->NewNode(mcgraph()->machine()->I32x4Neg(), inputs[0]);
    case wasm::kExprI32x4Shl:
      return graph()->NewNode(mcgraph()->machine()->I32x4Shl(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4ShrS:
      return graph()->NewNode(mcgraph()->machine()->I32x4ShrS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Add:
      return graph()->NewNode(mcgraph()->machine()->I32x4Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Sub:
      return graph()->NewNode(mcgraph()->machine()->I32x4Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Mul:
      return graph()->NewNode(mcgraph()->machine()->I32x4Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4MinS:
      return graph()->NewNode(mcgraph()->machine()->I32x4MinS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4MaxS:
      return graph()->NewNode(mcgraph()->machine()->I32x4MaxS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Eq:
      return graph()->NewNode(mcgraph()->machine()->I32x4Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Ne:
      return graph()->NewNode(mcgraph()->machine()->I32x4Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4LtS:
      return graph()->NewNode(mcgraph()->machine()->I32x4GtS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI32x4LeS:
      return graph()->NewNode(mcgraph()->machine()->I32x4GeS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI32x4GtS:
      return graph()->NewNode(mcgraph()->machine()->I32x4GtS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4GeS:
      return graph()->NewNode(mcgraph()->machine()->I32x4GeS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4UConvertI16x8Low:
      return graph()->NewNode(mcgraph()->machine()->I32x4UConvertI16x8Low(),
                              inputs[0]);
    case wasm::kExprI32x4UConvertI16x8High:
      return graph()->NewNode(mcgraph()->machine()->I32x4UConvertI16x8High(),
                              inputs[0]);
    case wasm::kExprI32x4ShrU:
      return graph()->NewNode(mcgraph()->machine()->I32x4ShrU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4MinU:
      return graph()->NewNode(mcgraph()->machine()->I32x4MinU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4MaxU:
      return graph()->NewNode(mcgraph()->machine()->I32x4MaxU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4LtU:
      return graph()->NewNode(mcgraph()->machine()->I32x4GtU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI32x4LeU:
      return graph()->NewNode(mcgraph()->machine()->I32x4GeU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI32x4GtU:
      return graph()->NewNode(mcgraph()->machine()->I32x4GtU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4GeU:
      return graph()->NewNode(mcgraph()->machine()->I32x4GeU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4Abs:
      return graph()->NewNode(mcgraph()->machine()->I32x4Abs(), inputs[0]);
    case wasm::kExprI32x4BitMask:
      return graph()->NewNode(mcgraph()->machine()->I32x4BitMask(), inputs[0]);
    case wasm::kExprI32x4DotI16x8S:
      return graph()->NewNode(mcgraph()->machine()->I32x4DotI16x8S(), inputs[0],
                              inputs[1]);
    case wasm::kExprI32x4ExtMulLowI16x8S:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtMulLowI16x8S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtMulHighI16x8S:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtMulHighI16x8S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtMulLowI16x8U:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtMulLowI16x8U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtMulHighI16x8U:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtMulHighI16x8U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4ExtAddPairwiseI16x8S:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtAddPairwiseI16x8S(),
                              inputs[0]);
    case wasm::kExprI32x4ExtAddPairwiseI16x8U:
      return graph()->NewNode(mcgraph()->machine()->I32x4ExtAddPairwiseI16x8U(),
                              inputs[0]);
    case wasm::kExprI32x4TruncSatF64x2SZero:
      return graph()->NewNode(mcgraph()->machine()->I32x4TruncSatF64x2SZero(),
                              inputs[0]);
    case wasm::kExprI32x4TruncSatF64x2UZero:
      return graph()->NewNode(mcgraph()->machine()->I32x4TruncSatF64x2UZero(),
                              inputs[0]);
    case wasm::kExprI16x8Splat:
      return graph()->NewNode(mcgraph()->machine()->I16x8Splat(), inputs[0]);
    case wasm::kExprI16x8SConvertI8x16Low:
      return graph()->NewNode(mcgraph()->machine()->I16x8SConvertI8x16Low(),
                              inputs[0]);
    case wasm::kExprI16x8SConvertI8x16High:
      return graph()->NewNode(mcgraph()->machine()->I16x8SConvertI8x16High(),
                              inputs[0]);
    case wasm::kExprI16x8Shl:
      return graph()->NewNode(mcgraph()->machine()->I16x8Shl(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8ShrS:
      return graph()->NewNode(mcgraph()->machine()->I16x8ShrS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Neg:
      return graph()->NewNode(mcgraph()->machine()->I16x8Neg(), inputs[0]);
    case wasm::kExprI16x8SConvertI32x4:
      return graph()->NewNode(mcgraph()->machine()->I16x8SConvertI32x4(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8Add:
      return graph()->NewNode(mcgraph()->machine()->I16x8Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8AddSatS:
      return graph()->NewNode(mcgraph()->machine()->I16x8AddSatS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Sub:
      return graph()->NewNode(mcgraph()->machine()->I16x8Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8SubSatS:
      return graph()->NewNode(mcgraph()->machine()->I16x8SubSatS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Mul:
      return graph()->NewNode(mcgraph()->machine()->I16x8Mul(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8MinS:
      return graph()->NewNode(mcgraph()->machine()->I16x8MinS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8MaxS:
      return graph()->NewNode(mcgraph()->machine()->I16x8MaxS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Eq:
      return graph()->NewNode(mcgraph()->machine()->I16x8Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8Ne:
      return graph()->NewNode(mcgraph()->machine()->I16x8Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8LtS:
      return graph()->NewNode(mcgraph()->machine()->I16x8GtS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI16x8LeS:
      return graph()->NewNode(mcgraph()->machine()->I16x8GeS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI16x8GtS:
      return graph()->NewNode(mcgraph()->machine()->I16x8GtS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8GeS:
      return graph()->NewNode(mcgraph()->machine()->I16x8GeS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8UConvertI8x16Low:
      return graph()->NewNode(mcgraph()->machine()->I16x8UConvertI8x16Low(),
                              inputs[0]);
    case wasm::kExprI16x8UConvertI8x16High:
      return graph()->NewNode(mcgraph()->machine()->I16x8UConvertI8x16High(),
                              inputs[0]);
    case wasm::kExprI16x8UConvertI32x4:
      return graph()->NewNode(mcgraph()->machine()->I16x8UConvertI32x4(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ShrU:
      return graph()->NewNode(mcgraph()->machine()->I16x8ShrU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8AddSatU:
      return graph()->NewNode(mcgraph()->machine()->I16x8AddSatU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8SubSatU:
      return graph()->NewNode(mcgraph()->machine()->I16x8SubSatU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8MinU:
      return graph()->NewNode(mcgraph()->machine()->I16x8MinU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8MaxU:
      return graph()->NewNode(mcgraph()->machine()->I16x8MaxU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8LtU:
      return graph()->NewNode(mcgraph()->machine()->I16x8GtU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI16x8LeU:
      return graph()->NewNode(mcgraph()->machine()->I16x8GeU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI16x8GtU:
      return graph()->NewNode(mcgraph()->machine()->I16x8GtU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8GeU:
      return graph()->NewNode(mcgraph()->machine()->I16x8GeU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI16x8RoundingAverageU:
      return graph()->NewNode(mcgraph()->machine()->I16x8RoundingAverageU(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8Q15MulRSatS:
      return graph()->NewNode(mcgraph()->machine()->I16x8Q15MulRSatS(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8RelaxedQ15MulRS:
      return graph()->NewNode(mcgraph()->machine()->I16x8RelaxedQ15MulRS(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8DotI8x16I7x16S:
      return graph()->NewNode(mcgraph()->machine()->I16x8DotI8x16I7x16S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI32x4DotI8x16I7x16AddS:
      return graph()->NewNode(mcgraph()->machine()->I32x4DotI8x16I7x16AddS(),
                              inputs[0], inputs[1], inputs[2]);
    case wasm::kExprI16x8Abs:
      return graph()->NewNode(mcgraph()->machine()->I16x8Abs(), inputs[0]);
    case wasm::kExprI16x8BitMask:
      return graph()->NewNode(mcgraph()->machine()->I16x8BitMask(), inputs[0]);
    case wasm::kExprI16x8ExtMulLowI8x16S:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtMulLowI8x16S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtMulHighI8x16S:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtMulHighI8x16S(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtMulLowI8x16U:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtMulLowI8x16U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtMulHighI8x16U:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtMulHighI8x16U(),
                              inputs[0], inputs[1]);
    case wasm::kExprI16x8ExtAddPairwiseI8x16S:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtAddPairwiseI8x16S(),
                              inputs[0]);
    case wasm::kExprI16x8ExtAddPairwiseI8x16U:
      return graph()->NewNode(mcgraph()->machine()->I16x8ExtAddPairwiseI8x16U(),
                              inputs[0]);
    case wasm::kExprI8x16Splat:
      return graph()->NewNode(mcgraph()->machine()->I8x16Splat(), inputs[0]);
    case wasm::kExprI8x16Neg:
      return graph()->NewNode(mcgraph()->machine()->I8x16Neg(), inputs[0]);
    case wasm::kExprI8x16Shl:
      return graph()->NewNode(mcgraph()->machine()->I8x16Shl(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16ShrS:
      return graph()->NewNode(mcgraph()->machine()->I8x16ShrS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16SConvertI16x8:
      return graph()->NewNode(mcgraph()->machine()->I8x16SConvertI16x8(),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16Add:
      return graph()->NewNode(mcgraph()->machine()->I8x16Add(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16AddSatS:
      return graph()->NewNode(mcgraph()->machine()->I8x16AddSatS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16Sub:
      return graph()->NewNode(mcgraph()->machine()->I8x16Sub(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16SubSatS:
      return graph()->NewNode(mcgraph()->machine()->I8x16SubSatS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16MinS:
      return graph()->NewNode(mcgraph()->machine()->I8x16MinS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16MaxS:
      return graph()->NewNode(mcgraph()->machine()->I8x16MaxS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16Eq:
      return graph()->NewNode(mcgraph()->machine()->I8x16Eq(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16Ne:
      return graph()->NewNode(mcgraph()->machine()->I8x16Ne(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16LtS:
      return graph()->NewNode(mcgraph()->machine()->I8x16GtS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI8x16LeS:
      return graph()->NewNode(mcgraph()->machine()->I8x16GeS(), inputs[1],
                              inputs[0]);
    case wasm::kExprI8x16GtS:
      return graph()->NewNode(mcgraph()->machine()->I8x16GtS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16GeS:
      return graph()->NewNode(mcgraph()->machine()->I8x16GeS(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16ShrU:
      return graph()->NewNode(mcgraph()->machine()->I8x16ShrU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16UConvertI16x8:
      return graph()->NewNode(mcgraph()->machine()->I8x16UConvertI16x8(),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16AddSatU:
      return graph()->NewNode(mcgraph()->machine()->I8x16AddSatU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16SubSatU:
      return graph()->NewNode(mcgraph()->machine()->I8x16SubSatU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16MinU:
      return graph()->NewNode(mcgraph()->machine()->I8x16MinU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16MaxU:
      return graph()->NewNode(mcgraph()->machine()->I8x16MaxU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16LtU:
      return graph()->NewNode(mcgraph()->machine()->I8x16GtU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI8x16LeU:
      return graph()->NewNode(mcgraph()->machine()->I8x16GeU(), inputs[1],
                              inputs[0]);
    case wasm::kExprI8x16GtU:
      return graph()->NewNode(mcgraph()->machine()->I8x16GtU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16GeU:
      return graph()->NewNode(mcgraph()->machine()->I8x16GeU(), inputs[0],
                              inputs[1]);
    case wasm::kExprI8x16RoundingAverageU:
      return graph()->NewNode(mcgraph()->machine()->I8x16RoundingAverageU(),
                              inputs[0], inputs[1]);
    case wasm::kExprI8x16Popcnt:
      return graph()->NewNode(mcgraph()->machine()->I8x16Popcnt(), inputs[0]);
    case wasm::kExprI8x16Abs:
      return graph()->NewNode(mcgraph()->machine()->I8x16Abs(), inputs[0]);
    case wasm::kExprI8x16BitMask:
      return graph()->NewNode(mcgraph()->machine()->I8x16BitMask(), inputs[0]);
    case wasm::kExprS128And:
      return graph()->NewNode(mcgraph()->machine()->S128And(), inputs[0],
                              inputs[1]);
    case wasm::kExprS128Or:
      return graph()->NewNode(mcgraph()->machine()->S128Or(), inputs[0],
                              inputs[1]);
    case wasm::kExprS128Xor:
      return graph()->NewNode(mcgraph()->machine()->S128Xor(), inputs[0],
                              inputs[1]);
    case wasm::kExprS128Not:
"""


```