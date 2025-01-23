Response:
Let's break down the thought process for analyzing the provided C++ code snippet.

**1. Initial Scan and Keywords:**

The first step is a quick scan for recognizable keywords and structures. We see:

* `WasmGraphBuilder`: This immediately suggests we're dealing with the code generation or compilation phase for WebAssembly within V8. "GraphBuilder" implies construction of some sort of intermediate representation, likely a graph.
* `Node*`: This pointer type appears frequently, reinforcing the idea of a graph data structure where nodes represent operations or values.
* `gasm_->`: This prefix strongly suggests an interaction with a code generation backend (likely TurboFan's assembly generation).
* `Runtime::FunctionId`, `Builtin::kWasmCEntry`, `ExternalReference`: These point to interaction with V8's runtime system and built-in functions.
* `MemSize`, `GlobalGet`, `TableGet`, `LoadMem`, `StoreMem`: These are clearly operations related to accessing WebAssembly's memory, globals, and tables.
* `BoundsCheckMem`:  A critical function for ensuring memory safety in WebAssembly.
* `TrapIf...`:  Mechanisms for handling runtime errors (traps) in WebAssembly.
* `TraceFunctionEntry`, `TraceFunctionExit`, `TraceMemoryOperation`: Debugging and profiling related functions.
* SIMD-related functions (`LoadLane`, `StoreLane`, `LoadTransform`, `BuildF64x2Ceil`, etc.):  Indicates support for SIMD instructions.

**2. Identifying Core Functionality Blocks:**

Based on the keywords, we can start grouping related functions and infer their purposes:

* **Runtime Calls:** Functions like `BuildCallToRuntime` and `BuildCallToRuntimeWithContext` are clearly for calling into V8's runtime system from generated WebAssembly code.
* **Global Access:**  `GetGlobalBaseAndOffset`, `GlobalGet`, `GlobalSet` handle reading and writing WebAssembly global variables.
* **Table Access:** `TableGet`, `TableSet` deal with reading and writing elements within WebAssembly tables.
* **Memory Access:**  `CurrentMemoryPages`, `MemBuffer`, `LoadMem`, `StoreMem`, `LoadLane`, `StoreLane`, `LoadTransform` are all about accessing and manipulating WebAssembly memory. The prominent presence of `BoundsCheckMem` highlights the importance of memory safety.
* **Bounds Checking and Trapping:** Functions starting with `TrapIf` and `BoundsCheckMem` form a crucial part of enforcing WebAssembly's memory safety guarantees.
* **Tracing:** The `Trace...` functions are for debugging and performance analysis.
* **SIMD Support:** The numerous functions with names like `LoadLane`, `StoreLane`, and `BuildF64x2Ceil` indicate that this code is involved in generating SIMD (Single Instruction, Multiple Data) instructions for WebAssembly.
* **Asm.js Interop (Less Prominent but Present):**  `BuildAsmjsLoadMem` and `BuildAsmjsStoreMem` suggest some level of interaction with the older asm.js subset of JavaScript.

**3. Inferring the Overall Purpose:**

Putting the pieces together, it becomes clear that `wasm-compiler.cc` is responsible for a significant part of the process of translating WebAssembly bytecode into machine code within V8. It's the part that:

* Takes a WebAssembly module's representation.
* Builds a graph-based intermediate representation of the code (`WasmGraphBuilder`).
* Generates low-level code (using `gasm_`) for various WebAssembly operations, including memory access, global/table access, function calls, and SIMD instructions.
* Incorporates safety checks like bounds checking to prevent memory errors.
* Provides mechanisms for interacting with V8's runtime environment.
* Includes debugging and profiling capabilities.

**4. Addressing Specific Questions from the Prompt:**

Now we can address the specific questions raised in the prompt:

* **Functionality Listing:**  This is a direct result of the analysis in step 3.
* **`.tq` Extension:**  The code clearly doesn't end in `.tq`, so it's not a Torque source file.
* **Relationship to JavaScript:** The presence of `BuildCallToRuntime` and the mention of contexts (`js_context`) indicate interaction with JavaScript. The asm.js functions are another connection. The generated code ultimately runs within the V8 JavaScript engine.
* **JavaScript Example:** The most direct relationship is calling runtime functions. A JavaScript example would be a WebAssembly module that needs to interact with the JavaScript environment, for instance, calling `console.log` (which would likely involve a runtime call).
* **Code Logic Reasoning (Input/Output):**  `BoundsCheckMem` is a good candidate. *Input:* Memory object, access size, index, offset. *Output:* Bounds-checked index (potentially modified) and a `BoundsCheckResult` enum indicating the outcome. We could also consider `GlobalGet` or `GlobalSet` with the global index as input and the global's value as output/input.
* **Common Programming Errors:** Memory access is a prime area. *Example:*  Trying to access memory outside the allocated bounds. The `BoundsCheckMem` function and the `TrapIfFalse` calls are directly related to preventing this. Unaligned memory access is another example, specifically mentioned in the code.
* **Part 5 of 12:**  This tells us it's an intermediate stage of the compilation process. Likely after parsing and validation but before final code emission or optimization passes.

**5. Refinement and Summarization:**

Finally, we refine the description to be concise and accurate, emphasizing the key roles of the `wasm-compiler.cc` file within the broader V8 WebAssembly compilation pipeline. The "graph builder" aspect and the focus on safety and runtime interaction are important points to highlight.

This systematic approach, moving from a high-level overview to detailed examination of specific functions, allows for a comprehensive understanding of the code's purpose and its role within the larger system.
这个 `v8/src/compiler/wasm-compiler.cc` 文件是 V8 引擎中用于编译 WebAssembly 代码的关键组件。它负责将 WebAssembly 的字节码转换成 V8 的内部表示形式，以便后续的优化和代码生成。

**主要功能归纳:**

1. **构建 WebAssembly 的图表示 (Graph Representation):**
   - `WasmGraphBuilder` 类是核心，它遍历 WebAssembly 的指令序列，并将其转换为 V8 的中间表示形式——Sea of Nodes 图。这个图表示了程序的控制流和数据流。
   - 文件中包含了大量的函数，对应于各种 WebAssembly 指令（如 `CurrentMemoryPages`, `GlobalGet`, `GlobalSet`, `TableGet`, `TableSet`, `LoadMem`, `StoreMem` 等），这些函数负责在图中创建相应的节点来表示这些操作。

2. **处理内存访问:**
   - 实现了 WebAssembly 的内存访问操作，包括加载和存储各种数据类型 (`LoadMem`, `StoreMem`)。
   - 包含了内存访问的边界检查 (`BoundsCheckMem`)，确保不会发生越界访问，保证 WebAssembly 代码的安全性。可以根据配置选择不同的边界检查策略。
   - 支持原子操作和对齐检查。

3. **处理全局变量和表:**
   - 实现了对 WebAssembly 全局变量的读取 (`GlobalGet`) 和写入 (`GlobalSet`)。
   - 实现了对 WebAssembly 表的元素读取 (`TableGet`) 和写入 (`TableSet`)，包括对函数引用的处理。

4. **调用 V8 运行时函数:**
   - 提供了将 WebAssembly 代码与 V8 运行时环境连接起来的机制 (`BuildCallToRuntime`, `BuildCallToRuntimeWithContext`)。这允许 WebAssembly 代码调用 V8 的内置函数或 JavaScript 函数。

5. **处理函数调用:**
   - 虽然这段代码没有直接展示函数调用的构建，但 `BuildCallToRuntime` 是处理从 WebAssembly 调用到 V8 运行时的关键部分，也间接关联到 WebAssembly 函数的调用。

6. **SIMD (Single Instruction, Multiple Data) 支持:**
   - 包含了一些处理 SIMD 指令的函数 (`LoadLane`, `StoreLane`, `LoadTransform`, `BuildF64x2Ceil` 等)，表明 V8 的 WebAssembly 编译器支持 SIMD 优化。

7. **Asm.js 兼容性 (部分):**
   - `BuildAsmjsLoadMem` 和 `BuildAsmjsStoreMem` 函数表明该编译器也处理一部分 Asm.js 代码，虽然 WebAssembly 是其主要目标。

8. **调试和追踪:**
   - 提供了用于调试和性能分析的函数 (`TraceFunctionEntry`, `TraceFunctionExit`, `TraceMemoryOperation`)，可以在编译过程中插入代码来追踪函数的执行和内存操作。

**关于 `.tq` 结尾:**

文件中并没有以 `.tq` 结尾，所以它不是 Torque 源代码。Torque 是 V8 中用于定义内置函数的一种领域特定语言。

**与 JavaScript 的关系 (举例说明):**

WebAssembly 最终是在 JavaScript 引擎中执行的，因此 `wasm-compiler.cc` 生成的代码需要能够与 JavaScript 环境交互。一个典型的例子是 WebAssembly 模块调用 JavaScript 函数或者访问 JavaScript 的全局对象。

**JavaScript 例子:**

```javascript
// JavaScript 代码
function jsFunction(arg) {
  console.log("来自 JavaScript:", arg);
  return arg * 2;
}

WebAssembly.instantiateStreaming(fetch('module.wasm'), {
  imports: {
    imported_function: jsFunction // 将 JavaScript 函数导入 WebAssembly 模块
  }
}).then(result => {
  const wasmInstance = result.instance;
  const wasmResult = wasmInstance.exports.exportedFunction(10); // 调用 WebAssembly 导出的函数
  console.log("来自 WebAssembly:", wasmResult);
});
```

在上面的例子中，`wasm-compiler.cc` 负责编译 `module.wasm` 中的 `exportedFunction`。如果 `exportedFunction` 内部调用了导入的 `imported_function`，那么 `wasm-compiler.cc` 需要生成代码，使得 WebAssembly 能够安全地调用 JavaScript 的 `jsFunction`。 `BuildCallToRuntime` 或类似机制会被用于生成这个调用过程的代码。

**代码逻辑推理 (假设输入与输出):**

假设输入是一个 WebAssembly 的 `i32.load` 指令，用于从线性内存的某个偏移量加载一个 32 位整数。

**假设输入:**

- WebAssembly 指令: `i32.load offset=16`
- 内存索引: 0
- 索引节点 (用于计算最终内存地址):  一个表示内存地址偏移量的 `Node*` 变量，假设其值为 4。

**代码逻辑推理 (在 `WasmGraphBuilder::LoadMem` 中):**

1. **计算有效地址:**  `index + offset`，即 4 + 16 = 20。
2. **边界检查 (`BoundsCheckMem`):**  `BoundsCheckMem` 函数会检查计算出的地址 (20) 是否在当前内存的有效范围内。这需要知道当前内存的大小。假设内存大小足够大。
3. **生成加载指令:**  如果边界检查通过，`WasmGraphBuilder::LoadMem` 会使用 `gasm_->Load` (或其他合适的加载指令) 在图中创建一个新的节点，表示从内存地址 20 加载一个 32 位整数。
4. **输出:**  返回一个表示加载结果的 `Node*` 变量。

**假设输出:**

- 一个新的 `Node*` 变量，其操作符是表示 32 位整数加载的某种类型 (例如，`kLoad`)，并且其输入包括内存起始地址节点、计算出的地址节点等。

**用户常见的编程错误 (举例说明):**

1. **内存越界访问:**
   - **错误示例 (WebAssembly 代码层面):** 尝试加载或存储超出已分配内存范围的地址。
   - **`wasm-compiler.cc` 的作用:** `BoundsCheckMem` 函数会检测到这种潜在的错误，并在运行时触发一个 WebAssembly 陷阱 (trap)，防止程序崩溃或造成安全问题。

2. **非对齐内存访问 (在需要对齐的架构上):**
   - **错误示例 (WebAssembly 代码层面):** 尝试从一个不是数据类型大小倍数的地址加载或存储数据，例如在一个 4 字节对齐的架构上从地址 1 加载一个 4 字节的整数。
   - **`wasm-compiler.cc` 的作用:**  `GetSafeLoadOperator` 和 `GetSafeStoreOperator` 以及 `BoundsCheckMem` 中的对齐检查逻辑会处理这种情况。如果架构不支持非对齐访问，可能会生成一个陷阱或者使用更慢的非对齐访问指令。

**功能归纳 (作为第 5 部分):**

作为编译过程的第 5 部分，`v8/src/compiler/wasm-compiler.cc` 的主要功能是 **将 WebAssembly 的抽象语法树或中间表示转换为 V8 内部的图表示 (Sea of Nodes)，并为各种 WebAssembly 操作生成相应的低级操作节点。**  在这个阶段，会进行初步的类型推断、安全检查（如边界检查），并为后续的优化和代码生成奠定基础。  它处于解析和验证之后，但在更高级的优化和机器码生成之前。这个阶段的关键是将高级的 WebAssembly 语义转换为更接近机器指令的、可优化的图结构。

### 提示词
```
这是目录为v8/src/compiler/wasm-compiler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/wasm-compiler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
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
    if (origin == wasm::kCalledFromJ
```