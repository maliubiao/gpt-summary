Response:
The user wants a summary of the functionality of the provided C++ code snippet, which is a part of the V8 JavaScript engine's WebAssembly implementation.

Here's a breakdown of the thought process to generate the response:

1. **Identify the Core Functionality:** The code snippet is within the `v8/src/wasm/turboshaft-graph-interface.cc` file. The name suggests it's related to the interface between the Turboshaft compiler (a new V8 compiler) and the WebAssembly execution. Keywords like `FullDecoder`, `Value`, `OpIndex`, `TSBlock`, and specific Wasm opcodes (e.g., `I32Const`, `LoadMem`, `StoreMem`) strongly indicate this is responsible for translating WebAssembly bytecode into Turboshaft's intermediate representation (IR).

2. **Analyze Key Methods:**  Scan through the provided methods and group them by their apparent purpose.

    * **Control Flow:** Methods like `StartBlock`, `StartLoop`, `StartIf`, `StartIfElse`, `EndBlock`, `Break`, `Continue`, `BrTable`, `FallThruTo`, `PopControl`, and `DoReturn` clearly manage the control flow structures in WebAssembly.
    * **Stack Manipulation:** Although not explicit stack manipulation like "push" and "pop", the `Value` objects and the interaction with `FullDecoder` suggest the code manages values as they are processed, conceptually similar to a stack.
    * **Operations/Instructions:**  Methods with names matching Wasm opcodes (e.g., `I32Const`, `I64Const`, `F32Const`, `F64Const`, `LocalGet`, `LocalSet`, `GlobalGet`, `GlobalSet`, `LoadMem`, `StoreMem`, `UnOp`, `BinOp`, `Select`) handle the translation of individual WebAssembly instructions.
    * **Memory Access:**  Methods like `LoadMem`, `StoreMem`, `LoadTransform`, `LoadLane`, `StoreLane`, `CurrentMemoryPages`, and `MemoryGrow` deal with accessing and modifying the WebAssembly linear memory.
    * **Function Calls:** `CallDirect`, `CallIndirect`, `CallRef`, and `ReturnCall` handle different types of function calls in WebAssembly.
    * **Traps/Assertions:** `Trap`, `AssertNullTypecheck`, and `AssertNotNullTypecheck` handle runtime error conditions.
    * **SIMD:** Methods like `S128Const`, `LoadTransform`, `LoadLane`, and `StoreLane` (with `Simd128` types) indicate support for WebAssembly's SIMD instructions.
    * **Miscellaneous:**  `RefNull`, `RefFunc`, `RefAsNonNull`, `Drop`, `TraceInstruction`, `NopForTestingUnsupportedInLiftoff`.

3. **Summarize High-Level Functionality:** Based on the method analysis, formulate a concise summary. The core function is translating Wasm bytecode to Turboshaft IR. Highlight the handling of control flow, stack-like value management, operation translation, memory access, function calls, and error handling.

4. **Address Specific Questions:**  Go through the user's specific requests:

    * **.tq extension:** Explain that `.tq` indicates Torque code, a TypeScript-like language for V8 internals. This file is `.cc`, so it's C++.
    * **Relationship to JavaScript:** Explain the indirect relationship. This code is part of the *implementation* of WebAssembly within V8, which allows JavaScript to run WebAssembly code. Provide a simple JavaScript example that would trigger the execution of this underlying C++ code.
    * **Code Logic Inference:** Select a straightforward method, like `I32Const`, and provide a simple example of input (the `value`) and output (the `OpIndex` representing the constant in the Turboshaft graph).
    * **Common Programming Errors:** Focus on memory access errors, as they are common in WebAssembly. Provide an example of out-of-bounds access that this code would help to handle (through bounds checks).

5. **Address "Part 2 of 12":**  Emphasize that this snippet focuses on the *instruction processing* part of the compilation process. It doesn't handle the entire compilation pipeline (like parsing or optimization).

6. **Review and Refine:** Read through the generated response to ensure clarity, accuracy, and completeness. Check for any jargon that might need further explanation. Ensure the JavaScript example is simple and illustrative.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Maybe focus on specific Turboshaft concepts. **Correction:** The user asked for general functionality. Focus on what the *code does* in relation to Wasm, not just the internal Turboshaft mechanisms.
* **Initial thought:**  Provide very detailed explanations of each method. **Correction:** The user asked for a summary. Group related methods and provide a higher-level overview.
* **Initial thought:**  Give a very technical JavaScript example. **Correction:**  Keep the JavaScript example simple and focused on the user's perspective (running Wasm in the browser).
* **Consider edge cases:** While explaining potential errors, focus on a common and understandable scenario like memory access. Avoid overly complex or internal V8-specific error conditions.
这是 `v8/src/wasm/turboshaft-graph-interface.cc` 文件的第二部分，它定义了 `TurboshaftGraphBuildingInterface` 类中的一部分方法。 这个类是 WebAssembly 代码到 Turboshaft 图形表示的转换接口的核心组件。

**归纳一下这部分代码的功能：**

这部分代码主要负责处理 WebAssembly 的 **控制流指令** 和部分 **内存访问指令** 的转换，将其转化为 Turboshaft 编译器可以理解的图形节点。 具体来说，它实现了以下功能：

1. **处理控制流指令:**
   - `StartBlock`, `StartLoop`, `StartIf`, `StartIfElse`:  创建新的控制流块，并处理块的入口条件和参数。
   - `EndBlock`:  结束当前控制流块，并处理与外部块的连接。
   - `Break`, `Continue`:  处理 `break` 和 `continue` 指令，跳转到相应的循环或块的出口。
   - `BrTable`: 处理 `br_table` 指令，根据索引跳转到不同的目标块。
   - `FallThruTo`:  处理控制流的顺序执行，从一个块跳转到下一个块。
   - `PopControl`:  在控制流结构结束时进行清理和连接操作，例如处理 `if` 语句的合并块和循环的后置块。
   - `DoReturn`:  处理 `return` 指令，将返回值传递给调用者。

2. **处理部分内存访问指令:**
   - `LoadMem`: 处理从内存中加载值的指令。它会进行边界检查，并生成相应的 Turboshaft `Load` 操作。
   - `StoreMem`: 处理将值存储到内存中的指令。它也会进行边界检查，并生成相应的 Turboshaft `Store` 操作。
   - `LoadTransform`, `LoadLane`, `StoreLane`: 处理 SIMD 指令相关的内存加载和存储操作。
   - `CurrentMemoryPages`:  获取当前内存大小（以页为单位）。
   - `MemoryGrow`:  处理内存增长指令。

**与 JavaScript 的关系：**

`v8/src/wasm/turboshaft-graph-interface.cc` 的功能是 V8 执行 WebAssembly 代码的关键部分。当 JavaScript 代码执行 WebAssembly 模块时，V8 会将 WebAssembly 的字节码传递给 Turboshaft 编译器。 `TurboshaftGraphBuildingInterface` 类（包括这部分代码）负责将这些字节码转换为 Turboshaft 内部的图形表示，以便后续的优化和代码生成。

**JavaScript 示例：**

```javascript
const wasmCode = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // Magic number and version
  0x01, 0x07, 0x01, 0x60, 0x00, 0x01, 0x7f,       // Type section: function type (no params, one i32 result)
  0x03, 0x02, 0x01, 0x00,                         // Function section: one function, type index 0
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x41, 0x05, 0x0f, 0x0b // Code section: function 0 implementation (local.get 0; i32.const 5; return)
]);

WebAssembly.instantiate(wasmCode).then(module => {
  console.log(module.instance.exports.f()); // 执行 WebAssembly 函数
});
```

当上面的 JavaScript 代码执行 `WebAssembly.instantiate` 并调用导出的函数 `f` 时，V8 内部会将 `wasmCode` 中的字节码（包括 `local.get`, `i32.const`, `return` 等指令）传递给 Turboshaft 编译器。 这部分 `turboshaft-graph-interface.cc` 中的代码会被调用来处理这些指令，例如：

- `I32Const` 会被调用来处理 `0x41 0x05` ( `i32.const 5` )，生成一个表示常量 5 的 Turboshaft 节点。
- `LocalGet` 会被调用来处理 `0x20 0x00` ( `local.get 0` )，获取局部变量的值。
- `DoReturn` 会被调用来处理 `0x0f` ( `return` )，生成返回指令。

**代码逻辑推理：**

**假设输入：**  正在处理一个 `br_table` 指令，其立即数为 `imm.table_count = 3`，且有以下分支目标： `target1`, `target2`, `target3`，默认目标为 `default_target`。  `key.op` 是一个表示跳转索引的 `OpIndex`。

**输出：**  Turboshaft 图形中会生成以下逻辑：

1. **边界检查：** 会生成代码来检查 `key.op` 的值是否在 `0` 到 `imm.table_count - 1` 之间。
2. **条件分支：**  如果 `key.op` 的值为 `0`，则跳转到 `target1`。如果为 `1`，则跳转到 `target2`。如果为 `2`，则跳转到 `target3`。
3. **默认分支：** 如果 `key.op` 的值超出范围，则跳转到 `default_target`。

**用户常见的编程错误：**

1. **内存越界访问:**  在 WebAssembly 中尝试访问超出分配的内存范围的地址。  `LoadMem` 和 `StoreMem` 中的边界检查机制可以帮助捕获这类错误，并在运行时抛出异常。

   **JavaScript 示例 (导致内存越界)：**

   ```javascript
   const wasmCode = new Uint8Array([
     // ... (WASM 代码定义了一个内存，并尝试访问超出范围的地址)
     0x41, 0x00,          // i32.const 0  (访问地址 0)
     0x28, 0x02, 0x00,    // i32.load offset=0  (假设内存大小不足以访问)
     0x0f                 // return
     // ...
   ]);

   WebAssembly.instantiate(wasmCode).catch(error => {
     console.error("WASM 错误:", error); // 可能会捕获到内存访问错误
   });
   ```

2. **类型错误:**  尝试将一种类型的值存储到期望另一种类型的内存位置。虽然 Turboshaft 主要处理低级表示，但 WebAssembly 的类型系统会在早期进行验证，防止大多数此类错误发生。

**总结一下它的功能 (基于整个提供的代码片段):**

这段 `v8/src/wasm/turboshaft-graph-interface.cc` 的代码是 Turboshaft 编译器处理 WebAssembly 代码的核心部分，专注于将 **控制流指令** (如分支、循环、返回) 和部分 **内存访问指令** (加载、存储) 转换为 Turboshaft 编译器内部的图形表示。 它负责确保代码的控制流程正确，并处理与内存的交互，同时进行必要的边界检查，以防止常见的 WebAssembly 编程错误。  它在 V8 执行 WebAssembly 代码的过程中扮演着至关重要的角色，连接了 WebAssembly 字节码和 Turboshaft 的优化和代码生成阶段。

### 提示词
```
这是目录为v8/src/wasm/turboshaft-graph-interface.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/wasm/turboshaft-graph-interface.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共12部分，请归纳一下它的功能
```

### 源代码
```cpp
upper =
              __ Int32LessThan(key.op, __ Word32Constant(imm.table_count));
          OpIndex cond = __ Word32BitwiseAnd(lower, upper);
          insert_cond_branch(cond, table_analysis.primary_target());
        }
        // Always fallthrough and branch to the default case.
        BrOrRet(decoder, table_analysis.default_target());
        return;
      }
    }
    compiler::turboshaft::SwitchOp::Case* cases =
        __ output_graph().graph_zone()
            -> AllocateArray<compiler::turboshaft::SwitchOp::Case>(
                             imm.table_count);
    BranchTableIterator<ValidationTag> new_block_iterator(decoder, imm);
    SmallZoneVector<TSBlock*, 16> intermediate_blocks(decoder->zone_);
    TSBlock* default_case = nullptr;
    while (new_block_iterator.has_next()) {
      TSBlock* intermediate = __ NewBlock();
      intermediate_blocks.emplace_back(intermediate);
      uint32_t i = new_block_iterator.cur_index();
      if (i == imm.table_count) {
        default_case = intermediate;
      } else {
        cases[i] = {static_cast<int>(i), intermediate, BranchHint::kNone};
      }
      new_block_iterator.next();
    }
    DCHECK_NOT_NULL(default_case);
    __ Switch(key.op, base::VectorOf(cases, imm.table_count), default_case);

    int i = 0;
    BranchTableIterator<ValidationTag> branch_iterator(decoder, imm);
    while (branch_iterator.has_next()) {
      TSBlock* intermediate = intermediate_blocks[i];
      i++;
      __ Bind(intermediate);
      BrOrRet(decoder, branch_iterator.next());
    }
  }

  void FallThruTo(FullDecoder* decoder, Control* block) {
    // TODO(14108): Why is {block->reachable()} not reliable here? Maybe it is
    // not in other spots as well.
    if (__ current_block() != nullptr) {
      SetupControlFlowEdge(decoder, block->merge_block);
      __ Goto(block->merge_block);
    }
  }

  void PopControl(FullDecoder* decoder, Control* block) {
    switch (block->kind) {
      case kControlIf:
        if (block->reachable()) {
          SetupControlFlowEdge(decoder, block->merge_block);
          __ Goto(block->merge_block);
        }
        BindBlockAndGeneratePhis(decoder, block->false_or_loop_or_catch_block,
                                 nullptr);
        // Exceptionally for one-armed if, we cannot take the values from the
        // stack; we have to pass the stack values at the beginning of the
        // if-block.
        SetupControlFlowEdge(decoder, block->merge_block, 0, OpIndex::Invalid(),
                             &block->start_merge);
        __ Goto(block->merge_block);
        BindBlockAndGeneratePhis(decoder, block->merge_block,
                                 block->br_merge());
        break;
      case kControlIfElse:
      case kControlBlock:
      case kControlTry:
      case kControlTryCatch:
      case kControlTryCatchAll:
        // {block->reachable()} is not reliable here for exceptions, because
        // the decoder sets the reachability to the upper block's reachability
        // before calling this interface function.
        if (__ current_block() != nullptr) {
          SetupControlFlowEdge(decoder, block->merge_block);
          __ Goto(block->merge_block);
        }
        BindBlockAndGeneratePhis(decoder, block->merge_block,
                                 block->br_merge());
        break;
      case kControlTryTable:
        DCHECK_EQ(__ current_block(), nullptr);
        BindBlockAndGeneratePhis(decoder, block->merge_block,
                                 block->br_merge());
        break;
      case kControlLoop: {
        TSBlock* post_loop = NewBlockWithPhis(decoder, nullptr);
        if (block->reachable()) {
          SetupControlFlowEdge(decoder, post_loop);
          __ Goto(post_loop);
        }
        if (!block->false_or_loop_or_catch_block->IsBound()) {
          // The loop is unreachable. In this case, no operations have been
          // emitted for it. Do nothing.
        } else if (block->merge_block->PredecessorCount() == 0) {
          // Turns out, the loop has no backedges, i.e. it is not quite a loop
          // at all. Replace it with a merge, and its PendingPhis with one-input
          // phis.
          block->false_or_loop_or_catch_block->SetKind(
              compiler::turboshaft::Block::Kind::kMerge);
          for (auto& op : __ output_graph().operations(
                   *block->false_or_loop_or_catch_block)) {
            PendingLoopPhiOp* pending_phi = op.TryCast<PendingLoopPhiOp>();
            if (!pending_phi) break;
            OpIndex replaced = __ output_graph().Index(op);
            __ output_graph().Replace<compiler::turboshaft::PhiOp>(
                replaced, base::VectorOf({pending_phi -> first()}),
                pending_phi->rep);
          }
        } else {
          // We abuse the start merge of the loop, which is not used otherwise
          // anymore, to store backedge inputs for the pending phi stack values
          // of the loop.
          BindBlockAndGeneratePhis(decoder, block->merge_block,
                                   block->br_merge());
          __ Goto(block->false_or_loop_or_catch_block);
          auto operations = __ output_graph().operations(
              *block -> false_or_loop_or_catch_block);
          auto to = operations.begin();
          // The VariableReducer can introduce loop phis as well which are at
          // the beginning of the block. We need to skip them.
          while (to != operations.end() &&
                 to->Is<compiler::turboshaft::PhiOp>()) {
            ++to;
          }
          for (auto it = block->assigned->begin(); it != block->assigned->end();
               ++it, ++to) {
            // The last bit represents the instance cache.
            if (*it == static_cast<int>(ssa_env_.size())) break;
            PendingLoopPhiOp& pending_phi = to->Cast<PendingLoopPhiOp>();
            OpIndex replaced = __ output_graph().Index(*to);
            __ output_graph().Replace<compiler::turboshaft::PhiOp>(
                replaced, base::VectorOf({pending_phi.first(), ssa_env_[*it]}),
                pending_phi.rep);
          }
          for (uint32_t i = 0; i < block->br_merge()->arity; ++i, ++to) {
            PendingLoopPhiOp& pending_phi = to->Cast<PendingLoopPhiOp>();
            OpIndex replaced = __ output_graph().Index(*to);
            __ output_graph().Replace<compiler::turboshaft::PhiOp>(
                replaced,
                base::VectorOf(
                    {pending_phi.first(), (*block->br_merge())[i].op}),
                pending_phi.rep);
          }
        }
        BindBlockAndGeneratePhis(decoder, post_loop, nullptr);
        break;
      }
    }
  }

  void DoReturn(FullDecoder* decoder, uint32_t drop_values) {
    size_t return_count = decoder->sig_->return_count();
    SmallZoneVector<OpIndex, 16> return_values(return_count, decoder->zone_);
    Value* stack_base = return_count == 0
                            ? nullptr
                            : decoder->stack_value(static_cast<uint32_t>(
                                  return_count + drop_values));
    for (size_t i = 0; i < return_count; i++) {
      return_values[i] = stack_base[i].op;
    }
    if (v8_flags.trace_wasm) {
      V<WordPtr> info = __ IntPtrConstant(0);
      if (return_count == 1) {
        wasm::ValueType return_type = decoder->sig_->GetReturn(0);
        int size = return_type.value_kind_size();
        // TODO(14108): This won't fit everything.
        info = __ StackSlot(size, size);
        // TODO(14108): Write barrier might be needed.
        __ Store(
            info, return_values[0], StoreOp::Kind::RawAligned(),
            MemoryRepresentation::FromMachineType(return_type.machine_type()),
            compiler::kNoWriteBarrier);
      }
      CallRuntime(decoder->zone(), Runtime::kWasmTraceExit, {info},
                  __ NoContextConstant());
    }
    if (mode_ == kRegular || mode_ == kInlinedTailCall) {
      __ Return(__ Word32Constant(0), base::VectorOf(return_values),
                v8_flags.experimental_wasm_growable_stacks);
    } else {
      // Do not add return values if we are in unreachable code.
      if (__ generating_unreachable_operations()) return;
      for (size_t i = 0; i < return_count; i++) {
        return_phis_->AddInputForPhi(i, return_values[i]);
      }
      __ Goto(return_block_);
    }
  }

  void UnOp(FullDecoder* decoder, WasmOpcode opcode, const Value& value,
            Value* result) {
    result->op = UnOpImpl(opcode, value.op, value.type);
  }

  void BinOp(FullDecoder* decoder, WasmOpcode opcode, const Value& lhs,
             const Value& rhs, Value* result) {
    result->op = BinOpImpl(opcode, lhs.op, rhs.op);
  }

  void TraceInstruction(FullDecoder* decoder, uint32_t markid) {
    // TODO(14108): Implement.
  }

  void I32Const(FullDecoder* decoder, Value* result, int32_t value) {
    result->op = __ Word32Constant(value);
  }

  void I64Const(FullDecoder* decoder, Value* result, int64_t value) {
    result->op = __ Word64Constant(value);
  }

  void F32Const(FullDecoder* decoder, Value* result, float value) {
    result->op = __ Float32Constant(value);
  }

  void F64Const(FullDecoder* decoder, Value* result, double value) {
    result->op = __ Float64Constant(value);
  }

  void S128Const(FullDecoder* decoder, const Simd128Immediate& imm,
                 Value* result) {
    result->op = __ Simd128Constant(imm.value);
  }

  void RefNull(FullDecoder* decoder, ValueType type, Value* result) {
    result->op = __ Null(type);
  }

  void RefFunc(FullDecoder* decoder, uint32_t function_index, Value* result) {
    ModuleTypeIndex sig_index =
        decoder->module_->functions[function_index].sig_index;
    bool shared = decoder->module_->type(sig_index).is_shared;
    result->op = __ WasmRefFunc(trusted_instance_data(shared), function_index);
  }

  void RefAsNonNull(FullDecoder* decoder, const Value& arg, Value* result) {
    result->op =
        __ AssertNotNull(arg.op, arg.type, TrapId::kTrapNullDereference);
  }

  void Drop(FullDecoder* decoder) {}

  void LocalGet(FullDecoder* decoder, Value* result,
                const IndexImmediate& imm) {
    result->op = ssa_env_[imm.index];
  }

  void LocalSet(FullDecoder* decoder, const Value& value,
                const IndexImmediate& imm) {
    ssa_env_[imm.index] = value.op;
  }

  void LocalTee(FullDecoder* decoder, const Value& value, Value* result,
                const IndexImmediate& imm) {
    ssa_env_[imm.index] = result->op = value.op;
  }

  void GlobalGet(FullDecoder* decoder, Value* result,
                 const GlobalIndexImmediate& imm) {
    bool shared = decoder->module_->globals[imm.index].shared;
    result->op = __ GlobalGet(trusted_instance_data(shared), imm.global);
  }

  void GlobalSet(FullDecoder* decoder, const Value& value,
                 const GlobalIndexImmediate& imm) {
    bool shared = decoder->module_->globals[imm.index].shared;
    __ GlobalSet(trusted_instance_data(shared), value.op, imm.global);
  }

  void Trap(FullDecoder* decoder, TrapReason reason) {
    __ TrapIfNot(__ Word32Constant(0), GetTrapIdForTrap(reason));
    __ Unreachable();
  }

  void AssertNullTypecheck(FullDecoder* decoder, const Value& obj,
                           Value* result) {
    __ TrapIfNot(__ IsNull(obj.op, obj.type), TrapId::kTrapIllegalCast);
    Forward(decoder, obj, result);
  }

  void AssertNotNullTypecheck(FullDecoder* decoder, const Value& obj,
                              Value* result) {
    __ AssertNotNull(obj.op, obj.type, TrapId::kTrapIllegalCast);
    Forward(decoder, obj, result);
  }

  void NopForTestingUnsupportedInLiftoff(FullDecoder* decoder) {
    // This is just for testing bailouts in Liftoff, here it's just a nop.
  }

  void Select(FullDecoder* decoder, const Value& cond, const Value& fval,
              const Value& tval, Value* result) {
    using Implementation = compiler::turboshaft::SelectOp::Implementation;
    bool use_select = false;
    switch (tval.type.kind()) {
      case kI32:
        if (SupportedOperations::word32_select()) use_select = true;
        break;
      case kI64:
        if (SupportedOperations::word64_select()) use_select = true;
        break;
      case kF32:
        if (SupportedOperations::float32_select()) use_select = true;
        break;
      case kF64:
        if (SupportedOperations::float64_select()) use_select = true;
        break;
      case kRef:
      case kRefNull:
      case kS128:
        break;
      case kI8:
      case kI16:
      case kF16:
      case kRtt:
      case kVoid:
      case kTop:
      case kBottom:
        UNREACHABLE();
    }
    result->op = __ Select(
        cond.op, tval.op, fval.op, RepresentationFor(tval.type),
        BranchHint::kNone,
        use_select ? Implementation::kCMove : Implementation::kBranch);
  }

  OpIndex BuildChangeEndiannessStore(OpIndex node,
                                     MachineRepresentation mem_rep,
                                     wasm::ValueType wasmtype) {
    OpIndex result;
    OpIndex value = node;
    int value_size_in_bytes = wasmtype.value_kind_size();
    int value_size_in_bits = 8 * value_size_in_bytes;
    bool is_float = false;

    switch (wasmtype.kind()) {
      case wasm::kF64:
        value = __ BitcastFloat64ToWord64(node);
        is_float = true;
        [[fallthrough]];
      case wasm::kI64:
        result = __ Word64Constant(static_cast<uint64_t>(0));
        break;
      case wasm::kF32:
        value = __ BitcastFloat32ToWord32(node);
        is_float = true;
        [[fallthrough]];
      case wasm::kI32:
        result = __ Word32Constant(0);
        break;
      case wasm::kS128:
        DCHECK(ReverseBytesSupported(value_size_in_bytes));
        break;
      default:
        UNREACHABLE();
    }

    if (mem_rep == MachineRepresentation::kWord8) {
      // No need to change endianness for byte size, return original node
      return node;
    }
    if (wasmtype == wasm::kWasmI64 &&
        mem_rep < MachineRepresentation::kWord64) {
      // In case we store lower part of WasmI64 expression, we can truncate
      // upper 32bits.
      value_size_in_bytes = wasm::kWasmI32.value_kind_size();
      value_size_in_bits = 8 * value_size_in_bytes;
      if (mem_rep == MachineRepresentation::kWord16) {
        value = __ Word32ShiftLeft(value, 16);
      }
    } else if (wasmtype == wasm::kWasmI32 &&
               mem_rep == MachineRepresentation::kWord16) {
      value = __ Word32ShiftLeft(value, 16);
    }

    int i;
    uint32_t shift_count;

    if (ReverseBytesSupported(value_size_in_bytes)) {
      switch (value_size_in_bytes) {
        case 4:
          result = __ Word32ReverseBytes(V<Word32>::Cast(value));
          break;
        case 8:
          result = __ Word64ReverseBytes(V<Word64>::Cast(value));
          break;
        case 16:
          result = __ Simd128ReverseBytes(
              V<compiler::turboshaft::Simd128>::Cast(value));
          break;
        default:
          UNREACHABLE();
      }
    } else {
      for (i = 0, shift_count = value_size_in_bits - 8;
           i < value_size_in_bits / 2; i += 8, shift_count -= 16) {
        OpIndex shift_lower;
        OpIndex shift_higher;
        OpIndex lower_byte;
        OpIndex higher_byte;

        DCHECK_LT(0, shift_count);
        DCHECK_EQ(0, (shift_count + 8) % 16);

        if (value_size_in_bits > 32) {
          shift_lower = __ Word64ShiftLeft(value, shift_count);
          shift_higher = __ Word64ShiftRightLogical(value, shift_count);
          lower_byte = __ Word64BitwiseAnd(shift_lower,
                                           static_cast<uint64_t>(0xFF)
                                               << (value_size_in_bits - 8 - i));
          higher_byte = __ Word64BitwiseAnd(shift_higher,
                                            static_cast<uint64_t>(0xFF) << i);
          result = __ Word64BitwiseOr(result, lower_byte);
          result = __ Word64BitwiseOr(result, higher_byte);
        } else {
          shift_lower = __ Word32ShiftLeft(value, shift_count);
          shift_higher = __ Word32ShiftRightLogical(value, shift_count);
          lower_byte = __ Word32BitwiseAnd(shift_lower,
                                           static_cast<uint32_t>(0xFF)
                                               << (value_size_in_bits - 8 - i));
          higher_byte = __ Word32BitwiseAnd(shift_higher,
                                            static_cast<uint32_t>(0xFF) << i);
          result = __ Word32BitwiseOr(result, lower_byte);
          result = __ Word32BitwiseOr(result, higher_byte);
        }
      }
    }

    if (is_float) {
      switch (wasmtype.kind()) {
        case wasm::kF64:
          result = __ BitcastWord64ToFloat64(result);
          break;
        case wasm::kF32:
          result = __ BitcastWord32ToFloat32(result);
          break;
        default:
          UNREACHABLE();
      }
    }

    return result;
  }

  OpIndex BuildChangeEndiannessLoad(OpIndex node, MachineType memtype,
                                    wasm::ValueType wasmtype) {
    OpIndex result;
    OpIndex value = node;
    int value_size_in_bytes = ElementSizeInBytes(memtype.representation());
    int value_size_in_bits = 8 * value_size_in_bytes;
    bool is_float = false;

    switch (memtype.representation()) {
      case MachineRepresentation::kFloat64:
        value = __ BitcastFloat64ToWord64(node);
        is_float = true;
        [[fallthrough]];
      case MachineRepresentation::kWord64:
        result = __ Word64Constant(static_cast<uint64_t>(0));
        break;
      case MachineRepresentation::kFloat32:
        value = __ BitcastFloat32ToWord32(node);
        is_float = true;
        [[fallthrough]];
      case MachineRepresentation::kWord32:
      case MachineRepresentation::kWord16:
        result = __ Word32Constant(0);
        break;
      case MachineRepresentation::kWord8:
        // No need to change endianness for byte size, return original node.
        return node;
      case MachineRepresentation::kSimd128:
        DCHECK(ReverseBytesSupported(value_size_in_bytes));
        break;
      default:
        UNREACHABLE();
    }

    int i;
    uint32_t shift_count;

    if (ReverseBytesSupported(value_size_in_bytes < 4 ? 4
                                                      : value_size_in_bytes)) {
      switch (value_size_in_bytes) {
        case 2:
          result = __ Word32ReverseBytes(__ Word32ShiftLeft(value, 16));
          break;
        case 4:
          result = __ Word32ReverseBytes(value);
          break;
        case 8:
          result = __ Word64ReverseBytes(value);
          break;
        case 16:
          result = __ Simd128ReverseBytes(value);
          break;
        default:
          UNREACHABLE();
      }
    } else {
      for (i = 0, shift_count = value_size_in_bits - 8;
           i < value_size_in_bits / 2; i += 8, shift_count -= 16) {
        OpIndex shift_lower;
        OpIndex shift_higher;
        OpIndex lower_byte;
        OpIndex higher_byte;

        DCHECK_LT(0, shift_count);
        DCHECK_EQ(0, (shift_count + 8) % 16);

        if (value_size_in_bits > 32) {
          shift_lower = __ Word64ShiftLeft(value, shift_count);
          shift_higher = __ Word64ShiftRightLogical(value, shift_count);
          lower_byte = __ Word64BitwiseAnd(shift_lower,
                                           static_cast<uint64_t>(0xFF)
                                               << (value_size_in_bits - 8 - i));
          higher_byte = __ Word64BitwiseAnd(shift_higher,
                                            static_cast<uint64_t>(0xFF) << i);
          result = __ Word64BitwiseOr(result, lower_byte);
          result = __ Word64BitwiseOr(result, higher_byte);
        } else {
          shift_lower = __ Word32ShiftLeft(value, shift_count);
          shift_higher = __ Word32ShiftRightLogical(value, shift_count);
          lower_byte = __ Word32BitwiseAnd(shift_lower,
                                           static_cast<uint32_t>(0xFF)
                                               << (value_size_in_bits - 8 - i));
          higher_byte = __ Word32BitwiseAnd(shift_higher,
                                            static_cast<uint32_t>(0xFF) << i);
          result = __ Word32BitwiseOr(result, lower_byte);
          result = __ Word32BitwiseOr(result, higher_byte);
        }
      }
    }

    if (is_float) {
      switch (memtype.representation()) {
        case MachineRepresentation::kFloat64:
          result = __ BitcastWord64ToFloat64(result);
          break;
        case MachineRepresentation::kFloat32:
          result = __ BitcastWord32ToFloat32(result);
          break;
        default:
          UNREACHABLE();
      }
    }

    // We need to sign or zero extend the value.
    // Values with size >= 32-bits may need to be sign/zero extended after
    // calling this function.
    if (value_size_in_bits < 32) {
      DCHECK(!is_float);
      int shift_bit_count = 32 - value_size_in_bits;
      result = __ Word32ShiftLeft(result, shift_bit_count);
      if (memtype.IsSigned()) {
        result =
            __ Word32ShiftRightArithmeticShiftOutZeros(result, shift_bit_count);
      } else {
        result = __ Word32ShiftRightLogical(result, shift_bit_count);
      }
    }

    return result;
  }

  void LoadMem(FullDecoder* decoder, LoadType type,
               const MemoryAccessImmediate& imm, const Value& index,
               Value* result) {
    bool needs_f16_to_f32_conv = false;
    if (type.value() == LoadType::kF32LoadF16 &&
        !SupportedOperations::float16()) {
      needs_f16_to_f32_conv = true;
      type = LoadType::kI32Load16U;
    }
    MemoryRepresentation repr =
        MemoryRepresentation::FromMachineType(type.mem_type());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       compiler::EnforceBoundsCheck::kCanOmitBoundsCheck,
                       compiler::AlignmentCheck::kNo);

    V<WordPtr> mem_start = MemStart(imm.memory->index);

    LoadOp::Kind load_kind = GetMemoryAccessKind(repr, strategy);

    const bool offset_in_int_range =
        imm.offset <= std::numeric_limits<int32_t>::max();
    OpIndex base =
        offset_in_int_range ? mem_start : __ WordPtrAdd(mem_start, imm.offset);
    int32_t offset = offset_in_int_range ? static_cast<int32_t>(imm.offset) : 0;
    OpIndex load = __ Load(base, final_index, load_kind, repr, offset);

#if V8_TARGET_BIG_ENDIAN
    load = BuildChangeEndiannessLoad(load, type.mem_type(), type.value_type());
#endif

    if (type.value_type() == kWasmI64 && repr.SizeInBytes() < 8) {
      load = repr.IsSigned() ? __ ChangeInt32ToInt64(load)
                             : __ ChangeUint32ToUint64(load);
    }

    if (needs_f16_to_f32_conv) {
      load = CallCStackSlotToStackSlot(
          load, ExternalReference::wasm_float16_to_float32(),
          MemoryRepresentation::Uint16(), MemoryRepresentation::Float32());
    }

    if (v8_flags.trace_wasm_memory) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(decoder, false, repr, final_index, imm.offset);
    }

    result->op = load;
  }

  void LoadTransform(FullDecoder* decoder, LoadType type,
                     LoadTransformationKind transform,
                     const MemoryAccessImmediate& imm, const Value& index,
                     Value* result) {
    MemoryRepresentation repr =
        transform == LoadTransformationKind::kExtend
            ? MemoryRepresentation::Int64()
            : MemoryRepresentation::FromMachineType(type.mem_type());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       compiler::EnforceBoundsCheck::kCanOmitBoundsCheck,
                       compiler::AlignmentCheck::kNo);

    compiler::turboshaft::Simd128LoadTransformOp::LoadKind load_kind =
        GetMemoryAccessKind(repr, strategy);

    using TransformKind =
        compiler::turboshaft::Simd128LoadTransformOp::TransformKind;

    TransformKind transform_kind;

    if (transform == LoadTransformationKind::kExtend) {
      if (type.mem_type() == MachineType::Int8()) {
        transform_kind = TransformKind::k8x8S;
      } else if (type.mem_type() == MachineType::Uint8()) {
        transform_kind = TransformKind::k8x8U;
      } else if (type.mem_type() == MachineType::Int16()) {
        transform_kind = TransformKind::k16x4S;
      } else if (type.mem_type() == MachineType::Uint16()) {
        transform_kind = TransformKind::k16x4U;
      } else if (type.mem_type() == MachineType::Int32()) {
        transform_kind = TransformKind::k32x2S;
      } else if (type.mem_type() == MachineType::Uint32()) {
        transform_kind = TransformKind::k32x2U;
      } else {
        UNREACHABLE();
      }
    } else if (transform == LoadTransformationKind::kSplat) {
      if (type.mem_type() == MachineType::Int8()) {
        transform_kind = TransformKind::k8Splat;
      } else if (type.mem_type() == MachineType::Int16()) {
        transform_kind = TransformKind::k16Splat;
      } else if (type.mem_type() == MachineType::Int32()) {
        transform_kind = TransformKind::k32Splat;
      } else if (type.mem_type() == MachineType::Int64()) {
        transform_kind = TransformKind::k64Splat;
      } else {
        UNREACHABLE();
      }
    } else {
      if (type.mem_type() == MachineType::Int32()) {
        transform_kind = TransformKind::k32Zero;
      } else if (type.mem_type() == MachineType::Int64()) {
        transform_kind = TransformKind::k64Zero;
      } else {
        UNREACHABLE();
      }
    }

    V<compiler::turboshaft::Simd128> load = __ Simd128LoadTransform(
        __ WordPtrAdd(MemStart(imm.mem_index), imm.offset), final_index,
        load_kind, transform_kind, 0);

    if (v8_flags.trace_wasm_memory) {
      TraceMemoryOperation(decoder, false, repr, final_index, imm.offset);
    }

    result->op = load;
  }

  void LoadLane(FullDecoder* decoder, LoadType type, const Value& value,
                const Value& index, const MemoryAccessImmediate& imm,
                const uint8_t laneidx, Value* result) {
    using compiler::turboshaft::Simd128LaneMemoryOp;

    MemoryRepresentation repr =
        MemoryRepresentation::FromMachineType(type.mem_type());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       compiler::EnforceBoundsCheck::kCanOmitBoundsCheck,
                       compiler::AlignmentCheck::kNo);
    Simd128LaneMemoryOp::Kind kind = GetMemoryAccessKind(repr, strategy);

    Simd128LaneMemoryOp::LaneKind lane_kind;

    switch (repr) {
      case MemoryRepresentation::Int8():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k8;
        break;
      case MemoryRepresentation::Int16():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k16;
        break;
      case MemoryRepresentation::Int32():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k32;
        break;
      case MemoryRepresentation::Int64():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k64;
        break;
      default:
        UNREACHABLE();
    }

    // TODO(14108): If `offset` is in int range, use it as static offset, or
    // consider using a larger type as offset.
    OpIndex load = __ Simd128LaneMemory(
        __ WordPtrAdd(MemStart(imm.mem_index), imm.offset), final_index,
        value.op, Simd128LaneMemoryOp::Mode::kLoad, kind, lane_kind, laneidx,
        0);

    if (v8_flags.trace_wasm_memory) {
      TraceMemoryOperation(decoder, false, repr, final_index, imm.offset);
    }

    result->op = load;
  }

  void StoreMem(FullDecoder* decoder, StoreType type,
                const MemoryAccessImmediate& imm, const Value& index,
                const Value& value) {
    bool needs_f32_to_f16_conv = false;
    if (type.value() == StoreType::kF32StoreF16 &&
        !SupportedOperations::float16()) {
      needs_f32_to_f16_conv = true;
      type = StoreType::kI32Store16;
    }
    MemoryRepresentation repr =
        MemoryRepresentation::FromMachineRepresentation(type.mem_rep());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       wasm::kPartialOOBWritesAreNoops
                           ? compiler::EnforceBoundsCheck::kCanOmitBoundsCheck
                           : compiler::EnforceBoundsCheck::kNeedsBoundsCheck,
                       compiler::AlignmentCheck::kNo);

    V<WordPtr> mem_start = MemStart(imm.memory->index);

    StoreOp::Kind store_kind = GetMemoryAccessKind(repr, strategy);

    OpIndex store_value = value.op;
    if (value.type == kWasmI64 && repr.SizeInBytes() <= 4) {
      store_value = __ TruncateWord64ToWord32(store_value);
    }
    if (needs_f32_to_f16_conv) {
      store_value = CallCStackSlotToStackSlot(
          store_value, ExternalReference::wasm_float32_to_float16(),
          MemoryRepresentation::Float32(), MemoryRepresentation::Int16());
    }

#if defined(V8_TARGET_BIG_ENDIAN)
    store_value = BuildChangeEndiannessStore(store_value, type.mem_rep(),
                                             type.value_type());
#endif
    const bool offset_in_int_range =
        imm.offset <= std::numeric_limits<int32_t>::max();
    OpIndex base =
        offset_in_int_range ? mem_start : __ WordPtrAdd(mem_start, imm.offset);
    int32_t offset = offset_in_int_range ? static_cast<int32_t>(imm.offset) : 0;
    __ Store(base, final_index, store_value, store_kind, repr,
             compiler::kNoWriteBarrier, offset);

    if (v8_flags.trace_wasm_memory) {
      // TODO(14259): Implement memory tracing for multiple memories.
      CHECK_EQ(0, imm.memory->index);
      TraceMemoryOperation(decoder, true, repr, final_index, imm.offset);
    }
  }

  void StoreLane(FullDecoder* decoder, StoreType type,
                 const MemoryAccessImmediate& imm, const Value& index,
                 const Value& value, const uint8_t laneidx) {
    using compiler::turboshaft::Simd128LaneMemoryOp;

    MemoryRepresentation repr =
        MemoryRepresentation::FromMachineRepresentation(type.mem_rep());

    auto [final_index, strategy] =
        BoundsCheckMem(imm.memory, repr, index.op, imm.offset,
                       kPartialOOBWritesAreNoops
                           ? compiler::EnforceBoundsCheck::kCanOmitBoundsCheck
                           : compiler::EnforceBoundsCheck::kNeedsBoundsCheck,
                       compiler::AlignmentCheck::kNo);
    Simd128LaneMemoryOp::Kind kind = GetMemoryAccessKind(repr, strategy);

    Simd128LaneMemoryOp::LaneKind lane_kind;

    switch (repr) {
      // TODO(manoskouk): Why use unsigned representations here as opposed to
      // LoadLane?
      case MemoryRepresentation::Uint8():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k8;
        break;
      case MemoryRepresentation::Uint16():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k16;
        break;
      case MemoryRepresentation::Uint32():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k32;
        break;
      case MemoryRepresentation::Uint64():
        lane_kind = Simd128LaneMemoryOp::LaneKind::k64;
        break;
      default:
        UNREACHABLE();
    }

    // TODO(14108): If `offset` is in int range, use it as static offset, or
    // consider using a larger type as offset.
    __ Simd128LaneMemory(__ WordPtrAdd(MemStart(imm.mem_index), imm.offset),
                         final_index, value.op,
                         Simd128LaneMemoryOp::Mode::kStore, kind, lane_kind,
                         laneidx, 0);

    if (v8_flags.trace_wasm_memory) {
      TraceMemoryOperation(decoder, true, repr, final_index, imm.offset);
    }
  }

  void CurrentMemoryPages(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                          Value* result) {
    V<WordPtr> result_wordptr =
        __ WordPtrShiftRightArithmetic(MemSize(imm.index), kWasmPageSizeLog2);
    // In the 32-bit case, truncation happens implicitly.
    if (imm.memory->is_memory64()) {
      result->op = __ ChangeIntPtrToInt64(result_wordptr);
    } else {
      result->op = __ TruncateWordPtrToWord32(result_wordptr);
    }
  }

  void MemoryGrow(FullDecoder* decoder, const MemoryIndexImmediate& imm,
                  const Value& value, Value* result) {
    if (!imm.memory->is_memory64()) {
      result->op =
          CallBuiltinThroughJumptable<BuiltinCallDescriptor::WasmMemoryGrow>(
              decoder, {__ Word32Constant(imm.index), value.op});
    }
```