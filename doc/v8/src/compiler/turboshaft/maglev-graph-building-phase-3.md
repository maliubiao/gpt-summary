Response: The user wants a summary of the C++ code provided, which is part of the Turboshaft compilation pipeline in V8.

The file `maglev-graph-building-phase.cc` seems to be responsible for translating a Maglev graph (an intermediate representation used in V8's Maglev compiler) into a Turboshaft graph (another IR used in V8's Turboshaft compiler).

The code defines a `GraphBuildingNodeProcessor` class with `Process` methods for various Maglev node types. These methods seem to perform the translation of individual Maglev nodes into corresponding Turboshaft operations.

Key observations:

- Each `Process` method handles a specific Maglev node type (e.g., `Float64ToUint8Clamped`, `CheckedNumberToUint8Clamped`, `ToObject`, `Return`, `Deopt`, etc.).
- The methods interact with a Turboshaft `AssemblerT` to build the Turboshaft graph.
- Some methods handle deoptimization scenarios (`Deopt` nodes).
- Some methods handle function calls and returns (`ToObject`, `Return`).
- Some methods interact with the JavaScript runtime environment (e.g., `SetPendingMessage`).
- Some methods handle generator functions (`GeneratorStore`, `GeneratorRestoreRegister`).
- There's logic for handling frame states during deoptimization.
- There are cases where Maglev nodes are directly translated to Turboshaft operations, and cases where more complex logic is required.
- The code handles different types of deoptimization frames (interpreted, builtin continuation, etc.).
- The code appears to manage frame state information necessary for deoptimization.
- There's logic for handling virtual objects during frame state construction.
- There's a `Deduplicator` class, likely used to avoid redundant creation of frame state elements.
- There are helper functions for comparisons and type conversions.
- There's a `ThrowingScope` class for handling exceptions during the translation.

The user also requested an example in JavaScript if there's a relation to JavaScript functionality. Many of the handled Maglev nodes directly correspond to JavaScript operations.

The file is part 4 of 5, suggesting that it focuses on the core translation logic, building upon earlier stages and leading to later stages in the Turboshaft pipeline.
这是 `v8/src/compiler/turboshaft/maglev-graph-building-phase.cc` 文件的第 4 部分，该文件负责将 Maglev 图转换为 Turboshaft 图。这一部分主要定义了 `GraphBuildingNodeProcessor` 类，并实现了其 `Process` 方法，用于处理各种 Maglev 节点，将其转换为对应的 Turboshaft 操作。

**主要功能归纳:**

1. **Maglev 节点到 Turboshaft 操作的转换:**  `GraphBuildingNodeProcessor` 类中的每个 `Process` 方法都针对一个特定的 Maglev 节点类型，例如 `Float64ToUint8Clamped`, `CheckedNumberToUint8Clamped`, `ToObject`, `Return`, `Deopt` 等。这些方法接收 Maglev 节点作为输入，并生成相应的 Turboshaft 操作，添加到 Turboshaft 的 `AssemblerT` 中。

2. **处理类型转换和检查:** 代码处理了各种类型转换，例如浮点数到整数的转换 (`Float64ToUint8Clamped`)，以及带有类型检查的转换 (`CheckedNumberToUint8Clamped`)。在进行类型转换时，还会处理可能的 deoptimization 情况。

3. **处理函数调用:**  `Process(maglev::ToObject*)` 方法处理 `ToObject` 操作，它会生成一个对内置函数 `Builtin::kToObject` 的调用。

4. **处理控制流:**  `Process(maglev::Return*)` 生成返回指令，`Process(maglev::Deopt*)` 生成 deoptimization 指令。

5. **处理异常和错误:** `Process(maglev::SetPendingMessage*)` 用于设置待处理的消息，`Process(maglev::Abort*)` 用于运行时中止。

6. **处理生成器函数:**  `Process(maglev::GeneratorStore*)` 和 `Process(maglev::GeneratorRestoreRegister*)` 处理生成器函数的存储和恢复操作。

7. **处理帧状态 (Frame State):** 代码中大量使用了 `FrameState`，这与 deoptimization 密切相关。当需要 deoptimize 时，需要恢复到之前的执行状态。这部分代码负责构建和管理这种状态。`BuildFrameState` 系列函数根据不同的 deoptimization 帧类型（例如解释执行帧、内置延续帧）构建 `FrameState` 对象。

8. **处理内联和虚拟对象:** 代码能够处理内联分配 (`maglev::InlinedAllocation`) 和虚拟对象 (`maglev::VirtualObject`)，这些是在优化过程中创建的抽象表示。

9. **处理调试和断点:** `Process(maglev::DebugBreak*)` 生成断点指令。

10. **处理 JavaScript 特有的操作:** 例如 `Process(maglev::HandleNoHeapWritesInterrupt*)` 用于处理堆写入中断。

**与 JavaScript 功能的关系及 JavaScript 示例:**

该文件的核心功能是将 Maglev 图转换为 Turboshaft 图，而 Maglev 图本身是对 JavaScript 代码执行过程的一种抽象表示。因此，这里涉及的几乎每一个操作都与 JavaScript 的功能直接或间接地相关。

以下是一些 JavaScript 示例，对应于代码中的一些处理逻辑：

**1. 类型转换 (`Float64ToUint8Clamped`, `CheckedNumberToUint8Clamped`):**

```javascript
// JavaScript 会自动进行类型转换
let num1 = 123.45;
let clamped1 = Math.min(Math.max(0, num1), 255); // 模拟 clamp 操作

let num2 = 300;
let clamped2 = Math.min(Math.max(0, num2), 255);

// `CheckedNumberToUint8Clamped` 可能会在运行时检查类型
function foo(x) {
  return Math.min(Math.max(0, x), 255);
}

foo(100); // 正常执行
// 如果传入非 Number 类型，可能会触发 deoptimization
// foo("hello");
```

**2. `ToObject` 操作:**

```javascript
let str = "hello";
let objStr = Object(str); // 将原始值转换为对象

let num = 10;
let objNum = Object(num);
```

**3. 函数调用:**

```javascript
function greet(name) {
  console.log("Hello, " + name);
}

greet("World"); // 调用函数
```

**4. 异常处理:**

```javascript
try {
  throw new Error("Something went wrong!");
} catch (e) {
  console.error("Caught an error:", e.message);
}
```

**5. 生成器函数:**

```javascript
function* myGenerator() {
  yield 1;
  yield 2;
  return 3;
}

const generator = myGenerator();
console.log(generator.next()); // { value: 1, done: false }
console.log(generator.next()); // { value: 2, done: false }
console.log(generator.next()); // { value: 3, done: true }
```

**总结:**

作为 Turboshaft 编译管道的一部分，这个文件的主要职责是将 Maglev 图中的各种操作转换为 Turboshaft 可以理解的形式。这些操作都直接对应于 JavaScript 的语义和运行时行为，包括类型转换、函数调用、控制流、异常处理以及更高级的特性如生成器函数。`GraphBuildingNodeProcessor` 就像一个翻译器，将 Maglev 的指令翻译成 Turboshaft 的指令，为后续的优化和代码生成阶段做准备。第 4 部分重点在于具体的节点转换逻辑和帧状态的管理。

### 提示词
```
这是目录为v8/src/compiler/turboshaft/maglev-graph-building-phase.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```
aglev::ProcessResult Process(maglev::Float64ToUint8Clamped* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, Float64ToUint8Clamped(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedNumberToUint8Clamped* node,
                                const maglev::ProcessingState& state) {
    ScopedVar<Word32, AssemblerT> result(this);
    V<Object> value = Map(node->input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    IF (__ IsSmi(value)) {
      result = Int32ToUint8Clamped(__ UntagSmi(V<Smi>::Cast(value)));
    } ELSE {
      V<i::Map> map = __ LoadMapField(value);
      __ DeoptimizeIfNot(
          __ TaggedEqual(map,
                         __ HeapConstant(local_factory_->heap_number_map())),
          frame_state, DeoptimizeReason::kNotAHeapNumber,
          node->eager_deopt_info()->feedback_to_update());
      result = Float64ToUint8Clamped(
          __ LoadHeapNumberValue(V<HeapNumber>::Cast(value)));
    }
    RETURN_IF_UNREACHABLE();
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ToObject* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    OpIndex arguments[] = {Map(node->value_input()), Map(node->context())};

    GENERATE_AND_MAP_BUILTIN_CALL(node, Builtin::kToObject, frame_state,
                                  base::VectorOf(arguments));

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Return* node,
                                const maglev::ProcessingState& state) {
    __ Return(Map(node->value_input()));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Deopt* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ Deoptimize(frame_state, node->reason(),
                  node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::SetPendingMessage* node,
                                const maglev::ProcessingState& state) {
    V<WordPtr> message_address = __ ExternalConstant(
        ExternalReference::address_of_pending_message(isolate_));
    V<Object> old_message = __ LoadMessage(message_address);
    __ StoreMessage(message_address, Map(node->value()));
    SetMap(node, old_message);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::GeneratorStore* node,
                                const maglev::ProcessingState& state) {
    base::SmallVector<OpIndex, 32> parameters_and_registers;
    int num_parameters_and_registers = node->num_parameters_and_registers();
    for (int i = 0; i < num_parameters_and_registers; i++) {
      parameters_and_registers.push_back(
          Map(node->parameters_and_registers(i)));
    }
    __ GeneratorStore(Map(node->context_input()), Map(node->generator_input()),
                      parameters_and_registers, node->suspend_id(),
                      node->bytecode_offset());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::GeneratorRestoreRegister* node,
                                const maglev::ProcessingState& state) {
    V<FixedArray> array = Map(node->array_input());
    V<Object> result =
        __ LoadTaggedField(array, FixedArray::OffsetOfElementAt(node->index()));
    __ Store(array, Map(node->stale_input()), StoreOp::Kind::TaggedBase(),
             MemoryRepresentation::TaggedSigned(),
             WriteBarrierKind::kNoWriteBarrier,
             FixedArray::OffsetOfElementAt(node->index()));

    SetMap(node, result);

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Abort* node,
                                const maglev::ProcessingState& state) {
    __ RuntimeAbort(node->reason());
    // TODO(dmercadier): remove this `Unreachable` once RuntimeAbort is marked
    // as a block terminator.
    __ Unreachable();
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Identity* node,
                                const maglev::ProcessingState&) {
    SetMap(node, Map(node->input(0)));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Dead*, const maglev::ProcessingState&) {
    // Nothing to do; `Dead` is in Maglev to kill a node when removing it
    // directly from the graph is not possible.
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::DebugBreak*,
                                const maglev::ProcessingState&) {
    __ DebugBreak();
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::GapMove*,
                                const maglev::ProcessingState&) {
    // GapMove nodes are created by Maglev's register allocator, which
    // doesn't run when using Maglev as a frontend for Turboshaft.
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::ConstantGapMove*,
                                const maglev::ProcessingState&) {
    // ConstantGapMove nodes are created by Maglev's register allocator, which
    // doesn't run when using Maglev as a frontend for Turboshaft.
    UNREACHABLE();
  }

  maglev::ProcessResult Process(maglev::VirtualObject*,
                                const maglev::ProcessingState&) {
    // VirtualObjects should never be part of the Maglev graph.
    UNREACHABLE();
  }

  maglev::ProcessResult Process(maglev::GetSecondReturnedValue* node,
                                const maglev::ProcessingState& state) {
    DCHECK(second_return_value_.valid());
    SetMap(node, second_return_value_);

#ifdef DEBUG
    second_return_value_ = V<Object>::Invalid();
#endif

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::TryOnStackReplacement*,
                                const maglev::ProcessingState&) {
    // Turboshaft is the top tier compiler, so we never need to OSR from it.
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ReduceInterruptBudgetForReturn*,
                                const maglev::ProcessingState&) {
    // No need to update the interrupt budget once we reach Turboshaft.
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ReduceInterruptBudgetForLoop* node,
                                const maglev::ProcessingState&) {
    // ReduceInterruptBudgetForLoop nodes are not emitted by Maglev when it is
    // used as a frontend for Turboshaft.
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::HandleNoHeapWritesInterrupt* node,
                                const maglev::ProcessingState&) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    __ JSLoopStackCheck(native_context(), frame_state);
    return maglev::ProcessResult::kContinue;
  }

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
  maglev::ProcessResult Process(
      maglev::GetContinuationPreservedEmbedderData* node,
      const maglev::ProcessingState&) {
    V<Object> data = __ GetContinuationPreservedEmbedderData();
    SetMap(node, data);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(
      maglev::SetContinuationPreservedEmbedderData* node,
      const maglev::ProcessingState&) {
    V<Object> data = Map(node->input(0));
    __ SetContinuationPreservedEmbedderData(data);
    return maglev::ProcessResult::kContinue;
  }
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

  maglev::ProcessResult Process(maglev::AssertInt32* node,
                                const maglev::ProcessingState&) {
    bool negate_result = false;
    V<Word32> cmp = ConvertInt32Compare(node->left_input(), node->right_input(),
                                        node->condition(), &negate_result);
    Label<> abort(this);
    Label<> end(this);
    if (negate_result) {
      GOTO_IF(cmp, abort);
    } else {
      GOTO_IF_NOT(cmp, abort);
    }
    GOTO(end);

    BIND(abort);
    __ RuntimeAbort(node->reason());
    __ Unreachable();

    BIND(end);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CallSelf*,
                                const maglev::ProcessingState&) {
    // CallSelf nodes are only created when Maglev is the top-tier compiler
    // (which can't be the case here, since we're currently compiling for
    // Turboshaft).
    UNREACHABLE();
  }

  // Nodes unused by maglev but still existing.
  maglev::ProcessResult Process(maglev::ExternalConstant*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::CallCPPBuiltin*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::UnsafeTruncateUint32ToInt32*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::UnsafeTruncateFloat64ToInt32*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }
  maglev::ProcessResult Process(maglev::BranchIfTypeOf*,
                                const maglev::ProcessingState&) {
    UNREACHABLE();
  }

  AssemblerT& Asm() { return assembler_; }
  Zone* temp_zone() { return temp_zone_; }
  Zone* graph_zone() { return Asm().output_graph().graph_zone(); }

 private:
  OptionalV<FrameState> BuildFrameState(
      maglev::EagerDeoptInfo* eager_deopt_info) {
    deduplicator_.Reset();
    // Eager deopts don't have a result location/size.
    const interpreter::Register result_location =
        interpreter::Register::invalid_value();
    const int result_size = 0;
    const maglev::VirtualObject::List& virtual_objects =
        maglev::GetVirtualObjects(eager_deopt_info->top_frame());

    switch (eager_deopt_info->top_frame().type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(eager_deopt_info->top_frame().as_interpreted(),
                               virtual_objects, result_location, result_size);
      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(
            eager_deopt_info->top_frame().as_builtin_continuation(),
            virtual_objects);
      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        UNIMPLEMENTED();
    }
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::LazyDeoptInfo* lazy_deopt_info) {
    deduplicator_.Reset();
    const maglev::VirtualObject::List& virtual_objects =
        maglev::GetVirtualObjects(lazy_deopt_info->top_frame());
    switch (lazy_deopt_info->top_frame().type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(
            lazy_deopt_info->top_frame().as_interpreted(), virtual_objects,
            lazy_deopt_info->result_location(), lazy_deopt_info->result_size());
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        return BuildFrameState(lazy_deopt_info->top_frame().as_construct_stub(),
                               virtual_objects);

      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(
            lazy_deopt_info->top_frame().as_builtin_continuation(),
            virtual_objects);

      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
        UNIMPLEMENTED();
    }
  }

  OptionalV<FrameState> BuildParentFrameState(
      maglev::DeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    // Only the topmost frame should have a valid result_location and
    // result_size. One reason for this is that, in Maglev, the PokeAt is not an
    // attribute of the DeoptFrame but rather of the LazyDeoptInfo (to which the
    // topmost frame is attached).
    const interpreter::Register result_location =
        interpreter::Register::invalid_value();
    const int result_size = 0;

    switch (frame.type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return BuildFrameState(frame.as_interpreted(), virtual_objects,
                               result_location, result_size);
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        return BuildFrameState(frame.as_construct_stub(), virtual_objects);
      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
        return BuildFrameState(frame.as_inlined_arguments(), virtual_objects);
      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return BuildFrameState(frame.as_builtin_continuation(),
                               virtual_objects);
    }
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::ConstructInvokeStubDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    // TODO(dmercadier): ConstructInvokeStub frames don't have a Closure input,
    // but the instruction selector assumes that they do and that it should be
    // skipped. We thus use SmiConstant(0) as a fake Closure input here, but it
    // would be nicer to fix the instruction selector to not require this input
    // at all for such frames.
    V<Any> fake_closure_input = __ SmiConstant(0);
    builder.AddInput(MachineType::AnyTagged(), fake_closure_input);

    // Parameters
    AddDeoptInput(builder, virtual_objects, frame.receiver());

    // Context
    AddDeoptInput(builder, virtual_objects, frame.context());

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::InlinedArgumentsDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    AddDeoptInput(builder, virtual_objects, frame.closure());

    // Parameters
    for (const maglev::ValueNode* arg : frame.arguments()) {
      AddDeoptInput(builder, virtual_objects, arg);
    }

    // Context
    // TODO(dmercadier): InlinedExtraArguments frames don't have a Context
    // input, but the instruction selector assumes that they do and that it
    // should be skipped. We thus use SmiConstant(0) as a fake Context input
    // here, but it would be nicer to fix the instruction selector to not
    // require this input at all for such frames.
    V<Any> fake_context_input = __ SmiConstant(0);
    builder.AddInput(MachineType::AnyTagged(), fake_context_input);

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::BuiltinContinuationDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects) {
    FrameStateData::Builder builder;
    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    if (frame.is_javascript()) {
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(frame.javascript_target().object()));
    } else {
      builder.AddUnusedRegister();
    }

    // Parameters
    for (maglev::ValueNode* param : frame.parameters()) {
      AddDeoptInput(builder, virtual_objects, param);
    }

    // Extra fixed JS frame parameters. These are at the end since JS builtins
    // push their parameters in reverse order.
    constexpr int kExtraFixedJSFrameParameters =
        V8_ENABLE_LEAPTIERING_BOOL ? 4 : 3;
    if (frame.is_javascript()) {
      DCHECK_EQ(Builtins::CallInterfaceDescriptorFor(frame.builtin_id())
                    .GetRegisterParameterCount(),
                kExtraFixedJSFrameParameters);
      static_assert(kExtraFixedJSFrameParameters ==
                    3 + (V8_ENABLE_LEAPTIERING_BOOL ? 1 : 0));
      // kJavaScriptCallTargetRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(frame.javascript_target().object()));
      // kJavaScriptCallNewTargetRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(local_factory_->undefined_value()));
      // kJavaScriptCallArgCountRegister
      builder.AddInput(
          MachineType::AnyTagged(),
          __ SmiConstant(Smi::FromInt(
              Builtins::GetStackParameterCount(frame.builtin_id()))));
#ifdef V8_ENABLE_LEAPTIERING
      // kJavaScriptCallDispatchHandleRegister
      builder.AddInput(MachineType::AnyTagged(),
                       __ SmiConstant(Smi::FromInt(kInvalidDispatchHandle)));
#endif
    }

    // Context
    AddDeoptInput(builder, virtual_objects, frame.context());

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  OptionalV<FrameState> BuildFrameState(
      maglev::InterpretedDeoptFrame& frame,
      const maglev::VirtualObject::List& virtual_objects,
      interpreter::Register result_location, int result_size) {
    DCHECK_EQ(result_size != 0, result_location.is_valid());
    FrameStateData::Builder builder;

    if (frame.parent() != nullptr) {
      OptionalV<FrameState> parent_frame =
          BuildParentFrameState(*frame.parent(), virtual_objects);
      if (!parent_frame.has_value()) return OptionalV<FrameState>::Nullopt();
      builder.AddParentFrameState(parent_frame.value());
    }

    // Closure
    AddDeoptInput(builder, virtual_objects, frame.closure());

    // Parameters
    frame.frame_state()->ForEachParameter(
        frame.unit(), [&](maglev::ValueNode* value, interpreter::Register reg) {
          AddDeoptInput(builder, virtual_objects, value, reg, result_location,
                        result_size);
        });

    // Context
    AddDeoptInput(builder, virtual_objects,
                  frame.frame_state()->context(frame.unit()));

    // Locals
    // ForEachLocal in Maglev skips over dead registers, but we still need to
    // call AddUnusedRegister on the Turboshaft FrameStateData Builder.
    // {local_index} is used to keep track of such unused registers.
    // Among the variables not included in ForEachLocal is the Accumulator (but
    // this is fine since there is an entry in the state specifically for the
    // accumulator later).
    int local_index = 0;
    frame.frame_state()->ForEachLocal(
        frame.unit(), [&](maglev::ValueNode* value, interpreter::Register reg) {
          while (local_index < reg.index()) {
            builder.AddUnusedRegister();
            local_index++;
          }
          AddDeoptInput(builder, virtual_objects, value, reg, result_location,
                        result_size);
          local_index++;
        });
    for (; local_index < frame.unit().register_count(); local_index++) {
      builder.AddUnusedRegister();
    }

    // Accumulator
    if (frame.frame_state()->liveness()->AccumulatorIsLive()) {
      AddDeoptInput(builder, virtual_objects,
                    frame.frame_state()->accumulator(frame.unit()),
                    interpreter::Register::virtual_accumulator(),
                    result_location, result_size);
    } else {
      builder.AddUnusedRegister();
    }

    OutputFrameStateCombine combine =
        ComputeCombine(frame, result_location, result_size);

    if (builder.Inputs().size() >
        std::numeric_limits<decltype(Operation::input_count)>::max() - 1) {
      *bailout_ = BailoutReason::kTooManyArguments;
      return OptionalV<FrameState>::Nullopt();
    }

    const FrameStateInfo* frame_state_info = MakeFrameStateInfo(frame, combine);
    return __ FrameState(
        builder.Inputs(), builder.inlined(),
        builder.AllocateFrameStateData(*frame_state_info, graph_zone()));
  }

  void AddDeoptInput(FrameStateData::Builder& builder,
                     const maglev::VirtualObject::List& virtual_objects,
                     const maglev::ValueNode* node) {
    if (const maglev::InlinedAllocation* alloc =
            node->TryCast<maglev::InlinedAllocation>()) {
      DCHECK(alloc->HasBeenAnalysed());
      if (alloc->HasBeenElided()) {
        AddVirtualObjectInput(builder, virtual_objects,
                              virtual_objects.FindAllocatedWith(alloc));
        return;
      }
    }
    if (const maglev::Identity* ident_obj = node->TryCast<maglev::Identity>()) {
      // The value_representation of Identity nodes is always Tagged rather than
      // the actual value_representation of their input. We thus bypass identity
      // nodes manually here to get to correct value_representation and thus the
      // correct MachineType.
      node = ident_obj->input(0).node();
      // Identity nodes should not have Identity as input.
      DCHECK(!node->Is<maglev::Identity>());
    }
    builder.AddInput(MachineTypeFor(node->value_representation()), Map(node));
  }

  void AddDeoptInput(FrameStateData::Builder& builder,
                     const maglev::VirtualObject::List& virtual_objects,
                     const maglev::ValueNode* node, interpreter::Register reg,
                     interpreter::Register result_location, int result_size) {
    if (result_location.is_valid() && maglev::LazyDeoptInfo::InReturnValues(
                                          reg, result_location, result_size)) {
      builder.AddUnusedRegister();
    } else {
      AddDeoptInput(builder, virtual_objects, node);
    }
  }

  void AddVirtualObjectInput(FrameStateData::Builder& builder,
                             const maglev::VirtualObject::List& virtual_objects,
                             const maglev::VirtualObject* vobj) {
    if (vobj->type() == maglev::VirtualObject::kHeapNumber) {
      // We need to add HeapNumbers as dematerialized HeapNumbers (rather than
      // simply NumberConstant), because they could be mutable HeapNumber
      // fields, in which case we don't want GVN to merge them.
      constexpr int kNumberOfField = 2;  // map + value
      builder.AddDematerializedObject(deduplicator_.CreateFreshId().id,
                                      kNumberOfField);
      builder.AddInput(MachineType::AnyTagged(),
                       __ HeapConstant(local_factory_->heap_number_map()));
      builder.AddInput(MachineType::Float64(),
                       __ Float64Constant(vobj->number()));
      return;
    }

    Deduplicator::DuplicatedId dup_id = deduplicator_.GetDuplicatedId(vobj);
    if (dup_id.duplicated) {
      builder.AddDematerializedObjectReference(dup_id.id);
      return;
    }
    if (vobj->type() == maglev::VirtualObject::kFixedDoubleArray) {
      constexpr int kMapAndLengthFieldCount = 2;
      uint32_t length = vobj->double_elements_length();
      uint32_t field_count = length + kMapAndLengthFieldCount;
      builder.AddDematerializedObject(dup_id.id, field_count);
      builder.AddInput(
          MachineType::AnyTagged(),
          __ HeapConstantNoHole(local_factory_->fixed_double_array_map()));
      builder.AddInput(MachineType::AnyTagged(),
                       __ SmiConstant(Smi::FromInt(length)));
      FixedDoubleArrayRef elements = vobj->double_elements();
      for (uint32_t i = 0; i < length; i++) {
        i::Float64 value = elements.GetFromImmutableFixedDoubleArray(i);
        if (value.is_hole_nan()) {
          builder.AddInput(
              MachineType::AnyTagged(),
              __ HeapConstantHole(local_factory_->the_hole_value()));
        } else {
          builder.AddInput(MachineType::AnyTagged(),
                           __ NumberConstant(value.get_scalar()));
        }
      }
      return;
    }

    DCHECK_EQ(vobj->type(), maglev::VirtualObject::kDefault);
    constexpr int kMapFieldCount = 1;
    uint32_t field_count = vobj->slot_count() + kMapFieldCount;
    builder.AddDematerializedObject(dup_id.id, field_count);
    builder.AddInput(MachineType::AnyTagged(),
                     __ HeapConstantNoHole(vobj->map().object()));
    for (uint32_t i = 0; i < vobj->slot_count(); i++) {
      AddVirtualObjectNestedValue(builder, virtual_objects,
                                  vobj->get_by_index(i));
    }
  }

  void AddVirtualObjectNestedValue(
      FrameStateData::Builder& builder,
      const maglev::VirtualObject::List& virtual_objects,
      const maglev::ValueNode* value) {
    if (maglev::IsConstantNode(value->opcode())) {
      switch (value->opcode()) {
        case maglev::Opcode::kConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ HeapConstant(value->Cast<maglev::Constant>()->ref().object()));
          break;

        case maglev::Opcode::kFloat64Constant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ NumberConstant(value->Cast<maglev::Float64Constant>()
                                    ->value()
                                    .get_scalar()));
          break;

        case maglev::Opcode::kInt32Constant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ NumberConstant(value->Cast<maglev::Int32Constant>()->value()));
          break;

        case maglev::Opcode::kUint32Constant:
          builder.AddInput(MachineType::AnyTagged(),
                           __ NumberConstant(
                               value->Cast<maglev::Uint32Constant>()->value()));
          break;

        case maglev::Opcode::kRootConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              (__ HeapConstant(Cast<HeapObject>(isolate_->root_handle(
                  value->Cast<maglev::RootConstant>()->index())))));
          break;

        case maglev::Opcode::kSmiConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ SmiConstant(value->Cast<maglev::SmiConstant>()->value()));
          break;

        case maglev::Opcode::kTrustedConstant:
          builder.AddInput(
              MachineType::AnyTagged(),
              __ TrustedHeapConstant(
                  value->Cast<maglev::TrustedConstant>()->object().object()));
          break;

        case maglev::Opcode::kTaggedIndexConstant:
        case maglev::Opcode::kExternalConstant:
        default:
          UNREACHABLE();
      }
      return;
    }

    // Special nodes.
    switch (value->opcode()) {
      case maglev::Opcode::kArgumentsElements:
        builder.AddArgumentsElements(
            value->Cast<maglev::ArgumentsElements>()->type());
        break;
      case maglev::Opcode::kArgumentsLength:
        builder.AddArgumentsLength();
        break;
      case maglev::Opcode::kRestLength:
        builder.AddRestLength();
        break;
      case maglev::Opcode::kVirtualObject:
        UNREACHABLE();
      default:
        AddDeoptInput(builder, virtual_objects, value);
        break;
    }
  }

  class Deduplicator {
   public:
    struct DuplicatedId {
      uint32_t id;
      bool duplicated;
    };
    DuplicatedId GetDuplicatedId(const maglev::VirtualObject* object) {
      // TODO(dmercadier): do better than a linear search here.
      for (uint32_t idx = 0; idx < object_ids_.size(); idx++) {
        if (object_ids_[idx] == object) {
          return {idx, true};
        }
      }
      object_ids_.push_back(object);
      return {next_id_++, false};
    }

    DuplicatedId CreateFreshId() { return {next_id_++, false}; }

    void Reset() {
      object_ids_.clear();
      next_id_ = 0;
    }

    static const uint32_t kNotDuplicated = -1;

   private:
    std::vector<const maglev::VirtualObject*> object_ids_{10};
    uint32_t next_id_ = 0;
  };

  OutputFrameStateCombine ComputeCombine(maglev::InterpretedDeoptFrame& frame,
                                         interpreter::Register result_location,
                                         int result_size) {
    if (result_size == 0) {
      return OutputFrameStateCombine::Ignore();
    }
    return OutputFrameStateCombine::PokeAt(
        frame.ComputeReturnOffset(result_location, result_size));
  }

  const FrameStateInfo* MakeFrameStateInfo(
      maglev::InterpretedDeoptFrame& maglev_frame,
      OutputFrameStateCombine combine) {
    FrameStateType type = FrameStateType::kUnoptimizedFunction;
    uint16_t parameter_count = maglev_frame.unit().parameter_count();
    uint16_t max_arguments = maglev_frame.unit().max_arguments();
    int local_count = maglev_frame.unit().register_count();
    Handle<SharedFunctionInfo> shared_info =
        maglev_frame.unit().shared_function_info().object();
    Handle<BytecodeArray> bytecode_array =
        maglev_frame.unit().bytecode().object();
    FrameStateFunctionInfo* info = graph_zone()->New<FrameStateFunctionInfo>(
        type, parameter_count, max_arguments, local_count, shared_info,
        bytecode_array);

    return graph_zone()->New<FrameStateInfo>(maglev_frame.bytecode_position(),
                                             combine, info);
  }

  const FrameStateInfo* MakeFrameStateInfo(
      maglev::InlinedArgumentsDeoptFrame& maglev_frame) {
    FrameStateType type = FrameStateType::kInlinedExtraArguments;
    uint16_t parameter_count =
        static_cast<uint16_t>(maglev_frame.arguments().size());
    uint16_t max_arguments = 0;
    int local_count = 0;
    Handle<SharedFunctionInfo> shared_info =
        maglev_frame.unit().shared_function_info().object();
    FrameStateFunctionInfo* info = graph_zone()->New<FrameStateFunctionInfo>(
        type, parameter_count, max_arguments, local_count, shared_info,
        kNullMaybeHandle);

    return graph_zone()->New<FrameStateInfo>(maglev_frame.bytecode_position(),
                                             OutputFrameStateCombine::Ignore(),
                                             info);
  }

  const FrameStateInfo* MakeFrameStateInfo(
      maglev::ConstructInvokeStubDeoptFrame& maglev_frame) {
    FrameStateType type = FrameStateType::kConstructInvokeStub;
    Handle<SharedFunctionInfo> shared_info =
        maglev_frame.unit().shared_function_info().object();
    constexpr uint16_t kParameterCount = 1;  // Only 1 parameter: the receiver.
    constexpr uint16_t kMaxArguments = 0;
    constexpr int kLocalCount = 0;
    FrameStateFunctionInfo* info = graph_zone()->New<FrameStateFunctionInfo>(
        type, kParameterCount, kMaxArguments, kLocalCount, shared_info,
        kNullMaybeHandle);

    return graph_zone()->New<FrameStateInfo>(
        BytecodeOffset::None(), OutputFrameStateCombine::Ignore(), info);
  }

  const FrameStateInfo* MakeFrameStateInfo(
      maglev::BuiltinContinuationDeoptFrame& maglev_frame) {
    FrameStateType type = maglev_frame.is_javascript()
                              ? FrameStateType::kJavaScriptBuiltinContinuation
                              : FrameStateType::kBuiltinContinuation;
    uint16_t parameter_count =
        static_cast<uint16_t>(maglev_frame.parameters().length());
    if (maglev_frame.is_javascript()) {
      constexpr int kExtraFixedJSFrameParameters =
          V8_ENABLE_LEAPTIERING_BOOL ? 4 : 3;
      DCHECK_EQ(Builtins::CallInterfaceDescriptorFor(maglev_frame.builtin_id())
                    .GetRegisterParameterCount(),
                kExtraFixedJSFrameParameters);
      parameter_count += kExtraFixedJSFrameParameters;
    }
    Handle<SharedFunctionInfo> shared_info =
        GetSharedFunctionInfo(maglev_frame).object();
    constexpr int kLocalCount = 0;
    constexpr uint16_t kMaxArguments = 0;
    FrameStateFunctionInfo* info = graph_zone()->New<FrameStateFunctionInfo>(
        type, parameter_count, kMaxArguments, kLocalCount, shared_info,
        kNullMaybeHandle);

    return graph_zone()->New<FrameStateInfo>(
        Builtins::GetContinuationBytecodeOffset(maglev_frame.builtin_id()),
        OutputFrameStateCombine::Ignore(), info);
  }

  SharedFunctionInfoRef GetSharedFunctionInfo(
      const maglev::DeoptFrame& deopt_frame) {
    switch (deopt_frame.type()) {
      case maglev::DeoptFrame::FrameType::kInterpretedFrame:
        return deopt_frame.as_interpreted().unit().shared_function_info();
      case maglev::DeoptFrame::FrameType::kInlinedArgumentsFrame:
        return deopt_frame.as_inlined_arguments().unit().shared_function_info();
      case maglev::DeoptFrame::FrameType::kConstructInvokeStubFrame:
        return deopt_frame.as_construct_stub().unit().shared_function_info();
      case maglev::DeoptFrame::FrameType::kBuiltinContinuationFrame:
        return GetSharedFunctionInfo(*deopt_frame.parent());
    }
    UNREACHABLE();
  }

  enum class Sign { kSigned, kUnsigned };
  template <typename rep>
  V<Word32> ConvertCompare(maglev::Input left_input, maglev::Input right_input,
                           ::Operation operation, Sign sign) {
    DCHECK_IMPLIES(
        (std::is_same_v<rep, Float64> || std::is_same_v<rep, Float32>),
        sign == Sign::kSigned);
    ComparisonOp::Kind kind;
    bool swap_inputs = false;
    switch (operation) {
      case ::Operation::kEqual:
      case ::Operation::kStrictEqual:
        kind = ComparisonOp::Kind::kEqual;
        break;
      case ::Operation::kLessThan:
        kind = sign == Sign::kSigned ? ComparisonOp::Kind::kSignedLessThan
                                     : ComparisonOp::Kind::kUnsignedLessThan;
        break;
      case ::Operation::kLessThanOrEqual:
        kind = sign == Sign::kSigned
                   ? ComparisonOp::Kind::kSignedLessThanOrEqual
                   : ComparisonOp::Kind::kUnsignedLessThanOrEqual;
        break;
      case ::Operation::kGreaterThan:
        kind = sign == Sign::kSigned ? ComparisonOp::Kind::kSignedLessThan
                                     : ComparisonOp::Kind::kUnsignedLessThan;
        swap_inputs = true;
        break;
      case ::Operation::kGreaterThanOrEqual:
        kind = sign == Sign::kSigned
                   ? ComparisonOp::Kind::kSignedLessThanOrEqual
                   : ComparisonOp::Kind::kUnsignedLessThanOrEqual;
        swap_inputs = true;
        break;
      default:
        UNREACHABLE();
    }
    V<rep> left = Map(left_input);
    V<rep> right = Map(right_input);
    if (swap_inputs) std::swap(left, right);
    return __ Comparison(left, right, kind, V<rep>::rep);
  }

  V<Word32> ConvertInt32Compare(maglev::Input left_input,
                                maglev::Input right_input,
                                maglev::AssertCondition condition,
                                bool* negate_result) {
    ComparisonOp::Kind kind;
    bool swap_inputs = false;
    switch (condition) {
      case maglev::AssertCondition::kEqual:
        kind = ComparisonOp::Kind::kEqual;
        break;
      case maglev::AssertCondition::kNotEqual:
        kind = ComparisonOp::Kind::kEqual;
        *negate_result = true;
        break;
      case maglev::AssertCondition::kLessThan:
        kind = ComparisonOp::Kind::kSignedLessThan;
        break;
      case maglev::AssertCondition::kLessThanEqual:
        kind = ComparisonOp::Kind::kSignedLessThanOrEqual;
        break;
      case maglev::AssertCondition::kGreaterThan:
        kind = ComparisonOp::Kind::kSignedLessThan;
        swap_inputs = true;
        break;
      case maglev::AssertCondition::kGreaterThanEqual:
        kind = ComparisonOp::Kind::kSignedLessThanOrEqual;
        swap_inputs = true;
        break;
      case maglev::AssertCondition::kUnsignedLessThan:
        kind = ComparisonOp::Kind::kUnsignedLessThan;
        break;
      case maglev::AssertCondition::kUnsignedLessThanEqual:
        kind = ComparisonOp::Kind::kUnsignedLessThanOrEqual;
        break;
      case maglev::AssertCondition::kUnsignedGreaterThan:
        kind = ComparisonOp::Kind::kUnsignedLessThan;
        swap_inputs = true;
        break;
      case maglev::AssertCondition::kUnsignedGreaterThanEqual:
        kind = ComparisonOp::Kind::kUnsignedLessThanOrEqual;
        swap_inputs = true;
        break;
    }
    V<Word32> left = Map(left_input);
    V<Word32> right = Map(right_input);
    if (swap_inputs) std::swap(left, right);
    return __ Comparison(left, right, kind, WordRepresentation::Word32());
  }

  V<Word32> RootEqual(maglev::Input input, RootIndex root) {
    return __ RootEqual(Map(input), root, isolate_);
  }

  void DeoptIfInt32IsNotSmi(maglev::Input maglev_input,
                            V<FrameState> frame_state,
                            const compiler::FeedbackSource& feedback) {
    return DeoptIfInt32IsNotSmi(Map<Word32>(maglev_input), frame_state,
                                feedback);
  }
  void DeoptIfInt32IsNotSmi(V<Word32> input, V<FrameState> frame_state,
                            const compiler::FeedbackSource& feedback) {
    // TODO(dmercadier): is there no higher level way of doing this?
    V<Tuple<Word32, Word32>> add = __ Int32AddCheckOverflow(input, input);
    V<Word32> check = __ template Projection<1>(add);
    __ DeoptimizeIf(check, frame_state, DeoptimizeReason::kNotASmi, feedback);
  }

  std::pair<V<WordPtr>, V<Object>> GetTypedArrayDataAndBasePointers(
      V<JSTypedArray> typed_array) {
    V<WordPtr> data_pointer = __ LoadField<WordPtr>(
        typed_array, AccessBuilder::ForJSTypedArrayExternalPointer());
    V<Object> base_pointer = __ LoadField<Object>(
        typed_array, AccessBuilder::ForJSTypedArrayBasePointer());
    return {data_pointer, base_pointer};
  }
  V<Untagged> BuildTypedArrayLoad(V<JSTypedArray> typed_array, V<Word32> index,
                                  ElementsKind kind) {
    auto [data_pointer, base_pointer] =
        GetTypedArrayDataAndBasePointers(typed_array);
    return __ LoadTypedElement(typed_array, base_pointer, data_pointer,
                               __ ChangeUint32ToUintPtr(index),
                               GetArrayTypeFromElementsKind(kind));
  }
  void BuildTypedArrayStore(V<JSTypedArray> typed_array, V<Word32> index,
                            V<Untagged> value, ElementsKind kind) {
    auto [data_pointer, base_pointer] =
        GetTypedArrayDataAndBasePointers(typed_array);
    __ StoreTypedElement(typed_array, base_pointer, data_pointer,
                         __ ChangeUint32ToUintPtr(index), value,
                         GetArrayTypeFromElementsKind(kind));
  }

  V<Number> Float64ToTagged(
      V<Float64> input,
      maglev::Float64ToTagged::ConversionMode conversion_mode) {
    // Float64ToTagged's conversion mode is used to control whether integer
    // floats should be converted to Smis or to HeapNumbers: kCanonicalizeSmi
    // means that they can be converted to Smis, and otherwise they should
    // remain HeapNumbers.
    ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind kind =
        conversion_mode ==
                maglev::Float64ToTagged::ConversionMode::kCanonicalizeSmi
            ? ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kNumber
            : ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kHeapNumber;
    return V<Number>::Cast(__ ConvertUntaggedToJSPrimitive(
        input, kind, RegisterRepresentation::Float64(),
        ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned,
        CheckForMinusZeroMode::kCheckForMinusZero));
  }

  V<NumberOrUndefined> HoleyFloat64ToTagged(
      V<Float64> input,
      maglev::HoleyFloat64ToTagged::ConversionMode conversion_mode) {
    Label<NumberOrUndefined> done(this);
    if (conversion_mode ==
        maglev::HoleyFloat64ToTagged::ConversionMode::kCanonicalizeSmi) {
      // ConvertUntaggedToJSPrimitive cannot at the same time canonicalize smis
      // and handle holes. We thus manually insert a smi check when the
      // conversion_mode is CanonicalizeSmi.
      IF (__ Float64IsSmi(input)) {
        V<Word32> as_int32 = __ TruncateFloat64ToInt32OverflowUndefined(input);
        V<Smi> as_smi = V<Smi>::Cast(__ ConvertUntaggedToJSPrimitive(
            as_int32, ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::kSmi,
            RegisterRepresentation::Word32(),
            ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned,
            CheckForMinusZeroMode::kDontCheckForMinusZero));
        GOTO(done, as_smi);
      }
    }
    V<NumberOrUndefined> as_obj =
        V<NumberOrUndefined>::Cast(__ ConvertUntaggedToJSPrimitive(
            input,
            ConvertUntaggedToJSPrimitiveOp::JSPrimitiveKind::
                kHeapNumberOrUndefined,
            RegisterRepresentation::Float64(),
            ConvertUntaggedToJSPrimitiveOp::InputInterpretation::kSigned,
            CheckForMinusZeroMode::kCheckForMinusZero));
    if (done.has_incoming_jump()) {
      GOTO(done, as_obj);
      BIND(done, result);
      return result;
    } else {
      // Avoid creating a new block if {as_obj} is the only possible return
      // value.
      return as_obj;
    }
  }

  void FixLoopPhis(maglev::BasicBlock* loop) {
    DCHECK(loop->is_loop());
    if (!loop->has_phi()) return;
    for (maglev::Phi* maglev_phi : *loop->phis()) {
      OpIndex phi_index = Map(maglev_phi);
      PendingLoopPhiOp& pending_phi =
          __ output_graph().Get(phi_index).Cast<PendingLoopPhiOp>();
      __ output_graph().Replace<PhiOp>(
          phi_index,
          base::VectorOf(
              {pending_phi.first(), Map(maglev_phi -> backedge_input())}),
          pending_phi.rep);
    }
  }

  RegisterRepresentation RegisterRepresentationFor(
      maglev::ValueRepresentation value_rep) {
    switch (value_rep) {
      case maglev::ValueRepresentation::kTagged:
        return RegisterRepresentation::Tagged();
      case maglev::ValueRepresentation::kInt32:
      case maglev::ValueRepresentation::kUint32:
        return RegisterRepresentation::Word32();
      case maglev::ValueRepresentation::kFloat64:
      case maglev::ValueRepresentation::kHoleyFloat64:
        return RegisterRepresentation::Float64();
      case maglev::ValueRepresentation::kIntPtr:
        return RegisterRepresentation::WordPtr();
    }
  }

  // TODO(dmercadier): Using a Branch would open more optimization opportunities
  // for BranchElimination compared to using a Select. However, in most cases,
  // Maglev should avoid materializing JS booleans, so there is a good chance
  // that it we actually need to do it, it's because we have to, and
  // BranchElimination probably cannot help. Thus, using a Select rather than a
  // Branch leads to smaller graphs, which is generally beneficial. Still, once
  // the graph builder is finished, we should evaluate whether Select or Branch
  // is the best choice here.
  V<Boolean> ConvertWord32ToJSBool(V<Word32> b, bool flip = false) {
    V<Boolean> true_idx = __ HeapConstant(local_factory_->true_value());
    V<Boolean> false_idx = __ HeapConstant(local_factory_->false_value());
    if (flip) std::swap(true_idx, false_idx);
    return __ Select(b, true_idx, false_idx, RegisterRepresentation::Tagged(),
                     BranchHint::kNone, SelectOp::Implementation::kBranch);
  }

  // This function corresponds to MaglevAssembler::ToBoolean.
  V<Word32> ToBit(
      maglev::Input input,
      TruncateJSPrimitiveToUntaggedOp::InputAssumptions assumptions) {
    // TODO(dmercadier): {input} in Maglev is of type Object (like, any
    // HeapObject or Smi). However, the implementation of ToBoolean in Maglev is
    // identical to the lowering of TruncateJSPrimitiveToUntaggedOp(kBit) in
    // Turboshaft (which is done in MachineLoweringReducer), so we're using
    // TruncateJSPrimitiveToUntaggedOp with a non-JSPrimitive input (but it
    // still works). We should avoid doing this to avoid any confusion. Renaming
    // TruncateJSPrimitiveToUntagged to TruncateObjectToUntagged might be the
    // proper fix, in particular because it seems that the Turbofan input to
    // this operation is indeed an Object rather than a JSPrimitive (since
    // we use this operation in the regular TF->TS graph builder to translate
    // TruncateTaggedToBit and TruncateTaggedPointerToBit).
    return V<Word32>::Cast(__ TruncateJSPrimitiveToUntagged(
        Map(input.node()), TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kBit,
        assumptions));
  }

  // Converts a Float64 to a Word32 boolean, correctly producing 0 for NaN, by
  // relying on the fact that "0.0 < abs(x)" is only false for NaN and 0.
  V<Word32> Float64ToBit(V<Float64> input) {
    return __ Float64LessThan(0.0, __ Float64Abs(input));
  }

  LazyDeoptOnThrow ShouldLazyDeoptOnThrow(maglev::NodeBase* node) {
    if (!node->properties().can_throw()) return LazyDeoptOnThrow::kNo;
    const maglev::ExceptionHandlerInfo* info = node->exception_handler_info();
    if (info->ShouldLazyDeopt()) return LazyDeoptOnThrow::kYes;
    return LazyDeoptOnThrow::kNo;
  }

  class ThrowingScope {
    // In Maglev, exception handlers have no predecessors, and their Phis are a
    // bit special: they all correspond to interpreter registers, and get
    // eventually initialized with the value that their predecessors have for
    // the corresponding interpreter registers.

    // In Turboshaft, exception handlers have predecessors and contain regular
    // phis. Creating a ThrowingScope takes care of recording in Variables
    // the current value of interpreter registers (right before emitting a node
    // that can throw), and sets the current_catch_block of the Assembler.
    // Throwing operations that are emitted while the scope is active will
    // automatically be wired to the catch handler. Then, when calling
    // Process(Phi) on exception phis (= when processing the catch handler),
    // these Phis will be mapped to the Variable corresponding to their owning
    // intepreter register.

   public:
    ThrowingScope(GraphBuildingNodeProcessor* builder,
                  maglev::NodeBase* throwing_node)
        : builder_(*builder) {
      DCHECK_EQ(__ current_catch_block(), nullptr);
      if (!throwing_node->properties().can_throw()) return;
      const maglev::ExceptionHandlerInfo* handler_info =
          throwing_node->exception_handler_info();
      if (!handler_info->HasExceptionHandler() ||
          handler_info->ShouldLazyDeopt()) {
        return;
      }

      catch_block_ = handler_info->catch_block.block_ptr();

      __ set_current_catch_block(builder_.Map(catch_block_));

      // We now need to prepare recording the inputs for the exception phis of
      // the catch handler.

      if (!catch_block_->has_phi()) {
        // Catch handler doesn't have any Phis, no need to do anything else.
        return;
      }

      const maglev::InterpretedDeoptFrame& interpreted_frame =
          throwing_node->lazy_deopt_info()->GetFrameForExceptionHandler(
              handler_info);
      const maglev::CompactInterpreterFrameState* compact_frame =
          interpreted_frame.frame_state();
      const maglev::MaglevCompilationUnit& maglev_unit =
          interpreted_frame.unit();

      builder_.IterCatchHandlerPhis(
          catch_block_, [this, compact_frame, maglev_unit](
                            interpreter::Register owner, Variable var) {
            DCHECK_NE(owner, interpreter::Register::virtual_accumulator());

            const maglev::ValueNode* maglev_value =
                compact_frame->GetValueOf(owner, maglev_unit);
            DCHECK_NOT_NULL(maglev_value);

            if (const maglev::VirtualObject* vobj =
                    maglev_value->TryCast<maglev::VirtualObject>()) {
              maglev_value = vobj->allocation();
            }

            V<Any> ts_value = builder_.Map(maglev_value);
            __ SetVariable(var, ts_value);
            builder_.RecordRepresentation(ts_value,
                                          maglev_value->value_representation());
          });
    }

    ~ThrowingScope() {
      // Resetting the catch handler. It is always set on a case-by-case basis
      // before emitting a throwing node, so there is no need to "reset the
      // previous catch handler" or something like that, since there is no
      // previous handler (there is a DCHECK in the ThrowingScope constructor
      // checking that the current_catch_block is indeed nullptr when the scope
      // is created).
      __ set_current_catch_block(nullptr);

      if (catch_block_ == nullptr) return;
      if (!catch_block_->has_phi()) return;

      // We clear the Variables that we've set when initializing the scope, in
      // order to avoid creating Phis for such Variables. These are really only
      // meant to be used when translating the Phis in the catch handler, and
      // when the scope is destroyed, we shouldn't be in the Catch handler yet.
      builder_.IterCatchHandlerPhis(
          catch_block_, [this](interpreter::Register, Variable var) {
            __ SetVariable(var, V<Object>::Invalid());
          });
    }

   private:
    GraphBuildingNodeProcessor::AssemblerT& Asm() { return builder_.Asm(); }
    GraphBuildingNodeProcessor& builder_;
    const maglev::BasicBlock* catch_block_ = nullptr;
  };

  class NoThrowingScopeRequired {
   public:
    explicit NoThrowingScopeRequired(maglev::NodeBase* node) {
      // If this DCHECK fails, then the caller should instead use a
      // ThrowingScope. Additionally, all of the calls it contains should
      // explicitely pass LazyDeoptOnThrow.
      DCHECK(!node->properties().can_throw());
    }
  };

  template <typename Function>
  void IterCatchHandlerPhis(const maglev::BasicBlock* catch_block,
                            Function&& callback) {
    DCHECK_NOT_NULL(catch_block);
    DCHECK(catch_block->has_phi());
    for (auto phi : *catch_block->phis()) {
      DCHECK(phi->is_exception_phi());
      interpreter::Register owner = phi->owner();
      if (owner == interpreter::Register::virtual_accumulator()) {
        // The accumulator exception phi corresponds to the exception object
        // rather than whatever value the accumulator contained before the
        // throwing operation. We don't need to iterate here, since there is
        // special handling when processing Phis to use `catch_block_begin_`
        // for it instead of a Variable.
        continue;
      }

      auto it = regs_to_vars_.find(owner.index());
      Variable var;
      if (it == regs_to_vars_.end()) {
        // We use a LoopInvariantVariable: if loop phis were needed, then the
        // Maglev value would already be a loop Phi, and we wouldn't need
        // Turboshaft to automatically insert a loop phi.
        var = __ NewLoopInvariantVariable(RegisterRepresentation::Tagged());
        regs_to_vars_.insert({owner.index(), var});
      } else {
        var = it->second;
      }

      callback(owner, var);
    }
  }

  OpIndex MapPhiInput(const maglev::Input input, int input_index) {
    return MapPhiInput(input.node(), input_index);
  }
  OpIndex MapPhiInput(const maglev::NodeBase* node, int input_index) {
    if (V8_UNLIKELY(node == maglev_generator_context_node_)) {
      OpIndex generator_context = __ GetVariable(generator_context_);
      if (__ current_block()->Contains(generator_context)) {
        DCHECK(!__ current_block()->IsLoop());
        DCHECK(__ output_graph().Get(generator_context).Is<PhiOp>());
        // If {generator_context} is a Phi defined in the current block and it's
        // used as input for another Phi, then we need to use it's value from
        // the correct predecessor, since a Phi can't be an input to another Phi
        // in the same block.
        return __ GetPredecessorValue(generator_context_, input_index);
      }
      return generator_context;
    }
    return Map(node);
  }

  template <typename T>
  V<T> Map(const maglev::Input input) {
    return V<T>::Cast(Map(input.node()));
  }
  OpIndex Map(const maglev::Input input) { return Map(input.node()); }
  OpIndex Map(const maglev::NodeBase* node) {
    if (V8_UNLIKELY(node == maglev_generator_context_node_)) {
      return __ GetVariable(generator_context_);
    }
    DCHECK(node_mapping_[node].valid());
    return node_mapping_[node];
  }
  Block* Map(const maglev::BasicBlock* block) { return block_mapping_[block]; }

  void SetMap(maglev::NodeBase* node, V<Any> idx) {
    DCHECK(idx.valid());
    DCHECK_EQ(__ output_graph().Get(idx).outputs_rep().size(), 1);
    node_mapping_[node] = idx;
  }

  void SetMapMaybeMultiReturn(maglev::NodeBase* node, V<Any> idx) {
    const Operation& op = __ output_graph().Get(idx);
    if (const TupleOp* tuple = op.TryCast<TupleOp>()) {
      // If the call returned multiple values, then in Maglev, {node} is
      // used as the 1st returned value, and a GetSecondReturnedValue node is
      // used to access the 2nd value. We thus call `SetMap` with the 1st
      // projection of the call, and record the 2nd projection in
      // {second_return_value_}, which we'll use when translating
      // GetSecondReturnedValue.
      DCHECK_EQ(tuple->input_count, 2);
      SetMap(node, tuple->input(0));
      second_return_value_ = tuple->input<Object>(1);
    } else {
      SetMap(node, idx);
    }
  }

  void RecordRepresentation(OpIndex idx, maglev::ValueRepresentation repr) {
    DCHECK_IMPLIES(maglev_representations_.contains(idx),
                   maglev_representations_[idx] == repr);
    maglev_representations_[idx] = repr;
  }

  V<NativeContext> native_context() {
    DCHECK(native_context_.valid());
    return native_context_;
  }

  PipelineData* data_;
  Zone* temp_zone_;
  Isolate* isolate_ = data_->isolate();
  LocalIsolate* local_isolate_ = isolate_->AsLocalIsolate();
  JSHeapBroker* broker_ = data_->broker();
  LocalFactory* local_factory_ = local_isolate_->factory();
  AssemblerT assembler_;
  maglev::MaglevCompilationUnit* maglev_compilation_unit_;
  ZoneUnorderedMap<const maglev::NodeBase*, OpIndex> node_mapping_;
  ZoneUnorderedMap<const maglev::BasicBlock*, Block*> block_mapping_;
  ZoneUnorderedMap<int, Variable> regs_to_vars_;

  // The {deduplicator_} is used when building frame states containing escaped
  // objects. It could be a local object in `BuildFrameState`, but it's instead
  // defined here to recycle its memory.
  Deduplicator deduplicator_;

  // In Turboshaft, exception blocks start with a CatchBlockBegin. In Maglev,
  // there is no such operation, and the exception is instead populated into the
  // accumulator by the throwing code, and is then loaded in Maglev through an
  // exception phi. When emitting a Turboshaft exception block, we thus store
  // the CatchBlockBegin in {catch_block_begin_}, which we then use when trying
  // to map the exception phi corresponding to the accumulator.
  V<Object> catch_block_begin_ = V<Object>::Invalid();

  // Maglev loops can have multiple forward edges, while Turboshaft should only
  // have a single one. When a Maglev loop has multiple forward edges, we create
  // an additional Turboshaft block before (which we record in
  // {loop_single_edge_predecessors_}), and jumps to the loop will instead go to
  // this additional block, which will become the only forward predecessor of
  // the loop.
  ZoneUnorderedMap<const maglev::BasicBlock*, Block*>
      loop_single_edge_predecessors_;
  // When we create an additional loop predecessor for loops that have multiple
  // forward predecessors, we store the newly created phis in
  // {loop_phis_first_input_}, so that we can then use them as the first input
  // of the original loop phis. {loop_phis_first_input_index_} is used as an
  // index in {loop_phis_first_input_} in VisitPhi so that we know where to find
  // the first input for the current loop phi.
  base::SmallVector<OpIndex, 16> loop_phis_first_input_;
  int loop_phis_first_input_index_ = -1;

  // Magle doesn't have projections. Instead, after nodes that return multiple
  // values (currently, only maglev::ForInPrepare and maglev::CallBuiltin for
  // some builtins), Maglev inserts a GetSecondReturnedValue node, which
  // basically just binds kReturnRegister1 to a ValueNode. In the
  // Maglev->Turboshaft translation, when we emit a builtin call with multiple
  // return values, we set {second_return_value_} to the 2nd projection, and
  // then use it when translating GetSecondReturnedValue.
  V<Object> second_return_value_ = V<Object>::Invalid();

  // {maglev_representations_} contains a map from Turboshaft OpIndex to
  // ValueRepresentation of the corresponding Maglev node. This is used when
  // translating exception phis: they might need to be re-tagged, and we need to
  // know the Maglev ValueRepresentation to distinguish between Float64 and
  // HoleyFloat64 (both of which would have Float64 RegisterRepresentation in
  // Turboshaft, but they need to be tagged differently).
  ZoneAbslFlatHashMap<OpIndex, maglev::ValueRepresentation>
      maglev_representations_;

  GeneratorAnalyzer generator_analyzer_;
  static constexpr int kDefaultSwitchVarValue = -1;
  // {is_visiting_generator_main_switch_} is true if the function is a resumable
  // generator, and the current input block is the main dispatch switch for
  // resuming the generator.
  bool is_visiting_generator_main_switch_ = false;
  // {on_generator_switch_loop_} is true if the current input block is a loop
  // that used to be bypassed by generator resumes, and thus that needs a
  // secondary generator dispatch switch.
  bool on_generator_switch_loop_ = false;
  // {header_switch_input_} is the value on which secondary generator switches
  // should switch.
  Variable header_switch_input_;
  // When secondary dispatch switches for generators are created,
  // {loop_default_generator_value_} is used as the default inputs for
  // {header_switch_input_} for edges that weren't manually inserted in the
  // translation for generators.
  V<Word32> loop_default_generator_value_ = V<Word32>::Invalid();
  // If the main generator switch bypasses some loop headers, we'll need to
  // add an additional predecessor to these loop headers to get rid of the
  // bypass. If we do so, we'll need a dummy input for the loop Phis, which
  // we create here.
  V<Object> dummy_object_input_ = V<Object>::Invalid();
  V<Word32> dummy_word32_input_ = V<Word32>::Invalid();
  V<Float64> dummy_float64_input_ = V<Float64>::Invalid();
  // {maglev_generator_context_node_} is the 1st Maglev node that load the
  // context from the generator. Because of the removal of loop header bypasses,
  // we can end up using this node in place that's not dominated by the block
  // defining this node. To fix this problem, when loading the context from the
  // generator for the 1st time, we set {generator_context_}, and in `Map`, we
  // always check whether we're trying to get the generator context (=
  // {maglev_generator_context_node_}): if so, then we get the value from
  // {generator_context_} instead. Note that {generator_context_} is initialized
  // with a dummy value (NoContextConstant) so that valid Phis get inserted
  // where needed, but by construction, we'll never actually use this dummy
  // value.
  maglev::NodeBase* maglev_generator_context_node_ = nullptr;
  Variable generator_context_;

  struct GeneratorSplitEdge {
    Block* pre_loop_dst;
    Block* inside_loop_target;
    int switch_value;
  };
  std::unordered_map<const maglev::BasicBlock*, std::vector<GeneratorSplitEdge>>
      pre_loop_generator_blocks_;

  V<NativeContext> native_context_ = V<NativeContext>::Invalid();
  V<Object> new_target_param_ = V<Object>::Invalid();
  base::SmallVector<int, 16> predecessor_permutation_;

  std::optional<BailoutReason>* bailout_;
};

// A wrapper around GraphBuildingNodeProcessor that takes care of
//  - skipping nodes when we are in Unreachable code.
//  - recording source positions.
class NodeProcessorBase : public GraphBuildingNodeProcessor {
 public:
  using GraphBuildingNodeProcessor::GraphBuildingNodeProcessor;

  NodeProcessorBase(PipelineData* data, Graph& graph, Zone* temp_zone,
                    maglev::MaglevCompilationUnit* maglev_compilation_unit,
                    std::optional<BailoutReason>* bailout)
      : GraphBuildingNodeProcessor(data, graph, temp_zone,
                                   maglev_compilation_unit, bailout),
        graph_(graph),
        labeller_(maglev_compilation_unit->graph_labeller()) {}

  template <typename NodeT>
  maglev::ProcessResult Process(NodeT* node,
                                const maglev::ProcessingState& state) {
    if (GraphBuildingNodeProcessor::Asm().generating_unreachable_operations()) {
      // It doesn't matter much whether we return kRemove or kContinue here,
      // since we'll be done with the Maglev graph anyway once this phase is
      // over. Maglev currently doesn't support kRemove for control nodes, so we
      // just return kContinue for simplicity.
      return maglev::ProcessResult::kContinue;
    }

    OpIndex end_index_before = graph_.EndIndex();
    maglev::ProcessResult result =
        GraphBuildingNodeProcessor::Process(node, state);

    // Recording the SourcePositions of the OpIndex that were just created.
    SourcePosition source = labeller_->GetNodeProvenance(node).position;
    for (OpIndex idx = end_index_before; idx != graph_.EndIndex();
         idx = graph_.NextIndex(idx)) {
      graph_.source_positions()[idx] = source;
    }

    return result;
  }

 private:
  Graph& graph_;
  maglev::MaglevGraphLabeller* labeller_;
};

void PrintBytecode(PipelineData& data,
                   maglev::MaglevCompilationInfo* compilation_info) {
  DCHECK(data.info()->trace_turbo_graph());
  maglev::MaglevCompilationUnit* top_level_unit =
      compilation_info->toplevel_compilation_unit();
  CodeTracer* code_tracer = data.GetCodeTracer();
  CodeTracer::StreamScope tracing_scope(code_tracer);
  tracing_scope.stream()
      << "\n----- Bytecode before MaglevGraphBuilding -----\n"
      << std::endl;
  tracing_scope.stream() << "Function: "
                         << Brief(*compilation_info->toplevel_function())
                         << std::endl;
  BytecodeArray::Disassemble(top_level_unit->bytecode().object(),
                             tracing_scope.stream());
  Print(*top_level_unit->feedback().object(), tracing_scope.stream());
}

void PrintMaglevGraph(PipelineData& data,
                      maglev::MaglevCompilationInfo* compilation_info,
                      maglev::Graph* maglev_graph, const char* msg) {
  CodeTracer* code_tracer = data.GetCodeTracer();
  CodeTracer::StreamScope tracing_scope(code_tracer);
  tracing_scope.stream() << "\n----- " << msg << " -----" << std::endl;
  maglev::PrintGraph(tracing_scope.stream(), compilation_info, maglev_graph);
}

// TODO(dmercadier, nicohartmann): consider doing some of these optimizations on
// the Turboshaft graph after the Maglev->Turboshaft translation. For instance,
// MaglevPhiRepresentationSelector is the Maglev equivalent of Turbofan's
// SimplifiedLowering, but is much less powerful (doesn't take truncations into
// account, doesn't do proper range analysis, doesn't run a fixpoint
// analysis...).
void RunMaglevOptimizations(PipelineData* data,
                            maglev::MaglevCompilationInfo* compilation_info,
                            maglev::MaglevGraphBuilder& maglev_graph_builder,
                            maglev::Graph* maglev_graph) {
  // Phi untagging.
  {
    maglev::GraphProcessor<maglev::MaglevPhiRepresentationSelector> processor(
        &maglev_graph_builder);
    processor.ProcessGraph(maglev_graph);
  }

  if (V8_UNLIKELY(data->
```