Response: The user wants me to summarize the functionality of the C++ code provided. This is the third part of a five-part series. The code seems to be related to processing different kinds of nodes within a compiler's intermediate representation, likely for a JavaScript engine (given the file path and the mentions of JavaScript concepts).

I need to:
1. **Identify the core functionality** of this specific code block.
2. **Explain the connection to JavaScript** using a simple example if possible.
3. **Acknowledge that this is the third part** of a larger process and its function might be dependent on the preceding and succeeding parts.

Based on the code, this part seems to handle nodes related to:
- **Memory operations**: Loading and storing values in memory, dealing with different data types and write barriers.
- **Type checks and conversions**: Checking the type of JavaScript values and converting between them (e.g., to boolean, number).
- **Control flow**: Implementing jumps, branches, and switches based on conditions.
- **Arithmetic and logical operations**: Performing integer and floating-point arithmetic, bitwise operations, comparisons, and logical negation.
- **Specific JavaScript features**: Operations related to typed arrays, DataViews, and enumeration.

The code iterates through different Maglev nodes and translates them into corresponding Turboshaft operations.
这是 `v8/src/compiler/turboshaft/maglev-graph-building-phase.cc` 文件的第三部分，主要负责将 Maglev 图中的节点（中间表示形式）转换为 Turboshaft 图中的节点。Turboshaft 是 V8 引擎中更底层的、更接近机器码的中间表示。

**主要功能归纳：**

这部分代码定义了 `MaglevGraphBuildingPhase` 类的 `Process` 方法的多个重载版本。每个重载版本对应处理一种特定的 Maglev 节点类型。这些方法会将 Maglev 节点所代表的操作转换为一系列 Turboshaft 指令。

具体来说，这部分代码处理了以下 Maglev 节点类型，可以大致分为以下几类：

1. **内存操作 (Memory Operations):**
    *   `StoreField`、`StoreDoubleField`、`StoreTrustedPointerFieldWithWriteBarrier`、`StoreFixedArrayElementNoWriteBarrier`、`StoreFixedArrayElementWithWriteBarrier`、`StoreFixedDoubleArrayElement`、`StoreMap`、`StoreFloat64`:  这些节点负责将值存储到对象的属性或数组元素中，并处理可能的写屏障（Write Barrier），以维护垃圾回收机制的正确性。
    *   `LoadField`、`LoadTaggedField`：从对象的属性中加载值。

2. **控制流 (Control Flow):**
    *   `Jump`、`CheckpointedJump`：无条件跳转到目标代码块。
    *   `JumpLoop`：跳转到循环的头部，并处理循环变量的更新。
    *   `Int32Compare`、`Float64Compare`、`TaggedEqual`、`TaggedNotEqual`：执行比较操作，并将结果转换为 JavaScript 布尔值。
    *   `BranchIfToBooleanTrue`、`BranchIfInt32Compare`、`BranchIfUint32Compare`、`BranchIfFloat64Compare`、`BranchIfInt32ToBooleanTrue`、`BranchIfFloat64ToBooleanTrue`、`BranchIfFloat64IsHole`、`BranchIfReferenceEqual`、`BranchIfRootConstant`、`BranchIfUndefinedOrNull`、`BranchIfUndetectable`、`BranchIfSmi`、`BranchIfJSReceiver`：基于条件执行分支跳转。
    *   `Switch`：实现多路分支选择结构。

3. **类型检查与转换 (Type Checks and Conversions):**
    *   `TestUndetectable`、`TestTypeOf`：检查对象的类型。
    *   `CheckDetectableCallable`：检查对象是否是可调用的。
    *   `CheckedSmiUntag`、`UnsafeSmiUntag`、`CheckedSmiTagInt32`、`CheckedSmiTagUint32`、`CheckedSmiTagFloat64`、`UnsafeSmiTagInt32`、`UnsafeSmiTagUint32`：处理 Smi (Small Integer) 类型的转换，包括检查溢出。
    *   `ToBoolean`、`Int32ToBoolean`、`Float64ToBoolean`：将值转换为 JavaScript 布尔值。
    *   `Int32ToNumber`、`Uint32ToNumber`、`Float64ToTagged`、`HoleyFloat64ToTagged`、`Float64ToHeapNumberForField`：将数值类型转换为 JavaScript Number 对象。
    *   `CheckedNumberOrOddballToFloat64`、`CheckedNumberOrOddballToHoleyFloat64`、`UncheckedNumberOrOddballToFloat64`：将 Number 或 Oddball 类型转换为 Float64。
    *   `TruncateUint32ToInt32`、`CheckedInt32ToUint32`、`CheckedUint32ToInt32`、`UnsafeInt32ToUint32`：处理整数类型的截断和转换。
    *   `CheckedObjectToIndex`：将对象转换为数组索引。
    *   `ChangeInt32ToFloat64`、`ChangeUint32ToFloat64`：将整数转换为浮点数。
    *   `CheckedTruncateFloat64ToInt32`、`CheckedTruncateFloat64ToUint32`、`CheckedTruncateNumberOrOddballToInt32`、`TruncateNumberOrOddballToInt32`、`TruncateFloat64ToInt32`：将浮点数或 Number 类型截断为整数。
    *   `ConvertHoleToUndefined`：将 "hole" 值转换为 `undefined`。
    *   `ConvertReceiver`：转换函数调用的接收者（`this` 值）。

4. **算术与逻辑运算 (Arithmetic and Logical Operations):**
    *   `Int32AddWithOverflow`、`Int32SubtractWithOverflow`、`Int32MultiplyWithOverflow`、`Int32DivideWithOverflow`、`Int32ModulusWithOverflow`、`Int32IncrementWithOverflow`、`Int32DecrementWithOverflow`、`Int32NegateWithOverflow`：执行带溢出检查的 32 位整数算术运算。
    *   `Float64Add`、`Float64Subtract`、`Float64Multiply`、`Float64Divide`、`Float64Modulus`、`Float64Exponentiate`、`Float64Negate`、`Float64Abs`、`Float64Round`、`Float64Ieee754Unary`: 执行 64 位浮点数算术运算和 IEEE 754 标准的运算。
    *   `Int32BitwiseAnd`、`Int32BitwiseOr`、`Int32BitwiseXor`、`Int32ShiftLeft`、`Int32ShiftRight`、`Int32ShiftRightLogical`、`Int32BitwiseNot`、`Int32AbsWithOverflow`: 执行 32 位整数的位运算。
    *   `CheckedSmiIncrement`、`CheckedSmiDecrement`: 执行带溢出检查的 Smi 类型的加减运算。
    *   `LogicalNot`、`ToBooleanLogicalNot`: 执行逻辑非运算。

5. **特定 JavaScript 功能 (Specific JavaScript Features):**
    *   **For-in 循环相关:** `LoadEnumCacheLength`、`CheckCacheIndicesNotCleared`、`LoadTaggedFieldByFieldIndex`：处理 `for...in` 循环中的枚举操作。
    *   **Typed Arrays 和 DataViews 相关:** `LoadTypedArrayLength`、`CheckTypedArrayBounds`、`LoadUnsignedIntTypedArrayElement`、`LoadSignedIntTypedArrayElement`、`LoadDoubleTypedArrayElement`、`StoreIntTypedArrayElement`、`StoreDoubleTypedArrayElement`、`CheckJSDataViewBounds`、`LoadSignedIntDataViewElement`、`LoadDoubleDataViewElement`、`StoreSignedIntDataViewElement`、`StoreDoubleDataViewElement`、`CheckTypedArrayNotDetached`：处理类型化数组和 DataView 的操作，包括边界检查和元素访问。
    *   **Generic 运算:** `GenericAdd`、`GenericSubtract` 等：处理需要调用运行时系统的通用算术和逻辑运算，通常用于处理非优化的情况或需要特殊处理的情况。
    *   `ToNumberOrNumeric`: 将值转换为 Number 或 BigInt 类型。
    *   `HoleyFloat64IsHole`、`HoleyFloat64ToMaybeNanFloat64`、`CheckedHoleyFloat64ToFloat64`: 处理可能包含 "hole" 值的浮点数。
    *   `Int32ToUint8Clamped`、`Uint32ToUint8Clamped`: 将整数转换为 8 位无符号整数并进行 clamped 处理（限制在 0-255 范围内）。

**与 JavaScript 功能的关系及示例：**

这段 C++ 代码是 JavaScript 引擎内部的实现细节，它负责将高级的 JavaScript 代码转换成更底层的指令。每一种 Maglev 节点都对应着某种 JavaScript 操作或概念。

例如：

*   **`Process(maglev::StoreField* node, ...)`**  与 JavaScript 的对象属性赋值操作相关：

    ```javascript
    let obj = {};
    obj.property = 10; //  在引擎内部，可能会生成一个 StoreField 节点
    ```

*   **`Process(maglev::Int32AddWithOverflow* node, ...)`** 与 JavaScript 的整数加法运算相关，并且会检查是否发生溢出：

    ```javascript
    let a = 2147483647; // 32位有符号整数的最大值
    let b = 1;
    let sum = a + b; //  在引擎内部，如果启用溢出检查，可能会生成 Int32AddWithOverflow 节点
    ```

*   **`Process(maglev::BranchIfToBooleanTrue* node, ...)`** 与 JavaScript 的条件语句或逻辑运算相关：

    ```javascript
    let x = 5;
    if (x) { //  在引擎内部，会检查 x 的真值，并可能生成 BranchIfToBooleanTrue 节点
        console.log("x is truthy");
    }
    ```

**作为第 3 部分的意义：**

由于这是第 3 部分，可以推断：

*   **前面部分 (第 1 和 2 部分)** 可能负责 Maglev 图的构建，或者进行一些预处理和准备工作。
*   **后面部分 (第 4 和 5 部分)** 可能会涉及 Turboshaft 图的进一步优化、代码生成或与后端执行引擎的交互。

因此，这第 3 部分是连接 Maglev 这种相对高层的中间表示和 Turboshaft 这种更底层的中间表示的关键桥梁。它将 JavaScript 的语义转换为更接近机器执行的指令序列。

Prompt: 
```
这是目录为v8/src/compiler/turboshaft/maglev-graph-building-phase.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共5部分，请归纳一下它的功能

"""
    MemoryRepresentation::AnyTagged(),
               WriteBarrierKind::kFullWriteBarrier, node->offset(), false);
    }
    GOTO(done);
    BIND(done);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StoreDoubleField* node,
                                const maglev::ProcessingState& state) {
    V<HeapNumber> field = __ LoadTaggedField<HeapNumber>(
        Map(node->object_input()), node->offset());
    __ StoreField(field, AccessBuilder::ForHeapNumberValue(),
                  Map(node->value_input()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(
      maglev::StoreTrustedPointerFieldWithWriteBarrier* node,
      const maglev::ProcessingState& state) {
    __ Store(Map(node->object_input()), Map(node->value_input()),
             StoreOp::Kind::TaggedBase(),
             MemoryRepresentation::IndirectPointer(),
             WriteBarrierKind::kIndirectPointerWriteBarrier, node->offset(),
             node->initializing_or_transitioning(), node->tag());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(
      maglev::StoreFixedArrayElementNoWriteBarrier* node,
      const maglev::ProcessingState& state) {
    __ StoreFixedArrayElement(Map(node->elements_input()),
                              __ ChangeInt32ToIntPtr(Map(node->index_input())),
                              Map(node->value_input()),
                              WriteBarrierKind::kNoWriteBarrier);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(
      maglev::StoreFixedArrayElementWithWriteBarrier* node,
      const maglev::ProcessingState& state) {
    __ StoreFixedArrayElement(Map(node->elements_input()),
                              __ ChangeInt32ToIntPtr(Map(node->index_input())),
                              Map(node->value_input()),
                              WriteBarrierKind::kFullWriteBarrier);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StoreFixedDoubleArrayElement* node,
                                const maglev::ProcessingState& state) {
    __ StoreFixedDoubleArrayElement(
        Map(node->elements_input()),
        __ ChangeInt32ToIntPtr(Map(node->index_input())),
        Map(node->value_input()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StoreMap* node,
                                const maglev::ProcessingState& state) {
    __ Store(Map(node->object_input()), __ HeapConstant(node->map().object()),
             StoreOp::Kind::TaggedBase(), MemoryRepresentation::TaggedPointer(),
             WriteBarrierKind::kMapWriteBarrier, HeapObject::kMapOffset,
             /*maybe_initializing_or_transitioning*/ true);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StoreFloat64* node,
                                const maglev::ProcessingState& state) {
    __ Store(Map(node->object_input()), Map(node->value_input()),
             StoreOp::Kind::TaggedBase(), MemoryRepresentation::Float64(),
             WriteBarrierKind::kNoWriteBarrier, node->offset());
    return maglev::ProcessResult::kContinue;
  }

  // For-in specific operations.
  maglev::ProcessResult Process(maglev::LoadEnumCacheLength* node,
                                const maglev::ProcessingState& state) {
    V<Word32> bitfield3 =
        __ LoadField<Word32>(V<i::Map>::Cast(Map(node->map_input())),
                             AccessBuilder::ForMapBitField3());
    V<Word32> length = __ Word32ShiftRightLogical(
        __ Word32BitwiseAnd(bitfield3, Map::Bits3::EnumLengthBits::kMask),
        Map::Bits3::EnumLengthBits::kShift);
    SetMap(node, length);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckCacheIndicesNotCleared* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    // If the cache length is zero, we don't have any indices, so we know this
    // is ok even though the indices are the empty array.
    IF_NOT (__ Word32Equal(Map(node->length_input()), 0)) {
      // Otherwise, an empty array with non-zero required length is not valid.
      V<Word32> condition =
          RootEqual(node->indices_input(), RootIndex::kEmptyFixedArray);
      __ DeoptimizeIf(condition, frame_state,
                      DeoptimizeReason::kWrongEnumIndices,
                      node->eager_deopt_info()->feedback_to_update());
    }
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadTaggedFieldByFieldIndex* node,
                                const maglev::ProcessingState& state) {
    SetMap(node,
           __ LoadFieldByIndex(Map(node->object_input()),
                               __ UntagSmi(Map<Smi>(node->index_input()))));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::LoadTypedArrayLength* node,
                                const maglev::ProcessingState& state) {
    // TODO(dmercadier): consider loading the raw length instead of the byte
    // length. This is not currently done because the raw length field might be
    // removed soon.
    V<WordPtr> length =
        __ LoadField<WordPtr>(Map<JSTypedArray>(node->receiver_input()),
                              AccessBuilder::ForJSTypedArrayByteLength());

    int element_size = ElementsKindSize(node->elements_kind());
    if (element_size > 1) {
      DCHECK(element_size == 2 || element_size == 4 || element_size == 8);
      length = __ WordPtrShiftRightLogical(
          length, base::bits::CountTrailingZeros(element_size));
    }
    SetMap(node, length);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckTypedArrayBounds* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIfNot(
        __ UintPtrLessThan(__ ChangeUint32ToUintPtr(Map(node->index_input())),
                           Map(node->length_input())),
        frame_state, DeoptimizeReason::kOutOfBounds,
        node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::LoadUnsignedIntTypedArrayElement* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, BuildTypedArrayLoad(Map<JSTypedArray>(node->object_input()),
                                     Map<Word32>(node->index_input()),
                                     node->elements_kind()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadSignedIntTypedArrayElement* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, BuildTypedArrayLoad(Map<JSTypedArray>(node->object_input()),
                                     Map<Word32>(node->index_input()),
                                     node->elements_kind()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadDoubleTypedArrayElement* node,
                                const maglev::ProcessingState& state) {
    DCHECK_EQ(node->elements_kind(),
              any_of(FLOAT32_ELEMENTS, FLOAT64_ELEMENTS));
    V<Float> value = V<Float>::Cast(BuildTypedArrayLoad(
        Map<JSTypedArray>(node->object_input()),
        Map<Word32>(node->index_input()), node->elements_kind()));
    if (node->elements_kind() == FLOAT32_ELEMENTS) {
      value = __ ChangeFloat32ToFloat64(V<Float32>::Cast(value));
    }
    SetMap(node, value);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::StoreIntTypedArrayElement* node,
                                const maglev::ProcessingState& state) {
    BuildTypedArrayStore(Map<JSTypedArray>(node->object_input()),
                         Map<Word32>(node->index_input()),
                         Map<Untagged>(node->value_input()),
                         node->elements_kind());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StoreDoubleTypedArrayElement* node,
                                const maglev::ProcessingState& state) {
    DCHECK_EQ(node->elements_kind(),
              any_of(FLOAT32_ELEMENTS, FLOAT64_ELEMENTS));
    V<Float> value = Map<Float>(node->value_input());
    if (node->elements_kind() == FLOAT32_ELEMENTS) {
      value = __ TruncateFloat64ToFloat32(Map(node->value_input()));
    }
    BuildTypedArrayStore(Map<JSTypedArray>(node->object_input()),
                         Map<Word32>(node->index_input()), value,
                         node->elements_kind());
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CheckJSDataViewBounds* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    // Normal DataView (backed by AB / SAB) or non-length tracking backed by
    // GSAB.
    V<WordPtr> byte_length =
        __ LoadField<WordPtr>(Map<JSTypedArray>(node->receiver_input()),
                              AccessBuilder::ForJSDataViewByteLength());

    int element_size = ExternalArrayElementSize(node->element_type());
    if (element_size > 1) {
      // For element_size larger than 1, we need to make sure that {index} is
      // less than {byte_length}, but also that {index+element_size} is less
      // than {byte_length}. We do this by subtracting {element_size-1} from
      // {byte_length}: if the resulting length is greater than 0, then we can
      // just treat {element_size} as 1 and check if {index} is less than this
      // new {byte_length}.
      DCHECK(element_size == 2 || element_size == 4 || element_size == 8);
      byte_length = __ WordPtrSub(byte_length, element_size - 1);
      __ DeoptimizeIf(__ IntPtrLessThan(byte_length, 0), frame_state,
                      DeoptimizeReason::kOutOfBounds,
                      node->eager_deopt_info()->feedback_to_update());
    }
    __ DeoptimizeIfNot(
        __ Uint32LessThan(Map<Word32>(node->index_input()),
                          __ TruncateWordPtrToWord32(byte_length)),
        frame_state, DeoptimizeReason::kOutOfBounds,
        node->eager_deopt_info()->feedback_to_update());
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::LoadSignedIntDataViewElement* node,
                                const maglev::ProcessingState& state) {
    V<JSDataView> data_view = Map<JSDataView>(node->object_input());
    V<WordPtr> storage = __ LoadField<WordPtr>(
        data_view, AccessBuilder::ForJSDataViewDataPointer());
    V<Word32> is_little_endian =
        ToBit(node->is_little_endian_input(),
              TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kObject);
    SetMap(node, __ LoadDataViewElement(
                     data_view, storage,
                     __ ChangeUint32ToUintPtr(Map<Word32>(node->index_input())),
                     is_little_endian, node->type()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::LoadDoubleDataViewElement* node,
                                const maglev::ProcessingState& state) {
    V<JSDataView> data_view = Map<JSDataView>(node->object_input());
    V<WordPtr> storage = __ LoadField<WordPtr>(
        data_view, AccessBuilder::ForJSDataViewDataPointer());
    V<Word32> is_little_endian =
        ToBit(node->is_little_endian_input(),
              TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kObject);
    SetMap(node,
           __ LoadDataViewElement(
               data_view, storage,
               __ ChangeUint32ToUintPtr(Map<Word32>(node->index_input())),
               is_little_endian, ExternalArrayType::kExternalFloat64Array));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::StoreSignedIntDataViewElement* node,
                                const maglev::ProcessingState& state) {
    V<JSDataView> data_view = Map<JSDataView>(node->object_input());
    V<WordPtr> storage = __ LoadField<WordPtr>(
        data_view, AccessBuilder::ForJSDataViewDataPointer());
    V<Word32> is_little_endian =
        ToBit(node->is_little_endian_input(),
              TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kObject);
    __ StoreDataViewElement(
        data_view, storage,
        __ ChangeUint32ToUintPtr(Map<Word32>(node->index_input())),
        Map<Word32>(node->value_input()), is_little_endian, node->type());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::StoreDoubleDataViewElement* node,
                                const maglev::ProcessingState& state) {
    V<JSDataView> data_view = Map<JSDataView>(node->object_input());
    V<WordPtr> storage = __ LoadField<WordPtr>(
        data_view, AccessBuilder::ForJSDataViewDataPointer());
    V<Word32> is_little_endian =
        ToBit(node->is_little_endian_input(),
              TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kObject);
    __ StoreDataViewElement(
        data_view, storage,
        __ ChangeUint32ToUintPtr(Map<Word32>(node->index_input())),
        Map<Float64>(node->value_input()), is_little_endian,
        ExternalArrayType::kExternalFloat64Array);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CheckTypedArrayNotDetached* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIf(
        __ ArrayBufferIsDetached(Map<JSArrayBufferView>(node->object_input())),
        frame_state, DeoptimizeReason::kArrayBufferWasDetached,
        node->eager_deopt_info()->feedback_to_update());

    return maglev::ProcessResult::kContinue;
  }

  void BuildJump(maglev::BasicBlock* target) {
    Block* destination = Map(target);
    if (target->is_loop() && (target->predecessor_count() > 2 ||
                              generator_analyzer_.HeaderIsBypassed(target))) {
      // This loop has multiple forward edges in Maglev, so we'll create an
      // extra block in Turboshaft that will be the only predecessor.
      auto it = loop_single_edge_predecessors_.find(target);
      if (it != loop_single_edge_predecessors_.end()) {
        destination = it->second;
      } else {
        Block* loop_only_pred = __ NewBlock();
        loop_single_edge_predecessors_[target] = loop_only_pred;
        destination = loop_only_pred;
      }
    }
    __ Goto(destination);
  }

  maglev::ProcessResult Process(maglev::Jump* node,
                                const maglev::ProcessingState& state) {
    BuildJump(node->target());
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckpointedJump* node,
                                const maglev::ProcessingState& state) {
    BuildJump(node->target());
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::JumpLoop* node,
                                const maglev::ProcessingState& state) {
    if (header_switch_input_.valid()) {
      __ SetVariable(header_switch_input_, loop_default_generator_value_);
    }
    __ Goto(Map(node->target()));
    FixLoopPhis(node->target());
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Int32Compare* node,
                                const maglev::ProcessingState& state) {
    V<Word32> bool_res =
        ConvertCompare<Word32>(node->left_input(), node->right_input(),
                               node->operation(), Sign::kSigned);
    SetMap(node, ConvertWord32ToJSBool(bool_res));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Float64Compare* node,
                                const maglev::ProcessingState& state) {
    V<Word32> bool_res =
        ConvertCompare<Float64>(node->left_input(), node->right_input(),
                                node->operation(), Sign::kSigned);
    SetMap(node, ConvertWord32ToJSBool(bool_res));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TaggedEqual* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, ConvertWord32ToJSBool(
                     __ TaggedEqual(Map(node->lhs()), Map(node->rhs()))));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TaggedNotEqual* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, ConvertWord32ToJSBool(
                     __ TaggedEqual(Map(node->lhs()), Map(node->rhs())),
                     /*flip*/ true));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TestUndetectable* node,
                                const maglev::ProcessingState& state) {
    ObjectIsOp::InputAssumptions assumption;
    switch (node->check_type()) {
      case maglev::CheckType::kCheckHeapObject:
        assumption = ObjectIsOp::InputAssumptions::kNone;
        break;
      case maglev::CheckType::kOmitHeapObjectCheck:
        assumption = ObjectIsOp::InputAssumptions::kHeapObject;
        break;
    }
    SetMap(node, ConvertWord32ToJSBool(
                     __ ObjectIs(Map(node->value()),
                                 ObjectIsOp::Kind::kUndetectable, assumption)));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TestTypeOf* node,
                                const maglev::ProcessingState& state) {
    V<Object> input = Map(node->value());
    V<Boolean> result;
    switch (node->literal()) {
      case interpreter::TestTypeOfFlags::LiteralFlag::kNumber:
        result = ConvertWord32ToJSBool(
            __ ObjectIs(input, ObjectIsOp::Kind::kNumber,
                        ObjectIsOp::InputAssumptions::kNone));
        break;
      case interpreter::TestTypeOfFlags::LiteralFlag::kString:
        result = ConvertWord32ToJSBool(
            __ ObjectIs(input, ObjectIsOp::Kind::kString,
                        ObjectIsOp::InputAssumptions::kNone));
        break;
      case interpreter::TestTypeOfFlags::LiteralFlag::kSymbol:
        result = ConvertWord32ToJSBool(
            __ ObjectIs(input, ObjectIsOp::Kind::kSymbol,
                        ObjectIsOp::InputAssumptions::kNone));
        break;
      case interpreter::TestTypeOfFlags::LiteralFlag::kBigInt:
        result = ConvertWord32ToJSBool(
            __ ObjectIs(input, ObjectIsOp::Kind::kBigInt,
                        ObjectIsOp::InputAssumptions::kNone));
        break;
      case interpreter::TestTypeOfFlags::LiteralFlag::kFunction:
        result = ConvertWord32ToJSBool(
            __ ObjectIs(input, ObjectIsOp::Kind::kDetectableCallable,
                        ObjectIsOp::InputAssumptions::kNone));
        break;
      case interpreter::TestTypeOfFlags::LiteralFlag::kBoolean:
        result = __ Select(__ RootEqual(input, RootIndex::kTrueValue, isolate_),
                           __ HeapConstant(local_factory_->true_value()),
                           ConvertWord32ToJSBool(__ RootEqual(
                               input, RootIndex::kFalseValue, isolate_)),
                           RegisterRepresentation::Tagged(), BranchHint::kNone,
                           SelectOp::Implementation::kBranch);
        break;
      case interpreter::TestTypeOfFlags::LiteralFlag::kUndefined:
        result = __ Select(__ RootEqual(input, RootIndex::kNullValue, isolate_),
                           __ HeapConstant(local_factory_->false_value()),
                           ConvertWord32ToJSBool(__ ObjectIs(
                               input, ObjectIsOp::Kind::kUndetectable,
                               ObjectIsOp::InputAssumptions::kNone)),
                           RegisterRepresentation::Tagged(), BranchHint::kNone,
                           SelectOp::Implementation::kBranch);
        break;
      case interpreter::TestTypeOfFlags::LiteralFlag::kObject:
        result = __ Select(__ ObjectIs(input, ObjectIsOp::Kind::kNonCallable,
                                       ObjectIsOp::InputAssumptions::kNone),
                           __ HeapConstant(local_factory_->true_value()),
                           ConvertWord32ToJSBool(__ RootEqual(
                               input, RootIndex::kNullValue, isolate_)),
                           RegisterRepresentation::Tagged(), BranchHint::kNone,
                           SelectOp::Implementation::kBranch);
        break;
      case interpreter::TestTypeOfFlags::LiteralFlag::kOther:
        UNREACHABLE();  // Should never be emitted.
    }

    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CheckDetectableCallable* node,
                                const maglev::ProcessingState& state) {
    V<Object> receiver = Map(node->receiver_input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());

    ObjectIsOp::InputAssumptions assumptions;
    switch (node->check_type()) {
      case maglev::CheckType::kCheckHeapObject:
        assumptions = ObjectIsOp::InputAssumptions::kNone;
        break;
      case maglev::CheckType::kOmitHeapObjectCheck:
        assumptions = ObjectIsOp::InputAssumptions::kHeapObject;
        break;
    }

    __ DeoptimizeIfNot(
        __ ObjectIs(receiver, ObjectIsOp::Kind::kDetectableCallable,
                    assumptions),
        frame_state, DeoptimizeReason::kNotDetectableReceiver,
        node->eager_deopt_info()->feedback_to_update());

    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::BranchIfToBooleanTrue* node,
                                const maglev::ProcessingState& state) {
    TruncateJSPrimitiveToUntaggedOp::InputAssumptions assumption =
        node->check_type() == maglev::CheckType::kCheckHeapObject
            ? TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kObject
            : TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kHeapObject;
    V<Word32> condition = ToBit(node->condition_input(), assumption);
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfInt32Compare* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition =
        ConvertCompare<Word32>(node->left_input(), node->right_input(),
                               node->operation(), Sign::kSigned);
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfUint32Compare* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition =
        ConvertCompare<Word32>(node->left_input(), node->right_input(),
                               node->operation(), Sign::kUnsigned);
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfFloat64Compare* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition =
        ConvertCompare<Float64>(node->left_input(), node->right_input(),
                                node->operation(), Sign::kSigned);
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfInt32ToBooleanTrue* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition = Map(node->condition_input());
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfFloat64ToBooleanTrue* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition = Float64ToBit(Map(node->condition_input()));
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfFloat64IsHole* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition = __ Float64IsHole(Map(node->condition_input()));
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfReferenceEqual* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition =
        __ TaggedEqual(Map(node->left_input()), Map(node->right_input()));
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfRootConstant* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition =
        RootEqual(node->condition_input(), node->root_index());
    __ Branch(condition, Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfUndefinedOrNull* node,
                                const maglev::ProcessingState& state) {
    __ GotoIf(RootEqual(node->condition_input(), RootIndex::kUndefinedValue),
              Map(node->if_true()));
    __ Branch(RootEqual(node->condition_input(), RootIndex::kNullValue),
              Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfUndetectable* node,
                                const maglev::ProcessingState& state) {
    ObjectIsOp::InputAssumptions assumption;
    switch (node->check_type()) {
      case maglev::CheckType::kCheckHeapObject:
        assumption = ObjectIsOp::InputAssumptions::kNone;
        break;
      case maglev::CheckType::kOmitHeapObjectCheck:
        assumption = ObjectIsOp::InputAssumptions::kHeapObject;
        break;
    }
    __ Branch(__ ObjectIs(Map(node->condition_input()),
                          ObjectIsOp::Kind::kUndetectable, assumption),
              Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfSmi* node,
                                const maglev::ProcessingState& state) {
    __ Branch(__ IsSmi(Map(node->condition_input())), Map(node->if_true()),
              Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::BranchIfJSReceiver* node,
                                const maglev::ProcessingState& state) {
    __ GotoIf(__ IsSmi(Map(node->condition_input())), Map(node->if_false()));
    __ Branch(__ JSAnyIsNotPrimitive(Map(node->condition_input())),
              Map(node->if_true()), Map(node->if_false()));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Switch* node,
                                const maglev::ProcessingState& state) {
    if (is_visiting_generator_main_switch_) {
      // This is the main resume-switch for a generator, and some of its target
      // bypass loop headers. We need to re-route the destinations to the
      // bypassed loop headers, where secondary switches will be inserted.

      compiler::turboshaft::SwitchOp::Case* cases =
          __ output_graph().graph_zone()
              -> AllocateArray<compiler::turboshaft::SwitchOp::Case>(
                               node->size());

      DCHECK_EQ(0, node->value_base());

      for (int i = 0; i < node->size(); i++) {
        maglev::BasicBlock* target = node->targets()[i].block_ptr();
        if (generator_analyzer_.JumpBypassesHeader(target)) {
          Block* new_dst = __ NewBlock();

          const maglev::BasicBlock* innermost_bypassed_header =
              generator_analyzer_.GetInnermostBypassedHeader(target);

          pre_loop_generator_blocks_[innermost_bypassed_header].push_back(
              {new_dst, Map(target), i});

          // {innermost_bypassed_header} is only the innermost bypassed header.
          // We also need to record bypasses of outer headers. In the end, we
          // want this main Switch to go to before the outermost header, which
          // will dispatch to the next inner loop, and so on until the innermost
          // loop header and then to the initial destination.
          for (const maglev::BasicBlock* bypassed_header =
                   generator_analyzer_.GetLoopHeader(innermost_bypassed_header);
               bypassed_header != nullptr;
               bypassed_header =
                   generator_analyzer_.GetLoopHeader(bypassed_header)) {
            Block* prev_loop_dst = __ NewBlock();
            pre_loop_generator_blocks_[bypassed_header].push_back(
                {prev_loop_dst, new_dst, i});
            new_dst = prev_loop_dst;
          }

          cases[i] = {i, new_dst, BranchHint::kNone};

        } else {
          cases[i] = {i, Map(target), BranchHint::kNone};
        }
      }

      Block* default_block = __ NewBlock();
      __ Switch(Map(node->value()), base::VectorOf(cases, node->size()),
                default_block);
      __ Bind(default_block);
      __ Unreachable();

      return maglev::ProcessResult::kContinue;
    }

    compiler::turboshaft::SwitchOp::Case* cases =
        __ output_graph().graph_zone()
            -> AllocateArray<compiler::turboshaft::SwitchOp::Case>(
                             node->size());
    int case_value_base = node->value_base();
    for (int i = 0; i < node->size(); i++) {
      cases[i] = {i + case_value_base, Map(node->targets()[i].block_ptr()),
                  BranchHint::kNone};
    }
    Block* default_block;
    bool emit_default_block = false;
    if (node->has_fallthrough()) {
      default_block = Map(state.next_block());
    } else {
      default_block = __ NewBlock();
      emit_default_block = true;
    }
    __ Switch(Map(node->value()), base::VectorOf(cases, node->size()),
              default_block);
    if (emit_default_block) {
      __ Bind(default_block);
      __ Unreachable();
    }
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CheckedSmiUntag* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(node,
           __ CheckedSmiUntag(Map(node->input()), frame_state,
                              node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::UnsafeSmiUntag* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ UntagSmi(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedSmiTagInt32* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(
        node,
        __ ConvertUntaggedToJSPrimitiveOrDeopt(
            Map(node->input()), frame_state,
            ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind::kSmi,
            RegisterRepresentation::Word32(),
            ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation::kSigned,
            node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedSmiTagUint32* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(node,
           __ ConvertUntaggedToJSPrimitiveOrDeopt(
               Map(node->input()), frame_state,
               ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind::kSmi,
               RegisterRepresentation::Word32(),
               ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation::
                   kUnsigned,
               node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedSmiTagFloat64* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    V<Word32> as_int32 = __ ChangeFloat64ToInt32OrDeopt(
        Map(node->input()), frame_state,
        CheckForMinusZeroMode::kCheckForMinusZero,
        node->eager_deopt_info()->feedback_to_update());
    SetMap(
        node,
        __ ConvertUntaggedToJSPrimitiveOrDeopt(
            as_int32, frame_state,
            ConvertUntaggedToJSPrimitiveOrDeoptOp::JSPrimitiveKind::kSmi,
            RegisterRepresentation::Word32(),
            ConvertUntaggedToJSPrimitiveOrDeoptOp::InputInterpretation::kSigned,
            node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::UnsafeSmiTagInt32* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ TagSmi(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::UnsafeSmiTagUint32* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ TagSmi(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }

#define PROCESS_BINOP_WITH_OVERFLOW(MaglevName, TurboshaftName,                \
                                    minus_zero_mode)                           \
  maglev::ProcessResult Process(maglev::Int32##MaglevName##WithOverflow* node, \
                                const maglev::ProcessingState& state) {        \
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());        \
    SetMap(node,                                                               \
           __ Word32##TurboshaftName##DeoptOnOverflow(                         \
               Map(node->left_input()), Map(node->right_input()), frame_state, \
               node->eager_deopt_info()->feedback_to_update(),                 \
               CheckForMinusZeroMode::k##minus_zero_mode));                    \
    return maglev::ProcessResult::kContinue;                                   \
  }
  PROCESS_BINOP_WITH_OVERFLOW(Add, SignedAdd, DontCheckForMinusZero)
  PROCESS_BINOP_WITH_OVERFLOW(Subtract, SignedSub, DontCheckForMinusZero)
  PROCESS_BINOP_WITH_OVERFLOW(Multiply, SignedMul, CheckForMinusZero)
  PROCESS_BINOP_WITH_OVERFLOW(Divide, SignedDiv, CheckForMinusZero)
  PROCESS_BINOP_WITH_OVERFLOW(Modulus, SignedMod, CheckForMinusZero)
#undef PROCESS_BINOP_WITH_OVERFLOW
  maglev::ProcessResult Process(maglev::Int32IncrementWithOverflow* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    // Turboshaft doesn't have a dedicated Increment operation; we use a regular
    // addition instead.
    SetMap(node, __ Word32SignedAddDeoptOnOverflow(
                     Map(node->value_input()), 1, frame_state,
                     node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Int32DecrementWithOverflow* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    // Turboshaft doesn't have a dedicated Decrement operation; we use a regular
    // addition instead.
    SetMap(node, __ Word32SignedSubDeoptOnOverflow(
                     Map(node->value_input()), 1, frame_state,
                     node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Int32NegateWithOverflow* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    // Turboshaft doesn't have an Int32NegateWithOverflow operation, but
    // Turbofan emits multiplications by -1 for this, so using this as well
    // here.
    SetMap(node, __ Word32SignedMulDeoptOnOverflow(
                     Map(node->value_input()), -1, frame_state,
                     node->eager_deopt_info()->feedback_to_update(),
                     CheckForMinusZeroMode::kCheckForMinusZero));
    return maglev::ProcessResult::kContinue;
  }

#define PROCESS_FLOAT64_BINOP(MaglevName, TurboshaftName)               \
  maglev::ProcessResult Process(maglev::Float64##MaglevName* node,      \
                                const maglev::ProcessingState& state) { \
    SetMap(node, __ Float64##TurboshaftName(Map(node->left_input()),    \
                                            Map(node->right_input()))); \
    return maglev::ProcessResult::kContinue;                            \
  }
  PROCESS_FLOAT64_BINOP(Add, Add)
  PROCESS_FLOAT64_BINOP(Subtract, Sub)
  PROCESS_FLOAT64_BINOP(Multiply, Mul)
  PROCESS_FLOAT64_BINOP(Divide, Div)
  PROCESS_FLOAT64_BINOP(Modulus, Mod)
  PROCESS_FLOAT64_BINOP(Exponentiate, Power)
#undef PROCESS_FLOAT64_BINOP

#define PROCESS_INT32_BITWISE_BINOP(Name)                               \
  maglev::ProcessResult Process(maglev::Int32Bitwise##Name* node,       \
                                const maglev::ProcessingState& state) { \
    SetMap(node, __ Word32Bitwise##Name(Map(node->left_input()),        \
                                        Map(node->right_input())));     \
    return maglev::ProcessResult::kContinue;                            \
  }
  PROCESS_INT32_BITWISE_BINOP(And)
  PROCESS_INT32_BITWISE_BINOP(Or)
  PROCESS_INT32_BITWISE_BINOP(Xor)
#undef PROCESS_INT32_BITWISE_BINOP

#define PROCESS_INT32_SHIFT(MaglevName, TurboshaftName)                        \
  maglev::ProcessResult Process(maglev::Int32##MaglevName* node,               \
                                const maglev::ProcessingState& state) {        \
    V<Word32> right = Map(node->right_input());                                \
    if (!SupportedOperations::word32_shift_is_safe()) {                        \
      /* JavaScript spec says that the right-hand side of a shift should be    \
       * taken modulo 32. Some architectures do this automatically, some       \
       * don't. For those that don't, which do this modulo 32 with a `& 0x1f`. \
       */                                                                      \
      right = __ Word32BitwiseAnd(right, 0x1f);                                \
    }                                                                          \
    SetMap(node, __ Word32##TurboshaftName(Map(node->left_input()), right));   \
    return maglev::ProcessResult::kContinue;                                   \
  }
  PROCESS_INT32_SHIFT(ShiftLeft, ShiftLeft)
  PROCESS_INT32_SHIFT(ShiftRight, ShiftRightArithmetic)
#undef PROCESS_INT32_SHIFT

  maglev::ProcessResult Process(maglev::Int32ShiftRightLogical* node,
                                const maglev::ProcessingState& state) {
    V<Word32> right = Map(node->right_input());
    if (!SupportedOperations::word32_shift_is_safe()) {
      // JavaScript spec says that the right-hand side of a shift should be
      // taken modulo 32. Some architectures do this automatically, some
      // don't. For those that don't, which do this modulo 32 with a `& 0x1f`.
      right = __ Word32BitwiseAnd(right, 0x1f);
    }
    V<Word32> ts_op =
        __ Word32ShiftRightLogical(Map(node->left_input()), right);
    SetMap(node, __ Word32SignHintUnsigned(ts_op));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Int32BitwiseNot* node,
                                const maglev::ProcessingState& state) {
    // Turboshaft doesn't have a bitwise Not operator; we instead use "^ -1".
    SetMap(node, __ Word32BitwiseXor(Map(node->value_input()),
                                     __ Word32Constant(-1)));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Int32AbsWithOverflow* node,
                                const maglev::ProcessingState& state) {
    V<Word32> input = Map(node->input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    ScopedVar<Word32, AssemblerT> result(this, input);

    IF (__ Int32LessThan(input, 0)) {
      V<Tuple<Word32, Word32>> result_with_ovf =
          __ Int32MulCheckOverflow(input, -1);
      __ DeoptimizeIf(__ Projection<1>(result_with_ovf), frame_state,
                      DeoptimizeReason::kOverflow,
                      node->eager_deopt_info()->feedback_to_update());
      result = __ Projection<0>(result_with_ovf);
    }

    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Float64Negate* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ Float64Negate(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Float64Abs* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ Float64Abs(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Float64Round* node,
                                const maglev::ProcessingState& state) {
    if (node->kind() == maglev::Float64Round::Kind::kFloor) {
      SetMap(node, __ Float64RoundDown(Map(node->input())));
    } else if (node->kind() == maglev::Float64Round::Kind::kCeil) {
      SetMap(node, __ Float64RoundUp(Map(node->input())));
    } else {
      DCHECK_EQ(node->kind(), maglev::Float64Round::Kind::kNearest);
      // Nearest rounds to +infinity on ties. We emulate this by rounding up and
      // adjusting if the difference exceeds 0.5 (like SimplifiedLowering does
      // for lower Float64Round).
      OpIndex input = Map(node->input());
      ScopedVar<Float64, AssemblerT> result(this, __ Float64RoundUp(input));
      IF_NOT (__ Float64LessThanOrEqual(__ Float64Sub(result, 0.5), input)) {
        result = __ Float64Sub(result, 1.0);
      }

      SetMap(node, result);
    }
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::Float64Ieee754Unary* node,
                                const maglev::ProcessingState& state) {
    FloatUnaryOp::Kind kind;
    switch (node->ieee_function()) {
#define CASE(MathName, ExpName, EnumName)                         \
  case maglev::Float64Ieee754Unary::Ieee754Function::k##EnumName: \
    kind = FloatUnaryOp::Kind::k##EnumName;                       \
    break;
      IEEE_754_UNARY_LIST(CASE)
#undef CASE
    }
    SetMap(node, __ Float64Unary(Map(node->input()), kind));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::CheckedSmiIncrement* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    V<Smi> result;
    if constexpr (SmiValuesAre31Bits()) {
      result = __ BitcastWord32ToSmi(__ Word32SignedAddDeoptOnOverflow(
          __ BitcastSmiToWord32(Map(node->value_input())),
          Smi::FromInt(1).ptr(), frame_state,
          node->eager_deopt_info()->feedback_to_update()));
    } else {
      // Remember that 32-bit Smis are stored in the upper 32 bits of 64-bit
      // qwords. We thus perform a 64-bit addition rather than a 32-bit one,
      // despite Smis being only 32 bits.
      result = __ BitcastWordPtrToSmi(__ WordPtrSignedAddDeoptOnOverflow(
          __ BitcastSmiToWordPtr(Map(node->value_input())),
          Smi::FromInt(1).ptr(), frame_state,
          node->eager_deopt_info()->feedback_to_update()));
    }
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedSmiDecrement* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    V<Smi> result;
    if constexpr (SmiValuesAre31Bits()) {
      result = __ BitcastWord32ToSmi(__ Word32SignedSubDeoptOnOverflow(
          __ BitcastSmiToWord32(Map(node->value_input())),
          Smi::FromInt(1).ptr(), frame_state,
          node->eager_deopt_info()->feedback_to_update()));
    } else {
      result = __ BitcastWordPtrToSmi(__ WordPtrSignedSubDeoptOnOverflow(
          __ BitcastSmiToWordPtr(Map(node->value_input())),
          Smi::FromInt(1).ptr(), frame_state,
          node->eager_deopt_info()->feedback_to_update()));
    }
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }

// Note that Maglev collects feedback in the generic binops and unops, so that
// Turbofan has chance to get better feedback. However, once we reach Turbofan,
// we stop collecting feedback, since we've tried multiple times to keep
// collecting feedback in Turbofan, but it never seemed worth it. The latest
// occurence of this was ended by this CL: https://crrev.com/c/4110858.
#define PROCESS_GENERIC_BINOP(Name)                                            \
  maglev::ProcessResult Process(maglev::Generic##Name* node,                   \
                                const maglev::ProcessingState& state) {        \
    ThrowingScope throwing_scope(this, node);                                  \
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());         \
    SetMap(node,                                                               \
           __ Generic##Name(Map(node->left_input()), Map(node->right_input()), \
                            frame_state, native_context(),                     \
                            ShouldLazyDeoptOnThrow(node)));                    \
    return maglev::ProcessResult::kContinue;                                   \
  }
  GENERIC_BINOP_LIST(PROCESS_GENERIC_BINOP)
#undef PROCESS_GENERIC_BINOP

#define PROCESS_GENERIC_UNOP(Name)                                            \
  maglev::ProcessResult Process(maglev::Generic##Name* node,                  \
                                const maglev::ProcessingState& state) {       \
    ThrowingScope throwing_scope(this, node);                                 \
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());        \
    SetMap(node,                                                              \
           __ Generic##Name(Map(node->operand_input()), frame_state,          \
                            native_context(), ShouldLazyDeoptOnThrow(node))); \
    return maglev::ProcessResult::kContinue;                                  \
  }
  GENERIC_UNOP_LIST(PROCESS_GENERIC_UNOP)
#undef PROCESS_GENERIC_UNOP

  maglev::ProcessResult Process(maglev::ToNumberOrNumeric* node,
                                const maglev::ProcessingState& state) {
    ThrowingScope throwing_scope(this, node);
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->lazy_deopt_info());
    SetMap(node, __ ToNumberOrNumeric(Map(node->value_input()), frame_state,
                                      native_context(), node->mode(),
                                      ShouldLazyDeoptOnThrow(node)));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::LogicalNot* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition = __ TaggedEqual(
        Map(node->value()), __ HeapConstant(local_factory_->true_value()));
    SetMap(node, ConvertWord32ToJSBool(condition, /*flip*/ true));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ToBooleanLogicalNot* node,
                                const maglev::ProcessingState& state) {
    TruncateJSPrimitiveToUntaggedOp::InputAssumptions assumption =
        node->check_type() == maglev::CheckType::kCheckHeapObject
            ? TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kObject
            : TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kHeapObject;
    V<Word32> condition = ToBit(node->value(), assumption);
    SetMap(node, ConvertWord32ToJSBool(condition, /*flip*/ true));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::ToBoolean* node,
                                const maglev::ProcessingState& state) {
    TruncateJSPrimitiveToUntaggedOp::InputAssumptions input_assumptions;
    switch (node->check_type()) {
      case maglev::CheckType::kCheckHeapObject:
        input_assumptions =
            TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kObject;
        break;
      case maglev::CheckType::kOmitHeapObjectCheck:
        input_assumptions =
            TruncateJSPrimitiveToUntaggedOp::InputAssumptions::kHeapObject;
        break;
    }
    SetMap(node,
           ConvertWord32ToJSBool(ToBit(node->value(), input_assumptions)));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Int32ToBoolean* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, ConvertWord32ToJSBool(Map(node->value()), node->flip()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Float64ToBoolean* node,
                                const maglev::ProcessingState& state) {
    V<Word32> condition = Float64ToBit(Map(node->value()));
    SetMap(node, ConvertWord32ToJSBool(condition, node->flip()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Int32ToNumber* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ ConvertInt32ToNumber(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Uint32ToNumber* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ ConvertUint32ToNumber(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Float64ToTagged* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, Float64ToTagged(Map(node->input()), node->conversion_mode()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::HoleyFloat64ToTagged* node,
                                const maglev::ProcessingState& state) {
    SetMap(node,
           HoleyFloat64ToTagged(Map(node->input()), node->conversion_mode()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Float64ToHeapNumberForField* node,
                                const maglev::ProcessingState& state) {
    // We don't use ConvertUntaggedToJSPrimitive but instead the lower level
    // AllocateHeapNumberWithValue helper, because ConvertUntaggedToJSPrimitive
    // can be GVNed, which we don't want for Float64ToHeapNumberForField, since
    // it creates a mutable HeapNumber, that will then be owned by an object
    // field.
    SetMap(node, __ AllocateHeapNumberWithValue(Map(node->input()),
                                                isolate_->factory()));
    return maglev::ProcessResult::kContinue;
  }

  maglev::ProcessResult Process(maglev::HoleyFloat64IsHole* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, ConvertWord32ToJSBool(__ Float64IsHole(Map(node->input()))));
    return maglev::ProcessResult::kContinue;
  }

  template <typename NumberToFloat64Op>
    requires(std::is_same_v<NumberToFloat64Op,
                            maglev::CheckedNumberOrOddballToFloat64> ||
             std::is_same_v<NumberToFloat64Op,
                            maglev::CheckedNumberOrOddballToHoleyFloat64>)
  maglev::ProcessResult Process(NumberToFloat64Op* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind kind;
    switch (node->conversion_type()) {
      case maglev::TaggedToFloat64ConversionType::kOnlyNumber:
        kind = ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumber;
        break;
      case maglev::TaggedToFloat64ConversionType::kNumberOrBoolean:
        kind = ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::
            kNumberOrBoolean;
        break;
      case maglev::TaggedToFloat64ConversionType::kNumberOrOddball:
        kind = ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::
            kNumberOrOddball;
        break;
    }
    SetMap(node,
           __ ConvertJSPrimitiveToUntaggedOrDeopt(
               Map(node->input()), frame_state, kind,
               ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kFloat64,
               CheckForMinusZeroMode::kCheckForMinusZero,
               node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::UncheckedNumberOrOddballToFloat64* node,
                                const maglev::ProcessingState& state) {
    // `node->conversion_type()` doesn't matter here, since for both HeapNumbers
    // and Oddballs, the Float64 value is at the same index (and this node never
    // deopts, regardless of its input).
    SetMap(node, __ ConvertJSPrimitiveToUntagged(
                     Map(node->input()),
                     ConvertJSPrimitiveToUntaggedOp::UntaggedKind::kFloat64,
                     ConvertJSPrimitiveToUntaggedOp::InputAssumptions::
                         kNumberOrOddball));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TruncateUint32ToInt32* node,
                                const maglev::ProcessingState& state) {
    // This doesn't matter in Turboshaft: both Uint32 and Int32 are Word32.
    SetMap(node, __ Word32SignHintSigned(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedInt32ToUint32* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIf(__ Int32LessThan(Map(node->input()), 0), frame_state,
                    DeoptimizeReason::kNotUint32,
                    node->eager_deopt_info()->feedback_to_update());
    SetMap(node, __ Word32SignHintUnsigned(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedUint32ToInt32* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    __ DeoptimizeIf(__ Int32LessThan(Map(node->input()), 0), frame_state,
                    DeoptimizeReason::kNotInt32,
                    node->eager_deopt_info()->feedback_to_update());
    SetMap(node, __ Word32SignHintSigned(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::UnsafeInt32ToUint32* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ Word32SignHintUnsigned(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedObjectToIndex* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    const FeedbackSource& feedback =
        node->eager_deopt_info()->feedback_to_update();
    OpIndex result = __ ConvertJSPrimitiveToUntaggedOrDeopt(
        Map(node->object_input()), frame_state,
        ConvertJSPrimitiveToUntaggedOrDeoptOp::JSPrimitiveKind::kNumberOrString,
        ConvertJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kArrayIndex,
        CheckForMinusZeroMode::kCheckForMinusZero, feedback);
    if constexpr (Is64()) {
      // ArrayIndex is 32-bit in Maglev, but 64 in Turboshaft. This means that
      // we have to convert it to 32-bit before the following `SetMap`, and we
      // thus have to check that it actually fits in a Uint32.
      __ DeoptimizeIfNot(__ Uint64LessThanOrEqual(
                             result, std::numeric_limits<uint32_t>::max()),
                         frame_state, DeoptimizeReason::kNotInt32, feedback);
      RETURN_IF_UNREACHABLE();
    }
    SetMap(node, Is64() ? __ TruncateWord64ToWord32(result) : result);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ChangeInt32ToFloat64* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ ChangeInt32ToFloat64(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ChangeUint32ToFloat64* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ ChangeUint32ToFloat64(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedTruncateFloat64ToInt32* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(node, __ ChangeFloat64ToInt32OrDeopt(
                     Map(node->input()), frame_state,
                     CheckForMinusZeroMode::kCheckForMinusZero,
                     node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedTruncateFloat64ToUint32* node,
                                const maglev::ProcessingState& state) {
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(node, __ ChangeFloat64ToUint32OrDeopt(
                     Map(node->input()), frame_state,
                     CheckForMinusZeroMode::kCheckForMinusZero,
                     node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(
      maglev::CheckedTruncateNumberOrOddballToInt32* node,
      const maglev::ProcessingState& state) {
    TruncateJSPrimitiveToUntaggedOrDeoptOp::InputRequirement input_requirement;
    switch (node->conversion_type()) {
      case maglev::TaggedToFloat64ConversionType::kOnlyNumber:
        input_requirement =
            TruncateJSPrimitiveToUntaggedOrDeoptOp::InputRequirement::kNumber;
        break;
      case maglev::TaggedToFloat64ConversionType::kNumberOrBoolean:
        input_requirement = TruncateJSPrimitiveToUntaggedOrDeoptOp::
            InputRequirement::kNumberOrBoolean;
        break;
      case maglev::TaggedToFloat64ConversionType::kNumberOrOddball:
        input_requirement = TruncateJSPrimitiveToUntaggedOrDeoptOp::
            InputRequirement::kNumberOrOddball;
        break;
    }
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());
    SetMap(
        node,
        __ TruncateJSPrimitiveToUntaggedOrDeopt(
            Map(node->input()), frame_state,
            TruncateJSPrimitiveToUntaggedOrDeoptOp::UntaggedKind::kInt32,
            input_requirement, node->eager_deopt_info()->feedback_to_update()));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TruncateNumberOrOddballToInt32* node,
                                const maglev::ProcessingState& state) {
    // In Maglev, TruncateNumberOrOddballToInt32 does the same thing for both
    // NumberOrOddball and Number; except when debug_code is enabled: then,
    // Maglev inserts runtime checks ensuring that the input is indeed a Number
    // or NumberOrOddball. Turboshaft doesn't typically introduce such runtime
    // checks, so we instead just lower both Number and NumberOrOddball to the
    // NumberOrOddball variant.
    SetMap(node, __ TruncateJSPrimitiveToUntagged(
                     Map(node->input()),
                     TruncateJSPrimitiveToUntaggedOp::UntaggedKind::kInt32,
                     TruncateJSPrimitiveToUntaggedOp::InputAssumptions::
                         kNumberOrOddball));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::TruncateFloat64ToInt32* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ JSTruncateFloat64ToWord32(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::HoleyFloat64ToMaybeNanFloat64* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, __ Float64SilenceNaN(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::CheckedHoleyFloat64ToFloat64* node,
                                const maglev::ProcessingState& state) {
    V<Float64> input = Map(node->input());
    GET_FRAME_STATE_MAYBE_ABORT(frame_state, node->eager_deopt_info());

    __ DeoptimizeIf(__ Float64IsHole(input), frame_state,
                    DeoptimizeReason::kHole,
                    node->eager_deopt_info()->feedback_to_update());

    SetMap(node, input);
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ConvertHoleToUndefined* node,
                                const maglev::ProcessingState& state) {
    V<Word32> cond = RootEqual(node->object_input(), RootIndex::kTheHoleValue);
    SetMap(node,
           __ Select(cond, __ HeapConstant(local_factory_->undefined_value()),
                     Map<Object>(node->object_input()),
                     RegisterRepresentation::Tagged(), BranchHint::kNone,
                     SelectOp::Implementation::kBranch));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::ConvertReceiver* node,
                                const maglev::ProcessingState& state) {
    NoThrowingScopeRequired no_throws(node);

    Label<Object> done(this);
    Label<> non_js_receiver(this);
    V<Object> receiver = Map(node->receiver_input());

    GOTO_IF(__ IsSmi(receiver), non_js_receiver);

    GOTO_IF(__ JSAnyIsNotPrimitive(V<HeapObject>::Cast(receiver)), done,
            receiver);

    if (node->mode() != ConvertReceiverMode::kNotNullOrUndefined) {
      Label<> convert_global_proxy(this);
      GOTO_IF(__ RootEqual(receiver, RootIndex::kUndefinedValue, isolate_),
              convert_global_proxy);
      GOTO_IF_NOT(__ RootEqual(receiver, RootIndex::kNullValue, isolate_),
                  non_js_receiver);
      GOTO(convert_global_proxy);
      BIND(convert_global_proxy);
      GOTO(done,
           __ HeapConstant(
               node->native_context().global_proxy_object(broker_).object()));
    } else {
      GOTO(non_js_receiver);
    }

    BIND(non_js_receiver);
    GOTO(done, __ CallBuiltin_ToObject(
                   isolate_, __ HeapConstant(node->native_context().object()),
                   V<JSPrimitive>::Cast(receiver)));

    BIND(done, result);
    SetMap(node, result);

    return maglev::ProcessResult::kContinue;
  }

  static constexpr int kMinClampedUint8 = 0;
  static constexpr int kMaxClampedUint8 = 255;
  V<Word32> Int32ToUint8Clamped(V<Word32> value) {
    ScopedVar<Word32, AssemblerT> result(this);
    IF (__ Int32LessThan(value, kMinClampedUint8)) {
      result = __ Word32Constant(kMinClampedUint8);
    } ELSE IF (__ Int32LessThan(value, kMaxClampedUint8)) {
      result = value;
    } ELSE {
      result = __ Word32Constant(kMaxClampedUint8);
    }
    return result;
  }
  V<Word32> Float64ToUint8Clamped(V<Float64> value) {
    ScopedVar<Word32, AssemblerT> result(this);
    IF (__ Float64LessThan(value, kMinClampedUint8)) {
      result = __ Word32Constant(kMinClampedUint8);
    } ELSE IF (__ Float64LessThan(kMaxClampedUint8, value)) {
      result = __ Word32Constant(kMaxClampedUint8);
    } ELSE {
      // Note that this case handles values that are in range of Clamped Uint8
      // and NaN. The order of the IF/ELSE-IF/ELSE in this function is so that
      // we do indeed end up here for NaN.
      result = __ JSTruncateFloat64ToWord32(__ Float64RoundTiesEven(value));
    }
    return result;
  }

  maglev::ProcessResult Process(maglev::Int32ToUint8Clamped* node,
                                const maglev::ProcessingState& state) {
    SetMap(node, Int32ToUint8Clamped(Map(node->input())));
    return maglev::ProcessResult::kContinue;
  }
  maglev::ProcessResult Process(maglev::Uint32ToUint8Clamped* node,
                                const maglev::ProcessingState& state) {
    ScopedVar<Word32, AssemblerT> result(this);
    V<Word32> value = Map(node->input());
    IF (__ Uint32LessThan(value, kMaxClampedUint8)) {
      result = value;
    } ELSE {
      result = __ Word32Constant(kMaxClampedUint8);
    }
    SetMap(node, result);
    return maglev::ProcessResult::kContinue;
  }
  m
"""


```