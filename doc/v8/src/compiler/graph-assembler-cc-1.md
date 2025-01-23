Response:
The user wants a summary of the functionality of the provided C++ code snippet from `v8/src/compiler/graph-assembler.cc`.

Here's a breakdown of the code and how to explain its functionality:

1. **Overall Purpose:**  The code is part of the `JSGraphAssembler` class in V8's compiler. This class is a helper for building the intermediate representation (IR) of JavaScript code as a graph. It provides a higher-level, more convenient way to create nodes in the graph compared to directly manipulating the graph's data structures.

2. **Key Components:**
   - **`ArrayBufferViewAccessBuilder`:**  A helper class within `JSGraphAssembler` specifically designed to generate code for accessing properties of `ArrayBufferView` objects (like TypedArrays and DataViews). This involves handling different underlying storage mechanisms (normal, Rab, Gsab) and checking for detached buffers.
   - **Methods for ArrayBufferView:**  The `JSGraphAssembler` has methods like `ArrayBufferViewByteLength`, `TypedArrayLength`, and `CheckIfTypedArrayWasDetached` that use the `ArrayBufferViewAccessBuilder` to generate the necessary graph nodes for these operations.
   - **Runtime Calls:** Methods like `JSCallRuntime1` and `JSCallRuntime2` are used to generate calls to V8's runtime functions.
   - **Graph Manipulation:** The `GraphAssembler` (base class of `JSGraphAssembler`) provides core functionalities for adding nodes to the graph, creating branches, handling control flow (e.g., `Unreachable`), and managing effects.
   - **Machine Operations:** Functions like `Load`, `Store`, `IntPtrAdd`, `BitcastWordToTagged`, etc., generate low-level machine-specific operations in the graph.
   - **Deoptimization:** Functions like `DeoptimizeIf` allow the compiler to generate code that bails out to the interpreter if certain conditions are not met.

3. **Relationship to JavaScript:** The code is directly related to how V8 compiles JavaScript, particularly when dealing with typed arrays and array buffers. Operations on these objects require careful handling of memory, potential detachment, and different storage strategies.

4. **Torque:** The code is C++, not Torque. Torque is a higher-level language used within V8 that can generate C++ code. The prompt includes a condition about the file extension being `.tq`, which is false here.

5. **Logic and Examples:**
   - **`ArrayBufferViewByteLength`:**  This function calculates the length of an `ArrayBufferView` in bytes. The logic involves checking if the underlying buffer is resizable (Rab/Gsab) and handling different cases.
   - **`BuildDetachedCheck`:** This function generates code to check if an `ArrayBufferView`'s underlying buffer has been detached. It needs to consider the possibility of Rab/Gsab-backed buffers and length tracking.

6. **Common Programming Errors:** Detaching an `ArrayBuffer` while a `TypedArray` or `DataView` is still using it is a common error that this code helps to detect and handle.

7. **Summarization for Part 2:** Since this is part 2, the summary should focus on the functionalities within this specific snippet, building upon the understanding from part 1. It should highlight the `ArrayBufferViewAccessBuilder`, the methods for length and detached checks, and the interaction with lower-level graph building functions.

**Plan for Generating the Response:**

1. State that the code is C++ and not Torque.
2. Summarize the overall function of `v8/src/compiler/graph-assembler.cc` as a helper for building the IR graph.
3. Explain the role of `ArrayBufferViewAccessBuilder` in handling `ArrayBufferView` specifics.
4. Describe the functionalities of `BuildByteLength` and `BuildDetachedCheck`, including the handling of Rab/Gsab and length tracking.
5. Provide a JavaScript example demonstrating the concept of detached ArrayBuffers and how V8's compiler might use this code.
6. Create a hypothetical input/output scenario for `BuildDetachedCheck`.
7. Give an example of a common programming error related to detached ArrayBuffers.
8. Finally, summarize the functions of this specific code part as requested by the prompt for part 2.
好的，让我们来分析一下 `v8/src/compiler/graph-assembler.cc` 代码片段的功能。

**功能归纳：**

这段代码是 `v8::internal::compiler::JSGraphAssembler` 类的一部分，主要负责构建用于表示 JavaScript 代码执行的**中间图（Intermediate Representation Graph）** 中的节点，特别是与 **ArrayBufferView（例如 TypedArray 和 DataView）** 相关的操作。

更具体地说，这段代码片段提供了以下功能：

1. **构建获取 ArrayBufferView 字节长度的图节点 (`BuildByteLength`)：**
   -  根据 `ArrayBufferView` 的类型和 `ElementsKind`（元素类型），生成获取其字节长度的代码。
   -  考虑了不同类型的 `ArrayBufferView`，包括普通 `ArrayBufferView` 和由可调整大小的 ArrayBuffer (Resizable ArrayBuffer - RAB) 或可共享的可调整大小的 ArrayBuffer (Growable Shared ArrayBuffer - GSAB) 支持的 `ArrayBufferView`。
   -  针对 RAB 和 GSAB，会检查是否启用了长度跟踪 (`length_tracking_bit`)，并根据不同的情况计算字节长度。

2. **构建获取 ArrayBufferView 元素个数的图节点 (`BuildLength`)：**
   -  类似于 `BuildByteLength`，但计算的是元素的个数，而不是字节数。
   -  同样需要考虑不同类型的 `ArrayBufferView` 和 RAB/GSAB 的情况。

3. **构建检查 ArrayBufferView 是否已分离的图节点 (`BuildDetachedCheck`)：**
   -  生成用于检查 `ArrayBufferView` 底层的 `ArrayBuffer` 是否已被分离（detached）的代码。
   -  这是为了确保在访问 `ArrayBufferView` 的数据之前，其底层缓冲区仍然有效。
   -  同样需要处理 RAB 和 GSAB 支持的 `ArrayBufferView`，并检查长度跟踪位。

4. **辅助函数 `MachineLoadField`：**
   -  一个模板函数，用于在构建图节点时，加载对象的字段。它将 `assembler_->LoadField` 的结果封装到机器图上下文中。

**关于文件类型和 JavaScript 关系：**

- 代码以 `.cc` 结尾，表明它是 **C++ 源代码**，而不是 Torque 源代码（Torque 源代码以 `.tq` 结尾）。
- 这段代码与 JavaScript 的功能 **密切相关**。`ArrayBufferView` (包括 `TypedArray` 和 `DataView`) 是 JavaScript 中用于处理二进制数据的关键概念。这段代码负责在 V8 编译 JavaScript 代码时，生成处理这些对象的底层操作。

**JavaScript 示例：**

以下 JavaScript 示例展示了与这段 C++ 代码功能相关的操作：

```javascript
// 创建一个 ArrayBuffer
const buffer = new ArrayBuffer(16);

// 创建一个 Int32Array 视图
const typedArray = new Int32Array(buffer);

// 获取 TypedArray 的字节长度
const byteLength = typedArray.byteLength;
console.log(byteLength); // 输出: 16

// 获取 TypedArray 的元素个数
const length = typedArray.length;
console.log(length); // 输出: 4 (16 字节 / 4 字节每元素)

// 分离 ArrayBuffer
// (只有 Resizable ArrayBuffer 才支持真正的分离，普通的 ArrayBuffer 只能置零)
// 在支持 Resizable ArrayBuffer 的环境中：
// buffer.resize(0); // 可能会抛出异常，取决于视图的状态

// 检查 TypedArray 的 buffer 是否已分离 (模拟)
function isBufferDetached(typedArray) {
  try {
    typedArray[0]; // 尝试访问元素
    return false;
  } catch (e) {
    return true; // 如果访问失败，很可能已分离
  }
}

console.log(isBufferDetached(typedArray)); // 输出: false (在分离之前)

// 如果 buffer 被分离（或置零），再次尝试访问将会报错
// 例如，如果 buffer 被置零，访问 typedArray[0] 会得到 0，但概念上仍然关联。
```

**代码逻辑推理 (假设输入与输出)：**

假设我们有一个 `Int32Array` 的 `view`，其底层 `ArrayBuffer` 的字节长度为 16，`view` 的字节偏移量为 0。

**输入（针对 `BuildByteLength`）：**

- `view`：表示 `Int32Array` 的图节点
- `instance_type_`：`JS_TYPED_ARRAY_TYPE`
- `candidates_`：包含 `kInt32Elements` 的集合
- `context`：当前的上下文

**输出（`BuildByteLength` 返回的图节点表示）：**

- 一系列机器指令，最终计算出 `view` 的字节长度为 16。
- 如果底层 `ArrayBuffer` 是 RAB 或 GSAB 并且启用了长度跟踪，则会包含加载底层 `ArrayBuffer` 字节长度并进行减法运算的指令。
- 如果底层 `ArrayBuffer` 是 RAB 或 GSAB 并且未启用长度跟踪，则会直接加载 `view` 的字节长度字段。
- 如果底层 `ArrayBuffer` 不是 RAB 或 GSAB，则直接加载 `view` 的字节长度字段。

**输入（针对 `BuildDetachedCheck`）：**

- `view`：表示 `Int32Array` 的图节点

**输出（`BuildDetachedCheck` 返回的图节点表示）：**

- 一系列机器指令，执行以下操作：
    1. 加载底层 `ArrayBuffer` 及其位域。
    2. 提取分离位 (`WasDetachedBit::kMask`)。
    3. 如果不是 RAB/GSAB，则返回分离位。
    4. 如果是 RAB/GSAB，则加载 `view` 的位域，检查长度跟踪位和 RAB 支持位。
    5. 根据不同的 RAB/GSAB 和长度跟踪情况，生成相应的检查，例如比较底层 `ArrayBuffer` 的字节长度和 `view` 的字节偏移量。
    6. 最终返回一个表示是否已分离的 32 位整数 (0 表示未分离，非 0 表示已分离)。

**用户常见的编程错误：**

一个常见的编程错误是在 `ArrayBufferView` 仍然被使用时，对其底层的 `ArrayBuffer` 进行分离操作（在支持 Resizable ArrayBuffer 的环境中）。这会导致访问 `ArrayBufferView` 时出现错误。

**示例：**

```javascript
const buffer = new ArrayBuffer(8);
const view = new Int32Array(buffer);

// ... 使用 view ...

// 错误：在 view 还在使用时分离 buffer (Resizable ArrayBuffer 环境)
// buffer.resize(0);

console.log(view[0]); // 如果 buffer 被分离，这里可能会抛出异常
```

这段 `v8/src/compiler/graph-assembler.cc` 中的代码就是为了在编译时生成必要的检查，以防止或处理这类运行时错误。

**第 2 部分功能归纳：**

作为第二部分，这段代码片段的核心功能集中在：

- **为访问和检查 `ArrayBufferView` 对象的关键属性（字节长度、元素个数、是否已分离）生成中间图节点。**
- **特别关注了 Resizable ArrayBuffer (RAB) 和 Growable Shared ArrayBuffer (GSAB) 的特殊处理逻辑，包括长度跟踪机制。**
- **提供了用于构建类型化数组和 DataView 相关操作的底层构建块，为 V8 优化这些操作提供了基础。**

总而言之，这段代码是 V8 编译器中至关重要的一部分，它负责将 JavaScript 中对 `ArrayBufferView` 的操作转换为可以在底层机器上执行的指令，并确保在处理这些对象时考虑到各种边缘情况和潜在的错误。

### 提示词
```
这是目录为v8/src/compiler/graph-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/compiler/graph-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
return RoundDownToElementSize(
                a.UintPtrSub(byte_length, byte_offset));
          })
          .Else([&]() { return a.UintPtrConstant(0); })
          .ExpectTrue()
          .Value();
    };

    return a.MachineSelectIf<UintPtrT>(length_tracking_bit)
        .Then([&]() {
          return a.MachineSelectIf<UintPtrT>(backed_by_rab_bit)
              .Then(RabTracking)
              .Else(GsabTracking)
              .Value();
        })
        .Else([&]() {
          return a.MachineSelectIf<UintPtrT>(backed_by_rab_bit)
              .Then(RabFixed)
              .Else(GsabFixedOrNormal)
              .Value();
        })
        .Value();
  }

  TNode<Word32T> BuildDetachedCheck(TNode<JSArrayBufferView> view) {
    auto& a = *assembler_;

    // Load the underlying buffer and its bitfield.
    TNode<HeapObject> buffer = a.LoadField<HeapObject>(
        AccessBuilder::ForJSArrayBufferViewBuffer(), view);
    TNode<Word32T> buffer_bit_field =
        MachineLoadField<Word32T>(AccessBuilder::ForJSArrayBufferBitField(),
                                  buffer, UseInfo::TruncatingWord32());
    // Mask the detached bit.
    TNode<Word32T> detached_bit =
        a.Word32And(buffer_bit_field,
                    a.Uint32Constant(JSArrayBuffer::WasDetachedBit::kMask));

    // If we statically know we cannot have rab/gsab backed, we are done here.
    if (!maybe_rab_gsab()) {
      return detached_bit;
    }

    // Otherwise, we need to generate the checks for the view's bitfield.
    TNode<Word32T> bitfield = a.EnterMachineGraph<Word32T>(
        a.LoadField<Word32T>(AccessBuilder::ForJSArrayBufferViewBitField(),
                             view),
        UseInfo::TruncatingWord32());
    TNode<Word32T> length_tracking_bit = a.Word32And(
        bitfield, a.Uint32Constant(JSArrayBufferView::kIsLengthTracking));
    TNode<Word32T> backed_by_rab_bit = a.Word32And(
        bitfield, a.Uint32Constant(JSArrayBufferView::kIsBackedByRab));

    auto RabLengthTracking = [&]() {
      TNode<UintPtrT> byte_offset = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteOffset(), view,
          UseInfo::Word());

      TNode<UintPtrT> underlying_byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferByteLength(), buffer, UseInfo::Word());

      return a.Word32Or(detached_bit,
                        a.UintPtrLessThan(underlying_byte_length, byte_offset));
    };

    auto RabFixed = [&]() {
      TNode<UintPtrT> unchecked_byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteLength(), view,
          UseInfo::Word());
      TNode<UintPtrT> byte_offset = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferViewByteOffset(), view,
          UseInfo::Word());

      TNode<UintPtrT> underlying_byte_length = MachineLoadField<UintPtrT>(
          AccessBuilder::ForJSArrayBufferByteLength(), buffer, UseInfo::Word());

      return a.Word32Or(
          detached_bit,
          a.UintPtrLessThan(underlying_byte_length,
                            a.UintPtrAdd(byte_offset, unchecked_byte_length)));
    };

    // Dispatch depending on rab/gsab and length tracking.
    return a.MachineSelectIf<Word32T>(backed_by_rab_bit)
        .Then([&]() {
          return a.MachineSelectIf<Word32T>(length_tracking_bit)
              .Then(RabLengthTracking)
              .Else(RabFixed)
              .Value();
        })
        .Else([&]() { return detached_bit; })
        .Value();
  }

 private:
  template <typename T>
  TNode<T> MachineLoadField(FieldAccess const& access, TNode<HeapObject> object,
                            const UseInfo& use_info) {
    return assembler_->EnterMachineGraph<T>(
        assembler_->LoadField<T>(access, object), use_info);
  }

  JSGraphAssembler* assembler_;
  InstanceType instance_type_;
  std::set<ElementsKind> candidates_;
};

TNode<Number> JSGraphAssembler::ArrayBufferViewByteLength(
    TNode<JSArrayBufferView> array_buffer_view, InstanceType instance_type,
    std::set<ElementsKind> elements_kinds_candidates, TNode<Context> context) {
  ArrayBufferViewAccessBuilder builder(this, instance_type,
                                       std::move(elements_kinds_candidates));
  return ExitMachineGraph<Number>(
      builder.BuildByteLength(array_buffer_view, context),
      MachineType::PointerRepresentation(),
      TypeCache::Get()->kJSArrayBufferByteLengthType);
}

TNode<Number> JSGraphAssembler::TypedArrayLength(
    TNode<JSTypedArray> typed_array,
    std::set<ElementsKind> elements_kinds_candidates, TNode<Context> context) {
  ArrayBufferViewAccessBuilder builder(this, JS_TYPED_ARRAY_TYPE,
                                       std::move(elements_kinds_candidates));
  return ExitMachineGraph<Number>(builder.BuildLength(typed_array, context),
                                  MachineType::PointerRepresentation(),
                                  TypeCache::Get()->kJSTypedArrayLengthType);
}

void JSGraphAssembler::CheckIfTypedArrayWasDetached(
    TNode<JSTypedArray> typed_array,
    std::set<ElementsKind> elements_kinds_candidates,
    const FeedbackSource& feedback) {
  ArrayBufferViewAccessBuilder builder(this, JS_TYPED_ARRAY_TYPE,
                                       std::move(elements_kinds_candidates));

  TNode<Word32T> detached_check = builder.BuildDetachedCheck(typed_array);
  TNode<Boolean> is_not_detached =
      ExitMachineGraph<Boolean>(Word32Equal(detached_check, Uint32Constant(0)),
                                MachineRepresentation::kBit, Type::Boolean());
  CheckIf(is_not_detached, DeoptimizeReason::kArrayBufferWasDetached, feedback);
}

TNode<Uint32T> JSGraphAssembler::LookupByteShiftForElementsKind(
    TNode<Uint32T> elements_kind) {
  TNode<UintPtrT> index = ChangeUint32ToUintPtr(Int32Sub(
      elements_kind, Uint32Constant(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)));
  TNode<RawPtrT> shift_table = TNode<RawPtrT>::UncheckedCast(ExternalConstant(
      ExternalReference::
          typed_array_and_rab_gsab_typed_array_elements_kind_shifts()));
  return TNode<Uint8T>::UncheckedCast(
      Load(MachineType::Uint8(), shift_table, index));
}

TNode<Uint32T> JSGraphAssembler::LookupByteSizeForElementsKind(
    TNode<Uint32T> elements_kind) {
  TNode<UintPtrT> index = ChangeUint32ToUintPtr(Int32Sub(
      elements_kind, Uint32Constant(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)));
  TNode<RawPtrT> size_table = TNode<RawPtrT>::UncheckedCast(ExternalConstant(
      ExternalReference::
          typed_array_and_rab_gsab_typed_array_elements_kind_sizes()));
  return TNode<Uint8T>::UncheckedCast(
      Load(MachineType::Uint8(), size_table, index));
}

TNode<Object> JSGraphAssembler::JSCallRuntime1(
    Runtime::FunctionId function_id, TNode<Object> arg0, TNode<Context> context,
    std::optional<FrameState> frame_state, Operator::Properties properties) {
  return MayThrow([&]() {
    if (frame_state.has_value()) {
      return AddNode<Object>(graph()->NewNode(
          javascript()->CallRuntime(function_id, 1, properties), arg0, context,
          static_cast<Node*>(*frame_state), effect(), control()));
    } else {
      return AddNode<Object>(graph()->NewNode(
          javascript()->CallRuntime(function_id, 1, properties), arg0, context,
          effect(), control()));
    }
  });
}

TNode<Object> JSGraphAssembler::JSCallRuntime2(Runtime::FunctionId function_id,
                                               TNode<Object> arg0,
                                               TNode<Object> arg1,
                                               TNode<Context> context,
                                               FrameState frame_state) {
  return MayThrow([&]() {
    return AddNode<Object>(
        graph()->NewNode(javascript()->CallRuntime(function_id, 2), arg0, arg1,
                         context, frame_state, effect(), control()));
  });
}

Node* JSGraphAssembler::Chained(const Operator* op, Node* input) {
  DCHECK_EQ(op->ValueInputCount(), 1);
  return AddNode(
      graph()->NewNode(common()->Chained(op), input, effect(), control()));
}

Node* GraphAssembler::TypeGuard(Type type, Node* value) {
  return AddNode(
      graph()->NewNode(common()->TypeGuard(type), value, effect(), control()));
}

Node* GraphAssembler::Checkpoint(FrameState frame_state) {
  return AddNode(graph()->NewNode(common()->Checkpoint(), frame_state, effect(),
                                  control()));
}

Node* GraphAssembler::DebugBreak() {
  return AddNode(
      graph()->NewNode(machine()->DebugBreak(), effect(), control()));
}

Node* GraphAssembler::Unreachable() {
  Node* result = UnreachableWithoutConnectToEnd();
  ConnectUnreachableToEnd();
  InitializeEffectControl(nullptr, nullptr);
  return result;
}

Node* GraphAssembler::UnreachableWithoutConnectToEnd() {
  return AddNode(
      graph()->NewNode(common()->Unreachable(), effect(), control()));
}

TNode<RawPtrT> GraphAssembler::StackSlot(int size, int alignment,
                                         bool is_tagged) {
  return AddNode<RawPtrT>(
      graph()->NewNode(machine()->StackSlot(size, alignment, is_tagged)));
}

Node* GraphAssembler::AdaptLocalArgument(Node* argument) {
#ifdef V8_ENABLE_DIRECT_HANDLE
  // With direct locals, the argument can be passed directly.
  return BitcastTaggedToWord(argument);
#else
  // With indirect locals, the argument has to be stored on the stack and the
  // slot address is passed.
  Node* stack_slot = StackSlot(sizeof(uintptr_t), alignof(uintptr_t), true);
  Store(StoreRepresentation(MachineType::PointerRepresentation(),
                            kNoWriteBarrier),
        stack_slot, 0, BitcastTaggedToWord(argument));
  return stack_slot;
#endif
}

Node* GraphAssembler::Store(StoreRepresentation rep, Node* object, Node* offset,
                            Node* value) {
  return AddNode(graph()->NewNode(machine()->Store(rep), object, offset, value,
                                  effect(), control()));
}

Node* GraphAssembler::Store(StoreRepresentation rep, Node* object, int offset,
                            Node* value) {
  return Store(rep, object, IntPtrConstant(offset), value);
}

Node* GraphAssembler::Load(MachineType type, Node* object, Node* offset) {
  return AddNode(graph()->NewNode(machine()->Load(type), object, offset,
                                  effect(), control()));
}

Node* GraphAssembler::Load(MachineType type, Node* object, int offset) {
  return Load(type, object, IntPtrConstant(offset));
}

Node* GraphAssembler::StoreUnaligned(MachineRepresentation rep, Node* object,
                                     Node* offset, Node* value) {
  Operator const* const op =
      (rep == MachineRepresentation::kWord8 ||
       machine()->UnalignedStoreSupported(rep))
          ? machine()->Store(StoreRepresentation(rep, kNoWriteBarrier))
          : machine()->UnalignedStore(rep);
  return AddNode(
      graph()->NewNode(op, object, offset, value, effect(), control()));
}

Node* GraphAssembler::LoadUnaligned(MachineType type, Node* object,
                                    Node* offset) {
  Operator const* const op =
      (type.representation() == MachineRepresentation::kWord8 ||
       machine()->UnalignedLoadSupported(type.representation()))
          ? machine()->Load(type)
          : machine()->UnalignedLoad(type);
  return AddNode(graph()->NewNode(op, object, offset, effect(), control()));
}

Node* GraphAssembler::ProtectedStore(MachineRepresentation rep, Node* object,
                                     Node* offset, Node* value) {
  return AddNode(graph()->NewNode(machine()->ProtectedStore(rep), object,
                                  offset, value, effect(), control()));
}

Node* GraphAssembler::ProtectedLoad(MachineType type, Node* object,
                                    Node* offset) {
  return AddNode(graph()->NewNode(machine()->ProtectedLoad(type), object,
                                  offset, effect(), control()));
}

Node* GraphAssembler::LoadTrapOnNull(MachineType type, Node* object,
                                     Node* offset) {
  return AddNode(graph()->NewNode(machine()->LoadTrapOnNull(type), object,
                                  offset, effect(), control()));
}

Node* GraphAssembler::StoreTrapOnNull(StoreRepresentation rep, Node* object,
                                      Node* offset, Node* value) {
  return AddNode(graph()->NewNode(machine()->StoreTrapOnNull(rep), object,
                                  offset, value, effect(), control()));
}

Node* GraphAssembler::Retain(Node* buffer) {
  return AddNode(graph()->NewNode(common()->Retain(), buffer, effect()));
}

Node* GraphAssembler::IntPtrAdd(Node* a, Node* b) {
  return AddNode(graph()->NewNode(
      machine()->Is64() ? machine()->Int64Add() : machine()->Int32Add(), a, b));
}

Node* GraphAssembler::IntPtrSub(Node* a, Node* b) {
  return AddNode(graph()->NewNode(
      machine()->Is64() ? machine()->Int64Sub() : machine()->Int32Sub(), a, b));
}

TNode<Number> JSGraphAssembler::PlainPrimitiveToNumber(TNode<Object> value) {
  return AddNode<Number>(graph()->NewNode(
      PlainPrimitiveToNumberOperator(), PlainPrimitiveToNumberBuiltinConstant(),
      value, effect()));
}

Node* GraphAssembler::BitcastWordToTaggedSigned(Node* value) {
  return AddNode(
      graph()->NewNode(machine()->BitcastWordToTaggedSigned(), value));
}

Node* GraphAssembler::BitcastWordToTagged(Node* value) {
  return AddNode(graph()->NewNode(machine()->BitcastWordToTagged(), value,
                                  effect(), control()));
}

Node* GraphAssembler::BitcastTaggedToWord(Node* value) {
  return AddNode(graph()->NewNode(machine()->BitcastTaggedToWord(), value,
                                  effect(), control()));
}

Node* GraphAssembler::BitcastTaggedToWordForTagAndSmiBits(Node* value) {
  return AddNode(graph()->NewNode(
      machine()->BitcastTaggedToWordForTagAndSmiBits(), value));
}

Node* GraphAssembler::BitcastMaybeObjectToWord(Node* value) {
  return AddNode(graph()->NewNode(machine()->BitcastMaybeObjectToWord(), value,
                                  effect(), control()));
}

Node* GraphAssembler::DeoptimizeIf(DeoptimizeReason reason,
                                   FeedbackSource const& feedback,
                                   Node* condition, Node* frame_state) {
  return AddNode(graph()->NewNode(common()->DeoptimizeIf(reason, feedback),
                                  condition, frame_state, effect(), control()));
}

Node* GraphAssembler::DeoptimizeIfNot(DeoptimizeReason reason,
                                      FeedbackSource const& feedback,
                                      Node* condition, Node* frame_state) {
  return AddNode(graph()->NewNode(common()->DeoptimizeUnless(reason, feedback),
                                  condition, frame_state, effect(), control()));
}

TNode<Object> GraphAssembler::Call(const CallDescriptor* call_descriptor,
                                   int inputs_size, Node** inputs) {
  return Call(common()->Call(call_descriptor), inputs_size, inputs);
}

TNode<Object> GraphAssembler::Call(const Operator* op, int inputs_size,
                                   Node** inputs) {
  DCHECK_EQ(IrOpcode::kCall, op->opcode());
  return AddNode<Object>(graph()->NewNode(op, inputs_size, inputs));
}

void GraphAssembler::TailCall(const CallDescriptor* call_descriptor,
                              int inputs_size, Node** inputs) {
#ifdef DEBUG
  static constexpr int kTargetEffectControl = 3;
  DCHECK_EQ(inputs_size,
            call_descriptor->ParameterCount() + kTargetEffectControl);
#endif  // DEBUG

  Node* node = AddNode(graph()->NewNode(common()->TailCall(call_descriptor),
                                        inputs_size, inputs));

  // Unlike ConnectUnreachableToEnd, the TailCall node terminates a block; to
  // keep it live, it *must* be connected to End (also in Turboprop schedules).
  NodeProperties::MergeControlToEnd(graph(), common(), node);

  // Setting effect, control to nullptr effectively terminates the current block
  // by disallowing the addition of new nodes until a new label has been bound.
  InitializeEffectControl(nullptr, nullptr);
}

void GraphAssembler::BranchWithCriticalSafetyCheck(
    Node* condition, GraphAssemblerLabel<0u>* if_true,
    GraphAssemblerLabel<0u>* if_false) {
  BranchHint hint = BranchHint::kNone;
  if (if_true->IsDeferred() != if_false->IsDeferred()) {
    hint = if_false->IsDeferred() ? BranchHint::kTrue : BranchHint::kFalse;
  }

  BranchImpl(default_branch_semantics_, condition, if_true, if_false, hint);
}

void GraphAssembler::ConnectUnreachableToEnd() {
  DCHECK_EQ(effect()->opcode(), IrOpcode::kUnreachable);
  Node* throw_node = graph()->NewNode(common()->Throw(), effect(), control());
  NodeProperties::MergeControlToEnd(graph(), common(), throw_node);
  if (node_changed_callback_.has_value()) {
    (*node_changed_callback_)(graph()->end());
  }
  effect_ = control_ = mcgraph()->Dead();
}

Node* GraphAssembler::AddClonedNode(Node* node) {
  DCHECK(node->op()->HasProperty(Operator::kPure));
  UpdateEffectControlWith(node);
  return node;
}

Node* GraphAssembler::AddNode(Node* node) {
  if (!inline_reducers_.empty() && !inline_reductions_blocked_) {
    // Reducers may add new nodes to the graph using this graph assembler,
    // however they should never introduce nodes that need further reduction,
    // so block reduction
    BlockInlineReduction scope(this);
    Reduction reduction;
    for (auto reducer : inline_reducers_) {
      reduction = reducer->Reduce(node, nullptr);
      if (reduction.Changed()) break;
    }
    if (reduction.Changed()) {
      Node* replacement = reduction.replacement();
      if (replacement != node) {
        // Replace all uses of node and kill the node to make sure we don't
        // leave dangling dead uses.
        NodeProperties::ReplaceUses(node, replacement, effect(), control());
        node->Kill();
        return replacement;
      }
    }
  }

  if (node->opcode() == IrOpcode::kTerminate) {
    return node;
  }

  UpdateEffectControlWith(node);
  return node;
}

void GraphAssembler::Reset() {
  effect_ = nullptr;
  control_ = nullptr;
}

void GraphAssembler::InitializeEffectControl(Node* effect, Node* control) {
  effect_ = effect;
  control_ = control;
}

Operator const* JSGraphAssembler::PlainPrimitiveToNumberOperator() {
  if (!to_number_operator_.is_set()) {
    Callable callable =
        Builtins::CallableFor(isolate(), Builtin::kPlainPrimitiveToNumber);
    CallDescriptor::Flags flags = CallDescriptor::kNoFlags;
    auto call_descriptor = Linkage::GetStubCallDescriptor(
        graph()->zone(), callable.descriptor(),
        callable.descriptor().GetStackParameterCount(), flags,
        Operator::kEliminatable);
    to_number_operator_.set(common()->Call(call_descriptor));
  }
  return to_number_operator_.get();
}

}  // namespace compiler
}  // namespace internal
}  // namespace v8
```