Response:
My thinking process to analyze the provided C++ code snippet follows these steps:

1. **Identify the Core Functionality:** The filename `code-stub-assembler.cc` and the class name `CodeStubAssembler` strongly suggest this code is about generating low-level code stubs. The presence of functions like `LoadArrayElement`, `LoadFixedArrayElement`, and functions dealing with weak references confirms this. It's about manipulating data structures at a very granular level within the V8 engine.

2. **Categorize Functions by Purpose:** I start grouping the functions based on what they seem to be doing:
    * **Weak References:**  Functions like `IsStrong`, `GetHeapObjectIfStrong`, `IsWeakOrCleared`, `IsCleared`, `GetHeapObjectAssumeWeak`, `IsWeakReferenceToObject`, `IsWeakReferenceTo`, `MakeWeak`, and `ClearedValue`. These clearly deal with the concept of weak references in V8's garbage collection.
    * **Array/Data Loading:** Functions like `LoadArrayLength`, `LoadArrayElement`, `LoadFixedArrayElement`, `LoadPropertyArrayElement`, `LoadJSTypedArrayDataPtr`, `LoadFixedBigInt64ArrayElementAsTagged`, `LoadFixedTypedArrayElementAsTagged`, `LoadFeedbackVectorSlot`, `LoadWeakFixedArrayElement`, `LoadFixedDoubleArrayElement`, and `LoadFixedArrayBaseElementAsTagged`. These are all about reading data from various array-like structures within V8's memory.
    * **BigInt Handling:** Functions like `BigIntFromInt32Pair`, `BigIntFromInt64`, `BigIntFromUint32Pair`, and `BigIntFromUint64`. These deal specifically with converting integer values to V8's BigInt representation.
    * **Bounds Checking:** Functions like `FixedArrayBoundsCheck`. This is related to safety and ensuring array accesses are within valid ranges.
    * **Context/Scope Handling:** Functions like `LoadScopeInfo`, `LoadScopeInfoHasExtensionField`, `LoadScopeInfoClassScopeHasPrivateBrand`, `StoreContextElementNoWriteBarrier`, `LoadNativeContext`, `LoadModuleContext`, `GetImportMetaObject`, and `LoadObjectFunctionInitialMap`. These deal with V8's context and scope management, crucial for JavaScript execution.
    * **Map Cache:** Functions like `LoadCachedMap`. This relates to optimizing object property access by caching frequently used Maps.
    * **Double Hole Handling:** Functions like `IsDoubleHole` and `LoadDoubleWithHoleCheck`. These are related to handling "holes" in double arrays, a performance optimization.

3. **Identify Key Concepts and Data Structures:** As I categorize, I note down the key concepts and data structures being manipulated:
    * **HeapObject:** The base class for most V8 objects in the heap.
    * **HeapObjectReference:** A weak reference to a HeapObject.
    * **MaybeObject:**  Represents either a HeapObject or a Smi (small integer).
    * **FixedArray, PropertyArray, DescriptorArray, TransitionArray, WeakFixedArray, TrustedFixedArray, ClosureFeedbackCellArray, RegExpMatchInfo, ScriptContextTable:**  Various specialized array types in V8.
    * **JSTypedArray:**  JavaScript's Typed Arrays.
    * **BigInt:**  JavaScript's BigInt type.
    * **FeedbackVector:**  Used for collecting feedback on function execution for optimization.
    * **Context, ScopeInfo, NativeContext:**  Data structures related to JavaScript execution context and scope.
    * **Map:**  Describes the structure and properties of an object.
    * **ElementsKind:**  An enumeration describing the type of elements in an array.
    * **Smi:**  Small integers encoded directly in pointers.

4. **Analyze Individual Functions:** For each function, I try to understand its specific purpose:
    * **Input and Output Types:** What kind of data does it take, and what does it return?
    * **Core Logic:** What are the essential steps the function performs?  Are there conditional branches or loops?
    * **Assumptions and Preconditions:** Does the function rely on certain conditions being true (e.g., `CSA_DCHECK`)?
    * **Relationship to Other Functions:** How does this function interact with other functions in the snippet?

5. **Look for Conditional Logic and Examples:**  I pay attention to `GotoIf`, `Branch`, and `Switch` statements, as these indicate different code paths. I consider what input values would lead to these different paths. This helps in understanding the "if-else" logic embedded within the code. I try to formulate simple JavaScript scenarios that might trigger these code paths (even if the C++ code doesn't directly *execute* JavaScript).

6. **Infer JavaScript Relevance:** I connect the C++ code back to JavaScript functionality. For instance, functions dealing with Typed Arrays are directly related to the JavaScript `TypedArray` objects. Functions involving `Context` and `ScopeInfo` are essential for how JavaScript manages variables and function scope. Weak references are a garbage collection mechanism that allows JavaScript objects to be collected when they are no longer strongly reachable.

7. **Identify Potential Programming Errors:** Based on the functionality, I think about common mistakes developers make in JavaScript that might relate to this low-level code. For example, accessing array elements out of bounds, working with weak references incorrectly, or misunderstanding the behavior of Typed Arrays.

8. **Synthesize the Summary:** Finally, I combine my understanding of the individual functions and their relationships to create a concise summary of the code's overall purpose. I focus on the key areas of functionality and the role of `CodeStubAssembler`. I also explicitly address the prompt's questions about `.tq` files and JavaScript relevance.

By following this structured approach, I can systematically analyze the C++ code snippet and derive a comprehensive understanding of its functionality within the V8 engine. The key is to break down the code into smaller, manageable parts and then build back up to the overall picture.
这是 V8 源代码文件 `v8/src/codegen/code-stub-assembler.cc` 的第 4 部分，共 23 部分。根据提供的代码片段，我们可以归纳出以下功能：

**总体功能归纳：**

这个代码片段主要提供了 `CodeStubAssembler` 类中用于**处理弱引用、数组操作（特别是 Typed Arrays 和 Fixed Arrays）以及与执行上下文相关的操作**的工具函数。这些函数是为了在生成代码桩（code stubs）时提供便捷的操作，代码桩是 V8 编译和执行 JavaScript 代码的关键组成部分。

**具体功能列举：**

1. **弱引用处理:**
   - `IsStrong(TNode<MaybeObject>)`, `IsStrong(TNode<HeapObjectReference>)`:  检查给定的值是否为强引用。
   - `GetHeapObjectIfStrong(TNode<MaybeObject>, Label*)`, `GetHeapObjectIfStrong(TNode<HeapObjectReference>, Label*)`: 如果是强引用，则返回堆对象，否则跳转到指定的标签。
   - `IsWeakOrCleared(TNode<MaybeObject>)`, `IsWeakOrCleared(TNode<HeapObjectReference>)`: 检查值是否为弱引用或已清除的弱引用。
   - `IsCleared(TNode<MaybeObject>)`: 检查值是否为已清除的弱引用。
   - `GetHeapObjectAssumeWeak(TNode<MaybeObject>)`, `GetHeapObjectAssumeWeak(TNode<MaybeObject>, Label*)`:  假定是弱引用并获取堆对象，可以选择在清除时跳转。
   - `IsWeakReferenceToObject(TNode<MaybeObject>, TNode<Object>)`: 检查一个 `MaybeObject` 是否是对特定对象的弱引用。
   - `IsWeakReferenceTo(TNode<MaybeObject>, TNode<HeapObject>)`: 检查一个 `MaybeObject` 是否是对特定堆对象的弱引用。
   - `MakeWeak(TNode<HeapObject>)`: 将一个堆对象转换为弱引用。
   - `ClearedValue()`: 返回表示已清除弱引用的特殊值。

2. **数组长度加载:**
   - 针对不同类型的数组（`FixedArray`, `ClosureFeedbackCellArray`, `ScriptContextTable`, `RegExpMatchInfo`, `WeakFixedArray`, `PropertyArray`, `DescriptorArray`, `TransitionArray`, `TrustedFixedArray`）提供了 `LoadArrayLength` 模板函数的特化版本，用于加载数组的长度。

3. **数组元素加载:**
   - `LoadArrayElement`:  一个通用的模板函数，用于加载各种类型数组的元素，可以指定偏移量。
   - `LoadFixedArrayElement`: 用于加载 `FixedArray` 的元素，可以选择进行越界检查。
   - `LoadPropertyArrayElement`: 用于加载 `PropertyArray` 的元素。
   - `LoadWeakFixedArrayElement`: 用于加载 `WeakFixedArray` 的元素。
   - `LoadFixedDoubleArrayElement`: 用于加载 `FixedDoubleArray` 的元素，并可以检查是否为 hole。
   - `LoadFixedArrayBaseElementAsTagged`:  根据元素的种类加载 `FixedArrayBase` 的元素，并能处理 accessor 和 hole 的情况。
   - `LoadFeedbackVectorSlot`: 用于加载 `FeedbackVector` 的槽位。
   - `LoadAndUntagToWord32ArrayElement`, `LoadAndUntagToWord32FixedArrayElement`:  加载数组元素并去除 Tag，转换为 32 位整数。

4. **Typed Array 操作:**
   - `LoadJSTypedArrayDataPtr`: 获取 `JSTypedArray` 的数据指针。
   - `LoadFixedBigInt64ArrayElementAsTagged`, `LoadFixedBigUint64ArrayElementAsTagged`:  加载 `BigInt64Array` 和 `BigUint64Array` 的元素并转换为 Tagged 的 `BigInt`。
   - `BigIntFromInt32Pair`, `BigIntFromInt64`, `BigIntFromUint32Pair`, `BigIntFromUint64`:  将整数值转换为 `BigInt` 对象。
   - `LoadFixedTypedArrayElementAsTagged`:  根据元素类型加载各种 `TypedArray` 的元素并转换为 Tagged 的数值或 `BigInt`。

5. **边界检查:**
   - `FixedArrayBoundsCheck`:  用于在调试模式下检查 `FixedArray` 的访问是否越界。

6. **Double 类型的特殊处理:**
   - `IsDoubleHole`: 检查给定的偏移量是否对应一个 double 类型的 hole。
   - `LoadDoubleWithHoleCheck`: 加载 double 类型的值，可以选择在遇到 hole 时跳转。

7. **上下文 (Context) 和作用域 (Scope) 操作:**
   - `LoadScopeInfo`: 加载 `Context` 的 `ScopeInfo`。
   - `LoadScopeInfoHasExtensionField`, `LoadScopeInfoClassScopeHasPrivateBrand`: 检查 `ScopeInfo` 中的特定标志位。
   - `StoreContextElementNoWriteBarrier`:  存储 `Context` 的元素，不使用写屏障（通常用于性能关键的内部操作）。
   - `LoadNativeContext`: 加载 `Context` 的 `NativeContext`。
   - `LoadModuleContext`: 加载 `Context` 的 `ModuleContext`。
   - `GetImportMetaObject`: 获取模块的 `import.meta` 对象。
   - `LoadObjectFunctionInitialMap`: 加载 `Object` 构造函数的初始 Map。

8. **Map 缓存:**
   - `LoadCachedMap`: 从 NativeContext 的 Map 缓存中加载 Map 对象。

**如果 `v8/src/codegen/code-stub-assembler.cc` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 用于定义运行时函数的领域特定语言，它比直接编写 C++ 更安全、更易于维护。Torque 代码会被编译成 C++ 代码。

**与 JavaScript 功能的关系及示例:**

这些 `CodeStubAssembler` 中的函数直接支撑着 V8 执行 JavaScript 代码的底层操作。以下是一些 JavaScript 功能与这些 C++ 函数的关联示例：

* **弱引用 (Weak References):**  JavaScript 的 `WeakRef` 和 `FinalizationRegistry` API 的实现会用到这里提供的弱引用处理函数。
   ```javascript
   let target = {};
   let weakRef = new WeakRef(target);

   // 在 C++ 层面，当垃圾回收器运行时，会使用类似 `IsWeakOrCleared` 的函数来检查 `weakRef` 引用的对象是否还存活。
   ```

* **数组操作 (Array Operations):** JavaScript 中对数组的访问、修改，特别是 `TypedArray` 的操作，会直接或间接地使用这些数组加载函数。
   ```javascript
   let arr = new Uint32Array(10);
   let value = arr[5]; //  在底层，V8 可能会调用类似 `LoadFixedTypedArrayElementAsTagged` 的函数来读取元素。

   let fixedArr = [1, 2, 3];
   let val = fixedArr[1]; // 底层可能使用 `LoadFixedArrayElement`。
   ```

* **BigInt 操作 (BigInt Operations):**  当 JavaScript 中使用 `BigInt` 类型时，这些 C++ 的 `BigIntFrom...` 函数用于创建和操作 `BigInt` 对象。
   ```javascript
   let bigIntVal = 9007199254740991n; //  V8 在内部会使用类似 `BigIntFromInt64` 的函数来表示这个 BigInt。
   ```

* **上下文和作用域 (Context and Scope):** JavaScript 的变量查找、闭包的实现都依赖于 V8 的上下文和作用域机制。这些 C++ 函数用于加载和操作上下文信息。
   ```javascript
   function outer() {
     let x = 10;
     function inner() {
       console.log(x); // V8 需要查找 `x` 变量，这涉及到加载作用域信息。
     }
     return inner;
   }
   let closure = outer();
   closure();
   ```

**代码逻辑推理和假设输入/输出:**

以 `IsWeakOrCleared(TNode<MaybeObject> value)` 为例：

* **假设输入:** 一个 `TNode<MaybeObject>`，它可以指向一个堆对象或一个 Smi。
    * **输入 1 (强引用):**  `value` 指向一个普通的堆对象（例如，一个 JavaScript 对象）。
    * **输入 2 (弱引用):** `value` 指向一个弱引用对象。
    * **输入 3 (已清除的弱引用):** `value` 指向一个已被垃圾回收器清除的弱引用。
    * **输入 4 (Smi):** `value` 是一个 Smi 值。

* **代码逻辑:** 函数会检查 `value` 的标签位，判断其是否为弱引用或已清除的弱引用。Smi 值会有不同的标签，强引用也有其自身的标签。

* **输出:** 一个 `TNode<BoolT>`，表示真或假。
    * **输入 1 输出:** `false` (强引用不是弱引用或已清除的)
    * **输入 2 输出:** `true` (弱引用)
    * **输入 3 输出:** `true` (已清除的弱引用)
    * **输入 4 输出:** `false` (Smi 不是弱引用)

**用户常见的编程错误举例:**

与这些 C++ 代码相关的常见 JavaScript 编程错误可能包括：

* **意外地依赖弱引用指向的对象仍然存在:**
   ```javascript
   let target = { data: 1 };
   let weakRef = new WeakRef(target);
   target = null; // 解除强引用

   // 错误地假设 weakRef.deref() 总是返回对象
   if (weakRef.deref()) {
     console.log(weakRef.deref().data); // 如果对象已被回收，这将导致错误。
   }
   ```

* **在 Typed Array 操作中越界访问:**
   ```javascript
   let arr = new Int32Array(5);
   arr[10] = 10; // 这是一个越界访问，虽然 JavaScript 引擎可能会处理，但在底层，这些 C++ 的边界检查函数是为了确保内存安全。
   ```

**总结第 4 部分的功能:**

第 4 部分的 `v8/src/codegen/code-stub-assembler.cc` 提供了 `CodeStubAssembler` 类中用于处理弱引用、各种类型的数组操作（包括 Typed Arrays 和 Fixed Arrays）、BigInt 操作以及与 JavaScript 执行上下文和作用域相关的底层工具函数。这些函数是 V8 生成高效代码桩的关键组成部分，直接支持着 JavaScript 语言的各种特性和运行时行为。

Prompt: 
```
这是目录为v8/src/codegen/code-stub-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/codegen/code-stub-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第4部分，共23部分，请归纳一下它的功能

"""
t> value, Label* if_not_strong) {
  GotoIfNot(IsStrong(value), if_not_strong);
  return CAST(value);
}

TNode<HeapObject> CodeStubAssembler::GetHeapObjectIfStrong(
    TNode<HeapObjectReference> value, Label* if_not_strong) {
  GotoIfNot(IsStrong(value), if_not_strong);
  return ReinterpretCast<HeapObject>(value);
}

TNode<BoolT> CodeStubAssembler::IsWeakOrCleared(TNode<MaybeObject> value) {
  return Word32Equal(Word32And(TruncateIntPtrToInt32(
                                   BitcastTaggedToWordForTagAndSmiBits(value)),
                               Int32Constant(kHeapObjectTagMask)),
                     Int32Constant(kWeakHeapObjectTag));
}

TNode<BoolT> CodeStubAssembler::IsWeakOrCleared(
    TNode<HeapObjectReference> value) {
  return IsSetWord32(
      TruncateIntPtrToInt32(BitcastTaggedToWordForTagAndSmiBits(value)),
      kHeapObjectReferenceTagMask);
}

TNode<BoolT> CodeStubAssembler::IsCleared(TNode<MaybeObject> value) {
  return Word32Equal(TruncateIntPtrToInt32(BitcastMaybeObjectToWord(value)),
                     Int32Constant(kClearedWeakHeapObjectLower32));
}

TNode<HeapObject> CodeStubAssembler::GetHeapObjectAssumeWeak(
    TNode<MaybeObject> value) {
  CSA_DCHECK(this, IsWeakOrCleared(value));
  CSA_DCHECK(this, IsNotCleared(value));
  return UncheckedCast<HeapObject>(BitcastWordToTagged(WordAnd(
      BitcastMaybeObjectToWord(value), IntPtrConstant(~kWeakHeapObjectMask))));
}

TNode<HeapObject> CodeStubAssembler::GetHeapObjectAssumeWeak(
    TNode<MaybeObject> value, Label* if_cleared) {
  GotoIf(IsCleared(value), if_cleared);
  return GetHeapObjectAssumeWeak(value);
}

// This version generates
//   (maybe_object & ~mask) == value
// It works for non-Smi |maybe_object| and for both Smi and HeapObject values
// but requires a big constant for ~mask.
TNode<BoolT> CodeStubAssembler::IsWeakReferenceToObject(
    TNode<MaybeObject> maybe_object, TNode<Object> value) {
  CSA_DCHECK(this, TaggedIsNotSmi(maybe_object));
  if (COMPRESS_POINTERS_BOOL) {
    return Word32Equal(
        Word32And(TruncateWordToInt32(BitcastMaybeObjectToWord(maybe_object)),
                  Uint32Constant(~static_cast<uint32_t>(kWeakHeapObjectMask))),
        TruncateWordToInt32(BitcastTaggedToWord(value)));
  } else {
    return WordEqual(WordAnd(BitcastMaybeObjectToWord(maybe_object),
                             IntPtrConstant(~kWeakHeapObjectMask)),
                     BitcastTaggedToWord(value));
  }
}

// This version generates
//   maybe_object == (heap_object | mask)
// It works for any |maybe_object| values and generates a better code because it
// uses a small constant for mask.
TNode<BoolT> CodeStubAssembler::IsWeakReferenceTo(
    TNode<MaybeObject> maybe_object, TNode<HeapObject> heap_object) {
  if (COMPRESS_POINTERS_BOOL) {
    return Word32Equal(
        TruncateWordToInt32(BitcastMaybeObjectToWord(maybe_object)),
        Word32Or(TruncateWordToInt32(BitcastTaggedToWord(heap_object)),
                 Int32Constant(kWeakHeapObjectMask)));
  } else {
    return WordEqual(BitcastMaybeObjectToWord(maybe_object),
                     WordOr(BitcastTaggedToWord(heap_object),
                            IntPtrConstant(kWeakHeapObjectMask)));
  }
}

TNode<HeapObjectReference> CodeStubAssembler::MakeWeak(
    TNode<HeapObject> value) {
  return ReinterpretCast<HeapObjectReference>(BitcastWordToTagged(
      WordOr(BitcastTaggedToWord(value), IntPtrConstant(kWeakHeapObjectTag))));
}

TNode<MaybeObject> CodeStubAssembler::ClearedValue() {
  return ReinterpretCast<MaybeObject>(
      BitcastWordToTagged(IntPtrConstant(kClearedWeakHeapObjectLower32)));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(TNode<FixedArray> array) {
  return LoadAndUntagFixedArrayBaseLength(array);
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<ClosureFeedbackCellArray> array) {
  return SmiUntag(LoadSmiArrayLength(array));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<ScriptContextTable> array) {
  return SmiUntag(LoadSmiArrayLength(array));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<RegExpMatchInfo> array) {
  return SmiUntag(LoadSmiArrayLength(array));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(TNode<WeakFixedArray> array) {
  return LoadAndUntagWeakFixedArrayLength(array);
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(TNode<PropertyArray> array) {
  return LoadPropertyArrayLength(array);
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<DescriptorArray> array) {
  return IntPtrMul(ChangeInt32ToIntPtr(LoadNumberOfDescriptors(array)),
                   IntPtrConstant(DescriptorArray::kEntrySize));
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<TransitionArray> array) {
  return LoadAndUntagWeakFixedArrayLength(array);
}

template <>
TNode<IntPtrT> CodeStubAssembler::LoadArrayLength(
    TNode<TrustedFixedArray> array) {
  return SmiUntag(LoadSmiArrayLength(array));
}

template <typename Array, typename TIndex, typename TValue>
TNode<TValue> CodeStubAssembler::LoadArrayElement(TNode<Array> array,
                                                  int array_header_size,
                                                  TNode<TIndex> index_node,
                                                  int additional_offset) {
  // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
  static_assert(
      std::is_same<TIndex, Smi>::value ||
          std::is_same<TIndex, UintPtrT>::value ||
          std::is_same<TIndex, IntPtrT>::value ||
          std::is_same<TIndex, TaggedIndex>::value,
      "Only Smi, UintPtrT, IntPtrT or TaggedIndex indices are allowed");
  CSA_DCHECK(this, IntPtrGreaterThanOrEqual(ParameterToIntPtr(index_node),
                                            IntPtrConstant(0)));
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  int32_t header_size = array_header_size + additional_offset - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index_node, HOLEY_ELEMENTS, header_size);
  CSA_DCHECK(this, IsOffsetInBounds(offset, LoadArrayLength(array),
                                    array_header_size));
  constexpr MachineType machine_type = MachineTypeOf<TValue>::value;
  return UncheckedCast<TValue>(LoadFromObject(machine_type, array, offset));
}

template V8_EXPORT_PRIVATE TNode<MaybeObject>
CodeStubAssembler::LoadArrayElement<TransitionArray, IntPtrT>(
    TNode<TransitionArray>, int, TNode<IntPtrT>, int);
template V8_EXPORT_PRIVATE TNode<FeedbackCell>
CodeStubAssembler::LoadArrayElement<ClosureFeedbackCellArray, UintPtrT>(
    TNode<ClosureFeedbackCellArray>, int, TNode<UintPtrT>, int);
template V8_EXPORT_PRIVATE TNode<Smi> CodeStubAssembler::LoadArrayElement<
    RegExpMatchInfo, IntPtrT>(TNode<RegExpMatchInfo>, int, TNode<IntPtrT>, int);
template V8_EXPORT_PRIVATE TNode<Context>
CodeStubAssembler::LoadArrayElement<ScriptContextTable, IntPtrT>(
    TNode<ScriptContextTable>, int, TNode<IntPtrT>, int);
template V8_EXPORT_PRIVATE TNode<MaybeObject>
CodeStubAssembler::LoadArrayElement<TrustedFixedArray, IntPtrT>(
    TNode<TrustedFixedArray>, int, TNode<IntPtrT>, int);

template <typename TIndex>
TNode<Object> CodeStubAssembler::LoadFixedArrayElement(
    TNode<FixedArray> object, TNode<TIndex> index, int additional_offset,
    CheckBounds check_bounds) {
  // TODO(v8:9708): Do we want to keep both IntPtrT and UintPtrT variants?
  static_assert(
      std::is_same<TIndex, Smi>::value ||
          std::is_same<TIndex, UintPtrT>::value ||
          std::is_same<TIndex, IntPtrT>::value ||
          std::is_same<TIndex, TaggedIndex>::value,
      "Only Smi, UintPtrT, IntPtrT or TaggedIndex indexes are allowed");
  CSA_DCHECK(this, IsFixedArraySubclass(object));
  CSA_DCHECK(this, IsNotWeakFixedArraySubclass(object));

  if (NeedsBoundsCheck(check_bounds)) {
    FixedArrayBoundsCheck(object, index, additional_offset);
  }
  TNode<MaybeObject> element = LoadArrayElement(
      object, OFFSET_OF_DATA_START(FixedArray), index, additional_offset);
  return CAST(element);
}

template V8_EXPORT_PRIVATE TNode<Object>
CodeStubAssembler::LoadFixedArrayElement<Smi>(TNode<FixedArray>, TNode<Smi>,
                                              int, CheckBounds);
template V8_EXPORT_PRIVATE TNode<Object>
CodeStubAssembler::LoadFixedArrayElement<TaggedIndex>(TNode<FixedArray>,
                                                      TNode<TaggedIndex>, int,
                                                      CheckBounds);
template V8_EXPORT_PRIVATE TNode<Object>
CodeStubAssembler::LoadFixedArrayElement<UintPtrT>(TNode<FixedArray>,
                                                   TNode<UintPtrT>, int,
                                                   CheckBounds);
template V8_EXPORT_PRIVATE TNode<Object>
CodeStubAssembler::LoadFixedArrayElement<IntPtrT>(TNode<FixedArray>,
                                                  TNode<IntPtrT>, int,
                                                  CheckBounds);

void CodeStubAssembler::FixedArrayBoundsCheck(TNode<FixedArrayBase> array,
                                              TNode<Smi> index,
                                              int additional_offset) {
  if (!v8_flags.fixed_array_bounds_checks) return;
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  TNode<Smi> effective_index;
  Tagged<Smi> constant_index;
  bool index_is_constant = TryToSmiConstant(index, &constant_index);
  if (index_is_constant) {
    effective_index = SmiConstant(Smi::ToInt(constant_index) +
                                  additional_offset / kTaggedSize);
  } else {
    effective_index =
        SmiAdd(index, SmiConstant(additional_offset / kTaggedSize));
  }
  CSA_CHECK(this, SmiBelow(effective_index, LoadFixedArrayBaseLength(array)));
}

void CodeStubAssembler::FixedArrayBoundsCheck(TNode<FixedArrayBase> array,
                                              TNode<IntPtrT> index,
                                              int additional_offset) {
  if (!v8_flags.fixed_array_bounds_checks) return;
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  // IntPtrAdd does constant-folding automatically.
  TNode<IntPtrT> effective_index =
      IntPtrAdd(index, IntPtrConstant(additional_offset / kTaggedSize));
  CSA_CHECK(this, UintPtrLessThan(effective_index,
                                  LoadAndUntagFixedArrayBaseLength(array)));
}

TNode<Object> CodeStubAssembler::LoadPropertyArrayElement(
    TNode<PropertyArray> object, TNode<IntPtrT> index) {
  int additional_offset = 0;
  return CAST(LoadArrayElement(object, PropertyArray::kHeaderSize, index,
                               additional_offset));
}

void CodeStubAssembler::FixedArrayBoundsCheck(TNode<FixedArrayBase> array,
                                              TNode<TaggedIndex> index,
                                              int additional_offset) {
  if (!v8_flags.fixed_array_bounds_checks) return;
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  // IntPtrAdd does constant-folding automatically.
  TNode<IntPtrT> effective_index =
      IntPtrAdd(TaggedIndexToIntPtr(index),
                IntPtrConstant(additional_offset / kTaggedSize));
  CSA_CHECK(this, UintPtrLessThan(effective_index,
                                  LoadAndUntagFixedArrayBaseLength(array)));
}

TNode<IntPtrT> CodeStubAssembler::LoadPropertyArrayLength(
    TNode<PropertyArray> object) {
  TNode<Int32T> value = LoadAndUntagToWord32ObjectField(
      object, PropertyArray::kLengthAndHashOffset);
  return Signed(
      ChangeUint32ToWord(DecodeWord32<PropertyArray::LengthField>(value)));
}

TNode<RawPtrT> CodeStubAssembler::LoadJSTypedArrayDataPtr(
    TNode<JSTypedArray> typed_array) {
  // Data pointer = external_pointer + static_cast<Tagged_t>(base_pointer).
  TNode<RawPtrT> external_pointer =
      LoadJSTypedArrayExternalPointerPtr(typed_array);

  TNode<IntPtrT> base_pointer;
  if (COMPRESS_POINTERS_BOOL) {
    TNode<Int32T> compressed_base =
        LoadObjectField<Int32T>(typed_array, JSTypedArray::kBasePointerOffset);
    // Zero-extend TaggedT to WordT according to current compression scheme
    // so that the addition with |external_pointer| (which already contains
    // compensated offset value) below will decompress the tagged value.
    // See JSTypedArray::ExternalPointerCompensationForOnHeapArray() for
    // details.
    base_pointer = Signed(ChangeUint32ToWord(compressed_base));
  } else {
    base_pointer =
        LoadObjectField<IntPtrT>(typed_array, JSTypedArray::kBasePointerOffset);
  }
  return RawPtrAdd(external_pointer, base_pointer);
}

TNode<BigInt> CodeStubAssembler::LoadFixedBigInt64ArrayElementAsTagged(
    TNode<RawPtrT> data_pointer, TNode<IntPtrT> offset) {
  if (Is64()) {
    TNode<IntPtrT> value = Load<IntPtrT>(data_pointer, offset);
    return BigIntFromInt64(value);
  } else {
    DCHECK(!Is64());
#if defined(V8_TARGET_BIG_ENDIAN)
    TNode<IntPtrT> high = Load<IntPtrT>(data_pointer, offset);
    TNode<IntPtrT> low = Load<IntPtrT>(
        data_pointer, IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)));
#else
    TNode<IntPtrT> low = Load<IntPtrT>(data_pointer, offset);
    TNode<IntPtrT> high = Load<IntPtrT>(
        data_pointer, IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)));
#endif
    return BigIntFromInt32Pair(low, high);
  }
}

TNode<BigInt> CodeStubAssembler::BigIntFromInt32Pair(TNode<IntPtrT> low,
                                                     TNode<IntPtrT> high) {
  DCHECK(!Is64());
  TVARIABLE(BigInt, var_result);
  TVARIABLE(Word32T, var_sign, Int32Constant(BigInt::SignBits::encode(false)));
  TVARIABLE(IntPtrT, var_high, high);
  TVARIABLE(IntPtrT, var_low, low);
  Label high_zero(this), negative(this), allocate_one_digit(this),
      allocate_two_digits(this), if_zero(this), done(this);

  GotoIf(IntPtrEqual(var_high.value(), IntPtrConstant(0)), &high_zero);
  Branch(IntPtrLessThan(var_high.value(), IntPtrConstant(0)), &negative,
         &allocate_two_digits);

  BIND(&high_zero);
  Branch(IntPtrEqual(var_low.value(), IntPtrConstant(0)), &if_zero,
         &allocate_one_digit);

  BIND(&negative);
  {
    var_sign = Int32Constant(BigInt::SignBits::encode(true));
    // We must negate the value by computing "0 - (high|low)", performing
    // both parts of the subtraction separately and manually taking care
    // of the carry bit (which is 1 iff low != 0).
    var_high = IntPtrSub(IntPtrConstant(0), var_high.value());
    Label carry(this), no_carry(this);
    Branch(IntPtrEqual(var_low.value(), IntPtrConstant(0)), &no_carry, &carry);
    BIND(&carry);
    var_high = IntPtrSub(var_high.value(), IntPtrConstant(1));
    Goto(&no_carry);
    BIND(&no_carry);
    var_low = IntPtrSub(IntPtrConstant(0), var_low.value());
    // var_high was non-zero going into this block, but subtracting the
    // carry bit from it could bring us back onto the "one digit" path.
    Branch(IntPtrEqual(var_high.value(), IntPtrConstant(0)),
           &allocate_one_digit, &allocate_two_digits);
  }

  BIND(&allocate_one_digit);
  {
    var_result = AllocateRawBigInt(IntPtrConstant(1));
    StoreBigIntBitfield(var_result.value(),
                        Word32Or(var_sign.value(),
                                 Int32Constant(BigInt::LengthBits::encode(1))));
    StoreBigIntDigit(var_result.value(), 0, Unsigned(var_low.value()));
    Goto(&done);
  }

  BIND(&allocate_two_digits);
  {
    var_result = AllocateRawBigInt(IntPtrConstant(2));
    StoreBigIntBitfield(var_result.value(),
                        Word32Or(var_sign.value(),
                                 Int32Constant(BigInt::LengthBits::encode(2))));
    StoreBigIntDigit(var_result.value(), 0, Unsigned(var_low.value()));
    StoreBigIntDigit(var_result.value(), 1, Unsigned(var_high.value()));
    Goto(&done);
  }

  BIND(&if_zero);
  var_result = AllocateBigInt(IntPtrConstant(0));
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

TNode<BigInt> CodeStubAssembler::BigIntFromInt64(TNode<IntPtrT> value) {
  DCHECK(Is64());
  TVARIABLE(BigInt, var_result);
  Label done(this), if_positive(this), if_negative(this), if_zero(this);
  GotoIf(IntPtrEqual(value, IntPtrConstant(0)), &if_zero);
  var_result = AllocateRawBigInt(IntPtrConstant(1));
  Branch(IntPtrGreaterThan(value, IntPtrConstant(0)), &if_positive,
         &if_negative);

  BIND(&if_positive);
  {
    StoreBigIntBitfield(var_result.value(),
                        Int32Constant(BigInt::SignBits::encode(false) |
                                      BigInt::LengthBits::encode(1)));
    StoreBigIntDigit(var_result.value(), 0, Unsigned(value));
    Goto(&done);
  }

  BIND(&if_negative);
  {
    StoreBigIntBitfield(var_result.value(),
                        Int32Constant(BigInt::SignBits::encode(true) |
                                      BigInt::LengthBits::encode(1)));
    StoreBigIntDigit(var_result.value(), 0,
                     Unsigned(IntPtrSub(IntPtrConstant(0), value)));
    Goto(&done);
  }

  BIND(&if_zero);
  {
    var_result = AllocateBigInt(IntPtrConstant(0));
    Goto(&done);
  }

  BIND(&done);
  return var_result.value();
}

TNode<BigInt> CodeStubAssembler::LoadFixedBigUint64ArrayElementAsTagged(
    TNode<RawPtrT> data_pointer, TNode<IntPtrT> offset) {
  Label if_zero(this), done(this);
  if (Is64()) {
    TNode<UintPtrT> value = Load<UintPtrT>(data_pointer, offset);
    return BigIntFromUint64(value);
  } else {
    DCHECK(!Is64());
#if defined(V8_TARGET_BIG_ENDIAN)
    TNode<UintPtrT> high = Load<UintPtrT>(data_pointer, offset);
    TNode<UintPtrT> low = Load<UintPtrT>(
        data_pointer, IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)));
#else
    TNode<UintPtrT> low = Load<UintPtrT>(data_pointer, offset);
    TNode<UintPtrT> high = Load<UintPtrT>(
        data_pointer, IntPtrAdd(offset, IntPtrConstant(kSystemPointerSize)));
#endif
    return BigIntFromUint32Pair(low, high);
  }
}

TNode<BigInt> CodeStubAssembler::BigIntFromUint32Pair(TNode<UintPtrT> low,
                                                      TNode<UintPtrT> high) {
  DCHECK(!Is64());
  TVARIABLE(BigInt, var_result);
  Label high_zero(this), if_zero(this), done(this);

  GotoIf(IntPtrEqual(high, IntPtrConstant(0)), &high_zero);
  var_result = AllocateBigInt(IntPtrConstant(2));
  StoreBigIntDigit(var_result.value(), 0, low);
  StoreBigIntDigit(var_result.value(), 1, high);
  Goto(&done);

  BIND(&high_zero);
  GotoIf(IntPtrEqual(low, IntPtrConstant(0)), &if_zero);
  var_result = AllocateBigInt(IntPtrConstant(1));
  StoreBigIntDigit(var_result.value(), 0, low);
  Goto(&done);

  BIND(&if_zero);
  var_result = AllocateBigInt(IntPtrConstant(0));
  Goto(&done);

  BIND(&done);
  return var_result.value();
}

TNode<BigInt> CodeStubAssembler::BigIntFromUint64(TNode<UintPtrT> value) {
  DCHECK(Is64());
  TVARIABLE(BigInt, var_result);
  Label done(this), if_zero(this);
  GotoIf(IntPtrEqual(value, IntPtrConstant(0)), &if_zero);
  var_result = AllocateBigInt(IntPtrConstant(1));
  StoreBigIntDigit(var_result.value(), 0, value);
  Goto(&done);

  BIND(&if_zero);
  var_result = AllocateBigInt(IntPtrConstant(0));
  Goto(&done);
  BIND(&done);
  return var_result.value();
}

TNode<Numeric> CodeStubAssembler::LoadFixedTypedArrayElementAsTagged(
    TNode<RawPtrT> data_pointer, TNode<UintPtrT> index,
    ElementsKind elements_kind) {
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(Signed(index), elements_kind, 0);
  switch (elements_kind) {
    case UINT8_ELEMENTS: /* fall through */
    case UINT8_CLAMPED_ELEMENTS:
      return SmiFromInt32(Load<Uint8T>(data_pointer, offset));
    case INT8_ELEMENTS:
      return SmiFromInt32(Load<Int8T>(data_pointer, offset));
    case UINT16_ELEMENTS:
      return SmiFromInt32(Load<Uint16T>(data_pointer, offset));
    case INT16_ELEMENTS:
      return SmiFromInt32(Load<Int16T>(data_pointer, offset));
    case UINT32_ELEMENTS:
      return ChangeUint32ToTagged(Load<Uint32T>(data_pointer, offset));
    case INT32_ELEMENTS:
      return ChangeInt32ToTagged(Load<Int32T>(data_pointer, offset));
    case FLOAT16_ELEMENTS:
      return AllocateHeapNumberWithValue(
          ChangeFloat16ToFloat64(Load<Float16RawBitsT>(data_pointer, offset)));
    case FLOAT32_ELEMENTS:
      return AllocateHeapNumberWithValue(
          ChangeFloat32ToFloat64(Load<Float32T>(data_pointer, offset)));
    case FLOAT64_ELEMENTS:
      return AllocateHeapNumberWithValue(Load<Float64T>(data_pointer, offset));
    case BIGINT64_ELEMENTS:
      return LoadFixedBigInt64ArrayElementAsTagged(data_pointer, offset);
    case BIGUINT64_ELEMENTS:
      return LoadFixedBigUint64ArrayElementAsTagged(data_pointer, offset);
    default:
      UNREACHABLE();
  }
}

TNode<Numeric> CodeStubAssembler::LoadFixedTypedArrayElementAsTagged(
    TNode<RawPtrT> data_pointer, TNode<UintPtrT> index,
    TNode<Int32T> elements_kind) {
  TVARIABLE(Numeric, var_result);
  Label done(this), if_unknown_type(this, Label::kDeferred);
  int32_t elements_kinds[] = {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) TYPE##_ELEMENTS,
      TYPED_ARRAYS(TYPED_ARRAY_CASE) RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  };

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) Label if_##type##array(this);
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  Label* elements_kind_labels[] = {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) &if_##type##array,
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
      // The same labels again for RAB / GSAB. We dispatch RAB / GSAB elements
      // kinds to the corresponding non-RAB / GSAB elements kinds.
      TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE
  };
  static_assert(arraysize(elements_kinds) == arraysize(elements_kind_labels));

  Switch(elements_kind, &if_unknown_type, elements_kinds, elements_kind_labels,
         arraysize(elements_kinds));

  BIND(&if_unknown_type);
  Unreachable();

#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                        \
  BIND(&if_##type##array);                                               \
  {                                                                      \
    var_result = LoadFixedTypedArrayElementAsTagged(data_pointer, index, \
                                                    TYPE##_ELEMENTS);    \
    Goto(&done);                                                         \
  }
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  BIND(&done);
  return var_result.value();
}

template <typename TIndex>
TNode<MaybeObject> CodeStubAssembler::LoadFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<TIndex> slot,
    int additional_offset) {
  int32_t header_size = FeedbackVector::kRawFeedbackSlotsOffset +
                        additional_offset - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(slot, HOLEY_ELEMENTS, header_size);
  CSA_SLOW_DCHECK(
      this, IsOffsetInBounds(offset, LoadFeedbackVectorLength(feedback_vector),
                             FeedbackVector::kHeaderSize));
  return Load<MaybeObject>(feedback_vector, offset);
}

template TNode<MaybeObject> CodeStubAssembler::LoadFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<TaggedIndex> slot,
    int additional_offset);
template TNode<MaybeObject> CodeStubAssembler::LoadFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<IntPtrT> slot,
    int additional_offset);
template TNode<MaybeObject> CodeStubAssembler::LoadFeedbackVectorSlot(
    TNode<FeedbackVector> feedback_vector, TNode<UintPtrT> slot,
    int additional_offset);

template <typename Array>
TNode<Int32T> CodeStubAssembler::LoadAndUntagToWord32ArrayElement(
    TNode<Array> object, int array_header_size, TNode<IntPtrT> index,
    int additional_offset) {
  DCHECK(IsAligned(additional_offset, kTaggedSize));
  int endian_correction = 0;
#if V8_TARGET_LITTLE_ENDIAN
  if (SmiValuesAre32Bits()) endian_correction = 4;
#endif
  int32_t header_size = array_header_size + additional_offset - kHeapObjectTag +
                        endian_correction;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index, HOLEY_ELEMENTS, header_size);
  CSA_DCHECK(this, IsOffsetInBounds(offset, LoadArrayLength(object),
                                    array_header_size + endian_correction));
  if (SmiValuesAre32Bits()) {
    return Load<Int32T>(object, offset);
  } else {
    return SmiToInt32(Load<Smi>(object, offset));
  }
}

TNode<Int32T> CodeStubAssembler::LoadAndUntagToWord32FixedArrayElement(
    TNode<FixedArray> object, TNode<IntPtrT> index, int additional_offset) {
  CSA_SLOW_DCHECK(this, IsFixedArraySubclass(object));
  return LoadAndUntagToWord32ArrayElement(
      object, OFFSET_OF_DATA_START(FixedArray), index, additional_offset);
}

TNode<MaybeObject> CodeStubAssembler::LoadWeakFixedArrayElement(
    TNode<WeakFixedArray> object, TNode<IntPtrT> index, int additional_offset) {
  return LoadArrayElement(object, OFFSET_OF_DATA_START(WeakFixedArray), index,
                          additional_offset);
}

TNode<Float64T> CodeStubAssembler::LoadFixedDoubleArrayElement(
    TNode<FixedDoubleArray> object, TNode<IntPtrT> index, Label* if_hole,
    MachineType machine_type) {
  int32_t header_size = OFFSET_OF_DATA_START(FixedDoubleArray) - kHeapObjectTag;
  TNode<IntPtrT> offset =
      ElementOffsetFromIndex(index, HOLEY_DOUBLE_ELEMENTS, header_size);
  CSA_DCHECK(this,
             IsOffsetInBounds(offset, LoadAndUntagFixedArrayBaseLength(object),
                              OFFSET_OF_DATA_START(FixedDoubleArray),
                              HOLEY_DOUBLE_ELEMENTS));
  return LoadDoubleWithHoleCheck(object, offset, if_hole, machine_type);
}

TNode<Object> CodeStubAssembler::LoadFixedArrayBaseElementAsTagged(
    TNode<FixedArrayBase> elements, TNode<IntPtrT> index,
    TNode<Int32T> elements_kind, Label* if_accessor, Label* if_hole) {
  TVARIABLE(Object, var_result);
  Label done(this), if_packed(this), if_holey(this), if_packed_double(this),
      if_holey_double(this), if_dictionary(this, Label::kDeferred);

  int32_t kinds[] = {
      // Handled by if_packed.
      PACKED_SMI_ELEMENTS, PACKED_ELEMENTS, PACKED_NONEXTENSIBLE_ELEMENTS,
      PACKED_SEALED_ELEMENTS, PACKED_FROZEN_ELEMENTS,
      // Handled by if_holey.
      HOLEY_SMI_ELEMENTS, HOLEY_ELEMENTS, HOLEY_NONEXTENSIBLE_ELEMENTS,
      HOLEY_SEALED_ELEMENTS, HOLEY_FROZEN_ELEMENTS,
      // Handled by if_packed_double.
      PACKED_DOUBLE_ELEMENTS,
      // Handled by if_holey_double.
      HOLEY_DOUBLE_ELEMENTS};
  Label* labels[] = {// PACKED_{SMI,}_ELEMENTS
                     &if_packed, &if_packed, &if_packed, &if_packed, &if_packed,
                     // HOLEY_{SMI,}_ELEMENTS
                     &if_holey, &if_holey, &if_holey, &if_holey, &if_holey,
                     // PACKED_DOUBLE_ELEMENTS
                     &if_packed_double,
                     // HOLEY_DOUBLE_ELEMENTS
                     &if_holey_double};
  Switch(elements_kind, &if_dictionary, kinds, labels, arraysize(kinds));

  BIND(&if_packed);
  {
    var_result = LoadFixedArrayElement(CAST(elements), index, 0);
    Goto(&done);
  }

  BIND(&if_holey);
  {
    var_result = LoadFixedArrayElement(CAST(elements), index);
    Branch(TaggedEqual(var_result.value(), TheHoleConstant()), if_hole, &done);
  }

  BIND(&if_packed_double);
  {
    var_result = AllocateHeapNumberWithValue(
        LoadFixedDoubleArrayElement(CAST(elements), index));
    Goto(&done);
  }

  BIND(&if_holey_double);
  {
    var_result = AllocateHeapNumberWithValue(
        LoadFixedDoubleArrayElement(CAST(elements), index, if_hole));
    Goto(&done);
  }

  BIND(&if_dictionary);
  {
    CSA_DCHECK(this, IsDictionaryElementsKind(elements_kind));
    var_result = BasicLoadNumberDictionaryElement(CAST(elements), index,
                                                  if_accessor, if_hole);
    Goto(&done);
  }

  BIND(&done);
  return var_result.value();
}

TNode<BoolT> CodeStubAssembler::IsDoubleHole(TNode<Object> base,
                                             TNode<IntPtrT> offset) {
  // TODO(ishell): Compare only the upper part for the hole once the
  // compiler is able to fold addition of already complex |offset| with
  // |kIeeeDoubleExponentWordOffset| into one addressing mode.
  if (Is64()) {
    TNode<Uint64T> element = Load<Uint64T>(base, offset);
    return Word64Equal(element, Int64Constant(kHoleNanInt64));
  } else {
    TNode<Uint32T> element_upper = Load<Uint32T>(
        base, IntPtrAdd(offset, IntPtrConstant(kIeeeDoubleExponentWordOffset)));
    return Word32Equal(element_upper, Int32Constant(kHoleNanUpper32));
  }
}

TNode<Float64T> CodeStubAssembler::LoadDoubleWithHoleCheck(
    TNode<Object> base, TNode<IntPtrT> offset, Label* if_hole,
    MachineType machine_type) {
  if (if_hole) {
    GotoIf(IsDoubleHole(base, offset), if_hole);
  }
  if (machine_type.IsNone()) {
    // This means the actual value is not needed.
    return TNode<Float64T>();
  }
  return UncheckedCast<Float64T>(Load(machine_type, base, offset));
}

TNode<ScopeInfo> CodeStubAssembler::LoadScopeInfo(TNode<Context> context) {
  return CAST(LoadContextElement(context, Context::SCOPE_INFO_INDEX));
}

TNode<BoolT> CodeStubAssembler::LoadScopeInfoHasExtensionField(
    TNode<ScopeInfo> scope_info) {
  TNode<Uint32T> value =
      LoadObjectField<Uint32T>(scope_info, ScopeInfo::kFlagsOffset);
  return IsSetWord32<ScopeInfo::HasContextExtensionSlotBit>(value);
}

TNode<BoolT> CodeStubAssembler::LoadScopeInfoClassScopeHasPrivateBrand(
    TNode<ScopeInfo> scope_info) {
  TNode<Uint32T> value =
      LoadObjectField<Uint32T>(scope_info, ScopeInfo::kFlagsOffset);
  return IsSetWord32<ScopeInfo::ClassScopeHasPrivateBrandBit>(value);
}

void CodeStubAssembler::StoreContextElementNoWriteBarrier(
    TNode<Context> context, int slot_index, TNode<Object> value) {
  int offset = Context::SlotOffset(slot_index);
  StoreNoWriteBarrier(MachineRepresentation::kTagged, context,
                      IntPtrConstant(offset), value);
}

TNode<NativeContext> CodeStubAssembler::LoadNativeContext(
    TNode<Context> context) {
  TNode<Map> map = LoadMap(context);
  return CAST(LoadObjectField(
      map, Map::kConstructorOrBackPointerOrNativeContextOffset));
}

TNode<Context> CodeStubAssembler::LoadModuleContext(TNode<Context> context) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> module_map = CAST(
      LoadContextElement(native_context, Context::MODULE_CONTEXT_MAP_INDEX));
  TVariable<Object> cur_context(context, this);

  Label context_found(this);

  Label context_search(this, &cur_context);

  // Loop until cur_context->map() is module_map.
  Goto(&context_search);
  BIND(&context_search);
  {
    CSA_DCHECK(this, Word32BinaryNot(
                         TaggedEqual(cur_context.value(), native_context)));
    GotoIf(TaggedEqual(LoadMap(CAST(cur_context.value())), module_map),
           &context_found);

    cur_context =
        LoadContextElement(CAST(cur_context.value()), Context::PREVIOUS_INDEX);
    Goto(&context_search);
  }

  BIND(&context_found);
  return UncheckedCast<Context>(cur_context.value());
}

TNode<Object> CodeStubAssembler::GetImportMetaObject(TNode<Context> context) {
  const TNode<Context> module_context = LoadModuleContext(context);
  const TNode<HeapObject> module =
      CAST(LoadContextElement(module_context, Context::EXTENSION_INDEX));
  const TNode<Object> import_meta =
      LoadObjectField(module, SourceTextModule::kImportMetaOffset);

  TVARIABLE(Object, return_value, import_meta);

  Label end(this);
  GotoIfNot(IsTheHole(import_meta), &end);

  return_value = CallRuntime(Runtime::kGetImportMetaObject, context);
  Goto(&end);

  BIND(&end);
  return return_value.value();
}

TNode<Map> CodeStubAssembler::LoadObjectFunctionInitialMap(
    TNode<NativeContext> native_context) {
  TNode<JSFunction> object_function =
      CAST(LoadContextElement(native_context, Context::OBJECT_FUNCTION_INDEX));
  return CAST(LoadJSFunctionPrototypeOrInitialMap(object_function));
}

TNode<Map> CodeStubAssembler::LoadCachedMap(TNode<NativeContext> native_context,
                                            TNode<IntPtrT> number_of_properties,
                                            Label* runtime) {
  CSA_DCHECK(this, UintPtrLessThan(number_of_properties,
                                   IntPtrConstant(JSObject::kMapCacheSize)));
  TNode<WeakFixedArray> cache =
      CAST(LoadContextElement(native_context, Context::MAP_CACHE_INDEX));
  TNode<MaybeObject> value =
      LoadWeakFixedArrayElement(cache, number_of_properties, 0);
  TNode<Map> result = CAST(GetH
"""


```