Response:
The user wants to understand the functionality of the provided C++ code snippet from `v8/src/maglev/maglev-graph-builder.cc`.

Here's a breakdown of the thought process to analyze the code and fulfill the user's request:

1. **Identify the Core Purpose:**  The file name `maglev-graph-builder.cc` strongly suggests this code is responsible for building the Maglev graph, which is an intermediate representation used in V8's compilation pipeline. The functions within this snippet seem to be related to *reducing* or *lowering* certain JavaScript operations into their Maglev graph equivalents. This involves checking types, handling different scenarios, and generating Maglev nodes.

2. **Analyze Individual Functions:**  Go through each `TryReduce...` function and determine what JavaScript operation it's trying to handle. Pay attention to the arguments, the checks being performed, and the Maglev nodes being created.

    * **Iterator Functions (`TryReduceArrayPrototypeEntries`, `Keys`, `Values`):** These clearly relate to the `entries()`, `keys()`, and `values()` methods of JavaScript arrays. The code builds a `JSArrayIterator`.

    * **`TryReduceArrayPrototypeNext`:** This function handles the `next()` call on an array iterator. It checks if the iteration is done, loads the next element based on the iteration kind (keys, values, or entries), updates the iterator's state, and returns the result.

    * **String Functions (`TryReduceStringFromCharCode`, `CharCodeAt`, `CodePointAt`, `Iterator`):**  These correspond to JavaScript's string manipulation functions. They involve type checks, constant folding, and the creation of specific Maglev builtin nodes.

    * **`TryReduceStringPrototypeLocaleCompareIntl`:** This function seems related to internationalization and string comparison. It checks arguments and tries to use a fast path if possible.

    * **Embedder Data Functions (`TryReduceGetContinuationPreservedEmbedderData`, `SetContinuationPreservedEmbedderData`):**  These are specific to V8's embedding API and handle getting and setting embedder data.

    * **DataView Functions (`TryReduceDataViewPrototypeGet...`, `Set...`):**  These functions deal with reading and writing to `DataView` objects, which provide a way to access the underlying buffer of an `ArrayBuffer`. They involve bounds checks and handling endianness.

    * **Function Prototype Methods (`TryReduceFunctionPrototypeCall`, `Apply`):** These handle the `call()` and `apply()` methods of JavaScript functions. These are more complex as they involve potentially calling other functions.

    * **Array Resizing Methods (`TryReduceArrayPrototypePush`, `Pop`):** These are optimized implementations of `push()` and `pop()` for arrays. They check array types, handle different element kinds (Smi, Object, Double, Packed/Holey), and potentially grow the array. They involve complex logic for efficiency.

3. **Identify Common Themes and Patterns:**

    * **Type Checking:**  Many functions start with `if (!CanSpeculateCall())` and then perform checks on the receiver and arguments using `CheckType`, `BuildCheckString`, `AddNewNode<CheckInstanceType>`, etc. This is crucial for Maglev to make assumptions and generate optimized code.
    * **Builtin Calls:**  The code frequently uses `AddNewNode<Builtin...>` to represent calls to V8's built-in functions. This is a way to leverage existing optimized code.
    * **Memory Access:** Functions like `BuildLoadTaggedField`, `BuildStoreTaggedField`, `BuildLoadElements`, `BuildStoreFixedArrayElement`, etc., directly interact with the memory layout of JavaScript objects.
    * **Subgraphs and Control Flow:** The use of `MaglevSubGraphBuilder` and labels (`GotoIfTrue`, `GotoIfFalse`, `Bind`) indicates the construction of control flow within the Maglev graph.
    * **Optimization for Different Element Kinds:** The array resizing functions show a significant effort to handle different element kinds (Smi, Object, Double, Packed, Holey) efficiently.

4. **Relate to JavaScript Functionality (with Examples):** For each group of functions, provide a simple JavaScript example that demonstrates the functionality being implemented in the C++ code. This helps bridge the gap between the low-level C++ and the high-level JavaScript.

5. **Code Logic Reasoning (Input/Output):** For functions with more intricate logic (like `TryReduceArrayPrototypeNext` or `Push`/`Pop`), provide hypothetical inputs and the expected outputs based on the code. This helps illustrate the control flow and the transformations happening within the Maglev graph construction.

6. **Common Programming Errors:**  Think about the typical errors JavaScript developers make when using the corresponding functions and relate them to the checks and assumptions made in the C++ code (e.g., calling array methods on non-array objects, accessing array elements out of bounds).

7. **Summarize Functionality:**  Combine the observations from the individual function analyses to provide a high-level overview of the file's purpose. Emphasize its role in Maglev graph construction and optimization.

8. **Address Specific Instructions:**  Ensure all parts of the user's prompt are addressed, such as checking for `.tq` extension, relating to JavaScript, providing examples, reasoning about logic, and pointing out common errors. Specifically, note that the file is `.cc` and therefore not a Torque file.

9. **Consider the "Part 11 of 18" Context:**  This implies that the file likely focuses on a specific set of JavaScript built-ins or language features. In this case, it seems to be related to iterators, string manipulation, and basic array methods. The summary should reflect this scope.

By following these steps, we can effectively analyze the C++ code and provide a comprehensive explanation of its functionality to the user.
这是一个V8 JavaScript引擎的源代码文件，路径为 `v8/src/maglev/maglev-graph-builder.cc`，它是Maglev编译器的一部分，负责构建Maglev图。Maglev图是V8用于优化的中间表示形式。

**功能归纳：**

这个文件的主要功能是实现将某些JavaScript操作（特别是内置函数和原型方法）“降低”到Maglev图中的节点。换句话说，它定义了当Maglev编译器遇到特定的JavaScript代码结构时，应该如何将其转换为更底层的Maglev图表示。  作为第11部分，它专注于以下方面的内置函数和方法：

* **数组迭代器:**  实现了 `Array.prototype.entries()`, `Array.prototype.keys()`, `Array.prototype.values()` 和数组迭代器的 `next()` 方法的优化路径。
* **字符串操作:** 实现了 `String.fromCharCode()`, `String.prototype.charCodeAt()`, `String.prototype.codePointAt()` 和 `String.prototype[@@iterator]()` 的优化路径。
* **国际化支持 (如果启用):**  实现了 `String.prototype.localeCompare()` 的快速路径。
* **Continuation preserved embedder data:** 提供了获取和设置 continuation preserved embedder data 的功能 (如果启用)。
* **DataView 操作:**  实现了 `DataView.prototype.getInt8()`, `setInt8()`, `getInt16()`, `setInt16()`, `getInt32()`, `setInt32()`, `getFloat64()`, `setFloat64()` 的优化路径。
* **函数调用:**  实现了 `Function.prototype.call()` 和 `Function.prototype.apply()` 的优化路径。
* **数组修改:**  实现了 `Array.prototype.push()` 和 `Array.prototype.pop()` 的优化路径，包括对不同元素类型（Smi, Object, Double, Packed, Holey）的优化处理。

**关于文件类型：**

* 由于文件名以 `.cc` 结尾，它是一个 **C++源代码文件**，而不是 Torque 源代码文件（Torque 文件以 `.tq` 结尾）。

**与 JavaScript 功能的关系及示例：**

这个文件中的每个 `TryReduce...` 函数都对应着一个或一组特定的 JavaScript 功能。Maglev 编译器的目标是尽可能地将这些高级的 JavaScript 操作转换为更高效的底层操作。

**1. 数组迭代器 (`Array.prototype.entries()`, `keys()`, `values()`):**

```javascript
const arr = ['a', 'b', 'c'];

// entries()
for (const [index, element] of arr.entries()) {
  console.log(index, element); // 输出: 0 "a", 1 "b", 2 "c"
}

// keys()
for (const key of arr.keys()) {
  console.log(key); // 输出: 0, 1, 2
}

// values()
for (const value of arr.values()) {
  console.log(value); // 输出: "a", "b", "c"
}

// 迭代器 next()
const iterator = arr.entries();
console.log(iterator.next()); // 输出: { value: [ 0, 'a' ], done: false }
console.log(iterator.next()); // 输出: { value: [ 1, 'b' ], done: false }
console.log(iterator.next()); // 输出: { value: [ 2, 'c' ], done: false }
console.log(iterator.next()); // 输出: { value: undefined, done: true }
```

`v8/src/maglev/maglev-graph-builder.cc` 中的代码负责构建在 Maglev 图中表示这些迭代器创建和 `next()` 调用的节点。

**2. 字符串操作 (`String.fromCharCode()`, `charCodeAt()`, `codePointAt()`, 迭代器):**

```javascript
// String.fromCharCode()
console.log(String.fromCharCode(65)); // 输出: "A"

const str = "ABC";
// charCodeAt()
console.log(str.charCodeAt(0)); // 输出: 65
// codePointAt()
console.log(str.codePointAt(0)); // 输出: 65

// 字符串迭代器
for (const char of str) {
  console.log(char); // 输出: "A", "B", "C"
}
```

**3. DataView 操作:**

```javascript
const buffer = new ArrayBuffer(16);
const dataView = new DataView(buffer);

dataView.setInt32(0, 42);
console.log(dataView.getInt32(0)); // 输出: 42

dataView.setFloat64(8, 3.14);
console.log(dataView.getFloat64(8)); // 输出: 3.14
```

**4. 函数调用 (`Function.prototype.call()`, `apply()`):**

```javascript
function greet(greeting) {
  console.log(greeting + ', ' + this.name);
}

const person = { name: 'Alice' };

greet.call(person, 'Hello');   // 输出: "Hello, Alice"
greet.apply(person, ['Hi']);    // 输出: "Hi, Alice"
```

**5. 数组修改 (`Array.prototype.push()`, `pop()`):**

```javascript
const arr = [1, 2];
arr.push(3);
console.log(arr); // 输出: [1, 2, 3]

const last = arr.pop();
console.log(last); // 输出: 3
console.log(arr);  // 输出: [1, 2]
```

**代码逻辑推理 (假设输入与输出):**

以 `TryReduceArrayPrototypeNext` 为例：

**假设输入:**

* `receiver`: 一个指向 `JSArrayIterator` 对象的 `ValueNode`。
* 该迭代器的 `[[NextIndex]]` 字段为 1。
* 被迭代的数组长度为 3。
* 迭代类型是 `IterationKind::kValues`。
* 被迭代的数组的第一个元素是字符串 "hello"。

**预期输出:**

* `is_done` 变量将被设置为 `false`。
* `ret_value` 变量将包含一个指向字符串 "hello" 的 `ValueNode`。
* 迭代器的 `[[NextIndex]]` 字段将被更新为 2。
* 函数返回一个表示迭代结果对象的 `ValueNode`，其 `value` 属性为 "hello"，`done` 属性为 `false`。

**用户常见的编程错误举例说明:**

**1. 对非对象或非数组对象调用数组方法:**

```javascript
const notAnArray = "hello";
notAnArray.push("world"); // TypeError: notAnArray.push is not a function
```

Maglev 图构建器中的 `TryReduceArrayPrototypePush` 等函数会首先检查接收者是否是合适的类型，如果不是，则会失败或回退到更通用的路径。

**2. 对非字符串调用字符串方法:**

```javascript
const notAString = 123;
notAString.charCodeAt(0); // TypeError: notAString.charCodeAt is not a function
```

`TryReduceStringPrototypeCharCodeAt` 等函数会进行类似的类型检查。

**3. `DataView` 越界访问:**

```javascript
const buffer = new ArrayBuffer(8);
const dataView = new DataView(buffer);
dataView.getInt32(4); // 读取索引 4, 5, 6, 7 的 4 个字节
dataView.getInt32(5); // RangeError: Offset is outside the bounds of the DataView
```

`TryBuildLoadDataView` 和 `TryBuildStoreDataView` 等函数会生成检查 `DataView` 边界的 Maglev 节点，以防止此类错误。

**总结第11部分的功能:**

总而言之，`v8/src/maglev/maglev-graph-builder.cc` 的第 11 部分专注于将 JavaScript 中与数组迭代、字符串操作、DataView 操作和基本的函数调用及数组修改相关的内置函数和原型方法转换为 Maglev 图中的高效表示。它通过检查操作数的类型、处理不同的元素类型和场景，并调用相应的内置函数来实现优化。这部分代码是 Maglev 编译器进行性能优化的关键组成部分。

Prompt: 
```
这是目录为v8/src/maglev/maglev-graph-builder.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/maglev/maglev-graph-builder.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第11部分，共18部分，请归纳一下它的功能

"""
;
  RETURN_IF_ABORT(subgraph.Branch(
      {&is_done, &ret_value},
      [&](auto& builder) {
        return BuildBranchIfUint32Compare(builder, Operation::kLessThan,
                                          uint32_index, uint32_length);
      },
      [&] {
        ValueNode* int32_index = GetInt32(uint32_index);
        subgraph.set(is_done, GetBooleanConstant(false));
        DCHECK(
            iterator->get(JSArrayIterator::kKindOffset)->Is<Int32Constant>());
        IterationKind iteration_kind = static_cast<IterationKind>(
            iterator->get(JSArrayIterator::kKindOffset)
                ->Cast<Int32Constant>()
                ->value());
        if (iteration_kind == IterationKind::kKeys) {
          subgraph.set(ret_value, index);
        } else {
          ValueNode* value;
          GET_VALUE_OR_ABORT(
              value,
              TryBuildElementLoadOnJSArrayOrJSObject(
                  iterated_object, int32_index, base::VectorOf(maps),
                  elements_kind, KeyedAccessLoadMode::kHandleOOBAndHoles));
          if (iteration_kind == IterationKind::kEntries) {
            subgraph.set(ret_value,
                         BuildAndAllocateKeyValueArray(index, value));
          } else {
            subgraph.set(ret_value, value);
          }
        }
        // Add 1 to index
        ValueNode* next_index = AddNewNode<Int32AddWithOverflow>(
            {int32_index, GetInt32Constant(1)});
        EnsureType(next_index, NodeType::kSmi);
        // Update [[NextIndex]]
        BuildStoreTaggedFieldNoWriteBarrier(receiver, next_index,
                                            JSArrayIterator::kNextIndexOffset,
                                            StoreTaggedMode::kDefault);
        return ReduceResult::Done();
      },
      [&] {
        // Index is greater or equal than length.
        subgraph.set(is_done, GetBooleanConstant(true));
        subgraph.set(ret_value, GetRootConstant(RootIndex::kUndefinedValue));
        if (!IsTypedArrayElementsKind(elements_kind)) {
          // Mark the {iterator} as exhausted by setting the [[NextIndex]] to a
          // value that will never pass the length check again (aka the maximum
          // value possible for the specific iterated object). Note that this is
          // different from what the specification says, which is changing the
          // [[IteratedObject]] field to undefined, but that makes it difficult
          // to eliminate the map checks and "length" accesses in for..of loops.
          //
          // This is not necessary for JSTypedArray's, since the length of those
          // cannot change later and so if we were ever out of bounds for them
          // we will stay out-of-bounds forever.
          BuildStoreTaggedField(receiver, GetFloat64Constant(kMaxUInt32),
                                JSArrayIterator::kNextIndexOffset,
                                StoreTaggedMode::kDefault);
        }
        return ReduceResult::Done();
      }));

  // Allocate result object and return.
  compiler::MapRef map =
      broker()->target_native_context().iterator_result_map(broker());
  VirtualObject* iter_result = CreateJSIteratorResult(
      map, subgraph.get(ret_value), subgraph.get(is_done));
  ValueNode* allocation =
      BuildInlinedAllocation(iter_result, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypeEntries(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  if (!CheckType(receiver, NodeType::kJSReceiver)) {
    return ReduceResult::Fail();
  }
  return BuildAndAllocateJSArrayIterator(receiver, IterationKind::kEntries);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypeKeys(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  if (!CheckType(receiver, NodeType::kJSReceiver)) {
    return ReduceResult::Fail();
  }
  return BuildAndAllocateJSArrayIterator(receiver, IterationKind::kKeys);
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypeValues(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  if (!CheckType(receiver, NodeType::kJSReceiver)) {
    return ReduceResult::Fail();
  }
  return BuildAndAllocateJSArrayIterator(receiver, IterationKind::kValues);
}

ReduceResult MaglevGraphBuilder::TryReduceStringFromCharCode(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (args.count() != 1) return ReduceResult::Fail();
  return AddNewNode<BuiltinStringFromCharCode>({GetTruncatedInt32ForToNumber(
      args[0], ToNumberHint::kAssumeNumberOrOddball)});
}

ReduceResult MaglevGraphBuilder::TryReduceStringPrototypeCharCodeAt(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  ValueNode* index;
  if (args.count() == 0) {
    // Index is the undefined object. ToIntegerOrInfinity(undefined) = 0.
    index = GetInt32Constant(0);
  } else {
    index = GetInt32ElementIndex(args[0]);
  }
  // Any other argument is ignored.

  // Try to constant-fold if receiver and index are constant
  if (auto cst = TryGetConstant(receiver)) {
    if (cst->IsString() && index->Is<Int32Constant>()) {
      compiler::StringRef str = cst->AsString();
      int idx = index->Cast<Int32Constant>()->value();
      if (idx >= 0 && static_cast<uint32_t>(idx) < str.length()) {
        if (std::optional<uint16_t> value = str.GetChar(broker(), idx)) {
          return GetSmiConstant(*value);
        }
      }
    }
  }

  // Ensure that {receiver} is actually a String.
  BuildCheckString(receiver);
  // And index is below length.
  ValueNode* length = BuildLoadStringLength(receiver);
  RETURN_IF_ABORT(TryBuildCheckInt32Condition(
      index, length, AssertCondition::kUnsignedLessThan,
      DeoptimizeReason::kOutOfBounds));
  return AddNewNode<BuiltinStringPrototypeCharCodeOrCodePointAt>(
      {receiver, index},
      BuiltinStringPrototypeCharCodeOrCodePointAt::kCharCodeAt);
}

ReduceResult MaglevGraphBuilder::TryReduceStringPrototypeCodePointAt(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  ValueNode* index;
  if (args.count() == 0) {
    // Index is the undefined object. ToIntegerOrInfinity(undefined) = 0.
    index = GetInt32Constant(0);
  } else {
    index = GetInt32ElementIndex(args[0]);
  }
  // Any other argument is ignored.
  // Ensure that {receiver} is actually a String.
  BuildCheckString(receiver);
  // And index is below length.
  ValueNode* length = BuildLoadStringLength(receiver);
  RETURN_IF_ABORT(TryBuildCheckInt32Condition(
      index, length, AssertCondition::kUnsignedLessThan,
      DeoptimizeReason::kOutOfBounds));
  return AddNewNode<BuiltinStringPrototypeCharCodeOrCodePointAt>(
      {receiver, index},
      BuiltinStringPrototypeCharCodeOrCodePointAt::kCodePointAt);
}

ReduceResult MaglevGraphBuilder::TryReduceStringPrototypeIterator(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  // Ensure that {receiver} is actually a String.
  BuildCheckString(receiver);
  compiler::MapRef map =
      broker()->target_native_context().initial_string_iterator_map(broker());
  VirtualObject* string_iterator = CreateJSStringIterator(map, receiver);
  ValueNode* allocation =
      BuildInlinedAllocation(string_iterator, AllocationType::kYoung);
  // TODO(leszeks): Don't eagerly clear the raw allocation, have the
  // next side effect clear it.
  ClearCurrentAllocationBlock();
  return allocation;
}

#ifdef V8_INTL_SUPPORT

ReduceResult MaglevGraphBuilder::TryReduceStringPrototypeLocaleCompareIntl(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() < 1 || args.count() > 3) return ReduceResult::Fail();

  LocalFactory* factory = local_isolate()->factory();
  compiler::ObjectRef undefined_ref = broker()->undefined_value();

  Handle<Object> locales_handle;
  ValueNode* locales_node = nullptr;
  if (args.count() > 1) {
    compiler::OptionalHeapObjectRef maybe_locales = TryGetConstant(args[1]);
    if (!maybe_locales) return ReduceResult::Fail();
    compiler::HeapObjectRef locales = maybe_locales.value();
    if (locales.equals(undefined_ref)) {
      locales_handle = factory->undefined_value();
      locales_node = GetRootConstant(RootIndex::kUndefinedValue);
    } else {
      if (!locales.IsString()) return ReduceResult::Fail();
      compiler::StringRef sref = locales.AsString();
      std::optional<Handle<String>> maybe_locales_handle =
          sref.ObjectIfContentAccessible(broker());
      if (!maybe_locales_handle) return ReduceResult::Fail();
      locales_handle = *maybe_locales_handle;
      locales_node = args[1];
    }
  } else {
    locales_handle = factory->undefined_value();
    locales_node = GetRootConstant(RootIndex::kUndefinedValue);
  }

  if (args.count() > 2) {
    compiler::OptionalHeapObjectRef maybe_options = TryGetConstant(args[2]);
    if (!maybe_options) return ReduceResult::Fail();
    if (!maybe_options.value().equals(undefined_ref))
      return ReduceResult::Fail();
  }

  DCHECK(!locales_handle.is_null());
  DCHECK_NOT_NULL(locales_node);

  if (Intl::CompareStringsOptionsFor(local_isolate(), locales_handle,
                                     factory->undefined_value()) !=
      Intl::CompareStringsOptions::kTryFastPath) {
    return ReduceResult::Fail();
  }
  return BuildCallBuiltin<Builtin::kStringFastLocaleCompare>(
      {GetConstant(target),
       GetTaggedValue(GetValueOrUndefined(args.receiver())),
       GetTaggedValue(args[0]), GetTaggedValue(locales_node)});
}

#endif  // V8_INTL_SUPPORT

#ifdef V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA
ReduceResult MaglevGraphBuilder::TryReduceGetContinuationPreservedEmbedderData(
    compiler::JSFunctionRef target, CallArguments& args) {
  return AddNewNode<GetContinuationPreservedEmbedderData>({});
}

ReduceResult MaglevGraphBuilder::TryReduceSetContinuationPreservedEmbedderData(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (args.count() == 0) return ReduceResult::Fail();

  AddNewNode<SetContinuationPreservedEmbedderData>({args[0]});
  return GetRootConstant(RootIndex::kUndefinedValue);
}
#endif  // V8_ENABLE_CONTINUATION_PRESERVED_EMBEDDER_DATA

template <typename LoadNode>
ReduceResult MaglevGraphBuilder::TryBuildLoadDataView(const CallArguments& args,
                                                      ExternalArrayType type) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (!broker()->dependencies()->DependOnArrayBufferDetachingProtector()) {
    // TODO(victorgomes): Add checks whether the array has been detached.
    return ReduceResult::Fail();
  }
  // TODO(victorgomes): Add data view to known types.
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  AddNewNode<CheckInstanceType>({receiver}, CheckType::kCheckHeapObject,
                                JS_DATA_VIEW_TYPE, JS_DATA_VIEW_TYPE);
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  ValueNode* offset =
      args[0] ? GetInt32ElementIndex(args[0]) : GetInt32Constant(0);
  AddNewNode<CheckJSDataViewBounds>({receiver, offset}, type);
  ValueNode* is_little_endian = args[1] ? args[1] : GetBooleanConstant(false);
  return AddNewNode<LoadNode>({receiver, offset, is_little_endian}, type);
}

template <typename StoreNode, typename Function>
ReduceResult MaglevGraphBuilder::TryBuildStoreDataView(
    const CallArguments& args, ExternalArrayType type, Function&& getValue) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  if (!broker()->dependencies()->DependOnArrayBufferDetachingProtector()) {
    // TODO(victorgomes): Add checks whether the array has been detached.
    return ReduceResult::Fail();
  }
  // TODO(victorgomes): Add data view to known types.
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  AddNewNode<CheckInstanceType>({receiver}, CheckType::kCheckHeapObject,
                                JS_DATA_VIEW_TYPE, JS_DATA_VIEW_TYPE);
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  ValueNode* offset =
      args[0] ? GetInt32ElementIndex(args[0]) : GetInt32Constant(0);
  AddNewNode<CheckJSDataViewBounds>({receiver, offset},
                                    ExternalArrayType::kExternalFloat64Array);
  ValueNode* value = getValue(args[1]);
  ValueNode* is_little_endian = args[2] ? args[2] : GetBooleanConstant(false);
  AddNewNode<StoreNode>({receiver, offset, value, is_little_endian}, type);
  return GetRootConstant(RootIndex::kUndefinedValue);
}

ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeGetInt8(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildLoadDataView<LoadSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt8Array);
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeSetInt8(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildStoreDataView<StoreSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt8Array,
      [&](ValueNode* value) { return value ? value : GetInt32Constant(0); });
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeGetInt16(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildLoadDataView<LoadSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt16Array);
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeSetInt16(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildStoreDataView<StoreSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt16Array,
      [&](ValueNode* value) { return value ? value : GetInt32Constant(0); });
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeGetInt32(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildLoadDataView<LoadSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt32Array);
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeSetInt32(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildStoreDataView<StoreSignedIntDataViewElement>(
      args, ExternalArrayType::kExternalInt32Array,
      [&](ValueNode* value) { return value ? value : GetInt32Constant(0); });
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeGetFloat64(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildLoadDataView<LoadDoubleDataViewElement>(
      args, ExternalArrayType::kExternalFloat64Array);
}
ReduceResult MaglevGraphBuilder::TryReduceDataViewPrototypeSetFloat64(
    compiler::JSFunctionRef target, CallArguments& args) {
  return TryBuildStoreDataView<StoreDoubleDataViewElement>(
      args, ExternalArrayType::kExternalFloat64Array, [&](ValueNode* value) {
        return value ? GetHoleyFloat64ForToNumber(
                           value, ToNumberHint::kAssumeNumberOrOddball)
                     : GetFloat64Constant(
                           std::numeric_limits<double>::quiet_NaN());
      });
}

ReduceResult MaglevGraphBuilder::TryReduceFunctionPrototypeCall(
    compiler::JSFunctionRef target, CallArguments& args) {
  // We can't reduce Function#call when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());
  args.PopReceiver(ConvertReceiverMode::kAny);

  SaveCallSpeculationScope saved(this);
  return ReduceCall(receiver, args, saved.value());
}

ReduceResult MaglevGraphBuilder::TryReduceFunctionPrototypeApply(
    compiler::JSFunctionRef target, CallArguments& args) {
  compiler::OptionalHeapObjectRef maybe_receiver;
  if (current_speculation_feedback_.IsValid()) {
    const compiler::ProcessedFeedback& processed_feedback =
        broker()->GetFeedbackForCall(current_speculation_feedback_);
    DCHECK_EQ(processed_feedback.kind(), compiler::ProcessedFeedback::kCall);
    const compiler::CallFeedback& call_feedback = processed_feedback.AsCall();
    compiler::OptionalHeapObjectRef maybe_receiver;
    if (call_feedback.call_feedback_content() ==
        CallFeedbackContent::kReceiver) {
      maybe_receiver = call_feedback.target();
    }
  }
  return ReduceFunctionPrototypeApplyCallWithReceiver(
      maybe_receiver, args, current_speculation_feedback_);
}

namespace {

template <size_t MaxKindCount, typename KindsToIndexFunc>
bool CanInlineArrayResizingBuiltin(
    compiler::JSHeapBroker* broker, const PossibleMaps& possible_maps,
    std::array<SmallZoneVector<compiler::MapRef, 2>, MaxKindCount>& map_kinds,
    KindsToIndexFunc&& elements_kind_to_index, int* unique_kind_count,
    bool is_loading) {
  uint8_t kind_bitmap = 0;
  for (compiler::MapRef map : possible_maps) {
    if (!map.supports_fast_array_resize(broker)) {
      return false;
    }
    ElementsKind kind = map.elements_kind();
    if (is_loading && kind == HOLEY_DOUBLE_ELEMENTS) {
      return false;
    }
    // Group maps by elements kind, using the provided function to translate
    // elements kinds to indices.
    // kind_bitmap is used to get the unique kinds (predecessor count for the
    // next block).
    uint8_t kind_index = elements_kind_to_index(kind);
    kind_bitmap |= 1 << kind_index;
    map_kinds[kind_index].push_back(map);
  }

  *unique_kind_count = base::bits::CountPopulation(kind_bitmap);
  DCHECK_GE(*unique_kind_count, 1);
  return true;
}

}  // namespace

template <typename MapKindsT, typename IndexToElementsKindFunc,
          typename BuildKindSpecificFunc>
ReduceResult MaglevGraphBuilder::BuildJSArrayBuiltinMapSwitchOnElementsKind(
    ValueNode* receiver, const MapKindsT& map_kinds,
    MaglevSubGraphBuilder& sub_graph,
    std::optional<MaglevSubGraphBuilder::Label>& do_return,
    int unique_kind_count, IndexToElementsKindFunc&& index_to_elements_kind,
    BuildKindSpecificFunc&& build_kind_specific) {
  // TODO(pthier): Support map packing.
  DCHECK(!V8_MAP_PACKING_BOOL);
  ValueNode* receiver_map =
      BuildLoadTaggedField(receiver, HeapObject::kMapOffset);
  int emitted_kind_checks = 0;
  bool any_successful = false;
  for (size_t kind_index = 0; kind_index < map_kinds.size(); kind_index++) {
    const auto& maps = map_kinds[kind_index];
    // Skip kinds we haven't observed.
    if (maps.empty()) continue;
    ElementsKind kind = index_to_elements_kind(kind_index);
    // Create branches for all but the last elements kind. We don't need
    // to check the maps of the last kind, as all possible maps have already
    // been checked when the property (builtin name) was loaded.
    if (++emitted_kind_checks < unique_kind_count) {
      MaglevSubGraphBuilder::Label check_next_map(&sub_graph, 1);
      std::optional<MaglevSubGraphBuilder::Label> do_push;
      if (maps.size() > 1) {
        do_push.emplace(&sub_graph, static_cast<int>(maps.size()));
        for (size_t map_index = 1; map_index < maps.size(); map_index++) {
          sub_graph.GotoIfTrue<BranchIfReferenceEqual>(
              &*do_push, {receiver_map, GetConstant(maps[map_index])});
        }
      }
      sub_graph.GotoIfFalse<BranchIfReferenceEqual>(
          &check_next_map, {receiver_map, GetConstant(maps[0])});
      if (do_push.has_value()) {
        sub_graph.Goto(&*do_push);
        sub_graph.Bind(&*do_push);
      }
      if (!build_kind_specific(kind).IsDoneWithAbort()) {
        any_successful = true;
      }
      DCHECK(do_return.has_value());
      sub_graph.GotoOrTrim(&*do_return);
      sub_graph.Bind(&check_next_map);
    } else {
      if (!build_kind_specific(kind).IsDoneWithAbort()) {
        any_successful = true;
      }
      if (do_return.has_value()) {
        sub_graph.GotoOrTrim(&*do_return);
      }
    }
  }
  DCHECK_IMPLIES(!any_successful, !current_block_);
  return any_successful ? ReduceResult::Done() : ReduceResult::DoneWithAbort();
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypePush(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  // We can't reduce Function#call when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.push - no receiver"
                << std::endl;
    }
    return ReduceResult::Fail();
  }
  // TODO(pthier): Support multiple arguments.
  if (args.count() != 1) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.push - invalid "
                   "argument count"
                << std::endl;
    }
    return ReduceResult::Fail();
  }
  ValueNode* receiver = GetValueOrUndefined(args.receiver());

  auto node_info = known_node_aspects().TryGetInfoFor(receiver);
  // If the map set is not found, then we don't know anything about the map of
  // the receiver, so bail.
  if (!node_info || !node_info->possible_maps_are_known()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout
          << "  ! Failed to reduce Array.prototype.push - unknown receiver map"
          << std::endl;
    }
    return ReduceResult::Fail();
  }

  const PossibleMaps& possible_maps = node_info->possible_maps();
  // If the set of possible maps is empty, then there's no possible map for this
  // receiver, therefore this path is unreachable at runtime. We're unlikely to
  // ever hit this case, BuildCheckMaps should already unconditionally deopt,
  // but check it in case another checking operation fails to statically
  // unconditionally deopt.
  if (possible_maps.is_empty()) {
    // TODO(leszeks): Add an unreachable assert here.
    return ReduceResult::DoneWithAbort();
  }

  if (!broker()->dependencies()->DependOnNoElementsProtector()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.push - "
                   "NoElementsProtector invalidated"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  // Check that inlining resizing array builtins is supported and group maps
  // by elements kind.
  std::array<SmallZoneVector<compiler::MapRef, 2>, 3> map_kinds = {
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone())};
  // Function to group maps by elements kind, ignoring packedness. Packedness
  // doesn't matter for push().
  // Kinds we care about are all paired in the first 6 values of ElementsKind,
  // so we can use integer division to truncate holeyness.
  auto elements_kind_to_index = [&](ElementsKind kind) {
    static_assert(kFastElementsKindCount <= 6);
    static_assert(kFastElementsKindPackedToHoley == 1);
    return static_cast<uint8_t>(kind) / 2;
  };
  auto index_to_elements_kind = [&](uint8_t kind_index) {
    return static_cast<ElementsKind>(kind_index * 2);
  };
  int unique_kind_count;
  if (!CanInlineArrayResizingBuiltin(broker(), possible_maps, map_kinds,
                                     elements_kind_to_index, &unique_kind_count,
                                     false)) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.push - Map doesn't "
                   "support fast resizing"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  MaglevSubGraphBuilder sub_graph(this, 0);

  std::optional<MaglevSubGraphBuilder::Label> do_return;
  if (unique_kind_count > 1) {
    do_return.emplace(&sub_graph, unique_kind_count);
  }

  ValueNode* old_array_length_smi;
  GET_VALUE_OR_ABORT(old_array_length_smi,
                     GetSmiValue(BuildLoadJSArrayLength(receiver)));
  ValueNode* old_array_length =
      AddNewNode<UnsafeSmiUntag>({old_array_length_smi});
  ValueNode* new_array_length_smi =
      AddNewNode<CheckedSmiIncrement>({old_array_length_smi});

  ValueNode* elements_array = BuildLoadElements(receiver);
  ValueNode* elements_array_length = BuildLoadFixedArrayLength(elements_array);

  auto build_array_push = [&](ElementsKind kind) {
    ValueNode* value;
    GET_VALUE_OR_ABORT(value, ConvertForStoring(args[0], kind));

    ValueNode* writable_elements_array = AddNewNode<MaybeGrowFastElements>(
        {elements_array, receiver, old_array_length, elements_array_length},
        kind);

    AddNewNode<StoreTaggedFieldNoWriteBarrier>({receiver, new_array_length_smi},
                                               JSArray::kLengthOffset,
                                               StoreTaggedMode::kDefault);

    // Do the store
    if (IsDoubleElementsKind(kind)) {
      BuildStoreFixedDoubleArrayElement(writable_elements_array,
                                        old_array_length, value);
    } else {
      DCHECK(IsSmiElementsKind(kind) || IsObjectElementsKind(kind));
      BuildStoreFixedArrayElement(writable_elements_array, old_array_length,
                                  value);
    }
    return ReduceResult::Done();
  };

  RETURN_IF_ABORT(BuildJSArrayBuiltinMapSwitchOnElementsKind(
      receiver, map_kinds, sub_graph, do_return, unique_kind_count,
      index_to_elements_kind, build_array_push));

  if (do_return.has_value()) {
    sub_graph.Bind(&*do_return);
  }
  RecordKnownProperty(receiver, broker()->length_string(), new_array_length_smi,
                      false, compiler::AccessMode::kStore);
  return new_array_length_smi;
}

ReduceResult MaglevGraphBuilder::TryReduceArrayPrototypePop(
    compiler::JSFunctionRef target, CallArguments& args) {
  if (!CanSpeculateCall()) {
    return ReduceResult::Fail();
  }
  // We can't reduce Function#call when there is no receiver function.
  if (args.receiver_mode() == ConvertReceiverMode::kNullOrUndefined) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.pop - no receiver"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  ValueNode* receiver = GetValueOrUndefined(args.receiver());

  auto node_info = known_node_aspects().TryGetInfoFor(receiver);
  // If the map set is not found, then we don't know anything about the map of
  // the receiver, so bail.
  if (!node_info || !node_info->possible_maps_are_known()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout
          << "  ! Failed to reduce Array.prototype.pop - unknown receiver map"
          << std::endl;
    }
    return ReduceResult::Fail();
  }

  const PossibleMaps& possible_maps = node_info->possible_maps();

  // If the set of possible maps is empty, then there's no possible map for this
  // receiver, therefore this path is unreachable at runtime. We're unlikely to
  // ever hit this case, BuildCheckMaps should already unconditionally deopt,
  // but check it in case another checking operation fails to statically
  // unconditionally deopt.
  if (possible_maps.is_empty()) {
    // TODO(leszeks): Add an unreachable assert here.
    return ReduceResult::DoneWithAbort();
  }

  if (!broker()->dependencies()->DependOnNoElementsProtector()) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.pop - "
                   "NoElementsProtector invalidated"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  constexpr int max_kind_count = 4;
  std::array<SmallZoneVector<compiler::MapRef, 2>, max_kind_count> map_kinds = {
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone()),
      SmallZoneVector<compiler::MapRef, 2>(zone())};
  // Smi and Object elements kinds are treated as identical for pop, so we can
  // group them together without differentiation.
  // ElementsKind is mapped to an index in the 4 element array using:
  //   - Bit 2 (Only set for double in the fast element range) is mapped to bit
  //   1)
  //   - Bit 0 (packedness)
  // The complete mapping:
  // +-------+----------------------------------------------+
  // | Index |    ElementsKinds                             |
  // +-------+----------------------------------------------+
  // |   0   |    PACKED_SMI_ELEMENTS and PACKED_ELEMENTS   |
  // |   1   |    HOLEY_SMI_ELEMENETS and HOLEY_ELEMENTS    |
  // |   2   |    PACKED_DOUBLE_ELEMENTS                    |
  // |   3   |    HOLEY_DOUBLE_ELEMENTS                     |
  // +-------+----------------------------------------------+
  auto elements_kind_to_index = [&](ElementsKind kind) {
    uint8_t kind_int = static_cast<uint8_t>(kind);
    uint8_t kind_index = ((kind_int & 0x4) >> 1) | (kind_int & 0x1);
    DCHECK_LT(kind_index, max_kind_count);
    return kind_index;
  };
  auto index_to_elements_kind = [&](uint8_t kind_index) {
    uint8_t kind_int;
    kind_int = ((kind_index & 0x2) << 1) | (kind_index & 0x1);
    return static_cast<ElementsKind>(kind_int);
  };

  int unique_kind_count;
  if (!CanInlineArrayResizingBuiltin(broker(), possible_maps, map_kinds,
                                     elements_kind_to_index, &unique_kind_count,
                                     true)) {
    if (v8_flags.trace_maglev_graph_building) {
      std::cout << "  ! Failed to reduce Array.prototype.pop - Map doesn't "
                   "support fast resizing"
                << std::endl;
    }
    return ReduceResult::Fail();
  }

  MaglevSubGraphBuilder sub_graph(this, 2);
  MaglevSubGraphBuilder::Variable var_value(0);
  MaglevSubGraphBuilder::Variable var_new_array_length(1);

  std::optional<MaglevSubGraphBuilder::Label> do_return =
      std::make_optional<MaglevSubGraphBuilder::Label>(
          &sub_graph, unique_kind_count + 1,
          std::initializer_list<MaglevSubGraphBuilder::Variable*>{
              &var_value, &var_new_array_length});
  MaglevSubGraphBuilder::Label empty_array(&sub_graph, 1);

  ValueNode* old_array_length_smi;
  GET_VALUE_OR_ABORT(old_array_length_smi,
                     GetSmiValue(BuildLoadJSArrayLength(receiver)));

  // If the array is empty, skip the pop and return undefined.
  sub_graph.GotoIfTrue<BranchIfReferenceEqual>(
      &empty_array, {old_array_length_smi, GetSmiConstant(0)});

  ValueNode* elements_array = BuildLoadElements(receiver);
  ValueNode* new_array_length_smi =
      AddNewNode<CheckedSmiDecrement>({old_array_length_smi});
  ValueNode* new_array_length =
      AddNewNode<UnsafeSmiUntag>({new_array_length_smi});
  sub_graph.set(var_new_array_length, new_array_length_smi);

  auto build_array_pop = [&](ElementsKind kind) {
    // Handle COW if needed.
    ValueNode* writable_elements_array =
        IsSmiOrObjectElementsKind(kind)
            ? AddNewNode<EnsureWritableFastElements>({elements_array, receiver})
            : elements_array;

    // Store new length.
    AddNewNode<StoreTaggedFieldNoWriteBarrier>({receiver, new_array_length_smi},
                                               JSArray::kLengthOffset,
                                               StoreTaggedMode::kDefault);

    // Load the value and store the hole in it's place.
    ValueNode* value;
    if (IsDoubleElementsKind(kind)) {
      value = BuildLoadFixedDoubleArrayElement(writable_elements_array,
                                               new_array_length);
      BuildStoreFixedDoubleArrayElement(
          writable_elements_array, new_array_length,
          GetFloat64Constant(Float64::FromBits(kHoleNanInt64)));
    } else {
      DCHECK(IsSmiElementsKind(kind) || IsObjectElementsKind(kind));
      value =
          BuildLoadFixedArrayElement(writable_elements_array, new_array_length);
      BuildStoreFixedArrayElement(writable_elements_array, new_array_length,
                                  GetRootConstant(RootIndex::kTheHoleValue));
    }

    if (IsHoleyElementsKind(kind)) {
      value = AddN
"""


```