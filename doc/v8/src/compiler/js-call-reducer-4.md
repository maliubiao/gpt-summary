Response: My thought process for summarizing the `js-call-reducer.cc` file goes like this:

1. **Understand the Context:** The prompt explicitly states this is part 5 of 6 for the `v8/src/compiler/js-call-reducer.cc` file. It also mentions the previous parts. This immediately tells me the file is about *optimizing JavaScript calls* within the V8 compiler's Turbofan pipeline. The "reducer" part suggests transforming or simplifying these calls.

2. **Scan for Keywords and Patterns:** I quickly scan the code for recurring patterns, function names, and class names. Key things that jump out are:
    * `JSCallReducer::Reduce...`: This is a very common pattern, indicating individual functions responsible for handling specific JavaScript call types (e.g., `ReduceArrayPrototypeSlice`, `ReduceStringPrototypeCharAt`).
    * Method names like `Array.prototype.slice`, `String.prototype.startsWith`, `Promise.prototype.then`, etc. These directly link the code to standard JavaScript APIs.
    * Operations like `CheckString`, `CheckBounds`, `LoadField`, `StoreField`, `Call`, `CreateObject`, etc. These hint at the low-level operations the reducer uses to transform the calls.
    * The presence of `MapInference`, `dependencies()`, and `SpeculationMode`. This points to the optimization strategies: understanding object types, relying on runtime behavior, and handling potential deoptimizations.
    * Assembler usage (`JSCallReducerAssembler`). This signifies a more complex inlining approach where assembly-like instructions are generated.
    * Mentions of `Builtins::CallableFor`. This indicates the reducer is sometimes replacing JavaScript calls with direct calls to optimized built-in functions.

3. **Group Functionality by JavaScript API:**  The file is organized around optimizing calls to specific JavaScript methods and constructors. I start grouping the observed `Reduce...` functions by the JavaScript object they operate on:
    * **Array:** `ReduceArrayPrototypeSlice`, `ReduceArrayIsArray`, `ReduceArrayIterator`, `ReduceArrayIteratorPrototypeNext`
    * **String:** `ReduceStringPrototypeStringAt`, `ReduceStringPrototypeStartsWith`, `ReduceStringPrototypeEndsWith`, `ReduceStringPrototypeCharAt`, `ReduceStringFromCharCode`, `ReduceStringFromCodePoint`, `ReduceStringPrototypeIterator`, `ReduceStringPrototypeConcat`, `ReduceStringConstructor`
    * **Promise:** `ReducePromiseConstructor`, `ReducePromisePrototypeCatch`, `ReducePromisePrototypeFinally`, `ReducePromisePrototypeThen`, `ReducePromiseResolveTrampoline`
    * **TypedArray:** `ReduceTypedArrayConstructor`, `ReduceTypedArrayPrototypeToStringTag`, `ReduceArrayBufferViewByteLengthAccessor`, `ReduceArrayBufferViewByteOffsetAccessor`, `ReduceTypedArrayPrototypeLength`
    * **Number:** `ReduceNumberIsFinite`, `ReduceNumberIsInteger`, `ReduceNumberIsSafeInteger`, `ReduceNumberIsNaN`
    * **Map/Set:** `ReduceMapPrototypeGet`, `ReduceMapPrototypeHas`, `ReduceSetPrototypeHas`, `ReduceCollectionIteration`

4. **Identify Core Optimization Techniques:**  As I go through the grouped functions, I note the common optimization patterns:
    * **Inlining:** Replacing JavaScript calls with more direct sequences of simpler operations (e.g., for `String.prototype.charAt`).
    * **Specialized Built-ins:**  Substituting calls with optimized built-in functions (`Builtins::kCloneFastJSArray`).
    * **Type Specialization:**  Using `MapInference` to understand object types and generate more efficient code based on those types.
    * **Guard Conditions:**  Inserting checks (`CheckString`, `CheckBounds`) to ensure assumptions hold at runtime, with potential deoptimization if they don't.
    * **Constant Folding:**  Evaluating expressions at compile time when inputs are known constants (e.g., in `ReduceStringPrototypeCharAt`).
    * **Assembler Integration:** For complex inlining scenarios.
    * **Promise-Specific Optimizations:**  Directly manipulating the promise internal state.

5. **Connect to JavaScript Functionality (with Examples):** For each major category of JavaScript API, I think of simple JavaScript examples that would trigger the optimizations being described. This helps illustrate *why* the reducer is doing what it's doing. For example:
    * `Array.prototype.slice()`:  The common case of cloning an array.
    * `String.prototype.charAt()`:  Accessing individual characters.
    * `Promise` methods: Chaining and handling asynchronous operations.

6. **Summarize the Overall Function:** Based on the identified patterns and techniques, I formulate a high-level summary that captures the essence of the file's purpose. This involves mentioning the core goal (optimizing JavaScript calls), the context within the Turbofan pipeline, and the key strategies employed.

7. **Refine and Structure:** I organize the information logically, starting with a general summary, then diving into specific JavaScript API optimizations, and finally highlighting the core optimization techniques. I use clear and concise language. I make sure to address the "part 5 of 6" aspect by noting that it builds upon previous parts and contributes to the overall call optimization.

By following these steps, I can effectively analyze the C++ code and generate a comprehensive summary that explains its functionality and its relationship to JavaScript. The iterative process of scanning, grouping, and identifying patterns is crucial for understanding the purpose and techniques used in the code.
这是 `v8/src/compiler/js-call-reducer.cc` 文件的第五部分，该文件是 V8 引擎中 Turbofan 编译器的一个关键组件。它的主要功能是**对 JavaScript 函数调用进行优化**，通过模式匹配和分析，将高层次的 JavaScript 调用转换为更高效的底层操作。

**本部分的功能可以归纳为继续处理和优化特定 JavaScript 内置对象和方法的调用，主要集中在以下几个方面：**

* **数组 (Array) 相关方法的优化：**
    * `Array.prototype.slice()`:  针对特定情况（如克隆数组）进行优化。
    * `Array.isArray()`: 直接判断是否为数组。
    * `Array.prototype` 的迭代器方法 (`Array.prototype.values()`, `Array.prototype.keys()`, `Array.prototype.entries()`): 将其转换为更底层的 `JSCreateArrayIterator` 操作。
    * 数组迭代器原型链上的 `next()` 方法的优化，直接进行元素加载和索引更新。

* **字符串 (String) 相关方法的优化：**
    * `String.prototype.charCodeAt()` 和 `String.prototype.codePointAt()`:  直接获取指定位置的字符码点。
    * `String.prototype.startsWith()` 和 `String.prototype.endsWith()`: 尝试内联匹配逻辑。
    * `String.prototype.charAt()`:  尝试常量折叠和内联优化。
    * `String.fromCharCode()` 和 `String.fromCodePoint()`:  将字符码点转换为字符串。
    * `String.prototype[@@iterator]()`:  创建字符串迭代器。
    * `String.prototype.concat()`:  将字符串连接操作转换为底层的 `StringConcat` 操作。
    * `String` 构造函数 (`new String()`):  创建字符串包装对象。
    * `String.prototype.localeCompare()` (在 `V8_INTL_SUPPORT` 宏定义下):  尝试使用快速路径进行优化。
    * 字符串迭代器原型链上的 `next()` 方法的优化。

* **Promise 相关方法的优化：**
    * `Promise` 构造函数 (`new Promise()`):  直接创建 Promise 对象。
    * `Promise.prototype.catch()`:  转换为调用 `Promise.prototype.then()` 并只传入 rejected 回调。
    * `Promise.prototype.finally()`:  转换为调用 `Promise.prototype.then()` 并插入相应的 finally 回调逻辑。
    * `Promise.prototype.then()`:  直接创建新的 Promise 并链接到当前 Promise。
    * `Promise.resolve()`:  将给定的值包装成一个 resolved 的 Promise。

* **类型化数组 (TypedArray) 相关方法的优化：**
    * 类型化数组的构造函数 (`new Uint8Array()`, `new Float64Array()`, 等):  直接创建类型化数组。
    * 类型化数组原型链上的 `@@toStringTag` 访问器的优化，直接返回类型化数组的标签字符串。
    * `ArrayBufferView` 的 `byteLength` 和 `byteOffset` 访问器的优化，直接读取相应的字段。
    * 类型化数组的 `length` 访问器的优化。

* **Number 相关方法的优化：**
    * `Number.isFinite()`, `Number.isInteger()`, `Number.isSafeInteger()`, `Number.isNaN()`:  直接使用底层的判断操作。

* **Map 和 Set 相关方法的优化：**
    * `Map.prototype.get()`:  直接查找 Map 中的键值对。
    * `Map.prototype.has()` 和 `Set.prototype.has()`:  直接判断 Map 或 Set 中是否存在指定元素。
    * Map 和 Set 的迭代器方法 (`Map.prototype.entries()`, `Set.prototype.values()`, 等):  将其转换为更底层的迭代器创建操作。

**与 JavaScript 功能的关系及 JavaScript 示例：**

本部分代码直接对应着 JavaScript 中常用的内置对象和方法。`JSCallReducer` 的目标就是当在 JavaScript 代码中调用这些方法时，能够在编译阶段进行识别并将其替换为更高效的底层实现，从而提升代码执行性能。

**例如：`ReduceArrayPrototypeSlice()`**

在 JavaScript 中：

```javascript
const arr = [1, 2, 3, 4, 5];
const newArr = arr.slice(); // 克隆数组
```

`ReduceArrayPrototypeSlice()` 函数会尝试识别这种克隆数组的模式（当 `start` 为 0，`end` 为 `undefined` 时），并将其优化为调用内置的 `CloneFastJSArray` 函数，而不是执行更通用的 `slice` 逻辑。

**例如：`ReduceStringPrototypeCharAt()`**

在 JavaScript 中：

```javascript
const str = "hello";
const char = str.charAt(1); // 获取索引为 1 的字符
```

`ReduceStringPrototypeCharAt()` 函数会尝试将这个调用转换为底层的 `StringCharCodeAt` 或 `StringCodePointAt` 操作，直接访问字符串内部的字符数据，避免了调用复杂的 JavaScript 函数的开销。

**总结来说，这部分 `js-call-reducer.cc` 的功能是持续对 JavaScript 的内置方法调用进行精细化的分析和优化，旨在将常见的、可以被高效实现的 JavaScript 操作在编译时转换为更底层的、性能更高的操作，从而提升整体 JavaScript 代码的执行效率。** 它依赖于类型推断、内联、常量折叠等多种编译优化技术。

### 提示词
```
这是目录为v8/src/compiler/js-call-reducer.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```
count),
                         count + 1, &values_to_merge.front());
  }

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 22.1.3.23 Array.prototype.slice ( )
Reduction JSCallReducer::ReduceArrayPrototypeSlice(Node* node) {
  if (!v8_flags.turbo_inline_array_builtins) return NoChange();
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* start = n.ArgumentOr(0, jsgraph()->ZeroConstant());
  Node* end = n.ArgumentOrUndefined(1, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  // Optimize for the case where we simply clone the {receiver}, i.e. when the
  // {start} is zero and the {end} is undefined (meaning it will be set to
  // {receiver}s "length" property). This logic should be in sync with
  // ReduceArrayPrototypeSlice (to a reasonable degree). This is because
  // CloneFastJSArray produces arrays which are potentially COW. If there's a
  // discrepancy, TF generates code which produces a COW array and then expects
  // it to be non-COW (or the other way around) -> immediate deopt.
  if (!NumberMatcher(start).Is(0) ||
      !HeapObjectMatcher(end).Is(factory()->undefined_value())) {
    return NoChange();
  }

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  // Check that the maps are of JSArray (and more).
  // TODO(turbofan): Consider adding special case for the common pattern
  // `slice.call(arguments)`, for example jQuery makes heavy use of that.
  bool can_be_holey = false;
  for (MapRef receiver_map : receiver_maps) {
    if (!receiver_map.supports_fast_array_iteration(broker())) {
      return inference.NoChange();
    }
    if (IsHoleyElementsKind(receiver_map.elements_kind())) {
      can_be_holey = true;
    }
  }

  if (!dependencies()->DependOnArraySpeciesProtector()) {
    return inference.NoChange();
  }
  if (can_be_holey && !dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // TODO(turbofan): We can do even better here, either adding a CloneArray
  // simplified operator, whose output type indicates that it's an Array,
  // saving subsequent checks, or yet better, by introducing new operators
  // CopySmiOrObjectElements / CopyDoubleElements and inlining the JSArray
  // allocation in here. That way we'd even get escape analysis and scalar
  // replacement to help in some cases.
  Callable callable =
      Builtins::CallableFor(isolate(), Builtin::kCloneFastJSArray);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph()->zone(), callable.descriptor(),
      callable.descriptor().GetStackParameterCount(), CallDescriptor::kNoFlags,
      Operator::kNoThrow | Operator::kNoDeopt);

  // Calls to Builtin::kCloneFastJSArray produce COW arrays
  // if the original array is COW
  Node* clone = effect =
      graph()->NewNode(common()->Call(call_descriptor),
                       jsgraph()->HeapConstantNoHole(callable.code()), receiver,
                       context, effect, control);

  ReplaceWithValue(node, clone, effect, control);
  return Replace(clone);
}

// ES6 section 22.1.2.2 Array.isArray ( arg )
Reduction JSCallReducer::ReduceArrayIsArray(Node* node) {
  // We certainly know that undefined is not an array.
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Node* object = n.Argument(0);
  node->ReplaceInput(0, object);
  node->ReplaceInput(1, context);
  node->ReplaceInput(2, frame_state);
  node->ReplaceInput(3, effect);
  node->ReplaceInput(4, control);
  node->TrimInputCount(5);
  NodeProperties::ChangeOp(node, javascript()->ObjectIsArray());
  return Changed(node);
}

Reduction JSCallReducer::ReduceArrayIterator(Node* node,
                                             ArrayIteratorKind array_kind,
                                             IterationKind iteration_kind) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  // Check if we know that {receiver} is a valid JSReceiver.
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAreJSReceiver()) {
    return NoChange();
  }

  // TypedArray iteration is stricter: it throws if the receiver is not a typed
  // array. So don't bother optimizing in that case.
  if (array_kind == ArrayIteratorKind::kTypedArray &&
      !inference.AllOfInstanceTypesAre(InstanceType::JS_TYPED_ARRAY_TYPE)) {
    return NoChange();
  }

  if (array_kind == ArrayIteratorKind::kTypedArray) {
    // Make sure we deopt when the JSArrayBuffer is detached.
    if (!dependencies()->DependOnArrayBufferDetachingProtector()) {
      CallParameters const& p = CallParametersOf(node->op());
      if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
        return NoChange();
      }

      std::set<ElementsKind> elements_kinds;
      for (MapRef map : inference.GetMaps()) {
        elements_kinds.insert(map.elements_kind());
      }

      // The following detach check is built with the given {elements_kinds} in
      // mind, so we have to install dependency on those.
      inference.RelyOnMapsPreferStability(
          dependencies(), jsgraph(), &effect, control,
          CallParametersOf(node->op()).feedback());

      JSCallReducerAssembler a(this, node);
      a.CheckIfTypedArrayWasDetached(
          TNode<JSTypedArray>::UncheckedCast(receiver),
          std::move(elements_kinds), p.feedback());
      std::tie(effect, control) = ReleaseEffectAndControlFromAssembler(&a);
    }
  }

  // JSCreateArrayIterator doesn't have control output, so we bypass the old
  // JSCall node on the control chain.
  ReplaceWithValue(node, node, node, control);

  // Morph the {node} into a JSCreateArrayIterator with the given {kind}.
  node->ReplaceInput(0, receiver);
  node->ReplaceInput(1, context);
  node->ReplaceInput(2, effect);
  node->ReplaceInput(3, control);
  node->TrimInputCount(4);
  NodeProperties::ChangeOp(node,
                           javascript()->CreateArrayIterator(iteration_kind));
  return Changed(node);
}

// ES #sec-%arrayiteratorprototype%.next
Reduction JSCallReducer::ReduceArrayIteratorPrototypeNext(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  Node* iterator = n.receiver();
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();

  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  if (iterator->opcode() != IrOpcode::kJSCreateArrayIterator) return NoChange();

  IterationKind const iteration_kind =
      CreateArrayIteratorParametersOf(iterator->op()).kind();
  Node* iterated_object = NodeProperties::GetValueInput(iterator, 0);
  Effect iterator_effect{NodeProperties::GetEffectInput(iterator)};

  MapInference inference(broker(), iterated_object, iterator_effect);
  if (!inference.HaveMaps()) return NoChange();
  ZoneRefSet<Map> const& iterated_object_maps = inference.GetMaps();

  // Check that various {iterated_object_maps} have compatible elements kinds.
  ElementsKind elements_kind = iterated_object_maps[0].elements_kind();
  if (IsTypedArrayElementsKind(elements_kind)) {
    // TurboFan doesn't support loading from BigInt typed arrays yet.
    if (elements_kind == BIGUINT64_ELEMENTS ||
        elements_kind == BIGINT64_ELEMENTS) {
      return inference.NoChange();
    }
    for (MapRef iterated_object_map : iterated_object_maps) {
      if (iterated_object_map.elements_kind() != elements_kind) {
        return inference.NoChange();
      }
    }
  } else {
    if (!CanInlineArrayIteratingBuiltin(broker(), iterated_object_maps,
                                        &elements_kind)) {
      return inference.NoChange();
    }
  }

  if (IsHoleyElementsKind(elements_kind) &&
      !dependencies()->DependOnNoElementsProtector()) {
    return inference.NoChange();
  }

  if (IsFloat16TypedArrayElementsKind(elements_kind)) {
    // TODO(v8:14212): Allow optimizing Float16 typed arrays here, once they are
    // supported in the rest of the compiler.
    return inference.NoChange();
  }

  // Since the map inference was done relative to {iterator_effect} rather than
  // {effect}, we need to guard the use of the map(s) even when the inference
  // was reliable.
  inference.InsertMapChecks(jsgraph(), &effect, control, p.feedback());

  if (IsTypedArrayElementsKind(elements_kind)) {
    // See if we can skip the detaching check.
    if (!dependencies()->DependOnArrayBufferDetachingProtector()) {
      // Bail out if the {iterated_object}s JSArrayBuffer was detached.
      Node* buffer = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForJSArrayBufferViewBuffer()),
          iterated_object, effect, control);
      Node* buffer_bit_field = effect = graph()->NewNode(
          simplified()->LoadField(AccessBuilder::ForJSArrayBufferBitField()),
          buffer, effect, control);
      Node* check = graph()->NewNode(
          simplified()->NumberEqual(),
          graph()->NewNode(
              simplified()->NumberBitwiseAnd(), buffer_bit_field,
              jsgraph()->ConstantNoHole(JSArrayBuffer::WasDetachedBit::kMask)),
          jsgraph()->ZeroConstant());
      effect = graph()->NewNode(
          simplified()->CheckIf(DeoptimizeReason::kArrayBufferWasDetached,
                                p.feedback()),
          check, effect, control);
    }
  }

  // Load the [[NextIndex]] from the {iterator} and leverage the fact
  // that we definitely know that it's in Unsigned32 range since the
  // {iterated_object} is either a JSArray or a JSTypedArray. For the
  // latter case we even know that it's a Smi in UnsignedSmall range.
  FieldAccess index_access = AccessBuilder::ForJSArrayIteratorNextIndex();
  if (IsTypedArrayElementsKind(elements_kind)) {
    index_access.type = TypeCache::Get()->kJSTypedArrayLengthType;
  } else {
    index_access.type = TypeCache::Get()->kJSArrayLengthType;
  }
  Node* index = effect = graph()->NewNode(simplified()->LoadField(index_access),
                                          iterator, effect, control);

  // Load the elements of the {iterated_object}. While it feels
  // counter-intuitive to place the elements pointer load before
  // the condition below, as it might not be needed (if the {index}
  // is out of bounds for the {iterated_object}), it's better this
  // way as it allows the LoadElimination to eliminate redundant
  // reloads of the elements pointer.
  Node* elements = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSObjectElements()),
      iterated_object, effect, control);

  // Load the length of the {iterated_object}. Due to the map checks we
  // already know something about the length here, which we can leverage
  // to generate Word32 operations below without additional checking.
  FieldAccess length_access =
      IsTypedArrayElementsKind(elements_kind)
          ? AccessBuilder::ForJSTypedArrayLength()
          : AccessBuilder::ForJSArrayLength(elements_kind);
  Node* length = effect = graph()->NewNode(
      simplified()->LoadField(length_access), iterated_object, effect, control);

  // Check whether {index} is within the valid range for the {iterated_object}.
  Node* check = graph()->NewNode(simplified()->NumberLessThan(), index, length);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kNone), check, control);

  Node* done_true;
  Node* value_true;
  Node* etrue = effect;
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  {
    // This extra check exists to refine the type of {index} but also to break
    // an exploitation technique that abuses typer mismatches.
    if (v8_flags.turbo_typer_hardening) {
      index = etrue = graph()->NewNode(
          simplified()->CheckBounds(p.feedback(),
                                    CheckBoundsFlag::kAbortOnOutOfBounds),
          index, length, etrue, if_true);
    }

    done_true = jsgraph()->FalseConstant();
    if (iteration_kind == IterationKind::kKeys) {
      // Just return the {index}.
      value_true = index;
    } else {
      DCHECK(iteration_kind == IterationKind::kEntries ||
             iteration_kind == IterationKind::kValues);

      if (IsTypedArrayElementsKind(elements_kind)) {
        Node* base_ptr = etrue =
            graph()->NewNode(simplified()->LoadField(
                                 AccessBuilder::ForJSTypedArrayBasePointer()),
                             iterated_object, etrue, if_true);
        Node* external_ptr = etrue = graph()->NewNode(
            simplified()->LoadField(
                AccessBuilder::ForJSTypedArrayExternalPointer()),
            iterated_object, etrue, if_true);

        ExternalArrayType array_type = kExternalInt8Array;
        switch (elements_kind) {
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype) \
  case TYPE##_ELEMENTS:                           \
    array_type = kExternal##Type##Array;          \
    break;
          TYPED_ARRAYS(TYPED_ARRAY_CASE)
          default:
            UNREACHABLE();
#undef TYPED_ARRAY_CASE
        }

        Node* buffer = etrue =
            graph()->NewNode(simplified()->LoadField(
                                 AccessBuilder::ForJSArrayBufferViewBuffer()),
                             iterated_object, etrue, if_true);

        value_true = etrue =
            graph()->NewNode(simplified()->LoadTypedElement(array_type), buffer,
                             base_ptr, external_ptr, index, etrue, if_true);
      } else {
        value_true = etrue = graph()->NewNode(
            simplified()->LoadElement(
                AccessBuilder::ForFixedArrayElement(elements_kind)),
            elements, index, etrue, if_true);

        // Convert hole to undefined if needed.
        if (IsHoleyElementsKind(elements_kind)) {
          value_true = ConvertHoleToUndefined(value_true, elements_kind);
        }
      }

      if (iteration_kind == IterationKind::kEntries) {
        // Allocate elements for key/value pair
        value_true = etrue =
            graph()->NewNode(javascript()->CreateKeyValueArray(), index,
                             value_true, context, etrue);
      } else {
        DCHECK_EQ(IterationKind::kValues, iteration_kind);
      }
    }

    // Increment the [[NextIndex]] field in the {iterator}. The TypeGuards
    // above guarantee that the {next_index} is in the UnsignedSmall range.
    Node* next_index = graph()->NewNode(simplified()->NumberAdd(), index,
                                        jsgraph()->OneConstant());
    etrue = graph()->NewNode(simplified()->StoreField(index_access), iterator,
                             next_index, etrue, if_true);
  }

  Node* done_false;
  Node* value_false;
  Node* efalse = effect;
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  {
    // iterator.[[NextIndex]] >= array.length, stop iterating.
    done_false = jsgraph()->TrueConstant();
    value_false = jsgraph()->UndefinedConstant();

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
      Node* end_index = jsgraph()->ConstantNoHole(index_access.type.Max());
      efalse = graph()->NewNode(simplified()->StoreField(index_access),
                                iterator, end_index, efalse, if_false);
    }
  }

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       value_true, value_false, control);
  Node* done =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       done_true, done_false, control);

  // Create IteratorResult object.
  value = effect = graph()->NewNode(javascript()->CreateIterResultObject(),
                                    value, done, context, effect);
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES6 section 21.1.3.2 String.prototype.charCodeAt ( pos )
// ES6 section 21.1.3.3 String.prototype.codePointAt ( pos )
Reduction JSCallReducer::ReduceStringPrototypeStringAt(
    const Operator* string_access_operator, Node* node) {
  DCHECK(string_access_operator->opcode() == IrOpcode::kStringCharCodeAt ||
         string_access_operator->opcode() == IrOpcode::kStringCodePointAt);
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* index = n.ArgumentOr(0, jsgraph()->ZeroConstant());
  Effect effect = n.effect();
  Control control = n.control();

  // Ensure that the {receiver} is actually a String.
  receiver = effect = graph()->NewNode(simplified()->CheckString(p.feedback()),
                                       receiver, effect, control);

  // Determine the {receiver} length.
  Node* receiver_length =
      graph()->NewNode(simplified()->StringLength(), receiver);

  // Check that the {index} is within range.
  index = effect = graph()->NewNode(simplified()->CheckBounds(p.feedback()),
                                    index, receiver_length, effect, control);

  // Return the character from the {receiver} as single character string.
  Node* value = effect = graph()->NewNode(string_access_operator, receiver,
                                          index, effect, control);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES section 21.1.3.20
// String.prototype.startsWith ( searchString [ , position ] )
Reduction JSCallReducer::ReduceStringPrototypeStartsWith(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  TNode<Object> search_element = n.ArgumentOrUndefined(0, jsgraph());

  // Here are three conditions:
  // First, If search_element is definitely not a string, we make no change.
  // Second, If search_element is definitely a string and its length is less
  // or equal than max inline matching sequence threshold, we could inline
  // the entire matching sequence.
  // Third, we try to inline, and have a runtime deopt if search_element is
  // not a string.
  HeapObjectMatcher search_element_matcher(search_element);
  if (search_element_matcher.HasResolvedValue()) {
    ObjectRef target_ref = search_element_matcher.Ref(broker());
    if (!target_ref.IsString()) return NoChange();
    StringRef search_element_string = target_ref.AsString();
    if (!search_element_string.IsContentAccessible()) return NoChange();
    int length = search_element_string.length();
    // If search_element's length is less or equal than
    // kMaxInlineMatchSequence, we inline the entire
    // matching sequence.
    if (length <= kMaxInlineMatchSequence) {
      JSCallReducerAssembler a(this, node);
      Node* subgraph = a.ReduceStringPrototypeStartsWith(search_element_string);
      return ReplaceWithSubgraph(&a, subgraph);
    }
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeStartsWith();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES section 21.1.3.7
// String.prototype.endsWith(searchString [, endPosition])
Reduction JSCallReducer::ReduceStringPrototypeEndsWith(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  TNode<Object> search_element = n.ArgumentOrUndefined(0, jsgraph());

  // Here are three conditions:
  // First, If search_element is definitely not a string, we make no change.
  // Second, If search_element is definitely a string and its length is less
  // or equal than max inline matching sequence threshold, we could inline
  // the entire matching sequence.
  // Third, we try to inline, and have a runtime deopt if search_element is
  // not a string.
  HeapObjectMatcher search_element_matcher(search_element);
  if (search_element_matcher.HasResolvedValue()) {
    ObjectRef target_ref = search_element_matcher.Ref(broker());
    if (!target_ref.IsString()) return NoChange();
    StringRef search_element_string = target_ref.AsString();
    if (!search_element_string.IsContentAccessible()) return NoChange();
    int length = search_element_string.length();
    // If search_element's length is less or equal than
    // kMaxInlineMatchSequence, we inline the entire
    // matching sequence.
    if (length <= kMaxInlineMatchSequence) {
      JSCallReducerAssembler a(this, node);
      Node* subgraph = a.ReduceStringPrototypeEndsWith(search_element_string);
      return ReplaceWithSubgraph(&a, subgraph);
    }
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeEndsWith();
  return ReplaceWithSubgraph(&a, subgraph);
}

// ES section 21.1.3.1 String.prototype.charAt ( pos )
Reduction JSCallReducer::ReduceStringPrototypeCharAt(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* index = n.ArgumentOr(0, jsgraph()->ZeroConstant());

  // Attempt to constant fold the operation when we know
  // that receiver is a string and index is a number.
  HeapObjectMatcher receiver_matcher(receiver);
  NumberMatcher index_matcher(index);
  if (receiver_matcher.HasResolvedValue()) {
    HeapObjectRef receiver_ref = receiver_matcher.Ref(broker());
    if (!receiver_ref.IsString()) return NoChange();
    StringRef receiver_string = receiver_ref.AsString();
    bool is_content_accessible = receiver_string.IsContentAccessible();
    bool is_integer_in_max_range =
        index_matcher.IsInteger() &&
        index_matcher.IsInRange(
            0.0, static_cast<double>(JSObject::kMaxElementIndex));
    if (is_content_accessible && is_integer_in_max_range) {
      const uint32_t index =
          static_cast<uint32_t>(index_matcher.ResolvedValue());
      JSCallReducerAssembler a(this, node);
      Node* subgraph = a.ReduceStringPrototypeCharAt(receiver_string, index);
      return ReplaceWithSubgraph(&a, subgraph);
    }
  }

  JSCallReducerAssembler a(this, node);
  Node* subgraph = a.ReduceStringPrototypeCharAt();
  return ReplaceWithSubgraph(&a, subgraph);
}

#ifdef V8_INTL_SUPPORT

Reduction JSCallReducer::ReduceStringPrototypeToLowerCaseIntl(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  Effect effect = n.effect();
  Control control = n.control();

  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);

  NodeProperties::ReplaceEffectInput(node, effect);
  RelaxEffectsAndControls(node);
  node->ReplaceInput(0, receiver);
  node->TrimInputCount(1);
  NodeProperties::ChangeOp(node, simplified()->StringToLowerCaseIntl());
  NodeProperties::SetType(node, Type::String());
  return Changed(node);
}

Reduction JSCallReducer::ReduceStringPrototypeToUpperCaseIntl(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  Effect effect = n.effect();
  Control control = n.control();

  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);

  NodeProperties::ReplaceEffectInput(node, effect);
  RelaxEffectsAndControls(node);
  node->ReplaceInput(0, receiver);
  node->TrimInputCount(1);
  NodeProperties::ChangeOp(node, simplified()->StringToUpperCaseIntl());
  NodeProperties::SetType(node, Type::String());
  return Changed(node);
}

#endif  // V8_INTL_SUPPORT

// ES #sec-string.fromcharcode
Reduction JSCallReducer::ReduceStringFromCharCode(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() == 1) {
    Effect effect = n.effect();
    Control control = n.control();
    Node* input = n.Argument(0);

    input = effect = graph()->NewNode(
        simplified()->SpeculativeToNumber(NumberOperationHint::kNumberOrOddball,
                                          p.feedback()),
        input, effect, control);

    Node* value =
        graph()->NewNode(simplified()->StringFromSingleCharCode(), input);
    ReplaceWithValue(node, value, effect);
    return Replace(value);
  }
  return NoChange();
}

// ES #sec-string.fromcodepoint
Reduction JSCallReducer::ReduceStringFromCodePoint(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  if (n.ArgumentCount() != 1) return NoChange();

  Effect effect = n.effect();
  Control control = n.control();
  Node* input = n.Argument(0);

  input = effect = graph()->NewNode(
      simplified()->CheckBounds(p.feedback(),
                                CheckBoundsFlag::kConvertStringAndMinusZero),
      input, jsgraph()->ConstantNoHole(0x10FFFF + 1), effect, control);

  Node* value =
      graph()->NewNode(simplified()->StringFromSingleCodePoint(), input);
  ReplaceWithValue(node, value, effect);
  return Replace(value);
}

Reduction JSCallReducer::ReduceStringPrototypeIterator(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);
  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);
  Node* iterator = effect =
      graph()->NewNode(javascript()->CreateStringIterator(), receiver,
                       jsgraph()->NoContextConstant(), effect);
  ReplaceWithValue(node, iterator, effect, control);
  return Replace(iterator);
}

#ifdef V8_INTL_SUPPORT

Reduction JSCallReducer::ReduceStringPrototypeLocaleCompareIntl(Node* node) {
  JSCallNode n(node);
  // Signature: receiver.localeCompare(compareString, locales, options)
  if (n.ArgumentCount() < 1 || n.ArgumentCount() > 3) {
    return NoChange();
  }

  {
    DirectHandle<Object> locales;
    {
      HeapObjectMatcher m(n.ArgumentOrUndefined(1, jsgraph()));
      if (!m.HasResolvedValue()) return NoChange();
      if (m.Is(factory()->undefined_value())) {
        locales = factory()->undefined_value();
      } else {
        ObjectRef ref = m.Ref(broker());
        if (!ref.IsString()) return NoChange();
        StringRef sref = ref.AsString();
        if (std::optional<Handle<String>> maybe_locales =
                sref.ObjectIfContentAccessible(broker())) {
          locales = *maybe_locales;
        } else {
          return NoChange();
        }
      }
    }

    TNode<Object> options = n.ArgumentOrUndefined(2, jsgraph());
    {
      HeapObjectMatcher m(options);
      if (!m.Is(factory()->undefined_value())) {
        return NoChange();
      }
    }

    if (Intl::CompareStringsOptionsFor(broker()->local_isolate_or_isolate(),
                                       locales, factory()->undefined_value()) !=
        Intl::CompareStringsOptions::kTryFastPath) {
      return NoChange();
    }
  }

  Callable callable =
      Builtins::CallableFor(isolate(), Builtin::kStringFastLocaleCompare);
  auto call_descriptor = Linkage::GetStubCallDescriptor(
      graph()->zone(), callable.descriptor(),
      callable.descriptor().GetStackParameterCount(),
      CallDescriptor::kNeedsFrameState);
  node->RemoveInput(n.FeedbackVectorIndex());
  if (n.ArgumentCount() == 3) {
    node->RemoveInput(n.ArgumentIndex(2));
  } else if (n.ArgumentCount() == 1) {
    node->InsertInput(graph()->zone(), n.LastArgumentIndex() + 1,
                      jsgraph()->UndefinedConstant());
  } else {
    DCHECK_EQ(2, n.ArgumentCount());
  }
  node->InsertInput(graph()->zone(), 0,
                    jsgraph()->HeapConstantNoHole(callable.code()));
  NodeProperties::ChangeOp(node, common()->Call(call_descriptor));
  return Changed(node);
}
#endif  // V8_INTL_SUPPORT

Reduction JSCallReducer::ReduceStringIteratorPrototypeNext(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();
  Node* context = n.context();

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(JS_STRING_ITERATOR_TYPE)) {
    return NoChange();
  }

  Node* string = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSStringIteratorString()),
      receiver, effect, control);
  Node* index = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSStringIteratorIndex()),
      receiver, effect, control);
  Node* length = graph()->NewNode(simplified()->StringLength(), string);

  // branch0: if (index < length)
  Node* check0 =
      graph()->NewNode(simplified()->NumberLessThan(), index, length);
  Node* branch0 =
      graph()->NewNode(common()->Branch(BranchHint::kNone), check0, control);

  Node* etrue0 = effect;
  Node* if_true0 = graph()->NewNode(common()->IfTrue(), branch0);
  Node* done_true;
  Node* vtrue0;
  {
    done_true = jsgraph()->FalseConstant();
    vtrue0 = etrue0 = graph()->NewNode(simplified()->StringFromCodePointAt(),
                                       string, index, etrue0, if_true0);

    // Update iterator.[[NextIndex]]
    Node* char_length = graph()->NewNode(simplified()->StringLength(), vtrue0);
    index = graph()->NewNode(simplified()->NumberAdd(), index, char_length);
    etrue0 = graph()->NewNode(
        simplified()->StoreField(AccessBuilder::ForJSStringIteratorIndex()),
        receiver, index, etrue0, if_true0);
  }

  Node* if_false0 = graph()->NewNode(common()->IfFalse(), branch0);
  Node* done_false;
  Node* vfalse0;
  {
    vfalse0 = jsgraph()->UndefinedConstant();
    done_false = jsgraph()->TrueConstant();
  }

  control = graph()->NewNode(common()->Merge(2), if_true0, if_false0);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue0, effect, control);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2), vtrue0,
                       vfalse0, control);
  Node* done =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       done_true, done_false, control);

  value = effect = graph()->NewNode(javascript()->CreateIterResultObject(),
                                    value, done, context, effect);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

// ES #sec-string.prototype.concat
Reduction JSCallReducer::ReduceStringPrototypeConcat(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  const int parameter_count = n.ArgumentCount();
  if (parameter_count > 1) return NoChange();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Effect effect = n.effect();
  Control control = n.control();
  Node* receiver = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.receiver(), effect, control);

  if (parameter_count == 0) {
    ReplaceWithValue(node, receiver, effect, control);
    return Replace(receiver);
  }

  Node* argument = effect = graph()->NewNode(
      simplified()->CheckString(p.feedback()), n.Argument(0), effect, control);
  Node* receiver_length =
      graph()->NewNode(simplified()->StringLength(), receiver);
  Node* argument_length =
      graph()->NewNode(simplified()->StringLength(), argument);
  Node* length = graph()->NewNode(simplified()->NumberAdd(), receiver_length,
                                  argument_length);
  length = effect = graph()->NewNode(
      simplified()->CheckBounds(p.feedback()), length,
      jsgraph()->ConstantNoHole(String::kMaxLength + 1), effect, control);

  Node* value = graph()->NewNode(simplified()->StringConcat(), length, receiver,
                                 argument);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

FrameState CreateStringCreateLazyDeoptContinuationFrameState(
    JSGraph* graph, SharedFunctionInfoRef shared, Node* target, Node* context,
    Node* outer_frame_state) {
  Node* const receiver = graph->TheHoleConstant();
  Node* stack_parameters[]{receiver};
  const int stack_parameter_count = arraysize(stack_parameters);
  return CreateJavaScriptBuiltinContinuationFrameState(
      graph, shared, Builtin::kStringCreateLazyDeoptContinuation, target,
      context, stack_parameters, stack_parameter_count, outer_frame_state,
      ContinuationFrameStateMode::LAZY);
}

}  // namespace

Reduction JSCallReducer::ReduceStringConstructor(Node* node,
                                                 JSFunctionRef constructor) {
  JSConstructNode n(node);
  if (n.target() != n.new_target()) return NoChange();

  DCHECK_EQ(constructor, native_context().string_function(broker_));
  DCHECK(constructor.initial_map(broker_).IsJSPrimitiveWrapperMap());

  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  Node* primitive_value;
  if (n.ArgumentCount() == 0) {
    primitive_value = jsgraph()->EmptyStringConstant();
  } else {
    // Insert a construct stub frame into the chain of frame states. This will
    // reconstruct the proper frame when deoptimizing within the constructor.
    frame_state = CreateConstructInvokeStubFrameState(
        node, frame_state, constructor.shared(broker_), context, common(),
        graph());

    // This continuation takes the newly created primitive string, and wraps it
    // in a string wrapper, matching CreateStringWrapper.
    Node* continuation_frame_state =
        CreateStringCreateLazyDeoptContinuationFrameState(
            jsgraph(), constructor.shared(broker_), n.target(), context,
            frame_state);

    primitive_value = effect = control =
        graph()->NewNode(javascript()->ToString(), n.Argument(0), context,
                         continuation_frame_state, effect, control);

    // Rewire potential exception edges.
    Node* on_exception = nullptr;
    if (NodeProperties::IsExceptionalCall(node, &on_exception)) {
      // Create appropriate {IfException} and {IfSuccess} nodes.
      Node* if_exception =
          graph()->NewNode(common()->IfException(), effect, control);
      control = graph()->NewNode(common()->IfSuccess(), control);

      // Join the exception edges.
      Node* merge =
          graph()->NewNode(common()->Merge(2), if_exception, on_exception);
      Node* ephi = graph()->NewNode(common()->EffectPhi(2), if_exception,
                                    on_exception, merge);
      Node* phi =
          graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                           if_exception, on_exception, merge);
      ReplaceWithValue(on_exception, phi, ephi, merge);
      merge->ReplaceInput(1, on_exception);
      ephi->ReplaceInput(1, on_exception);
      phi->ReplaceInput(1, on_exception);
    }
  }

  RelaxControls(node, control);
  node->ReplaceInput(0, primitive_value);
  node->ReplaceInput(1, context);
  node->ReplaceInput(2, effect);
  node->TrimInputCount(3);
  NodeProperties::ChangeOp(node, javascript()->CreateStringWrapper());
  return Changed(node);
}

Reduction JSCallReducer::ReducePromiseConstructor(Node* node) {
  PromiseBuiltinReducerAssembler a(this, node);

  // We only inline when we have the executor.
  if (a.ConstructArity() < 1) return NoChange();
  // Only handle builtins Promises, not subclasses.
  if (a.TargetInput() != a.NewTargetInput()) return NoChange();
  if (!dependencies()->DependOnPromiseHookProtector()) return NoChange();

  TNode<Object> subgraph = a.ReducePromiseConstructor(native_context());
  return ReplaceWithSubgraph(&a, subgraph);
}

bool JSCallReducer::DoPromiseChecks(MapInference* inference) {
  if (!inference->HaveMaps()) return false;
  ZoneRefSet<Map> const& receiver_maps = inference->GetMaps();

  // Check whether all {receiver_maps} are JSPromise maps and
  // have the initial Promise.prototype as their [[Prototype]].
  for (MapRef receiver_map : receiver_maps) {
    if (!receiver_map.IsJSPromiseMap()) return false;
    HeapObjectRef prototype = receiver_map.prototype(broker());
    if (!prototype.equals(native_context().promise_prototype(broker()))) {
      return false;
    }
  }

  return true;
}

// ES section #sec-promise.prototype.catch
Reduction JSCallReducer::ReducePromisePrototypeCatch(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }
  int arity = p.arity_without_implicit_args();
  Node* receiver = n.receiver();
  Effect effect = n.effect();
  Control control = n.control();

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();

  if (!dependencies()->DependOnPromiseThenProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Massage the {node} to call "then" instead by first removing all inputs
  // following the onRejected parameter, and then filling up the parameters
  // to two inputs from the left with undefined.
  Node* target = jsgraph()->ConstantNoHole(
      native_context().promise_then(broker()), broker());
  NodeProperties::ReplaceValueInput(node, target, 0);
  NodeProperties::ReplaceEffectInput(node, effect);
  for (; arity > 1; --arity) node->RemoveInput(3);
  for (; arity < 2; ++arity) {
    node->InsertInput(graph()->zone(), 2, jsgraph()->UndefinedConstant());
  }
  NodeProperties::ChangeOp(
      node, javascript()->Call(
                JSCallNode::ArityForArgc(arity), p.frequency(), p.feedback(),
                ConvertReceiverMode::kNotNullOrUndefined, p.speculation_mode(),
                CallFeedbackRelation::kUnrelated));
  return Changed(node).FollowedBy(ReducePromisePrototypeThen(node));
}

Node* JSCallReducer::CreateClosureFromBuiltinSharedFunctionInfo(
    SharedFunctionInfoRef shared, Node* context, Node* effect, Node* control) {
  DCHECK(shared.HasBuiltinId());
  Handle<FeedbackCell> feedback_cell =
      isolate()->factory()->many_closures_cell();
  Callable const callable =
      Builtins::CallableFor(isolate(), shared.builtin_id());
  CodeRef code = MakeRef(broker(), *callable.code());
  return graph()->NewNode(javascript()->CreateClosure(shared, code),
                          jsgraph()->HeapConstantNoHole(feedback_cell), context,
                          effect, control);
}

// ES section #sec-promise.prototype.finally
Reduction JSCallReducer::ReducePromisePrototypeFinally(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  int arity = p.arity_without_implicit_args();
  Node* receiver = n.receiver();
  Node* on_finally = n.ArgumentOrUndefined(0, jsgraph());
  Effect effect = n.effect();
  Control control = n.control();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();
  ZoneRefSet<Map> const& receiver_maps = inference.GetMaps();

  if (!dependencies()->DependOnPromiseHookProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseThenProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseSpeciesProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Check if {on_finally} is callable, and if so wrap it into appropriate
  // closures that perform the finalization.
  Node* check = graph()->NewNode(simplified()->ObjectIsCallable(), on_finally);
  Node* branch =
      graph()->NewNode(common()->Branch(BranchHint::kTrue), check, control);

  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* catch_true;
  Node* then_true;
  {
    Node* context = jsgraph()->ConstantNoHole(native_context(), broker());
    Node* constructor = jsgraph()->ConstantNoHole(
        native_context().promise_function(broker()), broker());

    // Allocate shared context for the closures below.
    context = etrue = graph()->NewNode(
        javascript()->CreateFunctionContext(
            native_context().scope_info(broker()),
            int{PromiseBuiltins::kPromiseFinallyContextLength} -
                Context::MIN_CONTEXT_SLOTS,
            FUNCTION_SCOPE),
        context, etrue, if_true);
    etrue = graph()->NewNode(
        simplified()->StoreField(
            AccessBuilder::ForContextSlot(PromiseBuiltins::kOnFinallySlot)),
        context, on_finally, etrue, if_true);
    etrue = graph()->NewNode(
        simplified()->StoreField(
            AccessBuilder::ForContextSlot(PromiseBuiltins::kConstructorSlot)),
        context, constructor, etrue, if_true);

    // Allocate the closure for the reject case.
    SharedFunctionInfoRef promise_catch_finally =
        MakeRef(broker(), factory()->promise_catch_finally_shared_fun());
    catch_true = etrue = CreateClosureFromBuiltinSharedFunctionInfo(
        promise_catch_finally, context, etrue, if_true);

    // Allocate the closure for the fulfill case.
    SharedFunctionInfoRef promise_then_finally =
        MakeRef(broker(), factory()->promise_then_finally_shared_fun());
    then_true = etrue = CreateClosureFromBuiltinSharedFunctionInfo(
        promise_then_finally, context, etrue, if_true);
  }

  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  Node* catch_false = on_finally;
  Node* then_false = on_finally;

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);
  Node* catch_finally =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       catch_true, catch_false, control);
  Node* then_finally =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, 2),
                       then_true, then_false, control);

  // At this point we definitely know that {receiver} has one of the
  // {receiver_maps}, so insert a MapGuard as a hint for the lowering
  // of the call to "then" below.
  {
    effect = graph()->NewNode(simplified()->MapGuard(receiver_maps), receiver,
                              effect, control);
  }

  // Massage the {node} to call "then" instead by first removing all inputs
  // following the onFinally parameter, and then replacing the only parameter
  // input with the {on_finally} value.
  Node* target = jsgraph()->ConstantNoHole(
      native_context().promise_then(broker()), broker());
  NodeProperties::ReplaceValueInput(node, target, n.TargetIndex());
  NodeProperties::ReplaceEffectInput(node, effect);
  NodeProperties::ReplaceControlInput(node, control);
  for (; arity > 2; --arity) node->RemoveInput(2);
  for (; arity < 2; ++arity) {
    node->InsertInput(graph()->zone(), 2, then_finally);
  }
  node->ReplaceInput(2, then_finally);
  node->ReplaceInput(3, catch_finally);
  NodeProperties::ChangeOp(
      node, javascript()->Call(
                JSCallNode::ArityForArgc(arity), p.frequency(), p.feedback(),
                ConvertReceiverMode::kNotNullOrUndefined, p.speculation_mode(),
                CallFeedbackRelation::kUnrelated));
  return Changed(node).FollowedBy(ReducePromisePrototypeThen(node));
}

Reduction JSCallReducer::ReducePromisePrototypeThen(Node* node) {
  JSCallNode n(node);
  CallParameters const& p = n.Parameters();
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return NoChange();
  }

  Node* receiver = n.receiver();
  Node* on_fulfilled = n.ArgumentOrUndefined(0, jsgraph());
  Node* on_rejected = n.ArgumentOrUndefined(1, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();
  FrameState frame_state = n.frame_state();

  MapInference inference(broker(), receiver, effect);
  if (!DoPromiseChecks(&inference)) return inference.NoChange();

  if (!dependencies()->DependOnPromiseHookProtector()) {
    return inference.NoChange();
  }
  if (!dependencies()->DependOnPromiseSpeciesProtector()) {
    return inference.NoChange();
  }
  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  // Check that {on_fulfilled} is callable.
  on_fulfilled = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kTrue),
      graph()->NewNode(simplified()->ObjectIsCallable(), on_fulfilled),
      on_fulfilled, jsgraph()->UndefinedConstant());

  // Check that {on_rejected} is callable.
  on_rejected = graph()->NewNode(
      common()->Select(MachineRepresentation::kTagged, BranchHint::kTrue),
      graph()->NewNode(simplified()->ObjectIsCallable(), on_rejected),
      on_rejected, jsgraph()->UndefinedConstant());

  // Create the resulting JSPromise.
  Node* promise = effect =
      graph()->NewNode(javascript()->CreatePromise(), context, effect);

  // Chain {result} onto {receiver}.
  promise = effect = graph()->NewNode(
      javascript()->PerformPromiseThen(), receiver, on_fulfilled, on_rejected,
      promise, context, frame_state, effect, control);

  // At this point we know that {promise} is going to have the
  // initial Promise map, since even if {PerformPromiseThen}
  // above called into the host rejection tracker, the {promise}
  // doesn't escape to user JavaScript. So bake this information
  // into the graph such that subsequent passes can use the
  // information for further optimizations.
  MapRef promise_map =
      native_context().promise_function(broker()).initial_map(broker());
  effect =
      graph()->NewNode(simplified()->MapGuard(ZoneRefSet<Map>(promise_map)),
                       promise, effect, control);

  ReplaceWithValue(node, promise, effect, control);
  return Replace(promise);
}

// ES section #sec-promise.resolve
Reduction JSCallReducer::ReducePromiseResolveTrampoline(Node* node) {
  JSCallNode n(node);
  Node* receiver = n.receiver();
  Node* value = n.ArgumentOrUndefined(0, jsgraph());
  Node* context = n.context();
  Effect effect = n.effect();
  Control control = n.control();
  FrameState frame_state = n.frame_state();

  // Only reduce when the receiver is guaranteed to be a JSReceiver.
  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAreJSReceiver()) {
    return NoChange();
  }

  // Morph the {node} into a JSPromiseResolve operation.
  node->ReplaceInput(0, receiver);
  node->ReplaceInput(1, value);
  node->ReplaceInput(2, context);
  node->ReplaceInput(3, frame_state);
  node->ReplaceInput(4, effect);
  node->ReplaceInput(5, control);
  node->TrimInputCount(6);
  NodeProperties::ChangeOp(node, javascript()->PromiseResolve());
  return Changed(node);
}

// ES #sec-typedarray-constructors
Reduction JSCallReducer::ReduceTypedArrayConstructor(
    Node* node, SharedFunctionInfoRef shared) {
  JSConstructNode n(node);
  Node* target = n.target();
  Node* arg0 = n.ArgumentOrUndefined(0, jsgraph());
  Node* arg1 = n.ArgumentOrUndefined(1, jsgraph());
  Node* arg2 = n.ArgumentOrUndefined(2, jsgraph());
  Node* new_target = n.new_target();
  Node* context = n.context();
  FrameState frame_state = n.frame_state();
  Effect effect = n.effect();
  Control control = n.control();

  // Insert a construct stub frame into the chain of frame states. This will
  // reconstruct the proper frame when deoptimizing within the constructor.
  frame_state = CreateConstructInvokeStubFrameState(node, frame_state, shared,
                                                    context, common(), graph());

  // This continuation just returns the newly created JSTypedArray. We
  // pass the_hole as the receiver, just like the builtin construct stub
  // does in this case.
  Node* const receiver = jsgraph()->TheHoleConstant();
  Node* continuation_frame_state = CreateGenericLazyDeoptContinuationFrameState(
      jsgraph(), shared, target, context, receiver, frame_state);

  Node* result = graph()->NewNode(javascript()->CreateTypedArray(), target,
                                  new_target, arg0, arg1, arg2, context,
                                  continuation_frame_state, effect, control);
  return Replace(result);
}

// ES #sec-get-%typedarray%.prototype-@@tostringtag
Reduction JSCallReducer::ReduceTypedArrayPrototypeToStringTag(Node* node) {
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Node* effect = NodeProperties::GetEffectInput(node);
  Node* control = NodeProperties::GetControlInput(node);

  NodeVector values(graph()->zone());
  NodeVector effects(graph()->zone());
  NodeVector controls(graph()->zone());

  Node* smi_check = graph()->NewNode(simplified()->ObjectIsSmi(), receiver);
  control = graph()->NewNode(common()->Branch(BranchHint::kFalse), smi_check,
                             control);

  values.push_back(jsgraph()->UndefinedConstant());
  effects.push_back(effect);
  controls.push_back(graph()->NewNode(common()->IfTrue(), control));

  control = graph()->NewNode(common()->IfFalse(), control);
  Node* receiver_map = effect =
      graph()->NewNode(simplified()->LoadField(AccessBuilder::ForMap()),
                       receiver, effect, control);
  Node* receiver_bit_field2 = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForMapBitField2()), receiver_map,
      effect, control);
  Node* receiver_elements_kind = graph()->NewNode(
      simplified()->NumberShiftRightLogical(),
      graph()->NewNode(
          simplified()->NumberBitwiseAnd(), receiver_bit_field2,
          jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kMask)),
      jsgraph()->ConstantNoHole(Map::Bits2::ElementsKindBits::kShift));

  // Offset the elements kind by FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND,
  // so that the branch cascade below is turned into a simple table
  // switch by the ControlFlowOptimizer later.
  receiver_elements_kind = graph()->NewNode(
      simplified()->NumberSubtract(), receiver_elements_kind,
      jsgraph()->ConstantNoHole(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND));

  // To be converted into a switch by the ControlFlowOptimizer, the below
  // code requires that TYPED_ARRAYS and RAB_GSAB_TYPED_ARRAYS are consecutive.
  static_assert(LAST_FIXED_TYPED_ARRAY_ELEMENTS_KIND + 1 ==
                FIRST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND);
#define TYPED_ARRAY_CASE(Type, type, TYPE, ctype)                          \
  do {                                                                     \
    Node* check = graph()->NewNode(                                        \
        simplified()->NumberEqual(), receiver_elements_kind,               \
        jsgraph()->ConstantNoHole(TYPE##_ELEMENTS -                        \
                                  FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)); \
    control = graph()->NewNode(common()->Branch(), check, control);        \
    values.push_back(jsgraph()->ConstantNoHole(                            \
        broker()->GetTypedArrayStringTag(TYPE##_ELEMENTS), broker()));     \
    effects.push_back(effect);                                             \
    controls.push_back(graph()->NewNode(common()->IfTrue(), control));     \
    control = graph()->NewNode(common()->IfFalse(), control);              \
  } while (false);
  TYPED_ARRAYS(TYPED_ARRAY_CASE)
  RAB_GSAB_TYPED_ARRAYS(TYPED_ARRAY_CASE)
#undef TYPED_ARRAY_CASE

  values.push_back(jsgraph()->UndefinedConstant());
  effects.push_back(effect);
  controls.push_back(control);

  int const count = static_cast<int>(controls.size());
  control = graph()->NewNode(common()->Merge(count), count, &controls.front());
  effects.push_back(control);
  effect =
      graph()->NewNode(common()->EffectPhi(count), count + 1, &effects.front());
  values.push_back(control);
  Node* value =
      graph()->NewNode(common()->Phi(MachineRepresentation::kTagged, count),
                       count + 1, &values.front());
  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceArrayBufferViewByteLengthAccessor(
    Node* node, InstanceType instance_type, Builtin builtin) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  DCHECK(instance_type == JS_TYPED_ARRAY_TYPE ||
         instance_type == JS_DATA_VIEW_TYPE);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  if (instance_type == JS_TYPED_ARRAY_TYPE) {
    for (MapRef map : inference.GetMaps()) {
      ElementsKind kind = map.elements_kind();
      elements_kinds.insert(kind);
      if (IsRabGsabTypedArrayElementsKind(kind)) maybe_rab_gsab = true;
    }
  }

  if (!maybe_rab_gsab) {
    // We do not perform any change depending on this inference.
    Reduction unused_reduction = inference.NoChange();
    USE(unused_reduction);
    // Call default implementation for non-rab/gsab TAs.
    return ReduceArrayBufferViewAccessor(
        node, instance_type, AccessBuilder::ForJSArrayBufferViewByteLength(),
        builtin);
  }

  const CallParameters& p = CallParametersOf(node->op());
  if (p.speculation_mode() == SpeculationMode::kDisallowSpeculation) {
    return inference.NoChange();
  }
  DCHECK(p.feedback().IsValid());

  inference.RelyOnMapsPreferStability(dependencies(), jsgraph(), &effect,
                                      control, p.feedback());

  const bool depended_on_detaching_protector =
      dependencies()->DependOnArrayBufferDetachingProtector();
  if (!depended_on_detaching_protector && instance_type == JS_DATA_VIEW_TYPE) {
    // DataView prototype accessors throw on detached ArrayBuffers instead of
    // return 0, so skip the optimization.
    //
    // TODO(turbofan): Ideally we would bail out if the buffer is actually
    // detached.
    return inference.NoChange();
  }

  JSCallReducerAssembler a(this, node);
  TNode<JSTypedArray> typed_array =
      TNode<JSTypedArray>::UncheckedCast(receiver);
  TNode<Number> length = a.ArrayBufferViewByteLength(
      typed_array, instance_type, std::move(elements_kinds), a.ContextInput());

  return ReplaceWithSubgraph(&a, length);
}

Reduction JSCallReducer::ReduceArrayBufferViewByteOffsetAccessor(
    Node* node, InstanceType instance_type, Builtin builtin) {
  // TODO(v8:11111): Optimize for JS_RAB_GSAB_DATA_VIEW_TYPE too.
  DCHECK(instance_type == JS_TYPED_ARRAY_TYPE ||
         instance_type == JS_DATA_VIEW_TYPE);
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  if (instance_type == JS_TYPED_ARRAY_TYPE) {
    for (MapRef map : inference.GetMaps()) {
      ElementsKind kind = map.elements_kind();
      elements_kinds.insert(kind);
      if (IsRabGsabTypedArrayElementsKind(kind)) maybe_rab_gsab = true;
    }
  }

  if (!maybe_rab_gsab) {
    // We do not perform any change depending on this inference.
    Reduction unused_reduction = inference.NoChange();
    USE(unused_reduction);
    // Call default implementation for non-rab/gsab TAs.
    return ReduceArrayBufferViewAccessor(
        node, instance_type, AccessBuilder::ForJSArrayBufferViewByteOffset(),
        builtin);
  }

  // TODO(v8:11111): Optimize for RAG/GSAB TypedArray/DataView.
  return inference.NoChange();
}

Reduction JSCallReducer::ReduceTypedArrayPrototypeLength(Node* node) {
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(JS_TYPED_ARRAY_TYPE)) {
    return inference.NoChange();
  }

  std::set<ElementsKind> elements_kinds;
  bool maybe_rab_gsab = false;
  for (MapRef map : inference.GetMaps()) {
    ElementsKind kind = map.elements_kind();
    elements_kinds.insert(kind);
    if (IsRabGsabTypedArrayElementsKind(kind)) maybe_rab_gsab = true;
  }

  if (!maybe_rab_gsab) {
    // We do not perform any change depending on this inference.
    Reduction unused_reduction = inference.NoChange();
    USE(unused_reduction);
    // Call default implementation for non-rab/gsab TAs.
    return ReduceArrayBufferViewAccessor(node, JS_TYPED_ARRAY_TYPE,
                                         AccessBuilder::ForJSTypedArrayLength(),
                                         Builtin::kTypedArrayPrototypeLength);
  }

  if (!inference.RelyOnMapsViaStability(dependencies())) {
    return inference.NoChange();
  }

  JSCallReducerAssembler a(this, node);
  TNode<JSTypedArray> typed_array =
      TNode<JSTypedArray>::UncheckedCast(receiver);
  TNode<Number> length = a.TypedArrayLength(
      typed_array, std::move(elements_kinds), a.ContextInput());

  return ReplaceWithSubgraph(&a, length);
}

// ES #sec-number.isfinite
Reduction JSCallReducer::ReduceNumberIsFinite(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Node* value = graph()->NewNode(simplified()->ObjectIsFiniteNumber(), input);
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES #sec-number.isfinite
Reduction JSCallReducer::ReduceNumberIsInteger(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Node* value = graph()->NewNode(simplified()->ObjectIsInteger(), input);
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES #sec-number.issafeinteger
Reduction JSCallReducer::ReduceNumberIsSafeInteger(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Node* value = graph()->NewNode(simplified()->ObjectIsSafeInteger(), input);
  ReplaceWithValue(node, value);
  return Replace(value);
}

// ES #sec-number.isnan
Reduction JSCallReducer::ReduceNumberIsNaN(Node* node) {
  JSCallNode n(node);
  if (n.ArgumentCount() < 1) {
    Node* value = jsgraph()->FalseConstant();
    ReplaceWithValue(node, value);
    return Replace(value);
  }
  Node* input = n.Argument(0);
  Node* value = graph()->NewNode(simplified()->ObjectIsNaN(), input);
  ReplaceWithValue(node, value);
  return Replace(value);
}

Reduction JSCallReducer::ReduceMapPrototypeGet(Node* node) {
  // We only optimize if we have target, receiver and key parameters.
  JSCallNode n(node);
  if (n.ArgumentCount() != 1) return NoChange();
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};
  Node* key = NodeProperties::GetValueInput(node, 2);

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() || !inference.AllOfInstanceTypesAre(JS_MAP_TYPE)) {
    return NoChange();
  }

  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionTable()), receiver,
      effect, control);

  Node* entry = effect = graph()->NewNode(
      simplified()->FindOrderedCollectionEntry(CollectionKind::kMap), table,
      key, effect, control);

  Node* check = graph()->NewNode(simplified()->NumberEqual(), entry,
                                 jsgraph()->MinusOneConstant());

  Node* branch = graph()->NewNode(common()->Branch(), check, control);

  // Key not found.
  Node* if_true = graph()->NewNode(common()->IfTrue(), branch);
  Node* etrue = effect;
  Node* vtrue = jsgraph()->UndefinedConstant();

  // Key found.
  Node* if_false = graph()->NewNode(common()->IfFalse(), branch);
  Node* efalse = effect;
  Node* vfalse = efalse = graph()->NewNode(
      simplified()->LoadElement(AccessBuilder::ForOrderedHashMapEntryValue()),
      table, entry, efalse, if_false);

  control = graph()->NewNode(common()->Merge(2), if_true, if_false);
  Node* value = graph()->NewNode(
      common()->Phi(MachineRepresentation::kTagged, 2), vtrue, vfalse, control);
  effect = graph()->NewNode(common()->EffectPhi(2), etrue, efalse, control);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

namespace {

InstanceType InstanceTypeForCollectionKind(CollectionKind kind) {
  switch (kind) {
    case CollectionKind::kMap:
      return JS_MAP_TYPE;
    case CollectionKind::kSet:
      return JS_SET_TYPE;
  }
  UNREACHABLE();
}

}  // namespace

Reduction JSCallReducer::ReduceCollectionPrototypeHas(
    Node* node, CollectionKind collection_kind) {
  // We only optimize if we have target, receiver and key parameters.
  JSCallNode n(node);
  if (n.ArgumentCount() != 1) return NoChange();
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};
  Node* key = NodeProperties::GetValueInput(node, 2);
  InstanceType instance_type = InstanceTypeForCollectionKind(collection_kind);

  MapInference inference(broker(), receiver, effect);
  if (!inference.HaveMaps() ||
      !inference.AllOfInstanceTypesAre(instance_type)) {
    return NoChange();
  }

  Node* table = effect = graph()->NewNode(
      simplified()->LoadField(AccessBuilder::ForJSCollectionTable()), receiver,
      effect, control);

  Node* index = effect = graph()->NewNode(
      simplified()->FindOrderedCollectionEntry(collection_kind), table, key,
      effect, control);

  Node* value = graph()->NewNode(simplified()->NumberEqual(), index,
                                 jsgraph()->MinusOneConstant());
  value = graph()->NewNode(simplified()->BooleanNot(), value);

  ReplaceWithValue(node, value, effect, control);
  return Replace(value);
}

Reduction JSCallReducer::ReduceMapPrototypeHas(Node* node) {
  return ReduceCollectionPrototypeHas(node, CollectionKind::kMap);
}

Reduction JSCallReducer::ReduceSetPrototypeHas(Node* node) {
  return ReduceCollectionPrototypeHas(node, CollectionKind::kSet);
}

Reduction JSCallReducer::ReduceCollectionIteration(
    Node* node, CollectionKind collection_kind, IterationKind iteration_kind) {
  DCHECK_EQ(IrOpcode::kJSCall, node->opcode());
  Node* receiver = NodeProperties::GetValueInput(node, 1);
  Node* context = NodeProperties::GetContextInput(node);
  Effect effect{NodeProperties::GetEffectInput(node)};
  Control control{NodeProperties::GetControlInput(node)};

  InstanceType type = InstanceType
```