Response: The user wants to understand the functionality of the C++ code in `v8/src/ic/accessor-assembler.cc`. This is part 4 of 4, suggesting it's a continuation of related code. The code seems to be generating inline caches (ICs) for property access in V8, the JavaScript engine.

Here's a breakdown of how to approach this:

1. **Identify Key Functions:** Look for function definitions, especially those starting with `Generate`. These likely represent the core functionalities.

2. **Analyze Function Names:**  The function names often reveal their purpose. For example, `GenerateDefineKeyedOwnIC`, `GenerateStoreInArrayLiteralIC`, and `GenerateCloneObjectIC` clearly relate to specific JavaScript operations.

3. **Examine Function Body:**  Within each function, focus on:
    * **Parameter Types:**  The `Descriptor` struct and parameter names indicate the inputs (receiver, name, value, etc.).
    * **Builtin Calls:**  `TailCallBuiltin` suggests calls to pre-compiled, optimized code within V8. The `Builtin::k...` enum values are crucial.
    * **Runtime Calls:** `CallRuntime` indicates calls to more general, less optimized runtime functions.
    * **Control Flow:**  `GotoIf`, `Branch`, `Label` suggest different execution paths based on conditions. This is often related to optimizing for different object shapes or access patterns.
    * **Feedback Vector:** The frequent use of `FeedbackVector` points to the IC's mechanism for remembering previous access patterns to optimize future accesses.
    * **Load/Store Operations:** Functions like `LoadMap`, `LoadElements`, `AllocateJSObjectFromMap` indicate memory manipulation.

4. **Relate to JavaScript:** For each C++ function, try to connect it to a corresponding JavaScript operation. Think about how these operations are performed and how V8 might optimize them. Use simple JavaScript examples to illustrate.

5. **Consider "Baseline" and Non-Baseline:**  The presence of functions like `GenerateDefineKeyedOwnICBaseline` and `GenerateDefineKeyedOwnIC` suggests different optimization levels. Baseline likely refers to a simpler, less optimized version, while the non-baseline version uses feedback to perform more sophisticated optimizations.

6. **Focus on IC Concepts:** The code heavily involves concepts like monomorphic, polymorphic, and megamorphic ICs. Identify where these are handled (e.g., in `GenerateCloneObjectIC`).

7. **Summarize Functionality:**  Based on the analysis, group the functions by their general purpose (e.g., defining properties, storing values, cloning objects, checking for property existence).

8. **Provide JavaScript Examples:**  For each summarized function group, create concise JavaScript code snippets that would trigger the corresponding IC.

9. **Address "Part 4 of 4":**  Acknowledge that this is part of a larger system and that it likely deals with specific aspects of IC generation.

**Self-Correction/Refinement during the thought process:**

* Initially, I might focus too much on the low-level details of the assembly-like code. It's important to step back and focus on the higher-level purpose of each function.
* I should ensure the JavaScript examples are clear and directly related to the C++ function's name and parameters.
* The "Baseline" vs. non-baseline distinction is important for understanding V8's optimization strategy. Make sure to explain this if it's evident in the code.
* The role of the `FeedbackVector` is central to ICs, so its presence and how it's used should be highlighted.
这是 `v8/src/ic/accessor-assembler.cc` 文件的第四部分，它主要负责生成**内联缓存 (Inline Cache, IC)** 的代码，用于优化 JavaScript 中属性的访问和操作。

**总而言之，这部分代码定义了用于生成特定类型内联缓存的汇编代码，这些内联缓存用于加速以下 JavaScript 操作：**

* **定义对象的自有属性 (keyed properties):**  无论是第一次定义还是更新已有的属性。
* **存储数组字面量中的元素:**  优化数组字面量创建时的元素赋值。
* **克隆对象:**  高效地复制对象，包括浅拷贝和处理原型链。
* **检查对象是否拥有某个键 (keyed has):**  优化 `in` 操作符和 `hasOwnProperty` 方法。

**与 JavaScript 功能的关系以及示例说明：**

这部分 C++ 代码直接对应于 V8 引擎在执行 JavaScript 代码时对对象属性进行操作的优化。 内联缓存是一种运行时优化技术，它会记住之前属性访问的类型和位置，以便在后续访问相同属性时能够更快地执行。

以下是针对每个功能的 JavaScript 示例，以及它们如何与 C++ 代码中的函数对应：

**1. 定义对象的自有属性 (`GenerateDefineKeyedOwnIC`, `GenerateDefineKeyedOwnICBaseline`)**

* **JavaScript 示例:**

```javascript
const obj = {};
obj['key'] = 'value'; // 这会触发 DefineKeyedOwnIC

const arr = [];
arr[0] = 10; // 这也会触发 DefineKeyedOwnIC
```

* **C++ 代码关联:** `GenerateDefineKeyedOwnIC` 和 `GenerateDefineKeyedOwnICBaseline` 负责生成处理 `obj['key'] = 'value'` 这类操作的优化代码。 `Baseline` 版本是更基础的版本，而另一个版本会利用反馈向量进行更精细的优化。

**2. 存储数组字面量中的元素 (`GenerateStoreInArrayLiteralIC`, `GenerateStoreInArrayLiteralICBaseline`)**

* **JavaScript 示例:**

```javascript
const arr = [1, 2, 3]; // 在创建数组字面量时，元素会被存储
```

* **C++ 代码关联:** `GenerateStoreInArrayLiteralIC` 和 `GenerateStoreInArrayLiteralICBaseline` 负责优化数组字面量创建时的元素存储操作。

**3. 克隆对象 (`GenerateCloneObjectIC_Slow`, `GenerateCloneObjectICBaseline`, `GenerateCloneObjectIC`)**

* **JavaScript 示例:**

```javascript
const obj1 = { a: 1, b: 2 };
const obj2 = { ...obj1 }; // 使用展开运算符进行浅拷贝，会触发 CloneObjectIC
const obj3 = Object.assign({}, obj1); // 使用 Object.assign 进行浅拷贝，也会触发 CloneObjectIC
```

* **C++ 代码关联:** `GenerateCloneObjectIC` 系列函数负责生成克隆对象的优化代码。 `GenerateCloneObjectIC_Slow` 是一个慢速路径，当无法进行快速优化时会调用。 `GenerateCloneObjectICBaseline` 是基础版本，而 `GenerateCloneObjectIC` 则尝试利用反馈信息进行更智能的克隆。 代码中还包含了尝试快速克隆的逻辑，如果对象结构简单可以直接复制，否则会回退到运行时函数。

**4. 检查对象是否拥有某个键 (`GenerateKeyedHasIC`, `GenerateKeyedHasICBaseline`, `GenerateKeyedHasIC_Megamorphic`, `GenerateKeyedHasIC_PolymorphicName`)**

* **JavaScript 示例:**

```javascript
const obj = { a: 1 };
'a' in obj; // 这会触发 KeyedHasIC
obj.hasOwnProperty('a'); // 这也会触发 KeyedHasIC
```

* **C++ 代码关联:** `GenerateKeyedHasIC` 系列函数负责生成优化代码，用于检查对象是否拥有指定的键。 不同的函数对应不同的优化策略，例如处理单态 (monomorphic)、多态 (polymorphic) 和巨态 (megamorphic) 的对象。 `GenerateKeyedHasIC_Megamorphic` 是处理多种不同对象类型的慢速路径。

**更深入的理解：**

* **反馈向量 (Feedback Vector):**  代码中多次出现的 `FeedbackVector` 是内联缓存的核心机制。 它用于存储先前属性访问的信息（例如，属性所在的对象的类型、属性在对象中的位置），以便在下次访问相同属性时可以根据这些信息直接跳转到相应的代码，而无需重新查找。
* **基线 (Baseline) 和优化版本:**  代码中存在 `Baseline` 和非 `Baseline` 版本的函数。 `Baseline` 版本是更基础、更通用的实现。 非 `Baseline` 版本则利用反馈向量进行更具体的优化，例如，如果一个属性总是出现在同一类型的对象上，那么可以直接访问该对象的固定位置。
* **多态 (Polymorphic) 和巨态 (Megamorphic):**  V8 的内联缓存可以处理不同类型的对象。 多态 IC 可以处理有限几种对象类型，而巨态 IC 则用于处理更多种不同的对象类型，但通常性能较低。

**总结:**

这部分 `AccessorAssembler.cc` 代码是 V8 引擎进行性能优化的关键组成部分。 它通过生成针对特定 JavaScript 属性访问和操作的内联缓存代码，显著提高了 JavaScript 代码的执行效率。 不同的函数针对不同的操作和优化程度，体现了 V8 引擎在运行时进行动态优化的能力。

### 提示词
```
这是目录为v8/src/ic/accessor-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第4部分，共4部分，请归纳一下它的功能
```

### 源代码
```
or::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto flags = Parameter<Smi>(Descriptor::kFlags);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kDefineKeyedOwnIC, context, receiver, name, value,
                  flags, slot, vector);
}

void AccessorAssembler::GenerateDefineKeyedOwnICBaseline() {
  using Descriptor = DefineKeyedOwnBaselineDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto flags = Parameter<Smi>(Descriptor::kFlags);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kDefineKeyedOwnIC, context, receiver, name, value,
                  flags, slot, vector);
}

void AccessorAssembler::GenerateStoreInArrayLiteralIC() {
  using Descriptor = StoreWithVectorDescriptor;

  auto array = Parameter<Object>(Descriptor::kReceiver);
  auto index = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto flags = std::nullopt;
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  StoreICParameters p(context, array, index, value, flags, slot, vector,
                      StoreICMode::kDefault);
  StoreInArrayLiteralIC(&p);
}

void AccessorAssembler::GenerateStoreInArrayLiteralICBaseline() {
  using Descriptor = StoreBaselineDescriptor;

  auto array = Parameter<Object>(Descriptor::kReceiver);
  auto index = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);

  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kStoreInArrayLiteralIC, context, array, index, value,
                  slot, vector);
}

void AccessorAssembler::GenerateCloneObjectIC_Slow() {
  using Descriptor = CloneObjectWithVectorDescriptor;
  auto source = Parameter<Object>(Descriptor::kSource);
  auto flags = Parameter<Smi>(Descriptor::kFlags);
  auto context = Parameter<Context>(Descriptor::kContext);

  // The CloneObjectIC_Slow implementation uses the same call interface as
  // CloneObjectIC, so that it can be tail called from it. However, the feedback
  // slot and vector are not used.

  // First try a fast case where we copy the properties with a CSA loop.
  Label try_fast_case(this), call_runtime(this, Label::kDeferred);

  // For SMIs and non JSObjects we use 0 in object properties.
  TVARIABLE(IntPtrT, number_of_properties, IntPtrConstant(0));
  GotoIf(TaggedIsSmi(source), &try_fast_case);
  {
    TNode<Map> source_map = LoadMap(CAST(source));
    // We still want to stay in the semi-fast case for oddballs, strings,
    // proxies and such. Therefore we continue here, but using 0 in object
    // properties.
    GotoIfNot(IsJSObjectMap(source_map), &try_fast_case);

    // At this point we don't know yet if ForEachEnumerableOwnProperty can
    // handle the source object. In case it is a dictionary mode object or has
    // non simple properties the latter will bail to `runtime_copy`. For code
    // compactness we don't check it here, assuming that the number of in-object
    // properties is set to 0 (or a reasonable value).
    number_of_properties = MapUsedInObjectProperties(source_map);
    GotoIf(IntPtrGreaterThanOrEqual(number_of_properties.value(),
                                    IntPtrConstant(JSObject::kMapCacheSize)),
           &call_runtime);
  }
  Goto(&try_fast_case);

  BIND(&try_fast_case);
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<Map> initial_map = LoadCachedMap(
      native_context, number_of_properties.value(), &call_runtime);
  TNode<JSObject> result = AllocateJSObjectFromMap(initial_map);

  // Handle the case where the object literal overrides the prototype.
  {
    Label did_set_proto_if_needed(this);
    TNode<BoolT> is_null_proto = SmiNotEqual(
        SmiAnd(flags, SmiConstant(ObjectLiteral::kHasNullPrototype)),
        SmiConstant(Smi::zero()));
    GotoIfNot(is_null_proto, &did_set_proto_if_needed);

    CallRuntime(Runtime::kInternalSetPrototype, context, result,
                NullConstant());

    Goto(&did_set_proto_if_needed);
    BIND(&did_set_proto_if_needed);
  }

  // Early return for when we know there are no properties.
  ReturnIf(TaggedIsSmi(source), result);
  ReturnIf(IsNullOrUndefined(source), result);

  Label runtime_copy(this, Label::kDeferred);

  TNode<Map> source_map = LoadMap(CAST(source));
  GotoIfNot(IsJSObjectMap(source_map), &runtime_copy);
  // Takes care of objects with elements.
  GotoIfNot(IsEmptyFixedArray(LoadElements(CAST(source))), &runtime_copy);

  // TODO(olivf, chrome:1204540) This can still be several times slower than the
  // Babel translation. TF uses FastGetOwnValuesOrEntries -- should we do sth
  // similar here?
  ForEachEnumerableOwnProperty(
      context, source_map, CAST(source), kPropertyAdditionOrder,
      [=, this](TNode<Name> key, LazyNode<Object> value) {
        CreateDataProperty(context, result, key, value());
      },
      &runtime_copy);
  Return(result);

  // This is the fall-back case for the above fastcase, where we allocated an
  // object, but failed to copy the properties in CSA.
  BIND(&runtime_copy);
  CallRuntime(Runtime::kCopyDataProperties, context, result, source);
  Return(result);

  // Final fallback is to call into the runtime version.
  BIND(&call_runtime);
  Return(CallRuntime(Runtime::kCloneObjectIC_Slow, context, source, flags));
}

void AccessorAssembler::GenerateCloneObjectICBaseline() {
  using Descriptor = CloneObjectBaselineDescriptor;

  auto source = Parameter<Object>(Descriptor::kSource);
  auto flags = Parameter<Smi>(Descriptor::kFlags);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);

  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kCloneObjectIC, context, source, flags, slot,
                  vector);
}

void AccessorAssembler::GenerateCloneObjectIC() {
  using Descriptor = CloneObjectWithVectorDescriptor;
  auto source = Parameter<Object>(Descriptor::kSource);
  auto flags = Parameter<Smi>(Descriptor::kFlags);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto maybe_vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);
  TVARIABLE(Map, result_map);
  Label if_result_map(this, &result_map), if_empty_object(this),
      miss(this, Label::kDeferred), try_polymorphic(this, Label::kDeferred),
      try_megamorphic(this, Label::kDeferred), slow(this, Label::kDeferred);

  TNode<Map> source_map = LoadReceiverMap(source);
  GotoIf(IsDeprecatedMap(source_map), &miss);

  GotoIf(IsUndefined(maybe_vector), &miss);

  TNode<HeapObjectReference> feedback;
  TNode<HeapObjectReference> weak_source_map = MakeWeak(source_map);

  // Decide if monomorphic or polymorphic, then dispatch based on the handler.
  {
    TVARIABLE(MaybeObject, var_handler);
    Label if_handler(this, &var_handler);
    feedback = TryMonomorphicCase(slot, CAST(maybe_vector), weak_source_map,
                                  &if_handler, &var_handler, &try_polymorphic);

    BIND(&try_polymorphic);
    TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
    {
      Comment("CloneObjectIC_try_polymorphic");
      GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)),
                &try_megamorphic);
      HandlePolymorphicCase(weak_source_map, CAST(strong_feedback), &if_handler,
                            &var_handler, &miss);
    }

    BIND(&try_megamorphic);
    {
      Comment("CloneObjectIC_try_megamorphic");
      CSA_DCHECK(
          this,
          Word32Or(TaggedEqual(strong_feedback, UninitializedSymbolConstant()),
                   TaggedEqual(strong_feedback, MegamorphicSymbolConstant())));
      GotoIfNot(TaggedEqual(strong_feedback, MegamorphicSymbolConstant()),
                &miss);
      Goto(&slow);
    }

    BIND(&if_handler);
    Comment("CloneObjectIC_if_handler");

    // When the result of cloning the object is an empty object literal we store
    // a Smi into the feedback.
    GotoIf(TaggedIsSmi(var_handler.value()), &if_empty_object);

    // Handlers for the CloneObjectIC stub are weak references to the Map of
    // a result object.
    result_map = CAST(GetHeapObjectAssumeWeak(var_handler.value(), &miss));
    GotoIf(IsDeprecatedMap(result_map.value()), &miss);
    Goto(&if_result_map);
  }

  // Cloning with a concrete result_map.
  {
    BIND(&if_result_map);
    Comment("CloneObjectIC_if_result_map");

    TNode<Object> object = FastCloneJSObject(
        CAST(source), source_map, result_map.value(),
        [&](TNode<Map> map, TNode<HeapObject> properties,
            TNode<FixedArray> elements) {
          return UncheckedCast<JSObject>(AllocateJSObjectFromMap(
              map, properties, elements, AllocationFlag::kNone,
              SlackTrackingMode::kDontInitializeInObjectProperties));
        },
        true /* target_is_new */);

    Return(object);
  }

  // Case for when the result is the empty object literal. Can't be shared with
  // the above since we must initialize the in-object properties.
  {
    BIND(&if_empty_object);
    Comment("CloneObjectIC_if_empty_object");
    TNode<NativeContext> native_context = LoadNativeContext(context);
    TNode<Map> initial_map = LoadObjectFunctionInitialMap(native_context);
    TNode<JSObject> object =
        UncheckedCast<JSObject>(AllocateJSObjectFromMap(initial_map, {}, {}));
    Return(object);
  }

  BIND(&slow);
  {
    TailCallBuiltin(Builtin::kCloneObjectIC_Slow, context, source, flags, slot,
                    maybe_vector);
  }

  BIND(&miss);
  {
    Comment("CloneObjectIC_miss");
    TNode<HeapObject> map_or_result =
        CAST(CallRuntime(Runtime::kCloneObjectIC_Miss, context, source, flags,
                         slot, maybe_vector));
    Label restart(this);
    GotoIf(IsMap(map_or_result), &restart);
    CSA_DCHECK(this, IsJSObject(map_or_result));
    Return(map_or_result);

    BIND(&restart);
    result_map = CAST(map_or_result);
    Goto(&if_result_map);
  }
}

void AccessorAssembler::GenerateKeyedHasIC() {
  using Descriptor = KeyedHasICWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  LoadICParameters p(context, receiver, name, slot, vector);
  KeyedLoadIC(&p, LoadAccessMode::kHas);
}

void AccessorAssembler::GenerateKeyedHasICBaseline() {
  using Descriptor = KeyedHasICBaselineDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kKeyedHasIC, context, receiver, name, slot, vector);
}

void AccessorAssembler::GenerateKeyedHasIC_Megamorphic() {
  using Descriptor = KeyedHasICWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto context = Parameter<Context>(Descriptor::kContext);
  // TODO(magardn): implement HasProperty handling in KeyedLoadICGeneric
  Return(HasProperty(context, receiver, name,
                     HasPropertyLookupMode::kHasProperty));
}

void AccessorAssembler::GenerateKeyedHasIC_PolymorphicName() {
  using Descriptor = LoadWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  LoadICParameters p(context, receiver, name, slot, vector);
  KeyedLoadICPolymorphicName(&p, LoadAccessMode::kHas);
}

void AccessorAssembler::BranchIfPrototypesHaveNoElements(
    TNode<Map> receiver_map, Label* definitely_no_elements,
    Label* possibly_elements) {
  TVARIABLE(Map, var_map, receiver_map);
  Label loop_body(this, &var_map);
  TNode<FixedArray> empty_fixed_array = EmptyFixedArrayConstant();
  TNode<NumberDictionary> empty_slow_element_dictionary =
      EmptySlowElementDictionaryConstant();
  Goto(&loop_body);

  BIND(&loop_body);
  {
    TNode<Map> map = var_map.value();
    TNode<HeapObject> prototype = LoadMapPrototype(map);
    GotoIf(IsNull(prototype), definitely_no_elements);
    TNode<Map> prototype_map = LoadMap(prototype);
    TNode<Uint16T> prototype_instance_type = LoadMapInstanceType(prototype_map);

    // Pessimistically assume elements if a Proxy, Special API Object,
    // or JSPrimitiveWrapper wrapper is found on the prototype chain. After this
    // instance type check, it's not necessary to check for interceptors or
    // access checks.
    Label if_custom(this, Label::kDeferred), if_notcustom(this);
    Branch(IsCustomElementsReceiverInstanceType(prototype_instance_type),
           &if_custom, &if_notcustom);

    BIND(&if_custom);
    {
      // For string JSPrimitiveWrapper wrappers we still support the checks as
      // long as they wrap the empty string.
      GotoIfNot(
          InstanceTypeEqual(prototype_instance_type, JS_PRIMITIVE_WRAPPER_TYPE),
          possibly_elements);
      TNode<Object> prototype_value =
          LoadJSPrimitiveWrapperValue(CAST(prototype));
      Branch(IsEmptyString(prototype_value), &if_notcustom, possibly_elements);
    }

    BIND(&if_notcustom);
    {
      TNode<FixedArrayBase> prototype_elements = LoadElements(CAST(prototype));
      var_map = prototype_map;
      GotoIf(TaggedEqual(prototype_elements, empty_fixed_array), &loop_body);
      Branch(TaggedEqual(prototype_elements, empty_slow_element_dictionary),
             &loop_body, possibly_elements);
    }
  }
}

#undef LOAD_KIND
#undef STORE_KIND

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```