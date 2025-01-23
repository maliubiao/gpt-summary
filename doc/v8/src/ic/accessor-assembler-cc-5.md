Response:
The user wants a summary of the provided C++ code snippet from `v8/src/ic/accessor-assembler.cc`. The summary should cover:

1. **Functionality:** What does this code do?
2. **Torque Source:** Is it related to Torque? (Answer: No, it's C++)
3. **JavaScript Relationship:** Does it connect to JavaScript features? If so, provide examples.
4. **Code Logic Inference:**  Are there any clear input/output scenarios that can be deduced?
5. **Common Programming Errors:** Does it relate to typical mistakes developers make?
6. **Overall Function (Part 6 of 7):**  A high-level summary of this specific part.

Let's break down the code:

* **Focus on IC (Inline Cache):** The file path `v8/src/ic/` strongly suggests this code is part of V8's Inline Cache mechanism. ICs are used to optimize property access in JavaScript.
* **Assembler:** The `AccessorAssembler` class likely generates machine code (or bytecode that's close to machine code) for accessing object properties.
* **Various `Generate...IC` Functions:** The code defines many functions with names like `GenerateLoadIC`, `GenerateStoreIC`, `GenerateKeyedLoadIC`, etc. These correspond to different types of property access (load, store, keyed access) and different optimization levels (trampoline, baseline, megamorphic).
* **`LoadICParameters` and `StoreICParameters`:**  These structs likely encapsulate the information needed for generating the IC code (receiver object, property name, feedback vector, etc.).
* **Feedback Vectors:** The code frequently interacts with "feedback vectors". These are runtime data structures that store information about the types of objects and properties accessed during execution. This information is used to optimize future accesses.
* **Monomorphic, Polymorphic, Megamorphic:** The code handles different "shapes" of objects. Monomorphic means a property is accessed on objects of the same type repeatedly. Polymorphic means a property is accessed on a few different object types. Megamorphic means a property is accessed on many different object types.
* **Stub Cache:**  The code interacts with the "stub cache," which stores pre-compiled code for common property access patterns.
* **Runtime Calls:**  When the IC cannot be optimized further, the code "falls back" to calling runtime functions (e.g., `Runtime::kLoadIC_Miss`).
* **Context:**  The `context` parameter is essential in JavaScript for managing scope and variable access.
* **Trampoline and Baseline:**  These terms refer to different levels of optimization. Trampolines are often initial, less optimized entry points, while baseline code is a more optimized version.
* **Keyed Access:** Functions like `GenerateKeyedLoadIC` handle accessing properties using bracket notation (e.g., `obj[key]`).
* **Global Access:** Functions like `GenerateLoadGlobalIC` handle accessing global variables.
* **Lookup Context:** Functions like `GenerateLookupContextTrampoline` are involved in resolving variable names in different scopes.

**Plan:**

1. State the core functionality: Optimizing property access using Inline Caches.
2. Confirm it's C++ and not Torque.
3. Show JavaScript examples that would trigger the ICs (property access).
4. Provide a simple hypothetical load scenario with inputs and expected behavior.
5. Discuss common errors (like assuming property existence or type).
6. Summarize the focus of this part: Generating code for various IC scenarios (load, store, keyed, global, etc.) and optimization levels.
`v8/src/ic/accessor-assembler.cc` 是 V8 引擎中负责生成用于访问对象属性的内联缓存 (Inline Cache, IC) 代码的组件。IC 是 V8 用于优化属性访问性能的关键机制。

**功能列举:**

这个 C++ 代码文件的主要功能是：

1. **生成不同类型的 Load IC 代码:**  `GenerateLoadIC`, `GenerateLoadIC_Megamorphic`, `GenerateLoadIC_Noninlined`, `GenerateLoadIC_NoFeedback`, `GenerateLoadSuperIC`, `GenerateLoadGlobalIC` 等函数负责生成用于读取对象属性值的优化代码。这些函数会根据反馈信息 (feedback) 和对象类型生成不同的代码路径，以提高效率。例如，如果某个属性经常在同一类型的对象上被访问，Load IC 可以被优化为直接访问该属性的偏移量，而无需进行完整的属性查找。
2. **生成不同类型的 Store IC 代码:** `GenerateStoreIC`, `GenerateStoreIC_Megamorphic`, `GenerateStoreGlobalIC`, `GenerateKeyedStoreIC` 等函数负责生成用于设置对象属性值的优化代码。类似于 Load IC，Store IC 也会根据反馈信息进行优化。
3. **生成 Define Own Property 的 IC 代码:** `GenerateDefineNamedOwnIC`, `GenerateDefineKeyedOwnIC` 用于生成定义对象自有属性的优化代码。
4. **处理 Megamorphic 状态:**  当一个属性在多种不同类型的对象上被访问时，会进入 Megamorphic 状态。这个文件中的一些函数，例如 `GenerateLoadIC_Megamorphic` 和 `GenerateStoreIC_Megamorphic`，专门处理这种情况，它们通常会使用更通用的查找机制，例如 Stub Cache。
5. **处理 Keyed Access (索引访问):** `GenerateKeyedLoadIC`, `GenerateKeyedStoreIC`, `GenerateDefineKeyedOwnIC` 等函数处理使用方括号 `[]` 进行属性访问的情况。
6. **处理 Global Access (全局访问):** `GenerateLoadGlobalIC`, `GenerateStoreGlobalIC` 处理对全局变量的访问。
7. **处理 Super 关键字访问:** `GenerateLoadSuperIC` 处理使用 `super` 关键字进行的属性访问。
8. **处理 Context Lookup (上下文查找):** `GenerateLookupContextTrampoline`, `GenerateLookupGlobalIC` 等函数负责在作用域链中查找变量。
9. **生成 Trampoline 和 Baseline 代码:**  这些是不同优化级别的 IC 入口点。Trampoline 通常是较为通用的入口，而 Baseline 是在 Turbofan 优化编译之前的优化级别。
10. **利用 Feedback Vector:** 代码中频繁出现对 `FeedbackVector` 的操作。Feedback Vector 用于存储运行时收集的类型信息和操作信息，以便 IC 可以根据这些信息进行优化。
11. **使用 Stub Cache:**  对于 Megamorphic 状态，代码会尝试使用 Stub Cache，这是一个缓存了已编译代码片段的结构，可以加速属性访问。

**关于 .tq 结尾:**

如果 `v8/src/ic/accessor-assembler.cc` 以 `.tq` 结尾，那么它将是使用 V8 的 Torque 语言编写的源代码。 Torque 是一种用于编写 V8 内部代码的领域特定语言，它可以生成 C++ 代码。 **但根据您提供的文件名，它以 `.cc` 结尾，所以它是一个标准的 C++ 源代码文件。**

**与 Javascript 功能的关系及举例:**

`accessor-assembler.cc` 中生成的代码直接对应于 JavaScript 中对象属性的访问操作。以下是一些 JavaScript 例子，它们在 V8 引擎内部会触发 `accessor-assembler.cc` 中生成的 IC 代码：

**1. 属性读取 (Load):**

```javascript
const obj = { a: 10 };
const value = obj.a; // 这会触发 Load IC
```

**2. 属性设置 (Store):**

```javascript
const obj = {};
obj.b = 20; // 这会触发 Store IC
```

**3. 索引访问 (Keyed Access):**

```javascript
const arr = [1, 2, 3];
const element = arr[1]; // 这会触发 KeyedLoadIC
arr[0] = 4; // 这会触发 KeyedStoreIC
```

**4. 全局变量访问 (Global Access):**

```javascript
console.log(globalVar); // 这会触发 LoadGlobalIC
globalVar = 30; // 这会触发 StoreGlobalIC
```

**5. 定义属性 (Define Own Property):**

```javascript
const obj = {};
Object.defineProperty(obj, 'c', { value: 40 }); // 这会触发 DefineNamedOwnIC 或 DefineKeyedOwnIC
```

**代码逻辑推理 (假设输入与输出):**

考虑 `GenerateLoadIC` 函数。

**假设输入:**

* `receiver`: 一个 JavaScript 对象，例如 `{ x: 5 }`
* `name`:  一个表示属性名的字符串，例如 `"x"`
* `slot`: 一个 `TaggedIndex`，表示反馈向量中的槽位
* `vector`: 一个 `FeedbackVector` 对象，存储了关于此属性访问的反馈信息
* `context`: 当前的 JavaScript 执行上下文

**预期输出:**

生成的机器码或 bytecode 会执行以下操作：

1. **检查 `FeedbackVector`:**  根据 `slot` 从 `vector` 中加载反馈信息。
2. **根据反馈信息优化:**
   * **Monomorphic:** 如果反馈表明 `"x"` 总是被访问类型相同的对象，则生成直接从该对象类型的偏移量读取 `"x"` 属性的代码。
   * **Polymorphic:** 如果反馈表明 `"x"` 被访问于几种有限的不同类型的对象，则生成检查对象类型并跳转到对应类型特定读取代码的代码。
   * **Megamorphic:** 如果反馈表明 `"x"` 被访问于多种不同类型的对象，或者没有足够的反馈信息，则可能调用 Stub Cache 或回退到更慢的运行时查找机制。
3. **返回属性值:**  最终，生成的代码会返回对象 `receiver` 的 `"x"` 属性值 `5`。

**涉及用户常见的编程错误:**

IC 机制的优化依赖于运行时收集的类型信息。以下是一些可能影响 IC 性能的常见编程错误：

1. **频繁改变对象形状 (Hidden Class):**  在对象创建后频繁添加或删除属性会导致对象形状改变，使得之前优化的 IC 失效。

   ```javascript
   function Point(x, y) {
     this.x = x;
   }

   const p1 = new Point(1, 2);
   p1.y = 3; // 第一次给 p1 添加 y 属性

   const p2 = new Point(4, 5); // p2 没有 y 属性
   ```

   在这个例子中，`p1` 和 `p2` 的形状不同，对它们的属性访问可能无法充分利用 IC 的优化。

2. **访问不存在的属性:**  访问不存在的属性会导致属性查找失败，并可能触发 deoptimization。

   ```javascript
   const obj = { a: 1 };
   console.log(obj.b); // 访问不存在的属性 'b'
   ```

3. **对类型不一致的对象进行相同的属性访问:**  如果同一段代码访问某个属性时，对象类型经常变化，会导致 IC 无法稳定优化到单态或多态状态。

   ```javascript
   function process(obj) {
     return obj.value;
   }

   process({ value: 1 });
   process({ value: "hello" }); // 类型不一致
   ```

**归纳一下它的功能 (第 6 部分，共 7 部分):**

作为第 6 部分，`accessor-assembler.cc` 的主要功能是 **定义和实现了生成各种类型对象属性访问 IC 代码的具体逻辑**。  它涵盖了读取、设置和定义属性的多种场景，包括命名属性和索引属性，以及对全局变量和 `super` 关键字的访问。 这一部分的代码详细描述了如何根据反馈信息生成不同优化级别的 IC 代码，以及如何处理 Megamorphic 状态和回退到更通用的机制。 可以推断，前几部分可能定义了相关的接口、数据结构和辅助函数，而最后一部分可能会包含一些收尾工作或更高层次的抽象。

### 提示词
```
这是目录为v8/src/ic/accessor-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/accessor-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第6部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
&if_handler, &var_handler, &miss);
    }

    BIND(&try_megamorphic);
    {
      // Check megamorphic case.
      Comment("DefineKeyedOwnIC_try_megamorphic");
      Branch(TaggedEqual(strong_feedback, MegamorphicSymbolConstant()),
             &no_feedback, &try_polymorphic_name);
    }

    BIND(&no_feedback);
    {
      TailCallBuiltin(Builtin::kDefineKeyedOwnIC_Megamorphic, p->context(),
                      p->receiver(), p->name(), p->value());
    }

    BIND(&try_polymorphic_name);
    {
      // We might have a name in feedback, and a fixed array in the next slot.
      Comment("DefineKeyedOwnIC_try_polymorphic_name");
      GotoIfNot(TaggedEqual(strong_feedback, p->name()), &miss);
      // If the name comparison succeeded, we know we have a feedback vector
      // with at least one map/handler pair.
      TNode<MaybeObject> feedback_element =
          LoadFeedbackVectorSlot(CAST(p->vector()), p->slot(), kTaggedSize);
      TNode<WeakFixedArray> array = CAST(feedback_element);
      HandlePolymorphicCase(weak_receiver_map, array, &if_handler, &var_handler,
                            &miss);
    }
  }
  BIND(&miss);
  {
    Comment("DefineKeyedOwnIC_miss");
    TailCallRuntime(Runtime::kDefineKeyedOwnIC_Miss, p->context(), p->value(),
                    p->slot(), p->vector(), p->receiver(), p->name());
  }
}

void AccessorAssembler::StoreInArrayLiteralIC(const StoreICParameters* p) {
  Label miss(this, Label::kDeferred), no_feedback(this, Label::kDeferred);
  {
    TVARIABLE(MaybeObject, var_handler);

    Label if_handler(this, &var_handler),
        try_polymorphic(this, Label::kDeferred),
        try_megamorphic(this, Label::kDeferred);

    TNode<Map> array_map = LoadReceiverMap(p->receiver());
    GotoIf(IsDeprecatedMap(array_map), &miss);

    GotoIf(IsUndefined(p->vector()), &no_feedback);

    TNode<HeapObjectReference> weak_array_map = MakeWeak(array_map);
    TNode<HeapObjectReference> feedback =
        TryMonomorphicCase(p->slot(), CAST(p->vector()), weak_array_map,
                           &if_handler, &var_handler, &try_polymorphic);

    BIND(&if_handler);
    {
      Comment("StoreInArrayLiteralIC_if_handler");
      // This is a stripped-down version of HandleStoreICHandlerCase.
      Label if_transitioning_element_store(this), if_smi_handler(this);

      // Check used to identify the Slow case.
      // Currently only the Slow case uses a Smi handler.
      GotoIf(TaggedIsSmi(var_handler.value()), &if_smi_handler);

      TNode<HeapObject> handler = CAST(var_handler.value());
      GotoIfNot(IsCode(handler), &if_transitioning_element_store);

      {
        // Call the handler.
        TNode<Code> code_handler = CAST(handler);
        TailCallStub(StoreWithVectorDescriptor{}, code_handler, p->context(),
                     p->receiver(), p->name(), p->value(), p->slot(),
                     p->vector());
      }

      BIND(&if_transitioning_element_store);
      {
        TNode<MaybeObject> maybe_transition_map =
            LoadHandlerDataField(CAST(handler), 1);
        TNode<Map> transition_map =
            CAST(GetHeapObjectAssumeWeak(maybe_transition_map, &miss));
        GotoIf(IsDeprecatedMap(transition_map), &miss);
        TNode<Code> code =
            CAST(LoadObjectField(handler, StoreHandler::kSmiHandlerOffset));
        TailCallStub(StoreTransitionDescriptor{}, code, p->context(),
                     p->receiver(), p->name(), transition_map, p->value(),
                     p->slot(), p->vector());
      }

      BIND(&if_smi_handler);
      {
#ifdef DEBUG
        // A check to ensure that no other Smi handler uses this path.
        TNode<Int32T> handler_word = SmiToInt32(CAST(var_handler.value()));
        TNode<Uint32T> handler_kind =
            DecodeWord32<StoreHandler::KindBits>(handler_word);
        CSA_DCHECK(this, Word32Equal(handler_kind, STORE_KIND(kSlow)));
#endif

        Comment("StoreInArrayLiteralIC_Slow");
        TailCallRuntime(Runtime::kStoreInArrayLiteralIC_Slow, p->context(),
                        p->value(), p->receiver(), p->name());
      }
    }

    BIND(&try_polymorphic);
    TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
    {
      Comment("StoreInArrayLiteralIC_try_polymorphic");
      GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)),
                &try_megamorphic);
      HandlePolymorphicCase(weak_array_map, CAST(strong_feedback), &if_handler,
                            &var_handler, &miss);
    }

    BIND(&try_megamorphic);
    {
      Comment("StoreInArrayLiteralIC_try_megamorphic");
      CSA_DCHECK(
          this,
          Word32Or(TaggedEqual(strong_feedback, UninitializedSymbolConstant()),
                   TaggedEqual(strong_feedback, MegamorphicSymbolConstant())));
      GotoIfNot(TaggedEqual(strong_feedback, MegamorphicSymbolConstant()),
                &miss);
      TailCallRuntime(Runtime::kStoreInArrayLiteralIC_Slow, p->context(),
                      p->value(), p->receiver(), p->name());
    }
  }

  BIND(&no_feedback);
  {
    Comment("StoreInArrayLiteralIC_NoFeedback");
    TailCallBuiltin(Builtin::kCreateDataProperty, p->context(), p->receiver(),
                    p->name(), p->value());
  }

  BIND(&miss);
  {
    Comment("StoreInArrayLiteralIC_miss");
    TailCallRuntime(Runtime::kStoreInArrayLiteralIC_Miss, p->context(),
                    p->value(), p->slot(), p->vector(), p->receiver(),
                    p->name());
  }
}

//////////////////// Public methods.

void AccessorAssembler::GenerateLoadIC() {
  using Descriptor = LoadWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  LoadICParameters p(context, receiver, name, slot, vector);
  LoadIC(&p);
}

void AccessorAssembler::GenerateLoadIC_Megamorphic() {
  using Descriptor = LoadWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  ExitPoint direct_exit(this);
  TVARIABLE(MaybeObject, var_handler);
  Label if_handler(this, &var_handler), miss(this, Label::kDeferred);

  CSA_DCHECK(this, TaggedEqual(LoadFeedbackVectorSlot(CAST(vector), slot),
                               MegamorphicSymbolConstant()));

  TryProbeStubCache(isolate()->load_stub_cache(), receiver, CAST(name),
                    &if_handler, &var_handler, &miss);

  BIND(&if_handler);
  LazyLoadICParameters p(
      // lazy_context
      [=] { return context; }, receiver,
      // lazy_name
      [=] { return name; },
      // lazy_slot
      [=] { return slot; }, vector);
  HandleLoadICHandlerCase(&p, var_handler.value(), &miss, &direct_exit);

  BIND(&miss);
  direct_exit.ReturnCallRuntime(Runtime::kLoadIC_Miss, context, receiver, name,
                                slot, vector);
}

void AccessorAssembler::GenerateLoadIC_Noninlined() {
  using Descriptor = LoadWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<FeedbackVector>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  ExitPoint direct_exit(this);
  TVARIABLE(MaybeObject, var_handler);
  Label if_handler(this, &var_handler), miss(this, Label::kDeferred);

  TNode<MaybeObject> feedback_element = LoadFeedbackVectorSlot(vector, slot);
  TNode<HeapObject> feedback = CAST(feedback_element);

  LoadICParameters p(context, receiver, name, slot, vector);
  TNode<Map> lookup_start_object_map = LoadReceiverMap(p.lookup_start_object());
  LoadIC_Noninlined(&p, lookup_start_object_map, feedback, &var_handler,
                    &if_handler, &miss, &direct_exit);

  BIND(&if_handler);
  {
    LazyLoadICParameters lazy_p(&p);
    HandleLoadICHandlerCase(&lazy_p, var_handler.value(), &miss, &direct_exit);
  }

  BIND(&miss);
  direct_exit.ReturnCallRuntime(Runtime::kLoadIC_Miss, context, receiver, name,
                                slot, vector);
}

void AccessorAssembler::GenerateLoadIC_NoFeedback() {
  using Descriptor = LoadNoFeedbackDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto ic_kind = Parameter<Smi>(Descriptor::kICKind);

  LoadICParameters p(context, receiver, name,
                     TaggedIndexConstant(FeedbackSlot::Invalid().ToInt()),
                     UndefinedConstant());
  LoadIC_NoFeedback(&p, ic_kind);
}

void AccessorAssembler::GenerateLoadICTrampoline() {
  using Descriptor = LoadDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kLoadIC, context, receiver, name, slot, vector);
}

void AccessorAssembler::GenerateLoadICBaseline() {
  using Descriptor = LoadBaselineDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kLoadIC, context, receiver, name, slot, vector);
}

void AccessorAssembler::GenerateLoadICTrampoline_Megamorphic() {
  using Descriptor = LoadDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kLoadIC_Megamorphic, context, receiver, name, slot,
                  vector);
}

void AccessorAssembler::GenerateLoadSuperIC() {
  using Descriptor = LoadWithReceiverAndVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto lookup_start_object = Parameter<Object>(Descriptor::kLookupStartObject);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  LoadICParameters p(context, receiver, name, slot, vector,
                     lookup_start_object);
  LoadSuperIC(&p);
}

void AccessorAssembler::GenerateLoadSuperICBaseline() {
  using Descriptor = LoadWithReceiverBaselineDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto lookup_start_object = Parameter<Object>(Descriptor::kLookupStartObject);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kLoadSuperIC, context, receiver, lookup_start_object,
                  name, slot, vector);
}

void AccessorAssembler::GenerateLoadGlobalIC_NoFeedback() {
  using Descriptor = LoadGlobalNoFeedbackDescriptor;

  auto name = Parameter<Object>(Descriptor::kName);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto ic_kind = Parameter<Smi>(Descriptor::kICKind);

  LoadGlobalIC_NoFeedback(context, name, ic_kind);
}

void AccessorAssembler::GenerateLoadGlobalIC(TypeofMode typeof_mode) {
  using Descriptor = LoadGlobalWithVectorDescriptor;

  auto name = Parameter<Name>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  ExitPoint direct_exit(this);
  LoadGlobalIC(
      vector,
      // lazy_slot
      [=] { return slot; },
      // lazy_context
      [=] { return context; },
      // lazy_name
      [=] { return name; }, typeof_mode, &direct_exit);
}

void AccessorAssembler::GenerateLoadGlobalICTrampoline(TypeofMode typeof_mode) {
  using Descriptor = LoadGlobalDescriptor;

  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtins::LoadGlobalICInOptimizedCode(typeof_mode), context,
                  name, slot, vector);
}

void AccessorAssembler::GenerateLoadGlobalICBaseline(TypeofMode typeof_mode) {
  using Descriptor = LoadGlobalBaselineDescriptor;

  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtins::LoadGlobalICInOptimizedCode(typeof_mode), context,
                  name, slot, vector);
}

void AccessorAssembler::LookupContext(LazyNode<Object> lazy_name,
                                      TNode<TaggedIndex> depth,
                                      LazyNode<TaggedIndex> lazy_slot,
                                      TNode<Context> context,
                                      TypeofMode typeof_mode,
                                      ContextKind context_kind) {
  Label slowpath(this, Label::kDeferred);

  // Check for context extensions to allow the fast path.
  TNode<Context> slot_context = GotoIfHasContextExtensionUpToDepth(
      context, Unsigned(TruncateWordToInt32(TaggedIndexToIntPtr(depth))),
      &slowpath);

  // Fast path does a normal load context.
  {
    auto slot = lazy_slot();
    Return(
        context_kind == ContextKind::kScriptContext
            ? LoadScriptContextElement(slot_context, TaggedIndexToIntPtr(slot))
            : LoadContextElement(slot_context, TaggedIndexToIntPtr(slot)));
  }

  // Slow path when we have to call out to the runtime.
  BIND(&slowpath);
  {
    auto name = lazy_name();
    Runtime::FunctionId function_id = typeof_mode == TypeofMode::kInside
                                          ? Runtime::kLoadLookupSlotInsideTypeof
                                          : Runtime::kLoadLookupSlot;
    TailCallRuntime(function_id, context, name);
  }
}

void AccessorAssembler::GenerateLookupContextTrampoline(
    TypeofMode typeof_mode, ContextKind context_kind) {
  using Descriptor = LookupTrampolineDescriptor;
  LookupContext([&] { return Parameter<Object>(Descriptor::kName); },
                Parameter<TaggedIndex>(Descriptor::kDepth),
                [&] { return Parameter<TaggedIndex>(Descriptor::kSlot); },
                Parameter<Context>(Descriptor::kContext), typeof_mode,
                context_kind);
}

void AccessorAssembler::GenerateLookupContextBaseline(
    TypeofMode typeof_mode, ContextKind context_kind) {
  using Descriptor = LookupBaselineDescriptor;
  LookupContext([&] { return Parameter<Object>(Descriptor::kName); },
                Parameter<TaggedIndex>(Descriptor::kDepth),
                [&] { return Parameter<TaggedIndex>(Descriptor::kSlot); },
                LoadContextFromBaseline(), typeof_mode, context_kind);
}

void AccessorAssembler::LookupGlobalIC(
    LazyNode<Object> lazy_name, TNode<TaggedIndex> depth,
    LazyNode<TaggedIndex> lazy_slot, TNode<Context> context,
    LazyNode<FeedbackVector> lazy_feedback_vector, TypeofMode typeof_mode) {
  Label slowpath(this, Label::kDeferred);

  // Check for context extensions to allow the fast path
  GotoIfHasContextExtensionUpToDepth(
      context, Unsigned(TruncateWordToInt32(TaggedIndexToIntPtr(depth))),
      &slowpath);

  // Fast path does a normal load global
  {
    TailCallBuiltin(Builtins::LoadGlobalICInOptimizedCode(typeof_mode), context,
                    lazy_name(), lazy_slot(), lazy_feedback_vector());
  }

  // Slow path when we have to call out to the runtime
  BIND(&slowpath);
  Runtime::FunctionId function_id = typeof_mode == TypeofMode::kInside
                                        ? Runtime::kLoadLookupSlotInsideTypeof
                                        : Runtime::kLoadLookupSlot;
  TailCallRuntime(function_id, context, lazy_name());
}

void AccessorAssembler::GenerateLookupGlobalIC(TypeofMode typeof_mode) {
  using Descriptor = LookupWithVectorDescriptor;
  LookupGlobalIC([&] { return Parameter<Object>(Descriptor::kName); },
                 Parameter<TaggedIndex>(Descriptor::kDepth),
                 [&] { return Parameter<TaggedIndex>(Descriptor::kSlot); },
                 Parameter<Context>(Descriptor::kContext),
                 [&] { return Parameter<FeedbackVector>(Descriptor::kVector); },
                 typeof_mode);
}

void AccessorAssembler::GenerateLookupGlobalICTrampoline(
    TypeofMode typeof_mode) {
  using Descriptor = LookupTrampolineDescriptor;
  LookupGlobalIC([&] { return Parameter<Object>(Descriptor::kName); },
                 Parameter<TaggedIndex>(Descriptor::kDepth),
                 [&] { return Parameter<TaggedIndex>(Descriptor::kSlot); },
                 Parameter<Context>(Descriptor::kContext),
                 [&] { return LoadFeedbackVectorForStub(); }, typeof_mode);
}

void AccessorAssembler::GenerateLookupGlobalICBaseline(TypeofMode typeof_mode) {
  using Descriptor = LookupBaselineDescriptor;
  LookupGlobalIC([&] { return Parameter<Object>(Descriptor::kName); },
                 Parameter<TaggedIndex>(Descriptor::kDepth),
                 [&] { return Parameter<TaggedIndex>(Descriptor::kSlot); },
                 LoadContextFromBaseline(),
                 [&] { return LoadFeedbackVectorFromBaseline(); }, typeof_mode);
}

void AccessorAssembler::GenerateKeyedLoadIC() {
  using Descriptor = KeyedLoadWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  LoadICParameters p(context, receiver, name, slot, vector);
  KeyedLoadIC(&p, LoadAccessMode::kLoad);
}

void AccessorAssembler::GenerateEnumeratedKeyedLoadIC() {
  using Descriptor = EnumeratedKeyedLoadDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto enum_index = Parameter<Smi>(Descriptor::kEnumIndex);
  auto cache_type = Parameter<Object>(Descriptor::kCacheType);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto lookup_start_object = std::nullopt;

  LoadICParameters p(context, receiver, name, slot, vector, lookup_start_object,
                     enum_index, cache_type);
  KeyedLoadIC(&p, LoadAccessMode::kLoad);
}

void AccessorAssembler::GenerateKeyedLoadIC_Megamorphic() {
  using Descriptor = KeyedLoadWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  LoadICParameters p(context, receiver, name, slot, vector);
  KeyedLoadICGeneric(&p);
}

void AccessorAssembler::GenerateKeyedLoadICTrampoline() {
  using Descriptor = KeyedLoadDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kKeyedLoadIC, context, receiver, name, slot, vector);
}

void AccessorAssembler::GenerateKeyedLoadICBaseline() {
  using Descriptor = KeyedLoadBaselineDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kKeyedLoadIC, context, receiver, name, slot, vector);
}

void AccessorAssembler::GenerateEnumeratedKeyedLoadICBaseline() {
  using Descriptor = EnumeratedKeyedLoadBaselineDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto enum_index = Parameter<Smi>(Descriptor::kEnumIndex);
  auto cache_type = Parameter<Object>(Descriptor::kCacheType);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kEnumeratedKeyedLoadIC, context, receiver, name,
                  enum_index, cache_type, slot, vector);
}

void AccessorAssembler::GenerateKeyedLoadICTrampoline_Megamorphic() {
  using Descriptor = KeyedLoadDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kKeyedLoadIC_Megamorphic, context, receiver, name,
                  slot, vector);
}

void AccessorAssembler::GenerateKeyedLoadIC_PolymorphicName() {
  using Descriptor = LoadWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<FeedbackVector>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  LoadICParameters p(context, receiver, name, slot, vector);
  KeyedLoadICPolymorphicName(&p, LoadAccessMode::kLoad);
}

void AccessorAssembler::GenerateStoreGlobalIC() {
  using Descriptor = StoreGlobalWithVectorDescriptor;

  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto flags = std::nullopt;
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  StoreICParameters p(context, std::nullopt, name, value, flags, slot, vector,
                      StoreICMode::kDefault);
  StoreGlobalIC(&p);
}

void AccessorAssembler::GenerateStoreGlobalICTrampoline() {
  using Descriptor = StoreGlobalDescriptor;

  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kStoreGlobalIC, context, name, value, slot, vector);
}

void AccessorAssembler::GenerateStoreGlobalICBaseline() {
  using Descriptor = StoreGlobalBaselineDescriptor;

  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kStoreGlobalIC, context, name, value, slot, vector);
}

void AccessorAssembler::GenerateStoreIC() {
  using Descriptor = StoreWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto flags = std::nullopt;
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  StoreICParameters p(context, receiver, name, value, flags, slot, vector,
                      StoreICMode::kDefault);
  StoreIC(&p);
}

void AccessorAssembler::GenerateStoreIC_Megamorphic() {
  using Descriptor = StoreWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto flags = std::nullopt;
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  ExitPoint direct_exit(this);
  TVARIABLE(MaybeObject, var_handler);
  Label if_handler(this, &var_handler), miss(this, Label::kDeferred);

  CSA_DCHECK(this, TaggedEqual(LoadFeedbackVectorSlot(CAST(vector), slot),
                               MegamorphicSymbolConstant()));

  TryProbeStubCache(isolate()->store_stub_cache(), receiver, CAST(name),
                    &if_handler, &var_handler, &miss);

  BIND(&if_handler);
  {
    StoreICParameters p(context, receiver, name, value, flags, slot, vector,
                        StoreICMode::kDefault);
    HandleStoreICHandlerCase(&p, var_handler.value(), &miss,
                             ICMode::kNonGlobalIC);
  }

  BIND(&miss);
  {
    direct_exit.ReturnCallRuntime(Runtime::kStoreIC_Miss, context, value, slot,
                                  vector, receiver, name);
  }
}

void AccessorAssembler::GenerateStoreICTrampoline() {
  using Descriptor = StoreDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kStoreIC, context, receiver, name, value, slot,
                  vector);
}

void AccessorAssembler::GenerateStoreICTrampoline_Megamorphic() {
  using Descriptor = StoreDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kStoreIC_Megamorphic, context, receiver, name, value,
                  slot, vector);
}

void AccessorAssembler::GenerateStoreICBaseline() {
  using Descriptor = StoreBaselineDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kStoreIC, context, receiver, name, value, slot,
                  vector);
}

void AccessorAssembler::GenerateDefineNamedOwnIC() {
  using Descriptor = StoreWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto flags = std::nullopt;
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  StoreICParameters p(context, receiver, name, value, flags, slot, vector,
                      StoreICMode::kDefineNamedOwn);
  // StoreIC is a generic helper than handle both set and define own
  // named stores.
  StoreIC(&p);
}

void AccessorAssembler::GenerateDefineNamedOwnICTrampoline() {
  using Descriptor = StoreDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kDefineNamedOwnIC, context, receiver, name, value,
                  slot, vector);
}

void AccessorAssembler::GenerateDefineNamedOwnICBaseline() {
  using Descriptor = StoreWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kDefineNamedOwnIC, context, receiver, name, value,
                  slot, vector);
}

void AccessorAssembler::GenerateKeyedStoreIC() {
  using Descriptor = StoreWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto flags = std::nullopt;
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  StoreICParameters p(context, receiver, name, value, flags, slot, vector,
                      StoreICMode::kDefault);
  KeyedStoreIC(&p);
}

void AccessorAssembler::GenerateKeyedStoreICTrampoline() {
  using Descriptor = StoreDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kKeyedStoreIC, context, receiver, name, value, slot,
                  vector);
}

void AccessorAssembler::GenerateKeyedStoreICTrampoline_Megamorphic() {
  using Descriptor = StoreDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto context = Parameter<Context>(Descriptor::kContext);
  TNode<FeedbackVector> vector = LoadFeedbackVectorForStub();

  TailCallBuiltin(Builtin::kKeyedStoreIC_Megamorphic, context, receiver, name,
                  value, slot, vector);
}

void AccessorAssembler::GenerateKeyedStoreICBaseline() {
  using Descriptor = StoreBaselineDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  TNode<FeedbackVector> vector = LoadFeedbackVectorFromBaseline();
  TNode<Context> context = LoadContextFromBaseline();

  TailCallBuiltin(Builtin::kKeyedStoreIC, context, receiver, name, value, slot,
                  vector);
}

void AccessorAssembler::GenerateDefineKeyedOwnIC() {
  using Descriptor = DefineKeyedOwnWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto flags = Parameter<Smi>(Descriptor::kFlags);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  StoreICParameters p(context, receiver, name, value, flags, slot, vector,
                      StoreICMode::kDefineKeyedOwn);
  DefineKeyedOwnIC(&p);
}

void AccessorAssembler::GenerateDefineKeyedOwnICTrampoline() {
  using Descriptor = DefineKeyedOwnDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descript
```