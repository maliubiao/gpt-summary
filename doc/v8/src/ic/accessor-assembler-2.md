Response: The user wants a summary of the C++ source code file `v8/src/ic/accessor-assembler.cc`.
This is the third part of a four-part summary request.
The previous parts likely covered the beginning of the file.
This part seems to focus on implementing various IC (Inline Cache) operations, particularly load and store operations for both regular properties and keyed properties.
It handles different IC states (monomorphic, polymorphic, megamorphic, uninitialized) and fallbacks to runtime functions when needed.
The code also interacts with the feedback vector to optimize property access based on past behavior.

Key aspects to look for:
- Functions related to LoadIC, StoreIC, and their variations (Global, Keyed, Super).
- Handling of different IC states (monomorphic, polymorphic, etc.).
- Use of feedback vectors for optimization.
- Interaction with the runtime.
- Assembly language constructs (labels, jumps, etc.).
- Connection to Javascript concepts (property access, global variables, etc.).

Plan:
1. Read through the code and identify the main function groups.
2. Summarize the purpose of each function group.
3. If there's a clear connection to Javascript, provide a simple example.
这是 `v8/src/ic/accessor-assembler.cc` 文件的第三部分，主要负责实现**属性访问的内联缓存（Inline Cache, IC）机制**，特别是针对**属性加载（Load）和存储（Store）**操作。它处理了不同类型的属性访问，包括普通属性、全局属性、键值属性以及原型链上的属性，并利用反馈向量来优化属性访问的性能。

**主要功能归纳:**

1. **LoadIC (加载属性内联缓存):**
   - 实现了 `LoadIC` 的多种变体，例如 `LoadIC_NoFeedback` (无反馈信息的加载)、`LoadSuperIC` (加载父类属性)、`LoadGlobalIC` (加载全局属性) 等。
   - 针对不同的反馈状态（例如单态、多态、巨态、未初始化）采取不同的优化策略。
   - 利用反馈向量（`FeedbackVector`）中的信息来快速定位属性。
   - 如果缓存命中，则直接返回属性值；如果缓存未命中，则根据情况尝试不同的处理路径，最终可能回退到运行时 (Runtime) 函数。
   - 针对 `Function.prototype` 的加载进行了特殊优化，因为这是一种常见的且可能只执行一次的场景。

2. **StoreIC (存储属性内联缓存):**
   - 实现了 `StoreIC` 的多种变体，例如 `StoreGlobalIC` (存储全局属性)、`KeyedStoreIC` (存储键值属性)、`DefineKeyedOwnIC` (定义键值自有属性) 等。
   - 类似于 `LoadIC`，它也根据反馈状态进行优化，并利用反馈向量。
   - 处理了存储操作的各种情况，包括只写属性、常量属性等。
   - 对于全局属性的存储，还处理了词法变量的情况。

3. **KeyedLoadIC (键值加载内联缓存):**
   - 专门处理通过键（例如数组索引或字符串）访问属性的情况。
   - 区分了不同的访问模式 (`LoadAccessMode`)。
   - 同样利用反馈向量来优化性能。
   - 提供了 `KeyedLoadICGeneric` 用于处理更一般的情况，例如键不是字符串或数字的情况。
   - 实现了 `KeyedLoadICPolymorphicName` 用于处理当反馈向量中记录了属性名的情况。

4. **GlobalIC (全局属性内联缓存):**
   - 专门处理全局对象的属性访问。
   - 区分了在 `typeof` 运算符内部和外部的加载操作 (`TypeofMode`)。
   - 实现了 `LoadGlobalIC_TryPropertyCellCase` 和 `LoadGlobalIC_TryHandlerCase` 来尝试不同的优化路径。
   - 提供了 `ScriptContextTableLookup` 用于在脚本上下文表中查找变量。

5. **Monomorphic/Polymorphic/Megamorphic 优化:**
   - 代码中大量使用了 `TryMonomorphicCase` 和 `HandlePolymorphicCase` 等函数，用于处理不同类型的内联缓存状态。
   - 单态 (Monomorphic) 指的是属性只在一个特定的对象结构上被访问过。
   - 多态 (Polymorphic) 指的是属性在少数几种对象结构上被访问过。
   - 巨态 (Megamorphic) 指的是属性在很多种对象结构上被访问过，此时通常会使用更通用的缓存策略或直接回退到运行时。

6. **与 Runtime 的交互:**
   - 当内联缓存无法处理属性访问时，代码会回退到调用 V8 的运行时 (Runtime) 函数，例如 `Runtime::kLoadIC_Miss`、`Runtime::kStoreIC_Miss` 等。

7. **反馈向量 (Feedback Vector):**
   - 代码中大量使用了 `p->vector()` 和 `p->slot()` 来访问反馈向量中的信息。
   - 反馈向量用于记录属性访问的历史信息，例如访问过的对象类型和处理函数，以便后续的属性访问可以更快。

**与 JavaScript 的功能关系及示例:**

这些 C++ 代码直接影响着 JavaScript 中属性访问的性能。内联缓存的目标是在运行时优化属性的读取和写入操作。

**JavaScript 示例 (LoadIC):**

```javascript
function Point(x, y) {
  this.x = x;
  this.y = y;
}

const p1 = new Point(1, 2);
const p2 = new Point(3, 4);

// 第一次访问 p1.x，可能触发 LoadIC 的 miss，并记录反馈信息
console.log(p1.x);

// 第二次访问 p1.x，LoadIC 可能会命中，直接返回缓存的值，速度更快
console.log(p1.x);

// 访问 p2.x，如果 p1 和 p2 的结构相同，LoadIC 可能会继续命中（单态或多态）
console.log(p2.x);
```

在这个例子中，当第一次访问 `p1.x` 时，V8 的 LoadIC 机制可能会因为没有缓存信息而错过 (miss)。此时，V8 会执行更慢的查找操作，并将有关 `Point` 对象和 `x` 属性的信息记录到反馈向量中。当再次访问 `p1.x` 或访问具有相同结构的对象（如 `p2`) 的 `x` 属性时，LoadIC 就可以利用反馈向量中的信息快速定位属性，从而提高性能。

**JavaScript 示例 (StoreIC):**

```javascript
const obj = {};

// 第一次设置 obj.name，可能触发 StoreIC 的 miss，并记录反馈信息
obj.name = "Alice";

// 第二次设置 obj.name，StoreIC 可能会命中，直接更新缓存，速度更快
obj.name = "Bob";
```

类似于 LoadIC，StoreIC 也会缓存属性存储的相关信息，以便后续对相同属性的存储操作可以更快地执行。

**JavaScript 示例 (KeyedLoadIC):**

```javascript
const arr = [1, 2, 3];

// 第一次访问 arr[0]，可能触发 KeyedLoadIC 的 miss
console.log(arr[0]);

// 第二次访问 arr[0]，KeyedLoadIC 可能会命中
console.log(arr[0]);
```

KeyedLoadIC 用于优化通过索引或字符串键访问对象属性的情况，例如访问数组元素或对象的字符串属性。

总而言之，`accessor-assembler.cc` 的这部分代码是 V8 引擎中至关重要的性能优化组件，它通过内联缓存和反馈向量等技术，显著提高了 JavaScript 属性访问的速度，从而提升了整体的 JavaScript 执行效率。

Prompt: 
```
这是目录为v8/src/ic/accessor-assembler.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
&try_megamorphic);
    GotoIf(TaggedEqual(feedback, MegaDOMSymbolConstant()), &try_megadom);
    Goto(miss);

    BIND(&try_megamorphic);
    {
      TryProbeStubCache(isolate()->load_stub_cache(), p->lookup_start_object(),
                        lookup_start_object_map, CAST(p->name()), if_handler,
                        var_handler, miss);
    }

    BIND(&try_megadom);
    {
      TryMegaDOMCase(p->lookup_start_object(), lookup_start_object_map,
                     var_handler, p->vector(), p->slot(), miss, exit_point);
    }
  }
}

void AccessorAssembler::LoadIC_NoFeedback(const LoadICParameters* p,
                                          TNode<Smi> ic_kind) {
  Label miss(this, Label::kDeferred);
  TNode<Object> lookup_start_object = p->receiver_and_lookup_start_object();
  GotoIf(TaggedIsSmi(lookup_start_object), &miss);
  TNode<Map> lookup_start_object_map = LoadMap(CAST(lookup_start_object));
  GotoIf(IsDeprecatedMap(lookup_start_object_map), &miss);

  TNode<Uint16T> instance_type = LoadMapInstanceType(lookup_start_object_map);

  {
    // Special case for Function.prototype load, because it's very common
    // for ICs that are only executed once (MyFunc.prototype.foo = ...).
    Label not_function_prototype(this, Label::kDeferred);
    GotoIfNot(IsJSFunctionInstanceType(instance_type), &not_function_prototype);
    GotoIfNot(IsPrototypeString(p->name()), &not_function_prototype);

    GotoIfPrototypeRequiresRuntimeLookup(CAST(lookup_start_object),
                                         lookup_start_object_map,
                                         &not_function_prototype);
    Return(LoadJSFunctionPrototype(CAST(lookup_start_object), &miss));
    BIND(&not_function_prototype);
  }

  GenericPropertyLoad(CAST(lookup_start_object), lookup_start_object_map,
                      instance_type, p, &miss, kDontUseStubCache);

  BIND(&miss);
  {
    TailCallRuntime(Runtime::kLoadNoFeedbackIC_Miss, p->context(),
                    p->receiver(), p->name(), ic_kind);
  }
}

void AccessorAssembler::LoadSuperIC_NoFeedback(const LoadICParameters* p) {
  Label miss(this, Label::kDeferred);
  TNode<Object> lookup_start_object = p->lookup_start_object();

  // The lookup start object cannot be a SMI, since it's the home object's
  // prototype, and it's not possible to set SMIs as prototypes.
  TNode<Map> lookup_start_object_map = LoadMap(CAST(lookup_start_object));
  GotoIf(IsDeprecatedMap(lookup_start_object_map), &miss);

  TNode<Uint16T> instance_type = LoadMapInstanceType(lookup_start_object_map);

  GenericPropertyLoad(CAST(lookup_start_object), lookup_start_object_map,
                      instance_type, p, &miss, kDontUseStubCache);

  BIND(&miss);
  {
    TailCallRuntime(Runtime::kLoadWithReceiverNoFeedbackIC_Miss, p->context(),
                    p->receiver(), p->lookup_start_object(), p->name());
  }
}

void AccessorAssembler::LoadGlobalIC(TNode<HeapObject> maybe_feedback_vector,
                                     const LazyNode<TaggedIndex>& lazy_slot,
                                     const LazyNode<Context>& lazy_context,
                                     const LazyNode<Name>& lazy_name,
                                     TypeofMode typeof_mode,
                                     ExitPoint* exit_point) {
  Label try_handler(this, Label::kDeferred), miss(this, Label::kDeferred),
      no_feedback(this, Label::kDeferred);

  GotoIf(IsUndefined(maybe_feedback_vector), &no_feedback);
  {
    TNode<TaggedIndex> slot = lazy_slot();

    {
      TNode<FeedbackVector> vector = CAST(maybe_feedback_vector);
      LoadGlobalIC_TryPropertyCellCase(vector, slot, lazy_context, exit_point,
                                       &try_handler, &miss);

      BIND(&try_handler);
      LoadGlobalIC_TryHandlerCase(vector, slot, lazy_context, lazy_name,
                                  typeof_mode, exit_point, &miss);
    }

    BIND(&miss);
    {
      Comment("LoadGlobalIC_MissCase");
      TNode<Context> context = lazy_context();
      TNode<Name> name = lazy_name();
      exit_point->ReturnCallRuntime(Runtime::kLoadGlobalIC_Miss, context, name,
                                    slot, maybe_feedback_vector,
                                    SmiConstant(typeof_mode));
    }
  }

  BIND(&no_feedback);
  {
    int ic_kind =
        static_cast<int>((typeof_mode == TypeofMode::kInside)
                             ? FeedbackSlotKind::kLoadGlobalInsideTypeof
                             : FeedbackSlotKind::kLoadGlobalNotInsideTypeof);
    exit_point->ReturnCallBuiltin(Builtin::kLoadGlobalIC_NoFeedback,
                                  lazy_context(), lazy_name(),
                                  SmiConstant(ic_kind));
  }
}

void AccessorAssembler::LoadGlobalIC_TryPropertyCellCase(
    TNode<FeedbackVector> vector, TNode<TaggedIndex> slot,
    const LazyNode<Context>& lazy_context, ExitPoint* exit_point,
    Label* try_handler, Label* miss) {
  Comment("LoadGlobalIC_TryPropertyCellCase");

  Label if_lexical_var(this), if_property_cell(this);
  TNode<MaybeObject> maybe_weak_ref = LoadFeedbackVectorSlot(vector, slot);
  Branch(TaggedIsSmi(maybe_weak_ref), &if_lexical_var, &if_property_cell);

  BIND(&if_property_cell);
  {
    // This branch also handles the "handler mode": the weak reference is
    // cleared, the feedback extra is the handler. In that case we jump to
    // try_handler. (See FeedbackNexus::ConfigureHandlerMode.)
    CSA_DCHECK(this, IsWeakOrCleared(maybe_weak_ref));
    TNode<PropertyCell> property_cell =
        CAST(GetHeapObjectAssumeWeak(maybe_weak_ref, try_handler));
    TNode<Object> value =
        LoadObjectField(property_cell, PropertyCell::kValueOffset);
    GotoIf(TaggedEqual(value, PropertyCellHoleConstant()), miss);
    exit_point->Return(value);
  }

  BIND(&if_lexical_var);
  {
    // This branch handles the "lexical variable mode": the feedback is a SMI
    // encoding the variable location. (See
    // FeedbackNexus::ConfigureLexicalVarMode.)
    Comment("Load lexical variable");
    TNode<IntPtrT> lexical_handler = SmiUntag(CAST(maybe_weak_ref));
    TNode<IntPtrT> context_index =
        Signed(DecodeWord<FeedbackNexus::ContextIndexBits>(lexical_handler));
    TNode<IntPtrT> slot_index =
        Signed(DecodeWord<FeedbackNexus::SlotIndexBits>(lexical_handler));
    TNode<Context> context = lazy_context();
    TNode<Context> script_context = LoadScriptContext(context, context_index);
    TNode<Object> result = LoadContextElement(script_context, slot_index);
    exit_point->Return(result);
  }
}

void AccessorAssembler::LoadGlobalIC_TryHandlerCase(
    TNode<FeedbackVector> vector, TNode<TaggedIndex> slot,
    const LazyNode<Context>& lazy_context, const LazyNode<Name>& lazy_name,
    TypeofMode typeof_mode, ExitPoint* exit_point, Label* miss) {
  Comment("LoadGlobalIC_TryHandlerCase");

  Label call_handler(this), non_smi(this);

  TNode<MaybeObject> feedback_element =
      LoadFeedbackVectorSlot(vector, slot, kTaggedSize);
  TNode<Object> handler = CAST(feedback_element);
  GotoIf(TaggedEqual(handler, UninitializedSymbolConstant()), miss);

  OnNonExistent on_nonexistent = typeof_mode == TypeofMode::kNotInside
                                     ? OnNonExistent::kThrowReferenceError
                                     : OnNonExistent::kReturnUndefined;

  TNode<Context> context = lazy_context();
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TNode<JSGlobalProxy> receiver =
      CAST(LoadContextElement(native_context, Context::GLOBAL_PROXY_INDEX));
  TNode<Object> global =
      LoadContextElement(native_context, Context::EXTENSION_INDEX);

  LazyLoadICParameters p([=] { return context; }, receiver, lazy_name,
                         [=] { return slot; }, vector, global);

  HandleLoadICHandlerCase(&p, handler, miss, exit_point, ICMode::kGlobalIC,
                          on_nonexistent);
}

void AccessorAssembler::ScriptContextTableLookup(
    TNode<Name> name, TNode<NativeContext> native_context, Label* found_hole,
    Label* not_found) {
  TNode<ScriptContextTable> script_context_table = CAST(
      LoadContextElement(native_context, Context::SCRIPT_CONTEXT_TABLE_INDEX));
  TVARIABLE(IntPtrT, context_index, IntPtrConstant(-1));
  Label loop(this, &context_index);
  TNode<IntPtrT> num_script_contexts = PositiveSmiUntag(CAST(LoadObjectField(
      script_context_table, offsetof(ScriptContextTable, length_))));
  Goto(&loop);

  BIND(&loop);
  {
    context_index = IntPtrAdd(context_index.value(), IntPtrConstant(1));
    GotoIf(IntPtrGreaterThanOrEqual(context_index.value(), num_script_contexts),
           not_found);

    TNode<Context> script_context =
        LoadArrayElement(script_context_table, context_index.value());
    TNode<ScopeInfo> scope_info =
        CAST(LoadContextElement(script_context, Context::SCOPE_INFO_INDEX));

    TNode<IntPtrT> context_local_index =
        IndexOfLocalName(scope_info, name, &loop);

    TNode<IntPtrT> var_index =
        IntPtrAdd(IntPtrConstant(Context::MIN_CONTEXT_EXTENDED_SLOTS),
                  context_local_index);
    TNode<Object> result = LoadContextElement(script_context, var_index);
    GotoIf(IsTheHole(result), found_hole);
    Return(result);
  }
}

void AccessorAssembler::LoadGlobalIC_NoFeedback(TNode<Context> context,
                                                TNode<Object> name,
                                                TNode<Smi> smi_typeof_mode) {
  TNode<NativeContext> native_context = LoadNativeContext(context);
  Label regular_load(this), throw_reference_error(this, Label::kDeferred);

  GotoIfNot(IsString(CAST(name)), &regular_load);
  ScriptContextTableLookup(CAST(name), native_context, &throw_reference_error,
                           &regular_load);

  BIND(&throw_reference_error);
  Return(CallRuntime(Runtime::kThrowReferenceError, context, name));

  BIND(&regular_load);
  TNode<JSGlobalObject> global_object =
      CAST(LoadContextElement(native_context, Context::EXTENSION_INDEX));
  TailCallBuiltin(Builtin::kLoadIC_NoFeedback, context, global_object, name,
                  smi_typeof_mode);
}

void AccessorAssembler::KeyedLoadIC(const LoadICParameters* p,
                                    LoadAccessMode access_mode) {
  ExitPoint direct_exit(this);

  TVARIABLE(MaybeObject, var_handler);
  Label if_handler(this, &var_handler), try_polymorphic(this, Label::kDeferred),
      try_megamorphic(this, Label::kDeferred),
      try_uninitialized(this, Label::kDeferred),
      try_polymorphic_name(this, Label::kDeferred),
      miss(this, Label::kDeferred), generic(this, Label::kDeferred);

  TNode<Map> lookup_start_object_map =
      LoadReceiverMap(p->receiver_and_lookup_start_object());
  GotoIf(IsDeprecatedMap(lookup_start_object_map), &miss);

  TryEnumeratedKeyedLoad(p, lookup_start_object_map, &direct_exit);

  GotoIf(IsUndefined(p->vector()), &generic);

  // Check monomorphic case.
  TNode<HeapObjectReference> weak_lookup_start_object_map =
      MakeWeak(lookup_start_object_map);
  TNode<HeapObjectReference> feedback = TryMonomorphicCase(
      p->slot(), CAST(p->vector()), weak_lookup_start_object_map, &if_handler,
      &var_handler, &try_polymorphic);
  BIND(&if_handler);
  {
    LazyLoadICParameters lazy_p(p);
    HandleLoadICHandlerCase(
        &lazy_p, var_handler.value(), &miss, &direct_exit, ICMode::kNonGlobalIC,
        OnNonExistent::kReturnUndefined, kSupportElements, access_mode);
  }

  BIND(&try_polymorphic);
  TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
  {
    // Check polymorphic case.
    Comment("KeyedLoadIC_try_polymorphic");
    GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)), &try_megamorphic);
    HandlePolymorphicCase(weak_lookup_start_object_map, CAST(strong_feedback),
                          &if_handler, &var_handler, &miss);
  }

  BIND(&try_megamorphic);
  {
    // Check megamorphic case.
    Comment("KeyedLoadIC_try_megamorphic");
    Branch(TaggedEqual(strong_feedback, MegamorphicSymbolConstant()), &generic,
           &try_uninitialized);
  }

  BIND(&generic);
  {
    // TODO(jkummerow): Inline this? Or some of it?
    TailCallBuiltin(
        access_mode == LoadAccessMode::kLoad ? Builtin::kKeyedLoadIC_Megamorphic
                                             : Builtin::kKeyedHasIC_Megamorphic,
        p->context(), p->receiver(), p->name(), p->slot(), p->vector());
  }

  BIND(&try_uninitialized);
  {
    // Check uninitialized case.
    Comment("KeyedLoadIC_try_uninitialized");
    Branch(TaggedEqual(strong_feedback, UninitializedSymbolConstant()), &miss,
           &try_polymorphic_name);
  }

  BIND(&try_polymorphic_name);
  {
    // We might have a name in feedback, and a weak fixed array in the next
    // slot.
    Comment("KeyedLoadIC_try_polymorphic_name");
    TVARIABLE(Name, var_name);
    Label if_polymorphic_name(this), feedback_matches(this),
        if_internalized(this), if_notinternalized(this, Label::kDeferred);

    // Fast-case: The recorded {feedback} matches the {name}.
    GotoIf(TaggedEqual(strong_feedback, p->name()), &feedback_matches);

    {
      // Try to internalize the {name} if it isn't already.
      TVARIABLE(IntPtrT, var_index);
      TryToName(p->name(), &miss, &var_index, &if_internalized, &var_name,
                &miss, &if_notinternalized);
    }

    BIND(&if_internalized);
    {
      // The {var_name} now contains a unique name.
      Branch(TaggedEqual(strong_feedback, var_name.value()),
             &if_polymorphic_name, &miss);
    }

    BIND(&if_notinternalized);
    {
      TVARIABLE(IntPtrT, var_index);
      TryInternalizeString(CAST(p->name()), &miss, &var_index, &if_internalized,
                           &var_name, &miss, &miss);
    }

    BIND(&feedback_matches);
    {
      var_name = CAST(p->name());
      Goto(&if_polymorphic_name);
    }

    BIND(&if_polymorphic_name);
    {
      // If the name comparison succeeded, we know we have a weak fixed array
      // with at least one map/handler pair.
      TailCallBuiltin(access_mode == LoadAccessMode::kLoad
                          ? Builtin::kKeyedLoadIC_PolymorphicName
                          : Builtin::kKeyedHasIC_PolymorphicName,
                      p->context(), p->receiver(), var_name.value(), p->slot(),
                      p->vector());
    }
  }

  BIND(&miss);
  {
    Comment("KeyedLoadIC_miss");
    TailCallRuntime(
        access_mode == LoadAccessMode::kLoad ? Runtime::kKeyedLoadIC_Miss
                                             : Runtime::kKeyedHasIC_Miss,
        p->context(), p->receiver(), p->name(), p->slot(), p->vector());
  }
}

void AccessorAssembler::KeyedLoadICGeneric(const LoadICParameters* p) {
  TVARIABLE(Object, var_name, p->name());

  Label if_runtime(this, Label::kDeferred);
  TNode<Object> lookup_start_object = p->lookup_start_object();
  GotoIf(TaggedIsSmi(lookup_start_object), &if_runtime);
  GotoIf(IsNullOrUndefined(lookup_start_object), &if_runtime);

  {
    TVARIABLE(IntPtrT, var_index);
    TVARIABLE(Name, var_unique);
    Label if_index(this), if_unique_name(this, &var_name), if_notunique(this),
        if_other(this, Label::kDeferred);

    TryToName(var_name.value(), &if_index, &var_index, &if_unique_name,
              &var_unique, &if_other, &if_notunique);

    BIND(&if_unique_name);
    {
      LoadICParameters pp(p, var_unique.value());
      TNode<Map> lookup_start_object_map = LoadMap(CAST(lookup_start_object));
      GenericPropertyLoad(CAST(lookup_start_object), lookup_start_object_map,
                          LoadMapInstanceType(lookup_start_object_map), &pp,
                          &if_runtime);
    }

    BIND(&if_other);
    {
      var_name = CallBuiltin(Builtin::kToName, p->context(), var_name.value());
      TryToName(var_name.value(), &if_index, &var_index, &if_unique_name,
                &var_unique, &if_runtime, &if_notunique);
    }

    BIND(&if_notunique);
    {
      if (v8_flags.internalize_on_the_fly) {
        // Ideally we could return undefined directly here if the name is not
        // found in the string table, i.e. it was never internalized, but that
        // invariant doesn't hold with named property interceptors (at this
        // point), so we take the {if_runtime} path instead.
        Label if_in_string_table(this);
        TryInternalizeString(CAST(var_name.value()), &if_index, &var_index,
                             &if_in_string_table, &var_unique, &if_runtime,
                             &if_runtime);

        BIND(&if_in_string_table);
        {
          // TODO(bmeurer): We currently use a version of GenericPropertyLoad
          // here, where we don't try to probe the megamorphic stub cache
          // after successfully internalizing the incoming string. Past
          // experiments with this have shown that it causes too much traffic
          // on the stub cache. We may want to re-evaluate that in the future.
          LoadICParameters pp(p, var_unique.value());
          TNode<Map> lookup_start_object_map =
              LoadMap(CAST(lookup_start_object));
          GenericPropertyLoad(CAST(lookup_start_object),
                              lookup_start_object_map,
                              LoadMapInstanceType(lookup_start_object_map), &pp,
                              &if_runtime, kDontUseStubCache);
        }
      } else {
        Goto(&if_runtime);
      }
    }

    BIND(&if_index);
    {
      TNode<Map> lookup_start_object_map = LoadMap(CAST(lookup_start_object));
      GenericElementLoad(CAST(lookup_start_object), lookup_start_object_map,
                         LoadMapInstanceType(lookup_start_object_map),
                         var_index.value(), &if_runtime);
    }
  }

  BIND(&if_runtime);
  {
    Comment("KeyedLoadGeneric_slow");
    // TODO(jkummerow): Should we use the GetProperty TF stub instead?
    TailCallRuntime(Runtime::kGetProperty, p->context(),
                    p->receiver_and_lookup_start_object(), var_name.value());
  }
}

void AccessorAssembler::KeyedLoadICPolymorphicName(const LoadICParameters* p,
                                                   LoadAccessMode access_mode) {
  TVARIABLE(MaybeObject, var_handler);
  Label if_handler(this, &var_handler), miss(this, Label::kDeferred);

  TNode<Object> lookup_start_object = p->lookup_start_object();
  TNode<Map> lookup_start_object_map = LoadReceiverMap(lookup_start_object);
  TNode<Name> name = CAST(p->name());
  TNode<FeedbackVector> vector = CAST(p->vector());
  TNode<TaggedIndex> slot = p->slot();
  TNode<Context> context = p->context();

  // When we get here, we know that the {name} matches the recorded
  // feedback name in the {vector} and can safely be used for the
  // LoadIC handler logic below.
  CSA_DCHECK(this, Word32BinaryNot(IsDeprecatedMap(lookup_start_object_map)));
  CSA_DCHECK(this, TaggedEqual(name, LoadFeedbackVectorSlot(vector, slot)),
             name, vector);

  // Check if we have a matching handler for the {lookup_start_object_map}.
  TNode<MaybeObject> feedback_element =
      LoadFeedbackVectorSlot(vector, slot, kTaggedSize);
  TNode<WeakFixedArray> array = CAST(feedback_element);
  HandlePolymorphicCase(MakeWeak(lookup_start_object_map), array, &if_handler,
                        &var_handler, &miss);

  BIND(&if_handler);
  {
    ExitPoint direct_exit(this);
    LazyLoadICParameters lazy_p(p);
    HandleLoadICHandlerCase(
        &lazy_p, var_handler.value(), &miss, &direct_exit, ICMode::kNonGlobalIC,
        OnNonExistent::kReturnUndefined, kOnlyProperties, access_mode);
  }

  BIND(&miss);
  {
    Comment("KeyedLoadIC_miss");
    TailCallRuntime(
        access_mode == LoadAccessMode::kLoad ? Runtime::kKeyedLoadIC_Miss
                                             : Runtime::kKeyedHasIC_Miss,
        context, p->receiver_and_lookup_start_object(), name, slot, vector);
  }
}

void AccessorAssembler::StoreIC(const StoreICParameters* p) {
  TVARIABLE(MaybeObject, var_handler,
            ReinterpretCast<MaybeObject>(SmiConstant(0)));

  Label if_handler(this, &var_handler),
      if_handler_from_stub_cache(this, &var_handler, Label::kDeferred),
      try_polymorphic(this, Label::kDeferred),
      try_megamorphic(this, Label::kDeferred), miss(this, Label::kDeferred),
      no_feedback(this, Label::kDeferred);

  TNode<Map> receiver_map = LoadReceiverMap(p->receiver());
  GotoIf(IsDeprecatedMap(receiver_map), &miss);

  GotoIf(IsUndefined(p->vector()), &no_feedback);

  // Check monomorphic case.
  TNode<HeapObjectReference> weak_receiver_map = MakeWeak(receiver_map);
  TNode<HeapObjectReference> feedback =
      TryMonomorphicCase(p->slot(), CAST(p->vector()), weak_receiver_map,
                         &if_handler, &var_handler, &try_polymorphic);
  BIND(&if_handler);
  {
    Comment("StoreIC_if_handler");
    HandleStoreICHandlerCase(p, var_handler.value(), &miss,
                             ICMode::kNonGlobalIC);
  }

  BIND(&try_polymorphic);
  TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
  {
    // Check polymorphic case.
    Comment("StoreIC_try_polymorphic");
    GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)), &try_megamorphic);
    HandlePolymorphicCase(weak_receiver_map, CAST(strong_feedback), &if_handler,
                          &var_handler, &miss);
  }

  BIND(&try_megamorphic);
  {
    // Check megamorphic case.
    GotoIfNot(TaggedEqual(strong_feedback, MegamorphicSymbolConstant()), &miss);

    TryProbeStubCache(p->stub_cache(isolate()), p->receiver(), receiver_map,
                      CAST(p->name()), &if_handler, &var_handler, &miss);
  }

  BIND(&no_feedback);
  {
    // TODO(v8:12548): refactor SetNamedIC as a subclass of StoreIC, which can
    // be called here and below when !p->IsDefineNamedOwn().
    auto builtin = p->IsDefineNamedOwn() ? Builtin::kDefineNamedOwnIC_NoFeedback
                                         : Builtin::kStoreIC_NoFeedback;
    TailCallBuiltin(builtin, p->context(), p->receiver(), p->name(),
                    p->value());
  }

  BIND(&miss);
  {
    auto runtime = p->IsDefineNamedOwn() ? Runtime::kDefineNamedOwnIC_Miss
                                         : Runtime::kStoreIC_Miss;
    TailCallRuntime(runtime, p->context(), p->value(), p->slot(), p->vector(),
                    p->receiver(), p->name());
  }
}

void AccessorAssembler::StoreGlobalIC(const StoreICParameters* pp) {
  Label no_feedback(this, Label::kDeferred), if_lexical_var(this),
      if_heapobject(this);
  GotoIf(IsUndefined(pp->vector()), &no_feedback);

  TNode<MaybeObject> maybe_weak_ref =
      LoadFeedbackVectorSlot(CAST(pp->vector()), pp->slot());
  Branch(TaggedIsSmi(maybe_weak_ref), &if_lexical_var, &if_heapobject);

  BIND(&if_heapobject);
  {
    Label try_handler(this), miss(this, Label::kDeferred);

    // This branch also handles the "handler mode": the weak reference is
    // cleared, the feedback extra is the handler. In that case we jump to
    // try_handler. (See FeedbackNexus::ConfigureHandlerMode.)
    CSA_DCHECK(this, IsWeakOrCleared(maybe_weak_ref));
    TNode<PropertyCell> property_cell =
        CAST(GetHeapObjectAssumeWeak(maybe_weak_ref, &try_handler));

    ExitPoint direct_exit(this);
    StoreGlobalIC_PropertyCellCase(property_cell, pp->value(), &direct_exit,
                                   &miss);

    BIND(&try_handler);
    {
      Comment("StoreGlobalIC_try_handler");
      TNode<MaybeObject> handler =
          LoadFeedbackVectorSlot(CAST(pp->vector()), pp->slot(), kTaggedSize);

      GotoIf(TaggedEqual(handler, UninitializedSymbolConstant()), &miss);

      DCHECK(pp->receiver_is_null());
      DCHECK(pp->flags_is_null());
      TNode<NativeContext> native_context = LoadNativeContext(pp->context());
      StoreICParameters p(
          pp->context(),
          LoadContextElement(native_context, Context::GLOBAL_PROXY_INDEX),
          pp->name(), pp->value(), std::nullopt, pp->slot(), pp->vector(),
          StoreICMode::kDefault);

      HandleStoreICHandlerCase(&p, handler, &miss, ICMode::kGlobalIC);
    }

    BIND(&miss);
    {
      TailCallRuntime(Runtime::kStoreGlobalIC_Miss, pp->context(), pp->value(),
                      pp->slot(), pp->vector(), pp->name());
    }
  }

  BIND(&if_lexical_var);
  {
    // This branch handles the "lexical variable mode": the feedback is a SMI
    // encoding the variable location. (See
    // FeedbackNexus::ConfigureLexicalVarMode.)
    Comment("Store lexical variable");
    TNode<IntPtrT> lexical_handler = SmiUntag(CAST(maybe_weak_ref));
    TNode<IntPtrT> context_index =
        Signed(DecodeWord<FeedbackNexus::ContextIndexBits>(lexical_handler));
    TNode<IntPtrT> slot_index =
        Signed(DecodeWord<FeedbackNexus::SlotIndexBits>(lexical_handler));
    TNode<Context> script_context =
        LoadScriptContext(pp->context(), context_index);
    StoreContextElementAndUpdateSideData(script_context, slot_index,
                                         pp->value());
    Return(pp->value());
  }

  BIND(&no_feedback);
  {
    TailCallRuntime(Runtime::kStoreGlobalICNoFeedback_Miss, pp->context(),
                    pp->value(), pp->name());
  }
}

void AccessorAssembler::StoreGlobalIC_PropertyCellCase(
    TNode<PropertyCell> property_cell, TNode<Object> value,
    ExitPoint* exit_point, Label* miss) {
  Comment("StoreGlobalIC_TryPropertyCellCase");

  // Load the payload of the global parameter cell. A hole indicates that
  // the cell has been invalidated and that the store must be handled by the
  // runtime.
  TNode<Object> cell_contents =
      LoadObjectField(property_cell, PropertyCell::kValueOffset);
  TNode<Int32T> details = LoadAndUntagToWord32ObjectField(
      property_cell, PropertyCell::kPropertyDetailsRawOffset);
  GotoIf(IsSetWord32(details, PropertyDetails::kAttributesReadOnlyMask), miss);
  CSA_DCHECK(this,
             Word32Equal(DecodeWord32<PropertyDetails::KindField>(details),
                         Int32Constant(static_cast<int>(PropertyKind::kData))));

  TNode<Uint32T> type =
      DecodeWord32<PropertyDetails::PropertyCellTypeField>(details);

  Label constant(this), store(this), not_smi(this);

  GotoIf(Word32Equal(type, Int32Constant(
                               static_cast<int>(PropertyCellType::kConstant))),
         &constant);
  CSA_DCHECK(this, IsNotAnyHole(cell_contents));

  GotoIf(Word32Equal(
             type, Int32Constant(static_cast<int>(PropertyCellType::kMutable))),
         &store);
  CSA_DCHECK(this,
             Word32Or(Word32Equal(type, Int32Constant(static_cast<int>(
                                            PropertyCellType::kConstantType))),
                      Word32Equal(type, Int32Constant(static_cast<int>(
                                            PropertyCellType::kUndefined)))));

  GotoIfNot(TaggedIsSmi(cell_contents), &not_smi);
  GotoIfNot(TaggedIsSmi(value), miss);
  Goto(&store);

  BIND(&not_smi);
  {
    GotoIf(TaggedIsSmi(value), miss);
    TNode<Map> expected_map = LoadMap(CAST(cell_contents));
    TNode<Map> map = LoadMap(CAST(value));
    GotoIfNot(TaggedEqual(expected_map, map), miss);
    Goto(&store);
  }

  BIND(&store);
  {
    StoreObjectField(property_cell, PropertyCell::kValueOffset, value);
    exit_point->Return(value);
  }

  BIND(&constant);
  {
    // Since |value| is never the hole, the equality check below also handles an
    // invalidated property cell correctly.
    CSA_DCHECK(this, IsNotAnyHole(value));
    GotoIfNot(TaggedEqual(cell_contents, value), miss);
    exit_point->Return(value);
  }
}

void AccessorAssembler::KeyedStoreIC(const StoreICParameters* p) {
  Label miss(this, Label::kDeferred);
  {
    TVARIABLE(MaybeObject, var_handler);

    Label if_handler(this, &var_handler),
        try_polymorphic(this, Label::kDeferred),
        try_megamorphic(this, Label::kDeferred),
        no_feedback(this, Label::kDeferred),
        try_polymorphic_name(this, Label::kDeferred);

    TNode<Map> receiver_map = LoadReceiverMap(p->receiver());
    GotoIf(IsDeprecatedMap(receiver_map), &miss);

    GotoIf(IsUndefined(p->vector()), &no_feedback);

    // Check monomorphic case.
    TNode<HeapObjectReference> weak_receiver_map = MakeWeak(receiver_map);
    TNode<HeapObjectReference> feedback =
        TryMonomorphicCase(p->slot(), CAST(p->vector()), weak_receiver_map,
                           &if_handler, &var_handler, &try_polymorphic);
    BIND(&if_handler);
    {
      Comment("KeyedStoreIC_if_handler");
      HandleStoreICHandlerCase(p, var_handler.value(), &miss,
                               ICMode::kNonGlobalIC, kSupportElements);
    }

    BIND(&try_polymorphic);
    TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
    {
      // CheckPolymorphic case.
      Comment("KeyedStoreIC_try_polymorphic");
      GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)),
                &try_megamorphic);
      HandlePolymorphicCase(weak_receiver_map, CAST(strong_feedback),
                            &if_handler, &var_handler, &miss);
    }

    BIND(&try_megamorphic);
    {
      // Check megamorphic case.
      Comment("KeyedStoreIC_try_megamorphic");
      Branch(TaggedEqual(strong_feedback, MegamorphicSymbolConstant()),
             &no_feedback, &try_polymorphic_name);
    }

    BIND(&no_feedback);
    {
      TailCallBuiltin(Builtin::kKeyedStoreIC_Megamorphic, p->context(),
                      p->receiver(), p->name(), p->value(), p->slot(),
                      p->vector());
    }

    BIND(&try_polymorphic_name);
    {
      // We might have a name in feedback, and a fixed array in the next slot.
      Comment("KeyedStoreIC_try_polymorphic_name");
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
    Comment("KeyedStoreIC_miss");
    TailCallRuntime(Runtime::kKeyedStoreIC_Miss, p->context(), p->value(),
                    p->slot(), p->vector(), p->receiver(), p->name());
  }
}

void AccessorAssembler::DefineKeyedOwnIC(const StoreICParameters* p) {
  Label miss(this, Label::kDeferred);
  {
    {
      // TODO(v8:13451): Port SetFunctionName to an ic so that we can remove
      // the runtime call here. Potentially we may also remove the
      // StoreICParameters flags and have builtins:kDefineKeyedOwnIC reusing
      // StoreWithVectorDescriptor again.
      Label did_set_function_name_if_needed(this);
      TNode<Int32T> needs_set_function_name = Word32And(
          SmiToInt32(p->flags()),
          Int32Constant(
              static_cast<int>(DefineKeyedOwnPropertyFlag::kSetFunctionName)));
      GotoIfNot(needs_set_function_name, &did_set_function_name_if_needed);

      Comment("DefineKeyedOwnIC_set_function_name");
      CallRuntime(Runtime::kSetFunctionName, p->context(), p->value(),
                  p->name());

      Goto(&did_set_function_name_if_needed);
      BIND(&did_set_function_name_if_needed);
    }
    TVARIABLE(MaybeObject, var_handler);

    Label if_handler(this, &var_handler),
        try_polymorphic(this, Label::kDeferred),
        try_megamorphic(this, Label::kDeferred),
        no_feedback(this, Label::kDeferred),
        try_polymorphic_name(this, Label::kDeferred);

    TNode<Map> receiver_map = LoadReceiverMap(p->receiver());
    GotoIf(IsDeprecatedMap(receiver_map), &miss);

    GotoIf(IsUndefined(p->vector()), &no_feedback);

    // Check monomorphic case.
    TNode<HeapObjectReference> weak_receiver_map = MakeWeak(receiver_map);
    TNode<HeapObjectReference> feedback =
        TryMonomorphicCase(p->slot(), CAST(p->vector()), weak_receiver_map,
                           &if_handler, &var_handler, &try_polymorphic);
    BIND(&if_handler);
    {
      Comment("DefineKeyedOwnIC_if_handler");
      HandleStoreICHandlerCase(p, var_handler.value(), &miss,
                               ICMode::kNonGlobalIC, kSupportElements);
    }

    BIND(&try_polymorphic);
    TNode<HeapObject> strong_feedback = GetHeapObjectIfStrong(feedback, &miss);
    {
      // CheckPolymorphic case.
      Comment("DefineKeyedOwnIC_try_polymorphic");
      GotoIfNot(IsWeakFixedArrayMap(LoadMap(strong_feedback)),
                &try_megamorphic);
      HandlePolymorphicCase(weak_receiver_map, CAST(strong_feedback),
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
"""


```