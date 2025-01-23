Response:
My thinking process to analyze the provided C++ code snippet and fulfill the user's request goes like this:

1. **Understand the Core Request:** The user wants to understand the functionality of the given C++ code from `v8/src/ic/accessor-assembler.cc`. They also want to know if it relates to JavaScript, see examples if it does, understand the logic with hypothetical inputs/outputs, and learn about common programming errors it might prevent or be related to. Crucially, they've specified this is part 5 of a 7-part series, so I need to focus on summarizing the *specific* functions within this snippet.

2. **Initial Code Scan and Function Identification:** I first scan the code to identify the distinct functions defined. These are:
    * `LoadIC`
    * `LoadIC_NoFeedback`
    * `LoadSuperIC_NoFeedback`
    * `LoadGlobalIC`
    * `LoadGlobalIC_TryPropertyCellCase`
    * `LoadGlobalIC_TryHandlerCase`
    * `ScriptContextTableLookup`
    * `LoadGlobalIC_NoFeedback` (overload)
    * `KeyedLoadIC`
    * `KeyedLoadICGeneric`
    * `KeyedLoadICPolymorphicName`
    * `StoreIC`
    * `StoreGlobalIC`
    * `StoreGlobalIC_PropertyCellCase`
    * `KeyedStoreIC`
    * `DefineKeyedOwnIC`

3. **Categorize Function Functionality:** I observe that many function names start with "LoadIC" or "StoreIC". This strongly suggests these functions are related to loading and storing properties in JavaScript, specifically within the context of Inline Caches (ICs). The "Keyed" prefix indicates operations on properties accessed using bracket notation (e.g., `obj[key]`). The "_NoFeedback" suffix implies versions that don't utilize feedback from previous executions for optimization. "GlobalIC" refers to operations on global variables.

4. **Analyze Individual Function Logic (High-Level):**  I go through each function and try to grasp its main purpose:

    * **`LoadIC`:**  Seems to handle loading properties with feedback, trying different optimization strategies (monomorphic, polymorphic, megamorphic).
    * **`LoadIC_NoFeedback`:** Loads properties without using feedback, with a special case for `Function.prototype`.
    * **`LoadSuperIC_NoFeedback`:** Similar to `LoadIC_NoFeedback` but for `super` calls.
    * **`LoadGlobalIC`:** Loads global variables, checking for feedback and handling different cases (property cells, lexical variables, handlers).
    * **`LoadGlobalIC_TryPropertyCellCase`:**  A helper for `LoadGlobalIC` specifically dealing with property cells.
    * **`LoadGlobalIC_TryHandlerCase`:** Another helper for `LoadGlobalIC`, handling cases with IC handlers.
    * **`ScriptContextTableLookup`:** Looks up variables in the script context, essential for resolving global variable references.
    * **`LoadGlobalIC_NoFeedback` (overload):**  A simpler version for global loads without feedback.
    * **`KeyedLoadIC`:** Loads properties using keys (bracket notation), again with different optimization paths.
    * **`KeyedLoadICGeneric`:**  A slower, more general fallback for keyed loads.
    * **`KeyedLoadICPolymorphicName`:** A specialized version for keyed loads when the name is already known and matches feedback.
    * **`StoreIC`:** Handles storing properties, similar to `LoadIC` with feedback mechanisms.
    * **`StoreGlobalIC`:** Stores values to global variables, managing property cells and lexical variables.
    * **`StoreGlobalIC_PropertyCellCase`:** Helper for `StoreGlobalIC` dealing with property cell updates.
    * **`KeyedStoreIC`:** Stores properties using keys, with feedback.
    * **`DefineKeyedOwnIC`:** Defines a new own property on an object using a key.

5. **Identify JavaScript Relevance:** The function names and the logic within them directly correspond to fundamental JavaScript operations: property access (both dot and bracket notation), global variable access, and property assignment. This strongly indicates a relationship with JavaScript execution.

6. **Construct JavaScript Examples:** Based on the function analysis, I create simple JavaScript code snippets that would trigger these IC mechanisms. For example, accessing a property like `obj.prop` would likely involve `LoadIC`, while `obj[key]` would involve `KeyedLoadIC`. Global variable access like `globalVar` would use `LoadGlobalIC`.

7. **Hypothesize Inputs and Outputs:** For a few key functions (like `LoadIC` and `KeyedLoadIC`), I consider hypothetical scenarios and predict the flow of execution and the output. This helps illustrate the conditional logic within the code.

8. **Identify Common Programming Errors:** I think about common JavaScript errors related to property access and assignment. `TypeError` when accessing properties of `null` or `undefined`, and `ReferenceError` when accessing undeclared variables are relevant here. The ICs are designed to optimize these operations but also handle these error conditions.

9. **Address the ".tq" Question:** I explicitly state that the code is C++ and not Torque (.tq).

10. **Synthesize the Summary:**  Based on the individual function analysis and categorization, I formulate a concise summary of the file's overall purpose, emphasizing its role in optimizing property access and assignment in V8.

11. **Structure the Output:** I organize the information clearly, addressing each part of the user's request (functionality, JavaScript relation, examples, logic, errors, summary, and the ".tq" point). I use headings and bullet points for readability.

12. **Review and Refine:** I review my analysis and examples to ensure accuracy and clarity. I make sure the summary effectively captures the essence of the code snippet. I also double-check that I've addressed the "part 5 of 7" aspect by focusing the summary on the specific functions present in *this* snippet.

This iterative process of scanning, analyzing, categorizing, creating examples, and summarizing allows me to effectively understand and explain the functionality of the given C++ code within the context of V8 and its relationship to JavaScript.
好的，这是对 `v8/src/ic/accessor-assembler.cc` 代码片段的功能分析：

**功能归纳（针对提供的代码片段）：**

这段代码是 V8 引擎中 `AccessorAssembler` 类的一部分，专门负责生成用于优化属性访问（包括读取和写入）的内联缓存 (Inline Cache, IC) 代码。它包含了一系列方法，用于处理不同场景下的属性访问，并尝试通过缓存之前的操作结果来加速后续的访问。

具体来说，这段代码的功能可以归纳为以下几点：

* **加载属性 (LoadIC)：** 包含多种 `LoadIC` 函数变体，用于处理不同类型的属性加载操作：
    * **带反馈的加载 (LoadIC)：**  利用反馈向量（Feedback Vector）中的信息来优化属性加载，尝试单态 (monomorphic)、多态 (polymorphic) 和巨态 (megamorphic) 的缓存策略。
    * **无反馈的加载 (LoadIC_NoFeedback, LoadSuperIC_NoFeedback)：**  在没有反馈信息的情况下执行属性加载，例如首次执行或某些特殊情况。
    * **全局加载 (LoadGlobalIC)：**  处理全局变量的加载，包括查找属性单元 (PropertyCell) 和处理作用域 (ScriptContextTable)。
    * **键式加载 (KeyedLoadIC)：**  处理使用方括号 `[]` 进行的属性加载，同样有带反馈和无反馈的版本，并考虑了不同的缓存策略。
* **存储属性 (StoreIC)：** 包含多种 `StoreIC` 函数变体，用于处理不同类型的属性存储操作：
    * **带反馈的存储 (StoreIC)：** 利用反馈向量优化属性存储，尝试单态、多态和巨态缓存。
    * **全局存储 (StoreGlobalIC)：** 处理全局变量的存储，包括更新属性单元和处理词法作用域变量。
    * **键式存储 (KeyedStoreIC)：** 处理使用方括号 `[]` 进行的属性存储，同样有带反馈的版本。
    * **定义键式自有属性 (DefineKeyedOwnIC)：**  处理使用 `Object.defineProperty()` 或类似方式定义的键式自有属性。
* **处理 IC 处理器 (HandleLoadICHandlerCase, HandleStoreICHandlerCase)：**  这些辅助函数用于处理反馈信息中存储的“处理器”（handler），这些处理器包含了之前成功执行的属性访问的信息，用于指导当前的访问。
* **查找作用域 (ScriptContextTableLookup)：**  用于在脚本上下文表中查找变量，这对于解析全局变量至关重要。
* **尝试缓存 (TryProbeStubCache, TryMonomorphicCase, HandlePolymorphicCase)：**  代码中多次出现尝试不同缓存策略的逻辑，例如尝试在桩缓存 (StubCache) 中查找，或者检查是否可以应用单态或多态优化。

**关于 `.tq` 扩展名：**

这段代码确实是 `.cc` 文件，所以它不是 Torque 源代码。如果 `v8/src/ic/accessor-assembler.cc` 以 `.tq` 结尾，那么它会是 Torque 源代码。Torque 是一种用于 V8 内部实现的领域特定语言，用于生成高效的 C++ 代码。

**与 JavaScript 的关系 (及其示例)：**

这段代码直接关系到 JavaScript 的属性访问操作。每当你尝试在 JavaScript 中读取或写入一个对象的属性，V8 引擎的 IC 机制就会尝试优化这个操作。

**JavaScript 示例：**

```javascript
// 假设有一个对象
const obj = { a: 1, b: 2 };

// 读取属性 'a' (可能触发 LoadIC)
const valueA = obj.a;

// 读取属性 'c'，对象上不存在 (可能触发 LoadIC 的 miss 分支)
const valueC = obj.c;

// 使用键式访问读取属性 'b' (可能触发 KeyedLoadIC)
const key = 'b';
const valueB = obj[key];

// 设置属性 'c' (可能触发 StoreIC)
obj.c = 3;

// 使用键式访问设置属性 'd' (可能触发 KeyedStoreIC)
const keyD = 'd';
obj[keyD] = 4;

// 访问全局变量 (可能触发 LoadGlobalIC)
console.log(window.location);

// 修改全局变量 (可能触发 StoreGlobalIC)
window.myGlobal = 5;

// 使用 Object.defineProperty 定义属性 (可能触发 DefineKeyedOwnIC)
Object.defineProperty(obj, 'e', {
  value: 6,
  writable: false,
  enumerable: true,
  configurable: false
});
```

**代码逻辑推理（假设输入与输出）：**

**示例：`LoadIC` 函数 - 单态场景**

**假设输入：**

* `p->lookup_start_object()`: 一个具有特定 Map 的对象 `obj1 = { x: 1 }`。
* `p->name()`: 字符串 "x"。
* `p->vector()`: 一个反馈向量，其中 `p->slot()` 位置存储了与 `obj1` 的 Map 相关的单态反馈信息（例如，指向 `obj1` 的 Map 的弱引用）。

**预期输出：**

1. 代码会首先检查反馈向量中的信息。
2. `TryMonomorphicCase` 会成功匹配到存储的 Map 和当前对象的 Map。
3. 代码会跳转到 `if_handler` 分支（如果反馈信息中包含 handler，可能用于处理 getter/setter）。
4. 如果没有 handler，则很可能直接从对象的属性中加载值 `1` 并返回。

**示例：`KeyedLoadIC` 函数 - 缓存未命中**

**假设输入：**

* `p->receiver_and_lookup_start_object()`: 对象 `obj = { a: 1 }`。
* `p->name()`: 字符串 "b"。
* `p->vector()`: 一个反馈向量，没有关于键 "b" 的缓存信息。

**预期输出：**

1. 由于反馈向量中没有关于键 "b" 的信息，单态和多态的尝试都会失败。
2. 代码会最终跳转到 `miss` 分支。
3. 在 `miss` 分支中，会调用运行时函数 `Runtime::kKeyedLoadIC_Miss`，这会导致更慢的属性查找过程，并可能更新反馈向量以记录这次未命中的信息，以便未来优化。

**用户常见的编程错误：**

这段代码主要在 V8 内部工作，用户通常不会直接与之交互。然而，它所优化的操作与一些常见的 JavaScript 编程错误相关：

1. **访问 `null` 或 `undefined` 的属性：**
   ```javascript
   let myVar = null;
   console.log(myVar.someProperty); // TypeError: Cannot read properties of null (reading 'someProperty')
   ```
   虽然 IC 不会阻止这种错误发生，但 V8 的属性访问机制（IC 在其中起关键作用）会检测到 `null` 或 `undefined` 并抛出 `TypeError`。代码中的 `GotoIf(TaggedIsSmi(lookup_start_object), &miss);` 和 `GotoIf(IsNullOrUndefined(lookup_start_object), &if_runtime);` 等检查，在更底层的层面处理了类似的情况。

2. **访问未定义的变量（全局变量）：**
   ```javascript
   console.log(nonExistentVariable); // ReferenceError: nonExistentVariable is not defined
   ```
   `LoadGlobalIC` 及其相关的查找机制负责处理全局变量的访问。如果全局变量不存在，最终会触发 `ReferenceError`。代码中的 `ScriptContextTableLookup` 尝试在作用域链中查找变量，如果找不到则会进入 `miss` 分支，最终可能导致运行时抛出错误。

3. **拼写错误的属性名：**
   ```javascript
   const obj = { myProperty: 1 };
   console.log(obj.myProprty); // 输出 undefined
   ```
   IC 可能会缓存对拼写错误的属性的查找失败，从而在后续访问时更快地返回 `undefined`。

4. **对只读属性进行赋值：**
   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'readonly', { value: 1, writable: false });
   obj.readonly = 2; // 严格模式下会抛出 TypeError，非严格模式下赋值静默失败
   ```
   `StoreIC` 和 `StoreGlobalIC_PropertyCellCase` 中检查属性的 `PropertyDetails`，包括是否只读，从而决定是否允许赋值。

**总结 `v8/src/ic/accessor-assembler.cc` 的功能 (针对提供的代码片段作为第 5 部分)：**

作为第 5 部分，这段代码集中展示了 `AccessorAssembler` 中用于生成 **加载 (Load) 和存储 (Store) 属性的 IC 代码** 的核心逻辑。它详细展示了 V8 如何区分带反馈和无反馈的场景，以及如何尝试不同的缓存策略（单态、多态、巨态）来优化属性访问。此外，它还包含了处理全局变量访问和键式属性访问的特定逻辑。

总而言之，这段代码是 V8 引擎中至关重要的性能优化部分，它通过动态生成和利用内联缓存，显著提高了 JavaScript 属性访问的速度。

### 提示词
```
这是目录为v8/src/ic/accessor-assembler.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/accessor-assembler.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第5部分，共7部分，请归纳一下它的功能
```

### 源代码
```cpp
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
```