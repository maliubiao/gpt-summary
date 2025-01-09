Response:
Let's break down the thought process to analyze the provided C++ code snippet.

**1. Initial Understanding and Context:**

* **File Path:** `v8/src/builtins/builtins-internal-gen.cc`. This immediately tells us it's part of V8's internals, specifically related to built-in functions. The `gen` suffix suggests it might be generated code or involved in code generation.
* **Keywords:**  `builtins`, `internal`, `gen`. These confirm the file's purpose: implementing core JavaScript functionalities within V8.
* **"Part 2 of 3":**  This is a crucial hint. The functionality is likely spread across multiple files. This part likely handles a specific set of related operations.

**2. High-Level Structure and Key Classes:**

* **`DeletePropertyBaseAssembler`:** This class suggests functionality related to deleting properties. The `TF_BUILTIN` macro indicates this class is used to define a Torque built-in function named `DeleteProperty`.
* **`SetOrCopyDataPropertiesAssembler`:** This class seems to handle setting or copying properties, likely for operations like `Object.assign()` or object literals. The `TF_BUILTIN` macros define Torque built-ins related to this: `CopyDataPropertiesWithExcludedPropertiesOnStack`, `CopyDataPropertiesWithExcludedProperties`, `CopyDataProperties`, and `SetDataProperties`.
* **`CodeStubAssembler`:**  This is a general-purpose class for building built-in functions in V8 using Torque. Many of the `TF_BUILTIN` declarations use it directly.
* **`CppBuiltinsAdaptorAssembler`:** This class appears to be involved in adapting C++ functions for use as JavaScript built-ins.

**3. Deeper Dive into Functionality - `DeletePropertyBaseAssembler`:**

* **`DictionaryShrink`:**  This function aims to optimize dictionary-based property storage by shrinking the underlying dictionary if it becomes too sparse after deletions. It checks the ratio of used slots to capacity.
* **`DictionarySpecificDelete`:** This function handles the actual deletion of a property from a dictionary (likely a `SwissNameDictionary`, a more optimized dictionary implementation).
* **`DeleteDictionaryProperty`:** This function combines lookup and deletion for dictionary properties, also checking the "don't delete" attribute.
* **`TF_BUILTIN(DeleteProperty, DeletePropertyBaseAssembler)`:** This is the main built-in function for `delete obj.prop`. It handles different property types (indexed, named, etc.), fast vs. slow properties, and proxies. The logic includes checks for dictionary mode and calls the dictionary-specific deletion functions.

**4. Deeper Dive into Functionality - `SetOrCopyDataPropertiesAssembler`:**

* **`AllocateJsObjectTarget`:**  Helper to create a plain JavaScript object.
* **`SetOrCopyDataProperties`:**  The core function. It handles copying properties from a source to a target. It differentiates between regular objects and strings (which are treated as iterable sequences of characters). It also manages excluded properties. The `use_set` boolean likely distinguishes between creating new properties and potentially overwriting existing ones.
* **`TF_BUILTIN` functions related to `SetOrCopyDataPropertiesAssembler`:** These implement different variations of property copying, including those that handle excluded properties provided on the stack or as arguments.

**5. Deeper Dive into Functionality - Other `TF_BUILTIN`s:**

* **`ForInEnumerate`, `ForInPrepare`, `ForInFilter`:** These clearly relate to the `for...in` loop.
* **`SameValue`, `SameValueNumbersOnly`:** Implementations of the `Object.is()` and related abstract equality comparisons.
* **`CppBuiltinsAdaptorAssembler` and its `TF_BUILTIN`s (`AdaptorWithBuiltinExitFrame*`)**: These create adapter functions that bridge C++ functions into the V8 built-in system, handling argument passing and stack frames.
* **`NewHeapNumber`, `AllocateInYoungGeneration`, `AllocateInOldGeneration`, `WasmAllocateInYoungGeneration`, `WasmAllocateInOldGeneration`:**  Memory allocation related functions.
* **`Abort`, `AbortCSADcheck`:** Functions for triggering runtime errors or assertions.
* **`GetProperty`, `GetPropertyWithReceiver`:** Implementations of the object property access (the `.` operator or bracket notation).
* **`SetProperty`:** Implementation of object property assignment.
* **`CreateDataProperty`:** A specialized version of property creation, often used during object initialization.
* **`InstantiateAsmJs`:** Deals with the instantiation of WebAssembly (specifically the older asm.js subset).

**6. Identifying JavaScript Relationships and Examples:**

Throughout the analysis, it becomes clear how these C++ functions relate to JavaScript features. For example:

* `DeleteProperty` maps directly to the `delete` operator.
* `CopyDataProperties` is used by `Object.assign()`.
* `SetDataProperties` is used when creating object literals or setting properties directly.
* `ForInEnumerate`, etc., relate to the `for...in` loop.
* `SameValue` and `SameValueNumbersOnly` relate to `Object.is()` and abstract equality.
* `GetProperty` and `GetPropertyWithReceiver` are used for property access (`obj.prop` or `obj['prop']`).
* `SetProperty` is used for property assignment (`obj.prop = value`).
* `CreateDataProperty` is involved in object literal creation.

**7. Code Logic Inference and Examples:**

For functions like `DictionaryShrink`, we can infer the input and output:

* **Input:** A `NameDictionary` object and the new number of properties.
* **Output:** Potentially a new, smaller `NameDictionary` if shrinking is needed, or the original dictionary if not.

**8. Common Programming Errors:**

Relating the code to common errors is also possible:

* The `DeleteProperty` code handles the "don't delete" attribute, which is relevant when users try to delete non-configurable properties (e.g., properties of the global object in strict mode).
* The `SetOrCopyDataProperties` code implicitly relates to errors when trying to assign to read-only properties or properties of non-extensible objects.

**9. Iterative Refinement:**

The analysis isn't necessarily linear. We might jump between looking at function names, examining the code inside, and then thinking about the corresponding JavaScript behavior. If something isn't clear initially, we revisit the code or look for related functions. The `Label` constructs in the code are hints about conditional execution and different paths within the functions.

**10. Addressing the Specific Prompt Questions:**

Finally, after understanding the code, we can address the prompt's questions directly:

* **Functionality Listing:** Summarize the purpose of each significant function or class.
* **Torque Source:**  Check if the file name ends with `.tq` (it doesn't).
* **JavaScript Relationship and Examples:** Provide concrete JavaScript examples for the identified functionalities.
* **Code Logic Inference:**  Describe the input and output for key logical blocks.
* **Common Programming Errors:**  Relate the code to potential errors users might encounter.
* **Overall Functionality (Part 2):** Synthesize the information to provide a concise summary of what this specific part of the file handles. In this case, it appears to focus on property manipulation (deletion, copying, setting), comparisons, and some lower-level built-in infrastructure.
好的，这是对提供的V8源代码片段（`v8/src/builtins/builtins-internal-gen.cc` 的一部分）的功能归纳：

**核心功能归纳（基于提供的代码片段）：**

这段代码主要定义了 V8 引擎内部使用的一些内置函数（built-ins），这些函数是用 Torque 语言编写并生成为 C++ 代码的。  它集中在以下几个关键领域：

1. **属性删除 (Property Deletion):**  实现了 JavaScript 中 `delete` 操作符的功能，特别是针对不同类型的对象和属性存储方式（例如，字典模式）。

2. **属性复制与设置 (Property Copying and Setting):**  实现了将一个对象的属性复制到另一个对象的功能，对应于 `Object.assign()` 以及对象字面量赋值等操作。  也包括设置数据属性的特定场景。

3. **`for...in` 循环支持:**  提供了支持 JavaScript `for...in` 循环的关键内置函数，包括枚举属性、准备迭代器和过滤属性。

4. **值比较 (Value Comparison):**  实现了 JavaScript 中的 `Object.is()` 方法，用于判断两个值是否严格相等（包括对 `NaN` 和 `+/-0` 的特殊处理）。

5. **C++ 内置函数适配器 (C++ Built-in Adaptors):**  提供了一种机制，可以将 C++ 函数适配为 V8 的内置函数，方便在 JavaScript 中调用 C++ 代码。

6. **内存分配 (Memory Allocation):**  包含用于在新生代和老生代堆中分配内存的内置函数。

7. **错误处理 (Error Handling):**  提供了 `Abort` 和 `AbortCSADcheck` 等内置函数，用于触发 V8 引擎的错误或断言失败。

8. **属性获取 (Property Getting):** 实现了 JavaScript 中属性访问（`.` 操作符和 `[]` 操作符）的功能，包括在原型链上查找属性。

9. **属性设置 (Property Setting):** 实现了 JavaScript 中属性赋值操作。

10. **WebAssembly 支持 (部分):**  包含与 WebAssembly 实例化相关的内置函数 (`InstantiateAsmJs`) 和 WebAssembly 特定的内存分配函数。

**详细功能分解和 JavaScript 示例：**

**1. 属性删除 (Property Deletion):**

* **功能:**  `DeleteProperty` 内置函数实现了 JavaScript 中 `delete` 操作符的功能。它会检查属性是否存在，是否可配置，然后执行删除操作。对于字典模式的对象，会进行优化，例如在删除后可能收缩字典大小。
* **JavaScript 示例:**
   ```javascript
   const obj = { a: 1, b: 2 };
   delete obj.a;
   console.log(obj.a); // 输出: undefined

   const nonConfigurable = {};
   Object.defineProperty(nonConfigurable, 'c', {
       value: 3,
       configurable: false
   });
   delete nonConfigurable.c; // 在严格模式下会报错，非严格模式下返回 false
   console.log(nonConfigurable.c); // 输出: 3
   ```
* **代码逻辑推理:**
    * **假设输入:** 一个 JavaScript 对象 `receiver` 和要删除的属性键 `key`。
    * **输出:** 如果成功删除，通常返回 `true`，否则根据语言模式可能返回 `false` 或抛出错误。
* **常见编程错误:** 尝试删除不可配置的属性。

**2. 属性复制与设置 (Property Copying and Setting):**

* **功能:** `CopyDataProperties` 和 `SetDataProperties` 用于将一个对象的属性复制到另一个对象。`CopyDataProperties` 对应 `Object.assign()`，而 `SetDataProperties` 用于更底层的属性设置。代码中还处理了排除特定属性的场景。
* **JavaScript 示例:**
   ```javascript
   const source = { x: 10, y: 20 };
   const target = { a: 1 };

   Object.assign(target, source);
   console.log(target); // 输出: { a: 1, x: 10, y: 20 }

   const obj = {};
   obj.name = "example"; // SetDataProperties 的一种体现
   ```
* **代码逻辑推理:**
    * **假设输入 (CopyDataProperties):** 目标对象 `target` 和源对象 `source`。
    * **输出:**  `target` 对象会被修改，包含 `source` 对象的属性。
* **常见编程错误:**  尝试复制到不可写或不可扩展的对象可能会失败或抛出错误。

**3. `for...in` 循环支持:**

* **功能:** `ForInEnumerate`, `ForInPrepare`, `ForInFilter` 等内置函数共同实现了 `for...in` 循环的逻辑，包括获取可枚举的属性、准备迭代和过滤继承来的属性。
* **JavaScript 示例:**
   ```javascript
   const obj = { a: 1, b: 2 };
   for (let key in obj) {
       console.log(key); // 输出: "a", "b"
   }
   ```

**4. 值比较 (Value Comparison):**

* **功能:** `SameValue` 和 `SameValueNumbersOnly` 实现了 JavaScript 的严格相等比较，`SameValue` 对应 `Object.is()`。
* **JavaScript 示例:**
   ```javascript
   console.log(Object.is(1, 1));        // true
   console.log(Object.is(NaN, NaN));    // true
   console.log(Object.is(+0, -0));      // false

   console.log(1 === 1);              // true
   console.log(NaN === NaN);          // false
   console.log(+0 === -0);            // true
   ```

**5. C++ 内置函数适配器:**

* **功能:** `CppBuiltinsAdaptorAssembler` 提供了一种将 C++ 函数包装成可以在 JavaScript 中调用的内置函数的方法。这涉及到参数处理、调用 C++ 函数以及处理返回值。

**6. 内存分配:**

* **功能:** `AllocateInYoungGeneration` 和 `AllocateInOldGeneration` 用于在 V8 的堆内存中分配对象。

**7. 错误处理:**

* **功能:** `Abort` 和 `AbortCSADcheck` 用于在内部触发错误，通常用于调试或在出现不可恢复的错误时终止执行。

**8. 属性获取:**

* **功能:** `GetProperty` 和 `GetPropertyWithReceiver` 实现了属性访问的逻辑，包括查找自有属性和在原型链上查找。
* **JavaScript 示例:**
   ```javascript
   const obj = { x: 1 };
   console.log(obj.x);       // 使用 GetProperty
   console.log(obj['x']);    // 使用 GetProperty

   const proto = { y: 2 };
   const child = Object.create(proto);
   console.log(child.y);    // GetProperty 会在原型链上查找
   ```

**9. 属性设置:**

* **功能:** `SetProperty` 实现了属性赋值的逻辑。
* **JavaScript 示例:**
   ```javascript
   const obj = {};
   obj.name = "test"; // 使用 SetProperty
   obj['value'] = 100; // 使用 SetProperty
   ```

**10. WebAssembly 支持:**

* **功能:** `InstantiateAsmJs` 负责实例化 asm.js 模块。`WasmAllocateInYoungGeneration` 和 `WasmAllocateInOldGeneration` 是 WebAssembly 专用的内存分配函数。

**总结:**

这段 `builtins-internal-gen.cc` 代码片段是 V8 引擎中实现核心 JavaScript 功能的关键部分，它使用 Torque 语言定义了用于属性操作（删除、复制、设置、获取）、循环控制、值比较、内存管理以及 WebAssembly 支持的底层内置函数。这些内置函数是 V8 执行 JavaScript 代码的基础。

由于这是第 2 部分，可以推测第 1 部分可能包含其他类型的内置函数定义，而第 3 部分可能会处理更多的复杂逻辑或者与其他 V8 内部组件的交互。

Prompt: 
```
这是目录为v8/src/builtins/builtins-internal-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-internal-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能

"""
Label shrinking_done(this);
    TNode<Smi> capacity = GetCapacity<NameDictionary>(properties);
    GotoIf(SmiGreaterThan(new_nof, SmiShr(capacity, 2)), &shrinking_done);
    GotoIf(SmiLessThan(new_nof, SmiConstant(16)), &shrinking_done);

    TNode<NameDictionary> new_properties =
        CAST(CallRuntime(Runtime::kShrinkNameDictionary, context, properties));

    StoreJSReceiverPropertiesOrHash(receiver, new_properties);

    Goto(&shrinking_done);
    BIND(&shrinking_done);
  }

  void DictionarySpecificDelete(TNode<JSReceiver> receiver,
                                TNode<SwissNameDictionary> properties,
                                TNode<IntPtrT> key_index,
                                TNode<Context> context) {
    Label shrunk(this), done(this);
    TVARIABLE(SwissNameDictionary, shrunk_table);

    SwissNameDictionaryDelete(properties, key_index, &shrunk, &shrunk_table);
    Goto(&done);
    BIND(&shrunk);
    StoreJSReceiverPropertiesOrHash(receiver, shrunk_table.value());
    Goto(&done);

    BIND(&done);
  }

  template <typename Dictionary>
  void DeleteDictionaryProperty(TNode<JSReceiver> receiver,
                                TNode<Dictionary> properties, TNode<Name> name,
                                TNode<Context> context, Label* dont_delete,
                                Label* notfound) {
    TVARIABLE(IntPtrT, var_name_index);
    Label dictionary_found(this, &var_name_index);
    NameDictionaryLookup<Dictionary>(properties, name, &dictionary_found,
                                     &var_name_index, notfound);

    BIND(&dictionary_found);
    TNode<IntPtrT> key_index = var_name_index.value();
    TNode<Uint32T> details = LoadDetailsByKeyIndex(properties, key_index);
    GotoIf(IsSetWord32(details, PropertyDetails::kAttributesDontDeleteMask),
           dont_delete);

    DictionarySpecificDelete(receiver, properties, key_index, context);

    Return(TrueConstant());
  }
};

TF_BUILTIN(DeleteProperty, DeletePropertyBaseAssembler) {
  auto receiver = Parameter<Object>(Descriptor::kObject);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto language_mode = Parameter<Smi>(Descriptor::kLanguageMode);
  auto context = Parameter<Context>(Descriptor::kContext);

  TVARIABLE(IntPtrT, var_index);
  TVARIABLE(Name, var_unique);
  Label if_index(this, &var_index), if_unique_name(this), if_notunique(this),
      if_notfound(this), slow(this), if_proxy(this);

  GotoIf(TaggedIsSmi(receiver), &slow);
  TNode<Map> receiver_map = LoadMap(CAST(receiver));
  TNode<Uint16T> instance_type = LoadMapInstanceType(receiver_map);
  GotoIf(InstanceTypeEqual(instance_type, JS_PROXY_TYPE), &if_proxy);
  GotoIf(IsCustomElementsReceiverInstanceType(instance_type), &slow);
  TryToName(key, &if_index, &var_index, &if_unique_name, &var_unique, &slow,
            &if_notunique);

  BIND(&if_index);
  {
    Comment("integer index");
    Goto(&slow);  // TODO(jkummerow): Implement more smarts here.
  }

  BIND(&if_unique_name);
  {
    Comment("key is unique name");
    CheckForAssociatedProtector(var_unique.value(), &slow);

    Label dictionary(this), dont_delete(this);
    GotoIf(IsDictionaryMap(receiver_map), &dictionary);

    // Fast properties need to clear recorded slots and mark the deleted
    // property as mutable, which can only be done in C++.
    Goto(&slow);

    BIND(&dictionary);
    {
      InvalidateValidityCellIfPrototype(receiver_map);

      TNode<PropertyDictionary> properties =
          CAST(LoadSlowProperties(CAST(receiver)));
      DeleteDictionaryProperty(CAST(receiver), properties, var_unique.value(),
                               context, &dont_delete, &if_notfound);
    }

    BIND(&dont_delete);
    {
      static_assert(LanguageModeSize == 2);
      GotoIf(SmiNotEqual(language_mode, SmiConstant(LanguageMode::kSloppy)),
             &slow);
      Return(FalseConstant());
    }
  }

  BIND(&if_notunique);
  {
    // If the string was not found in the string table, then no object can
    // have a property with that name.
    TryInternalizeString(CAST(key), &if_index, &var_index, &if_unique_name,
                         &var_unique, &if_notfound, &slow);
  }

  BIND(&if_notfound);
  Return(TrueConstant());

  BIND(&if_proxy);
  {
    TNode<Name> name = CAST(CallBuiltin(Builtin::kToName, context, key));
    GotoIf(IsPrivateSymbol(name), &slow);
    TailCallBuiltin(Builtin::kProxyDeleteProperty, context, receiver, name,
                    language_mode);
  }

  BIND(&slow);
  {
    TailCallRuntime(Runtime::kDeleteProperty, context, receiver, key,
                    language_mode);
  }
}

namespace {

class SetOrCopyDataPropertiesAssembler : public CodeStubAssembler {
 public:
  explicit SetOrCopyDataPropertiesAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

 protected:
  TNode<JSObject> AllocateJsObjectTarget(TNode<Context> context) {
    const TNode<NativeContext> native_context = LoadNativeContext(context);
    const TNode<JSFunction> object_function = Cast(
        LoadContextElement(native_context, Context::OBJECT_FUNCTION_INDEX));
    const TNode<Map> map =
        Cast(LoadJSFunctionPrototypeOrInitialMap(object_function));
    const TNode<JSObject> target = AllocateJSObjectFromMap(map);
    return target;
  }
  TNode<Object> SetOrCopyDataProperties(
      TNode<Context> context, TNode<JSReceiver> target, TNode<Object> source,
      Label* if_runtime,
      std::optional<TNode<IntPtrT>> excluded_property_count = std::nullopt,
      std::optional<TNode<IntPtrT>> excluded_property_base = std::nullopt,
      bool use_set = true) {
    Label if_done(this), if_noelements(this),
        if_sourcenotjsobject(this, Label::kDeferred);

    // JSPrimitiveWrapper wrappers for numbers don't have any enumerable own
    // properties, so we can immediately skip the whole operation if {source} is
    // a Smi.
    GotoIf(TaggedIsSmi(source), &if_done);

    // Otherwise check if {source} is a proper JSObject, and if not, defer
    // to testing for non-empty strings below.
    TNode<Map> source_map = LoadMap(CAST(source));
    TNode<Uint16T> source_instance_type = LoadMapInstanceType(source_map);
    GotoIfNot(IsJSObjectInstanceType(source_instance_type),
              &if_sourcenotjsobject);

    TNode<FixedArrayBase> source_elements = LoadElements(CAST(source));
    GotoIf(IsEmptyFixedArray(source_elements), &if_noelements);
    Branch(IsEmptySlowElementDictionary(source_elements), &if_noelements,
           if_runtime);

    BIND(&if_noelements);
    {
      // If the target is deprecated, the object will be updated on first
      // store. If the source for that store equals the target, this will
      // invalidate the cached representation of the source. Handle this case
      // in runtime.
      TNode<Map> target_map = LoadMap(target);
      GotoIf(IsDeprecatedMap(target_map), if_runtime);
      if (use_set) {
        TNode<BoolT> target_is_simple_receiver = IsSimpleObjectMap(target_map);
        ForEachEnumerableOwnProperty(
            context, source_map, CAST(source), kEnumerationOrder,
            [=, this](TNode<Name> key, LazyNode<Object> value) {
              KeyedStoreGenericGenerator::SetProperty(
                  state(), context, target, target_is_simple_receiver, key,
                  value(), LanguageMode::kStrict);
            },
            if_runtime);
      } else {
        ForEachEnumerableOwnProperty(
            context, source_map, CAST(source), kEnumerationOrder,
            [=, this](TNode<Name> key, LazyNode<Object> value) {
              Label skip(this);
              if (excluded_property_count.has_value()) {
                BuildFastLoop<IntPtrT>(
                    IntPtrConstant(0), excluded_property_count.value(),
                    [&](TNode<IntPtrT> index) {
                      auto offset = Signed(TimesSystemPointerSize(index));
                      TNode<IntPtrT> location = Signed(
                          IntPtrSub(excluded_property_base.value(), offset));
                      auto property = LoadFullTagged(location);

                      Label continue_label(this);
                      BranchIfSameValue(key, property, &skip, &continue_label);
                      Bind(&continue_label);
                    },
                    1, LoopUnrollingMode::kNo, IndexAdvanceMode::kPost);
              }

              CallBuiltin(Builtin::kCreateDataProperty, context, target, key,
                          value());
              Goto(&skip);
              Bind(&skip);
            },
            if_runtime);
      }
      Goto(&if_done);
    }

    BIND(&if_sourcenotjsobject);
    {
      // Handle other JSReceivers in the runtime.
      GotoIf(IsJSReceiverInstanceType(source_instance_type), if_runtime);

      // Non-empty strings are the only non-JSReceivers that need to be
      // handled explicitly by Object.assign() and CopyDataProperties.
      GotoIfNot(IsStringInstanceType(source_instance_type), &if_done);
      TNode<Uint32T> source_length = LoadStringLengthAsWord32(CAST(source));
      Branch(Word32Equal(source_length, Uint32Constant(0)), &if_done,
             if_runtime);
    }

    BIND(&if_done);
    return target;
  }
};

}  // namespace

TF_BUILTIN(CopyDataPropertiesWithExcludedPropertiesOnStack,
           SetOrCopyDataPropertiesAssembler) {
  auto source = UncheckedParameter<Object>(Descriptor::kSource);
  auto excluded_property_count =
      UncheckedParameter<IntPtrT>(Descriptor::kExcludedPropertyCount);
  auto excluded_properties =
      UncheckedParameter<IntPtrT>(Descriptor::kExcludedPropertyBase);
  auto context = Parameter<Context>(Descriptor::kContext);

  // first check undefine or null
  Label if_runtime(this, Label::kDeferred);
  GotoIf(IsNullOrUndefined(source), &if_runtime);

  TNode<JSReceiver> target = AllocateJsObjectTarget(context);
  Return(SetOrCopyDataProperties(context, target, source, &if_runtime,
                                 excluded_property_count, excluded_properties,
                                 false));

  BIND(&if_runtime);
  // The excluded_property_base is passed as a raw stack pointer, but is
  // bitcasted to a Smi . This is safe because the stack pointer is aligned, so
  // it looks like a Smi to the GC.
  CSA_DCHECK(this, IntPtrEqual(WordAnd(excluded_properties,
                                       IntPtrConstant(kSmiTagMask)),
                               IntPtrConstant(kSmiTag)));
  TailCallRuntime(Runtime::kCopyDataPropertiesWithExcludedPropertiesOnStack,
                  context, source, SmiTag(excluded_property_count),
                  BitcastWordToTaggedSigned(excluded_properties));
}

TF_BUILTIN(CopyDataPropertiesWithExcludedProperties,
           SetOrCopyDataPropertiesAssembler) {
  auto source = UncheckedParameter<Object>(Descriptor::kSource);

  auto excluded_property_count_smi =
      UncheckedParameter<Smi>(Descriptor::kExcludedPropertyCount);
  auto context = Parameter<Context>(Descriptor::kContext);

  auto excluded_property_count = SmiToIntPtr(excluded_property_count_smi);
  CodeStubArguments arguments(this, excluded_property_count);

  TNode<IntPtrT> excluded_properties =
      ReinterpretCast<IntPtrT>(arguments.AtIndexPtr(
          IntPtrSub(excluded_property_count, IntPtrConstant(2))));

  arguments.PopAndReturn(CallBuiltin(
      Builtin::kCopyDataPropertiesWithExcludedPropertiesOnStack, context,
      source, excluded_property_count, excluded_properties));
}

// ES #sec-copydataproperties
TF_BUILTIN(CopyDataProperties, SetOrCopyDataPropertiesAssembler) {
  auto target = Parameter<JSObject>(Descriptor::kTarget);
  auto source = Parameter<Object>(Descriptor::kSource);
  auto context = Parameter<Context>(Descriptor::kContext);

  CSA_DCHECK(this, TaggedNotEqual(target, source));

  Label if_runtime(this, Label::kDeferred);
  SetOrCopyDataProperties(context, target, source, &if_runtime, std::nullopt,
                          std::nullopt, false);
  Return(UndefinedConstant());

  BIND(&if_runtime);
  TailCallRuntime(Runtime::kCopyDataProperties, context, target, source);
}

TF_BUILTIN(SetDataProperties, SetOrCopyDataPropertiesAssembler) {
  auto target = Parameter<JSReceiver>(Descriptor::kTarget);
  auto source = Parameter<Object>(Descriptor::kSource);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label if_runtime(this, Label::kDeferred);
  GotoIfForceSlowPath(&if_runtime);
  SetOrCopyDataProperties(context, target, source, &if_runtime, std::nullopt,
                          std::nullopt, true);
  Return(UndefinedConstant());

  BIND(&if_runtime);
  TailCallRuntime(Runtime::kSetDataProperties, context, target, source);
}

TF_BUILTIN(ForInEnumerate, CodeStubAssembler) {
  auto receiver = Parameter<JSReceiver>(Descriptor::kReceiver);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label if_empty(this), if_runtime(this, Label::kDeferred);
  TNode<Map> receiver_map = CheckEnumCache(receiver, &if_empty, &if_runtime);
  Return(receiver_map);

  BIND(&if_empty);
  Return(EmptyFixedArrayConstant());

  BIND(&if_runtime);
  TailCallRuntime(Runtime::kForInEnumerate, context, receiver);
}

TF_BUILTIN(ForInPrepare, CodeStubAssembler) {
  // The {enumerator} is either a Map or a FixedArray.
  auto enumerator = Parameter<HeapObject>(Descriptor::kEnumerator);
  auto index = Parameter<TaggedIndex>(Descriptor::kVectorIndex);
  auto feedback_vector = Parameter<FeedbackVector>(Descriptor::kFeedbackVector);
  TNode<UintPtrT> vector_index = Unsigned(TaggedIndexToIntPtr(index));

  TNode<FixedArray> cache_array;
  TNode<Smi> cache_length;
  ForInPrepare(enumerator, vector_index, feedback_vector, &cache_array,
               &cache_length, UpdateFeedbackMode::kGuaranteedFeedback);
  Return(cache_array, cache_length);
}

TF_BUILTIN(ForInFilter, CodeStubAssembler) {
  auto key = Parameter<String>(Descriptor::kKey);
  auto object = Parameter<HeapObject>(Descriptor::kObject);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label if_true(this), if_false(this);
  TNode<Oddball> result = HasProperty(context, object, key, kForInHasProperty);
  Branch(IsTrue(result), &if_true, &if_false);

  BIND(&if_true);
  Return(key);

  BIND(&if_false);
  Return(UndefinedConstant());
}

TF_BUILTIN(SameValue, CodeStubAssembler) {
  auto lhs = Parameter<Object>(Descriptor::kLeft);
  auto rhs = Parameter<Object>(Descriptor::kRight);

  Label if_true(this), if_false(this);
  BranchIfSameValue(lhs, rhs, &if_true, &if_false);

  BIND(&if_true);
  Return(TrueConstant());

  BIND(&if_false);
  Return(FalseConstant());
}

TF_BUILTIN(SameValueNumbersOnly, CodeStubAssembler) {
  auto lhs = Parameter<Object>(Descriptor::kLeft);
  auto rhs = Parameter<Object>(Descriptor::kRight);

  Label if_true(this), if_false(this);
  BranchIfSameValue(lhs, rhs, &if_true, &if_false, SameValueMode::kNumbersOnly);

  BIND(&if_true);
  Return(TrueConstant());

  BIND(&if_false);
  Return(FalseConstant());
}

class CppBuiltinsAdaptorAssembler : public CodeStubAssembler {
 public:
  using Descriptor = CppBuiltinAdaptorDescriptor;

  explicit CppBuiltinsAdaptorAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  void GenerateAdaptor(int formal_parameter_count);
};

void CppBuiltinsAdaptorAssembler::GenerateAdaptor(int formal_parameter_count) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto target = Parameter<JSFunction>(Descriptor::kTarget);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto c_function = UncheckedParameter<WordT>(Descriptor::kCFunction);
  auto actual_argc =
      UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);

  // The logic contained here is mirrored for TurboFan inlining in
  // JSTypedLowering::ReduceJSCall{Function,Construct}. Keep these in sync.

  // Make sure we operate in the context of the called function.
  CSA_DCHECK(this, TaggedEqual(context, LoadJSFunctionContext(target)));

  static_assert(kDontAdaptArgumentsSentinel == 0);
  // The code below relies on |actual_argc| to include receiver.
  static_assert(i::JSParameterCount(0) == 1);
  TVARIABLE(Int32T, pushed_argc, actual_argc);

  // It's guaranteed that the receiver is pushed to the stack, thus both
  // kDontAdaptArgumentsSentinel and JSParameterCount(0) cases don't require
  // arguments adaptation. Just use the latter version for consistency.
  DCHECK_NE(kDontAdaptArgumentsSentinel, formal_parameter_count);
  if (formal_parameter_count > i::JSParameterCount(0)) {
    TNode<Int32T> formal_count = Int32Constant(formal_parameter_count);

    // The number of arguments pushed is the maximum of actual arguments count
    // and formal parameters count.
    Label done_argc(this);
    GotoIf(Int32GreaterThanOrEqual(pushed_argc.value(), formal_count),
           &done_argc);
    // Update pushed args.
    pushed_argc = formal_count;
    Goto(&done_argc);
    BIND(&done_argc);
  }

  // Update arguments count for CEntry to contain the number of arguments
  // including the receiver and the extra arguments.
  TNode<Int32T> argc =
      Int32Add(pushed_argc.value(),
               Int32Constant(BuiltinExitFrameConstants::kNumExtraArgs));

  const bool builtin_exit_frame = true;
  const bool switch_to_central_stack = false;
  Builtin centry = Builtins::CEntry(1, ArgvMode::kStack, builtin_exit_frame,
                                    switch_to_central_stack);

  static_assert(BuiltinArguments::kNewTargetIndex == 0);
  static_assert(BuiltinArguments::kTargetIndex == 1);
  static_assert(BuiltinArguments::kArgcIndex == 2);
  static_assert(BuiltinArguments::kPaddingIndex == 3);

  // Unconditionally push argc, target and new target as extra stack arguments.
  // They will be used by stack frame iterators when constructing stack trace.
  TailCallBuiltin(centry, context,     // standard arguments for TailCallBuiltin
                  argc, c_function,    // register arguments
                  TheHoleConstant(),   // additional stack argument 1 (padding)
                  SmiFromInt32(argc),  // additional stack argument 2
                  target,              // additional stack argument 3
                  new_target);         // additional stack argument 4
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame0, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(0));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame1, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(1));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame2, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(2));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame3, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(3));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame4, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(4));
}

TF_BUILTIN(AdaptorWithBuiltinExitFrame5, CppBuiltinsAdaptorAssembler) {
  GenerateAdaptor(i::JSParameterCount(5));
}

TF_BUILTIN(NewHeapNumber, CodeStubAssembler) {
  auto val = UncheckedParameter<Float64T>(Descriptor::kValue);
  Return(ChangeFloat64ToTagged(val));
}

TF_BUILTIN(AllocateInYoungGeneration, CodeStubAssembler) {
  auto requested_size = UncheckedParameter<IntPtrT>(Descriptor::kRequestedSize);
  CSA_CHECK(this, IsValidPositiveSmi(requested_size));

  TNode<Smi> allocation_flags =
      SmiConstant(Smi::FromInt(AllocateDoubleAlignFlag::encode(false)));
  TailCallRuntime(Runtime::kAllocateInYoungGeneration, NoContextConstant(),
                  SmiFromIntPtr(requested_size), allocation_flags);
}

TF_BUILTIN(AllocateInOldGeneration, CodeStubAssembler) {
  auto requested_size = UncheckedParameter<IntPtrT>(Descriptor::kRequestedSize);
  CSA_CHECK(this, IsValidPositiveSmi(requested_size));

  TNode<Smi> runtime_flags =
      SmiConstant(Smi::FromInt(AllocateDoubleAlignFlag::encode(false)));
  TailCallRuntime(Runtime::kAllocateInOldGeneration, NoContextConstant(),
                  SmiFromIntPtr(requested_size), runtime_flags);
}

#if V8_ENABLE_WEBASSEMBLY
TF_BUILTIN(WasmAllocateInYoungGeneration, CodeStubAssembler) {
  auto requested_size = UncheckedParameter<IntPtrT>(Descriptor::kRequestedSize);
  CSA_CHECK(this, IsValidPositiveSmi(requested_size));

  TNode<Smi> allocation_flags =
      SmiConstant(Smi::FromInt(AllocateDoubleAlignFlag::encode(false)));
  TailCallRuntime(Runtime::kAllocateInYoungGeneration, NoContextConstant(),
                  SmiFromIntPtr(requested_size), allocation_flags);
}

TF_BUILTIN(WasmAllocateInOldGeneration, CodeStubAssembler) {
  auto requested_size = UncheckedParameter<IntPtrT>(Descriptor::kRequestedSize);
  CSA_CHECK(this, IsValidPositiveSmi(requested_size));

  TNode<Smi> runtime_flags =
      SmiConstant(Smi::FromInt(AllocateDoubleAlignFlag::encode(false)));
  TailCallRuntime(Runtime::kAllocateInOldGeneration, NoContextConstant(),
                  SmiFromIntPtr(requested_size), runtime_flags);
}
#endif

TF_BUILTIN(Abort, CodeStubAssembler) {
  auto message_id = Parameter<Smi>(Descriptor::kMessageOrMessageId);
  TailCallRuntime(Runtime::kAbort, NoContextConstant(), message_id);
}

TF_BUILTIN(AbortCSADcheck, CodeStubAssembler) {
  auto message = Parameter<String>(Descriptor::kMessageOrMessageId);
  TailCallRuntime(Runtime::kAbortCSADcheck, NoContextConstant(), message);
}

void Builtins::Generate_CEntry_Return1_ArgvOnStack_NoBuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 1, ArgvMode::kStack, false, false);
}

void Builtins::Generate_CEntry_Return1_ArgvOnStack_BuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 1, ArgvMode::kStack, true, false);
}

void Builtins::Generate_CEntry_Return1_ArgvInRegister_NoBuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 1, ArgvMode::kRegister, false, false);
}

void Builtins::Generate_CEntry_Return2_ArgvOnStack_NoBuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 2, ArgvMode::kStack, false, false);
}

void Builtins::Generate_CEntry_Return2_ArgvOnStack_BuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 2, ArgvMode::kStack, true, false);
}

void Builtins::Generate_CEntry_Return2_ArgvInRegister_NoBuiltinExit(
    MacroAssembler* masm) {
  Generate_CEntry(masm, 2, ArgvMode::kRegister, false, false);
}

void Builtins::Generate_WasmCEntry(MacroAssembler* masm) {
  Generate_CEntry(masm, 1, ArgvMode::kStack, false, true);
}

#if !defined(V8_TARGET_ARCH_ARM)
void Builtins::Generate_MemCopyUint8Uint8(MacroAssembler* masm) {
  masm->CallBuiltin(Builtin::kIllegal);
}
#endif  // !defined(V8_TARGET_ARCH_ARM)

#ifndef V8_TARGET_ARCH_IA32
void Builtins::Generate_MemMove(MacroAssembler* masm) {
  masm->CallBuiltin(Builtin::kIllegal);
}
#endif  // V8_TARGET_ARCH_IA32

void Builtins::Generate_BaselineLeaveFrame(MacroAssembler* masm) {
#ifdef V8_ENABLE_SPARKPLUG
  EmitReturnBaseline(masm);
#else
  masm->Trap();
#endif  // V8_ENABLE_SPARKPLUG
}

// TODO(v8:11421): Remove #if once the Maglev compiler is ported to other
// architectures.
#ifndef V8_TARGET_ARCH_X64
void Builtins::Generate_MaglevOnStackReplacement(MacroAssembler* masm) {
  using D =
      i::CallInterfaceDescriptorFor<Builtin::kMaglevOnStackReplacement>::type;
  static_assert(D::kParameterCount == 1);
  masm->Trap();
}
#endif  // V8_TARGET_ARCH_X64

#if defined(V8_ENABLE_MAGLEV) && !defined(V8_ENABLE_LEAPTIERING)
void Builtins::Generate_MaglevOptimizeCodeOrTailCallOptimizedCodeSlot(
    MacroAssembler* masm) {
  using D = MaglevOptimizeCodeOrTailCallOptimizedCodeSlotDescriptor;
  Register flags = D::GetRegisterParameter(D::kFlags);
  Register feedback_vector = D::GetRegisterParameter(D::kFeedbackVector);
  Register temporary = D::GetRegisterParameter(D::kTemporary);
  masm->AssertFeedbackVector(feedback_vector, temporary);
  masm->OptimizeCodeOrTailCallOptimizedCodeSlot(flags, feedback_vector);
  masm->Trap();
}
#else
void Builtins::Generate_MaglevOptimizeCodeOrTailCallOptimizedCodeSlot(
    MacroAssembler* masm) {
  masm->Trap();
}
#endif  // V8_ENABLE_MAGLEV && !V8_ENABLE_LEAPTIERING

#ifndef V8_ENABLE_MAGLEV
// static
void Builtins::Generate_MaglevFunctionEntryStackCheck(MacroAssembler* masm,
                                                      bool save_new_target) {
  masm->Trap();
}
#endif  // !V8_ENABLE_MAGLEV

void Builtins::Generate_MaglevFunctionEntryStackCheck_WithoutNewTarget(
    MacroAssembler* masm) {
  Generate_MaglevFunctionEntryStackCheck(masm, false);
}

void Builtins::Generate_MaglevFunctionEntryStackCheck_WithNewTarget(
    MacroAssembler* masm) {
  Generate_MaglevFunctionEntryStackCheck(masm, true);
}

// ES6 [[Get]] operation.
TF_BUILTIN(GetProperty, CodeStubAssembler) {
  auto object = Parameter<Object>(Descriptor::kObject);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto context = Parameter<Context>(Descriptor::kContext);
  // TODO(duongn): consider tailcalling to GetPropertyWithReceiver(object,
  // object, key, OnNonExistent::kReturnUndefined).
  Label if_notfound(this), if_proxy(this, Label::kDeferred),
      if_slow(this, Label::kDeferred);

  CodeStubAssembler::LookupPropertyInHolder lookup_property_in_holder =
      [=, this](TNode<HeapObject> receiver, TNode<HeapObject> holder,
                TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
                TNode<Name> unique_name, Label* next_holder,
                Label* if_bailout) {
        TVARIABLE(Object, var_value);
        Label if_found(this);
        // If we get here then it's guaranteed that |object| (and thus the
        // |receiver|) is a JSReceiver.
        TryGetOwnProperty(context, receiver, CAST(holder), holder_map,
                          holder_instance_type, unique_name, &if_found,
                          &var_value, next_holder, if_bailout,
                          kExpectingJSReceiver);
        BIND(&if_found);
        Return(var_value.value());
      };

  CodeStubAssembler::LookupElementInHolder lookup_element_in_holder =
      [=, this](TNode<HeapObject> receiver, TNode<HeapObject> holder,
                TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
                TNode<IntPtrT> index, Label* next_holder, Label* if_bailout) {
        // Not supported yet.
        Use(next_holder);
        Goto(if_bailout);
      };

  TryPrototypeChainLookup(object, object, key, lookup_property_in_holder,
                          lookup_element_in_holder, &if_notfound, &if_slow,
                          &if_proxy);

  BIND(&if_notfound);
  Return(UndefinedConstant());

  BIND(&if_slow);
  TailCallRuntime(Runtime::kGetProperty, context, object, key);

  BIND(&if_proxy);
  {
    // Convert the {key} to a Name first.
    TNode<Object> name = CallBuiltin(Builtin::kToName, context, key);

    // The {object} is a JSProxy instance, look up the {name} on it, passing
    // {object} both as receiver and holder. If {name} is absent we can safely
    // return undefined from here.
    TailCallBuiltin(Builtin::kProxyGetProperty, context, object, name, object,
                    SmiConstant(OnNonExistent::kReturnUndefined));
  }
}

// ES6 [[Get]] operation with Receiver.
TF_BUILTIN(GetPropertyWithReceiver, CodeStubAssembler) {
  auto object = Parameter<Object>(Descriptor::kObject);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto on_non_existent = Parameter<Object>(Descriptor::kOnNonExistent);
  Label if_notfound(this), if_proxy(this, Label::kDeferred),
      if_slow(this, Label::kDeferred);

  CodeStubAssembler::LookupPropertyInHolder lookup_property_in_holder =
      [=, this](TNode<HeapObject> receiver, TNode<HeapObject> holder,
                TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
                TNode<Name> unique_name, Label* next_holder,
                Label* if_bailout) {
        TVARIABLE(Object, var_value);
        Label if_found(this);
        TryGetOwnProperty(context, receiver, CAST(holder), holder_map,
                          holder_instance_type, unique_name, &if_found,
                          &var_value, next_holder, if_bailout,
                          kExpectingAnyReceiver);
        BIND(&if_found);
        Return(var_value.value());
      };

  CodeStubAssembler::LookupElementInHolder lookup_element_in_holder =
      [=, this](TNode<HeapObject> receiver, TNode<HeapObject> holder,
                TNode<Map> holder_map, TNode<Int32T> holder_instance_type,
                TNode<IntPtrT> index, Label* next_holder, Label* if_bailout) {
        // Not supported yet.
        Use(next_holder);
        Goto(if_bailout);
      };

  TryPrototypeChainLookup(receiver, object, key, lookup_property_in_holder,
                          lookup_element_in_holder, &if_notfound, &if_slow,
                          &if_proxy);

  BIND(&if_notfound);
  Label throw_reference_error(this);
  GotoIf(TaggedEqual(on_non_existent,
                     SmiConstant(OnNonExistent::kThrowReferenceError)),
         &throw_reference_error);
  CSA_DCHECK(this, TaggedEqual(on_non_existent,
                               SmiConstant(OnNonExistent::kReturnUndefined)));
  Return(UndefinedConstant());

  BIND(&throw_reference_error);
  Return(CallRuntime(Runtime::kThrowReferenceError, context, key));

  BIND(&if_slow);
  TailCallRuntime(Runtime::kGetPropertyWithReceiver, context, object, key,
                  receiver, on_non_existent);

  BIND(&if_proxy);
  {
    // Convert the {key} to a Name first.
    TNode<Name> name = CAST(CallBuiltin(Builtin::kToName, context, key));

    // Proxy cannot handle private symbol so bailout.
    GotoIf(IsPrivateSymbol(name), &if_slow);

    // The {object} is a JSProxy instance, look up the {name} on it, passing
    // {object} both as receiver and holder. If {name} is absent we can safely
    // return undefined from here.
    TailCallBuiltin(Builtin::kProxyGetProperty, context, object, name, receiver,
                    on_non_existent);
  }
}

// ES6 [[Set]] operation.
TF_BUILTIN(SetProperty, CodeStubAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto value = Parameter<Object>(Descriptor::kValue);

  KeyedStoreGenericGenerator::SetProperty(state(), context, receiver, key,
                                          value, LanguageMode::kStrict);
}

// ES6 CreateDataProperty(), specialized for the case where objects are still
// being initialized, and have not yet been made accessible to the user. Thus,
// any operation here should be unobservable until after the object has been
// returned.
TF_BUILTIN(CreateDataProperty, CodeStubAssembler) {
  auto context = Parameter<Context>(Descriptor::kContext);
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kKey);
  auto value = Parameter<Object>(Descriptor::kValue);

  KeyedStoreGenericGenerator::CreateDataProperty(state(), context, receiver,
                                                 key, value);
}

TF_BUILTIN(InstantiateAsmJs, CodeStubAssembler) {
  Label tailcall_to_function(this);
  auto function = Parameter<JSFunction>(Descriptor::kTarget);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto new_target = Parameter<Object>(Descriptor::kNewTarget);
  auto arg_count =
      UncheckedParameter<Int32T>(Descriptor::kActualArgumentsCount);
#ifdef V8_ENABLE_LEAPTIERING
  auto dispatch_handle =
      UncheckedParameter<JSDispatchHandleT>(Descriptor::kDispatchHandle);
#else
  auto dispatch_handle = InvalidDispatchHandleConstant();
#endif

  // This builtin is used on functions with different parameter counts.
  SetSupportsDynamicParameterCount(function, dispatch_handle);

  // Retrieve arguments from caller (stdlib, foreign, heap).
  CodeStubArguments args(this, arg_count);

  TNode<Object> stdlib = args.GetOptionalArgumentValue(0);
  TNode<Object> foreign = args.GetOptionalArgumentValue(1);
  TNode<Object> heap = args.GetOptionalArgumentValue(2);

  // Call runtime, on success just pass the result to the caller and pop all
  // arguments. A smi 0 is returned on failure, an object on success.
  TNode<Object> maybe_result_or_smi_zero = CallRuntime(
      Runtime::kInstantiateAsmJs, context, function, stdlib, foreign, heap);
  GotoIf(TaggedIsSmi(maybe_result_or_smi_zero), &tailcall_to_function);
  args.PopAndReturn(maybe_result_or_smi_zero);

  BIND(&tailcall_to_function);
  // On failure, tail call back to regular JavaScript by re-calling the given
  // function which has been reset to the compile lazy builtin.

  TNode<Code> code = LoadJSFunctionCode(function);
  TailCallJSCode(code, context, function, new_target, arg_count,
                 disp
"""


```