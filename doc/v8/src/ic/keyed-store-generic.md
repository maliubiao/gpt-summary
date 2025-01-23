Response: Let's break down the thought process for analyzing this C++ code and explaining its functionality and relationship to JavaScript.

**1. Initial Skim and Keyword Identification:**

The first step is to quickly read through the code, looking for familiar keywords and patterns. In this case, we see:

* `// Copyright`:  Indicates standard V8 copyright and licensing.
* `#include`: C++ includes, hinting at dependencies like codegen, execution, and objects within V8.
* `namespace v8 { namespace internal {`: Clearly within V8's internal implementation.
* `enum class StoreMode`:  This immediately suggests different ways to store properties, which is a core concept in JavaScript. The specific modes (`kSet`, `kDefineKeyedOwnInLiteral`, etc.) give clues about their usage.
* `class KeyedStoreGenericAssembler`:  The central class. The name "Assembler" strongly implies code generation. "KeyedStoreGeneric" points to handling stores of properties accessed via keys (like `object[key]`).
* Methods like `KeyedStoreGeneric()`, `KeyedStoreMegamorphic()`, `StoreProperty()`, `EmitGenericElementStore()`, `EmitGenericPropertyStore()`, etc.: These suggest different code paths for various storage scenarios.
*  Terms like "prototype chain", "setters", "accessor", "dictionary", "elements kind", "transition map": These are all fundamental concepts in JavaScript object models and optimization.

**2. Understanding the Core Purpose:**

Based on the keywords and the class name, the core function of this file is to implement the logic for *storing* properties in JavaScript objects when accessed using keys (like array indices or string keys). The "Generic" part likely means it handles various scenarios and optimizations.

**3. Analyzing `StoreMode`:**

The `StoreMode` enum is crucial for understanding the different execution paths. Let's analyze each mode:

* `kSet`: The most general form of setting a property, like `obj[key] = value;`. It implies traversing the prototype chain and potentially calling setters.
* `kDefineKeyedOwnInLiteral`: Used when creating objects with literals, like `{ [key]: value }`. It's optimized for this specific case, assuming the object is newly created.
* `kDefineNamedOwn`: For statically known keys, used in object literals (`{ key: value }`) and public class fields.
* `kDefineKeyedOwn`: For computed keys (`{ [key]: value }`) and private class fields. The distinction with `kDefineNamedOwn` about the key being "statically known" is important for optimization.

**4. Deconstructing Key Methods:**

* `KeyedStoreGenericAssembler::KeyedStoreGeneric()`: This is likely the main entry point for generic keyed stores. It seems to handle both integer indices and string keys.
* `KeyedStoreGenericAssembler::KeyedStoreMegamorphic()`:  The term "Megamorphic" in V8 often refers to cases where a property access has seen many different object shapes. This function likely handles such scenarios, possibly involving stub caches for optimization.
* `KeyedStoreGenericAssembler::StoreProperty()`:  Overloaded methods for storing properties with various levels of information (e.g., knowing if the receiver is simple, knowing the `LanguageMode`).
* `KeyedStoreGenericAssembler::EmitGenericElementStore()`:  Deals with storing elements in array-like objects using integer indices. The logic here handles fast vs. slow arrays, typed arrays, and potential resizing.
* `KeyedStoreGenericAssembler::EmitGenericPropertyStore()`: Handles storing properties with string keys, considering fast properties, dictionary properties, accessors, and transition maps.

**5. Connecting to JavaScript Functionality:**

Now, the crucial step is to connect the C++ implementation to actual JavaScript code.

* **`kSet`:** Directly corresponds to standard property assignment: `object[key] = value;` or when you have feedback information in the IC (Inline Cache).
* **`kDefineKeyedOwnInLiteral`:**  Maps to object literal creation with computed keys: `const key = 'myKey'; const obj = { [key]: 'value' };`.
* **`kDefineNamedOwn`:** Maps to object literal creation with static keys: `const obj = { myKey: 'value' };` and public class field declarations: `class MyClass { myField = 'value'; }`.
* **`kDefineKeyedOwn`:**  Connects to computed public class fields and private class fields:  `class MyClass { [computedKey] = 'value'; #privateField = 'value'; }`.

**6. Explaining Optimizations:**

The code reveals various optimization techniques used by V8:

* **Inline Caches (ICs):** The presence of `KeyedStoreMegamorphic()` and the mention of "feedback slot" and "stub cache" strongly suggest ICs are involved. ICs store information about previous property accesses to optimize future accesses on objects with the same shape.
* **Fast Properties vs. Dictionary Properties:** The code distinguishes between "fast properties" (stored in a contiguous block) and "dictionary properties" (stored in a hash table). This is a key optimization in V8.
* **Transition Maps:** The `FindCandidateStoreICTransitionMapHandler()` function indicates how V8 tracks changes in object shapes to optimize property accesses after an object's structure has changed.
* **Elements Kinds:**  The handling of different `ElementsKind` (e.g., `PACKED_SMI_ELEMENTS`, `HOLEY_DOUBLE_ELEMENTS`) shows how V8 optimizes array storage based on the types of elements.

**7. Structuring the Explanation:**

Finally, organize the information logically. Start with a high-level summary, then delve into the specific functionalities and their JavaScript equivalents, and conclude with the optimization strategies employed. Use code examples to make the connection between C++ and JavaScript clear.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "Maybe this is just about array access."  **Correction:**  The presence of `StoreProperty` and handling of string keys makes it clear it's about general keyed property access, including objects.
* **Initial thought:** "The different `StoreMode` values are arbitrary." **Correction:**  Realizing the connection to specific JavaScript language features (object literals, class fields) provides a clear rationale for each mode.
* **Initial thought:**  "The assembler code is too complex to explain in detail." **Refinement:** Focus on the *purpose* of the different methods and how they contribute to the overall goal of efficient property storage, rather than getting bogged down in the assembly-level details. Emphasize the *concepts* being implemented.

By following these steps, combining keyword recognition, conceptual understanding of JavaScript internals, and careful analysis of the code structure, we can arrive at a comprehensive explanation of the `keyed-store-generic.cc` file.
这个C++源代码文件 `v8/src/ic/keyed-store-generic.cc` 的功能是实现 **JavaScript 中通过键（key）进行属性存储的通用逻辑**。  更具体地说，它包含了在 V8 引擎中，当执行类似 `object[key] = value` 这样的操作时，如何进行属性写入的核心代码。

**功能归纳：**

1. **多种存储模式 (StoreMode):**  该文件定义了不同的属性存储模式，对应着 JavaScript 规范中不同的属性定义行为：
    * `kSet`:  实现标准的 `[[Set]]` 操作，会遍历原型链来查找并调用 setter。这是最常见的属性赋值方式，用于 `KeyedStoreIC` 和 `StoreIC` 在没有反馈信息时的操作。
    * `kDefineKeyedOwnInLiteral`:  实现 `[[CreateDataProperty]]` 操作，但它假设接收者是一个新创建的 `JSObject`。用于 `Object.fromEntries()`、`CloneObjectIC` 和 `StoreInArrayLiteralIC` 在对象字面量中定义属性，不会遍历原型链。
    * `kDefineNamedOwn`: 实现 `[[CreateDataProperty]]`，可以处理用户自定义的接收者（如 `JSProxy`），并且假设属性名是静态已知的。用于初始化对象字面量中的命名属性和公共类字段。
    * `kDefineKeyedOwn`: 实现 `[[CreateDataProperty]]`，可以处理用户自定义的接收者，并且属性名可以是动态的。对于私有类字段，如果字段已存在则会抛出错误。用于初始化计算得出的公共类字段和私有类字段。

2. **通用存储逻辑 (KeyedStoreGenericAssembler):**  提供了一个 `KeyedStoreGenericAssembler` 类，其中包含了通用的属性存储逻辑，可以根据不同的 `StoreMode` 执行不同的操作。

3. **处理不同类型的键 (整数索引 vs. 字符串键):**  代码能够区分使用整数索引（如数组访问）和字符串键进行属性存储，并采取相应的优化措施。

4. **优化策略:**  代码中包含了多种优化策略，例如：
    * **快速属性 (Fast Properties) 和字典属性 (Dictionary Properties):**  根据对象的属性结构，选择不同的存储方式以提高效率。
    * **内联缓存 (Inline Caches, ICs):**  `KeyedStoreMegamorphic` 相关的功能暗示了内联缓存的使用，用于优化重复的属性访问。
    * **原型链查找:**  `LookupPropertyOnPrototypeChain` 函数负责在原型链上查找属性，以处理继承和 setter 的调用。
    * **元素种类 (ElementsKind):**  对于数组，会根据元素的类型（SMI, 浮点数, 对象等）选择不同的存储方式，并进行必要的类型转换和内存管理。
    * **转型映射 (Transition Maps):** `FindCandidateStoreICTransitionMapHandler` 用于查找可能发生的属性添加导致的 Map 转型，以优化后续的属性访问。

5. **与反馈向量 (Feedback Vector) 的交互:**  代码中涉及到反馈向量，这是 V8 用于存储运行时类型信息以进行优化的机制。

**与 JavaScript 功能的关系及示例:**

该文件的核心功能直接对应着 JavaScript 中对象属性的赋值操作。不同的 `StoreMode` 体现了 JavaScript 中创建和修改属性的不同语义。

**JavaScript 示例：**

```javascript
const obj = {};
const key = 'myKey';
const index = 0;

// 对应 StoreMode::kSet (最常见的属性赋值)
obj.prop1 = 'value1';
obj[key] = 'value2';
obj[index] = 'value3';

// 对应 StoreMode::kDefineKeyedOwnInLiteral (对象字面量中定义属性)
const objLiteral = { [key]: 'value4', 1: 'value5' };

// 对应 StoreMode::kDefineNamedOwn (对象字面量中定义命名属性)
const objNamed = { propA: 'value6', propB: 'value7' };

class MyClass {
  publicField = 'value8'; // 对应 StoreMode::kDefineNamedOwn
  [key] = 'value9';      // 对应 StoreMode::kDefineKeyedOwn
  #privateField = 'value10'; // 对应 StoreMode::kDefineKeyedOwn

  constructor() {
    this.anotherPublicField = 'value11'; // 对应 StoreMode::kSet 或其他 IC 优化
  }
}

const instance = new MyClass();
instance.dynamicProp = 'value12'; // 对应 StoreMode::kSet 或其他 IC 优化
```

**解释示例：**

* 当执行 `obj.prop1 = 'value1';` 或 `obj[key] = 'value2';` 时，如果 V8 没有关于 `obj` 属性结构的预先信息，或者需要处理原型链上的 setter，则 `KeyedStoreGeneric` 可能会以 `kSet` 模式执行。
* 当创建 `objLiteral` 时，V8 知道正在创建一个新的对象，并使用 `kDefineKeyedOwnInLiteral` 模式来高效地定义属性，而无需查找原型链。
* 在 `MyClass` 中，`publicField = 'value8';` 在类定义时使用 `kDefineNamedOwn` 模式来定义属性，因为它是一个静态已知的属性名。
* `[key] = 'value9';` 使用 `kDefineKeyedOwn`，因为属性名是计算得出的。
* `#privateField = 'value10';` 也使用 `kDefineKeyedOwn`，私有字段有特殊的存储和访问规则。
* `instance.dynamicProp = 'value12';` 这样的动态属性赋值，V8 可能会利用内联缓存 (`KeyedStoreMegamorphic`) 来优化后续的访问。

总而言之，`keyed-store-generic.cc` 文件是 V8 引擎中处理 JavaScript 属性赋值操作的核心组件，它根据不同的场景和优化策略，选择合适的存储模式和执行路径，以确保 JavaScript 代码的高效运行。它直接影响了 JavaScript 中对对象属性的读写性能。

### 提示词
```
这是目录为v8/src/ic/keyed-store-generic.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明
```

### 源代码
```
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/ic/keyed-store-generic.h"

#include <optional>

#include "src/codegen/code-factory.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/codegen/interface-descriptors.h"
#include "src/execution/isolate.h"
#include "src/ic/accessor-assembler.h"
#include "src/objects/contexts.h"
#include "src/objects/feedback-vector.h"
#include "src/objects/objects-inl.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

enum class StoreMode {
  // kSet implements [[Set]] in the spec and traverses the prototype
  // chain to invoke setters. it's used by KeyedStoreIC and StoreIC to
  // set the properties when there is no feedback.
  kSet,
  // kDefineKeyedOwnInLiteral implements [[CreateDataProperty]] in the spec,
  // and it assumes that the receiver is a JSObject that is created by us.
  // It is used by Object.fromEntries(), CloneObjectIC and
  // StoreInArrayLiteralIC to define a property in an object without
  // traversing the prototype chain.
  // TODO(v8:12548): merge this into the more generic kDefineKeyedOwn.
  kDefineKeyedOwnInLiteral,
  // kDefineNamedOwn implements [[CreateDataProperty]] but it can deal with
  // user-defined receivers such as a JSProxy. It also assumes that the key
  // is statically known. It's used to initialize named roperties in object
  // literals and named public class fields.
  kDefineNamedOwn,
  // kDefineKeyedOwn implements [[CreateDataProperty]], but it can deal with
  // user-defined receivers such as a JSProxy, and for private class fields,
  // it will throw if the field does already exist. It's different from
  // kDefineNamedOwn in that it does not assume the key is statically known.
  // It's used to initialized computed public class fields and private
  // class fields.
  kDefineKeyedOwn
};

// With private symbols, 'define' semantics will throw if the field already
// exists, while 'update' semantics will throw if the field does not exist.
enum class PrivateNameSemantics { kUpdate, kDefine };

class KeyedStoreGenericAssembler : public AccessorAssembler {
 public:
  explicit KeyedStoreGenericAssembler(compiler::CodeAssemblerState* state,
                                      StoreMode mode)
      : AccessorAssembler(state), mode_(mode) {}

  void KeyedStoreGeneric();
  void KeyedStoreMegamorphic();

  void StoreIC_NoFeedback();

  // Generates code for [[Set]] or [[CreateDataProperty]] operation,
  // the |unique_name| is supposed to be unique otherwise this code will
  // always go to runtime.
  void StoreProperty(TNode<Context> context, TNode<JSReceiver> receiver,
                     TNode<BoolT> is_simple_receiver, TNode<Name> unique_name,
                     TNode<Object> value, LanguageMode language_mode);

  // This does [[Set]] or [[CreateDataProperty]] but it's more generic than
  // the above. It is essentially the same as "KeyedStoreGeneric" but does not
  // use feedback slot and uses a hardcoded LanguageMode instead of trying
  // to deduce it from the feedback slot's kind.
  void StoreProperty(TNode<Context> context, TNode<Object> receiver,
                     TNode<Object> key, TNode<Object> value,
                     LanguageMode language_mode);

 private:
  StoreMode mode_;

  enum UpdateLength {
    kDontChangeLength,
    kIncrementLengthByOne,
    kBumpLengthWithGap
  };

  enum UseStubCache { kUseStubCache, kDontUseStubCache };

  // Helper that is used by the public KeyedStoreGeneric, KeyedStoreMegamorphic
  // and StoreProperty.
  void KeyedStoreGeneric(TNode<Context> context, TNode<Object> receiver,
                         TNode<Object> key, TNode<Object> value,
                         Maybe<LanguageMode> language_mode,
                         UseStubCache use_stub_cache = kDontUseStubCache,
                         TNode<TaggedIndex> slot = {},
                         TNode<HeapObject> maybe_vector = {});

  void EmitGenericElementStore(TNode<JSObject> receiver,
                               TNode<Map> receiver_map,
                               TNode<Uint16T> instance_type,
                               TNode<IntPtrT> index, TNode<Object> value,
                               TNode<Context> context, Label* slow);

  // If language mode is not provided it is deduced from the feedback slot's
  // kind.
  void EmitGenericPropertyStore(TNode<JSReceiver> receiver,
                                TNode<Map> receiver_map,
                                TNode<Uint16T> instance_type,
                                const StoreICParameters* p,
                                ExitPoint* exit_point, Label* slow,
                                Maybe<LanguageMode> maybe_language_mode,
                                UseStubCache use_stub_cache);

  void EmitGenericPropertyStore(TNode<JSReceiver> receiver,
                                TNode<Map> receiver_map,
                                TNode<Uint16T> instance_type,
                                const StoreICParameters* p, Label* slow) {
    ExitPoint direct_exit(this);
    EmitGenericPropertyStore(receiver, receiver_map, instance_type, p,
                             &direct_exit, slow, Nothing<LanguageMode>(),
                             kDontUseStubCache);
  }

  void BranchIfPrototypesMayHaveReadOnlyElements(
      TNode<Map> receiver_map, Label* maybe_read_only_elements,
      Label* only_fast_writable_elements);

  void TryRewriteElements(TNode<JSObject> receiver, TNode<Map> receiver_map,
                          TNode<FixedArrayBase> elements,
                          TNode<NativeContext> native_context,
                          ElementsKind from_kind, ElementsKind to_kind,
                          Label* bailout);

  void StoreSharedArrayElement(TNode<Context> context,
                               TNode<FixedArrayBase> elements,
                               TNode<IntPtrT> index, TNode<Object> value);

  void StoreElementWithCapacity(TNode<JSObject> receiver,
                                TNode<Map> receiver_map,
                                TNode<FixedArrayBase> elements,
                                TNode<Word32T> elements_kind,
                                TNode<IntPtrT> index, TNode<Object> value,
                                TNode<Context> context, Label* slow,
                                UpdateLength update_length);

  void MaybeUpdateLengthAndReturn(TNode<JSObject> receiver,
                                  TNode<IntPtrT> index, TNode<Object> value,
                                  UpdateLength update_length);

  void TryChangeToHoleyMapHelper(TNode<JSObject> receiver,
                                 TNode<Map> receiver_map,
                                 TNode<NativeContext> native_context,
                                 ElementsKind packed_kind,
                                 ElementsKind holey_kind, Label* done,
                                 Label* map_mismatch, Label* bailout);
  void TryChangeToHoleyMap(TNode<JSObject> receiver, TNode<Map> receiver_map,
                           TNode<Word32T> current_elements_kind,
                           TNode<Context> context, ElementsKind packed_kind,
                           Label* bailout);
  void TryChangeToHoleyMapMulti(TNode<JSObject> receiver,
                                TNode<Map> receiver_map,
                                TNode<Word32T> current_elements_kind,
                                TNode<Context> context,
                                ElementsKind packed_kind,
                                ElementsKind packed_kind_2, Label* bailout);

  void LookupPropertyOnPrototypeChain(
      TNode<Map> receiver_map, TNode<Name> name, Label* accessor,
      TVariable<Object>* var_accessor_pair,
      TVariable<HeapObject>* var_accessor_holder, Label* readonly,
      Label* bailout);

  TNode<Map> FindCandidateStoreICTransitionMapHandler(TNode<Map> map,
                                                      TNode<Name> name,
                                                      Label* slow);

  bool IsSet() const { return mode_ == StoreMode::kSet; }
  bool IsDefineKeyedOwnInLiteral() const {
    return mode_ == StoreMode::kDefineKeyedOwnInLiteral;
  }
  bool IsDefineNamedOwn() const { return mode_ == StoreMode::kDefineNamedOwn; }
  bool IsDefineKeyedOwn() const { return mode_ == StoreMode::kDefineKeyedOwn; }
  bool IsAnyDefineOwn() const {
    return IsDefineNamedOwn() || IsDefineKeyedOwn();
  }

  bool ShouldCheckPrototype() const { return IsSet(); }
  bool ShouldReconfigureExisting() const { return IsDefineKeyedOwnInLiteral(); }
  bool ShouldCallSetter() const { return IsSet(); }
  bool ShouldCheckPrototypeValidity() const {
    // We don't do this for "in-literal" stores, because it is impossible for
    // the target object to be a "prototype".
    // We don't need the prototype validity check for "own" stores, because
    // we don't care about the prototype chain.
    // Thus, we need the prototype check only for ordinary stores.
    DCHECK_IMPLIES(!IsSet(), IsDefineKeyedOwnInLiteral() ||
                                 IsDefineNamedOwn() || IsDefineKeyedOwn());
    return IsSet();
  }
};

// static
void KeyedStoreMegamorphicGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.KeyedStoreMegamorphic();
}

// static
void KeyedStoreGenericGenerator::Generate(compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.KeyedStoreGeneric();
}

// static
void DefineKeyedOwnGenericGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kDefineKeyedOwn);
  assembler.KeyedStoreGeneric();
}

// static
void StoreICNoFeedbackGenerator::Generate(compiler::CodeAssemblerState* state) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreIC_NoFeedback();
}

// static
void DefineNamedOwnICNoFeedbackGenerator::Generate(
    compiler::CodeAssemblerState* state) {
  // TODO(v8:12548): it's a hack to reuse KeyedStoreGenericAssembler for
  // DefineNamedOwnIC, we should separate it out.
  KeyedStoreGenericAssembler assembler(state, StoreMode::kDefineNamedOwn);
  assembler.StoreIC_NoFeedback();
}

// static
void KeyedStoreGenericGenerator::SetProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<JSReceiver> receiver, TNode<BoolT> is_simple_receiver,
    TNode<Name> name, TNode<Object> value, LanguageMode language_mode) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreProperty(context, receiver, is_simple_receiver, name, value,
                          language_mode);
}

// static
void KeyedStoreGenericGenerator::SetProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<Object> receiver, TNode<Object> key, TNode<Object> value,
    LanguageMode language_mode) {
  KeyedStoreGenericAssembler assembler(state, StoreMode::kSet);
  assembler.StoreProperty(context, receiver, key, value, language_mode);
}

// static
void KeyedStoreGenericGenerator::CreateDataProperty(
    compiler::CodeAssemblerState* state, TNode<Context> context,
    TNode<JSObject> receiver, TNode<Object> key, TNode<Object> value) {
  KeyedStoreGenericAssembler assembler(state,
                                       StoreMode::kDefineKeyedOwnInLiteral);
  assembler.StoreProperty(context, receiver, key, value, LanguageMode::kStrict);
}

void KeyedStoreGenericAssembler::BranchIfPrototypesMayHaveReadOnlyElements(
    TNode<Map> receiver_map, Label* maybe_read_only_elements,
    Label* only_fast_writable_elements) {
  TVARIABLE(Map, var_map);
  var_map = receiver_map;
  Label loop_body(this, &var_map);
  Goto(&loop_body);

  BIND(&loop_body);
  {
    TNode<Map> map = var_map.value();
    TNode<HeapObject> prototype = LoadMapPrototype(map);
    GotoIf(IsNull(prototype), only_fast_writable_elements);
    TNode<Map> prototype_map = LoadMap(prototype);
    var_map = prototype_map;
    TNode<Uint16T> instance_type = LoadMapInstanceType(prototype_map);
    GotoIf(IsCustomElementsReceiverInstanceType(instance_type),
           maybe_read_only_elements);
    TNode<Int32T> elements_kind = LoadMapElementsKind(prototype_map);
    GotoIf(IsFastOrNonExtensibleOrSealedElementsKind(elements_kind),
           &loop_body);
    GotoIf(Word32Equal(elements_kind, Int32Constant(NO_ELEMENTS)), &loop_body);
    Goto(maybe_read_only_elements);
  }
}

void KeyedStoreGenericAssembler::TryRewriteElements(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<FixedArrayBase> elements, TNode<NativeContext> native_context,
    ElementsKind from_kind, ElementsKind to_kind, Label* bailout) {
  DCHECK(IsFastPackedElementsKind(from_kind));
  ElementsKind holey_from_kind = GetHoleyElementsKind(from_kind);
  ElementsKind holey_to_kind = GetHoleyElementsKind(to_kind);
  if (AllocationSite::ShouldTrack(from_kind, to_kind)) {
    TrapAllocationMemento(receiver, bailout);
  }
  Label perform_transition(this), check_holey_map(this);
  TVARIABLE(Map, var_target_map);
  // Check if the receiver has the default |from_kind| map.
  {
    TNode<Map> packed_map = LoadJSArrayElementsMap(from_kind, native_context);
    GotoIf(TaggedNotEqual(receiver_map, packed_map), &check_holey_map);
    var_target_map = CAST(
        LoadContextElement(native_context, Context::ArrayMapIndex(to_kind)));
    Goto(&perform_transition);
  }

  // Check if the receiver has the default |holey_from_kind| map.
  BIND(&check_holey_map);
  {
    TNode<Object> holey_map = LoadContextElement(
        native_context, Context::ArrayMapIndex(holey_from_kind));
    GotoIf(TaggedNotEqual(receiver_map, holey_map), bailout);
    var_target_map = CAST(LoadContextElement(
        native_context, Context::ArrayMapIndex(holey_to_kind)));
    Goto(&perform_transition);
  }

  // Found a supported transition target map, perform the transition!
  BIND(&perform_transition);
  {
    if (IsDoubleElementsKind(from_kind) != IsDoubleElementsKind(to_kind)) {
      TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
      GrowElementsCapacity(receiver, elements, from_kind, to_kind, capacity,
                           capacity, bailout);
    }
    StoreMap(receiver, var_target_map.value());
  }
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMapHelper(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<NativeContext> native_context, ElementsKind packed_kind,
    ElementsKind holey_kind, Label* done, Label* map_mismatch, Label* bailout) {
  TNode<Map> packed_map = LoadJSArrayElementsMap(packed_kind, native_context);
  GotoIf(TaggedNotEqual(receiver_map, packed_map), map_mismatch);
  if (AllocationSite::ShouldTrack(packed_kind, holey_kind)) {
    TrapAllocationMemento(receiver, bailout);
  }
  TNode<Map> holey_map = CAST(
      LoadContextElement(native_context, Context::ArrayMapIndex(holey_kind)));
  StoreMap(receiver, holey_map);
  Goto(done);
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMap(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Word32T> current_elements_kind, TNode<Context> context,
    ElementsKind packed_kind, Label* bailout) {
  ElementsKind holey_kind = GetHoleyElementsKind(packed_kind);
  Label already_holey(this);

  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind)),
         &already_holey);
  TNode<NativeContext> native_context = LoadNativeContext(context);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context, packed_kind,
                            holey_kind, &already_holey, bailout, bailout);
  BIND(&already_holey);
}

void KeyedStoreGenericAssembler::TryChangeToHoleyMapMulti(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Word32T> current_elements_kind, TNode<Context> context,
    ElementsKind packed_kind, ElementsKind packed_kind_2, Label* bailout) {
  ElementsKind holey_kind = GetHoleyElementsKind(packed_kind);
  ElementsKind holey_kind_2 = GetHoleyElementsKind(packed_kind_2);
  Label already_holey(this), check_other_kind(this);

  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind)),
         &already_holey);
  GotoIf(Word32Equal(current_elements_kind, Int32Constant(holey_kind_2)),
         &already_holey);

  TNode<NativeContext> native_context = LoadNativeContext(context);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context, packed_kind,
                            holey_kind, &already_holey, &check_other_kind,
                            bailout);
  BIND(&check_other_kind);
  TryChangeToHoleyMapHelper(receiver, receiver_map, native_context,
                            packed_kind_2, holey_kind_2, &already_holey,
                            bailout, bailout);
  BIND(&already_holey);
}

void KeyedStoreGenericAssembler::MaybeUpdateLengthAndReturn(
    TNode<JSObject> receiver, TNode<IntPtrT> index, TNode<Object> value,
    UpdateLength update_length) {
  if (update_length != kDontChangeLength) {
    TNode<Smi> new_length = SmiTag(Signed(IntPtrAdd(index, IntPtrConstant(1))));
    StoreObjectFieldNoWriteBarrier(receiver, JSArray::kLengthOffset,
                                   new_length);
  }
  Return(value);
}

void KeyedStoreGenericAssembler::StoreSharedArrayElement(
    TNode<Context> context, TNode<FixedArrayBase> elements,
    TNode<IntPtrT> index, TNode<Object> value) {
  TVARIABLE(Object, shared_value, value);
  SharedValueBarrier(context, &shared_value);
  UnsafeStoreFixedArrayElement(CAST(elements), index, shared_value.value());
  Return(value);
}

void KeyedStoreGenericAssembler::StoreElementWithCapacity(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<FixedArrayBase> elements, TNode<Word32T> elements_kind,
    TNode<IntPtrT> index, TNode<Object> value, TNode<Context> context,
    Label* slow, UpdateLength update_length) {
  if (update_length != kDontChangeLength) {
    CSA_DCHECK(this, IsJSArrayMap(receiver_map));
    // Check if the length property is writable. The fast check is only
    // supported for fast properties.
    GotoIf(IsDictionaryMap(receiver_map), slow);
    // The length property is non-configurable, so it's guaranteed to always
    // be the first property.
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(receiver_map);
    TNode<Uint32T> details = LoadDetailsByDescriptorEntry(descriptors, 0);
    GotoIf(IsSetWord32(details, PropertyDetails::kAttributesReadOnlyMask),
           slow);
  }
  static_assert(OFFSET_OF_DATA_START(FixedArray) ==
                OFFSET_OF_DATA_START(FixedDoubleArray));
  const int kHeaderSize = OFFSET_OF_DATA_START(FixedArray) - kHeapObjectTag;

  Label check_double_elements(this), check_cow_elements(this);
  TNode<Map> elements_map = LoadMap(elements);
  GotoIf(IsNotFixedArrayMap(elements_map), &check_double_elements);

  // FixedArray backing store -> Smi or object elements.
  {
    TNode<IntPtrT> offset =
        ElementOffsetFromIndex(index, PACKED_ELEMENTS, kHeaderSize);
    if (!IsDefineKeyedOwnInLiteral()) {
      // Check if we're about to overwrite the hole. We can safely do that
      // only if there can be no setters on the prototype chain.
      // If we know that we're storing beyond the previous array length, we
      // can skip the hole check (and always assume the hole).
      {
        Label hole_check_passed(this);
        if (update_length == kDontChangeLength) {
          TNode<Object> element =
              CAST(Load(MachineType::AnyTagged(), elements, offset));
          GotoIf(IsNotTheHole(element), &hole_check_passed);
        }
        BranchIfPrototypesMayHaveReadOnlyElements(receiver_map, slow,
                                                  &hole_check_passed);
        BIND(&hole_check_passed);
      }
    }

    // Check if the value we're storing matches the elements_kind. Smis
    // can always be stored.
    {
      Label non_smi_value(this);
      GotoIfNot(TaggedIsSmi(value), &non_smi_value);
      // If we're about to introduce holes, ensure holey elements.
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMapMulti(receiver, receiver_map, elements_kind, context,
                                 PACKED_SMI_ELEMENTS, PACKED_ELEMENTS, slow);
      }
      StoreNoWriteBarrier(MachineRepresentation::kTaggedSigned, elements,
                          offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&non_smi_value);
    }

    // Check if we already have object elements; just do the store if so.
    {
      Label must_transition(this);
      static_assert(PACKED_SMI_ELEMENTS == 0);
      static_assert(HOLEY_SMI_ELEMENTS == 1);
      GotoIf(Int32LessThanOrEqual(elements_kind,
                                  Int32Constant(HOLEY_SMI_ELEMENTS)),
             &must_transition);
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMap(receiver, receiver_map, elements_kind, context,
                            PACKED_ELEMENTS, slow);
      }
      Store(elements, offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&must_transition);
    }

    // Transition to the required ElementsKind.
    {
      Label transition_to_double(this), transition_to_object(this);
      TNode<NativeContext> native_context = LoadNativeContext(context);
      Branch(IsHeapNumber(CAST(value)), &transition_to_double,
             &transition_to_object);
      BIND(&transition_to_double);
      {
        // If we're adding holes at the end, always transition to a holey
        // elements kind, otherwise try to remain packed.
        ElementsKind target_kind = update_length == kBumpLengthWithGap
                                       ? HOLEY_DOUBLE_ELEMENTS
                                       : PACKED_DOUBLE_ELEMENTS;
        TryRewriteElements(receiver, receiver_map, elements, native_context,
                           PACKED_SMI_ELEMENTS, target_kind, slow);
        // Reload migrated elements.
        TNode<FixedArrayBase> double_elements = LoadElements(receiver);
        TNode<IntPtrT> double_offset =
            ElementOffsetFromIndex(index, PACKED_DOUBLE_ELEMENTS, kHeaderSize);
        // Make sure we do not store signalling NaNs into double arrays.
        TNode<Float64T> double_value =
            Float64SilenceNaN(LoadHeapNumberValue(CAST(value)));
        StoreNoWriteBarrier(MachineRepresentation::kFloat64, double_elements,
                            double_offset, double_value);
        MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
      }

      BIND(&transition_to_object);
      {
        // If we're adding holes at the end, always transition to a holey
        // elements kind, otherwise try to remain packed.
        ElementsKind target_kind = update_length == kBumpLengthWithGap
                                       ? HOLEY_ELEMENTS
                                       : PACKED_ELEMENTS;
        TryRewriteElements(receiver, receiver_map, elements, native_context,
                           PACKED_SMI_ELEMENTS, target_kind, slow);
        // The elements backing store didn't change, no reload necessary.
        CSA_DCHECK(this, TaggedEqual(elements, LoadElements(receiver)));
        Store(elements, offset, value);
        MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
      }
    }
  }

  BIND(&check_double_elements);
  GotoIf(IsNotFixedDoubleArrayMap(elements_map), &check_cow_elements);
  // FixedDoubleArray backing store -> double elements.
  {
    TNode<IntPtrT> offset =
        ElementOffsetFromIndex(index, PACKED_DOUBLE_ELEMENTS, kHeaderSize);
    if (!IsDefineKeyedOwnInLiteral()) {
      // Check if we're about to overwrite the hole. We can safely do that
      // only if there can be no setters on the prototype chain.
      {
        Label hole_check_passed(this);
        // If we know that we're storing beyond the previous array length, we
        // can skip the hole check (and always assume the hole).
        if (update_length == kDontChangeLength) {
          Label found_hole(this);
          LoadDoubleWithHoleCheck(elements, offset, &found_hole,
                                  MachineType::None());
          Goto(&hole_check_passed);
          BIND(&found_hole);
        }
        BranchIfPrototypesMayHaveReadOnlyElements(receiver_map, slow,
                                                  &hole_check_passed);
        BIND(&hole_check_passed);
      }
    }

    // Try to store the value as a double.
    {
      Label non_number_value(this);
      TNode<Float64T> double_value =
          TryTaggedToFloat64(value, &non_number_value);

      // Make sure we do not store signalling NaNs into double arrays.
      double_value = Float64SilenceNaN(double_value);
      // If we're about to introduce holes, ensure holey elements.
      if (update_length == kBumpLengthWithGap) {
        TryChangeToHoleyMap(receiver, receiver_map, elements_kind, context,
                            PACKED_DOUBLE_ELEMENTS, slow);
      }
      StoreNoWriteBarrier(MachineRepresentation::kFloat64, elements, offset,
                          double_value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);

      BIND(&non_number_value);
    }

    // Transition to object elements.
    {
      TNode<NativeContext> native_context = LoadNativeContext(context);
      ElementsKind target_kind = update_length == kBumpLengthWithGap
                                     ? HOLEY_ELEMENTS
                                     : PACKED_ELEMENTS;
      TryRewriteElements(receiver, receiver_map, elements, native_context,
                         PACKED_DOUBLE_ELEMENTS, target_kind, slow);
      // Reload migrated elements.
      TNode<FixedArrayBase> fast_elements = LoadElements(receiver);
      TNode<IntPtrT> fast_offset =
          ElementOffsetFromIndex(index, PACKED_ELEMENTS, kHeaderSize);
      Store(fast_elements, fast_offset, value);
      MaybeUpdateLengthAndReturn(receiver, index, value, update_length);
    }
  }

  BIND(&check_cow_elements);
  {
    // TODO(jkummerow): Use GrowElementsCapacity instead of bailing out.
    Goto(slow);
  }
}

void KeyedStoreGenericAssembler::EmitGenericElementStore(
    TNode<JSObject> receiver, TNode<Map> receiver_map,
    TNode<Uint16T> instance_type, TNode<IntPtrT> index, TNode<Object> value,
    TNode<Context> context, Label* slow) {
  Label if_fast(this), if_in_bounds(this), if_increment_length_by_one(this),
      if_bump_length_with_gap(this), if_grow(this), if_nonfast(this),
      if_typed_array(this), if_dictionary(this), if_shared_array(this);
  TNode<FixedArrayBase> elements = LoadElements(receiver);
  TNode<Int32T> elements_kind = LoadMapElementsKind(receiver_map);
  Branch(IsFastElementsKind(elements_kind), &if_fast, &if_nonfast);
  BIND(&if_fast);
  Label if_array(this);
  GotoIf(IsJSArrayInstanceType(instance_type), &if_array);
  {
    TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
    Branch(UintPtrLessThan(index, capacity), &if_in_bounds, &if_grow);
  }
  BIND(&if_array);
  {
    TNode<IntPtrT> length =
        PositiveSmiUntag(LoadFastJSArrayLength(CAST(receiver)));
    GotoIf(UintPtrLessThan(index, length), &if_in_bounds);
    TNode<IntPtrT> capacity = LoadAndUntagFixedArrayBaseLength(elements);
    GotoIf(UintPtrGreaterThanOrEqual(index, capacity), &if_grow);
    Branch(WordEqual(index, length), &if_increment_length_by_one,
           &if_bump_length_with_gap);
  }

  BIND(&if_in_bounds);
  {
    StoreElementWithCapacity(receiver, receiver_map, elements, elements_kind,
                             index, value, context, slow, kDontChangeLength);
  }

  BIND(&if_increment_length_by_one);
  {
    StoreElementWithCapacity(receiver, receiver_map, elements, elements_kind,
                             index, value, context, slow,
                             kIncrementLengthByOne);
  }

  BIND(&if_bump_length_with_gap);
  {
    StoreElementWithCapacity(receiver, receiver_map, elements, elements_kind,
                             index, value, context, slow, kBumpLengthWithGap);
  }

  // Out-of-capacity accesses (index >= capacity) jump here. Additionally,
  // an ElementsKind transition might be necessary.
  // The index can also be negative or larger than kMaxElementIndex at this
  // point! Jump to the runtime in that case to convert it to a named property.
  BIND(&if_grow);
  {
    Comment("Grow backing store");
    // TODO(jkummerow): Support inline backing store growth.
    Goto(slow);
  }

  // Any ElementsKind > LAST_FAST_ELEMENTS_KIND jumps here for further
  // dispatch.
  BIND(&if_nonfast);
  {
    static_assert(LAST_ELEMENTS_KIND ==
                  LAST_RAB_GSAB_FIXED_TYPED_ARRAY_ELEMENTS_KIND);
    GotoIf(Int32GreaterThanOrEqual(
               elements_kind,
               Int32Constant(FIRST_FIXED_TYPED_ARRAY_ELEMENTS_KIND)),
           &if_typed_array);
    GotoIf(Word32Equal(elements_kind, Int32Constant(DICTIONARY_ELEMENTS)),
           &if_dictionary);
    GotoIf(Word32Equal(elements_kind, Int32Constant(SHARED_ARRAY_ELEMENTS)),
           &if_shared_array);
    Goto(slow);
  }

  BIND(&if_dictionary);
  {
    Comment("Dictionary");
    // TODO(jkummerow): Support storing to dictionary elements.
    Goto(slow);
  }

  BIND(&if_typed_array);
  {
    Comment("Typed array");
    // TODO(jkummerow): Support typed arrays. Note: RAB / GSAB backed typed
    // arrays end up here too.
    Goto(slow);
  }

  BIND(&if_shared_array);
  {
    TNode<IntPtrT> length = LoadAndUntagFixedArrayBaseLength(elements);
    GotoIf(UintPtrGreaterThanOrEqual(index, length), slow);
    StoreSharedArrayElement(context, elements, index, value);
  }
}

void KeyedStoreGenericAssembler::LookupPropertyOnPrototypeChain(
    TNode<Map> receiver_map, TNode<Name> name, Label* accessor,
    TVariable<Object>* var_accessor_pair,
    TVariable<HeapObject>* var_accessor_holder, Label* readonly,
    Label* bailout) {
  Label ok_to_write(this);
  TVARIABLE(HeapObject, var_holder);
  TVARIABLE(Map, var_holder_map);
  var_holder = LoadMapPrototype(receiver_map);
  var_holder_map = LoadMap(var_holder.value());

  Label loop(this, {&var_holder, &var_holder_map});
  Goto(&loop);
  BIND(&loop);
  {
    TNode<HeapObject> holder = var_holder.value();
    GotoIf(IsNull(holder), &ok_to_write);
    TNode<Map> holder_map = var_holder_map.value();
    TNode<Uint16T> instance_type = LoadMapInstanceType(holder_map);
    Label next_proto(this);
    {
      Label found(this), found_fast(this), found_dict(this), found_global(this);
      TVARIABLE(HeapObject, var_meta_storage);
      TVARIABLE(IntPtrT, var_entry);
      TryLookupProperty(holder, holder_map, instance_type, name, &found_fast,
                        &found_dict, &found_global, &var_meta_storage,
                        &var_entry, &next_proto, bailout);
      BIND(&found_fast);
      {
        TNode<DescriptorArray> descriptors = CAST(var_meta_storage.value());
        TNode<IntPtrT> name_index = var_entry.value();
        TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, name_index);
        JumpIfDataProperty(details, &ok_to_write, readonly);

        // Accessor case.
        // TODO(jkummerow): Implement a trimmed-down
        // LoadAccessorFromFastObject.
        LoadPropertyFromFastObject(holder, holder_map, descriptors, name_index,
                                   details, var_accessor_pair);
        *var_accessor_holder = holder;
        Goto(accessor);
      }

      BIND(&found_dict);
      {
        TNode<PropertyDictionary> dictionary = CAST(var_meta_storage.value());
        TNode<IntPtrT> entry = var_entry.value();
        TNode<Uint32T> details = LoadDetailsByKeyIndex(dictionary, entry);
        JumpIfDataProperty(details, &ok_to_write, readonly);

        if (accessor != nullptr) {
          // Accessor case.
          *var_accessor_pair = LoadValueByKeyIndex(dictionary, entry);
          *var_accessor_holder = holder;
          Goto(accessor);
        } else {
          Goto(&ok_to_write);
        }
      }

      BIND(&found_global);
      {
        TNode<GlobalDictionary> dictionary = CAST(var_meta_storage.value());
        TNode<IntPtrT> entry = var_entry.value();
        TNode<PropertyCell> property_cell =
            CAST(LoadValueByKeyIndex(dictionary, entry));
        TNode<Object> value =
            LoadObjectField(property_cell, PropertyCell::kValueOffset);
        GotoIf(TaggedEqual(value, TheHoleConstant()), &next_proto);
        TNode<Uint32T> details = Unsigned(LoadAndUntagToWord32ObjectField(
            property_cell, PropertyCell::kPropertyDetailsRawOffset));
        JumpIfDataProperty(details, &ok_to_write, readonly);

        if (accessor != nullptr) {
          // Accessor case.
          *var_accessor_pair = value;
          *var_accessor_holder = holder;
          Goto(accessor);
        } else {
          Goto(&ok_to_write);
        }
      }
    }

    BIND(&next_proto);
    // Bailout if it can be an integer indexed exotic case.
    GotoIf(IsJSTypedArrayInstanceType(instance_type), bailout);
    TNode<HeapObject> proto = LoadMapPrototype(holder_map);
    GotoIf(IsNull(proto), &ok_to_write);
    var_holder = proto;
    var_holder_map = LoadMap(proto);
    Goto(&loop);
  }
  BIND(&ok_to_write);
}

TNode<Map> KeyedStoreGenericAssembler::FindCandidateStoreICTransitionMapHandler(
    TNode<Map> map, TNode<Name> name, Label* slow) {
  TVARIABLE(Map, var_transition_map);
  Label simple_transition(this), transition_array(this),
      found_handler_candidate(this);

  TNode<MaybeObject> maybe_handler =
      LoadMaybeWeakObjectField(map, Map::kTransitionsOrPrototypeInfoOffset);

  // Smi -> slow,
  // Cleared weak reference -> slow
  // weak reference -> simple_transition
  // strong reference -> transition_array
  TVARIABLE(Object, var_transition_map_or_array);
  DispatchMaybeObject(maybe_handler, slow, slow, &simple_transition,
                      &transition_array, &var_transition_map_or_array);

  BIND(&simple_transition);
  {
    var_transition_map = CAST(var_transition_map_or_array.value());
    Goto(&found_handler_candidate);
  }

  BIND(&transition_array);
  {
    TNode<Map> maybe_handler_map =
        LoadMap(CAST(var_transition_map_or_array.value()));
    GotoIfNot(IsTransitionArrayMap(maybe_handler_map), slow);

    TVARIABLE(IntPtrT, var_name_index);
    Label if_found_candidate(this);
    TNode<TransitionArray> transitions =
        CAST(var_transition_map_or_array.value());
    TransitionLookup(name, transitions, &if_found_candidate, &var_name_index,
                     slow);

    BIND(&if_found_candidate);
    {
      // Given that
      // 1) transitions with the same name are ordered in the transition
      //    array by PropertyKind and then by PropertyAttributes values,
      // 2) kData < kAccessor,
      // 3) NONE == 0,
      // 4) properties with private symbol names are guaranteed to be
      //    non-enumerable (so DONT_ENUM bit in attributes is always set),
      // the resulting map of transitioning store if it exists in the
      // transition array is expected to be the first among the transitions
      // with the same name.
      // See TransitionArray::CompareDetails() for details.
      static_assert(static_cast<int>(PropertyKind::kData) == 0);
      static_assert(NONE == 0);
      const int kKeyToTargetOffset = (TransitionArray::kEntryTargetIndex -
                                      TransitionArray::kEntryKeyIndex) *
                                     kTaggedSize;
      var_transition_map = CAST(GetHeapObjectAssumeWeak(
          LoadArrayElement(transitions, OFFSET_OF_DATA_START(WeakFixedArray),
                           var_name_index.value(), kKeyToTargetOffset)));
      Goto(&found_handler_candidate);
    }
  }

  BIND(&found_handler_candidate);
  return var_transition_map.value();
}

void KeyedStoreGenericAssembler::EmitGenericPropertyStore(
    TNode<JSReceiver> receiver, TNode<Map> receiver_map,
    TNode<Uint16T> instance_type, const StoreICParameters* p,
    ExitPoint* exit_point, Label* slow, Maybe<LanguageMode> maybe_language_mode,
    UseStubCache use_stub_cache) {
  CSA_DCHECK(this, IsSimpleObjectMap(receiver_map));
  // TODO(rmcilroy) Type as Struct once we use a trimmed down
  // LoadAccessorFromFastObject instead of LoadPropertyFromFastObject.
  TVARIABLE(Object, var_accessor_pair);
  TVARIABLE(HeapObject, var_accessor_holder);
  Label fast_properties(this), dictionary_properties(this), accessor(this),
      readonly(this), try_stub_cache(this);
  TNode<Uint32T> bitfield3 = LoadMapBitField3(receiver_map);
  TNode<Name> name = CAST(p->name());
  Branch(IsSetWord32<Map::Bits3::IsDictionaryMapBit>(bitfield3),
         &dictionary_properties, &fast_properties);

  BIND(&fast_properties);
  {
    Comment("fast property store");
    TNode<DescriptorArray> descriptors = LoadMapDescriptors(receiver_map);
    Label descriptor_found(this), lookup_transition(this);
    TVARIABLE(IntPtrT, var_name_index);
    DescriptorLookup(name, descriptors, bitfield3,
                     IsAnyDefineOwn() ? slow : &descriptor_found,
                     &var_name_index, &lookup_transition);

    // When dealing with class fields defined with DefineKeyedOwnIC or
    // DefineNamedOwnIC, use the slow path to check the existing property.
    if (!IsAnyDefineOwn()) {
      BIND(&descriptor_found);
      {
        TNode<IntPtrT> name_index = var_name_index.value();
        TNode<Uint32T> details = LoadDetailsByKeyIndex(descriptors, name_index);
        Label data_property(this);
        JumpIfDataProperty(details, &data_property,
                           ShouldReconfigureExisting() ? nullptr : &readonly);

        if (ShouldCallSetter()) {
          // Accessor case.
          // TODO(jkummerow): Implement a trimmed-down
          // LoadAccessorFromFastObject.
          LoadPropertyFromFastObject(receiver, receiver_map, descriptors,
                                     name_index, details, &var_accessor_pair);
          var_accessor_holder = receiver;
          Goto(&accessor);
        } else {
          // Handle accessor to data property reconfiguration in runtime.
          Goto(slow);
        }

        BIND(&data_property);
        {
          Label shared(this);
          GotoIf(IsJSSharedStructInstanceType(instance_type), &shared);

          CheckForAssociatedProtector(name, slow);
          OverwriteExistingFastDataProperty(receiver, receiver_map, descriptors,
                                            name_index, details, p->value(),
                                            slow, false);
          exit_point->Return(p->value());

          BIND(&shared);
          {
            StoreJSSharedStructField(p->context(), receiver, receiver_map,
                                     descriptors, name_index, details,
                                     p->value());
            exit_point->Return(p->value());
          }
        }
      }
    }

    BIND(&lookup_transition);
    {
      Comment("lookup transition");
      CheckForAssociatedProtector(name, slow);

      DCHECK_IMPLIES(use_stub_cache == kUseStubCache, IsSet());
      Label* if_not_found =
          use_stub_cache == kUseStubCache ? &try_stub_cache : slow;

      TNode<Map> transition_map = FindCandidateStoreICTransitionMapHandler(
          receiver_map, name, if_not_found);

      // Validate the transition handler candidate and apply the transition.
      StoreTransitionMapFlags flags = kValidateTransitionHandler;
      if (ShouldCheckPrototypeValidity()) {
        flags = StoreTransitionMapFlags(flags | kCheckPrototypeValidity);
      }
      HandleStoreICTransitionMapHandlerCase(p, transition_map, slow, flags);
      exit_point->Return(p->value());
    }
  }

  BIND(&dictionary_properties);
  {
    Comment("dictionary property store");
    // We checked for LAST_CUSTOM_ELEMENTS_RECEIVER before, which rules out
    // seeing global objects here (which would need special handling).

    TVARIABLE(IntPtrT, var_name_index);
    Label dictionary_found(this, &var_name_index),
        not_found(this, &var_name_index);
    TNode<PropertyDictionary> properties = CAST(LoadSlowProperties(receiver));

    // When dealing with class fields defined with DefineKeyedOwnIC or
    // DefineNamedOwnIC, use the slow path to check the existing property.
    NameDictionaryLookup<PropertyDictionary>(
        properties, name, IsAnyDefineOwn() ? slow : &dictionary_found,
        &var_name_index, &not_found, kFindExistingOrInsertionIndex);

    if (!IsAnyDefineOwn()) {
      BIND(&dictionary_found);
      {
        Label check_const(this), overwrite(this), done(this);
        TNode<Uint32T> details =
            LoadDetailsByKeyIndex(properties, var_name_index.value());
        JumpIfDataProperty(details, &check_const,
                           ShouldReconfigureExisting() ? nullptr : &readonly);

        if (ShouldCallSetter()) {
          // Accessor case.
          var_accessor_pair =
              LoadValueByKeyIndex(properties, var_name_index.value());
          var_accessor_holder = receiver;
          Goto(&accessor);
        } else {
          // We must reconfigure an accessor property to a data property
          // here, let the runtime take care of that.
          Goto(slow);
        }

        BIND(&check_const);
        {
          if (V8_DICT_PROPERTY_CONST_TRACKING_BOOL) {
            GotoIfNot(IsPropertyDetailsConst(details), &overwrite);
            TNode<Object> prev_value =
                LoadValueByKeyIndex(properties, var_name_index.value());

            Branch(TaggedEqual(prev_value, p->value()), &done, slow);
          } else {
            Goto(&overwrite);
          }
        }

        BIND(&overwrite);
        {
          CheckForAssociatedProtector(name, slow);
          StoreValueByKeyIndex<PropertyDictionary>(
              properties, var_name_index.value(), p->value());
          Goto(&done);
        }

        BIND(&done);
        exit_point->Return(p->value());
      }
    }

    BIND(&not_found);
    {
      // TODO(jkummerow): Also add support to correctly handle integer exotic
      // cases for typed arrays and remove this check here.
      GotoIf(IsJSTypedArrayMap(receiver_map), slow);
      CheckForAssociatedProtector(name, slow);
      Label extensible(this), is_private_symbol(this);
      GotoIf(IsPrivateSymbol(name), &is_private_symbol);
      Branch(IsSetWord32<Map::Bits3::IsExtensibleBit>(bitfield3), &extensible,
             slow);

      BIND(&is_private_symbol);
      {
        CSA_DCHECK(this, IsPrivateSymbol(name));
        // For private names, we miss to the runtime which will throw.
        // For private symbols, we extend and store an own property.
        Branch(IsPrivateName(CAST(name)), slow, &extensible);
      }

      BIND(&extensible);
      if (ShouldCheckPrototype()) {
        DCHECK(ShouldCallSetter());
        LookupPropertyOnPrototypeChain(
            receiver_map, name, &accessor, &var_accessor_pair,
            &var_accessor_holder,
            ShouldReconfigureExisting() ? nullptr : &readonly, slow);
      }
      Label add_dictionary_property_slow(this);
      InvalidateValidityCellIfPrototype(receiver_map, bitfield3);
      UpdateMayHaveInterestingProperty(properties, name);
      AddToDictionary<PropertyDictionary>(properties, name, p->value(),
                                          &add_dictionary_property_slow,
                                          var_name_index.value());
      exit_point->Return(p->value());

      BIND(&add_dictionary_property_slow);
      exit_point->ReturnCallRuntime(Runtime::kAddDictionaryProperty,
                                    p->context(), p->receiver(), name,
                                    p->value());
    }
  }

  if (ShouldCallSetter()) {
    BIND(&accessor);
    {
      Label not_callable(this);
      TNode<HeapObject> accessor_pair = CAST(var_accessor_pair.value());
      GotoIf(IsAccessorInfo(accessor_pair), slow);
      CSA_DCHECK(this, IsAccessorPair(accessor_pair));
      TNode<HeapObject> setter =
          CAST(LoadObjectField(accessor_pair, AccessorPair::kSetterOffset));
      TNode<Map> setter_map = LoadMap(setter);
      // FunctionTemplateInfo setters are not supported yet.
      GotoIf(IsFunctionTemplateInfoMap(setter_map), slow);
      GotoIfNot(IsCallableMap(setter_map), &not_callable);

      Call(p->context(), setter, receiver, p->value());
      exit_point->Return(p->value());

      BIND(&not_callable);
      {
        LanguageMode language_mode;
        if (maybe_language_mode.To(&language_mode)) {
          if (language_mode == LanguageMode::kStrict) {
            exit_point->ReturnCallRuntime(
                Runtime::kThrowTypeError, p->context(),
                SmiConstant(MessageTemplate::kNoSetterInCallback), name,
                var_accessor_holder.value());
          } else {
            exit_point->Return(p->value());
          }
        } else {
          CallRuntime(Runtime::kThrowTypeErrorIfStrict, p->context(),
                      SmiConstant(MessageTemplate::kNoSetterInCallback), name,
                      var_accessor_holder.value());
          exit_point->Return(p->value());
        }
      }
    }
  }

  if (!ShouldReconfigureExisting() && !IsAnyDefineOwn()) {
    BIND(&readonly);
    {
      LanguageMode language_mode;
      if (maybe_language_mode.To(&language_mode)) {
        if (language_mode == LanguageMode::kStrict) {
          TNode<String> type = Typeof(p->receiver());
          ThrowTypeError(p->context(), MessageTemplate::kStrictReadOnlyProperty,
                         name, type, p->receiver());
        } else {
          exit_point->Return(p->value());
        }
      } else {
        CallRuntime(Runtime::kThrowTypeErrorIfStrict, p->context(),
                    SmiConstant(MessageTemplate::kStrictReadOnlyProperty), name,
                    Typeof(p->receiver()), p->receiver());
        exit_point->Return(p->value());
      }
    }
  }

  if (use_stub_cache == kUseStubCache) {
    DCHECK(IsSet());
    BIND(&try_stub_cache);
    // Do megamorphic cache lookup only for Api objects where it definitely
    // pays off.
    GotoIfNot(IsJSApiObjectInstanceType(instance_type), slow);

    Comment("stub cache probe");
    TVARIABLE(MaybeObject, var_handler);
    Label found_handler(this, &var_handler), stub_cache_miss(this);

    TryProbeStubCache(p->stub_cache(isolate()), receiver, name, &found_handler,
                      &var_handler, &stub_cache_miss);

    BIND(&found_handler);
    {
      Comment("KeyedStoreGeneric found handler");
      HandleStoreICHandlerCase(p, var_handler.value(), &stub_cache_miss,
                               ICMode::kNonGlobalIC);
    }
    BIND(&stub_cache_miss);
    {
      Comment("KeyedStoreGeneric_miss");
      TailCallRuntime(Runtime::kKeyedStoreIC_Miss, p->context(), p->value(),
                      p->slot(), p->vector(), p->receiver(), name);
    }
  }
}

// Helper that is used by the public KeyedStoreGeneric and by StoreProperty.
void KeyedStoreGenericAssembler::KeyedStoreGeneric(
    TNode<Context> context, TNode<Object> receiver_maybe_smi, TNode<Object> key,
    TNode<Object> value, Maybe<LanguageMode> language_mode,
    UseStubCache use_stub_cache, TNode<TaggedIndex> slot,
    TNode<HeapObject> maybe_vector) {
  DCHECK_IMPLIES(use_stub_cache == kUseStubCache, IsSet());
  TVARIABLE(IntPtrT, var_index);
  TVARIABLE(Name, var_unique);
  Label if_index(this, &var_index), if_unique_name(this),
      not_internalized(this), slow(this);

  GotoIf(TaggedIsSmi(receiver_maybe_smi), &slow);
  TNode<HeapObject> receiver = CAST(receiver_maybe_smi);
  TNode<Map> receiver_map = LoadMap(receiver);
  TNode<Uint16T> instance_type = LoadMapInstanceType(receiver_map);
  // Receivers requiring non-standard element accesses (interceptors, access
  // checks, strings and string wrappers, proxies) are handled in the runtime.
  GotoIf(IsCustomElementsReceiverInstanceType(instance_type), &slow);

  TryToName(key, &if_index, &var_index, &if_unique_name, &var_unique, &slow,
            &not_internalized);

  BIND(&if_index);
  {
    Comment("integer index");
    EmitGenericElementStore(CAST(receiver), receiver_map, instance_type,
                            var_index.value(), value, context, &slow);
  }

  BIND(&if_unique_name);
  {
    Comment("key is unique name");
    StoreICParameters p(context, receiver, var_unique.value(), value,
                        std::nullopt, slot, maybe_vector,
                        StoreICMode::kDefault);
    ExitPoint direct_exit(this);
    EmitGenericPropertyStore(CAST(receiver), receiver_map, instance_type, &p,
                             &direct_exit, &slow, language_mode,
                             use_stub_cache);
  }

  BIND(&not_internalized);
  {
    if (v8_flags.internalize_on_the_fly) {
      TryInternalizeString(CAST(key), &if_index, &var_index, &if_unique_name,
                           &var_unique, &slow, &slow);
    } else {
      Goto(&slow);
    }
  }

  BIND(&slow);
  {
    if (IsSet() || IsDefineNamedOwn()) {
      // The DefineNamedOwnIC hacky reuse should never reach here.
      CSA_DCHECK(this, BoolConstant(!IsDefineNamedOwn()));
      Comment("KeyedStoreGeneric_slow");
      TailCallRuntime(Runtime::kSetKeyedProperty, context, receiver, key,
                      value);
    } else if (IsDefineKeyedOwn()) {
      TailCallRuntime(Runtime::kDefineObjectOwnProperty, context, receiver, key,
                      value);
    } else {
      DCHECK(IsDefineKeyedOwnInLiteral());
      TNode<Smi> flags =
          SmiConstant(DefineKeyedOwnPropertyInLiteralFlag::kNoFlags);
      TNode<TaggedIndex> slot =
          TaggedIndexConstant(FeedbackSlot::Invalid().ToInt());
      TailCallRuntime(Runtime::kDefineKeyedOwnPropertyInLiteral, context,
                      receiver, key, value, flags, UndefinedConstant(), slot);
    }
  }
}

void KeyedStoreGenericAssembler::KeyedStoreGeneric() {
  using Descriptor = StoreNoFeedbackDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);

  KeyedStoreGeneric(context, receiver, name, value, Nothing<LanguageMode>());
}

void KeyedStoreGenericAssembler::KeyedStoreMegamorphic() {
  DCHECK(IsSet());  // Only [[Set]] handlers are stored in the stub cache.
  using Descriptor = StoreWithVectorDescriptor;

  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);
  auto slot = Parameter<TaggedIndex>(Descriptor::kSlot);
  auto maybe_vector = Parameter<HeapObject>(Descriptor::kVector);

  KeyedStoreGeneric(context, receiver, name, value, Nothing<LanguageMode>(),
                    kUseStubCache, slot, maybe_vector);
}

void KeyedStoreGenericAssembler::StoreProperty(TNode<Context> context,
                                               TNode<Object> receiver,
                                               TNode<Object> key,
                                               TNode<Object> value,
                                               LanguageMode language_mode) {
  KeyedStoreGeneric(context, receiver, key, value, Just(language_mode));
}

void KeyedStoreGenericAssembler::StoreIC_NoFeedback() {
  using Descriptor = StoreNoFeedbackDescriptor;

  auto receiver_maybe_smi = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label miss(this, Label::kDeferred), store_property(this);

  GotoIf(TaggedIsSmi(receiver_maybe_smi), &miss);

  {
    TNode<HeapObject> receiver = CAST(receiver_maybe_smi);
    TNode<Map> receiver_map = LoadMap(receiver);
    TNode<Uint16T> instance_type = LoadMapInstanceType(receiver_map);
    // Receivers requiring non-standard element accesses (interceptors, access
    // checks, strings and string wrappers, proxies) are handled in the runtime.
    GotoIf(IsSpecialReceiverInstanceType(instance_type), &miss);
    {
      StoreICParameters p(context, receiver, name, value, std::nullopt, {},
                          UndefinedConstant(),
                          IsDefineNamedOwn() ? StoreICMode::kDefineNamedOwn
                                             : StoreICMode::kDefault);
      EmitGenericPropertyStore(CAST(receiver), receiver_map, instance_type, &p,
                               &miss);
    }
  }

  BIND(&miss);
  {
    auto runtime = IsDefineNamedOwn() ? Runtime::kDefineNamedOwnIC_Miss
                                      : Runtime::kStoreIC_Miss;
    TNode<TaggedIndex> slot =
        TaggedIndexConstant(FeedbackSlot::Invalid().ToInt());
    TailCallRuntime(runtime, context, value, slot, UndefinedConstant(),
                    receiver_maybe_smi, name);
  }
}

void KeyedStoreGenericAssembler::StoreProperty(TNode<Context> context,
                                               TNode<JSReceiver> receiver,
                                               TNode<BoolT> is_simple_receiver,
                                               TNode<Name> unique_name,
                                               TNode<Object> value,
                                               LanguageMode language_mode) {
  StoreICParameters p(context, receiver, unique_name, value, std::nullopt, {},
                      UndefinedConstant(), StoreICMode::kDefault);

  Label done(this), slow(this, Label::kDeferred);
  ExitPoint exit_point(this, [&](TNode<Object> result) { Goto(&done); });

  CSA_DCHECK(this, Word32Equal(is_simple_receiver,
                               IsSimpleObjectMap(LoadMap(receiver))));
  GotoIfNot(is_simple_receiver, &slow);

  TNode<Map> map = LoadMap(receiver);
  TNode<Uint16T> instance_type = LoadMapInstanceType(map);
  EmitGenericPropertyStore(receiver, map, instance_type, &p, &exit_point, &slow,
                           Just(language_mode), kDontUseStubCache);

  BIND(&slow);
  {
    if (IsDefineKeyedOwnInLiteral()) {
      TNode<Smi> flags =
          SmiConstant(DefineKeyedOwnPropertyInLiteralFlag::kNoFlags);
      TNode<TaggedIndex> slot =
          TaggedIndexConstant(FeedbackSlot::Invalid().ToInt());
      CallRuntime(Runtime::kDefineKeyedOwnPropertyInLiteral, context, receiver,
                  unique_name, value, flags, p.vector(), slot);
    } else {
      CallRuntime(Runtime::kSetKeyedProperty, context, receiver, unique_name,
                  value);
    }
    Goto(&done);
  }

  BIND(&done);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```