Response:
Let's break down the request and the provided C++ header file.

**1. Understanding the Request:**

The user wants a functional description of the `v8/src/ic/accessor-assembler.h` file. Specifically, they're asking for:

* **Core Functionality:** What does this code do?
* **Torque Check:** Is it a Torque file (based on `.tq` extension)?
* **JavaScript Relationship:** How does it relate to JavaScript concepts?  Illustrate with JavaScript examples.
* **Logic Reasoning:** Provide examples of how the code might work with hypothetical inputs and outputs.
* **Common Programming Errors:** Highlight potential user-side errors that this code helps manage or avoid.

**2. Analyzing the Header File:**

The header file defines a C++ class named `AccessorAssembler` that inherits from `CodeStubAssembler`. This immediately tells us a few things:

* **Low-Level Code Generation:** The `Assembler` part strongly suggests this code is involved in generating machine code or an intermediate representation close to it.
* **IC (Inline Cache):** The `ic` directory points to code related to optimizing property access in JavaScript. Inline caches are a key technique for this.
* **"Accessor":** This hints at handling property access (both reading and writing).

**3. Deconstructing the Class Members:**

The `AccessorAssembler` class contains a large number of `Generate...IC...` methods. Let's categorize them:

* **LoadIC Family:** `GenerateLoadIC`, `GenerateLoadGlobalIC`, `GenerateLoadSuperIC`, `GenerateKeyedLoadIC`, `GenerateEnumeratedKeyedLoadIC`. These are clearly related to reading properties. The variations (Global, Super, Keyed, Enumerated) indicate different scenarios for property access.
* **StoreIC Family:** `GenerateStoreIC`, `GenerateStoreGlobalIC`, `GenerateDefineNamedOwnIC`, `GenerateDefineKeyedOwnIC`, `GenerateStoreInArrayLiteralIC`. These methods deal with writing or defining properties.
* **CloneObjectIC Family:** `GenerateCloneObjectIC`. This seems to handle object cloning.
* **KeyedHasIC Family:** `GenerateKeyedHasIC`. Related to checking if an object has a specific key.
* **Trampolines and Baselines:**  The terms "Trampoline" and "Baseline" are often associated with different stages of optimization. Trampolines might be temporary or generic entry points, while baselines represent a more optimized starting point.
* **NoFeedback:** Methods suffixed with `_NoFeedback` likely handle cases where the IC system hasn't collected enough information to optimize.
* **Megamorphic and Polymorphic:** These terms relate to the shape and types of objects being accessed. Megamorphic means many different shapes, while polymorphic means a few.
* **Helper Methods:**  Methods like `TryProbeStubCache`, `StubCachePrimaryOffsetForTesting`, `LoadHandlerDataField`, `HandleStoreICHandlerCase`, `HandleLoadICHandlerCase`, etc., provide the underlying logic for the `Generate...IC...` methods.
* **Internal Structs:** `LoadICParameters`, `LazyLoadICParameters`, `StoreICParameters` encapsulate the data needed for the IC operations.
* **`ExitPoint` Class:** This manages how the generated code exits (either by returning or jumping to another label).

**4. Connecting to JavaScript Concepts:**

The names of the `Generate...IC...` methods directly map to common JavaScript operations:

* **LoadIC:**  Reading a property (e.g., `object.property`).
* **StoreIC:** Writing a property (e.g., `object.property = value`).
* **LoadGlobalIC:** Accessing global variables (e.g., `window.variable` or just `variable`).
* **LoadSuperIC:** Accessing properties on the prototype chain within a class (`super.method()`).
* **KeyedLoadIC:** Reading properties using bracket notation (e.g., `object[key]`).
* **KeyedHasIC:** Checking if a property exists using bracket notation (`key in object`).
* **DefineNamedOwnIC/DefineKeyedOwnIC:** Defining new properties directly on an object (e.g., `Object.defineProperty`).
* **CloneObjectIC:** Creating a copy of an object (shallow or deep, depending on the specific implementation).

**5. Developing Logic Reasoning Examples:**

We can create hypothetical scenarios based on the method names and their likely purpose.

**6. Identifying Common Programming Errors:**

The IC system in V8 is designed to optimize property access, but it's often a consequence of JavaScript code. Common errors that might trigger different IC paths include:

* **Accessing non-existent properties:**  This might lead to `LoadIC_NoFeedback` or megamorphic paths.
* **Dynamically adding and deleting properties:** This can make it harder for V8 to optimize and might lead to megamorphic ICs.
* **Frequent changes in object structure:**  Creating objects with different sets of properties in different orders can hinder optimization.
* **Using bracket notation with unpredictable keys:**  While necessary in some cases, using variable keys for property access can be less optimizable than using dot notation with fixed property names.

**7. Structuring the Output:**

Finally, I need to organize the information into the format requested by the user, addressing each point systematically. This involves:

* Clearly stating the overall purpose of `AccessorAssembler`.
* Confirming that it's *not* a Torque file.
* Providing concrete JavaScript examples for the various `Generate...IC...` methods.
* Creating simple "input/output" examples for a few key methods.
* Listing common programming errors and explaining how they relate to the IC system.
`v8/src/ic/accessor-assembler.h` 是 V8 引擎中用于生成处理对象属性访问（读取和写入）的汇编代码的头文件。它定义了一个名为 `AccessorAssembler` 的 C++ 类，该类继承自 `CodeStubAssembler`，后者是 V8 中用于生成优化的机器代码的基类。

**功能列举:**

`AccessorAssembler` 类的主要功能是提供一系列方法，用于生成各种 Inline Cache (IC) 代码片段，这些代码片段用于加速 JavaScript 中常见的属性访问操作。以下是其主要功能的详细说明：

* **生成不同类型的 LoadIC 代码:**
    * `GenerateLoadIC()`: 生成通用的属性读取 IC 代码。
    * `GenerateLoadIC_Megamorphic()`: 生成处理多种对象形状（maps）的属性读取 IC 代码。
    * `GenerateLoadIC_Noninlined()`: 生成未内联到字节码处理器的属性读取 IC 代码。
    * `GenerateLoadIC_NoFeedback()`: 生成没有反馈信息的属性读取 IC 代码（例如，首次访问或发生错误后）。
    * `GenerateLoadGlobalIC_NoFeedback()`: 生成没有反馈信息的全局变量读取 IC 代码。
    * `GenerateLoadICTrampoline()`: 生成属性读取 IC 的跳板代码，用于在不同 IC 状态之间跳转。
    * `GenerateLoadICBaseline()`: 生成属性读取 IC 的基线代码，通常是优化程度较低的版本。
    * `GenerateLoadICTrampoline_Megamorphic()`: 生成处理多种对象形状的属性读取 IC 跳板代码。
    * `GenerateLoadSuperIC()`: 生成 `super` 关键字的属性读取 IC 代码。
    * `GenerateLoadSuperICBaseline()`: 生成 `super` 关键字的属性读取 IC 基线代码。
    * `GenerateKeyedLoadIC()`: 生成通过键（例如，数组索引或字符串）读取属性的 IC 代码。
    * `GenerateEnumeratedKeyedLoadIC()`: 生成在枚举过程中通过键读取属性的 IC 代码。
    * `GenerateKeyedLoadIC_Megamorphic()`: 生成处理多种对象形状的键属性读取 IC 代码。
    * `GenerateKeyedLoadIC_PolymorphicName()`: 生成处理少数几种属性名的键属性读取 IC 代码。
    * `GenerateKeyedLoadICTrampoline()`: 生成键属性读取 IC 的跳板代码。
    * `GenerateKeyedLoadICBaseline()`: 生成键属性读取 IC 的基线代码。
    * `GenerateEnumeratedKeyedLoadICBaseline()`: 生成枚举过程中键属性读取 IC 的基线代码。
    * `GenerateKeyedLoadICTrampoline_Megamorphic()`: 生成处理多种对象形状的键属性读取 IC 跳板代码。

* **生成不同类型的 StoreIC 代码:**
    * `GenerateStoreIC()`: 生成通用的属性写入 IC 代码。
    * `GenerateStoreIC_Megamorphic()`: 生成处理多种对象形状的属性写入 IC 代码。
    * `GenerateStoreICTrampoline()`: 生成属性写入 IC 的跳板代码。
    * `GenerateStoreICTrampoline_Megamorphic()`: 生成处理多种对象形状的属性写入 IC 跳板代码。
    * `GenerateStoreICBaseline()`: 生成属性写入 IC 的基线代码。
    * `GenerateDefineNamedOwnIC()`: 生成定义对象自身命名属性的 IC 代码。
    * `GenerateDefineNamedOwnICTrampoline()`: 生成定义对象自身命名属性的 IC 跳板代码。
    * `GenerateDefineNamedOwnICBaseline()`: 生成定义对象自身命名属性的 IC 基线代码。
    * `GenerateStoreGlobalIC()`: 生成全局变量写入的 IC 代码。
    * `GenerateStoreGlobalICTrampoline()`: 生成全局变量写入 IC 的跳板代码。
    * `GenerateStoreGlobalICBaseline()`: 生成全局变量写入 IC 的基线代码。

* **生成对象克隆 IC 代码:**
    * `GenerateCloneObjectIC()`: 生成对象克隆的 IC 代码。
    * `GenerateCloneObjectICBaseline()`: 生成对象克隆的 IC 基线代码。
    * `GenerateCloneObjectIC_Slow()`: 生成慢速的对象克隆代码，通常用于处理复杂情况。

* **生成 KeyedHasIC 代码:**
    * `GenerateKeyedHasIC()`: 生成检查对象是否拥有指定键的 IC 代码 (`in` 操作符)。
    * `GenerateKeyedHasICBaseline()`: 生成检查对象是否拥有指定键的 IC 基线代码。
    * `GenerateKeyedHasIC_Megamorphic()`: 生成处理多种对象形状的键存在性检查 IC 代码。
    * `GenerateKeyedHasIC_PolymorphicName()`: 生成处理少数几种属性名的键存在性检查 IC 代码。

* **生成带有 TypeofMode 的 Global 和 Context Lookup IC 代码:** 这些方法处理全局变量和上下文变量的查找，并考虑 `typeof` 运算符的特殊行为。

* **生成 KeyedStoreIC 代码:** 用于通过键写入属性。

* **生成 DefineKeyedOwnIC 代码:** 用于定义对象自身的键属性。

* **生成 StoreInArrayLiteralIC 代码:** 用于在数组字面量初始化时存储元素。

* **Stub Cache 探测:** `TryProbeStubCache` 方法用于在 StubCache 中查找已编译的处理器，以加速属性访问。

* **Stub Cache 偏移计算:** `StubCachePrimaryOffsetForTesting` 和 `StubCacheSecondaryOffsetForTesting` 用于计算 StubCache 中条目的偏移量，主要用于测试。

* **参数结构体:** `LoadICParameters`, `LazyLoadICParameters`, `StoreICParameters` 等结构体用于组织传递给各种 IC 生成方法的参数。

* **处理不同类型的 Handler:**  提供 `Handle...HandlerCase` 系列方法，用于处理不同类型的 Inline Cache Handler，这些 Handler 存储了优化后的属性访问信息。

* **辅助方法:** 包含一些辅助方法，例如 `JumpIfDataProperty`, `InvalidateValidityCellIfPrototype`, `OverwriteExistingFastDataProperty`, `CheckFieldType` 等，用于执行更细粒度的代码生成和条件判断。

**关于 .tq 结尾:**

如果 `v8/src/ic/accessor-assembler.h` 以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现运行时函数和内置函数。 然而，根据您提供的文件名 `accessor-assembler.h`，**它不是一个 Torque 文件**，而是一个标准的 C++ 头文件。

**与 Javascript 的关系 (举例说明):**

`AccessorAssembler` 生成的代码直接服务于 JavaScript 的属性访问操作。每当 JavaScript 代码尝试读取或写入对象的属性时，V8 引擎会尝试使用优化的 IC 代码来执行这些操作。

**JavaScript 示例:**

```javascript
const obj = { x: 10 };
const key = 'x';

// 属性读取 (对应 LoadIC)
const value1 = obj.x;         // GenerateLoadIC 或其变种
const value2 = obj[key];      // GenerateKeyedLoadIC 或其变种
const globalValue = window.Math; // GenerateLoadGlobalIC 或其变种

class MyClass {
  constructor() {
    this.y = 20;
  }
  getMethodValue() {
    return super.toString(); // GenerateLoadSuperIC 或其变种
  }
}

// 属性写入 (对应 StoreIC)
obj.x = 15;               // GenerateStoreIC 或其变种
obj['y'] = 25;            // GenerateKeyedStoreIC 或其变种
window.myGlobal = 30;     // GenerateStoreGlobalIC 或其变种

// 定义属性 (对应 DefineNamedOwnIC, DefineKeyedOwnIC)
Object.defineProperty(obj, 'z', { value: 30, writable: true });

// 检查属性是否存在 (对应 KeyedHasIC)
if ('x' in obj) {
  console.log('obj has x');
}

// 克隆对象 (对应 GenerateCloneObjectIC)
const clonedObj = { ...obj };
```

**代码逻辑推理 (假设输入与输出):**

假设我们有以下 JavaScript 代码：

```javascript
const myObject = { a: 1 };
const propertyName = 'a';
```

当执行 `myObject.a` 时，V8 可能会调用 `GenerateLoadIC` 相关的方法来生成代码。

**假设输入:**

* `lookup_start_object`: 指向 `myObject` 的指针。
* `name`: 指向表示字符串 "a" 的 `Name` 对象的指针。
* `slot`:  反馈向量中的一个槽位，用于存储有关此属性访问的信息。
* `vector`: 指向反馈向量的指针。

**可能的代码逻辑 (简化):**

1. **检查 Stub Cache:**  生成的代码首先会尝试在 Stub Cache 中查找是否已经存在针对 `myObject` 的 map 和属性名 "a" 的优化代码。
2. **Monomorphic Check:** 如果 Stub Cache 中没有，则会检查反馈向量中的信息。如果反馈向量指示此属性只在具有相同 "形状"（map）的对象上被访问过，则会生成针对该特定 map 的快速路径代码。
3. **Polymorphic Check:** 如果反馈向量指示此属性在少数几种不同的 "形状" 的对象上被访问过，则会生成检查这些常见形状的代码。
4. **Megamorphic Case:** 如果属性在很多不同 "形状" 的对象上被访问过，则会生成更通用的代码，可能涉及查找属性字典。
5. **Handler Call:** 如果找到了匹配的优化代码（handler），则会跳转到该 handler 执行，直接获取属性值。
6. **Miss Handler:** 如果所有优化路径都失败，则会跳转到 "miss" 标签，执行更慢速的通用属性访问逻辑，并可能更新反馈向量以供未来优化。

**假设输出 (如果命中 Monomorphic Cache):**

生成的汇编代码可能会直接从 `myObject` 的已知偏移量处加载属性 "a" 的值，并将其存储到寄存器中。

**用户常见的编程错误:**

`AccessorAssembler` 生成的代码旨在优化常见的属性访问模式。然而，某些 JavaScript 编程模式可能会导致 IC 无法有效优化，从而降低性能。一些常见的编程错误包括：

* **频繁修改对象的形状 (添加或删除属性):** 这会导致 IC 反复失效，因为之前优化的代码不再适用。例如：

```javascript
const obj = {};
if (someCondition) {
  obj.a = 1;
}
if (anotherCondition) {
  obj.b = 2;
}
// 访问 obj.a 或 obj.b 的时候，V8 需要处理多种可能的对象形状
```

* **以不一致的顺序添加属性:** 即使最终对象的属性相同，以不同的顺序添加属性也会导致不同的对象形状。

```javascript
const createObj1 = () => { const o = {}; o.a = 1; o.b = 2; return o; };
const createObj2 = () => { const o = {}; o.b = 2; o.a = 1; return o; };
const obj1 = createObj1();
const obj2 = createObj2();
// obj1 和 obj2 的形状不同，即使它们具有相同的属性
```

* **过度使用动态属性名称:** 虽然 `obj[variable]` 很灵活，但如果 `variable` 的值经常变化，会导致难以优化。

```javascript
const obj = { a: 1, b: 2 };
const keys = ['a', 'b'];
for (let i = 0; i < keys.length; i++) {
  console.log(obj[keys[i]]); // 如果 keys 数组内容动态变化，优化会更困难
}
```

* **访问未定义的属性:** 虽然 JavaScript 不会抛出错误，但频繁访问未定义的属性会增加 IC 的 "miss" 率。

通过理解 `AccessorAssembler` 的功能，开发者可以编写更易于 V8 优化的 JavaScript 代码，从而提高应用程序的性能。

Prompt: 
```
这是目录为v8/src/ic/accessor-assembler.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/accessor-assembler.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明

"""
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_IC_ACCESSOR_ASSEMBLER_H_
#define V8_IC_ACCESSOR_ASSEMBLER_H_

#include <optional>

#include "src/codegen/code-stub-assembler.h"
#include "src/compiler/code-assembler.h"
#include "src/objects/dictionary.h"

namespace v8 {
namespace internal {

namespace compiler {
class CodeAssemblerState;
}  // namespace compiler

class ExitPoint;

class V8_EXPORT_PRIVATE AccessorAssembler : public CodeStubAssembler {
 public:
  explicit AccessorAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

  void GenerateLoadIC();
  void GenerateLoadIC_Megamorphic();
  void GenerateLoadIC_Noninlined();
  void GenerateLoadIC_NoFeedback();
  void GenerateLoadGlobalIC_NoFeedback();
  void GenerateLoadICTrampoline();
  void GenerateLoadICBaseline();
  void GenerateLoadICTrampoline_Megamorphic();
  void GenerateLoadSuperIC();
  void GenerateLoadSuperICBaseline();
  void GenerateKeyedLoadIC();
  void GenerateEnumeratedKeyedLoadIC();
  void GenerateKeyedLoadIC_Megamorphic();
  void GenerateKeyedLoadIC_PolymorphicName();
  void GenerateKeyedLoadICTrampoline();
  void GenerateKeyedLoadICBaseline();
  void GenerateEnumeratedKeyedLoadICBaseline();
  void GenerateKeyedLoadICTrampoline_Megamorphic();
  void GenerateStoreIC();
  void GenerateStoreIC_Megamorphic();
  void GenerateStoreICTrampoline();
  void GenerateStoreICTrampoline_Megamorphic();
  void GenerateStoreICBaseline();
  void GenerateDefineNamedOwnIC();
  void GenerateDefineNamedOwnICTrampoline();
  void GenerateDefineNamedOwnICBaseline();
  void GenerateStoreGlobalIC();
  void GenerateStoreGlobalICTrampoline();
  void GenerateStoreGlobalICBaseline();
  void GenerateCloneObjectIC();
  void GenerateCloneObjectICBaseline();
  void GenerateCloneObjectIC_Slow();
  void GenerateKeyedHasIC();
  void GenerateKeyedHasICBaseline();
  void GenerateKeyedHasIC_Megamorphic();
  void GenerateKeyedHasIC_PolymorphicName();

  void GenerateLoadGlobalIC(TypeofMode typeof_mode);
  void GenerateLoadGlobalICTrampoline(TypeofMode typeof_mode);
  void GenerateLoadGlobalICBaseline(TypeofMode typeof_mode);
  void GenerateLookupGlobalIC(TypeofMode typeof_mode);
  void GenerateLookupGlobalICTrampoline(TypeofMode typeof_mode);
  void GenerateLookupGlobalICBaseline(TypeofMode typeof_mode);
  void GenerateLookupContextTrampoline(TypeofMode typeof_mode,
                                       ContextKind context_kind);
  void GenerateLookupContextBaseline(TypeofMode typeof_mode,
                                     ContextKind context_kind);

  void GenerateKeyedStoreIC();
  void GenerateKeyedStoreICTrampoline();
  void GenerateKeyedStoreICTrampoline_Megamorphic();
  void GenerateKeyedStoreICBaseline();

  void GenerateDefineKeyedOwnIC();
  void GenerateDefineKeyedOwnICTrampoline();
  void GenerateDefineKeyedOwnICBaseline();

  void GenerateStoreInArrayLiteralIC();
  void GenerateStoreInArrayLiteralICBaseline();

  void TryProbeStubCache(StubCache* stub_cache,
                         TNode<Object> lookup_start_object,
                         TNode<Map> lookup_start_object_map, TNode<Name> name,
                         Label* if_handler, TVariable<MaybeObject>* var_handler,
                         Label* if_miss);
  void TryProbeStubCache(StubCache* stub_cache,
                         TNode<Object> lookup_start_object, TNode<Name> name,
                         Label* if_handler, TVariable<MaybeObject>* var_handler,
                         Label* if_miss) {
    return TryProbeStubCache(stub_cache, lookup_start_object,
                             LoadReceiverMap(lookup_start_object), name,
                             if_handler, var_handler, if_miss);
  }

  TNode<IntPtrT> StubCachePrimaryOffsetForTesting(TNode<Name> name,
                                                  TNode<Map> map) {
    return StubCachePrimaryOffset(name, map);
  }
  TNode<IntPtrT> StubCacheSecondaryOffsetForTesting(TNode<Name> name,
                                                    TNode<Map> map) {
    return StubCacheSecondaryOffset(name, map);
  }

  struct LoadICParameters {
    LoadICParameters(
        TNode<Context> context, TNode<Object> receiver, TNode<Object> name,
        TNode<TaggedIndex> slot, TNode<HeapObject> vector,
        std::optional<TNode<Object>> lookup_start_object = std::nullopt,
        std::optional<TNode<Smi>> enum_index = std::nullopt,
        std::optional<TNode<Object>> cache_type = std::nullopt)
        : context_(context),
          receiver_(receiver),
          name_(name),
          slot_(slot),
          vector_(vector),
          lookup_start_object_(lookup_start_object ? lookup_start_object.value()
                                                   : receiver),
          enum_index_(enum_index),
          cache_type_(cache_type) {}

    LoadICParameters(const LoadICParameters* p, TNode<Object> unique_name)
        : context_(p->context_),
          receiver_(p->receiver_),
          name_(unique_name),
          slot_(p->slot_),
          vector_(p->vector_),
          lookup_start_object_(p->lookup_start_object_) {}

    TNode<Context> context() const { return context_; }
    TNode<Object> receiver() const { return receiver_; }
    TNode<Object> name() const { return name_; }
    TNode<TaggedIndex> slot() const { return slot_; }
    TNode<HeapObject> vector() const { return vector_; }
    TNode<Object> lookup_start_object() const {
      return lookup_start_object_.value();
    }
    TNode<Smi> enum_index() const { return *enum_index_; }
    TNode<Object> cache_type() const { return *cache_type_; }

    // Usable in cases where the receiver and the lookup start object are
    // expected to be the same, i.e., when "receiver != lookup_start_object"
    // case is not supported or not expected by the surrounding code.
    TNode<Object> receiver_and_lookup_start_object() const {
      DCHECK_EQ(receiver_, lookup_start_object_);
      return receiver_;
    }

    bool IsEnumeratedKeyedLoad() const { return enum_index_ != std::nullopt; }

   private:
    TNode<Context> context_;
    TNode<Object> receiver_;
    TNode<Object> name_;
    TNode<TaggedIndex> slot_;
    TNode<HeapObject> vector_;
    std::optional<TNode<Object>> lookup_start_object_;
    std::optional<TNode<Smi>> enum_index_;
    std::optional<TNode<Object>> cache_type_;
  };

  struct LazyLoadICParameters {
    LazyLoadICParameters(
        LazyNode<Context> context, TNode<Object> receiver,
        LazyNode<Object> name, LazyNode<TaggedIndex> slot,
        TNode<HeapObject> vector,
        std::optional<TNode<Object>> lookup_start_object = std::nullopt)
        : context_(context),
          receiver_(receiver),
          name_(name),
          slot_(slot),
          vector_(vector),
          lookup_start_object_(lookup_start_object ? lookup_start_object.value()
                                                   : receiver) {}

    explicit LazyLoadICParameters(const LoadICParameters* p)
        : receiver_(p->receiver()),
          vector_(p->vector()),
          lookup_start_object_(p->lookup_start_object()) {
      slot_ = [=] { return p->slot(); };
      context_ = [=] { return p->context(); };
      name_ = [=] { return p->name(); };
    }

    TNode<Context> context() const { return context_(); }
    TNode<Object> receiver() const { return receiver_; }
    TNode<Object> name() const { return name_(); }
    TNode<TaggedIndex> slot() const { return slot_(); }
    TNode<HeapObject> vector() const { return vector_; }
    TNode<Object> lookup_start_object() const { return lookup_start_object_; }

    // Usable in cases where the receiver and the lookup start object are
    // expected to be the same, i.e., when "receiver != lookup_start_object"
    // case is not supported or not expected by the surrounding code.
    TNode<Object> receiver_and_lookup_start_object() const {
      DCHECK_EQ(receiver_, lookup_start_object_);
      return receiver_;
    }

   private:
    LazyNode<Context> context_;
    TNode<Object> receiver_;
    LazyNode<Object> name_;
    LazyNode<TaggedIndex> slot_;
    TNode<HeapObject> vector_;
    TNode<Object> lookup_start_object_;
  };

  void LoadGlobalIC(TNode<HeapObject> maybe_feedback_vector,
                    const LazyNode<TaggedIndex>& lazy_slot,
                    const LazyNode<Context>& lazy_context,
                    const LazyNode<Name>& lazy_name, TypeofMode typeof_mode,
                    ExitPoint* exit_point);

  // Specialized LoadIC for inlined bytecode handler, hand-tuned to omit frame
  // construction on common paths.
  void LoadIC_BytecodeHandler(const LazyLoadICParameters* p,
                              ExitPoint* exit_point);

  // Loads dataX field from the DataHandler object.
  TNode<MaybeObject> LoadHandlerDataField(TNode<DataHandler> handler,
                                          int data_index);

 protected:
  enum class StoreICMode {
    // TODO(v8:12548): rename to kDefineKeyedOwnInLiteral
    kDefault,
    kDefineNamedOwn,
    kDefineKeyedOwn,
  };
  struct StoreICParameters {
    StoreICParameters(TNode<Context> context,
                      std::optional<TNode<Object>> receiver, TNode<Object> name,
                      TNode<Object> value, std::optional<TNode<Smi>> flags,
                      TNode<TaggedIndex> slot, TNode<HeapObject> vector,
                      StoreICMode mode)
        : context_(context),
          receiver_(receiver),
          name_(name),
          value_(value),
          flags_(flags),
          slot_(slot),
          vector_(vector),
          mode_(mode) {}

    TNode<Context> context() const { return context_; }
    TNode<Object> receiver() const { return receiver_.value(); }
    TNode<Object> name() const { return name_; }
    TNode<Object> value() const { return value_; }
    TNode<Smi> flags() const { return flags_.value(); }
    TNode<TaggedIndex> slot() const { return slot_; }
    TNode<HeapObject> vector() const { return vector_; }

    TNode<Object> lookup_start_object() const { return receiver(); }

    bool receiver_is_null() const { return !receiver_.has_value(); }
    bool flags_is_null() const { return !flags_.has_value(); }

    bool IsDefineNamedOwn() const {
      return mode_ == StoreICMode::kDefineNamedOwn;
    }
    bool IsDefineKeyedOwn() const {
      return mode_ == StoreICMode::kDefineKeyedOwn;
    }
    bool IsAnyDefineOwn() const {
      return IsDefineNamedOwn() || IsDefineKeyedOwn();
    }

    StubCache* stub_cache(Isolate* isolate) const {
      return IsAnyDefineOwn() ? isolate->define_own_stub_cache()
                              : isolate->store_stub_cache();
    }

   private:
    TNode<Context> context_;
    std::optional<TNode<Object>> receiver_;
    TNode<Object> name_;
    TNode<Object> value_;
    std::optional<TNode<Smi>> flags_;
    TNode<TaggedIndex> slot_;
    TNode<HeapObject> vector_;
    StoreICMode mode_;
  };

  enum class LoadAccessMode { kLoad, kHas };
  enum class ICMode { kNonGlobalIC, kGlobalIC };
  enum ElementSupport { kOnlyProperties, kSupportElements };
  void HandleStoreICHandlerCase(
      const StoreICParameters* p, TNode<MaybeObject> handler, Label* miss,
      ICMode ic_mode, ElementSupport support_elements = kOnlyProperties);
  enum StoreTransitionMapFlags {
    kDontCheckPrototypeValidity = 0,
    kCheckPrototypeValidity = 1 << 0,
    kValidateTransitionHandler = 1 << 1,
    kStoreTransitionMapFlagsMask =
        kCheckPrototypeValidity | kValidateTransitionHandler,
  };
  void HandleStoreICTransitionMapHandlerCase(const StoreICParameters* p,
                                             TNode<Map> transition_map,
                                             Label* miss,
                                             StoreTransitionMapFlags flags);

  // Updates flags on |dict| if |name| is an interesting property.
  void UpdateMayHaveInterestingProperty(TNode<PropertyDictionary> dict,
                                        TNode<Name> name);

  void JumpIfDataProperty(TNode<Uint32T> details, Label* writable,
                          Label* readonly);

  void InvalidateValidityCellIfPrototype(
      TNode<Map> map, std::optional<TNode<Uint32T>> bitfield3 = std::nullopt);

  void OverwriteExistingFastDataProperty(TNode<HeapObject> object,
                                         TNode<Map> object_map,
                                         TNode<DescriptorArray> descriptors,
                                         TNode<IntPtrT> descriptor_name_index,
                                         TNode<Uint32T> details,
                                         TNode<Object> value, Label* slow,
                                         bool do_transitioning_store);

  void StoreJSSharedStructField(TNode<Context> context,
                                TNode<HeapObject> shared_struct,
                                TNode<Map> shared_struct_map,
                                TNode<DescriptorArray> descriptors,
                                TNode<IntPtrT> descriptor_name_index,
                                TNode<Uint32T> details, TNode<Object> value);

  TNode<BoolT> IsPropertyDetailsConst(TNode<Uint32T> details);

  void CheckFieldType(TNode<DescriptorArray> descriptors,
                      TNode<IntPtrT> name_index, TNode<Word32T> representation,
                      TNode<Object> value, Label* bailout);

 private:
  // Stub generation entry points.

  // LoadIC contains the full LoadIC logic, while LoadIC_Noninlined contains
  // logic not inlined into Ignition bytecode handlers.
  void LoadIC(const LoadICParameters* p);

  // Can be used in the receiver != lookup_start_object case.
  void LoadIC_Noninlined(const LoadICParameters* p,
                         TNode<Map> lookup_start_object_map,
                         TNode<HeapObject> feedback,
                         TVariable<MaybeObject>* var_handler, Label* if_handler,
                         Label* miss, ExitPoint* exit_point);

  void LoadSuperIC(const LoadICParameters* p);

  TNode<Object> LoadDescriptorValue(TNode<Map> map,
                                    TNode<IntPtrT> descriptor_entry);
  TNode<MaybeObject> LoadDescriptorValueOrFieldType(
      TNode<Map> map, TNode<IntPtrT> descriptor_entry);

  void LoadIC_NoFeedback(const LoadICParameters* p, TNode<Smi> smi_typeof_mode);
  void LoadSuperIC_NoFeedback(const LoadICParameters* p);
  void LoadGlobalIC_NoFeedback(TNode<Context> context, TNode<Object> name,
                               TNode<Smi> smi_typeof_mode);

  void KeyedLoadIC(const LoadICParameters* p, LoadAccessMode access_mode);
  void KeyedLoadICGeneric(const LoadICParameters* p);
  void KeyedLoadICPolymorphicName(const LoadICParameters* p,
                                  LoadAccessMode access_mode);

  void StoreIC(const StoreICParameters* p);
  void StoreGlobalIC(const StoreICParameters* p);
  void StoreGlobalIC_PropertyCellCase(TNode<PropertyCell> property_cell,
                                      TNode<Object> value,
                                      ExitPoint* exit_point, Label* miss);
  void KeyedStoreIC(const StoreICParameters* p);
  void DefineKeyedOwnIC(const StoreICParameters* p);
  void StoreInArrayLiteralIC(const StoreICParameters* p);

  void LookupGlobalIC(LazyNode<Object> lazy_name, TNode<TaggedIndex> depth,
                      LazyNode<TaggedIndex> lazy_slot, TNode<Context> context,
                      LazyNode<FeedbackVector> lazy_feedback_vector,
                      TypeofMode typeof_mode);
  void LookupContext(LazyNode<Object> lazy_name, TNode<TaggedIndex> depth,
                     LazyNode<TaggedIndex> lazy_slot, TNode<Context> context,
                     TypeofMode typeof_mode, ContextKind context_kind);

  void GotoIfNotSameNumberBitPattern(TNode<Float64T> left,
                                     TNode<Float64T> right, Label* miss);

  // IC dispatcher behavior.

  // Checks monomorphic case. Returns {feedback} entry of the vector.
  TNode<HeapObjectReference> TryMonomorphicCase(
      TNode<TaggedIndex> slot, TNode<FeedbackVector> vector,
      TNode<HeapObjectReference> weak_lookup_start_object_map,
      Label* if_handler, TVariable<MaybeObject>* var_handler, Label* if_miss);
  void HandlePolymorphicCase(
      TNode<HeapObjectReference> weak_lookup_start_object_map,
      TNode<WeakFixedArray> feedback, Label* if_handler,
      TVariable<MaybeObject>* var_handler, Label* if_miss);

  void TryMegaDOMCase(TNode<Object> lookup_start_object,
                      TNode<Map> lookup_start_object_map,
                      TVariable<MaybeObject>* var_handler, TNode<Object> vector,
                      TNode<TaggedIndex> slot, Label* miss,
                      ExitPoint* exit_point);

  void TryEnumeratedKeyedLoad(const LoadICParameters* p,
                              TNode<Map> lookup_start_object_map,
                              ExitPoint* exit_point);

  // LoadIC implementation.
  void HandleLoadICHandlerCase(
      const LazyLoadICParameters* p, TNode<MaybeObject> handler, Label* miss,
      ExitPoint* exit_point, ICMode ic_mode = ICMode::kNonGlobalIC,
      OnNonExistent on_nonexistent = OnNonExistent::kReturnUndefined,
      ElementSupport support_elements = kOnlyProperties,
      LoadAccessMode access_mode = LoadAccessMode::kLoad);

  void HandleLoadICSmiHandlerCase(const LazyLoadICParameters* p,
                                  TNode<Object> holder, TNode<Smi> smi_handler,
                                  TNode<MaybeObject> handler, Label* miss,
                                  ExitPoint* exit_point, ICMode ic_mode,
                                  OnNonExistent on_nonexistent,
                                  ElementSupport support_elements,
                                  LoadAccessMode access_mode);

  void HandleLoadICProtoHandler(const LazyLoadICParameters* p,
                                TNode<DataHandler> handler,
                                TVariable<Object>* var_holder,
                                TVariable<MaybeObject>* var_smi_handler,
                                Label* if_smi_handler, Label* miss,
                                ExitPoint* exit_point, ICMode ic_mode,
                                LoadAccessMode access_mode);

  void HandleLoadCallbackProperty(const LazyLoadICParameters* p,
                                  TNode<JSObject> holder,
                                  TNode<Word32T> handler_word,
                                  ExitPoint* exit_point);

  void HandleLoadAccessor(const LazyLoadICParameters* p,
                          TNode<FunctionTemplateInfo> function_template_info,
                          TNode<Word32T> handler_word,
                          TNode<DataHandler> handler,
                          TNode<Uint32T> handler_kind, ExitPoint* exit_point);

  void HandleLoadField(TNode<JSObject> holder, TNode<Word32T> handler_word,
                       TVariable<Float64T>* var_double_value,
                       Label* rebox_double, Label* miss, ExitPoint* exit_point);

#if V8_ENABLE_WEBASSEMBLY
  void HandleLoadWasmField(TNode<WasmObject> holder,
                           TNode<Int32T> wasm_value_type,
                           TNode<IntPtrT> field_offset,
                           TVariable<Float64T>* var_double_value,
                           Label* rebox_double, ExitPoint* exit_point);

  void HandleLoadWasmField(TNode<WasmObject> holder,
                           TNode<Word32T> handler_word,
                           TVariable<Float64T>* var_double_value,
                           Label* rebox_double, ExitPoint* exit_point);
#endif  // V8_ENABLE_WEBASSEMBLY

  void EmitAccessCheck(TNode<Context> expected_native_context,
                       TNode<Context> context, TNode<Object> receiver,
                       Label* can_access, Label* miss);

  void HandleLoadICSmiHandlerLoadNamedCase(
      const LazyLoadICParameters* p, TNode<Object> holder,
      TNode<Uint32T> handler_kind, TNode<Word32T> handler_word,
      Label* rebox_double, TVariable<Float64T>* var_double_value,
      TNode<MaybeObject> handler, Label* miss, ExitPoint* exit_point,
      ICMode ic_mode, OnNonExistent on_nonexistent,
      ElementSupport support_elements);

  void HandleLoadICSmiHandlerHasNamedCase(const LazyLoadICParameters* p,
                                          TNode<Object> holder,
                                          TNode<Uint32T> handler_kind,
                                          Label* miss, ExitPoint* exit_point,
                                          ICMode ic_mode);

  // LoadGlobalIC implementation.

  void LoadGlobalIC_TryPropertyCellCase(TNode<FeedbackVector> vector,
                                        TNode<TaggedIndex> slot,
                                        const LazyNode<Context>& lazy_context,
                                        ExitPoint* exit_point,
                                        Label* try_handler, Label* miss);

  void LoadGlobalIC_TryHandlerCase(TNode<FeedbackVector> vector,
                                   TNode<TaggedIndex> slot,
                                   const LazyNode<Context>& lazy_context,
                                   const LazyNode<Name>& lazy_name,
                                   TypeofMode typeof_mode,
                                   ExitPoint* exit_point, Label* miss);

  // This is a copy of ScriptContextTable::Lookup. They should be kept in sync.
  void ScriptContextTableLookup(TNode<Name> name,
                                TNode<NativeContext> native_context,
                                Label* found_hole, Label* not_found);

  // StoreIC implementation.

  void HandleStoreICProtoHandler(const StoreICParameters* p,
                                 TNode<StoreHandler> handler, Label* slow,
                                 Label* miss, ICMode ic_mode,
                                 ElementSupport support_elements);
  void HandleStoreICSmiHandlerCase(TNode<Word32T> handler_word,
                                   TNode<JSObject> holder, TNode<Object> value,
                                   Label* miss);
  void HandleStoreICSmiHandlerJSSharedStructFieldCase(
      TNode<Context> context, TNode<Word32T> handler_word,
      TNode<JSObject> holder, TNode<Object> value);
  void HandleStoreFieldAndReturn(TNode<Word32T> handler_word,
                                 TNode<JSObject> holder, TNode<Object> value,
                                 std::optional<TNode<Float64T>> double_value,
                                 Representation representation, Label* miss);

  void CheckPrototypeValidityCell(TNode<Object> maybe_validity_cell,
                                  Label* miss);
  void HandleStoreICNativeDataProperty(const StoreICParameters* p,
                                       TNode<HeapObject> holder,
                                       TNode<Word32T> handler_word);

  void HandleStoreToProxy(const StoreICParameters* p, TNode<JSProxy> proxy,
                          Label* miss, ElementSupport support_elements);

  // KeyedLoadIC_Generic implementation.

  void GenericElementLoad(TNode<HeapObject> lookup_start_object,
                          TNode<Map> lookup_start_object_map,
                          TNode<Int32T> lookup_start_object_instance_type,
                          TNode<IntPtrT> index, Label* slow);

  enum UseStubCache { kUseStubCache, kDontUseStubCache };
  void GenericPropertyLoad(TNode<HeapObject> lookup_start_object,
                           TNode<Map> lookup_start_object_map,
                           TNode<Int32T> lookup_start_object_instance_type,
                           const LoadICParameters* p, Label* slow,
                           UseStubCache use_stub_cache = kUseStubCache);

  // Low-level helpers.

  using OnCodeHandler = std::function<void(TNode<Code> code_handler)>;
  using OnFoundOnLookupStartObject = std::function<void(
      TNode<PropertyDictionary> properties, TNode<IntPtrT> name_index)>;

  template <typename ICHandler, typename ICParameters>
  TNode<Object> HandleProtoHandler(
      const ICParameters* p, TNode<DataHandler> handler,
      const OnCodeHandler& on_code_handler,
      const OnFoundOnLookupStartObject& on_found_on_lookup_start_object,
      Label* miss, ICMode ic_mode);

  void CheckHeapObjectTypeMatchesDescriptor(TNode<Word32T> handler_word,
                                            TNode<JSObject> holder,
                                            TNode<Object> value,
                                            Label* bailout);
  // Double fields store double values in a mutable box, where stores are
  // writes into this box rather than HeapNumber assignment.
  void CheckDescriptorConsidersNumbersMutable(TNode<Word32T> handler_word,
                                              TNode<JSObject> holder,
                                              Label* bailout);

  // Extends properties backing store by JSObject::kFieldsAdded elements,
  // returns updated properties backing store.
  TNode<PropertyArray> ExtendPropertiesBackingStore(TNode<HeapObject> object,
                                                    TNode<IntPtrT> index);

  void EmitFastElementsBoundsCheck(TNode<JSObject> object,
                                   TNode<FixedArrayBase> elements,
                                   TNode<IntPtrT> intptr_index,
                                   TNode<BoolT> is_jsarray_condition,
                                   Label* miss);
  void EmitElementLoad(TNode<HeapObject> object, TNode<Word32T> elements_kind,
                       TNode<IntPtrT> key, TNode<BoolT> is_jsarray_condition,
                       Label* if_hole, Label* rebox_double,
                       TVariable<Float64T>* var_double_value,
                       Label* unimplemented_elements_kind, Label* out_of_bounds,
                       Label* miss, ExitPoint* exit_point,
                       LoadAccessMode access_mode = LoadAccessMode::kLoad);

  // Stub cache access helpers.

  // This enum is used here as a replacement for StubCache::Table to avoid
  // including stub cache header.
  enum StubCacheTable : int;

  TNode<IntPtrT> StubCachePrimaryOffset(TNode<Name> name, TNode<Map> map);
  TNode<IntPtrT> StubCacheSecondaryOffset(TNode<Name> name, TNode<Map> map);

  void TryProbeStubCacheTable(StubCache* stub_cache, StubCacheTable table_id,
                              TNode<IntPtrT> entry_offset, TNode<Object> name,
                              TNode<Map> map, Label* if_handler,
                              TVariable<MaybeObject>* var_handler,
                              Label* if_miss);

  void BranchIfPrototypesHaveNoElements(TNode<Map> receiver_map,
                                        Label* definitely_no_elements,
                                        Label* possibly_elements);
};

// Abstraction over direct and indirect exit points. Direct exits correspond to
// tailcalls and Return, while indirect exits store the result in a variable
// and then jump to an exit label.
class ExitPoint {
 private:
  using CodeAssemblerLabel = compiler::CodeAssemblerLabel;

 public:
  using IndirectReturnHandler = std::function<void(TNode<Object> result)>;

  explicit ExitPoint(CodeStubAssembler* assembler)
      : ExitPoint(assembler, nullptr) {}

  ExitPoint(CodeStubAssembler* assembler,
            const IndirectReturnHandler& indirect_return_handler)
      : asm_(assembler), indirect_return_handler_(indirect_return_handler) {}

  ExitPoint(CodeStubAssembler* assembler, CodeAssemblerLabel* out,
            compiler::CodeAssembler::TVariable<Object>* var_result)
      : ExitPoint(assembler, [=](TNode<Object> result) {
          *var_result = result;
          assembler->Goto(out);
        }) {
    DCHECK_EQ(out != nullptr, var_result != nullptr);
  }

  template <class... TArgs>
  void ReturnCallRuntime(Runtime::FunctionId function, TNode<Context> context,
                         TArgs... args) {
    if (IsDirect()) {
      asm_->TailCallRuntime(function, context, args...);
    } else {
      indirect_return_handler_(asm_->CallRuntime(function, context, args...));
    }
  }

  template <class... TArgs>
  void ReturnCallBuiltin(Builtin builtin, TNode<Context> context,
                         TArgs... args) {
    if (IsDirect()) {
      asm_->TailCallBuiltin(builtin, context, args...);
    } else {
      indirect_return_handler_(asm_->CallBuiltin(builtin, context, args...));
    }
  }

  template <class... TArgs>
  void ReturnCallStub(const CallInterfaceDescriptor& descriptor,
                      TNode<Code> target, TNode<Context> context,
                      TArgs... args) {
    if (IsDirect()) {
      asm_->TailCallStub(descriptor, target, context, args...);
    } else {
      indirect_return_handler_(
          asm_->CallStub(descriptor, target, context, args...));
    }
  }

  void Return(const TNode<Object> result) {
    if (IsDirect()) {
      asm_->Return(result);
    } else {
      indirect_return_handler_(result);
    }
  }

  bool IsDirect() const { return !indirect_return_handler_; }

 private:
  CodeStubAssembler* const asm_;
  IndirectReturnHandler indirect_return_handler_;
};

}  // namespace internal
}  // namespace v8

#endif  // V8_IC_ACCESSOR_ASSEMBLER_H_

"""

```