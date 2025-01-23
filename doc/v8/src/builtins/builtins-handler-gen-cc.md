Response:
Let's break down the thought process for analyzing the provided C++ code.

1. **Understand the Goal:** The request asks for the functionality of the `builtins-handler-gen.cc` file in V8, specifically focusing on its role in handling built-in functions and potential connections to JavaScript. It also prompts for examples, logic analysis, and common errors.

2. **Initial Scan and Keywords:**  Quickly scan the code for recognizable keywords and patterns. "Builtins", "Handler", "IC" (Inline Cache), "Load", "Store", "ElementsKind", "Transition", "SloppyArguments", "Interceptor", `TF_BUILTIN`, `CodeStubAssembler`, `TailCallRuntime`. These keywords immediately suggest that this code is involved in the optimized execution paths of JavaScript operations, specifically focusing on property access and manipulation.

3. **Identify Core Components:**  The code defines a class `HandlerBuiltinsAssembler` that inherits from `CodeStubAssembler`. This immediately indicates that the code uses V8's CodeStubAssembler framework, which is used for generating machine code for built-in functions and runtime routines.

4. **Focus on `TF_BUILTIN` Macros:** These macros are the entry points for the built-in functions implemented in this file. Analyze each one individually:
    * `LoadIC_StringLength`, `LoadIC_StringWrapperLength`: Clearly related to accessing the `length` property of strings and String wrapper objects.
    * `ElementsTransitionAndStore_*`:  Involved in changing the internal representation (elements kind) of arrays while storing a value.
    * `StoreFastElementIC_*`:  Optimized storage of elements in arrays.
    * `LoadIC_FunctionPrototype`:  Handles accessing the `prototype` property of functions.
    * `StoreGlobalIC_Slow`: The slower path for storing global variables.
    * `KeyedLoadIC_SloppyArguments`, `KeyedStoreIC_SloppyArguments_*`, `KeyedHasIC_SloppyArguments`: Specifically deal with accessing properties of the `arguments` object in non-strict mode functions.
    * `LoadIndexedInterceptorIC`, `HasIndexedInterceptorIC`:  Handle cases where an object has an interceptor for property access.

5. **Analyze Helper Functions within `HandlerBuiltinsAssembler`:**
    * `DispatchByElementsKind`: This is crucial. It's a way to generate specialized code based on the underlying storage type of an array (e.g., packed integers, doubles, holes). The `ElementsKindSwitchCase` suggests a function pointer or lambda is used for the specialized logic.
    * `DispatchForElementsKindTransition`: Similar to the above, but handles transitions between different storage types.
    * `Generate_ElementsTransitionAndStore`, `Generate_StoreFastElementIC`, `Generate_KeyedStoreIC_SloppyArguments`: These functions encapsulate the logic for the `TF_BUILTIN` macros related to storing values. They often involve dispatching based on element kind and potentially calling runtime functions for slower paths.

6. **Look for Connections to JavaScript:** The names of the built-ins (`LoadIC`, `StoreIC`, `ElementsTransitionAndStore`) directly correspond to common JavaScript operations like accessing properties (`obj.prop` or `obj['prop']`) and assigning values (`obj.prop = value` or `obj['prop'] = value`). The handling of `SloppyArguments` directly relates to a specific JavaScript language feature.

7. **Infer Functionality from Names and Operations:** Based on the names and the operations performed (loading, storing, transitioning element kinds), infer the general purpose of the file. It's about optimizing common property access patterns in JavaScript.

8. **Relate to Torque (if applicable):** The prompt mentions ".tq" files. While this specific file is `.cc`, the description of Torque is important context for understanding how these built-ins are *defined* at a higher level before being translated into the C++ seen here. Torque provides a more abstract way to specify the logic.

9. **Construct JavaScript Examples:** For each significant built-in, create simple JavaScript code that would trigger its execution. This demonstrates the connection between the C++ code and the observable behavior of JavaScript.

10. **Consider Logic and Assumptions:**  For functions like `DispatchByElementsKind` and `DispatchForElementsKindTransition`, think about the input (elements kind) and the expected outcome (specialized code execution). This helps in understanding the optimization strategy.

11. **Identify Potential User Errors:**  Think about common mistakes JavaScript developers make that could lead to the execution of these built-ins, especially the "miss" cases that fall back to the runtime. Type mismatches, accessing non-existent properties, and issues with `arguments` are good candidates.

12. **Structure the Answer:** Organize the findings into logical sections: overall functionality, specific built-in functions, connections to JavaScript, logic analysis, and common errors. Use clear and concise language.

13. **Refine and Review:**  Read through the generated answer to ensure accuracy, clarity, and completeness. Check if all aspects of the prompt have been addressed. For example, explicitly stating it's not a Torque file because it ends in `.cc` is important given the prompt's conditions.

Self-Correction/Refinement during the process:

* **Initial thought:**  Maybe this file is only about error handling. **Correction:** The presence of `LoadIC`, `StoreIC`, and element kind transitions points to optimization, not just errors. The "miss" labels handle fallback scenarios.
* **Initial thought:**  Just list the built-in names. **Correction:**  Explain *what* each built-in does and how it relates to JavaScript concepts.
* **Missing Link:**  Initially I might have focused too much on the C++ details. **Correction:** Emphasize the *connection* to JavaScript semantics and provide concrete JavaScript examples.
* **Overlooking `SloppyArguments`:** Initially, I might have treated it as just another property access. **Correction:** Realize its special nature and create specific examples for it.
* **Not explaining Torque:** Since the prompt specifically mentions it, even though this file isn't a `.tq` file, briefly explaining Torque's role adds valuable context.

By following this structured approach, combining code analysis with an understanding of JavaScript concepts, one can effectively dissect and explain the functionality of a complex piece of V8 source code.
`v8/src/builtins/builtins-handler-gen.cc` 是 V8 JavaScript 引擎中的一个 C++ 源文件。从其文件名和内容来看，它主要负责生成和实现**处理程序 (Handler) 相关的内置函数 (Builtins)**。这些 builtins 是 V8 引擎中用于执行特定 JavaScript 操作的底层代码，通常是性能关键的部分。

**功能列举:**

1. **实现 LoadIC (Load Inline Cache) Builtins:**
   - `LoadIC_StringLength`:  用于优化访问字符串 `length` 属性的操作。当 JavaScript 代码尝试读取字符串的 `length` 时，V8 会尝试使用这个优化的 built-in。
   - `LoadIC_StringWrapperLength`: 用于优化访问 `String` 对象包装器 (String Wrapper) 的 `length` 属性。

2. **实现 KeyedStoreIC (Keyed Store Inline Cache) Builtins:**
   - 提供 Megamorphic (多态) 版本的 keyed store (通过索引或字符串键存储属性) 操作。
   - 提供 NoFeedback (无反馈) 版本的 keyed store 操作，用于某些不需要收集性能反馈的场景。
   - 实现各种针对不同元素类型转换的 keyed store 操作 (`Generate_ElementsTransitionAndStore`)。这些操作处理数组在存储元素时可能发生的内部表示形式的转换（例如，从存储整数到存储浮点数）。
   - 实现快速元素存储的 keyed store 操作 (`Generate_StoreFastElementIC`)，针对不同类型的数组元素进行优化。
   - 实现针对 `arguments` 对象的特殊 keyed store 操作 (`Generate_KeyedStoreIC_SloppyArguments`)。`arguments` 是 JavaScript 函数中可用的一个类数组对象，用于访问传递给函数的所有参数。

3. **实现 DefineKeyedOwnIC (Define Keyed Own Inline Cache) Builtins:**
   - 提供 Megamorphic 和 NoFeedback 版本的定义对象自身属性的操作。

4. **实现 StoreIC (Store Inline Cache) Builtins:**
   - 提供 NoFeedback 版本的属性存储操作。

5. **实现 DefineNamedOwnIC (Define Named Own Inline Cache) Builtins:**
   - 提供 NoFeedback 版本的定义对象自身命名属性的操作。

6. **实现元素类型转换和存储 (`ElementsTransitionAndStore`)：**
   - 提供了在存储元素时进行数组元素类型转换的 built-in。例如，当向一个只存储整数的数组中存储一个浮点数时，数组的内部表示可能需要转换为允许存储浮点数。

7. **实现快速元素存储 (`StoreFastElementIC`)：**
   - 针对不同类型的数组元素（例如，SMI，双精度浮点数，普通对象等）提供了优化的存储路径。

8. **实现 `LoadIC_FunctionPrototype`:**
   - 用于优化访问函数 `prototype` 属性的操作。

9. **实现 `StoreGlobalIC_Slow`:**
   -  处理全局变量存储的慢速路径。

10. **实现针对 `arguments` 对象的特殊 LoadIC 和 HasIC Builtins:**
    - `KeyedLoadIC_SloppyArguments`: 优化访问非严格模式函数 `arguments` 对象的属性。
    - `KeyedHasIC_SloppyArguments`: 优化检查非严格模式函数 `arguments` 对象是否拥有特定属性。

11. **实现拦截器相关的 LoadIC 和 HasIC Builtins:**
    - `LoadIndexedInterceptorIC`:  处理带有索引属性访问拦截器的对象的属性读取。
    - `HasIndexedInterceptorIC`: 处理带有索引属性存在性拦截器的对象的属性检查。

12. **内部辅助函数 (`HandlerBuiltinsAssembler` 类中的方法):**
    - `DispatchByElementsKind`:  根据数组的元素类型 (ElementsKind) 分发执行不同的代码路径，实现针对不同元素类型的优化。
    - `DispatchForElementsKindTransition`: 根据元素类型的转换情况分发执行不同的代码路径。

**关于 `.tq` 结尾:**

如果 `v8/src/builtins/builtins-handler-gen.cc` 以 `.tq` 结尾，那么它就是一个 **V8 Torque** 源代码文件。Torque 是 V8 使用的一种领域特定语言 (DSL)，用于更安全、更易于维护的方式编写 built-in 函数。Torque 代码会被编译成 C++ 代码。但目前的这个文件是 `.cc` 结尾，所以它是直接用 C++ 编写的。

**与 JavaScript 的关系及示例:**

这个文件中的 built-ins 直接对应于 JavaScript 中常见的操作。以下是一些 JavaScript 例子，它们可能会触发这里定义的一些 built-ins：

1. **`LoadIC_StringLength`:**

   ```javascript
   const str = "hello";
   const len = str.length; // 访问字符串的 length 属性
   ```

2. **`ElementsTransitionAndStore_*` 和 `StoreFastElementIC_*`:**

   ```javascript
   const arr = [1, 2, 3]; // 初始为 PackedSmiElements
   arr[0] = 1.5;         // 存储浮点数，可能触发元素类型转换
   arr[1] = 4;           // 快速存储整数
   ```

3. **`LoadIC_FunctionPrototype`:**

   ```javascript
   function MyClass() {}
   const proto = MyClass.prototype; // 访问函数的 prototype 属性
   ```

4. **`KeyedLoadIC_SloppyArguments` 和 `KeyedStoreIC_SloppyArguments_*`:**

   ```javascript
   function foo() {
     console.log(arguments[0]); // 读取 arguments 对象的属性
     arguments[1] = 'new value'; // 修改 arguments 对象的属性
   }
   foo(1, 2);
   ```

5. **`LoadIndexedInterceptorIC` 和 `HasIndexedInterceptorIC`:**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, '0', {
     get: function() { console.log('getting index 0'); return 10; },
     set: function(value) { console.log('setting index 0 to', value); },
   });
   const val = obj[0]; // 触发 LoadIndexedInterceptorIC
   console.log(0 in obj); // 触发 HasIndexedInterceptorIC
   ```

**代码逻辑推理 (假设输入与输出):**

以 `LoadIC_StringLength` 为例：

**假设输入:**

- `Descriptor::kReceiver`: 一个 JavaScript 字符串对象，例如 `"world"`.

**代码逻辑:**

1. 从 `Descriptor::kReceiver` 参数中获取字符串对象。
2. 调用 `LoadStringLengthAsSmi` 函数，该函数会从字符串对象的内部表示中读取长度，并将其编码为 Smi (Small Integer)。

**预期输出:**

- 返回一个 Smi，其值等于输入字符串的长度，例如，对于 `"world"`，返回的 Smi 的值为 5。

**涉及用户常见的编程错误及示例:**

1. **类型错误导致性能下降:** 如果代码频繁地在不同类型的数组之间进行元素存储，可能会导致频繁的元素类型转换，从而降低性能。

   ```javascript
   const arr = [];
   arr.push(1);     // PackedSmiElements
   arr.push(1.5);   // 转换为 PackedDoubleElements
   arr.push("hello"); // 转换为 PackedElements (存储任意类型)
   ```

2. **过度依赖 `arguments` 对象 (尤其是在严格模式下):** 虽然 `arguments` 对象在非严格模式下可用，但它的使用可能会导致性能损失，并且在严格模式下有不同的行为。现代 JavaScript 建议使用剩余参数 (`...args`) 来代替。

   ```javascript
   function badExample() {
     for (let i = 0; i < arguments.length; i++) {
       console.log(arguments[i]);
     }
   }
   ```

3. **在具有拦截器的对象上进行频繁的属性访问:**  如果对象定义了 getter 或 setter 拦截器，每次访问这些属性时都需要执行额外的代码，这可能比直接访问普通属性更慢。

   ```javascript
   const objWithInterceptor = {};
   Object.defineProperty(objWithInterceptor, 'x', {
     get: function() { console.log('getting x'); return this._x; },
     set: function(value) { console.log('setting x to', value); this._x = value; },
   });

   for (let i = 0; i < 1000; i++) {
     objWithInterceptor.x = i; // 每次赋值都会触发拦截器
   }
   ```

总而言之，`v8/src/builtins/builtins-handler-gen.cc` 是 V8 引擎中负责实现许多关键的 JavaScript 操作的优化代码，它通过内联缓存 (IC) 和针对不同数据类型的特殊处理来提高性能。理解这个文件的内容有助于深入了解 V8 如何高效地执行 JavaScript 代码。

### 提示词
```
这是目录为v8/src/builtins/builtins-handler-gen.cc的一个v8源代码， 请列举一下它的功能, 
如果v8/src/builtins/builtins-handler-gen.cc以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```cpp
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "src/builtins/builtins-utils-gen.h"
#include "src/builtins/builtins.h"
#include "src/codegen/code-stub-assembler-inl.h"
#include "src/ic/ic.h"
#include "src/ic/keyed-store-generic.h"
#include "src/objects/objects-inl.h"
#include "torque-generated/exported-macros-assembler.h"

namespace v8 {
namespace internal {

#include "src/codegen/define-code-stub-assembler-macros.inc"

class HandlerBuiltinsAssembler : public CodeStubAssembler {
 public:
  explicit HandlerBuiltinsAssembler(compiler::CodeAssemblerState* state)
      : CodeStubAssembler(state) {}

 protected:
  void Generate_KeyedStoreIC_SloppyArguments();

  // Essentially turns runtime elements kinds (TNode<Int32T>) into
  // compile-time types (int) by dispatching over the runtime type and
  // emitting a specialized copy of the given case function for each elements
  // kind. Use with caution. This produces a *lot* of code.
  using ElementsKindSwitchCase = std::function<void(ElementsKind)>;
  void DispatchByElementsKind(TNode<Int32T> elements_kind,
                              const ElementsKindSwitchCase& case_function,
                              bool handle_typed_elements_kind);

  // Dispatches over all possible combinations of {from,to} elements kinds.
  using ElementsKindTransitionSwitchCase =
      std::function<void(ElementsKind, ElementsKind)>;
  void DispatchForElementsKindTransition(
      TNode<Int32T> from_kind, TNode<Int32T> to_kind,
      const ElementsKindTransitionSwitchCase& case_function);

  void Generate_ElementsTransitionAndStore(KeyedAccessStoreMode store_mode);
  void Generate_StoreFastElementIC(KeyedAccessStoreMode store_mode);
};

TF_BUILTIN(LoadIC_StringLength, CodeStubAssembler) {
  auto string = Parameter<String>(Descriptor::kReceiver);
  Return(LoadStringLengthAsSmi(string));
}

TF_BUILTIN(LoadIC_StringWrapperLength, CodeStubAssembler) {
  auto value = Parameter<JSPrimitiveWrapper>(Descriptor::kReceiver);
  TNode<String> string = CAST(LoadJSPrimitiveWrapperValue(value));
  Return(LoadStringLengthAsSmi(string));
}

void Builtins::Generate_KeyedStoreIC_Megamorphic(
    compiler::CodeAssemblerState* state) {
  KeyedStoreMegamorphicGenerator::Generate(state);
}

void Builtins::Generate_DefineKeyedOwnIC_Megamorphic(
    compiler::CodeAssemblerState* state) {
  DefineKeyedOwnGenericGenerator::Generate(state);
}

void Builtins::Generate_StoreIC_NoFeedback(
    compiler::CodeAssemblerState* state) {
  StoreICNoFeedbackGenerator::Generate(state);
}

void Builtins::Generate_DefineNamedOwnIC_NoFeedback(
    compiler::CodeAssemblerState* state) {
  DefineNamedOwnICNoFeedbackGenerator::Generate(state);
}

// All possible fast-to-fast transitions. Transitions to dictionary mode are not
// handled by ElementsTransitionAndStore builtins.
#define ELEMENTS_KIND_TRANSITIONS(V)               \
  V(PACKED_SMI_ELEMENTS, HOLEY_SMI_ELEMENTS)       \
  V(PACKED_SMI_ELEMENTS, PACKED_DOUBLE_ELEMENTS)   \
  V(PACKED_SMI_ELEMENTS, HOLEY_DOUBLE_ELEMENTS)    \
  V(PACKED_SMI_ELEMENTS, PACKED_ELEMENTS)          \
  V(PACKED_SMI_ELEMENTS, HOLEY_ELEMENTS)           \
  V(HOLEY_SMI_ELEMENTS, HOLEY_DOUBLE_ELEMENTS)     \
  V(HOLEY_SMI_ELEMENTS, HOLEY_ELEMENTS)            \
  V(PACKED_DOUBLE_ELEMENTS, HOLEY_DOUBLE_ELEMENTS) \
  V(PACKED_DOUBLE_ELEMENTS, PACKED_ELEMENTS)       \
  V(PACKED_DOUBLE_ELEMENTS, HOLEY_ELEMENTS)        \
  V(HOLEY_DOUBLE_ELEMENTS, HOLEY_ELEMENTS)         \
  V(PACKED_ELEMENTS, HOLEY_ELEMENTS)

void HandlerBuiltinsAssembler::DispatchForElementsKindTransition(
    TNode<Int32T> from_kind, TNode<Int32T> to_kind,
    const ElementsKindTransitionSwitchCase& case_function) {
  static_assert(sizeof(ElementsKind) == sizeof(uint8_t));

  Label next(this), if_unknown_type(this, Label::kDeferred);

  int32_t combined_elements_kinds[] = {
#define ELEMENTS_KINDS_CASE(FROM, TO) (FROM << kBitsPerByte) | TO,
      ELEMENTS_KIND_TRANSITIONS(ELEMENTS_KINDS_CASE)
#undef ELEMENTS_KINDS_CASE
  };

#define ELEMENTS_KINDS_CASE(FROM, TO) Label if_##FROM##_##TO(this);
  ELEMENTS_KIND_TRANSITIONS(ELEMENTS_KINDS_CASE)
#undef ELEMENTS_KINDS_CASE

  Label* elements_kind_labels[] = {
#define ELEMENTS_KINDS_CASE(FROM, TO) &if_##FROM##_##TO,
      ELEMENTS_KIND_TRANSITIONS(ELEMENTS_KINDS_CASE)
#undef ELEMENTS_KINDS_CASE
  };
  static_assert(arraysize(combined_elements_kinds) ==
                arraysize(elements_kind_labels));

  TNode<Int32T> combined_elements_kind =
      Word32Or(Word32Shl(from_kind, Int32Constant(kBitsPerByte)), to_kind);

  Switch(combined_elements_kind, &if_unknown_type, combined_elements_kinds,
         elements_kind_labels, arraysize(combined_elements_kinds));

#define ELEMENTS_KINDS_CASE(FROM, TO) \
  BIND(&if_##FROM##_##TO);            \
  {                                   \
    case_function(FROM, TO);          \
    Goto(&next);                      \
  }
  ELEMENTS_KIND_TRANSITIONS(ELEMENTS_KINDS_CASE)
#undef ELEMENTS_KINDS_CASE

  BIND(&if_unknown_type);
  Unreachable();

  BIND(&next);
}

#undef ELEMENTS_KIND_TRANSITIONS

void HandlerBuiltinsAssembler::Generate_ElementsTransitionAndStore(
    KeyedAccessStoreMode store_mode) {
  using Descriptor = StoreTransitionDescriptor;
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto map = Parameter<Map>(Descriptor::kMap);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<FeedbackVector>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  Comment("ElementsTransitionAndStore: store_mode=", store_mode);

  Label miss(this);

  if (v8_flags.trace_elements_transitions) {
    // Tracing elements transitions is the job of the runtime.
    Goto(&miss);
  } else {
    // TODO(v8:8481): Pass from_kind and to_kind in feedback vector slots.
    DispatchForElementsKindTransition(
        LoadElementsKind(receiver), LoadMapElementsKind(map),
        [=, this, &miss](ElementsKind from_kind, ElementsKind to_kind) {
          TransitionElementsKind(receiver, map, from_kind, to_kind, &miss);
          EmitElementStore(receiver, key, value, to_kind, store_mode, &miss,
                           context, nullptr);
        });
    Return(value);
  }

  BIND(&miss);
  TailCallRuntime(Runtime::kElementsTransitionAndStoreIC_Miss, context,
                  receiver, key, value, map, slot, vector);
}

TF_BUILTIN(ElementsTransitionAndStore_InBounds, HandlerBuiltinsAssembler) {
  Generate_ElementsTransitionAndStore(KeyedAccessStoreMode::kInBounds);
}

TF_BUILTIN(ElementsTransitionAndStore_NoTransitionGrowAndHandleCOW,
           HandlerBuiltinsAssembler) {
  Generate_ElementsTransitionAndStore(KeyedAccessStoreMode::kGrowAndHandleCOW);
}

TF_BUILTIN(ElementsTransitionAndStore_NoTransitionIgnoreTypedArrayOOB,
           HandlerBuiltinsAssembler) {
  Generate_ElementsTransitionAndStore(
      KeyedAccessStoreMode::kIgnoreTypedArrayOOB);
}

TF_BUILTIN(ElementsTransitionAndStore_NoTransitionHandleCOW,
           HandlerBuiltinsAssembler) {
  Generate_ElementsTransitionAndStore(KeyedAccessStoreMode::kHandleCOW);
}

// All elements kinds handled by EmitElementStore. Specifically, this includes
// fast elements and fixed typed array elements.
#define ELEMENTS_KINDS(V)            \
  V(PACKED_SMI_ELEMENTS)             \
  V(HOLEY_SMI_ELEMENTS)              \
  V(PACKED_ELEMENTS)                 \
  V(PACKED_NONEXTENSIBLE_ELEMENTS)   \
  V(PACKED_SEALED_ELEMENTS)          \
  V(SHARED_ARRAY_ELEMENTS)           \
  V(HOLEY_ELEMENTS)                  \
  V(HOLEY_NONEXTENSIBLE_ELEMENTS)    \
  V(HOLEY_SEALED_ELEMENTS)           \
  V(PACKED_DOUBLE_ELEMENTS)          \
  V(HOLEY_DOUBLE_ELEMENTS)           \
  V(UINT8_ELEMENTS)                  \
  V(INT8_ELEMENTS)                   \
  V(UINT16_ELEMENTS)                 \
  V(INT16_ELEMENTS)                  \
  V(UINT32_ELEMENTS)                 \
  V(INT32_ELEMENTS)                  \
  V(FLOAT16_ELEMENTS)                \
  V(FLOAT32_ELEMENTS)                \
  V(FLOAT64_ELEMENTS)                \
  V(UINT8_CLAMPED_ELEMENTS)          \
  V(BIGUINT64_ELEMENTS)              \
  V(BIGINT64_ELEMENTS)               \
  V(RAB_GSAB_UINT8_ELEMENTS)         \
  V(RAB_GSAB_INT8_ELEMENTS)          \
  V(RAB_GSAB_UINT16_ELEMENTS)        \
  V(RAB_GSAB_INT16_ELEMENTS)         \
  V(RAB_GSAB_UINT32_ELEMENTS)        \
  V(RAB_GSAB_INT32_ELEMENTS)         \
  V(RAB_GSAB_FLOAT16_ELEMENTS)       \
  V(RAB_GSAB_FLOAT32_ELEMENTS)       \
  V(RAB_GSAB_FLOAT64_ELEMENTS)       \
  V(RAB_GSAB_UINT8_CLAMPED_ELEMENTS) \
  V(RAB_GSAB_BIGUINT64_ELEMENTS)     \
  V(RAB_GSAB_BIGINT64_ELEMENTS)

void HandlerBuiltinsAssembler::DispatchByElementsKind(
    TNode<Int32T> elements_kind, const ElementsKindSwitchCase& case_function,
    bool handle_typed_elements_kind) {
  Label next(this), if_unknown_type(this, Label::kDeferred);

  int32_t elements_kinds[] = {
#define ELEMENTS_KINDS_CASE(KIND) KIND,
      ELEMENTS_KINDS(ELEMENTS_KINDS_CASE)
#undef ELEMENTS_KINDS_CASE
  };

#define ELEMENTS_KINDS_CASE(KIND) Label if_##KIND(this);
  ELEMENTS_KINDS(ELEMENTS_KINDS_CASE)
#undef ELEMENTS_KINDS_CASE

  Label* elements_kind_labels[] = {
#define ELEMENTS_KINDS_CASE(KIND) &if_##KIND,
      ELEMENTS_KINDS(ELEMENTS_KINDS_CASE)
#undef ELEMENTS_KINDS_CASE
  };
  static_assert(arraysize(elements_kinds) == arraysize(elements_kind_labels));

  // TODO(mythria): Do not emit cases for typed elements kind when
  // handle_typed_elements is false to decrease the size of the jump table.
  Switch(elements_kind, &if_unknown_type, elements_kinds, elements_kind_labels,
         arraysize(elements_kinds));

#define ELEMENTS_KINDS_CASE(KIND)                                   \
  BIND(&if_##KIND);                                                 \
  {                                                                 \
    if (!v8_flags.enable_sealed_frozen_elements_kind &&             \
        IsAnyNonextensibleElementsKindUnchecked(KIND)) {            \
      /* Disable support for frozen or sealed elements kinds. */    \
      Unreachable();                                                \
    } else if (!handle_typed_elements_kind &&                       \
               IsTypedArrayOrRabGsabTypedArrayElementsKind(KIND)) { \
      Unreachable();                                                \
    } else {                                                        \
      case_function(KIND);                                          \
      Goto(&next);                                                  \
    }                                                               \
  }
  ELEMENTS_KINDS(ELEMENTS_KINDS_CASE)
#undef ELEMENTS_KINDS_CASE

  BIND(&if_unknown_type);
  Unreachable();

  BIND(&next);
}

#undef ELEMENTS_KINDS

void HandlerBuiltinsAssembler::Generate_StoreFastElementIC(
    KeyedAccessStoreMode store_mode) {
  using Descriptor = StoreWithVectorDescriptor;
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  Comment("StoreFastElementStub: store_mode=", store_mode);

  Label miss(this);

  // For typed arrays maybe_converted_value contains the value obtained after
  // calling ToNumber. We should pass the converted value to the runtime to
  // avoid doing the user visible conversion again.
  TVARIABLE(Object, maybe_converted_value, value);
  // TODO(v8:8481): Pass elements_kind in feedback vector slots.
  DispatchByElementsKind(
      LoadElementsKind(receiver),
      [=, this, &miss, &maybe_converted_value](ElementsKind elements_kind) {
        EmitElementStore(receiver, key, value, elements_kind, store_mode, &miss,
                         context, &maybe_converted_value);
      },
      StoreModeSupportsTypeArray(store_mode));
  Return(value);

  BIND(&miss);
  TailCallRuntime(Runtime::kKeyedStoreIC_Miss, context,
                  maybe_converted_value.value(), slot, vector, receiver, key);
}

TF_BUILTIN(StoreFastElementIC_InBounds, HandlerBuiltinsAssembler) {
  Generate_StoreFastElementIC(KeyedAccessStoreMode::kInBounds);
}

TF_BUILTIN(StoreFastElementIC_NoTransitionGrowAndHandleCOW,
           HandlerBuiltinsAssembler) {
  Generate_StoreFastElementIC(KeyedAccessStoreMode::kGrowAndHandleCOW);
}

TF_BUILTIN(StoreFastElementIC_NoTransitionIgnoreTypedArrayOOB,
           HandlerBuiltinsAssembler) {
  Generate_StoreFastElementIC(KeyedAccessStoreMode::kIgnoreTypedArrayOOB);
}

TF_BUILTIN(StoreFastElementIC_NoTransitionHandleCOW, HandlerBuiltinsAssembler) {
  Generate_StoreFastElementIC(KeyedAccessStoreMode::kHandleCOW);
}

TF_BUILTIN(LoadIC_FunctionPrototype, CodeStubAssembler) {
  auto receiver = Parameter<JSFunction>(Descriptor::kReceiver);
  auto name = Parameter<Name>(Descriptor::kName);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<FeedbackVector>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label miss(this, Label::kDeferred);
  Return(LoadJSFunctionPrototype(receiver, &miss));

  BIND(&miss);
  TailCallRuntime(Runtime::kLoadIC_Miss, context, receiver, name, slot, vector);
}

TF_BUILTIN(StoreGlobalIC_Slow, CodeStubAssembler) {
  auto receiver = Parameter<Object>(Descriptor::kReceiver);
  auto name = Parameter<Name>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<FeedbackVector>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  // The slow case calls into the runtime to complete the store without causing
  // an IC miss that would otherwise cause a transition to the generic stub.
  TailCallRuntime(Runtime::kStoreGlobalIC_Slow, context, value, slot, vector,
                  receiver, name);
}

TF_BUILTIN(KeyedLoadIC_SloppyArguments, HandlerBuiltinsAssembler) {
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label miss(this);

  TNode<Object> result = SloppyArgumentsLoad(receiver, key, &miss);
  Return(result);

  BIND(&miss);
  {
    Comment("Miss");
    TailCallRuntime(Runtime::kKeyedLoadIC_Miss, context, receiver, key, slot,
                    vector);
  }
}

void HandlerBuiltinsAssembler::Generate_KeyedStoreIC_SloppyArguments() {
  using Descriptor = StoreWithVectorDescriptor;
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kName);
  auto value = Parameter<Object>(Descriptor::kValue);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label miss(this);

  SloppyArgumentsStore(receiver, key, value, &miss);
  Return(value);

  BIND(&miss);
  TailCallRuntime(Runtime::kKeyedStoreIC_Miss, context, value, slot, vector,
                  receiver, key);
}

TF_BUILTIN(KeyedStoreIC_SloppyArguments_InBounds, HandlerBuiltinsAssembler) {
  Generate_KeyedStoreIC_SloppyArguments();
}

TF_BUILTIN(KeyedStoreIC_SloppyArguments_NoTransitionGrowAndHandleCOW,
           HandlerBuiltinsAssembler) {
  Generate_KeyedStoreIC_SloppyArguments();
}

TF_BUILTIN(KeyedStoreIC_SloppyArguments_NoTransitionIgnoreTypedArrayOOB,
           HandlerBuiltinsAssembler) {
  Generate_KeyedStoreIC_SloppyArguments();
}

TF_BUILTIN(KeyedStoreIC_SloppyArguments_NoTransitionHandleCOW,
           HandlerBuiltinsAssembler) {
  Generate_KeyedStoreIC_SloppyArguments();
}

TF_BUILTIN(LoadIndexedInterceptorIC, CodeStubAssembler) {
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label if_keyispositivesmi(this), if_keyisinvalid(this);
  Branch(TaggedIsPositiveSmi(key), &if_keyispositivesmi, &if_keyisinvalid);
  BIND(&if_keyispositivesmi);
  TailCallRuntime(Runtime::kLoadElementWithInterceptor, context, receiver, key);

  BIND(&if_keyisinvalid);
  TailCallRuntime(Runtime::kKeyedLoadIC_Miss, context, receiver, key, slot,
                  vector);
}

TF_BUILTIN(KeyedHasIC_SloppyArguments, HandlerBuiltinsAssembler) {
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label miss(this);

  TNode<Object> result = SloppyArgumentsHas(receiver, key, &miss);
  Return(result);

  BIND(&miss);
  {
    Comment("Miss");
    TailCallRuntime(Runtime::kKeyedHasIC_Miss, context, receiver, key, slot,
                    vector);
  }
}

TF_BUILTIN(HasIndexedInterceptorIC, CodeStubAssembler) {
  auto receiver = Parameter<JSObject>(Descriptor::kReceiver);
  auto key = Parameter<Object>(Descriptor::kName);
  auto slot = Parameter<Smi>(Descriptor::kSlot);
  auto vector = Parameter<HeapObject>(Descriptor::kVector);
  auto context = Parameter<Context>(Descriptor::kContext);

  Label if_keyispositivesmi(this), if_keyisinvalid(this);
  Branch(TaggedIsPositiveSmi(key), &if_keyispositivesmi, &if_keyisinvalid);
  BIND(&if_keyispositivesmi);
  TailCallRuntime(Runtime::kHasElementWithInterceptor, context, receiver, key);

  BIND(&if_keyisinvalid);
  TailCallRuntime(Runtime::kKeyedHasIC_Miss, context, receiver, key, slot,
                  vector);
}

#include "src/codegen/undef-code-stub-assembler-macros.inc"

}  // namespace internal
}  // namespace v8
```