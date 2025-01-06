Response: Let's break down the thought process for analyzing the C++ code and generating the summary and JavaScript example.

1. **Understand the Goal:** The request asks for a summary of the C++ file's functionality and a JavaScript example illustrating the connection, if any.

2. **Initial Scan and Keywords:** Quickly skim the code, looking for recognizable terms and patterns. Keywords like "Builtins," "Assembler," "LoadIC," "StoreIC," "Keyed," "ElementsKind," "Transition," "SloppyArguments," and "Runtime" jump out. The `#include` directives also give clues about the areas involved (code generation, IC, objects).

3. **Identify the Core Class:** The `HandlerBuiltinsAssembler` class appears central. Its methods (`Generate_...`) strongly suggest it's responsible for generating code for specific built-in operations. The inheritance from `CodeStubAssembler` confirms this, as code stubs are small pieces of generated code for common operations.

4. **Focus on "IC":** The repeated use of "IC" (LoadIC, StoreIC, KeyedLoadIC, KeyedStoreIC) suggests this file deals with Inline Caches. ICs are a crucial optimization technique in JavaScript engines.

5. **Decipher "ElementsKind":** The numerous functions related to `ElementsKind` (e.g., `DispatchByElementsKind`, `DispatchForElementsKindTransition`, `Generate_ElementsTransitionAndStore`) indicate that a significant part of this code handles how JavaScript arrays (and array-like objects) store their elements. The various `PACKED_*`, `HOLEY_*`, and typed array element kinds are strong indicators.

6. **Connect to JavaScript:**  At this point, the connection to JavaScript starts becoming clearer. ICs are triggered by common JavaScript operations (property access, array access). The `ElementsKind` relates directly to how JavaScript engines optimize array storage behind the scenes.

7. **Analyze Specific Functions:**
    * `TF_BUILTIN` macros: These define built-in functions accessible from the JavaScript engine. `LoadIC_StringLength`, `LoadIC_StringWrapperLength` directly relate to accessing the `length` property of strings and String wrapper objects.
    * `Generate_KeyedStoreIC_Megamorphic`, `Generate_DefineKeyedOwnIC_Megamorphic`, etc.: These seem to generate generic handlers for property access operations that haven't been fully optimized.
    * `Generate_ElementsTransitionAndStore`:  This is key. It handles the behind-the-scenes changes in how an array stores its elements (e.g., from storing only integers to storing both integers and floating-point numbers).
    * `Generate_StoreFastElementIC`: This likely handles optimized storage for arrays with elements of a specific type.
    * Functions related to `SloppyArguments`: These deal with the special `arguments` object in non-strict mode functions.

8. **Synthesize the Functionality:** Based on the analysis, the core functionality is:
    * Generating optimized code (built-ins) for common JavaScript operations (property access, array access).
    * Specifically handling different scenarios for accessing object properties (LoadIC, StoreIC).
    * Optimizing array access and storage based on the types of elements stored (`ElementsKind`). This includes handling transitions between different element storage types.
    * Dealing with specific, less common cases like the `arguments` object.
    * Providing fallback mechanisms (calling into the runtime) when optimizations don't apply or fail.

9. **Formulate the Summary:**  Structure the summary logically, starting with the main purpose and then elaborating on key areas like ICs, element kinds, and specific built-ins. Use clear and concise language, avoiding overly technical jargon where possible.

10. **Create the JavaScript Example:** The goal here is to illustrate *how* the C++ code is relevant to JavaScript. Focus on the concepts identified in the analysis.
    * Array element transitions are a good example. Create an array and then add elements of different types to trigger a transition.
    * Property access is another core area. Show both reading and writing properties, as this relates to `LoadIC` and `StoreIC`.
    * Briefly mention the `arguments` object as it's specifically handled in the code.

11. **Refine and Review:** Read through the summary and example, ensuring they are accurate, easy to understand, and directly address the prompt's requirements. For instance, initially, I might have focused too much on the technical details of the assembler. The revision would involve shifting the focus towards the *effects* on JavaScript behavior. Similarly, the initial JavaScript example might have been too simple; adding the array transition case makes it more illustrative of the underlying C++ logic.这个C++源代码文件 `builtins-handler-gen.cc` 的主要功能是 **为 V8 JavaScript 引擎生成处理各种 JavaScript 操作的内置函数（built-ins）的代码**。 这些内置函数通常与对象的属性访问（load/store）、数组元素访问、函数调用等操作相关。

更具体地说，这个文件专注于生成 **Handler Builtins** 的代码。 "Handler" 这里指的是 V8 优化编译流水线中用于处理特定操作的专门代码。这些 built-ins 通常是性能关键路径上的代码，因此需要高度优化。

**以下是其关键功能的细分:**

* **生成 LoadIC 和 StoreIC 的代码:**  `LoadIC` (Load Inline Cache) 和 `StoreIC` (Store Inline Cache) 是 V8 中用于优化属性访问的关键机制。这个文件生成了在不同场景下处理属性读取和写入的内置函数，例如：
    * `LoadIC_StringLength`:  用于加载字符串的 `length` 属性。
    * `LoadIC_StringWrapperLength`: 用于加载 String 对象包装器的 `length` 属性。
    * `Generate_KeyedStoreIC_Megamorphic`: 生成处理多种对象类型的键值存储的通用代码。
    * `Generate_StoreFastElementIC`: 生成快速元素存储的代码，用于优化数组元素的写入。
* **处理数组元素的类型转换和存储:**  JavaScript 数组可以存储不同类型的元素。当数组的元素类型发生变化时，V8 需要进行相应的转换。这个文件生成了处理元素类型转换 (`ElementsTransitionAndStore`) 和根据不同的元素类型进行存储 (`EmitElementStore`) 的代码。
* **处理特殊的对象类型，例如 `arguments` 对象:**  `arguments` 是 JavaScript 函数内部可用的一个类数组对象，包含了传递给函数的所有参数。这个文件包含处理 `arguments` 对象属性访问的特殊 built-ins，例如 `KeyedLoadIC_SloppyArguments` 和 `KeyedStoreIC_SloppyArguments`。
* **处理拦截器 (Interceptors):** JavaScript 对象可以定义拦截器来控制属性的访问。这个文件生成了处理带有拦截器的属性访问的 built-ins，例如 `LoadIndexedInterceptorIC` 和 `HasIndexedInterceptorIC`。
* **使用 CodeStubAssembler 生成代码:** 这个文件使用了 V8 的 `CodeStubAssembler` API 来生成底层的汇编代码。`CodeStubAssembler` 提供了一种相对高级的方式来编写汇编代码，同时仍然允许进行细粒度的控制。
* **处理不同的执行模式和优化级别:**  例如，区分快速路径和慢速路径，以及处理不同的优化策略。
* **与运行时 (Runtime) 系统交互:**  当 built-ins 无法高效处理某个操作时，它们会调用 V8 的运行时系统来进行更复杂的处理。例如，`TailCallRuntime` 用于调用运行时函数。

**它与 JavaScript 的功能关系以及 JavaScript 例子:**

这个文件生成的 C++ 代码直接影响着 JavaScript 代码的执行性能和行为。它实现了 JavaScript 引擎内部的关键优化逻辑。

**JavaScript 例子:**

```javascript
// 例子 1: 访问字符串的 length 属性
const str = "hello";
const len = str.length; // 这里会触发 LoadIC，最终可能执行由 builtins-handler-gen.cc 生成的 LoadIC_StringLength 代码

// 例子 2: 修改数组的元素类型
const arr = [1, 2, 3]; // 初始可能是 PACKED_SMI_ELEMENTS
arr.push(3.14);       // 添加浮点数，可能导致元素类型转换为 PACKED_DOUBLE_ELEMENTS，
                      // 触发由 builtins-handler-gen.cc 生成的 ElementsTransitionAndStore 相关代码

// 例子 3: 访问 arguments 对象
function foo(a, b) {
  console.log(arguments[0]); // 这里会触发 KeyedLoadIC，最终可能执行由 builtins-handler-gen.cc 生成的 KeyedLoadIC_SloppyArguments 代码
  arguments[1] = 10;       // 这里会触发 KeyedStoreIC，最终可能执行由 builtins-handler-gen.cc 生成的 KeyedStoreIC_SloppyArguments 相关代码
  console.log(b); // b 的值可能因为 arguments 的修改而改变
}
foo(5, 6);

// 例子 4: 使用带有拦截器的对象
const obj = {};
Object.defineProperty(obj, 'x', {
  get() {
    console.log('Getting x');
    return this._x;
  },
  set(value) {
    console.log('Setting x to', value);
    this._x = value;
  }
});
obj.x = 5; // 这里会触发 StoreIC，并且由于定义了 setter，可能会涉及到由 builtins-handler-gen.cc 生成的拦截器相关的代码
console.log(obj.x); // 这里会触发 LoadIC，并且由于定义了 getter，可能会涉及到由 builtins-handler-gen.cc 生成的拦截器相关的代码
```

**总结:**

`builtins-handler-gen.cc` 是 V8 引擎中一个非常核心的文件，它负责生成用于高效处理各种 JavaScript 操作的底层代码。它通过使用 `CodeStubAssembler` 和处理不同的对象类型、元素类型和执行场景，直接影响着 JavaScript 代码的执行效率和行为。 开发者编写的 JavaScript 代码，在引擎的执行过程中，会频繁地调用这里生成的 built-in 函数。理解这个文件的功能有助于更深入地理解 V8 引擎的内部工作原理和性能优化机制。

Prompt: 
```
这是目录为v8/src/builtins/builtins-handler-gen.cc的一个c++源代码文件， 请归纳一下它的功能, 如果它与javascript的功能有关系，请用javascript举例说明

"""
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

"""

```