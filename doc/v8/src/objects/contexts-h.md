Response:
Let's break down the thought process for analyzing this V8 header file.

**1. Initial Scan and Keyword Recognition:**

* The first thing I see is the `#ifndef V8_OBJECTS_CONTEXTS_H_` guard. This immediately tells me it's a header file, designed to prevent multiple inclusions.
* The `// Copyright` line indicates it's part of the V8 project.
*  Includes like `v8-promise.h`, `handles.h`, `fixed-array.h`, etc., point towards core V8 data structures and functionalities.
* The `namespace v8 { namespace internal {` structure is standard for V8's internal implementation details.
* The `class ContextSidePropertyCell;`, `class JSGlobalObject;`, etc., are forward declarations, indicating dependencies on other V8 components.

**2. Key Data Structure: `Context`:**

* The comments about "Heap-allocated activation contexts" and "FixedArray-like objects" are crucial. This is the central concept of the file.
* The definition of `NATIVE_CONTEXT_FIELDS(V)` with a macro `V` strongly suggests a pattern for defining fields within the `NativeContext`. This looks like a way to generate field declarations efficiently.

**3. Analyzing `NATIVE_CONTEXT_FIELDS` Content:**

* I see a lot of fields ending with `_INDEX`,  `_FUN_INDEX`, and `_MAP_INDEX`. This pattern is highly suggestive.
    * `_INDEX`:  Likely an index into an array or a fixed offset within the `NativeContext` object.
    * `_FUN_INDEX`: Almost certainly related to JavaScript functions (constructors, built-in functions).
    * `_MAP_INDEX`:  Probably refers to `Map` objects used for various purposes (e.g., element maps for arrays, prototype maps).
* Many field names are directly related to JavaScript concepts: `JSGlobalProxy`, `Promise`, `TypedArray`, `ArrayBuffer`, `Function`, `Object`, `RegExp`, `Map`, `Set`, `WeakMap`, `WeakSet`, `Intl`, `Proxy`, `WASM`. This reinforces the connection to JavaScript's runtime environment.
* The `DEBUG_CONTEXT_ID_INDEX`, `ERRORS_THROWN_INDEX` suggest internal state tracking.
* The "Fast Path Protectors" comment points to optimizations within the engine.
*  The long list of function-related indices (`FUNCTION_PROTOTYPE_APPLY_INDEX`, `ARRAY_FUNCTION_INDEX`, etc.) strongly suggests pre-initialized handles to important JavaScript functions stored within the `NativeContext`.

**4. Inferring Functionality:**

* Based on the identified fields and the "activation contexts" comment, I can start inferring the file's purpose:
    * It defines the structure of `Context` objects, which are crucial for managing the execution environment of JavaScript code.
    * `NativeContext` seems to be a special type of context holding global-level information and built-in objects.
    * The numerous `_INDEX` fields suggest that `NativeContext` acts as a central registry or cache for essential JavaScript objects and functions. This allows for faster access during runtime.
    * The inclusion of WASM-related fields (`WASM_...`) indicates that contexts are also involved in WASM execution.

**5. Connecting to JavaScript:**

* The presence of JavaScript-related names makes the connection straightforward. The `NativeContext` essentially holds the "standard library" and fundamental objects that every JavaScript program relies on.
* Examples would naturally involve accessing these built-in objects (like `Array`, `Object`, `Promise`) or using their methods.

**6. Considering `.tq` and Torque:**

* The instruction to check for `.tq` is important. Recognizing that `.tq` signifies Torque, V8's internal language, helps understand the relationship between this `.h` file and potential code generation. This header likely defines the C++ structure that Torque code might interact with or generate code for.

**7. Code Logic and Assumptions:**

* The indexing pattern suggests a design where accessing these built-ins is done via offsets or indices rather than direct pointer lookups, likely for performance reasons.
* The assumption is that the `NATIVE_CONTEXT_FIELDS` macro is used to generate the actual member variables within the `NativeContext` class.

**8. Common Programming Errors (Relating to Contexts):**

*  Thinking about how JavaScript developers interact with scopes and contexts helps generate error examples. Closure-related bugs (accessing variables from the wrong scope) and `this` binding issues are classic examples.

**9. Structuring the Answer:**

* Start with a high-level summary of the file's purpose.
* Detail the key data structure (`Context`, `NativeContext`) and its role.
* Explain the significance of the `NATIVE_CONTEXT_FIELDS` macro and the naming conventions of the fields.
* Provide JavaScript examples illustrating how the concepts in the header relate to the language.
* Briefly touch upon the Torque aspect if the `.tq` extension were present.
* Offer examples of common programming errors related to contexts and scopes.
* Conclude with a concise summary of the file's functionality.

**Self-Correction/Refinement During the Process:**

* Initially, I might just see a bunch of seemingly random fields. But looking for patterns (`_INDEX`, `_FUN_INDEX`, `_MAP_INDEX`) is crucial to understanding the underlying structure.
*  Connecting the field names directly to JavaScript concepts is key to making the purpose clear.
* I need to make sure I differentiate between `Context` and `NativeContext`. While related, `NativeContext` is a specific type of `Context`.
* The explanation of Torque's role needs to be included *if* the `.tq` extension was mentioned. If not, it's less relevant.

By following these steps and iteratively refining my understanding, I can arrive at a comprehensive and accurate explanation of the header file's functionality.
## 功能归纳：v8/src/objects/contexts.h (第1部分)

这个头文件 `v8/src/objects/contexts.h` 定义了 V8 引擎中用于管理执行上下文的关键数据结构和相关枚举。它主要关注以下几个方面：

**1. 定义了上下文对象 (`Context`) 的基本结构：**

* 上下文是 V8 引擎中用于跟踪代码执行环境的关键概念。它包含了执行代码所需的各种信息，例如变量的绑定、作用域链等。
* 该头文件定义了 `Context` 类的基本布局，尽管具体的成员变量是通过宏 `NATIVE_CONTEXT_FIELDS` 定义的。
* 强调了 `Context` 对象是类似 `FixedArray` 的堆分配对象，并且需要通过特定的 V8 API (`Heap::AllocateContext()` 或 `Factory::NewContext`) 进行分配。

**2. 定义了 `NativeContext` 的具体结构和字段：**

* `NativeContext` 是一种特殊的上下文，通常与全局作用域关联。它包含了大量的预先创建和缓存的 JavaScript 对象、函数和元数据，用于快速访问和执行。
* 通过宏 `NATIVE_CONTEXT_FIELDS(V)` 定义了大量的字段，这些字段包含了：
    * **内置对象和函数:**  例如 `Array`, `Object`, `Promise`, `Function` 的构造函数和原型对象，以及一些重要的内置函数如 `map.get`, `set.add` 等。
    * **TypedArray 相关的构造函数和 Map:**  定义了各种类型化数组的构造函数，例如 `Uint8Array`, `Float64Array` 等，以及它们对应的 Map 对象。
    * **Intl (国际化) 相关的构造函数:** 定义了 `Intl.Collator`, `Intl.DateTimeFormat` 等国际化相关对象的构造函数。
    * **Proxy 相关的 Map:** 用于存储 `Proxy` 对象的 Map。
    * **WASM (WebAssembly) 相关的构造函数和对象:**  定义了 WebAssembly 相关的构造函数，例如 `WebAssembly.Module`, `WebAssembly.Instance` 等。
    * **Context 自身的 Map:**  例如 `FunctionContextMap`, `ModuleContextMap` 等，用于管理不同类型的上下文。
    * **缓存:**  例如 `map_cache`, `normalized_map_cache` 等，用于缓存一些常用的 Map 对象。
    * **内部状态:** 例如 `math_random_index`, `math_random_state` 等，用于支持内部操作。
    * **Fast Path Protectors (快速路径保护):** 例如 `regexp_species_protector`，用于优化某些操作。
* 这些字段都通过宏 `V` 来定义，这意味着这些字段在 `NativeContext` 对象中占据固定的偏移量，方便快速访问。

**3. 定义了上下文查找的标志 (`ContextLookupFlags`)：**

* `ContextLookupFlags` 枚举定义了在上下文中查找变量时可以使用的标志。
* `FOLLOW_CONTEXT_CHAIN`:  指示在查找变量时是否需要沿着上下文链向上查找。
* `FOLLOW_PROTOTYPE_CHAIN`: 指示在查找属性时是否需要沿着原型链向上查找。
* `DONT_FOLLOW_CHAINS` 和 `FOLLOW_CHAINS` 是方便使用的组合标志。

**如果 `v8/src/objects/contexts.h` 以 `.tq` 结尾，那它是个 v8 torque 源代码:**

虽然这个文件以 `.h` 结尾，但如果它以 `.tq` 结尾，那么它将是一个用 V8 的内部类型化汇编语言 Torque 编写的源文件。 Torque 代码通常用于实现 V8 引擎的核心功能，并且可以与 C++ 代码互操作。在这种情况下，该文件可能会包含用 Torque 编写的用于创建、操作和管理上下文对象的代码。

**如果它与 javascript 的功能有关系，请用 javascript 举例说明:**

`v8/src/objects/contexts.h` 中定义的 `NativeContext` 包含了大量与 JavaScript 功能直接相关的对象和函数。例如：

```javascript
// 获取全局对象 (Global Proxy Object)
// 在 C++ 中，这对应于 NATIVE_CONTEXT_FIELDS 中的 GLOBAL_PROXY_INDEX
console.log(globalThis);

// 使用 Array 构造函数创建数组
// 在 C++ 中，这对应于 NATIVE_CONTEXT_FIELDS 中的 ARRAY_FUNCTION_INDEX
const arr = new Array(1, 2, 3);
console.log(arr);

// 使用 Promise 构造函数创建 Promise
// 在 C++ 中，这对应于 NATIVE_CONTEXT_FIELDS 中的 PROMISE_FUNCTION_INDEX
const promise = new Promise((resolve, reject) => {
  setTimeout(resolve, 1000);
});
promise.then(() => console.log("Promise resolved"));

// 使用 Map 对象
// 在 C++ 中，这对应于 NATIVE_CONTEXT_FIELDS 中的 JS_MAP_FUN_INDEX
const map = new Map();
map.set('key', 'value');
console.log(map.get('key'));

// 使用 parseInt 函数
// 在 C++ 中，这对应于 NATIVE_CONTEXT_FIELDS 中的 GLOBAL_PARSE_INT_FUN_INDEX
const num = parseInt("10");
console.log(num);
```

这些 JavaScript 代码中使用的 `globalThis`, `Array`, `Promise`, `Map`, `parseInt` 等全局对象和函数，在 V8 引擎内部的 `NativeContext` 中都有对应的表示和存储。  `NativeContext` 就像一个容器，存放着 JavaScript 运行时环境的基础设施。

**如果有代码逻辑推理，请给出假设输入与输出:**

由于这个头文件主要是数据结构的定义，直接的代码逻辑推理比较少。但是，我们可以推断访问 `NativeContext` 中字段的逻辑：

**假设输入:**  V8 引擎需要获取全局 `Array` 构造函数。

**代码逻辑推理:**

1. V8 引擎内部会有一个指向当前 `NativeContext` 对象的指针。
2. 根据 `NATIVE_CONTEXT_FIELDS` 宏中的定义，`ARRAY_FUNCTION_INDEX`  代表了 `Array` 构造函数在 `NativeContext` 对象中的偏移量或索引。
3. V8 引擎会使用这个索引/偏移量，从 `NativeContext` 对象中读取相应的 `JSFunction` 对象，即 `Array` 构造函数。

**输出:** 指向 `Array` 构造函数的 `JSFunction` 对象的指针。

**如果涉及用户常见的编程错误，请举例说明:**

虽然 `contexts.h` 定义的是内部结构，但它直接影响着 JavaScript 的作用域和上下文行为，因此与用户常见的编程错误息息相关。

**示例 1: 闭包中的变量捕获错误:**

```javascript
function createCounter() {
  let count = 0;
  return {
    increment: function() {
      count++;
      console.log(count);
    }
  };
}

const counter1 = createCounter();
const counter2 = createCounter();

counter1.increment(); // 输出 1
counter2.increment(); // 输出 1
counter1.increment(); // 输出 2
```

**解释:**  `createCounter` 函数创建了一个闭包。返回的 `increment` 函数可以访问和修改其父作用域中的 `count` 变量。每个 `counter` 实例都有自己的上下文 (虽然这里是闭包的上下文，但概念类似)，维护着自己的 `count` 变量。理解上下文对于理解闭包的行为至关重要。

**示例 2: `this` 指向错误:**

```javascript
const myObject = {
  value: 10,
  getValue: function() {
    console.log(this.value);
  }
};

myObject.getValue(); // 输出 10

const getValueFunc = myObject.getValue;
getValueFunc(); // 输出 undefined (或在严格模式下报错)
```

**解释:**  `this` 的指向取决于函数的调用方式。当 `getValue` 作为 `myObject` 的方法调用时，`this` 指向 `myObject`。但是，当将 `getValue` 赋值给 `getValueFunc` 并直接调用时，`this` 的指向会发生改变 (通常指向全局对象或 `undefined`)。理解函数调用的上下文对于正确使用 `this` 非常重要。 `NativeContext` 中包含了全局对象等信息，这些信息会影响 `this` 的解析。

**总结 `v8/src/objects/contexts.h` 的功能 (第 1 部分):**

总而言之，`v8/src/objects/contexts.h` 的主要功能是：

* **定义了 V8 引擎中用于管理执行上下文的核心数据结构 `Context` 和其特殊形式 `NativeContext`。**
* **详细定义了 `NativeContext` 对象的内部结构，包括大量的预先创建和缓存的 JavaScript 内置对象、函数和元数据，为 JavaScript 代码的执行提供了基础环境。**
* **定义了在上下文中查找变量的标志，控制着作用域链和原型链的查找行为。**

这个头文件是 V8 引擎中非常核心的部分，它为 JavaScript 代码的执行提供了必要的上下文环境和运行时支持。理解它有助于深入理解 V8 引擎的内部工作原理。

### 提示词
```
这是目录为v8/src/objects/contexts.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/objects/contexts.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
// Copyright 2012 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_OBJECTS_CONTEXTS_H_
#define V8_OBJECTS_CONTEXTS_H_

#include "include/v8-promise.h"
#include "src/handles/handles.h"
#include "src/objects/fixed-array.h"
#include "src/objects/function-kind.h"
#include "src/objects/ordered-hash-table.h"
#include "src/objects/property-cell.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

class ContextSidePropertyCell;
class JSGlobalObject;
class JSGlobalProxy;
class MicrotaskQueue;
class NativeContext;
class RegExpMatchInfo;
struct VariableLookupResult;

enum ContextLookupFlags {
  FOLLOW_CONTEXT_CHAIN = 1 << 0,
  FOLLOW_PROTOTYPE_CHAIN = 1 << 1,

  DONT_FOLLOW_CHAINS = 0,
  FOLLOW_CHAINS = FOLLOW_CONTEXT_CHAIN | FOLLOW_PROTOTYPE_CHAIN,
};

// Heap-allocated activation contexts.
//
// Contexts are implemented as FixedArray-like objects having a fixed
// header with a set of common fields.
//
// Note: Context must have no virtual functions and Context objects
// must always be allocated via Heap::AllocateContext() or
// Factory::NewContext.

#define NATIVE_CONTEXT_FIELDS(V)                                               \
  V(GLOBAL_PROXY_INDEX, JSGlobalProxy, global_proxy_object)                    \
  /* TODO(ishell): Actually we store exactly EmbedderDataArray here but */     \
  /* it's already UBSan-fiendly and doesn't require a star... So declare */    \
  /* it as a HeapObject for now. */                                            \
  V(EMBEDDER_DATA_INDEX, HeapObject, embedder_data)                            \
  V(CONTINUATION_PRESERVED_EMBEDDER_DATA_INDEX, HeapObject,                    \
    continuation_preserved_embedder_data)                                      \
  V(GENERATOR_NEXT_INTERNAL, JSFunction, generator_next_internal)              \
  V(ASYNC_MODULE_EVALUATE_INTERNAL, JSFunction,                                \
    async_module_evaluate_internal)                                            \
  V(REFLECT_APPLY_INDEX, JSFunction, reflect_apply)                            \
  V(REFLECT_CONSTRUCT_INDEX, JSFunction, reflect_construct)                    \
  V(PERFORM_PROMISE_THEN_INDEX, JSFunction, perform_promise_then)              \
  V(PROMISE_THEN_INDEX, JSFunction, promise_then)                              \
  V(PROMISE_RESOLVE_INDEX, JSFunction, promise_resolve)                        \
  V(FUNCTION_PROTOTYPE_APPLY_INDEX, JSFunction, function_prototype_apply)      \
  /* TypedArray constructors - these must stay in order! */                    \
  V(UINT8_ARRAY_FUN_INDEX, JSFunction, uint8_array_fun)                        \
  V(INT8_ARRAY_FUN_INDEX, JSFunction, int8_array_fun)                          \
  V(UINT16_ARRAY_FUN_INDEX, JSFunction, uint16_array_fun)                      \
  V(INT16_ARRAY_FUN_INDEX, JSFunction, int16_array_fun)                        \
  V(UINT32_ARRAY_FUN_INDEX, JSFunction, uint32_array_fun)                      \
  V(INT32_ARRAY_FUN_INDEX, JSFunction, int32_array_fun)                        \
  V(BIGUINT64_ARRAY_FUN_INDEX, JSFunction, biguint64_array_fun)                \
  V(BIGINT64_ARRAY_FUN_INDEX, JSFunction, bigint64_array_fun)                  \
  V(UINT8_CLAMPED_ARRAY_FUN_INDEX, JSFunction, uint8_clamped_array_fun)        \
  V(FLOAT32_ARRAY_FUN_INDEX, JSFunction, float32_array_fun)                    \
  V(FLOAT64_ARRAY_FUN_INDEX, JSFunction, float64_array_fun)                    \
  V(FLOAT16_ARRAY_FUN_INDEX, JSFunction, float16_array_fun)                    \
  V(RAB_GSAB_UINT8_ARRAY_MAP_INDEX, Map, rab_gsab_uint8_array_map)             \
  V(RAB_GSAB_INT8_ARRAY_MAP_INDEX, Map, rab_gsab_int8_array_map)               \
  V(RAB_GSAB_UINT16_ARRAY_MAP_INDEX, Map, rab_gsab_uint16_array_map)           \
  V(RAB_GSAB_INT16_ARRAY_MAP_INDEX, Map, rab_gsab_int16_array_map)             \
  V(RAB_GSAB_UINT32_ARRAY_MAP_INDEX, Map, rab_gsab_uint32_array_map)           \
  V(RAB_GSAB_INT32_ARRAY_MAP_INDEX, Map, rab_gsab_int32_array_map)             \
  V(RAB_GSAB_BIGUINT64_ARRAY_MAP_INDEX, Map, rab_gsab_biguint64_array_map)     \
  V(RAB_GSAB_BIGINT64_ARRAY_MAP_INDEX, Map, rab_gsab_bigint64_array_map)       \
  V(RAB_GSAB_UINT8_CLAMPED_ARRAY_MAP_INDEX, Map,                               \
    rab_gsab_uint8_clamped_array_map)                                          \
  V(RAB_GSAB_FLOAT32_ARRAY_MAP_INDEX, Map, rab_gsab_float32_array_map)         \
  V(RAB_GSAB_FLOAT64_ARRAY_MAP_INDEX, Map, rab_gsab_float64_array_map)         \
  V(RAB_GSAB_FLOAT16_ARRAY_MAP_INDEX, Map, rab_gsab_float16_array_map)         \
  /* Below is alpha-sorted */                                                  \
  V(ABSTRACT_MODULE_SOURCE_FUNCTION_INDEX, JSFunction,                         \
    abstract_module_source_function)                                           \
  V(ABSTRACT_MODULE_SOURCE_PROTOTYPE_INDEX, JSObject,                          \
    abstract_module_source_prototype)                                          \
  V(ACCESSOR_PROPERTY_DESCRIPTOR_MAP_INDEX, Map,                               \
    accessor_property_descriptor_map)                                          \
  V(ALLOW_CODE_GEN_FROM_STRINGS_INDEX, Object, allow_code_gen_from_strings)    \
  V(ARRAY_BUFFER_FUN_INDEX, JSFunction, array_buffer_fun)                      \
  V(ARRAY_BUFFER_MAP_INDEX, Map, array_buffer_map)                             \
  V(ARRAY_BUFFER_NOINIT_FUN_INDEX, JSFunction, array_buffer_noinit_fun)        \
  V(ARRAY_FUNCTION_INDEX, JSFunction, array_function)                          \
  V(ARRAY_JOIN_STACK_INDEX, HeapObject, array_join_stack)                      \
  V(ARRAY_FROM_ASYNC_INDEX, JSFunction, from_async)                            \
  V(ASYNC_FROM_SYNC_ITERATOR_MAP_INDEX, Map, async_from_sync_iterator_map)     \
  V(ASYNC_FUNCTION_FUNCTION_INDEX, JSFunction, async_function_constructor)     \
  V(ASYNC_FUNCTION_OBJECT_MAP_INDEX, Map, async_function_object_map)           \
  V(ASYNC_GENERATOR_FUNCTION_FUNCTION_INDEX, JSFunction,                       \
    async_generator_function_function)                                         \
  V(BIGINT_FUNCTION_INDEX, JSFunction, bigint_function)                        \
  V(BOOLEAN_FUNCTION_INDEX, JSFunction, boolean_function)                      \
  V(BOUND_FUNCTION_WITH_CONSTRUCTOR_MAP_INDEX, Map,                            \
    bound_function_with_constructor_map)                                       \
  V(BOUND_FUNCTION_WITHOUT_CONSTRUCTOR_MAP_INDEX, Map,                         \
    bound_function_without_constructor_map)                                    \
  V(CALL_AS_CONSTRUCTOR_DELEGATE_INDEX, JSFunction,                            \
    call_as_constructor_delegate)                                              \
  V(CALL_AS_FUNCTION_DELEGATE_INDEX, JSFunction, call_as_function_delegate)    \
  V(CALLSITE_FUNCTION_INDEX, JSFunction, callsite_function)                    \
  V(CONTEXT_EXTENSION_FUNCTION_INDEX, JSFunction, context_extension_function)  \
  V(DATA_PROPERTY_DESCRIPTOR_MAP_INDEX, Map, data_property_descriptor_map)     \
  V(DATA_VIEW_FUN_INDEX, JSFunction, data_view_fun)                            \
  V(DATE_FUNCTION_INDEX, JSFunction, date_function)                            \
  V(DEBUG_CONTEXT_ID_INDEX, (UnionOf<Smi, Undefined>), debug_context_id)       \
  V(EMPTY_FUNCTION_INDEX, JSFunction, empty_function)                          \
  V(ERROR_MESSAGE_FOR_CODE_GEN_FROM_STRINGS_INDEX, Object,                     \
    error_message_for_code_gen_from_strings)                                   \
  V(ERROR_MESSAGE_FOR_WASM_CODE_GEN_INDEX, Object,                             \
    error_message_for_wasm_code_gen)                                           \
  V(ERRORS_THROWN_INDEX, Smi, errors_thrown)                                   \
  V(EXTRAS_BINDING_OBJECT_INDEX, JSObject, extras_binding_object)              \
  V(FAST_ALIASED_ARGUMENTS_MAP_INDEX, Map, fast_aliased_arguments_map)         \
  V(FAST_TEMPLATE_INSTANTIATIONS_CACHE_INDEX, FixedArray,                      \
    fast_template_instantiations_cache)                                        \
  V(FUNCTION_FUNCTION_INDEX, JSFunction, function_function)                    \
  V(FUNCTION_PROTOTYPE_INDEX, JSObject, function_prototype)                    \
  V(GENERATOR_FUNCTION_FUNCTION_INDEX, JSFunction,                             \
    generator_function_function)                                               \
  V(GENERATOR_OBJECT_PROTOTYPE_MAP_INDEX, Map, generator_object_prototype_map) \
  V(ASYNC_GENERATOR_OBJECT_PROTOTYPE_MAP_INDEX, Map,                           \
    async_generator_object_prototype_map)                                      \
  V(INITIAL_ARRAY_ITERATOR_MAP_INDEX, Map, initial_array_iterator_map)         \
  V(INITIAL_ARRAY_ITERATOR_PROTOTYPE_INDEX, JSObject,                          \
    initial_array_iterator_prototype)                                          \
  V(INITIAL_ARRAY_PROTOTYPE_INDEX, JSObject, initial_array_prototype)          \
  V(INITIAL_ERROR_PROTOTYPE_INDEX, JSObject, initial_error_prototype)          \
  V(INITIAL_GENERATOR_PROTOTYPE_INDEX, JSObject, initial_generator_prototype)  \
  V(INITIAL_ASYNC_ITERATOR_PROTOTYPE_INDEX, JSObject,                          \
    initial_async_iterator_prototype)                                          \
  V(INITIAL_ASYNC_GENERATOR_PROTOTYPE_INDEX, JSObject,                         \
    initial_async_generator_prototype)                                         \
  V(INITIAL_ITERATOR_PROTOTYPE_INDEX, JSObject, initial_iterator_prototype)    \
  V(INITIAL_DISPOSABLE_STACK_PROTOTYPE_INDEX, JSObject,                        \
    initial_disposable_stack_prototype)                                        \
  V(INITIAL_MAP_ITERATOR_PROTOTYPE_INDEX, JSObject,                            \
    initial_map_iterator_prototype)                                            \
  V(INITIAL_MAP_PROTOTYPE_MAP_INDEX, Map, initial_map_prototype_map)           \
  V(INITIAL_OBJECT_PROTOTYPE_INDEX, JSObject, initial_object_prototype)        \
  V(INITIAL_SET_ITERATOR_PROTOTYPE_INDEX, JSObject,                            \
    initial_set_iterator_prototype)                                            \
  V(INITIAL_SET_PROTOTYPE_INDEX, JSObject, initial_set_prototype)              \
  V(INITIAL_SET_PROTOTYPE_MAP_INDEX, Map, initial_set_prototype_map)           \
  V(INITIAL_STRING_ITERATOR_MAP_INDEX, Map, initial_string_iterator_map)       \
  V(INITIAL_STRING_ITERATOR_PROTOTYPE_INDEX, JSObject,                         \
    initial_string_iterator_prototype)                                         \
  V(INITIAL_STRING_PROTOTYPE_INDEX, JSObject, initial_string_prototype)        \
  V(INITIAL_WEAKMAP_PROTOTYPE_MAP_INDEX, Map, initial_weakmap_prototype_map)   \
  V(INITIAL_WEAKSET_PROTOTYPE_MAP_INDEX, Map, initial_weakset_prototype_map)   \
  V(INTL_COLLATOR_FUNCTION_INDEX, JSFunction, intl_collator_function)          \
  V(INTL_DATE_TIME_FORMAT_FUNCTION_INDEX, JSFunction,                          \
    intl_date_time_format_function)                                            \
  V(INTL_DISPLAY_NAMES_FUNCTION_INDEX, JSFunction,                             \
    intl_display_names_function)                                               \
  V(INTL_DURATION_FORMAT_FUNCTION_INDEX, JSFunction,                           \
    intl_duration_format_function)                                             \
  V(INTL_NUMBER_FORMAT_FUNCTION_INDEX, JSFunction,                             \
    intl_number_format_function)                                               \
  V(INTL_LOCALE_FUNCTION_INDEX, JSFunction, intl_locale_function)              \
  V(INTL_LIST_FORMAT_FUNCTION_INDEX, JSFunction, intl_list_format_function)    \
  V(INTL_PLURAL_RULES_FUNCTION_INDEX, JSFunction, intl_plural_rules_function)  \
  V(INTL_RELATIVE_TIME_FORMAT_FUNCTION_INDEX, JSFunction,                      \
    intl_relative_time_format_function)                                        \
  V(INTL_SEGMENTER_FUNCTION_INDEX, JSFunction, intl_segmenter_function)        \
  V(INTL_SEGMENTS_MAP_INDEX, Map, intl_segments_map)                           \
  V(INTL_SEGMENT_DATA_OBJECT_MAP_INDEX, Map, intl_segment_data_object_map)     \
  V(INTL_SEGMENT_DATA_OBJECT_WORDLIKE_MAP_INDEX, Map,                          \
    intl_segment_data_object_wordlike_map)                                     \
  V(INTL_SEGMENT_ITERATOR_MAP_INDEX, Map, intl_segment_iterator_map)           \
  V(ITERATOR_FILTER_HELPER_MAP_INDEX, Map, iterator_filter_helper_map)         \
  V(ITERATOR_MAP_HELPER_MAP_INDEX, Map, iterator_map_helper_map)               \
  V(ITERATOR_TAKE_HELPER_MAP_INDEX, Map, iterator_take_helper_map)             \
  V(ITERATOR_DROP_HELPER_MAP_INDEX, Map, iterator_drop_helper_map)             \
  V(ITERATOR_FLAT_MAP_HELPER_MAP_INDEX, Map, iterator_flatMap_helper_map)      \
  V(ITERATOR_FUNCTION_INDEX, JSFunction, iterator_function)                    \
  V(VALID_ITERATOR_WRAPPER_MAP_INDEX, Map, valid_iterator_wrapper_map)         \
  V(ITERATOR_RESULT_MAP_INDEX, Map, iterator_result_map)                       \
  V(JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX, Map,                               \
    js_array_packed_smi_elements_map)                                          \
  V(JS_ARRAY_HOLEY_SMI_ELEMENTS_MAP_INDEX, Map,                                \
    js_array_holey_smi_elements_map)                                           \
  V(JS_ARRAY_PACKED_ELEMENTS_MAP_INDEX, Map, js_array_packed_elements_map)     \
  V(JS_ARRAY_HOLEY_ELEMENTS_MAP_INDEX, Map, js_array_holey_elements_map)       \
  V(JS_ARRAY_PACKED_DOUBLE_ELEMENTS_MAP_INDEX, Map,                            \
    js_array_packed_double_elements_map)                                       \
  V(JS_ARRAY_HOLEY_DOUBLE_ELEMENTS_MAP_INDEX, Map,                             \
    js_array_holey_double_elements_map)                                        \
  V(JS_ARRAY_TEMPLATE_LITERAL_OBJECT_MAP, Map,                                 \
    js_array_template_literal_object_map)                                      \
  V(JS_DISPOSABLE_STACK_FUNCTION_INDEX, JSFunction,                            \
    js_disposable_stack_function)                                              \
  V(JS_ASYNC_DISPOSABLE_STACK_FUNCTION_INDEX, JSFunction,                      \
    js_async_disposable_stack_function)                                        \
  V(JS_DISPOSABLE_STACK_MAP_INDEX, Map, js_disposable_stack_map)               \
  V(JS_MAP_FUN_INDEX, JSFunction, js_map_fun)                                  \
  V(JS_MAP_MAP_INDEX, Map, js_map_map)                                         \
  V(JS_MODULE_NAMESPACE_MAP, Map, js_module_namespace_map)                     \
  V(JS_RAW_JSON_MAP, Map, js_raw_json_map)                                     \
  V(JS_SET_FUN_INDEX, JSFunction, js_set_fun)                                  \
  V(JS_SET_MAP_INDEX, Map, js_set_map)                                         \
  V(JS_WEAK_MAP_FUN_INDEX, JSFunction, js_weak_map_fun)                        \
  V(JS_WEAK_SET_FUN_INDEX, JSFunction, js_weak_set_fun)                        \
  V(JS_WEAK_REF_FUNCTION_INDEX, JSFunction, js_weak_ref_fun)                   \
  V(JS_FINALIZATION_REGISTRY_FUNCTION_INDEX, JSFunction,                       \
    js_finalization_registry_fun)                                              \
  V(JS_TEMPORAL_CALENDAR_FUNCTION_INDEX, JSFunction,                           \
    temporal_calendar_function)                                                \
  V(JS_TEMPORAL_DURATION_FUNCTION_INDEX, JSFunction,                           \
    temporal_duration_function)                                                \
  V(JS_TEMPORAL_INSTANT_FUNCTION_INDEX, JSFunction, temporal_instant_function) \
  V(JS_TEMPORAL_PLAIN_DATE_FUNCTION_INDEX, JSFunction,                         \
    temporal_plain_date_function)                                              \
  V(JS_TEMPORAL_PLAIN_DATE_TIME_FUNCTION_INDEX, JSFunction,                    \
    temporal_plain_date_time_function)                                         \
  V(JS_TEMPORAL_PLAIN_MONTH_DAY_FUNCTION_INDEX, JSFunction,                    \
    temporal_plain_month_day_function)                                         \
  V(JS_TEMPORAL_PLAIN_TIME_FUNCTION_INDEX, JSFunction,                         \
    temporal_plain_time_function)                                              \
  V(JS_TEMPORAL_PLAIN_YEAR_MONTH_FUNCTION_INDEX, JSFunction,                   \
    temporal_plain_year_month_function)                                        \
  V(JS_TEMPORAL_TIME_ZONE_FUNCTION_INDEX, JSFunction,                          \
    temporal_time_zone_function)                                               \
  V(JS_TEMPORAL_ZONED_DATE_TIME_FUNCTION_INDEX, JSFunction,                    \
    temporal_zoned_date_time_function)                                         \
  V(JSON_OBJECT, JSObject, json_object)                                        \
  V(PROMISE_WITHRESOLVERS_RESULT_MAP_INDEX, Map,                               \
    promise_withresolvers_result_map)                                          \
  V(TEMPORAL_OBJECT_INDEX, HeapObject, temporal_object)                        \
  V(TEMPORAL_INSTANT_FIXED_ARRAY_FROM_ITERABLE_FUNCTION_INDEX, JSFunction,     \
    temporal_instant_fixed_array_from_iterable)                                \
  V(STRING_FIXED_ARRAY_FROM_ITERABLE_FUNCTION_INDEX, JSFunction,               \
    string_fixed_array_from_iterable)                                          \
  /* Context maps */                                                           \
  V(META_MAP_INDEX, Map, meta_map)                                             \
  V(FUNCTION_CONTEXT_MAP_INDEX, Map, function_context_map)                     \
  V(MODULE_CONTEXT_MAP_INDEX, Map, module_context_map)                         \
  V(EVAL_CONTEXT_MAP_INDEX, Map, eval_context_map)                             \
  V(SCRIPT_CONTEXT_MAP_INDEX, Map, script_context_map)                         \
  V(AWAIT_CONTEXT_MAP_INDEX, Map, await_context_map)                           \
  V(BLOCK_CONTEXT_MAP_INDEX, Map, block_context_map)                           \
  V(CATCH_CONTEXT_MAP_INDEX, Map, catch_context_map)                           \
  V(WITH_CONTEXT_MAP_INDEX, Map, with_context_map)                             \
  V(DEBUG_EVALUATE_CONTEXT_MAP_INDEX, Map, debug_evaluate_context_map)         \
  V(JS_RAB_GSAB_DATA_VIEW_MAP_INDEX, Map, js_rab_gsab_data_view_map)           \
  V(MAP_CACHE_INDEX, Object, map_cache)                                        \
  V(MAP_KEY_ITERATOR_MAP_INDEX, Map, map_key_iterator_map)                     \
  V(MAP_KEY_VALUE_ITERATOR_MAP_INDEX, Map, map_key_value_iterator_map)         \
  V(MAP_VALUE_ITERATOR_MAP_INDEX, Map, map_value_iterator_map)                 \
  V(MATH_RANDOM_INDEX_INDEX, Smi, math_random_index)                           \
  V(MATH_RANDOM_STATE_INDEX, ByteArray, math_random_state)                     \
  V(MATH_RANDOM_CACHE_INDEX, FixedDoubleArray, math_random_cache)              \
  V(NORMALIZED_MAP_CACHE_INDEX, Object, normalized_map_cache)                  \
  V(NUMBER_FUNCTION_INDEX, JSFunction, number_function)                        \
  V(OBJECT_FUNCTION_INDEX, JSFunction, object_function)                        \
  V(OBJECT_FUNCTION_PROTOTYPE_INDEX, JSObject, object_function_prototype)      \
  V(OBJECT_FUNCTION_PROTOTYPE_MAP_INDEX, Map, object_function_prototype_map)   \
  V(PROMISE_HOOK_INIT_FUNCTION_INDEX, Object, promise_hook_init_function)      \
  V(PROMISE_HOOK_BEFORE_FUNCTION_INDEX, Object, promise_hook_before_function)  \
  V(PROMISE_HOOK_AFTER_FUNCTION_INDEX, Object, promise_hook_after_function)    \
  V(PROMISE_HOOK_RESOLVE_FUNCTION_INDEX, Object,                               \
    promise_hook_resolve_function)                                             \
  V(PROXY_CALLABLE_MAP_INDEX, Map, proxy_callable_map)                         \
  V(PROXY_CONSTRUCTOR_MAP_INDEX, Map, proxy_constructor_map)                   \
  V(PROXY_FUNCTION_INDEX, JSFunction, proxy_function)                          \
  V(PROXY_MAP_INDEX, Map, proxy_map)                                           \
  V(PROXY_REVOCABLE_RESULT_MAP_INDEX, Map, proxy_revocable_result_map)         \
  V(PROMISE_PROTOTYPE_INDEX, JSObject, promise_prototype)                      \
  V(RECORDER_CONTEXT_ID, Object, recorder_context_id)                          \
  V(REGEXP_EXEC_FUNCTION_INDEX, JSFunction, regexp_exec_function)              \
  V(REGEXP_FUNCTION_INDEX, JSFunction, regexp_function)                        \
  V(REGEXP_LAST_MATCH_INFO_INDEX, RegExpMatchInfo, regexp_last_match_info)     \
  V(REGEXP_MATCH_ALL_FUNCTION_INDEX, JSFunction, regexp_match_all_function)    \
  V(REGEXP_MATCH_FUNCTION_INDEX, JSFunction, regexp_match_function)            \
  V(REGEXP_PROTOTYPE_INDEX, JSObject, regexp_prototype)                        \
  V(REGEXP_PROTOTYPE_MAP_INDEX, Map, regexp_prototype_map)                     \
  V(REGEXP_REPLACE_FUNCTION_INDEX, JSFunction, regexp_replace_function)        \
  V(REGEXP_RESULT_MAP_INDEX, Map, regexp_result_map)                           \
  V(REGEXP_RESULT_WITH_INDICES_MAP_INDEX, Map, regexp_result_with_indices_map) \
  V(REGEXP_RESULT_INDICES_MAP_INDEX, Map, regexp_result_indices_map)           \
  V(REGEXP_SEARCH_FUNCTION_INDEX, JSFunction, regexp_search_function)          \
  V(REGEXP_SPLIT_FUNCTION_INDEX, JSFunction, regexp_split_function)            \
  V(INITIAL_REGEXP_STRING_ITERATOR_PROTOTYPE_MAP_INDEX, Map,                   \
    initial_regexp_string_iterator_prototype_map)                              \
  V(SCRIPT_CONTEXT_TABLE_INDEX, ScriptContextTable, script_context_table)      \
  V(SCRIPT_EXECUTION_CALLBACK_INDEX, Object, script_execution_callback)        \
  V(SECURITY_TOKEN_INDEX, Object, security_token)                              \
  V(SERIALIZED_OBJECTS, HeapObject, serialized_objects)                        \
  V(SET_VALUE_ITERATOR_MAP_INDEX, Map, set_value_iterator_map)                 \
  V(SET_KEY_VALUE_ITERATOR_MAP_INDEX, Map, set_key_value_iterator_map)         \
  V(SHARED_ARRAY_BUFFER_FUN_INDEX, JSFunction, shared_array_buffer_fun)        \
  V(SLOPPY_ARGUMENTS_MAP_INDEX, Map, sloppy_arguments_map)                     \
  V(SLOW_ALIASED_ARGUMENTS_MAP_INDEX, Map, slow_aliased_arguments_map)         \
  V(STRICT_ARGUMENTS_MAP_INDEX, Map, strict_arguments_map)                     \
  V(SLOW_OBJECT_WITH_NULL_PROTOTYPE_MAP, Map,                                  \
    slow_object_with_null_prototype_map)                                       \
  V(SLOW_OBJECT_WITH_OBJECT_PROTOTYPE_MAP, Map,                                \
    slow_object_with_object_prototype_map)                                     \
  V(SLOW_TEMPLATE_INSTANTIATIONS_CACHE_INDEX, SimpleNumberDictionary,          \
    slow_template_instantiations_cache)                                        \
  V(ATOMICS_WAITASYNC_PROMISES, OrderedHashSet, atomics_waitasync_promises)    \
  V(WASM_DEBUG_MAPS, FixedArray, wasm_debug_maps)                              \
  /* Fast Path Protectors */                                                   \
  V(REGEXP_SPECIES_PROTECTOR_INDEX, PropertyCell, regexp_species_protector)    \
  /* All *_FUNCTION_MAP_INDEX definitions used by Context::FunctionMapIndex */ \
  /* must remain together. */                                                  \
  V(SLOPPY_FUNCTION_MAP_INDEX, Map, sloppy_function_map)                       \
  V(SLOPPY_FUNCTION_WITH_NAME_MAP_INDEX, Map, sloppy_function_with_name_map)   \
  V(SLOPPY_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX, Map,                          \
    sloppy_function_without_prototype_map)                                     \
  V(SLOPPY_FUNCTION_WITH_READONLY_PROTOTYPE_MAP_INDEX, Map,                    \
    sloppy_function_with_readonly_prototype_map)                               \
  V(STRICT_FUNCTION_MAP_INDEX, Map, strict_function_map)                       \
  V(STRICT_FUNCTION_WITH_NAME_MAP_INDEX, Map, strict_function_with_name_map)   \
  V(STRICT_FUNCTION_WITH_READONLY_PROTOTYPE_MAP_INDEX, Map,                    \
    strict_function_with_readonly_prototype_map)                               \
  V(STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX, Map,                          \
    strict_function_without_prototype_map)                                     \
  V(METHOD_WITH_NAME_MAP_INDEX, Map, method_with_name_map)                     \
  V(ASYNC_FUNCTION_MAP_INDEX, Map, async_function_map)                         \
  V(ASYNC_FUNCTION_WITH_NAME_MAP_INDEX, Map, async_function_with_name_map)     \
  V(GENERATOR_FUNCTION_MAP_INDEX, Map, generator_function_map)                 \
  V(GENERATOR_FUNCTION_WITH_NAME_MAP_INDEX, Map,                               \
    generator_function_with_name_map)                                          \
  V(ASYNC_GENERATOR_FUNCTION_MAP_INDEX, Map, async_generator_function_map)     \
  V(ASYNC_GENERATOR_FUNCTION_WITH_NAME_MAP_INDEX, Map,                         \
    async_generator_function_with_name_map)                                    \
  V(CLASS_FUNCTION_MAP_INDEX, Map, class_function_map)                         \
  V(STRING_FUNCTION_INDEX, JSFunction, string_function)                        \
  V(STRING_FUNCTION_PROTOTYPE_MAP_INDEX, Map, string_function_prototype_map)   \
  V(SYMBOL_FUNCTION_INDEX, JSFunction, symbol_function)                        \
  V(IS_WASM_JS_INSTALLED_INDEX, Smi, is_wasm_js_installed)                     \
  V(IS_WASM_JSPI_INSTALLED_INDEX, Smi, is_wasm_jspi_installed)                 \
  V(WASM_WEBASSEMBLY_OBJECT_INDEX, JSObject, wasm_webassembly_object)          \
  V(WASM_EXPORTED_FUNCTION_MAP_INDEX, Map, wasm_exported_function_map)         \
  V(WASM_TAG_CONSTRUCTOR_INDEX, JSFunction, wasm_tag_constructor)              \
  V(WASM_EXCEPTION_CONSTRUCTOR_INDEX, JSFunction, wasm_exception_constructor)  \
  V(WASM_GLOBAL_CONSTRUCTOR_INDEX, JSFunction, wasm_global_constructor)        \
  V(WASM_INSTANCE_CONSTRUCTOR_INDEX, JSFunction, wasm_instance_constructor)    \
  V(WASM_JS_TAG_INDEX, JSObject, wasm_js_tag)                                  \
  V(WASM_MEMORY_CONSTRUCTOR_INDEX, JSFunction, wasm_memory_constructor)        \
  V(WASM_MODULE_CONSTRUCTOR_INDEX, JSFunction, wasm_module_constructor)        \
  V(WASM_TABLE_CONSTRUCTOR_INDEX, JSFunction, wasm_table_constructor)          \
  V(WASM_SUSPENDING_CONSTRUCTOR_INDEX, JSFunction,                             \
    wasm_suspending_constructor)                                               \
  V(WASM_SUSPENDER_CONSTRUCTOR_INDEX, JSFunction, wasm_suspender_constructor)  \
  V(WASM_SUSPENDING_MAP, Map, wasm_suspending_map)                             \
  V(WASM_SUSPENDING_PROTOTYPE, JSObject, wasm_suspending_prototype)            \
  V(TEMPLATE_WEAKMAP_INDEX, HeapObject, template_weakmap)                      \
  V(TYPED_ARRAY_FUN_INDEX, JSFunction, typed_array_function)                   \
  V(TYPED_ARRAY_PROTOTYPE_INDEX, JSObject, typed_array_prototype)              \
  V(ARRAY_ENTRIES_ITERATOR_INDEX, JSFunction, array_entries_iterator)          \
  V(ARRAY_FOR_EACH_ITERATOR_INDEX, JSFunction, array_for_each_iterator)        \
  V(ARRAY_KEYS_ITERATOR_INDEX, JSFunction, array_keys_iterator)                \
  V(ARRAY_VALUES_ITERATOR_INDEX, JSFunction, array_values_iterator)            \
  V(ERROR_FUNCTION_INDEX, JSFunction, error_function)                          \
  V(ERROR_TO_STRING, JSFunction, error_to_string)                              \
  V(EVAL_ERROR_FUNCTION_INDEX, JSFunction, eval_error_function)                \
  V(AGGREGATE_ERROR_FUNCTION_INDEX, JSFunction, aggregate_error_function)      \
  V(GLOBAL_EVAL_FUN_INDEX, JSFunction, global_eval_fun)                        \
  V(GLOBAL_PARSE_FLOAT_FUN_INDEX, JSFunction, global_parse_float_fun)          \
  V(GLOBAL_PARSE_INT_FUN_INDEX, JSFunction, global_parse_int_fun)              \
  V(GLOBAL_PROXY_FUNCTION_INDEX, JSFunction, global_proxy_function)            \
  V(MAP_DELETE_INDEX, JSFunction, map_delete)                                  \
  V(MAP_GET_INDEX, JSFunction, map_get)                                        \
  V(MAP_HAS_INDEX, JSFunction, map_has)                                        \
  V(MAP_SET_INDEX, JSFunction, map_set)                                        \
  V(FINALIZATION_REGISTRY_CLEANUP_SOME, JSFunction,                            \
    finalization_registry_cleanup_some)                                        \
  V(FUNCTION_HAS_INSTANCE_INDEX, JSFunction, function_has_instance)            \
  V(FUNCTION_TO_STRING_INDEX, JSFunction, function_to_string)                  \
  V(OBJECT_TO_STRING, JSFunction, object_to_string)                            \
  V(OBJECT_VALUE_OF_FUNCTION_INDEX, JSFunction, object_value_of_function)      \
  V(PROMISE_ALL_INDEX, JSFunction, promise_all)                                \
  V(PROMISE_ALL_SETTLED_INDEX, JSFunction, promise_all_settled)                \
  V(PROMISE_ANY_INDEX, JSFunction, promise_any)                                \
  V(PROMISE_FUNCTION_INDEX, JSFunction, promise_function)                      \
  V(RANGE_ERROR_FUNCTION_INDEX, JSFunction, range_error_function)              \
  V(REFERENCE_ERROR_FUNCTION_INDEX, JSFunction, reference_error_function)      \
  V(SET_ADD_INDEX, JSFunction, set_add)                                        \
  V(SET_DELETE_INDEX, JSFunction, set_delete)                                  \
  V(SET_HAS_INDEX, JSFunction, set_has)                                        \
  V(SHADOW_REALM_IMPORT_VALUE_REJECTED_INDEX, JSFunction,                      \
    shadow_realm_import_value_rejected)                                        \
  V(SUPPRESSED_ERROR_FUNCTION_INDEX, JSFunction, suppressed_error_function)    \
  V(SYNTAX_ERROR_FUNCTION_INDEX, JSFunction, syntax_error_function)            \
  V(TYPE_ERROR_FUNCTION_INDEX, JSFunction, type_error_function)                \
  V(URI_ERROR_FUNCTION_INDEX, JSFunction, uri_error_function)                  \
  V(WASM_COMPILE_ERROR_FUNCTION_INDEX, JSFunction,                             \
    wasm_compile_error_function)                                               \
  V(WASM_LINK_ERROR_FUNCTION_INDEX, JSFunction, wasm_link_error_function)      \
  V(WASM_RUNTIME_ERROR_FUNCTION_INDEX, JSFunction,                             \
    wasm_runtime_error_function)                                               \
  V(WEAKMAP_SET_INDEX, JSFunction, weakmap_set)                                \
  V(WEAKMAP_GET_INDEX, JSFunction, weakmap_get)                                \
  V(WEAKMAP_DELETE_INDEX, JSFunction, weakmap_delete)                          \
  V(WEAKSET_ADD_INDEX, JSFunction, weakset_add)                                \
  V(WRAPPED_FUNCTION_MAP_INDEX, Map, wrapped_function_map)                     \
  V(RETAINED_MAPS, Object, retained_maps)                                      \
  V(SHARED_SPACE_JS_OBJECT_HAS_INSTANCE_INDEX, JSFunction,                     \
    shared_space_js_object_has_instance)

#include "torque-generated/src/objects/contexts-tq.inc"

// JSFunctions are pairs (context, function code), sometimes also called
// closures. A Context object is used to represent function contexts and
// dynamically pushed 'with' contexts (or 'scopes' in ECMA-262 speak).
//
// At runtime, the contexts build a stack in parallel to the execution
// stack, with the top-most context being the current context. All contexts
// have the following slots:
//
// [ scope_info     ]  This is the scope info describing the current context. It
//                     contains the names of statically allocated context slots,
//                     and stack-allocated locals.  The names are needed for
//                     dynamic lookups in the presence of 'with' or 'eval', and
//                     for the debugger.
//
// [ previous       ]  A pointer to the previous context.
//
// [ extension      ]  Additional data. This slot is only available when
//                     ScopeInfo::HasContextExtensionSlot returns true.
//
//                     For native contexts, it contains the global object.
//                     For module contexts, it contains the module object.
//                     For await contexts, it contains the generator object.
//                     For var block contexts, it may contain an "extension
//                     object".
//                     For with contexts, it contain
```