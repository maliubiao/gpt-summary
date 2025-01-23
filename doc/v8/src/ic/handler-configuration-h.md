Response:
Let's break down the request and formulate the response step-by-step.

**1. Understanding the Core Request:**

The request asks for an explanation of the `handler-configuration.h` file in V8. Key aspects of the request are:

* **Functionality:**  What does this file *do*?
* **Torque Check:**  Is it a Torque file (`.tq`)?
* **JavaScript Relation:**  How does it connect to JavaScript concepts?  Illustrate with JS examples.
* **Code Logic/Inference:**  If there are logical patterns, provide examples with input/output.
* **Common Errors:**  Does it relate to typical programming mistakes?  Give examples.

**2. Initial Analysis of the File Content:**

* **Header File:** The `#ifndef V8_IC_HANDLER_CONFIGURATION_H_` indicates this is a C++ header file. This immediately tells us it's not a Torque file.
* **Includes:** The included headers (`globals.h`, `handles/maybe-handles.h`, etc.) point towards core V8 infrastructure related to memory management, object representation, and internal utilities.
* **Namespaces:** The `v8::internal` namespace confirms this is an internal V8 component.
* **`WasmValueType` Enum:** This suggests a connection to WebAssembly.
* **`LoadHandler` and `StoreHandler` Classes:** These are the central pieces. The names strongly imply they manage how V8 *loads* and *stores* properties.
* **Enums within Handlers:**  The `Kind` enums within `LoadHandler` and `StoreHandler` suggest different strategies or scenarios for loading and storing properties (e.g., `kField`, `kGlobal`, `kProxy`).
* **Bit Fields:** The use of `base::BitField` indicates that information about the load/store operation is being compactly encoded within a small number of bits. This is typical for performance optimization in VMs.
* **Static `Create` Methods:**  Methods like `LoadNormal`, `LoadField`, `StoreField` suggest ways to create specific handler types.
* **`OBJECT_CONSTRUCTORS` Macro:** This is a common V8 macro for generating constructor-related code.

**3. Addressing Each Point of the Request:**

* **Functionality:** Based on the analysis, the core functionality is **defining and configuring handlers for property access (loads and stores) within the V8 engine.** These handlers likely optimize common access patterns. The bitfield encoding suggests an effort to represent different access scenarios efficiently.

* **Torque Check:** The file ends with `.h`, not `.tq`. Therefore, it's **not a Torque file.**

* **JavaScript Relation:** This requires connecting the internal V8 concepts to what a JavaScript developer experiences.
    * **Property Access:**  The handlers directly relate to how JavaScript accesses properties (`object.property` or `object['property']`).
    * **Prototypes:** The presence of handlers like `LoadConstantFromPrototype` and methods involving prototypes (`LoadFromPrototype`, `StoreThroughPrototype`) clearly link to JavaScript's prototype inheritance model.
    * **Accessors (Getters/Setters):**  `LoadAccessorFromPrototype`, `StoreAccessorFromPrototype`, `LoadApiGetter`, `StoreApiSetter` connect to JavaScript getter and setter definitions.
    * **Proxies:** `LoadProxy`, `StoreProxy` tie into the JavaScript `Proxy` object.
    * **WebAssembly:** The `WasmValueType` and handler methods for WASM arrays/structs show integration with WebAssembly.

* **Code Logic/Inference:** The bit fields and the different `Kind` enums imply a selection process. Based on the type of object and the property being accessed, V8 will choose a specific handler.
    * **Hypothetical Load:** If you access `object.x` on a "fast" object with a field named `x`, the `LoadField` handler would likely be used. The `FieldIndex` would specify the memory location of `x`.
    * **Hypothetical Store:** If you assign to a property that has a setter defined in the prototype chain, the `StoreAccessorFromPrototype` handler would be relevant.

* **Common Errors:**  This is trickier, as this file is about *internal optimization*. However, we can infer some connections:
    * **`undefined` Errors:** The `LoadNonExistent` handler suggests this relates to accessing non-existent properties, which in JavaScript results in `undefined`.
    * **Type Errors (Setters):** If a setter expects a specific type and the assigned value is wrong, this might involve the `StoreApiSetter` and lead to a TypeError.
    * **Performance Issues:** While not *errors*, the existence of different handlers (fast vs. slow) implies that certain coding patterns can lead to less efficient property access. Repeatedly accessing properties on objects that fall into the "slow" category could be a performance bottleneck.

**4. Structuring the Response:**

Organize the information clearly, addressing each point of the request explicitly. Use headings and bullet points to enhance readability. Provide concrete JavaScript examples where possible.

**5. Refinement and Clarity:**

Review the drafted response for clarity and accuracy. Ensure the JavaScript examples are correct and directly illustrate the concepts. Double-check the connections between the internal V8 code and the observable JavaScript behavior. For example, emphasize that the header file itself doesn't *cause* errors, but its contents are part of the machinery that handles JavaScript operations, including those that can lead to errors.
这个头文件 `v8/src/ic/handler-configuration.h` 定义了 V8 引擎中用于 **内联缓存 (Inline Caches, ICs)** 的 **处理器 (Handlers)** 的配置和结构。更具体地说，它定义了用于优化对象属性 **加载 (load)** 和 **存储 (store)** 操作的各种处理器类型。

**主要功能：**

1. **定义 `LoadHandler` 类:**  `LoadHandler` 类用于表示不同类型的属性加载操作的优化策略。它使用位域 (bit fields) 来高效地编码各种信息，例如：
    * **加载操作的类型 (`Kind`):**  例如，从一个普通的属性、一个字段、一个全局对象、一个原型链上的属性等加载。
    * **其他配置信息:** 例如，是否需要进行访问权限检查，是否需要在原型链上查找等。
    * **特定类型的信息:** 例如，如果是加载字段，则包含字段的索引、是否为Wasm结构体、是否为双精度浮点数等。如果是加载数组元素，则包含元素的类型、是否允许越界访问等。

2. **定义 `StoreHandler` 类:**  `StoreHandler` 类与 `LoadHandler` 类似，但用于表示不同类型的属性存储操作的优化策略。它也使用位域来编码信息，例如：
    * **存储操作的类型 (`Kind`):** 例如，存储到一个字段、一个常量字段、一个原型链上的访问器、一个全局代理对象等。
    * **其他配置信息:** 例如，是否需要进行访问权限检查，是否需要在原型链上查找等。
    * **特定类型的信息:** 例如，如果是存储到字段，则包含字段的描述符索引、是否在对象内部、表示类型等。

3. **定义 `WasmValueType` 枚举:**  此枚举定义了 WebAssembly 中使用的各种值类型，这些类型在加载和存储 WebAssembly 对象的属性时使用。

4. **提供创建和解码处理器的静态方法:** `LoadHandler` 和 `StoreHandler` 类都提供了一系列的静态方法，用于创建特定类型的处理器 (`LoadNormal`, `LoadField`, `StoreField` 等) 以及从处理器中解码信息 (`GetHandlerKind`, `GetKeyedAccessLoadMode` 等)。

**如果 `v8/src/ic/handler-configuration.h` 以 `.tq` 结尾：**

如果文件以 `.tq` 结尾，那么它将是一个 **V8 Torque 源代码文件**。 Torque 是一种 V8 特有的领域特定语言 (DSL)，用于生成高效的 C++ 代码，特别是用于实现运行时函数和优化代码。然而，根据你提供的文件名，它以 `.h` 结尾，所以它是 **一个 C++ 头文件，而不是 Torque 文件**。

**与 JavaScript 功能的关系 (通过 IC 机制)：**

`handler-configuration.h` 中定义的处理器是 V8 引擎内联缓存机制的核心组成部分。内联缓存是一种用于优化重复执行的 JavaScript 代码的技术。当 V8 执行属性访问操作 (例如 `object.property` 或 `object.property = value`) 时，它会尝试记录操作的类型和相关信息 (例如对象的形状、属性的位置等)。这些信息被编码成一个处理器并存储在代码中。

下次执行相同的代码时，V8 可以直接使用缓存的处理器，而无需重新进行属性查找等操作，从而显著提高性能。

**JavaScript 示例：**

考虑以下 JavaScript 代码：

```javascript
function getProperty(obj) {
  return obj.x;
}

const myObject = { x: 10 };
getProperty(myObject); // 第一次调用

const anotherObject = { x: 20 };
getProperty(anotherObject); // 第二次调用
```

当第一次调用 `getProperty(myObject)` 时，V8 可能会创建一个 `LoadHandler`，其 `Kind` 为 `kField`，并记录 `myObject` 的形状和 `x` 属性的偏移量。

当第二次调用 `getProperty(anotherObject)` 时，如果 `anotherObject` 的形状与 `myObject` 兼容 (例如，也具有名为 `x` 的属性，并且在内存中的布局相似)，V8 可以直接使用之前缓存的 `LoadHandler`，快速地加载 `anotherObject.x` 的值，而无需重新进行完整的属性查找过程。

**代码逻辑推理 (假设输入与输出)：**

假设有一个 `LoadHandler`，其 `KindBits` 为 `kField`，并且编码了以下信息：

* `IsInobjectBits`: 1 (表示属性在对象内部)
* `IsDoubleBits`: 0 (表示属性不是双精度浮点数)
* `FieldIndexBits`: 5 (假设属性 `x` 的偏移量为 5)

**假设输入:**  一个指向 `myObject` 的指针，该对象在内存中有一个偏移量为 5 的整数属性 `x`，其值为 10。

**输出:**  加载操作会直接读取 `myObject` 偏移量为 5 的内存位置，并返回整数值 `10`。

**涉及用户常见的编程错误：**

虽然 `handler-configuration.h` 本身不直接涉及用户的编程错误，但它所支持的内联缓存机制的行为会受到用户代码的影响。一些可能导致内联缓存失效或效率降低的常见编程错误包括：

1. **形状不一致的对象:**  如果频繁地使用具有不同属性集或属性顺序的对象调用同一个函数，会导致 V8 难以有效地缓存加载和存储操作。

   ```javascript
   function getX(obj) {
     return obj.x;
   }

   getX({ x: 1, y: 2 });
   getX({ a: 3, x: 4 }); // 对象形状不同，可能导致 IC 失效
   ```

2. **频繁地添加或删除属性:**  动态地修改对象的属性会改变对象的形状，导致之前缓存的处理器失效，需要重新生成。

   ```javascript
   const obj = { a: 1 };
   function accessA(o) {
     return o.a;
   }
   accessA(obj);
   obj.b = 2; // 添加属性，可能导致 IC 失效
   accessA(obj);
   ```

3. **访问不存在的属性:** 虽然 V8 可以缓存对不存在属性的访问 (`LoadNonExistent` 处理器)，但过多的此类操作可能暗示着代码中存在逻辑错误。

   ```javascript
   function getZ(obj) {
     return obj.z; // 如果 obj 通常没有 z 属性
   }
   ```

**总结：**

`v8/src/ic/handler-configuration.h` 是 V8 引擎中一个关键的头文件，它定义了用于优化属性加载和存储操作的各种处理器类型。这些处理器是内联缓存机制的核心，通过高效地编码和重用属性访问的信息，显著提高了 JavaScript 代码的执行性能。理解这些内部机制有助于开发者编写更高效的 JavaScript 代码。

### 提示词
```
这是目录为v8/src/ic/handler-configuration.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/handler-configuration.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_IC_HANDLER_CONFIGURATION_H_
#define V8_IC_HANDLER_CONFIGURATION_H_

#include "src/common/globals.h"
#include "src/handles/maybe-handles.h"
#include "src/heap/heap.h"
#include "src/objects/data-handler.h"
#include "src/objects/elements-kind.h"
#include "src/objects/field-index.h"
#include "src/objects/objects.h"
#include "src/utils/utils.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

class JSProxy;

enum class WasmValueType {
  kI8,
  kI16,
  kI32,
  kU32,  // Used only for loading WasmArray length.
  kI64,
  kF32,
  kF64,
  kS128,

  kRef,
  kRefNull,

  kNumTypes
};

// A set of bit fields representing Smi handlers for loads and a HeapObject
// that represents load handlers that can't be encoded in a Smi.
// TODO(ishell): move to load-handler.h
class LoadHandler final : public DataHandler {
 public:
  DECL_PRINTER(LoadHandler)
  DECL_VERIFIER(LoadHandler)

  enum class Kind {
    kElement,
    kIndexedString,
    kNormal,
    kGlobal,
    kField,
    kConstantFromPrototype,
    kAccessorFromPrototype,
    kNativeDataProperty,
    kApiGetter,
    kApiGetterHolderIsPrototype,
    kInterceptor,
    kSlow,
    kProxy,
    kNonExistent,
    kModuleExport
  };
  using KindBits = base::BitField<Kind, 0, 4>;

  // Defines whether access rights check should be done on lookup start object.
  // Applicable to named property kinds only when loading value from prototype
  // chain. Ignored when loading from lookup start object.
  using DoAccessCheckOnLookupStartObjectBits = KindBits::Next<bool, 1>;

  // Defines whether a lookup should be done on lookup start object before
  // proceeding to the prototype chain. Applicable to named property kinds only
  // when loading value from prototype chain. Ignored when loading from lookup
  // start object.
  using LookupOnLookupStartObjectBits =
      DoAccessCheckOnLookupStartObjectBits::Next<bool, 1>;

  //
  // Encoding when KindBits contains kNativeDataProperty.
  //

  // Index of a value entry in the descriptor array.
  using DescriptorBits =
      LookupOnLookupStartObjectBits::Next<unsigned, kDescriptorIndexBitCount>;
  // Make sure we don't overflow the smi.
  static_assert(DescriptorBits::kLastUsedBit < kSmiValueSize);

  //
  // Encoding when KindBits contains kField.
  //
  using IsWasmStructBits = LookupOnLookupStartObjectBits::Next<bool, 1>;

  //
  // Encoding when KindBits contains kField and IsWasmStructBits is 0.
  //
  using IsInobjectBits = IsWasmStructBits::Next<bool, 1>;
  using IsDoubleBits = IsInobjectBits::Next<bool, 1>;
  // +1 here is to cover all possible JSObject header sizes.
  using FieldIndexBits =
      IsDoubleBits::Next<unsigned, kDescriptorIndexBitCount + 1>;
  // Make sure we don't overflow the smi.
  static_assert(FieldIndexBits::kLastUsedBit < kSmiValueSize);

  //
  // Encoding when KindBits contains kField and IsWasmStructBits is 1.
  //
  using WasmFieldTypeBits = IsWasmStructBits::Next<WasmValueType, 4>;
  using WasmFieldOffsetBits = WasmFieldTypeBits::Next<unsigned, 20>;
  // Make sure we don't overflow the smi.
  static_assert(WasmFieldOffsetBits::kLastUsedBit < kSmiValueSize);

  //
  // Encoding when KindBits contains kElement or kIndexedString.
  //
  using AllowOutOfBoundsBits = LookupOnLookupStartObjectBits::Next<bool, 1>;

  //
  // Encoding when KindBits contains kElement.
  //
  using IsWasmArrayBits = AllowOutOfBoundsBits::Next<bool, 1>;

  //
  // Encoding when KindBits contains kElement and IsWasmArrayBits is 0.
  //
  using IsJsArrayBits = IsWasmArrayBits::Next<bool, 1>;
  using AllowHandlingHole = IsJsArrayBits::Next<bool, 1>;
  using ElementsKindBits = AllowHandlingHole::Next<ElementsKind, 8>;
  // Make sure we don't overflow the smi.
  static_assert(ElementsKindBits::kLastUsedBit < kSmiValueSize);

  //
  // Encoding when KindBits contains kElement and IsWasmArrayBits is 1.
  //
  using WasmArrayTypeBits = IsWasmArrayBits::Next<WasmValueType, 4>;
  // Make sure we don't overflow the smi.
  static_assert(WasmArrayTypeBits::kLastUsedBit < kSmiValueSize);

  //
  // Encoding when KindBits contains kModuleExport.
  //
  using ExportsIndexBits = LookupOnLookupStartObjectBits::Next<
      unsigned,
      kSmiValueSize - LookupOnLookupStartObjectBits::kLastUsedBit - 1>;
  static_assert(ExportsIndexBits::kLastUsedBit < kSmiValueSize);

  // Decodes kind from Smi-handler.
  static inline Kind GetHandlerKind(Tagged<Smi> smi_handler);

  // Creates a Smi-handler for loading a property from a slow object.
  static inline Handle<Smi> LoadNormal(Isolate* isolate);

  // Creates a Smi-handler for loading a property from a global object.
  static inline Handle<Smi> LoadGlobal(Isolate* isolate);

  // Creates a Smi-handler for loading a property from an object with an
  // interceptor.
  static inline Handle<Smi> LoadInterceptor(Isolate* isolate);

  // Creates a Smi-handler for loading a property from an object.
  static inline Handle<Smi> LoadSlow(Isolate* isolate);

  // Creates a Smi-handler for loading a field from fast object.
  static inline Handle<Smi> LoadField(Isolate* isolate, FieldIndex field_index);

  // Creates a Smi-handler for loading a cached constant from fast
  // prototype object.
  static inline Handle<Smi> LoadConstantFromPrototype(Isolate* isolate);

  // Creates a Smi-handler for calling a getter on a fast object.
  static inline Handle<Smi> LoadAccessorFromPrototype(Isolate* isolate);

  // Creates a Smi-handler for calling a getter on a proxy.
  static inline Handle<Smi> LoadProxy(Isolate* isolate);

  // Creates a Smi-handler for loading a native data property from fast object.
  static inline Handle<Smi> LoadNativeDataProperty(Isolate* isolate,
                                                   int descriptor);

  // Creates a Smi-handler for calling a native getter on a fast object.
  static inline Handle<Smi> LoadApiGetter(Isolate* isolate,
                                          bool holder_is_receiver);

  // Creates a Smi-handler for loading a Module export.
  // |index| is the index to the "value" slot in the Module's "exports"
  // dictionary.
  static inline Handle<Smi> LoadModuleExport(Isolate* isolate, int index);

  static inline Handle<Smi> LoadWasmStructField(Isolate* isolate,
                                                WasmValueType type, int offset);
  static inline Handle<Smi> LoadWasmArrayElement(Isolate* isolate,
                                                 WasmValueType type);

  // Creates a data handler that represents a load of a non-existent property.
  // {holder} is the object from which the property is loaded. If no holder is
  // needed (e.g., for "nonexistent"), null_value() may be passed in.
  static Handle<Object> LoadFullChain(Isolate* isolate,
                                      Handle<Map> receiver_map,
                                      const MaybeObjectHandle& holder,
                                      Handle<Smi> smi_handler);

  // Creates a data handler that represents a prototype chain check followed
  // by given Smi-handler that encoded a load from the holder.
  static Handle<Object> LoadFromPrototype(
      Isolate* isolate, Handle<Map> receiver_map, Handle<JSReceiver> holder,
      Tagged<Smi> smi_handler,
      MaybeObjectHandle maybe_data1 = MaybeObjectHandle(),
      MaybeObjectHandle maybe_data2 = MaybeObjectHandle());

  // Creates a Smi-handler for loading a non-existent property. Works only as
  // a part of prototype chain check.
  static inline Handle<Smi> LoadNonExistent(Isolate* isolate);

  // Creates a Smi-handler for loading an element.
  static inline Handle<Smi> LoadElement(Isolate* isolate,
                                        ElementsKind elements_kind,
                                        bool is_js_array,
                                        KeyedAccessLoadMode load_mode);

  // Creates a Smi-handler for loading from a String.
  static inline Handle<Smi> LoadIndexedString(Isolate* isolate,
                                              KeyedAccessLoadMode load_mode);

  // Decodes the KeyedAccessLoadMode from a {handler}.
  static KeyedAccessLoadMode GetKeyedAccessLoadMode(
      Tagged<MaybeObject> handler);

  // Returns true iff the handler can be used in the "holder != lookup start
  // object" case.
  static bool CanHandleHolderNotLookupStart(Tagged<Object> handler);

#if defined(OBJECT_PRINT)
  static void PrintHandler(Tagged<Object> handler, std::ostream& os);
#endif  // defined(OBJECT_PRINT)

  OBJECT_CONSTRUCTORS(LoadHandler, DataHandler);
};

// A set of bit fields representing Smi handlers for stores and a HeapObject
// that represents store handlers that can't be encoded in a Smi.
// TODO(ishell): move to store-handler.h
class StoreHandler final : public DataHandler {
 public:
  DECL_PRINTER(StoreHandler)
  DECL_VERIFIER(StoreHandler)

  enum class Kind {
    kField,
    kConstField,
    kAccessorFromPrototype,
    kNativeDataProperty,
    kSharedStructField,
    kApiSetter,
    kApiSetterHolderIsPrototype,
    kGlobalProxy,
    kNormal,
    kInterceptor,
    kSlow,
    kProxy,
    kKindsNumber  // Keep last
  };
  using KindBits = base::BitField<Kind, 0, 4>;

  // Applicable to kGlobalProxy, kProxy kinds.

  // Defines whether access rights check should be done on lookup start object.
  using DoAccessCheckOnLookupStartObjectBits = KindBits::Next<bool, 1>;

  // Defines whether a lookup should be done on lookup start object before
  // proceeding to the prototype chain. Applicable to named property kinds only
  // when storing through prototype chain. Ignored when storing to holder.
  using LookupOnLookupStartObjectBits =
      DoAccessCheckOnLookupStartObjectBits::Next<bool, 1>;

  // Applicable to kField, kAccessor and kNativeDataProperty.

  // Index of a value entry in the descriptor array.
  using DescriptorBits =
      LookupOnLookupStartObjectBits::Next<unsigned, kDescriptorIndexBitCount>;

  //
  // Encoding when KindBits contains kStoreSlow.
  //
  using KeyedAccessStoreModeBits =
      LookupOnLookupStartObjectBits::Next<KeyedAccessStoreMode, 2>;

  //
  // Encoding when KindBits contains kField.
  //
  using IsInobjectBits = DescriptorBits::Next<bool, 1>;
  using RepresentationBits = IsInobjectBits::Next<Representation::Kind, 3>;
  // +1 here is to cover all possible JSObject header sizes.
  using FieldIndexBits =
      RepresentationBits::Next<unsigned, kDescriptorIndexBitCount + 1>;
  // Make sure we don't overflow the smi.
  static_assert(FieldIndexBits::kLastUsedBit < kSmiValueSize);

  // Creates a Smi-handler for storing a field to fast object.
  static inline Handle<Smi> StoreField(Isolate* isolate, int descriptor,
                                       FieldIndex field_index,
                                       PropertyConstness constness,
                                       Representation representation);

  // Creates a Smi-handler for storing a field to a JSSharedStruct.
  static inline Handle<Smi> StoreSharedStructField(
      Isolate* isolate, int descriptor, FieldIndex field_index,
      Representation representation);

  // Create a store transition handler which doesn't check prototype chain.
  static MaybeObjectHandle StoreOwnTransition(Isolate* isolate,
                                              Handle<Map> transition_map);

  // Create a store transition handler with prototype chain validity cell check.
  static MaybeObjectHandle StoreTransition(Isolate* isolate,
                                           Handle<Map> transition_map);

  // Creates a Smi-handler for storing a native data property on a fast object.
  static inline Handle<Smi> StoreNativeDataProperty(Isolate* isolate,
                                                    int descriptor);

  // Creates a Smi-handler for calling a setter on a fast object.
  static inline Handle<Smi> StoreAccessorFromPrototype(Isolate* isolate);

  // Creates a Smi-handler for calling a native setter on a fast object.
  static inline Handle<Smi> StoreApiSetter(Isolate* isolate,
                                           bool holder_is_receiver);

  static Handle<Object> StoreThroughPrototype(
      Isolate* isolate, Handle<Map> receiver_map, Handle<JSReceiver> holder,
      Tagged<Smi> smi_handler,
      MaybeObjectHandle maybe_data1 = MaybeObjectHandle(),
      MaybeObjectHandle maybe_data2 = MaybeObjectHandle());

  static Handle<Object> StoreElementTransition(
      Isolate* isolate, DirectHandle<Map> receiver_map,
      DirectHandle<Map> transition, KeyedAccessStoreMode store_mode,
      MaybeHandle<UnionOf<Smi, Cell>> prev_validity_cell = kNullMaybeHandle);

  static Handle<Object> StoreProxy(Isolate* isolate, Handle<Map> receiver_map,
                                   Handle<JSProxy> proxy,
                                   Handle<JSReceiver> receiver);

  // Creates a handler for storing a property to the property cell of a global
  // object.
  static MaybeObjectHandle StoreGlobal(Handle<PropertyCell> cell);

  // Creates a Smi-handler for storing a property to a global proxy object.
  static inline Handle<Smi> StoreGlobalProxy(Isolate* isolate);

  // Creates a Smi-handler for storing a property to a slow object.
  static inline Handle<Smi> StoreNormal(Isolate* isolate);

  // Creates a Smi-handler for storing a property to an interceptor.
  static inline Handle<Smi> StoreInterceptor(Isolate* isolate);

  static inline Handle<Code> StoreSloppyArgumentsBuiltin(
      Isolate* isolate, KeyedAccessStoreMode mode);
  static inline Handle<Code> StoreFastElementBuiltin(Isolate* isolate,
                                                     KeyedAccessStoreMode mode);
  static inline Handle<Code> ElementsTransitionAndStoreBuiltin(
      Isolate* isolate, KeyedAccessStoreMode mode);

  // Creates a Smi-handler for storing a property.
  static inline Handle<Smi> StoreSlow(
      Isolate* isolate,
      KeyedAccessStoreMode store_mode = KeyedAccessStoreMode::kInBounds);

  // Creates a Smi-handler for storing a property on a proxy.
  static inline Handle<Smi> StoreProxy(Isolate* isolate);
  static inline Tagged<Smi> StoreProxy();

  // Decodes the KeyedAccessStoreMode from a {handler}.
  static KeyedAccessStoreMode GetKeyedAccessStoreMode(
      Tagged<MaybeObject> handler);

#if defined(OBJECT_PRINT)
  static void PrintHandler(Tagged<Object> handler, std::ostream& os);
#endif  // defined(OBJECT_PRINT)

 private:
  static inline Handle<Smi> StoreField(Isolate* isolate, Kind kind,
                                       int descriptor, FieldIndex field_index,
                                       Representation representation);

  OBJECT_CONSTRUCTORS(StoreHandler, DataHandler);
};

inline const char* WasmValueType2String(WasmValueType type);

std::ostream& operator<<(std::ostream& os, WasmValueType type);

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_IC_HANDLER_CONFIGURATION_H_
```