Response:
Let's break down the thought process for analyzing this C++ header file.

1. **Understand the Context:** The first line `// Copyright 2016 the V8 project authors.` immediately tells us this is part of the V8 JavaScript engine. The path `v8/src/ic/handler-configuration-inl.h` provides more context: it's related to the "IC" (Inline Cache) and "handler configuration."  The `.inl.h` suffix suggests it's an inline implementation file for a header.

2. **Identify the Core Purpose:** The file defines two classes: `LoadHandler` and `StoreHandler`. These names strongly suggest that the file is responsible for configuring how property *loads* and *stores* are handled within V8's IC.

3. **Analyze `LoadHandler`:**
    * **`GetHandlerKind`:**  This static method takes a `Tagged<Smi>` and returns a `LoadHandler::Kind`. This hints at a pattern where handler information is encoded within a Small Integer (Smi). The `KindBits::decode` reinforces this.
    * **`LoadNormal`, `LoadGlobal`, etc.:** A series of static methods with descriptive names like `LoadGlobal`, `LoadInterceptor`, `LoadField`. Each returns a `Handle<Smi>`. This confirms the encoding idea – each method creates a `Smi` representing a specific load handling strategy.
    * **Encoding Logic:**  Methods like `LoadField` and `LoadWasmStructField` use bitwise OR operations (`|`) and helper structures like `KindBits`, `IsInobjectBits`, etc. This indicates that the `Smi` is being used as a bitfield to pack multiple pieces of information about the load operation.
    * **Specific Load Scenarios:**  The names of the methods reveal various load scenarios that V8 handles, such as loading from:
        * Regular properties (`LoadNormal`)
        * Global objects (`LoadGlobal`)
        * Interceptors (`LoadInterceptor`)
        * Object fields (`LoadField`)
        * WASM structures (`LoadWasmStructField`)
        * Prototypes (`LoadConstantFromPrototype`, `LoadAccessorFromPrototype`)
        * Proxies (`LoadProxy`)
        * Native data properties (`LoadNativeDataProperty`)
        * API getters (`LoadApiGetter`)
        * Module exports (`LoadModuleExport`)
        * Non-existent properties (`LoadNonExistent`)
        * Array elements (`LoadElement`)
        * Strings (`LoadIndexedString`)
        * WASM arrays (`LoadWasmArrayElement`)

4. **Analyze `StoreHandler`:**
    * **Similar Structure:**  Like `LoadHandler`, it has static methods returning `Handle<Smi>` or `Handle<Code>`. This indicates a similar encoding strategy for store operations.
    * **Store Scenarios:** Methods like `StoreGlobalProxy`, `StoreNormal`, `StoreInterceptor`, `StoreField`, etc., cover various store scenarios.
    * **Builtin Code:**  `StoreHandler` has methods that return `Handle<Code>`, such as `StoreSloppyArgumentsBuiltin` and `StoreFastElementBuiltin`. This suggests that for some common or performance-critical store operations, V8 uses pre-compiled code (builtins). The `KeyedAccessStoreMode` parameter hints at different strategies for storing elements in indexed properties (like arrays).
    * **Distinction between `Smi` and `Code`:**  The use of both `Handle<Smi>` and `Handle<Code>` is important. `Smi` likely represents simpler store cases where the handler can be described with a few bits, while `Code` is used for more complex scenarios requiring actual execution.

5. **Infer Overall Functionality:** Based on the individual method analysis, the file's primary function is to *configure* and *represent* different ways that property loads and stores can be performed within the V8 engine. The `Smi` encoding acts as a compact representation of this configuration. This configuration is likely used by the Inline Cache (IC) to optimize property access.

6. **Check for `.tq` Extension:** The prompt specifically asks about a `.tq` extension. The file ends with `.h`, so it's *not* a Torque file.

7. **Relate to JavaScript (If Applicable):** Since this file deals with property access, there's a direct connection to how JavaScript code interacts with objects. Examples of property access (`object.property`, `object['property']`) are relevant.

8. **Code Logic and Assumptions:**  The encoding logic using bitwise operations is clear. Assumptions about the input and output of specific encoding/decoding functions (like `KindBits::encode`) can be made based on the method names and parameters.

9. **Common Programming Errors:**  Thinking about how this relates to JavaScript, incorrect property access (e.g., accessing non-existent properties, trying to write to read-only properties) are relevant. Type errors could also be related (e.g., trying to store the wrong type in a typed array).

10. **Review and Organize:** Finally, organize the findings into clear sections addressing each part of the prompt (functionality, Torque, JavaScript examples, code logic, common errors). Use clear and concise language.

This systematic approach of analyzing the code structure, method names, and data types allows for a comprehensive understanding of the file's purpose and its connection to the broader V8 engine and JavaScript.
看起来你提供的是 V8 引擎中 `v8/src/ic/handler-configuration-inl.h` 文件的内容。让我们来分析一下它的功能。

**功能概述:**

`v8/src/ic/handler-configuration-inl.h` 文件定义了用于配置和表示 V8 引擎中 **Inline Cache (IC)** 处理器的内联函数。  IC 是 V8 用来优化属性访问（读取和写入）的关键机制。这个头文件主要定义了两种处理器的配置方式：

* **`LoadHandler`**:  用于配置属性 **读取** 操作的处理器。
* **`StoreHandler`**: 用于配置属性 **写入** 操作的处理器。

这些处理器配置信息被编码成 `Smi` (Small Integer) 对象，以便在运行时快速地进行判断和分发。  不同的配置代表了不同的属性访问场景和优化策略。

**详细功能分解:**

**1. `LoadHandler` (加载处理器):**

   * **`GetHandlerKind(Tagged<Smi> smi_handler)`:**  从一个 `Smi` 类型的处理器配置中解码出处理器的类型 (`Kind`).
   * **各种 `Load...` 方法 (例如 `LoadNormal`, `LoadGlobal`, `LoadField` 等):**  这些静态方法用于创建并返回代表不同加载场景的 `Smi` 处理器配置。每个方法对应一种特定的属性加载情况，例如：
      * `LoadNormal`: 常规的对象属性加载。
      * `LoadGlobal`: 全局对象的属性加载。
      * `LoadInterceptor`: 通过拦截器进行的属性加载。
      * `LoadField`:  直接从对象的字段中加载（包括内联字段和外部字段）。
      * `LoadWasmStructField`: 从 WebAssembly 结构的字段中加载。
      * `LoadConstantFromPrototype`: 从原型链上的常量属性加载。
      * `LoadAccessorFromPrototype`: 从原型链上的访问器属性加载。
      * `LoadProxy`: 通过代理对象进行加载。
      * `LoadNativeDataProperty`: 加载原生数据属性。
      * `LoadApiGetter`: 调用 C++ API Getter 进行加载。
      * `LoadModuleExport`: 加载模块导出的属性。
      * `LoadNonExistent`:  尝试加载不存在的属性。
      * `LoadElement`: 加载数组元素。
      * `LoadIndexedString`: 加载字符串的索引字符。
      * `LoadWasmArrayElement`: 加载 WebAssembly 数组的元素。

   * **编码方式:** 这些方法通常使用位运算 (`|`) 和预定义的位域 (`KindBits`, `IsInobjectBits` 等) 将不同的属性信息编码到 `Smi` 中。例如，`LoadField` 方法会将字段是否在对象内、是否是双精度浮点数、以及字段的索引编码到 `Smi` 中。

**2. `StoreHandler` (存储处理器):**

   * **各种 `Store...` 方法 (例如 `StoreGlobalProxy`, `StoreNormal`, `StoreField` 等):**  这些静态方法用于创建并返回代表不同存储场景的 `Smi` 或 `Code` 处理器配置。
      * `StoreGlobalProxy`: 存储到全局代理对象。
      * `StoreNormal`: 常规的对象属性存储。
      * `StoreInterceptor`: 通过拦截器进行属性存储。
      * `StoreField`: 存储到对象的字段中。
      * `StoreNativeDataProperty`: 存储到原生数据属性。
      * `StoreAccessorFromPrototype`: 存储到原型链上的访问器属性。
      * `StoreApiSetter`: 调用 C++ API Setter 进行存储。
      * `StoreProxy`: 通过代理对象进行存储。
      * `StoreSlow`:  慢速存储路径（通常用于处理更复杂的情况）。

   * **`StoreSloppyArgumentsBuiltin`, `StoreFastElementBuiltin`, `ElementsTransitionAndStoreBuiltin`:** 这些方法返回的是 `Code` 类型的处理器，指向预编译的内置函数。这通常用于优化性能关键的数组元素存储操作。它们会根据 `KeyedAccessStoreMode` 选择不同的内置函数，以处理不同的存储模式（例如，是否需要进行数组扩容，是否需要处理写入时复制等）。

   * **编码方式:**  类似于 `LoadHandler`，`StoreHandler` 也使用位运算来编码处理器信息。

**关于 .tq 扩展名:**

你提到如果文件以 `.tq` 结尾，那么它是一个 V8 Torque 源代码。这是正确的。`.tq` 文件是 V8 使用的 **Torque** 语言编写的，Torque 是一种用于定义 V8 内置函数和运行时调用的领域特定语言。

**与 JavaScript 的关系及示例:**

`v8/src/ic/handler-configuration-inl.h` 中定义的处理器配置直接影响 V8 如何执行 JavaScript 代码中的属性访问操作。

**JavaScript 示例:**

```javascript
const obj = { a: 10 };
const x = obj.a; // 这会触发一个 LoadHandler
obj.a = 20;     // 这会触发一个 StoreHandler

const arr = [1, 2, 3];
const y = arr[0]; // 可能会触发一个 LoadHandler::LoadElement
arr[0] = 4;     // 可能会触发一个 StoreHandler 的某种变体

globalThis.b = 30; // 可能会触发一个 StoreHandler::StoreGlobal
const z = globalThis.b; // 可能会触发一个 LoadHandler::LoadGlobal
```

当 V8 执行这些 JavaScript 代码时，它会使用 IC 来优化属性的访问。  `LoadHandler` 和 `StoreHandler` 中定义的配置决定了 V8 在不同场景下会采取哪种优化策略。例如，如果 V8 知道某个对象的属性是一个简单的内联字段，它可能会使用 `LoadHandler::LoadField` 来直接访问内存，而无需进行更复杂的查找。

**代码逻辑推理及假设输入输出:**

**假设输入:**  一个 `LoadHandler::LoadField` 方法的调用，传入一个 `Isolate` 指针和一个 `FieldIndex` 对象，该 `FieldIndex` 对象表示对象内部的一个双精度浮点数字段，索引为 2。

**代码:**

```c++
Handle<Smi> LoadHandler::LoadField(Isolate* isolate, FieldIndex field_index) {
  int config = KindBits::encode(Kind::kField) |
               IsInobjectBits::encode(field_index.is_inobject()) |
               IsDoubleBits::encode(field_index.is_double()) |
               FieldIndexBits::encode(field_index.index());
  return handle(Smi::FromInt(config), isolate);
}
```

**假设输入值:**

* `field_index.is_inobject()` 为 `true`
* `field_index.is_double()` 为 `true`
* `field_index.index()` 为 `2`
* 假设 `Kind::kField` 的编码值为 `0` (这是一个假设，实际值在 `handler-configuration.h` 中定义)

**输出:**

`config` 的计算过程如下：

* `KindBits::encode(Kind::kField)`  => `0`
* `IsInobjectBits::encode(true)` =>  假设编码为 `1 << X` (例如 `1 << 0 = 1`)
* `IsDoubleBits::encode(true)` => 假设编码为 `1 << Y` (例如 `1 << 1 = 2`)
* `FieldIndexBits::encode(2)` => 假设编码需要一定的位数，例如将 `2` 直接作为值。

最终 `config` 的值可能是 `0 | 1 | 2 | 2 = 5`。  然后，`handle(Smi::FromInt(5), isolate)` 会创建一个包含值 `5` 的 `Smi` 对象的句柄。

**涉及用户常见的编程错误:**

虽然这个文件本身是 V8 内部的实现细节，但它所处理的逻辑与用户常见的编程错误息息相关：

1. **访问未定义的属性:**

   ```javascript
   const obj = {};
   console.log(obj.nonExistent); //  这可能会在内部触发 LoadHandler::LoadNonExistent
   ```

   V8 需要判断属性是否存在，并根据情况返回 `undefined`。

2. **对 `undefined` 或 `null` 进行属性访问:**

   ```javascript
   let obj = null;
   console.log(obj.a); // TypeError: Cannot read properties of null
   ```

   V8 的 IC 机制需要在访问属性之前检查对象的类型，避免出现运行时错误。

3. **尝试写入只读属性:**

   ```javascript
   const obj = {};
   Object.defineProperty(obj, 'readonly', { value: 10, writable: false });
   obj.readonly = 20; // Strict mode 下会报错，非严格模式下赋值无效
   ```

   `StoreHandler` 需要处理只读属性的情况，确保不会意外修改。

4. **类型错误导致的属性访问失败:**

   ```javascript
   const num = 10;
   console.log(num.toUpperCase()); // TypeError: num.toUpperCase is not a function
   ```

   虽然这不直接涉及到 `LoadHandler` 或 `StoreHandler` 的核心功能，但 IC 也会参与到方法查找的过程中，而方法的查找和调用也是属性访问的一种形式。

**总结:**

`v8/src/ic/handler-configuration-inl.h` 是 V8 引擎中一个关键的内部文件，它定义了用于配置和表示 IC 处理器的机制。这些处理器负责优化 JavaScript 代码中的属性访问操作，涵盖了各种不同的加载和存储场景。理解这个文件有助于深入了解 V8 的优化策略和内部工作原理。

### 提示词
```
这是目录为v8/src/ic/handler-configuration-inl.h的一个v8源代码， 请列举一下它的功能, 
如果v8/src/ic/handler-configuration-inl.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
```

### 源代码
```c
// Copyright 2016 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef V8_IC_HANDLER_CONFIGURATION_INL_H_
#define V8_IC_HANDLER_CONFIGURATION_INL_H_

#include "src/builtins/builtins.h"
#include "src/execution/isolate.h"
#include "src/handles/handles-inl.h"
#include "src/ic/handler-configuration.h"
#include "src/objects/data-handler-inl.h"
#include "src/objects/field-index-inl.h"
#include "src/objects/objects-inl.h"
#include "src/objects/smi.h"

// Has to be the last include (doesn't have include guards):
#include "src/objects/object-macros.h"

namespace v8 {
namespace internal {

OBJECT_CONSTRUCTORS_IMPL(LoadHandler, DataHandler)

// Decodes kind from Smi-handler.
LoadHandler::Kind LoadHandler::GetHandlerKind(Tagged<Smi> smi_handler) {
  return KindBits::decode(smi_handler.value());
}

Handle<Smi> LoadHandler::LoadNormal(Isolate* isolate) {
  int config = KindBits::encode(Kind::kNormal);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadGlobal(Isolate* isolate) {
  int config = KindBits::encode(Kind::kGlobal);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadInterceptor(Isolate* isolate) {
  int config = KindBits::encode(Kind::kInterceptor);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadSlow(Isolate* isolate) {
  int config = KindBits::encode(Kind::kSlow);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadField(Isolate* isolate, FieldIndex field_index) {
  int config = KindBits::encode(Kind::kField) |
               IsInobjectBits::encode(field_index.is_inobject()) |
               IsDoubleBits::encode(field_index.is_double()) |
               FieldIndexBits::encode(field_index.index());
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadWasmStructField(Isolate* isolate,
                                             WasmValueType type, int offset) {
  int config = KindBits::encode(Kind::kField) | IsWasmStructBits::encode(true) |
               WasmFieldTypeBits::encode(type) |
               WasmFieldOffsetBits::encode(offset);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadConstantFromPrototype(Isolate* isolate) {
  int config = KindBits::encode(Kind::kConstantFromPrototype);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadAccessorFromPrototype(Isolate* isolate) {
  int config = KindBits::encode(Kind::kAccessorFromPrototype);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadProxy(Isolate* isolate) {
  int config = KindBits::encode(Kind::kProxy);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadNativeDataProperty(Isolate* isolate,
                                                int descriptor) {
  int config = KindBits::encode(Kind::kNativeDataProperty) |
               DescriptorBits::encode(descriptor);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadApiGetter(Isolate* isolate,
                                       bool holder_is_receiver) {
  int config =
      KindBits::encode(holder_is_receiver ? Kind::kApiGetter
                                          : Kind::kApiGetterHolderIsPrototype);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadModuleExport(Isolate* isolate, int index) {
  int config =
      KindBits::encode(Kind::kModuleExport) | ExportsIndexBits::encode(index);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadNonExistent(Isolate* isolate) {
  int config = KindBits::encode(Kind::kNonExistent);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadElement(Isolate* isolate,
                                     ElementsKind elements_kind,
                                     bool is_js_array,
                                     KeyedAccessLoadMode load_mode) {
  DCHECK_IMPLIES(LoadModeHandlesHoles(load_mode),
                 IsHoleyElementsKind(elements_kind));
  int config = KindBits::encode(Kind::kElement) |
               AllowOutOfBoundsBits::encode(LoadModeHandlesOOB(load_mode)) |
               ElementsKindBits::encode(elements_kind) |
               AllowHandlingHole::encode(LoadModeHandlesHoles(load_mode)) |
               IsJsArrayBits::encode(is_js_array);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadIndexedString(Isolate* isolate,
                                           KeyedAccessLoadMode load_mode) {
  int config = KindBits::encode(Kind::kIndexedString) |
               AllowOutOfBoundsBits::encode(LoadModeHandlesOOB(load_mode));
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> LoadHandler::LoadWasmArrayElement(Isolate* isolate,
                                              WasmValueType type) {
  int config = KindBits::encode(Kind::kElement) |
               IsWasmArrayBits::encode(true) | WasmArrayTypeBits::encode(type);
  return handle(Smi::FromInt(config), isolate);
}

OBJECT_CONSTRUCTORS_IMPL(StoreHandler, DataHandler)

Handle<Smi> StoreHandler::StoreGlobalProxy(Isolate* isolate) {
  int config = KindBits::encode(Kind::kGlobalProxy);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> StoreHandler::StoreNormal(Isolate* isolate) {
  int config = KindBits::encode(Kind::kNormal);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> StoreHandler::StoreInterceptor(Isolate* isolate) {
  int config = KindBits::encode(Kind::kInterceptor);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Code> StoreHandler::StoreSloppyArgumentsBuiltin(
    Isolate* isolate, KeyedAccessStoreMode mode) {
  switch (mode) {
    case KeyedAccessStoreMode::kInBounds:
      return BUILTIN_CODE(isolate, KeyedStoreIC_SloppyArguments_InBounds);
    case KeyedAccessStoreMode::kGrowAndHandleCOW:
      return BUILTIN_CODE(
          isolate, KeyedStoreIC_SloppyArguments_NoTransitionGrowAndHandleCOW);
    case KeyedAccessStoreMode::kIgnoreTypedArrayOOB:
      return BUILTIN_CODE(
          isolate,
          KeyedStoreIC_SloppyArguments_NoTransitionIgnoreTypedArrayOOB);
    case KeyedAccessStoreMode::kHandleCOW:
      return BUILTIN_CODE(isolate,
                          KeyedStoreIC_SloppyArguments_NoTransitionHandleCOW);
    default:
      UNREACHABLE();
  }
}

Handle<Code> StoreHandler::StoreFastElementBuiltin(Isolate* isolate,
                                                   KeyedAccessStoreMode mode) {
  switch (mode) {
    case KeyedAccessStoreMode::kInBounds:
      return BUILTIN_CODE(isolate, StoreFastElementIC_InBounds);
    case KeyedAccessStoreMode::kGrowAndHandleCOW:
      return BUILTIN_CODE(isolate,
                          StoreFastElementIC_NoTransitionGrowAndHandleCOW);
    case KeyedAccessStoreMode::kIgnoreTypedArrayOOB:
      return BUILTIN_CODE(isolate,
                          StoreFastElementIC_NoTransitionIgnoreTypedArrayOOB);
    case KeyedAccessStoreMode::kHandleCOW:
      return BUILTIN_CODE(isolate, StoreFastElementIC_NoTransitionHandleCOW);
    default:
      UNREACHABLE();
  }
}

Handle<Code> StoreHandler::ElementsTransitionAndStoreBuiltin(
    Isolate* isolate, KeyedAccessStoreMode mode) {
  switch (mode) {
    case KeyedAccessStoreMode::kInBounds:
      return BUILTIN_CODE(isolate, ElementsTransitionAndStore_InBounds);
    case KeyedAccessStoreMode::kGrowAndHandleCOW:
      return BUILTIN_CODE(
          isolate, ElementsTransitionAndStore_NoTransitionGrowAndHandleCOW);
    case KeyedAccessStoreMode::kIgnoreTypedArrayOOB:
      return BUILTIN_CODE(
          isolate, ElementsTransitionAndStore_NoTransitionIgnoreTypedArrayOOB);
    case KeyedAccessStoreMode::kHandleCOW:
      return BUILTIN_CODE(isolate,
                          ElementsTransitionAndStore_NoTransitionHandleCOW);
    default:
      UNREACHABLE();
  }
}

Handle<Smi> StoreHandler::StoreSlow(Isolate* isolate,
                                    KeyedAccessStoreMode store_mode) {
  int config = KindBits::encode(Kind::kSlow) |
               KeyedAccessStoreModeBits::encode(store_mode);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> StoreHandler::StoreProxy(Isolate* isolate) {
  return handle(StoreProxy(), isolate);
}

Tagged<Smi> StoreHandler::StoreProxy() {
  int config = KindBits::encode(Kind::kProxy);
  return Smi::FromInt(config);
}

Handle<Smi> StoreHandler::StoreField(Isolate* isolate, Kind kind,
                                     int descriptor, FieldIndex field_index,
                                     Representation representation) {
  DCHECK(!representation.IsNone());
  DCHECK(kind == Kind::kField || kind == Kind::kConstField ||
         kind == Kind::kSharedStructField);

  int config = KindBits::encode(kind) |
               IsInobjectBits::encode(field_index.is_inobject()) |
               RepresentationBits::encode(representation.kind()) |
               DescriptorBits::encode(descriptor) |
               FieldIndexBits::encode(field_index.index());
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> StoreHandler::StoreField(Isolate* isolate, int descriptor,
                                     FieldIndex field_index,
                                     PropertyConstness constness,
                                     Representation representation) {
  Kind kind = constness == PropertyConstness::kMutable ? Kind::kField
                                                       : Kind::kConstField;
  return StoreField(isolate, kind, descriptor, field_index, representation);
}

Handle<Smi> StoreHandler::StoreSharedStructField(
    Isolate* isolate, int descriptor, FieldIndex field_index,
    Representation representation) {
  DCHECK(representation.Equals(Representation::Tagged()));
  return StoreField(isolate, Kind::kSharedStructField, descriptor, field_index,
                    representation);
}

Handle<Smi> StoreHandler::StoreNativeDataProperty(Isolate* isolate,
                                                  int descriptor) {
  int config = KindBits::encode(Kind::kNativeDataProperty) |
               DescriptorBits::encode(descriptor);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> StoreHandler::StoreAccessorFromPrototype(Isolate* isolate) {
  int config = KindBits::encode(Kind::kAccessorFromPrototype);
  return handle(Smi::FromInt(config), isolate);
}

Handle<Smi> StoreHandler::StoreApiSetter(Isolate* isolate,
                                         bool holder_is_receiver) {
  int config =
      KindBits::encode(holder_is_receiver ? Kind::kApiSetter
                                          : Kind::kApiSetterHolderIsPrototype);
  return handle(Smi::FromInt(config), isolate);
}

inline const char* WasmValueType2String(WasmValueType type) {
  switch (type) {
    case WasmValueType::kI8:
      return "i8";
    case WasmValueType::kI16:
      return "i16";
    case WasmValueType::kI32:
      return "i32";
    case WasmValueType::kU32:
      return "u32";
    case WasmValueType::kI64:
      return "i64";
    case WasmValueType::kF32:
      return "f32";
    case WasmValueType::kF64:
      return "f64";
    case WasmValueType::kS128:
      return "s128";

    case WasmValueType::kRef:
      return "Ref";
    case WasmValueType::kRefNull:
      return "RefNull";

    case WasmValueType::kNumTypes:
      return "???";
  }
}

}  // namespace internal
}  // namespace v8

#include "src/objects/object-macros-undef.h"

#endif  // V8_IC_HANDLER_CONFIGURATION_INL_H_
```