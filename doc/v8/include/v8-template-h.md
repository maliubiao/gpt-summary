Response:
The user wants to understand the functionality of the C++ header file `v8/include/v8-template.h` from the V8 JavaScript engine.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the core purpose:** The filename `v8-template.h` strongly suggests that this file defines template classes used for creating JavaScript objects and functions within the V8 engine.

2. **Scan for key classes:** Look for the main classes defined in the header. `Template`, `FunctionTemplate`, and `ObjectTemplate` stand out as the primary building blocks.

3. **Analyze the `Template` class:**
    * It's the base class for `FunctionTemplate` and `ObjectTemplate`, indicating shared functionality.
    * The methods `Set`, `SetPrivate`, `SetAccessorProperty`, `SetNativeDataProperty`, `SetLazyDataProperty`, and `SetIntrinsicDataProperty` all relate to adding properties to objects created from templates. Note the different types of properties (data, accessor, native, lazy, intrinsic).

4. **Analyze the `FunctionTemplate` class:**
    * It's used to create JavaScript functions.
    * Key methods include `New` (for creating templates), `GetFunction` (for getting the actual function object), `InstanceTemplate` (for defining the structure of objects created with `new`), `PrototypeTemplate` (for the prototype chain), `Inherit` (for inheritance), `SetCallHandler` (for the function's code), `SetClassName`, `SetInterfaceName`.

5. **Analyze the `ObjectTemplate` class (will be in the next part, but anticipate its role):** It will be used to define the structure of plain JavaScript objects.

6. **Look for related types and enums:**
    * `Intrinsic`: Defines built-in JavaScript objects and functions.
    * Callback types like `FunctionCallback`, `AccessorNameGetterCallback`, `AccessorNameSetterCallback`, and the various `NamedProperty...Callback` and `IndexedProperty...Callback` types are crucial for defining custom behavior.
    * The `PropertyAttribute` enum defines property attributes like read-only, enumerable, configurable.
    * The `Intercepted` enum is used by property interceptors.
    * `PropertyHandlerFlags` configure the behavior of property handlers.

7. **Consider the user's specific questions:**
    * **Functionality Listing:** Summarize the purpose of each major class and its key methods.
    * **`.tq` extension:**  Explain that `.tq` indicates Torque code, a TypeScript-like language for V8 internals. Since the provided file is `.h`, this isn't relevant *for this specific file*, but the user asked a general question, so address it.
    * **Relationship to JavaScript:**  Provide JavaScript examples demonstrating how the C++ templates are used to create and customize JavaScript objects and functions. Focus on concepts like properties, prototypes, inheritance, and accessors.
    * **Code Logic Reasoning:** For simple examples, show how setting properties on templates affects instances. Use a simple scenario with clear input and output.
    * **Common Programming Errors:**  Think about mistakes developers might make when using these templates, like forgetting to set a callback, incorrect callback signatures, or misunderstanding inheritance.

8. **Structure the response:** Organize the information logically, starting with a high-level summary and then diving into details for each class and concept. Use headings and bullet points for clarity. Address each of the user's specific requests.

9. **Address the "part 1 of 2" aspect:** Conclude the summary by noting that this is the first part and that further details will likely be in the next part (anticipating the `ObjectTemplate` content).

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Focus heavily on individual methods.
* **Correction:** Shift to a higher-level understanding of the classes and their roles first, then delve into specific methods. This provides better context.
* **Initial thought:** Provide very complex C++ examples.
* **Correction:**  Focus on the core concepts and use simpler, illustrative C++ snippets. Prioritize clear JavaScript examples to show the user the *outcome* of using the C++ templates.
* **Initial thought:**  Address the `.tq` question only if it was relevant to this specific file.
* **Correction:**  Address it as a general point since the user explicitly asked. Clarify that *this* file is not `.tq`.

By following this structured approach and refining the response along the way, the generated summary effectively addresses the user's request and provides a good understanding of the `v8-template.h` header file.
```cpp
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_TEMPLATE_H_
#define INCLUDE_V8_TEMPLATE_H_

#include <cstddef>
#include <string_view>

#include "v8-data.h"               // NOLINT(build/include_directory)
#include "v8-exception.h"          // NOLINT(build/include_directory)
#include "v8-function-callback.h"  // NOLINT(build/include_directory)
#include "v8-local-handle.h"       // NOLINT(build/include_directory)
#include "v8-memory-span.h"        // NOLINT(build/include_directory)
#include "v8-object.h"             // NOLINT(build/include_directory)
#include "v8config.h"              // NOLINT(build/include_directory)

namespace v8 {

class CFunction;
class FunctionTemplate;
class ObjectTemplate;
class Signature;

// --- Templates ---

#define V8_INTRINSICS_LIST(F)                                 \
  F(ArrayProto_entries, array_entries_iterator)               \
  F(ArrayProto_forEach, array_for_each_iterator)              \
  F(ArrayProto_keys, array_keys_iterator)                     \
  F(ArrayProto_values, array_values_iterator)                 \
  F(ArrayPrototype, initial_array_prototype)                  \
  F(AsyncIteratorPrototype, initial_async_iterator_prototype) \
  F(ErrorPrototype, initial_error_prototype)                  \
  F(IteratorPrototype, initial_iterator_prototype)            \
  F(MapIteratorPrototype, initial_map_iterator_prototype)     \
  F(ObjProto_valueOf, object_value_of_function)               \
  F(SetIteratorPrototype, initial_set_iterator_prototype)

enum Intrinsic {
#define V8_DECL_INTRINSIC(name, iname) k##name,
  V8_INTRINSICS_LIST(V8_DECL_INTRINSIC)
#undef V8_DECL_INTRINSIC
};

/**
 * The superclass of object and function templates.
 */
class V8_EXPORT Template : public Data {
 public:
  /**
   * Adds a property to each instance created by this template.
   *
   * The property must be defined either as a primitive value, or a template.
   */
  void Set(Local<Name> name, Local<Data> value,
           PropertyAttribute attributes = None);
  void SetPrivate(Local<Private> name, Local<Data> value,
                  PropertyAttribute attributes = None);
  V8_INLINE void Set(Isolate* isolate, const char* name, Local<Data> value,
                     PropertyAttribute attributes = None);

  /**
   * Sets an "accessor property" on the object template, see
   * https://tc39.es/ecma262/#sec-object-type.
   *
   * Whenever the property with the given name is accessed on objects
   * created from this ObjectTemplate the getter and setter functions
   * are called.
   *
   * \param name The name of the property for which an accessor is added.
   * \param getter The callback to invoke when getting the property.
   * \param setter The callback to invoke when setting the property.
   * \param attribute The attributes of the property for which an accessor
   *   is added.
   */
  void SetAccessorProperty(
      Local<Name> name,
      Local<FunctionTemplate> getter = Local<FunctionTemplate>(),
      Local<FunctionTemplate> setter = Local<FunctionTemplate>(),
      PropertyAttribute attribute = None);

  /**
   * Sets a "data property" on the object template, see
   * https://tc39.es/ecma262/#sec-object-type.
   *
   * Whenever the property with the given name is accessed on objects
   * created from this Template the getter and setter callbacks
   * are called instead of getting and setting the property directly
   * on the JavaScript object.
   * Note that in case a property is written via a "child" object, the setter
   * will not be called according to the JavaScript specification. See
   * https://tc39.es/ecma262/#sec-ordinary-object-internal-methods-and-internal-slots-set-p-v-receiver.
   *
   * \param name The name of the data property for which an accessor is added.
   * \param getter The callback to invoke when getting the property.
   * \param setter The callback to invoke when setting the property.
   * \param data A piece of data that will be passed to the getter and setter
   *   callbacks whenever they are invoked.
   * \param attribute The attributes of the property for which an accessor
   *   is added.
   */
  void SetNativeDataProperty(
      Local<Name> name, AccessorNameGetterCallback getter,
      AccessorNameSetterCallback setter = nullptr,
      Local<Value> data = Local<Value>(), PropertyAttribute attribute = None,
      SideEffectType getter_side_effect_type = SideEffectType::kHasSideEffect,
      SideEffectType setter_side_effect_type = SideEffectType::kHasSideEffect);

  /**
   * Like SetNativeDataProperty, but V8 will replace the native data property
   * with a real data property on first access.
   */
  void SetLazyDataProperty(
      Local<Name> name, AccessorNameGetterCallback getter,
      Local<Value> data = Local<Value>(), PropertyAttribute attribute = None,
      SideEffectType getter_side_effect_type = SideEffectType::kHasSideEffect,
      SideEffectType setter_side_effect_type = SideEffectType::kHasSideEffect);

  /**
   * During template instantiation, sets the value with the intrinsic property
   * from the correct context.
   */
  void SetIntrinsicDataProperty(Local<Name> name, Intrinsic intrinsic,
                                PropertyAttribute attribute = None);

 private:
  Template();

  friend class ObjectTemplate;
  friend class FunctionTemplate;
};

/**
 * Interceptor callbacks use this value to indicate whether the request was
 * intercepted or not.
 */
enum class Intercepted : uint8_t { kNo = 0, kYes = 1 };

// ... (rest of the code)
```

## 功能归纳 (第 1 部分)

这是 V8 JavaScript 引擎中 `v8/include/v8-template.h` 文件的源代码片段。它主要定义了用于创建和自定义 JavaScript 对象和函数的 **模板 (Templates)** 机制。

**主要功能点:**

1. **定义了 `Template` 基类:**  这是一个抽象基类，作为 `ObjectTemplate` 和 `FunctionTemplate` 的父类。它提供了向由模板创建的实例添加属性的基础功能。

2. **定义了 `Intrinsic` 枚举:**  列举了 V8 引擎内部的一些内置对象和函数的标识符，例如数组原型、迭代器原型等。这些在创建自定义对象和函数时可以被引用。

3. **提供了向模板添加属性的方法:**
    *   `Set()`: 添加一个常规属性，可以设置属性特性（如是否可枚举、可配置等）。
    *   `SetPrivate()`: 添加一个私有属性。
    *   `SetAccessorProperty()`: 添加一个访问器属性，通过 `getter` 和 `setter` 函数来控制属性的读取和写入。这与 JavaScript 中的 `Object.defineProperty()` 中使用 `get` 和 `set` 定义属性类似。
    *   `SetNativeDataProperty()`: 添加一个原生数据属性，其读取和写入操作会调用指定的 C++ 回调函数 (`getter`, `setter`). 可以关联用户自定义数据。
    *   `SetLazyDataProperty()`: 类似于 `SetNativeDataProperty()`, 但只有在第一次访问该属性时才会调用 `getter` 回调，并将结果设置为实际的属性值。
    *   `SetIntrinsicDataProperty()`:  将一个内置的 `Intrinsic` 值设置为属性的值。

4. **定义了属性拦截器 (Interceptors) 相关的类型:**  引入了 `Intercepted` 枚举，用于指示属性访问是否被拦截器处理。同时定义了各种 `NamedProperty...Callback` 和 `IndexedProperty...Callback` 类型的回调函数，这些函数允许 C++ 代码拦截和自定义 JavaScript 对象的属性访问、设置、删除等操作。

5. **定义了 `FunctionTemplate` 类:**  用于创建 JavaScript 函数。
    *   可以设置函数的调用处理程序 (`SetCallHandler`)，即当 JavaScript 代码调用该函数时执行的 C++ 函数。
    *   可以设置函数的原型 (`PrototypeTemplate`)，定义通过 `new` 操作符创建的对象实例的原型。
    *   可以设置实例模板 (`InstanceTemplate`)，定义通过 `new` 操作符创建的对象实例的属性。
    *   支持继承 (`Inherit`)，允许创建继承自其他函数模板的函数。
    *   可以设置函数的类名 (`SetClassName`) 和接口名 (`SetInterfaceName`)，用于调试和错误处理。

**如果 `v8/include/v8-template.h` 以 `.tq` 结尾:**

如果文件以 `.tq` 结尾，那么它将是 V8 的 **Torque** 源代码。Torque 是一种用于编写 V8 内部代码的领域特定语言，它是一种强类型的、类似 TypeScript 的语言，旨在提高 V8 代码的安全性和性能。在这个场景下，文件中定义的功能将以 Torque 语法实现，而不是 C++。

**与 JavaScript 的关系 (使用 JavaScript 举例说明):**

`v8-template.h` 中定义的类和方法直接映射到在 V8 引擎中创建和操作 JavaScript 对象和函数的底层机制。

*   **`Template::Set()` 对应于在 JavaScript 中给对象添加属性:**

    ```javascript
    const myObj = {};
    myObj.myProperty = 10;
    ```

    在 C++ 中，使用 `Template::Set()` 可以预先为由模板创建的所有对象实例添加类似的属性。

*   **`Template::SetAccessorProperty()` 对应于 JavaScript 中的 `Object.defineProperty()` 使用 `get` 和 `set`:**

    ```javascript
    const myObj = {};
    Object.defineProperty(myObj, 'myAccessor', {
      get() {
        return this._myValue;
      },
      set(value) {
        this._myValue = value * 2;
      }
    });

    myObj.myAccessor = 5; // 内部会调用 set()
    console.log(myObj.myAccessor); // 内部会调用 get()，输出 10
    ```

    `Template::SetAccessorProperty()` 允许在 C++ 中定义类似的访问器属性，并将 `getter` 和 `setter` 实现为 C++ 函数。

*   **`FunctionTemplate` 用于创建自定义的 JavaScript 函数或类:**

    ```javascript
    function MyClass(value) {
      this.value = value;
    }

    MyClass.prototype.getValue = function() {
      return this.value;
    };

    const instance = new MyClass(5);
    console.log(instance.getValue()); // 输出 5
    ```

    `FunctionTemplate` 允许 C++ 代码定义类似 `MyClass` 这样的构造函数，并为其原型添加方法。

*   **属性拦截器允许 C++ 代码介入 JavaScript 对象的属性访问:**

    想象一个 C++ 拦截器拦截对某个对象特定属性的读取操作。在 JavaScript 中访问该属性时，不会直接返回存储的值，而是会先调用 C++ 拦截器，由拦截器决定返回值或者执行其他操作。

**代码逻辑推理 (假设输入与输出):**

假设我们使用 `FunctionTemplate` 创建了一个简单的 JavaScript 函数，并使用 `InstanceTemplate` 为其创建的实例添加了一个属性：

**C++ 代码 (简化示例):**

```c++
v8::Local<v8::FunctionTemplate> function_template =
    v8::FunctionTemplate::New(isolate);

v8::Local<v8::ObjectTemplate> instance_template =
    function_template->InstanceTemplate();

instance_template->Set(
    v8::String::NewFromUtf8Literal(isolate, "myInstanceProperty"),
    v8::Number::New(isolate, 42));

v8::Local<v8::Function> function =
    function_template->GetFunction(context).ToLocalChecked();

v8::Local<v8::Object> instance =
    function->NewInstance(context).ToLocalChecked();
```

**假设输入:** 以上 C++ 代码被执行。

**输出:**

*   在 JavaScript 环境中，将存在一个由 `function` 代表的函数对象。
*   通过 `new function()` 创建的实例 (`instance`) 将拥有一个名为 `myInstanceProperty` 的属性，其值为 `42`。

**JavaScript 中可以验证:**

```javascript
console.log(instance.myInstanceProperty); // 输出 42
```

**用户常见的编程错误:**

1. **忘记设置回调函数:**  使用 `SetNativeDataProperty` 或 `SetAccessorProperty` 时，如果忘记提供 `getter` 或 `setter` 回调函数，会导致程序崩溃或行为异常。

    **错误示例 (C++):**

    ```c++
    // 忘记设置 getter
    instance_template->SetNativeDataProperty(
        v8::String::NewFromUtf8Literal(isolate, "myProperty"),
        nullptr // 错误：缺少 getter
    );
    ```

2. **回调函数签名不正确:**  V8 的回调函数有特定的签名要求。如果提供的回调函数参数或返回值类型不匹配，会导致运行时错误。

    **错误示例 (C++):**

    ```c++
    // 错误的 getter 签名
    void WrongGetter(v8::Local<v8::Name> property, const v8::PropertyCallbackInfo<void>& info) {
        // ...
    }

    instance_template->SetAccessorProperty(
        v8::String::NewFromUtf8Literal(isolate, "myAccessor"),
        v8::FunctionTemplate::New(isolate, WrongGetter) // 错误：Getter 应该返回 Value
    );
    ```

3. **在回调函数中执行不安全的操作:**  例如，在属性拦截器或访问器回调中进行可能触发垃圾回收或执行 JavaScript 代码的操作，可能会导致 V8 引擎状态不一致。

4. **误解模板的生命周期:**  `FunctionTemplate` 通常在应用程序生命周期内创建和使用。在不应该修改模板之后尝试修改它会导致崩溃。

这是第一部分的功能归纳。下一部分可能会涉及 `ObjectTemplate` 的更详细信息，以及属性处理器的配置和使用。

Prompt: 
```
这是目录为v8/include/v8-template.h的一个v8源代码， 请列举一下它的功能, 
如果v8/include/v8-template.h以.tq结尾，那它是个v8 torque源代码，
如果它与javascript的功能有关系，请用javascript举例说明,
如果有代码逻辑推理，请给出假设输入与输出，
如果涉及用户常见的编程错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能

"""
// Copyright 2021 the V8 project authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef INCLUDE_V8_TEMPLATE_H_
#define INCLUDE_V8_TEMPLATE_H_

#include <cstddef>
#include <string_view>

#include "v8-data.h"               // NOLINT(build/include_directory)
#include "v8-exception.h"          // NOLINT(build/include_directory)
#include "v8-function-callback.h"  // NOLINT(build/include_directory)
#include "v8-local-handle.h"       // NOLINT(build/include_directory)
#include "v8-memory-span.h"        // NOLINT(build/include_directory)
#include "v8-object.h"             // NOLINT(build/include_directory)
#include "v8config.h"              // NOLINT(build/include_directory)

namespace v8 {

class CFunction;
class FunctionTemplate;
class ObjectTemplate;
class Signature;

// --- Templates ---

#define V8_INTRINSICS_LIST(F)                                 \
  F(ArrayProto_entries, array_entries_iterator)               \
  F(ArrayProto_forEach, array_for_each_iterator)              \
  F(ArrayProto_keys, array_keys_iterator)                     \
  F(ArrayProto_values, array_values_iterator)                 \
  F(ArrayPrototype, initial_array_prototype)                  \
  F(AsyncIteratorPrototype, initial_async_iterator_prototype) \
  F(ErrorPrototype, initial_error_prototype)                  \
  F(IteratorPrototype, initial_iterator_prototype)            \
  F(MapIteratorPrototype, initial_map_iterator_prototype)     \
  F(ObjProto_valueOf, object_value_of_function)               \
  F(SetIteratorPrototype, initial_set_iterator_prototype)

enum Intrinsic {
#define V8_DECL_INTRINSIC(name, iname) k##name,
  V8_INTRINSICS_LIST(V8_DECL_INTRINSIC)
#undef V8_DECL_INTRINSIC
};

/**
 * The superclass of object and function templates.
 */
class V8_EXPORT Template : public Data {
 public:
  /**
   * Adds a property to each instance created by this template.
   *
   * The property must be defined either as a primitive value, or a template.
   */
  void Set(Local<Name> name, Local<Data> value,
           PropertyAttribute attributes = None);
  void SetPrivate(Local<Private> name, Local<Data> value,
                  PropertyAttribute attributes = None);
  V8_INLINE void Set(Isolate* isolate, const char* name, Local<Data> value,
                     PropertyAttribute attributes = None);

  /**
   * Sets an "accessor property" on the object template, see
   * https://tc39.es/ecma262/#sec-object-type.
   *
   * Whenever the property with the given name is accessed on objects
   * created from this ObjectTemplate the getter and setter functions
   * are called.
   *
   * \param name The name of the property for which an accessor is added.
   * \param getter The callback to invoke when getting the property.
   * \param setter The callback to invoke when setting the property.
   * \param attribute The attributes of the property for which an accessor
   *   is added.
   */
  void SetAccessorProperty(
      Local<Name> name,
      Local<FunctionTemplate> getter = Local<FunctionTemplate>(),
      Local<FunctionTemplate> setter = Local<FunctionTemplate>(),
      PropertyAttribute attribute = None);

  /**
   * Sets a "data property" on the object template, see
   * https://tc39.es/ecma262/#sec-object-type.
   *
   * Whenever the property with the given name is accessed on objects
   * created from this Template the getter and setter callbacks
   * are called instead of getting and setting the property directly
   * on the JavaScript object.
   * Note that in case a property is written via a "child" object, the setter
   * will not be called according to the JavaScript specification. See
   * https://tc39.es/ecma262/#sec-ordinary-object-internal-methods-and-internal-slots-set-p-v-receiver.
   *
   * \param name The name of the data property for which an accessor is added.
   * \param getter The callback to invoke when getting the property.
   * \param setter The callback to invoke when setting the property.
   * \param data A piece of data that will be passed to the getter and setter
   *   callbacks whenever they are invoked.
   * \param attribute The attributes of the property for which an accessor
   *   is added.
   */
  void SetNativeDataProperty(
      Local<Name> name, AccessorNameGetterCallback getter,
      AccessorNameSetterCallback setter = nullptr,
      Local<Value> data = Local<Value>(), PropertyAttribute attribute = None,
      SideEffectType getter_side_effect_type = SideEffectType::kHasSideEffect,
      SideEffectType setter_side_effect_type = SideEffectType::kHasSideEffect);

  /**
   * Like SetNativeDataProperty, but V8 will replace the native data property
   * with a real data property on first access.
   */
  void SetLazyDataProperty(
      Local<Name> name, AccessorNameGetterCallback getter,
      Local<Value> data = Local<Value>(), PropertyAttribute attribute = None,
      SideEffectType getter_side_effect_type = SideEffectType::kHasSideEffect,
      SideEffectType setter_side_effect_type = SideEffectType::kHasSideEffect);

  /**
   * During template instantiation, sets the value with the intrinsic property
   * from the correct context.
   */
  void SetIntrinsicDataProperty(Local<Name> name, Intrinsic intrinsic,
                                PropertyAttribute attribute = None);

 private:
  Template();

  friend class ObjectTemplate;
  friend class FunctionTemplate;
};

/**
 * Interceptor callbacks use this value to indicate whether the request was
 * intercepted or not.
 */
enum class Intercepted : uint8_t { kNo = 0, kYes = 1 };

/**
 * Interceptor for get requests on an object.
 *
 * If the interceptor handles the request (i.e. the property should not be
 * looked up beyond the interceptor or in case an exception was thrown) it
 * should
 *  - (optionally) use info.GetReturnValue().Set()` to set the return value
 *    (by default the result is set to v8::Undefined),
 *  - return `Intercepted::kYes`.
 * If the interceptor does not handle the request it must return
 * `Intercepted::kNo` and it must not produce side effects.
 *
 * \param property The name of the property for which the request was
 * intercepted.
 * \param info Information about the intercepted request, such as
 * isolate, receiver, return value, or whether running in `'use strict'` mode.
 * See `PropertyCallbackInfo`.
 *
 * \code
 *  Intercepted GetterCallback(
 *      Local<Name> name, const v8::PropertyCallbackInfo<v8::Value>& info) {
 *    if (!IsKnownProperty(info.GetIsolate(), name)) return Intercepted::kNo;
 *    info.GetReturnValue().Set(v8_num(42));
 *    return Intercepted::kYes;
 *  }
 *
 *  v8::Local<v8::FunctionTemplate> templ =
 *      v8::FunctionTemplate::New(isolate);
 *  templ->InstanceTemplate()->SetHandler(
 *      v8::NamedPropertyHandlerConfiguration(GetterCallback));
 *  LocalContext env;
 *  env->Global()
 *      ->Set(env.local(), v8_str("obj"), templ->GetFunction(env.local())
 *                                             .ToLocalChecked()
 *                                             ->NewInstance(env.local())
 *                                             .ToLocalChecked())
 *      .FromJust();
 *  v8::Local<v8::Value> result = CompileRun("obj.a = 17; obj.a");
 *  CHECK(v8_num(42)->Equals(env.local(), result).FromJust());
 * \endcode
 *
 * See also `ObjectTemplate::SetHandler`.
 */
using NamedPropertyGetterCallback = Intercepted (*)(
    Local<Name> property, const PropertyCallbackInfo<Value>& info);
// This variant will be deprecated soon.
//
// Use `info.GetReturnValue().Set()` to set the return value of the
// intercepted get request. If the property does not exist the callback should
// not set the result and must not produce side effects.
using GenericNamedPropertyGetterCallback =
    void (*)(Local<Name> property, const PropertyCallbackInfo<Value>& info);

/**
 * Interceptor for set requests on an object.
 *
 * If the interceptor handles the request (i.e. the property should not be
 * looked up beyond the interceptor or in case an exception was thrown) it
 * should return `Intercepted::kYes`.
 * If the interceptor does not handle the request it must return
 * `Intercepted::kNo` and it must not produce side effects.
 *
 * \param property The name of the property for which the request was
 * intercepted.
 * \param value The value which the property will have if the request
 * is not intercepted.
 * \param info Information about the intercepted request, such as
 * isolate, receiver, return value, or whether running in `'use strict'` mode.
 * See `PropertyCallbackInfo`.
 *
 * See also `ObjectTemplate::SetHandler.`
 */
using NamedPropertySetterCallback =
    Intercepted (*)(Local<Name> property, Local<Value> value,
                    const PropertyCallbackInfo<void>& info);
// This variant will be deprecated soon.
//
// Use `info.GetReturnValue()` to indicate whether the request was intercepted
// or not. If the setter successfully intercepts the request, i.e., if the
// request should not be further executed, call
// `info.GetReturnValue().Set(value)`. If the setter did not intercept the
// request, i.e., if the request should be handled as if no interceptor is
// present, do not not call `Set()` and do not produce side effects.
using GenericNamedPropertySetterCallback =
    void (*)(Local<Name> property, Local<Value> value,
             const PropertyCallbackInfo<Value>& info);

/**
 * Intercepts all requests that query the attributes of the
 * property, e.g., getOwnPropertyDescriptor(), propertyIsEnumerable(), and
 * defineProperty().
 *
 * If the interceptor handles the request (i.e. the property should not be
 * looked up beyond the interceptor or in case an exception was thrown) it
 * should
 *  - (optionally) use `info.GetReturnValue().Set()` to set to an Integer
 *    value encoding a `v8::PropertyAttribute` bits,
 *  - return `Intercepted::kYes`.
 * If the interceptor does not handle the request it must return
 * `Intercepted::kNo` and it must not produce side effects.
 *
 * \param property The name of the property for which the request was
 * intercepted.
 * \param info Information about the intercepted request, such as
 * isolate, receiver, return value, or whether running in `'use strict'` mode.
 * See `PropertyCallbackInfo`.
 *
 * \note Some functions query the property attributes internally, even though
 * they do not return the attributes. For example, `hasOwnProperty()` can
 * trigger this interceptor depending on the state of the object.
 *
 * See also `ObjectTemplate::SetHandler.`
 */
using NamedPropertyQueryCallback = Intercepted (*)(
    Local<Name> property, const PropertyCallbackInfo<Integer>& info);
// This variant will be deprecated soon.
//
// Use `info.GetReturnValue().Set(value)` to set the property attributes. The
// value is an integer encoding a `v8::PropertyAttribute`. If the property does
// not exist the callback should not set the result and must not produce side
// effects.
using GenericNamedPropertyQueryCallback =
    void (*)(Local<Name> property, const PropertyCallbackInfo<Integer>& info);

/**
 * Interceptor for delete requests on an object.
 *
 * If the interceptor handles the request (i.e. the property should not be
 * looked up beyond the interceptor or in case an exception was thrown) it
 * should
 *  - (optionally) use `info.GetReturnValue().Set()` to set to a Boolean value
 *    indicating whether the property deletion was successful or not,
 *  - return `Intercepted::kYes`.
 * If the interceptor does not handle the request it must return
 * `Intercepted::kNo` and it must not produce side effects.
 *
 * \param property The name of the property for which the request was
 * intercepted.
 * \param info Information about the intercepted request, such as
 * isolate, receiver, return value, or whether running in `'use strict'` mode.
 * See `PropertyCallbackInfo`.
 *
 * \note If you need to mimic the behavior of `delete`, i.e., throw in strict
 * mode instead of returning false, use `info.ShouldThrowOnError()` to determine
 * if you are in strict mode.
 *
 * See also `ObjectTemplate::SetHandler.`
 */
using NamedPropertyDeleterCallback = Intercepted (*)(
    Local<Name> property, const PropertyCallbackInfo<Boolean>& info);
// This variant will be deprecated soon.
//
// Use `info.GetReturnValue()` to indicate whether the request was intercepted
// or not. If the deleter successfully intercepts the request, i.e., if the
// request should not be further executed, call
// `info.GetReturnValue().Set(value)` with a boolean `value`. The `value` is
// used as the return value of `delete`. If the deleter does not intercept the
// request then it should not set the result and must not produce side effects.
using GenericNamedPropertyDeleterCallback =
    void (*)(Local<Name> property, const PropertyCallbackInfo<Boolean>& info);

/**
 * Returns an array containing the names of the properties the named
 * property getter intercepts.
 *
 * Note: The values in the array must be of type v8::Name.
 */
using NamedPropertyEnumeratorCallback =
    void (*)(const PropertyCallbackInfo<Array>& info);
// This variant will be deprecated soon.
// This is just a renaming of the typedef.
using GenericNamedPropertyEnumeratorCallback = NamedPropertyEnumeratorCallback;

/**
 * Interceptor for defineProperty requests on an object.
 *
 * If the interceptor handles the request (i.e. the property should not be
 * looked up beyond the interceptor or in case an exception was thrown) it
 * should return `Intercepted::kYes`.
 * If the interceptor does not handle the request it must return
 * `Intercepted::kNo` and it must not produce side effects.
 *
 * \param property The name of the property for which the request was
 * intercepted.
 * \param desc The property descriptor which is used to define the
 * property if the request is not intercepted.
 * \param info Information about the intercepted request, such as
 * isolate, receiver, return value, or whether running in `'use strict'` mode.
 * See `PropertyCallbackInfo`.
 *
 * See also `ObjectTemplate::SetHandler`.
 */
using NamedPropertyDefinerCallback =
    Intercepted (*)(Local<Name> property, const PropertyDescriptor& desc,
                    const PropertyCallbackInfo<void>& info);
// This variant will be deprecated soon.
//
// Use `info.GetReturnValue()` to indicate whether the request was intercepted
// or not. If the definer successfully intercepts the request, i.e., if the
// request should not be further executed, call
// `info.GetReturnValue().Set(value)`. If the definer did not intercept the
// request, i.e., if the request should be handled as if no interceptor is
// present, do not not call `Set()` and do not produce side effects.
using GenericNamedPropertyDefinerCallback =
    void (*)(Local<Name> property, const PropertyDescriptor& desc,
             const PropertyCallbackInfo<Value>& info);

/**
 * Interceptor for getOwnPropertyDescriptor requests on an object.
 *
 * If the interceptor handles the request (i.e. the property should not be
 * looked up beyond the interceptor or in case an exception was thrown) it
 * should
 *  - (optionally) use `info.GetReturnValue().Set()` to set the return value
 *    which must be object that can be converted to a PropertyDescriptor (for
 *    example, a value returned by `v8::Object::getOwnPropertyDescriptor`),
 *  - return `Intercepted::kYes`.
 * If the interceptor does not handle the request it must return
 * `Intercepted::kNo` and it must not produce side effects.
 *
 * \param property The name of the property for which the request was
 * intercepted.
 * \info Information about the intercepted request, such as
 * isolate, receiver, return value, or whether running in `'use strict'` mode.
 * See `PropertyCallbackInfo`.
 *
 * \note If GetOwnPropertyDescriptor is intercepted, it will
 * always return true, i.e., indicate that the property was found.
 *
 * See also `ObjectTemplate::SetHandler`.
 */
using NamedPropertyDescriptorCallback = Intercepted (*)(
    Local<Name> property, const PropertyCallbackInfo<Value>& info);
// This variant will be deprecated soon.
//
// Use `info.GetReturnValue().Set()` to set the return value of the
// intercepted request. The return value must be an object that
// can be converted to a PropertyDescriptor, e.g., a `v8::Value` returned from
// `v8::Object::getOwnPropertyDescriptor`.
using GenericNamedPropertyDescriptorCallback =
    void (*)(Local<Name> property, const PropertyCallbackInfo<Value>& info);

// TODO(ishell): Rename IndexedPropertyXxxCallbackV2 back to
// IndexedPropertyXxxCallback once the old IndexedPropertyXxxCallback is
// removed.

/**
 * See `v8::NamedPropertyGetterCallback`.
 */
using IndexedPropertyGetterCallbackV2 =
    Intercepted (*)(uint32_t index, const PropertyCallbackInfo<Value>& info);
// This variant will be deprecated soon.
using IndexedPropertyGetterCallback =
    void (*)(uint32_t index, const PropertyCallbackInfo<Value>& info);

/**
 * See `v8::NamedPropertySetterCallback`.
 */
using IndexedPropertySetterCallbackV2 = Intercepted (*)(
    uint32_t index, Local<Value> value, const PropertyCallbackInfo<void>& info);
// This variant will be deprecated soon.
using IndexedPropertySetterCallback =
    void (*)(uint32_t index, Local<Value> value,
             const PropertyCallbackInfo<Value>& info);

/**
 * See `v8::NamedPropertyQueryCallback`.
 */
using IndexedPropertyQueryCallbackV2 =
    Intercepted (*)(uint32_t index, const PropertyCallbackInfo<Integer>& info);
// This variant will be deprecated soon.
using IndexedPropertyQueryCallback =
    void (*)(uint32_t index, const PropertyCallbackInfo<Integer>& info);

/**
 * See `v8::NamedPropertyDeleterCallback`.
 */
using IndexedPropertyDeleterCallbackV2 =
    Intercepted (*)(uint32_t index, const PropertyCallbackInfo<Boolean>& info);
// This variant will be deprecated soon.
using IndexedPropertyDeleterCallback =
    void (*)(uint32_t index, const PropertyCallbackInfo<Boolean>& info);

/**
 * Returns an array containing the indices of the properties the indexed
 * property getter intercepts.
 *
 * Note: The values in the array must be uint32_t.
 */
using IndexedPropertyEnumeratorCallback =
    void (*)(const PropertyCallbackInfo<Array>& info);

/**
 * See `v8::NamedPropertyDefinerCallback`.
 */
using IndexedPropertyDefinerCallbackV2 =
    Intercepted (*)(uint32_t index, const PropertyDescriptor& desc,
                    const PropertyCallbackInfo<void>& info);
// This variant will be deprecated soon.
using IndexedPropertyDefinerCallback =
    void (*)(uint32_t index, const PropertyDescriptor& desc,
             const PropertyCallbackInfo<Value>& info);

/**
 * See `v8::NamedPropertyDescriptorCallback`.
 */
using IndexedPropertyDescriptorCallbackV2 =
    Intercepted (*)(uint32_t index, const PropertyCallbackInfo<Value>& info);
// This variant will be deprecated soon.
using IndexedPropertyDescriptorCallback =
    void (*)(uint32_t index, const PropertyCallbackInfo<Value>& info);

/**
 * Returns true if the given context should be allowed to access the given
 * object.
 */
using AccessCheckCallback = bool (*)(Local<Context> accessing_context,
                                     Local<Object> accessed_object,
                                     Local<Value> data);

enum class ConstructorBehavior { kThrow, kAllow };

/**
 * A FunctionTemplate is used to create functions at runtime. There
 * can only be one function created from a FunctionTemplate in a
 * context.  The lifetime of the created function is equal to the
 * lifetime of the context.  So in case the embedder needs to create
 * temporary functions that can be collected using Scripts is
 * preferred.
 *
 * Any modification of a FunctionTemplate after first instantiation will trigger
 * a crash.
 *
 * A FunctionTemplate can have properties, these properties are added to the
 * function object when it is created.
 *
 * A FunctionTemplate has a corresponding instance template which is
 * used to create object instances when the function is used as a
 * constructor. Properties added to the instance template are added to
 * each object instance.
 *
 * A FunctionTemplate can have a prototype template. The prototype template
 * is used to create the prototype object of the function.
 *
 * The following example shows how to use a FunctionTemplate:
 *
 * \code
 *    v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New(isolate);
 *    t->Set(isolate, "func_property", v8::Number::New(isolate, 1));
 *
 *    v8::Local<v8::Template> proto_t = t->PrototypeTemplate();
 *    proto_t->Set(isolate,
 *                 "proto_method",
 *                 v8::FunctionTemplate::New(isolate, InvokeCallback));
 *    proto_t->Set(isolate, "proto_const", v8::Number::New(isolate, 2));
 *
 *    v8::Local<v8::ObjectTemplate> instance_t = t->InstanceTemplate();
 *    instance_t->SetNativeDataProperty(
 *        String::NewFromUtf8Literal(isolate, "instance_accessor"),
 *        InstanceAccessorCallback);
 *    instance_t->SetHandler(
 *        NamedPropertyHandlerConfiguration(PropertyHandlerCallback));
 *    instance_t->Set(String::NewFromUtf8Literal(isolate, "instance_property"),
 *                    Number::New(isolate, 3));
 *
 *    v8::Local<v8::Function> function = t->GetFunction();
 *    v8::Local<v8::Object> instance = function->NewInstance();
 * \endcode
 *
 * Let's use "function" as the JS variable name of the function object
 * and "instance" for the instance object created above.  The function
 * and the instance will have the following properties:
 *
 * \code
 *   func_property in function == true;
 *   function.func_property == 1;
 *
 *   function.prototype.proto_method() invokes 'InvokeCallback'
 *   function.prototype.proto_const == 2;
 *
 *   instance instanceof function == true;
 *   instance.instance_accessor calls 'InstanceAccessorCallback'
 *   instance.instance_property == 3;
 * \endcode
 *
 * A FunctionTemplate can inherit from another one by calling the
 * FunctionTemplate::Inherit method.  The following graph illustrates
 * the semantics of inheritance:
 *
 * \code
 *   FunctionTemplate Parent  -> Parent() . prototype -> { }
 *     ^                                                  ^
 *     | Inherit(Parent)                                  | .__proto__
 *     |                                                  |
 *   FunctionTemplate Child   -> Child()  . prototype -> { }
 * \endcode
 *
 * A FunctionTemplate 'Child' inherits from 'Parent', the prototype
 * object of the Child() function has __proto__ pointing to the
 * Parent() function's prototype object. An instance of the Child
 * function has all properties on Parent's instance templates.
 *
 * Let Parent be the FunctionTemplate initialized in the previous
 * section and create a Child FunctionTemplate by:
 *
 * \code
 *   Local<FunctionTemplate> parent = t;
 *   Local<FunctionTemplate> child = FunctionTemplate::New();
 *   child->Inherit(parent);
 *
 *   Local<Function> child_function = child->GetFunction();
 *   Local<Object> child_instance = child_function->NewInstance();
 * \endcode
 *
 * The Child function and Child instance will have the following
 * properties:
 *
 * \code
 *   child_func.prototype.__proto__ == function.prototype;
 *   child_instance.instance_accessor calls 'InstanceAccessorCallback'
 *   child_instance.instance_property == 3;
 * \endcode
 *
 * The additional 'c_function' parameter refers to a fast API call, which
 * must not trigger GC or JavaScript execution, or call into V8 in other
 * ways. For more information how to define them, see
 * include/v8-fast-api-calls.h. Please note that this feature is still
 * experimental.
 */
class V8_EXPORT FunctionTemplate : public Template {
 public:
  /** Creates a function template.*/
  static Local<FunctionTemplate> New(
      Isolate* isolate, FunctionCallback callback = nullptr,
      Local<Value> data = Local<Value>(),
      Local<Signature> signature = Local<Signature>(), int length = 0,
      ConstructorBehavior behavior = ConstructorBehavior::kAllow,
      SideEffectType side_effect_type = SideEffectType::kHasSideEffect,
      const CFunction* c_function = nullptr, uint16_t instance_type = 0,
      uint16_t allowed_receiver_instance_type_range_start = 0,
      uint16_t allowed_receiver_instance_type_range_end = 0);

  /** Creates a function template for multiple overloaded fast API calls.*/
  static Local<FunctionTemplate> NewWithCFunctionOverloads(
      Isolate* isolate, FunctionCallback callback = nullptr,
      Local<Value> data = Local<Value>(),
      Local<Signature> signature = Local<Signature>(), int length = 0,
      ConstructorBehavior behavior = ConstructorBehavior::kAllow,
      SideEffectType side_effect_type = SideEffectType::kHasSideEffect,
      const MemorySpan<const CFunction>& c_function_overloads = {});

  /**
   * Creates a function template backed/cached by a private property.
   */
  static Local<FunctionTemplate> NewWithCache(
      Isolate* isolate, FunctionCallback callback,
      Local<Private> cache_property, Local<Value> data = Local<Value>(),
      Local<Signature> signature = Local<Signature>(), int length = 0,
      SideEffectType side_effect_type = SideEffectType::kHasSideEffect);

  /** Returns the unique function instance in the current execution context.*/
  V8_WARN_UNUSED_RESULT MaybeLocal<Function> GetFunction(
      Local<Context> context);

  /**
   * Similar to Context::NewRemoteContext, this creates an instance that
   * isn't backed by an actual object.
   *
   * The InstanceTemplate of this FunctionTemplate must have access checks with
   * handlers installed.
   */
  V8_WARN_UNUSED_RESULT MaybeLocal<Object> NewRemoteInstance();

  /**
   * Set the call-handler callback for a FunctionTemplate.  This
   * callback is called whenever the function created from this
   * FunctionTemplate is called. The 'c_function' represents a fast
   * API call, see the comment above the class declaration.
   */
  void SetCallHandler(
      FunctionCallback callback, Local<Value> data = Local<Value>(),
      SideEffectType side_effect_type = SideEffectType::kHasSideEffect,
      const MemorySpan<const CFunction>& c_function_overloads = {});

  /** Set the predefined length property for the FunctionTemplate. */
  void SetLength(int length);

  /** Get the InstanceTemplate. */
  Local<ObjectTemplate> InstanceTemplate();

  /**
   * Causes the function template to inherit from a parent function template.
   * This means the function's prototype.__proto__ is set to the parent
   * function's prototype.
   **/
  void Inherit(Local<FunctionTemplate> parent);

  /**
   * A PrototypeTemplate is the template used to create the prototype object
   * of the function created by this template.
   */
  Local<ObjectTemplate> PrototypeTemplate();

  /**
   * A PrototypeProviderTemplate is another function template whose prototype
   * property is used for this template. This is mutually exclusive with setting
   * a prototype template indirectly by calling PrototypeTemplate() or using
   * Inherit().
   **/
  void SetPrototypeProviderTemplate(Local<FunctionTemplate> prototype_provider);

  /**
   * Set the class name of the FunctionTemplate.  This is used for
   * printing objects created with the function created from the
   * FunctionTemplate as its constructor.
   */
  void SetClassName(Local<String> name);

  /**
   * Set the interface name of the FunctionTemplate. This is provided as
   * contextual information in an ExceptionPropagationMessage to the embedder.
   */
  void SetInterfaceName(Local<String> name);

  /**
   * Provides information on the type of FunctionTemplate for embedder
   * exception handling.
   */
  void SetExceptionContext(ExceptionContext context);

  /**
   * When set to true, no access check will be performed on the receiver of a
   * function call.  Currently defaults to true, but this is subject to change.
   */
  void SetAcceptAnyReceiver(bool value);

  /**
   * Sets the ReadOnly flag in the attributes of the 'prototype' property
   * of functions created from this FunctionTemplate to true.
   */
  void ReadOnlyPrototype();

  /**
   * Removes the prototype property from functions created from this
   * FunctionTemplate.
   */
  void RemovePrototype();

  /**
   * Returns true if the given object is an instance of this function
   * template.
   */
  bool HasInstance(Local<Value> object);

  /**
   * Returns true if the given value is an API object that was constructed by an
   * instance of this function template (without checking for inheriting
   * function templates).
   *
   * This is an experimental feature and may still change significantly.
   */
  bool IsLeafTemplateForApiObject(v8::Local<v8::Value> value) const;

  V8_INLINE static FunctionTemplate* Cast(Data* data);

 private:
  FunctionTemplate();

  static void CheckCast(Data* that);
  friend class Context;
  friend class ObjectTemplate;
};

/**
 * Configuration flags for v8::NamedPropertyHandlerConfiguration or
 * v8::IndexedPropertyHandlerConfiguration.
 */
enum class PropertyHandlerFlags {
  /**
   * None.
   */
  kNone = 0,

  /**
   * Will not call into interceptor for properties on the receiver or prototype
   * chain, i.e., only call into interceptor for properties that do not exist.
   * Currently only valid for named interceptors.
   */
  kNonMasking = 1,

  /**
   * Will not call into interceptor for symbol lookup.  Only meaningful for
   * named interceptors.
   */
  kOnlyInterceptStrings = 1 << 1,

  /**
   * The getter, query, enumerator callbacks do not produce side effects.
   */
  kHasNoSideEffect = 1 << 2,

  /**
   * This flag is used to distinguish which callbacks were provided -
   * GenericNamedPropertyXXXCallback (old signature) or
   * NamedPropertyXXXCallback (new signature).
   * DO NOT use this flag, it'll be removed once embedders migrate to new
   * callbacks signatures.
   */
  kInternalNewCallbacksSignatures = 1 << 10,
};

struct NamedPropertyHandlerConfiguration {
 private:
  static constexpr PropertyHandlerFlags WithNewSignatureFlag(
      PropertyHandlerFlags flags) {
    return static_cast<PropertyHandlerFlags>(
        static_cast<int>(flags) |
        static_cast<int>(
            PropertyHandlerFlags::kInternalNewCallbacksSignatures));
  }

 public:
  NamedPropertyHandlerConfiguration(
      NamedPropertyGetterCallback getter,          //
      NamedPropertySetterCallback setter,          //
      NamedPropertyQueryCallback query,            //
      NamedPropertyDeleterCallback deleter,        //
      NamedPropertyEnumeratorCallback enumerator,  //
      NamedPropertyDefinerCallback definer,        //
      NamedPropertyDescriptorCallback descriptor,  //
      Local<Value> data = Local<Value>(),
      PropertyHandlerFlags flags = PropertyHandlerFlags::kNone)
      : getter(getter),
        setter(setter),
        query(query),
        deleter(deleter),
        enumerator(enumerator),
        definer(definer),
        descriptor(descriptor),
        data(data),
        flags(flags) {}

  explicit NamedPropertyHandlerConfiguration(
      NamedPropertyGetterCallback getter,
      NamedPropertySetterCallback setter = nullptr,
      NamedPropertyQueryCallback query = nullptr,
      NamedPropertyDeleterCallback deleter = nullptr,
      NamedPropertyEnumeratorCallback enumerator = nullptr,
      Local<Value> data = Local<Value>(),
      PropertyHandlerFlags flags = PropertyHandlerFlags::kNone)
      : getter(getter),
        setter(setter),
        query(query),
        deleter(deleter),
        enumerator(enumerator),
        definer(nullptr),
        descriptor(nullptr),
        data(data),
        flags(flags) {}

  NamedPropertyHandlerConfiguration(
      NamedPropertyGetterCallback getter,          //
      NamedPropertySetterCallback setter,          //
      NamedPropertyDescriptorCallback descriptor,  //
      NamedPropertyDeleterCallback deleter,        //
      NamedPropertyEnumeratorCallback enumerator,  //
      NamedPropertyDefinerCallback definer,        //
      Local<Value> data = Local<Value>(),
      PropertyHandlerFlags flags = PropertyHandlerFlags::kNone)
      : getter(getter),
        setter(setter),
        query(nullptr),
        deleter(deleter),
        enumerator(enumerator),
        definer(definer),
        descriptor(descriptor),
        data(data),
        flags(flags) {}

  NamedPropertyGetterCallback getter;
  NamedPropertySetterCallback setter;
  NamedPropertyQueryCallback query;
  NamedPropertyDeleterCallback deleter;
  NamedPropertyEnumeratorCallback enumerator;
  NamedPropertyDefinerCallback definer;
  NamedPropertyDescriptorCallback descriptor;
  Local<Value> data;
  PropertyHandlerFlags fl
"""


```